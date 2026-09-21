//! A client for `raven-faced`, the one process that touches the camera.
//!
//! Its socket is `/run/raven-face/camera.sock`, root's only, one line in and
//! lines out -- the shape `raven-fprintd`'s sensor socket has, for the reasons
//! that one has it: the traffic is a handful of messages per unlock, and being
//! able to drive it from `socat` while bringing a camera up is worth more than
//! the bytes.
//!
//! - `status`, `list`, `forget`, `forget-all` answer once.
//! - `verify` and `enrol` stream: a line per look, then a verdict.
//! - Every failure is a line beginning `error`, never a dropped connection.
//! - Anything at all on the connection -- a byte, a close -- ends a wait. So
//!   cancelling is closing: see [`Faced::hangup_handle`].
//!
//! The daemon serves one connection at a time, because there is one camera.
//!
//! # Pixels do not cross this socket
//!
//! Nothing here carries an image, in either direction, and there is no verb
//! that would. What comes back is a verdict, a correction, and a colour to
//! paint. A login screen that could ask the camera daemon for a picture would
//! be a login screen worth compromising for the picture, and the frames the
//! camera takes of somebody's face never leave the process that took them.
//!
//! That is also why there is no preview on the login screen. It would be nice,
//! and it would mean piping video to the least trusted process on the machine.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use raven_greet_proto::{Camera, Flash, Look, Wash};

use crate::{MAX_MISSES, advice, clean_label, split_label};

/// Where `raven-faced` listens.
pub const SOCKET: &str = "/run/raven-face/camera.sock";

/// A connection to `raven-faced`.
#[derive(Debug)]
pub struct Faced {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

/// Something that happened during a watch that is not the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEvent {
    /// Paint the screen, or stop. Part of the liveness challenge, and the one
    /// event a client must act on rather than merely display.
    Wash(Wash),
    /// The camera saw something it could not use. Not a miss, and it costs
    /// nothing: the sentence says what to do differently.
    Retry(&'static str),
    /// A clear look at a face that is not this account's.
    Miss {
        /// How many more are allowed before the watch gives up.
        left: u8,
    },
    /// A face, and the liveness check would not call it a live one.
    ///
    /// Counted as a miss, because the model that decides this has a false
    /// positive rate and the person it lands on most often is the account's
    /// own owner in bad light. Logged as itself, because the times it is not a
    /// false positive are the times somebody wants to know about.
    Spoof {
        /// How many more are allowed before the watch gives up.
        left: u8,
    },
}

/// How a watch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watch {
    /// One of the account's own looks. `None` if the daemon matched a record
    /// it would not number -- still the account's, so still a match.
    Matched(Option<u8>),
    /// [`MAX_MISSES`] clear looks that were not it. The password is the way in
    /// now.
    Missed {
        /// Whether the last of them failed the liveness check rather than the
        /// comparison, so the screen can say the more useful of the two
        /// things.
        spoofed: bool,
    },
    /// The connection went away before a verdict: the caller hung up, or the
    /// daemon did.
    Cancelled,
}

/// One enrolment capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Good captures so far.
    pub done: u8,
    /// How many the daemon wants.
    pub of: u8,
    /// The capture was not usable, and this is what to do about it.
    pub retry: Option<&'static str>,
}

/// Something that happened during an enrolment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrolEvent {
    /// As [`WatchEvent::Wash`].
    Wash(Wash),
    Progress(Progress),
}

impl Faced {
    /// Connect to the daemon. `Ok(None)` if it is not running, which on a
    /// machine without the service is ordinary and not an error.
    pub fn connect() -> std::io::Result<Option<Self>> {
        Self::connect_to(Path::new(SOCKET))
    }

    pub fn connect_to(path: &Path) -> std::io::Result<Option<Self>> {
        let stream = match UnixStream::connect(path) {
            Ok(stream) => stream,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        // Writes are one short line; a daemon that cannot take one in ten
        // seconds is wedged, and the caller should find out rather than hang.
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Some(Self {
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
        }))
    }

    /// A second handle on the connection, for ending it from another thread.
    ///
    /// `shutdown(Both)` on it makes the daemon put the camera down and makes
    /// whatever this `Faced` is blocked in return [`Watch::Cancelled`] (or
    /// `Ok(None)` from [`Self::enrol`]).
    pub fn hangup_handle(&self) -> std::io::Result<UnixStream> {
        self.writer.try_clone()
    }

    /// How long to wait for any one line. `None`, the default, is forever,
    /// which is right for a lock screen and wrong for a settings panel.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.writer.set_read_timeout(timeout)
    }

    fn send(&mut self, line: &str) -> std::io::Result<()> {
        writeln!(self.writer, "{line}")?;
        self.writer.flush()
    }

    /// The next line, or `None` if the connection has closed.
    fn line(&mut self) -> std::io::Result<Option<String>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(line.trim_end_matches(['\r', '\n']).to_string())),
            Err(e) => Err(e),
        }
    }

    fn expect_line(&mut self) -> std::io::Result<String> {
        self.line()?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "raven-faced closed the connection",
            )
        })
    }

    /// Whether there is a camera, and whether there is anything to run on what
    /// it sees.
    ///
    /// Never [`Camera::NoService`]: that is what a connection that could not be
    /// made means, and it is [`Self::connect`] that reports it.
    pub fn status(&mut self) -> std::io::Result<Camera> {
        self.send("status")?;
        let line = self.expect_line()?;
        parse_status(&line).map_err(std::io::Error::other)
    }

    /// The looks stored for `account`, and only for it.
    pub fn looks_of(&mut self, account: &str) -> std::io::Result<Vec<Look>> {
        self.send(&format!("list {account}"))?;
        let mut looks = Vec::new();
        loop {
            let line = self.expect_line()?;
            if line == "ok" {
                looks.sort_by_key(|look: &Look| look.id);
                return Ok(looks);
            }
            if let Some(why) = line.strip_prefix("error") {
                return Err(std::io::Error::other(why.trim().to_string()));
            }
            if let Some(rest) = line.strip_prefix("look ")
                && let Some(look) = parse_look(rest)
            {
                looks.push(look);
            }
        }
    }

    /// Remove one of `account`'s looks, or all of them with `None`.
    ///
    /// Never another account's: the account is named in the request and the
    /// daemon keeps each one's templates apart, so there is no "clear
    /// everything" here of the kind a fingerprint sensor with no per-finger
    /// delete forces.
    pub fn forget(&mut self, account: &str, look: Option<u8>) -> std::io::Result<()> {
        match look {
            Some(id) => self.send(&format!("forget {account} {id}"))?,
            None => self.send(&format!("forget-all {account}"))?,
        }
        let line = self.expect_line()?;
        match line.strip_prefix("error") {
            Some(why) => Err(std::io::Error::other(why.trim().to_string())),
            None => Ok(()),
        }
    }

    /// Enrol another of `account`'s looks.
    ///
    /// `on` hears every capture. `Ok(Some(look))` is a stored template;
    /// `Ok(None)` is a connection that closed first -- see
    /// [`Self::hangup_handle`].
    pub fn enrol(
        &mut self,
        account: &str,
        label: &str,
        flash: bool,
        mut on: impl FnMut(EnrolEvent),
    ) -> std::io::Result<Option<Look>> {
        let label = clean_label(label);
        let wants_flash = u8::from(flash);
        if self
            .send(&format!("enrol {account} {wants_flash} {label}"))
            .is_err()
        {
            return Ok(None);
        }
        loop {
            let Some(line) = self.line_or_cancelled()? else {
                return Ok(None);
            };
            match parse_enrol(&line) {
                EnrolLine::Wash(wash) => on(EnrolEvent::Wash(wash)),
                EnrolLine::Frame { done, of } => on(EnrolEvent::Progress(Progress {
                    done,
                    of,
                    retry: None,
                })),
                EnrolLine::Retry { word, done, of } => on(EnrolEvent::Progress(Progress {
                    done,
                    of,
                    retry: Some(advice(word)),
                })),
                EnrolLine::Done { id, added } => {
                    return Ok(Some(Look { id, label, added }));
                }
                EnrolLine::Error(why) => return Err(std::io::Error::other(why.to_string())),
                EnrolLine::Unknown => {
                    tracing::debug!(line, "ignoring a line raven-faced sent mid-enrolment");
                }
            }
        }
    }

    /// Wait for `account`'s face.
    ///
    /// Asks the daemon for a look, and again after every miss, until one of
    /// this account's templates matches or `allowed` clear misses have gone by
    /// -- at most [`MAX_MISSES`], and fewer for a caller carrying a count over
    /// from an earlier watch. A template belonging to a *different* account is
    /// a miss however well it matched: that is the whole reason records carry
    /// the account's name.
    ///
    /// `flash` is what the caller promises about the screen in front of the
    /// person, and the daemon tests rather than believes it -- a caller that
    /// says yes and paints nothing gets the same answer a photograph does.
    pub fn watch(
        &mut self,
        account: &str,
        allowed: u8,
        flash: bool,
        mut on: impl FnMut(WatchEvent),
    ) -> std::io::Result<Watch> {
        let allowed = allowed.clamp(1, MAX_MISSES);
        let wants_flash = u8::from(flash);
        let mut misses: u8 = 0;
        loop {
            if self.send(&format!("verify {account} {wants_flash}")).is_err() {
                return Ok(Watch::Cancelled);
            }
            let spoofed = loop {
                let Some(line) = self.line_or_cancelled()? else {
                    return Ok(Watch::Cancelled);
                };
                match parse_verify(&line) {
                    VerifyLine::Wash(wash) => on(WatchEvent::Wash(wash)),
                    VerifyLine::Retry(word) => on(WatchEvent::Retry(advice(word))),
                    VerifyLine::Match(label) => match split_label(label) {
                        Some((owner, look)) if owner == account => {
                            return Ok(Watch::Matched(Some(look)));
                        }
                        // A match the daemon would not attribute is one that
                        // could let the wrong account in, so it is a miss --
                        // the same call `raven-fprintd`'s unnamed slot gets.
                        _ => break false,
                    },
                    VerifyLine::NoMatch => break false,
                    VerifyLine::Spoof => break true,
                    VerifyLine::Error(why) => return Err(std::io::Error::other(why.to_string())),
                    VerifyLine::Unknown => {
                        tracing::debug!(line, "ignoring a line raven-faced sent mid-verify");
                    }
                }
            };
            misses += 1;
            if misses >= allowed {
                return Ok(Watch::Missed { spoofed });
            }
            let left = allowed - misses;
            on(if spoofed {
                WatchEvent::Spoof { left }
            } else {
                WatchEvent::Miss { left }
            });
        }
    }

    /// The next line; `None` if the connection was closed from either end.
    ///
    /// A reset or a broken pipe mid-wait is how a hung-up connection looks
    /// from this side, so those are a close too. A timeout is not: that is a
    /// caller's deadline, and it is reported as the error it is.
    fn line_or_cancelled(&mut self) -> std::io::Result<Option<String>> {
        match self.line() {
            Ok(line) => Ok(line),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// `ok present <device> <0|1>`, `ok absent`, or `ok nomodel <why>`.
fn parse_status(line: &str) -> Result<Camera, String> {
    if let Some(why) = line.strip_prefix("error") {
        return Err(why.trim().to_string());
    }
    let mut words = line.split_whitespace();
    match (words.next(), words.next()) {
        (Some("ok"), Some("absent")) => Ok(Camera::Absent),
        (Some("ok"), Some("nomodel")) => {
            let why = words.collect::<Vec<_>>().join(" ");
            Ok(Camera::NoModel {
                why: if why.is_empty() {
                    "the face recognition models are not installed".to_string()
                } else {
                    why
                },
            })
        }
        (Some("ok"), Some("present")) => Ok(Camera::Present {
            device: words.next().unwrap_or("").to_string(),
            infrared: words.next() == Some("1"),
        }),
        _ => Err(format!("raven-faced said {line:?} to status")),
    }
}

/// `<id> <added> <label...>`; the label is the rest of the line and may be
/// empty or contain spaces.
fn parse_look(rest: &str) -> Option<Look> {
    let mut words = rest.splitn(3, ' ');
    let id = words.next()?.parse().ok()?;
    let added = words.next()?.parse().ok()?;
    let label = clean_label(words.next().unwrap_or(""));
    Some(Look { id, label, added })
}

/// `flash <r> <g> <b>`, or `flash off`.
///
/// Two instructions and not one: see [`Wash`]. `flash 0 0 0` is a dark step of
/// a challenge -- the face lit by the room alone, which is the baseline every
/// lit step is measured against -- and `flash off` is the end of the sequence.
fn parse_wash(rest: &str) -> Option<Wash> {
    let rest = rest.trim();
    if rest == "off" {
        return Some(Wash::Off);
    }
    let mut words = rest.split_whitespace();
    let mut channel = || words.next().and_then(|w| w.parse::<u8>().ok());
    let colour = Flash {
        r: channel()?,
        g: channel()?,
        b: channel()?,
    };
    // A fourth word means the daemon said something this does not understand,
    // and painting three quarters of it would be worse than painting none.
    words.next().is_none().then_some(Wash::Colour(colour))
}

#[derive(Debug, PartialEq, Eq)]
enum EnrolLine<'a> {
    Wash(Wash),
    Frame { done: u8, of: u8 },
    Retry { word: &'a str, done: u8, of: u8 },
    Done { id: u8, added: i64 },
    Error(&'a str),
    Unknown,
}

fn parse_enrol(line: &str) -> EnrolLine<'_> {
    if let Some(rest) = line.strip_prefix("ok") {
        let mut words = rest.split_whitespace();
        return match (
            words.next().and_then(|w| w.parse().ok()),
            words.next().and_then(|w| w.parse().ok()),
        ) {
            (Some(id), Some(added)) => EnrolLine::Done { id, added },
            // A daemon that stored the template and would not say which one it
            // is has left the caller unable to name, show or remove it.
            _ => EnrolLine::Error("raven-faced did not say which look it stored"),
        };
    }
    if let Some(why) = line.strip_prefix("error") {
        return EnrolLine::Error(why.trim());
    }
    if let Some(rest) = line.strip_prefix("flash ") {
        return parse_wash(rest).map_or(EnrolLine::Unknown, EnrolLine::Wash);
    }
    fn numbers(rest: &str) -> Option<(&str, u8, u8)> {
        let (rest, of) = rest.trim().rsplit_once(' ')?;
        let (word, done) = rest.trim().rsplit_once(' ').unwrap_or(("", rest.trim()));
        Some((word.trim(), done.parse().ok()?, of.parse().ok()?))
    }
    if let Some(rest) = line.strip_prefix("frame ")
        && let Some((_, done, of)) = numbers(rest)
    {
        return EnrolLine::Frame { done, of };
    }
    if let Some(rest) = line.strip_prefix("retry ")
        && let Some((word, done, of)) = numbers(rest)
    {
        return EnrolLine::Retry { word, done, of };
    }
    EnrolLine::Unknown
}

#[derive(Debug, PartialEq, Eq)]
enum VerifyLine<'a> {
    Wash(Wash),
    Retry(&'a str),
    Match(&'a str),
    NoMatch,
    Spoof,
    Error(&'a str),
    Unknown,
}

fn parse_verify(line: &str) -> VerifyLine<'_> {
    if line == "nomatch" {
        VerifyLine::NoMatch
    } else if line == "spoof" {
        VerifyLine::Spoof
    } else if let Some(label) = line.strip_prefix("match ") {
        VerifyLine::Match(label.trim())
    } else if let Some(rest) = line.strip_prefix("flash ") {
        parse_wash(rest).map_or(VerifyLine::Unknown, VerifyLine::Wash)
    } else if let Some(word) = line.strip_prefix("retry ") {
        VerifyLine::Retry(word.trim())
    } else if let Some(why) = line.strip_prefix("error") {
        VerifyLine::Error(why.trim())
    } else {
        VerifyLine::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn status_lines_parse() {
        assert_eq!(
            parse_status("ok present /dev/video0 0"),
            Ok(Camera::Present {
                device: "/dev/video0".to_string(),
                infrared: false,
            })
        );
        assert_eq!(
            parse_status("ok present /dev/video2 1"),
            Ok(Camera::Present {
                device: "/dev/video2".to_string(),
                infrared: true,
            })
        );
        assert_eq!(parse_status("ok absent"), Ok(Camera::Absent));
        assert!(matches!(
            parse_status("ok nomodel the recogniser is not installed"),
            Ok(Camera::NoModel { why }) if why == "the recogniser is not installed"
        ));
        assert!(parse_status("error this socket is root's").is_err());
    }

    /// A label may be empty, and may have spaces in it.
    #[test]
    fn look_lines_parse() {
        assert_eq!(
            parse_look("2 1774000000 with glasses"),
            Some(Look {
                id: 2,
                label: "with glasses".to_string(),
                added: 1_774_000_000,
            })
        );
        assert_eq!(
            parse_look("1 0"),
            Some(Look {
                id: 1,
                label: String::new(),
                added: 0,
            })
        );
        assert_eq!(parse_look("not-a-number 0 x"), None);
    }

    #[test]
    fn verify_lines_parse() {
        assert_eq!(parse_verify("nomatch"), VerifyLine::NoMatch);
        assert_eq!(parse_verify("spoof"), VerifyLine::Spoof);
        assert_eq!(parse_verify("match javan:2"), VerifyLine::Match("javan:2"));
        assert_eq!(parse_verify("retry dark"), VerifyLine::Retry("dark"));
        assert_eq!(
            parse_verify("flash 255 0 128"),
            VerifyLine::Wash(Wash::Colour(Flash {
                r: 255,
                g: 0,
                b: 128
            }))
        );
        assert_eq!(parse_verify("flash off"), VerifyLine::Wash(Wash::Off));
        // A dark step is a colour, and is not the end of the sequence.
        assert_eq!(
            parse_verify("flash 0 0 0"),
            VerifyLine::Wash(Wash::Colour(Flash { r: 0, g: 0, b: 0 }))
        );
        // A channel out of range is not a colour, and painting a guess at what
        // was meant would fail the very check the flash exists for.
        assert_eq!(parse_verify("flash 300 0 0"), VerifyLine::Unknown);
        assert_eq!(parse_verify("flash 1 2"), VerifyLine::Unknown);
        assert_eq!(parse_verify("flash 1 2 3 4"), VerifyLine::Unknown);
    }

    #[test]
    fn enrolment_lines_parse() {
        assert_eq!(parse_enrol("frame 3 5"), EnrolLine::Frame { done: 3, of: 5 });
        assert_eq!(
            parse_enrol("retry dark 1 5"),
            EnrolLine::Retry {
                word: "dark",
                done: 1,
                of: 5
            }
        );
        assert_eq!(
            parse_enrol("ok 3 1774000000"),
            EnrolLine::Done {
                id: 3,
                added: 1_774_000_000
            }
        );
        assert!(matches!(parse_enrol("ok"), EnrolLine::Error(_)));
        assert_eq!(
            parse_enrol("error no camera"),
            EnrolLine::Error("no camera")
        );
    }

    /// A fake daemon on a real socket: `script` maps each verb received to the
    /// lines sent back.
    fn fake_daemon(
        name: &str,
        script: Vec<(&'static str, Vec<&'static str>)>,
    ) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("raven-face-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("camera.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut out = stream;
            for (verb, lines) in script {
                let mut got = String::new();
                if reader.read_line(&mut got).unwrap_or(0) == 0 {
                    return;
                }
                assert_eq!(got.trim(), verb);
                for line in lines {
                    writeln!(out, "{line}").expect("write");
                }
            }
        });
        path
    }

    /// Somebody else's face matching cleanly is a miss, not a way in.
    #[test]
    fn another_accounts_face_is_a_miss() {
        let path = fake_daemon(
            "other",
            vec![
                ("verify javan 1", vec!["match somebody:1"]),
                (
                    "verify javan 1",
                    vec!["flash 255 255 255", "retry dark", "match javan:2"],
                ),
            ],
        );
        let mut faced = Faced::connect_to(&path).expect("connect").expect("there");
        let mut events = Vec::new();
        let verdict = faced
            .watch("javan", MAX_MISSES, true, |e| events.push(e))
            .expect("watch");
        assert_eq!(verdict, Watch::Matched(Some(2)));
        assert_eq!(
            events,
            vec![
                WatchEvent::Miss { left: 2 },
                WatchEvent::Wash(Wash::Colour(Flash {
                    r: 255,
                    g: 255,
                    b: 255
                })),
                WatchEvent::Retry("There is not enough light to see you."),
            ]
        );
    }

    /// A face that fails the liveness check spends a miss like any other, and
    /// the verdict remembers which kind the last one was.
    #[test]
    fn a_spoof_spends_a_miss_and_is_remembered() {
        let path = fake_daemon(
            "spoof",
            vec![
                ("verify javan 1", vec!["nomatch"]),
                ("verify javan 1", vec!["spoof"]),
                ("verify javan 1", vec!["spoof"]),
            ],
        );
        let mut faced = Faced::connect_to(&path).expect("connect").expect("there");
        let mut events = Vec::new();
        let verdict = faced
            .watch("javan", MAX_MISSES, true, |e| events.push(e))
            .expect("watch");
        assert_eq!(verdict, Watch::Missed { spoofed: true });
        assert_eq!(
            events,
            vec![WatchEvent::Miss { left: 2 }, WatchEvent::Spoof { left: 1 }]
        );
    }

    #[test]
    fn three_clean_misses_end_the_watch() {
        let path = fake_daemon(
            "misses",
            vec![
                ("verify javan 0", vec!["nomatch"]),
                ("verify javan 0", vec!["retry look", "nomatch"]),
                ("verify javan 0", vec!["match javanx:1"]),
            ],
        );
        let mut faced = Faced::connect_to(&path).expect("connect").expect("there");
        let verdict = faced.watch("javan", MAX_MISSES, false, |_| {}).expect("watch");
        assert_eq!(verdict, Watch::Missed { spoofed: false });
    }

    /// A budget carried over from an earlier watch is honoured: one miss left
    /// means one miss ends it.
    #[test]
    fn a_carried_over_budget_is_honoured() {
        let path = fake_daemon("budget", vec![("verify javan 1", vec!["nomatch"])]);
        let mut faced = Faced::connect_to(&path).expect("connect").expect("there");
        assert_eq!(
            faced.watch("javan", 1, true, |_| {}).expect("watch"),
            Watch::Missed { spoofed: false }
        );
    }

    #[test]
    fn a_hangup_is_a_cancel_not_an_error() {
        let path = fake_daemon("hangup", vec![("verify javan 1", vec!["retry look"])]);
        let mut faced = Faced::connect_to(&path).expect("connect").expect("there");
        let verdict = faced.watch("javan", MAX_MISSES, true, |_| {}).expect("watch");
        assert_eq!(verdict, Watch::Cancelled);
    }

    #[test]
    fn looks_come_back_in_order_with_their_labels() {
        let path = fake_daemon(
            "list",
            vec![(
                "list javan",
                vec![
                    "look 3 1774000300 in the dark",
                    "look 1 1774000100 with glasses",
                    "look 2 1774000200",
                    "ok",
                ],
            )],
        );
        let mut faced = Faced::connect_to(&path).expect("connect").expect("there");
        let looks = faced.looks_of("javan").expect("list");
        assert_eq!(
            looks.iter().map(|l| l.id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(looks[1].display_name(), "Face 2");
        assert_eq!(looks[0].label, "with glasses");
    }

    /// The label the caller asked for is the label the stored look carries,
    /// cleaned of anything that would have ended the line it was sent on.
    #[test]
    fn an_enrolment_returns_the_look_it_stored() {
        let path = fake_daemon(
            "enrol",
            vec![(
                "enrol javan 1 with glasses",
                vec!["flash 0 0 255", "frame 1 5", "retry still 1 5", "ok 4 1774000000"],
            )],
        );
        let mut faced = Faced::connect_to(&path).expect("connect").expect("there");
        let mut events = Vec::new();
        let look = faced
            .enrol("javan", "with glasses\n", true, |e| events.push(e))
            .expect("enrol")
            .expect("stored");
        assert_eq!(look.id, 4);
        assert_eq!(look.label, "with glasses");
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], EnrolEvent::Wash(Wash::Colour(_))));
    }

    #[test]
    fn no_daemon_is_none_not_an_error() {
        let missing = std::env::temp_dir().join("raven-face-no-such-dir/camera.sock");
        assert!(Faced::connect_to(&missing).expect("not an error").is_none());
    }
}
