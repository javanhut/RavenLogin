//! A client for `raven-fprintd`, the one process that touches the reader.
//!
//! Its socket is `/run/raven-fprint/sensor.sock`, root's only, one line in and
//! lines out. The verbs are documented in RavenLinux's `init/src/fprintd.rs`;
//! what matters here is the shape:
//!
//! - `status`, `list`, `forget` answer once.
//! - `verify` and `enrol` stream: a line per reading, then a verdict.
//! - Every failure is a line beginning `error`, never a dropped connection.
//! - Anything at all on the connection -- a byte, a close -- ends a wait for a
//!   finger. So cancelling is closing: see [`Sensor::hangup_handle`].
//!
//! The daemon serves one connection at a time, because there is one sensor.
//! A second caller waits in the listen backlog, which is why callers that
//! must not wait forever -- `sudo` -- set a timeout.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use raven_greet_proto::{Finger, Reader};

use crate::{MAX_MISSES, advice};

/// Where `raven-fprintd` listens.
pub const SOCKET: &str = "/run/raven-fprint/sensor.sock";

/// A connection to `raven-fprintd`.
#[derive(Debug)]
pub struct Sensor {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

/// Something that happened during a watch that is not the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEvent {
    /// The sensor saw something it could not use. Not a miss, and it costs
    /// nothing: the sentence says what to do differently.
    Retry(&'static str),
    /// A clean reading of a finger that is not one of this account's.
    Miss {
        /// How many more are allowed before the watch gives up.
        left: u8,
    },
}

/// How a watch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watch {
    /// One of the account's own fingers. `None` if it was stored under a name
    /// this stack does not use -- still the account's, so still a match.
    Matched(Option<Finger>),
    /// [`MAX_MISSES`] clean misses. The password is the way in now.
    Missed,
    /// The connection went away before a verdict: the caller hung up, or the
    /// daemon did.
    Cancelled,
}

/// One enrolment reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Good readings so far.
    pub done: u8,
    /// How many the sensor wants.
    pub of: u8,
    /// The reading was not usable, and this is what to do about it.
    pub retry: Option<&'static str>,
}

impl Sensor {
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
    /// `shutdown(Both)` on it makes the daemon stop waiting for a finger and
    /// makes whatever this `Sensor` is blocked in return [`Watch::Cancelled`]
    /// (or `Ok(false)` from [`Self::enrol`]).
    pub fn hangup_handle(&self) -> std::io::Result<UnixStream> {
        self.writer.try_clone()
    }

    /// How long to wait for any one line. `None`, the default, is forever,
    /// which is right for a lock screen and wrong for `sudo`.
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
            Ok(_) => Ok(Some(line.trim().to_string())),
            Err(e) => Err(e),
        }
    }

    fn expect_line(&mut self) -> std::io::Result<String> {
        self.line()?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "raven-fprintd closed the connection",
            )
        })
    }

    /// Whether there is a reader, and what it says about itself.
    pub fn status(&mut self) -> std::io::Result<Reader> {
        self.send("status")?;
        let line = self.expect_line()?;
        parse_status(&line).map_err(std::io::Error::other)
    }

    /// Every stored record's name, for every account.
    pub fn records(&mut self) -> std::io::Result<Vec<String>> {
        self.send("list")?;
        let mut records = Vec::new();
        loop {
            let line = self.expect_line()?;
            if line == "ok" {
                return Ok(records);
            }
            if let Some(why) = line.strip_prefix("error") {
                return Err(std::io::Error::other(why.trim().to_string()));
            }
            if let Some(label) = line.strip_prefix("finger ") {
                records.push(label.trim().to_string());
            }
        }
    }

    /// The fingers stored for `account`, and only for it.
    pub fn fingers_of(&mut self, account: &str) -> std::io::Result<Vec<Finger>> {
        let mut fingers: Vec<Finger> = self
            .records()?
            .iter()
            .filter_map(|label| split_label(label))
            .filter(|(owner, _)| *owner == account)
            .filter_map(|(_, finger)| Finger::parse(finger))
            .collect();
        fingers.sort();
        fingers.dedup();
        Ok(fingers)
    }

    /// Remove one of `account`'s fingers.
    pub fn forget(&mut self, account: &str, finger: Finger) -> std::io::Result<()> {
        self.send(&format!("forget {account} {}", finger.as_str()))?;
        let line = self.expect_line()?;
        match line.strip_prefix("error") {
            Some(why) => Err(std::io::Error::other(why.trim().to_string())),
            None => Ok(()),
        }
    }

    /// Enrol one of `account`'s fingers, replacing it if it is already there.
    ///
    /// `on` hears every reading. `Ok(true)` is a stored template; `Ok(false)`
    /// is a connection that closed first -- see [`Self::hangup_handle`].
    pub fn enrol(
        &mut self,
        account: &str,
        finger: Finger,
        mut on: impl FnMut(Progress),
    ) -> std::io::Result<bool> {
        if self
            .send(&format!("enrol {account} {}", finger.as_str()))
            .is_err()
        {
            return Ok(false);
        }
        loop {
            let Some(line) = self.line_or_cancelled()? else {
                return Ok(false);
            };
            match parse_enrol(&line) {
                EnrolLine::Frame { done, of } => on(Progress {
                    done,
                    of,
                    retry: None,
                }),
                EnrolLine::Retry { word, done, of } => on(Progress {
                    done,
                    of,
                    retry: Some(advice(word)),
                }),
                EnrolLine::Done => return Ok(true),
                EnrolLine::Error(why) => return Err(std::io::Error::other(why.to_string())),
                EnrolLine::Unknown => {
                    tracing::debug!(line, "ignoring a line raven-fprintd sent mid-enrolment");
                }
            }
        }
    }

    /// Wait for one of `account`'s fingers.
    ///
    /// Asks the daemon for a reading, and again after every miss, until one of
    /// this account's fingers matches or `allowed` clean misses have gone by
    /// -- at most [`MAX_MISSES`], and fewer for a caller that is carrying a
    /// count over from an earlier watch. A finger enrolled to a *different* account is a miss however
    /// cleanly it matched: that is the whole reason records carry the
    /// account's name.
    pub fn watch(
        &mut self,
        account: &str,
        allowed: u8,
        mut on: impl FnMut(WatchEvent),
    ) -> std::io::Result<Watch> {
        let allowed = allowed.clamp(1, MAX_MISSES);
        let mut misses: u8 = 0;
        loop {
            if self.send("verify").is_err() {
                return Ok(Watch::Cancelled);
            }
            let missed = loop {
                let Some(line) = self.line_or_cancelled()? else {
                    return Ok(Watch::Cancelled);
                };
                match parse_verify(&line) {
                    VerifyLine::Retry(word) => on(WatchEvent::Retry(advice(word))),
                    VerifyLine::Match(label) => match split_label(label) {
                        Some((owner, finger)) if owner == account => {
                            return Ok(Watch::Matched(Finger::parse(finger)));
                        }
                        _ => break true,
                    },
                    VerifyLine::NoMatch => break true,
                    VerifyLine::Error(why) => return Err(std::io::Error::other(why.to_string())),
                    VerifyLine::Unknown => {
                        tracing::debug!(line, "ignoring a line raven-fprintd sent mid-verify");
                    }
                }
            };
            if missed {
                misses += 1;
                if misses >= allowed {
                    return Ok(Watch::Missed);
                }
                on(WatchEvent::Miss {
                    left: allowed - misses,
                });
            }
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

/// `<account>:<finger>`, split. The account cannot contain a colon (see
/// [`crate::valid_account`]), so the first one is the boundary.
#[must_use]
pub fn split_label(label: &str) -> Option<(&str, &str)> {
    let (account, finger) = label.split_once(':')?;
    (!account.is_empty() && !finger.is_empty()).then_some((account, finger))
}

/// `ok present <stages> <stored> <firmware>` or `ok absent`.
fn parse_status(line: &str) -> Result<Reader, String> {
    if let Some(why) = line.strip_prefix("error") {
        return Err(why.trim().to_string());
    }
    let mut words = line.split_whitespace();
    match (words.next(), words.next()) {
        (Some("ok"), Some("absent")) => Ok(Reader::Absent),
        (Some("ok"), Some("present")) => {
            let stages = words.next().and_then(|w| w.parse().ok()).unwrap_or(0);
            let stored = words.next().and_then(|w| w.parse().ok()).unwrap_or(0);
            let firmware = words.next().unwrap_or("").to_string();
            Ok(Reader::Present {
                stages,
                stored,
                firmware,
            })
        }
        _ => Err(format!("raven-fprintd said {line:?} to status")),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum EnrolLine<'a> {
    Frame { done: u8, of: u8 },
    Retry { word: &'a str, done: u8, of: u8 },
    Done,
    Error(&'a str),
    Unknown,
}

/// One line of an enrolment. A retry's word can be two words (`try again`),
/// so the numbers are taken from the right.
fn parse_enrol(line: &str) -> EnrolLine<'_> {
    if line == "ok" {
        return EnrolLine::Done;
    }
    if let Some(why) = line.strip_prefix("error") {
        return EnrolLine::Error(why.trim());
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
    Retry(&'a str),
    Match(&'a str),
    NoMatch,
    Error(&'a str),
    Unknown,
}

fn parse_verify(line: &str) -> VerifyLine<'_> {
    if line == "nomatch" {
        VerifyLine::NoMatch
    } else if let Some(label) = line.strip_prefix("match ") {
        VerifyLine::Match(label.trim())
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
        assert_eq!(parse_status("ok absent"), Ok(Reader::Absent));
        assert_eq!(
            parse_status("ok present 9 2 0104"),
            Ok(Reader::Present {
                stages: 9,
                stored: 2,
                firmware: "0104".to_string()
            })
        );
        assert!(parse_status("error this socket is root's").is_err());
    }

    #[test]
    fn enrolment_lines_parse_including_two_word_retries() {
        assert_eq!(
            parse_enrol("frame 3 9"),
            EnrolLine::Frame { done: 3, of: 9 }
        );
        assert_eq!(
            parse_enrol("retry centre 1 9"),
            EnrolLine::Retry {
                word: "centre",
                done: 1,
                of: 9
            }
        );
        assert_eq!(
            parse_enrol("retry try again 4 9"),
            EnrolLine::Retry {
                word: "try again",
                done: 4,
                of: 9
            }
        );
        assert_eq!(parse_enrol("ok"), EnrolLine::Done);
        assert_eq!(
            parse_enrol("error the sensor could not read that finger"),
            EnrolLine::Error("the sensor could not read that finger")
        );
    }

    #[test]
    fn labels_split_at_the_first_colon() {
        assert_eq!(
            split_label("javan:right-index"),
            Some(("javan", "right-index"))
        );
        assert_eq!(split_label("nocolon"), None);
        assert_eq!(split_label(":right-index"), None);
    }

    /// A fake daemon on a real socket: `script` maps each verb received to the
    /// lines sent back.
    fn fake_daemon(
        name: &str,
        script: Vec<(&'static str, Vec<&'static str>)>,
    ) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("raven-finger-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("sensor.sock");
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

    /// Somebody else's finger matching cleanly is a miss, not a way in.
    #[test]
    fn another_accounts_finger_is_a_miss() {
        let path = fake_daemon(
            "other",
            vec![
                ("verify", vec!["match somebody:right-index"]),
                ("verify", vec!["retry centre", "match javan:left-thumb"]),
            ],
        );
        let mut sensor = Sensor::connect_to(&path).expect("connect").expect("there");
        let mut events = Vec::new();
        let verdict = sensor
            .watch("javan", MAX_MISSES, |e| events.push(e))
            .expect("watch");
        assert_eq!(verdict, Watch::Matched(Some(Finger::LeftThumb)));
        assert_eq!(
            events,
            vec![
                WatchEvent::Miss { left: 2 },
                WatchEvent::Retry("Centre your finger on the sensor."),
            ]
        );
    }

    #[test]
    fn three_clean_misses_end_the_watch() {
        let path = fake_daemon(
            "misses",
            vec![
                ("verify", vec!["nomatch"]),
                ("verify", vec!["retry wipe", "nomatch"]),
                ("verify", vec!["match javanx:right-index"]),
            ],
        );
        let mut sensor = Sensor::connect_to(&path).expect("connect").expect("there");
        let verdict = sensor.watch("javan", MAX_MISSES, |_| {}).expect("watch");
        assert_eq!(verdict, Watch::Missed);
    }

    #[test]
    fn a_hangup_is_a_cancel_not_an_error() {
        let path = fake_daemon("hangup", vec![("verify", vec!["retry centre"])]);
        let mut sensor = Sensor::connect_to(&path).expect("connect").expect("there");
        let verdict = sensor.watch("javan", MAX_MISSES, |_| {}).expect("watch");
        assert_eq!(verdict, Watch::Cancelled);
    }

    #[test]
    fn only_this_accounts_fingers_are_listed() {
        let path = fake_daemon(
            "list",
            vec![(
                "list",
                vec![
                    "finger javan:right-index",
                    "finger other:left-thumb",
                    "finger javan:left-index",
                    "finger javan:something-libfprint-wrote",
                    "ok",
                ],
            )],
        );
        let mut sensor = Sensor::connect_to(&path).expect("connect").expect("there");
        assert_eq!(
            sensor.fingers_of("javan").expect("list"),
            vec![Finger::LeftIndex, Finger::RightIndex]
        );
    }

    #[test]
    fn no_daemon_is_none_not_an_error() {
        let missing = std::env::temp_dir().join("raven-finger-no-such-dir/sensor.sock");
        assert!(
            Sensor::connect_to(&missing)
                .expect("not an error")
                .is_none()
        );
    }
}
