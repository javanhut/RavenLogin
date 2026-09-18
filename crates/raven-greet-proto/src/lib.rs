//! What `ravend` and the greeter say to each other.
//!
//! A 4-byte big-endian length, then that many bytes of JSON. JSON because the
//! message rate is "a few per login" and being able to read the traffic with
//! `socat` while bringing the thing up is worth more than the bytes; big-endian
//! because a length prefix that means different things on different machines is
//! a bug waiting for the first big-endian port.
//!
//! # The one design decision worth arguing about
//!
//! There is no separate "start session" request. [`Request::Authenticate`]
//! carries the password, and on success `ravend` starts the session *itself*
//! and replies [`Response::Granted`].
//!
//! greetd splits these, and the split is what makes it flexible: a greeter can
//! authenticate, then decide which session to launch. It also means the daemon
//! holds "this connection has authenticated as X" as state between two
//! requests, and every such state is a thing that can be reached the wrong way
//! — authenticate as one user, start a session as another; authenticate, hold
//! the connection open, start a session an hour later. Raven ships one session,
//! so the flexibility buys nothing, and collapsing the two requests into one
//! deletes the state and the whole class of bug with it. The daemon never
//! holds an authenticated identity across a message boundary.
//!
//! # What crosses this socket
//!
//! In one direction, a password. In the other, never a hash, never a reason
//! more specific than the greeter is allowed to display, and never anything
//! read out of `/etc/shadow`. The greeter is unprivileged and is assumed to be
//! the more likely of the two to be compromised.

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Where the socket lives.
///
/// Under `/run` because it must not survive a reboot, and in its own directory
/// so the directory can be `0700` and owned by the greeter — a socket is only
/// as protected as the path to it.
pub const SOCKET_PATH: &str = "/run/raven-login/greet.sock";

/// Where the lock screen asks its one question.
///
/// A second socket, in a second directory, and the separation is the point.
/// [`SOCKET_PATH`] lives in a `0700` directory owned by the greeter because
/// only the greeter may ever reach it -- what crosses it can *start a session*.
/// This one has to be reachable by whoever is logged in, so its directory is
/// world-traversable and the socket itself accepts any connection.
///
/// That is safe only because of what is *not* on this socket. It cannot start
/// a session, it cannot name an account, and it answers about exactly one
/// account: the one that owns the connection, resolved from `SO_PEERCRED` and
/// never from anything the caller said. A socket anyone may connect to is a
/// password oracle unless it can only be asked about the asker, so that is the
/// only question it takes.
pub const VERIFY_SOCKET_PATH: &str = "/run/raven-lock/verify.sock";

/// The largest message this protocol will read.
///
/// Small on purpose. The biggest legitimate message is a user list, which for
/// any real machine is a few hundred bytes; the cap exists so that a length
/// prefix corrupted to 4 GiB makes the daemon close a connection instead of
/// asking the allocator for 4 GiB.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// A password, in transit.
///
/// Wrapped rather than passed as a `String` for three reasons, all of which
/// have bitten real login screens:
///
/// - It is zeroed on drop, so it does not sit in freed heap.
/// - Its [`std::fmt::Debug`] is redacted, so `dbg!(&request)` or a
///   `tracing::debug!(?request)` cannot put a password in the journal. This is
///   the one that actually happens.
/// - It is a distinct type, so a function that takes a password cannot be
///   handed a username by accident.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The bytes, for handing to `raven-auth`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Redacted. See the type's documentation — this is the whole point of it.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// One account, as much of it as the greeter needs to draw a tile.
///
/// Notably absent: the home directory, the shell, and the group list. The
/// greeter has no use for any of them, and the less this struct carries the
/// less there is to leak if the greeter is compromised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// The account name, which is what goes back in an `Authenticate`.
    pub name: String,
    /// What to draw under the avatar.
    pub display_name: String,
    /// The letter for the avatar circle.
    pub initial: char,
}

/// Which finger a template was taken from.
///
/// Serialized as the word `raven-fprintd` stores on the sensor --
/// `right-index` -- so the name in a message, the name in a record and the
/// name in the policy file are the same string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Finger {
    LeftThumb,
    LeftIndex,
    LeftMiddle,
    LeftRing,
    LeftLittle,
    RightThumb,
    RightIndex,
    RightMiddle,
    RightRing,
    RightLittle,
}

impl Finger {
    /// Every finger, in the order a picker lists them.
    pub const ALL: [Self; 10] = [
        Self::RightIndex,
        Self::LeftIndex,
        Self::RightThumb,
        Self::LeftThumb,
        Self::RightMiddle,
        Self::LeftMiddle,
        Self::RightRing,
        Self::LeftRing,
        Self::RightLittle,
        Self::LeftLittle,
    ];

    /// The word on the sensor and on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeftThumb => "left-thumb",
            Self::LeftIndex => "left-index",
            Self::LeftMiddle => "left-middle",
            Self::LeftRing => "left-ring",
            Self::LeftLittle => "left-little",
            Self::RightThumb => "right-thumb",
            Self::RightIndex => "right-index",
            Self::RightMiddle => "right-middle",
            Self::RightRing => "right-ring",
            Self::RightLittle => "right-little",
        }
    }

    /// What to call it on screen.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LeftThumb => "Left thumb",
            Self::LeftIndex => "Left index finger",
            Self::LeftMiddle => "Left middle finger",
            Self::LeftRing => "Left ring finger",
            Self::LeftLittle => "Left little finger",
            Self::RightThumb => "Right thumb",
            Self::RightIndex => "Right index finger",
            Self::RightMiddle => "Right middle finger",
            Self::RightRing => "Right ring finger",
            Self::RightLittle => "Right little finger",
        }
    }

    /// The inverse of [`Self::as_str`]. `None` for a record some other stack
    /// wrote under a name this one does not use.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.as_str() == word)
    }
}

/// Where an account has said a finger may stand in for its password.
///
/// Everything is off until the account's owner turns it on, and turning any of
/// it on takes the password: a finger is a weaker proof than a password in one
/// important way -- it can be enrolled by whoever is sitting at an unlocked
/// machine -- so the switch that trusts it is guarded by the stronger one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FingerPolicy {
    /// At the login screen, for this account.
    pub login: bool,
    /// At the lock screen, for this account's own session.
    pub unlock: bool,
    /// In place of the password `sudo` asks for.
    pub sudo: bool,
}

impl FingerPolicy {
    /// Whether `next` switches on anything this one has off -- the changes
    /// that need the password.
    #[must_use]
    pub fn widened_by(self, next: Self) -> bool {
        (next.login && !self.login) || (next.unlock && !self.unlock) || (next.sudo && !self.sudo)
    }
}

/// What the machine has in the way of a fingerprint reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Reader {
    /// `raven-fprintd` is not running, so there is nobody to ask.
    NoService,
    /// The daemon is running and there is no reader plugged in.
    Absent,
    /// A reader is there.
    Present {
        /// Good readings the sensor wants for one template.
        stages: u8,
        /// Templates stored on it, for every account.
        stored: u8,
        /// Firmware version, as the sensor reports it.
        firmware: String,
    },
}

impl Reader {
    #[must_use]
    pub fn is_present(&self) -> bool {
        matches!(self, Self::Present { .. })
    }
}

/// Greeter to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Who can log in? Answered with [`Response::Users`].
    ListUsers,
    /// What should the login screen be drawn on? Answered with
    /// [`Response::Wallpaper`].
    Wallpaper,
    /// Check this password and, if it is right, start this account's session.
    ///
    /// Only ever valid on [`SOCKET_PATH`]. The verify socket rejects it, and
    /// that rejection is the reason the lock screen cannot be tricked into
    /// starting a second session for somebody.
    Authenticate { username: String, secret: Secret },
    /// Whose connection is this? Answered with [`Response::You`], resolved from
    /// the peer's credentials.
    ///
    /// The lock screen uses it to draw the right name and avatar without
    /// parsing `/etc/passwd` itself. Only valid on [`VERIFY_SOCKET_PATH`].
    Whoami,
    /// Is this the password of the account that owns this connection?
    ///
    /// Deliberately carries no username. The account is the peer's, always, so
    /// there is no field an attacker could put somebody else's name in. Only
    /// valid on [`VERIFY_SOCKET_PATH`]; answered with [`Response::Verified`] or
    /// [`Response::Denied`], and never with anything that starts a session.
    Verify { secret: Secret },

    /// Watch the reader for this connection's account, and let the lock screen
    /// go if one of its fingers is presented.
    ///
    /// Carries no username, like `Verify`, and for the same reason. Only valid
    /// on [`VERIFY_SOCKET_PATH`]. Answered with [`Response::FingerUnavailable`]
    /// if the account has not turned this on or has nothing enrolled;
    /// otherwise with a run of [`Response::Finger`] and then exactly one of
    /// [`Response::Verified`], [`Response::Denied`] or [`Response::Failed`].
    ///
    /// The connection *is* the watch: it is closed by the daemon once the
    /// verdict is sent, and if the client closes it first the daemon puts the
    /// reader down. There is no cancel request, because a cancel that had to
    /// be delivered is a sensor left running for a lock screen that has died.
    WatchFinger,
    /// Watch the reader for this account, and log it in if one of its fingers
    /// is presented.
    ///
    /// Only valid on [`SOCKET_PATH`], and only for an account whose owner has
    /// turned fingerprint login on. The account is named because at the login
    /// screen nobody is logged in to be the connection's owner -- but the name
    /// only chooses whose fingers count: a finger enrolled to anybody else is
    /// a miss, however cleanly it matches. Streams like `WatchFinger`, ending
    /// in [`Response::Granted`] rather than `Verified`.
    LoginByFinger { username: String },
    /// Is there a reader, which of this account's fingers are enrolled, and
    /// where has it said they may be used? Only valid on
    /// [`VERIFY_SOCKET_PATH`]; answered with [`Response::FingerStatus`].
    FingerStatus,
    /// Enrol one of this account's fingers, replacing any template it already
    /// has. Takes the password: see [`FingerPolicy`].
    ///
    /// Only valid on [`VERIFY_SOCKET_PATH`]. Streams [`Response::Finger`] with
    /// progress, then one of [`Response::FingerEnrolled`], [`Response::Denied`]
    /// (the password) or [`Response::Failed`], and the connection closes.
    EnrolFinger { finger: Finger, secret: Secret },
    /// Forget one of this account's fingers, or all of them with `None`.
    /// Never another account's. Answered with [`Response::FingerStatus`].
    ForgetFinger { finger: Option<Finger> },
    /// Change where this account's fingers may be used. `secret` is required
    /// when the change switches anything on, and ignored otherwise. Answered
    /// with [`Response::FingerStatus`] or [`Response::Denied`].
    SetFingerPolicy {
        policy: FingerPolicy,
        secret: Option<Secret>,
    },
}

/// Daemon to greeter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    Users {
        users: Vec<User>,
    },
    /// Where the wallpaper is, if the machine has one configured.
    ///
    /// A path and not the pixels. The daemon reads `login.toml` and so is the
    /// only process that knows what the administrator wrote there, but it must
    /// not be the process that opens the file: ravend runs as root, and a
    /// privileged process that opens whatever a config file names is a
    /// privileged process that can be pointed at something else. The greeter
    /// opens it, unprivileged, and if it is missing or unreadable *by the
    /// greeter* then it does not get drawn -- which is the correct outcome and
    /// not a thing worth failing a login over.
    ///
    /// `None` means `login.toml` names no wallpaper, which is the default and
    /// is not the end of the question: the greeter then looks at
    /// `/usr/share/wallpaper/set`, which is where the machine keeps the
    /// wallpaper somebody chose and what the session compositor draws behind
    /// the desktop. That lookup is deliberately the greeter's and not the
    /// daemon's -- it is a fixed path being read by the process that has to be
    /// able to read it anyway, so routing it through a root process that then
    /// hands the answer back would add a privileged step and no check.
    Wallpaper {
        path: Option<String>,
    },
    /// The password was right and the session is starting. The greeter should
    /// stop drawing and exit; the daemon is about to take its compositor down.
    Granted {
        username: String,
    },
    /// The attempt failed. `message` is already filtered for display — the
    /// daemon decided what is safe to say, so the greeter can render it
    /// verbatim without a second policy of its own.
    Denied {
        message: String,
        /// How long before another attempt will be accepted. Zero means now.
        /// The greeter uses this to disable the field and show a countdown
        /// rather than letting someone type into a box that will refuse them.
        retry_after_ms: u64,
    },
    /// Whose connection this is. The answer to [`Request::Whoami`].
    You {
        user: User,
    },
    /// The password was right. The lock screen may let go.
    ///
    /// Distinct from [`Response::Granted`], which means "a session is starting
    /// and you should exit". Nothing starts here; the session was already
    /// running, and this only says the person at the keyboard is its owner.
    Verified,
    /// Something is wrong with the machine, not with the password — an
    /// unreadable `/etc/shadow`, a session that would not start.
    Failed {
        message: String,
    },
    /// One reading, mid-watch or mid-enrolment. Not a verdict.
    Finger {
        /// Already filtered for display, as `Denied`'s message is.
        message: String,
        /// Enrolment only: good readings so far, and how many are wanted.
        progress: Option<(u8, u8)>,
    },
    /// The reader cannot be offered for this, and the screen should show only
    /// the password. Not an error: no reader, nothing enrolled and "the owner
    /// has not turned this on" are all ordinary.
    FingerUnavailable {
        /// Why, for a log line or a settings panel. A login screen shows
        /// nothing at all rather than this.
        reason: String,
    },
    /// The answer to [`Request::FingerStatus`], and to the requests that
    /// change it.
    FingerStatus {
        reader: Reader,
        enrolled: Vec<Finger>,
        policy: FingerPolicy,
    },
    /// An enrolment finished and the template is on the sensor.
    FingerEnrolled {
        finger: Finger,
    },
}

/// Framing and transport failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error on the greeter socket: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("message of {size} bytes exceeds the {MAX_MESSAGE}-byte limit")]
    TooLarge { size: usize },
    #[error("the peer closed the connection")]
    Closed,
}

/// Write one message: a 4-byte big-endian length, then the JSON.
pub fn write_message<W: Write, T: Serialize>(writer: &mut W, message: &T) -> Result<(), Error> {
    let body = serde_json::to_vec(message)?;
    if body.len() > MAX_MESSAGE {
        return Err(Error::TooLarge { size: body.len() });
    }
    // A single write for the header and body together. Two writes would let a
    // reader see a length with no payload behind it yet, which is harmless over
    // a stream socket but makes packet captures confusing for no reason.
    let mut framed = Vec::with_capacity(4 + body.len());
    let len = u32::try_from(body.len()).map_err(|_| Error::TooLarge { size: body.len() })?;
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&body);
    writer.write_all(&framed)?;
    writer.flush()?;
    Ok(())
}

/// Read one message.
///
/// The length is checked against [`MAX_MESSAGE`] *before* the buffer is
/// allocated, which is the only ordering that makes the limit mean anything.
pub fn read_message<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> Result<T, Error> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Error::Closed),
        Err(e) => return Err(Error::Io(e)),
    }

    let size = u32::from_be_bytes(header) as usize;
    if size > MAX_MESSAGE {
        return Err(Error::TooLarge { size });
    }

    let mut body = vec![0u8; size];
    match reader.read_exact(&mut body) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Error::Closed),
        Err(e) => return Err(Error::Io(e)),
    }

    let message = serde_json::from_slice(&body)?;
    // The body held a password on its way in. Wipe it rather than leaving it
    // for the allocator; the deserialized `Secret` wipes its own copy on drop.
    body.zeroize();
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips() {
        let request = Request::Authenticate {
            username: "javan".to_string(),
            secret: Secret::new("hunter2".to_string()),
        };
        let mut buffer = Vec::new();
        write_message(&mut buffer, &request).expect("writes");

        let decoded: Request = read_message(&mut buffer.as_slice()).expect("reads");
        match decoded {
            Request::Authenticate { username, secret } => {
                assert_eq!(username, "javan");
                assert_eq!(secret.as_bytes(), b"hunter2");
            }
            other => panic!("expected Authenticate, got {other:?}"),
        }
    }

    #[test]
    fn a_response_round_trips() {
        let response = Response::Users {
            users: vec![User {
                name: "javan".to_string(),
                display_name: "Javan".to_string(),
                initial: 'J',
            }],
        };
        let mut buffer = Vec::new();
        write_message(&mut buffer, &response).expect("writes");
        let decoded: Response = read_message(&mut buffer.as_slice()).expect("reads");
        assert!(matches!(decoded, Response::Users { users } if users.len() == 1));
    }

    /// The wallpaper exchange, both halves. A path is the only thing in this
    /// protocol that is neither a name nor a secret, so it is the one worth
    /// checking survives the trip both ways -- including the `None` a machine
    /// with no wallpaper answers with, which serializes differently.
    #[test]
    fn a_wallpaper_round_trips() {
        let mut buffer = Vec::new();
        write_message(&mut buffer, &Request::Wallpaper).expect("writes");
        let decoded: Request = read_message(&mut buffer.as_slice()).expect("reads");
        assert!(matches!(decoded, Request::Wallpaper));

        for path in [Some("/usr/share/raven/wallpaper.png".to_string()), None] {
            let mut buffer = Vec::new();
            write_message(&mut buffer, &Response::Wallpaper { path: path.clone() })
                .expect("writes");
            let decoded: Response = read_message(&mut buffer.as_slice()).expect("reads");
            match decoded {
                Response::Wallpaper { path: got } => assert_eq!(got, path),
                other => panic!("expected Wallpaper, got {other:?}"),
            }
        }
    }

    /// Several messages down one stream must not run into each other.
    #[test]
    fn messages_are_framed_independently() {
        let mut buffer = Vec::new();
        write_message(&mut buffer, &Request::ListUsers).expect("writes");
        write_message(
            &mut buffer,
            &Request::Authenticate {
                username: "a".to_string(),
                secret: Secret::new("b".to_string()),
            },
        )
        .expect("writes");

        let mut stream = buffer.as_slice();
        assert!(matches!(
            read_message::<_, Request>(&mut stream).expect("first"),
            Request::ListUsers
        ));
        assert!(matches!(
            read_message::<_, Request>(&mut stream).expect("second"),
            Request::Authenticate { .. }
        ));
        assert!(matches!(
            read_message::<_, Request>(&mut stream),
            Err(Error::Closed)
        ));
    }

    /// The size cap must be enforced from the header, before any allocation.
    #[test]
    fn an_oversized_length_is_refused_without_allocating() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        // No body at all: if the limit were checked after reading, this would
        // block or allocate 4 GiB rather than returning.
        let err = read_message::<_, Request>(&mut framed.as_slice()).expect_err("must refuse");
        assert!(matches!(err, Error::TooLarge { .. }), "got {err:?}");
    }

    #[test]
    fn a_truncated_body_is_a_clean_close_not_a_hang() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&100u32.to_be_bytes());
        framed.extend_from_slice(b"{\"request\":");
        assert!(matches!(
            read_message::<_, Request>(&mut framed.as_slice()),
            Err(Error::Closed)
        ));
    }

    /// Finger names on the wire are the words on the sensor, so a record, a
    /// message and a policy file all say `right-index`.
    #[test]
    fn fingers_are_named_as_the_sensor_names_them() {
        for finger in Finger::ALL {
            let json = serde_json::to_string(&finger).expect("serializes");
            assert_eq!(json, format!("\"{}\"", finger.as_str()));
            assert_eq!(Finger::parse(finger.as_str()), Some(finger));
        }
        assert_eq!(Finger::parse("sixth-finger"), None);
    }

    /// The lock screen's watch carries no account, like `Verify`.
    #[test]
    fn watch_finger_names_no_account() {
        let mut wire = Vec::new();
        write_message(&mut wire, &Request::WatchFinger).expect("serializes");
        assert!(!String::from_utf8_lossy(&wire).contains("username"));
    }

    /// Enrolment carries the password, so it must be as redacted as `Verify`.
    #[test]
    fn an_enrolment_password_is_redacted() {
        let request = Request::EnrolFinger {
            finger: Finger::RightIndex,
            secret: Secret::new("hunter2".to_string()),
        };
        assert!(!format!("{request:?}").contains("hunter2"));
    }

    #[test]
    fn finger_status_round_trips() {
        let response = Response::FingerStatus {
            reader: Reader::Present {
                stages: 9,
                stored: 1,
                firmware: "0104".to_string(),
            },
            enrolled: vec![Finger::RightIndex],
            policy: FingerPolicy {
                login: false,
                unlock: true,
                sudo: true,
            },
        };
        let mut buffer = Vec::new();
        write_message(&mut buffer, &response).expect("writes");
        match read_message(&mut buffer.as_slice()).expect("reads") {
            Response::FingerStatus {
                reader,
                enrolled,
                policy,
            } => {
                assert!(reader.is_present());
                assert_eq!(enrolled, vec![Finger::RightIndex]);
                assert!(policy.unlock && policy.sudo && !policy.login);
            }
            other => panic!("expected FingerStatus, got {other:?}"),
        }
    }

    /// The single most valuable property in this file: a password cannot be
    /// logged by accident.
    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let secret = Secret::new("hunter2".to_string());
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");

        let request = Request::Authenticate {
            username: "javan".to_string(),
            secret,
        };
        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains("hunter2"),
            "a password reached Debug output: {rendered}"
        );
        assert!(
            rendered.contains("javan"),
            "the username should still be visible"
        );
    }

    /// ...but it must still serialize as a plain string, or the daemon cannot
    /// read what the greeter sent.
    #[test]
    fn secrets_serialize_transparently() {
        let json = serde_json::to_string(&Secret::new("hunter2".to_string())).expect("serializes");
        assert_eq!(json, "\"hunter2\"");
    }
}
