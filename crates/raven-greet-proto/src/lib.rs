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

/// Greeter to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Who can log in? Answered with [`Response::Users`].
    ListUsers,
    /// Check this password and, if it is right, start this account's session.
    Authenticate { username: String, secret: Secret },
}

/// Daemon to greeter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    Users {
        users: Vec<User>,
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
    /// Something is wrong with the machine, not with the password — an
    /// unreadable `/etc/shadow`, a session that would not start.
    Failed {
        message: String,
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
