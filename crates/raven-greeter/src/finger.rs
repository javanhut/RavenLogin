//! Watching the fingerprint reader for the account on screen.
//!
//! On its own connection and its own thread, unlike everything in `client`.
//! A watch has no deadline -- it lasts as long as somebody is looking at the
//! login screen deciding whether to type -- so it cannot share the connection
//! the password goes down, and it cannot block the thread that draws.
//!
//! The thread only reads. What it hears goes into a channel the frame loop
//! drains, so the screen changes on the next frame and the state machine stays
//! on one thread. Dropping a [`FingerWatch`] shuts the socket, which is how
//! `ravend` learns to put the reader down: there is no cancel message to send.

use std::os::unix::net::UnixStream;
use std::sync::mpsc;

use raven_greet_proto::{Request, Response, SOCKET_PATH};

/// What the reader has done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// Something to show under the field. The first is the invitation; any
    /// after it are corrections.
    Prompt(String),
    /// A finger of this account's, and the session is starting.
    Granted,
    /// Too many fingers were not recognised; the password is the way in.
    Denied(String),
    /// The watch is over without a verdict -- not offered, or broken. The
    /// screen should quietly stop mentioning the reader.
    Ended,
}

/// A watch on the reader for one account.
#[derive(Debug)]
pub(crate) struct FingerWatch {
    username: String,
    events: mpsc::Receiver<Event>,
    stream: UnixStream,
}

impl FingerWatch {
    /// Ask `ravend` to watch for `username`'s fingers.
    ///
    /// `None` if the daemon cannot be reached. Whether the account has a
    /// finger to offer is not known here -- the daemon answers that with an
    /// `Ended` a moment later, which is also what a machine with no reader
    /// gets, so the screen treats all of them the same way: by saying nothing.
    pub(crate) fn start(username: &str) -> Option<Self> {
        let mut stream = match UnixStream::connect(SOCKET_PATH) {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!("cannot open a second connection to ravend: {e}");
                return None;
            }
        };
        let request = Request::LoginByFinger {
            username: username.to_string(),
        };
        if let Err(e) = raven_greet_proto::write_message(&mut stream, &request) {
            tracing::warn!("cannot ask ravend to watch the reader: {e}");
            return None;
        }
        let mut reader = stream.try_clone().ok()?;
        let (tx, events) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("finger".to_string())
            .spawn(move || {
                loop {
                    let event = match raven_greet_proto::read_message::<_, Response>(&mut reader) {
                        Ok(Response::Finger { message, .. }) => Event::Prompt(message),
                        Ok(Response::Granted { .. }) => Event::Granted,
                        Ok(Response::Denied { message, .. }) => Event::Denied(message),
                        Ok(Response::FingerUnavailable { reason }) => {
                            tracing::info!("the reader is not offered: {reason}");
                            Event::Ended
                        }
                        Ok(Response::Failed { message }) => {
                            tracing::warn!("the fingerprint watch failed: {message}");
                            Event::Ended
                        }
                        Ok(other) => {
                            tracing::warn!("unexpected reply to a finger watch: {other:?}");
                            Event::Ended
                        }
                        Err(_) => Event::Ended,
                    };
                    let last = !matches!(event, Event::Prompt(_));
                    if tx.send(event).is_err() || last {
                        return;
                    }
                }
            });
        if let Err(e) = spawned {
            tracing::warn!("cannot start the finger thread: {e}");
            return None;
        }
        Some(Self {
            username: username.to_string(),
            events,
            stream,
        })
    }

    /// Whose fingers this is watching for.
    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    /// Everything that has happened since the last call.
    pub(crate) fn drain(&self) -> Vec<Event> {
        self.events.try_iter().collect()
    }
}

impl Drop for FingerWatch {
    fn drop(&mut self) {
        // The only way a watch is ever cancelled.
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
