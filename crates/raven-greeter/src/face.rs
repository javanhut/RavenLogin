//! Watching the camera for the account on screen.
//!
//! [`crate::finger`]'s shape exactly -- its own connection, its own thread, a
//! channel the frame loop drains, cancelled by being dropped -- with one thing
//! the reader's watch does not have: the wash.
//!
//! # The screen is part of the check
//!
//! `raven-faced` decides that the face in front of the camera is a live one by
//! throwing light at it and watching what comes back, and the light comes from
//! this screen. So a [`Event::Wash`] is not a thing to display: it is an
//! instruction to paint, and it has to reach the panel within a frame or two
//! or the daemon sees the colour arrive late and calls the face a photograph.
//! That is why the watch is started even before anybody has pressed a key, and
//! why the frame loop drains this channel before it draws rather than after.
//!
//! The greeter is told what to paint and never why. It does not know the
//! sequence in advance -- it could not, or a compromised greeter would be able
//! to play one back -- and it does not know whether any given watch passed.

use std::os::unix::net::UnixStream;
use std::sync::mpsc;

use raven_greet_proto::{Request, Response, SOCKET_PATH, Wash};

/// What the camera has done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// Something to show under the field. The first is the invitation; any
    /// after it are corrections.
    Prompt(String),
    /// Paint the screen, or stop. Not a thing to display.
    Wash(Wash),
    /// This account's face, and the session is starting.
    Granted,
    /// The face was not recognised enough times; the password is the way in.
    Denied(String),
    /// The watch is over without a verdict -- not offered, or broken. The
    /// screen should quietly stop mentioning the camera.
    Ended,
}

/// A watch on the camera for one account.
#[derive(Debug)]
pub(crate) struct FaceWatch {
    username: String,
    events: mpsc::Receiver<Event>,
    stream: UnixStream,
}

impl FaceWatch {
    /// Ask `ravend` to watch for `username`'s face.
    ///
    /// `None` if the daemon cannot be reached. Whether the account has a face
    /// to offer is not known here -- the daemon answers that with an `Ended` a
    /// moment later, which is also what a machine with no camera gets, so the
    /// screen treats all of them the same way: by saying nothing.
    pub(crate) fn start(username: &str) -> Option<Self> {
        let mut stream = match UnixStream::connect(SOCKET_PATH) {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!("cannot open a second connection to ravend: {e}");
                return None;
            }
        };
        // The claim that this screen will run the liveness challenge. It is
        // true because `poll_face` acts on every `Wash` before the next frame;
        // `raven-faced` checks rather than believes it, so a greeter that
        // stopped painting would simply stop being able to let anybody in.
        let request = Request::LoginByFace {
            username: username.to_string(),
            flash: true,
        };
        if let Err(e) = raven_greet_proto::write_message(&mut stream, &request) {
            tracing::warn!("cannot ask ravend to watch the camera: {e}");
            return None;
        }
        let mut reader = stream.try_clone().ok()?;
        let (tx, events) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("face".to_string())
            .spawn(move || {
                loop {
                    let mut events = Vec::new();
                    let last = match raven_greet_proto::read_message::<_, Response>(&mut reader) {
                        // One message can carry both a colour to paint and a
                        // sentence to show, and usually carries exactly one of
                        // them, so neither is assumed.
                        Ok(Response::Face { message, flash, .. }) => {
                            if let Some(wash) = flash {
                                events.push(Event::Wash(wash));
                            }
                            if !message.is_empty() {
                                events.push(Event::Prompt(message));
                            }
                            false
                        }
                        Ok(Response::Granted { .. }) => {
                            events.push(Event::Granted);
                            true
                        }
                        Ok(Response::Denied { message, .. }) => {
                            events.push(Event::Denied(message));
                            true
                        }
                        Ok(Response::FaceUnavailable { reason }) => {
                            tracing::info!("the camera is not offered: {reason}");
                            events.push(Event::Ended);
                            true
                        }
                        Ok(Response::Failed { message }) => {
                            tracing::warn!("the face watch failed: {message}");
                            events.push(Event::Ended);
                            true
                        }
                        Ok(other) => {
                            tracing::warn!("unexpected reply to a face watch: {other:?}");
                            events.push(Event::Ended);
                            true
                        }
                        Err(_) => {
                            events.push(Event::Ended);
                            true
                        }
                    };
                    for event in events {
                        if tx.send(event).is_err() {
                            return;
                        }
                    }
                    if last {
                        return;
                    }
                }
            });
        if let Err(e) = spawned {
            tracing::warn!("cannot start the face thread: {e}");
            return None;
        }
        Some(Self {
            username: username.to_string(),
            events,
            stream,
        })
    }

    /// Whose face this is watching for.
    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    /// Everything that has happened since the last call.
    pub(crate) fn drain(&self) -> Vec<Event> {
        self.events.try_iter().collect()
    }
}

impl Drop for FaceWatch {
    fn drop(&mut self) {
        // The only way a watch is ever cancelled.
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
