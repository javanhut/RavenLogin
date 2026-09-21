//! Watching the camera for this session's owner.
//!
//! [`crate::finger`]'s shape, with the same two differences from the greeter's
//! that the reader's watch has -- it asks on the verify socket, where the
//! account is the connection's own and never named, and its channel is a
//! calloop source rather than something drained per frame -- and one of its
//! own: the wash.
//!
//! # Why the wash matters more here than at the login screen
//!
//! A lock screen spends most of its life with the panel off. The liveness
//! check needs the panel *on*, throwing a known sequence of colours at
//! somebody's face, so the watch has to be able to light the screen up before
//! anybody has touched anything. That is what the calloop source is for: a
//! [`Event::Wash`] arriving while nothing is being drawn still reaches the
//! screen, and the frame it asks for follows it.

use std::os::unix::net::UnixStream;

use raven_greet_proto::{Request, Response, VERIFY_SOCKET_PATH, Wash};
use smithay_client_toolkit::reexports::calloop::channel::{Channel, Sender, channel};

/// What the camera has done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// Something to show under the field.
    Prompt(String),
    /// Paint the screen, or stop. Not a thing to display.
    Wash(Wash),
    /// This session's owner. The screen may let go.
    Verified,
    /// The face was not recognised enough times; the password is the way in.
    Denied(String),
    /// Not offered: no camera, no models, nothing enrolled, or not turned on.
    /// Asking again will get the same answer.
    Unavailable,
    /// The watch broke without a verdict -- the daemon restarted, the camera
    /// was unplugged. Asking again later may work.
    Ended,
}

/// A watch on the camera. Dropping it cancels it.
#[derive(Debug)]
pub(crate) struct FaceWatch {
    stream: UnixStream,
}

impl FaceWatch {
    /// Start watching. Events arrive on the returned channel, which the
    /// caller puts in its event loop.
    pub(crate) fn start() -> Option<(Self, Channel<Event>)> {
        let mut stream = match UnixStream::connect(VERIFY_SOCKET_PATH) {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!("cannot open a second connection to ravend: {e}");
                return None;
            }
        };
        // The claim that this screen will run the liveness challenge; see the
        // greeter's `face` module for why saying it is not the same as being
        // believed.
        if let Err(e) =
            raven_greet_proto::write_message(&mut stream, &Request::WatchFace { flash: true })
        {
            tracing::warn!("cannot ask ravend to watch the camera: {e}");
            return None;
        }
        let reader = stream.try_clone().ok()?;
        let (tx, rx) = channel();
        let spawned = std::thread::Builder::new()
            .name("face".to_string())
            .spawn(move || listen(reader, &tx));
        if let Err(e) = spawned {
            tracing::warn!("cannot start the face thread: {e}");
            return None;
        }
        Some((Self { stream }, rx))
    }
}

fn listen(mut reader: UnixStream, tx: &Sender<Event>) {
    loop {
        // One message can carry both a colour to paint and a sentence to show.
        let (events, last) = match raven_greet_proto::read_message::<_, Response>(&mut reader) {
            Ok(Response::Face { message, flash, .. }) => {
                let mut events = Vec::new();
                if let Some(wash) = flash {
                    events.push(Event::Wash(wash));
                }
                if !message.is_empty() {
                    events.push(Event::Prompt(message));
                }
                (events, false)
            }
            Ok(Response::Verified) => (vec![Event::Verified], true),
            Ok(Response::Denied { message, .. }) => (vec![Event::Denied(message)], true),
            Ok(Response::FaceUnavailable { reason }) => {
                tracing::info!("the camera is not offered: {reason}");
                (vec![Event::Unavailable], true)
            }
            Ok(Response::Failed { message }) => {
                tracing::warn!("the face watch failed: {message}");
                (vec![Event::Ended], true)
            }
            Ok(other) => {
                tracing::warn!("unexpected reply to a face watch: {other:?}");
                (vec![Event::Ended], true)
            }
            Err(_) => (vec![Event::Ended], true),
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
}

impl Drop for FaceWatch {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
