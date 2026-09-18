//! Watching the fingerprint reader for this session's owner.
//!
//! The same shape as the greeter's watch -- its own connection, its own
//! thread, a channel back to the screen, cancelled by being dropped -- with two
//! differences. It asks on the verify socket, where the account is the
//! connection's own and never named. And the channel is a calloop source rather
//! than something drained per frame: a lock screen spends most of its life with
//! the panel off and no frames arriving, and a finger on the sensor then has to
//! unlock the machine without waiting for somebody to wake the display first.

use std::os::unix::net::UnixStream;

use raven_greet_proto::{Request, Response, VERIFY_SOCKET_PATH};
use smithay_client_toolkit::reexports::calloop::channel::{Channel, Sender, channel};

/// What the reader has done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// Something to show under the field.
    Prompt(String),
    /// One of this account's fingers. The screen may let go.
    Verified,
    /// Too many fingers were not recognised; the password is the way in.
    Denied(String),
    /// Not offered: no reader, nothing enrolled, or not turned on. Asking
    /// again will get the same answer.
    Unavailable,
    /// The watch broke without a verdict -- the daemon restarted, the reader
    /// was unplugged. Asking again later may work.
    Ended,
}

/// A watch on the reader. Dropping it cancels it.
#[derive(Debug)]
pub(crate) struct FingerWatch {
    stream: UnixStream,
}

impl FingerWatch {
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
        if let Err(e) = raven_greet_proto::write_message(&mut stream, &Request::WatchFinger) {
            tracing::warn!("cannot ask ravend to watch the reader: {e}");
            return None;
        }
        let reader = stream.try_clone().ok()?;
        let (tx, rx) = channel();
        let spawned = std::thread::Builder::new()
            .name("finger".to_string())
            .spawn(move || listen(reader, &tx));
        if let Err(e) = spawned {
            tracing::warn!("cannot start the finger thread: {e}");
            return None;
        }
        Some((Self { stream }, rx))
    }
}

fn listen(mut reader: UnixStream, tx: &Sender<Event>) {
    loop {
        let event = match raven_greet_proto::read_message::<_, Response>(&mut reader) {
            Ok(Response::Finger { message, .. }) => Event::Prompt(message),
            Ok(Response::Verified) => Event::Verified,
            Ok(Response::Denied { message, .. }) => Event::Denied(message),
            Ok(Response::FingerUnavailable { reason }) => {
                tracing::info!("the reader is not offered: {reason}");
                Event::Unavailable
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
}

impl Drop for FingerWatch {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
