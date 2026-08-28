//! Asking `ravend` whether this is the right password.
//!
//! A different socket from the greeter's, and a smaller conversation. This one
//! cannot start a session, cannot name an account, and answers only about the
//! account that owns the connection -- see `VERIFY_SOCKET_PATH` in the protocol
//! crate for why that restriction is what makes a world-connectable socket
//! safe.
//!
//! Blocking, for the same reason the greeter's client is: a password check is a
//! few milliseconds, and a lock screen that can be halfway through an
//! asynchronous authentication when a key arrives is a lock screen with a state
//! machine nobody wants to reason about.

use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context, Result};
use raven_greet_proto::{Request, Response, Secret, User, VERIFY_SOCKET_PATH};

/// How long to wait for the daemon to answer.
const TIMEOUT: Duration = Duration::from_secs(20);

/// A connection to `ravend`'s verify socket.
#[derive(Debug)]
pub(crate) struct Client {
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
}

impl Client {
    pub(crate) fn connect() -> Result<Self> {
        let stream = UnixStream::connect(VERIFY_SOCKET_PATH).with_context(|| {
            format!("cannot connect to {VERIFY_SOCKET_PATH}; is ravend running?")
        })?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .context("cannot set a read timeout")?;
        stream
            .set_write_timeout(Some(TIMEOUT))
            .context("cannot set a write timeout")?;

        Ok(Self {
            reader: BufReader::new(stream.try_clone().context("cannot clone the socket")?),
            writer: BufWriter::new(stream),
        })
    }

    fn exchange(&mut self, request: &Request) -> Result<Response> {
        raven_greet_proto::write_message(&mut self.writer, request)
            .context("cannot send a request to ravend")?;
        raven_greet_proto::read_message(&mut self.reader).context("cannot read a reply from ravend")
    }

    /// Whose session this is.
    ///
    /// Asked rather than worked out locally, and not to save the `/etc/passwd`
    /// parsing: the daemon answers from the connection's own credentials, so
    /// the name on the screen is the account the password will actually be
    /// checked against. Reading the name here and letting the daemon decide the
    /// account separately would be two answers that could differ.
    pub(crate) fn whoami(&mut self) -> Result<User> {
        match self.exchange(&Request::Whoami)? {
            Response::You { user } => Ok(user),
            Response::Failed { message } => anyhow::bail!("{message}"),
            other => anyhow::bail!("unexpected reply to Whoami: {other:?}"),
        }
    }

    /// Check a password.
    pub(crate) fn verify(&mut self, password: String) -> Result<Attempt> {
        let request = Request::Verify {
            secret: Secret::new(password),
        };
        match self.exchange(&request)? {
            Response::Verified => Ok(Attempt::Verified),
            Response::Denied {
                message,
                retry_after_ms,
            } => Ok(Attempt::Denied {
                message,
                retry_after: Duration::from_millis(retry_after_ms),
            }),
            Response::Failed { message } => Ok(Attempt::Failed { message }),
            other => anyhow::bail!("unexpected reply to Verify: {other:?}"),
        }
    }
}

/// What came back from an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Attempt {
    /// The right password. The screen may let go.
    Verified,
    /// Wrong, or throttled. `message` is already safe to display.
    Denied {
        message: String,
        retry_after: Duration,
    },
    /// The machine is broken, not the password.
    Failed { message: String },
}
