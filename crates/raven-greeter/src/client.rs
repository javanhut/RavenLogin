//! Talking to `ravend`.
//!
//! Blocking, and single-threaded on purpose. The two things this asks for — the
//! user list, and a password check — take microseconds and a few milliseconds
//! respectively, and the daemon answers a refused attempt immediately with a
//! `retry_after_ms` rather than sleeping on it. So there is nothing here worth
//! the machinery of doing it off the event loop, and a login screen that can
//! be in the middle of an asynchronous authentication when a key arrives is a
//! login screen with a state machine nobody wants to reason about.
//!
//! The one real risk is the daemon going away, which is why the socket carries
//! timeouts: a greeter blocked forever on a read is a black screen with a
//! cursor, and the only way out is the power button.

use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context, Result};
use raven_greet_proto::{Request, Response, SOCKET_PATH, Secret, User};

/// How long to wait for the daemon to answer.
///
/// Comfortably longer than a password check (about 4ms) but short enough that
/// a wedged daemon becomes an error message rather than a hang.
const TIMEOUT: Duration = Duration::from_secs(20);

/// A connection to `ravend`.
#[derive(Debug)]
pub(crate) struct Client {
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
}

impl Client {
    /// Connect to the daemon's socket.
    pub(crate) fn connect() -> Result<Self> {
        let stream = UnixStream::connect(SOCKET_PATH)
            .with_context(|| format!("cannot connect to {SOCKET_PATH}; is ravend running?"))?;
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

    /// Who can log in.
    pub(crate) fn list_users(&mut self) -> Result<Vec<User>> {
        match self.exchange(&Request::ListUsers)? {
            Response::Users { users } => Ok(users),
            Response::Failed { message } => anyhow::bail!("{message}"),
            other => anyhow::bail!("unexpected reply to ListUsers: {other:?}"),
        }
    }

    /// Where the wallpaper is, if the machine has one.
    ///
    /// The daemon answers with a path and never opens it; this process does,
    /// unprivileged. A machine with none configured answers `None`, which is
    /// the default and not an error.
    pub(crate) fn wallpaper(&mut self) -> Result<Option<std::path::PathBuf>> {
        match self.exchange(&Request::Wallpaper)? {
            Response::Wallpaper { path } => Ok(path.map(std::path::PathBuf::from)),
            Response::Failed { message } => anyhow::bail!("{message}"),
            other => anyhow::bail!("unexpected reply to Wallpaper: {other:?}"),
        }
    }

    /// Try to log in. On [`Attempt::Granted`] the session is already starting
    /// and this process is about to be stopped.
    pub(crate) fn authenticate(&mut self, username: &str, password: String) -> Result<Attempt> {
        let request = Request::Authenticate {
            username: username.to_string(),
            secret: Secret::new(password),
        };
        match self.exchange(&request)? {
            Response::Granted { .. } => Ok(Attempt::Granted),
            Response::Denied {
                message,
                retry_after_ms,
            } => Ok(Attempt::Denied {
                message,
                retry_after: Duration::from_millis(retry_after_ms),
            }),
            Response::Failed { message } => Ok(Attempt::Failed { message }),
            other => anyhow::bail!("unexpected reply to Authenticate: {other:?}"),
        }
    }
}

/// What came back from an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Attempt {
    /// The session is starting.
    Granted,
    /// Wrong, or not allowed. `message` is already safe to display — the
    /// daemon decided what could be said, so there is no second policy here.
    Denied {
        message: String,
        retry_after: Duration,
    },
    /// The machine is broken, not the password.
    Failed { message: String },
}
