//! The lock screen's one question: *is this the password of whoever is asking?*
//!
//! # Why this is not the greeter's socket
//!
//! A lock screen needs the same thing a login screen needs -- somebody who can
//! read `/etc/shadow` to say yes or no -- and it is tempting to hand it the
//! socket that already exists. That would be a mistake, twice over.
//!
//! The greet socket can *start a session*. A lock screen that could reach it
//! could be talked into starting a second session for an account that is not
//! the one it is holding, which is a way past the lock rather than through it.
//! And the greet socket lives in a `0700` directory owned by the greeter, which
//! is exactly right for it and exactly wrong here: the process asking is the
//! logged-in user's, and it has to be able to connect.
//!
//! So this is a second listener, with a second question, and the request it
//! answers is not the request that starts sessions.
//!
//! # Why anyone may connect to it
//!
//! The socket is world-connectable, and that is safe for one reason: it will
//! only ever answer about the account that owns the connection. The account
//! comes from `SO_PEERCRED`, which the kernel fills in and the caller cannot
//! forge, and [`Request::Verify`] carries no username at all -- there is no
//! field to put somebody else's name in.
//!
//! Take that away and this becomes a password oracle: any local process could
//! guess at any account as fast as the rate limiter allows, from a socket that
//! exists on every machine. With it, a caller can only guess at a password it
//! is already sitting behind.
//!
//! # Why it runs on its own thread
//!
//! `ravend`'s main loop is busy: it shows the login screen, then blocks waiting
//! for the session to end. The lock screen's whole life happens *inside* that
//! wait, so it cannot be served from there.

use std::io::{BufReader, BufWriter};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use raven_auth::{Account, Authenticator, Denial, Outcome};
use raven_greet_proto::{Request, Response, User, VERIFY_SOCKET_PATH};

use crate::ratelimit::{Limits, RateLimiter};

/// How long a connection may sit silent before it is dropped.
///
/// Longer than a person takes to type a password, shorter than a process can
/// usefully squat on the socket for. The lock screen holds one connection open
/// for as long as the screen is up, so this is a limit on *silence*, not on the
/// life of the connection: every message read resets it.
const READ_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a write may block.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many connections may be in flight at once.
///
/// A lock screen needs one. The rest of the allowance is for a second one
/// starting while a first is being torn down, and the cap is what stops a local
/// process from spawning a thread in this daemon for every file descriptor it
/// can open.
const MAX_CONNECTIONS: usize = 8;

/// Start serving verify requests, and return.
///
/// The listener lives on a thread of its own for the life of the daemon. A
/// failure to bind is reported and *not* fatal: a machine whose lock screen
/// cannot authenticate is a machine somebody can still log in to, and taking
/// the login daemon down over it would turn a broken lock screen into a broken
/// computer.
pub(crate) fn spawn(authenticator: Authenticator, limits: Limits) {
    let listener = match bind() {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("the lock screen will not be able to authenticate: {e:#}");
            return;
        }
    };

    // Its own limiter, not the login screen's. They throttle the same accounts
    // but they are different doors, and a person who has mistyped their
    // password at the lock screen should not find themselves unable to log in
    // on a TTY -- nor should a guessing loop at one door be able to learn
    // anything about the state of the other.
    let limiter = Arc::new(Mutex::new(RateLimiter::new(limits)));
    let authenticator = Arc::new(authenticator);
    let live = Arc::new(AtomicUsize::new(0));

    let spawned = std::thread::Builder::new()
        .name("verify".to_string())
        .spawn(move || accept_loop(&listener, &authenticator, &limiter, &live));

    match spawned {
        Ok(_) => tracing::info!(path = VERIFY_SOCKET_PATH, "listening for the lock screen"),
        Err(e) => tracing::error!("cannot start the verify thread: {e}"),
    }
}

/// Create the socket, and the directory it lives in.
fn bind() -> Result<UnixListener> {
    let path = Path::new(VERIFY_SOCKET_PATH);
    let dir = path
        .parent()
        .context("the verify socket path has no directory")?;

    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    // 0755, unlike the greeter's 0700: the person who has to reach this is the
    // one logged in, and there is no account to give it to instead.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("cannot set the mode on {}", dir.display()))?;

    // A socket left by a previous run would make bind() fail with EADDRINUSE.
    if path.exists() {
        std::fs::remove_file(path).ok();
    }

    let listener =
        UnixListener::bind(path).with_context(|| format!("cannot bind {}", path.display()))?;

    // World-connectable on purpose; see the module documentation. The peer
    // credential check, not the file mode, is what makes this safe.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .with_context(|| format!("cannot set the mode on {}", path.display()))?;

    Ok(listener)
}

/// Accept forever, one thread per connection.
///
/// A blocking accept, unlike the greeter's loop. The reason that one polls is
/// that it supervises two children between accepts; this thread has nothing
/// else to do, and a blocking accept costs no wakeups on an idle machine.
fn accept_loop(
    listener: &UnixListener,
    authenticator: &Arc<Authenticator>,
    limiter: &Arc<Mutex<RateLimiter>>,
    live: &Arc<AtomicUsize>,
) {
    loop {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!("verify accept failed: {e}");
                continue;
            }
        };

        if live.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            tracing::warn!("refusing a verify connection: too many already open");
            drop(stream);
            continue;
        }

        live.fetch_add(1, Ordering::SeqCst);
        let authenticator = Arc::clone(authenticator);
        let limiter = Arc::clone(limiter);
        let counter = Arc::clone(live);

        let spawned = std::thread::Builder::new()
            .name("verify-conn".to_string())
            .spawn(move || {
                if let Err(e) = serve(stream, &authenticator, &limiter) {
                    tracing::warn!("verify connection ended: {e:#}");
                }
                counter.fetch_sub(1, Ordering::SeqCst);
            });

        if spawned.is_err() {
            // The closure that would have decremented never ran, so the slot
            // has to be given back here or the cap leaks one on every failure.
            live.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!("cannot start a thread for a verify connection");
        }
    }
}

/// Serve one connection until it closes.
fn serve(
    stream: UnixStream,
    authenticator: &Authenticator,
    limiter: &Mutex<RateLimiter>,
) -> Result<()> {
    // Who is on the other end. Everything this function answers is about this
    // account and no other, and this is where that account is decided -- once,
    // from the kernel, before a single byte of the request has been read.
    let peer =
        rustix::net::sockopt::socket_peercred(&stream).context("cannot read peer credentials")?;
    let peer_uid = peer.uid.as_raw();

    let account = resolve(authenticator, peer_uid)?;
    tracing::info!(user = %account.name, uid = peer_uid, "a lock screen connected");

    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .context("cannot set a read timeout")?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .context("cannot set a write timeout")?;

    let mut reader = BufReader::new(stream.try_clone().context("cannot clone the stream")?);
    let mut writer = BufWriter::new(stream);

    loop {
        let request: Request = match raven_greet_proto::read_message(&mut reader) {
            Ok(request) => request,
            Err(raven_greet_proto::Error::Closed) => return Ok(()),
            Err(e) => return Err(anyhow::Error::new(e).context("cannot read a request")),
        };

        let response = answer(request, &account, authenticator, limiter);
        raven_greet_proto::write_message(&mut writer, &response)?;
    }
}

/// Turn one request into one response.
///
/// Split out from the I/O so the policy -- which requests this socket answers,
/// and which it refuses -- can be tested without a socket, a daemon or root.
fn answer(
    request: Request,
    account: &Account,
    authenticator: &Authenticator,
    limiter: &Mutex<RateLimiter>,
) -> Response {
    match request {
        Request::Whoami => Response::You {
            user: User {
                name: account.name.clone(),
                display_name: account.display_name().to_string(),
                initial: account.initial(),
            },
        },

        Request::Verify { secret } => verify(account, secret.as_bytes(), authenticator, limiter),

        // The refusal that matters. `Authenticate` is what starts a session,
        // and it is not a thing this socket does for anybody -- not for the
        // account that owns the connection, not for root. A lock screen that
        // could reach it would be a way around the lock rather than through it.
        Request::Authenticate { .. } => {
            tracing::warn!(
                user = %account.name,
                "refused an authenticate request on the verify socket"
            );
            Response::Failed {
                message: "This socket does not start sessions.".to_string(),
            }
        }

        // Not refused for safety, just not answered here: these belong to the
        // login screen, which has its own socket and its own reasons.
        Request::ListUsers | Request::Wallpaper => Response::Failed {
            message: "This socket answers only about the account that is asking.".to_string(),
        },
    }
}

/// Check a password against the connection's own account.
fn verify(
    account: &Account,
    password: &[u8],
    authenticator: &Authenticator,
    limiter: &Mutex<RateLimiter>,
) -> Response {
    let now = Instant::now();

    // Checked before the password is, so a guessing loop pays the delay whether
    // or not it guessed right.
    let wait = {
        let limiter = limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.delay_for(&account.name, now)
    };
    if !wait.is_zero() {
        tracing::warn!(user = %account.name, ?wait, "unlock refused; throttled");
        return Response::Denied {
            message: "Too many attempts. Try again shortly.".to_string(),
            retry_after_ms: wait.as_millis().try_into().unwrap_or(u64::MAX),
        };
    }

    match authenticator.authenticate(&account.name, password) {
        Ok(Outcome::Granted(_)) => {
            limiter
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_success(&account.name);
            tracing::info!(user = %account.name, "unlocked");
            Response::Verified
        }
        Ok(Outcome::Denied(denial)) => {
            let wait = {
                let mut limiter = limiter.lock().unwrap_or_else(|e| e.into_inner());
                limiter.record_failure(&account.name, now);
                limiter.delay_for(&account.name, Instant::now())
            };
            tracing::warn!(user = %account.name, ?denial, "unlock denied");
            // The same filter the login screen applies: the real reason goes to
            // the log, and the screen gets only what raven-auth says is safe to
            // put in front of somebody.
            let message = if denial.is_safe_to_display() {
                denial.message()
            } else {
                Denial::BadPassword.message()
            };
            Response::Denied {
                message,
                retry_after_ms: wait.as_millis().try_into().unwrap_or(u64::MAX),
            }
        }
        Err(e) => {
            tracing::error!("cannot authenticate: {e:#}");
            Response::Failed {
                message: "This machine's account database cannot be read.".to_string(),
            }
        }
    }
}

/// The account behind a uid.
///
/// Only regular accounts, which is the same set the login screen offers. That
/// is not a limitation worth working around: an account that cannot log in
/// graphically has no graphical session to lock.
fn resolve(authenticator: &Authenticator, uid: u32) -> Result<Account> {
    authenticator
        .people()
        .context("cannot read the account database")?
        .into_iter()
        .find(|account| account.uid == uid)
        .with_context(|| format!("uid {uid} is not a regular account on this machine"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_greet_proto::Secret;

    fn account() -> Account {
        Account {
            name: "javan".to_string(),
            uid: 1000,
            gid: 1000,
            gecos: "Javan,,,".to_string(),
            home: "/home/javan".to_string(),
            shell: "/bin/ravenshell".to_string(),
            groups: vec![1000],
        }
    }

    fn limiter() -> Mutex<RateLimiter> {
        Mutex::new(RateLimiter::new(Limits::default()))
    }

    /// The one that would be a way past the lock.
    #[test]
    fn authenticate_is_refused_here() {
        let authenticator = Authenticator::new(Default::default());
        let response = answer(
            Request::Authenticate {
                username: "root".to_string(),
                secret: Secret::new("hunter2".to_string()),
            },
            &account(),
            &authenticator,
            &limiter(),
        );
        assert!(
            matches!(response, Response::Failed { .. }),
            "the verify socket must never start a session, got {response:?}"
        );
    }

    /// A verify carries no username, so there is nothing to point elsewhere.
    #[test]
    fn a_verify_request_names_no_account() {
        // A compile-time property, asserted here so that adding a `username`
        // field to `Verify` fails a test rather than passing review.
        let request = Request::Verify {
            secret: Secret::new("x".to_string()),
        };
        let mut wire = Vec::new();
        raven_greet_proto::write_message(&mut wire, &request).expect("serialises");
        let wire = String::from_utf8_lossy(&wire);
        assert!(
            !wire.contains("username"),
            "Verify must not carry an account name: {wire}"
        );
    }

    #[test]
    fn whoami_answers_about_the_connection_and_not_the_request() {
        let authenticator = Authenticator::new(Default::default());
        let response = answer(Request::Whoami, &account(), &authenticator, &limiter());
        match response {
            Response::You { user } => {
                assert_eq!(user.name, "javan");
                assert_eq!(user.display_name, "Javan");
                assert_eq!(user.initial, 'J');
            }
            other => panic!("expected the peer's own account, got {other:?}"),
        }
    }

    #[test]
    fn the_login_screens_requests_are_not_served_here() {
        let authenticator = Authenticator::new(Default::default());
        for request in [Request::ListUsers, Request::Wallpaper] {
            let response = answer(request, &account(), &authenticator, &limiter());
            assert!(matches!(response, Response::Failed { .. }));
        }
    }
}
