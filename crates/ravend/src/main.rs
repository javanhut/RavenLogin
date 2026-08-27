//! `ravend` — the RavenLinux login daemon.
//!
//! Runs as root, because `/etc/shadow` is `0600 root:root` and somebody has to
//! read it. Everything that follows from that is the design:
//!
//! - It draws nothing. No GPU, no fonts, no image decoding, no Wayland client
//!   library. The list of things that have historically been remotely
//!   exploitable in a login screen is almost entirely a list of things this
//!   process does not link.
//! - It starts a compositor and a greeter as an unprivileged account, and talks
//!   to the greeter over a Unix socket that only that account can open.
//! - It never tells the greeter anything it did not need to know. A hash never
//!   crosses the socket, and neither does a denial reason more specific than
//!   the greeter is allowed to display.
//! - It holds no authenticated state between messages. `Authenticate` either
//!   starts a session or does not; there is no window in which this process is
//!   holding "somebody proved who they are" and waiting to be told what to do
//!   about it.
//!
//! # The loop
//!
//! A display manager is a loop, and the loop is the part that is easy to get
//! wrong. Start the greeter, wait for somebody to log in, tear the greeter
//! down, start their session, wait for it to end, start the greeter again. The
//! tear-down before the session start is not optional: the greeter's compositor
//! holds the DRM master and the seat, and a session compositor that cannot
//! acquire either fails in a way that looks like a driver problem.
//!
//! # What this does not do
//!
//! It does not handle signals. `rustix` exposes no safe `signalfd` and this
//! workspace forbids unsafe outside `raven-privdrop`, which is the same
//! limitation `cawd` documents. In practice `raven-init` stops services with
//! `SIGTERM` and then `SIGKILL`, and the children here are in the daemon's
//! process group, so a shutdown takes the greeter and the session down with it.
//! What is lost is the tidy path: a session gets killed rather than asked.

#![forbid(unsafe_code)]

mod config;
mod ratelimit;
mod session;

use std::io::{BufReader, BufWriter};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use raven_auth::{Account, Authenticator, Denial, Outcome};
use raven_greet_proto::{Request, Response, SOCKET_PATH, User};

use crate::config::Config;
use crate::ratelimit::RateLimiter;

/// How often the accept loop wakes to check on the children it is supervising.
const SUPERVISE_POLL: Duration = Duration::from_millis(100);

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // `{:#}` so the whole `anyhow` context chain lands in the log. A
            // login daemon that fails with only its innermost message is a
            // login daemon nobody can debug from the console it just failed to
            // give them.
            tracing::error!("ravend: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from(config::DEFAULT_PATH), PathBuf::from);
    let config = Config::load(&config_path)?;
    tracing::info!(path = %config_path.display(), "configuration loaded");

    if !rustix::process::geteuid().is_root() {
        anyhow::bail!(
            "ravend must run as root: it reads /etc/shadow and starts sessions as other users"
        );
    }

    let authenticator = Authenticator::new(config.policy.into());

    // The greeter's own account, resolved once. A missing one is fatal and
    // says so precisely, because the alternative -- falling back to running the
    // greeter as root -- is exactly the thing this daemon exists to avoid.
    let greeter_account = resolve_greeter_account(&config.greeter.user)?;
    tracing::info!(
        user = %greeter_account.name,
        uid = greeter_account.uid,
        "greeter account resolved"
    );

    let listener = bind_socket(&greeter_account)?;
    let mut limiter = RateLimiter::new(config.ratelimit.into());

    loop {
        let account = greet(
            &config,
            &greeter_account,
            &listener,
            &authenticator,
            &mut limiter,
        )?;
        tracing::info!(user = %account.name, uid = account.uid, "starting session");
        run_session(&config, &account)?;
        tracing::info!(user = %account.name, "session ended; returning to the login screen");
    }
}

/// Look up the greeter's account, and insist that it is unprivileged.
fn resolve_greeter_account(name: &str) -> Result<Account> {
    let mut accounts = raven_auth::passwd::load(Path::new("/etc/passwd"))?;
    raven_auth::passwd::attach_groups(&mut accounts, Path::new("/etc/group"));

    let account = accounts
        .into_iter()
        .find(|a| a.name == name)
        .with_context(|| {
            format!(
                "no account named '{name}'. Create it as a system account with no password \
                 and a nologin shell, in the video, render, input and seat groups"
            )
        })?;

    // Checked rather than assumed. A `login.toml` naming `root` here, whether
    // by typo or otherwise, would put a Wayland compositor and a UI that parses
    // fonts and images back into the privileged process -- undoing the entire
    // split in one line of configuration.
    if account.uid == 0 {
        anyhow::bail!(
            "the greeter account '{name}' has uid 0. The greeter must be unprivileged; \
             running it as root would put the compositor back in the process that holds \
             /etc/shadow"
        );
    }

    Ok(account)
}

/// Create the socket directory and bind, with the greeter as the only account
/// that can reach it.
///
/// Two layers, because either alone is thin. The directory is `0700` and owned
/// by the greeter, so nothing else can even traverse to the socket; the socket
/// itself is `0600`. `bind` respects the umask, so the permissions are set
/// explicitly afterwards rather than hoped for.
fn bind_socket(greeter: &Account) -> Result<UnixListener> {
    let path = Path::new(SOCKET_PATH);
    let dir = path
        .parent()
        .context("the socket path has no parent directory")?;

    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot chmod {}", dir.display()))?;
    std::os::unix::fs::chown(dir, Some(greeter.uid), Some(greeter.gid))
        .with_context(|| format!("cannot chown {}", dir.display()))?;

    // A socket left behind by a previous run makes `bind` fail with EADDRINUSE.
    // /run is a tmpfs and should be empty at boot, but a restarted daemon is
    // the common case and it should just work.
    match std::fs::remove_file(path) {
        Ok(()) => tracing::info!(path = %path.display(), "removed a stale socket"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::Error::new(e)
                .context(format!("cannot remove the stale socket {}", path.display())));
        }
    }

    let listener =
        UnixListener::bind(path).with_context(|| format!("cannot bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot chmod {}", path.display()))?;
    std::os::unix::fs::chown(path, Some(greeter.uid), Some(greeter.gid))
        .with_context(|| format!("cannot chown {}", path.display()))?;

    listener
        .set_nonblocking(true)
        .context("cannot make the listener non-blocking")?;

    tracing::info!(path = %path.display(), "listening");
    Ok(listener)
}

/// Bring up the login screen and stay there until somebody logs in.
///
/// Returns the account whose session should start. Everything this function
/// spawned is stopped before it returns, successfully or not.
fn greet(
    config: &Config,
    greeter: &Account,
    listener: &UnixListener,
    authenticator: &Authenticator,
    limiter: &mut RateLimiter,
) -> Result<Account> {
    let runtime_dir = session::prepare_runtime_dir(greeter.uid, greeter.gid)?;

    let mut compositor =
        session::spawn_greeter_compositor(&config.greeter.compositor, greeter, &runtime_dir)?;
    tracing::info!(compositor = %config.greeter.compositor, "greeter compositor started");

    // From here on every exit path must tear the compositor down, so the body
    // is wrapped and the cleanup happens once, on both arms.
    let result = greet_inner(
        config,
        greeter,
        &runtime_dir,
        &mut compositor,
        listener,
        authenticator,
        limiter,
    );

    session::stop(
        &mut compositor,
        config.session.stop_timeout,
        "greeter compositor",
    );

    result
}

#[allow(clippy::too_many_arguments)]
fn greet_inner(
    config: &Config,
    greeter: &Account,
    runtime_dir: &Path,
    compositor: &mut Child,
    listener: &UnixListener,
    authenticator: &Authenticator,
    limiter: &mut RateLimiter,
) -> Result<Account> {
    let display =
        session::wait_for_wayland_socket(runtime_dir, compositor, config.greeter.wayland_timeout)?;

    let mut ui =
        session::spawn_greeter_ui(&config.greeter.command, greeter, runtime_dir, &display)?;
    tracing::info!(command = %config.greeter.command, "greeter UI started");

    let outcome = accept_until_login(
        listener,
        compositor,
        &mut ui,
        authenticator,
        limiter,
        greeter.uid,
    );

    session::stop(&mut ui, config.session.stop_timeout, "greeter UI");
    outcome
}

/// The accept loop.
///
/// Non-blocking accept with a poll, rather than a blocking one, because this
/// loop is also the supervisor: if the compositor or the UI dies, nobody is
/// looking at a login screen any more and continuing to wait for a connection
/// would hang forever in front of a black display.
///
/// One connection at a time. The greeter is the only client, so a queue buys
/// nothing, and handling connections serially means the rate limiter cannot be
/// raced by opening two sockets at once.
fn accept_until_login(
    listener: &UnixListener,
    compositor: &mut Child,
    ui: &mut Child,
    authenticator: &Authenticator,
    limiter: &mut RateLimiter,
    greeter_uid: u32,
) -> Result<Account> {
    let mut last_sweep = Instant::now();

    loop {
        match listener.accept() {
            Ok((stream, _)) => match serve(stream, authenticator, limiter, greeter_uid) {
                Ok(Some(account)) => return Ok(account),
                Ok(None) => {}
                Err(e) => tracing::warn!("greeter connection failed: {e:#}"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(anyhow::Error::new(e).context("cannot accept on the socket")),
        }

        if let Some(status) = compositor
            .try_wait()
            .context("cannot check the compositor")?
        {
            anyhow::bail!("the greeter's compositor exited ({status})");
        }
        if let Some(status) = ui.try_wait().context("cannot check the greeter UI")? {
            anyhow::bail!("the greeter UI exited ({status})");
        }

        if last_sweep.elapsed() > Duration::from_secs(60) {
            limiter.forget_old(Instant::now());
            last_sweep = Instant::now();
        }

        std::thread::sleep(SUPERVISE_POLL);
    }
}

/// Handle one greeter connection until it closes or somebody logs in.
fn serve(
    stream: UnixStream,
    authenticator: &Authenticator,
    limiter: &mut RateLimiter,
    greeter_uid: u32,
) -> Result<Option<Account>> {
    // Who is actually on the other end. The socket's permissions should already
    // guarantee this, but permissions are a property of a path, and a path can
    // be got wrong by a packaging change nobody noticed. `SO_PEERCRED` is a
    // property of the connection, which cannot be. The two are cheap and
    // independent, and this one is the one that keeps holding if the other
    // breaks.
    // `std`'s `UnixStream::peer_cred` is still unstable (rust#42839), so this
    // goes through rustix, which is where the rest of Raven gets its syscalls
    // anyway.
    let peer =
        rustix::net::sockopt::socket_peercred(&stream).context("cannot read peer credentials")?;
    let peer_uid = peer.uid.as_raw();
    if peer_uid != greeter_uid && peer_uid != 0 {
        anyhow::bail!(
            "refusing a connection from uid {peer_uid}; \
             only the greeter ({greeter_uid}) may connect"
        );
    }

    // A greeter that connects and then says nothing must not hold the login
    // screen hostage. These are generous -- somebody is typing a password on
    // the other end -- but finite.
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .context("cannot set a read timeout")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .context("cannot set a write timeout")?;

    let mut reader = BufReader::new(stream.try_clone().context("cannot clone the stream")?);
    let mut writer = BufWriter::new(stream);

    loop {
        let request: Request = match raven_greet_proto::read_message(&mut reader) {
            Ok(request) => request,
            Err(raven_greet_proto::Error::Closed) => return Ok(None),
            Err(e) => return Err(anyhow::Error::new(e).context("cannot read a request")),
        };

        match request {
            Request::ListUsers => {
                let users = authenticator
                    .people()?
                    .iter()
                    .map(|a| User {
                        name: a.name.clone(),
                        display_name: a.display_name().to_string(),
                        initial: a.initial(),
                    })
                    .collect::<Vec<_>>();
                tracing::info!(count = users.len(), "sending the user list");
                raven_greet_proto::write_message(&mut writer, &Response::Users { users })?;
            }

            Request::Authenticate { username, secret } => {
                let now = Instant::now();

                // The throttle is checked before the password is, so that a
                // guessing loop pays the delay whether or not it guessed right.
                let wait = limiter.delay_for(&username, now);
                if !wait.is_zero() {
                    tracing::warn!(
                        user = %username,
                        ?wait,
                        "attempt refused; the account is being throttled"
                    );
                    raven_greet_proto::write_message(
                        &mut writer,
                        &Response::Denied {
                            message: "Too many attempts. Try again shortly.".to_string(),
                            retry_after_ms: wait.as_millis().try_into().unwrap_or(u64::MAX),
                        },
                    )?;
                    continue;
                }

                match authenticator.authenticate(&username, secret.as_bytes()) {
                    Ok(Outcome::Granted(account)) => {
                        limiter.record_success(&username);
                        tracing::info!(user = %username, "authenticated");
                        raven_greet_proto::write_message(
                            &mut writer,
                            &Response::Granted {
                                username: username.clone(),
                            },
                        )?;
                        return Ok(Some(*account));
                    }
                    Ok(Outcome::Denied(denial)) => {
                        limiter.record_failure(&username, now);
                        // The real reason goes to the log; the greeter gets
                        // only what `raven-auth` says is safe to display.
                        tracing::warn!(user = %username, ?denial, "denied");
                        let message = if denial.is_safe_to_display() {
                            denial.message()
                        } else {
                            Denial::BadPassword.message()
                        };
                        let wait = limiter.delay_for(&username, Instant::now());
                        raven_greet_proto::write_message(
                            &mut writer,
                            &Response::Denied {
                                message,
                                retry_after_ms: wait.as_millis().try_into().unwrap_or(u64::MAX),
                            },
                        )?;
                    }
                    Err(e) => {
                        // A broken machine, not a wrong password. Say so: this
                        // is the case where telling somebody "incorrect
                        // password" sends them looking in the wrong place.
                        tracing::error!("cannot authenticate: {e:#}");
                        raven_greet_proto::write_message(
                            &mut writer,
                            &Response::Failed {
                                message: "This machine's account database cannot be read."
                                    .to_string(),
                            },
                        )?;
                    }
                }
            }
        }
    }
}

/// Start the session and wait for it to finish.
fn run_session(config: &Config, account: &Account) -> Result<()> {
    let runtime_dir = session::prepare_runtime_dir(account.uid, account.gid)?;
    let mut child = session::spawn_session(&config.session.command, account, &runtime_dir)?;

    let status = child.wait().context("cannot wait for the session")?;
    if !status.success() {
        // Not fatal to the daemon. A session that crashes should put the login
        // screen back up, not take the machine down to a console.
        tracing::warn!(user = %account.name, %status, "the session exited badly");
    }
    Ok(())
}
