//! Starting and stopping the processes the daemon owns.
//!
//! Three of them, in two shapes. The greeter's compositor and the greeter UI
//! run as the unprivileged greeter account and exist to be torn down; the
//! session runs as whoever logged in and exists to be waited on. What they have
//! in common is everything in this module: a runtime directory that must exist
//! before the process starts, an environment built from nothing rather than
//! inherited from root, and a stop that asks before it insists.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use raven_auth::Account;
use raven_privdrop::Credentials;
use rustix::process::{Pid, Signal, kill_process};

/// How often to look at a child that is being asked to exit.
const REAP_POLL: Duration = Duration::from_millis(50);

/// The credentials to exec an account's processes with.
///
/// A free function rather than a `From` impl: `Account` and `Credentials` are
/// both foreign to this crate, so an impl would violate the orphan rule. Adding
/// the conversion to `raven-privdrop` instead would make the crate that exists
/// to hold three syscalls depend on the account database, which is the wrong
/// direction.
fn credentials_for(account: &Account) -> Credentials {
    Credentials {
        uid: account.uid,
        gid: account.gid,
        groups: if account.groups.is_empty() {
            // An account whose groups were never attached still needs its
            // primary gid in the supplementary list, or `setgroups` clears the
            // inherited list and leaves it in no groups at all.
            vec![account.gid]
        } else {
            account.groups.clone()
        },
    }
}

/// Create `/run/user/<uid>`, owned by that account and readable by nobody else.
///
/// There is no logind here to do this on login, and the Wayland socket lives
/// inside it, so if this does not happen the compositor has nowhere to bind and
/// exits. `raven-init` does the same thing today for the autologin session; the
/// daemon takes it over because it now happens twice, once for the greeter and
/// once for whoever logs in.
///
/// The order matters: `0700` before the `chown`, never after. A directory
/// created `0700` while owned by root and then handed over is private the whole
/// time. Chowning first would leave a window in which the account owns a
/// directory that has not been locked down yet.
pub(crate) fn prepare_runtime_dir(uid: u32, gid: u32) -> Result<PathBuf> {
    let path = PathBuf::from(format!("/run/user/{uid}"));

    if let Err(e) = std::fs::create_dir_all(&path)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(anyhow::Error::new(e).context(format!("cannot create {}", path.display())));
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot chmod {}", path.display()))?;
    std::os::unix::fs::chown(&path, Some(uid), Some(gid))
        .with_context(|| format!("cannot chown {} to {uid}:{gid}", path.display()))?;

    Ok(path)
}

/// The environment a process gets, built rather than inherited.
///
/// `env_clear` first, always. The daemon's own environment is root's, from
/// whatever `raven-init` was started with, and letting it through means a
/// session running as a regular user with root's `HOME` — which writes that
/// user's dotfiles into `/root`, where they cannot read them back. Everything
/// the session needs is set here explicitly; everything else is the session
/// script's business, which is where `XDG_CURRENT_DESKTOP`, `XCURSOR_THEME` and
/// the rest already live.
fn base_environment(account: &Account, runtime_dir: &Path) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("HOME".to_string(), account.home.clone());
    env.insert("USER".to_string(), account.name.clone());
    env.insert("LOGNAME".to_string(), account.name.clone());
    env.insert("SHELL".to_string(), account.shell.clone());
    env.insert(
        "PATH".to_string(),
        "/usr/local/bin:/usr/bin:/bin".to_string(),
    );
    env.insert(
        "XDG_RUNTIME_DIR".to_string(),
        runtime_dir.display().to_string(),
    );
    env.insert("XDG_SESSION_TYPE".to_string(), "wayland".to_string());
    // seatd rather than logind, because there is no logind. The session script
    // defaults this too; setting it here covers the greeter's compositor, which
    // does not go through the script.
    env.insert("LIBSEAT_BACKEND".to_string(), "seatd".to_string());
    env
}

/// Start a program as `account`, with a built environment.
///
/// stdin is `/dev/null` and stdout/stderr are inherited, so a compositor's
/// panic message lands in the daemon's own log rather than in a pipe nobody
/// reads. A pipe would be tidier and would deadlock the first time a child
/// filled it.
fn spawn_as(
    program: &str,
    account: &Account,
    runtime_dir: &Path,
    extra_env: &[(&str, &str)],
) -> Result<Child> {
    let mut command = Command::new(program);
    command
        .env_clear()
        .envs(base_environment(account, runtime_dir))
        .current_dir(if Path::new(&account.home).is_dir() {
            account.home.as_str()
        } else {
            // A greeter account often has no home, and a `current_dir` that
            // does not exist makes `spawn` fail with a confusing ENOENT that
            // reads as "the program is missing".
            "/"
        })
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    for (key, value) in extra_env {
        command.env(key, value);
    }

    raven_privdrop::drop_to(&mut command, &credentials_for(account));

    command
        .spawn()
        .with_context(|| format!("cannot start {program} as {}", account.name))
}

/// Start the compositor that will host the greeter.
pub(crate) fn spawn_greeter_compositor(
    compositor: &str,
    account: &Account,
    runtime_dir: &Path,
) -> Result<Child> {
    spawn_as(compositor, account, runtime_dir, &[])
}

/// Start the greeter UI, pointed at the compositor's socket.
pub(crate) fn spawn_greeter_ui(
    command: &str,
    account: &Account,
    runtime_dir: &Path,
    wayland_display: &str,
) -> Result<Child> {
    spawn_as(
        command,
        account,
        runtime_dir,
        &[("WAYLAND_DISPLAY", wayland_display)],
    )
}

/// Start the session for whoever just logged in.
pub(crate) fn spawn_session(command: &str, account: &Account, runtime_dir: &Path) -> Result<Child> {
    spawn_as(command, account, runtime_dir, &[])
}

/// Wait for a compositor to bind its Wayland socket, and say which one.
///
/// Polls rather than watching with inotify: this runs once per login, for at
/// most a few seconds, and an inotify watch on a directory that may not exist
/// yet is more code and more failure modes for a wait that nobody is timing.
///
/// `wayland-0` is what a compositor with no `WAYLAND_DISPLAY` set picks; the
/// scan covers `wayland-1` and up too, because a stale socket file from a
/// previous boot makes the next compositor pick the next number, and hard-coding
/// `wayland-0` would then point the greeter at a socket nothing is listening on.
pub(crate) fn wait_for_wayland_socket(
    runtime_dir: &Path,
    child: &mut Child,
    timeout: Duration,
) -> Result<String> {
    let deadline = Instant::now() + timeout;

    loop {
        // A compositor that has already exited will never bind anything, and
        // waiting the full timeout to say so turns a clear error into a hang.
        if let Some(status) = child.try_wait().context("cannot check on the compositor")? {
            anyhow::bail!("the compositor exited before binding a socket ({status})");
        }

        for n in 0..8 {
            let name = format!("wayland-{n}");
            if runtime_dir.join(&name).exists() {
                tracing::info!(socket = %name, "compositor is listening");
                return Ok(name);
            }
        }

        if Instant::now() >= deadline {
            anyhow::bail!(
                "no Wayland socket appeared in {} within {timeout:?}",
                runtime_dir.display()
            );
        }
        std::thread::sleep(REAP_POLL);
    }
}

/// Ask a child to exit, then insist.
///
/// `SIGTERM`, then `SIGKILL` once `grace` has passed. The compositor holds the
/// DRM master and the seat; leaving it running while starting the session means
/// the session's compositor cannot acquire either, and the symptom is a black
/// screen rather than an error. So this is always waited for, never fired and
/// forgotten.
pub(crate) fn stop(child: &mut Child, grace: Duration, what: &str) {
    // `Child::id` is a u32; a pid that does not fit an i32 is not a pid.
    let pid = i32::try_from(child.id()).ok().and_then(Pid::from_raw);

    match pid {
        Some(pid) => {
            if let Err(e) = kill_process(pid, Signal::TERM) {
                // ESRCH means it is already gone, which is the outcome we
                // wanted; anything else is worth knowing about.
                tracing::debug!(%what, error = %e, "SIGTERM was not delivered");
            }
        }
        None => tracing::warn!(%what, "no usable pid; cannot signal it"),
    }

    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                tracing::info!(%what, %status, "exited");
                return;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(%what, error = %e, "cannot wait for it; giving up");
                return;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(REAP_POLL);
    }

    tracing::warn!(%what, ?grace, "did not exit in time; killing it");
    let _ = child.kill();
    // Reap it, so it does not sit as a zombie for the life of the daemon.
    // SIGKILL cannot be caught, so this cannot block for long.
    if let Err(e) = child.wait() {
        tracing::warn!(%what, error = %e, "cannot reap it");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Account {
        Account {
            name: "javan".to_string(),
            uid: 1000,
            gid: 1000,
            gecos: "Javan".to_string(),
            home: "/home/javan".to_string(),
            shell: "/usr/bin/ravenshell".to_string(),
            groups: vec![91, 97, 1000],
        }
    }

    #[test]
    fn the_environment_is_built_not_inherited() {
        let env = base_environment(&account(), Path::new("/run/user/1000"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home/javan"));
        assert_eq!(env.get("USER").map(String::as_str), Some("javan"));
        assert_eq!(env.get("LOGNAME").map(String::as_str), Some("javan"));
        assert_eq!(
            env.get("XDG_RUNTIME_DIR").map(String::as_str),
            Some("/run/user/1000")
        );
        assert_eq!(
            env.get("XDG_SESSION_TYPE").map(String::as_str),
            Some("wayland")
        );
    }

    /// The daemon's own environment must not leak into a session.
    ///
    /// Asserted as an exact key set rather than by planting a canary variable,
    /// because `std::env::set_var` is `unsafe` in edition 2024 and this crate
    /// forbids unsafe. The exact set is the stronger check anyway: it fails
    /// when a variable is *added* here without being thought about, not only
    /// when one leaks in.
    #[test]
    fn the_environment_contains_exactly_what_was_put_there() {
        let env = base_environment(&account(), Path::new("/run/user/1000"));
        let keys: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "HOME",
                "LIBSEAT_BACKEND",
                "LOGNAME",
                "PATH",
                "SHELL",
                "USER",
                "XDG_RUNTIME_DIR",
                "XDG_SESSION_TYPE",
            ]
        );
        // And in particular, nothing this process happens to have.
        assert!(!env.contains_key("CARGO"));
        assert!(!env.contains_key("PWD"));
    }

    /// An account with no attached groups must still get its primary gid, or
    /// `setgroups` with an empty list drops it out of every group.
    #[test]
    fn credentials_never_have_an_empty_group_list() {
        let mut bare = account();
        bare.groups.clear();
        let credentials = credentials_for(&bare);
        assert_eq!(credentials.groups, vec![1000]);
    }

    #[test]
    fn credentials_carry_the_attached_groups() {
        let credentials = credentials_for(&account());
        assert_eq!(credentials.uid, 1000);
        assert_eq!(credentials.gid, 1000);
        assert_eq!(credentials.groups, vec![91, 97, 1000]);
    }

    /// A compositor that dies immediately must be reported as dead, not waited
    /// on until the timeout.
    #[test]
    fn a_dead_compositor_is_noticed_immediately() {
        let dir = std::env::temp_dir().join(format!("ravend-wayland-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("can create a test directory");

        let mut child = Command::new("/bin/false")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("can run /bin/false");
        // Give it a moment to actually exit, so this tests the try_wait branch
        // rather than racing it.
        std::thread::sleep(Duration::from_millis(100));

        let start = Instant::now();
        let err = wait_for_wayland_socket(&dir, &mut child, Duration::from_secs(30))
            .expect_err("a dead compositor cannot bind a socket");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "waited {:?}; should have returned as soon as the child was seen dead",
            start.elapsed()
        );
        assert!(err.to_string().contains("exited before binding"), "{err}");
    }

    /// A socket that is already there is found without waiting.
    #[test]
    fn an_existing_socket_is_found() {
        let dir = std::env::temp_dir().join(format!("ravend-wayland-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("can create a test directory");
        std::fs::write(dir.join("wayland-1"), b"").expect("can create a fake socket");

        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("can run sleep");

        let socket = wait_for_wayland_socket(&dir, &mut child, Duration::from_secs(5))
            .expect("the socket is there");
        assert_eq!(socket, "wayland-1");

        stop(&mut child, Duration::from_secs(2), "test sleep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `stop` must reap what it kills, and must return promptly for a process
    /// that ignores SIGTERM.
    #[test]
    fn stop_kills_a_process_that_ignores_sigterm() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; sleep 30"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("can run sh");

        let start = Instant::now();
        stop(&mut child, Duration::from_millis(200), "stubborn child");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "stop took {:?}",
            start.elapsed()
        );
        // Already reaped: a second wait must not block.
        assert!(child.try_wait().is_ok());
    }

    #[test]
    fn stop_returns_promptly_for_a_cooperative_process() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("can run sleep");

        let start = Instant::now();
        stop(&mut child, Duration::from_secs(5), "cooperative child");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "stop took {:?} for a process that exits on SIGTERM",
            start.elapsed()
        );
    }
}
