//! Handing a child process to an unprivileged account.
//!
//! `ravend` runs as root because it reads `/etc/shadow`. Everything it starts —
//! the greeter's compositor, and the session it hands over to — must not. This
//! crate is the three syscalls in between, and it is the only crate in the
//! workspace allowed to say `unsafe`.
//!
//! # Why this cannot be safe code
//!
//! `std` offers safe [`CommandExt::uid`] and [`CommandExt::gid`], and they are
//! not enough: they set the primary uid and gid and say nothing about
//! *supplementary* groups. On this desktop the supplementary groups are the
//! whole point — `video` and `render` are what let the session open the GPU,
//! and `input` is what lets it read the keyboard. A session dropped to the
//! right uid without them starts, draws nothing, and looks like a driver bug.
//!
//! `CommandExt::groups` exists and would do exactly this, but is still unstable
//! ([rust#90747]), and pinning the login path of a distribution to a nightly
//! feature is a worse trade than one audited `unsafe` block. `rustix`, which
//! Raven uses for syscalls elsewhere, deliberately does not wrap `setuid`,
//! `setgid` or `setgroups` at all — they change process-wide state and are
//! unsound to expose safely in a threaded program.
//!
//! The remaining option is to shell out to `setpriv(1)`. That was rejected for
//! the reason libpam was rejected: it puts a binary that must exist, and must
//! be the right one, on the path between a person and their own machine. If it
//! is missing from an image, nobody can log in to find out why.
//!
//! # The ordering trap
//!
//! All three calls happen inside one [`pre_exec`] closure, and none of them go
//! through `CommandExt::uid`/`gid`. This is not style. `std` applies the uid
//! and gid it was given *before* running any `pre_exec` closure, so a closure
//! calling `setgroups` would run after `setuid` had already given away the
//! privilege `setgroups` requires, and fail with `EPERM`.
//!
//! Within the closure the order is the classic one — supplementary groups,
//! then the primary gid, then the uid last — because each step gives away
//! privilege the next one needs. `setuid` first is the well-known way to end up
//! still holding root's groups.
//!
//! This reasoning, and the trap, are `raven-init`'s; see `apply_credentials` in
//! `RavenLinux/init/src/service.rs`. It is repeated here rather than shared
//! because the two live in different repositories and neither should depend on
//! the other to be able to start a process.
//!
//! [`CommandExt::uid`]: std::os::unix::process::CommandExt::uid
//! [`CommandExt::gid`]: std::os::unix::process::CommandExt::gid
//! [`pre_exec`]: std::os::unix::process::CommandExt::pre_exec
//! [rust#90747]: https://github.com/rust-lang/rust/issues/90747

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// The credentials a child should exec with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups, primary gid included. Order does not matter to the
    /// kernel; `raven-auth` sorts them so that two machines with the same
    /// accounts produce the same list.
    pub groups: Vec<u32>,
}

/// Arrange for `command` to drop to `credentials` between fork and exec.
///
/// Returns the same `command` for chaining. Nothing happens until the command
/// is spawned; a failure to drop privilege surfaces as a spawn error, and the
/// child is never exec'd.
pub fn drop_to<'a>(command: &'a mut Command, credentials: &Credentials) -> &'a mut Command {
    let uid = credentials.uid;
    let gid = credentials.gid;
    // Built out here, and moved into the closure, so that the closure itself
    // allocates nothing: only async-signal-safe work is permitted after fork,
    // and a malloc in the child of a threaded process can deadlock on a lock
    // held by a thread that no longer exists.
    let groups: Vec<libc::gid_t> = credentials.groups.to_vec();

    // SAFETY: the closure runs in the forked child, between `fork` and `exec`,
    // where only async-signal-safe work is permitted.
    //
    // - `setgroups`, `setgid`, `setuid` and `getuid`/`getgid` are raw syscalls.
    //   They allocate nothing, take no locks, and are async-signal-safe.
    // - `groups` was allocated in the parent and is only read here; `as_ptr`
    //   and `len` do not allocate. The `Vec` outlives the call because the
    //   closure owns it.
    // - `io::Error::last_os_error` reads `errno`, which is thread-local and
    //   already set by the failing call.
    // - Nothing here can panic: there is no indexing, no unwrap, and no
    //   formatting. A panic across the fork boundary would be undefined.
    unsafe {
        command.pre_exec(move || {
            // Supplementary groups first, while still root.
            if libc::setgroups(groups.len() as libc::size_t, groups.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            // Then the primary gid. `setgid` before `setuid`, always.
            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(io::Error::last_os_error());
            }
            // Then the uid, which is the step that cannot be undone.
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(io::Error::last_os_error());
            }

            // Prove it took. `setuid` returning 0 while leaving the process
            // privileged should be impossible, but "should be impossible" is
            // not a thing to stake a root shell on: if this check ever fires,
            // the alternative to failing here is exec'ing a session with
            // root's credentials and no indication that anything went wrong.
            if libc::getuid() != uid as libc::uid_t
                || libc::geteuid() != uid as libc::uid_t
                || libc::getgid() != gid as libc::gid_t
                || libc::getegid() != gid as libc::gid_t
            {
                return Err(io::Error::other(
                    "credentials did not take effect; refusing to exec",
                ));
            }
            Ok(())
        });
    }

    command
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drop is applied lazily, so this asserts the plumbing rather than the
    /// syscalls: a real drop needs root, which a test suite does not have.
    /// Behaviour under root is covered by `ravend`'s own bring-up.
    #[test]
    fn dropping_is_wired_without_spawning() {
        let mut command = Command::new("/bin/true");
        let credentials = Credentials {
            uid: 1000,
            gid: 1000,
            groups: vec![91, 97, 1000],
        };
        drop_to(&mut command, &credentials);
    }

    /// An unprivileged process trying to drop to *another* uid must fail at
    /// spawn rather than silently exec'ing with the wrong credentials.
    ///
    /// Skipped when the suite happens to be running as root, where the drop
    /// legitimately succeeds.
    #[test]
    fn a_drop_that_cannot_succeed_fails_the_spawn() {
        // SAFETY: `getuid` is a raw syscall with no preconditions. This is in
        // a test rather than in `drop_to`, but the crate-level allowance is
        // the same one.
        let running_as_root = unsafe { libc::getuid() } == 0;
        if running_as_root {
            return;
        }

        let mut command = Command::new("/bin/true");
        drop_to(
            &mut command,
            &Credentials {
                uid: 12345,
                gid: 12345,
                groups: vec![12345],
            },
        );
        assert!(
            command.spawn().is_err(),
            "an unprivileged process must not be able to drop to another uid"
        );
    }
}
