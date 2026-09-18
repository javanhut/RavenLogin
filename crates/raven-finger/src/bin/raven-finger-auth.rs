//! `raven-finger-auth` -- a finger in place of `sudo`'s password.
//!
//! `sudo` authenticates through PAM, and PAM's `pam_exec` runs a program and
//! takes its exit status as the answer. So this is that program, and one line
//! in `/etc/pam.d/sudo` puts it ahead of the password:
//!
//! ```text
//! auth       sufficient   pam_rootok.so
//! auth       sufficient   pam_exec.so quiet seteuid /usr/bin/raven-finger-auth
//! auth       required     pam_unix.so nullok try_first_pass
//! ```
//!
//! `sufficient`: a match is enough, and anything else -- no reader, nothing
//! enrolled, the owner never turned it on, three misses, a timeout, Enter --
//! falls through to the password exactly as if the line were not there. This
//! program can say yes. It can never make the password stop working.
//!
//! # When it does nothing at all
//!
//! Silently, in a few milliseconds, unless every one of these holds:
//!
//! - The account has turned fingerprint `sudo` on, in the root-owned policy
//!   file only `ravend` writes (see `raven_finger::policy`).
//! - One of its fingers is on the reader.
//! - `sudo` has a terminal. Somebody has to be told to touch the sensor, and
//!   has to be able to press Enter to skip it.
//! - `sudo` was not run over SSH. A finger on the machine's own reader proves
//!   somebody is sitting at it, which says nothing about who is typing
//!   commands from the other side of the world.
//!
//! # Other uses
//!
//! ```text
//! raven-finger-auth --install-pam [file]   add the line above (idempotent)
//! raven-finger-auth --remove-pam  [file]   take it out again
//! raven-finger-auth --pam-status  [file]   exit 0 if it is there
//! ```
//!
//! The file defaults to `/etc/pam.d/sudo`. Settings offers the first one in a
//! terminal when fingerprint `sudo` is switched on and the line is missing.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use raven_finger::sensor::{Sensor, Watch, WatchEvent};
use raven_finger::{policy, valid_account};

/// How long to wait for a finger before handing over to the password.
const TIMEOUT: Duration = Duration::from_secs(20);

const DEFAULT_PAM_FILE: &str = "/etc/pam.d/sudo";

/// What marks our line in a PAM file, whatever path the binary is at.
const MARKER: &str = "raven-finger-auth";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let file = || {
        args.get(1)
            .map_or_else(|| PathBuf::from(DEFAULT_PAM_FILE), PathBuf::from)
    };
    match args.first().map(String::as_str) {
        Some("--install-pam") => report(install_pam(&file())),
        Some("--remove-pam") => report(remove_pam(&file())),
        Some("--pam-status") => {
            let installed = std::fs::read_to_string(file())
                .map(|text| has_line(&text))
                .unwrap_or(false);
            println!("{}", if installed { "installed" } else { "missing" });
            if installed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some("--help" | "-h") => {
            println!(
                "raven-finger-auth: run by pam_exec for sudo.\n\
                 \n  --install-pam [file]   add the fingerprint line to {DEFAULT_PAM_FILE}\
                 \n  --remove-pam  [file]   remove it\
                 \n  --pam-status  [file]   exit 0 if it is present"
            );
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("raven-finger-auth: unknown argument {other:?}; see --help");
            ExitCode::FAILURE
        }
        None => {
            if authenticate() {
                ExitCode::SUCCESS
            } else {
                // Any non-zero status is PAM_AUTH_ERR to pam_exec, and with
                // `sufficient` that means "ask the next module", which is the
                // password. Nothing here is ever a refusal.
                ExitCode::FAILURE
            }
        }
    }
}

fn report(result: std::io::Result<String>) -> ExitCode {
    match result {
        Ok(what) => {
            println!("{what}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("raven-finger-auth: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// The PAM side
// ---------------------------------------------------------------------------

/// The whole of the `pam_exec` path. `true` only for one of this account's own
/// fingers.
fn authenticate() -> bool {
    // Only the auth stack. pam_exec can be named in the others, and a finger
    // is not an answer to "open a session" or "change the password".
    if std::env::var("PAM_TYPE").is_ok_and(|t| t != "auth") {
        return false;
    }
    let Ok(account) = std::env::var("PAM_USER") else {
        return false;
    };
    if !valid_account(&account) {
        return false;
    }
    // Without root there is no sensor socket and no policy file to read. The
    // `seteuid` in the PAM line is what gives it; without that, just step
    // aside.
    if !rustix::process::geteuid().is_root() {
        return false;
    }
    if !policy::load(&account).sudo {
        return false;
    }
    if is_remote() || !interactive() {
        return false;
    }
    let Some(tty) = Tty::open() else {
        return false;
    };

    let mut sensor = match Sensor::connect() {
        Ok(Some(sensor)) => sensor,
        _ => return false,
    };
    // Every step before the wait gets a short deadline: the daemon serves one
    // connection at a time, and a lock screen holding the reader must not
    // turn `sudo` into a hang before the prompt has even been shown.
    if sensor
        .set_read_timeout(Some(Duration::from_secs(3)))
        .is_err()
    {
        return false;
    }
    match sensor.fingers_of(&account) {
        Ok(fingers) if !fingers.is_empty() => {}
        _ => return false,
    }
    if sensor.set_read_timeout(Some(TIMEOUT)).is_err() {
        return false;
    }
    let Ok(hangup) = sensor.hangup_handle() else {
        return false;
    };
    let hangup = Arc::new(hangup);

    tty.say("Touch the fingerprint sensor, or press Enter to type your password.");
    let _echo = tty.quiet();

    // Enter skips to the password: a line on the terminal ends the wait.
    let skipped = Arc::new(AtomicBool::new(false));
    if let Some(mut input) = tty.reader() {
        let skipped = Arc::clone(&skipped);
        let hangup = Arc::clone(&hangup);
        std::thread::spawn(move || {
            let mut byte = [0u8; 64];
            if matches!(input.read(&mut byte), Ok(n) if n > 0) {
                skipped.store(true, Ordering::SeqCst);
                let _ = hangup.shutdown(std::net::Shutdown::Both);
            }
        });
    }

    let verdict = sensor.watch(&account, raven_finger::MAX_MISSES, |event| match event {
        WatchEvent::Retry(advice) => tty.say(advice),
        WatchEvent::Miss { .. } => tty.say("Not recognised. Try again."),
    });

    match verdict {
        Ok(Watch::Matched(_)) => {
            tty.say("Fingerprint recognised.");
            true
        }
        Ok(Watch::Missed) => {
            tty.say("Fingerprint not recognised.");
            false
        }
        Ok(Watch::Cancelled) if skipped.load(Ordering::SeqCst) => false,
        // A timeout surfaces as an error from the read, and so does a daemon
        // that went away. Either way the password is next, and saying why
        // keeps the pause from looking like a hang.
        Ok(Watch::Cancelled) | Err(_) => {
            tty.say("No fingerprint; using your password.");
            false
        }
    }
}

/// Whether the `sudo` that ran this came in over the network.
///
/// pam_exec hands over PAM's environment, not the caller's, so `sudo`'s own is
/// read from `/proc` -- it is this process's parent, and this process is root.
fn is_remote() -> bool {
    if std::env::var("PAM_RHOST").is_ok_and(|h| !h.is_empty()) {
        return true;
    }
    let Some(parent) = rustix::process::getppid() else {
        return false;
    };
    let Ok(environ) = std::fs::read(format!("/proc/{}/environ", parent.as_raw_nonzero())) else {
        // Cannot tell. Refusing is the side that cannot be wrong in a way that
        // matters: the password still works.
        return true;
    };
    environ.split(|b| *b == 0).any(|var| {
        var.starts_with(b"SSH_CONNECTION=")
            || var.starts_with(b"SSH_CLIENT=")
            || var.starts_with(b"SSH_TTY=")
    })
}

/// Whether the `sudo` that ran this is one somebody is sitting at.
///
/// Not when its standard input is not a terminal -- `sudo -S` reading a
/// password from a pipe, `sudo -A` with an askpass program -- and not with
/// `-n`, which must never wait for anything. In each of those a prompt to
/// touch the sensor would be a pause nobody sees, in front of a script.
fn interactive() -> bool {
    let Some(parent) = rustix::process::getppid() else {
        return false;
    };
    let pid = parent.as_raw_nonzero();
    let stdin_is_tty = std::fs::read_link(format!("/proc/{pid}/fd/0"))
        .is_ok_and(|target| is_terminal_path(&target));
    let args: Vec<String> = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect()
        })
        .unwrap_or_default();
    stdin_is_tty && !non_interactive(&args)
}

fn is_terminal_path(target: &Path) -> bool {
    let target = target.to_string_lossy();
    target.starts_with("/dev/pts/") || target.starts_with("/dev/tty")
}

/// Whether `sudo`'s own arguments ask it never to prompt.
///
/// Only the options before the command are sudo's, so this stops at the first
/// word that is not one. It errs towards "yes": a short option cluster with an
/// `n` in it anywhere counts, and the cost of a wrong yes is only that the
/// password is asked for instead of a finger.
fn non_interactive(args: &[String]) -> bool {
    /// Short options whose value is the next word: `-u root`, `-g wheel`.
    const TAKES_VALUE: [char; 10] = ['u', 'g', 'p', 'C', 'D', 'r', 't', 'T', 'U', 'c'];
    let mut words = args.iter().skip(1);
    while let Some(arg) = words.next() {
        match arg.as_str() {
            "--" => return false,
            "--non-interactive" | "--stdin" | "--askpass" => return true,
            long if long.starts_with("--") => {}
            short if short.starts_with('-') && short.len() > 1 => {
                if short.contains(['n', 'S', 'A']) {
                    return true;
                }
                if short.ends_with(TAKES_VALUE) {
                    words.next();
                }
            }
            _ => return false,
        }
    }
    false
}

/// The terminal `sudo` is running on.
struct Tty {
    file: File,
}

impl Tty {
    fn open() -> Option<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        Some(Self { file })
    }

    fn say(&self, line: &str) {
        let _ = writeln!(&self.file, "{line}");
    }

    fn reader(&self) -> Option<File> {
        self.file.try_clone().ok()
    }

    /// Turn echo off until the guard drops, or until a signal ends the
    /// process.
    ///
    /// Off because people type `sudo` and then their password without looking
    /// up, and while this is waiting for a finger nothing is reading the
    /// terminal the way the password prompt would -- so what they type would
    /// be echoed in the clear, into the scrollback.
    fn quiet(&self) -> Option<EchoGuard> {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

        let saved = tcgetattr(&self.file).ok()?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        tcsetattr(&self.file, OptionalActions::Now, &quiet).ok()?;

        // A Ctrl-C mid-wait must not leave the terminal silent afterwards: the
        // shell would come back with nothing echoed and no sign of why.
        if let (Ok(file), Ok(mut signals)) = (
            self.file.try_clone(),
            signal_hook::iterator::Signals::new([
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
                signal_hook::consts::SIGHUP,
                signal_hook::consts::SIGQUIT,
            ]),
        ) {
            let restore = saved.clone();
            std::thread::spawn(move || {
                if signals.forever().next().is_some() {
                    let _ = tcsetattr(&file, OptionalActions::Now, &restore);
                    let _ = writeln!(&file);
                    std::process::exit(1);
                }
            });
        }

        Some(EchoGuard {
            file: self.file.try_clone().ok()?,
            saved,
        })
    }
}

struct EchoGuard {
    file: File,
    saved: rustix::termios::Termios,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // Anything typed while waiting -- often the start of a password --
        // goes, rather than being handed to the command sudo is about to run.
        let _ = rustix::termios::tcflush(&self.file, rustix::termios::QueueSelector::IFlush);
        let _ = rustix::termios::tcsetattr(
            &self.file,
            rustix::termios::OptionalActions::Now,
            &self.saved,
        );
    }
}

// ---------------------------------------------------------------------------
// Installing the PAM line
// ---------------------------------------------------------------------------

fn pam_line() -> String {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .unwrap_or_else(|_| PathBuf::from("/usr/bin/raven-finger-auth"));
    format!(
        "auth       sufficient   pam_exec.so quiet seteuid {}",
        exe.display()
    )
}

fn has_line(text: &str) -> bool {
    text.lines()
        .any(|line| !line.trim_start().starts_with('#') && line.contains(MARKER))
}

/// Put the line after `pam_rootok` -- root never needs a finger -- and before
/// everything else in the auth stack.
fn with_line(text: &str, line: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let is_auth = |l: &&str| l.split_whitespace().next() == Some("auth");
    let at = lines
        .iter()
        .rposition(|l| is_auth(l) && l.contains("pam_rootok.so"))
        .map(|i| i + 1)
        .or_else(|| lines.iter().position(is_auth))
        .unwrap_or(lines.len());

    let mut out: Vec<&str> = Vec::with_capacity(lines.len() + 1);
    out.extend_from_slice(&lines[..at]);
    out.push(line);
    out.extend_from_slice(&lines[at..]);
    let mut joined = out.join("\n");
    joined.push('\n');
    joined
}

fn without_line(text: &str) -> String {
    let mut out: String = text
        .lines()
        .filter(|line| line.trim_start().starts_with('#') || !line.contains(MARKER))
        .collect::<Vec<_>>()
        .join("\n");
    out.push('\n');
    out
}

fn install_pam(file: &Path) -> std::io::Result<String> {
    let text = std::fs::read_to_string(file)?;
    if has_line(&text) {
        return Ok(format!("{} already asks for a finger", file.display()));
    }
    if !["/usr/lib/security/pam_exec.so", "/lib/security/pam_exec.so"]
        .iter()
        .any(|p| Path::new(p).exists())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "pam_exec.so is not installed, so PAM cannot run this; nothing was changed",
        ));
    }
    replace(file, &with_line(&text, &pam_line()))?;
    Ok(format!(
        "{} now offers the fingerprint reader before the password",
        file.display()
    ))
}

fn remove_pam(file: &Path) -> std::io::Result<String> {
    let text = std::fs::read_to_string(file)?;
    if !has_line(&text) {
        return Ok(format!("{} does not ask for a finger", file.display()));
    }
    replace(file, &without_line(&text))?;
    Ok(format!(
        "{} asks only for the password again",
        file.display()
    ))
}

/// Write `text` over `file` through a rename, keeping its mode.
///
/// A PAM file that is half written is a `sudo` that refuses everybody, which
/// on a machine whose only root access is `sudo` is a machine that needs a
/// rescue disk.
fn replace(file: &Path, text: &str) -> std::io::Result<()> {
    let permissions = std::fs::metadata(file)?.permissions();
    let tmp = file.with_extension("raven-finger.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::set_permissions(&tmp, permissions)?;
    std::fs::rename(&tmp, file)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAVEN_SUDO: &str = "#%PAM-1.0
# Begin /etc/pam.d/sudo - RavenLinux
auth       sufficient   pam_rootok.so
auth       required     pam_unix.so nullok try_first_pass
account    sufficient   pam_rootok.so
account    required     pam_unix.so
session    required     pam_unix.so
# End /etc/pam.d/sudo
";

    const LINE: &str =
        "auth       sufficient   pam_exec.so quiet seteuid /usr/bin/raven-finger-auth";

    #[test]
    fn the_line_goes_after_rootok_and_before_the_password() {
        let out = with_line(RAVEN_SUDO, LINE);
        let lines: Vec<&str> = out.lines().collect();
        let rootok = lines
            .iter()
            .position(|l| l.contains("auth") && l.contains("pam_rootok"))
            .unwrap();
        assert_eq!(lines[rootok + 1], LINE);
        assert!(lines[rootok + 2].contains("pam_unix"));
        assert!(has_line(&out));
    }

    /// Arch's file includes system-auth rather than naming pam_unix.
    #[test]
    fn without_rootok_it_goes_first_in_the_auth_stack() {
        let arch = "#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\n";
        let out = with_line(arch, LINE);
        assert_eq!(out.lines().nth(1), Some(LINE));
    }

    #[test]
    fn removing_restores_the_file() {
        let out = without_line(&with_line(RAVEN_SUDO, LINE));
        assert_eq!(out, RAVEN_SUDO);
        assert!(!has_line(&out));
    }

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    /// A sudo that must not wait, or that reads its password from somewhere
    /// other than a person, gets no finger prompt.
    #[test]
    fn sudo_options_that_forbid_waiting_are_seen() {
        for line in [
            "sudo -n true",
            "sudo --non-interactive true",
            "sudo -nu root true",
            "sudo -S apt",
            "sudo -A make install",
            "sudo --stdin true",
            "sudo -u root -n true",
        ] {
            assert!(non_interactive(&args(line)), "{line}");
        }
        for line in [
            "sudo pacman -Syu",
            "sudo -u root ls -n",
            "sudo -- nano /etc/hosts",
            "sudo -E env",
        ] {
            assert!(!non_interactive(&args(line)), "{line}");
        }
    }

    #[test]
    fn terminals_are_recognised_by_their_device() {
        assert!(is_terminal_path(Path::new("/dev/pts/3")));
        assert!(is_terminal_path(Path::new("/dev/tty2")));
        assert!(!is_terminal_path(Path::new("pipe:[12345]")));
        assert!(!is_terminal_path(Path::new("/dev/null")));
    }

    /// A commented-out mention is not an installed line.
    #[test]
    fn a_comment_does_not_count() {
        assert!(!has_line(
            "# auth sufficient pam_exec.so raven-finger-auth\n"
        ));
    }
}
