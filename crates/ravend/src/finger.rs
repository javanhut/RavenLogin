//! Fingers: what `ravend` lets them do, and the conversations that carry them.
//!
//! The reader is root's. `raven-fprintd` drives it and answers one question --
//! which stored finger is on the sensor -- and this module decides what that
//! answer is worth, the way the rest of `ravend` decides what a password is
//! worth. Nothing unprivileged reaches the reader except through here.
//!
//! # Who may ask what
//!
//! On the verify socket, everything is about the connection's own account,
//! resolved from `SO_PEERCRED` as it is for `Verify`: its status, its fingers,
//! its policy, a watch for its own fingers. Enrolling one and switching any use
//! of one *on* take the password, because a finger can be enrolled by whoever
//! is sitting at an unlocked machine and a password cannot be.
//!
//! On the greet socket there is one request, [`Request::LoginByFinger`], and
//! it names the account because at the login screen there is nobody logged in
//! to be the connection's owner. The name only chooses whose fingers count. A
//! finger enrolled to anybody else is a miss, however cleanly it matched.
//!
//! # The watch is the connection
//!
//! A watch holds the reader for as long as the screen is up, and it ends when
//! the connection does: a thread waits for the client to hang up, and hangs up
//! on `raven-fprintd` when it does. A lock screen that dies, or a greeter that
//! `ravend` stops because somebody typed their password, puts the reader down
//! without having to say so.
//!
//! [`Request::LoginByFinger`]: raven_greet_proto::Request::LoginByFinger

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use raven_auth::{Account, Authenticator, Denial, Outcome};
use raven_finger::sensor::{Sensor, Watch, WatchEvent};
use raven_finger::{MAX_MISSES, policy};
use raven_greet_proto::{Finger, FingerPolicy, Reader, Response};

/// What a watch is for, which decides the policy switch it needs and what a
/// match turns into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    /// The login screen: a match starts a session.
    Login,
    /// The lock screen: a match lets the session back in.
    Unlock,
}

impl Use {
    fn allowed_by(self, policy: FingerPolicy) -> bool {
        match self {
            Self::Login => policy.login,
            Self::Unlock => policy.unlock,
        }
    }
}

/// How long a spent budget of misses lasts, if the password does not reset it
/// first. The same fifteen minutes the password throttle forgets after.
const STRIKES_LAST: Duration = Duration::from_secs(15 * 60);

/// Clean misses per account, across watches and across both screens.
///
/// [`Sensor::watch`] stops after [`MAX_MISSES`], but a client could simply
/// start another watch. So the count lives here, and a new watch gets only
/// what is left of it. It is not a lockout: the password field is on screen
/// the whole time, and a right password clears the count.
#[derive(Debug, Default)]
struct Strikes {
    counts: HashMap<String, (u8, Instant)>,
}

impl Strikes {
    fn left(&mut self, account: &str, now: Instant) -> u8 {
        match self.counts.get(account) {
            Some((_, at)) if now.duration_since(*at) > STRIKES_LAST => {
                self.counts.remove(account);
                MAX_MISSES
            }
            Some((count, _)) => MAX_MISSES.saturating_sub(*count),
            None => MAX_MISSES,
        }
    }

    fn miss(&mut self, account: &str, now: Instant) {
        let entry = self.counts.entry(account.to_string()).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now;
    }

    fn clear(&mut self, account: &str) {
        self.counts.remove(account);
    }
}

static STRIKES: LazyLock<Mutex<Strikes>> = LazyLock::new(Mutex::default);

fn strikes() -> std::sync::MutexGuard<'static, Strikes> {
    STRIKES.lock().unwrap_or_else(|e| e.into_inner())
}

/// A right password resets the finger budget, as it resets the password
/// throttle. Called from both sockets' password paths.
pub(crate) fn password_succeeded(account: &str) {
    strikes().clear(account);
}

/// How long the calls that answer at once may wait on `raven-fprintd`.
///
/// It serves one connection at a time, so a screen holding the reader makes
/// every other caller wait. A settings panel asking for status should be told
/// the reader is busy, not hang.
///
/// Longer than one sensor command can take -- `raven-fprintd` gives the write
/// and the read five seconds each -- so that a daemon bringing a slow sensor up
/// is waited for rather than reported busy on every single request. Each
/// connection here has its own thread, so the wait holds up nobody else.
const QUICK: Duration = Duration::from_secs(12);

fn connect_quick() -> std::io::Result<Option<Sensor>> {
    let sensor = Sensor::connect()?;
    if let Some(sensor) = &sensor {
        sensor.set_read_timeout(Some(QUICK))?;
    }
    Ok(sensor)
}

/// [`Response::FingerStatus`] for `account`.
pub(crate) fn status(account: &str) -> Response {
    let policy = policy::load(account);
    let (reader, enrolled) = match connect_quick() {
        Ok(None) => (Reader::NoService, Vec::new()),
        Ok(Some(mut sensor)) => match sensor.status() {
            Ok(reader) if reader.is_present() => {
                let enrolled = sensor.fingers_of(account).unwrap_or_else(|e| {
                    tracing::warn!("cannot list fingers: {e}");
                    Vec::new()
                });
                (reader, enrolled)
            }
            Ok(reader) => (reader, Vec::new()),
            Err(e) => return busy_or_broken(&e),
        },
        Err(e) => return busy_or_broken(&e),
    };
    Response::FingerStatus {
        reader,
        enrolled,
        policy,
    }
}

fn busy_or_broken(e: &std::io::Error) -> Response {
    tracing::warn!("cannot reach raven-fprintd: {e}");
    let message = if matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        "The fingerprint reader is busy. Try again in a moment."
    } else if e.kind() == std::io::ErrorKind::Other {
        // `raven-fprintd` answered, with an `error` line: the daemon is fine
        // and the sensor is what failed.
        "The fingerprint reader is not responding. Try again in a moment."
    } else {
        "The fingerprint service is not answering."
    };
    Response::Failed {
        message: message.to_string(),
    }
}

/// Forget one of `account`'s fingers, or clear the sensor entirely.
///
/// `Some(finger)` is this account's and only this account's. `None` is the
/// whole sensor, everybody's fingers included, which is not a thing to do
/// quietly: it exists because a reader may have no way to remove one finger at
/// a time -- the Elan `0c00` refuses every per-finger delete it is sent and
/// honours only "clear everything" -- and on such a reader it is the only
/// removal there is. Whatever asks for it is responsible for saying so first.
///
/// This used to be one finger at a time in both cases, on the reasoning that
/// `raven-fprintd`'s `forget-all` would take other people's. It would, and it
/// still does; what changed is that the alternative turned out not to exist on
/// the hardware in hand.
pub(crate) fn forget(account: &str, finger: Option<Finger>) -> Response {
    let mut sensor = match connect_quick() {
        Ok(Some(sensor)) => sensor,
        Ok(None) => {
            return Response::Failed {
                message: "The fingerprint service is not running.".to_string(),
            };
        }
        Err(e) => return busy_or_broken(&e),
    };
    match finger {
        Some(finger) => {
            if let Err(e) = sensor.forget(account, finger) {
                tracing::warn!(user = %account, finger = finger.as_str(), "cannot forget: {e}");
                // The daemon's own words, not a summary of them. A reader that
                // cannot remove one finger says which removal it can do, and
                // that sentence is the only thing that tells somebody what to
                // try instead.
                return Response::Failed {
                    message: format!("Could not remove the {}. {e}", finger.label().to_lowercase()),
                };
            }
            tracing::info!(user = %account, finger = finger.as_str(), "forgot a finger");
        }
        // Everybody's fingers, in one command, because a reader without a
        // per-finger delete cannot do it any other way -- and one that has one
        // still ends up here only when somebody asked for the lot. What this
        // costs other accounts is said at the point somebody is asked to
        // confirm it, which is the settings page and not here.
        None => {
            if let Err(e) = sensor.forget_all() {
                tracing::warn!(user = %account, "cannot clear the sensor: {e}");
                return Response::Failed {
                    message: format!("Could not remove the fingerprints. {e}"),
                };
            }
            tracing::info!(user = %account, "cleared every finger on the sensor");
        }
    }
    // With nothing left to present, every switch is off. Leaving them on would
    // mean re-enrolling one finger quietly brought back fingerprint sudo that
    // somebody had forgotten they ever turned on.
    if sensor.fingers_of(account).is_ok_and(|left| left.is_empty())
        && let Err(e) = policy::remove(account)
    {
        tracing::warn!(user = %account, "cannot clear the fingerprint policy: {e}");
    }
    drop(sensor);
    status(account)
}

/// Store where `account`'s fingers may be used. The caller has already
/// checked the password if this widens anything.
pub(crate) fn set_policy(account: &str, next: FingerPolicy) -> Response {
    if let Err(e) = policy::save(account, next) {
        tracing::error!(user = %account, "cannot save the fingerprint policy: {e}");
        return Response::Failed {
            message: "Could not save the fingerprint settings.".to_string(),
        };
    }
    tracing::info!(
        user = %account,
        login = next.login,
        unlock = next.unlock,
        sudo = next.sudo,
        "fingerprint policy changed"
    );
    status(account)
}

/// Hang up on `raven-fprintd` when the client hangs up on us.
///
/// Returns the flag that says the client went first, which is what tells a
/// cancelled watch from a daemon that died under one.
fn follow_client(client: &UnixStream, sensor: &Sensor) -> std::io::Result<Arc<AtomicBool>> {
    let mut client = client.try_clone()?;
    let hangup = sensor.hangup_handle()?;
    let gone = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&gone);
    std::thread::Builder::new()
        .name("finger-hangup".to_string())
        .spawn(move || {
            // Nothing is expected from the client mid-watch. Anything at all
            // -- a byte, a close, a timeout -- ends it.
            let mut byte = [0u8; 1];
            let _ = client.read(&mut byte);
            flag.store(true, Ordering::SeqCst);
            let _ = hangup.shutdown(std::net::Shutdown::Both);
        })?;
    Ok(gone)
}

/// Send one response; a client that has gone is not an error worth more than
/// a debug line, because the watch is about to notice the same thing.
fn send<W: Write>(writer: &mut W, response: &Response) {
    if let Err(e) = raven_greet_proto::write_message(writer, response) {
        tracing::debug!("cannot write to a finger client: {e}");
    }
}

fn finger(message: &str) -> Response {
    Response::Finger {
        message: message.to_string(),
        progress: None,
    }
}

fn unavailable(reason: &str) -> Response {
    Response::FingerUnavailable {
        reason: reason.to_string(),
    }
}

/// Watch the reader for `account` and send the conversation down `writer`.
///
/// Returns the admitted account on a match, for the login screen to start a
/// session with. The connection is shut down before this returns, whatever
/// happened: a watch is one conversation, and the thread following the client
/// has to be woken so it can go.
///
/// `claim` is asked once, after a match and before the success is sent. The
/// login screen uses it so that a finger and a password arriving in the same
/// instant cannot both start a session; `false` turns the match away.
pub(crate) fn watch<W: Write>(
    account: &str,
    purpose: Use,
    authenticator: &Authenticator,
    client: &UnixStream,
    writer: &mut W,
    claim: impl FnOnce() -> bool,
) -> Option<Account> {
    let admitted = watch_inner(account, purpose, authenticator, client, writer, claim);
    let _ = writer.flush();
    let _ = client.shutdown(std::net::Shutdown::Both);
    admitted
}

fn watch_inner<W: Write>(
    account: &str,
    purpose: Use,
    authenticator: &Authenticator,
    client: &UnixStream,
    writer: &mut W,
    claim: impl FnOnce() -> bool,
) -> Option<Account> {
    if !purpose.allowed_by(policy::load(account)) {
        send(
            writer,
            &unavailable("fingerprint is not turned on for this"),
        );
        return None;
    }
    let allowed = strikes().left(account, Instant::now());
    if allowed == 0 {
        send(
            writer,
            &unavailable("too many fingers were not recognised; use the password"),
        );
        return None;
    }

    let mut sensor = match connect_quick() {
        Ok(Some(sensor)) => sensor,
        Ok(None) => {
            send(
                writer,
                &unavailable("the fingerprint service is not running"),
            );
            return None;
        }
        Err(e) => {
            tracing::warn!("cannot reach raven-fprintd: {e}");
            send(
                writer,
                &unavailable("the fingerprint service is not answering"),
            );
            return None;
        }
    };
    match sensor.fingers_of(account) {
        Ok(fingers) if !fingers.is_empty() => {}
        Ok(_) => {
            send(writer, &unavailable("no fingers are enrolled"));
            return None;
        }
        Err(e) => {
            tracing::warn!(user = %account, "cannot list fingers: {e}");
            send(
                writer,
                &unavailable("the fingerprint reader is not answering"),
            );
            return None;
        }
    }
    // From here the wait has no deadline: a lock screen sits overnight.
    if sensor.set_read_timeout(None).is_err() {
        send(
            writer,
            &unavailable("the fingerprint reader is not answering"),
        );
        return None;
    }
    let client_gone = match follow_client(client, &sensor) {
        Ok(flag) => flag,
        Err(e) => {
            tracing::warn!("cannot follow the finger client: {e}");
            send(
                writer,
                &unavailable("the login service is short of resources"),
            );
            return None;
        }
    };

    tracing::info!(user = %account, ?purpose, "watching the reader");
    send(writer, &finger("Touch the fingerprint sensor."));

    let verdict = sensor.watch(account, allowed, |event| match event {
        WatchEvent::Retry(advice) => send(writer, &finger(advice)),
        WatchEvent::Miss { .. } => {
            strikes().miss(account, Instant::now());
            send(writer, &finger("Not recognised. Try again."));
        }
    });

    match verdict {
        Ok(Watch::Matched(which)) => admit(account, which, purpose, authenticator, writer, claim),
        Ok(Watch::Missed) => {
            strikes().miss(account, Instant::now());
            tracing::warn!(user = %account, ?purpose, "fingerprint not recognised; watch over");
            send(
                writer,
                &Response::Denied {
                    message: "Fingerprint not recognised. Enter your password.".to_string(),
                    retry_after_ms: 0,
                },
            );
            None
        }
        Ok(Watch::Cancelled) if client_gone.load(Ordering::SeqCst) => {
            tracing::debug!(user = %account, "the finger client hung up");
            None
        }
        Ok(Watch::Cancelled) | Err(_) => {
            if let Err(e) = verdict {
                tracing::warn!(user = %account, "the fingerprint watch failed: {e}");
            }
            send(
                writer,
                &Response::Failed {
                    message: "The fingerprint reader stopped responding.".to_string(),
                },
            );
            None
        }
    }
}

/// A match, and the account's own. It still has to be an account that may
/// come in: a locked or expired one is refused here exactly as its password
/// would have been.
fn admit<W: Write>(
    account: &str,
    which: Option<Finger>,
    purpose: Use,
    authenticator: &Authenticator,
    writer: &mut W,
    claim: impl FnOnce() -> bool,
) -> Option<Account> {
    match authenticator.admit(account) {
        Ok(Outcome::Granted(_)) if !claim() => {
            tracing::warn!(user = %account, "fingerprint matched after another login had begun");
            send(
                writer,
                &Response::Failed {
                    message: "Another login is already starting.".to_string(),
                },
            );
            None
        }
        Ok(Outcome::Granted(admitted)) => {
            strikes().clear(account);
            tracing::info!(
                user = %account,
                finger = which.map_or("unnamed", Finger::as_str),
                ?purpose,
                "fingerprint accepted"
            );
            let response = match purpose {
                Use::Login => Response::Granted {
                    username: account.to_string(),
                },
                Use::Unlock => Response::Verified,
            };
            send(writer, &response);
            Some(*admitted)
        }
        Ok(Outcome::Denied(denial)) => {
            tracing::warn!(user = %account, ?denial, "fingerprint matched but the account is refused");
            let message = if denial.is_safe_to_display() {
                denial.message()
            } else {
                Denial::BadPassword.message()
            };
            send(
                writer,
                &Response::Denied {
                    message,
                    retry_after_ms: 0,
                },
            );
            None
        }
        Err(e) => {
            tracing::error!("cannot read the account database: {e:#}");
            send(
                writer,
                &Response::Failed {
                    message: "This machine's account database cannot be read.".to_string(),
                },
            );
            None
        }
    }
}

/// Enrol one of `account`'s fingers, streaming progress down `writer`. The
/// caller has checked the password. Shuts the connection down when done.
pub(crate) fn enrol<W: Write>(account: &str, which: Finger, client: &UnixStream, writer: &mut W) {
    enrol_inner(account, which, client, writer);
    let _ = writer.flush();
    let _ = client.shutdown(std::net::Shutdown::Both);
}

fn enrol_inner<W: Write>(account: &str, which: Finger, client: &UnixStream, writer: &mut W) {
    let failed = |writer: &mut W, message: &str| {
        send(
            writer,
            &Response::Failed {
                message: message.to_string(),
            },
        );
    };
    let mut sensor = match connect_quick() {
        Ok(Some(sensor)) => sensor,
        Ok(None) => return failed(writer, "The fingerprint service is not running."),
        Err(e) => {
            if let Response::Failed { message } = busy_or_broken(&e) {
                failed(writer, &message);
            }
            return;
        }
    };
    match sensor.status() {
        Ok(reader) if reader.is_present() => {}
        Ok(_) => return failed(writer, "There is no fingerprint reader on this machine."),
        Err(e) => {
            if let Response::Failed { message } = busy_or_broken(&e) {
                failed(writer, &message);
            }
            return;
        }
    }
    if sensor.set_read_timeout(None).is_err() {
        return failed(writer, "The fingerprint reader is not answering.");
    }
    let client_gone = match follow_client(client, &sensor) {
        Ok(flag) => flag,
        Err(_) => return failed(writer, "The login service is short of resources."),
    };

    tracing::info!(user = %account, finger = which.as_str(), "enrolling");
    send(
        writer,
        &Response::Finger {
            message: format!(
                "Touch the sensor with your {}.",
                which.label().to_lowercase()
            ),
            progress: None,
        },
    );
    let result = sensor.enrol(account, which, |progress| {
        let message = match progress.retry {
            Some(advice) => advice.to_string(),
            None if progress.done >= progress.of => "Got it.".to_string(),
            None => "Lift your finger, then touch the sensor again.".to_string(),
        };
        send(
            writer,
            &Response::Finger {
                message,
                progress: Some((progress.done, progress.of)),
            },
        );
    });
    match result {
        Ok(true) => {
            tracing::info!(user = %account, finger = which.as_str(), "enrolled");
            send(writer, &Response::FingerEnrolled { finger: which });
        }
        Ok(false) if client_gone.load(Ordering::SeqCst) => {
            tracing::info!(user = %account, "enrolment cancelled");
        }
        Ok(false) => failed(writer, "The fingerprint reader stopped responding."),
        Err(e) => {
            tracing::warn!(user = %account, "enrolment failed: {e}");
            // raven-fprintd's reasons are written for people -- "the sensor
            // could not read that finger" -- and name nothing about anybody
            // else, so they are safe to pass on.
            let why = e.to_string();
            let mut why = why.trim().to_string();
            if let Some(first) = why.get(..1) {
                why = first.to_uppercase() + &why[1..];
            }
            failed(writer, &format!("{why}."));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strikes_are_shared_across_watches_and_reset_by_a_password() {
        let mut s = Strikes::default();
        let now = Instant::now();
        assert_eq!(s.left("javan", now), MAX_MISSES);
        s.miss("javan", now);
        s.miss("javan", now);
        assert_eq!(
            s.left("javan", now),
            MAX_MISSES - 2,
            "a new watch gets what is left"
        );
        assert_eq!(s.left("other", now), MAX_MISSES, "per account");
        s.miss("javan", now);
        assert_eq!(s.left("javan", now), 0);
        s.clear("javan");
        assert_eq!(s.left("javan", now), MAX_MISSES);
    }

    #[test]
    fn a_spent_budget_comes_back_on_its_own() {
        let mut s = Strikes::default();
        let then = Instant::now();
        for _ in 0..MAX_MISSES {
            s.miss("javan", then);
        }
        assert_eq!(s.left("javan", then), 0);
        assert_eq!(
            s.left("javan", then + STRIKES_LAST + Duration::from_secs(1)),
            MAX_MISSES
        );
    }

    #[test]
    fn each_screen_needs_its_own_switch() {
        let unlock_only = FingerPolicy {
            unlock: true,
            ..FingerPolicy::default()
        };
        assert!(Use::Unlock.allowed_by(unlock_only));
        assert!(!Use::Login.allowed_by(unlock_only));
        assert!(!Use::Unlock.allowed_by(FingerPolicy::default()));
    }
}
