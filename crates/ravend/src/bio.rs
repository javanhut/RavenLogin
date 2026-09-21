//! What a finger and a face have in common, once the hardware is out of the
//! way.
//!
//! Two sensors, two daemons, two policies -- and underneath them one set of
//! rules about what a biometric proof is worth here. Those rules live in this
//! module rather than twice in [`crate::finger`] and [`crate::face`], because
//! every one of them is security-relevant and two copies of a security rule is
//! one copy that gets fixed:
//!
//! - **[`Use`]**: what a watch is for. Each screen needs its own switch; a
//!   face turned on for the lock screen does not open the login screen.
//! - **[`Strikes`]**: how many clean misses an account gets before the
//!   password is the only way in, counted across watches so that a client
//!   cannot buy three more by reconnecting. A right password clears it.
//! - **[`Follow`]**: how a watch ends when the client goes away. The watch is
//!   the connection; there is no cancel message to lose.
//! - **[`admit`]**: a match is not yet a login. The account still has to be
//!   one that may come in, and it is refused here exactly as its password
//!   would have been.
//!
//! # Why the two budgets are separate and the reset is shared
//!
//! Each modality counts its own misses. A dark room spends the face's budget
//! and must not also stop the fingerprint reader working -- they fail for
//! unrelated reasons, and a shared count would let either one's bad day
//! disable the other.
//!
//! A right password clears both, because a password is a stronger proof than
//! either and it has just been given. Anything else would leave somebody who
//! typed their way in still locked out of their own sensors.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use raven_auth::{Account, Authenticator, Denial, Outcome};
use raven_greet_proto::{FacePolicy, FingerPolicy, Response};

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
    fn allows(self, login: bool, unlock: bool) -> bool {
        match self {
            Self::Login => login,
            Self::Unlock => unlock,
        }
    }

    pub(crate) fn allowed_by_finger(self, policy: FingerPolicy) -> bool {
        self.allows(policy.login, policy.unlock)
    }

    pub(crate) fn allowed_by_face(self, policy: FacePolicy) -> bool {
        self.allows(policy.login, policy.unlock)
    }
}

/// How long a spent budget of misses lasts, if the password does not reset it
/// first. The same fifteen minutes the password throttle forgets after.
const STRIKES_LAST: Duration = Duration::from_secs(15 * 60);

/// Clean misses per account, across watches and across both screens.
///
/// A sensor's own watch stops after its maximum, but a client could simply
/// start another watch. So the count lives here, and a new watch gets only
/// what is left of it. It is not a lockout: the password field is on screen
/// the whole time, and a right password clears the count.
#[derive(Debug)]
pub(crate) struct Strikes {
    max: u8,
    counts: std::collections::HashMap<String, (u8, Instant)>,
}

impl Strikes {
    fn new(max: u8) -> Self {
        Self {
            max,
            counts: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn left(&mut self, account: &str, now: Instant) -> u8 {
        match self.counts.get(account) {
            Some((_, at)) if now.duration_since(*at) > STRIKES_LAST => {
                self.counts.remove(account);
                self.max
            }
            Some((count, _)) => self.max.saturating_sub(*count),
            None => self.max,
        }
    }

    pub(crate) fn miss(&mut self, account: &str, now: Instant) {
        let entry = self.counts.entry(account.to_string()).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now;
    }

    pub(crate) fn clear(&mut self, account: &str) {
        self.counts.remove(account);
    }
}

static FINGER: LazyLock<Mutex<Strikes>> =
    LazyLock::new(|| Mutex::new(Strikes::new(raven_finger::MAX_MISSES)));
static FACE: LazyLock<Mutex<Strikes>> =
    LazyLock::new(|| Mutex::new(Strikes::new(raven_face::MAX_MISSES)));

fn lock(strikes: &'static LazyLock<Mutex<Strikes>>) -> std::sync::MutexGuard<'static, Strikes> {
    strikes.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn finger_strikes() -> std::sync::MutexGuard<'static, Strikes> {
    lock(&FINGER)
}

pub(crate) fn face_strikes() -> std::sync::MutexGuard<'static, Strikes> {
    lock(&FACE)
}

/// A right password resets both budgets, as it resets the password throttle.
/// Called from both sockets' password paths.
pub(crate) fn password_succeeded(account: &str) {
    finger_strikes().clear(account);
    face_strikes().clear(account);
}

/// Whoever is on the far end of a watch, followed from another thread.
///
/// Set up once per watch, before any sensor exists, because a watch can spend
/// a while waiting for hardware to come back -- and a client that hangs up
/// during that wait must end it just as it ends one in progress.
pub(crate) struct Follow {
    /// The client went first: a cancelled watch, not a daemon that died.
    gone: Arc<AtomicBool>,
    /// The sensor connection to hang up on when it does. Replaced each time
    /// the watch reconnects.
    hangup: Arc<Mutex<Option<UnixStream>>>,
}

impl std::fmt::Debug for Follow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Follow")
            .field("gone", &self.is_gone())
            .finish_non_exhaustive()
    }
}

impl Follow {
    pub(crate) fn is_gone(&self) -> bool {
        self.gone.load(Ordering::SeqCst)
    }

    /// Point the hang-up at a fresh connection to the hardware daemon.
    /// `false` if the client has already gone, in which case that connection
    /// is not worth using.
    pub(crate) fn attach(&self, hangup: UnixStream) -> bool {
        *self.hangup.lock().unwrap_or_else(|e| e.into_inner()) = Some(hangup);
        // Checked after storing, so a hang-up racing this either sees the
        // handle and shuts it or is seen here.
        !self.is_gone()
    }
}

/// Hang up on the hardware daemon when the client hangs up on us.
///
/// `name` is what the following thread is called, so a stuck one can be told
/// apart from the other modality's in a backtrace.
pub(crate) fn follow_client(client: &UnixStream, name: &str) -> std::io::Result<Follow> {
    let mut client = client.try_clone()?;
    let follow = Follow {
        gone: Arc::new(AtomicBool::new(false)),
        hangup: Arc::new(Mutex::new(None)),
    };
    let (flag, slot) = (Arc::clone(&follow.gone), Arc::clone(&follow.hangup));
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            // Nothing is expected from the client mid-watch. Anything at all
            // -- a byte, a close, a timeout -- ends it.
            let mut byte = [0u8; 1];
            let _ = client.read(&mut byte);
            flag.store(true, Ordering::SeqCst);
            if let Some(hangup) = slot.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                let _ = hangup.shutdown(std::net::Shutdown::Both);
            }
        })?;
    Ok(follow)
}

/// Send one response; a client that has gone is not an error worth more than
/// a debug line, because the watch is about to notice the same thing.
pub(crate) fn send<W: Write>(writer: &mut W, response: &Response) {
    if let Err(e) = raven_greet_proto::write_message(writer, response) {
        tracing::debug!("cannot write to a biometric client: {e}");
    }
}

/// A match, and the account's own. It still has to be an account that may come
/// in: a locked or expired one is refused here exactly as its password would
/// have been.
///
/// `how` names the proof for the log -- `"right-index"`, `"look 2"` -- and
/// goes nowhere near the client. `strikes` is the budget that matched, and the
/// only one a success here clears: a face that worked says nothing about
/// whether the fingerprint reader is having a good day.
pub(crate) fn admit<W: Write>(
    account: &str,
    purpose: Use,
    how: &str,
    strikes: fn() -> std::sync::MutexGuard<'static, Strikes>,
    authenticator: &Authenticator,
    writer: &mut W,
    claim: impl FnOnce() -> bool,
) -> Option<Account> {
    match authenticator.admit(account) {
        Ok(Outcome::Granted(_)) if !claim() => {
            tracing::warn!(user = %account, how, "a biometric matched after another login had begun");
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
            tracing::info!(user = %account, how, ?purpose, "biometric accepted");
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
            tracing::warn!(user = %account, how, ?denial, "a biometric matched but the account is refused");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strikes_are_shared_across_watches_and_reset_by_a_password() {
        let mut s = Strikes::new(3);
        let now = Instant::now();
        assert_eq!(s.left("javan", now), 3);
        s.miss("javan", now);
        s.miss("javan", now);
        assert_eq!(s.left("javan", now), 1, "a new watch gets what is left");
        assert_eq!(s.left("other", now), 3, "per account");
        s.miss("javan", now);
        assert_eq!(s.left("javan", now), 0);
        s.clear("javan");
        assert_eq!(s.left("javan", now), 3);
    }

    #[test]
    fn a_spent_budget_comes_back_on_its_own() {
        let mut s = Strikes::new(3);
        let then = Instant::now();
        for _ in 0..3 {
            s.miss("javan", then);
        }
        assert_eq!(s.left("javan", then), 0);
        assert_eq!(s.left("javan", then + STRIKES_LAST + Duration::from_secs(1)), 3);
    }

    #[test]
    fn each_screen_needs_its_own_switch() {
        let unlock_only = FingerPolicy {
            unlock: true,
            ..FingerPolicy::default()
        };
        assert!(Use::Unlock.allowed_by_finger(unlock_only));
        assert!(!Use::Login.allowed_by_finger(unlock_only));
        assert!(!Use::Unlock.allowed_by_finger(FingerPolicy::default()));

        let face = FacePolicy {
            login: true,
            unlock: false,
        };
        assert!(Use::Login.allowed_by_face(face));
        assert!(!Use::Unlock.allowed_by_face(face));
    }

    /// A camera having a bad day must not stop the fingerprint reader, and the
    /// other way round. The two budgets are separate for that reason, and this
    /// is the test that keeps them so.
    #[test]
    fn the_two_budgets_do_not_spend_each_other() {
        let account = "budget-test-account";
        let now = Instant::now();
        for _ in 0..raven_face::MAX_MISSES {
            face_strikes().miss(account, now);
        }
        assert_eq!(face_strikes().left(account, now), 0);
        assert_eq!(
            finger_strikes().left(account, now),
            raven_finger::MAX_MISSES,
            "the finger still has its whole budget"
        );

        // ...and one password clears both.
        password_succeeded(account);
        assert_eq!(face_strikes().left(account, now), raven_face::MAX_MISSES);
        assert_eq!(finger_strikes().left(account, now), raven_finger::MAX_MISSES);
    }
}
