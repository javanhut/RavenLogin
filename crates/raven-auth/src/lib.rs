//! Deciding whether someone may start a session.
//!
//! Three questions, kept apart because they fail differently:
//!
//! 1. **Who exists?** [`passwd`] — readable by anyone, and the greeter needs it
//!    to draw a list of faces before anybody has typed anything.
//! 2. **What does this account's password field say?** [`shadow`] — readable
//!    only by root, and only ever inside `ravend`.
//! 3. **Does this password produce that hash?** `raven-crypt` — pure, and
//!    tested against libxcrypt.
//!
//! The answer to (1) is not a secret and the answer to (2) is, which is the
//! seam the daemon/greeter split is cut along: the process that draws the login
//! screen can answer (1) for itself and must ask for (2).

#![forbid(unsafe_code)]

pub mod passwd;
pub mod shadow;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub use passwd::Account;
pub use raven_crypt::Scheme;
use raven_crypt::Verdict;
pub use shadow::Status;

/// Something went wrong reading the system's account files.
///
/// Distinct from "authentication failed": a missing `/etc/shadow` is a broken
/// machine, not a wrong password, and the two must not produce the same
/// message.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the system clock is before the Unix epoch; account aging cannot be evaluated")]
    ClockBeforeEpoch,
}

/// The questions about *policy* rather than about this machine's files.
/// Both fields default to `false`, which is derived rather than written out —
/// the safe answer for each happens to be "off", and an explicit impl saying so
/// would just be a second place to keep in step. The reasoning for each default
/// is on the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Policy {
    /// Whether an account with an empty password field may log in by pressing
    /// Enter.
    ///
    /// Off by default, and the default is the interesting half. An empty hash
    /// means "no password has been set", which on a half-provisioned machine is
    /// an accident rather than an intent — and a graphical greeter that accepts
    /// it turns that accident into an unlocked machine for anyone who walks
    /// past. A console login can still be used to set one.
    pub allow_empty_password: bool,

    /// Whether `root` may log in to a graphical session.
    ///
    /// Off by default. Nothing on this desktop needs to be root, `sudo-rs` is
    /// installed for the things that do, and a root session is one
    /// misconfigured application away from being unable to open its own home
    /// directory. This is separate from the uid-range check in
    /// [`Account::is_person`] so that turning it on is one obvious switch
    /// rather than a change to what "a person" means.
    pub allow_root: bool,
}

/// Why a login attempt did not produce a session.
///
/// Every variant here is something a person could be told. What they are
/// *actually* told is the greeter's decision — see
/// [`Denial::is_safe_to_display`] — but the daemon knows the real reason and
/// logs it, so that "it just says wrong password" is always diagnosable from
/// the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// The account exists and the password is wrong.
    BadPassword,
    /// No such account.
    NoSuchUser,
    /// The account exists but is a daemon, or has a `nologin` shell.
    NotAPerson,
    /// `root`, with [`Policy::allow_root`] off.
    RootNotPermitted,
    /// `passwd -l`, or an account that never had a password set.
    Locked,
    /// The hash is `*`.
    NoPasswordLogin,
    /// The account has no password and [`Policy::allow_empty_password`] is off.
    PasswordlessNotPermitted,
    /// The account's expiry date has passed.
    AccountExpired,
    /// The password's lifetime has run out, and a greeter cannot change it.
    PasswordExpired,
    /// The password must be changed at next login, which must happen elsewhere.
    MustChangePassword,
    /// The hash is in a scheme `raven-crypt` cannot compute. Not a wrong
    /// password — a machine this build cannot log in to at all.
    UnsupportedHash(Scheme),
    /// The shadow line is damaged.
    MalformedHash,
}

impl Denial {
    /// Whether this reason can be shown on the login screen as-is.
    ///
    /// The three that can are the ones where the person's next action differs:
    /// an expired password sends them to a console, an unsupported hash sends
    /// them to whoever built the image. Everything else collapses to "wrong
    /// password" on screen — not to prevent account enumeration, which a
    /// greeter that draws a list of users has already conceded, but because
    /// "that account is locked" tells someone who is not the account's owner
    /// something they have no use for, and tells the owner nothing they can act
    /// on either.
    #[must_use]
    pub fn is_safe_to_display(self) -> bool {
        matches!(
            self,
            Self::AccountExpired
                | Self::PasswordExpired
                | Self::MustChangePassword
                | Self::UnsupportedHash(_)
        )
    }

    /// The sentence to put in front of the person at the keyboard.
    #[must_use]
    pub fn message(self) -> String {
        match self {
            Self::AccountExpired => "This account has expired.".to_string(),
            Self::PasswordExpired => {
                "This password has expired. Change it from a console, then log in.".to_string()
            }
            Self::MustChangePassword => {
                "This password must be changed. Do it from a console, then log in.".to_string()
            }
            Self::UnsupportedHash(scheme) => {
                format!(
                    "This account's password uses {}, which this build cannot check.",
                    scheme.name()
                )
            }
            _ => "Incorrect password.".to_string(),
        }
    }
}

/// What an attempt produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The password was right, and this is who to start a session as.
    Granted(Box<Account>),
    Denied(Denial),
}

/// A hash to check a password against when there is nothing to check it
/// against.
///
/// When the named account does not exist, or is locked, the honest
/// implementation returns immediately — and takes a few microseconds to do it,
/// against the ~4ms that 5000 rounds of SHA-512 cost for an account that does
/// exist. That difference is measurable over a socket, and it turns the login
/// screen into an oracle for which accounts are real.
///
/// So the work is done anyway, against this. The password is
/// `raven-auth-timing-equalizer`, which is not a secret because nothing
/// authenticates against it; what matters is only that it is a real `$6$` hash
/// with the default round count, so that checking it costs what checking a real
/// one costs.
const TIMING_EQUALIZER: &str = "$6$ravenlogin$h.y/.sSnqYmMxGdzyULDnA5wE/nVfSv6W1v7GUKHf8qPQQtrj1HgEC80oWKNUS9ltu1N0tcYGJuRE3SDvoI61/";

/// Reads the system's account files and answers login attempts.
#[derive(Debug, Clone)]
pub struct Authenticator {
    passwd_path: PathBuf,
    shadow_path: PathBuf,
    group_path: PathBuf,
    policy: Policy,
}

impl Authenticator {
    /// The real system's files.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            passwd_path: PathBuf::from("/etc/passwd"),
            shadow_path: PathBuf::from("/etc/shadow"),
            group_path: PathBuf::from("/etc/group"),
            policy,
        }
    }

    /// Point at a different set of files. For tests, and for a build host
    /// checking an image it is not running.
    #[must_use]
    pub fn with_paths(
        policy: Policy,
        passwd_path: impl AsRef<Path>,
        shadow_path: impl AsRef<Path>,
        group_path: impl AsRef<Path>,
    ) -> Self {
        Self {
            passwd_path: passwd_path.as_ref().to_path_buf(),
            shadow_path: shadow_path.as_ref().to_path_buf(),
            group_path: group_path.as_ref().to_path_buf(),
            policy,
        }
    }

    /// The accounts a login screen should offer, lowest uid first.
    ///
    /// Sorted by uid rather than by name so the order is stable across
    /// machines and across an edit to `/etc/passwd`: the tile someone reaches
    /// for by muscle memory should not move because a new account was created.
    pub fn people(&self) -> Result<Vec<Account>, Error> {
        let mut accounts = passwd::load(&self.passwd_path)?;
        accounts.retain(Account::is_person);
        accounts.sort_by_key(|a| a.uid);
        passwd::attach_groups(&mut accounts, &self.group_path);
        Ok(accounts)
    }

    /// Check `password` against `name`, and say who to start a session as.
    ///
    /// The password is borrowed as bytes rather than as a `str` because a
    /// password is not required to be UTF-8 — a keyboard layout that produces
    /// a stray byte should fail to match, not fail to be represented.
    pub fn authenticate(&self, name: &str, password: &[u8]) -> Result<Outcome, Error> {
        let today = days_since_epoch()?;

        // Resolve the account first. Everything below wants it, and its absence
        // is the case that most needs the timing floor applied.
        let account = passwd::load(&self.passwd_path)?
            .into_iter()
            .find(|a| a.name == name);

        let Some(mut account) = account else {
            return Ok(self.denied_after_equal_work(password, Denial::NoSuchUser));
        };

        if account.uid == 0 && !self.policy.allow_root {
            return Ok(self.denied_after_equal_work(password, Denial::RootNotPermitted));
        }
        if !account.is_person() && account.uid != 0 {
            return Ok(self.denied_after_equal_work(password, Denial::NotAPerson));
        }

        let Some(entry) = shadow::find(&self.shadow_path, name)? else {
            // An account in passwd with no shadow line. On a shadowed system
            // this is a broken account, not a passwordless one.
            return Ok(self.denied_after_equal_work(password, Denial::NoSuchUser));
        };

        let denial = match shadow::status(&entry, today) {
            Status::Usable => None,
            Status::Locked => Some(Denial::Locked),
            Status::NoPasswordLogin => Some(Denial::NoPasswordLogin),
            Status::AccountExpired => Some(Denial::AccountExpired),
            Status::PasswordExpired => Some(Denial::PasswordExpired),
            Status::MustChangePassword => Some(Denial::MustChangePassword),
            Status::Passwordless => {
                if self.policy.allow_empty_password && password.is_empty() {
                    // Nothing to check. Fall through to a grant below.
                    passwd::attach_groups(std::slice::from_mut(&mut account), &self.group_path);
                    return Ok(Outcome::Granted(Box::new(account)));
                }
                Some(Denial::PasswordlessNotPermitted)
            }
        };
        if let Some(denial) = denial {
            return Ok(self.denied_after_equal_work(password, denial));
        }

        match raven_crypt::verify(password, &entry.hash) {
            Verdict::Match => {
                passwd::attach_groups(std::slice::from_mut(&mut account), &self.group_path);
                Ok(Outcome::Granted(Box::new(account)))
            }
            Verdict::Mismatch => Ok(Outcome::Denied(Denial::BadPassword)),
            Verdict::Unsupported(scheme) => {
                tracing::error!(
                    account = %name,
                    scheme = scheme.name(),
                    "this account's password hash is in a scheme raven-crypt cannot check; \
                     nobody can log in to it graphically until it is re-hashed with passwd"
                );
                Ok(Outcome::Denied(Denial::UnsupportedHash(scheme)))
            }
            Verdict::Malformed => {
                tracing::error!(account = %name, "damaged /etc/shadow line");
                Ok(Outcome::Denied(Denial::MalformedHash))
            }
        }
    }

    /// Return `denial`, having first spent what a real check would have spent.
    ///
    /// See [`TIMING_EQUALIZER`]. The result is discarded — deliberately, and
    /// `black_box` keeps the optimizer from noticing that and deleting the
    /// work, which would silently remove the only thing this function does.
    fn denied_after_equal_work(&self, password: &[u8], denial: Denial) -> Outcome {
        let verdict = raven_crypt::verify(password, TIMING_EQUALIZER);
        let _ = std::hint::black_box(verdict);
        Outcome::Denied(denial)
    }
}

/// Today, as days since the Unix epoch, which is the unit `/etc/shadow` counts
/// aging in.
fn days_since_epoch() -> Result<i64, Error> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::ClockBeforeEpoch)?
        .as_secs();
    // u64 seconds / 86400 cannot exceed i64 for any clock this side of the
    // heat death of the universe, but the cast is done explicitly rather than
    // by inference so it is visible.
    Ok(i64::try_from(secs / 86_400).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `$6$` hash of "correct horse", generated with `openssl passwd -6`.
    const HORSE: &str = "$6$ravensalt$Lqq6CckQU4F9v/LsmKwDfkl1CwgIEVYU7EcYw/DFZcG2MknNLWcA3N144U/vQcAnXJ2/Uub3Rqofrnw/h1VlY.";

    pub(super) struct Fixture {
        pub(super) _dir: std::path::PathBuf,
        pub(super) auth: Authenticator,
    }

    pub(super) fn fixture(policy: Policy, shadow_extra: &str) -> Fixture {
        // A unique directory per test, without a tempfile dependency.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("raven-auth-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("can create a test directory");

        let passwd = dir.join("passwd");
        let shadow = dir.join("shadow");
        let group = dir.join("group");

        std::fs::write(
            &passwd,
            "root:x:0:0:root:/root:/bin/bash\n\
             javan:x:1000:1000:Javan,,,:/home/javan:/usr/bin/ravenshell\n\
             svc:x:1002:1002::/var/lib/svc:/usr/bin/nologin\n",
        )
        .expect("can write passwd");
        std::fs::write(
            &shadow,
            format!(
                "root:!:20000:0:99999:7:::\n\
                 javan:{HORSE}:20000:0:99999:7:::\n\
                 svc:!:20000:0:99999:7:::\n{shadow_extra}"
            ),
        )
        .expect("can write shadow");
        std::fs::write(&group, "javan:x:1000:\nvideo:x:91:javan\n").expect("can write group");

        Fixture {
            auth: Authenticator::with_paths(policy, &passwd, &shadow, &group),
            _dir: dir,
        }
    }

    #[test]
    fn the_right_password_grants() {
        let f = fixture(Policy::default(), "");
        let outcome = f
            .auth
            .authenticate("javan", b"correct horse")
            .expect("readable files");
        match outcome {
            Outcome::Granted(account) => {
                assert_eq!(account.name, "javan");
                assert_eq!(account.uid, 1000);
                // Groups must be attached on the granted account, or the
                // session starts without `video` and cannot open the GPU.
                assert!(account.groups.contains(&91), "groups were not attached");
            }
            other => panic!("expected a grant, got {other:?}"),
        }
    }

    #[test]
    fn the_wrong_password_denies() {
        let f = fixture(Policy::default(), "");
        assert_eq!(
            f.auth
                .authenticate("javan", b"wrong horse")
                .expect("readable files"),
            Outcome::Denied(Denial::BadPassword)
        );
    }

    #[test]
    fn unknown_accounts_are_denied() {
        let f = fixture(Policy::default(), "");
        assert_eq!(
            f.auth
                .authenticate("nobodyhere", b"anything")
                .expect("readable files"),
            Outcome::Denied(Denial::NoSuchUser)
        );
    }

    #[test]
    fn root_is_refused_by_default_even_with_the_right_password() {
        let f = fixture(Policy::default(), "");
        assert_eq!(
            f.auth
                .authenticate("root", b"anything")
                .expect("readable files"),
            Outcome::Denied(Denial::RootNotPermitted)
        );
    }

    #[test]
    fn nologin_accounts_are_refused() {
        let f = fixture(Policy::default(), "");
        assert_eq!(
            f.auth
                .authenticate("svc", b"anything")
                .expect("readable files"),
            Outcome::Denied(Denial::NotAPerson)
        );
    }

    #[test]
    fn a_passwordless_account_is_refused_by_default() {
        let f = fixture(Policy::default(), "empty::20000:0:99999:7:::\n");
        std::fs::write(
            f._dir.join("passwd"),
            "empty:x:1003:1003::/home/empty:/bin/sh\n",
        )
        .expect("can rewrite passwd");
        assert_eq!(
            f.auth.authenticate("empty", b"").expect("readable files"),
            Outcome::Denied(Denial::PasswordlessNotPermitted)
        );
    }

    #[test]
    fn a_passwordless_account_is_allowed_when_policy_says_so() {
        let policy = Policy {
            allow_empty_password: true,
            ..Policy::default()
        };
        let f = fixture(policy, "empty::20000:0:99999:7:::\n");
        std::fs::write(
            f._dir.join("passwd"),
            "empty:x:1003:1003::/home/empty:/bin/sh\n",
        )
        .expect("can rewrite passwd");
        assert!(matches!(
            f.auth.authenticate("empty", b"").expect("readable files"),
            Outcome::Granted(_)
        ));
        // ...but only with an actually empty password. A non-empty guess
        // against a passwordless account is still a denial, not a grant.
        assert_eq!(
            f.auth
                .authenticate("empty", b"something")
                .expect("readable files"),
            Outcome::Denied(Denial::PasswordlessNotPermitted)
        );
    }

    #[test]
    fn only_actionable_denials_reach_the_screen() {
        assert!(!Denial::BadPassword.is_safe_to_display());
        assert!(!Denial::NoSuchUser.is_safe_to_display());
        assert!(!Denial::Locked.is_safe_to_display());
        assert!(Denial::PasswordExpired.is_safe_to_display());
        assert!(Denial::UnsupportedHash(Scheme::Yescrypt).is_safe_to_display());
        // The ones that do not reach the screen all say the same thing.
        assert_eq!(Denial::Locked.message(), "Incorrect password.");
        assert_eq!(Denial::NoSuchUser.message(), "Incorrect password.");
    }

    #[test]
    fn people_excludes_root_and_daemons() {
        let f = fixture(Policy::default(), "");
        let names: Vec<String> = f
            .auth
            .people()
            .expect("readable files")
            .into_iter()
            .map(|a| a.name)
            .collect();
        assert_eq!(names, vec!["javan"]);
    }
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    /// The timing floor is load-bearing and silently breakable: if
    /// `TIMING_EQUALIZER` were ever mistyped, `verify` would reject it as
    /// malformed in microseconds and every "no such user" would answer
    /// instantly again — restoring exactly the oracle it exists to remove,
    /// with no test failing. So assert it is a hash that actually gets
    /// computed.
    #[test]
    fn the_timing_equalizer_is_a_computable_hash() {
        assert_eq!(
            raven_crypt::verify(b"raven-auth-timing-equalizer", TIMING_EQUALIZER),
            Verdict::Match,
            "TIMING_EQUALIZER must be a real $6$ hash of its documented password"
        );
        assert_eq!(
            raven_crypt::verify(b"anything else", TIMING_EQUALIZER),
            Verdict::Mismatch
        );
    }

    /// A missing account must not answer measurably faster than a wrong
    /// password. The threshold is deliberately loose — this is a test suite on
    /// a shared machine, not a lab bench — but a regression that removed the
    /// equalizer entirely turns ~4ms into ~50us, which is two orders of
    /// magnitude and clears any sane threshold.
    #[test]
    fn a_missing_account_is_not_measurably_faster() {
        let f = super::tests::fixture(Policy::default(), "");
        let time = |name: &str| {
            let start = std::time::Instant::now();
            for _ in 0..5 {
                let _ = f.auth.authenticate(name, b"some guess");
            }
            start.elapsed()
        };
        // Warm the page cache so the first call does not pay for the file read.
        let _ = time("javan");

        let real = time("javan");
        let missing = time("nobodyhere");
        let ratio = real.as_secs_f64() / missing.as_secs_f64().max(f64::MIN_POSITIVE);
        assert!(
            ratio < 8.0,
            "a real account took {ratio:.1}x as long as a missing one \
             ({real:?} vs {missing:?}); the timing equalizer is not doing its job"
        );
    }
}
