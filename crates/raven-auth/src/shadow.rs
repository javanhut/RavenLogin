//! `/etc/shadow`: the password hash, and the aging fields around it.
//!
//! This file is `0600 root:root`. Everything in this module therefore runs
//! inside `ravend` and nowhere else — the greeter that draws the password box
//! never links a code path that opens it. That split is the whole reason
//! `ravend` exists.
//!
//! Field order, from `shadow(5)`:
//!
//! ```text
//! name:hash:last_change:min:max:warn:inactive:expire:reserved
//!   0    1       2        3   4   5      6       7      8
//! ```
//!
//! Every numeric field is optional and empty means "unset", which is why they
//! are all `Option<i64>` rather than defaulted to zero. Zero is a real value in
//! `last_change` — it means "must change password at next login" — so
//! collapsing empty into zero would lock accounts out of their own machine.

use std::fs;
use std::path::Path;

use zeroize::Zeroize;

use crate::Error;

/// One `/etc/shadow` line.
///
/// `Zeroize` on drop: this struct owns a password hash, and a hash that has
/// been read once should not stay in the daemon's heap until the allocator
/// happens to reuse the page. It is not a password, but it is the thing an
/// offline attack is run against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    pub name: String,
    /// Field 1, verbatim — including a `!` or `*` prefix, which is what makes
    /// an account locked and must not be stripped before [`status`] sees it.
    pub hash: String,
    /// Days since the epoch when the password was last changed. `Some(0)` means
    /// "must be changed at next login".
    pub last_change: Option<i64>,
    /// Days that must pass before the password may be changed again.
    pub min: Option<i64>,
    /// Days after `last_change` that the password remains valid.
    pub max: Option<i64>,
    /// Days before expiry to start warning. Not enforced here; carried so a
    /// greeter can say "your password expires in 3 days".
    pub warn: Option<i64>,
    /// Days after password expiry before the account is disabled entirely.
    pub inactive: Option<i64>,
    /// Days since the epoch after which the account is disabled outright.
    pub expire: Option<i64>,
}

impl Drop for ShadowEntry {
    fn drop(&mut self) {
        self.hash.zeroize();
    }
}

/// Why an account cannot be logged into, or that it can.
///
/// Separate from "the password was wrong" on purpose. All of these are states
/// of the *account*, knowable before a password is checked, and each one needs
/// a different sentence in front of the person at the keyboard: "your password
/// expired" and "your password is wrong" send them to completely different
/// places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The account has a usable password. Check it.
    Usable,
    /// The hash is `!` or `!!` or begins with `!` — `passwd -l`, or an account
    /// created but never given a password.
    Locked,
    /// The hash is `*` — no password will ever match. Conventionally a system
    /// account, or one that authenticates by some other means entirely.
    NoPasswordLogin,
    /// The hash field is empty: the account has no password at all.
    ///
    /// Whether this may be logged into is a policy question, not a parsing
    /// one, so it is reported rather than decided here.
    Passwordless,
    /// `expire` has passed: the account is disabled.
    AccountExpired,
    /// `last_change + max` has passed: the password must be changed, and a
    /// greeter cannot change it.
    PasswordExpired,
    /// `last_change` is 0: the password must be changed at next login.
    MustChangePassword,
}

/// What a shadow line says about whether this account can be logged into
/// today.
///
/// `today` is days since the Unix epoch, passed in rather than read from the
/// clock so that every one of these branches is testable without waiting for
/// one. The caller gets it from the system clock exactly once per attempt.
///
/// Order matters, and it is from most to least fundamental: an expired account
/// is dead regardless of its password, a locked one cannot be unlocked by
/// typing the right thing, and an expired password is only worth mentioning to
/// someone whose account is otherwise fine.
#[must_use]
pub fn status(entry: &ShadowEntry, today: i64) -> Status {
    // Field 7. A literal 0 here is ambiguous in the wild — some tools write it
    // meaning "never" — but shadow(5) says days-since-epoch, which would be
    // 1970 and expired. Treating 0 as "not set" is what `shadow` itself does.
    if let Some(expire) = entry.expire
        && expire > 0
        && today >= expire
    {
        return Status::AccountExpired;
    }

    if entry.hash.is_empty() {
        return Status::Passwordless;
    }
    // `*` is checked before `!`, since `!*` should read as locked either way
    // and the leading character is what decides.
    if entry.hash.starts_with('!') {
        return Status::Locked;
    }
    if entry.hash.starts_with('*') {
        return Status::NoPasswordLogin;
    }

    match entry.last_change {
        // 0 is "change it at next login", not "changed on 1 Jan 1970".
        Some(0) => return Status::MustChangePassword,
        Some(last_change) => {
            // A `max` of 0 or less means aging is off, not "expired instantly".
            if let Some(max) = entry.max
                && max > 0
                && today >= last_change.saturating_add(max)
            {
                return Status::PasswordExpired;
            }
        }
        None => {}
    }

    Status::Usable
}

/// Read every entry from an `/etc/shadow`-shaped file.
pub fn load(path: &Path) -> Result<Vec<ShadowEntry>, Error> {
    let mut text = fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.display().to_string(),
        source,
    })?;
    let entries = parse(&text);
    // The whole file was just in a String. Wipe it before it goes back to the
    // allocator; the entries keep their own copies and wipe those on drop.
    text.zeroize();
    Ok(entries)
}

/// Find one entry by account name.
pub fn find(path: &Path, name: &str) -> Result<Option<ShadowEntry>, Error> {
    Ok(load(path)?.into_iter().find(|e| e.name == name))
}

#[must_use]
pub fn parse(text: &str) -> Vec<ShadowEntry> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<ShadowEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let fields: Vec<&str> = line.split(':').collect();
    // Name and hash are the only two a line cannot do without. Real files have
    // nine fields, but a hand-edited one missing its trailing colons should
    // still authenticate rather than lock the machine.
    if fields.len() < 2 {
        return None;
    }

    let field = |i: usize| -> Option<i64> { fields.get(i)?.trim().parse().ok() };

    Some(ShadowEntry {
        name: fields[0].to_string(),
        hash: fields[1].to_string(),
        last_change: field(2),
        min: field(3),
        max: field(4),
        warn: field(5),
        inactive: field(6),
        expire: field(7),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-08-27, the day this was written, as days since the epoch.
    const TODAY: i64 = 20692;

    fn entry(line: &str) -> ShadowEntry {
        parse_line(line).expect("a parseable shadow line")
    }

    #[test]
    fn parses_a_full_line() {
        let e = entry("javan:$6$salt$hash:20000:0:99999:7:::");
        assert_eq!(e.name, "javan");
        assert_eq!(e.hash, "$6$salt$hash");
        assert_eq!(e.last_change, Some(20000));
        assert_eq!(e.min, Some(0));
        assert_eq!(e.max, Some(99999));
        assert_eq!(e.warn, Some(7));
        assert_eq!(e.inactive, None);
        assert_eq!(e.expire, None);
    }

    #[test]
    fn a_normal_account_is_usable() {
        let e = entry("javan:$6$salt$hash:20000:0:99999:7:::");
        assert_eq!(status(&e, TODAY), Status::Usable);
    }

    #[test]
    fn empty_numeric_fields_are_none_not_zero() {
        let e = entry("javan:$6$salt$hash::::::");
        assert_eq!(e.last_change, None);
        assert_eq!(e.max, None);
        // And an unset last_change must not read as "must change password".
        assert_eq!(status(&e, TODAY), Status::Usable);
    }

    #[test]
    fn locked_accounts_are_locked() {
        assert_eq!(
            status(&entry("a:!:20000:0:99999:7:::"), TODAY),
            Status::Locked
        );
        assert_eq!(
            status(&entry("a:!!:20000:0:99999:7:::"), TODAY),
            Status::Locked
        );
        assert_eq!(
            status(&entry("a:!$6$salt$hash:20000:0:99999:7:::"), TODAY),
            Status::Locked
        );
    }

    #[test]
    fn star_is_not_a_password() {
        assert_eq!(
            status(&entry("a:*:20000:0:99999:7:::"), TODAY),
            Status::NoPasswordLogin
        );
    }

    #[test]
    fn an_empty_hash_is_passwordless() {
        assert_eq!(
            status(&entry("a::20000:0:99999:7:::"), TODAY),
            Status::Passwordless
        );
    }

    #[test]
    fn zero_last_change_means_change_it_now() {
        assert_eq!(
            status(&entry("a:$6$salt$hash:0:0:99999:7:::"), TODAY),
            Status::MustChangePassword
        );
    }

    #[test]
    fn a_password_past_its_max_has_expired() {
        // Changed 100 days ago, valid for 30.
        let line = format!("a:$6$salt$hash:{}:0:30:7:::", TODAY - 100);
        assert_eq!(status(&entry(&line), TODAY), Status::PasswordExpired);
    }

    /// The common `max = 99999` is aging switched off, not an expiry 273 years
    /// out that arithmetic might overflow into.
    #[test]
    fn a_huge_max_never_expires() {
        let line = format!("a:$6$salt$hash:{}:0:99999:7:::", TODAY - 100);
        assert_eq!(status(&entry(&line), TODAY), Status::Usable);
    }

    /// `max` of 0 means aging is disabled, and must not expire everything.
    #[test]
    fn a_zero_max_disables_aging() {
        let line = format!("a:$6$salt$hash:{}:0:0:7:::", TODAY - 100);
        assert_eq!(status(&entry(&line), TODAY), Status::Usable);
    }

    /// An out-of-range `last_change` must not panic the daemon on overflow.
    #[test]
    fn absurd_aging_values_do_not_overflow() {
        let line = format!("a:$6$salt$hash:{}:0:{}:7:::", i64::MAX, i64::MAX);
        assert_eq!(status(&entry(&line), TODAY), Status::Usable);
    }

    #[test]
    fn an_expired_account_is_expired_whatever_its_password_says() {
        let line = format!("a:$6$salt$hash:20000:0:99999:7::{}:", TODAY - 1);
        assert_eq!(status(&entry(&line), TODAY), Status::AccountExpired);
        // Even locked-and-expired reports the account, which is the more
        // fundamental of the two.
        let line = format!("a:!:20000:0:99999:7::{}:", TODAY - 1);
        assert_eq!(status(&entry(&line), TODAY), Status::AccountExpired);
    }

    /// `expire` of 0 is written by some tools to mean "never".
    #[test]
    fn a_zero_expire_means_never() {
        assert_eq!(
            status(&entry("a:$6$salt$hash:20000:0:99999:7::0:"), TODAY),
            Status::Usable
        );
    }

    /// An account expiring today is expired; tomorrow is not.
    #[test]
    fn expiry_boundary_is_inclusive() {
        let today = format!("a:$6$h$h:20000:0:99999:7::{TODAY}:");
        let tomorrow = format!("a:$6$h$h:20000:0:99999:7::{}:", TODAY + 1);
        assert_eq!(status(&entry(&today), TODAY), Status::AccountExpired);
        assert_eq!(status(&entry(&tomorrow), TODAY), Status::Usable);
    }

    #[test]
    fn a_truncated_line_still_parses_its_hash() {
        let e = entry("javan:$6$salt$hash");
        assert_eq!(e.hash, "$6$salt$hash");
        assert_eq!(status(&e, TODAY), Status::Usable);
    }

    #[test]
    fn junk_lines_are_skipped() {
        assert!(parse_line("noseparator").is_none());
        assert!(parse_line("").is_none());
        assert!(parse_line("# comment").is_none());
    }
}
