//! Slowing down repeated failures.
//!
//! A login screen with no throttle is an offline attack that does not need the
//! hash file: a script driving the socket can try passwords as fast as
//! sha512-crypt runs, which on a modern machine is a few thousand a second.
//! The 5000 rounds are a cost to the attacker, but they are a cost this daemon
//! pays too, and paying it in a loop is not a defence.
//!
//! The shape here is deliberately dull — a free allowance, then exponential
//! backoff to a ceiling — because the interesting failure modes of a login
//! throttle are all about *who* gets delayed, not how long for:
//!
//! - **Per account, not per connection.** A throttle keyed on the connection is
//!   defeated by reconnecting, which costs an attacker one syscall.
//! - **Failures only.** A correct password clears the account's counter, so
//!   somebody who mistypes twice and then gets it right is not left waiting on
//!   their next login.
//! - **No global lockout.** Nothing here can make an account permanently
//!   unreachable, because the machine this runs on is somebody's own computer
//!   and the person most likely to be locked out of it by a lockout policy is
//!   its owner. The ceiling is a delay, not a wall.
//!
//! This is pure and takes its clock as an argument, so every branch is testable
//! without sleeping.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How the backoff is shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Failures allowed before any delay at all. Covers the ordinary case of
    /// mistyping a password, which should cost nothing.
    pub free_attempts: u32,
    /// The delay after the first non-free failure. Doubles from there.
    pub base_delay: Duration,
    /// The longest this will ever make somebody wait.
    pub max_delay: Duration,
    /// How long a quiet account keeps its failure count. Long enough that a
    /// slow guessing loop cannot outwait it, short enough that yesterday's
    /// typos do not delay today's login.
    pub forget_after: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            free_attempts: 3,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            forget_after: Duration::from_secs(15 * 60),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Record {
    failures: u32,
    last_failure: Instant,
}

/// Failure counters, keyed by account name.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    limits: Limits,
    records: HashMap<String, Record>,
}

impl RateLimiter {
    #[must_use]
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            records: HashMap::new(),
        }
    }

    /// How long `account` must wait before another attempt is worth making.
    ///
    /// `now` is passed in rather than read here so the tests do not sleep.
    #[must_use]
    pub(crate) fn delay_for(&self, account: &str, now: Instant) -> Duration {
        let Some(record) = self.records.get(account) else {
            return Duration::ZERO;
        };
        let since = now.saturating_duration_since(record.last_failure);
        if since >= self.limits.forget_after {
            return Duration::ZERO;
        }

        let penalized = record.failures.saturating_sub(self.limits.free_attempts);
        if penalized == 0 {
            return Duration::ZERO;
        }

        // base * 2^(penalized-1), saturating rather than overflowing: a
        // determined script can drive `failures` arbitrarily high, and a shift
        // by 64 is undefined rather than merely large.
        let required = self
            .limits
            .base_delay
            .saturating_mul(1u32.checked_shl(penalized - 1).unwrap_or(u32::MAX))
            .min(self.limits.max_delay);

        required.saturating_sub(since)
    }

    /// Record a failed attempt.
    pub(crate) fn record_failure(&mut self, account: &str, now: Instant) {
        let record = self.records.entry(account.to_string()).or_insert(Record {
            failures: 0,
            last_failure: now,
        });
        // An account that has been quiet long enough starts over rather than
        // resuming yesterday's backoff.
        if now.saturating_duration_since(record.last_failure) >= self.limits.forget_after {
            record.failures = 0;
        }
        record.failures = record.failures.saturating_add(1);
        record.last_failure = now;
    }

    /// Record a success, clearing the account's history.
    pub(crate) fn record_success(&mut self, account: &str) {
        self.records.remove(account);
    }

    /// Drop records that have aged out. Called occasionally so that a machine
    /// left at a login screen for a month does not accumulate an entry per
    /// account name anybody ever typed.
    pub(crate) fn forget_old(&mut self, now: Instant) {
        let forget_after = self.limits.forget_after;
        self.records
            .retain(|_, r| now.saturating_duration_since(r.last_failure) < forget_after);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            free_attempts: 3,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            forget_after: Duration::from_secs(900),
        }
    }

    #[test]
    fn an_unknown_account_waits_for_nothing() {
        let limiter = RateLimiter::new(limits());
        assert_eq!(limiter.delay_for("javan", Instant::now()), Duration::ZERO);
    }

    #[test]
    fn the_first_few_failures_are_free() {
        let mut limiter = RateLimiter::new(limits());
        let now = Instant::now();
        for _ in 0..3 {
            limiter.record_failure("javan", now);
            assert_eq!(limiter.delay_for("javan", now), Duration::ZERO);
        }
    }

    #[test]
    fn delay_doubles_after_the_free_attempts() {
        let mut limiter = RateLimiter::new(limits());
        let now = Instant::now();
        for _ in 0..4 {
            limiter.record_failure("javan", now);
        }
        assert_eq!(limiter.delay_for("javan", now), Duration::from_secs(1));
        limiter.record_failure("javan", now);
        assert_eq!(limiter.delay_for("javan", now), Duration::from_secs(2));
        limiter.record_failure("javan", now);
        assert_eq!(limiter.delay_for("javan", now), Duration::from_secs(4));
    }

    #[test]
    fn the_delay_stops_at_the_ceiling() {
        let mut limiter = RateLimiter::new(limits());
        let now = Instant::now();
        for _ in 0..40 {
            limiter.record_failure("javan", now);
        }
        assert_eq!(limiter.delay_for("javan", now), Duration::from_secs(30));
    }

    /// Forty failures shifts by 37, which overflows a naive `1 << n`.
    #[test]
    fn an_absurd_failure_count_does_not_overflow() {
        let mut limiter = RateLimiter::new(limits());
        let now = Instant::now();
        for _ in 0..1000 {
            limiter.record_failure("javan", now);
        }
        assert_eq!(limiter.delay_for("javan", now), Duration::from_secs(30));
    }

    /// Time already served counts. Waiting out a 4-second penalty and then
    /// trying should not restart the clock.
    #[test]
    fn time_already_waited_counts_against_the_delay() {
        let mut limiter = RateLimiter::new(limits());
        let start = Instant::now();
        for _ in 0..5 {
            limiter.record_failure("javan", start);
        }
        assert_eq!(limiter.delay_for("javan", start), Duration::from_secs(2));
        let later = start + Duration::from_millis(1500);
        assert_eq!(
            limiter.delay_for("javan", later),
            Duration::from_millis(500)
        );
        let done = start + Duration::from_secs(2);
        assert_eq!(limiter.delay_for("javan", done), Duration::ZERO);
    }

    #[test]
    fn a_success_clears_the_history() {
        let mut limiter = RateLimiter::new(limits());
        let now = Instant::now();
        for _ in 0..6 {
            limiter.record_failure("javan", now);
        }
        assert!(limiter.delay_for("javan", now) > Duration::ZERO);
        limiter.record_success("javan");
        assert_eq!(limiter.delay_for("javan", now), Duration::ZERO);
    }

    /// The throttle is per account: hammering one must not delay another.
    #[test]
    fn accounts_are_throttled_independently() {
        let mut limiter = RateLimiter::new(limits());
        let now = Instant::now();
        for _ in 0..10 {
            limiter.record_failure("javan", now);
        }
        assert!(limiter.delay_for("javan", now) > Duration::ZERO);
        assert_eq!(limiter.delay_for("second", now), Duration::ZERO);
    }

    #[test]
    fn an_account_left_alone_is_forgiven() {
        let mut limiter = RateLimiter::new(limits());
        let start = Instant::now();
        for _ in 0..10 {
            limiter.record_failure("javan", start);
        }
        let much_later = start + Duration::from_secs(901);
        assert_eq!(limiter.delay_for("javan", much_later), Duration::ZERO);
        // And the next failure starts a fresh, free run rather than resuming.
        limiter.record_failure("javan", much_later);
        assert_eq!(limiter.delay_for("javan", much_later), Duration::ZERO);
    }

    #[test]
    fn old_records_are_dropped() {
        let mut limiter = RateLimiter::new(limits());
        let start = Instant::now();
        limiter.record_failure("javan", start);
        limiter.forget_old(start + Duration::from_secs(901));
        assert!(limiter.records.is_empty());
    }
}
