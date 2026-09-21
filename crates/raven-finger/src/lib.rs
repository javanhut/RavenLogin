//! Fingers, from the side of the machine that decides what they are worth.
//!
//! Two things live here because two processes need them and they must agree:
//! `ravend`, which answers the login screen, the lock screen and the settings
//! panel, and `raven-finger-auth`, which `sudo` runs through `pam_exec`.
//!
//! - [`policy`]: where an account has said a finger may stand in for its
//!   password. A file per account, owned by root, written only by `ravend` and
//!   only for the account asking.
//! - [`sensor`]: a client for `raven-fprintd`'s socket. That socket is root's,
//!   so both callers are root; nothing unprivileged ever reaches the reader
//!   except by asking `ravend`.
//!
//! # What a finger is allowed to do
//!
//! Whatever its owner turned on, and never more than the password could. The
//! password stays offered beside it everywhere -- the field on the login and
//! lock screens is live the whole time, and `sudo` falls through to its
//! password prompt the moment the reader gives up -- because a reader that has
//! broken, got dirty, or decided today that this is not the finger it enrolled
//! must be an inconvenience and never a locked-out machine.

#![forbid(unsafe_code)]

pub mod policy;
pub mod sensor;

pub use sensor::{Sensor, Watch, WatchEvent};

/// Clean misses a watch allows before it stops offering the reader.
///
/// A miss is a finger the sensor read well and did not know. An unusable
/// reading is not one -- see [`WatchEvent::Retry`] -- so this is three honest
/// tries, not three presses of a wet thumb.
pub const MAX_MISSES: u8 = 3;

/// The sentence for one of `raven-fprintd`'s retry words.
///
/// Imperative, and never blaming the person for a sensor that could not read.
/// Off-centre and not-enough are kept apart because the corrections differ: a
/// finger that is already centred should not be told to move.
#[must_use]
pub fn advice(word: &str) -> &'static str {
    match word {
        "centre" | "center" => "Centre your finger on the sensor.",
        "cover" => "Cover more of the sensor with your finger.",
        "wipe" => "Wipe the sensor and try again.",
        _ => "Try again.",
    }
}

/// Re-exported: the rule now lives in `raven-greet-proto`, because
/// `raven-face` needs the same one and a second copy of it is a second thing
/// to get wrong.
pub use raven_greet_proto::valid_account;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_retry_word_has_a_sentence() {
        for word in ["centre", "cover", "wipe", "again", "try again", "?"] {
            assert!(advice(word).ends_with('.'));
        }
        assert_ne!(advice("centre"), advice("cover"));
    }
}
