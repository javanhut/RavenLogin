//! Faces, from the side of the machine that decides what they are worth.
//!
//! The shape of [`raven_finger`], deliberately, because the two are the same
//! kind of thing and a machine with both should not have two of everything:
//!
//! - [`policy`]: where an account has said its face may stand in for its
//!   password. A file per account, owned by root, written only by `ravend` and
//!   only for the account asking.
//! - [`camera`]: a client for `raven-faced`'s socket. That socket is root's, so
//!   the only caller is `ravend`; nothing unprivileged ever reaches the camera.
//!
//! [`raven_finger`]: https://docs.rs/raven-finger
//!
//! # How a face is weaker than a finger, and what follows from it
//!
//! A fingerprint is presented on purpose, to a reader that has to be touched.
//! A face is presented continuously, to a sensor across the room, by somebody
//! who may be asleep or looking at something else -- and, unlike a finger, it
//! is a thing other people already have photographs of.
//!
//! Three things follow, and all three are enforced rather than advised:
//!
//! - There is no `sudo` switch. See [`FacePolicy`].
//! - A watch is refused outright unless the screen asking for it will run the
//!   liveness challenge. See [`Flash`].
//! - The password field stays live underneath, as it does for a finger, so a
//!   camera that has failed is an inconvenience and never a locked-out machine.
//!
//! [`FacePolicy`]: raven_greet_proto::FacePolicy
//! [`Flash`]: raven_greet_proto::Flash

#![forbid(unsafe_code)]

pub mod camera;
pub mod policy;

pub use camera::{EnrolEvent, Faced, Progress, Watch, WatchEvent};
pub use raven_greet_proto::valid_account;

/// Clean misses a watch allows before it stops offering the camera.
///
/// The same three [`raven_finger::MAX_MISSES`] allows, and counted the same
/// way: a miss is a face the camera saw properly and did not know. A look the
/// camera could not use is not one -- see [`WatchEvent::Retry`] -- so this is
/// three honest tries and not three seconds of somebody walking past.
///
/// [`raven_finger::MAX_MISSES`]: https://docs.rs/raven-finger
pub const MAX_MISSES: u8 = 3;

/// Good captures one enrolment wants.
///
/// More than one, because a template built from a single frame is a template
/// of one blink, and fewer than a fingerprint's nine, because the camera can
/// take them as fast as somebody can sit still.
pub const ENROL_CAPTURES: u8 = 5;

/// The sentence for one of `raven-faced`'s retry words.
///
/// Imperative, and never blaming the person for a camera that could not see.
/// Each one names a different thing to do, because a correction that does not
/// say what to change is a correction somebody repeats.
#[must_use]
pub fn advice(word: &str) -> &'static str {
    match word {
        "look" => "Look at the camera.",
        "dark" => "There is not enough light to see you.",
        "bright" => "The light behind you is too strong. Try facing a window.",
        "far" => "Move a little closer.",
        "near" => "Move back a little.",
        "angle" => "Look straight at the camera.",
        "still" => "Hold still.",
        "covered" => "Something is covering the camera.",
        "alone" => "Only one person should be in view.",
        _ => "Try again.",
    }
}

/// What to say about a face the liveness check would not pass.
///
/// One sentence, and it says what to do rather than what was suspected. Two
/// reasons, pulling the same way: the person who sees this most often is the
/// account's owner in bad light, and telling somebody who is *not* the owner
/// precisely which part of the check they failed is telling them what to fix.
#[must_use]
pub const fn spoof_advice() -> &'static str {
    "Could not tell that was a live face. Try again in better light."
}

/// `<account>:<look>`, split.
///
/// The account cannot contain a colon -- see [`valid_account`] -- so the first
/// one is the boundary. The same shape `raven-fprintd` uses for a finger, so
/// that the two daemons' records read alike.
#[must_use]
pub fn split_label(label: &str) -> Option<(&str, u8)> {
    let (account, look) = label.split_once(':')?;
    let look = look.trim().parse().ok()?;
    (!account.is_empty()).then_some((account, look))
}

/// A label as it may be written on one line of the camera socket.
///
/// Whatever somebody typed, with the two things a line protocol cannot carry
/// taken out -- a newline would end the message early, and a control character
/// would be rendered by whatever draws it. Capped, because a label is a note
/// to oneself and not a document.
#[must_use]
pub fn clean_label(label: &str) -> String {
    label
        .chars()
        .filter(|c| !c.is_control())
        .take(48)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_retry_word_has_its_own_sentence() {
        let words = ["look", "dark", "bright", "far", "near", "angle", "still", "covered", "alone"];
        for word in words {
            assert!(advice(word).ends_with('.'), "{word} has no sentence");
        }
        // A correction that says the same thing as another correction is one
        // somebody cannot act on: "move closer" and "move back" must differ.
        let mut sentences: Vec<&str> = words.iter().map(|w| advice(w)).collect();
        sentences.sort_unstable();
        let before = sentences.len();
        sentences.dedup();
        assert_eq!(sentences.len(), before, "two retry words say the same thing");
        assert_eq!(advice("something-new"), "Try again.");
    }

    #[test]
    fn labels_split_at_the_first_colon() {
        assert_eq!(split_label("javan:2"), Some(("javan", 2)));
        assert_eq!(split_label("nocolon"), None);
        assert_eq!(split_label(":2"), None);
        assert_eq!(split_label("javan:not-a-number"), None);
    }

    /// A label goes onto one line of a text protocol, so it may not end one.
    #[test]
    fn a_label_cannot_end_the_line_it_is_written_on() {
        assert_eq!(clean_label("with glasses"), "with glasses");
        assert_eq!(clean_label("  padded  "), "padded");
        assert_eq!(clean_label("one\nok error two"), "oneok error two");
        assert_eq!(clean_label("\r\n\t"), "");
        assert!(clean_label(&"x".repeat(500)).len() <= 48);
    }

    /// The spoof sentence must not name the check it failed.
    #[test]
    fn the_spoof_sentence_says_what_to_do_and_not_what_was_suspected() {
        let said = spoof_advice().to_lowercase();
        for leak in ["photo", "screen", "print", "replay", "flash", "spoof"] {
            assert!(!said.contains(leak), "{leak:?} is in the spoof sentence");
        }
        assert!(said.ends_with('.'));
    }
}
