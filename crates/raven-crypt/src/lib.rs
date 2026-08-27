//! Checking a password against a `crypt(3)` hash from `/etc/shadow`.
//!
//! This crate is pure. It opens no files, spawns nothing, and logs nothing, so
//! the one piece of Raven that decides whether a password is right can be read
//! end to end and unit-tested on any machine, including one that cannot build a
//! compositor. Everything about *whose* hash this is, and what to do when it
//! does not match, lives in `raven-auth`.
//!
//! # Why not libcrypt
//!
//! Linking libxcrypt would answer every hash format at the cost of putting a C
//! library on the critical path of a distro whose base is deliberately
//! dependency-free, and of making the login path depend on a shared object
//! being present and correct before anyone can log in to fix it. RavenLinux
//! sets `ENCRYPT_METHOD SHA512` in `login.defs`, so `passwd` writes `$6$`, and
//! `$6$` is a fully specified algorithm that fits in one readable file.
//!
//! The tradeoff is honest rather than hidden: a hash this crate does not
//! implement returns [`Verdict::Unsupported`], never [`Verdict::Mismatch`].
//! Reporting "wrong password" for a hash we simply cannot read would send
//! whoever hit it looking in exactly the wrong place.

#![forbid(unsafe_code)]

mod sha512_crypt;

pub use sha512_crypt::{Error as Sha512Error, sha512_crypt};

use subtle::ConstantTimeEq;

/// Which `crypt(3)` scheme a hash string is written in.
///
/// Identified by the `$id$` prefix, which is the only part of the format every
/// scheme agrees on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `$6$` — sha512-crypt. What RavenLinux's `passwd` produces, and the only
    /// scheme this crate can actually check.
    Sha512Crypt,
    /// `$5$` — sha256-crypt. Same construction, 32-byte digest.
    Sha256Crypt,
    /// `$y$` — yescrypt. The default on current Arch, so a hash migrated from
    /// an Arch install will land here.
    Yescrypt,
    /// `$gy$` — gost-yescrypt.
    GostYescrypt,
    /// `$7$` — scrypt, in yescrypt's encoding.
    Scrypt,
    /// `$2a$`, `$2b$`, `$2y$` — bcrypt.
    Bcrypt,
    /// `$1$` — md5-crypt.
    Md5Crypt,
    /// No `$` prefix at all: traditional DES crypt, 13 characters.
    Des,
    /// A `$id$` this crate has no name for.
    Unknown,
}

impl Scheme {
    /// Read the scheme off the front of a hash string.
    ///
    /// Note that this says nothing about whether the rest of the string is
    /// well formed — only which algorithm claims it.
    #[must_use]
    pub fn identify(hash: &str) -> Self {
        let Some(rest) = hash.strip_prefix('$') else {
            return Self::Des;
        };
        // The id runs to the next '$'. A string with no second '$' is
        // malformed, but the id is still whatever came first, and naming it
        // produces a better message than "unknown".
        let id = rest.split('$').next().unwrap_or("");
        match id {
            "6" => Self::Sha512Crypt,
            "5" => Self::Sha256Crypt,
            "y" => Self::Yescrypt,
            "gy" => Self::GostYescrypt,
            "7" => Self::Scrypt,
            "2a" | "2b" | "2y" => Self::Bcrypt,
            "1" => Self::Md5Crypt,
            _ => Self::Unknown,
        }
    }

    /// The name to put in front of a person when their hash cannot be checked.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha512Crypt => "sha512-crypt ($6$)",
            Self::Sha256Crypt => "sha256-crypt ($5$)",
            Self::Yescrypt => "yescrypt ($y$)",
            Self::GostYescrypt => "gost-yescrypt ($gy$)",
            Self::Scrypt => "scrypt ($7$)",
            Self::Bcrypt => "bcrypt ($2*$)",
            Self::Md5Crypt => "md5-crypt ($1$)",
            Self::Des => "traditional DES crypt",
            Self::Unknown => "an unrecognized hash format",
        }
    }
}

/// The result of checking one password against one hash.
///
/// Deliberately three-valued. Folding [`Unsupported`](Verdict::Unsupported)
/// into [`Mismatch`](Verdict::Mismatch) would turn "this machine cannot read
/// your hash" into "you typed it wrong", which is the single most confusing
/// thing a login screen can say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// The password produces this hash.
    Match,
    /// It does not.
    Mismatch,
    /// The hash is in a scheme this crate cannot compute.
    Unsupported(Scheme),
    /// The scheme is supported but the hash string itself is not well formed —
    /// a truncated field, a `rounds=` that is not a number. Distinct from
    /// `Unsupported` because this one means the shadow file is damaged.
    Malformed,
}

/// Check `password` against a `crypt(3)` hash string.
///
/// The comparison is constant-time in the checksum, so the time this takes
/// does not depend on how many leading characters of a wrong guess happened to
/// be right. That matters less than it sounds for a login screen someone is
/// typing at, and costs nothing to get right.
///
/// Only the checksum field is compared, not the whole string. glibc normalizes
/// a clamped `rounds=` on output — feed it `rounds=10` and it returns
/// `rounds=1000` — so a whole-string comparison would depend on whether the
/// stored hash had already been through that normalization. The checksum is
/// the part that actually proves anything.
pub fn verify(password: &[u8], hash: &str) -> Verdict {
    match Scheme::identify(hash) {
        Scheme::Sha512Crypt => verify_sha512(password, hash),
        other => Verdict::Unsupported(other),
    }
}

fn verify_sha512(password: &[u8], hash: &str) -> Verdict {
    let Some(expected) = checksum_field(hash) else {
        return Verdict::Malformed;
    };
    let computed = match sha512_crypt(password, hash) {
        Ok(c) => c,
        Err(_) => return Verdict::Malformed,
    };
    let Some(actual) = checksum_field(&computed) else {
        return Verdict::Malformed;
    };

    // Length is compared in the clear on purpose: it is a property of the
    // stored hash, not of the guess, so it leaks nothing about the password.
    // ConstantTimeEq on slices of different lengths would be a false `false`.
    if expected.len() != actual.len() {
        return Verdict::Mismatch;
    }
    if bool::from(expected.as_bytes().ct_eq(actual.as_bytes())) {
        Verdict::Match
    } else {
        Verdict::Mismatch
    }
}

/// The checksum: everything after the last `$`.
///
/// Returns `None` when there is no `$` at all, or when the field is empty —
/// `$6$salt$` has a salt and no checksum, and treating that empty string as a
/// checksum would make it match any password whose checksum was also empty.
/// Nothing produces an empty checksum, but this is the wrong place to rely on
/// that.
fn checksum_field(hash: &str) -> Option<&str> {
    let (_, checksum) = hash.rsplit_once('$')?;
    if checksum.is_empty() {
        return None;
    }
    Some(checksum)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drepper's published sha512-crypt vector, confirmed against
    /// `openssl passwd -6 -salt saltstring "Hello world!"`.
    const HELLO: &str = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";

    #[test]
    fn right_password_matches() {
        assert_eq!(verify(b"Hello world!", HELLO), Verdict::Match);
    }

    #[test]
    fn wrong_password_does_not() {
        assert_eq!(verify(b"Hello world", HELLO), Verdict::Mismatch);
        assert_eq!(verify(b"", HELLO), Verdict::Mismatch);
        assert_eq!(verify(b"hello world!", HELLO), Verdict::Mismatch);
    }

    /// A near-miss that shares every character but the last still mismatches —
    /// guards against a prefix comparison sneaking in.
    #[test]
    fn near_miss_checksum_mismatches() {
        let mut near = HELLO.to_string();
        near.pop();
        near.push(if HELLO.ends_with('1') { '2' } else { '1' });
        assert_eq!(verify(b"Hello world!", &near), Verdict::Mismatch);
    }

    #[test]
    fn schemes_are_identified() {
        assert_eq!(Scheme::identify(HELLO), Scheme::Sha512Crypt);
        assert_eq!(Scheme::identify("$y$j9T$abc$def"), Scheme::Yescrypt);
        assert_eq!(Scheme::identify("$2b$10$abcdef"), Scheme::Bcrypt);
        assert_eq!(Scheme::identify("$1$salt$hash"), Scheme::Md5Crypt);
        assert_eq!(Scheme::identify("$5$salt$hash"), Scheme::Sha256Crypt);
        assert_eq!(Scheme::identify("ab1234567890x"), Scheme::Des);
        assert_eq!(Scheme::identify("$99$salt$hash"), Scheme::Unknown);
    }

    /// The whole point of the third variant: an unreadable hash must never be
    /// reported as a wrong password.
    #[test]
    fn unsupported_is_not_mismatch() {
        let v = verify(b"anything", "$y$j9T$SALT$CHECKSUM");
        assert_eq!(v, Verdict::Unsupported(Scheme::Yescrypt));
        assert_ne!(v, Verdict::Mismatch);
    }

    #[test]
    fn malformed_hashes_are_malformed() {
        // No checksum field at all.
        assert_eq!(verify(b"x", "$6$saltstring$"), Verdict::Malformed);
        assert_eq!(verify(b"x", "$6$"), Verdict::Malformed);
        // rounds= that is not a number.
        assert_eq!(verify(b"x", "$6$rounds=abc$salt$hash"), Verdict::Malformed);
    }

    /// An empty checksum must not be treated as a checksum that anything can
    /// match. `$6$salt$` is the shape a truncated shadow line takes.
    #[test]
    fn empty_checksum_never_matches() {
        assert_eq!(checksum_field("$6$saltstring$"), None);
        assert_ne!(verify(b"", "$6$saltstring$"), Verdict::Match);
    }
}
