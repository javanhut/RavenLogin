//! sha512-crypt (`$6$`), following Ulrich Drepper's specification.
//!
//! The construction looks arbitrary because it is: the digest is fed a
//! password-and-salt-dependent *sequence* of inputs, and the sequence itself
//! depends on the length of the password, so an implementation cannot skip
//! ahead or precompute. It is transcribed here in the order the specification
//! gives it, with the step numbers kept in the comments, because the only way
//! to review a transcription is against the thing it was transcribed from.
//!
//! Two details are worth flagging, because both are off-by-one traps that
//! produce a hash that is wrong for *some* password lengths and right for
//! others — which is to say, a bug that passes a single test vector:
//!
//! - Step 9 consumes digest B with `while cnt > 64`, then a final partial
//!   block of `cnt` bytes where `cnt` is in `1..=64`.
//! - Building `p_bytes`/`s_bytes` (steps 14 and 17) uses `while cnt >= 64`,
//!   because there the goal is to fill exactly `len` bytes.
//!
//! Using the same comparison in both places is the classic way to get this
//! wrong. The tests cover password lengths on both sides of 64.

use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// The digest width, in bytes. Named because it is both the block-consumption
/// stride above and the size of every intermediate buffer below.
const DIGEST: usize = 64;

/// Salt is truncated here, per the specification.
const SALT_MAX: usize = 16;

/// What `crypt` uses when the setting carries no `rounds=`.
const ROUNDS_DEFAULT: u32 = 5_000;
const ROUNDS_MIN: u32 = 1_000;
const ROUNDS_MAX: u32 = 999_999_999;

/// The only ways a `$6$` setting string can be unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The string does not start with `$6$`.
    #[error("not a $6$ (sha512-crypt) setting string")]
    NotSha512,
    /// A `rounds=` field that is not a decimal number.
    #[error("malformed rounds= field")]
    BadRounds,
}

/// Compute the full `$6$...` crypt string for `password` under `setting`.
///
/// `setting` may be a bare setting (`$6$salt`) or a complete stored hash
/// (`$6$salt$checksum`) — everything from the checksum onward is ignored, which
/// is what lets a stored hash be handed straight back in to verify against.
///
/// The returned string carries `rounds=` only if `setting` did, matching
/// glibc, and carries the *clamped* value if the requested one was out of
/// range — also matching glibc, which is why `rounds=10` round-trips as
/// `rounds=1000`.
pub fn sha512_crypt(password: &[u8], setting: &str) -> Result<String, Error> {
    let body = setting.strip_prefix("$6$").ok_or(Error::NotSha512)?;

    // `rounds=` is optional and, when present, is the first field.
    let (rounds, rounds_explicit, body) = match body.strip_prefix("rounds=") {
        Some(rest) => {
            let (digits, rest) = rest.split_once('$').unwrap_or((rest, ""));
            let requested: u32 = digits.parse().map_err(|_| Error::BadRounds)?;
            (requested.clamp(ROUNDS_MIN, ROUNDS_MAX), true, rest)
        }
        None => (ROUNDS_DEFAULT, false, body),
    };

    // The salt runs to the next '$' and is truncated to 16 bytes. Truncation is
    // on bytes rather than chars because that is what crypt does; a multi-byte
    // salt is not something `passwd` can produce, and splitting one here would
    // panic on a char boundary rather than reproduce crypt's answer.
    let salt_field = body.split('$').next().unwrap_or("");
    let salt = &salt_field.as_bytes()[..salt_field.len().min(SALT_MAX)];

    let mut checksum = hash(password, salt, rounds);
    let encoded = b64_encode(&checksum);
    checksum.zeroize();

    let salt_str = core::str::from_utf8(salt).unwrap_or("");
    Ok(if rounds_explicit {
        format!(
            "$6${}${salt_str}${encoded}",
            format_args!("rounds={rounds}")
        )
    } else {
        format!("$6${salt_str}${encoded}")
    })
}

/// Steps 1–21 of the specification, producing the raw 64-byte digest.
fn hash(password: &[u8], salt: &[u8], rounds: u32) -> [u8; DIGEST] {
    let pw_len = password.len();
    let salt_len = salt.len();

    // Steps 4–8: digest B = SHA512(password || salt || password).
    let mut b = Sha512::new();
    b.update(password);
    b.update(salt);
    b.update(password);
    let mut digest_b: [u8; DIGEST] = b.finalize().into();

    // Steps 1–3 and 9–12: digest A.
    let mut a = Sha512::new();
    a.update(password);
    a.update(salt);

    // Step 9: add digest B, one full digest per 64 bytes of password, then a
    // final partial block. `> 64`, not `>= 64` — see the module comment.
    let mut cnt = pw_len;
    while cnt > DIGEST {
        a.update(digest_b);
        cnt -= DIGEST;
    }
    a.update(&digest_b[..cnt]);

    // Steps 10–11: walk the bits of the password length from the bottom up,
    // adding digest B for a set bit and the password itself for a clear one.
    let mut cnt = pw_len;
    while cnt > 0 {
        if cnt & 1 != 0 {
            a.update(digest_b);
        } else {
            a.update(password);
        }
        cnt >>= 1;
    }
    let mut digest_a: [u8; DIGEST] = a.finalize().into();

    // Steps 13–15: DP = SHA512(password repeated len(password) times), then
    // p_bytes is DP repeated out to exactly len(password) bytes.
    let mut dp = Sha512::new();
    for _ in 0..pw_len {
        dp.update(password);
    }
    let mut digest_dp: [u8; DIGEST] = dp.finalize().into();
    let mut p_bytes = repeat_to_len(&digest_dp, pw_len);
    digest_dp.zeroize();

    // Steps 16–18: DS = SHA512(salt repeated 16 + A[0] times), then s_bytes is
    // DS repeated out to exactly len(salt) bytes. The repeat count depending on
    // a byte of digest A is what stops the salt schedule being precomputable.
    let mut ds = Sha512::new();
    for _ in 0..(16 + u32::from(digest_a[0])) {
        ds.update(salt);
    }
    let mut digest_ds: [u8; DIGEST] = ds.finalize().into();
    let s_bytes = repeat_to_len(&digest_ds, salt_len);
    digest_ds.zeroize();

    // Steps 19–21: the stretching loop. Alternates whether the running digest
    // goes in first or last, and mixes salt and password in on all but every
    // third and every seventh round respectively.
    let mut c = digest_a;
    for round in 0..rounds {
        let mut ctx = Sha512::new();
        let odd = round & 1 != 0;

        if odd {
            ctx.update(&p_bytes);
        } else {
            ctx.update(c);
        }
        if round % 3 != 0 {
            ctx.update(&s_bytes);
        }
        if round % 7 != 0 {
            ctx.update(&p_bytes);
        }
        if odd {
            ctx.update(c);
        } else {
            ctx.update(&p_bytes);
        }
        c = ctx.finalize().into();
    }

    digest_a.zeroize();
    digest_b.zeroize();
    p_bytes.zeroize();
    // s_bytes is derived from the salt, which is public, but it is wiped for
    // the same reason as the rest: one rule about intermediate buffers is
    // easier to keep than a per-buffer judgement about what is secret.
    let mut s_bytes = s_bytes;
    s_bytes.zeroize();

    c
}

/// `digest` tiled out to exactly `len` bytes, truncating the last copy.
///
/// `>= DIGEST` here, unlike step 9: this fills a buffer of a known length
/// rather than consuming one.
fn repeat_to_len(digest: &[u8; DIGEST], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut cnt = len;
    while cnt >= DIGEST {
        out.extend_from_slice(digest);
        cnt -= DIGEST;
    }
    out.extend_from_slice(&digest[..cnt]);
    out
}

/// crypt's base64 alphabet, which is its own ordering and not RFC 4648's.
const B64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The byte order the 64-byte digest is emitted in.
///
/// sha512-crypt does not encode the digest in order. It walks it in a fixed
/// interleaving, three bytes at a time, and the table is written out here
/// rather than computed because the specification gives it as a literal list
/// and a clever formula would be a second thing to get wrong. 21 triples cover
/// bytes 0..=62; byte 63 is emitted alone by the caller.
#[rustfmt::skip]
const B64_ORDER: [[usize; 3]; 21] = [
    [ 0, 21, 42], [22, 43,  1], [44,  2, 23], [ 3, 24, 45], [25, 46,  4],
    [47,  5, 26], [ 6, 27, 48], [28, 49,  7], [50,  8, 29], [ 9, 30, 51],
    [31, 52, 10], [53, 11, 32], [12, 33, 54], [34, 55, 13], [56, 14, 35],
    [15, 36, 57], [37, 58, 16], [59, 17, 38], [18, 39, 60], [40, 61, 19],
    [62, 20, 41],
];

/// Encode the digest into the 86-character crypt checksum.
fn b64_encode(digest: &[u8; DIGEST]) -> String {
    // 21 groups of 4 characters, plus a final group of 2.
    let mut out = String::with_capacity(86);
    for [b2, b1, b0] in B64_ORDER {
        push_24(&mut out, digest[b2], digest[b1], digest[b0], 4);
    }
    // The last byte on its own, as two characters: 12 bits of room for 8 bits
    // of digest, which is why the checksum is 86 and not a multiple of 4.
    push_24(&mut out, 0, 0, digest[63], 2);
    out
}

/// Emit `n` base64 characters from a 24-bit big-endian group, least
/// significant six bits first — which is the order crypt uses, and the reverse
/// of ordinary base64.
fn push_24(out: &mut String, b2: u8, b1: u8, b0: u8, n: usize) {
    let mut w = (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0);
    for _ in 0..n {
        out.push(char::from(B64[(w & 0x3f) as usize]));
        w >>= 6;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drepper's published vectors. Every one of these was re-confirmed on the
    /// build host with `openssl passwd -6`, so a failure here is this crate's,
    /// not a mistranscribed constant.
    #[test]
    fn published_vectors() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "$6$saltstring",
                "Hello world!",
                "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
            ),
            (
                "$6$rounds=10000$saltstringsaltstring",
                "Hello world!",
                "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
            ),
            (
                "$6$rounds=5000$toolongsaltstring",
                "This is just a test",
                "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
            ),
        ];
        for (setting, password, expected) in cases {
            let got = sha512_crypt(password.as_bytes(), setting).expect("valid setting");
            assert_eq!(&got, expected, "setting {setting} password {password:?}");
        }
    }

    /// Rounds below the minimum clamp up, and the clamped value is what gets
    /// written back out — `rounds=10` becomes `rounds=1000`.
    ///
    /// This follows the specification rather than libxcrypt, which is what the
    /// build host actually ships: libxcrypt *rejects* an out-of-range `rounds=`
    /// and returns failure where this clamps. The divergence is unreachable in
    /// practice, because the thing that rejects it is also the only thing that
    /// writes `/etc/shadow` — no `passwd` can store a hash carrying
    /// `rounds=10`, so no stored hash can take this path. It is tested because
    /// it is a branch, not because a real system can reach it.
    #[test]
    fn rounds_below_minimum_clamp() {
        let got = sha512_crypt(
            b"we have a short salt string but not a short password",
            "$6$rounds=10$roundstoolow",
        )
        .expect("valid setting");
        assert!(got.starts_with("$6$rounds=1000$roundstoolow$"), "got {got}");
    }

    /// The two block-consumption loops differ by one comparison, and the
    /// difference only shows up at particular password lengths. This walks
    /// straight across the 64-byte boundary that separates them.
    ///
    /// Expected values come from `openssl passwd -6 -salt saltstring`.
    #[test]
    fn password_lengths_across_the_digest_boundary() {
        let cases: &[(usize, &str)] = &[
            (
                63,
                "$6$saltstring$G/I3Mgca7qjB0/P50Q0k/.AHC6ua1SVEEfWm0n08bEjOV3oHlrqFvwA00OdnEI8pCh68rckAuH2LLWLnfrbLp1",
            ),
            (
                64,
                "$6$saltstring$xNfEGWEsbTgq/Y30XyIRNcZdD2drPqzAwh6fXDj7D6WVE0OazIpLhya3Bird/wrtzcCJhM8Es.wueUOoZXbEi/",
            ),
            (
                65,
                "$6$saltstring$c6io.ih6GI98Pz5jiddo0HZGtfQHUegE9SisEYxSKDssOvZdRvd7v1z7E7Hqk6UBWUVJ2e.SkCQp.zxUjd.et0",
            ),
        ];
        for (len, expected) in cases {
            let password = vec![b'a'; *len];
            let got = sha512_crypt(&password, "$6$saltstring").expect("valid setting");
            assert_eq!(&got, expected, "password length {len}");
        }
    }

    /// An empty password is a legal input to crypt, and hits the `cnt == 0`
    /// edge of both loops.
    #[test]
    fn empty_password() {
        let got = sha512_crypt(b"", "$6$saltstring").expect("valid setting");
        assert_eq!(
            got,
            "$6$saltstring$kyGrqt6gmjAdtFLPrflEFifSYLCWWq1pyx95SvqinLDy2UHmj0sTF0MSLMwxPFZc3tu5kQckI8fks0zOPda3n1"
        );
    }

    #[test]
    fn salt_is_truncated_to_sixteen_bytes() {
        // The 17th salt byte must make no difference.
        let a = sha512_crypt(b"pw", "$6$0123456789abcdefX").expect("valid");
        let b = sha512_crypt(b"pw", "$6$0123456789abcdefY").expect("valid");
        assert_eq!(a, b);
    }

    /// A complete stored hash can be fed back in as the setting — this is what
    /// verification relies on.
    #[test]
    fn a_full_hash_works_as_a_setting() {
        let stored = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
        let got = sha512_crypt(b"Hello world!", stored).expect("valid setting");
        assert_eq!(got, stored);
    }

    #[test]
    fn rejects_other_schemes_and_bad_rounds() {
        assert_eq!(sha512_crypt(b"x", "$5$salt"), Err(Error::NotSha512));
        assert_eq!(sha512_crypt(b"x", "$y$j9T$salt"), Err(Error::NotSha512));
        assert_eq!(
            sha512_crypt(b"x", "$6$rounds=abc$salt"),
            Err(Error::BadRounds)
        );
    }

    #[test]
    fn checksum_is_always_86_characters() {
        for pw in [&b""[..], b"a", b"short", &[b'z'; 200][..]] {
            let got = sha512_crypt(pw, "$6$saltstring").expect("valid");
            let checksum = got.rsplit_once('$').expect("has a checksum").1;
            assert_eq!(checksum.len(), 86, "password of {} bytes", pw.len());
        }
    }
}
