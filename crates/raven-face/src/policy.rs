//! `/var/lib/raven-login/face/<account>.toml`.
//!
//! One small file per account:
//!
//! ```toml
//! login = true
//! unlock = true
//! ```
//!
//! # Why a root-owned file and not one in the home directory
//!
//! The same reason `raven-finger`'s is: the reader of it is root and what it
//! decides is whether a password is needed. A file the account could write
//! itself would let any process running as that account turn face login on and
//! then wait for its owner to sit down in front of the machine. So the
//! directory is `0700` root, the files are `0600`, and the only writer is
//! `ravend`, which takes the password before it switches anything on.
//!
//! # What is not here
//!
//! The templates. Those are `raven-faced`'s, under its own directory, for the
//! same reason the fingerprint templates are the sensor's: the process holding
//! `/etc/shadow` does not also hold the biometrics. This file says only where
//! a match is allowed to count.
//!
//! # Failing safe
//!
//! A missing file is "everything off", which is the default. So is a file that
//! does not parse: the alternative is guessing at what somebody meant about
//! whether their password is needed, and the only guess that cannot hurt them
//! is no.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use raven_greet_proto::{FacePolicy, valid_account};

/// Where the files live.
pub const DIR: &str = "/var/lib/raven-login/face";

/// The file for one account, or `None` for a name that is not safe to put in
/// a path.
#[must_use]
pub fn path_for(dir: &Path, account: &str) -> Option<PathBuf> {
    valid_account(account).then(|| dir.join(format!("{account}.toml")))
}

/// What `account` has turned on. Everything off if the file is missing,
/// unreadable or damaged.
#[must_use]
pub fn load(account: &str) -> FacePolicy {
    load_from(Path::new(DIR), account)
}

#[must_use]
pub fn load_from(dir: &Path, account: &str) -> FacePolicy {
    let Some(path) = path_for(dir, account) else {
        return FacePolicy::default();
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return FacePolicy::default(),
        Err(e) => {
            tracing::warn!(path = %path.display(), "cannot read the face policy: {e}");
            return FacePolicy::default();
        }
    };
    match toml::from_str(&text) {
        Ok(policy) => policy,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                "the face policy does not parse, so every use is off: {e}"
            );
            FacePolicy::default()
        }
    }
}

/// Write what `account` has turned on.
///
/// Through a temporary file and a rename, so a crash halfway leaves the old
/// file rather than a truncated one -- and a truncated one would read as
/// "everything off", which is safe but not what anybody asked for.
pub fn save(account: &str, policy: FacePolicy) -> std::io::Result<()> {
    save_to(Path::new(DIR), account, policy)
}

pub fn save_to(dir: &Path, account: &str, policy: FacePolicy) -> std::io::Result<()> {
    let path = path_for(dir, account).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{account:?} is not an account name that can be stored"),
        )
    })?;

    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;

    let text = format!(
        "# Where {account} lets its face stand in for the password.\n\
         # Written by ravend, from Settings > Security. Every key is optional\n\
         # and off by default. There is no `sudo` key: a face may open a\n\
         # machine that is already shut, and may not become root.\n\
         login = {}\nunlock = {}\n",
        policy.login, policy.unlock
    );

    let tmp = dir.join(format!(".{account}.toml.tmp"));
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &path)
}

/// Forget `account` entirely: its templates are gone, so nothing is on.
pub fn remove(account: &str) -> std::io::Result<()> {
    let Some(path) = path_for(Path::new(DIR), account) else {
        return Ok(());
    };
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("raven-face-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_missing_file_is_everything_off() {
        let dir = scratch("missing");
        assert_eq!(load_from(&dir, "javan"), FacePolicy::default());
    }

    #[test]
    fn a_policy_round_trips_and_is_private() {
        let dir = scratch("round-trip");
        let policy = FacePolicy {
            login: true,
            unlock: true,
        };
        save_to(&dir, "javan", policy).expect("saves");
        assert_eq!(load_from(&dir, "javan"), policy);

        let mode = |p: &Path| std::fs::metadata(p).expect("exists").permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("javan.toml")), 0o600);
    }

    /// Guessing at a damaged file could only ever guess "on" wrongly.
    #[test]
    fn a_damaged_file_is_everything_off() {
        let dir = scratch("damaged");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("javan.toml"), "login = whenever").expect("write");
        assert_eq!(load_from(&dir, "javan"), FacePolicy::default());
    }

    #[test]
    fn a_partial_file_leaves_the_rest_off() {
        let dir = scratch("partial");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("javan.toml"), "unlock = true\n").expect("write");
        let policy = load_from(&dir, "javan");
        assert!(policy.unlock && !policy.login);
    }

    /// A `sudo = true` somebody wrote by hand, or carried over from a
    /// fingerprint policy, must not turn into anything. `serde(default)` with
    /// no such field ignores it, and this is the test that says so on purpose
    /// rather than by accident.
    #[test]
    fn a_sudo_key_written_by_hand_does_nothing() {
        let dir = scratch("sudo");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("javan.toml"), "login = true\nsudo = true\n").expect("write");
        let policy = load_from(&dir, "javan");
        assert!(policy.login);
        // There is no field to read it into, and the file still parsed.
        assert!(!policy.unlock);
    }

    #[test]
    fn a_name_that_is_a_path_is_never_written() {
        let dir = scratch("traversal");
        assert!(save_to(&dir, "../escape", FacePolicy::default()).is_err());
        assert!(!dir.with_file_name("escape.toml").exists());
    }

    /// The file says out loud that a face cannot become root, so that somebody
    /// reading it on a machine does not go looking for the switch.
    #[test]
    fn the_written_file_explains_the_missing_switch() {
        let dir = scratch("comment");
        save_to(&dir, "javan", FacePolicy::default()).expect("saves");
        let text = std::fs::read_to_string(dir.join("javan.toml")).expect("reads");
        assert!(text.contains("sudo"), "the file must mention why there is none");
        assert!(!text.contains("sudo ="), "...without looking like a key");
    }
}
