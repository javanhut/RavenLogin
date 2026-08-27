//! `/etc/raven/login.toml`.
//!
//! Huginn ships one look and no configuration, and that is right for a
//! compositor: a theme schema is a thing that drifts under people between
//! releases. This file is not a theme. Every value in it is something an
//! installer or an administrator has a legitimate reason to change and no way
//! to express otherwise — which account the greeter runs as, what the session
//! command is, whether root may log in. Those are facts about a machine, not
//! preferences about how it looks.
//!
//! The whole file is optional, and so is every field in it. A machine with no
//! `login.toml` gets the defaults below, which are the right answer for an
//! image built by `raven-install`. That matters more than it sounds: the
//! configuration for logging in must not be a thing you can be locked out by.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::ratelimit::Limits;

/// Where the daemon looks, when not told otherwise on the command line.
pub(crate) const DEFAULT_PATH: &str = "/etc/raven/login.toml";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Config {
    pub greeter: Greeter,
    pub session: Session,
    pub policy: Policy,
    pub ratelimit: RateLimit,
}

/// The unprivileged half: who draws the login screen, and how.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Greeter {
    /// The account the greeter's compositor and UI run as.
    ///
    /// A dedicated system account, not `nobody`: `nobody` is shared by every
    /// unprivileged daemon on the machine, so anything running as it can reach
    /// the greeter's runtime directory and its Wayland socket.
    pub user: String,
    /// The compositor to host the greeter in.
    pub compositor: String,
    /// The greeter UI binary.
    pub command: String,
    /// An image to draw the login screen on, or `None` for the built-in
    /// backdrop.
    ///
    /// The daemon does no more than pass this along -- it never opens it. See
    /// [`raven_greet_proto::Response::Wallpaper`] for why that separation is
    /// the point rather than an accident, and note the consequence: the file
    /// has to be readable by the greeter's account, not by root.
    pub wallpaper: Option<PathBuf>,
    /// How long to wait for the compositor's Wayland socket to appear before
    /// giving up on it.
    ///
    /// This is the `ready_path` pattern `raven-init` uses for D-Bus, and for
    /// the same reason: starting the client before the compositor has bound its
    /// socket is a race the client loses by exiting immediately.
    #[serde(with = "seconds")]
    pub wayland_timeout: Duration,
}

impl Default for Greeter {
    fn default() -> Self {
        Self {
            user: "raven-greeter".to_string(),
            compositor: "huginn".to_string(),
            command: "raven-greeter".to_string(),
            wallpaper: None,
            wayland_timeout: Duration::from_secs(10),
        }
    }
}

/// What to start once somebody has authenticated.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Session {
    /// The session launcher. The same script `raven-init` starts today when
    /// `raven.graphics=wayland` is on the cmdline and there is no greeter.
    pub command: String,
    /// How long a session gets to exit after being asked to, before it is
    /// killed. Only reached on shutdown or when the daemon is restarting.
    #[serde(with = "seconds")]
    pub stop_timeout: Duration,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            command: "/usr/bin/raven-wayland-session".to_string(),
            stop_timeout: Duration::from_secs(10),
        }
    }
}

/// Who may log in. Mirrors [`raven_auth::Policy`]; kept separate so the
/// serialized names are this file's business rather than the library's.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    pub allow_empty_password: bool,
    pub allow_root: bool,
}

impl Default for Policy {
    fn default() -> Self {
        let defaults = raven_auth::Policy::default();
        Self {
            allow_empty_password: defaults.allow_empty_password,
            allow_root: defaults.allow_root,
        }
    }
}

impl From<Policy> for raven_auth::Policy {
    fn from(value: Policy) -> Self {
        Self {
            allow_empty_password: value.allow_empty_password,
            allow_root: value.allow_root,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RateLimit {
    pub free_attempts: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub forget_after_s: u64,
}

impl Default for RateLimit {
    fn default() -> Self {
        let defaults = Limits::default();
        Self {
            free_attempts: defaults.free_attempts,
            base_delay_ms: defaults.base_delay.as_millis() as u64,
            max_delay_ms: defaults.max_delay.as_millis() as u64,
            forget_after_s: defaults.forget_after.as_secs(),
        }
    }
}

impl From<RateLimit> for Limits {
    fn from(value: RateLimit) -> Self {
        Self {
            free_attempts: value.free_attempts,
            base_delay: Duration::from_millis(value.base_delay_ms),
            max_delay: Duration::from_millis(value.max_delay_ms),
            forget_after: Duration::from_secs(value.forget_after_s),
        }
    }
}

/// `Duration` as a whole number of seconds, so the file says `10` rather than
/// `{ secs = 10, nanos = 0 }`.
mod seconds {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}

impl Config {
    /// Read the file, or return defaults if it is not there.
    ///
    /// A *missing* file is normal and silent. A file that exists but does not
    /// parse is an error, and a loud one: the alternative is to fall back to
    /// defaults, which would silently ignore a `allow_root = false` somebody
    /// wrote down and believed. Better to refuse to start than to run under a
    /// policy nobody chose.
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(path = %path.display(), "no config file; using defaults");
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(
                    anyhow::Error::new(e).context(format!("cannot read {}", path.display()))
                );
            }
        };
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("{} is not valid: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_is_all_defaults() {
        let config: Config = toml::from_str("").expect("an empty config is valid");
        assert_eq!(config.greeter.user, "raven-greeter");
        assert_eq!(config.greeter.compositor, "huginn");
        assert_eq!(config.session.command, "/usr/bin/raven-wayland-session");
        assert!(!config.policy.allow_root);
        assert!(!config.policy.allow_empty_password);
    }

    /// A partial file must leave everything it does not mention alone. This is
    /// the property that lets somebody set one value without transcribing the
    /// whole default file and going stale against the next release.
    #[test]
    fn a_partial_file_keeps_the_other_defaults() {
        let config: Config = toml::from_str("[policy]\nallow_root = true\n").expect("valid");
        assert!(config.policy.allow_root);
        assert!(!config.policy.allow_empty_password);
        assert_eq!(config.greeter.compositor, "huginn");
    }

    #[test]
    fn durations_are_written_as_seconds() {
        let config: Config = toml::from_str("[greeter]\nwayland_timeout = 25\n").expect("valid");
        assert_eq!(config.greeter.wayland_timeout, Duration::from_secs(25));
    }

    /// A misspelled key must be an error, not a silently ignored line. Somebody
    /// who writes `allow_roots = false` and is not told about it has a machine
    /// whose policy is the opposite of what they wrote down.
    #[test]
    fn unknown_keys_are_refused() {
        let err = toml::from_str::<Config>("[policy]\nallow_roots = true\n")
            .expect_err("must be refused");
        assert!(err.to_string().contains("allow_roots"), "{err}");
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let config = Config::load(Path::new("/nonexistent/raven/login.toml"))
            .expect("a missing config is not an error");
        assert_eq!(config.greeter.user, "raven-greeter");
    }

    #[test]
    fn a_malformed_file_is_an_error() {
        let dir = std::env::temp_dir().join(format!("ravend-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("can create a test directory");
        let path = dir.join("login.toml");
        std::fs::write(&path, "this is not toml {{{").expect("can write");
        assert!(Config::load(&path).is_err());
    }

    /// The daemon's defaults and the library's must not drift apart.
    #[test]
    fn policy_defaults_match_raven_auth() {
        let ours: raven_auth::Policy = Policy::default().into();
        assert_eq!(ours, raven_auth::Policy::default());
    }

    #[test]
    fn ratelimit_defaults_match_the_limiter() {
        let ours: Limits = RateLimit::default().into();
        assert_eq!(ours, Limits::default());
    }
}
