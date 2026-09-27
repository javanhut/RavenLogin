//! The small part of Raven's per-user desktop settings the lock screen needs.
//!
//! RavenSettingsUI records a user's wallpaper, accent and glass theme in
//! `$XDG_CONFIG_HOME/raven/desktop.toml`. Huginn reads the same wallpaper for
//! the desktop, so the lock screen must consult it before falling back to the
//! machine-wide wallpaper too; the accent colours the focus ring and caret,
//! as it does in every other Raven app, and the glass theme tints the field
//! and the avatar the way the compositor tints its panels.
//!
//! `theme_mode` is deliberately not read, and the glass is always its dark
//! variant: the lock screen is drawn over the wallpaper darkened by a dark
//! scrim whatever the desktop's mode, the way the greeter it shares
//! `raven-ui` with is. Its contrast guarantees are computed against that
//! scrim.
//!
//! The file is read once per lock. While the screen is locked nothing can
//! change it, so the next lock is as soon as a change could show.

use std::path::PathBuf;

use raven_ui::theme::{Color, Glass};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DesktopConfig {
    appearance: Appearance,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Appearance {
    wallpaper: String,
    accent: String,
    glass_theme: String,
}

/// The still wallpaper RavenSettingsUI chose for this account.
///
/// Missing and malformed settings are deliberately non-fatal: a lock screen
/// must remain usable even when an unrelated preference file is broken.
pub(crate) fn wallpaper() -> Option<PathBuf> {
    parse_wallpaper(&load()?)
}

/// The accent RavenSettingsUI chose for this account. `None` (for the caller
/// to keep the built-in accent) when there is none or it is not `#RRGGBB`.
pub(crate) fn accent() -> Option<Color> {
    parse_accent(&load()?)
}

/// The glass theme RavenSettingsUI chose for this account. `None` (for the
/// caller to keep the built-in material) for Black Glass, none, or unknown.
pub(crate) fn glass() -> Option<Glass> {
    parse_glass(&load()?)
}

/// `desktop.toml`, parsed. `None` when it is missing or unreadable, which is
/// logged unless it is simply absent.
fn load() -> Option<DesktopConfig> {
    let path = path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(path = %path.display(), "could not read desktop.toml: {e}");
            return None;
        }
    };
    match toml::from_str(&text) {
        Ok(config) => Some(config),
        Err(e) => {
            tracing::warn!(path = %path.display(), "ignoring desktop.toml: {e}");
            None
        }
    }
}

/// Where RavenSettingsUI and Huginn keep the desktop settings.
fn path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("raven").join("desktop.toml"))
}

fn parse_wallpaper(config: &DesktopConfig) -> Option<PathBuf> {
    let wallpaper = config.appearance.wallpaper.trim();
    (!wallpaper.is_empty()).then(|| PathBuf::from(wallpaper))
}

fn parse_accent(config: &DesktopConfig) -> Option<Color> {
    Color::from_hex(&config.appearance.accent)
}

fn parse_glass(config: &DesktopConfig) -> Option<Glass> {
    Glass::named(&config.appearance.glass_theme)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> DesktopConfig {
        toml::from_str(text).unwrap()
    }

    fn parse_wallpaper(text: &str) -> Result<Option<PathBuf>, toml::de::Error> {
        Ok(super::parse_wallpaper(&toml::from_str(text)?))
    }

    #[test]
    fn reads_the_wallpaper_written_by_settings() {
        let path = parse_wallpaper(
            "[appearance]\nwallpaper = \"/home/raven/.local/share/raven/wallpaper/wallpaper.jpg\"\n",
        )
        .unwrap();
        assert_eq!(
            path,
            Some(PathBuf::from(
                "/home/raven/.local/share/raven/wallpaper/wallpaper.jpg"
            ))
        );
    }

    #[test]
    fn absent_or_blank_wallpaper_means_the_system_default() {
        assert_eq!(parse_wallpaper("").unwrap(), None);
        assert_eq!(
            parse_wallpaper("[appearance]\nwallpaper = \"  \"\n").unwrap(),
            None
        );
    }

    #[test]
    fn ignores_unrelated_desktop_settings() {
        assert_eq!(
            parse_wallpaper(
                "[appearance]\naccent = \"#7AA2F7\"\n[general]\nlock_after_minutes = 10\n"
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn reads_the_accent_written_by_settings() {
        assert_eq!(
            parse_accent(&parse("[appearance]\naccent = \"#F7768E\"\n")),
            Some(Color::from_argb(0xFFF7_768E))
        );
    }

    #[test]
    fn a_missing_or_bad_accent_keeps_the_built_in_one() {
        assert_eq!(parse_accent(&parse("")), None);
        assert_eq!(
            parse_accent(&parse("[appearance]\naccent = \"red\"\n")),
            None
        );
        assert_eq!(
            parse_accent(&parse("[appearance]\naccent = \"#7AA2F\"\n")),
            None
        );
    }

    #[test]
    fn reads_the_glass_theme_written_by_settings() {
        assert_eq!(
            parse_glass(&parse("[appearance]\nglass_theme = \"Rose Glass\"\n")),
            Glass::named("rose")
        );
        assert!(Glass::named("rose").is_some());
        assert_eq!(parse_glass(&parse("")), None);
        assert_eq!(
            parse_glass(&parse("[appearance]\nglass_theme = \"black\"\n")),
            None
        );
    }
}
