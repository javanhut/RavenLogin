//! The small part of Raven's per-user desktop settings the lock screen needs.
//!
//! RavenSettingsUI records a user's wallpaper in
//! `$XDG_CONFIG_HOME/raven/desktop.toml`. Huginn reads the same field for the
//! desktop, so the lock screen must consult it before falling back to the
//! machine-wide wallpaper too.

use std::path::PathBuf;

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
}

/// The still wallpaper RavenSettingsUI chose for this account.
///
/// Missing and malformed settings are deliberately non-fatal: a lock screen
/// must remain usable even when an unrelated preference file is broken.
pub(crate) fn wallpaper() -> Option<PathBuf> {
    let path = path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(path = %path.display(), "could not read desktop.toml: {e}");
            return None;
        }
    };
    match parse_wallpaper(&text) {
        Ok(wallpaper) => wallpaper,
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

fn parse_wallpaper(text: &str) -> Result<Option<PathBuf>, toml::de::Error> {
    let config: DesktopConfig = toml::from_str(text)?;
    let wallpaper = config.appearance.wallpaper.trim();
    Ok((!wallpaper.is_empty()).then(|| PathBuf::from(wallpaper)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
