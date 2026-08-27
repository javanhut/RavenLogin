//! The login screen's one look, compiled in.
//!
//! Constants rather than a schema, for the reason huginn's `theme.rs` gives:
//! a format a user can write is a format that must not change between
//! releases, and a config schema drifting under somebody is the commonest way
//! to break their desktop. A constant cannot drift, because nothing outside
//! this binary ever names it.
//!
//! # Why these numbers are copied rather than shared
//!
//! [`ACCENT`] and [`BACKDROP`] are huginn's `ACCENT` and `BACKGROUND`, to the
//! digit. They are duplicated because huginn's `theme` module is `pub(crate)`
//! inside `huginn-comp`, in a different repository — RavenLogin cannot name it
//! without RavenGUI first promoting it to a shared `raven-theme` crate, which
//! is a change to RavenGUI and not this project's to make.
//!
//! Duplication has a cost and it is worth being honest about it: the login
//! screen and the desktop it hands over to can drift apart, and the seam is
//! visible precisely because the handover is a cut between two full-screen
//! surfaces of the same colour. If these ever stop matching, the fix is the
//! shared crate, not a second edit here.

/// A colour, as `0xAARRGGBB`.
///
/// Packed into one integer so it is `Copy` and comparable, and converted at
/// the edges: `wl_shm`'s `Argb8888` wants this exact layout, little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Color(u32);

impl Color {
    #[must_use]
    pub(crate) const fn from_argb(argb: u32) -> Self {
        Self(argb)
    }

    #[must_use]
    pub(crate) const fn alpha(self) -> u8 {
        (self.0 >> 24) as u8
    }

    #[must_use]
    pub(crate) const fn red(self) -> u8 {
        (self.0 >> 16) as u8
    }

    #[must_use]
    pub(crate) const fn green(self) -> u8 {
        (self.0 >> 8) as u8
    }

    #[must_use]
    pub(crate) const fn blue(self) -> u8 {
        self.0 as u8
    }

    /// The same colour at a different opacity.
    #[must_use]
    pub(crate) const fn with_alpha(self, alpha: u8) -> Self {
        Self((self.0 & 0x00FF_FFFF) | ((alpha as u32) << 24))
    }

    /// This colour scaled toward transparent by `factor` in `0.0..=1.0`.
    #[must_use]
    pub(crate) fn faded(self, factor: f32) -> Self {
        let alpha = (f32::from(self.alpha()) * factor.clamp(0.0, 1.0)) as u8;
        self.with_alpha(alpha)
    }
}

// ---------------------------------------------------------------------------
// Colour
// ---------------------------------------------------------------------------

/// The whole screen behind everything. huginn's `BACKGROUND`.
pub(crate) const BACKDROP: Color = Color::from_argb(0xFF16_161F);

/// The darker vignette the backdrop falls off to at the edges.
///
/// The gradient is very shallow on purpose. It exists to stop a large flat
/// panel showing its own banding, not to be seen as a gradient.
pub(crate) const BACKDROP_EDGE: Color = Color::from_argb(0xFF0D_0D14);

/// Laid over a wallpaper, and only over a wallpaper.
///
/// Every colour in this file was chosen against [`BACKDROP`], and a photograph
/// is not [`BACKDROP`]. So a wallpaper is darkened toward the backdrop until
/// text on it is readable again.
///
/// The alpha is the whole decision, and the honest worst case is a pure white
/// photograph. At 78%, [`TEXT`] lands at 5.6:1 against that -- comfortably
/// past 4.5:1 -- while a wallpaper is still plainly a wallpaper. Going darker
/// buys another point of contrast and costs the feature its point.
///
/// [`TEXT_DIM`] does *not* survive this, which is what
/// [`TEXT_DIM_ON_WALLPAPER`] exists for; see there.
pub(crate) const SCRIM: Color = BACKDROP.with_alpha(0xC8);

/// [`TEXT_DIM`], for the date and the footer, when they are sitting on a
/// scrimmed wallpaper instead of on the backdrop.
///
/// [`TEXT_DIM`] is 2.9:1 against [`BACKDROP`], which is fine for secondary
/// text on a colour this file controls. On a scrimmed *white* photograph it
/// falls to 1.5:1 and stops being text at all -- and worse, it inverts, going
/// from lighter-than-background to darker, which no single choice of alpha
/// fixes. A brighter dim is the fix that works at both ends: this is 3.0:1
/// against a scrimmed white wallpaper, 7.6:1 against a scrimmed black one,
/// and still clearly subordinate to [`TEXT`].
///
/// Two constants rather than one, because the backdrop case is not broken and
/// making the date brighter on a machine with no wallpaper would be changing
/// a screen nobody asked to change.
pub(crate) const TEXT_DIM_ON_WALLPAPER: Color = Color::from_argb(0xFF8A_93BE);

/// The card the prompt sits on.
pub(crate) const SURFACE: Color = Color::from_argb(0xFF1A_1B26);

/// Hairline borders.
pub(crate) const BORDER: Color = Color::from_argb(0xFF2A_2E45);

/// Focus rings and the caret. huginn's `ACCENT`.
pub(crate) const ACCENT: Color = Color::from_argb(0xFF7A_A2F7);

/// Ordinary text.
pub(crate) const TEXT: Color = Color::from_argb(0xFFC0_CAF5);

/// Secondary text: the date, the footer, the hint line.
pub(crate) const TEXT_DIM: Color = Color::from_argb(0xFF56_5F89);

/// A failed attempt.
pub(crate) const ERROR: Color = Color::from_argb(0xFFF7_768E);

/// Caps Lock, and anything else that is a caution rather than a failure.
pub(crate) const WARNING: Color = Color::from_argb(0xFFE0_AF68);

/// A granted login, for the moment before the screen goes away.
pub(crate) const SUCCESS: Color = Color::from_argb(0xFF9E_CE6A);

// ---------------------------------------------------------------------------
// Metric
// ---------------------------------------------------------------------------

/// Everything is laid out against this, and it is scaled by the output's
/// scale factor before use, so the login screen is the same physical size on
/// a HiDPI panel as on a 96dpi one.
pub(crate) const CARD_WIDTH: f32 = 380.0;

pub(crate) const AVATAR_RADIUS: f32 = 44.0;
pub(crate) const AVATAR_RING: f32 = 2.0;

pub(crate) const FIELD_HEIGHT: f32 = 44.0;
pub(crate) const FIELD_RADIUS: f32 = 10.0;
pub(crate) const FIELD_BORDER: f32 = 1.5;

/// The dots that stand in for the password.
pub(crate) const DOT_RADIUS: f32 = 4.0;
pub(crate) const DOT_SPACING: f32 = 14.0;
/// Beyond this many, the row stops growing and just stays full — a password
/// whose length is legible from across the room is a password leaked to
/// anybody watching.
pub(crate) const DOT_MAX: usize = 12;

pub(crate) const CLOCK_SIZE: f32 = 72.0;
pub(crate) const DATE_SIZE: f32 = 16.0;
pub(crate) const NAME_SIZE: f32 = 20.0;
pub(crate) const BODY_SIZE: f32 = 14.0;
pub(crate) const SMALL_SIZE: f32 = 12.5;
pub(crate) const AVATAR_SIZE: f32 = 36.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_unpack_in_the_right_order() {
        let c = Color::from_argb(0xFF7A_A2F7);
        assert_eq!(c.alpha(), 0xFF);
        assert_eq!(c.red(), 0x7A);
        assert_eq!(c.green(), 0xA2);
        assert_eq!(c.blue(), 0xF7);
    }

    #[test]
    fn with_alpha_keeps_the_colour() {
        let c = ACCENT.with_alpha(0x80);
        assert_eq!(c.alpha(), 0x80);
        assert_eq!(c.red(), ACCENT.red());
        assert_eq!(c.green(), ACCENT.green());
        assert_eq!(c.blue(), ACCENT.blue());
    }

    /// sRGB relative luminance, per WCAG.
    fn luminance(c: Color) -> f32 {
        let channel = |v: u8| {
            let v = f32::from(v) / 255.0;
            if v <= 0.040_45 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(c.red()) + 0.7152 * channel(c.green()) + 0.0722 * channel(c.blue())
    }

    fn contrast(a: Color, b: Color) -> f32 {
        let (a, b) = (luminance(a), luminance(b));
        let (lighter, darker) = if a > b { (a, b) } else { (b, a) };
        (lighter + 0.05) / (darker + 0.05)
    }

    /// A wallpaper of solid `value`, with [`SCRIM`] over it.
    fn scrimmed(value: u8) -> Color {
        let alpha = f32::from(SCRIM.alpha()) / 255.0;
        let mix = |over: u8| (f32::from(value) * (1.0 - alpha) + f32::from(over) * alpha) as u8;
        Color::from_argb(
            0xFF00_0000
                | (u32::from(mix(SCRIM.red())) << 16)
                | (u32::from(mix(SCRIM.green())) << 8)
                | u32::from(mix(SCRIM.blue())),
        )
    }

    /// The scrim exists to make a photograph safe to put text on. These are
    /// the numbers its documentation claims; if somebody retunes it, this is
    /// what should stop them shipping an unreadable login screen.
    ///
    /// White and black stand in for the extremes of any real wallpaper: the
    /// scrim is a uniform blend, so every photograph in between lands between
    /// these two.
    #[test]
    fn text_stays_readable_on_any_wallpaper() {
        for value in [0x00, 0x80, 0xFF] {
            let background = scrimmed(value);

            let primary = contrast(TEXT, background);
            assert!(
                primary >= 4.5,
                "TEXT on a scrimmed 0x{value:02X} wallpaper is {primary:.2}:1"
            );

            let secondary = contrast(TEXT_DIM_ON_WALLPAPER, background);
            assert!(
                secondary >= 3.0,
                "the dim text on a scrimmed 0x{value:02X} wallpaper is {secondary:.2}:1"
            );
        }
    }

    /// The wallpaper dim has to still read as secondary, or the date competes
    /// with the clock above it.
    #[test]
    fn the_wallpaper_dim_is_still_dimmer_than_the_text() {
        assert!(luminance(TEXT_DIM_ON_WALLPAPER) < luminance(TEXT));
        assert!(luminance(TEXT_DIM_ON_WALLPAPER) > luminance(TEXT_DIM));
    }

    #[test]
    fn fading_is_clamped() {
        assert_eq!(ACCENT.faded(2.0).alpha(), 0xFF);
        assert_eq!(ACCENT.faded(-1.0).alpha(), 0x00);
        assert_eq!(ACCENT.faded(0.5).alpha(), 0x7F);
    }

    /// These two are huginn's, and the handover between the login screen and
    /// the desktop is a cut between two surfaces of this colour. If somebody
    /// changes one, this is the test that should make them think about the
    /// other.
    #[test]
    fn the_shared_colours_still_match_huginn() {
        assert_eq!(
            BACKDROP,
            Color::from_argb(0xFF16_161F),
            "huginn theme::BACKGROUND"
        );
        assert_eq!(
            ACCENT,
            Color::from_argb(0xFF7A_A2F7),
            "huginn theme::ACCENT"
        );
    }
}
