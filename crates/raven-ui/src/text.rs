//! Shaping and rasterizing text into the canvas.
//!
//! `cosmic-text` with `fontdb`, matching huginn's choice so that the login
//! screen and the desktop it hands over to render type identically. Fontconfig
//! is off: it would put a C library on the critical path of a distro that
//! ships almost no GUI dependencies, and fontdb finds fonts by scanning the
//! standard directories without it.
//!
//! # The font
//!
//! JetBrains Mono, because it is the one font RavenLinux is guaranteed to
//! ship — it is in `RavenLinux/fonts/`, and it is what the terminal and the
//! editor already use. A login screen set in a proportional face that may or
//! may not be installed is a login screen that renders in whatever fallback
//! fontdb finds first, which is not a design so much as a coin flip.
//!
//! A monospaced login screen is an unusual choice and it is a deliberate one:
//! this is the front door of a distribution whose shell, editor and terminal
//! are all its own, and it should look like the same machine.

use cosmic_text::{Attrs, Buffer, Family, FontSystem, Metrics, Shaping, SwashCache, Weight};

use crate::canvas::Canvas;
use crate::theme::Color;

/// The family names to ask for, best first.
///
/// fontdb matches on the family name recorded in the font file's `name` table,
/// which is emphatically not the file name. The four files RavenLinux ships are
/// called `JetBrainsMonoNerdFontMono-*.ttf` and register as:
///
/// ```text
/// nameID 1  (family)              JetBrainsMono NFM
/// nameID 16 (typographic family)  JetBrainsMono Nerd Font Mono
/// ```
///
/// So neither "JetBrainsMono Nerd Font" nor "JetBrains Mono" matches them —
/// the Nerd Font patcher abbreviates *Mono* builds to `NFM`, and the `Mono`
/// suffix on the typographic name is not optional. Asking for the wrong string
/// does not fail loudly; fontdb silently falls back to whatever it finds first,
/// and the login screen renders in some other face entirely.
///
/// The list covers the two names the shipped files actually use, then the
/// non-Mono Nerd Font build and plain upstream JetBrains Mono, in case somebody
/// swaps the files in `RavenLinux/fonts/` for a different variant.
const FAMILIES: &[&str] = &[
    "JetBrainsMono NFM",
    "JetBrainsMono Nerd Font Mono",
    "JetBrainsMono Nerd Font",
    "JetBrains Mono",
];

/// How text is placed against the `x` it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    /// `x` is the left edge.
    Left,
    /// `x` is the centre.
    Center,
    /// `x` is the right edge.
    Right,
}

/// A shaped, rasterized run of text.
#[derive(Debug)]
pub struct TextRenderer {
    font_system: FontSystem,
    cache: SwashCache,
    /// The family that was actually found, resolved once at startup.
    family: Option<String>,
}

impl TextRenderer {
    /// Build the font database. This is the expensive part — it scans the
    /// system font directories — and it happens once, before the first frame.
    #[must_use]
    pub fn new() -> Self {
        let font_system = FontSystem::new();

        // Resolve the family once rather than per draw call. A name that
        // matches nothing makes cosmic-text fall back silently, which is the
        // right behaviour but leaves nobody any way to find out that the font
        // they shipped is not being used.
        let available: Vec<String> = font_system
            .db()
            .faces()
            .flat_map(|face| face.families.iter().map(|(name, _)| name.clone()))
            .collect();
        let family = FAMILIES
            .iter()
            .find(|wanted| available.iter().any(|have| have == *wanted))
            .map(|found| (*found).to_string());

        match &family {
            Some(name) => tracing::info!(font = %name, "using font"),
            None => {
                // List what *is* there. The failure mode this warning exists
                // for is a family name that is subtly wrong rather than a font
                // that is missing, and "none of these matched" without saying
                // what was on offer sends you looking for an uninstalled font
                // that is in fact installed under another name.
                let mut available: Vec<String> = available;
                available.sort_unstable();
                available.dedup();
                let shown: Vec<&String> = available.iter().take(24).collect();
                tracing::warn!(
                    tried = ?FAMILIES,
                    available = ?shown,
                    total_available = available.len(),
                    "none of the expected fonts are installed; falling back to whatever \
                     fontdb finds. If one of the names above looks like the intended font, \
                     FAMILIES in text.rs is what needs correcting -- not the font package"
                );
            }
        }

        Self {
            font_system,
            cache: SwashCache::new(),
            family,
        }
    }

    fn attrs(&self, weight: Weight) -> Attrs<'_> {
        let mut attrs = Attrs::new();
        attrs.family = match &self.family {
            Some(name) => Family::Name(name),
            None => Family::Monospace,
        };
        attrs.weight = weight;
        attrs
    }

    /// Lay one line out and hand back the buffer plus its measured width.
    fn shape(&mut self, text: &str, size: f32, weight: Weight) -> (Buffer, f32) {
        // Line height 1.25x is the usual readable ratio, and every string this
        // renders is a single line, so it only affects vertical centring.
        let mut buffer = Buffer::new(&mut self.font_system, Metrics::new(size, size * 1.25));
        // No wrapping: everything here is a label that should be measured and
        // placed, not flowed into a column.
        buffer.set_size(None, None);
        let attrs = self.attrs(weight);
        buffer.set_text(text, &attrs, Shaping::Advanced, None);
        buffer.shape_until_scroll(&mut self.font_system, false);

        let width = buffer
            .layout_runs()
            .map(|run| run.line_w)
            .fold(0.0_f32, f32::max);
        (buffer, width)
    }

    /// How wide `text` would be. Used to centre things and to size the field
    /// around its contents.
    pub fn measure(&mut self, text: &str, size: f32, weight: Weight) -> f32 {
        self.shape(text, size, weight).1
    }

    /// Draw one line of text.
    ///
    /// `y` is the *top* of the line box, not the baseline: every caller here
    /// is placing a label inside a layout it already computed, and tops are
    /// what that arithmetic is in.
    #[allow(clippy::too_many_arguments)]
    pub fn draw(
        &mut self,
        canvas: &mut Canvas<'_>,
        text: &str,
        x: f32,
        y: f32,
        size: f32,
        weight: Weight,
        color: Color,
        align: Align,
    ) {
        if text.is_empty() {
            return;
        }
        let (mut buffer, width) = self.shape(text, size, weight);

        let left = match align {
            Align::Left => x,
            Align::Center => x - width / 2.0,
            Align::Right => x - width,
        };

        // cosmic-text hands back a coverage value per pixel in the alpha
        // channel; the colour it is given rides along unchanged. So the glyph
        // colour is ours and the alpha is the anti-aliasing.
        let (ox, oy) = (left.round() as i32, y.round() as i32);
        let ink = cosmic_text::Color::rgba(color.red(), color.green(), color.blue(), color.alpha());

        buffer.draw(
            &mut self.font_system,
            &mut self.cache,
            ink,
            |gx, gy, gw, gh, glyph_color| {
                let coverage = f32::from(glyph_color.a()) / 255.0;
                if coverage <= 0.0 {
                    return;
                }
                // A glyph's cell is usually 1x1, but a decoration span (an
                // underline) arrives as a filled rectangle, so this handles
                // both rather than assuming a single pixel.
                for dy in 0..gh as i32 {
                    for dx in 0..gw as i32 {
                        canvas.blend(ox + gx + dx, oy + gy + dy, color, coverage);
                    }
                }
            },
        );
    }
}

impl Default for TextRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// Re-exported so the UI can ask for a weight without naming cosmic-text.
pub use cosmic_text::Weight as FontWeight;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme;

    /// Building the font database touches the filesystem, so these are one
    /// test rather than several: `FontSystem::new()` scans every font
    /// directory on the machine and is far too slow to do once per assertion.
    #[test]
    fn text_measures_and_draws() {
        let mut renderer = TextRenderer::new();

        // Measuring
        let empty = renderer.measure("", 16.0, FontWeight::NORMAL);
        assert_eq!(empty, 0.0, "an empty string has no width");

        let short = renderer.measure("R", 16.0, FontWeight::NORMAL);
        let long = renderer.measure("Raven Linux", 16.0, FontWeight::NORMAL);
        assert!(short > 0.0, "a glyph should have a width");
        assert!(long > short, "a longer string should be wider");

        let big = renderer.measure("Raven", 32.0, FontWeight::NORMAL);
        let small = renderer.measure("Raven", 16.0, FontWeight::NORMAL);
        assert!(big > small, "larger text should be wider");

        // Drawing
        let mut data = vec![0u8; 200 * 60 * 4];
        {
            let mut canvas = Canvas::new(&mut data, 200, 60);
            renderer.draw(
                &mut canvas,
                "Raven",
                10.0,
                10.0,
                24.0,
                FontWeight::BOLD,
                theme::TEXT,
                Align::Left,
            );
        }
        assert!(
            data.chunks_exact(4).any(|p| p[3] != 0),
            "drawing text should have marked some pixels"
        );
    }

    /// If a JetBrains Mono is installed, `FAMILIES` must match it.
    ///
    /// This is the test the font-name bug got past. Asking for a name no font
    /// registers under does not fail: fontdb quietly falls back, and the login
    /// screen renders in some unrelated face that nobody notices until they
    /// look at a screenshot. The four files RavenLinux ships are named
    /// `JetBrainsMonoNerdFontMono-*.ttf` but register as `JetBrainsMono NFM`,
    /// so the obvious guesses -- "JetBrains Mono", "JetBrainsMono Nerd Font" --
    /// both miss.
    ///
    /// Conditional rather than absolute, so it does not fail on a build host
    /// with no fonts at all: the invariant is "we do not miss a JetBrains Mono
    /// that is present", not "one is present".
    #[test]
    fn an_installed_jetbrains_mono_is_not_missed() {
        let renderer = TextRenderer::new();
        let installed: Vec<String> = FontSystem::new()
            .db()
            .faces()
            .flat_map(|face| face.families.iter().map(|(name, _)| name.clone()))
            .filter(|name| {
                name.replace(' ', "")
                    .to_lowercase()
                    .contains("jetbrainsmono")
            })
            .collect();

        if installed.is_empty() {
            return;
        }
        assert!(
            renderer.family.is_some(),
            "a JetBrains Mono is installed under {installed:?}, but FAMILIES matched none of \
             them: {FAMILIES:?}. Add the real name -- do not assume the font is missing."
        );
    }

    /// Text drawn off the edge must be clipped, not panic. A greeter that dies
    /// on a narrow screen shows nobody a prompt.
    #[test]
    fn text_off_the_canvas_is_clipped() {
        let mut renderer = TextRenderer::new();
        let mut data = vec![0u8; 40 * 20 * 4];
        let mut canvas = Canvas::new(&mut data, 40, 20);
        for (x, y) in [(-500.0, -500.0), (500.0, 500.0), (-5.0, 5.0)] {
            renderer.draw(
                &mut canvas,
                "a string much wider than this canvas",
                x,
                y,
                24.0,
                FontWeight::NORMAL,
                theme::TEXT,
                Align::Left,
            );
        }
    }
}
