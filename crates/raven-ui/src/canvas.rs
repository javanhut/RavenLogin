//! Software drawing into a `wl_shm` buffer.
//!
//! The login screen is drawn on the CPU. That is a deliberate choice and not a
//! shortcut: a greeter runs once per boot, covers one screen, and animates
//! nothing but a caret, so the GPU buys it no frames worth having — and using
//! one would mean this process links EGL, GLES and a DRM driver, which is a
//! large amount of C on the far side of a login prompt. `huginn` already holds
//! the GPU; this fills a rectangle of memory and hands it over.
//!
//! Everything is anti-aliased through a signed distance field rather than by
//! supersampling. For the shapes here — rounded rectangles and circles — the
//! distance to the edge has a closed form, so coverage is one `clamp` per pixel
//! instead of four or sixteen samples, and the result is exact rather than
//! approximated.
//!
//! Pixels are `0xAARRGGBB` written little-endian, which is what `wl_shm`'s
//! `Argb8888` means. The canvas is opaque: everything is composited onto a
//! filled background, so the alpha channel is 255 everywhere by the time it is
//! handed over and premultiplication never comes into it.

use crate::theme::Color;

/// A borrowed `wl_shm` buffer, with drawing operations on top.
#[derive(Debug)]
pub struct Canvas<'a> {
    data: &'a mut [u8],
    width: i32,
    height: i32,
}

impl<'a> Canvas<'a> {
    /// Wrap a buffer. `data` must be `width * height * 4` bytes.
    pub fn new(data: &'a mut [u8], width: i32, height: i32) -> Self {
        debug_assert_eq!(
            data.len(),
            (width * height * 4) as usize,
            "canvas buffer is the wrong size for {width}x{height}"
        );
        Self {
            data,
            width,
            height,
        }
    }

    #[must_use]
    pub fn width(&self) -> f32 {
        self.width as f32
    }

    #[must_use]
    pub fn height(&self) -> f32 {
        self.height as f32
    }

    /// Composite one pixel, source-over.
    ///
    /// Out-of-bounds coordinates are dropped rather than clamped. A shape
    /// partly off the edge should be clipped, not smeared along it, and the
    /// callers below all rely on being able to iterate a bounding box that may
    /// hang off the screen.
    pub fn blend(&mut self, x: i32, y: i32, color: Color, coverage: f32) {
        if x < 0 || y < 0 || x >= self.width || y >= self.height {
            return;
        }
        let alpha = f32::from(color.alpha()) / 255.0 * coverage.clamp(0.0, 1.0);
        if alpha <= 0.0 {
            return;
        }

        let index = ((y * self.width + x) * 4) as usize;
        let Some(pixel) = self.data.get_mut(index..index + 4) else {
            return;
        };

        // Little-endian ARGB: byte 0 is blue, byte 3 is alpha.
        let mix = |dst: u8, src: u8| -> u8 {
            (f32::from(src) * alpha + f32::from(dst) * (1.0 - alpha)) as u8
        };
        pixel[0] = mix(pixel[0], color.blue());
        pixel[1] = mix(pixel[1], color.green());
        pixel[2] = mix(pixel[2], color.red());
        pixel[3] = 0xFF;
    }

    /// Fill the whole canvas with a vertical gradient, `top` to `bottom`.
    ///
    /// Written directly rather than through `blend`, because this is the one
    /// operation that touches every pixel and it has no coverage or alpha to
    /// consider — it is the ground everything else is composited onto.
    ///
    /// # Dithering
    ///
    /// The backdrop runs from `0x16161F` to `0x0D0D14`: nine values of red
    /// across the whole height of the screen. Rounded to the nearest byte that
    /// is nine flat bands with hard edges, and on a large dark panel those
    /// edges are clearly visible — the gradient meant to *prevent* banding
    /// produces it instead.
    ///
    /// So the channel value is perturbed by a 4x4 ordered (Bayer) threshold
    /// before it is truncated, which trades the hard edges for a stipple far
    /// below the noise floor of any real panel. Ordered rather than random
    /// because it is deterministic: the same frame renders identically every
    /// time, so a preview PNG can be compared against the last one.
    pub fn gradient(&mut self, top: Color, bottom: Color) {
        /// A 4x4 Bayer matrix, scaled to 0.0..1.0 and centred on zero, so the
        /// perturbation is +/- half a step and the mean is unchanged.
        #[rustfmt::skip]
        const BAYER: [[f32; 4]; 4] = [
            [ 0.0 / 16.0,  8.0 / 16.0,  2.0 / 16.0, 10.0 / 16.0],
            [12.0 / 16.0,  4.0 / 16.0, 14.0 / 16.0,  6.0 / 16.0],
            [ 3.0 / 16.0, 11.0 / 16.0,  1.0 / 16.0,  9.0 / 16.0],
            [15.0 / 16.0,  7.0 / 16.0, 13.0 / 16.0,  5.0 / 16.0],
        ];

        let height = (self.height.max(1) - 1).max(1) as f32;
        for y in 0..self.height {
            let t = y as f32 / height;
            let lerp = |a: u8, b: u8| -> f32 { f32::from(a) + (f32::from(b) - f32::from(a)) * t };
            // Exact, unrounded channel values for this row.
            let (bf, gf, rf) = (
                lerp(top.blue(), bottom.blue()),
                lerp(top.green(), bottom.green()),
                lerp(top.red(), bottom.red()),
            );

            let row = (y * self.width * 4) as usize;
            let bayer_row = &BAYER[(y & 3) as usize];
            for x in 0..self.width as usize {
                let threshold = bayer_row[x & 3] - 0.5;
                let quantize = |v: f32| (v + threshold).clamp(0.0, 255.0) as u8;

                let i = row + x * 4;
                let Some(pixel) = self.data.get_mut(i..i + 4) else {
                    continue;
                };
                pixel[0] = quantize(bf);
                pixel[1] = quantize(gf);
                pixel[2] = quantize(rf);
                pixel[3] = 0xFF;
            }
        }
    }

    /// Replace every pixel with a pre-scaled background.
    ///
    /// `pixels` must already be this canvas's exact size, in this canvas's
    /// layout -- which is what [`crate::wallpaper::Wallpaper::prepared`]
    /// returns, and the reason the scaling lives there rather than here. All
    /// this does is the copy, so a wallpapered frame costs one `memcpy` more
    /// than a plain one.
    ///
    /// Returns whether it drew. A mismatched buffer is refused rather than
    /// partially copied, so the caller can fall back to [`Self::gradient`]:
    /// half a wallpaper and half an uninitialized frame is worse than no
    /// wallpaper.
    #[must_use]
    pub fn blit(&mut self, pixels: &[u8]) -> bool {
        if pixels.len() != self.data.len() {
            return false;
        }
        self.data.copy_from_slice(pixels);
        true
    }

    /// A filled rounded rectangle.
    ///
    /// `radius` is clamped to half the shorter side, so a "rounded rectangle"
    /// with an absurd radius becomes a capsule rather than folding inside out.
    pub fn rounded_rect(&mut self, rect: Rect, radius: f32, color: Color) {
        self.rounded_rect_impl(rect, radius, color, None);
    }

    /// The outline of a rounded rectangle, `thickness` wide, drawn inside the
    /// rectangle's bounds.
    pub fn rounded_rect_outline(&mut self, rect: Rect, radius: f32, thickness: f32, color: Color) {
        self.rounded_rect_impl(rect, radius, color, Some(thickness.max(0.1)));
    }

    fn rounded_rect_impl(&mut self, rect: Rect, radius: f32, color: Color, outline: Option<f32>) {
        let radius = radius.min(rect.width / 2.0).min(rect.height / 2.0).max(0.0);

        // The distance field is evaluated about the rectangle's centre, so the
        // half-extents are what the formula needs.
        let (cx, cy) = (rect.x + rect.width / 2.0, rect.y + rect.height / 2.0);
        let (hx, hy) = (rect.width / 2.0 - radius, rect.height / 2.0 - radius);

        // One pixel of margin so the anti-aliased edge is not clipped.
        for y in bounds(rect.y - 1.0, rect.y + rect.height + 1.0, self.height) {
            for x in bounds(rect.x - 1.0, rect.x + rect.width + 1.0, self.width) {
                // Pixel centre, not corner: sampling at the corner shifts every
                // shape half a pixel up and left.
                let px = x as f32 + 0.5 - cx;
                let py = y as f32 + 0.5 - cy;

                // Distance to the rounded rectangle's boundary. Negative
                // inside, positive outside.
                let dx = px.abs() - hx;
                let dy = py.abs() - hy;
                let outside = (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt();
                let inside = dx.max(dy).min(0.0);
                let distance = outside + inside - radius;

                let coverage = match outline {
                    // A ring: coverage falls off on both sides of the edge.
                    Some(thickness) => coverage_of(distance.abs() - thickness / 2.0),
                    None => coverage_of(distance),
                };
                self.blend(x, y, color, coverage);
            }
        }
    }

    /// A filled circle.
    pub fn circle(&mut self, cx: f32, cy: f32, radius: f32, color: Color) {
        self.circle_impl(cx, cy, radius, color, None);
    }

    /// A circular ring, `thickness` wide, centred on `radius`.
    pub fn circle_outline(&mut self, cx: f32, cy: f32, radius: f32, thickness: f32, color: Color) {
        self.circle_impl(cx, cy, radius, color, Some(thickness.max(0.1)));
    }

    fn circle_impl(&mut self, cx: f32, cy: f32, radius: f32, color: Color, outline: Option<f32>) {
        for y in bounds(cy - radius - 1.0, cy + radius + 1.0, self.height) {
            for x in bounds(cx - radius - 1.0, cx + radius + 1.0, self.width) {
                let dx = x as f32 + 0.5 - cx;
                let dy = y as f32 + 0.5 - cy;
                let distance = (dx * dx + dy * dy).sqrt() - radius;

                let coverage = match outline {
                    Some(thickness) => coverage_of(distance.abs() - thickness / 2.0),
                    None => coverage_of(distance),
                };
                self.blend(x, y, color, coverage);
            }
        }
    }
}

/// A rectangle in surface coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl Rect {
    #[must_use]
    pub const fn new(x: f32, y: f32, width: f32, height: f32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

/// Coverage for a pixel whose centre is `distance` from an edge.
///
/// The one-pixel linear ramp either side of the boundary is what makes the
/// edges smooth. A step function here is the difference between this looking
/// drawn and looking rasterized.
fn coverage_of(distance: f32) -> f32 {
    (0.5 - distance).clamp(0.0, 1.0)
}

/// The pixel rows or columns a shape can touch, clipped to the canvas.
fn bounds(low: f32, high: f32, limit: i32) -> std::ops::Range<i32> {
    let start = (low.floor() as i32).max(0);
    let end = (high.ceil() as i32).min(limit);
    start..end.max(start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme;

    fn canvas(width: i32, height: i32) -> Vec<u8> {
        vec![0; (width * height * 4) as usize]
    }

    fn pixel(data: &[u8], width: i32, x: i32, y: i32) -> (u8, u8, u8, u8) {
        let i = ((y * width + x) * 4) as usize;
        (data[i + 2], data[i + 1], data[i], data[i + 3])
    }

    #[test]
    fn a_filled_rect_covers_its_interior() {
        let mut data = canvas(40, 40);
        let mut c = Canvas::new(&mut data, 40, 40);
        c.rounded_rect(Rect::new(10.0, 10.0, 20.0, 20.0), 0.0, theme::ACCENT);

        // Well inside.
        let (r, g, b, a) = pixel(&data, 40, 20, 20);
        assert_eq!((r, g, b, a), (0x7A, 0xA2, 0xF7, 0xFF));
        // Well outside.
        assert_eq!(pixel(&data, 40, 2, 2).3, 0x00);
    }

    /// The point of the distance field: an edge pixel is partially covered
    /// rather than fully on or off.
    #[test]
    fn edges_are_antialiased() {
        let mut data = canvas(40, 40);
        let mut c = Canvas::new(&mut data, 40, 40);
        // A half-pixel offset guarantees a partially covered column.
        c.rounded_rect(Rect::new(10.5, 10.0, 20.0, 20.0), 0.0, theme::TEXT);

        let edge = pixel(&data, 40, 10, 20).0;
        assert!(edge > 0, "the edge pixel should have some coverage");
        assert!(edge < theme::TEXT.red(), "it should not be fully covered");
    }

    #[test]
    fn a_circle_is_round() {
        let mut data = canvas(40, 40);
        let mut c = Canvas::new(&mut data, 40, 40);
        c.circle(20.0, 20.0, 10.0, theme::ACCENT);

        // Centre is filled; the corners of its bounding box are not.
        assert_eq!(pixel(&data, 40, 20, 20).3, 0xFF);
        assert_eq!(pixel(&data, 40, 11, 11).3, 0x00);
        // A point just inside the radius, on the axis, is filled.
        assert_eq!(pixel(&data, 40, 28, 20).3, 0xFF);
    }

    #[test]
    fn an_outline_is_hollow() {
        let mut data = canvas(60, 60);
        let mut c = Canvas::new(&mut data, 60, 60);
        c.circle_outline(30.0, 30.0, 20.0, 3.0, theme::ACCENT);

        // On the ring.
        assert!(
            pixel(&data, 60, 50, 30).3 > 0x80,
            "the ring should be drawn"
        );
        // Inside it.
        assert_eq!(
            pixel(&data, 60, 30, 30).3,
            0x00,
            "the middle should be empty"
        );
    }

    /// Nothing may be written outside the buffer, whatever it is asked to
    /// draw. A greeter that panics on an odd screen size shows nobody a login
    /// prompt.
    #[test]
    fn shapes_are_clipped_not_wrapped() {
        let mut data = canvas(20, 20);
        {
            let mut c = Canvas::new(&mut data, 20, 20);
            c.circle(-50.0, -50.0, 10.0, theme::ACCENT);
            c.circle(1000.0, 1000.0, 100.0, theme::ACCENT);
            c.rounded_rect(Rect::new(-100.0, -100.0, 50.0, 50.0), 8.0, theme::ACCENT);
            // One that straddles the edge, which is the case that actually
            // happens on a narrow screen.
            c.rounded_rect(Rect::new(-10.0, 5.0, 40.0, 5.0), 2.0, theme::ACCENT);
        }
        // Nothing off-shape was touched.
        assert_eq!(pixel(&data, 20, 19, 19).3, 0x00);
    }

    #[test]
    fn a_zero_sized_shape_draws_nothing_and_does_not_panic() {
        let mut data = canvas(20, 20);
        let mut c = Canvas::new(&mut data, 20, 20);
        c.rounded_rect(Rect::new(5.0, 5.0, 0.0, 0.0), 4.0, theme::ACCENT);
        c.circle(10.0, 10.0, 0.0, theme::ACCENT);
    }

    /// An absurd corner radius must round the shape off, not invert it.
    #[test]
    fn an_oversized_radius_becomes_a_capsule() {
        let mut data = canvas(60, 40);
        let mut c = Canvas::new(&mut data, 60, 40);
        c.rounded_rect(Rect::new(10.0, 10.0, 40.0, 20.0), 999.0, theme::ACCENT);

        // The centre is filled and the corners are not.
        assert_eq!(pixel(&data, 60, 30, 20).3, 0xFF);
        assert_eq!(pixel(&data, 60, 11, 11).3, 0x00);
    }

    #[test]
    fn the_gradient_runs_top_to_bottom_and_is_opaque() {
        let mut data = canvas(4, 16);
        {
            let mut c = Canvas::new(&mut data, 4, 16);
            c.gradient(theme::BACKDROP, theme::BACKDROP_EDGE);
        }
        let top = pixel(&data, 4, 0, 0);
        let bottom = pixel(&data, 4, 0, 15);
        // Within one step: dithering perturbs each channel by up to half a
        // level either way, which is the whole point of it.
        assert!(
            top.0.abs_diff(theme::BACKDROP.red()) <= 1,
            "top was {}",
            top.0
        );
        assert!(
            bottom.0.abs_diff(theme::BACKDROP_EDGE.red()) <= 1,
            "bottom was {}",
            bottom.0
        );
        assert!(top.0 > bottom.0, "the gradient should darken downwards");
        assert_eq!(top.3, 0xFF);
        assert_eq!(bottom.3, 0xFF);
    }

    /// Blending a translucent colour over a filled background must land
    /// between the two, and must leave the result opaque.
    #[test]
    fn blending_is_source_over() {
        let mut data = canvas(4, 4);
        let mut c = Canvas::new(&mut data, 4, 4);
        c.gradient(theme::BACKDROP, theme::BACKDROP);
        c.blend(1, 1, theme::TEXT.with_alpha(0x80), 1.0);

        let (r, _, _, a) = pixel(&data, 4, 1, 1);
        assert_eq!(a, 0xFF, "the canvas must stay opaque");
        assert!(
            r > theme::BACKDROP.red() && r < theme::TEXT.red(),
            "half-alpha text over the backdrop should land between them, got {r:#04x}"
        );
    }
}
