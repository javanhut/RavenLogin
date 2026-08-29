//! The image the login screen is drawn on.
//!
//! Decoded once, scaled once per surface size, and after that a wallpapered
//! frame costs exactly one `copy_from_slice` more than an unwallpapered one.
//! That matters because [`crate::screen::LoginScreen::draw`] runs on every frame
//! callback -- the caret blinks and the clock ticks, so this surface redraws
//! at the panel's refresh rate forever -- and rescaling two million pixels
//! sixty times a second to draw the same picture would be the only expensive
//! thing in a process that is otherwise idle.
//!
//! # What is trusted here
//!
//! A wallpaper is the first attacker-shaped input the greeter takes that is
//! not a font: an administrator names a path in `login.toml`, and this decodes
//! whatever is at it. Three things bound that:
//!
//! - The decoders are pure-Rust and this crate forbids `unsafe`, so a
//!   malformed image is a `Result::Err` rather than a corrupted stack.
//! - Both decoders are given explicit limits, below, so a 40-byte file
//!   claiming to be 60000x60000 is refused instead of being allocated.
//! - Every failure is non-fatal. A wallpaper that will not decode logs a
//!   warning and leaves the backdrop gradient in place, because the one
//!   outcome a login screen must never have is "cannot log in, bad picture".
//!
//! # Colour
//!
//! Pixels are kept in the canvas's own layout -- little-endian `0xAARRGGBB`,
//! so bytes are `[B, G, R, A]` -- rather than in the decoder's RGBA. The swap
//! happens once, here, instead of on every pixel of every blit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::theme;

/// The largest file this will read, before any decoding.
///
/// A wallpaper is a photograph. 64 MiB is far past any real one and well short
/// of anything that would embarrass the greeter's memory footprint.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The largest image this will decode, in pixels.
///
/// 64 megapixels is about an 8000x8000 image -- comfortably more than an 8K
/// panel needs and roughly 256 MiB once it is RGBA, which is the real ceiling
/// being set here. Both decoders are told about this rather than being allowed
/// to allocate first and be checked afterwards.
const MAX_PIXELS: usize = 64 * 1_000_000;

/// The largest single dimension this will decode.
///
/// Separate from [`MAX_PIXELS`] because that is an area and the decoders take
/// a width and a height. A 100000x2 image is only 200k pixels and would pass
/// the area check while still being nothing anybody meant to set as a
/// wallpaper.
const MAX_DIMENSION: usize = 32_768;

/// Where a machine keeps the wallpaper somebody has chosen.
///
/// `/usr/share/wallpaper` is the library of images an installation ships or
/// collects. `set/` holds the one that is currently on, under the name
/// `wallpaper` with whatever extension the image arrived with -- an extension
/// which is a label for humans and still not what decides the format, since
/// [`decode`] reads that out of the first bytes either way. A symlink into the
/// library counts, because this follows them.
///
/// Compiled in rather than made another key in `login.toml`, deliberately.
/// This is the path huginn draws on the desktop too, so it is a contract
/// between the login screen and the session that follows it rather than a
/// preference belonging to either -- and a machine that wants a *different*
/// picture on the login screen specifically already has `wallpaper =` to say
/// so, which still wins over this.
const SET_DIR: &str = "/usr/share/wallpaper/set";

/// The basename of the active wallpaper inside [`SET_DIR`].
const SET_STEM: &str = "wallpaper";

/// The wallpaper this machine has set, if it has one.
///
/// Consulted only when `login.toml` names no wallpaper of its own. Every
/// failure here is silence rather than a warning, which is the opposite of how
/// a configured path is treated and is the point: a path an administrator
/// wrote down and got wrong is worth complaining about, and a directory nobody
/// has put anything in is the ordinary state of a machine that never set one.
pub fn installed() -> Option<PathBuf> {
    let entries = std::fs::read_dir(SET_DIR).ok()?;
    let found = choose(
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            // Follows symlinks, so `set/wallpaper.jpg -> ../cliff.jpg` is a
            // file by this test and a directory called `wallpaper.d` is not.
            .filter(|path| path.is_file()),
    )?;
    tracing::info!(path = %found.display(), "using the wallpaper this machine has set");
    Some(found)
}

/// Pick the active wallpaper out of the names in [`SET_DIR`].
///
/// Split from [`installed`] so the rule is testable without a filesystem.
/// Sorted, because `read_dir` yields whatever order the filesystem feels like
/// and a directory holding two of these should not mean a wallpaper that
/// changes between boots. More than one `wallpaper.*` in `set/` is a mistake
/// however it is resolved; sorting at least makes it the same mistake twice.
fn choose(entries: impl Iterator<Item = PathBuf>) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = entries
        .filter(|path| path.file_stem().is_some_and(|stem| stem == SET_STEM))
        .collect();
    candidates.sort();
    candidates.into_iter().next()
}

/// A decoded wallpaper, and the scaled copy last asked for.
pub struct Wallpaper {
    image: Image,
    prepared: Option<Prepared>,
}

impl std::fmt::Debug for Wallpaper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written: the derived one would try to format several megabytes
        // of pixels into a log line.
        f.debug_struct("Wallpaper")
            .field("width", &self.image.width)
            .field("height", &self.image.height)
            .field(
                "prepared",
                &self.prepared.as_ref().map(|p| (p.width, p.height)),
            )
            .finish()
    }
}

/// Pixels in the canvas's layout: `[B, G, R, A]` per pixel.
struct Image {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

/// The image scaled to one particular surface, with the scrim already in it.
struct Prepared {
    width: i32,
    height: i32,
    pixels: Vec<u8>,
}

impl Wallpaper {
    /// Read and decode the file at `path`.
    ///
    /// The format is decided by the file's first bytes and not by its
    /// extension. That is partly because an extension is a claim anybody can
    /// get wrong -- a `.jpg` that is really a PNG is a common enough accident
    /// that it is worth not caring about -- and partly because dispatching a
    /// parser on a filename is how a parser ends up being handed a file the
    /// caller did not think it was handing it.
    pub fn load(path: &Path) -> Result<Self> {
        let size = std::fs::metadata(path)
            .with_context(|| format!("cannot stat {}", path.display()))?
            .len();
        if size > MAX_FILE_BYTES {
            bail!(
                "{} is {size} bytes, past the {MAX_FILE_BYTES}-byte limit for a wallpaper",
                path.display()
            );
        }

        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let image = decode(&bytes)
            .with_context(|| format!("cannot decode {} as a wallpaper", path.display()))?;

        tracing::info!(
            path = %path.display(),
            width = image.width,
            height = image.height,
            "wallpaper loaded"
        );
        Ok(Self {
            image,
            prepared: None,
        })
    }

    /// A wallpaper of one flat colour.
    ///
    /// For tests elsewhere in the crate that need something to draw on
    /// without a file on disk to decode.
    #[cfg(test)]
    pub fn flat(width: u32, height: u32, blue: u8, green: u8, red: u8) -> Self {
        let mut pixels = Vec::with_capacity((width as usize) * (height as usize) * 4);
        for _ in 0..(width as usize) * (height as usize) {
            pixels.extend_from_slice(&[blue, green, red, 0xFF]);
        }
        Self {
            image: Image {
                width,
                height,
                pixels,
            },
            prepared: None,
        }
    }

    /// The image scaled to cover `width` x `height`, ready to blit.
    ///
    /// Cached: the scale is redone only when the surface size changes, which
    /// happens at the first configure and then essentially never.
    pub fn prepared(&mut self, width: i32, height: i32) -> &[u8] {
        let stale = self
            .prepared
            .as_ref()
            .is_none_or(|p| p.width != width || p.height != height);

        if stale {
            tracing::debug!(width, height, "scaling the wallpaper");
            self.prepared = Some(Prepared {
                width,
                height,
                pixels: self.image.scaled_to_cover(width, height),
            });
        }

        // Set immediately above if it was stale, so this cannot be `None`.
        self.prepared.as_ref().map_or(&[], |p| &p.pixels)
    }
}

impl Image {
    /// Scale to fill `width` x `height` exactly, cropping the overflowing
    /// axis, and darken the result by [`theme::SCRIM`].
    ///
    /// "Cover" rather than "fit" because a letterboxed wallpaper looks like a
    /// mistake, and because the bars would be the one part of the screen not
    /// matching the desktop this hands over to.
    ///
    /// The scrim is baked in here rather than composited at draw time for the
    /// reason the module header gives: this runs once, and drawing runs sixty
    /// times a second.
    fn scaled_to_cover(&self, width: i32, height: i32) -> Vec<u8> {
        let (dst_w, dst_h) = (width.max(1) as usize, height.max(1) as usize);
        let (src_w, src_h) = (self.width.max(1) as usize, self.height.max(1) as usize);

        // The larger of the two ratios is the one that leaves no gap.
        let scale = (dst_w as f32 / src_w as f32).max(dst_h as f32 / src_h as f32);
        // How much of the source is visible, and where it starts, so the crop
        // takes the middle of the image rather than the top-left corner.
        let window_w = (dst_w as f32 / scale).min(src_w as f32);
        let window_h = (dst_h as f32 / scale).min(src_h as f32);
        let origin_x = (src_w as f32 - window_w) / 2.0;
        let origin_y = (src_h as f32 - window_h) / 2.0;

        let scrim = f32::from(theme::SCRIM.alpha()) / 255.0;
        let keep = 1.0 - scrim;
        let (scrim_b, scrim_g, scrim_r) = (
            f32::from(theme::SCRIM.blue()) * scrim,
            f32::from(theme::SCRIM.green()) * scrim,
            f32::from(theme::SCRIM.red()) * scrim,
        );

        let mut out = vec![0u8; dst_w * dst_h * 4];
        for y in 0..dst_h {
            // Sample at pixel centres. Sampling at the corner instead shifts
            // the whole image by half a source pixel, which is invisible on a
            // photograph and obvious on anything with a straight edge in it.
            let sy = origin_y + (y as f32 + 0.5) / scale;
            for x in 0..dst_w {
                let sx = origin_x + (x as f32 + 0.5) / scale;
                let (b, g, r) = self.sample(sx, sy);

                let i = (y * dst_w + x) * 4;
                out[i] = (b * keep + scrim_b) as u8;
                out[i + 1] = (g * keep + scrim_g) as u8;
                out[i + 2] = (r * keep + scrim_r) as u8;
                // The canvas is opaque; see `canvas`'s header.
                out[i + 3] = 0xFF;
            }
        }
        out
    }

    /// Bilinear sample, in `(B, G, R)` and unrounded.
    ///
    /// Bilinear and not nearest because the common case is a 1920x1080 photo
    /// on a panel that is not 1920x1080, and nearest-neighbour on a downscale
    /// is where the aliasing on a diagonal comes from. It is not a box filter,
    /// so a very large downscale still aliases; that is a trade for one pass
    /// over the destination rather than one over the source.
    fn sample(&self, x: f32, y: f32) -> (f32, f32, f32) {
        let (w, h) = (self.width as usize, self.height as usize);
        if w == 0 || h == 0 {
            return (0.0, 0.0, 0.0);
        }

        // Half a pixel back, so `x0` is the sample to the left of the point
        // rather than the one containing it.
        let fx = (x - 0.5).clamp(0.0, (w - 1) as f32);
        let fy = (y - 0.5).clamp(0.0, (h - 1) as f32);
        let (x0, y0) = (fx.floor() as usize, fy.floor() as usize);
        let (x1, y1) = ((x0 + 1).min(w - 1), (y0 + 1).min(h - 1));
        let (tx, ty) = (fx - x0 as f32, fy - y0 as f32);

        let at = |px: usize, py: usize, c: usize| -> f32 {
            f32::from(self.pixels[(py * w + px) * 4 + c])
        };
        let lerp = |a: f32, b: f32, t: f32| a + (b - a) * t;

        let mut out = [0.0f32; 3];
        for (c, channel) in out.iter_mut().enumerate() {
            let top = lerp(at(x0, y0, c), at(x1, y0, c), tx);
            let bottom = lerp(at(x0, y1, c), at(x1, y1, c), tx);
            *channel = lerp(top, bottom, ty);
        }
        (out[0], out[1], out[2])
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Dispatch on the file's magic number.
fn decode(bytes: &[u8]) -> Result<Image> {
    const PNG_MAGIC: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    const JPEG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF];

    if bytes.starts_with(PNG_MAGIC) {
        decode_png(bytes)
    } else if bytes.starts_with(JPEG_MAGIC) {
        decode_jpeg(bytes)
    } else {
        bail!("not a PNG or a JPEG");
    }
}

fn decode_png(bytes: &[u8]) -> Result<Image> {
    // A `Cursor`, because png wants `Read + Seek` and a slice is only `Read`.
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    // Ask the decoder to normalise the awkward cases -- palettes, 1/2/4-bit
    // depths, 16-bit channels, missing alpha -- so the only outputs left to
    // handle below are 8-bit RGBA and 8-bit grey+alpha.
    decoder.set_transformations(
        png::Transformations::EXPAND | png::Transformations::STRIP_16 | png::Transformations::ALPHA,
    );
    decoder.set_limits(png::Limits {
        bytes: MAX_PIXELS * 4,
    });

    let mut reader = decoder.read_info().context("bad PNG header")?;
    let info = reader.info();
    let (width, height) = (info.width, info.height);
    check_dimensions(width, height)?;

    let mut buffer = vec![0u8; reader.output_buffer_size().context("PNG is too large")?];
    let frame = reader.next_frame(&mut buffer).context("bad PNG data")?;
    let channels = match frame.color_type {
        png::ColorType::Rgba => 4,
        png::ColorType::GrayscaleAlpha => 2,
        other => bail!("unsupported PNG colour type {other:?}"),
    };

    let pixels = to_canvas_order(&buffer[..frame.buffer_size()], width, height, channels)?;
    Ok(Image {
        width,
        height,
        pixels,
    })
}

fn decode_jpeg(bytes: &[u8]) -> Result<Image> {
    use zune_jpeg::zune_core::colorspace::ColorSpace;
    use zune_jpeg::zune_core::options::DecoderOptions;

    // The dimension caps are set before the header is read, so an oversized
    // image is refused by the decoder rather than allocated and then rejected.
    let options = DecoderOptions::default()
        .jpeg_set_out_colorspace(ColorSpace::RGB)
        .set_max_width(MAX_DIMENSION)
        .set_max_height(MAX_DIMENSION);

    // A `Cursor` for the same reason as the PNG side: the decoder wants
    // `Read + Seek`, and a slice is only `Read`.
    let mut decoder =
        zune_jpeg::JpegDecoder::new_with_options(std::io::Cursor::new(bytes), options);
    decoder
        .decode_headers()
        .map_err(|e| anyhow::anyhow!("bad JPEG header: {e}"))?;
    let (width, height) = decoder
        .dimensions()
        .context("the JPEG header carries no dimensions")?;
    let (width, height) = (
        u32::try_from(width).context("absurd JPEG width")?,
        u32::try_from(height).context("absurd JPEG height")?,
    );
    check_dimensions(width, height)?;

    let decoded = decoder
        .decode()
        .map_err(|e| anyhow::anyhow!("bad JPEG data: {e}"))?;

    // A greyscale JPEG comes back as one channel even having asked for RGB,
    // because the requested colourspace is a request and not a conversion.
    let channels = match decoder.output_colorspace() {
        Some(ColorSpace::RGB) => 3,
        Some(ColorSpace::Luma) => 1,
        other => bail!("unsupported JPEG colourspace {other:?}"),
    };

    let pixels = to_canvas_order(&decoded, width, height, channels)?;
    Ok(Image {
        width,
        height,
        pixels,
    })
}

fn check_dimensions(width: u32, height: u32) -> Result<()> {
    if width == 0 || height == 0 {
        bail!("the image is {width}x{height}");
    }
    if width as usize > MAX_DIMENSION || height as usize > MAX_DIMENSION {
        bail!("the image is {width}x{height}, past the {MAX_DIMENSION}-pixel limit on a side");
    }
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .context("the image dimensions overflow")?;
    if pixels > MAX_PIXELS {
        bail!("the image is {width}x{height}, past the {MAX_PIXELS}-pixel limit");
    }
    Ok(())
}

/// Convert decoder output to the canvas's `[B, G, R, A]`, opaque.
///
/// `channels` is what the decoder produced per pixel: 4 for RGBA, 3 for RGB,
/// 2 for grey+alpha, 1 for grey. Alpha is dropped rather than composited --
/// there is nothing behind a wallpaper to blend it onto, and treating a
/// translucent pixel as opaque is more predictable than inventing a colour to
/// put behind it.
fn to_canvas_order(src: &[u8], width: u32, height: u32, channels: usize) -> Result<Vec<u8>> {
    let count = (width as usize) * (height as usize);
    let wanted = count * channels;
    if src.len() < wanted {
        bail!(
            "the decoder produced {} bytes for a {width}x{height} image needing {wanted}",
            src.len()
        );
    }

    let mut out = vec![0u8; count * 4];
    for i in 0..count {
        let (r, g, b) = match channels {
            1 | 2 => {
                let grey = src[i * channels];
                (grey, grey, grey)
            }
            _ => {
                let p = i * channels;
                (src[p], src[p + 1], src[p + 2])
            }
        };
        let o = i * 4;
        out[o] = b;
        out[o + 1] = g;
        out[o + 2] = r;
        out[o + 3] = 0xFF;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(|n| Path::new(SET_DIR).join(n)).collect()
    }

    #[test]
    fn any_extension_is_the_wallpaper() {
        for name in ["wallpaper.png", "wallpaper.jpg", "wallpaper.jpeg"] {
            let picked = choose(paths(&[name]).into_iter());
            assert_eq!(picked, Some(Path::new(SET_DIR).join(name)), "{name}");
        }
    }

    /// The extension is a label, so a file that never got one is still the
    /// wallpaper -- `decode` reads the format out of the bytes regardless.
    #[test]
    fn no_extension_is_still_the_wallpaper() {
        assert_eq!(
            choose(paths(&["wallpaper"]).into_iter()),
            Some(Path::new(SET_DIR).join("wallpaper"))
        );
    }

    #[test]
    fn other_names_are_not() {
        assert_eq!(
            choose(paths(&["cliff_arch_sea.jpg", "README"]).into_iter()),
            None
        );
        assert_eq!(choose(paths(&["wallpaper.old.png"]).into_iter()), None);
    }

    /// `read_dir` order is the filesystem's business, and a login screen that
    /// picks a different picture on alternate boots is a bug report nobody
    /// can reproduce.
    #[test]
    fn two_wallpapers_resolve_the_same_way_every_time() {
        let forwards = choose(paths(&["wallpaper.png", "wallpaper.jpg"]).into_iter());
        let backwards = choose(paths(&["wallpaper.jpg", "wallpaper.png"]).into_iter());
        assert_eq!(forwards, backwards);
        assert_eq!(forwards, Some(Path::new(SET_DIR).join("wallpaper.jpg")));
    }

    #[test]
    fn an_empty_directory_has_no_wallpaper() {
        assert_eq!(choose(std::iter::empty()), None);
    }

    /// A 2x2 image: red, green / blue, white.
    fn checker() -> Image {
        #[rustfmt::skip]
        let pixels = vec![
            0x00, 0x00, 0xFF, 0xFF,   0x00, 0xFF, 0x00, 0xFF,
            0xFF, 0x00, 0x00, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,
        ];
        Image {
            width: 2,
            height: 2,
            pixels,
        }
    }

    #[test]
    fn rgb_becomes_bgra() {
        let src = [0x11, 0x22, 0x33];
        let out = to_canvas_order(&src, 1, 1, 3).unwrap();
        assert_eq!(out, vec![0x33, 0x22, 0x11, 0xFF]);
    }

    #[test]
    fn grey_expands_to_three_channels() {
        let out = to_canvas_order(&[0x7F], 1, 1, 1).unwrap();
        assert_eq!(out, vec![0x7F, 0x7F, 0x7F, 0xFF]);
    }

    #[test]
    fn a_short_buffer_is_an_error_rather_than_a_panic() {
        assert!(to_canvas_order(&[0x00, 0x11], 4, 4, 3).is_err());
    }

    #[test]
    fn scaling_produces_exactly_the_requested_size() {
        for (w, h) in [(1, 1), (7, 3), (1920, 1080), (100, 4000)] {
            let out = checker().scaled_to_cover(w, h);
            assert_eq!(out.len(), (w * h * 4) as usize, "{w}x{h}");
        }
    }

    #[test]
    fn scaling_leaves_every_pixel_opaque() {
        let out = checker().scaled_to_cover(16, 9);
        assert!(out.chunks_exact(4).all(|p| p[3] == 0xFF));
    }

    /// The scrim is the only thing between a bright photograph and unreadable
    /// text, so it has to actually be applied.
    #[test]
    fn the_scrim_darkens_what_it_covers() {
        let white = Image {
            width: 1,
            height: 1,
            pixels: vec![0xFF, 0xFF, 0xFF, 0xFF],
        };
        let out = white.scaled_to_cover(4, 4);
        assert!(
            out[0] < 0xFF,
            "a white wallpaper came back white; the scrim did nothing"
        );
    }

    /// Cover-scaling an image onto a surface of a different aspect ratio must
    /// crop it, not squash it. A 2x2 checker stretched onto a wide surface
    /// keeps its left half red-ish and its right half green-ish; a squashed
    /// one would not.
    #[test]
    fn cover_crops_rather_than_distorting() {
        let out = checker().scaled_to_cover(64, 8);
        let row = 4 * 64 * 4;
        let left = &out[row..row + 4];
        let right = &out[row + 60 * 4..row + 61 * 4];
        assert!(left[2] > left[1], "the left edge should still be red-ish");
        assert!(
            right[1] > right[2],
            "the right edge should still be green-ish"
        );
    }

    #[test]
    fn the_cache_is_reused_and_invalidated_by_a_resize() {
        let mut wallpaper = Wallpaper {
            image: checker(),
            prepared: None,
        };
        assert_eq!(wallpaper.prepared(8, 8).len(), 8 * 8 * 4);
        assert_eq!(wallpaper.prepared(8, 8).len(), 8 * 8 * 4);
        assert_eq!(wallpaper.prepared(16, 4).len(), 16 * 4 * 4);
    }

    #[test]
    fn a_file_that_is_not_an_image_is_refused() {
        assert!(decode(b"this is not a wallpaper").is_err());
        assert!(decode(&[]).is_err());
    }

    /// A truncated PNG has the right magic and nothing else. It must come back
    /// as an error, because the alternative -- a panic -- is a greeter that
    /// dies at boot over a corrupted file.
    #[test]
    fn a_truncated_png_is_an_error_rather_than_a_panic() {
        let mut truncated = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        truncated.extend_from_slice(&[0x00; 16]);
        assert!(decode(&truncated).is_err());
    }

    #[test]
    fn a_truncated_jpeg_is_an_error_rather_than_a_panic() {
        assert!(decode(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]).is_err());
    }

    #[test]
    fn absurd_dimensions_are_refused() {
        assert!(check_dimensions(0, 100).is_err());
        assert!(check_dimensions(100, 0).is_err());
        assert!(check_dimensions(60_000, 60_000).is_err());
        // Small in area, absurd on one side.
        assert!(check_dimensions(100_000, 2).is_err());
        assert!(check_dimensions(1920, 1080).is_ok());
    }
}
