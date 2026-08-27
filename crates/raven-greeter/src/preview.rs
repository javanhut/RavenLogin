//! `raven-greeter --preview OUT.png [WIDTHxHEIGHT] [STATE] [--wallpaper PATH]`
//! — render one frame to a file and exit.
//!
//! `OUT.png` is written, not read. It is the first argument because the flag
//! is `--preview <where to put it>`, and a wallpaper to render *behind* the
//! screen is a named `--wallpaper` rather than a fifth positional so that the
//! two paths cannot be confused for one another.
//!
//! The login screen is the one part of this system that cannot be judged by
//! reading it, and the ordinary way to look at it is to reboot a machine into
//! it. That is a slow enough loop that the design stops being iterated on, so
//! this renders exactly what the greeter would draw — the same [`LoginScreen`],
//! the same canvas, the same font — into a PNG, on any host, in a few hundred
//! milliseconds.
//!
//! It is not a test double. It calls the same `draw` the compositor drives, so
//! a change that breaks the layout breaks the preview in the same way.
//!
//! # The encoder
//!
//! PNG, written here rather than pulled in, because the alternative is a
//! dependency on an image crate in the login path to serve a development flag.
//! The deflate stream uses *stored* (uncompressed) blocks, which is legal
//! zlib and about forty lines instead of a compressor — the output is a few
//! megabytes and is going to be looked at once and deleted.

use std::path::Path;

use anyhow::{Context, Result};

use crate::canvas::Canvas;
use crate::text::TextRenderer;
use crate::ui::{LoginScreen, Message, MessageKind};
use crate::wallpaper::Wallpaper;
use raven_greet_proto::User;

/// Parse `--preview`'s arguments and render.
///
/// `args` is everything after the flag itself.
pub(crate) fn main(args: &[String]) -> Result<()> {
    let mut positional = Vec::new();
    let mut wallpaper: Option<&str> = None;

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--wallpaper" => {
                let path = rest
                    .next()
                    .context("--wallpaper needs the path to an image")?;
                wallpaper = Some(path);
            }
            other if other.starts_with("--") => anyhow::bail!("unknown option {other}"),
            other => positional.push(other),
        }
    }

    let path = positional
        .first()
        .context("--preview needs a file to write to")?;
    let (width, height) = positional
        .get(1)
        .map_or(Some((1920, 1080)), |s| parse_size(s))
        .context("the size should look like 1920x1080")?;
    let state = positional
        .get(2)
        .map_or(Some(State::Empty), |s| State::parse(s))
        .context("the state should be one of: empty, typing, denied, caps")?;
    if let Some(extra) = positional.get(3) {
        anyhow::bail!("unexpected argument {extra}");
    }

    // Unlike at login, a wallpaper that will not load here is a hard error.
    // The greeter falls back silently because somebody has to be able to log
    // in; a developer who asked to see an image and got the plain backdrop
    // instead is owed the reason.
    let wallpaper = wallpaper
        .map(|p| Wallpaper::load(Path::new(p)))
        .transpose()?;

    let path = Path::new(path);
    render(path, width, height, state, wallpaper)?;
    tracing::info!(path = %path.display(), width, height, ?state, "preview written");
    Ok(())
}

/// Render one frame and write it to `path`.
pub(crate) fn render(
    path: &Path,
    width: i32,
    height: i32,
    state: State,
    wallpaper: Option<Wallpaper>,
) -> Result<()> {
    let mut text = TextRenderer::new();

    // Stand-in accounts, so a preview on a build host looks like a preview on
    // a real machine rather than an empty screen.
    let mut screen = LoginScreen::new(vec![
        User {
            name: "javan".to_string(),
            display_name: "Javan Hutchinson".to_string(),
            initial: 'J',
        },
        User {
            name: "second".to_string(),
            display_name: "Second Account".to_string(),
            initial: 'S',
        },
    ]);

    screen.set_wallpaper(wallpaper);

    match state {
        State::Empty => {}
        State::Typing => {
            for c in "hunter2".chars() {
                screen.push_char(c);
            }
        }
        State::Denied => {
            screen.set_message(Some(Message {
                text: "Incorrect password.".to_string(),
                kind: MessageKind::Error,
            }));
        }
        State::CapsLock => screen.set_caps_lock(true),
    }

    let mut data = vec![0u8; (width * height * 4) as usize];
    {
        let mut canvas = Canvas::new(&mut data, width, height);
        screen.draw(&mut canvas, &mut text, 1.0, std::time::Instant::now());
    }

    let png = encode_png(&data, width as u32, height as u32);
    std::fs::write(path, png).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Which of the screen's states to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Empty,
    Typing,
    Denied,
    CapsLock,
}

impl State {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "empty" => Some(Self::Empty),
            "typing" => Some(Self::Typing),
            "denied" => Some(Self::Denied),
            "caps" => Some(Self::CapsLock),
            _ => None,
        }
    }
}

/// `WIDTHxHEIGHT`.
pub(crate) fn parse_size(s: &str) -> Option<(i32, i32)> {
    let (w, h) = s.split_once(['x', 'X'])?;
    let (w, h) = (w.trim().parse().ok()?, h.trim().parse().ok()?);
    (w > 0 && h > 0).then_some((w, h))
}

// ---------------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------------

/// Encode a canvas buffer as an RGBA PNG.
///
/// The canvas holds little-endian ARGB, so the bytes are `[B, G, R, A]`; PNG
/// wants `[R, G, B, A]`. That swap is the only pixel work here.
fn encode_png(canvas: &[u8], width: u32, height: u32) -> Vec<u8> {
    // Scanlines, each prefixed with filter type 0 ("None"). Filtering exists to
    // help compression, and this does not compress.
    let mut raw = Vec::with_capacity((height * (1 + width * 4)) as usize);
    for y in 0..height {
        raw.push(0);
        for x in 0..width {
            let i = ((y * width + x) * 4) as usize;
            raw.extend_from_slice(&[canvas[i + 2], canvas[i + 1], canvas[i], canvas[i + 3]]);
        }
    }

    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8 bits, RGBA, deflate, no filter, no interlace
    write_chunk(&mut png, b"IHDR", &ihdr);
    write_chunk(&mut png, b"IDAT", &zlib_stored(&raw));
    write_chunk(&mut png, b"IEND", &[]);
    png
}

fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(body);

    let mut crc = Crc32::new();
    crc.update(kind);
    crc.update(body);
    out.extend_from_slice(&crc.finish().to_be_bytes());
}

/// A zlib stream made entirely of stored (uncompressed) deflate blocks.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    // 0x78 0x01: deflate, 32K window, no preset dictionary, fastest level.
    // The two bytes together must be a multiple of 31, and 0x7801 is.
    let mut out = vec![0x78, 0x01];

    // A stored block's length field is 16 bits, so anything longer is split.
    let mut chunks = data.chunks(0xFFFF).peekable();
    if data.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
    }
    while let Some(chunk) = chunks.next() {
        let final_block = u8::from(chunks.peek().is_none());
        let len = chunk.len() as u16;
        out.push(final_block); // BFINAL, BTYPE=00 (stored)
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes()); // one's complement
        out.extend_from_slice(chunk);
    }

    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// The CRC-32 PNG specifies, table-free.
struct Crc32(u32);

impl Crc32 {
    fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.0 ^= u32::from(byte);
            for _ in 0..8 {
                // The reflected polynomial, 0xEDB88320.
                self.0 = if self.0 & 1 != 0 {
                    (self.0 >> 1) ^ 0xEDB8_8320
                } else {
                    self.0 >> 1
                };
            }
        }
    }

    fn finish(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("1920x1080"), Some((1920, 1080)));
        assert_eq!(parse_size("800X600"), Some((800, 600)));
        assert_eq!(parse_size("nonsense"), None);
        assert_eq!(parse_size("0x100"), None);
        assert_eq!(parse_size("-4x10"), None);
    }

    #[test]
    fn states_parse() {
        assert_eq!(State::parse("denied"), Some(State::Denied));
        assert_eq!(State::parse("caps"), Some(State::CapsLock));
        assert_eq!(State::parse("nope"), None);
    }

    /// The published CRC-32 check value: `"123456789"` is `0xCBF43926`.
    #[test]
    fn crc32_matches_the_known_answer() {
        let mut crc = Crc32::new();
        crc.update(b"123456789");
        assert_eq!(crc.finish(), 0xCBF4_3926);
    }

    /// Adler-32 of `"123456789"` is `0x091E01DE`.
    #[test]
    fn adler32_matches_the_known_answer() {
        assert_eq!(adler32(b"123456789"), 0x091E_01DE);
    }

    /// A stored deflate block's NLEN must be the one's complement of LEN, or
    /// every decoder rejects the stream.
    #[test]
    fn stored_blocks_are_well_formed() {
        let stream = zlib_stored(&[0xAB; 10]);
        assert_eq!(&stream[..2], &[0x78, 0x01]);
        assert_eq!(stream[2], 0x01, "the only block should be final");
        let len = u16::from_le_bytes([stream[3], stream[4]]);
        let nlen = u16::from_le_bytes([stream[5], stream[6]]);
        assert_eq!(len, 10);
        assert_eq!(nlen, !len);
    }

    /// Data larger than one stored block must be split, and only the last
    /// block may be marked final.
    #[test]
    fn long_data_is_split_across_blocks() {
        let stream = zlib_stored(&vec![0u8; 0x1_0000]);
        assert_eq!(stream[2], 0x00, "the first of two blocks is not final");
    }

    #[test]
    fn a_png_has_the_right_signature_and_chunks() {
        let pixels = vec![0u8; 4 * 4 * 4];
        let png = encode_png(&pixels, 4, 4);
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_eq!(&png[12..16], b"IHDR");
        assert!(png.windows(4).any(|w| w == b"IDAT"));
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
    }
}
