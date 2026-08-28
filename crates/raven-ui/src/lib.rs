//! What the login screen and the lock screen both draw with.
//!
//! Extracted from `raven-greeter` when `raven-lock` was built, because the two
//! screens are the same screen. A person looking at either one is being asked
//! for the password to this machine, and the only honest way to make those two
//! moments look identical is to make them the same code — a lock screen that is
//! a near-miss of the login screen teaches its owner to accept near-misses.
//!
//! Nothing here talks to Wayland, and nothing here talks to a socket. It takes
//! a buffer and draws into it, which is why [`screen`]'s state machine can be
//! tested without either.
//!
//! | Module | What it is |
//! |---|---|
//! | [`canvas`] | An ARGB buffer, and the shapes that go into it |
//! | [`text`] | Glyph rasterisation and layout, over `cosmic-text` |
//! | [`theme`] | Every colour and metric, in one place |
//! | [`wallpaper`] | Decoding and scaling the image behind it all |
//! | [`screen`] | The password screen itself: state, keys, and drawing |

pub mod canvas;
pub mod screen;
pub mod text;
pub mod theme;
pub mod wallpaper;
