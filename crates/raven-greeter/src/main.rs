//! `raven-greeter` — the RavenLinux login screen.
//!
//! An unprivileged Wayland client. It runs as the `raven-greeter` account, in a
//! compositor `ravend` started for it, and the only privileged thing it can do
//! is ask `ravend` a question over a Unix socket. It cannot read `/etc/shadow`,
//! it cannot start a session, and it cannot become anybody.
//!
//! That is the whole point of the split. This process is the one that parses
//! font files, decodes glyphs and touches a shared memory buffer the compositor
//! also maps — the historically interesting attack surface of a login screen —
//! and none of it happens in the process that holds the password hashes.
//!
//! # Why layer-shell rather than a session lock
//!
//! `ext-session-lock-v1` would be the natural protocol for a screen that must
//! not be dismissed, and it is what `muninn-lock` will use. huginn does not
//! implement it yet, and a greeter does not actually need it: at login time
//! there is nothing behind this surface to protect, because no session exists.
//! An `overlay` layer with exclusive keyboard interactivity is enough, and it
//! needs no change to the compositor.
//!
//! What that does mean is that this surface is not a security boundary the way
//! a lock screen is. It does not have to be: the machine is not unlocked, and
//! `ravend` is the thing enforcing who may log in, not this.

#![forbid(unsafe_code)]

mod canvas;
mod client;
mod preview;
mod text;
mod theme;
mod ui;
mod wallpaper;

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use smithay_client_toolkit::compositor::{CompositorHandler, CompositorState, FrameCallbackData};
use smithay_client_toolkit::output::{OutputHandler, OutputState};
use smithay_client_toolkit::registry::{ProvidesRegistryState, RegistryState};
use smithay_client_toolkit::seat::keyboard::{
    KeyEvent, KeyboardHandler, Keysym, Modifiers, RawModifiers,
};
use smithay_client_toolkit::seat::{Capability, SeatHandler, SeatState};
use smithay_client_toolkit::shell::WaylandSurface;
use smithay_client_toolkit::shell::wlr_layer::{
    Anchor, KeyboardInteractivity, Layer, LayerShell, LayerShellHandler, LayerSurface,
    LayerSurfaceConfigure,
};
use smithay_client_toolkit::shm::slot::SlotPool;
use smithay_client_toolkit::shm::{Shm, ShmHandler};
use smithay_client_toolkit::{delegate_registry, registry_handlers};
// Through sctk's re-export rather than a direct dependency: that guarantees
// this is the exact `wayland-client` sctk was built against. Naming it in
// Cargo.toml separately would let the two resolve to different semver-compatible
// versions, and the protocol objects would then be different types.
use smithay_client_toolkit::reexports::client::globals::registry_queue_init;
use smithay_client_toolkit::reexports::client::protocol::{
    wl_keyboard, wl_output, wl_seat, wl_shm, wl_surface,
};
use smithay_client_toolkit::reexports::client::{Connection, QueueHandle};

use crate::canvas::Canvas;
use crate::client::{Attempt, Client};
use crate::text::TextRenderer;
use crate::ui::{Action, LoginScreen, Message, MessageKind};
use crate::wallpaper::Wallpaper;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("raven-greeter: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    // `--preview` renders one frame to a PNG and exits, without a compositor
    // and without ravend. It is how the login screen is iterated on: the
    // alternative is rebooting a machine to look at a colour.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "--preview") {
        return preview::main(&args[1..]);
    }

    // Connect to the daemon before touching Wayland. If ravend is not there
    // this is not a login screen, and failing here produces a message on the
    // console rather than a blank surface nobody can type into.
    let mut daemon = Client::connect()?;
    let users = daemon.list_users().context("cannot get the user list")?;
    tracing::info!(count = users.len(), "accounts available");

    // Every step of this is allowed to fail without taking the login screen
    // with it -- an unreachable daemon field, a path that is not there, a file
    // that will not decode. The screen falls back to its backdrop and somebody
    // can still log in, which is the only requirement a greeter really has.
    //
    // Two places, in this order: what `login.toml` names, and failing that
    // what the machine has set at /usr/share/wallpaper/set. The configured
    // path wins because somebody wrote it down for this screen specifically;
    // the set one is what the desktop behind the login screen draws, so
    // falling back to it is what makes the two look like one machine.
    let configured = match daemon.wallpaper() {
        Ok(path) => path,
        Err(e) => {
            tracing::warn!("cannot ask ravend about the wallpaper: {e:#}");
            None
        }
    };
    let wallpaper = configured
        .or_else(wallpaper::installed)
        .and_then(|path| match Wallpaper::load(&path) {
            Ok(wallpaper) => Some(wallpaper),
            Err(e) => {
                tracing::warn!("ignoring the wallpaper: {e:#}");
                None
            }
        });

    let conn = Connection::connect_to_env()
        .context("cannot connect to the Wayland display; is WAYLAND_DISPLAY set?")?;
    let (globals, mut queue) =
        registry_queue_init(&conn).context("cannot initialize the Wayland registry")?;
    let qh = queue.handle();

    let compositor =
        CompositorState::bind(&globals, &qh).context("the compositor has no wl_compositor")?;
    let layer_shell = LayerShell::bind(&globals, &qh)
        .context("the compositor does not implement wlr-layer-shell, which this greeter needs")?;
    let shm = Shm::bind(&globals, &qh).context("the compositor has no wl_shm")?;

    let surface = compositor.create_surface(&qh);
    let layer =
        layer_shell.create_layer_surface(&qh, surface, Layer::Overlay, Some("raven-login"), None);

    // Anchored to all four edges with a size of 0x0, which is how layer-shell
    // spells "fill the output": the compositor answers the configure with the
    // output's real dimensions.
    layer.set_anchor(Anchor::TOP | Anchor::BOTTOM | Anchor::LEFT | Anchor::RIGHT);
    layer.set_size(0, 0);
    // Exclusive, not OnDemand: a login screen must have the keyboard without
    // anybody having to click it first, and nothing else should be able to
    // take it away.
    layer.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
    // -1 so nothing reserves space against this surface; it is the whole
    // screen and there is nothing to tile around it.
    layer.set_exclusive_zone(-1);
    layer.commit();

    // Sized for a common panel; the pool grows when the configure says the
    // screen is bigger.
    let pool = SlotPool::new(1920 * 1080 * 4, &shm).context("cannot create an shm pool")?;

    let mut greeter = Greeter {
        registry_state: RegistryState::new(&globals),
        seat_state: SeatState::new(&globals, &qh),
        output_state: OutputState::new(&globals, &qh),
        shm,
        pool,
        layer,
        keyboard: None,
        width: 0,
        height: 0,
        scale: 1.0,
        configured: false,
        exit: false,
        ctrl: false,
        screen: {
            let mut screen = LoginScreen::new(users);
            screen.set_wallpaper(wallpaper);
            screen
        },
        text: TextRenderer::new(),
        daemon,
    };

    while !greeter.exit {
        queue
            .blocking_dispatch(&mut greeter)
            .context("the Wayland connection failed")?;
    }

    tracing::info!("greeter exiting");
    Ok(())
}

struct Greeter {
    registry_state: RegistryState,
    seat_state: SeatState,
    output_state: OutputState,
    shm: Shm,
    pool: SlotPool,
    layer: LayerSurface,
    keyboard: Option<wl_keyboard::WlKeyboard>,

    width: u32,
    height: u32,
    scale: f32,
    configured: bool,
    exit: bool,
    /// Whether Control is held. Tracked because the keysym for Ctrl-U is
    /// simply `u`: without this, typing the letter "u" into a password would
    /// take the Ctrl-U branch and silently clear the field.
    ctrl: bool,

    screen: LoginScreen,
    text: TextRenderer,
    daemon: Client,
}

impl std::fmt::Debug for Greeter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written because most of the Wayland state is not Debug, and
        // because deriving it would be one careless `?self` away from putting
        // the login screen's contents in a log.
        f.debug_struct("Greeter")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("scale", &self.scale)
            .field("configured", &self.configured)
            .finish_non_exhaustive()
    }
}

impl Greeter {
    /// Render one frame and request the next.
    fn draw(&mut self, qh: &QueueHandle<Self>) {
        if self.width == 0 || self.height == 0 {
            return;
        }
        let (width, height) = (self.width as i32, self.height as i32);
        let stride = width * 4;

        let (buffer, data) =
            match self
                .pool
                .create_buffer(width, height, stride, wl_shm::Format::Argb8888)
            {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!("cannot create a buffer: {e}");
                    return;
                }
            };

        {
            // `create_buffer` can hand back a slice longer than the frame when
            // it reuses a slot from the pool. Trimming it keeps `Canvas`'s
            // size invariant true rather than tripping its debug assertion.
            let frame = &mut data[..(width * height * 4) as usize];
            let mut canvas = Canvas::new(frame, width, height);
            self.screen
                .draw(&mut canvas, &mut self.text, self.scale, Instant::now());
        }

        let surface = self.layer.wl_surface();
        surface.damage_buffer(0, 0, width, height);
        // Ask for another frame unconditionally: the caret blinks and the clock
        // ticks, so this surface is never truly static. The compositor paces
        // this to the refresh rate, so it costs one memset-sized redraw per
        // frame and nothing else.
        surface.frame(qh, FrameCallbackData(surface.clone()));
        if let Err(e) = buffer.attach_to(surface) {
            tracing::error!("cannot attach the buffer: {e}");
            return;
        }
        self.layer.commit();
    }

    /// Send an attempt to the daemon and act on the reply.
    fn submit(&mut self, username: &str, password: String) {
        match self.daemon.authenticate(username, password) {
            Ok(Attempt::Granted) => {
                // The daemon is starting the session and is about to stop this
                // process. Say so, and keep the screen busy so nothing else can
                // be typed into it in the meantime.
                tracing::info!(user = %username, "granted");
                self.screen.set_message(Some(Message {
                    text: "Welcome back.".to_string(),
                    kind: MessageKind::Success,
                }));
            }
            Ok(Attempt::Denied {
                message,
                retry_after,
            }) => {
                self.screen.throttle_until(retry_after);
                self.screen.set_message(Some(Message {
                    text: message,
                    kind: MessageKind::Error,
                }));
                self.screen.set_idle();
            }
            Ok(Attempt::Failed { message }) => {
                self.screen.set_message(Some(Message {
                    text: message,
                    kind: MessageKind::Error,
                }));
                self.screen.set_idle();
            }
            Err(e) => {
                // The socket broke. There is no way to log in from here and no
                // way to recover, so say something true and stay up rather than
                // exiting into a black screen.
                tracing::error!("cannot reach ravend: {e:#}");
                self.screen.set_message(Some(Message {
                    text: "Lost contact with the login service.".to_string(),
                    kind: MessageKind::Error,
                }));
                self.screen.set_idle();
            }
        }
    }
}

impl CompositorHandler for Greeter {
    fn scale_factor_changed(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        new_factor: i32,
    ) {
        // Integer scale only, which is what wl_surface.set_buffer_scale
        // supports. Fractional scaling would need wp-fractional-scale-v1, and
        // a login screen a few percent off the ideal size is not worth another
        // protocol on the boot path.
        self.scale = new_factor.max(1) as f32;
        self.layer.wl_surface().set_buffer_scale(new_factor.max(1));
        self.draw(qh);
    }

    fn transform_changed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: wl_output::Transform,
    ) {
    }

    fn frame(&mut self, _: &Connection, qh: &QueueHandle<Self>, _: &wl_surface::WlSurface, _: u32) {
        self.draw(qh);
    }

    fn surface_enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: &wl_output::WlOutput,
    ) {
    }

    fn surface_leave(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: &wl_output::WlOutput,
    ) {
    }
}

impl LayerShellHandler for Greeter {
    fn closed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &LayerSurface) {
        self.exit = true;
    }

    fn configure(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        _: &LayerSurface,
        configure: LayerSurfaceConfigure,
        _: u32,
    ) {
        // A compositor is allowed to answer 0 for a dimension it has no opinion
        // about. Falling back to something drawable is better than a zero-sized
        // buffer, which is a protocol error.
        let (w, h) = configure.new_size;
        self.width = if w == 0 { 1920 } else { w };
        self.height = if h == 0 { 1080 } else { h };

        if !self.configured {
            self.configured = true;
            tracing::info!(width = self.width, height = self.height, "configured");
        }
        self.draw(qh);
    }
}

impl KeyboardHandler for Greeter {
    fn enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: &wl_surface::WlSurface,
        _: u32,
        _: &[u32],
        _: &[Keysym],
    ) {
    }

    fn leave(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: &wl_surface::WlSurface,
        _: u32,
    ) {
    }

    fn press_key(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        event: KeyEvent,
    ) {
        self.handle_key(&event, qh);
    }

    /// Held keys repeat. Backspace especially — holding it should empty the
    /// field, not delete one character.
    fn repeat_key(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        event: KeyEvent,
    ) {
        self.handle_key(&event, qh);
    }

    fn release_key(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        _: KeyEvent,
    ) {
    }

    fn update_modifiers(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        modifiers: Modifiers,
        _: RawModifiers,
        _: u32,
    ) {
        // Caps Lock is the one modifier worth showing. Somebody typing a
        // password they cannot see, into a field that shows dots, has no other
        // way to find out why it keeps being refused.
        self.screen.set_caps_lock(modifiers.caps_lock);
        self.ctrl = modifiers.ctrl;
    }
}

impl Greeter {
    fn handle_key(&mut self, event: &KeyEvent, qh: &QueueHandle<Self>) {
        // While an attempt is in flight the screen takes nothing at all.
        // `push_char` and `backspace` already refuse, but the navigation keys
        // are the ones that matter here: switching account mid-attempt would
        // leave the screen showing one person while the daemon answers about
        // another, and the reply would land on the wrong name.
        if self.screen.is_busy() {
            return;
        }

        match interpret(event.keysym, self.ctrl, event.utf8.as_deref()) {
            Key::Submit => {
                if let Action::Submit { username, password } = self.screen.submit(Instant::now()) {
                    // Draw the busy state before blocking on the socket, so the
                    // screen acknowledges the keypress rather than appearing to
                    // freeze for the duration of the check.
                    self.draw(qh);
                    self.submit(&username, password);
                }
            }
            Key::Backspace => self.screen.backspace(),
            Key::Clear => {
                self.screen.clear_password();
                self.screen.set_message(None);
            }
            Key::NextUser => self.screen.next_user(),
            Key::PreviousUser => self.screen.previous_user(),
            Key::Text(text) => {
                for c in text.chars() {
                    self.screen.push_char(c);
                }
            }
            Key::Ignored => {}
        }
        self.draw(qh);
    }
}

/// What a key means to the login screen.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    Submit,
    Backspace,
    /// Empty the field: Escape, or Ctrl-U.
    Clear,
    NextUser,
    PreviousUser,
    /// Characters to type into the password.
    Text(String),
    Ignored,
}

/// Turn a keysym plus the modifier state into what it means.
///
/// Pulled out of the handler as a pure function so it can be tested, because
/// the bug it exists to prevent is invisible by inspection and silent in use:
/// the keysym delivered for Ctrl-U is plain `u`, so a branch matching `u`
/// *without* checking Control clears the password every time somebody types
/// the letter u. Nothing about that shows up until a person whose password
/// contains a "u" cannot log in.
fn interpret(keysym: Keysym, ctrl: bool, utf8: Option<&str>) -> Key {
    match keysym {
        Keysym::Return | Keysym::KP_Enter => Key::Submit,
        Keysym::BackSpace => Key::Backspace,
        Keysym::Escape => Key::Clear,
        // Ctrl-U clears the line, as it does in a shell and at a getty.
        Keysym::u | Keysym::U if ctrl => Key::Clear,
        Keysym::Tab | Keysym::Down | Keysym::Right => Key::NextUser,
        Keysym::ISO_Left_Tab | Keysym::Up | Keysym::Left => Key::PreviousUser,
        _ => match utf8 {
            // A chord that produced no text -- Ctrl-C, a bare modifier -- is
            // not something to type. Without this, every unhandled Control
            // combination would fall through as characters.
            _ if ctrl => Key::Ignored,
            Some(text) if !text.is_empty() => Key::Text(text.to_string()),
            _ => Key::Ignored,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_submits() {
        assert_eq!(interpret(Keysym::Return, false, Some("\r")), Key::Submit);
        assert_eq!(interpret(Keysym::KP_Enter, false, None), Key::Submit);
    }

    /// The regression this function exists for. `u` is a letter; Ctrl-U is a
    /// command; they arrive as the same keysym.
    #[test]
    fn a_plain_u_is_typed_and_ctrl_u_clears() {
        assert_eq!(
            interpret(Keysym::u, false, Some("u")),
            Key::Text("u".to_string()),
            "typing the letter u must not clear the password"
        );
        assert_eq!(interpret(Keysym::u, true, Some("u")), Key::Clear);
        assert_eq!(interpret(Keysym::U, true, Some("U")), Key::Clear);
        // ...and an uppercase U with no Control is still just a letter.
        assert_eq!(
            interpret(Keysym::U, false, Some("U")),
            Key::Text("U".to_string())
        );
    }

    #[test]
    fn escape_clears() {
        assert_eq!(interpret(Keysym::Escape, false, None), Key::Clear);
    }

    #[test]
    fn navigation_moves_between_accounts() {
        assert_eq!(interpret(Keysym::Tab, false, None), Key::NextUser);
        assert_eq!(interpret(Keysym::Down, false, None), Key::NextUser);
        assert_eq!(
            interpret(Keysym::ISO_Left_Tab, false, None),
            Key::PreviousUser
        );
        assert_eq!(interpret(Keysym::Up, false, None), Key::PreviousUser);
    }

    #[test]
    fn ordinary_characters_are_typed() {
        assert_eq!(
            interpret(Keysym::a, false, Some("a")),
            Key::Text("a".to_string())
        );
        // Non-ASCII, from a dead key or a compose sequence.
        assert_eq!(
            interpret(Keysym::adiaeresis, false, Some("ä")),
            Key::Text("ä".to_string())
        );
    }

    /// A Control chord that is not one we handle must be dropped, not typed.
    /// Ctrl-C used to arrive as "\u{3}" and would have gone into the password.
    #[test]
    fn unhandled_control_chords_are_ignored() {
        assert_eq!(interpret(Keysym::c, true, Some("\u{3}")), Key::Ignored);
        assert_eq!(interpret(Keysym::a, true, Some("\u{1}")), Key::Ignored);
    }

    #[test]
    fn keys_with_no_text_are_ignored() {
        assert_eq!(interpret(Keysym::Shift_L, false, None), Key::Ignored);
        assert_eq!(interpret(Keysym::F1, false, None), Key::Ignored);
        assert_eq!(interpret(Keysym::a, false, Some("")), Key::Ignored);
    }
}

impl SeatHandler for Greeter {
    fn seat_state(&mut self) -> &mut SeatState {
        &mut self.seat_state
    }

    fn new_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat) {}

    fn new_capability(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        seat: wl_seat::WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard && self.keyboard.is_none() {
            match self.seat_state.get_keyboard(qh, &seat, None) {
                Ok(keyboard) => self.keyboard = Some(keyboard),
                // Without a keyboard nobody can type a password. Log it loudly;
                // there is nothing this process can do to fix it.
                Err(e) => tracing::error!("cannot get the keyboard: {e}"),
            }
        }
    }

    fn remove_capability(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: wl_seat::WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard
            && let Some(keyboard) = self.keyboard.take()
        {
            keyboard.release();
        }
    }

    fn remove_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat) {}
}

impl OutputHandler for Greeter {
    fn output_state(&mut self) -> &mut OutputState {
        &mut self.output_state
    }

    fn new_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
    fn update_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
    fn output_destroyed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
}

impl ShmHandler for Greeter {
    fn shm_state(&mut self) -> &mut Shm {
        &mut self.shm
    }
}

delegate_registry!(Greeter);

impl ProvidesRegistryState for Greeter {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry_state
    }
    registry_handlers![OutputState, SeatState];
}

smithay_client_toolkit::delegate_dispatch2!(Greeter);

/// Unused, but it keeps `Duration` imported for the throttle types that cross
/// from `client` into `ui`.
const _: Option<Duration> = None;
