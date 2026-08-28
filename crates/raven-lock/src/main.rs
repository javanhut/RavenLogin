//! `raven-lock` — the RavenLinux lock screen.
//!
//! Run it and the session is held: the desktop is replaced by the same screen
//! that asks for a password at login, and nothing but the right password gets
//! past it.
//!
//! # Why this is a session-lock client and the greeter is not
//!
//! `raven-greeter` draws its screen as a `wlr-layer-shell` overlay, and that is
//! the right choice there: at login there is nothing behind the surface, so a
//! greeter that crashes reveals an empty compositor and `ravend` restarts it.
//!
//! Here there is a whole session behind the surface. `ext-session-lock-v1`
//! exists for exactly this difference: once the compositor has confirmed the
//! lock, the session stays hidden *even if this process dies*. A crash, a
//! `kill -9`, an OOM — none of them reveal the desktop; the screen stays blank
//! and locked until something authenticates. That guarantee is the whole
//! reason this is a separate binary from anything else in the session, and it
//! is why the failure paths below stay up and complain rather than exiting.
//!
//! # What it can and cannot do
//!
//! It draws, it reads a keyboard, and it can ask one question over a socket:
//! *is this the password of the account that owns this connection?* It cannot
//! name an account, cannot start a session, and never sees a password hash.
//! `ravend` answers from the connection's credentials; see `raven-lock`'s
//! `client` module and the daemon's `verify`.

mod client;

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use raven_ui::canvas::Canvas;
use raven_ui::screen::{Action, Message, MessageKind, PasswordScreen};
use raven_ui::text::TextRenderer;
use raven_ui::wallpaper::{self, Wallpaper};
use smithay_client_toolkit::compositor::{CompositorHandler, CompositorState, FrameCallbackData};
use smithay_client_toolkit::output::{OutputHandler, OutputState};
use smithay_client_toolkit::reexports::client::globals::registry_queue_init;
use smithay_client_toolkit::reexports::client::protocol::{
    wl_keyboard, wl_output, wl_seat, wl_shm, wl_surface,
};
use smithay_client_toolkit::reexports::client::{Connection, QueueHandle};
use smithay_client_toolkit::registry::{ProvidesRegistryState, RegistryState};
use smithay_client_toolkit::seat::keyboard::{
    KeyEvent, KeyboardHandler, Keysym, Modifiers, RawModifiers,
};
use smithay_client_toolkit::seat::{Capability, SeatHandler, SeatState};
use smithay_client_toolkit::session_lock::{
    SessionLock, SessionLockHandler, SessionLockState, SessionLockSurface,
    SessionLockSurfaceConfigure,
};
use smithay_client_toolkit::shm::slot::SlotPool;
use smithay_client_toolkit::shm::{Shm, ShmHandler};
use smithay_client_toolkit::{delegate_registry, registry_handlers};

use crate::client::{Attempt, Client};

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().init();

    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    // The socket first, before a single Wayland object exists. If the daemon
    // cannot be reached there is no password anybody could type that would get
    // them out again, and a lock screen that can never be unlocked is worse
    // than no lock screen at all -- it is a machine that has to be power-cycled.
    let mut daemon = Client::connect()?;
    let user = daemon
        .whoami()
        .context("ravend will not say whose session this is")?;
    tracing::info!(user = %user.name, "locking");

    // The same picture the desktop is drawing. Read straight from where the
    // machine keeps it rather than asked for over the socket: the verify socket
    // deliberately answers nothing but the one question, and this is a fixed
    // path being read by an unprivileged process that can read it anyway.
    let wallpaper = wallpaper::installed().and_then(|path| match Wallpaper::load(&path) {
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
    let shm = Shm::bind(&globals, &qh).context("the compositor has no wl_shm")?;
    let session_lock_state = SessionLockState::new(&globals, &qh);

    // The request that matters. Everything after this is drawing; the session
    // is hidden from the moment the compositor answers `locked`, whether or not
    // this process ever manages to put a pixel on the screen.
    let lock = session_lock_state.lock(&qh).context(
        "the compositor does not implement ext-session-lock-v1, so this session cannot be \
         locked. huginn supports it; an older one does not",
    )?;

    let pool = SlotPool::new(1920 * 1080 * 4, &shm).context("cannot create an shm pool")?;

    let mut state = Lock {
        registry_state: RegistryState::new(&globals),
        seat_state: SeatState::new(&globals, &qh),
        output_state: OutputState::new(&globals, &qh),
        compositor,
        shm,
        pool,
        lock: Some(lock),
        locked: false,
        surfaces: Vec::new(),
        keyboard: None,
        ctrl: false,
        exit: false,
        screen: {
            let mut screen = PasswordScreen::locked(user);
            screen.set_wallpaper(wallpaper);
            screen
        },
        text: TextRenderer::new(),
        daemon,
    };

    while !state.exit {
        queue
            .blocking_dispatch(&mut state)
            .context("the Wayland connection failed")?;
    }

    // The unlock request has been sent but not necessarily flushed. Without
    // this the process can exit with it still sitting in the outgoing buffer,
    // and the compositor -- which is required to keep the session hidden if the
    // client goes away without unlocking -- would do exactly that.
    conn.roundtrip()
        .context("cannot flush the unlock to the compositor")?;

    tracing::info!("unlocked");
    Ok(())
}

/// One output's share of the lock.
///
/// `ext-session-lock-v1` requires a surface per output, and requires them
/// before the compositor will consider the screen covered. A monitor plugged in
/// while the screen is locked gets one too — otherwise it would come up showing
/// whatever the compositor puts behind an output with no lock surface.
struct Output {
    output: wl_output::WlOutput,
    surface: SessionLockSurface,
    width: u32,
    height: u32,
    scale: f32,
}

struct Lock {
    registry_state: RegistryState,
    seat_state: SeatState,
    output_state: OutputState,
    compositor: CompositorState,
    shm: Shm,
    pool: SlotPool,

    /// `None` only after unlocking, which is also when `exit` goes true.
    lock: Option<SessionLock>,
    /// The compositor has confirmed the session is hidden.
    locked: bool,
    surfaces: Vec<Output>,
    keyboard: Option<wl_keyboard::WlKeyboard>,
    /// Whether Control is held; see the greeter for the Ctrl-U trap this avoids.
    ctrl: bool,
    exit: bool,

    screen: PasswordScreen,
    text: TextRenderer,
    daemon: Client,
}

impl std::fmt::Debug for Lock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written, like the greeter's: most of the Wayland state is not
        // Debug, and deriving it would be one careless `?self` away from
        // putting the contents of the password field in a log.
        f.debug_struct("Lock")
            .field("locked", &self.locked)
            .field("outputs", &self.surfaces.len())
            .field("exit", &self.exit)
            .finish_non_exhaustive()
    }
}

impl Lock {
    /// Draw one output.
    fn draw(&mut self, index: usize, qh: &QueueHandle<Self>) {
        let Some(output) = self.surfaces.get(index) else {
            return;
        };
        if output.width == 0 || output.height == 0 {
            return;
        }

        let (width, height, scale) = (output.width as i32, output.height as i32, output.scale);
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
            // it reuses a slot from the pool; trimming keeps `Canvas`'s size
            // invariant true.
            let frame = &mut data[..(width * height * 4) as usize];
            let mut canvas = Canvas::new(frame, width, height);
            self.screen
                .draw(&mut canvas, &mut self.text, scale, Instant::now());
        }

        let surface = self.surfaces[index].surface.wl_surface().clone();
        surface.damage_buffer(0, 0, width, height);
        // Unconditionally ask for another frame: the caret blinks and the clock
        // ticks, so this surface is never static. The compositor paces it.
        surface.frame(qh, FrameCallbackData(surface.clone()));
        if let Err(e) = buffer.attach_to(&surface) {
            tracing::error!("cannot attach the buffer: {e}");
            return;
        }
        surface.commit();
    }

    /// Draw every output. Used when the screen's contents changed rather than
    /// when one surface asked for a frame.
    fn draw_all(&mut self, qh: &QueueHandle<Self>) {
        for index in 0..self.surfaces.len() {
            self.draw(index, qh);
        }
    }

    fn index_of(&self, surface: &wl_surface::WlSurface) -> Option<usize> {
        self.surfaces
            .iter()
            .position(|o| o.surface.wl_surface() == surface)
    }

    /// Give an output that has none a lock surface.
    fn cover(&mut self, output: wl_output::WlOutput, qh: &QueueHandle<Self>) {
        let Some(lock) = self.lock.clone() else {
            return;
        };
        if self.surfaces.iter().any(|o| o.output == output) {
            return;
        }

        let surface = self.compositor.create_surface(qh);
        let surface = lock.create_lock_surface(surface, &output, qh);
        self.surfaces.push(Output {
            output,
            surface,
            // Zero until the compositor configures it. Nothing is drawn before
            // then, because a zero-sized buffer is a protocol error.
            width: 0,
            height: 0,
            scale: 1.0,
        });
    }

    /// Check a password and act on the answer.
    fn submit(&mut self, password: String, qh: &QueueHandle<Self>) {
        match self.daemon.verify(password) {
            Ok(Attempt::Verified) => {
                tracing::info!("password accepted");
                // Order matters. `unlock` is what tells the compositor it may
                // reveal the session; until it is called, dropping this process
                // leaves the screen locked, which is the behaviour we want on
                // every other path out of here.
                if let Some(lock) = self.lock.take() {
                    lock.unlock();
                }
                self.exit = true;
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
                self.draw_all(qh);
            }
            Ok(Attempt::Failed { message }) => {
                self.screen.set_message(Some(Message {
                    text: message,
                    kind: MessageKind::Error,
                }));
                self.screen.set_idle();
                self.draw_all(qh);
            }
            Err(e) => {
                // The socket broke while the screen is up. This is the one
                // failure with no good answer: nobody can get in until the
                // daemon comes back. Staying locked and saying so is still the
                // right side to fail on -- exiting here would hand the session
                // to whoever is standing at the machine.
                tracing::error!("cannot reach ravend: {e:#}");
                self.screen.set_message(Some(Message {
                    text: "Lost contact with the login service.".to_string(),
                    kind: MessageKind::Error,
                }));
                self.screen.set_idle();
                self.draw_all(qh);
            }
        }
    }

    fn handle_key(&mut self, event: &KeyEvent, qh: &QueueHandle<Self>) {
        if self.screen.is_busy() {
            return;
        }

        match interpret(event.keysym, self.ctrl, event.utf8.as_deref()) {
            Key::Submit => {
                if let Action::Submit { password, .. } = self.screen.submit(Instant::now()) {
                    // Draw the busy state before blocking on the socket, so the
                    // screen acknowledges the keypress rather than appearing to
                    // freeze for the length of the check.
                    self.draw_all(qh);
                    self.submit(password, qh);
                }
            }
            Key::Backspace => self.screen.backspace(),
            Key::Clear => {
                self.screen.clear_password();
                self.screen.set_message(None);
            }
            Key::Text(text) => {
                for c in text.chars() {
                    self.screen.push_char(c);
                }
            }
            Key::Ignored => {}
        }
        self.draw_all(qh);
    }
}

/// What a key means to the lock screen.
///
/// Shorter than the greeter's by exactly one thing: there is no next or
/// previous account. The session belongs to one person and Tab has nowhere to
/// go, so it is a character like any other.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    Submit,
    Backspace,
    /// Empty the field: Escape, or Ctrl-U.
    Clear,
    Text(String),
    Ignored,
}

/// Turn a keysym plus the modifier state into what it means.
///
/// A pure function for the same reason the greeter's is: the keysym delivered
/// for Ctrl-U is plain `u`, so a branch matching `u` without checking Control
/// clears the field every time somebody types the letter u — and nobody whose
/// password contains a "u" could ever unlock the machine.
fn interpret(keysym: Keysym, ctrl: bool, utf8: Option<&str>) -> Key {
    match keysym {
        Keysym::Return | Keysym::KP_Enter => Key::Submit,
        Keysym::BackSpace => Key::Backspace,
        Keysym::Escape => Key::Clear,
        Keysym::u | Keysym::U if ctrl => Key::Clear,
        // Dropped rather than typed. On the greeter these move between
        // accounts; here there is no other account, and a tab is not something
        // anybody meant to put in a password. `push_char` would discard the
        // control character anyway -- saying so here is what makes that a
        // decision rather than an accident of the filter downstream.
        Keysym::Tab | Keysym::ISO_Left_Tab => Key::Ignored,
        _ => match utf8 {
            _ if ctrl => Key::Ignored,
            Some(text) if !text.is_empty() => Key::Text(text.to_string()),
            _ => Key::Ignored,
        },
    }
}

impl SessionLockHandler for Lock {
    fn locked(&mut self, _: &Connection, qh: &QueueHandle<Self>, _: SessionLock) {
        // The compositor has hidden the session. Only now is it safe to say
        // the machine is locked, and only now do the surfaces get created.
        self.locked = true;
        tracing::info!("the compositor has locked the session");

        let outputs: Vec<_> = self.output_state.outputs().collect();
        for output in outputs {
            self.cover(output, qh);
        }
    }

    fn finished(&mut self, _: &Connection, _: &QueueHandle<Self>, _: SessionLock) {
        // The compositor refused, or took the lock away. It never hid the
        // session, so there is nothing being held and nothing to protect by
        // staying up: exiting is honest, and leaves the desktop as it was.
        tracing::error!("the compositor would not lock the session");
        self.lock = None;
        self.exit = true;
    }

    fn configure(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        surface: SessionLockSurface,
        configure: SessionLockSurfaceConfigure,
        _: u32,
    ) {
        let Some(index) = self.index_of(surface.wl_surface()) else {
            return;
        };

        // A compositor may answer 0 for a dimension it has no opinion about.
        // Something drawable beats a zero-sized buffer, which is a protocol
        // error and would take the lock screen down.
        let (w, h) = configure.new_size;
        self.surfaces[index].width = if w == 0 { 1920 } else { w };
        self.surfaces[index].height = if h == 0 { 1080 } else { h };
        self.draw(index, qh);
    }
}

impl CompositorHandler for Lock {
    fn scale_factor_changed(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        surface: &wl_surface::WlSurface,
        new_factor: i32,
    ) {
        let Some(index) = self.index_of(surface) else {
            return;
        };
        let factor = new_factor.max(1);
        self.surfaces[index].scale = factor as f32;
        surface.set_buffer_scale(factor);
        self.draw(index, qh);
    }

    fn transform_changed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: wl_output::Transform,
    ) {
    }

    fn frame(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        surface: &wl_surface::WlSurface,
        _: u32,
    ) {
        if let Some(index) = self.index_of(surface) {
            self.draw(index, qh);
        }
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

impl KeyboardHandler for Lock {
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

    /// Held keys repeat; holding Backspace should empty the field.
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
        self.screen.set_caps_lock(modifiers.caps_lock);
        self.ctrl = modifiers.ctrl;
    }
}

impl SeatHandler for Lock {
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
                // Without a keyboard nobody can type a password, and the screen
                // stays locked. Loud, because there is nothing to be done here.
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

impl OutputHandler for Lock {
    fn output_state(&mut self) -> &mut OutputState {
        &mut self.output_state
    }

    /// A monitor plugged in while the screen is locked.
    ///
    /// It needs a lock surface of its own, or it comes up showing whatever the
    /// compositor puts behind an uncovered output — which is the one way a
    /// session-lock client can leak the session it is holding.
    fn new_output(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        output: wl_output::WlOutput,
    ) {
        if self.locked {
            self.cover(output, qh);
        }
    }

    fn update_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}

    fn output_destroyed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        output: wl_output::WlOutput,
    ) {
        self.surfaces.retain(|o| o.output != output);
    }
}

impl ShmHandler for Lock {
    fn shm_state(&mut self) -> &mut Shm {
        &mut self.shm
    }
}

delegate_registry!(Lock);

impl ProvidesRegistryState for Lock {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry_state
    }
    registry_handlers![OutputState, SeatState];
}

smithay_client_toolkit::delegate_dispatch2!(Lock);

/// Kept so the throttle's `Duration` crosses from `client` into the screen.
const _: Option<Duration> = None;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_submits() {
        assert_eq!(interpret(Keysym::Return, false, Some("\r")), Key::Submit);
        assert_eq!(interpret(Keysym::KP_Enter, false, None), Key::Submit);
    }

    /// The trap the greeter documents, which applies here with higher stakes:
    /// get this wrong and nobody whose password contains a "u" can unlock the
    /// machine at all.
    #[test]
    fn a_plain_u_is_typed_and_ctrl_u_clears() {
        assert_eq!(
            interpret(Keysym::u, false, Some("u")),
            Key::Text("u".to_string())
        );
        assert_eq!(interpret(Keysym::u, true, Some("u")), Key::Clear);
        assert_eq!(interpret(Keysym::U, true, Some("U")), Key::Clear);
    }

    /// There is no other account to switch to, so Tab is a character.
    #[test]
    fn tab_does_not_switch_accounts() {
        assert_eq!(interpret(Keysym::Tab, false, Some("\t")), Key::Ignored);
        assert_ne!(interpret(Keysym::Down, false, None), Key::Submit);
    }

    #[test]
    fn escape_clears() {
        assert_eq!(interpret(Keysym::Escape, false, None), Key::Clear);
    }

    #[test]
    fn ordinary_characters_are_typed() {
        assert_eq!(
            interpret(Keysym::a, false, Some("a")),
            Key::Text("a".to_string())
        );
    }
}
