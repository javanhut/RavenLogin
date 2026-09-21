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
//!
//! # Leaving
//!
//! The right password does not cut straight to the desktop. The padlock on
//! the screen opens and the screen lifts away, and the compositor is told to
//! reveal the session only once it has -- so what somebody sees is the lock
//! letting go, rather than a frame with a lock screen on it followed by a
//! frame without. That takes a few hundred milliseconds of frames, which
//! the compositor paces.
//!
//! It must not be able to take forever. The frames come from the compositor,
//! and a compositor that has turned the panel off, or has simply stopped
//! sending frame callbacks, would leave the session verified and never
//! revealed -- which is the one failure a lock screen must never have. So a
//! timer runs alongside, and the unlock goes out when the screen says it has
//! finished *or* when the timer says it has had long enough, whichever is
//! first. That timer is why this binary has an event loop and not just a
//! `blocking_dispatch`.

mod client;
mod desktop_config;
mod face;
mod finger;

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use raven_ui::canvas::Canvas;
use raven_greet_proto::Wash;
use raven_ui::screen::{
    Action, Biometric, BiometricKind, BiometricPrompt, Message, MessageKind, PasswordScreen,
};
use raven_ui::text::TextRenderer;
use raven_ui::wallpaper::{self, Wallpaper};
use smithay_client_toolkit::compositor::{CompositorHandler, CompositorState, FrameCallbackData};
use smithay_client_toolkit::output::{OutputHandler, OutputState};
use smithay_client_toolkit::reexports::calloop::timer::{TimeoutAction, Timer};
use smithay_client_toolkit::reexports::calloop::{EventLoop, LoopHandle};
use smithay_client_toolkit::reexports::calloop_wayland_source::WaylandSource;
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
use crate::face::{Event as FaceEvent, FaceWatch};
use crate::finger::{Event as FingerEvent, FingerWatch};
use smithay_client_toolkit::reexports::calloop::channel::Event as ChannelEvent;

/// How long the screen gets to finish leaving after the password is
/// accepted, before the session is revealed regardless.
///
/// The departure takes about 400 ms when frames are flowing. This is
/// comfortably past that, and still short enough that a compositor which has
/// stopped drawing does not keep somebody who has typed the right password
/// waiting in front of a screen that will not go away.
const UNLOCK_DEADLINE: Duration = Duration::from_millis(900);

/// How long to wait before asking for the reader again after a watch broke --
/// the daemon restarted, the reader was unplugged and plugged back in. Long
/// enough that a daemon which is down stays a few cheap reconnects an hour.
const FINGER_RETRY: Duration = Duration::from_secs(30);

/// Set in the environment to cross-fade instead of move. See
/// [`PasswordScreen::set_reduced_motion`].
const REDUCE_MOTION_VAR: &str = "RAVEN_REDUCE_MOTION";

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

    // The same picture the desktop is drawing. RavenSettingsUI puts a user's
    // choice in desktop.toml; when there is none (or it cannot be loaded), use
    // the machine-wide picture. The verify socket deliberately answers
    // nothing but authentication questions, and both paths are readable by
    // the account whose session this process belongs to.
    let wallpaper = desktop_config::wallpaper()
        .filter(|path| path.is_file())
        .and_then(load_wallpaper)
        .or_else(|| wallpaper::installed().and_then(load_wallpaper));

    let conn = Connection::connect_to_env()
        .context("cannot connect to the Wayland display; is WAYLAND_DISPLAY set?")?;
    let (globals, queue) =
        registry_queue_init(&conn).context("cannot initialize the Wayland registry")?;
    let qh = queue.handle();

    let mut event_loop: EventLoop<'static, Lock> =
        EventLoop::try_new().context("cannot create an event loop")?;
    WaylandSource::new(conn.clone(), queue)
        .insert(event_loop.handle())
        .context("cannot add the Wayland connection to the event loop")?;

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
        loop_handle: event_loop.handle(),
        screen: {
            let mut screen = PasswordScreen::locked(user);
            screen.set_wallpaper(wallpaper);
            screen.set_reduced_motion(reduce_motion());
            screen
        },
        text: TextRenderer::new(),
        daemon,
        qh: qh.clone(),
        finger: None,
        finger_prompts: 0,
        face: None,
        face_prompts: 0,
        unlocking: false,
    };
    // Straight away, before the compositor has even confirmed the lock: the
    // reader is slower to answer than the surfaces are to appear, and the
    // first thing somebody does at a locked laptop is often touch it.
    state.start_finger();
    state.start_face();

    while !state.exit {
        event_loop
            .dispatch(None, &mut state)
            .context("the event loop failed")?;
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

fn load_wallpaper(path: std::path::PathBuf) -> Option<Wallpaper> {
    match Wallpaper::load(&path) {
        Ok(wallpaper) => {
            tracing::info!(path = %path.display(), "wallpaper loaded");
            Some(wallpaper)
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), "ignoring the wallpaper: {e:#}");
            None
        }
    }
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
    /// For the unlock deadline; see the module header.
    loop_handle: LoopHandle<'static, Lock>,

    screen: PasswordScreen,
    text: TextRenderer,
    daemon: Client,
    /// For drawing from event-loop callbacks, which are not handed one.
    qh: QueueHandle<Lock>,
    /// The reader, watched for this session's owner. Dropped, which cancels
    /// it, once it has an answer or the screen is going.
    finger: Option<FingerWatch>,
    /// Prompts heard from the current watch; the first is the invitation.
    finger_prompts: u32,
    /// The camera, watched the same way and independently: a machine with
    /// both offers both, and either failing leaves the other alone.
    face: Option<FaceWatch>,
    /// As `finger_prompts`.
    face_prompts: u32,
    /// Accepted, by password or by finger. A second acceptance arriving in
    /// the meantime must not arm a second timer.
    unlocking: bool,
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

        // The configure is in logical pixels, and `set_buffer_scale` tells
        // the compositor this buffer is `scale` times denser than that. So the
        // buffer itself must be `scale` times larger, or the compositor sees a
        // surface a fraction of the size it configured -- which for a lock
        // surface is not a small picture but a protocol error, and a lock
        // screen that dies on its first frame leaves a locked session with
        // nothing to type a password into. `screen.draw` scales its layout by
        // the same factor, so the two agree.
        let scale = output.scale.max(1.0);
        let factor = scale as i32;
        let (width, height) = (output.width as i32 * factor, output.height as i32 * factor);
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

        // The screen has finished leaving; let the session through.
        if self.screen.is_dismissed() {
            self.finish_unlock();
        }
    }

    /// Tell the compositor to reveal the session, and leave.
    ///
    /// Idempotent, because it has two callers -- the frame that finishes the
    /// departure, and the deadline timer -- and whichever is second must be
    /// a no-op rather than a second `unlock` on a lock that is gone.
    fn finish_unlock(&mut self) {
        // Order matters. `unlock` is what tells the compositor it may reveal
        // the session; until it is called, dropping this process leaves the
        // screen locked, which is the behaviour we want on every other path
        // out of here.
        if let Some(lock) = self.lock.take() {
            lock.unlock();
        }
        self.exit = true;
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

    /// Watch the reader, with the events coming back through the event loop.
    fn start_finger(&mut self) {
        if self.unlocking {
            return;
        }
        self.finger = None;
        self.finger_prompts = 0;
        let Some((watch, events)) = FingerWatch::start() else {
            return;
        };
        let qh = self.qh.clone();
        let inserted = self
            .loop_handle
            .insert_source(events, move |event, _, lock: &mut Lock| {
                if let ChannelEvent::Msg(event) = event {
                    lock.on_finger(event, &qh);
                }
            });
        match inserted {
            Ok(_) => self.finger = Some(watch),
            Err(e) => tracing::warn!("cannot watch the reader from the event loop: {e}"),
        }
    }

    /// Watch the camera, with the events coming back through the event loop.
    fn start_face(&mut self) {
        if self.unlocking {
            return;
        }
        self.face = None;
        self.face_prompts = 0;
        // A watch that ended mid-sequence must not leave the screen washed.
        self.screen.set_flash(None);
        let Some((watch, events)) = FaceWatch::start() else {
            return;
        };
        let qh = self.qh.clone();
        let inserted = self
            .loop_handle
            .insert_source(events, move |event, _, lock: &mut Lock| {
                if let ChannelEvent::Msg(event) = event {
                    lock.on_face(event, &qh);
                }
            });
        match inserted {
            Ok(_) => self.face = Some(watch),
            Err(e) => tracing::warn!("cannot watch the camera from the event loop: {e}"),
        }
    }

    /// Act on something the camera did.
    fn on_face(&mut self, event: FaceEvent, qh: &QueueHandle<Self>) {
        if self.unlocking {
            return;
        }
        match event {
            FaceEvent::Wash(wash) => self.screen.set_flash(match wash {
                Wash::Colour(colour) => Some(colour),
                Wash::Off => None,
            }),
            FaceEvent::Prompt(text) => {
                let kind = if self.face_prompts == 0 {
                    BiometricKind::Waiting
                } else {
                    BiometricKind::Retry
                };
                self.face_prompts += 1;
                self.screen
                    .set_biometric(Biometric::Face, Some(BiometricPrompt { text, kind }));
            }
            FaceEvent::Verified => {
                tracing::info!("face accepted");
                self.screen.set_flash(None);
                self.screen.set_biometric(
                    Biometric::Face,
                    Some(BiometricPrompt {
                        text: "Face recognised.".to_string(),
                        kind: BiometricKind::Accepted,
                    }),
                );
                self.face = None;
                self.accept(qh);
                return;
            }
            FaceEvent::Denied(text) => {
                self.screen.set_flash(None);
                self.screen.set_biometric(Biometric::Face, None);
                self.screen.set_message(Some(Message {
                    text,
                    kind: MessageKind::Warning,
                }));
                self.face = None;
            }
            FaceEvent::Unavailable => {
                self.screen.set_flash(None);
                self.screen.set_biometric(Biometric::Face, None);
                self.face = None;
            }
            FaceEvent::Ended => {
                self.screen.set_flash(None);
                self.screen.set_biometric(Biometric::Face, None);
                self.face = None;
                let timer = Timer::from_duration(FINGER_RETRY);
                if let Err(e) = self
                    .loop_handle
                    .insert_source(timer, |_, _, lock: &mut Lock| {
                        lock.start_face();
                        TimeoutAction::Drop
                    })
                {
                    tracing::warn!("cannot schedule another look at the camera: {e}");
                }
            }
        }
        self.draw_all(qh);
    }

    /// Act on something the reader did.
    fn on_finger(&mut self, event: FingerEvent, qh: &QueueHandle<Self>) {
        if self.unlocking {
            return;
        }
        match event {
            FingerEvent::Prompt(text) => {
                let kind = if self.finger_prompts == 0 {
                    BiometricKind::Waiting
                } else {
                    BiometricKind::Retry
                };
                self.finger_prompts += 1;
                self.screen
                    .set_biometric(Biometric::Fingerprint, Some(BiometricPrompt { text, kind }));
            }
            FingerEvent::Verified => {
                tracing::info!("fingerprint accepted");
                self.screen.set_biometric(
                    Biometric::Fingerprint,
                    Some(BiometricPrompt {
                        text: "Fingerprint recognised.".to_string(),
                        kind: BiometricKind::Accepted,
                    }),
                );
                self.finger = None;
                self.accept(qh);
                return;
            }
            FingerEvent::Denied(text) => {
                self.screen.set_biometric(Biometric::Fingerprint, None);
                self.screen.set_message(Some(Message {
                    text,
                    kind: MessageKind::Warning,
                }));
                self.finger = None;
            }
            FingerEvent::Unavailable => {
                self.screen.set_biometric(Biometric::Fingerprint, None);
                self.finger = None;
            }
            FingerEvent::Ended => {
                self.screen.set_biometric(Biometric::Fingerprint, None);
                self.finger = None;
                let timer = Timer::from_duration(FINGER_RETRY);
                if let Err(e) = self
                    .loop_handle
                    .insert_source(timer, |_, _, lock: &mut Lock| {
                        lock.start_finger();
                        TimeoutAction::Drop
                    })
                {
                    tracing::warn!("cannot schedule another look at the reader: {e}");
                }
            }
        }
        self.draw_all(qh);
    }

    /// The owner has proved who they are, by either route. Open the lock on
    /// screen; the frames finish it, and the timer makes sure of it. See the
    /// module header.
    fn accept(&mut self, qh: &QueueHandle<Self>) {
        if self.unlocking {
            return;
        }
        self.unlocking = true;
        self.finger = None;
        self.face = None;
        self.screen.set_flash(None);
        self.screen.dismiss();
        self.draw_all(qh);
        let timer = Timer::from_duration(UNLOCK_DEADLINE);
        if let Err(e) = self
            .loop_handle
            .insert_source(timer, |_, _, lock: &mut Lock| {
                if !lock.exit {
                    tracing::warn!("the screen did not finish leaving in time; unlocking anyway");
                }
                lock.finish_unlock();
                TimeoutAction::Drop
            })
        {
            // No timer means no safety net, and a safety net that cannot be
            // hung is worth more than the departure: go now.
            tracing::error!("cannot arm the unlock deadline ({e}); unlocking now");
            self.finish_unlock();
        }
    }

    /// Check a password and act on the answer.
    fn submit(&mut self, password: String, qh: &QueueHandle<Self>) {
        match self.daemon.verify(password) {
            Ok(Attempt::Verified) => {
                tracing::info!("password accepted");
                self.accept(qh);
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
                // The socket broke and a reconnect failed too. This is the one
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
    fn new_output(&mut self, _: &Connection, qh: &QueueHandle<Self>, output: wl_output::WlOutput) {
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

/// Whether the environment asks for reduced motion.
///
/// `RAVEN_REDUCE_MOTION=1` in the session's environment, which is where an
/// accessibility preference on this desktop lives until there is somewhere
/// better. Anything but empty or `0` counts.
fn reduce_motion() -> bool {
    std::env::var_os(REDUCE_MOTION_VAR).is_some_and(|v| !v.is_empty() && v != "0")
}

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
