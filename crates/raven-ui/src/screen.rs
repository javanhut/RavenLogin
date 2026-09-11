//! A screen that asks for a password: what it holds, what a keystroke does to
//! it, and how it is drawn.
//!
//! Two things use this. `raven-greeter` asks for a password to *start* a
//! session; `raven-lock` asks for one to get back into a session that is
//! already running. They are the same screen with two words changed, and they
//! share this type rather than a look — a lock screen that drifts a shade away
//! from the login screen it is imitating is a lock screen that looks like a
//! phishing attempt on the machine's own owner.
//!
//! Separated from either binary's `main.rs` so that all of it except the
//! drawing is testable without a Wayland connection. The state machine is
//! small, but it is the part that has to be right — a screen that loses a
//! keystroke, or that lets Enter through while an attempt is already in
//! flight, is one somebody cannot get past and cannot debug.
//!
//! # Two layers
//!
//! The screen keeps two kinds of state and is careful about which is which.
//!
//! The *logical* state is what the keys change: the password, the message,
//! whether an attempt is in flight. It changes instantly, because a keystroke
//! that takes effect a frame late is a keystroke that feels dropped, and
//! every test in this file is about it.
//!
//! The *presentation* is what the frame shows, and it follows the logical
//! state on springs -- see [`crate::motion`]. A dot pops in after the
//! character is already in the password; the field is still shaking after
//! the denial has already been recorded. Nothing in the presentation is ever
//! consulted to decide what a key does, so a spring that is mid-flight cannot
//! swallow input, and nothing waits for an animation to end.
//!
//! Every motion here follows the same rules. Feedback lands on the key press,
//! not after. Everything starts from where it is, so a change mid-flight
//! bends the path rather than restarting it. Motion is critically damped
//! unless the thing itself would ring, and only the shake rings. The screen
//! leaves the way it arrived.

use std::time::{Duration, Instant};

use raven_greet_proto::User;

use crate::canvas::{Backdrop, Canvas, Rect};
use crate::motion::{Motion, Spring};
use crate::text::{Align, FontWeight, TextRenderer, TextStyle};
use crate::theme::{self, Color};
use crate::wallpaper::Wallpaper;

/// Which of the two screens this is.
///
/// It changes two things and deliberately nothing else: the words under the
/// field, and whether Tab offers the other accounts. A lock screen must not
/// offer them — the session behind it belongs to one person, and letting the
/// screen switch to another account would either be a lie or a way in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// `raven-greeter`: no session exists yet.
    #[default]
    Login,
    /// `raven-lock`: a session exists and is being held.
    Lock,
}

// ---------------------------------------------------------------------------
// Motion
// ---------------------------------------------------------------------------

/// The screen arriving and leaving: fade, with a slight settle in scale.
const PRESENCE: Motion = Motion::smooth(0.45);
/// Leaving is quicker than arriving. Somebody who has just typed the right
/// password is waiting on this, and nobody is waiting on the lock screen to
/// finish appearing.
const DEPARTURE: Motion = Motion::smooth(0.28);
/// How much larger than life the screen is before it settles, and again as
/// it lifts off. Enter and exit along the same path.
const LIFT: f32 = 0.035;

/// A dot popping in or out of the field.
const DOT: Motion = Motion::smooth(0.22);
/// The row of dots re-centring as one is added or taken away.
const SLIDE: Motion = Motion::smooth(0.24);
/// State colour and opacity changes: the border, the spinner, the line under
/// the field.
const STATE: Motion = Motion::smooth(0.26);
/// The caret catching up with the last dot.
const CARET: Motion = Motion::smooth(0.15);

/// The shake, which is the one motion here that is meant to ring.
///
/// Under-damped, so a single shove sideways swings the field back through
/// its rest a few times and dies out -- the way a physical thing that has
/// been knocked does, and the way the field on every Mac has since 2001.
const SHAKE: Motion = Motion::bouncy(0.17, 0.28);
/// The shove, in logical pixels per second. Sized for a first swing of
/// about ten pixels.
const SHAKE_KICK: f32 = 420.0;

/// The padlock's shackle springing open. A little overshoot, because it is a
/// latch letting go, and a latch that stops dead is a drawing of a latch.
const UNLOCK: Motion = Motion::bouncy(0.32, 0.62);
/// How far the shackle lifts, in logical pixels.
const SHACKLE_LIFT: f32 = 4.0;

/// How long the caret is on, then off.
const CARET_PERIOD: Duration = Duration::from_millis(1100);
/// The spinner's speed, in turns per second.
const SPINNER_TURNS: f32 = 0.9;

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Where the clock block's top sits, as a fraction of the height.
const CLOCK_ANCHOR: f32 = 0.13;
/// Where the identity block's centre sits, as a fraction of the height.
const IDENTITY_ANCHOR: f32 = 0.60;
/// Below this height, in logical pixels, the two blocks are stacked into one
/// and centred instead of anchored separately: the anchors would otherwise
/// run into each other.
const STACK_BELOW: f32 = 640.0;

/// What the line under the field is saying, and in what colour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub text: String,
    pub kind: MessageKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Error,
    Warning,
    Success,
}

impl MessageKind {
    fn color(self) -> Color {
        match self {
            Self::Error => theme::ERROR,
            Self::Warning => theme::WARNING,
            Self::Success => theme::SUCCESS,
        }
    }
}

/// What a keystroke asked the screen to do that it cannot do itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Nothing the caller needs to know about; just redraw.
    None,
    /// Check this password. The screen has already put itself in its busy
    /// state, so a second Enter cannot start a second attempt.
    Submit { username: String, password: String },
}

/// One dot in the field: where it is, and how big.
#[derive(Debug, Clone, Copy)]
struct Dot {
    /// Offset from the field's centre, in logical pixels.
    x: Spring,
    /// `0.0` is absent, `1.0` is full size.
    scale: Spring,
}

/// The line under the field as it is currently shown, which lags the line it
/// should show by a fade.
#[derive(Debug, Clone)]
struct Line {
    text: String,
    color: Color,
    alpha: Spring,
}

/// The login screen.
#[derive(Debug)]
pub struct PasswordScreen {
    users: Vec<User>,
    selected: usize,
    password: String,
    message: Option<Message>,
    caps_lock: bool,
    /// An attempt is in flight, or the screen is closing. Blocks input.
    busy: bool,
    /// The daemon told us to wait. Nothing is submitted before this passes.
    retry_after: Option<Instant>,
    /// The screen has been told to go, and is on its way out.
    dismissing: bool,
    started: Instant,
    hostname: String,
    os_name: String,
    /// The image to draw on, if the machine has one. `None` is the built-in
    /// backdrop, and is the default on a machine that has not configured one.
    wallpaper: Option<Wallpaper>,
    /// Whether the last frame actually got a wallpaper under it.
    ///
    /// Not the same question as `wallpaper.is_some()`: the blit can be refused
    /// (see [`Canvas::blit`]), and the secondary text colour has to follow
    /// what was really drawn rather than what was configured, or a fallback
    /// frame gets the brighter dim over the plain backdrop.
    on_wallpaper: bool,
    mode: Mode,
    /// Cross-fade instead of move; no shake, no pop, no lift.
    reduced_motion: bool,

    // Presentation. None of this is read by anything but `draw`.
    last_frame: Option<Instant>,
    /// `0.0` is gone, `1.0` is here.
    presence: Spring,
    /// Sideways offset of the field, in logical pixels.
    shake: Spring,
    dots: Vec<Dot>,
    /// Offset of the caret from the field's centre.
    caret_x: Spring,
    /// `1.0` when the placeholder is showing.
    placeholder: Spring,
    /// Where the caret goes beside the placeholder, from the field's centre
    /// in logical pixels. Measured while drawing, because the text renderer
    /// is not available to `tick`; zero until the first frame.
    placeholder_end: f32,
    /// `1.0` when the border is the error colour.
    error_mix: Spring,
    /// `1.0` when the spinner is showing.
    busy_mix: Spring,
    /// `1.0` when the field is dimmed by a throttle.
    throttle_mix: Spring,
    /// `1.0` when the padlock is open.
    unlock: Spring,
    spinner_angle: f32,
    line: Line,
}

impl PasswordScreen {
    /// A login screen, offering every account it was given.
    #[must_use]
    pub fn new(users: Vec<User>) -> Self {
        Self::with_mode(users, Mode::Login)
    }

    /// A lock screen for one account: the person whose session this is.
    ///
    /// Takes a single user rather than a list, because that is the whole
    /// difference. There is nothing to choose between.
    #[must_use]
    pub fn locked(user: User) -> Self {
        Self::with_mode(vec![user], Mode::Lock)
    }

    #[must_use]
    fn with_mode(users: Vec<User>, mode: Mode) -> Self {
        Self {
            mode,
            users,
            selected: 0,
            password: String::new(),
            message: None,
            caps_lock: false,
            busy: false,
            retry_after: None,
            dismissing: false,
            started: Instant::now(),
            hostname: read_hostname(),
            os_name: read_os_pretty_name(),
            wallpaper: None,
            on_wallpaper: false,
            reduced_motion: false,
            last_frame: None,
            presence: Spring::at(0.0, PRESENCE),
            shake: Spring::at(0.0, SHAKE),
            dots: Vec::new(),
            caret_x: Spring::at(0.0, CARET),
            placeholder: Spring::at(1.0, STATE),
            placeholder_end: 0.0,
            error_mix: Spring::at(0.0, STATE),
            busy_mix: Spring::at(0.0, STATE),
            throttle_mix: Spring::at(0.0, STATE),
            unlock: Spring::at(0.0, UNLOCK),
            spinner_angle: 0.0,
            line: Line {
                text: String::new(),
                color: theme::TEXT_DIM,
                alpha: Spring::at(0.0, STATE),
            },
        }
    }

    /// Draw on `wallpaper` instead of the backdrop, or on the backdrop again
    /// with `None`.
    pub fn set_wallpaper(&mut self, wallpaper: Option<Wallpaper>) {
        self.wallpaper = wallpaper;
    }

    /// Cross-fade instead of move.
    ///
    /// Reduced motion is not no feedback. The border still changes colour,
    /// the line under the field still says what happened, the screen still
    /// fades. What goes is everything that moves across the screen: the
    /// shake, the pop, the slide, the lift.
    pub fn set_reduced_motion(&mut self, reduced: bool) {
        self.reduced_motion = reduced;
    }

    /// The colour for text that sits directly on the background.
    ///
    /// Text inside the field keeps [`theme::TEXT_DIM`] whatever is behind the
    /// screen, because the field is an opaque card and the wallpaper never
    /// reaches it.
    fn dim(&self) -> Color {
        if self.on_wallpaper {
            theme::TEXT_DIM_ON_WALLPAPER
        } else {
            theme::TEXT_DIM
        }
    }

    /// The account currently selected, if there is one.
    #[must_use]
    pub fn current(&self) -> Option<&User> {
        self.users.get(self.selected)
    }

    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Let the screen accept input again, after a denied attempt.
    pub fn set_idle(&mut self) {
        if self.dismissing {
            // A screen on its way out does not come back.
            return;
        }
        self.busy = false;
    }

    pub fn set_message(&mut self, message: Option<Message>) {
        // A failure is felt before it is read: the field is shoved sideways
        // on the same frame the message is set, and rings back to rest.
        if matches!(
            message,
            Some(Message {
                kind: MessageKind::Error,
                ..
            })
        ) && !self.reduced_motion
        {
            self.shake.kick(SHAKE_KICK);
        }
        self.message = message;
    }

    /// Clear the typed password without touching anything else.
    ///
    /// Overwritten before being dropped rather than just `clear()`ed: `clear`
    /// sets the length to zero and leaves the bytes in the allocation.
    pub fn clear_password(&mut self) {
        // SAFETY-adjacent note, not an unsafe block: this writes over the
        // existing bytes through the same `String`, which is why it is done
        // by replacing the contents rather than by touching the buffer.
        let len = self.password.len();
        self.password.clear();
        self.password.extend(std::iter::repeat_n('\0', len));
        self.password.clear();
    }

    pub fn set_caps_lock(&mut self, on: bool) {
        self.caps_lock = on;
    }

    /// Refuse further attempts until `when`.
    pub fn throttle_until(&mut self, retry_after: Duration) {
        if retry_after.is_zero() {
            self.retry_after = None;
        } else {
            self.retry_after = Some(Instant::now() + retry_after);
        }
    }

    /// Whether the screen is currently refusing attempts, and for how long.
    #[must_use]
    pub fn throttled_for(&self, now: Instant) -> Option<Duration> {
        let until = self.retry_after?;
        (until > now).then(|| until - now)
    }

    /// Move to the next account. A no-op with fewer than two.
    pub fn next_user(&mut self) {
        if self.mode == Mode::Lock || self.users.len() < 2 {
            return;
        }
        self.selected = (self.selected + 1) % self.users.len();
        self.clear_password();
        self.message = None;
    }

    pub fn previous_user(&mut self) {
        if self.mode == Mode::Lock || self.users.len() < 2 {
            return;
        }
        self.selected = (self.selected + self.users.len() - 1) % self.users.len();
        self.clear_password();
        self.message = None;
    }

    /// A character was typed.
    pub fn push_char(&mut self, c: char) {
        if self.busy {
            return;
        }
        // Control characters arrive as `utf8` on some keys — Enter is "\r",
        // Escape is "\u{1b}" — and must not end up in the password.
        if c.is_control() {
            return;
        }
        self.password.push(c);
        // Typing is what clears a stale "incorrect password": leaving it up
        // while somebody retypes makes the screen look stuck.
        self.message = None;
    }

    pub fn backspace(&mut self) {
        if self.busy {
            return;
        }
        self.password.pop();
        self.message = None;
    }

    /// Enter. Returns what the caller should do about it.
    pub fn submit(&mut self, now: Instant) -> Action {
        if self.busy {
            return Action::None;
        }
        if self.throttled_for(now).is_some() {
            // The countdown itself is drawn live under the field; this is the
            // reason for it, and the shove that says the key was refused.
            self.set_message(Some(Message {
                text: "Too many attempts.".to_string(),
                kind: MessageKind::Warning,
            }));
            if !self.reduced_motion {
                self.shake.kick(SHAKE_KICK * 0.6);
            }
            return Action::None;
        }
        let Some(user) = self.users.get(self.selected) else {
            self.set_message(Some(Message {
                text: match self.mode {
                    Mode::Login => {
                        "There are no accounts on this machine to log in to.".to_string()
                    }
                    // Unreachable in practice -- a lock screen is built from
                    // the account whose session it is holding -- but a lock
                    // screen must never render the login screen's sentence.
                    Mode::Lock => "This session has no account to unlock.".to_string(),
                },
                kind: MessageKind::Error,
            }));
            return Action::None;
        };

        // Set busy *before* returning the action, so that a second Enter
        // arriving while the socket round-trip is in progress cannot start a
        // second attempt against the rate limiter.
        self.busy = true;
        Action::Submit {
            username: user.name.clone(),
            password: std::mem::take(&mut self.password),
        }
    }

    /// The password was right. Open the lock and leave.
    ///
    /// The screen stays busy for good: nothing typed after this point has
    /// anywhere to go. The caller keeps drawing until [`Self::is_dismissed`]
    /// says the screen is gone, and only then reveals what is behind it, so
    /// the last thing seen is the padlock opening rather than a cut.
    pub fn dismiss(&mut self) {
        self.busy = true;
        self.dismissing = true;
        self.unlock.set_target(1.0);
    }

    /// Whether a dismissed screen has finished leaving.
    ///
    /// Also true if it was never told to leave and asked anyway? No: a screen
    /// that was not dismissed is not dismissed, so a caller that unlocks on
    /// this cannot be tricked into unlocking by a frame count.
    #[must_use]
    pub fn is_dismissed(&self) -> bool {
        self.dismissing && self.presence.settled() && self.presence.value() <= 0.0
    }

    /// Whether anything on the screen is still moving.
    ///
    /// The caret blinks and the clock ticks whatever this says; it is about
    /// the springs, for a caller that wants to know whether the frame after
    /// this one will differ from it for any other reason.
    #[must_use]
    pub fn is_animating(&self) -> bool {
        self.busy
            || !self.presence.settled()
            || !self.shake.settled()
            || !self.caret_x.settled()
            || !self.placeholder.settled()
            || !self.error_mix.settled()
            || !self.busy_mix.settled()
            || !self.throttle_mix.settled()
            || !self.unlock.settled()
            || !self.line.alpha.settled()
            || self
                .dots
                .iter()
                .any(|d| !d.x.settled() || !d.scale.settled())
    }

    // -----------------------------------------------------------------------
    // Presentation
    // -----------------------------------------------------------------------

    /// Move the presentation on to `now` without drawing.
    ///
    /// [`Self::draw`] does this itself. It is public for the preview, which
    /// wants to render one frame from partway through a motion without
    /// rendering every frame before it.
    pub fn advance(&mut self, now: Instant) {
        let dt = self
            .last_frame
            .map_or(Duration::ZERO, |last| now.saturating_duration_since(last));
        self.last_frame = Some(now);
        self.tick(dt, now);
    }

    /// Point every spring at where the logical state says it should be, then
    /// advance them all by `dt`.
    ///
    /// Targets are recomputed from scratch every frame rather than set by the
    /// methods that change the state. That is deliberate: it means there is
    /// exactly one place that decides what the screen should look like, and
    /// a state change that forgot to update a target is impossible.
    fn tick(&mut self, dt: Duration, now: Instant) {
        let throttled = self.throttled_for(now).is_some();
        let error = matches!(
            self.message,
            Some(Message {
                kind: MessageKind::Error,
                ..
            })
        );

        // The screen arrives on its first frame, and leaves once the padlock
        // is most of the way open -- the latch first, then the lift, so the
        // two read as cause and effect rather than as one blur.
        if self.dismissing {
            if self.unlock.value() > 0.6 {
                self.presence.retarget(0.0, DEPARTURE);
            }
        } else {
            self.presence.set_target(1.0);
        }

        // Dots follow the password, except while an attempt is in flight:
        // the password has been handed over by then, and a field that emptied
        // itself on Enter would look like the keystroke had been lost.
        let wanted = if self.busy && !self.dismissing {
            self.dots.len()
        } else {
            self.password.chars().count().min(theme::DOT_MAX)
        };
        self.sync_dots(wanted);

        // The placeholder comes back only once the last dot has gone, not as
        // soon as the password is empty: for the few frames in between they
        // would be drawn over each other. The caret goes where the text is.
        let empty = self.dots.is_empty();
        self.placeholder
            .set_target(if empty && !self.busy { 1.0 } else { 0.0 });
        let row = (wanted.saturating_sub(1)) as f32 * theme::DOT_SPACING;
        if empty {
            self.caret_x.set_target(self.placeholder_end);
        } else if wanted > 0 {
            self.caret_x
                .set_target(row / 2.0 + theme::DOT_SPACING * 0.75);
        }
        // Otherwise the dots are on their way out and the caret stays where
        // it was until they have gone; sliding to the centre and back again
        // in the meantime would be motion that means nothing.

        self.error_mix.set_target(if error { 1.0 } else { 0.0 });
        self.busy_mix.set_target(if self.busy && !self.dismissing {
            1.0
        } else {
            0.0
        });
        self.throttle_mix
            .set_target(if throttled { 1.0 } else { 0.0 });

        self.sync_line(now);

        if self.reduced_motion {
            // Position and size snap; only opacity and colour take time.
            self.shake.snap(0.0);
            self.caret_x.snap(self.caret_x.target());
            self.unlock.snap(self.unlock.target());
            for dot in &mut self.dots {
                dot.x.snap(dot.x.target());
                dot.scale.snap(dot.scale.target());
            }
        }

        self.presence.step(dt);
        self.shake.step(dt);
        self.caret_x.step(dt);
        self.placeholder.step(dt);
        self.error_mix.step(dt);
        self.busy_mix.step(dt);
        self.throttle_mix.step(dt);
        self.unlock.step(dt);
        self.line.alpha.step(dt);
        for dot in &mut self.dots {
            dot.x.step(dt);
            dot.scale.step(dt);
        }
        // Dots that have finished leaving are gone.
        self.dots
            .retain(|d| !(d.scale.target() <= 0.0 && d.scale.settled()));

        if self.busy_mix.value() > 0.0 {
            self.spinner_angle = (self.spinner_angle
                + dt.as_secs_f32() * SPINNER_TURNS * std::f32::consts::TAU)
                .rem_euclid(std::f32::consts::TAU);
        }
    }

    /// Make the row of dots `wanted` long: new ones pop in at their place,
    /// surplus ones pop out where they are, and everything in between slides
    /// to re-centre.
    fn sync_dots(&mut self, wanted: usize) {
        let position = |i: usize| -> f32 {
            let row = (wanted.saturating_sub(1)) as f32 * theme::DOT_SPACING;
            i as f32 * theme::DOT_SPACING - row / 2.0
        };

        // How many are currently meant to be there, as opposed to on their
        // way out.
        let present = self.dots.iter().filter(|d| d.scale.target() > 0.0).count();

        if wanted > present {
            // Anything on its way out is reclaimed first, so a quick
            // backspace-and-retype brings the same dot back rather than
            // stacking a new one on a vanishing one.
            let mut i = 0;
            for dot in &mut self.dots {
                if dot.scale.target() <= 0.0 {
                    dot.scale.set_target(1.0);
                }
                dot.x.set_target(position(i));
                i += 1;
            }
            while i < wanted {
                let mut scale = Spring::at(0.0, DOT);
                scale.set_target(1.0);
                self.dots.push(Dot {
                    x: Spring::at(position(i), SLIDE),
                    scale,
                });
                i += 1;
            }
        } else {
            let mut i = 0;
            for dot in &mut self.dots {
                if i < wanted {
                    dot.scale.set_target(1.0);
                    dot.x.set_target(position(i));
                    i += 1;
                } else {
                    dot.scale.set_target(0.0);
                }
            }
        }
    }

    /// The line under the field, as it should read right now.
    ///
    /// Precedence, and it is deliberate. A message about the attempt that
    /// just failed matters more than a caps-lock caution, which matters more
    /// than an affordance somebody has already read. While the screen is
    /// checking, the spinner is the status and the line says nothing.
    fn wanted_line(&self, now: Instant) -> Option<(String, Color)> {
        if let Some(remaining) = self.throttled_for(now) {
            let lead = match &self.message {
                Some(m) => m.text.as_str(),
                None => "Too many attempts.",
            };
            return Some((
                format!("{lead} Try again in {}.", humanize(remaining)),
                theme::WARNING,
            ));
        }
        if let Some(message) = &self.message {
            return Some((message.text.clone(), message.kind.color()));
        }
        if self.busy {
            return None;
        }
        if self.caps_lock {
            return Some(("Caps Lock is on".to_string(), theme::WARNING));
        }
        if self.mode == Mode::Login && self.users.len() > 1 {
            return Some(("Tab to switch account".to_string(), self.dim()));
        }
        None
    }

    /// Cross-fade the line under the field toward what it should say.
    ///
    /// Text is swapped only while the line is invisible, so a change reads
    /// as one line fading out and another fading in rather than as words
    /// changing under the reader.
    fn sync_line(&mut self, now: Instant) {
        match self.wanted_line(now) {
            Some((text, color)) => {
                if text == self.line.text {
                    self.line.color = color;
                    self.line.alpha.set_target(1.0);
                } else if self.line.alpha.value() < 0.05 || self.reduced_motion {
                    self.line.text = text;
                    self.line.color = color;
                    self.line.alpha.snap(0.0);
                    self.line.alpha.set_target(1.0);
                } else {
                    self.line.alpha.set_target(0.0);
                }
            }
            None => self.line.alpha.set_target(0.0),
        }
    }

    // -----------------------------------------------------------------------
    // Drawing
    // -----------------------------------------------------------------------

    /// Draw the whole screen.
    ///
    /// `scale` is the output's scale factor: every metric in [`theme`] is in
    /// logical pixels and is multiplied by it here, so the login screen is the
    /// same physical size on a HiDPI panel as on a 96dpi one.
    pub fn draw(
        &mut self,
        canvas: &mut Canvas<'_>,
        text: &mut TextRenderer,
        scale: f32,
        now: Instant,
    ) {
        self.advance(now);

        let (w, h) = (canvas.width(), canvas.height());

        // `&mut self` is here only for this: the scaled wallpaper is cached on
        // the screen, because this runs on every frame callback and rescaling
        // a photograph at the refresh rate would be the only expensive thing
        // the greeter ever did. It is taken out of `self` for the duration of
        // the frame so the blurred copy can be borrowed while the rest of the
        // screen is drawn.
        let mut wallpaper = self.wallpaper.take();
        let prepared = wallpaper
            .as_mut()
            .map(|wallpaper| wallpaper.prepared(w as i32, h as i32));
        self.on_wallpaper = match &prepared {
            Some(prepared) => canvas.blit(prepared.pixels()),
            None => false,
        };
        if !self.on_wallpaper {
            canvas.gradient(theme::BACKDROP, theme::BACKDROP_EDGE);
        }
        let backdrop = if self.on_wallpaper {
            prepared.as_ref().map(|p| p.backdrop())
        } else {
            None
        };

        // The screen settles from slightly larger than life as it arrives,
        // and lifts off the same way as it leaves. The lift is about the
        // centre of the screen, so nothing slides toward an edge.
        let presence = self.presence.value().clamp(0.0, 1.0);
        let lift = if self.reduced_motion {
            1.0
        } else {
            1.0 + LIFT * (1.0 - presence)
        };
        let frame = Frame {
            scale: scale * lift,
            cx: w / 2.0,
            pivot: h / 2.0,
            lift,
            alpha: presence,
        };
        let s = |v: f32| v * scale;

        // Two blocks. The clock sits high, where the eye lands first and
        // where it is out of the way of the thing being asked; the identity
        // and the field sit below the centre, where the hands are. On a
        // short screen the two would collide, so they stack.
        let clock_height = s(theme::LOCK_WIDTH)
            + s(12.0)
            + s(theme::DATE_SIZE) * 1.25
            + s(theme::CLOCK_SIZE) * 1.25;
        let identity_height = s(theme::AVATAR_RADIUS) * 2.0
            + s(12.0)
            + s(theme::NAME_SIZE) * 1.25
            + s(20.0)
            + s(theme::FIELD_HEIGHT)
            + s(14.0)
            + s(theme::SMALL_SIZE) * 1.25;

        let (clock_top, identity_top) = if h >= s(STACK_BELOW) {
            (
                h * CLOCK_ANCHOR,
                (h * IDENTITY_ANCHOR - identity_height / 2.0).max(h * CLOCK_ANCHOR + clock_height),
            )
        } else {
            let gap = s(28.0);
            let top = ((h - clock_height - gap - identity_height) / 2.0).max(s(16.0));
            (top, top + clock_height + gap)
        };

        let mut y = clock_top;
        y = self.draw_padlock(canvas, &frame, y);
        y += s(12.0);
        self.draw_clock(canvas, text, &frame, y);

        let mut y = identity_top;
        y = self.draw_identity(canvas, text, &frame, backdrop, y);
        y += s(20.0);
        y = self.draw_field(canvas, text, &frame, backdrop, y, now);
        y += s(14.0);
        self.draw_line(canvas, text, &frame, y);

        self.draw_footer(canvas, text, &frame, w, h);

        self.wallpaper = wallpaper;
    }

    /// The padlock above the clock. Returns the y below what it drew.
    fn draw_padlock(&self, canvas: &mut Canvas<'_>, frame: &Frame, y: f32) -> f32 {
        use std::f32::consts::PI;
        let s = |v: f32| v * frame.scale;
        let cx = frame.cx;
        let width = theme::LOCK_WIDTH;
        let stroke = s(1.6);
        let ink = theme::TEXT.faded(0.9 * frame.alpha);

        // The shackle is a half ring whose ends run straight down into the
        // body. Open, it lifts by SHACKLE_LIFT and the ends come clear.
        let open = self.unlock.value().clamp(0.0, 1.2);
        let shackle_r = s(width * 0.32);
        let body_top = frame.y(y + frame.l(width * 0.55));
        let body = Rect::new(cx - s(width / 2.0), body_top, s(width), s(width * 0.72));
        let hinge_y = body_top - s(SHACKLE_LIFT) * open;
        canvas.arc(cx, hinge_y, shackle_r, stroke, PI, PI, ink);
        let leg = s(width * 0.22);
        for side in [-1.0, 1.0] {
            canvas.rounded_rect(
                Rect::new(cx + side * shackle_r - stroke / 2.0, hinge_y, stroke, leg),
                stroke / 2.0,
                ink,
            );
        }
        canvas.rounded_rect(body, s(2.5), ink);

        y + frame.l(width * 0.55 + width * 0.72)
    }

    /// The date over the time. Returns the y below what it drew.
    fn draw_clock(&self, canvas: &mut Canvas<'_>, text: &mut TextRenderer, frame: &Frame, y: f32) {
        let (time, date) = local_time();
        let date_style =
            TextStyle::new(theme::DATE_SIZE, FontWeight::NORMAL).tracked(theme::DATE_TRACKING);
        let clock_style =
            TextStyle::new(theme::CLOCK_SIZE, FontWeight::NORMAL).tracked(theme::CLOCK_TRACKING);

        text.draw(
            canvas,
            &date,
            frame.cx,
            frame.y(y),
            date_style.scaled(frame.scale),
            theme::TEXT.faded(frame.alpha),
            Align::Center,
        );
        let clock_y = y + frame.l(theme::DATE_SIZE * 1.25);
        text.draw(
            canvas,
            &time,
            frame.cx,
            frame.y(clock_y),
            clock_style.scaled(frame.scale),
            theme::TEXT.faded(frame.alpha),
            Align::Center,
        );
    }

    /// The avatar and the name. Returns the y below what it drew.
    fn draw_identity(
        &self,
        canvas: &mut Canvas<'_>,
        text: &mut TextRenderer,
        frame: &Frame,
        backdrop: Option<Backdrop<'_>>,
        y: f32,
    ) -> f32 {
        let s = |v: f32| v * frame.scale;
        let cx = frame.cx;
        let radius = s(theme::AVATAR_RADIUS);
        let center_y = frame.y(y + frame.l(theme::AVATAR_RADIUS));

        // A disc of the same material as the field, with a hairline where it
        // catches the light. The desktop's accent is kept for the caret and
        // the focus ring: one colour, meaning one thing, in one place.
        canvas.material(
            Rect::new(cx - radius, center_y - radius, radius * 2.0, radius * 2.0),
            radius,
            backdrop,
            theme::MATERIAL.faded(frame.alpha),
        );
        canvas.circle_outline(
            cx,
            center_y,
            radius - s(theme::AVATAR_RING) / 2.0,
            s(theme::AVATAR_RING),
            theme::MATERIAL_EDGE.faded(frame.alpha),
        );

        let (initial, name) = match self.current() {
            Some(user) => (user.initial.to_string(), user.display_name.clone()),
            None => ("!".to_string(), "No accounts".to_string()),
        };

        // Vertically centred in the disc by its own line box, not by its
        // baseline: close enough for a single capital, and it does not depend
        // on the font's metrics being sensible.
        let initial_style = TextStyle::new(theme::AVATAR_SIZE, FontWeight::BOLD);
        text.draw(
            canvas,
            &initial,
            cx,
            center_y - s(theme::AVATAR_SIZE) * 0.62,
            initial_style.scaled(frame.scale),
            theme::TEXT.faded(frame.alpha),
            Align::Center,
        );

        let name_y = y + frame.l(theme::AVATAR_RADIUS * 2.0 + 12.0);
        let name_style =
            TextStyle::new(theme::NAME_SIZE, FontWeight::BOLD).tracked(theme::NAME_TRACKING);
        text.draw(
            canvas,
            &name,
            cx,
            frame.y(name_y),
            name_style.scaled(frame.scale),
            theme::TEXT.faded(frame.alpha),
            Align::Center,
        );

        name_y + frame.l(theme::NAME_SIZE * 1.25)
    }

    /// The password field, its dots, the caret, and the spinner.
    fn draw_field(
        &mut self,
        canvas: &mut Canvas<'_>,
        text: &mut TextRenderer,
        frame: &Frame,
        backdrop: Option<Backdrop<'_>>,
        y: f32,
        now: Instant,
    ) -> f32 {
        let s = |v: f32| v * frame.scale;
        let alpha = frame.alpha;
        let cx = frame.cx + s(self.shake.value());
        let width = s(theme::FIELD_WIDTH);
        let height = s(theme::FIELD_HEIGHT);
        let radius = height / 2.0;
        let rect = Rect::new(cx - width / 2.0, frame.y(y), width, height);
        let center_y = rect.y + height / 2.0;

        let error = self.error_mix.value().clamp(0.0, 1.0);
        let busy = self.busy_mix.value().clamp(0.0, 1.0);
        let throttled = self.throttle_mix.value().clamp(0.0, 1.0);
        // The field is focused whenever it will take a key. That is what the
        // ring says, and it is the only place the accent says anything.
        let focus = (1.0 - busy) * (1.0 - throttled) * alpha;
        let state = theme::ACCENT.mix(theme::ERROR, error);

        // Halo, material, hairline. The halo sits outside the border and is
        // most of what changes when the field goes from ready to refused.
        let halo = focus.max(error * alpha) * 0.32;
        if halo > 0.0 {
            let grow = s(theme::FIELD_HALO);
            canvas.rounded_rect_outline(
                Rect::new(
                    rect.x - grow,
                    rect.y - grow,
                    rect.width + grow * 2.0,
                    rect.height + grow * 2.0,
                ),
                radius + grow,
                grow,
                state.faded(halo),
            );
        }
        canvas.material(rect, radius, backdrop, theme::MATERIAL.faded(alpha));
        let border = theme::MATERIAL_EDGE
            .mix(theme::ACCENT.faded(0.85), focus * (1.0 - error))
            .mix(theme::ERROR.faded(0.9), error);
        canvas.rounded_rect_outline(rect, radius, s(theme::FIELD_BORDER), border.faded(alpha));

        // What is drawn on the material dims while it cannot be typed into.
        let ink_alpha = alpha * (1.0 - 0.45 * busy.max(throttled));

        // The placeholder, fading as the first dot arrives. Its end is
        // remembered for the caret, in logical pixels, so the caret can be
        // beside it rather than through it: "Enter Pass|word" is not a field.
        let placeholder = self.placeholder.value().clamp(0.0, 1.0);
        let style =
            TextStyle::new(theme::BODY_SIZE, FontWeight::NORMAL).tracked(theme::BODY_TRACKING);
        let end = text.measure("Enter Password", style) / 2.0 + 5.0;
        if self.placeholder_end == 0.0 && self.dots.is_empty() {
            // The first frame: the caret has had no end to go to until now,
            // and must not be seen sliding across the placeholder to reach it.
            self.caret_x.snap(end);
        }
        self.placeholder_end = end;
        if placeholder > 0.0 {
            text.draw(
                canvas,
                "Enter Password",
                cx,
                center_y - s(theme::BODY_SIZE) * 0.62,
                style.scaled(frame.scale),
                self.dim().faded(ink_alpha * placeholder),
                Align::Center,
            );
        }

        // The dots, each at its own place and size.
        for dot in &self.dots {
            let size = dot.scale.value().clamp(0.0, 1.2);
            if size <= 0.0 {
                continue;
            }
            canvas.circle(
                cx + s(dot.x.value()),
                center_y,
                s(theme::DOT_RADIUS) * size,
                theme::TEXT.faded(ink_alpha),
            );
        }

        // The caret blinks only while the field is live. A caret still
        // blinking under an attempt in flight reads as "nothing happened".
        // It breathes rather than switching: on, then off, on a curve.
        if focus > 0.0 {
            let phase = now.duration_since(self.started).as_secs_f32() / CARET_PERIOD.as_secs_f32();
            let blink = (0.5 + 0.5 * (phase * std::f32::consts::TAU).cos()).powf(0.6);
            canvas.rounded_rect(
                Rect::new(
                    cx + s(self.caret_x.value()) - s(0.75),
                    center_y - s(8.0),
                    s(1.5),
                    s(16.0),
                ),
                s(0.75),
                theme::ACCENT.faded(focus * blink),
            );
        }

        // The spinner, beside the field, while the daemon is asked.
        if busy > 0.0 {
            let r = s(theme::SPINNER_RADIUS);
            canvas.arc(
                rect.x + rect.width + s(16.0) + r,
                center_y,
                r,
                s(theme::SPINNER_STROKE),
                self.spinner_angle,
                std::f32::consts::TAU * 0.72,
                self.dim().faded(alpha * busy),
            );
        }

        y + frame.l(theme::FIELD_HEIGHT)
    }

    /// The line under the field: an error, a countdown, a caps-lock caution,
    /// or the one affordance the keyboard cannot discover on its own.
    fn draw_line(&self, canvas: &mut Canvas<'_>, text: &mut TextRenderer, frame: &Frame, y: f32) {
        let alpha = self.line.alpha.value().clamp(0.0, 1.0) * frame.alpha;
        if alpha <= 0.0 {
            return;
        }
        let style =
            TextStyle::new(theme::SMALL_SIZE, FontWeight::NORMAL).tracked(theme::SMALL_TRACKING);
        text.draw(
            canvas,
            &self.line.text,
            frame.cx,
            frame.y(y),
            style.scaled(frame.scale),
            self.line.color.faded(alpha),
            Align::Center,
        );
    }

    /// Hostname on the left, distribution on the right.
    ///
    /// Not lifted with the rest: it is the label on the screen, not a thing
    /// on it, and it fades in place.
    fn draw_footer(
        &self,
        canvas: &mut Canvas<'_>,
        text: &mut TextRenderer,
        frame: &Frame,
        w: f32,
        h: f32,
    ) {
        let scale = frame.scale / frame.lift;
        let s = |v: f32| v * scale;
        let margin = s(28.0);
        let style =
            TextStyle::new(s(theme::SMALL_SIZE), FontWeight::NORMAL).tracked(theme::SMALL_TRACKING);
        let y = h - margin - style.size;
        let color = self.dim().faded(frame.alpha);

        // On a narrow screen these two would draw straight through each other.
        // Measuring first and dropping the distribution name is the right way
        // round: which machine you are logging in to is the useful half, and
        // the one you cannot work out from looking at the screen.
        let hostname_w = text.measure(&self.hostname, style);
        let os_w = text.measure(&self.os_name, style);
        let fits = hostname_w + os_w + margin * 3.0 <= w;

        text.draw(canvas, &self.hostname, margin, y, style, color, Align::Left);
        if fits {
            text.draw(
                canvas,
                &self.os_name,
                w - margin,
                y,
                style,
                color,
                Align::Right,
            );
        }
    }
}

/// Where one frame puts things: the output scale with the lift folded in, the
/// centre line, and the opacity everything is drawn at.
///
/// Layout is done in unlifted canvas pixels -- `l` turns a logical metric
/// into one of those -- and each thing is lifted about the centre as it is
/// drawn, with `y` for its position and `s` for its size. Keeping the two
/// apart is what lets the layout be computed once and the lift be applied
/// uniformly, rather than every offset being lifted twice.
#[derive(Debug, Clone, Copy)]
struct Frame {
    /// Output scale times lift. Every drawn size is multiplied by this.
    scale: f32,
    /// The horizontal centre, in canvas pixels.
    cx: f32,
    /// The vertical centre, in canvas pixels, which the lift is about.
    pivot: f32,
    lift: f32,
    alpha: f32,
}

impl Frame {
    /// A logical metric as an unlifted canvas distance, for layout.
    fn l(&self, v: f32) -> f32 {
        v * self.scale / self.lift
    }

    /// A canvas y, lifted about the pivot.
    fn y(&self, y: f32) -> f32 {
        self.pivot + (y - self.pivot) * self.lift
    }
}

/// `1m 30s` / `12s`, for the throttle countdown.
fn humanize(d: Duration) -> String {
    let secs = d.as_secs().max(1);
    if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// The wall clock, as `(time, date)`.
///
/// `jiff` reads the system tzdb, so this is the time on the wall rather than
/// UTC. A failure falls back to placeholders instead of propagating: a clock
/// that cannot be formatted is not a reason to refuse somebody a login screen.
fn local_time() -> (String, String) {
    use jiff::fmt::strtime;

    let now = jiff::Zoned::now();
    let time = strtime::format("%H:%M", &now).unwrap_or_else(|_| "--:--".to_string());
    let date = strtime::format("%A, %-d %B", &now).unwrap_or_default();
    (time, date)
}

/// This machine's name.
fn read_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "raven".to_string())
}

/// `PRETTY_NAME` from `/etc/os-release`.
fn read_os_pretty_name() -> String {
    let Ok(text) = std::fs::read_to_string("/etc/os-release") else {
        return "Raven Linux".to_string();
    };
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            return value.trim().trim_matches('"').to_string();
        }
    }
    "Raven Linux".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, initial: char) -> User {
        User {
            name: name.to_string(),
            display_name: name.to_string(),
            initial,
        }
    }

    fn screen() -> PasswordScreen {
        PasswordScreen::new(vec![user("javan", 'J'), user("second", 'S')])
    }

    /// Advance the presentation by `frames` sixty-hertz frames from `from`,
    /// without drawing. Returns the instant reached.
    fn advance(s: &mut PasswordScreen, from: Instant, frames: u32) -> Instant {
        let step = Duration::from_millis(16);
        let mut now = from;
        for _ in 0..frames {
            now += step;
            s.tick(step, now);
        }
        now
    }

    #[test]
    fn typing_builds_a_password() {
        let mut s = screen();
        for c in "hunter2".chars() {
            s.push_char(c);
        }
        assert_eq!(s.password, "hunter2");
        s.backspace();
        assert_eq!(s.password, "hunter");
    }

    /// Enter arrives as `utf8: Some("\r")` on some keyboards. It must not
    /// become part of the password.
    #[test]
    fn control_characters_are_not_typed() {
        let mut s = screen();
        s.push_char('\r');
        s.push_char('\n');
        s.push_char('\u{1b}');
        s.push_char('\t');
        assert!(s.password.is_empty(), "got {:?}", s.password);
    }

    #[test]
    fn submitting_hands_over_the_password_and_clears_it() {
        let mut s = screen();
        for c in "hunter2".chars() {
            s.push_char(c);
        }
        match s.submit(Instant::now()) {
            Action::Submit { username, password } => {
                assert_eq!(username, "javan");
                assert_eq!(password, "hunter2");
            }
            other => panic!("expected a submit, got {other:?}"),
        }
        assert!(
            s.password.is_empty(),
            "the field should be empty after submit"
        );
    }

    /// The property that stops a held Enter key from burning through the rate
    /// limiter: once an attempt is in flight, nothing else gets submitted.
    #[test]
    fn a_second_enter_while_busy_does_nothing() {
        let mut s = screen();
        s.push_char('a');
        assert!(matches!(s.submit(Instant::now()), Action::Submit { .. }));
        assert!(s.is_busy());
        assert_eq!(s.submit(Instant::now()), Action::None);
        assert_eq!(s.submit(Instant::now()), Action::None);
    }

    #[test]
    fn typing_is_ignored_while_busy() {
        let mut s = screen();
        s.push_char('a');
        let _ = s.submit(Instant::now());
        s.push_char('b');
        s.backspace();
        assert!(s.password.is_empty());
    }

    #[test]
    fn going_idle_accepts_input_again() {
        let mut s = screen();
        s.push_char('a');
        let _ = s.submit(Instant::now());
        s.set_idle();
        s.push_char('b');
        assert_eq!(s.password, "b");
    }

    #[test]
    fn switching_users_wraps_and_clears_the_password() {
        let mut s = screen();
        s.push_char('a');
        assert_eq!(s.current().map(|u| u.name.as_str()), Some("javan"));

        s.next_user();
        assert_eq!(s.current().map(|u| u.name.as_str()), Some("second"));
        assert!(
            s.password.is_empty(),
            "switching must not carry a password over"
        );

        s.next_user();
        assert_eq!(s.current().map(|u| u.name.as_str()), Some("javan"));
        s.previous_user();
        assert_eq!(s.current().map(|u| u.name.as_str()), Some("second"));
    }

    #[test]
    fn switching_does_nothing_with_one_account() {
        let mut s = PasswordScreen::new(vec![user("javan", 'J')]);
        s.push_char('a');
        s.next_user();
        assert_eq!(s.current().map(|u| u.name.as_str()), Some("javan"));
        // ...and must not clear a password that was being typed.
        assert_eq!(s.password, "a");
    }

    #[test]
    fn a_throttle_refuses_submission_until_it_passes() {
        let mut s = screen();
        s.push_char('a');
        s.throttle_until(Duration::from_secs(30));

        assert_eq!(s.submit(Instant::now()), Action::None);
        assert!(
            !s.is_busy(),
            "a refused submit must not mark the screen busy"
        );
        assert!(s.message.is_some(), "it should say why");

        // A zero retry clears it.
        s.throttle_until(Duration::ZERO);
        assert!(matches!(s.submit(Instant::now()), Action::Submit { .. }));
    }

    /// The countdown is live: it is the line under the field for as long as
    /// the throttle lasts, whether or not Enter was pressed, and it goes
    /// when the throttle does.
    #[test]
    fn a_throttle_is_counted_down_under_the_field() {
        let mut s = screen();
        let now = Instant::now();
        s.throttle_until(Duration::from_secs(30));
        let (line, color) = s.wanted_line(now).expect("a countdown");
        assert!(line.contains("Try again in 30s"), "{line}");
        assert_eq!(color, theme::WARNING);

        let later = now + Duration::from_secs(18);
        let (line, _) = s.wanted_line(later).expect("still counting");
        assert!(line.contains("12s"), "{line}");

        let after = s.wanted_line(now + Duration::from_secs(31));
        assert!(
            after.as_ref().is_none_or(|(l, _)| !l.contains("Try again")),
            "the countdown should be gone: {after:?}"
        );
    }

    #[test]
    fn a_machine_with_no_accounts_says_so() {
        let mut s = PasswordScreen::new(Vec::new());
        assert_eq!(s.submit(Instant::now()), Action::None);
        assert_eq!(s.message.as_ref().map(|m| m.kind), Some(MessageKind::Error));
        assert!(!s.is_busy());
    }

    #[test]
    fn typing_clears_a_stale_error() {
        let mut s = screen();
        s.set_message(Some(Message {
            text: "Incorrect password.".to_string(),
            kind: MessageKind::Error,
        }));
        s.push_char('a');
        assert!(s.message.is_none());
    }

    /// The lock screen says nothing it does not have to. There is one thing
    /// the keyboard cannot discover -- that Tab switches account -- and it
    /// is said only where it is true.
    #[test]
    fn the_idle_line_is_empty_except_for_tab() {
        let now = Instant::now();
        let lock = PasswordScreen::locked(user("javan", 'J'));
        assert_eq!(lock.wanted_line(now), None);

        let one = PasswordScreen::new(vec![user("javan", 'J')]);
        assert_eq!(one.wanted_line(now), None);

        let two = screen();
        assert!(two.wanted_line(now).is_some_and(|(l, _)| l.contains("Tab")));

        let mut caps = PasswordScreen::locked(user("javan", 'J'));
        caps.set_caps_lock(true);
        assert!(
            caps.wanted_line(now)
                .is_some_and(|(l, _)| l.contains("Caps Lock"))
        );
    }

    #[test]
    fn humanize_reads_like_a_countdown() {
        assert_eq!(humanize(Duration::from_secs(12)), "12s");
        assert_eq!(humanize(Duration::from_secs(90)), "1m 30s");
        // Sub-second rounds up rather than saying "0s".
        assert_eq!(humanize(Duration::from_millis(300)), "1s");
    }

    // -- presentation -------------------------------------------------------

    /// A keystroke is in the password before any frame is drawn, and the dot
    /// for it arrives over the following frames rather than all at once.
    #[test]
    fn dots_follow_the_password_on_a_spring() {
        let mut s = screen();
        let now = Instant::now();
        s.push_char('a');
        assert_eq!(s.password, "a");

        s.tick(Duration::ZERO, now);
        assert_eq!(s.dots.len(), 1);
        let first = s.dots[0].scale.value();
        assert!(first < 0.5, "the dot should start small, got {first}");

        advance(&mut s, now, 40);
        assert!(s.dots[0].scale.settled());
        assert_eq!(s.dots[0].scale.value(), 1.0);

        s.backspace();
        advance(&mut s, now, 60);
        assert!(
            s.dots.is_empty(),
            "a removed dot is dropped once it has gone"
        );
    }

    /// The row stays full past DOT_MAX, whatever is typed.
    #[test]
    fn the_row_of_dots_stops_growing() {
        let mut s = screen();
        for _ in 0..(theme::DOT_MAX + 10) {
            s.push_char('x');
        }
        s.tick(Duration::ZERO, Instant::now());
        assert_eq!(s.dots.len(), theme::DOT_MAX);
    }

    /// The dots stay in the field while the daemon is asked, so that Enter
    /// does not look like it emptied the field, and clear when it answers.
    #[test]
    fn dots_are_held_while_busy_and_cleared_on_denial() {
        let mut s = screen();
        let now = Instant::now();
        for c in "abc".chars() {
            s.push_char(c);
        }
        let now = advance(&mut s, now, 40);
        assert_eq!(s.dots.len(), 3);

        let _ = s.submit(now);
        assert!(s.password.is_empty());
        let now = advance(&mut s, now, 10);
        assert_eq!(s.dots.len(), 3, "still shown while checking");
        assert!(s.dots.iter().all(|d| d.scale.target() == 1.0));

        s.set_message(Some(Message {
            text: "Incorrect password.".to_string(),
            kind: MessageKind::Error,
        }));
        s.set_idle();
        advance(&mut s, now, 60);
        assert!(s.dots.is_empty());
    }

    /// A denial shoves the field sideways, and it comes back to rest.
    #[test]
    fn a_denial_shakes_the_field_and_it_settles() {
        let mut s = screen();
        let now = Instant::now();
        s.set_message(Some(Message {
            text: "Incorrect password.".to_string(),
            kind: MessageKind::Error,
        }));
        assert!(
            s.shake.velocity() > 0.0,
            "the shove lands on the same frame"
        );

        let mut peak = 0.0_f32;
        let mut t = now;
        for _ in 0..20 {
            t += Duration::from_millis(16);
            s.tick(Duration::from_millis(16), t);
            peak = peak.max(s.shake.value().abs());
        }
        assert!(peak > 4.0 && peak < 20.0, "swung {peak} px");
        advance(&mut s, t, 90);
        assert!(s.shake.settled(), "still at {}", s.shake.value());
    }

    /// Reduced motion keeps the feedback and drops the movement.
    #[test]
    fn reduced_motion_does_not_shake_or_pop() {
        let mut s = screen();
        s.set_reduced_motion(true);
        s.set_message(Some(Message {
            text: "Incorrect password.".to_string(),
            kind: MessageKind::Error,
        }));
        assert_eq!(s.shake.velocity(), 0.0);

        s.message = None;
        s.push_char('a');
        s.tick(Duration::ZERO, Instant::now());
        assert_eq!(s.dots[0].scale.value(), 1.0, "the dot is simply there");
        // ...but the colour still says what happened.
        s.set_message(Some(Message {
            text: "Incorrect password.".to_string(),
            kind: MessageKind::Error,
        }));
        s.tick(Duration::ZERO, Instant::now());
        assert_eq!(s.error_mix.target(), 1.0);
    }

    /// Dismissing opens the lock first and then fades the screen, and only
    /// once it has faded is it dismissed. Nothing typed in the meantime goes
    /// anywhere.
    #[test]
    fn dismissing_opens_the_lock_then_leaves() {
        let mut s = PasswordScreen::locked(user("javan", 'J'));
        let now = Instant::now();
        let now = advance(&mut s, now, 90);
        assert!(s.presence.settled() && s.presence.value() == 1.0);

        s.dismiss();
        assert!(s.is_busy());
        assert!(!s.is_dismissed());
        s.push_char('a');
        assert!(s.password.is_empty());

        // First frames: the shackle is moving, the screen is not yet.
        let now = advance(&mut s, now, 3);
        assert!(s.unlock.value() > 0.0);
        assert_eq!(s.presence.target(), 1.0, "the lift waits for the latch");
        assert!(!s.is_dismissed());

        advance(&mut s, now, 120);
        assert!(s.is_dismissed());
        // ...and it stays dismissed: idle cannot bring it back.
        s.set_idle();
        assert!(s.is_busy());
    }

    /// A screen that was never dismissed is never "dismissed", however long
    /// it sits there. This is what the lock's unlock hangs on.
    #[test]
    fn an_undismissed_screen_never_reports_dismissed() {
        let mut s = PasswordScreen::locked(user("javan", 'J'));
        advance(&mut s, Instant::now(), 600);
        assert!(!s.is_dismissed());
        assert!(!s.is_animating());
    }

    /// The line under the field swaps text only while invisible.
    #[test]
    fn the_line_cross_fades_rather_than_changing_under_the_reader() {
        let mut s = screen();
        let now = Instant::now();
        s.set_caps_lock(true);
        let now = advance(&mut s, now, 60);
        assert_eq!(s.line.text, "Caps Lock is on");
        assert!(s.line.alpha.value() > 0.95);

        s.set_message(Some(Message {
            text: "Incorrect password.".to_string(),
            kind: MessageKind::Error,
        }));
        s.tick(Duration::from_millis(16), now);
        assert_eq!(s.line.text, "Caps Lock is on", "still the old line...");
        assert_eq!(s.line.alpha.target(), 0.0, "...on its way out");

        advance(&mut s, now, 60);
        assert_eq!(s.line.text, "Incorrect password.");
        assert!(s.line.alpha.value() > 0.9);
    }

    /// Drawing must not panic at any size, including sizes no real screen has.
    /// This is the cheapest possible guard against a layout that divides by a
    /// zero dimension.
    #[test]
    fn drawing_survives_absurd_screen_sizes() {
        let mut text = TextRenderer::new();
        let mut s = screen();
        for (w, h) in [(1, 1), (16, 9), (640, 480), (3840, 2160), (200, 4000)] {
            let mut data = vec![0u8; (w * h * 4) as usize];
            let mut canvas = Canvas::new(&mut data, w, h);
            s.draw(&mut canvas, &mut text, 1.0, Instant::now());
        }
    }

    /// The same, with a wallpaper under it. This is the path that scales an
    /// image to the surface, so it is the one with a division by a dimension
    /// in it -- and a 1x1 screen or a 1x1 wallpaper is where that would show.
    #[test]
    fn drawing_on_a_wallpaper_survives_absurd_screen_sizes() {
        let mut text = TextRenderer::new();
        let mut s = screen();
        s.set_wallpaper(Some(Wallpaper::flat(1, 1, 0xFF, 0xFF, 0xFF)));
        for (w, h) in [(1, 1), (16, 9), (640, 480), (200, 4000)] {
            let mut data = vec![0u8; (w * h * 4) as usize];
            let mut canvas = Canvas::new(&mut data, w, h);
            s.draw(&mut canvas, &mut text, 1.0, Instant::now());
        }
    }

    /// Every state the screen can be in draws, at every point in its motion.
    #[test]
    fn every_state_draws_through_its_motion() {
        let mut text = TextRenderer::new();
        let mut s = screen();
        s.set_wallpaper(Some(Wallpaper::flat(8, 8, 0x20, 0x40, 0x80)));
        let mut data = vec![0u8; 320 * 240 * 4];
        let mut now = Instant::now();
        let mut frame = |s: &mut PasswordScreen, now: Instant| {
            let mut canvas = Canvas::new(&mut data, 320, 240);
            s.draw(&mut canvas, &mut text, 1.0, now);
        };

        for _ in 0..5 {
            now += Duration::from_millis(16);
            frame(&mut s, now);
        }
        for c in "hunter2".chars() {
            s.push_char(c);
            now += Duration::from_millis(16);
            frame(&mut s, now);
        }
        s.set_caps_lock(true);
        let _ = s.submit(now);
        frame(&mut s, now);
        s.throttle_until(Duration::from_secs(5));
        s.set_message(Some(Message {
            text: "Incorrect password.".to_string(),
            kind: MessageKind::Error,
        }));
        s.set_idle();
        for _ in 0..5 {
            now += Duration::from_millis(16);
            frame(&mut s, now);
        }
        s.dismiss();
        for _ in 0..80 {
            now += Duration::from_millis(16);
            frame(&mut s, now);
        }
        assert!(s.is_dismissed());
    }

    /// A wallpaper must actually reach the frame, and the secondary text must
    /// follow it. Both are silent failures otherwise: the screen still draws,
    /// it just draws the wrong thing.
    #[test]
    fn a_wallpaper_is_drawn_and_switches_the_dim_colour() {
        let mut text = TextRenderer::new();
        let mut s = screen();
        assert_eq!(s.dim(), theme::TEXT_DIM);

        s.set_wallpaper(Some(Wallpaper::flat(64, 64, 0xFF, 0x00, 0x00)));
        let mut data = vec![0u8; (64 * 64 * 4) as usize];
        {
            let mut canvas = Canvas::new(&mut data, 64, 64);
            s.draw(&mut canvas, &mut text, 1.0, Instant::now());
        }

        assert_eq!(s.dim(), theme::TEXT_DIM_ON_WALLPAPER);
        // A blue wallpaper under the scrim: the corner is nowhere near the
        // card or the text, so it is still the wallpaper's colour, and blue
        // is still the channel it leads with.
        assert!(
            data[0] > data[2],
            "the corner is {:?}, which is not a blue wallpaper",
            &data[..4]
        );
    }

    /// Taking the wallpaper away has to put the backdrop back, colour and all.
    #[test]
    fn removing_a_wallpaper_restores_the_backdrop() {
        let mut text = TextRenderer::new();
        let mut s = screen();
        s.set_wallpaper(Some(Wallpaper::flat(64, 64, 0xFF, 0x00, 0x00)));
        s.set_wallpaper(None);

        let mut data = vec![0u8; (64 * 64 * 4) as usize];
        {
            let mut canvas = Canvas::new(&mut data, 64, 64);
            s.draw(&mut canvas, &mut text, 1.0, Instant::now());
        }
        assert_eq!(s.dim(), theme::TEXT_DIM);
        // Within a step of the backdrop rather than equal to it: the gradient
        // dithers, so the top-left pixel is the backdrop plus or minus the
        // Bayer perturbation. The point is that it is the backdrop and not the
        // 0xFF blue the wallpaper was.
        assert!(
            data[0].abs_diff(theme::BACKDROP.blue()) <= 1,
            "the corner is {:?}, which is not the backdrop",
            &data[..4]
        );
    }

    /// ...and at a fractional scale factor, which is what a 1.5x display gives.
    #[test]
    fn drawing_survives_fractional_scaling() {
        let mut text = TextRenderer::new();
        let mut s = screen();
        for scale in [0.5, 1.0, 1.5, 2.0, 3.0] {
            let mut data = vec![0u8; (800 * 600 * 4) as usize];
            let mut canvas = Canvas::new(&mut data, 800, 600);
            s.draw(&mut canvas, &mut text, scale, Instant::now());
        }
    }
}
