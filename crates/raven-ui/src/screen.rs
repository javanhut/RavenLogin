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

use std::time::{Duration, Instant};

use raven_greet_proto::User;

use crate::canvas::{Canvas, Rect};
use crate::text::{Align, FontWeight, TextRenderer};
use crate::theme;
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

/// How long the caret is on, then off.
const CARET_PERIOD: Duration = Duration::from_millis(1100);

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
    fn color(self) -> theme::Color {
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
            started: Instant::now(),
            hostname: read_hostname(),
            os_name: read_os_pretty_name(),
            wallpaper: None,
            on_wallpaper: false,
        }
    }

    /// Draw on `wallpaper` instead of the backdrop, or on the backdrop again
    /// with `None`.
    pub fn set_wallpaper(&mut self, wallpaper: Option<Wallpaper>) {
        self.wallpaper = wallpaper;
    }

    /// The colour for text that sits directly on the background.
    ///
    /// Text inside the field keeps [`theme::TEXT_DIM`] whatever is behind the
    /// screen, because the field is an opaque card and the wallpaper never
    /// reaches it.
    fn dim(&self) -> theme::Color {
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
        self.busy = false;
    }

    pub fn set_message(&mut self, message: Option<Message>) {
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
        if let Some(remaining) = self.throttled_for(now) {
            self.message = Some(Message {
                text: format!("Too many attempts. {} to go.", humanize(remaining)),
                kind: MessageKind::Warning,
            });
            return Action::None;
        }
        let Some(user) = self.users.get(self.selected) else {
            self.message = Some(Message {
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
            });
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
        let (w, h) = (canvas.width(), canvas.height());

        // `&mut self` is here only for this: the scaled wallpaper is cached on
        // the screen, because this runs on every frame callback and rescaling
        // a photograph at the refresh rate would be the only expensive thing
        // the greeter ever did.
        self.on_wallpaper = match self.wallpaper.as_mut() {
            Some(wallpaper) => canvas.blit(wallpaper.prepared(w as i32, h as i32)),
            None => false,
        };
        if !self.on_wallpaper {
            canvas.gradient(theme::BACKDROP, theme::BACKDROP_EDGE);
        }

        let cx = w / 2.0;
        let s = |v: f32| v * scale;

        // The block of clock-through-hint is centred as a unit, rather than
        // each piece being placed against the screen edges. On a very short
        // screen this keeps it together instead of pulling it apart.
        let block_height = s(220.0) + s(theme::AVATAR_RADIUS) * 2.0 + s(theme::FIELD_HEIGHT);
        let top = ((h - block_height) / 2.0).max(s(24.0));

        let mut y = top;
        y = self.draw_clock(canvas, text, cx, y, scale);
        y += s(28.0);
        y = self.draw_identity(canvas, text, cx, y, scale);
        y += s(24.0);
        y = self.draw_field(canvas, text, cx, y, scale, now);
        y += s(16.0);
        self.draw_message(canvas, text, cx, y, scale);

        self.draw_footer(canvas, text, w, h, scale);
    }

    /// The time and date. Returns the y below what it drew.
    fn draw_clock(
        &self,
        canvas: &mut Canvas<'_>,
        text: &mut TextRenderer,
        cx: f32,
        y: f32,
        scale: f32,
    ) -> f32 {
        let s = |v: f32| v * scale;
        let (time, date) = local_time();

        text.draw(
            canvas,
            &time,
            cx,
            y,
            s(theme::CLOCK_SIZE),
            FontWeight::BOLD,
            theme::TEXT,
            Align::Center,
        );
        let after_clock = y + s(theme::CLOCK_SIZE) * 1.25;
        text.draw(
            canvas,
            &date,
            cx,
            after_clock + s(4.0),
            s(theme::DATE_SIZE),
            FontWeight::NORMAL,
            self.dim(),
            Align::Center,
        );
        after_clock + s(4.0) + s(theme::DATE_SIZE) * 1.25
    }

    /// The avatar and the name.
    fn draw_identity(
        &self,
        canvas: &mut Canvas<'_>,
        text: &mut TextRenderer,
        cx: f32,
        y: f32,
        scale: f32,
    ) -> f32 {
        let s = |v: f32| v * scale;
        let radius = s(theme::AVATAR_RADIUS);
        let center_y = y + radius;

        // A filled disc, then a ring. The ring is the accent, which is the one
        // place on this screen the desktop's colour shows up before you are in
        // the desktop.
        canvas.circle(cx, center_y, radius, theme::SURFACE);
        canvas.circle_outline(
            cx,
            center_y,
            radius,
            s(theme::AVATAR_RING),
            theme::ACCENT.faded(0.55),
        );

        let (initial, name) = match self.current() {
            Some(user) => (user.initial.to_string(), user.display_name.clone()),
            None => ("!".to_string(), "No accounts".to_string()),
        };

        // Vertically centred in the disc by its own line box, not by its
        // baseline: close enough for a single capital, and it does not depend
        // on the font's metrics being sensible.
        let size = s(theme::AVATAR_SIZE);
        text.draw(
            canvas,
            &initial,
            cx,
            center_y - size * 0.62,
            size,
            FontWeight::BOLD,
            theme::ACCENT,
            Align::Center,
        );

        let name_y = center_y + radius + s(18.0);
        text.draw(
            canvas,
            &name,
            cx,
            name_y,
            s(theme::NAME_SIZE),
            FontWeight::BOLD,
            theme::TEXT,
            Align::Center,
        );

        name_y + s(theme::NAME_SIZE) * 1.25
    }

    /// The password field, its dots, and the caret.
    fn draw_field(
        &self,
        canvas: &mut Canvas<'_>,
        text: &mut TextRenderer,
        cx: f32,
        y: f32,
        scale: f32,
        now: Instant,
    ) -> f32 {
        let s = |v: f32| v * scale;
        let width = s(theme::CARD_WIDTH * 0.72);
        let height = s(theme::FIELD_HEIGHT);
        let rect = Rect::new(cx - width / 2.0, y, width, height);

        canvas.rounded_rect(rect, s(theme::FIELD_RADIUS), theme::SURFACE);

        // The border says what state the field is in, and it is the only thing
        // on screen that does: accent when it is ready, error when the last
        // attempt failed, dim while an attempt is in flight.
        let border = if self.busy {
            theme::BORDER
        } else if matches!(
            self.message.as_ref().map(|m| m.kind),
            Some(MessageKind::Error)
        ) {
            theme::ERROR.faded(0.8)
        } else {
            theme::ACCENT.faded(0.7)
        };
        canvas.rounded_rect_outline(rect, s(theme::FIELD_RADIUS), s(theme::FIELD_BORDER), border);

        let center_y = y + height / 2.0;

        // Where the caret goes: at the end of whatever the field is showing.
        // Both branches compute it, because the two share a centre line --
        // drawing the caret at `cx` unconditionally puts it through the middle
        // of the placeholder, so the field reads "Pass|word".
        let caret_x = if self.password.is_empty() && !self.busy {
            // A placeholder rather than an empty box, so it is obvious the
            // field is where typing goes without needing a label above it.
            const PLACEHOLDER: &str = "Password";
            let size = s(theme::BODY_SIZE);
            let width = text.measure(PLACEHOLDER, size, FontWeight::NORMAL);
            text.draw(
                canvas,
                PLACEHOLDER,
                cx,
                center_y - size * 0.62,
                size,
                FontWeight::NORMAL,
                theme::TEXT_DIM,
                Align::Center,
            );
            cx + width / 2.0 + s(5.0)
        } else {
            // The dot count stops at DOT_MAX: a row of dots whose length is
            // readable across a room leaks the password's length to anyone
            // watching, and tells the person typing nothing they did not know.
            let shown = self.password.chars().count().min(theme::DOT_MAX);
            let spacing = s(theme::DOT_SPACING);
            let total = (shown.saturating_sub(1)) as f32 * spacing;
            let start = cx - total / 2.0;
            for i in 0..shown {
                canvas.circle(
                    start + i as f32 * spacing,
                    center_y,
                    s(theme::DOT_RADIUS),
                    theme::TEXT,
                );
            }
            cx + total / 2.0 + spacing * 0.75
        };

        // The caret blinks only while the field is live. A caret still
        // blinking under an attempt in flight reads as "nothing happened".
        if !self.busy && self.throttled_for(now).is_none() {
            let phase = now.duration_since(self.started).as_millis() as u64
                % CARET_PERIOD.as_millis() as u64;
            if phase < CARET_PERIOD.as_millis() as u64 / 2 {
                canvas.rounded_rect(
                    Rect::new(caret_x - s(1.0), center_y - s(9.0), s(2.0), s(18.0)),
                    s(1.0),
                    theme::ACCENT,
                );
            }
        }

        y + height
    }

    /// The line under the field: an error, a caps-lock caution, or the hint.
    fn draw_message(
        &self,
        canvas: &mut Canvas<'_>,
        text: &mut TextRenderer,
        cx: f32,
        y: f32,
        scale: f32,
    ) {
        let s = |v: f32| v * scale;

        // Precedence, and it is deliberate. A real message about the attempt
        // that just failed matters more than a caps-lock caution, which
        // matters more than a hint somebody has already read.
        let (line, color) = if let Some(message) = &self.message {
            (message.text.clone(), message.kind.color())
        } else if self.busy {
            ("Checking…".to_string(), self.dim())
        } else if self.caps_lock {
            ("Caps Lock is on".to_string(), theme::WARNING)
        } else if self.mode == Mode::Lock {
            ("Enter to unlock".to_string(), self.dim())
        } else if self.users.len() > 1 {
            (
                "Enter to log in · Tab to switch account".to_string(),
                self.dim(),
            )
        } else {
            ("Enter to log in".to_string(), self.dim())
        };

        text.draw(
            canvas,
            &line,
            cx,
            y,
            s(theme::SMALL_SIZE),
            FontWeight::NORMAL,
            color,
            Align::Center,
        );
    }

    /// Hostname on the left, distribution on the right.
    fn draw_footer(
        &self,
        canvas: &mut Canvas<'_>,
        text: &mut TextRenderer,
        w: f32,
        h: f32,
        scale: f32,
    ) {
        let s = |v: f32| v * scale;
        let margin = s(28.0);
        let size = s(theme::SMALL_SIZE);
        let y = h - margin - size;

        // On a narrow screen these two would draw straight through each other.
        // Measuring first and dropping the distribution name is the right way
        // round: which machine you are logging in to is the useful half, and
        // the one you cannot work out from looking at the screen.
        let hostname_w = text.measure(&self.hostname, size, FontWeight::NORMAL);
        let os_w = text.measure(&self.os_name, size, FontWeight::NORMAL);
        let fits = hostname_w + os_w + margin * 3.0 <= w;

        text.draw(
            canvas,
            &self.hostname,
            margin,
            y,
            size,
            FontWeight::NORMAL,
            self.dim(),
            Align::Left,
        );
        if fits {
            text.draw(
                canvas,
                &self.os_name,
                w - margin,
                y,
                size,
                FontWeight::NORMAL,
                self.dim(),
                Align::Right,
            );
        }
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

    #[test]
    fn humanize_reads_like_a_countdown() {
        assert_eq!(humanize(Duration::from_secs(12)), "12s");
        assert_eq!(humanize(Duration::from_secs(90)), "1m 30s");
        // Sub-second rounds up rather than saying "0s".
        assert_eq!(humanize(Duration::from_millis(300)), "1s");
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
