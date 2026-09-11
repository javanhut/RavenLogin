//! Springs: how anything on the screen gets from where it is to where it is
//! going.
//!
//! Every value that moves on the login screen is a [`Spring`], and nothing is
//! a timeline. The difference is what happens when the target changes halfway
//! through: a timeline restarts from its beginning, or jumps to its end, and
//! either way the screen visibly hiccups. A spring already knows where the
//! value is and how fast it is moving, so a new target just bends the path.
//! Type a character while the previous one is still popping in, submit while
//! the caps-lock line is still fading — nothing waits, nothing snaps.
//!
//! # Parameters
//!
//! Not mass, stiffness and damping. Those are the physics, and nobody designs
//! in them. A spring here is described the way Apple's are:
//!
//! - **response**, in seconds: roughly how long the value takes to arrive.
//!   Smaller is snappier. It is the period of the underlying oscillator, which
//!   is why it is *roughly* and not exactly a duration -- a spring has no
//!   fixed duration; its settle time falls out of the parameters.
//! - **damping ratio**: `1.0` arrives without overshooting, which is what
//!   almost everything wants. Below `1.0` the value overshoots and rings, and
//!   the further below, the longer it rings. That is reserved for the one
//!   motion here that *should* ring, which is the shake.
//!
//! The mapping is the standard one: stiffness `k = (2π / response)²` for unit
//! mass, damping `c = 2ζ√k`.
//!
//! # Integration
//!
//! Semi-implicit Euler in fixed sub-steps, because the frame interval is
//! whatever the compositor gives and a stiff spring stepped once across a
//! long frame explodes. Sub-steps are cheap -- there are a dozen springs on
//! the whole screen -- and stable for every response used here.

use std::time::Duration;

/// How a spring moves: its response and its damping ratio.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Motion {
    /// Roughly how long the value takes to arrive, in seconds.
    pub response: f32,
    /// `1.0` arrives without overshooting; less rings.
    pub damping: f32,
}

impl Motion {
    /// A critically damped spring with the given response.
    #[must_use]
    pub const fn smooth(response: f32) -> Self {
        Self {
            response,
            damping: 1.0,
        }
    }

    /// A spring that rings: under-damped, for motion that should oscillate.
    #[must_use]
    pub const fn bouncy(response: f32, damping: f32) -> Self {
        Self { response, damping }
    }
}

/// The largest sub-step the integrator takes.
///
/// 1/240 s: four sub-steps per 60 Hz frame, sixteen per frame when the frame
/// interval is the 100 ms clamp. Stable for a response of 0.1 s, which is
/// snappier than anything on the screen.
const SUB_STEP: f32 = 1.0 / 240.0;

/// A frame longer than this is treated as this long.
///
/// After a suspend, a stalled compositor, or a laptop lid, the first frame
/// back can be seconds or hours late. Springs stepped across that arrive
/// instantly, which is right; the clamp is so the integrator does not spin
/// through millions of sub-steps to find that out.
const MAX_FRAME: f32 = 0.1;

/// Below this, in value and in velocity, the spring is at rest.
const REST: f32 = 0.0005;

/// A value that moves toward its target like a mass on a spring.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spring {
    value: f32,
    velocity: f32,
    target: f32,
    motion: Motion,
}

impl Spring {
    /// A spring at rest at `value`, which is also its target.
    #[must_use]
    pub const fn at(value: f32, motion: Motion) -> Self {
        Self {
            value,
            velocity: 0.0,
            target: value,
            motion,
        }
    }

    /// Where the value is right now.
    #[must_use]
    pub const fn value(&self) -> f32 {
        self.value
    }

    /// Where the value is going.
    #[must_use]
    pub const fn target(&self) -> f32 {
        self.target
    }

    /// How fast the value is moving, in units per second.
    #[must_use]
    pub const fn velocity(&self) -> f32 {
        self.velocity
    }

    /// Head toward `target` from wherever the value currently is, keeping its
    /// current velocity. This is what makes a retarget mid-flight continuous.
    pub fn set_target(&mut self, target: f32) {
        self.target = target;
    }

    /// Head toward `target` under a different motion. The value and velocity
    /// are kept; only the path changes.
    pub fn retarget(&mut self, target: f32, motion: Motion) {
        self.target = target;
        self.motion = motion;
    }

    /// Jump to `value` and stop. For the first frame, and for reduced motion.
    pub fn snap(&mut self, value: f32) {
        self.value = value;
        self.target = value;
        self.velocity = 0.0;
    }

    /// Add `velocity` to the current velocity, in units per second.
    ///
    /// A kick with the target unchanged is how the shake works: the field is
    /// shoved sideways and the spring brings it back, ringing as it does.
    pub fn kick(&mut self, velocity: f32) {
        self.velocity += velocity;
    }

    /// Whether the spring has arrived and stopped.
    #[must_use]
    pub fn settled(&self) -> bool {
        (self.value - self.target).abs() < REST && self.velocity.abs() < REST
    }

    /// Advance by `dt`. A settled spring is left exactly at its target.
    pub fn step(&mut self, dt: Duration) {
        if self.settled() {
            self.value = self.target;
            self.velocity = 0.0;
            return;
        }

        let mut remaining = dt.as_secs_f32().clamp(0.0, MAX_FRAME);
        let omega = std::f32::consts::TAU / self.motion.response.max(0.01);
        let stiffness = omega * omega;
        let damping = 2.0 * self.motion.damping.max(0.0) * omega;

        while remaining > 0.0 {
            let h = remaining.min(SUB_STEP);
            remaining -= h;

            let displacement = self.value - self.target;
            let acceleration = -stiffness * displacement - damping * self.velocity;
            self.velocity += acceleration * h;
            self.value += self.velocity * h;
        }

        if self.settled() {
            self.value = self.target;
            self.velocity = 0.0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(spring: &mut Spring, seconds: f32) {
        let frame = Duration::from_millis(16);
        let frames = (seconds / 0.016).ceil() as usize;
        for _ in 0..frames {
            spring.step(frame);
        }
    }

    #[test]
    fn a_smooth_spring_arrives_without_overshooting() {
        let mut s = Spring::at(0.0, Motion::smooth(0.3));
        s.set_target(1.0);
        let mut peak = 0.0_f32;
        for _ in 0..120 {
            s.step(Duration::from_millis(16));
            peak = peak.max(s.value());
        }
        assert!(s.settled(), "value {} velocity {}", s.value(), s.velocity());
        assert_eq!(s.value(), 1.0);
        assert!(peak <= 1.0 + 1e-4, "overshot to {peak}");
    }

    /// The response is roughly the time to arrive: a 0.3 s spring is most of
    /// the way there at 0.3 s and settled well before a second.
    #[test]
    fn response_is_roughly_the_arrival_time() {
        let mut s = Spring::at(0.0, Motion::smooth(0.3));
        s.set_target(1.0);
        run(&mut s, 0.3);
        assert!(s.value() > 0.8, "only at {} after one response", s.value());
        run(&mut s, 0.7);
        assert!(s.settled());
    }

    #[test]
    fn a_bouncy_spring_rings_and_then_stops() {
        let mut s = Spring::at(0.0, Motion::bouncy(0.2, 0.3));
        s.kick(500.0);
        let mut crossings = 0;
        let mut last = s.value();
        for _ in 0..240 {
            s.step(Duration::from_millis(16));
            if (s.value() > 0.0) != (last > 0.0) && s.value().abs() > 0.01 {
                crossings += 1;
            }
            last = s.value();
        }
        assert!(crossings >= 2, "a shake should cross zero more than once");
        assert!(s.settled(), "but it must come to rest");
    }

    /// The whole point: a new target while moving does not jump.
    #[test]
    fn retargeting_mid_flight_is_continuous() {
        let mut s = Spring::at(0.0, Motion::smooth(0.3));
        s.set_target(1.0);
        run(&mut s, 0.1);
        let before = s.value();
        s.set_target(0.0);
        s.step(Duration::from_millis(16));
        assert!(
            (s.value() - before).abs() < 0.1,
            "jumped from {before} to {}",
            s.value()
        );
    }

    /// A frame after a suspend can be hours long. It must land the spring,
    /// not hang the integrator.
    #[test]
    fn an_enormous_frame_lands_the_spring() {
        let mut s = Spring::at(0.0, Motion::smooth(0.3));
        s.set_target(1.0);
        s.step(Duration::from_secs(3600));
        assert!(s.value() > 0.0);
        run(&mut s, 1.0);
        assert!(s.settled());
    }

    #[test]
    fn a_snapped_spring_is_settled() {
        let mut s = Spring::at(0.0, Motion::smooth(0.3));
        s.set_target(1.0);
        s.snap(1.0);
        assert!(s.settled());
        assert_eq!(s.value(), 1.0);
    }
}
