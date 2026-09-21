//! Faces: what `ravend` lets them do, and the conversations that carry them.
//!
//! The camera is root's. `raven-faced` drives it and answers one question --
//! whose stored face, if anybody's, is in front of it -- and this module
//! decides what that answer is worth, the way [`crate::finger`] does for the
//! reader and the rest of `ravend` does for a password. Nothing unprivileged
//! reaches the camera except through here, and no image ever comes back
//! through here: see [`raven_face::camera`].
//!
//! # Who may ask what
//!
//! Exactly as for a finger. On the verify socket everything is about the
//! connection's own account, resolved from `SO_PEERCRED`. On the greet socket
//! there is one request, [`Request::LoginByFace`], and it names the account
//! because at the login screen there is nobody logged in to be the
//! connection's owner. The name only chooses whose templates count.
//!
//! # The liveness gate
//!
//! This module refuses a watch that cannot run the challenge.
//!
//! A camera that sees visible light cannot tell a face from a photograph of
//! one, and the anti-spoofing model narrows that gap without closing it. What
//! closes it is the screen: `raven-faced` picks colours, the screen in front of
//! the person paints them, and the daemon checks the face reflects what it
//! asked for. A client that will not do that is refused here rather than
//! quietly let past with a weaker check -- an optional liveness check is not
//! one.
//!
//! The exception is an infrared camera, which sees warmth and so is not fooled
//! by a picture in the first place. On a machine with one, a client that
//! cannot flash is still served.
//!
//! [`Request::LoginByFace`]: raven_greet_proto::Request::LoginByFace

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use raven_auth::{Account, Authenticator};
use raven_face::camera::{EnrolEvent, Faced, Watch, WatchEvent};
use raven_face::{policy, spoof_advice};
use raven_greet_proto::{Camera, FacePolicy, Response, Wash};

use crate::bio::{self, Follow, Use, send};

/// How long the calls that answer at once may wait on `raven-faced`.
///
/// It serves one connection at a time, so a screen holding the camera makes
/// every other caller wait. A settings panel asking for status should be told
/// the camera is busy, not hang. The same twelve seconds [`crate::finger`]
/// gives the reader, and for the same reason: a daemon opening a slow device
/// should be waited for rather than reported busy on every request.
const QUICK: Duration = Duration::from_secs(12);

fn connect_quick() -> std::io::Result<Option<Faced>> {
    let faced = Faced::connect()?;
    if let Some(faced) = &faced {
        faced.set_read_timeout(Some(QUICK))?;
    }
    Ok(faced)
}

/// [`Response::FaceStatus`] for `account`.
pub(crate) fn status(account: &str) -> Response {
    let policy = policy::load(account);
    let (camera, looks) = match connect_quick() {
        Ok(None) => (Camera::NoService, Vec::new()),
        Ok(Some(mut faced)) => match faced.status() {
            Ok(camera) if camera.is_present() => {
                let looks = faced.looks_of(account).unwrap_or_else(|e| {
                    tracing::warn!("cannot list faces: {e}");
                    Vec::new()
                });
                (camera, looks)
            }
            Ok(camera) => (camera, Vec::new()),
            Err(e) => return busy_or_broken(&e),
        },
        Err(e) => return busy_or_broken(&e),
    };
    Response::FaceStatus {
        camera,
        looks,
        policy,
    }
}

fn busy_or_broken(e: &std::io::Error) -> Response {
    tracing::warn!("cannot reach raven-faced: {e}");
    let message = if matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        "The camera is busy. Try again in a moment."
    } else if e.kind() == std::io::ErrorKind::Other {
        // `raven-faced` answered, with an `error` line: the daemon is fine and
        // the camera is what failed.
        "The camera is not responding. Try again in a moment."
    } else {
        "The face unlock service is not answering."
    };
    Response::Failed {
        message: message.to_string(),
    }
}

/// Forget one of `account`'s looks, or all of them with `None`.
///
/// Never anybody else's, in either case. `raven-faced` keeps each account's
/// templates in its own place and takes the account in the request, so there
/// is no counterpart here of the fingerprint sensor's "clear the whole chip":
/// the removal that a reader without a per-finger delete forces on
/// [`crate::finger::forget`] has no analogue on a camera.
pub(crate) fn forget(account: &str, look: Option<u8>) -> Response {
    let mut faced = match connect_quick() {
        Ok(Some(faced)) => faced,
        Ok(None) => {
            return Response::Failed {
                message: "The face unlock service is not running.".to_string(),
            };
        }
        Err(e) => return busy_or_broken(&e),
    };
    if let Err(e) = faced.forget(account, look) {
        tracing::warn!(user = %account, ?look, "cannot forget a face: {e}");
        return Response::Failed {
            message: match look {
                Some(id) => format!("Could not remove face {id}. {e}"),
                None => format!("Could not remove the stored faces. {e}"),
            },
        };
    }
    tracing::info!(user = %account, ?look, "forgot a face");

    // With nothing left to present, every switch is off. Leaving them on would
    // mean enrolling one face later quietly brought back a login somebody had
    // forgotten they ever turned on.
    if faced.looks_of(account).is_ok_and(|left| left.is_empty())
        && let Err(e) = policy::remove(account)
    {
        tracing::warn!(user = %account, "cannot clear the face policy: {e}");
    }
    drop(faced);
    status(account)
}

/// Store where `account`'s face may be used. The caller has already checked
/// the password if this widens anything.
pub(crate) fn set_policy(account: &str, next: FacePolicy) -> Response {
    if let Err(e) = policy::save(account, next) {
        tracing::error!(user = %account, "cannot save the face policy: {e}");
        return Response::Failed {
            message: "Could not save the face unlock settings.".to_string(),
        };
    }
    tracing::info!(
        user = %account,
        login = next.login,
        unlock = next.unlock,
        "face policy changed"
    );
    status(account)
}

/// Something to show under the field, with no flash attached.
fn message(text: &str) -> Response {
    Response::Face {
        message: text.to_string(),
        progress: None,
        flash: None,
    }
}

/// Something to do about the wash and nothing to say. The screen changes; the
/// words under the field do not.
///
/// Passed through from `raven-faced` rather than decided here. `ravend` has no
/// opinion about the sequence and must not: it is the daemon on the far side
/// that knows what it asked for and will check what came back, and a colour
/// this process substituted would fail that check.
fn wash(wash: Wash) -> Response {
    Response::Face {
        message: String::new(),
        progress: None,
        flash: Some(wash),
    }
}

/// The screen is done with the challenge, so stop painting.
///
/// Sent whatever the verdict was, and sent before it, because a screen left
/// washed in the last colour of a sequence is a screen somebody is looking at
/// wondering why it is green.
fn stop_flashing() -> Response {
    Response::Face {
        message: String::new(),
        progress: None,
        flash: Some(Wash::Off),
    }
}

fn unavailable(reason: &str) -> Response {
    Response::FaceUnavailable {
        reason: reason.to_string(),
    }
}

/// How long a watch waits for a camera that is not there yet.
///
/// A USB camera drops off the bus across a suspend and takes a few seconds to
/// come back, and the lock screen is started the instant the lid opens -- so
/// the first question it asks is answered "No such device". The same thirty
/// seconds [`crate::finger`] waits, for the same reason.
const READY_WAIT: Duration = Duration::from_secs(30);

/// How often to look again while waiting.
const READY_POLL: Duration = Duration::from_millis(500);

/// Failures in a row, each within [`READY_WAIT`] of the last good start, that
/// end a watch.
const MAX_REBINDS: u8 = 3;

/// What waiting for the camera came to.
enum Ready {
    Camera(Faced),
    /// Not offered, and not worth waiting for; the reason is for the client.
    Unavailable(&'static str),
    /// The client hung up while waiting.
    Gone,
}

/// Connect to `raven-faced` and check that this watch can actually happen:
/// that there is a camera, that the models are loaded, that `account` has a
/// face to offer, and that the screen asking can run the liveness challenge.
///
/// Nothing is sent to the client meanwhile: the screen says nothing about the
/// camera until the camera can be used.
fn ready_camera(account: &str, will_flash: bool, follow: &Follow) -> Ready {
    let deadline = Instant::now() + READY_WAIT;
    let mut logged = false;
    loop {
        let reason = match connect_quick() {
            Ok(Some(mut faced)) => match faced.status() {
                // The gate. An ordinary camera with a screen that will not
                // paint has no liveness check worth the name, so it is not
                // offered at all rather than offered weakened.
                Ok(Camera::Present { infrared, .. }) if !infrared && !will_flash => {
                    tracing::warn!(
                        user = %account,
                        "refused a face watch: the client will not run the liveness challenge"
                    );
                    return Ready::Unavailable("this screen cannot run the liveness check");
                }
                Ok(Camera::Present { .. }) => match faced.looks_of(account) {
                    Ok(looks) if !looks.is_empty() => return Ready::Camera(faced),
                    // Nothing to wait for: enrolling one takes the settings
                    // panel, and the password.
                    Ok(_) => return Ready::Unavailable("no face is enrolled"),
                    Err(e) => {
                        if !logged {
                            tracing::warn!(user = %account, "cannot list faces: {e}; waiting for the camera");
                        }
                        "the camera is not answering"
                    }
                },
                // A machine with no models will not grow any while somebody
                // stands at the login screen, so this does not wait.
                Ok(Camera::NoModel { why }) => {
                    tracing::warn!(user = %account, "face unlock has no models: {why}");
                    return Ready::Unavailable("the face recognition models are not installed");
                }
                Ok(Camera::Absent) => "there is no camera",
                Ok(Camera::NoService) => "the face unlock service is not running",
                Err(e) => {
                    if !logged {
                        tracing::warn!("cannot ask raven-faced for its status: {e}; waiting");
                    }
                    "the camera is not answering"
                }
            },
            Ok(None) => "the face unlock service is not running",
            Err(e) => {
                if !logged {
                    tracing::warn!("cannot reach raven-faced: {e}; waiting for it");
                }
                "the face unlock service is not answering"
            }
        };
        logged = true;
        if Instant::now() >= deadline {
            tracing::warn!(user = %account, "gave up waiting for the camera: {reason}");
            return Ready::Unavailable(reason);
        }
        std::thread::sleep(READY_POLL);
        if follow.is_gone() {
            return Ready::Gone;
        }
    }
}

/// Watch the camera for `account` and send the conversation down `writer`.
///
/// Returns the admitted account on a match, for the login screen to start a
/// session with. The connection is shut down before this returns, whatever
/// happened: a watch is one conversation, and the thread following the client
/// has to be woken so it can go.
///
/// `will_flash` is the client's claim about the screen in front of the person.
/// It is not trusted -- `raven-faced` tests it against what the camera sees --
/// but a client that does not even claim it is turned away here, because on a
/// machine without an infrared camera there is nothing else good enough.
///
/// `claim` is asked once, after a match and before the success is sent, so
/// that a face and a password arriving in the same instant cannot both start a
/// session.
pub(crate) fn watch<W: Write>(
    account: &str,
    purpose: Use,
    will_flash: bool,
    authenticator: &Authenticator,
    client: &UnixStream,
    writer: &mut W,
    claim: impl FnOnce() -> bool,
) -> Option<Account> {
    let admitted = watch_inner(
        account,
        purpose,
        will_flash,
        authenticator,
        client,
        writer,
        claim,
    );
    let _ = writer.flush();
    let _ = client.shutdown(std::net::Shutdown::Both);
    admitted
}

fn watch_inner<W: Write>(
    account: &str,
    purpose: Use,
    will_flash: bool,
    authenticator: &Authenticator,
    client: &UnixStream,
    writer: &mut W,
    claim: impl FnOnce() -> bool,
) -> Option<Account> {
    if !purpose.allowed_by_face(policy::load(account)) {
        send(writer, &unavailable("face unlock is not turned on for this"));
        return None;
    }
    let follow = match bio::follow_client(client, "face-hangup") {
        Ok(follow) => follow,
        Err(e) => {
            tracing::warn!("cannot follow the face client: {e}");
            send(
                writer,
                &unavailable("the login service is short of resources"),
            );
            return None;
        }
    };

    let mut rebinds: u8 = 0;
    loop {
        let allowed = bio::face_strikes().left(account, Instant::now());
        if allowed == 0 {
            send(
                writer,
                &unavailable("your face was not recognised enough times; use the password"),
            );
            return None;
        }

        let mut faced = match ready_camera(account, will_flash, &follow) {
            Ready::Camera(faced) => faced,
            Ready::Unavailable(reason) => {
                send(writer, &unavailable(reason));
                return None;
            }
            Ready::Gone => {
                tracing::debug!(user = %account, "the face client hung up while waiting");
                return None;
            }
        };
        // From here the wait has no deadline: a lock screen sits overnight.
        if faced.set_read_timeout(None).is_err() {
            send(writer, &unavailable("the camera is not answering"));
            return None;
        }
        match faced.hangup_handle() {
            Ok(hangup) => {
                if !follow.attach(hangup) {
                    return None;
                }
            }
            Err(e) => {
                tracing::warn!("cannot follow the face client: {e}");
                send(
                    writer,
                    &unavailable("the login service is short of resources"),
                );
                return None;
            }
        }

        tracing::info!(user = %account, ?purpose, "watching the camera");
        send(writer, &message("Look at the camera."));
        let started = Instant::now();

        let verdict = faced.watch(account, allowed, will_flash, |event| match event {
            WatchEvent::Wash(w) => send(writer, &wash(w)),
            WatchEvent::Retry(advice) => send(writer, &message(advice)),
            WatchEvent::Miss { .. } => {
                bio::face_strikes().miss(account, Instant::now());
                send(writer, &message("Not recognised. Try again."));
            }
            WatchEvent::Spoof { .. } => {
                bio::face_strikes().miss(account, Instant::now());
                // Logged as what it was. The model behind this has a false
                // positive rate and lands on the owner in bad light more often
                // than on anybody holding up a photograph -- but the times it
                // is right are the times somebody wants a record of.
                tracing::warn!(user = %account, ?purpose, "a face failed the liveness check");
                send(writer, &message(spoof_advice()));
            }
        });

        match verdict {
            Ok(Watch::Matched(which)) => {
                send(writer, &stop_flashing());
                let how = which.map_or_else(|| "an unnumbered look".to_string(), |id| format!("look {id}"));
                return bio::admit(
                    account,
                    purpose,
                    &how,
                    bio::face_strikes,
                    authenticator,
                    writer,
                    claim,
                );
            }
            Ok(Watch::Missed { spoofed }) => {
                send(writer, &stop_flashing());
                bio::face_strikes().miss(account, Instant::now());
                tracing::warn!(user = %account, ?purpose, spoofed, "face not recognised; watch over");
                send(
                    writer,
                    &Response::Denied {
                        message: if spoofed {
                            format!("{} Enter your password.", spoof_advice())
                        } else {
                            "Face not recognised. Enter your password.".to_string()
                        },
                        retry_after_ms: 0,
                    },
                );
                return None;
            }
            Ok(Watch::Cancelled) if follow.is_gone() => {
                tracing::debug!(user = %account, "the face client hung up");
                return None;
            }
            // The camera or its daemon went away under the watch -- a suspend,
            // a USB reset, `raven-faced` restarting. Wait for it to come back
            // rather than leaving the screen password-only.
            Ok(Watch::Cancelled) | Err(_) => {
                if let Err(e) = &verdict {
                    tracing::warn!(user = %account, "the face watch failed: {e}");
                }
                send(writer, &stop_flashing());
                if started.elapsed() > READY_WAIT {
                    rebinds = 0;
                }
                rebinds += 1;
                if rebinds > MAX_REBINDS {
                    send(
                        writer,
                        &Response::Failed {
                            message: "The camera stopped responding.".to_string(),
                        },
                    );
                    return None;
                }
                tracing::info!(user = %account, "reconnecting to the camera");
            }
        }
    }
}

/// Enrol another of `account`'s looks, streaming progress down `writer`. The
/// caller has checked the password. Shuts the connection down when done.
pub(crate) fn enrol<W: Write>(
    account: &str,
    label: &str,
    will_flash: bool,
    client: &UnixStream,
    writer: &mut W,
) {
    enrol_inner(account, label, will_flash, client, writer);
    let _ = writer.flush();
    let _ = client.shutdown(std::net::Shutdown::Both);
}

fn enrol_inner<W: Write>(
    account: &str,
    label: &str,
    will_flash: bool,
    client: &UnixStream,
    writer: &mut W,
) {
    let failed = |writer: &mut W, text: &str| {
        send(
            writer,
            &Response::Failed {
                message: text.to_string(),
            },
        );
    };
    let mut faced = match connect_quick() {
        Ok(Some(faced)) => faced,
        Ok(None) => return failed(writer, "The face unlock service is not running."),
        Err(e) => {
            if let Response::Failed { message } = busy_or_broken(&e) {
                failed(writer, &message);
            }
            return;
        }
    };
    match faced.status() {
        Ok(camera) if camera.is_present() => {}
        Ok(Camera::NoModel { why }) => {
            tracing::warn!(user = %account, "cannot enrol a face: {why}");
            return failed(writer, "Face unlock is not set up on this machine.");
        }
        Ok(_) => return failed(writer, "There is no camera on this machine."),
        Err(e) => {
            if let Response::Failed { message } = busy_or_broken(&e) {
                failed(writer, &message);
            }
            return;
        }
    }
    match faced.looks_of(account) {
        Ok(looks) if looks.len() >= usize::from(raven_greet_proto::MAX_LOOKS) => {
            return failed(
                writer,
                "There is no room for another face. Remove one first.",
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(user = %account, "cannot list faces before enrolling: {e}");
            return failed(writer, "The camera is not responding. Try again in a moment.");
        }
    }
    if faced.set_read_timeout(None).is_err() {
        return failed(writer, "The camera is not answering.");
    }
    let follow = match bio::follow_client(client, "face-hangup") {
        Ok(follow) => follow,
        Err(_) => return failed(writer, "The login service is short of resources."),
    };
    match faced.hangup_handle() {
        Ok(hangup) => {
            if !follow.attach(hangup) {
                return;
            }
        }
        Err(_) => return failed(writer, "The login service is short of resources."),
    }

    tracing::info!(user = %account, "enrolling a face");
    send(writer, &message("Look at the camera."));
    let result = faced.enrol(account, label, will_flash, |event| match event {
        EnrolEvent::Wash(w) => send(writer, &wash(w)),
        EnrolEvent::Progress(progress) => {
            let text = match progress.retry {
                Some(advice) => advice.to_string(),
                None if progress.done >= progress.of => "Got it.".to_string(),
                None => "Keep looking at the camera.".to_string(),
            };
            send(
                writer,
                &Response::Face {
                    message: text,
                    progress: Some((progress.done, progress.of)),
                    flash: None,
                },
            );
        }
    });
    send(writer, &stop_flashing());
    match result {
        Ok(Some(look)) => {
            tracing::info!(user = %account, id = look.id, "enrolled a face");
            send(writer, &Response::FaceEnrolled { look });
        }
        Ok(None) if follow.is_gone() => {
            tracing::info!(user = %account, "face enrolment cancelled");
        }
        Ok(None) => failed(writer, "The camera stopped responding."),
        Err(e) => {
            tracing::warn!(user = %account, "face enrolment failed: {e}");
            // raven-faced's reasons are written for people -- "no face was in
            // view for long enough" -- and name nothing about anybody else, so
            // they are safe to pass on.
            let why = e.to_string();
            let mut why = why.trim().to_string();
            if let Some(first) = why.get(..1) {
                why = first.to_uppercase() + &why[1..];
            }
            failed(writer, &format!("{why}."));
        }
    }
}
