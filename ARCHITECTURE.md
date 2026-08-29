# Architecture

This is the reasoning behind the shape of RavenLogin. The README says what it
is; this says why it is not something else.

## The boot path

```
kernel
  └─ raven-init (PID 1)
       ├─ udev            coldplug, so the GPU driver is loaded
       ├─ seatd           so something unprivileged can hold the DRM master
       └─ ravend ─────────────────────────────────────────── root
            │
            │  ┌─ loop ──────────────────────────────────────────────┐
            │  │                                                     │
            ├──┼─ prepare /run/user/<greeter uid>   0700, chowned     │
            ├──┼─ spawn huginn            as raven-greeter            │
            ├──┼─ wait for wayland-N to be bound    (or fail fast)    │
            ├──┼─ spawn raven-greeter     as raven-greeter            │
            │  │                                                      │
            │  │     greeter ── ListUsers ──────────▶ ravend           │
            │  │     greeter ◀─ Users ───────────────                  │
            │  │     greeter ── Wallpaper ──────────▶ ravend           │
            │  │     greeter ◀─ path (never pixels) ─                  │
            │  │       opens and decodes it itself, unprivileged       │
            │  │     greeter ── Authenticate ───────▶ ravend           │
            │  │                                      reads /etc/shadow│
            │  │                                      sha512-crypt     │
            │  │     greeter ◀─ Denied / Granted ────                  │
            │  │                                                      │
            ├──┼─ stop raven-greeter, then huginn   SIGTERM → SIGKILL │
            ├──┼─ prepare /run/user/<user uid>                        │
            ├──┼─ spawn raven-wayland-session  as the authenticated user│
            ├──┼─ wait for it to exit                                 │
            │  └──────────────── back to the top ─────────────────────┘
```

The tear-down before the session starts is not optional and not tidiness. The
greeter's compositor holds the DRM master and the seat. A session compositor
that cannot acquire either fails in a way that looks like a driver problem, and
the two symptoms — "the GPU is broken" and "something else is still holding it"
— are indistinguishable from the console.

## Why the greeter is a layer-shell client

`ext-session-lock-v1` is the protocol designed for a surface that must not be
dismissed, and it is what `raven-lock` uses. It is not used *here*, and the
difference between the two screens is the reason.

A greeter does not need what session-lock provides. The guarantee that
protocol gives is that if the locking client dies, the compositor keeps the
screen locked rather than revealing the session behind it. At login time there
is nothing behind the surface: no session exists. If the greeter dies, `ravend`
notices — it supervises both children in the same loop it accepts on — and
brings the whole login screen back up.

So this surface is not a security boundary the way a lock screen is. It does
not have to be. `ravend` is what enforces who may log in, and it would enforce
it identically if the greeter were replaced with a hostile one.

## The verify socket

`raven-lock` needs what the greeter needs — somebody who can read `/etc/shadow`
and say yes or no — and it must not get it from the socket that already exists.

The greet socket can *start a session*. A lock screen able to reach it could be
talked into starting a session for an account that is not the one it is
holding, which is a way around the lock rather than through it. And that socket
lives in a `0700` directory owned by the greeter, which is right for it and
wrong here: the process asking is the logged-in user's.

So `ravend` binds a second listener, `/run/raven-lock/verify.sock`, on its own
thread — the lock screen's whole life happens inside the `run_session` call the
main loop is blocked in, so it could not be served from there.

**Anyone may connect to it, and that is safe for exactly one reason.** It only
ever answers about the account that owns the connection. The account comes from
`SO_PEERCRED`, which the kernel fills in and the caller cannot forge, and the
`Verify` request carries no username at all — there is no field to put somebody
else's name in. Take that away and this is a password oracle: any local process
could guess at any account, from a socket present on every machine. With it, a
caller can only guess at a password it is already sitting behind.

`Authenticate` is refused on this socket, explicitly and with a test, and
`Verify` and `Whoami` are refused on the greeter's. The two doors do not
overlap. They keep separate rate limiters, so a person who has mistyped at the
lock screen does not find themselves throttled out of a TTY login.

## Why the daemon polls

`ravend`'s accept loop is a non-blocking `accept` with a 100ms sleep, not a
blocking one. That looks like a mistake and is not.

The loop is also the supervisor. If the compositor or the greeter dies, nobody
is looking at a login screen any more, and a blocking `accept` would wait
forever for a connection that is never coming — in front of a black display,
with no way out but the power button. Polling lets the same loop notice.

The honest alternative is a `calloop` event loop with a `pidfd` per child,
which is what huginn does. It is more code, one more dependency, and saves ten
wakeups a second on a process that exists for the thirty seconds somebody
spends typing a password.

## Why a failed login screen is retried, not fatal

`ravend` exits for exactly one class of problem: a precondition it cannot
retry into existence -- a config that does not parse, not being root, no
greeter account, a socket it cannot bind. Everything after that is a child
process, and a child that fails brings the login screen back up after a
backoff (1s, doubling to 10s) with the reason in the log. It never takes the
daemon down.

The reason is how `raven-init` supervises. It restarts a service that exits,
but gives up on one that exits five times in a minute. A greeter that dies in
under a second -- and one pointed at a dead socket does -- hits that limit in
five seconds, after which the machine has no login screen until it is
rebooted. A restart loop inside the daemon has no such limit, and it should
not: there is nobody at the console who can `raven-rc start ravend`, because
the login screen is how they would get there.

The failure that found this is worth recording. A compositor stopped with
`SIGTERM` does not always unlink its socket, and `/run` only empties on reboot.
So when a session ended, `wait_for_wayland_socket` found the previous
compositor's stale `wayland-1` twenty microseconds after spawning the next one
and declared it listening. The greeter connected to a socket nobody held,
exited, the daemon exited, and init restarted it into the same stale file five
times. Two fixes, either sufficient, both kept: `prepare_runtime_dir` removes
every `wayland-*` socket and lock before a compositor is spawned -- nothing
else may bind one there -- and the wait only counts an entry that is actually
a socket.

## Ordering that is load-bearing

Three places where the sequence matters and the wrong one fails quietly:

**Privilege drop: `setgroups`, then `setgid`, then `setuid`.** Each step gives
away privilege the next one needs. `setuid` first is the well-known way to end
up still holding root's supplementary groups. All three happen inside one
`pre_exec` closure rather than through `CommandExt::uid`/`gid`, because `std`
applies the uid and gid it was given *before* running any `pre_exec` closure —
so a closure calling `setgroups` would run after `setuid` had already dropped
the privilege it requires, and fail with `EPERM`. This trap is `raven-init`'s;
`raven-privdrop` repeats the reasoning because the two live in different
repositories.

**Runtime directory: `0700`, then `chown`.** Created owned by root and locked
down before it is handed over, so it is private for its whole existence.
Chowning first leaves a window in which the account owns a directory that has
not been locked down yet.

**Socket: `bind`, then `chmod`, then `chown`.** `bind` respects the umask, so
the permissions are set explicitly afterwards rather than hoped for.

## Timing

An account that does not exist must not answer faster than one that does.

The honest implementation returns immediately when `/etc/passwd` has no such
name — in a few microseconds, against the ~4ms that 5000 rounds of SHA-512 cost
for an account that does exist. Two orders of magnitude is trivially measurable
over a socket, and it turns the login screen into an oracle for which accounts
are real.

So `raven-auth` does the work anyway, against a fixed hash, on every path that
would otherwise return early: no such user, locked, expired, `nologin`. The
result is discarded through `black_box`, so the optimizer cannot notice it is
unused and delete the only thing the function does.

That constant is silently breakable — mistype it and `verify` rejects it as
malformed in microseconds, restoring exactly the oracle it exists to remove,
with no test failing. So there is a test asserting it is a hash that actually
gets computed, and another asserting a missing account is not measurably
faster than a real one.

This matters less than it sounds for a screen somebody is typing at, and it
costs nothing to get right.

## What the greeter is told

The greeter renders `Response::Denied { message }` verbatim. It has no policy of
its own about what may be said, because two places deciding that is one place
too many.

`ravend` decides. `raven-auth::Denial::is_safe_to_display` is the whole rule:
an expired password, an account expiry, a must-change flag and an unsupported
hash are shown as themselves, because each sends the person somewhere
different. Everything else — wrong password, no such account, locked, `nologin`,
root refused — collapses to "Incorrect password."

Not to prevent account enumeration: a greeter that draws a list of faces has
already conceded that. Because "that account is locked" tells somebody who is
not the account's owner something they have no use for, and tells the owner
nothing they can act on either. The real reason goes to the log every time, so
"it just says wrong password" is always diagnosable.

## Testing what cannot be booted

Most of this runs as root, in front of a GPU, on a machine that has just
started. Almost none of that is in the code under test:

- `raven-crypt` is pure, and cross-checked against libxcrypt on 40 vectors.
- `raven-auth` takes its file paths and its clock as arguments, so account
  expiry, password aging and the `!`/`*`/empty hash cases are all ordinary
  unit tests. No test waits for a day to pass.
- `ratelimit` takes `Instant` as an argument. No test sleeps.
- `ui` separates state from drawing, so every keystroke path is testable with
  no Wayland connection, and `draw` is smoke-tested at absurd sizes and
  fractional scales because a greeter that panics on an odd screen shows nobody
  a prompt.
- `--preview` renders a real frame to a PNG on any host, optionally over a
  `--wallpaper`. It refuses to overwrite a file it did not write.

What is left untested by construction is the privilege drop itself, which needs
root to exercise, and the Wayland glue. `raven-privdrop` covers the half it can:
that an unprivileged process trying to drop to another uid fails at spawn rather
than silently exec'ing with the wrong credentials.
