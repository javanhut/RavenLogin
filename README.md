# RavenLogin

The login screen for [RavenLinux](../RavenLinux), and the daemon behind it.

```
        ╭──────╮
        │  J   │        04:29
        ╰──────╯        Thursday, 27 August
     Javan Hutchinson
   ┌────────────────────┐
   │  ● ● ● ● ● ● ●│    │
   └────────────────────┘
      Enter to log in
```

Before this, `raven-init` read the lowest-uid regular account out of
`/etc/passwd` and started its session with no password prompt anywhere in the
path. That is the right behaviour for an image you are bringing up and the
wrong one for a machine you use. RavenLogin is the password prompt.

| Binary | What it is |
|---|---|
| `ravend` | the login daemon: reads `/etc/shadow`, starts sessions. Runs as root. |
| `raven-greeter` | the login screen: a Wayland client. Runs as `raven-greeter`. |
| `raven-lock` | the lock screen: the same screen, for a session that already exists. Runs as the person logged in. |
| `raven-ui` | what both screens are drawn with. A library; no Wayland, no sockets. |

## The lock screen

`raven-lock` is here rather than in RavenGUI because it is the login screen
again. Same layout, same colours, same field, same code — `raven-ui` is the
crate both of them draw with, and the only differences are two words of copy
and the absence of an account to switch to.

That is not tidiness. A lock screen is the other moment a machine asks its
owner for their password, and if it is a near-miss of the login screen — the
avatar a few pixels off, the hint reworded, a slightly different blue — then
what it teaches is that near-misses are normal. Making them the same code is
the only way to guarantee they cannot drift.

What differs is underneath. The greeter draws an `wlr-layer-shell` overlay;
`raven-lock` is an `ext-session-lock-v1` client, because there *is* a session
behind it and the protocol's guarantee — if the locking client dies, the
compositor keeps the screen locked rather than revealing the desktop — is the
whole point. And it authenticates on a different socket, which cannot start a
session and answers only about the account that owns the connection. See
[the verify socket](#the-verify-socket) below.

## The split

The interesting decision in a login screen is not what it looks like. It is
which process is allowed to read the password file.

A greeter draws text. Drawing text means parsing font files, rasterizing
glyphs, decoding images and writing into a buffer the compositor also maps —
which is, near enough, a list of everything that has ever been remotely
exploitable in a login screen. The password hashes should not be in that
process.

So they are not:

```
raven-init
  └─ ravend                     root. No GPU, no fonts, no image decoding,
       │                        no Wayland client library at all.
       ├─ huginn                uid raven-greeter
       │    └─ raven-greeter    uid raven-greeter — draws, and can ask one
       │                        question over a Unix socket
       ├─ reads /etc/shadow, checks the password
       └─ on success: setgroups → setgid → setuid → the session
```

`ravend` links no drawing code. `raven-greeter` can read no hashes, start no
session, and become nobody. The socket between them is `0600`, in a `0700`
directory owned by the greeter, and `ravend` checks `SO_PEERCRED` on every
connection anyway — the permissions are a property of a path, which a packaging
change can get wrong; the peer's uid is a property of the connection, which it
cannot.

**There is no "authenticated" state between messages.** `Authenticate` carries
the password, and on success `ravend` starts the session itself. greetd splits
these into authenticate-then-start, and that split is what makes it flexible: a
greeter can authenticate and then choose a session. It also means the daemon
holds "this connection is X" across a message boundary, and every such state is
something that can be reached the wrong way — authenticate as one user and
start a session as another, or authenticate and start a session an hour later.
Raven ships one session, so the flexibility buys nothing, and collapsing the
two requests deletes the state and the whole class of bug with it.

## The crates

```
crates/
├── raven-crypt/        ★ crypt(3) verification. Pure. Tested against libxcrypt.
├── raven-auth/         ★ /etc/passwd, /etc/shadow, and who may log in
├── raven-greet-proto/  ★ the wire protocol. Pure.
├── raven-privdrop/     ⚠ the only crate permitted `unsafe`
├── ravend/               the daemon
└── raven-greeter/        the login screen
```

★ marks a crate with no I/O in its core, testable on any host — including one
that cannot build a compositor.

### Passwords are checked in Rust, not by libcrypt

`raven-crypt` implements sha512-crypt (`$6$`) directly. RavenLinux sets
`ENCRYPT_METHOD SHA512` in `login.defs`, so that is what `passwd` writes, and
it is a fully specified algorithm that fits in one readable file.

Linking libxcrypt would answer every hash format, at the cost of putting a C
library on the critical path of a distro whose base is deliberately
dependency-free — and of making logging in depend on a shared object being
present and correct before anybody can log in to fix it.

The tradeoff is honest rather than hidden: a hash this cannot compute returns
`Unsupported`, never `Mismatch`. Telling somebody "incorrect password" when the
truth is "this build cannot read your hash" sends them looking in exactly the
wrong place. If you migrate an account from an Arch install, its `$y$`
(yescrypt) hash will need `passwd` run once to re-hash it, and the login screen
will say so by name.

Correctness is not taken on trust. `crates/raven-crypt/tests/` cross-checks
forty password/salt pairs against the system's own `crypt(3)`, spread across
lengths 1..130 — sha512-crypt's input schedule depends on the password's length
in three separate places, so a transcription error typically produces a hash
that is right for some lengths and wrong for others. One vector proves almost
nothing.

### One `unsafe` crate, and why it exists

`unsafe_code = "forbid"` is set workspace-wide and inherited by every crate.
`raven-privdrop` is the single exception, following RavenGUI's `huginn-egl`
pattern, and `scripts/check-unsafe.sh` proves no other manifest has quietly
dropped the opt-in.

It contains three syscalls: `setgroups`, `setgid`, `setuid`. There is no safe
way to make them on stable Rust. `CommandExt::uid`/`gid` are safe and set only
the primary ids — but the *supplementary* groups are the ones that matter here,
because `video` and `render` are what let a session open the GPU and `input` is
what lets it read the keyboard. `CommandExt::groups` would do exactly this and
is still unstable ([rust#90747]). `rustix` deliberately does not wrap any of
the three. Shelling out to `setpriv(1)` was rejected for the same reason
libpam was: it puts a binary that must exist, and must be the right one, between
a person and their own machine.

[rust#90747]: https://github.com/rust-lang/rust/issues/90747

## Seeing it without booting

```
cargo run -p raven-greeter -- --preview OUT.png [WIDTHxHEIGHT] [empty|typing|denied|caps]
                                      [--wallpaper IMAGE.png] [--force]
```

Renders one frame to a PNG, on any host, with no compositor and no `ravend`.
It calls the same `draw` the compositor drives, so it is not a mock — a change
that breaks the layout breaks the preview the same way.

`OUT.png` is the file to **write**. To see the screen drawn on top of an image,
that is `--wallpaper`, which is a separate argument on purpose — and an
existing file is only overwritten if this tool wrote it, checked by a stamp in
the PNG rather than by the extension. `--force` overrides that.

```
cargo run -p raven-greeter -- --preview /tmp/login.png 1920x1080 typing \
    --wallpaper /usr/share/raven/wallpaper.png
```

## Building and installing

```
imlazy install          # cargo build --release, then sudo ./scripts/install.sh
```

`install.sh` creates the `raven-greeter` account (nologin shell, no password,
in `video`/`render`/`input`/`seat`), installs both binaries, installs
`config/login.toml` to `/etc/raven/login.toml` if it is not already there, and
wires the daemon into `raven-init` if this machine's init needs that — see
below. It is idempotent: run it again after a rebuild.

To remove it again, including the wiring:

```
imlazy uninstall        # sudo ./scripts/uninstall.sh
imlazy purge            # the same, plus login.toml and the greeter account
```

### Wiring it to raven-init

**On an image built since RavenLinux wired this up, nothing.**
`apply_kernel_cmdline_overrides` in RavenLinux's `init/src/main.rs` looks for
the `ravend` binary when the cmdline says `raven.graphics=wayland`, and starting
it *replaces* the autologin session rather than racing it. Installing the
daemon is the whole of turning the login screen on; removing it falls back to
the autologin session with no file edited either way. `raven.graphics=wayland`
is now correct to have on the cmdline, which it was not before.

That change also answers the failure case: `ravend` is restarted and there is no
fallback to the passwordless session, because a password prompt that can be
skipped by breaking it is not one. The console gettys are the way in to fix it.

On an older image, or any machine whose `raven-init` predates that,
`install.sh` wires it up — it installs `etc/raven/init-service.toml` as a
drop-in at `/etc/raven/init.d/ravend.toml`, sets `enabled = false` on
`getty-tty1`, and enables `seatd`. It keeps a backup of every file it edits at
`<file>.pre-ravend`, and `scripts/uninstall.sh` puts all of it back.

Two things it refuses to do, both of which it tells you about:

- **It will not disable the tty1 getty unless `getty-tty2` is enabled.** That
  getty is the way back in when the greeter will not start, and a machine with
  neither is one you fix with a USB stick.
- **It will not wire an old init booted with `raven.graphics=wayland`.** On an
  init without the branch above, that flag makes `raven-init` build its own
  autologin session service, which would then race `ravend` for the GPU and the
  seat. Either update `raven-init`, or take the flag off the kernel cmdline and
  run the script again. Note that the same flag is what makes an old init turn
  the tty1 getty off and start `seatd` by itself — so once it is gone, those are
  exactly the two things `install.sh` has to do, and does.

`WIRE_INIT=0 sudo ./scripts/install.sh` installs the binaries and touches no
service config at all.

Reboot, and check you can still log in on tty2 before relying on this.

## Configuration

`/etc/raven/login.toml`, and the whole file is optional — see `config/login.toml`
for every value with its default. A machine without the file behaves
identically; a file that exists but does not parse is a hard error rather than
a silent fallback, because falling back would ignore a policy somebody wrote
down and believed.

Two defaults are worth knowing:

- **`allow_root = false`.** A root graphical session is one misconfigured
  application away from being unable to open its own home directory, and
  `sudo-rs` is installed for the things that need privilege.
- **`allow_empty_password = false`.** An empty hash means "no password has been
  set", which on a half-provisioned machine is an accident. A greeter that
  accepts Enter on such an account turns that accident into an unlocked machine.

There is no lockout, only a delay: three free attempts, then exponential backoff
per account to a 30-second ceiling, cleared by a success and forgotten after
fifteen minutes of quiet. The machine this runs on is somebody's own computer,
and the person most likely to be locked out by a lockout policy is its owner.

### Setting a wallpaper

The login screen draws whatever wallpaper the machine has set, and a flat
backdrop when it has none. There is no login-specific setting to change for the
ordinary case:

```
/usr/share/wallpaper/                 the library: every image the machine has
/usr/share/wallpaper/set/wallpaper.*  the one that is on
```

`set/` holds exactly one file, named `wallpaper` with whatever extension the
image arrived with — a copy or a symlink into the library, either works. The
extension is a label: PNG and JPEG are told apart by their first bytes, here as
everywhere else in this repo, so a JPEG called `.png` still draws.

That path is compiled into the greeter rather than configured, because huginn
draws the same file behind the desktop. It is the contract that makes the login
screen and the session you land in look like one computer, and a contract a
third file can move is not one. `scripts/try-wallpaper.sh set` writes both
halves; a desktop wallpaper picker would write the same two.

The login screen can still be made to differ, and that is what the config key
is now for:

```toml
# /etc/raven/login.toml
[greeter]
wallpaper = "/usr/share/raven/login-only.png"
```

Set, it wins outright and `set/` is not consulted. Unset — the default — the
greeter falls back to `set/`. `ravend` reads the key at startup, so restart it
(or reboot) to pick up a change to it; the fallback is read by the greeter each
time it starts, which is every time the login screen appears.

**The file must be readable by the `raven-greeter` account.** This is the one
thing that catches people, and it is a consequence of the split rather than an
oversight: `ravend` passes the greeter a *path* and never opens the file
itself, because a root process that opens whatever a config file names is a
root process that can be pointed somewhere else. The greeter opens it,
unprivileged. So somewhere like `/usr/share` works and a path inside your home
directory does not — `raven-greeter` cannot read it, and on an encrypted home
it does not exist yet at login time.

PNG or JPEG, decided by the file's first bytes rather than its extension. It is
scaled to cover the screen and cropped from the centre, so its aspect ratio
need not match the panel, and it is darkened so that the text stays readable
whatever the picture is — bright photographs included.

Nothing about a wallpaper can stop a login. A missing file, an unreadable one,
one that is not an image, one too large to decode: each logs a warning and
leaves the plain backdrop in place. If you set one and get the backdrop, that
warning says which of those it was. It comes from the greeter rather than from
`ravend`, but it lands in `ravend`'s output — the greeter's stderr is
inherited, not piped.

To see the result without rebooting, render it:

```
cargo run -p raven-greeter -- --preview /tmp/login.png 1920x1080 typing \
    --wallpaper /usr/share/wallpaper/set/wallpaper.jpg
```

Run as yourself, that reads files the greeter could not, so it tells you the
image decodes and the screen looks right — not that the permissions are.

For that half, and to see it on the real greeter rather than in a PNG:

```
sudo ./scripts/try-wallpaper.sh set /path/to/image   # into the library, links
                                                     # set/, checks the format
                                                     # and the greeter's access
sudo ./scripts/try-wallpaper.sh stop                 # the way out
sudo ./scripts/try-wallpaper.sh revert               # undo everything
```

`set` deliberately does not write `login.toml`. A path there is an override for
the login screen alone, so writing one would set the wallpaper everywhere
except the place you were testing it; if it finds a key already there it says
so, and `revert` takes it out.

`run` is the one with a constraint on *where* you type it. It refuses to start
anywhere but a virtual terminal, because a second compositor started inside the
session it would be fighting is a GPU conflict that reports itself afterwards
as a driver bug. That check reads the terminal the process is attached to, not
what is on the screen, and two things are easy to get wrong about the
difference:

- `sudo chvt 2` moves the **screen** to tty2. It does not move your shell,
  which is still the pty it always was. Running `run` from that same terminal
  afterwards fails with `this is /dev/pts/N, not a virtual terminal`.
- A terminal emulator, a tmux pane, an ssh session, an editor's shell — each
  hands the commands you type it a pty, wherever you happen to be sitting.

So either switch to a VT, log in at the getty, and type it in *that* shell, or
have `openvt` allocate one for you, which works from anywhere including inside
your own session:

```
sudo openvt -sw -- ./scripts/try-wallpaper.sh run [SECONDS]
```

`-s` switches to the free VT it finds, `-w` waits for the test to finish, and
the script sees `/dev/ttyN` and is satisfied.

Look at the greeter; do not log in at it. A successful login is not a no-op —
`ravend` tears the greeter down and starts a real session, which the watchdog
below then kills part-way through when the timer runs out.

`run` touches neither `init.toml` nor the kernel cmdline, so a reboot returns
you to whatever you had before — which is what makes it safe to try before
committing to the wiring above.

**Ctrl+Alt+Fn does not work from inside a session.** huginn links libseat and
handles the VT-switch event, but binds nothing to the key that asks for one, so
the compositor swallows the combination. The greeter also takes an exclusive
keyboard grab. Between them, a greeter that comes up wrong can leave a keyboard
with nowhere to go — which is why `run` arms a watchdog that stops the test on
its own after `SECONDS` (180 by default) whether or not anything is listening.
`sudo chvt N` is the way to move between VTs by hand; it calls `VT_ACTIVATE`
directly and does not care what the compositor binds.

## What this does not do yet

- **A client cannot hold the idle lock off.** `raven-lock` locks on
  `Super`+`L`, on resume from suspend, after ten minutes with no input, and
  when somebody runs it. What is missing is `idle-inhibit-unstable-v1` in
  huginn: a full-screen film is indistinguishable from an empty room, so a
  long one locks the screen mid-play unless somebody turns the idle row off in
  quick settings.
- **No signal handling.** `rustix` exposes no safe `signalfd`, which is the same
  limitation `cawd` documents. `raven-init` stops services with SIGTERM then
  SIGKILL and the children are in `ravend`'s process group, so a shutdown does
  take everything down — what is lost is the tidy path, where a session is asked
  rather than killed.
- **Integer scaling only.** Fractional scaling would need
  `wp-fractional-scale-v1`, and a login screen a few percent off the ideal size
  is not worth another protocol on the boot path.
- **One session.** There is no session picker, because there is one session.
