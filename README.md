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
cargo build --release
sudo ./scripts/install.sh
```

`install.sh` creates the `raven-greeter` account (nologin shell, no password,
in `video`/`render`/`input`/`seat`), installs both binaries, and installs
`config/login.toml` to `/etc/raven/login.toml` if it is not already there.

### Wiring it to raven-init

**This step is deliberately not automated**, because it involves turning off
the getty you would want if it goes wrong.

1. Append the block in `etc/raven/init-service.toml` to `/etc/raven/init.toml`.
2. In the same file, set `enabled = false` on `getty-tty1`. The greeter's
   compositor needs that VT; a getty holding it means the two fight.
3. Leave `getty-tty2` enabled. That is the way back in.
4. Do **not** put `raven.graphics=wayland` on the kernel cmdline. That flag
   makes `raven-init` build its own autologin session service, which would then
   race `ravend` for the GPU and the seat.

Reboot, and check you can still log in on tty2 before relying on this.

That fourth point is a wart, and the fix belongs in RavenLinux rather than
here: `configure_wayland_session` in `init/src/main.rs` should start `ravend`
when it finds it, and fall back to the autologin session only when it does not.
That is a change to another repository and is not made by this one.

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

The login screen draws on a flat backdrop unless you give it an image:

```toml
# /etc/raven/login.toml
[greeter]
wallpaper = "/usr/share/raven/wallpaper.png"
```

`ravend` reads that at startup, so restart it (or reboot) to pick up a change.

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
    --wallpaper /usr/share/raven/wallpaper.png
```

Run as yourself, that reads files the greeter could not, so it tells you the
image decodes and the screen looks right — not that the permissions are.
`sudo -u raven-greeter test -r <path>` is the check for that half.

## What this does not do yet

- **`muninn-lock` is still a stub.** Locking a running session is RavenGUI's
  job and is unrelated to logging in to a new one, but they will want to share
  a look. When it is built, `theme.rs` here is the thing to reconcile with.
- **No signal handling.** `rustix` exposes no safe `signalfd`, which is the same
  limitation `cawd` documents. `raven-init` stops services with SIGTERM then
  SIGKILL and the children are in `ravend`'s process group, so a shutdown does
  take everything down — what is lost is the tidy path, where a session is asked
  rather than killed.
- **Integer scaling only.** Fractional scaling would need
  `wp-fractional-scale-v1`, and a login screen a few percent off the ideal size
  is not worth another protocol on the boot path.
- **One session.** There is no session picker, because there is one session.
