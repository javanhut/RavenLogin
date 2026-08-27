#!/usr/bin/env bash
# Try a wallpaper on the real login screen, reversibly.
#
# The preview flag renders the greeter to a PNG, which is enough for layout and
# contrast but cannot tell you whether the greeter's own account can read the
# file you picked -- the commonest way a wallpaper silently does nothing. This
# runs the real thing on a spare VT to answer that.
#
# What it touches: /usr/share/wallpaper, the machine's wallpaper library, and
# the single entry in /usr/share/wallpaper/set that says which one is on.
# `revert` undoes both. It does NOT write to /etc/raven/login.toml: a path in
# there overrides the machine's wallpaper for the login screen alone, which is
# the opposite of setting one, so `set` warns if it finds a key already there
# rather than adding to it.
#
# What it does NOT touch, deliberately: /etc/raven/init.toml and the kernel
# cmdline. Wiring ravend into init means disabling the getty on tty1 and
# dropping raven.graphics=wayland, which is the change that can leave you
# without a graphical login. See README.md, "Wiring it to raven-init". Until
# you do that, `run` below is a foreground test you can walk away from: a
# reboot puts everything back with no revert needed.
#
# Getting back out, in the order you should reach for them:
#
#   1. Wait. `run` arms a watchdog that stops the test on its own, because
#      the greeter takes an exclusive keyboard grab and huginn implements no
#      VT-switch keybinding -- Ctrl+Alt+F1 does nothing from inside either of
#      them. That combination can leave a keyboard with nowhere to go, so the
#      timeout is the escape that needs no input at all.
#   2. `ssh` in from another machine and run `stop`.
#   3. `sudo chvt 1` from anywhere with a shell. chvt calls VT_ACTIVATE
#      directly, so it does not care that the compositor ignores the keys.
#   4. Reboot. Nothing here survives one.
#
#   sudo ./scripts/try-wallpaper.sh set /path/to/image
#   sudo openvt -sw -- ./scripts/try-wallpaper.sh run [SECONDS]
#   sudo ./scripts/try-wallpaper.sh stop            # the escape hatch
#   sudo ./scripts/try-wallpaper.sh revert
#   ./scripts/try-wallpaper.sh status               # no root needed
#
# `run` is the one that cares where you type it: it refuses anything but a
# virtual terminal. The check reads the terminal this process is attached to,
# not what is on the screen -- `chvt 2` moves the screen and leaves your shell
# on the pty it always was, and a terminal emulator, a tmux pane or an ssh
# session hands it a pty too. Either log in at a getty and run it in that
# shell, or let `openvt -sw` above allocate a VT from wherever you are.
set -euo pipefail
cd "$(dirname "$0")/.."

# The library, and the one directory whose contents answer "which wallpaper is
# this machine using". Both the greeter and huginn read the second by a path
# compiled into them; neither is configurable, because a contract between two
# programs that a third file can move is not a contract.
LIB="${LIB:-/usr/share/wallpaper}"
SET_DIR="${SET_DIR:-$LIB/set}"
CONF="${CONF:-/etc/raven/login.toml}"
# Only read now, never written. Kept because machines set up before the
# wallpaper moved here have a real backup sitting next to their config, and
# `revert` is the command that should put it back.
BACKUP="${CONF}.pre-wallpaper"
LEGACY_DEST="${LEGACY_DEST:-/usr/share/raven/wallpaper.png}"
GREETER_USER="${GREETER_USER:-raven-greeter}"
WATCHDOG_PID="${WATCHDOG_PID:-/run/try-wallpaper.watchdog}"
DEFAULT_TIMEOUT="${DEFAULT_TIMEOUT:-180}"

need_root() {
    [ "$(id -u)" -eq 0 ] || { echo "'$1' must run as root" >&2; exit 1; }
}

usage() {
    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
    exit "${1:-0}"
}

# --- set -------------------------------------------------------------------

cmd_set() {
    local src="${1:-}"
    need_root set
    [ -n "$src" ] || { echo "usage: sudo $0 set /path/to/image" >&2; exit 2; }
    [ -f "$src" ] || { echo "no such file: $src" >&2; exit 1; }

    # The format is checked here rather than at the login screen, by the same
    # two magic numbers the greeter dispatches on. An extension proves nothing
    # -- the file that motivated the preview overwrite guard was a PNG named
    # .jpg. The extension this picks is therefore derived from the contents,
    # and is a label: nothing downstream decides anything by reading it.
    local magic format ext
    magic=$(head -c 3 "$src" | od -An -tx1 | tr -d ' \n')
    case "$magic" in
        89504e) format=PNG;  ext=png ;;
        ffd8ff) format=JPEG; ext=jpg ;;
        *) echo "FAIL  $src is not a PNG or a JPEG (starts with $magic)" >&2
           echo "      The greeter would refuse it and draw the plain backdrop." >&2
           exit 1 ;;
    esac
    echo "ok    $src is a $format"

    # Into the library under its own name. The library is the set of images
    # the machine has; renaming them on the way in would lose the only thing
    # that tells one from another once there are three.
    local name
    name=$(basename "$src")
    # An image already in the library is the ordinary case for the second and
    # every later call -- `set` is how you switch between them, not only how
    # you add one. install(1) refuses a copy onto itself, so it is not asked to.
    if [ "$(readlink -f "$src")" = "$(readlink -f "$LIB/$name" 2>/dev/null || true)" ]; then
        echo "ok    $LIB/$name is already the library copy"
    else
        install -D -m 0644 -o root -g root "$src" "$LIB/$name"
        echo "ok    installed $LIB/$name"
    fi

    # And then exactly one entry in set/, by symlink rather than a second copy.
    # Every wallpaper.* already there goes first: two of them is an ambiguity
    # the readers resolve by sorting, which is deterministic and still not what
    # anybody meant.
    install -d -m 0755 -o root -g root "$SET_DIR"
    local stale
    for stale in "$SET_DIR"/wallpaper.* "$SET_DIR/wallpaper"; do
        [ -e "$stale" ] || [ -L "$stale" ] || continue
        rm -f "$stale"
        echo "ok    removed the previous $(basename "$stale")"
    done
    ln -s "../$name" "$SET_DIR/wallpaper.$ext"
    echo "ok    $SET_DIR/wallpaper.$ext -> ../$name"

    # The only permission check that means anything: ravend passes the greeter
    # a path and never opens it, so this file is read by an unprivileged
    # account, not by root. -r follows the symlink, which is the whole path
    # being tested and not just its last component.
    if sudo -u "$GREETER_USER" test -r "$SET_DIR/wallpaper.$ext"; then
        echo "ok    $GREETER_USER can read it"
    else
        echo "FAIL  $GREETER_USER cannot read $SET_DIR/wallpaper.$ext" >&2
        echo "      The greeter would fall back to the backdrop. Check the" >&2
        echo "      permissions on every directory above it, not just the file." >&2
        exit 1
    fi

    # A path in login.toml is an override for the login screen alone, and it
    # wins over everything above. Machines set up before the wallpaper lived
    # here have one, pointing at a file this no longer writes.
    local override
    override=$(grep -E '^[[:space:]]*wallpaper[[:space:]]*=' "$CONF" 2>/dev/null || true)
    if [ -n "$override" ]; then
        echo "WARN  $CONF overrides this for the login screen:" >&2
        echo "        $override" >&2
        echo "      The desktop will use what you just set and the login screen" >&2
        echo "      will not. 'sudo $0 revert' removes the override." >&2
    fi

    cat <<EOF

The desktop picks this up when huginn next starts. To see it on the real login
screen now, on a VT rather than in a terminal inside your desktop session --
Ctrl+Alt+F2 will not get you there, huginn binds no VT-switch key, and 'chvt 2'
moves only the screen, leaving your shell on its pty, which 'run' refuses. So
either log in at the getty on another VT and run it in that shell:

    sudo chvt 2
    sudo $0 run

or have openvt allocate one, which works from where you are standing now:

    sudo openvt -sw -- $0 run

and the way back out, from anywhere:

    sudo $0 stop
EOF
}

# --- run -------------------------------------------------------------------

cmd_run() {
    need_root run

    # A graphical terminal is a pty. Starting a second compositor from inside
    # the session it would be fighting is how this goes wrong, and the error
    # afterwards looks like a driver bug rather than a mistake.
    local where
    where=$(tty 2>/dev/null) || where="no terminal at all"
    case "$where" in
        /dev/tty[0-9]*) echo "ok    on $where" ;;
        *) echo "FAIL  not a virtual terminal (this is $where)." >&2
           echo "      Starting the greeter's compositor from inside your own" >&2
           echo "      session means two compositors fighting for the GPU." >&2
           echo >&2
           echo "      This is about the terminal the command is attached to," >&2
           echo "      not what is on the screen: 'chvt 2' moves the screen and" >&2
           echo "      leaves this shell on its pty. Log in at a getty and run" >&2
           echo "      it there, or from anywhere at all:" >&2
           echo >&2
           echo "          sudo openvt -sw -- $0 run" >&2
           exit 1 ;;
    esac

    grep -qE '^[[:space:]]*wallpaper[[:space:]]*=' "$CONF" \
        || echo "WARN  no wallpaper set in $CONF; you will get the plain backdrop"

    local timeout="${1:-$DEFAULT_TIMEOUT}"
    case "$timeout" in
        ''|*[!0-9]*) echo "FAIL  timeout must be a whole number of seconds" >&2; exit 2 ;;
    esac

    # The watchdog is the point of this command.
    #
    # The greeter takes an exclusive keyboard grab, and huginn binds nothing to
    # Ctrl+Alt+Fn -- it links libseat and handles the VT-switch *event*, but
    # never calls for one. So if the greeter comes up and misbehaves, a
    # keyboard may have nowhere at all to go: no key combination reaches the
    # kernel, and the shell that started this is behind a compositor.
    #
    # This runs before ravend and outlives it. Whatever happens on screen, the
    # machine comes back by itself.
    stop_after "$timeout"

    cat <<EOF
..    starting ravend in the foreground
ok    it will stop by itself in ${timeout}s

      Look at the screen. Do NOT log in at it -- a successful login starts a
      real session, which is a bigger mess than this test needs.

      Ctrl+Alt+F1 does NOT work: huginn binds no VT-switch key, and the greeter
      grabs the keyboard. If you need out sooner than ${timeout}s, either ssh in
      and run 'sudo $0 stop', or run 'sudo chvt 1' from any shell you can reach.

EOF
    exec ravend "$CONF"
}

# Kill the test after `seconds`, from a process that survives ravend exec'ing
# over this shell.
stop_after() {
    local seconds="$1"
    setsid sh -c '
        sleep "$1"
        pkill -u "$2" 2>/dev/null
        pkill -x ravend 2>/dev/null
        sleep 2
        pkill -9 -u "$2" 2>/dev/null
        pkill -9 -x ravend 2>/dev/null
        rm -f "$3"
    ' watchdog "$seconds" "$GREETER_USER" "$WATCHDOG_PID" >/dev/null 2>&1 &
    echo $! > "$WATCHDOG_PID"
    echo "ok    watchdog armed (pid $(cat "$WATCHDOG_PID"), ${seconds}s)"
}

# --- stop ------------------------------------------------------------------

cmd_stop() {
    need_root stop

    # Disarm first, so a watchdog that has not fired yet cannot come back
    # minutes later and kill a greeter you started on purpose.
    if [ -f "$WATCHDOG_PID" ]; then
        kill "$(cat "$WATCHDOG_PID")" 2>/dev/null || true
        rm -f "$WATCHDOG_PID"
        echo "ok    watchdog disarmed"
    fi

    # By account, never by process name. The greeter's compositor and yours are
    # both called huginn, and 'pkill huginn' would take your session down with
    # the test. Nothing but the greeter runs as $GREETER_USER.
    local killed=0
    if pgrep -u "$GREETER_USER" >/dev/null 2>&1; then
        pkill -u "$GREETER_USER" || true
        killed=1
    fi
    if pgrep -x ravend >/dev/null 2>&1; then
        pkill -x ravend || true
        killed=1
    fi

    if [ "$killed" -eq 1 ]; then
        sleep 1
        pkill -9 -u "$GREETER_USER" 2>/dev/null || true
        pkill -9 -x ravend 2>/dev/null || true
    fi

    pgrep -u "$GREETER_USER" >/dev/null 2>&1 \
        && echo "WARN  something still running as $GREETER_USER" \
        || echo "ok    nothing running as $GREETER_USER"
    pgrep -x ravend >/dev/null 2>&1 \
        && echo "WARN  ravend still running" \
        || echo "ok    ravend is not running"
    echo "      If the display is still wrong, 'sudo chvt 1' -- Ctrl+Alt+F1 does"
    echo "      nothing while huginn holds the keyboard. Nothing persists:"
    echo "      init.toml and the kernel cmdline were never touched."
}

# --- revert ----------------------------------------------------------------

cmd_revert() {
    need_root revert

    # Resolve before removing: the set entry is a symlink into the library, and
    # once it is gone nothing records which image it named.
    local target=""
    local entry
    for entry in "$SET_DIR"/wallpaper.* "$SET_DIR/wallpaper"; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        target=$(readlink -f "$entry" 2>/dev/null || true)
        rm -f "$entry"
        echo "ok    removed $entry"
    done
    [ -n "$target" ] || echo "..    nothing set in $SET_DIR"

    # Only inside the library, and only the file this would have installed. An
    # image somebody pointed at from elsewhere on the disk is theirs.
    case "$target" in
        "$LIB"/*)
            if [ -f "$target" ]; then
                rm -f "$target"
                echo "ok    removed $target"
            fi
            ;;
        "") ;;
        *) echo "..    left $target alone; it is outside $LIB" ;;
    esac

    # The login-screen override. A backup means a machine set up before the
    # wallpaper moved here, and restoring it is exactly right. Without one, the
    # key is still an override that outlives everything above, so it goes.
    if [ -f "$BACKUP" ]; then
        mv -f "$BACKUP" "$CONF"
        echo "ok    restored $CONF"
    elif grep -qE '^[[:space:]]*wallpaper[[:space:]]*=' "$CONF" 2>/dev/null; then
        local tmp
        tmp=$(mktemp)
        awk '!/^[[:space:]]*wallpaper[[:space:]]*=/' "$CONF" > "$tmp"
        cat "$tmp" > "$CONF"
        rm -f "$tmp"
        echo "ok    removed the wallpaper override from $CONF"
    else
        echo "ok    no override in $CONF"
    fi

    if [ -f "$LEGACY_DEST" ]; then
        rm -f "$LEGACY_DEST"
        echo "ok    removed $LEGACY_DEST (where wallpapers used to go)"
    fi
}

# --- status ----------------------------------------------------------------

cmd_status() {
    local entry found=""
    for entry in "$SET_DIR"/wallpaper.* "$SET_DIR/wallpaper"; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        found="$entry"
        if [ -L "$entry" ]; then
            echo "ok    $entry -> $(readlink "$entry")"
        else
            echo "ok    $entry"
        fi
        # Magic rather than extension, the same way everything else here
        # decides, so a .png that is really a JPEG is visible as one.
        [ -r "$entry" ] && echo "      magic $(head -c 3 "$entry" | od -An -tx1 | tr -d ' \n')"
        sudo -n -u "$GREETER_USER" test -r "$entry" 2>/dev/null \
            && echo "ok    $GREETER_USER can read it" \
            || echo "..    cannot check readability without root"
    done
    [ -n "$found" ] || echo "..    nothing set in $SET_DIR (the backdrop is what you get)"

    if [ -d "$LIB" ]; then
        echo "ok    $LIB holds $(find "$LIB" -maxdepth 1 -type f | wc -l) image(s)"
    else
        echo "..    no $LIB"
    fi

    # Not a sed replacement: $CONF is a path, and a path full of slashes in
    # the replacement half of s/// is a syntax error.
    local override
    override=$(grep -E '^[[:space:]]*wallpaper[[:space:]]*=' "$CONF" 2>/dev/null || true)
    if [ -n "$override" ]; then
        echo "..    $CONF overrides the login screen: $override"
    else
        echo "ok    no override in $CONF; the login screen uses what is set above"
    fi
    [ -f "$LEGACY_DEST" ] && echo "..    $LEGACY_DEST still exists (wallpapers no longer go there)"
    [ -f "$BACKUP" ] && echo "ok    backup at $BACKUP" || true
    pgrep -x ravend >/dev/null 2>&1 && echo "..    ravend IS running" || echo "ok    ravend is not running"
    [ -f "$WATCHDOG_PID" ] && echo "..    watchdog armed (pid $(cat "$WATCHDOG_PID"))" || echo "ok    no watchdog armed"
    grep -q 'name = "ravend"' /etc/raven/init.toml 2>/dev/null \
        && echo "..    ravend is wired into init.toml" \
        || echo "ok    init.toml untouched (a reboot returns to your current setup)"
}

case "${1:-}" in
    set)    shift; cmd_set "$@" ;;
    run)    shift; cmd_run "$@" ;;
    stop)   shift; cmd_stop "$@" ;;
    revert) shift; cmd_revert "$@" ;;
    status) shift; cmd_status "$@" ;;
    -h|--help|help) usage 0 ;;
    "")     usage 2 ;;
    *)      echo "unknown command: $1" >&2; usage 2 ;;
esac
