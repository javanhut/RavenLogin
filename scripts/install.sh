#!/usr/bin/env bash
# Install RavenLogin: the binaries, the config, and the greeter's account.
#
# Idempotent. Run it again after a rebuild to replace the binaries without
# touching the account or a config file you have edited.
#
# It also wires ravend into raven-init when that is needed and safe -- a
# drop-in service, the tty1 getty off, seatd on. A current RavenLinux needs
# none of that: init starts ravend because the binary is here. The one case it
# refuses to touch is an old init booted with raven.graphics=wayland, where
# wiring would leave two things fighting over the GPU; it says so and stops.
# WIRE_INIT=0 skips the wiring entirely. See README.md, "Wiring it to
# raven-init".
set -euo pipefail

PREFIX="${PREFIX:-/usr}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
GREETER_USER="${GREETER_USER:-raven-greeter}"
GREETER_HOME="/var/lib/${GREETER_USER}"

cd "$(dirname "$0")/.."

[ "$(id -u)" -eq 0 ] || { echo "install.sh must run as root" >&2; exit 1; }

# --- the greeter's account -------------------------------------------------
#
# A dedicated system account rather than `nobody`: `nobody` is shared by every
# unprivileged daemon on the machine, so anything running as it could reach the
# greeter's runtime directory and its Wayland socket.
#
# The groups are what let its compositor work at all -- video and render for
# the GPU, input for the keyboard, seat for seatd. A greeter missing `video`
# starts, draws nothing, and looks like a driver bug.
if id "${GREETER_USER}" >/dev/null 2>&1; then
    echo "ok    account ${GREETER_USER} already exists"
else
    echo "..    creating ${GREETER_USER}"
    useradd --system \
            --home-dir "${GREETER_HOME}" \
            --create-home \
            --shell /usr/bin/nologin \
            --comment "Raven login screen" \
            "${GREETER_USER}"
    # No password, and locked: this account is never logged in to.
    passwd --lock "${GREETER_USER}" >/dev/null
fi

for group in video render input seat; do
    if getent group "${group}" >/dev/null 2>&1; then
        usermod --append --groups "${group}" "${GREETER_USER}"
        echo "ok    ${GREETER_USER} is in ${group}"
    else
        echo "WARN  group '${group}' does not exist on this system; skipping."
        echo "      If the greeter's compositor cannot open the GPU or the"
        echo "      keyboard, this is the first thing to check."
    fi
done

install -d -m 0755 "${GREETER_HOME}"
chown "${GREETER_USER}:${GREETER_USER}" "${GREETER_HOME}"

# --- binaries --------------------------------------------------------------
if [ ! -x target/release/ravend ] || [ ! -x target/release/raven-greeter ]; then
    echo "Build first: cargo build --release" >&2
    exit 1
fi

install -D -m 0755 target/release/ravend        "${PREFIX}/bin/ravend"
install -D -m 0755 target/release/raven-greeter "${PREFIX}/bin/raven-greeter"
echo "ok    installed ravend and raven-greeter into ${PREFIX}/bin"

# --- config ----------------------------------------------------------------
#
# Never overwritten. Every value in it is a default that ravend already has
# compiled in, so a machine without this file behaves identically -- there is
# nothing to be gained by clobbering one somebody has edited.
if [ -f "${SYSCONFDIR}/raven/login.toml" ]; then
    echo "ok    ${SYSCONFDIR}/raven/login.toml exists; leaving it alone"
else
    install -D -m 0644 config/login.toml "${SYSCONFDIR}/raven/login.toml"
    echo "ok    installed ${SYSCONFDIR}/raven/login.toml"
fi

# --- the wallpaper directories ---------------------------------------------
#
# Empty, and nothing is installed into them. The greeter draws
# /usr/share/wallpaper/set/wallpaper.<ext> when login.toml names no wallpaper of
# its own, and huginn draws the same file behind the desktop -- so the
# directories are the contract, and an image goes in them rather than being
# named in a config file. scripts/try-wallpaper.sh writes both halves.
install -d -m 0755 "${PREFIX}/share/wallpaper" "${PREFIX}/share/wallpaper/set"
echo "ok    ${PREFIX}/share/wallpaper and set/ exist"


# --- wiring ravend into raven-init -----------------------------------------
#
# Three shapes of machine, decided by facts rather than by asking:
#
#   1. An init that looks for ravend itself. Nothing to do: it starts this
#      daemon in place of the autologin session because the binary is here,
#      and it disables the tty1 getty and starts seatd on its own.
#
#   2. An older init, and no 'raven.graphics=wayland' on the kernel cmdline.
#      Wired here: a drop-in for ravend, the tty1 getty off, seatd on.
#
#   3. An older init WITH 'raven.graphics=wayland'. Not wired, and it must not
#      be: that flag makes an old init build its own autologin session, which
#      would race ravend for the GPU and the seat. Instructions, not edits.
#
# Set WIRE_INIT=0 to skip all of it and get the old print-and-leave behaviour.
WIRE_INIT="${WIRE_INIT:-1}"
INIT_BIN="$(readlink -f /sbin/init 2>/dev/null || true)"
[ -n "${INIT_BIN}" ] || INIT_BIN="${PREFIX}/bin/raven-init"

INIT_TOML="${SYSCONFDIR}/raven/init.toml"
DROPIN_DIR="${SYSCONFDIR}/raven/init.d"

# Does this init start ravend by itself? The log line it prints on a boot that
# finds the binary is in the binary whether or not it has run, so this answers
# on the boot you install, not the one after. Checking the binary rather than
# the boot log is also the only thing that works on the very first install:
# the log says nothing about ravend because ravend was not there at boot.
init_finds_ravend() {
    [ -r "${INIT_BIN}" ] && grep -aq 'Found ravend' "${INIT_BIN}"
}

cmdline_wayland() {
    grep -q 'raven\.graphics=wayland' /proc/cmdline 2>/dev/null
}

# Is a service enabled in a config file? Used as a guard, never to decide a
# rewrite: the answer is "no" for a service that is not in the file at all.
svc_enabled() {
    awk -v svc="$2" '
        /^\[\[services\]\]/ { in_svc = 0 }
        $0 ~ "^name[[:space:]]*=[[:space:]]*\"" svc "\"" { in_svc = 1 }
        in_svc && /^enabled[[:space:]]*=[[:space:]]*true/ { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$1" 2>/dev/null
}

# Set enabled = <value> on one service, in place, preserving any trailing
# comment on the line. Idempotent: a file already saying the right thing is
# left byte-identical and no backup is taken.
set_enabled() {
    local file="$1" svc="$2" val="$3" tmp
    [ -f "${file}" ] || return 1
    tmp="$(mktemp)"
    awk -v svc="${svc}" -v val="${val}" '
        /^\[\[services\]\]/ { in_svc = 0 }
        $0 ~ "^name[[:space:]]*=[[:space:]]*\"" svc "\"" { in_svc = 1 }
        in_svc && /^enabled[[:space:]]*=/ {
            comment = ""
            if (match($0, /#.*/)) comment = "  " substr($0, RSTART, RLENGTH)
            $0 = "enabled = " val comment
            in_svc = 0
        }
        { print }
    ' "${file}" > "${tmp}"

    if cmp -s "${file}" "${tmp}"; then
        rm -f "${tmp}"
        return 1
    fi
    cp -p "${file}" "${file}.pre-ravend"
    cat "${tmp}" > "${file}"
    rm -f "${tmp}"
    return 0
}

install_dropin() {
    # PREFIX is substituted rather than hardcoded so a non-/usr install points
    # at the binary that was actually installed a few lines above.
    install -d -m 0755 "${DROPIN_DIR}"
    sed "s|^exec = \"/usr/bin/ravend\"|exec = \"${PREFIX}/bin/ravend\"|" \
        etc/raven/init-service.toml > "${DROPIN_DIR}/ravend.toml.new"

    # pre_exec is appended here rather than shipped in the file because init
    # treats a pre_exec it cannot run as a failed start -- a hardcoded path
    # would stop ravend from starting at all on an image without raven-udev.
    # Resolved through PATH so it is the binary this machine actually has.
    local udev_settle
    udev_settle="$(command -v raven-udev 2>/dev/null || true)"
    if [ -n "${udev_settle}" ]; then
        printf '\n# Appended by install.sh: coldplug settle before the greeter'\''s\n' \
            >> "${DROPIN_DIR}/ravend.toml.new"
        printf '# compositor opens the GPU. See the note above.\npre_exec = ["%s"]\n' \
            "${udev_settle}" >> "${DROPIN_DIR}/ravend.toml.new"
    else
        echo "WARN  raven-udev not found; ravend starts without a coldplug settle."
        echo "      If the greeter dies at startup with a lost DRM device, that"
        echo "      is the first thing to look at."
    fi
    chmod 0644 "${DROPIN_DIR}/ravend.toml.new"

    if [ -f "${DROPIN_DIR}/ravend.toml" ] &&
       cmp -s "${DROPIN_DIR}/ravend.toml" "${DROPIN_DIR}/ravend.toml.new"; then
        rm -f "${DROPIN_DIR}/ravend.toml.new"
        echo "ok    ${DROPIN_DIR}/ravend.toml is current"
        return
    fi
    mv "${DROPIN_DIR}/ravend.toml.new" "${DROPIN_DIR}/ravend.toml"
    echo "ok    installed ${DROPIN_DIR}/ravend.toml"
}

WIRED=0
NEEDS_CMDLINE_EDIT=0

if [ "${WIRE_INIT}" != "1" ]; then
    echo "..    WIRE_INIT=0; leaving raven-init alone"

elif init_finds_ravend; then
    echo "ok    this raven-init starts ravend itself; nothing to wire"
    # A drop-in from an earlier install of this script is harmless here -- the
    # init's own definition overwrites exec/args/enabled -- but it is dead
    # config, and dead config is read later by somebody as intent.
    if [ -f "${DROPIN_DIR}/ravend.toml" ]; then
        echo "WARN  ${DROPIN_DIR}/ravend.toml is left over from an older init"
        echo "      and is now redundant. Safe to delete."
    fi
    WIRED=1

elif cmdline_wayland; then
    NEEDS_CMDLINE_EDIT=1
    echo "WARN  not wiring: this raven-init predates ravend, and the kernel"
    echo "      cmdline says raven.graphics=wayland. On this init that flag"
    echo "      builds an autologin session that would race ravend for the"
    echo "      GPU and the seat, so wiring now would give you both."

else
    # Refuse to take tty1 away without confirming tty2 is there to fall back
    # to. This is the one edit that can leave a machine with no way in.
    if ! svc_enabled "${INIT_TOML}" getty-tty2; then
        echo "WARN  not wiring: getty-tty2 is not enabled in ${INIT_TOML}."
        echo "      That getty is the way back in if the greeter fails, and"
        echo "      wiring turns tty1 off. Enable it, then run this again."
    else
        install_dropin

        if set_enabled "${INIT_TOML}" getty-tty1 false; then
            echo "ok    disabled getty-tty1 (backup: ${INIT_TOML}.pre-ravend)"
        else
            echo "ok    getty-tty1 is already off"
        fi

        # Nothing synthesizes seatd on a console boot, and the greeter's
        # compositor cannot open a seat without it -- it fails with
        # "Function not implemented (os error 38)", which reads like a
        # permissions problem and is a daemon that was never started.
        if [ -f "${DROPIN_DIR}/seatd.toml" ]; then
            if set_enabled "${DROPIN_DIR}/seatd.toml" seatd true; then
                echo "ok    enabled seatd (backup: ${DROPIN_DIR}/seatd.toml.pre-ravend)"
            else
                echo "ok    seatd is already on"
            fi
        else
            echo "WARN  no ${DROPIN_DIR}/seatd.toml; ravend will have no seat."
            echo "      Install seatd's service definition before rebooting."
        fi

        echo "ok    getty-tty2 left enabled -- that is the way back in"
        WIRED=1
    fi
fi

# --- what is left ----------------------------------------------------------
echo
if [ "${NEEDS_CMDLINE_EDIT}" = "1" ]; then
    cat <<NEXT
Installed, but the login screen is NOT wired up yet. Pick one:

  A. Update raven-init to a build that looks for ravend, then run this
     script again. It is the path with no config edited anywhere: init
     starts ravend instead of the autologin session, turns off the tty1
     getty and starts seatd, all because the binary is present.

  B. Remove 'raven.graphics=wayland' from the kernel cmdline, reboot, and
     run this script again. It will wire everything on that boot.

Until then this machine keeps the autologin session it has now.
NEXT
elif [ "${WIRED}" = "1" ]; then
    cat <<NEXT
Installed and wired. Before you reboot, try the greeter from where you are:

  sudo openvt -sw -- ./scripts/try-wallpaper.sh run

Then reboot. Check you can log in on tty2 before you rely on this -- and if
the greeter does not come up, tty2 is how you get back in to fix it.

To undo all of it: sudo ./scripts/uninstall.sh
NEXT
else
    cat <<NEXT
Installed. The wiring was not done -- see the warnings above for why.

You can still try the greeter without committing to it:

  sudo openvt -sw -- ./scripts/try-wallpaper.sh run
NEXT
fi
