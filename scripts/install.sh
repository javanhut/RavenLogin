#!/usr/bin/env bash
# Install RavenLogin: the binaries, the config, and the greeter's account.
#
# Idempotent. Run it again after a rebuild to replace the binaries without
# touching the account or a config file you have edited.
#
# What it does NOT do is wire ravend into raven-init -- that means disabling the
# getty on tty1, which is the thing you would want back if this goes wrong. See
# README.md, "Wiring it to raven-init".
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

cat <<NEXT

Installed. Two things left, and neither is done for you because both are how
you would get back in if this goes wrong:

  1. Add the service block in etc/raven/init-service.toml to
     ${SYSCONFDIR}/raven/init.toml

  2. In the same file, set 'enabled = false' on the getty-tty1 service. The
     greeter's compositor needs that VT. Leave getty-tty2 enabled -- that is
     the way back in.

Then reboot. Make sure you can log in on tty2 before you rely on this.
NEXT
