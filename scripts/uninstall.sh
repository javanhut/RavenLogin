#!/usr/bin/env bash
# Remove RavenLogin: unwire it from raven-init, then take the binaries out.
#
# The order matters and is not cosmetic. The config is put back first, so that
# a machine which loses power halfway through this is one with a getty on tty1
# and no greeter, rather than one with no getty and no greeter. The binaries go
# last for the same reason.
#
# Idempotent, and safe to run on a machine where install.sh never wired
# anything: every step checks before it acts.
#
# By default the greeter's account and /etc/raven/login.toml are LEFT ALONE --
# the account owns nothing but its home directory, and the config is a file
# somebody may have edited. --purge takes both.
set -euo pipefail

PREFIX="${PREFIX:-/usr}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
GREETER_USER="${GREETER_USER:-raven-greeter}"
GREETER_HOME="/var/lib/${GREETER_USER}"

PURGE=0
for arg in "$@"; do
    case "${arg}" in
        --purge) PURGE=1 ;;
        -h|--help)
            echo "usage: uninstall.sh [--purge]"
            echo "  --purge  also remove ${GREETER_USER} and ${SYSCONFDIR}/raven/login.toml"
            exit 0 ;;
        *) echo "unknown argument: ${arg}" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$0")/.."

[ "$(id -u)" -eq 0 ] || { echo "uninstall.sh must run as root" >&2; exit 1; }

INIT_TOML="${SYSCONFDIR}/raven/init.toml"
DROPIN_DIR="${SYSCONFDIR}/raven/init.d"

# Same editor install.sh uses, and for the same reason: rewrite one line of one
# service and leave every comment in the file where its author put it.
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
    cat "${tmp}" > "${file}"
    rm -f "${tmp}"
    return 0
}

# --- put the console back --------------------------------------------------
#
# First, and unconditionally. Turning the tty1 getty back on costs nothing on a
# machine where it was already on, and is the difference between a working
# console and a black screen on one where install.sh turned it off.
if [ -f "${INIT_TOML}" ]; then
    if set_enabled "${INIT_TOML}" getty-tty1 true; then
        echo "ok    re-enabled getty-tty1 in ${INIT_TOML}"
    else
        echo "ok    getty-tty1 is already enabled"
    fi
    # The backup install.sh took is now stale -- it describes the wired state,
    # and leaving it next to the file invites somebody to restore it later and
    # silently turn the getty back off.
    if [ -f "${INIT_TOML}.pre-ravend" ]; then
        rm -f "${INIT_TOML}.pre-ravend"
        echo "ok    removed stale ${INIT_TOML}.pre-ravend"
    fi
else
    echo "WARN  no ${INIT_TOML}; nothing to put back"
fi

# --- unwire ----------------------------------------------------------------
if [ -f "${DROPIN_DIR}/ravend.toml" ]; then
    rm -f "${DROPIN_DIR}/ravend.toml"
    echo "ok    removed ${DROPIN_DIR}/ravend.toml"
else
    echo "ok    no ravend drop-in to remove"
fi

# seatd is deliberately NOT turned back off. install.sh may have enabled it,
# but a seat is useful to anything running a compositor from a TTY, nothing
# else on the machine is harmed by a running seatd, and guessing wrong here
# breaks the console workflow in scripts/tty-session.sh. Its backup goes,
# because it too describes a state we are walking away from.
if [ -f "${DROPIN_DIR}/seatd.toml.pre-ravend" ]; then
    rm -f "${DROPIN_DIR}/seatd.toml.pre-ravend"
    echo "ok    removed stale ${DROPIN_DIR}/seatd.toml.pre-ravend"
fi
if [ -f "${DROPIN_DIR}/seatd.toml" ]; then
    echo "ok    left seatd enabled; harmless, and a TTY compositor still needs it"
fi

# --- binaries --------------------------------------------------------------
for bin in ravend raven-greeter raven-lock; do
    if [ -e "${PREFIX}/bin/${bin}" ]; then
        rm -f "${PREFIX}/bin/${bin}"
        echo "ok    removed ${PREFIX}/bin/${bin}"
    else
        echo "ok    ${PREFIX}/bin/${bin} is not installed"
    fi
done

# --- config and account, only on --purge -----------------------------------
if [ "${PURGE}" = "1" ]; then
    if [ -f "${SYSCONFDIR}/raven/login.toml" ]; then
        rm -f "${SYSCONFDIR}/raven/login.toml"
        echo "ok    removed ${SYSCONFDIR}/raven/login.toml"
    fi
    if id "${GREETER_USER}" >/dev/null 2>&1; then
        userdel --remove "${GREETER_USER}" 2>/dev/null ||
            userdel "${GREETER_USER}" || true
        echo "ok    removed account ${GREETER_USER}"
    fi
    rm -rf "${GREETER_HOME}"
else
    echo "ok    kept ${SYSCONFDIR}/raven/login.toml and the ${GREETER_USER} account"
    echo "      (--purge removes both)"
fi

cat <<NEXT

Uninstalled. The autologin session comes back on the next boot.

ravend may still be running from before this ran -- removing the binary does
not stop a process that already started. To land it now:

  sudo raven-rc stop ravend    # if this init knows the service
  sudo raven-rc reload         # re-read the config you just changed

Or just reboot, which is the only way to be sure of what a fresh boot does.
NEXT
