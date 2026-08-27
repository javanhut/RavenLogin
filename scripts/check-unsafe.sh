#!/usr/bin/env bash
# Assert that every crate inherits the workspace-wide `unsafe_code = "forbid"`,
# except the one crate documented as the quarantine for unsafe code.
#
# `forbid` cannot be overridden by an #[allow] inside a crate, so the only way
# to smuggle unsafe into this workspace is to drop `[lints] workspace = true`
# from a manifest. That is exactly what this looks for.
#
# The check runs in both directions on purpose. A crate that quietly stops
# inheriting the lints is the obvious failure; a *quarantine* crate that starts
# inheriting them is the quiet one, because it fails at compile time with a
# confusing E0453 rather than here with an explanation.
#
# Run from CI and from a pre-push hook.
set -euo pipefail
cd "$(dirname "$0")/.."

QUARANTINE="crates/raven-privdrop/Cargo.toml"
status=0

inherits_workspace_lints() {
    awk '/^\[lints\]/ {inside=1; next} /^\[/ {inside=0} inside' "$1" \
        | grep -qE '^[[:space:]]*workspace[[:space:]]*=[[:space:]]*true'
}

while IFS= read -r manifest; do
    if [ "$manifest" = "$QUARANTINE" ]; then
        if inherits_workspace_lints "$manifest"; then
            echo "FAIL  $manifest is the quarantine crate but inherits workspace lints;"
            echo "      it needs its own [lints] table or it cannot compile the three"
            echo "      syscalls it exists for."
            status=1
        else
            echo "ok    $manifest (quarantine: unsafe permitted, SAFETY comments enforced)"
        fi
        continue
    fi

    if inherits_workspace_lints "$manifest"; then
        echo "ok    $manifest"
    else
        echo "FAIL  $manifest does not set [lints] workspace = true."
        echo "      Every crate must inherit unsafe_code = \"forbid\". If this crate"
        echo "      genuinely needs unsafe, that is a design discussion, not a"
        echo "      manifest edit -- and the answer is almost certainly to put the"
        echo "      unsafe in raven-privdrop and call it from here."
        status=1
    fi
done < <(find crates -name Cargo.toml | sort)

if [ "$status" -eq 0 ]; then
    echo
    echo "All crates accounted for: unsafe is confined to $QUARANTINE."
fi
exit "$status"
