#!/bin/sh
# Guard against the .deb env samples drifting from the code. Every MAILSTRIX_* key
# named in a packaging/deb/*.env (commented or not) must be a key the binaries
# actually read — i.e. appear as a "MAILSTRIX_..." string token in the Go sources.
# Catches renamed/stale knobs (e.g. MAILSTRIX_ADDR when the code reads MAILSTRIX_HOST).
# Covers every shipped unit's env file (strixd, strix-milter, ...), so a new one
# cannot be added without its keys being checked.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

# All MAILSTRIX_* keys the Go code references (env reads, struct comments, flags).
known="$(grep -rhoE 'MAILSTRIX_[A-Z0-9_]+' "$root/internal" "$root/cmd" | sort -u)"

# A key may legitimately be consumed by a systemd unit instead of by Go — e.g.
# MAILSTRIX_MILTER_ARGS, which the unit interpolates into ExecStart to pass extra
# flags. Those are still checked, just against the units rather than the sources:
# a key that NOTHING reads is the drift we are hunting.
unit_known="$(grep -rhoE 'MAILSTRIX_[A-Z0-9_]+' "$here"/*.service | sort -u)"

fail=0
found_env=0
for env in "$here"/*.env; do
    [ -e "$env" ] || continue
    found_env=1
    name="$(basename "$env")"
    # Keys used in the env file: left-hand side of an (optionally #-commented) NAME=…
    # (MAILSTRIX_* tokens have no whitespace, so word-splitting the list is intended.)
    # shellcheck disable=SC2013
    for key in $(grep -oE '^#?[[:space:]]*MAILSTRIX_[A-Z0-9_]+=' "$env" \
                    | sed -E 's/^#?[[:space:]]*//; s/=$//' | sort -u); do
        if printf '%s\n' "$known" | grep -qx "$key"; then
            echo "ok   - $name: $key"
        elif printf '%s\n' "$unit_known" | grep -qx "$key"; then
            echo "ok   - $name: $key (consumed by a systemd unit)"
        else
            echo "FAIL - $key in $name is read by neither a Go source nor a systemd unit"; fail=1
        fi
    done
done

# A glob that matched nothing would make this whole gate silently vacuous.
if [ "$found_env" -eq 0 ]; then
    echo "FAIL - no packaging/deb/*.env found; this test would pass vacuously"; fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "ALL OK"
else
    echo "FAILURES"; exit 1
fi
