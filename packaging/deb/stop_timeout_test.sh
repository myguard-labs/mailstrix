#!/bin/sh
# strix-milter drains in-flight sessions on SIGTERM for up to -timeout + 5s
# (default -timeout 20s => 25s). If the unit's TimeoutStopSec is lower, systemd
# SIGKILLs the milter mid-verdict. -timeout arrives via MAILSTRIX_MILTER_ARGS, so
# the unit cannot compute it; instead the env sample documents the -timeout ceiling
# (TimeoutStopSec - 5s) that needs a drop-in. This test parses the REAL shipped
# unit and env file and keeps the two in step.
#
# Usage: stop_timeout_test.sh            (checks the shipped files, then controls)
#        stop_timeout_test.sh check UNIT ENV   (checks the given pair; exit 1 on drift)
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
default_drain=25 # default -timeout 20s + drainGrace 5s
grace=5
headroom=5 # TimeoutStopSec must exceed the default drain by at least this

# check UNIT ENV: print findings, return non-zero on any drift.
check() {
    unit="$1"
    env="$2"
    rc=0
    # Last assignment wins, as in systemd. Only a bare-seconds value is accepted.
    tso="$(sed -nE 's/^[[:space:]]*TimeoutStopSec=[[:space:]]*([0-9]+)s?[[:space:]]*$/\1/p' "$unit" | tail -n 1)"
    if [ -z "$tso" ]; then
        echo "FAIL - $unit has no numeric TimeoutStopSec= (systemd default 90s is unrelated to -timeout)"
        return 1
    fi
    need=$((default_drain + headroom))
    if [ "$tso" -lt "$need" ]; then
        echo "FAIL - TimeoutStopSec=$tso is below default drain ${default_drain}s + ${headroom}s headroom ($need)"
        rc=1
    else
        echo "ok   - TimeoutStopSec=$tso >= $need"
    fi
    # The env note must state the ceiling: "a -timeout above <N>s needs a ... drop-in".
    note="$(tr '\n#' '  ' <"$env" | tr -s ' ' | grep -oE '\-timeout above [0-9]+s needs a systemd drop-in' | head -n 1 || true)"
    if [ -z "$note" ]; then
        echo "FAIL - $env has no '-timeout above <N>s needs a systemd drop-in' note"
        return 1
    fi
    ceil="$(printf '%s' "$note" | grep -oE '[0-9]+')"
    if [ "$ceil" -ne $((tso - grace)) ]; then
        echo "FAIL - env note ceiling ${ceil}s != TimeoutStopSec-${grace}s ($((tso - grace))s)"
        rc=1
    else
        echo "ok   - env note ceiling ${ceil}s == TimeoutStopSec-${grace}s"
    fi
    return "$rc"
}

if [ "${1:-}" = check ]; then
    check "$2" "$3"
    exit $?
fi

unit="$here/strix-milter.service"
env="$here/strix-milter.env"
if [ ! -f "$unit" ] || [ ! -f "$env" ]; then
    echo "FAIL - shipped unit/env missing"; exit 1
fi

fail=0
check "$unit" "$env" || fail=1

# Negative controls on temp copies: each mutation of the shipped files must go red.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
expect_red() {
    label="$1"
    if sh "$0" check "$tmp/u" "$tmp/e" >"$tmp/out" 2>&1; then
        echo "FAIL - control '$label' stayed green (test is inert)"; fail=1
    else
        echo "ok   - control '$label' goes red"
    fi
}
tso="$(sed -nE 's/^TimeoutStopSec=([0-9]+)$/\1/p' "$unit")"
[ -n "$tso" ] || { echo "FAIL - shipped TimeoutStopSec not a bare number line"; exit 1; }

sed '/^[[:space:]]*TimeoutStopSec=/d' "$unit" >"$tmp/u"; cp "$env" "$tmp/e"
expect_red "missing TimeoutStopSec"
sed -E 's/^TimeoutStopSec=.*/TimeoutStopSec=24/' "$unit" >"$tmp/u"
sed -E 's/above [0-9]+s needs/above 19s needs/' "$env" >"$tmp/e"
expect_red "value below 25s"
sed -E 's/^TimeoutStopSec=.*/TimeoutStopSec=29/' "$unit" >"$tmp/u"
expect_red "value 29 (<30, headroom)"
cp "$unit" "$tmp/u"
sed -E 's/above [0-9]+s needs/above 54s needs/' "$env" >"$tmp/e"
expect_red "mismatched env note"
grep -v 'timeout above' "$env" >"$tmp/e"
expect_red "missing env note"
# Positive control: a consistent raised pair is accepted.
sed -E 's/^TimeoutStopSec=.*/TimeoutStopSec=125/' "$unit" >"$tmp/u"
sed -E 's/above [0-9]+s needs/above 120s needs/' "$env" >"$tmp/e"
if sh "$0" check "$tmp/u" "$tmp/e" >"$tmp/out" 2>&1; then
    echo "ok   - control 'consistent raised pair' stays green"
else
    echo "FAIL - consistent raised pair rejected"; fail=1
fi

if [ "$fail" -eq 0 ]; then echo "ALL OK"; else echo "FAILURES"; exit 1; fi
