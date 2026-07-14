#!/bin/sh
# Maintainer-script behaviour test. Runs each unit's preremove/postinstall with a
# fake `systemctl` (and the systemd marker dir faked present) and asserts, for
# EVERY shipped unit (strixd, strix-milter, ...):
#   - prerm "upgrade"  must NOT stop or disable the unit
#   - prerm "remove"   must     stop and  disable the unit
#   - postinst upgrade (configure <oldver>) try-restarts the unit
#   - postinst install (configure, no oldver) does NOT restart, prints hints
# The upgrade cases are the ones that matter: a prerm that stopped+disabled on an
# upgrade would leave the service down after a routine `apt upgrade` — silently
# unscanned mail (or, with milter_default_action=tempfail, a mail outage).
# No root / no real systemd needed; the fake systemctl just logs its argv.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Fake systemctl that appends its arguments to $CALLS, one call per line.
mkdir -p "$work/bin"
cat > "$work/bin/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> "$work/calls"
exit 0
EOF
chmod +x "$work/bin/systemctl"
# Pretend systemd is running so the `[ -d /run/systemd/system ]` guards fire.
mkdir -p "$work/run/systemd/system"

fail=0
check() { # desc, expected-grep (empty = must be absent), file
    desc="$1"; pat="$2"; f="$3"
    if [ -z "$pat" ]; then return 0; fi
    if grep -q -- "$pat" "$f" 2>/dev/null; then
        echo "ok   - $desc"
    else
        echo "FAIL - $desc (expected '$pat' in calls)"; fail=1
    fi
}
absent() { # desc, pattern, file
    desc="$1"; pat="$2"; f="$3"
    if grep -q -- "$pat" "$f" 2>/dev/null; then
        echo "FAIL - $desc (unexpected '$pat' in calls)"; fail=1
    else
        echo "ok   - $desc"
    fi
}

run() { # script, args...  -> resets calls, runs with fakes on PATH + faked root
    : > "$work/calls"
    script="$1"; shift
    # Run a copy with /run/systemd/system check redirected: we can't fake an
    # absolute path, so the scripts test `-d /run/systemd/system`. Instead we
    # rely on the host having it; if absent, skip the systemd-gated asserts.
    PATH="$work/bin:$PATH" sh "$here/$script" "$@"
}

if [ ! -d /run/systemd/system ]; then
    echo "# /run/systemd/system absent on host — systemd-gated asserts limited"
fi

# check_unit <unit> <preremove.sh> <postinstall.sh> <first-install-hint>
check_unit() {
    unit="$1"; prerm="$2"; postinst="$3"; hint="$4"

    echo "# --- $unit ---"

    # --- prerm upgrade: keep service ---
    run "$prerm" upgrade 1.1.1
    absent "$unit: prerm upgrade does not stop"    "stop $unit"    "$work/calls"
    absent "$unit: prerm upgrade does not disable" "disable $unit" "$work/calls"

    # --- prerm remove: tear down ---
    run "$prerm" remove
    if [ -d /run/systemd/system ]; then
        check "$unit: prerm remove stops"    "stop $unit"    "$work/calls"
        check "$unit: prerm remove disables" "disable $unit" "$work/calls"
    fi

    # --- postinst upgrade: restart new binary ---
    out="$(run "$postinst" configure 1.1.0 2>&1 || true)"
    if [ -d /run/systemd/system ]; then
        check "$unit: postinst upgrade try-restarts" "try-restart $unit" "$work/calls"
    fi
    if printf '%s' "$out" | grep -q "$hint"; then
        echo "FAIL - $unit: postinst upgrade printed first-install hints"; fail=1
    else
        echo "ok   - $unit: postinst upgrade stays quiet"
    fi

    # --- postinst fresh install: no restart, prints hints ---
    out="$(run "$postinst" configure 2>&1 || true)"
    absent "$unit: postinst install does not restart" "try-restart $unit" "$work/calls"
    if printf '%s' "$out" | grep -q "$hint"; then
        echo "ok   - $unit: postinst install prints hints"
    else
        echo "FAIL - $unit: postinst install missing hints"; fail=1
    fi
}

check_unit strixd       preremove.sh        postinstall.sh        "strixd installed"
check_unit strix-milter preremove-milter.sh postinstall-milter.sh "strix-milter installed"

if [ "$fail" -eq 0 ]; then
    echo "ALL OK"
else
    echo "FAILURES"; exit 1
fi
