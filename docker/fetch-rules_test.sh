#!/bin/sh
# Test that invalid MAILSTRIX_PROFILE produces the intended diagnostic message
# (not "fail: not found" from calling fail before it was defined).
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/fetch-rules.sh"

# Use a temporary output directory
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Test 1: an invalid MAILSTRIX_PROFILE must produce the diagnostic (not
# "fail: not found") AND abort. MAILSTRIX_RULES_OPTIONAL=1 is set deliberately:
# it downgrades a failed download to a warning, and the validation must not be
# reachable through it. Without the exit-status assertion this test passed while
# the script printed the diagnostic and then fetched under the bad profile.
set +e
output=$(MAILSTRIX_PROFILE=invalid MAILSTRIX_RULES_OPTIONAL=1 "$script" "$tmpdir" 2>&1)
status=$?
set -e
if [ "$status" -eq 0 ]; then
    echo "FAIL - invalid MAILSTRIX_PROFILE exited 0; it must abort"
    echo "Output was: $output"
    exit 1
fi
if echo "$output" | grep -q "rule profile = invalid"; then
    echo "FAIL - invalid MAILSTRIX_PROFILE was accepted and used anyway"
    exit 1
fi
if echo "$output" | grep -q "invalid MAILSTRIX_PROFILE=invalid"; then
    echo "ok   - invalid MAILSTRIX_PROFILE produces the intended diagnostic and aborts"
else
    if echo "$output" | grep -q "fail: not found"; then
        echo "FAIL - fail() was called before being defined (error: 'fail: not found')"
        exit 1
    else
        echo "FAIL - invalid MAILSTRIX_PROFILE did not produce expected diagnostic"
        echo "Output was: $output"
        exit 1
    fi
fi

# Test 2: valid profiles should not trigger the error
for profile in mail full; do
    output=$(MAILSTRIX_PROFILE="$profile" LOCAL_ONLY=1 "$script" "$tmpdir" 2>&1 || true)
    if echo "$output" | grep -q "rule profile = $profile"; then
        echo "ok   - MAILSTRIX_PROFILE=$profile accepted"
    else
        echo "FAIL - MAILSTRIX_PROFILE=$profile was not accepted"
        exit 1
    fi
done

echo "ALL OK"
