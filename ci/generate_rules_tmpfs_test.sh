#!/usr/bin/env bash
# Focused checks for docker/generate-rules.sh's pure marker tmpfs sizing contract.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
publisher="${GENERATE_RULES_SCRIPT:-${here}/docker/generate-rules.sh}"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

calculator="$test_root/calculator.sh"
awk '
    /# BEGIN marker verifier tmpfs sizing contract/ { copying=1; next }
    /# END marker verifier tmpfs sizing contract/ { copying=0 }
    copying { print }
' "$publisher" >"$calculator"
# shellcheck source=/dev/null
source "$calculator"
declare -F marker_gate_tmpfs_size >/dev/null \
    || { echo 'FAIL: marker tmpfs calculator contract was not found' >&2; exit 1; }

assert_size() {
    local name="$1" expected="$2"
    shift 2
    local actual
    actual="$(marker_gate_tmpfs_size "$@")" \
        || { echo "FAIL: ${name}: valid sizing input was refused" >&2; exit 1; }
    [ "$actual" = "$expected" ] \
        || { echo "FAIL: ${name}: got ${actual}, want ${expected}" >&2; exit 1; }
}

assert_refused() {
    local name="$1" diagnostic="$2"
    shift 2
    if marker_gate_tmpfs_size "$@" >"$test_root/out" 2>"$test_root/err"; then
        echo "FAIL: ${name}: invalid sizing input was accepted" >&2
        exit 1
    fi
    grep -F "$diagnostic" "$test_root/err" >/dev/null \
        || { echo "FAIL: ${name}: named diagnostic missing" >&2; cat "$test_root/err" >&2; exit 1; }
}

# On a supported 64 KiB-page ARM64 kernel, 65536 nonempty tiny files already
# need at least 4 GiB of data pages before the bundle, archive, directories, and
# metadata. Two explicit contract directories make 65538 archive members. This
# shape must therefore be rejected; a former 8192-byte/member allowance accepts
# it and is the negative control for this boundary.
arm64_tiny_files=65536
arm64_members=$((arm64_tiny_files + 2))
[ $((arm64_tiny_files * 65536)) -eq $((4 * 1024 * 1024 * 1024)) ] \
    || { echo 'FAIL: arm64-64k-page lower-bound test setup is invalid' >&2; exit 1; }
assert_refused arm64-64k-many-small-entries 'staged artifacts exceed the 4 GiB verifier ceiling' \
    1 1 "$arm64_tiny_files" "$arm64_members"

# Exact values independently pin simultaneous payload accounting, all reserves,
# MiB rounding, and the minimum safe allocation.
assert_size simultaneous-lifecycle size=142606336 16777216 8388608 33554432 100
assert_size minimum-valid size=68157440 1 1 1 4
assert_size maximum-logical-sizes-minimum-entries size=4061134848 \
    536870912 1073741824 2147483648 4

assert_refused maximum-valid-components 'staged artifacts exceed the 4 GiB verifier ceiling' \
    536870912 1073741824 2147483648 131072
assert_refused bundle-over-client-cap 'bundle outside client bounds' 536870913 1 1 4
assert_refused archive-over-client-cap 'archive outside client bounds' 1 1073741825 1 4
assert_refused tree-over-client-cap 'tree outside client bounds' 1 1 2147483649 4
assert_refused entries-over-client-cap 'entries outside client bounds' 1 1 1 131073
assert_refused tiny-bundle 'bundle outside client bounds' 0 1 1 4
assert_refused tiny-entry-set 'entries outside client bounds' 1 1 1 3
assert_refused malformed-decimal 'malformed archive' 1 1x 1 4
assert_refused signed-decimal 'malformed tree' 1 1 -1 4
assert_refused arbitrary-precision-overflow 'bundle outside client bounds' \
    999999999999999999999999999999999999 1 1 4

echo 'PASS: marker tmpfs sizing covers simultaneous artifacts, rounds safely, and rejects malformed or over-ceiling inputs'
