#!/bin/sh
# Verify the smoke matrix lives in ONE shared script (scripts/smoke.sh) and that
# the authoritative remote gate (.github/workflows/ci.yml docker job) invokes it
# rather than re-inlining the ~13 rule/extractor smoke blocks. Guards against the
# drift class where the inline smokes and a separate local gate diverge.
#
# The superrepo's tools/yarad-local-ci.sh also invokes the script, but it lives
# OUTSIDE this submodule, so it can't be checked from here — its invocation is
# verified by that file's own review. This test pins the in-repo half.
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0

script="$root/scripts/smoke.sh"
if [ ! -f "$script" ]; then
    echo "FAIL - scripts/smoke.sh missing"; exit 1
fi
if [ ! -x "$script" ]; then
    echo "FAIL - scripts/smoke.sh not executable"; fail=1
fi

ci="$root/.github/workflows/ci.yml"
if ! grep -q 'scripts/smoke.sh' "$ci"; then
    echo "FAIL - ci.yml does not invoke scripts/smoke.sh"; fail=1
fi

# No inline `name: smoke ...` step should remain in ci.yml — they must all be
# folded into the shared script (the one allowed match is the matrix step that
# CALLS the script, which has no per-rule body).
inline=$(grep -cE '^\s+- name: smoke \(' "$ci" || true)
if [ "$inline" -ne 0 ]; then
    echo "FAIL - $inline inline 'smoke (...)' step(s) still in ci.yml; fold into scripts/smoke.sh"
    fail=1
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "ok   - smoke matrix is shared (scripts/smoke.sh) and invoked by ci.yml"
echo "ALL OK"
