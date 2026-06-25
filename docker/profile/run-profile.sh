#!/bin/sh
# run-profile.sh — PERF-12 rule-cost profiling wrapper.
#
# Extracts the AES-encrypted live samples (testdata/live-samples/*.zip, pw
# `infected`), builds the profiling image, scans every sample on one
# accumulating YR_SCANNER, and prints the per-rule cost table (descending) so
# the dominant rules are obvious. Run from the repo root.
#
#   docker/profile/run-profile.sh [out.tsv]
#
# Requires: docker, python3 + pyzipper (pip install pyzipper) for the AES zips.
# Re-run after a redeploy — yaraify refetches daily; add new top-cost offenders
# to SLOW_RULE_DENYLIST in docker/fetch-rules.sh.
set -eu

OUT="${1:-perf12-rule-cost.tsv}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

SAMPLES="$(mktemp -d)"
trap 'rm -rf "$SAMPLES"' EXIT

echo "→ extracting live samples (pyzipper, pw=infected) → $SAMPLES" >&2
python3 - "$SAMPLES" <<'PY'
import sys, os, glob
import pyzipper
out = sys.argv[1]
n = 0
for zp in sorted(glob.glob("testdata/live-samples/*.zip")):
    base = os.path.basename(zp).rsplit(".zip", 1)[0]
    with pyzipper.AESZipFile(zp) as z:
        z.pwd = b"infected"
        for info in z.infolist():
            with open(os.path.join(out, base), "wb") as f:
                f.write(z.read(info.filename))
            n += 1
print(f"extracted {n} samples", file=sys.stderr)
PY

echo "→ building profiling image (libyara --enable-profiling + full ruleset)" >&2
docker build -f docker/profile/Dockerfile.profile -t yarad-profile \
    --build-arg CACHEBUST="$(date +%s)" . >&2

echo "→ scanning; cost table → $OUT" >&2
# FAST_MODE=1 in the env mirrors yarad's SCAN_FLAGS_FAST_MODE (PERF-15) so the
# total cost can be compared with/without the flag.
docker run --rm -e FAST_MODE="${FAST_MODE:-}" -v "$SAMPLES:/samples:ro" yarad-profile > "$OUT"

echo "→ top 10 by cost:" >&2
tail -n +2 "$OUT" | sort -t"$(printf '\t')" -k1,1 -nr | head -10 \
    | awk -F"$(printf '\t')" '{printf "%14d  %-42s %s\n",$1,substr($3,1,42),$2}' >&2
echo "→ wrote $(($(wc -l < "$OUT") - 1)) rules to $OUT" >&2
