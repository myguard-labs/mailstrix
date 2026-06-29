#!/bin/sh
# Verify the documented rule-source pin/toggle knobs actually reach the rule
# build. Three surfaces must agree: fetch-rules.sh HONORS the env var, the
# Dockerfile DECLARES it as an ARG (else --build-arg can't reach fetch-rules),
# and generate-rules.sh FORWARDS it (else the rolling bundle ignores it). The
# CAPE/YARAIFY drift — fetch-rules honored them but the Dockerfile never declared
# them and generate-rules never forwarded them — is the regression this guards.
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
df="$root/docker/Dockerfile"
gr="$root/docker/generate-rules.sh"
bad="$(mktemp)"
trap 'rm -f "$bad"' EXIT

# Args fetch-rules.sh reads and that --build-arg / the wrapper must be able to
# set. (YARAFORGE_URL/SIGBASE_REF/*_URL are pins for the same sources.)
ARGS="MAILSTRIX_PROFILE YARAFORGE_SET YARAFORGE_URL SIGBASE_REF \
ANYRUN ANYRUN_REF DIDIER DIDIER_REF BARTBLAZE BARTBLAZE_REF \
INQUEST INQUEST_REF CAPE CAPE_REF YARAIFY YARAIFY_URL"

for a in $ARGS; do
    grep -qE "^[[:space:]]*ARG[[:space:]]+$a([[:space:]=]|\$)" "$df" \
        || echo "Dockerfile missing: ARG $a" >> "$bad"
    grep -qE "[[:space:]]$a=\"\\\$\{$a\}\"" "$df" \
        || echo "Dockerfile does not pass $a into the fetch-rules RUN env" >> "$bad"
    grep -qE "\b$a\b" "$gr" \
        || echo "generate-rules.sh does not forward: $a" >> "$bad"
done

if [ -s "$bad" ]; then
    echo "FAIL - rule-source build-arg wiring gaps:"
    sed 's/^/  /' "$bad"
    exit 1
fi
echo "ok   - every documented rule-source arg is declared + passed + forwarded"
echo "ALL OK"
