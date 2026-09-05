#!/bin/sh
# Enforce immutable CI inputs.
#
# Three properties. The first two are what make a pin real — pinning without
# enforcement rots back to tags the first time someone adds a step:
#
#   1. EVERY third-party `uses:` is pinned to a full 40-hex commit SHA. A tag
#      (@v4) or branch (@main) ref is mutable: whoever can move the tag decides
#      what runs in CI, with privileged runner access, no diff and no review.
#      Local refs (./...) are exempt — they come from this repo and are covered
#      by ordinary review.
#   2. Every `go install` pins an exact version. `@latest` is the same hole in a
#      different coat: it silently adopts whatever upstream published most
#      recently. A ${VAR} ref is accepted — the literal it expands to is pinned
#      in the workflow (and keyed into the tool cache, so a bump actually takes
#      effect instead of being masked by a stale cached binary).
#   3. An action must not be pinned to two DIFFERENT SHAs across workflows: one
#      of them is stale or typo'd, and its jobs die at action resolution before
#      doing any work.
set -eu

scriptdir="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
root="${1:-$(cd "$scriptdir/../.." && pwd)}"
python3 "$scriptdir/immutable_inputs_test.py" "$root"
echo "ALL OK"
