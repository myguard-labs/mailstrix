#!/bin/bash
# Fail locally on the CI planner's refusals (unmapped/unsafe changed paths) before push.
# Usage: ci-preflight.sh [BASE]; default BASE is the merge-base of origin/main and HEAD.
# Runs scripts/ci-impact.py over BASE..HEAD, then tools/testscope on its selection.
# Read-only; additions, edits and removals are all checked. Needs git, python3, go.
set -euo pipefail
if [[ ${1-} == --help ]]; then
	sed -n '2,5p' "$0"
	exit 0
fi
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=${1-}
if [[ -z "$base" ]]; then
	base=$(git merge-base origin/main HEAD)
fi
plan=$(python3 "$here/ci-impact.py" --base "$base" --head HEAD)
changed=$(python3 -c 'import json, sys; print(json.load(sys.stdin)["changed_files"])' <<<"$plan")
# Same argv construction as ci-go-checks.sh; empty means a full (non-PR) caller.
if [[ -n "$changed" ]]; then
	read -r -a changed_args <<<"$changed"
	(cd "$here/.." && go run ./tools/testscope "${changed_args[@]}") >/dev/null
fi
echo "ci-preflight: changed paths mapped (base ${base:0:12})"
