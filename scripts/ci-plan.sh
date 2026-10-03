#!/bin/bash
# Emit validated workflow scopes from the checked-out PR merge/base or full caller.
# Usage: ci-plan.sh; inputs EVENT_NAME/GITHUB_OUTPUT; output planner JSON/job outputs.
# No builds/network; unknown paths or missing history fail before publishing outputs.
set -euo pipefail
if [[ ${1-} == --help ]]; then
	sed -n '2,4p' "$0"
	exit 0
fi
case "${EVENT_NAME:?}" in
pull_request) python3 scripts/ci-impact.py --base HEAD^1 --output "${GITHUB_OUTPUT:?}" ;;
*) python3 scripts/ci-impact.py --full --output "${GITHUB_OUTPUT:?}" ;;
esac
