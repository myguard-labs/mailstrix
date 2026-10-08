#!/bin/bash
# Fail when combined Go statement coverage is below a floor.
# Usage: go_coverage.sh PROFILE [FLOOR_PERCENT]; PROFILE comes from the single
# `go test -coverpkg=./... -coverprofile=PROFILE` run, so no second test run.
# Default floor is the measured total on the head that introduced this gate,
# rounded down to one decimal; raise it, never lower it.
set -euo pipefail
if [[ ${1-} == --help ]]; then
	sed -n '2,6p' "$0"
	exit 0
fi
FLOOR_DEFAULT=85.5
profile=${1-}
floor=${2-$FLOOR_DEFAULT}
if [[ -z $profile || ! -s $profile ]]; then
	echo "go_coverage: missing or empty profile: ${profile:-<none>}" >&2
	exit 2
fi
if [[ ! $floor =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
	echo "go_coverage: invalid floor: $floor" >&2
	exit 2
fi
if ! out=$(go tool cover -func="$profile" 2>&1); then
	echo "go_coverage: unreadable profile: $profile" >&2
	exit 2
fi
total=$(awk '$1 == "total:" { sub(/%$/, "", $NF); print $NF }' <<<"$out")
if [[ ! $total =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
	echo "go_coverage: no total in profile: $profile" >&2
	exit 2
fi
if awk -v t="$total" -v f="$floor" 'BEGIN { exit !(t + 0 >= f + 0) }'; then
	echo "go_coverage: total ${total}% >= floor ${floor}%"
else
	echo "go_coverage: total ${total}% is below floor ${floor}%" >&2
	exit 1
fi
