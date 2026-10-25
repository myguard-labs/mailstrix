#!/usr/bin/env bash
# Behavioral regression entry point. Go requires owning-package tests beside
# private fetch/marker helpers; the normal native Docker test lane runs them too.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
test -s ci/testdata/marker-runtime.zip || {
	printf 'prepare native fixtures first: python3 ci/prepare_marker_runtime.py\n' >&2
	exit 1
}
exec go test -count=1 -race -tags yara_static -run '^TestFetchRulesMarkerRetry' ./internal/mailstrix
