#!/bin/bash
# Emit validated workflow scopes from the checked-out PR merge/base or full caller.
# Usage: ci-plan.sh; inputs EVENT_NAME/GITHUB_OUTPUT; output planner JSON/job outputs.
# No builds/network; unknown paths or missing history select full CI.
set -euo pipefail
lane_manifest='{"version":1,"logical_groups":4,"grouping_runner_start_delta":0,"speed_claim":false,"lanes":['
lane_manifest+='{"id":"static-analysis","mode":"lightweight","jobs":[".github/workflows/ci.yml#scanners",".github/workflows/ci.yml#publisher-concurrency",".github/workflows/ci.yml#publisher-ordering",".github/workflows/maintenance.yml#codeql",".github/workflows/maintenance.yml#semgrep"],"observes":["scanners","publisher-concurrency","publisher-ordering","docker"]},'
lane_manifest+='{"id":"go-correctness","mode":"go-analysis-test","jobs":[".github/workflows/ci.yml#lint",".github/workflows/maintenance.yml#fuzz",".github/workflows/maintenance.yml#asan",".github/workflows/maintenance.yml#perf-regression",".github/workflows/maintenance.yml#race-arm64"],"observes":["lint","docker"]},'
lane_manifest+='{"id":"native-builds-artifacts","mode":"native-architecture","jobs":[".github/workflows/ci.yml#compiler-inputs",".github/workflows/ci.yml#pr-binaries",".github/workflows/ci.yml#pr-marker-image",".github/workflows/nightly.yml#binaries",".github/workflows/nightly.yml#marker-image",".github/workflows/build-binaries.yml#binaries",".github/workflows/release.yml#binaries",".github/workflows/release.yml#marker-image",".github/workflows/release.yml#debs",".github/workflows/release.yml#libyara-repro",".github/workflows/maintenance.yml#release-libyara-repro"],"observes":["compiler-inputs","pr-binaries","pr-marker-image"]},'
lane_manifest+='{"id":"contracts-integrations","mode":"isolated-integration","jobs":[".github/workflows/ci.yml#changes",".github/workflows/ci.yml#docker",".github/workflows/ci.yml#parity-isolation",".github/workflows/ci.yml#rspamd",".github/workflows/ci.yml#spamassassin",".github/workflows/ci.yml#ci-ok",".github/workflows/nightly.yml#plan",".github/workflows/nightly.yml#gate",".github/workflows/nightly.yml#publish",".github/workflows/release.yml#notes",".github/workflows/release.yml#gate",".github/workflows/release.yml#release",".github/workflows/runner-isolation.yml#leave-lxc-state",".github/workflows/runner-isolation.yml#prove-lxc-restore",".github/workflows/runner-isolation.yml#leave-docker-state",".github/workflows/runner-isolation.yml#prove-docker-restore",".github/workflows/runner-isolation.yml#cross-slot-negative-control"],"observes":["docker","parity-isolation","rspamd","spamassassin"]}],'
lane_manifest+='"step_overrides":[{"identity":".github/workflows/ci.yml#docker#build test stage (affected vet + race tests in-image)","lane":"go-correctness","mode":"production-yara-static-race-coverage"},{"identity":".github/workflows/ci.yml#docker#trivy image scan (HIGH,CRITICAL)","lane":"static-analysis","mode":"dependency-image-scan"}],'
lane_manifest+='"check_aliases":[{"current":".github/workflows/ci.yml#rspamd#Lua lint and unit tests (5.4 + 5.1)","baseline":[".github/workflows/ci.yml#rspamd#luacheck (Lua lint for rspamd plugin)",".github/workflows/ci.yml#rspamd#lua plugin unit tests (dedup + effort + explainability contracts)"],"lane":"contracts-integrations","mode":"batched-compatible-runtime"}]}'
readonly lane_manifest
if [[ ${1-} == --help ]]; then
	sed -n '2,4p' "$0"
	exit 0
fi
case "${EVENT_NAME:?}" in
pull_request) python3 scripts/ci-impact.py --base HEAD^1 --output "${GITHUB_OUTPUT:?}" ;;
*) python3 scripts/ci-impact.py --full --output "${GITHUB_OUTPUT:?}" ;;
esac
printf 'lane_manifest=%s\n' "$lane_manifest" >>"$GITHUB_OUTPUT"
