#!/usr/bin/env bash
# Build and qualify the optional Linux/amd64 parity worker with inert inputs.
# Usage: bash scripts/qualify-parity-isolation.sh NEW_OUTPUT_DIRECTORY
# Requires a local Docker daemon with cgroup v2 and the repository build inputs.
# Creates local images, bounded temporary containers and retained build/test logs.
# No external corpus, public rule refresh, deployment changes or dry-run mode.
# Extend named TestIsolatedLive tests for additional enforcement claims.
set -euo pipefail
if [[ ${1:-} == --help ]]; then
	printf '%s\n' 'Usage: bash scripts/qualify-parity-isolation.sh NEW_OUTPUT_DIRECTORY'
	exit 0
fi
if [[ $# != 1 ]]; then
	printf '%s\n' 'One new output directory is required.' >&2
	exit 2
fi
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -- "$1"
qualification_dir=$(cd -- "$1" && pwd)
cd -- "$repo_dir"
docker_args=(--host unix:///var/run/docker.sock)
for target in parity-runtime parity-probe-runtime parity-qualification-bin; do
	output_args=(--load --iidfile "$qualification_dir/$target.id")
	if [[ $target == parity-qualification-bin ]]; then
		output_args=(--output "type=local,dest=$qualification_dir/bin")
	fi
	if ! timeout 900s docker "${docker_args[@]}" buildx build \
		--platform linux/amd64 --target "$target" -f docker/Dockerfile \
		"${output_args[@]}" . >"$qualification_dir/$target.log" 2>&1; then
		tail -60 "$qualification_dir/$target.log" >&2
		exit 1
	fi
done
PARITY_WORKER_IMAGE=$(<"$qualification_dir/parity-runtime.id")
PARITY_PROBE_IMAGE=$(<"$qualification_dir/parity-probe-runtime.id")
if [[ ! $PARITY_WORKER_IMAGE =~ ^sha256:[a-f0-9]{64}$ || ! $PARITY_PROBE_IMAGE =~ ^sha256:[a-f0-9]{64}$ ]]; then
	printf '%s\n' 'Build did not produce immutable local image IDs.' >&2
	exit 1
fi
export PARITY_WORKER_IMAGE PARITY_PROBE_IMAGE
export PARITY_ISOLATION_REQUIRED=1 PARITY_RULES_DIR="$repo_dir/docker/local-rules"
timeout 120s "$qualification_dir/bin/parity.test" \
	-test.run '^TestIsolatedLive' -test.count=1 -test.v -test.timeout=110s |
	tee "$qualification_dir/qualification.log"
printf 'Isolation qualification artifacts: %s\n' "$qualification_dir"
