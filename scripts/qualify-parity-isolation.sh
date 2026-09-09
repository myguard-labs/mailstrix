#!/usr/bin/env bash
# Build and qualify the optional Linux/amd64 parity worker with inert inputs.
# Usage: bash scripts/qualify-parity-isolation.sh [--cleanup-images] [--] NEW_OUTPUT_DIRECTORY
# Requires a local Docker daemon with cgroup v2 and the repository build inputs.
# Creates local images, bounded temporary containers and retained build/test logs.
# No external corpus, public rule refresh, deployment changes or dry-run mode.
# Extend named TestIsolatedLive tests for additional enforcement claims.
set -euo pipefail
if [[ $# -gt 0 ]]; then
	for arg in "$@"; do
		[[ $arg == -- ]] && break
		if [[ $arg == --help ]]; then
			printf '%s\n' 'Usage: bash scripts/qualify-parity-isolation.sh [--cleanup-images] [--] NEW_OUTPUT_DIRECTORY'
			exit 0
		fi
	done
fi
cleanup_images=0
options_done=0
output_dir=
while [[ $# -gt 0 ]]; do
	if ((options_done == 0)); then
		case $1 in
		--)
			options_done=1
			shift
			if [[ $# -eq 0 ]]; then
				printf '%s\n' 'One new output directory is required.' >&2
				exit 2
			fi
			continue
			;;
		--cleanup-images)
			if ((cleanup_images)); then
				printf '%s\n' 'Duplicate option: --cleanup-images.' >&2
				exit 2
			fi
			cleanup_images=1
			shift
			continue
			;;
		-*)
			printf 'Unknown option: %s.\n' "$1" >&2
			exit 2
			;;
		esac
	fi
	if [[ -z $1 ]]; then
		printf '%s\n' 'Output directory must not be empty.' >&2
		exit 2
	fi
	if [[ -n $output_dir ]]; then
		printf '%s\n' 'Only one output directory is allowed.' >&2
		exit 2
	fi
	output_dir=$1
	shift
done
if [[ -z $output_dir ]]; then
	printf '%s\n' 'One new output directory is required.' >&2
	exit 2
fi
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -- "$output_dir"
qualification_dir=$(cd -- "$output_dir" && pwd)
cd -- "$repo_dir"
docker_args=(--host unix:///var/run/docker.sock)
owned_tags=()
cleanup_owned_images() {
	local tag identity image_id image_owner inspect_status inspect_error stderr_file failed=0
	local diagnostic_line absent
	# Bash <=4.3 treats an empty array expansion as unset under nounset.
	if [[ -z ${owned_tags[*]:-} ]]; then
		return 0
	fi
	if ! stderr_file=$(mktemp -t mailstrix-parity-inspect.XXXXXXXX); then
		printf '%s\n' 'Cannot allocate Docker inspection diagnostic file.' >&2
		return 1
	fi
	# Remove only our references. Non-forced removal protects container users;
	# --no-prune preserves parents and other builds' shared layers.
	for tag in "${owned_tags[@]}"; do
		identity=$(timeout --kill-after=1s 5s docker "${docker_args[@]}" image inspect --format '{{.Id}} {{index .Config.Labels "io.myguard.parity-qualification.owner"}}' "$tag" 2>"$stderr_file") && inspect_status=0 || inspect_status=$?
		inspect_error=$(<"$stderr_file") || failed=1
		if [[ -n $inspect_error ]]; then
			printf '%s\n' "$inspect_error" || failed=1
		fi
		if ((inspect_status != 0)); then
			absent=0
			if ((inspect_status == 1)); then
				while IFS= read -r diagnostic_line; do
					case $diagnostic_line in
					"No such image: $tag" | "No such object: $tag" | \
						"Error: No such image: $tag" | "Error: No such object: $tag" | \
						"Error response from daemon: No such image: $tag" | \
						"Error response from daemon: No such object: $tag") absent=1 ;;
					esac
				done <<<"$inspect_error"
			fi
			if ((absent)); then
				printf 'Tag already absent: %s\n' "$tag" || failed=1
			else
				printf 'Image inspection failed: %s\n' "$tag"
				failed=1
			fi
			continue
		fi
		read -r image_id image_owner <<<"$identity"
		if [[ ! $image_id =~ ^sha256:[a-f0-9]{64}$ || $identity != "$image_id $image_owner" ]]; then
			printf 'Skipping cleanup (invalid image ID): %s\n' "$tag"
			failed=1
			continue
		fi
		if [[ $image_owner != "$owner" ]]; then
			printf 'Skipping cleanup (owner mismatch): %s\n' "$tag"
			failed=1
			continue
		fi
		if ! timeout --kill-after=2s 15s docker "${docker_args[@]}" image rm --no-prune "$tag"; then
			printf 'Retaining unavailable or shared image: %s\n' "$tag"
			failed=1
		fi
	done
	rm -- "$stderr_file" || failed=1
	return "$failed"
}
cleanup() {
	local status=$? cleanup_status=0 cleanup_log
	# Cleanup is best-effort even when artifact storage or diagnostics fail.
	set +e
	if { exec {cleanup_log}>>"$qualification_dir/image-cleanup.log"; }; then
		cleanup_owned_images >&"$cleanup_log" 2>&1 || cleanup_status=$?
		exec {cleanup_log}>&- || cleanup_status=1
	else
		cleanup_owned_images >&2
		cleanup_status=1
	fi
	if ((status == 0 && cleanup_status != 0)); then
		status=1
	fi
	exit "$status"
}
if ((cleanup_images)); then
	owner_dir=$(mktemp -d "$qualification_dir/image-owner.XXXXXXXXXXXX")
	owner=${owner_dir##*/}
	rmdir -- "$owner_dir"
	trap cleanup EXIT
fi
for target in parity-runtime parity-probe-runtime parity-qualification-bin; do
	output_args=(--load --iidfile "$qualification_dir/$target.id")
	if [[ $target == parity-qualification-bin ]]; then
		output_args=(--output "type=local,dest=$qualification_dir/bin")
	elif ((cleanup_images)); then
		tag="mailstrix-qualification:$owner-$target"
		owned_tags+=("$tag")
		output_args+=(--tag "$tag" --label "io.myguard.parity-qualification.owner=$owner")
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
