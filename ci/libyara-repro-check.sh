#!/usr/bin/env bash
# Build the production yara stage twice from scratch and require an identical
# libyara.a, so one published marker artifact binds across rebuilds. Both layer
# and compiler-object reuse are disabled; normal production caching is unchanged.
# Usage: ci/libyara-repro-check.sh [Dockerfile] [image-tag-prefix] [platform]
# platform (e.g. linux/arm64) selects the published architecture to check; it
# is passed to both builds. Unset keeps the builder's default platform.
# Builds use `docker buildx build`, like build-binaries.yml, so the check runs on
# the same Buildx builder the published binaries use.
set -euo pipefail
declare -A sha
cd "$(dirname "$0")/.."
dockerfile="${1:-docker/Dockerfile}"
prefix="${2:-mailstrix-repro}-$$"
platform="${3:-}"
# --load is always passed: it keeps the image in the local store with both the
# docker driver and the docker-container driver (as after setup-buildx-action).
platform_args=()
create_args=()
if [ -n "$platform" ]; then
	platform_args=(--platform "$platform")
	create_args=(--platform "$platform")
fi
work="$(mktemp -d)"
extract="$prefix-extract"
cleanup() {
	docker container rm -f "$extract" >/dev/null 2>&1 || :
	docker image rm "$prefix-1" "$prefix-2" >/dev/null 2>&1 || :
	rm -rf "$work"
}
trap cleanup EXIT
for n in 1 2; do
	docker buildx build --no-cache --load "${platform_args[@]}" --target yara --build-arg CCACHE_DISABLE=1 -f "$dockerfile" -t "$prefix-$n" .
	docker create "${create_args[@]}" --name "$extract" --label "myguard.run=$prefix" "$prefix-$n" >/dev/null
	docker cp "$extract:/usr/local/lib/libyara.a" "$work/libyara-$n.a"
	docker cp "$extract:/tmp/ccache-repro.log" "$work/ccache-$n.log"
	results="$(sed -n 's/^.*Result: //p' "$work/ccache-$n.log" | sort -u)"
	if [ "$results" != disabled ] || ! grep -Eq 'Executing .*/gcc( .*)? -c( |$)' "$work/ccache-$n.log"; then
		echo "libyara.a build $n did not prove compiler-cache bypass" >&2
		exit 1
	fi
	echo "libyara.a build $n compiler-cache bypass verified"
	docker container rm -f "$extract" >/dev/null
	sha[$n]="$(sha256sum "$work/libyara-$n.a" | cut -d' ' -f1)"
	echo "libyara.a build $n sha256=${sha[$n]}"
done
if [ "${sha[1]}" != "${sha[2]}" ]; then
	echo "libyara.a is not byte-reproducible: ${sha[1]} != ${sha[2]}" >&2
	exit 1
fi
echo "libyara.a reproducible: ${sha[1]}"
