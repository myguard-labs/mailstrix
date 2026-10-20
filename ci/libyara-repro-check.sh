#!/usr/bin/env bash
# Build the production yara stage twice from scratch and require an identical
# libyara.a, so one published marker artifact binds across rebuilds.
# Usage: ci/libyara-repro-check.sh [Dockerfile] [image-tag-prefix]
set -euo pipefail
declare -A sha
cd "$(dirname "$0")/.."
dockerfile="${1:-docker/Dockerfile}"
prefix="${2:-mailstrix-repro}-$$"
work="$(mktemp -d)"
extract="$prefix-extract"
cleanup() {
	docker container rm -f "$extract" >/dev/null 2>&1 || :
	docker image rm "$prefix-1" "$prefix-2" >/dev/null 2>&1 || :
	rm -rf "$work"
}
trap cleanup EXIT
for n in 1 2; do
	docker build --no-cache --target yara -f "$dockerfile" -t "$prefix-$n" .
	docker create --name "$extract" --label "myguard.run=$prefix" "$prefix-$n" >/dev/null
	docker cp "$extract:/usr/local/lib/libyara.a" "$work/libyara-$n.a"
	docker container rm -f "$extract" >/dev/null
	sha[$n]="$(sha256sum "$work/libyara-$n.a" | cut -d' ' -f1)"
	echo "libyara.a build $n sha256=${sha[$n]}"
done
if [ "${sha[1]}" != "${sha[2]}" ]; then
	echo "libyara.a is not byte-reproducible: ${sha[1]} != ${sha[2]}" >&2
	exit 1
fi
echo "libyara.a reproducible: ${sha[1]}"
