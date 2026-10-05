#!/bin/bash
# Analyze affected Go packages using the same dependency plan as Docker tests.
# Usage: ci-go-checks.sh; input CHANGED_FILES (selector argv, empty=full caller).
# Outputs analyzer diagnostics; no source mutation. Missing tools/errors are fatal.
# Extend tools/testscope for new external consumers; never substitute a full suite.
set -euo pipefail
if [[ ${1-} == --help ]]; then
	sed -n '2,6p' "$0"
	exit 0
fi
read -r -a changed_args <<<"${CHANGED_FILES-}"
packages=$(go run ./tools/testscope "${changed_args[@]}")
if [[ -z "$packages" ]]; then
	echo 'No affected Go analysis packages'
	exit 0
fi
read -r -a package_args <<<"$packages"
# Formatting follows selected package directories, including dependent consumers.
directories=$(go list -f '{{.Dir}}' "${package_args[@]}")
while IFS= read -r directory; do
	unformatted=$(gofmt -l "$directory"/*.go)
	if [[ -n "$unformatted" ]]; then
		printf 'gofmt needed:\n%s\n' "$unformatted" >&2
		exit 1
	fi
done <<<"$directories"
# Vet runs once in the Docker test stage with the production yara_static tag.
staticcheck "${package_args[@]}"
govulncheck "${package_args[@]}"
mapfile -t gosec_directories <<<"$directories"
gosec "${gosec_directories[@]}"
# The replaced module's own tests are outside the root package graph.
if [[ " ${CHANGED_FILES-} " == *' third_party/oleparse/'* || -z ${CHANGED_FILES-} ]]; then
	(cd third_party/oleparse && go test -race ./...)
fi
