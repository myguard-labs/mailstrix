#!/bin/bash
# Selector unit tests and CLI/CI wiring controls; no native app tests.
set -eu
scope_bin_dir=$(mktemp -d)
trap 'rm -rf "$scope_bin_dir"' EXIT
go test -covermode=atomic -coverprofile="$scope_bin_dir/unit.out" ./tools/testscope
go build -cover -covermode=atomic -o "$scope_bin_dir/testscope" ./tools/testscope
mkdir "$scope_bin_dir/cov"
export GOCOVERDIR="$scope_bin_dir/cov"
scope=$("$scope_bin_dir/testscope" --changed --)
test -z "$scope"
scope=$("$scope_bin_dir/testscope" README.md)
test -z "$scope"
scope=$("$scope_bin_dir/testscope" .github/workflows/ci.yml)
case "$scope" in */tools/testscope) ;; *) exit 1 ;; esac
if "$scope_bin_dir/testscope" internal/gone/removed.go >"$scope_bin_dir/unknown" 2>&1; then
	echo 'unknown impact accepted' >&2
	exit 1
fi
grep -q 'unmapped changed paths' "$scope_bin_dir/unknown"
# Release caller compatibility: selection only, never execute that test suite.
scope=$("$scope_bin_dir/testscope")
test "$scope" = './...'
scope=$("$scope_bin_dir/testscope" --changed -- go.mod)
case "$scope" in '' | './...') exit 1 ;; esac
# Failed graph discovery must fail, not emit a broad selection.
mkdir "$scope_bin_dir/fake-go"
printf '#!/bin/sh\nexit 1\n' >"$scope_bin_dir/fake-go/go"
chmod +x "$scope_bin_dir/fake-go/go"
if PATH="$scope_bin_dir/fake-go:$PATH" "$scope_bin_dir/testscope" --changed -- README.md >"$scope_bin_dir/graph-error" 2>&1; then
	echo 'graph discovery failure accepted' >&2
	exit 1
fi
grep -q 'go list -m' "$scope_bin_dir/graph-error"
# Exercise package-list transport and malformed metadata separately.
cat >"$scope_bin_dir/fake-go/go" <<'FAKEGO'
#!/bin/sh
if [ "${2-}" = -m ]; then
    printf '%s\n' "$PWD"
    exit 0
fi
exit 1
FAKEGO
if PATH="$scope_bin_dir/fake-go:$PATH" "$scope_bin_dir/testscope" --changed -- README.md >"$scope_bin_dir/graph-error" 2>&1; then exit 1; fi
grep -q 'testscope: go list:' "$scope_bin_dir/graph-error"
sed -i 's/^exit 1$/printf malformed-json/' "$scope_bin_dir/fake-go/go"
if PATH="$scope_bin_dir/fake-go:$PATH" "$scope_bin_dir/testscope" --changed -- README.md >"$scope_bin_dir/graph-error" 2>&1; then exit 1; fi
grep -q 'invalid character' "$scope_bin_dir/graph-error"
# Keep coverage of CLI/error paths alongside the selector unit coverage.
go tool covdata textfmt -i "$scope_bin_dir/cov" -o "$scope_bin_dir/cli.out"

# shellcheck disable=SC2016 # literal workflow variable, not shell expansion
grep -q 'CHANGED_FILES="$changed"' .github/workflows/ci.yml
grep -q 'go run ./tools/testscope.*CHANGED_FILES' docker/Dockerfile
grep -q 'bash ci/testscope_test.sh' .github/workflows/ci.yml
grep -q -- '--changed --' .github/workflows/ci.yml
python3 - "$scope_bin_dir/unit.out" "$scope_bin_dir/cli.out" "$scope_bin_dir/merged.out" <<'COVER'
import sys
counts = {}
for source in sys.argv[1:3]:
    for line in open(source).read().splitlines()[1:]:
        key, statements, count = line.split()
        counts[(key, statements)] = counts.get((key, statements), 0) + int(count)
with open(sys.argv[3], "w") as result:
    result.write("mode: atomic\n")
    for (key, statements), count in sorted(counts.items()):
        result.write(f"{key} {statements} {count}\n")
COVER
go tool cover -func="$scope_bin_dir/merged.out"
