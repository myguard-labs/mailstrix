#!/bin/sh
# Validate the exported Docker context consumed by the native test selector.
set -eu

if [ "$#" -ne 2 ] || [ ! -d "$1" ] || [ ! -d "$2" ]; then
	echo "usage: docker_context_selector_test.sh EXPORTED_CONTEXT SOURCE_ROOT" >&2
	exit 2
fi

context=$1
source_root=$2
package=ci/cache_distribution

for source in main.go main_test.go; do
	[ -f "$context/$package/$source" ] || {
		echo "FAIL - $package/$source missing from exported Docker context" >&2
		exit 1
	}
	cmp "$source_root/$package/$source" "$context/$package/$source" || {
		echo "FAIL - $package/$source differs from source checkout" >&2
		exit 1
	}
done

sentinel="$package/private-corpus.sentinel.json"
if [ -e "$context/$sentinel" ] || [ -L "$context/$sentinel" ]; then
	echo "FAIL - $sentinel present in exported Docker context" >&2
	exit 1
fi

scope=$(cd "$context" && GOFLAGS=-buildvcs=false go run ./tools/testscope \
	--changed -- .dockerignore "$package/main.go" "$package/main_test.go" tools/testscope/main.go)
for expected in \
	"github.com/myguard-labs/mailstrix/$package" \
	"github.com/myguard-labs/mailstrix/tools/testscope"; do
	case " $scope " in
		*" $expected "*) ;;
		*) echo "FAIL - native selector scope lacks $expected: $scope" >&2; exit 1 ;;
	esac
done

echo "ok - exported cache_distribution Go sources select cache_distribution and testscope"
