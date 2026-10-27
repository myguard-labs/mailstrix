#!/usr/bin/env bash
# Native, local-rules-only smoke for docker/profile/Dockerfile.profile.
# The positive image compiles the maintained fetch/filter/compile/capture
# pipeline and scans inert samples without network access. Two rebuilt
# Dockerfiles prove the helper and compiler instrumentation are load-bearing.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
run=${MAILSTRIX_PROFILE_PIPELINE_RUN:-profile-pipeline-$$}
case "$run" in
*[!A-Za-z0-9_.-]*)
	echo "invalid MAILSTRIX_PROFILE_PIPELINE_RUN: $run" >&2
	exit 2
	;;
esac
label="myguard.run=${run}"
image="mailstrix-profile:${run}"
container="mailstrix-profile-${run}"
tmp=$(mktemp -d)
evidence=${MAILSTRIX_PROFILE_PIPELINE_EVIDENCE:-$tmp}
mkdir -p "$evidence"

cleanup() {
	docker ps -aq --filter "label=${label}" | xargs -r docker rm -f >/dev/null || true
	docker image ls -q --filter "label=${label}" | sort -u | xargs -r docker image rm -f >/dev/null || true
	rm -rf "${tmp:?}"
}
trap cleanup EXIT

build() { # build DOCKERFILE TAG LOG
	docker build --progress=plain --label "$label" --build-arg LOCAL_ONLY=1 \
		-f "$1" -t "$2" "$root" >"$3" 2>&1
}

positive="$tmp/Dockerfile.profile"
cp "$root/docker/profile/Dockerfile.profile" "$positive"
if ! build "$positive" "$image" "$evidence/positive.log"; then
	echo "FAIL: profiling image build failed" >&2
	grep -nE 'error:|Error|undefined|No rule|No such|failed' "$evidence/positive.log" | tail -n 80 >&2 || true
	exit 1
fi

mkdir "$tmp/samples"
printf 'ordinary inert mail body\n' >"$tmp/samples/plain.txt"
docker run --rm --network none --label "$label" --name "$container" \
	-v "$tmp/samples:/samples:ro" "$image" \
	>"$evidence/profile.tsv" 2>"$evidence/profile.err"
grep -qx "$(printf 'COST\tNAMESPACE\tRULE')" "$evidence/profile.tsv"
grep -qx 'scanned 1 samples' "$evidence/profile.err"
[ "$(wc -l <"$evidence/profile.tsv")" -gt 1 ] || {
	echo "FAIL: profile smoke emitted no rule costs" >&2
	exit 1
}
echo "PASS: native profiling image compiled local rules and scanned an inert sample offline"

missing="$tmp/Dockerfile.missing-helper"
sed 's# docker/capture-compiler-inputs\.py##' "$positive" >"$missing"
if cmp -s "$positive" "$missing"; then
	echo "FAIL: missing-helper fixture was not mutated" >&2
	exit 1
fi
if build "$missing" "${image}-missing-helper" "$evidence/missing-helper.log"; then
	echo "FAIL: profiling image built without capture-compiler-inputs.py" >&2
	exit 1
fi
grep -Fq "can't open file '/usr/local/bin/capture-compiler-inputs.py'" \
	"$evidence/missing-helper.log"
echo "PASS: missing profiling helper control failed red"

plain="$tmp/Dockerfile.uninstrumented"
sed 's#python3 /tmp/capture/patch-compiler-input-capture.py \.#true#' \
	"$positive" >"$plain"
if cmp -s "$positive" "$plain"; then
	echo "FAIL: instrumentation fixture was not mutated" >&2
	exit 1
fi
if build "$plain" "${image}-uninstrumented" "$evidence/uninstrumented.log"; then
	echo "FAIL: profiling image built with an uninstrumented compiler" >&2
	exit 1
fi
grep -Fq 'compile-rules: input retention failed:' "$evidence/uninstrumented.log"
echo "PASS: missing compiler-capture instrumentation control failed red"
