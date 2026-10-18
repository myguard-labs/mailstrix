#!/usr/bin/env bash
# release_marker_image_test.sh ARCH ASSET_DIR
#
# Release-build control for docker/Dockerfile.release. ASSET_DIR holds one
# architecture's release assets as build-binaries.yml names them
# (strixd-linux-ARCH, strix-scan-linux-ARCH, strix-milter-linux-ARCH,
# yarac-linux-ARCH, libyara-linux-ARCH.a). The real Dockerfile.release is built
# with only its network fetch stage replaced by those local files, then:
#   positive: before strixd logs "listening on" (the initial rule load,
#             including the marker step, is complete), it has logged
#             "PERF-18: marker artifact loaded". A per-root "marker artifact
#             unavailable" line alone is not a failure: the writable cache root
#             is tried first and the baked seed root second;
#   negative: a yarac or libyara.a whose SHA-256 is not linked into strixd
#             fails the build at release-marker-toolchain.sh.
# Rules are LOCAL_ONLY so the control needs no public rule feeds.
# Every Docker resource carries --label myguard.run=$MAILSTRIX_RELEASE_MARKER_RUN
# and is removed by that label on exit.
set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: release_marker_image_test.sh ARCH ASSET_DIR" >&2
	exit 2
fi
arch=$1
assets=$(cd "$2" && pwd)
here=$(cd "$(dirname "$0")/.." && pwd)
run=${MAILSTRIX_RELEASE_MARKER_RUN:-release-marker-$$}
label="myguard.run=${run}"
image="mailstrix-release-marker:${run}-${arch}"
container="mailstrix-release-marker-${run}-${arch}"
wait_seconds=${MAILSTRIX_RELEASE_MARKER_WAIT:-300}
tmp=$(mktemp -d)

cleanup() {
	docker ps -aq --filter "label=${label}" | xargs -r docker rm -f >/dev/null || true
	docker image ls -q --filter "label=${label}" | sort -u | xargs -r docker image rm -f >/dev/null || true
	rm -rf "${tmp:?}"
}
trap cleanup EXIT

# Stage the fetch stage's /out layout from local release assets.
stage() { # stage DEST
	mkdir -p "$1/bin" "$1/marker"
	for b in strixd strix-scan strix-milter; do
		if [ -f "$assets/${b}-linux-${arch}" ]; then
			install -m 0755 "$assets/${b}-linux-${arch}" "$1/bin/${b}"
		fi
	done
	[ -x "$1/bin/strixd" ] || {
		echo "FAIL: $assets/strixd-linux-${arch} missing" >&2
		exit 1
	}
	install -m 0755 "$assets/yarac-linux-${arch}" "$1/marker/yarac"
	install -m 0644 "$assets/libyara-linux-${arch}.a" "$1/marker/libyara.a"
	cp "$here/NOTICE" "$1/NOTICE"
}

# The real Dockerfile.release with only the fetch stage swapped for a local
# named build context; every later stage is byte-for-byte the shipped text.
awk '
	/^FROM .* AS fetch$/ { print "FROM scratch AS fetch"; print "COPY --from=release / /out/"; skip = 1; next }
	skip && /^FROM / { skip = 0 }
	!skip { print }
' "$here/docker/Dockerfile.release" >"$tmp/Dockerfile.release"
grep -q '^COPY --from=release / /out/$' "$tmp/Dockerfile.release" ||
	{
		echo "FAIL: fetch stage not found in Dockerfile.release" >&2
		exit 1
	}

build() { # build CONTEXT_DIR LOG
	docker buildx build --load --platform "linux/${arch}" \
		--label "$label" -t "$image" \
		--build-arg VERSION=release-marker-ci --build-arg LOCAL_ONLY=1 \
		--build-context "release=$1" \
		-f "$tmp/Dockerfile.release" "$here" >"$2" 2>&1
}

# ---- negative: a toolchain not linked into strixd must fail the build -------
for f in yarac libyara.a; do
	stage "$tmp/bad-$f"
	printf 'x' >>"$tmp/bad-$f/marker/$f"
	if build "$tmp/bad-$f" "$tmp/bad-$f.log"; then
		echo "FAIL: mismatched $f built a release image" >&2
		exit 1
	fi
	if ! grep -q "release ${f} sha256 [0-9a-f]\{64\} is not linked into strixd" "$tmp/bad-$f.log"; then
		echo "FAIL: mismatched $f failed for another reason:" >&2
		tail -n 40 "$tmp/bad-$f.log" >&2
		exit 1
	fi
	echo "PASS: mismatched $f rejected by release-marker-toolchain.sh"
done

# ---- positive: the released toolchain bakes a marker artifact strixd loads ---
stage "$tmp/good"
if ! build "$tmp/good" "$tmp/good.log"; then
	echo "FAIL: release image build failed:" >&2
	tail -n 60 "$tmp/good.log" >&2
	exit 1
fi
docker image inspect "$image" >/dev/null
docker run -d --platform "linux/${arch}" --network none --label "$label" \
	--name "$container" "$image" >/dev/null
deadline=$((SECONDS + wait_seconds))
log="$tmp/container.log"
startup="$tmp/startup.log"
while :; do
	docker logs "$container" >"$log" 2>&1 || true
	if grep -q '\] listening on ' "$log"; then
		# Initial load is complete once strixd listens; judge only that window.
		sed '/\] listening on /q' "$log" >"$startup"
		if ! grep 'PERF-18: marker artifact loaded' "$startup"; then
			echo "FAIL: release image fell back to the full ruleset:" >&2
			grep 'PERF-18' "$startup" >&2 || true
			exit 1
		fi
		break
	fi
	if [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]; then
		echo "FAIL: strixd exited before loading rules:" >&2
		tail -n 40 "$log" >&2
		exit 1
	fi
	if [ "$SECONDS" -ge "$deadline" ]; then
		echo "FAIL: no marker load within ${wait_seconds}s:" >&2
		tail -n 40 "$log" >&2
		exit 1
	fi
	sleep 2
done
echo "PASS: ${arch} release image loads the marker artifact"
