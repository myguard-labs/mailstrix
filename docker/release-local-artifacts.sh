#!/bin/sh
# release-local-artifacts.sh ARCH IN_DIR OUT_DIR
#
# Local-candidate counterpart of the fetch-download stage in
# docker/Dockerfile.release (RELEASE_SOURCE=local). IN_DIR holds one
# architecture's candidate assets under the names build-binaries.yml gives them:
# strixd-linux-ARCH, strix-scan-linux-ARCH, strix-milter-linux-ARCH,
# yarac-linux-ARCH and libyara-linux-ARCH.a. They are laid out as the download
# stage does (OUT_DIR/bin/{strixd,strix-scan,strix-milter}, OUT_DIR/marker/
# {yarac,libyara.a}).
#
# Fails closed: a candidate is complete or it is rejected. Unlike the download
# stage, nothing is optional (a candidate build always produces strix-milter and
# the marker toolchain), an empty file is rejected, and there is never a
# fallback to downloading a published release. The toolchain-to-strixd binding is
# still enforced afterwards by release-marker-toolchain.sh in the rules stage.
set -eu

if [ "$#" -ne 3 ]; then
	echo "usage: release-local-artifacts.sh ARCH IN_DIR OUT_DIR" >&2
	exit 2
fi
arch=$1
in=$2
out=$3

case "$arch" in
'' | *[!a-z0-9_]*)
	echo "release-local-artifacts: invalid ARCH: $arch" >&2
	exit 2
	;;
esac
[ -d "$in" ] || {
	echo "release-local-artifacts: input directory not found: $in" >&2
	exit 1
}

missing=""
for f in "strixd-linux-$arch" "strix-scan-linux-$arch" "strix-milter-linux-$arch" \
	"yarac-linux-$arch" "libyara-linux-$arch.a"; do
	[ -f "$in/$f" ] && [ -s "$in/$f" ] || missing="$missing $f"
done
if [ -n "$missing" ]; then
	echo "release-local-artifacts: incomplete local artifacts (missing or empty):$missing" >&2
	exit 1
fi

mkdir -p "$out/bin" "$out/marker"
for b in strixd strix-scan strix-milter; do
	install -m 0755 "$in/$b-linux-$arch" "$out/bin/$b"
done
install -m 0755 "$in/yarac-linux-$arch" "$out/marker/yarac"
install -m 0644 "$in/libyara-linux-$arch.a" "$out/marker/libyara.a"
