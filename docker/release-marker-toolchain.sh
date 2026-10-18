#!/bin/sh
# release-marker-toolchain.sh STRIXD TOOLCHAIN_DIR YARAC_DEST LIBYARA_DEST
#
# docker/Dockerfile.release consumes prebuilt release binaries. strixd only
# loads a marker artifact whose recorded compiler and static libyara hashes equal
# the identities linked into that binary (markerValidateBinding in
# internal/mailstrix/marker_artifact.go). libyara.a is not byte-reproducible
# (LTO objects carry random symbol seeds), so a locally rebuilt toolchain can
# never match. Releases therefore publish the exact yarac and libyara.a the
# binary was linked against; this helper installs them over the local yara
# stage so compile-rules.sh and build-marker-artifact.py use those exact bytes.
#
# Prints "marker" when the toolchain was installed and verified (the caller
# must build the marker artifact) or "legacy" for a release that predates
# marker support (no toolchain assets and no marker loader in strixd). Fails
# when a marker-capable strixd lacks the toolchain, when only half of it is
# present, or when either file's SHA-256 is not linked into strixd: such an
# image would silently log "marker artifact unavailable" and never load markers.
set -eu

if [ "$#" -ne 4 ]; then
	echo "usage: release-marker-toolchain.sh STRIXD TOOLCHAIN_DIR YARAC_DEST LIBYARA_DEST" >&2
	exit 2
fi
strixd=$1
dir=$2
yarac_dest=$3
libyara_dest=$4

[ -f "$strixd" ] || {
	echo "release-marker-toolchain: strixd not found: $strixd" >&2
	exit 1
}

if [ ! -e "$dir/yarac" ] && [ ! -e "$dir/libyara.a" ]; then
	# Every marker-capable strixd embeds this fallback log text.
	if grep -qaF 'marker artifact unavailable' "$strixd"; then
		echo "release-marker-toolchain: strixd loads marker artifacts but the release has no yarac/libyara assets" >&2
		exit 1
	fi
	echo legacy
	exit 0
fi

for f in yarac libyara.a; do
	[ -f "$dir/$f" ] || {
		echo "release-marker-toolchain: incomplete release toolchain: $f missing" >&2
		exit 1
	}
	sum=$(sha256sum "$dir/$f" | cut -d ' ' -f1)
	if ! grep -qaF "$sum" "$strixd"; then
		echo "release-marker-toolchain: release $f sha256 $sum is not linked into strixd" >&2
		exit 1
	fi
done

install -m 0755 "$dir/yarac" "$yarac_dest"
install -m 0644 "$dir/libyara.a" "$libyara_dest"
echo marker
