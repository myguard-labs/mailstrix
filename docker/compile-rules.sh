#!/bin/sh
# compile-rules.sh — compile the fetched *.yar/*.yara into ONE precompiled .yac
# bundle at image-build time, so the runtime loads a ready set (low memory, fast
# start) instead of compiling ~10k rules on the mail host (that peaked at >3 GB
# and OOM-killed the container).
#
# Two things make this robust against real public rulesets:
#   * external variables — THOR/Loki-style rules reference filepath/filename/
#     extension/filetype/owner, and InQuest uses file_type; define them (empty
#     defaults) so those rules both
#     COMPILE and SCAN. The path conditions just never match raw mail bytes,
#     which is the right behaviour for a mail scanner. VBA=0 is declared the same
#     way for Didier's vba.yara (`VBA and any of (...)`): it must exist at compile
#     so the file isn't skipped, defaults to 0 (off) for raw bytes, and yarad
#     flips it to 1 at scan time ONLY for decompressed macro streams.
#   * per-file validation — a single file importing a module we didn't build in
#     (cuckoo/magic) or with bad syntax would fail the whole yarac run, so each
#     file is test-compiled alone first and only the good ones go in the bundle.
#
# NOTE: a .yac is locked to the libyara version that wrote it. yarac here comes
# from the same `yara` build stage that go-yara links against, so they match.
set -eu

SRC="${1:-/rules/src}"
OUT="${2:-/rules/compiled.yac}"
EXT="-d filepath= -d filename= -d extension= -d filetype= -d file_type= -d owner= -d VBA=0"

good="$(mktemp)"
tmpout="$(mktemp)"
n=0
skip=0
for f in "$SRC"/*.yar "$SRC"/*.yara; do
    [ -e "$f" ] || continue
    ns="$(basename "$f")"
    # shellcheck disable=SC2086
    if yarac $EXT "${ns}:${f}" "$tmpout" >/dev/null 2>&1; then
        printf '%s:%s\n' "$ns" "$f" >> "$good"
        n=$((n + 1))
    else
        echo "compile-rules: skip $ns (uncompilable)" >&2
        skip=$((skip + 1))
    fi
done
rm -f "$tmpout"

[ "$n" -gt 0 ] || { echo "compile-rules: nothing compiled from $SRC" >&2; exit 1; }

# one bundle from every good (namespaced) file
# shellcheck disable=SC2046,SC2086
yarac $EXT $(cat "$good") "$OUT"
rm -f "$good"
echo "compile-rules: bundled $n files ($skip skipped) -> $OUT"

# Carry sources.json (per-ruleset provenance) next to compiled.yac so the
# rm -rf of the src dir does not erase it.
OUTDIR="$(dirname "$OUT")"
if [ -f "$SRC/sources.json" ] && [ "$OUTDIR" != "$SRC" ]; then
    cp "$SRC/sources.json" "$OUTDIR/sources.json"
    echo "compile-rules: copied sources.json -> $OUTDIR/sources.json"
fi
