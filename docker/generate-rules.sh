#!/usr/bin/env bash
# generate-rules.sh — build a fresh compiled YARA bundle and publish it as the
# `rules-current` GitHub release asset, with a manifest yarad's `--fetch-rules`
# reads to decide whether to update.
#
# Run from a home cron. It compiles the .yac INSIDE the build image (the `rules`
# stage), so `yarac` matches the libyara yarad links against — a .yac only loads
# on a matching libyara, so this is mandatory, not a convenience.
#
# The .yac (~37 MB) is published as a release ASSET, never committed to git, so
# the repo history stays small. The release tag `rules-current` is rolling: each
# run clobbers its assets.
#
# Manifest (compiled.yac.manifest.json), the file yarad fetches first:
#   version    monotonic integer — the update decision (yarad skips if <= local)
#   generated  RFC3339 UTC timestamp
#   checksum   "sha256:<hex>" of the .yac (integrity; the download crosses the net)
#   libyara    the libyara version that compiled it (the skew guard)
#   rules      rule count (sanity / display)
#   size       .yac size in bytes (sanity)
#
# Requirements: docker (buildx), gh (authenticated), jq, sha256sum.
# Env overrides: REPO (owner/name), TAG (default rules-current),
#   YARAFORGE_SET / *_REF build-args are passed through if set.
set -euo pipefail

REPO="${REPO:-eilandert/rspamd-yarad}"
TAG="${TAG:-rules-current}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"   # repo root (script lives in docker/)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

note() { echo "generate-rules: $*" >&2; }
die()  { note "ERROR: $*"; exit 1; }

for bin in docker gh jq sha256sum; do
    command -v "$bin" >/dev/null 2>&1 || die "missing required tool: $bin"
done

# 1) Build the rules-export stage and extract the .yac + the libyara version.
note "building rules (CACHEBUST forces a fresh fetch of the public rulesets)…"
docker buildx build \
    --target rules-export \
    --build-arg "CACHEBUST=$(date +%s)" \
    ${YARAFORGE_SET:+--build-arg "YARAFORGE_SET=${YARAFORGE_SET}"} \
    --output "type=local,dest=${WORK}" \
    -f "${HERE}/docker/Dockerfile" "${HERE}"

YAC="${WORK}/compiled.yac"
[ -s "$YAC" ] || die "no compiled.yac produced"
SOURCES="${WORK}/sources.json"
[ -f "$SOURCES" ] || note "no sources.json in export — provenance will be absent from manifest"
LIBYARA="$(tr -d '[:space:]' < "${WORK}/libyara.version")"
[ -n "$LIBYARA" ] || die "could not determine libyara version"

# 2) Determine the new monotonic version: previous (from the published manifest)
#    + 1. Never reuse or decrement.
#
#    CRITICAL: only treat version as 0 (first publish) when the release GENUINELY
#    does not exist. A release that EXISTS but whose manifest we failed to fetch
#    (transient gh/network error) must ABORT — silently resetting to 1 would
#    republish a LOWER version than the live one, breaking monotonicity and making
#    yarad skip every future update ("version 1 <= local"). So: no release ⇒ start
#    at 1; release present but manifest unreadable ⇒ die.
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    gh release download "$TAG" --repo "$REPO" \
        --pattern 'compiled.yac.manifest.json' --dir "$WORK" --clobber \
        || die "release ${TAG} exists but its manifest could not be fetched; refusing to reset the version (re-run when gh/network recovers)"
    PREV="$(jq -e -r '.version' "${WORK}/compiled.yac.manifest.json")" \
        || die "published manifest has no readable .version; refusing to guess"
    case "$PREV" in (''|*[!0-9]*) die "published version '${PREV}' is not an integer; refusing to bump" ;; esac
else
    note "no existing ${TAG} release — first publish, starting at version 1"
    PREV=0
fi
VERSION=$((PREV + 1))

# 3) Compute the checksum + sanity fields, write the manifest.
SUM="$(sha256sum "$YAC" | awk '{print $1}')"
SIZE="$(stat -c '%s' "$YAC")"
# Rule count: yarac doesn't print it; the build's compile step logs it, but for a
# robust standalone number, leave 0 if we can't get it cheaply (display-only).
RULES="${RULES_COUNT:-0}"
GENERATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

MANIFEST="${WORK}/compiled.yac.manifest.json"
if [ -f "$SOURCES" ]; then
    jq -n \
        --argjson version "$VERSION" \
        --arg generated "$GENERATED" \
        --arg checksum "sha256:${SUM}" \
        --arg libyara "$LIBYARA" \
        --argjson rules "$RULES" \
        --argjson size "$SIZE" \
        --slurpfile sources "$SOURCES" \
        '{version:$version, generated:$generated, checksum:$checksum, libyara:$libyara, rules:$rules, size:$size, sources:$sources[0]}' \
        > "$MANIFEST"
else
    jq -n \
        --argjson version "$VERSION" \
        --arg generated "$GENERATED" \
        --arg checksum "sha256:${SUM}" \
        --arg libyara "$LIBYARA" \
        --argjson rules "$RULES" \
        --argjson size "$SIZE" \
        '{version:$version, generated:$generated, checksum:$checksum, libyara:$libyara, rules:$rules, size:$size}' \
        > "$MANIFEST"
fi

note "version ${PREV} -> ${VERSION}, libyara ${LIBYARA}, size ${SIZE}, sha256 ${SUM:0:12}…"

# 4) Publish to the rolling release (create once if absent), clobbering assets.
if ! gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    note "creating rolling release ${TAG}"
    gh release create "$TAG" --repo "$REPO" \
        --title "Compiled rules (rolling)" \
        --notes "Rolling compiled YARA bundle for \`yarad --fetch-rules\`. Assets are clobbered on each rule regeneration; see compiled.yac.manifest.json for the current version." \
        --latest=false
fi
gh release upload "$TAG" --repo "$REPO" --clobber "$YAC" "$MANIFEST"

note "published ${TAG}: compiled.yac (v${VERSION}) + manifest"
