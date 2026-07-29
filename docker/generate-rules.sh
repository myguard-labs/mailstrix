#!/usr/bin/env bash
# generate-rules.sh — build a fresh compiled YARA bundle and publish it as the
# `rules-current` GitHub release asset, with a manifest strixd's `--fetch-rules`
# reads to decide whether to update.
#
# Run from a home cron. It compiles the .yac INSIDE the build image (the `rules`
# stage), so `yarac` matches the libyara strixd links against — a .yac only loads
# on a matching libyara, so this is mandatory, not a convenience.
#
# The .yac (~37 MB) is published as a release ASSET, never committed to git, so
# the repo history stays small. The release tag `rules-current` is rolling: each
# run clobbers its assets.
#
# Manifest (compiled.yac.manifest.json), the file strixd fetches first:
#   version    monotonic integer — the update decision (strixd skips if <= local)
#   generated  RFC3339 UTC timestamp
#   checksum   "sha256:<hex>" of the .yac (integrity; the download crosses the net)
#   libyara    the libyara version that compiled it (the skew guard)
#   rules      rule count (sanity / display)
#   size       .yac size in bytes (sanity)
#
# Requirements: docker (buildx), gh (authenticated), jq, sha256sum.
# Env overrides: REPO (owner/name), TAG (default rules-current).
#   Every documented rule-source build-arg is passed through to the Dockerfile
#   when set in the environment: YARAFORGE_SET, YARAFORGE_URL, SIGBASE_REF,
#   ANYRUN(/_REF), DIDIER(/_REF), BARTBLAZE(/_REF), INQUEST(/_REF),
#   CAPE(/_REF), YARAIFY(/_URL) — so the rolling bundle honours the same
#   pin/toggle knobs as a direct image build.
set -euo pipefail

REPO="${REPO:-myguard-labs/mailstrix}"
TAG="${TAG:-rules-current}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"   # repo root (script lives in docker/)

# gh needs a token with contents:write on the myguard-labs ORG to publish the
# rolling release. The build user's default gh login (hosts.yml) carries the
# personal GITHUB_API_TOKEN, which only has READ on org repos -> asset upload/
# clobber 403s ("Resource not accessible by personal access token"). The
# org-owned fine-grained PAT lives in /etc/myguard-build-env as
# GITHUB_ORG_LAB_TOKEN; export it as GH_TOKEN so every gh call here uses it
# without disturbing the default login or GITHUB_API_TOKEN (lastversion's key).
# build-env is mode 600 root-only (since 2026-07-26), so a plain `[ -r ]` test is
# FALSE for the cron user (eilander) and the old sourcing block was skipped
# SILENTLY -> GH_TOKEN unset -> gh fell back to the interactive hosts.yml login.
# Read it via `sudo cat` (passwordless sudo on this host) and extract only the one
# var, so an `export `-prefixed line still matches and no other secret enters the
# environment. No token => die here: publishing is impossible without it, and
# failing fast beats discovering it after a 55s docker build.
if [ -z "${GH_TOKEN:-}" ]; then
    GH_TOKEN="$(sudo -n cat /etc/myguard-build-env 2>/dev/null \
        | sed -n 's/^[[:space:]]*\(export[[:space:]]\+\)\?GITHUB_ORG_LAB_TOKEN=//p' \
        | tail -n1 | tr -d '"'"'"'' | tr -d "'")"
    export GH_TOKEN
fi
# Never let a stale/invalid ~/.config/gh/hosts.yml login serve as the fallback:
# that token is currently invalid and 401s even on READS, which is what defeated
# the version guard below. GH_TOKEN takes precedence over hosts.yml in gh.
[ -n "${GH_TOKEN:-}" ] || { echo "generate-rules: ERROR: GITHUB_ORG_LAB_TOKEN not readable from /etc/myguard-build-env; cannot publish" >&2; exit 1; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

note() { echo "generate-rules: $*" >&2; }

# Discord #builds shout (via discord-notify.py → myguard-discord-bot socket; the
# build host has no DISCORD_WEBHOOK_*, only the bot). Best-effort: a notify
# failure must never fail the publish, so swallow errors. Located relative to the
# repo root (HERE) so cron's minimal PATH still finds it.
NOTIFY="${HERE}/../../tools/discord-notify.py"
_SHOUTED_FAIL=0
shout() {  # shout <title> <body>
    [ -x "$NOTIFY" ] || return 0
    python3 "$NOTIFY" message "$1" "$2" >/dev/null 2>&1 || true
}
shout_fail() {  # shout_fail <body> — fires at most once per run
    [ "$_SHOUTED_FAIL" -eq 0 ] || return 0
    _SHOUTED_FAIL=1
    shout "strixd rules: regeneration FAILED" "$1"
}

# Any unexpected abort (set -e / a failed command) shouts FAIL to #builds before
# exiting, so a broken nightly is visible instead of silent. die() shouts its own
# message; the once-guard stops a double-shout when die triggers ERR.
# shellcheck disable=SC2154  # rc IS assigned (rc=$?) inside the trap-quoted string
trap 'rc=$?; [ "$rc" -ne 0 ] && shout_fail "generate-rules.sh exited $rc — rules-current NOT updated. Check /opt/myguard/packages/log/yarad-generate-rules.log"; exit $rc' ERR

die()  { note "ERROR: $*"; shout_fail "$*"; exit 1; }

for bin in docker gh jq sha256sum python3; do
    command -v "$bin" >/dev/null 2>&1 || die "missing required tool: $bin"
done

# 1) Build the rules-export stage and extract the .yac + the libyara version.
# Forward every documented rule-source build-arg that is set in the environment
# so the published rolling bundle honours the same pin/toggle knobs as a direct
# `docker build --build-arg …` of the image.
note "building rules (CACHEBUST forces a fresh fetch of the public rulesets)…"
build_args=""
for v in MAILSTRIX_PROFILE YARAFORGE_SET YARAFORGE_FILTER YARAFORGE_URL SIGBASE_REF \
         ANYRUN ANYRUN_REF DIDIER DIDIER_REF BARTBLAZE BARTBLAZE_REF \
         INQUEST INQUEST_REF CAPE CAPE_REF YARAIFY YARAIFY_URL; do
    eval "val=\${$v+set}"
    [ "${val:-}" = set ] || continue
    eval "build_args=\"\$build_args --build-arg $v=\${$v}\""
done
# shellcheck disable=SC2086  # build_args is a deliberately word-split arg list
docker buildx build \
    --target rules-export \
    --build-arg "CACHEBUST=$(date +%s)" \
    $build_args \
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
#    strixd skip every future update ("version 1 <= local"). So: no release ⇒ start
#    at 1; release present but manifest unreadable ⇒ die.
#    The existence probe must NOT rely on `gh release view`'s exit status: with an
#    invalid credential gh has been observed printing "401 Unauthorized" while
#    STILL exiting 0, so the old `if gh release view` took the else-branch and
#    reset the version to 1 while live was 34 (2026-07-30). Probe the REST API and
#    branch on the HTTP STATUS instead: 200 => exists, 404 => genuinely absent,
#    anything else (401/403/5xx) => credential/network fault, so abort rather than
#    guess. This is what actually enforces the monotonicity rule described above.
RELEASE_HTTP="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${REPO}/releases/tags/${TAG}" || echo 000)"
case "$RELEASE_HTTP" in
    200|404) : ;;
    *) die "cannot determine whether release ${TAG} exists (HTTP ${RELEASE_HTTP}); refusing to guess the version — check the GITHUB_ORG_LAB_TOKEN and network" ;;
esac

if [ "$RELEASE_HTTP" = 200 ]; then
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
# Reuse the HTTP-status probe from step 1 (same reason: gh's exit status is not
# trustworthy here). RELEASE_HTTP is 200 or 404 by now — anything else already died.
if [ "$RELEASE_HTTP" != 200 ]; then
    note "creating rolling release ${TAG}"
    gh release create "$TAG" --repo "$REPO" \
        --title "Compiled rules (rolling)" \
        --notes "Rolling compiled YARA bundle for \`strixd --fetch-rules\`. Assets are clobbered on each rule regeneration; see compiled.yac.manifest.json for the current version." \
        --latest=false
fi
gh release upload "$TAG" --repo "$REPO" --clobber "$YAC" "$MANIFEST"

note "published ${TAG}: compiled.yac (v${VERSION}) + manifest"

# Shout success to Discord #builds. Size in MiB; rules count only if known (>0).
SIZE_MIB="$(awk -v b="$SIZE" 'BEGIN{printf "%.1f", b/1048576}')"
rules_line=""; [ "${RULES:-0}" -gt 0 ] 2>/dev/null && rules_line=", ${RULES} rules"
shout "strixd rules: rules-current v${VERSION} published" \
      "Fresh compiled YARA bundle published to \`${TAG}\` (v${PREV}→v${VERSION}${rules_line}, ${SIZE_MIB} MiB, libyara ${LIBYARA}). strixd \`--fetch-rules\` clients update on next check."
