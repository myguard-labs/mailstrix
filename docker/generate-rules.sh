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
#   marker     OPTIONAL {asset,sha256,size,libyara_sha256,compiler_sha256,main_sha256}
#              describing marker-tree.tar.gz, the signed marker artifact tree that
#              lets strixd keep its marker speed gain after a rules refresh. It is
#              published only when the bundle was compiled with the latest
#              release's exact yarac + libyara.a (docker/Dockerfile.release,
#              docker/release-marker-toolchain.sh) AND that release's strixd
#              loaded the staged candidate with `fetch-rules -verify-only
#              -require-marker` before upload. Any other outcome publishes the
#              bundle, manifest and signature exactly as before, with no field.
#
# Detached signature (compiled.yac.manifest.json.sig), published beside it:
#   base64 of the raw 64-byte ed25519 signature over the exact manifest bytes.
#   strixd verifies it against the public key(s) compiled into the binary and
#   refuses an unsigned, malformed or untrusted manifest, so publication without
#   a signature produces a bundle no client will install.
#
# Requirements: docker (buildx), gh (authenticated), git, jq, sha256sum, go.
# Required secret: MAILSTRIX_RULES_SIGNING_KEY — the ed25519 PKCS#8 PEM signing
#   key, supplied through the ENVIRONMENT only (never argv). It must stay out of
#   any pull_request-triggered CI job.
#   The cron run has no such environment (the key is a GitHub Actions secret), so
#   this script also resolves it from /etc/myguard-build-env. The PEM is
#   multi-line and the build-env extractor is line-based, so build-env carries
#   ONE base64 line instead:
#     MAILSTRIX_RULES_SIGNING_KEY_B64=<base64 of the ed25519 PKCS#8 PEM>
#   Install it as root, e.g.
#     base64 -w0 key.pem   # paste the single line into /etc/myguard-build-env
#   keeping the file root-owned and mode 600. An already-set
#   MAILSTRIX_RULES_SIGNING_KEY wins and the build-env fallback is skipped, so
#   CI and manual runs are unchanged. Neither value is ever printed, logged, or
#   placed on a command line.
# Env overrides: REPO (owner/name), TAG (default rules-current),
#   MARKER_RELEASE_TAG (release whose marker toolchain compiles the bundle;
#   default: the latest published release; "off" disables the marker tree).
#   PUBLISH_LEASE_RECOVER_OID removes exactly that expired publisher mutex and
#   continues only after an operator has independently proved its holder ended.
#   Every documented rule-source build-arg is passed through to the Dockerfile
#   when set in the environment: YARAFORGE_SET, YARAFORGE_URL, SIGBASE_REF,
#   ANYRUN(/_REF), DIDIER(/_REF), BARTBLAZE(/_REF), INQUEST(/_REF),
#   CAPE(/_REF), YARAIFY(/_URL) — so the rolling bundle honours the same
#   pin/toggle knobs as a direct image build.
set -euo pipefail

REPO="${REPO:-myguard-labs/mailstrix}"
TAG="${TAG:-rules-current}"
HERE=""
WORK=""
LOG="/opt/myguard/packages/log/yarad-generate-rules.log"

# Seed the best-effort notifier path without a subshell or external command so
# startup failures while canonicalizing HERE can still notify.
case "${BASH_SOURCE[0]}" in
    */*) notifier_dir="${BASH_SOURCE[0]%/*}" ;;
    *) notifier_dir="." ;;
esac
case "$notifier_dir" in
    /*) ;;
    *) notifier_dir="${PWD}/${notifier_dir}" ;;
esac
NOTIFY="${notifier_dir}/../../../tools/discord-notify.py"

note() { echo "generate-rules: $*" >&2; }

# Emit one JSON object for the terminal nightly result. Successful receipts carry
# the same identity and native-load evidence as `strixd fetch-rules -verify-only`;
# failures intentionally contain only a fixed stage/status pair, so cron logs do
# not turn command output or credentials into an artifact.
NIGHTLY_STAGE=build
PUBLISH_STATE=not-started
_RECEIPTED=0
_RECEIPT_WRITE_ATTEMPTED=0
_RECEIPT_EMITTING=0
_PENDING_SIGNAL=0
_FAILURE_EXIT=0
nightly_receipt() {  # nightly_receipt <success|failed>
    local status="$1" receipt
    [ "$_RECEIPTED" -eq 0 ] || return 0
    # A failed write may already have emitted a prefix. Never append a fallback
    # object after that attempt; serializer failures before stdout remain retryable.
    [ "$_RECEIPT_WRITE_ATTEMPTED" -eq 0 ] || return 1
    if [ "$status" = success ]; then
        receipt="$(jq -cn \
            --arg stage "$NIGHTLY_STAGE" \
            --arg status "$status" \
            --argjson version "$VERSION" \
            --arg generated "$GENERATED" \
            --arg checksum "sha256:${SUM}" \
            --arg libyara "$LIBYARA" \
            --argjson rules "$RULES" \
            --argjson size "$SIZE" \
            '{schema:"mailstrix-rules-nightly-v1", stage:$stage, status:$status, version:$version, generated:$generated, checksum:$checksum, libyara:$libyara, rules:$rules, size:$size, loadable:true}')" || return 1
    else
        receipt="$(jq -cn --arg stage "$NIGHTLY_STAGE" --arg status "$status" \
            '{schema:"mailstrix-rules-nightly-v1", stage:$stage, status:$status}')" || return 1
    fi
    # A signal received while the serializer child was running is handled once
    # this function unwinds. Do not expose the now-stale success object first.
    [ "$status" = failed ] || [ "$_PENDING_SIGNAL" -eq 0 ] || return 0
    # Functions do not inherit ERR by default, so explicitly return a failed
    # output write to the caller. Record the attempt before the write, separately
    # from completion so signals cannot mistake a partial receipt for success.
    _RECEIPT_WRITE_ATTEMPTED=1
    if ! printf '%s\n' "$receipt"; then
        return 1
    fi
    _RECEIPTED=1
}

# Discord #builds shout (via discord-notify.py → myguard-discord-bot socket; the
# build host has no DISCORD_WEBHOOK_*, only the bot). Best-effort: a notify
# failure must never fail the publish, so swallow errors. Located relative to the
# repo root (HERE) so cron's minimal PATH still finds it.
_SHOUTED_FAIL=0
shout() {  # shout <title> <body>
    [ -x "$NOTIFY" ] || return 0
    python3 "$NOTIFY" message "$1" "$2" >/dev/null 2>&1 || true
}
shout_fail() {  # shout_fail <body> — fires at most once per run
    [ "$_SHOUTED_FAIL" -eq 0 ] || return 0
    _SHOUTED_FAIL=1
    _RECEIPT_EMITTING=1
    if ! nightly_receipt failed; then
        note "ERROR: failed to emit nightly receipt"
    fi
    _RECEIPT_EMITTING=0
    shout "strixd rules: ${NIGHTLY_STAGE} FAILED" "$1"
    finish_pending_signal
}
published_verify_notice() {  # published_verify_notice <failed|"was interrupted">
    printf 'rules-current v%s was published, but native verification %s; clients may encounter an unverified bundle. Inspect and repair the release. Check %s' "$VERSION" "$1" "$LOG"
}
failure_notice() {  # failure_notice <exit-code>
    case "$NIGHTLY_STAGE" in
        receipt)
            printf '%s' "terminal receipt preparation or emission failed after rules-current was published and native-verified. Check $LOG"
            ;;
        *)
            case "$PUBLISH_STATE" in
                not-started)
                    printf 'generate-rules.sh exited %s — rules-current NOT updated. Check %s' "$1" "$LOG"
                    ;;
                uncertain)
                    printf 'generate-rules.sh exited %s — rules-current may be partially updated. Check %s' "$1" "$LOG"
                    ;;
                published)
                    case "$NIGHTLY_STAGE" in
                        verify)
                            case "$1" in
                                129|130|143) published_verify_notice 'was interrupted' ;;
                                *) published_verify_notice failed ;;
                            esac
                            ;;
                        *) printf 'generate-rules.sh exited %s — rules-current was published, but the nightly did not finish. Check %s' "$1" "$LOG" ;;
                    esac
                    ;;
            esac
            ;;
    esac
}

# Any unexpected abort (set -e / a failed command) shouts FAIL to #builds before
# exiting, so a broken nightly is visible instead of silent. die() shouts its own
# message; the once-guard stops a double-shout when die triggers ERR. The
# Discord delivery itself is the publisher-only best-effort exception; build,
# publish, and verify failures remain fatal. A receipt-emission fault cannot
# mask the original failure after its stage-specific alert is sent.
SERVER_PID=""
PUBLISH_LEASE_HELD=0
PUBLISH_LEASE_HEARTBEAT_PID=""
PUBLISH_LEASE_STOP_FD=""
PUBLISH_LEASE_ACTIVE_LOCK_FD=""
cleanup() {
    [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
    # EXIT traps run before Bash closes descriptors owned by an interrupted
    # function. Release a foreground local-lock descriptor first, otherwise the
    # heartbeat wait and exact-OID release below can block behind our own flock.
    if [ -n "$PUBLISH_LEASE_ACTIVE_LOCK_FD" ]; then
        flock -u "$PUBLISH_LEASE_ACTIVE_LOCK_FD" 2>/dev/null || true
        exec {PUBLISH_LEASE_ACTIVE_LOCK_FD}>&- || true
        PUBLISH_LEASE_ACTIVE_LOCK_FD=""
    fi
    if [ -n "$PUBLISH_LEASE_HEARTBEAT_PID" ]; then
        [ -z "$PUBLISH_LEASE_STOP_FD" ] || printf 'stop\n' >&"$PUBLISH_LEASE_STOP_FD" || true
        wait "$PUBLISH_LEASE_HEARTBEAT_PID" 2>/dev/null || true
        PUBLISH_LEASE_HEARTBEAT_PID=""
    fi
    if [ -n "$PUBLISH_LEASE_STOP_FD" ]; then
        exec {PUBLISH_LEASE_STOP_FD}>&-
        PUBLISH_LEASE_STOP_FD=""
    fi
    [ "$PUBLISH_LEASE_HELD" -eq 0 ] || publisher_lease_release || true
    [ -z "$WORK" ] || rm -rf "${WORK:?}"
}
trap cleanup EXIT
# shellcheck disable=SC2154  # rc IS assigned (rc=$?) inside the trap-quoted string
trap 'rc=$?; if [ "$rc" -ne 0 ]; then _FAILURE_EXIT=$rc; [ "$_RECEIPT_EMITTING" -eq 0 ] || NIGHTLY_STAGE=receipt; shout_fail "$(failure_notice "$rc")"; fi; exit $rc' ERR
signal_abort() {  # signal_abort <conventional-signal-exit>
    local rc="$1"
    if [ "$_RECEIPT_EMITTING" -ne 0 ]; then
        _PENDING_SIGNAL="$rc"
        return 0
    fi
    # A terminal receipt is authoritative. In particular, do not contradict a
    # completed success receipt if shutdown lands in the best-effort notifier.
    [ "$_FAILURE_EXIT" -eq 0 ] || rc="$_FAILURE_EXIT"
    [ "$_RECEIPTED" -eq 0 ] || exit "$rc"
    _FAILURE_EXIT="$rc"
    shout_fail "$(failure_notice "$rc")"
    exit "$rc"
}
finish_pending_signal() {
    local rc
    [ "$_PENDING_SIGNAL" -ne 0 ] || return 0
    rc="$_PENDING_SIGNAL"
    _PENDING_SIGNAL=0
    signal_abort "$rc"
}
trap 'signal_abort 143' TERM
trap 'signal_abort 130' INT
trap 'signal_abort 129' HUP

die()  { note "ERROR: $*"; _FAILURE_EXIT=1; shout_fail "$*"; exit 1; }

# BEGIN marker verifier tmpfs sizing contract
# The marker verifier keeps the downloaded bundle, marker archive, and expanded
# marker tree in its /tmp cache at the same time. Size that scratch space from
# those actual staged artifacts. Supported ARM64 kernels may use 64 KiB pages,
# so each archive member gets two such pages: one bounds a regular file's final
# partial data page and one conservatively covers inode/dentry or directory
# bookkeeping. The publisher's packer emits every traversed directory as an
# archive member, so this count also covers nested directory creation. The fixed
# reserve covers the small signed files, download page tails, empty rollback
# scaffolding, and atomic metadata writes; the fresh verify-only cache has no
# live files to copy and the client installs the staged bundle/tree by rename.
# The client-side limits are repeated here so a larger or malformed candidate
# is refused before release state changes.
marker_gate_tmpfs_size() {  # marker_gate_tmpfs_size <bundle> <archive> <tree> <entries>
    python3 - "$@" <<'PY'
import re
import sys

names = ("bundle", "archive", "tree", "entries")
limits = (512 << 20, 1 << 30, 2 << 30, 1 << 17)
if len(sys.argv) != 5:
    print("marker tmpfs sizing: expected four decimal inputs", file=sys.stderr)
    raise SystemExit(2)

values = []
for name, raw, limit in zip(names, sys.argv[1:], limits):
    if not re.fullmatch(r"[0-9]+", raw, flags=re.ASCII):
        print(f"marker tmpfs sizing: malformed {name}", file=sys.stderr)
        raise SystemExit(2)
    value = int(raw, 10)
    minimum = 4 if name == "entries" else 1
    if value < minimum or value > limit:
        print(f"marker tmpfs sizing: {name} outside client bounds", file=sys.stderr)
        raise SystemExit(2)
    values.append(value)

bundle, archive, tree, entries = values
payload = bundle + archive + tree
needed = payload + entries * (2 * (64 << 10)) + (64 << 20) + (payload + 15) // 16
allocation = ((needed + (1 << 20) - 1) // (1 << 20)) * (1 << 20)
if allocation > 4 << 30:
    print("marker tmpfs sizing: staged artifacts exceed the 4 GiB verifier ceiling", file=sys.stderr)
    raise SystemExit(2)
print(f"size={allocation}")
PY
}
# END marker verifier tmpfs sizing contract

marker_tree_metrics() {  # marker_tree_metrics <packed-tree>
    python3 - "$1" <<'PY'
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as archive:
    members = archive.getmembers()
    if any(not (member.isdir() or member.isreg()) for member in members):
        print("marker tmpfs sizing: packed tree has an unsupported member", file=sys.stderr)
        raise SystemExit(2)
    print(sum(member.size for member in members if member.isreg()), len(members))
PY
}

# Bring up receipt/error handling before fallible startup work so a missing
# credential, temporary directory, or repository path still produces one build
# receipt. A missing notifier remains the approved best-effort exception.
HERE="$(cd "$(dirname "$0")/.." && pwd)"   # canonical repo root for builds
NOTIFY="${HERE}/../../tools/discord-notify.py"

# Cron's deliberately small PATH does not include the host Go installation.
# Accept PATH resolution only when it yields an absolute executable, so a
# caller with `.` in PATH cannot silently run ./go from the checkout. Fall back
# to the host's standard installation paths for the unattended publisher.
RULESIGN_GO="$(command -v go 2>/dev/null || true)"
case "$RULESIGN_GO" in
    /*) [ -x "$RULESIGN_GO" ] || RULESIGN_GO="" ;;
    *) RULESIGN_GO="" ;;
esac
if [ -z "$RULESIGN_GO" ]; then
    for candidate in /usr/local/bin/go /usr/local/go/bin/go /usr/bin/go; do
        if [ -x "$candidate" ]; then
            RULESIGN_GO="$candidate"
            break
        fi
    done
fi
[ -n "$RULESIGN_GO" ] \
    || die "missing required tool: go (checked PATH and /usr/local/bin/go, /usr/local/go/bin/go, /usr/bin/go)"

# The one reader of /etc/myguard-build-env. build-env is mode 600 root-only
# (since 2026-07-26), so a plain `[ -r ]` test is FALSE for the cron user
# (eilander) and the old sourcing block was skipped SILENTLY. Read it via
# `sudo cat` (passwordless sudo on this host) and extract only the one requested
# var, so an `export `-prefixed line still matches and no other secret enters the
# environment. Tolerances: leading whitespace, an optional `export ` prefix,
# surrounding single/double quotes, and a duplicate line (last one wins).
#
# The value is produced on stdout for command substitution ONLY: it must never be
# passed as an argument, written to a file, or interpolated into a log line.
# An unreadable or absent file yields the EMPTY value, never a run abort: under
# `set -o pipefail` a bare `sudo … | sed` pipeline returns sudo's non-zero status,
# so the assignment at the call site would trip the ERR trap and exit with the
# generic "NOT updated" notice instead of the caller's actionable die message.
build_env_value() {  # build_env_value <NAME>
    { sudo -n cat /etc/myguard-build-env 2>/dev/null || true; } \
        | sed -n "s/^[[:space:]]*\(export[[:space:]]\+\)\?$1=//p" \
        | tail -n1 | tr -d "\"'"
}

# gh needs a token with contents:write on the myguard-labs ORG to publish the
# rolling release. The build user's default gh login (hosts.yml) carries the
# personal GITHUB_API_TOKEN, which only has READ on org repos -> asset upload/
# clobber 403s ("Resource not accessible by personal access token"). The
# org-owned fine-grained PAT lives in /etc/myguard-build-env as
# GITHUB_ORG_LAB_TOKEN; export it as GH_TOKEN so every gh call here uses it
# without disturbing the default login or GITHUB_API_TOKEN (lastversion's key).
# It is read through build_env_value above; see that helper for why `sudo cat` is
# the only way the cron user sees the file. A silently skipped read left GH_TOKEN
# unset and gh fell back to the interactive hosts.yml login. No token => die
# here: publishing is impossible without it, and failing fast beats discovering
# it after a 55s docker build.
if [ -z "${GH_TOKEN:-}" ]; then
    GH_TOKEN="$(build_env_value GITHUB_ORG_LAB_TOKEN)"
    export GH_TOKEN
fi
# Never let a stale/invalid ~/.config/gh/hosts.yml login serve as the fallback:
# that token is currently invalid and 401s even on READS, which is what defeated
# the version guard below. GH_TOKEN takes precedence over hosts.yml in gh.
[ -n "${GH_TOKEN:-}" ] || die "GITHUB_ORG_LAB_TOKEN not readable from /etc/myguard-build-env; cannot publish"

# Resolve the ed25519 manifest signing key HERE, beside GH_TOKEN, for exactly the
# same reason: step 3b cannot publish without it, so failing now beats dying
# after the ~55s docker build. cmd/rulessign reads MAILSTRIX_RULES_SIGNING_KEY
# from the ENVIRONMENT, so an already-set value WINS and build-env is never
# consulted — that is how CI and manual runs supply it today. The cron run has
# no such environment, which is why the 00:00Z publication stopped updating the
# rolling bundle: the key exists only as a GitHub Actions secret.
#
# build_env_value is line-based and a PEM is multi-line, so build-env stores one
# base64 line (MAILSTRIX_RULES_SIGNING_KEY_B64) which is decoded in memory here.
# Every diagnostic below names the VARIABLE and never any part of its value, so a
# malformed key cannot be reconstructed from the cron log.
if [ -z "${MAILSTRIX_RULES_SIGNING_KEY:-}" ]; then
    command -v base64 >/dev/null 2>&1 \
        || die "missing required tool: base64 (needed to decode MAILSTRIX_RULES_SIGNING_KEY_B64)"
    # Strip whitespace: build_env_value keeps the line verbatim after `=`, and a
    # stray trailing space would make `base64 -d` reject an otherwise valid key.
    # Base64 of a PEM contains no whitespace, so this is lossless.
    signing_key_b64="$(build_env_value MAILSTRIX_RULES_SIGNING_KEY_B64 | tr -d '[:space:]')"
    [ -n "$signing_key_b64" ] \
        || die "MAILSTRIX_RULES_SIGNING_KEY is not set and MAILSTRIX_RULES_SIGNING_KEY_B64 is not readable from /etc/myguard-build-env; refusing to publish an unsigned manifest that no client would install. Add one line MAILSTRIX_RULES_SIGNING_KEY_B64=\$(base64 -w0 key.pem) to /etc/myguard-build-env (root-owned, mode 600), or export MAILSTRIX_RULES_SIGNING_KEY for this run"
    MAILSTRIX_RULES_SIGNING_KEY="$(printf '%s' "$signing_key_b64" | base64 -d 2>/dev/null)" \
        || die "MAILSTRIX_RULES_SIGNING_KEY_B64 in /etc/myguard-build-env is not valid base64; re-install it as a single base64 -w0 line"
    unset signing_key_b64
    # Both PEM armour lines are required. base64 -d accepts any input whose
    # length is a valid base64 length, so a truncated key can still decode — to a
    # PEM PREFIX that keeps its BEGIN line and loses its END line. Checking both
    # rejects that class here instead of after the docker build.
    case "$MAILSTRIX_RULES_SIGNING_KEY" in
        *"-----BEGIN "*"-----END "*) ;;
        *) die "MAILSTRIX_RULES_SIGNING_KEY_B64 in /etc/myguard-build-env did not decode to a complete PEM (no '-----BEGIN ' / '-----END ' armour); re-install the ed25519 PKCS#8 PEM" ;;
    esac
    export MAILSTRIX_RULES_SIGNING_KEY
fi

WORK="$(mktemp -d)"

for bin in date docker flock gh git jq mkfifo sha256sum python3 timeout tr; do
    command -v "$bin" >/dev/null 2>&1 || die "missing required tool: $bin"
done

# The rolling release is one shared mutable object. Its publisher protocol is:
# absent -> held (one compare-and-swap push); held -> renewed (CAS); held ->
# released (CAS delete); any ownership mismatch -> lost (terminal).
# The authoritative state is a GitHub-hosted ref scoped by REPO/TAG, not a
# host-local lock. Owner and expiry move together as the ref's commit target.
# A stale actor may never read prior version state or mutate release assets: it
# must still own the exact ref target before those operations. Expiry is
# diagnostic only. Release-asset uploads cannot carry this ref's fencing token,
# so automatically replacing an expired holder would let an already-started
# stale upload complete after a replacement publisher. A crashed holder is
# removed only after an operator proves quiescence and supplies its exact
# current OID through PUBLISH_LEASE_RECOVER_OID; deletion is an exact-OID CAS.
#
# The dedicated temporary bare repository keeps lease objects and refs out of
# the publisher checkout/index. Git's --force-with-lease is the atomic compare-
# and-swap: competing hosts cannot both acquire or renew the same REPO/TAG.
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
    || die "REPO must be an owner/name pair before publisher coordination can start"
# GitHub repository owner/name identity is ASCII case-insensitive. Canonicalize
# it for the mutex scope so spelling variants cannot partition one release's
# coordination ref. Tags remain byte-exact because Git ref names are case-sensitive.
PUBLISH_LEASE_REPO_IDENTITY="$(printf '%s' "$REPO" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
PUBLISH_LEASE_SCOPE="$(printf '%s\0%s' "$PUBLISH_LEASE_REPO_IDENTITY" "$TAG" | sha256sum | awk '{print $1}')"
# GitHub exposes atomic compare-and-swap through ordinary branch-ref pushes.
# Keep the mutex under refs/heads so the same GH_TOKEN contents:write grant used
# for release assets can update it through GIT_ASKPASS; CI has no push trigger,
# so these private coordination refs do not enqueue product workflows.
PUBLISH_LEASE_REF="refs/heads/mailstrix-publisher-leases/${PUBLISH_LEASE_SCOPE}"
PUBLISH_LEASE_REMOTE="${PUBLISH_LEASE_REMOTE:-https://github.com/${REPO}.git}"
PUBLISH_LEASE_TTL_SECONDS="${PUBLISH_LEASE_TTL_SECONDS:-3600}"
PUBLISH_LEASE_HEARTBEAT_SECONDS="${PUBLISH_LEASE_HEARTBEAT_SECONDS:-60}"
PUBLISH_LEASE_POLL_SECONDS="${PUBLISH_LEASE_POLL_SECONDS:-5}"
PUBLISH_LEASE_WAIT_SECONDS="${PUBLISH_LEASE_WAIT_SECONDS:-14400}"
PUBLISH_LEASE_RECOVER_OID="${PUBLISH_LEASE_RECOVER_OID:-}"
for lease_number in "$PUBLISH_LEASE_TTL_SECONDS" "$PUBLISH_LEASE_HEARTBEAT_SECONDS" "$PUBLISH_LEASE_POLL_SECONDS" "$PUBLISH_LEASE_WAIT_SECONDS"; do
    case "$lease_number" in
        ''|*[!0-9]*|0[0-9]*|??????*)
            die "publisher lease timing values must be canonical decimal integers of at most five digits"
            ;;
    esac
done
if [ "$PUBLISH_LEASE_TTL_SECONDS" -lt 300 ] \
    || [ "$PUBLISH_LEASE_TTL_SECONDS" -gt 86400 ] \
    || [ "$PUBLISH_LEASE_HEARTBEAT_SECONDS" -lt 10 ] \
    || [ "$PUBLISH_LEASE_HEARTBEAT_SECONDS" -ge "$PUBLISH_LEASE_TTL_SECONDS" ] \
    || [ "$PUBLISH_LEASE_POLL_SECONDS" -lt 1 ] \
    || [ "$PUBLISH_LEASE_POLL_SECONDS" -gt 60 ] \
    || [ "$PUBLISH_LEASE_WAIT_SECONDS" -gt 86400 ]; then
    die "publisher lease timing values are outside their safe bounds"
fi
PUBLISH_LEASE_REPO="${WORK}/publisher-lease.git"
PUBLISH_LEASE_STATE="${WORK}/publisher-lease.oid"
PUBLISH_LEASE_LOCAL_LOCK="${WORK}/publisher-lease-state.lock"
PUBLISH_LEASE_LOST="${WORK}/publisher-lease.lost"
PUBLISH_LEASE_UNCERTAIN="${WORK}/publisher-lease.uncertain"
PUBLISH_LEASE_STOP="${WORK}/publisher-lease.stop"
PUBLISH_LEASE_ASKPASS="${WORK}/publisher-lease-askpass"
PUBLISH_LEASE_RETRY_LIMIT=3
PUBLISH_LEASE_RETRY_MARGIN_SECONDS=60
PUBLISH_LEASE_GIT_TIMEOUT_SECONDS=45
PUBLISH_LEASE_CLOCK_TIMEOUT_SECONDS=30
PUBLISH_LEASE_LOCAL_LOCK_MARGIN_SECONDS=30
# Refresh can consume four Git budgets (read, local commit, CAS push, ambiguous
# push reread) plus one authoritative-clock budget. A waiter must outlive that
# complete critical section with an explicit scheduling margin.
PUBLISH_LEASE_LOCAL_LOCK_WAIT_SECONDS=$((
    4 * PUBLISH_LEASE_GIT_TIMEOUT_SECONDS
    + PUBLISH_LEASE_CLOCK_TIMEOUT_SECONDS
    + PUBLISH_LEASE_LOCAL_LOCK_MARGIN_SECONDS
))
PUBLISH_LEASE_OWNER="$(printf '%s\0%s\0%s\0%s' "$PUBLISH_LEASE_SCOPE" "$$" "$WORK" "$(date +%s%N)" | sha256sum | awk '{print $1}')"
cat >"$PUBLISH_LEASE_ASKPASS" <<'SH'
#!/usr/bin/env bash
case "$1" in
    *Username*) printf '%s\n' x-access-token ;;
    *Password*) printf '%s\n' "${GH_TOKEN:?}" ;;
    *) exit 1 ;;
esac
SH
chmod 700 "$PUBLISH_LEASE_ASKPASS"
git init --bare --quiet --object-format=sha1 "$PUBLISH_LEASE_REPO" \
    || die "cannot initialize isolated publisher lease state; nothing was published"
mkfifo "$PUBLISH_LEASE_STOP" \
    || die "cannot initialize publisher lease heartbeat; nothing was published"
exec {PUBLISH_LEASE_STOP_FD}<>"$PUBLISH_LEASE_STOP" \
    || die "cannot open publisher lease heartbeat control; nothing was published"
PUBLISH_LEASE_TREE="$(git -C "$PUBLISH_LEASE_REPO" mktree </dev/null)" \
    || die "cannot initialize publisher lease object; nothing was published"

publisher_lease_git() {
    GIT_ASKPASS="$PUBLISH_LEASE_ASKPASS" GIT_TERMINAL_PROMPT=0 \
        timeout --kill-after=5s "${PUBLISH_LEASE_GIT_TIMEOUT_SECONDS}s" \
        git -C "$PUBLISH_LEASE_REPO" "$@"
}

publisher_lease_now() {
    local http server_date headers="${WORK}/publisher-lease-clock.${BASHPID}.headers"
    : >"$headers"
    http="$(curl -fsS --connect-timeout 10 --max-time "$PUBLISH_LEASE_CLOCK_TIMEOUT_SECONDS" \
        -D "$headers" -o /dev/null -w '%{http_code}' \
        -H @- -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/${REPO}" \
        <<<"Authorization: Bearer ${GH_TOKEN}")" || return 1
    [ "$http" = 200 ] || return 1
    server_date="$(sed -n 's/^[Dd]ate:[[:space:]]*//p' "$headers" | tail -n1 | tr -d '\r')"
    [ -n "$server_date" ] || return 1
    date -u -d "$server_date" +%s
}

publisher_lease_remote_oid() {
    local listing oid ref extra
    listing="$(publisher_lease_git ls-remote --refs "$PUBLISH_LEASE_REMOTE" "$PUBLISH_LEASE_REF")" \
        || return 1
    [ -n "$listing" ] || return 0
    read -r oid ref extra <<<"$listing"
    [ -z "${extra:-}" ] && [ "$ref" = "$PUBLISH_LEASE_REF" ] \
        && [[ "$oid" =~ ^[0-9a-f]{40}$ ]] || return 1
    printf '%s\n' "$oid"
}

publisher_lease_commit() {  # publisher_lease_commit <expires>
    local expires="$1"
    printf 'schema=mailstrix-publisher-lease-v1\nowner=%s\nscope=%s\nexpires=%s\n' \
        "$PUBLISH_LEASE_OWNER" "$PUBLISH_LEASE_SCOPE" "$expires" \
        | GIT_AUTHOR_NAME=mailstrix-publisher GIT_AUTHOR_EMAIL=noreply@invalid \
            GIT_COMMITTER_NAME=mailstrix-publisher GIT_COMMITTER_EMAIL=noreply@invalid \
            publisher_lease_git commit-tree "$PUBLISH_LEASE_TREE"
}

publisher_lease_details() {  # publisher_lease_details <oid>; prints owner expiry
    local oid="$1" size message schema owner scope expires extra
    publisher_lease_git fetch --quiet --no-write-fetch-head "$PUBLISH_LEASE_REMOTE" "$oid" \
        || return 1
    size="$(publisher_lease_git cat-file -s "$oid")" || return 1
    case "$size" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$size" -le 4096 ] || return 1
    message="$(publisher_lease_git cat-file commit "$oid" | sed -n '1,/^$/d; p')" \
        || return 1
    IFS= read -r schema <<<"$message"
    IFS= read -r owner <<<"$(printf '%s\n' "$message" | sed -n '2p')"
    IFS= read -r scope <<<"$(printf '%s\n' "$message" | sed -n '3p')"
    IFS= read -r expires <<<"$(printf '%s\n' "$message" | sed -n '4p')"
    extra="$(printf '%s\n' "$message" | sed -n '5p')"
    [ "$schema" = schema=mailstrix-publisher-lease-v1 ] \
        && [[ "$owner" =~ ^owner=[0-9a-f]{64}$ ]] \
        && [ "$scope" = "scope=${PUBLISH_LEASE_SCOPE}" ] \
        && [[ "$expires" =~ ^expires=[0-9]{10}$ ]] \
        && [ -z "$extra" ] || return 1
    printf '%s %s\n' "${owner#owner=}" "${expires#expires=}"
}

publisher_lease_write_state() {  # publisher_lease_write_state <oid> <expires> <observed-now>
    local oid="$1" expires="$2" observed_now="$3" deadline
    deadline="$(python3 - "$expires" "$observed_now" <<'PY'
import sys
import time

expires = int(sys.argv[1])
observed_now = int(sys.argv[2])
if expires <= observed_now:
    raise SystemExit(2)
print(time.monotonic_ns() + (expires - observed_now) * 1_000_000_000)
PY
)" || return 1
    printf '%s %s %s\n' "$oid" "$expires" "$deadline" >"${PUBLISH_LEASE_STATE}.new" || return 1
    mv "${PUBLISH_LEASE_STATE}.new" "$PUBLISH_LEASE_STATE"
}

publisher_lease_read_state() {
    local oid expires deadline extra
    read -r oid expires deadline extra <"$PUBLISH_LEASE_STATE" || return 1
    [[ "$oid" =~ ^[0-9a-f]{40}$ ]] \
        && [[ "$expires" =~ ^[0-9]{10}$ ]] \
        && [[ "$deadline" =~ ^[0-9]+$ ]] \
        && [ -z "${extra:-}" ] || return 1
    printf '%s %s %s\n' "$oid" "$expires" "$deadline"
}

publisher_lease_retry_safe() {
    local oid expires deadline extra
    read -r oid expires deadline extra <<<"$(publisher_lease_read_state)" || return 1
    [ -n "$oid" ] && [ -z "${extra:-}" ] || return 1
    python3 - "$deadline" "$PUBLISH_LEASE_RETRY_MARGIN_SECONDS" "$PUBLISH_LEASE_POLL_SECONDS" <<'PY'
import sys
import time

deadline = int(sys.argv[1])
required = (int(sys.argv[2]) + int(sys.argv[3])) * 1_000_000_000
raise SystemExit(0 if deadline - time.monotonic_ns() > required else 1)
PY
}

publisher_lease_sleep() {
    python3 - "$PUBLISH_LEASE_POLL_SECONDS" <<'PY'
import sys
import time
time.sleep(int(sys.argv[1]))
PY
}

publisher_lease_process_start() {  # publisher_lease_process_start <pid>
    python3 - "$1" <<'PY'
import pathlib
import sys

pid = sys.argv[1]
if not pid.isdecimal() or pid == "0":
    raise SystemExit(1)
try:
    stat = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
except (OSError, UnicodeError):
    raise SystemExit(1)
# comm is parenthesized and may contain spaces or ')'; fields after its final
# ')' start at field 3, making starttime (field 22) tail index 19.
closing = stat.rfind(")")
tail = stat[closing + 2:].split() if closing >= 0 else []
if len(tail) <= 19 or not tail[19].isdecimal():
    raise SystemExit(1)
print(tail[19])
PY
}

PUBLISH_LEASE_FOREGROUND_PID="$$"
PUBLISH_LEASE_FOREGROUND_START="$(publisher_lease_process_start "$PUBLISH_LEASE_FOREGROUND_PID")" \
    || die "cannot capture foreground publisher identity; nothing was published"

publisher_lease_foreground_alive() {
    local observed
    observed="$(publisher_lease_process_start "$PUBLISH_LEASE_FOREGROUND_PID" 2>/dev/null)" \
        || return 1
    [ "$observed" = "$PUBLISH_LEASE_FOREGROUND_START" ]
}

publisher_lease_with_local_lock() {  # publisher_lease_with_local_lock <operation> <lock-failure-status>
    local operation="$1" lock_failure="$2" lock_fd status foreground_lock=0
    exec {lock_fd}>"$PUBLISH_LEASE_LOCAL_LOCK" || return "$lock_failure"
    if [ "$BASHPID" = "$PUBLISH_LEASE_FOREGROUND_PID" ]; then
        PUBLISH_LEASE_ACTIVE_LOCK_FD="$lock_fd"
        foreground_lock=1
    fi
    if ! flock -w "$PUBLISH_LEASE_LOCAL_LOCK_WAIT_SECONDS" "$lock_fd"; then
        exec {lock_fd}>&-
        [ "$foreground_lock" -eq 0 ] || PUBLISH_LEASE_ACTIVE_LOCK_FD=""
        return "$lock_failure"
    fi
    if "$operation"; then
        status=0
    else
        status=$?
    fi
    flock -u "$lock_fd" || status="$lock_failure"
    exec {lock_fd}>&-
    [ "$foreground_lock" -eq 0 ] || PUBLISH_LEASE_ACTIVE_LOCK_FD=""
    return "$status"
}

# The heartbeat and foreground publisher share PUBLISH_LEASE_STATE. Renewal's
# remote CAS and local state replacement are one observable transition: an
# ownership assertion must see the old OID in both places or the new OID in
# both places. The process-local lock serializes that transition and is held
# across bounded Git I/O. A fresh descriptor per call is required because the
# heartbeat is a forked subshell; inherited descriptors share one flock owner.
publisher_lease_refresh_locked() {
    local now old state_extra expires new remote
    [ ! -e "$PUBLISH_LEASE_LOST" ] && [ ! -e "$PUBLISH_LEASE_UNCERTAIN" ] || return 3
    read -r old _ _ state_extra <<<"$(publisher_lease_read_state)" || return 1
    [ -n "$old" ] && [ -z "${state_extra:-}" ] || return 1
    remote="$(publisher_lease_remote_oid)" || return 2
    [ "$remote" = "$old" ] || return 3
    now="$(publisher_lease_now)" || return 2
    expires=$((now + PUBLISH_LEASE_TTL_SECONDS))
    new="$(publisher_lease_commit "$expires")" || return 1
    if publisher_lease_git push --quiet --force-with-lease="${PUBLISH_LEASE_REF}:${old}" \
            "$PUBLISH_LEASE_REMOTE" "${new}:${PUBLISH_LEASE_REF}"; then
        publisher_lease_write_state "$new" "$expires" "$now"
        return
    fi
    # A lost response may hide a successful CAS. Re-read before deciding: our
    # new OID proves renewal, the old OID permits a bounded retry, and any other
    # value (including absence) proves ownership loss.
    remote="$(publisher_lease_remote_oid)" || return 2
    if [ "$remote" = "$new" ]; then
        publisher_lease_write_state "$new" "$expires" "$now"
    elif [ "$remote" = "$old" ]; then
        return 2
    else
        return 3
    fi
}

publisher_lease_refresh() {
    publisher_lease_with_local_lock publisher_lease_refresh_locked 2
}

publisher_lease_assert_owned_locked() {
    local expected state_extra remote owner expires extra
    [ "$PUBLISH_LEASE_HELD" -eq 1 ] \
        && [ ! -e "$PUBLISH_LEASE_LOST" ] \
        && [ ! -e "$PUBLISH_LEASE_UNCERTAIN" ] || return 1
    read -r expected _ _ state_extra <<<"$(publisher_lease_read_state)" || return 1
    [ -n "$expected" ] && [ -z "${state_extra:-}" ] || return 1
    remote="$(publisher_lease_remote_oid)" || return 1
    [ "$remote" = "$expected" ] || return 1
    read -r owner expires extra <<<"$(publisher_lease_details "$remote")" || return 1
    [ "$owner" = "$PUBLISH_LEASE_OWNER" ] && [ -z "${extra:-}" ] || return 1
}

publisher_lease_assert_owned() {
    publisher_lease_with_local_lock publisher_lease_assert_owned_locked 1
}

publisher_lease_release_locked() {
    local expected remote
    [ "$PUBLISH_LEASE_HELD" -eq 1 ] || return 0
    PUBLISH_LEASE_HELD=0
    read -r expected _ <<<"$(publisher_lease_read_state 2>/dev/null || true)"
    [ -n "$expected" ] || return 1
    remote="$(publisher_lease_remote_oid)" || return 1
    [ "$remote" = "$expected" ] || return 1
    publisher_lease_git push --quiet --force-with-lease="${PUBLISH_LEASE_REF}:${expected}" \
        "$PUBLISH_LEASE_REMOTE" ":${PUBLISH_LEASE_REF}"
}

publisher_lease_release() {
    publisher_lease_with_local_lock publisher_lease_release_locked 1
}

publisher_lease_acquire() {
    local started now current owner expires detail_extra new
    started="$(publisher_lease_now)" || return 1
    while :; do
        now="$(publisher_lease_now)" || return 1
        [ "$((now - started))" -le "$PUBLISH_LEASE_WAIT_SECONDS" ] || return 1
        current="$(publisher_lease_remote_oid)" || return 1
        if [ -n "$current" ]; then
            read -r owner expires detail_extra <<<"$(publisher_lease_details "$current")" || return 1
            [ -n "$owner" ] && [ -z "${detail_extra:-}" ] || return 1
            if [ "$expires" -le "$now" ]; then
                note "publisher mutex ${current} is expired but remains authoritative; after proving the holder quiescent, rerun with PUBLISH_LEASE_RECOVER_OID=${current}"
                return 1
            fi
            publisher_lease_sleep
            continue
        fi
        expires=$((now + PUBLISH_LEASE_TTL_SECONDS))
        new="$(publisher_lease_commit "$expires")" || return 1
        if publisher_lease_git push --quiet \
            --force-with-lease="${PUBLISH_LEASE_REF}:" \
            "$PUBLISH_LEASE_REMOTE" "${new}:${PUBLISH_LEASE_REF}"; then
            publisher_lease_write_state "$new" "$expires" "$now" || return 1
            PUBLISH_LEASE_HELD=1
            return 0
        fi
        # A lost response may hide our successful create. Exact equality with
        # the locally created OID proves ownership, just as it does for renewal.
        # A competing CAS normally leaves a different ref to observe. A rejection
        # while the ref remains absent is an unavailable/denied write, not
        # contention: fail closed instead of spinning at network speed.
        current="$(publisher_lease_remote_oid)" || return 1
        if [ "$current" = "$new" ]; then
            publisher_lease_write_state "$new" "$expires" "$now" || return 1
            PUBLISH_LEASE_HELD=1
            return 0
        fi
        if [ -z "$current" ]; then
            note "publisher mutex acquire push was rejected while the remote ref stayed absent"
            return 1
        fi
        publisher_lease_sleep
    done
}

publisher_lease_recover_stale() {
    local current owner expires extra now
    [ -n "$PUBLISH_LEASE_RECOVER_OID" ] || return 0
    [[ "$PUBLISH_LEASE_RECOVER_OID" =~ ^[0-9a-f]{40}$ ]] \
        || die "PUBLISH_LEASE_RECOVER_OID must be the exact 40-hex current mutex OID"
    current="$(publisher_lease_remote_oid)" \
        || die "cannot read publisher mutex for explicit recovery"
    [ "$current" = "$PUBLISH_LEASE_RECOVER_OID" ] \
        || die "publisher mutex recovery OID is stale or wrong; nothing was changed"
    read -r owner expires extra <<<"$(publisher_lease_details "$current")" \
        || die "publisher mutex recovery target is malformed; nothing was changed"
    if [ -z "$owner" ] || [ -n "${extra:-}" ]; then
        die "publisher mutex recovery target is malformed; nothing was changed"
    fi
    now="$(publisher_lease_now)" \
        || die "cannot read authoritative time for publisher mutex recovery"
    [ "$expires" -le "$now" ] \
        || die "publisher mutex recovery target has not expired; nothing was changed"
    publisher_lease_git push --quiet \
        --force-with-lease="${PUBLISH_LEASE_REF}:${current}" \
        "$PUBLISH_LEASE_REMOTE" ":${PUBLISH_LEASE_REF}" \
        || die "publisher mutex changed during explicit recovery; nothing was changed"
    note "removed expired publisher mutex ${current} by explicit exact-OID recovery"
}

publisher_lease_recover_stale
publisher_lease_acquire \
    || die "authoritative publisher coordination is unavailable or timed out; nothing was published"
(
    # Reopen the FIFO read-only, then discard the inherited read/write anchor.
    # The foreground publisher is the sole writer identity: normal cleanup
    # writes a stop line, while SIGKILL closes its descriptor and produces EOF.
    # Unlike PID polling this cannot mistake a reused PID for the publisher.
    exec {heartbeat_stop_fd}<"$PUBLISH_LEASE_STOP" || exit 1
    exec {PUBLISH_LEASE_STOP_FD}>&-
    while :; do
        if IFS= read -r -t "$PUBLISH_LEASE_HEARTBEAT_SECONDS" -u "$heartbeat_stop_fd" _; then
            break
        else
            heartbeat_read_status=$?
        fi
        # Bash read returns >128 for a timeout. EOF/error means the foreground
        # writer is gone, so leave the durable ref unrenewed for exact-OID
        # operator recovery after expiry.
        [ "$heartbeat_read_status" -gt 128 ] || break
        publisher_lease_foreground_alive || break
        transient_attempts=0
        while :; do
            publisher_lease_foreground_alive || exit 0
            if publisher_lease_refresh; then
                break
            else
                refresh_status=$?
            fi
            case "$refresh_status" in
                2)
                    transient_attempts=$((transient_attempts + 1))
                    if [ "$transient_attempts" -le "$PUBLISH_LEASE_RETRY_LIMIT" ] \
                        && publisher_lease_retry_safe; then
                        note "publisher mutex refresh had a transient coordination error; retrying while the prior lease retains its safety margin"
                        publisher_lease_sleep
                        continue
                    fi
                    note "publisher mutex refresh could not be confirmed within its bounded safety margin"
                    : >"$PUBLISH_LEASE_UNCERTAIN"
                    exit 1
                    ;;
                3)
                    note "publisher mutex ownership changed; stopping the publisher"
                    : >"$PUBLISH_LEASE_LOST"
                    exit 1
                    ;;
                *)
                    note "publisher mutex local state became invalid; stopping the publisher"
                    : >"$PUBLISH_LEASE_UNCERTAIN"
                    exit 1
                    ;;
            esac
        done
    done
    exec {heartbeat_stop_fd}<&-
) &
PUBLISH_LEASE_HEARTBEAT_PID=$!

# Build the exact helper once, then make it prove both key usability and client
# trust before the expensive rules images are built. This is a real signing
# operation rather than `-print-public`: that mode intentionally exits before
# -require-trusted is enforced. The throwaway bytes never leave WORK.
RULESIGN_BIN="${WORK}/rulessign"
( cd "$HERE" && GOTOOLCHAIN=local "$RULESIGN_GO" build -buildvcs=false -o "$RULESIGN_BIN" ./cmd/rulessign ) \
    || die "building the manifest signer failed; refusing to start the rules build"

# With the shared mutex held, authenticate the complete previous state before
# any rules build or signing operation. Release-asset write authority alone
# must never choose a value that the independent signing key later blesses.
publisher_lease_assert_owned \
    || die "publisher lease was lost before reading prior version state; nothing was published"
NIGHTLY_STAGE=publish
RELEASE_HTTP="$(curl -s --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' \
    -H @- \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${REPO}/releases/tags/${TAG}" \
    <<<"Authorization: Bearer ${GH_TOKEN}" || echo 000)"
case "$RELEASE_HTTP" in
    200|404) : ;;
    *) die "cannot determine whether release ${TAG} exists (HTTP ${RELEASE_HTTP}); refusing to guess the version — check the GITHUB_ORG_LAB_TOKEN and network" ;;
esac

CURRENT_STATE_DIR="${WORK}/published-state"
RECOVERY_STATE_DIR="${WORK}/recovery-state"
RESTORE_STATE_DIR="${WORK}/restore-state"
RECOVERY_BUNDLE=compiled.yac.recovery
RECOVERY_MANIFEST=compiled.yac.manifest.json.recovery
RECOVERY_SIGNATURE=compiled.yac.manifest.json.recovery.sig
VERSION_HIGH_WATER_ASSET=compiled.yac.version-high-water.json
VERSION_HIGH_WATER_RECOVERY_ASSET=compiled.yac.version-high-water.recovery.json
VERSION_HIGH_WATER_DIR="${WORK}/version-high-water"
VERSION_HIGH_WATER_CANDIDATE_DIR="${WORK}/next-version-high-water"
VERSION_HIGH_WATER_CANDIDATE="${VERSION_HIGH_WATER_CANDIDATE_DIR}/${VERSION_HIGH_WATER_ASSET}"
VERSION_HIGH_WATER_RECOVERY_CANDIDATE="${VERSION_HIGH_WATER_CANDIDATE_DIR}/${VERSION_HIGH_WATER_RECOVERY_ASSET}"
VERSION_HIGH_WATER=""
RELEASE_ASSETS=""

release_has_asset() {  # <asset>
    grep -Fxq -- "$1" <<<"$RELEASE_ASSETS"
}

download_release_state() {  # <dir> <bundle> <manifest> <signature> [marker]
    local destination="$1"
    shift
    rm -rf "${destination:?}"
    mkdir -p "$destination"
    gh release download "$TAG" --repo "$REPO" \
        --pattern "$1" --pattern "$2" --pattern "$3" \
        --dir "$destination" --clobber || return 1
    # Marker metadata is inside the authenticated manifest. Absence is allowed
    # only when that manifest has no marker field; validate_release_state makes
    # the final decision after signature verification.
    if [ -n "${4:-}" ] && release_has_asset "$4"; then
        gh release download "$TAG" --repo "$REPO" \
            --pattern "$4" --dir "$destination" --clobber >/dev/null 2>&1 || return 1
    fi
}

validate_release_state() {  # <manifest> <signature> <bundle> [marker]; prints previous next
    local manifest="$1" signature="$2" bundle="$3" marker="${4:-}"
    "$RULESIGN_BIN" -manifest "$manifest" -verify-signature "$signature" \
        || return 1
    python3 - "$manifest" "$bundle" "$marker" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys

maximum = (1 << 63) - 1
maximum_bundle = 512 << 20

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

try:
    manifest_path = Path(sys.argv[1])
    bundle_path = Path(sys.argv[2])
    marker_path = Path(sys.argv[3]) if sys.argv[3] else None
    with manifest_path.open("rb") as stream:
        manifest = json.load(stream, object_pairs_hook=unique_object)
    if not isinstance(manifest, dict):
        raise ValueError("manifest root is not an object")
    previous = manifest.get("version")
    size = manifest.get("size")
    checksum = manifest.get("checksum")
    if isinstance(previous, bool) or not isinstance(previous, int):
        raise ValueError("version is not an integer")
    if previous < 1 or previous > maximum:
        raise ValueError("version is outside the authenticated client range")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1 or size > maximum_bundle:
        raise ValueError("bundle size is outside the accepted range")
    if not isinstance(checksum, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", checksum) is None:
        raise ValueError("bundle checksum is malformed")
    if bundle_path.is_symlink() or not bundle_path.is_file() or bundle_path.stat().st_size != size:
        raise ValueError("bundle file does not match the signed size")
    digest = hashlib.sha256()
    with bundle_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    if checksum != "sha256:" + digest.hexdigest():
        raise ValueError("bundle file does not match the signed checksum")
    marker = manifest.get("marker")
    if marker is not None:
        if not isinstance(marker, dict) or marker.get("asset") != "marker-tree.tar.gz":
            raise ValueError("marker metadata is malformed")
        marker_size = marker.get("size")
        marker_checksum = marker.get("sha256")
        if (isinstance(marker_size, bool) or not isinstance(marker_size, int)
                or marker_size < 1 or marker_size > (1 << 30)):
            raise ValueError("marker size is outside the accepted range")
        if not isinstance(marker_checksum, str) or re.fullmatch(r"[0-9a-f]{64}", marker_checksum) is None:
            raise ValueError("marker checksum is malformed")
        if (marker_path is None or marker_path.is_symlink() or not marker_path.is_file()
                or marker_path.stat().st_size != marker_size):
            raise ValueError("marker file does not match the signed size")
        marker_digest = hashlib.sha256()
        with marker_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                marker_digest.update(chunk)
        if marker_checksum != marker_digest.hexdigest():
            raise ValueError("marker file does not match the signed checksum")
except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
print(previous, previous + 1, 1 if marker is not None else 0)
PY
}

read_version_high_water() {  # <fixed asset name>
    local asset="$1"
    local envelope="${VERSION_HIGH_WATER_DIR}/${asset}"
    local record="${VERSION_HIGH_WATER_DIR}/record.json"
    local signature="${VERSION_HIGH_WATER_DIR}/record.sig"
    rm -rf "${VERSION_HIGH_WATER_DIR:?}"
    mkdir -p "$VERSION_HIGH_WATER_DIR"
    gh release download "$TAG" --repo "$REPO" \
        --pattern "$asset" --dir "$VERSION_HIGH_WATER_DIR" --clobber \
        || return 1
    python3 - "$envelope" "$record" "$signature" <<'PY' || return 1
import base64
import json
from pathlib import Path
import sys

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

try:
    envelope_path = Path(sys.argv[1])
    if envelope_path.is_symlink() or not envelope_path.is_file() or envelope_path.stat().st_size > (128 << 10):
        raise ValueError("high-water envelope is not a bounded regular file")
    with envelope_path.open("rb") as stream:
        envelope = json.load(stream, object_pairs_hook=unique_object)
    if (not isinstance(envelope, dict)
            or set(envelope) != {"schema", "record", "signature"}
            or envelope.get("schema") != "mailstrix-version-high-water-envelope-v1"
            or not isinstance(envelope.get("record"), str)
            or not isinstance(envelope.get("signature"), str)):
        raise ValueError("high-water envelope is malformed")
    record = base64.b64decode(envelope["record"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    if not record or len(record) > (64 << 10) or not signature or len(signature) > (1 << 10):
        raise ValueError("high-water envelope members are outside their bounds")
    Path(sys.argv[2]).write_bytes(record)
    Path(sys.argv[3]).write_bytes(signature)
except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
PY
    "$RULESIGN_BIN" -manifest "$record" -verify-signature "$signature" || return 1
    python3 - "$record" <<'PY'
import json
from pathlib import Path
import re
import sys

maximum = (1 << 63) - 1

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

try:
    with Path(sys.argv[1]).open("rb") as stream:
        record = json.load(stream, object_pairs_hook=unique_object)
    version_text = record.get("version") if isinstance(record, dict) else None
    if (not isinstance(record, dict)
            or set(record) != {"schema", "version"}
            or record.get("schema") != "mailstrix-version-high-water-v1"
            or not isinstance(version_text, str)
            or re.fullmatch(r"[1-9][0-9]{0,18}", version_text) is None):
        raise ValueError("high-water record is malformed")
    version = int(version_text)
    if version > maximum:
        raise ValueError("high-water version exceeds the client range")
except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
print(version)
PY
}

merge_version_high_water() {  # <validated value or empty> <validated value or empty>
    python3 - "$1" "$2" <<'PY'
import sys

values = [int(value) for value in sys.argv[1:] if value]
if not values:
    raise SystemExit(2)
print(max(values))
PY
}

derive_next_version() {  # <authenticated-current>; prints unused next version
    python3 - "$1" "$VERSION_HIGH_WATER" <<'PY'
import sys

maximum = (1 << 63) - 1
try:
    current = int(sys.argv[1])
    high_water = int(sys.argv[2]) if sys.argv[2] else current
except ValueError:
    raise SystemExit(2)
if current < 1 or current > maximum or high_water < current or high_water >= maximum:
    raise SystemExit(2)
print(high_water + 1)
PY
}

prepare_version_high_water() {  # [exact version; defaults to candidate]
    local version="${1:-$VERSION}" record signature
    rm -rf "${VERSION_HIGH_WATER_CANDIDATE_DIR:?}"
    mkdir -p "$VERSION_HIGH_WATER_CANDIDATE_DIR"
    record="${VERSION_HIGH_WATER_CANDIDATE_DIR}/record.json"
    signature="${VERSION_HIGH_WATER_CANDIDATE_DIR}/record.sig"
    # Keep the 64-bit version as a canonical decimal string. jq 1.6 stores JSON
    # numbers as IEEE-754 doubles and cannot preserve MaxInt exactly.
    jq -cn --arg version "$version" \
        '{schema:"mailstrix-version-high-water-v1",version:$version}' >"$record" \
        || return 1
    "$RULESIGN_BIN" -require-trusted -manifest "$record" -out "$signature" \
        || return 1
    python3 - "$record" "$signature" "$VERSION_HIGH_WATER_CANDIDATE" <<'PY'
import base64
import json
from pathlib import Path
import sys

record = Path(sys.argv[1]).read_bytes()
signature = Path(sys.argv[2]).read_bytes()
envelope = {
    "schema": "mailstrix-version-high-water-envelope-v1",
    "record": base64.b64encode(record).decode("ascii"),
    "signature": base64.b64encode(signature).decode("ascii"),
}
Path(sys.argv[3]).write_text(json.dumps(envelope, separators=(",", ":")) + "\n", encoding="ascii")
PY
    cp "$VERSION_HIGH_WATER_CANDIDATE" "$VERSION_HIGH_WATER_RECOVERY_CANDIDATE"
}

reconcile_version_high_water() {
    # Before advancing, make both bounded slots carry the authenticated maximum.
    # Only a missing/lower slot is clobbered, so the other slot preserves that
    # maximum through a delete-before-upload failure or ambiguous response.
    prepare_version_high_water "$VERSION_HIGH_WATER" || return 1
    PUBLISH_STATE=uncertain
    if [ "$primary_high_water" != "$VERSION_HIGH_WATER" ]; then
        publisher_lease_assert_owned || return 1
        gh release upload "$TAG" --repo "$REPO" --clobber "$VERSION_HIGH_WATER_CANDIDATE" \
            || return 1
        primary_high_water="$VERSION_HIGH_WATER"
    fi
    if [ "$recovery_high_water" != "$VERSION_HIGH_WATER" ]; then
        publisher_lease_assert_owned || return 1
        gh release upload "$TAG" --repo "$REPO" --clobber "$VERSION_HIGH_WATER_RECOVERY_CANDIDATE" \
            || return 1
        recovery_high_water="$VERSION_HIGH_WATER"
    fi
    PUBLISH_STATE=not-started
}

restore_recovery_journal() {
    local journal_pair journal_previous journal_next journal_marker journal_extra
    download_release_state "$RECOVERY_STATE_DIR" \
        "$RECOVERY_BUNDLE" "$RECOVERY_MANIFEST" "$RECOVERY_SIGNATURE" \
        marker-tree.tar.gz.recovery \
        || return 1
    journal_pair="$(validate_release_state \
        "${RECOVERY_STATE_DIR}/${RECOVERY_MANIFEST}" \
        "${RECOVERY_STATE_DIR}/${RECOVERY_SIGNATURE}" \
        "${RECOVERY_STATE_DIR}/${RECOVERY_BUNDLE}" \
        "${RECOVERY_STATE_DIR}/marker-tree.tar.gz.recovery")" || return 1
    read -r journal_previous journal_next journal_marker journal_extra <<<"$journal_pair"
    [ -n "$journal_previous" ] && [ -n "$journal_next" ] \
        && { [ "$journal_marker" = 0 ] || [ "$journal_marker" = 1 ]; } \
        && [ -z "${journal_extra:-}" ] || return 1
    PREV="$journal_previous"
    PREVIOUS_MARKER="$journal_marker"
    rm -rf "${RESTORE_STATE_DIR:?}"
    mkdir -p "$RESTORE_STATE_DIR"
    cp "${RECOVERY_STATE_DIR}/${RECOVERY_BUNDLE}" "${RESTORE_STATE_DIR}/compiled.yac"
    cp "${RECOVERY_STATE_DIR}/${RECOVERY_SIGNATURE}" "${RESTORE_STATE_DIR}/compiled.yac.manifest.json.sig"
    cp "${RECOVERY_STATE_DIR}/${RECOVERY_MANIFEST}" "${RESTORE_STATE_DIR}/compiled.yac.manifest.json"
    if [ "$journal_marker" -eq 1 ]; then
        cp "${RECOVERY_STATE_DIR}/marker-tree.tar.gz.recovery" "${RESTORE_STATE_DIR}/marker-tree.tar.gz"
    fi
    PUBLISH_STATE=uncertain
    publisher_lease_assert_owned || return 1
    gh release upload "$TAG" --repo "$REPO" --clobber "${RESTORE_STATE_DIR}/compiled.yac" || return 1
    if [ -f "${RESTORE_STATE_DIR}/marker-tree.tar.gz" ]; then
        publisher_lease_assert_owned || return 1
        gh release upload "$TAG" --repo "$REPO" --clobber "${RESTORE_STATE_DIR}/marker-tree.tar.gz" || return 1
    fi
    publisher_lease_assert_owned || return 1
    gh release upload "$TAG" --repo "$REPO" --clobber "${RESTORE_STATE_DIR}/compiled.yac.manifest.json.sig" || return 1
    publisher_lease_assert_owned || return 1
    gh release upload "$TAG" --repo "$REPO" --clobber "${RESTORE_STATE_DIR}/compiled.yac.manifest.json" || return 1
    rm -rf "${CURRENT_STATE_DIR:?}"
    cp -a "$RESTORE_STATE_DIR" "$CURRENT_STATE_DIR"
    PUBLISH_STATE=not-started
    note "restored the exact authenticated prior release state from the recovery journal"
}

write_recovery_journal() {
    local journal="${WORK}/next-recovery-journal"
    rm -rf "${journal:?}"
    mkdir -p "$journal"
    cp "${CURRENT_STATE_DIR}/compiled.yac" "${journal}/${RECOVERY_BUNDLE}"
    cp "${CURRENT_STATE_DIR}/compiled.yac.manifest.json.sig" "${journal}/${RECOVERY_SIGNATURE}"
    cp "${CURRENT_STATE_DIR}/compiled.yac.manifest.json" "${journal}/${RECOVERY_MANIFEST}"
    if [ "$PREVIOUS_MARKER" -eq 1 ]; then
        cp "${CURRENT_STATE_DIR}/marker-tree.tar.gz" "${journal}/marker-tree.tar.gz.recovery"
    fi
    # The recovery manifest is the activation record. If preparing this journal
    # is interrupted, canonical assets are untouched and the next run rebuilds
    # the journal from them before any canonical mutation.
    publisher_lease_assert_owned || return 1
    gh release upload "$TAG" --repo "$REPO" --clobber "${journal}/${RECOVERY_BUNDLE}" || return 1
    if [ -f "${journal}/marker-tree.tar.gz.recovery" ]; then
        publisher_lease_assert_owned || return 1
        gh release upload "$TAG" --repo "$REPO" --clobber "${journal}/marker-tree.tar.gz.recovery" || return 1
    fi
    publisher_lease_assert_owned || return 1
    gh release upload "$TAG" --repo "$REPO" --clobber "${journal}/${RECOVERY_SIGNATURE}" || return 1
    publisher_lease_assert_owned || return 1
    gh release upload "$TAG" --repo "$REPO" --clobber "${journal}/${RECOVERY_MANIFEST}"
}

if [ "$RELEASE_HTTP" = 200 ]; then
    RELEASE_ASSETS="$(gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets[].name')" \
        || die "cannot inspect release asset inventory; refusing to classify canonical damage"
    primary_high_water=""
    recovery_high_water=""
    if release_has_asset "$VERSION_HIGH_WATER_ASSET"; then
        primary_high_water="$(read_version_high_water "$VERSION_HIGH_WATER_ASSET")" \
            || die "version high-water asset exists but cannot be downloaded and authenticated; refusing recovery"
    fi
    if release_has_asset "$VERSION_HIGH_WATER_RECOVERY_ASSET"; then
        recovery_high_water="$(read_version_high_water "$VERSION_HIGH_WATER_RECOVERY_ASSET")" \
            || die "recovery version high-water asset exists but cannot be downloaded and authenticated; refusing recovery"
    fi
    if [ -n "$primary_high_water" ] || [ -n "$recovery_high_water" ]; then
        VERSION_HIGH_WATER="$(merge_version_high_water "$primary_high_water" "$recovery_high_water")" \
            || die "authenticated version high-water assets are inconsistent"
    fi

    recovery_journal_present=0
    for journal_asset in "$RECOVERY_BUNDLE" "$RECOVERY_MANIFEST" "$RECOVERY_SIGNATURE" marker-tree.tar.gz.recovery; do
        release_has_asset "$journal_asset" && recovery_journal_present=1
    done

    # A create response can be lost, and a first publication can stop after one
    # or both version reservations but before manifest activation. With no
    # canonical manifest and no recovery-journal evidence there is no prior
    # client-visible state to restore: start at one if the release is empty, or
    # advance past the authenticated reservation. Any journal evidence routes to
    # normal exact recovery below and must be complete.
    if ! release_has_asset compiled.yac.manifest.json \
            && [ "$recovery_journal_present" -eq 0 ]; then
        PREV=0
        PREVIOUS_MARKER=0
        if [ -n "$VERSION_HIGH_WATER" ]; then
            VERSION="$(derive_next_version "$VERSION_HIGH_WATER")" \
                || die "unactivated initial publication exhausted its authenticated version reservation"
            reconcile_version_high_water \
                || die "could not preserve the interrupted initial publication's version reservation"
            note "initial publication was interrupted before manifest activation; advancing past reserved version ${VERSION_HIGH_WATER}"
        else
            [ -z "$RELEASE_ASSETS" ] \
                || die "release has unauthenticated assets but no canonical manifest, recovery journal, or version reservation"
            VERSION=1
            note "existing ${TAG} release is empty — first publish, starting at version 1"
        fi
    else

        canonical_inventory_complete=1
        for required_asset in compiled.yac compiled.yac.manifest.json compiled.yac.manifest.json.sig; do
            release_has_asset "$required_asset" || canonical_inventory_complete=0
        done
        canonical_downloaded=0
        if [ "$canonical_inventory_complete" -eq 1 ]; then
            download_release_state "$CURRENT_STATE_DIR" \
                compiled.yac compiled.yac.manifest.json compiled.yac.manifest.json.sig marker-tree.tar.gz \
                || die "complete canonical assets are listed but could not be downloaded; treating this as transient and refusing recovery"
            canonical_downloaded=1
        fi
        if [ "$canonical_downloaded" -eq 1 ] \
            && version_pair="$(validate_release_state \
                "${CURRENT_STATE_DIR}/compiled.yac.manifest.json" \
                "${CURRENT_STATE_DIR}/compiled.yac.manifest.json.sig" \
                "${CURRENT_STATE_DIR}/compiled.yac" \
                "${CURRENT_STATE_DIR}/marker-tree.tar.gz")"; then
            read -r PREV ignored_next PREVIOUS_MARKER version_extra <<<"$version_pair"
            if [ -z "$PREV" ] || [ -z "$ignored_next" ] \
                || { [ "$PREVIOUS_MARKER" != 0 ] && [ "$PREVIOUS_MARKER" != 1 ]; } \
                || [ -n "${version_extra:-}" ]; then
                die "published manifest version parser returned malformed state; refusing to bump"
            fi
        else
            [ -n "$VERSION_HIGH_WATER" ] \
                || die "canonical release state is damaged without an authenticated version high-water mark; refusing rollback recovery"
            note "canonical release state is incomplete or unauthenticated; attempting exact recovery"
            restore_recovery_journal \
                || die "canonical release state is invalid and no complete authenticated recovery journal could restore it without version reuse"
        fi
        VERSION="$(derive_next_version "$PREV")" \
            || die "authenticated version state is exhausted or inconsistent with its high-water mark; prior canonical state was restored when recovery was required"
        [ -n "$VERSION_HIGH_WATER" ] || VERSION_HIGH_WATER="$PREV"
        reconcile_version_high_water \
            || die "could not preserve the authenticated version maximum in both reservation slots; canonical assets were not changed"
        write_recovery_journal \
            || die "could not preserve the complete authenticated prior release state; canonical assets were not changed"
    fi
else
    note "no existing ${TAG} release — first publish, starting at version 1"
    PREV=0
    VERSION=1
    PREVIOUS_MARKER=0
fi

# The prior-state gate is publication coordination; the preflight and every
# later local candidate-construction failure retain their build-stage identity.
NIGHTLY_STAGE=build
PREFLIGHT_MANIFEST="${WORK}/signing-preflight.json"
PREFLIGHT_SIG="${PREFLIGHT_MANIFEST}.sig"
printf '%s\n' '{"schema":"mailstrix-rules-signing-preflight-v1"}' >"$PREFLIGHT_MANIFEST"
"$RULESIGN_BIN" -require-trusted -manifest "$PREFLIGHT_MANIFEST" -out "$PREFLIGHT_SIG" \
    || die "signing-key preflight failed; refusing to start the rules build"
[ -s "$PREFLIGHT_SIG" ] \
    || die "signing-key preflight produced an empty signature; refusing to start the rules build"

# 1) Build the rules-export stage and extract the .yac + the libyara version.
# Forward every documented rule-source build-arg that is set in the environment
# so the published rolling bundle honours the same pin/toggle knobs as a direct
# `docker build --build-arg …` of the image.
build_args=""
for v in MAILSTRIX_PROFILE YARAFORGE_SET YARAFORGE_FILTER YARAFORGE_URL SIGBASE_REF \
         ANYRUN ANYRUN_REF DIDIER DIDIER_REF BARTBLAZE BARTBLAZE_REF \
         INQUEST INQUEST_REF CAPE CAPE_REF YARAIFY YARAIFY_URL; do
    eval "val=\${$v+set}"
    [ "${val:-}" = set ] || continue
    eval "build_args=\"\$build_args --build-arg $v=\${$v}\""
done

# Marker tree (decision D2: latest-release toolchain only). A marker artifact
# binds to the exact yarac and libyara.a linked into the binary that loads it,
# and libyara.a is not byte-reproducible (docker/release-marker-toolchain.sh), so
# the bundle and its tree are compiled together with the latest release's own
# toolchain through docker/Dockerfile.release. Every failure on this path (no
# release, legacy release without toolchain assets, toolchain not linked into the
# release strixd, a build error) falls back to the unchanged build below and
# publishes no marker field; it never fails the publication.
EXPORT_DIR="$WORK"
MARKER_VERIFIER_IMAGE=""
MARKER_TAG="${MARKER_RELEASE_TAG-}"
if [ "${MARKER_RELEASE_TAG+set}" != set ]; then
    MARKER_TAG="$(gh api "repos/${REPO}/releases/latest" --jq .tag_name 2>/dev/null || true)"
fi
case "$MARKER_TAG" in
    v[0-9]*) case "$MARKER_TAG" in *[!A-Za-z0-9._-]*) MARKER_TAG="" ;; esac ;;
    *) MARKER_TAG="" ;;
esac

verify_marker_release_abi() {  # <tag> <export-dir> <verifier-image>
    local sums="${WORK}/marker-release.SHA256SUMS" arch
    # Use the actual verifier's architecture, not the host's (the Docker daemon
    # or buildx builder may target another architecture).
    arch="$(docker image inspect --format '{{.Architecture}}' "$3")" || return 1
    case "$arch" in amd64|arm64) ;; *) return 1 ;; esac
    gh release download "$1" --repo "$REPO" --pattern SHA256SUMS --output "$sums" || return 1
    # Dockerfile.release fetches these exact asset names. Independently bind
    # the exported ABI bytes to the selected release before trusting the tree;
    # a matching version string alone does not establish compiler identity.
    python3 - "$sums" "$2" "$arch" <<'PY'
import hashlib
from pathlib import Path
import re
import sys

sums, export, arch = sys.argv[1:]
try:
    entries = {}
    lines = Path(sums).read_text(encoding="ascii").splitlines()
    if not lines:
        raise ValueError("empty SHA256SUMS")
    for line in lines:
        match = re.fullmatch(r"([0-9a-fA-F]{64})  (\S+)", line)
        if match is None or match[2] in entries:
            raise ValueError("malformed or duplicate SHA256SUMS entry")
        entries[match[2]] = match[1].lower()
    for local, asset in (("yarac", f"yarac-linux-{arch}"),
                         ("libyara.a", f"libyara-linux-{arch}.a")):
        path = Path(export) / "marker-artifact" / "abi" / local
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("missing regular ABI file")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if entries.get(asset) != digest.hexdigest():
            raise ValueError("release ABI checksum mismatch or missing entry")
except (OSError, UnicodeError, ValueError) as error:
    print(f"generate-rules: cannot bind marker ABI to release SHA256SUMS: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

build_marker_export() {  # build_marker_export <tag>; 0 only for a complete marker export + verifier
    local tag="$1" out="${WORK}/marker-export"
    mkdir -p "$out" || return 1
    # shellcheck disable=SC2086  # build_args is a deliberately word-split arg list
    docker buildx build \
        --target rules-export \
        --build-arg "RELEASE_TAG=${tag}" \
        --build-arg "CACHEBUST=$(date +%s)" \
        $build_args \
        --output "type=local,dest=${out}" \
        -f "${HERE}/docker/Dockerfile.release" "${HERE}" || return 1
    [ -s "${out}/compiled.yac" ] && [ -f "${out}/libyara.version" ] \
        && [ -d "${out}/compiler-inputs" ] && [ -d "${out}/marker-artifact" ] || return 1
    # Skew guard: the pre-publish check-rules load and the later verification
    # use the HEAD-built verifier, while this export carries the release's
    # libyara. A .yac only loads on a matching libyara, so when HEAD moved
    # YARA_VERSION past the release, publish the unmarked HEAD build instead of
    # dying at check-rules. An empty or invalid release version file still dies.
    local rel_ver head_ver
    # Trim only surrounding whitespace: an embedded space must fail validation,
    # not collapse into a different, valid-looking version.
    rel_ver="$(<"${out}/libyara.version")"
    rel_ver="${rel_ver#"${rel_ver%%[![:space:]]*}"}"
    rel_ver="${rel_ver%"${rel_ver##*[![:space:]]}"}"
    [[ "$rel_ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "invalid libyara version in the ${tag} marker export: '${rel_ver}'"
    head_ver="$(sed -n 's/^ARG YARA_VERSION=\([0-9][0-9.]*\)[[:space:]]*$/\1/p' "${HERE}/docker/Dockerfile" 2>/dev/null | head -n1)"
    if [ -z "$head_ver" ]; then
        note "WARNING: cannot read ARG YARA_VERSION from HEAD docker/Dockerfile; publishing the unmarked HEAD build"
        return 1
    fi
    if [ "$head_ver" != "$rel_ver" ]; then
        note "the ${tag} toolchain libyara ${rel_ver} differs from HEAD libyara ${head_ver}; publishing the unmarked HEAD build"
        return 1
    fi
    # The released strixd is the binary that must load the tree.
    docker buildx build --target rules-verifier --load \
        --build-arg "RELEASE_TAG=${tag}" \
        --iidfile "${WORK}/marker-verifier.iid" \
        -f "${HERE}/docker/Dockerfile.release" "${HERE}" || return 1
    [ -s "${WORK}/marker-verifier.iid" ] || return 1
    MARKER_VERIFIER_IMAGE="$(<"${WORK}/marker-verifier.iid")"
    [ -n "$MARKER_VERIFIER_IMAGE" ] || return 1
    if ! verify_marker_release_abi "$tag" "$out" "$MARKER_VERIFIER_IMAGE"; then
        note "cannot verify the ${tag} marker toolchain against release SHA256SUMS; publishing the unmarked HEAD build"
        return 1
    fi
    # A marker-capable release built before -require-marker existed cannot run
    # the staged gate; without this probe every publication would die there
    # instead of falling back. `-h` prints the flag list and exits 2.
    local usage
    usage="$(docker run --rm --network none "$MARKER_VERIFIER_IMAGE" -h 2>&1 || true)"
    grep -qF -- '-require-marker' <<<"$usage" || {
        note "the ${tag} strixd has no -require-marker gate; publishing without a marker tree"
        MARKER_VERIFIER_IMAGE=""
        return 1
    }
}
if [ -n "$MARKER_TAG" ]; then
    note "building rules with the ${MARKER_TAG} marker toolchain…"
    if build_marker_export "$MARKER_TAG"; then
        EXPORT_DIR="${WORK}/marker-export"
    else
        note "no marker-capable build from ${MARKER_TAG}; publishing without a marker tree"
        rm -rf "${WORK}/marker-export" "${WORK}/marker-verifier.iid"
        MARKER_VERIFIER_IMAGE=""
    fi
fi

if [ -z "$MARKER_VERIFIER_IMAGE" ]; then
    note "building rules (CACHEBUST forces a fresh fetch of the public rulesets)…"
    # shellcheck disable=SC2086  # build_args is a deliberately word-split arg list
    docker buildx build \
        --target rules-export \
        --build-arg "CACHEBUST=$(date +%s)" \
        $build_args \
        --output "type=local,dest=${WORK}" \
        -f "${HERE}/docker/Dockerfile" "${HERE}"
fi

YAC="${EXPORT_DIR}/compiled.yac"
[ -s "$YAC" ] || die "no compiled.yac produced"
SOURCES="${EXPORT_DIR}/sources.json"
[ -f "$SOURCES" ] || note "no sources.json in export — provenance will be absent from manifest"
LIBYARA="$(tr -d '[:space:]' < "${EXPORT_DIR}/libyara.version")"
[ -n "$LIBYARA" ] || die "could not determine libyara version"

# Build the matching native consumer, then load the exact exported bundle before
# publishing. The image has no production cache or rule sources.
docker buildx build --target rules-verifier --load \
    --iidfile "${WORK}/verifier.iid" \
    -f "${HERE}/docker/Dockerfile" "${HERE}"
VERIFIER_IMAGE="$(<"${WORK}/verifier.iid")"

# check-rules reports the native scanner's count only after loading succeeds.
# Mount only the exported file read-only; override the download-only entrypoint
# and disable networking so local verification cannot fetch a different bundle.
RULES_REPORT="$(docker run --rm --read-only --network none \
    --tmpfs /tmp:rw,nosuid,nodev,size=2g \
    --mount "type=bind,src=${YAC},dst=/compiled.yac,readonly" \
    --entrypoint /usr/local/bin/strixd "$VERIFIER_IMAGE" \
    check-rules -rules /compiled.yac -cache-dir '' -seed-rules '')" \
    || die "could not load exported bundle to determine rule count"
COUNT_PATTERN='^check-rules: OK — (0|[1-9][0-9]*) rules loaded \(fingerprint [^[:space:]()]+\)$'
[[ "$RULES_REPORT" =~ $COUNT_PATTERN ]] \
    || die "native rule verifier returned malformed count output"
RULES="${BASH_REMATCH[1]}"
# Both the manifest and receipt must remain decodable by every Go int consumer.
MAX_RULES=2147483647
if [ "${#RULES}" -gt "${#MAX_RULES}" ] || [ "$RULES" -gt "$MAX_RULES" ]; then
    die "native rule count exceeds ${MAX_RULES}"
fi
if [ "$RULES" -eq 0 ]; then
    die "native rule verifier loaded 0 rules; refusing to publish an empty bundle"
fi

# 3) Compute the checksum + sanity fields, write the manifest.
SUM="$(sha256sum "$YAC" | awk '{print $1}')"
SIZE="$(stat -c '%s' "$YAC")"
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

# 3a) Marker field. Pack the tree from the marker export and bind it into the
# manifest, so the signature below covers it. Any packing problem drops only the
# marker (the bundle still publishes as before).
MARKER_ASSET="marker-tree.tar.gz"
MARKER_FILE="${WORK}/${MARKER_ASSET}"
MARKER_PUBLISH=0
MARKER_GATE_TMPFS=""
if [ -n "$MARKER_VERIFIER_IMAGE" ]; then
    marker_json=""
    if python3 "${HERE}/docker/pack-marker-tree.py" "$EXPORT_DIR" "$MARKER_FILE" \
        && [ -f "${EXPORT_DIR}/marker-artifact/abi/libyara.a" ] \
        && [ -f "${EXPORT_DIR}/marker-artifact/abi/yarac" ]; then
        marker_json="$(jq -cn \
            --arg asset "$MARKER_ASSET" \
            --arg sha256 "$(sha256sum "$MARKER_FILE" | awk '{print $1}')" \
            --argjson size "$(stat -c '%s' "$MARKER_FILE")" \
            --arg libyara "$(sha256sum "${EXPORT_DIR}/marker-artifact/abi/libyara.a" | awk '{print $1}')" \
            --arg compiler "$(sha256sum "${EXPORT_DIR}/marker-artifact/abi/yarac" | awk '{print $1}')" \
            --arg main "$SUM" \
            '{asset:$asset, sha256:$sha256, size:$size, libyara_sha256:$libyara, compiler_sha256:$compiler, main_sha256:$main}')" || marker_json=""
    fi
    if [ -n "$marker_json" ] \
        && jq --argjson marker "$marker_json" '. + {marker:$marker}' "$MANIFEST" > "${MANIFEST}.marker" \
        && mv "${MANIFEST}.marker" "$MANIFEST"; then
        MARKER_PUBLISH=1
    else
        note "could not pack or bind the marker tree; publishing without a marker tree"
        rm -f "${MANIFEST}.marker" "$MARKER_FILE"
    fi
fi

# Bind the verifier resource limit to the exact candidate that will be signed
# and served. This runs after marker construction but before signing or any
# release mutation, so malformed, oversized, or arithmetically unsafe inputs
# cannot result in a partially published release.
if [ "$MARKER_PUBLISH" -eq 1 ]; then
    marker_metrics="$(marker_tree_metrics "$MARKER_FILE")" \
        || die "cannot measure the staged marker tree; nothing was published"
    read -r marker_tree_bytes marker_tree_entries marker_metrics_extra <<<"$marker_metrics"
    if [ -z "$marker_tree_bytes" ] || [ -z "$marker_tree_entries" ] || [ -n "${marker_metrics_extra:-}" ]; then
        die "staged marker tree metrics are malformed; nothing was published"
    fi
    MARKER_GATE_TMPFS="$(marker_gate_tmpfs_size \
        "$SIZE" "$(stat -c '%s' "$MARKER_FILE")" \
        "$marker_tree_bytes" "$marker_tree_entries")" \
        || die "staged marker verifier tmpfs requirement is invalid or exceeds its bounded ceiling; nothing was published"
fi

# 3b) Sign the manifest. strixd refuses any remote manifest without a valid
# ed25519 signature from a key compiled into the binary, so an unsigned
# publication would be rejected by every client (and by the post-publish
# verification below). Fail here rather than publish an uninstallable bundle.
#
# The key never touches argv: cmd/rulessign reads MAILSTRIX_RULES_SIGNING_KEY
# from the environment. It signs the exact manifest bytes; nothing re-encodes
# the JSON between signing and upload.
#
# Startup already resolved and validated the key (environment, else the
# MAILSTRIX_RULES_SIGNING_KEY_B64 build-env fallback) and died if it could not,
# so this refusal is defence in depth: it keeps the invariant local to the step
# that depends on it rather than trusting a distant block.
prepare_version_high_water "$VERSION" \
    || die "could not prepare the authenticated version high-water mark; nothing was published"
MANIFEST_SIG="${MANIFEST}.sig"
[ -n "${MAILSTRIX_RULES_SIGNING_KEY:-}" ] \
    || die "MAILSTRIX_RULES_SIGNING_KEY is not set; refusing to publish an unsigned manifest that no client would install"
# -require-trusted: refuse to sign with a key whose public half is not pinned in
# the client binary. Without it a rotated or wrong key would publish a perfectly
# valid signature that every deployed strixd refuses, i.e. a silently dead
# updater discovered only by users.
"$RULESIGN_BIN" -require-trusted -manifest "$MANIFEST" -out "$MANIFEST_SIG" \
    || die "signing the manifest failed; refusing to publish an unsigned manifest"
[ -s "$MANIFEST_SIG" ] || die "manifest signature is empty; refusing to publish"

note "version ${PREV} -> ${VERSION}, libyara ${LIBYARA}, size ${SIZE}, sha256 ${SUM:0:12}…"

# 3c) Prove the marker tree before anything is uploaded: serve the staged
# candidate on loopback and let the release's own strixd fetch, verify and load
# it. A failure here publishes nothing new (the release is still untouched).
VERIFY_IMAGE="$VERIFIER_IMAGE"
VERIFY_EXTRA=()
# The non-marker verifier only downloads the compiled bundle. Marker candidates
# use the candidate-specific bounded value computed above.
VERIFY_TMPFS="size=2g"
if [ "$MARKER_PUBLISH" -eq 1 ]; then
    [ -n "$MARKER_GATE_TMPFS" ] \
        || die "marker verifier tmpfs size was not derived; nothing was published"
    NIGHTLY_STAGE=verify
    STAGE="${WORK}/stage"
    mkdir -p "$STAGE"
    cp "$YAC" "${STAGE}/compiled.yac"
    cp "$MANIFEST" "${STAGE}/compiled.yac.manifest.json"
    cp "$MANIFEST_SIG" "${STAGE}/compiled.yac.manifest.json.sig"
    cp "$MARKER_FILE" "${STAGE}/${MARKER_ASSET}"
    cat >"${WORK}/serve-stage.py" <<'PY'
import functools
import http.server
import sys


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


handler = functools.partial(Quiet, directory=sys.argv[1])
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
print(server.server_address[1], flush=True)
server.serve_forever()
PY
    exec {server_fd}< <(exec python3 -u "${WORK}/serve-stage.py" "$STAGE")
    SERVER_PID=$!
    stage_port=""
    read -r -t 30 -u "$server_fd" stage_port || true
    case "$stage_port" in
        ''|*[!0-9]*) die "could not start the local server for the staged candidate" ;;
    esac
    docker run --rm --read-only --network host \
        --tmpfs "/tmp:rw,nosuid,nodev,${MARKER_GATE_TMPFS}" \
        "$MARKER_VERIFIER_IMAGE" -url "http://127.0.0.1:${stage_port}" -allow-http \
        -timeout 5m -expected-version "$VERSION" -require-marker \
        || die "staged marker tree did not verify and load with the ${MARKER_TAG} strixd; nothing was published"
    kill "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    exec {server_fd}<&-
    VERIFY_IMAGE="$MARKER_VERIFIER_IMAGE"
    VERIFY_EXTRA=(-require-marker)
    VERIFY_TMPFS="$MARKER_GATE_TMPFS"
    NIGHTLY_STAGE=build
    note "marker tree verified against ${MARKER_TAG}: ${MARKER_ASSET}"
fi

# 4) Publish to the rolling release (create once if absent), clobbering assets.
# Reuse the HTTP-status probe from step 1 (same reason: gh's exit status is not
# trustworthy here). RELEASE_HTTP is 200 or 404 by now — anything else already died.
NIGHTLY_STAGE=publish
# A failed create can follow a server-side mutation or ambiguous transport loss,
# so uncertainty starts before the first remote release mutation.
PUBLISH_STATE=uncertain
if [ "$RELEASE_HTTP" != 200 ]; then
    publisher_lease_assert_owned \
        || die "publisher lease was lost before release creation; nothing was published"
    note "creating rolling release ${TAG}"
    gh release create "$TAG" --repo "$REPO" \
        --title "Compiled rules (rolling)" \
        --notes "Rolling compiled YARA bundle for \`strixd --fetch-rules\`. Assets are clobbered on each rule regeneration; see compiled.yac.manifest.json for the current version." \
        --latest=false
fi
# Reserve the candidate version durably before the first canonical mutation.
# Startup reconciled both bounded slots to the previous authenticated maximum.
# The recovery copy lands first while canonical preserves that maximum; canonical
# then lands while recovery preserves the candidate. A failed/ambiguous run is
# repaired back to two equal slots before any later version may advance.
publisher_lease_assert_owned \
    || die "publisher lease was lost before version reservation; nothing was published"
gh release upload "$TAG" --repo "$REPO" --clobber "$VERSION_HIGH_WATER_RECOVERY_CANDIDATE"
publisher_lease_assert_owned \
    || die "publisher lease was lost before canonical version reservation; nothing was published"
gh release upload "$TAG" --repo "$REPO" --clobber "$VERSION_HIGH_WATER_CANDIDATE"
# Publish the manifest last. During the rolling asset replacement window an
# older manifest can describe the new bytes; consumers reject and retry later.
publisher_lease_assert_owned \
    || die "publisher lease was lost before bundle upload; nothing was published"
gh release upload "$TAG" --repo "$REPO" --clobber "$YAC"
# The marker tree goes up BEFORE the signature and manifest that reference it, so
# no client ever sees a signed manifest naming a missing or older tree asset.
if [ "$MARKER_PUBLISH" -eq 1 ]; then
    publisher_lease_assert_owned \
        || die "publisher lease was lost before marker upload"
    gh release upload "$TAG" --repo "$REPO" --clobber "$MARKER_FILE"
fi
# The signature goes up BEFORE the manifest it covers: during the rolling
# replacement window a client must never see a new manifest paired with the
# previous signature, which it would (correctly) refuse.
publisher_lease_assert_owned \
    || die "publisher lease was lost before manifest signature upload"
gh release upload "$TAG" --repo "$REPO" --clobber "$MANIFEST_SIG"
publisher_lease_assert_owned \
    || die "publisher lease was lost before manifest activation"
gh release upload "$TAG" --repo "$REPO" --clobber "$MANIFEST"
PUBLISH_STATE=published

# An independent download through the actual consumer validates release/CDN
# bytes, manifest identity and native loadability without touching any host cache.
# Asset replacement can be briefly incoherent at the CDN, so retry with bounded
# backoff and alert only when the new release stays unverifiable.
NIGHTLY_STAGE=verify
verified=0
for attempt in 1 2 3 4 5; do
	if docker run --rm --read-only --tmpfs "/tmp:rw,nosuid,nodev,${VERIFY_TMPFS}" \
		"$VERIFY_IMAGE" -url "https://github.com/${REPO}/releases/download/${TAG}" \
		-timeout 5m -expected-version "$VERSION" ${VERIFY_EXTRA[@]+"${VERIFY_EXTRA[@]}"}; then
        verified=1
        break
    fi
    if [ "$attempt" -lt 5 ]; then
        note "post-publish verification attempt ${attempt} failed; retrying"
        sleep $((attempt * 5))
    fi
done
[ "$verified" -eq 1 ] \
    || die "$(published_verify_notice failed)"

note "published ${TAG}: compiled.yac (v${VERSION}) + signed manifest"

# Prepare the success notification before the terminal receipt. The notification
# delivery itself remains best-effort, so no fallible work follows that receipt.
NIGHTLY_STAGE=receipt
SIZE_MIB="$(awk -v b="$SIZE" 'BEGIN{printf "%.1f", b/1048576}')"
rules_line=""
[ "$RULES" = 0 ] || rules_line=", ${RULES} rules"

# This is the terminal verify artifact, not best-effort telemetry: its numeric
# fields have already passed jq while writing MANIFEST before publication. An
# encoding fault fails closed as its own receipt stage rather than mislabeling a
# successfully native-verified release as a verify failure.
# Success reports `verify`; only an in-flight serialization or emission failure is relabeled
# `receipt` by the ERR trap while _RECEIPT_EMITTING is set.
# Defer signals before exposing the success stage; verification already finished.
_RECEIPT_EMITTING=1
NIGHTLY_STAGE=verify
nightly_receipt success
_RECEIPT_EMITTING=0
if [ "$_PENDING_SIGNAL" -ne 0 ]; then NIGHTLY_STAGE=receipt; fi
finish_pending_signal

# Shout success to Discord #builds. Size in MiB; rules count only if known (>0).
shout "strixd rules: rules-current v${VERSION} published" \
      "Fresh compiled YARA bundle published to \`${TAG}\` (v${PREV}→v${VERSION}${rules_line}, ${SIZE_MIB} MiB, libyara ${LIBYARA}). strixd \`--fetch-rules\` clients update on next check."
