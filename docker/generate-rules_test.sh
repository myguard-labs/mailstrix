#!/usr/bin/env bash
# Exercise terminal receipts, stage-specific failure notices, ordered publishing,
# and verifier error propagation with all external commands stubbed.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
for bin in awk date dirname jq mktemp python3; do
    command -v "$bin" >/dev/null 2>&1 || {
        printf 'FAIL: required test tool unavailable: %s\n' "$bin" >&2
        exit 2
    }
done
REAL_JQ="$(command -v jq)"
REAL_MKTEMP="$(command -v mktemp)"
REAL_AWK="$(command -v awk)"
REAL_DIRNAME="$(command -v dirname)"
REAL_DATE="$(command -v date)"
export REAL_JQ REAL_MKTEMP REAL_AWK REAL_DIRNAME REAL_DATE
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
mkdir -p "$test_root/sandbox/project/docker" "$test_root/bin" "$test_root/tools"
cp "$here/generate-rules.sh" "$test_root/sandbox/project/docker/"
export EVENTS="$test_root/events"
export PATH="$test_root/bin:$PATH"
export GH_TOKEN=fixture-not-a-credential

cat >"$test_root/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = run ]; then
    printf 'verify %s\n' "$*" >> "$EVENTS"
    attempts_file="${EVENTS}.attempts"
    attempts=0
    [ ! -f "$attempts_file" ] || attempts="$(cat "$attempts_file")"
    attempts=$((attempts + 1))
    printf '%s\n' "$attempts" > "$attempts_file"
    [ "$attempts" -gt "${FAIL_VERIFY_UNTIL:-0}" ]
    exit
fi
[ "${FAIL_BUILD:-0}" -eq 0 ] || exit 41
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)
            dir="${2#type=local,dest=}"
            printf 'fixture bundle' > "$dir/compiled.yac"
            printf '4.5.2\n' > "$dir/libyara.version"
            shift ;;
        --iidfile) printf 'sha256:fixture\n' > "$2"; shift ;;
    esac
    shift
done
STUB

cat >"$test_root/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "${2:-}" in
    create)
        printf 'create\n' >> "$EVENTS"
        [ "${FAIL_CREATE:-0}" -eq 0 ] || exit 49
        ;;
    upload)
        printf 'upload %s\n' "$(basename "${!#}")" >> "$EVENTS"
        [ "${FAIL_PUBLISH:-0}" -eq 0 ] || exit 42
        ;;
esac
STUB

cat >"$test_root/bin/curl" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null
printf '%s' "${RELEASE_HTTP:-404}"
STUB

cat >"$test_root/bin/mktemp" <<'STUB'
#!/usr/bin/env bash
if [ "${FAIL_MKTEMP:-0}" -eq 1 ]; then
    exit 44
fi
exec "$REAL_MKTEMP" "$@"
STUB

cat >"$test_root/bin/awk" <<'STUB'
#!/usr/bin/env bash
if [ "${FAIL_POST_VERIFY_AWK:-0}" -eq 1 ] && [[ "$*" == *'-v b='* ]]; then
    exit 47
fi
exec "$REAL_AWK" "$@"
STUB

cat >"$test_root/bin/dirname" <<'STUB'
#!/usr/bin/env bash
if [ "${FAIL_HERE:-0}" -eq 1 ]; then
    printf '%s\n' /missing-repository-path
    exit 0
fi
exec "$REAL_DIRNAME" "$@"
STUB

cat >"$test_root/bin/date" <<'STUB'
#!/usr/bin/env bash
if [ "${FAIL_MANIFEST_DATE:-0}" -eq 1 ] && [ "${1:-}" = -u ]; then
    exit 48
fi
exec "$REAL_DATE" "$@"
STUB

cat >"$test_root/bin/jq" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAIL_RECEIPT:-0}" -eq 1 ] && [[ "$*" == *mailstrix-rules-nightly-v1* ]]; then
    exit 43
fi
if [ "${FAIL_RECEIPT_ONCE:-0}" -eq 1 ] && [[ "$*" == *mailstrix-rules-nightly-v1* ]]; then
    receipt_attempts="${EVENTS}.receipt-attempts"
    attempts=0
    [ ! -f "$receipt_attempts" ] || attempts="$(cat "$receipt_attempts")"
    attempts=$((attempts + 1))
    printf '%s\n' "$attempts" > "$receipt_attempts"
    [ "$attempts" -gt 1 ] || exit 43
fi
exec "$REAL_JQ" "$@"
STUB

cat >"$test_root/tools/discord-notify.py" <<'STUB'
#!/usr/bin/env python3
import os
import sys

with open(os.environ["EVENTS"], "a", encoding="utf-8") as events:
    events.write(f"notify {sys.argv[2]}\n")
    events.write(f"notify-body {sys.argv[3]}\n")
raise SystemExit(int(os.environ.get("FAIL_NOTIFY", "0")))
STUB

cat >"$test_root/bin/sleep" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$test_root/bin/"* "$test_root/tools/discord-notify.py"

assert_event() {
    printf 'FAIL: %s\nevents:\n' "$1" >&2
    sed 's/^/  /' "$EVENTS" >&2
    exit 1
}

assert_receipt() {  # assert_receipt <stage> <status> [rules]
    python3 - "$test_root/log" "$1" "$2" "${3:-0}" <<'PY'
import json
import sys

path, stage, status, expected_rules = sys.argv[1:]
rows = []
for line in open(path, encoding="utf-8"):
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        continue
    if value.get("schema") == "mailstrix-rules-nightly-v1":
        rows.append(value)
if len(rows) != 1:
    raise SystemExit(f"expected one nightly receipt, got {rows!r}")
receipt = rows[0]
if receipt.get("stage") != stage or receipt.get("status") != status:
    raise SystemExit(f"receipt stage/status {receipt!r}, want {stage}/{status}")
if status == "success":
    expected = {"version": 1, "libyara": "4.5.2", "rules": int(expected_rules), "size": 14, "loadable": True}
    if any(receipt.get(k) != v for k, v in expected.items()) or not receipt.get("checksum", "").startswith("sha256:") or not receipt.get("generated", "").endswith("Z"):
        raise SystemExit(f"success receipt lost fresh-verifier evidence: {receipt!r}")
elif set(receipt) != {"schema", "stage", "status"}:
    raise SystemExit(f"failure receipt leaked variable output: {receipt!r}")
PY
}

assert_verifier_contract() {  # assert_verifier_contract <case> <count>
    local name="$1" verify_count="$2" first_verify
    [ "$verify_count" -gt 0 ] || return 0
    first_verify="$(grep -m1 '^verify ' "$EVENTS")"
    [[ "$first_verify" == *'-expected-version 1'* ]] || assert_event "$name: verifier version pin"
    [[ "$first_verify" == *'-timeout 5m'* ]] || assert_event "$name: verifier timeout"
    [[ "$first_verify" == *'--read-only --tmpfs /tmp:rw,nosuid,nodev,size=2g'* ]] || assert_event "$name: verifier isolation"
}

assert_notification() {  # assert_notification <case> <stage> <status>
    local name="$1" stage="$2" status="$3"
    [ "$(grep -c '^notify ' "$EVENTS" || true)" -eq 1 ] || assert_event "$name: notification count"
    if [ "$status" = success ]; then
        grep -Fx 'upload compiled.yac' "$EVENTS" >/dev/null || assert_event "$name: bundle upload missing"
        grep -Fx 'upload compiled.yac.manifest.json' "$EVENTS" >/dev/null || assert_event "$name: manifest upload missing"
        grep -Fx 'notify strixd rules: rules-current v1 published' "$EVENTS" >/dev/null || assert_event "$name: success notification"
        return
    fi
    grep -Fx "notify strixd rules: ${stage} FAILED" "$EVENTS" >/dev/null || assert_event "$name: stage notification"
}

assert_success_event_order() {  # assert_success_event_order <case> <verify-count>
    local name="$1" verify_count="$2" index event
    local -a lifecycle
    while IFS= read -r event; do
        case "$event" in
            upload\ *|verify\ *|notify\ *) lifecycle+=("$event") ;;
        esac
    done <"$EVENTS"
    [ "${lifecycle[0]:-}" = 'upload compiled.yac' ] || assert_event "$name: compiled.yac was not uploaded first"
    [ "${lifecycle[1]:-}" = 'upload compiled.yac.manifest.json' ] || assert_event "$name: manifest was not uploaded after compiled.yac"
    for ((index = 0; index < verify_count; index++)); do
        [[ "${lifecycle[index + 2]:-}" == verify\ * ]] || assert_event "$name: verifier ran before both uploads"
    done
    [ "${lifecycle[verify_count + 2]:-}" = 'notify strixd rules: rules-current v1 published' ] || assert_event "$name: success notification did not follow verification"
    [ "${#lifecycle[@]}" -eq "$((verify_count + 3))" ] || assert_event "$name: unexpected lifecycle event count"
}

assert_receipt_failure_preserves_stage_failure() {
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if FAIL_BUILD=1 FAIL_RECEIPT=1 bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq 41 ] || assert_event "receipt failure masked build exit: $actual"
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 0 ] || assert_event 'failed serializer emitted a receipt'
    grep -Fx 'notify strixd rules: build FAILED' "$EVENTS" >/dev/null || assert_event 'receipt failure lost build notification'
    grep -F 'ERROR: failed to emit nightly receipt' "$test_root/log" >/dev/null || assert_event 'receipt failure not diagnosed'
}

assert_release_probe_failure_is_publish() {
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if RELEASE_HTTP=401 bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq 1 ] || assert_event "release probe exit: $actual"
    assert_receipt publish failed
    grep -Fx 'notify strixd rules: publish FAILED' "$EVENTS" >/dev/null || assert_event 'release probe stage notification'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'release probe uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'release probe started verifier'
}

assert_release_create_failure_is_publish_uncertain() {
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if FAIL_CREATE=1 bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq 49 ] || assert_event "release create exit: $actual"
    assert_receipt publish failed
    assert_notification release-create publish failed
    grep -F 'notify-body generate-rules.sh exited 49 — rules-current may be partially updated.' "$EVENTS" >/dev/null || assert_event 'release create state wording'
    [ "$(grep -c '^create$' "$EVENTS" || true)" -eq 1 ] || assert_event 'release create was not attempted'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'release create uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'release create started verifier'
}

assert_success_receipt_failure_is_receipt_stage() {
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if FAIL_RECEIPT_ONCE=1 bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq 1 ] || assert_event "receipt-stage exit: $actual"
    assert_receipt receipt failed
    grep -Fx 'notify strixd rules: receipt FAILED' "$EVENTS" >/dev/null || assert_event 'receipt-stage notification'
    grep -F 'notify-body terminal receipt preparation or emission failed after rules-current was published and native-verified.' "$EVENTS" >/dev/null || assert_event 'receipt-stage body'
    ! grep -F 'notify-body generate-rules.sh exited' "$EVENTS" || assert_event 'receipt-stage stale failure body'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 2 ] || assert_event 'receipt-stage upload count'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event 'receipt-stage verifier count'
}

assert_valid_rules_count() {  # assert_valid_rules_count <count>
    local rules="$1"
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    RULES_COUNT="$rules" bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1 || assert_event "valid rules count ${rules} failed"
    assert_receipt verify success "$rules"
    grep -F "${rules} rules" "$EVENTS" >/dev/null || assert_event "valid rules count ${rules} notification"
    assert_success_event_order "valid rules count ${rules}" 1
}

assert_invalid_rules_count_is_build_failure() {  # assert_invalid_rules_count_is_build_failure <count>
    local rules="$1"
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if RULES_COUNT="$rules" bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq 1 ] || assert_event "invalid rules count ${rules} exit: $actual"
    assert_receipt build failed
    grep -F 'ERROR: RULES_COUNT must be a canonical non-negative decimal no greater than 2147483647' "$test_root/log" >/dev/null || assert_event "invalid rules count ${rules} diagnostic"
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event "invalid rules count ${rules} uploaded assets"
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event "invalid rules count ${rules} started verifier"
    assert_notification "invalid-rules-count-${rules}" build failed
}

assert_startup_failure_is_build_failure() {
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if FAIL_MKTEMP=1 bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq 44 ] || assert_event "mktemp startup exit: $actual"
    assert_receipt build failed
    assert_notification startup-mktemp build failed
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'mktemp startup uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'mktemp startup started verifier'
}

assert_repository_path_failure_notifies() {
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if FAIL_HERE=1 bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq 1 ] || assert_event "repository path startup exit: $actual"
    assert_receipt build failed
    assert_notification repository-path build failed
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'repository path uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'repository path started verifier'
}

assert_manifest_preparation_failure_is_build_failure() {
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if FAIL_MANIFEST_DATE=1 bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq 48 ] || assert_event "manifest preparation exit: $actual"
    assert_receipt build failed
    assert_notification manifest-preparation build failed
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'manifest preparation uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'manifest preparation started verifier'
}

assert_post_verify_preparation_is_receipt_stage() {
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if FAIL_POST_VERIFY_AWK=1 bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq 47 ] || assert_event "post-verify preparation exit: $actual"
    assert_receipt receipt failed
    assert_notification post-verify-preparation receipt failed
    grep -F 'notify-body terminal receipt preparation or emission failed after rules-current was published and native-verified.' "$EVENTS" >/dev/null || assert_event 'post-verify preparation body'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 2 ] || assert_event 'post-verify preparation upload count'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event 'post-verify preparation verifier count'
}

run_case() {  # run_case <name> <exit> <stage> <status> <verify-count> <uploads> <build-fail> <publish-fail> <verify-until> <notify-fail>
    local name="$1" expected_exit="$2" stage="$3" status="$4" verify_count="$5" uploads="$6"
    local fail_build="$7" fail_publish="$8" fail_verify="$9" fail_notify="${10}"
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts"
    if FAIL_BUILD="$fail_build" FAIL_PUBLISH="$fail_publish" FAIL_VERIFY_UNTIL="$fail_verify" FAIL_NOTIFY="$fail_notify" \
        bash "$test_root/sandbox/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    [ "$actual" -eq "$expected_exit" ] || {
        cat "$test_root/log" >&2
        assert_event "$name: exit $actual, want $expected_exit"
    }
    assert_receipt "$stage" "$status"
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq "$verify_count" ] || assert_event "$name: verifier count"
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq "$uploads" ] || assert_event "$name: upload count"
    assert_verifier_contract "$name" "$verify_count"
    assert_notification "$name" "$stage" "$status"
    [ "$status" != success ] || assert_success_event_order "$name" "$verify_count"
}

# Positive, retry-boundary, and stage-error receipts. The last row proves the
# documented publisher-only exception: a notification failure cannot mask a
# successful publish or its receipt.
run_case success 0 verify success 1 2 0 0 0 0
run_case verify-retry 0 verify success 3 2 0 0 2 0
run_case build-failure 41 build failed 0 0 1 0 0 0
run_case publish-failure 42 publish failed 0 1 0 1 0 0
grep -F 'notify-body generate-rules.sh exited 42 — rules-current may be partially updated.' "$EVENTS" >/dev/null || assert_event 'publish failure state wording'
run_case verify-failure 1 verify failed 5 2 0 0 5 0
grep -Fx 'notify-body rules-current was published, but native verification failed; clients may encounter an unverified bundle. Inspect and repair the release.' "$EVENTS" >/dev/null || assert_event 'verify failure risk wording'
run_case notify-failure-is-best-effort 0 verify success 1 2 0 0 0 1
assert_receipt_failure_preserves_stage_failure
assert_release_probe_failure_is_publish
assert_release_create_failure_is_publish_uncertain
assert_success_receipt_failure_is_receipt_stage
assert_valid_rules_count 2147483647
for invalid_rules in -1 not-a-number 12oops 12e1 012 2147483648 9223372036854775808; do
    assert_invalid_rules_count_is_build_failure "$invalid_rules"
done
assert_startup_failure_is_build_failure
assert_repository_path_failure_notifies
assert_manifest_preparation_failure_is_build_failure
assert_post_verify_preparation_is_receipt_stage
echo 'PASS: terminal JSON receipts distinguish build/publish/verify; publish order and verifier contract hold'
