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
    if [ "${SIGNAL_VERIFY:-0}" -eq 1 ]; then
        kill -TERM "$(cat "${EVENTS}.signal-target")"
    fi
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
        if [[ "${!#}" == */compiled.yac.manifest.json ]]; then
            cp "${!#}" "${EVENTS}.manifest"
        fi
        if [ "${SIGNAL_PUBLISH:-0}" -eq 1 ]; then
            kill -TERM "$(cat "${EVENTS}.signal-target")"
        fi
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
if [ "${SIGNAL_SUCCESS_RECEIPT:-0}" -eq 1 ] && [[ "$*" == *'--arg status success'* ]]; then
    "$REAL_JQ" "$@"
    kill -TERM "$(cat "${EVENTS}.signal-target")"
    exit 0
fi
if [ "${SIGNAL_FAILURE_RECEIPT:-0}" -eq 1 ] && [[ "$*" == *'--arg status failed'* ]]; then
    "$REAL_JQ" "$@"
    kill -TERM "$(cat "${EVENTS}.signal-target")"
    exit 0
fi
if [ "${FAIL_AND_SIGNAL_SUCCESS_RECEIPT:-0}" -eq 1 ] && [[ "$*" == *'--arg status success'* ]]; then
    kill -TERM "$(cat "${EVENTS}.signal-target")"
    exit 43
fi
exec "$REAL_JQ" "$@"
STUB

cat >"$test_root/tools/discord-notify.py" <<'STUB'
#!/usr/bin/env python3
import os
import signal
import sys

with open(os.environ["EVENTS"], "a", encoding="utf-8") as events:
    events.write(f"notify {sys.argv[2]}\n")
    events.write(f"notify-body {sys.argv[3]}\n")
if os.environ.get("SIGNAL_SUCCESS_NOTIFY") == "1" and sys.argv[2].endswith("published"):
    with open(os.environ["EVENTS"] + ".signal-target", encoding="utf-8") as target:
        os.kill(int(target.read()), signal.SIGTERM)
if os.environ.get("SIGNAL_FAILURE_NOTIFY") == "1" and sys.argv[2].endswith("FAILED"):
    with open(os.environ["EVENTS"] + ".signal-target", encoding="utf-8") as target:
        os.kill(int(target.read()), signal.SIGTERM)
raise SystemExit(int(os.environ.get("FAIL_NOTIFY", "0")))
STUB

cat >"$test_root/bin/sleep" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

# Inject the write failure at the stdout boundary, after emitting real bytes.
# Other printf uses (including stage-specific notices) retain builtin behavior.
cat >"$test_root/partial-write.bash" <<'STUB'
printf() {
    if [ "${1:-}" = '%s\n' ] && [[ "${2:-}" == *'"schema":"mailstrix-rules-nightly-v1"'* ]]; then
        builtin printf 'receipt-write\n' >> "$EVENTS"
        if [ "${_PARTIAL_RECEIPT_WRITTEN:-0}" -eq 0 ]; then
            _PARTIAL_RECEIPT_WRITTEN=1
            builtin printf '%s' '{"schema":'
            if [ "${SIGNAL_PARTIAL_WRITE:-0}" -eq 1 ]; then
                kill -TERM "$BASHPID"
            fi
            return 1
        fi
    fi
    builtin printf "$@"
}
STUB

# DEBUG runs before each top-level command. Arm before the receipt->verify
# assignment, then send TERM at the very next command, after that assignment
# completed. This fixes the scheduler boundary without depending on the guard's
# value or changing the source under test.
cat >"$test_root/receipt-boundary.bash" <<'STUB'
receipt_boundary_signal() {
    if [ "${_BOUNDARY_ARMED:-0}" -eq 1 ] && [ "${_BOUNDARY_SENT:-0}" -eq 0 ]; then
        _BOUNDARY_SENT=1
        builtin printf 'receipt-boundary-signal\n' >> "$EVENTS"
        kill -TERM "$BASHPID"
    fi
    if [ "$1" = NIGHTLY_STAGE=verify ] && [ "${NIGHTLY_STAGE:-}" = receipt ]; then
        _BOUNDARY_ARMED=1
    fi
    return 0
}
trap 'receipt_boundary_signal "$BASH_COMMAND"' DEBUG
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

run_script_with_output() {  # run_script_with_output <stdout> <stderr> <env-assignment>...; assigns caller-local actual
    local stdout="$1" stderr="$2" runner_pid
    shift 2
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts" "${EVENTS}.signal-target" "${EVENTS}.manifest"
    (
        if [ "$stdout" = "$stderr" ]; then
            exec >"$stdout" 2>&1
        else
            exec >"$stdout" 2>"$stderr"
        fi
        printf '%s\n' "$BASHPID" >"${EVENTS}.signal-target"
        exec env "$@" bash "$test_root/sandbox/project/docker/generate-rules.sh"
    ) &
    runner_pid=$!
    if wait "$runner_pid"; then
        actual=0
    else
        actual=$?
    fi
    rm -f "${EVENTS}.signal-target"
}

run_script() {  # run_script <env-assignment>...; assigns caller-local actual
    run_script_with_output "$test_root/log" "$test_root/log" "$@"
}

run_script_stdout_full() {  # assigns caller-local actual
    run_script_with_output /dev/full "$test_root/log"
}

assert_receipt_failure_preserves_stage_failure() {
    local actual
    run_script FAIL_BUILD=1 FAIL_RECEIPT=1
    [ "$actual" -eq 41 ] || assert_event "receipt failure masked build exit: $actual"
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 0 ] || assert_event 'failed serializer emitted a receipt'
    grep -Fx 'notify strixd rules: build FAILED' "$EVENTS" >/dev/null || assert_event 'receipt failure lost build notification'
    grep -F 'ERROR: failed to emit nightly receipt' "$test_root/log" >/dev/null || assert_event 'receipt failure not diagnosed'
}

assert_release_probe_failure_is_publish() {
    local actual
    run_script RELEASE_HTTP=401
    [ "$actual" -eq 1 ] || assert_event "release probe exit: $actual"
    assert_receipt publish failed
    grep -Fx 'notify strixd rules: publish FAILED' "$EVENTS" >/dev/null || assert_event 'release probe stage notification'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'release probe uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'release probe started verifier'
}

assert_release_create_failure_is_publish_uncertain() {
    local actual
    run_script FAIL_CREATE=1
    [ "$actual" -eq 49 ] || assert_event "release create exit: $actual"
    assert_receipt publish failed
    assert_notification release-create publish failed
    grep -F 'notify-body generate-rules.sh exited 49 — rules-current may be partially updated.' "$EVENTS" >/dev/null || assert_event 'release create state wording'
    [ "$(grep -c '^create$' "$EVENTS" || true)" -eq 1 ] || assert_event 'release create was not attempted'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'release create uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'release create started verifier'
}

assert_success_receipt_failure_is_receipt_stage() {
    local actual
    run_script FAIL_RECEIPT_ONCE=1
    [ "$actual" -eq 1 ] || assert_event "receipt-stage exit: $actual"
    assert_receipt receipt failed
    grep -Fx 'notify strixd rules: receipt FAILED' "$EVENTS" >/dev/null || assert_event 'receipt-stage notification'
    grep -F 'notify-body terminal receipt preparation or emission failed after rules-current was published and native-verified.' "$EVENTS" >/dev/null || assert_event 'receipt-stage body'
    ! grep -F 'notify-body generate-rules.sh exited' "$EVENTS" || assert_event 'receipt-stage stale failure body'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 2 ] || assert_event 'receipt-stage upload count'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event 'receipt-stage verifier count'
}

assert_stdout_failure_is_receipt_stage() {
    local actual
    run_script_stdout_full
    [ "$actual" -eq 1 ] || assert_event "stdout-full exit: $actual"
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 0 ] || assert_event 'stdout-full emitted a receipt on stderr'
    assert_notification stdout-full receipt failed
    grep -F 'notify-body terminal receipt preparation or emission failed after rules-current was published and native-verified.' "$EVENTS" >/dev/null || assert_event 'stdout-full receipt-stage body'
    grep -F 'ERROR: failed to emit nightly receipt' "$test_root/log" >/dev/null || assert_event 'stdout-full fallback failure not diagnosed'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 2 ] || assert_event 'stdout-full upload count'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event 'stdout-full verifier count'
}

assert_partial_receipt_write_is_not_retried() {  # <build-failure> <signal> <serializer-failure>
    local fail_build="$1" signal="$2" serializer_failure="$3" actual expected=1 stage=receipt
    if [ "$fail_build" -eq 1 ]; then expected=41; stage=build; fi
    run_script_with_output "$test_root/stdout" "$test_root/log" \
        BASH_ENV="$test_root/partial-write.bash" FAIL_BUILD="$fail_build" \
        SIGNAL_PARTIAL_WRITE="$signal" FAIL_RECEIPT_ONCE="$serializer_failure"
    [ "$actual" -eq "$expected" ] || assert_event "partial-write exit: $actual, want $expected"
    [ "$(grep -c '^receipt-write$' "$EVENTS" || true)" -eq 1 ] || assert_event 'partial-write retried stdout emission'
    [ "$(cat "$test_root/stdout")" = '{"schema":' ] || assert_event 'partial-write appended bytes after failed emission'
    [ "$(wc -c < "$test_root/stdout")" -eq 10 ] || assert_event 'partial-write prefix byte count changed'
    assert_notification partial-write "$stage" failed
    grep -F 'ERROR: failed to emit nightly receipt' "$test_root/log" >/dev/null || assert_event 'partial-write not diagnosed'
    if [ "$stage" = receipt ]; then
        grep -F 'notify-body terminal receipt preparation or emission failed after rules-current was published and native-verified.' "$EVENTS" >/dev/null || assert_event 'partial-write receipt-stage body'
    else
        grep -F 'notify-body generate-rules.sh exited 41 — rules-current NOT updated.' "$EVENTS" >/dev/null || assert_event 'partial-write lost original build error'
    fi
}

assert_valid_rules_count() {  # assert_valid_rules_count <input> [normalized-count]
    local rules="$1" expected="${2:-$1}" actual
    run_script RULES_COUNT="$rules"
    [ "$actual" -eq 0 ] || assert_event "valid rules count ${rules} failed"
    assert_receipt verify success "$expected"
    jq -e --argjson expected "$expected" '.rules == $expected' "${EVENTS}.manifest" >/dev/null || assert_event "valid rules count ${rules} manifest"
    if [ "$expected" = 0 ]; then
        ! grep -F '0 rules' "$EVENTS" >/dev/null || assert_event 'zero rules count must remain omitted from notification'
    else
        grep -F ", ${expected} rules," "$EVENTS" >/dev/null || assert_event "valid rules count ${rules} notification"
    fi
    assert_success_event_order "valid rules count ${rules}" 1
}

assert_invalid_rules_count_is_build_failure() {  # assert_invalid_rules_count_is_build_failure <count>
    local rules="$1" actual
    run_script RULES_COUNT="$rules"
    [ "$actual" -eq 1 ] || assert_event "invalid rules count ${rules} exit: $actual"
    assert_receipt build failed
    grep -F 'ERROR: RULES_COUNT must be a canonical non-negative decimal no greater than 2147483647' "$test_root/log" >/dev/null || assert_event "invalid rules count ${rules} diagnostic"
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event "invalid rules count ${rules} uploaded assets"
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event "invalid rules count ${rules} started verifier"
    assert_notification "invalid-rules-count-${rules}" build failed
}

assert_startup_failure_is_build_failure() {
    local actual
    run_script FAIL_MKTEMP=1
    [ "$actual" -eq 44 ] || assert_event "mktemp startup exit: $actual"
    assert_receipt build failed
    assert_notification startup-mktemp build failed
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'mktemp startup uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'mktemp startup started verifier'
}

assert_repository_path_failure_notifies() {
    local actual
    run_script FAIL_HERE=1
    [ "$actual" -eq 1 ] || assert_event "repository path startup exit: $actual"
    assert_receipt build failed
    assert_notification repository-path build failed
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'repository path uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'repository path started verifier'
}

assert_manifest_preparation_failure_is_build_failure() {
    local actual
    run_script FAIL_MANIFEST_DATE=1
    [ "$actual" -eq 48 ] || assert_event "manifest preparation exit: $actual"
    assert_receipt build failed
    assert_notification manifest-preparation build failed
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'manifest preparation uploaded assets'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'manifest preparation started verifier'
}

assert_post_verify_preparation_is_receipt_stage() {
    local actual
    run_script FAIL_POST_VERIFY_AWK=1
    [ "$actual" -eq 47 ] || assert_event "post-verify preparation exit: $actual"
    assert_receipt receipt failed
    assert_notification post-verify-preparation receipt failed
    grep -F 'notify-body terminal receipt preparation or emission failed after rules-current was published and native-verified.' "$EVENTS" >/dev/null || assert_event 'post-verify preparation body'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 2 ] || assert_event 'post-verify preparation upload count'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event 'post-verify preparation verifier count'
}

assert_publish_signal_reports_failure() {
    local actual
    run_script SIGNAL_PUBLISH=1
    [ "$actual" -eq 143 ] || assert_event "publish signal exit: $actual"
    assert_receipt publish failed
    assert_notification publish-signal publish failed
    grep -F 'notify-body generate-rules.sh exited 143 — rules-current may be partially updated.' "$EVENTS" >/dev/null || assert_event 'publish signal state wording'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 1 ] || assert_event 'publish signal upload count'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event 'publish signal started verifier'
}

assert_success_receipt_signal_is_receipt_failure() {
    local actual
    run_script SIGNAL_SUCCESS_RECEIPT=1
    [ "$actual" -eq 143 ] || assert_event "success receipt signal exit: $actual"
    assert_receipt receipt failed
    assert_notification success-receipt-signal receipt failed
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 1 ] || assert_event 'success receipt signal emitted conflicting receipts'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 2 ] || assert_event 'success receipt signal upload count'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event 'success receipt signal verifier count'
}

assert_receipt_stage_transition_defers_signal() {
    local actual
    run_script BASH_ENV="$test_root/receipt-boundary.bash"
    [ "$(grep -c '^receipt-boundary-signal$' "$EVENTS" || true)" -eq 1 ] || assert_event 'receipt boundary signal did not fire exactly once'
    [ "$actual" -eq 143 ] || assert_event "receipt boundary signal exit: $actual"
    assert_receipt receipt failed
    assert_notification receipt-boundary-signal receipt failed
    grep -F 'notify-body terminal receipt preparation or emission failed after rules-current was published and native-verified.' "$EVENTS" >/dev/null || assert_event 'receipt boundary reported completed verification as interrupted'
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 1 ] || assert_event 'receipt boundary signal duplicated terminal receipt'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 2 ] || assert_event 'receipt boundary signal upload count'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event 'receipt boundary signal verifier count'
}

assert_failure_receipt_signal_finishes_reporting() {
    local actual
    run_script FAIL_BUILD=1 SIGNAL_FAILURE_RECEIPT=1
    [ "$actual" -eq 41 ] || assert_event "failure receipt signal exit: $actual"
    assert_receipt build failed
    assert_notification failure-receipt-signal build failed
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 1 ] || assert_event 'failure receipt signal lost or duplicated terminal receipt'
}

assert_signaled_success_serializer_failure_falls_back() {
    local actual
    run_script FAIL_AND_SIGNAL_SUCCESS_RECEIPT=1
    [ "$actual" -eq 1 ] || assert_event "signaled serializer failure exit: $actual"
    assert_receipt receipt failed
    assert_notification signaled-serializer-failure receipt failed
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 1 ] || assert_event 'signaled serializer failure lost or duplicated fallback receipt'
}

assert_verify_signal_reports_interruption() {
    local actual
    run_script SIGNAL_VERIFY=1
    [ "$actual" -eq 143 ] || assert_event "verify signal exit: $actual"
    assert_receipt verify failed
    assert_notification verify-signal verify failed
    grep -Fx 'notify-body rules-current v1 was published, but native verification was interrupted; clients may encounter an unverified bundle. Inspect and repair the release. Check /opt/myguard/packages/log/yarad-generate-rules.log' "$EVENTS" >/dev/null || assert_event 'verify signal interruption wording'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 2 ] || assert_event 'verify signal upload count'
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event 'verify signal verifier count'
}

assert_success_notification_signal_stays_successful() {
    local actual
    run_script SIGNAL_SUCCESS_NOTIFY=1
    [ "$actual" -eq 143 ] || assert_event "success notification signal exit: $actual"
    assert_receipt verify success
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 1 ] || assert_event 'success notification signal changed terminal receipt'
    [ "$(grep -c 'FAILED' "$EVENTS" || true)" -eq 0 ] || assert_event 'success notification signal emitted contradictory failure alert'
    grep -Fx 'notify strixd rules: rules-current v1 published' "$EVENTS" >/dev/null || assert_event 'success notification was not attempted'
}

assert_failure_notification_signal_preserves_stage_exit() {
    local actual
    run_script FAIL_BUILD=1 SIGNAL_FAILURE_NOTIFY=1
    [ "$actual" -eq 41 ] || assert_event "failure notification signal exit: $actual"
    assert_receipt build failed
    assert_notification failure-notification-signal build failed
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 1 ] || assert_event 'failure notification signal changed terminal receipt'
}

assert_broken_receipt_notification_signal_preserves_stage_exit() {
    local actual
    run_script FAIL_BUILD=1 FAIL_RECEIPT=1 SIGNAL_FAILURE_NOTIFY=1
    [ "$actual" -eq 41 ] || assert_event "broken receipt notification signal exit: $actual"
    [ "$(grep -c 'mailstrix-rules-nightly-v1' "$test_root/log" || true)" -eq 0 ] || assert_event 'broken receipt notification signal emitted a receipt'
    assert_notification broken-receipt-notification-signal build failed
    grep -F 'ERROR: failed to emit nightly receipt' "$test_root/log" >/dev/null || assert_event 'broken receipt notification signal lost serializer diagnostic'
}

run_case() {  # run_case <name> <exit> <stage> <status> <verify-count> <uploads> <build-fail> <publish-fail> <verify-until> <notify-fail>
    local name="$1" expected_exit="$2" stage="$3" status="$4" verify_count="$5" uploads="$6"
    local fail_build="$7" fail_publish="$8" fail_verify="$9" fail_notify="${10}" actual
    run_script FAIL_BUILD="$fail_build" FAIL_PUBLISH="$fail_publish" FAIL_VERIFY_UNTIL="$fail_verify" FAIL_NOTIFY="$fail_notify"
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
grep -Fx 'notify-body rules-current v1 was published, but native verification failed; clients may encounter an unverified bundle. Inspect and repair the release. Check /opt/myguard/packages/log/yarad-generate-rules.log' "$EVENTS" >/dev/null || assert_event 'verify failure risk wording'
run_case notify-failure-is-best-effort 0 verify success 1 2 0 0 0 1
assert_receipt_failure_preserves_stage_failure
assert_release_probe_failure_is_publish
assert_release_create_failure_is_publish_uncertain
assert_success_receipt_failure_is_receipt_stage
assert_stdout_failure_is_receipt_stage
assert_partial_receipt_write_is_not_retried 0 0 0
assert_partial_receipt_write_is_not_retried 1 0 0
assert_partial_receipt_write_is_not_retried 0 1 0
assert_partial_receipt_write_is_not_retried 1 1 0
assert_partial_receipt_write_is_not_retried 0 0 1
assert_valid_rules_count 2147483647
assert_valid_rules_count ' 42 ' 42
assert_valid_rules_count $'\t\r\n\v\f0\f\v\n\r\t' 0
assert_valid_rules_count $' \t2147483647\r\n' 2147483647
for invalid_rules in -1 +1 not-a-number 12oops 12e1 012 2147483648 9223372036854775808 ' ' $'\t\r\n\v\f' '4 2' $'4\t2' $'4\n2' ' 2147483648 ' ' 012 ' ' -1 '; do
    assert_invalid_rules_count_is_build_failure "$invalid_rules"
done
assert_startup_failure_is_build_failure
assert_repository_path_failure_notifies
assert_manifest_preparation_failure_is_build_failure
assert_post_verify_preparation_is_receipt_stage
assert_publish_signal_reports_failure
assert_success_receipt_signal_is_receipt_failure
assert_receipt_stage_transition_defers_signal
assert_failure_receipt_signal_finishes_reporting
assert_signaled_success_serializer_failure_falls_back
assert_verify_signal_reports_interruption
assert_success_notification_signal_stays_successful
assert_failure_notification_signal_preserves_stage_exit
assert_broken_receipt_notification_signal_preserves_stage_exit
echo 'PASS: terminal JSON receipts distinguish build/publish/verify; publish order and verifier contract hold'
