#!/usr/bin/env bash
# Exercise terminal receipts, stage-specific failure notices, ordered publishing,
# and verifier error propagation with all external commands stubbed.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
for bin in awk date dd dirname jq mktemp python3 tr wc; do
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
cp "$here/generate-rules.sh" "$here/pack-marker-tree.py" "$test_root/sandbox/project/docker/"
# HEAD's libyara pin, read by the marker skew guard; cases rewrite it.
printf 'ARG YARA_VERSION=4.5.2\n' > "$test_root/sandbox/project/docker/Dockerfile"
export EVENTS="$test_root/events"
export PATH="$test_root/bin:$PATH"
export GH_TOKEN=fixture-not-a-credential
# Throwaway non-credential: the `go` stub only checks that the publisher passes
# the key through the ENVIRONMENT and never on a command line.
export MAILSTRIX_RULES_SIGNING_KEY=fixture-not-a-signing-key
# The build-env fallback validates PEM armour, so its fixture must be PEM-SHAPED.
# It is still an obvious non-credential: no key material, same sentinel body as
# the environment fixture above, which the leak oracle greps for.
FIXTURE_KEY_BODY='fixture-not-a-signing-key'
FIXTURE_PEM="-----BEGIN PRIVATE KEY-----
${FIXTURE_KEY_BODY}
-----END PRIVATE KEY-----"
FIXTURE_PEM_B64="$(printf '%s' "$FIXTURE_PEM" | base64 -w0)"

cat >"$test_root/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = run ]; then
    if [[ " $* " == *' sha256:markerverifier -h '* ]]; then
        # Flag probe of the release strixd. VERIFIER_NO_REQUIRE_MARKER=1 models a
        # marker-capable release that predates the -require-marker gate.
        printf 'probe %s\n' "$*" >> "$EVENTS"
        printf 'Usage of fetch-rules:\n  -verify-only\n'
        [ "${VERIFIER_NO_REQUIRE_MARKER:-0}" -eq 1 ] || printf '  -require-marker\n'
        exit 2
    fi
    if [[ " $* " == *' check-rules '* ]]; then
        printf 'count %s\n' "$*" >> "$EVENTS"
        [ "${FAIL_COUNT:-0}" -eq 0 ] || exit 51
        printf '%s\n' "${COUNT_REPORT-check-rules: OK — 1 rules loaded (fingerprint fixture)}"
        exit 0
    fi
    if [[ " $* " == *' -allow-http '* ]]; then
        # Pre-upload verification of the staged candidate: really fetch what the
        # publisher serves, so the staged files and the loopback server are proven.
        url="$(sed -n 's/.* -url \([^ ]*\) .*/\1/p' <<<" $* ")"
        printf 'stage-verify %s\n' "$*" >> "$EVENTS"
        python3 - "$url" "$EVENTS" <<'PYV'
import hashlib
import json
import sys
import urllib.request

url, events = sys.argv[1:]
get = lambda name: urllib.request.urlopen(f"{url}/{name}", timeout=10).read()
manifest = json.loads(get("compiled.yac.manifest.json"))
get("compiled.yac.manifest.json.sig")
get("compiled.yac")
tree = get(manifest["marker"]["asset"])
ok = hashlib.sha256(tree).hexdigest() == manifest["marker"]["sha256"] and len(tree) == manifest["marker"]["size"]
open(events, "a").write(f"stage-fetch {'ok' if ok else 'MISMATCH'}\n")
sys.exit(0 if ok else 1)
PYV
        [ "${FAIL_MARKER_VERIFY:-0}" -eq 0 ] || exit 52
        exit 0
    fi
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
dockerfile=""; target=""; prev=""
for arg in "$@"; do
    case "$prev" in
        -f) dockerfile="$(basename "$arg")" ;;
        --target) target="$arg" ;;
    esac
    prev="$arg"
done
printf 'dockerfile %s %s\n' "$dockerfile" "$target" >> "$EVENTS"
if [ "$dockerfile" = Dockerfile.release ]; then
    # Marker toolchain build. MARKER_BUILD=fail models a release whose yarac /
    # libyara.a are not linked into its strixd (release-marker-toolchain.sh exits
    # non-zero); legacy models a release without marker support (no tree).
    [ "${MARKER_BUILD:-ok}" != fail ] || exit 61
    [ "${FAIL_BUILD:-0}" -eq 0 ] || exit 41
    case "$target" in
        rules-verifier)
            while [ "$#" -gt 0 ]; do
                [ "$1" != --iidfile ] || printf 'sha256:markerverifier\n' > "$2"
                shift
            done
            exit 0 ;;
        rules-export)
            while [ "$#" -gt 0 ]; do
                if [ "$1" = --output ]; then
                    dir="${2#type=local,dest=}"
                    dd if=/dev/zero of="$dir/compiled.yac" bs=1024 count=1536 2>/dev/null
                    printf '%s\n' "${RELEASE_LIBYARA-4.5.2}" > "$dir/libyara.version"
                    printf 'local' > "$dir/local.yac"
                    printf '{"fixture":"sources"}\n' > "$dir/sources.json"
                    if [ "${MARKER_BUILD:-ok}" != legacy ]; then
                        mkdir -p "$dir/compiler-inputs/main/objects" "$dir/marker-artifact/abi"
                        printf 'index' > "$dir/compiler-inputs/index.json"
                        printf 'graph' > "$dir/compiler-inputs/main/objects/aa"
                        printf 'marker' > "$dir/marker-artifact/binding.json"
                        printf 'fixture-yarac' > "$dir/marker-artifact/abi/yarac"
                        printf 'fixture-libyara' > "$dir/marker-artifact/abi/libyara.a"
                        [ -z "${MARKER_SYMLINK:-}" ] || ln -s /etc/passwd "$dir/compiler-inputs/escape"
                    fi
                    shift
                fi
                shift
            done
            exit 0 ;;
    esac
fi
[ "${FAIL_BUILD:-0}" -eq 0 ] || exit 41
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)
            dir="${2#type=local,dest=}"
            # A discriminating size: 1572864 B renders 1.5 MiB under b/1048576
            # but 1.6 MiB under b/1000000, so the body oracle pins the divisor.
            # Fail loudly here rather than letting a short write surface later as
            # a confusing size/checksum mismatch.
            dd if=/dev/zero of="$dir/compiled.yac" bs=1024 count=1536 2>/dev/null
            [ "$(wc -c < "$dir/compiled.yac" | tr -d '[:space:]')" = 1572864 ] ||
                { printf 'FAIL: fixture compiled.yac not 1572864 bytes\n' >&2; exit 2; }
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
    repos/*/releases/latest)
        printf '%s\n' "${LATEST_TAG-}"
        ;;
    create)
        printf 'create\n' >> "$EVENTS"
        [ "${FAIL_CREATE:-0}" -eq 0 ] || exit 49
        ;;
    upload)
        printf 'upload %s\n' "$(basename "${!#}")" >> "$EVENTS"
        if [[ "${!#}" == */compiled.yac.manifest.json ]]; then
            cp "${!#}" "${EVENTS}.manifest"
        fi
        if [[ "${!#}" == */marker-tree.tar.gz ]]; then
            cp "${!#}" "${EVENTS}.tree"
        fi
        if [ "${SIGNAL_PUBLISH:-0}" -eq 1 ]; then
            kill -TERM "$(cat "${EVENTS}.signal-target")"
        fi
        [ "${FAIL_PUBLISH:-0}" -eq 0 ] || exit 42
        # FAIL_PUBLISH_AT=<n> fails only the nth upload; the failed upload does
        # not reach the simulated remote (${EVENTS}.remote), a successful one does.
        n=$(( $(cat "${EVENTS}.upload-n" 2>/dev/null || echo 0) + 1 ))
        printf '%s\n' "$n" >"${EVENTS}.upload-n"
        [ "${FAIL_PUBLISH_AT:-0}" -ne "$n" ] || exit 42
        if [ -d "${EVENTS}.remote" ]; then
            cp "${!#}" "${EVENTS}.remote/$(basename "${!#}")"
        fi
        ;;
esac
STUB

# The Go compiler and its built `rulessign` helper are stubbed: this harness
# covers the publisher's orchestration (preflight, signature produced, uploaded,
# and ordered before the manifest).
# The signing and verification crypto itself is covered by the Go unit tests in
# cmd/rulessign, internal/mailstrix, and ci/generate_rules_cron_signer_test.sh.
cat >"$test_root/bin/go" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'go-build %s\n' "$*" >> "$EVENTS"
out=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift ;;
    esac
    shift
done
[ -n "$out" ] || { printf 'go: build -o missing\n' >&2; exit 2; }
cat >"$out" <<'SIGNER'
#!/usr/bin/env bash
set -euo pipefail
printf 'rulessign-bin %s\n' "$0" >> "$EVENTS"
printf 'rulessign %s\n' "$*" >> "$EVENTS"
[ -n "${MAILSTRIX_RULES_SIGNING_KEY:-}" ] || { printf 'rulessign: key missing from the environment\n' >&2; exit 2; }
# Record the SHAPE of the key the signer received — armour and line count — so a
# test can prove the build-env fallback delivered a decoded multi-line PEM rather
# than the raw base64 line. Shape only: the value itself is never emitted, which
# is what the leak oracle depends on.
case "$MAILSTRIX_RULES_SIGNING_KEY" in
    *"-----BEGIN "*"-----END "*) key_armour=pem ;;
    *) key_armour=raw ;;
esac
printf 'go-key %s %s\n' "$key_armour" \
    "$(printf '%s\n' "$MAILSTRIX_RULES_SIGNING_KEY" | wc -l | tr -d '[:space:]')" >> "$EVENTS"
case " $* " in
    *" -require-trusted "*) ;;
    *) printf 'rulessign: publisher must pass -require-trusted\n' >&2; exit 2 ;;
esac
[ "${FAIL_SIGN:-0}" -eq 0 ] || exit 3
out=""
manifest=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -manifest) manifest="$2"; shift ;;
        -out) out="$2"; shift ;;
    esac
    shift
done
[ "${FAIL_FINAL_SIGN:-0}" -eq 0 ] || [[ "$manifest" != */compiled.yac.manifest.json ]] || exit 3
[ -n "$out" ] || { printf 'rulessign: -out missing\n' >&2; exit 2; }
if [[ "$manifest" == */compiled.yac.manifest.json ]]; then
    printf 'signed-sha %s\n' "$(sha256sum "$manifest" | cut -d ' ' -f1)" >> "$EVENTS"
fi
printf 'ZmFrZS1zaWduYXR1cmUtZml4dHVyZQ==\n' > "$out"
SIGNER
chmod +x "$out"
STUB

# /etc/myguard-build-env is root-owned mode 600, so the publisher reads it with
# passwordless `sudo -n cat`. The stub serves the file named by
# BUILD_ENV_FIXTURE so each case controls the content, records that it was
# consulted at all (the precedence oracle asserts ZERO reads when the key comes
# from the environment), and fails exactly like the real file when the fixture is
# absent or unreadable. It never echoes the content anywhere but stdout.
cat >"$test_root/bin/sudo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'sudo-read %s\n' "$*" >> "$EVENTS"
[ "${1:-}" = -n ] || { printf 'sudo: a password is required\n' >&2; exit 1; }
[ "${2:-}" = cat ] && [ "${3:-}" = /etc/myguard-build-env ] || {
    printf 'sudo: unexpected command: %s\n' "$*" >&2
    exit 1
}
[ -n "${BUILD_ENV_FIXTURE:-}" ] && [ -r "$BUILD_ENV_FIXTURE" ] || {
    printf 'cat: /etc/myguard-build-env: Permission denied\n' >&2
    exit 1
}
exec cat "$BUILD_ENV_FIXTURE"
STUB

cat >"$test_root/bin/curl" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null
printf 'curl %s\n' "$*" >> "$EVENTS"
if [ "${CURL_TIMEOUT:-0}" -eq 1 ]; then
    # Model a hung API socket: curl -s -w prints 000 and exits 28, but only a
    # bounded call ever gets there; an unbounded one would hang forever.
    case " $* " in
        *' --max-time '*) printf '000'; exit 28 ;;
        *) sleep 30 ;;
    esac
fi
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
import re
import signal
import sys

body = sys.argv[3]
# Test-only fault injection: fabricate a count in the emitted body so a
# count-omission oracle can be shown to REJECT it. Production is untouched.
if os.environ.get("MAILSTRIX_TEST_INJECT_RULES_COUNT"):
    # Insert in the production slot (before the size field) without depending on
    # the rendered size value, so the count oracle and the size oracle stay
    # independent of each other.
    injected = os.environ["MAILSTRIX_TEST_INJECT_RULES_COUNT"]
    body = re.sub(r"(\d+\.\d+ MiB)", injected + r" rules, \1", body, count=1)
with open(os.environ["EVENTS"], "a", encoding="utf-8") as events:
    events.write(f"notify {sys.argv[2]}\n")
    events.write(f"notify-body {body}\n")
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
    python3 - "$test_root/log" "$1" "$2" "${3:-1}" <<'PY'
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
    expected = {"version": 1, "libyara": "4.5.2", "rules": int(expected_rules), "size": 1572864, "loadable": True}
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
    # The detached signature must land BEFORE the manifest it covers: during the
    # rolling replacement window a client must never fetch a new manifest paired
    # with the previous signature, which it would correctly refuse.
    [ "${lifecycle[1]:-}" = 'upload compiled.yac.manifest.json.sig' ] || assert_event "$name: manifest signature was not uploaded before the manifest"
    [ "${lifecycle[2]:-}" = 'upload compiled.yac.manifest.json' ] || assert_event "$name: manifest was not uploaded after its signature"
    for ((index = 0; index < verify_count; index++)); do
        [[ "${lifecycle[index + 3]:-}" == verify\ * ]] || assert_event "$name: verifier ran before every upload"
    done
    [ "${lifecycle[verify_count + 3]:-}" = 'notify strixd rules: rules-current v1 published' ] || assert_event "$name: success notification did not follow verification"
    [ "${#lifecycle[@]}" -eq "$((verify_count + 4))" ] || assert_event "$name: unexpected lifecycle event count"
}

run_script_with_output() {  # run_script_with_output <stdout> <stderr> <env-assignment>...; assigns caller-local actual
    local stdout="$1" stderr="$2" runner_pid
    shift 2
    : >"$EVENTS"
    rm -f "${EVENTS}.attempts" "${EVENTS}.receipt-attempts" "${EVENTS}.signal-target" "${EVENTS}.manifest" "${EVENTS}.upload-n" "${EVENTS}.tree"
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

assert_release_probe_is_time_bounded() {
    local actual
    run_script RELEASE_HTTP=404
    grep -E '^curl .*--connect-timeout [0-9]+ ' "$EVENTS" >/dev/null || assert_event 'release probe has no --connect-timeout'
    grep -E '^curl .*--max-time [0-9]+ ' "$EVENTS" >/dev/null || assert_event 'release probe has no --max-time'
    run_script CURL_TIMEOUT=1
    [ "$actual" -eq 1 ] || assert_event "release probe timeout exit: $actual"
    assert_receipt publish failed
    grep -F 'cannot determine whether release' "$test_root/log" >/dev/null || assert_event 'release probe timeout diagnostic'
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event 'release probe timeout uploaded assets'
    [ "$(grep -c '^create$' "$EVENTS" || true)" -eq 0 ] || assert_event 'release probe timeout created a release'
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
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 3 ] || assert_event 'receipt-stage upload count'
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
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 3 ] || assert_event 'stdout-full upload count'
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

expected_success_body() {  # expected_success_body <normalized-count>; prints the exact #builds body
    local rules="$1" rules_line=""
    [ "$rules" = 0 ] || rules_line=", ${rules} rules"
    local bt='`'
    printf 'Fresh compiled YARA bundle published to %s%s%s (v0→v1%s, 1.5 MiB, libyara 4.5.2). strixd %s%s%s clients update on next check.' \
        "$bt" rules-current "$bt" "$rules_line" "$bt" --fetch-rules "$bt"
}

# The success body is matched EXACTLY, not by absence of one literal. A
# substring oracle (`! grep 0 rules`) accepts a fabricated nonzero count, which
# is precisely the CI-04-ZERO-NOTIFY escape this asserts against: any inserted,
# rescaled or otherwise wrong count changes the body and fails here.
#
# The predicate is separate from the asserting wrapper so a negative control can
# query the oracle without assert_event's `exit` tearing down the whole suite.
success_notification_body_matches() {  # <normalized-count>
    [ "$(grep -c '^notify-body ' "$EVENTS" || true)" -eq 1 ] || return 1
    grep -Fx "notify-body $(expected_success_body "$1")" "$EVENTS" >/dev/null
}

assert_success_notification_body() {  # assert_success_notification_body <case> <normalized-count>
    local name="$1" expected="$2"
    [ "$(grep -c '^notify-body ' "$EVENTS" || true)" -eq 1 ] || assert_event "$name: notification body count"
    success_notification_body_matches "$expected" || assert_event "$name: success notification body changed"
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
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 3 ] || assert_event 'post-verify preparation upload count'
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
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 3 ] || assert_event 'success receipt signal upload count'
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
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 3 ] || assert_event 'receipt boundary signal upload count'
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
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 3 ] || assert_event 'verify signal upload count'
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
run_case success 0 verify success 1 3 0 0 0 0
run_case verify-retry 0 verify success 3 3 0 0 2 0
run_case build-failure 41 build failed 0 0 1 0 0 0
run_case publish-failure 42 publish failed 0 1 0 1 0 0
grep -F 'notify-body generate-rules.sh exited 42 — rules-current may be partially updated.' "$EVENTS" >/dev/null || assert_event 'publish failure state wording'
run_case verify-failure 1 verify failed 5 3 0 0 5 0
grep -Fx 'notify-body rules-current v1 was published, but native verification failed; clients may encounter an unverified bundle. Inspect and repair the release. Check /opt/myguard/packages/log/yarad-generate-rules.log' "$EVENTS" >/dev/null || assert_event 'verify failure risk wording'
run_case notify-failure-is-best-effort 0 verify success 1 3 0 0 0 1
assert_receipt_failure_preserves_stage_failure
assert_release_probe_failure_is_publish
assert_release_probe_is_time_bounded
assert_release_create_failure_is_publish_uncertain
assert_success_receipt_failure_is_receipt_stage
assert_stdout_failure_is_receipt_stage
assert_partial_receipt_write_is_not_retried 0 0 0
assert_partial_receipt_write_is_not_retried 1 0 0
assert_partial_receipt_write_is_not_retried 0 1 0
assert_partial_receipt_write_is_not_retried 1 1 0
assert_partial_receipt_write_is_not_retried 0 0 1
# Negative control for CI-04-ZERO-NOTIFY: a zero count is rejected during the
# count check, not later during oracle matching, so the verifier count check
# must die before publication is attempted. Verify that fabricated "42 rules"
# would be rejected by the exact-body oracle on a valid (non-zero) count.
assert_fabricated_count_is_rejected() {
    local actual
    # Explicit export/unset instead of the assignment-prefix form: that form's
    # scoping around a function call differs across bash versions and POSIX mode.
    export MAILSTRIX_TEST_INJECT_RULES_COUNT=42
    run_script COUNT_REPORT="check-rules: OK — 1 rules loaded (fingerprint fixture)"
    unset MAILSTRIX_TEST_INJECT_RULES_COUNT
    [ "$actual" -eq 0 ] || assert_event 'fabricated-count fixture run failed'
    grep -Eq 'notify-body .*42 rules' "$EVENTS" || assert_event 'fabricated-count fixture did not inject a count'
    # The oracle should reject a body with conflicting counts (1 rules, 42 rules).
    if success_notification_body_matches 1; then
        assert_event 'fabricated count body was accepted with conflicting counts'
    fi
    # Verify that the oracle rejects a body that tries to claim 42 rules.
    ! success_notification_body_matches 42 || assert_event 'fabricated-count fixture oracle accepted injected count'
}

# shellcheck source=ci/generate_rules_count_test.sh
source "$here/../ci/generate_rules_count_test.sh"
assert_fabricated_count_is_rejected
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
# The manifest signature is what makes a bundle installable: strixd refuses an
# unsigned remote manifest. So an unset key or a failed signing run must stop
# the run BEFORE any asset is published, rather than publish a bundle no client
# would accept.
assert_unsigned_publication_is_refused() {
    local name="$1" actual
    shift
    run_script "$@"
    [ "$actual" -eq 1 ] || assert_event "${name}: exit ${actual}, want 1"
    assert_receipt build failed
    [ "$(grep -Ec '^(create$|upload |verify )' "$EVENTS" || true)" -eq 0 ] \
        || assert_event "${name}: an unsigned run reached publication"
}

assert_unsigned_publication_is_refused missing-signing-key MAILSTRIX_RULES_SIGNING_KEY=
grep -F 'MAILSTRIX_RULES_SIGNING_KEY is not set' "$test_root/log" >/dev/null \
    || assert_event 'missing signing key was not diagnosed'

assert_unsigned_publication_is_refused signing-failure FAIL_SIGN=1
grep -F 'signing-key preflight failed' "$test_root/log" >/dev/null \
    || assert_event 'signing preflight failure was not diagnosed'

# The preflight can succeed and the exact final-manifest signing operation can
# still fail. That later failure remains build-stage and must precede every
# release mutation, upload, and remote verifier invocation.
assert_unsigned_publication_is_refused final-signing-failure FAIL_FINAL_SIGN=1
grep -F 'signing the manifest failed; refusing to publish an unsigned manifest' "$test_root/log" >/dev/null \
    || assert_event 'final manifest signing failure was not diagnosed'
[ "$(grep -c '^rulessign ' "$EVENTS")" -eq 2 ] \
    || assert_event 'final signing failure did not follow a successful preflight'
grep -E '^rulessign -require-trusted -manifest .*/compiled\.yac\.manifest\.json -out .*/compiled\.yac\.manifest\.json\.sig$' "$EVENTS" >/dev/null \
    || assert_event 'final signing failure did not exercise the exact manifest argv'

# The key reaches the signer through the environment only. Build the helper
# exactly once, use that same executable for the preflight first and the exact
# final manifest second, and never put key material in a recorded command line.
run_script
grep -n 'fixture-not-a-signing-key' "$EVENTS" >/dev/null \
    && assert_event 'the signing key appeared in a command line'
assert_signer_reuse_contract() {
    local built
    local -a binaries invocations
    mapfile -t binaries <<<"$(sed -n '/^rulessign-bin /p' "$EVENTS")"
    mapfile -t invocations <<<"$(sed -n '/^rulessign /p' "$EVENTS")"
    [ "$(grep -c '^go-build ' "$EVENTS")" -eq 1 ] \
        || assert_event 'the publisher did not build exactly one signing helper'
    built="$(sed -n 's/^go-build build -o \([^ ]*\) \.\/cmd\/rulessign$/\1/p' "$EVENTS")"
    [ -n "$built" ] || assert_event 'the publisher signer build argv changed'
    if [ "${#binaries[@]}" -ne 2 ] \
        || [ "${binaries[0]:-}" != "rulessign-bin ${built}" ] \
        || [ "${binaries[1]:-}" != "rulessign-bin ${built}" ]; then
        assert_event 'the publisher did not reuse its built signing helper'
    fi
    [ "${#invocations[@]}" -eq 2 ] || assert_event 'the publisher signer invocation count changed'
    [[ "${invocations[0]}" == "rulessign -require-trusted -manifest ${built%/rulessign}/signing-preflight.json -out ${built%/rulessign}/signing-preflight.json.sig" ]] \
        || assert_event 'the trusted signing preflight argv or order changed'
    [[ "${invocations[1]}" == "rulessign -require-trusted -manifest ${built%/rulessign}/compiled.yac.manifest.json -out ${built%/rulessign}/compiled.yac.manifest.json.sig" ]] \
        || assert_event 'the final exact-manifest signing argv or order changed'
}
assert_signer_reuse_contract

# AUD-06c-f2: the rolling release has no atomic activation (assets are clobbered
# one by one), so an interrupted publication cannot leave the previously
# published pair verifiable: the first clobbered asset already breaks it. This
# pins the real behaviour: the run fails closed as publish/uncertain, the
# verifier never runs, and the remote state at the interruption is exactly the
# documented signature-first window (never a new manifest with an old signature).
assert_interrupted_publication() {  # assert_interrupted_publication <fail-at> <uploads> <sig-new:0|1> <manifest-new:0|1>
    local at="$1" uploads="$2" sig_new="$3" man_new="$4" actual remote="${EVENTS}.remote"
    rm -rf "${remote:?}"
    mkdir "$remote"
    printf 'OLD-SIG\n' >"$remote/compiled.yac.manifest.json.sig"
    printf 'OLD-MANIFEST\n' >"$remote/compiled.yac.manifest.json"
    run_script FAIL_PUBLISH_AT="$at"
    [ "$actual" -eq 42 ] || assert_event "interrupted@$at: exit $actual, want 42"
    assert_receipt publish failed
    assert_notification "interrupted@$at" publish failed
    grep -F 'notify-body generate-rules.sh exited 42 — rules-current may be partially updated.' "$EVENTS" >/dev/null || assert_event "interrupted@$at: uncertain state wording"
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq "$uploads" ] || assert_event "interrupted@$at: upload count"
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event "interrupted@$at: verifier ran"
    if [ "$sig_new" -eq 1 ]; then
        ! grep -Fx OLD-SIG "$remote/compiled.yac.manifest.json.sig" >/dev/null || assert_event "interrupted@$at: signature was not replaced"
    else
        grep -Fx OLD-SIG "$remote/compiled.yac.manifest.json.sig" >/dev/null || assert_event "interrupted@$at: signature replaced too early"
    fi
    if [ "$man_new" -eq 1 ]; then
        ! grep -Fx OLD-MANIFEST "$remote/compiled.yac.manifest.json" >/dev/null || assert_event "interrupted@$at: manifest was not replaced"
    else
        grep -Fx OLD-MANIFEST "$remote/compiled.yac.manifest.json" >/dev/null || assert_event "interrupted@$at: manifest replaced too early"
    fi
    rm -rf "${remote:?}"
}
# Failure at the 2nd (signature) upload: only the bundle was replaced.
assert_interrupted_publication 2 2 0 0
# Failure at the 3rd (manifest) upload: new signature over the old manifest, so
# the pair does not verify and a consumer refuses (fail closed); the previous
# pair is NOT recoverable from the remote.
assert_interrupted_publication 3 3 1 0

# AUD-06c-f4: the 00:00Z cron run has no MAILSTRIX_RULES_SIGNING_KEY in its
# environment (the key exists only as a GitHub Actions secret), so the publisher
# resolves it from /etc/myguard-build-env. A PEM is multi-line and the build-env
# reader is line-based, so build-env carries ONE base64 line,
# MAILSTRIX_RULES_SIGNING_KEY_B64, decoded in memory before the docker build.

write_build_env() {  # write_build_env <line>...; prints the fixture path
    local path="$test_root/build-env"
    : >"$path"
    local line
    for line in "$@"; do
        printf '%s\n' "$line" >>"$path"
    done
    printf '%s' "$path"
}

# The hygiene oracle. Neither the decoded PEM body nor the base64 line may appear
# in the cron log or in any recorded command line, for ANY outcome: a diagnostic
# is allowed to name the variable, never to quote its value.
assert_no_key_leak() {  # assert_no_key_leak <case> <sentinel>...
    local name="$1" sentinel sink
    shift
    for sentinel in "$@"; do
        for sink in "$EVENTS" "$test_root/log"; do
            ! grep -F -- "$sentinel" "$sink" >/dev/null \
                || assert_event "${name}: key material leaked into $(basename "$sink")"
        done
    done
}

# POSITIVE: no key in the environment, a valid base64 line in build-env. The run
# must succeed with the SAME receipts, ordering and notification as the plain
# `success` case, and the signer must receive the DECODED three-line PEM.
assert_build_env_key_publishes() {  # assert_build_env_key_publishes <case> <line>...
    local name="$1" fixture actual
    shift
    fixture="$(write_build_env "$@")"
    run_script -u MAILSTRIX_RULES_SIGNING_KEY "BUILD_ENV_FIXTURE=$fixture"
    [ "$actual" -eq 0 ] || { cat "$test_root/log" >&2; assert_event "${name}: exit ${actual}, want 0"; }
    [ "$(grep -c '^sudo-read -n cat /etc/myguard-build-env$' "$EVENTS" || true)" -eq 1 ] \
        || assert_event "${name}: build-env was not read exactly once"
    # The discriminating assertion: `pem 3` can only come from a decoded PEM.
    # Exporting the raw base64 instead yields `raw 1`.
    grep -Fx 'go-key pem 3' "$EVENTS" >/dev/null \
        || assert_event "${name}: the signer did not receive the decoded multi-line PEM"
    assert_receipt verify success
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 3 ] || assert_event "${name}: upload count"
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event "${name}: verifier count"
    assert_verifier_contract "$name" 1
    assert_notification "$name" verify success
    assert_success_event_order "$name" 1
    assert_success_notification_body "$name" 1
    assert_no_key_leak "$name" "$FIXTURE_KEY_BODY" "$FIXTURE_PEM_B64"
}

assert_build_env_key_publishes build-env-key "MAILSTRIX_RULES_SIGNING_KEY_B64=${FIXTURE_PEM_B64}"
# BOUNDARY: the same tolerances the GITHUB_ORG_LAB_TOKEN extractor has — an
# `export ` prefix, leading/trailing whitespace, surrounding quotes, and a
# duplicate line where the LAST one wins. The decoy value would not decode to a
# PEM, so a first-match extractor fails the armour check instead of publishing.
assert_build_env_key_publishes build-env-key-export \
    "export MAILSTRIX_RULES_SIGNING_KEY_B64=${FIXTURE_PEM_B64}"
assert_build_env_key_publishes build-env-key-quoted \
    "  export  MAILSTRIX_RULES_SIGNING_KEY_B64=\"${FIXTURE_PEM_B64}\"  "
assert_build_env_key_publishes build-env-key-single-quoted \
    "MAILSTRIX_RULES_SIGNING_KEY_B64='${FIXTURE_PEM_B64}'"
assert_build_env_key_publishes build-env-key-last-wins \
    "MAILSTRIX_RULES_SIGNING_KEY_B64=$(printf 'decoy-not-a-pem' | base64 -w0)" \
    "MAILSTRIX_RULES_SIGNING_KEY_B64=${FIXTURE_PEM_B64}" \
    'GITHUB_ORG_LAB_TOKEN=fixture-not-a-credential'

# ERROR/MALFORMED: every bad build-env state must fail fast — before the docker
# build, any release mutation or the verifier — and must still produce exactly
# one build-stage receipt and alert. The key is resolved at startup, so `count`
# (the in-image rule check) must not appear either.
assert_build_env_key_refused() {  # assert_build_env_key_refused <case> <diagnostic> [line]...
    local name="$1" diagnostic="$2" fixture actual
    shift 2
    fixture="$(write_build_env "$@")"
    run_script -u MAILSTRIX_RULES_SIGNING_KEY "BUILD_ENV_FIXTURE=$fixture"
    [ "$actual" -eq 1 ] || assert_event "${name}: exit ${actual}, want 1"
    assert_receipt build failed
    assert_notification "$name" build failed
    [ "$(grep -Ec '^(create$|upload |verify |count |go-build |rulessign )' "$EVENTS" || true)" -eq 0 ] \
        || assert_event "${name}: an unresolved signing key reached the build or publication"
    grep -F -- "$diagnostic" "$test_root/log" >/dev/null \
        || assert_event "${name}: missing diagnostic: ${diagnostic}"
    assert_no_key_leak "$name" "$FIXTURE_KEY_BODY" "$FIXTURE_PEM_B64"
}

# Absent entirely: the actual production failure this fixes. The message must
# name both variables and the file so the operator can act on the cron log alone.
assert_build_env_key_refused build-env-key-absent \
    'MAILSTRIX_RULES_SIGNING_KEY is not set and MAILSTRIX_RULES_SIGNING_KEY_B64 is not readable from /etc/myguard-build-env' \
    'GITHUB_ORG_LAB_TOKEN=fixture-not-a-credential'
# shellcheck disable=SC2016  # the $(...) is the literal install recipe in the diagnostic
grep -F 'MAILSTRIX_RULES_SIGNING_KEY_B64=$(base64 -w0 key.pem)' "$test_root/log" >/dev/null \
    || assert_event 'build-env-key-absent: diagnostic is not actionable'
# Present but empty is indistinguishable from absent, and must not be silently
# treated as a key.
assert_build_env_key_refused build-env-key-empty \
    'MAILSTRIX_RULES_SIGNING_KEY is not set and MAILSTRIX_RULES_SIGNING_KEY_B64 is not readable' \
    'MAILSTRIX_RULES_SIGNING_KEY_B64='
# Not base64 at all.
assert_build_env_key_refused build-env-key-not-base64 \
    'MAILSTRIX_RULES_SIGNING_KEY_B64 in /etc/myguard-build-env is not valid base64' \
    'MAILSTRIX_RULES_SIGNING_KEY_B64=****not-base64****'
# Truncated to a length base64 cannot decode.
assert_build_env_key_refused build-env-key-truncated \
    'MAILSTRIX_RULES_SIGNING_KEY_B64 in /etc/myguard-build-env is not valid base64' \
    "MAILSTRIX_RULES_SIGNING_KEY_B64=${FIXTURE_PEM_B64:0:17}"
# Valid base64 of something that is not a PEM.
assert_build_env_key_refused build-env-key-not-pem \
    "did not decode to a complete PEM (no '-----BEGIN ' / '-----END ' armour)" \
    "MAILSTRIX_RULES_SIGNING_KEY_B64=$(printf 'not-a-pem-at-all' | base64 -w0)"
# Valid base64 of a TRUNCATED PEM: it keeps the BEGIN line and loses the END
# line, which is the class a BEGIN-only armour check accepts. base64 -d decodes
# it happily, so only the armour pair rejects it.
assert_build_env_key_refused build-env-key-headless-pem \
    "did not decode to a complete PEM (no '-----BEGIN ' / '-----END ' armour)" \
    "MAILSTRIX_RULES_SIGNING_KEY_B64=$(printf '%s' "${FIXTURE_PEM%-----END*}" | base64 -w0)"

# PRECEDENCE: an environment-provided key is used VERBATIM and build-env is never
# consulted. That is how CI and manual runs work, so the fallback must not be
# able to override or re-validate them — note the environment fixture is NOT
# PEM-shaped and still publishes.
assert_environment_key_wins() {
    local fixture actual
    fixture="$(write_build_env "MAILSTRIX_RULES_SIGNING_KEY_B64=${FIXTURE_PEM_B64}")"
    run_script "BUILD_ENV_FIXTURE=$fixture"
    [ "$actual" -eq 0 ] || { cat "$test_root/log" >&2; assert_event "environment-key-wins: exit ${actual}, want 0"; }
    [ "$(grep -c '^sudo-read ' "$EVENTS" || true)" -eq 0 ] \
        || assert_event 'environment-key-wins: build-env was consulted despite an environment key'
    grep -Fx 'go-key raw 1' "$EVENTS" >/dev/null \
        || assert_event 'environment-key-wins: the environment key was not passed through verbatim'
    assert_receipt verify success
    assert_no_key_leak environment-key-wins "$FIXTURE_KEY_BODY" "$FIXTURE_PEM_B64"
}
assert_environment_key_wins

# GH_TOKEN now shares the single build-env extractor, so its behaviour needs its
# own coverage: the same tolerances must still resolve it, and a build-env with
# no token line must still die before the build.
assert_build_env_token_resolves() {
    local fixture actual
    fixture="$(write_build_env '  export GITHUB_ORG_LAB_TOKEN="fixture-not-a-credential"' \
        "MAILSTRIX_RULES_SIGNING_KEY_B64=${FIXTURE_PEM_B64}")"
    run_script -u GH_TOKEN -u MAILSTRIX_RULES_SIGNING_KEY "BUILD_ENV_FIXTURE=$fixture"
    [ "$actual" -eq 0 ] || { cat "$test_root/log" >&2; assert_event "build-env-token: exit ${actual}, want 0"; }
    [ "$(grep -c '^sudo-read -n cat /etc/myguard-build-env$' "$EVENTS" || true)" -eq 2 ] \
        || assert_event 'build-env-token: expected one build-env read per secret'
    assert_receipt verify success
    assert_no_key_leak build-env-token "$FIXTURE_KEY_BODY" "$FIXTURE_PEM_B64" fixture-not-a-credential
}
assert_build_env_token_resolves

assert_missing_build_env_token_dies() {
    local fixture actual
    fixture="$(write_build_env "MAILSTRIX_RULES_SIGNING_KEY_B64=${FIXTURE_PEM_B64}")"
    run_script -u GH_TOKEN "BUILD_ENV_FIXTURE=$fixture"
    [ "$actual" -eq 1 ] || assert_event "missing-build-env-token: exit ${actual}, want 1"
    assert_receipt build failed
    assert_notification missing-build-env-token build failed
    grep -F 'GITHUB_ORG_LAB_TOKEN not readable from /etc/myguard-build-env' "$test_root/log" >/dev/null \
        || assert_event 'missing-build-env-token: diagnostic changed'
    [ "$(grep -Ec '^(create$|upload |verify |count |go-build |rulessign )' "$EVENTS" || true)" -eq 0 ] \
        || assert_event 'missing-build-env-token: a tokenless run reached the build or publication'
}
assert_missing_build_env_token_dies

# An unreadable/absent build-env must behave exactly like a missing value rather
# than aborting on sudo's non-zero exit inside the extractor pipeline.
assert_unreadable_build_env_is_a_missing_value() {
    local actual
    run_script -u MAILSTRIX_RULES_SIGNING_KEY
    [ "$actual" -eq 1 ] || assert_event "unreadable-build-env: exit ${actual}, want 1"
    assert_receipt build failed
    grep -F 'MAILSTRIX_RULES_SIGNING_KEY is not set and MAILSTRIX_RULES_SIGNING_KEY_B64 is not readable' "$test_root/log" >/dev/null \
        || assert_event 'unreadable-build-env: diagnostic changed'
    [ "$(grep -c '^sudo-read ' "$EVENTS" || true)" -eq 1 ] \
        || assert_event 'unreadable-build-env: build-env read count'
}
assert_unreadable_build_env_is_a_missing_value

echo 'PASS: the signing key resolves from the environment or the build-env base64 fallback without leaking'
echo 'PASS: unsigned or failed-signing publication is refused before any asset upload'
echo 'PASS: terminal JSON receipts distinguish build/publish/verify; publish order and verifier contract hold'

# ---------------------------------------------------------------------------
# Marker tree publication (M3). The fake docker serves a release-toolchain
# export; everything else (pack, manifest field, ordering, staged verification)
# is the real publisher code.
# ---------------------------------------------------------------------------
manifest_has_marker() { "$REAL_JQ" -e 'has("marker")' "${EVENTS}.manifest" >/dev/null; }

tree_members() {  # tree_members <tar.gz>: type<TAB>name per member, sorted as stored
    python3 - "$1" <<'PY'
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as tar:
    for m in tar.getmembers():
        print(("d" if m.isdir() else "f" if m.isreg() else "?") + "\t" + m.name)
PY
}

assert_marker_published() {
    local actual name=marker-published
    run_script LATEST_TAG=v1.2.3
    [ "$actual" -eq 0 ] || { cat "$test_root/log" >&2; assert_event "${name}: exit ${actual}, want 0"; }
    assert_receipt verify success
    manifest_has_marker || assert_event "${name}: manifest has no marker field"
    local tree_sha manifest_sha
    tree_sha="$(sha256sum "${EVENTS}.tree" | cut -d ' ' -f1)"
    # shellcheck disable=SC2016  # jq program, not shell expansion
    "$REAL_JQ" -e --arg sha "$tree_sha" --argjson size "$(stat -c %s "${EVENTS}.tree")" \
        --arg lib "$(printf 'fixture-libyara' | sha256sum | cut -d ' ' -f1)" \
        --arg comp "$(printf 'fixture-yarac' | sha256sum | cut -d ' ' -f1)" \
        --arg main "$(sha256sum <(dd if=/dev/zero bs=1024 count=1536 2>/dev/null) | cut -d ' ' -f1)" \
        '.marker == {asset:"marker-tree.tar.gz", sha256:$sha, size:$size, libyara_sha256:$lib, compiler_sha256:$comp, main_sha256:$main} and (.checksum == "sha256:" + $main)' \
        "${EVENTS}.manifest" >/dev/null || assert_event "${name}: marker field does not describe the uploaded tree and toolchain"
    # The signature covers the manifest that carries the marker field.
    manifest_sha="$(sha256sum "${EVENTS}.manifest" | cut -d ' ' -f1)"
    grep -Fx "signed-sha ${manifest_sha}" "$EVENTS" >/dev/null || assert_event "${name}: the signed manifest bytes differ from the uploaded manifest"
    # Exact archive contract: only the allowed top-level names, dirs and regular files.
    [ -z "$(tree_members "${EVENTS}.tree" | grep -vE '^(d|f)	(compiler-inputs|marker-artifact|libyara\.version|sources\.json)(/|$)' || true)" ] \
        || assert_event "${name}: archive holds entries outside the contract set"
    [ "$(tree_members "${EVENTS}.tree" | grep -c '^?' || true)" -eq 0 ] || assert_event "${name}: archive holds non-regular members"
    [ "$(tree_members "${EVENTS}.tree" | tr '\t' ' ' | tr '\n' ',')" = 'd compiler-inputs,f compiler-inputs/index.json,d compiler-inputs/main,d compiler-inputs/main/objects,f compiler-inputs/main/objects/aa,f libyara.version,d marker-artifact,d marker-artifact/abi,f marker-artifact/abi/libyara.a,f marker-artifact/abi/yarac,f marker-artifact/binding.json,f sources.json,' ] \
        || { tree_members "${EVENTS}.tree" >&2; assert_event "${name}: archive member list differs from the contract tree"; }
    # Upload order: tree strictly before the signature and the manifest; the
    # staged-candidate verification precedes every upload.
    local -a order=()
    local event
    while IFS= read -r event; do
        case "$event" in
            stage-verify\ *|upload\ *|verify\ *) order+=("${event%% *} ${event#* }") ;;
        esac
    done <"$EVENTS"
    [ "${order[0]%% *}" = stage-verify ] || assert_event "${name}: staged verification did not run first"
    [ "${order[1]}" = 'upload compiled.yac' ] || assert_event "${name}: compiled.yac not uploaded right after verification"
    [ "${order[2]}" = 'upload marker-tree.tar.gz' ] || assert_event "${name}: marker tree not uploaded before sig/manifest"
    [ "${order[3]}" = 'upload compiled.yac.manifest.json.sig' ] || assert_event "${name}: signature not uploaded after the tree"
    [ "${order[4]}" = 'upload compiled.yac.manifest.json' ] || assert_event "${name}: manifest not uploaded last"
    [ "${order[5]%% *}" = verify ] || assert_event "${name}: post-publish verification missing"
    grep -Fx 'stage-fetch ok' "$EVENTS" >/dev/null || assert_event "${name}: the staged candidate was not served intact"
    grep -E '^stage-verify .*-require-marker' "$EVENTS" >/dev/null || assert_event "${name}: staged verification lacks -require-marker"
    grep -E '^stage-verify .*sha256:markerverifier' "$EVENTS" >/dev/null || assert_event "${name}: staged verification did not use the release strixd image"
    grep -E '^probe .*--network none sha256:markerverifier -h' "$EVENTS" >/dev/null || assert_event "${name}: release strixd was not probed for -require-marker"
    grep -E '^verify .*sha256:markerverifier .*-require-marker' "$EVENTS" >/dev/null || assert_event "${name}: post-publish verification is not marker-gated"
    grep -E '^stage-verify .*size=4g' "$EVENTS" >/dev/null || assert_event "${name}: staged marker gate lacks the 4g tmpfs"
    grep -E '^verify .*size=4g .*sha256:markerverifier' "$EVENTS" >/dev/null || assert_event "${name}: post-publish marker gate lacks the 4g tmpfs"
    grep -Fx 'dockerfile Dockerfile.release rules-export' "$EVENTS" >/dev/null || assert_event "${name}: bundle not built with the release toolchain"
    ! grep -Fx 'dockerfile Dockerfile rules-export' "$EVENTS" >/dev/null || assert_event "${name}: the unmarked build ran despite a marker export"
    # Same fixture twice -> byte-identical tree asset.
    cp "${EVENTS}.tree" "$test_root/tree-first"
    run_script LATEST_TAG=v1.2.3
    cmp -s "$test_root/tree-first" "${EVENTS}.tree" || assert_event "${name}: two publishes of one tree differ"
}
assert_marker_published

# Without a marker field every pre-existing guarantee is unchanged.
assert_marker_skipped() {  # assert_marker_skipped <case> <env-assignment>...
    local name="$1" actual
    shift
    run_script "$@"
    [ "$actual" -eq 0 ] || { cat "$test_root/log" >&2; assert_event "${name}: exit ${actual}, want 0"; }
    assert_receipt verify success
    ! manifest_has_marker || assert_event "${name}: manifest carries a marker field"
    [ ! -e "${EVENTS}.tree" ] || assert_event "${name}: a marker tree was uploaded"
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 3 ] || assert_event "${name}: upload count"
    [ "$(grep -c '^stage-verify ' "$EVENTS" || true)" -eq 0 ] || assert_event "${name}: staged verification ran without a marker"
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 1 ] || assert_event "${name}: verifier count"
    ! grep -E '^verify .*-require-marker' "$EVENTS" >/dev/null || assert_event "${name}: unmarked publish gated on a marker"
    grep -Fx "dockerfile ${EXPECT_BUILD:-Dockerfile rules-export}" "$EVENTS" >/dev/null || assert_event "${name}: expected bundle build did not run"
    assert_verifier_contract "$name" 1
    assert_success_event_order "$name" 1
    local signed manifest_sha
    manifest_sha="$(sha256sum "${EVENTS}.manifest" | cut -d ' ' -f1)"
    signed="$(grep '^signed-sha ' "$EVENTS" | tail -n1)"
    [ "$signed" = "signed-sha ${manifest_sha}" ] || assert_event "${name}: signature does not cover the uploaded manifest"
}
# Toolchain / libyara hashes do not match the release strixd (the toolchain
# build exits non-zero), a legacy release without marker support, a tree the
# packer refuses (symlink), an unusable tag, and the operator opt-out.
assert_marker_skipped toolchain-mismatch LATEST_TAG=v1.2.3 MARKER_BUILD=fail
assert_marker_skipped legacy-release LATEST_TAG=v1.2.3 MARKER_BUILD=legacy
# A marker-capable release whose strixd predates -require-marker: fall back, never die.
assert_marker_skipped verifier-without-require-marker LATEST_TAG=v1.2.3 VERIFIER_NO_REQUIRE_MARKER=1
# The bundle itself is still the release-toolchain build; only the field is dropped.
EXPECT_BUILD='Dockerfile.release rules-export' assert_marker_skipped unpackable-tree LATEST_TAG=v1.2.3 MARKER_SYMLINK=1
assert_marker_skipped no-latest-release LATEST_TAG=
assert_marker_skipped malformed-tag 'LATEST_TAG=v1;rm -rf'
assert_marker_skipped operator-off LATEST_TAG=v1.2.3 MARKER_RELEASE_TAG=off

# Toolchain skew: HEAD bumped YARA_VERSION past the latest release, so the release
# export's libyara cannot load in the HEAD verifier. Fall back, still publish.
head_dockerfile="$test_root/sandbox/project/docker/Dockerfile"
printf 'ARG YARA_VERSION=4.6.0\n' > "$head_dockerfile"
assert_marker_skipped libyara-skew LATEST_TAG=v1.2.3
grep -F 'differs from HEAD libyara' "$test_root/log" >/dev/null || assert_event 'libyara-skew: no fallback note'
# HEAD pin unreadable or unparsable: cannot prove a match, so no marker.
printf 'FROM scratch\n' > "$head_dockerfile"
assert_marker_skipped libyara-head-unknown LATEST_TAG=v1.2.3
grep -F 'cannot read ARG YARA_VERSION' "$test_root/log" >/dev/null || assert_event 'libyara-head-unknown: no unreadable-pin warning'
# The real HEAD Dockerfile must stay parseable: with a release export on the same
# libyara, the marker path is kept. A format change to the pin fails here instead
# of silently dropping the marker on every nightly.
cp "$here/Dockerfile" "$head_dockerfile"
real_pin="$(awk -F= '/^ARG YARA_VERSION=/{print $2; exit}' "$head_dockerfile")"
[ -n "$real_pin" ] || assert_event 'real-dockerfile: no ARG YARA_VERSION pin found'
RELEASE_LIBYARA="$real_pin" assert_marker_published
# Bounds: a lower HEAD pin and a longer-but-different version are still skew.
printf 'ARG YARA_VERSION=4.5.1\n' > "$head_dockerfile"
assert_marker_skipped libyara-skew-lower LATEST_TAG=v1.2.3
printf 'ARG YARA_VERSION=4.5.20\n' > "$head_dockerfile"
assert_marker_skipped libyara-skew-longer LATEST_TAG=v1.2.3
printf 'ARG YARA_VERSION=4.5.2\n' > "$head_dockerfile"
# Negative control: matching versions keep the marker path.
assert_marker_published
# Malformed release version file: fail closed, nothing published.
assert_libyara_file_dies() {  # assert_libyara_file_dies <case> <value>
    local actual name="$1"
    run_script LATEST_TAG=v1.2.3 "RELEASE_LIBYARA=$2"
    [ "$actual" -eq 1 ] || assert_event "${name}: exit ${actual}, want 1"
    grep -F 'invalid libyara version' "$test_root/log" >/dev/null || assert_event "${name}: no invalid-version diagnosis"
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event "${name}: assets uploaded"
}
assert_libyara_file_dies libyara-empty ''
assert_libyara_file_dies libyara-garbage 'not-a-version'
assert_libyara_file_dies libyara-injection '4.5.2;rm'

# -require-marker verification failure: nothing new is published.
assert_marker_verify_failure_publishes_nothing() {
    local actual name=marker-verify-failure
    run_script LATEST_TAG=v1.2.3 FAIL_MARKER_VERIFY=1
    [ "$actual" -eq 1 ] || assert_event "${name}: exit ${actual}, want 1"
    assert_receipt verify failed
    assert_notification "$name" verify failed
    grep -F 'nothing was published' "$EVENTS" >/dev/null || assert_event "${name}: failure does not say nothing was updated"
    grep -E '^stage-verify .*-require-marker' "$EVENTS" >/dev/null || assert_event "${name}: staged verification did not run"
    [ "$(grep -c '^upload ' "$EVENTS" || true)" -eq 0 ] || assert_event "${name}: assets were uploaded after a failed verification"
    [ "$(grep -c '^create$' "$EVENTS" || true)" -eq 0 ] || assert_event "${name}: a release was created after a failed verification"
    [ "$(grep -c '^verify ' "$EVENTS" || true)" -eq 0 ] || assert_event "${name}: post-publish verifier ran"
}
assert_marker_verify_failure_publishes_nothing

# The pack is deterministic regardless of file mtimes and creation order, and a
# tree the client would refuse (symlink) or that lacks a required entry is
# refused by the packer.
assert_pack_deterministic_and_strict() {
    local tree="$test_root/packtree" a="$test_root/pack-a.tar.gz" b="$test_root/pack-b.tar.gz" pack
    pack="$test_root/sandbox/project/docker/pack-marker-tree.py"
    mkdir -p "$tree/compiler-inputs/main" "$tree/marker-artifact/abi"
    printf 'x' >"$tree/compiler-inputs/main/z"; printf 'y' >"$tree/compiler-inputs/a"
    printf 'z' >"$tree/marker-artifact/abi/yarac"; printf '4.5.2\n' >"$tree/libyara.version"
    printf '{}\n' >"$tree/sources.json"
    printf 'ignored' >"$tree/compiled.yac"
    python3 "$pack" "$tree" "$a" || assert_event 'pack: valid tree refused'
    touch -d '2001-01-01' "$tree/compiler-inputs/a" "$tree/libyara.version"
    chmod 600 "$tree/marker-artifact/abi/yarac"
    python3 "$pack" "$tree" "$b" || assert_event 'pack: second pack refused'
    cmp -s "$a" "$b" || assert_event 'pack: archives differ across mtime/mode changes'
    ! tree_members "$a" | grep -q compiled.yac || assert_event 'pack: archived a file outside the contract set'
    # gzip header carries no name and a zero mtime.
    [ "$(head -c 8 "$a" | od -An -tx1 | tr -d ' \n' | cut -c7-16)" = '0000000000' ] \
        || assert_event 'pack: gzip header carries a name flag or timestamp'
    ln -s /etc/passwd "$tree/compiler-inputs/link"
    ! python3 "$pack" "$tree" "$test_root/pack-c.tar.gz" 2>"$test_root/pack.err" || assert_event 'pack: symlink accepted'
    grep -F 'not a regular file' "$test_root/pack.err" >/dev/null || assert_event 'pack: symlink diagnostic'
    rm "$tree/compiler-inputs/link"; mv "$tree/sources.json" "$test_root/sources.json.aside"
    ! python3 "$pack" "$tree" "$test_root/pack-s.tar.gz" 2>"$test_root/pack.err" || assert_event 'pack: missing sources.json accepted'
    grep -F 'missing required entry: sources.json' "$test_root/pack.err" >/dev/null || assert_event 'pack: missing-sources diagnostic'
    mv "$test_root/sources.json.aside" "$tree/sources.json"; rm -rf "$tree/marker-artifact"
    ! python3 "$pack" "$tree" "$test_root/pack-d.tar.gz" 2>"$test_root/pack.err" || assert_event 'pack: missing marker-artifact accepted'
    grep -F 'missing required entry' "$test_root/pack.err" >/dev/null || assert_event 'pack: missing-entry diagnostic'
}
assert_pack_deterministic_and_strict

echo 'PASS: marker tree is published tree-first with a signed marker field, only after staged -require-marker verification; every skip leaves publication unchanged'
