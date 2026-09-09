#!/usr/bin/env bash
# Exercise publish ordering and verifier error propagation with all external
# commands stubbed. Native release-byte validation is covered by the Go CLI test.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
mkdir -p "$test_root/project/docker" "$test_root/bin"
cp "$here/generate-rules.sh" "$test_root/project/docker/"
# Copying isolates the script's relative notification helper: no real messages.
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
if [ "$2" = upload ]; then
    printf 'upload %s\n' "$(basename "${!#}")" >> "$EVENTS"
fi
STUB
cat >"$test_root/bin/curl" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null
printf 404
STUB
cat >"$test_root/bin/jq" <<'STUB'
#!/usr/bin/env bash
# The first-publish branch only generates JSON, never queries an old manifest.
printf '{}\n'
STUB
cat >"$test_root/bin/sleep" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$test_root/bin/"*
for case_spec in '0 0 1' '2 0 3' '5 1 5'; do
	read -r fail_until status verify_count <<<"$case_spec"
	: >"$EVENTS"
	rm -f "${EVENTS}.attempts"
	if FAIL_VERIFY_UNTIL="$fail_until" bash "$test_root/project/docker/generate-rules.sh" >"$test_root/log" 2>&1; then
		actual=0
	else
		actual=$?
	fi
	if [ "$actual" -ne "$status" ]; then
		cat "$test_root/log"
		echo "FAIL: verifier status $status became publisher status $actual" >&2
		exit 1
	fi
	mapfile -t events <"$EVENTS"
	assert_event() {
		printf 'FAIL: %s\nevents:\n' "$1" >&2
		printf '  %s\n' "${events[@]}" >&2
		exit 1
	}
	[ "${#events[@]}" -eq $((2 + verify_count)) ] || assert_event "expected $((2 + verify_count)) events"
	[ "${events[0]}" = 'upload compiled.yac' ] || assert_event 'bundle must upload first'
	[ "${events[1]}" = 'upload compiled.yac.manifest.json' ] || assert_event 'manifest must upload second'
	[[ "${events[2]}" == verify*'-expected-version 1' ]] || assert_event 'verifier must pin the published version'
	[[ "${events[2]}" == *'-timeout 5m'* ]] || assert_event 'verifier must carry the fetch timeout'
	[[ "${events[2]}" == *'--read-only --tmpfs /tmp:rw,nosuid,nodev,size=2g'* ]] || assert_event 'verifier must run isolated'
done
echo 'PASS: ordered publication; verifier retries recover or abort at the bound'
