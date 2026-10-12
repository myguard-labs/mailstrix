#!/usr/bin/env bash
# Exercise the cron PATH fallback and the publisher's real trusted-signing
# preflight with throwaway keys. No generated private key leaves the temp tree.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
host_go=""
for candidate in /usr/local/bin/go /usr/local/go/bin/go /usr/bin/go; do
	if [ -x "$candidate" ]; then
		host_go="$candidate"
		break
	fi
done
[ -n "$host_go" ] || {
	printf 'FAIL: no standard host Go executable available\n' >&2
	exit 2
}

test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
base="$test_root/base"
mkdir -p "$base/docker" "$base/cmd" "$base/internal" "$test_root/minimal-bin"
cp "$repo/docker/generate-rules.sh" "$base/docker/"
cp "$repo/go.mod" "$repo/go.sum" "$base/"
cp -R "$repo/cmd/rulessign" "$base/cmd/"
cp -R "$repo/internal/rulespin" "$base/internal/"

# The publisher runs with this PATH. It deliberately has no `go`; only the
# script's standard absolute fallback can reach the compiler.
for tool in bash base64 cp dirname jq mktemp python3 rm sed sha256sum stat tail tr; do
	resolved="$(command -v "$tool")"
	ln -s "$resolved" "$test_root/minimal-bin/$tool"
done

cat >"$test_root/minimal-bin/gh" <<'EOF'
#!/usr/bin/env bash
exit 99
EOF
cat >"$test_root/minimal-bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker\n' >>"$EVENTS"
while [ "$#" -gt 0 ]; do
	if [ "$1" = --output ]; then
		work="${2#type=local,dest=}"
		cp "$work/signing-preflight.json" "$CAPTURE_DIR/"
		cp "$work/signing-preflight.json.sig" "$CAPTURE_DIR/"
		stat -c '%Y %s %n' "$work/rulessign" >"$CAPTURE_DIR/rulessign.stat"
		break
    fi
    shift
done
exit 73
EOF
chmod +x "$test_root/minimal-bin/gh" "$test_root/minimal-bin/docker"

cat >"$test_root/keygen.go" <<'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { panic(err) }
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil { panic(err) }
	path := os.Getenv("TEST_KEY_OUT")
	if path == "" { panic("TEST_KEY_OUT is empty") }
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil { panic(err) }
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
}
EOF

cat >"$test_root/verify.go" <<'EOF'
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
)

func main() {
	pub, err := base64.StdEncoding.DecodeString(os.Getenv("TEST_PUBLIC_KEY"))
	if err != nil { panic(err) }
	body, err := os.ReadFile(os.Getenv("TEST_MANIFEST"))
	if err != nil { panic(err) }
	encoded, err := os.ReadFile(os.Getenv("TEST_SIGNATURE"))
	if err != nil { panic(err) }
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil { panic(err) }
	if !ed25519.Verify(ed25519.PublicKey(pub), body, sig) { panic("signature rejected over exact manifest bytes") }
	if ed25519.Verify(ed25519.PublicKey(pub), append(body, '\n'), sig) { panic("signature accepted modified manifest bytes") }
}
EOF

new_key() { # new_key <name>; sets generated_key/generated_public
	local name="$1"
	generated_key="$test_root/${name}.pem"
	generated_public="$(TEST_KEY_OUT="$generated_key" "$host_go" run "$test_root/keygen.go")"
	[ "$(stat -c '%a' "$generated_key")" = 600 ] || {
		printf 'FAIL: transient key mode\n' >&2
		exit 1
	}
}

new_key trusted
trusted_key="$generated_key"
trusted_public="$generated_public"
# Public fixture substitution only. The production pin remains untouched.
sed -i '/^var keysB64 = \[\]string{/,/^}/c\var keysB64 = []string{"'"$trusted_public"'"}' \
	"$base/internal/rulespin/rulespin.go"

make_case() { # make_case <name>
	case_dir="$test_root/$1"
	cp -R "$base" "$case_dir"
	events="$case_dir/events"
	log="$case_dir/log"
	capture="$case_dir/capture"
	mkdir "$capture"
}

run_publisher() { # run_publisher <key-file>; sets actual
	local key_file="$1"
	(
		export PATH="${PUBLISH_PATH:-$test_root/minimal-bin}"
		export GH_TOKEN=fixture-not-a-credential
		export MAILSTRIX_RULES_SIGNING_KEY
		MAILSTRIX_RULES_SIGNING_KEY="$(<"$key_file")"
		export EVENTS="$events" CAPTURE_DIR="$capture"
		cd "$case_dir"
		docker/generate-rules.sh
	) >"$log" 2>&1 && actual=0 || actual=$?
}

assert_no_docker() {
	[ ! -s "$events" ] || {
		printf 'FAIL: %s reached the Docker build\n' "$(basename "$case_dir")" >&2
		exit 1
	}
}

record_case() { # Copies only public diagnostics/artifacts, never generated keys.
	[ -n "${EVIDENCE_DIR:-}" ] || return 0
	local destination
	destination="$EVIDENCE_DIR/$(basename "$case_dir")"
	mkdir -p "$destination"
	cp "$log" "$destination/publisher.log"
	[ ! -f "$events" ] || cp "$events" "$destination/events"
	printf '%s\n' "$actual" >"$destination/status"
	if [ -d "$capture" ]; then
		cp "$capture"/* "$destination/" 2>/dev/null || true
	fi
}

# Positive regression: PATH has no Go, yet the actual cmd/rulessign builds from
# the standard host fallback and completes a trusted signing operation before
# the Docker stopping stub. Verify the captured detached signature independently.
make_case positive
run_publisher "$trusted_key"
[ "$actual" -eq 73 ] || {
	cat "$log" >&2
	printf 'FAIL: cron fallback did not reach Docker\n' >&2
	exit 1
}
[ "$(cat "$events")" = docker ] || {
	printf 'FAIL: positive path did not reach Docker once\n' >&2
	exit 1
}
TEST_PUBLIC_KEY="$trusted_public" \
	TEST_MANIFEST="$capture/signing-preflight.json" \
	TEST_SIGNATURE="$capture/signing-preflight.json.sig" \
	"$host_go" run "$test_root/verify.go"
record_case

# A checkout-local executable must not win merely because cron's PATH contains
# `.`. command -v reports it as ./go, which the publisher deliberately rejects
# before using the same standard absolute fallback as the positive case.
make_case cwd-go-rejected
cat >"$case_dir/go" <<'EOF'
#!/usr/bin/env bash
printf 'cwd-go-ran\n' >"$EVENTS.cwd-go"
exit 88
EOF
chmod +x "$case_dir/go"
PUBLISH_PATH=".:$test_root/minimal-bin" run_publisher "$trusted_key"
[ "$actual" -eq 73 ] || {
	cat "$log" >&2
	printf 'FAIL: checkout-local Go was not safely ignored\n' >&2
	exit 1
}
[ ! -e "$events.cwd-go" ] || {
	printf 'FAIL: checkout-local Go executable ran\n' >&2
	exit 1
}
record_case

# Missing Go: transform only the three audited fallback constants in a private
# fixture. This is necessary because the CI host itself provides those paths.
make_case missing-go
sed -i \
	-e 's#/usr/local/bin/go#/missing/usr-local-bin-go#g' \
	-e 's#/usr/local/go/bin/go#/missing/usr-local-go-bin-go#g' \
	-e 's#/usr/bin/go#/missing/usr-bin-go#g' \
	"$case_dir/docker/generate-rules.sh"
run_publisher "$trusted_key"
[ "$actual" -eq 1 ] || {
	cat "$log" >&2
	printf 'FAIL: missing Go exit %s\n' "$actual" >&2
	exit 1
}
grep -F 'missing required tool: go' "$log" >/dev/null || {
	printf 'FAIL: missing Go diagnostic\n' >&2
	exit 1
}
assert_no_docker
record_case

# An executable Go path that cannot build is also rejected before Docker.
make_case unusable-go
broken_go="$case_dir/broken-go"
printf '#!/usr/bin/env bash\nexit 72\n' >"$broken_go"
chmod +x "$broken_go"
sed -i \
	-e "s#/usr/local/bin/go#${broken_go}#g" \
	-e 's#/usr/local/go/bin/go#/missing/usr-local-go-bin-go#g' \
	-e 's#/usr/bin/go#/missing/usr-bin-go#g' \
	"$case_dir/docker/generate-rules.sh"
run_publisher "$trusted_key"
[ "$actual" -eq 1 ] || {
	cat "$log" >&2
	printf 'FAIL: unusable Go exit %s\n' "$actual" >&2
	exit 1
}
grep -F 'building the manifest signer failed' "$log" >/dev/null || {
	printf 'FAIL: unusable Go diagnostic\n' >&2
	exit 1
}
assert_no_docker
record_case

# Malformed and untrusted keys must fail in the real signer preflight, before
# either the expensive build or any possible publication command.
malformed="$test_root/malformed.pem"
printf '%s\n' 'not a PEM key' >"$malformed"
make_case malformed-key
run_publisher "$malformed"
[ "$actual" -eq 1 ] || {
	cat "$log" >&2
	printf 'FAIL: malformed key exit %s\n' "$actual" >&2
	exit 1
}
grep -F 'signing-key preflight failed' "$log" >/dev/null || {
	printf 'FAIL: malformed-key diagnostic\n' >&2
	exit 1
}
assert_no_docker
record_case

new_key untrusted
untrusted_key="$generated_key"
make_case untrusted-key
run_publisher "$untrusted_key"
[ "$actual" -eq 1 ] || {
	cat "$log" >&2
	printf 'FAIL: untrusted key exit %s\n' "$actual" >&2
	exit 1
}
grep -F 'is not among the 1 public key(s) compiled into strixd' "$log" >/dev/null || {
	printf 'FAIL: untrusted-key diagnostic\n' >&2
	exit 1
}
assert_no_docker
record_case

# Named negative control for the production incident: restoring bare `go` makes
# the positive case fail under the same minimal PATH before Docker.
make_case bare-go-control
# shellcheck disable=SC2016  # literal source text, not this test's variables
sed -i 's/GOTOOLCHAIN=local "$RULESIGN_GO" build/GOTOOLCHAIN=local go build/' \
	"$case_dir/docker/generate-rules.sh"
run_publisher "$trusted_key"
[ "$actual" -ne 73 ] || {
	printf 'FAIL: bare-go control survived\n' >&2
	exit 1
}
grep -F 'go: command not found' "$log" >/dev/null || {
	cat "$log" >&2
	printf 'FAIL: bare-go control missed intended failure\n' >&2
	exit 1
}
assert_no_docker
record_case

# Guard-removal control: deleting the trusted-signing preflight lets an
# untrusted key reach Docker. The unmodified case above rejects that same key.
make_case preflight-removal-control
# shellcheck disable=SC2016  # literal source text, not this test's variables
sed -i \
	-e '/^"$RULESIGN_BIN" -require-trusted -manifest "$PREFLIGHT_MANIFEST"/,/refusing to start the rules build"$/d' \
	"$case_dir/docker/generate-rules.sh"
# shellcheck disable=SC2016  # literal source text, not this test's variables
sed -i '/mailstrix-rules-signing-preflight-v1/a printf fake >"$PREFLIGHT_SIG"' \
	"$case_dir/docker/generate-rules.sh"
run_publisher "$untrusted_key"
[ "$actual" -eq 73 ] || {
	cat "$log" >&2
	printf 'FAIL: preflight-removal control did not reach Docker\n' >&2
	exit 1
}
[ "$(cat "$events")" = docker ] || {
	printf 'FAIL: preflight-removal control event\n' >&2
	exit 1
}
record_case

printf 'PASS: minimal cron PATH uses a standard absolute Go fallback and a real trusted-signing preflight\n'
printf 'PASS: missing/unusable Go and malformed/untrusted keys fail before Docker or publication\n'
printf 'PASS: exact preflight bytes verify independently; bare-Go and removed-preflight controls are detected\n'
