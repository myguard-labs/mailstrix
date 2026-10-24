#!/usr/bin/env bash
# Direct helper controls and, when sourced by generate-rules_test.sh, real
# publisher controls. Both use the same fake release SHA256SUMS assets.
# shellcheck disable=SC2154  # Publisher fixture variables belong to the caller.
set -euo pipefail

if [ "${1:-}" = --fixture ]; then
    [ "${SUMS_MODE:-matching}" != download-failed ] || exit 66
    [ "${SUMS_MODE:-matching}" != missing-file ] || exit 0
    python3 - "$2" <<'PY'
import hashlib
import os
from pathlib import Path
import sys

mode = os.environ.get("SUMS_MODE", "matching")
arch = os.environ.get("RELEASE_ARCH", "amd64")
if mode == "wrong-arch":
    arch = "arm64" if arch == "amd64" else "amd64"
compiler, library = f"yarac-linux-{arch}", f"libyara-linux-{arch}.a"
sha = lambda value: hashlib.sha256(value.encode()).hexdigest()
records = [(sha("fixture-yarac"), compiler), (sha("fixture-libyara"), library)]
if mode == "compiler-mismatch":
    records[0] = (sha("different-yarac"), compiler)
elif mode == "library-mismatch":
    records[1] = (sha("different-libyara"), library)
elif mode in ("missing-compiler", "missing-library"):
    records.pop(0 if mode == "missing-compiler" else 1)
elif mode in ("duplicate-compiler", "duplicate-library", "conflicting-duplicate"):
    digest, name = records[1 if mode == "duplicate-library" else 0]
    records.append((sha("conflict") if mode == "conflicting-duplicate" else digest, name))
elif mode in ("short-digest", "long-digest", "nonhex-digest"):
    records[0] = ({"short-digest": "a" * 63, "long-digest": "a" * 65,
                   "nonhex-digest": "g" * 64}[mode], compiler)
elif mode == "uppercase":
    records = [(digest.upper(), name) for digest, name in records]
elif mode == "other-assets":
    records += [(sha("deb"), "./mailstrix_1.2.3_amd64.deb"),
                (sha("other-arch"), "yarac-linux-arm64"),
                (sha("daemon"), "strixd-linux-amd64")]
text = "\n".join(f"{digest}  {name}" for digest, name in records)
if mode == "empty":
    text = ""
elif mode == "extra-column":
    text += " unexpected"
elif mode == "blank-record":
    text += "\n\n"
elif mode == "malformed-unrelated":
    text += "\nnot-a-checksum unrelated-asset"
elif mode == "binary-record":
    text = text.replace("  ", " *")
elif mode == "nonascii":
    text += "\né"
Path(sys.argv[1]).write_text(text + ("" if mode == "no-final-newline" else "\n"))
PY
    exit
fi

marker_sums_direct=0
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    marker_sums_direct=1
    here="$(cd "$(dirname "$0")/../docker" && pwd)"
    test_root="$(mktemp -d)"
    trap 'rm -rf "$test_root"' EXIT
    mkdir -p "$test_root/bin" "$test_root/export/marker-artifact/abi" "$test_root/work"
    export WORK="$test_root/work" REPO=myguard-labs/mailstrix
    export ABI_EXPORT="$test_root/export" EXPECTED_MARKER_TAG=v1.2.3
    export MARKER_SUMS_TEST="${BASH_SOURCE[0]}"
    MARKER_SUMS_TEST="$(cd "$(dirname "$MARKER_SUMS_TEST")" && pwd)/$(basename "$MARKER_SUMS_TEST")"
    # Source only the helper; executing the publisher itself would require its
    # full Docker/signing fixture, covered by the sourcing runner below.
    sed -n '/^verify_marker_release_abi() {/,/^}/p' "$here/generate-rules.sh" > "$test_root/verify.sh"
    # shellcheck disable=SC1091  # The helper was extracted immediately above.
    source "$test_root/verify.sh"
    declare -F verify_marker_release_abi >/dev/null
    export -f verify_marker_release_abi
    cat > "$test_root/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[ "$*" = 'image inspect --format {{.Architecture}} fixture-image' ] || exit 63
[ "${FAIL_ARCH_INSPECT:-0}" -eq 0 ] || exit 64
printf '%s\n' "${RELEASE_ARCH-amd64}"
STUB
    cat > "$test_root/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 9 ] && [ "$1" = release ] && [ "$2" = download ] \
    && [ "$3" = "$EXPECTED_MARKER_TAG" ] && [ "$4" = --repo ] \
    && [ "$5" = myguard-labs/mailstrix ] && [ "$6" = --pattern ] \
    && [ "$7" = SHA256SUMS ] && [ "$8" = --output ] || exit 65
bash "$MARKER_SUMS_TEST" --fixture "$9"
STUB
    chmod +x "$test_root/bin/docker" "$test_root/bin/gh"
    export PATH="$test_root/bin:$PATH"
fi

marker_sums_run_direct() {
    local actual
    # Reset downloaded sums and ABI files so failed downloads cannot reuse a
    # previous case's accepted release asset.
    rm -f "$WORK/marker-release.SHA256SUMS" "$ABI_EXPORT/marker-artifact/abi/yarac" \
        "$ABI_EXPORT/marker-artifact/abi/libyara.a"
    printf 'fixture-yarac' > "$ABI_EXPORT/marker-artifact/abi/yarac"
    printf 'fixture-libyara' > "$ABI_EXPORT/marker-artifact/abi/libyara.a"
    # shellcheck disable=SC2016  # These variables expand in the child shell.
    if env "$@" bash -c '
        abi="$ABI_EXPORT/marker-artifact/abi"
        case "${ABI_MODE:-}" in
            missing-compiler) rm "$abi/yarac" ;;
            missing-library) rm "$abi/libyara.a" ;;
            empty-compiler) : > "$abi/yarac" ;;
            empty-library) : > "$abi/libyara.a" ;;
            symlink-compiler) mv "$abi/yarac" "$abi/yarac-real"; ln -s yarac-real "$abi/yarac" ;;
            symlink-library) mv "$abi/libyara.a" "$abi/library-real"; ln -s library-real "$abi/libyara.a" ;;
        esac
        verify_marker_release_abi "$EXPECTED_MARKER_TAG" "$ABI_EXPORT" fixture-image
    ' > "$test_root/log" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    return "$actual"
}

assert_marker_sums_accepts() {
    local name="$1" actual
    shift
    if [ "$marker_sums_direct" -eq 1 ]; then
        marker_sums_run_direct "$@" || { cat "$test_root/log" >&2; printf 'FAIL: %s: matching release ABI rejected\n' "$name" >&2; exit 1; }
    else
        run_script LATEST_TAG=v1.2.3 "$@"
        [ "$actual" -eq 0 ] || assert_event "${name}: matching release ABI failed"
        manifest_has_marker || assert_event "${name}: matching release ABI has no marker"
        assert_receipt verify success
        grep -E '^stage-verify .*-require-marker' "$EVENTS" >/dev/null || assert_event "${name}: marker not verified before upload"
    fi
}

assert_marker_sums_rejects() {
    local name="$1"
    shift
    if [ "$marker_sums_direct" -eq 1 ]; then
        if marker_sums_run_direct "$@"; then
            printf 'FAIL: %s: release ABI checksum comparison accepted invalid input\n' "$name" >&2
            exit 1
        fi
    else
        assert_marker_skipped "$name" LATEST_TAG=v1.2.3 "$@"
        grep -F 'against release SHA256SUMS' "$test_root/log" >/dev/null || assert_event "${name}: checksum fallback not diagnosed"
        ! grep -q '^probe ' "$EVENTS" || assert_event "${name}: marker probe ran after rejected release checksums"
    fi
}

for good_sums in matching uppercase no-final-newline other-assets; do
    assert_marker_sums_accepts "$good_sums" "SUMS_MODE=$good_sums"
done
assert_marker_sums_accepts arm64 RELEASE_ARCH=arm64
assert_marker_sums_accepts selected-tag MARKER_RELEASE_TAG=v2.3.4 EXPECTED_MARKER_TAG=v2.3.4
for bad_sums in compiler-mismatch library-mismatch missing-compiler missing-library \
    duplicate-compiler duplicate-library conflicting-duplicate wrong-arch \
    short-digest long-digest nonhex-digest extra-column blank-record \
    malformed-unrelated binary-record nonascii empty download-failed missing-file; do
    assert_marker_sums_rejects "$bad_sums" "SUMS_MODE=$bad_sums"
done
assert_marker_sums_rejects unknown-arch RELEASE_ARCH=unknown
assert_marker_sums_rejects missing-arch RELEASE_ARCH=
assert_marker_sums_rejects arch-inspect-failed FAIL_ARCH_INSPECT=1
for bad_abi in missing-compiler missing-library empty-compiler empty-library symlink-compiler symlink-library; do
    assert_marker_sums_rejects "$bad_abi" "ABI_MODE=$bad_abi"
done
printf 'PASS: release SHA256SUMS binds both marker ABI files before publication\n'
