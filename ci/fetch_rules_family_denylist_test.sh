#!/bin/sh
# FP-FAMILY denylist in docker/fetch-rules.sh: yaraify rules whose name contains
# a denied family token (_ForgeAuto_) are pruned at build time; everything else,
# and any multi-rule bundle, survives. Hermetic: runs only the extracted block.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/../docker/fetch-rules.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0

ok() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; fails=$((fails + 1)); }
# expect <ok-msg> <fail-msg> <command...>
expect() {
    okm="$1"; badm="$2"; shift 2
    if "$@"; then ok "$okm"; else bad "$badm"; fi
}

block="$tmp/block.sh"
sed -n '/^FP_RULE_FAMILY_DENYLIST=/,/^done$/p' "$script" > "$block"
expect "_ForgeAuto_ is in FP_RULE_FAMILY_DENYLIST" "_ForgeAuto_ missing from FP_RULE_FAMILY_DENYLIST" \
    grep -q '^FP_RULE_FAMILY_DENYLIST="[^"]*_ForgeAuto_' "$block"

rule() { printf 'rule %s\n{\n    condition:\n        true\n}\n' "$1"; }

run_block() {
    out_dir="$1"
    # shellcheck disable=SC2034,SC1090  # OUT is read by the sourced block
    (OUT="$out_dir"; set -eu; . "$block") > "$tmp/log" 2>&1
}

# Positive, boundary and negative controls in one fixture tree.
d="$tmp/out"; mkdir -p "$d"
rule MULTI_Malware_Unknown_ForgeAuto_0fd7af39_Extrait > "$d/yaraify-MULTI_Malware_Unknown_ForgeAuto_0fd7af39_Extrait.yar"
printf 'private ' > "$d/yaraify-private.yar"; rule WIN_Malware_ForgeAuto_1ec7d1c2 >> "$d/yaraify-private.yar"
rule MULTI_Sample_Unique_ab12cd34 > "$d/yaraify-MULTI_Sample_Unique_ab12cd34.yar"
rule NotForgeAuto_Prefix > "$d/yaraify-NotForgeAuto_Prefix.yar"
rule Some_Rule > "$d/yaraify-mentions.yar"; printf '// MULTI_Malware_Unknown_ForgeAuto_x\n' >> "$d/yaraify-mentions.yar"
rule MULTI_Malware_Unknown_ForgeAuto_ffff0000_Extrait > "$d/yaraforge-core.yar"
{ rule MULTI_Malware_Unknown_ForgeAuto_bundled; rule Innocent_Sibling; } > "$d/yaraify-bundle.yar"

run_block "$d" || bad "block exited non-zero: $(cat "$tmp/log")"

expect "ForgeAuto rule file pruned" "ForgeAuto rule file survived" \
    test ! -e "$d/yaraify-MULTI_Malware_Unknown_ForgeAuto_0fd7af39_Extrait.yar"
expect "private ForgeAuto rule pruned" "private ForgeAuto rule survived" \
    test ! -e "$d/yaraify-private.yar"
expect "other yaraify rule kept" "other yaraify rule wrongly pruned" \
    test -e "$d/yaraify-MULTI_Sample_Unique_ab12cd34.yar"
expect "name without the _ForgeAuto_ token kept" "NotForgeAuto_Prefix wrongly pruned" \
    test -e "$d/yaraify-NotForgeAuto_Prefix.yar"
expect "comment mention does not prune" "comment mention pruned the file" \
    test -e "$d/yaraify-mentions.yar"
expect "non-yaraify source untouched" "non-yaraify file pruned" \
    test -e "$d/yaraforge-core.yar"
expect "multi-rule bundle kept by the guard" "bundle guard failed: multi-rule file removed" \
    test -e "$d/yaraify-bundle.yar"
expect "bundle skip is reported" "bundle skip not reported" \
    grep -q 'SKIP yaraify-bundle.yar' "$tmp/log"
expect "drop count reported" "drop count wrong: $(cat "$tmp/log")" \
    grep -q "dropped 2 yaraify rule(s) matching '_ForgeAuto_'" "$tmp/log"

# Empty output dir: the glob does not match; must not fail.
e="$tmp/empty"; mkdir -p "$e"
run_block "$e" || bad "empty rule dir: block exited non-zero"
expect "empty rule dir is a no-op" "empty rule dir failed: $(cat "$tmp/log")" \
    grep -q 'dropped 0 ' "$tmp/log"

[ "$fails" -eq 0 ] || { echo "$fails failure(s)"; exit 1; }
echo "ALL OK"
