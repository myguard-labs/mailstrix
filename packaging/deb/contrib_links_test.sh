#!/bin/sh
# Verify every relative link target in tracked contrib/ README files resolves
# to a real path, including nested deployment documentation. Only relative
# (non-http, non-anchor) targets are checked; bare #anchors and external URLs
# are skipped.
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
miss="$(mktemp)"
stale="$(mktemp)"
readmes="$(mktemp)"
trap 'rm -f "$miss" "$stale" "$readmes"' EXIT

if ! git -C "$root" ls-files -- 'contrib/**/README.md' > "$readmes"; then
    echo "FAIL - cannot enumerate tracked contrib README files" >&2
    exit 1
fi

while IFS= read -r rel; do
    md="$root/$rel"
    dir="$(dirname "$md")"
    # ](target) link targets, fragment stripped, URLs/anchors skipped.
    grep -oE '\]\([^)]+\)' "$md" \
        | sed -E 's/^\]\(//; s/\)$//; s/#.*$//' \
        | while IFS= read -r tgt; do
            [ -n "$tgt" ] || continue
            case "$tgt" in http://*|https://*|mailto:*) continue;; esac
            [ -e "$dir/$tgt" ] || echo "$md -> $tgt" >> "$miss"
        done
done < "$readmes"

if [ -s "$miss" ]; then
    echo "FAIL - dangling contrib/ README links:"
    sed 's/^/  /' "$miss"
    exit 1
fi
echo "ok   - all contrib/ README relative links resolve"

if git -C "$root" grep -nE 'href="/20[0-9]{2}/[0-9]{2}/|deb\.myguard\.nl/20[0-9]{2}/[0-9]{2}/' -- \
    README.md contrib docker packaging .github internal cmd third_party > "$stale"; then
    echo "FAIL - stale deb.myguard.nl dated permalink:"
    sed 's/^/  /' "$stale"
    exit 1
fi
echo "ok   - no stale deb.myguard.nl dated permalinks"
echo "ALL OK"
