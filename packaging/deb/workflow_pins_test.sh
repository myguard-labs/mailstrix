#!/bin/sh
# Enforce immutable CI inputs.
#
# Three properties. The first two are what make a pin real — pinning without
# enforcement rots back to tags the first time someone adds a step:
#
#   1. EVERY third-party `uses:` is pinned to a full 40-hex commit SHA. A tag
#      (@v4) or branch (@main) ref is mutable: whoever can move the tag decides
#      what runs in CI, with privileged runner access, no diff and no review.
#      Local refs (./...) are exempt — they come from this repo and are covered
#      by ordinary review.
#   2. Every `go install` pins an exact version. `@latest` is the same hole in a
#      different coat: it silently adopts whatever upstream published most
#      recently. A ${VAR} ref is accepted — the literal it expands to is pinned
#      in the workflow (and keyed into the tool cache, so a bump actually takes
#      effect instead of being masked by a stale cached binary).
#   3. An action must not be pinned to two DIFFERENT SHAs across workflows: one
#      of them is stale or typo'd, and its jobs die at action resolution before
#      doing any work.
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
wfdir="$root/.github/workflows"
pairs="$(mktemp)"
bad="$(mktemp)"
trap 'rm -f "$pairs" "$bad"' EXIT

wfs=""
for wf in "$wfdir"/*.yml "$wfdir"/*.yaml; do
    [ -f "$wf" ] || continue
    wfs="$wfs $wf"
done
[ -n "$wfs" ] || { echo "FAIL - no workflows found under $wfdir"; exit 1; }

# --- 1. every third-party `uses:` is SHA-pinned -----------------------------
for wf in $wfs; do
    grep -nE '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*[^[:space:]]+' "$wf" \
        | grep -vE 'uses:[[:space:]]*\./' \
        | grep -vE 'uses:[[:space:]]*[A-Za-z0-9._/-]+@[0-9a-f]{40}([[:space:]]|$)' \
        | while IFS= read -r hit; do
            echo "$(basename "$wf"):$hit" >> "$bad"
        done
done
if [ -s "$bad" ]; then
    echo "FAIL - third-party action(s) not pinned to a full commit SHA:"
    sed 's/^/  /' "$bad"
    echo "  A tag/branch ref is mutable. Pin to a 40-hex SHA."
    exit 1
fi

# --- 2. no `go install ...@latest` (or any non-exact version) ---------------
for wf in $wfs; do
    name="$(basename "$wf")"
    # grep -n gives us "<lineno>:<text>" without a read-loop over the workflow, so
    # nothing reads $wf while $bad is being appended to.
    installs="$(grep -nE 'go install[[:space:]]' "$wf" || true)"
    [ -n "$installs" ] || continue
    echo "$installs" | while IFS= read -r hit; do
        lineno="${hit%%:*}"
        refs="$(echo "${hit#*:}" | grep -oE 'go install[[:space:]]+"?[^"[:space:]]+' \
            | sed -E 's/go install[[:space:]]+"?//')"
        for ref in $refs; do
            # The '@${' pattern is a LITERAL to match (a ${VAR} ref, whose version is
            # pinned in the workflow itself), not an expansion — hence the quoting.
            # shellcheck disable=SC2016
            case "$ref" in
                *'@${'*) continue ;;
                *@v[0-9]*) continue ;;               # @v1.2.3
                *) echo "$name:$lineno: $ref" >> "$bad" ;;
            esac
        done
    done
done
if [ -s "$bad" ]; then
    echo "FAIL - go install without an exact pinned version:"
    sed 's/^/  /' "$bad"
    echo "  @latest silently adopts whatever upstream published most recently. Pin the version."
    exit 1
fi

# --- 3. an action must not be pinned to two different SHAs ------------------
for wf in $wfs; do
    grep -oE 'uses:[[:space:]]*[A-Za-z0-9._/-]+@[0-9a-f]{40}' "$wf" \
        | sed -E 's/^uses:[[:space:]]*//' \
        | while IFS= read -r ref; do
            printf '%s\t%s\n' "${ref%@*}" "${ref##*@}" >> "$pairs"
        done
done
sort -u "$pairs" | cut -f1 | sort | uniq -d | while IFS= read -r action; do
    [ -n "$action" ] || continue
    shas="$(awk -F'\t' -v a="$action" '$1==a{print $2}' "$pairs" | sort -u | tr '\n' ' ')"
    echo "$action pinned to multiple SHAs: $shas" >> "$bad"
done
if [ -s "$bad" ]; then
    echo "FAIL - inconsistent pinned action SHAs across workflows:"
    sed 's/^/  /' "$bad"
    exit 1
fi

echo "ok   - every third-party action is pinned to a full commit SHA"
echo "ok   - every go install pins an exact version"
echo "ok   - every SHA-pinned action is consistent across all workflows"
echo "ALL OK"
