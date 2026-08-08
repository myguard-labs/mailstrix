#!/usr/bin/env bash
# Reap only stale, marker-owned JIT LXCs; never infer ownership from a prefix.
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"; policy="$script_dir/runner-policy.json"
usage() { echo "usage: $0 --dry-run|--apply" >&2; exit 64; }
[ "$#" -eq 1 ] || usage
case "$1" in --dry-run) apply=0 ;; --apply) apply=1 ;; *) usage ;; esac
command -v jq >/dev/null; command -v lxc >/dev/null; command -v timeout >/dev/null
: "${RUNNER_ATTESTATION_DIR:?RUNNER_ATTESTATION_DIR is required}"
bound="$(jq -er '.lifecycle.reconcile_after_seconds' "$policy")"; command_timeout="$(jq -er '.lifecycle.command_timeout_seconds' "$policy")"
run_external() { timeout --foreground --kill-after=5 "${command_timeout}s" "$@"; }
now="$(date +%s)"; failed=0
claim_root="$RUNNER_ATTESTATION_DIR/claims"; receipt_root="$RUNNER_ATTESTATION_DIR/receipts"
# A claim is intentionally retained after a receipt (dedup/audit trail).  Only
# an unreceipted, canonically named claim beyond the same lifecycle bound may be
# removed; this cannot race an in-bound job on another dispatcher host.
if [ -d "$claim_root" ]; then
    for claim in "$claim_root"/*; do
        [ -d "$claim" ] || continue
        key="${claim##*/}"
        [[ "$key" =~ ^r[0-9]+-a[0-9]+-j[0-9]+-(lxc|docker)-(generic|canary-leave|canary-prove)$ ]] || continue
        [ -e "$receipt_root/$key.json" ] && continue
        started="$(jq -er '.started_epoch' "$claim/identity.json" 2>/dev/null)" || continue
        case "$started" in *[!0-9]*|'') continue ;; esac
        [ $((now-started)) -gt "$bound" ] || continue
        expiry="$(jq -er '.expires_epoch // 0' "$claim/lease/metadata.json" 2>/dev/null || echo 0)"
        [ "$expiry" -le "$now" ] || continue
        instance="$(jq -er '.instance' "$claim/identity.json" 2>/dev/null)" || continue
        [[ "$instance" =~ ^mailstrix-jit-(lxc|docker)-[0-9]+-[0-9]+-[0-9]+-(generic|canary-leave|canary-prove)-[0-9]+-resume$ ]] || continue
        present="$(run_external lxc list "$instance" --format json)" || { failed=1; continue; }
        if jq -e 'type == "array" and length == 1' >/dev/null <<<"$present"; then
            if [ "$apply" -eq 0 ]; then
                printf 'would delete claim-recorded partial LXC %s\n' "$instance"
            elif ! run_external lxc delete --force "$instance"; then
                failed=1
                continue
            fi
        fi
        if [ "$apply" -eq 0 ]; then
            printf 'would remove stale JIT claim %s\n' "$key"
            continue
        fi
        absent="$(run_external lxc list "$instance" --format json)" || { failed=1; continue; }
        jq -e 'type == "array" and length == 0' >/dev/null <<<"$absent" || { failed=1; continue; }
        rm -rf "$claim"
    done
fi
listing="$(run_external lxc list --format json)" || exit 1
while IFS=$'\t' read -r name status; do
    [[ "$name" =~ ^mailstrix-jit-(lxc|docker)-([0-9]+)-([0-9]+)-([0-9]+)-(generic|canary-leave|canary-prove)-([0-9]+)-resume$ ]] || continue
    profile="${BASH_REMATCH[1]}"; run_id="${BASH_REMATCH[2]}"; attempt="${BASH_REMATCH[3]}"; job_id="${BASH_REMATCH[4]}"; role="${BASH_REMATCH[5]}"; stamp="${BASH_REMATCH[6]}"
    [ $((now-stamp)) -gt "$bound" ] || continue
    key="r${run_id}-a${attempt}-j${job_id}-${profile}-${role}"
    marker="$(run_external lxc config get "$name" user.mailstrix.jit-key)" || { failed=1; continue; }
    [ "$marker" = "$key" ] || continue
    if [ "$apply" -eq 0 ]; then printf 'would delete stale owned JIT LXC %s (%s)\n' "$name" "$status"; continue; fi
    run_external lxc delete --force "$name" || { failed=1; continue; }
    remains="$(run_external lxc list "$name" --format json)" || { failed=1; continue; }
    jq -e 'type == "array" and length == 0' >/dev/null <<<"$remains" || { echo "owned orphan remains: $name" >&2; failed=1; }
done < <(jq -r '.[] | [.name, .status] | @tsv' <<<"$listing")
exit "$failed"
