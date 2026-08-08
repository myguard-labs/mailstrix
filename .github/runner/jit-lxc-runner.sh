#!/usr/bin/env bash
# One sealed LXC, one canonical workflow-job identity, one receipt.
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
policy="$script_dir/runner-policy.json"
usage() { echo "usage: $0 --profile P --run-id N --run-attempt N --job-id N [--role R] [--predecessor-key K]" >&2; exit 64; }

profile=""; run_id=""; run_attempt=""; job_id=""; role="generic"; predecessor_key=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile|--run-id|--run-attempt|--job-id|--role|--predecessor-key)
            [ "$#" -ge 2 ] || usage
            case "$1" in
                --profile) profile="$2" ;; --run-id) run_id="$2" ;; --run-attempt) run_attempt="$2" ;;
                --job-id) job_id="$2" ;; --role) role="$2" ;; --predecessor-key) predecessor_key="$2" ;;
            esac
            shift 2 ;;
        *) usage ;;
    esac
done
case "$profile" in docker|lxc) ;; *) usage ;; esac
case "$role" in generic|canary-leave|canary-prove) ;; *) usage ;; esac
case "$run_id:$run_attempt:$job_id" in *[!0-9:]*|:*|*::*) usage ;; esac
case "$role:$predecessor_key" in generic:?*|canary-leave:?*|canary-prove:) usage ;; esac

[ -r "$policy" ] || { echo "runner policy is missing" >&2; exit 1; }
command -v gh >/dev/null; command -v jq >/dev/null; command -v lxc >/dev/null; command -v timeout >/dev/null
group_name="$(jq -er '.runner_group.name' "$policy")"
organization="$(jq -er '.runner_group.organization' "$policy")"
snapshot="$(jq -er --arg p "$profile" '.profiles[$p].snapshot' "$policy")"
sha_env="$(jq -er --arg p "$profile" '.profiles[$p].snapshot_sha256_env' "$policy")"
command_timeout="$(jq -er '.lifecycle.command_timeout_seconds' "$policy")"
receipt_fresh="$(jq -er '.lifecycle.receipt_fresh_seconds' "$policy")"
max_seconds="$(jq -er '.lifecycle.max_seconds' "$policy")"
delete_attempts="$(jq -er '.lifecycle.delete_attempts' "$policy")"
delete_delay="$(jq -er '.lifecycle.delete_delay_seconds' "$policy")"
: "${RUNNER_GROUP_ID:?RUNNER_GROUP_ID is required}"; : "${RUNNER_ATTESTATION_DIR:?RUNNER_ATTESTATION_DIR is required}"; : "${GH_TOKEN:?GH_TOKEN is required}"
case "$RUNNER_GROUP_ID" in *[!0-9]*|'') exit 1 ;; esac
[ "$RUNNER_GROUP_ID" -gt 1 ] || { echo "Default runner group is forbidden" >&2; exit 1; }
expected_sha="${!sha_env:?$sha_env must pin the sealed snapshot digest}"
key="r${run_id}-a${run_attempt}-j${job_id}-${profile}-${role}"
[[ "$key" =~ ^r[0-9]+-a[0-9]+-j[0-9]+-(lxc|docker)-(generic|canary-leave|canary-prove)$ ]] || exit 1

run_external() { timeout --foreground --kill-after=5 "${command_timeout}s" "$@"; }
state_root="$RUNNER_ATTESTATION_DIR"
receipt_dir="$state_root/receipts"; claim_dir="$state_root/claims"; index_dir="$state_root/indexes"
mkdir -p "$receipt_dir" "$claim_dir" "$index_dir"; chmod 700 "$state_root" "$receipt_dir" "$claim_dir" "$index_dir"
receipt="$receipt_dir/$key.json"
[ ! -e "$receipt" ] || { echo "receipt already exists for canonical job identity" >&2; exit 1; }
claim="$claim_dir/$key"
if mkdir "$claim" 2>/dev/null; then
    started_epoch="$(date +%s)"; started_at="$(date --iso-8601=seconds)"
    instance="mailstrix-jit-${profile}-${run_id}-${run_attempt}-${job_id}-${role}-${started_epoch}-resume"
    jq -cn --arg key "$key" --arg instance "$instance" --argjson run "$run_id" --argjson attempt "$run_attempt" --argjson job "$job_id" --arg role "$role" --arg profile "$profile" --argjson started "$started_epoch" \
        '{key:$key,instance:$instance,run_id:$run,run_attempt:$attempt,job_id:$job,role:$role,profile:$profile,started_epoch:$started}' > "$claim/identity.json"
    chmod 600 "$claim/identity.json"
else
    jq -e --arg key "$key" '.key==$key and (.instance|type=="string")' "$claim/identity.json" >/dev/null || { echo "conflicting job claim" >&2; exit 1; }
    started_epoch="$(jq -er '.started_epoch' "$claim/identity.json")"
    started_at="$(date -d "@$started_epoch" --iso-8601=seconds)"
    instance="$(jq -er '.instance' "$claim/identity.json")"
fi
lease="$claim/lease"
mkdir "$lease" 2>/dev/null || { echo "job identity lease is active" >&2; exit 75; }
lease_meta="$lease/metadata.json"
renew_lease() {
    local now expiry tmp
    now="$(date +%s)"; expiry=$((now + max_seconds + command_timeout + 60)); tmp="$lease/.metadata.$$.tmp"
    jq -cn --argjson expires "$expiry" --argjson renewed "$now" '{expires_epoch:$expires,renewed_epoch:$renewed}' > "$tmp" && mv -f "$tmp" "$lease_meta"
}
renew_lease || { rm -rf "$lease"; exit 1; }
# From this point every pre-launch failure releases the active lease; the claim
# remains durable so a redelivery can resume its canonical instance safely.
trap 'rm -rf "$lease"' EXIT

actual_sha="$(run_external lxc config get "$snapshot" user.mailstrix.snapshot-sha256)"
if ! { [ -n "$actual_sha" ] && [ "$actual_sha" = "$expected_sha" ]; }; then
    echo "sealed snapshot digest mismatch" >&2
    exit 1
fi
predecessor='null'
if [ -n "$predecessor_key" ]; then
    [[ "$predecessor_key" =~ ^r${run_id}-a${run_attempt}-j[0-9]+-${profile}-canary-leave$ ]] || { echo "non-canonical predecessor key" >&2; exit 1; }
    predecessor_path="$receipt_dir/$predecessor_key.json"
    [ -f "$predecessor_path" ] || { echo "missing predecessor receipt" >&2; exit 1; }
    predecessor="$(cat "$predecessor_path")"
    now="$(date +%s)"
    jq -e --arg key "$predecessor_key" --argjson run "$run_id" --argjson attempt "$run_attempt" --arg profile "$profile" --argjson now "$now" --argjson fresh "$receipt_fresh" '
        .schema == 2 and .key == $key and .run_id == $run and .run_attempt == $attempt and
        .profile == $profile and .role == "canary-leave" and .deleted == true and
        .instance_absent == true and (.instance|type == "string" and length > 0) and
        (.snapshot.name|type == "string" and length > 0) and (.snapshot.sha256|type == "string" and length > 0) and
        (.started_epoch|type == "number") and (.deleted_epoch|type == "number") and
        .deleted_epoch >= .started_epoch and .deleted_epoch <= ($now + 30) and .deleted_epoch >= ($now - $fresh)
    ' >/dev/null <<<"$predecessor" || { echo "invalid, stale, or swapped predecessor receipt" >&2; exit 1; }
fi

attestation="$(jq -cn --arg key "$key" --arg group "$group_name" --arg profile "$profile" --arg instance "$instance" --arg snapshot "$snapshot" --arg sha "$actual_sha" --arg role "$role" --arg started "$started_at" --argjson run "$run_id" --argjson attempt "$run_attempt" --argjson job "$job_id" --argjson group_id "$RUNNER_GROUP_ID" --argjson predecessor "$predecessor" --argjson started_epoch "$started_epoch" \
 '{schema:2,key:$key,run_id:$run,run_attempt:$attempt,job_id:$job,runner_group:$group,runner_group_id:$group_id,profile:$profile,role:$role,instance:$instance,snapshot:{name:$snapshot,sha256:$sha},started_at:$started,started_epoch:$started_epoch,predecessor:$predecessor}')"
launch_attempted=0
launched=0

# 0=present; 1=authoritatively absent (successful list returned []); 2=operational error.
instance_state() {
    local listing
    listing="$(run_external lxc list "$instance" --format json)" || return 2
    jq -e --arg instance "$instance" 'type == "array" and ((length == 0) or (length == 1 and .[0].name == $instance))' >/dev/null <<<"$listing" || return 2
    [ "$(jq 'length' <<<"$listing")" -eq 0 ] && return 1
    return 0
}
write_receipt() {
    local finished epoch tmp
    finished="$(date --iso-8601=seconds)"; epoch="$(date +%s)"; tmp="$receipt_dir/.${key}.$$.tmp"
    jq -cn --argjson launch "$attestation" --arg finished "$finished" --argjson epoch "$epoch" '$launch + {deleted:true,instance_absent:true,deleted_at:$finished,deleted_epoch:$epoch}' > "$tmp"
    chmod 600 "$tmp"
    ln "$tmp" "$receipt" 2>/dev/null || { rm -f "$tmp"; echo "receipt collision" >&2; return 1; }
    rm -f "$tmp"
}
cleanup() {
    local attempt=1 state
    renew_lease || return 1
    [ "$launch_attempted" -eq 1 ] || return 0
    while [ "$attempt" -le "$delete_attempts" ]; do
        if instance_state; then state=0; else state=$?; fi
        case "$state" in 1) if [ "$launched" -eq 1 ]; then write_receipt; return $?; fi; return 0 ;; 2) echo "cannot establish LXC absence" >&2; return 1 ;; esac
        run_external lxc delete --force "$instance" >/dev/null 2>&1 || true
        if instance_state; then state=0; else state=$?; fi
        case "$state" in 1) if [ "$launched" -eq 1 ]; then write_receipt; return $?; fi; return 0 ;; 2) echo "cannot establish post-delete LXC absence" >&2; return 1 ;; esac
        attempt=$((attempt + 1)); sleep "$delete_delay"
    done
    echo "failed to delete JIT LXC after $delete_attempts attempts" >&2; return 1
}
on_exit() { local status=$? cleanup_status=0; trap - EXIT INT TERM; cleanup || cleanup_status=1; rm -rf "$lease"; [ "$cleanup_status" -eq 0 ] || exit 1; exit "$status"; }
on_signal() { local code="$1" cleanup_status=0; trap - EXIT INT TERM; cleanup || cleanup_status=1; rm -rf "$lease"; [ "$cleanup_status" -eq 0 ] || exit 1; exit "$code"; }
trap on_exit EXIT; trap 'on_signal 130' INT; trap 'on_signal 143' TERM

labels="$(jq -cn --arg profile "$profile" --arg role "$role" '["self-hosted","mailstrix","ephemeral",$profile] + if $role == "generic" then [] else [$role] end')"
jit_config="$(jq -cn --arg name "$instance" --argjson group "$RUNNER_GROUP_ID" --argjson labels "$labels" '{name:$name,runner_group_id:$group,labels:$labels,work_folder:"_work"}' | run_external gh api --method POST "orgs/${organization}/actions/runners/generate-jitconfig" --input - --jq '.encoded_jit_config')"
[ -n "$jit_config" ] || { echo "empty JIT configuration" >&2; exit 1; }
if instance_state; then
    marker="$(run_external lxc config get "$instance" user.mailstrix.jit-key)"
    [ "$marker" = "$key" ] || { echo "existing claimed instance has wrong ownership marker" >&2; exit 1; }
    launch_attempted=1; launched=1
else
    state=$?
    [ "$state" -eq 1 ] || { echo "cannot inspect partial launch state" >&2; exit 1; }
    launch_attempted=1
    # LXD accepts -c at creation, so ownership exists in the same request that
    # creates the clone; the claim still records this deterministic name for a
    # crash between request submission and response.
    run_external lxc launch "$snapshot" "$instance" --ephemeral -c "user.mailstrix.jit-key=$key"
    launched=1
fi
# shellcheck disable=SC2016
printf '%s' "$attestation" | timeout --foreground --kill-after=5 "${command_timeout}s" lxc exec "$instance" --mode=noninteractive -- bash -ceu 'install -d -m 700 /run/mailstrix-jit; cat > /run/mailstrix-jit/attestation.json; chmod 600 /run/mailstrix-jit/attestation.json'
# shellcheck disable=SC2016
printf '%s' "$jit_config" | timeout --foreground --signal=TERM --kill-after=60 "${max_seconds}s" lxc exec "$instance" --mode=noninteractive -- bash -ceu 'config="$(cat)"; [ -n "$config" ]; exec /opt/actions-runner/run.sh --jitconfig "$config"'
