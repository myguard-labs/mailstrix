#!/usr/bin/env bash
# Run only a signature-verified, policy-authorized workflow_job delivery.
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"; policy="$script_dir/runner-policy.json"; launcher="$script_dir/jit-lxc-runner.sh"
usage() { echo "usage: $0 --delivery-id ID --event verified-workflow-job.json" >&2; exit 64; }
if ! { [ "$#" -eq 4 ] && [ "$1" = "--delivery-id" ] && [ "$3" = "--event" ]; }; then usage; fi
delivery="$2"; event="$4"
[[ "$delivery" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || usage
[ -r "$event" ] && [ -r "$policy" ] || exit 1
command -v jq >/dev/null
: "${RUNNER_ATTESTATION_DIR:?RUNNER_ATTESTATION_DIR is required}"
state="$RUNNER_ATTESTATION_DIR"; deliveries="$state/deliveries"; indexes="$state/indexes"
mkdir -p "$deliveries" "$indexes"; chmod 700 "$state" "$deliveries" "$indexes"
delivery_dir="$deliveries/$delivery"
if mkdir "$delivery_dir" 2>/dev/null; then
    printf '%s\n' received > "$delivery_dir/state"
else
    # Redelivery resumes an incomplete durable delivery rather than silently
    # acknowledging it. Completed deliveries remain idempotent.
    state_name="$(cat "$delivery_dir/state" 2>/dev/null || true)"
    [ "$state_name" = completed ] && exit 0
fi

action="$(jq -er '.action' "$event")"; full_name="$(jq -er '.repository.full_name' "$event")"
workflow="$(jq -er '.workflow_job.workflow_name' "$event")"; job_name="$(jq -er '.workflow_job.name' "$event")"
base_job="${job_name%% (*}"
run_id="$(jq -er '.workflow_job.run_id|tostring' "$event")"; attempt="$(jq -er '.workflow_job.run_attempt|tostring' "$event")"; job_id="$(jq -er '.workflow_job.id|tostring' "$event")"
source_ref="$(jq -er '.workflow_job.head_branch // .workflow_job.head_sha' "$event")"
labels="$(jq -cer '.workflow_job.labels' "$event")"
repository="$(jq -er '.runner_group.repository' "$policy")"; ref_regex="$(jq -er '.dispatcher.allowed_ref_regex' "$policy")"
if ! { [ "$action" = queued ] && [ "$full_name" = "$repository" ]; }; then
    echo "unauthorized delivery" >&2
    exit 1
fi
[[ "$source_ref" =~ $ref_regex ]] || { echo "unauthorized ref" >&2; exit 1; }
jq -e --arg workflow "$workflow" --arg job "$base_job" '.dispatcher.workflows[$workflow] | index($job) != null' "$policy" >/dev/null || { echo "workflow/job is not allow-listed" >&2; exit 1; }
profile="$(jq -er '([.[]|select(.=="lxc" or .=="docker")]) | if length==1 then .[0] else error("profile") end' <<<"$labels")"
role="$(jq -er '([.[]|select(.=="canary-leave" or .=="canary-prove")]) | if length==0 then "generic" elif length==1 then .[0] else error("role") end' <<<"$labels")"
jq -e --arg workflow "$workflow" --arg job "$base_job" --arg profile "$profile" --arg role "$role" '
    .dispatcher.routes[$workflow][$job] as $route | $route[1] == $role and ($route[0] == "matrix" or $route[0] == $profile)
' "$policy" >/dev/null || { echo "profile/role route is not policy-authorized" >&2; exit 1; }
jq -e --arg profile "$profile" --arg role "$role" '
  .runner_group.name == "mailstrix-jit" and
  (["self-hosted","mailstrix","ephemeral",$profile] + if $role=="generic" then [] else [$role] end) as $required |
  (($required | sort) == ($ARGS.named.labels | sort))
' --argjson labels "$labels" "$policy" >/dev/null || { echo "required JIT labels/group rejected" >&2; exit 1; }

key="r${run_id}-a${attempt}-j${job_id}-${profile}-${role}"
printf '%s\n' "$key" > "$deliveries/$delivery/key"
receipt="$state/receipts/$key.json"
# A crash after the launcher completed but before the delivery state flip is
# resolved from the canonical receipt, not by a second runner registration.
if jq -e --arg key "$key" '.schema==2 and .key==$key and .deleted==true and .instance_absent==true' "$receipt" >/dev/null 2>&1; then
    printf '%s\n' completed > "$delivery_dir/state"
    exit 0
fi
printf '%s\n' authorized > "$delivery_dir/state"
if [ "$role" = canary-leave ]; then
    index="$indexes/${run_id}-${attempt}-${profile}-canary-leave"
    tmp="$indexes/.${delivery}.tmp"; printf '%s\n' "$key" > "$tmp"
    if ! ln "$tmp" "$index" 2>/dev/null; then
        existing="$(cat "$index" 2>/dev/null || true)"
        rm -f "$tmp"
        [ "$existing" = "$key" ] || { echo "canary predecessor index conflicts with canonical key" >&2; exit 1; }
    fi
    rm -f "$tmp"
fi
if [ "$role" = canary-prove ]; then
    index="$indexes/${run_id}-${attempt}-${profile}-canary-leave"
    wait_seconds="$(jq -er '.lifecycle.predecessor_wait_seconds' "$policy")"; elapsed=0
    while [ ! -r "$index" ] && [ "$elapsed" -lt "$wait_seconds" ]; do sleep 1; elapsed=$((elapsed+1)); done
    [ -r "$index" ] || { echo "timed out waiting for predecessor index" >&2; exit 1; }
    predecessor="$(cat "$index")"
    [[ "$predecessor" =~ ^r${run_id}-a${attempt}-j[0-9]+-${profile}-canary-leave$ ]] || { echo "invalid predecessor index" >&2; exit 1; }
    receipt="$state/receipts/$predecessor.json"
    elapsed=0
    while [ ! -r "$receipt" ] && [ "$elapsed" -lt "$wait_seconds" ]; do sleep 1; elapsed=$((elapsed+1)); done
    [ -r "$receipt" ] || { echo "timed out waiting for exact predecessor receipt" >&2; exit 1; }
    jq -e --arg key "$predecessor" --argjson run "$run_id" --argjson attempt "$attempt" --arg profile "$profile" '
        .schema == 2 and .key == $key and .run_id == $run and .run_attempt == $attempt and
        .profile == $profile and .role == "canary-leave" and .deleted == true and .instance_absent == true
    ' "$receipt" >/dev/null || { echo "invalid exact predecessor receipt" >&2; exit 1; }
    printf '%s\n' launching > "$delivery_dir/state"
    "$launcher" --profile "$profile" --run-id "$run_id" --run-attempt "$attempt" --job-id "$job_id" --role "$role" --predecessor-key "$predecessor"
    printf '%s\n' completed > "$delivery_dir/state"
    exit 0
fi
printf '%s\n' launching > "$delivery_dir/state"
"$launcher" --profile "$profile" --run-id "$run_id" --run-attempt "$attempt" --job-id "$job_id" --role "$role"
printf '%s\n' completed > "$delivery_dir/state"
