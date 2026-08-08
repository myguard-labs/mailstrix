# Ephemeral GitHub Actions runners

Every self-hosted job routes to the non-default `mailstrix-jit` runner group
and requires `self-hosted`, `mailstrix`, `ephemeral`, plus exactly one profile
label (`docker` or `lxc`).  The group must be organization-scoped, `selected`
only for `myguard-labs/mailstrix`, and restricted to this repository's reviewed
workflow files.  Never put a JIT runner in the Default group.

`runner-policy.json` is the versioned deployment contract.  It names the group,
the two sealed snapshots, and the environment variables that pin their digest.
After verifying the GitHub webhook signature, the dispatcher invokes
`dispatch-workflow-job.sh --delivery-id <GitHub delivery ID> --event <trusted
payload>` once for each queued `workflow_job`; that helper authorizes the
repository, workflow/job, ref, labels, and group policy before atomically
claiming both the delivery and the canonical run/attempt/job identity.

```sh
RUNNER_GROUP_ID=<mailstrix-jit group ID>
RUNNER_REPOSITORY=myguard-labs/mailstrix
RUNNER_ATTESTATION_DIR=/var/lib/mailstrix-jit/attestations
RUNNER_LXC_SNAPSHOT_SHA256=<sealed digest>
RUNNER_DOCKER_SNAPSHOT_SHA256=<sealed digest>
.github/runner/dispatch-workflow-job.sh --delivery-id <delivery> --event <verified-event>
```

The two canary-only labels (`canary-leave` and `canary-prove`) are a dispatch
protocol, not capacity labels.  The helper derives durable keys from the GitHub
run ID, run attempt, exact job ID, profile, and role, and passes the exact first
key as the prove job's predecessor. It rejects duplicate delivery/job claims,
ambiguous labels, path-like keys, stale receipts, and an absent/deletion-unverified predecessor. The
durable attestation directory must be shared by every dispatcher host and
writable only by the dispatcher service.  Before launch, the script verifies the LXC snapshot's
`user.mailstrix.snapshot-sha256` against the profile pin.  After the runner
stops it retries forced deletion, distinguishes a successful empty LXC list
from an operational query error, and only then writes a collision-safe receipt.
The next clone receives that predecessor receipt at
`/run/mailstrix-jit/attestation.json`, which the canary prints into the GitHub
job log.  This makes a green canary evidence of both a sealed clone and prior
instance deletion, not merely two jobs landing on different persistent hosts.

The launcher has a 65-minute default lifetime and does not suppress a failed
delete. The dispatcher waits up to 120 seconds for the predecessor's durable
deletion receipt, covering GitHub's normal job-complete/runner-exit race.
Install the included systemd service/timer on each dispatcher host to
reconcile only marker-owned stale `mailstrix-jit-<profile>-...` instances and
unreceipted expired claims, using the single bound in `runner-policy.json`. Run
the reconciler with `--dry-run` first; it needs `--apply` to delete anything.

`GH_TOKEN` is supplied through the dispatcher service environment, never a
workflow, command line, or repository file.  For the organization JIT endpoint
and the `mailstrix-jit` group, a fine-grained GitHub App or PAT needs the
organization **Self-hosted runners: write** permission (and repository
Metadata: read when configuring selected-repository access).  A repository-only
JIT implementation instead requires repository **Administration: write**;
that is insufficient to administer this organization runner group.  Classic
PATs require `admin:org`. Keep the
group's repository and workflow allow-lists enforced outside this checkout.

Snapshots must contain `gh`, `jq`, `timeout`, `python3`, and the `python3-yaml`
module used by the structural routing guard. Snapshot preparation, authenticated
webhook delivery, durable attestation storage, and systemd installation are host
operations deliberately outside this repository.
