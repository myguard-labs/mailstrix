# Disposable self-hosted runner contract

Mailstrix uses the shared `builder02`/`builder03` runner service. Each matching
self-hosted slot creates a fresh, single-job JIT runner identity and restores
that slot's trusted `pristine` golden snapshot after the job, whether the job
succeeds, fails, or is cancelled. Host deployment and snapshot management are
owned by that shared service; this repository must not require a project-only
organization runner group or a second dispatcher.

General workflows select `builder02` capacity with a `docker` or `lxc` profile.
These broad labels do not identify a unique physical slot. The
[runner isolation workflow](../workflows/runner-isolation.yml) additionally pins
both phases of each leave/prove pair to `ci-slot-builder02-runner-01` (LXC) or
`ci-slot-builder02-docker-01` (Docker). Each first job leaves a canary outside
`_work`; its successor must prove both the same physical identity and absence
of that canary. `RUNNER_NAME` is not identity evidence: the service may reuse a
name while issuing a fresh JIT registration.

The host service publishes `/run/myguard-ci-slot` as exactly two
newline-terminated lines: the CT name and `/opt/actions-runner`. It must
regenerate this metadata after successful restoration and before registering
a successor; uncertain restoration must stop scheduling. The canary requires
Python 3, already used by the CI fixture tests.

Leave validates the configured slot, profile and namespace, creates the canary,
then publishes its slot/profile/namespace/run/attempt/canary tuple. Prove checks
its metadata against the expected slot and producer tuple before examining
absence. Missing or malformed metadata, namespace errors and stale producer
attempts fail. A prove-only retry requires rerunning the complete workflow.
Workflow concurrency holds the complete pairs across branches. Host service
locking permits only one supervisor per physical slot; other repositories' jobs
may run between phases.

This is a correctness check for controlled jobs. The host supervisor and
restored execution environment are trusted; root-capable jobs can alter the
metadata and check. No cryptographic attestation or protection against deliberate
current-job tampering is claimed.

For live acceptance, dispatch with `cross_slot_control=true`. The extra job runs
on `ci-slot-builder02-runner-02` with the first LXC slot's producer output and
must fail with `slot identity mismatch` before checking absence. That manually
requested workflow is intentionally red; verify its actual runner assignments
and failure message. Normal PR runs omit this job.

Run local controls from the [repository root](../../README.md#build--test) with
`sh packaging/deb/runner_isolation_test.sh`. Explicit `--test-root` fixtures
exercise the production guard that forbids this option on Actions.
