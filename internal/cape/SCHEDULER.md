# CAPE scheduler checkpoint

`NewScheduler` takes an already opened private store, a fixed generation-to-client
map, an explicit trusted result mapper and 1–8 workers. `Run` is the sole
network scheduler owner for the store. Importing the package starts nothing;
no API listener, adapter, production settings, credential lookup or CAPE endpoint
is enabled by this building block. Keep clients for old endpoint/account/profile
generations until their debt is resolved. Generation keys must match the client;
no request can substitute the current generation for an old job.

Run local maintenance every iteration, including outages. It retries local payload
removal after committed submission success while a job is remote_pending or
fetching, without changing ownership or permitting another submission.
One request occupies one bounded worker. The eight-worker ceiling bounds
simultaneously retained report bodies to 64 MiB before decoded structures;
live uploads also occupy the store's deployment/tenant
submission slots until their outcomes commit, including after cancellation.
Eligible owned-task deletion is selected first, with a separate tenant rotation
for deletion and submission/poll traffic. All requests consume the same persisted
total budget; submission additionally consumes its persistent deployment/tenant
attempt budgets. A restart never refills those budgets.

Only a nil `BeginSubmission` error authorizes opening the payload and sending.
Any error is reconciled from the current durable job. A possibly committed
attempt is recorded uncertain without sending or claiming positive no-send proof.
Payload-open failures also become uncertain. The transport's explicit positive
`NoBytesSent` proof alone permits a bounded queued retry. Startup converts
submitting rows to uncertain; the scheduler never automatically submits those.

Safe reads persist their next attempt before dispatch. Exponential jitter stays
between five seconds and five minutes; throttled Retry-After can only extend that
retry time, within the transport's five-minute bound. Original one-hour queue and
24-hour analysis deadlines never move. Callback hints are cleared only with
checked work and cannot advance the persisted next attempt, bypass a request
token, resurrect a terminal job or supply a verdict. Polling works without hints.

Only `reported` transitions remote_pending to fetching. A transport-validated
report retains its exact task, generation and digest privately; publication
rechecks that identity, the mutable document envelope and the current persisted
state/version. It checks the persisted state/version again after trusted
normalization, so cancellation, expiry or concurrent callback updates cannot be
overwritten. Normalization
schema version 1 contains only an admitted result-policy identifier, the typed
malicious/suspicious/no_signal evidence and at most 128 distinct bounded local
signal identifiers, within the existing 16 KiB cap. There is no default policy
mapper. Missing/invalid mapping fails unavailable with no result. `SignatureMapper`
maps exact signature names under operator-selected rules; the daemon builds
these mappers from [`signal_policies` configuration](../mailstrix/CAPE.md).
Operators must select the signal interpretation policy before activation.
Raw report documents are never
written to SQLite, spool, logs or an API. The immutable static verdict is retained.

Cancellation/shutdown cancel owned requests and join their workers. Late IDs are
still recorded with the original submission version under contexts independent
of caller cancellation. Failed durable outcomes remain in a bounded in-memory
pending list; new network dispatch pauses until it drains. Shutdown retries for
30 seconds after joining network requests (each transport operation has its own
30-second limit). Every persistence pass uses the earlier of its five-second
bound and that single absolute drain deadline; retry waits share the deadline.
An exhausted drain budget starts no further pass.
If storage remains unavailable, Run returns `ErrStoreUnavailable` and keeps the
pending packets in that scheduler object. Repair storage and call Run again
before discarding the object or closing the store. Process loss at this boundary
can lose newly returned IDs; durable uncertainty still prevents another POST and
retains unknown debt. This is not an exactly-once or durable-ID promise during a
storage outage. Cooperative credential providers and mappers must obey contexts.
`Store.Close` refuses while Run is active.

401/403 responses durably pause that generation's detonation admission and queued
submissions. Authenticated read/cleanup maintenance remains possible. Only the
administrator's `SetGenerationAdmission(..., true)` following credential repair
resumes it. No pause changes static scanning. No credential value enters the DB.

Known owned tasks are deleted after completion/cancel/failure/expiry. An exact
native acknowledgement remains `remote_delete_acknowledged_unverified`; missing,
orphaned and timed-out responses remain debt. The scheduler stops remote cleanup
attempts at 48 hours from the original attempt and persists
`CleanupDeadlineExceeded`, including acknowledged-but-unverified debt. Ordinary
retention cannot hide this debt; the existing seven-day tenant pause and retained
job/byte capacity still apply. Alert/API wiring for this field remains integration
work. It is not a remote purge certificate.

Operator reconciliation remains an explicit external capability gap: no pinned
authenticated API establishes tenant/account + opaque marker + hash + profile
ownership, descendant inventory or complete purge across artifacts/backups.
Hash coincidence and missing task responses cannot settle it. No adoption,
unknown-debt clearing or audited resubmission interface is provided until that
evidence contract is verified. Polling and truthful local debt handling are
available without it; deployment activation remains blocked by CA06/08 storage,
reaper, unknown-task and descendant evidence requirements.

Tests use fake TLS, inert bytes and real temporary SQLite with a package-private
capacity probe. They include actual POST/request counts, restart, post-commit
begin errors, live occupancy, late cancellation, failed outcome persistence,
bounded shutdown failure, deletion fairness, generation routing, total budget,
backoff/hints, identity/mapper races and debt boundaries. These do not establish
production physical quota enforcement, real CAPE compatibility or remote purge.
