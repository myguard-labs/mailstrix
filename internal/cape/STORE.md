# Durable CAPE store checkpoint

`OpenStore` is an optional local building block; nothing activates it or submits
HTTP requests. Configuration requires an explicit tenant allowlist. The caller
provides the authenticated tenant, profile generation and policy versions.
`Enqueue` takes ownership of an `io.ReadCloser`; its `Close` must unblock a
concurrent `Read`, as an HTTP request body does. If a reader violates that
contract, its reservation remains occupied until its writer actually stops.

The production storage subset is Linux with an **already provisioned dedicated
ext4 or XFS filesystem mounted at the configured private 0700 directory**. Its
kernel-reported total allocation capacity must be at most 2 GiB and large enough
for the reserved state budget. The store verifies mount identity, filesystem
type, mount root, geometry, available space and that the device has a unique
mount visible in its current mount namespace at startup and before every
admission. A subdirectory, bind subtree, device mounted more than once in that
namespace, oversized filesystem, network filesystem, tmpfs or overlay is
rejected. This check reads `/proc/self/mountinfo`; it cannot prove host-global
exclusivity across other mount namespaces. Production activation therefore
requires trusted host activation evidence that no other namespace mounts the
device. Without that evidence, keep CAPE disabled. Other operating systems build
and return `cape_store_unavailable`. The store does not provision filesystems or
accept an operator assertion as enforcement.

The physical bound comes from filesystem geometry. Available-space checks alone
do not establish a cap. Admission additionally leaves 128 MiB unused and accounts
for all outstanding full staging reservations, one allocation block per staged
file, and a conservative three times the 64 MiB SQLite database limit for
database/WAL/checkpoint growth. Default logical quotas remain 1000/100 records
and 1 GiB/100 MiB globally/per tenant, including staging and retained records.
The full configured attachment ceiling plus 4 KiB metadata and 16 KiB result
allowances is reserved transactionally before any input is read. Attachment
limits cannot exceed 10 MiB. Dedup requires temporary admission capacity too.

One permanent lock inode enforces a single process owner. SQLite uses one
connection, WAL, FULL synchronous writes, a one-second busy timeout and bounded
pages; required PRAGMAs are read back. Readers never retain database cursors
outside the store mutex. Automatic checkpoints run every 32 pages, with explicit
truncate checkpoints on publication/outcome and shutdown. Files use exclusive
creation and descriptor-relative operations without symlink traversal. The
database path remains attached to the held directory descriptor.

Ingress has persisted 30-second absolute and five-second idle deadlines. After
writing and hashing, the file is synced, renamed without replacement, and its
directory synced before queued publication. A failure never acknowledges an
enqueue. Failed staging cleanup keeps its reservation if files cannot be
removed and directory-synced; startup must reconcile before admitting anything.
A crash after queued commit may leave a durable job whose client never received
the response: a subsequent request can discover it through scoped dedup.

`BeginSubmission` checks tenant, expected version/state, original deadlines,
concurrency and persisted deployment/tenant/total request tokens before committing
`submitting`. Only a nil error from `BeginSubmission` permits the scheduler
to send bytes. Restart converts
every `submitting` row to `submit_uncertain`, preserving age and a dedup barrier.
`RecordSubmission` stores validated bounded task IDs under the job's generation,
records uncertainty, or permits bounded retry only with positive no-bytes-sent
proof. A durable success precedes local payload removal. Rate buckets do not
reset on restart, refill by elapsed UTC time up to one minute, and clock rollback
over five seconds pauses admission/attempts. Ambiguous outcome recording remains
possible during rollback so task ownership is not discarded.

Both methods can return an error after durably advancing state and version:
`BeginSubmission` can fail its checkpoint after commit, and `RecordSubmission`
can fail local payload cleanup or its checkpoint after storing task IDs. An
error does not imply rollback, and a nonzero returned `Job` with an error does
not authorize sending or blind retry. Callers must use tenant-scoped `Lookup`
and reconciliation to establish authoritative state, keeping an ambiguous
attempt conservatively uncertain until reconciled. On `RecordSubmission`
errors, retain ownership of supplied and returned tasks for reconciliation;
never blindly repeat the POST.

The CA04 lifecycle foundation adds tenant-scoped `Cancel` and `RecordDeletion`,
and store-wide `Maintain`. `Cancel` suppresses completed results immediately
and never changes the first `terminal_at`. A staging cancellation signals the
live writer; the returned staging snapshot is not an assertion that the writer
has stopped.
The writer removes its reservation only after stopping. Cancelling an upload
does not promise to stop upstream work. `BeginSubmission` persists a separate
attempt version; pass that original version to `RecordSubmission`, including
after concurrent cancellation or expiry. A recorded outcome cannot be replayed.
Late responses retain bounded valid IDs and cleanup ownership without reopening
terminal jobs. Multiplicity fails terminally with known IDs and unknown debt.

Restrictive cancellation remains available during clock rollback, using the
persisted high-water timestamp without unpausing admission. Live submission
occupancy survives cancellation until its outcome is durably recorded; restart
abandons in-process occupancy while retaining unresolved remote debt. A scheduler
must close the outbound request before recording its outcome. Maintenance scans
the absolute supported record bound even after admission quotas are lowered,
and unchanged terminal metadata does not advance versions or invalidate cleanup
responses; local file cleanup is still retried.

`Maintain` is called regularly by the scheduler, including during
outages. It enforces the original one-hour queue and 24-hour analysis deadlines,
commits terminal state before unlinking payloads, and removes ordinary terminal
records 24 hours after their first terminal transition. Uncertain/unverified
debt survives as a suppressed tombstone under the original quota and dedup key.
Cleanup failures leave retryable state; rerun maintenance. Cancellation and
maintenance errors can follow durable transitions, so use `Lookup` to reconcile.

`RecordDeletion` accepts a terminal job's expected current version and an owned
generation/task reference, tracking each native acknowledgement. A stale version
requires lookup and retry of the local record operation, not blindly repeating
the remote deletion request. Missing tasks and errors remain debt. Acknowledged
native deletion is always unverified; it cannot clear the barrier or establish
purge. No operator reconciliation interface or real remote cleanup is provided
by these methods.

The scheduler and checked publication building blocks are documented in
SCHEDULER.md; the optional authenticated receiver is documented in CALLBACK.md.
Operator reconciliation with purge evidence, production activation and remote
purge verification remain incomplete. These local components are not mounted
or enabled by this package.

Tests use real temporary SQLite databases, small synthetic bytes, fake clocks,
an explicit **package-private test capacity probe**, and subprocess exits at
durable crash points. Tests cover actual SQLite page-cap exhaustion and
production rejection of unverified storage. No positive activation test on a
real dedicated capped filesystem has run; test capacity probes do not establish
physical enforcement on the host or prove power-loss behavior of its hardware.
No real CAPE request, credential lookup or host storage change is involved.

Driver: [modernc.org/sqlite v1.58.0](https://pkg.go.dev/modernc.org/sqlite@v1.58.0),
pure Go, BSD-3-Clause, verified against its official package documentation.
Durability and sizing follow SQLite's [WAL documentation](https://www.sqlite.org/wal.html)
and [PRAGMA reference](https://www.sqlite.org/pragma.html).
