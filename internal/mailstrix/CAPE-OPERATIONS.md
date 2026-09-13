# CAPE operator guide

CAPE detonation is disabled unless an administrator selects a configuration file
with `strixd serve -cape-config` or `MAILSTRIX_CAPE_CONFIG_FILE`. Selecting one
starts an optional HTTPS service and can resume persisted work. `static-only`
controls mail disposition; it does **not** prevent the enabled manual attachment
API from submitting eligible bytes. No mail adapter submits automatically, waits
for CAPE, or binds an unrelated manual job to a message. The Milter stays report-only.
`tempfail` and `quarantine-pending` are rejected; Rspamd requires the explicit
[include/preflight](../../contrib/rspamd/test/CAPE-policy.md) for startup rejection.

## Consent before activation

The administrator must record approval for the specific private endpoint/account,
tenant set, permitted attachment content, machine and sandbox network egress
policy. Agree who may manually submit on each tenant's behalf and which exact
signature rules produce local suspicious/malicious signals. `allow_unknown: true`
is an explicit eligibility choice: a successful static scan with no actionable
match is unknown, not independently clean. Actionable malicious matches and scan
errors are not admitted by the daemon's classifier.

Mailstrix cannot determine consent from attachment bytes or attest a sandbox's
network isolation. A syntactically valid numeric destination is not proof that
it is a private authorized deployment. Operators must enforce that boundary,
verify the supported CAPEv2 revision/profile named in the [transport guide](../cape/README.md),
and use a dedicated scoped upstream account. The transport uses fixed HTTPS,
certificate verification and a pinned numeric destination; no DNS, ambient proxy,
redirect or caller-supplied upstream URL is used.

Only exact selected attachment bytes leave Mailstrix, with a generated filename,
fixed machine and opaque correlation marker. Do not submit whole mail, original
filenames, sender/recipient metadata or recursively extracted children. Deployment
must disable automatic upstream fan-out or provide a complete descendant inventory
and cleanup procedure. No URL submission or report-artifact download is supported.

Record the remote reaper procedure and evidence covering original binaries,
artifacts, database reports, object stores, descendants and backups, including
submissions whose task ID was never returned. Establish a maximum remote retention
of 48 hours from submission. A native delete acknowledgement or a missing task
is insufficient. If this capability cannot be verified, keep detonation disabled.
There is no daemon consent flag that supplies this evidence automatically.

## Local storage and retention

Provision a dedicated private 0700 ext4/XFS filesystem with total capacity at most
2 GiB, as specified in [STORE.md](../cape/STORE.md). The runtime verifies geometry
and identity and rejects another mount of the device visible in its current mount
namespace, but its `/proc/self/mountinfo` view cannot prove host-global exclusivity
across other mount namespaces. Before production activation, retain trusted host
activation evidence that no other namespace mounts the device; without it, keep
CAPE disabled. The runtime reserves 128 MiB free space plus state/staging allowances.
A normal directory, tmpfs, overlay or a logical byte quota is not a substitute.
There is no configuration switch to bypass the check. Default logical quotas are
1,000 jobs/1 GiB globally and 100 jobs/100 MiB per tenant, with a hard attachment
ceiling of 10 MiB. Reservations include staging and retained cleanup debt;
even a duplicate requires temporary capacity. Full capacity returns 429.

These intervals are fixed by the implementation, not JSON retention settings:

<!-- markdownlint-disable MD013 -- fixed operational limits are clearest as a table -->

| Item | Lifetime / consequence |
| --- | --- |
| Staging ingress | 30-second absolute deadline, five-second idle deadline; reservation remains until the writer/classifier stops |
| Queued work | One hour from enqueue |
| Analysis | 24 hours from enqueue, including outages; retries do not extend it |
| Local payload | Removed after durable successful submission, or on cancellation/failure/expiry; failed local cleanup is retried |
| Ordinary terminal metadata/results | 24 hours from the first terminal transition; reads and cancellation never extend it |
| Remote cleanup attempts | Stop at 48 hours from the original attempt; unverified cleanup remains debt |
| Unresolved debt | No automatic expiry; at seven days from the submission attempt (`AttemptAt`, or `CreatedAt` if no attempt timestamp exists), the affected tenant's admission pauses; retained quotas can fill sooner |
<!-- markdownlint-enable MD013 -->

Raw reports are bounded, parsed in memory and discarded; only normalized local
signals are retained. A validated report with no mapped signal is `no_signal`,
not clean. Failed report reads expose `unavailable` while safe reads may retry;
a later valid report can recover before the original deadline. Neither outcome
lowers the current static concern or authorizes another POST.

Debt tombstones can outlive ordinary retention and retain identifiers including
tenant/job/task/generation/hash/correlation and cleanup reasons/timestamps. They
occupy the original quota and dedup barrier. Operators must explicitly accept
this data-minimization exception before activation. Local removal is unlinking,
not forensic secure erasure; encryption and backup policy remain operator-owned.
Exclude the spool/database from backups unless equivalent retention is enforced.

## Manual API workflow and operations

After deployment prerequisites are met, an authorized client uses the separate
HTTPS listener and one Bearer Authorization header. Tenant identity comes from
the token; `X-Mailstrix-CAPE-Profile` selects an allowed local profile. Upstream
tokens are separate reference-backed service credentials. Keep token values out
of command arguments, logs and examples. See [configuration](CAPE.md) for file/env
references and explicit token overlap; reference values are snapshotted at startup.

Submit bounded `application/octet-stream` bytes to `POST /v1/cape/jobs`; no multipart,
Content-Encoding, query string or caller static verdict is accepted. Save the
returned id and Location. A 202 means durable admission, not completion; 200 means
a reusable completed job. Poll that tenant's `GET /v1/cape/jobs/{id}` with bounded
Retry-After handling. The status exposes evidence separately from cleanup.
401 means tenant authentication failed or the selected generation's admission is
paused, even with valid tenant credentials. 400 means invalid/ineligible input,
413 oversize, 429 quota/rate pressure and 503 unavailable. A 409 with an
existing Location is retained unavailable work, not a new submission.
Wrong-tenant and absent IDs both
return 404. No API exposes raw reports or upstream task IDs.

`DELETE /v1/cape/jobs/{id}` cancels for the entire tenant-shared dedup job,
including completed work, immediately suppressing result reuse. It cannot promise
to stop an in-flight upload or remote analysis. Late task IDs still need cleanup.
Do not clear the database/spool or change generations to escape a barrier:
uncertain submissions are never automatically replayed. Correlation markers and
hash matches alone do not establish ownership or purge.

Keep old endpoint descriptors/credentials and exact old result-policy mappings
while retained jobs need them. Rotate policies additively; change the account or
generation label when an upstream account changes behind the same reference.
Restart to load repaired references. A persisted 401/403 generation pause is not
cleared merely by restarting: the store has an administrator resume method, but
the daemon exposes no resume/reconciliation command or endpoint. Likewise there
is no operator API to clear unknown debt, adopt tasks or certify remote purge.
Treat these as operational capability gaps, not instructions to edit SQLite.

Monitor retained jobs' reason/cleanup state and capacity. Native acknowledgement
is only `remote_delete_acknowledged_unverified`; the scheduler marks an exceeded
cleanup deadline internally, but the public status does not expose that flag
and no automatic external alert delivery is provided here.
Callbacks are not mounted by the daemon; authenticated polling is authoritative.
Removing CAPE configuration stops its maintenance too and does not erase existing
local data or remote work. Static scanning can continue during CAPE outages.

## Offline example validation and evidence limits

The [configuration example](CAPE.md#administrator-configuration) uses reserved
documentation addresses and reference names, with no real token or runnable
submission command. Validate its syntax against the actual configuration parser
from the repository root (using the project's normal Go/native build dependencies):

<!-- markdownlint-disable MD013 -- command is intentionally copyable -->

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test ./internal/mailstrix -run '^TestCAPEDocumentedConfiguration$' -count=1 -timeout=30s
```

<!-- markdownlint-enable MD013 -->

This test only reads the Markdown and parses the embedded JSON. It does not
resolve references, create a store, start a listener, scan a sample or send any
request. Missing build dependencies must be provisioned separately; this command
disables Go module/toolchain downloads and uses the installed Go version (which
must satisfy go.mod). Parsing is not activation validation.

Existing fake TLS/SQLite and startup tests cover local behavior using synthetic
bytes. Positive activation on a dedicated capped filesystem and physical spool
ENOSPC have **not been demonstrated**. SQLite page-cap tests and process crash
tests do not establish physical capacity or hardware power-loss durability.
Real remote reaper, unknown-task and descendant purge evidence is also absent.
Passing local tests or this documentation does not close those activation and
delivery acceptance requirements.
