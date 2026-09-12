# CAPE transport profile

Local opt-in transport only; importing this package activates no service. Supported
source profile: CAPEv2 `471ee4bb422ec4aa0f1aa1089540a1ad0b7d84f0`.

`New` requires an administrator-selected HTTPS origin, an explicit approved numeric
destination/port, generation, one machine, credential reference and runtime token
provider. It dials only that destination, retaining the original hostname for TLS
verification. Optional PEM replaces system roots. There is no DNS resolution,
ambient proxy, cookie jar, redirect, compression, URL submission or arbitrary
request options. Source `Close` and credential-provider cancellation must cooperate
with context cancellation; the transport cannot interrupt an arbitrary malicious
Go implementation. Default connection/TLS handshake bounds are 5 seconds; the
whole operation has a 30-second context with earlier caller deadlines preserved.

`Submit` owns and closes an immutable `io.ReadCloser`. It streams exactly the
declared size (1 byte through 10 MiB), probes one extra byte without uploading it,
and generates the filename. The caller first persists a random 128-bit lowercase
hex correlation marker and attempt state; the marker is not an idempotency key or
ownership proof. The only multipart fields are `machine`, `custom`, and `file`.

Every error after invoking the transport is conservatively uncertain. Always
persist returned `Tasks` even with an error; up to 16 valid unique IDs are recovered
from confidently parsed elements of the expected `data.task_ids` array, including
before a trailing syntax/size/read failure. IDs in unrelated text/objects are not
adopted. Partial errors, duplicates, multiplicity, invalid IDs, malformed JSON and
overflow leave `UnknownDebt`; no absence of IDs proves absence of remote work.
Only pre-transport rejection is reported as `NoBytesSent`.

All retries belong to the durable scheduler, including safe reads and GET deletion.
No automatic HTTP retries occur. The scheduler must disable admission on
`Unauthorized`, honor the bounded throttle hint, retain absolute job deadlines,
and never replay uncertain POSTs. `TaskRef` is supplied from an authorized durable
ownership record; generation and numeric-ID validation alone do not prove tenant
ownership. Closing the client cancels requests, but late results still require
durable cleanup accounting.

Metadata responses are capped at 64 KiB, report JSON at 8 MiB, nesting at 64.
Duplicate keys, nonfinite numbers and trailing documents fail closed. Reports
validate integer `info.id`, file categories and exact `target.file.sha256`; the
in-memory document is only for the later versioned signal mapper. It is never a
verdict and must not be persisted, logged or exposed. No report file is written.
`CAPE_current_commit` is untrusted metadata and may be `unknown` with packed refs
or deployment layout differences. Operator activation must verify deployment
revision/profile separately. Errors contain local enum codes only.

Deletion accepts one owned ID, uses uncached GET, and recognizes only the pinned
single-ID acknowledgement. Its only success state is
`remote_delete_acknowledged_unverified`. Missing/orphaned/failed responses and
timeouts do not prove purge; reaper/descendant/backups evidence remains external.

Pinned source evidence (synthetic tests model these envelopes, not real reports):

<!-- markdownlint-disable MD013 -- pinned source URLs are intentionally immutable -->

- [Routes](https://github.com/kevoreilly/CAPEv2/blob/471ee4bb422ec4aa0f1aa1089540a1ad0b7d84f0/web/apiv2/urls.py): file creation, status, JSON report, single-ID deletion.
- [Handlers](https://github.com/kevoreilly/CAPEv2/blob/471ee4bb422ec4aa0f1aa1089540a1ad0b7d84f0/web/apiv2/views.py): create initializes `error=[]` and successful responses include `errors` and `data.task_ids`; status uses boolean `error` and string `data`; successful deletion omits `error` and emits a task-specific string, with separate orphan/failed outcomes. JSON reports are served directly.
- [Analysis info](https://github.com/kevoreilly/CAPEv2/blob/471ee4bb422ec4aa0f1aa1089540a1ad0b7d84f0/modules/processing/analysisinfo.py): emits task identity/category and best-effort commit metadata; the commit helper falls back to `unknown`.
- [Status constants](https://github.com/kevoreilly/CAPEv2/blob/471ee4bb422ec4aa0f1aa1089540a1ad0b7d84f0/lib/cuckoo/core/data/task.py): accepted status vocabulary.

<!-- markdownlint-enable MD013 -->

Verification: `go test -race ./internal/cape -count=1 -timeout=180s`,
`go build ./internal/cape`, `go vet ./internal/cape`. Tests use isolated TLS
listeners and synthetic bytes only. No real CAPE deployment or sample was used.
The durable store and scheduler are described in STORE.md and SCHEDULER.md;
the HTTPS service, mail-adapter policy gates, and daemon mounting are integrated
in `internal/mailstrix`. Physical capacity, remote purge, and operator activation
evidence remain deployment-specific prerequisites.
