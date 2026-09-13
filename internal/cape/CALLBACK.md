# Optional callback bridge foundation

`NewCallbackHandler(store, CallbackConfig{})` returns 404 for every request.
Only explicitly provisioned bridge keys enable it. This package does not mount
the receiver or start a listener. Mount on a directly terminated HTTPS server
with bounded headers, read/header timeouts and connection limits. TLS forwarding
headers do not enable plain HTTP. Native unsigned CAPE callbacks are incompatible.

The sole accepted route is `POST /v1/cape/events`, without query or alternate
path encoding, with `Content-Type: application/json` and no content encoding.
Body size is at most 4096 raw bytes, including whitespace. The exact JSON object
has seven fields: `version` (integer 1), `event_id` (random 128-bit lowercase hex),
`tenant_id`, `job_id` (128-bit lowercase hex), `endpoint_generation`, `task_id`
(positive signed 32-bit integer), and `timestamp` (positive Unix seconds).
Unknown/duplicate fields, trailing JSON and mismatched types are rejected.

Supply one each of `X-Cape-Key-ID`, `X-Cape-Timestamp`, `X-Cape-Event-ID`, and
`X-Cape-Signature`. Signature is hexadecimal HMAC-SHA256 of these six strings,
joined by newlines, without a final newline:

1. `mailstrix-cape-v1`
2. `POST`
3. `/v1/cape/events`
4. canonical decimal timestamp header
5. event ID header
6. lowercase hexadecimal SHA-256 of the exact raw body

MAC comparison is constant time. Both signed headers must equal body fields;
time skew may be at most five minutes. Authentication precedes job lookup.
Keys bind an explicit tenant and endpoint generation set; the job's persisted
tenant/job/generation/single task must match exactly. Callbacks never provide
accepted report data or verdicts.

Provision keys through trusted secret configuration, never request parameters.
There are at most 32 distinct key IDs, exactly 32 secret bytes per key and 4096
combined tenant/generation entries. Tenant entries must be approved store tenants.
Secrets are copied into handler memory and never stored in SQLite. Each key has
an explicit inclusive NotBefore and exclusive NotAfter window of at most 30 days.
Shared tenant/generation authority may overlap only within explicitly configured
`RotationOverlap` (maximum one hour). Replace the handler to rotate configuration;
remove the old handler after swapping. Do not recycle key IDs for unrelated keys.
No remote key discovery, dynamic key URL or outbound callback request exists.

An accepted event and its `Job.PollWakeAt` hint commit in one SQLite transaction.
The hint updates only remote_pending/fetching jobs before their absolute deadline,
never terminal or suppressed jobs; callback processing never changes job state,
evidence or retry deadlines. The scheduler consumes hints with state
and version checks, obeys normal polling budgets, and independently validates the
authenticated CAPE response. A stale hint on a subsequently cancelled job grants
no permission to poll or resurrect it. The scheduler consumer and its persisted
budget/backoff checks are documented in SCHEDULER.md.

Replay entries expire after eleven minutes, persist over restart, and cap at
10,000 total / 1,000 per tenant. The same rows enforce a rolling maximum of ten
accepted events per key per minute, without restart refill. Full tables reject
new events; no unexpired event is evicted. Polling remains independent. A duplicate
event returns 409 without changing the job, including after receiver replacement
or store restart. New authenticated events for terminal jobs consume replay/rate
capacity and return 202 without work. Clock rollback from the last accepted
callback pauses callbacks until correction; the store clock guard also applies.

Responses have empty bodies and no-store: 202 committed, 409 duplicate, 429
rate/capacity, 503 unavailable/rollback, 401 authentication/schema/binding failure,
400 malformed transport, 413 oversized body, 404 disabled. Identity and secret
material are not logged. Tests use inert keys, local fake TLS and private temporary
SQLite stores with a fake capacity checker; they do not prove physical quota
activation or production bridge provisioning.
