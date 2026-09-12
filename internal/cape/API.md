# CAPE API and adapter foundation

This package provides the opt-in handler mounted by strixd's separately configured
[HTTPS service](../mailstrix/CAPE.md). Existing `/scan`, ICAP and Milter behavior
is unchanged. The daemon authenticates configured tenants and accepts manual
selected-attachment requests; it does not associate these jobs with mail scans.
Deployment activation still requires the [operator prerequisites](../mailstrix/CAPE-OPERATIONS.md).
There is no default endpoint, tenant, submission policy or signal policy.

`NewAPIHandler` requires a store, trusted authenticator, tenant-scoped profile
resolver and static scanner when enabled. The enclosing server must provide TLS
and its normal connection/request limits. Authentication and profile resolution
must not consume the attachment. All injected callbacks must honor cancellation
and support concurrent calls; do not retain request bodies or staged readers.
Tenant identity must be derived from trusted credentials/configuration, never
from a message header or a caller-supplied tenant ID.

## Requests

- `POST /v1/cape/jobs`: exact selected attachment bytes, with
  `Content-Type: application/octet-stream` and an explicitly configured profile
  name in `X-Mailstrix-CAPE-Profile`. No multipart upload, original filename,
  compression, query parameters, message envelope or caller static verdict is
  consumed. Profile names resolve only inside the authenticated tenant's policy.
  Any Content-Encoding header occurrence, including an empty or repeated value,
  is rejected.
- `GET /v1/cape/jobs/{id}`: original admission static snapshot, sandbox state and
  normalized evidence/signals, local reason, cleanup state, creation time, first
  terminal time and analysis deadline. No digest, tenant, upstream task IDs,
  generation, correlation marker or raw report is exposed.
  After ordinary result/metadata retention, an unresolved cleanup tombstone
  exposes an empty `static_verdict`; the original snapshot is not retained there.
- `DELETE /v1/cape/jobs/{id}`: tenant-scoped idempotent cancellation, including
  completed jobs. It suppresses results immediately without promising remote
  stop or purge, and preserves the original terminal timestamp.

POST returns 202 and JSON `id`/`location` only after durable admission, or 200 for
reusable completed work. A Location header identifies the status endpoint.
Pending work and throttling use `Retry-After: 5`; no handler polls or waits for
detonation. Responses are `Cache-Control: no-store`. Missing/wrong-tenant lookups
share 404. Invalid input/profile/ineligible content returns 400, oversize 413,
quota exhaustion 429 and disabled/unavailable service 503. Authentication failure
returns 401. A missing terminal timestamp is represented by Go's zero UTC time.
Reusing retained work with unavailable evidence returns 409 with
`{"error":"unavailable"}` and the existing Location header: it is neither a new
queued job nor a reusable completed result. The retained dedup barrier remains.
Pending presentation respects staging, queue and analysis deadlines even before
maintenance updates the persisted state. Adapters preserve explicit unavailable
evidence when combining it with a still-active persisted state.

`EnqueueClassified` reserves the full staging allowance before reading input,
then calls the scanner over a bounded read-only staged file before publication.
The original 30-second ingress deadline includes classification. Failure,
cancellation or expiry cannot publish queued work. The reservation remains until
an uncooperative classifier actually returns. A scanner can materialize the
bounded attachment within the reserved slot; it must not retain that memory.
The API permits only explicitly enabled unknown/suspicious classifications;
static clean and malicious content are not detonation candidates in this policy.
Static failures produce unavailable, not an eligible unknown result.

Dedup preserves `Job.StaticVerdict` as the first admission snapshot during normal
retention. It is empty in retained cleanup tombstones after ordinary retention.
`Admission.CurrentStatic` separately returns the current classifier output even
when a previous job is reused. Adapters must combine evidence with the current
static scan, never substitute a stored older static snapshot. The POST response
does not expose this internal field. An empty tombstone static snapshot must
never replace the current static scan. GET omits expired/suppressed normalized
results even before maintenance deletes them.

## Signal and adapter policy

`NewSignatureMapper` takes an explicit policy identifier and 1–128 configured
exact signature-name rules. Changing rules requires a new policy identifier.
Each rule maps to a local identifier and suspicious/malicious evidence. Policy
semantics are locally configured; they are not upstream severity guarantees.
The mapper requires a `signatures` array (maximum 4096 objects), each with a
nonempty name accepted by the package's bounded identifier grammar. Empty arrays
and valid unknown names yield `no_signal`. Missing/null/malformed arrays or
entries fail normalization and remain unavailable. Other fields and scores are
ignored; descriptions never enter normalized output. Malicious takes precedence,
signals are deduplicated and sorted, and a mismatched policy fails normalization.

The pure-Go `internal/verdict` sandbox helper preserves current static concern
and exposes pending/unavailable/no_signal distinctly. It never invents a clean
sandbox verdict. `ValidateReportOnlyPolicy` accepts empty/default or `static-only`
and rejects `quarantine-pending`, `tempfail` and unknown policies. The daemon,
ICAP and report-only Milter enforce this at startup; Rspamd has matching policy
validation and requires the explicit include/preflight described in the
[adapter guide](../../contrib/rspamd/test/CAPE-policy.md). There is no durable
quarantine integration or automatic job-to-mail projection.
