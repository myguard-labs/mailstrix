# Optional CAPE daemon service

`strixd serve -cape-config /absolute/admin.json` (or
`MAILSTRIX_CAPE_CONFIG_FILE`) selects a separate HTTPS API. With no configuration
file, no CAPE listener, state or scheduler is created. The existing plaintext
`/scan` listener, cache and mail dispositions retain their defaults. This option
is unrelated to the build-time `CAPE=0` public YARA-rule-source switch.

Before activation, read the [operator consent and retention guide](CAPE-OPERATIONS.md).
The JSON example below can be validated offline; it is not deployment approval.

`-cape-policy` / `MAILSTRIX_CAPE_POLICY` and the file's `policy` accept only
`static-only` (empty also means static-only). `tempfail`, `quarantine-pending`
and unknown policies are startup errors. This daemon integration does not add
mail-to-job binding, automatic submissions, enforcement, Milter/Lua metadata or
an authenticated callback bridge. Polling remains authoritative.

## Administrator configuration

JSON is limited to 256 KiB and 16 nesting levels. Unknown fields, duplicate keys,
case aliases and trailing documents are rejected. References must select exactly
one absolute regular file or environment-variable name; inline secret values are
not supported. Reference contents are capped at 1 MiB; tokens at 4096 bytes.
Files and any symlink targets are administrator-controlled, local regular files.
Tenant credentials and upstream tokens are snapshotted at service construction;
rotate or repair them with a restart. Nothing logs their values.

This structural example uses placeholders and does not satisfy activation's
private endpoint, trust, volume, approved content/egress or remote reaper checks:

```json
{
  "version": 1,
  "policy": "static-only",
  "listen": "127.0.0.1:8443",
  "accept_limit": 128,
  "tls_cert_ref": "listener_cert",
  "tls_key_ref": "listener_key",
  "references": {
    "listener_cert": {"file": "/run/secrets/cape-listener-cert"},
    "listener_key": {"file": "/run/secrets/cape-listener-key"},
    "upstream_token": {"env": "MAILSTRIX_PRIVATE_CAPE_TOKEN"},
    "tenant_token": {"env": "MAILSTRIX_PRIVATE_TENANT_TOKEN"}
  },
  "endpoints": {
    "primary": {
      "generation": "deployment_v1",
      "account": "service_account_v1",
      "origin": "https://cape.example.invalid",
      "destination": "192.0.2.10:443",
      "machine": "configured_machine",
      "credential_ref": "upstream_token"
    }
  },
  "profiles": {
    "manual": {
      "endpoint": "primary",
      "submission_policy": "manual_v1",
      "result_policy": "signals_v1",
      "static_policy": "actionable-v1",
      "allow_unknown": true
    }
  },
  "tenants": {
    "approved_tenant": {"token_refs": ["tenant_token"], "profiles": ["manual"]}
  },
  "signal_policies": {
    "signals_v1": [
      {
        "name": "operator_selected_signature",
        "signal": "local_signal",
        "evidence": "malicious"
      }
    ]
  },
  "store": {"Directory": "/var/lib/mailstrix/cape-volume"},
  "workers": 1
}
```

The CAPE listener must use a different nonzero port from configured HTTP, ICAP
and clamd TCP listeners. `accept_limit` (1–4096) bounds accepted connections
until they close, including HTTP keep-alive connections. TLS 1.2 or later is
required. An endpoint's optional
`ca_ref` names a reference containing its PEM trust bundle; otherwise standard
system trust applies. Destinations are explicit numeric IP:port pairs. No proxies,
redirects or request-supplied upstream endpoints, machines or options are used.
`X-Mailstrix-CAPE-Profile` selects only a locally configured profile allowed for
the authenticated tenant.

Limits: 16 endpoint descriptors, 128 tenant/profile/result-policy entries,
256 references and 1–100 workers. Tenants have one or two token references for
explicit rotation overlap. Duplicate token values are rejected, including across
tenants. Bearer authentication accepts exactly one Authorization header and
does not derive tenants from message or tenant headers.

`store` uses the existing [StoreConfig field names and defaults](../cape/STORE.md),
including `MaxAttachment`, `MaxJobs`, `TenantJobs`, `MaxBytes`, `TenantBytes`,
submission/request rate and concurrency limits. `Tenants` must be absent/empty:
the service derives it from the authenticated tenant map. The existing dedicated
capped-volume and private-directory checks are enforced by OpenStore. No daemon
option bypasses those checks. A normal temporary directory is not activation
evidence.

## Identity and admission

Runtime generation IDs hash the explicit generation/account labels, origin,
numeric destination, machine, credential reference, CA reference and configured
CA contents. They never hash credential values. Changing the account behind an
unchanged credential reference requires changing its account/generation label;
the service cannot infer remote account identity from a token. Keep old endpoint
descriptors and credentials for outstanding cleanup. Removing them leaves old
work/debt without a configured client; it does not migrate task IDs or prove purge.

Result-policy identities hash their version label and sorted exact signature
rules; submission-policy identities hash the version label, eligibility and fixed
static policy. Reusing a label with changed effective policy cannot reuse the old
result identity. Reordering signature rules does not change identity.

Rotate result policies additively: add a new `signal_policies` label with its
new rules and point new admission profiles at that label. Retain each old label
and its exact rules while persisted jobs still need result mapping, alongside
the old endpoint descriptors and credentials needed for cleanup. Removing or
editing an old policy removes its mapper identity from the runtime registry;
pending jobs cannot use a new policy identity in its place.

The [manual attachment API](../cape/API.md) reserves and stages exact input bytes
before invoking the actual ScanEngine. The classifier uses fixed empty filename,
extension/password metadata and the configured effort ceiling. It acquires the
existing memory/CPU gates and calls the scanner directly, bypassing the static
fail-open cache. `actionable-v1` maps a successful actionable match to malicious,
and successful scanning without actionable matches to unknown. Canary/allowlist
matches remain log-only. Raw, extracted-child and marker native scan errors,
exhausted scan budgets, panic and cancellation are unavailable, even if the mail
scanner recovered matches from other channels. This completion status belongs
to the individual call; ordinary mail scanning retains its recovery behavior. A
no-match result is not independent proof of clean. The manual profile must
explicitly permit unknown input; malicious input is not enqueued. No Lua score,
name heuristic or upstream score threshold is introduced.

## Failure and shutdown

Malformed configuration is a daemon startup error. Operational reference,
storage or CAPE-listener failures leave static scanning running. Where TLS can
start but durable CAPE runtime cannot, its endpoint responds 503. Repairing a
startup failure requires a restart. Existing scheduler authentication pauses and
retention/debt behavior remain in effect; no remote purge evidence is invented.

Shutdown stops new ingress and cancels request contexts, waits for native scans
and HTTP handlers, then cancels/joins the scheduler before closing its store and
clients. Native calls retain their gates and staged reservation until they return,
even when the request expires. An enabled CAPE service adds 30 seconds to the
daemon's existing native-scan drain budget; disabled defaults are unchanged.
Failed drain is reported and scanner cleanup is skipped. A scheduler persistence
failure retains its owner/store rather than discarding pending outcomes.
