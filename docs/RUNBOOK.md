# yarad Operational Runbook

## Health checks

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /health` | none | Liveness — 200 `ok` if rules are loaded; 503 `no rules` if the rule set failed to load. Stays 200 during graceful drain so the container isn't killed before in-flight scans finish. |
| `GET /ready` | none | Readiness — 200 when rules are loaded and the server is not draining. Returns 503 `draining` during SIGTERM drain, 503 `no rules` if the scanner has no ruleset. Returns 200 with body `ready (stale rules)` when `YARAD_RULES_MAX_AGE` is set and exceeded (stale does NOT pull the scanner from rotation — fail-open). Returns 200 with body `ready (redis breaker open)` or similar when the Redis L2 cache is degraded. |
| `GET /version` | `YARAD_METRICS_AUTH` | Build info, rule count, fingerprint, `prev_fingerprint` (after a reload), last reload timestamp, rules mtime, rules_stale flag, top 20 matches, and rules manifest (version/generated/libyara/count) when a bundle from `fetch-rules` is loaded. |
| `GET /metrics` | `YARAD_METRICS_AUTH` | Prometheus text format (see Key metrics below). |
| `GET /debug/pprof*` | `YARAD_METRICS_AUTH` | Go profiling endpoints — only exposed when `YARAD_PPROF=1`. |

`YARAD_METRICS_AUTH=1` requires the same `YARAD_TOKEN` / `X-YARAD-Token` or `Authorization: Bearer` on `/metrics`, `/version`, and `/debug/pprof`. `/health` and `/ready` are always open.

Docker HEALTHCHECK: `yarad health` (the CLI sub-command), interval 30s, start_period 20s.

---

## Key metrics (`/metrics`)

All metric names are prefixed `yarad_`.

### Scan throughput

| Metric | Type | Description |
|--------|------|-------------|
| `yarad_scans_total` | counter | Total `/scan` POST requests served |
| `yarad_matches_total` | counter | Requests with ≥1 rule match |
| `yarad_errors_total` | counter | Scan/read/length errors (fail-open) |
| `yarad_busy_total` | counter | Requests rejected by the concurrency gate (503 busy) |
| `yarad_canceled_total` | counter | Requests abandoned because the client disconnected/timed out |

### Cache

| Metric | Type | Description |
|--------|------|-------------|
| `yarad_cache_hits_total` | counter | Verdicts served from cache (L1 LRU or Redis L2) |
| `yarad_cache_misses_total` | counter | Cache misses — a real libyara scan ran |
| `yarad_cache_coalesced_total` | counter | Scans collapsed onto an in-flight identical scan (request coalescing) |

### Rules

| Metric | Type | Description |
|--------|------|-------------|
| `yarad_rules` | gauge | Loaded YARA rule count |
| `yarad_rules_mtime_seconds` | gauge | mtime (unix) of the loaded ruleset on disk; 0 if unknown |
| `yarad_rules_age_seconds` | gauge | Age of the loaded ruleset (now − mtime) |
| `yarad_rules_stale` | gauge | 1 when `rules_age_seconds` exceeds `YARAD_RULES_MAX_AGE`; 0 otherwise |

### Reload activity

| Metric | Type | Description |
|--------|------|-------------|
| `yarad_reload_attempts_total` | counter | Rule reload attempts including the boot load |
| `yarad_reload_success_total` | counter | Successful reloads |
| `yarad_reload_failure_total` | counter | Failed reloads (previous rule set kept) |
| `yarad_reload_last_timestamp_seconds` | gauge | Unix time of the last successful reload |
| `yarad_reload_last_duration_ms` | gauge | Wall-clock duration of the last reload attempt |

### Extractor counters

All are counters prefixed `yarad_extract_`.

| Suffix | What it counts |
|--------|---------------|
| `docs_total` | Attachments recognised as OLE2/OOXML containers |
| `macro_docs_total` | Documents that yielded ≥1 decompressed macro stream |
| `streams_total` | Decompressed macro streams scanned |
| `failed_total` | Container parse attempts that errored |
| `panicked_total` | Parser panics recovered (subset of `failed_total`) |
| `encrypted_total` | ECMA-376 encrypted OOXML seen (not decrypted) |
| `msi_total` | OLE2 MSI installers with streams dumped |
| `msg_total` | Outlook `.msg` files with nested attachments extracted |
| `onenote_total` | OneNote `.one` files with embedded files carved |
| `archive_total` | Archives (zip/gz/7z/rar/tar) with members unpacked |
| `ole_package_total` | OLE2 docs with an embedded OLE Package (`Ole10Native`) carved |
| `lnk_total` | Windows `.lnk` files with StringData surfaced |
| `pdf_total` | PDFs with FlateDecode object streams inflated |
| `rtf_total` | RTF docs with `\objdata` embedded objects hex-decoded |
| `encoded_script_total` | Buffers with ≥1 decoded VBE/JSE block |
| `decoded_total` | Buffers with ≥1 base64/hex/StrReverse blob from the static decode pass |
| `docprops_total` | Documents with doc-property strings extracted |
| `stream_matches_total` | Rule hits attributable only to an extracted stream (not raw bytes) |
| `deduped_total` | Streams skipped before YARA scan (content-hash duplicate) |

### Abuse.ch feeds (when enabled)

URLhaus (`YARAD_URLHAUS_KEY` set):

- `yarad_urlhaus_lookups_total`, `yarad_urlhaus_hits_total`, `yarad_urlhaus_refresh_failures_total`
- `yarad_urlhaus_feed_urls` (gauge), `yarad_urlhaus_feed_hosts` (gauge), `yarad_urlhaus_last_refresh_timestamp_seconds` (gauge)

MalwareBazaar (`YARAD_MBAZAAR_KEY` set):

- `yarad_malwarebazaar_lookups_total`, `yarad_malwarebazaar_hits_total`, `yarad_malwarebazaar_refresh_failures_total`
- `yarad_malwarebazaar_feed_hashes` (gauge), `yarad_malwarebazaar_last_refresh_timestamp_seconds` (gauge)

---

## Common scenarios

### Rule reload (SIGHUP)

```sh
docker kill --signal=HUP yarad
```

yarad recompiles all rules in place and flushes the verdict cache (so old cached verdicts computed against the previous ruleset don't survive). The previous rule set is kept active if compilation fails — a bad rule edit cannot disarm the running scanner.

Verify the reload succeeded:

```sh
# fingerprint changes on success; prev_fingerprint shows the old one
curl -s -H 'X-YARAD-Token: <token>' http://127.0.0.1:8079/version | jq '{fingerprint, prev_fingerprint, rules}'

# metrics: reload_success_total should have incremented; reload_failure_total should not
curl -s -H 'X-YARAD-Token: <token>' http://127.0.0.1:8079/metrics | grep yarad_reload
```

Alert on `yarad_reload_failure_total` increasing — a failed reload is silent to callers (old rules still run) but indicates a bad rule set on disk.

### Fetch and apply updated rules (without image rebuild)

```sh
# On the host or in the container (if cache dir is a writable bindmount):
yarad fetch-rules -cache-dir /var/cache/yarad

# Then reload:
docker kill --signal=HUP yarad
```

`fetch-rules` downloads a version-matched, SHA256-verified compiled bundle from the release. It refuses a bundle built against a different libyara version, swaps atomically (keeps one `.bak`), and leaves the current bundle untouched on any error.

### Redis / Valkey down

yarad continues scanning — cache is fail-open. Behaviour:

- In-process LRU (L1) still functions; only cross-replica sharing (L2) is lost.
- `/ready` returns 200 with body `ready (redis breaker open)` or similar — still ready, just degraded.
- Performance degrades at high volume (more cache misses, more libyara scans).
- The circuit breaker probes Redis periodically; auto-recovers when Redis returns (half-open probe succeeds).

No operator action required unless the degraded state is prolonged.

### High latency / 503 busy responses

`503 busy` means the admission gate (`YARAD_MAX_INFLIGHT`) is full — the queue of in-flight requests exceeded the limit.

Diagnosis checklist:

1. Check `yarad_busy_total` — rising means the gate is firing regularly.
2. Check `YARAD_MAX_CONCURRENT` vs available CPU count. Default is `auto` (CPU count). Under-provisioning means scan slots fill up and buffers queue.
3. Check `YARAD_MAX_INFLIGHT` (default 2 × `MAX_CONCURRENT`). The admission gate is intentionally larger than the scan gate so slow body reads or Redis L2 lookups don't starve scan slots.
4. Check `YARAD_BACKEND_TIMEOUT` (default 1s). This is how long a request waits for a scan slot before returning 503. Raising it queues more rather than rejecting — usually the wrong fix.
5. Check `YARAD_SCAN_TIMEOUT` (default 8s). If rules are slow, scans hold slots longer. Check yarac compile warnings for slow-rule hints at build time.
6. Profile with `/debug/pprof` (requires `YARAD_PPROF=1` and, if `YARAD_METRICS_AUTH=1`, the token):

```sh
go tool pprof http://127.0.0.1:8079/debug/pprof/profile?seconds=30
```

Memory: startup log prints estimated peak request-buffer memory (`max_inflight × max_body`). A warning is emitted if buffers alone exceed half the container `mem_limit`. Check `yarad_extract_panicked_total` — parser panics may indicate a memory-exhausting input (zip bomb, malformed container). If `panicked_total` is rising, consider lowering `YARAD_MAX_BODY` or `YARAD_MAX_INFLIGHT`.

### Token rotation (zero-downtime)

Two approaches are supported:

**Comma-separated primary token** (`YARAD_TOKEN=old,new`): all listed values are accepted simultaneously. Migrate clients to `new`, then remove `old` from the list and restart.

**`YARAD_TOKEN_NEXT` (incoming token)**: the value is accepted alongside the primary. Workflow:

1. Add `YARAD_TOKEN_NEXT=<new-token>` to the container environment and restart.
2. Both old and new tokens are accepted. Update rspamd `yara.lua` to use the new token and reload rspamd.
3. Promote: set `YARAD_TOKEN=<new-token>`, clear `YARAD_TOKEN_NEXT`, restart.

Token via file (Docker secret): use `YARAD_TOKEN_FILE` / `YARAD_TOKEN_NEXT_FILE` — the file is read at startup, not re-read on SIGHUP.

### Rule source degradation (stale rules)

If `YARAD_RULES_MAX_AGE` is set (seconds), the `yarad_rules_stale` metric becomes 1 when the loaded ruleset's mtime exceeds that age. This catches a silently broken daily image rebuild — the running container keeps serving old baked rules with no error, but the metric and `/ready` body (`ready (stale rules)`) surface it.

Action:

- Check `/version` for `rules_stale` and `rules_mtime_unix`.
- Check `yarad_reload_failure_total` — a failed reload would keep stale rules.
- Re-run `fetch-rules` or rebuild the image (see above).
- Check `sources` in `/version` for missing/stale rule source entries.

Stale rules do NOT fail `/ready` (still 200). The scanner stays in rotation — old rules still catch most malware; pulling the scanner out is strictly worse.

### Memory pressure / OOM risk

yarad logs peak buffer estimate at startup:

```
est. peak request-buffer memory ~N MiB (max_inflight=X × max_body=Y MiB) on top of rules RSS
```

A warning is emitted when buffers alone exceed half the cgroup `mem_limit`. If the container OOMKills:

- Lower `YARAD_MAX_INFLIGHT` (reduces in-flight buffer count), or
- Lower `YARAD_MAX_BODY` (reduces per-request buffer ceiling), or
- Raise `mem_limit` in docker-compose (`512m` baseline; `768m` when MalwareBazaar full feed is enabled — adds ~40 MiB resident plus a ~100–150 MiB transient spike on daily refresh).

Check `yarad_extract_panicked_total` — parser panics may indicate a memory-exhausting malformed input (zip bomb, OLE quine). Panicked scans are fail-open and not cached.

### Graceful shutdown / rolling update

On SIGTERM:

1. `/ready` immediately starts returning 503 (load balancers / rspamd stop routing new scans here).
2. `/health` stays 200 so the container is not force-killed during drain.
3. In-flight scans are allowed to finish.
4. The process exits cleanly after drain.

No special operator action required; `restart: unless-stopped` in docker-compose handles restart.

---

## Environment variables quick reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `YARAD_HOST` | `0.0.0.0` | HTTP bind address |
| `YARAD_PORT` | `8079` | HTTP bind port |
| `YARAD_TOKEN[_FILE]` | — | Shared secret; comma-separated for zero-downtime rotation; unset/`none`/`0`/`off` = open scanner (warned at startup) |
| `YARAD_TOKEN_NEXT[_FILE]` | — | Incoming rotation token accepted alongside primary |
| `YARAD_RULES_DIR` | `/rules` | Directory of `*.yar`/`*.yara` source files; compiled at boot and on SIGHUP |
| `YARAD_RULES` | — | Precompiled `.yac` bundle; takes precedence over `RULES_DIR` |
| `YARAD_CACHE_DIR` | — | Writable directory for the updatable rule bundle (`fetch-rules`) |
| `YARAD_SEED_RULES` | — | Baked read-only `.yac` to seed the cache on a fresh deploy |
| `YARAD_RULES_MAX_AGE` | `0` (off) | Seconds; flags rules `stale` via metric + `/ready` body when exceeded |
| `YARAD_SCAN_TIMEOUT` | `8s` | Per-request libyara budget (raw + all extracted streams share it) |
| `YARAD_BACKEND_TIMEOUT` | `1s` | How long to wait for an admission or scan slot before returning 503 |
| `YARAD_MAX_CONCURRENT` | auto (CPU count) | Max concurrent libyara scans (CPU gate) |
| `YARAD_MAX_INFLIGHT` | auto (2× concurrent) | Max in-flight requests (admission gate) |
| `YARAD_MAX_BODY` | `8388608` (8 MiB) | Max request body in bytes |
| `YARAD_CACHE_TTL` | `600s` | Verdict cache TTL; `0` disables |
| `YARAD_CACHE_SIZE` | `65536` | In-memory LRU entry count |
| `YARAD_REDIS_URL` | — | Optional shared L2 cache (e.g. `redis://host:6379/6`) |
| `YARAD_REDIS_PREFIX` | `yara:scan:` | Redis key prefix |
| `YARAD_METRICS_AUTH` | off | Require the token for `/metrics`, `/version`, and `/debug/pprof` |
| `YARAD_URLHAUS_KEY[_FILE]` | — | abuse.ch Auth-Key; enables URLhaus malware-URL lookup |
| `YARAD_URLHAUS_REFRESH` | `21600s` (6 h) | URLhaus feed refresh interval (floor 5 min) |
| `YARAD_URLHAUS_MAX_URLS` | `64` | Max URLs examined per message |
| `YARAD_MBAZAAR_KEY[_FILE]` | — | abuse.ch Auth-Key (same key); enables MalwareBazaar hash lookup |
| `YARAD_MBAZAAR_REFRESH` | `86400s` (24 h) | MalwareBazaar feed refresh interval (floor 5 min) |
| `YARAD_MBAZAAR_FEED` | full dump | Override feed URL (e.g. the lighter "recent" export) |
| `YARAD_RULE_DENYLIST` | `http` | Comma-separated rule names to suppress; set empty to disable |
| `YARAD_RULE_ALLOWLIST` | — | Comma-separated rule names to keep but tag log-only (`yarad_allow=1`); deny wins if in both |
| `YARAD_VERBOSE` | off | Log one line per request |
| `YARAD_LOG_STDOUT` | off | Route info/access logs to stdout (errors always go to stderr) |
| `YARAD_PPROF` | off | Enable `/debug/pprof` profiling endpoints |

---

## Threat model

**yarad scans untrusted attachments — input is hostile by design.**

| Surface | Mitigation |
|---------|-----------|
| libyara (C, via CGO) | Main native attack surface. Per-scan timeout (`YARAD_SCAN_TIMEOUT`) bounds runaway rules. All Go extractors are memory-safe; panics are recovered and the scan fails open (not cached). |
| Document extractors | Deadline + budget capped, fail-open on any parse error or panic. Zip-bomb / quine caps (per-item, total bytes, member and depth counts) bound decompression work. |
| Subprocess execution | None — no shell, no exec, no scripting. No shell injection surface. |
| Token auth | All `/scan`, `/metrics`, `/version`, and `/debug/pprof` endpoints are token-gated when `YARAD_TOKEN` is set. Auth check uses `hmac.Equal` (constant-time). |
| Network exposure | No `ports:` in the reference compose — reachable only on the internal Docker network by a static IPv4. |
| Container hardening | Distroless final image (no shell, no package manager). Non-root user. Read-only rootfs. `cap_drop: ALL`. `no-new-privileges:true`. Only `/tmp` is writable (tmpfs). |
| Resource exhaustion | Admission gate (`YARAD_MAX_INFLIGHT`) bounds concurrent in-flight request buffers. Scan gate (`YARAD_MAX_CONCURRENT`) bounds concurrent libyara scans. Body cap (`YARAD_MAX_BODY`) is checked before reading. 503 is returned when the gate is full rather than queuing indefinitely. |
| Cache poisoning | Cache key mixes the rule fingerprint (invalidated on reload), the attachment filename metadata, and SHA256(body). A reload always flushes the cache. |
| Secret leakage | Token supplied via `YARAD_TOKEN_FILE` (Docker secret mount) rather than an env var visible in `docker inspect`. `YARAD_METRICS_AUTH=1` gates `/version` and `/metrics` so rule count and fingerprint are not exposed on an accidentally-published port. |
