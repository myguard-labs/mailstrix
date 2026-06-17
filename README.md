# yarad — YARA scanning for rspamd

[![CI](https://github.com/eilandert/rspamd-yarad/actions/workflows/ci.yml/badge.svg)](https://github.com/eilandert/rspamd-yarad/actions/workflows/ci.yml)
[![Release](https://github.com/eilandert/rspamd-yarad/actions/workflows/release.yml/badge.svg)](https://github.com/eilandert/rspamd-yarad/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/eilandert/rspamd-yarad.svg)](https://pkg.go.dev/github.com/eilandert/rspamd-yarad)

[rspamd](https://rspamd.com/) has **no built-in YARA module** (still true as of
4.1.0; it's an [open feature request](https://github.com/rspamd/rspamd/discussions/3511)).
`yarad` adds one without dragging YARA into rspamd itself. It runs the scanner as
a separate little HTTP service and lets rspamd ask it questions:

```
                POST /scan (raw bytes)
   rspamd  ───────────────────────────▶  yarad  ──▶  libyara
 (yara.lua plugin)                      (Go service)   compiled .yar rules
           ◀───────────────────────────         (public rulesets, baked in)
                {"matches":[ ... ]}
```

Why a separate service instead of a plugin? libyara is a C library (CGO). Calling
it inside an rspamd worker would block rspamd's event loop and pull a heavy C
dependency into the mail-flow image. Keeping it out-of-process means the rspamd
side stays fully async, and the scanner can be restarted, scaled, or have its
rules reloaded on its own. It's the same shape as the
[gozer](https://github.com/eilandert/gozer) DCC/Razor/Pyzor backend.

## What it gives you

* **`POST /scan`** — put raw message bytes (or one MIME part) in the body, get
  back the YARA rules that matched, as JSON:
  ```json
  {"matches":[{"rule":"Suspicious_Macro","tags":["office"],"meta":{"author":"…"}}]}
  ```
  The list is empty (`[]`, never `null`) when nothing matched.
* **`GET /health`** — liveness: `200` while a rule set is loaded. Wired to the
  container `HEALTHCHECK`; stays `200` during a graceful drain so the container
  isn't killed mid-shutdown.
* **`GET /ready`** — readiness: `200` only when rules are loaded **and** the
  server isn't draining. A load balancer / rspamd should route on this so it
  stops sending new scans the moment shutdown begins.
* **`GET /version`** — build + ruleset identity as JSON (`version`,
  `extractor_version`, `rules`, `fingerprint`, `last_reload_unix`) so a live
  FP/perf change can be tied to a specific image + rule bundle.
* **`GET /metrics`** — Prometheus counters: scans, matches, errors, busy
  rejections, cache hits/misses/coalesced, the loaded rule count, the document
  pre-extraction counters (`yarad_extract_docs_total`, `extract_macro_docs_total`,
  `extract_streams_total`, `extract_failed_total`, `extract_panicked_total`,
  `extract_encrypted_total`), and rule-reload activity (`reload_attempts_total`,
  `reload_success_total`, `reload_failure_total`, `reload_last_timestamp_seconds`,
  `reload_last_duration_ms`).

On `SIGTERM`/`SIGINT` yarad drains: `/ready` starts returning `503` and in-flight
scans finish (up to `YARAD_SCAN_TIMEOUT` + 5 s) before the process exits — safe
for rolling image/rule updates.

## Built for a real mail firehose

YARA scanning is CPU work, and mail at volume is wildly repetitive: bulk
campaigns, one body sent to a dozen recipients, MTA retries. yarad leans on that:

1. **Verdict cache (always on).** Keyed on `SHA256(body)`, so a body it has seen
   recently is a microsecond map lookup, not a scan. In-process LRU with a TTL.
   Turn it off with `YARAD_CACHE_TTL=0`.
2. **Request coalescing.** When the same body arrives N times at once, exactly
   one scan runs and the other N−1 callers wait on its result. One campaign
   becomes one scan, not hundreds.
3. **Optional shared cache (Redis/Valkey).** Set `YARAD_REDIS_URL` and several
   yarad replicas share one verdict cache, so you can scale horizontally behind
   rspamd. A slow or dead Redis just means a cache miss; it never blocks mail
   (150 ms per-op budget, fail-open, with a circuit breaker that skips Redis
   entirely after repeated failures so a dead Redis can't hold scan slots).

And it **fails open everywhere**: a scan error, timeout, or even a libyara panic
is reported to rspamd as "no match". A broken scanner must never hold up mail.
Other guards: a bounded concurrency gate (`YARAD_MAX_CONCURRENT`), a per-scan
libyara timeout (`YARAD_SCAN_TIMEOUT`), and a request body cap checked *before*
the body is read into memory.

## Quick start

```sh
# scan against your own rules directory, with a token:
docker run -d --name yarad \
    -e YARAD_TOKEN=changeme \
    -e YARAD_RULES=                 # disable the baked bundle…
    -e YARAD_RULES_DIR=/rules \     # …and compile this dir instead
    -v "$PWD/myrules:/rules:ro" \
    -p 8079:8079 \
    eilandert/rspamd-yarad

# ask it something:
printf 'hello' | curl -s -H 'X-YARAD-Token: changeme' \
    --data-binary @- http://127.0.0.1:8079/scan
# -> {"matches":[]}
```

Out of the box the image already has ~10k public rules baked in (see
[Rules](#rules)), so you can also just run it with a token and nothing else.

> **A token is mandatory.** Until `YARAD_TOKEN` (or `YARAD_TOKEN_FILE`) is set,
> every `/scan` is refused with `503`. The rspamd plugin must present the same
> secret as a `Bearer` header or `X-YARAD-Token`.

For the full container setup (read-only rootfs, dropped capabilities, Docker
secret for the token, static IPv4 on the rspamd network) see
[`docker/docker-compose.yml`](docker/docker-compose.yml).

## Configuration

Every setting is an environment variable, and also a `serve` CLI flag. Flags win
over env, env wins over the default.

| Env | Default | Meaning |
|-----|---------|---------|
| `YARAD_HOST` / `YARAD_PORT` | `0.0.0.0` / `8079` | HTTP bind address |
| `YARAD_TOKEN[_FILE]` | — | shared secret for `/scan`; unset ⇒ every POST is `503` |
| `YARAD_RULES_DIR` | `/rules` | directory of `*.yar`/`*.yara` compiled at boot and on SIGHUP |
| `YARAD_RULES` | — | a precompiled `.yac` bundle; loaded instead of `RULES_DIR` (faster start) |
| `YARAD_SCAN_TIMEOUT` | `10` (s) | per-scan libyara budget |
| `YARAD_BACKEND_TIMEOUT` | `6` (s) | per-request budget / how long to wait for a concurrency slot |
| `YARAD_MAX_CONCURRENT` | `auto` (CPU count) | max concurrent libyara scans (CPU gate); `auto` = CPU count |
| `YARAD_MAX_INFLIGHT` | `auto` (2× concurrent) | max in-flight requests/buffers (admission gate); kept above the scan gate so a slow body/Redis can't starve scan slots |
| `YARAD_MAX_BODY` | `8388608` (8 MiB) | max request body, in bytes |
| `YARAD_CACHE_TTL` | `600` (s) | verdict cache TTL; `0` disables caching entirely |
| `YARAD_CACHE_SIZE` | `65536` | in-memory LRU entries |
| `YARAD_REDIS_URL` | — | optional shared L2 cache, e.g. `redis://host:6379/6` |
| `YARAD_REDIS_PREFIX` | `yara:scan:` | Redis key prefix |
| `YARAD_VERBOSE` | off | log one line per request |
| `YARAD_LOG_STDOUT` | off | info/access logs to stdout (errors always go to stderr) |

**Reloading rules:** `docker kill -s HUP yarad` recompiles the rule set in place
and flushes the verdict cache. A reload that fails to compile keeps the previous
(working) rules active, so a bad rule edit can never disarm a running scanner.

## Rules

The image bakes public rulesets at build time. A daily rebuild
(`--build-arg CACHEBUST=$(date +%s)`) re-pulls the latest:

* **[YARA-Forge](https://github.com/YARAHQ/yara-forge)** — the curated "core"
  bundle of vetted public rules.
* **[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)** — the
  broad community malware/phishing set (THOR/Loki rules).
* **[ANY.RUN](https://github.com/anyrun/YARA)** — actively maintained
  malware-family and phishing rules (set `ANYRUN=0` to skip).
* **[Didier Stevens Suite](https://github.com/DidierStevens/DidierStevensSuite)**
  — public-domain OLE/RTF/maldoc rules, including the `vba.yara` macro-keyword
  set that fires on extracted VBA (see below). Set `DIDIER=0` to skip.
* **[bartblaze/Yara-rules](https://github.com/bartblaze/Yara-rules)** — MIT;
  maldoc/RTF (RoyalRoad, OLE-in-CAD) and phishing-doc rules not aggregated by
  YARA-Forge. Set `BARTBLAZE=0` to skip.

Together that's roughly 10,000 rules. Pin or toggle any source with a build arg:
`--build-arg YARAFORGE_URL=…`, `--build-arg SIGBASE_REF=<tag>`,
`--build-arg ANYRUN_REF=<ref>`, `--build-arg DIDIER_REF=<ref>`,
`--build-arg BARTBLAZE_REF=<ref>` (and `DIDIER=0` / `BARTBLAZE=0` / `ANYRUN=0`).

Public rulesets are messy by nature, so two things keep them from breaking the
build:

* libyara is compiled **without** the `magic`/`cuckoo` modules (not needed for
  email attachments), and rules that import them are skipped.
* Each rule file is test-compiled on its own first; a single unparseable file is
  logged and skipped rather than aborting the whole load. It's an error only if
  *nothing* compiles.

## Office macro extraction

A raw `.docm`/`.xlsm` is a ZIP, and its VBA macros sit MS-OVBA-compressed inside
a `vbaProject.bin` — so YARA keyword rules scanning the raw bytes see nothing.
Before matching, yarad sniffs OLE2/OOXML attachments and decompresses the VBA to
cleartext (pure-Go [oleparse](https://github.com/Velocidex/oleparse), no extra C
deps), then scans **both** the raw bytes (file-format/exploit rules) and the
decompressed macro source (keyword rules). Matches are merged and de-duplicated.

While scanning that decompressed source, the external YARA variable `VBA` is set
to `1`, so Didier's `vba.yara` rules (`VBA and any of (...)` — AutoOpen, Shell,
CallByName, …) fire exactly where they should and stay inert on raw bytes.
Extraction is best-effort and fail-open: a non-document, a parse error, or a
hostile/poison file just falls back to a raw-only scan. The whole request shares
one `YARAD_SCAN_TIMEOUT` budget across raw + every macro stream, so a document
crafted with hundreds of modules can't monopolize a worker. Encrypted
(ECMA-376) OOXML is detected and counted but not decrypted.

## Build & test

The tests need real libyara, so they run **inside the image build** (CGO, race
detector). CI fails on a bad commit before an image is ever published:

```sh
# unit tests + go vet, against the same statically-linked libyara as production:
docker build --target test -f docker/Dockerfile -t yarad-test .

# the production image (distroless, nonroot, ~74 MB):
docker build --target final -f docker/Dockerfile -t eilandert/rspamd-yarad \
    --build-arg CACHEBUST=$(date +%s) .
```

## Wiring it into rspamd

The [`rspamd/`](rspamd/) directory has everything the rspamd side needs:

* [`plugins/yara.lua`](rspamd/plugins/yara.lua) — the async plugin that POSTs to
  yarad and raises a single `YARA_MATCH` symbol carrying the matched rule names.
* [`rspamd.conf.local`](rspamd/rspamd.conf.local) — how to load a *custom* lua
  module (it must be an inline `yara { }` block + explicit `lua =` include, not a
  `local.d/` file; see the comments for why).
* [`local.d/groups.conf`](rspamd/local.d/groups.conf) — the score. Ships at
  weight `7.0`; set it to `0.0` for a cautious log-only first run.

## See also

* **[gozer](https://github.com/eilandert/gozer)** — the DCC/Razor/Pyzor sibling
  backend this mirrors.
* **[rspamd-dcc-razor-pyzor](https://github.com/eilandert/rspamd-dcc-razor-pyzor)**
  — the same out-of-process pattern in a fuller rspamd deployment.
* **Article:** [YARA malware scanning in rspamd](https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/)
  — the why and how, on deb.myguard.nl.
* **Docker Hub:** `eilandert/rspamd-yarad` *(TODO: link once the repo page exists)*.

## License

[MIT](LICENSE). Baked rule sets keep their own licenses (YARA-Forge core,
signature-base, ANY.RUN, bartblaze = permissive; Didier Stevens = public
domain).

