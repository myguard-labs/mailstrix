# yarad — YARA scanning for rspamd

[![CI](https://github.com/eilandert/rspamd-yarad/actions/workflows/ci.yml/badge.svg)](https://github.com/eilandert/rspamd-yarad/actions/workflows/ci.yml)
[![fuzz](https://github.com/eilandert/rspamd-yarad/actions/workflows/fuzz.yml/badge.svg)](https://github.com/eilandert/rspamd-yarad/actions/workflows/fuzz.yml)
[![Release](https://github.com/eilandert/rspamd-yarad/actions/workflows/release.yml/badge.svg)](https://github.com/eilandert/rspamd-yarad/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/eilandert/rspamd-yarad.svg)](https://pkg.go.dev/github.com/eilandert/rspamd-yarad)

> 📋 **[Status & roadmap](#status--roadmap)** — what's already implemented and what's planned.

[rspamd](https://rspamd.com/) has **no built-in YARA module** (still true as of
4.1.0; it's an [open feature request](https://github.com/rspamd/rspamd/discussions/3511)).
`yarad` adds one without dragging YARA into rspamd itself. It runs the scanner as
a separate little HTTP service and lets rspamd ask it questions:

```
 ┌─────────────────┐  POST /scan ┌────────────┐    ┌──────────────┐
 │     rspamd      │ ─────────▶ │   yarad    │ ─▶ │   libyara    │
 │(yara.lua plugin)│ ◀───────── │(Go service)│    │compiled rules│
 └─────────────────┘  {matches}  └────────────┘    └──────────────┘
 libyara rules = curated public YARA rulesets, baked into the image
```

Why a separate service instead of a plugin? libyara is a C library (CGO). Calling
it inside an rspamd worker would block rspamd's event loop and pull a heavy C
dependency into the mail-flow image. Keeping it out-of-process means the rspamd
side stays fully async, and the scanner can be restarted, scaled, or have its
rules reloaded on its own. It's the same shape as the
[gozer](https://github.com/eilandert/gozer) DCC/Razor/Pyzor backend.

## YARA is more than a pile of regexes

It's tempting to think of YARA as "grep with a config file". It isn't. A regex
matches a string; a YARA rule matches the *shape* of a file. A rule is a small
declarative program — `strings:` (literal, hex, or regex patterns) plus a
`condition:` that combines them with boolean logic, counts, offsets, and file
position. On top of that, libyara ships **format-aware modules** that parse a
file before you match against it:

* **`pe` / `elf` / `macho` / `dotnet`** — parse the executable header so a rule
  can key off the import table, the entry-point section, the rich header, the
  number of sections, a specific exported symbol, or the .NET module GUID —
  structural traits a malware author can't change without breaking their own
  payload.
* **`hash`** — `hash.md5(0, filesize)`, or an **imphash** over the import table,
  so a rule can pin an exact known-bad blob or a whole family that shares an
  import layout.
* **`math`** — `math.entropy(...)` to flag a packed/encrypted section, mean-byte
  and chi-square tests to spot compression or XOR.
* **`time`, `console`, external variables** — runtime context folded into the
  condition. yarad sets `filename`/`extension` from the attachment name (passed
  by the plugin) and its own `VBA` flag (below), so name-keyed and macro rules
  fire instead of always seeing an empty default.

That's the difference that matters for mail: a literal-string signature dies the
moment the author edits one byte; a rule that asserts "PE file, entropy of the
last section > 7.0, imports `VirtualAlloc` and `CreateRemoteThread`, and the
overlay starts with these magic bytes" survives the next variant. Hashes catch
yesterday's exact file — rules catch tomorrow's. yarad compiles all of this
(modules and all) and runs it over every message and attachment.

## What it gives you

* **`POST /scan`** — put raw message bytes (or one MIME part) in the body, get
  back the YARA rules that matched, as JSON:
  ```json
  {"matches":[{"rule":"Suspicious_Macro","namespace":"sigbase-gen_maldoc.yar","tags":["office"],"meta":{"author":"…"}}]}
  ```
  The list is empty (`[]`, never `null`) when nothing matched. `namespace` is the
  **source ruleset file** the rule was compiled from (yarad namespaces each rule
  file by its name), so a generic rule like `http` is traceable to the set that
  shipped it — the rspamd plugin shows it as `http (anyrun-phishing.yar)`.
  Send the attachment name in an optional **`X-YARAD-Filename`** header (base64
  — the name is attacker-controlled, so encoding it stops header injection) and
  yarad sets the YARA `filename`/`extension` external variables for the scan, so
  THOR/Loki-style name-keyed rules (`filename matches /\.exe$/`, `extension ==
  ".scr"`) fire. The filename is part of the verdict cache key.
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
  `extract_encrypted_total`, `extract_msi_total`, `extract_msg_total`, `extract_onenote_total`, `extract_archive_total`, `extract_ole_package_total`, `extract_lnk_total`, `extract_pdf_total`, `extract_rtf_total`, `extract_iso_total`, `extract_encoded_script_total`, `extract_stream_matches_total`), and rule-reload activity (`reload_attempts_total`,
  `reload_success_total`, `reload_failure_total`, `reload_last_timestamp_seconds`,
  `reload_last_duration_ms`), and rule **staleness** (`yarad_rules_mtime_seconds`,
  `yarad_rules_age_seconds`, and `yarad_rules_stale` = 1 once the loaded ruleset
  is older than `YARAD_RULES_MAX_AGE` — catches a silently-broken daily rebuild).
  When the abuse.ch feeds are enabled, their
  lookup/hit/refresh counters and feed-size gauges appear too
  (`yarad_urlhaus_*`, `yarad_malwarebazaar_*`).

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

# with an attachment name (base64 — sets the filename/extension YARA vars):
printf 'MZ...' | curl -s -H 'X-YARAD-Token: changeme' \
    -H "X-YARAD-Filename: $(printf 'invoice.exe' | base64)" \
    --data-binary @- http://127.0.0.1:8079/scan
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
| `YARAD_RULES_MAX_AGE` | `0` (off) | seconds; flag rules `stale` (metric + `/ready` body) once the loaded ruleset's mtime is older than this. Fail-open: never fails readiness |
| `YARAD_RULES` | — | a precompiled `.yac` bundle; loaded instead of `RULES_DIR` (faster start) |
| `YARAD_SCAN_TIMEOUT` | `8` (s) | per-scan libyara budget |
| `YARAD_BACKEND_TIMEOUT` | `1` (s) | queue budget / how long to wait for an admission or scan slot |
| `YARAD_MAX_CONCURRENT` | `auto` (CPU count) | max concurrent libyara scans (CPU gate); `auto` = CPU count |
| `YARAD_MAX_INFLIGHT` | `auto` (2× concurrent) | max in-flight requests/buffers (admission gate); kept above the scan gate so a slow body/Redis can't starve scan slots |
| `YARAD_MAX_BODY` | `8388608` (8 MiB) | max request body, in bytes |
| `YARAD_CACHE_TTL` | `600` (s) | verdict cache TTL; `0` disables caching entirely |
| `YARAD_CACHE_SIZE` | `65536` | in-memory LRU entries |
| `YARAD_REDIS_URL` | — | optional shared L2 cache, e.g. `redis://host:6379/6` |
| `YARAD_REDIS_PREFIX` | `yara:scan:` | Redis key prefix |
| `YARAD_METRICS_AUTH` | off | require the token for `/metrics` and `/version` (`/health` & `/ready` stay open) |
| `YARAD_URLHAUS_KEY[_FILE]` | — | abuse.ch Auth-Key; enables the URLhaus malware-URL lookup (see below) |
| `YARAD_URLHAUS_REFRESH` | `21600` (s, = 6 h) | URLhaus feed refresh interval (floor 5 min) |
| `YARAD_URLHAUS_MAX_URLS` | `64` | max URLs examined per message |
| `YARAD_MBAZAAR_KEY[_FILE]` | — | abuse.ch Auth-Key (same key as URLhaus); enables the MalwareBazaar attachment-hash lookup (see below) |
| `YARAD_MBAZAAR_REFRESH` | `86400` (s, = 24 h) | MalwareBazaar feed refresh interval (floor 5 min) |
| `YARAD_MBAZAAR_FEED` | full dump | override the feed URL (e.g. the lighter "recent" export) |
| `YARAD_RULE_DENYLIST` | `http` | comma-sep rule names to suppress (case-insensitive); public sets ship demo/noise rules (e.g. Didier's `http` = `"http" nocase`) that FP on nearly every mail. Set empty to disable. |
| `YARAD_RULE_ALLOWLIST` | — | comma-sep rule names to force **log-only** (case-insensitive): the match is kept and tagged `yarad_allow`, and the plugin scores it via the 0-weight `YARA_ALLOWLISTED` symbol — demote a known-FP rule without dropping its visibility or patching the source. Deny wins if a name is in both lists. |
| `YARAD_VERBOSE` | off | log one line per request |
| `YARAD_LOG_STDOUT` | off | info/access logs to stdout (errors always go to stderr) |

**Reloading rules:** `docker kill -s HUP yarad` recompiles the rule set in place
and flushes the verdict cache. A reload that fails to compile keeps the previous
(working) rules active, so a bad rule edit can never disarm a running scanner.

## Rules

The image bakes six public rulesets at build time. A daily rebuild
(`--build-arg CACHEBUST=$(date +%s)`) re-pulls the latest. **Full credit to the
authors — yarad only packages their work; the rules are theirs.** Each set keeps
its own license:

| Ruleset | Author / source | License | Notes |
|---------|-----------------|---------|-------|
| **YARA-Forge package** | [YARAHQ/yara-forge](https://github.com/YARAHQ/yara-forge) | aggregator (tooling GPL-3.0; **each bundled rule retains its upstream author's license**) | ingests dozens of public repos, dedupes, drops the broken/dangerous, ships one vetted bundle in quality tiers; default is `core`, opt into `extended`/`full` with `YARAFORGE_SET` |
| **signature-base** | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) (Florian Roth) | [Detection Rule License (DRL) 1.1](https://github.com/Neo23x0/signature-base/blob/master/LICENSE) (permissive) | the broad community malware/phishing set behind THOR/Loki |
| **ANY.RUN** | [anyrun/YARA](https://github.com/anyrun/YARA) | published as public detection rules (no separate LICENSE file) | actively maintained malware-family + phishing (`ANYRUN=0` to skip) |
| **Didier Stevens Suite** | [DidierStevens/DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite) | **public domain** ("no Copyright, use at your own risk") | OLE/RTF/maldoc rules — incl. the `vba.yara` macro-keyword set that fires on extracted VBA (see below), plus a tiny PDF/ActiveMime maldoc rule; curated subset, the multi-thousand-rule PEiD packer DB is excluded (`DIDIER=0` to skip) |
| **bartblaze/Yara-rules** | [bartblaze/Yara-rules](https://github.com/bartblaze/Yara-rules) | **MIT** | maldoc/RTF (RoyalRoad, OLE-in-CAD) + phishing-doc rules not aggregated by YARA-Forge (`BARTBLAZE=0` to skip) |
| **InQuest yara-rules-vt** | [InQuest/yara-rules-vt](https://github.com/InQuest/yara-rules-vt) | **MIT** | curated mail-carrier subset: PDF launch/JS, LNK command refs, OneNote, Outlook `.msg`, RTF exploit/obfuscation rules (`INQUEST=0` to skip) |

Together that's roughly 10,000+ rules. Pin or toggle any source with a build arg:
`--build-arg YARAFORGE_SET=extended` (or `core`/`full`),
`--build-arg YARAFORGE_URL=…`, `--build-arg SIGBASE_REF=<tag>`,
`--build-arg ANYRUN_REF=<ref>`, `--build-arg DIDIER_REF=<ref>`,
`--build-arg BARTBLAZE_REF=<ref>`, `--build-arg INQUEST_REF=<ref>`
(and `DIDIER=0` / `BARTBLAZE=0` / `ANYRUN=0` / `INQUEST=0`).

The default bundle is intentionally mail-oriented: YARA-Forge `core` plus
signature-base, ANY.RUN, Didier's curated Office/RTF/maldoc rules, bartblaze
maldoc/phishing-doc rules, and a curated InQuest subset. InQuest is not imported
wholesale; yarad currently copies the PDF launch/JS rules, LNK command-reference
rules, OneNote suspicious-string rule, Outlook `.msg` phishing rule, and selected
RTF exploit/obfuscation rules. The InQuest PDF rule that `yarac` flags as slow
(`PDF_with_Embedded_RTF_OLE_Newlines.yar`) is deliberately excluded.

The Didier addition beyond the upstream `vba`/`rtf`/`maldoc` files is
`didier-pdf-activemime.yara`, a small PDF/ActiveMime polyglot detector based on
Didier Stevens' public write-up. It avoids broad regexes so it does not add new
slow-rule warnings.

Public rulesets are messy by nature, so two things keep them from breaking the
build:

* libyara is compiled **without** the `magic`/`cuckoo` modules (not needed for
  email attachments), and rules that import them are skipped.
* Each rule file is test-compiled on its own first; a single unparseable file is
  logged and skipped rather than aborting the whole load. It's an error only if
  *nothing* compiles.

## OLE / RTF / Office-macro handling

Malware in mail mostly arrives as a document, and a document hides its payload in
ways a raw byte-scan can't see. yarad handles the three shapes separately:

**OLE2 / OOXML macros — decompress, then scan.** A raw `.docm`/`.xlsm` is a ZIP
whose VBA macros sit **MS-OVBA run-length-compressed** inside a `vbaProject.bin`
(itself an OLE2/CFB compound file); a legacy `.doc`/`.xls` is OLE2 directly. YARA
keyword rules scanning the raw bytes see only the compressed blob — they never
fire. So before matching, yarad magic-sniffs `D0CF11E0` (OLE2) / `PK\x03\x04`
(zip) and **decompresses the VBA back to cleartext** with the pure-Go
[Velocidex/oleparse](https://github.com/Velocidex/oleparse) (no extra C deps,
runs the MS-OVBA `DecompressStream`). It then scans **both** the raw bytes
(file-format/exploit rules) and the decompressed macro source (keyword rules),
and merges + de-duplicates the matches. While scanning the cleartext, the
external YARA variable `VBA` is set to `1`, so Didier's `vba.yara` rules (`VBA
and any of (...)` — `AutoOpen`, `Shell`, `CallByName`, …) fire exactly where they
should and stay inert on raw bytes.

**Filename / extension externals — name-keyed rules.** A large slice of the
public rulesets (THOR/Loki signature-base) keys on the file *name*, not just its
bytes: `filename matches /\.(exe|scr|js)$/`, `extension == ".lnk"`. The rspamd
plugin sends each MIME part's filename to yarad (base64, in `X-YARAD-Filename`),
which sets the YARA `filename` and `extension` external variables for that scan —
on both the raw bytes and any decompressed macro stream. For InQuest's Outlook
message rule, `.msg`/`.oft` names also set `file_type = "outlook"`; otherwise
`file_type` stays empty. With no name (the whole-message scan, or an unnamed
part) the variables keep their empty default and those conditions stay inert,
exactly as before. Because the verdict now depends on the name, the filename is
folded into the verdict cache key: the same bytes carried as `invoice.pdf` and
`invoice.exe` are scanned and cached separately. `filepath`/`filetype`/`owner`
stay empty — yarad has no real path, magic-type, or owner for a mail attachment.

**RTF exploits — raw-byte rules plus `\objdata` carve.** RTF maldocs (the classic
CVE-2017-11882 Equation-Editor drop, CVE-2017-0199 / OLE2Link) carry their payload
as hex in the raw `.rtf`, so the signature-base / Didier `rtf.yara` exploit rules
already match the raw bytes directly. yarad *additionally* hex-decodes every
`{\*\objdata …}` group and surfaces the decoded object — a full OLE2 (CFB) blob is
re-run through the macro/package/MSI/`.msg` extraction, a bare `Ole10Native` is
carved directly — so the dropped binary itself is scanned, not only the RTF
wrapper (`extract_rtf_total`).

**Deobfuscation.** Two passes. (1) The MS-OVBA decompression above *is* the first
deobfuscation — it turns the on-disk compressed stream into the source the author
wrote. (2) On every buffer (raw message **and** each decompressed macro/RTF
stream) yarad runs cheap, bounded URL **defanging** — `hxxp`→`http`, `[.]`/`(dot)`
→`.`, `[:]`→`:` — so a malware URL written `hxxp://evil[.]tld` is un-mangled
before the URLhaus lookup (below). A hit found only after defanging is flagged
`_DEOBF`.

Extraction is **best-effort and fail-open**: a non-document, a parse error, an
encrypted package, or a hostile/poison file (oleparse panics are recovered) just
falls back to a raw-only scan — a broken document never blocks mail. The whole
request shares one `YARAD_SCAN_TIMEOUT` budget across raw + every macro stream,
and zip-bomb caps bound the work (max streams / bytes-per-bin / total cleartext /
zip entries / parsed `.bin` count), so a document stuffed with hundreds of
modules can't monopolize a worker. Encrypted (ECMA-376) OOXML is detected and
counted (`yarad_extract_encrypted_total`) but **not** decrypted.

### How much of Python's oletools this replaces

The Python [oletools](https://github.com/decalage2/oletools) suite (`olevba`,
`mraptor`, `oleid`, `rtfobj`, …) is the reference toolkit for maldoc triage, and
yarad's [`rspamd-olefy`](https://github.com/eilandert/rspamd-olefy) sibling wraps
it. With the extract front-end above **plus the baked maldoc rules, yarad now
covers roughly 80% of what oletools does for mail, in-process and with no Python**:

* **VBA extraction + MS-OVBA decompression** — the core of `olevba`. ✅
* **Macro keyword / autoexec / suspicious-call detection** — `olevba`'s indicator
  list and `mraptor`'s autoexec+write+execute heuristic, expressed as YARA rules
  (`vba.yara`, signature-base maldoc rules) over the cleartext. ✅
* **OLE indicators** — macro presence and ECMA-376 **encryption** detection, the
  heart of `oleid`. ✅
* **RTF / embedded-OLE exploit detection** — CVE-2017-11882 etc. via raw-byte
  rules, the maldoc half of `rtfobj`. ✅
* **IOC / URL extraction → reputation** — yarad goes *beyond* oletools here by
  checking extracted URLs against the live URLhaus feed (below). ✅
* **Attachment-hash reputation** — the SHA256 of each attachment is matched
  against the abuse.ch MalwareBazaar corpus of known malware samples (below). ✅

The remaining ~20% is the deep tail that still belongs to oletools/olefy, and why
that scorer stays running in parallel: `olevba`'s **deobfuscation decode**
(actually decoding Base64/hex/`StrReverse`/Dridex chains to reveal the hidden
string, not just pattern-matching that they're present), **XLM / Excel-4.0 macro
emulation**, and `rtfobj`'s **carve-and-decode** of embedded objects out of
hostile RTF. yarad matches the *patterns* of obfuscation; it doesn't fully decode
them. So `rspamd-olefy` remains the parallel deep-scan scorer until that tail is
covered.

## URLhaus malware-URL lookup (optional)

Set an abuse.ch Auth-Key (free, <https://auth.abuse.ch/>) via `YARAD_URLHAUS_KEY`
to also check every message — and every decompressed macro/RTF stream — for URLs
that appear in the [URLhaus](https://urlhaus.abuse.ch/) feed of known
malware-distribution links. The feed is downloaded once per `YARAD_URLHAUS_REFRESH`
(floor 5 min, fair-use) into an in-memory set; lookups are local map hits, never a
per-message API call, and a failed refresh keeps the previous set. Cheap defanging
(`hxxp`, `host[.]tld`, `(dot)`) catches URLs hidden in document code.

Hits come back as matches with rule names `URLHAUS_MALWARE_URL` (exact),
`URLHAUS_MALWARE_HOST` (known-bad host), and a `_DEOBF` variant when only found
after defanging; the matched URL/host is carried in `meta.url`. The rspamd plugin
routes these to a separate `URLHAUS_MALWARE_URL` symbol (so they score
independently of YARA rules) and uses the **URL itself** as the symbol option —
so the rspamd history shows the actual malicious link, not just a constant rule
name — with a `(host)`/`(deobf)` tag for those variants.

## MalwareBazaar attachment-hash lookup (optional)

Set the **same** abuse.ch Auth-Key via `YARAD_MBAZAAR_KEY` to also check the
SHA256 of every scanned attachment against the
[MalwareBazaar](https://bazaar.abuse.ch/) corpus of known malware samples. An
exact hash hit is a direct file-level "this is known malware" verdict,
independent of the YARA rules.

Same fail-open feed-cache infra as URLhaus: the full CSV dump is downloaded once
per `YARAD_MBAZAAR_REFRESH` (daily by default, floor 5 min) into an in-memory set
of raw 32-byte digests (~40 MiB for ~1M samples — kept as `[32]byte` keys, not
hex, to stay lean), and lookups are local map hits, never a per-message API call.
A failed refresh keeps the previous set. The dump is a ZIP (one CSV); a plain-CSV
feed (the lighter "recent" export, via `YARAD_MBAZAAR_FEED`) is also accepted —
the body is magic-sniffed. **Memory:** the full feed adds ~40 MiB resident plus a
~100–150 MiB transient spike while the daily dump is downloaded + unzipped; raise
the container `mem_limit` (~768m) when enabling it.

Hits come back as matches with rule name `MALWAREBAZAAR_MALWARE` and the matched
digest in `meta.sha256`. The rspamd plugin routes these to a separate
`MALWAREBAZAAR_MALWARE` symbol (highest weight — an exact known-malware file) and
uses the **SHA256 itself** as the symbol option, so the history names the bad
file (paste it into MalwareBazaar for the family/analysis).

## Build & test

The tests need real libyara, so they run **inside the image build** (CGO, race
detector). CI fails on a bad commit before an image is ever published:

```sh
# unit tests + go vet, against the same statically-linked libyara as production:
docker build --target test -f docker/Dockerfile -t yarad-test .

# the production image (distroless, nonroot, ~74 MB: ~37 MB compiled rules +
# ~25 MB distroless base/libs + ~8 MB Go/libyara binary):
docker build --target final -f docker/Dockerfile -t eilandert/rspamd-yarad \
    --build-arg CACHEBUST=$(date +%s) .

# broader YARA-Forge coverage, still with the same curated extra mail sources:
docker build --target final -f docker/Dockerfile -t eilandert/rspamd-yarad \
    --build-arg CACHEBUST=$(date +%s) \
    --build-arg YARAFORGE_SET=extended .
```

## Wiring it into rspamd

The [`rspamd/`](rspamd/) directory has everything the rspamd side needs:

* [`plugins/yara.lua`](rspamd/plugins/yara.lua) — the async plugin that POSTs to
  yarad and **classifies each matched rule into a scoring tier** (by its name /
  source-file / tags / `meta.score`), raising one of these symbols with the
  matched rules as options (`name (source-file.yar)`, so a hit is traceable to
  its ruleset):

  | symbol | tier | default weight |
  |--------|------|----------------|
  | `YARA_MALWARE` | malware family / webshell / RAT / APT / ransomware | `8.0` |
  | `YARA_EXPLOIT` | exploit / CVE / maldoc exploit | `7.0` |
  | `YARA_PHISHING` | phishing kit / document | `5.0` |
  | `YARA` | uncategorized rule match (default bucket) | `4.0` |
  | `YARA_SUSPICIOUS` | heuristic / suspicious / anomaly (FP-prone) | `2.0` |
  | `URLHAUS_MALWARE_URL` | known malware URL — options are the **URLs** (`(host)`/`(deobf)` tagged) | `8.0` |

  Tiers stack, capped by the group `max_score`. The classifier is heuristic and
  lives in the plugin, so retuning needs only an rspamd reload (no yarad rebuild).
* [`rspamd.conf.local`](rspamd/rspamd.conf.local) — how to load a *custom* lua
  module (it must be an inline `yara { }` block + explicit `lua =` include, not a
  `local.d/` file; see the comments for why).
* [`local.d/groups.conf`](rspamd/local.d/groups.conf) — the per-tier weights
  (above). Set any tier to `0.0` for a cautious log-only first run.

## Status & roadmap

### Already in

- [x] Out-of-process Go scanner over HTTP (`/scan`); rspamd never blocks on libyara
- [x] ~10k+ public rules baked in (YARA-Forge, signature-base, ANY.RUN, Didier, bartblaze, InQuest), daily refresh, precompiled `.yac`
- [x] libyara modules `pe`/`elf`/`macho`/`dotnet`/`hash`/`math`/`dex` (no magic/cuckoo)
- [x] `/health`, `/ready`, `/version`, `/metrics` (Prometheus); graceful drain on SIGTERM
- [x] Verdict cache (LRU+TTL) + request coalescing (singleflight); optional Redis/Valkey L2 with circuit breaker
- [x] Fail-open everywhere; concurrency gate, admission gate, per-scan timeout, body cap
- [x] OLE2/OOXML macro **decompression** (MS-OVBA) → scans raw **and** decompressed VBA, `VBA` external var
- [x] RTF / embedded-OLE exploit detection (raw-byte rules)
- [x] URL **defang** + **URLhaus** malware-URL/host lookup (cached feed, fail-open)
- [x] Rule **source-file** surfaced in matches (`rule (source-file.yar)`)
- [x] `YARAD_RULE_DENYLIST` — drop public demo/noise rules (default `http`)
- [x] **Tiered scoring** — `YARA_MALWARE`/`YARA_EXPLOIT`/`YARA_PHISHING`/`YARA`/`YARA_SUSPICIOUS` + `URLHAUS_MALWARE_URL`
- [x] rspamd plugin fan-out bounded (`max_jobs` cap + per-part dedup)
- [x] SIGHUP rule reload (atomic swap, keeps old rules on a bad edit)
- [x] Distroless, non-root, read-only rootfs (~74 MB)

### Planned (sorted low-investment → high-return)

**Quick wins (low effort, high value):**
- [x] Pass filename/extension to yarad → set YARA `filename`/`extension` external vars (activates many existing rules) — `X-YARAD-Filename` (base64) header, plugin sends the MIME part name
- [x] MalwareBazaar attachment-hash lookup (SHA256 → known malware; cached full-dump feed, fail-open, own symbol)
- [x] Use `meta.score` in classification (finer tiering, no new parsers) — plugin scales the symbol weight by the rule's `meta.score` onto a `[score_weight_min, score_weight_max]` band
- [x] Rule-staleness healthcheck/metric (catch a silently-broken daily rebuild) — `yarad_rules_age_seconds`/`yarad_rules_stale` metrics + `YARAD_RULES_MAX_AGE`; `/ready` notes "stale rules" (fail-open, never pulls the scanner out of rotation)
- [x] MSI extraction (OLE2, reuse the macro `fromOLE` path) — recognise a Windows Installer database by its root CLSID and dump its streams (CustomAction script bodies, embedded DLL/EXE names) for the keyword rules; `extract_msi_total` metric
- [x] VBE/JSE decode + WSF/HTA cleartext surfacing — decode MS-Script-Encoder (`#@~^…^#~@`) blocks to cleartext so keyword rules match the real script (covers `.vbe`/`.jse` and encoded blocks embedded in `.wsf`/`.hta`/`.html`/`.sct`); `extract_encoded_script_total` metric
- [x] Rule allowlist (force-log-only without patching the source) — `YARAD_RULE_ALLOWLIST` keeps a known-FP rule's match visible but tags it `yarad_allow`; the plugin routes it to the 0-weight `YARA_ALLOWLISTED` symbol
- [x] Outlook `.msg` nested-attachment extraction (OLE2) — recognise a MAPI `.msg` (props store + attachment storages) and surface each nested attachment's `PR_ATTACH_DATA_BIN` stream for scanning; `extract_msg_total` metric (nested doc/archive attachments are scanned as raw bytes — deep re-extraction is a separate item)
- [x] Per-tier / per-extractor `/metrics` — per-extractor counters (`extract_*` incl. `extract_msi_total`, `extract_encoded_script_total`) plus `extract_stream_matches_total` (hits attributable only to an extracted stream — what pre-extraction adds over a raw scan). Per-**tier** counts come from rspamd's native per-symbol stats (`YARA_MALWARE`/`YARA_EXPLOIT`/… are real symbols), so no duplicate counter in yarad.

**Worth it (more effort, high value):**
- [x] OneNote `.one` embedded-object extraction (top post-macro vector) — recognise a OneNote section/TOC by its file-type GUID and carve every embedded `FileDataStoreObject` (the dropped `.exe`/`.hta`/`.cmd`/`.lnk` payload) for the keyword/PE rules; `extract_onenote_total` metric
- [x] Nested-archive unpacking (`.zip`/`.7z`/`.rar`/`.gz`/`.tar.gz`) — unpack each member and recurse into nested archives/containers up to a bounded depth, surfacing the inner dropper for scanning; bounded by shared depth/member-count/total-byte budget (decompression-bomb + archive-quine guard). Office docs (OOXML/ODF zips) stay on the macro path only (no part-dumping — FP guard). `extract_archive_total` metric
- [x] OLE Package-object / embedded-EXE carve — carve the dropped file (`.exe`/`.bat`/`.scr`) out of an `\x01Ole10Native` Packager stream embedded in an OLE2 document (the "double-click the icon to run" maldoc trick); bounds-checked field walk, clamps a hostile NativeDataSize; `extract_ole_package_total` metric
- [x] `.lnk` shortcut parsing — parse the Windows ShellLink header and surface the StringData fields (name / relative-path / working-dir / **command-line arguments** / icon) so a `powershell -enc …` / `cmd /c …` payload hidden in a shortcut is matched; bounds-checked section walk, UTF-16→UTF-8; `extract_lnk_total` metric

**Bigger / niche (lower ratio):**
- [x] RTF embedded-object (`\objdata`) carve — hex-decode every `{\*\objdata …}` group in an RTF document (the CVE-2017-0199 / CVE-2017-11882 / OLE2Link delivery path) and surface the decoded object: a full OLE2 (CFB) blob runs the same macro / package / MSI / `.msg` extraction, a bare `Ole10Native`/OLENativeStream is carved directly. Sibling of the OLE Package carve, which only covered the OLE2-storage case. BOM-tolerant recogniser, bounded object-count / per-object / total-byte caps, skips whitespace-broken hex; `extract_rtf_total` metric
- [x] PDF pre-extraction — carve every `stream … endstream` object body and inflate it (FlateDecode: zlib then raw-deflate), surfacing the decompressed bytes so hidden JS / `/OpenAction` / `/Launch` / embedded files are matched; bounded inflate attempts + per-stream/total caps (decompression-bomb guard), token-boundary check so a stray `stream` can't hide the real object; `extract_pdf_total` metric
- [ ] ThreatFox / Feodo Tracker IOC feeds (domains/IPs)
- [ ] File-level fuzzy hashing (TLSH/ssdeep)
- [x] ISO9660 disc-image (`.iso`) member extraction — walk the directory tree (plain ECMA-119 + the Joliet supplementary descriptor for Unicode names) and surface every regular file's bytes, so a dropper mailed inside an `.iso` (the mark-of-the-web bypass) is scanned as its own buffer rather than buried in the on-disk filesystem layout; bounded file-count / directory-walk / per-file / total-byte caps, cycle-guarded; `extract_iso_total` metric. UDF / `.img` (FAT) / VHD(X) images not yet handled (separate items)
- [ ] UDF / `.img` (FAT) / VHD(X) container extraction
- [ ] CHM / CAB / MSIX extraction
- [ ] Extractor sandbox hardening (seccomp/rlimits) — after more parsers land
- [ ] Batch `/scan` endpoint (collapse N part round-trips)
- [ ] macOS `.dmg`/`.pkg`/`.mpkg` → Mach-O; Android `.apk` → dex/manifest
- [ ] PE-overlay bytes; `.url`/`.settingcontent-ms` launcher fields

> iOS/iPhone is intentionally out of scope — no executable email vector.

## See also

* **[gozer](https://github.com/eilandert/gozer)** — the DCC/Razor/Pyzor sibling
  backend this mirrors.
* **[rspamd-dcc-razor-pyzor](https://github.com/eilandert/rspamd-dcc-razor-pyzor)**
  — the same out-of-process pattern in a fuller rspamd deployment.
* **Article:** [YARA malware scanning in rspamd](https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/)
  — the why and how, on deb.myguard.nl.
* **Docker Hub:** `eilandert/rspamd-yarad` *(TODO: link once the repo page exists)*.

## License

yarad itself is [MIT](LICENSE). The baked rule sets are **not** yarad's work and
**keep their own licenses** — see the [Rules](#rules) table for per-source credit:
signature-base = DRL 1.1, bartblaze = MIT, InQuest = MIT, Didier Stevens =
public domain, ANY.RUN = public detection rules, and the YARA-Forge package is an
aggregate where each rule retains its upstream author's license. Dependencies are permissive
(`go-yara` BSD-2, `oleparse` MIT, redis client BSD/Apache).
