# yarad — YARA malware scanning for rspamd

[![CI](https://github.com/eilandert/rspamd-yarad/actions/workflows/ci.yml/badge.svg)](https://github.com/eilandert/rspamd-yarad/actions/workflows/ci.yml)
[![fuzz](https://github.com/eilandert/rspamd-yarad/actions/workflows/fuzz.yml/badge.svg)](https://github.com/eilandert/rspamd-yarad/actions/workflows/fuzz.yml)
[![Release](https://github.com/eilandert/rspamd-yarad/actions/workflows/release.yml/badge.svg)](https://github.com/eilandert/rspamd-yarad/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/eilandert/rspamd-yarad.svg)](https://pkg.go.dev/github.com/eilandert/rspamd-yarad)

**yarad is a small HTTP service that scans mail with [YARA](https://virustotal.github.io/yara/)** —
the malware-detection rule engine — against ~10,000 curated public rules. Put a
message (or one attachment) on `POST /scan`; get back the rules that matched.

YARA is the engine malware analysts use to recognise *families* of malicious
files — booby-trapped Office docs, packed executables, phishing kits, script
droppers. A literal-string signature dies the moment the author edits a byte; a
YARA rule matches the *shape* of a file (PE imports, section entropy, embedded
magic) and survives the next variant. yarad compiles those rules — libyara
modules and all — and runs them over your mail.

Two ways to plug it in (both shipped here):

- **rspamd** — an async `yara.lua` plugin ([`rspamd/`](rspamd/)) POSTs each
  message/part to yarad at SMTP time and turns the hits into a spam-score symbol.
- **Dovecot / Sieve** — the lean [`yarad-scan`](#thin-client-for-dovecot--sieve-yarad-scan)
  client scans at *delivery* and a Sieve rule quarantines a match
  ([`sieve/`](sieve/)).

```
 ┌──────────────────────┐  POST /scan ┌────────────┐    ┌──────────────┐
 │ rspamd  (yara.lua)   │ ─────────▶ │   yarad    │ ─▶ │   libyara    │
 │   or  Dovecot/Sieve  │ ◀───────── │(Go service)│    │compiled rules│
 │      (yarad-scan)    │  {matches}  └────────────┘    └──────────────┘
 └──────────────────────┘
```

> **Where should YARA scanning live — opinion.** YARA scanning is genuinely
> CPU-intensive, and the MTA hot path is the most latency-sensitive place to spend
> that CPU: every connection waits on it, and at SMTP time you scan a lot of mail
> you will reject anyway. A defensible view is that it doesn't belong in the MTA at
> all — scanning at **delivery** (Dovecot LDA / Sieve), *after* rspamd has already
> dropped the obvious spam, scans far less and off the connection's critical path.
> Which is right depends on your mailflow and goals: scan early at SMTP to *reject*
> with rspamd's score, or scan late at delivery to *quarantine* a smaller, cleaner
> stream. yarad supports both; see the [thin client](#thin-client-for-dovecot--sieve-yarad-scan)
> and [`sieve/`](sieve/) for the delivery-time path.

It runs **out of process**, never inside the MTA worker, because libyara is a C
library (CGO): in an rspamd worker it would block the event loop and drag a heavy
C dependency into the mail image. Separate, the caller stays async and yarad can
be scaled, restarted, or reload its rules on its own. Same shape as the
[gozer](https://github.com/eilandert/gozer) DCC/Razor/Pyzor backend.

> 📋 Jump to **[Status & roadmap](#status--roadmap)** for what's done vs planned.

## Exactly what it does

- **Scans mail with YARA** — `POST /scan` raw message bytes (or one MIME part),
  get back the matched rules as JSON; the rspamd `yara.lua` plugin
  ([`rspamd/`](rspamd/)) wires the hits into the spam score, or the `yarad-scan`
  client scans at delivery from Dovecot/Sieve ([`sieve/`](sieve/)).
- **Ships ~10k public rules baked in** — YARA-Forge, signature-base, ANY.RUN,
  Didier Stevens, bartblaze, InQuest; precompiled `.yac`, daily refresh.
- **Decompresses Office macros before matching** — MS-OVBA VBA out of
  `.docm`/`.xlsm`/`.doc`/`.xls`, scans the cleartext (sets the `VBA` rule var).
- **Cracks open containers** — pulls the hidden payload out of: OLE2/OOXML,
  RTF `\objdata`, OLE Package (`Ole10Native`), MSI, Outlook `.msg`, OneNote
  `.one`, PDF (FlateDecode streams), `.lnk` shortcuts, VBE/JSE encoded scripts,
  and nested archives (zip/7z/rar/gz/tar.gz, recursive) — then scans each.
- **Uses the attachment name** — `filename`/`extension` YARA vars from the
  plugin's `X-YARAD-Filename`, so name-keyed (THOR/Loki) rules fire.
- **Checks abuse.ch feeds (optional)** — URLhaus malware-URL/host lookup (with
  URL defanging) and MalwareBazaar attachment-SHA256 lookup; cached, fail-open.
- **Drops/demotes noisy rules** — `YARAD_RULE_DENYLIST` (suppress) and
  `YARAD_RULE_ALLOWLIST` (keep but score log-only) without patching upstream.
- **Caches verdicts** — `SHA256(body)` → matches (LRU+TTL), plus request
  coalescing and an optional shared Redis/Valkey L2, for a high-volume firehose.
- **Fails open, always** — a scan error, timeout, or libyara panic is reported
  as "no match"; a broken scanner never blocks mail. Bounded concurrency,
  per-scan timeout, body cap, graceful drain on SIGTERM.
- **Updatable rules without a rebuild** — `yarad fetch-rules` pulls a
  version-matched, sha256-verified compiled bundle into a cache; SIGHUP reloads.
- **CLI tools** — `yarad scan` (local triage), `yarad extract` (dump what a
  container carves), `yarad check-rules`, `yarad info`; and `yarad-scan`, a tiny
  CGO-free client for a Dovecot/Sieve box ([`sieve/`](sieve/)).
- **Observable** — `/health`, `/ready`, `/version`, Prometheus `/metrics`
  (scans, matches, cache, per-extractor counters, rule staleness).

## Quick start

The image already bakes ~10k rules, so a token is all you need:

```sh
docker run -d --name yarad \
    -e YARAD_TOKEN=changeme \
    -p 8079:8079 \
    eilandert/rspamd-yarad

# ask it something:
printf 'hello' | curl -s -H 'X-YARAD-Token: changeme' \
    --data-binary @- http://127.0.0.1:8079/scan
# -> {"matches":[]}
```

To use your own rules instead of the baked bundle:

```sh
docker run -d --name yarad \
    -e YARAD_TOKEN=changeme \
    -e YARAD_RULES= \
    -e YARAD_RULES_DIR=/rules \
    -v "$PWD/myrules:/rules:ro" \
    -p 8079:8079 \
    eilandert/rspamd-yarad
```

Send an attachment name so name-keyed rules fire (base64 — the name is
attacker-controlled, encoding it stops header injection):

```sh
printf 'MZ...' | curl -s -H 'X-YARAD-Token: changeme' \
    -H "X-YARAD-Filename: $(printf 'invoice.exe' | base64)" \
    --data-binary @- http://127.0.0.1:8079/scan
```

> **Token is optional but recommended.** Set `YARAD_TOKEN` (or
> `YARAD_TOKEN_FILE`) and the caller must present the same secret as a `Bearer`
> header or `X-YARAD-Token`. Leave it unset (or `none`/`0`/`off`) to run an
> **open** scanner for a trusted private network — yarad logs a loud warning,
> since anyone who can reach the port can submit CPU-costly scans.

The `/scan` reply names the rule **and** its source ruleset file:

```json
{"matches":[{"rule":"Suspicious_Macro","namespace":"sigbase-gen_maldoc.yar","tags":["office"],"meta":{"author":"…"}}]}
```

The list is `[]` (never `null`) when nothing matched. `namespace` is the file the
rule was compiled from, so a generic rule like `http` is traceable to the set
that shipped it. For the hardened container setup (read-only rootfs, dropped
caps, Docker secret, static IPv4) see
[`docker/docker-compose.yml`](docker/docker-compose.yml).

## Scanning without a server

The same binary scans locally — no HTTP, no token — by compiling the rules
in-process. For one-off triage and pipelines:

```sh
yarad scan suspicious.doc            # one file
yarad scan /var/mail/cur             # a maildir, recursed
cat msg.eml | yarad scan             # stdin
yarad scan -json /tmp/quarantine     # machine-readable
```

Exit codes: **0** clean, **1** ≥1 match, **2** usage/load/read error. Other
helpers share the binary (`yarad help`):

```sh
yarad check-rules            # compile rules, print the count, non-zero on failure (CI gate)
yarad extract suspicious.doc # show what the extractor carves (no scan)
yarad fetch-rules            # update the cached rule bundle from the release
yarad info                   # build / libyara / loaded-bundle identity
```

### Updating rules without rebuilding (`fetch-rules`)

Rules move faster than image rebuilds — and outside Docker you'd otherwise need
`yarac` + a matching libyara to compile them. `yarad fetch-rules` downloads a
prebuilt, version-matched bundle into the cache instead:

```sh
yarad fetch-rules -cache-dir /var/cache/yarad
```

It reads a small manifest first and updates only when the published **version**
is newer; it **refuses** a bundle built against a different **libyara**,
**verifies the sha256**, and swaps atomically (keeping one `.bak`). On any error
the current bundle is untouched. Then SIGHUP (or restart) yarad to load it. The
bundle is published by `docker/generate-rules.sh` (run from cron); point `-url` /
`YARAD_RULES_URL` at a mirror if not fetching from GitHub.

## Thin client for Dovecot / Sieve (`yarad-scan`)

`yarad scan` (above) compiles the rules **in-process**, so it needs libyara and
the rule set on the host that runs it — fine on the scanner box, too heavy for a
mail-delivery box that should stay thin. **`yarad-scan`** is the answer: a
separate, tiny client that links **no CGO / libyara and embeds no rules** — pure
Go, a ~5 MB static binary you can drop on any mail host. It just reads the
message (stdin or a file), POSTs it to a central `yarad serve`, and exits on the
verdict — so all the CPU-heavy scanning stays on the central service.

```sh
# stdin or a file; exit code carries the verdict:
yarad-scan -url http://yarad.internal:8079 -token-file /etc/yarad.token - < message
cat message | yarad-scan -url http://yarad.internal:8079
```

| | |
|--|--|
| **Exit 0** | clean — no rule matched (**also** on a fail-open scanner outage) |
| **Exit 1** | at least one rule matched |
| **Exit 2** | usage / read / (fail-closed) transport error |

- **Fails open by default** — any transport error, timeout, or non-200 is treated
  as *clean* (exit 0), so a scanner outage never blocks or bounces delivery. Pass
  `-fail-open=false` for interactive triage where a silent miss is worse.
- **Token** via `-token-file` or `YARAD_TOKEN` — never `-token` on a shared host
  (it shows in `ps`). Redirects are never followed, so the token can't leak to a
  3xx target.
- **Same wire format** as the rspamd plugin: `X-YARAD-Token` for auth, base64
  `X-YARAD-Filename` for the attachment name.

This is the **delivery-time** path from the opinion in the intro: let rspamd drop
the obvious spam at SMTP, then scan the smaller, cleaner stream with YARA at
delivery and quarantine a hit — off the connection's critical path.

A ready-to-use Dovecot Sieve example (the `execute` rule, an install wrapper, the
dovecot config, and a setup/test walkthrough) lives in **[`sieve/`](sieve/)**.
Because the client fails open, a delivery is never lost if the backend is down.

## Configuration

Every setting is an env var and a `serve` CLI flag (flag > env > default).

| Env | Default | Meaning |
|-----|---------|---------|
| `YARAD_HOST` / `YARAD_PORT` | `0.0.0.0` / `8079` | HTTP bind address |
| `YARAD_TOKEN[_FILE]` | — | shared secret for `/scan` (optional); comma-separated for zero-downtime rotation (e.g. `old,new`); unset / `none` / `0` / `off` ⇒ auth disabled, `/scan` runs **open** (warned at startup) |
| `YARAD_TOKEN_NEXT[_FILE]` | — | incoming rotation token accepted alongside the primary; append here then migrate clients, then promote to `YARAD_TOKEN` and clear this |
| `YARAD_RULES_DIR` | `/rules` | dir of `*.yar`/`*.yara` compiled at boot and on SIGHUP |
| `YARAD_RULES` | — | a precompiled `.yac` bundle; loaded instead of `RULES_DIR` (faster start) |
| `YARAD_RULES_MAX_AGE` | `0` (off) | seconds; flag rules `stale` (metric + `/ready` body) once older than this. Fail-open: never fails readiness |
| `YARAD_SCAN_TIMEOUT` | `8` (s) | per-request libyara budget (raw + all extracted streams share it) |
| `YARAD_BACKEND_TIMEOUT` | `1` (s) | how long to wait for an admission / scan slot |
| `YARAD_MAX_CONCURRENT` | `auto` (CPU count) | max concurrent libyara scans (CPU gate) |
| `YARAD_MAX_INFLIGHT` | `auto` (2× concurrent) | max in-flight requests (admission gate); kept above the scan gate so a slow body/Redis can't starve scans |
| `YARAD_MAX_BODY` | `8388608` (8 MiB) | max request body, in bytes (checked before reading) |
| `YARAD_EFFORT_MAX` | `10` | effort-tier ceiling (1–10); the hard cap a per-request `X-YARAD-Effort` header can never exceed (DoS guard) |
| `YARAD_EFFORT` | `= YARAD_EFFORT_MAX` | default effort level when no `X-YARAD-Effort` header is sent (1 = raw + shallowest extraction, max = full depth). Set to `auto` (EFFORT-2) to derive the level from admission-gate pressure — full depth when idle, shedding a level at a time as in-flight scans fill the gate, climbing back as it drains (one level/scan; `yarad_effort_auto_level` gauge tracks it). *Plumbing landed (EFFORT-1/2); caps wire to it in EFFORT-4 — until then all levels behave identically.* |
| `YARAD_CACHE_TTL` | `600` (s) | verdict cache TTL; `0` disables caching |
| `YARAD_CACHE_SIZE` | `65536` | in-memory LRU entries |
| `YARAD_REDIS_URL` | — | optional shared L2 cache, e.g. `redis://host:6379/6` |
| `YARAD_REDIS_PREFIX` | `yara:scan:` | Redis key prefix |
| `YARAD_METRICS_AUTH` | off | require the token for `/metrics` and `/version` (`/health` & `/ready` stay open) |
| `YARAD_URLHAUS_KEY[_FILE]` | — | abuse.ch Auth-Key; enables the URLhaus malware-URL lookup |
| `YARAD_URLHAUS_REFRESH` | `21600` (6 h) | URLhaus feed refresh (floor 5 min) |
| `YARAD_URLHAUS_MAX_URLS` | `64` | max URLs examined per message |
| `YARAD_MBAZAAR_KEY[_FILE]` | — | abuse.ch Auth-Key (same key); enables the MalwareBazaar hash lookup |
| `YARAD_MBAZAAR_REFRESH` | `86400` (24 h) | MalwareBazaar feed refresh (floor 5 min) |
| `YARAD_MBAZAAR_FEED` | full dump | override the feed URL (e.g. the lighter "recent" export) |
| `YARAD_RULE_DENYLIST` | `http` | comma-sep rule names to suppress (case-insensitive); set empty to disable |
| `YARAD_RULE_ALLOWLIST` | — | comma-sep rule names to force log-only (kept + tagged `yarad_allow`); deny wins if in both |
| `YARAD_VERBOSE` | off | log one line per request |
| `YARAD_LOG_STDOUT` | off | info/access logs to stdout (errors always stderr) |
| `YARAD_PPROF` | off | enable `/debug/pprof` profiling endpoints (off by default; auth-gated when `YARAD_METRICS_AUTH` is set) |

**Reload rules:** `docker kill -s HUP yarad` recompiles in place and flushes the
cache. A reload that fails to compile keeps the previous (working) rules — a bad
edit can't disarm a running scanner. On SIGTERM/SIGINT yarad drains (`/ready` →
`503`, in-flight scans finish) before exiting — safe for rolling updates.

## Sizing profiles

`YARAD_MAX_CONCURRENT` defaults to the CPU count (`auto`). On a many-core host
(32+ CPUs) that reserves significant memory: each concurrent scan can hold up to
`MAX_BODY` bytes in RAM, so peak resident is roughly `MAX_CONCURRENT × MAX_BODY +
64 MB` overhead. Size `mem_limit` accordingly and pin `MAX_CONCURRENT` explicitly
when the default is too aggressive.

`YARAD_MAX_INFLIGHT` (default `2×MAX_CONCURRENT`) is the admission gate — excess
requests receive a `503` immediately rather than queuing. Keep it above
`MAX_CONCURRENT` so a slow body read or Redis round-trip can't starve scan slots.

Redis/Valkey L2 (`YARAD_REDIS_URL`) dramatically improves throughput for repeated
attachments, which is common in mail (bulk campaigns, MTA retries, one body to N
recipients). Without it each scanner instance maintains its own in-process LRU
only.

| Profile | `YARAD_MAX_CONCURRENT` | `YARAD_MAX_BODY` | `mem_limit` | Redis | Expected p95 | RPS capacity |
|---------|------------------------|------------------|-------------|-------|-------------|-------------|
| **Small** — single mailhost, <100 msgs/min | `2` | `10485760` (10 MiB) | `128m` | optional (LRU only) | <500 ms | ~10 |
| **Medium** — mailhost, 100–1000 msgs/min | `auto` (CPU count) | `26214400` (25 MiB) | `256m` | recommended | <300 ms | ~50 |
| **Large** — cluster, >1000 msgs/min | `auto` | `26214400` (25 MiB) | `512m`+ | required | <200 ms | ~200+ |

Notes:
- MalwareBazaar full-dump mode (`YARAD_MBAZAAR_KEY` set) adds ~40 MiB resident
  plus a ~100–150 MiB transient spike on refresh — raise `mem_limit` to ~768m in
  that case.
- For the Large profile, run multiple replicas behind a load balancer rather than
  one container with a very high `MAX_CONCURRENT`: smaller per-container concurrency
  improves tail latency under burst load and avoids one libyara panic taking all
  capacity.
- `YARAD_BACKEND_TIMEOUT` (default `1s`) caps how long a request waits for an
  admission slot. Under sustained overload this is the 503 fuse — keep it short
  so callers (rspamd) fail fast rather than stacking connections.

## Rules

The image bakes six public rulesets at build time; a daily rebuild
(`--build-arg CACHEBUST=$(date +%s)`) re-pulls the latest. **Full credit to the
authors — yarad only packages their work.** Each set keeps its own license:

| Ruleset | Author / source | License | Notes |
|---------|-----------------|---------|-------|
| **YARA-Forge** | [YARAHQ/yara-forge](https://github.com/YARAHQ/yara-forge) | aggregator (each rule keeps its upstream license) | vetted, deduped multi-repo bundle; default tier `core` (`YARAFORGE_SET=extended`/`full`) |
| **signature-base** | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | [DRL 1.1](https://github.com/Neo23x0/signature-base/blob/master/LICENSE) | the broad community set behind THOR/Loki |
| **ANY.RUN** | [anyrun/YARA](https://github.com/anyrun/YARA) | public detection rules | malware-family + phishing (`ANYRUN=0` to skip) |
| **Didier Stevens Suite** | [DidierStevens/DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite) | public domain | OLE/RTF/maldoc + the `vba.yara` macro set (`DIDIER=0` to skip) |
| **bartblaze/Yara-rules** | [bartblaze/Yara-rules](https://github.com/bartblaze/Yara-rules) | MIT | maldoc/RTF + phishing-doc not in YARA-Forge (`BARTBLAZE=0`) |
| **InQuest yara-rules-vt** | [InQuest/yara-rules-vt](https://github.com/InQuest/yara-rules-vt) | MIT | curated mail subset: PDF/LNK/OneNote/`.msg`/RTF (`INQUEST=0`) |

Roughly 10,000+ rules total. Pin or toggle any source with a build arg
(`YARAFORGE_SET`, `*_REF`, `DIDIER=0`/`BARTBLAZE=0`/`ANYRUN=0`/`INQUEST=0`).

On top of the public sets, yarad bakes its own local heuristics from
`docker/local-rules/`:

- `Maldoc_AutoExec_Write_Execute` (`maldoc_autoexec.yara`) — an
  [mraptor](https://github.com/decalage2/oletools/wiki/mraptor)-equivalent rule:
  it fires when one buffer combines an **auto-execution** trigger, a
  **file-write/drop** primitive, and an **execute/launch** primitive. The
  three-category `AND` is what keeps it low-FP (a benign document rarely does all
  three at once), and unlike Didier's `vba.yara` it has no `VBA` gate, so it
  also catches non-Office droppers (HTA/WSF/JS, script carriers) in the raw body.
- `Maldoc_Suspicious_VBA_Keywords` + `Maldoc_VBA_Shellcode_API`
  (`maldoc_suspicious.yara`) — the olevba *suspicious-keyword* tier the strict
  rule misses. The first is a **count** heuristic (fires on ≥6 distinct
  exec/persist/network/evasion/obfuscation keywords in one buffer — one keyword
  is noise, six together is a macro doing real work; low score, low tier). The
  second is the specific **VBA shellcode** shape: a `Declare` of a Win32 API
  combined with a process-injection primitive (`VirtualAlloc`, `RtlMoveMemory`,
  `CreateThread`, a hook installer) — benign macros ~never allocate executable
  memory, so it scores higher.
- `OOXML_Remote_Template` (`ooxml_template_injection.yara`) — **remote-template
  injection** heuristic. The extractor reads every `*/_rels/*.rels` part inside
  the OOXML zip and emits a synthetic `OOXML-EXTERNAL-REL <type> <target>` stream
  for any relationship whose `TargetMode="External"` points to an `http://`,
  `https://`, `smb://`, or UNC target. This rule matches that stream, covering
  CVE-2017-0199-style attacks (Word fetches a remote `.dotm`/`.dotx` at open time
  and executes its macros — no embedded macro in the original document). Score 50,
  tagged `suspicious`, routes to `YARA_SUSPICIOUS`.
- `Maldoc_DDE_Field` (`ooxml_dde.yara`) — **DDE/DDEAUTO field injection**
  heuristic. The extractor reads `word/document.xml` (and header/footer parts),
  extracts field instructions from `w:fldSimple/@w:instr` attributes and from
  concatenated `w:instrText` runs (so obfuscated split-token instructions are
  caught), and emits a synthetic `OOXML-DDE-FIELD <instr>` stream for any
  instruction that begins with `DDE` or `DDEAUTO`. This rule matches that stream,
  covering macro-free command execution via DDE fields (T1559.002). Score 55,
  tagged `suspicious`, routes to `YARA_SUSPICIOUS`.
- `XLM_Hidden_Macrosheet` (`xlm_macrosheet.yara`) — **hidden Excel-4.0 macrosheet**
  detection. The extractor performs structural-only (zero execution) detection in
  two paths: for OOXML workbooks it checks `xl/workbook.xml` for sheets with
  `state="hidden"` or `state="veryHidden"` when an `xl/macrosheets/` part is
  present; for legacy `.xls` (BIFF8/OLE2) it scans `BOUNDSHEET8` records in the
  `Workbook` stream for sheets with `dt=0x01` (Excel-4.0 macro type) and hidden
  state bits set. Each hit emits a synthetic `XLM-HIDDEN-MACROSHEET <state> <name>`
  stream. This rule matches that stream. Score 60, tagged `suspicious`.
- `LOLBins_Invocation` / `WMI_Process_Spawn` / `PowerShell_Abuse_Flags` /
  `Maldoc_AntiAnalysis_Evasion` (`intent.yara`) — **behaviour/intent** heuristics.
  Each pairs a tool or keyword with a *specific* abusive form so a bare mention
  doesn't fire: a LOLBin with a download/execute arg (`regsvr32 /i:http…`,
  `certutil -decode`, `mshta http…`), `winmgmts:`+`Win32_Process`+`.Create`,
  `powershell` with an encoded/hidden/download flag, or two-or-more
  sandbox-evasion primitives together. Scores 30–55, `YARA_SUSPICIOUS`.

These are all tagged `suspicious`, so they score in the `YARA_SUSPICIOUS` tier
(tunable), run over the decompressed VBA cleartext (and body / decoded blobs),
and are keyword/behaviour heuristics — not emulation (Chr() chains / XLM
execution stay with `olevba`).

Public rulesets are messy, so two things keep them from breaking the build:
libyara is compiled **without** `magic`/`cuckoo` (unneeded for mail; rules
importing them are skipped), and each file is test-compiled alone first — one
unparseable file is logged and skipped, not fatal (error only if *nothing*
compiles).

## How it reads documents

Malware in mail mostly arrives as a document that hides its payload where a raw
byte-scan can't see it. yarad **pre-extracts** the hidden content, then scans
both the raw bytes (format/exploit rules) and each extracted blob (keyword
rules), merging and de-duplicating matches:

- **OLE2/OOXML macros** — magic-sniff `D0CF11E0` / `PK\x03\x04`, decompress the
  MS-OVBA VBA to cleartext (pure-Go [oleparse](https://github.com/Velocidex/oleparse),
  no extra C deps); the `VBA` rule var is set so macro-keyword rules fire.
- **RTF** — raw-byte exploit rules match directly (CVE-2017-11882 / -0199); plus
  every `{\*\objdata …}` group is hex-decoded and the embedded object re-run.
- **Other containers** — MSI streams, Outlook `.msg` attachments, OneNote
  embedded files, OLE Package (`Ole10Native`) EXEs, PDF FlateDecode streams,
  `.lnk` command lines, VBE/JSE decoded scripts, and nested archives.
- **Static decode pass** — over the raw body and every extracted stream, the
  long base64/hex runs are decoded and any whole-buffer reverse (VBA
  `StrReverse`) is undone, then the decoded blobs are re-scanned. This is
  **single-layer** only — a decoded blob is not decoded again (depth cap 1) and
  no VBA/XLM is *executed*; multi-stage unpacking stays with `olevba`.
- **VBA string folding** — the olevba constant-fold set is reassembled in
  cleartext so keyword/IOC rules see the payload: `Chr`/`ChrW` concat,
  `Replace("s","o","n")`, `Array(...) Xor k`, `StrReverse("literal")`,
  `Environ("NAME")` → a `VBA-ENVIRON %NAME%` marker, and the **Dridex** string
  obfuscation (`DridexUrlDecode`). Each fold's regex input is clamped (1 MiB) so
  a pathological body can't blow the scan budget.
- **oleid structural indicators** — an `ObjectPool` storage (embedded OLE
  objects) and embedded Flash/SWF objects are surfaced as `OLEID-OBJECTPOOL` /
  `OLEID-FLASH` markers and scored by `oleid_indicators.yara`.
- **Filename/extension externals** — name-keyed rules fire from the plugin's
  `X-YARAD-Filename`; the name is folded into the verdict cache key.
- **URL defanging** — `hxxp`→`http`, `[.]`/`(dot)`→`.` on every buffer before
  the URLhaus lookup; a hit found only after defanging is flagged `_DEOBF`.

Extraction is **best-effort and fail-open**: a non-document, a parse error, an
encrypted package, or a hostile/poison file (oleparse panics are recovered)
falls back to a raw-only scan. The whole request shares one `YARAD_SCAN_TIMEOUT`
across raw + every extracted stream, and zip-bomb/quine caps (per-item, total
bytes, member/depth counts) bound the work, so one document can't monopolize a
worker. Encrypted (ECMA-376) OOXML is counted but **not** decrypted.

This covers what Python [oletools](https://github.com/decalage2/oletools) does
for mail (VBA extraction+decompression, macro/autoexec keyword detection incl. an
mraptor-style autoexec+write+execute heuristic, OLE/encryption + ObjectPool/Flash
indicators, RTF exploit + embedded-object carve, the olevba string-fold set
— `Chr`/`Replace`/`Xor`/`StrReverse`/`Environ` and Dridex string decode —
single-layer base64/hex, IOC→reputation), in-process and with no Python, while
adding container formats oletools does not touch (MSI, `.msg`, OneNote, `.lnk`,
PDF, nested archives) and live URLhaus/MalwareBazaar reputation. The deep tail —
***multi-stage*** deobfuscation (a payload encoded two-plus layers deep) and
XLM/Excel-4.0 *emulation* — still belongs to `olevba`, which is why
[`rspamd-olefy`](https://github.com/eilandert/rspamd-olefy) stays as a parallel
deep-scan scorer.

### oletools parity matrix

Capability-by-capability against `oletools`. **lead** = yarad does more than the
oletools equivalent; **parity** = equivalent coverage; **SKIP (defensible)** =
intentionally not built, with the rationale recorded in
[`memory/.../history.md`](https://github.com/eilandert/rspamd-yarad) and covered
another way. Every emitted marker in this table is asserted to have a scoring
rule by `internal/extract/parity_doc_test.go` (CI fails if a carve goes unscored
or a new marker is added without classification).

| oletools capability | yarad status |
|---|---|
| `olevba` Chr/Replace/Array-Xor/StrReverse fold | lead |
| `olevba` Environ → marker | parity (`VBA-ENVIRON`) |
| `olevba` Dridex string decode | parity (`DridexUrlDecode`) |
| `olevba` keyword/IOC taxonomy (AutoExec/Suspicious/IOC/Hex/Base64) | parity (`intent.yara` + `maldoc_suspicious.yara`) |
| `olevba` multi-layer deobf (Dridex N-layer) | **lead** — depth-4 bounded (`MSD-DEEPDECODE`) |
| `olevba` defang-normalise before decode | parity (ingest-time) |
| `olevba` VBA-stomping detection | parity — **heuristic** (p-code ≥256 + src <32, `VBA-STOMPED`), *not* pcodedmp opcode decompilation |
| `olevba`/`pcodedmp` P-code disassembly | **SKIP (defensible)** — stomping heuristic instead of opcode decompile |
| XLM — OOXML macrosheet fold | lead |
| XLM — BIFF8 `.xls` / `.xlsb` (BIFF12) / SLK fold | parity (`XLM-DANGEROUS-FUNC`, `XLM-HIDDEN-MACROSHEET`) |
| XLM — cell-ref/SET.VALUE resolve | parity — bounded 1-level (not full interpreter) |
| `oleid` — ObjectPool + Flash indicators | parity+ (`OLEID-OBJECTPOOL`, `OLEID-FLASH` markers + rules) |
| `oleid` — encrypted / ext-rels / vba indicators | parity (`ENCRYPTION-AES`, `OOXML-EXTERNAL-REL`) |
| `oleid` — encryption TYPE (RC4/XOR/AES) | parity+ — typed (`ENCRYPTION-XOR`/`-RC4`/`-AES`) |
| `oleid` — DOC_SECURITY property flag | parity+ (`OLE-DOC-SECURITY-<n>` marker + rule) |
| `oletimes` — timestamp anomaly | **lead** — anomaly heuristic, not raw dump (`OLETIMES-FUTURE`/`-SYNTHETIC`) |
| `oledir` — orphaned/unreferenced streams | **lead** — carves+scans, not just lists |
| `olemap` — sector/FAT layout dump | **SKIP (defensible)** — covered by oledir carve + Failed/Panicked metrics |
| DDE / DDEAUTO (OOXML / RTF / SLK / CSV / Excel-2003-XML) | parity+ (`OOXML-DDE-FIELD`, `RTF-DDE-FIELD`, `SLK-DDE`, `CSV-DDE`) |
| OLE2Link URL moniker (CVE-2017-0199) | parity (`OLE2LINK-URL`) |
| digital-signature streams | **lead** — beyond oletools (`DIGITAL-SIGNATURE`) |
| PDF action/JS droppers | **lead** — oletools has no PDF triage (`PDF-*` family) |

## abuse.ch feeds (optional)

Set a free [abuse.ch Auth-Key](https://auth.abuse.ch/) to add live reputation,
on top of the YARA rules:

- **URLhaus** (`YARAD_URLHAUS_KEY`) — checks every message and extracted stream
  against the known malware-URL feed. Hits: `URLHAUS_MALWARE_URL` (exact),
  `URLHAUS_MALWARE_HOST`, `_DEOBF` variant; matched URL in `meta.url`.
- **MalwareBazaar** (`YARAD_MBAZAAR_KEY`, same key) — checks each attachment's
  SHA256 against the known-malware corpus. Hit: `MALWAREBAZAAR_MALWARE`, digest
  in `meta.sha256`.

Both use the same fail-open cached-feed design: the feed is downloaded once per
refresh interval into an in-memory set (lookups are local map hits, never a
per-message API call); a failed refresh keeps the previous set. MalwareBazaar's
full dump adds ~40 MiB resident + a ~100–150 MiB transient spike on refresh —
raise the container `mem_limit` (~768m) when enabling it.

## Wiring it into rspamd

The [`rspamd/`](rspamd/) directory has everything the rspamd side needs:

- [`plugins/yara.lua`](rspamd/plugins/yara.lua) — the async plugin that POSTs to
  yarad and classifies each matched rule into a scoring tier:

  | symbol | tier | default weight |
  |--------|------|----------------|
  | `YARA_MALWARE` | malware family / webshell / RAT / APT / ransomware | `8.0` |
  | `YARA_EXPLOIT` | exploit / CVE / maldoc exploit | `7.0` |
  | `YARA_PHISHING` | phishing kit / document | `5.0` |
  | `YARA` | uncategorized match (default) | `4.0` |
  | `YARA_SUSPICIOUS` | heuristic / anomaly (FP-prone) | `2.0` |
  | `URLHAUS_MALWARE_URL` | known malware URL (options = the URLs) | `8.0` |

  Tiers stack, capped by the group `max_score`. The classifier lives in the
  plugin, so retuning is just an rspamd reload (no yarad rebuild).
- [`rspamd.conf.local`](rspamd/rspamd.conf.local) — how to load a custom lua
  module (inline `yara { }` block + explicit `lua =` include).
- [`local.d/groups.conf`](rspamd/local.d/groups.conf) — the per-tier weights.
  Set any to `0.0` for a cautious log-only first run.

## Build & test

Tests need real libyara, so they run **inside the image build** (CGO, race
detector) — CI fails on a bad commit before any image is published:

```sh
# unit tests + go vet, against the same statically-linked libyara as production:
docker build --target test -f docker/Dockerfile -t yarad-test .

# the production image (distroless, nonroot, ~89 MB):
docker build --target final -f docker/Dockerfile -t eilandert/rspamd-yarad \
    --build-arg CACHEBUST=$(date +%s) .
```

## Status & roadmap

### Already in

- [x] Out-of-process Go scanner over HTTP (`/scan`); rspamd never blocks on libyara
- [x] ~10k+ public rules baked in (YARA-Forge, signature-base, ANY.RUN, Didier, bartblaze, InQuest), daily refresh, precompiled `.yac`
- [x] libyara modules `pe`/`elf`/`macho`/`dotnet`/`hash`/`math`/`dex` (no magic/cuckoo)
- [x] `/health`, `/ready`, `/version`, `/metrics` (Prometheus); graceful drain on SIGTERM
- [x] Verdict cache (LRU+TTL) + request coalescing; optional Redis/Valkey L2 with circuit breaker
- [x] Fail-open everywhere; concurrency gate, admission gate, per-request scan deadline, body cap
- [x] Hot-path hygiene: body hashed once per scan (cache key + dedup + reputation share it), pooled `yara.Scanner` reuse, per-fold/carve 1 MiB input clamps, panic-safe scan coalescing, clean feed-goroutine shutdown
- [x] `/debug/pprof` (token-gated) + `docker/pprof-capture.sh` baseline harness
- [x] OLE2/OOXML macro decompression (MS-OVBA) → scans raw **and** decompressed VBA, `VBA` external var
- [x] Container extraction: RTF `\objdata`, OLE Package, MSI, Outlook `.msg`, OneNote, PDF, `.lnk`, VBE/JSE, nested archives — **recursively**: a carrier carved out of another (a PDF inside a `.msg` attachment, an Office macro inside an archive member, a `.vbe` inside an OLE Package) is routed back through the matching extractor under one shared depth/byte budget, not scanned only as raw bytes
- [x] Local heuristic `Maldoc_AutoExec_Write_Execute` (mraptor-style autoexec∧write∧execute), baked from `docker/local-rules/`
- [x] Local heuristics `Maldoc_Suspicious_VBA_Keywords` (olevba count heuristic) + `Maldoc_VBA_Shellcode_API` (Declare+injection-API)
- [x] OOXML external-relationship scan (`*/_rels/*.rels`) → `OOXML_Remote_Template` rule (remote-template injection, T1221)
- [x] Static single-layer decode pass (base64/hex/`StrReverse`) over raw + extracted streams, re-scanned (depth cap 1)
- [x] VBA string folding: `Chr`/`Replace`/`Array Xor`/`StrReverse("lit")`/`Environ`→marker + **Dridex** (`DridexUrlDecode`); per-fold input clamp
- [x] oleid structural indicators: `OLEID-OBJECTPOOL` (embedded OLE objects) + `OLEID-FLASH` (SWF) markers → `oleid_indicators.yara`
- [x] oleid DOC_SECURITY: `SummaryInformation` PIDSI 0x13 bitfield → `OLE-DOC-SECURITY-<n>` marker + `OLE_Doc_Security` rule
- [x] Filename/extension externals (name-keyed rules) via `X-YARAD-Filename`
- [x] URL defang + URLhaus URL/host lookup; MalwareBazaar attachment-hash lookup (cached feeds, fail-open)
- [x] `YARAD_RULE_DENYLIST` (drop) + `YARAD_RULE_ALLOWLIST` (log-only)
- [x] Tiered scoring (`YARA_MALWARE`/`_EXPLOIT`/`_PHISHING`/`YARA`/`_SUSPICIOUS` + `URLHAUS_MALWARE_URL`)
- [x] SIGHUP rule reload (atomic swap, keeps old rules on a bad edit); `fetch-rules` out-of-image updates
- [x] `yarad-scan` lean CGO-free Sieve/LDA client ([`sieve/`](sieve/))
- [x] UserForm hidden-string extraction (carves payload strings from VBA UserForm `o`/`f`/`\x03VBFrame` OLE2 streams; `Maldoc_UserForm_Payload` rule)
- [x] Document-properties string extraction (OOXML `docProps/`, `customXml/`, `word/settings.xml` docVars; OLE2 `\x05SummaryInformation`; `Maldoc_DocProps_Payload` rule)
- [x] Distroless, non-root, read-only rootfs (~89 MB)

### Planned

- [x] OOXML remote-template injection (`*/_rels/*.rels` external-relationship scan + `OOXML_Remote_Template` rule)
- [x] OOXML DDE/DDEAUTO field detection (`word/document.xml` field-instruction scan + `Maldoc_DDE_Field` rule)
- [x] Intent rules (`intent.yara`): LOLBin invocation, WMI `Win32_Process.Create`, PowerShell abuse flags, anti-analysis/evasion
- [x] XLM hidden-macrosheet detection (OOXML veryHidden+macrosheets, legacy xls BIFF BOUNDSHEET)
- [x] VBA stomping detection (p-code vs. source heuristic; `VBA_Stomped` rule via `vba_stomping.yara`)
- [x] Equation Editor exploit detection (`equation_editor.yara`): OLE2 with Equation Native/CLSID + MTEF bytecode

- [x] VBA string folds at `olevba` parity: `Chr`/`Replace`/`Array Xor`/`StrReverse("lit")`/`Environ`→marker + **Dridex** `DridexUrlDecode`
- [x] `oleid` structural indicators: embedded-OLE `ObjectPool` + Flash/SWF markers
- [ ] **Multi-stage deobfuscation** — bounded recursive decode (depth ~4) so a 2+-layer payload (Dridex-style) is unwound, not just the first layer; the remaining `olevba` edge over yarad
- [ ] **BIFF8/`.xlsb`/SLK XLM folding** — static `ptg`-token string reassembly for legacy/binary/SLK macrosheets (OOXML `.xlsm` already folds), fuzz-gated
- [ ] **PDF action/JS triage** — `/OpenAction`+`/JS`, `/AA`, `/Launch`, `/EmbeddedFile`, `/JBIG2Decode`, hex-name de-obfuscation markers (oletools has no PDF triage; this leads it)
- [ ] CFB orphan/timestamp indicators (`oledir`/`oletimes`: unreferenced dir entries carved + scanned, FILETIME anomalies)
- [ ] Encryption-type + digital-signature markers (`ENCRYPTION-<RC4|XOR|AES>`, `DIGITAL-SIGNATURE`)
- [ ] Parse-robustness hardening (explicit CFB block-bounds / chain-loop / recursion / module-count guards; pathological-input fuzz)
- [x] `olevba`-parity matrix doc + CI check ([oletools parity matrix](#oletools-parity-matrix) above; `internal/extract/parity_doc_test.go` asserts every CONTRACT marker has a scoring rule and that the inventory is exhaustive)

**Performance / operations**

- [~] **Effort tiers** — config + resolution + cache key + profile struct (EFFORT-1), `YARAD_EFFORT=auto` from admission-gate pressure (EFFORT-2), and the rspamd plugin setting `X-YARAD-Effort` from the sender's prior score / auth-failure symbols (EFFORT-3, opt-in via `effort_enabled`) all landed; EFFORT-4 wires each extraction/scan cap (decode depth, XLM/PDF clamps, reputation feeds, scan timeout) to read the resolved profile so the dial actually scales work
- [ ] Batch `/scan` endpoint (collapse N part round-trips)

**Other planned**

- [ ] ThreatFox / Feodo Tracker IOC feeds (domains/IPs)
- [ ] File-level fuzzy hashing (TLSH/ssdeep)
- [ ] CHM / CAB / MSIX extraction
- [ ] Extractor sandbox hardening (seccomp/rlimits)
- [ ] PE-overlay bytes; `.url`/`.settingcontent-ms` launcher fields

> Disk-image (ISO/UDF/`.dmg`/`.pkg`) and Android `.apk` are intentionally out of
> scope — not a realistic executable mail vector, and high-attack-surface
> parsers for low return. iOS has no executable email vector either.

## See also

- **[gozer](https://github.com/eilandert/gozer)** — the DCC/Razor/Pyzor sibling backend this mirrors.
- **[rspamd-olefy](https://github.com/eilandert/rspamd-olefy)** — the parallel oletools deep-scan scorer.
- **[Dovecot/Sieve example](sieve/)** — quarantine a match with the `yarad-scan` client.
- **Article:** [YARA malware scanning in rspamd](https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/) — the why and how, on deb.myguard.nl.
- **Docker Hub:** [`eilandert/rspamd-yarad`](https://hub.docker.com/r/eilandert/rspamd-yarad).

## License

yarad itself is [MIT](LICENSE). The baked rule sets are **not** yarad's work and
keep their own licenses (see the [Rules](#rules) table): signature-base = DRL
1.1, bartblaze = MIT, InQuest = MIT, Didier Stevens = public domain, ANY.RUN =
public detection rules, YARA-Forge = aggregate (each rule keeps its upstream
license). Dependencies are permissive (`go-yara` BSD-2, `oleparse` MIT, redis
client BSD/Apache).
</content>
