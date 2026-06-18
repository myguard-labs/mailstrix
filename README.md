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
| `YARAD_TOKEN[_FILE]` | — | shared secret for `/scan` (optional); unset / `none` / `0` / `off` ⇒ auth disabled, `/scan` runs **open** (warned at startup) |
| `YARAD_RULES_DIR` | `/rules` | dir of `*.yar`/`*.yara` compiled at boot and on SIGHUP |
| `YARAD_RULES` | — | a precompiled `.yac` bundle; loaded instead of `RULES_DIR` (faster start) |
| `YARAD_RULES_MAX_AGE` | `0` (off) | seconds; flag rules `stale` (metric + `/ready` body) once older than this. Fail-open: never fails readiness |
| `YARAD_SCAN_TIMEOUT` | `8` (s) | per-request libyara budget (raw + all extracted streams share it) |
| `YARAD_BACKEND_TIMEOUT` | `1` (s) | how long to wait for an admission / scan slot |
| `YARAD_MAX_CONCURRENT` | `auto` (CPU count) | max concurrent libyara scans (CPU gate) |
| `YARAD_MAX_INFLIGHT` | `auto` (2× concurrent) | max in-flight requests (admission gate); kept above the scan gate so a slow body/Redis can't starve scans |
| `YARAD_MAX_BODY` | `8388608` (8 MiB) | max request body, in bytes (checked before reading) |
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

**Reload rules:** `docker kill -s HUP yarad` recompiles in place and flushes the
cache. A reload that fails to compile keeps the previous (working) rules — a bad
edit can't disarm a running scanner. On SIGTERM/SIGINT yarad drains (`/ready` →
`503`, in-flight scans finish) before exiting — safe for rolling updates.

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
`docker/local-rules/`. Currently that is `Maldoc_AutoExec_Write_Execute`, an
[mraptor](https://github.com/decalage2/oletools/wiki/mraptor)-equivalent rule:
it fires when one buffer combines an **auto-execution** trigger, a
**file-write/drop** primitive, and an **execute/launch** primitive. The
three-category `AND` is what keeps it low-FP (a benign document rarely does all
three at once), and unlike Didier's `vba.yara` it has no `VBA` gate, so it
also catches non-Office droppers (HTA/WSF/JS, script carriers) in the raw body.
Tagged `suspicious`, so it scores in the `YARA_SUSPICIOUS` tier (tunable).

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

This covers ~80% of what Python [oletools](https://github.com/decalage2/oletools)
does for mail (VBA extraction+decompression, macro/autoexec keyword detection
incl. an mraptor-style autoexec+write+execute heuristic, OLE/encryption
indicators, RTF exploit + embedded-object carve, IOC→reputation),
in-process and with no Python. The deep tail — full Base64/StrReverse/Dridex
*decode* and XLM/Excel-4.0 emulation — still belongs to `olevba`, which is why
[`rspamd-olefy`](https://github.com/eilandert/rspamd-olefy) stays as a parallel
deep-scan scorer.

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
- [x] OLE2/OOXML macro decompression (MS-OVBA) → scans raw **and** decompressed VBA, `VBA` external var
- [x] Container extraction: RTF `\objdata`, OLE Package, MSI, Outlook `.msg`, OneNote, PDF, `.lnk`, VBE/JSE, nested archives
- [x] Local heuristic `Maldoc_AutoExec_Write_Execute` (mraptor-style autoexec∧write∧execute), baked from `docker/local-rules/`
- [x] Filename/extension externals (name-keyed rules) via `X-YARAD-Filename`
- [x] URL defang + URLhaus URL/host lookup; MalwareBazaar attachment-hash lookup (cached feeds, fail-open)
- [x] `YARAD_RULE_DENYLIST` (drop) + `YARAD_RULE_ALLOWLIST` (log-only)
- [x] Tiered scoring (`YARA_MALWARE`/`_EXPLOIT`/`_PHISHING`/`YARA`/`_SUSPICIOUS` + `URLHAUS_MALWARE_URL`)
- [x] SIGHUP rule reload (atomic swap, keeps old rules on a bad edit); `fetch-rules` out-of-image updates
- [x] `yarad-scan` lean CGO-free Sieve/LDA client ([`sieve/`](sieve/))
- [x] Distroless, non-root, read-only rootfs (~89 MB)

### Planned

- [ ] ThreatFox / Feodo Tracker IOC feeds (domains/IPs)
- [ ] File-level fuzzy hashing (TLSH/ssdeep)
- [ ] CHM / CAB / MSIX extraction
- [ ] Extractor sandbox hardening (seccomp/rlimits)
- [ ] Batch `/scan` endpoint (collapse N part round-trips)
- [ ] PE-overlay bytes; `.url`/`.settingcontent-ms` launcher fields

> Disk-image (ISO/UDF/`.dmg`/`.pkg`) and Android `.apk` are intentionally out of
> scope — not a realistic executable mail vector, and high-attack-surface
> parsers for low return. iOS has no executable email vector either.

## See also

- **[gozer](https://github.com/eilandert/gozer)** — the DCC/Razor/Pyzor sibling backend this mirrors.
- **[rspamd-olefy](https://github.com/eilandert/rspamd-olefy)** — the parallel oletools deep-scan scorer.
- **[Dovecot/Sieve example](sieve/)** — quarantine a match with the `yarad-scan` client.
- **Article:** [YARA malware scanning in rspamd](https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/) — the why and how, on deb.myguard.nl.
- **Docker Hub:** `eilandert/rspamd-yarad` *(TODO: link once the repo page exists)*.

## License

yarad itself is [MIT](LICENSE). The baked rule sets are **not** yarad's work and
keep their own licenses (see the [Rules](#rules) table): signature-base = DRL
1.1, bartblaze = MIT, InQuest = MIT, Didier Stevens = public domain, ANY.RUN =
public detection rules, YARA-Forge = aggregate (each rule keeps its upstream
license). Dependencies are permissive (`go-yara` BSD-2, `oleparse` MIT, redis
client BSD/Apache).
</content>
