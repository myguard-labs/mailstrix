<p align="center">
  <a href="https://mailstrix.com"><img src=".github/mailstrix.webp" alt="Mailstrix — the owl that finds malware hiding in your mail" width="100%"></a>
</p>

# Mailstrix — YARA malware scanning for mail, ICAP and clamd

**Mailstrix is the owl that finds malware hiding in your mail.** It takes hostile
attachments apart — unwrapping OLE2/OOXML, VBA, RTF objects, PDFs, archives and
nested carriers — until YARA detection rules can finally see the dangerous bits.
It runs out-of-process behind Rspamd (async HTTP), SpamAssassin, an ICAP server,
Dovecot Sieve, or standalone.

[![CI](https://github.com/myguard-labs/mailstrix/actions/workflows/ci.yml/badge.svg)](https://github.com/myguard-labs/mailstrix/actions/workflows/ci.yml)
[![Release](https://github.com/myguard-labs/mailstrix/actions/workflows/release.yml/badge.svg)](https://github.com/myguard-labs/mailstrix/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/myguard-labs/mailstrix.svg)](https://pkg.go.dev/github.com/myguard-labs/mailstrix)

**strixd is a small HTTP service that scans email for malware with
[YARA](https://virustotal.github.io/yara/).** You hand it a message (or one
attachment) on `POST /scan`; it runs compiled YARA rules over it
and tells you which ones matched. It ships as a ready-to-run Docker image with
an initial rules bundle — see **[Quick start](#quick-start)** below or pull it
straight from **[Docker Hub](https://hub.docker.com/r/eilandert/mailstrix)**.

**Why YARA, in one paragraph.** YARA is the rule engine malware analysts use to
recognise *families* of malicious files — booby-trapped Office docs, packed
executables, phishing kits, script droppers. A plain string signature dies the
moment the author edits one byte; a YARA rule matches the *shape* of a file (PE
imports, section entropy, embedded magic) and survives the next variant. strixd
compiles those rules — libyara modules and all — and runs them over your mail.

**Six ways to plug it into a mail server, all shipped in this repo:**

- **rspamd** — an async `mailstrix.lua` plugin ([`contrib/rspamd/`](contrib/rspamd/)) POSTs each
  message/part to strixd at SMTP time and turns the hits into a spam-score symbol.
- **SpamAssassin** — the [`Mailstrix.pm`](contrib/spamassassin/) plugin scans each message
  through the same central service and turns a YARA match into a spam-score hit
  ([`contrib/spamassassin/`](contrib/spamassassin/)).
- **Dovecot / Sieve** — the lean [`strix-scan`](#thin-client-for-dovecot--sieve-strix-scan)
  client scans at *delivery* and a Sieve rule quarantines a match
  ([`contrib/sieve/`](contrib/sieve/)).
- **Postfix / Sendmail (milter)** — the lean
  [`strix-milter`](#milter-for-postfix--sendmail-strix-milter) runs on the MTA host,
  POSTs each message to strixd and stamps the verdict as a header. It **always
  accepts**; your `milter_header_checks` decides what to do about it
  ([`contrib/postfix/`](contrib/postfix/)).
- **ICAP** — set `MAILSTRIX_ICAP_ADDR` and strixd also speaks ICAP (RFC 3507) so an
  ICAP-aware proxy or content-filter (Squid, c-icap) scans REQMOD/RESPMOD bodies
  through the same engine ([ICAP mode](#icap-mode-optional)).
- **clamd streams** — opt-in Unix/TCP listeners in `strixd` accept `INSTREAM`
  from supported clamd clients ([subset, limits and examples](contrib/clamd/)).

These integrations use the same strixd scan engine and rules:

| Interface | Clients |
| --- | --- |
| HTTP `POST /scan` | Rspamd, SpamAssassin, Sieve, Postfix/Sendmail Milter |
| ICAP REQMOD/RESPMOD | ICAP-aware proxies |
| clamd `INSTREAM` | Supported stream clients |

> **Where should YARA scanning live — opinion.** YARA scanning is genuinely
> CPU-intensive, and the MTA hot path is the most latency-sensitive place to spend
> that CPU: every connection waits on it, and at SMTP time you scan a lot of mail
> you will reject anyway. A defensible view is that it doesn't belong in the MTA at
> all — scanning at **delivery** (Dovecot LDA / Sieve), *after* rspamd has already
> dropped the obvious spam, scans far less and off the connection's critical path.
> Which is right depends on your mailflow and goals: scan early at SMTP to *reject*
> with rspamd's score, or scan late at delivery to *quarantine* a smaller, cleaner
> stream. strixd supports both; see the [thin client](#thin-client-for-dovecot--sieve-strix-scan)
> and [`contrib/sieve/`](contrib/sieve/) for the delivery-time path.

It runs **out of process**, never inside the MTA worker, because libyara is a C
library (CGO): in an rspamd worker it would block the event loop and drag a heavy
C dependency into the mail image. Separate, the caller stays async and strixd can
be scaled, restarted, or reload its rules on its own. Same shape as the
[gozer](https://github.com/eilandert/gozer) DCC/Razor/Pyzor backend.

> 📋 Jump to **[Status & roadmap](#status--roadmap)** for what's done vs planned.

## Exactly what it does

- **Scans mail with YARA** — `POST /scan` raw message bytes (or one MIME part),
  get back the matched rules as JSON; the rspamd `mailstrix.lua` plugin
  ([`contrib/rspamd/`](contrib/rspamd/)) wires the hits into the spam score, or the `strix-scan`
  client scans at delivery from Dovecot/Sieve ([`contrib/sieve/`](contrib/sieve/)).
- **Loads a compiled rules bundle** — the image includes a seed; the rolling
  `rules-current` publication can refresh the active bundle without changing
  the binary. The source set includes YARA-Forge, signature-base, ANY.RUN,
  Didier Stevens, bartblaze, InQuest, CAPEv2 and YARAify.
- **Decompresses Office macros before matching** — MS-OVBA VBA out of
  `.docm`/`.xlsm`/`.doc`/`.xls`, scans the cleartext (sets the `VBA` rule var).
- **Cracks open containers** — pulls the hidden payload out of: OLE2/OOXML,
  RTF `\objdata`, OLE Package (`Ole10Native`), MSI, Outlook `.msg`, TNEF
  (`winmail.dat`), OneNote `.one`, PDF (FlateDecode streams), `.lnk` shortcuts,
  VBE/JSE encoded scripts, and nested archives (zip/7z/rar/gz/tar.gz/cab, recursive)
  — then scans each. A part that is itself a message is **walked as MIME**, so
  attachments inside a forwarded or `message/rfc822` carrier are unpacked too.
- **Deobfuscates before matching** — decodes long base64/hex runs, undoes
  `StrReverse`, and folds the olevba string set (`Chr`/`ChrW` concat,
  `Replace()`, `Array() Xor k`, `Environ`, Dridex `DridexUrlDecode`) to
  cleartext; a bounded recursive pass unwinds **multi-stage** (2+-layer)
  payloads, not just the first layer.
- **Resolves Excel 4.0 (XLM) macros** — detects hidden/very-hidden macrosheets
  (OOXML + legacy `.xls` BIFF), reassembles `ptg`-token formula strings
  (BIFF8/`.xlsb`/SLK), and runs a **bounded XLM emulator** (cell eval, `GOTO`,
  `SET.VALUE`) to resolve obfuscated cell references. BIFF8 macrosheets also
  resolve `SHRFMLA` shared formulas referenced by `ptgExp`, within parser limits.
- **Triages PDFs** — surfaces `/OpenAction`, `/JS`, `/Launch`, `/EmbeddedFile`,
  `/JBIG2Decode` and hex-name obfuscation as scoreable markers.
- **Catches macro-less & exploit attacks** — Equation Editor (CVE-2017-11882),
  remote-template injection (CVE-2017-0199 / T1221), DDE/DDEAUTO fields,
  MHTML/`x-usc` (CVE-2021-40444), Shell.Explorer CLSID, and OLE structural
  indicators (`ObjectPool`, embedded Flash, digital-signature, doc-security).
- **Decrypts default-password documents** — VelvetSweatshop XOR, BIFF8 RC4, and
  OOXML agile/standard AES, so an "encrypted" but default-keyed payload is
  unlocked and re-scanned (other encryption is flagged, not cracked).
- **Analyses carved executables** — PE/ELF structural checks on embedded/decoded
  binaries (section entropy / packing, overlay, .NET, anomalies), plus base64-PE
  carving that re-aligns a padded `MZ` header so the `pe` rules fire.
- **Ships 100+ of its own rules** — [`docker/local-rules/`](docker/local-rules/)
  scores the structural evidence extraction surfaces, so a sample with no public
  signature still has something to hit: weight-of-evidence maldoc scoring,
  `oleid`/`oletimes`/`pdfid` parity indicators, XLM dropper shapes,
  macro-less execution carriers, HTML/SVG smuggling, PowerShell/VBS/JScript
  dropper families, polyglot and renamed-container evasion, and carved-PE
  structure — full inventory under
  [What Mailstrix detects on its own](#what-mailstrix-detects-on-its-own).
  Among them: an mraptor-style autoexec∧write∧execute rule, olevba suspicious-keyword / VBA-shellcode-API heuristics, LOLBin / WMI /
  PowerShell / anti-analysis intent rules, HTML-smuggling (`data:` URI, embedded
  SVG, `javascript:`/`vbscript:` and entity-hidden script URIs) detection, and a
  position-independent-shellcode `GetEIP` prologue rule.
- **Scales effort under load** — a single 1–10 effort dial (`MAILSTRIX_EFFORT`)
  scales decode depth, XLM/PDF clamps, feeds and scan timeout; `auto` sheds a
  level at a time as the admission gate fills and climbs back as it drains.
- **Speaks ICAP too (optional)** — `MAILSTRIX_ICAP_ADDR` adds an RFC 3507
  REQMOD/RESPMOD listener for ICAP-aware proxies, sharing the same scan engine,
  cache and concurrency gate as `/scan`.
- **Uses the attachment name** — `filename`/`extension` YARA vars from the
  plugin's `X-MAILSTRIX-Filename`, so name-keyed (THOR/Loki) rules fire.
- **Checks abuse.ch feeds (optional)** — URLhaus malware-URL/host lookup (with
  URL defanging), MalwareBazaar attachment-SHA256 lookup, and ThreatFox
  URL/domain IOCs; all cached, fail-open.
- **Drops/demotes noisy rules** — `MAILSTRIX_RULE_DENYLIST` (suppress) and
  `MAILSTRIX_RULE_ALLOWLIST` (keep but score log-only) without patching upstream.
- **Canary mode** — `MAILSTRIX_CANARY=1` returns hits as log-only metadata so
  integrations can observe rule/feed behaviour without scoring or blocking mail.
- **Caches verdicts** — `SHA256(body)` → matches (LRU+TTL), plus request
  coalescing and an optional shared Redis/Valkey L2 for a high-volume firehose.
  The L2 can be integrity-protected with `MAILSTRIX_REDIS_MAC_KEY`: an
  HMAC-SHA256 bound to the Redis key, so a tampered or un-MACed value, or a valid
  value lifted to a different key, is treated as a cache miss instead of a trusted
  verdict. The MAC carries no nonce or counter, so it does not make an entry fresh
  — a stale value restored under its own key still verifies.
- **Fails open, always** — a scan error, timeout, or libyara panic is reported
  as "no match"; a broken scanner never blocks mail. Bounded concurrency,
  per-scan timeout, body cap, graceful drain on SIGTERM.
- **Updatable rules without a rebuild, origin-checked** — `strixd fetch-rules`
  pulls a version-matched compiled bundle into a cache; SIGHUP reloads it. The
  remote manifest must carry a valid **ed25519 signature** from a trusted public
  key — one **pinned into the binary** (`internal/rulespin`), plus any the operator
  adds through `MAILSTRIX_RULES_EXTRA_SIGNING_KEYS`, which is additive and cannot
  remove a pinned key. Otherwise the update is refused, so a tampered, truncated or
  untrusted-key manifest never reaches the compiler. There is no switch to turn
  verification off ([details](#rules-manifest-signature)).
- **CLI tools** — `strixd scan` (local triage), `strixd extract` (dump what a
  container carves), `strixd check-rules`, `strixd info`; and `strix-scan`, a tiny
  CGO-free client for a Dovecot/Sieve box ([`contrib/sieve/`](contrib/sieve/)).
- **Optional CAPE detonation adapter (report-only)** — a separate, disabled-by-default
  HTTPS listener (`MAILSTRIX_CAPE_CONFIG_FILE`) can submit an attachment to a
  [CAPEv2](https://github.com/kevoreilly/CAPEv2) sandbox and poll its report. It
  is deliberately **not** in the delivery path: `MAILSTRIX_CAPE_POLICY` accepts
  only `static-only`, so mail always follows the static verdict and a pending
  detonation never holds, quarantines or tempfails a message. No automatic
  submission, no enforcement, no callback bridge
  ([configuration](internal/mailstrix/CAPE.md),
  [operator guide](internal/mailstrix/CAPE-OPERATIONS.md)).
- **Observable** — `/health`, `/ready`, `/version`, Prometheus `/metrics`
  (scans, matches, cache, per-extractor counters, rule staleness).

## Install

Three ways, pick one:

**Debian/Ubuntu package** (`.deb`, amd64 + arm64) — attached to every
[release](https://github.com/myguard-labs/mailstrix/releases/latest):

```sh
# Resolve the latest version + your arch (release assets are version-pinned,
# e.g. strixd_1.1.0_amd64.deb — the bare latest/download/ path is not).
VER=$(curl -fsSL https://api.github.com/repos/myguard-labs/mailstrix/releases/latest \
        | grep -oP '"tag_name":\s*"v\K[^"]+')
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
BASE=https://github.com/myguard-labs/mailstrix/releases/download/v${VER}

# strixd — the daemon (systemd unit + /etc/mailstrix/strixd.env config)
curl -fsSLO "${BASE}/strixd_${VER}_${ARCH}.deb"
sudo apt install "./strixd_${VER}_${ARCH}.deb"

# fetch the rolling compiled rule bundle into the cache dir, then start it
sudo -u strixd strixd fetch-rules -cache-dir /var/cache/mailstrix   # or drop your own .yar in /var/lib/mailstrix/rules
sudoedit /etc/mailstrix/strixd.env                                 # set MAILSTRIX_TOKEN, feeds, …
sudo systemctl enable --now strixd

# strix-scan — the lean CGO-free Sieve/LDA client (no daemon)
curl -fsSLO "${BASE}/strix-scan_${VER}_${ARCH}.deb"
sudo apt install "./strix-scan_${VER}_${ARCH}.deb"

# strix-milter — the lean CGO-free Postfix/Sendmail milter (systemd unit)
curl -fsSLO "${BASE}/strix-milter_${VER}_${ARCH}.deb"
sudo apt install "./strix-milter_${VER}_${ARCH}.deb"
```

The daemon package installs a hardened systemd unit (unprivileged `strixd` user,
`ProtectSystem=strict`, `NoNewPrivileges`) and a documented
`/etc/mailstrix/strixd.env`. State (rules) lives in `/var/lib/mailstrix`.

**Static binaries** — `strixd-linux-{amd64,arm64}`,
`strix-scan-linux-{amd64,arm64}` and `strix-milter-linux-{amd64,arm64}` plus
`SHA256SUMS` are on the same release page.

**Docker** — see [Quick start](#quick-start) below (rules baked in).

## Quick start

The image includes a compiled seed bundle, so a token is all you need:

```sh
docker run -d --name strixd \
    -e MAILSTRIX_TOKEN=changeme \
    -p 8079:8079 \
    eilandert/mailstrix

# ask it something:
printf 'hello' | curl -s -H 'X-MAILSTRIX-Token: changeme' \
    --data-binary @- http://127.0.0.1:8079/scan
# -> {"matches":[]}
```

To use your own rules instead of the baked bundle:

```sh
docker run -d --name strixd \
    -e MAILSTRIX_TOKEN=changeme \
    -e MAILSTRIX_RULES= \
    -e MAILSTRIX_RULES_DIR=/rules \
    -v "$PWD/myrules:/rules:ro" \
    -p 8079:8079 \
    eilandert/mailstrix
```

Send an attachment name so name-keyed rules fire (base64 — the name is
attacker-controlled, encoding it stops header injection). To check that
detection works end to end, send the harmless
[EICAR test string](https://www.eicar.org/download-anti-malware-testfile/):

```sh
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' |
    curl -s -H 'X-MAILSTRIX-Token: changeme' \
    -H "X-MAILSTRIX-Filename: $(printf 'eicar.com' | base64)" \
    --data-binary @- http://127.0.0.1:8079/scan
# -> {"matches":[{"rule":"SUSP_Just_EICAR",…},{"rule":"TRELLIX_ARC_Malw_Eicar",…}]}
```

A few placeholder bytes such as `MZ...` are not malware and correctly return
`{"matches":[]}`; test with a real sample. Set `MAILSTRIX_VERBOSE=1` to log one
line per request.

> **Token is optional but recommended.** Set `MAILSTRIX_TOKEN` (or
> `MAILSTRIX_TOKEN_FILE`) and the caller must present the same secret as a `Bearer`
> header or `X-MAILSTRIX-Token`. A `*_FILE` secret that is set but cannot be read
> stops `strixd serve` with exit code 2 instead of falling back to the plain variable.
> Leave it unset (or `none`/`0`/`off`) to run an
> **open** scanner for a trusted private network — strixd logs a loud warning,
> since anyone who can reach the port can submit CPU-costly scans.

The `/scan` reply names the rule **and** its source ruleset file:

```json
{"matches":[{"rule":"Suspicious_Macro","namespace":"sigbase-gen_maldoc.yar","tags":["office"],"meta":{"author":"…"}}]}
```

The list is `[]` (never `null`) when nothing matched. `namespace` is the file the
rule was compiled from, so a generic rule like `http` is traceable to the set
that shipped it.

When strixd could not compute a complete verdict, the reply still answers 200
(fail-open) but adds `"degraded"` and an `X-MAILSTRIX-Degraded` header with the
reason: `incomplete` (scan budget ran out, an extraction cap such as the
stream or archive-member limit stopped the walk, an extracted stream failed to scan,
or an extractor crashed), `error` (the scan failed) or `busy` (no scan slot
freed up in time). A log-only `MAILSTRIX_SCAN_INCOMPLETE` or
`MAILSTRIX_SCAN_DEGRADED` match names it too. Treat a degraded reply with no
actionable match as **unknown, not clean**; any actionable match in it is still
a real detection. Degraded results are never cached. ICAP answers `500` instead
of `204` for them. For the hardened container setup (read-only rootfs, dropped
caps, Docker secret, static IPv4) see
[`docker/docker-compose.yml`](docker/docker-compose.yml).

## Scanning without a server

The same binary scans locally — no HTTP, no token — by compiling the rules
in-process. For one-off triage and pipelines:

```sh
strixd scan suspicious.doc            # one file
strixd scan /var/mail/cur             # a maildir, recursed
cat msg.eml | strixd scan             # stdin
strixd scan -json /tmp/quarantine     # machine-readable
```

Exit codes: **0** clean, **1** ≥1 match, **2** usage/load/read error. Other
helpers share the binary (`strixd help`):

```sh
strixd check-rules            # compile rules, print the count, non-zero on failure (CI gate)
strixd extract suspicious.doc # show what the extractor carves (no scan)
strixd fetch-rules            # update the cached rule bundle from the release
strixd info                   # build / libyara / loaded-bundle identity
```

### Updating rules without rebuilding (`fetch-rules`)

Rules move faster than image rebuilds — and outside Docker you'd otherwise need
`yarac` + a matching libyara to compile them. `strixd fetch-rules` downloads a
prebuilt, version-matched bundle into the cache instead:

```sh
strixd fetch-rules -cache-dir /var/cache/mailstrix
```

The tagged binary release and the rolling `rules-current` bundle have separate
dates. The local nightly publisher replaces the rolling bundle's assets; it
does not rebuild a tagged binary. A binary's release date therefore cannot tell
you when its loaded rules were generated. Check the `/version` fields
`rules_manifest.generated` and `rules_update.loaded_version` for the active
bundle when present. The published and cached versions may differ from the
successfully loaded one.

It reads a small manifest first and updates only when the published **version**
is newer; it **refuses** a bundle built against a different **libyara**,
**verifies the sha256**, and swaps atomically (keeping one `.bak`). On any error
the current bundle is retained; rollback errors explicitly require cache recovery.
Then SIGHUP (or restart) strixd to load it, or enable daemon polling below. The
bundle is published by `docker/generate-rules.sh` (run from cron).
Point `-url` /
`MAILSTRIX_RULES_URL` at a mirror if not fetching from GitHub. The URL must be
`https`; a plain-`http` mirror needs an explicit opt-in (`-allow-http`,
`serve -rules-allow-http`, or `MAILSTRIX_RULES_ALLOW_HTTP=1`). Other schemes and
URLs without a host are always refused, and a redirect from `https` to `http` is
refused even with the opt-in. The base URL must not contain userinfo
(credentials), query parameters, or fragments; these are refused to prevent
credential leaks and broken asset URL construction.

#### Rules-manifest signature

A remote manifest must carry a valid `ed25519` signature or the update is
refused and the running rules stay loaded. The publisher writes a detached
`compiled.yac.manifest.json.sig` beside the manifest: base64 of the raw 64-byte
signature over the **exact** manifest bytes. strixd verifies it against the
public key(s) compiled into the binary before reading a single manifest field,
so an unsigned, truncated, tampered or untrusted-key manifest never reaches the
update logic. Verification uses the Go standard library only.

Two embedded key slots (current, then a pre-published successor) allow rotation
without an unsigned window: ship the build that trusts the successor first, then
switch publication to it. `-require-trusted` only proves the key matches the pin
in the *publisher's* checkout; it cannot speak for binaries already deployed, so
the trusting build must reach clients before publication switches keys. `MAILSTRIX_RULES_EXTRA_SIGNING_KEYS` can add further
trust anchors for an operator who signs their own mirror; it can never remove an
embedded key, and there is deliberately no switch to skip verification.

A manifest **already installed in the cache** is not signature-checked — it is
trusted on its recorded checksum against the cached bytes, as before. An
existing deployment that was seeded before signing existed therefore keeps
serving its bundle; it simply cannot be updated until the publisher signs.

Publishing requires `MAILSTRIX_RULES_SIGNING_KEY` (an `ed25519` PKCS#8 PEM key)
in the environment of `docker/generate-rules.sh`, which signs through
`cmd/rulessign`. The key is never passed on a command line, and it must never be
exposed to a `pull_request`-triggered CI job. The nightly cron run has no such
environment, so when `MAILSTRIX_RULES_SIGNING_KEY` is unset the publisher falls
back to `/etc/myguard-build-env`, where the operator installs the same key as a
single base64 line `MAILSTRIX_RULES_SIGNING_KEY_B64=$(base64 -w0 key.pem)` in
that root-owned mode-600 file (the PEM is multi-line; the build-env reader is
not). An exported `MAILSTRIX_RULES_SIGNING_KEY` always wins. The publisher
resolves and validates the key before building, so a missing or malformed one
fails in seconds instead of after the rules build. The publisher signs with
`-require-trusted`, so a key whose public half is not pinned in the binary
aborts the run before any asset is uploaded rather than publishing a bundle
every client would refuse. `rulessign -print-public` prints the base64 public
key to compare against the pin, which lives in `internal/rulespin` — a
stdlib-only package, so the signer builds on a host without libyara.

A bundle is refused when the rules actually loaded from the verified download
number zero, or fall below 50% of the installed bundle's rule count (exactly 50%
is accepted; a first install is refused only at zero). The manifest `rules`
field is never trusted for this. On a refusal, a daemon poll keeps the current
rules, logs the error and counts it in `count_drop_refusals` of the rules-update
state, while `strixd fetch-rules` keeps the current rules, prints the error and
exits 2. To deliberately ship a much smaller ruleset, set
`MAILSTRIX_RULES_ALLOW_COUNT_DROP=1` (default off) or
pass `strixd fetch-rules -allow-count-drop`.

Docker images, the reference Compose service, and Debian packages enable daemon
polling daily (`MAILSTRIX_RULES_POLL_INTERVAL=86400` seconds). Set it explicitly
to `0` to disable polling for offline installations or custom local `.yar`
directories. Bare binaries and library configuration keep the code default `0`;
opt in with `MAILSTRIX_RULES_POLL_INTERVAL=900` or
`serve -rules-poll-interval=15m`. Polling requires the compiled cache actually
loaded by the scanner; a cache fallback cannot silently change to remote rules.
If writable cache setup fails, strixd serves the baked/local
fallback and logs that automatic polling was disabled. Network and cache-lock
waits share a configurable five-minute default deadline. Native libyara
validation and reload finish synchronously once entered. There is one check at
startup, then one per interval plus 0–20% jitter,
including after failure (no retry burst).
Concurrent polls coalesce and shutdown cancels and joins the worker.

The manifest checksum detects corruption but is not an origin signature because
the manifest and bundle share one channel. Use an HTTPS URL whose publisher you
trust; reserve plaintext HTTP overrides for loopback or an equivalently trusted
private transport. Detached manifest signing remains tracked separately.

The lifecycle is `check manifest -> validate/download -> install -> reload`.
Version, libyara, positive bounded size, generation timestamp and SHA-256 must
validate; the native library must load the staged bytes before publication.
Cache readers/writers and SIGHUP share a process-independent cache lock, acquired
after downloading, with the version rechecked under that lock. The daemon uses
the existing atomic rules swap and flushes verdicts only after successful reload.
Standalone `fetch-rules` installs are picked up on the next successful poll.
The cache directory is a writable runtime directory, not a read-only rules mount;
the daemon and any cron updater must both be able to create `.rules.lock` and
replace its files. Size `MAILSTRIX_RULES_FETCH_TIMEOUT` for the complete download,
native validation, and subsequent lock acquisition on the slowest expected link.

| Outcome | Cache and active rules |
| --- | --- |
| Current release, valid cache | No download; reconcile cached rules |
| Invalid metadata, bytes or interrupted download | Preserve both |
| Install or reload fails | Restore both cache files; retain active rules |
| Rollback itself fails | Keep active rules and remaining recovery files |
| Successful update | Record version; new scans use new rules |

Each file replacement is atomic and participating readers see coherent pairs.
The two files are **not crash/power-loss atomic**. Startup still load-validates
and reseeds the cache; a version record whose checksum does not describe the
cache cannot suppress a repair download. Do not modify the cache concurrently
with tools that ignore its `.rules.lock` advisory lock. An update can briefly
use roughly four bundle sizes of disk for the live file, `.bak`, staged download,
and rollback copy. Startup removes interrupted `.rules-rollback-*` directories
only after proving the public cache pair coherent or installing the baked seed;
otherwise they remain as operator recovery data.

Age checking now defaults to **48 hours**, using a verified manifest's generated
time or the local rules' modification time. Remote manifests with future
timestamps are rejected without clock-skew tolerance; a cached future timestamp
falls back to filesystem mtime. Keep publisher and scanner clocks synchronized.
Set `MAILSTRIX_RULES_MAX_AGE=0`
(or `-rules-max-age=0`) explicitly for static/offline rules. `/health` and scans
remain available; `/ready` stays HTTP 200 for stale rules and reports the stale
state in its body. A strict deployment must explicitly have its readiness probe
reject that state; it trades outage availability for freshness. Unknown age is
reported separately through a zero `rules_mtime_unix`/mtime metric. These legacy
field names report the age origin (publication time or filesystem fallback),
not necessarily filesystem mtime. `/version`
and metrics expose whether age checking is enabled, so disabled does not mean
fresh.

`/version.rules_update` and corresponding `mailstrix_rules_*` metrics distinguish
the last observed published version, the cached publication record, and the
successfully loaded version, plus last check/success/failure times and failure
counters. Zero version means unknown and zero timestamp means never. Cached
telemetry reads the record; byte integrity is checked during fetch/reload, not
on every scrape. While a cache transaction is busy, telemetry keeps its last
observed identity pair without delaying HTTP probes. Custom local rules do not
inherit an unrelated release manifest from a feed cache directory.
The bundled Prometheus alerts allow 30 hours after an earlier successful check,
covering the daily polling default plus up to 20% jitter (28.8 hours). Adjust the
`108000`-second threshold when selecting a longer polling interval. The initial
check and published-but-not-loaded deadlines remain 30 minutes.
These are monitoring thresholds, not a guarantee that new rule updates will be
available or loaded within a fixed time. A failed publisher, network check or
reload keeps the last good rules and must be investigated through the receipt,
`/version` identity and alert metrics.

The publisher uploads the bundle first and manifest last, then runs an isolated
native verifier against the released URLs. During replacement, a mismatched
manifest/asset pair is rejected and retried at the next poll. Verification uses
a fresh temporary cache and alerts on failure; it never mounts a production
cache. Reproduce the verification with:

```sh
strixd fetch-rules -verify-only -expected-version 42
```

The receipt includes version, libyara, size, checksum and native load success.
Each nightly whose serializer can write emits exactly one JSON receipt line with
schema `mailstrix-rules-nightly-v1`. A successful receipt reports stage
`verify` and records that same fresh verifier evidence; a failed receipt contains only
`schema: "mailstrix-rules-nightly-v1"`, `stage` (`build`, `publish`, `verify`,
or `receipt`), and `status: "failed"`. A broken
serializer fails closed and may leave no JSON line; cron monitoring must treat a
missing or failed receipt as a failure. For the publish/native-verification
outcome, a completed success receipt takes precedence over the process exit
code: a later signal can still produce a nonzero exit (for example, 143 during
success notification). Monitor that exit as a subsequent process interruption,
not as a reversal of the recorded publish/verification success.
Failure notifications carry the same stage in
their title. Discord delivery is the sole best-effort publisher exception: its
failure does not change an otherwise successful publish or receipt.

## Thin client for Dovecot / Sieve (`strix-scan`)

`strixd scan` (above) compiles the rules **in-process**, so it needs libyara and
the rule set on the host that runs it — fine on the scanner box, too heavy for a
mail-delivery box that should stay thin. **`strix-scan`** is the answer: a
separate, tiny client that links **no CGO / libyara and embeds no rules** — pure
Go, a ~6 MB static binary you can drop on any mail host. It just reads the
message (stdin or a file), POSTs it to a central `strixd serve`, and exits on the
verdict — so all the CPU-heavy scanning stays on the central service.

```sh
# stdin or a file; exit code carries the verdict:
strix-scan -url http://strixd.internal:8079 -token-file /etc/strixd.token - < message
cat message | strix-scan -url http://strixd.internal:8079
```

| | |
|--|--|
| **Exit 0** | clean — no actionable rule matched (**also** for canary/allowlisted log-only hits and on a fail-open scanner outage) |
| **Exit 1** | at least one actionable rule matched |
| **Exit 2** | usage / read / (fail-closed) transport error |

- **Fails open by default** — any transport error, timeout, or non-200 is treated
  as *clean* (exit 0), so a scanner outage never blocks or bounces delivery. Pass
  `-fail-open=false` for interactive triage where a silent miss is worse.
- **Token** via `-token-file` or `MAILSTRIX_TOKEN` — never `-token` on a shared host
  (it shows in `ps`). Redirects are never followed, so the token can't leak to a
  3xx target.
- **Same wire format** as the rspamd plugin: `X-MAILSTRIX-Token` for auth, base64
  `X-MAILSTRIX-Filename` for the attachment name.
- **Structured verdict** — `-json` prints
  `{"malicious":bool,"family":"<name|>","confidence":"family|rule|","rules":[...]}`
  and `-label` prints a single `LABEL <family>` line (nothing when no family is
  known). The family comes from the matched rules' metadata
  (`family` / `malware_family` / `actor`, in that order); generic/technique rules
  that carry no family meta still count as malicious but contribute no family. One
  family per file = the highest-confidence family-bearing hit. Useful for labelling
  a malware-store sample's family without burning external lookup quota.
  `-json` and `-label` are mutually exclusive (passing both is a usage error).

This is the **delivery-time** path from the opinion in the intro: let rspamd drop
the obvious spam at SMTP, then scan the smaller, cleaner stream with YARA at
delivery and quarantine a hit — off the connection's critical path.

A ready-to-use Dovecot Sieve example (the `execute` rule, an install wrapper, the
dovecot config, and a setup/test walkthrough) lives in **[`contrib/sieve/`](contrib/sieve/)**.
Because the client fails open, a delivery is never lost if the backend is down.

## Milter for Postfix / Sendmail (`strix-milter`)

`strix-milter` is a milter (mail filter) front-end for strixd. It runs on the
**MTA host**, buffers each message, POSTs it to strixd's `/scan`, and stamps the
verdict into the message as `X-Mailstrix-*` headers.

It **always accepts the message.** It never rejects, defers, discards or
quarantines — it only reports. Turning a verdict into policy is the MTA's job.
That is deliberate:

- **Fail-open is trivial.** A scanner outage, timeout or oversized message is
  just an `unknown` stamp, not a bounce. A bug here can never eat mail.
- **Mail policy stays in the MTA**, where you already express it, version it, and
  can change it without restarting the filter.
- **The heavy lifting stays out of the delivery path.** Like `strix-scan`, this
  binary links no CGO / libyara and holds no rules — it is a small pure-Go static
  binary. The extractors and the YARA engine stay behind strixd's admission cap.

```sh
# on the MTA host
sudoedit /etc/mailstrix/strix-milter.env     # set MAILSTRIX_URL (+ MAILSTRIX_TOKEN)
sudo systemctl enable --now strix-milter
```

Ready-to-copy MTA config (Postfix `main.cf` + `milter_header_checks`, the Sendmail
`INPUT_MAIL_FILTER`, and a setup/test walkthrough) lives in
**[`contrib/postfix/`](contrib/postfix/)**.

### Headers it stamps

| Header | Value |
| --- | --- |
| `X-Mailstrix-Status` | `clean`, `infected`, or `unknown` |
| `X-Mailstrix-Rules` | comma-separated actionable rule names (on `infected`) |
| `X-Mailstrix-Family` | the malware family, when a rule carried one |
| `X-Mailstrix-Info` | why the verdict is `unknown` (outage, no complete verdict, oversized, empty) |
| `X-Mailstrix-Version` | the `strix-milter` version |

`unknown` means *not scanned* — it is **not** a clean bill of health. Decide
explicitly what you want to do with it (most people accept and let the rest of the
stack judge; a high-security site may prefer to hold it).

Canary and allowlisted rules (`mailstrix_canary=1` / `mailstrix_allow=1`) are
log-only and never make a message `infected` — the same rule the other clients
apply, from the same code.

**Forged headers are deleted, not just logged.** A sender who ships their own
`X-Mailstrix-Status: clean` would otherwise be read by any downstream consumer
doing a *first-match* header lookup (`net/mail`, `textproto.Get`, most MUA and
Sieve implementations) — so the milter negotiates `SMFIF_CHGHDRS` and removes
every inbound `X-Mailstrix-*` header before stamping its own. The forged header is
not fed to the scanner either.

**What gets scanned:** the milter protocol delivers the header block and the body
separately; `strix-milter` reassembles them into the complete RFC 5322 message
before posting it — the same bytes `strix-scan` sends for an `.eml`. Scanning the
body alone would strip the MIME framing (`Content-Type`, `boundary`,
`Content-Transfer-Encoding`, attachment `filename`) that the extractor needs.
strixd splits the message into its MIME parts, decodes base64 and
quoted-printable, and unpacks each attachment as if that file had been posted on
its own (at most 256 parts per message; `message/rfc822` parts are walked too).

### Postfix

```ini
# main.cf
smtpd_milters     = inet:127.0.0.1:8081
non_smtpd_milters = inet:127.0.0.1:8081
milter_default_action = accept       # keep mail flowing if the milter is down
milter_header_checks = pcre:/etc/postfix/milter_header_checks
```

```pcre
# /etc/postfix/milter_header_checks — hold anything the scanner called infected
/^X-Mailstrix-Status:\s*infected/   HOLD Mailstrix: malware detected
```

`milter_default_action = accept` matters: with `tempfail`, a milter outage would
defer your entire mailflow. The whole design assumes the filter is allowed to
disappear.

Released messages sit in the hold queue (`postsuper -H` / `-r`). Prefer to reject
outright instead? Swap `HOLD` for `REJECT` — but note you are then rejecting on a
scanner the MTA cannot see the health of.

### Sendmail

```m4
INPUT_MAIL_FILTER(`strix', `S=inet:8081@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` tempfails if the milter is unreachable; use `F=` (empty) to accept instead,
which matches the fail-open posture above.

### Flags

| Flag / env | Default | What it does |
| --- | --- | --- |
| `-url` / `MAILSTRIX_URL` | — | **required**; base URL of strixd |
| `-listen` / `MAILSTRIX_MILTER_LISTEN` | `inet:127.0.0.1:8081` | `inet:HOST:PORT` or `unix:/path.sock` |
| `-token-file` / `MAILSTRIX_TOKEN` | — | strixd's shared secret; `-token-file` keeps it out of the process list |
| `-timeout` | `20s` | hard per-message deadline; on expiry the message is **accepted** as `unknown` |
| `-max-body` | `8 MiB` | a larger message is accepted **unscanned** rather than scanned as a truncated prefix (which would be a silent miss); the milter path may transiently hold up to ~2x this value per message during buffering |
| `-max-conns` | `64` | max concurrent MTA connections; bounds memory at roughly `max-conns × max-body × 2` for the milter path (due to transient buffering), so a flood of large messages cannot OOM the filter (an OOM restart would, with `milter_default_action = accept`, let mail through unscanned) |
| `-cape-policy` / `MAILSTRIX_CAPE_POLICY` | `static-only` | Delivery always follows the current static verdict; this adapter is report-only. Accepted values are `static-only` and the empty string, which behave identically. An empty environment variable is treated as unset and selects the default. Any other value, including quarantine or temporary-failure policies, is rejected at startup with exit status 2. |
| `-log-clean` | off | log clean verdicts too (noisy) |

Keep the listener on loopback or a unix socket: anyone who can reach it can have
messages scanned.

## Configuration

Optional manual attachment detonation has a separate HTTPS listener configured
by `MAILSTRIX_CAPE_CONFIG_FILE` (`strixd serve -cape-config`). It is disabled by
default; `MAILSTRIX_CAPE_POLICY` supports only `static-only`. See the
[CAPE daemon configuration](internal/mailstrix/CAPE.md) for reference-based
credentials, tenant policy, storage prerequisites and shutdown behavior.
Read the [CAPE operator guide](internal/mailstrix/CAPE-OPERATIONS.md) for
explicit content/egress consent, retention exceptions and offline examples.
Local tests do not establish physical spool capacity or remote purge;
deployment activation remains conditional on that evidence.

Settings use environment variables; `serve -help` lists available CLI overrides
(flag > env > default). The optional clamd listener settings below are env-only.

| Env | Default | Meaning |
|-----|---------|---------|
| `MAILSTRIX_HOST` / `MAILSTRIX_PORT` | `0.0.0.0` / `8079` | HTTP bind address |
| `MAILSTRIX_TOKEN[_FILE]` | — | shared secret for `/scan` (optional); comma-separated for zero-downtime rotation (e.g. `old,new`); unset / `none` / `0` / `off` ⇒ auth disabled, `/scan` runs **open** (warned at startup) |
| `MAILSTRIX_TOKEN_NEXT[_FILE]` | — | incoming rotation token accepted alongside the primary; append here then migrate clients, then promote to `MAILSTRIX_TOKEN` and clear this |
| `MAILSTRIX_RULES_DIR` | `/rules` | dir of `*.yar`/`*.yara` compiled at boot and on SIGHUP |
| `MAILSTRIX_RULES` | — | a precompiled `.yac` bundle; loaded instead of `RULES_DIR` (faster start) |
| `MAILSTRIX_RULES_MAX_AGE` | `172800` (48h) | seconds; flag rules `stale` (metric + `/ready` body); explicit `0` disables. Fail-open: never fails readiness |
| `MAILSTRIX_RULES_ALLOW_COUNT_DROP` | off | `1`/`true`: install a verified rules bundle with zero rules or under 50% of the current rule count (refused by default) |
| `MAILSTRIX_RULES_POLL_INTERVAL` | `86400` Docker/deb; `0` code default | seconds; automatic verified update and reload; explicit `0` disables; enabled intervals must be at least 60 seconds |
| `MAILSTRIX_RULES_FETCH_TIMEOUT` | `300` | seconds; shared deadline for automatic update network and cache-lock waits |
| `MAILSTRIX_RULES_URL` | GitHub `rules-current` release | public bundle/manifest directory override for daemon polling and `fetch-rules` |
| `MAILSTRIX_RULES_ALLOW_HTTP` | off | permit a plain-`http` `MAILSTRIX_RULES_URL`; `https` is required otherwise, and `https`-to-`http` redirects are always refused |
| `MAILSTRIX_RULES_EXTRA_SIGNING_KEYS` | — | comma-separated extra trusted rules-manifest signing public keys (raw 32-byte ed25519, base64). **Additive only:** the keys built into the binary stay trusted and cannot be removed. A malformed entry fails startup; a configured key is logged loudly. There is no way to disable signature verification |
| `MAILSTRIX_SCAN_TIMEOUT` | `8` (s) | per-request libyara budget (raw + all extracted streams share it) |
| `MAILSTRIX_BACKEND_TIMEOUT` | `1` (s) | how long to wait for an admission / scan slot |
| `MAILSTRIX_MAX_CONCURRENT` | `auto` (CPU count) | max concurrent libyara scans (CPU gate) |
| `MAILSTRIX_MAX_INFLIGHT` | `auto` (2× concurrent) | max in-flight requests (admission gate); kept above the scan gate so a slow body/Redis can't starve scans |
| `MAILSTRIX_ICAP_MAX_CONNS` | `auto` (8× in-flight) | max live ICAP connections, capped at `accept()` (pre-admission); over the cap the server answers `503` and hangs up, so a slow-loris pool cannot accumulate goroutines/fds |
| `MAILSTRIX_MAX_BODY` | `8388608` (8 MiB) | max request body, in bytes (checked before reading) |
| `MAILSTRIX_EFFORT_MAX` | `10` | effort-tier ceiling (1–10); the hard cap a per-request `X-MAILSTRIX-Effort` header can never exceed (DoS guard) |
| `MAILSTRIX_EFFORT` | `= MAILSTRIX_EFFORT_MAX` | default effort level when no `X-MAILSTRIX-Effort` header is sent (1 = raw + shallowest extraction, max = full depth). Set to `auto` (EFFORT-2) to derive the level from admission-gate pressure — full depth when idle, shedding a level at a time as in-flight scans fill the gate, climbing back as it drains (one level/scan; `mailstrix_effort_auto_level` gauge tracks it). The level scales real work: decode depth, XLM/PDF clamps, reputation feeds and scan timeout are all wired to the resolved profile (EFFORT-4), so a lower level genuinely does less. |
| `MAILSTRIX_ARCHIVE_PW` | `0` (off) | **opt-in**: when `1`, try to decrypt password-protected archive members (zip ZipCrypto + WinZip-AES, 7z, rar) using candidate passwords scraped from the mail (subject/body/filename) plus an optional wordlist, then scan the recovered payload. Default OFF ⇒ an encrypted member is flagged `ARCHIVE-ENCRYPTED` and never decrypted (historical behaviour, byte-identical). The brute loop is hard-bounded: ≤64 candidates, a global per-input attempt cap, a tighter sub-cap for KDF formats (7z/rar/AES), a per-attempt wall-clock watchdog, and a per-attempt deadline check. Fail-open everywhere — any error/cap/timeout degrades to skip + keep `ARCHIVE-ENCRYPTED`. A cracked member emits `ARCHIVE-DECRYPTED`. |
| `MAILSTRIX_ARCHIVE_PW_FILE` | — | optional newline wordlist of extra candidate passwords, loaded once at boot (capped, fail-open) and appended to the per-mail candidates. Consulted only when `MAILSTRIX_ARCHIVE_PW=1`. |
| `MAILSTRIX_CACHE_TTL` | `3600` (s) | verdict cache TTL; `0` disables caching |
| `MAILSTRIX_CACHE_SIZE` | `65536` | in-memory LRU entries |
| `MAILSTRIX_REDIS_URL` | — | optional shared L2 cache, e.g. `redis://host:6379/6` |
| `MAILSTRIX_REDIS_PREFIX` | `yara:scan:` | Redis key prefix |
| `MAILSTRIX_REDIS_MAC_KEY` (or `_FILE`) | — | optional HMAC-SHA256 key (>= 32 bytes) over Redis L2 values, bound to the Redis key; a missing or bad MAC is a cache miss. Unset = no MAC. Roll the key out on all replicas; values written before the rollout read as misses and repopulate |
| `MAILSTRIX_METRICS_AUTH` | off | require the token for `/metrics` and `/version` (`/health` & `/ready` stay open) |
| `MAILSTRIX_URLHAUS_KEY[_FILE]` | — | abuse.ch Auth-Key; enables the URLhaus malware-URL lookup |
| `MAILSTRIX_URLHAUS_REFRESH` | `21600` (6 h) | URLhaus feed refresh (floor 5 min) |
| `MAILSTRIX_URLHAUS_MAX_URLS` | `64` | max URLs examined per message |
| `MAILSTRIX_MBAZAAR_KEY[_FILE]` | — | abuse.ch Auth-Key (same key); enables the MalwareBazaar hash lookup |
| `MAILSTRIX_MBAZAAR_REFRESH` | `86400` (24 h) | MalwareBazaar feed refresh (floor 5 min) |
| `MAILSTRIX_MBAZAAR_FEED` | full dump | override the feed URL (e.g. the lighter "recent" export) |
| `MAILSTRIX_THREATFOX_KEY[_FILE]` | — | abuse.ch Auth-Key (same key); enables the ThreatFox URL/domain IOC lookup |
| `MAILSTRIX_THREATFOX_REFRESH` | `21600` (6 h) | ThreatFox feed refresh (floor 5 min) |
| `MAILSTRIX_THREATFOX_MAX_URLS` | `64` | max URLs/domains examined per message |
| `MAILSTRIX_BIGFILE_THRESHOLD` | `6291456` (6 MiB) | buffers larger than this scan against the smaller `BIGFILE_RULES` set, not the full bundle (cost gate); markers always use the full set; `0` disables the gate |
| `MAILSTRIX_BIGFILE_RULES` | baked seed | optional `.yac` bundle scanned for oversized buffers; unset ⇒ the baked `local.yac` seed set |
| `MAILSTRIX_RULE_DENYLIST` | `http` | comma-sep rule names to suppress (case-insensitive); set empty to disable |
| `MAILSTRIX_RULE_ALLOWLIST` | — | comma-sep rule names to force log-only (kept + tagged `mailstrix_allow`); deny wins if in both |
| `MAILSTRIX_DENYLIST_FILE` | — | optional file of rule names to suppress (one per line, `#` comments, case-insensitive), merged with `MAILSTRIX_RULE_DENYLIST`; re-read on SIGHUP; missing or unreadable logs a warning and keeps the env list |
| `MAILSTRIX_CACHE_DIR` | — (disabled) | writable dir for the live rule bundle; reseeded from `MAILSTRIX_SEED_RULES` when its `compiled.yac` is missing or unreadable |
| `MAILSTRIX_SEED_RULES` | — | baked read-only `.yac` used to (re)seed `MAILSTRIX_CACHE_DIR` |
| `MAILSTRIX_CANARY` | `0` | tag every match as log-only canary/shadow output; shipped rspamd/SpamAssassin/Sieve/ICAP integrations observe but do not score/block these hits |
| `MAILSTRIX_ICAP_ADDR` | — (disabled) | TCP address for the optional ICAP listener (RFC 3507), e.g. `127.0.0.1:1344`. A wildcard host (`:1344`, `0.0.0.0`, `::`) is refused unless `MAILSTRIX_ALLOW_WILDCARD_BIND=1`. When set, strixd also accepts REQMOD/RESPMOD from ICAP-aware proxies (Squid, c-icap). Unset = ICAP disabled. No ICAP-level auth; gate by network/firewall. If the listener cannot bind or stops accepting, `/ready` answers `503`. |
| `MAILSTRIX_CLAMD_TCP_ADDR` | — (disabled) | Explicit `host:port`; a wildcard host needs `MAILSTRIX_ALLOW_WILDCARD_BIND=1` |
| `MAILSTRIX_ALLOW_WILDCARD_BIND` | `0` | permit a wildcard (all-interface) ICAP or clamd TCP bind; these listeners do not check the `/scan` token |
| `MAILSTRIX_CLAMD_UNIX_PATH` | — (disabled) | Absolute socket path |
| `MAILSTRIX_CLAMD_MAX_CONNS` | `64` | Shared Unix/TCP cap, range 1–1024 |
| `MAILSTRIX_VERBOSE` | off | log one line per request |
| `MAILSTRIX_LOG_STDOUT` | off | info/access logs to stdout (errors always stderr) |
| `MAILSTRIX_PPROF` | off | enable `/debug/pprof` profiling endpoints (off by default; auth-gated when `MAILSTRIX_METRICS_AUTH` is set) |

**Reload rules:** `docker kill -s HUP strixd` recompiles in place and flushes the
cache. A reload that fails to compile keeps the previous (working) rules — a bad
edit can't disarm a running scanner. On SIGTERM/SIGINT strixd drains (`/ready` →
`503`, in-flight scans finish) before exiting — safe for rolling updates.

## Sizing profiles

`MAILSTRIX_MAX_CONCURRENT` defaults to the CPU count (`auto`). On a many-core host
(32+ CPUs) that reserves significant memory. The request-buffer ceiling is set by
the admission gate, not the scan gate: up to `MAX_INFLIGHT` requests can each hold
a full body plus its extracted streams, so the startup log estimates peak resident
as roughly `MAX_INFLIGHT × MAX_BODY + RSS` (the loaded-rules resident set). Size
`mem_limit` accordingly and pin `MAX_CONCURRENT`/`MAX_INFLIGHT` explicitly when the
defaults are too aggressive.

`MAILSTRIX_MAX_INFLIGHT` (default `2×MAX_CONCURRENT`) is the admission gate — excess
requests receive a `503` immediately rather than queuing. Keep it above
`MAX_CONCURRENT` so a slow body read or Redis round-trip can't starve scan slots.

Redis/Valkey L2 (`MAILSTRIX_REDIS_URL`) dramatically improves throughput for repeated
attachments, which is common in mail (bulk campaigns, MTA retries, one body to N
recipients). Without it each scanner instance maintains its own in-process LRU
only.
Set `MAILSTRIX_REDIS_MAC_KEY` (>= 32 bytes) to authenticate L2 values with an
HMAC bound to the Redis key; tampered, un-MACed, or cross-key-reused values are
cache misses. The MAC is not a freshness check.

| Profile | `MAILSTRIX_MAX_CONCURRENT` | `MAILSTRIX_MAX_BODY` | `mem_limit` | Redis | Expected p95 | RPS capacity |
|---------|------------------------|------------------|-------------|-------|-------------|-------------|
| **Small** — single mailhost, <100 msgs/min | `2` | `10485760` (10 MiB) | `128m` | optional (LRU only) | <500 ms | ~10 |
| **Medium** — mailhost, 100–1000 msgs/min | `auto` (CPU count) | `26214400` (25 MiB) | `256m` | recommended | <300 ms | ~50 |
| **Large** — cluster, >1000 msgs/min | `auto` | `26214400` (25 MiB) | `512m`+ | required | <200 ms | ~200+ |

Notes:
- MalwareBazaar full-dump mode (`MAILSTRIX_MBAZAAR_KEY` set) adds ~40 MiB resident
  plus a ~100–150 MiB transient spike on refresh — raise `mem_limit` to ~768m in
  that case.
- For the Large profile, run multiple replicas behind a load balancer rather than
  one container with a very high `MAX_CONCURRENT`: smaller per-container concurrency
  improves tail latency under burst load and avoids one libyara panic taking all
  capacity.
- `MAILSTRIX_BACKEND_TIMEOUT` (default `1s`) caps how long a request waits for an
  admission slot. Under sustained overload this is the 503 fuse — keep it short
  so callers (rspamd) fail fast rather than stacking connections.

## Rules

The image bakes eight public rulesets at build time; a daily rebuild
(`--build-arg CACHEBUST=$(date +%s)`) re-pulls the latest. **Full credit to the
authors — strixd only packages their work.** Each set keeps its own license:

| Ruleset | Author / source | License | Notes |
|---------|-----------------|---------|-------|
| **YARA-Forge** | [YARAHQ/yara-forge](https://github.com/YARAHQ/yara-forge) | aggregator (each rule keeps its upstream license) | vetted, deduped multi-repo bundle; default tier `core` (`YARAFORGE_SET=extended`/`full`) |
| **signature-base** | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | [DRL 1.1](https://github.com/Neo23x0/signature-base/blob/master/LICENSE) | the broad community set behind THOR/Loki |
| **ANY.RUN** | [anyrun/YARA](https://github.com/anyrun/YARA) | public detection rules | malware-family + phishing (`ANYRUN=0` to skip) |
| **Didier Stevens Suite** | [DidierStevens/DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite) | public domain | OLE/RTF/maldoc + the `vba.yara` macro set (`DIDIER=0` to skip) |
| **bartblaze/Yara-rules** | [bartblaze/Yara-rules](https://github.com/bartblaze/Yara-rules) | MIT | maldoc/RTF + phishing-doc not in YARA-Forge (`BARTBLAZE=0`) |
| **InQuest yara-rules-vt** | [InQuest/yara-rules-vt](https://github.com/InQuest/yara-rules-vt) | MIT | curated mail subset: PDF/LNK/OneNote/`.msg`/RTF (`INQUEST=0`) |
| **CAPEv2** | [kevoreilly/CAPEv2](https://github.com/kevoreilly/CAPEv2) | BSD-3-Clause | curated mail-relevant family rules (Guloader/Formbook/AgentTesla/Obfuscar); raw-fetched, not the full sandbox (`CAPE=0`) |
| **YARAify** | [abuse.ch YARAhub](https://yaraify.abuse.ch/yarahub/) | CC0 | abuse.ch community feed, refreshed daily (`YARAIFY=0`) |

Roughly 10,000+ rules total. Pin or toggle any source with a build arg
(`YARAFORGE_SET`, `*_REF`, `DIDIER=0`/`BARTBLAZE=0`/`ANYRUN=0`/`INQUEST=0`/`CAPE=0`/`YARAIFY=0`).

**Rule profile (PERF-25)** — `MAILSTRIX_PROFILE` selects how much of the fetched
breadth is baked:

- **`mail`** (default) — runs a conservative per-rule filter
  (`docker/filter-rules.py`) over *every* fetched source, dropping only the rules
  that can never fire on a mail attachment's bytes (memory-dump / kernel-driver /
  Linux-ELF-only / pcap / non-redistributable MALPEDIA). A rule is kept whenever a
  maldoc/script/dropper/loader/stealer/RAT token appears in its name (KEEP-wins),
  and all `private` helper rules are always kept. Smaller, faster bundle with **no
  measured loss of mail detection** on the malware corpus.
- **`full`** — bakes every fetched rule, no filtering.

Legacy `YARAFORGE_FILTER=0` is honoured as an alias for `MAILSTRIX_PROFILE=full`.

On top of the public sets, strixd bakes its own local heuristics from
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
  tagged `suspicious`, routes to `STRIX_SUSPICIOUS`.
- `Maldoc_DDE_Field` (`ooxml_dde.yara`) — **DDE/DDEAUTO field injection**
  heuristic. The extractor reads `word/document.xml` (and header/footer parts),
  extracts field instructions from `w:fldSimple/@w:instr` attributes and from
  concatenated `w:instrText` runs (so obfuscated split-token instructions are
  caught), and emits a synthetic `OOXML-DDE-FIELD <instr>` stream for any
  instruction that begins with `DDE` or `DDEAUTO`. This rule matches that stream,
  covering macro-free command execution via DDE fields (T1559.002). Score 55,
  tagged `suspicious`, routes to `STRIX_SUSPICIOUS`.
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
  sandbox-evasion primitives together. Scores 30–55, `STRIX_SUSPICIOUS`.

These are all tagged `suspicious`, so they score in the `STRIX_SUSPICIOUS` tier
(tunable), run over the decompressed VBA cleartext (and body / decoded blobs),
and are keyword/behaviour heuristics — not emulation (Chr() chains / XLM
execution stay with `olevba`).

Public rulesets are messy, so two things keep them from breaking the build:
libyara is compiled **without** `magic`/`cuckoo` (unneeded for mail; rules
importing them are skipped), and each file is test-compiled alone first — one
unparsable file is logged and skipped, not fatal (error only if *nothing*
compiles).

## How it reads documents

Malware in mail mostly arrives as a document that hides its payload where a raw
byte-scan can't see it. strixd **pre-extracts** the hidden content, then scans
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
- **Windows launcher fields** — content-recognised Internet Shortcut INI
  (`URL`, `IconFile`, `WorkingDirectory`, `ShowCommand`, `HotKey`, `IDList`) and
  settings XML (`DeepLink`, `Icon`)
  are surfaced as marker/value streams, including inside archives and Outlook
  attachments. A local rule scores suspicious PowerShell DeepLink arguments at
  50; format presence, remote icons and executable-looking URLs alone add no
  score. Extraction never opens a target.
  Launcher enrichment accepts UTF-8 and BOM-signalled UTF-16LE/BE. UTF-16
  normalization rejects odd byte counts and unpaired surrogates, with separate
  1 MiB limits on original and decoded bytes. For UTF-16 input, XML encoding
  declarations must name UTF-16 or the endian-specific encoding matching the
  BOM; declarations are limited to 8 KiB of decoded text. A failed normalization
  emits no fields.
  BOM-less UTF-16 still has generic text recovery but no launcher enrichment.
  Recognition and extraction inspect at most 1 MiB; INI records/XML tokens are
  capped at 4096, XML depth at 64, fields at 32 and values at 4 KiB.
  For XML, malformed or oversized input contributes no fields; token, depth and
  time limits retain complete fields parsed before the budget stop. Field counts
  and values are truncated to their caps.
  INI extraction retains fields collected before its limits. Raw scanning still
  runs when launcher recognition or extraction reaches a limit.
- **MSIX manifest fields** — existing ZIP walkers, including nested packages
  and packages carrying `[Content_Types].xml`, enrich a root `AppxManifest.xml`.
  Supported Windows 10 foundation namespace paths expose Identity Name,
  Publisher, Version, ProcessorArchitecture and ResourceId; Applications /
  Application Id, Executable, EntryPoint and StartPage; and the UAP
  `windows.protocol` Extension / Protocol Name. Combined `MSIX-IDENTITY`,
  `MSIX-APPLICATION` and `MSIX-PROTOCOL` field/value streams contain untrusted
  declarations, not verified publisher identities or risk scores. Recognition
  checks selected namespaces, paths and attributes, not full XSD conformance,
  package signatures or executable existence. See Microsoft's
  [identity schema](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-f-identity),
  [application schema](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-f-application)
  and [protocol schema](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-uap-protocol).
  Malformed XML or exceeded 1 MiB input, 4096-token, 32-level, 64-attributes-per-element
  or deadline budgets contribute no fields; output is capped at 32 fields,
  2048 bytes per value and the shared stream limit. UTF-8-compatible XML only.
  Payload selection remains unchanged. A recognized OPC manifest charges one
  member and its input bytes to the shared archive budget; a generic ZIP
  manifest is already charged as a raw member. This is limited metadata
  enrichment, with no filesystem unpacking or execution and
  no new payload-extraction guarantee. Raw scanning still runs.
- **Multi-stage decode pass** — over the raw body and every extracted stream,
  long base64/hex runs are decoded and any whole-buffer reverse (VBA
  `StrReverse`) is undone, then the decoded blobs are re-scanned. The pass is
  **recursive**: a decoded blob is fed back through the decoders, up to
  `maxDecodeDepth = 4` ([`internal/extract/decode.go`](internal/extract/decode.go)),
  so a Dridex-style 2+-layer payload is unwound rather than only its outer
  wrapper. Depth is one of the caps the [effort dial](#sizing-profiles) scales.
  No VBA is *executed* on this path — the bounded XLM emulator is the only
  evaluator, and full VBA emulation stays out of scope.
- **HTML carriers** — plain HTML and HTML-ish parts are checked for smuggled
  containers and script-bearing URIs: a `data:` URI container
  (`HTML_DataURI_Container`), a base64 payload embedded in `<svg>`
  (`SVG_Embedded_Payload`), and `javascript:`/`vbscript:` URIs in HTML
  attributes — surfaced as an `HTML-SCRIPT-URI` marker, or
  `HTML-SCRIPT-URI-OBFUSCATED` when the scheme was hidden behind HTML entity
  encoding (`HTML_Script_URI` / `HTML_Script_URI_Obfuscated`).
- **MIME walk** — a part handed over as a whole message is walked as MIME:
  strixd splits it into parts, decodes the transfer encoding and routes each
  attachment back through the extractors above, so a carrier nested in a
  forwarded or `message/rfc822` part is unwrapped rather than scanned as one
  opaque blob ([`internal/extract/mime.go`](internal/extract/mime.go)).
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
  `X-MAILSTRIX-Filename`; the name is folded into the verdict cache key.
- **URL defanging** — `hxxp`→`http`, `[.]`/`(dot)`→`.` on every buffer before
  the URLhaus lookup; a hit found only after defanging is flagged `_DEOBF`.

Extraction is **best-effort and fail-open**: a non-document, a parse error, an
unsupported or non-default-password encrypted package, or a hostile/poison file
(oleparse panics are recovered) falls back to a raw-only scan. Supported
default-password documents are decrypted and re-scanned as described above.
The whole request shares one `MAILSTRIX_SCAN_TIMEOUT`
across raw + every extracted stream, and zip-bomb/quine caps (per-item, total
bytes, member/depth counts) bound the work, so one document can't monopolize a
Production extraction, bounded multi-stage decoding and XLM evaluation run in
strixd without Python, oletools or olefy. The optional
[`rspamd-olefy`](https://github.com/eilandert/rspamd-olefy) integration is a
separate scorer; it is not required for these features. These bounded heuristics
do not provide full VBA emulation or a guarantee of oletools parity.

## What Mailstrix detects on its own

The public rule sets catch *known* samples. On top of them Mailstrix ships
**over 100 rules of its own** in [`docker/local-rules/`](docker/local-rules/),
baked into every image. That directory is the source of truth for the local
pack; `strixd check-rules` reports the rule count of the **whole** compiled
bundle (local rules plus every public source). They score
the structural evidence the extractors surface — the markers and cleartext that
only exist *because* a carrier was taken apart — so a brand-new sample with no
public signature still has something to hit.

A CI parity check ([`internal/extract/parity_doc_test.go`](internal/extract/parity_doc_test.go))
asserts that every marker in the extractor contract has a scoring rule and that
the inventory is exhaustive, so a new marker cannot ship unscored.

### Office macros and maldoc behaviour

| Rule | Catches |
| --- | --- |
| `Maldoc_AutoExec_Write_Execute` | auto-exec ∧ file-write ∧ execute (mraptor-style) |
| `Maldoc_Suspicious_VBA_Keywords` | olevba-style suspicious-keyword count heuristic |
| `Maldoc_VBA_Shellcode_API` | `Declare` of a Win32 API plus a process-injection primitive |
| `Maldoc_UserForm_Payload` | payload strings hidden in VBA UserForm control data |
| `Maldoc_DocProps_Payload` | payload strings in document properties / custom XML |
| `VBA_Stomped` | p-code present, decompressed source missing or trivial |
| `VBA_Environ_Probe` | `Environ()` probing, including obfuscation-folded |
| `Maldoc_AntiAnalysis_Evasion` | two or more anti-analysis / sandbox-evasion primitives |
| `PPT_VBA_Macro` | legacy `.ppt`/`.pps` with an embedded VBA project |
| `Maldoc_Behavior_Score`, `_High` | **weight of evidence** — 3+ (or 5+) independent low-confidence structural markers co-occurring, so a document that trips nothing individually damning still scores |

### OLE2 / CFB structure (`oleid`, `oletimes`, `olemeta` parity)

| Rule | Catches |
| --- | --- |
| `OLEID_ObjectPool`, `OLEID_Flash` | embedded OLE objects; embedded Shockwave Flash |
| `OLE2_ExtraData` | payload stapled past the last FAT-allocated sector |
| `OLE_Doc_Security` | `SummaryInformation` DOC_SECURITY flag (password / read-only) |
| `Document_DigitalSignature` | a digital-signature storage (stacks with macros) |
| `OLETimes_FutureStamp`, `_SyntheticStamps` | a directory entry stamped in the future; many entries sharing one fabricated timestamp |
| `OLE_Meta_Template_Injection` | `SummaryInformation` Template pointing at a remote `http(s)`/UNC path (T1221) |
| `OLE_Meta_AppName_Equation` | authoring AppName is Equation Editor (EQNEDT32 vector) |
| `OLE_Meta_FreshDoc_Stomp` | RevNumber 0/1 with zero total editing time (fresh or stomped) |
| `Encrypted_Document`, `Encrypted_XOR_Obfuscation` | RC4/AES encryption; reversible XOR `FILEPASS` obfuscation |
| `DefaultPW_Decrypted` | BIFF8 workbook unlocked with the `VelvetSweatshop` default password |
| `OLEID_OOXML_VBA_Present`, `_ExternalRel`, `_DDE`, `_XLM_Present` | `oleid2` presence indicators for OOXML |

### Excel 4.0 (XLM) macros

| Rule | Catches |
| --- | --- |
| `XLM_Hidden_Macrosheet` | a hidden or very-hidden macrosheet |
| `XLM_Dangerous_Function` | `EXEC`/`CALL`/`REGISTER`/`FOPEN`/`FWRITE`/`HALT` |
| `XLM_AutoOpen_Dropper` | `Auto_Open`/`Auto_Close` plus a hidden sheet or code-exec call |
| `XLM_Hidden_Dangerous_Dropper` | both at once — the classic XLM dropper shape |
| `XLM_Emulator_Deep_Exec` | `CALL` reached only through a loop or branch, i.e. control-flow evasion the **bounded emulator** had to execute to see |

### Macro-less Office execution

| Rule | Catches |
| --- | --- |
| `Maldoc_DDE_Field`, `RTF_DDE_Field` | `DDE`/`DDEAUTO` field instructions in OOXML and RTF |
| `SLK_DDE_Command`, `CSV_DDE_Command`, `XLSB_DDE_SupBook` | DDE command execution via SYLK cells, CSV / Excel-2003-XML cells, and XLSB external-link supporting books |
| `OOXML_Remote_Template` | external relationship to a remote URI (template injection, T1221) |
| `OOXML_MHTML_Scheme` | `mhtml:` / `!x-usc:` MSHTML scheme (CVE-2021-40444) |
| `RTF_ObjUpdate` | `\objupdate` auto-fetch (CVE-2017-0199 vector) |
| `OLE2Link_URL_Moniker` | embedded OLE2Link URL moniker (CVE-2017-0199 auto-load) |
| `Exploit_EquationEditor`, `_MTEF` | Equation Editor object; with MTEF bytecode (CVE-2017-11882 / CVE-2018-0802) |
| `OLE_ShellExplorer_CLSID` | Shell.Explorer CLSID `{EAB22AC3-…}` (CVE-2026-21509 IE WebBrowser lure) |
| `VSTO_Remote_Codebase` | `.vsto` ClickOnce add-in with a remote `codebase` (T1137.006) |
| `SettingContent_DeepLink_EncodedPowerShell` | `.settingcontent-ms` DeepLink launching encoded PowerShell |
| `XLL_AddIn` | an emailed `.xll` — a PE DLL exporting `xlAutoOpen`, which runs on load with **no macro prompt** |

### PDF (`pdfid` parity)

`PDF_OpenAction_JS`, `PDF_Additional_Actions`, `PDF_Launch_Action`,
`PDF_EmbeddedFile`, `PDF_JBIG2` (CVE-2009-3459), `PDF_HexObfuscatedName`
(`#XX` name-escape evasion) and `PDF_ObjStm` (objects hidden in an object
stream).

### HTML and SVG smuggling

| Rule | Catches |
| --- | --- |
| `HTML_Smuggling_Blob` | script reassembling a Blob / object-URL and force-downloading it |
| `HTML_Smuggling_DataURI` | force-downloaded base64 `data:` URI payload |
| `HTML_DataURI_Container` | a `data:` URI decoding to `PK`/OLE2/`MZ`/`%PDF` with no download attribute |
| `SVG_Scripted` | `<svg>` root carrying `<script>` / `onload` / `<foreignObject>` |
| `SVG_Embedded_Payload` | `<image href>` base64 decoding to a container magic — a smuggled dropper, not raster art |
| `HTML_Script_URI`, `_Obfuscated` | `javascript:`/`vbscript:` in `href`/`src`/`action`/`formaction`, and the same scheme visible **only after HTML-entity decoding** (`&#118;`, `&#x76;`, IE spaced/NUL entities) |

### Script droppers — PowerShell, VBS, JScript, batch

This is where a fresh campaign usually lands first, so the set is deliberately
behavioural rather than hash-based:

- **PowerShell** — `PS1_IEX_IRM_DownloadCradle` (`iex(irm …)`),
  `PS1_Curl_Rundll32_PNG_Loader` (download a `.png`, run it as a DLL via
  `rundll32 file.png,export`), `PS1_RandomName_Temp_Download_Exec_Delete`,
  `PS1_Defender_Exclusion_Cleanup_Loader` (run, then remove its own Defender
  exclusion and self-delete), `PS1_Despaced_Assembly_Load_Loader`,
  `PS1_ControlFlowFlatten_CharSurgery` (a `while`/`switch` state machine plus
  `.Insert` char surgery), `PS1_DotNet_LOLBin_Killer_Loader` (kills
  `aspnet_compiler`/`AddInProcess` to prep an inject — AsyncRAT/DcRat),
  `PS1_PSCredential_Password_Spray`, and `PowerShell_Abuse_Flags`.
- **VBScript** — `VBS_GetObject_Scriptlet_SelfDelete`,
  `VBS_WScriptShell_Run_TempBat_Hidden`, `VBS_CustomBase64_MSXML_ExecuteGlobal`,
  `VBS_CharCode_Split_Dropper`, `VBS_ArrayScatter_OffsetTable_Dropper`,
  `VBS_Sibling_Exe_Hidden_Launcher`.
- **JScript** — `JS_Obfusc_StringConcat_Accumulate`,
  `JS_Dropper_CharCodeArray_ActiveX`, `JS_Dropper_XorArray_ActiveX`.
- **Batch / LOLBin** — `BAT_Dropper_Curl_Execute`, `LOLBins_Invocation`,
  `WMI_Process_Spawn` (`Win32_Process.Create`),
  `Script_MSIExec_Remote_Package_Silent` (including Unicode-homoglyph
  `-Package` evasion), and `AnyDesk_Unattended_Access_Abuse` (a batch that
  silently sets an AnyDesk unattended-access password — RMM-abuse remote
  access).
- **Stacked obfuscation** — `Multilayer_Encoded_Payload` fires on 3+ nested
  decode layers, which is itself the signal.

### Carved executables and file-type confusion

| Rule | Catches |
| --- | --- |
| `PE_Section_Packed` / `PE_Section_High_Entropy` | section entropy ≥ 7.2 / ≥ 7.0 |
| `PE_Overlay` | data appended past the last section |
| `PE_Virtual_Section` | `SizeOfRawData=0`, `VirtualSize>0` (FormBook `.ndata` / hollowing) |
| `PE_DotNet`, `PE_Anomaly` | a CLR data directory; structural header anomalies |
| `ELF_Executable` | a valid ELF executable inside a mail container |
| `Base64_Stuffed_PE` | a whole PE base64'd into a document text field with a pad so `MZ` misses offset 0 — decoded, re-aligned and carved so the `pe` rules fire |
| `Polyglot_PE_ZIP` | one buffer that is **both** a valid PE and a valid ZIP: the gateway parses the ZIP, the endpoint runs the PE |
| `Renamed_Container` | the real parsed type (OLE/OOXML/RTF/archive/LNK/MSI/OneNote) contradicts a benign-looking extension — driven by the *extracted* type, not a magic-byte grep |
| `Shellcode_GetEIP` | position-independent shellcode prologues (`E8 00000000`+`pop`, Didier-Stevens `fnstenv`) in a non-PE blob |
| `CanonStager_SideLoad_Loader` | CANONSTAGER DLL side-loading shellcode stager (PRC-Nexus / SOGU.SEC / PlugX) |
| `Node_RAT_Webpack_Bundle` | webpack-bundled Node.js RAT: `child_process`+`axios`+`form-data` shims, `execSync`, scheme-split C2 |

### Password-protected archives

`Archive_Encrypted` flags a password-protected zip/rar/7z member — a payload the
scanner cannot see. With `MAILSTRIX_ARCHIVE_PW=1`, candidate passwords scraped
from the mail subject and body (plus an optional wordlist) are tried; a recovered
member is scanned separately and raises `Archive_Decrypted`, because **a password
supplied in the mail body is itself the evasion tell**.

### How matches are reported

Matches surface under tiered symbols — `STRIX_MALWARE`, `STRIX_EXPLOIT`,
`STRIX_PHISHING`, `STRIX_SUSPICIOUS` and bare `STRIX` — so a confident family hit
scores differently from a structural suspicion; the
[rspamd plugin](contrib/rspamd/) maps each tier to its own weight. Reputation
hits report separately as `URLHAUS_MALWARE_URL` / `_HOST` / `_DEOBF`,
`MALWAREBAZAAR_MALWARE` and `THREATFOX_IOC_URL` / `_DOMAIN`.

## abuse.ch feeds (optional)

Set a free [abuse.ch Auth-Key](https://auth.abuse.ch/) to add live reputation,
on top of the YARA rules:

- **URLhaus** (`MAILSTRIX_URLHAUS_KEY`) — checks every message and extracted stream
  against the known malware-URL feed. Hits: `URLHAUS_MALWARE_URL` (exact),
  `URLHAUS_MALWARE_HOST`, `_DEOBF` variant; matched URL in `meta.url`.
- **MalwareBazaar** (`MAILSTRIX_MBAZAAR_KEY`, same key) — checks each attachment's
  SHA256 against the known-malware corpus. Hit: `MALWAREBAZAAR_MALWARE`, digest
  in `meta.sha256`.
- **ThreatFox** (`MAILSTRIX_THREATFOX_KEY`, same key) — checks URLs/domains in every
  message and stream against the ThreatFox IOC feed. Hits: `THREATFOX_IOC_URL`,
  `_DOMAIN`, `_DEOBF`; matched URL in `meta.url`. Routes to the `THREATFOX_IOC`
  symbol.

These use the same fail-open cached-feed design: the feed is downloaded once per
refresh interval into an in-memory set (lookups are local map hits, never a
per-message API call); a failed refresh keeps the previous set. MalwareBazaar's
full dump adds ~40 MiB resident + a ~100–150 MiB transient spike on refresh —
raise the container `mem_limit` (~768m) when enabling it.

## ICAP mode (optional)

strixd can run as an ICAP server alongside the HTTP `/scan` endpoint, making it
usable as a drop-in content-scanning service for ICAP-aware proxies (Squid,
c-icap, traffic proxies, MTA content-filters).

### Enabling

```sh
docker run --rm --name mailstrix-icap \
    -e MAILSTRIX_HOST=127.0.0.1 \
    -e MAILSTRIX_ICAP_ADDR=:1344 \
    -e MAILSTRIX_ALLOW_WILDCARD_BIND=1 \
    -p 127.0.0.1:1344:1344 \
    myguard-labs/mailstrix
```

The ICAP listener starts on `:1344` (IANA ICAP port). The HTTP `/scan` server
continues to run on `MAILSTRIX_PORT` alongside it; this example binds HTTP to
the container's loopback and publishes only ICAP on the host's loopback. Both
interfaces share the scan engine, verdict cache, and concurrency budget
(`MAILSTRIX_MAX_INFLIGHT`).

**No ICAP-level authentication.** Gate the port by firewall/network; only
trusted proxies should reach it; when a `/scan` token is configured, strixd
logs a startup warning that this listener does not check it
(mirroring the `/scan` open-mode warning).

### Request bounds

Because the listener is unauthenticated, every part of an ICAP request is capped
before it can allocate:

| Bound | Limit | What it stops |
| --- | --- | --- |
| request line / header line | 8 KiB | a line with no `\n` buffered without bound |
| header count | 128 | a flood of short header lines |
| header block, total | 64 KiB | many medium lines, each under the line cap |
| chunk-header line | 256 B | an oversized chunk-size line |
| body | `MAILSTRIX_MAX_BODY` | an oversized payload (`413`) |
| head read time | 30 s | a slow-loris holding a connection without completing a request |
| live connections | `MAILSTRIX_ICAP_MAX_CONNS` | a connection pool exhausting goroutines/fds (`503` + close) |

Refused connections are counted in the `icap_conn_refused_total` metric.

### Supported methods

| Method | Support |
|--------|---------|
| `OPTIONS` | returns `Methods: REQMOD, RESPMOD`, `Allow: 204`, `Preview: 0`, `ISTag` (a hash of the full ruleset fingerprint, so it changes on every SIGHUP reload that changes the rules) |
| `RESPMOD` | scans the encapsulated response body |
| `REQMOD` | scans the encapsulated request body |

### Verdicts

| Verdict | ICAP response |
|---------|--------------|
| Clean (no actionable match) + `Allow: 204` sent by proxy | `204 No Modification` (proxy serves original) |
| Clean (no actionable match), no `Allow: 204` | `200 OK` echoing the original headers and body unchanged |
| Infected (≥1 actionable match) | `200 OK` with a replacement `403 Forbidden` body. `X-Infection-Found` and the body name the **first** actionable rule; `X-Violations-Found` carries the count followed by, per violation, four TAB-led continuation lines (Filename `-`, rule name, ProblemID `0`, Resolution `2`; draft-stecher-icap-subid-00 §3.4), control characters stripped and each value bounded to 256 bytes; at most 16 violations are listed and the count equals the number listed, so the header block stays bounded |
| Log-only matches only (allowlisted, canary, `MAILSTRIX_SCAN_*` markers) | treated as clean: they never block |
| No complete verdict (scan error, incomplete or degraded scan) | `500 Server Error`, never `204` clean |
| No scan slot free in time | `503 Service Unavailable` |
| Body exceeds `MAILSTRIX_MAX_BODY` | `413 Request Entity Too Large` |
| Unknown ICAP method | `501 Method Not Implemented`, then the connection is closed |

### Squid example

```
icap_enable on
icap_service mailstrix_req reqmod_precache bypass=1 icap://strixd:1344/scan
icap_service mailstrix_resp respmod_precache bypass=1 icap://strixd:1344/scan
adaptation_access mailstrix_req allow all
adaptation_access mailstrix_resp allow all
```

### Testing with c-icap-client

`c-icap-client` (from the c-icap package) sends the file given with `-f` as the
encapsulated body. `-req`/`-resp` take a **URL**, not a file: without `-f` no
body is sent, nothing is scanned, and the reply is always `204`.

```sh
c-icap-client -i 127.0.0.1 -p 1344 -f test.pdf -req http://example.test/test.pdf
# -> Blocked: PDF_OpenAction_JS          (a PDF that auto-runs JavaScript)
c-icap-client -i 127.0.0.1 -p 1344 -f eicar.com -resp http://example.test/eicar.com
# -> Blocked: SUSP_Just_EICAR
```

### Metrics

When `MAILSTRIX_ICAP_ADDR` is set, three additional counters appear in `/metrics`:
- `mailstrix_icap_requests_total` — REQMOD/RESPMOD requests served
- `mailstrix_icap_infected_total` — requests with ≥1 rule match (403 sent)
- `mailstrix_icap_options_total` — OPTIONS requests served

## clamd stream mode (optional)

strixd also accepts the clamd `INSTREAM` subset on an opt-in Unix socket or TCP
listener. Set `MAILSTRIX_CLAMD_UNIX_PATH` to an absolute socket path, or set
`MAILSTRIX_CLAMD_TCP_ADDR` to an explicit `host:port`; both are disabled by
default. For example, a local client can connect over TCP when strixd starts
with `MAILSTRIX_CLAMD_TCP_ADDR=127.0.0.1:3310`.

Submit bytes with `clamdscan --stream` or an existing stream-client hook. The
adapter returns `FOUND` for actionable matches, `OK` for clean or log-only
results, and `ERROR` when it cannot give a complete verdict. It does not accept
clamd file-path scans, and it does not turn Mailstrix rules into ClamAV
signatures. TCP has no protocol authentication or TLS; keep it on a trusted
network; when a `/scan` token is configured, strixd logs a startup warning that
the TCP listener does not check it. The
[clamd adapter guide](contrib/clamd/README.md) has socket and Docker setup,
client examples, supported commands and limits.

## Observability (Grafana + Prometheus)

`/metrics` is Prometheus exposition format (counters + gauges, no auth unless
`MAILSTRIX_METRICS_AUTH=1`). Ready-to-import artifacts live in
[`contrib/deploy/`](contrib/deploy/):

- **[`contrib/deploy/grafana/mailstrix-dashboard.json`](contrib/deploy/grafana/mailstrix-dashboard.json)**
  — a dashboard with the request path (scans/matches/errors/busy), cache hit
  ratio, libyara scan channels (raw/stream/marker/bigfile), extraction by
  carrier, rule reloads, ruleset age/staleness, abuse.ch feed lookups/hits, and
  the auto effort level. Import it and pick your Prometheus datasource.
- **[`contrib/deploy/prometheus/mailstrix-alerts.yml`](contrib/deploy/prometheus/mailstrix-alerts.yml)**
  — alert rules: daemon down, zero rules loaded, stale ruleset, reload failing,
  high scan-error / busy rate, feed-refresh failures. Reference it from
  `rule_files:` in `prometheus.yml`.

Minimal scrape config:

```yaml
scrape_configs:
  - job_name: strixd
    static_configs:
      - targets: ['strixd:8079']
```

## Kubernetes (Helm)

A Helm chart lives at
[`contrib/deploy/helm/mailstrix/`](contrib/deploy/helm/mailstrix/) — a single Deployment
+ ClusterIP Service (internal scan backend, no Ingress by design), mirroring the
Docker compose security posture (nonroot, read-only rootfs, drop ALL caps,
RuntimeDefault seccomp). It wires the token + abuse.ch key from a Secret
(`--set token.value=…` or `token.existingSecret`), exposes the optional
`MAILSTRIX_*` tunables under `config:`, and can emit a Prometheus-Operator
`ServiceMonitor` (`--set serviceMonitor.enabled=true`) scraping the same
`/metrics` the dashboard/alerts above consume. Replicas > 1 want
`redis.url` for a shared verdict cache. See the
[chart README](contrib/deploy/helm/mailstrix/README.md) for the values table.

```sh
helm install strixd ./contrib/deploy/helm/mailstrix \
    --set token.existingSecret=strixd-token
```

Create the `strixd-token` Secret with a `token` key first, as described in the
chart README; the token should not be passed on the command line.

## Wiring it into rspamd

For packaged mail stacks, see the [Mailcow, docker-mailserver, Mailu and Proxmox
Mail Gateway recipes](contrib/integrations/README.md).

The [`contrib/rspamd/`](contrib/rspamd/) directory has everything the rspamd side needs:

- [`plugins/mailstrix.lua`](contrib/rspamd/plugins/mailstrix.lua) — the async plugin that POSTs to
  strixd and classifies each matched rule into a scoring tier:

  | symbol | tier | default weight |
  |--------|------|----------------|
  | `STRIX_MALWARE` | malware family / webshell / RAT / APT / ransomware | `8.0` |
  | `STRIX_EXPLOIT` | exploit / CVE / maldoc exploit | `7.0` |
  | `STRIX_PHISHING` | phishing kit / document | `5.0` |
  | `STRIX` | uncategorized match (default) | `4.0` |
  | `STRIX_SUSPICIOUS` | heuristic / anomaly (FP-prone) | `2.0` |
  | `URLHAUS_MALWARE_URL` | known malware URL (options = the URLs) | `8.0` |
  | `MALWAREBAZAAR_MALWARE` | attachment SHA256 = known sample (option = digest) | `10.0` |
  | `THREATFOX_IOC` | ThreatFox URL/domain IOC (options = the URLs) | `7.0` |
  | `STRIX_ALLOWLISTED` | allowlisted log-only hit (options = rule/feed details) | `0.0` |
  | `STRIX_CANARY` | canary/shadow hit (options = rule/feed details) | `0.0` |
  | `STRIX_UNKNOWN` | degraded or failed scan with no actionable match: unknown, not clean (option = `incomplete`/`error`/`busy`/`transport`/`http`/`parse`/`malformed`/`unscheduled`) | `0.0` |

  Tiers stack, capped by the group `max_score`. The classifier lives in the
  plugin, so retuning is just an rspamd reload (no strixd rebuild).
- [`rspamd.conf.local`](contrib/rspamd/rspamd.conf.local) — how to load a custom lua
  module (inline `mailstrix { }` block + explicit `lua =` include).
- [`local.d/groups.conf`](contrib/rspamd/local.d/groups.conf) — the per-tier weights.
  Set any to `0.0` for a cautious log-only first run.

## Build & test

The [reproducible detection baseline](tools/parity/README.md) runs generated inert
fixtures through Mailstrix and reports explicitly labelled indicator results.
It counts TP, FP, FN and TN per labelled indicator and reports precision as
`TP / (TP + FP)` only when the denominator is nonzero. A structural marker on
an inert fixture is a true positive for that marker, not proof of malware
detection. Missing or incomplete scans are excluded from ratios and fail the
labelled gate. The report leaves `real_world_precision` null: representative
corpus precision and accuracy thresholds have not been measured.
Its optional `run-isolated` command evaluates caller-owned local corpora in
Docker with immutable image-owned rules and fixed resource limits. The in-process
`run` remains synthetic-only; cross-tool parity and real-world precision remain
unmeasured.

See the [runner contract](.github/runner/README.md) for physical-slot restoration
checks, retry requirements and live negative-control acceptance.

Build images, nested actions and the YARA/nfpm downloads use immutable pins.
See [build input pins](docker/INPUTS.md) for update sources and validation.
Changing `GO_VERSION` or `YARA_VERSION` also requires updating the matching
image digest or archive checksum; a version argument alone is insufficient.

Tests need real libyara, so they run **inside the image build** (CGO, race
detector) — CI fails on a bad commit before any image is published:

```sh
# unit tests + go vet, against the same statically-linked libyara as production:
docker build --target test -f docker/Dockerfile -t strixd-test .

# the production image (distroless, nonroot, ~100 MB):
docker build --target final -f docker/Dockerfile -t myguard-labs/mailstrix \
    --build-arg CACHEBUST=$(date +%s) .
```

## Verifying releases

Every release asset is checksummed. Verify a downloaded binary against the
`SHA256SUMS` shipped on the release:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

## Status & roadmap

The capability surface is documented in the
sections above rather than duplicated here as a changelog — see
[Exactly what it does](#exactly-what-it-does) for the summary,
[How it reads documents](#how-it-reads-documents) for the extraction chain,
[What Mailstrix detects on its own](#what-mailstrix-detects-on-its-own) for the
local rule pack, and the per-interface sections for
[ICAP](#icap-mode-optional), [clamd](#clamd-stream-mode-optional),
[`strix-scan`](#thin-client-for-dovecot--sieve-strix-scan) and
[`strix-milter`](#milter-for-postfix--sendmail-strix-milter). Release history is
on the [releases page](https://github.com/myguard-labs/mailstrix/releases).

### Open

- [ ] **Batch `/scan` endpoint** — collapse N per-part round-trips into one request.
- [ ] **TLSH fuzzy hashing** — `glaslos/tlsh` plus MalwareBazaar `get_tlsh`
  family lookup (distance < 30 ≈ same family). Blocked on a labelled corpus to
  FP-tune against; shipping it untuned would cost more than it catches.
- [ ] **FP auto-tuning** — derive the rule denylist from the rspamd ham corpus
  instead of the three hand-curated entries.
- [ ] **CHM extraction** — `.chm` help-file carriers.
- [ ] **Sample-gated legacy XLM/BIFF edge cases** — CSV-DDE-XLSB `sbt=1`,
  per-`funcid` `ptgFunc` arity, BIFF `CONTINUE` reassembly. Each needs a real
  sample before it is worth the parser risk.

### Known limits

- **No full VBA emulation.** String folding and a bounded XLM emulator are
  deliberate stopping points; ViperMonkey-style interpretation and p-code
  disassembly are out of scope. The bounded heuristics do not promise oletools
  parity.
- **Encryption that is not default-keyed is flagged, not cracked** —
  VelvetSweatshop XOR, BIFF8 RC4 and OOXML agile/standard AES are unlocked and
  re-scanned; anything else raises `Encrypted_Document` and is scanned raw.
- **CAPE detonation is report-only by design.** `MAILSTRIX_CAPE_POLICY` accepts
  only `static-only`; a sandbox verdict never gates delivery.

### Out of scope

Disk images (ISO/UDF/`.dmg`/`.pkg`), full VBA emulation (ViperMonkey), p-code
disassembly, and extractor seccomp sandboxing are intentionally excluded — not a
realistic executable mail vector, or over-engineered for an MTA pipe. Android
`.apk` and Java `.jar` members *are* unpacked as archives, but Android-specific
analysis is not attempted. iOS has no executable email vector.

## See also

- **[mailstrix.com](https://mailstrix.com)** — the project home page (the owl that finds malware hiding in your mail).
- **[gozer](https://github.com/eilandert/gozer)** — the DCC/Razor/Pyzor sibling backend this mirrors.
- **[rspamd-olefy](https://github.com/eilandert/rspamd-olefy)** — an optional, separate oletools deep-scan scorer.
- **[Rspamd plugin](contrib/rspamd/)** — score `/scan` matches during SMTP filtering.
- **[ICAP mode](#icap-mode-optional)** — serve REQMOD and RESPMOD to an ICAP proxy.
- **[clamd stream adapter](contrib/clamd/README.md)** — accept `INSTREAM` from
  supported clients.
- **[SpamAssassin plugin](contrib/spamassassin/)** — scan each message through strixd and score a YARA match.
- **[Dovecot/Sieve example](contrib/sieve/)** — quarantine a match with the `strix-scan` client.
- **[Milter for Postfix / Sendmail](#milter-for-postfix--sendmail-strix-milter)** — stamp a verdict header with `strix-milter` and let `milter_header_checks` act on it.
- **Article:** [Mailstrix: YARA malware scanning for mail](https://deb.myguard.nl/articles/yara-malware-scanning-mailstrix/) — the why and how, on deb.myguard.nl.
- **Docker Hub:** [`eilandert/mailstrix`](https://hub.docker.com/r/eilandert/mailstrix)
  (`:latest` = newest release, `:testing` = current `main`).

## License

strixd itself is [MIT](LICENSE). The baked rule sets are **not** strixd's work and
keep their own licenses (see the [Rules](#rules) table): signature-base = DRL
1.1, bartblaze = MIT, InQuest = MIT, Didier Stevens = public domain, ANY.RUN =
public detection rules, YARA-Forge = aggregate (each rule keeps its upstream
license). Dependencies are permissive (`go-yara` BSD-2, `oleparse` MIT, redis
client BSD/Apache).
</content>
