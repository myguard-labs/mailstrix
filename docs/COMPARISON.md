# Mail attachment scanner comparison

Scope: tools commonly layered under rspamd / amavis / Postfix for detecting
malicious Office documents, scripts, and other attachment-borne threats.

---

## At a glance

| Dimension              | oletools                        | SA OLE plugin                   | ClamAV                             | yarad                                  |
|------------------------|---------------------------------|----------------------------------|------------------------------------|----------------------------------------|
| Type                   | Static extractor + heuristics   | Score contributor (presence)     | Signature AV                       | YARA engine + reputation feed lookups  |
| Language / runtime     | Python 3 (subprocess)           | Perl (in-process SA)             | C (clamd daemon)                   | Go + cgo/libyara (daemon)              |
| Detection basis        | VBA keyword patterns, auto-exec, obfuscation markers | Macro present (binary + OOXML) | Known-bad signatures + hashes      | YARA rules (heuristic + IOC) + feeds   |
| Pre-extraction         | VBA decompress, RTF peel, embedded object carve | Raw OLE header probe only | OLE2 unpack, ZIP (OOXML), PE sections | VBA decompress, XLM eval, URL extract, OLE stream walk, SVG/MHTML carve |
| Novel variant coverage | Medium — keyword patterns age   | Low — presence signal only       | Low — signature lag (hours–days)   | High — rules target patterns not hashes |
| Reputation feeds       | None                            | None                             | None                               | URLhaus, MalwareBazaar, ThreatFox, Feodo |
| Integration path       | CLI subprocess / milter wrapper | SA `loadplugin`                  | clamd UNIX socket / amavis         | rspamd HTTP plugin (yara.lua)          |
| Inline latency         | ~200–800 ms (Python cold start) | ~10–30 ms (in-process)           | ~10–50 ms (clamd socket)           | ~5–30 ms (Go, warm cache)              |
| Rule / sig updates     | pip release (weeks)             | Manual plugin update             | freshclam (multiple per day)       | Nightly `.yac` cron → Docker rebuild   |
| False positive risk    | Medium (keywords hit legit macros) | Low (presence-only, weak signal) | Low (precise sigs)              | Medium (heuristic YARA rules)          |
| Tuning surface         | Per-tool flags, allow-lists     | SA score weight                  | Whitelist signatures               | `SLOW_RULE_DENYLIST`, `YARAD_RULE_DENYLIST`, rspamd score weight |
| Memory footprint       | ~50 MB Python per process       | in-process SA heap               | ~30 MB clamd + ~200 MB sig DB      | ~75 MB rules RSS + feed hash sets      |
| Archive / container unpack | OLE2, ZIP, RTF, embedded objects | None                        | ZIP (OOXML), PE                    | ZIP, OLE2, RTF, encoded streams, SVG data: URIs, MHTML |

---

## Strengths

**oletools** — deepest VBA analysis available open-source. Deobfuscation, auto-exec
classification (mraptor), metadata extraction, embedded-object carving. olevba is
the ground-truth reference tool for "is this macro malicious". Best for async triage
and manual review.

**SpamAssassin OLE plugin** — zero additional infra if SA already in the stack. Useful
as a lightweight trip-wire (macro-in-attachment score bump) without running a separate
daemon. Signal is weak (presence-only); combine with higher-signal tools.

**ClamAV** — best known-bad coverage. Fast, operationally well-understood, low FP
profile. Essential for bulk signature matches (Emotet, QakBot, known Office droppers).
Freshclam keeps signatures current within hours of a new family being catalogued.

**yarad** — only tool in this set that combines pre-extraction (macros, XLM formulas,
URLs, container payloads) with heuristic YARA rules AND live reputation feed lookups
in one inline pass. Catches novel variants ClamAV misses before signatures exist.
Rules are auditable and tunable. Compiled ruleset baked into the image — no 200 MB
sig DB pulled at runtime.

---

## Weaknesses

**oletools** — Python subprocess overhead (~200–800 ms) makes synchronous inline use
at volume impractical. No reputation feeds. Keyword rules drift vs obfuscation
evolution; requires periodic rule review.

**SA OLE plugin** — presence-only: fires on every macro-containing document regardless
of content or intent. No extraction, no feeds, no YARA. Produces noise on legitimate
finance / legal macro documents. Redundant if rspamd with a real scanner is the MTA
layer.

**ClamAV** — ineffective against zero-days until a signature is published (hours to
days lag). Signatures match near-exact bytes; minor repacking, XOR, or base64 wrapping
evades. No macro pre-extraction — macros must match in compressed OLE2 form.

**yarad** — no dynamic execution (sandbox); cannot observe payload that only manifests
at runtime. YARA rules require human curation to stay effective; false positives
possible on legitimate macro-heavy templates (finance, legal, HR). No built-in
sandboxed URL fetch (ThreatFox/Feodo check is feed-based, not live).

---

## Gaps — tools worth considering

| Tool | What it adds | Why not inline |
|------|--------------|----------------|
| **Strelka** (target/strangereal) | Go-based file dissector; 50+ processors; Redis queue; structured JSON output per file | Separate infra; async; latency budget varies |
| **Any.run / Cuckoo / CAPE** | Dynamic sandbox execution — catches payloads that never fire statically | Async only; minutes of latency; mail content leaves perimeter |
| **VirusTotal** | 70+ AV engines + community YARA rules + behaviour reports | Latency + mail content / header PII leakage |
| **ExifTool** | Metadata anomaly detection — author/created mismatch, language mismatch, suspicious embedded paths | CLI subprocess; low signal-to-noise ratio without tuning |
| **ssdeep / TLSH** | Fuzzy hash clustering — catch re-packed or slightly-mutated known-bad variants | Needs curated corpus; no public on-prem feed |
| **InQuest Labs / FIF** | Deep OOXML/OLE dissection, file identification, community threat intel | SaaS; no on-prem free tier |
| **p7zip / unar** | Archive unpacking (password-protected ZIPs, RAR, 7z, ACE) — password often in mail body | Subprocess; password extraction heuristic needed |

---

## Recommended stack

**Minimum:** ClamAV (known-bad, fast) + yarad (heuristic + feeds, novel variants).

**Enhanced:** add oletools as an **async** enrichment path (rspamd async DNS-style
call or Strelka side-channel) to surface olevba verdict without blocking the mail
queue. SA OLE plugin is redundant when rspamd is the MTA layer.

**Maximum coverage:** Strelka as an async enrichment bus feeding structured metadata
back to rspamd (via Redis header injection or custom header) without blocking delivery.
Cuckoo/CAPE for high-value targets in a deferred re-scan queue.

---

## What yarad does NOT replace

- ClamAV: known-bad hash/signature coverage; freshclam update velocity
- A sandbox: dynamic payload execution and C2 callback observation
- SPF / DKIM / DMARC: sender authentication (different layer entirely)
- Content policies: attachment type blocking, password-protected archive policy
