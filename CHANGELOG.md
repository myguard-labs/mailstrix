# Changelog

All notable changes to yarad are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Document-properties (`docprops`) and `docVars` string extraction for YARA scan
- UserForm/VBFrame hidden-string extraction
- Excel-4.0 XLM macrosheet detection (OOXML + BIFF8)
- OOXML DDE/DDEAUTO field detection
- OOXML remote-template-injection detection
- RTF `\objdata` embedded-object carve
- Static single-layer decode pass (base64 / hex / StrReverse)
- VBA stomping detection rule
- Equation Editor exploit rules (CVE-2017-11882 / CVE-2018-0802)
- Intent heuristics rules (LOLBin / WMI / PowerShell / evasion)
- mraptor-style autoexec∧write∧execute maldoc heuristic
- olevba suspicious-keyword maldoc tier rules
- RTF evasion hardening (DDE, objupdate, hex-obfuscation tolerance)
- VBA Chr()/concat/Replace/Xor constant-folding in extractor
- Dir-stream robustness hardening + fuzz seeds
- Opt-in `/debug/pprof` endpoint behind `YARAD_PPROF`
- Dual-token rotation support (`YARAD_TOKEN_NEXT`, comma-separated)
- Bounded top-match counter exposed in `/version`
- Redis/circuit-breaker state surfaced in `/ready` (degraded vs. down)
- Rule-source provenance in `yarad info` and `/version` manifest
- Reload fingerprint delta: tracks previous fingerprint across rule reloads
- Optional token mode (open scanner) with hardened `yarad-scan` client

### Changed
- libyara static build optimized with `-O2`, LTO, and `NDEBUG`
- Extracted streams deduplicated before YARA scan (reduces redundant work)

### Fixed
- RTF control-symbol parser edge cases (whitespace, fake groups, `\bin`)
- `strfold` doubled-quotes regression

### CI
- Trivy image scan + SBOM generation on release
- Zizmor GitHub Actions hardening scanner
- Semgrep scan (non-blocking)
- Monthly rule-bundle audit job
- Monthly benchmark regression job
- Luacheck Lua linting for rspamd plugin
- Scanner and extractor benchmarks
- Fast per-PR gate split from monthly deep checks; full Go + libyara layer caching

---

## [0.10.0] — 2026-05-28

### Added
- PDF pre-extraction (inflate FlateDecode object streams)
- LNK shell-link parsing (surface command-line arguments)
- Archive member extraction (zip/tar-family)
- MSI/OLE package embedded-object extraction
- OneNote section/page content extraction
- Lean CGO-free `yarad-scan` client for Sieve / Dovecot LDA
- CLI subcommands: `local scan`, `check-rules`, `extract`
- Rules cache: seed-on-startup with self-heal
- `generate-rules.sh` + rules-export CI stage (publish `.yac` to `rules-current` release)
- Manifest-driven `fetch-rules` cache update
- abuse.ch feed persistence to cache with warm-start
- Rules provenance: `yarad info` + `/version` manifest + help text

### Changed
- Reverted disk-image container extraction (ISO9660 / UDF — reliability concerns)

---

## [0.5.0] — 2026-04-30

### Added
- OLE/OOXML macro pre-extraction with observability and perf hardening
- `/ready` and `/version` endpoints; reload metrics
- Graceful shutdown; CI scanners
- URLhaus malware-URL lookup + optional `/metrics` auth
- `YARAD_RULE_DENYLIST` to drop public-ruleset noise rules
- Rule source-file + URLhaus URL surfaced in match output
- Tiered YARA scoring — per-category rspamd symbols instead of one flat weight

### Fixed
- Scan slot released before cache PUT (Redis L2 SET no longer holds a scan slot)
- Split admit/scan gates, ctx cancellation, OLE guardrails
- Aligned timeout defaults: `BACKEND_TIMEOUT` 6→1 s, `SCAN_TIMEOUT` 10→8 s

[Unreleased]: https://github.com/eilandert/rspamd-yarad/compare/main...HEAD
[0.10.0]: https://github.com/eilandert/rspamd-yarad/releases/tag/v0.10.0
[0.5.0]: https://github.com/eilandert/rspamd-yarad/releases/tag/v0.5.0
