# Changelog

All notable changes to Mailstrix are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Before pushing the next `vX.Y.Z` tag, rename the `## [Unreleased]` heading to
`## [X.Y.Z] - YYYY-MM-DD` (the date is optional) and start a new empty
`## [Unreleased]` above it, so exactly one non-empty section matches the tag. The
release workflow publishes that section as the GitHub release notes and stops
before building if it is missing, duplicated or empty, or if the tag is not
SemVer.

## [Unreleased]

## [1.3.0] - 2026-10-29

Changes since v1.2.0.

### Known caveats

- The live end-to-end proof that a deployed `strixd` loads published rule
  marker artifacts has not been performed for this release; the marker path is
  covered by CI and the release image test only.
- A full independent Opus-class code audit of this release was not performed.

### Fixed

- `MAILSTRIX_MAX_CONCURRENT=auto` and the over-subscription warning now honor CPU
  limits of nested/systemd cgroups (resolved from `/proc/self/cgroup` and
  `mountinfo`, most restrictive level wins), not only the fixed container paths.

### Changed (breaking)

- `strixd serve` refuses wildcard ICAP and clamd TCP binds unless
  `MAILSTRIX_ALLOW_WILDCARD_BIND=1` is set (#496). See "Upgrading from v1.2.0"
  in the README.
- Rule-bundle URLs must be `https`; plain `http` needs an explicit opt-in and
  an https-to-http redirect is always refused (#441, #482). See "Upgrading
  from v1.2.0" in the README.

### Changed

- `MAILSTRIX_MAX_CONCURRENT=auto` now respects the container's cgroup CPU limit
  (v2 `cpu.max`, v1 `cfs_quota_us`/`cfs_period_us`), rounded up, minimum 1,
  instead of always using the host CPU count.

### Security

Severity wording follows the pull request. "Hardening" means no working exploit
was demonstrated. Entries marked "v1.2.0" were verified against the v1.2.0 tag.

- Release binaries are hardened ELF executables. strixd and yarac are PIE
  with full RELRO, stack protector and `_FORTIFY_SOURCE=2`. strix-scan and
  strix-milter stay static non-PIE (portable to any libc) and are guarded for
  static linking and a non-executable stack. `scripts/elf-hardening.py` fails
  the binary build on a regression. The rebuilt libyara changes its archive
  hash, so strixd skips marker trees built against an earlier libyara and
  scans with the full main ruleset (same detection, slower); rebuild marker
  trees against this release to keep marker-scan speed. Hardening; affected:
  v1.2.0.
- ICAP request parsing is bounded (#343, #345). In v1.2.0 the request line,
  headers and trailer lines had no length limit and the connection count was
  uncapped, so an unauthenticated client could exhaust memory with one endless
  line or many slow connections. Affected: v1.2.0.
- ICAP bodies are read only after an admission slot is held (#535, #539).
  Before, waiting connections buffered full bodies, so memory could exceed the
  `MaxInflight` limit under load. Affected: v1.2.0.
- ICAP framing is validated strictly (#571, #574). Duplicate or conflicting
  `Encapsulated` fields and malformed chunk extensions could be read as a
  clean verdict, and a crafted chunk size could overflow the body-size check
  (`int64(len(out))+size`) and bypass `MaxBody`. Affected: v1.2.0.
- A scan without a complete verdict is no longer reported as clean (#399,
  #566). An extractor panic, a malformed scanner reply or a signalled
  SpamAssassin child could look like a clean scan, so a crafted file could
  pass. v1.2.0 has no incomplete-scan signal. Affected: v1.2.0.
- Decode de-duplication confirms 64-bit hash hits with a byte compare (#440).
  v1.2.0 skipped a blob that only shared an FNV-1a hash with an earlier one,
  so a decoy could hide a payload from YARA. Shown only with a
  forced-collision test seam, so treat it as hardening. Affected: v1.2.0.
- Rule updates are authenticated (#441, #482, #442, #489, #517, #520, #521).
  The updater now requires https, refuses downgrades, requires an ed25519
  signature on the rules manifest from a key compiled into the binary (with a
  pinned successor key), and refuses empty or sharply smaller bundles. v1.2.0
  trusted whoever served the manifest over HTTPS, which controls the YARA
  bytecode strixd loads. Affected: v1.2.0.
- The rolling `rules-current` publisher is serialized with a lease and
  authenticates its previous state and version records (#592). Overlapping
  hosts could allocate the same version, and an unauthenticated previous
  manifest was trusted. This concerns the publishing pipeline, not the
  runtime.
- 7z LZMA and LZMA2 dictionary sizes are capped at 8 MiB and 64 MiB (#491,
  #499). A hostile archive could request a very large dictionary. v1.2.0
  applied no such cap. Hardening. Affected: v1.2.0.
- Scan cache keys length-prefix per-request password candidates (#463). In
  v1.2.0 the key joined them with a NUL byte, so different lists could share a
  key. Reachable only by direct `ScanMeta.PWCandidates` callers. Hardening.
  Affected: v1.2.0.
- Public deployment examples no longer run unauthenticated (#578). The README
  used `MAILSTRIX_TOKEN=changeme` with a publicly published port, which
  exposed CPU-heavy scans to anyone who could reach it. Examples now use a
  file-backed token and bind to `127.0.0.1`. Affected: v1.2.0 documentation.
- The profiling helper sends its bearer token on standard input (#566). In
  v1.2.0 it was in the `curl` argument list and visible to local users through
  the process table (`docker/pprof-capture.sh`). Affected: v1.2.0.
- Extraction marker provenance and per-format work budgets for OneNote, MSG,
  MSI, OLEPackage, PPT and TNEF are enforced (#591). Untrusted content can no
  longer supply extractor-only markers. Hardening.
- Go toolchain is pinned to 1.26.10 for the x509 certificate-validation fix
  GO-2026-6809 (#561), after an earlier bump for stdlib findings and a
  `golang.org/x/net` HTTP/2 HPACK race, GO-2026-6617 (#510). v1.2.0 does not
  depend on `golang.org/x/net`; its toolchain exposure was not assessed.
- RAR members stored as plaintext after an encrypted member are scanned
  (#594). Once a password from the request cracked the archive, the re-walk
  skipped every plaintext member, but the first walk had only scanned those
  before the first encrypted one. A decoy encrypted member followed by a
  plaintext payload returned a clean verdict. Major. Affected: v1.2.0.
- A refused solid RAR archive or member makes the scan incomplete instead of
  clean (#594). Solid RAR is still not decoded; the refusal now records the
  `rar-solid` cap. Major. The solid refusal was added after v1.2.0, so this
  gap is in no release; v1.2.0's solid handling was not assessed.
- `golang.org/x/net` is v0.62.0 for two `x/net/html` advisories (#593):
  quadratic text-node coalescing, GO-2026-6860, and an incomplete ancestor
  namespace check when rendering raw text, GO-2026-6866. The HTML extractor
  parses untrusted mail HTML with this package since #500. v1.2.0 does not
  depend on `golang.org/x/net`, so no released version is affected.
- MIME header probing is bounded and an unfinished header block is marked
  incomplete instead of clean (#585). The MIME walker arrived after v1.2.0
  (#404), so no released version is affected.
