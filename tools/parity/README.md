# Reproducible detection baseline

This initial harness runs six generated inert fixtures through the production
Mailstrix scanner. Its `run` command accepts caller-owned corpus directories, but
**arbitrary external corpora are integrity-checked only, never scanned by
Mailstrix**. The executable
allowlist is computed from the generator's bytes, not trusted manifest claims.

The separate opt-in `compare` command runs pinned oletools and olefy against local
Office inputs in isolated containers. Neither runs during `generate`, `check` or
`run`. ClamAV remains unimplemented. This baseline establishes selected indicator
expectations; it does not
measure real-world precision, prove oletools parity or replace ClamAV.

## Run

From the [Mailstrix repository](../../README.md), with its Go toolchain and
libyara development files installed:

```sh
go build -o /tmp/mailstrix-parity ./tools/parity
/tmp/mailstrix-parity generate -out /tmp/mailstrix-synthetic-v1
/tmp/mailstrix-parity check \
  -manifest /tmp/mailstrix-synthetic-v1/manifest.json \
  -corpus-root /tmp/mailstrix-synthetic-v1
/tmp/mailstrix-parity run \
  -manifest /tmp/mailstrix-synthetic-v1/manifest.json \
  -corpus-root /tmp/mailstrix-synthetic-v1 -rules docker/local-rules
```

Generation requires a new destination and leaves a partial directory on failure.
Fixtures and the manifest are reproducible under the pinned Go toolchain; archive
timestamps, entry ordering and personal data are fixed. No acquisition command,
network feed, credential, external payload or malware corpus is used.

`run` emits report-v1 JSON to stdout and a short human summary to stderr. Exit 0
means every explicit label passed and every unique sample completed; exit 1 means
a labelled regression or incomplete scan; exit 2 means invalid input or setup.
`check` exit 0 means schema/provenance fields and all file checksums validated;
it does not certify the truth of external provenance or labels.

The rules directory is trusted operator input and must remain unchanged during
the run. Scanner effort is fixed at 10, feeds and password guessing are disabled,
and scan metadata uses a fixed filename for each format. Eight seconds is the
scanner's budget, not an enforced subprocess deadline. Over-budget results,
parser/raw errors and scanner diagnostics prevent a passing verdict. Whole-process
deadline and memory isolation remain prerequisites for future external Mailstrix
execution.

## Manifest v1

`generate` writes a complete example. The typed definitions and validator in
[manifest.go](manifest.go) are the executable schema: every JSON field is required
with exact spelling; unknown fields, duplicate keys, trailing data and unsupported
versions are rejected. Limits: 4 MiB manifest, depth 16, 10,000 samples/sources,
16 MiB per sample, and 256 explicit symbol labels per sample.

- Manifest: `schema_version=1`, `corpus_id`, positive `revision`, `sources`,
  `samples`.
- Source: `id`, `kind`, `reference`, immutable `revision`, `license`,
  `license_evidence`, `redistribution`, `privacy`, `review_ref`.
- Sample: `id`, `source_id`, lowercase `sha256`, `size_bytes`, relative `locator`,
  `partition`, `split`, `group_id`, `format`, `input_unit`, `truth`.
- Truth: `class`, `basis`, `evidence_ref`, `review_ref`, `symbols`.
- Symbol label: `symbol` containing `namespace` and `rule`;
  `expected=present|absent`.

Partitions are `synthetic-clean`, `synthetic-indicator`, `external-clean`,
`external-threat` and `external-unlabelled`. Source kind is `generated|external`;
redistribution is `approved|local-only|unknown`; privacy is
`synthetic|reviewed-public|restricted|unknown`. Public fixtures require generated,
approved, synthetic provenance. External benign/malicious labels require independent
evidence; unknown provenance is not permission to redistribute. A license name
alone is not a review: retain exact source revision, applicable license text and
the provenance/privacy review reference in the caller's own records.

Splits are `regression|calibration|holdout`. Related wrappers, decoded members and
generator variants share a group and cannot cross splits. Each sample names the
exact bytes presented for evaluation; no implicit archive decryption or extraction
changes the comparison unit. Formats are `mime|office|pdf|html|image`, input units
`message|file`. Corpus files must be stable regular files in a caller-controlled
directory; do not mutate the corpus concurrently with validation or scanning.

Identical SHA-256 bytes are counted once, with additional references counted as
duplicates. Aliases may vary only in ID, locator and source; conflicting labels,
partition, format or split reject the manifest. All alias references are checked.
No fuzzy deduplication or automatic family inference is performed.

## Ground truth

The generated clean cases cover MIME text, a minimal OOXML document, PDF, HTML
and PNG. A second PDF contains only `/OpenAction` JavaScript expression `0`, an
inert structural positive. Construction labels assert `PDF_OpenAction_JS` for
that case and explicitly absent labels for the other six shipped PDF indicators;
the five clean cases explicitly lack all seven. These labels describe indicator
presence, not maliciousness. All six fixtures are benign and locally authored
under the repository's MIT license. No third-party binary fixture is imported.

The initial expected matrix is **1 TP and 41 TN**, with zero FP/FN and six
completed scans, scoped to these seven indicators and these six files. Each
namespace/rule pair is distinct. Unlisted symbols remain unknown; new unlabelled
matches are counted separately and cannot inflate precision. Adding labels needs
review independent of the current scanner output. The production scanner and
shipped rules supply observations; manifest labels never supply matches.

Reports separate `synthetic-clean` and `synthetic-indicator`, and provide per-symbol
TP/FP/FN/TN, excluded counts, nullable precision and recall. Missing, integrity,
timeout, error and indeterminate outcomes are not negative verdicts. They are
excluded from ratios and independently fail the gate. No raw hit-rate is called
precision. Reported real-world precision is `null`, and real-world thresholds are
explicitly unmeasured. Timing is diagnostic, with no performance threshold.

## Privacy and reproducibility

Keep restricted manifests, hashes, paths, evidence and payloads outside Git.
Private hashes can themselves disclose membership; only publish them after an
explicit privacy review. The aggregate report omits sample IDs, hashes, locators,
message content, matched metadata and raw scanner output. Its manifest digest
identifies the exact local input and should also be reviewed before publication.

Reports record the generator revision, Go version, platform, build revision/dirty
state, rules fingerprint and fixed configuration. Elapsed time intentionally
varies. Immutable Mailstrix binary/libyara identity and versioned semantic
oletools-to-Mailstrix mappings are still needed before claiming a reproducible
cross-tool baseline; the `run` report explicitly records all comparators as
not run.

## Opt-in native Office comparison

`compare` requires Linux/amd64, Docker on the local `/var/run/docker.sock`, and
the exact image in [comparator-pins.json](comparator-pins.json) already present.
It never pulls or builds images and ignores remote Docker contexts/host settings.
Provision this optional test image separately; it is not a Mailstrix runtime,
build or release dependency. The registry pins the OCI index and its linux/amd64
platform manifest. Docker selects that platform from the pinned index; the
reported platform manifest is the registry pin, not a fresh registry query.

```sh
/tmp/mailstrix-parity compare \
  -manifest /tmp/mailstrix-synthetic-v1/manifest.json \
  -corpus-root /tmp/mailstrix-synthetic-v1 -adapter both
```

`-adapter` accepts `oletools`, `olefy` or `both` (default). The six-fixture example
returns exit **1**: only its Office file is supported and the other five inputs
are explicitly `unsupported`. To compare an Office-only corpus, supply a valid
v1 manifest containing just those samples. Caller-owned local external Office
bytes are allowed here after integrity checks; `run` retains its generator
allowlist. No corpus acquisition, network feed or upload is performed.

Each unique sample is passed on stdin into a fresh non-networked container;
no corpus directory is mounted. Both adapters use `olevba -a -j -l error`.
The olefy adapter starts the pinned daemon and connects to its loopback TCP
listener **inside** that container; no port is published. It retains olefy's
500-byte minimum and rejects all ERROR-level daemon diagnostics, including
nonzero child exits that olefy can otherwise hide behind valid-looking JSON.
The pinned olefy regex's Python 3.13 `invalid escape sequence` SyntaxWarning is
filtered at daemon startup; runtime diagnostics remain failures.
The direct adapter also rejects nonzero exits and any stderr. Raw tool output,
error text, macro code, names and keywords are discarded before reporting.

Before each scan, the embedded runner checks the installed oletools distribution
version and hashes `/usr/local/bin/olefy.py` against the compiled registry.
Missing/mismatched identity never yields a completed observation. The image was
qualified as oletools 0.60.2 and the pinned upstream olefy source on 2026-09-07.
Version/file checks qualify these identities, not every transitive dependency;
the immutable image digest fixes the remaining bytes. Source references:
[oletools release](https://github.com/decalage2/oletools/releases/tag/v0.60.2),
[PyPI wheel digest](https://pypi.org/pypi/oletools/0.60.2/json), and
[olefy commit](https://github.com/HeinleinSupport/olefy/commit/9ac23a718ed1e70a770df15faf6cb9660d1cba17).
Oletools core is BSD-2-Clause (bundled portions retain their licenses); olefy is
Apache-2.0. This repository neither vendors nor redistributes the image; an image
redistribution still needs aggregate license/SBOM review.

Isolation: UID/GID 65534, read-only root, 64 MiB noexec/nosuid tmpfs, no
capabilities, no-new-privileges, 32 processes, one CPU, 256 MiB memory including
swap, and no Docker log storage. Input is at most 16 MiB. Python bounds the scan
to eight seconds and each temporary file to 16 MiB plus one byte. Raw responses
are capped at 1 MiB; host stdout/stderr each at 2 MiB. The host bounds each
container invocation to 30 seconds and forcibly removes its exact unique
container after failures, with up to two five-second cleanup checks. A failed
cleanup is reported as `cleanup_error`; investigate the local daemon before
continuing. It stops all later adapter launches in that report, recording their
observations as `not_run` while retaining completed observations. Ordinary parser
or unsupported-format failures do not stop later samples. These limits bound
each input, not the whole corpus's elapsed time.
Docker and the host kernel are trusted isolation infrastructure.

The separate comparison schema reports aggregate native Office format, macro
presence and category-presence counts (`AutoExec`, `Suspicious`, `IOC` and decoded
string categories). It accepts exactly one complete file record with the pinned
metadata header; logs, malformed JSON, errors, missing fields, nested/decrypted
comparison units and unsupported types/categories cannot count as no-macro
observations. `without_macros` means only that olevba completed with an empty
macro list; it never means benign. Manifest malicious/benign labels and Mailstrix
symbols are not used as an oracle for these categories.

Exit 0 means all requested native observations completed and, when both adapters
ran, their normalized observations agreed. Exit 1 includes unsupported, missing,
integrity, identity, timeout, resource, execution, cleanup or parser failures and
interface differences; exit 2 is invalid CLI/manifest or report I/O. Agreement
counts omit every incomplete pair. **Olefy and direct oletools share one engine**:
agreement tests the interfaces, not independent ground truth, real-world precision
or Mailstrix parity. The report includes compiled pins and their hash, qualified
inner identities, runner hash, adapter schema, platform and fixed budgets, while
omitting sample IDs, paths, hashes, content and raw diagnostics. The manifest
digest still needs privacy review before publication.

## Validation

```sh
go test -race ./tools/parity
go test ./tools/parity -run TestSyntheticScannerBaseline -count=1
python3 -B -m unittest discover -s tools/parity -p 'comparator_runner_test.py'
```

These tests run in the existing Docker CI `go test -race -tags yara_static ./...`
stage. They exercise generation twice, strict manifests, integrity/containment,
deduplication, explicit confusion matrices, missing observations and the actual
scanner against the shipped PDF rule. Public CI uses only generated inert bytes.
Go subprocess tests run their own test binary as a fake Docker client, exercising
cancellation, bounded pipes, exact-container cleanup and report exit codes without
a daemon. The CI scanner job also runs standard-library Python tests with mocked
identity, subprocess and socket providers for protocol framing, diagnostics,
timeouts, input/output bounds and process cleanup. These tests do not require
oletools, olefy, an image or an external corpus.
The complete external-corpus harness, cross-tool parity/ClamAV-only
metrics and representative non-regression thresholds remain unfinished.
