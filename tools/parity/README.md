# Reproducible detection baseline

This initial harness runs six generated inert fixtures through the production
Mailstrix scanner. It accepts caller-owned corpus directories, but **arbitrary
external corpora are integrity-checked only, never scanned**. The executable
allowlist is computed from the generator's bytes, not trusted manifest claims.

Oletools, olefy and ClamAV are not run. Their immutable pins and adapters remain
pending. This baseline establishes selected indicator expectations; it does not
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
deadline and memory isolation are prerequisites for future external execution.

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
varies. Immutable binary/libyara/comparator identity and versioned semantic
oletools mappings are still needed before claiming a reproducible cross-tool
baseline; the current report explicitly records all comparators as not run.

## Validation

```sh
go test -race ./tools/parity
go test ./tools/parity -run TestSyntheticScannerBaseline -count=1
```

These tests run in the existing Docker CI `go test -race -tags yara_static ./...`
stage. They exercise generation twice, strict manifests, integrity/containment,
deduplication, explicit confusion matrices, missing observations and the actual
scanner against the shipped PDF rule. Public CI uses only generated inert bytes.
The complete external-corpus harness, oracle pins, cross-tool parity/ClamAV-only
metrics and representative non-regression thresholds remain unfinished.
