package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"
)

const corpusMapping = "ooxml-vba-observations-v1"
const corpusSchema = "mailstrix-corpus-comparison-v1"
const maxPolicyBytes = 64 << 10
const maxReceiptBytes = 64 << 20

var corpusVBASymbol = symbol{"oleid_indicators.yara", "OLEID_OOXML_VBA_Present"}

type comparisonScope struct {
	Format    string `json:"format"`
	InputUnit string `json:"input_unit"`
}

// Policy is an explicitly reviewed observation predicate, never corpus truth.
// Unmapped hits remain unknown even when another hit belongs to Positive.
// Negative requires Closed, exact rules identity, and explicit applicability.
type corpusPolicy struct {
	SchemaVersion          int               `json:"schema_version"`
	ID                     string            `json:"id"`
	ReviewRef              string            `json:"review_ref"`
	RulesFingerprintSHA256 string            `json:"rules_fingerprint_sha256"`
	Mapping                string            `json:"mapping"`
	Scope                  []comparisonScope `json:"scope"`
	Closed                 bool              `json:"closed"`
	Positive               []symbol          `json:"positive"`
	Neutral                []symbol          `json:"neutral"`
}

func decodeCorpusPolicy(raw []byte) (corpusPolicy, error) {
	var p corpusPolicy
	if len(raw) > maxPolicyBytes || isolatedJSON(raw, &p) != nil || p.SchemaVersion != 1 ||
		!identifier.MatchString(p.ID) || len(p.ReviewRef) == 0 || len(p.ReviewRef) > 512 || strings.ContainsAny(p.ReviewRef, "\x00\r\n") ||
		!sha256Text(p.RulesFingerprintSHA256) || p.Mapping != corpusMapping || len(p.Scope) == 0 || len(p.Scope) > 10 ||
		len(p.Positive) == 0 || p.Neutral == nil || len(p.Positive)+len(p.Neutral) > 256 {
		return p, errors.New("invalid versioned comparison policy")
	}
	seenScope := map[comparisonScope]bool{}
	for _, scope := range p.Scope {
		if seenScope[scope] || !slices.Contains([]string{"mime", "office", "pdf", "html", "image"}, scope.Format) || !slices.Contains([]string{"file", "message"}, scope.InputUnit) {
			return p, errors.New("invalid comparison applicability")
		}
		seenScope[scope] = true
	}
	seen := map[symbol]bool{}
	for _, group := range [][]symbol{p.Positive, p.Neutral} {
		for _, sym := range group {
			if seen[sym] || !identifier.MatchString(sym.Rule) || sym.Namespace != "" && !identifier.MatchString(sym.Namespace) {
				return p, errors.New("invalid or overlapping policy symbols")
			}
			seen[sym] = true
		}
	}
	return p, nil
}

func (p corpusPolicy) decision(s sample, o observation, rulesSHA string) (string, string) {
	if o.Status != "ok" {
		return "unknown", "mailstrix_unavailable"
	}
	if rulesSHA != p.RulesFingerprintSHA256 {
		return "unknown", "rules_identity_mismatch"
	}
	if !slices.Contains(p.Scope, comparisonScope{s.Format, s.InputUnit}) {
		return "unknown", "policy_not_applicable"
	}
	positive := false
	for _, hit := range o.Matches {
		switch {
		case slices.Contains(p.Positive, hit):
			positive = true
		case slices.Contains(p.Neutral, hit):
		default:
			return "unknown", "unmapped_rule_hit"
		}
	}
	if positive {
		return "positive", "known"
	}
	if !p.Closed {
		return "unknown", "open_policy_without_positive"
	}
	return "negative", "known"
}

type corpusContext struct {
	Schema                  string            `json:"schema"`
	ManifestSHA256          string            `json:"manifest_sha256"`
	PolicySHA256            string            `json:"policy_sha256"`
	PolicyID                string            `json:"policy_id"`
	PolicyClosed            bool              `json:"policy_closed"`
	PolicyScope             []comparisonScope `json:"policy_scope"`
	PolicyRulesSHA256       string            `json:"policy_rules_fingerprint_sha256"`
	PolicyPositiveSymbols   int               `json:"policy_positive_symbols"`
	PolicyNeutralSymbols    int               `json:"policy_neutral_symbols"`
	PolicyProvenance        string            `json:"policy_provenance"`
	MailstrixImage          string            `json:"mailstrix_image_id"`
	MailstrixWorker         isolatedIdentity  `json:"mailstrix_worker"`
	MailstrixEnvelopeSHA256 string            `json:"mailstrix_envelope_sha256"`
	OletoolsPins            comparatorPins    `json:"oletools_pins"`
	OletoolsRunnerSHA256    string            `json:"oletools_runner_sha256"`
	ClamAV                  clamIdentity      `json:"clamav"`
	ClamAVScanArgs          []string          `json:"clamav_scan_args"`
	ClamAVEnvelope          string            `json:"clamav_envelope"`
	ClamAVAdapterSHA256     string            `json:"clamav_adapter_sha256"`
	ClamAVBridgeSHA256      string            `json:"clamav_bridge_sha256"`
	Runtime                 isolatedRuntime   `json:"runtime"`
}

type correspondenceReport struct {
	Mapping             string         `json:"mapping"`
	Applicability       string         `json:"applicability"`
	LeftPredicate       string         `json:"mailstrix_predicate"`
	RightPredicate      string         `json:"oletools_predicate"`
	SemanticEquivalence bool           `json:"semantic_equivalence"`
	Cells               map[string]int `json:"cells"`
}

type clamRelationReport struct {
	Definition      string         `json:"definition"`
	Cells           map[string]int `json:"cells"`
	ExcludedReasons map[string]int `json:"excluded_reasons"`
	UniqueNames     map[string]int `json:"unique_detection_names"`
	StaleDatabase   int            `json:"stale_database_observations"`
}

type corpusReport struct {
	Context            corpusContext             `json:"context"`
	Summary            summary                   `json:"mailstrix_labelled_summary"`
	Statuses           map[string]map[string]int `json:"engine_statuses"`
	Correspondence     correspondenceReport      `json:"oletools_correspondence"`
	ClamAVRelation     clamRelationReport        `json:"clamav_relation"`
	Complete           bool                      `json:"all_observations_and_comparisons_known"`
	ElapsedMS          int64                     `json:"elapsed_ms"`
	RealWorldPrecision *float64                  `json:"real_world_precision"`
	Limits             string                    `json:"interpretation_limits"`
}

type mailstrixReceipt struct {
	Status  string   `json:"status"`
	Symbols []symbol `json:"symbols"`
}

type oletoolsReceipt struct {
	Status     string             `json:"status"`
	Format     string             `json:"format"`
	HasMacros  bool               `json:"has_macro_records"`
	Categories []string           `json:"categories"`
	Identity   comparatorIdentity `json:"identity"`
}

type corpusReceipt struct {
	Schema         string           `json:"schema"`
	ContextSHA256  string           `json:"context_sha256"`
	ManifestSHA256 string           `json:"manifest_sha256"`
	SampleSHA256   string           `json:"sample_sha256"`
	Size           int64            `json:"size_bytes"`
	InputUnit      string           `json:"input_unit"`
	Mailstrix      mailstrixReceipt `json:"mailstrix"`
	Oletools       oletoolsReceipt  `json:"oletools"`
	ClamAV         clamObservation  `json:"clamav"`
	PolicyDecision string           `json:"mailstrix_policy_decision"`
}

type corpusObservers struct {
	mailstrix func(sample, []byte) observation
	oletools  func(string, []byte) nativeObservation
	clamav    func(sample, []byte) clamObservation
}

func terminalOletoolsStatus(status string) bool {
	switch status {
	case "ok", "unsupported", "malformed_output", "tool_error", "execution_error", "timeout", "output_limit", "input_error":
		return false
	default:
		return true
	}
}

func terminalMailstrixStatus(status string) bool {
	switch status {
	case "ok", "error", "timeout", "indeterminate", "execution_error", "output_limit", "memory_limit", "malformed_output", "integrity_error":
		return false
	default:
		return true
	}
}

func clamBridgeSetupDiagnostic(err error) string {
	if errors.Is(err, errClamBridgePython) {
		return errClamBridgePython.Error()
	}
	return "ClamAV frozen identity setup failed"
}

func corpusCorrespondence(s sample, left observation, right nativeObservation) string {
	if s.Format != "office" || s.InputUnit != "file" || left.Status != "ok" || right.Status != "ok" || right.Format != "OpenXML" {
		return "unknown"
	}
	return booleanCell(slices.Contains(left.Matches, corpusVBASymbol), right.HasMacros,
		"both", "mailstrix_only", "oletools_only", "neither")
}

func booleanCell(left, right bool, both, leftOnly, rightOnly, neither string) string {
	switch {
	case left && right:
		return both
	case left:
		return leftOnly
	case right:
		return rightOnly
	default:
		return neither
	}
}

type receiptWriter struct {
	out       io.Writer
	remaining int
}

func openCorpusReceipts(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- caller explicitly selects the new local receipt path; O_EXCL prevents replacement.
}

func (w *receiptWriter) write(value any) error {
	if w.out == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw)+1 > w.remaining {
		return errors.New("local receipts exceed 64 MiB")
	}
	raw = append(raw, '\n')
	n, err := w.out.Write(raw)
	w.remaining -= n
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}

var readCorpusSample = readSample

// Caller-owned bytes are joined only within this pass. All aliases are checked
// before any sample reaches any engine, then each unique input is re-read and
// hash checked immediately before use. Retained truth-scoring matches are limited
// to manifest labels; full symbol/detection observations stream only to opt-in
// private receipts. Cross-tool agreement never supplies a truth label.
func compareCorpusAll(root *os.Root, m manifest, p corpusPolicy, context corpusContext, observers corpusObservers, receipts io.Writer) (corpusReport, error) {
	started := time.Now()
	r := corpusReport{Context: context, Complete: true,
		Statuses: map[string]map[string]int{"mailstrix": {}, "oletools": {}, "clamav": {}},
		Correspondence: correspondenceReport{Mapping: corpusMapping, Applicability: "office/file with completed native OpenXML classification",
			LeftPredicate:  "observed oleid_indicators.yara:OLEID_OOXML_VBA_Present symbol; intended decoded-VBA marker indicator, not extraction attestation",
			RightPredicate: "oletools native OpenXML format and at least one macro record, including records with null code",
			Cells:          map[string]int{"both": 0, "mailstrix_only": 0, "oletools_only": 0, "neither": 0, "unknown": 0}},
		ClamAVRelation: clamRelationReport{Definition: "ClamAV unique = named non-heuristic detection with applicable known-negative Mailstrix policy observation; neither side is benign/malware ground truth",
			Cells: map[string]int{"both_positive": 0, "mailstrix_only": 0, "clamav_unique": 0, "both_negative": 0, "unknown": 0}, ExcludedReasons: map[string]int{}, UniqueNames: map[string]int{}},
		Limits: "explicit independent symbol labels only; observational correspondence does not establish semantic equivalence; olefy and oletools are one engine, direct oletools used here; invocation completion is not exhaustive extraction; real-world precision/representative thresholds unmeasured; source checksums are identity not attestation; Go-parent/kernel death outside bridge cleanup guarantee"}
	w := receiptWriter{receipts, maxReceiptBytes}
	contextJSON, err := json.Marshal(context)
	if err != nil {
		return r, err
	}
	contextSHA := digest(contextJSON)
	if err := w.write(struct {
		Schema     string        `json:"schema"`
		ContextSHA string        `json:"context_sha256"`
		Context    corpusContext `json:"context"`
	}{"mailstrix-local-corpus-context-v1", contextSHA, context}); err != nil {
		return r, err
	}
	invalid := map[string]bool{}
	for _, s := range m.Samples {
		if _, err := readCorpusSample(root, s); err != nil {
			invalid[s.SHA256] = true
		}
	}
	observations := map[string]observation{}
	unlabelled := 0
	stopped := false
	for _, s := range m.Samples {
		if _, seen := observations[s.SHA256]; seen {
			continue
		}
		left := observation{Status: "not_run"}
		right := nativeObservation{Status: "not_run"}
		clam := clamObservation{Status: "not_run", Detections: []string{}, Diagnostics: []clamDiagnostic{}}
		switch {
		case stopped:
		case invalid[s.SHA256]:
			left.Status, right.Status, clam.Status = "integrity_error", "integrity_error", "integrity_error"
		case len(invalid) != 0:
			// One invalid alias invalidates the corpus preflight. Unaffected
			// groups remain unobserved; no parser receives a partial corpus.
		default:
			data, readErr := readCorpusSample(root, s)
			if readErr != nil {
				left.Status, right.Status, clam.Status = "integrity_error", "integrity_error", "integrity_error"
				break
			}
			left = observers.mailstrix(s, data)
			if terminalMailstrixStatus(left.Status) {
				stopped = true
				break
			}
			right.Status = "unsupported"
			if s.Format == "office" && s.InputUnit == "file" {
				right = observers.oletools("oletools", data)
				if terminalOletoolsStatus(right.Status) {
					stopped = true
					break
				}
			}
			clam = observers.clamav(s, data)
			if clam.Terminal || clam.Status == "bridge_error" {
				stopped = true
			}
		}
		r.Statuses["mailstrix"][left.Status]++
		r.Statuses["oletools"][right.Status]++
		r.Statuses["clamav"][clam.Status]++
		cell := corpusCorrespondence(s, left, right)
		if context.MailstrixWorker.RulesFingerprintSHA256 != p.RulesFingerprintSHA256 {
			cell = "unknown"
		}
		r.Correspondence.Cells[cell]++
		decision, reason := p.decision(s, left, context.MailstrixWorker.RulesFingerprintSHA256)
		clamKnown := clam.Status == "no_detection" || clam.Status == "detection"
		if !clamKnown || decision == "unknown" {
			r.ClamAVRelation.Cells["unknown"]++
			if !clamKnown {
				reason = "clamav_" + clam.Status
			}
			r.ClamAVRelation.ExcludedReasons[reason]++
		} else {
			relation := booleanCell(decision == "positive", clam.Status == "detection", "both_positive", "mailstrix_only", "clamav_unique", "both_negative")
			r.ClamAVRelation.Cells[relation]++
			if relation == "clamav_unique" {
				for _, name := range clam.Detections {
					r.ClamAVRelation.UniqueNames[name]++
				}
			}
		}
		if clam.DatabaseStale {
			r.ClamAVRelation.StaleDatabase++
		}
		if left.Status != "ok" || right.Status != "ok" || !clamKnown || decision == "unknown" || cell == "unknown" {
			r.Complete = false
		}
		if err := w.write(corpusReceipt{"mailstrix-local-corpus-observation-v1", contextSHA, context.ManifestSHA256, s.SHA256, s.Size, s.InputUnit,
			mailstrixReceipt{left.Status, append([]symbol{}, left.Matches...)},
			oletoolsReceipt{right.Status, right.Format, right.HasMacros, append([]string{}, right.Categories...), right.Identity}, clam, decision}); err != nil {
			return r, err
		}
		kept := observation{Status: left.Status}
		labelled := map[symbol]bool{}
		for _, label := range s.Truth.Symbols {
			labelled[label.Symbol] = true
		}
		seen := map[symbol]bool{}
		for _, hit := range left.Matches {
			if seen[hit] {
				continue
			}
			seen[hit] = true
			if labelled[hit] {
				kept.Matches = append(kept.Matches, hit)
			} else if left.Status == "ok" {
				unlabelled++
			}
		}
		observations[s.SHA256] = kept
	}
	r.Summary = summarize(m, observations)
	r.Summary.UnlabelledMatches = unlabelled
	r.ElapsedMS = time.Since(started).Milliseconds()
	reportJSON, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	err = w.write(struct {
		Schema    string `json:"schema"`
		Count     int    `json:"unique_samples"`
		Complete  bool   `json:"complete"`
		ReportSHA string `json:"report_sha256"`
	}{"mailstrix-local-corpus-end-v1", len(observations), r.Complete, digest(reportJSON)})
	return r, err
}

func corpusCompareCLI(args []string, stdout, stderr io.Writer) (exitCode int) {
	flags := flag.NewFlagSet("compare-corpus", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "v1 corpus manifest")
	rootPath := flags.String("corpus-root", "", "caller-owned corpus directory")
	image := flags.String("engine-image", "", "immutable local Mailstrix image ID")
	qualification := flags.String("clamav-qualification", "", "local frozen ClamAV qualification directory")
	variant := flags.String("clamav-variant", "engine", "engine or explicitly private inert private-engine")
	policyPath := flags.String("policy", "", "explicit reviewed v1 observation policy")
	receiptPath := flags.String("local-receipts", "", "opt-in sensitive local JSONL, new 0600 file only")
	if flags.Parse(args) != nil {
		return 2
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || flags.NArg() != 0 || *manifestPath == "" || *rootPath == "" || *image == "" || *qualification == "" || *policyPath == "" || !slices.Contains([]string{"engine", "private-engine"}, *variant) {
		printError(stderr, "compare-corpus requires Linux/amd64, manifest, corpus-root, engine-image, clamav-qualification and policy")
		return 2
	}
	m, hash, err := loadManifest(*manifestPath)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	file, err := openCorpusConfig(*policyPath)
	if err != nil {
		printError(stderr, "cannot open comparison policy")
		return 2
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPolicyBytes {
		_ = file.Close()
		printError(stderr, "comparison policy must be a bounded regular file")
		return 2
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		printError(stderr, "comparison policy must be a bounded regular file")
		return 2
	}
	p, err := decodeCorpusPolicy(raw)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	root, err := os.OpenRoot(*rootPath)
	if err != nil {
		printError(stderr, "cannot open corpus root")
		return 2
	}
	defer func() { _ = root.Close() }()
	d := isolatedDocker{image: *image, diagnostics: stderr}
	if err := d.setup(); err != nil {
		printError(stderr, err)
		return 2
	}
	bridge, err := prepareClamBridge(stderr)
	if err != nil {
		printError(stderr, "cannot prepare ClamAV bridge")
		return 2
	}
	defer func() {
		if err := bridge.close(); err != nil {
			printError(stderr, "ClamAV bridge temporary module cleanup failed")
			exitCode = 2
		}
	}()
	if err := bridge.setup(*qualification, *variant, hash); err != nil {
		printError(stderr, clamBridgeSetupDiagnostic(err))
		return 2
	}
	pins, err := pinnedComparators()
	if err != nil {
		printError(stderr, "comparator pins unavailable")
		return 2
	}
	context := corpusContext{Schema: corpusSchema, ManifestSHA256: hash, PolicySHA256: digest(raw), PolicyID: p.ID,
		PolicyClosed: p.Closed, PolicyScope: p.Scope, PolicyRulesSHA256: p.RulesFingerprintSHA256,
		PolicyPositiveSymbols: len(p.Positive), PolicyNeutralSymbols: len(p.Neutral), PolicyProvenance: "caller-provided review_ref bound by policy hash, not an attestation",
		MailstrixImage: d.image, MailstrixWorker: d.identity, MailstrixEnvelopeSHA256: digest([]byte(isolatedEnvelope)),
		OletoolsPins: pins, OletoolsRunnerSHA256: digest([]byte(comparatorRunner)), ClamAV: bridge.identity, ClamAVScanArgs: bridge.scanArgs,
		ClamAVEnvelope: clamEnvelope, ClamAVAdapterSHA256: digest(clamavAdapterSource), ClamAVBridgeSHA256: digest(clamavBridgeSource), Runtime: d.runtime}
	var receipt *os.File
	var writer io.Writer
	if *receiptPath != "" {
		receipt, err = openCorpusReceipts(*receiptPath)
		if err != nil {
			printError(stderr, "local receipts require a new file; none overwritten")
			return 2
		}
		writer = receipt
	}
	r, err := compareCorpusAll(root, m, p, context, corpusObservers{d.observe, (dockerComparator{pins: pins}).observe, bridge.observe}, writer)
	if receipt != nil {
		err = errors.Join(err, receipt.Close())
	}
	if err != nil {
		printError(stderr, "local receipt write failed; receipt incomplete")
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if encoder.Encode(r) != nil {
		printError(stderr, "report write failed")
		return 2
	}
	if _, err := fmt.Fprintf(stderr, "corpus comparison: %d unique samples; complete=%t; correspondence is not equivalence; relation is not accuracy\n", r.Summary.UniqueSamples, r.Complete); err != nil {
		return 2
	}
	if !r.Complete || !r.Summary.Pass {
		return 1
	}
	return 0
}
