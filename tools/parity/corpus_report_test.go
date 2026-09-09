package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func comparisonPolicyFixture() corpusPolicy {
	return corpusPolicy{SchemaVersion: 1, ID: "inert-policy-v1", ReviewRef: "inert-test-review",
		RulesFingerprintSHA256: digest([]byte("inert rules")), Mapping: corpusMapping,
		Scope: []comparisonScope{{"office", "file"}}, Closed: true,
		Positive: []symbol{{"inert.yara", "Positive"}}, Neutral: []symbol{corpusVBASymbol}}
}

func TestCorpusPolicyExplicitUnknowns(t *testing.T) {
	p := comparisonPolicyFixture()
	s := sample{Format: "office", InputUnit: "file"}
	for _, tc := range []struct {
		name             string
		edit             func(*corpusPolicy, *sample, *observation, *string)
		decision, reason string
	}{
		{"closed negative", func(*corpusPolicy, *sample, *observation, *string) {}, "negative", "known"},
		{"positive", func(p *corpusPolicy, _ *sample, o *observation, _ *string) { o.Matches = p.Positive }, "positive", "known"},
		{"neutral", func(p *corpusPolicy, _ *sample, o *observation, _ *string) { o.Matches = p.Neutral }, "negative", "known"},
		{"unmapped overrides positive", func(p *corpusPolicy, _ *sample, o *observation, _ *string) {
			o.Matches = append([]symbol{{"other", "unmapped"}}, p.Positive...)
		}, "unknown", "unmapped_rule_hit"},
		{"positive then unmapped", func(p *corpusPolicy, _ *sample, o *observation, _ *string) {
			o.Matches = append(append([]symbol{}, p.Positive...), symbol{"other", "unmapped"})
		}, "unknown", "unmapped_rule_hit"},
		{"open", func(p *corpusPolicy, _ *sample, _ *observation, _ *string) { p.Closed = false }, "unknown", "open_policy_without_positive"},
		{"rules", func(_ *corpusPolicy, _ *sample, _ *observation, sha *string) { *sha = digest(nil) }, "unknown", "rules_identity_mismatch"},
		{"scope", func(_ *corpusPolicy, s *sample, _ *observation, _ *string) { s.InputUnit = "message" }, "unknown", "policy_not_applicable"},
		{"failure", func(_ *corpusPolicy, _ *sample, o *observation, _ *string) { o.Status = "timeout" }, "unknown", "mailstrix_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, input, o, sha := p, s, observation{Status: "ok"}, p.RulesFingerprintSHA256
			tc.edit(&policy, &input, &o, &sha)
			if decision, reason := policy.decision(input, o, sha); decision != tc.decision || reason != tc.reason {
				t.Fatalf("decision=%s reason=%s, want %s/%s", decision, reason, tc.decision, tc.reason)
			}
		})
	}
	raw, _ := json.Marshal(p)
	if _, err := decodeCorpusPolicy(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		bytes.Replace(raw, []byte(`"closed":true`), []byte(`"Closed":true`), 1),
		bytes.Replace(raw, []byte(`"neutral":[`), []byte(`"unknown":1,"neutral":[`), 1),
		append(raw, []byte(`{}`)...), bytes.Repeat([]byte(" "), maxPolicyBytes+1),
	} {
		if _, err := decodeCorpusPolicy(bad); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}

func TestCorpusCorrespondenceNullCodeWitness(t *testing.T) {
	pins := testPins(t)
	id := comparatorIdentity{OletoolsVersion: pins.OletoolsVersion, OlefySHA256: pins.OlefySHA256}
	raw := strings.Replace(nativeCleanFixture, `"macros":[]`, `"macros":[{"code":null,"vba_filename":"inert","subfilename":"inert","ole_stream":"inert"}]`, 1)
	raw = strings.Replace(raw, `"analysis":null`, `"analysis":[]`, 1)
	right := normalizeComparator(fixtureEnvelope(t, "ok", raw, id), pins)
	s := sample{Format: "office", InputUnit: "file"}
	left := observation{Status: "ok"}
	if got := corpusCorrespondence(s, left, right); got != "oletools_only" {
		t.Fatalf("null code record witness: %s", got)
	}
	left.Matches = []symbol{corpusVBASymbol}
	if got := corpusCorrespondence(s, left, right); got != "both" {
		t.Fatalf("both: %s", got)
	}
	right.HasMacros = false
	if got := corpusCorrespondence(s, left, right); got != "mailstrix_only" {
		t.Fatalf("left: %s", got)
	}
	left.Matches = nil
	if got := corpusCorrespondence(s, left, right); got != "neither" {
		t.Fatalf("neither: %s", got)
	}
	for _, format := range []string{"OLE", "Text", ""} {
		right.Format = format
		if got := corpusCorrespondence(s, left, right); got != "unknown" {
			t.Fatalf("inapplicable %s became %s", format, got)
		}
	}
}

func TestCorpusReportTruthPrivacyAndReceipts(t *testing.T) {
	m, hash, root := generated(t)
	p := comparisonPolicyFixture()
	ctx := corpusContext{Schema: corpusSchema, ManifestSHA256: hash, PolicySHA256: digest([]byte("policy")), MailstrixWorker: isolatedIdentity{RulesFingerprintSHA256: p.RulesFingerprintSHA256}}
	// All inputs are inert generated fixtures. Applicability and explicit truth
	// are assigned here independently of the fake engine observations.
	for i := range m.Samples {
		m.Samples[i].Format, m.Samples[i].InputUnit = "office", "file"
		m.Samples[i].Partition = "synthetic"
		want := "absent"
		if i < 2 {
			want = "present"
		}
		m.Samples[i].Truth.Symbols = []label{{Symbol: p.Positive[0], Expected: want}}
	}
	i := 0
	observers := corpusObservers{
		mailstrix: func(sample, []byte) observation {
			index := i
			i++
			if index == 4 {
				return observation{Status: "timeout"}
			}
			o := observation{Status: "ok"}
			if index == 0 || index == 2 {
				o.Matches = append(o.Matches, p.Positive[0])
			}
			if index == 5 {
				o.Matches = append(o.Matches, symbol{"inert", "unmapped"})
			}
			return o
		},
		oletools: func(string, []byte) nativeObservation { return nativeObservation{Status: "ok", Format: "OpenXML"} },
		clamav: func(sample, []byte) clamObservation {
			return clamObservation{Status: "detection", Detections: []string{"Inert.Test"}, Diagnostics: []clamDiagnostic{}}
		},
	}
	var receipts bytes.Buffer
	r, err := compareCorpusAll(root, m, p, ctx, observers, &receipts)
	if err != nil {
		t.Fatal(err)
	}
	c := r.Summary.Symbols[0]
	if c.TP != 1 || c.FP != 1 || c.FN != 1 || c.TN != 2 || c.Excluded != 1 || r.Summary.UnlabelledMatches != 1 {
		t.Fatalf("independent truth counts: %+v", r.Summary)
	}
	if r.ClamAVRelation.Cells["clamav_unique"] != 2 || r.ClamAVRelation.Cells["both_positive"] != 2 || r.ClamAVRelation.Cells["unknown"] != 2 || r.Complete || r.RealWorldPrecision != nil {
		t.Fatalf("relation counts: %+v", r)
	}
	public, _ := json.Marshal(r)
	for _, s := range m.Samples {
		for _, private := range []string{s.ID, s.SHA256, s.Locator, root.Name()} {
			if bytes.Contains(public, []byte(private)) {
				t.Fatalf("public report exposed %q", private)
			}
		}
	}
	lines := bytes.Split(bytes.TrimSpace(receipts.Bytes()), []byte{'\n'})
	if len(lines) != len(m.Samples)+2 {
		t.Fatalf("receipt rows=%d", len(lines))
	}
	var header struct {
		Schema     string `json:"schema"`
		ContextSHA string `json:"context_sha256"`
	}
	if err := json.Unmarshal(lines[0], &header); err != nil {
		t.Fatal(err)
	}
	if header.Schema != "mailstrix-local-corpus-context-v1" {
		t.Fatalf("receipt header schema=%q", header.Schema)
	}
	for i, line := range lines[1 : len(lines)-1] {
		var row corpusReceipt
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		if row.Schema != "mailstrix-local-corpus-observation-v1" || row.ContextSHA256 != header.ContextSHA || row.SampleSHA256 != m.Samples[i].SHA256 || row.ManifestSHA256 != hash || row.Size != m.Samples[i].Size || row.InputUnit != "file" {
			t.Fatalf("receipt binding lost: %+v", row)
		}
	}
	var footer struct {
		Schema    string `json:"schema"`
		Count     int    `json:"unique_samples"`
		Complete  bool   `json:"complete"`
		ReportSHA string `json:"report_sha256"`
	}
	if err := json.Unmarshal(lines[len(lines)-1], &footer); err != nil || footer.Schema != "mailstrix-local-corpus-end-v1" || footer.Count != len(m.Samples) || footer.Complete != r.Complete || footer.ReportSHA != digest(public) {
		t.Fatal("receipt footer does not bind aggregate")
	}
}

func TestCorpusAliasesAndRulesMismatch(t *testing.T) {
	m, hash, root := generated(t)
	all := append([]sample(nil), m.Samples...)
	for _, s := range m.Samples {
		if s.Format == "office" {
			m.Samples = []sample{s}
			break
		}
	}
	p := comparisonPolicyFixture()
	ctx := corpusContext{ManifestSHA256: hash, MailstrixWorker: isolatedIdentity{RulesFingerprintSHA256: p.RulesFingerprintSHA256}}
	calls := 0
	o := corpusObservers{
		mailstrix: func(sample, []byte) observation { calls++; return observation{Status: "ok"} },
		oletools: func(string, []byte) nativeObservation {
			calls++
			return nativeObservation{Status: "ok", Format: "OpenXML"}
		},
		clamav: func(sample, []byte) clamObservation { calls++; return clamObservation{Status: "no_detection"} },
	}
	ctx.MailstrixWorker.RulesFingerprintSHA256 = digest(nil)
	r, err := compareCorpusAll(root, m, p, ctx, o, nil)
	if err != nil || calls != 3 || r.Correspondence.Cells["unknown"] != 1 || r.ClamAVRelation.ExcludedReasons["rules_identity_mismatch"] != 1 {
		t.Fatalf("rules mismatch accepted: %+v, %v", r, err)
	}
	alias := m.Samples[0]
	alias.ID, alias.Locator = "private-alias", "missing-private-alias"
	m.Samples = append(m.Samples, alias)
	for _, s := range all {
		if s.SHA256 != alias.SHA256 {
			m.Samples = append(m.Samples, s)
		}
	}
	calls = 0
	r, err = compareCorpusAll(root, m, p, ctx, o, nil)
	if err != nil || calls != 0 || r.Summary.Duplicates != 1 || r.Statuses["clamav"]["integrity_error"] != 1 || r.Statuses["clamav"]["not_run"] != 5 {
		t.Fatalf("bad duplicate alias reached parser: %+v, calls=%d", r, calls)
	}
}

type receiptShortWriter struct{}

func (receiptShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type receiptErrorWriter struct{}

func (receiptErrorWriter) Write([]byte) (int, error) { return 0, errors.New("inert write failure") }

func TestCorpusReceiptWriteFailures(t *testing.T) {
	w := receiptWriter{out: io.Discard, remaining: 1}
	if err := w.write("inert"); err == nil {
		t.Fatal("receipt byte bound ignored")
	}
	w = receiptWriter{out: receiptShortWriter{}, remaining: 1024}
	if err := w.write("inert"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	w = receiptWriter{out: receiptErrorWriter{}, remaining: 1024}
	if err := w.write("inert"); err == nil || err.Error() != "inert write failure" {
		t.Fatalf("write error: %v", err)
	}
	w = receiptWriter{out: io.Discard, remaining: 1024}
	if err := w.write(make(chan int)); err == nil {
		t.Fatal("receipt JSON error ignored")
	}
}

func TestCorpusReceiptsAreExclusivePrivateFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-receipts.jsonl")
	file, err := openCorpusReceipts(path)
	if err != nil {
		t.Fatal(err)
	}
	info, statErr := file.Stat()
	if closeErr := file.Close(); statErr != nil || closeErr != nil {
		t.Fatalf("receipt stat/close: %v / %v", statErr, closeErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode=%#o, want 0600", info.Mode().Perm())
	}
	if _, err := openCorpusReceipts(path); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing receipt was not rejected: %v", err)
	}
}
