package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func shippedRules(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile("../../docker/local-rules/pdf_indicators.yara")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pdf_indicators.yara"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func encodeManifest(m manifest) ([]byte, error) {
	var b bytes.Buffer
	err := json.NewEncoder(&b).Encode(m)
	return b.Bytes(), err
}

func generated(t *testing.T) (manifest, string, *os.Root) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "corpus")
	if err := generate(dir); err != nil {
		t.Fatal(err)
	}
	m, hash, err := loadManifest(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return m, hash, root
}

func TestGeneratorReproducible(t *testing.T) {
	a, hashA, rootA := generated(t)
	b, hashB, rootB := generated(t)
	if hashA != hashB || len(a.Samples) != 6 || len(b.Samples) != 6 {
		t.Fatalf("generation is not reproducible: %s != %s", hashA, hashB)
	}
	formats := map[string]int{}
	for _, s := range a.Samples {
		x, err := readSample(rootA, s)
		if err != nil {
			t.Fatal(err)
		}
		y, err := readSample(rootB, s)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(x, y) {
			t.Fatalf("fixture %s changed across runs", s.ID)
		}
		formats[s.Format]++
	}
	if len(formats) != 5 || formats["pdf"] != 2 {
		t.Fatalf("format coverage: %v", formats)
	}
	if err := generate(rootA.Name()); err == nil {
		t.Fatal("generation overwrote an existing corpus")
	}
}

func TestManifestRejectsMalformed(t *testing.T) {
	m, _, _ := generated(t)
	good, err := encodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"duplicate":  bytes.Replace(good, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		"wrong case": bytes.Replace(good, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1),
		"unknown":    bytes.Replace(good, []byte(`"schema_version":1`), []byte(`"extra":true,"schema_version":1`), 1),
		"missing":    bytes.Replace(good, []byte(`"schema_version":1,`), nil, 1),
		"trailing":   append(slices.Clone(good), []byte(`{}`)...),
		"truncated":  good[:len(good)/2],
		"oversize":   bytes.Repeat([]byte(" "), maxManifest+1),
		"nested":     []byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeManifest(bytes.NewReader(data)); err == nil {
				t.Fatal("accepted malformed manifest")
			}
		})
	}
}

func TestManifestContracts(t *testing.T) {
	cases := []struct {
		name, want string
		mutate     func(*manifest)
	}{
		{"version", "version", func(m *manifest) { m.SchemaVersion = 2 }},
		{"empty", "count", func(m *manifest) { m.Samples = nil }},
		{"duplicate ID", "duplicate sample", func(m *manifest) { m.Samples[1].ID = m.Samples[0].ID }},
		{"duplicate source", "duplicate source", func(m *manifest) { m.Sources = append(m.Sources, m.Sources[0]) }},
		{"unknown source", "unknown source", func(m *manifest) { m.Samples[0].SourceID = "absent" }},
		{"checksum", "checksum", func(m *manifest) { m.Samples[0].SHA256 = "abc" }},
		{"large file", "size", func(m *manifest) { m.Samples[0].Size = maxSample + 1 }},
		{"traversal", "locator", func(m *manifest) { m.Samples[0].Locator = "../secret" }},
		{"absolute", "locator", func(m *manifest) { m.Samples[0].Locator = "/secret" }},
		{"format", "format", func(m *manifest) { m.Samples[0].Format = "invalid" }},
		{"split", "split", func(m *manifest) { m.Samples[0].Split = "invalid" }},
		{"group leak", "crosses splits", func(m *manifest) { m.Samples[5].Split = "holdout" }},
		{"provenance", "provenance", func(m *manifest) { m.Sources[0].License = "" }},
		{"private synthetic", "provenance/label", func(m *manifest) { m.Sources[0].Privacy = "restricted" }},
		{"malicious synthetic", "provenance/label", func(m *manifest) { m.Samples[0].Truth.Class = "malicious" }},
		{"unknown expected", "symbol label", func(m *manifest) { m.Samples[0].Truth.Symbols[0].Expected = "unknown" }},
		{"duplicate label", "symbol label", func(m *manifest) {
			m.Samples[0].Truth.Symbols = append(m.Samples[0].Truth.Symbols, m.Samples[0].Truth.Symbols[0])
		}},
		{"conflicting alias", "conflicting", func(m *manifest) {
			a := m.Samples[0]
			a.ID = "alias"
			a.Truth.Class = "unknown"
			a.Partition = "external-unlabelled"
			a.SourceID = "external"
			s := m.Sources[0]
			s.ID = "external"
			s.Kind = "external"
			m.Sources = append(m.Sources, s)
			m.Samples = append(m.Samples, a)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := generated(t)
			tc.mutate(&m)
			if err := m.validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestSampleIntegrityAndContainment(t *testing.T) {
	m, _, root := generated(t)
	s := m.Samples[0]
	if err := root.WriteFile(s.Locator, bytes.Repeat([]byte("x"), int(s.Size)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSample(root, s); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("same-size changed bytes accepted: %v", err)
	}
	s.Size++
	if _, err := readSample(root, s); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("changed size accepted: %v", err)
	}
	s.Locator = "missing"
	if _, err := readSample(root, s); err == nil {
		t.Fatal("missing sample accepted")
	}
	s.Locator = "../outside"
	if _, err := readSample(root, s); err == nil {
		t.Fatal("path escape accepted")
	}
	s.Locator = "link"
	if err := os.Symlink(t.TempDir(), filepath.Join(root.Name(), s.Locator)); err != nil {
		t.Fatal(err)
	}
	if _, err := readSample(root, s); err == nil {
		t.Fatal("external symlink accepted")
	}
}

func TestExternalManifestCheckOnly(t *testing.T) {
	m, _, root := generated(t)
	m.Sources[0].Kind, m.Sources[0].Privacy, m.Sources[0].Redistribution = "external", "restricted", "local-only"
	for i := range m.Samples {
		m.Samples[i].Partition = "external-clean"
		m.Samples[i].Truth.Basis = "independent"
	}
	if err := m.validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateFiles(root, m); err != nil {
		t.Fatal(err)
	}
	if err := requireSynthetic(m); err == nil {
		t.Fatal("external execution accepted")
	}
	m.Samples[0].Partition = "synthetic-clean"
	m.Samples[0].SHA256 = strings.Repeat("0", 64)
	if err := requireSynthetic(m); err == nil {
		t.Fatal("unrecognized bytes accepted as synthetic")
	}
}

func TestSummaryGroundTruth(t *testing.T) {
	x := symbol{Namespace: "rules.yara", Rule: "Indicator"}
	y := symbol{Namespace: "other.yara", Rule: "Indicator"}
	m := manifest{Samples: []sample{
		{SHA256: "positive-hit", Partition: "synthetic-indicator", Truth: truth{Symbols: []label{{Symbol: x, Expected: "present"}}}},
		{SHA256: "positive-miss", Partition: "synthetic-indicator", Truth: truth{Symbols: []label{{Symbol: x, Expected: "present"}}}},
		{SHA256: "negative-hit", Partition: "synthetic-indicator", Truth: truth{Symbols: []label{{Symbol: x, Expected: "absent"}}}},
		{SHA256: "negative-clean", Partition: "synthetic-indicator", Truth: truth{Symbols: []label{{Symbol: x, Expected: "absent"}}}},
		{SHA256: "failed", Partition: "synthetic-indicator", Truth: truth{Symbols: []label{{Symbol: x, Expected: "present"}}}},
	}}
	m.Samples = append(m.Samples, m.Samples[0])
	obs := map[string]observation{
		"positive-hit":   {Status: "ok", Matches: []symbol{x, x}},
		"positive-miss":  {Status: "ok", Matches: []symbol{y}},
		"negative-hit":   {Status: "ok", Matches: []symbol{x}},
		"negative-clean": {Status: "ok"},
		"failed":         {Status: "timeout", Matches: []symbol{x}},
	}
	r := summarize(m, obs)
	if r.Pass || r.UniqueSamples != 5 || r.Duplicates != 1 || r.UnlabelledMatches != 1 || r.Statuses["timeout"] != 1 {
		t.Fatalf("incorrect summary: %+v", r)
	}
	c := r.Symbols[0]
	if c.TP != 1 || c.FP != 1 || c.FN != 1 || c.TN != 1 || c.Excluded != 1 || *c.Precision != 0.5 || *c.Recall != 0.5 {
		t.Fatalf("incorrect confusion matrix: %+v", c)
	}
	slices.Reverse(m.Samples)
	r2 := summarize(m, obs)
	a, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("summary changed with manifest order")
	}
	r = summarize(manifest{Samples: m.Samples[:1]}, nil)
	if r.Pass || r.Symbols[0].Precision != nil || r.Symbols[0].Recall != nil || r.Statuses["missing"] != 1 {
		t.Fatalf("missing observation treated as verdict: %+v", r)
	}
}

// This frozen matrix comes from fixture construction, not scanner observations.
func loadSyntheticBaseline(t *testing.T) summary {
	t.Helper()
	b, err := os.ReadFile("testdata/synthetic-baseline-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var baseline struct {
		Generator string  `json:"generator"`
		Summary   summary `json:"summary"`
	}
	if err := json.Unmarshal(b, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.Generator != generatorRevision || len(baseline.Summary.Symbols) != 14 {
		t.Fatal("synthetic baseline requires reviewed generator and 14-row matrix")
	}
	return baseline.Summary
}

func matchSyntheticBaseline(got, want summary) error {
	type key struct{ partition, namespace, rule string }
	index := func(rows []symbolCounts) (map[key]symbolCounts, error) {
		out := make(map[key]symbolCounts, len(rows))
		for _, row := range rows {
			k := key{row.Partition, row.Symbol.Namespace, row.Symbol.Rule}
			if _, exists := out[k]; exists {
				return nil, fmt.Errorf("duplicate synthetic baseline row: %+v", k)
			}
			out[k] = row
		}
		return out, nil
	}
	g, err := index(got.Symbols)
	if err != nil {
		return err
	}
	w, err := index(want.Symbols)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(g, w) {
		return errors.New("synthetic baseline symbol/partition matrix differs")
	}
	got.Symbols, want.Symbols = nil, nil
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("synthetic baseline population/status differs: got %+v, want %+v", got, want)
	}
	return nil
}

// This enters the production extractor and YARA scanner using a shipped rule,
// not a fake match returned from the fixture's source label.
func TestSyntheticScannerBaseline(t *testing.T) {
	m, hash, root := generated(t)
	rules := shippedRules(t)
	r, err := run(root, m, hash, rules)
	if err != nil {
		t.Fatal(err)
	}
	want := loadSyntheticBaseline(t)
	if err := matchSyntheticBaseline(r.Summary, want); err != nil {
		t.Fatal(err)
	}
	// Corrupt actual scanner results, preserving aggregate TP/TN for the
	// reassociation cases. Each must fail the frozen keyed matrix/population.
	for name, mutate := range map[string]func(*summary){
		"symbol-reassociation": func(s *summary) {
			s.Symbols[12].Symbol, s.Symbols[13].Symbol = s.Symbols[13].Symbol, s.Symbols[12].Symbol
		},
		"partition-reassociation": func(s *summary) {
			s.Symbols[0].Partition, s.Symbols[7].Partition = s.Symbols[7].Partition, s.Symbols[0].Partition
		},
		"missing-symbol":   func(s *summary) { s.Symbols = s.Symbols[:13] },
		"duplicate-symbol": func(s *summary) { s.Symbols = append(s.Symbols, s.Symbols[0]) },
		"missing-status":   func(s *summary) { delete(s.Statuses, "ok") },
		"extra-status":     func(s *summary) { s.Statuses["timeout"] = 1 },
		"excluded":         func(s *summary) { s.Symbols[0].Excluded = 1 },
		"missing-sample":   func(s *summary) { s.UniqueSamples-- },
	} {
		t.Run(name, func(t *testing.T) {
			altered := r.Summary
			altered.Symbols = slices.Clone(r.Summary.Symbols)
			altered.Statuses = map[string]int{"ok": 6}
			mutate(&altered)
			if err := matchSyntheticBaseline(altered, want); err == nil {
				t.Fatal("corrupted actual scanner baseline accepted")
			}
		})
	}
	if !r.Summary.Pass || r.Summary.Statuses["ok"] != 6 {
		t.Fatalf("synthetic baseline failed: %+v", r.Summary)
	}
	tp, tn := 0, 0
	for _, c := range r.Summary.Symbols {
		tp += c.TP
		tn += c.TN
	}
	if tp != 1 || tn != 41 {
		t.Fatalf("want actual scanner TP=1 TN=41, got TP=%d TN=%d", tp, tn)
	}
	if r.RealWorldPrecision != nil || r.RealWorldThresholds == "" || r.RulesFingerprint == "" {
		t.Fatal("report lost scope/provenance")
	}
	if err := root.WriteFile(m.Samples[0].Locator, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err = run(root, m, hash, rules)
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.Pass || r.Summary.Statuses["integrity_error"] != 1 {
		t.Fatalf("integrity failure disappeared: %+v", r.Summary)
	}
}

func TestRejectPartialRules(t *testing.T) {
	m, hash, root := generated(t)
	rules := shippedRules(t)
	if err := os.WriteFile(filepath.Join(rules, "invalid.yara"), []byte("not valid YARA syntax"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(root, m, hash, rules); err == nil || !strings.Contains(err.Error(), "rule loading produced diagnostics") {
		t.Fatalf("partial rule load must prevent a baseline: %v", err)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("test writer unavailable") }

func TestCLIRunReportAndExit(t *testing.T) {
	m, _, root := generated(t)
	args := []string{"run", "-manifest", filepath.Join(root.Name(), "manifest.json"), "-corpus-root", root.Name(), "-rules", shippedRules(t)}
	var stdout, stderr bytes.Buffer
	if code := cli(args, &stdout, &stderr); code != 0 {
		t.Fatalf("successful run exit=%d: %s", code, stderr.String())
	}
	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.SchemaVersion != 1 || !r.Summary.Pass || r.Summary.Statuses["ok"] != 6 || !strings.Contains(stderr.String(), "6 unique samples") {
		t.Fatalf("missing report/summary contract: %+v, %s", r.Summary, stderr.String())
	}
	if code := cli(args, brokenWriter{}, &stderr); code != 2 {
		t.Fatalf("broken report writer exit=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "report write failed") {
		t.Fatal("missing writer error diagnostic")
	}
	if code := cli(args, &stdout, brokenWriter{}); code != 2 {
		t.Fatalf("broken summary writer exit=%d, want 2", code)
	}
	// Change an explicit negative expectation to a required indicator that is
	// absent in the clean MIME bytes. The resulting FN must reach exit status 1.
	m.Samples[0].Truth.Symbols[0].Expected = "present"
	b, err := encodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("manifest.json", b, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := cli(args, &stdout, &stderr); code != 1 {
		t.Fatalf("failed label exit=%d, want 1", code)
	}
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Summary.Pass {
		t.Fatal("failed-label report claimed pass")
	}
}

func TestCLI(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{nil, {"bad"}, {"generate"}, {"run"}, {"check"}, {"run", "-unknown"}} {
		if got := cli(args, &stdout, &stderr); got != 2 {
			t.Fatalf("args %v: exit %d", args, got)
		}
	}
	dir := filepath.Join(t.TempDir(), "corpus")
	if got := cli([]string{"generate", "-out", dir}, &stdout, &stderr); got != 0 {
		t.Fatalf("generate exit %d: %s", got, stderr.String())
	}
	if got := cli([]string{"check", "-manifest", filepath.Join(dir, "manifest.json"), "-corpus-root", dir}, &stdout, &stderr); got != 0 {
		t.Fatalf("check exit %d: %s", got, stderr.String())
	}
}

func TestGenerationErrorRedactsPath(t *testing.T) {
	// An overlong basename gives a real OS error distinct from destination
	// permissions, without filling a disk or modifying host resource limits.
	dir := filepath.Join(t.TempDir(), strings.Repeat("private-corpus-", 40))
	var stdout, stderr bytes.Buffer
	if code := cli([]string{"generate", "-out", dir}, &stdout, &stderr); code != 2 {
		t.Fatalf("generation failure exit=%d, want 2", code)
	}
	message := stderr.String()
	if !strings.Contains(message, "generation failed: mkdir:") || !strings.Contains(message, syscall.ENAMETOOLONG.Error()) {
		t.Fatalf("generation failure lost operation or OS cause: %q", message)
	}
	if strings.Contains(message, "private-corpus") || strings.Contains(message, filepath.Dir(dir)) {
		t.Fatal("generation failure exposed a private destination")
	}
}
