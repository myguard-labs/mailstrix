package yarad

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// eicar reconstructs the standard EICAR antivirus test string from fragments so
// the test binary itself is not flagged by an on-access scanner in the repo or
// CI. It is the canonical harmless test pattern, not real malware.
func eicar() []byte {
	return []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}` + `$EICAR-STANDARD-` +
		`ANTIVIRUS-TEST-FILE!` + `$H+H*`)
}

const eicarRule = `
rule EICAR_Test_File : test
{
    meta:
        description = "EICAR antivirus test pattern"
        severity = "low"
    strings:
        $eicar = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $eicar
}
`

func writeRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newScanner(t *testing.T, dir string) *Scanner {
	t.Helper()
	cfg := &Config{RulesDir: dir, ScanTimeout: 0}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

func TestScannerCompileAndCount(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	if s.RuleCount() != 1 {
		t.Errorf("rule count = %d, want 1", s.RuleCount())
	}
}

func TestScannerMatch(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	m, err := s.Scan(eicar())
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m[0].Rule != "EICAR_Test_File" {
		t.Fatalf("matches = %+v", m)
	}
	if m[0].Meta["description"] == "" {
		t.Errorf("meta not propagated: %+v", m[0].Meta)
	}
	if len(m[0].Tags) != 1 || m[0].Tags[0] != "test" {
		t.Errorf("tags = %v, want [test]", m[0].Tags)
	}
}

func TestScannerNoMatch(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	m, err := s.Scan([]byte("a perfectly innocent email body"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("clean input matched: %+v", m)
	}
}

func TestScannerEmptyDirIsError(t *testing.T) {
	cfg := &Config{RulesDir: t.TempDir(), ScanTimeout: 0}
	cfg.sanitize()
	if _, err := NewScanner(cfg, func(string, ...any) {}); err == nil {
		t.Error("empty rules dir should error at startup")
	}
}

func TestScannerSkipsBadFileKeepsGood(t *testing.T) {
	// A dir with one good and one unparseable file must load the good rules and
	// skip the bad one, not abort the whole compile. This is the real public-
	// ruleset case (a stray cuckoo/magic import or bad syntax among hundreds).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.yar"), []byte(eicarRule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yar"), []byte("rule oops { this is not yara }"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newScanner(t, dir)
	if s.RuleCount() != 1 {
		t.Fatalf("rule count = %d, want 1 (good kept, bad skipped)", s.RuleCount())
	}
	m, err := s.Scan(eicar())
	if err != nil || len(m) != 1 {
		t.Errorf("good rule should still match: %+v err=%v", m, err)
	}
}

func TestScannerBrokenRuleKeepsOld(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScanner(t, dir)
	// Overwrite with a syntactically broken rule, then reload: must fail and
	// keep the previous (working) set active.
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte("rule broken {"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Error("broken reload should error")
	}
	m, err := s.Scan(eicar())
	if err != nil || len(m) != 1 {
		t.Errorf("old ruleset should still match after failed reload: %+v err=%v", m, err)
	}
}

// vbaRule matches the per-module "Attribute VB_Name" header that appears ONLY in
// decompressed VBA source — never in the raw .xlsm bytes (MS-OVBA + zip
// compressed). So a match can only arrive via the pre-extract path.
const vbaRule = `
rule VBA_Macro_Attribute : macro
{
    meta:
        description = "decompressed VBA module marker"
    strings:
        $vbname = "Attribute VB_Name"
    condition:
        $vbname
}
`

func macroDoc(t *testing.T) []byte {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join("testdata", "xlswithmacro.xlsm"))
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

// The whole pre-extract feature, end to end: scanning a macro .xlsm fires a rule
// whose string lives only in the DECOMPRESSED VBA. If the marker were present in
// the raw bytes the test would prove nothing, so guard that invariant first.
func TestScanMatchesMacroViaDecompressedStream(t *testing.T) {
	doc := macroDoc(t)
	if bytes.Contains(doc, []byte("Attribute VB_Name")) {
		t.Fatal("fixture changed: marker present in raw bytes, test no longer proves the extract path")
	}
	s := newScanner(t, writeRules(t, vbaRule))
	m, err := s.Scan(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m[0].Rule != "VBA_Macro_Attribute" {
		t.Fatalf("macro rule did not fire via decompressed stream: %+v", m)
	}
}

// The extract counters must move for a macro doc and stay put for a non-doc.
func TestScanExtractMetrics(t *testing.T) {
	s := newScanner(t, writeRules(t, vbaRule))
	if _, err := s.Scan(macroDoc(t)); err != nil {
		t.Fatal(err)
	}
	em := s.ExtractMetrics()
	if em.Docs != 1 || em.MacroDocs != 1 || em.Streams < 1 {
		t.Errorf("after macro doc: %+v want Docs=1 MacroDocs=1 Streams>=1", em)
	}
	if em.Failed != 0 || em.Panicked != 0 || em.Encrypted != 0 {
		t.Errorf("macro doc set fail/panic/enc: %+v", em)
	}
	if _, err := s.Scan([]byte("a plain non-document body")); err != nil {
		t.Fatal(err)
	}
	if got := s.ExtractMetrics().Docs; got != 1 {
		t.Errorf("non-doc scan bumped Docs to %d, want 1", got)
	}
}

// A malformed OLE attachment must be counted (Docs+Failed) yet never fail the
// scan — fail-open: the raw verdict (here, EICAR matching) survives.
func TestScanMalformedOLECountedButFailsOpen(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	poison := append(append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, eicar()...),
		bytes.Repeat([]byte{0x7F}, 2048)...)
	m, err := s.Scan(poison)
	if err != nil {
		t.Fatalf("malformed OLE must not error the scan: %v", err)
	}
	if len(m) != 1 || m[0].Rule != "EICAR_Test_File" {
		t.Fatalf("raw verdict lost on malformed OLE: %+v", m)
	}
	em := s.ExtractMetrics()
	if em.Docs != 1 || em.Failed != 1 {
		t.Errorf("malformed OLE: %+v want Docs=1 Failed=1", em)
	}
}

// Directly proves the external-variable mechanism behind Didier's vba.yara: a
// rule whose condition IS the external VBA variable must be inert on raw bytes
// (VBA=false) and fire on a decompressed macro stream (VBA=true). Without
// defineExternals declaring VBA at compile, this rule would not even load.
func TestScanOneVBAExternalVariable(t *testing.T) {
	s := newScanner(t, writeRules(t, "rule Needs_VBA { condition: VBA }"))
	rules := s.rules.Load()
	if m, err := s.scanOne(rules, []byte("x"), false, 0); err != nil || len(m) != 0 {
		t.Fatalf("VBA=false (raw) must not match: %+v err=%v", m, err)
	}
	if m, err := s.scanOne(rules, []byte("x"), true, 0); err != nil || len(m) != 1 {
		t.Fatalf("VBA=true (macro stream) must match: %+v err=%v", m, err)
	}
}

func TestReloadMetrics(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	// NewScanner already did the initial load: 1 attempt, 1 success, rules=1.
	rm := s.ReloadMetrics()
	if rm.Attempts < 1 || rm.Successes < 1 || rm.Rules != 1 {
		t.Fatalf("boot reload not counted: %+v", rm)
	}
	before := rm.Successes
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	rm = s.ReloadMetrics()
	if rm.Successes != before+1 {
		t.Errorf("successful reload not counted: %+v", rm)
	}
	if rm.LastUnix == 0 {
		t.Error("last reload timestamp not set")
	}
}

func TestReloadMetricsFailure(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScanner(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte("rule broken {"), 0o600); err != nil {
		t.Fatal(err)
	}
	failBefore := s.ReloadMetrics().Failures
	if err := s.Reload(); err == nil {
		t.Error("broken reload should error")
	}
	if s.ReloadMetrics().Failures != failBefore+1 {
		t.Error("failed reload not counted")
	}
}

func TestMergeMatches(t *testing.T) {
	raw := []Match{{Rule: "A"}, {Rule: "B"}}
	got := mergeMatches(raw, []Match{{Rule: "B"}, {Rule: "C"}})
	if want := []string{"A", "B", "C"}; !sameRules(got, want) {
		t.Errorf("dedup/order wrong: %+v want %v", got, want)
	}
	if got := mergeMatches(raw, nil); len(got) != 2 {
		t.Errorf("nil more changed length: %+v", got)
	}
	if got := mergeMatches(nil, []Match{{Rule: "X"}}); !sameRules(got, []string{"X"}) {
		t.Errorf("nil into lost stream match: %+v", got)
	}
}

func sameRules(m []Match, want []string) bool {
	if len(m) != len(want) {
		return false
	}
	for i := range want {
		if m[i].Rule != want[i] {
			return false
		}
	}
	return true
}
