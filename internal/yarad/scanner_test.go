package yarad

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// scanT calls Scan with the body's digest (PERF-3 threaded the hash); test
// helper so a body that is a function call isn't evaluated twice.
func scanT(s *Scanner, buf []byte, meta ScanMeta) ([]Match, error) {
	return s.Scan(buf, sha256.Sum256(buf), meta)
}

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
	m, err := scanT(s, eicar(), ScanMeta{})
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
	// Namespace must surface the source rule file so the rspamd plugin can show
	// which ruleset fired (compileDir namespaces each file by its basename).
	if m[0].Namespace != "eicar.yar" {
		t.Errorf("namespace = %q, want %q", m[0].Namespace, "eicar.yar")
	}
}

func TestScannerRuleDenylist(t *testing.T) {
	// A denylisted rule name (case-insensitive) must be dropped from results, so
	// public-ruleset noise rules like Didier's `http` never reach rspamd.
	dir := writeRules(t, eicarRule)
	cfg := &Config{RulesDir: dir, ScanTimeout: 0,
		RuleDenylist: map[string]struct{}{"eicar_test_file": {}}}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	m, err := scanT(s, eicar(), ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("denylisted rule not filtered: %+v", m)
	}
}

func TestScannerRuleAllowlist(t *testing.T) {
	// An allowlisted rule name (case-insensitive) must be KEPT but tagged
	// meta.yarad_allow="1" so the plugin can score it log-only — visibility
	// preserved, unlike the denylist which drops the match entirely.
	dir := writeRules(t, eicarRule)
	cfg := &Config{RulesDir: dir, ScanTimeout: 0,
		RuleAllowlist: map[string]struct{}{"eicar_test_file": {}}}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	m, err := scanT(s, eicar(), ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Fatalf("allowlisted rule must still be reported: %+v", m)
	}
	if m[0].Meta["yarad_allow"] != "1" {
		t.Errorf("allowlisted match not tagged yarad_allow=1: %+v", m[0])
	}
}

// A name in BOTH lists is denied (drop wins over demote).
func TestScannerDenyWinsOverAllow(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{RulesDir: dir, ScanTimeout: 0,
		RuleDenylist:  map[string]struct{}{"eicar_test_file": {}},
		RuleAllowlist: map[string]struct{}{"eicar_test_file": {}}}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	m, err := scanT(s, eicar(), ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("deny must win over allow: %+v", m)
	}
}

// A rule that fires only on decompressed macro cleartext (never on the raw,
// still-compressed .xlsm bytes) must register in extract_stream_matches_total —
// the metric that measures what pre-extraction adds over a raw-only scan.
func TestExtractStreamMatchesMetric(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "extract", "testdata", "xlswithmacro.xlsm"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	// "Attribute VB_Name" exists in every decompressed VBA module but not in the
	// raw (zip-compressed) container bytes.
	rule := `rule MacroAttr { strings: $a = "Attribute VB_Name" condition: $a }`
	s := newScanner(t, writeRules(t, rule))
	if s.ExtractMetrics().StreamMatches != 0 {
		t.Fatalf("precondition: StreamMatches should start at 0")
	}
	m, err := scanT(s, doc, ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) == 0 {
		t.Fatal("expected a match from the decompressed macro")
	}
	if s.ExtractMetrics().StreamMatches == 0 {
		t.Errorf("stream-only match not counted in StreamMatches: %+v", m)
	}
}

// TestPerChannelScanCounts (PERF-17) verifies the raw / real-stream / marker
// per-channel scan counters increment on the right channel.
func TestPerChannelScanCounts(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))

	// A plain (non-document) buffer is scanned on the raw channel only.
	if _, err := scanT(s, eicar(), ScanMeta{}); err != nil {
		t.Fatal(err)
	}
	if got := s.RawChannelScans(); got != 1 {
		t.Errorf("raw channel: got %d want 1 after one plain scan", got)
	}
	if got := s.StreamChannelScans(); got != 0 {
		t.Errorf("stream channel: got %d want 0 for a non-document buffer", got)
	}

	// A macro document fans out into extracted streams, adding a raw scan plus at
	// least one real-content stream scan.
	doc, err := os.ReadFile(filepath.Join("..", "extract", "testdata", "xlswithmacro.xlsm"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	if _, err := scanT(s, doc, ScanMeta{}); err != nil {
		t.Fatal(err)
	}
	if got := s.RawChannelScans(); got != 2 {
		t.Errorf("raw channel: got %d want 2 after a second (document) scan", got)
	}
	if got := s.StreamChannelScans(); got == 0 {
		t.Error("stream channel: expected >=1 real-content stream scan from the macro document")
	}
}

func TestScannerNoMatch(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	m, err := scanT(s, []byte("a perfectly innocent email body"), ScanMeta{})
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
	m, err := scanT(s, eicar(), ScanMeta{})
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
	m, err := scanT(s, eicar(), ScanMeta{})
	if err != nil || len(m) != 1 {
		t.Errorf("old ruleset should still match after failed reload: %+v err=%v", m, err)
	}
}

// TestFingerprintFoldsRuleBody proves the verdict-cache fingerprint changes when a
// rule's BODY changes while its namespace+identifier stay the same — the gap the
// identity-only fingerprint missed (stale Redis L2 verdicts across rolling
// replicas). Each edit (string, meta, condition) must move Fingerprint().
func TestFingerprintFoldsRuleBody(t *testing.T) {
	const base = `rule SameName {
    strings:
        $a = "alpha"
    condition:
        $a
}
`
	// Same rule name, but each variant differs in exactly one body section.
	variants := map[string]string{
		"string-changed": `rule SameName {
    strings:
        $a = "BETA"
    condition:
        $a
}
`,
		"meta-changed": `rule SameName {
    meta:
        author = "x"
    strings:
        $a = "alpha"
    condition:
        $a
}
`,
		"condition-changed": `rule SameName {
    strings:
        $a = "alpha"
        $b = "alpha"
    condition:
        $a and $b
}
`,
	}

	dir := writeRules(t, base)
	s := newScanner(t, dir)
	want := s.Fingerprint()

	// Identity is unchanged across every variant (same namespace+identifier), so any
	// movement in Fingerprint() comes from the content hash.
	idBase := func() string { p := s.fp.Load(); return *p }()

	for name, body := range variants {
		if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.Reload(); err != nil {
			t.Fatalf("%s: reload: %v", name, err)
		}
		if got := s.Fingerprint(); got == want {
			t.Errorf("%s: fingerprint unchanged after rule-body edit: %s", name, got)
		}
		if id := func() string { p := s.fp.Load(); return *p }(); id != idBase {
			t.Logf("%s: note identity also changed (%s->%s) — content hash still required for string/meta edits", name, idBase, id)
		}
		// Restore base and confirm the fingerprint returns to its original value —
		// the hash is a pure function of the source, deterministic across reloads.
		if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte(base), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.Reload(); err != nil {
			t.Fatalf("%s: restore reload: %v", name, err)
		}
		if got := s.Fingerprint(); got != want {
			t.Errorf("%s: fingerprint not restored after reverting to base: got %s want %s", name, got, want)
		}
	}
}

// TestRulesetContentHashDeterministic confirms the content hash depends only on the
// source bytes (not directory iteration order or mtime) so replicas that loaded the
// same bundle share verdict-cache keys.
func TestRulesetContentHashDeterministic(t *testing.T) {
	dir := writeRules(t, eicarRule)
	a := rulesetContentHash("", dir, "", "")
	b := rulesetContentHash("", dir, "", "")
	if a != b {
		t.Fatalf("content hash not stable: %s != %s", a, b)
	}
	// A big-file-set-only change must move the combined hash even when the main set
	// is identical (the bypass the issue called out).
	bigDir := writeRules(t, vbaRule)
	withBig := rulesetContentHash("", dir, "", bigDir)
	if withBig == a {
		t.Fatal("big-file-set-only change did not move the content hash")
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
	m, err := scanT(s, doc, ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m[0].Rule != "VBA_Macro_Attribute" {
		t.Fatalf("macro rule did not fire via decompressed stream: %+v", m)
	}
}

// #5 regression: a VBA-gated rule must fire on the decompressed macro source
// (VBA=true for that stream) but must NOT fire on a non-VBA extracted stream that
// happens to carry the same keyword — here a plain .txt archive member. Before
// the fix every extracted stream scanned with VBA=true, so the archive member
// falsely satisfied the gate (a false positive).
func TestScanVBAGatedOnlyOnMacroStream(t *testing.T) {
	// strip the console import line — newScanner compiles a single rule file and
	// console may be unavailable; keep the rule self-contained.
	rule := `rule VBA_Gated { strings: $kw = "Attribute VB_Name" condition: VBA and $kw }`
	s := newScanner(t, writeRules(t, rule))

	// (a) Macro doc → VBA stream carries the keyword AND VBA is set → fires.
	if m, err := scanT(s, macroDoc(t), ScanMeta{}); err != nil || len(m) != 1 || m[0].Rule != "VBA_Gated" {
		t.Fatalf("(a) VBA-gated rule must fire on the real macro stream: %+v err=%v", m, err)
	}

	// (b) A zip whose member is a plain .txt containing the same keyword →
	// extracted as a NON-VBA archive member → VBA must be false → no match.
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, err := zw.Create("notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("harmless text that mentions Attribute VB_Name in passing")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if m, err := scanT(s, zb.Bytes(), ScanMeta{}); err != nil {
		t.Fatalf("(b) scan error: %v", err)
	} else if len(m) != 0 {
		t.Fatalf("(b) VBA-gated rule wrongly fired on a non-VBA archive member (FP): %+v", m)
	}
}

// The extract counters must move for a macro doc and stay put for a non-doc.
func TestScanExtractMetrics(t *testing.T) {
	s := newScanner(t, writeRules(t, vbaRule))
	if _, err := scanT(s, macroDoc(t), ScanMeta{}); err != nil {
		t.Fatal(err)
	}
	em := s.ExtractMetrics()
	if em.Docs != 1 || em.MacroDocs != 1 || em.Streams < 1 {
		t.Errorf("after macro doc: %+v want Docs=1 MacroDocs=1 Streams>=1", em)
	}
	if em.Failed != 0 || em.Panicked != 0 || em.Encrypted != 0 {
		t.Errorf("macro doc set fail/panic/enc: %+v", em)
	}
	if _, err := scanT(s, []byte("a plain non-document body"), ScanMeta{}); err != nil {
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
	m, err := scanT(s, poison, ScanMeta{})
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
	if m, err := s.scanOne(rules, []byte("x"), scanVars{}, 0); err != nil || len(m) != 0 {
		t.Fatalf("VBA=false (raw) must not match: %+v err=%v", m, err)
	}
	if m, err := s.scanOne(rules, []byte("x"), scanVars{vba: true}, 0); err != nil || len(m) != 1 {
		t.Fatalf("VBA=true (macro stream) must match: %+v err=%v", m, err)
	}
}

// A rule whose ONLY condition is the filename external variable must be inert
// with no filename and fire when ScanMeta carries a matching name — the whole
// point of the feature (THOR/Loki name-keyed rules). The body bytes are clean,
// so a match can only come from the external variable.
func TestScanFilenameExternalVariable(t *testing.T) {
	s := newScanner(t, writeRules(t, `rule Bad_Ext { condition: filename matches /\.exe$/ }`))
	clean := []byte("a perfectly innocent email body")
	if m, err := scanT(s, clean, ScanMeta{}); err != nil || len(m) != 0 {
		t.Fatalf("no filename must not match: %+v err=%v", m, err)
	}
	if m, err := scanT(s, clean, NewScanMeta("invoice.txt")); err != nil || len(m) != 0 {
		t.Fatalf("non-.exe filename must not match: %+v err=%v", m, err)
	}
	if m, err := scanT(s, clean, NewScanMeta("invoice.exe")); err != nil || len(m) != 1 || m[0].Rule != "Bad_Ext" {
		t.Fatalf(".exe filename must match: %+v err=%v", m, err)
	}
}

// The extension external variable (lowercased, dot included) must drive a rule
// independently of filename, including on a mixed-case name.
func TestScanExtensionExternalVariable(t *testing.T) {
	s := newScanner(t, writeRules(t, `rule Bad_Scr { condition: extension == ".scr" }`))
	clean := []byte("a perfectly innocent email body")
	if m, err := scanT(s, clean, NewScanMeta("greeting.GIF")); err != nil || len(m) != 0 {
		t.Fatalf(".gif must not match .scr rule: %+v err=%v", m, err)
	}
	if m, err := scanT(s, clean, NewScanMeta("greeting.SCR")); err != nil || len(m) != 1 {
		t.Fatalf("uppercase .SCR must normalize to .scr and match: %+v err=%v", m, err)
	}
}

// InQuest's Outlook-message rule uses `file_type contains "outlook"` rather
// than THOR/Loki's `filetype`. Only .msg/.oft names get that narrow hint.
func TestScanFileTypeExternalVariable(t *testing.T) {
	s := newScanner(t, writeRules(t, `rule Outlook_Type { condition: file_type contains "outlook" }`))
	clean := []byte("a perfectly innocent email body")
	if m, err := scanT(s, clean, NewScanMeta("invoice.txt")); err != nil || len(m) != 0 {
		t.Fatalf(".txt must not set outlook file_type: %+v err=%v", m, err)
	}
	if m, err := scanT(s, clean, NewScanMeta("message.MSG")); err != nil || len(m) != 1 {
		t.Fatalf(".MSG must set file_type=outlook and match: %+v err=%v", m, err)
	}
}

func TestNewScanMeta(t *testing.T) {
	cases := []struct {
		in           string
		wantName     string
		wantExt      string
		wantFileType string
	}{
		{"", "", "", ""},
		{"invoice.exe", "invoice.exe", ".exe", ""},
		{"Invoice.EXE", "Invoice.EXE", ".exe", ""},              // name case kept, ext lowered
		{`C:\Users\bob\payload.scr`, "payload.scr", ".scr", ""}, // windows path stripped
		{"/var/mail/report.PDF", "report.PDF", ".pdf", ""},      // unix path stripped
		{"archive.tar.gz", "archive.tar.gz", ".gz", ""},         // last extension only
		{"message.MSG", "message.MSG", ".msg", "outlook"},       // InQuest file_type hint
		{"template.oft", "template.oft", ".oft", "outlook"},     // Outlook template
		{".bashrc", ".bashrc", "", ""},                          // leading-dot = no extension
		{"trailingdot.", "trailingdot.", "", ""},                // trailing dot = no extension
		{"noext", "noext", "", ""},                              // no dot
		{"bad\r\nname.exe", "badname.exe", ".exe", ""},          // control chars stripped
		{"  spaced.doc  ", "spaced.doc", ".doc", ""},            // trimmed
	}
	for _, c := range cases {
		got := NewScanMeta(c.in)
		if got.Filename != c.wantName || got.Extension != c.wantExt || got.FileType != c.wantFileType {
			t.Errorf("NewScanMeta(%q) = {%q,%q,%q}, want {%q,%q,%q}", c.in, got.Filename, got.Extension, got.FileType, c.wantName, c.wantExt, c.wantFileType)
		}
	}
	// Over-length name is capped to maxFilenameLen.
	long := strings.Repeat("a", maxFilenameLen+50) + ".exe"
	if got := NewScanMeta(long); len(got.Filename) != maxFilenameLen {
		t.Errorf("over-length name not capped: len=%d want %d", len(got.Filename), maxFilenameLen)
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

// ModUnix must reflect the on-disk mtime of the loaded rules so staleness of a
// silently-broken daily rebuild is observable.
func TestReloadMetricsModUnix(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScanner(t, dir)
	if mu := s.ReloadMetrics().ModUnix; mu <= 0 {
		t.Fatalf("ModUnix not set after load: %d", mu)
	}
	// Newest source file wins: a freshly-touched second file moves the mtime up.
	old := s.ReloadMetrics().ModUnix
	fresh := filepath.Join(dir, "newer.yar")
	if err := os.WriteFile(fresh, []byte(eicarRule), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(fresh, future, future); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if mu := s.ReloadMetrics().ModUnix; mu <= old {
		t.Errorf("ModUnix did not track the newest file: got %d want > %d", mu, old)
	}
}

// A precompiled .yac bundle path reports that file's mtime; a missing/empty
// source reports 0 (unknown) rather than a bogus age.
func TestRulesetModUnix(t *testing.T) {
	dir := writeRules(t, eicarRule)
	if got := rulesetModUnix("", dir); got <= 0 {
		t.Errorf("dir mtime should be >0, got %d", got)
	}
	if got := rulesetModUnix("/nonexistent/file.yac", ""); got != 0 {
		t.Errorf("missing bundle should be 0, got %d", got)
	}
	if got := rulesetModUnix("", "/nonexistent/dir"); got != 0 {
		t.Errorf("missing dir should be 0, got %d", got)
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

	// Identity is namespace+name, not name alone: a stream-only rule whose
	// identifier collides with an UNRELATED raw match in a different namespace must
	// be KEPT (public rulesets reuse rule names across files). Same namespace+name
	// is still deduped.
	rawNs := []Match{{Rule: "Dropper", Namespace: "fileA.yar"}}
	merged := mergeMatches(rawNs, []Match{
		{Rule: "Dropper", Namespace: "fileB.yar"}, // different rule, same name -> keep
		{Rule: "Dropper", Namespace: "fileA.yar"}, // exact same rule -> dedup
	})
	if len(merged) != 2 {
		t.Fatalf("namespace dedup wrong: got %d matches, want 2 (%+v)", len(merged), merged)
	}
	if merged[1].Namespace != "fileB.yar" {
		t.Errorf("cross-namespace same-name match was dropped: %+v", merged)
	}
}

// TestScanRaceReload (STAB-10) hammers concurrent Scan() calls while Reload()
// and ReloadDenylist() fire simultaneously. Run with -race to verify no data
// races exist in the scanner pool / rule-generation machinery.
func TestScanRaceReload(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	benign := []byte("a perfectly innocent email body")
	benignDigest := sha256.Sum256(benign)

	n := runtime.NumCPU()
	if n < 2 {
		n = 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup

	// N goroutines scanning continuously until context expires.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_, err := s.Scan(benign, benignDigest, ScanMeta{})
				if err != nil {
					// Transient errors (pool exhaustion, rules reloading) are
					// expected under concurrent reload pressure — skip them.
					continue
				}
			}
		}()
	}

	// Fire Reload() several times while scans run.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = s.Reload() // errors are fine; old ruleset stays active
			time.Sleep(30 * time.Millisecond)
		}
	}()

	// Fire ReloadDenylist() at least once while scans run.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.ReloadDenylist()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	wg.Wait()
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

// TestStreamDeduplication verifies that identical extracted streams are skipped
// before YARA scanning and counted in the Deduped metric. The fixture
// (dup_vba_streams.xlsm) is a zip with two identical vbaProject.bin entries,
// which the extractor decompresses into 4+4 = 8 streams where streams 4-7 are
// byte-for-byte copies of streams 0-3. After dedup, only 4 unique streams are
// scanned and the remaining 4 should be counted in exDeduped.
func TestStreamDeduplication(t *testing.T) {
	buf, err := os.ReadFile(filepath.Join("testdata", "dup_vba_streams.xlsm"))
	if err != nil {
		t.Fatalf("fixture unavailable: %v", err)
	}
	// Use a rule that matches the VBA attribute header present in all streams.
	rule := `rule VBA_Attr { strings: $a = "Attribute VB_Name" condition: $a }`
	s := newScanner(t, writeRules(t, rule))
	if s.ExtractMetrics().Deduped != 0 {
		t.Fatal("precondition: Deduped should start at 0")
	}
	if _, err := scanT(s, buf, ScanMeta{}); err != nil {
		t.Fatal(err)
	}
	em := s.ExtractMetrics()
	if em.Deduped == 0 {
		t.Errorf("Deduped = 0 after scanning doc with duplicate streams; want > 0. ExtractMetrics=%+v", em)
	}
}

// TestScanPooledScannerNoExternalLeak guards PERF-2: yara.Scanner objects are
// pooled across scans, so an external set on one scan must not leak into the
// next. Scan a body with filename "x.exe" (matches, sets the filename external,
// returns the scanner to the pool), then scan an IDENTICAL body with NO filename
// on the same Scanner — it must NOT match, proving define() reset the external
// rather than leaving the pooled scanner's stale value.
func TestScanPooledScannerNoExternalLeak(t *testing.T) {
	s := newScanner(t, writeRules(t, `rule Bad_Ext { condition: filename matches /\.exe$/ }`))
	body := []byte("identical clean body bytes")

	// Run several dirty scans first to seed the pool with a scanner whose
	// filename external is "x.exe".
	for i := 0; i < 5; i++ {
		if m, err := scanT(s, body, NewScanMeta("x.exe")); err != nil || len(m) != 1 {
			t.Fatalf(".exe scan %d: %+v err=%v", i, m, err)
		}
	}
	// Now scan with no filename, reusing a pooled scanner. A leak would carry
	// "x.exe" forward and wrongly match.
	for i := 0; i < 5; i++ {
		if m, err := scanT(s, body, ScanMeta{}); err != nil || len(m) != 0 {
			t.Fatalf("no-filename scan %d leaked the pooled external (matched %+v) err=%v", i, m, err)
		}
	}
}

// TestScanPoolSurvivesReload guards the PERF-2 scanner-pool generation handling:
// after a Reload swaps the rules, scans must use the NEW rules — a yara.Scanner
// pooled against the OLD rules must never be reused (it is bound to freed rules).
// Uses a filename-external rule so the pooled-scanner path is exercised.
func TestScanPoolSurvivesReload(t *testing.T) {
	dir := writeRules(t, `rule Old_Ext { condition: filename matches /\.exe$/ }`)
	s := newScanner(t, dir)
	body := []byte("clean body bytes for reload test")

	// Populate the pool with scanners bound to the OLD ruleset.
	for i := 0; i < 4; i++ {
		if m, err := scanT(s, body, NewScanMeta("x.exe")); err != nil || len(m) != 1 {
			t.Fatalf("pre-reload .exe scan: %+v err=%v", m, err)
		}
	}

	// Swap in a DIFFERENT ruleset and reload.
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"),
		[]byte(`rule New_Scr { condition: extension == ".scr" }`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}

	// The OLD rule must be gone; the NEW rule must fire — proving the post-reload
	// scans built fresh scanners against the new rules rather than reusing pooled
	// ones from the retired generation.
	if m, err := scanT(s, body, NewScanMeta("x.exe")); err != nil || len(m) != 0 {
		t.Fatalf("old rule still matched after reload: %+v err=%v", m, err)
	}
	if m, err := scanT(s, body, NewScanMeta("y.scr")); err != nil || len(m) != 1 || m[0].Rule != "New_Scr" {
		t.Fatalf("new rule did not match after reload: %+v err=%v", m, err)
	}
}

// fastModeRule fires when a short string appears anywhere. With a buffer where
// that string repeats thousands of times, FAST_MODE (PERF-15) stops after the
// first hit — the rule must still fire exactly once, identically to a buffer
// where the string appears a single time. yarad reads only the rule-fired SET,
// never per-string offsets/counts, so the matched-rule result is byte-identical
// regardless of how many times the underlying string matched.
const fastModeRule = `
rule FastMode_Repeat
{
    strings:
        $s = "ZZTOKENZZ"
    condition:
        $s
}
`

func TestFastModeMatchSetIdentical(t *testing.T) {
	s := newScanner(t, writeRules(t, fastModeRule))

	single := []byte("prefix ZZTOKENZZ suffix")
	// Many repeats: pre-FAST_MODE libyara would record every offset; FAST_MODE
	// records only the first. The rule-fired set must be identical either way.
	many := bytes.Repeat([]byte("ZZTOKENZZ "), 50000)

	ms, err := scanT(s, single, ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	mm, err := scanT(s, many, ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Rule != "FastMode_Repeat" {
		t.Fatalf("single-match scan = %+v, want one FastMode_Repeat", ms)
	}
	if len(mm) != 1 || mm[0].Rule != "FastMode_Repeat" {
		t.Fatalf("many-match scan = %+v, want one FastMode_Repeat (FAST_MODE must not change the rule set)", mm)
	}
}

// TestFastModeScannerPath exercises the scanner (not bare-rules) branch of
// scanOne — taken when a scan sets an external variable (here: an extension).
// FAST_MODE is set on that path too, so a repeat-heavy buffer must still yield
// the same single rule match.
func TestFastModeScannerPath(t *testing.T) {
	s := newScanner(t, writeRules(t, fastModeRule))
	many := bytes.Repeat([]byte("ZZTOKENZZ "), 50000)
	// NewScanMeta sets a filename/extension → scanVars.needsScanner() true →
	// scanner path with SetFlags(FAST_MODE).
	m, err := scanT(s, many, NewScanMeta("x.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m[0].Rule != "FastMode_Repeat" {
		t.Fatalf("scanner-path many-match = %+v, want one FastMode_Repeat", m)
	}
}
