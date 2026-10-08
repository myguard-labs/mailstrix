package mailstrix

import (
	"os"
	"path/filepath"
	"testing"

	yara "github.com/hillu/go-yara/v4"
)

// TestCanaryTagsAllMatches verifies that with canary=true every match gets
// mailstrix_canary=1 in its Meta map.
func TestCanaryTagsAllMatches(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{RulesDir: dir, ScanTimeout: 0, Canary: true}
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
		t.Fatalf("expected 1 match, got %d", len(m))
	}
	if m[0].Meta["mailstrix_canary"] != "1" {
		t.Errorf("canary match not tagged: meta=%v", m[0].Meta)
	}
}

// TestCanaryOffNoTag verifies that with canary=false matches do NOT get
// mailstrix_canary.
func TestCanaryOffNoTag(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{RulesDir: dir, ScanTimeout: 0, Canary: false}
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
		t.Fatalf("expected 1 match, got %d", len(m))
	}
	if _, ok := m[0].Meta["mailstrix_canary"]; ok {
		t.Errorf("canary tag present when canary is off: meta=%v", m[0].Meta)
	}
}

// TestCanaryEnvParsing verifies MAILSTRIX_CANARY env parsing.
func TestCanaryEnvParsing(t *testing.T) {
	t.Setenv("MAILSTRIX_CANARY", "1")
	c := LoadConfig()
	if !c.Canary {
		t.Error("MAILSTRIX_CANARY=1 should set Canary=true")
	}
}

func TestCanaryTagsFeedMatches(t *testing.T) {
	s := newURLhausScannerCanary(t, true)
	defer s.Close()

	matches, err := scanT(s, []byte(feedURLBody), ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	fm := feedMatches(matches)
	if len(fm) == 0 {
		t.Fatal("precondition: URLhaus feed must match the test URL")
	}
	for _, m := range fm {
		if m.Meta["mailstrix_canary"] != "1" {
			t.Fatalf("feed match missing canary metadata: %+v", m)
		}
	}
}

func TestFingerprintFoldsScoringPolicy(t *testing.T) {
	dir := writeRules(t, eicarRule)
	mk := func(canary bool, allow map[string]struct{}) *Scanner {
		t.Helper()
		cfg := &Config{RulesDir: dir, ScanTimeout: 0, Canary: canary, RuleAllowlist: allow}
		cfg.sanitize()
		s, err := NewScanner(cfg, func(string, ...any) {})
		if err != nil {
			t.Fatalf("NewScanner: %v", err)
		}
		return s
	}

	base := mk(false, nil).Fingerprint()
	if got := mk(true, nil).Fingerprint(); got == base {
		t.Fatal("canary policy did not move Fingerprint; cached response metadata could cross modes")
	}
	allow := map[string]struct{}{"eicar_test_file": {}}
	if got := mk(false, allow).Fingerprint(); got == base {
		t.Fatal("allowlist policy did not move Fingerprint; cached response metadata could cross policies")
	}
	allowSame := map[string]struct{}{"eicar_test_file": {}}
	if a, b := mk(false, allow).Fingerprint(), mk(false, allowSame).Fingerprint(); a != b {
		t.Fatalf("same allowlist policy must hash deterministically: %s != %s", a, b)
	}
}

func TestActionableMatchesSkipsLogOnlyWithoutMutatingInput(t *testing.T) {
	in := []Match{
		{Rule: "A", Meta: map[string]string{"mailstrix_canary": "1"}},
		{Rule: "B"},
		{Rule: "C", Meta: map[string]string{"mailstrix_allow": "1"}},
	}
	got := actionableMatches(in)
	if len(got) != 1 || got[0].Rule != "B" {
		t.Fatalf("actionableMatches = %+v, want only B", got)
	}
	if in[0].Rule != "A" || in[1].Rule != "B" || in[2].Rule != "C" {
		t.Fatalf("actionableMatches mutated input slice: %+v", in)
	}
	if got := actionableMatches([]Match{{Rule: "A"}, {Rule: "B"}}); len(got) != 2 {
		t.Fatalf("all-actionable case changed length: %+v", got)
	}
}

// TestReloadAllMergesFile verifies that ReloadAll reads a file and
// merges its entries with the env-based baseDenylist.
func TestReloadAllMergesFile(t *testing.T) {
	dir := writeRules(t, eicarRule)
	// Write a denylist file with one rule name.
	denyFile := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(denyFile, []byte("# comment\n\nFromFile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		RulesDir:     dir,
		ScanTimeout:  0,
		RuleDenylist: map[string]struct{}{"fromenv": {}},
		DenylistFile: denyFile,
	}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	// Both env and file entries should be in the merged denylist.
	if _, ok := (*s.denylist.Load())["fromenv"]; !ok {
		t.Error("env denylist entry missing after merge")
	}
	if _, ok := (*s.denylist.Load())["fromfile"]; !ok {
		t.Error("file denylist entry missing after merge (should be lowercased)")
	}
}

// TestReloadAllMissingFile verifies that a missing denylist file logs a
// warning but does not crash (fail-open).
func TestReloadAllMissingFile(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{
		RulesDir:     dir,
		ScanTimeout:  0,
		RuleDenylist: map[string]struct{}{"fromenv": {}},
		DenylistFile: filepath.Join(t.TempDir(), "nonexistent.txt"),
	}
	cfg.sanitize()
	var warned bool
	logf := func(format string, a ...any) {
		if len(format) > 7 && format[:7] == "WARNING" {
			warned = true
		}
	}
	s, err := NewScanner(cfg, logf)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if !warned {
		t.Error("expected a warning for missing denylist file")
	}
	// Env denylist should still be intact.
	if _, ok := (*s.denylist.Load())["fromenv"]; !ok {
		t.Error("env denylist lost after missing-file reload")
	}
}

// TestReloadAllNoFile verifies that with no DenylistFile configured,
// ReloadAll is a no-op.
func TestReloadAllNoFile(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{
		RulesDir:     dir,
		ScanTimeout:  0,
		RuleDenylist: map[string]struct{}{"fromenv": {}},
	}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	// Calling again should be a no-op (no file configured).
	if err := s.ReloadAll(); err != nil {
		t.Fatal(err)
	}
	if _, ok := (*s.denylist.Load())["fromenv"]; !ok {
		t.Error("env denylist entry should still be present")
	}
}

// TestDenylistFileEnvParsing verifies MAILSTRIX_DENYLIST_FILE env parsing.
func TestDenylistFileEnvParsing(t *testing.T) {
	t.Setenv("MAILSTRIX_DENYLIST_FILE", "/tmp/deny.txt")
	c := LoadConfig()
	if c.DenylistFile != "/tmp/deny.txt" {
		t.Errorf("DenylistFile = %q, want /tmp/deny.txt", c.DenylistFile)
	}
}

// ReloadAll must compile the main rule set once per reload while still applying
// the freshly re-read denylist file (AUD-N5). Reload followed by ReloadDenylist
// is the old double-compile sequence and serves as the negative control.
func TestReloadAllCompilesOnceWithDenylist(t *testing.T) {
	orig := compileRuleFiles
	compiles := 0
	compileRuleFiles = func(dir string, files []string, logf func(string, ...any)) (*yara.Rules, error) {
		compiles++
		return orig(dir, files, logf)
	}
	t.Cleanup(func() { compileRuleFiles = orig })

	denyFile := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(denyFile, []byte("# none yet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{RulesDir: writeRules(t, eicarRule), DenylistFile: denyFile}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if compiles != 1 {
		t.Fatalf("NewScanner compiled %d times, want 1", compiles)
	}
	if m, _ := s.Scan(eicar(), ScanMeta{}); len(m) == 0 {
		t.Fatal("EICAR should fire before it is denied")
	}

	if err := os.WriteFile(denyFile, []byte("EICAR_Test_File\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	compiles = 0
	if err := s.ReloadAll(); err != nil {
		t.Fatal(err)
	}
	if compiles != 1 {
		t.Fatalf("ReloadAll compiled %d times, want 1", compiles)
	}
	if m, _ := s.Scan(eicar(), ScanMeta{}); len(m) != 0 {
		t.Fatalf("denylisted rule still fires after ReloadAll: %v", m)
	}

	// Negative control: Reload() then ReloadAll() compiles twice (proves counter counts every compile).
	compiles = 0
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := s.ReloadAll(); err != nil {
		t.Fatal(err)
	}
	if compiles != 2 {
		t.Fatalf("Reload+ReloadAll compiled %d times, want 2", compiles)
	}

	// Unreadable denylist file falls back to a single plain reload.
	if err := os.Remove(denyFile); err != nil {
		t.Fatal(err)
	}
	compiles = 0
	if err := s.ReloadAll(); err != nil {
		t.Fatal(err)
	}
	if compiles != 1 {
		t.Fatalf("ReloadAll with missing file compiled %d times, want 1", compiles)
	}
}
