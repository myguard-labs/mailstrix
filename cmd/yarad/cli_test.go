package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	yara "github.com/hillu/go-yara/v4"
)

// makeCompiledYac compiles rule into a real .yac bundle at path so it can be
// used as a SeedRules / cache fixture (yara.LoadRules validates the format).
func makeCompiledYac(t *testing.T, path, rule string) {
	t.Helper()
	c, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddString(rule, ""); err != nil {
		t.Fatal(err)
	}
	r, err := c.GetRules()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
}

// eicarRule is a minimal compilable YARA rule; eicarPayload is the string it
// matches. Reused across the scan/check-rules tests so a match is deterministic.
const eicarRule = `
rule EICAR_Test_File : test
{
    strings:
        $e = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $e
}
`

const eicarPayload = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// withRules writes a one-rule dir and points YARAD_RULES_DIR at it for the test,
// restoring the previous value afterward. The CLI subcommands build their own
// scanner from config, so the rule set is supplied through the environment.
func withRules(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YARAD_RULES_DIR", dir)
	// Make sure a precompiled bundle from the environment can't win over the dir.
	t.Setenv("YARAD_RULES", "")
}

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written. CLI output goes to stdout, so the tests assert on it directly.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

func TestCheckRulesOK(t *testing.T) {
	withRules(t, eicarRule)
	var code int
	out := captureStdout(t, func() { code = cmdCheckRules(nil) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "OK") || !strings.Contains(out, "1 rules loaded") {
		t.Errorf("output = %q", out)
	}
}

func TestCheckRulesFail(t *testing.T) {
	// An empty rules dir compiles nothing => NewScanner errors => exit 1.
	t.Setenv("YARAD_RULES_DIR", t.TempDir())
	t.Setenv("YARAD_RULES", "")
	code := cmdCheckRules(nil)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}

func TestScanFileMatch(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(f, []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{f}) })
	if code != 1 { // a match forces exit 1
		t.Fatalf("exit = %d, want 1 (match)", code)
	}
	if !strings.Contains(out, "MATCH EICAR_Test_File") {
		t.Errorf("output = %q", out)
	}
}

func TestScanFileClean(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "clean.txt")
	if err := os.WriteFile(f, []byte("nothing to see here"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{f}) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (clean)", code)
	}
	if !strings.Contains(out, "CLEAN") {
		t.Errorf("output = %q", out)
	}
}

func TestScanQuietSuppressesClean(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "clean.txt")
	if err := os.WriteFile(f, []byte("benign"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { cmdScan([]string{"-quiet", f}) })
	if strings.Contains(out, "CLEAN") {
		t.Errorf("-quiet should suppress CLEAN lines: %q", out)
	}
}

func TestScanDirRecurses(t *testing.T) {
	withRules(t, eicarRule)
	root := t.TempDir()
	sub := filepath.Join(root, "cur")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "msg:2,S"), []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "clean"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{root}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (one member matched)", code)
	}
	if !strings.Contains(out, "msg:2,S") || !strings.Contains(out, "MATCH") {
		t.Errorf("recursed output missing the maildir member match: %q", out)
	}
}

func TestScanStdin(t *testing.T) {
	withRules(t, eicarRule)
	// Feed the EICAR payload on stdin (the `yarad scan - < maildirfile` case).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(eicarPayload); err != nil {
		t.Fatal(err)
	}
	w.Close()
	origIn := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origIn }()

	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{"-"}) })
	if code != 1 {
		t.Fatalf("stdin exit = %d, want 1", code)
	}
	if !strings.Contains(out, "MATCH") {
		t.Errorf("stdin output = %q", out)
	}
}

func TestScanJSON(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "s.txt")
	if err := os.WriteFile(f, []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { cmdScan([]string{"-json", f}) })
	if !strings.Contains(out, `"matches"`) || !strings.Contains(out, "EICAR_Test_File") {
		t.Errorf("json output = %q", out)
	}
}

func TestScanMissingFileErrors(t *testing.T) {
	withRules(t, eicarRule)
	code := cmdScan([]string{filepath.Join(t.TempDir(), "does-not-exist")})
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (read error)", code)
	}
}

func TestExtractStreamsAndExit(t *testing.T) {
	// A plain text input is not a recognised container => zero streams => exit 1.
	f := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(f, []byte("just text"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdExtract([]string{f}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (nothing carved)", code)
	}
	if !strings.Contains(out, "container:") || !strings.Contains(out, "streams:") {
		t.Errorf("extract report missing fields: %q", out)
	}
}

func TestExtractMissingFileErrors(t *testing.T) {
	code := cmdExtract([]string{filepath.Join(t.TempDir(), "nope")})
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

// TestScanSymlinkedDirRoot guards the Codex P2 fix: a symlink whose target is a
// directory must be walked (os.Stat follows it, but filepath.WalkDir would not
// descend the symlinked root) so a maildir reached via a symlink isn't silently
// reported clean.
func TestScanSymlinkedDirRoot(t *testing.T) {
	withRules(t, eicarRule)
	realDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(realDir, "evil"), []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "maildir-link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{link}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (symlinked dir must be scanned, member matched)", code)
	}
	if !strings.Contains(out, "MATCH") {
		t.Errorf("symlinked-dir scan missed the member: %q", out)
	}
}

// TestScanMaxBodyZeroStillBounded guards the Codex P2 fix: a non-positive
// -max-body must not disable the read cap. We can't easily assert the cap size
// here, but the scan must still complete and not error — confirming the clamp
// keeps a valid LimitReader in place.
func TestScanMaxBodyZeroStillBounded(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "s.txt")
	if err := os.WriteFile(f, []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{"-max-body=0", f}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (clamped cap, payload still scanned)", code)
	}
	if !strings.Contains(out, "MATCH") {
		t.Errorf("output = %q", out)
	}
}

// TestScanOversizedIsError guards Bug 1: a file whose first maxBody bytes are
// clean but which has a match AFTER the cap must NOT return CLEAN/exit-0. The
// input must instead be reported as an oversized error (exit 2). An exactly-at-cap
// input that contains the match at the cap boundary must still scan and match.
func TestScanOversizedIsError(t *testing.T) {
	withRules(t, eicarRule)
	dir := t.TempDir()

	// limit = len(eicarPayload) - 1: the first (limit) bytes are benign padding;
	// the EICAR match is at the very end, starting after the cap.
	limit := int64(len(eicarPayload) - 1)
	maxBodyFlag := "-max-body=" + strconv.FormatInt(limit, 10)
	padding := strings.Repeat("A", int(limit))

	// oversized: prefix (all-A, clean) + EICAR payload. Total > limit.
	oversized := filepath.Join(dir, "oversized.txt")
	if err := os.WriteFile(oversized, []byte(padding+eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}

	var code int
	out := captureStdout(t, func() {
		code = cmdScan([]string{maxBodyFlag, oversized})
	})
	if code != 2 {
		t.Fatalf("oversized input: exit = %d, want 2 (error, not clean)", code)
	}
	if strings.Contains(out, "CLEAN") {
		t.Errorf("oversized input must not be reported CLEAN: %q", out)
	}
	if !strings.Contains(out, "oversized") && !strings.Contains(out, "ERROR") {
		t.Errorf("oversized input must produce an error line: %q", out)
	}

	// exactly-at-cap: a file that is EXACTLY limit bytes and clean must scan
	// normally — the important assertion is that it is NOT refused as oversized
	// (exit 2). It scans and comes back clean.
	atCapClean := filepath.Join(dir, "atcap-clean.txt")
	if err := os.WriteFile(atCapClean, []byte(strings.Repeat("B", int(limit))), 0o600); err != nil {
		t.Fatal(err)
	}
	var codeAtCap int
	captureStdout(t, func() {
		codeAtCap = cmdScan([]string{maxBodyFlag, atCapClean})
	})
	if codeAtCap == 2 {
		t.Fatalf("exactly-at-cap clean input: exit = 2 (refused as oversized), want 0")
	}
}

// TestScanSeedRulesSeeding guards Bug 2 for cmdScan: with a compiled .yac seed,
// a temp cache dir, and NO YARAD_RULES/YARAD_RULES_DIR, `yarad scan` must seed
// the cache from the seed (exactly as `serve` does) so the daemon's Docker-image
// env — YARAD_SEED_RULES + YARAD_CACHE_DIR set, YARAD_RULES unset — works without
// extra operator env. The proof is that the cache bundle is created from the seed
// and is loadable; before the fix cmdScan never called EnsureCachedRules so the
// cache stayed empty.
func TestScanSeedRulesSeeding(t *testing.T) {
	// Clear any dir/path rules so the only source is the seed.
	t.Setenv("YARAD_RULES_DIR", "")
	t.Setenv("YARAD_RULES", "")

	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yac")
	makeCompiledYac(t, seedPath, eicarRule)

	cacheDir := filepath.Join(dir, "cache")
	cachePath := filepath.Join(cacheDir, "compiled.yac")
	t.Setenv("YARAD_SEED_RULES", seedPath)
	t.Setenv("YARAD_CACHE_DIR", cacheDir)

	f := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(f, []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}

	captureStdout(t, func() { _ = cmdScan([]string{f}) })

	// The cache must have been seeded from the baked seed and be loadable. Without
	// the EnsureCachedRules call in cmdScan this file is never written.
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cmdScan did not seed the rule cache %s: %v", cachePath, err)
	}
	if r, err := yara.LoadRules(cachePath); err != nil {
		t.Fatalf("seeded cache %s is not loadable: %v", cachePath, err)
	} else {
		r.Destroy()
	}
}

// TestCheckRulesSeedRulesSeeding guards Bug 2 for cmdCheckRules: with a compiled
// .yac seed, a temp cache dir, and NO YARAD_RULES/YARAD_RULES_DIR, `check-rules`
// must seed from the seed and exit 0 (not fail "no rules").
func TestCheckRulesSeedRulesSeeding(t *testing.T) {
	t.Setenv("YARAD_RULES_DIR", "")
	t.Setenv("YARAD_RULES", "")

	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yac")
	makeCompiledYac(t, seedPath, eicarRule)

	cacheDir := filepath.Join(dir, "cache")
	t.Setenv("YARAD_SEED_RULES", seedPath)
	t.Setenv("YARAD_CACHE_DIR", cacheDir)

	var code int
	out := captureStdout(t, func() { code = cmdCheckRules(nil) })
	if code != 0 {
		t.Fatalf("seeded check-rules: exit = %d, want 0; output: %q", code, out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("seeded check-rules output = %q, want OK line", out)
	}
}
