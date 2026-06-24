package extract

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// localRulesDir locates docker/local-rules/ relative to the test working dir.
// Mirrors the path-probe shape in js_obfuscation_rule_test.go (the unit suite
// does not link libyara, so we lint the rule SOURCE; compile+match runs in the
// Docker `full` CI stage).
func localRulesDir(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules",
		"../../../docker/local-rules",
		"../../docker/local-rules",
	} {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
	}
	t.Skip("docker/local-rules not found relative to test dir")
	return ""
}

// reDotClassUnbounded matches the catastrophic-backtracking shape that bit the
// $url rules: a character class CONTAINING a dot, quantified by an unbounded
// `+`/`*`, immediately followed by a literal `\.` — the class overlaps its own
// follower, so a long run of dot-class bytes with no valid suffix forces the
// engine to retry every split point (quadratic). Bounding the quantifier
// (e.g. {1,253}) makes the backtrack linear and defuses it.
//
// Detects `[...\.]+\.` and `[...\.]*\.` (the `.` inside the class may be written
// `\.` or a bare `.`). Bounded `{m,n}` forms do not match and are accepted.
var reDotClassUnbounded = regexp.MustCompile(`\[[^\]]*\\?\.[^\]]*\][+*]\\?\.`)

func TestLocalRules_NoUnboundedDotClassOverlap(t *testing.T) {
	dir := localRulesDir(t)
	matches, _ := filepath.Glob(filepath.Join(dir, "*.yara"))
	if len(matches) == 0 {
		t.Skip("no .yara files found")
	}
	for _, f := range matches {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if loc := reDotClassUnbounded.FindIndex(b); loc != nil {
			t.Errorf("%s contains an unbounded dot-class overlapping a literal '.' "+
				"(%q) — quadratic-backtracking risk; bound the quantifier, e.g. {1,253}",
				filepath.Base(f), b[loc[0]:loc[1]])
		}
	}
}

// TestLocalRules_URLRegexBounded asserts the two $url rules carry the bounded
// form, so the fix can't silently regress to the bare `+` overlap.
func TestLocalRules_URLRegexBounded(t *testing.T) {
	dir := localRulesDir(t)
	for _, name := range []string{"docprops.yara", "userform_strings.yara"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Skipf("%s not present: %v", name, err)
			continue
		}
		reBounded := regexp.MustCompile(`\$url\s*=\s*/https\?.*\{1,253\}`)
		if !reBounded.Match(b) {
			t.Errorf("%s $url is not length-bounded ({1,253}) — backtracking-hardening regressed", name)
		}
	}
}
