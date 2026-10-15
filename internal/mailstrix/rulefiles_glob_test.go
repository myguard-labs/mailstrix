package mailstrix

import (
	"os"
	"path/filepath"
	"testing"
)

// ruleFiles must list rule files by directory entry, not by a glob built from
// the operator's directory path: a rules dir whose name contains glob
// metacharacters ("[", "*", "?") would otherwise yield ErrBadPattern or a
// mismatch and read as "no rule files".
func TestRuleFilesDirWithGlobMetacharacters(t *testing.T) {
	for _, name := range []string{"rules[v2", "rules[a-b]", "rules*x", "rules?"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), name)
			if err := os.Mkdir(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			for _, f := range []string{"b.yara", "a.yar", "skip.txt", "x.yar.bak"} {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := ruleFiles(dir)
			if err != nil {
				t.Fatalf("ruleFiles: %v", err)
			}
			want := []string{filepath.Join(dir, "a.yar"), filepath.Join(dir, "b.yara")}
			if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
				t.Fatalf("got %v want %v", got, want)
			}
		})
	}
}

func TestRuleFilesErrors(t *testing.T) {
	if _, err := ruleFiles(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing dir must error")
	}
	empty := t.TempDir()
	if _, err := ruleFiles(empty); err == nil {
		t.Fatal("dir without rule files must error")
	}
}
