package mailstrix

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := ruleFiles(missing); err == nil {
		t.Fatal("missing dir must error")
	} else {
		want := fmt.Sprintf("read rules dir %s: open %s: no such file or directory", missing, missing)
		if err.Error() != want {
			t.Fatalf("missing dir error = %q, want %q", err, want)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing dir error must wrap os.ErrNotExist: %v", err)
		}
	}
	empty := t.TempDir()
	if _, err := ruleFiles(empty); err == nil {
		t.Fatal("dir without rule files must error")
	} else if want := fmt.Sprintf("no *.yar/*.yara files in %s", empty); err.Error() != want {
		t.Fatalf("empty dir error = %q, want %q", err, want)
	}
}

func TestRuleFilesSuffixSemantics(t *testing.T) {
	dir := t.TempDir()
	entries := []string{
		".yar",
		".yara",
		"a.yar",
		"b.yara",
		"both.yar.yara",
		"UPPER.YAR",
		"mixed.Yar",
		"no-dot-yar",
		"x.yar.bak",
		"y.yaraa",
	}
	for _, name := range entries {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "directory.yar"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := ruleFiles(dir)
	if err != nil {
		t.Fatalf("ruleFiles: %v", err)
	}
	wantNames := []string{".yar", ".yara", "a.yar", "b.yara", "both.yar.yara", "directory.yar"}
	want := make([]string, len(wantNames))
	for i, name := range wantNames {
		want[i] = filepath.Join(dir, name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ruleFiles = %v, want %v", got, want)
	}
}

func BenchmarkRuleFileSuffixPass(b *testing.B) {
	dir := b.TempDir()
	for i := 0; i < 256; i++ {
		name := fmt.Sprintf("rule-%03d.txt", i)
		switch i % 8 {
		case 0:
			name += ".yar"
		case 1:
			name += ".yara"
		}
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("legacy-two-match-passes", func(b *testing.B) {
		for b.Loop() {
			files := make([]string, 0, len(entries)/4)
			for _, pattern := range []string{"*.yar", "*.yara"} {
				for _, entry := range entries {
					if ok, _ := filepath.Match(pattern, entry.Name()); ok {
						files = append(files, filepath.Join(dir, entry.Name()))
					}
				}
			}
			sort.Strings(files)
		}
	})
	b.Run("single-suffix-pass", func(b *testing.B) {
		for b.Loop() {
			files := make([]string, 0, len(entries)/4)
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasSuffix(name, ".yar") || strings.HasSuffix(name, ".yara") {
					files = append(files, filepath.Join(dir, name))
				}
			}
			sort.Strings(files)
		}
	})
}
