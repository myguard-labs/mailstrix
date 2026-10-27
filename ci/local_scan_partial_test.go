package ci_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func localScanBinary(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "strixd")
	cmd := exec.Command("go", "build", "-race", "-o", path, "./cmd/strixd") // #nosec G204 -- fixed tool and test-owned output path
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build race-enabled strixd: %v\n%s", err, out)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("race-enabled strixd path=%s size=%d mtime=%s", path, info.Size(), info.ModTime().UTC().Format("2006-01-02T15:04:05.000000000Z"))
	return path
}

func localScanRules(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rule := `rule LocalPartialHit { strings: $a = "LOCAL_PARTIAL_HIT" condition: $a }`
	if err := os.WriteFile(filepath.Join(dir, "fixture.yar"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func localScanZIP(t *testing.T, knownHit bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "partial.zip")
	f, err := os.Create(path) // #nosec G304 -- test owns the temporary path
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for i := range 40 {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:   fmt.Sprintf("%02d.txt", i),
			Method: zip.Store,
		})
		if err != nil {
			t.Fatal(err)
		}
		marker := "ordinary"
		if knownHit {
			marker = "LOCAL_PARTIAL_HIT"
		}
		if _, err := fmt.Fprintf(w, "%s %04d %s", marker, i, strings.Repeat("z", 128)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func runLocalScan(t *testing.T, binary, rules string, args ...string) (string, string, int) {
	t.Helper()
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- the test creates the binary and supplies every argument.
	cmd := exec.Command(binary, append([]string{"scan"}, args...)...) // #nosec G204 -- test-owned binary and literal test arguments
	cmd.Env = append(os.Environ(),
		"MAILSTRIX_RULES=",
		"MAILSTRIX_RULES_DIR="+rules,
		"MAILSTRIX_CACHE_DIR=",
		"MAILSTRIX_SEED_RULES=",
		"MAILSTRIX_EXTRACTION_RETAINED_BYTES=1024",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run strixd scan: %v", err)
	}
	return stdout.String(), stderr.String(), exitErr.ExitCode()
}

func TestLocalScanPartialKeepsKnownMatch(t *testing.T) {
	rules := localScanRules(t)
	stdout, stderr, code := runLocalScan(t, localScanBinary(t), rules, "-json", localScanZIP(t, true))
	if code != 2 {
		t.Fatalf("partial scan exit=%d, want 2; stderr=%q", code, stderr)
	}
	var items []struct {
		Matches []struct {
			Rule string `json:"rule"`
		} `json:"matches"`
		Err string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &items); err != nil {
		t.Fatalf("decode partial JSON %q: %v", stdout, err)
	}
	if len(items) != 1 || !strings.Contains(items[0].Err, "scan incomplete") {
		t.Fatalf("partial JSON lost scan error: %+v", items)
	}
	for _, match := range items[0].Matches {
		if match.Rule == "LocalPartialHit" {
			return
		}
	}
	t.Fatalf("partial JSON lost known match: %+v", items[0])
}

func TestLocalScanPartialText(t *testing.T) {
	stdout, stderr, code := runLocalScan(t, localScanBinary(t), localScanRules(t), "-quiet", localScanZIP(t, true))
	if code != 2 {
		t.Fatalf("partial scan exit=%d, want 2; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "MATCH LocalPartialHit") || !strings.Contains(stdout, "ERROR scan incomplete") {
		t.Fatalf("partial text lost known match or error: %q", stdout)
	}
}

func TestLocalScanJSONControls(t *testing.T) {
	binary := localScanBinary(t)
	rules := localScanRules(t)
	t.Run("partial-without-actionable-match", func(t *testing.T) {
		stdout, stderr, code := runLocalScan(t, binary, rules, "-json", localScanZIP(t, false))
		if code != 2 {
			t.Fatalf("partial scan exit=%d, want 2; stderr=%q", code, stderr)
		}
		if !strings.Contains(stdout, `"error": "scan incomplete`) || strings.Contains(stdout, `"rule": "LocalPartialHit"`) {
			t.Fatalf("partial scan without actionable hit=%q", stdout)
		}
	})
	for _, tc := range []struct {
		name     string
		body     string
		maxBody  int
		wantCode int
		wantRule bool
		wantErr  string
	}{
		{name: "known-match", body: "LOCAL_PARTIAL_HIT", maxBody: 1024, wantCode: 1, wantRule: true},
		{name: "clean-exact-boundary", body: "safe", maxBody: 4},
		{name: "one-over-boundary", body: "safe!", maxBody: 4, wantCode: 2, wantErr: "oversized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, code := runLocalScan(t, binary, rules, "-json", fmt.Sprintf("-max-body=%d", tc.maxBody), path)
			if code != tc.wantCode {
				t.Fatalf("exit=%d want=%d; stderr=%q", code, tc.wantCode, stderr)
			}
			var items []struct {
				Matches []struct {
					Rule string `json:"rule"`
				} `json:"matches"`
				Err string `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &items); err != nil || len(items) != 1 {
				t.Fatalf("JSON=%q items=%d err=%v", stdout, len(items), err)
			}
			gotRule := false
			for _, match := range items[0].Matches {
				gotRule = gotRule || match.Rule == "LocalPartialHit"
			}
			if gotRule != tc.wantRule || !strings.Contains(items[0].Err, tc.wantErr) {
				t.Fatalf("item=%+v wantRule=%v wantErr=%q", items[0], tc.wantRule, tc.wantErr)
			}
		})
	}
}

func TestLocalScanTextControls(t *testing.T) {
	binary := localScanBinary(t)
	rules := localScanRules(t)
	clean := filepath.Join(t.TempDir(), "clean")
	if err := os.WriteFile(clean, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runLocalScan(t, binary, rules, "-quiet", clean)
	if code != 0 || stdout != "" {
		t.Fatalf("quiet clean exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	stdout, stderr, code = runLocalScan(t, binary, rules, missing)
	if code != 2 || !strings.Contains(stdout, "ERROR") || strings.Contains(stdout, "MATCH") {
		t.Fatalf("read error exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
