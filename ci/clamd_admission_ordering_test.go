package ci_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestClamdAdmissionOrderingFixture runs a same-package fixture through an
// overlay: the clamd service internals are private and the fixture lives under
// ci/testdata to avoid a production test seam.
func TestClamdAdmissionOrderingFixture(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(root, "ci", "testdata", "clamd_admission_ordering_test.go")
	fixtureBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtureBytes) == 0 {
		t.Fatal("private clamd admission fixture is empty")
	}
	target := filepath.Join(root, "internal", "mailstrix", "clamd_admission_ordering_overlay_test.go")
	overlay := filepath.Join(t.TempDir(), "overlay.json")
	encoded, err := json.Marshal(map[string]any{"Replace": map[string]string{target: fixture}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "test", "-v", "-count=1", "-race", "-p=1",
		"-overlay="+overlay,
		"-run=^TestClamdAdmissionBeforeRead$",
		"./internal/mailstrix")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("private clamd admission fixture failed: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "ok  \tgithub.com/myguard-labs/mailstrix/internal/mailstrix") {
		t.Fatalf("clamd admission fixture did not report its package verdict:\n%s", out)
	}
	found := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "--- PASS: TestClamdAdmissionBeforeRead (") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("clamd admission fixture did not report top-level PASS:\n%s", out)
	}
}
