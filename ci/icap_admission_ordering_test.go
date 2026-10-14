package ci_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestICAPAdmissionOrderingFixture runs a same-package fixture through an
// overlay. The production ICAP entry points needed by the fixture are private;
// keeping the fixture under ci/testdata avoids adding a production test seam.
func TestICAPAdmissionOrderingFixture(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(root, "ci", "testdata", "icap_admission_ordering_test.go")
	fixtureBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtureBytes) == 0 {
		t.Fatal("private ICAP admission fixture is empty")
	}
	target := filepath.Join(root, "internal", "mailstrix", "icap_admission_ordering_overlay_test.go")
	overlay := filepath.Join(t.TempDir(), "overlay.json")
	encoded, err := json.Marshal(map[string]any{"Replace": map[string]string{target: fixture}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "test", "-count=1", "-race", "-p=1",
		"-overlay="+overlay,
		"-run=^TestICAPAdmission(BuffersBeforeGate|PreReadFailureCleanup)$",
		"./internal/mailstrix")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("private ICAP admission fixture failed: %v\n%s", err, out)
	}
	if text := string(out); !strings.Contains(text, "ok  \tgithub.com/myguard-labs/mailstrix/internal/mailstrix") {
		t.Fatalf("private ICAP admission fixture did not report its package verdict:\n%s", out)
	}
}
