package ci_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Keep the private-handler fixture in ci while exercising the actual ICAP
// parser, effort resolver, cache, and flight ownership without a production seam.
func TestICAPIdentityFixture(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(root, "ci", "testdata", "icap_identity_test.go")
	data, err := os.ReadFile(fixture)
	if err != nil || len(data) == 0 {
		t.Fatalf("ICAP identity fixture unavailable: %v", err)
	}
	target := filepath.Join(root, "internal", "mailstrix", "icap_identity_overlay_test.go")
	encoded, err := json.Marshal(map[string]any{"Replace": map[string]string{target: fixture}})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(overlay, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "test", "-v", "-count=1", "-race", "-p=1",
		"-overlay="+overlay, "-run=^TestICAPIdentity", "./internal/mailstrix")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ICAP identity fixture failed: %v\n%s", err, out)
	}
	text := string(out)
	for _, name := range []string{"TestICAPIdentityEffortCacheSeparation", "TestICAPIdentityDefaultsAndHeaders", "TestICAPIdentityConcurrentEfforts", "TestICAPIdentityIncompleteNeverCached"} {
		if !strings.Contains(text, "--- PASS: "+name+" (") {
			t.Fatalf("ICAP identity fixture did not report PASS for %s:\n%s", name, out)
		}
	}
	if !strings.Contains(text, "ok  \tgithub.com/myguard-labs/mailstrix/internal/mailstrix") {
		t.Fatalf("ICAP identity fixture did not report package success:\n%s", out)
	}
}
