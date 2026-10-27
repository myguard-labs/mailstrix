package ci_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// TestArchiveDecoderVersionOrdering keeps the decoder-status cache bump ahead
// of the terminal cache-domain suffix consumed by older compatibility gates.
func TestArchiveDecoderVersionOrdering(t *testing.T) {
	const suffix = "+decoderstatus+retainedlimit+xxh3key"
	if !strings.HasSuffix(extract.Version, suffix) {
		t.Fatalf("extract.Version must end with %q; got %q", suffix, extract.Version)
	}
}

// TestArchiveDecoderIncompleteFixture exercises private extraction entry points
// and their real HTTP/cache consumer without adding a production test seam.
func TestArchiveDecoderIncompleteFixture(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	replace := make(map[string]string)
	for _, name := range []string{"archive_decoder_incomplete_test.go", "archive_decoder_http_test.go"} {
		fixture := filepath.Join(root, "ci", "testdata", name)
		contents, err := os.ReadFile(fixture)
		if err != nil || len(contents) == 0 {
			t.Fatalf("read nonempty decoder fixture %s: %v", name, err)
		}
		replace[filepath.Join(root, "internal", "extract", "ci_"+name)] = fixture
	}
	encoded, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(overlay, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"test", "-v", "-count=1", "-race", "-p=1", "-overlay=" + overlay,
		"-run=^TestArchiveDecoder"}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "-tags" && setting.Value != "" {
				args = append(args, "-tags="+setting.Value)
			}
		}
	}
	args = append(args, "./internal/extract")
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GOFLAGS=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "GOFLAGS="+strings.TrimSpace(os.Getenv("GOFLAGS")+" -buildvcs=false"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("archive decoder fixture failed: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "ok  \tgithub.com/myguard-labs/mailstrix/internal/extract") {
		t.Fatalf("decoder fixture has no package verdict:\n%s", out)
	}
	for _, name := range []string{
		"TestArchiveDecoderHeaderIncomplete", "TestArchiveDecoderMemberIncomplete",
		"TestArchiveDecoderContinuesAfterRefusal", "TestArchiveDecoderRequestIsolation",
		"TestArchiveDecoderOrdinaryRefusalPolicy", "TestArchiveDecoderHTTPNoCleanCache",
		"TestArchiveDecoderHTTPRecoveredHit", "TestArchiveDecoderContainmentOutcomes",
		"TestArchiveDecoderCacheIdentity",
	} {
		if !strings.Contains(text, "--- PASS: "+name+" (") {
			t.Fatalf("decoder fixture did not pass %s:\n%s", name, out)
		}
	}
}
