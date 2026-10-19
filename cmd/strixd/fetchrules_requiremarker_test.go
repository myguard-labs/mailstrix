package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	yara "github.com/hillu/go-yara/v4"
)

// markerManifestServer serves a loadable bundle whose signed manifest carries
// the given marker field (nil omits it) and counts every request.
func markerManifestServer(t *testing.T, marker func(mainSum string) map[string]any) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	c, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if err := c.AddString("rule RequireMarker { condition: true }", ""); err != nil {
		t.Fatal(err)
	}
	r, err := c.GetRules()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	path := filepath.Join(t.TempDir(), "compiled.yac")
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(b))
	m := map[string]any{"version": 5, "generated": "2026-06-18T00:00:00Z", "checksum": "sha256:" + sum, "libyara": "4.5.2", "size": len(b)}
	if marker != nil {
		m["marker"] = marker(sum)
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	trustCLISigningKey(t)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(cliSigningPriv, body)) + "\n"
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch filepath.Ext(r.URL.Path) {
		case ".sig":
			_, _ = w.Write([]byte(sig))
		case ".json":
			_, _ = w.Write(body)
		case ".gz":
			http.NotFound(w, r)
		default:
			_, _ = w.Write(b)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func validMarkerField(mainSum string) map[string]any {
	h := strings.Repeat("ab", 32)
	return map[string]any{"asset": "marker-tree.tar.gz", "sha256": h, "size": 10, "libyara_sha256": h, "compiler_sha256": h, "main_sha256": mainSum}
}

// -require-marker is a usage error without -verify-only and must fail before
// any request.
func TestFetchRulesRequireMarkerNeedsVerifyOnly(t *testing.T) {
	srv, hits := markerManifestServer(t, nil)
	t.Setenv("MAILSTRIX_CACHE_DIR", t.TempDir())
	var code int
	stderr := captureStderr(t, func() { code = cmdFetchRules([]string{"-require-marker", "-allow-http", "-url", srv.URL}) })
	if code != 2 || !strings.Contains(stderr, "require-marker requires verify-only") {
		t.Fatalf("exit=%d stderr=%q, want 2 usage error", code, stderr)
	}
	if hits.Load() != 0 {
		t.Fatalf("usage error made %d requests", hits.Load())
	}
}

// Every outcome other than an installed, loaded tree fails the gate, while the
// same candidate without the flag still verifies (exit 0) so existing
// -verify-only callers are unchanged.
func TestFetchRulesRequireMarkerFailsWithoutLoadedTree(t *testing.T) {
	invalidField := func(mainSum string) map[string]any {
		f := validMarkerField(mainSum)
		f["asset"] = "../escape.tar.gz"
		return f
	}
	for _, tc := range []struct {
		name   string
		marker func(string) map[string]any
		mode   string
		want   string
	}{
		{"missing field", nil, "auto", "marker=absent"},
		{"invalid field", invalidField, "auto", "marker=rejected"},
		{"toolchain not linked into this binary", validMarkerField, "auto", "marker=skipped"},
		{"markers off", validMarkerField, "off", "marker=disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := markerManifestServer(t, tc.marker)
			t.Setenv("MAILSTRIX_CACHE_DIR", t.TempDir())
			t.Setenv("MAILSTRIX_RULES_MARKERS", tc.mode)
			args := []string{"-verify-only", "-allow-http", "-url", srv.URL}
			var plain int
			captureStdout(t, func() { plain = cmdFetchRules(args) })
			if plain != 0 {
				t.Fatalf("without -require-marker exit=%d, want 0", plain)
			}
			var code int
			var out string
			stderr := captureStderr(t, func() {
				out = captureStdout(t, func() { code = cmdFetchRules(append(args, "-require-marker")) })
			})
			if code != 2 || !strings.Contains(out, tc.want) || !strings.Contains(stderr, "marker tree required") {
				t.Fatalf("exit=%d stdout=%q stderr=%q, want 2 with %q and a required-marker error", code, out, stderr, tc.want)
			}
		})
	}
}

// The positive control of the gate: only the installed status passes.
func TestRequireMarkerInstalled(t *testing.T) {
	if err := requireMarkerInstalled("installed"); err != nil {
		t.Fatalf("installed rejected: %v", err)
	}
	for _, status := range []string{"", "absent", "disabled", "skipped: linked libyara/compiler identity differs", "rejected: bad tree", "Installed", "installed "} {
		if err := requireMarkerInstalled(status); err == nil {
			t.Fatalf("status %q accepted", status)
		}
	}
}
