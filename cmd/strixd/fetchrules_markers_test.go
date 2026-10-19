package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	yara "github.com/hillu/go-yara/v4"
	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

// An invalid MAILSTRIX_RULES_MARKERS value aborts fetch-rules before any
// request, like a malformed signing key.
func TestFetchRulesCLIRejectsInvalidMarkersMode(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	t.Setenv("MAILSTRIX_CACHE_DIR", t.TempDir())
	t.Setenv("MAILSTRIX_RULES_MARKERS", "maybe")
	var code int
	stderr := captureStderr(t, func() { code = cmdFetchRules([]string{"-allow-http", "-url", srv.URL}) })
	if code != 2 || !strings.Contains(stderr, "MAILSTRIX_RULES_MARKERS") {
		t.Fatalf("exit=%d stderr=%q, want 2 naming MAILSTRIX_RULES_MARKERS", code, stderr)
	}
	if hits.Load() != 0 {
		t.Fatalf("invalid marker mode made %d requests", hits.Load())
	}
}

// fetch-rules and verify-only report the marker outcome: "disabled" under
// MAILSTRIX_RULES_MARKERS=off, and "absent" for a manifest without the
// optional field, which installs exactly as before.
func TestFetchRulesCLIReportsMarkerStatus(t *testing.T) {
	c, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if err := c.AddString("rule MarkerStatus { condition: true }", ""); err != nil {
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
	m := mailstrix.RulesManifest{Version: 3, Generated: "2026-06-18T00:00:00Z", Checksum: fmt.Sprintf("sha256:%x", sha256.Sum256(b)), Libyara: "4.5.2", Size: int64(len(b))}
	trustCLISigningKey(t)
	body, sig := signedManifest(t, m)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Ext(r.URL.Path) {
		case ".sig":
			_, _ = w.Write([]byte(sig))
		case ".json":
			_, _ = w.Write(body)
		default:
			_, _ = w.Write(b)
		}
	}))
	defer srv.Close()
	for _, tc := range []struct {
		mode string
		args []string
		want string
	}{
		{"off", []string{"-allow-http", "-url", srv.URL}, "fetch-rules: marker tree disabled"},
		{"auto", []string{"-verify-only", "-allow-http", "-url", srv.URL}, "verify-rules: marker=absent"},
	} {
		t.Setenv("MAILSTRIX_CACHE_DIR", t.TempDir())
		t.Setenv("MAILSTRIX_RULES_MARKERS", tc.mode)
		var code int
		out := captureStdout(t, func() { code = cmdFetchRules(tc.args) })
		if code != 0 || !strings.Contains(out, tc.want) {
			t.Fatalf("mode=%s exit=%d stdout=%q, want %q", tc.mode, code, out, tc.want)
		}
	}
}
