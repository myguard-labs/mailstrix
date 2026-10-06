package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

// serveBundle publishes a compiled bundle of n rules as version 2.
func serveBundle(t *testing.T, n int) *httptest.Server {
	t.Helper()
	var src strings.Builder
	for i := range n {
		fmt.Fprintf(&src, "rule R%d { condition: true }\n", i)
	}
	path := filepath.Join(t.TempDir(), "compiled.yac")
	makeCompiledYac(t, path, src.String())
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	m := mailstrix.RulesManifest{Version: 2, Generated: "2026-06-18T00:00:00Z", Checksum: fmt.Sprintf("sha256:%x", sum), Libyara: firstNonEmpty(libyaraVersion, "4.5.2"), Size: int64(len(b))}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".json" {
			_ = json.NewEncoder(w).Encode(m)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s
}

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written. The pipe is drained concurrently so a large write cannot block fn.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, err := io.ReadAll(r)
		if err != nil {
			b = append(b, "read error: "+err.Error()...)
		}
		done <- string(b)
	}()
	defer func() { os.Stderr = orig }()
	fn()
	_ = w.Close()
	return <-done
}

func TestFetchRulesCLIRefusesEmptyBundleUnlessAllowed(t *testing.T) {
	source := serveBundle(t, 0)
	cache := t.TempDir()
	t.Setenv("MAILSTRIX_CACHE_DIR", cache)
	t.Setenv("MAILSTRIX_RULES_ALLOW_COUNT_DROP", "")
	var code int
	stderr := captureStderr(t, func() { code = cmdFetchRules([]string{"-allow-http", "-url", source.URL}) })
	if code != 2 {
		t.Fatalf("empty bundle accepted, exit=%d", code)
	}
	if !strings.Contains(stderr, "rule count drop") {
		t.Fatalf("stderr %q does not report the rule count drop refusal", stderr)
	}
	if _, err := os.Stat(filepath.Join(cache, "compiled.yac")); err == nil {
		t.Fatal("empty bundle installed despite refusal")
	}
	if code := cmdFetchRules([]string{"-allow-http", "-url", source.URL, "-allow-count-drop"}); code != 0 {
		t.Fatalf("flag opt-in exit=%d, want 0", code)
	}
	// Exit 0 is also returned when nothing was installed (!res.Updated), so
	// prove the opt-in run actually wrote the bundle.
	if _, err := os.Stat(filepath.Join(cache, "compiled.yac")); err != nil {
		t.Fatalf("opt-in run did not install the bundle: %v", err)
	}
}

func TestFetchRulesCLIAllowCountDropEnv(t *testing.T) {
	source := serveBundle(t, 0)
	t.Setenv("MAILSTRIX_CACHE_DIR", t.TempDir())
	t.Setenv("MAILSTRIX_RULES_ALLOW_COUNT_DROP", "1")
	if code := cmdFetchRules([]string{"-allow-http", "-url", source.URL}); code != 0 {
		t.Fatalf("env opt-in exit=%d, want 0", code)
	}
}

func TestFetchRulesCLIAcceptsNormalFirstInstall(t *testing.T) {
	source := serveBundle(t, 2)
	t.Setenv("MAILSTRIX_CACHE_DIR", t.TempDir())
	t.Setenv("MAILSTRIX_RULES_ALLOW_COUNT_DROP", "")
	if code := cmdFetchRules([]string{"-allow-http", "-url", source.URL}); code != 0 {
		t.Fatalf("normal install exit=%d, want 0", code)
	}
}
