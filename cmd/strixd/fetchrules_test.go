package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	yara "github.com/hillu/go-yara/v4"
	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func TestVerifyRulesFreshCacheReceipt(t *testing.T) {
	c, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if err := c.AddString("rule Verifier { condition: true }", ""); err != nil {
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
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	m := mailstrix.RulesManifest{Version: 7, Generated: "2026-06-18T00:00:00Z", Checksum: fmt.Sprintf("sha256:%x", sum), Libyara: "4.5.2", Size: int64(len(b))}
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".json" {
			if err := json.NewEncoder(w).Encode(m); err != nil {
				return
			}
			return
		}
		if _, err := w.Write(b); err != nil {
			return
		}
	}))
	defer source.Close()
	production := t.TempDir()
	sentinel := filepath.Join(production, "compiled.yac")
	if err := os.WriteFile(sentinel, []byte("production cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAILSTRIX_CACHE_DIR", production)
	if code := cmdFetchRules([]string{"-verify-only", "-expected-version", "7", "-url", source.URL}); code != 0 {
		t.Fatalf("verification exit=%d", code)
	}
	if code := cmdFetchRules([]string{"-verify-only", "-expected-version", "8", "-url", source.URL}); code != 2 {
		t.Fatalf("wrong version accepted, exit=%d", code)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != "production cache" {
		t.Fatalf("production cache mutated: %q %v", got, err)
	}
	entries, err := os.ReadDir(production)
	if err != nil || len(entries) != 1 {
		t.Fatalf("verification wrote into production cache: %v %v", entries, err)
	}
}
