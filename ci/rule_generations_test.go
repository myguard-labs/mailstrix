package ci

import (
	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

func TestRuleGenerationsMetricsReload(t *testing.T) {
	prior := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prior)
	dir, big := t.TempDir(), t.TempDir()
	reloadWrite(t, filepath.Join(dir, "main.yar"), "rule Main : marker { condition: true }")
	bigPath := filepath.Join(big, "big.yar")
	reloadWrite(t, bigPath, "rule Big { condition: true }")
	cfg := &ms.Config{RulesDir: dir, BigFileRules: big, BigFileThreshold: 1, MaxConcurrent: 1, MaxInflight: 1, CacheSize: 1}
	s, err := ms.NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := ms.NewServer(cfg, s)
	scrape := func() uint64 {
		t.Helper()
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		if !strings.Contains(w.Body.String(), "# TYPE mailstrix_rule_generations gauge\n") {
			t.Fatal("missing native generations gauge")
		}
		for _, line := range strings.Split(w.Body.String(), "\n") {
			if strings.HasPrefix(line, "mailstrix_rule_generations ") {
				v, e := strconv.ParseUint(strings.TrimPrefix(line, "mailstrix_rule_generations "), 10, 64)
				if e != nil {
					t.Fatal(e)
				}
				return v
			}
		}
		t.Fatal("missing native generations value")
		return 0
	}
	before := scrape()
	if before < 3 {
		t.Fatalf("main/big/marker count=%d want >=3", before)
	}
	// Auxiliary failure retains its previous alias: main is destroyed immediately; only the old marker awaits GC.
	reloadWrite(t, bigPath, "broken rules")
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := scrape(); got != before+1 {
		t.Fatalf("retired-unfreed gauge=%d want=%d after auxiliary failure", got, before+1)
	}
	reloadWrite(t, filepath.Join(dir, "main.yar"), "broken rules")
	if err := s.Reload(); err == nil {
		t.Fatal("malformed main reload succeeded")
	}
	if got := scrape(); got != before+1 {
		t.Fatalf("failed main reload changed gauge=%d", got)
	}
	if _, err := s.Scan([]byte("fixture"), ms.ScanMeta{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(bigPath); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(s)
}
