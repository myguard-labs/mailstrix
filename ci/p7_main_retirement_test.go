package ci

import (
	"errors"
	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestP7PublicCloseAndFailedReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.yar")
	reloadWrite(t, path, "rule Stable { condition: false }")
	cfg := &ms.Config{RulesDir: dir, MaxConcurrent: 1, MaxInflight: 1, CacheSize: 10}
	s, e := ms.NewScanner(cfg, func(string, ...any) {})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	before := s.Fingerprint()
	reloadWrite(t, path, "invalid source")
	if e := s.Reload(); e == nil {
		t.Fatal("invalid main accepted")
	}
	if s.Fingerprint() != before || s.RuleCount() != 1 {
		t.Fatal("failed reload changed published metadata")
	}
	if m, e := s.Scan([]byte("ordinary"), ms.ScanMeta{}); e != nil || len(m) != 0 {
		t.Fatalf("failed reload verdict=%v %v", m, e)
	}
	s.Close()
	s.Close()
	if _, e := s.Scan(nil, ms.ScanMeta{}); !errors.Is(e, ms.ErrScannerClosed) {
		t.Fatalf("closed scan=%v", e)
	}
	if e := s.Reload(); !errors.Is(e, ms.ErrScannerClosed) {
		t.Fatalf("closed reload=%v", e)
	}
	srv := ms.NewServer(cfg, s)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/scan", strings.NewReader("ordinary"))
	r.Header.Set("Content-Length", "8")
	srv.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "MAILSTRIX_SCAN_DEGRADED") {
		t.Fatalf("closed HTTP verdict was certified clean: %s", w.Body.String())
	}
}
