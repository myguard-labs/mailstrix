package yarad

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func get(s *Server, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// /ready is readiness (rules loaded AND not draining); /health is liveness and
// must stay 200 through a drain so the container isn't killed mid-shutdown.
func TestReadyVsHealth(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	if w := get(s, "/ready"); w.Code != http.StatusOK {
		t.Errorf("ready (loaded): %d want 200", w.Code)
	}
	s.draining.Store(true)
	if w := get(s, "/ready"); w.Code != http.StatusServiceUnavailable {
		t.Errorf("ready (draining): %d want 503", w.Code)
	}
	if w := get(s, "/health"); w.Code != http.StatusOK {
		t.Errorf("health (draining): %d want 200 (liveness stays up while draining)", w.Code)
	}
}

func TestReadyNoRules(t *testing.T) {
	if w := get(newTestServer(&fakeEngine{count: 0}, "tok"), "/ready"); w.Code != http.StatusServiceUnavailable {
		t.Errorf("ready (no rules): %d want 503", w.Code)
	}
}

func TestVersionEndpoint(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 5, fp: "abc"}, "tok")
	s.cfg.Version = "1.2.3"
	w := get(s, "/version")
	if w.Code != http.StatusOK {
		t.Fatalf("version: %d", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["version"] != "1.2.3" {
		t.Errorf("version = %v want 1.2.3", m["version"])
	}
	if m["extractor_version"] == "" || m["extractor_version"] == nil {
		t.Error("extractor_version missing")
	}
}

// A client that has already disconnected/timed out must not consume a scan: the
// request is counted as canceled and the engine is never called.
func TestScanClientCanceled(t *testing.T) {
	eng := &fakeEngine{count: 1}
	s := newTestServer(eng, "tok")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader([]byte("body"))).WithContext(ctx)
	r.Header.Set("Content-Length", "4")
	r.Header.Set("X-YARAD-Token", "tok")
	s.ServeHTTP(httptest.NewRecorder(), r)
	if got := s.metrics.canceled.Load(); got != 1 {
		t.Errorf("canceled=%d want 1", got)
	}
	if got := eng.scans.Load(); got != 0 {
		t.Errorf("engine scanned for a canceled client: %d", got)
	}
}

func TestShutdownSetsDraining(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	// Shutdown before ListenAndServe has stored a server: returns nil, still
	// flips draining so a subsequent /ready 503s.
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown before serve: %v", err)
	}
	if !s.draining.Load() {
		t.Error("Shutdown did not set draining")
	}
}

// fakeEngine exercises the HTTP layer without libyara: it returns canned
// matches (or an error) for any input, and a fixed rule count.
type fakeEngine struct {
	matches []Match
	err     error
	count   int64
	panic   bool
	fp      string
	scans   atomic.Int64 // how many times Scan actually ran
}

func (f *fakeEngine) Scan(buf []byte) ([]Match, error) {
	f.scans.Add(1)
	if f.panic {
		panic("boom")
	}
	return f.matches, f.err
}
func (f *fakeEngine) RuleCount() int64               { return f.count }
func (f *fakeEngine) Fingerprint() string            { return f.fp }
func (f *fakeEngine) ExtractMetrics() ExtractMetrics { return ExtractMetrics{} }
func (f *fakeEngine) ReloadMetrics() ReloadMetrics   { return ReloadMetrics{} }

func newTestServer(eng ScanEngine, token string) *Server {
	cfg := &Config{Token: token, MaxConcurrent: 4, MaxBody: 1 << 20, BackendTimeout: 0}
	cfg.sanitize()
	return NewServer(cfg, eng)
}

func post(s *Server, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader([]byte(body)))
	// The handler reads the Content-Length *header*; httptest only sets the
	// ContentLength field, so mirror it into the header as a real client would.
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestScanMatch(t *testing.T) {
	eng := &fakeEngine{matches: []Match{{Rule: "EICAR_Test", Tags: []string{"test"}}}, count: 1}
	s := newTestServer(eng, "tok")
	w := post(s, "anything", map[string]string{"X-YARAD-Token": "tok"})
	if w.Code != 200 {
		t.Fatalf("code = %d", w.Code)
	}
	var resp scanResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Matches) != 1 || resp.Matches[0].Rule != "EICAR_Test" {
		t.Errorf("matches = %+v", resp.Matches)
	}
}

func TestScanNoMatchEmptyList(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	w := post(s, "clean", map[string]string{"X-YARAD-Token": "tok"})
	if !strings.Contains(w.Body.String(), `"matches":[]`) {
		t.Errorf("no-match body should be empty list, got %s", w.Body.String())
	}
}

func TestAuth(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	if w := post(s, "x", map[string]string{"X-YARAD-Token": "wrong"}); w.Code != 401 {
		t.Errorf("wrong token = %d, want 401", w.Code)
	}
	if w := post(s, "x", nil); w.Code != 401 {
		t.Errorf("no token = %d, want 401", w.Code)
	}
	if w := post(s, "x", map[string]string{"Authorization": "Bearer tok"}); w.Code != 200 {
		t.Errorf("bearer = %d, want 200", w.Code)
	}
}

func TestAuthNotConfigured503(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	if w := post(s, "x", map[string]string{"X-YARAD-Token": "anything"}); w.Code != 503 {
		t.Errorf("no token configured = %d, want 503", w.Code)
	}
}

func TestBadLength(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	// empty body -> Content-Length 0 -> bad length
	if w := post(s, "", map[string]string{"X-YARAD-Token": "tok"}); w.Code != 400 {
		t.Errorf("empty body = %d, want 400", w.Code)
	}
}

func TestScanErrorFailsOpen(t *testing.T) {
	eng := &fakeEngine{err: bytes.ErrTooLarge, count: 1}
	s := newTestServer(eng, "tok")
	w := post(s, "x", map[string]string{"X-YARAD-Token": "tok"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"matches":[]`) {
		t.Errorf("scan error should fail open 200 empty, got %d %s", w.Code, w.Body.String())
	}
}

func TestScanPanicFailsOpen(t *testing.T) {
	s := newTestServer(&fakeEngine{panic: true, count: 1}, "tok")
	w := post(s, "x", map[string]string{"X-YARAD-Token": "tok"})
	if w.Code != 200 {
		t.Errorf("panic should fail open 200, got %d", w.Code)
	}
}

// newCachingServer builds a server with the in-process verdict cache enabled.
func newCachingServer(eng ScanEngine, token string) *Server {
	cfg := &Config{Token: token, MaxConcurrent: 4, MaxBody: 1 << 20, BackendTimeout: 0,
		CacheTTL: time.Minute, CacheSize: 1024}
	cfg.sanitize()
	return NewServer(cfg, eng)
}

func TestPanicNotCached(t *testing.T) {
	// A panicking scan must fail open AND not be cached as a clean verdict — the
	// same body must be rescanned, not served a pinned empty result.
	eng := &fakeEngine{panic: true, count: 1}
	s := newCachingServer(eng, "tok")
	for i := 0; i < 2; i++ {
		if w := post(s, "samebody", map[string]string{"X-YARAD-Token": "tok"}); w.Code != 200 {
			t.Fatalf("req %d code = %d", i, w.Code)
		}
	}
	if got := eng.scans.Load(); got != 2 {
		t.Errorf("panic verdict was cached: Scan ran %d times for 2 identical requests, want 2", got)
	}
}

func TestCleanVerdictIsCached(t *testing.T) {
	// Sanity counterpart: a successful scan IS cached (second identical request
	// does not rescan), so TestPanicNotCached proves the panic path specifically.
	eng := &fakeEngine{matches: []Match{{Rule: "R"}}, count: 1, fp: "A"}
	s := newCachingServer(eng, "tok")
	for i := 0; i < 2; i++ {
		post(s, "samebody", map[string]string{"X-YARAD-Token": "tok"})
	}
	if got := eng.scans.Load(); got != 1 {
		t.Errorf("clean verdict not cached: Scan ran %d times, want 1", got)
	}
}

func TestFingerprintChangeInvalidatesCache(t *testing.T) {
	// A rules reload changes the fingerprint, which is part of the cache key, so
	// the same body is rescanned under the new ruleset instead of serving a
	// verdict computed against the old rules.
	eng := &fakeEngine{matches: []Match{{Rule: "R"}}, count: 1, fp: "rules-v1"}
	s := newCachingServer(eng, "tok")
	post(s, "samebody", map[string]string{"X-YARAD-Token": "tok"})
	eng.fp = "rules-v2" // simulate a reload that changed the rule set
	post(s, "samebody", map[string]string{"X-YARAD-Token": "tok"})
	if got := eng.scans.Load(); got != 2 {
		t.Errorf("fingerprint change did not invalidate cache: Scan ran %d times, want 2", got)
	}
}

func TestHealth(t *testing.T) {
	ok := httptest.NewRecorder()
	newTestServer(&fakeEngine{count: 5}, "tok").ServeHTTP(ok, httptest.NewRequest(http.MethodGet, "/health", nil))
	if ok.Code != 200 {
		t.Errorf("health with rules = %d, want 200", ok.Code)
	}
	none := httptest.NewRecorder()
	newTestServer(&fakeEngine{count: 0}, "tok").ServeHTTP(none, httptest.NewRequest(http.MethodGet, "/health", nil))
	if none.Code != 503 {
		t.Errorf("health with 0 rules = %d, want 503", none.Code)
	}
}

func TestMetrics(t *testing.T) {
	s := newTestServer(&fakeEngine{matches: []Match{{Rule: "R"}}, count: 3}, "tok")
	post(s, "x", map[string]string{"X-YARAD-Token": "tok"})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{"yarad_scans_total 1", "yarad_matches_total 1", "yarad_rules 3"} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q in:\n%s", want, body)
		}
	}
}

func TestNotFound(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w.Code != 404 {
		t.Errorf("unknown path = %d, want 404", w.Code)
	}
}
