package yarad

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eilandert/rspamd-yarad/internal/mbazaar"
	"github.com/eilandert/rspamd-yarad/internal/urlhaus"
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

// Stale rules must NOT fail /ready (fail-open: old rules still scan), only flag
// it in the body and the yarad_rules_stale metric. Fresh rules / disabled check
// stay clean.
func TestRulesStaleness(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour).Unix()
	fresh := time.Now().Add(-1 * time.Minute).Unix()

	// max-age disabled (0): never stale even with an ancient mtime.
	s := newTestServer(&fakeEngine{count: 1, modUnix: old}, "tok")
	if w := get(s, "/ready"); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "stale") {
		t.Errorf("disabled check should not flag stale: %d %q", w.Code, w.Body.String())
	}

	// max-age 24h + 48h-old rules => stale, but still 200 (fail-open).
	s = newTestServer(&fakeEngine{count: 1, modUnix: old}, "tok")
	s.cfg.RulesMaxAge = 24 * time.Hour
	w := get(s, "/ready")
	if w.Code != http.StatusOK {
		t.Errorf("stale rules must stay ready (fail-open): got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "stale") {
		t.Errorf("stale rules should be flagged in body, got %q", w.Body.String())
	}
	if mw := get(s, "/metrics"); !strings.Contains(mw.Body.String(), "yarad_rules_stale 1") {
		t.Errorf("yarad_rules_stale 1 missing from metrics:\n%s", mw.Body.String())
	}

	// Fresh rules under the same max-age: not stale.
	s = newTestServer(&fakeEngine{count: 1, modUnix: fresh}, "tok")
	s.cfg.RulesMaxAge = 24 * time.Hour
	if w := get(s, "/ready"); strings.Contains(w.Body.String(), "stale") {
		t.Errorf("fresh rules flagged stale: %q", w.Body.String())
	}
	if mw := get(s, "/metrics"); !strings.Contains(mw.Body.String(), "yarad_rules_stale 0") {
		t.Errorf("yarad_rules_stale 0 missing for fresh rules:\n%s", mw.Body.String())
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

type blockingBody struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return 0, io.ErrUnexpectedEOF
}

// A slow authenticated upload may hold an admission/buffer slot, but it must not
// hold the scarce scan-CPU slot before the body has been read. Otherwise one
// slow client per scan slot can starve real scans.
func TestSlowBodyDoesNotHoldScanSlot(t *testing.T) {
	eng := &fakeEngine{count: 1}
	cfg := &Config{
		Token:          "tok",
		MaxConcurrent:  1,
		MaxInflight:    2,
		MaxBody:        1 << 20,
		BackendTimeout: 20 * time.Millisecond,
		CacheTTL:       0,
	}
	cfg.sanitize()
	s := NewServer(cfg, eng)

	body := &blockingBody{started: make(chan struct{}), release: make(chan struct{})}
	r := httptest.NewRequest(http.MethodPost, "/scan", body)
	r.Header.Set("Content-Length", "4")
	r.Header.Set("X-YARAD-Token", "tok")

	done := make(chan struct{})
	go func() {
		s.ServeHTTP(httptest.NewRecorder(), r)
		close(done)
	}()

	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("slow request did not reach body read")
	}

	w := post(s, "fast", map[string]string{"X-YARAD-Token": "tok"})
	if w.Code != http.StatusOK {
		t.Fatalf("fast scan behind slow body = %d, want 200", w.Code)
	}
	if got := eng.scans.Load(); got != 1 {
		t.Fatalf("fast request did not scan exactly once; scans=%d", got)
	}

	close(body.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("slow request did not finish after release")
	}
}

func TestMetricsAuth(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	// Default: /metrics and /version are open.
	if w := get(s, "/metrics"); w.Code != http.StatusOK {
		t.Errorf("metrics open by default: %d", w.Code)
	}
	// Enabled: 401 without the token.
	s.cfg.MetricsAuth = true
	if w := get(s, "/metrics"); w.Code != http.StatusUnauthorized {
		t.Errorf("metrics unauth: %d want 401", w.Code)
	}
	if w := get(s, "/version"); w.Code != http.StatusUnauthorized {
		t.Errorf("version unauth: %d want 401", w.Code)
	}
	// With the token: allowed.
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("X-YARAD-Token", "tok")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("metrics authed: %d want 200", w.Code)
	}
	// Probes stay open regardless.
	if w := get(s, "/health"); w.Code != http.StatusOK {
		t.Errorf("health must stay open under metrics auth: %d", w.Code)
	}
	if w := get(s, "/ready"); w.Code != http.StatusOK {
		t.Errorf("ready must stay open under metrics auth: %d", w.Code)
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
	matches  []Match
	err      error
	count    int64
	panic    bool
	fp       string
	scans    atomic.Int64 // how many times Scan actually ran
	lastMeta atomic.Pointer[ScanMeta]
	mb       mbazaar.Metrics // returned by MBazaarMetrics (zero = disabled)
	modUnix  int64           // returned as ReloadMetrics.ModUnix (rules mtime)
}

func (f *fakeEngine) Scan(buf []byte, meta ScanMeta) ([]Match, error) {
	f.scans.Add(1)
	m := meta
	f.lastMeta.Store(&m)
	if f.panic {
		panic("boom")
	}
	return f.matches, f.err
}
func (f *fakeEngine) RuleCount() int64                { return f.count }
func (f *fakeEngine) Fingerprint() string             { return f.fp }
func (f *fakeEngine) ExtractMetrics() ExtractMetrics  { return ExtractMetrics{} }
func (f *fakeEngine) ReloadMetrics() ReloadMetrics    { return ReloadMetrics{ModUnix: f.modUnix} }
func (f *fakeEngine) URLhausMetrics() urlhaus.Metrics { return urlhaus.Metrics{} }
func (f *fakeEngine) MBazaarMetrics() mbazaar.Metrics { return f.mb }

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

// The X-YARAD-Filename header (base64) must be decoded, normalized, and handed to
// the engine as ScanMeta so name-keyed YARA rules can fire.
func TestScanFilenameHeaderPlumbing(t *testing.T) {
	eng := &fakeEngine{count: 1}
	s := newTestServer(eng, "tok")
	hdr := map[string]string{
		"X-YARAD-Token":    "tok",
		"X-YARAD-Filename": base64.StdEncoding.EncodeToString([]byte(`C:\Users\bob\Invoice.EXE`)),
	}
	if w := post(s, "body", hdr); w.Code != 200 {
		t.Fatalf("code = %d", w.Code)
	}
	got := eng.lastMeta.Load()
	if got == nil {
		t.Fatal("engine never received metadata")
	}
	if got.Filename != "Invoice.EXE" { // basename, case preserved
		t.Errorf("filename = %q want %q", got.Filename, "Invoice.EXE")
	}
	if got.Extension != ".exe" { // lowercased, dot included
		t.Errorf("extension = %q want %q", got.Extension, ".exe")
	}
}

// A garbage / absent filename header must not error the scan; the engine just
// gets empty metadata (externals stay at their empty defaults).
func TestScanFilenameHeaderBadIsIgnored(t *testing.T) {
	eng := &fakeEngine{count: 1}
	s := newTestServer(eng, "tok")
	if w := post(s, "body", map[string]string{"X-YARAD-Token": "tok", "X-YARAD-Filename": "!!!not base64!!!"}); w.Code != 200 {
		t.Fatalf("bad filename header should not break scan: %d", w.Code)
	}
	if got := eng.lastMeta.Load(); got == nil || got.Filename != "" {
		t.Errorf("undecodable header should yield empty filename, got %+v", got)
	}
}

// Same bytes, different filename ⇒ different cache key ⇒ rescan. A name-keyed
// verdict must not be served from a sibling message that shared the bytes but
// had another name.
func TestFilenameIsPartOfCacheKey(t *testing.T) {
	eng := &fakeEngine{matches: []Match{{Rule: "R"}}, count: 1, fp: "A"}
	s := newCachingServer(eng, "tok")
	enc := func(n string) string { return base64.StdEncoding.EncodeToString([]byte(n)) }
	post(s, "samebody", map[string]string{"X-YARAD-Token": "tok", "X-YARAD-Filename": enc("a.exe")})
	post(s, "samebody", map[string]string{"X-YARAD-Token": "tok", "X-YARAD-Filename": enc("a.pdf")})
	if got := eng.scans.Load(); got != 2 {
		t.Errorf("different filename did not bypass cache: Scan ran %d times, want 2", got)
	}
	// Identical filename + bytes DOES hit the cache (no third scan).
	post(s, "samebody", map[string]string{"X-YARAD-Token": "tok", "X-YARAD-Filename": enc("a.pdf")})
	if got := eng.scans.Load(); got != 2 {
		t.Errorf("identical filename+bytes rescanned: Scan ran %d times, want 2", got)
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

// When the MalwareBazaar checker is enabled, /metrics must surface its gauges
// and counters; when disabled they must be absent (no zero-value noise).
func TestMetricsMalwareBazaar(t *testing.T) {
	eng := &fakeEngine{count: 1, mb: mbazaar.Metrics{Enabled: true, FeedHashes: 1234, Lookups: 7, Hits: 1}}
	s := newTestServer(eng, "tok")
	body := get(s, "/metrics").Body.String()
	for _, want := range []string{"yarad_malwarebazaar_feed_hashes 1234", "yarad_malwarebazaar_lookups_total 7", "yarad_malwarebazaar_hits_total 1"} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	off := get(newTestServer(&fakeEngine{count: 1}, "tok"), "/metrics").Body.String()
	if strings.Contains(off, "malwarebazaar") {
		t.Errorf("disabled MalwareBazaar should emit no metrics lines:\n%s", off)
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
