package yarad

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eilandert/rspamd-yarad/internal/feodo"
	"github.com/eilandert/rspamd-yarad/internal/mbazaar"
	"github.com/eilandert/rspamd-yarad/internal/threatfox"
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

// /version surfaces per-ruleset provenance (the manifest's sources array) so an
// operator can audit which rule sources are baked into the running bundle.
func TestVersionEndpointSources(t *testing.T) {
	dir := t.TempDir()
	man := RulesManifest{
		Version: 7, Generated: "2026-06-20T00:00:00Z", Libyara: "4.5.0", Rules: 42,
		Sources: []RuleSource{
			{Name: "yaraforge", Repo: "https://github.com/YARAHQ/yara-forge", License: "DRL-1.1", Ref: "v20260601", Set: "extended"},
			{Name: "local", Repo: "in-repo docker/local-rules", License: "MIT", Ref: "main"},
		},
	}
	b, err := json.Marshal(man)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), b, 0o644); err != nil {
		t.Fatal(err)
	}

	s := newTestServer(&fakeEngine{count: 5, fp: "abc"}, "tok")
	s.cfg.CacheDir = dir
	w := get(s, "/version")
	if w.Code != http.StatusOK {
		t.Fatalf("version: %d", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	srcs, ok := m["sources"].([]any)
	if !ok || len(srcs) != 2 {
		t.Fatalf("sources = %v, want 2 entries", m["sources"])
	}
	first, _ := srcs[0].(map[string]any)
	if first["name"] != "yaraforge" || first["license"] != "DRL-1.1" {
		t.Errorf("first source = %v, want yaraforge/DRL-1.1", first)
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

// TestProcRSSMiB: on Linux the running test process always has a non-trivial
// resident set, so the reader must return a positive MiB value.
func TestProcRSSMiB(t *testing.T) {
	if rss := procRSSMiB(); rss <= 0 {
		t.Fatalf("procRSSMiB() = %d MiB; want > 0 for the running process", rss)
	}
}

// TestLogStartupFoldsRSS: the startup memory estimate must add resident RSS
// (rules + mbazaar feed) to the request-buffer term, not report buffers alone.
// Drive logStartup with a huge MaxInflight×MaxBody so the buffer term dominates,
// and assert the info line reports the folded RSS+buffers form.
func TestLogStartupFoldsRSS(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	s.cfg.MaxInflight = 8
	s.cfg.MaxBody = 32 << 20 // 256 MiB of buffers
	var info bytes.Buffer
	s.info = log.New(&info, "", 0)
	s.errl = log.New(io.Discard, "", 0)
	s.logStartup("127.0.0.1:0")
	out := info.String()
	if !strings.Contains(out, "RSS=") || !strings.Contains(out, "est. peak memory") {
		t.Fatalf("startup line did not fold RSS into peak estimate:\n%s", out)
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

func (f *fakeEngine) Scan(buf []byte, digest [32]byte, meta ScanMeta) ([]Match, error) {
	f.scans.Add(1)
	m := meta
	f.lastMeta.Store(&m)
	if f.panic {
		panic("boom")
	}
	return f.matches, f.err
}
func (f *fakeEngine) RuleCount() int64                    { return f.count }
func (f *fakeEngine) BigFileScans() uint64                { return 0 }
func (f *fakeEngine) BigFileStreamScans() uint64          { return 0 }
func (f *fakeEngine) RawChannelScans() uint64             { return 0 }
func (f *fakeEngine) StreamChannelScans() uint64          { return 0 }
func (f *fakeEngine) MarkerChannelScans() uint64          { return 0 }
func (f *fakeEngine) RawScanErrs() uint64                 { return 0 }
func (f *fakeEngine) Fingerprint() string                 { return f.fp }
func (f *fakeEngine) ExtractMetrics() ExtractMetrics      { return ExtractMetrics{} }
func (f *fakeEngine) ReloadMetrics() ReloadMetrics        { return ReloadMetrics{ModUnix: f.modUnix} }
func (f *fakeEngine) URLhausMetrics() urlhaus.Metrics     { return urlhaus.Metrics{} }
func (f *fakeEngine) MBazaarMetrics() mbazaar.Metrics     { return f.mb }
func (f *fakeEngine) ThreatFoxMetrics() threatfox.Metrics { return threatfox.Metrics{} }
func (f *fakeEngine) FeodoMetrics() feodo.Metrics         { return feodo.Metrics{} }
func (f *fakeEngine) TopMatches(n int) []MatchCount       { return nil }

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

// With no token configured the scanner runs OPEN: /scan accepts requests with or
// without an auth header (intended for a trusted private network). A stray header
// is ignored, not an error.
func TestScanOpenWhenNoToken(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	if w := post(s, "x", nil); w.Code != 200 {
		t.Errorf("open scanner, no header = %d, want 200", w.Code)
	}
	if w := post(s, "x", map[string]string{"X-YARAD-Token": "anything"}); w.Code != 200 {
		t.Errorf("open scanner, stray header = %d, want 200", w.Code)
	}
}

// MetricsAuth can't gate anything when there's no token; /metrics stays open.
func TestMetricsAuthNoopWithoutToken(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	s.cfg.MetricsAuth = true
	if w := get(s, "/metrics"); w.Code != 200 {
		t.Errorf("metrics with auth-on but no token = %d, want 200 (nothing to gate)", w.Code)
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

// TestVersionPrevFingerprint verifies that after two reloads, /version surfaces
// the prev_fingerprint field with a non-empty value.
func TestVersionPrevFingerprint(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		RulesDir:    dir,
		ScanTimeout: 5 * time.Second,
	}
	// Write two minimal YARA rule files so we can swap between them.
	rule1 := []byte("rule A { condition: false }\n")
	rule2 := []byte("rule B { condition: false }\n")
	if err := os.WriteFile(filepath.Join(dir, "rules.yar"), rule1, 0o644); err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	// First reload gives us a fingerprint but prev should still be "".
	fp1 := sc.ReloadMetrics().PrevFingerprint
	if fp1 != "" {
		t.Errorf("prev_fingerprint after first load = %q, want empty", fp1)
	}
	// Second reload: swap the rule set so the fingerprint changes.
	if err := os.WriteFile(filepath.Join(dir, "rules.yar"), rule2, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sc.Reload(); err != nil {
		t.Fatalf("second Reload: %v", err)
	}
	rl := sc.ReloadMetrics()
	if rl.PrevFingerprint == "" {
		t.Error("prev_fingerprint is empty after second reload, want non-empty")
	}

	// Verify /version exposes it.
	s := newTestServer(sc, "")
	w := get(s, "/version")
	if w.Code != http.StatusOK {
		t.Fatalf("/version: %d", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	prev, ok := m["prev_fingerprint"].(string)
	if !ok || prev == "" {
		t.Errorf("/version prev_fingerprint = %v, want non-empty string", m["prev_fingerprint"])
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

// TestDualTokenAuth verifies that comma-separated YARAD_TOKEN and/or
// YARAD_TOKEN_NEXT enable zero-downtime token rotation: both tokens are
// accepted, a wrong token is still rejected, and duplicates are not admitted
// twice.
func TestDualTokenAuth(t *testing.T) {
	eng := &fakeEngine{count: 1}

	// Case 1: comma-separated Token — both parts accepted, wrong rejected.
	t.Run("comma_sep_primary", func(t *testing.T) {
		cfg := &Config{Token: "old,new", MaxConcurrent: 4, MaxBody: 1 << 20, BackendTimeout: 0}
		cfg.sanitize()
		s := NewServer(cfg, eng)
		if w := post(s, "x", map[string]string{"X-YARAD-Token": "old"}); w.Code != 200 {
			t.Errorf("old token: %d want 200", w.Code)
		}
		if w := post(s, "x", map[string]string{"X-YARAD-Token": "new"}); w.Code != 200 {
			t.Errorf("new token: %d want 200", w.Code)
		}
		if w := post(s, "x", map[string]string{"X-YARAD-Token": "wrong"}); w.Code != 401 {
			t.Errorf("wrong token: %d want 401", w.Code)
		}
	})

	// Case 2: primary + TokenNext — both accepted.
	t.Run("token_next", func(t *testing.T) {
		cfg := &Config{Token: "primary", TokenNext: "next", MaxConcurrent: 4, MaxBody: 1 << 20, BackendTimeout: 0}
		cfg.sanitize()
		s := NewServer(cfg, eng)
		if w := post(s, "x", map[string]string{"X-YARAD-Token": "primary"}); w.Code != 200 {
			t.Errorf("primary: %d want 200", w.Code)
		}
		if w := post(s, "x", map[string]string{"X-YARAD-Token": "next"}); w.Code != 200 {
			t.Errorf("next: %d want 200", w.Code)
		}
		if w := post(s, "x", map[string]string{"X-YARAD-Token": "other"}); w.Code != 401 {
			t.Errorf("other: %d want 401", w.Code)
		}
	})

	// Case 3: TokenNext already present in comma-sep primary — no duplicate,
	// still accepted.
	t.Run("no_duplicate", func(t *testing.T) {
		cfg := &Config{Token: "primary,next", TokenNext: "next", MaxConcurrent: 4, MaxBody: 1 << 20, BackendTimeout: 0}
		cfg.sanitize()
		s := NewServer(cfg, eng)
		if len(s.cfg.tokens) != 2 {
			t.Errorf("tokens len = %d, want 2 (no duplicate)", len(s.cfg.tokens))
		}
		if w := post(s, "x", map[string]string{"X-YARAD-Token": "primary"}); w.Code != 200 {
			t.Errorf("primary: %d want 200", w.Code)
		}
		if w := post(s, "x", map[string]string{"X-YARAD-Token": "next"}); w.Code != 200 {
			t.Errorf("next: %d want 200", w.Code)
		}
	})
}

// TestDecodeFilenameB64Variants covers the wire-format tolerance of the
// X-YARAD-Filename decoder: standard padded base64, raw (unpadded) base64, and a
// whitespace-folded value all decode to the same bytes; non-base64 garbage is
// rejected (the scan still runs, just without metadata).
func TestDecodeFilenameB64Variants(t *testing.T) {
	const name = "invoice.exe"
	padded := base64.StdEncoding.EncodeToString([]byte(name)) // "aW52b2ljZS5leGU="
	raw := base64.RawStdEncoding.EncodeToString([]byte(name)) // no "=" padding
	folded := padded[:4] + "\r\n " + padded[4:]               // CR/LF/space in the middle

	for _, in := range []string{padded, raw, folded} {
		got, ok := decodeFilenameB64(in)
		if !ok {
			t.Errorf("decodeFilenameB64(%q) = !ok, want decode to %q", in, name)
			continue
		}
		if string(got) != name {
			t.Errorf("decodeFilenameB64(%q) = %q, want %q", in, got, name)
		}
	}

	if _, ok := decodeFilenameB64("!!!not base64!!!"); ok {
		t.Error("garbage decoded as base64; want !ok")
	}
}

// TestPprofDisabledByDefault verifies that /debug/pprof/ returns 404 when
// YARAD_PPROF is not set (Pprof=false).
func TestPprofDisabledByDefault(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	if w := get(s, "/debug/pprof/"); w.Code != http.StatusNotFound {
		t.Errorf("pprof disabled: /debug/pprof/ = %d, want 404", w.Code)
	}
}

// TestPprofEnabled verifies that /debug/pprof/ returns 200 (the HTML index page)
// when Pprof=true and no auth is required.
func TestPprofEnabled(t *testing.T) {
	cfg := &Config{Token: "tok", MaxConcurrent: 4, MaxBody: 1 << 20, BackendTimeout: 0, Pprof: true}
	cfg.sanitize()
	s := NewServer(cfg, &fakeEngine{count: 1})
	if w := get(s, "/debug/pprof/"); w.Code != http.StatusOK {
		t.Errorf("pprof enabled: /debug/pprof/ = %d, want 200", w.Code)
	}
}

// TestPprofRequiresAuth verifies that /debug/pprof/ returns 401 when Pprof=true
// and MetricsAuth=true but no token is presented.
func TestPprofRequiresAuth(t *testing.T) {
	cfg := &Config{Token: "tok", MaxConcurrent: 4, MaxBody: 1 << 20, BackendTimeout: 0, Pprof: true, MetricsAuth: true}
	cfg.sanitize()
	s := NewServer(cfg, &fakeEngine{count: 1})
	if w := get(s, "/debug/pprof/"); w.Code != http.StatusUnauthorized {
		t.Errorf("pprof with auth: /debug/pprof/ (no token) = %d, want 401", w.Code)
	}
}

// TestPprofAuthedTokenAllowed verifies the complement of TestPprofRequiresAuth:
// with Pprof=true and MetricsAuth=true, a correct token unlocks /debug/pprof/.
// This is the path ops actually use to capture a live profile (PERF-1), so a
// regression that 401s a valid token would silently break profiling.
func TestPprofAuthedTokenAllowed(t *testing.T) {
	cfg := &Config{Token: "tok", MaxConcurrent: 4, MaxBody: 1 << 20, BackendTimeout: 0, Pprof: true, MetricsAuth: true}
	cfg.sanitize()
	s := NewServer(cfg, &fakeEngine{count: 1})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("pprof with auth + valid token: /debug/pprof/ = %d, want 200", w.Code)
	}

	// The X-YARAD-Token header must work too (the rspamd plugin's scheme).
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	req.Header.Set("X-YARAD-Token", "tok")
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("pprof with auth + X-YARAD-Token: /debug/pprof/ = %d, want 200", w.Code)
	}
}

// fakeDegradedCache wraps noopCache and returns a non-empty Degraded() string
// to exercise the /ready degraded-cache path without a real Redis.
type fakeDegradedCache struct{ noopCache }

func (f *fakeDegradedCache) Degraded() string { return "redis breaker open" }

func TestReadyDegradedCache(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	s.cache = &fakeDegradedCache{}

	w := get(s, "/ready")
	if w.Code != http.StatusOK {
		t.Errorf("/ready with degraded cache: %d want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "redis breaker open") {
		t.Errorf("/ready body missing degraded reason: %q", w.Body.String())
	}
}

func TestReadyNotDegradedWithNoopCache(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "tok")
	s.cache = noopCache{}

	w := get(s, "/ready")
	if w.Code != http.StatusOK {
		t.Errorf("/ready with noopCache: %d want 200", w.Code)
	}
	if strings.Contains(w.Body.String(), "degraded") {
		t.Errorf("/ready body should not mention degraded for noopCache: %q", w.Body.String())
	}
}

// brokenCache is a test double for the Cache interface that always fails —
// every Get misses, Put is a no-op, and Degraded reports a non-empty reason.
// It simulates a Redis instance that is down or unreachable.
type brokenCache struct{}

func (brokenCache) Get(string) ([]Match, bool) { return nil, false }
func (brokenCache) Put(string, []Match)        {}
func (brokenCache) Flush()                     {}
func (brokenCache) Degraded() string           { return "test-broken" }

// TestScanWithBrokenCache is a regression test: when the cache layer is
// completely broken (simulating Redis down), the scanner must still return
// matches — the cache is fail-open and must never block a scan result.
func TestScanWithBrokenCache(t *testing.T) {
	eng := &fakeEngine{matches: []Match{{Rule: "EICAR_Test_File", Tags: []string{"test"}}}, count: 1}
	s := newTestServer(eng, "tok")
	// Replace the production cache with one that always misses and reports degraded.
	s.cache = brokenCache{}

	if d := s.cache.Degraded(); d == "" {
		t.Fatal("precondition: brokenCache.Degraded() must return non-empty")
	}

	w := post(s, "payload", map[string]string{"X-YARAD-Token": "tok"})
	if w.Code != http.StatusOK {
		t.Fatalf("scan with broken cache: HTTP %d, body=%s", w.Code, w.Body.String())
	}
	var resp scanResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Matches) != 1 || resp.Matches[0].Rule != "EICAR_Test_File" {
		t.Fatalf("scan with broken cache returned wrong matches: %+v", resp.Matches)
	}
}

// TestBodyCacheHash verifies the fast verdict-cache fingerprint is deterministic,
// distinguishes distinct bodies (including single-bit flips), and is 16 bytes
// wide. It replaced SHA256 in the cache key (PERF: hashing multi-MB bodies on
// every cache hit was ~40% of server CPU); xxhash carries the cache-key load
// while the cryptographic SHA256 is computed lazily only on the scan (miss) path.
func TestBodyCacheHash(t *testing.T) {
	a := bytes.Repeat([]byte("malware payload "), 4096) // ~64 KiB
	b := make([]byte, len(a))
	copy(b, a)
	b[len(b)/2] ^= 0x01 // single-bit difference

	ha, hb := bodyCacheHash(a), bodyCacheHash(b)
	if len(ha) != 16 {
		t.Fatalf("bodyCacheHash width = %d bytes, want 16", len(ha))
	}
	if ha != bodyCacheHash(a) {
		t.Error("bodyCacheHash not deterministic for identical input")
	}
	if ha == hb {
		t.Error("bodyCacheHash collided on a single-bit-flipped body")
	}
	if bodyCacheHash(nil) == bodyCacheHash([]byte{0}) {
		t.Error("bodyCacheHash collided empty vs single-zero body")
	}
}
