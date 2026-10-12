package urlhaus

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/urlcand"
)

type refreshTestRoundTripper func(*http.Request) (*http.Response, error)

func (f refreshTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRefreshSuccessPersistsSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/downloads/csv_online/" || req.Header.Get("Auth-Key") != "fixture-key" || req.Header.Get("Accept") != "text/csv" {
			t.Errorf("refresh request contract changed: %s %s auth=%q accept=%q", req.Method, req.URL.Path, req.Header.Get("Auth-Key"), req.Header.Get("Accept"))
		}
		if _, err := w.Write([]byte(sampleCSV)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	logs := []string{}
	c := &Checker{
		key:       "fixture-key",
		cachePath: filepath.Join(t.TempDir(), "urlhaus.csv"),
		logf:      func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
		client: &http.Client{Transport: refreshTestRoundTripper(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != feedURL || req.Method != http.MethodGet {
				t.Errorf("original feed endpoint changed: %s %s", req.Method, req.URL)
			}
			// Rewrite only this private client's cloned request to the real loopback
			// server. Production endpoint/headers and the global transport stay intact.
			local := req.Clone(req.Context())
			copyURL := *req.URL
			copyURL.Scheme, copyURL.Host = target.Scheme, target.Host
			local.URL = &copyURL
			return client.Do(local)
		})},
	}
	for attempt := 0; attempt < 2; attempt++ {
		before := time.Now().Unix()
		if err := c.refreshOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		hits := c.Check([]byte("http://evil.example/malware.exe"), 64)
		if len(hits) != 1 || hits[0].URL != "http://evil.example/malware.exe" || hits[0].Host || hits[0].Rule() != "URLHAUS_MALWARE_URL" {
			t.Fatalf("successful refresh must publish actual URL detection: %+v", hits)
		}
		if refreshed := c.lastRefresh.Load(); refreshed < before || refreshed > time.Now().Unix() {
			t.Fatalf("successful refresh timestamp missing: %d", refreshed)
		}
		cached, err := os.ReadFile(c.cachePath)
		if err != nil || string(cached) != sampleCSV {
			t.Fatalf("successful refresh must persist actual feed bytes: %v", err)
		}
		if len(logs) != attempt+1 || logs[attempt] != "urlhaus feed loaded: 2 urls / 2 hosts" {
			t.Fatalf("successful refresh publication log missing: %v", logs)
		}
	}
}

type p12FailedFeedBody struct {
	data   string
	err    error
	reads  int
	closed bool
}

func (b *p12FailedFeedBody) Read(dst []byte) (int, error) {
	b.reads++
	return copy(dst, b.data), b.err
}

func (b *p12FailedFeedBody) Close() error { b.closed = true; return nil }

// A partial valid feed plus a read error must never replace the last good set.
// This does not rely on a real request being canceled during a background read.
func TestP12RefreshBodyFailureRetainsSnapshot(t *testing.T) {
	c := testChecker(t)
	before := c.rs.Load()
	c.lastRefresh.Store(123)
	c.cachePath = filepath.Join(t.TempDir(), "urlhaus.csv")
	if err := os.WriteFile(c.cachePath, []byte(sampleCSV), 0600); err != nil {
		t.Fatal(err)
	}
	body := &p12FailedFeedBody{
		data: `"1","2024-01-01","http://partial.example/p","online"` + "\n",
		err:  errors.New("fixture response body interrupted"),
	}
	c.client = &http.Client{Transport: refreshTestRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	})}
	if err := c.refreshOnce(context.Background()); !errors.Is(err, body.err) {
		t.Fatalf("response body error was not preserved: %v", err)
	}
	if body.reads != 1 || !body.closed {
		t.Fatal("failed response body was not read and closed")
	}
	if c.rs.Load() != before || c.lastRefresh.Load() != 123 {
		t.Fatal("partial failed feed replaced the last good snapshot or timestamp")
	}
	cache, err := os.ReadFile(c.cachePath)
	if err != nil || string(cache) != sampleCSV {
		t.Fatalf("partial failed feed replaced the last good cache: %v", err)
	}
}

// TestWarmStartFromCache: a persisted feed snapshot in cacheDir is loaded into
// the set at New() time, so a lookup hits before any network refresh. (New's
// background refresh fires against the real feed with a bogus key and fails
// harmlessly; warmStart ran synchronously first.)
func TestWarmStartFromCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "urlhaus.csv"), []byte(sampleCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New("bogus-key", 0, dir, func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil with a key set")
	}
	hits := c.Check([]byte("click http://evil.example/malware.exe now"), 64)
	if len(hits) == 0 {
		t.Error("warm-started feed should match the cached URL before any refresh")
	}
}

// TestWarmStartBadCacheIgnored: a corrupt cache file is ignored (logged), New
// still returns a usable (empty) checker.
func TestWarmStartBadCacheIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "urlhaus.csv"), []byte("\x00\x01 not csv"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := New("bogus-key", 0, dir, func(string, ...any) {}); c == nil {
		t.Error("New should still return a checker despite a bad cache")
	}
}

const sampleCSV = `# Dump generated 2024-01-02
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2024-01-01 00:00:00","http://evil.example/malware.exe","online","2024-01-02","malware_download","exe,doc","https://urlhaus.abuse.ch/url/1/","anon"
"2","2024-01-02 00:00:00","https://bad.host.test/path?x=1","online","2024-01-02","malware_download","","https://urlhaus.abuse.ch/url/2/","anon"
`

func testChecker(t *testing.T) *Checker {
	t.Helper()
	rs, err := parseFeed(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{logf: func(string, ...any) {}}
	c.rs.Store(rs)
	return c
}

func TestParseFeed(t *testing.T) {
	rs, err := parseFeed(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.urls) != 2 {
		t.Errorf("urls=%d want 2", len(rs.urls))
	}
	if _, ok := rs.hosts["evil.example"]; !ok {
		t.Error("host evil.example missing")
	}
}

func TestCheckExactURL(t *testing.T) {
	hits := testChecker(t).Check([]byte("please click http://evil.example/malware.exe right now"), 64)
	if len(hits) != 1 || hits[0].Host || hits[0].Deobf {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].Rule() != "URLHAUS_MALWARE_URL" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckHostMatch(t *testing.T) {
	// A different path on a known-bad host -> host-level hit, not exact.
	hits := testChecker(t).Check([]byte("see http://bad.host.test/some/other/path"), 64)
	if len(hits) != 1 || !hits[0].Host {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].Rule() != "URLHAUS_MALWARE_HOST" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckDeobf(t *testing.T) {
	// Defanged URL: only found after un-defanging -> Deobf hit.
	hits := testChecker(t).Check([]byte("dropper url: hxxp://evil[.]example/malware.exe"), 64)
	if len(hits) != 1 || !hits[0].Deobf {
		t.Fatalf("deobf hits=%+v", hits)
	}
	if hits[0].Rule() != "URLHAUS_MALWARE_URL_DEOBF" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckClean(t *testing.T) {
	if hits := testChecker(t).Check([]byte("nothing bad here https://good.example/ok"), 64); len(hits) != 0 {
		t.Errorf("clean buffer matched: %+v", hits)
	}
}

func TestCheckBudget(t *testing.T) {
	// maxURLs bounds how many URLs are examined; with budget 0 -> default 64, so
	// use 1 and a buffer whose first URL is clean to prove the bad one past the
	// budget is not examined.
	hits := testChecker(t).Check([]byte("https://good.example/a http://evil.example/malware.exe"), 1)
	if len(hits) != 0 {
		t.Errorf("budget not honoured: %+v", hits)
	}
}

func TestCheckCandidatesEmptyNoAlloc(t *testing.T) {
	c := testChecker(t)
	allocs := testing.AllocsPerRun(100, func() {
		if hits := c.CheckCandidates(nil, 64); hits != nil {
			t.Fatalf("empty candidates hit: %+v", hits)
		}
	})
	if allocs != 0 {
		t.Errorf("empty CheckCandidates allocs = %g, want 0", allocs)
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"http://Evil.Example/":        "http://evil.example",
		"https://h.test:443/p":        "https://h.test/p",
		"http://h.test:80/p?q=1#frag": "http://h.test/p?q=1",
		"ftp://h.test/x":              "",
		"not a url":                   "",
	}
	for in, want := range cases {
		if got, _ := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNewDisabledNoKey(t *testing.T) {
	if New("", 0, "", func(string, ...any) {}) != nil {
		t.Error("empty key must disable the checker (nil)")
	}
}

// BenchmarkCheckNoDefang measures Check() on a buffer that does NOT trigger
// defanging. The defang gate now scans for exact obfuscation tokens, so ordinary
// prose and URLs may contain x/X without forcing the defanged string copy.
// b.ReportAllocs() shows the alloc drop from avoiding the full-buffer
// []byte→string copy that the old check(string(data),...) call paid.
func BenchmarkCheckNoDefang(b *testing.B) {
	c := testCheckerB(b)
	// ~256 KB buffer. Noise intentionally contains x-heavy normal words: that is
	// the real-mail case the stricter defang-token gate should keep cheap.
	const (
		bodySize = 256 * 1024
		noise    = "example text xlsx exe maximum next extra clean prose "
	)
	buf := make([]byte, bodySize)
	for i := range buf {
		buf[i] = noise[i%len(noise)]
	}
	copy(buf[512:], []byte("http://neutral.example/file.exe"))
	copy(buf[bodySize-200:], []byte("https://safe.example/not-bad"))
	// Confirm urlcand.Extract produces no deobf candidates (defang gate skips).
	for _, c := range urlcand.Extract(buf, 64) {
		if c.Deobf {
			b.Fatal("bench buffer unexpectedly triggers defang output")
		}
	}
	b.SetBytes(int64(bodySize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Check(buf, 64)
	}
}

func testCheckerB(b *testing.B) *Checker {
	b.Helper()
	rs, err := parseFeed(strings.NewReader(sampleCSV))
	if err != nil {
		b.Fatal(err)
	}
	c := &Checker{logf: func(string, ...any) {}}
	c.rs.Store(rs)
	return c
}

// TestCloseNilSafeAndIdempotent: Close on a nil *Checker (disabled feature) and
// a double Close must not panic, so shutdown code can call it unconditionally.
// (STAB-7)
func TestCloseNilSafeAndIdempotent(t *testing.T) {
	var nilC *Checker
	nilC.Close() // must be a no-op, not a panic

	// A live checker (bogus key so the background fetch just fails) must close
	// cleanly, and a second Close must be a no-op rather than a double-close
	// panic on the stop channel.
	c := New("bogus-key", 0, "", func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil for a non-empty key")
	}
	c.Close()
	c.Close() // idempotent

	select {
	case <-c.stop:
		// closed as expected
	default:
		t.Fatal("Close did not close the stop channel")
	}
}
