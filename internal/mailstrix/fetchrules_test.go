package mailstrix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testRulesManifestGenerated = "2026-06-18T00:00:00Z"

func TestLoadManifestReportsLockContention(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockRules(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, ok, err := LoadManifest(dir); err == nil || ok {
		t.Fatalf("LoadManifest under contention: ok=%v err=%v", ok, err)
	}
}

// rulesServer serves a compiled.yac + manifest like the rolling release. yac is
// the bundle bytes; ver/libyara go into the manifest; the checksum is computed
// from yac (override with badSum to simulate corruption).
func rulesServer(t *testing.T, yac []byte, ver int, libyara, badSum string) *httptest.Server {
	t.Helper()
	return rulesServerWithGenerated(t, yac, ver, libyara, badSum, testRulesManifestGenerated)
}

func rulesServerWithGenerated(t *testing.T, yac []byte, ver int, libyara, badSum, generated string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(rulesHandler(yac, ver, libyara, badSum, generated))
}

func rulesHandler(yac []byte, ver int, libyara, badSum, generated string) *http.ServeMux {
	sum := sha256.Sum256(yac)
	checksum := "sha256:" + hex.EncodeToString(sum[:])
	if badSum != "" {
		checksum = badSum
	}
	m := RulesManifest{
		Version: ver, Generated: generated,
		Checksum: checksum, Libyara: libyara, Rules: 1, Size: int64(len(yac)),
	}
	mb, _ := json.Marshal(m)
	mux := http.NewServeMux()
	mux.HandleFunc("/"+manifestName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(mb) })
	mux.HandleFunc("/"+cachedRulesName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(yac) })
	return mux
}

// compiledYacBytes returns the bytes of a real compiled .yac, so a served bundle
// passes the new load-validation (FetchRules now yara.LoadRules-checks the temp
// bundle before swapping it into the cache).
func compiledYacBytes(t *testing.T, rule string) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bundle.yac")
	compiledYac(t, p, rule)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func seedLocal(t *testing.T, cacheDir string, ver int, yac []byte) {
	t.Helper()
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, cachedRulesName), yac, 0o600); err != nil {
		t.Fatal(err)
	}
	m := RulesManifest{Version: ver, Checksum: "sha256:x", Libyara: "4.5.2", Size: int64(len(yac))}
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(cacheDir, manifestName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFetchRulesUpdates(t *testing.T) {
	cacheDir := t.TempDir()
	newYac := compiledYacBytes(t, "rule N { condition: true }")
	srv := rulesServer(t, newYac, 5, "4.5.2", "")
	defer srv.Close()

	res, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updated || res.NewVersion != 5 {
		t.Fatalf("res = %+v, want updated v5", res)
	}
	got, _ := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if string(got) != string(newYac) {
		t.Errorf("bundle not installed: %q", got)
	}
	// Local manifest records the new version.
	lm := readLocalManifest(filepath.Join(cacheDir, manifestName))
	if lm.Version != 5 {
		t.Errorf("local manifest version = %d, want 5", lm.Version)
	}
}

func TestFetchRulesSkipsWhenUpToDate(t *testing.T) {
	cacheDir := t.TempDir()
	seedVerified(t, cacheDir, 7, "rule Current { condition: true }")
	cur, err := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if err != nil {
		t.Fatal(err)
	}
	srv := rulesServer(t, []byte("WOULD-BE-NEW"), 7, "4.5.2", "") // same version
	defer srv.Close()

	res, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated {
		t.Fatalf("updated despite equal version: %+v", res)
	}
	got, _ := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if string(got) != string(cur) {
		t.Errorf("bundle changed on a no-op: %q", got)
	}
}

func TestFetchRulesRefusesLibyaraSkew(t *testing.T) {
	cacheDir := t.TempDir()
	seedLocal(t, cacheDir, 1, []byte("CUR"))
	srv := rulesServer(t, []byte("NEW"), 2, "4.6.0", "") // newer but different libyara
	defer srv.Close()

	_, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client(), true)
	if err == nil {
		t.Fatal("expected refusal on libyara skew")
	}
	got, _ := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if string(got) != "CUR" {
		t.Errorf("bundle changed despite skew refusal: %q", got)
	}
}

func TestFetchRulesRejectsBadChecksum(t *testing.T) {
	cacheDir := t.TempDir()
	seedLocal(t, cacheDir, 1, []byte("CUR"))
	srv := rulesServer(t, []byte("NEW-CORRUPT"), 2, "4.5.2", "sha256:"+fmt.Sprintf("%064d", 0))
	defer srv.Close()

	_, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client(), true)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	got, _ := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if string(got) != "CUR" {
		t.Errorf("corrupt bundle was installed: %q", got)
	}
}

func TestFetchRulesKeepsBackup(t *testing.T) {
	cacheDir := t.TempDir()
	// A real (countable) bundle: an unreadable one now fails closed (AUD-06d-r1).
	old := compiledYacBytes(t, "rule O { condition: true }")
	seedLocal(t, cacheDir, 1, old)
	srv := rulesServer(t, compiledYacBytes(t, "rule N { condition: true }"), 2, "4.5.2", "")
	defer srv.Close()

	if _, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client(), true); err != nil {
		t.Fatal(err)
	}
	bak, err := os.ReadFile(filepath.Join(cacheDir, cachedRulesName+backupSuffix))
	if err != nil {
		t.Fatalf("backup not kept: %v", err)
	}
	if !bytes.Equal(bak, old) {
		t.Errorf("backup = %q, want the previous bundle", bak)
	}
}

// TestFetchRulesEmptyLibyaraSkipsSkewCheck: a dev build (ourLibyara="") accepts
// any remote libyara (skew check disabled).
func TestFetchRulesEmptyLibyaraSkipsSkewCheck(t *testing.T) {
	cacheDir := t.TempDir()
	srv := rulesServer(t, compiledYacBytes(t, "rule N { condition: true }"), 1, "9.9.9", "")
	defer srv.Close()

	res, err := FetchRules(context.Background(), srv.URL, cacheDir, "", srv.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updated {
		t.Fatalf("expected update with skew check disabled: %+v", res)
	}
}

// TestFetchRulesRejectsUnloadableBundle: a downloaded bundle whose bytes match the
// manifest size+checksum but do NOT load under libyara (corrupt at source / wrong
// libyara) must be rejected and the current cache + backup kept — integrity of the
// bytes is not proof they load.
func TestFetchRulesRejectsUnloadableBundle(t *testing.T) {
	cacheDir := t.TempDir()
	seedLocal(t, cacheDir, 1, []byte("CUR-BUNDLE"))
	// Garbage bytes, but rulesServer computes the checksum FROM them so verifyBundle
	// passes; only the load-validate catches it.
	srv := rulesServer(t, []byte("NOT-A-REAL-YAC-BUNDLE-ZZZZ"), 2, "4.5.2", "")
	defer srv.Close()

	_, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client(), true)
	if err == nil {
		t.Fatal("expected an error for an unloadable downloaded bundle")
	}
	got, _ := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if string(got) != "CUR-BUNDLE" {
		t.Errorf("unloadable bundle replaced the cache: %q", got)
	}
}

// TestRulesManifestJSONRoundTrip verifies that RulesManifest with Sources
// serialises and deserialises without loss.
func TestRulesManifestJSONRoundTrip(t *testing.T) {
	orig := RulesManifest{
		Version:   3,
		Generated: "2026-06-20T00:00:00Z",
		Checksum:  "sha256:abc123",
		Libyara:   "4.5.2",
		Rules:     42,
		Size:      1234,
		Sources: []RuleSource{
			{Name: "yaraforge", Repo: "https://github.com/YARAHQ/yara-forge", License: "mixed (see repo)", Ref: "latest", Set: "core"},
			{Name: "signature-base", Repo: "https://github.com/Neo23x0/signature-base", License: "CC BY-NC 4.0", Ref: "master"},
			{Name: "local", Repo: "https://github.com/myguard-labs/mailstrix", License: "MIT", Ref: "baked"},
		},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got RulesManifest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Version != orig.Version || len(got.Sources) != len(orig.Sources) {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}
	for i, s := range got.Sources {
		os := orig.Sources[i]
		if s.Name != os.Name || s.Repo != os.Repo || s.License != os.License || s.Ref != os.Ref || s.Set != os.Set {
			t.Errorf("sources[%d] = %+v, want %+v", i, s, os)
		}
	}
}

// TestLoadSources verifies that LoadSources reads and parses sources.json from a dir.
func TestLoadSources(t *testing.T) {
	dir := t.TempDir()
	srcs := []RuleSource{
		{Name: "yaraforge", Repo: "https://github.com/YARAHQ/yara-forge", License: "mixed (see repo)", Ref: "latest", Set: "core"},
		{Name: "local", Repo: "https://github.com/myguard-labs/mailstrix", License: "MIT", Ref: "baked"},
	}
	b, _ := json.Marshal(srcs)
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	got := LoadSources(dir)
	if len(got) != 2 {
		t.Fatalf("got %d sources, want 2", len(got))
	}
	if got[0].Name != "yaraforge" || got[0].Set != "core" {
		t.Errorf("sources[0] = %+v", got[0])
	}
	if got[1].Name != "local" || got[1].Ref != "baked" {
		t.Errorf("sources[1] = %+v", got[1])
	}
}

// TestLoadSourcesMissing returns nil for a missing file (no error).
func TestLoadSourcesMissing(t *testing.T) {
	if got := LoadSources(t.TempDir()); got != nil {
		t.Fatalf("expected nil for missing sources.json, got %v", got)
	}
}

// countingHandler counts every request before delegating to h.
func countingHandler(n *atomic.Int64, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h.ServeHTTP(w, r)
	})
}

// redirectHandler sends every request to target+path (same path, new origin).
func redirectHandler(n *atomic.Int64, target func() string) http.Handler {
	return countingHandler(n, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target()+r.URL.Path, http.StatusFound)
	}))
}

// countingTransport counts round trips so URL refusals can prove no request left.
type countingTransport struct{ n atomic.Int64 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, fmt.Errorf("unexpected request")
}

func newRulesYac(t *testing.T) []byte {
	t.Helper()
	return compiledYacBytes(t, "rule Transport { condition: true }")
}

func TestFetchRulesHTTPSBase(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(countingHandler(&hits, rulesHandler(newRulesYac(t), 2, "4.5.2", "", testRulesManifestGenerated)))
	defer srv.Close()
	hc := srv.Client()
	res, err := FetchRules(context.Background(), srv.URL, t.TempDir(), "4.5.2", hc, false)
	if err != nil || !res.Updated || res.NewVersion != 2 {
		t.Fatalf("https base: res=%+v err=%v", res, err)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits=%d, want manifest+bundle", hits.Load())
	}
	if hc.CheckRedirect != nil {
		t.Fatal("caller client was mutated")
	}
}

// A release asset redirects to another https origin (GitHub to object store).
func TestFetchRulesFollowsHTTPSRedirect(t *testing.T) {
	var storeHits, frontHits, vetoes atomic.Int64
	store := httptest.NewTLSServer(countingHandler(&storeHits, rulesHandler(newRulesYac(t), 3, "4.5.2", "", testRulesManifestGenerated)))
	defer store.Close()
	front := httptest.NewTLSServer(redirectHandler(&frontHits, func() string { return store.URL }))
	defer front.Close()
	pool := x509.NewCertPool()
	pool.AddCert(store.Certificate())
	pool.AddCert(front.Certificate())
	hc := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			vetoes.Add(1)
			return nil
		},
	}
	res, err := FetchRules(context.Background(), front.URL+"/", t.TempDir(), "4.5.2", hc, false)
	if err != nil || !res.Updated || res.NewVersion != 3 {
		t.Fatalf("https->https redirect: res=%+v err=%v", res, err)
	}
	if frontHits.Load() != 2 || storeHits.Load() != 2 {
		t.Fatalf("front=%d store=%d, want 2 each", frontHits.Load(), storeHits.Load())
	}
	// The caller's own policy still runs (composed, not replaced).
	if vetoes.Load() != 2 {
		t.Fatalf("caller CheckRedirect calls=%d, want 2", vetoes.Load())
	}
}

func TestFetchRulesComposesCallerRedirectVeto(t *testing.T) {
	var hits atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewTLSServer(redirectHandler(&hits, func() string { return srv.URL + "/next" }))
	defer srv.Close()
	hc := srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return fmt.Errorf("caller veto") }
	_, err := FetchRules(context.Background(), srv.URL, t.TempDir(), "4.5.2", hc, false)
	if err == nil || !strings.Contains(err.Error(), "caller veto") {
		t.Fatalf("caller CheckRedirect not honoured: %v", err)
	}
}

func TestFetchRulesPlainHTTPRequiresOptIn(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(countingHandler(&hits, rulesHandler(newRulesYac(t), 2, "4.5.2", "", testRulesManifestGenerated)))
	defer srv.Close()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	_, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client(), false)
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("plain http accepted without opt-in: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("refused URL still made %d requests", hits.Load())
	}
	if _, statErr := os.Stat(cacheDir); !os.IsNotExist(statErr) {
		t.Fatalf("refused URL touched the cache dir: %v", statErr)
	}
	res, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client(), true)
	if err != nil || !res.Updated {
		t.Fatalf("opt-in plain http: res=%+v err=%v", res, err)
	}
}

func TestFetchRulesRefusesHTTPSDowngradeRedirect(t *testing.T) {
	for _, allowHTTP := range []bool{false, true} {
		t.Run(fmt.Sprintf("allowHTTP=%v", allowHTTP), func(t *testing.T) {
			var plainHits, frontHits atomic.Int64
			plain := httptest.NewServer(countingHandler(&plainHits, rulesHandler(newRulesYac(t), 2, "4.5.2", "", testRulesManifestGenerated)))
			defer plain.Close()
			front := httptest.NewTLSServer(redirectHandler(&frontHits, func() string { return plain.URL }))
			defer front.Close()
			res, err := FetchRules(context.Background(), front.URL, t.TempDir(), "4.5.2", front.Client(), allowHTTP)
			if err == nil || res.Updated || !strings.Contains(err.Error(), "from https to http") {
				t.Fatalf("downgrade redirect accepted: res=%+v err=%v", res, err)
			}
			if frontHits.Load() != 1 || plainHits.Load() != 0 {
				t.Fatalf("front=%d plain=%d, want 1 and 0", frontHits.Load(), plainHits.Load())
			}
		})
	}
}

// With the opt-in, an http origin may redirect within http or up to https.
func TestFetchRulesOptInHTTPRedirectToHTTP(t *testing.T) {
	var hits, frontHits atomic.Int64
	plain := httptest.NewServer(countingHandler(&hits, rulesHandler(newRulesYac(t), 2, "4.5.2", "", testRulesManifestGenerated)))
	defer plain.Close()
	front := httptest.NewServer(redirectHandler(&frontHits, func() string { return plain.URL }))
	defer front.Close()
	if res, err := FetchRules(context.Background(), front.URL, t.TempDir(), "4.5.2", front.Client(), true); err != nil || !res.Updated {
		t.Fatalf("opt-in http->http: res=%+v err=%v", res, err)
	}
}

func TestFetchRulesRefusesMalformedURLs(t *testing.T) {
	for _, raw := range []string{
		"", "garbage", "ftp://example.com/rules", "file:///etc/passwd",
		"gopher://example.com", "https://", "https:///rules", "https://:443/rules",
		"http://", "//example.com/rules", "://example.com", "https://exa mple.com",
		"https://[::1", "HTTPS://", "javascript:alert(1)",
	} {
		for _, allowHTTP := range []bool{false, true} {
			rt := &countingTransport{}
			cacheDir := filepath.Join(t.TempDir(), "cache")
			_, err := FetchRules(context.Background(), raw, cacheDir, "4.5.2", &http.Client{Transport: rt}, allowHTTP)
			if err == nil {
				t.Fatalf("%q (allowHTTP=%v) accepted", raw, allowHTTP)
			}
			if rt.n.Load() != 0 {
				t.Fatalf("%q made %d requests", raw, rt.n.Load())
			}
			if _, statErr := os.Stat(cacheDir); !os.IsNotExist(statErr) {
				t.Fatalf("%q touched the cache dir", raw)
			}
		}
	}
}

func TestCheckRulesURL(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		allowHTTP bool
		ok        bool
	}{
		{"https://example.com/dir", false, true},
		{"HTTPS://example.com/dir", false, true},
		{"https://127.0.0.1:8443", false, true},
		{"http://mirror.lan/rules", false, false},
		{"http://mirror.lan/rules", true, true},
		{"HTTP://mirror.lan/rules", false, false},
		{"ftp://mirror.lan/rules", true, false},
		{"https://", true, false},
		{"garbage", true, false},
	} {
		if err := checkRulesURL(tc.raw, tc.allowHTTP); (err == nil) != tc.ok {
			t.Errorf("checkRulesURL(%q, %v) = %v, want ok=%v", tc.raw, tc.allowHTTP, err, tc.ok)
		}
	}
}

func TestCheckRulesBaseURL(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		allowHTTP bool
		ok        bool
		desc      string
	}{
		{"https://example.com/rules/", false, true, "https with trailing slash"},
		{"https://example.com/rules", false, true, "https without trailing slash"},
		{"http://mirror.lan/rules", true, true, "http with opt-in"},
		{"https://s3cretU:s3cretP@example.com/r", false, false, "userinfo with password"},
		{"https://s3cretU@example.com/r", false, false, "userinfo without password"},
		{"https://example.com/r?x=1", false, false, "query with value"},
		{"https://example.com/r?", false, false, "bare trailing query marker"},
		{"https://example.com/r#frag", false, false, "fragment"},
		{"https://example.com/r#", false, false, "bare trailing fragment marker"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := checkRulesBaseURL(tc.raw, tc.allowHTTP)
			if (err == nil) != tc.ok {
				t.Fatalf("checkRulesBaseURL(%q, %v) = %v, want ok=%v", tc.raw, tc.allowHTTP, err, tc.ok)
			}
			// For userinfo cases, verify that error message does not contain credentials
			if !tc.ok && strings.Contains(tc.raw, "s3cretU") {
				errMsg := err.Error()
				if strings.Contains(errMsg, "s3cretU") || strings.Contains(errMsg, "s3cretP") {
					t.Errorf("error message leaked credentials: %v", errMsg)
				}
			}
			// For query/fragment cases, verify that error message does not contain the URL
			if !tc.ok && (strings.Contains(tc.raw, "?") || strings.Contains(tc.raw, "#")) {
				errMsg := err.Error()
				if strings.Contains(errMsg, tc.raw) {
					t.Errorf("error message echoed the URL: %v", errMsg)
				}
			}
		})
	}
}

// TestFetchRulesRefusesUserinfoBaseURL verifies that a base URL with userinfo
// (credentials) is rejected before any HTTP request is made.
func TestFetchRulesRefusesUserinfoBaseURL(t *testing.T) {
	rt := &countingTransport{}
	cacheDir := filepath.Join(t.TempDir(), "cache")
	_, err := FetchRules(context.Background(), "https://s3cretU:s3cretP@example.com/r", cacheDir, "4.5.2", &http.Client{Transport: rt}, false)
	if err == nil {
		t.Fatal("userinfo base URL was accepted")
	}
	if rt.n.Load() != 0 {
		t.Fatalf("userinfo base URL made %d requests, want 0", rt.n.Load())
	}
	if _, statErr := os.Stat(cacheDir); !os.IsNotExist(statErr) {
		t.Fatalf("userinfo base URL touched the cache dir")
	}
}

// TestFetchRulesFollowsHTTPSRedirectToQueryURL verifies that redirects to URLs
// with query parameters (e.g., GitHub release assets) still succeed. The base URL
// itself must not have a query, but redirect targets may.
func TestFetchRulesFollowsHTTPSRedirectToQueryURL(t *testing.T) {
	yac := newRulesYac(t)
	var storeHits, frontHits atomic.Int64
	store := httptest.NewTLSServer(countingHandler(&storeHits, rulesHandler(yac, 2, "4.5.2", "", testRulesManifestGenerated)))
	defer store.Close()
	front := httptest.NewTLSServer(redirectHandler(&frontHits, func() string { return store.URL }))
	defer front.Close()
	pool := x509.NewCertPool()
	pool.AddCert(store.Certificate())
	pool.AddCert(front.Certificate())
	hc := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	// Base URL has no query, so it should pass validation
	res, err := FetchRules(context.Background(), front.URL+"/", t.TempDir(), "4.5.2", hc, false)
	if err != nil || !res.Updated || res.NewVersion != 2 {
		t.Fatalf("https->https redirect to query URL: res=%+v err=%v", res, err)
	}
}

// Redirects to a non-http scheme are refused by the guard itself.
func TestRulesClientRefusesRedirectToOtherScheme(t *testing.T) {
	hc := rulesClient(&http.Client{}, true)
	via := []*http.Request{httptest.NewRequest(http.MethodGet, "http://mirror.lan/a", nil)}
	for _, target := range []string{"ftp://mirror.lan/a", "file:///etc/passwd"} {
		req := httptest.NewRequest(http.MethodGet, "http://placeholder/", nil)
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		req.URL = u
		if err := hc.CheckRedirect(req, via); err == nil {
			t.Fatalf("redirect to %s accepted", target)
		}
	}
}

// The hop cap holds for a client with no CheckRedirect of its own (the
// serve-time updater): nine redirects succeed, ten are refused.
func TestFetchRulesRedirectHopCap(t *testing.T) {
	yac := newRulesYac(t)
	for _, tc := range []struct {
		hops int
		ok   bool
	}{{maxRulesRedirects - 1, true}, {maxRulesRedirects, false}, {1000, false}} {
		t.Run(fmt.Sprint(tc.hops), func(t *testing.T) {
			var hits atomic.Int64
			final := rulesHandler(yac, 2, "4.5.2", "", testRulesManifestGenerated)
			srv := httptest.NewTLSServer(countingHandler(&hits, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var n int
				if _, err := fmt.Sscanf(r.URL.Query().Get("n"), "%d", &n); err != nil {
					n = 0
				}
				if n < tc.hops {
					http.Redirect(w, r, fmt.Sprintf("%s?n=%d", r.URL.Path, n+1), http.StatusFound)
					return
				}
				final.ServeHTTP(w, r)
			})))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			hc := srv.Client()
			res, err := FetchRules(ctx, srv.URL, t.TempDir(), "4.5.2", hc, false)
			if tc.ok {
				if err != nil || !res.Updated {
					t.Fatalf("%d hops: res=%+v err=%v", tc.hops, res, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
				t.Fatalf("%d hops not capped: %v", tc.hops, err)
			}
			if hits.Load() != maxRulesRedirects {
				t.Fatalf("hits=%d, want %d", hits.Load(), maxRulesRedirects)
			}
			if hc.CheckRedirect != nil {
				t.Fatal("caller client was mutated")
			}
		})
	}
}
