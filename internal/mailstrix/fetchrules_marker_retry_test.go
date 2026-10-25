package mailstrix

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func markerRetryServer(t *testing.T, inner *markerServer, intercept func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	t.Helper()
	u, err := url.Parse(inner.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !intercept(w, r) {
			proxy.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(front.Close)
	return front
}

func retryFetch(t *testing.T, srv *httptest.Server, dir string, opts fetchOptions) FetchResult {
	t.Helper()
	opts.allowHTTP = true
	res, err := fetchRules(t.Context(), srv.URL, dir, "", srv.Client(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func retryRecord(t *testing.T, dir string) *markerRetryState {
	t.Helper()
	return trustedLocalManifest(filepath.Join(dir, cachedRulesName), filepath.Join(dir, manifestName)).markerRetry
}

func assertRetryClean(t *testing.T, dir string) {
	t.Helper()
	assertNoLeftovers(t, dir)
	entries, err := filepath.Glob(filepath.Join(dir, ".marker-retry-*"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("retry snapshot leftovers=%v err=%v", entries, err)
	}
}

func TestFetchRulesMarkerRetrySameVersion(t *testing.T) {
	f, dir := newMarkerFixture(t), t.TempDir()
	seedLocal(t, dir, 1, compiledYacBytes(t, "rule Old { condition: false }"))
	log := &markerLog{}
	scanner := cacheScanner(t, dir, log)
	inner := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
	var hits atomic.Int64
	front := markerRetryServer(t, inner, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/"+testMarkerAsset && hits.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	now := time.Unix(1700000000, 0)
	opts := fetchOptions{now: func() time.Time { return now }, reload: scanner.reloadLockedCache, logf: log.logf}
	first := retryFetch(t, front, dir, opts)
	if !first.Updated || first.NewVersion != 2 || !strings.HasPrefix(first.Marker, MarkerStatusRejected) || scanner.markerRules.Load() != nil {
		t.Fatalf("transient failure must install compiled-only v2: %+v", first)
	}
	r := retryRecord(t, dir)
	if r == nil || r.Attempts != 1 || !r.After.Equal(now.Add(time.Minute)) {
		t.Fatalf("missing initial bounded retry receipt: %+v", r)
	}
	before, err := os.ReadFile(filepath.Join(dir, cachedRulesName+backupSuffix))
	if err != nil {
		t.Fatal(err)
	}
	now = r.After.Add(-time.Nanosecond)
	if early := retryFetch(t, front, dir, opts); early.Updated || early.Marker != "" || hits.Load() != 1 {
		t.Fatalf("retried before backoff expired: %+v hits=%d", early, hits.Load())
	}
	now = r.After
	second := retryFetch(t, front, dir, opts)
	if second.Updated || second.LocalVersion != 2 || second.NewVersion != 2 || second.Marker != MarkerStatusInstalled {
		t.Fatalf("same-version retry did not install bound marker tree: %+v", second)
	}
	if scanner.markerRules.Load() == nil || !log.has(markerLoadedLog) || hits.Load() != 2 || inner.count("/"+cachedRulesName) != 1 {
		t.Fatalf("retry must reload marker without redownloading compiled.yac: hits=%d bundle=%d", hits.Load(), inner.count("/"+cachedRulesName))
	}
	after, _ := os.ReadFile(filepath.Join(dir, cachedRulesName+backupSuffix))
	if !bytes.Equal(before, after) || retryRecord(t, dir) != nil {
		t.Fatal("retry changed bundle backup or retained a completed receipt")
	}
	if cacheScanner(t, dir, &markerLog{}).markerRules.Load() == nil {
		t.Fatal("recovered tree does not survive restart")
	}
	retryFetch(t, front, dir, opts)
	if hits.Load() != 2 {
		t.Fatal("installed marker was downloaded again")
	}
	assertRetryClean(t, dir)
}

func TestFetchRulesMarkerRetryEOFBeforeHeaders(t *testing.T) {
	f, dir := newMarkerFixture(t), t.TempDir()
	seedLocal(t, dir, 1, compiledYacBytes(t, "rule Old { condition: false }"))
	log := &markerLog{}
	scanner := cacheScanner(t, dir, log)
	inner := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
	var failMarker atomic.Bool
	var closed atomic.Int64
	failMarker.Store(true)
	front := markerRetryServer(t, inner, func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/"+testMarkerAsset && failMarker.Load() {
			closed.Add(1)
			// Abort every marker request until FetchRules returns: Transport
			// may retry an idempotent GET on a previously reused connection.
			panic(http.ErrAbortHandler)
		}
		return false
	})
	now := time.Unix(1700000000, 0)
	opts := fetchOptions{now: func() time.Time { return now }, reload: scanner.reloadLockedCache, logf: log.logf}
	first := retryFetch(t, front, dir, opts)
	failMarker.Store(false)
	if closed.Load() == 0 || inner.count("/"+testMarkerAsset) != 0 || !first.Updated || first.NewVersion != 2 || !strings.Contains(first.Marker, "EOF") || scanner.markerRules.Load() != nil {
		t.Fatalf("initial EOF must install compiled-only v2: %+v closed=%d", first, closed.Load())
	}
	if got, err := os.ReadFile(filepath.Join(dir, cachedRulesName)); err != nil || !bytes.Equal(got, f.main) {
		t.Fatalf("EOF marker failure did not install the compiled bundle: %v", err)
	}
	r := retryRecord(t, dir)
	if r == nil || r.Attempts != 1 || !r.After.Equal(now.Add(time.Minute)) {
		t.Fatalf("EOF before response headers did not retain a transient marker receipt: %+v", r)
	}
	now = r.After
	recovered := retryFetch(t, front, dir, opts)
	if recovered.Updated || recovered.LocalVersion != 2 || recovered.NewVersion != 2 || recovered.Marker != MarkerStatusInstalled || scanner.markerRules.Load() == nil || !log.has(markerLoadedLog) {
		t.Fatalf("same-version EOF retry did not install the bound marker tree: %+v", recovered)
	}
	if inner.count("/"+cachedRulesName) != 1 || inner.count("/"+testMarkerAsset) != 1 || retryRecord(t, dir) != nil {
		t.Fatal("EOF recovery redownloaded the bundle or retained its retry receipt")
	}
	assertRetryClean(t, dir)
}

func TestFetchRulesMarkerRetryDisabledAndPermanent(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		off  bool
		bad  bool
	}{{"disabled-after-transient", 503, true, false}, {"permanent-http", 404, false, false}, {"invalid-archive", 0, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f, dir := newMarkerFixture(t), t.TempDir()
			archive := f.archive
			if tc.bad {
				archive = []byte("malformed archive with a matching signed digest")
			}
			inner := newMarkerServer(t, f.main, 2, f.field(archive), archive)
			var hits atomic.Int64
			front := markerRetryServer(t, inner, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/"+testMarkerAsset {
					return false
				}
				hits.Add(1)
				if tc.code != 0 {
					w.WriteHeader(tc.code)
					return true
				}
				return false
			})
			now := time.Unix(1700000000, 0)
			opts := fetchOptions{now: func() time.Time { return now }, logf: (&markerLog{}).logf}
			retryFetch(t, front, dir, opts)
			now = now.Add(24 * time.Hour)
			opts.markersOff = tc.off
			retryFetch(t, front, dir, opts)
			if hits.Load() != 1 {
				t.Fatalf("disabled/permanent failure was retried: %d", hits.Load())
			}
			if !tc.off && retryRecord(t, dir) != nil {
				t.Fatal("permanent failure retained retry state")
			}
			assertNoTree(t, dir)
			assertRetryClean(t, dir)
		})
	}
}

func TestFetchRulesMarkerRetryBackoffAndPermanentResponse(t *testing.T) {
	f, dir := newMarkerFixture(t), t.TempDir()
	inner := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
	var hits atomic.Int64
	front := markerRetryServer(t, inner, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/"+testMarkerAsset {
			return false
		}
		if hits.Add(1) == 10 {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusBadGateway)
		}
		return true
	})
	now := time.Unix(1700000000, 0)
	opts := fetchOptions{now: func() time.Time { return now }, logf: (&markerLog{}).logf}
	for i := 1; i <= 10; i++ {
		retryFetch(t, front, dir, opts)
		r := retryRecord(t, dir)
		if i == 10 {
			if r != nil {
				t.Fatal("permanent retry response retained a receipt")
			}
			break
		}
		wantDelay := min(time.Minute<<uint(min(i, markerRetryMaxAttempts)-1), time.Hour)
		if r == nil || r.Attempts != min(i, markerRetryMaxAttempts) || !r.After.Equal(now.Add(wantDelay)) {
			t.Fatalf("attempt %d: receipt=%+v delay=%v", i, r, wantDelay)
		}
		now = r.After
	}
	now = now.Add(24 * time.Hour)
	retryFetch(t, front, dir, opts)
	if hits.Load() != 10 || inner.count("/"+cachedRulesName) != 1 {
		t.Fatalf("permanent stop/bundle reuse failed: marker=%d bundle=%d", hits.Load(), inner.count("/"+cachedRulesName))
	}
	assertRetryClean(t, dir)
}

func TestFetchRulesMarkerRetryConcurrentRefresh(t *testing.T) {
	for _, newer := range []bool{false, true} {
		t.Run(fmt.Sprintf("newer=%v", newer), func(t *testing.T) {
			f, dir := newMarkerFixture(t), t.TempDir()
			inner := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			var hits atomic.Int64
			front := markerRetryServer(t, inner, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/"+testMarkerAsset {
					return false
				}
				if hits.Add(1) == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return true
				}
				close(entered)
				<-release
				return false
			})
			now := time.Unix(1700000000, 0)
			opts := fetchOptions{allowHTTP: true, now: func() time.Time { return now }, logf: (&markerLog{}).logf}
			retryFetch(t, front, dir, opts)
			now = retryRecord(t, dir).After
			type result struct {
				res FetchResult
				err error
			}
			done := make(chan result, 1)
			go func() {
				res, err := fetchRules(t.Context(), front.URL, dir, "", front.Client(), opts)
				done <- result{res, err}
			}()
			select {
			case <-entered:
			case <-time.After(20 * time.Second):
				t.Fatal("retry never reached marker download")
			}
			if newer {
				v3 := newMarkerServer(t, compiledYacBytes(t, nRules(12)), 3, nil, nil)
				if res := retryFetch(t, v3.Server, dir, opts); !res.Updated || res.NewVersion != 3 {
					t.Fatalf("concurrent v3 update failed: %+v", res)
				}
			} else {
				if res := retryFetch(t, front, dir, opts); res.Updated || res.Marker != "" || hits.Load() != 2 {
					t.Fatalf("concurrent retry bypassed claim: %+v hits=%d", res, hits.Load())
				}
			}
			unblock()
			got := <-done
			if got.err != nil {
				t.Fatal(got.err)
			}
			if newer {
				if got.res.NewVersion != 3 || got.res.Marker == MarkerStatusInstalled {
					t.Fatalf("stale retry replaced newer generation: %+v", got.res)
				}
				assertNoTree(t, dir)
			} else if got.res.Marker != MarkerStatusInstalled {
				t.Fatalf("claimed retry failed: %+v", got.res)
			}
			assertRetryClean(t, dir)
		})
	}
}

func TestFetchRulesMarkerRetryReloadRollback(t *testing.T) {
	f, dir := newMarkerFixture(t), t.TempDir()
	inner := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
	var hits atomic.Int64
	front := markerRetryServer(t, inner, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/"+testMarkerAsset && hits.Add(1) == 1 {
			w.WriteHeader(503)
			return true
		}
		return false
	})
	now := time.Unix(1700000000, 0)
	opts := fetchOptions{allowHTTP: true, now: func() time.Time { return now }, logf: (&markerLog{}).logf}
	retryFetch(t, front, dir, opts)
	now = retryRecord(t, dir).After
	opts.reload = func() error { return errors.New("injected retry reload failure") }
	res, err := fetchRules(t.Context(), front.URL, dir, "", front.Client(), opts)
	if err == nil || !strings.Contains(err.Error(), "injected retry reload failure") || res.Updated || res.Marker == MarkerStatusInstalled {
		t.Fatalf("retry reload failure not propagated: res=%+v err=%v", res, err)
	}
	assertNoTree(t, dir)
	if retryRecord(t, dir) == nil {
		t.Fatal("rollback lost the retry receipt")
	}
	got, _ := os.ReadFile(filepath.Join(dir, cachedRulesName))
	if !bytes.Equal(got, f.main) {
		t.Fatal("failed optional retry changed compiled.yac")
	}
	assertRetryClean(t, dir)
}

func TestFetchRulesMarkerRetryConcurrentInitialInstall(t *testing.T) {
	f, dir := newMarkerFixture(t), t.TempDir()
	inner := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var hits atomic.Int64
	front := markerRetryServer(t, inner, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/"+testMarkerAsset {
			return false
		}
		if hits.Add(1) == 1 {
			close(entered)
			<-release
			return false
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	})
	opts := fetchOptions{allowHTTP: true, logf: (&markerLog{}).logf}
	type result struct {
		res FetchResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := fetchRules(t.Context(), front.URL, dir, "", front.Client(), opts)
		done <- result{res, err}
	}()
	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		t.Fatal("first update never reached marker download")
	}
	if res := retryFetch(t, front, dir, opts); !res.Updated || res.NewVersion != 2 || retryRecord(t, dir) == nil {
		t.Fatalf("concurrent compiled-only install failed: %+v", res)
	}
	unblock()
	got := <-done
	if got.err != nil || got.res.Updated || got.res.NewVersion != 2 || got.res.Marker != MarkerStatusInstalled {
		t.Fatalf("concurrent version recheck discarded a verified recovery: res=%+v err=%v", got.res, got.err)
	}
	if cacheScanner(t, dir, &markerLog{}).markerRules.Load() == nil || retryRecord(t, dir) != nil {
		t.Fatal("concurrent recovery did not install/complete the bound tree")
	}
	assertRetryClean(t, dir)
}

func TestFetchRulesMarkerRetryPreservesSignedBinding(t *testing.T) {
	for _, mode := range []string{"untrusted-signature", "changed-marker", "wrong-abi", "older-version"} {
		t.Run(mode, func(t *testing.T) {
			f, dir := newMarkerFixture(t), t.TempDir()
			inner := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
			front := markerRetryServer(t, inner, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/"+testMarkerAsset {
					w.WriteHeader(http.StatusServiceUnavailable)
					return true
				}
				return false
			})
			now := time.Unix(1700000000, 0)
			opts := fetchOptions{allowHTTP: true, now: func() time.Time { return now }, logf: (&markerLog{}).logf}
			retryFetch(t, front, dir, opts)
			now = retryRecord(t, dir).After
			field := f.field(f.archive)
			version := 2
			switch mode {
			case "changed-marker":
				field["sha256"] = strings.Repeat("a", 64)
			case "wrong-abi":
				field["compiler_sha256"] = strings.Repeat("b", 64)
			case "older-version":
				version = 1
			}
			changed := newMarkerServer(t, f.main, version, field, f.archive)
			candidate := changed.Server
			if mode == "untrusted-signature" {
				candidate = markerRetryServer(t, changed, func(w http.ResponseWriter, r *http.Request) bool {
					if r.URL.Path == "/"+manifestSigName {
						signature := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
						if _, writeErr := w.Write([]byte(signature)); writeErr != nil {
							t.Errorf("write untrusted signature fixture: %v", writeErr)
						}
						return true
					}
					return false
				})
			}
			res, err := fetchRules(t.Context(), candidate.URL, dir, "", candidate.Client(), opts)
			if mode == "untrusted-signature" {
				const want = "fetch manifest: refusing update: rules manifest signature does not verify under any trusted key"
				if err == nil || err.Error() != want {
					t.Fatalf("signature-specific rejection: want %q, got %v", want, err)
				}
			}
			if (mode == "untrusted-signature") != (err != nil) || res.Updated || res.Marker == MarkerStatusInstalled {
				t.Fatalf("binding guard changed update semantics: res=%+v err=%v", res, err)
			}
			if changed.count("/"+testMarkerAsset) != 0 || changed.count("/"+cachedRulesName) != 0 {
				t.Fatal("untrusted, changed or old signed marker reached a download")
			}
			if retryRecord(t, dir) == nil {
				t.Fatal("unrelated manifest cleared the original retry receipt")
			}
			assertNoTree(t, dir)
			assertRetryClean(t, dir)
		})
	}
}

func TestFetchRulesMarkerRetryClassification(t *testing.T) {
	marker := &rulesMarker{Asset: "test"}
	for _, code := range []int{408, 425, 429, 500, 503, 599} {
		if newMarkerRetry(marker, markerDownloadError{rulesHTTPStatusError(code)}, 0, time.Now()) == nil {
			t.Errorf("transient HTTP %d not retried", code)
		}
	}
	for _, err := range []error{nil, context.Canceled, io.EOF, fmt.Errorf("outside marker: %w", io.EOF), &url.Error{Op: "Get", URL: "https://example.invalid", Err: io.EOF}, errors.New("invalid archive"), markerDownloadError{rulesHTTPStatusError(404)}} {
		if r := newMarkerRetry(marker, err, 0, time.Now()); r != nil {
			t.Errorf("permanent error %v created receipt %+v", err, r)
		}
	}
	permanent := markerDownloadError{&url.Error{Op: "Get", URL: "https://example.invalid", Err: errors.New("permanent redirect veto")}}
	if newMarkerRetry(marker, permanent, 0, time.Now()) != nil {
		t.Fatal("permanent URL policy error created receipt")
	}
	for _, err := range []error{context.DeadlineExceeded, markerDownloadError{io.EOF}, markerDownloadError{&url.Error{Op: "Get", URL: "https://example.invalid", Err: io.EOF}}, fmt.Errorf("marker operation: %w", markerDownloadError{io.EOF}), markerDownloadError{io.ErrUnexpectedEOF}, markerDownloadError{&net.OpError{Op: "read", Err: io.EOF}}} {
		if newMarkerRetry(marker, err, 0, time.Now()) == nil {
			t.Errorf("transient transport error %v not retried", err)
		}
	}
	if newMarkerRetry(nil, context.DeadlineExceeded, 0, time.Now()) != nil {
		t.Fatal("absent marker created receipt")
	}
}
