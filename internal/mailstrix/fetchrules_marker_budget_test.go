package mailstrix

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// slowTreeServer fronts a markerServer; the tree asset sends a few bytes and
// then stalls until the request ends or the test finishes.
func slowTreeServer(t *testing.T, inner *markerServer, stall bool) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	u, err := url.Parse(inner.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	hits := &atomic.Int64{}
	done := make(chan struct{})
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+testMarkerAsset {
			hits.Add(1)
			if stall {
				_, _ = w.Write([]byte{0x1f, 0x8b})
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-done:
				}
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	t.Cleanup(func() { close(done) })
	return front, hits
}

func fetchWithCtx(t *testing.T, ctx context.Context, srv *httptest.Server, dir string) (FetchResult, error) {
	t.Helper()
	return fetchRules(ctx, srv.URL, dir, "", srv.Client(), fetchOptions{allowHTTP: true, logf: (&markerLog{}).logf})
}

func assertCompiledInstalled(t *testing.T, f markerFixture, dir string, res FetchResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("compiled.yac install must survive the tree: %v", err)
	}
	if !res.Updated || res.NewVersion != 3 {
		t.Fatalf("res = %+v, want compiled.yac updated to v3", res)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, cachedRulesName)); !bytes.Equal(got, f.main) {
		t.Fatal("new compiled.yac is not live")
	}
	assertNoTree(t, dir)
	assertNoLeftovers(t, dir)
}

// Positive: a stalling tree hits its child deadline, the parent keeps its
// reserve, and compiled.yac still installs.
func TestFetchRulesMarkerTreeStallKeepsCoreInstall(t *testing.T) {
	old := markerCoreReserveMin
	markerCoreReserveMin = 500 * time.Millisecond
	t.Cleanup(func() { markerCoreReserveMin = old })
	f, dir := newDroppedCase(t)
	inner := newMarkerServer(t, f.main, 3, f.field(f.archive), f.archive)
	front, hits := slowTreeServer(t, inner, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := fetchWithCtx(t, ctx, front, dir)
	assertCompiledInstalled(t, f, dir, res, err)
	if !strings.HasPrefix(res.Marker, MarkerStatusRejected) {
		t.Fatalf("marker status = %q, want %q prefix", res.Marker, MarkerStatusRejected)
	}
	if hits.Load() != 1 {
		t.Fatalf("tree requests = %d, want 1", hits.Load())
	}
}

// Boundary: no parent deadline means no extra limit; the tree installs.
func TestFetchRulesMarkerTreeNoDeadlineInstalls(t *testing.T) {
	f := newMarkerFixture(t)
	dir := t.TempDir()
	inner := newMarkerServer(t, f.main, 3, f.field(f.archive), f.archive)
	front, hits := slowTreeServer(t, inner, false)
	res, err := fetchWithCtx(t, context.Background(), front, dir)
	if err != nil || !res.Updated || res.Marker != MarkerStatusInstalled || hits.Load() != 1 {
		t.Fatalf("res=%+v err=%v hits=%d, want installed tree", res, err, hits.Load())
	}
}

// Regression: a fast tree under a roomy deadline installs as before.
func TestFetchRulesMarkerTreeFastWithDeadlineInstalls(t *testing.T) {
	f := newMarkerFixture(t)
	dir := t.TempDir()
	inner := newMarkerServer(t, f.main, 3, f.field(f.archive), f.archive)
	front, _ := slowTreeServer(t, inner, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := fetchWithCtx(t, ctx, front, dir)
	if err != nil || !res.Updated || res.Marker != MarkerStatusInstalled {
		t.Fatalf("res=%+v err=%v, want installed tree", res, err)
	}
}

// Boundary: remaining budget at or below the reserve skips the tree without a
// single download request, and compiled.yac installs.
func TestFetchRulesMarkerTreeBelowReserveSkipped(t *testing.T) {
	f, dir := newDroppedCase(t)
	inner := newMarkerServer(t, f.main, 3, f.field(f.archive), f.archive)
	front, hits := slowTreeServer(t, inner, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // < 15s default reserve
	defer cancel()
	res, err := fetchWithCtx(t, ctx, front, dir)
	assertCompiledInstalled(t, f, dir, res, err)
	if !strings.HasPrefix(res.Marker, MarkerStatusSkipped) || !strings.Contains(res.Marker, "reserve") {
		t.Fatalf("marker status = %q, want skipped for reserve", res.Marker)
	}
	if hits.Load() != 0 {
		t.Fatalf("tree requests = %d, want 0", hits.Load())
	}
}

func TestMarkerTreeContext(t *testing.T) {
	ctx, cancel, ok := markerTreeContext(context.Background())
	defer cancel()
	if _, has := ctx.Deadline(); has || !ok {
		t.Fatal("no parent deadline must yield no limit")
	}
	parent, pc := context.WithTimeout(context.Background(), time.Minute)
	defer pc()
	c2, cancel2, ok := markerTreeContext(parent)
	defer cancel2()
	d, _ := c2.Deadline()
	pd, _ := parent.Deadline()
	if !ok || pd.Sub(d) < 15*time.Second-time.Second || pd.Sub(d) > 15*time.Second+time.Second {
		t.Fatalf("minute budget: ok=%v reserve=%v, want 15s", ok, pd.Sub(d))
	}
	long, lc := context.WithTimeout(context.Background(), 200*time.Second)
	defer lc()
	c3, cancel3, _ := markerTreeContext(long)
	defer cancel3()
	d3, _ := c3.Deadline()
	ld, _ := long.Deadline()
	if r := ld.Sub(d3); r < 49*time.Second || r > 51*time.Second {
		t.Fatalf("200s budget reserve = %v, want 50s (25%%)", r)
	}
}
