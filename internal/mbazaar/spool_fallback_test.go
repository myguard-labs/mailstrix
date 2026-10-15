package mbazaar

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/feedrefresh"
)

var errDiskFull = errors.New("no space left on device")

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errDiskFull }

// hookSpoolWriter makes writes fail where fail(f) is true; restored on cleanup.
func hookSpoolWriter(t *testing.T, fail func(f *os.File) bool) {
	t.Helper()
	orig := spoolWriter
	spoolWriter = func(f *os.File) io.Writer {
		if fail(f) {
			return failingWriter{}
		}
		return f
	}
	t.Cleanup(func() { spoolWriter = orig })
}

func newSpoolChecker(t *testing.T, url, cacheDir string) *Checker {
	t.Helper()
	c := &Checker{key: "k", feedURL: url, client: http.DefaultClient,
		logf: func(string, ...any) {}, stop: make(chan struct{})}
	if cacheDir != "" {
		c.cachePath = filepath.Join(cacheDir, "malwarebazaar.bin")
	}
	return c
}

func countingServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.Header.Get("Auth-Key") != "k" {
			t.Errorf("request %d missing Auth-Key", n.Load())
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func serveZip(t *testing.T) http.HandlerFunc {
	body := zipOf(t, csvFor("payload"))
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }
}

func assertNoSpools(t *testing.T, dir string) {
	t.Helper()
	if ms, _ := filepath.Glob(filepath.Join(dir, ".mbazaar-spool-*.tmp")); len(ms) != 0 {
		t.Fatalf("spool files left in %s: %v", dir, ms)
	}
}

// Positive: the cache-dir spool write fails after CreateTemp succeeded; one
// fresh request spools to the OS temp dir, the set is stored, the snapshot is
// not persisted.
func TestSpoolWriteFailureFallsBackToTempDir(t *testing.T) {
	srv, n := countingServer(t, serveZip(t))
	cache := t.TempDir()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	hookSpoolWriter(t, func(f *os.File) bool { return filepath.Dir(f.Name()) == cache })
	c := newSpoolChecker(t, srv.URL, cache)
	if err := c.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	if got := n.Load(); got != 2 {
		t.Fatalf("requests=%d, want 2", got)
	}
	if ok := c.set.Load().has(mustDigest(t, "payload")); !ok {
		t.Fatal("set not stored after fallback")
	}
	if _, err := os.Stat(c.cachePath); !os.IsNotExist(err) {
		t.Fatalf("cache snapshot written despite fallback: %v", err)
	}
	assertNoSpools(t, cache)
	assertNoSpools(t, tmp)
}

func mustDigest(t *testing.T, s string) [32]byte {
	t.Helper()
	d, ok := parseSHA256(hashOf(s))
	if !ok {
		t.Fatal("bad digest")
	}
	return d
}

// Negative: a size-ceiling failure is not a local write failure: no retry.
func TestSpoolTooLargeNoRetry(t *testing.T) {
	srv, n := countingServer(t, serveZip(t))
	orig := maxFeedBytes
	maxFeedBytes = 8
	defer func() { maxFeedBytes = orig }()
	cache := t.TempDir()
	c := newSpoolChecker(t, srv.URL, cache)
	err := c.refreshOnce(context.Background())
	var tl *feedrefresh.TooLargeError
	if !errors.As(err, &tl) {
		t.Fatalf("err=%v, want TooLargeError", err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("requests=%d, want 1", got)
	}
	assertNoSpools(t, cache)
}

// Negative: a response body read error is not a local write failure: no retry.
func TestSpoolBodyReadErrorNoRetry(t *testing.T) {
	srv, n := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100000")
		_, _ = w.Write([]byte("short"))
	})
	cache := t.TempDir()
	c := newSpoolChecker(t, srv.URL, cache)
	err := c.refreshOnce(context.Background())
	if err == nil {
		t.Fatal("want read error")
	}
	var we *localWriteError
	if errors.As(err, &we) {
		t.Fatalf("read error misclassified as local write: %v", err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("requests=%d, want 1", got)
	}
	assertNoSpools(t, cache)
}

// Boundary: the retry's own write failure is returned; no third request.
func TestSpoolRetryWriteFailureReturned(t *testing.T) {
	srv, n := countingServer(t, serveZip(t))
	cache := t.TempDir()
	hookSpoolWriter(t, func(*os.File) bool { return true })
	c := newSpoolChecker(t, srv.URL, cache)
	err := c.refreshOnce(context.Background())
	if !errors.Is(err, errDiskFull) {
		t.Fatalf("err=%v, want disk full", err)
	}
	if got := n.Load(); got != 2 {
		t.Fatalf("requests=%d, want 2", got)
	}
	assertNoSpools(t, cache)
}

// Boundary: the retry gets a non-200 status: StatusError, exactly two requests.
func TestSpoolRetryStatusError(t *testing.T) {
	var calls atomic.Int32
	ok := serveZip(t)
	srv, n := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			ok(w, r)
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	cache := t.TempDir()
	hookSpoolWriter(t, func(f *os.File) bool { return filepath.Dir(f.Name()) == cache })
	c := newSpoolChecker(t, srv.URL, cache)
	err := c.refreshOnce(context.Background())
	var se *feedrefresh.StatusError
	if !errors.As(err, &se) || se.Code != 500 {
		t.Fatalf("err=%v, want StatusError 500", err)
	}
	if got := n.Load(); got != 2 {
		t.Fatalf("requests=%d, want 2", got)
	}
	assertNoSpools(t, cache)
}

// Negative: with no cache dir configured a write failure is not retried.
func TestSpoolWriteFailureNoCacheDirNoRetry(t *testing.T) {
	srv, n := countingServer(t, serveZip(t))
	hookSpoolWriter(t, func(*os.File) bool { return true })
	c := newSpoolChecker(t, srv.URL, "")
	err := c.refreshOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no space") {
		t.Fatalf("err=%v", err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("requests=%d, want 1", got)
	}
}

// Negative: when the cache dir cannot even create the spool file, the spool is
// already in the OS temp dir; a write failure there is not retried.
func TestSpoolTempDirWriteFailureAfterCreateFallbackNoRetry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	srv, n := countingServer(t, serveZip(t))
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	hookSpoolWriter(t, func(*os.File) bool { return true })
	c := newSpoolChecker(t, srv.URL, ro)
	err := c.refreshOnce(context.Background())
	if !errors.Is(err, errDiskFull) {
		t.Fatalf("err=%v, want disk full", err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("requests=%d, want 1", got)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

// Boundary: a short write with a nil error is a local write failure.
func TestErrWriterShortWriteIsLocal(t *testing.T) {
	_, err := errWriter{shortWriter{}}.Write([]byte("abcd"))
	var we *localWriteError
	if !errors.As(err, &we) || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("err=%v, want localWriteError(ErrShortWrite)", err)
	}
	if _, err := (errWriter{io.Discard}).Write([]byte("abcd")); err != nil {
		t.Fatalf("clean write: %v", err)
	}
}
