package ci_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

type httpLifecycleEngine struct {
	ms.ScanEngine
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (e *httpLifecycleEngine) RuleCount() int64    { return 1 }
func (e *httpLifecycleEngine) Fingerprint() string { return "http-lifecycle-test" }
func (e *httpLifecycleEngine) Scan(_ []byte, _ ms.ScanMeta) ([]ms.Match, error) {
	e.once.Do(func() {
		if e.entered != nil {
			close(e.entered)
		}
	})
	if e.release != nil {
		<-e.release
	}
	return nil, nil
}

func newHTTPLifecycleServer(t *testing.T, engine ms.ScanEngine) (*ms.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	host, rawPort, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ms.Config{
		Host:                    host,
		Port:                    port,
		Token:                   "http-lifecycle-token", // #nosec G101 -- fixed test-only bearer value
		MaxConcurrent:           1,
		MaxInflight:             2,
		MaxBody:                 1024,
		ExtractionRetainedBytes: 1024,
		BackendTimeout:          time.Second,
		ScanTimeout:             time.Second,
		CacheSize:               1,
		ClamdMaxConns:           1,
		RulesFetchTimeout:       time.Second,
		EffortMax:               1,
	}
	return ms.NewServer(cfg, engine), addr
}

func startHTTPLifecycleServer(t *testing.T, server *ms.Server, addr string) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()

	client := http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		resp, err := client.Get("http://" + addr + "/health")
		if err == nil {
			if resp == nil {
				t.Fatal("health request returned neither a response nor an error")
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatalf("close health response: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("health status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			return done
		}
		select {
		case err := <-done:
			t.Fatalf("ListenAndServe returned before startup: %v", err)
		case <-deadline.C:
			t.Fatalf("HTTP server did not start on %s", addr)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func requireHTTPServerClosed(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("ListenAndServe error = %v, want %v", err, http.ErrServerClosed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after shutdown")
	}
}

func newHTTPLifecycleBarrier(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	barrier := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(barrier) }) }
	t.Cleanup(release)
	return barrier, release
}

func scanHTTPLifecycleServer(addr string) error {
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/scan", strings.NewReader("x"))
	if err != nil {
		return err
	}
	req.Header.Set("X-MAILSTRIX-Token", "http-lifecycle-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("scan request returned neither a response nor an error")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("scan status = %d", resp.StatusCode)
	}
	return nil
}

func requireHTTPScanEntered(t *testing.T, entered <-chan struct{}, response <-chan error) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-entered:
	case err := <-response:
		t.Fatalf("scan returned before entering the engine: %v", err)
	case <-timer.C:
		t.Fatal("scan did not enter the engine")
	}
}

func TestHTTPShutdownBeforePublication(t *testing.T) {
	server, addr := newHTTPLifecycleServer(t, &httpLifecycleEngine{})
	startupReady := make(chan struct{})
	startupRelease, releaseStartup := newHTTPLifecycleBarrier(t)
	done := make(chan error, 1)
	go func() {
		close(startupReady)
		<-startupRelease
		done <- server.ListenAndServe()
	}()

	<-startupReady
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown before publication: %v", err)
	}
	releaseStartup()

	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("ListenAndServe error = %v, want %v", err, http.ErrServerClosed)
		}
	case <-time.After(2 * time.Second):
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(cleanup); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("cleanup Shutdown: %v", err)
		}
		requireHTTPServerClosed(t, done)
		t.Fatal("ListenAndServe started after Shutdown returned")
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("shutdown-before-publication left a listener on %s: %v", addr, err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPNormalStartupAndIdempotentShutdown(t *testing.T) {
	server, addr := newHTTPLifecycleServer(t, &httpLifecycleEngine{})
	done := startHTTPLifecycleServer(t, server, addr)
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	requireHTTPServerClosed(t, done)
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("idempotent Shutdown: %v", err)
	}

	ready := httptest.NewRecorder()
	server.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if ready.Code != http.StatusServiceUnavailable || ready.Body.String() != "draining" {
		t.Fatalf("ready while draining = %d %q", ready.Code, ready.Body.String())
	}
}

func TestHTTPShutdownDeadlineAllowsRetry(t *testing.T) {
	entered := make(chan struct{})
	release, releaseScan := newHTTPLifecycleBarrier(t)
	server, addr := newHTTPLifecycleServer(t, &httpLifecycleEngine{entered: entered, release: release})
	done := startHTTPLifecycleServer(t, server, addr)

	response := make(chan error, 1)
	go func() { response <- scanHTTPLifecycleServer(addr) }()
	requireHTTPScanEntered(t, entered, response)

	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := server.Shutdown(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown with expired deadline = %v, want %v", err, context.DeadlineExceeded)
	}
	releaseScan()
	if err := <-response; err != nil {
		t.Fatalf("in-flight scan after deadline: %v", err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown retry: %v", err)
	}
	requireHTTPServerClosed(t, done)
}

func TestHTTPConcurrentShutdown(t *testing.T) {
	entered := make(chan struct{})
	release, releaseScan := newHTTPLifecycleBarrier(t)
	server, addr := newHTTPLifecycleServer(t, &httpLifecycleEngine{entered: entered, release: release})
	done := startHTTPLifecycleServer(t, server, addr)

	response := make(chan error, 1)
	go func() { response <- scanHTTPLifecycleServer(addr) }()
	requireHTTPScanEntered(t, entered, response)

	const callers = 8
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			results <- server.Shutdown(context.Background())
		}()
	}
	close(start)

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		ready := httptest.NewRecorder()
		server.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/ready", nil))
		if ready.Code == http.StatusServiceUnavailable {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("concurrent Shutdown calls did not enter draining state")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	releaseScan()
	if err := <-response; err != nil {
		t.Fatalf("in-flight scan during concurrent shutdown: %v", err)
	}
	for i := 0; i < callers; i++ {
		if err := <-results; err != nil {
			t.Errorf("Shutdown caller %d: %v", i, err)
		}
	}
	requireHTTPServerClosed(t, done)
}
