//go:build linux

package cape

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const interruptServerReadTimeout = 30 * time.Second

func interruptServer(t *testing.T, clock *fakeStoreClock) *httptest.Server {
	t.Helper()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	h, err := NewAPIHandler(apiFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ReadTimeout = interruptServerReadTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func interruptHeaders(length string) string {
	return "POST " + JobsPath + " HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer fixture-alpha\r\n" +
		"Content-Type: application/octet-stream\r\nX-Mailstrix-CAPE-Profile: private\r\nContent-Length: " + length + "\r\n\r\n"
}

func interruptStatus(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("no response within bound: %v", err)
	}
	return strings.TrimSpace(line)
}

// A client that sends headers plus one body byte and stalls must be rejected
// at the 5 s idle cap, not at the 30 s server ReadTimeout.
func TestAPIIngressStalledBodyInterrupted(t *testing.T) {
	clock := newStoreClock()
	srv := interruptServer(t, clock)
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte(interruptHeaders("10") + "x")); err != nil {
		t.Fatal(err)
	}
	waitStore(t, func() bool { return clock.hasDeadline(ingressIdle) })
	time.Sleep(100 * time.Millisecond) // let the handler block in Read
	start := time.Now()
	clock.advance(ingressIdle)
	status := interruptStatus(t, c)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled read not interrupted promptly: %v", elapsed)
	}
	if !strings.Contains(status, " 503 ") {
		t.Fatalf("stalled ingress not rejected as Deadline: %q", status)
	}
}

// A slow body that keeps making progress inside each idle window succeeds.
func TestAPIIngressSlowProgressingBodyAdmitted(t *testing.T) {
	clock := newStoreClock()
	srv := interruptServer(t, clock)
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte(interruptHeaders("4"))); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		clock.advance(4 * time.Second) // always inside the 5 s idle window
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if i < 3 { // the final byte completes the body; no new idle timer
			waitStore(t, func() bool { return clock.hasDeadline(ingressIdle) })
		}
	}
	if status := interruptStatus(t, c); !strings.Contains(status, " 202 ") {
		t.Fatalf("progressing body rejected: %q", status)
	}
}

// A writer without deadline support (httptest.ResponseRecorder) falls back to
// plain Close, still rejects with Deadline, and does not panic.
func TestAPIIngressInterruptUnsupportedWriterFallsBack(t *testing.T) {
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	h, err := NewAPIHandler(apiFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	b := newBlockingBody()
	r := httptest.NewRequest("POST", JobsPath, b)
	r.Header.Set("Authorization", "Bearer fixture-alpha")
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-Mailstrix-CAPE-Profile", "private")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, r); close(done) }()
	<-b.entered
	waitStore(t, func() bool { return clock.hasDeadline(ingressIdle) })
	clock.advance(ingressIdle)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fallback close did not end ingress")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("stalled ingress not rejected as Deadline: got %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(w.Body.String(), `"error":"unavailable"`) {
		t.Fatalf("Deadline rejection body lacks unavailable code: %q", w.Body.String())
	}
}

// serveStalledBody drives one stalled POST through a handler built from cfg and
// returns once the watchdog has ended it. w decides whether deadline support exists.
func serveStalledBody(t *testing.T, cfg APIConfig, clock *fakeStoreClock, w http.ResponseWriter) {
	t.Helper()
	h, err := NewAPIHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b := newBlockingBody()
	r := httptest.NewRequest("POST", JobsPath, b)
	r.Header.Set("Authorization", "Bearer fixture-alpha")
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-Mailstrix-CAPE-Profile", "private")
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, r); close(done) }()
	<-b.entered
	waitStore(t, func() bool { return clock.hasDeadline(ingressIdle) })
	clock.advance(ingressIdle)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stalled ingress did not end")
	}
}

// AUD-07e positive: a writer without deadline support reports to the hook once.
func TestAPIIngressInterruptFailureHookCounts(t *testing.T) {
	clock := newStoreClock()
	cfg := apiFixture(t, testStore(t, storeConfig(t.TempDir()), clock))
	var got []error
	var n atomic.Uint64
	cfg.OnInterruptFailure = func(err error) { n.Add(1); got = append(got, err) }
	serveStalledBody(t, cfg, clock, httptest.NewRecorder())
	if n.Load() != 1 || len(got) != 1 || !errors.Is(got[0], http.ErrNotSupported) {
		t.Fatalf("hook calls = %d (%v), want exactly one ErrNotSupported", n.Load(), got)
	}
}

// AUD-07e negative: a writer that supports deadlines is interrupted
// successfully, so the hook is never called.
func TestAPIIngressInterruptSuccessDoesNotCount(t *testing.T) {
	clock := newStoreClock()
	cfg := apiFixture(t, testStore(t, storeConfig(t.TempDir()), clock))
	var n atomic.Uint64
	cfg.OnInterruptFailure = func(error) { n.Add(1) }
	serveStalledBody(t, cfg, clock, deadlineRecorder{httptest.NewRecorder()})
	if n.Load() != 0 {
		t.Fatalf("hook called %d times for a successful interrupt", n.Load())
	}
}

// AUD-07e: a nil hook is safe on the failing path.
func TestAPIIngressInterruptFailureNilHookSafe(t *testing.T) {
	clock := newStoreClock()
	cfg := apiFixture(t, testStore(t, storeConfig(t.TempDir()), clock))
	if cfg.OnInterruptFailure != nil {
		t.Fatal("fixture must leave the hook nil")
	}
	serveStalledBody(t, cfg, clock, httptest.NewRecorder())
}

// deadlineRecorder is a ResponseWriter that accepts SetReadDeadline, as the
// net/http server writer does.
type deadlineRecorder struct{ *httptest.ResponseRecorder }

func (deadlineRecorder) SetReadDeadline(time.Time) error { return nil }
