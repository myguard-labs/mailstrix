//go:build linux

package cape

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const interruptUnsupportedLog = "cape ingress read interrupt unsupported"

// hidingWriter is the AUD-07c hazard: a ResponseWriter wrapper without Unwrap,
// so http.ResponseController cannot reach the connection deadline.
type hidingWriter struct{ http.ResponseWriter }

// unwrappingWriter is a well-behaved wrapper that exposes the inner writer.
type unwrappingWriter struct{ http.ResponseWriter }

func (w unwrappingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type syncLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// captureLog redirects the standard logger for one non-parallel test.
func captureLog(t *testing.T) *syncLog {
	t.Helper()
	out := &syncLog{}
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(out)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return out
}

type reportRecorder struct {
	mu   sync.Mutex
	errs []error
}

func (r *reportRecorder) report(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

func (r *reportRecorder) snapshot() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errs...)
}

// dialStalled sends headers plus one of ten body bytes, then stalls.
func dialStalled(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte(interruptHeaders("10") + "x")); err != nil {
		t.Fatal(err)
	}
	return c
}

// stalledInterrupt serves one request whose client sends headers plus one body
// byte and stalls. The handler wraps w, starts a body read, calls InterruptRead
// once the read is blocked and reports whether that read returned in bound.
func stalledInterrupt(t *testing.T, wrap func(http.ResponseWriter) http.ResponseWriter) (reports []error, readReturned bool) {
	t.Helper()
	rec := &reportRecorder{}
	result := make(chan bool, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := interruptibleBody{ReadCloser: r.Body, rc: http.NewResponseController(wrap(w)), report: rec.report}
		buf := make([]byte, 8)
		if _, err := io.ReadFull(body, buf[:1]); err != nil {
			result <- false
			return
		}
		readDone := make(chan struct{})
		go func() {
			// Only the return matters; the interrupted read error is expected.
			_, _ = body.Read(buf)
			close(readDone)
		}()
		time.Sleep(50 * time.Millisecond) // let the second Read block on the stalled client
		body.InterruptRead()
		select {
		case <-readDone:
			result <- true
		case <-time.After(2 * time.Second):
			result <- false
		}
	}))
	srv.Config.ReadTimeout = interruptServerReadTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	dialStalled(t, srv.Listener.Addr().String())
	select {
	case readReturned = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	return rec.snapshot(), readReturned
}

func TestInterruptReadSupportedWriterNotReported(t *testing.T) {
	for name, wrap := range map[string]func(http.ResponseWriter) http.ResponseWriter{
		"raw":    func(w http.ResponseWriter) http.ResponseWriter { return w },
		"unwrap": func(w http.ResponseWriter) http.ResponseWriter { return unwrappingWriter{w} },
	} {
		t.Run(name, func(t *testing.T) {
			reports, returned := stalledInterrupt(t, wrap)
			if !returned {
				t.Fatal("supported writer did not interrupt the stalled read")
			}
			if len(reports) != 0 {
				t.Fatalf("supported writer reported interrupt failure: %v", reports)
			}
		})
	}
}

func TestInterruptReadHidingWrapperReportsNotSupported(t *testing.T) {
	reports, returned := stalledInterrupt(t, func(w http.ResponseWriter) http.ResponseWriter { return hidingWriter{w} })
	if len(reports) != 1 || !errors.Is(reports[0], http.ErrNotSupported) {
		t.Fatalf("hiding wrapper: want exactly one http.ErrNotSupported report, got %v", reports)
	}
	if returned {
		t.Fatal("hiding wrapper unexpectedly interrupted the read; the fixture no longer models the hazard")
	}
}

func TestInterruptReadNilReportDoesNotPanic(t *testing.T) {
	body := interruptibleBody{ReadCloser: io.NopCloser(strings.NewReader("")), rc: http.NewResponseController(httptest.NewRecorder())}
	body.InterruptRead()
}

func TestLogInterruptFailure(t *testing.T) {
	out := captureLog(t)
	logInterruptFailure(http.ErrNotSupported)
	logInterruptFailure(errors.New("synthetic deadline failure"))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want one line per failure, got %q", out.String())
	}
	if !strings.Contains(lines[0], "[mailstrix] WARNING: "+interruptUnsupportedLog) {
		t.Fatalf("ErrNotSupported line: %q", lines[0])
	}
	if !strings.Contains(lines[1], "[mailstrix] WARNING: cape ingress read interrupt failed: synthetic deadline failure") {
		t.Fatalf("generic failure line: %q", lines[1])
	}
}

// The production APIHandler wiring logs the unsupported fallback: a hiding
// wrapper in front of the handler is reported when the idle watchdog fires.
func TestAPIIngressHidingWrapperLogsUnsupported(t *testing.T) {
	out := captureLog(t)
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	h, err := NewAPIHandler(apiFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(hidingWriter{w}, r)
	}))
	srv.Config.ReadTimeout = interruptServerReadTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	c := dialStalled(t, srv.Listener.Addr().String())
	waitStore(t, func() bool { return clock.hasDeadline(ingressIdle) })
	clock.advance(ingressIdle)
	waitStore(t, func() bool { return strings.Contains(out.String(), interruptUnsupportedLog) })
	// The fallback Close stays blocked behind the stalled Read; closing the
	// client releases it before cleanup.
	_ = c.Close()
}

// The supported production path interrupts without logging a failure.
func TestAPIIngressSupportedWriterDoesNotLog(t *testing.T) {
	out := captureLog(t)
	clock := newStoreClock()
	srv := interruptServer(t, clock)
	c := dialStalled(t, srv.Listener.Addr().String())
	waitStore(t, func() bool { return clock.hasDeadline(ingressIdle) })
	clock.advance(ingressIdle)
	if status := interruptStatus(t, c); !strings.Contains(status, " 503 ") {
		t.Fatalf("stalled ingress not rejected as Deadline: %q", status)
	}
	if strings.Contains(out.String(), "cape ingress read interrupt") {
		t.Fatalf("supported writer logged an interrupt failure: %q", out.String())
	}
}
