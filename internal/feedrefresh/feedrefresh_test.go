package feedrefresh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCheckSize (COR-08): an empty refresh and a collapse to under a tenth of
// a large previous set are rejected; normal growth and shrinkage pass.
func TestCheckSize(t *testing.T) {
	for _, c := range []struct {
		prev, next int
		reject     bool
	}{
		{0, 0, true},       // malformed: empty first load
		{5000, 0, true},    // empty refresh over a good set
		{5000, 499, true},  // collapse to under a tenth
		{5000, 500, false}, // boundary: exactly a tenth is kept
		{999, 1, false},    // small previous set: no drop check
		{1000, 99, true},   // boundary: drop check starts at 1000
		{0, 10, false},     // first load
		{5000, 6000, false},
	} {
		err := CheckSize(c.prev, c.next)
		if got := errors.Is(err, ErrShrank); got != c.reject {
			t.Errorf("CheckSize(%d, %d) = %v, reject=%v", c.prev, c.next, err, c.reject)
		}
	}
	if err := CheckSize(5000, 1); err == nil || !strings.Contains(err.Error(), "(5000 -> 1 entries)") {
		t.Errorf("CheckSize error text = %v", err)
	}
}

func TestNewHTTPClient(t *testing.T) {
	c := NewHTTPClient(time.Second)
	if c.Timeout != time.Second {
		t.Fatalf("Timeout = %v", c.Timeout)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.test/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRedirect(req, []*http.Request{{}}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}

func TestReadBody(t *testing.T) {
	for _, c := range []struct {
		name  string
		body  string
		limit int64
		large bool
	}{
		{"under", "1234", 5, false},
		{"exact limit", "12345", 5, false},
		{"limit plus one", "123456", 5, true},
		{"empty", "", 5, false},
		{"far over", strings.Repeat("x", 100), 5, true},
	} {
		got, err := ReadBody("urlhaus", strings.NewReader(c.body), c.limit)
		if c.large {
			var tl *TooLargeError
			if !errors.Is(err, ErrTooLarge) || !errors.As(err, &tl) {
				t.Errorf("%s: err = %v, want TooLargeError", c.name, err)
			} else if err.Error() != "urlhaus feed exceeds byte limit" {
				t.Errorf("%s: text = %q", c.name, err.Error())
			}
			if got != nil {
				t.Errorf("%s: body returned with error", c.name)
			}
			continue
		}
		if err != nil || !bytes.Equal(got, []byte(c.body)) {
			t.Errorf("%s: got %q, %v", c.name, got, err)
		}
	}
}

type errReader struct{}

var errBoom = errors.New("boom")

func (errReader) Read([]byte) (int, error) { return 0, errBoom }

func TestReadBodyReadError(t *testing.T) {
	got, err := ReadBody("threatfox", errReader{}, 5)
	if !errors.Is(err, errBoom) || errors.Is(err, ErrTooLarge) || got != nil {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestTooLargeErrorIsOnlyItself(t *testing.T) {
	if errors.Is(&TooLargeError{Feed: "x"}, ErrShrank) {
		t.Fatal("TooLargeError must not match ErrShrank")
	}
}

func TestStatusErrorText(t *testing.T) {
	for _, c := range []struct {
		feed string
		code int
		want string
	}{
		{"malwarebazaar", 503, "malwarebazaar feed HTTP 503"},
		{"threatfox", 401, "threatfox feed HTTP 401"},
		{"urlhaus", 0, "urlhaus feed HTTP 0"},
	} {
		var err error = &StatusError{Feed: c.feed, Code: c.code}
		if err.Error() != c.want {
			t.Errorf("got %q, want %q", err.Error(), c.want)
		}
		var se *StatusError
		if !errors.As(fmt.Errorf("wrap: %w", err), &se) || se.Code != c.code {
			t.Errorf("errors.As failed for %v", err)
		}
	}
}

type logSink struct {
	mu   sync.Mutex
	logs []string
}

func (l *logSink) logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, fmt.Sprintf(f, a...))
}

func (l *logSink) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.logs...)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached in time")
		}
		time.Sleep(time.Millisecond)
	}
}

// runLoop starts Loop and returns a channel closed when it returns.
func runLoop(ctx context.Context, stop <-chan struct{}, refresh func(context.Context) error,
	failures *atomic.Uint64, l *logSink) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		Loop(ctx, stop, 5*time.Millisecond, "urlhaus", refresh, failures, l.logf)
	}()
	return done
}

func TestLoopSuccessRunsImmediatelyAndOnInterval(t *testing.T) {
	var calls, failures atomic.Uint64
	stop := make(chan struct{})
	l := &logSink{}
	done := runLoop(context.Background(), stop, func(context.Context) error {
		calls.Add(1)
		return nil
	}, &failures, l)
	waitFor(t, func() bool { return calls.Load() >= 3 })
	close(stop)
	<-done
	if failures.Load() != 0 || len(l.snapshot()) != 0 {
		t.Fatalf("failures=%d logs=%v", failures.Load(), l.snapshot())
	}
}

func TestLoopCountsAndLogsFailures(t *testing.T) {
	var calls, failures atomic.Uint64
	stop := make(chan struct{})
	l := &logSink{}
	done := runLoop(context.Background(), stop, func(context.Context) error {
		calls.Add(1)
		return &StatusError{Feed: "urlhaus", Code: 503}
	}, &failures, l)
	waitFor(t, func() bool { return calls.Load() >= 2 && failures.Load() >= 2 })
	close(stop)
	<-done
	logs := l.snapshot()
	if logs[0] != "urlhaus initial feed fetch failed: urlhaus feed HTTP 503" {
		t.Errorf("initial log = %q", logs[0])
	}
	if logs[1] != "urlhaus feed refresh failed (keeping previous set): urlhaus feed HTTP 503" {
		t.Errorf("refresh log = %q", logs[1])
	}
	if failures.Load() != uint64(len(logs)) {
		t.Errorf("failures=%d logs=%d", failures.Load(), len(logs))
	}
}

// A failure caused by cancellation is shutdown, not a feed failure: not
// counted, not logged, and the loop exits.
func TestLoopCancelledInitialFailureNotCounted(t *testing.T) {
	var failures atomic.Uint64
	var calls atomic.Uint64
	l := &logSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := runLoop(ctx, make(chan struct{}), func(ctx context.Context) error {
		calls.Add(1)
		cancel()
		return ctx.Err()
	}, &failures, l)
	<-done
	if failures.Load() != 0 || len(l.snapshot()) != 0 || calls.Load() != 1 {
		t.Fatalf("failures=%d logs=%v calls=%d", failures.Load(), l.snapshot(), calls.Load())
	}
}

func TestLoopCancelledTickFailureNotCounted(t *testing.T) {
	var failures, calls atomic.Uint64
	l := &logSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := runLoop(ctx, make(chan struct{}), func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			return nil
		}
		cancel()
		return ctx.Err()
	}, &failures, l)
	<-done
	if failures.Load() != 0 || len(l.snapshot()) != 0 || calls.Load() != 2 {
		t.Fatalf("failures=%d logs=%v calls=%d", failures.Load(), l.snapshot(), calls.Load())
	}
}

func TestLoopStopWhileIdle(t *testing.T) {
	var failures atomic.Uint64
	stop := make(chan struct{})
	close(stop)
	var calls atomic.Uint64
	l := &logSink{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		Loop(context.Background(), stop, time.Hour, "urlhaus", func(context.Context) error {
			calls.Add(1)
			return nil
		}, &failures, l.logf)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Loop did not exit on stop")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d, want the immediate fetch only", calls.Load())
	}
}
