package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

// The fixture supplies Scan for clamd and RuleCount for HTTP readiness checks.
type clamdBlockingEngine struct {
	mailstrix.ScanEngine
	started chan struct{}
	release chan struct{}
	active  atomic.Bool
}

func (e *clamdBlockingEngine) RuleCount() int64 { return 1 }

func (e *clamdBlockingEngine) Scan([]byte, mailstrix.ScanMeta) ([]mailstrix.Match, error) {
	e.active.Store(true)
	close(e.started)
	<-e.release
	e.active.Store(false)
	return nil, nil
}

func TestClamdDrainNativeOwnership(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		name := "completed"
		if timeout {
			name = "timedout"
		}
		t.Run(name, func(t *testing.T) {
			e := &clamdBlockingEngine{started: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(e.release) })
			defer release()
			cfg := &mailstrix.Config{ClamdUnixPath: filepath.Join(t.TempDir(), "c"),
				MaxConcurrent: 1, MaxInflight: 1, MaxBody: 1024, BackendTimeout: time.Second, ScanTimeout: time.Second}
			service, err := mailstrix.NewServer(cfg, e).StartClamd()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				release()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := service.Shutdown(ctx); err != nil {
					t.Error(err)
				}
			})
			conn, err := net.DialTimeout("unix", cfg.ClamdUnixPath, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "zINSTREAM\x00\x00\x00\x00\x01x\x00\x00\x00\x00"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-e.started:
			case <-time.After(3 * time.Second):
				t.Fatal("scan did not start")
			}
			if !timeout {
				release()
			}
			budget := 3 * time.Second
			if timeout {
				budget = 20 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			drain := &clamdDrain{service: service}
			err = drain.shutdown(ctx)
			if timeout && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("drain error %v, want deadline", err)
			}
			if !timeout && err != nil {
				t.Fatal(err)
			}
			closed := false
			// This is the exact deferred close guard used by cmdServe, after a
			// real listener dispatched a still-blocked native-engine boundary.
			drain.closeScanner(func() {
				closed = true
				if e.active.Load() {
					t.Error("scanner.Close called beneath live native scan")
				}
			})
			if closed == timeout {
				t.Fatalf("scanner closed=%v, timeout=%v", closed, timeout)
			}
			// The deferred exit path must reuse the prior result, not spend a
			// second drain budget or clear the failure before scanner.Close.
			if got := drain.shutdown(context.Background()); got != err {
				t.Fatalf("drain result changed: %v -> %v", err, got)
			}
		})
	}
}

func TestClamdDrainDisabledClosesScanner(t *testing.T) {
	drain := &clamdDrain{}
	if err := drain.shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	closed := false
	drain.closeScanner(func() { closed = true })
	if !closed {
		t.Fatal("disabled adapter prevented scanner cleanup")
	}
}

func TestClamdShutdownConcurrentHTTP(t *testing.T) {
	e := &clamdBlockingEngine{started: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(e.release) })
	defer release()
	cfg := &mailstrix.Config{ClamdUnixPath: filepath.Join(t.TempDir(), "c"),
		MaxConcurrent: 1, MaxInflight: 1, MaxBody: 1024, BackendTimeout: time.Second, ScanTimeout: time.Second}
	srv := mailstrix.NewServer(cfg, e)
	service, err := srv.StartClamd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		release()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	conn, err := net.DialTimeout("unix", cfg.ClamdUnixPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "zINSTREAM\x00\x00\x00\x00\x01x\x00\x00\x00\x00"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.started:
	case <-time.After(3 * time.Second):
		t.Fatal("scan did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	httpStarted := make(chan struct{})
	contexts := make(chan context.Context, 2)
	readyStatus := make(chan int, 1)
	icapJoined := make(chan struct{})
	go func() {
		select {
		case <-httpStarted:
		case <-ctx.Done():
		}
		release()
	}()
	drain := &clamdDrain{service: service}
	wantErr := errors.New("HTTP shutdown result")
	err = shutdownAdapters(ctx, drain, func(got context.Context) error {
		contexts <- got
		if err := srv.Shutdown(got); err != nil {
			return err
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ready", nil))
		readyStatus <- w.Code
		close(httpStarted)
		return wantErr
	}, func(got context.Context) {
		contexts <- got
		<-e.release
		close(icapJoined)
	})
	if drain.err != nil {
		t.Fatalf("HTTP shutdown must begin before blocked clamd drain completes: %v", drain.err)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("HTTP shutdown error=%v, want %v", err, wantErr)
	}
	if status := <-readyStatus; status != http.StatusServiceUnavailable {
		t.Fatalf("ready status=%d, want 503 during clamd drain", status)
	}
	for range 2 {
		if got := <-contexts; got != ctx {
			t.Fatal("adapter did not receive shared shutdown context/deadline")
		}
	}
	select {
	case <-icapJoined:
	default:
		t.Fatal("shutdown returned before ICAP joined")
	}
}
