package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	milter "github.com/emersion/go-milter"

	"github.com/myguard-labs/mailstrix/internal/verdict"
)

// lockedBuf is a log sink safe to write from the serve and session goroutines
// while the test reads it.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// startServe runs serveUntil on a fresh loopback listener and returns its
// address, the stop channel, the exit-code channel and the log.
func startServe(t *testing.T, cfg config) (string, chan os.Signal, chan int, *lockedBuf) {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.listen = "inet:" + base.Addr().String()
	if cfg.maxConns == 0 {
		cfg.maxConns = 4
	}
	stop := make(chan os.Signal, 1)
	done := make(chan int, 1)
	lb := &lockedBuf{}
	go func() { done <- serveUntil(base, cfg, log.New(lb, "", 0), stop) }()
	return base.Addr().String(), stop, done, lb
}

// openSession dials the milter and completes option negotiation, which proves
// the server accepted the connection and is running a session on it.
func openSession(t *testing.T, addr string) *milter.ClientSession {
	t.Helper()
	// Ask only for what strix-milter negotiates: go-milter's default client mask
	// includes actions a v2 server cannot grant, which fails the downgrade.
	s, err := milter.NewClientWithOptions("tcp", addr, milter.ClientOptions{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		ActionMask:   milterActions,
	}).Session()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitExit(t *testing.T, done <-chan int, within time.Duration) int {
	t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(within):
		t.Fatalf("serve did not return within %s", within)
		return -1
	}
}

func TestShutdownDrainsAnInFlightSessionBeforeReturning(t *testing.T) {
	// SIGTERM mid-scan used to drop the session at once; with the MTA's usual
	// milter_default_action=accept that mail was then delivered UNSCANNED. The
	// in-flight verdict must reach the MTA before serve returns.
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		enterOnce.Do(func() { close(entered) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(stub.Close)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	cfg := baseCfg(stub.URL)
	cfg.drain = 10 * time.Second
	addr, stop, done, lb := startServe(t, cfg)

	s := openSession(t, addr)
	defer func() { _ = s.Close() }()
	if _, err := s.HeaderField("Subject", "drain"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HeaderEnd(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BodyChunk([]byte("hello\r\n")); err != nil {
		t.Fatal(err)
	}
	type endResult struct {
		mods []milter.ModifyAction
		act  *milter.Action
		err  error
	}
	endCh := make(chan endResult, 1)
	go func() {
		mods, act, err := s.End()
		endCh <- endResult{mods, act, err}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the scan never reached the stub")
	}
	stop <- syscall.SIGTERM

	select {
	case code := <-done:
		t.Fatalf("serve returned %d while a session was still scanning — in-flight mail is dropped (drain is inert)", code)
	case <-time.After(300 * time.Millisecond):
	}
	// Draining must not mean accepting new work: the listener is closed.
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("a new connection was accepted after shutdown began")
	}

	close(release)
	var res endResult
	select {
	case res = <-endCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight session never got its verdict")
	}
	if res.err != nil {
		t.Fatalf("in-flight session failed during drain: %v", res.err)
	}
	if res.act.Code != milter.ActAccept {
		t.Fatalf("verdict action = %q, want accept", res.act.Code)
	}
	var status string
	for _, m := range res.mods {
		if m.Code == milter.ActAddHeader && m.HeaderName == hdrStatus {
			status = m.HeaderValue
		}
	}
	if status != "clean" {
		t.Fatalf("%s = %q, want clean — the verdict did not reach the MTA (mods %+v)", hdrStatus, status, res.mods)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if code := waitExit(t, done, 5*time.Second); code != 0 {
		t.Fatalf("clean drain returned %d, want 0", code)
	}
	if strings.Contains(lb.String(), "drain timed out") {
		t.Fatalf("clean drain logged a timeout:\n%s", lb.String())
	}
}

func TestShutdownDrainIsBoundedAndReportsOpenSessions(t *testing.T) {
	// A peer that never finishes must not hold shutdown hostage: serve returns
	// after the bound, still exit 0, and names how many sessions it abandoned.
	const bound = 300 * time.Millisecond
	cfg := baseCfg("http://127.0.0.1:1")
	cfg.drain = bound
	addr, stop, done, lb := startServe(t, cfg)

	s := openSession(t, addr) // negotiated, then silent: stuck from the server's view
	defer func() { _ = s.Close() }()

	start := time.Now()
	stop <- syscall.SIGINT
	code := waitExit(t, done, 5*time.Second)
	elapsed := time.Since(start)

	if code != 0 {
		t.Fatalf("drain timeout returned %d, want 0 (a restart must not look like a failure)", code)
	}
	if elapsed < bound {
		t.Fatalf("serve returned after %s, before the %s drain bound — it did not wait", elapsed, bound)
	}
	want := "drain timed out after 300ms with 1 milter session(s) still open"
	if got := lb.String(); !strings.Contains(got, want) {
		t.Fatalf("log does not report the failed drain; want %q in:\n%s", want, got)
	}
}

func TestShutdownWithNoSessionsReturnsAtOnce(t *testing.T) {
	cfg := baseCfg("http://127.0.0.1:1")
	cfg.drain = time.Minute // would dominate if an idle drain waited for the bound
	_, stop, done, lb := startServe(t, cfg)
	stop <- syscall.SIGTERM
	if code := waitExit(t, done, 5*time.Second); code != 0 {
		t.Fatalf("idle shutdown returned %d, want 0", code)
	}
	if strings.Contains(lb.String(), "drain timed out") {
		t.Fatalf("idle shutdown logged a timeout:\n%s", lb.String())
	}
}

func TestShutdownDoesNotRaceTheServeLoop(t *testing.T) {
	// go-milter v0.4.1's Server.Close writes the listener list and closed flag
	// that Serve reads without a lock; calling it from the signal path is a data
	// race. This is the -race control: shut down immediately, repeatedly.
	for i := 0; i < 20; i++ {
		cfg := baseCfg("http://127.0.0.1:1")
		cfg.drain = time.Second
		_, stop, done, _ := startServe(t, cfg)
		stop <- syscall.SIGTERM
		if code := waitExit(t, done, 5*time.Second); code != 0 {
			t.Fatalf("iteration %d: shutdown returned %d, want 0", i, code)
		}
	}
}

// failingListener's Accept fails with a fixed, non-close error.
type failingListener struct {
	net.Listener
	err error
}

func (f failingListener) Accept() (net.Conn, error) { return nil, f.err }

func TestServeReturnsOneOnANonCloseAcceptError(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := baseCfg("http://127.0.0.1:1")
	cfg.maxConns = 2
	cfg.drain = time.Second
	lb := &lockedBuf{}
	done := make(chan int, 1)
	go func() {
		done <- serveUntil(failingListener{Listener: base, err: errors.New("accept boom")}, cfg, log.New(lb, "", 0), make(chan os.Signal))
	}()
	if code := waitExit(t, done, 5*time.Second); code != 1 {
		t.Fatalf("serve returned %d on a failed Accept, want 1", code)
	}
	if !strings.Contains(lb.String(), "serve: accept boom") {
		t.Fatalf("the Serve error was not logged:\n%s", lb.String())
	}
	// The listener serve() was given must be closed on the way out.
	if _, err := net.DialTimeout("tcp", base.Addr().String(), time.Second); err == nil {
		t.Fatal("serve left its listener open after a fatal Serve error")
	}
}

func TestLimitListenerAtCapacityUnblocksOnClose(t *testing.T) {
	// At the cap, Accept waits on the semaphore and never reaches the inner
	// listener, so closing the inner listener alone cannot wake it: shutdown
	// would hang with every slot busy. Close must release that waiter.
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := limitListener(base, 1)
	defer func() { _ = ln.Close() }()

	go func() {
		if c, err := net.Dial("tcp", base.Addr().String()); err == nil {
			defer func() { _ = c.Close() }()
			time.Sleep(3 * time.Second)
		}
	}()
	held, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()

	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept() // blocks on the full semaphore
		if c != nil {
			_ = c.Close()
		}
		errCh <- err
	}()
	time.Sleep(100 * time.Millisecond) // let it park on the semaphore
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close returned %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept at capacity stayed blocked after Close — shutdown would hang")
	}

	// Closed stays closed, and a second Close is harmless (go-milter's Serve
	// closes its listener again on the way out).
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept on a closed listener returned %v, want net.ErrClosed", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("second Close returned %v, want nil", err)
	}
}

// oneConnListener hands out a single pre-made conn.
type oneConnListener struct {
	net.Listener
	c net.Conn
}

func (o *oneConnListener) Accept() (net.Conn, error) { return o.c, nil }
func (o *oneConnListener) Close() error              { return nil }

func TestTrackedListenerRefusesAConnAcceptedAfterClose(t *testing.T) {
	// An Accept that returns in the instant Close ran must not register a session
	// the drain has already decided does not exist.
	srvSide, cliSide := net.Pipe()
	defer func() { _ = cliSide.Close() }()
	tl := trackListener(&oneConnListener{c: srvSide})
	if err := tl.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := tl.Accept(); !errors.Is(err, net.ErrClosed) || c != nil {
		t.Fatalf("Accept after Close = (%v, %v), want (nil, net.ErrClosed)", c, err)
	}
	if _, err := srvSide.Write([]byte("x")); err == nil {
		t.Fatal("the late conn was left open instead of being refused")
	}
	if open := tl.drain(time.Second); open != 0 {
		t.Fatalf("drain reports %d open after a refused late conn, want 0", open)
	}
}

func TestTrackedConnCountsOnceAcrossDoubleClose(t *testing.T) {
	srvSide, cliSide := net.Pipe()
	defer func() { _ = cliSide.Close() }()
	tl := trackListener(&oneConnListener{c: srvSide})
	c, err := tl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = tl.Close()
	if open := tl.drain(10 * time.Millisecond); open != 1 {
		t.Fatalf("drain with one live session reports %d open, want 1", open)
	}
	_ = c.Close()
	_ = c.Close() // a double close must not drive the count negative
	if open := tl.drain(time.Second); open != 0 {
		t.Fatalf("drain after the session closed reports %d open, want 0", open)
	}
	tl.mu.Lock()
	n := tl.open
	tl.mu.Unlock()
	if n != 0 {
		t.Fatalf("open count = %d after a double close, want 0", n)
	}
}

func TestDrainTimeoutDerivesFromScanTimeout(t *testing.T) {
	if got := drainTimeout(config{timeout: 7 * time.Second}); got != 7*time.Second+drainGrace {
		t.Fatalf("unset drain = %s, want timeout+grace %s", got, 7*time.Second+drainGrace)
	}
	if got := drainTimeout(config{timeout: 7 * time.Second, drain: 2 * time.Second}); got != 2*time.Second {
		t.Fatalf("explicit drain = %s, want 2s", got)
	}
	if drainTimeout(config{timeout: 20 * time.Second}) <= 20*time.Second {
		t.Fatal("the drain bound must exceed the scan timeout, or a scan still inside its deadline is cut off")
	}
}

func TestEffectiveCapSeesThroughTheSessionTracker(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = base.Close() }()
	if n := effectiveCap(trackListener(limitListener(base, 3))); n != 3 {
		t.Fatalf("effectiveCap through the tracker = %d, want 3", n)
	}
	if n := effectiveCap(trackListener(base)); n != 0 {
		t.Fatalf("effectiveCap of an uncapped tracked listener = %d, want 0", n)
	}
}
