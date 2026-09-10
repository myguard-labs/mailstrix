package mailstrix

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// Only the scanner boundary is replaced. Protocol, shared admission, socket
// reads/writes and service shutdown are the production implementation.
type clamdTestEngine struct {
	fakeEngine
	call  func([]byte, ScanMeta) ([]Match, error)
	calls atomic.Int32
}

func (e *clamdTestEngine) Scan(b []byte, meta ScanMeta) ([]Match, error) {
	e.calls.Add(1)
	if e.call != nil {
		return e.call(b, meta)
	}
	return nil, nil
}

func clamdWire(body string) string {
	var b bytes.Buffer
	b.WriteString("zINSTREAM\x00")
	if body != "" {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], uint32(len(body)))
		b.Write(h[:])
		b.WriteString(body)
	}
	b.Write([]byte{0, 0, 0, 0})
	return b.String()
}

func clamdPipe(t *testing.T, s *Server) (*ClamdService, net.Conn) {
	t.Helper()
	return clamdPipeAcceptedAt(t, s, time.Now())
}

func clamdPipeAcceptedAt(t *testing.T, s *Server, acceptedAt time.Time) (*ClamdService, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	c := &ClamdService{s: s, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{server: {}},
		slots: make(chan struct{}, 1), done: make(chan struct{}), forced: make(chan struct{})}
	c.slots <- struct{}{}
	c.wg.Add(1)
	go c.serve(server, acceptedAt)
	go func() { c.wg.Wait(); close(c.done) }()
	t.Cleanup(func() {
		_ = client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return c, client
}

func clamdExchange(t *testing.T, conn net.Conn, wire string) string {
	t.Helper()
	reply, err := clamdExchangeResult(conn, wire)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply
}

func clamdExchangeResult(conn net.Conn, wire string) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	written := make(chan struct{})
	go func() {
		defer close(written)
		// Malformed/pipelined requests may be rejected before upload completes.
		// The exact terminal reply below is the oracle, not upload success.
		_, _ = io.WriteString(conn, wire)
	}()
	reply, err := io.ReadAll(conn)
	<-written
	return string(reply), err
}

func TestClamdCommands(t *testing.T) {
	for _, tc := range []struct{ name, request, reply string }{
		{"nul", "zPING\x00", "PONG\x00"},
		{"newline", "nPING\n", "PONG\n"},
		{"version", "zVERSION\x00", "Mailstrix v1___x\x00"},
		{"commands", "nVERSIONCOMMANDS\n", "Mailstrix v1___x COMMANDS: PING VERSION VERSIONCOMMANDS INSTREAM\n"},
		{"legacy", "PING\n", "UNKNOWN COMMAND\n"},
		{"path", "zSCAN /etc/passwd\x00", "UNKNOWN COMMAND\x00"},
		{"shutdown", "nSHUTDOWN\n", "UNKNOWN COMMAND\n"},
		{"session", "zIDSESSION\x00", "UNKNOWN COMMAND\x00"},
		{"args", "nPING extra\n", "UNKNOWN COMMAND\n"},
		{"lowercase", "nping\n", "UNKNOWN COMMAND\n"},
		{"crlf", "nPING\r\n", "COMMAND PARSE ERROR\n"},
		{"mixed", "zPING\n", "COMMAND PARSE ERROR\x00"},
		{"wrongnul", "nPING\x00", "COMMAND PARSE ERROR\n"},
		{"limit", "n" + strings.Repeat("A", 62) + "\n", "UNKNOWN COMMAND\n"},
		{"overlimit", "n" + strings.Repeat("A", 63) + "\n", "COMMAND PARSE ERROR\n"},
		{"pipeline", "zPING\x00zINSTREAM\x00\x00\x00\x00\x00", "PONG\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &clamdTestEngine{}
			s := newTestServer(e, "")
			s.cfg.Version = "v1\n\x00:x"
			_, conn := clamdPipe(t, s)
			if got := clamdExchange(t, conn, tc.request); got != tc.reply {
				t.Fatalf("reply %q, want %q", got, tc.reply)
			}
			if e.calls.Load() != 0 {
				t.Fatal("command invoked scanner")
			}
		})
	}
	if got := clamdVersion(""); got != "unknown" {
		t.Fatal(got)
	}
	if got := clamdVersion(strings.Repeat("X", 100)); len(got) != 64 {
		t.Fatal(len(got))
	}
}

func TestClamdVerdictsAndFragmentation(t *testing.T) {
	for _, tc := range []struct {
		name, body, reply string
		matches           []Match
		err               error
		panicScan         bool
	}{
		{name: "clean", body: "a\x00b\r\nc", reply: "stream: OK\x00"},
		{name: "empty", reply: "stream: OK\x00"},
		{name: "match", body: "match", matches: []Match{{Rule: "evil\x00\n: OK"}}, reply: "stream: Mailstrix.Match FOUND\x00"},
		{name: "logonly", body: "canary", matches: []Match{{Rule: "shadow", Meta: map[string]string{"mailstrix_canary": "1"}}}, reply: "stream: OK\x00"},
		{name: "allowed", body: "allowed", matches: []Match{{Rule: "allowed", Meta: map[string]string{"mailstrix_allow": "1"}}}, reply: "stream: OK\x00"},
		{name: "mixed", body: "mixed", matches: []Match{{Rule: "shadow", Meta: map[string]string{"mailstrix_canary": "1"}}, {Rule: "active"}, {Rule: "allowed", Meta: map[string]string{"mailstrix_allow": "1"}}}, reply: "stream: Mailstrix.Match FOUND\x00"},
		{name: "all-logonly", body: "all-logonly", matches: []Match{{Rule: "shadow", Meta: map[string]string{"mailstrix_canary": "1"}}, {Rule: "allowed", Meta: map[string]string{"mailstrix_allow": "1"}}}, reply: "stream: OK\x00"},
		{name: "error", body: "bad", err: errors.New("secret\nOK"), matches: []Match{{Rule: "also"}}, reply: "stream: scan failed ERROR\x00"},
		{name: "panic", body: "panic", panicScan: true, reply: "stream: scan failed ERROR\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &clamdTestEngine{call: func(b []byte, meta ScanMeta) ([]Match, error) {
				if string(b) != tc.body {
					t.Errorf("body %q, want %q", b, tc.body)
				}
				if meta.RawKey != streamDedupKey(b) {
					t.Error("incorrect stream identity")
				}
				if tc.panicScan {
					panic("test panic")
				}
				return tc.matches, tc.err
			}}
			s := newTestServer(e, "")
			c, conn := clamdPipe(t, s)
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			writeDone := make(chan error, 1)
			go func() {
				for _, b := range []byte(clamdWire(tc.body)) {
					if _, err := conn.Write([]byte{b}); err != nil {
						writeDone <- err
						return
					}
				}
				writeDone <- nil
			}()
			got, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.reply {
				t.Fatalf("reply %q, want %q", got, tc.reply)
			}
			<-c.done
			var wantErrors uint64
			if tc.err != nil || tc.panicScan {
				wantErrors = 1
			}
			if got := s.metrics.errors.Load(); got != wantErrors {
				t.Fatalf("completed scan errors=%d, want %d", got, wantErrors)
			}
			var wantMatches uint64
			if wantErrors == 0 && len(tc.matches) > 0 {
				wantMatches = 1
			}
			if got := s.metrics.matches.Load(); got != wantMatches {
				t.Fatalf("completed scan matches=%d, want %d", got, wantMatches)
			}
			if e.calls.Load() != 1 {
				t.Fatalf("scans %d, want 1", e.calls.Load())
			}
			if len(s.admit) != 0 || len(s.sem) != 0 {
				t.Fatal("leaked scan ownership")
			}
		})
	}
}

func TestClamdEffortSelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		auto       bool
		held, want int
	}{
		{"static", false, 0, 7},
		{"auto_idle", true, 0, 7},
		{"auto_pressure", true, 3, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &clamdTestEngine{call: func(_ []byte, meta ScanMeta) ([]Match, error) {
				if meta.Effort != tc.want {
					t.Errorf("effort=%d, want %d", meta.Effort, tc.want)
				}
				return nil, nil
			}}
			s := newTestServer(e, "")
			s.cfg.Effort, s.cfg.EffortMax, s.cfg.EffortAuto = 7, 10, tc.auto
			s.autoEffort.Store(7)
			s.admit = make(chan struct{}, 4)
			for i := 0; i < tc.held; i++ {
				s.admit <- struct{}{}
			}
			c, conn := clamdPipe(t, s)
			if got := clamdExchange(t, conn, clamdWire("inert")); got != "stream: OK\x00" {
				t.Fatalf("reply=%q", got)
			}
			<-c.done
			for i := 0; i < tc.held; i++ {
				<-s.admit
			}
		})
	}
}

func TestClamdStreamLimits(t *testing.T) {
	header := func(n uint32) string { var b [4]byte; binary.BigEndian.PutUint32(b[:], n); return string(b[:]) }
	for _, tc := range []struct {
		name, wire string
		limit      int64
		reply      string
	}{
		{"exact", header(3) + "abc" + header(0), 3, ""},
		{"multiple", header(1) + "a" + header(2) + "bc" + header(0), 3, ""},
		{"total", header(2) + "ab" + header(2), 3, "INSTREAM size limit exceeded. ERROR"},
		{"overflow", header(^uint32(0)), 8, "INSTREAM size limit exceeded. ERROR"},
		{"chunk", header(clamdChunkLimit + 1), 2 * clamdChunkLimit, "stream: chunk size limit exceeded ERROR"},
		{"chunkexact", header(clamdChunkLimit) + strings.Repeat("a", clamdChunkLimit) + header(0), 2 * clamdChunkLimit, ""},
		{"shortheader", "\x00\x00", 8, "stream: truncated stream ERROR"},
		{"shortbody", header(3) + "ab", 8, "stream: truncated stream ERROR"},
		{"missingzero", header(3) + "abc", 8, "stream: truncated stream ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, reply := readClamdStream(strings.NewReader(tc.wire), tc.limit)
			if reply != tc.reply {
				t.Fatalf("reply %q, want %q", reply, tc.reply)
			}
			if int64(cap(body)) > tc.limit {
				t.Fatalf("capacity %d > %d", cap(body), tc.limit)
			}
			if reply == "" && tc.limit == 3 && string(body) != "abc" {
				t.Fatalf("body %q", body)
			}
		})
	}
}

func TestClamdAbsoluteDeadlines(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(map[bool]string{false: "command", true: "body"}[body], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := &clamdTestEngine{}
				_, conn := clamdPipe(t, newTestServer(e, ""))
				budget, prefix, reply := clamdCommandTimeout, "z", "COMMAND READ ERROR\x00"
				if body {
					budget, prefix, reply = clamdBodyTimeout, "zINSTREAM\x00", "stream: truncated stream ERROR\x00"
				}
				if _, err := io.WriteString(conn, prefix); err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				// Make progress near the deadline; it must not renew the budget.
				time.Sleep(budget - time.Second)
				if _, err := conn.Write([]byte{'A'}); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(conn)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != reply {
					t.Fatalf("reply %q, want %q", got, reply)
				}
				if elapsed := time.Since(start); elapsed != budget {
					t.Fatalf("deadline elapsed %v, want %v", elapsed, budget)
				}
				if e.calls.Load() != 0 {
					t.Fatal("incomplete request scanned")
				}
			})
		})
	}
}

func TestClamdCommandDeadlineStartsAtAccept(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		acceptedAt := time.Now()
		// A queued handler starts four seconds after the socket was accepted.
		time.Sleep(4 * time.Second)
		_, conn := clamdPipeAcceptedAt(t, newTestServer(&clamdTestEngine{}, ""), acceptedAt)
		if _, err := io.WriteString(conn, "z"); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "COMMAND READ ERROR\x00" {
			t.Fatalf("reply %q", got)
		}
		if elapsed := time.Since(acceptedAt); elapsed != 5*time.Second {
			t.Fatalf("command deadline elapsed %v from accept, want 5s", elapsed)
		}
	})
}

func TestClamdScanTimeoutOwnsResources(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		releaseScan := sync.OnceFunc(func() { close(release) })
		defer releaseScan()
		e := &clamdTestEngine{call: func([]byte, ScanMeta) ([]Match, error) { <-release; return nil, errors.New("late native error") }}
		s := newTestServer(e, "")
		c, conn := clamdPipe(t, s)
		if _, err := io.WriteString(conn, clamdWire("blocked")); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "stream: scan timed out ERROR\x00" {
			t.Fatalf("reply %q", got)
		}
		if time.Since(start) != s.cfg.ScanTimeout+clamdScanSlack {
			t.Fatal("wrong scan timeout")
		}
		if got := s.metrics.errors.Load(); got != 1 {
			t.Fatalf("timeout errors=%d, want 1", got)
		}
		synctest.Wait()
		if len(s.admit) != 1 || len(s.sem) != 1 {
			t.Fatal("native scan lost admission/CPU ownership on response timeout")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown %v, want timeout", err)
		}
		if len(s.admit) != 1 || len(s.sem) != 1 {
			t.Fatal("native scan lost ownership on shutdown timeout")
		}
		releaseScan()
		synctest.Wait()
		if err := c.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(s.admit) != 0 || len(s.sem) != 0 {
			t.Fatal("native scan permits not released after completion")
		}
		if got := s.metrics.errors.Load(); got != 2 {
			t.Fatalf("timeout plus late native errors=%d, want 2 distinct events", got)
		}
	})
}

func TestClamdShutdownCancelsUpload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestServer(&clamdTestEngine{}, "")
		c, conn := clamdPipe(t, s)
		if _, err := io.WriteString(conn, "zINSTREAM\x00"); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if len(s.admit) != 1 {
			t.Fatal("upload missing admission")
		}
		finished := make(chan error, 1)
		go func() { finished <- c.Shutdown(context.Background()) }()
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "stream: truncated stream ERROR\x00" {
			t.Fatalf("reply %q", got)
		}
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		if len(s.admit) != 0 {
			t.Fatal("upload admission leaked")
		}
	})
}

func TestClamdWriteDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestServer(&clamdTestEngine{}, "")
		c, conn := clamdPipe(t, s)
		if _, err := io.WriteString(conn, "zPING\x00"); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		// Never read the reply: the write deadline must release the connection.
		<-c.done
		if time.Since(start) != clamdWriteTimeout {
			t.Fatal("write did not finish at deadline")
		}
		if s.metrics.canceled.Load() != 1 {
			t.Fatal("write failure not recorded")
		}
	})
}

func TestClamdVerboseLogOnlyMatches(t *testing.T) {
	for _, marker := range []string{"mailstrix_canary", "mailstrix_allow"} {
		for _, verbose := range []bool{false, true} {
			t.Run(marker+"/verbose="+strconv.FormatBool(verbose), func(t *testing.T) {
				e := &clamdTestEngine{call: func([]byte, ScanMeta) ([]Match, error) {
					return []Match{{Rule: "log-only-fixture", Meta: map[string]string{marker: "1"}}}, nil
				}}
				s := newTestServer(e, "")
				s.cfg.Verbose = verbose
				var logs bytes.Buffer
				s.info = log.New(&logs, "", 0)
				c, conn := clamdPipe(t, s)
				if got := clamdExchange(t, conn, clamdWire("log-only")); got != "stream: OK\x00" {
					t.Fatalf("log-only reply %q, want OK", got)
				}
				<-c.done
				const want = `clamd 8B matches="[log-only-fixture]"`
				if verbose && !strings.Contains(logs.String(), want) {
					t.Fatalf("missing verbose log-only rule log %q: got %q", want, logs.String())
				}
				if !verbose && logs.Len() != 0 {
					t.Fatalf("unexpected nonverbose log %q", logs.String())
				}
				if got := s.metrics.matches.Load(); got != 1 {
					t.Fatalf("log-only matches counter=%d, want 1", got)
				}
			})
		}
	}
}

// Complete the service while Shutdown evaluates its blocking select, after
// its initial completion check. Both channels are then ready for selection.
type clamdCompleteOnDeadlineContext struct {
	context.Context
	complete func()
}

func (c clamdCompleteOnDeadlineContext) Done() <-chan struct{} {
	c.complete()
	return c.Context.Done()
}

func TestClamdShutdownCompletionAtDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	// Exercise either select winner; a completed service must never report a
	// timeout or enter forced shutdown, whichever ready channel is selected.
	for range 128 {
		c := &ClamdService{stopping: true, done: make(chan struct{}), forced: make(chan struct{})}
		boundary := clamdCompleteOnDeadlineContext{Context: ctx, complete: sync.OnceFunc(func() { close(c.done) })}
		if err := c.Shutdown(boundary); err != nil {
			t.Fatalf("completed service at deadline returned error: %v", err)
		}
		select {
		case <-c.forced:
			t.Fatal("completed service at deadline entered forced shutdown")
		default:
		}
	}
}

func TestClamdShutdownDuringNativeScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		releaseScan := sync.OnceFunc(func() { close(release) })
		defer releaseScan()
		started := make(chan struct{})
		e := &clamdTestEngine{call: func([]byte, ScanMeta) ([]Match, error) { close(started); <-release; return nil, nil }}
		s := newTestServer(e, "")
		c, conn := clamdPipe(t, s)
		if _, err := io.WriteString(conn, clamdWire("native")); err != nil {
			t.Fatal(err)
		}
		<-started
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("drain %v", err)
		}
		got, err := io.ReadAll(conn)
		if err != nil || len(got) != 0 {
			t.Fatalf("forced-close reply %q err=%v", got, err)
		}
		synctest.Wait()
		if len(s.sem) != 1 || len(s.admit) != 1 {
			t.Fatal("forced shutdown released live native ownership")
		}
		select {
		case <-c.done:
			t.Fatal("done before native return")
		default:
		}
		releaseScan()
		synctest.Wait()
		if err := c.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestClamdTruncationOverTCP(t *testing.T) {
	e := &clamdTestEngine{}
	s := newTestServer(e, "")
	s.cfg.ClamdTCPAddr = "127.0.0.1:0"
	c, err := s.StartClamd()
	if err != nil || c == nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()
	for _, tc := range []struct{ wire, reply string }{
		{"zIN", "COMMAND READ ERROR\x00"},
		{"zINSTREAM\x00\x00\x00", "stream: truncated stream ERROR\x00"},
		{"nINSTREAM\n\x00\x00\x00\x02a", "stream: truncated stream ERROR\n"},
		{"zINSTREAM\x00\x00\x00\x00\x01a", "stream: truncated stream ERROR\x00"},
	} {
		conn, err := net.DialTimeout("tcp", c.listeners[0].Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(conn, tc.wire); err != nil {
			t.Fatal(err)
		}
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(conn)
		_ = conn.Close()
		if err != nil || string(got) != tc.reply {
			t.Fatalf("truncation reply %q err=%v want %q", got, err, tc.reply)
		}
	}
	if e.calls.Load() != 0 {
		t.Fatal("truncated stream reached scanner")
	}
}

func TestClamdAdmissionAndCPUBudgets(t *testing.T) {
	for _, cpu := range []bool{false, true} {
		t.Run(map[bool]string{false: "admission", true: "cpu"}[cpu], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := &clamdTestEngine{}
				s := newTestServer(e, "")
				gate := s.admit
				if cpu {
					gate = s.sem
				}
				for i := 0; i < cap(gate); i++ {
					gate <- struct{}{}
				}
				defer func() {
					for len(gate) > 0 {
						<-gate
					}
				}()
				_, conn := clamdPipe(t, s)
				start := time.Now()
				got := clamdExchange(t, conn, clamdWire("body"))
				if got != "stream: busy ERROR\x00" {
					t.Fatalf("reply %q", got)
				}
				if time.Since(start) != s.cfg.BackendTimeout {
					t.Fatal("incorrect queue budget")
				}
				if e.calls.Load() != 0 {
					t.Fatal("scan escaped gate")
				}
				if busy, errs := s.metrics.busy.Load(), s.metrics.errors.Load(); busy != 1 || errs != 0 {
					t.Fatalf("capacity rejection busy=%d errors=%d, want 1/0", busy, errs)
				}
			})
		})
	}
}

func TestClamdCanceledCapacityWait(t *testing.T) {
	for _, cpu := range []bool{false, true} {
		t.Run(map[bool]string{false: "admission", true: "cpu"}[cpu], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newTestServer(&clamdTestEngine{}, "")
				gate := s.admit
				if cpu {
					gate = s.sem
				}
				for i := 0; i < cap(gate); i++ {
					gate <- struct{}{}
				}
				c, conn := clamdPipe(t, s)
				type exchangeResult struct {
					reply string
					err   error
				}
				done := make(chan exchangeResult, 1)
				go func() {
					reply, err := clamdExchangeResult(conn, clamdWire("inert"))
					done <- exchangeResult{reply, err}
				}()
				synctest.Wait() // Upload/CPU admission is waiting on the saturated gate.
				c.cancel()
				got := <-done
				if got.err != nil || got.reply != "stream: busy ERROR\x00" {
					t.Fatalf("canceled queue reply=%q err=%v", got.reply, got.err)
				}
				<-c.done
				for len(gate) > 0 {
					<-gate
				}
				if busy, errs := s.metrics.busy.Load(), s.metrics.errors.Load(); busy != 0 || errs != 0 {
					t.Fatalf("canceled wait busy=%d errors=%d, want 0/0", busy, errs)
				}
			})
		})
	}

}

type clamdTransientListener struct {
	net.Listener
	firstErr error
	calls    atomic.Int32
}

type clamdScriptListener struct {
	accept func() (net.Conn, error)
}

func (ln *clamdScriptListener) Accept() (net.Conn, error) { return ln.accept() }
func (*clamdScriptListener) Close() error                 { return nil }
func (*clamdScriptListener) Addr() net.Addr               { return &net.TCPAddr{} }

func clamdRetryService(t *testing.T) *ClamdService {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &ClamdService{s: newTestServer(&clamdTestEngine{}, ""), ctx: ctx, cancel: cancel,
		conns: make(map[net.Conn]struct{}), slots: make(chan struct{})}
}

func TestClamdAcceptBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := clamdRetryService(t)
		var times []time.Time
		ln := &clamdScriptListener{accept: func() (net.Conn, error) {
			times = append(times, time.Now())
			switch len(times) {
			case 12:
				// A successful accept resets the delay even when the cap refuses it.
				server, client := net.Pipe()
				_ = client.Close()
				return server, nil
			case 14:
				c.stop()
				return nil, net.ErrClosed
			default:
				return nil, &net.OpError{Op: "accept", Err: syscall.EMFILE}
			}
		}}
		c.listeners = []net.Listener{ln}
		c.wg.Add(1)
		go c.accept(ln)
		c.wg.Wait()
		if len(times) != 14 {
			t.Fatalf("accept calls=%d, want 14", len(times))
		}
		delay := 5 * time.Millisecond
		for i := 1; i < 12; i++ {
			if got := times[i].Sub(times[i-1]); got != delay {
				t.Fatalf("retry %d delay=%v, want %v", i, got, delay)
			}
			delay = min(delay*2, time.Second)
		}
		if got := times[12].Sub(times[11]); got != 0 {
			t.Fatalf("successful accept added delay %v", got)
		}
		if got := times[13].Sub(times[12]); got != 5*time.Millisecond {
			t.Fatalf("reset delay=%v, want 5ms", got)
		}
	})
}

func TestClamdAcceptBackoffShutdown(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM} {
		t.Run(errno.Error(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := clamdRetryService(t)
				var calls int
				ln := &clamdScriptListener{accept: func() (net.Conn, error) {
					calls++
					return nil, &net.OpError{Op: "accept", Err: errno}
				}}
				c.listeners = []net.Listener{ln}
				c.wg.Add(1)
				go c.accept(ln)
				synctest.Wait() // Accept has returned; the retry timer is now pending.
				if c.ctx.Err() != nil {
					t.Fatal("resource error stopped listener instead of entering backoff")
				}
				start := time.Now()
				c.stop()
				c.wg.Wait()
				if elapsed := time.Since(start); elapsed != 0 || calls != 1 {
					t.Fatalf("shutdown waited %v, accept calls=%d; want immediate exit after one call", elapsed, calls)
				}
			})
		})
	}
}

func TestClamdAcceptTerminalFailureMetric(t *testing.T) {
	c := clamdRetryService(t)
	ln := &clamdScriptListener{accept: func() (net.Conn, error) {
		return nil, &net.OpError{Op: "accept", Err: syscall.EINVAL}
	}}
	c.listeners = []net.Listener{ln}
	c.wg.Add(1)
	c.accept(ln)
	if c.ctx.Err() == nil {
		t.Fatal("terminal accept failure did not stop service")
	}
	w := httptest.NewRecorder()
	c.s.serveMetrics(w)
	if !strings.Contains(w.Body.String(), "mailstrix_clamd_accept_errors_total 1\n") {
		t.Fatal("terminal accept failure metric missing or not incremented")
	}
}

func (ln *clamdTransientListener) Accept() (net.Conn, error) {
	if ln.calls.Add(1) == 1 {
		return nil, ln.firstErr
	}
	return ln.Listener.Accept()
}

func TestClamdAcceptRetriesResourceExhaustion(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM} {
		t.Run(errno.Error(), func(t *testing.T) {
			base, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = base.Close() }()
			ln := &clamdTransientListener{Listener: base, firstErr: &net.OpError{
				Op: "accept", Net: "tcp", Err: &os.SyscallError{Syscall: "accept4", Err: errno},
			}}
			ctx, cancel := context.WithCancel(context.Background())
			c := &ClamdService{s: newTestServer(&clamdTestEngine{}, ""), ctx: ctx, cancel: cancel,
				listeners: []net.Listener{ln}, conns: make(map[net.Conn]struct{}),
				slots: make(chan struct{}, 1), done: make(chan struct{}), forced: make(chan struct{})}
			c.wg.Add(1)
			go c.accept(ln)
			go func() { c.wg.Wait(); close(c.done) }()
			t.Cleanup(func() {
				shutdown, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := c.Shutdown(shutdown); err != nil {
					t.Error(err)
				}
			})
			conn, err := net.DialTimeout("tcp", base.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("listener must recover after one temporary %v: dial: %v (accept calls=%d)", errno, err, ln.calls.Load())
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "zPING\x00"); err != nil {
				t.Fatalf("listener must recover after one temporary %v: write: %v (accept calls=%d)", errno, err, ln.calls.Load())
			}
			reply, err := io.ReadAll(conn)
			if err != nil || string(reply) != "PONG\x00" {
				t.Fatalf("listener must recover after one temporary %v: reply=%q err=%v (accept calls=%d)", errno, reply, err, ln.calls.Load())
			}
		})
	}
}

func TestClamdListeners(t *testing.T) {
	e := &clamdTestEngine{}
	s := newTestServer(e, "")
	s.cfg.ClamdTCPAddr = "127.0.0.1:0"
	s.cfg.ClamdUnixPath = filepath.Join(t.TempDir(), "clamd.sock")
	s.cfg.ClamdMaxConns = 1
	c, err := s.StartClamd()
	if err != nil || c == nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	info, err := os.Stat(s.cfg.ClamdUnixPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode info=%v err=%v", info, err)
	}
	assertClamdListenerStreams(t, c, s.cfg.ClamdUnixPath)
	if e.calls.Load() != 2 {
		t.Fatalf("scans %d, want 2", e.calls.Load())
	}
	assertClamdSharedConnectionCap(t, c, s.cfg.ClamdUnixPath)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s.cfg.ClamdUnixPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned socket remains: %v", err)
	}
}

// Both transports must scan once and discard pipelined trailing commands.
func assertClamdListenerStreams(t *testing.T, c *ClamdService, unixPath string) {
	t.Helper()
	for _, network := range []string{"tcp", "unix"} {
		addr := unixPath
		if network == "tcp" {
			addr = c.listeners[0].Addr().String()
		}
		conn, err := net.DialTimeout(network, addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		got := clamdExchange(t, conn, clamdWire("inert")+"zPING\x00")
		_ = conn.Close()
		if got != "stream: OK\x00" {
			t.Fatalf("%s reply %q", network, got)
		}
		waitClamdConnections(t, c, 0)
	}
}

// A partial command holds the shared cap across both listener types.
func assertClamdSharedConnectionCap(t *testing.T, c *ClamdService, unixPath string) {
	t.Helper()
	held, err := net.DialTimeout("tcp", c.listeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }() // teardown; already closed below
	if _, err := io.WriteString(held, "z"); err != nil {
		t.Fatal(err)
	}
	waitClamdConnections(t, c, 1)
	refused, err := net.DialTimeout("unix", unixPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = refused.Close() }() // refusal already closed the socket
	_ = refused.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if n, err := refused.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("cap refusal n=%d err=%v", n, err)
	}
	_ = held.Close()
}

// Both the registry and slot occupancy must reflect admission/release.
func waitClamdConnections(t *testing.T, c *ClamdService, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c.mu.Lock()
		n := len(c.conns)
		c.mu.Unlock()
		slots := len(c.slots)
		if n == want && slots == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("connections %d, slots %d, want %d", n, slots, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestClamdConfiguration(t *testing.T) {
	for _, name := range []string{"MAILSTRIX_CLAMD_TCP_ADDR", "MAILSTRIX_CLAMD_UNIX_PATH", "MAILSTRIX_CLAMD_MAX_CONNS"} {
		t.Setenv(name, "")
	}
	cfg := LoadConfig()
	if cfg.ClamdTCPAddr != "" || cfg.ClamdUnixPath != "" || cfg.ClamdMaxConns != 64 {
		t.Fatalf("unexpected clamd defaults: %q %q %d", cfg.ClamdTCPAddr, cfg.ClamdUnixPath, cfg.ClamdMaxConns)
	}
	t.Run("configured", func(t *testing.T) {
		const tcp = "127.0.0.1:3310"
		const unix = "/run/mailstrix/clamd.sock " // Whitespace belongs to the exact pathname.
		t.Setenv("MAILSTRIX_CLAMD_TCP_ADDR", tcp)
		t.Setenv("MAILSTRIX_CLAMD_UNIX_PATH", unix)
		t.Setenv("MAILSTRIX_CLAMD_MAX_CONNS", "17")
		got := LoadConfig()
		if got.ClamdTCPAddr != tcp {
			t.Errorf("configured TCP=%q, want %q", got.ClamdTCPAddr, tcp)
		}
		if got.ClamdUnixPath != unix {
			t.Errorf("configured Unix=%q, want %q", got.ClamdUnixPath, unix)
		}
		if got.ClamdMaxConns != 17 {
			t.Errorf("configured cap=%d, want 17", got.ClamdMaxConns)
		}
	})
	s := newTestServer(&clamdTestEngine{}, "")
	if c, err := s.StartClamd(); c != nil || err != nil {
		t.Fatalf("disabled listener: %v %v", c, err)
	}
	for _, addr := range []string{":3310", "127.0.0.1", "[::1]:"} {
		s.cfg.ClamdTCPAddr = addr
		if c, err := s.StartClamd(); err == nil {
			if c != nil {
				if err := c.Shutdown(context.Background()); err != nil {
					t.Error(err)
				}
			}
			t.Fatalf("accepted TCP address %q", addr)
		}
	}
	for _, value := range []int{-1, 0, 1025, 1, 1024} {
		x := &Config{ClamdMaxConns: value}
		x.sanitize()
		want := value
		if value < 1 || value > 1024 {
			want = 64
		}
		if x.ClamdMaxConns != want {
			t.Fatalf("cap %d -> %d", value, x.ClamdMaxConns)
		}
	}
}

func TestClamdUnixPathCapacity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("long private staging addresses use Linux proc-fd aliases")
	}
	root, err := os.MkdirTemp("", "cl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	const capacity = len(syscall.RawSockaddrUnix{}.Path) - 1
	t.Run("overlong-basename", func(t *testing.T) {
		parent := filepath.Join(root, "short")
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, strings.Repeat("s", capacity-len(parent)))
		if len(path) != capacity+1 {
			t.Fatal("invalid overcapacity fixture")
		}
		if ln, cleanup, err := listenClamdUnix(path); err == nil {
			_ = ln.Close()
			cleanup()
			t.Fatal("accepted overcapacity Unix path with short staging path")
		}
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != 0 {
			t.Fatalf("overcapacity publication/staging leftovers: %v, err=%v", entries, err)
		}
	})
	for _, size := range []int{capacity - 5, capacity, capacity + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			parent := filepath.Join(root, strings.Repeat("p", size-len(root)-4))
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "s ") // Exact trailing-space pathname.
			if len(path) != size {
				t.Fatalf("fixture path length=%d, want %d", len(path), size)
			}
			ln, cleanup, err := listenClamdUnix(path)
			if size > capacity {
				if err == nil {
					_ = ln.Close()
					cleanup()
					t.Fatal("accepted overcapacity Unix path")
				}
			} else {
				if err != nil {
					t.Fatalf("valid near-limit Unix path rejected: %v", err)
				}
				defer func() { _ = ln.Close(); cleanup() }()
				conn, err := net.DialTimeout("unix", path, time.Second)
				if err != nil {
					t.Fatalf("published path is not dialable: %v", err)
				}
				_ = conn.Close()
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("private socket mode: info=%v err=%v", info, err)
				}
				_ = ln.Close()
				cleanup()
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("socket/staging leftovers: %v, err=%v", entries, err)
			}
		})
	}
	if ln, cleanup, err := listenClamdUnix(filepath.Join(root, "bad\x00path")); err == nil {
		_ = ln.Close()
		cleanup()
		t.Fatal("accepted NUL in Unix path")
	}
}

func TestClamdUnixOwnership(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "socket")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if ln, _, err := listenClamdUnix(path); err == nil {
		_ = ln.Close()
		t.Fatal("replaced occupied path")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "keep" {
		t.Fatal("existing file modified")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "absent"), path); err != nil {
		t.Fatal(err)
	}
	if ln, _, err := listenClamdUnix(path); err == nil {
		_ = ln.Close()
		t.Fatal("replaced symlink")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ln, cleanup, err := listenClamdUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	cleanup()
	if got, err := os.ReadFile(path); err != nil || string(got) != "replacement" {
		t.Fatal("cleanup removed replacement")
	}
}

func FuzzClamdCommand(f *testing.F) {
	for _, seed := range []string{"zPING\x00", "nINSTREAM\n", "zPING\n", strings.Repeat("x", 100)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		cmd, term, reply := readClamdCommand(bufio.NewReader(strings.NewReader(wire)))
		if len(cmd) > 62 || len(reply) > 255 || term != 0 && term != '\n' {
			t.Fatal("unbounded command result")
		}
	})
}

// This opt-in probe uses real installed clients. Ordinary CI still exercises
// all parser/lifecycle paths above without these optional external tools.
func TestClamdRealClients(t *testing.T) {
	python := os.Getenv("MAILSTRIX_TEST_CLAMD_PYTHON")
	if python == "" {
		t.Skip("set MAILSTRIX_TEST_CLAMD_PYTHON to a venv with clamd==1.0.2")
	}
	clamdscan, err := exec.LookPath("clamdscan")
	if err != nil {
		t.Fatal(err)
	}
	e := &clamdTestEngine{call: func(body []byte, _ ScanMeta) ([]Match, error) {
		switch string(body) {
		case "MAILSTRIX-CLAMD-MATCH":
			return []Match{{Rule: "Fixture"}}, nil
		case "MAILSTRIX-CLAMD-ERROR":
			return nil, errors.New("injected scanner failure")
		default:
			return nil, nil
		}
	}}
	s := newTestServer(e, "")
	s.cfg.MaxBody = 4096
	s.cfg.ClamdTCPAddr = "127.0.0.1:0"
	s.cfg.ClamdUnixPath = filepath.Join(t.TempDir(), "s")
	c, err := s.StartClamd()
	if err != nil || c == nil {
		t.Fatalf("start: service=%v err=%v", c, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	host, port, err := net.SplitHostPort(c.listeners[0].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "../../contrib/clamd/test_clients.py", "--unix", s.cfg.ClamdUnixPath,
		"--host", host, "--port", port, "--clamdscan", clamdscan, "--scanner-error")
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("real client qualification: %v", err)
	}
}

func FuzzClamdStream(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{255, 255, 255, 255})
	f.Add([]byte{0, 0, 0, 2, 'a', 'b', 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		body, reply := readClamdStream(bytes.NewReader(b), 4096)
		if cap(body) > 4096 || len(reply) > 255 {
			t.Fatal("unbounded stream result")
		}
	})
}
