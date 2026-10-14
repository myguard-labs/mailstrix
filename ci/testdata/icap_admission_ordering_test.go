package mailstrix

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const admissionFixtureTimeout = 20 * time.Second

type admissionFixtureEngine struct {
	ScanEngine
	calls   atomic.Int32
	entered chan struct{}
	release <-chan struct{}
	maxBody int
}

func (e *admissionFixtureEngine) Fingerprint() string { return "admission-fixture" }

func (e *admissionFixtureEngine) Scan(body []byte, _ ScanMeta) ([]Match, error) {
	call := e.calls.Add(1)
	if call == 1 {
		close(e.entered)
	}
	<-e.release
	if len(body) != e.maxBody {
		return nil, fmt.Errorf("scan %d received %d bytes, want MaxBody=%d", call, len(body), e.maxBody)
	}
	if want := body[0]; !bytes.Equal(body, bytes.Repeat([]byte{want}, e.maxBody)) {
		return nil, fmt.Errorf("scan %d did not receive the complete uniform body marker %q", call, want)
	}
	return nil, nil
}

type admissionFixtureRequest struct {
	continued chan struct{}
	sent      chan struct{}
	response  chan string
	err       chan error
	done      chan struct{}
}

func startAdmissionFixtureRequest(conn net.Conn, body []byte) *admissionFixtureRequest {
	r := &admissionFixtureRequest{
		continued: make(chan struct{}),
		sent:      make(chan struct{}),
		response:  make(chan string, 1),
		err:       make(chan error, 1),
		done:      make(chan struct{}),
	}
	go func() {
		defer close(r.done)
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(admissionFixtureTimeout)); err != nil {
			r.err <- err
			return
		}
		br := bufio.NewReader(conn)
		resHeader := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
		head := "RESPMOD icap://fixture/scan ICAP/1.0\r\n" +
			"Host: fixture\r\nAllow: 204\r\nPreview: 0\r\n" +
			fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n\r\n", len(resHeader)) +
			resHeader + "0\r\n\r\n"
		if _, err := io.WriteString(conn, head); err != nil {
			r.err <- fmt.Errorf("write zero preview: %w", err)
			return
		}
		status, err := br.ReadString('\n')
		if err != nil {
			r.err <- fmt.Errorf("read 100 Continue: %w", err)
			return
		}
		blank, err := br.ReadString('\n')
		if err != nil {
			r.err <- fmt.Errorf("read 100 Continue terminator: %w", err)
			return
		}
		if status != "ICAP/1.0 100 Continue\r\n" || blank != "\r\n" {
			r.err <- fmt.Errorf("zero preview response = %q %q, want 100 Continue", status, blank)
			return
		}
		close(r.continued)
		continuation := fmt.Sprintf("%x\r\n", len(body)) + string(body) + "\r\n0\r\n\r\n"
		if _, err := io.WriteString(conn, continuation); err != nil {
			r.err <- fmt.Errorf("write full continuation: %w", err)
			return
		}
		close(r.sent)
		response, err := readAdmissionFixtureResponse(br)
		if err != nil {
			r.err <- err
			return
		}
		r.response <- response
	}()
	return r
}

func readAdmissionFixtureResponse(br *bufio.Reader) (string, error) {
	var response strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read ICAP response: %w", err)
		}
		response.WriteString(line)
		if line == "\r\n" {
			return response.String(), nil
		}
	}
}

func awaitAdmissionFixtureSignal(t *testing.T, name string, signal <-chan struct{}, errs <-chan error) {
	t.Helper()
	select {
	case <-signal:
	case err := <-errs:
		t.Fatalf("%s: %v", name, err)
	case <-time.After(admissionFixtureTimeout):
		t.Fatalf("%s did not complete while admission was saturated", name)
	}
}

func awaitAdmissionFixtureResponse(t *testing.T, name string, request *admissionFixtureRequest) string {
	t.Helper()
	select {
	case response := <-request.response:
		return response
	case err := <-request.err:
		t.Fatalf("%s: %v", name, err)
	case <-time.After(admissionFixtureTimeout):
		t.Fatalf("%s response did not complete", name)
	}
	return ""
}

func awaitAdmissionFixtureDone(t *testing.T, name string, request *admissionFixtureRequest) {
	t.Helper()
	select {
	case <-request.done:
	case <-time.After(admissionFixtureTimeout):
		t.Errorf("%s client goroutine did not stop", name)
	}
}

func waitAdmissionFixtureServer(wg *sync.WaitGroup, guard <-chan time.Time) (<-chan struct{}, bool) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()
	select {
	case <-done:
		return done, true
	case <-guard:
		return done, false
	}
}

func awaitAdmissionFixtureServer(t *testing.T, name string, wg *sync.WaitGroup, waiters *[]<-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(admissionFixtureTimeout)
	defer timer.Stop()
	done, stopped := waitAdmissionFixtureServer(wg, timer.C)
	*waiters = append(*waiters, done)
	if !stopped {
		t.Fatalf("%s server goroutines did not stop", name)
	}
}

func joinAdmissionFixtureServerWaiters(t *testing.T, waiters []<-chan struct{}) {
	t.Helper()
	for i, done := range waiters {
		select {
		case <-done:
		case <-time.After(admissionFixtureTimeout):
			t.Errorf("server waiter goroutine %d did not stop", i+1)
		}
	}
}

func waitForAdmissionFixtureWaiters(t *testing.T, want int) {
	t.Helper()
	const frame = "github.com/myguard-labs/mailstrix/internal/mailstrix.(*Server).acquireOn"
	stack := make([]byte, 1<<20)
	deadline := time.Now().Add(admissionFixtureTimeout)
	for time.Now().Before(deadline) {
		n := runtime.Stack(stack, true)
		if bytes.Count(stack[:n], []byte(frame)) >= want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("observed-before-admission assertion: %d requests sent full bodies, but fewer than %d handlers reached acquireOn", want, want)
}

func TestICAPAdmissionBuffersBeforeGate(t *testing.T) {
	const (
		maxInflight = 1
		maxConns    = 3
		maxBody     = 64 << 10
	)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
	engine := &admissionFixtureEngine{
		entered: make(chan struct{}),
		release: release,
		maxBody: maxBody,
	}
	s := NewServer(&Config{
		MaxConcurrent:  1,
		MaxInflight:    maxInflight,
		ICAPMaxConns:   maxConns,
		MaxBody:        maxBody,
		BackendTimeout: admissionFixtureTimeout,
		ScanTimeout:    admissionFixtureTimeout,
	}, engine)

	clients := make([]net.Conn, 0, maxConns+1)
	requests := make([]*admissionFixtureRequest, 0, maxConns)
	t.Cleanup(func() {
		releaseGate()
		for _, client := range clients {
			_ = client.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), admissionFixtureTimeout)
		defer cancel()
		s.ShutdownICAP(ctx)
		if err := ctx.Err(); err != nil {
			t.Errorf("cleanup ICAP shutdown: %v", err)
		}
		for i, request := range requests {
			awaitAdmissionFixtureDone(t, fmt.Sprintf("cleanup connection %d", i+1), request)
		}
	})
	for range maxConns {
		client, server := net.Pipe()
		clients = append(clients, client)
		s.acceptICAP(server)
	}
	if got := len(s.icapConns); got != maxConns {
		t.Fatalf("live ICAP connections = %d, want ICAPMaxConns=%d", got, maxConns)
	}

	refusedClient, refusedServer := net.Pipe()
	clients = append(clients, refusedClient)
	s.acceptICAP(refusedServer)
	if err := refusedClient.SetReadDeadline(time.Now().Add(admissionFixtureTimeout)); err != nil {
		t.Fatal(err)
	}
	refused, err := readAdmissionFixtureResponse(bufio.NewReader(refusedClient))
	_ = refusedClient.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(refused, "ICAP/1.0 503 Service Unavailable\r\n") {
		t.Fatalf("connection %d response = %q, want ICAPMaxConns refusal", maxConns+1, refused)
	}

	firstBody := bytes.Repeat([]byte{'A'}, maxBody)
	first := startAdmissionFixtureRequest(clients[0], firstBody)
	requests = append(requests, first)
	awaitAdmissionFixtureSignal(t, "first MaxBody continuation", first.sent, first.err)
	awaitAdmissionFixtureSignal(t, "first scanner entry", engine.entered, first.err)
	if got := engine.calls.Load(); got != maxInflight {
		t.Fatalf("scanner entries after saturating admission = %d, want MaxInflight=%d", got, maxInflight)
	}

	for i := 1; i < maxConns; i++ {
		body := bytes.Repeat([]byte{byte('A' + i)}, maxBody)
		request := startAdmissionFixtureRequest(clients[i], body)
		requests = append(requests, request)
		awaitAdmissionFixtureSignal(t, fmt.Sprintf("observed-before-admission connection %d 100 Continue", i+1), request.continued, request.err)
		awaitAdmissionFixtureSignal(t, fmt.Sprintf("observed-before-admission body %d", i+1), request.sent, request.err)
	}
	waitForAdmissionFixtureWaiters(t, maxConns-maxInflight)
	if got := engine.calls.Load(); got != maxInflight {
		t.Fatalf("scanner entries before causal release = %d, want exactly %d", got, maxInflight)
	}
	logicalRetained := int64(maxConns * maxBody)
	if want := int64(s.cfg.ICAPMaxConns) * s.cfg.MaxBody; logicalRetained != want {
		t.Fatalf("logical retained bytes = %d, want ICAPMaxConns*MaxBody=%d", logicalRetained, want)
	}
	t.Logf("observed %d logical bytes before admission: first admitted body plus %d waiting bodies, each MaxBody=%d", logicalRetained, maxConns-maxInflight, maxBody)
	for i, request := range requests {
		select {
		case response := <-request.response:
			t.Fatalf("connection %d returned before causal release: %q", i+1, response)
		case err := <-request.err:
			t.Fatalf("connection %d failed before causal release: %v", i+1, err)
		default:
		}
	}

	releaseGate()
	for i, request := range requests {
		response := awaitAdmissionFixtureResponse(t, fmt.Sprintf("connection %d", i+1), request)
		if !strings.HasPrefix(response, "ICAP/1.0 204 No Modification\r\n") {
			t.Errorf("connection %d final response = %q, want 204", i+1, response)
		}
		awaitAdmissionFixtureDone(t, fmt.Sprintf("connection %d", i+1), request)
	}
	if got := engine.calls.Load(); got != maxConns {
		t.Fatalf("full bodies scanned = %d, want ICAPMaxConns=%d", got, maxConns)
	}
	ctx, cancel := context.WithTimeout(context.Background(), admissionFixtureTimeout)
	defer cancel()
	s.ShutdownICAP(ctx)
	if err := ctx.Err(); err != nil {
		t.Fatalf("ICAP shutdown: %v", err)
	}
	if got := len(s.icapConns); got != 0 {
		t.Fatalf("live ICAP connections after shutdown = %d, want 0", got)
	}
	if got := len(s.admit); got != 0 {
		t.Fatalf("admission slots after shutdown = %d, want 0", got)
	}
}

func writeAdmissionFixtureHead(conn net.Conn, maxBody int, preview bool) error {
	previewHeader := ""
	bodyPrefix := ""
	if preview {
		previewHeader = "Preview: 0\r\n"
		bodyPrefix = "0\r\n\r\n"
	}
	resHeader := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", maxBody)
	_, err := io.WriteString(conn, "RESPMOD icap://fixture/scan ICAP/1.0\r\n"+
		"Host: fixture\r\nAllow: 204\r\n"+previewHeader+
		fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n\r\n", len(resHeader))+
		resHeader+bodyPrefix)
	return err
}

func TestICAPAdmissionPreReadFailureCleanup(t *testing.T) {
	const maxBody = 64
	cases := []struct {
		name       string
		wantStatus string
		drive      func(net.Conn, *bufio.Reader) error
	}{
		{
			name:       "one byte over MaxBody",
			wantStatus: "ICAP/1.0 413 Request Entity Too Large\r\n",
			drive: func(conn net.Conn, _ *bufio.Reader) error {
				if err := writeAdmissionFixtureHead(conn, maxBody, false); err != nil {
					return err
				}
				_, err := fmt.Fprintf(conn, "%x\r\n", maxBody+1)
				return err
			},
		},
		{
			name:       "malformed continuation",
			wantStatus: "ICAP/1.0 400 Bad Request\r\n",
			drive: func(conn net.Conn, br *bufio.Reader) error {
				if err := writeAdmissionFixtureHead(conn, maxBody, true); err != nil {
					return err
				}
				continued, err := readAdmissionFixtureResponse(br)
				if err != nil {
					return err
				}
				if continued != "ICAP/1.0 100 Continue\r\n\r\n" {
					return fmt.Errorf("continuation response = %q", continued)
				}
				_, err = io.WriteString(conn, "not-hex\r\n")
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			engine := &admissionFixtureEngine{entered: make(chan struct{}), release: release, maxBody: maxBody}
			s := NewServer(&Config{MaxConcurrent: 1, MaxInflight: 1, ICAPMaxConns: 1, MaxBody: maxBody}, engine)
			var cleanupOnce sync.Once
			var clients []net.Conn
			var reuseWriterDone chan struct{}
			var serverWaiters []<-chan struct{}
			cleanup := func() {
				cleanupOnce.Do(func() {
					close(release)
					for _, conn := range clients {
						_ = conn.Close()
					}
					ctx, cancel := context.WithTimeout(context.Background(), admissionFixtureTimeout)
					defer cancel()
					s.ShutdownICAP(ctx)
					if err := ctx.Err(); err != nil {
						t.Errorf("cleanup ICAP shutdown: %v", err)
					}
					if reuseWriterDone != nil {
						select {
						case <-reuseWriterDone:
						case <-time.After(admissionFixtureTimeout):
							t.Errorf("reusable-slot writer goroutine did not stop")
						}
					}
					joinAdmissionFixtureServerWaiters(t, serverWaiters)
				})
			}
			t.Cleanup(cleanup)
			client, server := net.Pipe()
			clients = append(clients, client)
			s.acceptICAP(server)
			if err := client.SetDeadline(time.Now().Add(admissionFixtureTimeout)); err != nil {
				t.Fatal(err)
			}
			br := bufio.NewReader(client)
			if err := tc.drive(client, br); err != nil {
				t.Fatal(err)
			}
			response, err := readAdmissionFixtureResponse(br)
			_ = client.Close()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(response, tc.wantStatus) {
				t.Fatalf("response = %q, want prefix %q", response, tc.wantStatus)
			}
			awaitAdmissionFixtureServer(t, "rejected-body", &s.icapWg, &serverWaiters)
			if got := engine.calls.Load(); got != 0 {
				t.Fatalf("scanner calls after pre-admission rejection = %d, want 0", got)
			}
			if got := len(s.icapConns); got != 0 {
				t.Fatalf("live connections after rejected body = %d, want 0", got)
			}

			reuseClient, reuseServer := net.Pipe()
			clients = append(clients, reuseClient)
			s.acceptICAP(reuseServer)
			if err := reuseClient.SetDeadline(time.Now().Add(admissionFixtureTimeout)); err != nil {
				t.Fatal(err)
			}
			writeDone := make(chan error, 1)
			reuseWriterDone = make(chan struct{})
			go func() {
				defer close(reuseWriterDone)
				_, err := io.WriteString(reuseClient, "OPTIONS icap://fixture/scan ICAP/1.0\r\nHost: fixture\r\n\r\n")
				writeDone <- err
			}()
			reuseResponse, err := readAdmissionFixtureResponse(bufio.NewReader(reuseClient))
			if err != nil {
				t.Fatal(err)
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			select {
			case <-reuseWriterDone:
			case <-time.After(admissionFixtureTimeout):
				t.Fatal("reusable-slot writer goroutine did not stop")
			}
			_ = reuseClient.Close()
			if !strings.HasPrefix(reuseResponse, "ICAP/1.0 200 OK\r\n") {
				t.Fatalf("connection slot was not reusable: %q", reuseResponse)
			}
			awaitAdmissionFixtureServer(t, "reusable-slot", &s.icapWg, &serverWaiters)
			cleanup()
			if got := len(s.icapConns); got != 0 {
				t.Fatalf("live connections after cleanup = %d, want 0", got)
			}
		})
	}

	t.Run("disconnect during exact-limit body", func(t *testing.T) {
		release := make(chan struct{})
		engine := &admissionFixtureEngine{entered: make(chan struct{}), release: release, maxBody: maxBody}
		s := NewServer(&Config{MaxConcurrent: 1, MaxInflight: 1, ICAPMaxConns: 1, MaxBody: maxBody}, engine)
		var cleanupOnce sync.Once
		var serverWaiters []<-chan struct{}
		client, server := net.Pipe()
		cleanup := func() {
			cleanupOnce.Do(func() {
				close(release)
				_ = client.Close()
				ctx, cancel := context.WithTimeout(context.Background(), admissionFixtureTimeout)
				defer cancel()
				s.ShutdownICAP(ctx)
				if err := ctx.Err(); err != nil {
					t.Errorf("cleanup ICAP shutdown: %v", err)
				}
				joinAdmissionFixtureServerWaiters(t, serverWaiters)
			})
		}
		t.Cleanup(cleanup)
		s.acceptICAP(server)
		if err := client.SetDeadline(time.Now().Add(admissionFixtureTimeout)); err != nil {
			t.Fatal(err)
		}
		if err := writeAdmissionFixtureHead(client, maxBody, false); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(client, "%x\r\npartial", maxBody); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		awaitAdmissionFixtureServer(t, "disconnected-body", &s.icapWg, &serverWaiters)
		if got := engine.calls.Load(); got != 0 {
			t.Fatalf("scanner calls after disconnected body = %d, want 0", got)
		}
		if got := len(s.icapConns); got != 0 {
			t.Fatalf("live connections after disconnected body = %d, want 0", got)
		}
		cleanup()
	})

	t.Run("server wait guard", func(t *testing.T) {
		var blocked sync.WaitGroup
		blocked.Add(1)
		var releaseBlocked sync.Once
		release := func() { releaseBlocked.Do(blocked.Done) }
		var blockedWaiter <-chan struct{}
		t.Cleanup(func() {
			release()
			if blockedWaiter != nil {
				joinAdmissionFixtureServerWaiters(t, []<-chan struct{}{blockedWaiter})
			}
		})
		expired := make(chan time.Time)
		close(expired)
		done, stopped := waitAdmissionFixtureServer(&blocked, expired)
		blockedWaiter = done
		if stopped {
			t.Fatal("server wait completed while its wait group was blocked")
		}
		release()
		joinAdmissionFixtureServerWaiters(t, []<-chan struct{}{done})

		var complete sync.WaitGroup
		timer := time.NewTimer(admissionFixtureTimeout)
		defer timer.Stop()
		done, stopped = waitAdmissionFixtureServer(&complete, timer.C)
		if !stopped {
			t.Fatal("server wait guard fired for a completed wait group")
		}
		joinAdmissionFixtureServerWaiters(t, []<-chan struct{}{done})
	})
}
