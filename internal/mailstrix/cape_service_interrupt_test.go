package mailstrix

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// capeInterruptBound is well below both the cape ingress idle cap (5 s) and the
// CAPEService ReadTimeout (35 s), so a read that only ends at ReadTimeout fails.
const capeInterruptBound = 2 * time.Second

type capeInterruptOutcome struct {
	deadlineErr error
	returned    bool
}

// AUD-07c: the cape ingress watchdog interrupts a stalled body through
// http.ResponseController.SetReadDeadline on the writer CAPEService hands to its
// runtime handler. The real CAPEService (TLS listener, accept bound, server
// timeouts, ServeHTTP) must keep passing a writer that reaches the connection
// deadline; a wrapper without Unwrap would silently degrade to the blocking
// Close and the 35 s ReadTimeout. The runtime handler does exactly what the
// cape interrupt does: read, stall, move the read deadline into the past.
func TestCAPEDaemonServiceInterruptsStalledBody(t *testing.T) {
	resolve, client := capeTLSFixture(t)
	s := newTestServer(&fakeEngine{}, "tok")
	outcome := make(chan capeInterruptOutcome, 1)
	build := func(context.Context, *capeDaemonConfig, capeResolver, func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		return &capeRuntime{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			buf := make([]byte, 8)
			if _, err := io.ReadFull(r.Body, buf[:1]); err != nil {
				outcome <- capeInterruptOutcome{deadlineErr: err}
				return
			}
			readDone := make(chan struct{})
			go func() {
				// Only the return matters; the interrupted read error is expected.
				_, _ = r.Body.Read(buf)
				close(readDone)
			}()
			time.Sleep(50 * time.Millisecond) // let the second Read block on the stalled client
			err := rc.SetReadDeadline(time.Now())
			select {
			case <-readDone:
				outcome <- capeInterruptOutcome{deadlineErr: err, returned: true}
			case <-time.After(capeInterruptBound):
				outcome <- capeInterruptOutcome{deadlineErr: err}
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		}), run: func(ctx context.Context) error { <-ctx.Done(); return nil }, close: func() error { return nil }}, nil
	}
	service, err := s.startCAPE(capeFixtureConfig(), capeServiceDeps{resolve, build, net.Listen})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("TLS fixture client transport is %T", client.Transport)
	}
	conn, err := tls.Dial("tcp", service.listener.Addr().String(), transport.TLSClientConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	request := "POST /v1/cape/jobs HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: 10\r\n\r\nx"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	var got capeInterruptOutcome
	select {
	case got = <-outcome:
	case <-time.After(capeInterruptBound + 3*time.Second):
		t.Fatal("CAPEService handler did not finish")
	}
	if got.deadlineErr != nil {
		t.Fatalf("CAPEService writer does not support read deadlines: %v", got.deadlineErr)
	}
	if !got.returned {
		t.Fatalf("stalled CAPE ingress read not interrupted within %v", capeInterruptBound)
	}
	_ = conn.SetReadDeadline(time.Now().Add(capeInterruptBound))
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(status, " 503 ") {
		t.Fatalf("interrupted request not answered: %q %v", status, err)
	}
}
