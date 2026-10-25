package mailstrix

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/cape"
)

// capeChainIdleBound is the largest acceptable wait for the real cape ingress
// idle watchdog (5 s cap, real clock). The margin over the 5 s cap absorbs
// -race scheduling and CI load while staying far below the CAPEService
// ReadTimeout of 35 s, which is what a disabled watchdog would fall back to.
const capeChainIdleBound = 5*time.Second + 3*time.Second

// closedLoopbackAddr returns a loopback host:port nothing listens on, so the
// real scheduler's submissions fail locally and never reach another service.
func closedLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// startCAPEChain starts the real CAPEService with the real buildCAPERuntime:
// real cape.APIHandler over a real cape.Store (capacity probe replaced by the
// documented test seam), behind the real TLS listener.
func startCAPEChain(t *testing.T, observe ...func(*capeDaemonConfig, *capeRuntime)) (*CAPEService, *http.Client) {
	t.Helper()
	resolve, client := capeTLSFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	restore := cape.SetStoreCapacityForTest()
	t.Cleanup(restore)
	cfg := capeFixtureConfig()
	cfg.Store = cape.StoreConfig{Directory: dir, SubmitPerMinute: 100, TenantSubmitPerMinute: 50, RequestsPerMinute: 1000}
	endpoint := cfg.Endpoints["primary"]
	endpoint.Destination = closedLoopbackAddr(t)
	_, port, _ := net.SplitHostPort(endpoint.Destination)
	endpoint.Origin = "https://cape.invalid:" + port // origin port must match the destination
	cfg.Endpoints["primary"] = endpoint
	s := newTestServer(&fakeEngine{}, "tok")
	build := func(ctx context.Context, c *capeDaemonConfig, resolver capeResolver, scan func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		runtime, err := s.buildCAPERuntime(ctx, c, resolver, scan)
		if err == nil {
			for _, hook := range observe {
				hook(c, runtime)
			}
		}
		return runtime, err
	}
	service, err := s.startCAPE(cfg, capeServiceDeps{resolve, build, net.Listen})
	if err != nil {
		t.Fatalf("composed CAPE chain did not start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return service, client
}

func chainRequest(t *testing.T, client *http.Client, service *CAPEService, method, path, token, body string) (*http.Response, []byte) {
	t.Helper()
	return chainRequestContext(t, context.Background(), client, service, method, path, token, body)
}

func chainRequestContext(t *testing.T, ctx context.Context, client *http.Client, service *CAPEService, method, path, token, body string) (*http.Response, []byte) {
	t.Helper()
	r, err := http.NewRequestWithContext(ctx, method, "https://"+service.listener.Addr().String()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-Mailstrix-CAPE-Profile", "manual")
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

// AUD-07f positive and negative: a well-formed authenticated POST is admitted by
// the real APIHandler into the real Store and is visible through the status
// endpoint to its tenant only; bad credentials are rejected by the real handler.
func TestCAPEServiceChainAdmitsAndRejects(t *testing.T) {
	service, client := startCAPEChain(t)
	resp, body := chainRequest(t, client, service, "POST", cape.JobsPath, "fixture-alpha", "attachment-bytes")
	location := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusAccepted || !strings.HasPrefix(location, cape.JobsPath+"/") {
		t.Fatalf("authenticated POST not admitted: %d %q %s", resp.StatusCode, location, body)
	}
	resp, body = chainRequest(t, client, service, "GET", location, "fixture-alpha", "")
	var view cape.APIJob
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &view) != nil || view.StaticVerdict == "" {
		t.Fatalf("admitted job not visible in the store: %d %s", resp.StatusCode, body)
	}
	if resp, _ = chainRequest(t, client, service, "GET", location, "fixture-beta", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("other tenant saw the job: %d", resp.StatusCode)
	}
	for _, token := range []string{"", "wrong", "fixture-remote"} {
		resp, _ = chainRequest(t, client, service, "POST", cape.JobsPath, token, "attachment-bytes")
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Location") != "" {
			t.Fatalf("token %q not rejected by the real handler: %d", token, resp.StatusCode)
		}
	}
}

// AUD-07f interrupt: headers plus one byte of a longer body, then a stall, is
// answered by the real cape ingress idle watchdog (real clock) long before the
// 35 s CAPEService ReadTimeout. Admission and durable cleanup have separate
// bounds: neither is part of the idle watchdog's read-interruption contract.
type capeChainReadResult struct {
	at  time.Time
	err error
}

type capeChainObservedBody struct {
	io.ReadCloser
	ready       chan time.Time
	interrupted chan capeChainReadResult
	primed      bool
	waiting     bool
}

func (b *capeChainObservedBody) Read(p []byte) (int, error) {
	// The client sends one byte, then stalls. The next Read is the first one
	// that must block; writeIngress has installed its watchdog by this point.
	if b.primed && !b.waiting {
		b.waiting = true
		b.ready <- time.Now()
	}
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.primed = true
	}
	if b.waiting && err != nil {
		// Buffered and nonblocking so a failing test cannot strand the handler.
		select {
		case b.interrupted <- capeChainReadResult{time.Now(), err}:
		default:
		}
	}
	return n, err
}

func TestCAPEServiceChainInterruptsStalledBody(t *testing.T) {
	ready := make(chan time.Time, 1)
	interrupted := make(chan capeChainReadResult, 1)
	done := make(chan struct{})
	var directory string
	service, client := startCAPEChain(t, func(c *capeDaemonConfig, runtime *capeRuntime) {
		directory = c.Store.Directory
		next := runtime.handler
		runtime.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = &capeChainObservedBody{ReadCloser: r.Body, ready: ready, interrupted: interrupted}
			defer close(done)
			next.ServeHTTP(w, r)
		})
	})
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("TLS fixture client transport is %T", client.Transport)
	}
	const setupBound = 10 * time.Second
	setupDeadline := time.Now().Add(setupBound)
	conn, err := tls.DialWithDialer(&net.Dialer{Deadline: setupDeadline}, "tcp", service.listener.Addr().String(), transport.TLSClientConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetWriteDeadline(setupDeadline); err != nil {
		t.Fatal(err)
	}
	request := "POST " + cape.JobsPath + " HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer fixture-alpha\r\n" +
		"Content-Type: application/octet-stream\r\nX-Mailstrix-CAPE-Profile: manual\r\nContent-Length: 10\r\n\r\nx"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	var start time.Time
	select {
	case start = <-ready:
	case <-done:
		select {
		case start = <-ready:
		default:
			t.Fatal("ingress returned before its stalled read began")
		}
	case <-time.After(time.Until(setupDeadline)):
		t.Fatal("ingress did not reach its stalled read within setup bound")
	}
	if start.After(setupDeadline) {
		t.Fatal("ingress reached its stalled read after setup bound")
	}
	var result capeChainReadResult
	select {
	case result = <-interrupted:
	case <-time.After(time.Until(start.Add(capeChainIdleBound))):
		select {
		case result = <-interrupted:
		default:
			t.Fatalf("stalled ingress read not interrupted within %v", capeChainIdleBound)
		}
	}
	var timeout net.Error
	if !errors.As(result.err, &timeout) || !timeout.Timeout() {
		t.Fatalf("stalled read ended without a deadline interrupt: %v", result.err)
	}
	if elapsed := result.at.Sub(start); elapsed < time.Second || elapsed > capeChainIdleBound {
		t.Fatalf("stalled read interruption outside idle window [1s, %v]: %v", capeChainIdleBound, elapsed)
	}
	// Keep the existing ten-second shutdown/cleanup cap independent of the
	// watchdog: the response is published only after SQL and spool cleanup.
	cleanupDeadline := result.at.Add(10 * time.Second)
	if err := conn.SetReadDeadline(cleanupDeadline); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("stalled ingress response not published within cleanup bound: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stalled ingress not rejected as unavailable: %s", resp.Status)
	}
	select {
	case <-done:
	case <-time.After(time.Until(cleanupDeadline)):
		t.Fatal("ingress handler did not finish durable cleanup")
	}
	ctx, cancel := context.WithDeadline(context.Background(), cleanupDeadline)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(directory, "spool"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("stalled ingress retained spool files: %v, %v", entries, err)
	}
	// Open read-only after shutdown: store recovery must not repair the state
	// before we prove the staging row/reservation was durably removed.
	u := url.URL{Scheme: "file", Path: filepath.Join(directory, "store.db"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var jobs int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM jobs").Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("stalled ingress retained durable jobs/reservations: %d, %v", jobs, err)
	}
}

// AUD-07g: through the composed chain, a submission to a refused endpoint ends in
// the scheduler's uncertain-submission state. cape.Client.Submit clears
// NoBytesSent before invoking the transport and sets UnknownDebt
// (internal/cape/client.go:293-294), so every transport failure, refusal
// included, is conservatively uncertain. Store.RecordSubmission therefore takes
// the default branch of applySubmissionOutcome (internal/cape/store_state.go:
// 229-233): State=SubmitUncertain, UnknownDebt, Cleanup
// "remote_delete_failed/unknown", Reason=Transport (outcomeCode, scheduler.go:
// 306 and 388). The scheduler never re-sends an uncertain row (SCHEDULER.md), so
// the state is stable. publicJob (api.go:224-251) exposes State, Reason and
// Cleanup and withholds any result unless State is Completed.
func TestCAPEServiceChainSubmissionFailureTransitionsJob(t *testing.T) {
	service, client := startCAPEChain(t)
	// One end-to-end budget covers both durable admission and the scheduler
	// transition. The shared TLS fixture's two-second transport timeout is not
	// an admission contract and must not preempt this state-transition oracle.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transitionClient := *client
	transitionClient.Timeout = 0
	resp, body := chainRequestContext(t, ctx, &transitionClient, service, "POST", cape.JobsPath, "fixture-alpha", "attachment-bytes")
	location := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusAccepted || !strings.HasPrefix(location, cape.JobsPath+"/") {
		t.Fatalf("authenticated POST not admitted: %d %q %s", resp.StatusCode, location, body)
	}
	var view cape.APIJob
	for {
		if ctx.Err() != nil {
			t.Fatalf("job never reached %s within the end-to-end budget; last state %q: %s", cape.SubmitUncertain, view.State, body)
		}
		resp, body = chainRequestContext(t, ctx, &transitionClient, service, "GET", location, "fixture-alpha", "")
		view = cape.APIJob{}
		if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &view) != nil {
			t.Fatalf("job not readable: %d %s", resp.StatusCode, body)
		}
		if view.State == cape.Completed {
			t.Fatalf("refused submission must never complete: %s", body)
		}
		if view.State == cape.SubmitUncertain {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("job never reached %s after a refused submission; last state %q: %s", cape.SubmitUncertain, view.State, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if view.Reason != cape.Transport {
		t.Fatalf("failure reason not recorded as %s: %s", cape.Transport, body)
	}
	if view.Cleanup != "remote_delete_failed/unknown" {
		t.Fatalf("unknown remote debt not recorded: %s", body)
	}
	if view.Evidence == "clean" || len(view.Signals) != 0 || view.StaticVerdict == "" {
		t.Fatalf("refused submission produced a detonation result or lost the static verdict: %s", body)
	}
	if !view.TerminalAt.IsZero() {
		t.Fatalf("uncertain job must not be terminal: %s", body)
	}
}

// AUD-07e: the production factory wires the cape read-interrupt failure hook to
// /metrics. A ResponseWriter without deadline support (httptest recorder) makes
// the real 5 s ingress watchdog fail to interrupt; the counter must show it.
// A server that never saw a failure renders the series at 0 (negative).
func TestCAPEBuildRuntimeCountsInterruptFailuresOnMetrics(t *testing.T) {
	resolve, _ := capeTLSFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cape.SetStoreCapacityForTest())
	cfg := capeFixtureConfig()
	cfg.Store = cape.StoreConfig{Directory: dir, SubmitPerMinute: 100, TenantSubmitPerMinute: 50, RequestsPerMinute: 1000}
	endpoint := cfg.Endpoints["primary"]
	endpoint.Destination = closedLoopbackAddr(t)
	_, port, _ := net.SplitHostPort(endpoint.Destination)
	endpoint.Origin = "https://cape.invalid:" + port
	cfg.Endpoints["primary"] = endpoint
	s := newTestServer(&fakeEngine{}, "tok")
	metrics := func() string {
		w := httptest.NewRecorder()
		s.serveMetrics(w)
		return w.Body.String()
	}
	const zero = "mailstrix_cape_ingress_interrupt_failures_total 0\n"
	if !strings.Contains(metrics(), zero) {
		t.Fatalf("fresh server lacks zero-valued interrupt failure series")
	}
	rt, err := s.buildCAPERuntime(context.Background(), cfg, resolve, s.capeStaticScan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.close() })
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	r := httptest.NewRequest("POST", cape.JobsPath, pr)
	r.Header.Set("Authorization", "Bearer fixture-alpha")
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-Mailstrix-CAPE-Profile", "manual")
	done := make(chan struct{})
	go func() { rt.handler.ServeHTTP(httptest.NewRecorder(), r); close(done) }()
	select {
	case <-done:
	case <-time.After(capeChainIdleBound):
		t.Fatal("stalled ingress did not end within the idle bound")
	}
	if m := metrics(); !strings.Contains(m, "# TYPE mailstrix_cape_ingress_interrupt_failures_total counter\n") ||
		!strings.Contains(m, "mailstrix_cape_ingress_interrupt_failures_total 1\n") {
		t.Fatalf("interrupt failure not counted on /metrics:\n%s", m)
	}
}
