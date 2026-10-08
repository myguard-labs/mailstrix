package mailstrix

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
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
func startCAPEChain(t *testing.T) (*CAPEService, *http.Client) {
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
	service, err := s.startCAPE(cfg, capeServiceDeps{resolve, buildCAPERuntime, net.Listen})
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
	r, err := http.NewRequest(method, "https://"+service.listener.Addr().String()+path, strings.NewReader(body))
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
// 35 s CAPEService ReadTimeout.
func TestCAPEServiceChainInterruptsStalledBody(t *testing.T) {
	service, client := startCAPEChain(t)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("TLS fixture client transport is %T", client.Transport)
	}
	conn, err := tls.Dial("tcp", service.listener.Addr().String(), transport.TLSClientConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	request := "POST " + cape.JobsPath + " HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer fixture-alpha\r\n" +
		"Content-Type: application/octet-stream\r\nX-Mailstrix-CAPE-Profile: manual\r\nContent-Length: 10\r\n\r\nx"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = conn.SetReadDeadline(start.Add(capeChainIdleBound))
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("stalled ingress not answered within %v: %v", capeChainIdleBound, err)
	}
	if !strings.Contains(status, " 503 ") {
		t.Fatalf("stalled ingress not rejected as unavailable: %q", status)
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Fatalf("answered before the idle window could elapse (%v): the stall was not what ended it", elapsed)
	}
}
