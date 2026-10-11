package mailstrix

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"os/exec"
	"testing"
)

// Exercise the deadline fixture with a connection whose transport goroutines
// already exist outside synctest. A child confines DefaultTransport replacement
// and any fatal runtime regression to this test, without external feed access.
func TestScanReputationDeadlineForwardingSharedTransport(t *testing.T) {
	const child = "MAILSTRIX_DEADLINE_TRANSPORT_CHILD"
	if os.Getenv(child) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestScanReputationDeadlineForwardingSharedTransport$", "-test.timeout=30m", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("prewarmed transport deadline fixture failed: %v\n%s", err, output)
		}
		return
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	transport := &http.Transport{
		// The local plaintext server supplies the HTTP response; bypass TLS only
		// for this loopback fixture while retaining real Transport goroutines.
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for attempt := 0; attempt < 2; attempt++ {
		reused := false
		req, err := http.NewRequest(http.MethodGet, "https://urlhaus.abuse.ch/downloads/csv_online/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
		}))
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusBadGateway {
			t.Fatalf("prewarm response: status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
		}
		if attempt == 1 && !reused {
			t.Fatal("transport prewarm did not reuse the outside-bubble connection")
		}
	}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = previous }()
	t.Run("deadline", TestScanReputationDeadlineForwarding)
}
