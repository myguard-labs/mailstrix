package mailstrix

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// slowBodyServer returns a server with one admission slot and a short body
// budget (BackendTimeout + icapBodySlack), restoring the slack on cleanup.
func slowBodyServer(t *testing.T, maxBody int64) (*Server, string, time.Duration) {
	t.Helper()
	cfg := &Config{MaxConcurrent: 1, MaxInflight: 1, MaxBody: maxBody, BackendTimeout: 300 * time.Millisecond}
	cfg.sanitize()
	cfg.BackendTimeout = 300 * time.Millisecond
	s := NewServer(cfg, &fakeEngine{count: 1, fp: "fp"})
	old := icapBodySlack
	icapBodySlack = 200 * time.Millisecond
	t.Cleanup(func() { icapBodySlack = old })
	return s, startTestICAPServer(t, s), cfg.BackendTimeout + icapBodySlack
}

func slowHead(host string, preview bool) string {
	resHdr := "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
	p := ""
	if preview {
		p = "Preview: 0\r\n"
	}
	return "RESPMOD icap://" + host + "/scan ICAP/1.0\r\nHost: " + host + "\r\nAllow: 204\r\n" + p +
		fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n\r\n", len(resHdr)) + resHdr
}

// waitClosed reports how long until the server closes conn and what it sent.
func waitClosed(t *testing.T, conn net.Conn) (time.Duration, string) {
	t.Helper()
	t0 := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	b, err := io.ReadAll(conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server never closed the stalled connection (slot held past the body deadline)")
	}
	return time.Since(t0), string(b)
}

func TestICAPTricklingBodyReleasesSlot(t *testing.T) {
	_, addr, budget := slowBodyServer(t, 1<<20)
	a, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	// Head, then a chunk that promises 100 bytes but delivers 3 and stalls.
	_, _ = io.WriteString(a, slowHead(addr, false)+"64\r\nabc")

	took, got := waitClosed(t, a)
	if took > budget+2*time.Second {
		t.Fatalf("closed after %v; want near %v", took, budget)
	}
	if strings.Contains(got, " 204 ") || strings.Contains(got, " 200 ") {
		t.Fatalf("trickling client got a verdict: %q", got)
	}
	// The slot is free: a second client is admitted and scanned.
	resp := doICAP(t, addr, icapRESPMODRequest(addr, "hello", true))
	if !strings.HasPrefix(resp, "ICAP/1.0 204") {
		t.Fatalf("second client not admitted after slot release: %q", resp)
	}
}

func TestICAPStallAfterContinueReleasesSlot(t *testing.T) {
	_, addr, budget := slowBodyServer(t, 1<<20)
	a, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	_, _ = io.WriteString(a, slowHead(addr, true)+"0\r\n\r\n")
	br := bufio.NewReader(a)
	line, _ := br.ReadString('\n')
	if !strings.HasPrefix(line, "ICAP/1.0 100") {
		t.Fatalf("want 100 Continue, got %q", line)
	}
	_, _ = br.ReadString('\n')
	t0 := time.Now()
	_ = a.SetReadDeadline(time.Now().Add(10 * time.Second))
	rest, err := io.ReadAll(br)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("stall after 100 Continue was never cut off")
	}
	if d := time.Since(t0); d > budget+2*time.Second {
		t.Fatalf("closed after %v; want near %v", d, budget)
	}
	if strings.Contains(string(rest), " 204 ") {
		t.Fatalf("stalled client got a clean verdict: %q", rest)
	}
	resp := doICAP(t, addr, icapRESPMODRequest(addr, "hello", true))
	if !strings.HasPrefix(resp, "ICAP/1.0 204") {
		t.Fatalf("slot not released: %q", resp)
	}
}

func TestICAPMaxSizeBodyStillScans(t *testing.T) {
	const max = 1 << 20
	_, addr, _ := slowBodyServer(t, max)
	resp := doICAP(t, addr, icapRESPMODRequest(addr, strings.Repeat("a", max), true))
	if !strings.HasPrefix(resp, "ICAP/1.0 204") {
		t.Fatalf("max-size body at normal speed: %q", resp[:min(len(resp), 80)])
	}
}

// A saturation 503 sent before the preview is read must reach the client even
// when preview bytes are still unread (no RST discarding the reply).
func TestICAP503SurvivesUnreadPreview(t *testing.T) {
	s, addr, _ := slowBodyServer(t, 1<<20)
	s.admit <- struct{}{} // saturate
	defer func() { <-s.admit }()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	big := strings.Repeat("x", 200<<10)
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(big), big)
	go func() { _, _ = io.WriteString(c, slowHead(addr, false)+body) }()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil || !strings.HasPrefix(string(b), "ICAP/1.0 503") {
		t.Fatalf("503 lost: err=%v got=%q", err, b)
	}
}
