package yarad

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startTestICAPServer starts a raw TCP ICAP listener backed by s.
// Returns the address string (e.g. "127.0.0.1:54321").
func startTestICAPServer(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveICAPConn(c)
		}
	}()
	return ln.Addr().String()
}

// doICAP sends a raw ICAP request and reads the full response (until the server
// closes the connection after CloseWrite).
func doICAP(t *testing.T, addr, req string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	// Signal EOF on write side so the server's next read gets EOF -> exits loop -> closes conn.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	var sb strings.Builder
	_, _ = io.Copy(&sb, conn)
	return sb.String()
}

// icapRESPMODRequest builds a minimal ICAP RESPMOD request with a chunked body.
func icapRESPMODRequest(host, body string, allow204 bool) string {
	chunkHex := fmt.Sprintf("%x", len(body))
	resHdr := "HTTP/1.1 200 OK\r\nContent-Length: " + fmt.Sprintf("%d", len(body)) + "\r\n\r\n"
	allowHdr := ""
	if allow204 {
		allowHdr = "Allow: 204\r\n"
	}
	return "RESPMOD icap://" + host + "/scan ICAP/1.0\r\n" +
		"Host: " + host + "\r\n" +
		allowHdr +
		fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr)) +
		"\r\n" +
		resHdr +
		chunkHex + "\r\n" +
		body + "\r\n" +
		"0\r\n\r\n"
}

// icapREQMODRequest builds a minimal ICAP REQMOD request with a chunked body.
func icapREQMODRequest(host, body string, allow204 bool) string {
	chunkHex := fmt.Sprintf("%x", len(body))
	reqHdr := "POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: " + fmt.Sprintf("%d", len(body)) + "\r\n\r\n"
	allowHdr := ""
	if allow204 {
		allowHdr = "Allow: 204\r\n"
	}
	return "REQMOD icap://" + host + "/scan ICAP/1.0\r\n" +
		"Host: " + host + "\r\n" +
		allowHdr +
		fmt.Sprintf("Encapsulated: req-hdr=0, req-body=%d\r\n", len(reqHdr)) +
		"\r\n" +
		reqHdr +
		chunkHex + "\r\n" +
		body + "\r\n" +
		"0\r\n\r\n"
}

func TestICAPOptions(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "testfp"}, "")
	addr := startTestICAPServer(t, s)

	req := "OPTIONS icap://" + addr + "/scan ICAP/1.0\r\n" +
		"Host: " + addr + "\r\n" +
		"Encapsulated: null-body=0\r\n" +
		"\r\n"
	resp := doICAP(t, addr, req)

	if !strings.HasPrefix(resp, "ICAP/1.0 200 OK") {
		t.Errorf("OPTIONS: want 200 OK, got:\n%s", resp)
	}
	if !strings.Contains(resp, "Methods: REQMOD, RESPMOD") {
		t.Errorf("OPTIONS: missing Methods header:\n%s", resp)
	}
	if !strings.Contains(resp, "Allow: 204") {
		t.Errorf("OPTIONS: missing Allow: 204:\n%s", resp)
	}
	if !strings.Contains(resp, `ISTag: "testfp"`) {
		t.Errorf("OPTIONS: wrong ISTag, want testfp:\n%s", resp)
	}
}

func TestICAPISTagTracksFingerprint(t *testing.T) {
	eng := &fakeEngine{count: 1, fp: "fp1"}
	s := newTestServer(eng, "")
	addr := startTestICAPServer(t, s)

	optReq := "OPTIONS icap://" + addr + "/scan ICAP/1.0\r\nHost: " + addr + "\r\nEncapsulated: null-body=0\r\n\r\n"
	resp1 := doICAP(t, addr, optReq)
	if !strings.Contains(resp1, `"fp1"`) {
		t.Errorf("ISTag should contain fp1, got:\n%s", resp1)
	}
}

func TestICAPRESPMODClean204(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)

	req := icapRESPMODRequest(addr, "hello world", true)
	resp := doICAP(t, addr, req)

	if !strings.HasPrefix(resp, "ICAP/1.0 204 No Modification") {
		t.Errorf("clean + Allow:204 should give 204, got:\n%s", resp)
	}
}

func TestICAPRESPMODInfected200(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp", matches: []Match{{Rule: "MALWARE_TEST"}}}, "")
	addr := startTestICAPServer(t, s)

	req := icapRESPMODRequest(addr, "malware payload", true)
	resp := doICAP(t, addr, req)

	if !strings.HasPrefix(resp, "ICAP/1.0 200 OK") {
		t.Errorf("infected should give 200, got:\n%s", resp)
	}
	if !strings.Contains(resp, "X-Infection-Found") {
		t.Errorf("infected: missing X-Infection-Found:\n%s", resp)
	}
	if !strings.Contains(resp, "403") {
		t.Errorf("infected: missing 403 in replacement body:\n%s", resp)
	}
	if !strings.Contains(resp, "MALWARE_TEST") {
		t.Errorf("infected: threat name missing:\n%s", resp)
	}
}

func TestICAPREQMODClean(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)

	req := icapREQMODRequest(addr, "safe request body", true)
	resp := doICAP(t, addr, req)

	if !strings.HasPrefix(resp, "ICAP/1.0 204 No Modification") {
		t.Errorf("REQMOD clean should give 204, got:\n%s", resp)
	}
}

func TestICAPPreviewHandling(t *testing.T) {
	// Preview: 0 — client sends body with ieof chunk extension.
	// "3\r\n" + "abc" + "; ieof\r\n" is NOT standard; instead ieof appears on the
	// size line: "3 ; ieof\r\n". We also test plain termination.
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)

	body := "abc"
	resHdr := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n"
	// ieof on the chunk size line
	req := "RESPMOD icap://" + addr + "/scan ICAP/1.0\r\n" +
		"Host: " + addr + "\r\n" +
		"Allow: 204\r\n" +
		fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr)) +
		"\r\n" +
		resHdr +
		fmt.Sprintf("%x ; ieof\r\n", len(body)) +
		body + "\r\n" +
		"0\r\n\r\n"

	resp := doICAP(t, addr, req)
	if !strings.HasPrefix(resp, "ICAP/1.0 204") {
		t.Errorf("ieof chunk: want 204, got:\n%s", resp)
	}
}

func TestICAPOversizeBody(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	s.cfg.MaxBody = 10 // very small limit
	addr := startTestICAPServer(t, s)

	bigBody := strings.Repeat("X", 100)
	req := icapRESPMODRequest(addr, bigBody, true)
	resp := doICAP(t, addr, req)

	if !strings.HasPrefix(resp, "ICAP/1.0 413") {
		t.Errorf("oversize body: want 413, got:\n%s", resp)
	}
}

func TestICAPChunkedParsing(t *testing.T) {
	// Multi-chunk body: "hello" in two chunks.
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)

	resHdr := "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"
	req := "RESPMOD icap://" + addr + "/scan ICAP/1.0\r\n" +
		"Host: " + addr + "\r\n" +
		"Allow: 204\r\n" +
		fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr)) +
		"\r\n" +
		resHdr +
		"5\r\nhello\r\n" + // chunk 1
		"5\r\nworld\r\n" + // chunk 2
		"0\r\n\r\n" // terminal

	resp := doICAP(t, addr, req)
	if !strings.HasPrefix(resp, "ICAP/1.0 204") {
		t.Errorf("multi-chunk: want 204, got:\n%s", resp)
	}
}

func TestICAPScanErrorFailsOpen(t *testing.T) {
	eng := &fakeEngine{count: 1, err: fmt.Errorf("scan engine exploded")}
	s := newTestServer(eng, "")
	addr := startTestICAPServer(t, s)

	req := icapRESPMODRequest(addr, "some content", true)
	resp := doICAP(t, addr, req)

	// Fail-open: engine error -> treat as clean -> 204
	if !strings.HasPrefix(resp, "ICAP/1.0 204") {
		t.Errorf("scan error should fail-open to 204, got:\n%s", resp)
	}
}

func TestICAPNullBody(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	addr := startTestICAPServer(t, s)

	req := "RESPMOD icap://" + addr + "/scan ICAP/1.0\r\n" +
		"Host: " + addr + "\r\n" +
		"Allow: 204\r\n" +
		"Encapsulated: null-body=0\r\n" +
		"\r\n"
	resp := doICAP(t, addr, req)
	if !strings.HasPrefix(resp, "ICAP/1.0 204") {
		t.Errorf("null-body: want 204, got:\n%s", resp)
	}
}

// TestICAPMetricsCounters verifies that the ICAP metric counters increment.
func TestICAPMetricsCounters(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp", matches: []Match{{Rule: "BAD"}}}, "")
	addr := startTestICAPServer(t, s)

	// OPTIONS
	optReq := "OPTIONS icap://" + addr + "/scan ICAP/1.0\r\nHost: " + addr + "\r\nEncapsulated: null-body=0\r\n\r\n"
	doICAP(t, addr, optReq)
	if s.metrics.icapOptions.Load() != 1 {
		t.Errorf("icapOptions: want 1, got %d", s.metrics.icapOptions.Load())
	}

	// RESPMOD infected
	doICAP(t, addr, icapRESPMODRequest(addr, "malware", true))
	if s.metrics.icapRequests.Load() != 1 {
		t.Errorf("icapRequests: want 1, got %d", s.metrics.icapRequests.Load())
	}
	if s.metrics.icapInfected.Load() != 1 {
		t.Errorf("icapInfected: want 1, got %d", s.metrics.icapInfected.Load())
	}
}

// Ensure parseICAPEncapsulated handles common forms.
func TestParseICAPEncapsulated(t *testing.T) {
	cases := []struct {
		in   string
		want []icapSection
	}{
		{"null-body=0", []icapSection{{"null-body", 0}}},
		{"req-hdr=0, req-body=100", []icapSection{{"req-hdr", 0}, {"req-body", 100}}},
		{"res-hdr=0, res-body=412", []icapSection{{"res-hdr", 0}, {"res-body", 412}}},
		{"req-hdr=0, res-hdr=100, res-body=512", []icapSection{{"req-hdr", 0}, {"res-hdr", 100}, {"res-body", 512}}},
	}
	for _, tc := range cases {
		got := parseICAPEncapsulated(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("parseICAPEncapsulated(%q): got %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseICAPEncapsulated(%q)[%d]: got %v, want %v", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// Ensure readICAPChunkedBody works correctly, including ieof detection.
func TestReadICAPChunkedBody(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		want     string
		wantIEOF bool
		wantErr  bool
	}{
		{
			name:     "simple no-ieof",
			input:    "5\r\nhello\r\n0\r\n\r\n",
			want:     "hello",
			wantIEOF: false,
		},
		{
			name:     "multi-chunk no-ieof",
			input:    "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n",
			want:     "helloworld",
			wantIEOF: false,
		},
		{
			name:     "ieof on data chunk size line",
			input:    "5 ; ieof\r\nhello\r\n0\r\n\r\n",
			want:     "hello",
			wantIEOF: false, // ieof on a data chunk, not the terminal 0-chunk
		},
		{
			name:     "ieof on terminal zero-chunk",
			input:    "5\r\nhello\r\n0 ; ieof\r\n\r\n",
			want:     "hello",
			wantIEOF: true,
		},
		{
			name:     "zero-byte preview with ieof — body is complete",
			input:    "0 ; ieof\r\n\r\n",
			want:     "",
			wantIEOF: true,
		},
		{
			name:     "zero-byte preview without ieof — continuation follows",
			input:    "0\r\n\r\n",
			want:     "",
			wantIEOF: false,
		},
		{
			name:     "empty body plain",
			input:    "0\r\n\r\n",
			want:     "",
			wantIEOF: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tc.input))
			got, gotIEOF, err := readICAPChunkedBody(br, 1024)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if string(got) != tc.want {
				t.Errorf("body got %q, want %q", got, tc.want)
			}
			if gotIEOF != tc.wantIEOF {
				t.Errorf("ieof got %v, want %v", gotIEOF, tc.wantIEOF)
			}
		})
	}
}

// TestICAPPreviewContinue verifies RFC 3507 §4.5 100-Continue handling:
// when a client sends Preview: 0 and a 0-byte preview terminating with plain
// "0\r\n\r\n" (no ieof), the server MUST write "100 Continue" and then read
// the continuation body before scanning. Failure to do so is an AV false-negative.
func TestICAPPreviewContinue(t *testing.T) {
	// Engine returns a match so we can verify the REAL body was scanned.
	s := newTestServer(&fakeEngine{count: 1, fp: "fp", matches: []Match{{Rule: "MALWARE_CONT"}}}, "")

	// Use a raw TCP listener to drive the full interactive exchange manually:
	// 1. Send request headers + 0-byte preview (no ieof).
	// 2. Read server's "100 Continue".
	// 3. Send full body as continuation chunked stream.
	// 4. Read and validate the final ICAP response.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		s.serveICAPConn(c)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	resHdr := "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n"
	// Step 1: send headers + 0-byte preview (terminal chunk has NO ieof).
	reqHdr := "RESPMOD icap://" + ln.Addr().String() + "/scan ICAP/1.0\r\n" +
		"Host: " + ln.Addr().String() + "\r\n" +
		"Allow: 204\r\n" +
		"Preview: 0\r\n" +
		fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr)) +
		"\r\n" +
		resHdr +
		"0\r\n\r\n" // 0-byte preview, NO ieof → server must 100-Continue
	if _, werr := io.WriteString(conn, reqHdr); werr != nil {
		t.Fatal(werr)
	}

	// Step 2: read the "100 Continue" response.
	br := bufio.NewReader(conn)
	continueLine, rerr := br.ReadString('\n')
	if rerr != nil {
		t.Fatalf("reading 100 Continue: %v", rerr)
	}
	if !strings.HasPrefix(continueLine, "ICAP/1.0 100") {
		t.Fatalf("expected 100 Continue, got: %q", continueLine)
	}
	// Consume the blank line after 100 Continue.
	blankLine, _ := br.ReadString('\n')
	_ = blankLine

	// Step 3: send the real body as continuation chunked stream.
	realBody := "malware"
	continuation := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(realBody), realBody)
	if _, werr := io.WriteString(conn, continuation); werr != nil {
		t.Fatal(werr)
	}

	// Step 4: close write side and read final response.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite() //nolint:errcheck
	}
	var sb strings.Builder
	io.Copy(&sb, br) //nolint:errcheck
	resp := sb.String()

	if !strings.HasPrefix(resp, "ICAP/1.0 200 OK") {
		t.Errorf("infected continuation: want 200 OK, got:\n%s", resp)
	}
	if !strings.Contains(resp, "MALWARE_CONT") {
		t.Errorf("infected continuation: threat name missing:\n%s", resp)
	}
}

// TestICAPPreviewIEOFNoContine verifies that a preview ending with "ieof" does
// NOT trigger a 100-Continue exchange — the body is complete after the preview.
func TestICAPPreviewIEOFNoContinue(t *testing.T) {
	// Engine returns no matches (clean); we verify a 204 comes back with no extra
	// round-trip (no "100 Continue" is written).
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)

	body := "safedata"
	resHdr := "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n"
	// Entire body sent in the preview chunk with ieof on the terminal 0-chunk.
	req := "RESPMOD icap://" + addr + "/scan ICAP/1.0\r\n" +
		"Host: " + addr + "\r\n" +
		"Allow: 204\r\n" +
		"Preview: 8\r\n" +
		fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr)) +
		"\r\n" +
		resHdr +
		fmt.Sprintf("%x\r\n", len(body)) + body + "\r\n" +
		"0 ; ieof\r\n\r\n" // terminal chunk WITH ieof → no continuation

	resp := doICAP(t, addr, req)
	if !strings.HasPrefix(resp, "ICAP/1.0 204") {
		t.Errorf("ieof preview clean: want 204, got:\n%s", resp)
	}
	if strings.Contains(resp, "100") {
		t.Errorf("ieof preview must not produce 100 Continue:\n%s", resp)
	}
}

// TestICAPPreviewContinueOversizeBody verifies that the combined preview +
// continuation body exceeding MaxBody yields 413, not a scan of truncated bytes.
func TestICAPPreviewContinueOversizeBody(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	s.cfg.MaxBody = 20 // tiny limit

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		s.serveICAPConn(c)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	resHdr := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
	// Send 5-byte preview (within limit so far), then continuation of 100 bytes.
	previewBody := "hello"
	reqHdr := "RESPMOD icap://" + ln.Addr().String() + "/scan ICAP/1.0\r\n" +
		"Host: " + ln.Addr().String() + "\r\n" +
		"Allow: 204\r\n" +
		"Preview: 5\r\n" +
		fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr)) +
		"\r\n" +
		resHdr +
		fmt.Sprintf("%x\r\n", len(previewBody)) + previewBody + "\r\n" +
		"0\r\n\r\n" // NO ieof → server will 100-Continue
	io.WriteString(conn, reqHdr) //nolint:errcheck

	// Read 100 Continue.
	br := bufio.NewReader(conn)
	for {
		line, lerr := br.ReadString('\n')
		if lerr != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	// Send continuation that pushes combined total over MaxBody=20.
	bigBody := strings.Repeat("X", 100)
	continuation := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(bigBody), bigBody)
	io.WriteString(conn, continuation) //nolint:errcheck

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite() //nolint:errcheck
	}
	var sb strings.Builder
	io.Copy(&sb, br) //nolint:errcheck
	resp := sb.String()

	if !strings.HasPrefix(resp, "ICAP/1.0 413") {
		t.Errorf("oversize combined body: want 413, got:\n%s", resp)
	}
}
