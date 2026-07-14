package mailstrix

import (
	"bufio"
	"context"
	"errors"
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

func TestICAPLogOnlyMatchesAreClean(t *testing.T) {
	for name, meta := range map[string]map[string]string{
		"canary": {"mailstrix_canary": "1"},
		"allow":  {"mailstrix_allow": "1"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestServer(&fakeEngine{count: 1, fp: "fp", matches: []Match{{Rule: "LOG_ONLY", Meta: meta}}}, "")
			addr := startTestICAPServer(t, s)

			req := icapRESPMODRequest(addr, "shadow payload", true)
			resp := doICAP(t, addr, req)
			if !strings.HasPrefix(resp, "ICAP/1.0 204 No Modification") {
				t.Errorf("log-only match should be clean 204, got:\n%s", resp)
			}
			if strings.Contains(resp, "X-Infection-Found") {
				t.Errorf("log-only match must not emit infection headers:\n%s", resp)
			}
		})
	}
}

func TestICAPMixedLogOnlyAndActionableBlocks(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp", matches: []Match{
		{Rule: "LOG_ONLY", Meta: map[string]string{"mailstrix_canary": "1"}},
		{Rule: "REAL_MALWARE"},
	}}, "")
	addr := startTestICAPServer(t, s)

	req := icapRESPMODRequest(addr, "malware payload", true)
	resp := doICAP(t, addr, req)
	if !strings.HasPrefix(resp, "ICAP/1.0 200 OK") {
		t.Errorf("mixed actionable match should block, got:\n%s", resp)
	}
	if strings.Contains(resp, "LOG_ONLY") {
		t.Errorf("replacement should name the actionable threat, not log-only match:\n%s", resp)
	}
	if !strings.Contains(resp, "REAL_MALWARE") {
		t.Errorf("actionable threat missing:\n%s", resp)
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

// TestICAPChunkedBodyMalformedSize guards readICAPChunkedBody against malformed
// chunk-size lines. A negative size ("-1") is the regression that mattered:
// strconv.ParseInt accepts the leading '-', so it slipped past the size==0 and
// >maxBytes guards and reached slices.Grow(out, negative) → panic (remote DoS).
// All of these must return an error, never panic.
func TestICAPChunkedBodyMalformedSize(t *testing.T) {
	const maxBody = 1 << 20
	for _, tc := range []struct{ name, body string }{
		{"negative", "-1\r\ndata\r\n0\r\n\r\n"},
		{"negative-hex", "-ff\r\ndata\r\n0\r\n\r\n"},
		{"not-hex", "zz\r\ndata\r\n0\r\n\r\n"},
		{"empty-size", "\r\ndata\r\n0\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tc.body))
			_, _, err := readICAPChunkedBody(br, maxBody)
			if err == nil {
				t.Fatalf("%s: expected error for malformed chunk size, got nil", tc.name)
			}
		})
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
		{"null-body=0", []icapSection{{"null-body"}}},
		{"req-hdr=0, req-body=100", []icapSection{{"req-hdr"}, {"req-body"}}},
		{"res-hdr=0, res-body=412", []icapSection{{"res-hdr"}, {"res-body"}}},
		{"req-hdr=0, res-hdr=100, res-body=512", []icapSection{{"req-hdr"}, {"res-hdr"}, {"res-body"}}},
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

func TestReadICAPChunkedBodyManyChunks(t *testing.T) {
	var in strings.Builder
	var want strings.Builder
	for i := 0; i < 128; i++ {
		in.WriteString("1\r\nx\r\n")
		want.WriteByte('x')
	}
	in.WriteString("0 ; ieof\r\n\r\n")

	got, gotIEOF, err := readICAPChunkedBody(bufio.NewReader(strings.NewReader(in.String())), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want.String() {
		t.Fatalf("body len=%d want %d", len(got), want.Len())
	}
	if !gotIEOF {
		t.Fatal("terminal ieof not preserved")
	}
}

func BenchmarkReadICAPChunkedBodyManyChunks(b *testing.B) {
	var in strings.Builder
	for i := 0; i < 512; i++ {
		in.WriteString("4\r\nabcd\r\n")
	}
	in.WriteString("0\r\n\r\n")
	payload := in.String()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, _, err := readICAPChunkedBody(bufio.NewReader(strings.NewReader(payload)), 4096)
		if err != nil || len(got) != 2048 {
			b.Fatalf("readICAPChunkedBody len=%d err=%v", len(got), err)
		}
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

// TestReadICAPChunkedBodyHeaderLineBounded ensures a chunk-size line with no
// terminating '\n' cannot grow the read buffer without bound (per-connection
// memory DoS). A multi-megabyte run of hex digits with no newline must be
// rejected promptly, not buffered whole.
func TestReadICAPChunkedBodyHeaderLineBounded(t *testing.T) {
	// 4 MiB of '0' with no '\n' — a legit chunk header is a few bytes.
	junk := strings.Repeat("0", 4<<20)
	_, _, err := readICAPChunkedBody(bufio.NewReader(strings.NewReader(junk)), 1024)
	if err == nil {
		t.Fatal("expected error on oversized chunk-header line, got nil")
	}
	if !errors.Is(err, errICAPLineTooLong) {
		t.Fatalf("want errICAPLineTooLong, got %v", err)
	}
}

// TestReadICAPChunkedBodyTrailerBounded ensures the post-data trailing-CRLF
// consume is bounded: a valid chunk followed by a multi-megabyte run with no
// '\n' must be rejected, not buffered whole (MaxBody bypass / per-conn DoS).
func TestReadICAPChunkedBodyTrailerBounded(t *testing.T) {
	// "1\r\nA" = one 1-byte chunk, then junk with no '\n' where the trailing CRLF
	// should be.
	body := "1\r\nA" + strings.Repeat("X", 4<<20)
	_, _, err := readICAPChunkedBody(bufio.NewReader(strings.NewReader(body)), 1<<20)
	if err == nil {
		t.Fatal("expected error on oversized chunk trailer, got nil")
	}
	if !errors.Is(err, errICAPLineTooLong) {
		t.Fatalf("want errICAPLineTooLong, got %v", err)
	}
}

// TestSkipHTTPHeadersBounded ensures an encapsulated HTTP header line with no
// terminating '\n' cannot grow the read buffer without bound.
func TestSkipHTTPHeadersBounded(t *testing.T) {
	junk := strings.Repeat("A", 4<<20) // no '\n' anywhere
	err := skipHTTPHeaders(bufio.NewReader(strings.NewReader(junk)))
	if err == nil {
		t.Fatal("expected error on oversized HTTP header line, got nil")
	}
	if !errors.Is(err, errICAPLineTooLong) {
		t.Fatalf("want errICAPLineTooLong, got %v", err)
	}
}

// --- A2: outer ICAP head bounds -------------------------------------------

// TestICAPRequestLineBounded: a request line with no CRLF must be rejected at
// the line cap instead of buffering unboundedly.
func TestICAPRequestLineBounded(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	addr := startTestICAPServer(t, s)

	req := "RESPMOD icap://" + strings.Repeat("A", maxICAPHeaderLine+1024) + " ICAP/1.0\r\n\r\n"
	resp := doICAP(t, addr, req)

	if !strings.HasPrefix(resp, "ICAP/1.0 400") {
		t.Errorf("oversized request line: want 400, got:\n%q", resp)
	}
}

// TestICAPHeaderLineBounded: one absurdly long header line is rejected.
func TestICAPHeaderLineBounded(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	addr := startTestICAPServer(t, s)

	req := "OPTIONS icap://x/scan ICAP/1.0\r\n" +
		"X-Big: " + strings.Repeat("A", maxICAPHeaderLine+1024) + "\r\n\r\n"
	resp := doICAP(t, addr, req)

	if !strings.HasPrefix(resp, "ICAP/1.0 400") {
		t.Errorf("oversized header line: want 400, got:\n%q", resp)
	}
}

// TestICAPHeaderCountBounded: many short header lines are rejected at the count
// cap. Per-line caps alone do not stop this.
func TestICAPHeaderCountBounded(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	addr := startTestICAPServer(t, s)

	var sb strings.Builder
	sb.WriteString("OPTIONS icap://x/scan ICAP/1.0\r\n")
	for i := 0; i < maxICAPHeaderCount+10; i++ {
		fmt.Fprintf(&sb, "X-H%d: v\r\n", i)
	}
	sb.WriteString("\r\n")
	resp := doICAP(t, addr, sb.String())

	if !strings.HasPrefix(resp, "ICAP/1.0 400") {
		t.Errorf("header flood: want 400, got:\n%q", resp)
	}
}

// TestICAPHeaderBytesBounded: a header block under both the per-line and the
// count cap, but over the aggregate byte cap, is rejected.
func TestICAPHeaderBytesBounded(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	addr := startTestICAPServer(t, s)

	// 32 lines × ~4 KiB = ~128 KiB > maxICAPHeaderBytes (64 KiB), while each line
	// stays under maxICAPHeaderLine and the count stays under maxICAPHeaderCount.
	var sb strings.Builder
	sb.WriteString("OPTIONS icap://x/scan ICAP/1.0\r\n")
	val := strings.Repeat("A", 4096)
	for i := 0; i < 32; i++ {
		fmt.Fprintf(&sb, "X-H%d: %s\r\n", i, val)
	}
	sb.WriteString("\r\n")
	resp := doICAP(t, addr, sb.String())

	if !strings.HasPrefix(resp, "ICAP/1.0 400") {
		t.Errorf("header byte flood: want 400, got:\n%q", resp)
	}
}

// TestReadBoundedMIMEHeaderContinuation: obs-fold continuation lines fold into
// the previous value (textproto parity), and a leading continuation is rejected.
func TestReadBoundedMIMEHeaderContinuation(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("X-A: one\r\n  two\r\nX-B: b\r\n\r\n"))
	hdr, err := readBoundedMIMEHeader(br)
	if err != nil {
		t.Fatalf("continuation: unexpected error: %v", err)
	}
	if got := hdr.Get("X-A"); got != "one two" {
		t.Errorf("continuation: X-A = %q, want %q", got, "one two")
	}
	if got := hdr.Get("X-B"); got != "b" {
		t.Errorf("continuation: X-B = %q, want %q", got, "b")
	}

	br = bufio.NewReader(strings.NewReader(" leading\r\n\r\n"))
	if _, err := readBoundedMIMEHeader(br); err == nil {
		t.Error("leading continuation: want error, got nil")
	}
}

// TestReadBoundedMIMEHeaderMalformed: a header line with no colon is rejected
// rather than silently dropped.
func TestReadBoundedMIMEHeaderMalformed(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("no-colon-here\r\n\r\n"))
	if _, err := readBoundedMIMEHeader(br); err == nil {
		t.Error("malformed header: want error, got nil")
	}
}

// TestICAPConnCapRefuses: once ICAPMaxConns connections are live, further
// connections are answered 503 and closed instead of accumulating goroutines.
func TestICAPConnCapRefuses(t *testing.T) {
	// An explicit ICAPMaxConns is honoured by sanitize(), so the gate really is 2.
	cfg := &Config{ICAPAddr: "127.0.0.1:0", MaxConcurrent: 1, ICAPMaxConns: 2}
	s := NewServer(cfg, &fakeEngine{count: 1})
	if s.cfg.ICAPMaxConns != 2 {
		t.Fatalf("sanitize overrode an explicit ICAPMaxConns: got %d, want 2", s.cfg.ICAPMaxConns)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	// Drive the accept loop against the real acceptICAP (the same function
	// ListenAndServeICAP calls), just on a listener we own so we don't have to
	// rebind the configured address.
	s.icapLn.Store(&ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.acceptICAP(c)
		}
	}()

	// Hold two connections open (idle: they never send a request).
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		held = append(held, c)
	}
	// Wait for the server to have both slots taken.
	deadline := time.Now().Add(2 * time.Second)
	for len(s.icapConns) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(s.icapConns) != 2 {
		t.Fatalf("setup: want 2 live conns, got %d", len(s.icapConns))
	}

	// The third must be refused with 503 and closed.
	c3, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	_ = c3.SetDeadline(time.Now().Add(3 * time.Second))
	var sb strings.Builder
	if _, err := io.Copy(&sb, c3); err != nil {
		t.Fatalf("refused conn: read: %v", err)
	}
	if !strings.HasPrefix(sb.String(), "ICAP/1.0 503") {
		t.Errorf("over-cap conn: want 503, got %q", sb.String())
	}
	if n := s.metrics.icapBusy.Load(); n != 1 {
		t.Errorf("icapBusy = %d, want 1", n)
	}
	_ = held
}

// TestICAPSlowClientsDoNotBlockOthers: concurrent idle (slow-loris) connections
// under the cap must not prevent a well-behaved client from being served.
func TestICAPSlowClientsDoNotBlockOthers(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	addr := startTestICAPServer(t, s)

	for i := 0; i < 8; i++ {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// Send a partial request line and stall.
		_, _ = io.WriteString(c, "OPTIONS icap://x/sc")
	}

	resp := doICAP(t, addr, "OPTIONS icap://x/scan ICAP/1.0\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(resp, "ICAP/1.0 200 OK") {
		t.Errorf("good client behind slow clients: want 200, got:\n%q", resp)
	}
}

// TestICAPTruncatedHeadIsRejected pins the fail-open regression: a head that
// ends before its blank-line terminator must be answered 400, NOT scanned as a
// header-less (and therefore body-less) request and reported clean.
func TestICAPTruncatedHeadIsRejected(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	addr := startTestICAPServer(t, s)

	// Note: no trailing "\r\n" blank line — the head is truncated.
	req := "RESPMOD icap://x/scan ICAP/1.0\r\nEncapsulated: res-body=0\r\n"
	resp := doICAP(t, addr, req)

	if !strings.HasPrefix(resp, "ICAP/1.0 400") {
		t.Errorf("truncated head: want 400, got:\n%q", resp)
	}
	if strings.Contains(resp, "200 OK") || strings.Contains(resp, "204") {
		t.Errorf("truncated head: fail-open clean verdict:\n%q", resp)
	}
}

// TestReadBoundedMIMEHeaderRejectsBadNames: a field name with a non-token byte,
// or whitespace between the name and the colon (RFC 7230 §3.2.4 smuggling
// vector), must be rejected rather than repaired.
func TestReadBoundedMIMEHeaderRejectsBadNames(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"space before colon", "X-A : 1\r\n\r\n"},
		{"tab before colon", "X-A\t: 1\r\n\r\n"},
		{"NUL in name", "X\x00A: 1\r\n\r\n"},
		{"space inside name", "X A: 1\r\n\r\n"},
		{"empty name", ": 1\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tc.in))
			if _, err := readBoundedMIMEHeader(br); err == nil {
				t.Errorf("%q: want error, got nil", tc.in)
			}
		})
	}
}

// TestReadBoundedLineBoundary pins the exact accepted maximum: readBoundedLine
// accepts a line of exactly limit bytes and rejects limit+1.
func TestReadBoundedLineBoundary(t *testing.T) {
	const limit = 64

	br := bufio.NewReader(strings.NewReader(strings.Repeat("A", limit) + "\n"))
	line, err := readBoundedLine(br, limit)
	if err != nil {
		t.Fatalf("exactly limit bytes: unexpected error: %v", err)
	}
	if len(line) != limit {
		t.Errorf("exactly limit bytes: len = %d, want %d", len(line), limit)
	}

	br = bufio.NewReader(strings.NewReader(strings.Repeat("A", limit+1) + "\n"))
	if _, err := readBoundedLine(br, limit); !errors.Is(err, errICAPLineTooLong) {
		t.Errorf("limit+1 bytes: err = %v, want errICAPLineTooLong", err)
	}
}

// TestICAPOptionsAdvertisesConnCap: Max-Connections must advertise the cap that
// actually causes a 503, so proxies size their pools against the real limit.
func TestICAPOptionsAdvertisesConnCap(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)

	resp := doICAP(t, addr, "OPTIONS icap://x/scan ICAP/1.0\r\nHost: x\r\n\r\n")
	want := fmt.Sprintf("Max-Connections: %d", s.cfg.ICAPMaxConns)
	if !strings.Contains(resp, want) {
		t.Errorf("OPTIONS: want %q, got:\n%s", want, resp)
	}
}

// TestICAPKeepAliveSurvivesIdle: a pooled keep-alive connection (Squid's
// icap_persistent_connections) must serve a second request on the same
// connection — the head deadline must not be armed while the connection is idle.
func TestICAPKeepAliveSurvivesIdle(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	addr := startTestICAPServer(t, s)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	for i := 0; i < 2; i++ {
		if _, err := io.WriteString(conn, "OPTIONS icap://x/scan ICAP/1.0\r\nHost: x\r\n\r\n"); err != nil {
			t.Fatalf("request %d: write: %v", i, err)
		}
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("request %d: read: %v", i, err)
		}
		if !strings.HasPrefix(line, "ICAP/1.0 200 OK") {
			t.Fatalf("request %d: want 200 OK, got %q", i, line)
		}
		// Drain the rest of the response head.
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("request %d: drain: %v", i, err)
			}
			if strings.TrimSpace(l) == "" {
				break
			}
		}
	}
}

// TestICAPMaxConnsSanitize: 0 means auto (8× in-flight); an explicit value is
// honoured, including one below MaxInflight; a nonsensical value falls back.
func TestICAPMaxConnsSanitize(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  int
		want func(c *Config) int
	}{
		{"auto", 0, func(c *Config) int { return c.MaxInflight * 8 }},
		{"explicit below inflight is honoured", 4, func(*Config) int { return 4 }},
		{"explicit above inflight is honoured", 9999, func(*Config) int { return 9999 }},
		{"negative falls back to auto", -1, func(c *Config) int { return c.MaxInflight * 8 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{MaxConcurrent: 2, ICAPMaxConns: tc.set}
			c.sanitize()
			if got := c.ICAPMaxConns; got != tc.want(c) {
				t.Errorf("ICAPMaxConns = %d, want %d", got, tc.want(c))
			}
		})
	}
}

// TestICAPShutdownDrainsRefusals: refusal goroutines are tracked by icapWg, so a
// shutdown does not report drained while they still hold open fds mid-write.
func TestICAPShutdownDrainsRefusals(t *testing.T) {
	cfg := &Config{ICAPAddr: "127.0.0.1:0", MaxConcurrent: 1, ICAPMaxConns: 1}
	s := NewServer(cfg, &fakeEngine{count: 1})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s.icapLn.Store(&ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.acceptICAP(c)
		}
	}()

	// Fill the single slot, then force several refusals.
	conns := make([]net.Conn, 0, 5)
	for i := 0; i < 5; i++ {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.metrics.icapBusy.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.metrics.icapBusy.Load() == 0 {
		t.Fatal("setup: no connection was refused")
	}

	for _, c := range conns {
		_ = c.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.ShutdownICAP(ctx)
	if ctx.Err() != nil {
		t.Fatal("ShutdownICAP did not drain before the deadline")
	}
}
