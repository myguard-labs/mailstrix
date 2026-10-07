package mailstrix

import (
	"bufio"
	"strconv"
	"strings"
	"testing"
)

// TestICAPRESPMODCleanEchoes (COR-03): a clean RESPMOD without Allow: 204
// returns the original response headers and body, not a synthetic "clean".
func TestICAPRESPMODCleanEchoes(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)
	body := "<html>the original object</html>"
	resp := doICAP(t, addr, icapRESPMODRequest(addr, body, false))
	resHdr := "HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n"
	want := "Encapsulated: res-hdr=0, res-body=" + itoa(len(resHdr)) + "\r\n\r\n" + resHdr + "20\r\n" + body + "\r\n0\r\n\r\n"
	if !strings.HasPrefix(resp, "ICAP/1.0 200 OK\r\n") || !strings.Contains(resp, want) {
		t.Fatalf("want echo of the original object, got:\n%q", resp)
	}
	if strings.Contains(resp, "clean\r\n") {
		t.Fatalf("synthetic clean body still sent:\n%q", resp)
	}
}

// TestICAPREQMODCleanEchoes: the request headers and body come back for
// REQMOD.
func TestICAPREQMODCleanEchoes(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)
	resp := doICAP(t, addr, icapREQMODRequest(addr, "form=data", false))
	if !strings.Contains(resp, "Encapsulated: req-hdr=0, req-body=") ||
		!strings.Contains(resp, "POST / HTTP/1.1\r\nHost: "+addr+"\r\nContent-Length: 9\r\n\r\n9\r\nform=data\r\n0\r\n\r\n") {
		t.Fatalf("want echo of the original request, got:\n%q", resp)
	}
}

// TestICAPCleanEchoNullBody (boundary): a header-only request echoes its
// headers with null-body.
func TestICAPCleanEchoNullBody(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)
	reqHdr := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	req := "REQMOD icap://" + addr + "/scan ICAP/1.0\r\nHost: " + addr + "\r\n" +
		"Encapsulated: req-hdr=0, null-body=" + itoa(len(reqHdr)) + "\r\n\r\n" + reqHdr
	resp := doICAP(t, addr, req)
	if !strings.Contains(resp, "Encapsulated: req-hdr=0, null-body="+itoa(len(reqHdr))+"\r\n\r\n"+reqHdr) {
		t.Fatalf("want header-only echo, got:\n%q", resp)
	}
}

// TestICAPCleanAllow204Unchanged (negative control): with Allow: 204 a clean
// object still gets 204 and no echo.
func TestICAPCleanAllow204Unchanged(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	addr := startTestICAPServer(t, s)
	resp := doICAP(t, addr, icapRESPMODRequest(addr, "<html>x</html>", true))
	if !strings.HasPrefix(resp, "ICAP/1.0 204 No Modification\r\nISTag: "+icapISTag("fp")+"\r\n\r\n") || strings.Contains(resp, "<html>") {
		t.Fatalf("want bare 204, got:\n%q", resp)
	}
}

// TestReadHTTPHeadersCaps (malformed): an oversized or unterminated header
// section is rejected.
func TestReadHTTPHeadersCaps(t *testing.T) {
	many := "HTTP/1.1 200 OK\r\n" + strings.Repeat("X-A: b\r\n", maxICAPHeaderCount+5) + "\r\n"
	if _, err := readHTTPHeaders(bufio.NewReader(strings.NewReader(many))); err == nil {
		t.Error("too many header lines accepted")
	}
	if _, err := readHTTPHeaders(bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nX: y\r\n"))); err == nil {
		t.Error("unterminated header section accepted")
	}
	got, err := readHTTPHeaders(bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\nX: y\n\nbody")))
	if err != nil || string(got) != "HTTP/1.1 200 OK\r\nX: y\r\n\r\n" {
		t.Errorf("LF-only section = %q, %v", got, err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
