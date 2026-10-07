package mailstrix

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

// badEncapReq builds a REQMOD head whose Encapsulated header is enc (omitted
// when enc is empty).
func badEncapReq(enc string) string {
	h := "REQMOD icap://x/scan ICAP/1.0\r\nHost: x\r\n"
	if enc != "" {
		h += "Encapsulated: " + enc + "\r\n"
	}
	return h + "\r\n"
}

func badEncapServer() (*Server, *bytes.Buffer) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	var errBuf bytes.Buffer
	s.errl = log.New(&errBuf, "", 0)
	return s, &errBuf
}

func sendBadEncap(t *testing.T, s *Server, enc string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := s.handleICAPRequest(&out, bufio.NewReader(strings.NewReader(badEncapReq(enc))))
	return out.String(), err
}

func TestICAPBadEncapLogThrottled(t *testing.T) {
	s, errBuf := badEncapServer()

	// Positive: the first malformed request logs once, even on a young process.
	if _, err := sendBadEncap(t, s, "bogus=1"); err == nil {
		t.Fatal("want error for malformed Encapsulated")
	}
	if n := strings.Count(errBuf.String(), "ICAP REQMOD 400"); n != 1 {
		t.Fatalf("first request: want 1 log line, got %d:\n%s", n, errBuf.String())
	}

	// Negative: repeats within the interval are suppressed (both shapes).
	errBuf.Reset()
	for i := 0; i < 5; i++ {
		_, _ = sendBadEncap(t, s, "bogus=1")
		_, _ = sendBadEncap(t, s, "")
	}
	if errBuf.Len() != 0 {
		t.Fatalf("repeats within interval must not log:\n%s", errBuf.String())
	}

	// Boundary: just inside the interval is still suppressed.
	now := int64(time.Since(processStart))
	s.icapBadEncapLog.Store(now - int64(icapBadEncapLogInterval) + int64(5*time.Second))
	_, _ = sendBadEncap(t, s, "bogus=1")
	if errBuf.Len() != 0 {
		t.Fatalf("inside interval must not log:\n%s", errBuf.String())
	}

	// Boundary: a full interval elapsed logs again, then re-arms.
	now = int64(time.Since(processStart))
	s.icapBadEncapLog.Store(now - int64(icapBadEncapLogInterval))
	_, _ = sendBadEncap(t, s, "bogus=1")
	if n := strings.Count(errBuf.String(), "ICAP REQMOD 400"); n != 1 {
		t.Fatalf("after interval: want 1 log line, got %d:\n%s", n, errBuf.String())
	}
	errBuf.Reset()
	_, _ = sendBadEncap(t, s, "bogus=1")
	if errBuf.Len() != 0 {
		t.Fatalf("must re-arm after logging:\n%s", errBuf.String())
	}
}

// Malformed: missing and malformed Encapsulated both still answer 400 and
// return the parse error, whether or not the log line is throttled.
func TestICAPBadEncapStill400(t *testing.T) {
	for _, enc := range []string{"", "bogus=1", "req-hdr=0, req-hdr=5"} {
		s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
		s.errl = log.New(io.Discard, "", 0)
		for i := 0; i < 3; i++ { // first logs, rest are throttled
			out, err := sendBadEncap(t, s, enc)
			if err == nil {
				t.Fatalf("enc=%q try %d: want error", enc, i)
			}
			if !strings.HasPrefix(out, "ICAP/1.0 400 Bad Request\r\n") {
				t.Fatalf("enc=%q try %d: want 400, got %q", enc, i, out)
			}
		}
	}
}
