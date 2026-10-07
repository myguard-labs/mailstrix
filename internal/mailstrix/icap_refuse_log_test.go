package mailstrix

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func refuseLogServer() (*Server, *bytes.Buffer) {
	s := newTestServer(&fakeEngine{count: 1, fp: "fp"}, "")
	var errBuf bytes.Buffer
	s.errl = log.New(&errBuf, "", 0)
	return s, &errBuf
}

func TestICAPRefuseLogThrottled(t *testing.T) {
	s, errBuf := refuseLogServer()

	// Positive: the first cap-reached call logs once, even on a young process.
	s.logRefusedICAP()
	if n := strings.Count(errBuf.String(), "ICAP 503 busy"); n != 1 {
		t.Fatalf("first call: want 1 log line, got %d:\n%s", n, errBuf.String())
	}

	// Negative: repeats within the interval are suppressed.
	errBuf.Reset()
	for i := 0; i < 5; i++ {
		s.logRefusedICAP()
	}
	if errBuf.Len() != 0 {
		t.Fatalf("repeats within interval must not log:\n%s", errBuf.String())
	}

	// Boundary: just inside the interval is still suppressed.
	now := int64(time.Since(processStart))
	s.icapRefuseLog.Store(now - int64(icapRefuseLogInterval) + int64(5*time.Second))
	s.logRefusedICAP()
	if errBuf.Len() != 0 {
		t.Fatalf("inside interval must not log:\n%s", errBuf.String())
	}

	// Boundary: a full interval elapsed logs again, then re-arms.
	now = int64(time.Since(processStart))
	s.icapRefuseLog.Store(now - int64(icapRefuseLogInterval))
	s.logRefusedICAP()
	if n := strings.Count(errBuf.String(), "ICAP 503 busy"); n != 1 {
		t.Fatalf("after interval: want 1 log line, got %d:\n%s", n, errBuf.String())
	}
	errBuf.Reset()
	s.logRefusedICAP()
	if errBuf.Len() != 0 {
		t.Fatalf("must re-arm after logging:\n%s", errBuf.String())
	}
}
