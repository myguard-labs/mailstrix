package mailstrix

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// optionsReq builds a minimal OPTIONS request.
func optionsReq() string {
	return "OPTIONS icap://x/scan ICAP/1.0\r\nHost: x\r\n\r\n"
}

// sendOptions sends an OPTIONS request directly through handleICAPRequest
// and returns the response as a string.
func sendOptions(t *testing.T, s *Server) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := s.handleICAPRequest(&out, bufio.NewReader(strings.NewReader(optionsReq())))
	return out.String(), err
}

// TestICAPOptionsNilEngineDoesNotPanic: handleICAPOptions must be nil-safe
// when the engine is nil. It should return "200 OK" with a well-formed ISTag
// header derived from an empty fingerprint (icapISTag("")).
func TestICAPOptionsNilEngineDoesNotPanic(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1}, "")
	s.engine = nil

	resp, err := sendOptions(t, s)
	if err != nil {
		t.Errorf("OPTIONS with nil engine returned error: %v", err)
	}

	// Verify "200 OK" in the response.
	if !strings.HasPrefix(resp, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("OPTIONS with nil engine: want 200 OK, got:\n%s", resp)
	}

	// Extract and verify the ISTag header.
	wantTag := icapISTag("")
	if !strings.Contains(resp, "ISTag: "+wantTag+"\r\n") {
		t.Errorf("OPTIONS with nil engine: missing ISTag %s in response:\n%s", wantTag, resp)
	}

	// Verify it's well-formed (quoted).
	if len(wantTag) < 3 || wantTag[0] != '"' || wantTag[len(wantTag)-1] != '"' {
		t.Errorf("ISTag(%q) not quoted/well-formed: %q", "", wantTag)
	}
}

// Positive control: OPTIONS with a non-nil engine should return its fingerprint-derived ISTag.
// This ensures the nil-safe icapFingerprint() helper correctly differentiates.
func TestICAPOptionsNonNilEngineUsesFingerprint(t *testing.T) {
	s := newTestServer(&fakeEngine{count: 1, fp: "test-fp"}, "")
	if s.engine == nil {
		t.Fatal("precondition: engine must not be nil")
	}

	resp, err := sendOptions(t, s)
	if err != nil {
		t.Errorf("OPTIONS with engine returned error: %v", err)
	}

	// Verify "200 OK".
	if !strings.HasPrefix(resp, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("OPTIONS with engine: want 200 OK, got:\n%s", resp)
	}

	// Verify it contains the engine's fingerprint-derived ISTag.
	wantTag := icapISTag("test-fp")
	if !strings.Contains(resp, "ISTag: "+wantTag+"\r\n") {
		t.Errorf("OPTIONS with engine: missing ISTag %s in response:\n%s", wantTag, resp)
	}
}
