package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	milter "github.com/emersion/go-milter"

	"github.com/myguard-labs/mailstrix/internal/verdict"
)

// stampedHeader is one header the milter asked to add. go-milter's *Modifier is
// a struct with unexported fields and no interface, so a test cannot construct a
// working one — the milter's stamp seam lets us record the calls instead.
type stampedHeader struct{ name, value string }

// newTestMilter builds the milter under test with its header sink redirected
// into a slice.
func newTestMilter(t *testing.T, cfg config) (*strixMilter, *[]stampedHeader, *strings.Builder) {
	t.Helper()
	var logbuf strings.Builder
	s := &strixMilter{
		cfg:    cfg,
		client: verdict.NewClient(cfg.url, cfg.token, "strix-milter/test", cfg.timeout),
		log:    log.New(&logbuf, "", 0),
	}
	stamped := &[]stampedHeader{}
	s.stamp = func(name, value string) {
		*stamped = append(*stamped, stampedHeader{name, sanitizeHeaderValue(value)})
	}
	return s, stamped, &logbuf
}

func headerValue(hs []stampedHeader, name string) (string, bool) {
	for _, h := range hs {
		if strings.EqualFold(h.name, name) {
			return h.value, true
		}
	}
	return "", false
}

// scanStub is a fake strixd. It returns the given matches, or the given status.
func scanStub(t *testing.T, matches []verdict.Match, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, "boom")
			return
		}
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{Matches: matches})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func baseCfg(url string) config {
	return config{url: url, timeout: 5 * time.Second, maxBody: 1 << 20}
}

// feed drives one complete message through the milter the way an MTA would.
func feed(t *testing.T, s *strixMilter, body []byte) milter.Response {
	t.Helper()
	for len(body) > 0 {
		n := len(body)
		if n > milter.MaxBodyChunk {
			n = milter.MaxBodyChunk
		}
		if _, err := s.BodyChunk(body[:n], nil); err != nil {
			t.Fatalf("BodyChunk: %v", err)
		}
		body = body[n:]
	}
	resp, err := s.Body(nil)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	return resp
}

// --- the contract: ALWAYS ACCEPT ------------------------------------------

func TestCleanMessageIsAcceptedAndStampedClean(t *testing.T) {
	srv := scanStub(t, nil, http.StatusOK)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	if got := feed(t, s, []byte("hello")); got != milter.RespAccept {
		t.Fatalf("response = %v, want RespAccept", got)
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusClean {
		t.Fatalf("%s = %q, want %q", hdrStatus, v, statusClean)
	}
	if _, ok := headerValue(*stamped, hdrRules); ok {
		t.Fatalf("clean message must not carry %s", hdrRules)
	}
}

func TestInfectedMessageIsSTILLAccepted(t *testing.T) {
	// The whole design: we report, the MTA decides. A malware hit must NOT be
	// rejected, deferred, discarded or quarantined by this binary.
	srv := scanStub(t, []verdict.Match{
		{Rule: "Win32_Emotet_A", Meta: map[string]string{"family": "Emotet"}},
	}, http.StatusOK)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	got := feed(t, s, []byte("evil"))
	if got != milter.RespAccept {
		t.Fatalf("response = %v, want RespAccept — the milter must never reject", got)
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusInfected {
		t.Fatalf("%s = %q, want %q", hdrStatus, v, statusInfected)
	}
	if v, _ := headerValue(*stamped, hdrRules); v != "Win32_Emotet_A" {
		t.Fatalf("%s = %q", hdrRules, v)
	}
	if v, _ := headerValue(*stamped, hdrFamily); v != "Emotet" {
		t.Fatalf("%s = %q, want Emotet", hdrFamily, v)
	}
}

// --- fail-open ------------------------------------------------------------

func TestScannerDownFailsOpenToUnknown(t *testing.T) {
	// Point at a closed port: transport error.
	s, stamped, _ := newTestMilter(t, baseCfg("http://127.0.0.1:1"))

	if got := feed(t, s, []byte("hello")); got != milter.RespAccept {
		t.Fatalf("response = %v, want RespAccept on scanner outage", got)
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusUnknown {
		t.Fatalf("%s = %q, want %q", hdrStatus, v, statusUnknown)
	}
	info, ok := headerValue(*stamped, hdrInfo)
	if !ok || !strings.Contains(info, "scanner unavailable") {
		t.Fatalf("%s = %q, want it to explain the outage", hdrInfo, info)
	}
}

func TestScannerErrorStatusFailsOpenToUnknown(t *testing.T) {
	srv := scanStub(t, nil, http.StatusInternalServerError)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	if got := feed(t, s, []byte("hello")); got != milter.RespAccept {
		t.Fatalf("response = %v, want RespAccept on scanner 500", got)
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusUnknown {
		t.Fatalf("%s = %q, want %q", hdrStatus, v, statusUnknown)
	}
}

func TestScannerTimeoutFailsOpenToUnknown(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	t.Cleanup(slow.Close)

	cfg := baseCfg(slow.URL)
	cfg.timeout = 100 * time.Millisecond // hard per-message deadline
	s, stamped, _ := newTestMilter(t, cfg)

	start := time.Now()
	if got := feed(t, s, []byte("hello")); got != milter.RespAccept {
		t.Fatalf("response = %v, want RespAccept on timeout", got)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %s — the per-message deadline did not bound the scan", elapsed)
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusUnknown {
		t.Fatalf("%s = %q, want %q", hdrStatus, v, statusUnknown)
	}
}

// --- oversize: no truncated-prefix scan -----------------------------------

func TestOversizeIsNotScannedAsTruncatedPrefix(t *testing.T) {
	// If we posted only the first max-body bytes, a dropper past the cap would
	// come back "clean" — a silent miss. The message must be stamped unknown and
	// the scanner must not be called at all.
	//
	// The chunking here is load-bearing. An MTA delivers the body in ≤64 KiB
	// chunks, so a real oversize message arrives as SEVERAL chunks that fit
	// followed by one that overflows — and it is precisely that already-buffered
	// prefix that must not be posted. Feeding one single over-cap chunk instead
	// would leave the buffer empty and the test would pass via the empty-body
	// path even if the truncation guard were removed entirely.
	var posted [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		posted = append(posted, b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	cfg := baseCfg(srv.URL)
	cfg.maxBody = 16
	s, stamped, _ := newTestMilter(t, cfg)

	// 3 chunks of 8: the first two fit (16 == cap), the third overflows.
	for i := 0; i < 3; i++ {
		if _, err := s.BodyChunk([]byte(strings.Repeat("A", 8)), nil); err != nil {
			t.Fatalf("BodyChunk: %v", err)
		}
	}
	if !s.oversize {
		t.Fatal("the third chunk pushed the message over max-body but oversize was not latched")
	}
	if s.body != nil {
		t.Fatal("oversize message must not retain a partial buffer")
	}

	got, err := s.Body(nil)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if got != milter.RespAccept {
		t.Fatalf("response = %v, want RespAccept", got)
	}
	if len(posted) != 0 {
		t.Fatalf("scanner was called with a TRUNCATED prefix (%q) — a silent miss", posted[0])
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusUnknown {
		t.Fatalf("%s = %q, want %q", hdrStatus, v, statusUnknown)
	}
	if info, _ := headerValue(*stamped, hdrInfo); !strings.Contains(info, "exceeds max-body") {
		t.Fatalf("%s = %q, want it to say the message was too large (not that it was empty)", hdrInfo, info)
	}
}

func TestExactlyMaxBodyIsScanned(t *testing.T) {
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = len(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	cfg := baseCfg(srv.URL)
	cfg.maxBody = 32
	s, stamped, _ := newTestMilter(t, cfg)

	feed(t, s, []byte(strings.Repeat("A", 32)))
	if got != 32 {
		t.Fatalf("scanner received %d bytes, want the full 32 (off-by-one at the cap)", got)
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusClean {
		t.Fatalf("%s = %q, want clean", hdrStatus, v)
	}
}

// --- log-only rules must not mark mail infected ---------------------------

func TestCanaryAndAllowlistDoNotMarkInfected(t *testing.T) {
	srv := scanStub(t, []verdict.Match{
		{Rule: "canary", Meta: map[string]string{"mailstrix_canary": "1"}},
		{Rule: "known_benign", Meta: map[string]string{"mailstrix_allow": "1"}},
	}, http.StatusOK)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	feed(t, s, []byte("hello"))
	if v, _ := headerValue(*stamped, hdrStatus); v != statusClean {
		t.Fatalf("%s = %q — a canary/allowlisted hit must stay CLEAN", hdrStatus, v)
	}
}

// --- header injection -----------------------------------------------------

func TestRuleNameCannotInjectAHeader(t *testing.T) {
	// A rule name (or family) carrying CRLF must not be able to terminate our
	// header and inject another one into the message.
	srv := scanStub(t, []verdict.Match{
		{Rule: "evil\r\nX-Spam-Flag: NO", Meta: map[string]string{"family": "bad\nX-Forged: yes"}},
	}, http.StatusOK)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	feed(t, s, []byte("x"))
	for _, h := range *stamped {
		if strings.ContainsAny(h.value, "\r\n") {
			t.Fatalf("header %s value %q still contains CR/LF — header injection", h.name, h.value)
		}
	}
	if v, _ := headerValue(*stamped, hdrRules); strings.Contains(v, "X-Spam-Flag") && strings.ContainsAny(v, "\r\n") {
		t.Fatalf("%s = %q", hdrRules, v)
	}
}

func TestSanitizeHeaderValueStripsControlChars(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"clean", "clean"},
		{"a\r\nb", "a  b"},
		{"a\x00b", "a b"},
		{"  padded  ", "padded"},
	} {
		if got := sanitizeHeaderValue(tc.in); got != tc.want {
			t.Errorf("sanitizeHeaderValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestInboundForgedHeaderIsLogged(t *testing.T) {
	srv := scanStub(t, nil, http.StatusOK)
	s, _, logbuf := newTestMilter(t, baseCfg(srv.URL))

	if _, err := s.Header("X-Mailstrix-Status", "clean", nil); err != nil {
		t.Fatalf("Header: %v", err)
	}
	if !strings.Contains(logbuf.String(), "WARNING") {
		t.Fatalf("a sender-supplied X-Mailstrix-* header must be logged loudly, got %q", logbuf.String())
	}
}

// --- rule-list capping ----------------------------------------------------

func TestManyRulesProduceABoundedHeader(t *testing.T) {
	var matches []verdict.Match
	for i := 0; i < 500; i++ {
		matches = append(matches, verdict.Match{Rule: fmt.Sprintf("rule_number_%03d", i)})
	}
	srv := scanStub(t, matches, http.StatusOK)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	feed(t, s, []byte("x"))
	v, ok := headerValue(*stamped, hdrRules)
	if !ok {
		t.Fatal("expected a rules header")
	}
	if len(v) > maxRuleHeaderLen+32 {
		t.Fatalf("%s is %d bytes — unbounded header line", hdrRules, len(v))
	}
	if !strings.Contains(v, "more)") {
		t.Fatalf("a truncated rule list must say how many were dropped, got %q", v)
	}
}

// --- per-message state ----------------------------------------------------

func TestAbortResetsMessageState(t *testing.T) {
	srv := scanStub(t, nil, http.StatusOK)
	s, _, _ := newTestMilter(t, baseCfg(srv.URL))

	if _, err := s.BodyChunk([]byte("partial"), nil); err != nil {
		t.Fatalf("BodyChunk: %v", err)
	}
	if err := s.Abort(nil); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if s.body != nil || s.oversize || s.subject != "" {
		t.Fatal("Abort must reset per-message state")
	}
}

func TestSecondMessageOnSameConnectionIsIndependent(t *testing.T) {
	// go-milter reuses one Milter per CONNECTION; a stale buffer from message 1
	// would get rescanned (and mis-stamped) as part of message 2.
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	s, _, _ := newTestMilter(t, baseCfg(srv.URL))
	feed(t, s, []byte("first"))
	feed(t, s, []byte("second"))

	if len(bodies) != 2 || bodies[0] != "first" || bodies[1] != "second" {
		t.Fatalf("bodies = %q, want [first second] — per-message state leaked", bodies)
	}
}

func TestEmptyBodyIsUnknownNotClean(t *testing.T) {
	srv := scanStub(t, nil, http.StatusOK)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	if got := feed(t, s, nil); got != milter.RespAccept {
		t.Fatalf("response = %v, want RespAccept", got)
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusUnknown {
		t.Fatalf("%s = %q, want %q — an empty body was never scanned, so it is not known-clean", hdrStatus, v, statusUnknown)
	}
}

// --- token handling -------------------------------------------------------

func TestTokenIsSentAndFilenameEncoded(t *testing.T) {
	var gotToken, gotName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-MAILSTRIX-Token")
		gotName = r.Header.Get("X-MAILSTRIX-Filename")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	c := verdict.NewClient(srv.URL, "s3cret", "test/1", time.Second)
	if _, err := c.Scan(t.Context(), "msg.eml", []byte("x")); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if gotToken != "s3cret" {
		t.Fatalf("token = %q", gotToken)
	}
	if want := base64.StdEncoding.EncodeToString([]byte("msg.eml")); gotName != want {
		t.Fatalf("filename = %q, want %q", gotName, want)
	}
}

func TestResolveTokenPrefersFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "tok")
	if err := os.WriteFile(f, []byte("  from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveToken("from-flag", f)
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "from-file" {
		t.Fatalf("token = %q, want from-file (the file must win, and be trimmed)", got)
	}
}

// --- listen spec ----------------------------------------------------------

func TestListenOnUnixSocketAndChmod(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "m.sock")
	ln, err := listenOn("unix:" + sock)
	if err != nil {
		t.Fatalf("listenOn: %v", err)
	}
	defer ln.Close()

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o660 {
		t.Fatalf("socket mode = %o, want 660 (the MTA runs as another user)", perm)
	}
}

func TestListenOnRefusesLiveUnixSocket(t *testing.T) {
	// A stale socket file may be removed; a LIVE one must not be — that would
	// silently steal the socket from a running instance.
	sock := filepath.Join(t.TempDir(), "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	if _, err := listenOn("unix:" + sock); err == nil {
		t.Fatal("listenOn stole a socket from a running process")
	}
}

func TestListenOnRemovesStaleUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "m.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil { // stale leftover, nobody listening
		t.Fatal(err)
	}
	ln, err := listenOn("unix:" + sock)
	if err != nil {
		t.Fatalf("listenOn did not clear a stale socket: %v", err)
	}
	_ = ln.Close()
}

func TestListenOnRejectsBadSpec(t *testing.T) {
	for _, spec := range []string{"", "nonsense", "udp:127.0.0.1:9", "inet:"} {
		if ln, err := listenOn(spec); err == nil {
			_ = ln.Close()
			t.Errorf("listenOn(%q) accepted a bad spec", spec)
		}
	}
}

// --- flag surface ---------------------------------------------------------

func TestRequiresURL(t *testing.T) {
	if got := run([]string{"-listen", "inet:127.0.0.1:0"}); got != 2 {
		t.Fatalf("run without -url = %d, want 2", got)
	}
}

func TestVersionFlag(t *testing.T) {
	if got := run([]string{"-version"}); got != 0 {
		t.Fatalf("run -version = %d, want 0", got)
	}
}
