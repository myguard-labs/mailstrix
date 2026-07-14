package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	milter "github.com/emersion/go-milter"

	"github.com/myguard-labs/mailstrix/internal/verdict"
)

// stampedHeader is one header the milter asked to add, with the value EXACTLY as
// the production path produced it (already sanitised — that is the point).
// go-milter's *Modifier is a struct with unexported fields and no interface, so
// a test cannot construct a working one; the stamp/strip seams record the calls.
type stampedHeader struct{ name, value string }

// strippedHeader is one inbound header the milter asked the MTA to delete.
type strippedHeader struct {
	index int
	name  string
}

// stripped is the recorder for the current milter under test. Package-level
// because newTestMilter's signature predates it; each newTestMilter call resets it.
var stripped *[]strippedHeader

// newTestMilter builds the milter under test with its header sink redirected
// into a slice.
func newTestMilter(t *testing.T, cfg config) (*strixMilter, *[]stampedHeader, *strings.Builder) {
	t.Helper()
	var logbuf strings.Builder
	stripped = &[]strippedHeader{}
	s := &strixMilter{
		cfg:    cfg,
		client: verdict.NewClient(cfg.url, cfg.token, "strix-milter/test", cfg.timeout),
		log:    log.New(&logbuf, "", 0),
	}
	stamped := &[]stampedHeader{}
	// Record the value EXACTLY as Body() passes it. Sanitising here instead would
	// make the injection tests prove only that sanitizeHeaderValue works, never
	// that the production stamping path calls it — the guard could then be deleted
	// from Body() with CI still green.
	s.stamp = func(name, value string) {
		*stamped = append(*stamped, stampedHeader{name, value})
	}
	s.strip = func(index int, name string) {
		*stripped = append(*stripped, strippedHeader{index, name})
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

// feed drives one complete message through the milter the way an MTA does:
// Header() per header line, Headers() at end-of-headers, BodyChunk() in <=64 KiB
// chunks, then Body() at end-of-message.
func feed(t *testing.T, s *strixMilter, hdrs [][2]string, body []byte) milter.Response {
	t.Helper()
	for _, h := range hdrs {
		if _, err := s.Header(h[0], h[1], nil); err != nil {
			t.Fatalf("Header: %v", err)
		}
	}
	if _, err := s.Headers(nil, nil); err != nil {
		t.Fatalf("Headers: %v", err)
	}
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

// feedBody drives a message with a minimal header block.
func feedBody(t *testing.T, s *strixMilter, body []byte) milter.Response {
	t.Helper()
	return feed(t, s, [][2]string{{"Subject", "test"}}, body)
}

// --- the contract: ALWAYS ACCEPT ------------------------------------------

func TestCleanMessageIsAcceptedAndStampedClean(t *testing.T) {
	srv := scanStub(t, nil, http.StatusOK)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	if got := feedBody(t, s, []byte("hello")); got != milter.RespAccept {
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

	got := feedBody(t, s, []byte("evil"))
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

	if got := feedBody(t, s, []byte("hello")); got != milter.RespAccept {
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

	if got := feedBody(t, s, []byte("hello")); got != milter.RespAccept {
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
	if got := feedBody(t, s, []byte("hello")); got != milter.RespAccept {
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

	// End the (empty) header block first, then 3 body chunks of 8: with a 16-byte
	// cap the CRLF (2) + two chunks fit, and the third overflows.
	if _, err := s.Headers(nil, nil); err != nil {
		t.Fatalf("Headers: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.BodyChunk([]byte(strings.Repeat("A", 8)), nil); err != nil {
			t.Fatalf("BodyChunk: %v", err)
		}
	}
	if !s.oversize {
		t.Fatal("the third chunk pushed the message over max-body but oversize was not latched")
	}
	if s.msg != nil {
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
	// Accumulate to EXACTLY the cap across several chunks (the multi-chunk
	// arithmetic is the load-bearing path — see the oversize test), and assert the
	// whole thing is still scanned rather than tripping the guard one byte early.
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = len(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	cfg := baseCfg(srv.URL)
	cfg.maxBody = 34 // 2 bytes of CRLF (empty header block) + 32 body bytes
	s, stamped, _ := newTestMilter(t, cfg)

	if _, err := s.Headers(nil, nil); err != nil {
		t.Fatalf("Headers: %v", err)
	}
	for i := 0; i < 4; i++ { // 4 x 8 = 32, landing exactly on the cap
		if _, err := s.BodyChunk([]byte(strings.Repeat("A", 8)), nil); err != nil {
			t.Fatalf("BodyChunk: %v", err)
		}
	}
	if s.oversize {
		t.Fatal("a message landing EXACTLY on max-body was wrongly refused (off-by-one)")
	}
	if _, err := s.Body(nil); err != nil {
		t.Fatalf("Body: %v", err)
	}
	if got != 34 {
		t.Fatalf("scanner received %d bytes, want the full 34", got)
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

	feedBody(t, s, []byte("hello"))
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

	feedBody(t, s, []byte("x"))
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
		{"a\r\nb", "a??b"},
		{"a\x00b", "a?b"},
		{"  padded  ", "padded"},
	} {
		if got := sanitizeHeaderValue(tc.in); got != tc.want {
			t.Errorf("sanitizeHeaderValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestInboundForgedHeaderIsDeletedNotJustLogged(t *testing.T) {
	// A sender who ships their own "X-Mailstrix-Status: clean" must not be able to
	// make a downstream FIRST-MATCH header lookup (net/mail, textproto.Get, most
	// MUA/Sieve implementations) read their verdict instead of ours. Appending our
	// own header after theirs is NOT enough — theirs has to go.
	srv := scanStub(t, []verdict.Match{{Rule: "Win32_Evil"}}, http.StatusOK)
	s, stamped, logbuf := newTestMilter(t, baseCfg(srv.URL))

	feed(t, s, [][2]string{
		{"Subject", "hi"},
		{"X-Mailstrix-Status", "clean"},
		{"X-Mailstrix-Rules", ""},
	}, []byte("evil"))

	if len(*stripped) != 2 {
		t.Fatalf("stripped = %+v, want both forged headers deleted", *stripped)
	}
	for _, h := range *stripped {
		if !strings.HasPrefix(strings.ToLower(h.name), strings.ToLower(headerPrefix)) {
			t.Fatalf("stripped a header that was not ours to strip: %+v", h)
		}
		if h.index < 1 {
			t.Fatalf("ChangeHeader index is 1-based per name, got %+v", h)
		}
	}
	if !strings.Contains(logbuf.String(), "WARNING") {
		t.Fatalf("a forged header must also be logged loudly, got %q", logbuf.String())
	}
	// Our real verdict still lands.
	if v, _ := headerValue(*stamped, hdrStatus); v != statusInfected {
		t.Fatalf("%s = %q, want infected", hdrStatus, v)
	}
}

func TestForgedHeaderIsNotFedToTheScanner(t *testing.T) {
	// The forged header must not be part of what we hand strixd either.
	var posted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	s, _, _ := newTestMilter(t, baseCfg(srv.URL))
	feed(t, s, [][2]string{{"X-Mailstrix-Status", "clean"}, {"Subject", "hi"}}, []byte("x"))

	if strings.Contains(string(posted), "X-Mailstrix-Status") {
		t.Fatalf("the forged header was fed to the scanner: %q", posted)
	}
}

func TestMultipleForgedCopiesAreAllDeletedHighestIndexFirst(t *testing.T) {
	// ChangeHeader's index is per NAME. Deleting index 1 first would renumber the
	// rest, so the second delete would hit the wrong (or a nonexistent) header.
	srv := scanStub(t, nil, http.StatusOK)
	s, _, _ := newTestMilter(t, baseCfg(srv.URL))

	feed(t, s, [][2]string{
		{"X-Mailstrix-Status", "clean"},
		{"X-Mailstrix-Status", "clean"},
		{"X-Mailstrix-Status", "clean"},
	}, []byte("x"))

	if len(*stripped) != 3 {
		t.Fatalf("stripped = %+v, want all 3 copies deleted", *stripped)
	}
	for i, want := range []int{3, 2, 1} {
		if (*stripped)[i].index != want {
			t.Fatalf("delete #%d used index %d, want %d — deleting low-to-high renumbers the rest",
				i, (*stripped)[i].index, want)
		}
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

	feedBody(t, s, []byte("x"))
	v, ok := headerValue(*stamped, hdrRules)
	if !ok {
		t.Fatal("expected a rules header")
	}
	if len(v) > maxHeaderValueLen {
		t.Fatalf("%s is %d bytes, over the %d-byte header cap — an over-long header line can be rejected by the MTA", hdrRules, len(v), maxHeaderValueLen)
	}
	// The "(+N more)" tail must SURVIVE the header cap: a truncated list that
	// looks complete is worse than one that admits it was cut.
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
	if s.msg != nil || s.oversize || s.subject != "" {
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
	feedBody(t, s, []byte("first"))
	feedBody(t, s, []byte("second"))

	if len(bodies) != 2 {
		t.Fatalf("want 2 scans, got %d", len(bodies))
	}
	if !strings.HasSuffix(bodies[0], "first") || !strings.HasSuffix(bodies[1], "second") {
		t.Fatalf("bodies = %q — per-message state leaked between messages", bodies)
	}
	if strings.Contains(bodies[1], "first") {
		t.Fatalf("message 2 still carries message 1's bytes: %q", bodies[1])
	}
}

func TestTotallyEmptyMessageIsUnknownNotClean(t *testing.T) {
	// Nothing at all was buffered => nothing was scanned => "unknown", never a
	// clean bill of health for bytes we never looked at.
	srv := scanStub(t, nil, http.StatusOK)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	got, err := s.Body(nil) // no Header/Headers/BodyChunk at all
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if got != milter.RespAccept {
		t.Fatalf("response = %v, want RespAccept", got)
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusUnknown {
		t.Fatalf("%s = %q, want %q — nothing was scanned, so it is not known-clean", hdrStatus, v, statusUnknown)
	}
}

func TestHeadersOnlyMessageIsStillScanned(t *testing.T) {
	// A body-less message still has headers, and those headers ARE the message.
	// It must be scanned, not written off as "empty".
	var posted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))
	feed(t, s, [][2]string{{"Subject", "hi"}}, nil)

	if !strings.Contains(string(posted), "Subject: hi") {
		t.Fatalf("scanner got %q, want the header block", posted)
	}
	if v, _ := headerValue(*stamped, hdrStatus); v != statusClean {
		t.Fatalf("%s = %q, want clean", hdrStatus, v)
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
	// An ORPHANED socket (bound, then the process died without unlinking) must be
	// cleared, or we could never restart.
	sock := filepath.Join(t.TempDir(), "m.sock")
	orphan, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	// Close the listener but leave the socket FILE behind, exactly as an unclean
	// shutdown does. (Go's unix listener unlinks on Close, so re-create the inode.)
	_ = orphan.Close()
	if _, err := os.Stat(sock); os.IsNotExist(err) {
		l2, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		f, _ := l2.(*net.UnixListener)
		f.SetUnlinkOnClose(false)
		_ = l2.Close()
	}
	if fi, err := os.Lstat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Skip("could not stage an orphaned socket on this platform")
	}

	ln, err := listenOn("unix:" + sock)
	if err != nil {
		t.Fatalf("listenOn did not clear an orphaned socket: %v", err)
	}
	_ = ln.Close()
}

func TestListenOnRefusesToDeleteANonSocketFile(t *testing.T) {
	// A typo in -listen (pointing at, say, an env file) must NOT make us delete an
	// operator's file. The old dial-probe could not tell "not a socket" from
	// "stale socket" and would unlink it.
	f := filepath.Join(t.TempDir(), "strix-milter.env")
	if err := os.WriteFile(f, []byte("MAILSTRIX_URL=http://x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenOn("unix:" + f); err == nil {
		_ = ln.Close()
		t.Fatal("listenOn accepted a non-socket path")
	}
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("listenOn DELETED an operator file that was not a socket: %v", err)
	}
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

// --- the message we scan: headers MUST be included (the BLOCKER) -----------

func TestScannedMessageIncludesHeadersAndMIMEFraming(t *testing.T) {
	// The milter protocol hands us headers and body separately. Posting only the
	// body would strip Content-Type/boundary/Content-Transfer-Encoding — exactly
	// the framing strixd's extractor needs to find an attachment. strix-scan posts
	// the whole .eml; so must we, or the two clients feed the scanner different
	// things and every name/MIME-keyed rule silently goes dead behind the milter.
	var posted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	s, _, _ := newTestMilter(t, baseCfg(srv.URL))
	feed(t, s, [][2]string{
		{"From", "a@example.com"},
		{"Subject", "invoice"},
		{"Content-Type", `multipart/mixed; boundary="XYZ"`},
	}, []byte("--XYZ\r\nContent-Disposition: attachment; filename=\"x.docm\"\r\n\r\nPK\x03\x04\r\n--XYZ--\r\n"))

	got := string(posted)
	for _, want := range []string{
		"From: a@example.com",
		"Subject: invoice",
		`Content-Type: multipart/mixed; boundary="XYZ"`,
		"filename=\"x.docm\"",
		"PK\x03\x04",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("scanned message is missing %q — the scanner never sees it.\ngot: %q", want, got)
		}
	}
	// The blank line that separates headers from body: without it this is not a
	// parseable RFC 5322 message.
	if !strings.Contains(got, "\r\n\r\n") {
		t.Fatalf("no header/body separator in the scanned message: %q", got)
	}
	if strings.Index(got, "From:") > strings.Index(got, "PK") {
		t.Fatal("headers must come BEFORE the body")
	}
}

func TestScanSendsAFilenameSoNameKeyedRulesFire(t *testing.T) {
	var gotName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotName = r.Header.Get("X-MAILSTRIX-Filename")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	s, _, _ := newTestMilter(t, baseCfg(srv.URL))
	feedBody(t, s, []byte("x"))

	want := base64.StdEncoding.EncodeToString([]byte(scanFilename))
	if gotName != want {
		t.Fatalf("X-MAILSTRIX-Filename = %q, want %q (%s)", gotName, want, scanFilename)
	}
}

// --- sanitisation happens on the PRODUCTION path ---------------------------

func TestBodySanitisesBeforeStamping(t *testing.T) {
	// The seam records the RAW value Body() passes. If Body() stopped sanitising,
	// the CR/LF would arrive here — which is precisely the mutation the old test
	// could not see, because the recorder used to sanitise on the test's behalf.
	srv := scanStub(t, []verdict.Match{
		{Rule: "evil\r\nX-Spam-Flag: NO", Meta: map[string]string{"family": "bad\nX-Forged: yes"}},
	}, http.StatusOK)
	s, stamped, _ := newTestMilter(t, baseCfg(srv.URL))

	feedBody(t, s, []byte("x"))

	if len(*stamped) == 0 {
		t.Fatal("nothing stamped")
	}
	for _, h := range *stamped {
		if strings.ContainsAny(h.value, "\r\n\x00") {
			t.Fatalf("Body() stamped an UNSANITISED value for %s: %q — header injection", h.name, h.value)
		}
	}
}

func TestSanitizeClampsToPrintableASCIIAndCaps(t *testing.T) {
	// A raw 8-bit or control byte in a header field body is illegal on a
	// non-SMTPUTF8 transport (RFC 5322 2.2): emitting one could make a downstream
	// MTA reject the very message we promised to accept.
	got := sanitizeHeaderValue("caf\u00e9\ttab\x1besc")
	for i := 0; i < len(got); i++ {
		if got[i] < 0x20 || got[i] > 0x7e {
			t.Fatalf("sanitized value still holds a non-printable-ASCII byte %#x: %q", got[i], got)
		}
	}
	long := sanitizeHeaderValue(strings.Repeat("A", maxHeaderValueLen*3))
	if len(long) > maxHeaderValueLen+8 {
		t.Fatalf("value not capped: %d bytes (an over-long header line can be rejected by the MTA)", len(long))
	}
}

func TestTruncateDoesNotSplitARune(t *testing.T) {
	s := strings.Repeat("\u00e9", 100) // 2 bytes each
	if got := truncate(s, 15); !utf8.ValidString(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
}

// --- connection cap --------------------------------------------------------

func TestLimitListenerCapsConcurrentConnections(t *testing.T) {
	// Each in-flight message buffers up to max-body. Unbounded connections =
	// unbounded memory = OOM = restart = (with milter_default_action=accept) a
	// window in which mail is delivered UNSCANNED. Cap the accepts.
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()

	ln := limitListener(base, 2)
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	var dialed []net.Conn
	defer func() {
		for _, c := range dialed {
			_ = c.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		dialed = append(dialed, c)
	}

	var held []net.Conn
	for i := 0; i < 2; i++ {
		select {
		case c := <-accepted:
			held = append(held, c)
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d connections accepted, want 2", i)
		}
	}
	// The 3rd must NOT be accepted while both slots are held.
	select {
	case <-accepted:
		t.Fatal("accepted a 3rd connection despite a cap of 2 — the cap is inert")
	case <-time.After(200 * time.Millisecond):
	}
	// Free a slot; now it comes through.
	_ = held[0].Close()
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("closing a connection did not free a slot — the cap leaks and will wedge")
	}
	_ = held[1].Close()
}

// --- negotiated milter options --------------------------------------------

func TestNegotiatedActionsIncludeChangeHeader(t *testing.T) {
	// Body() deletes forged inbound X-Mailstrix-* headers with ChangeHeader. The
	// MTA refuses any action that was not negotiated, so without OptChangeHeader
	// every one of those deletes is a silent no-op on the wire and the anti-forgery
	// guard is inert — while still looking present in the code.
	if milterActions&milter.OptChangeHeader == 0 {
		t.Fatal("OptChangeHeader is not negotiated — the forged-header deletes cannot take effect")
	}
	if milterActions&milter.OptAddHeader == 0 {
		t.Fatal("OptAddHeader is not negotiated — the verdict headers cannot be stamped")
	}
	// We must NOT hold power we never use: no body rewrite, no recipient change,
	// no quarantine. The milter's whole contract is that it only ever reports.
	for _, forbidden := range []struct {
		bit  milter.OptAction
		name string
	}{
		{milter.OptQuarantine, "OptQuarantine"},
		{milter.OptChangeBody, "OptChangeBody"},
		{milter.OptAddRcpt, "OptAddRcpt"},
		{milter.OptRemoveRcpt, "OptRemoveRcpt"},
		{milter.OptChangeFrom, "OptChangeFrom"},
	} {
		if milterActions&forbidden.bit != 0 {
			t.Errorf("%s is negotiated — this milter must only ever ADD headers and DELETE its own", forbidden.name)
		}
	}
}

func TestProtocolKeepsHeadersEOHAndBody(t *testing.T) {
	// All three feed the message we reassemble. Suppressing any of them would
	// silently shrink what the scanner sees.
	for _, suppressed := range []struct {
		bit  milter.OptProtocol
		name string
	}{
		{milter.OptNoHeaders, "OptNoHeaders"},
		{milter.OptNoEOH, "OptNoEOH"},
		{milter.OptNoBody, "OptNoBody"},
	} {
		if milterProtocol&suppressed.bit != 0 {
			t.Errorf("%s is set — the scanner would not see part of the message", suppressed.name)
		}
	}
}

// --- the PRODUCTION path is capped (not just the primitive) ----------------

func TestServerListenerAppliesTheConnectionCap(t *testing.T) {
	// Testing limitListener() alone proves only that the primitive works: the wrap
	// could be dropped out of the production path with the whole suite still green
	// (it was, and CI stayed green). Assert the cap on the listener serve() runs on.
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()

	cfg := baseCfg("http://127.0.0.1:1")
	cfg.maxConns = 3

	ln := serverListener(base, cfg)
	if got := effectiveCap(ln); got != 3 {
		t.Fatalf("the production listener is capped at %d, want 3 — the connection cap is not wired in", got)
	}
}

func TestEffectiveCapReportsZeroForAnUncappedListener(t *testing.T) {
	// The startup log prints effectiveCap(), so a missing wrap must NOT keep
	// claiming a cap is in force.
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	if got := effectiveCap(base); got != 0 {
		t.Fatalf("effectiveCap(uncapped) = %d, want 0", got)
	}
}

// --- joinRules edge cases ---------------------------------------------------

func TestJoinRulesAlwaysNamesAtLeastOneRule(t *testing.T) {
	// A single pathologically long rule name must not produce a header that is
	// nothing but "(+N more)" — the operator would lose every name.
	rules := []string{strings.Repeat("R", maxRuleHeaderLen+100), "second", "third"}
	got := joinRules(rules)
	if !strings.HasPrefix(got, "R") {
		t.Fatalf("joinRules = %q, want it to still name the first rule", got)
	}
	if !strings.Contains(got, "more)") {
		t.Fatalf("joinRules = %q, want it to admit it truncated", got)
	}
	if len(sanitizeHeaderValue(got)) > maxHeaderValueLen {
		t.Fatalf("joinRules produced %d bytes, over the header cap", len(sanitizeHeaderValue(got)))
	}
}

func TestJoinRulesTailSurvivesTheHeaderCapAtLargeN(t *testing.T) {
	var rules []string
	for i := 0; i < 10000; i++ {
		rules = append(rules, fmt.Sprintf("rule_%05d", i))
	}
	got := sanitizeHeaderValue(joinRules(rules))
	if !strings.Contains(got, "more)") {
		t.Fatalf("the (+N more) tail was clipped by the header cap: %q", got)
	}
}

// --- a body chunk arriving before end-of-headers ---------------------------

func TestBodyBeforeEOHStillGetsAHeaderSeparator(t *testing.T) {
	// Without the blank line the body is concatenated onto the last header line
	// and parsed as its continuation — a silently corrupted message.
	var posted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	s, _, _ := newTestMilter(t, baseCfg(srv.URL))
	if _, err := s.Header("Subject", "hi", nil); err != nil {
		t.Fatal(err)
	}
	// NOTE: no Headers() call — go straight to the body.
	if _, err := s.BodyChunk([]byte("BODY"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Body(nil); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(posted), "\r\n\r\nBODY") {
		t.Fatalf("no header/body separator: %q — BODY would parse as a Subject continuation", posted)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(posted)))
	if err != nil {
		t.Fatalf("the scanned message does not parse as RFC 5322: %v", err)
	}
	if got := msg.Header.Get("Subject"); got != "hi" {
		t.Fatalf("Subject = %q, want %q — the body leaked into the header", got, "hi")
	}
}

// --- the reassembled message really is a parseable MIME message ------------

func TestScannedMessageParsesAsMIMEWithTheAttachment(t *testing.T) {
	var posted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(verdict.Response{})
	}))
	t.Cleanup(srv.Close)

	s, _, _ := newTestMilter(t, baseCfg(srv.URL))
	feed(t, s, [][2]string{
		{"From", "a@example.com"},
		{"Subject", "invoice"},
		{"Content-Type", `multipart/mixed; boundary="XYZ"`},
	}, []byte("--XYZ\r\nContent-Disposition: attachment; filename=\"x.docm\"\r\n\r\nPK\x03\x04payload\r\n--XYZ--\r\n"))

	msg, err := mail.ReadMessage(strings.NewReader(string(posted)))
	if err != nil {
		t.Fatalf("scanned message is not RFC 5322: %v\ngot: %q", err, posted)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("Content-Type = %q (%v) — the extractor cannot see this is multipart", mt, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	part, err := mr.NextPart()
	if err != nil {
		t.Fatalf("no MIME part: %v", err)
	}
	if got := part.FileName(); got != "x.docm" {
		t.Fatalf("attachment filename = %q, want x.docm — name-keyed rules would not fire", got)
	}
	body, _ := io.ReadAll(part)
	if !strings.Contains(string(body), "PK\x03\x04") {
		t.Fatalf("attachment payload missing: %q", body)
	}
}

func TestServeActuallyServesACappedListener(t *testing.T) {
	// The one that matters: not "does serverListener cap?" but "does serve() run on
	// a capped listener?". Dropping the wrap from serve() left every other test
	// green — a guard present in the code and inert on the path that matters.
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan net.Listener, 1)
	serveListenerHook = func(ln net.Listener) { got <- ln }
	t.Cleanup(func() { serveListenerHook = nil })

	cfg := baseCfg("http://127.0.0.1:1")
	cfg.maxConns = 5
	cfg.listen = "inet:" + base.Addr().String()

	done := make(chan int, 1)
	go func() { done <- serve(base, cfg, log.New(io.Discard, "", 0)) }()

	var served net.Listener
	select {
	case served = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("serve() never reached its listener")
	}

	if n := effectiveCap(served); n != 5 {
		t.Fatalf("serve() is running on a listener capped at %d, want 5 — the connection cap is NOT wired into the production path", n)
	}

	_ = base.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve() did not return after the listener closed")
	}
}
