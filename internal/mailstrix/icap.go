package mailstrix

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"
)

const icapProtoVersion = "ICAP/1.0"

// processStart anchors monotonic elapsed-time measurements (time.Since carries
// the monotonic reading), so they survive a wall-clock step.
var processStart = time.Now()

// ListenAndServeICAP binds the ICAP TCP listener and serves until ctx is
// cancelled or the listener is closed. Safe to call concurrently with
// ListenAndServe. Returns nil when shut down cleanly.
func (s *Server) ListenAndServeICAP(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ICAPAddr)
	if err != nil {
		return fmt.Errorf("icap listen %s: %w", s.cfg.ICAPAddr, err)
	}
	s.icapLn.Store(&ln)
	s.logf("ICAP listening on %s", s.cfg.ICAPAddr)

	go func() {
		<-ctx.Done()
		_ = ln.Close() // #nosec G104 -- intentional shutdown; close error is not actionable here
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				s.icapWg.Wait()
				return nil
			default:
				return err
			}
		}
		s.acceptICAP(conn)
	}
}

// ShutdownICAP closes the ICAP listener and waits for in-flight connections to
// drain until ctx expires.
func (s *Server) ShutdownICAP(ctx context.Context) {
	if p := s.icapLn.Load(); p != nil {
		_ = (*p).Close() // #nosec G104 -- intentional shutdown; close error is not actionable here
	}
	done := make(chan struct{})
	go func() { s.icapWg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// acceptICAP takes a live-connection slot for conn and spawns its serve
// goroutine, or refuses conn when the cap is reached. The accept loop and the
// tests both go through here so the cap logic under test is the one that runs.
//
// The cap is applied *before* the goroutine is spawned: an accepted connection
// costs a goroutine, a read buffer and an fd from here on, which is exactly what
// a slow-loris pool exploits.
func (s *Server) acceptICAP(conn net.Conn) {
	select {
	case s.icapConns <- struct{}{}:
	default:
		s.refuseICAP(conn)
		return
	}
	s.icapWg.Add(1)
	go func() {
		defer s.icapWg.Done()
		defer func() { <-s.icapConns }()
		s.serveICAPConn(conn)
	}()
}

// refuseICAP answers a 503 and closes conn, off the accept goroutine.
//
// The write must not run inline: a refused client that never reads (zero window)
// would stall the write for the whole write deadline, and with the accept loop
// blocked behind it the refusal path would be a cheaper DoS than the connection
// flood the cap exists to stop. Refusal goroutines are themselves bounded, and
// past that bound the connection is dropped without a reply — RFC 3507 does not
// require the 503 to be delivered.
func (s *Server) refuseICAP(conn net.Conn) {
	s.metrics.icapBusy.Add(1)
	s.logRefusedICAP()

	select {
	case s.icapRefuse <- struct{}{}:
	default:
		_ = conn.Close()
		return
	}
	// Tracked by icapWg like a served connection, so ShutdownICAP does not report
	// "drained" while refusal goroutines still hold open fds mid-write. The write
	// deadline bounds the wait, so this cannot hang the drain.
	s.icapWg.Add(1)
	go func() {
		defer s.icapWg.Done()
		defer func() { <-s.icapRefuse }()
		defer func() { _ = conn.Close() }() // #nosec G104 -- refused conn; close error is not actionable
		_ = conn.SetWriteDeadline(time.Now().Add(icapRefuseWriteTimeout))
		_, _ = io.WriteString(conn, icapProtoVersion+" 503 Service Unavailable\r\nConnection: close\r\n\r\n")
	}()
}

// logRefusedICAP logs the cap being hit at most once per icapRefuseLogInterval.
// Unthrottled it is one synchronous stderr write per attacker connect, which
// fills the log volume and slows the accept loop. The exact count is in the
// icap_conn_refused_total metric.
func (s *Server) logRefusedICAP() {
	// Monotonic, not wall clock: an NTP step backwards would leave a wall-clock
	// stamp in the future, and the throttle would suppress the cap-reached line
	// for the whole skew — losing the only log signal precisely during a flood.
	now := int64(time.Since(processStart))
	last := s.icapRefuseLog.Load()
	if now-last < int64(icapRefuseLogInterval) {
		return
	}
	if !s.icapRefuseLog.CompareAndSwap(last, now) {
		return // another goroutine just logged it
	}
	s.errf("ICAP 503 busy (icap_max_conns=%d reached); refused=%d",
		s.cfg.ICAPMaxConns, s.metrics.icapBusy.Load())
}

func (s *Server) serveICAPConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		// Three deadlines, because "idle", "sending a head" and "sending a body"
		// have very different legitimate durations.
		//
		// Idle: a keep-alive proxy (Squid's icap_persistent_connections) holds a
		// pooled connection open between requests. Arming the short head deadline
		// here would tear that pool down every icapHeadTimeout, so we wait for the
		// first byte under the long idle deadline.
		_ = conn.SetDeadline(time.Now().Add(icapIdleTimeout))
		if _, err := br.Peek(1); err != nil {
			return
		}
		// A request has started. Head: a client that has begun a request but does
		// not finish the request line + headers is a slow-loris and must not hold a
		// live-connection slot for the whole body budget.
		_ = conn.SetDeadline(time.Now().Add(icapHeadTimeout))
		if err := s.handleICAPRequest(conn, br); err != nil {
			return
		}
		// Body: handleICAPRequest re-arms to the (legitimately slower) body
		// deadline once the head has parsed.
	}
}

// icapSection is one entry from the Encapsulated header.
type icapSection struct {
	name string // req-hdr, res-hdr, req-body, res-body, opt-body, null-body
}

const (
	// icapIdleTimeout bounds how long a connection may sit between requests. It
	// is generous because a keep-alive proxy legitimately pools idle connections.
	icapIdleTimeout = 5 * time.Minute
	// icapHeadTimeout bounds how long a connection that has *started* a request
	// may take to deliver a complete request line + header block. Bodies get the
	// longer BackendTimeout-derived deadline, re-armed once the head has parsed.
	icapHeadTimeout = 30 * time.Second
	// icapRefuseWriteTimeout bounds the 503 write on a refused connection.
	icapRefuseWriteTimeout = 5 * time.Second
	// icapRefuseLogInterval throttles the cap-reached log line.
	icapRefuseLogInterval = 10 * time.Second
	// icapMaxRefuseInflight bounds concurrent 503-refusal goroutines. Past it a
	// refused connection is closed without a reply.
	icapMaxRefuseInflight = 64
)

// deadlineSetter is satisfied by net.Conn. handleICAPRequest re-arms the read
// deadline after the head parses; a plain io.Writer (as in unit tests) simply
// skips that step.
type deadlineSetter interface{ SetDeadline(time.Time) error }

func (s *Server) handleICAPRequest(w io.Writer, br *bufio.Reader) error {
	line, err := readBoundedLine(br, maxICAPHeaderLine)
	if err != nil {
		if errors.Is(err, errICAPLineTooLong) {
			_, _ = io.WriteString(w, icapProtoVersion+" 400 Bad Request\r\n\r\n")
		}
		return err
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || parts[2] != icapProtoVersion {
		_, _ = io.WriteString(w, icapProtoVersion+" 400 Bad Request\r\n\r\n")
		return errors.New("bad ICAP request line")
	}

	method := parts[0]

	// No EOF tolerance: a head that never reaches its blank-line terminator is
	// truncated, not complete. Tolerating io.EOF here would hand handleICAPMod an
	// empty header set — no Encapsulated, no body — and it would answer 200 clean
	// for content it never read. Fail closed.
	hdr, err := readBoundedMIMEHeader(br)
	if err != nil {
		_, _ = io.WriteString(w, icapProtoVersion+" 400 Bad Request\r\n\r\n")
		return err
	}

	// Head is in. Re-arm with the body deadline: encapsulated headers and a
	// chunked body may legitimately take longer than icapHeadTimeout.
	if d, ok := w.(deadlineSetter); ok {
		_ = d.SetDeadline(time.Now().Add(s.cfg.BackendTimeout + 60*time.Second))
	}

	sections := parseICAPEncapsulated(hdr.Get("Encapsulated"))

	switch method {
	case "OPTIONS":
		return s.handleICAPOptions(w)
	case "REQMOD", "RESPMOD":
		return s.handleICAPMod(w, br, method, hdr, sections)
	default:
		_, _ = io.WriteString(w, icapProtoVersion+" 405 Method Not Allowed\r\n\r\n")
		return nil
	}
}

func (s *Server) handleICAPOptions(w io.Writer) error {
	s.metrics.icapOptions.Add(1)
	fp := s.engine.Fingerprint()
	istag := icapISTag(fp)
	var sb strings.Builder
	sb.WriteString(icapProtoVersion + " 200 OK\r\n")
	sb.WriteString("Methods: REQMOD, RESPMOD\r\n")
	sb.WriteString("ISTag: " + istag + "\r\n")
	sb.WriteString("Allow: 204\r\n")
	sb.WriteString("Preview: 0\r\n")
	sb.WriteString("Encapsulated: null-body=0\r\n")
	sb.WriteString("Options-TTL: 3600\r\n")
	sb.WriteString(fmt.Sprintf("Max-Connections: %d\r\n", s.cfg.ICAPMaxConns))
	sb.WriteString("Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT") + "\r\n")
	sb.WriteString("\r\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

// skipHTTPHeaders reads and discards lines from br until a blank line, consuming
// one complete HTTP header section (request/response line + headers + blank line).
// Used to skip encapsulated HTTP header sections inside an ICAP body.
func skipHTTPHeaders(br *bufio.Reader) error {
	for {
		line, err := readBoundedLine(br, maxICAPHeaderLine)
		if err != nil {
			return err
		}
		// Blank line (CR stripped by readBoundedLine → "") terminates the section.
		if line == "" {
			return nil
		}
	}
}

func (s *Server) handleICAPMod(w io.Writer, br *bufio.Reader, method string, hdr textproto.MIMEHeader, sections []icapSection) error {
	s.metrics.icapRequests.Add(1)

	allow204 := strings.Contains(hdr.Get("Allow"), "204")
	// hasPreview is true when the client sent a Preview header (even Preview: 0).
	// A preview read that returns ieof=false means MORE body follows and we MUST
	// send "100 Continue" to receive it (RFC 3507 §4.5). Without this, a proxy
	// that sends a 0-byte preview + full body continuation would get a false-negative
	// clean verdict because we'd scan only the empty preview bytes.
	hasPreview := hdr.Get("Preview") != ""

	// Count header sections that precede the body, then read past them.
	var hasBody bool
	hdrCount := 0
	for _, sec := range sections {
		switch sec.name {
		case "req-hdr", "res-hdr":
			hdrCount++
		case "req-body", "res-body", "opt-body":
			hasBody = true
		}
	}

	// Consume encapsulated HTTP header sections (not needed for scanning).
	// Encapsulated HTTP headers start with a request/status line (e.g. "HTTP/1.1 200 OK")
	// followed by MIME-style headers. We skip them by reading lines until a blank line,
	// which is simpler and more robust than textproto.ReadMIMEHeader (which would choke
	// on the leading request/status line).
	for i := 0; i < hdrCount; i++ {
		if herr := skipHTTPHeaders(br); herr != nil {
			_, _ = io.WriteString(w, icapProtoVersion+" 400 Bad Request\r\n\r\n")
			return herr
		}
	}

	// Read body (chunked per RFC 3507 §4.5).
	var buf []byte
	if hasBody {
		preview, ieof, readErr := readICAPChunkedBody(br, s.cfg.MaxBody)
		if errors.Is(readErr, errICAPBodyTooLarge) {
			_, _ = io.WriteString(w, icapProtoVersion+" 413 Request Entity Too Large\r\n\r\n")
			return readErr
		}
		if readErr != nil {
			_, _ = io.WriteString(w, icapProtoVersion+" 400 Bad Request\r\n\r\n")
			return readErr
		}
		buf = preview

		// RFC 3507 §4.5: if the request carried a Preview header and the terminal
		// chunk did NOT have the "ieof" extension, the preview is only partial.
		// We MUST send "100 Continue" to signal the client to send the rest, then
		// read the continuation chunk stream and append it. Without this, a proxy
		// (e.g. Squid) that sends a 0-byte preview before the real body would get
		// a false-negative clean verdict.
		if hasPreview && !ieof {
			if _, werr := io.WriteString(w, icapProtoVersion+" 100 Continue\r\n\r\n"); werr != nil {
				return werr
			}
			remaining := s.cfg.MaxBody - int64(len(buf))
			if remaining <= 0 {
				_, _ = io.WriteString(w, icapProtoVersion+" 413 Request Entity Too Large\r\n\r\n")
				return errICAPBodyTooLarge
			}
			cont, _, contErr := readICAPChunkedBody(br, remaining)
			if errors.Is(contErr, errICAPBodyTooLarge) {
				_, _ = io.WriteString(w, icapProtoVersion+" 413 Request Entity Too Large\r\n\r\n")
				return contErr
			}
			if contErr != nil {
				_, _ = io.WriteString(w, icapProtoVersion+" 400 Bad Request\r\n\r\n")
				return contErr
			}
			buf = append(buf, cont...)
		}
	}

	// Empty body — trivially clean.
	if len(buf) == 0 {
		if allow204 {
			_, err := io.WriteString(w, icapProtoVersion+" 204 No Modification\r\n\r\n")
			return err
		}
		return icapWrite200Clean(w, s.engine.Fingerprint())
	}

	// Admission gate (same budget as /scan). Bound the wait: the ICAP conn has no
	// request-scoped context like the HTTP path (server.go:476), so without a
	// timeout a stuck acquire on a dead follower pins an admission slot for the
	// full scan lifetime. BackendTimeout matches the scan budget.
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.BackendTimeout)
	defer cancel()
	if !s.acquireOn(ctx, s.admit) {
		s.metrics.busy.Add(1)
		s.errf("ICAP 503 busy (max_inflight=%d reached)", s.cfg.MaxInflight)
		_, _ = io.WriteString(w, icapProtoVersion+" 503 Service Unavailable\r\n\r\n")
		return errors.New("icap busy")
	}
	defer func() { <-s.admit }()

	t0 := time.Now()
	fp := s.engine.Fingerprint()
	icapMeta := ScanMeta{RawKey: streamDedupKey(buf)}
	key := fp + ":icap:" + string(icapMeta.RawKey[:])
	matches, cacheStatus := s.lookupOrScan(ctx, key, buf, icapMeta)
	actionable := actionableMatches(matches)

	if len(actionable) > 0 {
		s.metrics.icapInfected.Add(1)
		s.logf("ICAP %s %dB cache=%s %.1fms -> %d actionable matches %s", method, len(buf), cacheStatus, msSince(t0), len(actionable), ruleNames(actionable))
		return icapWriteInfected(w, fp, actionable)
	}
	if len(matches) > 0 {
		s.logf("ICAP %s %dB cache=%s %.1fms -> %d log-only matches %s", method, len(buf), cacheStatus, msSince(t0), len(matches), ruleNames(matches))
	} else {
		s.vlogf("ICAP %s %dB cache=%s %.1fms -> 0 matches", method, len(buf), cacheStatus, msSince(t0))
	}
	if allow204 {
		_, err := io.WriteString(w, icapProtoVersion+" 204 No Modification\r\n\r\n")
		return err
	}
	return icapWrite200Clean(w, fp)
}

// icapISTag produces a quoted ISTag from the engine fingerprint (≤32 chars).
func icapISTag(fp string) string {
	if len(fp) > 8 {
		fp = fp[:8]
	}
	return `"` + fp + `"`
}

// parseICAPEncapsulated parses the Encapsulated header value into an ordered
// slice of sections. Example: "req-hdr=0, res-hdr=412, res-body=1024".
func parseICAPEncapsulated(v string) []icapSection {
	var out []icapSection
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		i := strings.IndexByte(part, '=')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(part[:i])
		off, err := strconv.ParseInt(strings.TrimSpace(part[i+1:]), 10, 64)
		if err != nil {
			continue
		}
		_ = off // offset is parsed for validation only; sections are consumed by name
		out = append(out, icapSection{name: name})
	}
	return out
}

var errICAPBodyTooLarge = errors.New("ICAP body exceeds MaxBody limit")

var errICAPLineTooLong = errors.New("ICAP line exceeds length cap")

// Line caps bound every CRLF-terminated read so a missing '\n' cannot grow the
// buffer without bound. A legitimate chunk-size line is a few bytes; encapsulated
// HTTP header lines are larger (cookies, long URLs) but still bounded. Without
// these caps an attacker streams a multi-gigabyte line with no '\n' and the read
// buffers it all before the MaxBody check fires — unbounded per-connection memory
// on a fail-open service.
const (
	maxICAPChunkHeaderLine = 256
	maxICAPHeaderLine      = 8192
	// maxICAPHeaderCount and maxICAPHeaderBytes bound the ICAP request head as a
	// whole. Per-line caps alone let an attacker send unbounded *many* short
	// header lines; net/textproto would accumulate them all into one map.
	maxICAPHeaderCount = 128
	maxICAPHeaderBytes = 64 << 10
)

var (
	errICAPTooManyHeaders = errors.New("ICAP header count exceeds cap")
	errICAPHeadTooLarge   = errors.New("ICAP header block exceeds byte cap")
)

// isHTTPToken reports whether s is a non-empty RFC 7230 §3.2.6 token, the
// grammar a header field-name must satisfy.
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// readBoundedMIMEHeader reads a CRLF-terminated MIME header block with a cap on
// the length of each line, the number of header lines, and the total bytes of
// the block. It is the bounded replacement for textproto.Reader.ReadMIMEHeader,
// which applies none of these limits and will happily buffer an attacker's
// entire header stream. Continuation (obs-fold) lines are folded into the
// previous value, matching textproto's behaviour.
func readBoundedMIMEHeader(br *bufio.Reader) (textproto.MIMEHeader, error) {
	hdr := make(textproto.MIMEHeader)
	total := 0
	count := 0
	lastKey := ""
	for {
		line, err := readBoundedLine(br, maxICAPHeaderLine)
		if err != nil {
			return nil, err
		}
		if line == "" {
			return hdr, nil
		}
		total += len(line)
		if total > maxICAPHeaderBytes {
			return nil, errICAPHeadTooLarge
		}
		// Continuation line: append to the previous header's last value.
		if line[0] == ' ' || line[0] == '\t' {
			if lastKey == "" {
				return nil, errors.New("ICAP header continuation without a preceding header")
			}
			vals := hdr[lastKey]
			vals[len(vals)-1] += " " + strings.TrimSpace(line)
			hdr[lastKey] = vals
			continue
		}
		count++
		if count > maxICAPHeaderCount {
			return nil, errICAPTooManyHeaders
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, errors.New("malformed ICAP header line")
		}
		// Reject rather than repair. Whitespace between the field name and the
		// colon must be rejected (RFC 7230 §3.2.4) — trimming it is the classic
		// request-smuggling vector, because a downstream that does not trim sees a
		// different header set than we do. Likewise a name with a non-token byte:
		// textproto.CanonicalMIMEHeaderKey silently passes such keys through
		// unchanged instead of erroring, so an unvalidated name can collide with a
		// canonical one.
		if !isHTTPToken(key) {
			return nil, errors.New("invalid ICAP header name")
		}
		key = textproto.CanonicalMIMEHeaderKey(key)
		hdr[key] = append(hdr[key], strings.TrimSpace(value))
		lastKey = key
	}
}

// readBoundedLine reads one '\n'-terminated line, discarding a trailing '\r',
// capped at cap bytes. Returns errICAPLineTooLong if no '\n' arrives within cap.
func readBoundedLine(r *bufio.Reader, limit int) (string, error) {
	var sb strings.Builder
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return strings.TrimRight(sb.String(), "\r"), nil
		}
		if sb.Len() >= limit {
			return "", errICAPLineTooLong
		}
		sb.WriteByte(b)
	}
}

// readICAPChunkHeaderLine reads one CRLF-terminated chunk header, capped at
// maxICAPChunkHeaderLine bytes. Returns the line without the trailing CRLF.
func readICAPChunkHeaderLine(r *bufio.Reader) (string, error) {
	return readBoundedLine(r, maxICAPChunkHeaderLine)
}

// readICAPChunkedBody reads an ICAP chunked body (RFC 3507 §4.5) up to maxBytes.
// Each chunk: "<hex-size>[; ieof]\r\n<data>\r\n". Terminal chunk: "0\r\n\r\n".
//
// Returns (body, ieof, err).
//   - ieof=true  → the terminal 0-chunk carried the "ieof" extension: the preview
//     was the entire body and no continuation follows.
//   - ieof=false → the terminal 0-chunk had NO ieof extension: if this was a
//     preview read, the caller MUST send "ICAP/1.0 100 Continue\r\n\r\n" and
//     then read a second chunked stream to get the rest of the body.
func readICAPChunkedBody(r *bufio.Reader, maxBytes int64) ([]byte, bool, error) {
	var out []byte
	for {
		raw, err := readICAPChunkHeaderLine(r)
		if err != nil {
			return nil, false, err
		}
		// Detect and strip ICAP "ieof" extension: "3c; ieof" or "0 ; ieof"
		hasIEOF := false
		ext := raw
		if i := strings.IndexByte(raw, ';'); i >= 0 {
			ext = strings.TrimSpace(raw[:i])
			trailer := strings.ToLower(strings.TrimSpace(raw[i+1:]))
			hasIEOF = strings.Contains(trailer, "ieof")
		}
		size, err := strconv.ParseInt(strings.TrimSpace(ext), 16, 64)
		if err != nil {
			return nil, false, fmt.Errorf("bad ICAP chunk size %q: %w", raw, err)
		}
		// A chunk size is unsigned hex (RFC 3507 §4.5 / RFC 9112 §7.1). ParseInt
		// accepts a leading '-', so a hostile "-1\r\n" yields size<0, which skips
		// the size==0 and >maxBytes guards and reaches slices.Grow(out, negative)
		// → panic (a remote DoS). Reject any negative size up front.
		if size < 0 {
			return nil, false, fmt.Errorf("bad ICAP chunk size %q: negative", raw)
		}
		if size == 0 {
			// Terminal chunk — consume trailing CRLF (bounded).
			if _, err := readBoundedLine(r, maxICAPChunkHeaderLine); err != nil && !errors.Is(err, io.EOF) {
				return nil, false, err
			}
			return out, hasIEOF, nil
		}
		if int64(len(out))+size > maxBytes {
			return nil, false, errICAPBodyTooLarge
		}
		sizeInt := int(size)
		if int64(sizeInt) != size {
			return nil, false, errICAPBodyTooLarge
		}
		old := len(out)
		out = slices.Grow(out, sizeInt)
		out = out[:old+sizeInt]
		if _, err := io.ReadFull(r, out[old:]); err != nil {
			return nil, false, err
		}
		// Consume trailing CRLF after chunk data (bounded).
		if _, err := readBoundedLine(r, maxICAPChunkHeaderLine); err != nil {
			return nil, false, err
		}
	}
}

// icapWrite200Clean sends an ICAP 200 OK with an empty body (no modification)
// when the client did not advertise Allow: 204.
func icapWrite200Clean(w io.Writer, fp string) error {
	body := "clean\r\n"
	resHdr := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	chunkHex := strconv.FormatInt(int64(len(body)), 16)
	var sb strings.Builder
	sb.WriteString(icapProtoVersion + " 200 OK\r\n")
	sb.WriteString("ISTag: " + icapISTag(fp) + "\r\n")
	sb.WriteString(fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr)))
	sb.WriteString("\r\n")
	sb.WriteString(resHdr)
	sb.WriteString(chunkHex + "\r\n")
	sb.WriteString(body)
	sb.WriteString("\r\n0\r\n\r\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

// icapWriteInfected sends an ICAP 200 OK with a 403 Forbidden replacement body.
func icapWriteInfected(w io.Writer, fp string, matches []Match) error {
	threat := matches[0].Rule
	body := "Blocked: " + threat + "\r\n"
	resHdr := "HTTP/1.1 403 Forbidden\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"X-Infection-Found: Type=0; Resolution=2; Threat=" + threat + ";\r\n" +
		"\r\n"
	chunkHex := strconv.FormatInt(int64(len(body)), 16)
	var sb strings.Builder
	sb.WriteString(icapProtoVersion + " 200 OK\r\n")
	sb.WriteString("ISTag: " + icapISTag(fp) + "\r\n")
	sb.WriteString("X-Infection-Found: Type=0; Resolution=2; Threat=" + threat + ";\r\n")
	sb.WriteString(fmt.Sprintf("X-Violations-Found: %d\r\n", len(matches)))
	sb.WriteString(fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr)))
	sb.WriteString("\r\n")
	sb.WriteString(resHdr)
	sb.WriteString(chunkHex + "\r\n")
	sb.WriteString(body)
	sb.WriteString("\r\n0\r\n\r\n")
	_, err := io.WriteString(w, sb.String())
	return err
}
