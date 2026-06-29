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
		s.icapWg.Add(1)
		go func() {
			defer s.icapWg.Done()
			s.serveICAPConn(conn)
		}()
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

func (s *Server) serveICAPConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		deadline := time.Now().Add(s.cfg.BackendTimeout + 60*time.Second)
		_ = conn.SetDeadline(deadline)
		if err := s.handleICAPRequest(conn, br); err != nil {
			return
		}
	}
}

// icapSection is one entry from the Encapsulated header.
type icapSection struct {
	name   string // req-hdr, res-hdr, req-body, res-body, opt-body, null-body
	offset int64
}

func (s *Server) handleICAPRequest(w io.Writer, br *bufio.Reader) error {
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return err
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || parts[2] != icapProtoVersion {
		_, _ = io.WriteString(w, icapProtoVersion+" 400 Bad Request\r\n\r\n")
		return errors.New("bad ICAP request line")
	}

	method := parts[0]

	hdr, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		_, _ = io.WriteString(w, icapProtoVersion+" 400 Bad Request\r\n\r\n")
		return err
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
	sb.WriteString(fmt.Sprintf("Max-Connections: %d\r\n", s.cfg.MaxInflight))
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
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		// Blank line (CRLF or bare LF) terminates the HTTP header section.
		if line == "\r\n" || line == "\n" {
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

	// Admission gate (same budget as /scan).
	ctx := context.Background()
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

	if len(matches) > 0 {
		s.metrics.icapInfected.Add(1)
		s.logf("ICAP %s %dB cache=%s %.1fms -> %d matches %s", method, len(buf), cacheStatus, msSince(t0), len(matches), ruleNames(matches))
		return icapWriteInfected(w, fp, matches)
	}
	s.vlogf("ICAP %s %dB cache=%s %.1fms -> 0 matches", method, len(buf), cacheStatus, msSince(t0))
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
		out = append(out, icapSection{name: name, offset: off})
	}
	return out
}

var errICAPBodyTooLarge = errors.New("ICAP body exceeds MaxBody limit")

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
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, false, err
		}
		raw := strings.TrimRight(line, "\r\n")
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
		if size == 0 {
			// Terminal chunk — consume trailing CRLF.
			_, _ = r.ReadString('\n')
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
		// Consume trailing CRLF after chunk data.
		_, _ = r.ReadString('\n')
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
