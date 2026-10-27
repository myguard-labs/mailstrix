package extract

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
)

const (
	// maxMIMEParts bounds the leaf parts walked across one message, so a
	// message stuffed with thousands of tiny parts cannot spend the scan.
	maxMIMEParts = 256
	// maxMIMEHeaderBytes bounds top-level message classification. Real-world
	// trace headers can exceed the former 16 KiB sniff window, while an
	// unbounded search would let an unterminated header consume the full input.
	// A terminator whose final byte is exactly at this limit is accepted.
	maxMIMEHeaderBytes   = 256 << 10
	mimeHeaderCapHitKind = "mime-header"
)

type mimeHeaderClassification uint8

const (
	mimeHeaderOrdinary mimeHeaderClassification = iota
	mimeHeaderComplete
	mimeHeaderIncomplete
)

func isMIMEContextHeader(field string) bool {
	if strings.HasPrefix(field, "x-") || strings.HasPrefix(field, "arc-") {
		return true
	}
	switch field {
	case "mime-version", "from", "to", "cc", "bcc", "subject", "date", "received",
		"message-id", "return-path", "reply-to", "sender", "delivered-to",
		"dkim-signature", "authentication-results":
		return true
	default:
		return false
	}
}

// isMIMEMessage reports whether buf starts with an RFC 5322 header block that
// declares a MIME Content-Type (COR-01). It needs a Content-Type header plus
// one other message header, all before the first blank line, so ordinary
// text that happens to contain "Content-Type:" is not taken for a message.
func isMIMEMessage(buf []byte) bool {
	return classifyMIMEMessage(buf) == mimeHeaderComplete
}

// classifyMIMEMessage incrementally validates header lines within the fixed
// top-level header budget. A syntactically plausible message that exhausts the
// budget or input before its blank-line terminator is incomplete, not ordinary
// text, so callers can keep a clean verdict out of the cache.
func classifyMIMEMessage(buf []byte) mimeHeaderClassification {
	head := buf
	truncated := len(head) > maxMIMEHeaderBytes
	if truncated {
		head = head[:maxMIMEHeaderBytes]
	}
	headerEnd := -1
	if end := bytes.Index(head, []byte("\n\r\n")); end >= 0 {
		headerEnd = end + 1
	}
	if end := bytes.Index(head, []byte("\n\n")); end >= 0 && (headerEnd < 0 || end+1 < headerEnd) {
		headerEnd = end + 1
	}
	terminated := headerEnd >= 0
	if terminated {
		head = head[:headerEnd]
		truncated = false
	}
	var hasType, hasOther, hasContext bool
	for len(head) > 0 {
		line := head
		completeLine := true
		if end := bytes.IndexByte(head, '\n'); end >= 0 {
			line = head[:end]
			head = head[end+1:]
		} else {
			head = nil
			completeLine = !truncated
		}
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' { // folded continuation line
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || bytes.ContainsAny(line[:colon], " \t") {
			if !completeLine {
				break // the cap split ordinary text rather than a header field
			}
			return mimeHeaderOrdinary // not a header line: not a header block
		}
		field := strings.ToLower(string(line[:colon]))
		if field == "content-type" {
			if !completeLine {
				// The field value may be cut off, but a syntactically valid
				// media type prefix is enough to prove a MIME-like prefix.
				mediaType := bytes.TrimSpace(bytes.SplitN(line[colon+1:], []byte(";"), 2)[0])
				if slash := bytes.IndexByte(mediaType, '/'); slash > 0 {
					probe := string(mediaType)
					if slash == len(mediaType)-1 {
						probe += "x"
					}
					if _, _, err := mime.ParseMediaType(probe); err == nil {
						return mimeHeaderIncomplete
					}
				}
				if hasOther {
					return mimeHeaderIncomplete
				}
				return mimeHeaderOrdinary
			}
			hasType = true
		} else {
			hasOther = true
			hasContext = hasContext || isMIMEContextHeader(field)
		}
		if !completeLine {
			break
		}
	}
	if terminated {
		if hasType && hasOther {
			return mimeHeaderComplete
		}
		return mimeHeaderOrdinary
	}
	if truncated && (hasContext || hasType && hasOther) {
		// Content-Type may be the first complete field beyond the bounded
		// prefix. A valid message-header prefix cannot safely fall through as
		// ordinary text merely because that field lies past the cap.
		return mimeHeaderIncomplete
	}
	if hasType && hasOther {
		return mimeHeaderIncomplete
	}
	return mimeHeaderOrdinary
}

// fromMIME walks an RFC 5322 message (COR-01): multipart bodies are split,
// base64 and quoted-printable parts are decoded, and each leaf part is emitted
// and dispatched through extractChild, so an attachment is unpacked like the
// same file submitted on its own. message/rfc822 parts recurse. The walk is
// bounded by maxMIMEParts, the nest depth, the shared archive budget and the
// deadline; a malformed message keeps whatever parts decoded before the error.
func fromMIME(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	defer func() {
		if recover() != nil {
			res.Panicked = true
		}
	}()
	parts := 0
	walkMIMEMessage(buf, res, b, depth, deadline, &parts, true)
}

func walkMIMEMessage(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time, parts *int, completeAncestor bool) {
	msg, err := mail.ReadMessage(bytes.NewReader(buf))
	if err != nil {
		res.stopHit(mimeHeaderCapHitKind)
		return
	}
	if depth > maxNestDepth {
		res.stopHit("mime-depth") // AUD-02: a parsed message is left unwalked
		return
	}
	walkMIMEEntity(textproto.MIMEHeader(msg.Header), msg.Body, res, b, depth, deadline, parts, completeAncestor)
}

func walkMIMEEntity(h textproto.MIMEHeader, body io.Reader, res *Result, b *archiveBudget, depth int, deadline time.Time, parts *int, completeAncestor bool) {
	switch {
	case depth > maxNestDepth:
		res.stopHit("mime-depth") // AUD-02: this entity is left unwalked
		return
	case *parts >= maxMIMEParts:
		res.stopHit("mime-parts") // AUD-02: an entity past the part cap exists
		return
	case b.spent() || len(res.Streams) >= maxStreams:
		archiveCapHit(res, b)
		return
	case expired(deadline):
		return
	}
	mediaType, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		mediaType = "text/plain" // RFC 2045 default; also covers a malformed type
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return
		}
		mr := multipart.NewReader(body, boundary)
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return // end of parts, or a malformed boundary: keep what we have
			}
			if *parts >= maxMIMEParts {
				res.stopHit("mime-parts") // AUD-02: a further part exists
				return
			}
			walkMIMEEntity(p.Header, p, res, b, depth+1, deadline, parts, completeAncestor)
			if b.spent() || len(res.Streams) >= maxStreams || expired(deadline) {
				// Record only when a further part really exists and the stop
				// is a cap, not the deadline.
				if !expired(deadline) {
					if _, err := mr.NextRawPart(); err == nil {
						if *parts >= maxMIMEParts {
							res.stopHit("mime-parts")
						}
						archiveCapHit(res, b)
					}
				}
				return
			}
		}
	}
	limit := min(maxBytesPerMember, maxTotalArchive-b.total)
	data, complete, truncated := decodeMIMEBody(h.Get("Content-Transfer-Encoding"), body, limit)
	if truncated {
		// Even a prefix below the extraction floor represents unvisited input.
		if limit < maxBytesPerMember {
			res.stopHit("archive-budget")
		} else {
			res.stopHit("member-size") // AUD-04: per-member cap truncated the part
		}
	}
	complete = complete && completeAncestor
	attachment := isMIMEAttachment(h)
	admitted := len(data) >= minMemberBytes && len(data) <= maxTotalArchive-b.total
	var admission retainedToken
	if attachment && complete && admitted {
		// One admission and one owned array serve both the attachment index and
		// the stream. A refused file is never published as a complete identity.
		var ok bool
		if admission, ok = res.admitStream(&data, true); !ok {
			return
		}
		res.MIMEAttachments = append(res.MIMEAttachments, data)
	}
	if len(data) == 0 {
		return
	}
	*parts++
	if mediaType == "message/rfc822" {
		// Attached message files are not emitted as streams, so charge their
		// storage here. Descendants continue using the same remaining budget.
		if attachment && admitted {
			b.members++
			b.total += len(data)
			if b.spent() {
				// The wrapper leaves descendant input unvisited at this cap.
				archiveCapHit(res, b)
			}
		}
		walkMIMEMessage(data, res, b, depth+1, deadline, parts, complete)
		return
	}
	emitMIMEPart(data, res, b, depth, deadline, admission)
}

// isMIMEAttachment requires explicit, successfully parsed file metadata.
func isMIMEAttachment(h textproto.MIMEHeader) bool {
	disposition, params, err := mime.ParseMediaType(h.Get("Content-Disposition"))
	if err == nil && (disposition == "attachment" || params["filename"] != "") {
		return true
	}
	_, params, err = mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && params["name"] != ""
}

// decodeMIMEBody retains best-effort YARA bytes, but certifies identity only
// after a successful terminal read. The sentinel distinguishes EOF at the cap
// from a truncated file, including when the shared budget lowers that cap.
func decodeMIMEBody(cte string, body io.Reader, limit int) ([]byte, bool, bool) {
	r := body
	var filter *base64Filter
	known := true
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "", "7bit", "8bit", "binary":
	case "base64":
		filter = &base64Filter{r: bufio.NewReader(body)}
		r = base64.NewDecoder(base64.StdEncoding, filter)
	case "quoted-printable":
		r = quotedprintable.NewReader(body)
	default:
		known = false
	}
	var out bytes.Buffer
	_, err := out.ReadFrom(io.LimitReader(r, int64(limit)+1))
	complete := known && err == nil && out.Len() <= limit && (filter == nil || !filter.invalid)
	data := out.Bytes()
	if len(data) > limit {
		data = data[:limit]
	}
	return data, complete, out.Len() > limit
}

// base64Filter drops bytes outside the base64 alphabet (spaces, tabs, stray
// punctuation), which the stdlib decoder would reject; CR and LF it already
// skips.
type base64Filter struct {
	r       io.ByteReader
	invalid bool
}

func (f *base64Filter) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c, err := f.r.ReadByte()
		if err != nil {
			return n, err
		}
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			p[n] = c
			n++
		} else if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			f.invalid = true
		}
	}
	return n, nil
}

// emitMIMEPart appends one decoded part and dispatches it like an archive
// member, but without flagging the input as an archive.
func emitMIMEPart(data []byte, res *Result, b *archiveBudget, depth int, deadline time.Time, admission retainedToken) {
	if len(data) < minMemberBytes || b.spent() || len(res.Streams) >= maxStreams {
		return
	}
	if res.childOpts == nil || !res.childOpts.retained.owns(admission) {
		if _, ok := res.admitStream(&data, true); !ok {
			return
		}
	}
	b.members++
	b.total += len(data)
	res.Streams = append(res.Streams, data)
	res.IsMIME = true
	extractChild(data, res, b, depth+1, deadline)
}
