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
	// mimeSniffLen bounds how far into the input the header block is looked
	// for when deciding whether the input is an RFC 5322 message at all.
	mimeSniffLen = 16 << 10
)

// isMIMEMessage reports whether buf starts with an RFC 5322 header block that
// declares a MIME Content-Type (COR-01). It needs a Content-Type header plus
// one other message header, all before the first blank line, so ordinary
// text that happens to contain "Content-Type:" is not taken for a message.
func isMIMEMessage(buf []byte) bool {
	head := buf
	if len(head) > mimeSniffLen {
		head = head[:mimeSniffLen]
	}
	end := bytes.Index(head, []byte("\n\r\n"))
	if e := bytes.Index(head, []byte("\n\n")); e >= 0 && (end < 0 || e < end) {
		end = e
	}
	if end < 0 {
		return false
	}
	var hasType, hasOther bool
	for _, line := range bytes.Split(head[:end+1], []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' { // folded continuation line
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || bytes.ContainsAny(line[:colon], " \t") {
			return false // not a header line: not a header block
		}
		switch strings.ToLower(string(line[:colon])) {
		case "content-type":
			hasType = true
		case "mime-version", "from", "to", "subject", "date", "received", "message-id", "return-path":
			hasOther = true
		}
	}
	return hasType && hasOther
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
	if attachment && complete && admitted {
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
	emitMIMEPart(data, res, b, depth, deadline)
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
func emitMIMEPart(data []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	if len(data) < minMemberBytes || b.spent() || len(res.Streams) >= maxStreams {
		return
	}
	b.members++
	b.total += len(data)
	res.Streams = append(res.Streams, data)
	res.IsMIME = true
	extractChild(data, res, b, depth+1, deadline)
}
