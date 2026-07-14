package mailstrix

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// FuzzReadICAPChunkHeaderLine drives the single-chunk-header reader with
// arbitrary bytes. The reader is on the ICAP network path — any remote proxy
// can send hostile input. Invariants:
//   - never panic
//   - when errICAPLineTooLong is returned, no more than
//     maxICAPChunkHeaderLine bytes were buffered before the error
func FuzzReadICAPChunkHeaderLine(f *testing.F) {
	// Valid chunk-size lines.
	f.Add([]byte("0\r\n"))
	f.Add([]byte("1a\r\n"))
	f.Add([]byte("ff; ieof\r\n"))
	f.Add([]byte("3c ; ieof\r\n"))
	f.Add([]byte("100\n")) // LF-only (some proxies)
	// No terminator — must return an error, not block.
	f.Add([]byte("abc"))
	// Exactly at the cap, then newline.
	f.Add(append(bytes.Repeat([]byte("f"), maxICAPChunkHeaderLine), '\n'))
	// One over the cap — must return errICAPLineTooLong.
	f.Add(append(bytes.Repeat([]byte("f"), maxICAPChunkHeaderLine+1), '\n'))
	// Empty.
	f.Add([]byte{})
	// Binary junk.
	f.Add(bytes.Repeat([]byte{0xFF}, 32))
	f.Add([]byte("\x00\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReader(bytes.NewReader(data))
		line, err := readICAPChunkHeaderLine(br)
		if err != nil {
			return // errors expected; must not panic
		}
		// Returned line must be no longer than the cap (CRLF stripped).
		if len(line) > maxICAPChunkHeaderLine {
			t.Fatalf("returned line len %d > cap %d", len(line), maxICAPChunkHeaderLine)
		}
	})
}

// FuzzReadICAPChunkedBody drives the full chunked-body reader with arbitrary
// bytes. Any remote ICAP proxy can control this stream, making it a high-value
// target. Invariants:
//   - never panic
//   - on success, returned body len ≤ maxBody
//   - ieof=true only when a 0-chunk with "ieof" extension was seen (structural)
func FuzzReadICAPChunkedBody(f *testing.F) {
	const maxBody = 8 * 1024 * 1024 // mirrors default MaxBody

	// Well-formed terminal chunk (empty body, ieof).
	f.Add([]byte("0; ieof\r\n\r\n"))
	// Well-formed terminal chunk without ieof.
	f.Add([]byte("0\r\n\r\n"))
	// Single data chunk + terminal.
	f.Add([]byte("5\r\nhello\r\n0\r\n\r\n"))
	// Multi-chunk.
	f.Add([]byte("3\r\nfoo\r\n4\r\nbarr\r\n0; ieof\r\n\r\n"))
	// Chunk size that would exceed maxBody.
	f.Add([]byte(fmt.Sprintf("%x\r\n", int64(maxBody)+1)))
	// Bad hex size.
	f.Add([]byte("zz\r\ndata\r\n"))
	// Truncated mid-data.
	f.Add([]byte("a\r\nhello"))
	// Extensions with spaces and garbage.
	f.Add([]byte("5  ; ieof garbage extra\r\nhello\r\n0\r\n\r\n"))
	// Empty.
	f.Add([]byte{})
	// Binary junk.
	f.Add(bytes.Repeat([]byte{0xFF}, 64))
	// Chunk claiming 0 bytes (terminal) with no trailing CRLF.
	f.Add([]byte("0"))
	// Multiple terminators (should stop at first).
	f.Add([]byte("0\r\n\r\n0\r\n\r\n"))
	// Large valid body near the cap (2 chunks of 4 MiB - 1).
	chunk4m := strings.Repeat("A", 4*1024*1024-1)
	f.Add([]byte(fmt.Sprintf("%x\r\n%s\r\n%x\r\n%s\r\n0;ieof\r\n\r\n",
		len(chunk4m), chunk4m, len(chunk4m), chunk4m)))

	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReader(bytes.NewReader(data))
		body, _, err := readICAPChunkedBody(br, maxBody)
		if err != nil {
			return
		}
		if int64(len(body)) > maxBody {
			t.Fatalf("body len %d exceeds maxBody %d", len(body), maxBody)
		}
	})
}

// FuzzHandleICAPRequest drives a COMPLETE ICAP request — request line, header
// block, encapsulated HTTP headers and chunked body — through the same entry
// point the network path uses. The per-piece fuzzers above cannot reach state
// that depends on how the head steers the body read (Encapsulated section
// counts, Preview, header caps), which is exactly where the outer parse used to
// be unbounded. Invariants:
//   - never panic
//   - never buffer without bound: the head is capped by maxICAPHeaderLine /
//     maxICAPHeaderCount / maxICAPHeaderBytes and the body by MaxBody, so a
//     request of any shape terminates
func FuzzHandleICAPRequest(f *testing.F) {
	f.Add([]byte("OPTIONS icap://h/scan ICAP/1.0\r\nHost: h\r\nEncapsulated: null-body=0\r\n\r\n"))
	f.Add([]byte(icapRESPMODRequest("h", "hello", true)))
	f.Add([]byte(icapREQMODRequest("h", "hello", false)))
	// Bad version / arity on the request line.
	f.Add([]byte("RESPMOD icap://h/scan ICAP/2.0\r\n\r\n"))
	f.Add([]byte("GARBAGE\r\n\r\n"))
	// Unknown method.
	f.Add([]byte("FROBNICATE icap://h/scan ICAP/1.0\r\n\r\n"))
	// Head with no terminating blank line.
	f.Add([]byte("OPTIONS icap://h/scan ICAP/1.0\r\nHost: h\r\n"))
	// Over the per-line cap.
	f.Add([]byte("OPTIONS icap://h/scan ICAP/1.0\r\nX: " + strings.Repeat("A", maxICAPHeaderLine+16) + "\r\n\r\n"))
	// Over the header-count cap.
	var many strings.Builder
	many.WriteString("OPTIONS icap://h/scan ICAP/1.0\r\n")
	for i := 0; i < maxICAPHeaderCount+8; i++ {
		fmt.Fprintf(&many, "X-H%d: v\r\n", i)
	}
	many.WriteString("\r\n")
	f.Add([]byte(many.String()))
	// Obs-fold continuation, and a leading continuation with no preceding header.
	f.Add([]byte("OPTIONS icap://h/scan ICAP/1.0\r\nX-A: one\r\n\ttwo\r\n\r\n"))
	f.Add([]byte("OPTIONS icap://h/scan ICAP/1.0\r\n  orphan\r\n\r\n"))
	// Encapsulated claiming header sections that never arrive.
	f.Add([]byte("RESPMOD icap://h/scan ICAP/1.0\r\nEncapsulated: res-hdr=0, res-body=10\r\n\r\n"))
	// Preview with a truncated continuation.
	f.Add([]byte("RESPMOD icap://h/scan ICAP/1.0\r\nPreview: 0\r\n" +
		"Encapsulated: res-hdr=0, res-body=0\r\n\r\n\r\n0\r\n\r\n"))
	// Body chunk claiming more than it delivers.
	f.Add([]byte("RESPMOD icap://h/scan ICAP/1.0\r\nEncapsulated: res-body=0\r\n\r\nffff\r\nshort"))
	f.Add([]byte{})

	s := newTestServer(&fakeEngine{count: 1}, "")

	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReader(bytes.NewReader(data))
		// io.Discard is not a deadlineSetter, so the head/body deadline re-arm is
		// skipped; termination must come from the caps alone, which is the point.
		_ = s.handleICAPRequest(io.Discard, br)
	})
}
