package extract

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"strconv"
	"strings"
	"testing"
	"time"
)

func zlibDeflate(data []byte) []byte {
	var b bytes.Buffer
	zw := zlib.NewWriter(&b)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return b.Bytes()
}

func rawDeflate(data []byte) []byte {
	var b bytes.Buffer
	fw, _ := flate.NewWriter(&b, flate.DefaultCompression)
	_, _ = fw.Write(data)
	_ = fw.Close()
	return b.Bytes()
}

// pdfWithStream wraps a single object stream body into a minimal PDF.
func pdfWithStream(body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n1 0 obj\n<< /Length 1 >>\nstream\n")
	b.Write(body)
	b.WriteString("\nendstream\nendobj\n%%EOF")
	return b.Bytes()
}

// A PDF with a FlateDecode (zlib) stream hiding JavaScript must have the inflated
// script surfaced.
func TestExtractPDFFlate(t *testing.T) {
	js := []byte("/JavaScript (app.alert('pdf dropper payload'); this.exportDataObject())")
	buf := pdfWithStream(zlibDeflate(js))
	res := Extract(buf, time.Time{})
	if !res.IsPDF {
		t.Fatal("PDF not flagged IsPDF")
	}
	if !streamsContain(res, "pdf dropper payload") {
		t.Errorf("inflated JS not surfaced; got %d streams", len(res.Streams))
	}
}

// A raw-deflate stream (no zlib wrapper) must inflate via the fallback.
func TestExtractPDFRawDeflate(t *testing.T) {
	js := []byte("OpenAction Launch raw-deflate pdf payload")
	buf := pdfWithStream(rawDeflate(js))
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "raw-deflate pdf payload") {
		t.Errorf("raw-deflate stream not surfaced; got %d streams", len(res.Streams))
	}
}

// Multiple object streams must all be inflated.
func TestExtractPDFMultipleStreams(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n")
	for _, s := range [][]byte{[]byte("first pdf stream AAAA"), []byte("second pdf stream BBBB")} {
		b.WriteString("obj\nstream\n")
		b.Write(zlibDeflate(s))
		b.WriteString("\nendstream\n")
	}
	b.WriteString("%%EOF")
	res := Extract(b.Bytes(), time.Time{})
	if !streamsContain(res, "first pdf stream") || !streamsContain(res, "second pdf stream") {
		t.Errorf("not all streams inflated; got %d streams", len(res.Streams))
	}
}

// A non-deflate stream (e.g. raw image bytes) must be skipped without error.
func TestExtractPDFNonDeflateSkipped(t *testing.T) {
	buf := pdfWithStream([]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F'})
	res := Extract(buf, time.Time{})
	if !res.IsPDF {
		t.Fatal("PDF not flagged IsPDF")
	}
	if res.Panicked {
		t.Fatal("non-deflate stream panicked")
	}
}

// A truncated PDF (stream keyword but no endstream) must not panic.
func TestExtractPDFTruncated(t *testing.T) {
	buf := []byte("%PDF-1.4\nobj\nstream\n" + string(zlibDeflate([]byte("x"))))
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Fatal("truncated PDF panicked")
	}
}

// Regression (Codex #2): a stray "stream" substring (in a name/comment, not a
// real stream keyword) must NOT make the carver swallow the following real
// FlateDecode object — the genuine payload must still be inflated.
func TestExtractPDFStrayStreamKeyword(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	b.WriteString("/Name /upstream_thing  % a comment mentioning stream here\n")
	b.WriteString("1 0 obj\n<< /Length 1 >>\nstream\n")
	b.Write(zlibDeflate([]byte("genuine pdf payload after stray keyword")))
	b.WriteString("\nendstream\nendobj\n%%EOF")
	res := Extract(b.Bytes(), time.Time{})
	if !streamsContain(res, "genuine pdf payload") {
		t.Errorf("stray 'stream' hid the real object; got %d streams", len(res.Streams))
	}
}

// Regression (Codex #1): a PDF stuffed with many non-deflate stream bodies must
// be bounded by the attempt cap — the carve loop must stop after maxPDFStreams
// inflate attempts even though none emit a stream, so it cannot scan all
// (maxPDFStreams*4) objects. We assert termination implicitly (no hang, caught
// by `go test`'s timeout) and that no streams were emitted from non-deflate
// bodies. No goroutine: keep the asan thread count low.
func TestExtractPDFAttemptCapBounded(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	for i := 0; i < maxPDFStreams*4; i++ {
		b.WriteString("obj\nstream\nNOTDEFLATE rawbytes here\nendstream\n")
	}
	res := Extract(b.Bytes(), time.Time{})
	if len(res.Streams) != 0 {
		t.Errorf("non-deflate bodies should emit nothing, got %d streams", len(res.Streams))
	}
}

// A non-PDF buffer must not be flagged IsPDF.
func TestExtractNotPDF(t *testing.T) {
	res := Extract([]byte("not a pdf, just text"), time.Time{})
	if res.IsPDF {
		t.Error("plain text wrongly flagged IsPDF")
	}
}

// --- PDF-DEEPEN structural indicators ---

// An /OpenAction that runs /JavaScript must surface PDF-OPENACTION-JS.
func TestExtractPDFOpenActionJS(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "PDF-OPENACTION-JS") {
		t.Errorf("auto-run JS not flagged; streams=%v", res.Streams)
	}
}

// /Launch, /EmbeddedFile, /JBIG2Decode, /AA, /ObjStm each get their own marker.
func TestExtractPDFIndicatorMarkers(t *testing.T) {
	cases := []struct {
		body, marker string
	}{
		{"<< /Launch << /F (cmd.exe) >> >>", "PDF-LAUNCH"},
		{"<< /Type /Filespec /EmbeddedFile 2 0 R >>", "PDF-EMBEDDEDFILE"},
		{"<< /Filter /JBIG2Decode >>", "PDF-JBIG2"},
		{"<< /AA << /O 3 0 R >> >>", "PDF-AA-ACTION"},
		{"<< /Type /ObjStm /N 5 >>", "PDF-OBJSTM"},
	}
	for _, c := range cases {
		buf := []byte("%PDF-1.7\n1 0 obj\n" + c.body + "\nendobj\n%%EOF")
		res := Extract(buf, time.Time{})
		if !streamsContain(res, c.marker) {
			t.Errorf("%s not flagged for body %q; streams=%v", c.marker, c.body, res.Streams)
		}
	}
}

// A hex-escaped name (/J#61vaScript = /JavaScript) must both de-obfuscate to fire
// PDF-OPENACTION-JS and raise PDF-HEXOBFUSC.
func TestExtractPDFHexObfuscatedName(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /J#61vaScript /JS (x) >> >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "PDF-HEXOBFUSC") {
		t.Errorf("hex-escape obfuscation not flagged; streams=%v", res.Streams)
	}
	if !streamsContain(res, "PDF-OPENACTION-JS") {
		t.Errorf("de-obfuscated /JavaScript not matched; streams=%v", res.Streams)
	}
}

// A short name like /JS must not match inside a longer name (/JSomething), and a
// benign PDF must emit no indicator markers (no false positives).
func TestExtractPDFNoFalsePositive(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /Type /Page /JSomething (not js) /Contents 2 0 R >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	for _, m := range []string{"PDF-OPENACTION-JS", "PDF-LAUNCH", "PDF-AA-ACTION", "PDF-JBIG2", "PDF-EMBEDDEDFILE", "PDF-OBJSTM", "PDF-HEXOBFUSC"} {
		if streamsContain(res, m) {
			t.Errorf("false positive %s on benign PDF; streams=%v", m, res.Streams)
		}
	}
}

// An escaped delimiter (#2F = '/', #20 = space) inside a name is a LITERAL name
// char and must NOT be decoded into a boundary that fabricates a keyword.
func TestExtractPDFEscapedDelimiterNoFabrication(t *testing.T) {
	// /foo#2FLaunch would become /foo/Launch if #2F were decoded to '/'.
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /foo#2FLaunch (x) /OpenAction#20y 1 0 R >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	if streamsContain(res, "PDF-LAUNCH") {
		t.Errorf("escaped delimiter fabricated /Launch; streams=%v", res.Streams)
	}
	if streamsContain(res, "PDF-OPENACTION-JS") {
		t.Errorf("escaped space fabricated /OpenAction match; streams=%v", res.Streams)
	}
	// The escape is still present, so the obfuscation signal must fire.
	if !streamsContain(res, "PDF-HEXOBFUSC") {
		t.Errorf("hex escape not counted as obfuscation; streams=%v", res.Streams)
	}
}

// AUDIT-PDF-LEXER: an indicator name embedded in a literal string, a comment, a
// hex string, or a stream body must NOT fabricate a marker (FP injection).
func TestExtractPDFIndicatorContextScrub(t *testing.T) {
	cases := []struct{ name, body string }{
		{"literal-string", "1 0 obj\n<< /Title (see /OpenAction and /JS in this caption) >>\nendobj"},
		{"comment", "1 0 obj\n% /OpenAction /JS /Launch /JBIG2Decode are discussed here\n<< /Type /Page >>\nendobj"},
		{"hex-string", "1 0 obj\n<< /Title </OpenAction and /JS inside angle brackets> >>\nendobj"},
		{"stream-body", "1 0 obj\n<< /Length 40 >>\nstream\n/OpenAction /JS /Launch /JBIG2Decode\nendstream\nendobj"},
	}
	for _, c := range cases {
		buf := []byte("%PDF-1.7\n" + c.body + "\n%%EOF")
		res := Extract(buf, time.Time{})
		for _, m := range []string{"PDF-OPENACTION-JS", "PDF-LAUNCH", "PDF-JBIG2"} {
			if streamsContain(res, m) {
				t.Errorf("[%s] fabricated %s from non-name context; streams=%v", c.name, m, res.Streams)
			}
		}
	}
}

// A stream whose body contains the literal bytes "endstream" followed by fake
// indicator names must NOT fabricate markers: /Length tells the scrubber the
// exact body size, so the embedded "endstream" + fake names stay inside the body.
func TestExtractPDFStreamEndstreamInBody(t *testing.T) {
	body := "binary endstream /OpenAction /JS /Launch more binary"
	obj := "1 0 obj\n<< /Length " + strconv.Itoa(len(body)) + " >>\nstream\n" + body + "\nendstream\nendobj"
	buf := []byte("%PDF-1.7\n" + obj + "\n%%EOF")
	res := Extract(buf, time.Time{})
	for _, m := range []string{"PDF-OPENACTION-JS", "PDF-LAUNCH"} {
		if streamsContain(res, m) {
			t.Errorf("fabricated %s from a stream body containing 'endstream'; streams=%v", m, res.Streams)
		}
	}
}

// zlibStore zlib-wraps data with NO compression (stored blocks), so the
// compressed bytes contain the literal payload — letting a test embed an
// `endstream` token inside an otherwise-valid FlateDecode body.
func zlibStore(data []byte) []byte {
	var b bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&b, zlib.NoCompression)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return b.Bytes()
}

// AUDIT-PDF-ENDSTREAM: a FlateDecode body whose compressed bytes contain a
// literal `endstream` must be carved by its declared /Length, not truncated at
// the first `endstream` substring — otherwise the inflate drops everything past
// the embedded token and the real payload tail evades scanning.
func TestExtractPDFEndstreamInCompressedBody(t *testing.T) {
	payload := []byte("app.alert('PDF_HEAD'); /* endstream */ this.exportDataObject('PDF_TAIL_KEYWORD')")
	comp := zlibStore(payload)
	if !bytes.Contains(comp, []byte("endstream")) {
		t.Fatalf("test setup: stored-deflate body does not contain a literal 'endstream'")
	}
	obj := "1 0 obj\n<< /Length " + strconv.Itoa(len(comp)) + " >>\nstream\n"
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	buf.WriteString(obj)
	buf.Write(comp)
	buf.WriteString("\nendstream\nendobj\n%%EOF")

	res := Extract(buf.Bytes(), time.Time{})
	if !streamsContain(res, "PDF_TAIL_KEYWORD") {
		t.Errorf("payload past the embedded 'endstream' not inflated (carve truncated early); streams=%v", res.Streams)
	}
}

// pdfStreamLength / readPDFLength: direct integer trusted, indirect refs and a
// prior object's /Length rejected (the latter must not leak across objects).
func TestPDFStreamLength(t *testing.T) {
	streamPos := func(b string) int { return bytes.Index([]byte(b), []byte("stream")) }

	direct := "1 0 obj\n<< /Type /X /Length 42 >>\nstream\n"
	if got := pdfStreamLength([]byte(direct), streamPos(direct)); got != 42 {
		t.Errorf("direct /Length: got %d, want 42", got)
	}
	// Indirect `/Length 9 0 R` — unresolvable, must be -1.
	indirect := "2 0 obj\n<< /Length 9 0 R >>\nstream\n"
	if got := pdfStreamLength([]byte(indirect), streamPos(indirect)); got != -1 {
		t.Errorf("indirect /Length: got %d, want -1", got)
	}
	// Indirect split by a comment `/Length 9 %c\n0 R` — still -1 (comment is ws).
	commented := "3 0 obj\n<< /Length 9 %c\n0 R >>\nstream\n"
	if got := pdfStreamLength([]byte(commented), streamPos(commented)); got != -1 {
		t.Errorf("comment-split indirect /Length: got %d, want -1", got)
	}
	// /Length only in a PRIOR object; this stream's object has none → -1.
	stale := "1 0 obj\n<< /Length 5 >>\nendobj\n2 0 obj\n<< /Type /X >>\nstream\n"
	if got := pdfStreamLength([]byte(stale), strings.LastIndex(stale, "stream")); got != -1 {
		t.Errorf("prior-object /Length leaked: got %d, want -1", got)
	}
}

// A real dictionary /OpenAction must still fire even when the document ALSO
// contains a decoy /OpenAction inside a string (scrub keeps real names).
func TestExtractPDFIndicatorRealAfterDecoy(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /Title (decoy /OpenAction here) >>\nendobj\n" +
		"2 0 obj\n<< /OpenAction << /S /JavaScript /JS (real) >> >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "PDF-OPENACTION-JS") {
		t.Errorf("real /OpenAction not detected past a string decoy; streams=%v", res.Streams)
	}
}

// pdfHasName must respect name-token boundaries.
func TestPDFHasNameBoundary(t *testing.T) {
	if pdfHasName([]byte("<< /JSomething >>"), pdfNameJS) {
		t.Error("/JS matched inside /JSomething")
	}
	if !pdfHasName([]byte("<< /JS 1 0 R >>"), pdfNameJS) {
		t.Error("/JS not matched as a whole name")
	}
	if !pdfHasName([]byte("/ObjStm"), pdfNameObjStm) {
		t.Error("/ObjStm at end-of-buffer not matched")
	}
}
