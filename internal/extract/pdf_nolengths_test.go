package extract

import (
	"bytes"
	"testing"
)

// PERF-61 follow-up: a PDF with no indirect length objects hands
// scrubPDFForNames the shared empty map instead of nil, so it is not rescanned.
// Output must be identical to the nil (rescan) path; a PDF that does carry a
// length object still resolves it.
func TestScrubPDFNoLengthsMatchesRescan(t *testing.T) {
	docs := map[string][]byte{
		"no length objects": []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /Names << /JavaScript 2 0 R >> >> endobj\n" +
			"2 0 obj << /S /Java#53cript /JS (app.alert(1)) >> endobj\n%%EOF"),
		"direct length":   []byte("%PDF-1.4\n1 0 obj << /Length 5 >> stream\nhello\nendstream endobj\n/Open#41ction\n%%EOF"),
		"indirect length": []byte("%PDF-1.4\n1 0 obj << /Length 2 0 R >> stream\nhello\nendstream endobj\n2 0 obj 5 endobj\n/J#53\n%%EOF"),
		"empty":           {},
		"truncated":       []byte("%PDF-1.4\n1 0 obj << /Length 9 0 R >> stream\nabc"),
	}
	for name, d := range docs {
		wantBuf, wantHex := scrubPDFForNames(d, nil)
		passed := pdfIndirectLengths(d)
		if passed == nil {
			passed = noPDFLengths
		}
		gotBuf, gotHex := scrubPDFForNames(d, passed)
		if !bytes.Equal(gotBuf, wantBuf) || gotHex != wantHex {
			t.Errorf("%s: shared-map path differs from rescan path", name)
		}
	}
	if pdfIndirectLengths(docs["indirect length"])[2] != 5 {
		t.Fatal("indirect length object not resolved")
	}
	if len(noPDFLengths) != 0 {
		t.Fatal("noPDFLengths was written to")
	}
}
