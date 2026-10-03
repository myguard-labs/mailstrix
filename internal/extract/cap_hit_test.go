package extract

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func hasCapHit(res Result, kind string) bool {
	for _, k := range res.CapHits {
		if k == kind {
			return true
		}
	}
	return false
}

func junkPDF(junk int) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	for i := 0; i < junk; i++ {
		b.WriteString("1 0 obj\n<< >>\nstream\nnot-zlib!\nendstream\nendobj\n")
	}
	b.WriteString("%%EOF")
	return b.Bytes()
}

// TestCapHitStreams (COR-07b): 300 distinct members exhaust maxStreams; the
// hit is recorded once and surfaces as a marker on the Markers channel.
func TestCapHitStreams(t *testing.T) {
	z := paddedZip(t, 300, func(i int) []byte { return []byte(fmt.Sprintf("padding member %04d body", i)) })
	res := Extract(z, time.Time{})
	if !hasCapHit(res, "streams") {
		t.Fatalf("CapHits = %v, want streams", res.CapHits)
	}
	if !hasStreamExact(res.Markers, capHitMarkerPrefix+"streams") {
		t.Fatalf("marker missing from Markers: %q", res.Markers)
	}
	if hasStreamExact(res.Streams, capHitMarkerPrefix+"streams") {
		t.Fatal("marker left in Streams")
	}
}

// TestCapHitPDFAttempts (COR-07b): junk beyond maxPDFAttempts with a stream
// left records pdf-streams.
func TestCapHitPDFAttempts(t *testing.T) {
	if res := Extract(junkPDF(maxPDFAttempts+1), time.Time{}); !hasCapHit(res, "pdf-streams") {
		t.Fatalf("CapHits = %v, want pdf-streams", res.CapHits)
	}
}

// TestCapHitPDFBoundary: exactly maxPDFAttempts junk streams and nothing
// after is fully walked, so no cap is recorded.
func TestCapHitPDFBoundary(t *testing.T) {
	if res := Extract(junkPDF(maxPDFAttempts), time.Time{}); len(res.CapHits) != 0 {
		t.Fatalf("CapHits = %v, want none", res.CapHits)
	}
}

// TestCapHitRTFObjects (COR-07b): more non-empty objects than maxRTFObjects
// records rtf-objects.
func TestCapHitRTFObjects(t *testing.T) {
	var b strings.Builder
	b.WriteString("{\\rtf1\\ansi\\ansicpg1252\n")
	for i := 0; i < maxRTFObjects+3; i++ {
		stream := buildOle10Native("a.exe", "C:\\a.exe", "C:\\T\\a.exe", []byte(fmt.Sprintf("MZ object %d", i)), 0)
		b.WriteString(strings.TrimPrefix(string(wrapRTFObjData(stream)), "{\\rtf1\\ansi\\ansicpg1252\n"))
	}
	if res := Extract([]byte(b.String()), time.Time{}); !hasCapHit(res, "rtf-objects") {
		t.Fatalf("CapHits = %v, want rtf-objects", res.CapHits)
	}
}

// TestCapHitNone (negative control): a small zip, a short PDF and malformed
// input record no cap and emit no marker.
func TestCapHitNone(t *testing.T) {
	for name, in := range map[string][]byte{
		"zip":       paddedZip(t, 3, func(i int) []byte { return []byte(fmt.Sprintf("member %d body", i)) }),
		"pdf":       junkPDF(3),
		"truncated": paddedZip(t, 300, func(int) []byte { return []byte("abcd") })[:200],
	} {
		res := Extract(in, time.Time{})
		if len(res.CapHits) != 0 {
			t.Errorf("%s: CapHits = %v", name, res.CapHits)
		}
		for _, m := range res.Markers {
			if bytes.HasPrefix(m, []byte(capHitMarkerPrefix)) {
				t.Errorf("%s: unexpected marker %q", name, m)
			}
		}
	}
}

// TestCapHitDedup: a kind is recorded once, in first-hit order.
func TestCapHitDedup(t *testing.T) {
	var r Result
	r.capHit("streams")
	r.capHit("pdf-streams")
	r.capHit("streams")
	if got := strings.Join(r.CapHits, ","); got != "streams,pdf-streams" {
		t.Fatalf("CapHits = %s", got)
	}
}
