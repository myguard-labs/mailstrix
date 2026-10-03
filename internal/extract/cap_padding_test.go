package extract

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

const padNeedle = "COR07-HIDDEN-DROPPER-PAYLOAD"

func zipOfMembers(t *testing.T, names []string, bodies [][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for i, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(bodies[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func paddedZip(t *testing.T, pads int, padBody func(i int) []byte) []byte {
	t.Helper()
	var names []string
	var bodies [][]byte
	for i := 0; i < pads; i++ {
		names = append(names, fmt.Sprintf("pad%04d.txt", i))
		bodies = append(bodies, padBody(i))
	}
	names = append(names, "z.vbs")
	bodies = append(bodies, []byte(`WScript.Echo "`+padNeedle+`"`))
	return zipOfMembers(t, names, bodies)
}

// TestZipTrivialPaddingDoesNotHideDropper (COR-07): 300 one-byte members
// before z.vbs no longer exhaust maxStreams.
func TestZipTrivialPaddingDoesNotHideDropper(t *testing.T) {
	z := paddedZip(t, 300, func(int) []byte { return []byte("x") })
	if res := Extract(z, time.Time{}); !streamsContain(res, padNeedle) {
		t.Fatalf("dropper hidden by trivial padding; streams=%d", len(res.Streams))
	}
}

// TestZipScriptMemberScannedFirst: 300 non-trivial padding members still
// cannot crowd out a script member, which is visited first.
func TestZipScriptMemberScannedFirst(t *testing.T) {
	z := paddedZip(t, 300, func(i int) []byte { return []byte(fmt.Sprintf("padding member %04d body", i)) })
	if res := Extract(z, time.Time{}); !streamsContain(res, padNeedle) {
		t.Fatalf("script member not prioritised; streams=%d", len(res.Streams))
	}
}

// TestZipMemberSizeBoundary: a member of minMemberBytes is emitted, one byte
// less is not; an intact small zip is unchanged (negative control).
func TestZipMemberSizeBoundary(t *testing.T) {
	at := strings.Repeat("A", minMemberBytes)
	below := strings.Repeat("B", minMemberBytes-1)
	res := Extract(zipOfMembers(t, []string{"a.txt", "b.txt"}, [][]byte{[]byte(at), []byte(below)}), time.Time{})
	if !hasStreamExact(res.Streams, at) || hasStreamExact(res.Streams, below) {
		t.Fatalf("boundary: streams=%q", res.Streams)
	}
	if res := Extract(paddedZip(t, 0, nil), time.Time{}); !streamsContain(res, padNeedle) {
		t.Fatal("control: plain zip member missing")
	}
}

func hasStreamExact(streams [][]byte, want string) bool {
	for _, s := range streams {
		if string(s) == want {
			return true
		}
	}
	return false
}

// TestZipVisitOrder: priority extensions first (case-insensitive), archive
// order kept within each class; no extension and empty input are handled.
func TestZipVisitOrder(t *testing.T) {
	files := []*zip.File{
		{FileHeader: zip.FileHeader{Name: "a.txt"}},
		{FileHeader: zip.FileHeader{Name: "dir/RUN.EXE"}},
		{FileHeader: zip.FileHeader{Name: "noext"}},
		{FileHeader: zip.FileHeader{Name: "s.js"}},
	}
	if got := fmt.Sprint(zipVisitOrder(files)); got != "[1 3 0 2]" {
		t.Fatalf("order = %s", got)
	}
	if got := zipVisitOrder(nil); len(got) != 0 {
		t.Fatalf("empty: %v", got)
	}
}

// TestRTFEmptyObjDataPaddingDoesNotHideObject: 100 empty \objdata groups
// before a real object no longer exhaust maxRTFObjects.
func TestRTFEmptyObjDataPaddingDoesNotHideObject(t *testing.T) {
	payload := []byte("MZ\x90\x00 " + padNeedle)
	stream := buildOle10Native("calc.exe", "C:\\e\\calc.exe", "C:\\T\\calc.exe", payload, 0)
	real := string(wrapRTFObjData(stream))
	real = strings.TrimPrefix(real, "{\\rtf1\\ansi\\ansicpg1252\n")
	doc := "{\\rtf1\\ansi\\ansicpg1252\n" + strings.Repeat("{\\object\\objemb{\\*\\objdata }}\n", 100) + real
	if res := Extract([]byte(doc), time.Time{}); !streamsContain(res, padNeedle) {
		t.Fatalf("RTF object hidden by empty padding; streams=%d", len(res.Streams))
	}
}

// TestPDFJunkStreamsDoNotHideFlate: 300 non-deflate junk streams before a
// FlateDecode stream no longer exhaust maxPDFStreams.
func TestPDFJunkStreamsDoNotHideFlate(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "%d 0 obj\n<< /Length 9 >>\nstream\nnot-zlib!\nendstream\nendobj\n", i+1)
	}
	b.WriteString("999 0 obj\n<< /Filter /FlateDecode >>\nstream\n")
	b.Write(zlibDeflate([]byte("/JavaScript (app.alert('" + padNeedle + "'))")))
	b.WriteString("\nendstream\nendobj\n%%EOF")
	if res := Extract(b.Bytes(), time.Time{}); !streamsContain(res, padNeedle) {
		t.Fatalf("flate stream hidden by junk streams; streams=%d", len(res.Streams))
	}
}

// TestPDFAttemptCapStillBounds (boundary/malformed): junk beyond
// maxPDFAttempts stops the walk, so a flate stream past it is not reached.
func TestPDFAttemptCapStillBounds(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	for i := 0; i < maxPDFAttempts+5; i++ {
		b.WriteString("1 0 obj\n<< >>\nstream\nnot-zlib!\nendstream\nendobj\n")
	}
	b.WriteString("2 0 obj\n<< >>\nstream\n")
	b.Write(zlibDeflate([]byte(padNeedle)))
	b.WriteString("\nendstream\nendobj\n%%EOF")
	if res := Extract(b.Bytes(), time.Time{}); streamsContain(res, padNeedle) {
		t.Fatal("attempt cap no longer bounds junk stream walking")
	}
}
