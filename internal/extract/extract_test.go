package extract

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// A real OOXML workbook with VBA macros must yield decompressed cleartext that
// the keyword rules can match. Every VBA module carries an `Attribute VB_Name`
// header once decompressed, so its presence proves the MS-OVBA decompress ran.
func TestExtractOOXMLMacro(t *testing.T) {
	buf := readFixture(t, "xlswithmacro.xlsm")
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Error("known .xlsm not flagged IsDoc")
	}
	if res.Failed || res.Panicked || res.Encrypted {
		t.Errorf("unexpected flags: %+v", flags(res))
	}
	if len(res.Streams) == 0 {
		t.Fatal("no macro streams extracted from a known-macro .xlsm")
	}
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("Attribute VB_Name")) {
		t.Errorf("extracted streams missing decompressed VBA marker; got %dB", len(joined))
	}
}

// OLEID-VBA-PRESENT must be emitted for an OOXML workbook that contains
// decodable VBA macro bins. The marker must appear exactly once (dedup guard).
func TestOLEIDVBAPresentMarker(t *testing.T) {
	buf := readFixture(t, "xlswithmacro.xlsm")
	res := Extract(buf, time.Time{})
	if res.Failed || res.Panicked {
		t.Fatalf("unexpected failure flags: %+v", flags(res))
	}
	const marker = "OLEID-VBA-PRESENT"
	count := 0
	// PURE marker now lives in the out-of-band Markers channel (PLAN Phase 1).
	for _, s := range res.Markers {
		if string(s) == marker {
			count++
		}
	}
	if count == 0 {
		t.Errorf("%s marker not emitted for xlswithmacro.xlsm", marker)
	}
	if count > 1 {
		t.Errorf("%s marker emitted %d times (want 1, dedup guard broken)", marker, count)
	}
}

// Non-container input (a plain mail body) must extract nothing and not be
// flagged a document — the scanner then sees only the raw bytes, exactly as
// before this package existed.
func TestExtractNonContainer(t *testing.T) {
	for _, in := range [][]byte{[]byte("a perfectly innocent email body"), nil, {0x00}, {'P', 'K'}} {
		res := Extract(in, time.Time{})
		if res.IsDoc || len(res.Streams) != 0 || res.Failed || res.Encrypted {
			t.Errorf("non-container %q yielded %+v", in, flags(res))
		}
	}
}

// OLE2 magic followed by garbage must fail open: IsDoc=true (magic matched) but
// no streams, Failed/Panicked recorded, no crash. This is the poison-document
// path — a malformed compound file must degrade to a raw-only scan.
func TestExtractMalformedOLEFailsOpen(t *testing.T) {
	buf := append(append([]byte{}, oleMagic...), bytes.Repeat([]byte{0xAB}, 4096)...)
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Error("OLE magic not flagged IsDoc")
	}
	if len(res.Streams) != 0 {
		t.Errorf("malformed OLE yielded streams: %v", res.Streams)
	}
	if !res.Failed {
		t.Error("malformed OLE not flagged Failed")
	}
}

// ZIP magic but not a valid archive must be flagged a doc-attempt that Failed;
// a valid zip with no .bin member is a doc with no streams and no failure.
func TestExtractZipNoMacro(t *testing.T) {
	bad := Extract(append(append([]byte{}, zipMagic...), 0x00, 0x01, 0x02), time.Time{})
	if !bad.IsDoc || !bad.Failed {
		t.Errorf("truncated zip: want IsDoc+Failed, got %+v", flags(bad))
	}

	ok := Extract(makeZip(t, "word/document.xml", "<xml/>"), time.Time{})
	if !ok.IsDoc {
		t.Error("valid .docx not flagged IsDoc")
	}
	if ok.Failed || len(ok.Streams) != 0 {
		t.Errorf("macro-free .docx: want no streams/failure, got %+v", flags(ok))
	}
}

// A .bin member that is not a real OLE2 compound file must be skipped without
// panicking. When it's the ONLY .bin and it fails, the whole doc is marked
// Failed (observable) rather than looking like a clean macro-free document.
func TestExtractOOXMLBadBinSkipped(t *testing.T) {
	res := Extract(makeZip(t, "word/vbaProject.bin", "not really an OLE file"), time.Time{})
	if !res.IsDoc || res.Panicked {
		t.Errorf("bad .bin: want IsDoc, no panic, got %+v", flags(res))
	}
	if len(res.Streams) != 0 {
		t.Errorf("bad .bin yielded streams: %v", res.Streams)
	}
	if !res.Failed {
		t.Errorf("all-bad .bin should be Failed (observable): %+v", flags(res))
	}
}

// An already-expired deadline must stop the OOXML extraction loop before doing
// the parse work, yielding no streams and a Failed flag — the bound that keeps a
// small compressed bomb from burning CPU ahead of the libyara scan budget.
func TestExtractOOXMLDeadlineStops(t *testing.T) {
	doc := readFixture(t, "xlswithmacro.xlsm")
	res := Extract(doc, time.Now().Add(-time.Second))
	if len(res.Streams) != 0 {
		t.Errorf("expired deadline still extracted %d streams", len(res.Streams))
	}
	if !res.Failed {
		t.Errorf("expired deadline should mark Failed: %+v", flags(res))
	}
}

// Version must be non-empty: it is folded into the verdict-cache fingerprint, so
// an empty value would silently disable extractor-version cache invalidation.
func TestVersionSet(t *testing.T) {
	if Version == "" {
		t.Error("extract.Version is empty")
	}
}

// codes() must bound the OLE2-path macro output three ways (ROBUST-BOUNDS), so a
// crafted vbaProject.bin can't OOM the container through res.Streams: per-module
// truncation, a stream-count cap, and a total-bytes cap across modules.
func TestCodesBounded(t *testing.T) {
	// One oversized module is truncated to maxBytesPerModule, not copied whole.
	huge := oleparse.VBAModule{Code: string(make([]byte, maxBytesPerModule+4096))}
	out := codes(nil, []*oleparse.VBAModule{&huge}, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 stream, got %d", len(out))
	}
	if len(out[0]) != maxBytesPerModule {
		t.Errorf("module not clamped: got %d, want %d", len(out[0]), maxBytesPerModule)
	}

	// Thousands of modules can't exceed maxStreams blobs.
	many := make([]*oleparse.VBAModule, maxStreams+50)
	for i := range many {
		many[i] = &oleparse.VBAModule{Code: "x"}
	}
	if got := len(codes(nil, many, nil)); got > maxStreams {
		t.Errorf("stream-count cap breached: got %d, want <= %d", got, maxStreams)
	}

	// Total bytes across modules can't exceed maxTotalCode. Each 1 MiB module,
	// enough of them to blow maxTotalCode well before maxStreams (256).
	big := make([]*oleparse.VBAModule, 64)
	for i := range big {
		big[i] = &oleparse.VBAModule{Code: string(make([]byte, 1<<20))}
	}
	out = codes(nil, big, nil)
	total := 0
	for _, b := range out {
		total += len(b)
	}
	if total > maxTotalCode {
		t.Errorf("total-bytes cap breached: got %d, want <= %d", total, maxTotalCode)
	}
}

func TestCodesByteBackedModules(t *testing.T) {
	huge := oleparse.VBAModule{CodeBytes: bytes.Repeat([]byte{'x'}, maxBytesPerModule+4096)}
	res := &Result{}
	out := codes(res, []*oleparse.VBAModule{&huge}, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 stream, got %d", len(out))
	}
	if len(out[0]) != maxBytesPerModule {
		t.Fatalf("byte-backed module not clamped: got %d, want %d", len(out[0]), maxBytesPerModule)
	}
	if len(res.VBAStreams) != 1 || len(res.VBAStreams[0]) != maxBytesPerModule {
		t.Fatalf("byte-backed module not recorded as VBA stream: got %d streams", len(res.VBAStreams))
	}

	both := oleparse.VBAModule{Code: "legacy", CodeBytes: []byte("bytes")}
	out = codes(nil, []*oleparse.VBAModule{&both}, nil)
	if got := string(out[0]); got != "bytes" {
		t.Fatalf("CodeBytes should win over Code: got %q", got)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func makeZip(t *testing.T, name, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func flags(r Result) map[string]any {
	return map[string]any{
		"IsDoc": r.IsDoc, "Encrypted": r.Encrypted,
		"Failed": r.Failed, "Panicked": r.Panicked, "streams": len(r.Streams),
	}
}

// makeMultiPartZip builds an in-memory zip from name→bytes entries (write order
// preserved, which zip.Reader walks via the central directory).
func makeMultiPartZip(t *testing.T, entries [][2]any) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, e := range entries {
		w, err := zw.Create(e[0].(string))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e[1].([]byte)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func hasMarker(res Result, name string) bool {
	for _, s := range res.Markers {
		if string(s) == name {
			return true
		}
	}
	for _, s := range res.Streams {
		if string(s) == name {
			return true
		}
	}
	return false
}

// TestOLEIDVBAPresent_NoFalseMarkerFromLaterStream is the #1 regression for the
// VBA half: a macro-looking .bin that yields NO VBA codes (unparseable) plus a
// later DDE field must NOT emit OLEID-VBA-PRESENT. Before the fix, the marker
// condition measured len(out) > parentStreams at the END of the function, so the
// DDE-field stream appended after the .bin loop falsely satisfied it.
func TestOLEIDVBAPresent_NoFalseMarkerFromLaterStream(t *testing.T) {
	ddeDoc := []byte(`<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:fldSimple w:instr="DDEAUTO c:\Windows\System32\cmd.exe /k calc"/></w:p></w:body></w:document>`)
	zipBytes := makeMultiPartZip(t, [][2]any{
		{"word/vbaProject.bin", []byte("not a real OLE2 vbaProject — oleparse must fail on this")},
		{"word/document.xml", ddeDoc},
	})
	res := Extract(zipBytes, time.Time{})

	if hasMarker(res, "OLEID-VBA-PRESENT") {
		t.Error("false OLEID-VBA-PRESENT: the .bin produced no VBA codes; only a later DDE stream was appended")
	}
	// Sanity: the DDE field itself IS detected (proves the doc was processed, the
	// test isn't passing because nothing ran).
	if !hasMarker(res, "OLEID-DDE") {
		t.Errorf("setup: OLEID-DDE not emitted; markers=%v streams=%d", res.Markers, len(res.Streams))
	}
}

// TestOLEIDXLMPresent_NoFalseMarkerFromDocProps is the #1 regression for the XLM
// half: an OOXML doc with docProps strings (appended AFTER the XLM phase) but NO
// hidden macrosheet and NO folded XLM must NOT emit OLEID-XLM-PRESENT. Before the
// fix, len(out) > lenBeforeXLM measured at the END counted the docProps streams.
func TestOLEIDXLMPresent_NoFalseMarkerFromDocProps(t *testing.T) {
	core := []byte(`<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>http://payload.example/c2.exe</dc:title></cp:coreProperties>`)
	zipBytes := makeMultiPartZip(t, [][2]any{
		{"docProps/core.xml", core},
		{"word/document.xml", []byte(`<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>`)},
	})
	res := Extract(zipBytes, time.Time{})

	if hasMarker(res, "OLEID-XLM-PRESENT") {
		t.Error("false OLEID-XLM-PRESENT: no hidden macrosheet and no XLM fold; only docProps strings were appended")
	}
	// Sanity: docProps WAS processed (marker present), so the false-XLM path was
	// actually reachable in this test.
	if !res.HasDocProps {
		t.Errorf("setup: docProps not processed; markers=%v", res.Markers)
	}
}

// TestVBAStreamsPopulatedOnlyByMacros is the #5 regression (extract half): a real
// macro document must record its decompressed VBA modules in res.VBAStreams (a
// subset of Streams), and a non-macro container must leave VBAStreams empty — so
// the scanner can set the VBA external only for genuine macro source.
func TestVBAStreamsPopulatedOnlyByMacros(t *testing.T) {
	// Macro workbook → VBAStreams non-empty, every entry also present in Streams.
	macro := Extract(readFixture(t, "xlswithmacro.xlsm"), time.Time{})
	if len(macro.VBAStreams) == 0 {
		t.Fatal("macro workbook produced no VBAStreams")
	}
	inStreams := func(b []byte) bool {
		for _, s := range macro.Streams {
			if bytes.Equal(s, b) {
				return true
			}
		}
		return false
	}
	for i, vs := range macro.VBAStreams {
		if !inStreams(vs) {
			t.Errorf("VBAStreams[%d] not found in Streams (must be a subset)", i)
		}
	}

	// A non-macro container (a DDE-field doc, no vbaProject.bin) → no VBAStreams,
	// even though it produces extracted streams (the DDE marker etc.).
	ddeDoc := makeOOXMLWithDocument(t, `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:fldSimple w:instr="DDEAUTO c:\Windows\System32\cmd.exe /k calc"/></w:p></w:body></w:document>`)
	nonMacro := Extract(ddeDoc, time.Time{})
	if len(nonMacro.VBAStreams) != 0 {
		t.Errorf("non-macro doc recorded %d VBAStreams (want 0)", len(nonMacro.VBAStreams))
	}
}
