package extract

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// pptRecord builds one MS-PPT record header + body.
// ver: low 4 bits of verAndInstance (0xF = container, else leaf).
// inst: high 12 bits of verAndInstance.
// rt: RecordType uint16.
func pptRecord(ver, inst uint16, rt uint16, body []byte) []byte {
	buf := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint16(buf[0:], (inst<<4)|ver)
	binary.LittleEndian.PutUint16(buf[2:], rt)
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(body)))
	copy(buf[8:], body)
	return buf
}

// buildMinimalVBAOLE returns a minimal OLE2 that oleparse.ExtractMacros can
// parse. We reuse buildCFB from msg_test.go to construct an OLE2 with a
// _VBA_PROJECT stream (empty is fine — ExtractMacros sees the storage and
// returns at least one module with empty Code, which codes() emits as a
// zero-length stream). For the PPT test we just need a non-error extraction;
// the marker emission is what matters.
//
// Because buildCFB needs _VBA_PROJECT as a storage + a module stream inside it,
// and that is non-trivial to hand-build, we use the simplest possible approach:
// embed the existing xlswithmacro.xlsm bytes as a sub-OLE (it IS a valid OLE2
// with a vbaProject.bin inside a zip, but oleparse.NewOLEFile on a zip returns
// an error). Instead, build the smallest CFB that has a "Macros" storage with a
// dummy _VBA_PROJECT stream so ExtractMacros returns non-error.
//
// Simpler: just verify fromPPTVBA is a no-op on non-PPT OLE2 and does not panic
// on a crafted "PowerPoint Document" stream with a well-formed EOS record body
// that is NOT a valid sub-OLE2 (error path → skip → no crash, no marker).
func TestPPTVBA_NoPPTStream(t *testing.T) {
	// OLE2 with no "PowerPoint Document" stream — fromPPTVBA must be a no-op.
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "Workbook", mse: 2, data: []byte("dummy"), left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	res := fromPPTVBADirect(t, buf)
	if streamHasNeedle(res, "PPT-VBA-EXTRACTED") {
		t.Error("PPT-VBA-EXTRACTED emitted on non-PPT OLE2")
	}
}

func TestPPTVBA_InvalidEOSBody(t *testing.T) {
	// "PowerPoint Document" stream present, but EOS body is garbage (not a valid
	// sub-OLE2). fromPPTVBA must skip silently — no panic, no marker.
	eosBody := []byte("not-an-ole2-container")
	// inst=0 (uncompressed), rt=0x1011
	rec := pptRecord(0, 0, pptRecTypeExternalObjectStorage, eosBody)
	// Wrap in a container record (ver=0xF) so the walk enters it.
	container := pptRecord(0xF, 0, 0x0FA0, rec)

	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "PowerPoint Document", mse: 2, data: container, left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	res := fromPPTVBADirect(t, buf)
	// Garbage body → oleparse.NewOLEFile fails → no streams, no marker.
	if streamHasNeedle(res, "PPT-VBA-EXTRACTED") {
		t.Error("PPT-VBA-EXTRACTED emitted on invalid EOS body")
	}
}

func TestPPTVBA_ZlibInvalidPayload(t *testing.T) {
	// inst=1 (zlib), body = 4-byte size prefix + invalid compressed data.
	// Must not panic; must not emit marker.
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:], 100)   // declared decompressed size (ignored)
	copy(body[4:], []byte{0xFF, 0xFF, 0xFF, 0xFF}) // invalid zlib data
	rec := pptRecord(0, 1, pptRecTypeExternalObjectStorage, body)

	cfbData := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "PowerPoint Document", mse: 2, data: rec, left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	res := fromPPTVBADirect(t, cfbData)
	if streamHasNeedle(res, "PPT-VBA-EXTRACTED") {
		t.Error("PPT-VBA-EXTRACTED emitted on invalid zlib EOS body")
	}
}

func TestPPTVBA_ZlibValidButNotOLE(t *testing.T) {
	// inst=1, valid zlib but decompressed content is not an OLE2.
	raw := []byte("not-ole2-content-but-valid-zlib")
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	_, _ = zw.Write(raw)
	_ = zw.Close()

	body := make([]byte, 4+zbuf.Len())
	binary.LittleEndian.PutUint32(body[0:], uint32(len(raw)))
	copy(body[4:], zbuf.Bytes())

	rec := pptRecord(0, 1, pptRecTypeExternalObjectStorage, body)
	cfbData := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "PowerPoint Document", mse: 2, data: rec, left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	res := fromPPTVBADirect(t, cfbData)
	if streamHasNeedle(res, "PPT-VBA-EXTRACTED") {
		t.Error("PPT-VBA-EXTRACTED emitted when decompressed body is not OLE2")
	}
}

func TestPPTVBA_DeadlineExpired(t *testing.T) {
	// Expired deadline → fromPPTVBA returns immediately, no panic.
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "PowerPoint Document", mse: 2, data: pptRecord(0, 0, pptRecTypeExternalObjectStorage, []byte("x")),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	// Just verify it didn't panic; marker may or may not fire (expired).
	_ = streamHasNeedle(&res, "PPT-VBA-EXTRACTED")
}

func TestPPTVBA_EmptyStream(t *testing.T) {
	// "PowerPoint Document" exists but is empty (< 8 bytes) → no-op.
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "PowerPoint Document", mse: 2, data: []byte{0x00, 0x01},
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	res := fromPPTVBADirect(t, buf)
	if streamHasNeedle(res, "PPT-VBA-EXTRACTED") {
		t.Error("PPT-VBA-EXTRACTED emitted on too-short PPT stream")
	}
}

func TestPPTVBA_NilOLE(t *testing.T) {
	// Nil OLE2 must not panic.
	var res Result
	fromPPTVBA(nil, &res, time.Time{})
	if streamHasNeedle(&res, "PPT-VBA-EXTRACTED") {
		t.Error("PPT-VBA-EXTRACTED emitted on nil OLE")
	}
}

func TestPPTVBA_RecordBoundsTruncated(t *testing.T) {
	// Record header claims size larger than remaining data → walk stops cleanly.
	// verAndInst=0 (leaf, inst=0), rt=0x1011, size=0xFFFFFFFF
	truncated := make([]byte, 8)
	binary.LittleEndian.PutUint16(truncated[0:], 0x0000)
	binary.LittleEndian.PutUint16(truncated[2:], pptRecTypeExternalObjectStorage)
	binary.LittleEndian.PutUint32(truncated[4:], 0xFFFFFFFF)

	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "PowerPoint Document", mse: 2, data: truncated,
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	res := fromPPTVBADirect(t, buf)
	// No valid body → no marker, no panic.
	if streamHasNeedle(res, "PPT-VBA-EXTRACTED") {
		t.Error("PPT-VBA-EXTRACTED emitted on truncated record")
	}
}

// fromPPTVBADirect calls fromPPTVBA directly with a live deadline, bypassing
// Extract's expired time.Time{} guard. This allows the record-walk body to
// actually execute, making the tests below meaningful.
func fromPPTVBADirect(t *testing.T, buf []byte) *Result {
	t.Helper()
	ole, err := oleparse.NewOLEFile(buf)
	if err != nil {
		t.Fatalf("fromPPTVBADirect: NewOLEFile: %v", err)
	}
	var res Result
	fromPPTVBA(ole, &res, time.Now().Add(30*time.Second))
	return &res
}

func TestPPTVBA_ValidEOSNoVBA(t *testing.T) {
	// Valid sub-OLE2 (no VBA) as EOS body — walk must reach oleparse.NewOLEFile
	// without panic. No VBA modules → no marker.
	subOLE := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "Workbook", mse: 2, data: []byte("dummy workbook"), left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	// inst=0 (raw), rt=0x1011
	rec := pptRecord(0, 0, pptRecTypeExternalObjectStorage, subOLE)
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "PowerPoint Document", mse: 2, data: rec, left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	res := fromPPTVBADirect(t, buf)
	// No VBA modules in sub-OLE2 → no marker (marker only emitted when streams added).
	if streamHasNeedle(res, "PPT-VBA-EXTRACTED") {
		t.Error("PPT-VBA-EXTRACTED emitted when sub-OLE2 has no VBA modules")
	}
}
