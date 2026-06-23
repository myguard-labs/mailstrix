package extract

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// buildFDSO assembles one FileDataStoreObject: guidHeader + cbLength + unused +
// reserved + data (+ optional trailing padding/footer noise). cbLenOverride, if
// non-zero, is written as cbLength instead of len(data) — used to exercise a
// hostile oversized length claim.
func buildFDSO(data []byte, cbLenOverride uint64) []byte {
	var b bytes.Buffer
	b.Write(oneFDSOHeaderGUID)
	cb := uint64(len(data))
	if cbLenOverride != 0 {
		cb = cbLenOverride
	}
	var n8 [8]byte
	binary.LittleEndian.PutUint64(n8[:], cb)
	b.Write(n8[:])
	b.Write([]byte{0, 0, 0, 0})             // unused (uint32)
	b.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // reserved (uint64)
	b.Write(data)
	return b.Bytes()
}

// buildOneNote prepends the .one section file-type GUID to a body.
func buildOneNote(body []byte) []byte {
	out := append([]byte(nil), oneSectionGUID...)
	return append(out, body...)
}

// A .one section with an embedded executable payload must be recognised and the
// FileDataStoreObject bytes surfaced for scanning.
func TestExtractOneNoteEmbedded(t *testing.T) {
	payload := []byte("MZ\x90\x00 embedded onenote payload EICAR-ish dropper")
	buf := buildOneNote(buildFDSO(payload, 0))
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Fatal(".one not flagged IsDoc")
	}
	if !res.IsOneNote {
		t.Fatal(".one not flagged IsOneNote")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("embedded onenote payload")) {
			found = true
		}
	}
	if !found {
		t.Errorf("FileDataStoreObject payload not surfaced; got %d streams", len(res.Streams))
	}
}

// Two embedded files in one section must both be carved.
func TestExtractOneNoteMultiple(t *testing.T) {
	var body bytes.Buffer
	body.Write(buildFDSO([]byte("first dropper payload AAAA"), 0))
	body.Write([]byte("\x00\x00 some onenote object-graph filler \x00\x00"))
	body.Write(buildFDSO([]byte("second dropper payload BBBB"), 0))
	buf := buildOneNote(body.Bytes())
	res := Extract(buf, time.Time{})
	var a, b bool
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("first dropper payload")) {
			a = true
		}
		if bytes.Contains(s, []byte("second dropper payload")) {
			b = true
		}
	}
	if !a || !b {
		t.Errorf("expected both embedded files; first=%v second=%v (%d streams)", a, b, len(res.Streams))
	}
}

// A hostile cbLength far larger than the bytes present must clamp to what's
// available, never over-read or panic.
func TestExtractOneNoteOversizedLen(t *testing.T) {
	payload := []byte("short payload but lying about size")
	buf := buildOneNote(buildFDSO(payload, 1<<40)) // claim 1 TiB
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Fatal("oversized cbLength panicked")
	}
	if !res.IsOneNote {
		t.Fatal("not flagged IsOneNote")
	}
	for _, s := range res.Streams {
		if len(s) > len(payload)+64 {
			t.Errorf("emitted %d bytes from an oversized claim; expected clamp", len(s))
		}
	}
}

// A OneNote section with no FileDataStoreObject is still recognised, emits no
// streams, and never fails.
func TestExtractOneNoteNoEmbedded(t *testing.T) {
	buf := buildOneNote([]byte("a onenote section with only text, no embedded files"))
	res := Extract(buf, time.Time{})
	if !res.IsOneNote {
		t.Fatal("not flagged IsOneNote")
	}
	if len(res.Streams) != 0 {
		t.Errorf("expected no streams, got %d", len(res.Streams))
	}
	if res.Failed {
		t.Error("empty-but-valid OneNote wrongly flagged Failed")
	}
}

// A truncated FileDataStoreObject header (GUID present but not enough following
// bytes) must be handled without panic and emit nothing.
func TestExtractOneNoteTruncatedHeader(t *testing.T) {
	body := append([]byte(nil), oneFDSOHeaderGUID...)
	body = append(body, 0x01, 0x02, 0x03) // only 3 bytes after the GUID
	buf := buildOneNote(body)
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Fatal("truncated FDSO header panicked")
	}
	if len(res.Streams) != 0 {
		t.Errorf("truncated header should emit nothing, got %d streams", len(res.Streams))
	}
}

// A non-OneNote buffer must not be flagged IsOneNote.
func TestExtractNotOneNote(t *testing.T) {
	res := Extract([]byte("just some plain text, definitely not onenote"), time.Time{})
	if res.IsOneNote {
		t.Error("plain text wrongly flagged IsOneNote")
	}
}

// TestExtractOneNoteGUIDInDataNotReEmitted guards the carve-advance: the loop
// must step past the consumed FileDataStoreObject DATA, not just its header. A
// payload that itself contains the FDSO header GUID must NOT be re-found inside
// the bytes already emitted and surfaced again as an overlapping near-duplicate.
func TestExtractOneNoteGUIDInDataNotReEmitted(t *testing.T) {
	// Embedded payload whose bytes include the sentinel header GUID.
	payload := append([]byte("MZ before-"), oneFDSOHeaderGUID...)
	payload = append(payload, []byte("-after the embedded GUID")...)
	buf := buildOneNote(buildFDSO(payload, 0))

	res := Extract(buf, time.Time{})
	if len(res.Streams) != 1 {
		t.Fatalf("GUID-in-data re-emitted: got %d streams, want exactly 1", len(res.Streams))
	}
	if !bytes.Equal(res.Streams[0], payload) {
		t.Errorf("carved stream mismatch:\n  got  %q\n  want %q", res.Streams[0], payload)
	}
}

// TestFromOneNotePanicRecovery verifies that fromOneNote does not propagate a
// panic on a hostile buffer. The FDSO header GUID is present but the payload is
// truncated so that length-field reads and slice operations are out-of-bounds —
// potential panic sites without the recover guard.
func TestFromOneNotePanicRecovery(t *testing.T) {
	// A buffer containing the FDSO header GUID but only 4 bytes of data after it
	// (less than the 20-byte minimum header the parser expects). The subsequent
	// binary.LittleEndian.Uint64 and slice operations would previously panic.
	hostile := append(append([]byte{}, oneSectionGUID...), oneFDSOHeaderGUID...)
	hostile = append(hostile, []byte{0xDE, 0xAD, 0xBE, 0xEF}...)
	res := &Result{}
	// Must not panic.
	fromOneNote(hostile, res, time.Time{})
	if !res.IsOneNote {
		t.Error("IsOneNote should be set regardless of parse failure")
	}
}
