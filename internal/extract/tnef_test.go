package extract

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// tnefObj encodes one TNEF TLV object the way Teamwork/tnef's decoder reads it:
// level(1) name(2 LE) type(2 LE) length(4 LE) data[length] checksum(2).
func tnefObj(level, name int, data []byte) []byte {
	b := []byte{byte(level)}
	b = binary.LittleEndian.AppendUint16(b, uint16(name))
	b = binary.LittleEndian.AppendUint16(b, 0) // type (unused by us)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	b = append(b, data...)
	b = append(b, 0, 0) // checksum (decoder skips it)
	return b
}

// buildTNEF assembles a minimal valid winmail.dat carrying a single attachment
// whose ATTATTACHDATA bytes are payload.
func buildTNEF(payload []byte) []byte {
	const (
		lvlAttachment     = 0x02
		attAttachRendData = 0x9002 // starts a new attachment
		attAttachData     = 0x800f // the attachment file bytes
	)
	blob := []byte{0x78, 0x9F, 0x3E, 0x22, 0x00, 0x00} // signature + key
	blob = append(blob, tnefObj(lvlAttachment, attAttachRendData, []byte{0x00})...)
	blob = append(blob, tnefObj(lvlAttachment, attAttachData, payload)...)
	return blob
}

func TestIsTNEF(t *testing.T) {
	if !isTNEF([]byte{0x78, 0x9F, 0x3E, 0x22, 0, 0}) {
		t.Error("isTNEF rejected a valid TNEF signature")
	}
	for _, bad := range [][]byte{
		nil,
		{0x78, 0x9F, 0x3E},       // too short
		{0x4D, 0x5A, 0x90, 0x00}, // MZ
		{0x78, 0x9F, 0x3E, 0x23}, // last byte off by one
	} {
		if isTNEF(bad) {
			t.Errorf("isTNEF accepted non-TNEF %v", bad)
		}
	}
}

func TestFromTNEF_CarvesAttachment(t *testing.T) {
	payload := []byte("MZ\x90\x00TNEF-ATTACHMENT-PAYLOAD-MARKER")
	blob := buildTNEF(payload)

	var res Result
	// nil budget → no recursion; the raw attachment stream is still emitted.
	fromTNEF(blob, &res, nil, 0, time.Time{})

	if !res.IsTNEF {
		t.Fatal("fromTNEF did not set IsTNEF on a valid blob")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("TNEF-ATTACHMENT-PAYLOAD-MARKER")) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("attachment payload not emitted; got %d streams", len(res.Streams))
	}
}

// A blob with the signature but a truncated/garbage body must not crash the
// extractor (Extract's recover and fromTNEF's own recover cover it).
func TestFromTNEF_MalformedNoPanic(t *testing.T) {
	for _, blob := range [][]byte{
		{0x78, 0x9F, 0x3E, 0x22, 0x00, 0x00},                   // signature only
		{0x78, 0x9F, 0x3E, 0x22, 0x00, 0x00, 0x02, 0x0f, 0x80}, // truncated object header
	} {
		var res Result
		fromTNEF(blob, &res, nil, 0, time.Time{})
		if !res.IsTNEF {
			t.Error("IsTNEF should be set even on a malformed TNEF blob")
		}
	}
}
