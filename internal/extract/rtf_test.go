package extract

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// wrapRTFObjData builds a minimal RTF document embedding blob as the hex payload
// of a `{\object ... {\*\objdata <hex>}}` group, with the hex broken across lines
// (as real RTF writers do) to exercise the whitespace-skipping decoder.
func wrapRTFObjData(blob []byte) []byte {
	h := hex.EncodeToString(blob)
	var sb strings.Builder
	sb.WriteString("{\\rtf1\\ansi\\ansicpg1252\n{\\object\\objemb{\\*\\objdata\n")
	for i := 0; i < len(h); i += 64 {
		end := i + 64
		if end > len(h) {
			end = len(h)
		}
		sb.WriteString(h[i:end])
		sb.WriteByte('\n')
	}
	sb.WriteString("}}}\n")
	return []byte(sb.String())
}

// A bare Ole10Native blob hex-embedded in an RTF \objdata group must be decoded
// and its native data carved (the CVE-2017-0199/-11882 / OLE2Link delivery path).
func TestExtractRTFOle10Native(t *testing.T) {
	payload := []byte("MZ\x90\x00 rtf embedded objdata dropper payload calc.exe")
	stream := buildOle10Native("calc.exe", "C:\\evil\\calc.exe", "C:\\Temp\\calc.exe", payload, 0)
	buf := wrapRTFObjData(stream)
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Fatal("RTF not flagged IsDoc")
	}
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !res.IsOLEPackage {
		t.Fatal("bare Ole10Native via RTF not flagged IsOLEPackage")
	}
	if !streamsContain(res, "rtf embedded objdata dropper payload") {
		t.Errorf("carved native data not surfaced; got %d streams", len(res.Streams))
	}
}

// A full OLE2 (CFB) compound file embedded in an RTF \objdata group must run the
// same OLE2 package extraction — the embedded doc's Ole10Native stream is carved.
func TestExtractRTFEmbeddedCFB(t *testing.T) {
	payload := []byte("MZ embedded cfb-in-rtf dropper payload")
	stream := buildOle10Native("x.exe", "x.exe", "x.exe", payload, 0)
	cfb := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "\x01Ole10Native", mse: 2, data: stream},
	})
	buf := wrapRTFObjData(cfb)
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !res.IsOLEPackage {
		t.Fatal("embedded CFB package not flagged IsOLEPackage")
	}
	if !streamsContain(res, "embedded cfb-in-rtf dropper payload") {
		t.Errorf("CFB-in-RTF native data not surfaced; got %d streams", len(res.Streams))
	}
}

// An RTF with a leading BOM/whitespace must still be recognised.
func TestExtractRTFLeadingWhitespace(t *testing.T) {
	if !isRTF([]byte("  \r\n{\\rtf1}")) {
		t.Error("RTF with leading whitespace not recognised")
	}
	if isRTF([]byte("not an rtf {\\rtf1}")) {
		t.Error("non-RTF prefix wrongly recognised")
	}
	// UTF-8 BOM-prefixed RTF must be recognised.
	if !isRTF([]byte{0xEF, 0xBB, 0xBF, '{', '\\', 'r', 't', 'f', '1', '}'}) {
		t.Error("BOM-prefixed RTF not recognised")
	}
}

// A hostile RTF stuffed with empty \objdata groups must be bounded by
// maxRTFObjects (no per-group decode/index work beyond the cap) and yield no
// streams — fail-open, no resource exhaustion.
func TestExtractRTFManyEmptyObjects(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("{\\rtf1")
	for i := 0; i < maxRTFObjects*4; i++ {
		sb.WriteString("{\\object{\\*\\objdata }}")
	}
	sb.WriteString("}")
	res := Extract([]byte(sb.String()), time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if len(res.Streams) != 0 {
		t.Errorf("empty-object flood yielded %d streams", len(res.Streams))
	}
}

// An RTF with no \objdata group is still flagged IsRTF but yields no streams.
func TestExtractRTFNoObject(t *testing.T) {
	buf := []byte("{\\rtf1\\ansi plain document, no embedded object}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if len(res.Streams) != 0 {
		t.Errorf("expected no streams, got %d", len(res.Streams))
	}
}

// A truncated / garbage \objdata hex run must be skipped without panic (fail-open).
func TestExtractRTFGarbageObjData(t *testing.T) {
	// Odd-length, non-OLE, non-Ole10Native hex — must not panic or over-read.
	buf := []byte("{\\rtf1{\\object{\\*\\objdata 4d5a90zzz}}}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	// No valid payload — no crash is the assertion; streams may be empty.
	_ = res.Streams
}

func TestExtractRTFDDE(t *testing.T) {
	buf := []byte(`{\rtf1{\field{\*\fldinst DDEAUTO c:\\Windows\\System32\\cmd.exe /k calc}{\fldrslt }}}`)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("|"))
	if !bytes.Contains(joined, []byte("RTF-DDE-FIELD")) {
		t.Fatalf("RTF DDE not detected; streams=%d joined=%q", len(res.Streams), joined)
	}
	if !bytes.Contains(joined, []byte("DDEAUTO")) {
		t.Fatalf("DDEAUTO token not in emitted stream; got %q", joined)
	}
}

func TestExtractRTFDDE_BareControlWord(t *testing.T) {
	buf := []byte(`{\rtf1\ddeauto some text}`)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("|"))
	if !bytes.Contains(joined, []byte("RTF-DDE-FIELD")) {
		t.Fatalf("bare \\ddeauto not detected; streams=%d joined=%q", len(res.Streams), joined)
	}
}

func TestExtractRTFObjUpdate(t *testing.T) {
	buf := []byte(`{\rtf1{\object\objupdate{\*\objdata d0cf11e0}}}`)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("|"))
	if !bytes.Contains(joined, []byte("RTF-OBJUPDATE")) {
		t.Fatalf("\\objupdate not detected; streams=%d joined=%q", len(res.Streams), joined)
	}
}

func TestExtractRTFObjUpdate_Absent(t *testing.T) {
	buf := []byte(`{\rtf1{\object{\*\objdata d0cf11e0}}}`)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("|"))
	if bytes.Contains(joined, []byte("RTF-OBJUPDATE")) {
		t.Fatalf("\\objupdate marker emitted when absent; got %q", joined)
	}
}

func TestExtractRTFHexNestedGroups(t *testing.T) {
	// Hex "d0cf11e0a1b11ae1" with a nested group injected to break naive decoders
	buf := []byte(`{\rtf1{\object{\*\objdata d0cf11e0{\blipuid abcdef}a1b11ae1}}}`)
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("not flagged as RTF")
	}
	// The hex should decode despite the nested group
	// d0cf11e0 + a1b11ae1 = OLE magic (first 8 bytes)
	// Even though it won't be a valid OLE2, it should attempt the carve (and fail gracefully)
}

func TestExtractRTFHexControlWordSkip(t *testing.T) {
	// Build a valid Ole10Native stream so the carved payload appears in res.Streams.
	// The key assertion is that a \controlword injected in the middle of the hex run
	// is skipped by decodeRTFHex and the blob is reassembled correctly.
	payload := []byte("MZ\x90\x00 rtf-ctrl-word-obfuscated payload for test")
	stream := buildOle10Native("x.exe", "C:\\x.exe", "C:\\Temp\\x.exe", payload, 0)
	hexPayload := hexEncodeForRTF(stream)
	// Insert a control word in the middle of the hex to exercise obfuscation skip
	mid := len(hexPayload) / 2
	obfuscated := string(hexPayload[:mid]) + "\\somecontrolword " + string(hexPayload[mid:])
	buf := []byte(`{\rtf1{\object{\*\objdata ` + obfuscated + `}}}`)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "rtf-ctrl-word-obfuscated payload") {
		t.Fatalf("control-word obfuscation broke hex decode; streams=%d", len(res.Streams))
	}
}

func TestExtractRTFNoDDE(t *testing.T) {
	buf := []byte(`{\rtf1 plain text no dde}`)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("|"))
	if bytes.Contains(joined, []byte("RTF-DDE-FIELD")) || bytes.Contains(joined, []byte("RTF-OBJUPDATE")) {
		t.Fatalf("benign RTF produced markers; got %q", joined)
	}
}

func hexEncodeForRTF(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}

// Multiple \objdata groups are each carved, bounded by maxRTFObjects.
func TestExtractRTFMultipleObjects(t *testing.T) {
	s1 := buildOle10Native("a.exe", "a.exe", "a.exe", []byte("MZ first rtf objdata payload"), 0)
	s2 := buildOle10Native("b.exe", "b.exe", "b.exe", []byte("MZ second rtf objdata payload"), 0)
	h1 := hex.EncodeToString(s1)
	h2 := hex.EncodeToString(s2)
	buf := []byte("{\\rtf1{\\object{\\*\\objdata " + h1 + "}}{\\object{\\*\\objdata " + h2 + "}}}")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "first rtf objdata payload") || !streamsContain(res, "second rtf objdata payload") {
		t.Errorf("expected both objdata payloads carved; got %d streams", len(res.Streams))
	}
}
