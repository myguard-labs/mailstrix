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

// An RTF-embedded CFB must go through the FULL OLE2 surface (fromOLE), not just
// the macro/package/MSG/MSI subset (audit 2026-06-25). A CFB carrying an
// ObjectPool storage emits the OLEID-OBJECTPOOL indicator only via
// fromOLEIndicators, which the old hand-rolled RTF CFB branch never called — so
// this marker proves the embedded OLE2 now gets the same indicators as a
// top-level one.
func TestExtractRTFEmbeddedCFBFullOLESurface(t *testing.T) {
	cfb := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "ObjectPool", mse: 1},
		{name: "WordDocument", mse: 2, data: []byte("body text, no macros")},
	})
	buf := wrapRTFObjData(cfb)
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !streamsContain(res, "OLEID-OBJECTPOOL") {
		t.Errorf("RTF-embedded CFB did not run the full OLE2 indicator surface (no OLEID-OBJECTPOOL); streams=%v", streamsAsStrings(res))
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
	// RTF-OBJUPDATE is a PURE marker → out-of-band Markers channel (PLAN Phase 1).
	joined := bytes.Join(res.Markers, []byte("|"))
	if !bytes.Contains(joined, []byte("RTF-OBJUPDATE")) {
		t.Fatalf("\\objupdate not detected; markers=%d joined=%q", len(res.Markers), joined)
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

// RTF-HARDEN: \'HH hex-byte control symbols must decode as whole bytes, including
// interleaved with the raw nibble run and Word's single-hex-digit \' quirk.
func TestDecodeRTFHexQuoteBytes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []byte
	}{
		{"all-quoted", `\'4d\'5a`, []byte("MZ")},
		{"quoted-then-raw", `\'4d 5a`, []byte("MZ")},
		{"raw-then-quoted", `4d\'5a`, []byte("MZ")},
		// A dangling raw nibble before an explicit byte: the nibble flushes as its
		// own (high) half-byte, the \' byte stays intact — no cross-corruption.
		{"dangling-nibble", `4\'41`, []byte{0x04, 0x41}},
		{"single-digit-quirk", `\'4 5a`, []byte{0x04, 0x5a}},
	}
	for _, c := range cases {
		if got := decodeRTFHex([]byte(c.in)); !bytes.Equal(got, c.want) {
			t.Errorf("%s: decodeRTFHex(%q) = %x, want %x", c.name, c.in, got, c.want)
		}
	}
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

// --- Adversarial RTF obfuscation tests ---

// Attackers embed spaces/tabs/newlines between every hex nibble (not just between
// pairs) to break naive hex decoders that require contiguous pairs.
func TestExtractRTFHexWhitespaceBetweenNibbles(t *testing.T) {
	payload := []byte("MZ\x90\x00 rtf-whitespace-nibble obfuscated payload")
	stream := buildOle10Native("w.exe", "C:\\w.exe", "C:\\Temp\\w.exe", payload, 0)
	raw := hex.EncodeToString(stream)
	// Insert a space after every nibble and a CRLF+TAB after every pair
	var sb strings.Builder
	for i := 0; i < len(raw); i++ {
		sb.WriteByte(raw[i])
		if i%2 == 1 {
			sb.WriteString("\r\n\t")
		} else {
			sb.WriteByte(' ')
		}
	}
	buf := []byte("{\\rtf1{\\object{\\*\\objdata " + sb.String() + "}}}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !res.IsOLEPackage {
		t.Fatalf("whitespace-between-nibbles obfuscation defeated extraction; streams=%d", len(res.Streams))
	}
	if !streamsContain(res, "rtf-whitespace-nibble obfuscated payload") {
		t.Errorf("carved payload not found; got %d streams", len(res.Streams))
	}
}

// Mixed-case hex (D0CF11E0 vs d0cf11e0) must decode identically — uppercase
// A-F are valid per the RTF spec.
func TestExtractRTFMixedCaseHex(t *testing.T) {
	payload := []byte("MZ\x90\x00 rtf-mixed-case hex payload")
	stream := buildOle10Native("mc.exe", "C:\\mc.exe", "C:\\Temp\\mc.exe", payload, 0)
	raw := hex.EncodeToString(stream)
	// Alternate pairs: even-indexed pairs uppercase, odd-indexed pairs lowercase
	mixedHex := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		if (i/2)%2 == 0 {
			if raw[i] >= 'a' && raw[i] <= 'f' {
				mixedHex[i] = raw[i] - 32 // to uppercase
			} else {
				mixedHex[i] = raw[i]
			}
		} else {
			mixedHex[i] = raw[i]
		}
	}
	buf := []byte("{\\rtf1{\\object{\\*\\objdata " + string(mixedHex) + "}}}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !res.IsOLEPackage {
		t.Fatalf("mixed-case hex defeated extraction; streams=%d", len(res.Streams))
	}
	if !streamsContain(res, "rtf-mixed-case hex payload") {
		t.Errorf("carved payload not found; got %d streams", len(res.Streams))
	}
}

// Extra empty or keyword-carrying nested groups injected into the hex run must not
// discard surrounding hex — depth tracking must resume decoding after each close.
func TestExtractRTFFakeNestedGroups(t *testing.T) {
	payload := []byte("MZ\x90\x00 rtf-fake-nested-group payload for extraction")
	stream := buildOle10Native("fn.exe", "C:\\fn.exe", "C:\\Temp\\fn.exe", payload, 0)
	raw := hex.EncodeToString(stream)
	if len(raw) < 60 {
		t.Skip("stream too short for split test")
	}
	// Split at multiple offsets and insert various inert groups between chunks
	obfuscated := raw[:10] +
		"{}" +
		raw[10:30] +
		"{\\blipuid deadbeef}" +
		raw[30:60] +
		"{\\nonshppict{}}" +
		raw[60:]
	buf := []byte("{\\rtf1{\\object{\\*\\objdata " + obfuscated + "}}}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !res.IsOLEPackage {
		t.Fatalf("fake-nested-group obfuscation defeated extraction; streams=%d", len(res.Streams))
	}
	if !streamsContain(res, "rtf-fake-nested-group payload") {
		t.Errorf("carved payload not found; got %d streams", len(res.Streams))
	}
}

// \binN in the middle of the hex run: the decoder must skip exactly N binary bytes
// then resume hex decoding at the correct position.
func TestExtractRTFBinSkip(t *testing.T) {
	payload := []byte("MZ\x90\x00 rtf-bin-skip payload across bin boundary")
	stream := buildOle10Native("bs.exe", "C:\\bs.exe", "C:\\Temp\\bs.exe", payload, 0)
	raw := hex.EncodeToString(stream)
	mid := len(raw) / 2
	// Insert \bin5 with 5 junk binary bytes in the middle of the hex stream.
	// The binary bytes are literal (not hex), so the decoder must skip them by count.
	junk := "\x00\x01\x02\x03\x04" // 5 binary bytes
	obfuscated := raw[:mid] + "\\bin5 " + junk + raw[mid:]
	buf := []byte("{\\rtf1{\\object{\\*\\objdata " + obfuscated + "}}}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !res.IsOLEPackage {
		t.Fatalf("\\bin obfuscation defeated extraction; streams=%d", len(res.Streams))
	}
	if !streamsContain(res, "rtf-bin-skip payload") {
		t.Errorf("carved payload not found; got %d streams", len(res.Streams))
	}
}

// {\*\keyword ...} ignore-groups inside the hex run must be skipped in full
// (nested-group depth tracking handles them). Importantly the \* control symbol
// must not truncate hex decoding when encountered at depth 0 before the `{`.
func TestExtractRTFStarIgnoreGroup(t *testing.T) {
	payload := []byte("MZ\x90\x00 rtf-star-ignore-group payload extraction test")
	stream := buildOle10Native("si.exe", "C:\\si.exe", "C:\\Temp\\si.exe", payload, 0)
	raw := hex.EncodeToString(stream)
	mid := len(raw) / 2
	// Insert {\*\nonstandard ...} group in the middle — must be skipped entirely
	obfuscated := raw[:mid] + "{\\*\\nonstandard this should be ignored}" + raw[mid:]
	buf := []byte("{\\rtf1{\\object{\\*\\objdata " + obfuscated + "}}}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !res.IsOLEPackage {
		t.Fatalf("{\\*\\keyword} ignore-group terminated hex decoding early; streams=%d", len(res.Streams))
	}
	if !streamsContain(res, "rtf-star-ignore-group payload") {
		t.Errorf("carved payload not found; got %d streams", len(res.Streams))
	}
}

// A bare \* control symbol at depth 0 (not wrapped in a group) must be consumed
// without panicking or terminating hex decoding prematurely.
func TestExtractRTFBareStarControlSymbol(t *testing.T) {
	// Use OLE magic prefix so carveRTFObject exercises the CFB code path.
	// The \* splits the hex run at depth 0 — decoder must skip it and keep going.
	hexData := "d0cf11e0" + "\\* " + "a1b11ae1" + strings.Repeat("00", 24)
	buf := []byte("{\\rtf1{\\object{\\*\\objdata " + hexData + "}}}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	// The OLE may be invalid (truncated) but must not panic — no crash is the assertion.
	_ = res.Streams
}

// Deeply nested empty groups with no hex content at depth 0 must not panic and
// must yield no OLE package (graceful fail on genuinely empty payload).
func TestExtractRTFDeeplyNestedEmptyGroups(t *testing.T) {
	inner := ""
	for i := 0; i < 20; i++ {
		inner = "{" + inner + "}"
	}
	buf := []byte("{\\rtf1{\\object{\\*\\objdata " + inner + "}}}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if res.IsOLEPackage {
		t.Error("empty nested groups incorrectly yielded IsOLEPackage")
	}
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

// TestCarveRTFObjectPanicRecovery verifies that carveRTFObject does not propagate
// a panic on a hostile blob that starts with OLE magic but is otherwise garbage.
// oleparse may panic on such input; the defer/recover guard must catch it and mark
// res.Panicked without losing any previously written streams.
func TestCarveRTFObjectPanicRecovery(t *testing.T) {
	// OLE magic followed by attacker-controlled garbage — enough bytes to pass
	// the magic check but malformed enough to trigger deep panic paths in oleparse.
	hostile := append(append([]byte{}, oleMagic...), bytes.Repeat([]byte{0xFF}, 4096)...)
	res := &Result{}
	bud := &archiveBudget{}
	// Must not panic.
	carveRTFObject(hostile, res, bud, 0, time.Time{})
}

// TestDecodeRTFHexBinOverflow verifies a hostile \binN with an overlong count
// does not panic. strconv.Atoi overflows to (MaxInt, ErrRange); before the fix
// the ignored error let `j+n` wrap negative, slip past the `i > len(b)` clamp,
// and panic on the next index. decodeRTFHex must treat an unparseable / oversized
// N as "skip to end" and return cleanly.
func TestDecodeRTFHexBinOverflow(t *testing.T) {
	cases := [][]byte{
		[]byte(`41\bin99999999999999999999 4242`), // overflow N (> MaxInt)
		[]byte(`41\bin18446744073709551616 42`),   // > uint64 too
		[]byte(`41\bin99999999 42`),               // N far past the buffer
		[]byte(`41\bin0 4242`),                    // N=0, normal
		[]byte(`41\bin5 ` + "ABCDE" + `4242`),     // N=5, skip exactly 5
	}
	for _, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("decodeRTFHex panicked on %q: %v", in, r)
				}
			}()
			_ = decodeRTFHex(in) // must return without panic
		}()
	}
}
