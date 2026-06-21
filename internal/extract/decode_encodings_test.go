package extract

import (
	"encoding/base32"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------- \xXX hex-escape tests ----------

func TestDecodeXEscPositive(t *testing.T) {
	payload := []byte("http://evil.example/malware")
	var enc strings.Builder
	for _, b := range payload {
		fmt.Fprintf(&enc, `\x%02X`, b)
	}
	buf := []byte("var s = \"" + enc.String() + "\";")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, string(payload)) {
		t.Fatalf("\\xXX payload not decoded; streams=%v", streamsAsStrings(res))
	}
}

func TestDecodeXEscLooksEncoded(t *testing.T) {
	run := []byte(`\x68\x74\x74\x70\x3A\x2F\x2F\x65`) // 8 escapes
	if !looksEncoded(run) {
		t.Error("looksEncoded false for \\xXX run")
	}
	if looksEncoded([]byte("hello world plain text")) {
		t.Error("looksEncoded true for plain text")
	}
}

// ---------- &HXX VBA hex literal tests ----------

func TestDecodeAmpHPositive(t *testing.T) {
	payload := []byte("http://evil.example/malware")
	var enc strings.Builder
	for i, b := range payload {
		if i > 0 {
			enc.WriteByte(',')
		}
		fmt.Fprintf(&enc, "&H%02X", b)
	}
	buf := []byte(enc.String())
	res := Extract(buf, time.Time{})
	if !streamsContain(res, string(payload)) {
		t.Fatalf("&HXX payload not decoded; streams=%v", streamsAsStrings(res))
	}
}

// ---------- \uXXXX / %uXXXX Unicode escape tests ----------

func TestDecodeUEscPositive(t *testing.T) {
	// "http://evil.example/" encoded as \uXXXX (ASCII, so high byte is 0)
	payload := "http://evil.example/" // 20 chars = 20 units, well above min 8
	var enc strings.Builder
	for _, r := range payload {
		fmt.Fprintf(&enc, `\u%04X`, r)
	}
	buf := []byte(enc.String())
	res := Extract(buf, time.Time{})
	if !streamsContain(res, payload) {
		t.Fatalf("\\uXXXX payload not decoded; streams=%v", streamsAsStrings(res))
	}
}

func TestDecodePercentUEscPositive(t *testing.T) {
	payload := "http://evil.example/"
	var enc strings.Builder
	for _, r := range payload {
		fmt.Fprintf(&enc, "%%u%04X", r)
	}
	buf := []byte(enc.String())
	res := Extract(buf, time.Time{})
	if !streamsContain(res, payload) {
		t.Fatalf("%%uXXXX payload not decoded; streams=%v", streamsAsStrings(res))
	}
}

// ---------- Decimal sequence tests ----------

func TestDecodeDecSeqPositive(t *testing.T) {
	payload := []byte("http://evil.example/dropper") // 27 bytes, well above min 12
	parts := make([]string, len(payload))
	for i, b := range payload {
		parts[i] = strconv.Itoa(int(b))
	}
	buf := []byte(strings.Join(parts, ","))
	res := Extract(buf, time.Time{})
	if !streamsContain(res, string(payload)) {
		t.Fatalf("decimal sequence not decoded; streams=%v", streamsAsStrings(res))
	}
}

func TestDecodeDecSeqSemicolon(t *testing.T) {
	payload := []byte("http://evil.example/dropper")
	parts := make([]string, len(payload))
	for i, b := range payload {
		parts[i] = strconv.Itoa(int(b))
	}
	buf := []byte(strings.Join(parts, ";"))
	res := Extract(buf, time.Time{})
	if !streamsContain(res, string(payload)) {
		t.Fatalf("semicolon-separated decimal sequence not decoded; streams=%v", streamsAsStrings(res))
	}
}

func TestDecodeDecSeqNegativeMixed(t *testing.T) {
	// Mix of ; and , separators — should NOT decode (conservative FP gate).
	buf := []byte("104,116,116;112,58,47,47,101,118,105,108,46,99,111,109")
	before := &Result{}
	fromEncoded(buf, before, time.Time{})
	// Just assert it doesn't panic; mixed separators must not produce garbage.
	_ = before
}

// ---------- NETBIOS tests ----------

func TestDecodeNetbiosPositive(t *testing.T) {
	// Encode "http://evil.example/" (20 bytes = 40 NETBIOS chars, all printable ASCII)
	payload := []byte("http://evil.example/") // 20 bytes
	var enc strings.Builder
	for _, b := range payload {
		enc.WriteByte('A' + (b >> 4))
		enc.WriteByte('A' + (b & 0xF))
	}
	encoded := enc.String()
	buf := []byte("NETBIOS: " + encoded + " end")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, string(payload)) {
		t.Fatalf("NETBIOS payload not decoded; encoded=%q streams=%v", encoded, streamsAsStrings(res))
	}
}

func TestDecodeNetbiosNegativeNullBytes(t *testing.T) {
	// 32 'A's decode to 16 null bytes (0x00). mostlyText gate must reject them
	// (null bytes are not printable), so no garbage stream should be emitted.
	buf := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 32 A's = 16 null bytes
	res := Extract(buf, time.Time{})
	for _, s := range res.Streams {
		allNull := true
		for _, b := range s {
			if b != 0x00 {
				allNull = false
				break
			}
		}
		if allNull && len(s) > 4 {
			t.Fatalf("NETBIOS emitted null-byte garbage; stream=%q", s)
		}
	}
}

// ---------- Base32 tests ----------

func TestDecodeBase32Positive(t *testing.T) {
	payload := []byte("http://evil.example/malware")
	enc := base32.StdEncoding.EncodeToString(payload)
	// base32 of ASCII text always has 2-7 chars in the output for most inputs.
	buf := []byte("data: " + enc + " end")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, string(payload)) {
		t.Fatalf("base32 payload not decoded; encoded=%q streams=%v", enc, streamsAsStrings(res))
	}
}

func TestDecodeBase32NegativePureAlpha(t *testing.T) {
	// A run of pure [A-Z] with no 2-7 should be skipped by base32 (ambiguous).
	// Verify no panic and no crash.
	buf := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")
	res := Extract(buf, time.Time{})
	_ = res // just verify no panic
}

func TestDecodeBase32LooksEncoded(t *testing.T) {
	// A base32 string with 2-7 distinctive chars should trigger looksEncoded.
	run := []byte("JBSWY3DPEB3W64TMMQ2HK3TJNZSXI4TF") // contains 3, 6, 4, 3, etc.
	if !looksEncoded(run) {
		t.Errorf("looksEncoded false for base32 run with distinctive chars")
	}
}

func TestDecodeBase32NoPadding(t *testing.T) {
	// Verify tryBase32 handles missing padding (adds '=' to reach multiple of 8).
	payload := []byte("http://evil.example/")
	enc := base32.StdEncoding.EncodeToString(payload)
	// Strip trailing padding.
	enc = strings.TrimRight(enc, "=")
	buf := []byte(enc)
	dec, ok := tryBase32(buf)
	if !ok {
		t.Fatalf("tryBase32 failed on unpadded input %q", enc)
	}
	if string(dec) != string(payload) {
		t.Fatalf("tryBase32 decoded to %q, want %q", dec, payload)
	}
}
