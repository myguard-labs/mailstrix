package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestDecodeBase64Stream(t *testing.T) {
	payload := "Sub AutoOpen() : Shell \"powershell\" : End Sub"
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	buf := []byte("dim s : s = \"" + b64 + "\" : exec s")

	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatalf("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "AutoOpen") {
		t.Fatalf("decoded streams do not contain the base64 payload %q; got %d streams", payload, len(res.Streams))
	}
}

func TestDecodeHexStream(t *testing.T) {
	payload := "powershell -enc SQBFAFgA" // 24 bytes -> 48 hex chars
	h := hex.EncodeToString([]byte(payload))
	buf := []byte("cmd = " + h + " run")

	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatalf("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "powershell") {
		t.Fatalf("decoded streams do not contain the hex payload; got %d streams", len(res.Streams))
	}
}

func TestDecodeReversedKeyword(t *testing.T) {
	// "llehsrewop" reversed is "powershell"; reversing the whole buffer surfaces it.
	buf := []byte("harmless prefix llehsrewop harmless suffix")

	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatalf("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "powershell") {
		t.Fatalf("reversed stream does not surface 'powershell'; got %d streams", len(res.Streams))
	}
}

func TestDecodeNonEncodedYieldsNothing(t *testing.T) {
	buf := []byte("This is a perfectly ordinary email body with no encoded payload at all.")

	res := Extract(buf, time.Time{})
	if res.DecodedStreams > 0 {
		t.Fatalf("DecodedStreams > 0 on plain text, want 0")
	}
	if len(res.Streams) != 0 {
		t.Fatalf("plain text produced %d streams, want 0", len(res.Streams))
	}
}

func TestDecodeExpiredDeadlineYieldsNothing(t *testing.T) {
	payload := "Sub AutoOpen() : Shell \"powershell\" : End Sub"
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	buf := []byte("dim s : s = \"" + b64 + "\"")

	res := Extract(buf, time.Now().Add(-time.Second))
	if res.DecodedStreams > 0 {
		t.Fatalf("DecodedStreams > 0 with an expired deadline, want 0")
	}
	if len(res.Streams) != 0 {
		t.Fatalf("expired deadline produced %d streams, want 0", len(res.Streams))
	}
}

// TestDecodeDepthCapOne proves the pass does not chain: a base64-of-base64 blob
// decodes exactly one layer, so the inner plaintext is never surfaced.
func TestDecodeDepthCapOne(t *testing.T) {
	inner := "powershellPayloadHiddenTwoLayersDeep"
	b1 := base64.StdEncoding.EncodeToString([]byte(inner)) // first layer (still base64 text)
	outer := base64.StdEncoding.EncodeToString([]byte(b1)) // second layer
	buf := []byte(outer)

	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatalf("DecodedStreams = 0, want >0 (one layer must decode)")
	}
	// The single decode yields b1 (still encoded); the inner plaintext must NOT appear.
	if !streamsContain(res, b1) {
		t.Fatalf("first decode layer (b1) not surfaced")
	}
	if streamsContain(res, "powershellPayload") {
		t.Fatalf("inner plaintext surfaced — decode chained beyond depth 1")
	}
}

// TestDecodeBinarySkipped checks the mostly-text gate: a binary buffer is not
// fed to the decoders even if it embeds a long base64-alphabet run.
func TestDecodeBinarySkipped(t *testing.T) {
	payload := "Sub AutoOpen() : Shell \"powershell\" : End Sub"
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	// A buffer that is >10% non-printable (NUL bytes) fails mostlyText.
	buf := append(bytes.Repeat([]byte{0x00}, 64), []byte(b64)...)

	res := Extract(buf, time.Time{})
	if res.DecodedStreams > 0 {
		t.Fatalf("DecodedStreams > 0 on a binary buffer, want 0 (mostly-text gate)")
	}
}

// TestDecodeHexNotDoubleDecoded pins the all-hex skip in the base64 pass: an
// all-hex run is decoded once (by the hex pass), not also as bogus base64.
func TestDecodeHexNotDoubleDecoded(t *testing.T) {
	payload := "powershell -EncodedCommand AAAA" // >=16 bytes
	h := hex.EncodeToString([]byte(payload))     // pure [0-9a-f]
	buf := []byte("x " + h + " y")

	res := Extract(buf, time.Time{})
	if res.DecodedStreams != 1 {
		t.Fatalf("DecodedStreams = %d, want 1 (base64 must skip the all-hex run)", res.DecodedStreams)
	}
	if !streamsContain(res, "powershell") {
		t.Fatalf("hex payload not surfaced")
	}
}

// TestDecodeHugeRunTruncated pins the pre-decode cap: a base64 run far larger
// than the per-blob cap decodes to exactly one blob, capped at maxBytesPerDecodedBlob.
func TestDecodeHugeRunTruncated(t *testing.T) {
	// 0x18 bytes encode to "GBgY…" — non-hex base64 chars, so the base64 (not hex)
	// pass handles it.
	raw := bytes.Repeat([]byte{0x18}, 3*maxBytesPerDecodedBlob)
	b64 := base64.StdEncoding.EncodeToString(raw)

	res := Extract([]byte(b64), time.Time{})
	if res.DecodedStreams != 1 {
		t.Fatalf("DecodedStreams = %d, want 1", res.DecodedStreams)
	}
	if got := len(res.Streams[len(res.Streams)-1]); got != maxBytesPerDecodedBlob {
		t.Fatalf("decoded blob len = %d, want capped at %d", got, maxBytesPerDecodedBlob)
	}
}

// TestFoldChrConcat verifies that a Chr()/ChrW() concatenation expression is
// folded to the assembled string.
func TestFoldChrConcat(t *testing.T) {
	// "h" & Chr(116) & Chr(116) & "p://" & Chr(101) & "vil.com"
	// Chr(116)='t', Chr(101)='e' → "http://evil.com"
	buf := []byte(`dim s : s = "h" & Chr(116) & Chr(116) & "p://" & Chr(101) & "vil.com"`)
	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatal("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "http://evil.com") {
		t.Fatalf("folded Chr concat not found; streams: %v", streamsAsStrings(res))
	}
}

// TestFoldChrConcatPlus verifies that + as concat operator is also handled.
func TestFoldChrConcatPlus(t *testing.T) {
	// Chr(112)+…+Chr(101) → "powershe" (8 chars, above minDecodedLen)
	buf := []byte(`x = Chr(112) + Chr(111) + Chr(119) + Chr(101) + Chr(114) + Chr(115) + Chr(104) + Chr(101)`)
	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatal("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "powershe") {
		t.Fatalf("folded Chr+ concat not found; streams: %v", streamsAsStrings(res))
	}
}

// TestFoldReplace verifies that a VBA Replace("str","old","new") call with
// all-literal arguments is evaluated.
func TestFoldReplace(t *testing.T) {
	// Replace strips underscores from "p_o_w_e_r_s_h_e_l_l" → "powershell" (10 chars)
	buf := []byte(`s = Replace("p_o_w_e_r_s_h_e_l_l", "_", "")`)
	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatal("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "powershell") {
		t.Fatalf("folded Replace not found; streams: %v", streamsAsStrings(res))
	}
}

// TestFoldStrReverse verifies StrReverse("literal") is folded to cleartext, so a
// keyword rule sees the un-reversed string (olevba parity, PT-VBADEOBF-1).
func TestFoldStrReverse(t *testing.T) {
	// "llehsrewop" reversed is "powershell".
	buf := []byte(`cmd = StrReverse("llehsrewop")`)
	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatal("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "powershell") {
		t.Fatalf("folded StrReverse not found; streams: %v", streamsAsStrings(res))
	}
}

// TestFoldStrReverseDoubledQuotes verifies the "" escape inside the literal.
func TestFoldStrReverseDoubledQuotes(t *testing.T) {
	// Folded result must clear the minDecodedLen emit floor, so use a >=8-char
	// payload that carries a quote. Reversed `say "hi" now` is `won "ih" yas`;
	// in source the inner quotes are doubled.
	buf := []byte(`x = StrReverse("won ""ih"" yas")`)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, `say "hi" now`) {
		t.Fatalf("folded StrReverse with doubled quote not found; streams: %v", streamsAsStrings(res))
	}
}

// TestFoldArrayXor verifies that Array(N,...) Xor K is decoded byte-by-byte.
func TestFoldArrayXor(t *testing.T) {
	// Encode "powershe" (8 bytes) with key=7:
	// p=112^7=119, o=111^7=104, w=119^7=112, e=101^7=98, r=114^7=117, s=115^7=116, h=104^7=111, e=101^7=98
	buf := []byte(`Array(119, 104, 112, 98, 117, 116, 111, 98) Xor 7`)
	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatal("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "powershe") {
		t.Fatalf("folded ArrayXor not found; streams: %v", streamsAsStrings(res))
	}
}

// TestFoldChrConcatCaseInsensitive verifies (?i) flag handles chrw() lowercase.
func TestFoldChrConcatCaseInsensitive(t *testing.T) {
	// "htt" & chrw(112) & "s://ev" & chrw(105) & "l.com" → "https://evil.com" (16 chars)
	buf := []byte(`s = "htt" & chrw(112) & "s://ev" & chrw(105) & "l.com"`)
	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatal("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "https://evil.com") {
		t.Fatalf("case-insensitive chrw fold not found; streams: %v", streamsAsStrings(res))
	}
}

// TestFoldChrConcatDoubledQuotes verifies that VBA doubled-quote escapes ("") inside
// string literals in a Chr/concat chain are unescaped to a single " in the output.
func TestFoldChrConcatDoubledQuotes(t *testing.T) {
	// Chr(65) & "He said ""hi""" & Chr(66) → AHe said "hi"B (15 chars, above minDecodedLen)
	buf := []byte(`x = Chr(65) & "He said ""hi""" & Chr(66)`)
	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatal("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, `AHe said "hi"B`) {
		t.Fatalf("doubled-quote unescape in Chr concat not found; streams: %v", streamsAsStrings(res))
	}
}

// TestFoldReplaceDoubledQuotes verifies that VBA doubled-quote escapes ("") inside
// string arguments of Replace() are unescaped before evaluating the substitution.
func TestFoldReplaceDoubledQuotes(t *testing.T) {
	// Replace("He said ""bye""", "bye", "hi") → He said "hi" (13 chars)
	buf := []byte(`s = Replace("He said ""bye""", "bye", "hi")`)
	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatal("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, `He said "hi"`) {
		t.Fatalf("doubled-quote unescape in Replace not found; streams: %v", streamsAsStrings(res))
	}
}

// streamsAsStrings is a test helper that returns all streams as a string slice
// for readable failure messages.
func streamsAsStrings(res Result) []string {
	out := make([]string, len(res.Streams))
	for i, s := range res.Streams {
		out[i] = strings.ToValidUTF8(string(s), "?")
	}
	return out
}

// TestFoldVBAStringsInputClamp verifies the foldVBAStrings input clamp (STAB-5):
// a fold pattern within the first maxFoldInput bytes is still folded, while one
// pushed entirely past the clamp is ignored, and a multi-MiB body terminates
// quickly (worst-case bound, not a hang).
func TestFoldVBAStringsInputClamp(t *testing.T) {
	// Pattern within the clamp window: folds normally.
	within := []byte(`x = Replace("p_o_w_e_r_s_h_e_l_l", "_", "")`)
	got := false
	foldVBAStrings(within, time.Time{}, func(b []byte) bool {
		if string(b) == "powershell" {
			got = true
		}
		return true
	})
	if !got {
		t.Fatal("fold within clamp window was not emitted")
	}

	// Pattern pushed entirely past maxFoldInput: must be clamped away (not seen).
	big := make([]byte, 0, maxFoldInput+128)
	big = append(big, bytes.Repeat([]byte("A"), maxFoldInput)...)
	big = append(big, []byte(`Replace("p_o_w_e_r_s_h_e_l_l", "_", "")`)...)
	emitted := 0
	done := make(chan struct{})
	go func() {
		foldVBAStrings(big, time.Time{}, func([]byte) bool { emitted++; return true })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("foldVBAStrings did not terminate on a multi-MiB body")
	}
	if emitted != 0 {
		t.Fatalf("pattern past the clamp boundary was folded: %d emits", emitted)
	}
}
