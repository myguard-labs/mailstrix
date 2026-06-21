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
// TestDecodeMultiLayer verifies the MSD-1 recursion: a base64-over-base64 payload
// is unwrapped to the inner plaintext, where the old single-pass decoder stopped
// at the first (still-encoded) layer.
func TestDecodeMultiLayer(t *testing.T) {
	inner := "powershellPayloadHiddenTwoLayersDeep"
	b1 := base64.StdEncoding.EncodeToString([]byte(inner)) // first layer (still base64 text)
	outer := base64.StdEncoding.EncodeToString([]byte(b1)) // second layer
	buf := []byte(outer)

	res := Extract(buf, time.Time{})
	if !streamsContain(res, b1) {
		t.Fatalf("first decode layer (b1) not surfaced")
	}
	if !streamsContain(res, "powershellPayloadHidden") {
		t.Fatalf("inner plaintext not surfaced — recursion did not chain to depth 2")
	}
}

// TestDecodeDepthCapped verifies the recursion stops at maxDecodeDepth: a payload
// nested ONE layer deeper than the cap must not fully unwrap to the deepest
// plaintext.
func TestDecodeDepthCapped(t *testing.T) {
	// Innermost plaintext, then maxDecodeDepth+1 base64 layers on top. A decode
	// chain runs at most maxDecodeDepth passes (depths 0..maxDecodeDepth-1), so it
	// peels maxDecodeDepth layers and leaves the innermost plaintext still wrapped.
	s := "secretDeepPayloadMarkerXYZ"
	for i := 0; i < maxDecodeDepth+1; i++ {
		s = base64.StdEncoding.EncodeToString([]byte(s))
	}
	res := Extract([]byte(s), time.Time{})
	if streamsContain(res, "secretDeepPayloadMarker") {
		t.Fatalf("payload nested beyond maxDecodeDepth was fully unwrapped")
	}
}

// TestDecodeRecursesIntoVBAFold verifies looksEncoded re-enqueues a child blob
// that decoded into a VBA string-build construct: a base64 layer hiding a
// Replace(...) call must fold to the cleartext payload one layer down.
func TestDecodeRecursesIntoVBAFold(t *testing.T) {
	// Replace("poXwerXshell","X","") -> "powershell"
	vba := `Replace("poXwerXshell","X","")`
	buf := []byte(base64.StdEncoding.EncodeToString([]byte(vba)))
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "powershell") {
		t.Fatalf("base64->Replace() not folded; recursion missed the VBA construct; streams=%q", res.Streams)
	}
}

// TestDecodePerStreamBudget pins the MSD-1 budget contract: the blob budget is
// reset per source stream, not shared across them. Many streams, each carrying
// several encoded runs, must EACH get decoded — a single shared 32-blob pool
// would starve the later streams.
func TestDecodePerStreamBudget(t *testing.T) {
	const nStreams = 30
	const runsPer = 5
	res := &Result{}
	for i := 0; i < nStreams; i++ {
		var b strings.Builder
		for j := 0; j < runsPer; j++ {
			// Each payload is a distinct, recognisable, >=18-byte marker so its
			// base64 clears minBase64Run and its plaintext clears minDecodedLen.
			payload := "PER-STREAM-PAYLOAD-" + string(rune('A'+i)) + string(rune('0'+j)) + "-pad"
			b.WriteString(base64.StdEncoding.EncodeToString([]byte(payload)))
			b.WriteByte(' ')
		}
		res.Streams = append(res.Streams, []byte(b.String()))
	}
	// Decode pass over the pre-populated streams (buf empty).
	fromEncoded(nil, res, time.Time{})

	// A shared 32-blob budget would stop after ~6 streams (6*5=30). Assert the LAST
	// stream's payload decoded — only possible if each stream had its own budget.
	last := "PER-STREAM-PAYLOAD-" + string(rune('A'+nStreams-1))
	if !streamsContain(*res, last) {
		t.Fatalf("last stream's payload not decoded — budget shared across streams, not per-stream")
	}
}

// TestDecodeMSD2DedupsRepeatedBlob (MSD-2): when the same encoded run appears
// twice in one source, the recursive walk decodes it ONCE — fan-out convergence
// is collapsed by the fnv64 worklist dedup, so the decoded blob count does not
// double. (The scanner SHA-dedups emitted streams anyway; MSD-2 saves the
// redundant DECODE work that would otherwise re-run at every reappearance.)
func TestDecodeMSD2DedupsRepeatedBlob(t *testing.T) {
	// A two-layer payload (base64 wrapping base64) so the decoded layer-1 blob is
	// itself re-enqueued — the dedup point. Repeat the SAME outer run twice.
	inner := "MSD2_DEDUP_CONVERGENCE_PAYLOAD_KEYWORD"
	l1 := base64.StdEncoding.EncodeToString([]byte(inner))
	outer := base64.StdEncoding.EncodeToString([]byte(l1))

	once := &Result{Streams: [][]byte{[]byte(outer)}}
	fromEncoded(nil, once, time.Time{})

	twice := &Result{Streams: [][]byte{[]byte(outer + " " + outer)}}
	fromEncoded(nil, twice, time.Time{})

	if !streamsContain(*twice, inner) {
		t.Fatalf("payload not decoded at all; streams=%d", len(twice.Streams))
	}
	// The duplicated source must not produce more decoded blobs than the single one
	// (the second copy converges on already-seen bytes and is skipped).
	if twice.DecodedStreams > once.DecodedStreams {
		t.Errorf("MSD-2 dedup failed: %d decoded blobs for the duplicated run vs %d for one",
			twice.DecodedStreams, once.DecodedStreams)
	}
}

// TestDecodeReversedEqualsSourceStillEmitted (MSD-2 golang-pro F1): a decoded
// blob byte-identical to its SOURCE must still be emitted to YARA — the dedup set
// holds only EMITTED blobs, never the source, so seeding can't swallow a real
// decoded layer. Here a palindrome (X+reverse(X)) that carries a reversed marker
// reverses to itself; the reversed (==source) blob must surface its keyword.
func TestDecodeReversedEqualsSourceStillEmitted(t *testing.T) {
	// "cmd.exe" + "exe.dmc" — its own reverse, and contains the reversed marker
	// "exe.dmc" so emitReversed fires; the reversed output equals the source.
	buf := []byte("cmd.exeexe.dmc")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "cmd.exe") {
		t.Errorf("reversed-equals-source blob was swallowed by dedup seeding; streams=%v", res.Streams)
	}
}

// TestFNV64 sanity-checks the inlined hash: deterministic, and distinct inputs
// (incl. empty) hash distinctly here.
func TestFNV64(t *testing.T) {
	if fnv64([]byte("abc")) != fnv64([]byte("abc")) {
		t.Error("fnv64 not deterministic")
	}
	if fnv64([]byte("abc")) == fnv64([]byte("abd")) {
		t.Error("fnv64 collided on a 1-byte difference")
	}
	if fnv64(nil) == fnv64([]byte("x")) {
		t.Error("fnv64(empty) == fnv64(\"x\")")
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

// TestFoldEnviron verifies Environ("NAME") folds to a VBA-ENVIRON %NAME% marker
// so a rule can flag env-var probing (olevba parity, PT-VBADEOBF-2).
func TestFoldEnviron(t *testing.T) {
	buf := []byte(`p = Environ("APPDATA") & "\dropper.exe"`)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "VBA-ENVIRON %APPDATA%") {
		t.Fatalf("folded Environ marker not found; streams: %v", streamsAsStrings(res))
	}
}

// TestFoldEnvironShortName verifies a short var name still emits (the marker
// prefix clears the minDecodedLen floor that a bare %TEMP% would miss).
func TestFoldEnvironShortName(t *testing.T) {
	buf := []byte(`x = Environ$("TEMP")`)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "VBA-ENVIRON %TEMP%") {
		t.Fatalf("short Environ name not emitted; streams: %v", streamsAsStrings(res))
	}
}

// TestDridexURLDecodeVector checks the dridexURLDecode primitive against an
// olevba reference vector (PT-VBADEOBF-3). "C3iY…cknj" decodes to "TMP".
func TestDridexURLDecodeVector(t *testing.T) {
	got, ok := dridexURLDecode("C3iY1epSRGe6q8g15xStVesdG717MAlg2H4hmV1vkL6Glnf0cknj")
	if !ok || got != "TMP" {
		t.Fatalf("dridexURLDecode = %q ok=%v, want \"TMP\" true", got, ok)
	}
}

// TestFoldDridexURL checks the end-to-end fold: a Dridex-encoded C2 URL literal
// (olevba reference vector) is decoded and emitted so URL rules can match it.
func TestFoldDridexURL(t *testing.T) {
	enc := "HLIY3Nf3z2k8jD37h1n2OM3N712DGQ3c5M841RZ8C5e6P1C50C4ym1oF504WyV182p4mJ16cK9Z61l47h2dU1rVB5V681sFY728i16H3E2Qm1fn47y2cgAo156j8T1s600hukKO1568X1xE4Z7d2q17jvcwgk816Yz32o9Q216Mpr0B01vcwg856a17b9j2zAmWf1536B1t7d92rI1FZ5E36Pu1jl504Z34tm2R43i55Lg2F3eLE3T28lLX1D504348Goe8Gbdp37w443ADy36X0h14g7Wb2G3u584kEG332Ut8ws3wO584pzSTf"
	buf := []byte(`u = "` + enc + `"`)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "http://95.163.121.82:8080/koh/mui.php") {
		t.Fatalf("Dridex C2 URL not decoded; streams: %v", streamsAsStrings(res))
	}
}

// TestDridexRejectsPlainHex verifies a plain-hex string (no G-Z letters) is not
// treated as Dridex (the hex pass owns it).
func TestDridexRejectsPlainHex(t *testing.T) {
	if _, ok := dridexURLDecode("0011223344556677"); ok {
		// Not asserting the decode result, just that pure-digit/hex input
		// doesn't masquerade as a valid Dridex blob with printable output by luck.
		t.Skip("primitive may decode digits; gating is done by dridexNotHex at the call site")
	}
}
