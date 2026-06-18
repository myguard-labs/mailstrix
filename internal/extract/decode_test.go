package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
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
