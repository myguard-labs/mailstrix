package extract

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// tryBase64Ref is the pre-PERF-60 implementation, kept as the oracle.
func tryBase64Ref(run []byte) ([]byte, bool) {
	if len(run) > maxB64Encoded {
		run = run[:maxB64Encoded]
	}
	if dec, err := base64.StdEncoding.DecodeString(string(run)); err == nil {
		return dec, true
	}
	s := strings.TrimRight(string(run), "=")
	if len(s)%4 == 1 {
		return nil, false
	}
	if dec, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return dec, true
	}
	return nil, false
}

func checkBase64Same(t *testing.T, in []byte) {
	t.Helper()
	got, ok := tryBase64(in)
	want, wantOK := tryBase64Ref(in)
	if ok != wantOK || !bytes.Equal(got, want) {
		t.Fatalf("tryBase64(%q) = %q,%v; reference %q,%v", in, got, ok, want, wantOK)
	}
}

// TestTryBase64MatchesReference (PERF-60): the direct-Decode version returns
// exactly what DecodeString(string(run)) returned, for padded, unpadded,
// newline-wrapped, malformed and empty input.
func TestTryBase64MatchesReference(t *testing.T) {
	for _, s := range []string{
		"", "QQ==", "QQ", "QUJD", "QUJDRA", "QUJDRA==", "Q", "!!!!", "QU=JD",
		"SGVsbG8s\r\nIHdvcmxk", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff, 0, 7}, 400)),
	} {
		checkBase64Same(t, []byte(s))
	}
}

func FuzzTryBase64MatchesReference(f *testing.F) {
	for _, s := range []string{"QQ==", "QQ", "SGVsbG8s\r\nIHdvcmxk", "Q===", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) { checkBase64Same(t, in) })
}

// TestTryBase64Allocs: one decode allocates only the output buffer.
func TestTryBase64Allocs(t *testing.T) {
	run := []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("payload "), 512)))
	if a := testing.AllocsPerRun(50, func() { _, _ = tryBase64(run) }); a > 1 {
		t.Errorf("allocs = %g, want 1", a)
	}
}
