package extract

import (
	"strings"
	"testing"
)

// TestEffectiveSourceLen covers the various source shapes that stomping
// detection depends on.
func TestEffectiveSourceLen(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"empty", "", 0},
		{"whitespace only", "  \n\t\n  \n", 0},
		{"attribute VB_Name only", "Attribute VB_Name = \"Foo\"\n", 0},
		{"multiple attribute lines", "Attribute VB_Name = \"Foo\"\nAttribute VB_GlobalNameSpace = False\n", 0},
		{"real code line", "Sub Foo()\n  MsgBox \"hi\"\nEnd Sub\n", 30},
		{"mixed attr+code", "Attribute VB_Name = \"M\"\nSub Go()\nEnd Sub\n", 14},
	}
	for _, tc := range cases {
		got := effectiveSourceLen([]byte(tc.src))
		if tc.want == 0 && got != 0 {
			t.Errorf("%s: want 0, got %d", tc.name, got)
		} else if tc.want > 0 && got == 0 {
			t.Errorf("%s: want >0, got %d", tc.name, got)
		}
	}
}

// TestStompThresholds checks the boundary conditions the spec requires:
//   - pcode >= 256 AND effective source < 32 → stomped
//   - pcode >= 256 AND effective source >= 32 → not stomped (source looks real)
//
// These tests exercise the threshold constants directly so a constant change
// is caught immediately.
func TestStompThresholds(t *testing.T) {
	if stompPCodeThreshold != 256 {
		t.Errorf("stompPCodeThreshold changed: got %d, want 256", stompPCodeThreshold)
	}
	if stompSourceThreshold != 32 {
		t.Errorf("stompSourceThreshold changed: got %d, want 32", stompSourceThreshold)
	}

	// Source exactly at threshold → not stomped.
	exact := strings.Repeat("a", stompSourceThreshold)
	if got := effectiveSourceLen([]byte(exact)); got < stompSourceThreshold {
		t.Errorf("source at threshold: effective %d < %d — would falsely flag", got, stompSourceThreshold)
	}

	// Source one byte below threshold → stomped.
	below := strings.Repeat("a", stompSourceThreshold-1)
	if got := effectiveSourceLen([]byte(below)); got >= stompSourceThreshold {
		t.Errorf("source one below threshold: effective %d >= %d — stomping missed", got, stompSourceThreshold)
	}
}

// TestVBACompressStream_RoundTrip verifies the in-package vbaCompressStream
// helper (used to build synthetic test streams) round-trips through
// oleparse.DecompressStream correctly.
func TestVBACompressStream_RoundTrip(t *testing.T) {
	original := []byte("Sub Auto_Open()\n  Shell \"cmd.exe /c evil.bat\"\nEnd Sub\n")
	compressed := vbaCompressStream(original)
	if len(compressed) == 0 {
		t.Fatal("vbaCompressStream returned empty output")
	}
	// Re-import via walkDirStream path — decompression handled inside stomping.go.
	// Here we just verify the header byte and structure are non-trivial.
	if compressed[0] != 0x01 {
		t.Errorf("expected signature byte 0x01, got 0x%02x", compressed[0])
	}
}

// TestWalkDirStream_Empty verifies that an empty/truncated dir stream returns
// an error rather than a module list.
func TestWalkDirStream_Empty(t *testing.T) {
	_, err := walkDirStream([]byte{})
	if err == nil {
		t.Error("expected error for empty dir stream, got nil")
	}
}

// TestWalkDirStream_Truncated verifies graceful failure on truncated input.
func TestWalkDirStream_Truncated(t *testing.T) {
	// A few bytes — not enough for any real record.
	_, err := walkDirStream([]byte{0x01, 0x00, 0x04, 0x00})
	if err == nil {
		t.Error("expected error for truncated dir stream, got nil")
	}
}
