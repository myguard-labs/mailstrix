package extract

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestFoldConcatChr reassembles a split "powershell" built from string literals
// and Chr() calls joined by &, so the raw scan never sees the whole keyword.
func TestFoldConcatChr(t *testing.T) {
	buf := []byte(`s = "po" & Chr(119) & "ershe" & ChrW(108) & "l" : exec s`)

	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatalf("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "powershell") {
		t.Fatalf("folded concat did not surface 'powershell'; got %d streams", len(res.Streams))
	}
}

// TestFoldConcatHexChr folds a Chr(&H..) hex-literal argument.
func TestFoldConcatHexChr(t *testing.T) {
	// &H2E = '.', spelling "cmd.exe" across literals and a hex Chr.
	buf := []byte(`x = "cmd" & Chr(&H2E) & "exefile"`)

	res := Extract(buf, time.Time{})
	if !streamsContain(res, "cmd.exe") {
		t.Fatalf("folded hex Chr did not surface 'cmd.exe'; got %d streams", len(res.Streams))
	}
}

// TestFoldReplace evaluates a literal Replace() that hides a keyword behind a
// junk token.
func TestFoldReplace(t *testing.T) {
	buf := []byte(`s = Replace("powAAershell", "AA", "") : Eval s`)

	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatalf("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, "powershell") {
		t.Fatalf("folded Replace did not surface 'powershell'; got %d streams", len(res.Streams))
	}
}

// TestFoldArray decodes an Array() of decimal byte literals into ASCII.
func TestFoldArray(t *testing.T) {
	payload := "createobject"
	nums := make([]string, len(payload))
	for i := 0; i < len(payload); i++ {
		nums[i] = fmt.Sprintf("%d", payload[i])
	}
	buf := []byte("a = Array(" + strings.Join(nums, ", ") + ")")

	res := Extract(buf, time.Time{})
	if res.DecodedStreams == 0 {
		t.Fatalf("DecodedStreams = 0, want >0")
	}
	if !streamsContain(res, payload) {
		t.Fatalf("folded Array did not surface %q; got %d streams", payload, len(res.Streams))
	}
}

// TestFoldArrayXorKey applies a literal single-byte XOR key to an Array() so the
// trivial in-loop decoder's output surfaces without executing the loop.
func TestFoldArrayXorKey(t *testing.T) {
	payload := "createobject"
	const key = 0x41
	nums := make([]string, len(payload))
	for i := 0; i < len(payload); i++ {
		nums[i] = fmt.Sprintf("%d", payload[i]^key)
	}
	buf := []byte("a = Array(" + strings.Join(nums, ", ") + ")\nFor i = 0 To n : b(i) = a(i) Xor &H41 : Next")

	res := Extract(buf, time.Time{})
	if !streamsContain(res, payload) {
		t.Fatalf("XOR-keyed Array did not surface %q; got %d streams", payload, len(res.Streams))
	}
}

// TestFoldBenignNoOp pins the no-FP case: ordinary text with no foldable
// constant expression yields no extra stream.
func TestFoldBenignNoOp(t *testing.T) {
	buf := []byte(`Dim total : total = price + tax  ' a perfectly ordinary line`)

	res := Extract(buf, time.Time{})
	if res.DecodedStreams > 0 {
		t.Fatalf("DecodedStreams = %d on benign text, want 0", res.DecodedStreams)
	}
}

// TestFoldExpiredDeadline checks the concat fold honours the deadline.
func TestFoldExpiredDeadline(t *testing.T) {
	buf := []byte(`s = "po" & Chr(119) & "ershe" & ChrW(108) & "l"`)

	res := Extract(buf, time.Now().Add(-time.Second))
	if res.DecodedStreams > 0 {
		t.Fatalf("DecodedStreams = %d with an expired deadline, want 0", res.DecodedStreams)
	}
}
