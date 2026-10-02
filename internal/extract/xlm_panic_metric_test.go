package extract

import (
	"testing"
	"time"
)

// TestXLMEmulatorPanicCounted (COR-23): a panic inside the emulator is
// recovered, keeps partial output, and increments XLMEmulatorPanics.
func TestXLMEmulatorPanicCounted(t *testing.T) {
	xlmEmulTestHook = func() { panic("injected emulator panic") }
	t.Cleanup(func() { xlmEmulTestHook = nil })
	before := XLMEmulatorPanics()
	out := [][]byte{[]byte("partial")}
	total := 0
	emulateXLMCells([]xlmCell{{coord: "A1", formula: `=HALT()`}}, &out, &total, time.Time{})
	if got := XLMEmulatorPanics(); got != before+1 {
		t.Fatalf("XLMEmulatorPanics = %d, want %d", got, before+1)
	}
	if len(out) != 1 || string(out[0]) != "partial" {
		t.Fatalf("partial output not preserved: %q", out)
	}
}

// TestXLMEmulatorNoPanicNotCounted (negative / boundary): a normal run and an
// empty cell list leave the counter unchanged.
func TestXLMEmulatorNoPanicNotCounted(t *testing.T) {
	before := XLMEmulatorPanics()
	var out [][]byte
	total := 0
	emulateXLMCells([]xlmCell{{coord: "A1", formula: `=A1`}}, &out, &total, time.Time{})
	emulateXLMCells(nil, &out, &total, time.Time{})
	if got := XLMEmulatorPanics(); got != before {
		t.Fatalf("counter moved without a panic: %d -> %d", before, got)
	}
}
