package extract

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// emulDepthClass unit tests
// ---------------------------------------------------------------------------

func TestEmulDepthClass_Shallow(t *testing.T) {
	out := make([][]byte, 0)
	total := 0
	m := newMachine(&out, &total, time.Time{})
	// No revisits, no forks pushed.
	got := emulDepthClass(m)
	if got != "shallow" {
		t.Errorf("expected shallow, got %q", got)
	}
}

func TestEmulDepthClass_Looped(t *testing.T) {
	out := make([][]byte, 0)
	total := 0
	m := newMachine(&out, &total, time.Time{})
	m.visited["Sheet1!A1"] = 2 // cell revisited → loop
	got := emulDepthClass(m)
	if got != "looped" {
		t.Errorf("expected looped, got %q", got)
	}
}

func TestEmulDepthClass_Branched(t *testing.T) {
	out := make([][]byte, 0)
	total := 0
	m := newMachine(&out, &total, time.Time{})
	m.ifForksPushed = 1 // IF fork pushed, no revisits
	got := emulDepthClass(m)
	if got != "branched" {
		t.Errorf("expected branched, got %q", got)
	}
}

func TestEmulDepthClass_BothLoopedAndBranched(t *testing.T) {
	out := make([][]byte, 0)
	total := 0
	m := newMachine(&out, &total, time.Time{})
	m.visited["Sheet1!A1"] = 3 // revisited → looped
	m.ifForksPushed = 2        // also forked → branched wins
	got := emulDepthClass(m)
	if got != "branched" {
		t.Errorf("expected branched (higher signal wins), got %q", got)
	}
}

// ---------------------------------------------------------------------------
// emulateXLMCells depth marker integration tests
// ---------------------------------------------------------------------------

func TestEmulateXLMCells_EmitsDepthMarker(t *testing.T) {
	cells := []xlmCell{
		{coord: "A1", formula: `=EXEC("calc.exe")`},
	}
	var out [][]byte
	total := 0
	emulateXLMCells(cells, &out, &total, time.Time{})

	found := false
	for _, blob := range out {
		if bytes.Contains(blob, []byte("XLM-EMUL-DEPTH")) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected XLM-EMUL-DEPTH marker in output; got %d blobs: %v", len(out), out)
	}
}

func TestEmulateXLMCells_DepthMarkerIsShallow(t *testing.T) {
	// Simple sequential cell — no loops, no IF forks → shallow.
	cells := []xlmCell{
		{coord: "A1", formula: `=EXEC("cmd.exe")`},
	}
	var out [][]byte
	total := 0
	emulateXLMCells(cells, &out, &total, time.Time{})

	found := false
	for _, blob := range out {
		if bytes.Contains(blob, []byte("XLM-EMUL-DEPTH shallow")) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected XLM-EMUL-DEPTH shallow marker; output blobs: %v", out)
	}
}

func TestEmulateXLMCells_DepthMarkerLooped(t *testing.T) {
	// Cell A1 jumps to itself → self-referential GOTO → looped.
	cells := []xlmCell{
		{coord: "A1", formula: `=GOTO(A1)`},
	}
	var out [][]byte
	total := 0
	emulateXLMCells(cells, &out, &total, time.Time{})

	found := false
	for _, blob := range out {
		if bytes.Contains(blob, []byte("looped")) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected looped depth marker; output blobs: %v", out)
	}
}

// ---------------------------------------------------------------------------
// Version string test
// ---------------------------------------------------------------------------

func TestVersionContainsXLMEmulDepth(t *testing.T) {
	if !strings.Contains(Version, "+xlmemuldepth") {
		t.Errorf("Version %q does not contain +xlmemuldepth", Version)
	}
}

// ---------------------------------------------------------------------------
// Fallback still works when emulator produces only the depth marker
// ---------------------------------------------------------------------------

func TestEmulateXLMCells_FallbackStillWorksWithMarker(t *testing.T) {
	// A cell with no formula (value only) — the emulator produces no real output
	// (no formulas to execute). The depth marker is emitted, then the fallback
	// interpreter runs. The interpreter can't fold a value-only cell either, so
	// total output is just the depth marker. Verify the depth marker is present
	// and the code doesn't panic.
	cells := []xlmCell{
		{coord: "A1", formula: "", value: "some-value"},
	}
	var out [][]byte
	total := 0
	emulateXLMCells(cells, &out, &total, time.Time{})

	// Depth marker must be present (always emitted).
	found := false
	for _, blob := range out {
		if bytes.Contains(blob, []byte("XLM-EMUL-DEPTH")) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("depth marker missing from output (fallback scenario): %v", out)
	}
}

// ---------------------------------------------------------------------------
// YARA rule file existence check
// ---------------------------------------------------------------------------

func TestYARARule_FileExists(t *testing.T) {
	// Walk up from the package dir to find the docker/local-rules path.
	// The file is at a known relative location from the module root.
	paths := []string{
		"../../../../docker/local-rules/xlm_macrosheet.yara",
		"../../../docker/local-rules/xlm_macrosheet.yara",
	}
	var data []byte
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil {
			data = b
			break
		}
	}
	if data == nil {
		t.Skip("xlm_macrosheet.yara not found relative to test dir — skipping file-content check")
	}
	if !bytes.Contains(data, []byte("XLM-EMUL-DEPTH")) {
		t.Errorf("xlm_macrosheet.yara does not contain XLM-EMUL-DEPTH string")
	}
}
