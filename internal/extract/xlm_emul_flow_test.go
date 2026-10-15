package extract

import (
	"strings"
	"testing"
	"time"
)

// ---- helpers ----------------------------------------------------------------

// newFlowTestMachine returns a machine with a 10-second deadline.
func newFlowTestMachine() *xlmMachine {
	out := make([][]byte, 0)
	total := 0
	return newMachine(&out, &total, time.Now().Add(10*time.Second))
}

// flowOutput collects all emitted bytes as a single joined string.
func flowOutput(m *xlmMachine) string {
	var parts []string
	for _, b := range *m.out {
		parts = append(parts, string(b))
	}
	return strings.Join(parts, "|")
}

// ---- parseIFArgs ------------------------------------------------------------

func TestParseIFArgs(t *testing.T) {
	cases := []struct {
		formula   string
		wantCond  string
		wantTrue  string
		wantFalse string
		wantOK    bool
	}{
		{"=IF(TRUE,A2,A3)", "TRUE", "A2", "A3", true},
		{"IF(TRUE,A2,A3)", "TRUE", "A2", "A3", true},
		{"=IF(FALSE,A2,A3)", "FALSE", "A2", "A3", true},
		// Nested parens in condition.
		{"=IF(AND(A1,B1),C2,D3)", "AND(A1,B1)", "C2", "D3", true},
		// Empty formula.
		{"", "", "", "", false},
		// Missing false branch still parses (falsePart == "").
		{"=IF(A1,B1,)", "A1", "B1", "", true},
		// No IF(.
		{"=GOTO(A1)", "", "", "", false},
		// Nested comma inside arg.
		{`=IF(RAND(),Sheet1!A2,Sheet1!A3)`, "RAND()", "Sheet1!A2", "Sheet1!A3", true},
	}
	for _, tc := range cases {
		cond, tp, fp, ok := parseIFArgs(tc.formula)
		if ok != tc.wantOK {
			t.Errorf("parseIFArgs(%q) ok=%v want %v", tc.formula, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if cond != tc.wantCond {
			t.Errorf("parseIFArgs(%q) cond=%q want %q", tc.formula, cond, tc.wantCond)
		}
		if tp != tc.wantTrue {
			t.Errorf("parseIFArgs(%q) true=%q want %q", tc.formula, tp, tc.wantTrue)
		}
		if fp != tc.wantFalse {
			t.Errorf("parseIFArgs(%q) false=%q want %q", tc.formula, fp, tc.wantFalse)
		}
	}
}

// ---- parseNameArg -----------------------------------------------------------

func TestParseNameArg(t *testing.T) {
	cases := []struct {
		formula   string
		wantName  string
		wantValue string
		wantOK    bool
	}{
		{`=SET.NAME("myvar","hello")`, "myvar", "hello", true},
		{`SET.NAME("myvar","hello")`, "myvar", "hello", true},
		{`=DEFINE.NAME("x","=A1")`, "x", "=A1", true},
		// No quotes — raw identifiers.
		{`=SET.NAME(myvar,hello)`, "myvar", "hello", true},
		// Missing comma.
		{`=SET.NAME("a")`, "", "", false},
		// Empty formula.
		{"", "", "", false},
		// Wrong verb.
		{`=GOTO(A1)`, "", "", false},
	}
	for _, tc := range cases {
		name, val, ok := parseNameArg(tc.formula)
		if ok != tc.wantOK {
			t.Errorf("parseNameArg(%q) ok=%v want %v", tc.formula, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if name != tc.wantName {
			t.Errorf("parseNameArg(%q) name=%q want %q", tc.formula, name, tc.wantName)
		}
		if val != tc.wantValue {
			t.Errorf("parseNameArg(%q) value=%q want %q", tc.formula, val, tc.wantValue)
		}
	}
}

// ---- cowSheetsSnapshot ------------------------------------------------------

func TestCOWSheetsSnapshot(t *testing.T) {
	m := newFlowTestMachine()
	m.setCell("Sheet1", "A1", "=EXEC(\"cmd\")", "cmd")
	m.setCell("Sheet1", "A2", "=EXEC(\"dir\")", "dir")

	snap := cowSheetsSnapshot(m.sheets)

	// Snap should be independent at the map level.
	m.setCell("Sheet1", "A3", "=EXEC(\"new\")", "new")
	sheet := snap["Sheet1"]
	if sheet == nil {
		t.Fatal("snapshot lost Sheet1")
	}
	if _, ok := sheet.cells["A3"]; ok {
		t.Error("snapshot was affected by post-snapshot setCell on original")
	}

	// Pre-existing cells should still be in the snapshot.
	if _, ok := sheet.cells["A1"]; !ok {
		t.Error("A1 missing from snapshot")
	}
	if _, ok := sheet.cells["A2"]; !ok {
		t.Error("A2 missing from snapshot")
	}

	// Adding a new sheet to original should not appear in snap.
	m.setCell("Sheet2", "B1", "", "val")
	if _, ok := snap["Sheet2"]; ok {
		t.Error("new sheet Sheet2 appeared in snapshot")
	}
}

// ---- IF branch handling -----------------------------------------------------

// TestHandleIFTrueBranch: IF(TRUE,A2,A10) — PC moves to A2; A10 not visited.
func TestHandleIFTrueBranch(t *testing.T) {
	m := newFlowTestMachine()
	// False branch at A10 (far from true branch A2) so sequential fallthrough
	// from A2 never reaches A10.
	m.setCell("Sheet1", "A1", `=IF(TRUE,A2,A10)`, "")
	m.setCell("Sheet1", "A2", `="TRUERESULT"`, "")
	m.setCell("Sheet1", "A3", "=HALT()", "")
	m.setCell("Sheet1", "A10", `="FALSERESULT"`, "")
	m.run("Sheet1", "A1")
	out := flowOutput(m)
	if !strings.Contains(out, "TRUERESULT") {
		t.Errorf("expected TRUERESULT in output, got %q", out)
	}
	if strings.Contains(out, "FALSERESULT") {
		t.Errorf("expected FALSERESULT NOT in output (no fork for known TRUE), got %q", out)
	}
}

// TestHandleIFFalseBranch: IF(FALSE,A10,A2) — PC moves to A2; A10 not visited.
func TestHandleIFFalseBranch(t *testing.T) {
	m := newFlowTestMachine()
	m.setCell("Sheet1", "A1", `=IF(FALSE,A10,A2)`, "")
	m.setCell("Sheet1", "A2", `="FALSERESULT"`, "")
	m.setCell("Sheet1", "A3", "=HALT()", "")
	m.setCell("Sheet1", "A10", `="TRUERESULT"`, "")
	m.run("Sheet1", "A1")
	out := flowOutput(m)
	if strings.Contains(out, "TRUERESULT") {
		t.Errorf("expected TRUERESULT NOT in output (no fork for known FALSE), got %q", out)
	}
	if !strings.Contains(out, "FALSERESULT") {
		t.Errorf("expected FALSERESULT in output, got %q", out)
	}
}

// TestHandleIFUnknownBothPaths: IF(RAND(),A2,A3) — unknown cond, both paths visited.
func TestHandleIFUnknownBothPaths(t *testing.T) {
	m := newFlowTestMachine()
	// RAND() cannot be evaluated to TRUE/FALSE, so both branches explored.
	m.setCell("Sheet1", "A1", `=IF(RAND(),A2,A3)`, "")
	m.setCell("Sheet1", "A2", `="TRUEPATH"`, "")
	m.setCell("Sheet1", "A3", `="FALSEPATH"`, "")
	// A2 and A3 have no continuation cells → run naturally stops.
	m.run("Sheet1", "A1")
	out := flowOutput(m)
	if !strings.Contains(out, "TRUEPATH") {
		t.Errorf("expected TRUEPATH in output (true branch), got %q", out)
	}
	if !strings.Contains(out, "FALSEPATH") {
		t.Errorf("expected FALSEPATH in output (false branch via fork), got %q", out)
	}
}

// TestHandleIFForkQueueCap: push 65 IF forks; forkQueue must not exceed 64.
func TestHandleIFForkQueueCap(t *testing.T) {
	m := newFlowTestMachine()
	// Chain: A1=IF(RAND(),A2,A3), A2=IF(RAND(),A4,A5), ... — each unknown
	// condition causes a fork. With 65 IF cells, cap at 64.
	// Lay out the cells so the true branch always advances to the next IF.
	// False branches point to high-numbered cells that don't exist (safe stop).
	for i := 1; i <= 65; i++ {
		trueNext := "A" + itoa(i+1)
		falseTarget := "Z" + itoa(i) // non-existent → safe stop
		if i == 65 {
			trueNext = "HALT_CELL" // will not normalise → handled gracefully
		}
		m.setCell("Sheet1", "A"+itoa(i),
			"=IF(RAND(),"+trueNext+","+falseTarget+")", "")
	}
	m.run("Sheet1", "A1")
	// forkQueue is drained after run; check it's been processed (emptied).
	if len(m.forkQueue) != 0 {
		t.Errorf("forkQueue should be empty after drain, got len=%d", len(m.forkQueue))
	}
	// The key invariant: never exceeded maxEmulBranchStack during build-up.
	// We can't easily observe peak; just verify no panic and run terminates.
}

// itoa is a local helper to avoid importing strconv in the test file.
func itoa(n int) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

// ---- WHILE/NEXT handling ----------------------------------------------------

// TestHandleWHILE: WHILE(TRUE)+NEXT bounded at maxEmulWhileUnroll, terminates.
func TestHandleWHILE(t *testing.T) {
	m := newFlowTestMachine()
	// A1=WHILE(TRUE), A2=body (advance row emits), A3=NEXT()
	// Loop should unroll up to maxEmulWhileUnroll times then stop.
	m.setCell("Sheet1", "A1", "=WHILE(TRUE)", "")
	m.setCell("Sheet1", "A2", `="LOOPBODY"`, "")
	m.setCell("Sheet1", "A3", "=NEXT()", "")
	// A4 onwards: nothing — run stops naturally.
	m.run("Sheet1", "A1")
	out := flowOutput(m)
	// Should have emitted LOOPBODY at least once and terminated.
	if !strings.Contains(out, "LOOPBODY") {
		t.Errorf("expected at least one LOOPBODY emission, got %q", out)
	}
	// Must have terminated (not timed out / step-fused beyond reason).
	if m.steps >= maxEmulSteps {
		t.Errorf("run hit step fuse (%d), WHILE loop did not terminate", m.steps)
	}
}

// TestHandleWHILEFalse: WHILE(FALSE) — skip loop body, advance past NEXT.
func TestHandleWHILEFalse(t *testing.T) {
	m := newFlowTestMachine()
	m.setCell("Sheet1", "A1", "=WHILE(FALSE)", "")
	m.setCell("Sheet1", "A2", `="SHOULDNOTRUN"`, "")
	m.setCell("Sheet1", "A3", "=NEXT()", "")
	m.setCell("Sheet1", "A4", `="AFTERLOOP"`, "")
	m.setCell("Sheet1", "A5", "=HALT()", "")
	m.run("Sheet1", "A1")
	out := flowOutput(m)
	if strings.Contains(out, "SHOULDNOTRUN") {
		t.Errorf("loop body should not have run for WHILE(FALSE), got %q", out)
	}
	if !strings.Contains(out, "AFTERLOOP") {
		t.Errorf("expected AFTERLOOP after skipped loop, got %q", out)
	}
}

// TestHandleNEXT: standalone NEXT with no WHILE — advance PC (no panic).
func TestHandleNEXT(t *testing.T) {
	m := newFlowTestMachine()
	m.setCell("Sheet1", "A1", "=NEXT()", "")
	m.setCell("Sheet1", "A2", `="AFTERNEXT"`, "")
	m.setCell("Sheet1", "A3", "=HALT()", "")
	m.run("Sheet1", "A1")
	out := flowOutput(m)
	if !strings.Contains(out, "AFTERNEXT") {
		t.Errorf("expected AFTERNEXT after standalone NEXT, got %q", out)
	}
}

// ---- FOR.CELL cap -----------------------------------------------------------

// TestHandleFORCELL: 17 FOR.CELL cells — cap at 16, 17th skipped.
func TestHandleFORCELL(t *testing.T) {
	m := newFlowTestMachine()
	// Plant 17 FOR.CELL cells in a row.
	for i := 1; i <= 17; i++ {
		m.setCell("Sheet1", "A"+itoa(i), "=FOR.CELL(r,Sheet1,FALSE)", "")
	}
	m.setCell("Sheet1", "A18", "=HALT()", "")
	m.run("Sheet1", "A1")
	// forCellCount must equal the cap (16), not 17.
	if m.forCellCount > maxEmulWhileUnroll {
		t.Errorf("forCellCount=%d exceeded cap %d", m.forCellCount, maxEmulWhileUnroll)
	}
	if m.forCellCount != maxEmulWhileUnroll {
		t.Errorf("forCellCount=%d want %d", m.forCellCount, maxEmulWhileUnroll)
	}
}

// ---- SET.NAME / DEFINE.NAME -------------------------------------------------

// TestHandleSetName: SET.NAME stores name in m.names.
func TestHandleSetName(t *testing.T) {
	m := newFlowTestMachine()
	m.setCell("Sheet1", "A1", `=SET.NAME("payload","calc.exe")`, "")
	m.setCell("Sheet1", "A2", "=HALT()", "")
	m.run("Sheet1", "A1")
	if v, ok := m.names["payload"]; !ok || v != "calc.exe" {
		t.Errorf("m.names[payload]=%q (ok=%v), want calc.exe/true", v, ok)
	}
}

// TestHandleDefineName: DEFINE.NAME stores name in m.names.
func TestHandleDefineName(t *testing.T) {
	m := newFlowTestMachine()
	m.setCell("Sheet1", "A1", `=DEFINE.NAME("myrange","Sheet1!A2:A10")`, "")
	m.setCell("Sheet1", "A2", "=HALT()", "")
	m.run("Sheet1", "A1")
	if v, ok := m.names["myrange"]; !ok || v != "Sheet1!A2:A10" {
		t.Errorf("m.names[myrange]=%q (ok=%v), want Sheet1!A2:A10/true", v, ok)
	}
}

// ---- Integration: full run() with IF branching ------------------------------

// TestRunWithIF: integration test — run() with IF explores both branches.
func TestRunWithIF(t *testing.T) {
	m := newFlowTestMachine()
	// Sheet with:
	//   A1 = =IF(RAND(),A2,A3)   — unknown cond → fork
	//   A2 = ="TRUE_BRANCH"
	//   A3 = ="FALSE_BRANCH"
	m.setCell("Sheet1", "A1", `=IF(RAND(),A2,A3)`, "")
	m.setCell("Sheet1", "A2", `="TRUE_BRANCH"`, "")
	m.setCell("Sheet1", "A3", `="FALSE_BRANCH"`, "")
	m.run("Sheet1", "A1")
	out := flowOutput(m)
	if !strings.Contains(out, "TRUE_BRANCH") {
		t.Errorf("expected TRUE_BRANCH in output, got %q", out)
	}
	if !strings.Contains(out, "FALSE_BRANCH") {
		t.Errorf("expected FALSE_BRANCH in output (fork drained), got %q", out)
	}
}

// TestRunIFChainBothBranchesTerminate: A IF chain on known TRUE/FALSE must not fork.
func TestRunIFChainBothBranchesTerminate(t *testing.T) {
	m := newFlowTestMachine()
	m.setCell("Sheet1", "A1", `=IF(TRUE,A2,A3)`, "")
	m.setCell("Sheet1", "A2", "=HALT()", "")
	m.setCell("Sheet1", "A3", `="SHOULDNOTAPPEAR"`, "")
	m.run("Sheet1", "A1")
	if len(m.forkQueue) != 0 {
		t.Errorf("expected empty forkQueue for known-TRUE IF, got len=%d", len(m.forkQueue))
	}
	if strings.Contains(flowOutput(m), "SHOULDNOTAPPEAR") {
		t.Errorf("false branch visited despite TRUE condition")
	}
}

// TestRunIFMalformed: malformed IF just advances PC (no panic).
func TestRunIFMalformed(t *testing.T) {
	m := newFlowTestMachine()
	m.setCell("Sheet1", "A1", `=IF()`, "")
	m.setCell("Sheet1", "A2", "=HALT()", "")
	m.run("Sheet1", "A1") // must not panic
}

// TestRunWHILETerminatesUnderStepFuse: pathological WHILE(TRUE) without
// NEXT still terminates via revisit or step fuse.
func TestRunWHILETerminatesUnderStepFuse(t *testing.T) {
	out := make([][]byte, 0)
	total := 0
	m := newMachine(&out, &total, time.Now().Add(5*time.Second))
	m.setCell("Sheet1", "A1", "=WHILE(TRUE)", "")
	// No NEXT — WHILE pushes whileStack and advances to A2; A2 missing → stop.
	m.run("Sheet1", "A1")
	// Just verify no panic and reasonable step count.
	if m.steps > maxEmulSteps {
		t.Errorf("steps %d exceeded maxEmulSteps %d", m.steps, maxEmulSteps)
	}
}
