package extract

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---- helpers ----------------------------------------------------------------

// newPCTestMachine returns a machine with a real deadline (10 s) so that
// deadline-independent tests still have a safety net.
func newPCTestMachine() *xlmMachine {
	out := make([][]byte, 0)
	total := 0
	return newMachine(&out, &total, time.Now().Add(10*time.Second))
}

// pcOutput collects all emitted bytes as a single string for easy comparison.
func pcOutput(m *xlmMachine) string {
	var parts []string
	for _, b := range *m.out {
		parts = append(parts, string(b))
	}
	return strings.Join(parts, "|")
}

// ---- unit tests for helpers -------------------------------------------------

// TestNextRow verifies basic row increment behaviour.
func TestNextRow(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"A1", "A2"},
		{"A9", "A10"},
		{"Z9", "Z10"},
		{"AA100", "AA101"},
		{"Z9999998", "Z9999999"},
		{"Z9999999", ""},    // overflow → ""
		{"", ""},            // empty → ""
		{"1A", ""},          // no leading column → ""
		{"A", ""},           // no row → ""
		{"A0", ""},          // row 0 invalid → ""
		{"INVALID", ""},
	}
	for _, tc := range cases {
		got := nextRow(tc.in)
		if got != tc.want {
			t.Errorf("nextRow(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestParseControlFlowArg verifies argument extraction for GOTO and related verbs.
func TestParseControlFlowArg(t *testing.T) {
	cases := []struct {
		verb      string
		formula   string
		wantSheet string
		wantCoord string
		wantOK    bool
	}{
		{"GOTO", "=GOTO(A3)", "", "A3", true},
		{"GOTO", "GOTO(A3)", "", "A3", true},
		{"GOTO", "=GOTO(Sheet2!B5)", "Sheet2", "B5", true},
		{"RUN", "=RUN(C10)", "", "C10", true},
		{"RUN", "=RUN(Macro!A1)", "Macro", "A1", true},
		// Case-insensitive verb match.
		{"GOTO", "=goto(A5)", "", "A5", true},
		// No arg.
		{"GOTO", "=GOTO()", "", "", false},
		// Missing paren.
		{"GOTO", "=HALT()", "", "", false},
		// Invalid coord.
		{"GOTO", "=GOTO(!!!)", "", "", false},
	}
	for _, tc := range cases {
		sh, coord, ok := parseControlFlowArg(tc.verb, tc.formula)
		if ok != tc.wantOK {
			t.Errorf("parseControlFlowArg(%q,%q): ok=%v want %v", tc.verb, tc.formula, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if sh != tc.wantSheet || coord != tc.wantCoord {
			t.Errorf("parseControlFlowArg(%q,%q) = (%q,%q), want (%q,%q)",
				tc.verb, tc.formula, sh, coord, tc.wantSheet, tc.wantCoord)
		}
	}
}

// ---- PC loop tests ----------------------------------------------------------

// TestRunHalt: single cell with HALT() stops without panic.
func TestRunHalt(t *testing.T) {
	m := newPCTestMachine()
	m.setCell("Sheet1", "A1", "=HALT()", "")
	m.run("Sheet1", "A1")
	// No panic, no output.
	if got := pcOutput(m); got != "" {
		t.Errorf("expected no output, got %q", got)
	}
}

// TestRunGOTO: A1 jumps to A3, A3 halts.
func TestRunGOTO(t *testing.T) {
	m := newPCTestMachine()
	m.setCell("Sheet1", "A1", "=GOTO(A3)", "")
	m.setCell("Sheet1", "A3", "=HALT()", "")
	m.run("Sheet1", "A1")
	// A2 was never visited.
	if m.visited["Sheet1!A2"] != 0 {
		t.Errorf("A2 should not have been visited")
	}
	if m.visited["Sheet1!A3"] != 1 {
		t.Errorf("A3 should have been visited exactly once, got %d", m.visited["Sheet1!A3"])
	}
}

// TestRunRUNReturn: A1=RUN(B1), B1=RETURN(), A2=HALT().
// After B1 returns, execution should resume at A2 (next row after A1).
func TestRunRUNReturn(t *testing.T) {
	m := newPCTestMachine()
	m.setCell("Sheet1", "A1", "=RUN(B1)", "")
	m.setCell("Sheet1", "B1", "=RETURN()", "")
	m.setCell("Sheet1", "A2", "=HALT()", "")
	m.run("Sheet1", "A1")
	if m.visited["Sheet1!B1"] != 1 {
		t.Errorf("B1 should have been visited once, got %d", m.visited["Sheet1!B1"])
	}
	if m.visited["Sheet1!A2"] != 1 {
		t.Errorf("A2 should have been visited once (resume after RETURN), got %d", m.visited["Sheet1!A2"])
	}
}

// TestRunStepsFuse: chain of 2001 GOTO cells; must stop at step 2000.
func TestRunStepsFuse(t *testing.T) {
	m := newPCTestMachine()
	// A1→A2→…→A2001; each cell jumps to the next.
	for i := 1; i <= 2001; i++ {
		next := fmt.Sprintf("A%d", i+1)
		m.setCell("Sheet1", fmt.Sprintf("A%d", i), fmt.Sprintf("=GOTO(%s)", next), "")
	}
	m.run("Sheet1", "A1")
	if m.steps > maxEmulSteps {
		t.Errorf("steps=%d exceeded maxEmulSteps=%d", m.steps, maxEmulSteps)
	}
}

// TestRunRevisitFuse: A1 GOTO A1 (self-loop); must stop after revisit fuse.
func TestRunRevisitFuse(t *testing.T) {
	m := newPCTestMachine()
	m.setCell("Sheet1", "A1", "=GOTO(A1)", "")
	m.run("Sheet1", "A1")
	if m.visited["Sheet1!A1"] <= maxEmulRevisit {
		// It can be exactly maxEmulRevisit+1 because we increment then check.
		t.Errorf("expected revisit count > %d, got %d", maxEmulRevisit, m.visited["Sheet1!A1"])
	}
}

// TestRunCallStackFuse: 65 nested RUN calls must stop at branchStack 64.
func TestRunCallStackFuse(t *testing.T) {
	m := newPCTestMachine()
	// A1=RUN(B1), B1=RUN(C1), … — 65 levels deep. Last one is also a RUN
	// into a cell that doesn't exist so it would stop naturally, but the
	// fuse should fire first at depth 64.
	cols := []string{
		"A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
		"K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
		"U", "V", "W", "X", "Y", "Z",
		"AA", "AB", "AC", "AD", "AE", "AF", "AG", "AH", "AI", "AJ",
		"AK", "AL", "AM", "AN", "AO", "AP", "AQ", "AR", "AS", "AT",
		"AU", "AV", "AW", "AX", "AY", "AZ",
		"BA", "BB", "BC", "BD", "BE", "BF", "BG", "BH", "BI", "BJ",
		"BK", "BL", "BM", "BN",
	}
	// Build 65 RUN-chained cells (index 0..64).
	for i := 0; i < 65; i++ {
		coord := cols[i] + "1"
		var formula string
		if i < 64 {
			formula = fmt.Sprintf("=RUN(%s1)", cols[i+1])
		} else {
			formula = "=HALT()"
		}
		m.setCell("Sheet1", coord, formula, "")
	}
	m.run("Sheet1", "A1")
	// Must not panic; branchStack must not have grown beyond cap.
	if len(m.branchStack) > maxEmulBranchStack {
		t.Errorf("branchStack len %d exceeded cap %d", len(m.branchStack), maxEmulBranchStack)
	}
}

// TestRunDeadlineExpired: expired deadline → stops immediately.
func TestRunDeadlineExpired(t *testing.T) {
	out := make([][]byte, 0)
	total := 0
	// Already-expired deadline.
	m := newMachine(&out, &total, time.Now().Add(-time.Second))
	m.setCell("Sheet1", "A1", "=HALT()", "")
	m.run("Sheet1", "A1") // must not panic
}

// TestRunEmitsFormula: non-control formula cell emits output and advances.
// We use a string literal long enough to clear the minXLMFoldResult=8 noise floor.
func TestRunEmitsFormula(t *testing.T) {
	m := newPCTestMachine()
	// A1 has a plain formula that folds to a 9-char string; A2 halts.
	m.setCell("Sheet1", "A1", `="ABCDEFGHI"`, "")
	m.setCell("Sheet1", "A2", "=HALT()", "")
	m.run("Sheet1", "A1")
	out := pcOutput(m)
	if !strings.Contains(out, "ABCDEFGHI") {
		t.Errorf("expected emitted output to contain 'ABCDEFGHI', got %q", out)
	}
	if m.visited["Sheet1!A2"] != 1 {
		t.Errorf("expected A2 to be visited after advancing from A1, got %d", m.visited["Sheet1!A2"])
	}
}

// TestRunOutputCapStop: fill output to near-cap; verify run stops on cap.
func TestRunOutputCapStop(t *testing.T) {
	out := make([][]byte, 0)
	total := maxXLMFoldOutputLen - 2 // only 2 bytes headroom
	m := newMachine(&out, &total, time.Now().Add(10*time.Second))

	// Plant a cell that would emit a 10-byte string; should trigger cap.
	// Use a raw formula containing just the string in quotes so evalExpr returns it.
	m.setCell("Sheet1", "A1", `="ABCDEFGHIJ"`, "")
	m.setCell("Sheet1", "A2", "=HALT()", "")
	m.run("Sheet1", "A1")
	// Must not panic; output must not exceed cap.
	if *m.totalOutput > maxXLMFoldOutputLen {
		t.Errorf("totalOutput %d exceeded cap %d", *m.totalOutput, maxXLMFoldOutputLen)
	}
}

// TestRunFuzzSeeds: runs all D3 fuzz seeds through run() directly; verifies no panic.
func TestRunFuzzSeeds(t *testing.T) {
	// Seed 2: GOTO chain.
	{
		out := make([][]byte, 0)
		total := 0
		m := newMachine(&out, &total, time.Now().Add(5*time.Second))
		m.setCell("Sheet1", "A1", "=GOTO(A3)", "")
		m.setCell("Sheet1", "A3", "=HALT()", "")
		m.run("Sheet1", "A1")
	}
	// Seed 3: IF with branches (non-control; just emits and advances).
	{
		out := make([][]byte, 0)
		total := 0
		m := newMachine(&out, &total, time.Now().Add(5*time.Second))
		m.setCell("Sheet1", "A1", `=IF(TRUE,A2,A3)`, "")
		m.setCell("Sheet1", "A2", `=EXEC("yes")`, "")
		m.setCell("Sheet1", "A3", `=EXEC("no")`, "")
		m.run("Sheet1", "A1")
	}
	// Seed 6: self-GOTO tight loop — revisit fuse must stop it.
	{
		out := make([][]byte, 0)
		total := 0
		m := newMachine(&out, &total, time.Now().Add(5*time.Second))
		m.setCell("Sheet1", "A1", "=GOTO(A1)", "")
		m.run("Sheet1", "A1")
	}
	// Seed 5: SET.VALUE + CALL (no control flow; run emits/advances).
	{
		out := make([][]byte, 0)
		total := 0
		m := newMachine(&out, &total, time.Now().Add(5*time.Second))
		m.setCell("Sheet1", "A1", `=SET.VALUE(B1,"cmd")`, "")
		m.setCell("Sheet1", "B1", `=CALL("kernel32","VirtualAlloc","JJJJJ",0,4096,4096,64)`, "")
		m.run("Sheet1", "A1")
	}
	// Empty / nil sheet.
	{
		out := make([][]byte, 0)
		total := 0
		m := newMachine(&out, &total, time.Now().Add(5*time.Second))
		m.run("Sheet1", "A1") // missing sheet → immediate stop, no panic
	}
}
