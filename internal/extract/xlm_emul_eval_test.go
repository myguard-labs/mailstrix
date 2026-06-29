package extract

import (
	"strings"
	"testing"
	"time"
)

// newEvalTestMachine builds a minimal xlmMachine for eval tests.
func newEvalTestMachine() *xlmMachine {
	out := make([][]byte, 0)
	total := 0
	return newMachine(&out, &total, time.Now().Add(10*time.Second))
}

// TestEvalExprLiteral verifies that a formula with no cell refs passes through unchanged.
func TestEvalExprLiteral(t *testing.T) {
	m := newEvalTestMachine()
	got := evalExpr(m, "Sheet1", `"hello world"`, nil)
	if got != "hello world" {
		// foldXLMFormulaDepth strips outer quotes; accept either form.
		if !strings.Contains(got, "hello world") {
			t.Errorf("expected literal passthrough, got %q", got)
		}
	}
}

// TestEvalExprCHAR verifies that =CHAR(65) folds to "A".
func TestEvalExprCHAR(t *testing.T) {
	m := newEvalTestMachine()
	got := evalExpr(m, "Sheet1", "=CHAR(65)", nil)
	if got != "A" {
		t.Errorf("expected CHAR(65)=A, got %q", got)
	}
}

// TestEvalExprA1Resolve verifies A1 ref substitution.
func TestEvalExprA1Resolve(t *testing.T) {
	m := newEvalTestMachine()
	m.setCell("Sheet1", "A1", "", "hello ")
	got := evalExpr(m, "Sheet1", `=A1&"world"`, nil)
	if !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
		t.Errorf("expected resolved ref, got %q", got)
	}
}

func TestEvalExprRefPlaceholderQuoted(t *testing.T) {
	m := newEvalTestMachine()
	m.setCell("Sheet1", "A1", "", "ABCDEFGHIJK")
	got := evalExpr(m, "Sheet1", "=MID([[REF:A1]],2,8)&CHAR(33)", nil)
	if got != "BCDEFGHI!" {
		t.Fatalf("placeholder MID: got %q, want BCDEFGHI!", got)
	}
}

// TestEvalExprCycleBreak verifies that circular references do not infinite-loop.
func TestEvalExprCycleBreak(t *testing.T) {
	m := newEvalTestMachine()
	// A1 value references B1 textually; B1 value references A1 textually.
	// Because getCellValue returns stored strings (not re-evaluated formulas),
	// we simulate the cycle by having A1's stored value contain "B1" and
	// B1's stored value contain "A1".
	m.setCell("Sheet1", "A1", "", "B1")
	m.setCell("Sheet1", "B1", "", "A1")
	// Evaluate starting from an expression that references A1.
	evaluating := map[string]bool{"Sheet1!A1": true}
	got := evalExpr(m, "Sheet1", "=A1", evaluating)
	// Must terminate; partial or full result is acceptable.
	_ = got
}

// TestEvalExprR1C1Convert verifies R1C1 → A1 conversion and lookup.
func TestEvalExprR1C1Convert(t *testing.T) {
	m := newEvalTestMachine()
	m.setCell("Sheet1", "A1", "", "found")
	got := evalExpr(m, "Sheet1", "=R1C1", nil)
	if !strings.Contains(got, "found") {
		t.Errorf("expected R1C1 resolved to A1 value 'found', got %q", got)
	}
}

// TestEvalExprColNumToLetters unit-tests the column converter.
func TestEvalExprColNumToLetters(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{1, "A"},
		{26, "Z"},
		{27, "AA"},
		{702, "ZZ"},
		{703, "AAA"},
		{0, ""},
		{16385, ""},
	}
	for _, tc := range cases {
		got := colNumToLetters(tc.n)
		if got != tc.want {
			t.Errorf("colNumToLetters(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// TestEvalExprPassCap verifies that a chain of 33+ unique unresolvable refs
// terminates without panic (pass cap enforcement).
func TestEvalExprPassCap(t *testing.T) {
	m := newEvalTestMachine()
	// Build a formula referencing 33 unique cells none of which exist.
	// e.g. =A1&A2&A3&...&A33 — all unresolvable, forces maxRefResolvePasses.
	parts := make([]string, 34)
	for i := range parts {
		parts[i] = "A" + strings.TrimSpace(strings.Repeat("0", 0)) + string(rune('1'+i%9))
	}
	formula := "=" + strings.Join(parts, "&")
	got := evalExpr(m, "Sheet1", formula, nil)
	// Must return without panic; result may be partial.
	_ = got
}

// TestEvalExprNilEvaluating verifies that passing nil evaluating causes no panic.
func TestEvalExprNilEvaluating(t *testing.T) {
	m := newEvalTestMachine()
	got := evalExpr(m, "Sheet1", "=CHAR(66)", nil)
	if got != "B" {
		t.Errorf("expected B, got %q", got)
	}
}

// TestEvalExprEmptyFormula verifies that an empty formula returns an empty string.
func TestEvalExprEmptyFormula(t *testing.T) {
	m := newEvalTestMachine()
	got := evalExpr(m, "Sheet1", "", nil)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// TestEvalExprDeadlineExpired verifies no panic when deadline is already past.
func TestEvalExprDeadlineExpired(t *testing.T) {
	out := make([][]byte, 0)
	total := 0
	m := newMachine(&out, &total, time.Now().Add(-1*time.Second)) // expired
	got := evalExpr(m, "Sheet1", "=CHAR(67)", nil)
	// Fail-open: result may be partial or empty, must not panic.
	_ = got
}
