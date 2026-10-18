package mailstrix

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// defaultBudgetScannerCallers lists the only test functions allowed to build a
// scanner with newScanner (the effort-scaled production budget, about 4.4 s).
// Every one exercises budget/deadline behavior. A test asserting a scan RESULT
// must use newScannerBudget(..., loadInsensitiveScanTimeout) so a loaded -race
// runner cannot turn its verdict into ErrScanIncomplete.
var defaultBudgetScannerCallers = map[string]bool{
	"extract_budget_test.go:budgetScanner":                              true,
	"extract_budget_test.go:TestScanBudgetBoundary":                     true,
	"extract_budget_test.go:TestScanExtractedStreamTimeoutIsIncomplete": true,
	"extract_budget_test.go:TestScanExtractedStreamCleanControl":        true,
	"cape_scan_native_test.go:TestCAPENativeBudgetExhausted":            true,
}

// funcCallsNewScanner reports whether the named function in src calls newScanner.
func funcCallsNewScanner(t *testing.T, name, src, fn string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil && fd.Name.Name == fn {
			return callsNewScanner(fd.Body)
		}
	}
	return false
}

func callsNewScanner(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "newScanner" {
				found = true
			}
		}
		return true
	})
	return found
}

// scanBudgetViolations returns "file:func" for every function in the parsed
// files that calls newScanner and is not allowlisted.
func scanBudgetViolations(t *testing.T, files map[string]string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var bad []string
	for name, src := range files {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			found := callsNewScanner(fn.Body)
			key := filepath.Base(name) + ":" + fn.Name.Name
			if found && !defaultBudgetScannerCallers[key] {
				bad = append(bad, key)
			}
		}
	}
	sort.Strings(bad)
	return bad
}

func TestScanBudgetAuditResultTestsAvoidDefaultBudget(t *testing.T) {
	matches, err := filepath.Glob("*_test.go")
	if err != nil || len(matches) == 0 {
		t.Fatalf("glob: %v %d", err, len(matches))
	}
	files := map[string]string{}
	for _, m := range matches {
		src, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		files[m] = string(src)
	}
	if bad := scanBudgetViolations(t, files); len(bad) != 0 {
		t.Fatalf("result-asserting tests must use newScannerBudget(..., loadInsensitiveScanTimeout), not newScanner: %s", strings.Join(bad, ", "))
	}
	// Every allowlist entry must still exist, so the list cannot rot.
	for key := range defaultBudgetScannerCallers {
		file, fn, _ := strings.Cut(key, ":")
		if !funcCallsNewScanner(t, file, files[file], fn) {
			t.Errorf("stale allowlist entry %s: function missing or no longer calls newScanner", key)
		}
	}
}

// Negative control: a result test that reverts to newScanner is flagged; a
// budget-allowlisted one and a newScannerBudget caller are not.
func TestScanBudgetAuditNegativeControl(t *testing.T) {
	const reverted = "package p\nfunc TestResult(t *testing.T) { s := newScanner(t, \"\"); _ = s }\n"
	const fine = "package p\nfunc TestResult(t *testing.T) { s := newScannerBudget(t, \"\", 0); _ = s }\n"
	const budget = "package p\nfunc budgetScanner(t *testing.T) { _ = newScanner(t, \"\") }\n"
	if got := scanBudgetViolations(t, map[string]string{"x_test.go": reverted}); len(got) != 1 || got[0] != "x_test.go:TestResult" {
		t.Fatalf("reverted test not flagged: %v", got)
	}
	if got := scanBudgetViolations(t, map[string]string{"x_test.go": fine}); len(got) != 0 {
		t.Fatalf("newScannerBudget flagged: %v", got)
	}
	if got := scanBudgetViolations(t, map[string]string{"extract_budget_test.go": budget}); len(got) != 0 {
		t.Fatalf("allowlisted budget helper flagged: %v", got)
	}
}
