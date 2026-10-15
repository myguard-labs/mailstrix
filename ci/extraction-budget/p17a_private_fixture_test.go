package extractionbudget_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const p17aExtractPrivateFixture = `package extract

import (
	"testing"
	"time"
)

func TestP17aCIPrivateOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *Options
		want int64
	}{
		{name: "nil", want: DefaultRetainedBytesLimit},
		{name: "bare", opts: &Options{}, want: DefaultRetainedBytesLimit},
		{name: "negative", opts: &Options{RetainedBytesLimit: -1}, want: DefaultRetainedBytesLimit},
		{name: "explicit", opts: &Options{RetainedBytesLimit: 1024}, want: 1024},
		{name: "full", opts: FullOptions(time.Time{}), want: DefaultRetainedBytesLimit},
	}
	for _, tt := range tests {
		got := normalizeRequestOptions(tt.opts)
		if got.RetainedBytesLimit != tt.want {
			t.Fatalf("%s request retained limit=%d want=%d", tt.name, got.RetainedBytesLimit, tt.want)
		}
		if got.retained == nil {
			t.Fatalf("%s request retained ledger is nil", tt.name)
		}
	}
	shared := &Options{}
	first, second := normalizeRequestOptions(shared), normalizeRequestOptions(shared)
	if first.retained == second.retained {
		t.Fatal("separate invocations reused one retained ledger")
	}
	if shared.RetainedBytesLimit != 0 || shared.retained != nil {
		t.Fatal("request normalization mutated caller Options")
	}
}
`

const p17aScannerPrivateFixture = `package mailstrix

import (
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func TestP17aCIPrivateScannerPlumbing(t *testing.T) {
	s := &Scanner{extractionRetainedBytes: 4096}
	for _, level := range []int{1, 5, 10} {
		profile := EffortProfileFor(level, 10, time.Minute)
		if got := s.buildExtractOptions(ScanMeta{}, profile, time.Time{}).RetainedBytesLimit; got != 4096 {
			t.Fatalf("effort %d retained limit=%d want=4096", level, got)
		}
	}
	if got := (&Scanner{}).buildExtractOptions(ScanMeta{}, EffortProfile{}, time.Time{}).RetainedBytesLimit; got != extract.DefaultRetainedBytesLimit {
		t.Fatalf("zero scanner retained limit=%d want=%d", got, extract.DefaultRetainedBytesLimit)
	}
}
`

func p17aFixtureRun(t *testing.T, root, extractSource, scannerSource string, coverage bool) ([]byte, []byte, error) {
	t.Helper()
	dir := t.TempDir()
	replacements := make(map[string]string)
	if extractSource != "" {
		path := filepath.Join(dir, "extract_test.go")
		if err := os.WriteFile(path, []byte(extractSource), 0o600); err != nil {
			t.Fatal(err)
		}
		replacements[filepath.Join(root, "internal", "extract", "p17a_ci_fixture_test.go")] = path
	}
	if scannerSource != "" {
		path := filepath.Join(dir, "scanner_test.go")
		if err := os.WriteFile(path, []byte(scannerSource), 0o600); err != nil {
			t.Fatal(err)
		}
		replacements[filepath.Join(root, "internal", "mailstrix", "p17a_ci_fixture_test.go")] = path
	}
	overlay, err := json.Marshal(struct {
		Replace map[string]string
	}{Replace: replacements})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"test", "-race", "-count=1", "-overlay", overlayPath, "-run", "^TestP17aCIPrivate"}
	coveragePath := filepath.Join(dir, "private.coverage")
	if coverage {
		args = append(args, "-coverpkg=./internal/extract,./internal/mailstrix", "-covermode=atomic", "-coverprofile", coveragePath)
	}
	if extractSource != "" {
		args = append(args, "./internal/extract")
	}
	if scannerSource != "" {
		args = append(args, "./internal/mailstrix")
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	output, runErr := cmd.CombinedOutput()
	var profile []byte
	if coverage {
		profile, err = os.ReadFile(coveragePath)
		if err != nil && runErr == nil {
			runErr = err
		}
	}
	if evidenceDir := os.Getenv("P17A_FIXTURE_EVIDENCE"); evidenceDir != "" && coverage {
		if err := os.MkdirAll(evidenceDir, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{
			"extract-fixture.go": []byte(extractSource),
			"scanner-fixture.go": []byte(scannerSource),
			"overlay.json":       overlay,
			"private.coverage":   profile,
		} {
			if err := os.WriteFile(filepath.Join(evidenceDir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return output, profile, runErr
}

func p17aFunctionLines(t *testing.T, path, name string) (int, int) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fset.Position(fn.Pos()).Line, fset.Position(fn.End()).Line
		}
	}
	t.Fatalf("function %s not found in %s", name, path)
	return 0, 0
}

func p17aCoverageState(profile []byte, suffix string, first, last int) (map[string]uint64, error) {
	counts := make(map[string]uint64)
	for _, line := range strings.Split(string(profile), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		colon := strings.LastIndexByte(fields[0], ':')
		if colon < 0 || !strings.HasSuffix(fields[0][:colon], suffix) {
			continue
		}
		var startLine, startCol, endLine, endCol int
		if _, err := fmt.Sscanf(fields[0][colon+1:], "%d.%d,%d.%d", &startLine, &startCol, &endLine, &endCol); err != nil {
			return nil, fmt.Errorf("parse coverage coordinate %q: %w", fields[0], err)
		}
		if endLine < first || startLine > last {
			continue
		}
		count, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid private fixture coverage count %s=%q", fields[0], fields[2])
		}
		if _, ok := counts[fields[0]]; !ok {
			counts[fields[0]] = 0
		}
		if count > counts[fields[0]] {
			counts[fields[0]] = count
		}
	}
	return counts, nil
}

func p17aCoverageBlocks(t *testing.T, profile []byte, suffix string, first, last int) {
	t.Helper()
	counts, err := p17aCoverageState(profile, suffix, first, last)
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) == 0 {
		t.Fatalf("private fixture coverage lacks %s:%d-%d", suffix, first, last)
	}
	for coordinate, count := range counts {
		if count == 0 {
			t.Fatalf("uncovered private fixture block %s", coordinate)
		}
	}
}

func TestP17aCoverageUnionOracle(t *testing.T) {
	const coordinate = "github.com/myguard-labs/mailstrix/internal/extract/extract.go:410.1,411.2 1 "
	for _, tt := range []struct {
		name    string
		profile string
		suffix  string
		found   bool
		covered bool
	}{
		{name: "zero then positive", profile: "mode: atomic\n" + coordinate + "0\n" + coordinate + "2\n", suffix: "internal/extract/extract.go", found: true, covered: true},
		{name: "all zero", profile: "mode: atomic\n" + coordinate + "0\n" + coordinate + "0\n", suffix: "internal/extract/extract.go", found: true},
		{name: "unbound source", profile: "mode: atomic\n" + coordinate + "2\n", suffix: "internal/mailstrix/scanner.go"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			counts, err := p17aCoverageState([]byte(tt.profile), tt.suffix, 410, 411)
			if err != nil {
				t.Fatal(err)
			}
			if (len(counts) > 0) != tt.found {
				t.Fatalf("found=%v want=%v counts=%v", len(counts) > 0, tt.found, counts)
			}
			covered := len(counts) > 0
			for _, count := range counts {
				covered = covered && count > 0
			}
			if covered != tt.covered {
				t.Fatalf("covered=%v want=%v counts=%v", covered, tt.covered, counts)
			}
		})
	}
}

func TestP17aPrivatePackageFixtures(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate P17a fixture")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	output, profile, err := p17aFixtureRun(t, root, p17aExtractPrivateFixture, p17aScannerPrivateFixture, true)
	if err != nil {
		t.Fatalf("private package fixtures failed: %v\n%s", err, output)
	}
	extractPath := filepath.Join(root, "internal", "extract", "extract.go")
	scannerPath := filepath.Join(root, "internal", "mailstrix", "scanner.go")
	first, last := p17aFunctionLines(t, extractPath, "normalizeRequestOptions")
	p17aCoverageBlocks(t, profile, "internal/extract/extract.go", first, last)
	first, last = p17aFunctionLines(t, scannerPath, "validatedExtractionRetainedBytes")
	p17aCoverageBlocks(t, profile, "internal/mailstrix/scanner.go", first, last)
	source, err := os.ReadFile(scannerPath)
	if err != nil {
		t.Fatal(err)
	}
	buildLine := 0
	for i, line := range strings.Split(string(source), "\n") {
		if strings.Contains(line, "xopts.RetainedBytesLimit = validatedExtractionRetainedBytes") {
			buildLine = i + 1
			break
		}
	}
	if buildLine == 0 {
		t.Fatal("scanner retained-limit assignment not found")
	}
	p17aCoverageBlocks(t, profile, "internal/mailstrix/scanner.go", buildLine, buildLine)

	mutant := strings.Replace(
		p17aExtractPrivateFixture,
		`{name: "bare", opts: &Options{}, want: DefaultRetainedBytesLimit}`,
		`{name: "bare", opts: &Options{}, want: 999}`,
		1,
	)
	if mutant == p17aExtractPrivateFixture {
		t.Fatal("fixture negative control did not alter its oracle")
	}
	output, _, err = p17aFixtureRun(t, root, mutant, "", false)
	if err == nil {
		t.Fatal("fixture negative control unexpectedly passed")
	}
	if !strings.Contains(string(output), "bare request retained limit=2621440 want=999") {
		t.Fatalf("fixture negative control failed for the wrong reason: %v\n%s", err, output)
	}
}
