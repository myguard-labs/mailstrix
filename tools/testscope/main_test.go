package main

import (
	"reflect"
	"strings"
	"testing"
)

// graph: extract <- mailstrix <- cmd/strixd; verdict is independent; mbazaar
// is only imported by mailstrix's tests.
func testGraph() []pkg {
	const m = "example.com/m"
	return []pkg{
		{ImportPath: m + "/internal/extract", Dir: "/r/internal/extract"},
		{ImportPath: m + "/internal/mbazaar", Dir: "/r/internal/mbazaar"},
		{ImportPath: m + "/internal/mailstrix", Dir: "/r/internal/mailstrix",
			Deps: []string{m + "/internal/extract"}, TestImports: []string{m + "/internal/mbazaar"}},
		{ImportPath: m + "/internal/verdict", Dir: "/r/internal/verdict"},
		{ImportPath: m + "/cmd/strixd", Dir: "/r/cmd/strixd",
			Deps: []string{m + "/internal/mailstrix", m + "/internal/extract"}},
	}
}

func sel(files ...string) string {
	return strings.Join(selectPackages(files, testGraph(), "/r"), " ")
}

func TestSelectReverseDependencies(t *testing.T) {
	got := sel("internal/extract/archive.go")
	want := "example.com/m/cmd/strixd example.com/m/internal/extract example.com/m/internal/mailstrix"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSelectTestOnlyImporter(t *testing.T) {
	// mbazaar changes must run mailstrix's tests, which import it.
	got := sel("internal/mbazaar/client.go")
	want := "example.com/m/internal/mailstrix example.com/m/internal/mbazaar"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSelectLeafAndTestdata(t *testing.T) {
	if got := sel("internal/verdict/verdict_test.go"); got != "example.com/m/internal/verdict" {
		t.Fatalf("leaf: got %q", got)
	}
	if got := sel("internal/verdict/testdata/case/a.eml"); got != "example.com/m/internal/verdict" {
		t.Fatalf("testdata: got %q", got)
	}
}

// Anything that cannot be mapped safely runs the whole suite.
func TestSelectFallsBackToAll(t *testing.T) {
	for _, files := range [][]string{
		nil,                                 // no file list (push, workflow_call)
		{"go.mod"},                          // module input
		{"docker/Dockerfile"},               // build input outside any package
		{".github/workflows/ci.yml"},        // CI definition
		{"internal/gone/removed.go"},        // deleted package
		{"internal/verdict/sub/x.go"},       // unknown subdirectory of a package
		{"internal/verdict/v.go", "go.sum"}, // one unsafe file among safe ones
	} {
		if got := selectPackages(files, testGraph(), "/r"); !reflect.DeepEqual(got, []string{all}) {
			t.Errorf("%v: got %v, want [%s]", files, got, all)
		}
	}
}

func TestSelectDocsOnlyRunsNothing(t *testing.T) {
	if got := selectPackages([]string{"README.md", "internal/extract/NOTES.md"}, testGraph(), "/r"); len(got) != 0 {
		t.Fatalf("docs-only: got %v, want none", got)
	}
}

func TestSelectNormalisesPaths(t *testing.T) {
	if got := sel("./internal/verdict/v.go", " internal/verdict/w.go ", ""); got != "example.com/m/internal/verdict" {
		t.Fatalf("got %q", got)
	}
}

func TestDecodePackagesMalformed(t *testing.T) {
	if _, err := decodePackages(strings.NewReader(`{"ImportPath": "a"} {bad`)); err == nil {
		t.Fatal("malformed go list output accepted")
	}
	got, err := decodePackages(strings.NewReader(`{"ImportPath":"a","Dir":"/r/a"}{"ImportPath":"b"}`))
	if err != nil || len(got) != 2 || got[0].Dir != "/r/a" {
		t.Fatalf("got %+v, %v", got, err)
	}
}
