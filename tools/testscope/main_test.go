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

func TestChangedScopeExplicitMappings(t *testing.T) {
	graph := append(testGraph(), pkg{ImportPath: "example.com/m/tools/testscope", Dir: "/r/tools/testscope"})
	for _, tc := range []struct {
		name  string
		files []string
		want  string
		bad   bool
	}{
		{"empty-diff", nil, "", false},
		{"docs", []string{"README.md"}, "", false},
		{"workflow", []string{".github/workflows/ci.yml"}, "example.com/m/tools/testscope", false},
		{"shell-contract", []string{"scripts/smoke.sh", "packaging/deb/env_keys_test.sh", "ci/testscope_test.sh", "docker/Dockerfile.release"}, "", false},
		{"leaf", []string{"internal/verdict/verdict.go"}, "example.com/m/internal/verdict", false},
		{"importers", []string{"internal/extract/archive.go"}, "example.com/m/cmd/strixd example.com/m/internal/extract example.com/m/internal/mailstrix", false},
		{"test-only-importer", []string{"internal/mbazaar/a.go"}, "example.com/m/internal/mailstrix example.com/m/internal/mbazaar", false},
		{"testdata", []string{"internal/verdict/testdata/a.eml"}, "example.com/m/internal/verdict", false},
		{"deleted-package", []string{"internal/gone/a.go"}, "", true},
		{"unknown-script", []string{"scripts/unknown.go"}, "", true},
		{"unknown-ci-input", []string{"ci/unknown.txt"}, "", true},
		{"unknown-workflow-code", []string{".github/unknown.go"}, "", true},
		{"mixed-unknown", []string{"internal/verdict/a.go", "unknown.txt"}, "", true},
		{"global-does-not-hide-unknown", []string{"go.mod", "unknown.txt"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectChangedPackages(tc.files, graph, "/r")
			if (err != nil) != tc.bad || strings.Join(got, " ") != tc.want {
				t.Fatalf("got %v, %v; want %q, error=%v", got, err, tc.want, tc.bad)
			}
		})
	}
	for _, file := range []string{"go.mod", "go.sum", "docker/Dockerfile", ".dockerignore"} {
		got, err := selectChangedPackages([]string{file}, graph, "/r")
		if err != nil || len(got) != len(graph) || strings.Join(got, " ") == all {
			t.Fatalf("global %s: got %v, %v", file, got, err)
		}
	}
}

func TestChangedExternalInputs(t *testing.T) {
	graph := append(testGraph(), pkg{ImportPath: "example.com/m/internal/cape", Dir: "/r/internal/cape"})
	for _, tc := range []struct{ file, want string }{
		{"internal/mailstrix/CAPE.md", "example.com/m/internal/mailstrix"},
		{"internal/cape/STORE.md", "example.com/m/internal/cape"},
		{"internal/mailstrix/CAPE-OPERATIONS.md", "example.com/m/internal/cape"},
		{"docker/fetch-rules.sh", "example.com/m/internal/extract"},
		{"docker/local-rules/deleted.yara", "example.com/m/internal/extract example.com/m/internal/mailstrix"},
		{"contrib/clamd/test_clients.py", "example.com/m/internal/mailstrix"},
		{"internal/extract/testdata/deleted.eml", "example.com/m/internal/extract example.com/m/internal/mailstrix"},
		{"third_party/oleparse/oleparse.go", "example.com/m/cmd/strixd example.com/m/internal/extract example.com/m/internal/mailstrix"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			got, err := selectChangedPackages([]string{tc.file}, graph, "/r")
			if err != nil || strings.Join(got, " ") != tc.want {
				t.Fatalf("got %v, %v; want %s", got, err, tc.want)
			}
		})
	}
}

func TestSelectTestOnlyDoesNotRunProductionConsumers(t *testing.T) {
	for _, file := range []string{"internal/extract/archive_test.go", "internal/extract/testdata/deleted.eml", "internal/mbazaar/client_test.go"} {
		got := sel(file)
		owner := "example.com/m/" + strings.Split(file, "/")[0] + "/" + strings.Split(file, "/")[1]
		if got != owner {
			t.Fatalf("%s: got %s, want only %s", file, got, owner)
		}
	}
}

func TestSelectTestImporterOrderIndependent(t *testing.T) {
	graph := []pkg{
		{ImportPath: "m/a", Dir: "/r/a"},
		{ImportPath: "m/b", Dir: "/r/b", TestImports: []string{"m/a"}},
		{ImportPath: "m/c", Dir: "/r/c", XTestImports: []string{"m/b"}},
	}
	for _, reverse := range []bool{false, true} {
		if reverse {
			graph[0], graph[2] = graph[2], graph[0]
		}
		got := strings.Join(selectPackages([]string{"a/source.go"}, graph, "/r"), " ")
		if got != "m/a m/b" {
			t.Fatalf("reverse=%v: got %s", reverse, got)
		}
	}
}

func TestSelectRejectsTestdataPrefixLookalike(t *testing.T) {
	got := selectPackages([]string{"internal/verdict/testdatabase/x.eml"}, testGraph(), "/r")
	if !reflect.DeepEqual(got, []string{all}) {
		t.Fatalf("unmapped sibling accepted: %v", got)
	}
}

func TestSelectGraphWithRootPackage(t *testing.T) {
	graph := append(testGraph(), pkg{ImportPath: "example.com/m", Dir: "/r"})
	got := selectPackages([]string{"internal/verdict/verdict.go"}, graph, "/r")
	if strings.Join(got, " ") != "example.com/m/internal/verdict" {
		t.Fatalf("unrelated root package selected: %v", got)
	}
}
