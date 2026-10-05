// Command testscope prints the Go packages whose tests a change must run: the
// packages containing changed files plus every package that imports them,
// directly or through tests. It prints "./..." (the whole suite) when
// invoked with no list (release/maintenance). Explicit changed paths select
// affected packages, with non-Go CI inputs mapped explicitly and unknown paths
// rejected. Usage: testscope [--changed] [changed-file ...]
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
)

// pkg is the subset of `go list -json` testscope needs.
type pkg struct {
	ImportPath   string
	Dir          string
	Deps         []string
	TestImports  []string
	XTestImports []string
}

const all = "./..."

func main() {
	changed := flag.Bool("changed", false, "select a PR change; refuse unmapped inputs instead of testing everything")
	flag.Parse()
	pkgs, root, err := listPackages()
	if err != nil {
		fmt.Fprintln(os.Stderr, "testscope:", err)
		os.Exit(1)
	}
	if !*changed && len(flag.Args()) == 0 {
		fmt.Println(strings.Join(selectPackages(flag.Args(), pkgs, root), " "))
		return
	}
	selected, err := selectChangedPackages(flag.Args(), pkgs, root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testscope:", err)
		os.Exit(1)
	}
	fmt.Println(strings.Join(selected, " "))
}

// selectChangedPackages keeps PR selection explicit. Shared module/native-build
// inputs affect every package; workflow edits select the selector's own tests,
// while shell/package/release-image inputs have their separate CI contract tests.
// Unknown and deleted package paths require an explicit mapping before CI runs.
func selectChangedPackages(changed []string, pkgs []pkg, root string) ([]string, error) {
	var goFiles []string
	global := false
	for _, f := range changed {
		f = path.Clean(strings.TrimPrefix(strings.TrimSpace(f), "./"))
		switch {
		case len(externalInputs(f)) > 0:
			goFiles = append(goFiles, externalInputs(f)...)
		case f == "." || strings.HasSuffix(f, ".md"):
			continue
		case globalInputs[f]:
			global = true
		case workflowInput(f):
			goFiles = append(goFiles, "tools/testscope/main.go")
		case separateContract(f):
			continue // covered by the corresponding script/workflow/image contracts
		default:
			goFiles = append(goFiles, f)
		}
	}
	var selected []string
	if len(goFiles) > 0 {
		selected = selectPackages(goFiles, pkgs, root)
		if len(selected) == 1 && selected[0] == all {
			return nil, fmt.Errorf("unmapped changed paths: add an impact mapping before running PR unit tests")
		}
	}
	if global {
		selected = make([]string, 0, len(pkgs))
		for _, p := range pkgs {
			selected = append(selected, p.ImportPath)
		}
		sort.Strings(selected)
	}
	return selected, nil
}

// External runtime/test inputs must select their real Go consumers before generic
// documentation or script handling. Keep these in step with the tests reading them.
func externalInputs(f string) []string {
	switch {
	case f == "internal/mailstrix/CAPE.md", f == "contrib/clamd/test_clients.py":
		return []string{"internal/mailstrix/input_test.go"}
	case f == "internal/cape/STORE.md", f == "internal/mailstrix/CAPE-OPERATIONS.md":
		return []string{"internal/cape/input_test.go"}
	case f == "internal/extract/testdata/fixture-encrypted-files.rar":
		return []string{f, "internal/mailstrix/input_test.go", "ci/rar_password_extract_test.go"}
	case strings.HasPrefix(f, "internal/extract/testdata/"):
		return []string{f, "internal/mailstrix/input_test.go"}
	case f == "docker/fetch-rules.sh":
		return []string{"internal/extract/input_test.go"}
	case strings.HasPrefix(f, "docker/local-rules/"):
		return []string{"internal/extract/input_test.go", "internal/mailstrix/input_test.go"}
	case strings.HasPrefix(f, "third_party/oleparse/") && !strings.HasSuffix(f, ".md"):
		return []string{"internal/extract/input.go"}
	}
	return nil
}

var globalInputs = map[string]bool{
	"go.mod": true, "go.sum": true, "docker/Dockerfile": true, ".dockerignore": true,
}

func workflowInput(f string) bool {
	ext := path.Ext(f)
	return strings.HasPrefix(f, ".github/") && (ext == ".yml" || ext == ".yaml")
}

var contractFiles = map[string]bool{
	"ci/testscope_test.sh": true, "docker/Dockerfile.release": true, "docker/docker-compose.yml": true,
}

var contractExtensions = map[string]map[string]bool{
	"scripts":   {".sh": true},
	"docker":    {".sh": true},
	"packaging": {".sh": true, ".py": true, ".yaml": true, ".env": true, ".service": true, ".sysusers": true},
}

func separateContract(f string) bool {
	if contractFiles[f] {
		return true
	}
	// Only the namespace matters; no separator means an unmapped root input.
	root, _, _ := strings.Cut(f, "/")
	return contractExtensions[root][path.Ext(f)]
}

func listPackages() ([]pkg, string, error) {
	mod, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		return nil, "", fmt.Errorf("go list -m: %w", err)
	}
	out, err := exec.Command("go", "list", "-json", "./...").Output()
	if err != nil {
		return nil, "", fmt.Errorf("go list: %w", err)
	}
	pkgs, err := decodePackages(bytes.NewReader(out))
	return pkgs, strings.TrimSpace(string(mod)), err
}

func decodePackages(r io.Reader) ([]pkg, error) {
	var pkgs []pkg
	dec := json.NewDecoder(bufio.NewReader(r))
	for {
		var p pkg
		if err := dec.Decode(&p); err == io.EOF {
			return pkgs, nil
		} else if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
}

// selectPackages maps changed repository-relative paths to the packages to
// test, as import paths, or returns []string{"./..."} when it must not narrow.
func selectPackages(changed []string, pkgs []pkg, root string) []string {
	if len(changed) == 0 {
		return []string{all}
	}
	byDir := make(map[string]string, len(pkgs)) // repo-relative dir -> import path
	for _, p := range pkgs {
		rel := strings.TrimPrefix(strings.TrimPrefix(p.Dir, root), "/")
		if rel == "" {
			rel = "."
		}
		byDir[rel] = p.ImportPath
	}
	direct := map[string]bool{}
	testOnly := map[string]bool{}
	for _, f := range changed {
		f = path.Clean(strings.TrimPrefix(strings.TrimSpace(f), "./"))
		if f == "." || f == "" {
			continue
		}
		if strings.HasSuffix(f, ".md") {
			continue
		}
		owners := direct
		if strings.HasSuffix(f, "_test.go") || strings.Contains(f, "/testdata/") {
			owners = testOnly
		}
		if !inPackage(f, byDir, owners) {
			return []string{all}
		}
	}
	if len(direct) == 0 && len(testOnly) == 0 {
		return nil // documentation-only change: nothing to test
	}
	// Packages whose (non-test) dependency closure contains a changed package.
	affected := map[string]bool{}
	for _, p := range pkgs {
		if direct[p.ImportPath] || anyIn(p.Deps, direct) {
			affected[p.ImportPath] = true
		}
	}
	// Test dependencies observe production changes, never other packages' test-only changes.
	production := make(map[string]bool, len(affected))
	for ip := range affected {
		production[ip] = true
	}
	// Plus packages whose tests import a production-affected package.
	for _, p := range pkgs {
		if anyIn(p.TestImports, production) || anyIn(p.XTestImports, production) {
			affected[p.ImportPath] = true
		}
	}
	for ip := range testOnly {
		affected[ip] = true
	}
	out := make([]string, 0, len(affected))
	for ip := range affected {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// inPackage records the package owning f (a file in a package directory or in
// one of its testdata trees) and reports whether there is one.
func inPackage(f string, byDir map[string]string, direct map[string]bool) bool {
	dir := path.Dir(f)
	if dir == "." {
		return false // repository root: go.mod, go.sum, build and CI files
	}
	for d := dir; d != "."; d = path.Dir(d) {
		ip, ok := byDir[d]
		if !ok {
			continue
		}
		// Only the package's own dir or its testdata subtree belongs to it.
		if d == dir || (dir == d+"/testdata" || strings.HasPrefix(dir, d+"/testdata/")) {
			direct[ip] = true
			return true
		}
		return false
	}
	return false
}

func anyIn(list []string, set map[string]bool) bool {
	for _, s := range list {
		if set[s] {
			return true
		}
	}
	return false
}
