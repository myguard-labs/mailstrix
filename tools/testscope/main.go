// Command testscope prints the Go packages whose tests a change must run: the
// packages containing changed files plus every package that imports them,
// directly or through tests. It prints "./..." (the whole suite) whenever the
// change cannot be mapped safely: no file list, a module or build input
// (go.mod, go.sum, Dockerfile, workflows, scripts), or a file outside any Go
// package directory. Usage: testscope [changed-file ...]
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
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
	pkgs, root, err := listPackages()
	if err != nil {
		// Fail safe: an unreadable package graph means test everything.
		fmt.Fprintln(os.Stderr, "testscope:", err)
		fmt.Println(all)
		return
	}
	fmt.Println(strings.Join(selectPackages(os.Args[1:], pkgs, root), " "))
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
	for _, f := range changed {
		f = path.Clean(strings.TrimPrefix(strings.TrimSpace(f), "./"))
		if f == "." || f == "" {
			continue
		}
		if !strings.HasSuffix(f, ".md") && !inPackage(f, byDir, direct) {
			return []string{all}
		}
	}
	if len(direct) == 0 {
		return nil // documentation-only change: nothing to test
	}
	// Packages whose (non-test) dependency closure contains a changed package.
	affected := map[string]bool{}
	for _, p := range pkgs {
		if direct[p.ImportPath] || anyIn(p.Deps, direct) {
			affected[p.ImportPath] = true
		}
	}
	// Plus packages whose tests import an affected package.
	for _, p := range pkgs {
		if anyIn(p.TestImports, affected) || anyIn(p.XTestImports, affected) {
			affected[p.ImportPath] = true
		}
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
		if d == dir || strings.HasPrefix(dir, d+"/testdata") {
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
