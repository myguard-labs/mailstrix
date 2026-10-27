package ci_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultPWOOXMLDerivesEachCandidateOnce(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	path := filepath.Join(filepath.Dir(here), "..", "internal", "extract", "defaultpw.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	counts := make(map[string]int)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "fromDefaultPWOOXML" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok {
				counts[ident.Name]++
			}
			return true
		})
	}

	for _, name := range []string{"agilePasswordHash", "standardMakeKey"} {
		if counts[name] != 1 {
			t.Errorf("fromDefaultPWOOXML calls %s %d times, want exactly once", name, counts[name])
		}
	}
	for _, name := range []string{"agileVerifyPW", "agileExtractKey", "standardVerifyPW", "standardDecrypt"} {
		if counts[name] != 0 {
			t.Errorf("fromDefaultPWOOXML calls re-deriving wrapper %s %d times", name, counts[name])
		}
	}
}
