package ci_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func parseExtractSource(t *testing.T, name string) *ast.File {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	path := filepath.Join(filepath.Dir(here), "..", "internal", "extract", name)
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func namedFunction(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("function %s not found", name)
	return nil
}

func TestNestedMIMEUsesSharedDispatcher(t *testing.T) {
	file := parseExtractSource(t, "nested.go")
	extractChild := namedFunction(t, file, "extractChild")
	isDepthCarrier := namedFunction(t, file, "isDepthCarrier")

	fromMIMECalls := 0
	ast.Inspect(extractChild.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "fromMIME" {
			fromMIMECalls++
		}
		return true
	})
	if fromMIMECalls != 1 {
		t.Fatalf("extractChild calls fromMIME %d times, want exactly once", fromMIMECalls)
	}

	classifiesDepthCarrier := false
	ast.Inspect(isDepthCarrier.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "classifyMIMEMessage" {
			classifiesDepthCarrier = true
		}
		return true
	})
	if !classifiesDepthCarrier {
		t.Fatal("isDepthCarrier does not recognize bounded MIME headers")
	}
}

func TestDecryptedOOXMLReentersSharedZipPipeline(t *testing.T) {
	fn := namedFunction(t, parseExtractSource(t, "defaultpw.go"), "fromDefaultPWOOXML")
	fromZipCalls := 0
	fromOOXMLCalls := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		switch id.Name {
		case "fromOOXML":
			fromOOXMLCalls++
		case "fromZip":
			fromZipCalls++
			if len(call.Args) != 7 {
				t.Errorf("fromZip argument count=%d, want 7", len(call.Args))
				return true
			}
			for i, want := range map[int]string{2: "b", 3: "depth", 4: "deadline"} {
				arg, ok := call.Args[i].(*ast.Ident)
				if !ok || arg.Name != want {
					t.Errorf("fromZip argument %d does not preserve %s", i, want)
				}
			}
			selector, ok := call.Args[5].(*ast.SelectorExpr)
			if !ok {
				t.Error("fromZip does not preserve request child options")
			} else if base, baseOK := selector.X.(*ast.Ident); !baseOK || base.Name != "res" || selector.Sel.Name != "childOpts" {
				t.Error("fromZip does not preserve request child options")
			}
			last, ok := call.Args[6].(*ast.Ident)
			if !ok || last.Name != "true" {
				t.Error("decrypted ZIP must retain top-level parse-failure semantics")
			}
		}
		return true
	})
	if fromZipCalls != 2 || fromOOXMLCalls != 0 {
		t.Fatalf("fromDefaultPWOOXML calls fromZip=%d fromOOXML=%d, want 2/0", fromZipCalls, fromOOXMLCalls)
	}
}
