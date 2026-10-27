package extractionbudget_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type p16gSink struct {
	path        string
	function    string
	field       string
	payload     string
	disposition string
}

type p16gInventorySite struct {
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Function    string `json:"function"`
	Kind        string `json:"kind"`
	Expression  string `json:"expression"`
	Disposition string `json:"disposition"`
}

var p16gTransfers = map[string]bool{
	"internal/extract/extract.go:finalizeStreams:Markers:markers":                 true,
	"internal/extract/extract.go:finalizeStreams:Streams:content":                 true,
	"internal/extract/extract.go:fromOLE:Streams:codes(res, mods, res.Streams)":   true,
	"internal/extract/extract.go:fromOOXMLZip:Streams:out":                        true,
	"internal/extract/ppt.go:pptExtractEOS:Streams:codes(res, mods, res.Streams)": true,
}

func p16gNodeString(fset *token.FileSet, node ast.Node) string {
	var out bytes.Buffer
	if err := printer.Fprint(&out, fset, node); err != nil {
		panic(err)
	}
	return out.String()
}

func p16gSelectorField(expr ast.Expr) (string, bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	switch sel.Sel.Name {
	case "Streams", "Markers", "VBAStreams", "MIMEAttachments":
		return sel.Sel.Name, true
	default:
		return "", false
	}
}

func p16gAppendPayloads(fset *token.FileSet, expr ast.Expr) ([]string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) < 2 {
		return nil, false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "append" {
		return nil, false
	}
	payloads := make([]string, 0, len(call.Args)-1)
	for _, arg := range call.Args[1:] {
		payloads = append(payloads, p16gNodeString(fset, arg))
	}
	return payloads, true
}

func p16gLocalOut(expr ast.Expr) bool {
	switch out := expr.(type) {
	case *ast.Ident:
		return out.Name == "out"
	case *ast.StarExpr:
		ident, ok := out.X.(*ast.Ident)
		return ok && ident.Name == "out"
	default:
		return false
	}
}

func p16gPayload(function, payload string) string {
	if payload == "fields" {
		switch function {
		case "fromOfficeZipCarriersZip", "fromSettingContent", "emitZipMember":
			return "field"
		}
	}
	return payload
}

func p16gSourceClosure(t *testing.T) ([]p16gSink, map[string]int, []p16gInventorySite) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source-closure test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	paths, err := filepath.Glob(filepath.Join(root, "internal", "extract", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var sinks []p16gSink
	var inventory []p16gInventorySite
	registrations := make(map[string]int)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			signature := p16gNodeString(fset, fn.Type)
			addInventory := func(node ast.Node, kind, disposition string) {
				inventory = append(inventory, p16gInventorySite{
					Path: rel, Line: fset.Position(node.Pos()).Line, Function: fn.Name.Name,
					Kind: kind, Expression: p16gNodeString(fset, node), Disposition: disposition,
				})
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch n := node.(type) {
				case *ast.AssignStmt:
					for i, lhs := range n.Lhs {
						if i >= len(n.Rhs) {
							continue
						}
						field, retained := p16gSelectorField(lhs)
						if !retained {
							continue
						}
						rhs := p16gNodeString(fset, n.Rhs[i])
						payloads, appended := p16gAppendPayloads(fset, n.Rhs[i])
						switch field {
						case "Streams":
							if appended {
								addInventory(n, "result_assignment", "debit")
								for _, payload := range payloads {
									sinks = append(sinks, p16gSink{rel, fn.Name.Name, field, p16gPayload(fn.Name.Name, payload), "debit"})
								}
							} else {
								key := strings.Join([]string{rel, fn.Name.Name, field, rhs}, ":")
								if !p16gTransfers[key] {
									t.Errorf("unregistered Streams transfer %s", key)
								}
								sinks = append(sinks, p16gSink{rel, fn.Name.Name, field, rhs, "transfer"})
								addInventory(n, "result_assignment", "transfer")
							}
						case "Markers":
							key := strings.Join([]string{rel, fn.Name.Name, field, rhs}, ":")
							if !p16gTransfers[key] {
								t.Errorf("unregistered Markers transfer %s", key)
							}
							sinks = append(sinks, p16gSink{rel, fn.Name.Name, field, rhs, "transfer"})
							addInventory(n, "result_assignment", "transfer")
						case "VBAStreams":
							if fn.Name.Name != "codes" || !appended || len(payloads) != 1 || payloads[0] != "b" {
								t.Errorf("unregistered VBA alias %s:%s:%s", rel, fn.Name.Name, rhs)
							}
							sinks = append(sinks, p16gSink{rel, fn.Name.Name, field, "b", "alias"})
							addInventory(n, "result_assignment", "alias")
						case "MIMEAttachments":
							if fn.Name.Name != "walkMIMEEntity" || !appended || len(payloads) != 1 || payloads[0] != "data" {
								t.Errorf("unregistered MIME attachment %s:%s:%s", rel, fn.Name.Name, rhs)
							}
							sinks = append(sinks, p16gSink{rel, fn.Name.Name, field, "data", "attachment"})
							addInventory(n, "result_assignment", "attachment")
						}
					}
				case *ast.CallExpr:
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
						switch {
						case sel.Sel.Name == "recordRetained" && len(n.Args) == 1:
							key := strings.Join([]string{rel, fn.Name.Name, p16gNodeString(fset, n.Args[0])}, ":")
							registrations[key]++
						case sel.Sel.Name == "admitStream" && len(n.Args) == 2 && fn.Name.Name != "appendOut" && fn.Name.Name != "appendMarkerOut":
							// appendOut appends to a caller-chosen local slice, not a retained field.
							// P17b whole-entry admission: admitStream(&x, own) debits x,
							// and the helper form admitStream(p, own) debits *p.
							payload := "*" + p16gNodeString(fset, n.Args[0])
							if u, ok := n.Args[0].(*ast.UnaryExpr); ok && u.Op == token.AND {
								payload = p16gNodeString(fset, u.X)
							}
							registrations[strings.Join([]string{rel, fn.Name.Name, payload}, ":")]++
						case sel.Sel.Name == "admitReserve" && len(n.Args) == 0 && fn.Name.Name == "finalizeStreams":
							// The retained-bytes marker is the one entry admitted from
							// the reserve rather than from ordinary headroom.
							registrations[strings.Join([]string{rel, fn.Name.Name, "[]byte(capHitMarkerPrefix + retainedBytesKind)"}, ":")]++
						}
					}
					ident, isAppend := n.Fun.(*ast.Ident)
					if !isAppend || ident.Name != "append" {
						break
					}
					disposition := "temporary-or-bookkeeping"
					if field, retained := p16gSelectorField(n.Args[0]); retained {
						switch field {
						case "Streams":
							disposition = "emission-call"
						case "Markers":
							disposition = "marker-emission-call"
						case "VBAStreams":
							disposition = "alias-call"
						case "MIMEAttachments":
							disposition = "attachment-call"
						}
					} else if p16gLocalOut(n.Args[0]) && strings.Contains(signature, "Result") {
						disposition = "local-output-emission"
					} else if fn.Name.Name == "splitPureMarkers" {
						disposition = "promotion-transfer-call"
					}
					addInventory(n, "append", disposition)
					if disposition != "local-output-emission" || len(n.Args) < 2 {
						break
					}
					for _, arg := range n.Args[1:] {
						payload := p16gPayload(fn.Name.Name, p16gNodeString(fset, arg))
						sinks = append(sinks, p16gSink{rel, fn.Name.Name, "local-output", payload, "debit"})
					}
				case *ast.CompositeLit:
					if n.Type != nil && strings.HasPrefix(p16gNodeString(fset, n.Type), "[][]byte") {
						addInventory(n, "slice_batch", "temporary-batch-literal")
					}
				}
				return true
			})
		}
	}
	sort.Slice(inventory, func(i, j int) bool {
		a, b := inventory[i], inventory[j]
		return fmt.Sprintf("%s:%08d:%s:%s", a.Path, a.Line, a.Kind, a.Expression) <
			fmt.Sprintf("%s:%08d:%s:%s", b.Path, b.Line, b.Kind, b.Expression)
	})
	return sinks, registrations, inventory
}

func TestP16gSourceClosure(t *testing.T) {
	sinks, registrations, inventory := p16gSourceClosure(t)
	counts := make(map[string]int)
	debits := make(map[string]int)
	for _, sink := range sinks {
		counts[sink.disposition]++
		if sink.disposition == "debit" || sink.disposition == "attachment" {
			key := strings.Join([]string{sink.path, sink.function, sink.payload}, ":")
			debits[key]++
		}
	}
	wantCounts := map[string]int{"debit": 7, "attachment": 1, "alias": 1, "transfer": 5}
	if fmt.Sprint(counts) != fmt.Sprint(wantCounts) {
		t.Errorf("source sink inventory counts=%v want=%v", counts, wantCounts)
	}
	var mismatches []string
	for key, want := range debits {
		if got := registrations[key]; got != want {
			mismatches = append(mismatches, fmt.Sprintf("%s registrations=%d sinks=%d", key, got, want))
		}
		delete(registrations, key)
	}
	for key, count := range registrations {
		mismatches = append(mismatches, fmt.Sprintf("%s registrations=%d sinks=0", key, count))
	}
	sort.Strings(mismatches)
	if len(mismatches) != 0 {
		t.Fatalf("retained source closure mismatch:\n%s", strings.Join(mismatches, "\n"))
	}
	if len(inventory) != 211 {
		t.Fatalf("complete AST inventory sites=%d want=211", len(inventory))
	}
	inventoryCounts := make(map[string]int)
	for _, site := range inventory {
		if site.Disposition == "" {
			t.Fatalf("undisposed AST site: %+v", site)
		}
		inventoryCounts[site.Disposition]++
	}
	wantInventoryCounts := map[string]int{
		"alias": 1, "alias-call": 1, "attachment": 1, "attachment-call": 1,
		"debit": 7, "emission-call": 7,
		"promotion-transfer-call": 2, "temporary-batch-literal": 2,
		"temporary-or-bookkeeping": 184, "transfer": 5,
	}
	if !maps.Equal(inventoryCounts, wantInventoryCounts) {
		t.Fatalf("AST disposition counts=%v want=%v", inventoryCounts, wantInventoryCounts)
	}
	t.Logf("complete AST inventory dispositions=%v", inventoryCounts)
	if path := os.Getenv("P16G_INVENTORY_PATH"); path != "" {
		data, err := json.MarshalIndent(inventory, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, '\n')
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
