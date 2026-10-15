package extractionbudget_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// p17dReserve is D, the exact length of the diagnostic retained-bytes marker
// that every enforcing ledger holds back from ordinary admissions.
const p17dReserve = len("EXTRACT-CAP-HIT kind=retained-bytes")

// TestP17dEnforcedEmittersNeverExceedCeiling sweeps the whole P16 fixture
// corpus (text/decoder, structural, MIME, archive, marker and OOXML emitters)
// across a ladder of ceilings. For every fixture and ceiling the independent
// final-output sum must equal the recorded ledger and stay within E, so one
// emitter that bypasses whole-entry admission fails its owning fixture.
func TestP17dEnforcedEmittersNeverExceedCeiling(t *testing.T) {
	cases := p16gCases(t)
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	ceilings := []int64{int64(p17dReserve), int64(p17dReserve) + 1, 40, 48, 64, 96, 128, 192, 256, 512, 1024, 4096}
	truncatedSomewhere := 0
	for _, name := range names {
		run := cases[name]
		t.Run(name, func(t *testing.T) {
			full := run()
			fullBytes, _ := p16gIndependentBytes(full)
			if fullBytes == 0 || full.RetainedTruncated {
				t.Fatalf("below-budget fixture must be complete: bytes=%d truncated=%v", fullBytes, full.RetainedTruncated)
			}
			for _, e := range ceilings {
				res := func() extract.Result {
					defer extract.SetDefaultRetainedBytesLimitForTest(e)()
					return run()
				}()
				got, _ := p16gIndependentBytes(res)
				if uint64(got) > uint64(e) {
					t.Fatalf("E=%d: final output %d bytes exceeds the ceiling (an emitter bypassed admission)", e, got)
				}
				if res.Retained.Bytes() != got {
					t.Fatalf("E=%d: ledger=%d independent final bytes=%d", e, res.Retained.Bytes(), got)
				}
				if uint64(e) >= uint64(fullBytes)+uint64(p17dReserve) && res.RetainedTruncated {
					t.Fatalf("E=%d >= complete size %d but result truncated", e, fullBytes+uint64(p17dReserve))
				}
				if res.RetainedTruncated {
					truncatedSomewhere++
				}
			}
		})
	}
	if truncatedSomewhere == 0 {
		t.Fatal("no fixture was ever truncated: sweep does not exercise enforcement")
	}
}

// TestP17dBelowBudgetBytesIdentical pins that an explicit ceiling at the
// complete size reproduces the default-ceiling Result byte for byte.
func TestP17dBelowBudgetBytesIdentical(t *testing.T) {
	for name, run := range p16gCases(t) {
		t.Run(name, func(t *testing.T) {
			base := run()
			bytesNeeded, _ := p16gIndependentBytes(base)
			exact := func() extract.Result {
				defer extract.SetDefaultRetainedBytesLimitForTest(int64(bytesNeeded) + int64(p17dReserve))()
				return run()
			}()
			if p16dResultDigest(t, base) != p16dResultDigest(t, exact) {
				t.Fatal("result changed when the ceiling was set to the complete size")
			}
		})
	}
}

// p17dInventory collects the enforced emission call sites in internal/extract
// (file:function:helper -> count); p17dEmitterWant pins them so a new emitter
// must be added deliberately. A raw append of a retained field is rejected
// separately by TestP16gSourceClosure (unregistered sink).
func p17dInventory(t *testing.T) map[string]int {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	paths, err := filepath.Glob(filepath.Join(root, "internal", "extract", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	helpers := map[string]bool{"appendStream": true, "appendStreamOwned": true, "appendOut": true, "appendStreams": true, "admitStream": true}
	counts := make(map[string]int)
	fset := token.NewFileSet()
	for _, path := range paths {
		base := filepath.Base(path)
		if strings.HasSuffix(base, "_test.go") || base == "retained.go" {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && helpers[sel.Sel.Name] {
					counts[base+":"+fn.Name.Name+":"+sel.Sel.Name]++
				}
				return true
			})
		}
	}
	return counts
}

func TestP17dEmitterInventoryPinned(t *testing.T) {
	counts := p17dInventory(t)
	total := 0
	var bad []string
	for key, n := range counts {
		total += n
		if want, ok := p17dEmitterWant[key]; !ok || want != n {
			bad = append(bad, key)
		}
	}
	for key := range p17dEmitterWant {
		if _, ok := counts[key]; !ok {
			bad = append(bad, key)
		}
	}
	sort.Strings(bad)
	if len(bad) != 0 {
		t.Fatalf("enforced emitter inventory drifted (call sites=%d): %v", total, bad)
	}
}

var p17dEmitterWant = map[string]int{
	"archive.go:emitMember:appendStreamOwned":               1,
	"archive.go:fromOfficeZipCarriersZip:appendStreamOwned": 1,
	"archive.go:fromOfficeZipCarriersZip:appendStreams":     1,
	"archive.go:markEncryptedArchive:appendStream":          1,
	"archivepw.go:markDecryptedArchive:appendStream":        1,
	"biff12_xlsb.go:scanXLSBSupBookDDE:appendOut":           1,
	"binanalyze.go:analyzeBinaries:appendStream":            1,
	"cab.go:unpackCab:appendStream":                         1,
	"csv_dde.go:emitIfCSVDDE:appendStream":                  1,
	"decode.go:decodeSourceTree:appendStream":               1,
	"decode.go:decodeSourceTree:appendStreamOwned":          1,
	"decode.go:fromEncoded:appendStream":                    1,
	"decode.go:fromEncoded:appendStreamOwned":               3,
	"defaultpw.go:emitDefaultPWMarker:appendStream":         1,
	"docprops.go:fromOLEDocProps:appendStream":              3,
	"docprops.go:fromOLEDocProps:appendStreamOwned":         1,
	"docprops.go:fromOOXMLDocProps:appendOut":               2,
	"encsig.go:fromOLEDigSig:appendStream":                  1,
	"encsig.go:fromOLEEncInfo:appendStream":                 1,
	"encsig.go:fromOLEEncType:appendStream":                 1,
	"encsig.go:fromPPTEncryptedSummary:appendStream":        1,
	"encsig.go:fromWordFibEncryption:appendStream":          1,
	"extract.go:appendOLEIDMarker:appendOut":                1,
	"extract.go:codes:appendOut":                            1,
	"extract.go:finalizeStreams:appendStream":               3,
	"extract.go:fromMSG:appendStreamOwned":                  1,
	"extract.go:fromMSI:appendStreamOwned":                  1,
	"extract.go:fromOLEExtraData:appendStream":              2,
	"extract.go:fromOOXMLRels:appendOut":                    2,
	"extract.go:parseDDEFields:appendOut":                   1,
	"html.go:fromHTMLSmuggling:admitStream":                 2,
	"html.go:fromHTMLSmuggling:appendStream":                6,
	"launcher.go:fromSettingContent:appendStreams":          1,
	"launcher.go:fromURLShortcut:appendStream":              1,
	"lnk.go:fromLNK:appendStreamOwned":                      1,
	"mime.go:emitMIMEPart:admitStream":                      1,
	"mime.go:walkMIMEEntity:admitStream":                    1,
	"msix.go:emitZipMember:appendStreams":                   1,
	"ole2link.go:fromOLE2Link:appendStream":                 1,
	"oledir.go:fromOLEOrphans:appendStreamOwned":            1,
	"oleid.go:fromOLEIndicators:appendStream":               2,
	"olepackage.go:fromOLEPackage:appendStream":             1,
	"oletimes.go:fromOLETimes:appendStream":                 2,
	"onenote.go:fromOneNote:appendStream":                   1,
	"pdf.go:fromPDF:appendStreamOwned":                      2,
	"pdf.go:fromPDFIndicators:appendStream":                 1,
	"pecarve.go:carveEmbeddedPEs:appendStream":              2,
	"polyglot.go:fromPolyglot:appendStream":                 1,
	"ppt.go:emitPPTVBAMarkerIfProduced:appendStream":        1,
	"rtf.go:carveRTFObject:appendStream":                    1,
	"rtf.go:detectRTFDDE:appendStream":                      2,
	"rtf.go:fromRTF:appendStream":                           1,
	"script.go:fromEncodedScript:appendStream":              1,
	"slk.go:fromSLK:appendStream":                           1,
	"stomping.go:detectStompingModules:appendStream":        1,
	"tnef.go:fromTNEF:appendStream":                         1,
	"userform.go:fromUserForms:appendStream":                1,
	"userform.go:fromUserForms:appendStreamOwned":           1,
	"xll.go:fromXLL:appendStream":                           1,
	"xlm.go:fromOOXMLXLM:appendOut":                         1,
	"xlm.go:scanBIFFXLMStream:appendStream":                 3,
	"xlm_fold.go:emitDangerousMarkers:appendOut":            1,
	"xlm_fold.go:emitFoldedFormula:appendOut":               1,
}
