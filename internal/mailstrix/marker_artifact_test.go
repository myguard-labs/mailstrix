package mailstrix

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	yara "github.com/hillu/go-yara/v4"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func markerArtifactFixture(t testing.TB) string {
	t.Helper()
	archive, e := zip.OpenReader("../../ci/testdata/marker-runtime.zip")
	if e != nil {
		t.Fatalf("native marker fixture unavailable; run python3 ci/prepare_marker_runtime.py before local Go tests: %v", e)
	}
	defer archive.Close()
	root := t.TempDir()
	var total uint64
	for _, entry := range archive.File {
		if entry.Mode()&os.ModeSymlink != 0 || entry.FileInfo().IsDir() || filepath.IsAbs(entry.Name) || filepath.ToSlash(filepath.Clean(entry.Name)) != entry.Name || strings.HasPrefix(entry.Name, "../") {
			t.Fatalf("invalid fixture entry: %q", entry.Name)
		}
		if entry.UncompressedSize64 > (16<<20)-total {
			t.Fatal("fixture exceeds total size bound")
		}
		total += entry.UncompressedSize64
		path := filepath.Join(root, filepath.FromSlash(entry.Name))
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		reader, e := entry.Open()
		if e != nil {
			t.Fatal(e)
		}
		data, e := io.ReadAll(io.LimitReader(reader, 16<<20))
		closeError := reader.Close()
		if e == nil {
			e = closeError
		}
		if e == nil && uint64(len(data)) != entry.UncompressedSize64 {
			t.Fatal("fixture entry size mismatch")
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	var b markerBinding
	if _, e = markerReadJSON(filepath.Join(root, "marker-artifact/binding.json"), &b); e != nil {
		t.Fatal(e)
	}
	priorLibrary, priorCompiler, priorVersion := markerRuntimeLibYaraSHA256, markerRuntimeCompilerSHA256, markerRuntimeVersion
	markerRuntimeLibYaraSHA256 = b.ABI["libyara"].SHA256
	markerRuntimeCompilerSHA256 = b.ABI["compiler"].SHA256
	markerRuntimeVersion = b.Versions["libyara"]
	t.Cleanup(func() {
		markerRuntimeLibYaraSHA256 = priorLibrary
		markerRuntimeCompilerSHA256 = priorCompiler
		markerRuntimeVersion = priorVersion
	})
	return root
}
func markerFixtureScanner(t *testing.T, root string, deny map[string]struct{}) *Scanner {
	t.Helper()
	s, e := NewScanner(&Config{RulesPath: filepath.Join(root, "compiled.yac"), RuleDenylist: deny}, func(string, ...any) {})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func markerFixtureReplaceMain(t *testing.T, s *Scanner, source string) {
	t.Helper()
	r, e := compileDir(writeRules(t, source), func(string, ...any) {})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Destroy()
	if e = r.Save(s.srcFile); e != nil {
		t.Fatal(e)
	}
}
func markerArtifactMatches(t *testing.T, s *Scanner) []Match {
	t.Helper()
	out, e := s.Scan([]byte(`{\rtf1 harmless}`), ScanMeta{Filename: "enabled", Extension: ".jpg"})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestP12MatchedArtifactSelection(t *testing.T) {
	root := markerArtifactFixture(t)
	for _, deny := range []map[string]struct{}{nil, {"privatedependency": {}, "gate": {}, "publicdependency": {}, "markerfilename": {}}} {
		s := markerFixtureScanner(t, root, deny)
		if s.markerRules.Load() == nil || s.markerRules.Load() == s.rules.Load() || len(s.markerRules.Load().GetRules()) != 9 || len(s.rules.Load().GetRules()) != 10 {
			t.Fatal("matched authoritative narrow marker artifact missing or inventory differs")
		}
		got := markerArtifactMatches(t, s)
		lease := s.acquireScanLease()
		generation := scannerGeneration{rules: s.rules.Load(), deny: s.denylist.Load()}
		full, e := s.scanGeneration([]byte(`{\rtf1 harmless}`), ScanMeta{Filename: "enabled", Extension: ".jpg"}, generation)
		lease.release()
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(got, full) {
			t.Fatalf("narrow/full-main channel+deny parity: got=%v full=%v", got, full)
		}
		names := ruleNames(got)
		if !strings.Contains(names, "MarkerPrivate") || !strings.Contains(names, "Marker") {
			t.Fatalf("private/global dependency detection lost: %v", got)
		}
		if deny == nil && !strings.Contains(names, "MarkerPublic") {
			t.Fatalf("public dependency/external marker lost: %v", got)
		}
		if deny != nil && (strings.Contains(names, "MarkerPublic") || strings.Contains(names, "MarkerFilename")) {
			t.Fatalf("public deny dependency or post-match filtering lost: %v", got)
		}
		s.Close()
	}
}
func TestP12ArtifactFallbacks(t *testing.T) {
	for _, kind := range []string{"absent", "corrupt-marker", "corrupt-binding", "corrupt-graph", "missing-file", "extra-file", "symlink", "version", "library", "compiler", "external", "inventory", "closure", "include", "descriptor", "module", "unknown-build", "metadata-absent", "metadata-tamper", "metadata-sources-hash", "metadata-invalid-json", "metadata-array", "metadata-row", "metadata-field", "metadata-valid-types"} {
		t.Run(kind, func(t *testing.T) {
			root := markerArtifactFixture(t)
			bindingPath := filepath.Join(root, "marker-artifact/binding.json")
			var b markerBinding
			_, e := markerReadJSON(bindingPath, &b)
			if e != nil {
				t.Fatal(e)
			}
			write := func(p string, data []byte) {
				t.Helper()
				if e = os.WriteFile(filepath.Join(root, p), data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "metadata-absent":
				if e = os.Remove(filepath.Join(root, "libyara.version")); e != nil {
					t.Fatal(e)
				}
			case "metadata-tamper":
				write("libyara.version", []byte("0.0.0\n"))
			case "metadata-sources-hash":
				write("sources.json", []byte("[{}]"))
			case "metadata-invalid-json":
				write("sources.json", []byte("{"))
			case "metadata-array", "metadata-row", "metadata-field", "metadata-valid-types":
				data := []byte(`{}`)
				switch kind {
				case "metadata-row":
					data = []byte(`[null]`)
				case "metadata-field":
					data = []byte(`[{"name":1}]`)
				case "metadata-valid-types":
					data = []byte(`[{"name":"fixture","repo":null,"extra":42}]`)
					markerRuntimeCompilerSHA256 = strings.Repeat("0", 64)
				}
				write("sources.json", data)
				var index markerIndex
				if _, e = markerReadJSON(filepath.Join(root, "compiler-inputs/index.json"), &index); e != nil {
					t.Fatal(e)
				}
				index.Metadata["sources.json"] = markerBytesIdentity(data)
				data, e = json.Marshal(index)
				if e != nil {
					t.Fatal(e)
				}
				write("compiler-inputs/index.json", data)
			case "absent":
				if e = os.RemoveAll(filepath.Join(root, "marker-artifact")); e != nil {
					t.Fatal(e)
				}
			case "corrupt-marker":
				write("marker-artifact/markers.yac", []byte("truncated"))
			case "corrupt-binding":
				write("marker-artifact/binding.json", []byte("{"))
			case "corrupt-graph":
				write("compiler-inputs/main/manifest.json", []byte("{}"))
			case "missing-file":
				if e = os.Remove(filepath.Join(root, "marker-artifact/main.descriptors")); e != nil {
					t.Fatal(e)
				}
			case "extra-file":
				write("marker-artifact/extra", nil)
			case "symlink":
				p := filepath.Join(root, "marker-artifact/main.descriptors")
				if e = os.Remove(p); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink("marker.descriptors", p); e != nil {
					t.Fatal(e)
				}
			case "version":
				b.Versions["yarac"] = "0.0.0"
			case "library":
				markerRuntimeLibYaraSHA256 = strings.Repeat("0", 64)
			case "compiler":
				markerRuntimeCompilerSHA256 = strings.Repeat("0", 64)
			case "external":
				b.Externals[6].Value = json.RawMessage("false")
			case "inventory":
				b.MarkerInventory[0].Identifier = "changed"
			case "closure":
				b.Closure.Retained = []int{}
			case "include":
				b.Includes = []markerObserved{{Path: "invalid"}}
			case "descriptor":
				b.MarkerDescriptors.Rules[0].Lines[0] = "R\tchanged"
			case "module":
				b.ModuleIdentity = map[string]markerFingerprint{}
			case "unknown-build":
				markerRuntimeLibYaraSHA256 = ""
			}
			// Rebind the envelope hash for semantic corruption cases so the real
			// binding validator, rather than just its outer hash guard, owns the red.
			if kind == "version" || kind == "external" || kind == "inventory" || kind == "closure" || kind == "include" || kind == "descriptor" || kind == "module" {
				data, e := json.Marshal(b)
				if e != nil {
					t.Fatal(e)
				}
				write("marker-artifact/binding.json", data)
				var index markerIndex
				if _, e = markerReadJSON(filepath.Join(root, "compiler-inputs/index.json"), &index); e != nil {
					t.Fatal(e)
				}
				index.Marker.Files["binding.json"] = markerBytesIdentity(data)
				data, e = json.Marshal(index)
				if e != nil {
					t.Fatal(e)
				}
				write("compiler-inputs/index.json", data)
			}
			main, fp, e := readRulesSnapshot(filepath.Join(root, "compiled.yac"))
			if e != nil {
				t.Fatal(e)
			}
			artifact, _, e := loadMarkerArtifact(root, main, fp)
			main.Destroy()
			if e == nil {
				if artifact != nil {
					artifact.Destroy()
				}
				t.Fatalf("fallback fixture did not reach rejecting guard: %s", kind)
			}
			if kind == "metadata-valid-types" && e.Error() != "linked compiler/library ABI mismatch" {
				t.Fatalf("valid metadata did not reach ABI guard: %v", e)
			}
			t.Logf("fallback guard %s: %v", kind, e)
			s := markerFixtureScanner(t, root, nil)
			if s.markerRules.Load() != nil || s.markerContent != "" {
				t.Fatal("unmatched artifact published instead of nil/full-main fallback")
			}
			if names := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(names, "MarkerPrivate") || !strings.Contains(names, "MarkerPublic") {
				t.Fatalf("fallback lost dependent markers: %s", names)
			}
		})
	}
}
func TestP12ArtifactReloadAndShutdown(t *testing.T) {
	root := markerArtifactFixture(t)
	s := markerFixtureScanner(t, root, nil)
	main, marker := s.rules.Load(), s.markerRules.Load()
	if marker == nil {
		t.Fatal("authoritative marker missing")
	}
	mo := p8Owner(t, s, marker)
	old := s.acquireScanLease()
	defer old.release()
	if e := os.WriteFile(s.srcFile, []byte("malformed"), 0600); e != nil {
		t.Fatal(e)
	}
	identity := s.Fingerprint()
	if e := s.Reload(); e == nil {
		t.Fatal("malformed main unexpectedly loaded")
	}
	if s.rules.Load() != main || s.markerRules.Load() != marker || s.Fingerprint() != identity {
		t.Fatal("failed whole reload changed old generation")
	}
	markerFixtureReplaceMain(t, s, `global rule Gate { condition: true } private rule Dependency { condition: true } rule NewMarker : marker { strings: $a="EXT-MISMATCH" condition: $a and Dependency }`)
	if e := s.Reload(); e != nil {
		t.Fatal(e)
	}
	if s.markerRules.Load() != nil || s.markerContent != "" {
		t.Fatal("successful unmatched new-main reload retained old marker")
	}
	if names := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(names, "NewMarker") || strings.Contains(names, "MarkerPrivate") {
		t.Fatalf("new fallback verdict lost: %s", names)
	}
	p7Alive(t, mo, "pinned old marker")
	if out, e := old.scan([]byte(`{\rtf1 harmless}`), ScanMeta{Filename: "enabled", Extension: ".jpg"}); e != nil || !strings.Contains(ruleNames(out), "MarkerPrivate") {
		t.Fatalf("old pinned generation lost marker: %v %v", out, e)
	}
	s.Close()
	p7Alive(t, mo, "close pinned old marker")
	old.release()
	p7Dead(t, mo)
	if _, e := s.Scan([]byte("closed"), ScanMeta{}); e != ErrScannerClosed {
		t.Fatalf("shutdown scan: %v", e)
	}
}
func TestP12PreparedMainSnapshot(t *testing.T) {
	root := markerArtifactFixture(t)
	path := filepath.Join(root, "compiled.yac")
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	replacementRules, e := compileDir(writeRules(t, `rule NewMarker : marker { strings: $a="EXT-MISMATCH" condition: $a }`), func(string, ...any) {})
	if e != nil {
		t.Fatal(e)
	}
	var replacement bytes.Buffer
	if e = replacementRules.Write(&replacement); e != nil {
		t.Fatal(e)
	}
	replacementRules.Destroy()
	load := markerMainSnapshot
	defer func() { markerMainSnapshot = load }()
	markerMainSnapshot = func(path string) (*yara.Rules, markerFingerprint, error) {
		r, fp, e := load(path)
		if e == nil {
			if e = os.WriteFile(path, replacement.Bytes(), 0600); e != nil {
				r.Destroy()
				return nil, fp, e
			}
		}
		return r, fp, e
	}
	s, e := NewScanner(&Config{RulesPath: path}, func(string, ...any) {})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	identity := markerBytesIdentity(original)
	if s.preparedMainIdentity != identity || s.markerRules.Load() == nil {
		t.Fatal("artifact identity did not bind exact loaded main snapshot")
	}
	var binding markerBinding
	if _, e = markerReadJSON(filepath.Join(root, "marker-artifact/binding.json"), &binding); e != nil {
		t.Fatal(e)
	}
	mainContent := identity.SHA256 + ":" + denylistHash(nil)
	expected := sha256.Sum256([]byte(mainContent + "\x00big\x00\x00marker\x00" + binding.Marker.SHA256 + ":" + mainContent))
	if got := s.contentFP.Load(); got == nil || *got != hex.EncodeToString(expected[:8]) {
		t.Fatal("published generation/cache identity reopened replaced main path")
	}
	oldFingerprint := s.Fingerprint()
	if names := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(names, "MarkerPrivate") {
		t.Fatalf("snapshot lost marker: %s", names)
	}
	markerMainSnapshot = load
	if e = s.Reload(); e != nil {
		t.Fatal(e)
	}
	if s.Fingerprint() == oldFingerprint || s.markerRules.Load() != nil || s.preparedMainIdentity != markerBytesIdentity(replacement.Bytes()) {
		t.Fatal("actual replacement reload did not update snapshot identity and fallback")
	}
	if names := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(names, "NewMarker") || strings.Contains(names, "MarkerPrivate") {
		t.Fatalf("replacement snapshot scan: %s", names)
	}
}
func TestP12MarkerJSONAndSnapshotErrors(t *testing.T) {
	for _, input := range []string{`{"x":1,"x":2}`, `[1,`, `{} {}`, `true false`, `NaN`, ``} {
		var value any
		if markerJSON([]byte(input), &value) == nil {
			t.Fatalf("malformed JSON accepted: %q", input)
		}
	}
	for _, input := range []string{`{"x":[1,{},null]}`, `true`, `["x"]`} {
		var value any
		if e := markerJSON([]byte(input), &value); e != nil {
			t.Fatal(e)
		}
	}
	root := t.TempDir()
	if _, _, e := readRulesSnapshot(filepath.Join(root, "absent")); e == nil {
		t.Fatal("missing snapshot loaded")
	}
	path := filepath.Join(root, "bad.yac")
	if e := os.WriteFile(path, []byte("truncated"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := readRulesSnapshot(path); e == nil {
		t.Fatal("corrupt native snapshot loaded")
	}
	var value any
	if _, e := markerReadJSON(path, &value); e == nil {
		t.Fatal("invalid JSON file accepted")
	}
	if markerEqual([]string{}, []string(nil)) {
		t.Fatal("JSON array identity collapsed")
	}
}

func TestP12MarkerExternalUpdates(t *testing.T) {
	root := markerArtifactFixture(t)
	s := markerFixtureScanner(t, root, nil)
	rules := s.markerRules.Load()
	if rules == nil {
		t.Fatal("matched marker missing")
	}
	for _, vars := range []scanVars{{}, {vba: true, extension: ".jpg", filename: "enabled"}, {extension: ".msg", fileType: "outlook"}, {}} {
		got, e := s.scanOne(rules, []byte("EXT-MISMATCH"), vars, 0)
		if e != nil {
			t.Fatal(e)
		}
		full, e := s.scanOne(s.rules.Load(), []byte("EXT-MISMATCH"), vars, 0)
		if e != nil {
			t.Fatal(e)
		}
		got = filterMarkerChannel(got, true)
		full = filterMarkerChannel(full, true)
		if !reflect.DeepEqual(got, full) {
			t.Fatalf("external override parity: vars=%+v got=%v full=%v", vars, got, full)
		}
		names := ruleNames(got)
		if strings.Contains(names, "MarkerVBA") != vars.vba || strings.Contains(names, "MarkerFilename") != (vars.extension == ".jpg") {
			t.Fatalf("typed defaults/updates or scanner reset lost: vars=%+v matches=%v", vars, got)
		}
	}
}
func TestP12NativeGraphMalformed(t *testing.T) {
	root := markerArtifactFixture(t)
	var manifest markerManifest
	if _, e := markerReadJSON(filepath.Join(root, "compiler-inputs/main/manifest.json"), &manifest); e != nil {
		t.Fatal(e)
	}
	trace, e := os.ReadFile(filepath.Join(root, "compiler-inputs/main/objects", manifest.Final.Native.SHA256))
	if e != nil {
		t.Fatal(e)
	}
	type frame struct {
		start, name, payload, end int
		kind                      byte
	}
	frames := []frame{}
	for offset := 0; offset < len(trace); {
		start := offset
		nameSize := int(binary.LittleEndian.Uint64(trace[offset+1 : offset+9]))
		size := int(binary.LittleEndian.Uint64(trace[offset+9 : offset+17]))
		offset += 17
		frames = append(frames, frame{start, offset, offset + nameSize, offset + nameSize + size, trace[start]})
		offset += nameSize + size
	}
	find := func(kind byte) frame {
		t.Helper()
		for _, f := range frames {
			if f.kind == kind {
				return f
			}
		}
		t.Fatalf("fixture lacks frame %d", kind)
		return frame{}
	}
	writeRun := func(name string, data []byte, inv markerInvocation) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "trace")
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		if e = markerVerifyNativeGraph(path, inv); e == nil {
			t.Fatalf("native corruption accepted: %s", name)
		}
	}
	for _, length := range []int{0, 1, 16, len(trace) - 1} {
		writeRun(fmt.Sprintf("truncated-%d", length), trace[:length], manifest.Final)
	}
	for _, kind := range []byte{1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15} {
		f := find(kind)
		data := append([]byte(nil), trace...)
		data[f.start] = 255
		writeRun(fmt.Sprintf("unknown-kind-%d", kind), data, manifest.Final)
		if f.end > f.payload {
			data = append([]byte(nil), trace...)
			data[f.payload] ^= 128
			writeRun(fmt.Sprintf("payload-%d", kind), data, manifest.Final)
		}
		if f.payload > f.name {
			data = append([]byte(nil), trace...)
			data[f.name] ^= 128
			writeRun(fmt.Sprintf("name-%d", kind), data, manifest.Final)
		}
		data = append([]byte(nil), trace...)
		binary.LittleEndian.PutUint64(data[f.start+9:f.start+17], ^uint64(0))
		writeRun(fmt.Sprintf("overflow-size-%d", kind), data, manifest.Final)
	}
	// Each malformed structural branch is reached on an actual framed trace.
	truncateName := find(1)
	overflowName := append([]byte(nil), trace...)
	binary.LittleEndian.PutUint64(overflowName[truncateName.start+1:truncateName.start+9], ^uint64(0))
	writeRun("overflow-name-size", overflowName, manifest.Final)
	writeRun("truncated-name", trace[:truncateName.payload-1], manifest.Final)
	truncateSource := find(2)
	writeRun("truncated-source", trace[:truncateSource.end-1], manifest.Final)
	opcode := find(12)
	for _, kind := range []string{"size", "name", "overflow"} {
		data := append([]byte(nil), trace...)
		switch kind {
		case "size":
			binary.LittleEndian.PutUint64(data[opcode.start+9:opcode.start+17], 8)
		case "name":
			binary.LittleEndian.PutUint64(data[opcode.start+1:opcode.start+9], 1)
		case "overflow":
			binary.LittleEndian.PutUint64(data[opcode.payload:opcode.payload+8], ^uint64(0))
		}
		writeRun("opcode-"+kind, data, manifest.Final)
	}
	tag := find(14)
	dataTag := append(append([]byte(nil), trace[:tag.end]...), trace[tag.start:tag.end]...)
	dataTag = append(dataTag, trace[tag.end:]...)
	writeRun("duplicate-tag", dataTag, manifest.Final)
	seal := find(15)
	for _, kind := range []string{"size", "overflow", "after-seal"} {
		data := append([]byte(nil), trace...)
		switch kind {
		case "size":
			binary.LittleEndian.PutUint64(data[seal.start+9:seal.start+17], 31)
		case "overflow":
			binary.LittleEndian.PutUint64(data[seal.payload:seal.payload+8], ^uint64(0))
		case "after-seal":
			data = append(append([]byte(nil), trace[:seal.end]...), trace[tag.start:tag.end]...)
			data = append(data, trace[seal.end:]...)
		}
		writeRun("seal-"+kind, data, manifest.Final)
	}
	begin := find(1)
	doubleBegin := append(append([]byte(nil), trace[:begin.end]...), trace[begin.start:begin.end]...)
	doubleBegin = append(doubleBegin, trace[begin.end:]...)
	writeRun("overlapping-roots", doubleBegin, manifest.Final)
	end := find(9)
	data := append(append([]byte(nil), trace...), trace[end.start:end.end]...)
	writeRun("post-completion", data, manifest.Final)
	start := find(10)
	data = append(append([]byte(nil), trace[:start.end]...), trace[start.start:start.end]...)
	data = append(data, trace[start.end:]...)
	writeRun("duplicate-graph-start", data, manifest.Final)
	inv := manifest.Final
	inv.CompilerVersion = "changed"
	writeRun("manifest-version", trace, inv)
	inv = manifest.Final
	inv.Graph.Complete = false
	writeRun("manifest-incomplete", trace, inv)
	if e = markerVerifyNativeGraph(filepath.Join(root, "missing"), manifest.Final); e == nil {
		t.Fatal("missing native proof accepted")
	}
}
func TestP12GraphAndExternalInvalid(t *testing.T) {
	root := markerArtifactFixture(t)
	var manifest markerManifest
	if _, e := markerReadJSON(filepath.Join(root, "compiler-inputs/main/manifest.json"), &manifest); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"complete", "schema", "summary-count", "tags", "index", "completion", "identifier", "flags", "duplicate", "reference-range", "reference-negative", "reference-namespace"} {
		data, e := json.Marshal(manifest.Final.Graph)
		if e != nil {
			t.Fatal(e)
		}
		var g markerGraph
		if e = markerJSON(data, &g); e != nil {
			t.Fatal(e)
		}
		switch kind {
		case "complete":
			g.Complete = false
		case "schema":
			g.Schema = 2
		case "summary-count":
			g.Summary[0]++
		case "tags":
			g.Summary[3]++
		case "index":
			g.Inventory[0].Index = 100
		case "completion":
			g.Completions[0] = 100
		case "identifier":
			g.Inventory[0].Identifier = ""
		case "flags":
			g.Inventory[0].Flags = 16
		case "duplicate":
			g.Inventory[1].Namespace = g.Inventory[0].Namespace
			g.Inventory[1].Identifier = g.Inventory[0].Identifier
		case "reference-range":
			g.References[0][1] = 100
		case "reference-negative":
			g.References[0][0] = -1
		case "reference-namespace":
			g.Inventory[g.References[0][1]].Namespace = "other"
		}
		if e = markerValidateGraph(g); e == nil {
			t.Fatalf("invalid graph accepted: %s", kind)
		}
	}
	for _, kind := range []string{"count", "order", "int-type", "int-default", "string-type", "string-default"} {
		data, e := json.Marshal(manifest.Externals)
		if e != nil {
			t.Fatal(e)
		}
		var external []markerExternal
		if e = markerJSON(data, &external); e != nil {
			t.Fatal(e)
		}
		switch kind {
		case "count":
			external = nil
		case "order":
			external[0].Name = "changed"
		case "int-type":
			external[6].Type = "boolean"
		case "int-default":
			external[6].Value = json.RawMessage("1")
		case "string-type":
			external[0].Type = "integer"
		case "string-default":
			external[0].Value = json.RawMessage(`"changed"`)
		}
		if e = markerValidateExternals(external); e == nil {
			t.Fatalf("invalid external accepted: %s", kind)
		}
	}
	r, e := compileDir(writeRules(t, "rule Different { condition: true }"), func(string, ...any) {})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Destroy()
	if e = markerNativeInventory(r, manifest.Final.Graph.Inventory); e == nil {
		t.Fatal("native inventory count mismatch accepted")
	}
	if e = markerNativeInventory(r, manifest.Final.Graph.Inventory[:1]); e == nil {
		t.Fatal("native inventory identity mismatch accepted")
	}
}

type markerFailingReader struct {
	io.Reader
	readError, closeError error
}

func (r markerFailingReader) Read(b []byte) (int, error) {
	if r.readError != nil {
		return 0, r.readError
	}
	return r.Reader.Read(b)
}
func (r markerFailingReader) Close() error { return r.closeError }
func TestP12ArtifactIOBoundaries(t *testing.T) {
	root := markerArtifactFixture(t)
	main, identity, e := readRulesSnapshot(filepath.Join(root, "compiled.yac"))
	if e != nil {
		t.Fatal(e)
	}
	defer main.Destroy()
	var index markerIndex
	if _, e = markerReadJSON(filepath.Join(root, "compiler-inputs/index.json"), &index); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"open", "read", "close", "read-json", "read-binding-invalid", "read-main-invalid", "read-marker-invalid", "binding-swap", "main-swap", "marker-swap", "descriptor-read", "descriptor-swap", "marker-read", "marker-hash", "marker-native"} {
		t.Run(kind, func(t *testing.T) {
			open, read, load := markerOpenFile, markerReadFile, markerLoadSnapshot
			defer func() { markerOpenFile = open; markerReadFile = read; markerLoadSnapshot = load }()
			failure := errors.New("injected artifact I/O failure")
			switch kind {
			case "open":
				markerOpenFile = func(string) (io.ReadCloser, error) { return nil, failure }
			case "read", "close":
				markerOpenFile = func(path string) (io.ReadCloser, error) {
					data, e := os.ReadFile(path)
					if e != nil {
						return nil, e
					}
					r := markerFailingReader{Reader: bytes.NewReader(data)}
					if kind == "read" {
						r.readError = failure
					} else {
						r.closeError = failure
					}
					return r, nil
				}
			case "read-json", "read-binding-invalid", "read-main-invalid", "read-marker-invalid", "binding-swap", "main-swap", "marker-swap", "descriptor-read", "descriptor-swap":
				markerReadFile = func(path string) ([]byte, error) {
					target := false
					switch kind {
					case "read-json":
						target = strings.HasSuffix(path, "index.json")
					case "read-binding-invalid", "binding-swap":
						target = strings.HasSuffix(path, "binding.json")
					case "read-main-invalid", "main-swap":
						target = strings.HasSuffix(path, "compiler-inputs/main/manifest.json")
					case "read-marker-invalid", "marker-swap":
						target = strings.HasSuffix(path, "marker-artifact/graph/manifest.json")
					case "descriptor-read", "descriptor-swap":
						target = strings.HasSuffix(path, "marker.descriptors")
					}
					if target {
						if kind == "read-json" || kind == "descriptor-read" {
							return nil, failure
						}
						if strings.HasSuffix(kind, "invalid") {
							return []byte("{"), nil
						}
						data, e := read(path)
						return append(data, ' '), e
					}
					return read(path)
				}
			case "marker-read":
				markerLoadSnapshot = func(string) (*yara.Rules, markerFingerprint, error) { return nil, markerFingerprint{}, failure }
			case "marker-hash":
				markerLoadSnapshot = func(path string) (*yara.Rules, markerFingerprint, error) {
					r, fp, e := load(path)
					fp.SHA256 = strings.Repeat("0", 64)
					return r, fp, e
				}
			case "marker-native":
				markerLoadSnapshot = func(path string) (*yara.Rules, markerFingerprint, error) {
					r, fp, e := load(path)
					if e != nil {
						return nil, fp, e
					}
					r.Destroy()
					replacement, e := compileDir(writeRules(t, "rule Other { condition: true }"), func(string, ...any) {})
					return replacement, fp, e
				}
			}
			if r, _, e := loadMarkerArtifact(root, main, identity); e == nil {
				if r != nil {
					r.Destroy()
				}
				t.Fatalf("I/O/replacement boundary accepted: %s", kind)
			}
		})
	}
	if e = markerVerifyFiles(root, nil); e == nil {
		t.Fatal("empty inventory accepted")
	}
	missing := filepath.Join(root, "missing")
	if _, e = markerReadJSON(missing, &index); e == nil {
		t.Fatal("missing JSON accepted")
	}
	link := filepath.Join(root, "link")
	if e = os.Symlink("compiler-inputs/index.json", link); e != nil {
		t.Fatal(e)
	}
	if _, e = markerReadJSON(link, &index); e == nil {
		t.Fatal("symlink JSON accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if e = os.WriteFile(path, []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = markerVerifyFiles(dir, map[string]markerFingerprint{"file": {SHA256: "bad", Size: 4}}); e == nil {
		t.Fatal("malformed fingerprint accepted")
	}
	if e = os.Mkdir(filepath.Join(dir, "objects"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "objects/wrong"), []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	fp := markerBytesIdentity([]byte("data"))
	if e = markerVerifyFiles(dir, map[string]markerFingerprint{"file": fp, "objects/wrong": fp}); e == nil {
		t.Fatal("object name/hash mismatch accepted")
	}
	for _, input := range []string{`{"incomplete`, `{"key":[`, `{"key":}`} {
		var value any
		if markerJSON([]byte(input), &value) == nil {
			t.Fatalf("malformed nested JSON accepted: %s", input)
		}
	}
}
func TestP12BindingSemanticBoundaries(t *testing.T) {
	root := markerArtifactFixture(t)
	var b markerBinding
	var main, narrow markerManifest
	_, e := markerReadJSON(filepath.Join(root, "marker-artifact/binding.json"), &b)
	if e != nil {
		t.Fatal(e)
	}
	mi, e := markerReadJSON(filepath.Join(root, "compiler-inputs/main/manifest.json"), &main)
	if e != nil {
		t.Fatal(e)
	}
	ni, e := markerReadJSON(filepath.Join(root, "marker-artifact/graph/manifest.json"), &narrow)
	if e != nil {
		t.Fatal(e)
	}
	clone := func(in, out any) {
		t.Helper()
		data, e := json.Marshal(in)
		if e != nil {
			t.Fatal(e)
		}
		if e = markerJSON(data, out); e != nil {
			t.Fatal(e)
		}
	}
	for _, kind := range []string{"manifest-contract", "main-hash", "main-schema", "graph-externals", "graph-complete", "namespace-order", "source-order", "missing-namespace", "projected-inventory", "projected-references", "input-identity", "descriptor-count", "descriptor-identity"} {
		t.Run(kind, func(t *testing.T) {
			var binding markerBinding
			var m, n markerManifest
			clone(b, &binding)
			clone(main, &m)
			clone(narrow, &n)
			switch kind {
			case "manifest-contract":
				m.Validations[0].Argv[1] = "changed"
			case "main-hash":
				binding.Main.SHA256 = "changed"
			case "main-schema":
				m.Schema = 1
			case "graph-externals":
				m.Externals[0].Name = "changed"
			case "graph-complete":
				m.Final.Graph.Complete = false
			case "namespace-order":
				binding.Namespaces[0] = "changed"
			case "source-order":
				binding.Sources[0].Path = "changed"
			case "missing-namespace":
				m.Validations[0].Accepted = false
				m.Validations[0].Exit = 1
				m.Final.Argv = m.Final.Argv[:15]
				m.Final.Argv = append(m.Final.Argv, m.Output)
				m.Final.Sources = m.Final.Sources[1:]
				m.Final.Includes = nil
				m.Final.Argv = append(m.Final.Argv[:15], m.Final.Sources[0].Namespace+":"+m.Final.Sources[0].Path, m.Output)
				m.Inputs = map[string]markerFingerprint{m.Final.Sources[0].Path: m.Final.Sources[0].Observed}
				binding.Sources = []markerSource{}
				binding.Namespaces = []string{}
			case "projected-inventory":
				binding.MarkerInventory[0].Identifier = "changed"
				n.Final.Graph.Inventory[0].Identifier = "changed"
			case "projected-references":
				n.Final.Graph.References = append(n.Final.Graph.References, [2]int{0, 0})
				n.Final.Graph.Summary[1]++
			case "input-identity":
				source := markerObserved{Path: "/other/include.inc", Root: n.Final.Sources[0].Path, Observed: markerFingerprint{SHA256: strings.Repeat("0", 64), Size: 1}}
				n.Final.Includes = append(n.Final.Includes, source)
				binding.Includes = n.Final.Includes
				n.Inputs[source.Path] = source.Observed
				n.Directories = append(n.Directories, "/other")
				sort.Strings(n.Directories)
			case "descriptor-count":
				binding.MainDescriptors.Rules = nil
			case "descriptor-identity":
				binding.MainDescriptors.Rules[0].Identity[1] = "changed"
			default:
				return // Envelope-bound guard cases are exercised below.
			}
			if e = markerValidateBinding(binding, m, n, b.Main, mi, ni); e == nil {
				t.Fatalf("binding semantic corruption accepted: %s", kind)
			}
		})
	}
	// Recomputed semantic envelopes deliberately reach each late runtime guard.
	for _, kind := range []string{"abi-file", "index-version", "descriptor-file", "native-proof", "native-observation", "native-traversal"} {
		t.Run(kind, func(t *testing.T) {
			fixture := markerArtifactFixture(t)
			var index markerIndex
			if _, e = markerReadJSON(filepath.Join(fixture, "compiler-inputs/index.json"), &index); e != nil {
				t.Fatal(e)
			}
			write := func(path string, value any) {
				t.Helper()
				data, e := json.Marshal(value)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(fixture, path), data, 0600); e != nil {
					t.Fatal(e)
				}
				if strings.HasPrefix(path, "marker-artifact/") {
					index.Marker.Files[strings.TrimPrefix(path, "marker-artifact/")] = markerBytesIdentity(data)
				} else if path == "compiler-inputs/main/manifest.json" {
					slot := index.Artifacts["main"]
					slot.Files["manifest.json"] = markerBytesIdentity(data)
					index.Artifacts["main"] = slot
				}
			}
			var binding markerBinding
			clone(b, &binding)
			switch kind {
			case "abi-file":
				abi := binding.ABI["compiler"]
				abi.Size++
				binding.ABI["compiler"] = abi
				write("marker-artifact/binding.json", binding)
			case "index-version":
				slot := index.Artifacts["main"]
				slot.Versions["libyara"] = "changed"
				index.Artifacts["main"] = slot
			case "descriptor-file":
				data := []byte("tampered\n")
				if e = os.WriteFile(filepath.Join(fixture, "marker-artifact/marker.descriptors"), data, 0600); e != nil {
					t.Fatal(e)
				}
				index.Marker.Files["marker.descriptors"] = markerBytesIdentity(data)
			case "native-observation", "native-traversal":
				var m markerManifest
				clone(main, &m)
				if kind == "native-traversal" {
					m.Final.Native.SHA256 = "../../outside"
				} else {
					data, e := os.ReadFile(filepath.Join(fixture, "compiler-inputs/main/objects", m.Final.Native.SHA256))
					if e != nil {
						t.Fatal(e)
					}
					for offset := 0; offset < len(data); {
						nameSize := int(binary.LittleEndian.Uint64(data[offset+1 : offset+9]))
						size := int(binary.LittleEndian.Uint64(data[offset+9 : offset+17]))
						if data[offset] == 13 {
							data[offset+17+nameSize+12] ^= 1
							break
						}
						offset += 17 + nameSize + size
					}
					m.Final.Native = markerBytesIdentity(data)
					objectPath := "objects/" + m.Final.Native.SHA256
					if e = os.WriteFile(filepath.Join(fixture, "compiler-inputs/main", objectPath), data, 0600); e != nil {
						t.Fatal(e)
					}
					slot := index.Artifacts["main"]
					slot.Files[objectPath] = m.Final.Native
					index.Artifacts["main"] = slot
				}
				write("compiler-inputs/main/manifest.json", m)
				binding.MainManifest = index.Artifacts["main"].Files["manifest.json"]
				write("marker-artifact/binding.json", binding)
			case "native-proof":
				var m markerManifest
				clone(main, &m)
				m.Final.Native.SHA256 = strings.Repeat("0", 64)
				write("compiler-inputs/main/manifest.json", m)
				binding.MainManifest = index.Artifacts["main"].Files["manifest.json"]
				write("marker-artifact/binding.json", binding)
			}
			write("compiler-inputs/index.json", index)
			r, fp, e := readRulesSnapshot(filepath.Join(fixture, "compiled.yac"))
			if e != nil {
				t.Fatal(e)
			}
			defer r.Destroy()
			if narrow, _, e := loadMarkerArtifact(fixture, r, fp); e == nil {
				if narrow != nil {
					narrow.Destroy()
				}
				t.Fatalf("late semantic guard accepted: %s", kind)
			}
		})
	}
	r, e := compileDir(writeRules(t, "rule Other { condition: true }"), func(string, ...any) {})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Destroy()
	if narrow, _, e := loadMarkerArtifact(root, r, b.Main); e == nil {
		if narrow != nil {
			narrow.Destroy()
		}
		t.Fatal("loaded main inventory mismatch accepted")
	}
}

func TestP12SeedArtifactAndUnpreparedFallback(t *testing.T) {
	root := markerArtifactFixture(t)
	cache := t.TempDir()
	data, e := os.ReadFile(filepath.Join(root, "compiled.yac"))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(cache, cachedRulesName)
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	s, e := NewScanner(&Config{RulesPath: path, CacheDir: cache, SeedRules: filepath.Join(root, "compiled.yac")}, func(string, ...any) {})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.markerRules.Load() == nil {
		t.Fatal("cache-seeded exact main did not select matching seed artifact")
	}
	if names := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(names, "MarkerPrivate") {
		t.Fatalf("cache seed marker lost: %s", names)
	}
	for _, empty := range []*Scanner{{}, {srcFile: path}} {
		r, identity := prepareMarkerArtifact(empty, s.rules.Load(), nil, "")
		if r != nil || identity != "" {
			t.Fatal("unprepared/dynamic main published marker")
		}
	}
}

func TestP12ManifestContractFailures(t *testing.T) {
	root := markerArtifactFixture(t)
	var main markerManifest
	if _, e := markerReadJSON(filepath.Join(root, "compiler-inputs/main/manifest.json"), &main); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"validation-status", "validation-prefix", "validation-root", "final-arity", "final-prefix", "final-root-order", "duplicate-input", "input-map", "output"} {
		data, e := json.Marshal(main)
		if e != nil {
			t.Fatal(e)
		}
		var m markerManifest
		if e = markerJSON(data, &m); e != nil {
			t.Fatal(e)
		}
		switch kind {
		case "validation-status":
			m.Validations[0].Accepted = false
		case "validation-prefix":
			m.Validations[0].Argv[1] = "changed"
		case "validation-root":
			m.Validations[0].Argv[15] = "changed"
		case "final-arity":
			m.Final.Argv = nil
		case "final-prefix":
			m.Final.Argv[1] = "changed"
		case "final-root-order":
			m.Final.Sources[0].Namespace = "changed"
		case "duplicate-input":
			s := m.Final.Sources[0]
			s.Observed.SHA256 = "changed"
			m.Final.Includes = append(m.Final.Includes, s)
		case "input-map":
			m.Inputs = nil
		case "output":
			m.Output = "/different"
		}
		if e = markerValidateManifest(m); e == nil {
			t.Fatalf("manifest compiler/input mismatch accepted: %s", kind)
		}
	}
	// Relative native include paths resolve against the recorded compiler cwd.
	relative := main
	relative.Final.Includes = append([]markerObserved{}, main.Final.Includes...)
	relative.Inputs = map[string]markerFingerprint{}
	for p, fp := range main.Inputs {
		relative.Inputs[p] = fp
	}
	observed := markerObserved{Path: "relative.inc", Observed: markerFingerprint{SHA256: strings.Repeat("0", 64), Size: 0}}
	relative.Final.Includes = append(relative.Final.Includes, observed)
	relative.Inputs[filepath.Join(main.Final.Cwd, observed.Path)] = observed.Observed
	if e := markerValidateManifest(relative); e != nil {
		t.Fatal(e)
	}
	relative.Final.Argv = append([]string{}, main.Final.Argv...)
	relative.Final.Argv[len(relative.Final.Argv)-1] = "relative.yac"
	relative.Output = filepath.Join(main.Final.Cwd, "relative.yac")
	if e := markerValidateManifest(relative); e != nil {
		t.Fatal(e)
	}
}

func TestP12JSONIntegerTypeIdentity(t *testing.T) {
	for _, input := range []string{
		`{"native_index":null,"namespace":"n","identifier":"r","flags":0,"tags":[]}`,
		`{"native_index":0,"namespace":"n","identifier":"r","flags":null,"tags":[]}`,
		`{"namespace":"n","identifier":"r","flags":0,"tags":[]}`,
		`{"native_index":0,"namespace":"n","identifier":"r","tags":[]}`,
	} {
		var row markerInventoryRule
		if markerJSON([]byte(input), &row) == nil {
			t.Fatalf("null/missing integer identity accepted: %s", input)
		}
	}
	for _, input := range []string{`{"sha256":"abc"}`, `{"sha256":"abc","size":null}`} {
		var fp markerFingerprint
		if markerJSON([]byte(input), &fp) == nil {
			t.Fatalf("null/missing fingerprint integer accepted: %s", input)
		}
	}
	var m markerManifest
	if e := markerJSON([]byte(`{"validations":[{"rule_graph":{"summary":null},"sources":[{"errors":null}]}]}`), &m); e != nil {
		t.Fatalf("native failed-validation nullable observations rejected: %v", e)
	}
}

func TestP12PreparedMarkerLogRollback(t *testing.T) {
	awaitObserverCount(t, &observedRuleGenerations, 0)
	root := markerArtifactFixture(t)
	armed := false
	s, e := NewScanner(&Config{RulesPath: filepath.Join(root, "compiled.yac")}, func(format string, _ ...any) {
		if armed && strings.HasPrefix(format, "PERF-18: marker artifact loaded:") {
			if observedRuleGenerations.count() != 4 {
				t.Error("fresh marker not owned before operator callback")
			}
			panic("marker publication rollback")
		}
	})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	main, marker, fp := s.rules.Load(), s.markerRules.Load(), s.Fingerprint()
	if marker == nil {
		t.Fatal("authoritative marker missing")
	}
	destroyed := map[*yara.Rules]int{}
	observedRuleGenerations.mu.Lock()
	observedRuleGenerations.beforeDestroy = func(r *yara.Rules) {
		if r != main && r != marker {
			destroyed[r]++
		}
	}
	observedRuleGenerations.mu.Unlock()
	defer func() {
		observedRuleGenerations.mu.Lock()
		observedRuleGenerations.beforeDestroy = nil
		observedRuleGenerations.mu.Unlock()
	}()
	armed = true
	func() {
		defer func() {
			if recover() == nil {
				t.Error("marker callback rollback panic missing")
			}
		}()
		_ = s.Reload()
	}()
	if len(destroyed) != 2 || s.rules.Load() != main || s.markerRules.Load() != marker || s.Fingerprint() != fp || s.RuleGenerations() != 2 {
		t.Fatalf("marker rollback changed old generation or leaked prepared ownership: destroyed=%d generations=%d", len(destroyed), s.RuleGenerations())
	}
	for _, count := range destroyed {
		if count != 1 {
			t.Fatalf("marker rollback destruction count=%d", count)
		}
	}
	if names := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(names, "MarkerPrivate") {
		t.Fatalf("rollback lost old detection: %s", names)
	}
}

func TestP12GraphStateReferenceAndPublicationGuards(t *testing.T) {
	for _, kind := range []string{"compiled-object", "input-object", "native-object", "stderr-object", "snapshot-object", "source-object", "include-object", "cursor-read", "cursor-length", "cursor-count", "cursor-incomplete", "cursor-snapshot", "invocation-directory", "invocation-count", "invocation-slot", "record-read", "record-malformed", "record-identity", "record-contents", "raw-evidence", "native-observation"} {
		t.Run(kind, func(t *testing.T) {
			envelope := markerArtifactFixture(t)
			root := filepath.Join(envelope, "compiler-inputs/main")
			var index markerIndex
			var m markerManifest
			if _, e := markerReadJSON(filepath.Join(envelope, "compiler-inputs/index.json"), &index); e != nil {
				t.Fatal(e)
			}
			if _, e := markerReadJSON(filepath.Join(root, "manifest.json"), &m); e != nil {
				t.Fatal(e)
			}
			files := index.Artifacts["main"].Files
			bad := markerFingerprint{SHA256: strings.Repeat("0", 64), Size: 1}
			writeRecord := func() {
				t.Helper()
				record := markerInvocationRecord{Phase: "validation", Index: 0, Invocation: m.Validations[0]}
				data, e := json.Marshal(record)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(root, "invocations/validation-0.json"), data, 0600); e != nil {
					t.Fatal(e)
				}
				files["invocations/validation-0.json"] = markerBytesIdentity(data)
			}
			read := markerReadFile
			defer func() { markerReadFile = read }()
			switch kind {
			case "compiled-object":
				m.Compiled = bad
			case "input-object":
				for path := range m.Inputs {
					m.Inputs[path] = bad
					break
				}
			case "native-object":
				m.Validations[0].Native = bad
				writeRecord()
			case "stderr-object":
				m.Validations[0].Stderr = bad
				writeRecord()
			case "snapshot-object":
				m.Validations[0].Candidate.Snapshot = bad
				writeRecord()
			case "source-object":
				m.Validations[0].Sources[0].Observed = bad
				writeRecord()
			case "include-object":
				m.Validations[0].Includes[0].Observed = bad
				writeRecord()
			case "cursor-read":
				markerReadFile = func(path string) ([]byte, error) {
					if strings.HasSuffix(path, "/cursor") {
						return nil, errors.New("injected cursor read")
					}
					return read(path)
				}
			case "cursor-length", "cursor-count", "cursor-incomplete":
				data, e := os.ReadFile(filepath.Join(root, "cursor"))
				if e != nil {
					t.Fatal(e)
				}
				switch kind {
				case "cursor-length":
					data = nil
				case "cursor-count":
					data[0]++
				case "cursor-incomplete":
					data[8] = 0
				}
				if e = os.WriteFile(filepath.Join(root, "cursor"), data, 0600); e != nil {
					t.Fatal(e)
				}
				files["cursor"] = markerBytesIdentity(data)
			case "cursor-snapshot":
				files["cursor"] = bad
			case "invocation-directory":
				if e := os.Rename(filepath.Join(root, "invocations"), filepath.Join(root, "renamed")); e != nil {
					t.Fatal(e)
				}
			case "invocation-count":
				if e := os.Remove(filepath.Join(root, "invocations/validation-0.json")); e != nil {
					t.Fatal(e)
				}
			case "invocation-slot":
				if e := os.Rename(filepath.Join(root, "invocations/validation-0.json"), filepath.Join(root, "invocations/unexpected.json")); e != nil {
					t.Fatal(e)
				}
			case "record-read":
				markerReadFile = func(path string) ([]byte, error) {
					if strings.HasSuffix(path, "/validation-0.json") {
						return nil, errors.New("injected record read")
					}
					return read(path)
				}
			case "record-malformed":
				if e := os.WriteFile(filepath.Join(root, "invocations/validation-0.json"), []byte("{"), 0600); e != nil {
					t.Fatal(e)
				}
			case "record-identity":
				files["invocations/validation-0.json"] = bad
			case "record-contents":
				m.Validations[0].Candidate.Path = "changed"
			case "raw-evidence":
				files["validation-0.native"] = bad
			case "native-observation":
				m.Validations[0].Sources[0].EOF = false
				writeRecord()
			}
			if e := markerVerifyGraphState(root, files, m); e == nil {
				t.Fatalf("capture/export graph predicate accepted malformed %s", kind)
			}
		})
	}
}
func TestP12ReferencedSnapshotFallback(t *testing.T) {
	root := markerArtifactFixture(t)
	var index markerIndex
	var m markerManifest
	var b markerBinding
	if _, e := markerReadJSON(filepath.Join(root, "compiler-inputs/index.json"), &index); e != nil {
		t.Fatal(e)
	}
	if _, e := markerReadJSON(filepath.Join(root, "compiler-inputs/main/manifest.json"), &m); e != nil {
		t.Fatal(e)
	}
	if _, e := markerReadJSON(filepath.Join(root, "marker-artifact/binding.json"), &b); e != nil {
		t.Fatal(e)
	}
	fp := markerFingerprint{SHA256: strings.Repeat("0", 64), Size: 1}
	m.Validations[0].Candidate.Snapshot = fp
	b.Sources[0].Snapshot = fp
	write := func(path string, value any) markerFingerprint {
		t.Helper()
		data, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, path), data, 0600); e != nil {
			t.Fatal(e)
		}
		return markerBytesIdentity(data)
	}
	slot := index.Artifacts["main"]
	slot.Files["invocations/validation-0.json"] = write("compiler-inputs/main/invocations/validation-0.json", markerInvocationRecord{Phase: "validation", Index: 0, Invocation: m.Validations[0]})
	slot.Files["manifest.json"] = write("compiler-inputs/main/manifest.json", m)
	index.Artifacts["main"] = slot
	b.MainManifest = slot.Files["manifest.json"]
	index.Marker.Files["binding.json"] = write("marker-artifact/binding.json", b)
	write("compiler-inputs/index.json", index)
	main, identity, e := readRulesSnapshot(filepath.Join(root, "compiled.yac"))
	if e != nil {
		t.Fatal(e)
	}
	defer main.Destroy()
	marker, _, e := loadMarkerArtifact(root, main, identity)
	if e == nil {
		marker.Destroy()
		t.Fatal("missing referenced snapshot accepted after manifest/record/index/binding hashes rebound")
	}
	if !strings.Contains(e.Error(), "retained object identity/reference mismatch") {
		t.Fatalf("missing snapshot did not reach object guard: %v", e)
	}
	s := markerFixtureScanner(t, root, nil)
	if s.markerRules.Load() != nil {
		t.Fatal("missing snapshot published marker")
	}
	if names := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(names, "MarkerPrivate") || !strings.Contains(names, "MarkerPublic") {
		t.Fatalf("snapshot fallback lost dependencies: %s", names)
	}
}
func TestP12IntermediateEnvelopeDirectoryFallback(t *testing.T) {
	root := markerArtifactFixture(t)
	external := filepath.Join(t.TempDir(), "proofs")
	if e := os.Rename(filepath.Join(root, "compiler-inputs"), external); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(external, filepath.Join(root, "compiler-inputs")); e != nil {
		t.Fatal(e)
	}
	s := markerFixtureScanner(t, root, nil)
	if s.markerRules.Load() != nil {
		t.Fatal("symlinked intermediate proof directory published marker")
	}
	if names := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(names, "MarkerPrivate") || !strings.Contains(names, "MarkerPublic") {
		t.Fatalf("symlink fallback lost dependencies: %s", names)
	}
}
func TestP12LexicalDirectoryIdentity(t *testing.T) {
	root := markerArtifactFixture(t)
	var m markerManifest
	if _, e := markerReadJSON(filepath.Join(root, "compiler-inputs/main/manifest.json"), &m); e != nil {
		t.Fatal(e)
	}
	if e := markerValidateManifest(m); e != nil {
		t.Fatal(e)
	}
	source := markerObserved{Path: "/traversed//./leaf/../deep/file.inc", Observed: m.Final.Sources[0].Observed}
	m.Final.Includes = append(m.Final.Includes, source)
	m.Inputs[filepath.Clean(source.Path)] = source.Observed
	m.Directories = append(m.Directories, "/traversed", "/traversed/leaf", "/traversed/deep")
	sort.Strings(m.Directories)
	if e := markerValidateManifest(m); e != nil {
		t.Fatalf("lexically traversed directories mismatch: %v", e)
	}
	m.Directories = nil
	if e := markerValidateManifest(m); e == nil {
		t.Fatal("missing directory identities accepted")
	}
	// A file cannot also serve as a traversed parent directory.
	source.Path = m.Final.Sources[0].Path + "/child.inc"
	m.Final.Includes = append(m.Final.Includes, source)
	m.Inputs[source.Path] = source.Observed
	if e := markerValidateManifest(m); e == nil || !strings.Contains(e.Error(), "file/directory collision") {
		t.Fatalf("file/directory projection collision: %v", e)
	}
}

func TestP12NativeFailedAndSuccessfulRootContracts(t *testing.T) {
	root := markerArtifactFixture(t)
	var m markerManifest
	if _, e := markerReadJSON(filepath.Join(root, "compiler-inputs/main/manifest.json"), &m); e != nil {
		t.Fatal(e)
	}
	frame := func(kind byte, name string, payload []byte) []byte {
		data := make([]byte, 17)
		data[0] = kind
		binary.LittleEndian.PutUint64(data[1:9], uint64(len(name)))
		binary.LittleEndian.PutUint64(data[9:17], uint64(len(payload)))
		data = append(data, []byte(name)...)
		return append(data, payload...)
	}
	run := func(data []byte, inv markerInvocation, want string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "native")
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		e := markerVerifyNativeGraph(path, inv)
		if want == "" {
			if e != nil {
				t.Fatal(e)
			}
		} else if e == nil || !strings.Contains(e.Error(), want) {
			t.Fatalf("guard %s: %v", want, e)
		}
	}
	inv := m.Final
	inv.Graph = markerGraph{Schema: 1, Complete: true, Inventory: []markerInventoryRule{}, References: [][2]int{}, Completions: []int{}, Summary: []int{0, 0, 0, 0}}
	inv.Sources = []markerObserved{}
	inv.Includes = []markerObserved{}
	prefix := append(frame(10, "mailstrix-rule-graph/1", nil), frame(8, inv.LibraryVersion, nil)...)
	suffix := append(frame(15, "", make([]byte, 32)), frame(9, inv.CompilerVersion, make([]byte, 4))...)
	run(append(append([]byte(nil), prefix...), suffix...), inv, "successful compiler has no roots")
	count := 1
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, 1)
	source := markerObserved{Path: "/bad.yar", Namespace: "bad", Observed: markerBytesIdentity(nil), EOF: true, Errors: &count}
	inv.Sources = []markerObserved{source}
	data := append(append([]byte(nil), prefix...), frame(1, source.Path, []byte(source.Namespace))...)
	data = append(data, frame(2, source.Path, nil)...)
	data = append(data, frame(3, source.Path, payload)...)
	data = append(data, suffix...)
	run(data, inv, "successful compiler has failed root")
	data = append(append([]byte(nil), prefix...), frame(1, source.Path, []byte(source.Namespace))...)
	run(append(data, frame(3, source.Path, make([]byte, 4))...), inv, "successful native root lacks EOF")
	rule := make([]byte, 13)
	rule[12] = 'r'
	binary.LittleEndian.PutUint32(rule[8:12], 4)
	run(append(append([]byte(nil), prefix...), frame(13, "n", rule)...), inv, "native inventory flags mismatch")
	binary.LittleEndian.PutUint32(rule[8:12], 0)
	data = append(append([]byte(nil), prefix...), frame(13, "n", rule)...)
	binary.LittleEndian.PutUint64(rule[:8], 1)
	run(append(data, frame(13, "n", rule)...), inv, "duplicate native rule identity")
	for _, failed := range m.Validations {
		if failed.Exit != 1 {
			continue
		}
		trace, e := os.ReadFile(filepath.Join(root, "compiler-inputs/main/objects", failed.Native.SHA256))
		if e != nil {
			t.Fatal(e)
		}
		run(trace, failed, "")
		data = nil
		for offset := 0; offset < len(trace); {
			size := 17 + int(binary.LittleEndian.Uint64(trace[offset+1:offset+9])) + int(binary.LittleEndian.Uint64(trace[offset+9:offset+17]))
			if trace[offset] != 3 {
				data = append(data, trace[offset:offset+size]...)
			}
			offset += size
		}
		failed.Sources[0].Errors = nil
		run(data, failed, "")
		return
	}
	t.Fatal("fixture lacks real rejected native validation")
}
func TestP12MissingGraphInventoryRoot(t *testing.T) {
	if e := markerVerifyFiles(filepath.Join(t.TempDir(), "missing"), map[string]markerFingerprint{"x": markerBytesIdentity(nil)}); e == nil {
		t.Fatal("missing graph root accepted")
	}
}

func TestP12NativeLargeInventory(t *testing.T) {
	root := markerArtifactFixture(t)
	for _, count := range []int{2048, 16384} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			dir := filepath.Join(root, "native-inventory", fmt.Sprint(count))
			var inv markerInvocation
			if _, e := markerReadJSON(filepath.Join(dir, "invocation.json"), &inv); e != nil {
				t.Fatal(e)
			}
			if len(inv.Graph.Inventory) != count {
				t.Fatalf("genuine large inventory count: %d, want %d", len(inv.Graph.Inventory), count)
			}
			first, other := inv.Graph.Inventory[0], inv.Graph.Inventory[count/2]
			if first.Identifier != other.Identifier || first.Namespace == other.Namespace {
				t.Fatal("fixture must repeat identifiers in distinct native namespaces")
			}
			path := filepath.Join(dir, "native")
			if e := markerVerifyNativeGraph(path, inv); e != nil {
				t.Fatalf("large genuine native inventory or distinct namespaces rejected: %v", e)
			}
			trace, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			// Mutate only the final native identity, retaining its ordinal and flags.
			// Rejection must come from the streaming duplicate guard, before the
			// final native/manifest comparison or graph validator can mask it.
			for offset := 0; offset < len(trace); {
				nameSize := int(binary.LittleEndian.Uint64(trace[offset+1 : offset+9]))
				size := int(binary.LittleEndian.Uint64(trace[offset+9 : offset+17]))
				end := offset + 17 + nameSize + size
				payload := offset + 17 + nameSize
				if trace[offset] == 13 && binary.LittleEndian.Uint64(trace[payload:payload+8]) == uint64(count-1) { // #nosec G115 -- fixed positive test counts
					header := append([]byte(nil), trace[offset:offset+17]...)
					binary.LittleEndian.PutUint64(header[1:9], uint64(len(first.Namespace)))
					binary.LittleEndian.PutUint64(header[9:17], uint64(12+len(first.Identifier)))
					data := append([]byte(nil), trace[:offset]...)
					data = append(data, header...)
					data = append(data, []byte(first.Namespace)...)
					data = append(data, trace[payload:payload+12]...)
					data = append(data, []byte(first.Identifier)...)
					data = append(data, trace[end:]...)
					duplicate := filepath.Join(t.TempDir(), "late-duplicate")
					if e := os.WriteFile(duplicate, data, 0600); e != nil {
						t.Fatal(e)
					}
					if e := markerVerifyNativeGraph(duplicate, inv); e == nil || e.Error() != "duplicate native rule identity" {
						t.Fatalf("late duplicate must reach native identity guard: %v", e)
					}
					return
				}
				offset = end
			}
			t.Fatal("genuine large fixture lacks final native inventory frame")
		})
	}
}

func BenchmarkP12NativeInventory(b *testing.B) {
	root := markerArtifactFixture(b)
	for _, count := range []int{2048, 16384} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			dir := filepath.Join(root, "native-inventory", fmt.Sprint(count))
			var inv markerInvocation
			if _, e := markerReadJSON(filepath.Join(dir, "invocation.json"), &inv); e != nil {
				b.Fatal(e)
			}
			path := filepath.Join(dir, "native")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if e := markerVerifyNativeGraph(path, inv); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
