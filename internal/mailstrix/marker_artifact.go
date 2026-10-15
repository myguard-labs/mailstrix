package mailstrix

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	yara "github.com/hillu/go-yara/v4"
)

// These identities describe the archive actually linked into the production
// binary and the compiler from the same build stage. Unsupported builds leave
// them empty and use the full main set; artifact metadata cannot assert trust.
var markerRuntimeLibYaraSHA256, markerRuntimeCompilerSHA256, markerRuntimeVersion string

// I/O seams allow deterministic read/close/replacement failures in hermetic tests.
var markerOpenFile = func(path string) (io.ReadCloser, error) {
	return os.Open(path) // #nosec G304 -- operator artifact root or verified inventory descendant, never message input
}
var markerReadFile = os.ReadFile
var markerLoadSnapshot = readRulesSnapshot
var markerMainSnapshot = readRulesSnapshot

type markerFingerprint struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func markerBytesIdentity(b []byte) markerFingerprint {
	h := sha256.Sum256(b)
	return markerFingerprint{hex.EncodeToString(h[:]), int64(len(b))}
}

// Drop the backing bytes even if go-yara retains its reader on a native load
// error. Both the identity and the native object come from this same snapshot.
func readRulesSnapshot(path string) (*yara.Rules, markerFingerprint, error) {
	b, e := os.ReadFile(path) // #nosec G304 -- operator-configured compiled rules path, never message input
	if e != nil {
		return nil, markerFingerprint{}, e
	}
	identity := markerBytesIdentity(b)
	buf := bytes.NewBuffer(b)
	defer func() { *buf = bytes.Buffer{} }()
	r, e := yara.ReadRules(buf)
	return r, identity, e
}

type markerInventoryRule struct {
	Index      int      `json:"native_index"`
	Namespace  string   `json:"namespace"`
	Identifier string   `json:"identifier"`
	Flags      int      `json:"flags"`
	Tags       []string `json:"tags"`
}
type markerGraph struct {
	Schema      int                   `json:"schema"`
	Complete    bool                  `json:"complete"`
	Inventory   []markerInventoryRule `json:"inventory"`
	References  [][2]int              `json:"references"`
	Completions []int                 `json:"completions"`
	Summary     []int                 `json:"summary"`
}
type markerExternal struct {
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}
type markerSource struct {
	Namespace string            `json:"namespace"`
	Path      string            `json:"path"`
	Snapshot  markerFingerprint `json:"snapshot"`
}
type markerObserved struct {
	Namespace string            `json:"namespace,omitempty"`
	Path      string            `json:"path"`
	Root      string            `json:"root,omitempty"`
	Observed  markerFingerprint `json:"observed"`
	EOF       bool              `json:"eof,omitempty"`
	Errors    *int              `json:"errors,omitempty"`
}
type markerInvocation struct {
	Argv            []string          `json:"argv"`
	Cwd             string            `json:"cwd"`
	Exit            int               `json:"exit"`
	Candidate       markerSource      `json:"candidate"`
	Accepted        bool              `json:"accepted"`
	Sources         []markerObserved  `json:"sources"`
	Includes        []markerObserved  `json:"includes"`
	Graph           markerGraph       `json:"rule_graph"`
	Native          markerFingerprint `json:"native_trace"`
	Stderr          markerFingerprint `json:"stderr"`
	CompilerVersion string            `json:"yarac_version"`
	LibraryVersion  string            `json:"libyara_version"`
}
type markerInvocationRecord struct {
	Phase      string           `json:"phase"`
	Index      int              `json:"index"`
	Invocation markerInvocation `json:"invocation"`
}
type markerManifest struct {
	Cwd             string                       `json:"cwd"`
	SourceDirectory string                       `json:"source_directory"`
	Directories     []string                     `json:"final_directories"`
	Schema          int                          `json:"schema"`
	Output          string                       `json:"output"`
	Compiled        markerFingerprint            `json:"compiled"`
	Versions        map[string]string            `json:"versions"`
	Externals       []markerExternal             `json:"external_definitions"`
	Validations     []markerInvocation           `json:"validations"`
	Final           markerInvocation             `json:"final"`
	Inputs          map[string]markerFingerprint `json:"final_inputs"`
}
type markerDescriptors struct {
	Rules []struct {
		Identity [2]string `json:"identity"`
		Lines    []string  `json:"lines"`
	} `json:"rules"`
	Externals []string `json:"externals"`
}
type markerBinding struct {
	Schema         int                          `json:"schema"`
	Construction   string                       `json:"construction"`
	Main           markerFingerprint            `json:"main"`
	Marker         markerFingerprint            `json:"marker"`
	MainManifest   markerFingerprint            `json:"main_manifest"`
	MarkerManifest markerFingerprint            `json:"marker_manifest"`
	Versions       map[string]string            `json:"versions"`
	ABI            map[string]markerFingerprint `json:"abi"`
	ModuleIdentity map[string]markerFingerprint `json:"module_identity"`
	Externals      []markerExternal             `json:"external_definitions"`
	Namespaces     []string                     `json:"namespace_order"`
	Sources        []markerSource               `json:"sources"`
	Includes       []markerObserved             `json:"includes"`
	Closure        struct {
		Markers  []int `json:"markers"`
		Retained []int `json:"retained"`
	} `json:"closure"`
	MainInventory     []markerInventoryRule `json:"main_inventory"`
	MarkerInventory   []markerInventoryRule `json:"marker_inventory"`
	MainDescriptors   markerDescriptors     `json:"main_descriptors"`
	MarkerDescriptors markerDescriptors     `json:"marker_descriptors"`
}
type markerIndexSlot struct {
	Compiled string                       `json:"compiled"`
	Graph    string                       `json:"graph"`
	SHA256   string                       `json:"compiled_sha256"`
	Versions map[string]string            `json:"versions"`
	Files    map[string]markerFingerprint `json:"files"`
}
type markerIndex struct {
	Schema    int                          `json:"schema"`
	Artifacts map[string]markerIndexSlot   `json:"artifacts"`
	Metadata  map[string]markerFingerprint `json:"metadata"`
	Marker    struct {
		Files map[string]markerFingerprint `json:"files"`
	} `json:"marker"`
}

// Reject duplicate keys (encoding/json otherwise silently accepts the last
// value) and trailing values before decoding into the actual contract types.
func markerJSON(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	_, generic := out.(*any)
	_, manifest := out.(*markerManifest)
	_, record := out.(*markerInvocationRecord)
	var value func(string) error
	value = func(path string) error {
		token, e := d.Token()
		if e != nil {
			return e
		}
		// Failed native validations legitimately retain an unsealed graph summary
		// and a fatal root's unknown error count. Published/final contracts never do.
		nullable := ((manifest && strings.HasPrefix(path, "/validations/")) || (record && strings.HasPrefix(path, "/invocation/"))) && (strings.HasSuffix(path, "/rule_graph/summary") || strings.HasSuffix(path, "/errors"))
		if token == nil && !generic && !nullable {
			return errors.New("null contract value")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate/invalid JSON key")
				}
				seen[name] = true
				if e = value(path + "/" + name); e != nil {
					return e
				}
			}
			if !generic {
				required := []string{}
				if seen["native_index"] || seen["flags"] || seen["tags"] || seen["identifier"] {
					required = []string{"native_index", "namespace", "identifier", "flags", "tags"}
				}
				if seen["sha256"] || seen["size"] {
					required = []string{"sha256", "size"}
				}
				if seen["phase"] || seen["invocation"] {
					required = []string{"phase", "index", "invocation"}
				}
				for _, name := range required {
					if !seen[name] {
						return errors.New("missing typed contract field")
					}
				}
			}
		case '[':
			index := 0
			for d.More() {
				if e = value(path + "/" + strconv.Itoa(index)); e != nil {
					return e
				}
				index++
			}
		}
		// The decoder emits only opening delimiters while expecting a value;
		// closing delimiters are consumed here after the validated members.
		_, e = d.Token()
		return e
	}
	if e := value(""); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON data")
	}
	typed := json.NewDecoder(bytes.NewReader(data))
	typed.DisallowUnknownFields()
	return typed.Decode(out)
}

func markerReadRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("nonregular artifact file")
	}
	return markerReadFile(path)
}
func markerReadJSON(path string, out any) (markerFingerprint, error) {
	b, e := markerReadRegular(path)
	if e != nil {
		return markerFingerprint{}, e
	}
	return markerBytesIdentity(b), markerJSON(b, out)
}
func markerVerifyMetadata(root string, index markerIndex) error {
	version, e := markerReadRegular(filepath.Join(root, "libyara.version"))
	if e != nil {
		return e
	}
	if markerBytesIdentity(version) != index.Metadata["libyara.version"] || strings.TrimSpace(string(version)) != markerRuntimeVersion {
		return errors.New("export version identity mismatch")
	}
	var sources any
	identity, e := markerReadJSON(filepath.Join(root, "sources.json"), &sources)
	if e != nil {
		return e
	}
	if identity != index.Metadata["sources.json"] {
		return errors.New("export sources identity mismatch")
	}
	rows, ok := sources.([]any)
	if !ok {
		return errors.New("export sources must be an array")
	}
	for _, row := range rows {
		entry, ok := row.(map[string]any)
		if !ok {
			return errors.New("export source entry must be an object")
		}
		for _, field := range []string{"name", "repo", "license", "ref", "set"} {
			if value := entry[field]; value != nil {
				if _, ok := value.(string); !ok {
					return errors.New("export source string field malformed")
				}
			}
		}
	}
	return nil
}

// Stream the complete graph inventory, rejecting traversal and symlinks. Source
// blobs never enter the retained Go heap. A mismatch fails closed to full main.
func markerVerifyFiles(root string, expected map[string]markerFingerprint) error {
	if len(expected) == 0 {
		return errors.New("empty artifact inventory")
	}
	seen := 0
	e := filepath.WalkDir(root, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("nonregular artifact entry")
		}
		// WalkDir supplies descendants of the exact root passed to it.
		relative := strings.TrimPrefix(path, filepath.Clean(root)+string(os.PathSeparator))
		want, ok := expected[filepath.ToSlash(relative)]
		if !ok {
			return errors.New("unexpected artifact entry")
		}
		if len(want.SHA256) != 64 || want.Size < 0 {
			return errors.New("invalid artifact identity")
		}
		f, e := markerOpenFile(path)
		if e != nil {
			return e
		}
		h := sha256.New()
		n, e := io.Copy(h, f)
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		digest := hex.EncodeToString(h.Sum(nil))
		if strings.Contains("/"+filepath.ToSlash(relative), "/objects/") && filepath.Base(relative) != digest {
			return errors.New("graph object identity mismatch")
		}
		if n != want.Size || digest != want.SHA256 {
			return errors.New("artifact inventory/hash mismatch")
		}
		seen++
		return nil
	})
	if e != nil {
		return e
	}
	if seen != len(expected) {
		return errors.New("missing artifact entry")
	}
	return nil
}

// Reconstruct the final graph from the native frames, rather than trusting the
// manifest's complete bit or a source-text dependency approximation.
func markerVerifyNativeGraph(path string, invocation markerInvocation) error {
	f, e := markerOpenFile(path)
	if e != nil {
		return e
	}
	defer func() { _ = f.Close() }()
	reader := bufio.NewReader(f)
	g := markerGraph{Schema: 1, Complete: invocation.Exit == 0, Inventory: []markerInventoryRule{}, References: [][2]int{}, Completions: []int{}}
	started, sealed, complete := false, false, false
	identities := make(map[[2]string]struct{})
	var source *markerObserved
	var sourceHash hash.Hash
	sources, includes := []markerObserved{}, []markerObserved{}
	libraryVersion, compilerVersion := "", ""
	for {
		header := make([]byte, 17)
		_, e = io.ReadFull(reader, header)
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if complete {
			return errors.New("native frame after completion")
		}
		kind := header[0]
		nameSize, size := binary.LittleEndian.Uint64(header[1:9]), binary.LittleEndian.Uint64(header[9:17])
		// Native rule identifiers/namespaces and paths cannot exceed the frame file.
		// LimitReader/ReadAll avoids an allocation based on an untrusted header.
		if nameSize > uint64(^uint64(0)>>1) {
			return errors.New("invalid native name size")
		}
		nameBytes, e := io.ReadAll(io.LimitReader(reader, int64(nameSize)))
		if e != nil || uint64(len(nameBytes)) != nameSize {
			return errors.New("truncated native frame name")
		}
		name := string(nameBytes)
		if size > uint64(^uint64(0)>>1) {
			return errors.New("invalid native payload size")
		}
		if kind == 2 || kind == 4 {
			if source == nil || (kind == 2 && (source.Path != name || source.EOF)) {
				return errors.New("invalid native source observation")
			}
			target := sourceHash
			if kind == 4 {
				target = sha256.New()
			}
			count, e := io.CopyN(target, reader, int64(size))
			if e != nil || count != int64(size) {
				return errors.New("truncated native source")
			}
			if kind == 2 {
				source.Observed.Size += count
				source.EOF = size == 0
			} else {
				includes = append(includes, markerObserved{Path: name, Root: source.Path, Observed: markerFingerprint{hex.EncodeToString(target.Sum(nil)), count}})
			}
			continue
		}
		payload, e := io.ReadAll(io.LimitReader(reader, int64(size)))
		if e != nil || uint64(len(payload)) != size {
			return errors.New("truncated native payload")
		}
		if kind >= 10 && kind <= 15 {
			if kind == 10 {
				if started || name != "mailstrix-rule-graph/1" || size != 0 {
					return errors.New("invalid native graph start")
				}
				started = true
				continue
			}
			if !started || sealed || (source != nil && kind >= 13) {
				return errors.New("native graph frame out of order")
			}
			switch kind {
			case 11, 12:
				if name != "" || size != 16 || len(g.Inventory) > 0 {
					return errors.New("invalid native opcode frame")
				}
				a, b := binary.LittleEndian.Uint64(payload[:8]), binary.LittleEndian.Uint64(payload[8:])
				if a > uint64(^uint(0)>>1) || b > uint64(^uint(0)>>1) {
					return errors.New("native opcode index overflow")
				}
				if kind == 11 {
					g.References = append(g.References, [2]int{int(a), int(b)})
				} else {
					if a != b {
						return errors.New("native completion mismatch")
					}
					g.Completions = append(g.Completions, int(a))
				}
			case 13:
				if size <= 12 || binary.LittleEndian.Uint64(payload[:8]) != uint64(len(g.Inventory)) || strings.ContainsRune(name, '\x00') || strings.ContainsRune(string(payload[12:]), '\x00') {
					return errors.New("invalid native inventory frame")
				}
				flags := int(binary.LittleEndian.Uint32(payload[8:12]))
				if flags & ^3 != 0 {
					return errors.New("native inventory flags mismatch")
				}
				identity := [2]string{name, string(payload[12:])}
				if _, exists := identities[identity]; exists {
					return errors.New("duplicate native rule identity")
				}
				identities[identity] = struct{}{}
				g.Inventory = append(g.Inventory, markerInventoryRule{Index: len(g.Inventory), Namespace: name, Identifier: string(payload[12:]), Flags: int(binary.LittleEndian.Uint32(payload[8:12])), Tags: []string{}})
			case 14:
				if size != 8 || len(g.Inventory) == 0 || name == "" || strings.ContainsRune(name, '\x00') || binary.LittleEndian.Uint64(payload) != uint64(len(g.Inventory)-1) { // #nosec G115 -- preceding nonempty inventory guard makes index nonnegative
					return errors.New("invalid native tag frame")
				}
				row := &g.Inventory[len(g.Inventory)-1]
				for _, tag := range row.Tags {
					if tag == name {
						return errors.New("duplicate native tag")
					}
				}
				row.Tags = append(row.Tags, name)
			case 15:
				if name != "" || size != 32 {
					return errors.New("invalid native graph seal")
				}
				g.Summary = []int{}
				for i := 0; i < 4; i++ {
					n := binary.LittleEndian.Uint64(payload[8*i : 8*i+8])
					if n > uint64(^uint(0)>>1) {
						return errors.New("native summary overflow")
					}
					g.Summary = append(g.Summary, int(n))
				}
				sealed = true
			}
			continue
		}
		switch kind {
		case 1:
			if source != nil {
				return errors.New("overlapping native roots")
			}
			source = &markerObserved{Path: name, Namespace: string(payload)}
			sourceHash = sha256.New()
		case 3:
			if source == nil || source.Path != name || size != 4 {
				return errors.New("incomplete native root")
			}
			count := int(int32(binary.LittleEndian.Uint32(payload))) // #nosec G115 -- native root error count is a signed32 wire value, exactly capture.parse_trace
			if count == 0 && !source.EOF {
				return errors.New("successful native root lacks EOF")
			}
			source.Errors = &count
			source.Observed.SHA256 = hex.EncodeToString(sourceHash.Sum(nil))
			sources = append(sources, *source)
			source = nil
		case 8:
			if size != 0 || (libraryVersion != "" && libraryVersion != name) {
				return errors.New("native library version mismatch")
			}
			libraryVersion = name
		case 9:
			if size != 4 || int(int32(binary.LittleEndian.Uint32(payload))) != invocation.Exit || (source != nil && invocation.Exit == 0) { // #nosec G115 -- native compiler status is signed32, exactly capture.parse_trace
				return errors.New("native compiler completion mismatch")
			}
			if source != nil {
				source.Observed.SHA256 = hex.EncodeToString(sourceHash.Sum(nil))
				sources = append(sources, *source)
				source = nil
			}
			compilerVersion = name
			complete = true
		default:
			return errors.New("unknown native frame")
		}
	}
	if !started || (invocation.Exit == 0 && !sealed) || !complete || !markerEqual(g, invocation.Graph) || !markerEqual(sources, invocation.Sources) || !markerEqual(includes, invocation.Includes) || libraryVersion != invocation.LibraryVersion || compilerVersion != invocation.CompilerVersion {
		return errors.New("manifest disagrees with native final observation")
	}
	if invocation.Exit == 0 {
		for _, root := range sources {
			if root.Errors == nil || *root.Errors != 0 {
				return errors.New("successful compiler has failed root")
			}
		}
		if len(sources) == 0 {
			return errors.New("successful compiler has no roots")
		}
		return markerValidateGraph(g)
	}
	return nil
}

func markerEqual(a, b any) bool { return reflect.DeepEqual(a, b) }
func markerCheck(ok bool, msg string) error {
	if !ok {
		return errors.New(msg)
	}
	return nil
}

func markerValidateGraph(g markerGraph) error {
	if !g.Complete || g.Schema != 1 || len(g.Summary) != 4 || g.Summary[0] != len(g.Inventory) || g.Summary[1] != len(g.References) || g.Summary[2] != len(g.Completions) || len(g.Completions) != len(g.Inventory) {
		return errors.New("incomplete native graph")
	}
	identities := map[[2]string]bool{}
	tags := 0
	for i, r := range g.Inventory {
		id := [2]string{r.Namespace, r.Identifier}
		if r.Index != i || g.Completions[i] != i || r.Identifier == "" || r.Flags & ^3 != 0 || identities[id] {
			return errors.New("native inventory mismatch")
		}
		identities[id] = true
		tags += len(r.Tags)
	}
	if tags != g.Summary[3] {
		return errors.New("native tag count mismatch")
	}
	for _, edge := range g.References {
		if edge[0] < 0 || edge[1] < 0 || edge[0] >= len(g.Inventory) || edge[1] >= len(g.Inventory) || g.Inventory[edge[0]].Namespace != g.Inventory[edge[1]].Namespace {
			return errors.New("native reference mismatch")
		}
	}
	return nil
}
func markerValidateExternals(externals []markerExternal) error {
	names := []string{"filepath", "filename", "extension", "filetype", "file_type", "owner", "VBA"}
	if len(externals) != len(names) {
		return errors.New("external inventory mismatch")
	}
	for i, x := range externals {
		if x.Name != names[i] {
			return errors.New("external order mismatch")
		}
		if i == 6 {
			if x.Type != "integer" || string(x.Value) != "0" {
				return errors.New("external integer default mismatch")
			}
		} else if x.Type != "string" || string(x.Value) != `""` {
			return errors.New("external string default mismatch")
		}
	}
	return nil
}
func markerNativeInventory(rules *yara.Rules, expected []markerInventoryRule) error {
	list := rules.GetRules()
	if len(list) != len(expected) {
		return errors.New("loaded native inventory count mismatch")
	}
	for i, r := range list {
		flags := 0
		if r.IsPrivate() {
			flags |= 1
		}
		if r.IsGlobal() {
			flags |= 2
		}
		want := expected[i]
		if r.Identifier() != want.Identifier || r.Namespace() != want.Namespace || flags != want.Flags || !markerEqual(append([]string{}, r.Tags()...), want.Tags) {
			return errors.New("loaded native inventory mismatch")
		}
	}
	return nil
}

// Validate the same namespace closure/projection that build-marker-artifact.py
// binding() publishes. Whole source namespaces retain untagged dependencies and
// globals; the marker channel's post-match filter remains authoritative.
// Mirror capture-compiler-inputs.py verify_contract()/final_inputs(): the
// manifest must describe the actual accepted ordered roots and consumed bytes.
func markerValidateManifest(m markerManifest) error {
	prefix := []string{}
	for _, name := range []string{"filepath", "filename", "extension", "filetype", "file_type", "owner", "VBA"} {
		value := ""
		if name == "VBA" {
			value = "0"
		}
		prefix = append(prefix, "-d", name+"="+value)
	}
	accepted := []markerSource{}
	for _, v := range m.Validations {
		if (v.Exit != 0 && v.Exit != 1) || v.Accepted != (v.Exit == 0) || len(v.Argv) != 17 || !markerEqual(v.Argv[1:15], prefix) || v.Argv[15] != v.Candidate.Namespace+":"+v.Candidate.Path {
			return errors.New("validation compiler contract mismatch")
		}
		if v.Accepted {
			accepted = append(accepted, v.Candidate)
		}
	}
	if len(accepted) == 0 || len(m.Final.Argv) != 16+len(accepted) || len(m.Final.Sources) != len(accepted) || !markerEqual(m.Final.Argv[1:15], prefix) {
		return errors.New("final compiler contract mismatch")
	}
	for i, source := range m.Final.Sources {
		if source.Path != accepted[i].Path || source.Namespace != accepted[i].Namespace || m.Final.Argv[15+i] != source.Namespace+":"+source.Path {
			return errors.New("accepted compiler root/order mismatch")
		}
	}
	inputPaths := map[string]markerFingerprint{}
	for _, source := range append(append([]markerObserved{}, m.Final.Sources...), m.Final.Includes...) {
		path := source.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(m.Final.Cwd, path)
		}
		path = filepath.Clean(path)
		if previous, ok := inputPaths[path]; ok && previous != source.Observed {
			return errors.New("different final input bytes at one path")
		}
		inputPaths[path] = source.Observed
	}
	if !markerEqual(inputPaths, m.Inputs) {
		return errors.New("final input mapping mismatch")
	}
	output := m.Final.Argv[len(m.Final.Argv)-1]
	if !filepath.IsAbs(output) {
		output = filepath.Join(m.Final.Cwd, output)
	}
	if filepath.Clean(output) != m.Output {
		return errors.New("final compiler output mismatch")
	}
	dirs := map[string]bool{"/": true}
	paths := []string{}
	for _, source := range append(append([]markerObserved{}, m.Final.Sources...), m.Final.Includes...) {
		paths = append(paths, source.Path)
	}
	paths = append(paths, m.Final.Cwd+"/", m.Final.Argv[0], m.Final.Argv[len(m.Final.Argv)-1])
	for _, path := range paths {
		if !strings.HasPrefix(path, "/") {
			path = m.Final.Cwd + "/" + path
		}
		parts := strings.Split(path, "/")
		current := []string{}
		for _, part := range parts[:len(parts)-1] {
			if part == ".." {
				if len(current) > 0 {
					current = current[:len(current)-1]
				}
			} else if part != "" && part != "." {
				current = append(current, part)
			}
			dirs["/"+strings.Join(current, "/")] = true
		}
	}
	directoryList := []string{}
	for path := range dirs {
		if _, exists := inputPaths[path]; exists {
			return errors.New("final input file/directory collision")
		}
		directoryList = append(directoryList, path)
	}
	sort.Strings(directoryList)
	if !markerEqual(directoryList, m.Directories) {
		return errors.New("final directory mapping mismatch")
	}
	return nil
}

// markerRuleClosure consumes a validated native graph. Each rule is queued
// once; references are indexed by source, and namespace globals are expanded
// once even when that namespace has many markers. Inventory order preserves
// the producer's marker order and sorted retained indices without map iteration.
func markerRuleClosure(graph markerGraph) ([]int, []int, map[string]bool) {
	markers := []int{}
	retained := make([]bool, len(graph.Inventory))
	references := make([][]int, len(graph.Inventory))
	globals := map[string][]int{}
	for i, rule := range graph.Inventory {
		if rule.Flags&2 != 0 {
			globals[rule.Namespace] = append(globals[rule.Namespace], i)
		}
		for _, tag := range rule.Tags {
			if tag == markerTag {
				markers = append(markers, i)
				retained[i] = true
				break
			}
		}
	}
	for _, edge := range graph.References {
		references[edge[0]] = append(references[edge[0]], edge[1])
	}
	queue := append([]int{}, markers...)
	enqueue := func(index int) {
		if !retained[index] {
			retained[index] = true
			queue = append(queue, index)
		}
	}
	namespaces := map[string]bool{}
	for head := 0; head < len(queue); head++ {
		current := queue[head]
		namespace := graph.Inventory[current].Namespace
		namespaces[namespace] = true
		for _, dependency := range references[current] {
			enqueue(dependency)
		}
		for _, global := range globals[namespace] {
			enqueue(global)
		}
		delete(globals, namespace)
	}
	closure := []int{}
	for i, keep := range retained {
		if keep {
			closure = append(closure, i)
		}
	}
	return markers, closure, namespaces
}

func markerValidateBinding(b markerBinding, main, narrow markerManifest, mainIdentity markerFingerprint, mainManifest, narrowManifest markerFingerprint) error {
	if e := markerCheck(b.Schema == 1 && b.Construction == "complete-native-namespace-closure/1" && main.Schema == 2 && narrow.Schema == 2 && main.Final.Exit == 0 && narrow.Final.Exit == 0 && b.Main == mainIdentity && b.Main == main.Compiled && b.Marker == narrow.Compiled && b.MainManifest == mainManifest && b.MarkerManifest == narrowManifest, "marker main/graph identity mismatch"); e != nil {
		return e
	}
	for _, manifest := range []markerManifest{main, narrow} {
		if e := markerValidateManifest(manifest); e != nil {
			return e
		}
	}
	versions := map[string]string{"yarac": markerRuntimeVersion, "libyara": markerRuntimeVersion}
	if e := markerCheck(markerRuntimeVersion != "" && markerEqual(b.Versions, versions) && markerEqual(main.Versions, versions) && markerEqual(narrow.Versions, versions) && main.Final.CompilerVersion == markerRuntimeVersion && main.Final.LibraryVersion == markerRuntimeVersion && narrow.Final.CompilerVersion == markerRuntimeVersion && narrow.Final.LibraryVersion == markerRuntimeVersion, "compiler version mismatch"); e != nil {
		return e
	}
	if e := markerCheck(len(b.ABI) == 3 && b.ABI["descriptor_source"] == (markerFingerprint{"d71b05039b8dd71e3e472e5f48f6d81e1b86a5602ba214853fe3812b170944f3", 1400}) && b.ABI["libyara"].SHA256 == markerRuntimeLibYaraSHA256 && b.ABI["compiler"].SHA256 == markerRuntimeCompilerSHA256 && len(markerRuntimeLibYaraSHA256) == 64 && len(markerRuntimeCompilerSHA256) == 64 && markerEqual(b.ModuleIdentity, map[string]markerFingerprint{"static_libyara": b.ABI["libyara"]}), "linked compiler/library ABI mismatch"); e != nil {
		return e
	}
	if e := markerValidateExternals(b.Externals); e != nil {
		return e
	}
	if !markerEqual(main.Externals, b.Externals) || !markerEqual(narrow.Externals, b.Externals) {
		return errors.New("graph external identity mismatch")
	}
	for _, g := range []markerGraph{main.Final.Graph, narrow.Final.Graph} {
		if e := markerValidateGraph(g); e != nil {
			return e
		}
	}
	if !markerEqual(b.MainInventory, main.Final.Graph.Inventory) || !markerEqual(b.MarkerInventory, narrow.Final.Graph.Inventory) {
		return errors.New("binding native inventory mismatch")
	}
	graph := main.Final.Graph
	markers, closure, namespaces := markerRuleClosure(graph)
	if !markerEqual(markers, b.Closure.Markers) || !markerEqual(closure, b.Closure.Retained) {
		return errors.New("marker closure mismatch")
	}
	selected := []markerSource{}
	order := []string{}
	for _, v := range main.Validations {
		if v.Accepted && (len(markers) == 0 || namespaces[v.Candidate.Namespace]) {
			selected = append(selected, v.Candidate)
			order = append(order, v.Candidate.Namespace)
		}
	}
	if !markerEqual(selected, b.Sources) || !markerEqual(order, b.Namespaces) {
		return errors.New("marker source namespace/order mismatch")
	}
	selectedNS := map[string]bool{}
	for _, n := range order {
		selectedNS[n] = true
	}
	for n := range namespaces {
		if !selectedNS[n] {
			return errors.New("closure namespace missing")
		}
	}
	projected := []markerInventoryRule{}
	mapping := map[int]int{}
	for _, r := range graph.Inventory {
		if selectedNS[r.Namespace] {
			mapping[r.Index] = len(projected)
			r.Index = len(projected)
			projected = append(projected, r)
		}
	}
	if !markerEqual(projected, b.MarkerInventory) {
		return errors.New("marker projected inventory mismatch")
	}
	edges := [][2]int{}
	for _, edge := range graph.References {
		if source, ok := mapping[edge[0]]; ok {
			// Native graph validation guarantees same-namespace edges; a selected
			// complete namespace therefore contains every referenced target.
			target := mapping[edge[1]]
			edges = append(edges, [2]int{source, target})
		}
	}
	if !markerEqual(edges, narrow.Final.Graph.References) {
		return errors.New("marker projected references mismatch")
	}
	sources := []markerObserved{}
	for _, s := range main.Final.Sources {
		if selectedNS[s.Namespace] {
			sources = append(sources, s)
		}
	}
	if !markerEqual(sources, narrow.Final.Sources) || !markerEqual(b.Includes, narrow.Final.Includes) || main.Final.Cwd != narrow.Final.Cwd || len(main.Final.Argv) < 15 || len(narrow.Final.Argv) < 15 || !markerEqual(main.Final.Argv[:15], narrow.Final.Argv[:15]) {
		return errors.New("marker compiler/include invocation mismatch")
	}
	for p, v := range narrow.Inputs {
		if main.Inputs[p] != v {
			return errors.New("marker input identity mismatch")
		}
	}
	if len(b.MainDescriptors.Rules) != len(b.MainInventory) {
		return errors.New("main descriptor inventory mismatch")
	}
	descriptors := markerDescriptors{Externals: b.MainDescriptors.Externals}
	descriptors.Rules = b.MainDescriptors.Rules[:0:0]
	for i, r := range b.MainDescriptors.Rules {
		if r.Identity != [2]string{b.MainInventory[i].Namespace, b.MainInventory[i].Identifier} {
			return errors.New("main descriptor identity mismatch")
		}
		if selectedNS[r.Identity[0]] {
			descriptors.Rules = append(descriptors.Rules, r)
		}
	}
	if !markerEqual(descriptors, b.MarkerDescriptors) {
		return errors.New("marker descriptor projection mismatch")
	}
	return nil
}

func markerVerifyEnvelopeDirectories(root string) error {
	for _, path := range []string{root, filepath.Join(root, "compiler-inputs"), filepath.Join(root, "marker-artifact")} {
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("non-directory/symlink artifact component")
		}
	}
	return nil
}

// Every object reference is resolved through the verified inventory before
// native parsing, exactly as capture.get() binds its referenced bytes.
func markerVerifyGraphState(root string, files map[string]markerFingerprint, m markerManifest) error {
	object := func(fp markerFingerprint) error {
		if fp.Size < 0 || len(fp.SHA256) != 64 || strings.Trim(fp.SHA256, "0123456789abcdef") != "" || files["objects/"+fp.SHA256] != fp {
			return errors.New("retained object identity/reference mismatch")
		}
		return nil
	}
	if e := object(m.Compiled); e != nil {
		return e
	}
	for _, fp := range m.Inputs {
		if e := object(fp); e != nil {
			return e
		}
	}
	cursor, e := markerReadRegular(filepath.Join(root, "cursor"))
	if e != nil {
		return e
	}
	if len(cursor) != 9 || binary.LittleEndian.Uint64(cursor[:8]) != uint64(len(m.Validations)) || cursor[8] != 1 || markerBytesIdentity(cursor) != files["cursor"] {
		return errors.New("graph invocation cursor mismatch")
	}
	entries, e := os.ReadDir(filepath.Join(root, "invocations"))
	if e != nil {
		return e
	}
	expected := map[string]bool{"final.json": true}
	for i := range m.Validations {
		expected[fmt.Sprintf("validation-%d.json", i)] = true
	}
	if len(entries) != len(expected) {
		return errors.New("graph invocation inventory mismatch")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return errors.New("graph invocation slot mismatch")
		}
	}
	invocations := append(append([]markerInvocation{}, m.Validations...), m.Final)
	for i, inv := range invocations {
		phase, name := "validation", fmt.Sprintf("validation-%d.json", i)
		if i == len(m.Validations) {
			phase, name = "final", "final.json"
		}
		var record markerInvocationRecord
		identity, e := markerReadJSON(filepath.Join(root, "invocations", name), &record)
		if e != nil {
			return e
		}
		if identity != files["invocations/"+name] || record.Phase != phase || record.Index != i || !markerEqual(record.Invocation, inv) {
			return errors.New("graph invocation record mismatch")
		}
		for _, fp := range []markerFingerprint{inv.Native, inv.Stderr} {
			if e := object(fp); e != nil {
				return e
			}
		}
		if i < len(m.Validations) {
			if e := object(inv.Candidate.Snapshot); e != nil {
				return e
			}
		}
		for _, source := range append(append([]markerObserved{}, inv.Sources...), inv.Includes...) {
			if e := object(source.Observed); e != nil {
				return e
			}
		}
		for _, row := range []struct {
			suffix string
			fp     markerFingerprint
		}{{"native", inv.Native}, {"stderr", inv.Stderr}} {
			if files[fmt.Sprintf("%s-%d.%s", phase, i, row.suffix)] != row.fp {
				return errors.New("raw invocation evidence identity mismatch")
			}
		}
		if e := markerVerifyNativeGraph(filepath.Join(root, "objects", inv.Native.SHA256), inv); e != nil {
			return e
		}
	}
	return nil
}

func loadMarkerArtifact(root string, main *yara.Rules, identity markerFingerprint) (*yara.Rules, markerFingerprint, error) {
	if e := markerVerifyEnvelopeDirectories(root); e != nil {
		return nil, markerFingerprint{}, e
	}
	var index markerIndex
	if _, e := markerReadJSON(filepath.Join(root, "compiler-inputs/index.json"), &index); e != nil {
		return nil, markerFingerprint{}, e
	}
	slot, ok := index.Artifacts["main"]
	if !ok || len(index.Artifacts) != 2 || len(index.Metadata) != 2 || index.Metadata["libyara.version"].SHA256 == "" || index.Metadata["sources.json"].SHA256 == "" || index.Schema != 2 || slot.Compiled != "compiled.yac" || slot.Graph != "compiler-inputs/main" || slot.SHA256 != identity.SHA256 {
		return nil, markerFingerprint{}, errors.New("authoritative main artifact absent/mismatched")
	}
	if e := markerVerifyMetadata(root, index); e != nil {
		return nil, markerFingerprint{}, e
	}
	graphRoot := filepath.Join(root, "compiler-inputs/main")
	markerRoot := filepath.Join(root, "marker-artifact")
	for _, pair := range []struct {
		root  string
		files map[string]markerFingerprint
	}{{graphRoot, slot.Files}, {markerRoot, index.Marker.Files}} {
		if e := markerVerifyFiles(pair.root, pair.files); e != nil {
			return nil, markerFingerprint{}, e
		}
	}
	var b markerBinding
	var m, n markerManifest
	bi, e := markerReadJSON(filepath.Join(markerRoot, "binding.json"), &b)
	if e != nil {
		return nil, markerFingerprint{}, e
	}
	mi, e := markerReadJSON(filepath.Join(graphRoot, "manifest.json"), &m)
	if e != nil {
		return nil, markerFingerprint{}, e
	}
	ni, e := markerReadJSON(filepath.Join(markerRoot, "graph/manifest.json"), &n)
	if e != nil {
		return nil, markerFingerprint{}, e
	}
	if bi != index.Marker.Files["binding.json"] || mi != slot.Files["manifest.json"] || ni != index.Marker.Files["graph/manifest.json"] {
		return nil, markerFingerprint{}, errors.New("manifest snapshot hash mismatch")
	}
	if e = markerValidateBinding(b, m, n, identity, mi, ni); e != nil {
		return nil, markerFingerprint{}, e
	}
	markerFiles := map[string]markerFingerprint{}
	for path, fp := range index.Marker.Files {
		if strings.HasPrefix(path, "graph/") {
			markerFiles[strings.TrimPrefix(path, "graph/")] = fp
		}
	}
	for _, proof := range []struct {
		root     string
		files    map[string]markerFingerprint
		manifest markerManifest
	}{{graphRoot, slot.Files, m}, {filepath.Join(markerRoot, "graph"), markerFiles, n}} {
		if e = markerVerifyGraphState(proof.root, proof.files, proof.manifest); e != nil {
			return nil, markerFingerprint{}, e
		}
	}
	for _, pair := range []struct {
		path string
		want markerFingerprint
	}{{"abi/yarac", b.ABI["compiler"]}, {"abi/libyara.a", b.ABI["libyara"]}} {
		if index.Marker.Files[pair.path] != pair.want {
			return nil, markerFingerprint{}, errors.New("ABI file identity mismatch")
		}
	}
	if !markerEqual(slot.Versions, b.Versions) {
		return nil, markerFingerprint{}, errors.New("index version mismatch")
	}
	for _, pair := range []struct {
		path string
		want markerDescriptors
	}{{"main.descriptors", b.MainDescriptors}, {"marker.descriptors", b.MarkerDescriptors}} {
		data, e := markerReadFile(filepath.Join(markerRoot, pair.path))
		if e != nil {
			return nil, markerFingerprint{}, e
		}
		lines := []string{}
		for _, r := range pair.want.Rules {
			lines = append(lines, r.Lines...)
		}
		lines = append(lines, pair.want.Externals...)
		if string(data) != strings.Join(lines, "\n")+"\n" {
			return nil, markerFingerprint{}, errors.New("native descriptor identity mismatch")
		}
	}
	if e = markerNativeInventory(main, b.MainInventory); e != nil {
		return nil, markerFingerprint{}, e
	}
	rules, markerIdentity, e := markerLoadSnapshot(filepath.Join(markerRoot, "markers.yac"))
	if e != nil {
		return nil, markerFingerprint{}, e
	}
	if markerIdentity != b.Marker {
		rules.Destroy()
		return nil, markerFingerprint{}, errors.New("loaded marker hash mismatch")
	}
	if e = markerNativeInventory(rules, b.MarkerInventory); e != nil {
		rules.Destroy()
		return nil, markerFingerprint{}, e
	}
	return rules, markerIdentity, nil
}

// Successful new-main publication never keeps an old, unmatched marker object.
// A failed main preparation returns earlier and preserves the old generation.
var prepareMarkerArtifact = func(s *Scanner, main *yara.Rules, deny map[string]struct{}, mainContent string) (*yara.Rules, string) {
	if s.srcFile == "" || s.preparedMainIdentity.SHA256 == "" {
		return nil, ""
	}
	roots := []string{filepath.Dir(s.srcFile)}
	if s.markerSeedRoot != "" && s.markerSeedRoot != roots[0] {
		roots = append(roots, s.markerSeedRoot)
	}
	for _, root := range roots {
		rules, identity, e := loadMarkerArtifact(root, main, s.preparedMainIdentity)
		if e != nil {
			s.logf("PERF-18: marker artifact unavailable; full ruleset fallback: %v", e)
			continue
		}
		disableDeniedRules(rules, deny)
		return rules, fmt.Sprintf("%s:%s", identity.SHA256, mainContent)
	}
	return nil, ""
}
