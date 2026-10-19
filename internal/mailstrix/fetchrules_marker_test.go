package mailstrix

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const testMarkerAsset = "marker-tree.tar.gz"

// markerLog collects formatted log lines from fetchRules and the scanner.
type markerLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *markerLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *markerLog) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, sub) {
			return true
		}
	}
	return false
}

// tarEntry is one hand-built archive member for hostile-archive cases.
type tarEntry struct {
	hdr  tar.Header
	body []byte
}

func gzipTar(t testing.TB, entries []tarEntry) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, e := range entries {
		h := e.hdr
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return gzipBytes(t, raw.Bytes())
}

func gzipBytes(t testing.TB, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// fixtureTreeEntries returns the genuine fixture tree as sorted archive
// members (directories first by path order), optionally with extra members.
func fixtureTreeEntries(t testing.TB, root string) []tarEntry {
	t.Helper()
	var entries []tarEntry
	for _, top := range markerTreeEntries() {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				entries = append(entries, tarEntry{hdr: tar.Header{Name: rel + "/", Typeflag: tar.TypeDir, Mode: 0o755}})
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entries = append(entries, tarEntry{hdr: tar.Header{Name: rel, Typeflag: tar.TypeReg}, body: b})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].hdr.Name < entries[j].hdr.Name })
	return entries
}

// markerFixture is the genuine marker runtime fixture plus a published
// marker-tree archive built from it.
type markerFixture struct {
	root    string
	main    []byte
	archive []byte
}

func newMarkerFixture(t *testing.T) markerFixture {
	t.Helper()
	root := markerArtifactFixture(t)
	main, err := os.ReadFile(filepath.Join(root, "compiled.yac"))
	if err != nil {
		t.Fatal(err)
	}
	return markerFixture{root: root, main: main, archive: gzipTar(t, fixtureTreeEntries(t, root))}
}

func (f markerFixture) field(archive []byte) map[string]any {
	return map[string]any{
		"asset":           testMarkerAsset,
		"sha256":          sha256Hex(archive),
		"size":            len(archive),
		"libyara_sha256":  markerRuntimeLibYaraSHA256,
		"compiler_sha256": markerRuntimeCompilerSHA256,
		"main_sha256":     sha256Hex(f.main),
	}
}

// markerServer publishes a signed manifest whose optional marker field is the
// given raw JSON (omitted when nil), the bundle, and the archive. It counts
// requests per path so tests can prove what was or was not downloaded.
type markerServer struct {
	*httptest.Server
	hits sync.Map // path -> *atomic.Int64
}

func (s *markerServer) count(path string) int64 {
	if v, ok := s.hits.Load(path); ok {
		return v.(*atomic.Int64).Load()
	}
	return 0
}

func newMarkerServer(t *testing.T, yac []byte, ver int, marker any, archive []byte) *markerServer {
	t.Helper()
	m := RulesManifest{Version: ver, Generated: testRulesManifestGenerated, Checksum: "sha256:" + sha256Hex(yac), Libyara: "4.5.2", Rules: 1, Size: int64(len(yac))}
	base, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	body := base
	if marker != nil {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(base, &doc); err != nil {
			t.Fatal(err)
		}
		raw, ok := marker.(json.RawMessage)
		if !ok {
			if raw, err = json.Marshal(marker); err != nil {
				t.Fatal(err)
			}
		}
		doc["marker"] = raw
		if body, err = json.Marshal(doc); err != nil {
			t.Fatal(err)
		}
	}
	sig := signTestManifest(body)
	s := &markerServer{}
	mux := http.NewServeMux()
	for path, b := range map[string][]byte{"/" + manifestName: body, "/" + manifestSigName: []byte(sig), "/" + cachedRulesName: yac, "/" + testMarkerAsset: archive} {
		n := &atomic.Int64{}
		s.hits.Store(path, n)
		b := b
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) { n.Add(1); _, _ = w.Write(b) })
	}
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func fetchMarker(t *testing.T, srv *markerServer, cacheDir string, log *markerLog, opts fetchOptions) (FetchResult, error) {
	t.Helper()
	opts.allowHTTP = true
	if opts.logf == nil {
		opts.logf = log.logf
	}
	return fetchRules(context.Background(), srv.URL, cacheDir, "", srv.Client(), opts)
}

// treeSnapshot hashes every tree entry (and the cache pair) under dir.
func treeSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	for _, name := range append(markerTreeEntries(), cachedRulesName, manifestName) {
		top := filepath.Join(dir, name)
		if _, err := os.Lstat(top); errors.Is(err, os.ErrNotExist) {
			continue
		}
		err := filepath.WalkDir(top, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, path)
			if d.IsDir() {
				snap[rel+"/"] = "dir"
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			snap[rel] = sha256Hex(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return snap
}

func assertNoTree(t *testing.T, dir string) {
	t.Helper()
	for _, name := range markerTreeEntries() {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("marker tree entry %s present in cache (err=%v)", name, err)
		}
	}
}

func assertNoLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".marker-stage-") || strings.HasPrefix(e.Name(), ".rules-rollback-") || strings.HasPrefix(e.Name(), ".compiled-dl-") {
			t.Errorf("transaction leftover %s in cache", e.Name())
		}
	}
}

// fileScanner opens the cache bundle without managed-cache ownership, so it
// can inspect the cache while a fetch transaction holds the cache lock.
func fileScanner(t *testing.T, dir string, log *markerLog) *Scanner {
	t.Helper()
	s, err := NewScanner(&Config{RulesPath: filepath.Join(dir, cachedRulesName)}, log.logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// cacheScanner opens the managed cache the way serve does and reports whether
// the marker artifact (not the full-ruleset fallback) was loaded.
func cacheScanner(t *testing.T, dir string, log *markerLog) *Scanner {
	t.Helper()
	s, err := NewScanner(&Config{RulesPath: filepath.Join(dir, cachedRulesName), CacheDir: dir}, log.logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

const markerLoadedLog = "PERF-18: marker artifact loaded:"

// installFixtureTree performs a real successful marker install of v2 into dir.
func installFixtureTree(t *testing.T, f markerFixture, dir string) {
	t.Helper()
	srv := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
	res, err := fetchMarker(t, srv, dir, &markerLog{}, fetchOptions{})
	if err != nil || !res.Updated || res.Marker != MarkerStatusInstalled {
		t.Fatalf("baseline marker install: res=%+v err=%v", res, err)
	}
}

// --- positive: simulated refresh reaches the marker artifact path ---

func TestFetchRulesMarkerTreeRefreshLoadsMarkerArtifact(t *testing.T) {
	f := newMarkerFixture(t)
	dir := t.TempDir()
	old := compiledYacBytes(t, "rule old_one { condition: false }")
	seedLocal(t, dir, 1, old)
	log := &markerLog{}
	s := cacheScanner(t, dir, log)
	if s.markerRules.Load() != nil || log.has(markerLoadedLog) {
		t.Fatal("precondition: old cache must not have a marker artifact")
	}
	srv := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
	res, err := fetchMarker(t, srv, dir, log, fetchOptions{reload: s.reloadLockedCache})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updated || res.NewVersion != 2 || res.Marker != MarkerStatusInstalled {
		t.Fatalf("res = %+v, want updated v2 with installed marker tree", res)
	}
	if !log.has(markerLoadedLog) {
		t.Fatalf("refresh did not reach %q; log=%q", markerLoadedLog, log.lines)
	}
	if mr := s.markerRules.Load(); mr == nil || len(mr.GetRules()) != 9 {
		t.Fatal("reloaded scanner holds no 9-rule marker artifact")
	}
	if got, _ := os.ReadFile(filepath.Join(dir, cachedRulesName)); !bytes.Equal(got, f.main) {
		t.Fatal("new compiled.yac not installed")
	}
	if srv.count("/"+testMarkerAsset) != 1 {
		t.Fatalf("marker asset requests = %d, want 1", srv.count("/"+testMarkerAsset))
	}
	assertNoLeftovers(t, dir)
	// A fresh process on the same cache (restart) also binds the tree.
	log2 := &markerLog{}
	if cacheScanner(t, dir, log2).markerRules.Load() == nil || !log2.has(markerLoadedLog) {
		t.Fatal("restart on refreshed cache does not load the marker artifact")
	}
}

// The archive may carry a "./" root as produced by `tar -C dir .`.
func TestFetchRulesMarkerTreeAcceptsDotRootArchive(t *testing.T) {
	f := newMarkerFixture(t)
	entries := []tarEntry{{hdr: tar.Header{Name: "./", Typeflag: tar.TypeDir}}}
	for _, e := range fixtureTreeEntries(t, f.root) {
		e.hdr.Name = "./" + e.hdr.Name
		entries = append(entries, e)
	}
	archive := gzipTar(t, entries)
	dir := t.TempDir()
	srv := newMarkerServer(t, f.main, 2, f.field(archive), archive)
	res, err := fetchMarker(t, srv, dir, &markerLog{}, fetchOptions{})
	if err != nil || res.Marker != MarkerStatusInstalled {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if cacheScanner(t, dir, &markerLog{}).markerRules.Load() == nil {
		t.Fatal("dot-root archive tree did not load")
	}
}

// --- negative controls: each drops only the tree; compiled.yac installs ---

func expectTreeDropped(t *testing.T, f markerFixture, dir string, srv *markerServer, log *markerLog, opts fetchOptions, wantStatus, wantReason string) FetchResult {
	t.Helper()
	res, err := fetchMarker(t, srv, dir, log, opts)
	if err != nil {
		t.Fatalf("compiled.yac update must not fail on a marker problem: %v", err)
	}
	if !res.Updated || res.NewVersion != 3 {
		t.Fatalf("res = %+v, want compiled.yac updated to v3", res)
	}
	if !strings.HasPrefix(res.Marker, wantStatus) || !strings.Contains(res.Marker, wantReason) {
		t.Fatalf("marker status = %q, want %q containing %q", res.Marker, wantStatus, wantReason)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, cachedRulesName)); !bytes.Equal(got, f.main) {
		t.Fatal("compiled.yac was not installed")
	}
	assertNoTree(t, dir)
	assertNoLeftovers(t, dir)
	l := &markerLog{}
	s := cacheScanner(t, dir, l)
	if s.markerRules.Load() != nil || l.has(markerLoadedLog) || len(s.rules.Load().GetRules()) != 10 {
		t.Fatal("cache after a dropped tree must serve the full 10-rule main set without a marker artifact")
	}
	return res
}

// newDroppedCase starts from a cache holding a valid v2 tree, so every
// negative case also proves stale-tree removal for the v3 bundle.
func newDroppedCase(t *testing.T) (markerFixture, string) {
	t.Helper()
	f := newMarkerFixture(t)
	dir := t.TempDir()
	installFixtureTree(t, f, dir)
	return f, dir
}

func TestFetchRulesMarkerTreeWrongHash(t *testing.T) {
	f, dir := newDroppedCase(t)
	field := f.field(f.archive)
	field["sha256"] = sha256Hex([]byte("another archive"))
	srv := newMarkerServer(t, f.main, 3, field, f.archive)
	log := &markerLog{}
	expectTreeDropped(t, f, dir, srv, log, fetchOptions{}, MarkerStatusRejected, "verify marker tree: sha256")
	if !log.has("marker tree refused") {
		t.Fatal("rejected tree was not logged")
	}
}

func TestFetchRulesMarkerTreeWrongABI(t *testing.T) {
	for _, key := range []string{"libyara_sha256", "compiler_sha256"} {
		t.Run(key, func(t *testing.T) {
			f, dir := newDroppedCase(t)
			field := f.field(f.archive)
			field[key] = strings.Repeat("ab", 32)
			srv := newMarkerServer(t, f.main, 3, field, f.archive)
			expectTreeDropped(t, f, dir, srv, &markerLog{}, fetchOptions{}, MarkerStatusSkipped, "identity differs")
			if n := srv.count("/" + testMarkerAsset); n != 0 {
				t.Fatalf("ABI-mismatched tree was downloaded %d times", n)
			}
		})
	}
	t.Run("unsupported-build", func(t *testing.T) {
		f, dir := newDroppedCase(t)
		srv := newMarkerServer(t, f.main, 3, f.field(f.archive), f.archive)
		markerRuntimeLibYaraSHA256 = ""
		expectTreeDropped(t, f, dir, srv, &markerLog{}, fetchOptions{}, MarkerStatusSkipped, "identity differs")
	})
}

func hostileArchive(t *testing.T, f markerFixture, extra ...tarEntry) []byte {
	t.Helper()
	return gzipTar(t, append(fixtureTreeEntries(t, f.root), extra...))
}

func TestFetchRulesMarkerTreeHostileArchives(t *testing.T) {
	outside := t.TempDir()
	for _, tc := range []struct {
		name   string
		entry  tarEntry
		reason string
	}{
		{"tar-slip-dotdot", tarEntry{hdr: tar.Header{Name: "compiler-inputs/../../escaped", Typeflag: tar.TypeReg}, body: []byte("x")}, "leaves or obscures"},
		{"tar-slip-leading-dotdot", tarEntry{hdr: tar.Header{Name: "../escaped", Typeflag: tar.TypeReg}, body: []byte("x")}, "leaves or obscures"},
		{"absolute-path", tarEntry{hdr: tar.Header{Name: filepath.Join(outside, "escaped"), Typeflag: tar.TypeReg}, body: []byte("x")}, "is absolute"},
		{"symlink", tarEntry{hdr: tar.Header{Name: "marker-artifact/link", Typeflag: tar.TypeSymlink, Linkname: outside}}, "disallowed type"},
		{"hardlink", tarEntry{hdr: tar.Header{Name: "marker-artifact/hard", Typeflag: tar.TypeLink, Linkname: "sources.json"}}, "disallowed type"},
		{"char-device", tarEntry{hdr: tar.Header{Name: "marker-artifact/dev", Typeflag: tar.TypeChar}}, "disallowed type"},
		{"block-device", tarEntry{hdr: tar.Header{Name: "marker-artifact/blk", Typeflag: tar.TypeBlock}}, "disallowed type"},
		{"fifo", tarEntry{hdr: tar.Header{Name: "marker-artifact/fifo", Typeflag: tar.TypeFifo}}, "disallowed type"},
		{"outside-tree", tarEntry{hdr: tar.Header{Name: "compiled.yac", Typeflag: tar.TypeReg}, body: []byte("x")}, "outside the marker tree"},
		{"duplicate-file", tarEntry{hdr: tar.Header{Name: "sources.json", Typeflag: tar.TypeReg}, body: []byte("[]")}, "file exists"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, dir := newDroppedCase(t)
			archive := hostileArchive(t, f, tc.entry)
			srv := newMarkerServer(t, f.main, 3, f.field(archive), archive)
			expectTreeDropped(t, f, dir, srv, &markerLog{}, fetchOptions{}, MarkerStatusRejected, tc.reason)
			for _, p := range []string{filepath.Join(outside, "escaped"), filepath.Join(dir, "escaped"), filepath.Join(filepath.Dir(dir), "escaped")} {
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("hostile entry escaped the staging tree to %s", p)
				}
			}
		})
	}
}

func TestFetchRulesMarkerTreeOversize(t *testing.T) {
	t.Run("served-larger-than-signed", func(t *testing.T) {
		f, dir := newDroppedCase(t)
		field := f.field(f.archive)
		srv := newMarkerServer(t, f.main, 3, field, append(append([]byte{}, f.archive...), 0))
		expectTreeDropped(t, f, dir, srv, &markerLog{}, fetchOptions{}, MarkerStatusRejected, "download marker tree: downloaded size")
	})
	t.Run("expanded-tree-over-cap", func(t *testing.T) {
		// A header claiming more than the tree cap is refused before any byte
		// of it is written; the stream itself stays tiny.
		f, dir := newDroppedCase(t)
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		if err := tw.WriteHeader(&tar.Header{Name: "sources.json", Typeflag: tar.TypeReg, Size: maxMarkerTreeBytes + 1, Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		archive := gzipBytes(t, raw.Bytes())
		srv := newMarkerServer(t, f.main, 3, f.field(archive), archive)
		expectTreeDropped(t, f, dir, srv, &markerLog{}, fetchOptions{}, MarkerStatusRejected, "marker tree exceeds")
	})
	t.Run("too-many-entries", func(t *testing.T) {
		f, dir := newDroppedCase(t)
		entries := make([]tarEntry, maxMarkerTreeEntries+1)
		for i := range entries {
			entries[i] = tarEntry{hdr: tar.Header{Name: "compiler-inputs/", Typeflag: tar.TypeDir}}
		}
		archive := gzipTar(t, entries)
		srv := newMarkerServer(t, f.main, 3, f.field(archive), archive)
		expectTreeDropped(t, f, dir, srv, &markerLog{}, fetchOptions{}, MarkerStatusRejected, "more than")
	})
}

func TestFetchRulesMarkerTreeTruncated(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  func([]byte) []byte
	}{
		{"half-stream", func(b []byte) []byte { return b[:len(b)/2] }},
		{"missing-gzip-trailer", func(b []byte) []byte { return b[:len(b)-4] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, dir := newDroppedCase(t)
			archive := tc.cut(f.archive)
			// The publisher signs the truncated bytes: integrity checks pass and
			// only extraction can notice.
			srv := newMarkerServer(t, f.main, 3, f.field(archive), archive)
			expectTreeDropped(t, f, dir, srv, &markerLog{}, fetchOptions{}, MarkerStatusRejected, "extract marker tree")
		})
	}
}

// A well-formed archive whose content fails the loader is refused before the
// swap (pre-swap loadMarkerArtifact), never installed.
func TestFetchRulesMarkerTreeLoaderRejectsBeforeSwap(t *testing.T) {
	f, dir := newDroppedCase(t)
	entries := fixtureTreeEntries(t, f.root)
	for i := range entries {
		if entries[i].hdr.Name == "marker-artifact/markers.yac" {
			entries[i].body = append(append([]byte{}, entries[i].body...), 0)
		}
	}
	archive := gzipTar(t, entries)
	srv := newMarkerServer(t, f.main, 3, f.field(archive), archive)
	expectTreeDropped(t, f, dir, srv, &markerLog{}, fetchOptions{}, MarkerStatusRejected, "marker tree does not load")
}

// D1: every malformed/invalid marker field drops only the marker part.
func TestFetchRulesMarkerFieldMalformedInstallsCompiledOnly(t *testing.T) {
	f := newMarkerFixture(t)
	good := f.field(f.archive)
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for key, val := range good {
			m[key] = val
		}
		m[k] = v
		return m
	}
	for _, tc := range []struct {
		name   string
		marker any
		reason string
	}{
		{"bad-hex", with("sha256", strings.Repeat("zz", 32)), "sha256 must be 64 hex"},
		{"short-hex", with("libyara_sha256", "abcd"), "libyara_sha256 must be 64 hex"},
		{"bad-compiler-hex", with("compiler_sha256", ""), "compiler_sha256 must be 64 hex"},
		{"negative-size", with("size", -1), "marker size must be"},
		{"zero-size", with("size", 0), "marker size must be"},
		{"oversize-size", with("size", int64(maxMarkerArchiveBytes)+1), "marker size must be"},
		{"size-overflow", json.RawMessage(`{"size": 1e400}`), "marker field"},
		{"main-mismatch", with("main_sha256", strings.Repeat("0", 64)), "does not match the manifest"},
		{"asset-path", with("asset", "../marker-tree.tar.gz"), "plain *.tar.gz"},
		{"asset-slash", with("asset", "a/marker-tree.tar.gz"), "plain *.tar.gz"},
		{"asset-not-tgz", with("asset", "marker-tree.zip"), "plain *.tar.gz"},
		{"wrong-type", json.RawMessage(`"marker-tree.tar.gz"`), "marker field"},
		{"wrong-field-type", with("size", "12"), "marker field"},
		{"oversize-field", with("pad", strings.Repeat("p", maxRulesMarkerFieldBytes)), "exceeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			srv := newMarkerServer(t, f.main, 3, tc.marker, f.archive)
			log := &markerLog{}
			res := expectTreeDropped(t, f, dir, srv, log, fetchOptions{}, MarkerStatusRejected, tc.reason)
			if !log.has("marker field ignored") {
				t.Fatalf("malformed field was not logged as an error; res=%+v", res)
			}
			if n := srv.count("/" + testMarkerAsset); n != 0 {
				t.Fatalf("malformed field still downloaded the tree %d times", n)
			}
			if lm := readLocalManifest(filepath.Join(dir, manifestName)); lm.Version != 3 {
				t.Fatalf("local manifest version = %d, want 3", lm.Version)
			}
		})
	}
}

// A signature failure still refuses the whole manifest, marker or not.
func TestFetchRulesMarkerFieldDoesNotBypassSignature(t *testing.T) {
	f := newMarkerFixture(t)
	dir := t.TempDir()
	m := RulesManifest{Version: 3, Generated: testRulesManifestGenerated, Checksum: "sha256:" + sha256Hex(f.main), Libyara: "4.5.2", Rules: 1, Size: int64(len(f.main))}
	base, _ := json.Marshal(m)
	signed := signTestManifest(base)
	var doc map[string]any
	_ = json.Unmarshal(base, &doc)
	doc["marker"] = f.field(f.archive)
	served, _ := json.Marshal(doc) // marker added AFTER signing
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/"+manifestName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(served) })
	mux.HandleFunc("/"+manifestSigName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(signed)) })
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = w.Write(f.archive) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	_, err := fetchRules(context.Background(), srv.URL, dir, "", srv.Client(), fetchOptions{allowHTTP: true})
	if err == nil || !strings.Contains(err.Error(), "refusing update") {
		t.Fatalf("unsigned marker addition err = %v, want signature refusal", err)
	}
	if hits.Load() != 0 {
		t.Fatal("refused manifest still downloaded an asset")
	}
	assertNoTree(t, dir)
}

// --- rollback and interruption ---

func TestFetchRulesMarkerTreeFailedReloadRestoresPairAndTree(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withTree bool
	}{{"new-bundle-without-marker", false}, {"new-bundle-with-marker", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMarkerFixture(t)
			dir := t.TempDir()
			installFixtureTree(t, f, dir)
			// Distinguish the live tree from the archive: an extra file in a
			// directory the loader does not inventory must come back on restore.
			if err := os.WriteFile(filepath.Join(dir, "compiler-inputs", "old-generation"), []byte("v2"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := treeSnapshot(t, dir)
			yac, marker := compiledYacBytes(t, nRules(10)), any(nil)
			if tc.withTree {
				yac, marker = f.main, f.field(f.archive)
			}
			srv := newMarkerServer(t, yac, 3, marker, f.archive)
			reloads := 0
			_, err := fetchMarker(t, srv, dir, &markerLog{}, fetchOptions{allowHTTP: true, reload: func() error {
				reloads++
				// The new pair is live while the reload runs.
				if tc.withTree {
					if _, err := os.Stat(filepath.Join(dir, "compiler-inputs", "old-generation")); !errors.Is(err, os.ErrNotExist) {
						t.Error("reload saw the old tree instead of the new one")
					}
				} else {
					assertNoTree(t, dir)
				}
				return errors.New("injected reload failure")
			}})
			if err == nil || !strings.Contains(err.Error(), "injected reload failure") || reloads != 1 {
				t.Fatalf("err=%v reloads=%d, want the reload failure", err, reloads)
			}
			after := treeSnapshot(t, dir)
			if fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatalf("failed reload did not restore the previous pair and tree:\nbefore=%v\nafter=%v", before, after)
			}
			assertNoLeftovers(t, dir)
			if lm := trustedLocalManifest(filepath.Join(dir, cachedRulesName), filepath.Join(dir, manifestName)); lm.Version != 2 {
				t.Fatalf("restored local manifest version = %d, want 2", lm.Version)
			}
			if cacheScanner(t, dir, &markerLog{}).markerRules.Load() == nil {
				t.Fatal("restored v2 pair+tree no longer loads the marker artifact")
			}
		})
	}
}

// interruptRenames fails the k-th marker tree rename. At that instant (the
// state a crash would leave) a fresh scanner must load the cache safely: the
// marker artifact only with a complete matching tree, otherwise full main.
func interruptRenames(t *testing.T, dir string, k int, inspect func()) *int {
	t.Helper()
	calls := 0
	prior := markerTreeRename
	t.Cleanup(func() { markerTreeRename = prior })
	markerTreeRename = func(from, to string) error {
		calls++
		if calls == k {
			inspect()
			return fmt.Errorf("injected rename interruption %d", k)
		}
		return prior(from, to)
	}
	return &calls
}

func TestFetchRulesMarkerTreeInterruptedRenamesFallBackSafely(t *testing.T) {
	t.Run("retire-phase", func(t *testing.T) {
		// Live: v2 fixture pair + tree. New: v3 bundle without marker, so the
		// swap only retires the four tree entries.
		for k := 1; k <= len(markerTreeEntries()); k++ {
			t.Run(fmt.Sprint(k), func(t *testing.T) {
				f := newMarkerFixture(t)
				dir := t.TempDir()
				installFixtureTree(t, f, dir)
				before := treeSnapshot(t, dir)
				srv := newMarkerServer(t, compiledYacBytes(t, nRules(10)), 3, nil, nil)
				inspected := false
				interruptRenames(t, dir, k, func() {
					inspected = true
					s := fileScanner(t, dir, &markerLog{})
					complete := k == 1 // nothing moved yet: the old pair is still whole
					if (s.markerRules.Load() != nil) != complete || len(s.rules.Load().GetRules()) != 10 {
						t.Errorf("interrupted at rename %d: marker loaded=%v, want %v with full main", k, s.markerRules.Load() != nil, complete)
					}
				})
				_, err := fetchMarker(t, srv, dir, &markerLog{}, fetchOptions{})
				if err == nil || !strings.Contains(err.Error(), "injected rename interruption") || !inspected {
					t.Fatalf("err=%v inspected=%v", err, inspected)
				}
				if after := treeSnapshot(t, dir); fmt.Sprint(after) != fmt.Sprint(before) {
					t.Fatalf("interrupted swap not rolled back:\nbefore=%v\nafter=%v", before, after)
				}
				assertNoLeftovers(t, dir)
			})
		}
	})
	t.Run("install-phase", func(t *testing.T) {
		// Live: one-rule v1 without tree. New: v2 fixture pair + tree, so the
		// swap only installs; a partial new tree beside the old bundle must
		// never bind.
		for k := 1; k <= len(markerTreeEntries()); k++ {
			t.Run(fmt.Sprint(k), func(t *testing.T) {
				f := newMarkerFixture(t)
				dir := t.TempDir()
				seedLocal(t, dir, 1, compiledYacBytes(t, "rule old_one { condition: false }"))
				before := treeSnapshot(t, dir)
				srv := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
				inspected := false
				interruptRenames(t, dir, k, func() {
					inspected = true
					s := fileScanner(t, dir, &markerLog{})
					if s.markerRules.Load() != nil || len(s.rules.Load().GetRules()) != 1 {
						t.Errorf("interrupted at install rename %d: partial tree bound or main changed", k)
					}
				})
				_, err := fetchMarker(t, srv, dir, &markerLog{}, fetchOptions{})
				if err == nil || !strings.Contains(err.Error(), "install marker tree") || !inspected {
					t.Fatalf("err=%v inspected=%v", err, inspected)
				}
				if after := treeSnapshot(t, dir); fmt.Sprint(after) != fmt.Sprint(before) {
					t.Fatalf("interrupted install not rolled back:\nbefore=%v\nafter=%v", before, after)
				}
				assertNoLeftovers(t, dir)
			})
		}
	})
}

// --- MAILSTRIX_RULES_MARKERS ---

// Off wins over an invalid field too: nothing is downloaded or logged as an
// error for a part the operator opted out of.
func TestFetchRulesMarkersOffIgnoresInvalidField(t *testing.T) {
	f := newMarkerFixture(t)
	field := f.field(f.archive)
	field["size"] = -1
	srv := newMarkerServer(t, f.main, 3, field, f.archive)
	log := &markerLog{}
	expectTreeDropped(t, f, t.TempDir(), srv, log, fetchOptions{markersOff: true}, MarkerStatusDisabled, "")
	if log.has("ERROR") || srv.count("/"+testMarkerAsset) != 0 {
		t.Fatalf("off mode logged an error or downloaded the tree: %q", log.lines)
	}
}

func TestFetchRulesMarkersOffDownloadsNothing(t *testing.T) {
	f, dir := newDroppedCase(t)
	srv := newMarkerServer(t, f.main, 3, f.field(f.archive), f.archive)
	expectTreeDropped(t, f, dir, srv, &markerLog{}, fetchOptions{markersOff: true}, MarkerStatusDisabled, "")
	if n := srv.count("/" + testMarkerAsset); n != 0 {
		t.Fatalf("MAILSTRIX_RULES_MARKERS=off downloaded the tree %d times", n)
	}
	if srv.count("/"+cachedRulesName) != 1 {
		t.Fatal("compiled.yac was not downloaded")
	}
}

func TestParseRulesMarkersMode(t *testing.T) {
	for _, tc := range []struct {
		in  string
		off bool
		ok  bool
	}{
		{"", false, true}, {"auto", false, true}, {" AUTO ", false, true}, {"off", true, true}, {"Off", true, true},
		{"on", false, false}, {"0", false, false}, {"false", false, false}, {"autooff", false, false}, {"of", false, false},
	} {
		off, err := parseRulesMarkersMode(tc.in)
		if (err == nil) != tc.ok || off != tc.off {
			t.Errorf("parseRulesMarkersMode(%q) = %v, %v", tc.in, off, err)
		}
		if err != nil && !strings.Contains(err.Error(), rulesMarkersEnv) {
			t.Errorf("error %q does not name %s", err, rulesMarkersEnv)
		}
		if got := (&Config{RulesMarkers: tc.in}).ValidateRulesMarkers(); (got == nil) != tc.ok {
			t.Errorf("ValidateRulesMarkers(%q) = %v", tc.in, got)
		}
	}
}

func TestInvalidRulesMarkersRejected(t *testing.T) {
	t.Setenv(rulesMarkersEnv, "sometimes")
	cfg := LoadConfig()
	if cfg.RulesMarkers != "sometimes" || cfg.ValidateRulesMarkers() == nil {
		t.Fatalf("LoadConfig RulesMarkers=%q must fail validation", cfg.RulesMarkers)
	}
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	if _, err := FetchRulesWithOptions(context.Background(), srv.URL, t.TempDir(), "", srv.Client(), FetchRulesOptions{AllowHTTP: true, Markers: "sometimes"}); err == nil || !strings.Contains(err.Error(), rulesMarkersEnv) {
		t.Fatalf("FetchRulesWithOptions err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("invalid marker mode still made a request")
	}
	if _, err := NewRulesUpdater(&Config{RulesMarkers: "sometimes"}, &Scanner{}, "4.5.2", nil); err == nil || !strings.Contains(err.Error(), rulesMarkersEnv) {
		t.Fatalf("NewRulesUpdater err = %v", err)
	}
	t.Setenv(rulesMarkersEnv, "")
	if LoadConfig().ValidateRulesMarkers() != nil {
		t.Fatal("unset MAILSTRIX_RULES_MARKERS must default to auto")
	}
}

func TestFetchRulesWithOptionsModes(t *testing.T) {
	f := newMarkerFixture(t)
	for _, mode := range []string{"", "auto", "off"} {
		t.Run("mode="+mode, func(t *testing.T) {
			dir := t.TempDir()
			srv := newMarkerServer(t, f.main, 2, f.field(f.archive), f.archive)
			res, err := FetchRulesWithOptions(context.Background(), srv.URL, dir, "", srv.Client(), FetchRulesOptions{AllowHTTP: true, Markers: mode})
			if err != nil {
				t.Fatal(err)
			}
			want := MarkerStatusInstalled
			if mode == "off" {
				want = MarkerStatusDisabled
			}
			if res.Marker != want {
				t.Fatalf("marker = %q, want %q", res.Marker, want)
			}
		})
	}
}

func TestRulesUpdaterPassesMarkersMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		off  bool
	}{{"", false}, {"auto", false}, {"off", true}} {
		u, err := NewRulesUpdater(&Config{RulesMarkers: tc.mode}, &Scanner{}, "4.5.2", nil)
		if err != nil || u.markersOff != tc.off {
			t.Fatalf("mode %q: markersOff=%v err=%v", tc.mode, u != nil && u.markersOff, err)
		}
	}
}

// --- old manifests and old clients ---

func TestFetchRulesManifestWithoutMarkerUnchanged(t *testing.T) {
	f, dir := newDroppedCase(t)
	srv := newMarkerServer(t, f.main, 3, nil, f.archive)
	log := &markerLog{}
	expectTreeDropped(t, f, dir, srv, log, fetchOptions{}, MarkerStatusAbsent, "")
	if n := srv.count("/" + testMarkerAsset); n != 0 {
		t.Fatalf("manifest without marker downloaded an asset %d times", n)
	}
	if log.has("marker") {
		t.Fatalf("manifest without marker logged marker diagnostics: %q", log.lines)
	}
	srvNull := newMarkerServer(t, f.main, 4, json.RawMessage(`null`), f.archive)
	if res, err := fetchMarker(t, srvNull, dir, log, fetchOptions{}); err != nil || res.Marker != MarkerStatusAbsent {
		t.Fatalf("null marker: res=%+v err=%v", res, err)
	}
}

// oldRulesManifest is the pre-marker client struct, decoded the way older
// releases decode the signed bytes (non-strict json.Unmarshal).
type oldRulesManifest struct {
	Version   int          `json:"version"`
	Generated string       `json:"generated"`
	Checksum  string       `json:"checksum"`
	Libyara   string       `json:"libyara"`
	Rules     int          `json:"rules"`
	Size      int64        `json:"size"`
	Sources   []RuleSource `json:"sources,omitempty"`
}

func TestOldClientDecodesManifestWithMarker(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	body := []byte(`{"version":7,"generated":"2026-06-18T00:00:00Z","checksum":"sha256:` + sum + `","libyara":"4.5.2","rules":1,"size":3,"marker":{"asset":"marker-tree.tar.gz","sha256":"` + sum + `","size":9,"libyara_sha256":"` + sum + `","compiler_sha256":"` + sum + `","main_sha256":"` + sum + `","future":true}}`)
	var old oldRulesManifest
	if err := json.Unmarshal(body, &old); err != nil || old.Version != 7 || old.Checksum != "sha256:"+sum {
		t.Fatalf("old client decode: %+v err=%v", old, err)
	}
	m, absent, err := manifestMarker(body, "sha256:"+sum)
	if err != nil || absent || m.Asset != testMarkerAsset || m.Size != 9 {
		t.Fatalf("new client marker: %+v absent=%v err=%v", m, absent, err)
	}
	// Uppercase hex is normalized; the local record never persists the field.
	upper := bytes.ReplaceAll(body, []byte(sum), []byte(strings.ToUpper(sum)))
	if m, _, err = manifestMarker(upper, "sha256:"+sum); err != nil || m.SHA256 != sum {
		t.Fatalf("uppercase hex: %+v err=%v", m, err)
	}
	b, _ := json.Marshal(RulesManifest{Version: 1, marker: m})
	if bytes.Contains(b, []byte("marker")) {
		t.Fatalf("local manifest record leaked the marker field: %s", b)
	}
}

// --- extraction unit cases not reachable through a valid fixture ---

func TestMarkerTreeEntryName(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		dir  bool
		want string
		ok   bool
	}{
		{"compiler-inputs/", true, "compiler-inputs", true},
		{"./compiler-inputs/main/x", false, "compiler-inputs/main/x", true},
		{"marker-artifact/markers.yac", false, "marker-artifact/markers.yac", true},
		{"sources.json", false, "sources.json", true},
		{"libyara.version", false, "libyara.version", true},
		{"./", true, "", true},
		{".", true, "", true},
		{"", false, "", false},
		{"./", false, "", false},
		{"compiler-inputs", false, "", false},
		{"sources.json/", true, "", false},
		{"compiler-inputs//x", false, "", false},
		{"compiler-inputs/./x", false, "", false},
		{"compiler-inputs/..", true, "", false},
		{"..", true, "", false},
		{"/compiler-inputs/x", false, "", false},
		{"compiler-inputs\\x", false, "", false},
		{"compiler-inputs/x\x00", false, "", false},
		{"other/x", false, "", false},
		{"compiled.yac.manifest.json", false, "", false},
	} {
		got, err := markerTreeEntryName(tc.raw, tc.dir)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("markerTreeEntryName(%q, %v) = %q, %v", tc.raw, tc.dir, got, err)
		}
	}
}

func TestExtractMarkerTreeRejects(t *testing.T) {
	write := func(t *testing.T, b []byte) string {
		p := filepath.Join(t.TempDir(), "a.tar.gz")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var global bytes.Buffer
	tw := tar.NewWriter(&global)
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "x"}})
	_ = tw.Close()
	big := bytes.Repeat([]byte{0}, maxMarkerArchiveTrailer+512*4)
	var trailing bytes.Buffer
	tw = tar.NewWriter(&trailing)
	_ = tw.Close()
	trailing.Write(big)
	for _, tc := range []struct {
		name    string
		archive []byte
		reason  string
	}{
		{"not-gzip", bytes.Repeat([]byte("plain"), 20), "gzip: invalid header"},
		{"global-header", gzipBytes(t, global.Bytes()), "disallowed type"},
		{"file-dir-collision", gzipTar(t, []tarEntry{{hdr: tar.Header{Name: "compiler-inputs/a", Typeflag: tar.TypeReg}, body: []byte("1")}, {hdr: tar.Header{Name: "compiler-inputs/a/b", Typeflag: tar.TypeReg}, body: []byte("2")}}), "collides"},
		{"dir-over-file", gzipTar(t, []tarEntry{{hdr: tar.Header{Name: "compiler-inputs/a", Typeflag: tar.TypeReg}, body: []byte("1")}, {hdr: tar.Header{Name: "compiler-inputs/a/", Typeflag: tar.TypeDir}}}), "collides"},
		{"top-dir-as-file", gzipTar(t, []tarEntry{{hdr: tar.Header{Name: "marker-artifact", Typeflag: tar.TypeReg}, body: []byte("1")}}), "outside the marker tree"},
		{"trailing-garbage", gzipBytes(t, trailing.Bytes()), "trailing bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			err := extractMarkerTree(context.Background(), write(t, tc.archive), dest)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err = %v, want %q", err, tc.reason)
			}
		})
	}
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := extractMarkerTree(ctx, write(t, gzipTar(t, nil)), t.TempDir()); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing-archive", func(t *testing.T) {
		if err := extractMarkerTree(context.Background(), filepath.Join(t.TempDir(), "absent"), t.TempDir()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestMarkerTreeSwapRestoreReportsErrors(t *testing.T) {
	dir := t.TempDir()
	rollback := t.TempDir()
	w := newMarkerTreeSwap(dir, rollback)
	w.moved = []string{"sources.json"} // never actually moved aside
	if err := w.restore(); err == nil {
		t.Fatal("restore of a missing retired entry must report the failure")
	}
	if err := os.WriteFile(filepath.Join(rollback, "marker-tree"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newMarkerTreeSwap(dir, rollback).retire(); err == nil {
		t.Fatal("retire must fail when the aside directory cannot be created")
	}
}

func TestStageMarkerTreeBundleUnreadable(t *testing.T) {
	if err := verifyStagedMarkerTree(t.TempDir(), filepath.Join(t.TempDir(), "absent.yac")); err == nil {
		t.Fatal("verifyStagedMarkerTree with an unreadable bundle must fail")
	}
	bad := filepath.Join(t.TempDir(), "bad.yac")
	_ = os.WriteFile(bad, []byte("not yara"), 0o600)
	if err := verifyStagedMarkerTree(t.TempDir(), bad); err == nil {
		t.Fatal("verifyStagedMarkerTree with a corrupt bundle must fail")
	}
}

func TestMarkerHexDigest(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	if got, err := markerHex64("sha256", strings.ToUpper(hex.EncodeToString(sum[:]))); err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestManifestMarkerRejectsUndecodableManifest(t *testing.T) {
	if _, _, err := manifestMarker([]byte("{"), "sha256:"+strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "marker field") {
		t.Fatalf("err = %v", err)
	}
}

// Without an injected logger the marker diagnostics reach the standard log.
func TestPrepareRemoteMarkerTreeDefaultLogger(t *testing.T) {
	buf := captureLog(t)
	remote := RulesManifest{Version: 9, markerErr: errors.New("bad marker")}
	if stage, status := prepareRemoteMarkerTree(context.Background(), nil, "", t.TempDir(), "", remote, fetchOptions{}); stage != "" || !strings.HasPrefix(status, MarkerStatusRejected) {
		t.Fatalf("stage=%q status=%q", stage, status)
	}
	if !strings.Contains(buf.String(), "[mailstrix] ERROR: rules manifest v9 marker field ignored") {
		t.Fatalf("log = %q", buf.String())
	}
}

func TestExtractMarkerTreeHeaderErrors(t *testing.T) {
	write := func(t *testing.T, b []byte) string {
		p := filepath.Join(t.TempDir(), "a.tar.gz")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	corrupt := make([]byte, 1024)
	copy(corrupt, "compiler-inputs/x")
	corrupt[0x94] = 'Z' // invalid header checksum field
	for _, tc := range []struct {
		name    string
		archive []byte
		reason  string
	}{
		{"corrupt-header", gzipBytes(t, corrupt), "invalid tar header"},
		{"dir-outside-tree", gzipTar(t, []tarEntry{{hdr: tar.Header{Name: "other/", Typeflag: tar.TypeDir}}}), "outside the marker tree"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := extractMarkerTree(context.Background(), write(t, tc.archive), t.TempDir()); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err = %v, want %q", err, tc.reason)
			}
		})
	}
}

// A reader that ends early without an error must still fail the entry.
func TestMarkerWriteFileShortReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := markerWriteFile(path, strings.NewReader("ab"), 5); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v", err)
	}
	if err := markerWriteFile(path, strings.NewReader("ab"), 2); err == nil {
		t.Fatal("an existing staged file must never be overwritten")
	}
}

// Permission failures inside the private staging and cache directories fail
// closed. Root bypasses directory modes, so these run as an unprivileged user.
func TestMarkerTreePermissionFailures(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permission bits do not restrict root")
	}
	dest := t.TempDir()
	if err := os.Chmod(dest, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dest, 0o700) })
	if err := markerMkdirAll(dest, "compiler-inputs"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("mkdir in read-only dest: %v", err)
	}
	cache := t.TempDir()
	if err := os.Mkdir(filepath.Join(cache, "compiler-inputs"), 0o700); err != nil {
		t.Fatal(err)
	}
	w := newMarkerTreeSwap(cache, t.TempDir())
	// Without search permission, Lstat of a cache child fails with EACCES.
	if err := os.Chmod(cache, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cache, 0o700) })
	if err := w.retire(); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("retire without search permission: %v", err)
	}
}
