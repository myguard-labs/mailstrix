package mailstrix

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// packMarkerTree runs the publisher's real packer (docker/pack-marker-tree.py)
// over a tree and returns the archive bytes.
func packMarkerTree(t *testing.T, root string) []byte {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	out := filepath.Join(t.TempDir(), "marker-tree.tar.gz")
	cmd := exec.Command(py, "-I", "../../docker/pack-marker-tree.py", root, out) // #nosec G204 -- fixed test helper, no user input
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pack-marker-tree: %v\n%s", err, b)
	}
	b, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The publisher's packer must produce exactly the archive the client extractor
// and loader accept: deterministic bytes, only the contract entries, and a tree
// that installs end to end through FetchRules.
func TestPackMarkerTreeMatchesClientContract(t *testing.T) {
	f := newMarkerFixture(t)
	// Extra entries beside the tree (the real export also holds compiled.yac,
	// local.yac); they must not be packed.
	if err := os.WriteFile(filepath.Join(f.root, "local.yac"), []byte("not part of the tree"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := packMarkerTree(t, f.root)
	if second := packMarkerTree(t, f.root); !bytes.Equal(first, second) {
		t.Fatal("two packs of the same tree differ")
	}

	archive := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := os.WriteFile(archive, first, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := extractMarkerTree(context.Background(), archive, dest); err != nil {
		t.Fatalf("client extractor refused the packed archive: %v", err)
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, name := range markerTreeEntries() {
		allowed[name] = true
	}
	for _, e := range entries {
		if !allowed[e.Name()] {
			t.Errorf("packed archive carries %q outside the contract set", e.Name())
		}
	}
	want, got := treeSnapshot(t, f.root), treeSnapshot(t, dest)
	for k, v := range want {
		if k == cachedRulesName || k == manifestName {
			continue
		}
		if got[k] != v {
			t.Errorf("entry %s: extracted %q, source %q", k, got[k], v)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("extracted entry %s not in source", k)
		}
	}

	// End to end: the real fetch path installs the packed archive.
	dir := t.TempDir()
	srv := newMarkerServer(t, f.main, 2, f.field(first), first)
	res, err := fetchMarker(t, srv, dir, &markerLog{}, fetchOptions{})
	if err != nil || !res.Updated || res.Marker != MarkerStatusInstalled {
		t.Fatalf("packed archive did not install: res=%+v err=%v", res, err)
	}
}

// The packer refuses what the client would refuse, and a missing required entry.
func TestPackMarkerTreeRefuses(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	for _, tc := range []struct {
		name  string
		setup func(root string)
		want  string
	}{
		{"missing marker-artifact", func(root string) { _ = os.RemoveAll(filepath.Join(root, "marker-artifact")) }, "missing required entry"},
		{"missing sources.json", func(root string) { _ = os.Remove(filepath.Join(root, "sources.json")) }, "missing required entry: sources.json"},
		{"symlink inside tree", func(root string) {
			if err := os.Symlink("/etc/passwd", filepath.Join(root, "compiler-inputs", "link")); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		{"top-level file where a directory belongs", func(root string) {
			_ = os.RemoveAll(filepath.Join(root, "marker-artifact"))
			if err := os.WriteFile(filepath.Join(root, "marker-artifact"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "wrong type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := markerArtifactFixture(t)
			tc.setup(root)
			cmd := exec.Command(py, "-I", "../../docker/pack-marker-tree.py", root, filepath.Join(t.TempDir(), "o.tar.gz")) // #nosec G204 -- fixed test helper
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err=%v out=%q, want failure containing %q", err, out, tc.want)
			}
		})
	}
}
