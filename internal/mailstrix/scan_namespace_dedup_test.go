package mailstrix

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// PERF-66: the namespace+name dedup lives inline in Scan's stream merge; this
// drives it end to end. Two files define a rule with the same name. fileA's
// rule fires on the raw bytes (zip comment) AND on the deflated member, so the
// stream hit must be deduped; fileB's rule fires only on the member, so it must
// be kept even though its name collides with a raw match.
func TestScanStreamMergeDedupsByNamespace(t *testing.T) {
	dir := t.TempDir()
	write := func(name, lit string) {
		rule := "rule Dropper { strings: $a = \"" + lit + "\" condition: $a }\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(rule), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("fileA.yar", "RAWTOKEN7731")
	write("fileB.yar", "STREAMTOKEN4419")
	s := newScanner(t, dir)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("note.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hello RAWTOKEN7731 then STREAMTOKEN4419 bye")); err != nil {
		t.Fatal(err)
	}
	if err := zw.SetComment("RAWTOKEN7731"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("STREAMTOKEN4419")) {
		t.Fatal("fixture leaks the stream-only token into the raw bytes")
	}

	m, err := scanT(s, buf.Bytes(), ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	var a, b int
	for _, x := range m {
		if x.Rule != "Dropper" {
			continue
		}
		switch x.Namespace {
		case "fileA.yar":
			a++
		case "fileB.yar":
			b++
		}
	}
	if a != 1 {
		t.Errorf("fileA.yar/Dropper: got %d matches, want exactly 1 (raw+stream deduped): %+v", a, m)
	}
	if b != 1 {
		t.Errorf("fileB.yar/Dropper: got %d, want 1 (same name, other namespace kept): %+v", b, m)
	}

	// Negative control: a body with neither token matches neither rule.
	clean, err := scanT(s, []byte("nothing here"), ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range clean {
		if x.Rule == "Dropper" {
			t.Fatalf("clean body matched: %+v", clean)
		}
	}
}
