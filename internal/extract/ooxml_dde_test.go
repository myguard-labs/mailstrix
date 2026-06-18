package extract

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

// makeOOXMLWithDocument builds a minimal in-memory OOXML zip with the given
// word/document.xml content. Reuses the addZipEntry helper from ooxml_rels_test.go.
func makeOOXMLWithDocument(t *testing.T, documentXML string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	addZipEntry(t, zw, "word/document.xml", documentXML)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestOOXMLDDE_FldSimple checks that a w:fldSimple with a DDEAUTO instruction
// emits an OOXML-DDE-FIELD stream.
func TestOOXMLDDE_FldSimple(t *testing.T) {
	docXML := `<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:fldSimple w:instr="DDEAUTO c:\Windows\System32\cmd.exe /k calc">
        <w:r><w:t>click to update</w:t></w:r>
      </w:fldSimple>
    </w:p>
  </w:body>
</w:document>`

	buf := makeOOXMLWithDocument(t, docXML)
	res := Extract(buf, time.Time{})

	if !res.IsDoc {
		t.Fatal("OOXML zip not flagged IsDoc")
	}

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("OOXML-DDE-FIELD")) {
		t.Fatalf("no OOXML-DDE-FIELD stream emitted; streams=%d joined=%q", len(res.Streams), joined)
	}
	if !bytes.Contains(joined, []byte(`DDEAUTO c:\Windows\System32\cmd.exe`)) {
		t.Fatalf("DDE instruction not in emitted stream; got %q", joined)
	}
}

// TestOOXMLDDE_SplitRuns checks that a DDE instruction split across multiple
// w:instrText elements (common obfuscation) is concatenated and emitted.
func TestOOXMLDDE_SplitRuns(t *testing.T) {
	// The field instruction "DDEAUTO cmd /k calc" is split across three
	// w:instrText runs with a w:fldChar begin/end envelope.
	docXML := `<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:fldChar w:fldCharType="begin"/>
      </w:r>
      <w:r>
        <w:instrText xml:space="preserve">DDEA</w:instrText>
      </w:r>
      <w:r>
        <w:instrText xml:space="preserve">UTO cmd</w:instrText>
      </w:r>
      <w:r>
        <w:instrText xml:space="preserve"> /k calc</w:instrText>
      </w:r>
      <w:r>
        <w:fldChar w:fldCharType="end"/>
      </w:r>
    </w:p>
  </w:body>
</w:document>`

	buf := makeOOXMLWithDocument(t, docXML)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("OOXML-DDE-FIELD")) {
		t.Fatalf("split-run DDEAUTO not detected; streams=%d joined=%q", len(res.Streams), joined)
	}
	// After concatenation the instruction starts with "DDEAUTO"
	if !bytes.Contains(joined, []byte("DDEAUTO")) {
		t.Fatalf("concatenated instruction missing DDEAUTO token; got %q", joined)
	}
}

// TestOOXMLDDE_SpaceObfuscated checks that a space-obfuscated DDE directive like
// "D D E A U T O cmd" is detected AND that the emitted stream contains the
// contiguous token "DDEAUTO" so YARA patterns can match it.
func TestOOXMLDDE_SpaceObfuscated(t *testing.T) {
	docXML := `<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:fldSimple w:instr="D D E A U T O cmd /k calc">
        <w:r><w:t>click to update</w:t></w:r>
      </w:fldSimple>
    </w:p>
  </w:body>
</w:document>`

	buf := makeOOXMLWithDocument(t, docXML)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("OOXML-DDE-FIELD")) {
		t.Fatalf("space-obfuscated DDEAUTO not detected; streams=%d joined=%q", len(res.Streams), joined)
	}
	// The emitted stream must contain the contiguous "DDEAUTO" token so that
	// YARA rules like `$ddeauto = "DDEAUTO "` can fire.
	if !bytes.Contains(joined, []byte("DDEAUTO")) {
		t.Fatalf("emitted stream lacks contiguous DDEAUTO token; got %q", joined)
	}
}

// TestOOXMLDDE_NewlineObfuscated checks that a DDE directive containing a
// newline inside the token ("D\nD\nE\nA\nU\nT\nO") is also normalised correctly.
func TestOOXMLDDE_NewlineObfuscated(t *testing.T) {
	docXML := `<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:fldSimple w:instr="D&#10;D&#10;E&#10;A&#10;U&#10;T&#10;O cmd /k calc">
        <w:r><w:t>click to update</w:t></w:r>
      </w:fldSimple>
    </w:p>
  </w:body>
</w:document>`

	buf := makeOOXMLWithDocument(t, docXML)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("OOXML-DDE-FIELD")) {
		t.Fatalf("newline-obfuscated DDEAUTO not detected; streams=%d joined=%q", len(res.Streams), joined)
	}
	if !bytes.Contains(joined, []byte("DDEAUTO")) {
		t.Fatalf("emitted stream lacks contiguous DDEAUTO token after newline normalization; got %q", joined)
	}
}

// TestOOXMLDDE_BenignField checks that an ordinary field like PAGE emits nothing.
func TestOOXMLDDE_BenignField(t *testing.T) {
	docXML := `<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:fldSimple w:instr=" PAGE ">
        <w:r><w:t>1</w:t></w:r>
      </w:fldSimple>
    </w:p>
    <w:p>
      <w:r>
        <w:fldChar w:fldCharType="begin"/>
      </w:r>
      <w:r>
        <w:instrText> DATE \@ "d MMMM yyyy"</w:instrText>
      </w:r>
      <w:r>
        <w:fldChar w:fldCharType="end"/>
      </w:r>
    </w:p>
  </w:body>
</w:document>`

	buf := makeOOXMLWithDocument(t, docXML)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("OOXML-DDE-FIELD")) {
		t.Fatalf("benign PAGE/DATE field wrongly emitted OOXML-DDE-FIELD; got %q", joined)
	}
}
