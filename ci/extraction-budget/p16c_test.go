package extractionbudget_test

import (
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func TestP16cParentChildAndMalformedDuplicateParity(t *testing.T) {
	dde := []byte(`<w:document xmlns:w="urn:w"><w:body><w:fldSimple w:instr="DDEAUTO cmd /c calc"/></w:body></w:document>`)
	inner := p16bZip(t,
		p16bZipEntry{name: "[Content_Types].xml", data: []byte(`<Types/>`)},
		p16bZipEntry{name: "word/document.xml", data: dde},
		p16bZipEntry{name: "word/vbaProject.bin", data: []byte("malformed-one")},
		p16bZipEntry{name: "word/vbaProject.bin", data: []byte("malformed-two")},
	)
	outer := p16bZip(t, p16bZipEntry{name: "child.docm", data: inner})

	res := extract.Extract(outer, time.Time{})
	want := extract.Result{
		Streams:        [][]byte{inner, []byte("OOXML-DDE-FIELD DDEAUTO cmd /c calc")},
		Markers:        [][]byte{[]byte("OLEID-DDE")},
		IsDoc:          true,
		TopType:        extract.TopTypeZip,
		IsArchive:      true,
		ContentStreams: 2,
	}
	if gotJSON, wantJSON := p16bResultJSON(t, res), p16bResultJSON(t, want); gotJSON != wantJSON {
		t.Fatalf("complete Result changed\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
	wantRetained := uint64(len(inner) + len("OOXML-DDE-FIELD DDEAUTO cmd /c calc") + len("OLEID-DDE"))
	if got := res.Retained.Bytes(); got != wantRetained {
		t.Fatalf("parent+child retained bytes=%d want=%d", got, wantRetained)
	}
}

func TestP16cMalformedOOXMLParity(t *testing.T) {
	input := p16bZip(t,
		p16bZipEntry{name: "[Content_Types].xml", data: []byte(`<Types/>`)},
		p16bZipEntry{name: "word/document.xml", data: []byte(`<w:document><broken`)},
		p16bZipEntry{name: "word/vbaProject.bin", data: []byte("not-an-ole")},
	)
	res := extract.Extract(input, time.Time{})
	want := extract.Result{IsDoc: true, TopType: extract.TopTypeZip, Failed: true}
	if gotJSON, wantJSON := p16bResultJSON(t, res), p16bResultJSON(t, want); gotJSON != wantJSON {
		t.Fatalf("complete malformed Result changed\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
	if got := res.Retained.Bytes(); got != 0 {
		t.Fatalf("malformed OOXML retained bytes=%d want=0", got)
	}
}
