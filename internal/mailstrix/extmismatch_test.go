package mailstrix

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func TestExtMismatch(t *testing.T) {
	cases := []struct {
		name string
		res  extract.Result
		ext  string
		want string // "" = no mismatch
	}{
		// renames that MUST flag
		{"ole-doc as jpg", extract.Result{IsDoc: true}, ".jpg", "office-doc:jpg"},
		{"ole-doc as txt", extract.Result{IsDoc: true}, ".txt", "office-doc:txt"},
		{"rtf as pdf", extract.Result{IsRTF: true}, ".pdf", "rtf:pdf"},
		{"lnk as png", extract.Result{IsLNK: true}, ".png", "lnk:png"},
		{"msi as dat", extract.Result{IsMSI: true}, ".dat", "msi:dat"},
		{"onenote as txt", extract.Result{IsOneNote: true}, ".txt", "onenote:txt"},
		{"ole-package as jpeg", extract.Result{IsOLEPackage: true}, ".jpeg", "ole-package:jpeg"},

		// correctly-named — MUST NOT flag
		{"docm as docm", extract.Result{IsDoc: true}, ".docm", ""},
		{"xls as xls", extract.Result{IsDoc: true}, ".xls", ""},
		{"rtf as rtf", extract.Result{IsRTF: true}, ".rtf", ""},
		{"rtf as doc", extract.Result{IsRTF: true}, ".doc", ""},
		{"lnk as lnk", extract.Result{IsLNK: true}, ".lnk", ""},
		{"msi as msi", extract.Result{IsMSI: true}, ".msi", ""},
		{"onenote as one", extract.Result{IsOneNote: true}, ".one", ""},

		// no/unknown extension — cannot prove a rename, MUST NOT flag
		{"ole-doc no ext", extract.Result{IsDoc: true}, "", ""},
		{"ole-doc unknown ext", extract.Result{IsDoc: true}, ".xyz", ""},
		{"lnk unknown ext", extract.Result{IsLNK: true}, ".scr", ""},

		// non-container results — MUST NOT flag (a plain archive named .zip, a PDF, etc.)
		{"plain pdf as pdf", extract.Result{IsPDF: true}, ".pdf", ""},
		{"archive as zip", extract.Result{IsArchive: true}, ".zip", ""},
		{"nothing recovered", extract.Result{}, ".jpg", ""},
		{"encoded script as txt", extract.Result{EncodedScript: true}, ".txt", ""},

		// top-level non-Office types that also set IsDoc: correctly named MUST NOT
		// flag; under another benign coat or as a nested member they still do.
		{"top pdf as pdf", extract.Result{IsDoc: true, IsPDF: true, TopType: extract.TopTypePDF}, ".pdf", ""},
		{"top pdf as PDF", extract.Result{IsDoc: true, IsPDF: true, TopType: extract.TopTypePDF}, ".PDF", ""},
		{"top tnef as dat", extract.Result{IsDoc: true, IsTNEF: true, TopType: extract.TopTypeTNEF}, ".dat", ""},
		{"top spreadsheetml as xml", extract.Result{IsDoc: true, TopType: extract.TopTypeSpreadsheetML}, ".xml", ""},
		{"top pdf as jpg", extract.Result{IsDoc: true, IsPDF: true, TopType: extract.TopTypePDF}, ".jpg", "office-doc:jpg"},
		{"top tnef as pdf", extract.Result{IsDoc: true, IsTNEF: true, TopType: extract.TopTypeTNEF}, ".pdf", "office-doc:pdf"},
		{"zip holding pdf as pdf", extract.Result{IsDoc: true, IsArchive: true, IsPDF: true, TopType: extract.TopTypeZip}, ".pdf", "office-doc:pdf"},
		{"ole holding tnef as dat", extract.Result{IsDoc: true, IsTNEF: true, TopType: extract.TopTypeOLE}, ".dat", "office-doc:dat"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extMismatch(c.res, c.ext); got != c.want {
				t.Errorf("extMismatch(%+v, %q) = %q, want %q", c.res, c.ext, got, c.want)
			}
		})
	}
}

// Renamed_Container is a marker-tagged rule: the EXT-MISMATCH literal must be
// rejected on the content channel and accepted only out-of-band. This pins the
// tag wiring so a future rule edit that drops `marker` is caught.
func TestExtMismatchMarkerTagged(t *testing.T) {
	m := Match{Rule: "Renamed_Container", Tags: []string{"evasion", "heuristic", "suspicious", "marker"}}
	if !matchIsMarker(m) {
		t.Fatal("Renamed_Container must carry the marker tag (marker-channel only)")
	}
	// content channel drops it; marker channel keeps it
	if len(filterMarkerChannel([]Match{m}, false)) != 0 {
		t.Error("marker-tagged rule must be dropped on the content channel")
	}
	if len(filterMarkerChannel([]Match{m}, true)) != 1 {
		t.Error("marker-tagged rule must be kept on the marker channel")
	}
}

// TestExtMismatchRealExtract runs the real extractor so the Result flags are the
// ones production sets (Extract marks every recognised container IsDoc, not just
// Office ones). A unit case built from hand-picked flags missed that every PDF
// named .pdf was reported as a renamed Office document.
func TestExtMismatchRealExtract(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n" +
		"2 0 obj << /S /JavaScript /JS (app.alert(1);) >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n")

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, err := zw.Create("inner.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pdf); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	sml := []byte(`<?xml version="1.0"?>` + "\n" + `<?mso-application progid="Excel.Sheet"?>` + "\n" +
		`<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"></Workbook>`)

	cases := []struct {
		name string
		buf  []byte
		ext  string
		want string
	}{
		{"pdf as pdf", pdf, ".pdf", ""},
		{"pdf as jpg", pdf, ".jpg", "office-doc:jpg"},
		{"zip holding pdf as pdf", zbuf.Bytes(), ".pdf", "office-doc:pdf"},
		{"tnef as dat", testTNEF([]byte("hello")), ".dat", ""},
		{"tnef as txt", testTNEF([]byte("hello")), ".txt", "office-doc:txt"},
		{"spreadsheetml as xml", sml, ".xml", ""},
		{"spreadsheetml as txt", sml, ".txt", "office-doc:txt"},
		{"plain text as pdf", []byte("just text"), ".pdf", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := extract.Extract(c.buf, time.Now().Add(5*time.Second))
			if got := extMismatch(res, c.ext); got != c.want {
				t.Errorf("extMismatch(TopType=%q IsDoc=%v, %q) = %q, want %q",
					res.TopType, res.IsDoc, c.ext, got, c.want)
			}
		})
	}
}

// testTNEF builds a minimal winmail.dat with one attachment (mirrors the
// extract package's buildTNEF test helper).
func testTNEF(payload []byte) []byte {
	obj := func(name int, data []byte) []byte {
		b := []byte{0x02}
		b = binary.LittleEndian.AppendUint16(b, uint16(name))
		b = binary.LittleEndian.AppendUint16(b, 0)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
		b = append(b, data...)
		return append(b, 0, 0)
	}
	blob := []byte{0x78, 0x9F, 0x3E, 0x22, 0x00, 0x00}
	blob = append(blob, obj(0x9002, []byte{0x00})...)
	return append(blob, obj(0x800f, payload)...)
}
