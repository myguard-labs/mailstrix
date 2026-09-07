package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"time"
)

const generatorRevision = "synthetic-v1"

var pdfSymbols = []string{"PDF_OpenAction_JS", "PDF_Launch_Action", "PDF_JBIG2", "PDF_Additional_Actions", "PDF_EmbeddedFile", "PDF_HexObfuscatedName", "PDF_ObjStm"}

type fixture struct {
	name, format string
	data         []byte
	indicator    bool
}

// syntheticFixtures produces inert, locally authored bytes. No fixture executes
// commands, contacts a host, or embeds an external document. The positive PDF
// contains only a JavaScript literal expression, to exercise an indicator.
func syntheticFixtures() ([]fixture, error) {
	doc, err := officeFixture()
	if err != nil {
		return nil, err
	}
	img := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	img.SetNRGBA(0, 0, color.NRGBA{R: 42, G: 100, B: 180, A: 255})
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, img); err != nil {
		return nil, err
	}
	return []fixture{
		{"clean.eml", "mime", []byte("From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nDate: Sat, 01 Jan 2000 00:00:00 +0000\r\nSubject: Synthetic meeting\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThe meeting begins at noon.\r\n"), false},
		{"clean.docx", "office", doc, false},
		{"clean.pdf", "pdf", pdfFixture(false), false},
		{"clean.html", "html", []byte("<!doctype html><html><head><title>Meeting</title></head><body><p>The meeting begins at noon.</p></body></html>\n"), false},
		{"clean.png", "image", pngBytes.Bytes(), false},
		{"indicator.pdf", "pdf", pdfFixture(true), true},
	}, nil
}

func officeFixture() ([]byte, error) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	entries := []struct{ name, text string }{
		{"[Content_Types].xml", `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/document.xml", `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Synthetic meeting at noon.</w:t></w:r></w:p><w:sectPr/></w:body></w:document>`},
	}
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store,
			Modified: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
		h.SetMode(0o644)
		w, err := z.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(e.text)); err != nil {
			return nil, err
		}
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func pdfFixture(indicator bool) []byte {
	catalog := "<< /Type /Catalog /Pages 2 0 R >>"
	if indicator {
		catalog = "<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (0) >> >>"
	}
	objects := []string{catalog, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>"}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, 0, len(objects))
	for i, obj := range objects {
		offsets = append(offsets, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return b.Bytes()
}

func syntheticManifest(fixtures []fixture) manifest {
	m := manifest{SchemaVersion: 1, CorpusID: generatorRevision, Revision: 1,
		Sources: []source{{ID: "generated", Kind: "generated", Reference: "tools/parity/generate.go", Revision: generatorRevision, License: "MIT", LicenseEvidence: "LICENSE", Redistribution: "approved", Privacy: "synthetic", ReviewRef: "tools/parity/README.md#ground-truth"}},
		Samples: make([]sample, 0, len(fixtures)),
	}
	for _, f := range fixtures {
		partition := "synthetic-clean"
		if f.indicator {
			partition = "synthetic-indicator"
		}
		labels := make([]label, 0, len(pdfSymbols))
		for _, rule := range pdfSymbols {
			expected := "absent"
			if f.indicator && rule == "PDF_OpenAction_JS" {
				expected = "present"
			}
			labels = append(labels, label{Symbol: symbol{Namespace: "pdf_indicators.yara", Rule: rule}, Expected: expected})
		}
		unit := "file"
		if f.format == "mime" {
			unit = "message"
		}
		m.Samples = append(m.Samples, sample{ID: f.name, SourceID: "generated", SHA256: digest(f.data), Size: int64(len(f.data)), Locator: f.name,
			Partition: partition, Split: "regression", GroupID: f.format + "-basic", Format: f.format, InputUnit: unit,
			Truth: truth{Class: "benign", Basis: "construction", EvidenceRef: "tools/parity/generate.go:" + f.name, ReviewRef: "tools/parity/README.md#ground-truth", Symbols: labels}})
	}
	return m
}

// generate creates a new directory only; it never overwrites a caller corpus.
// A failed generation leaves a recoverable partial directory for inspection.
func generate(dir string) error {
	fixtures, err := syntheticFixtures()
	if err != nil {
		return err
	}
	m := syntheticManifest(fixtures)
	if err := m.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create new corpus directory: %w", err)
	}
	for _, f := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o600); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o600)
}
