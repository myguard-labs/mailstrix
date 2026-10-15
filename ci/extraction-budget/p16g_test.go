package extractionbudget_test

import (
	"bytes"
	"sort"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func p16gIndependentBytes(res extract.Result) (total uint64, attachmentOnly int) {
	for _, group := range [][][]byte{res.Streams, res.Markers} {
		for _, entry := range group {
			total += uint64(len(entry))
		}
	}
	for _, attachment := range res.MIMEAttachments {
		aliased := false
		for _, group := range [][][]byte{res.Streams, res.Markers} {
			for _, entry := range group {
				if p16fSameSlice(attachment, entry) {
					aliased = true
					break
				}
			}
			if aliased {
				break
			}
		}
		if !aliased {
			total += uint64(len(attachment))
			attachmentOnly++
		}
	}
	return total, attachmentOnly
}

func TestP16gCompleteAccountingClosure(t *testing.T) {
	rtf := []byte("{\\rtf1{\\field{\\*\\fldinst DDEAUTO cmd /c calc}}}")
	innerArchive := p16bZip(t, p16bZipEntry{name: "payload.rtf", data: rtf})
	mimePayload := []byte("P16G complete attachment payload")
	leaf := p16fMessage("application/octet-stream; name=inner.bin", "", mimePayload)
	innerMessage := p16fMessage("message/rfc822; name=inner.eml", "", leaf)

	cases := map[string]func() extract.Result{
		"marker_named_mime_attachment": func() extract.Result {
			return extract.Extract(p16fMessage("application/octet-stream; name=marker.bin", "", []byte("OLEID-DDE")), time.Time{})
		},
		"nested_archive": func() extract.Result {
			return extract.Extract(p16bZip(t, p16bZipEntry{name: "inner.zip", data: innerArchive}), time.Time{})
		},
		"nested_mime": func() extract.Result {
			return extract.Extract(p16fMessage("message/rfc822; name=forwarded.eml", "", innerMessage), time.Time{})
		},
		"ooxml_dde_marker": func() extract.Result {
			dde := []byte(`<w:document xmlns:w="urn:w"><w:body><w:fldSimple w:instr="DDEAUTO cmd /c calc"/></w:body></w:document>`)
			input := p16bZip(t,
				p16bZipEntry{name: "[Content_Types].xml", data: []byte(`<Types/>`)},
				p16bZipEntry{name: "word/document.xml", data: dde},
			)
			return extract.Extract(input, time.Time{})
		},
	}
	for _, tc := range p16dCases() {
		cases["text_"+tc.name] = func() extract.Result { return extract.Extract(tc.input, time.Time{}) }
	}
	for name, input := range p16eInputs(t) {
		input := bytes.Clone(input)
		cases["structural_"+name] = func() extract.Result { return p16eExtract(name, input) }
	}

	var streams, markers, attachmentOnly int
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		run := cases[name]
		t.Run(name, func(t *testing.T) {
			res := run()
			want, only := p16gIndependentBytes(res)
			if want == 0 {
				t.Fatal("positive closure fixture retained no output")
			}
			if got := res.Retained.Bytes(); got != want {
				t.Fatalf("complete retained closure=%d want Streams+Markers+attachment-only=%d", got, want)
			}
			streams += len(res.Streams)
			markers += len(res.Markers)
			attachmentOnly += only
		})
	}
	if streams == 0 || markers == 0 || attachmentOnly == 0 {
		t.Fatalf("fixture inventory incomplete: streams=%d markers=%d attachment-only=%d", streams, markers, attachmentOnly)
	}
}

func TestP16gMalformedInputsRetainNothing(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty":         nil,
		"truncated_zip": []byte("PK\x03\x04truncated"),
		"malformed_rtf": []byte("{\\rtf1{\\object{\\*\\objdata zzz}}}"),
	} {
		t.Run(name, func(t *testing.T) {
			res := extract.Extract(input, time.Time{})
			want, _ := p16gIndependentBytes(res)
			if got := res.Retained.Bytes(); got != want || want != 0 {
				t.Fatalf("malformed retained closure=%d want=%d", got, want)
			}
		})
	}
}
