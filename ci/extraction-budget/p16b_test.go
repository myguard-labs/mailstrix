package extractionbudget_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

type p16bZipEntry struct {
	name string
	data []byte
}

func p16bZip(t *testing.T, entries ...p16bZipEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, entry := range entries {
		w, err := zw.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func p16bResultJSON(t *testing.T, res extract.Result) string {
	t.Helper()
	res.Retained = extract.RetainedAccounting{}
	got, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestP16bNestedAndSiblingResultParity(t *testing.T) {
	rtf := []byte("{\\rtf1{\\field{\\*\\fldinst DDEAUTO cmd /c calc}}}")
	field := []byte("RTF-DDE-FIELD DDEAUTO cmd /c calc")
	inner := p16bZip(t, p16bZipEntry{name: "payload.rtf", data: rtf})

	tests := []struct {
		name           string
		input          []byte
		wantRetained   uint64
		wantResultJSON string
	}{
		{
			name:           "nested_archive",
			input:          p16bZip(t, p16bZipEntry{name: "inner.zip", data: inner}),
			wantRetained:   uint64(len(inner) + len(rtf) + len(field)),
			wantResultJSON: `{"Streams":["UEsDBBQACAAIAAAAAAAAAAAAAAAAAAAAAAALAAAAcGF5bG9hZC5ydGaqjikqSTOsjknLTM1JqY7RiknLScnMKy5RcHFxdQwN8VdIzk1R0E9WSE7MSa6trQUEAAD//1BLBwgBkq+qNQAAAC8AAABQSwECFAAUAAgACAAAAAAAAZKvqjUAAAAvAAAACwAAAAAAAAAAAAAAAAAAAAAAcGF5bG9hZC5ydGZQSwUGAAAAAAEAAQA5AAAAbgAAAAAA","e1xydGYxe1xmaWVsZHtcKlxmbGRpbnN0IERERUFVVE8gY21kIC9jIGNhbGN9fX0=","UlRGLURERS1GSUVMRCBEREVBVVRPIGNtZCAvYyBjYWxj"],"Markers":null,"IsDoc":true,"TopType":"zip","Encrypted":false,"Failed":false,"Panicked":false,"IsMSI":false,"IsMSG":false,"IsPDF":false,"IsLNK":false,"IsOLEPackage":false,"IsArchive":true,"EncryptedArchive":false,"DecryptedArchive":false,"Polyglot":false,"IsXLL":false,"IsRTF":true,"IsOneNote":false,"IsTNEF":false,"EncodedScript":false,"HasDocProps":false,"HasXLMFold":false,"IsMIME":false,"MIMEAttachments":null,"IsSLK":false,"DecodedStreams":0,"ContentStreams":3,"VBAStreams":null,"CapHits":null,"Retained":{}}`,
		},
		{
			name: "office_sibling",
			input: p16bZip(t,
				p16bZipEntry{name: "[Content_Types].xml", data: []byte(`<Types/>`)},
				p16bZipEntry{name: "word/document.xml", data: []byte(`<document/>`)},
				p16bZipEntry{name: "sibling.rtf", data: rtf},
			),
			wantRetained:   uint64(len(rtf) + len(field)),
			wantResultJSON: `{"Streams":["e1xydGYxe1xmaWVsZHtcKlxmbGRpbnN0IERERUFVVE8gY21kIC9jIGNhbGN9fX0=","UlRGLURERS1GSUVMRCBEREVBVVRPIGNtZCAvYyBjYWxj"],"Markers":null,"IsDoc":true,"TopType":"zip","Encrypted":false,"Failed":false,"Panicked":false,"IsMSI":false,"IsMSG":false,"IsPDF":false,"IsLNK":false,"IsOLEPackage":false,"IsArchive":false,"EncryptedArchive":false,"DecryptedArchive":false,"Polyglot":false,"IsXLL":false,"IsRTF":true,"IsOneNote":false,"IsTNEF":false,"EncodedScript":false,"HasDocProps":false,"HasXLMFold":false,"IsMIME":false,"MIMEAttachments":null,"IsSLK":false,"DecodedStreams":0,"ContentStreams":2,"VBAStreams":null,"CapHits":null,"Retained":{}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := extract.Extract(tc.input, time.Time{})
			gotResult := p16bResultJSON(t, res)
			if gotResult != tc.wantResultJSON {
				t.Fatalf("complete Result changed\n got: %s\nwant: %s", gotResult, tc.wantResultJSON)
			}
			if got := res.Retained.Bytes(); got != tc.wantRetained {
				t.Fatalf("source-bound retained bytes=%d want=%d", got, tc.wantRetained)
			}
		})
	}
}

func TestP16bBoundaryAndMalformedParity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{name: "archive_member_below_minimum", input: p16bZip(t, p16bZipEntry{name: "tiny", data: []byte("abc")})},
		{name: "truncated_zip", input: []byte("PK\x03\x04truncated")},
		{name: "malformed_rtf", input: []byte("{\\rtf1{\\object{\\*\\objdata zzz}}}")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := extract.Extract(tc.input, time.Time{})
			if got := res.Retained.Bytes(); got != 0 {
				t.Fatalf("retained bytes=%d want=0", got)
			}
		})
	}
}
