package yarad

import (
	"testing"

	"github.com/eilandert/rspamd-yarad/internal/extract"
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
