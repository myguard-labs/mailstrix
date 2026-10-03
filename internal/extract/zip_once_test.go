package extract

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// zipRef is the pre-PERF-55 dispatch: separate parses for classification, the
// macro path and the member/carrier walk, via the buffer-taking wrappers.
func zipRef(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time, opts *Options, top bool) {
	if top {
		if fromOOXML(buf, res, deadline, opts) {
			fromOfficeZipCarriers(buf, res, b, depth, deadline)
		} else {
			fromArchive(buf, res, b, depth, deadline)
		}
		return
	}
	if isOfficeZip(buf) {
		fromOOXML(buf, res, deadline, opts)
		fromOfficeZipCarriers(buf, res, b, depth, deadline)
	} else {
		fromArchive(buf, res, b, depth, deadline)
	}
}

func zipSummary(r *Result) string {
	var w bytes.Buffer
	fmt.Fprintf(&w, "failed=%v archive=%v vba=%d caps=%v\n", r.Failed, r.IsArchive, len(r.VBAStreams), r.CapHits)
	for _, s := range r.Streams {
		fmt.Fprintf(&w, "%x\n", s)
	}
	return w.String()
}

func TestFromZipMatchesSeparateParses(t *testing.T) {
	plain := buildZip(t, map[string][]byte{"a.txt": []byte("hello"), "b.js": []byte("WScript.Shell run")})
	office := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte("<Types/>"),
		"word/document.xml":   []byte("<w:document>body text</w:document>"),
		"payload.zip":         plain, // carrier sibling
	})
	jar := buildZip(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0"), "x.class": []byte("\xca\xfe\xba\xbe")})
	nestedPlain := buildZip(t, map[string][]byte{"inner.zip": plain})
	nestedOffice := buildZip(t, map[string][]byte{"doc.docx": office})
	cases := map[string][]byte{
		"plain":         plain,
		"office":        office,
		"jar":           jar,
		"nested plain":  nestedPlain,
		"nested office": nestedOffice,
		"corrupt":       append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x41}, 64)...),
		"truncated":     office[:len(office)/2],
		"empty zip":     buildZip(t, map[string][]byte{}),
	}
	for name, buf := range cases {
		for _, top := range []bool{true, false} {
			for _, depth := range []int{0, maxArchiveDepth + 1} {
				got, want := &Result{}, &Result{}
				fromZip(buf, got, &archiveBudget{}, depth, time.Time{}, nil, top)
				zipRef(buf, want, &archiveBudget{}, depth, time.Time{}, nil, top)
				if g, w := zipSummary(got), zipSummary(want); g != w {
					t.Errorf("%s top=%v depth=%d:\n got %s\nwant %s", name, top, depth, g, w)
				}
			}
		}
	}
	// Positive control: the plain archive's member really is surfaced.
	r := &Result{}
	fromZip(plain, r, &archiveBudget{}, 0, time.Time{}, nil, true)
	found := false
	for _, s := range r.Streams {
		found = found || bytes.Contains(s, []byte("WScript.Shell"))
	}
	if !found || r.Failed {
		t.Fatalf("plain zip member not extracted: failed=%v streams=%d", r.Failed, len(r.Streams))
	}
	// Negative control: a corrupt top-level zip is a parse failure.
	r = &Result{}
	fromZip(cases["corrupt"], r, &archiveBudget{}, 0, time.Time{}, nil, true)
	if !r.Failed {
		t.Fatal("corrupt top-level zip not flagged Failed")
	}
}

// The point of PERF-55: one central-directory parse instead of two or three.
// Directory parsing allocates per entry, so on a many-entry plain zip the
// single-parse dispatch must allocate clearly less than the reference.
func TestFromZipParsesDirectoryOnce(t *testing.T) {
	entries := make(map[string][]byte, 3000)
	for i := 0; i < 3000; i++ {
		entries[fmt.Sprintf("dir/f%04d.dat", i)] = nil
	}
	buf := buildZip(t, entries)
	once := testing.AllocsPerRun(3, func() {
		fromZip(buf, &Result{}, &archiveBudget{}, 0, time.Time{}, nil, true)
	})
	ref := testing.AllocsPerRun(3, func() {
		zipRef(buf, &Result{}, &archiveBudget{}, 0, time.Time{}, nil, true)
	})
	if once >= ref*0.85 { // top-level plain zip: 2 parses -> 1, ~24% fewer allocs measured
		t.Fatalf("single-parse dispatch allocates %v vs %v for separate parses", once, ref)
	}
	t.Logf("allocs: single parse %v, separate parses %v", once, ref)
}
