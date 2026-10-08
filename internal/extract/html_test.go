package extract

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// asciiContainsFold unit tests
// ---------------------------------------------------------------------------

func TestAsciiContainsFold(t *testing.T) {
	cases := []struct {
		haystack string
		needle   string // must be lowercase ASCII
		want     bool
	}{
		// basic matches
		{"<script>", "<script", true},
		{"<SCRIPT>", "<script", true},
		{"<ScRiPt>", "<script", true},
		{"<SVG onload=x>", "<svg", true},
		{"<svg>", "<svg", true},
		// match at start
		{"script", "script", true},
		// match at end
		{"foo<svg", "<svg", true},
		// no match
		{"<div>", "<script", false},
		// empty needle always matches
		{"anything", "", true},
		// needle longer than haystack
		{"hi", "hello", false},
		// empty haystack
		{"", "x", false},
		// both empty
		{"", "", true},
		// non-ASCII bytes adjacent to match — non-ASCII must NOT be folded
		// \x80 must not be treated as 'A'+0x3f or similar
		{"\x80<svg>", "<svg", true},
		{"\xc0SCRIPT\xfe", "script", true}, // bytes.ToLower would NOT fold 0xC0 for ASCII needle
		{"<\xc1cript>", "<script", false},  // \xc1 ≠ 's' after non-fold
		// case variation for download attribute keyword
		{"DOWNLOAD=", "download=", true},
		{"Download=", "download=", true},
		{"download=", "download=", true},
		// onload= variations
		{"OnLoad=alert(1)", "onload=", true},
		{"ONLOAD=", "onload=", true},
		// foreignobject
		{"<ForeignObject>", "<foreignobject", true},
		{"<FOREIGNOBJECT>", "<foreignobject", true},
	}
	for _, c := range cases {
		got := asciiContainsFold([]byte(c.haystack), []byte(c.needle))
		if got != c.want {
			t.Errorf("asciiContainsFold(%q, %q) = %v, want %v",
				c.haystack, c.needle, got, c.want)
		}
	}
}

// TestAsciiContainsFoldMatchesToLower verifies that asciiContainsFold gives
// identical results to bytes.Contains(bytes.ToLower(h), needle) for all
// pure-ASCII needles used in the HTML gate, across haystacks that include
// non-ASCII bytes (0x80–0xFF).
func TestAsciiContainsFoldMatchesToLower(t *testing.T) {
	needles := [][]byte{
		[]byte("<script"),
		[]byte("<svg"),
		[]byte("<a "),
		[]byte("download"),
		[]byte("onload="),
		[]byte("<foreignobject"),
	}
	// Haystacks: pure ASCII variants, mixed-case, and haystacks with high bytes.
	haystacks := [][]byte{
		[]byte("<script>foo</script>"),
		[]byte("<SCRIPT>foo</SCRIPT>"),
		[]byte("<ScRiPt>"),
		[]byte("<svg onload=x>"),
		[]byte("<SVG>"),
		[]byte("<a href=x DOWNLOAD=y>"),
		[]byte("ONLOAD=alert"),
		[]byte("<ForeignObject>"),
		[]byte("plain prose with no tags"),
		[]byte(""),
		// high bytes around a match
		append([]byte{0x80, 0x9F, 0xFF}, []byte("<script>")...),
		append([]byte("<SVG>"), []byte{0xC0, 0xFE}...),
		// high bytes that would be folded by a naive fold (0xC0 is 'A'+0x7F — must not fold)
		{0xC1, 0xC3, 0xC2, 0xC9, 0xD0, 0xD4},
	}
	for _, needle := range needles {
		for _, h := range haystacks {
			want := bytes.Contains(bytes.ToLower(h), needle)
			got := asciiContainsFold(h, needle)
			if got != want {
				t.Errorf("asciiContainsFold(%q, %q) = %v; bytes.ToLower path = %v",
					h, needle, got, want)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Differential marker tests — mixed-case tags must produce identical markers
// to what the old bytes.ToLower path produced.
// ---------------------------------------------------------------------------

func TestHTMLGateMixedCaseDetection(t *testing.T) {
	// Each input uses non-lowercase tag/attribute casing that the old
	// bytes.ToLower path handled. The new asciiContainsFold path must produce
	// byte-identical marker sets.
	cases := []struct {
		name    string
		input   string
		markers []string // all must appear
	}{
		{
			name: "uppercase SCRIPT tag",
			input: `<SCRIPT>var b=new Blob([atob(d)]);var u=URL.createObjectURL(b);` +
				`var a=document.createElement('a');a.DOWNLOAD='x.exe';a.click();</SCRIPT>`,
			markers: []string{"HTML-SMUGGLING-BLOB"},
		},
		{
			name:    "mixed-case SVG with ONLOAD",
			input:   `<SVG ONLOAD="alert(1)"></SVG>`,
			markers: []string{"SVG-SCRIPT"},
		},
		{
			name: "mixed-case SVG with SCRIPT child",
			input: `<Svg xmlns="http://www.w3.org/2000/svg">` +
				`<Script>location.href='http://evil'</Script></Svg>`,
			markers: []string{"SVG-SCRIPT"},
		},
		{
			name: "mixed-case ForeignObject",
			input: `<SVG><FOREIGNOBJECT><body xmlns="http://www.w3.org/1999/xhtml">` +
				`<script>x()</script></body></FOREIGNOBJECT></SVG>`,
			markers: []string{"SVG-SCRIPT"},
		},
		{
			name: "mixed-case DOWNLOAD attribute",
			input: `<a id=x DOWNLOAD="report.iso"></a>` +
				`<script>x.href=URL.createObjectURL(blob);</script>`,
			markers: []string{"HTML-SMUGGLING-BLOB"},
		},
	}
	for _, c := range cases {
		res := runHTML([]byte(c.input))
		for _, want := range c.markers {
			if !streamHas(res, want) {
				t.Errorf("[%s] missing marker %q; streams=%v", c.name, want, htmlStreamsAsStrings(res))
			}
		}
	}
}

// TestHTMLGateMixedCaseDifferential: for a representative set of inputs,
// assert that the new gate produces byte-identical Streams to the reference
// (old bytes.ToLower) implementation captured by runHTMLRef.
func TestHTMLGateMixedCaseDifferential(t *testing.T) {
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x41}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)

	inputs := []struct {
		name  string
		input []byte
	}{
		{"clean prose with stray <", []byte("some prose < more text, no tags")},
		{"blob smuggling classic", []byte(
			`<script>var b=new Blob([atob(data)]);var u=URL.createObjectURL(b);` +
				`var a=document.createElement('a');a.href=u;a.download='x.exe';a.click();</script>`,
		)},
		{"scripted SVG", []byte(`<svg onload="alert(1)"></svg>`)},
		{"SVG foreignObject", []byte(
			`<SVG><foreignObject><body xmlns="http://www.w3.org/1999/xhtml">` +
				`<script>x()</script></body></foreignObject></SVG>`,
		)},
		{"mixed case ScRiPt DOWNLOAD", []byte(
			`<ScRiPt>var b=new Blob([atob(d)]);var u=URL.createObjectURL(b);` +
				`var a=document.createElement('a');a.DOWNLOAD='x.exe';a.click();</ScRiPt>`,
		)},
		{"mixed case ONLOAD SVG", []byte(`<SVG ONLOAD="alert(1)"></SVG>`)},
		{"data URI force-download PK", []byte(
			`<a download="x.zip" href="data:application/octet-stream;base64,` + b64 + `">get</a>`,
		)},
		{"inline data:image no download", []byte(
			`<img src="data:image/png;base64,` +
				base64.StdEncoding.EncodeToString(append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x10}, 32)...)) +
				`">`,
		)},
	}

	for _, c := range inputs {
		got := runHTML(c.input)
		ref := runHTMLRef(c.input)
		if !streamSetsEqual(got.Streams, ref.Streams) {
			t.Errorf("[%s] stream set mismatch:\n  new: %v\n  ref: %v",
				c.name, htmlStreamsAsStrings(got), htmlStreamsAsStrings(ref))
		}
	}
}

// runHTMLRef is the reference implementation using the old bytes.ToLower path,
// used only in differential tests to verify the new gate is detection-identical.
func runHTMLRef(buf []byte) *Result {
	res := &Result{childOpts: FullOptions(time.Time{})}
	fromHTMLSmugglingRef(buf, res, &archiveBudget{}, 0, time.Time{})
	return res
}

// fromHTMLSmugglingRef mirrors the original bytes.ToLower-based detection so
// that the differential test has a ground truth to compare against.
func fromHTMLSmugglingRef(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	if len(buf) == 0 || expired(deadline) {
		return
	}
	head := buf
	if len(head) > htmlScanCap {
		head = head[:htmlScanCap]
	}
	// gate: replicate looksLikeMarkup with old logic
	if !bytes.ContainsRune(head, '<') {
		if !bytes.Contains(head, []byte("Blob")) && !bytes.Contains(head, []byte("data:")) {
			return
		}
	} else {
		lower0 := bytes.ToLower(head)
		if !bytes.Contains(lower0, []byte("<script")) &&
			!bytes.Contains(lower0, []byte("<svg")) &&
			!bytes.Contains(lower0, []byte("<a ")) &&
			!bytes.Contains(lower0, []byte("download")) &&
			!bytes.Contains(head, []byte("Blob")) &&
			!bytes.Contains(head, []byte("data:")) {
			return
		}
	}

	lower := bytes.ToLower(head)

	hasBlobAPI := false
	for _, a := range blobReconstructAPIs {
		if bytes.Contains(head, a) {
			hasBlobAPI = true
			break
		}
	}
	// old regex was NOT (?i) — it ran against lower
	reOld := regexp.MustCompile(`(?:\s|;|"|\.)download\s*=`)
	hasDownload := reOld.Match(lower) || bytes.Contains(head, []byte(".click("))
	if hasBlobAPI && hasDownload && len(res.Streams) < maxStreams {
		res.Streams = append(res.Streams, []byte("HTML-SMUGGLING-BLOB"))
	}

	isSVG := bytes.Contains(lower, []byte("<svg"))
	if isSVG {
		if bytes.Contains(lower, []byte("<script")) ||
			bytes.Contains(lower, []byte("onload=")) ||
			bytes.Contains(lower, []byte("<foreignobject")) {
			if len(res.Streams) < maxStreams {
				res.Streams = append(res.Streams, []byte("SVG-SCRIPT"))
			}
		}
		svgCarved := 0
		for _, m := range reDataURIBase64.FindAllSubmatch(head, htmlMaxDataURIs*2) {
			if svgCarved >= htmlMaxDataURIs || len(res.Streams) >= maxStreams || expired(deadline) {
				break
			}
			dec := decodeDataURIB64(m[1])
			if dec == nil || !hasContainerMagic(dec) {
				continue
			}
			if svgCarved == 0 && len(res.Streams) < maxStreams {
				res.Streams = append(res.Streams, []byte("SVG-EMBEDDED-PAYLOAD"))
			}
			svgCarved++
			extractChild(dec, res, b, depth+1, deadline)
			if len(res.Streams) < maxStreams {
				res.Streams = append(res.Streams, dec)
			}
		}
	}
	if isSVG {
		return
	}
	dataURIMarker := "HTML-SMUGGLING-DATAURI"
	if !hasDownload {
		dataURIMarker = "HTML-DATAURI-CONTAINER"
	}
	carved := 0
	for _, m := range reDataURIBase64.FindAllSubmatch(head, htmlMaxDataURIs*2) {
		if carved >= htmlMaxDataURIs || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		dec := decodeDataURIB64(m[1])
		if dec == nil {
			continue
		}
		isContainer := hasContainerMagic(dec)
		if !hasDownload && !isContainer {
			continue
		}
		if carved == 0 && len(res.Streams) < maxStreams {
			res.Streams = append(res.Streams, []byte(dataURIMarker))
		}
		carved++
		if isContainer {
			extractChild(dec, res, b, depth+1, deadline)
		}
		if len(res.Streams) < maxStreams {
			res.Streams = append(res.Streams, dec)
		}
	}
}

// htmlStreamsAsStrings converts Streams to []string for readable test output.
func htmlStreamsAsStrings(res *Result) []string {
	out := make([]string, 0, len(res.Streams))
	for _, s := range res.Streams {
		if len(s) < 80 {
			out = append(out, string(s))
		} else {
			out = append(out, string(s[:32])+"…")
		}
	}
	return out
}

// streamSetsEqual compares two Streams slices as ordered sequences of markers
// (pure-ASCII marker strings) while treating binary payload blobs as equal if
// they share the same prefix. For the differential test we compare marker
// presence; binary blobs are compared by first 4 bytes (magic) only.
func streamSetsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if bytes.Equal(a[i], b[i]) {
			continue
		}
		// Both blobs: compare magic prefix only.
		if len(a[i]) >= 4 && len(b[i]) >= 4 && bytes.Equal(a[i][:4], b[i][:4]) {
			continue
		}
		return false
	}
	return true
}

// streamHas reports whether res.Streams (or res.Markers) contains an entry equal
// to want. fromHTMLSmuggling emits markers into Streams; the splitPureMarkers
// pass that moves them to Markers runs only in the full Extract path, so the
// unit tests here inspect Streams directly.
func streamHas(res *Result, want string) bool {
	for _, s := range res.Streams {
		if string(s) == want {
			return true
		}
	}
	return false
}

func runHTML(buf []byte) *Result {
	res := &Result{childOpts: FullOptions(time.Time{})}
	fromHTMLSmuggling(buf, res, &archiveBudget{}, 0, time.Time{})
	return res
}

func TestHTMLSmugglingBlobMarker(t *testing.T) {
	pos := []string{
		// classic: atob → Blob → object URL → anchor download.click()
		`<script>var b=new Blob([atob(data)]);var u=URL.createObjectURL(b);
		 var a=document.createElement('a');a.href=u;a.download='invoice.exe';a.click();</script>`,
		// createObjectURL + download attribute in markup
		`<a id=x download="report.iso"></a><script>x.href=URL.createObjectURL(blob);</script>`,
		// msSaveBlob (IE/Edge legacy) + download intent
		`<script>navigator.msSaveBlob(blob,'x.zip');a.download='x.zip';</script>`,
	}
	for _, in := range pos {
		res := runHTML([]byte(in))
		if !streamHas(res, "HTML-SMUGGLING-BLOB") {
			t.Errorf("expected HTML-SMUGGLING-BLOB for:\n%s", in)
		}
	}
}

func TestHTMLSmugglingBlobNoFalsePositive(t *testing.T) {
	// Each lacks one half of the combo, or is benign markup.
	neg := []string{
		`<img src="cat.jpg"><p>hello world</p>`,                       // plain HTML
		`<script>var u=URL.createObjectURL(blob);img.src=u;</script>`, // blob, no download
		`<a href="/files/report.pdf" download="report.pdf">save</a>`,  // download, no blob reconstruct
		`<script>var x=atob("aGk=");console.log(x);</script>`,         // atob, no blob, no download
		`download = configValue;`,                                     // "download" word, no blob API
		``,                                                            // empty
	}
	for _, in := range neg {
		res := runHTML([]byte(in))
		if streamHas(res, "HTML-SMUGGLING-BLOB") {
			t.Errorf("unexpected HTML-SMUGGLING-BLOB (false positive) for:\n%s", in)
		}
	}
}

func TestHTMLSmugglingDataURICarve(t *testing.T) {
	// A force-downloaded base64 data: URI whose payload is a ZIP (PK magic).
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x41}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	in := `<a download="x.zip" href="data:application/octet-stream;base64,` + b64 + `">get</a>`
	res := runHTML([]byte(in))
	if !streamHas(res, "HTML-SMUGGLING-DATAURI") {
		t.Fatal("expected HTML-SMUGGLING-DATAURI marker")
	}
	// The decoded PK payload must be added as a stream (carved for the rule set).
	found := false
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("PK\x03\x04")) {
			found = true
		}
	}
	if !found {
		t.Error("decoded data: URI payload was not carved into Streams")
	}
}

func TestHTMLDataURINoDownloadNoCarve(t *testing.T) {
	// An inline data:image with NO download attribute must not fire/carve.
	b64 := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nfakepngbytes"))
	in := `<img src="data:image/png;base64,` + b64 + `">`
	res := runHTML([]byte(in))
	if streamHas(res, "HTML-SMUGGLING-DATAURI") {
		t.Error("inline data:image without download attr must not emit HTML-SMUGGLING-DATAURI")
	}
}

func TestSVGScriptMarker(t *testing.T) {
	pos := []string{
		`<svg xmlns="http://www.w3.org/2000/svg"><script>location='http://evil'</script></svg>`,
		`<svg onload="alert(1)"></svg>`,
		`<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>x()</script></body></foreignObject></svg>`,
	}
	for _, in := range pos {
		if !streamHas(runHTML([]byte(in)), "SVG-SCRIPT") {
			t.Errorf("expected SVG-SCRIPT for:\n%s", in)
		}
	}
	// Plain (non-scripted) SVG must not fire.
	if streamHas(runHTML([]byte(`<svg><rect width="10" height="10"/></svg>`)), "SVG-SCRIPT") {
		t.Error("plain SVG must not emit SVG-SCRIPT")
	}
}

func TestHTMLScriptURIMarker(t *testing.T) {
	pos := []string{
		`<html><a href="javascript:alert(1)">x</a></html>`,
		`<html><a href="/">y</a><img src='javascript:alert(1)'></html>`,
		`<html><a href="/">y</a><form action="javascript:evil()"><input></form></html>`,
		`<html><a href="/">y</a><button formaction=javascript:evil()>x</button></html>`,
		`<html><a href="vbscript:msgbox(1)">x</a></html>`,
		`<html><A HREF="JaVaScRiPt:alert(1)">x</A></html>`,
		"<html><a href = \"  \t\n javascript:alert(1)\">x</a></html>",
		`<html><a href="javascript:x`,
		`<html><a href=javascript:`,
		`<html><a title="a>b" href="javascript:x">x</a></html>`,
		`<html><!-- c --><a href="javascript:x">x</a></html>`,
	}
	for _, in := range pos {
		if !streamHas(runHTML([]byte(in)), "HTML-SCRIPT-URI") {
			t.Errorf("expected HTML-SCRIPT-URI for:\n%s", in)
		}
	}
	neg := []string{
		`<html><a href="/">y</a><p>click javascript:alert(1) here</p></html>`,
		`<html><a href="https://example.com/javascript:x">x</a></html>`,
		`<html><a data-href="javascript:x">x</a></html>`,
		`plain text href="javascript:alert(1)"`,
		`<html><p>Example: href="javascript:alert(1)"</p></html>`,
		`<html><a href="/">y</a><p>Example: href="javascript:alert(1)"</p></html>`,
		`<html><!-- <a href="javascript:x"> --><p>x</p></html>`,
		`<html><a href="/">y</a><!-- href="javascript:x" --></html>`,
		"<html><a href=\x1ajavascript\x1a>x</a></html>",
		"<html><a href=\x1ajavascript\x1a alert(1)>x</a></html>",
	}
	for _, in := range neg {
		if streamHas(runHTML([]byte(in)), "HTML-SCRIPT-URI") {
			t.Errorf("unexpected HTML-SCRIPT-URI for:\n%s", in)
		}
	}
}

// TestHasScriptURIAttrDirect exercises the scanner without the markup gate.
func TestHasScriptURIAttrDirect(t *testing.T) {
	far := time.Now().Add(time.Hour)
	if hasScriptURIAttr([]byte(`<html><p>Example: href="javascript:alert(1)"</p></html>`), far) {
		t.Error("prose attribute-lookalike must not match")
	}
	if !hasScriptURIAttr([]byte(`<a title='x>y' href="javascript:1">`), far) {
		t.Error("real attribute after quoted > must match")
	}
}

// TestSVGEmbeddedPayloadCarve: an <svg> with an <image href> base64 data: URI
// whose decoded bytes are a container magic (PK zip) must emit
// SVG-EMBEDDED-PAYLOAD and carve the dropper — no download attribute required.
func TestSVGEmbeddedPayloadCarve(t *testing.T) {
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x43}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	in := `<svg xmlns="http://www.w3.org/2000/svg">` +
		`<image href="data:application/octet-stream;base64,` + b64 + `"/></svg>`
	res := runHTML([]byte(in))
	if !streamHas(res, "SVG-EMBEDDED-PAYLOAD") {
		t.Fatalf("expected SVG-EMBEDDED-PAYLOAD marker; streams=%d", len(res.Streams))
	}
	found := false
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("PK\x03\x04")) {
			found = true
		}
	}
	if !found {
		t.Error("decoded SVG-embedded payload was not carved into Streams")
	}
}

// TestSVGEmbeddedPayloadXlinkHref: the legacy xlink:href spelling carries the
// same data: URI and must be carved identically.
func TestSVGEmbeddedPayloadXlinkHref(t *testing.T) {
	payload := append([]byte("%PDF-1.7"), bytes.Repeat([]byte{0x44}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	in := `<svg><image xlink:href="data:image/png;base64,` + b64 + `"/></svg>`
	if !streamHas(runHTML([]byte(in)), "SVG-EMBEDDED-PAYLOAD") {
		t.Error("expected SVG-EMBEDDED-PAYLOAD for xlink:href container payload")
	}
}

// TestSVGEmbeddedPayloadNoFalsePositive: an <svg> inlining real raster art (PNG,
// not a container magic) must NOT fire — legitimate SVG inlines images.
func TestSVGEmbeddedPayloadNoFalsePositive(t *testing.T) {
	// A real-ish PNG header — NOT a container magic (PK/OLE2/MZ/%PDF).
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x10}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(png)
	in := `<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,` + b64 + `"/></svg>`
	res := runHTML([]byte(in))
	if streamHas(res, "SVG-EMBEDDED-PAYLOAD") {
		t.Error("benign inline PNG in SVG wrongly emitted SVG-EMBEDDED-PAYLOAD")
	}
}

// TestSVGEmbeddedPayloadNotFromPlainHTML: a container data: URI in plain HTML
// (no <svg> root) must not be attributed to the SVG path.
func TestSVGEmbeddedPayloadNotFromPlainHTML(t *testing.T) {
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x45}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	// No <svg>: must NOT be attributed to the SVG path. A container payload in a
	// non-downloaded data: URI in plain HTML now carves on the general path as
	// HTML-DATAURI-CONTAINER instead (the container magic is the FP firewall).
	in := `<img src="data:application/octet-stream;base64,` + b64 + `">`
	res := runHTML([]byte(in))
	if streamHas(res, "SVG-EMBEDDED-PAYLOAD") {
		t.Error("non-SVG container data: URI wrongly emitted SVG-EMBEDDED-PAYLOAD")
	}
	if !streamHas(res, "HTML-DATAURI-CONTAINER") {
		t.Error("plain-HTML container data: URI must emit HTML-DATAURI-CONTAINER")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("PK\x03\x04")) {
			found = true
		}
	}
	if !found {
		t.Error("decoded PK container should be carved as a child stream")
	}
}

func TestHTMLDataURIContainerNoFalsePositive(t *testing.T) {
	// Non-container payload (a real PNG) with no download attr must NOT carve.
	payload := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x46}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	in := `<img src="data:image/png;base64,` + b64 + `">`
	res := runHTML([]byte(in))
	if streamHas(res, "HTML-DATAURI-CONTAINER") {
		t.Error("benign inline data:image must not emit HTML-DATAURI-CONTAINER")
	}
}

func TestHTMLSmugglingGateAndFailOpen(t *testing.T) {
	// Non-markup / binary garbage must short-circuit and emit nothing (no panic).
	res := runHTML([]byte{0x00, 0x01, 0x02, 0xff, 0xfe})
	if len(res.Streams) != 0 {
		t.Errorf("non-markup input produced %d streams, want 0", len(res.Streams))
	}
	res = runHTML([]byte(strings.Repeat("just some prose with no tags ", 100)))
	if len(res.Streams) != 0 {
		t.Errorf("plain prose produced %d streams, want 0", len(res.Streams))
	}
}

func TestHTMLDataURICarveCapped(t *testing.T) {
	// Many force-downloaded data: URIs: carve count must be bounded by htmlMaxDataURIs.
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x42}, 32)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	var sb strings.Builder
	sb.WriteString(`<a download="x">`)
	for i := 0; i < htmlMaxDataURIs+10; i++ {
		sb.WriteString(`<a href="data:x;base64,` + b64 + `">`)
	}
	res := runHTML([]byte(sb.String()))
	carved := 0
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("PK\x03\x04")) {
			carved++
		}
	}
	if carved > htmlMaxDataURIs {
		t.Errorf("carved %d data: URIs, want <= %d (cap)", carved, htmlMaxDataURIs)
	}
}

// HTML-smuggling triage must reach an .html part nested inside an archive, not
// just a top-level text part (PR #190 covered top-level only; the extractChild
// default path now also runs fromHTMLSmuggling). A blob-reconstruct+download
// HTML stored in a zip must still surface HTML-SMUGGLING-BLOB.
func TestHTMLSmugglingNestedInZip(t *testing.T) {
	html := []byte(`<script>var b=new Blob([atob(data)]);var u=URL.createObjectURL(b);` +
		`var a=document.createElement('a');a.href=u;a.download='invoice.exe';a.click();</script>`)
	zipBuf := buildZip(t, map[string][]byte{"invoice.html": html})
	res := Extract(zipBuf, time.Time{})
	if !streamsContain(res, "HTML-SMUGGLING-BLOB") {
		t.Error("HTML smuggling inside a zip member was not detected (nested path)")
	}
}
