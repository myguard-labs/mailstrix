package extract

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

// mzHTMLChain builds n levels of "MZ stub + HTML smuggling page whose data: URI
// carries the next level". MZ is a carved-payload magic but not a depth
// carrier, so each level would re-enter the probe if it recursed.
func mzHTMLChain(n int) []byte {
	cur := []byte("MZ\x90\x00 innermost payload bytes")
	for i := 0; i < n; i++ {
		page := fmt.Sprintf("MZ\x90\x00<html><script>var b=new Blob([atob('x')]);var a=document.createElement('a');a.download='x.exe';a.href='data:application/octet-stream;base64,%s';a.click();</script></html>",
			base64.StdEncoding.EncodeToString(cur))
		cur = []byte(page)
	}
	return cur
}

// A probe Result never walks a carved child: extractChild returns before any
// extractor runs, so the stream count and cap hits stay untouched.
func TestExtractChildProbeDoesNotWalk(t *testing.T) {
	zipData := buildZip(t, map[string][]byte{"a.vbs": []byte("CreateObject(\"WScript.Shell\")")})
	res := &Result{probe: true}
	extractChild(zipData, res, &archiveBudget{}, 1, time.Time{})
	if len(res.Streams) != 0 || len(res.CapHits) != 0 || res.IsArchive {
		t.Fatalf("probe walked child: streams=%d hits=%v", len(res.Streams), res.CapHits)
	}
	// Control: a non-probe Result does walk the same child.
	real := &Result{}
	extractChild(zipData, real, &archiveBudget{}, 1, time.Time{})
	if len(real.Streams) == 0 {
		t.Fatal("control: non-probe walk emitted nothing")
	}
}

// A deeply chained smuggling payload past the depth limit completes with the
// probe appending a bounded number of streams (one level only) and records
// the depth hit once.
func TestDepthDefaultContentProbeBounded(t *testing.T) {
	data := mzHTMLChain(40)
	if bytes.Count(data, []byte("MZ\x90")) != 1 {
		t.Fatal("chain should be base64-nested, single MZ visible")
	}
	res := &Result{}
	if !depthDefaultContent(data, res, maxNestDepth+1, time.Time{}) {
		t.Fatal("chained smuggling past depth not detected")
	}
	extractChild(data, res, &archiveBudget{}, maxNestDepth+1, time.Time{})
	if len(res.Streams) != 0 {
		t.Fatalf("depth stop appended %d streams to the real result", len(res.Streams))
	}
}

// When earlier extractors already filled the stream cap, a batch dropper that
// carves files must still record the cap hit (no emitMember call is reached).
func TestBatchDropperStreamsFullRecordsHit(t *testing.T) {
	dropper := []byte("@echo off\r\n>>\"x.vbs\" echo Set o=CreateObject(\"WScript.Shell\")\r\n>>\"x.vbs\" echo o.Run \"calc\"\r\ncscript x.vbs\r\n")
	res := &Result{}
	for i := 0; i < maxStreams; i++ {
		res.Streams = append(res.Streams, []byte("pad"))
	}
	fromBatchDropper(dropper, res, &archiveBudget{}, 0, time.Time{})
	if len(res.CapHits) != 1 || res.CapHits[0] != "streams" {
		t.Fatalf("CapHits=%v, want [streams]", res.CapHits)
	}
	// Negative control: nothing carved -> no hit even with a full stream list.
	res2 := &Result{}
	for i := 0; i < maxStreams; i++ {
		res2.Streams = append(res2.Streams, []byte("pad"))
	}
	fromBatchDropper([]byte("@echo off\r\nrem none\r\n"), res2, &archiveBudget{}, 0, time.Time{})
	if len(res2.CapHits) != 0 {
		t.Fatalf("no-carve flagged: %v", res2.CapHits)
	}
}
