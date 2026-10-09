package extract

import (
	"strings"
	"testing"
	"time"
)

func TestBatchWouldCarveEquivalence(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"not batch", "hello world\n", false},
		{"prefilter only", "@echo off\r\n", false},
		{"sub-minimum file", "@echo off\r\n>>\"a.txt\" echo abc\r\n", false},
		{"exactly minimum", "@echo off\r\n>>\"a.txt\" echo abcd\r\n", true},
		{"append reaches 4", "@echo off\r\n>>\"a.txt\" echo a\r\n>>\"a.txt\" echo b\r\n", true}, // a CRLF b = 4
		{"two small files", "@echo off\r\n>>\"a.txt\" echo ab\r\n>>\"b.txt\" echo cd\r\n", false},
		{"block form", "@echo off\r\n>\"a.vbs\" (\r\n echo ab\r\n echo cd\r\n)\r\n", true},
	}
	for _, c := range cases {
		files, _ := carveBatchFiles([]byte(c.in))
		full := false
		for _, f := range files {
			if len(f) >= minMemberBytes {
				full = true
			}
		}
		if got := batchWouldCarve([]byte(c.in)); got != c.want || full != c.want {
			t.Errorf("%s: probe=%v full=%v want %v", c.name, got, full, c.want)
		}
	}
}

func TestBatchProbeStopsEarly(t *testing.T) {
	head := "@echo off\r\n>>\"a.txt\" echo abcdef\r\n"
	tail := strings.Repeat(">>\"b.txt\" echo x\r\n", maxBatchBlocks)
	in := []byte(head + tail)
	if !batchWouldCarve(in) {
		t.Fatal("probe should report true")
	}
	_, _, consumed := carveBatchScan(in, true)
	if consumed >= len(in) || consumed > len(head) {
		t.Fatalf("probe parsed %d of %d bytes; want stop within head (%d)", consumed, len(in), len(head))
	}
	// Real extraction still parses everything.
	_, _, full := carveBatchScan(in, false)
	if full <= len(head) {
		t.Fatalf("full scan stopped early at %d", full)
	}
}

func TestDepthDefaultContentEarlyOrder(t *testing.T) {
	res := &Result{}
	if depthDefaultContent([]byte("plain text"), res, 0, time.Now().Add(time.Minute)) {
		t.Fatal("plain text must report false")
	}
	if !depthDefaultContent([]byte("@echo off\r\n>>\"a.txt\" echo abcd\r\n"), res, 0, time.Now().Add(time.Minute)) {
		t.Fatal("batch dropper must report true")
	}
}
