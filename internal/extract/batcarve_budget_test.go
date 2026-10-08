package extract

import (
	"strings"
	"testing"
	"time"
)

// batchShape builds a .bat whose carve yields one file per content string, in
// order, each written via the single-line append form.
func batchShape(contents ...string) []byte {
	var sb strings.Builder
	sb.WriteString("@echo off\r\n")
	for i, c := range contents {
		name := string(rune('a'+i)) + ".vbs"
		sb.WriteString(">>\"C:\\Temp\\" + name + "\" echo " + c + "\r\n")
	}
	return []byte(sb.String())
}

func hasCap(res *Result, kind string) bool {
	for _, c := range res.CapHits {
		if c == kind {
			return true
		}
	}
	return false
}

// At depth == maxNestDepth the spending member's own extractChild (depth+1)
// returns before its spent-budget cap record, so the loop in fromBatchDropper is
// the only place that can report a carved file left unemitted.
func TestBatchDropperBudgetSpentMidLoopRecordsCap(t *testing.T) {
	full := "WScript.Echo \"payload-one-long-enough\""
	tests := []struct {
		name        string
		contents    []string
		sizes       []int
		members     int
		wantStreams int
		wantCap     bool
	}{
		{"spent mid-loop, tiny then full", []string{full, "x", full + "2"}, []int{len(full), 1, len(full) + 1}, maxArchiveMembers - 1, 1, true},
		{"boundary: budget never spent", []string{full, "x", full + "2"}, []int{len(full), 1, len(full) + 1}, maxArchiveMembers - 3, 2, false},
		{"spent, remainder all tiny", []string{full, "x", "y"}, []int{len(full), 1, 1}, maxArchiveMembers - 1, 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := batchShape(tc.contents...)
			files, _ := carveBatchFiles(buf)
			if len(files) != len(tc.sizes) {
				t.Fatalf("carve produced %d files, want %d", len(files), len(tc.sizes))
			}
			for i, f := range files {
				if len(f) != tc.sizes[i] {
					t.Fatalf("file %d size %d, want %d", i, len(f), tc.sizes[i])
				}
			}
			b := &archiveBudget{members: tc.members}
			res := &Result{}
			fromBatchDropper(buf, res, b, maxNestDepth, time.Time{})
			if len(res.Streams) != tc.wantStreams {
				t.Errorf("streams = %d, want %d", len(res.Streams), tc.wantStreams)
			}
			if got := hasCap(res, "archive-budget"); got != tc.wantCap {
				t.Errorf("archive-budget cap hit = %v, want %v (CapHits=%v)", got, tc.wantCap, res.CapHits)
			}
		})
	}
}
