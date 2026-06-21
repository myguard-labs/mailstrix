package extract

import (
	"bytes"
	"testing"
	"time"
)

// timeToFiletime converts a time.Time to a Windows FILETIME (100-ns ticks since
// 1601-01-01) for fixture construction. Goes through Unix seconds (not a scaled
// Duration, which overflows int64 across the 369-year 1601→1970 gap).
func timeToFiletime(t time.Time) uint64 {
	return uint64(t.Unix()+filetimeEpochUnix)*10_000_000 + uint64(t.Nanosecond())/100
}

func streamHasNeedle(res *Result, needle string) bool {
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte(needle)) {
			return true
		}
	}
	return false
}

// A directory entry stamped well into the future is flagged.
func TestOLETimesFuture(t *testing.T) {
	future := timeToFiletime(time.Now().Add(10 * 365 * 24 * time.Hour))
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "S1", mse: 2, data: []byte("S1-DATA reachable"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true,
			ctime: future, mtime: future},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if !streamHasNeedle(&res, "OLETIMES-FUTURE") {
		t.Fatalf("future-dated entry not flagged; streams=%d", len(res.Streams))
	}
}

// >= minSyntheticIdentical entries sharing one non-zero (create,modify) pair are
// flagged as builder-fabricated.
func TestOLETimesSyntheticIdentical(t *testing.T) {
	stamp := timeToFiletime(time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC))
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true,
			ctime: stamp, mtime: stamp},
		{name: "S1", mse: 2, data: []byte("S1-DATA reachable"),
			left: cfbFree, right: 2, child: cfbFree, linksSet: true, ctime: stamp, mtime: stamp},
		{name: "S2", mse: 2, data: []byte("S2-DATA reachable"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true, ctime: stamp, mtime: stamp},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if !streamHasNeedle(&res, "OLETIMES-SYNTHETIC") {
		t.Fatalf("synthetic-identical stamps not flagged; streams=%d", len(res.Streams))
	}
}

// A normal doc (zero stamps, or fewer than the threshold sharing a stamp) does
// NOT trip either marker — the FP gate.
func TestOLETimesNoFalsePositive(t *testing.T) {
	// Two distinct old stamps, all zero elsewhere: not future, not >=3 identical.
	a := timeToFiletime(time.Date(2019, 5, 5, 0, 0, 0, 0, time.UTC))
	b := timeToFiletime(time.Date(2021, 6, 6, 0, 0, 0, 0, time.UTC))
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "S1", mse: 2, data: []byte("S1-DATA reachable"),
			left: cfbFree, right: 2, child: cfbFree, linksSet: true, ctime: a, mtime: a},
		{name: "S2", mse: 2, data: []byte("S2-DATA reachable"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true, ctime: b, mtime: b},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if streamHasNeedle(&res, "OLETIMES-FUTURE") || streamHasNeedle(&res, "OLETIMES-SYNTHETIC") {
		t.Fatalf("benign timestamps falsely flagged")
	}
}

// Null (zero) FILETIMEs — the overwhelmingly common Office case — never trip.
func TestOLETimesZeroIgnored(t *testing.T) {
	var res Result
	fromOLETimes(nil, &res, time.Time{}) // nil must not panic
	if len(res.Streams) != 0 {
		t.Fatalf("nil OLE produced streams: %d", len(res.Streams))
	}
	if _, ok := filetimeToTime(0); ok {
		t.Fatalf("zero FILETIME must report ok=false")
	}
}
