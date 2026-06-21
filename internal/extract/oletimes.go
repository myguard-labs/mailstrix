package extract

import (
	"fmt"
	"sort"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// OLETIMES-1: flag anomalous CFB directory-entry timestamps. A genuine Office
// document leaves most stream CreateTime/ModifyTime FILETIMEs zero and varies
// the few it sets; a builder that fabricates a CFB en masse tends to stamp every
// entry with one identical non-zero time, or with a clock that runs ahead of
// real time. Both are structural tells with no benign analogue, but zero and
// merely-old times are noisy, so we emit ONLY on:
//   - a future-dated stamp (create or modify beyond now + clock-skew slack), or
//   - >= minSyntheticIdentical entries sharing one identical non-zero
//     (create,modify) pair (mass-fabricated).
//
// The marker is informational (a rule scores it); it is never a verdict on its
// own. The walk is bounded by the directory length and the deadline.
const (
	// Clock-skew tolerance for a "future" stamp — a legitimately fast clock or a
	// sender a few hours ahead must not trip it.
	oleTimeFutureSlack = 48 * time.Hour
	// How many entries must share one identical non-zero (create,modify) pair
	// before it reads as builder-fabricated rather than coincidence.
	minSyntheticIdentical = 3
)

// filetimeEpochUnix is the FILETIME zero point (1601-01-01 UTC) expressed as
// seconds before the Unix epoch (1970-01-01). A FILETIME counts 100-ns ticks
// since 1601.
const filetimeEpochUnix = 11644473600

// filetimeToTime converts a Windows FILETIME (100-ns ticks since 1601) to a
// time.Time. ok is false for the null stamp (0). The conversion goes through
// seconds + nanoseconds (time.Unix), NOT a scaled time.Duration: a real stamp is
// ~1.3e17 ticks, and multiplying that to nanoseconds overflows int64 (Duration's
// max is ~292 years), so Duration math silently wraps. Seconds math does not.
func filetimeToTime(ft uint64) (t time.Time, ok bool) {
	if ft == 0 {
		return time.Time{}, false
	}
	secs := ft / 10_000_000 // 100-ns ticks → seconds
	nsec := (ft % 10_000_000) * 100
	// secs ≤ uint64Max/1e7 ≈ 1.8e12, well within int64 — but make the bound
	// explicit so the conversion is provably safe (silences gosec G115) and a
	// future loosening can't wrap.
	if secs > 1<<62 {
		secs = 1 << 62
	}
	return time.Unix(int64(secs)-filetimeEpochUnix, int64(nsec)).UTC(), true
}

func fromOLETimes(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || len(ole.Directory) == 0 || expired(deadline) {
		return
	}
	future := time.Now().Add(oleTimeFutureSlack)
	// Count identical non-zero (create,modify) pairs. Keyed on the raw uint64s so
	// the clamp above can't merge distinct stamps.
	type ftPair struct{ c, m uint64 }
	identical := make(map[ftPair]int)
	var (
		futureSeen bool
		futureC    uint64
		futureM    uint64
	)
	for _, d := range ole.Directory {
		if d == nil {
			continue
		}
		if expired(deadline) {
			return
		}
		c, m := d.Header.CreateTime, d.Header.ModifyTime
		if c == 0 && m == 0 {
			continue
		}
		if !futureSeen {
			if ct, ok := filetimeToTime(c); ok && ct.After(future) {
				futureSeen, futureC, futureM = true, c, m
			} else if mt, ok := filetimeToTime(m); ok && mt.After(future) {
				futureSeen, futureC, futureM = true, c, m
			}
		}
		if c != 0 && m != 0 {
			identical[ftPair{c, m}]++
		}
	}

	if futureSeen {
		// Report against real time so a baked image is reproducible only up to the
		// stamp itself; the marker carries the offending FILETIMEs, not "now".
		res.Streams = append(res.Streams,
			[]byte(fmt.Sprintf("OLETIMES-FUTURE create=%#016x modify=%#016x", futureC, futureM)))
	}
	// Emit in a deterministic order (Go map iteration is randomized): sort the
	// over-threshold pairs by (create,modify) so the marker stream is stable
	// across runs and the YARA scan input doesn't flap.
	var hits []ftPair
	for p, n := range identical {
		if n >= minSyntheticIdentical {
			hits = append(hits, p)
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].c != hits[j].c {
			return hits[i].c < hits[j].c
		}
		return hits[i].m < hits[j].m
	})
	for _, p := range hits {
		res.Streams = append(res.Streams,
			[]byte(fmt.Sprintf("OLETIMES-SYNTHETIC count=%d create=%#016x modify=%#016x", identical[p], p.c, p.m)))
	}
}
