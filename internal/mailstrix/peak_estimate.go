package mailstrix

import (
	"errors"
	"math/bits"
)

// Errors returned by EstimatePeakBytes.
var (
	// ErrEstimateRSSUnknown: the RSS baseline is unknown (negative). Unknown is
	// never treated as zero overhead.
	ErrEstimateRSSUnknown = errors.New("peak estimate: RSS baseline unknown")
	// ErrEstimateInvalid: inflight, body or extraction bound is negative.
	ErrEstimateInvalid = errors.New("peak estimate: negative input")
	// ErrEstimateOverflow: the result does not fit in uint64. The estimate
	// fails rather than saturating so a wrapped or clamped figure is never
	// reported as a real one.
	ErrEstimateOverflow = errors.New("peak estimate: arithmetic overflow")
)

// EstimatePeakBytes returns rss + n*(b+e) in bytes: rss is the resident
// baseline (negative = unknown), n the concurrency (max_inflight), b the
// per-scan body/buffer bound and e the retained extraction ceiling. Every
// addition and the multiplication are overflow-checked; no value is rounded to
// whole MiB. It is a lower-bound illustration and excludes ICAP pre-admission
// buffers, allocator slack and decoder transients.
func EstimatePeakBytes(rss, n, b, e int64) (uint64, error) {
	if rss < 0 {
		return 0, ErrEstimateRSSUnknown
	}
	if n < 0 || b < 0 || e < 0 {
		return 0, ErrEstimateInvalid
	}
	per, carry := bits.Add64(uint64(b), uint64(e), 0)
	if carry != 0 { // unreachable for int64 inputs; guards a future signature change
		return 0, ErrEstimateOverflow
	}
	hi, prod := bits.Mul64(uint64(n), per)
	if hi != 0 {
		return 0, ErrEstimateOverflow
	}
	total, carry := bits.Add64(uint64(rss), prod, 0)
	if carry != 0 {
		return 0, ErrEstimateOverflow
	}
	return total, nil
}
