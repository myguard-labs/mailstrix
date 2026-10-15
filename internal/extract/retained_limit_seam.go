package extract

import "sync/atomic"

// retainedLimitOverride is a test-only replacement for the default retained
// ceiling used by FullOptions and by unset request limits. Zero (the
// production state) means DefaultRetainedBytesLimit applies.
var retainedLimitOverride atomic.Int64

// defaultRetainedLimit returns the effective default request ceiling.
func defaultRetainedLimit() int64 {
	if v := retainedLimitOverride.Load(); v > 0 {
		return v
	}
	return DefaultRetainedBytesLimit
}

// SetDefaultRetainedBytesLimitForTest overrides the default request ceiling and
// returns a restore func. It lets black-box per-format cap tests, whose members
// legitimately exceed the calibrated ceiling E, exercise those caps without
// tripping the whole-request retained ledger; enforcement tests set an explicit
// Options.RetainedBytesLimit instead. Production never calls it; n <= 0
// restores the default.
func SetDefaultRetainedBytesLimitForTest(n int64) (restore func()) {
	prev := retainedLimitOverride.Swap(n)
	return func() { retainedLimitOverride.Store(prev) }
}

// EffectiveDefaultRetainedBytesLimit reports the default request ceiling in
// force: DefaultRetainedBytesLimit unless a test override is installed.
func EffectiveDefaultRetainedBytesLimit() int64 { return defaultRetainedLimit() }
