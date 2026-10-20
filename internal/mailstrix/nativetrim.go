package mailstrix

import (
	"runtime"
	"sync/atomic"
	"time"
)

// A retired ruleset's native memory is freed by a Go finalizer, so it only goes
// back to the allocator after a garbage collection. Forcing one at reload is
// ruled out (the P10 startup test pins reload/scan to zero forced
// collections), so the trim rides the next natural collection instead: a
// sentinel object is armed at reload, and its finalizer fires in the cycle that
// also queues the retired ruleset's finalizer.
var (
	nativeTrimFn = nativeTrim
	// trimDelay lets the retired ruleset's finalizer (queued in the same cycle,
	// run on the single finalizer goroutine) finish before malloc_trim runs.
	trimDelay = 2 * time.Second
	trimArmed atomic.Bool
)

type trimSentinel struct{ _ [32]byte } // >16B so it never joins the tiny allocator

// armNativeTrim schedules one malloc_trim after the next garbage collection.
// Reloads that arrive while a sentinel is pending share it.
func armNativeTrim() {
	if !trimArmed.CompareAndSwap(false, true) {
		return
	}
	// Captured here, not in the finalizer, so tests that swap them never race
	// with a finalizer goroutine.
	trim, delay := nativeTrimFn, trimDelay
	runtime.SetFinalizer(new(trimSentinel), func(*trimSentinel) {
		// Disarm first so a reload landing during the delay arms a fresh sentinel
		// for the cycle that frees its own retired ruleset.
		trimArmed.Store(false)
		go func() {
			time.Sleep(delay)
			trim()
		}()
	})
}
