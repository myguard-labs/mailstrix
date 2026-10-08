package extract

import (
	"sync/atomic"
	"time"
)

// decryptAttemptOverride is a test-only override of the per-attempt decrypt
// watchdog. Zero (the production state) means maxDecryptAttemptTime applies.
var decryptAttemptOverride atomic.Int64

// decryptAttemptLimit returns the effective per-attempt watchdog.
func decryptAttemptLimit() time.Duration {
	if d := time.Duration(decryptAttemptOverride.Load()); d > 0 {
		return d
	}
	return maxDecryptAttemptTime
}

// SetDecryptAttemptTimeForTest overrides the per-attempt decrypt watchdog and
// returns a restore func. It exists so black-box tests of the cap-stop paths,
// which must decrypt a full maxBytesPerMember member, do not race the 750ms
// production watchdog on loaded -race runners. The scan deadline still clamps
// the wait. Production code never calls it; d <= 0 restores the default.
func SetDecryptAttemptTimeForTest(d time.Duration) (restore func()) {
	prev := decryptAttemptOverride.Swap(int64(d))
	return func() { decryptAttemptOverride.Store(prev) }
}
