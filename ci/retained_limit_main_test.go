package ci

import (
	"os"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// The tests in this package drive per-format caps (up to 16 MiB members) through
// extract.Extract. Those members exceed the calibrated retained ceiling E, which
// is enforced by ci/extraction-budget with explicit limits. Lift the default
// here so these tests keep measuring their own caps.
func TestMain(m *testing.M) {
	extract.SetDefaultRetainedBytesLimitForTest(1 << 30)
	os.Exit(m.Run())
}
