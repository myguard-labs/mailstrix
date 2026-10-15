package extractionbudget_test

import (
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func TestDefaultRetainedLimitSeam(t *testing.T) {
	def := extract.DefaultRetainedBytesLimit
	if got := extract.EffectiveDefaultRetainedBytesLimit(); got != def {
		t.Fatalf("production default=%d want=%d", got, def)
	}
	restore := extract.SetDefaultRetainedBytesLimitForTest(def * 4)
	if got := extract.FullOptions(time.Time{}).RetainedBytesLimit; got != def*4 {
		t.Fatalf("override FullOptions limit=%d want=%d", got, def*4)
	}
	restore()
	if got := extract.FullOptions(time.Time{}).RetainedBytesLimit; got != def {
		t.Fatalf("restored limit=%d want=%d", got, def)
	}
	// Non-positive input restores the default rather than disabling the ledger.
	r2 := extract.SetDefaultRetainedBytesLimitForTest(-5)
	defer r2()
	if got := extract.EffectiveDefaultRetainedBytesLimit(); got != def {
		t.Fatalf("non-positive override limit=%d want=%d", got, def)
	}
}
