package threatfox

import (
	"errors"
	"testing"
)

// TestCheckFeedSize (COR-08): an empty refresh and a collapse to under a tenth
// of a large previous set are rejected; normal growth and shrinkage pass.
func TestCheckFeedSize(t *testing.T) {
	for _, c := range []struct {
		prev, next int
		reject     bool
	}{
		{0, 0, true},       // malformed: empty first load
		{5000, 0, true},    // empty refresh over a good set
		{5000, 499, true},  // collapse to under a tenth
		{5000, 500, false}, // boundary: exactly a tenth is kept
		{999, 1, false},    // small previous set: no drop check
		{0, 10, false},     // first load
		{5000, 6000, false},
	} {
		err := checkFeedSize(c.prev, c.next)
		if got := errors.Is(err, errFeedShrank); got != c.reject {
			t.Errorf("checkFeedSize(%d, %d) = %v, reject=%v", c.prev, c.next, err, c.reject)
		}
	}
}
