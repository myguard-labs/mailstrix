package extract

import "math"

// RetainedAccounting is the immutable, request-complete view of retained
// output accounting. Its fields stay private so callers can inspect the
// snapshot without modifying the ledger that produced it.
type RetainedAccounting struct {
	bytes uint64
}

// Bytes reports the logical retained-output bytes recorded for the request.
func (a RetainedAccounting) Bytes() uint64 { return a.bytes }

// retainedBudget belongs to exactly one ExtractWithOptions invocation. The
// request goroutine is its only writer; nested option copies share its pointer.
// record always admits in P16 and saturates the accounting total on overflow.
// P17 will add enforcement without changing token identity or ownership.
type retainedBudget struct {
	total      uint64
	admissions uint64
}

// retainedToken identifies one admitted output. Alias indexes may carry the
// token without recording the same bytes twice; tokens never transfer between
// request ledgers.
type retainedToken struct {
	owner  *retainedBudget
	serial uint64
}

func (b *retainedBudget) record(size uint64) (retainedToken, bool) {
	if b == nil {
		return retainedToken{}, false
	}
	if size > math.MaxUint64-b.total {
		b.total = math.MaxUint64
	} else {
		b.total += size
	}
	if b.admissions < math.MaxUint64 {
		b.admissions++
	}
	return retainedToken{owner: b, serial: b.admissions}, true
}

func (b *retainedBudget) recordBytes(data []byte) (retainedToken, bool) {
	return b.record(uint64(len(data)))
}

func (b *retainedBudget) owns(token retainedToken) bool {
	return b != nil && token.owner == b && token.serial > 0 && token.serial <= b.admissions
}

func (b *retainedBudget) snapshot() RetainedAccounting {
	if b == nil {
		return RetainedAccounting{}
	}
	return RetainedAccounting{bytes: b.total}
}
