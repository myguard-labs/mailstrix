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
// A zero-value budget (limit 0) is a non-enforcing shadow ledger used by probes
// and direct package tests; request ledgers come from newRetainedBudget and
// enforce the whole-entry ceiling. Debits saturate and never wrap.
type retainedBudget struct {
	total      uint64
	admissions uint64
	// limit is the request ceiling E; 0 means non-enforcing.
	limit uint64
	// exhausted latches after a real refusal of a nonempty entry: later nonempty
	// ordinary admissions are refused so no derived output is admitted.
	exhausted bool
	// reserved latches once the diagnostic reserve has been materialized.
	reserved bool
}

// retainedReserveBytes is D, the exact length of the retained-bytes cap marker.
// It is held back from ordinary admissions so the diagnostic always fits in E.
var retainedReserveBytes = uint64(len(capHitMarkerPrefix + "retained-bytes"))

func newRetainedBudget(limit int64) *retainedBudget {
	if limit <= 0 {
		limit = DefaultRetainedBytesLimit
	}
	return &retainedBudget{limit: uint64(limit)}
}

// ordinaryCap is E-D, saturating at zero.
func (b *retainedBudget) ordinaryCap() uint64 {
	if b.limit <= retainedReserveBytes {
		return 0
	}
	return b.limit - retainedReserveBytes
}

// admit is the single enforcing debit. It admits whole entries only: an empty
// entry is a no-op that never exhausts anything, an exact fit succeeds, and a
// real nonempty refusal latches exhaustion without debiting.
func (b *retainedBudget) admit(size uint64) (retainedToken, bool) {
	if b == nil {
		return retainedToken{}, false
	}
	if b.limit != 0 && size > 0 {
		if b.exhausted || size > b.ordinaryCap()-b.ordinaryUsed() {
			b.exhausted = true
			return retainedToken{}, false
		}
	}
	return b.record(size)
}

// ordinaryUsed is the ordinary (non-reserve) debit, clamped to the ceiling.
func (b *retainedBudget) ordinaryUsed() uint64 {
	used := b.total
	if b.reserved {
		used -= retainedReserveBytes
	}
	if c := b.ordinaryCap(); used > c {
		return c
	}
	return used
}

// admitReserve materializes the diagnostic reserve once, even after ordinary
// exhaustion. The final total stays within E because D was held back.
func (b *retainedBudget) admitReserve() bool {
	if b == nil || b.reserved || (b.limit != 0 && b.limit < retainedReserveBytes) {
		return false
	}
	b.reserved = true
	b.record(retainedReserveBytes)
	return true
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

// admitStream admits *p as one whole entry. When own is set the entry is first
// admitted, then copied into a tight array so a small admitted slice never pins
// an unknown (raw, third-party or clamped) backing array; *p is updated to the
// accepted array, which every index and recursive caller must use. Known
// admitted views and fresh tight allocations pass own=false and are reused.
// A result without a request ledger is non-enforcing and unchanged.
func (r *Result) admitStream(p *[]byte, own bool) (retainedToken, bool) {
	if r == nil || r.childOpts == nil {
		return retainedToken{}, true
	}
	token, ok := r.childOpts.retained.admit(uint64(len(*p)))
	if !ok {
		return token, r.childOpts.retained == nil
	}
	if own && len(*p) > 0 {
		*p = append(make([]byte, 0, len(*p)), *p...)
	}
	return token, true
}

// release returns an admitted but never-published entry's bytes to the ledger,
// saturating at zero. It does not clear a latched exhaustion.
func (b *retainedBudget) release(size uint64) {
	if b == nil {
		return
	}
	if size > b.total {
		b.total = 0
		return
	}
	b.total -= size
}

// releaseRetained undoes the debit of an entry admitted by admitStream whose
// publication was skipped (the Streams cap filled while its children ran).
func (r *Result) releaseRetained(data []byte) {
	if r == nil || r.childOpts == nil {
		return
	}
	r.childOpts.retained.release(uint64(len(data)))
}

// appendStream admits and appends one entry to Streams; false means refused.
func (r *Result) appendStream(p *[]byte) bool {
	if _, ok := r.admitStream(p, false); !ok {
		return false
	}
	r.Streams = append(r.Streams, *p)
	return true
}

// appendStreamOwned is appendStream with a copied, tight accepted array.
func (r *Result) appendStreamOwned(p *[]byte) bool {
	if _, ok := r.admitStream(p, true); !ok {
		return false
	}
	r.Streams = append(r.Streams, *p)
	return true
}

// appendOut admits and appends one entry to a local output slice.
func (r *Result) appendOut(out *[][]byte, p *[]byte, own bool) bool {
	if _, ok := r.admitStream(p, own); !ok {
		return false
	}
	*out = append(*out, *p)
	return true
}

// appendStreams admits each entry in order and appends the accepted ones to
// Streams, so each entry has its own outcome rather than the batch as a whole.
func (r *Result) appendStreams(entries [][]byte, own bool) {
	for _, e := range entries {
		r.appendOut(&r.Streams, &e, own)
	}
}

// recordRetained records one stream at its current emitted length. A Result
// built directly by a package test has no request ledger and remains usable.
func (r *Result) recordRetained(data []byte) (retainedToken, bool) {
	if r == nil || r.childOpts == nil {
		return retainedToken{}, false
	}
	return r.childOpts.retained.recordBytes(data)
}

// retainedResult returns the request result explicitly threaded through local
// output helpers. The variadic form preserves the existing nil/direct helper
// callers while scoped production paths pass exactly one request result.
func retainedResult(results []*Result) *Result {
	if len(results) == 0 {
		return nil
	}
	return results[0]
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
