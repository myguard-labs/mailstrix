package mailstrix

import (
	"runtime"
	"sync"
	"weak"

	yara "github.com/hillu/go-yara/v4"
)

// ruleGenerationObserver observes native lifetime without owning Rules. Weak
// identities deduplicate retained auxiliary aliases; disappearance of a weak
// pointer is never used as evidence of native destruction. The finalizer owns
// only the independent observer and identity, never a Scanner or Rules.
// Registration happens at candidate adoption/publication, never on the scan path.
type ruleGenerationObserver struct {
	beforeDestroy func(*yara.Rules) // test instrumentation; mu
	mu            sync.Mutex
	liveCount     uint64
	live          map[weak.Pointer[yara.Rules]]*ruleGenerationState
	managed       map[weak.Pointer[yara.Rules]]weak.Pointer[nativeRulesOwner]
}

// A claimed identity cannot gain a new owner, even if its weak owner has
// already disappeared before the owner's finalizer runs. Destroyed identities
// remain tombstones until Rules itself becomes unreachable.
type ruleGenerationState struct {
	claimed bool
}

var observedRuleGenerations ruleGenerationObserver

func (o *ruleGenerationObserver) observe(r *yara.Rules) {
	if r == nil {
		return
	}
	key := weak.Make(r)
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, exists := o.live[key]; exists {
		return
	}
	if o.live == nil {
		o.live = make(map[weak.Pointer[yara.Rules]]*ruleGenerationState)
	}
	// go-yara v4.3.3 installs (*Rules).Destroy. Replace it while r is
	// strongly reachable with exactly the same operation plus observation.
	runtime.SetFinalizer(r, nil)
	runtime.SetFinalizer(r, func(selected *yara.Rules) { o.destroy(selected, key) })
	o.live[key] = new(ruleGenerationState)
	o.liveCount++
	runtime.KeepAlive(r)
}

// destroy must also be used for any future explicit destruction of an observed
// object, under the caller's existing exclusive lifetime ownership. Production
// uses explicit ownership for every published main and auxiliary Rules object.
// Claim under mu, then destroy outside it; the count includes claimed objects
// until native destruction completes. Callers must still exclude native users.
func (o *ruleGenerationObserver) destroy(r *yara.Rules, key weak.Pointer[yara.Rules]) {
	o.mu.Lock()
	state := o.live[key]
	if state == nil || state.claimed {
		o.mu.Unlock()
		return
	}
	state.claimed = true
	beforeDestroy := o.beforeDestroy
	o.mu.Unlock()
	if beforeDestroy != nil {
		beforeDestroy(r)
	}
	r.Destroy()
	// Destroy clears go-yara's finalizer. Install only tombstone cleanup:
	// no native work and no strong reference to Rules or its owner.
	runtime.SetFinalizer(r, func(*yara.Rules) {
		o.mu.Lock()
		delete(o.live, key)
		o.mu.Unlock()
	})
	o.mu.Lock()
	o.liveCount--
	delete(o.managed, key)
	o.mu.Unlock()
	runtime.KeepAlive(r)
}

func (o *ruleGenerationObserver) count() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.liveCount
}

// RuleGenerations counts all distinct adopted/published native objects in the process,
// including retired objects whose go-yara destruction has not completed.
func (s *Scanner) RuleGenerations() uint64 { return observedRuleGenerations.count() }

// nativeRulesOwner is the sole explicit destroyer of one Rules identity. The
// registry uses weak handles: it must not keep a Scanner or its root alive.
type nativeRulesOwner struct {
	mu             sync.Mutex
	rules          *yara.Rules
	refs           int
	destroyed      bool
	destroyClaimed bool
	observer       *ruleGenerationObserver
}

func (o *nativeRulesOwner) retain() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.refs == 0 {
		panic("retaining destroyed native rules")
	}
	o.refs++
}
func (o *nativeRulesOwner) release() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.refs == 0 {
		o.mu.Unlock()
		panic("unbalanced native rules release")
	}
	o.refs--
	last := o.refs == 0
	o.mu.Unlock()
	if last {
		o.destroy()
	}
	runtime.KeepAlive(o)
}

// destroy is shared with the unreachable-owner safety net. Normal retirement
// always comes from a balanced release; no GC is needed for published roots.
func (o *nativeRulesOwner) destroy() {
	o.mu.Lock()
	if o.destroyClaimed {
		o.mu.Unlock()
		return
	}
	o.destroyClaimed = true
	o.refs = 0
	o.mu.Unlock()
	runtime.SetFinalizer(o, nil)
	key := weak.Make(o.rules)
	o.observer.destroy(o.rules, key)
	o.mu.Lock()
	o.destroyed = true
	o.mu.Unlock()
	runtime.KeepAlive(o)
}

// adopt transfers a fresh candidate to explicit ownership, or retains the
// existing owner for an alias. Caller releases the returned reference. Adoption
// of a terminal identity or an unreachable owner is invariant misuse and panics.
func (o *ruleGenerationObserver) adopt(r *yara.Rules) *nativeRulesOwner {
	if r == nil {
		return nil
	}
	key := weak.Make(r)
	o.mu.Lock()
	defer o.mu.Unlock()
	if state := o.live[key]; state != nil && state.claimed {
		panic("adopting destroyed native rules")
	}
	if handle, managed := o.managed[key]; managed {
		existing := handle.Value()
		if existing == nil {
			// Its pending finalizer remains the sole destroyer.
			panic("adopting unreachable native rules owner")
		}
		existing.retain()
		return existing
	}
	runtime.SetFinalizer(r, nil)
	owner := &nativeRulesOwner{rules: r, refs: 1, observer: o}
	runtime.SetFinalizer(owner, (*nativeRulesOwner).destroy)
	if o.live == nil {
		o.live = make(map[weak.Pointer[yara.Rules]]*ruleGenerationState)
	}
	if o.managed == nil {
		o.managed = make(map[weak.Pointer[yara.Rules]]weak.Pointer[nativeRulesOwner])
	}
	if o.live[key] == nil {
		o.live[key] = new(ruleGenerationState)
		o.liveCount++
	}
	o.managed[key] = weak.Make(owner)
	return owner
}

// retainManaged is only called with a live generation pin (or root) already
// protecting r. It supplies a separate dependency for a native scanner.
func (o *ruleGenerationObserver) retainManaged(r *yara.Rules) *nativeRulesOwner {
	if r == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	key := weak.Make(r)
	if state := o.live[key]; state != nil && state.claimed {
		panic("retaining destroyed native rules")
	}
	handle, managed := o.managed[key]
	owner := handle.Value()
	if managed && owner == nil {
		panic("retaining unreachable native rules owner")
	}
	if owner != nil {
		owner.retain()
	}
	return owner
}
