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
	live          map[weak.Pointer[yara.Rules]]struct{}
	managed       map[weak.Pointer[yara.Rules]]weak.Pointer[nativeRulesOwner]
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
		o.live = make(map[weak.Pointer[yara.Rules]]struct{})
	}
	// go-yara v4.3.3 installs (*Rules).Destroy. Replace it while r is
	// strongly reachable with exactly the same operation plus observation.
	runtime.SetFinalizer(r, nil)
	runtime.SetFinalizer(r, func(selected *yara.Rules) { o.destroy(selected, key) })
	o.live[key] = struct{}{}
	runtime.KeepAlive(r)
}

// destroy must also be used for any future explicit destruction of an observed
// object, under the caller's existing exclusive lifetime ownership. Production
// uses explicit ownership for main and finalizers for auxiliary-only Rules. Serializing the
// native operation with removal makes count reads observe complete transitions.
func (o *ruleGenerationObserver) destroy(r *yara.Rules, key weak.Pointer[yara.Rules]) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, exists := o.live[key]; !exists {
		return
	}
	if o.beforeDestroy != nil {
		o.beforeDestroy(r)
	}
	r.Destroy()
	delete(o.live, key)
	runtime.KeepAlive(r)
}

func (o *ruleGenerationObserver) count() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return uint64(len(o.live))
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
	o.observer.mu.Lock()
	delete(o.observer.managed, key)
	o.observer.mu.Unlock()
	o.mu.Lock()
	o.destroyed = true
	o.mu.Unlock()
	runtime.KeepAlive(o)
}

// adopt transfers a fresh candidate to explicit ownership, or retains the
// existing owner for an alias. Caller releases the returned reference.
func (o *ruleGenerationObserver) adopt(r *yara.Rules) *nativeRulesOwner {
	if r == nil {
		return nil
	}
	key := weak.Make(r)
	o.mu.Lock()
	defer o.mu.Unlock()
	if existing := o.managed[key].Value(); existing != nil {
		existing.retain()
		return existing
	}
	runtime.SetFinalizer(r, nil)
	owner := &nativeRulesOwner{rules: r, refs: 1, observer: o}
	runtime.SetFinalizer(owner, (*nativeRulesOwner).destroy)
	if o.live == nil {
		o.live = make(map[weak.Pointer[yara.Rules]]struct{})
	}
	if o.managed == nil {
		o.managed = make(map[weak.Pointer[yara.Rules]]weak.Pointer[nativeRulesOwner])
	}
	o.live[key] = struct{}{}
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
	owner := o.managed[weak.Make(r)].Value()
	if owner != nil {
		owner.retain()
	}
	return owner
}
