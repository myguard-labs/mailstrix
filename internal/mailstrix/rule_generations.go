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
// Registration happens at publication, never on the scan path.
type ruleGenerationObserver struct {
	mu   sync.Mutex
	live map[weak.Pointer[yara.Rules]]struct{}
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
// currently frees observed Rules only through the finalizer. Serializing the
// native operation with removal makes count reads observe complete transitions.
func (o *ruleGenerationObserver) destroy(r *yara.Rules, key weak.Pointer[yara.Rules]) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, exists := o.live[key]; !exists {
		return
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

// RuleGenerations counts all distinct published native objects in the process,
// including retired objects whose go-yara destruction has not completed.
func (s *Scanner) RuleGenerations() uint64 { return observedRuleGenerations.count() }
