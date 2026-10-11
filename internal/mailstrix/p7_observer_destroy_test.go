package mailstrix

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	yara "github.com/hillu/go-yara/v4"
)

func p7ObserverPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("terminal native identity accepted a new reference")
		}
	}()
	fn()
}

// TryLock is the regression oracle. The channel deadline below bounds a broken
// test; it is not a throughput/timing claim. No native call uses freed Rules.
func TestP7ObserverDestroyOutsideLock(t *testing.T) {
	for _, managed := range []bool{false, true} {
		name := "observed"
		if managed {
			name = "managed"
		}
		t.Run(name, func(t *testing.T) {
			o := new(ruleGenerationObserver)
			r := observerRules(t)
			key := weak.Make(r)
			var owner *nativeRulesOwner
			if managed {
				owner = o.adopt(r)
			} else {
				o.observe(r)
			}
			other := observerRules(t)
			otherOwner := o.adopt(other)
			fresh := observerRules(t)
			entered, unblock, done := make(chan bool, 1), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			o.beforeDestroy = func(selected *yara.Rules) {
				if selected != r {
					return
				}
				calls.Add(1)
				unlocked := o.mu.TryLock()
				if unlocked {
					o.mu.Unlock()
				}
				entered <- unlocked
				<-unblock
			}
			var once sync.Once
			release := func() { once.Do(func() { close(unblock) }) }
			defer release()
			go func() {
				defer close(done)
				if managed {
					owner.release()
				} else {
					o.destroy(r, key)
				}
			}()
			if !<-entered {
				release()
				<-done
				otherOwner.release()
				fresh.Destroy()
				t.Fatal("native destruction holds observer mutex")
			}
			progress := make(chan struct{})
			go func() {
				defer close(progress)
				if got := o.count(); got != 2 {
					t.Errorf("blocked native destructor count=%d want=2", got)
				}
				retained := o.retainManaged(other)
				if retained != otherOwner {
					t.Error("unrelated retain lost identity")
				}
				retained.release()
				adopted := o.adopt(fresh)
				if got := o.count(); got != 3 {
					t.Errorf("unrelated adoption count=%d want=3", got)
				}
				adopted.release()
				// Same-identity duplicates return without touching native memory.
				o.destroy(r, key)
				o.observe(r)
				p7ObserverPanic(t, func() { o.adopt(r) })
				p7ObserverPanic(t, func() { o.retainManaged(r) })
				if managed {
					owner.destroy() // same entry as its owner finalizer
					p7ObserverPanic(t, owner.retain)
				}
			}()
			select {
			case <-progress:
			case <-time.After(10 * time.Second):
				release()
				<-done
				<-progress
				t.Error("unrelated ownership work blocked by native destruction")
			}
			release()
			<-done
			// The local hook captures r; clear it so tombstone cleanup can collect Rules.
			o.mu.Lock()
			o.beforeDestroy = nil
			o.mu.Unlock()
			if got := o.count(); got != 1 {
				t.Errorf("completed destructor count=%d want=1", got)
			}
			o.destroy(r, key)
			o.observe(r)
			p7ObserverPanic(t, func() { o.adopt(r) })
			p7ObserverPanic(t, func() { o.retainManaged(r) })
			if calls.Load() != 1 {
				t.Errorf("native destruction calls=%d want=1", calls.Load())
			}
			otherOwner.release()
			if o.count() != 0 {
				t.Error("completed native releases remained counted")
			}
			runtime.KeepAlive(r)
			runtime.KeepAlive(owner)
		})
	}
}

func TestP7ObserverWeakOwnerCannotBeReplaced(t *testing.T) {
	o := new(ruleGenerationObserver)
	r := observerRules(t)
	owner := o.adopt(r)
	key := weak.Make(r)
	// Deterministically model the weak handle cleared before its finalizer is
	// scheduled. Keep the true owner alive so no native finalizer races the test.
	o.mu.Lock()
	o.managed[key] = weak.Pointer[nativeRulesOwner]{}
	o.mu.Unlock()
	p7ObserverPanic(t, func() { o.adopt(r) })
	p7ObserverPanic(t, func() { o.retainManaged(r) })
	if o.count() != 1 {
		t.Fatal("pending owner lost native accounting")
	}
	owner.release()
	if o.count() != 0 {
		t.Fatal("pending owner did not destroy exactly once")
	}
}

func TestP7ObserverObservedAdoptionAndTombstoneCleanup(t *testing.T) {
	o := new(ruleGenerationObserver)
	if o.adopt(nil) != nil || o.retainManaged(nil) != nil {
		t.Fatal("nil rules gained an owner")
	}
	func() {
		r := observerRules(t)
		o.observe(r)
		if o.retainManaged(r) != nil {
			t.Fatal("observed-only rules gained a managed reference")
		}
		owner := o.adopt(r)
		alias := o.adopt(r)
		if owner != alias || o.count() != 1 {
			t.Fatal("observed adoption created duplicate ownership/accounting")
		}
		alias.release()
		owner.release()
		runtime.KeepAlive(r)
	}()
	// Actual GC exercises the post-Destroy cleanup finalizer without a second
	// native operation. Count is already zero before any collection.
	if o.count() != 0 {
		t.Fatal("tombstone is counted as native memory")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		o.mu.Lock()
		empty := len(o.live) == 0 && len(o.managed) == 0
		o.mu.Unlock()
		if empty {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("destroyed weak identity tombstone retained after Rules GC")
}
