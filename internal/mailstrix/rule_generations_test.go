package mailstrix

import (
	yara "github.com/hillu/go-yara/v4"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"
)

func observerRules(t *testing.T) *yara.Rules {
	t.Helper()
	c, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if err := c.AddString("rule Observer { condition: true }", ""); err != nil {
		t.Fatal(err)
	}
	r, err := c.GetRules()
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func awaitObserverCount(t *testing.T, o *ruleGenerationObserver, want uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if o.count() == want {
			return
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatalf("native generations=%d want=%d after actual finalizer destruction", o.count(), want)
}
func TestRuleGenerationObserver(t *testing.T) {
	o := new(ruleGenerationObserver)
	o.observe(nil)
	if o.count() != 0 {
		t.Fatal("nil rules counted")
	}
	r := observerRules(t)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); o.observe(r); _ = o.count() }()
	}
	wg.Wait()
	if o.count() != 1 {
		t.Fatal("aliases must count once")
	}
	runtime.GC()
	if o.count() != 1 {
		t.Fatal("reachable native object was freed")
	}
	runtime.KeepAlive(r)
	key := weak.Make(r)
	o.destroy(r, key)
	if !reflect.ValueOf(r).Elem().FieldByName("cptr").IsNil() {
		t.Fatal("native Destroy did not clear the go-yara native pointer")
	}
	o.destroy(r, key)
	if o.count() != 0 {
		t.Fatal("explicit destroy failed or double removal")
	}
	r = nil
	runtime.GC()
	if o.count() != 0 {
		t.Fatal("explicit destruction underflow")
	}
}
func TestRuleGenerationFinalizerNonRetention(t *testing.T) {
	o := new(ruleGenerationObserver)
	func() {
		r := observerRules(t)
		o.observe(r)
		if o.count() != 1 {
			t.Fatal("unreachable native object disappeared before destruction")
		}
		runtime.KeepAlive(r)
	}()
	awaitObserverCount(t, o, 0)
	// Repeat to catch observer growth/retention and address reuse.
	for range 25 {
		func() { r := observerRules(t); o.observe(r); runtime.KeepAlive(r) }()
	}
	awaitObserverCount(t, o, 0)
}
func TestRuleGenerationPinnedReload(t *testing.T) {
	// Disable automatic collection so a retired-unfreed object has a deterministic
	// observation window. Restore process policy even on assertion failure.
	prior := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prior)
	awaitObserverCount(t, &observedRuleGenerations, 0)
	root := markerArtifactFixture(t)
	path := filepath.Join(root, "compiled.yac")
	s, err := NewScanner(&Config{RulesPath: path}, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	observerPinnedReload(t, s)
	awaitObserverCount(t, &observedRuleGenerations, 2)
	old := s.rules.Load()
	oldMarker := s.markerRules.Load()
	if err := os.WriteFile(path, []byte("invalid yara source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Fatal("malformed main reload succeeded")
	}
	if s.rules.Load() != old || s.markerRules.Load() != oldMarker || s.RuleGenerations() != 2 {
		t.Fatal("failed reload changed native identity/count")
	}
	runtime.KeepAlive(old)
	runtime.KeepAlive(oldMarker)
	runtime.KeepAlive(s)
}

// A lease pins both old bundles across successive reloads. Retirement is
// explicit even when Go pointers to the retired Rules remain reachable.
//
//go:noinline
func observerPinnedReload(t *testing.T, s *Scanner) {
	pin := s.acquireScanLease()
	if s.RuleGenerations() != 2 {
		t.Fatalf("initial main+marker=%d want=2", s.RuleGenerations())
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.RuleGenerations() != 4 {
		t.Fatalf("retired-unfreed generations=%d want=4", s.RuleGenerations())
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.RuleGenerations() != 4 {
		t.Fatalf("two reloads with pin=%d want=4", s.RuleGenerations())
	}
	runtime.GC()
	if s.RuleGenerations() != 4 {
		t.Fatal("pinned retired generation was freed")
	}
	if _, err := pin.scan([]byte("fixture"), ScanMeta{}); err != nil {
		t.Fatal(err)
	}
	pin.release()
}

func TestRuleGenerationMarkerFailureAlias(t *testing.T) {
	prior := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prior)
	awaitObserverCount(t, &observedRuleGenerations, 0)
	root := markerArtifactFixture(t)
	s := markerFixtureScanner(t, root, nil)
	marker := s.markerRules.Load()
	owner := p8Owner(t, s, marker)
	if err := os.Remove(filepath.Join(root, "marker-artifact/binding.json")); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.markerRules.Load() != nil || s.RuleGenerations() != 1 {
		t.Fatal("unmatched marker retained or native generation double-counted")
	}
	p7Dead(t, owner)
	if names := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(names, "MarkerPrivate") {
		t.Fatalf("fallback marker detection lost: %s", names)
	}
	runtime.KeepAlive(marker)
	runtime.KeepAlive(s)
}
