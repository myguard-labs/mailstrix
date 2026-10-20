package mailstrix

import (
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// The trim hook runs once per successful reload, and only after the retired
// ruleset has been destroyed (otherwise the freed pages would not exist yet).
func TestReloadTrimsNativeHeapAfterSuccess(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
	calls, genAtTrim := 0, uint64(0)
	s.trimHook = func() { calls++; genAtTrim = s.RuleGenerations() }
	before := s.RuleGenerations()
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("trim calls after successful reload = %d, want 1", calls)
	}
	if genAtTrim != before {
		t.Fatalf("trim ran with %d live generations, want %d (old ruleset must be destroyed first)", genAtTrim, before)
	}
	if err := s.Reload(); err != nil || calls != 2 {
		t.Fatalf("second reload: err=%v calls=%d, want 2", err, calls)
	}
}

// Negative controls: a failed reload and a reload of a closed scanner free
// nothing, so they must not trim.
func TestReloadDoesNotTrimOnFailure(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
	calls := 0
	s.trimHook = func() { calls++ }
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte("rule broken {"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Fatal("broken reload should error")
	}
	if calls != 0 {
		t.Fatalf("trim ran after failed reload: %d", calls)
	}
	s.Close()
	if err := s.Reload(); err == nil {
		t.Fatal("reload of closed scanner should error")
	}
	if calls != 0 {
		t.Fatalf("trim ran after closed-scanner reload: %d", calls)
	}
}

// The real trim must be callable at any time, including repeatedly and with
// nothing to free.
func TestNativeTrimIsSafe(t *testing.T) {
	for i := 0; i < 3; i++ {
		nativeTrim()
	}
	dir := writeRules(t, eicarRule)
	s := newScannerBudget(t, dir, loadInsensitiveScanTimeout) // trimHook nil: real path
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
}

// The real hook must not force a collection (the P10 startup test pins that),
// yet must still trim once a natural collection has run: arming schedules one
// trim after the next GC, and reloads that overlap share it.
func TestArmNativeTrimFiresAfterCollection(t *testing.T) {
	var calls atomic.Int32
	oldFn, oldDelay := nativeTrimFn, trimDelay
	nativeTrimFn, trimDelay = func() { calls.Add(1) }, 5*time.Millisecond
	t.Cleanup(func() { nativeTrimFn, trimDelay = oldFn, oldDelay })
	trimArmed.Store(false) // earlier tests may have left the real sentinel pending
	armNativeTrim()
	armNativeTrim() // overlapping reload shares the pending sentinel
	deadline := time.Now().Add(10 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("trim never ran after collections")
	}
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("trim calls = %d, want exactly 1 for two overlapping arms", got)
	}
	// Disarmed after firing: a later reload arms a fresh sentinel.
	armNativeTrim()
	for calls.Load() < 2 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("re-armed trim calls = %d, want 2", got)
	}
}
