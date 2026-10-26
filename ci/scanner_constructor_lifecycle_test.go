package ci

import (
	"bytes"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

const feedLoopStackFrame = "github.com/myguard-labs/mailstrix/internal/feedrefresh.Loop("

func activeFeedLoops(t *testing.T) int {
	t.Helper()
	var stacks bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&stacks, 2); err != nil {
		t.Fatalf("capture goroutines: %v", err)
	}
	return strings.Count(stacks.String(), feedLoopStackFrame)
}

func TestScannerConstructorLifecycle(t *testing.T) {
	t.Run("successful construction remains usable", func(t *testing.T) {
		dir := t.TempDir()
		reloadWrite(t, dir+"/main.yar", "rule ConstructorReady { condition: false }")
		scanner, err := ms.NewScanner(&ms.Config{RulesDir: dir}, func(string, ...any) {})
		if err != nil {
			t.Fatalf("NewScanner: %v", err)
		}
		defer scanner.Close()
		if scanner.RuleCount() != 1 {
			t.Fatalf("RuleCount=%d, want 1", scanner.RuleCount())
		}
	})

	t.Run("nil close is a no-op", func(t *testing.T) {
		var scanner *ms.Scanner
		scanner.Close()
	})

	t.Run("failed construction closes every feed loop", func(t *testing.T) {
		missingRules := t.TempDir() + "/missing"
		_, originalErr := ms.NewScanner(&ms.Config{RulesDir: missingRules}, func(string, ...any) {})
		if originalErr == nil {
			t.Fatal("disabled-feed construction unexpectedly succeeded")
		}

		before := activeFeedLoops(t)
		cfg := &ms.Config{
			RulesDir:         missingRules,
			URLhausKey:       "constructor-lifecycle",
			MBazaarKey:       "constructor-lifecycle",
			ThreatFoxKey:     "constructor-lifecycle",
			URLhausRefresh:   time.Hour,
			MBazaarRefresh:   time.Hour,
			ThreatFoxRefresh: time.Hour,
		}
		for i := 0; i < 4; i++ {
			scanner, err := ms.NewScanner(cfg, func(string, ...any) {})
			if scanner != nil {
				scanner.Close()
				t.Fatalf("failed construction %d returned a scanner", i)
			}
			if err == nil {
				t.Fatalf("failed construction %d returned no error", i)
			}
			if err.Error() != originalErr.Error() {
				t.Fatalf("failed construction %d replaced ReloadAll error: got %q want %q", i, err, originalErr)
			}
		}

		deadline := time.Now().Add(2 * time.Second)
		for {
			after := activeFeedLoops(t)
			if after <= before {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("failed constructors retained %d feed refresh loops (before=%d after=%d)", after-before, before, after)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}
