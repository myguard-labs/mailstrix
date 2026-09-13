package mailstrix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	yara "github.com/hillu/go-yara/v4"
	"github.com/myguard-labs/mailstrix/internal/extract"
)

type capeOfflineTransport struct{}

func (capeOfflineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("CAPE native test prohibits HTTP egress")
}

func requireCAPENativeTimeout(t *testing.T, err error) {
	t.Helper()
	var native yara.Error
	if !errors.As(err, &native) || native.Code != yara.ERROR_SCAN_TIMEOUT {
		t.Fatalf("native timeout precondition: got %T %v", err, err)
	}
}

func requireCAPEUnavailable(t *testing.T, s *Server, body []byte) {
	t.Helper()
	ctx := context.Background()
	verdict, err := s.capeStaticScan(ctx, "alpha", bytes.NewReader(body))
	if ctx.Err() != nil || verdict != "" || !errors.Is(err, ErrCAPEUnavailable) {
		t.Errorf("incomplete native scan admitted: verdict=%q err=%v context=%v", verdict, err, ctx.Err())
	}
}

func requireCAPEUnknown(t *testing.T, s *Server, body []byte) {
	t.Helper()
	verdict, err := s.capeStaticScan(context.Background(), "alpha", bytes.NewReader(body))
	if verdict != "unknown" || err != nil {
		t.Fatalf("successful control: verdict=%q err=%v", verdict, err)
	}
}

func TestCAPENativeRawFailureRecovered(t *testing.T) {
	// Feed refreshes in other tests can still be reading DefaultTransport.
	// Install the offline transport once in a fresh process before any scanner
	// exists, so this test neither races with nor changes their HTTP behavior.
	const child = "MAILSTRIX_TEST_CAPE_NATIVE_CHILD"
	if os.Getenv(child) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCAPENativeRawFailureRecovered$", "-test.count=1", "-test.timeout=15s", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1")
		out, err := cmd.CombinedOutput()
		t.Logf("isolated native regression:\n%s", out)
		if err != nil {
			t.Fatalf("isolated native regression failed: %v", err)
		}
		return
	}
	http.DefaultTransport = capeOfflineTransport{}
	for _, mode := range []string{"canary", "allow"} {
		t.Run(mode, func(t *testing.T) {
			cache := t.TempDir()
			if err := os.WriteFile(filepath.Join(cache, "urlhaus.csv"), []byte(feedCSV), 0600); err != nil {
				t.Fatal(err)
			}
			dir := writeRules(t, `rule Timeout { condition: uint8(0) == 99 and for all i in (1..1000000000): (i > 0) }`)
			cfg := &Config{RulesDir: dir, ScanTimeout: time.Second, CacheDir: cache, URLhausKey: "fixture", URLhausMaxURLs: 64, Canary: mode == "canary"}
			if mode == "allow" {
				cfg.RuleAllowlist = map[string]struct{}{"urlhaus_malware_url": {}, "urlhaus_malware_host": {}}
			}
			cfg.sanitize()
			sc, err := NewScanner(cfg, t.Logf)
			if err != nil {
				t.Fatal(err)
			}
			defer sc.Close()
			body := []byte(feedURLBody)
			_, err = sc.scanOne(sc.rules.Load(), body, scanVars{}, time.Second)
			requireCAPENativeTimeout(t, err)
			ordinary, err := sc.Scan(body, ScanMeta{})
			if err != nil || len(ordinary) == 0 {
				t.Fatalf("mail recovery: matches=%v err=%v", ordinary, err)
			}
			for _, m := range ordinary {
				if !matchIsLogOnly(m) {
					t.Fatalf("mail recovery no longer log-only: %+v", m)
				}
			}
			s := newTestServer(sc, "fixture")
			requireCAPEUnavailable(t, s, body)
			requireCAPEUnknown(t, s, []byte("benign control"))
		})
	}
}

func TestCAPENativePromptRawErrorTrackedAfterFeedRecovery(t *testing.T) {
	// YARA's stack size is process-global. Exercise the deliberately tiny stack
	// in a child so the prompt native error cannot affect parallel scanner tests.
	const child = "MAILSTRIX_TEST_CAPE_NATIVE_STACK_CHILD"
	if os.Getenv(child) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCAPENativePromptRawErrorTrackedAfterFeedRecovery$", "-test.count=1", "-test.timeout=5s", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1")
		out, err := cmd.CombinedOutput()
		t.Logf("isolated prompt native-error regression:\n%s", out)
		if err != nil {
			t.Fatalf("isolated prompt native-error regression failed: %v", err)
		}
		return
	}
	http.DefaultTransport = capeOfflineTransport{}
	if err := yara.SetConfiguration(yara.ConfigStackSize, 1); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	if err := os.WriteFile(filepath.Join(cache, "urlhaus.csv"), []byte(feedCSV), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		RulesDir:       writeRules(t, `rule StackUse { condition: for all i in (1..100): (i > 0) }`),
		ScanTimeout:    5 * time.Second,
		CacheDir:       cache,
		URLhausKey:     "fixture",
		URLhausMaxURLs: 64,
	}
	cfg.sanitize()
	sc, err := NewScanner(cfg, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	matches, err := sc.Scan([]byte(feedURLBody), ScanMeta{Effort: cfg.EffortMax, requireComplete: true})
	var native yara.Error
	if !errors.As(err, &native) || native.Code != yara.ERROR_EXEC_STACK_OVERFLOW {
		t.Fatalf("raw native error was not preserved after feed recovery: matches=%v err=%T %v", matches, err, err)
	}
	if len(matches) != 1 || matches[0].Rule != "URLHAUS_MALWARE_URL" {
		t.Fatalf("feed recovery mismatch: matches=%+v", matches)
	}
}

func TestCAPENativeExtractedFailure(t *testing.T) {
	for _, channel := range []string{"child", "marker"} {
		t.Run(channel, func(t *testing.T) {
			body := makePlainZIP(t, [][]byte{[]byte("X harmless child")})
			condition, tag := "uint8(0) == 88", ""
			if channel == "marker" {
				body = []byte(`{\rtf1\objupdate harmless}`)
				condition, tag = "uint8(0) == 82", " : marker"
			}
			dir := writeRules(t, fmt.Sprintf(`rule Timeout%s { condition: %s and for all i in (1..1000000000): (i > 0) }`, tag, condition))
			cfg := &Config{RulesDir: dir, ScanTimeout: 2 * time.Second}
			cfg.sanitize()
			failures := 0
			sc, err := NewScanner(cfg, func(format string, args ...any) {
				if strings.Contains(format, "scan of extracted stream failed") {
					requireCAPENativeTimeout(t, args[0].(error))
					failures++
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer sc.Close()
			_, err = sc.scanOne(sc.rules.Load(), body, scanVars{}, time.Second)
			if err != nil {
				t.Fatalf("raw success precondition: %v", err)
			}
			res := extract.ExtractWithOptions(body, extract.FullOptions(time.Time{}))
			if channel == "child" && len(res.Streams) == 0 || channel == "marker" && len(res.Markers) == 0 {
				t.Fatalf("missing %s extraction precondition", channel)
			}
			s := newTestServer(sc, "fixture")
			requireCAPEUnavailable(t, s, body)
			if failures != 1 {
				t.Fatalf("native %s timeout count=%d want 1", channel, failures)
			}
			ordinary, err := sc.Scan(body, ScanMeta{})
			if err != nil || len(ordinary) != 0 || failures != 2 {
				t.Fatalf("mail recovery: matches=%v err=%v failures=%d", ordinary, err, failures)
			}
			requireCAPEUnknown(t, s, makePlainZIP(t, [][]byte{[]byte("benign child")}))
		})
	}
}

func TestCAPENativeMalformedContainerRejected(t *testing.T) {
	sc := newScanner(t, writeRules(t, `rule Clean { condition: false }`))
	malformed := append(
		[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
		bytes.Repeat([]byte{0xAB}, 4096)...,
	)
	res := extract.ExtractWithOptions(malformed, extract.FullOptions(time.Time{}))
	if !res.IsDoc || !res.Failed {
		t.Fatalf("malformed fixture precondition: %+v", res)
	}

	s := newTestServer(sc, "fixture")
	requireCAPEUnavailable(t, s, malformed)
	if matches, err := sc.Scan(malformed, ScanMeta{}); err != nil || len(matches) != 0 {
		t.Fatalf("ordinary mail scan no longer fails open: matches=%v err=%v", matches, err)
	}
}

func TestCAPENativeBudgetExhausted(t *testing.T) {
	for _, container := range []bool{false, true} {
		t.Run(fmt.Sprintf("container=%v", container), func(t *testing.T) {
			sc := newScanner(t, writeRules(t, `rule Clean { condition: false }`))
			sc.scanTimeout = time.Second
			sc.bigFileThreshold = 1
			// Delay a synchronous diagnostic after the shared deadline is set.
			// The actual native scanner still succeeds; only the wall-clock
			// budget expires. No fake scanner or production clock hook is used.
			delayed := false
			sc.logf = func(format string, _ ...any) {
				if strings.Contains(format, "no big-file ruleset loaded") {
					time.Sleep(1100 * time.Millisecond)
					delayed = true
				}
			}
			body := []byte("benign plain body")
			if container {
				body = makePlainZIP(t, [][]byte{body})
			}
			_, err := sc.scanOne(sc.rules.Load(), body, scanVars{}, time.Second)
			if err != nil {
				t.Fatalf("native success precondition: %v", err)
			}
			s := newTestServer(sc, "fixture")
			requireCAPEUnavailable(t, s, body)
			if !delayed || sc.RawScanErrs() != 0 {
				t.Fatal("budget-only failure precondition missing")
			}
			sc.bigNilWarned.Store(false)
			if _, err := sc.Scan(body, ScanMeta{}); err != nil {
				t.Fatalf("mail budget behavior changed: %v", err)
			}
			sc.bigFileThreshold = 0
			requireCAPEUnknown(t, s, body)
		})
	}
}
