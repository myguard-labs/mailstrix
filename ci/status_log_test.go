package ci_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
	"github.com/myguard-labs/mailstrix/internal/mbazaar"
	"github.com/myguard-labs/mailstrix/internal/threatfox"
	"github.com/myguard-labs/mailstrix/internal/urlhaus"
)

type statusEngine struct {
	ms.ScanEngine
	rules  int64
	reload ms.ReloadMetrics
	uh     urlhaus.Metrics
}

func (e *statusEngine) RuleCount() int64                    { return e.rules }
func (e *statusEngine) Fingerprint() string                 { return "0123456789abcdef0123" }
func (e *statusEngine) ReloadMetrics() ms.ReloadMetrics     { return e.reload }
func (e *statusEngine) URLhausMetrics() urlhaus.Metrics     { return e.uh }
func (e *statusEngine) MBazaarMetrics() mbazaar.Metrics     { return mbazaar.Metrics{} }
func (e *statusEngine) ThreatFoxMetrics() threatfox.Metrics { return threatfox.Metrics{} }

// lockedBuf is a goroutine-safe writer for the emitter under test; every write
// signals wrote so tests wait on the emitter instead of sleeping.
type lockedBuf struct {
	mu    sync.Mutex
	b     bytes.Buffer
	wrote chan struct{}
}

func newLockedBuf() *lockedBuf { return &lockedBuf{wrote: make(chan struct{}, 16)} }

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	n, err := l.b.Write(p)
	l.mu.Unlock()
	select {
	case l.wrote <- struct{}{}:
	default:
	}
	return n, err
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func statusServer(cfg ms.Config, e *statusEngine) *ms.Server {
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 1
	}
	if cfg.MaxInflight == 0 {
		cfg.MaxInflight = 4
	}
	cfg.MaxBody = 4096
	cfg.CacheSize = 1
	cfg.Version = "v-test"
	return ms.NewServer(&cfg, e)
}

// tickLine delivers one tick and blocks until the emitter has written a line.
func tickLine(t *testing.T, ticks chan time.Time, out *lockedBuf) string {
	t.Helper()
	ticks <- time.Now()
	select {
	case <-out.wrote:
	case <-time.After(5 * time.Second):
		t.Fatalf("emitter wrote nothing; output=%q", out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	return lines[len(lines)-1]
}

func TestStatusLineHasEveryField(t *testing.T) {
	e := &statusEngine{rules: 7, reload: ms.ReloadMetrics{LastUnix: 1000, ModUnix: 900},
		uh: urlhaus.Metrics{Enabled: true, LastRefreshUnix: time.Now().Unix(), RefreshFailures: 0}}
	s := statusServer(ms.Config{StatusLog: true, StatusInterval: time.Minute, URLhausRefresh: time.Hour}, e)
	ticks := make(chan time.Time)
	out := newLockedBuf()
	ctx, cancel := context.WithCancel(context.Background())
	done := s.StartStatusLogTicks(ctx, out, ticks)
	line := tickLine(t, ticks, out)
	t.Log(line)
	if !strings.HasPrefix(line, "strixd status: ") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("want exactly one prefixed line, got %q", out.String())
	}
	for _, f := range []string{"version=v-test", "rev=", "uptime_s=", "rss_bytes=", "heap_alloc_bytes=", "heap_inuse_bytes=",
		"healthy=true", "rules=7", "rules_fp=0123456789ab", "rules_loaded_unix=1000", "rules_poll=disabled", "rules_poll_last_unix=",
		"rules_poll_age_s=", "urlhaus=on", "urlhaus_last_refresh_unix=", "urlhaus_failures=0", "mbazaar=off", "threatfox=off",
		"inflight=0", "inflight_max=4", "scan_slots=0", "scans=0", "cache_hits=0", "cache_misses=0", "blocking=none"} {
		if !strings.Contains(line, f) {
			t.Errorf("missing field %q in %q", f, line)
		}
	}
	cancel()
	<-done
}

func TestStatusBlockingForcedDegradations(t *testing.T) {
	now := time.Now().Unix()
	e := &statusEngine{rules: 0, reload: ms.ReloadMetrics{ModUnix: now - 7200},
		uh: urlhaus.Metrics{Enabled: true, LastRefreshUnix: 0, RefreshFailures: 3}}
	s := statusServer(ms.Config{StatusLog: true, RulesMaxAge: time.Hour}, e)
	line := ms.NewStatusLogger(s).Next()
	for _, tok := range []string{"unhealthy", "rules_stale", "urlhaus_failing"} {
		if !strings.Contains(line, tok) {
			t.Errorf("blocking lacks %q: %s", tok, line)
		}
	}
	if strings.Contains(line, "blocking=none") {
		t.Fatalf("blocking must not be none: %s", line)
	}
	// The status verdict must agree with the /health handler it shares a predicate with.
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusServiceUnavailable || w.Body.String() != "no rules" {
		t.Fatalf("/health changed: %d %q", w.Code, w.Body.String())
	}
}

func TestStatusFeedStaleAndRecovery(t *testing.T) {
	now := time.Now().Unix()
	e := &statusEngine{rules: 1, uh: urlhaus.Metrics{Enabled: true, LastRefreshUnix: now - 10*3600, RefreshFailures: 1}}
	s := statusServer(ms.Config{StatusLog: true, URLhausRefresh: time.Hour}, e)
	l := ms.NewStatusLogger(s)
	first := l.Next()
	if !strings.Contains(first, "urlhaus_stale") || !strings.Contains(first, "urlhaus_failing") {
		t.Fatalf("first tick should flag stale+failing: %s", first)
	}
	// No new failures and a fresh refresh: both tokens clear.
	e.uh = urlhaus.Metrics{Enabled: true, LastRefreshUnix: time.Now().Unix(), RefreshFailures: 1}
	if second := l.Next(); !strings.Contains(second, "blocking=none") {
		t.Fatalf("feed should have recovered: %s", second)
	}
}

func TestStatusFeedFailingLatchedUntilRefresh(t *testing.T) {
	now := time.Now().Unix()
	e := &statusEngine{rules: 1, uh: urlhaus.Metrics{Enabled: true, LastRefreshUnix: now - 60, RefreshFailures: 0}}
	s := statusServer(ms.Config{StatusLog: true, URLhausRefresh: 6 * time.Hour}, e)
	l := ms.NewStatusLogger(s)
	if l0 := l.Next(); !strings.Contains(l0, "blocking=none") {
		t.Fatalf("baseline should be healthy: %s", l0)
	}
	// (1) failure counter grows: reported.
	e.uh = urlhaus.Metrics{Enabled: true, LastRefreshUnix: now - 60, RefreshFailures: 1}
	if l1 := l.Next(); !strings.Contains(l1, "urlhaus_failing") {
		t.Fatalf("grown counter must report failing: %s", l1)
	}
	// (2) counter and LastRefresh unchanged: still failing (latched), across ticks.
	for i := 0; i < 3; i++ {
		if l2 := l.Next(); !strings.Contains(l2, "urlhaus_failing") {
			t.Fatalf("failing must stay latched without a new refresh (tick %d): %s", i, l2)
		}
	}
	// (3) LastRefresh advances: cleared.
	e.uh = urlhaus.Metrics{Enabled: true, LastRefreshUnix: now, RefreshFailures: 1}
	if l3 := l.Next(); !strings.Contains(l3, "blocking=none") {
		t.Fatalf("successful refresh must clear failing: %s", l3)
	}
	// Unchanged afterwards stays clear; a fresh failure latches again.
	if l4 := l.Next(); !strings.Contains(l4, "blocking=none") {
		t.Fatalf("must stay clear: %s", l4)
	}
	e.uh = urlhaus.Metrics{Enabled: true, LastRefreshUnix: now, RefreshFailures: 2}
	if l5 := l.Next(); !strings.Contains(l5, "urlhaus_failing") {
		t.Fatalf("new failure must latch again: %s", l5)
	}
}

func TestStatusAdmissionSaturated(t *testing.T) {
	e := &statusEngine{rules: 1}
	s := statusServer(ms.Config{StatusLog: true, MaxInflight: 1}, e)
	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, "/scan", pr)
	req.ContentLength = 100
	req.Header.Set("Content-Length", "100")
	handled := make(chan struct{})
	go func() { defer close(handled); s.ServeHTTP(httptest.NewRecorder(), req) }()
	l := ms.NewStatusLogger(s)
	deadline := time.Now().Add(5 * time.Second)
	var line string
	for time.Now().Before(deadline) {
		if line = l.Next(); strings.Contains(line, "admission_saturated") {
			break
		}
		runtime.Gosched()
	}
	if !strings.Contains(line, "inflight=1 inflight_max=1") || !strings.Contains(line, "blocking=admission_saturated") {
		t.Fatalf("want saturated admission, got %s", line)
	}
	_ = pw.Close() // short body: handler errors out and releases the slot
	<-handled
	if line = l.Next(); !strings.Contains(line, "blocking=none") {
		t.Fatalf("slot not released: %s", line)
	}
}

func TestStatusDisabledStartsNothing(t *testing.T) {
	s := statusServer(ms.Config{StatusLog: false}, &statusEngine{rules: 1})
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	out := newLockedBuf()
	if done := s.StartStatusLogTicks(context.Background(), out, ticks); done != nil {
		t.Fatal("disabled emitter must not start")
	}
	if done := s.StartStatusLog(context.Background(), out); done != nil {
		t.Fatal("disabled production emitter must not start")
	}
	if out.String() != "" || len(ticks) != 1 {
		t.Fatalf("disabled emitter consumed ticks or wrote: %q", out.String())
	}
}

func TestStatusShutdownStopsGoroutine(t *testing.T) {
	s := statusServer(ms.Config{StatusLog: true}, &statusEngine{rules: 1})
	ctx, cancel := context.WithCancel(context.Background())
	done := s.StartStatusLogTicks(ctx, newLockedBuf(), make(chan time.Time))
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("emitter goroutine did not exit on context cancel")
	}
	// Production path with its real ticker also stops and releases the ticker.
	ctx2, cancel2 := context.WithCancel(context.Background())
	stopped := s.StartStatusLog(ctx2, newLockedBuf())
	cancel2()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("production emitter did not stop")
	}
}

func TestStatusIntervalConfig(t *testing.T) {
	load := func(v string) *ms.Config {
		t.Setenv("MAILSTRIX_STATUS_INTERVAL", v)
		t.Setenv("MAILSTRIX_STATUS_LOG", "1")
		c := ms.LoadConfig()
		c.Finalize()
		return c
	}
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 15 * time.Minute},    // default
		{"900", 15 * time.Minute}, // explicit default
		{"60", time.Minute},       // exactly the floor
		{"59", time.Minute},       // just below: raised to floor
		{"1", time.Minute},        // far below
		{"3600", time.Hour},       // above
		{"abc", 15 * time.Minute}, // malformed -> default (envDur idiom)
		{"NaN", 15 * time.Minute}, // NaN rejected
		{"Inf", 15 * time.Minute}, // infinity rejected
		{"-5", 15 * time.Minute},  // negative -> default
		{"0", 15 * time.Minute},   // zero is unset
	}
	for _, tc := range cases {
		c := load(tc.in)
		if !c.StatusLog || c.StatusInterval != tc.want {
			t.Errorf("interval %q: log=%v got %s want %s", tc.in, c.StatusLog, c.StatusInterval, tc.want)
		}
	}
	t.Setenv("MAILSTRIX_STATUS_LOG", "")
	if ms.LoadConfig().StatusLog {
		t.Fatal("status log must be off by default")
	}
}
