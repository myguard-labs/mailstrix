package ci

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	yara "github.com/hillu/go-yara/v4"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

// The daemon's Run loop is what actually keeps rules current in production; the
// single-Poll tests in internal/mailstrix do not prove that the schedule fires
// again, recovers from a failed check, or honours its jitter window. These tests
// drive the real Run loop on synctest's fake clock against an in-memory
// publisher whose manifest is signed by a throwaway operator key, trusted only
// through RulesExtraSigningKeys so the full signature gate still runs.

const runUpdateURL = "http://rules.test"

var runUpdateSigner = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6d}, ed25519.SeedSize))

// runUpdatePublisher serves one release at a time; failing makes every request
// answer 503, modelling an unreachable or broken mirror.
type runUpdatePublisher struct {
	mu       sync.Mutex
	failing  bool
	manifest []byte
	sig      []byte
	bundle   []byte
	requests atomic.Int64
}

func (p *runUpdatePublisher) publish(t *testing.T, version int, rule string) {
	t.Helper()
	bundle := runUpdateBundle(t, rule)
	sum := sha256.Sum256(bundle)
	m := ms.RulesManifest{
		Version: version, Generated: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), Libyara: "4.5.2",
		Checksum: "sha256:" + hex.EncodeToString(sum[:]), Rules: 1, Size: int64(len(bundle)),
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failing = false
	p.manifest, p.bundle = body, bundle
	p.sig = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(runUpdateSigner, body)) + "\n")
}

func (p *runUpdatePublisher) fail() {
	p.mu.Lock()
	p.failing = true
	p.mu.Unlock()
}

// RoundTrip answers in memory: no sockets or transport goroutines enter the
// synctest bubble, so the fake clock advances whenever Run waits on its timer.
func (p *runUpdatePublisher) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
	p.requests.Add(1)
	p.mu.Lock()
	failing, manifest, sig, bundle := p.failing, p.manifest, p.sig, p.bundle
	p.mu.Unlock()
	rec := httptest.NewRecorder()
	switch name := filepath.Base(r.URL.Path); {
	case failing:
		rec.WriteHeader(http.StatusServiceUnavailable)
	case strings.HasSuffix(name, ".sig"):
		_, _ = rec.Write(sig)
	case strings.HasSuffix(name, ".json"):
		_, _ = rec.Write(manifest)
	case name == "compiled.yac":
		_, _ = rec.Write(bundle)
	default:
		rec.WriteHeader(http.StatusNotFound)
	}
	res := rec.Result()
	res.Request = r
	return res, nil
}

func runUpdateBundle(t *testing.T, rule string) []byte {
	t.Helper()
	c, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if err := c.AddString(rule, ""); err != nil {
		t.Fatal(err)
	}
	r, err := c.GetRules()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type runUpdateFixture struct {
	pub     *runUpdatePublisher
	cfg     *ms.Config
	scanner *ms.Scanner
	updater *ms.RulesUpdater
	flushes atomic.Int64
}

// newRunUpdateFixture installs release 1 into a fresh cache exactly as
// `strixd fetch-rules` would, then boots a scanner and updater on that cache.
func newRunUpdateFixture(t *testing.T, interval time.Duration) *runUpdateFixture {
	t.Helper()
	pub := &runUpdatePublisher{}
	pub.publish(t, 1, "rule Release1 { condition: true }")
	dir := t.TempDir()
	key := base64.StdEncoding.EncodeToString(runUpdateSigner[ed25519.SeedSize:])
	trusted, err := ms.ParseRulesSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.FetchRulesWithExtraKeys(context.Background(), runUpdateURL, dir, "4.5.2", &http.Client{Transport: pub}, true, []ed25519.PublicKey{trusted}); err != nil {
		t.Fatalf("seed release 1: %v", err)
	}
	cfg := &ms.Config{
		CacheDir: dir, RulesPath: filepath.Join(dir, "compiled.yac"),
		RulesURL: runUpdateURL, RulesAllowHTTP: true, RulesPollInterval: interval,
		RulesFetchTimeout: 30 * time.Second, RulesExtraSigningKeys: []string{key},
		ScanTimeout: time.Second,
	}
	cfg.Finalize()
	s, err := ms.NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	f := &runUpdateFixture{pub: pub, cfg: cfg, scanner: s}
	f.updater, err = ms.NewRulesUpdater(cfg, s, "4.5.2", func() { f.flushes.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	pub.requests.Store(0)
	// The daemon client uses the default transport; route it to the publisher.
	feedUseTransport(t, pub.RoundTrip)
	return f
}

func (f *runUpdateFixture) requireRule(t *testing.T, want string) {
	t.Helper()
	matches, err := f.scanner.Scan([]byte("harmless"), ms.ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Rule != want {
		t.Fatalf("active rules matched %+v, want only %q", matches, want)
	}
}

// startRun launches Run inside the bubble and returns a stop function that
// cancels it and proves the loop exits.
func (f *runUpdateFixture) startRun(t *testing.T) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.updater.Run(ctx) }()
	return func() {
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("Run did not return after cancellation")
		}
	}
}

// A release published while the daemon is running is downloaded, verified,
// loaded and used by scans on a later scheduled tick, never before the interval
// and always within its 20% jitter window. A failed check keeps the old rules
// and the loop retries on the next tick instead of stopping.
func TestRulesUpdaterRunInstallsLaterRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Hour
		f := newRunUpdateFixture(t, interval)
		f.pub.fail()
		stop := f.startRun(t)
		defer stop()

		// Tick 0 runs immediately and fails against the broken mirror.
		synctest.Wait()
		s := f.updater.Snapshot()
		if s.Failures != 1 || s.LastCheck == 0 || s.LastSuccess != 0 || s.LoadedVersion != 1 {
			t.Fatalf("after failed first check: %+v", s)
		}
		f.requireRule(t, "Release1")
		failedRequests := f.pub.requests.Load()
		if failedRequests == 0 {
			t.Fatal("first check made no request")
		}

		// Release 2 appears. Nothing may be fetched before the base interval.
		f.pub.publish(t, 2, "rule Release2 { condition: true }")
		time.Sleep(interval - time.Second)
		synctest.Wait()
		if got := f.pub.requests.Load(); got != failedRequests {
			t.Fatalf("polled before the interval elapsed: %d requests, want %d", got, failedRequests)
		}
		f.requireRule(t, "Release1")

		// By interval+20% the retry tick must have installed and loaded it.
		time.Sleep(interval/5 + 2*time.Second)
		synctest.Wait()
		s = f.updater.Snapshot()
		if s.PublishedVersion != 2 || s.CachedVersion != 2 || s.LoadedVersion != 2 || s.LastSuccess == 0 || s.Failures != 1 {
			t.Fatalf("release 2 not installed by the retry tick: %+v", s)
		}
		f.requireRule(t, "Release2")
		if got := f.flushes.Load(); got != 1 {
			t.Fatalf("verdict cache flushes=%d, want 1 after the upgrade", got)
		}
		reloads := f.scanner.ReloadMetrics().Successes

		// An unchanged release on the following tick checks but does not reload.
		before := f.pub.requests.Load()
		time.Sleep(interval + interval/5 + time.Second)
		synctest.Wait()
		if got := f.pub.requests.Load(); got == before {
			t.Fatal("loop stopped polling after the upgrade")
		}
		if got := f.scanner.ReloadMetrics().Successes; got != reloads {
			t.Fatalf("unchanged release reloaded rules: successes %d -> %d", reloads, got)
		}
		if got := f.flushes.Load(); got != 1 {
			t.Fatalf("unchanged release flushed the verdict cache: flushes=%d", got)
		}
		f.requireRule(t, "Release2")
	})
}

// A verified bundle that libyara rejects is never activated by the loop: the
// active rules and cache stay on release 1 and the next tick still runs.
func TestRulesUpdaterRunKeepsRulesOnBadRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Hour
		f := newRunUpdateFixture(t, interval)
		f.pub.publish(t, 2, "rule Release2 { condition: true }")
		f.pub.mu.Lock()
		f.pub.bundle = []byte("not a compiled yara bundle")
		sum := sha256.Sum256(f.pub.bundle)
		var m ms.RulesManifest
		if err := json.Unmarshal(f.pub.manifest, &m); err != nil {
			f.pub.mu.Unlock()
			t.Fatal(err)
		}
		m.Checksum, m.Size = "sha256:"+hex.EncodeToString(sum[:]), int64(len(f.pub.bundle))
		raw, err := json.Marshal(m)
		if err != nil {
			f.pub.mu.Unlock()
			t.Fatal(err)
		}
		f.pub.manifest = raw
		f.pub.sig = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(runUpdateSigner, f.pub.manifest)) + "\n")
		f.pub.mu.Unlock()

		seed, err := os.ReadFile(f.cfg.RulesPath)
		if err != nil {
			t.Fatal(err)
		}
		stop := f.startRun(t)
		defer stop()
		synctest.Wait()
		for tick := 0; tick < 2; tick++ {
			s := f.updater.Snapshot()
			if s.PublishedVersion != 2 || s.LoadedVersion != 1 || s.CachedVersion != 1 || s.Failures != uint64(tick+1) {
				t.Fatalf("tick %d: bad release changed state: %+v", tick, s)
			}
			f.requireRule(t, "Release1")
			time.Sleep(interval + interval/5 + time.Second)
			synctest.Wait()
		}
		if f.flushes.Load() != 0 {
			t.Fatal("rejected release flushed the verdict cache")
		}
		got, err := os.ReadFile(f.cfg.RulesPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, seed) {
			t.Fatal("rejected release changed the cached release 1 rules")
		}
	})
}

// With polling disabled Run returns at once and never touches the network,
// even when a newer release is available. Real time, not synctest: a broken
// guard spins on zero-length timers, which must fail here rather than hang.
func TestRulesUpdaterRunDisabledStaysOffline(t *testing.T) {
	f := newRunUpdateFixture(t, 0)
	f.pub.publish(t, 2, "rule Release2 { condition: true }")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); f.updater.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("disabled Run kept running")
	}
	if got := f.pub.requests.Load(); got != 0 {
		t.Fatalf("disabled updater made %d requests", got)
	}
	if s := f.updater.Snapshot(); s.Enabled || s.LastCheck != 0 || s.LoadedVersion != 1 {
		t.Fatalf("disabled state=%+v", s)
	}
	f.requireRule(t, "Release1")
}
