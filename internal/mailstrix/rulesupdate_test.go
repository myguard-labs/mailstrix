package mailstrix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func seedVerified(t *testing.T, dir string, version int, rule string) {
	t.Helper()
	seedVerifiedWithGenerated(t, dir, version, rule, testRulesManifestGenerated)
}

func seedVerifiedWithGenerated(t *testing.T, dir string, version int, rule, generated string) {
	t.Helper()
	b := compiledYacBytes(t, rule)
	seedLocal(t, dir, version, b)
	sum := sha256.Sum256(b)
	m := RulesManifest{Version: version, Generated: generated, Libyara: "4.5.2", Checksum: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(b))}
	if err := writeLocalManifest(filepath.Join(dir, manifestName), m); err != nil {
		t.Fatal(err)
	}
}

func readRuleFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testUpdaterServer(t *testing.T, url string) (*RulesUpdater, *Server) {
	t.Helper()
	return testUpdaterServerWithSeedGenerated(t, url, testRulesManifestGenerated)
}

func testUpdaterServerWithSeedGenerated(t *testing.T, url, generated string) (*RulesUpdater, *Server) {
	t.Helper()
	dir := t.TempDir()
	seedVerifiedWithGenerated(t, dir, 1, "rule Old { condition: true }", generated)
	cfg := &Config{CacheDir: dir, RulesPath: filepath.Join(dir, cachedRulesName), RulesPollInterval: time.Minute, RulesURL: url, ScanTimeout: time.Second}
	cfg.Finalize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	srv := NewServer(cfg, s)
	u, err := NewRulesUpdater(cfg, s, "4.5.2", srv.FlushCache)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetRulesUpdater(u)
	return u, srv
}

func testUpdater(t *testing.T, url string) *RulesUpdater {
	t.Helper()
	u, server := testUpdaterServer(t, url)
	if server == nil {
		t.Fatal("test server is nil")
	}
	return u
}

func requireUpdaterRule(t *testing.T, u *RulesUpdater, want string) {
	t.Helper()
	matches, err := u.scanner.Scan([]byte("harmless"), ScanMeta{})
	if err != nil {
		t.Fatalf("scan rules: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("match count=%d, want 1: %+v", len(matches), matches)
	}
	if got := matches[0].Rule; got != want {
		t.Fatalf("loaded rule=%q, want %q", got, want)
	}
}

func TestRulesUpdaterUpgradeAndUnchanged(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, "rule New { condition: true }"), 2, "4.5.2", "")
	defer source.Close()
	u, srv := testUpdaterServer(t, source.URL)
	for range 2 {
		if err := u.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	s := u.Snapshot()
	if s.PublishedVersion != 2 || s.CachedVersion != 2 || s.LoadedVersion != 2 || s.LastCheck == 0 || s.LastSuccess == 0 || s.Failures != 0 {
		t.Fatalf("state=%+v", s)
	}
	if got := u.scanner.ReloadMetrics().Successes; got != 2 {
		t.Fatalf("reload successes=%d, want boot+upgrade only", got)
	}
	matches, err := u.scanner.Scan([]byte("harmless"), ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Rule != "New" {
		t.Fatalf("loaded rule not used: %+v", matches)
	}
	w := get(srv, "/version")
	if !strings.Contains(w.Body.String(), `"loaded_version":2`) {
		t.Fatalf("version body=%s", w.Body.String())
	}
	w = get(srv, "/metrics")
	for _, metric := range []string{"mailstrix_rules_published_version 2", "mailstrix_rules_loaded_version 2", "mailstrix_rules_cached_version 2", "mailstrix_rules_age_check_enabled 0"} {
		if !strings.Contains(w.Body.String(), metric) {
			t.Errorf("missing %q", metric)
		}
	}
}

// The rules-current release rolls independently of the tagged binary release:
// a fresh rules identity may load into an unchanged binary, but an equal-version
// or libyara-incompatible publication must not replace the loaded rules.
func TestRulesUpdaterKeepsStableBinaryIdentityWhenRulesRoll(t *testing.T) {
	const (
		stableBinaryRelease      = "v2026.01.15"
		seedRulesPublished       = "2026-06-16T00:00:00Z"
		freshRulesPublished      = "2026-06-17T00:00:00Z"
		staleRulesPublished      = "2026-06-18T00:00:00Z"
		mismatchedRulesPublished = "2026-06-19T00:00:00Z"
	)
	fresh := rulesServerWithGenerated(t, compiledYacBytes(t, "rule Fresh { condition: true }"), 2, "4.5.2", "", freshRulesPublished)
	defer fresh.Close()
	u, srv := testUpdaterServerWithSeedGenerated(t, fresh.URL, seedRulesPublished)
	u.cfg.Version = stableBinaryRelease

	if err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	var version struct {
		Version       string `json:"version"`
		RulesManifest struct {
			Version   int    `json:"version"`
			Generated string `json:"generated"`
		} `json:"rules_manifest"`
	}
	if err := json.Unmarshal(get(srv, "/version").Body.Bytes(), &version); err != nil {
		t.Fatal(err)
	}
	if version.Version != stableBinaryRelease {
		t.Fatalf("binary version=%q, want stable %q", version.Version, stableBinaryRelease)
	}
	if version.RulesManifest.Version != 2 || version.RulesManifest.Generated != freshRulesPublished {
		t.Fatalf("rolling rules identity=%+v, want v2 with its publication time", version.RulesManifest)
	}
	requireUpdaterRule(t, u, "Fresh")

	// Version is the update identity; Generated is audit-only, so changed bytes
	// with the loaded version remain a no-op rather than a replacement.
	stale := rulesServerWithGenerated(t, compiledYacBytes(t, "rule Stale { condition: true }"), 2, "4.5.2", "", staleRulesPublished)
	defer stale.Close()
	u.cfg.RulesURL = stale.URL
	before := u.scanner.ReloadMetrics().Successes
	if err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := u.scanner.ReloadMetrics().Successes; got != before {
		t.Fatalf("stale rules reloaded: successes=%d, want %d", got, before)
	}
	requireUpdaterRule(t, u, "Fresh")

	mismatch := rulesServerWithGenerated(t, compiledYacBytes(t, "rule Mismatch { condition: true }"), 3, "9.9.9", "", mismatchedRulesPublished)
	defer mismatch.Close()
	u.cfg.RulesURL = mismatch.URL
	if err := u.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "libyara") {
		t.Fatalf("mismatched rules error=%v, want libyara refusal", err)
	}
	requireUpdaterRule(t, u, "Fresh")
}

func TestRulesUpdaterCurrentVersionIgnoresPublisherLibyaraSkew(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, "rule Current { condition: true }"), 1, "9.0.0", "")
	defer source.Close()
	u := testUpdater(t, source.URL)
	if err := u.Poll(context.Background()); err != nil {
		t.Fatalf("current rules should remain a successful no-op: %v", err)
	}
	if state := u.Snapshot(); state.LastSuccess == 0 || state.Failures != 0 || state.LoadedVersion != 1 {
		t.Fatalf("unexpected state after current-version check: %+v", state)
	}
}

func TestRulesUpdaterDoesNotReloadUntrustedReconcileManifest(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, "rule Current { condition: true }"), 1, "4.5.2", "")
	defer source.Close()
	u := testUpdater(t, source.URL)
	u.scanner.loadedManifest.Store(nil)
	before := u.scanner.ReloadMetrics().Successes
	u.afterFetch = func() {
		path := filepath.Join(u.cfg.CacheDir, manifestName)
		m := readLocalManifest(path)
		m.Checksum = "sha256:" + strings.Repeat("0", 64)
		if err := writeLocalManifest(path, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := u.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("untrusted reconcile manifest error=%v", err)
	}
	if got := u.scanner.ReloadMetrics().Successes; got != before {
		t.Fatalf("untrusted reconcile manifest triggered reload: successes=%d, want %d", got, before)
	}
	if loaded := u.scanner.loadedManifest.Load(); loaded != nil {
		t.Fatalf("untrusted identity became loaded during reconciliation: %+v", loaded)
	}
	if state := u.Snapshot(); state.Failures != 1 || state.LastFailure == 0 {
		t.Fatalf("untrusted reconcile manifest was not recorded: %+v", state)
	}
	// The next poll starts by treating the untrusted local identity as version
	// zero, so the current remote release is downloaded and repairs the cache.
	u.afterFetch = nil
	if err := u.Poll(context.Background()); err != nil {
		t.Fatalf("next poll did not repair untrusted cache: %v", err)
	}
	if loaded := u.scanner.loadedManifest.Load(); loaded == nil || loaded.Version != 1 {
		t.Fatalf("repaired identity was not loaded: %+v", loaded)
	}
}

func TestRulesAgeRejectsInvalidCachedPublicationOrigin(t *testing.T) {
	for _, generated := range []string{"9999-01-01T00:00:00Z", "1970-01-01T00:00:00Z", "1969-12-31T23:59:59Z"} {
		t.Run(generated, func(t *testing.T) {
			u, srv := testUpdaterServer(t, "")
			path := filepath.Join(u.cfg.CacheDir, manifestName)
			m := readLocalManifest(path)
			m.Generated = generated
			if err := writeLocalManifest(path, m); err != nil {
				t.Fatal(err)
			}
			old := time.Unix(1000000000, 0)
			if err := os.Chtimes(u.scanner.srcFile, old, old); err != nil {
				t.Fatal(err)
			}
			u.cfg.RulesMaxAge = 48 * time.Hour
			if err := u.scanner.Reload(); err != nil {
				t.Fatal(err)
			}
			if got := u.scanner.ReloadMetrics().ModUnix; got != old.Unix() {
				t.Fatalf("age origin=%d, want filesystem fallback %d", got, old.Unix())
			}
			if !srv.rulesStale() {
				t.Fatal("invalid cached publication suppressed stale rules")
			}
		})
	}
}

func TestRulesUpdaterFailureKeepsLoadedAndCache(t *testing.T) {
	for _, tc := range []struct {
		name, libyara, checksum string
		corrupt, reload         bool
	}{
		{name: "checksum", libyara: "4.5.2", checksum: "sha256:" + strings.Repeat("0", 64)},
		{name: "libyara", libyara: "9.0.0"},
		{name: "unloadable", libyara: "4.5.2", corrupt: true},
		{name: "reload", libyara: "4.5.2", reload: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := compiledYacBytes(t, "rule New { condition: true }")
			if tc.corrupt {
				b = []byte("invalid compiled rules")
			}
			source := rulesServer(t, b, 2, tc.libyara, tc.checksum)
			defer source.Close()
			u := testUpdater(t, source.URL)
			path := filepath.Join(u.cfg.CacheDir, cachedRulesName)
			backupPath := path + backupSuffix
			backupBefore := []byte("PREVIOUS-BACKUP")
			if err := os.WriteFile(backupPath, backupBefore, 0o640); err != nil {
				t.Fatal(err)
			}
			before := readRuleFile(t, path)
			manifestBefore := readRuleFile(t, filepath.Join(u.cfg.CacheDir, manifestName))
			if tc.reload {
				u.scanner.srcFile = filepath.Join(t.TempDir(), "missing.yac")
			}
			if err := u.Poll(context.Background()); err == nil {
				t.Fatal("expected failed update")
			}
			s := u.Snapshot()
			if s.CachedVersion != 1 || s.LoadedVersion != 1 || s.LastFailure == 0 || s.LastSuccess != 0 || s.Failures != 1 {
				t.Fatalf("state=%+v", s)
			}
			if tc.reload && s.ReloadFailures != 1 {
				t.Fatalf("reload failure not counted: %+v", s)
			}
			after := readRuleFile(t, path)
			manifestAfter := readRuleFile(t, filepath.Join(u.cfg.CacheDir, manifestName))
			if !bytes.Equal(before, after) || !bytes.Equal(manifestBefore, manifestAfter) {
				t.Fatal("failed update changed last-known-good cache")
			}
			if backupAfter := readRuleFile(t, backupPath); !bytes.Equal(backupBefore, backupAfter) {
				t.Fatal("failed update changed the pre-existing operator backup")
			}
			if got := u.scanner.rules.Load().GetRules()[0].Identifier(); got != "Old" {
				t.Fatalf("active rules changed: %s", got)
			}
		})
	}
}

func TestRulesUpdaterConcurrentPollAndShutdown(t *testing.T) {
	entered := make(chan struct{})
	var requests atomic.Int64
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(entered)
		}
		<-r.Context().Done()
	}))
	defer source.Close()
	u := testUpdater(t, source.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); u.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("poll never started")
	}
	if err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("concurrent poll performed overlapping request")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poll did not stop on cancellation")
	}
}

func TestRulesUpdaterReconcilesExternalFetch(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, "rule External { condition: true }"), 3, "4.5.2", "")
	defer source.Close()
	u := testUpdater(t, source.URL)
	if _, err := FetchRules(context.Background(), source.URL, u.cfg.CacheDir, "4.5.2", source.Client()); err != nil {
		t.Fatal(err)
	}
	if s := u.Snapshot(); s.CachedVersion != 3 || s.LoadedVersion != 1 {
		t.Fatalf("external cache install incorrectly counted as loaded: %+v", s)
	}
	if err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := u.Snapshot(); s.LoadedVersion != 3 {
		t.Fatalf("external fetch not reconciled: %+v", s)
	}
}

func TestFetchRulesRejectsMalformedManifestAndInterruptedDownload(t *testing.T) {
	for _, mode := range []string{"json", "size", "generated", "epoch", "pre_epoch", "future", "checksum", "libyara", "version", "interrupted"} {
		t.Run(mode, func(t *testing.T) {
			bundle := compiledYacBytes(t, "rule New { condition: true }")
			sum := sha256.Sum256(bundle)
			m := RulesManifest{Version: 2, Generated: "2026-06-18T00:00:00Z", Size: int64(len(bundle)), Checksum: fmt.Sprintf("sha256:%x", sum), Libyara: "4.5.2"}
			switch mode {
			case "size":
				m.Size = 0
			case "generated":
				m.Generated = "bad"
			case "epoch":
				m.Generated = "1970-01-01T00:00:00Z"
			case "pre_epoch":
				m.Generated = "1969-12-31T23:59:59Z"
			case "future":
				m.Generated = "9999-01-01T00:00:00Z"
			case "checksum":
				m.Checksum = "md5:abc"
			case "libyara":
				m.Libyara = ""
			case "version":
				m.Version = 0
			}
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, ".json") {
					if mode == "json" {
						if _, err := w.Write([]byte("{")); err != nil {
							return
						}
						return
					}
					if err := json.NewEncoder(w).Encode(m); err != nil {
						return
					}
					return
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(bundle)))
				if mode == "future" {
					if _, err := w.Write(bundle); err != nil {
						return
					}
					return
				}
				if _, err := w.Write(bundle[:len(bundle)/2]); err != nil {
					return
				}
			}))
			defer source.Close()
			u := testUpdater(t, source.URL)
			err := u.Poll(context.Background())
			if mode == "future" && (err == nil || !strings.Contains(err.Error(), "timestamp is in the future")) {
				t.Fatalf("future manifest not rejected before download: %v", err)
			}
			if (mode == "epoch" || mode == "pre_epoch") && (err == nil || !strings.Contains(err.Error(), "after the Unix epoch")) {
				t.Fatalf("nonpositive manifest timestamp not rejected before download: %v", err)
			}
			if err == nil {
				t.Fatal("invalid release accepted")
			}
			if s := u.Snapshot(); s.LoadedVersion != 1 || s.CachedVersion != 1 || s.Failures != 1 {
				t.Fatalf("state=%+v", s)
			}
		})
	}
}

func TestRulesLockCancellation(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockRules(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lockRules(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestRulesAgeDefaultAndExplicitOff(t *testing.T) {
	t.Setenv("MAILSTRIX_RULES_MAX_AGE", "")
	got := LoadConfig().RulesMaxAge
	if got != 48*time.Hour {
		t.Fatalf("default age=%s", got)
	}
	srv := NewServer(&Config{RulesMaxAge: got, MaxConcurrent: 1, MaxBody: 1 << 20}, &fakeEngine{
		count: 1, modUnix: time.Now().Add(-49 * time.Hour).Unix(),
	})
	if w := get(srv, "/ready"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "stale") {
		t.Fatalf("default stale readiness=%d %q, want fail-open 200 with stale body", w.Code, w.Body.String())
	}
	t.Setenv("MAILSTRIX_RULES_MAX_AGE", "0")
	if got := LoadConfig().RulesMaxAge; got != 0 {
		t.Fatalf("explicit off=%s", got)
	}
}

func TestRulesUpdaterDisabledAndCustomSource(t *testing.T) {
	u := testUpdater(t, "http://unused.invalid")
	u.cfg.RulesPollInterval = invalidEnvDuration
	if _, err := NewRulesUpdater(u.cfg, u.scanner, "4.5.2", nil); err == nil || !strings.Contains(err.Error(), "expressed as seconds") {
		t.Fatalf("malformed poll interval error=%v", err)
	}
	for _, invalid := range []time.Duration{-time.Second, 30 * time.Second} {
		u.cfg.RulesPollInterval = invalid
		if _, err := NewRulesUpdater(u.cfg, u.scanner, "4.5.2", nil); err == nil {
			t.Fatalf("accepted invalid poll interval %s", invalid)
		}
	}
	u.cfg.RulesPollInterval = 0
	disabled, err := NewRulesUpdater(u.cfg, u.scanner, "4.5.2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := disabled.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := disabled.Snapshot(); got.LastCheck != 0 || got.Enabled {
		t.Fatalf("disabled updater checked network: %+v", got)
	}
	u.cfg.RulesPollInterval = time.Minute
	u.scanner.cacheDir = ""
	if _, err := NewRulesUpdater(u.cfg, u.scanner, "4.5.2", nil); err == nil {
		t.Fatal("custom source accepted automatic polling")
	}
}

func TestRulesUpdaterRepairsReseededCache(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, "rule Published { condition: true }"), 2, "4.5.2", "")
	defer source.Close()
	u := testUpdater(t, source.URL)
	if err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(t.TempDir(), "seed.yac")
	compiledYac(t, seed, "rule Seed { condition: true }")
	seedTime := time.Unix(1000000000, 0)
	if err := os.Chtimes(seed, seedTime, seedTime); err != nil {
		t.Fatal(err)
	}
	u.cfg.SeedRules = seed
	if err := os.Remove(u.cfg.RulesPath); err != nil {
		t.Fatal(err)
	}
	if err := EnsureCachedRules(u.cfg, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(u.cfg.RulesPath); err != nil || !info.ModTime().Equal(seedTime) {
		t.Fatalf("reseed age=%v, want %v (stat error %v)", info, seedTime, err)
	}
	if err := u.scanner.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := u.Snapshot(); got.LoadedVersion != 2 {
		t.Fatalf("reseeded cache was never repaired: %+v", got)
	}
}

func TestRulesUpdaterNeverDowngradesLoadedRulesDuringCacheRepair(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, "rule Older { condition: true }"), 1, "4.5.2", "")
	defer source.Close()
	u := testUpdater(t, source.URL)
	seedVerified(t, u.cfg.CacheDir, 3, "rule Current { condition: true }")
	if err := u.scanner.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(u.cfg.RulesPath); err != nil {
		t.Fatal(err)
	}
	if err := u.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "older than loaded") {
		t.Fatalf("expected rollback rejection, got %v", err)
	}
	if got := u.scanner.loadedManifest.Load(); got == nil || got.Version != 3 {
		t.Fatalf("loaded identity regressed: %+v", got)
	}
	active := u.scanner.rules.Load().GetRules()
	if len(active) != 1 {
		t.Fatalf("active rules = %d, want 1", len(active))
	}
	if got := active[0].Identifier(); got != "Current" {
		t.Fatalf("active rules regressed: %s", got)
	}
}

func TestRulesTelemetryDoesNotWaitForCacheLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		u, srv := testUpdaterServer(t, "http://unused.invalid")
		before := u.Snapshot()
		unlock, err := lockRules(context.Background(), u.cfg.CacheDir)
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		start := time.Now()
		got := u.Snapshot()
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("telemetry waited for cache lock: %s", elapsed)
		}
		if got.CachedVersion != before.CachedVersion || got.LoadedVersion != before.LoadedVersion {
			t.Fatalf("busy cache lost last-observed identity: %+v -> %+v", before, got)
		}
		if w := get(srv, "/version"); w.Code != http.StatusOK {
			t.Fatalf("version status=%d", w.Code)
		}
		if w := get(srv, "/metrics"); w.Code != http.StatusOK {
			t.Fatalf("metrics status=%d", w.Code)
		}
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("HTTP telemetry waited for cache lock: %s", elapsed)
		}
	})
}

func TestRulesTelemetryRefreshCoalesces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		u, _ := testUpdaterServer(t, "http://unused.invalid")
		if got := u.Snapshot().CachedVersion; got != 1 {
			t.Fatalf("initial cached version=%d, want 1", got)
		}
		manifestPath := filepath.Join(u.cfg.CacheDir, manifestName)
		manifest := readLocalManifest(manifestPath)
		manifest.Version = 2
		if err := writeLocalManifest(manifestPath, manifest); err != nil {
			t.Fatal(err)
		}
		if got := u.Snapshot().CachedVersion; got != 1 {
			t.Fatalf("consecutive telemetry request reread disk: version=%d", got)
		}
		time.Sleep(time.Second)
		if got := u.Snapshot().CachedVersion; got != 2 {
			t.Fatalf("telemetry did not refresh after coalescing window: version=%d", got)
		}
	})
}

func TestRulesTelemetryKeepsCompletedTransactionPair(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, "rule Updated { condition: true }"), 2, "4.5.2", "")
	defer source.Close()
	u := testUpdater(t, source.URL)
	u.afterFetch = func() {
		newer := *u.scanner.loadedManifest.Load()
		newer.Version = 3
		u.scanner.loadedManifest.Store(&newer)
	}
	if err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	got := u.state
	u.mu.Unlock()
	if got.CachedVersion != 2 || got.LoadedVersion != 2 {
		t.Fatalf("coherent transaction pair mixed with later identity: %+v", got)
	}
}

func TestCustomRulesDoNotInheritCachedReleaseIdentity(t *testing.T) {
	dir := t.TempDir()
	seedVerified(t, dir, 9, "rule Cached { condition: true }")
	custom := filepath.Join(t.TempDir(), "local.yac")
	compiledYac(t, custom, "rule Custom { condition: true }")
	cfg := &Config{CacheDir: dir, RulesPath: custom, ScanTimeout: time.Second}
	cfg.Finalize()
	scanner, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	response := get(NewServer(cfg, scanner), "/version")
	if response.Code != http.StatusOK {
		t.Fatalf("version status=%d", response.Code)
	}
	if strings.Contains(response.Body.String(), `"rules_manifest"`) {
		t.Fatalf("unrelated cache manifest describes custom rules: %s", response.Body.String())
	}
}
