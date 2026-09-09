package mailstrix

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"sync"
	"time"
)

// RulesUpdateState distinguishes never checked, failed, cached and loaded rules.
// Version zero means unknown; timestamps are Unix seconds, zero means never.
type RulesUpdateState struct {
	Enabled          bool   `json:"enabled"`
	PublishedVersion int    `json:"published_version"`
	CachedVersion    int    `json:"cached_version"`
	LoadedVersion    int    `json:"loaded_version"`
	LastCheck        int64  `json:"last_check_unix"`
	LastSuccess      int64  `json:"last_success_unix"`
	LastFailure      int64  `json:"last_failure_unix"`
	Failures         uint64 `json:"failures"`
	ReloadFailures   uint64 `json:"reload_failures"`
}

// RulesUpdater owns one serial polling loop. Idle -> checking -> installed and
// reloaded, unchanged, or failed -> idle. Cancellation terminates the loop and
// waits for any in-progress attempt before the scanner can be closed.
// Poll serializes callers; cache flock serializes CLI/startup/SIGHUP publication.
// Downloads hold no cache lock. The version is rechecked at install, so a stale
// downloader cannot overwrite a newer publisher. Scanner.mu is always acquired
// AFTER the cache lock. State.mu is never held while acquiring either lock.
// Failed reloads preserve active immutable rules and restore both cache files.
// Existing scans may finish on the old rules; new scans see the atomic swap.
type RulesUpdater struct {
	mu              sync.Mutex
	poll            sync.Mutex
	state           RulesUpdateState
	cfg             *Config
	scanner         *Scanner
	libyara         string
	client          *http.Client
	flush           func()
	snapshotRefresh time.Time
	afterFetch      func() // test scheduling seam after the cache transaction releases
}

// SetRulesUpdater connects update telemetry before the server starts listening.
func (s *Server) SetRulesUpdater(u *RulesUpdater) { s.rulesUpdater = u }

// NewRulesUpdater binds polling to the cache actually used by the scanner.
// Source-directory and fallback scanners never silently switch to remote rules.
func NewRulesUpdater(cfg *Config, scanner *Scanner, libyara string, flush func()) (*RulesUpdater, error) {
	if cfg.RulesPollInterval == invalidEnvDuration {
		return nil, fmt.Errorf("MAILSTRIX_RULES_POLL_INTERVAL must be expressed as seconds (for example 900)")
	}
	if cfg.RulesPollInterval < 0 || (cfg.RulesPollInterval > 0 && cfg.RulesPollInterval < time.Minute) {
		return nil, fmt.Errorf("rules poll interval must be zero or at least one minute")
	}
	if cfg.RulesPollInterval > 0 && scanner.cacheDir == "" {
		return nil, fmt.Errorf("rules polling requires an active compiled rules cache")
	}
	// Poll's configured context bounds network and lock acquisition. Native
	// libyara load/reload calls cannot be safely preempted once entered, so the
	// client must not impose a second, shorter transport timeout.
	u := &RulesUpdater{cfg: cfg, scanner: scanner, libyara: libyara, flush: flush, client: &http.Client{}}
	u.state.Enabled = cfg.RulesPollInterval > 0
	if loaded := scanner.loadedManifest.Load(); loaded != nil {
		u.state.CachedVersion, u.state.LoadedVersion = loaded.Version, loaded.Version
	}
	return u, nil
}

// Snapshot reports a coherent last-observed identity pair. A busy cache keeps
// the previous pair without delaying an HTTP probe. External fetch-rules changes
// become visible as cached but not loaded when the cache lock is next available.
func (u *RulesUpdater) Snapshot() RulesUpdateState {
	now := time.Now()
	u.mu.Lock()
	s := u.state
	refresh := u.scanner.cacheDir != "" && (u.snapshotRefresh.IsZero() || !now.Before(u.snapshotRefresh.Add(time.Second)))
	if refresh {
		// Coalesce scrape bursts before attempting the shared flock. Otherwise a
		// sustained metrics workload could starve an exclusive updater lock.
		u.snapshotRefresh = now
	}
	u.mu.Unlock()
	if refresh {
		if unlock, err := tryLockRules(u.scanner.cacheDir); err == nil {
			// Publication records are cheap telemetry; byte validation belongs to
			// the update/reload path, never to an HTTP scrape.
			s.CachedVersion = readLocalManifest(filepath.Join(u.scanner.cacheDir, manifestName)).Version
			s.LoadedVersion = 0
			if m := u.scanner.loadedManifest.Load(); m != nil {
				s.LoadedVersion = m.Version
			}
			u.mu.Lock()
			u.state.CachedVersion, u.state.LoadedVersion = s.CachedVersion, s.LoadedVersion
			u.mu.Unlock()
			unlock()
		}
	}
	return s
}

// Poll performs one check with bounded network and lock waits. Native libyara
// calls finish synchronously once entered. Concurrent callers coalesce (no
// queue or overlapping fetch); a disabled updater performs no network requests.
func (u *RulesUpdater) Poll(ctx context.Context) error {
	if !u.state.Enabled || !u.poll.TryLock() {
		return nil
	}
	defer u.poll.Unlock()
	ctx, cancel := context.WithTimeout(ctx, u.cfg.RulesFetchTimeout)
	defer cancel()
	u.mu.Lock()
	u.state.LastCheck = time.Now().Unix()
	u.mu.Unlock()
	reloadFailed := false
	reload := func() error {
		err := u.scanner.reloadLockedCache()
		if err != nil {
			reloadFailed = true
			return err
		}
		if u.flush != nil {
			u.flush()
		}
		return nil
	}
	minimumVersion := 0
	if loaded := u.scanner.loadedManifest.Load(); loaded != nil {
		minimumVersion = loaded.Version
	}
	res, err := fetchRules(ctx, u.cfg.RulesURL, u.scanner.cacheDir, u.libyara, u.client, minimumVersion, reload)
	observedCached, observedLoaded := res.NewVersion, 0
	if res.Updated {
		// fetchRules returns only after the same locked transaction installed and
		// loaded this version, so this pair describes one coherent instant.
		observedLoaded = res.NewVersion
	}
	if u.afterFetch != nil {
		u.afterFetch()
	}
	// A standalone fetch may already have installed the current release. Reconcile
	// cached versus loaded even when there is no newer remote version to download.
	if err == nil && !res.Updated {
		var unlock func()
		unlock, err = lockRules(ctx, u.scanner.cacheDir)
		if err == nil {
			cachePath := filepath.Join(u.scanner.cacheDir, cachedRulesName)
			m := trustedLocalManifest(cachePath, filepath.Join(u.scanner.cacheDir, manifestName))
			loaded := u.scanner.loadedManifest.Load()
			if m.Version == 0 {
				err = fmt.Errorf("cached rules manifest is missing or does not match the compiled bundle")
			} else if loaded == nil || loaded.Version != m.Version {
				err = reload()
			}
			if err == nil {
				observedCached = m.Version
				if loaded = u.scanner.loadedManifest.Load(); loaded != nil {
					observedLoaded = loaded.Version
				}
			}
			unlock()
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if res.PublishedVersion > 0 {
		u.state.PublishedVersion = res.PublishedVersion
	}
	if err != nil {
		u.state.LastFailure = time.Now().Unix()
		u.state.Failures++
		if reloadFailed {
			u.state.ReloadFailures++
		}
		return err
	}
	if observedCached > 0 {
		u.state.CachedVersion = observedCached
	}
	if observedLoaded > 0 {
		u.state.LoadedVersion = observedLoaded
	}
	u.state.LastSuccess = time.Now().Unix()
	return nil
}

// Run checks immediately, then waits interval plus up to 20% jitter after each
// attempt. There are no nested retries; failures retry at the next bounded poll.
// The caller must join Run after cancellation before closing the scanner.
func (u *RulesUpdater) Run(ctx context.Context) {
	if !u.state.Enabled {
		return
	}
	for ctx.Err() == nil {
		if err := u.Poll(ctx); err != nil && ctx.Err() == nil {
			u.scanner.logf("rules update failed: %v", err)
		}
		// #nosec G404 -- schedule jitter is not used for a security decision.
		delay := u.cfg.RulesPollInterval + time.Duration(rand.Int64N(int64(u.cfg.RulesPollInterval/5)+1))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
