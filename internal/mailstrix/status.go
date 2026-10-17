package mailstrix

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Periodic status line (MAILSTRIX_STATUS_LOG). One compact key=value line per
// tick on stdout, built only from the atomics and snapshots that already back
// /health, /version and /metrics; nothing here touches the scan hot path.
const (
	defaultStatusInterval = 15 * time.Minute
	minStatusInterval     = time.Minute
	statusPrefix          = "strixd status:"
	// A feed is stale once its last good refresh is older than this many
	// refresh intervals (the interval itself is floored at feedMinRefresh).
	feedStaleFactor = 2
	feedMinRefresh  = 5 * time.Minute
)

// feedStatus is the per-source view the status line needs.
type feedStatus struct {
	Name        string
	Enabled     bool
	LastRefresh int64 // unix seconds of last good refresh; 0 = never
	Failures    uint64
	Refresh     time.Duration
}

// StatusSnapshot is a point-in-time read of the data behind /health, /version
// and /metrics. Taking it is allocation-light and lock-free apart from the
// updater snapshot /version already takes.
type StatusSnapshot struct {
	Version      string
	Rev          string
	Uptime       time.Duration
	RSS          int64
	Mem          memoryStats
	Healthy      bool // the /health predicate
	Rules        int64
	Fingerprint  string
	RulesVersion int // loaded manifest version, 0 = unknown
	RulesStale   bool
	Reload       ReloadMetrics
	Poll         RulesUpdateState
	PollPresent  bool
	Feeds        []feedStatus
	Inflight     int
	InflightMax  int
	ScanSlots    int
	ScanSlotsMax int
	Draining     bool
	ICAPDown     bool
	CacheDegrade string
	Scans        uint64
	Matches      uint64
	Errors       uint64
	Busy         uint64
	Canceled     uint64
	CacheHit     uint64
	CacheMiss    uint64
	CacheCoal    uint64
	Now          time.Time
}

func buildRev() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, kv := range bi.Settings {
			if kv.Key == "vcs.revision" && kv.Value != "" {
				if len(kv.Value) > 12 {
					return kv.Value[:12]
				}
				return kv.Value
			}
		}
	}
	return "unknown"
}

// StatusSnapshot gathers the current state from the same sources as the
// /health and /version handlers.
func (s *Server) StatusSnapshot() StatusSnapshot {
	rl := s.engine.ReloadMetrics()
	snap := StatusSnapshot{
		Version:      s.cfg.Version,
		Rev:          buildRev(),
		Uptime:       time.Since(s.started),
		RSS:          procRSSBytes(),
		Mem:          goMemStats(),
		Healthy:      s.healthy(),
		Rules:        s.engine.RuleCount(),
		Fingerprint:  s.engine.Fingerprint(),
		RulesStale:   s.rulesStale(),
		Reload:       rl,
		Inflight:     len(s.admit),
		InflightMax:  cap(s.admit),
		ScanSlots:    len(s.sem),
		ScanSlotsMax: cap(s.sem),
		Draining:     s.draining.Load(),
		ICAPDown:     s.icapDown.Load(),
		Scans:        s.metrics.scans.Load(),
		Matches:      s.metrics.matches.Load(),
		Errors:       s.metrics.errors.Load(),
		Busy:         s.metrics.busy.Load(),
		Canceled:     s.metrics.canceled.Load(),
		CacheHit:     s.metrics.cacheHit.Load(),
		CacheMiss:    s.metrics.cacheMiss.Load(),
		CacheCoal:    s.metrics.cacheCoalesced.Load(),
		Now:          time.Now(),
	}
	if s.cache != nil {
		snap.CacheDegrade = s.cache.Degraded()
	}
	if s.rulesUpdater != nil {
		snap.Poll, snap.PollPresent = s.rulesUpdater.Snapshot(), true
	}
	if provider, ok := s.engine.(interface {
		loadedRulesManifest() (RulesManifest, bool)
	}); ok {
		if m, ok := provider.loadedRulesManifest(); ok {
			snap.RulesVersion = m.Version
		}
	}
	uh, mb, tf := s.engine.URLhausMetrics(), s.engine.MBazaarMetrics(), s.engine.ThreatFoxMetrics()
	snap.Feeds = []feedStatus{
		{"urlhaus", uh.Enabled, uh.LastRefreshUnix, uh.RefreshFailures, s.cfg.URLhausRefresh},
		{"mbazaar", mb.Enabled, mb.LastRefreshUnix, mb.RefreshFailures, s.cfg.MBazaarRefresh},
		{"threatfox", tf.Enabled, tf.LastRefreshUnix, tf.RefreshFailures, s.cfg.ThreatFoxRefresh},
	}
	return snap
}

// pollResult classifies the rules poller: disabled, never, ok or failed.
func (sn StatusSnapshot) pollResult() string {
	switch {
	case !sn.PollPresent || !sn.Poll.Enabled:
		return "disabled"
	case sn.Poll.LastCheck == 0:
		return "never"
	case sn.Poll.LastFailure > 0 && sn.Poll.LastFailure >= sn.Poll.LastSuccess:
		return "failed"
	}
	return "ok"
}

func (sn StatusSnapshot) ageSecs(unix int64) int64 {
	if unix <= 0 {
		return -1
	}
	if a := sn.Now.Unix() - unix; a > 0 {
		return a
	}
	return 0
}

// Blocking lists the current degradations as stable tokens. failing is the set
// of feeds the StatusLogger has latched as failing (feed name -> LastRefresh
// seen when latched; nil means none): a feed stays failing until a successful
// refresh, so the token does not vanish between ticks while refreshes keep
// failing.
func (sn StatusSnapshot) Blocking(failing map[string]int64) []string {
	var out []string
	if !sn.Healthy {
		out = append(out, "unhealthy")
	}
	if sn.pollResult() == "failed" {
		out = append(out, "rules_poll_failing")
	}
	if sn.RulesStale {
		out = append(out, "rules_stale")
	}
	for _, f := range sn.Feeds {
		if !f.Enabled {
			continue
		}
		if _, ok := failing[f.Name]; ok {
			out = append(out, f.Name+"_failing")
		}
		interval := f.Refresh
		if interval < feedMinRefresh {
			interval = feedMinRefresh
		}
		if f.LastRefresh > 0 && sn.Now.Unix()-f.LastRefresh > int64((feedStaleFactor*interval).Seconds()) {
			out = append(out, f.Name+"_stale")
		}
	}
	if sn.InflightMax > 0 && sn.Inflight >= sn.InflightMax {
		out = append(out, "admission_saturated")
	}
	if sn.Draining {
		out = append(out, "draining")
	}
	if sn.ICAPDown {
		out = append(out, "icap_down")
	}
	if sn.CacheDegrade != "" {
		out = append(out, "cache_degraded")
	}
	return out
}

// Line renders the snapshot as one greppable line (no trailing newline).
func (sn StatusSnapshot) Line(failing map[string]int64) string {
	fp := sn.Fingerprint
	if len(fp) > 12 {
		fp = fp[:12]
	}
	if fp == "" {
		fp = "none"
	}
	ver := sn.Version
	if ver == "" {
		ver = "unknown"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s version=%s rev=%s uptime_s=%d rss_bytes=%d heap_alloc_bytes=%d heap_inuse_bytes=%d",
		statusPrefix, ver, sn.Rev, int64(sn.Uptime.Seconds()), sn.RSS, sn.Mem.HeapAlloc, sn.Mem.HeapInuse)
	fmt.Fprintf(&b, " healthy=%t rules=%d rules_fp=%s rules_version=%d rules_loaded_unix=%d rules_mtime_unix=%d rules_stale=%t",
		sn.Healthy, sn.Rules, fp, sn.RulesVersion, sn.Reload.LastUnix, sn.Reload.ModUnix, sn.RulesStale)
	fmt.Fprintf(&b, " rules_poll=%s rules_poll_last_unix=%d rules_poll_age_s=%d rules_poll_last_success_unix=%d rules_poll_last_failure_unix=%d rules_poll_failures=%d",
		sn.pollResult(), sn.Poll.LastCheck, sn.ageSecs(sn.Poll.LastCheck), sn.Poll.LastSuccess, sn.Poll.LastFailure, sn.Poll.Failures)
	for _, f := range sn.Feeds {
		if !f.Enabled {
			fmt.Fprintf(&b, " %s=off", f.Name)
			continue
		}
		fmt.Fprintf(&b, " %s=on %s_last_refresh_unix=%d %s_age_s=%d %s_failures=%d",
			f.Name, f.Name, f.LastRefresh, f.Name, sn.ageSecs(f.LastRefresh), f.Name, f.Failures)
	}
	fmt.Fprintf(&b, " inflight=%d inflight_max=%d scan_slots=%d scan_slots_max=%d",
		sn.Inflight, sn.InflightMax, sn.ScanSlots, sn.ScanSlotsMax)
	fmt.Fprintf(&b, " scans=%d matches=%d errors=%d busy=%d canceled=%d cache_hits=%d cache_misses=%d cache_coalesced=%d",
		sn.Scans, sn.Matches, sn.Errors, sn.Busy, sn.Canceled, sn.CacheHit, sn.CacheMiss, sn.CacheCoal)
	blocking := "none"
	if t := sn.Blocking(failing); len(t) > 0 {
		blocking = strings.Join(t, ",")
	}
	fmt.Fprintf(&b, " blocking=%s", blocking)
	return b.String()
}

// StatusLogger renders successive status lines. It remembers feed failure
// counters between ticks and latches a feed as failing when its counter grows
// (or it has failures and never succeeded); the latch clears only when
// LastRefresh advances past the value seen at latch time, i.e. a successful
// refresh. On the first tick a feed with failures is latched even when
// LastRefresh > 0: order cannot be told, so it is conservatively reported
// until the next good refresh.
type StatusLogger struct {
	s       *Server
	mu      sync.Mutex
	prev    map[string]uint64
	latched map[string]int64
}

// NewStatusLogger returns a logger bound to s.
func NewStatusLogger(s *Server) *StatusLogger { return &StatusLogger{s: s} }

// Next takes a snapshot and returns the line for it.
func (l *StatusLogger) Next() string {
	sn := l.s.StatusSnapshot()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.latched == nil {
		l.latched = make(map[string]int64, len(sn.Feeds))
	}
	for _, f := range sn.Feeds {
		if !f.Enabled {
			delete(l.latched, f.Name)
			continue
		}
		if at, ok := l.latched[f.Name]; ok && f.LastRefresh > at {
			delete(l.latched, f.Name)
		}
		if _, ok := l.latched[f.Name]; !ok &&
			f.Failures > 0 && (f.LastRefresh == 0 || f.Failures > l.prev[f.Name]) {
			l.latched[f.Name] = f.LastRefresh
		}
	}
	line := sn.Line(l.latched)
	l.prev = make(map[string]uint64, len(sn.Feeds))
	for _, f := range sn.Feeds {
		l.prev[f.Name] = f.Failures
	}
	return line
}

// StartStatusLogTicks starts the emitter when cfg.StatusLog is set and returns a
// channel closed once the goroutine has exited (ctx cancel or ticks closed).
// It returns nil, starting nothing and writing nothing, when disabled.
func (s *Server) StartStatusLogTicks(ctx context.Context, w io.Writer, ticks <-chan time.Time) <-chan struct{} {
	if !s.cfg.StatusLog {
		return nil
	}
	l := NewStatusLogger(s)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-ticks:
				if !ok {
					return
				}
				// A failed stdout write has no better sink; the next tick retries.
				_, _ = io.WriteString(w, l.Next()+"\n")
			}
		}
	}()
	return done
}

// StartStatusLog is the production entry point: a real ticker at
// cfg.StatusInterval, stopped with the goroutine. Returns nil when disabled.
func (s *Server) StartStatusLog(ctx context.Context, w io.Writer) <-chan struct{} {
	if !s.cfg.StatusLog {
		return nil
	}
	t := time.NewTicker(s.cfg.StatusInterval)
	done := s.StartStatusLogTicks(ctx, w, t.C)
	stopped := make(chan struct{})
	go func() {
		<-done
		t.Stop()
		close(stopped)
	}()
	return stopped
}
