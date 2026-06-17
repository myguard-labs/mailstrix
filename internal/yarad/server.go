package yarad

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/eilandert/rspamd-yarad/internal/extract"
	"github.com/eilandert/rspamd-yarad/internal/mbazaar"
	"github.com/eilandert/rspamd-yarad/internal/urlhaus"
)

// ScanEngine is what the server dispatches a request to. *Scanner is the
// production implementation; tests inject a fake to exercise the HTTP layer
// without libyara.
type ScanEngine interface {
	Scan(buf []byte, meta ScanMeta) ([]Match, error)
	RuleCount() int64
	// Fingerprint identifies the active rule set; it is mixed into the cache key
	// so a reload that changes the rules invalidates old verdicts (L1 and Redis).
	Fingerprint() string
	// ExtractMetrics reports the OLE/OOXML pre-extraction counters for /metrics.
	ExtractMetrics() ExtractMetrics
	// ReloadMetrics reports rule-reload activity for /metrics.
	ReloadMetrics() ReloadMetrics
	// URLhausMetrics reports the URLhaus checker state for /metrics.
	URLhausMetrics() urlhaus.Metrics
	// MBazaarMetrics reports the MalwareBazaar checker state for /metrics.
	MBazaarMetrics() mbazaar.Metrics
}

// scanResponse is the JSON the rspamd plugin parses. Matches is empty (not
// null) when nothing matched, so the plugin can branch on length alone.
type scanResponse struct {
	Matches []Match `json:"matches"`
}

// Server is the HTTP front-end: auth, body limits, the bounded-concurrency
// gate, and fail-open dispatch to the scanner. It mirrors gozer's server so the
// two backends behave identically to operators and to the rspamd plugins.
type Server struct {
	cfg     *Config
	engine  ScanEngine
	cache   Cache
	flights flightGroup
	admit   chan struct{} // admission gate: bounds in-flight buffers (held whole request)
	sem     chan struct{} // scan-CPU gate: held only around the libyara scan
	metrics struct {
		scans, matches, errors, busy        atomic.Uint64
		canceled                            atomic.Uint64
		cacheHit, cacheMiss, cacheCoalesced atomic.Uint64
	}
	info *log.Logger // access/info — stdout when YARAD_LOG_STDOUT, else stderr
	errl *log.Logger // errors/warnings — always stderr

	httpSrv  atomic.Pointer[http.Server] // set by ListenAndServe; used by Shutdown
	draining atomic.Bool                 // true once Shutdown begins -> /ready 503s
}

func newLoggers(cfg *Config) (info, errl *log.Logger) {
	var infoW io.Writer = os.Stderr
	if cfg.LogStdout {
		infoW = os.Stdout
	}
	return log.New(infoW, "[yarad] ", 0), log.New(os.Stderr, "[yarad] ", 0)
}

// NewServer builds the server around an engine (the compiled scanner) and a
// verdict cache built from cfg. The scanner is also used to flush the cache on
// a rules reload when it supports it (see CacheFlusher).
func NewServer(cfg *Config, engine ScanEngine) *Server {
	cfg.sanitize()
	info, errl := newLoggers(cfg)
	s := &Server{
		cfg:    cfg,
		engine: engine,
		admit:  make(chan struct{}, cfg.MaxInflight),
		sem:    make(chan struct{}, cfg.MaxConcurrent),
		info:   info,
		errl:   errl,
	}
	s.cache = NewCache(cfg, s.errf)
	return s
}

// FlushCache drops the verdict cache. main wires this to the SIGHUP reload so a
// new rule set never serves verdicts computed against the old rules.
func (s *Server) FlushCache() {
	if s.cache != nil {
		s.cache.Flush()
	}
}

func (s *Server) logf(format string, a ...any) { s.info.Printf(format, a...) }
func (s *Server) errf(format string, a ...any) { s.errl.Printf(format, a...) }
func (s *Server) vlogf(format string, a ...any) {
	if s.cfg.Verbose {
		s.logf(format, a...)
	}
}

// ListenAndServe binds and serves until Shutdown is called (then it returns
// http.ErrServerClosed). The *http.Server is published so Shutdown can drain it.
func (s *Server) ListenAndServe() error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second, // Slowloris guard
		ReadTimeout:       s.cfg.BackendTimeout + 20*time.Second,
		WriteTimeout:      s.cfg.BackendTimeout + 25*time.Second,
		IdleTimeout:       60 * time.Second,
	}
	s.httpSrv.Store(srv)
	s.logStartup(addr)
	return srv.ListenAndServe()
}

// Shutdown marks the server draining (so /ready starts returning 503 and load
// balancers stop sending new work) and gracefully drains in-flight requests
// until ctx expires. Safe to call before ListenAndServe has stored the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.draining.Store(true)
	srv := s.httpSrv.Load()
	if srv == nil {
		return nil
	}
	s.logf("draining: shutting down, waiting for in-flight scans")
	return srv.Shutdown(ctx)
}

func (s *Server) logStartup(addr string) {
	if s.cfg.Token == "" {
		s.errf("WARNING: no YARAD_TOKEN configured — /scan will refuse all requests (503). " +
			"Set YARAD_TOKEN or YARAD_TOKEN_FILE.")
	}
	cache := "off"
	if s.cfg.CacheTTL > 0 {
		cache = "memory"
		if s.cfg.RedisURL != "" {
			cache = "redis+memory"
		}
	}
	s.logf("listening on %s (rules=%d, timeout=%s, scan_timeout=%s, max_concurrent=%d, max_inflight=%d, max_body=%dB, cache=%s ttl=%s size=%d, auth=%t)",
		addr, s.engine.RuleCount(), s.cfg.BackendTimeout, s.cfg.ScanTimeout,
		s.cfg.MaxConcurrent, s.cfg.MaxInflight, s.cfg.MaxBody, cache, s.cfg.CacheTTL, s.cfg.CacheSize, s.cfg.Token != "")

	// Worst-case request-buffer memory: each in-flight scan can hold a full body
	// plus its extracted macro streams, on top of the loaded-rules RSS. Surface
	// it so an operator can see whether MAX_CONCURRENT × MAX_BODY fits the
	// container limit — with MAX_CONCURRENT=auto (CPU count) a many-core host can
	// reserve far more buffer memory than a small mem_limit allows (memory != rule
	// count). When the cgroup memory limit is known, warn if the buffers alone
	// would take more than half of it (leaving no room for rules RSS + GC + burst).
	// In-flight buffers are bounded by the admission gate (MaxInflight), not the
	// scan gate, so size the estimate on that.
	peakMiB := (int64(s.cfg.MaxInflight) * s.cfg.MaxBody) >> 20
	s.logf("est. peak request-buffer memory ~%d MiB (max_inflight=%d × max_body=%d MiB) on top of rules RSS",
		peakMiB, s.cfg.MaxInflight, s.cfg.MaxBody>>20)
	if limitMiB := cgroupMemLimitMiB(); limitMiB > 0 && peakMiB > limitMiB/2 {
		s.errf("WARNING: request buffers alone (~%d MiB) exceed half the %d MiB container memory limit; lower YARAD_MAX_INFLIGHT/YARAD_MAX_CONCURRENT or YARAD_MAX_BODY, or raise mem_limit",
			peakMiB, limitMiB)
	} else if limitMiB == 0 && peakMiB > 512 {
		s.errf("WARNING: max_inflight × max_body alone is ~%d MiB of buffers; lower YARAD_MAX_INFLIGHT or YARAD_MAX_BODY", peakMiB)
	}
	s.logf("repo: %s", RepoURL)
}

// RepoURL is the project's source, logged at startup when log-stdout is on.
const RepoURL = "https://github.com/eilandert/rspamd-yarad"

// cgroupMemLimitMiB returns the container memory limit in MiB, or 0 if there is
// no enforced limit or it can't be read. Supports cgroup v2 (memory.max) and v1
// (memory.limit_in_bytes); "max" or the kernel's no-limit sentinel is unlimited.
func cgroupMemLimitMiB() int64 {
	for _, p := range []string{
		"/sys/fs/cgroup/memory.max",                   // cgroup v2
		"/sys/fs/cgroup/memory/memory.limit_in_bytes", // cgroup v1
	} {
		b, err := os.ReadFile(p) // #nosec G304 -- fixed cgroup pseudo-file paths, not user input
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if s == "" || s == "max" {
			return 0
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 || n >= 1<<62 { // huge value = kernel "no limit" sentinel
			return 0
		}
		return n >> 20
	}
	return 0
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		// Liveness: healthy as long as a rule set is loaded — a scanner with zero
		// rules is broken and should fail the container HEALTHCHECK. Deliberately
		// stays 200 while draining so an in-progress graceful shutdown doesn't get
		// the container killed before in-flight scans finish.
		if s.engine.RuleCount() < 1 {
			writeText(w, http.StatusServiceUnavailable, "no rules")
			return
		}
		writeText(w, http.StatusOK, "ok")
	case r.Method == http.MethodGet && r.URL.Path == "/ready":
		// Readiness: are we accepting NEW scans? Rules loaded AND not draining.
		// A load balancer / rspamd should stop routing here during shutdown even
		// though /health stays green for the drain window.
		if s.engine.RuleCount() < 1 {
			writeText(w, http.StatusServiceUnavailable, "no rules")
			return
		}
		if s.draining.Load() {
			writeText(w, http.StatusServiceUnavailable, "draining")
			return
		}
		// Stale rules do NOT fail readiness: old rules still catch most malware,
		// and pulling the scanner out of rotation (or killing it) is strictly worse
		// than scanning with a slightly-old set (fail-open). Surface it in the body
		// for a human/curl; alerting keys off the yarad_rules_stale metric instead.
		if s.rulesStale() {
			writeText(w, http.StatusOK, "ready (stale rules)")
			return
		}
		writeText(w, http.StatusOK, "ready")
	case r.Method == http.MethodGet && r.URL.Path == "/version":
		if !s.metricsAuthed(r) {
			writeText(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.serveVersion(w)
	case r.Method == http.MethodGet && r.URL.Path == "/metrics":
		if !s.metricsAuthed(r) {
			writeText(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.serveMetrics(w)
	case r.Method == http.MethodPost && r.URL.Path == "/scan":
		s.handleScan(w, r)
	default:
		writeText(w, http.StatusNotFound, "not found")
	}
}

// rulesStale reports whether the loaded ruleset is older than the configured
// YARAD_RULES_MAX_AGE. False when the check is disabled (max age 0) or the
// on-disk mtime is unknown — staleness must never be a false alarm.
func (s *Server) rulesStale() bool {
	if s.cfg.RulesMaxAge <= 0 {
		return false
	}
	mod := s.engine.ReloadMetrics().ModUnix
	if mod <= 0 {
		return false
	}
	return time.Now().Unix()-mod > int64(s.cfg.RulesMaxAge.Seconds())
}

// serveVersion reports build + ruleset identity so a live FP/perf change can be
// correlated with a specific image and rule bundle. Unauthenticated like
// /health: it reveals version/rule-count/fingerprint, not message content.
func (s *Server) serveVersion(w http.ResponseWriter) {
	rl := s.engine.ReloadMetrics()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":           s.cfg.Version,
		"extractor_version": extract.Version,
		"rules":             s.engine.RuleCount(),
		"fingerprint":       s.engine.Fingerprint(),
		"last_reload_unix":  rl.LastUnix,
		"rules_mtime_unix":  rl.ModUnix,
		"rules_stale":       s.rulesStale(),
		"repo":              RepoURL,
	})
}

// maxBodyHardLimit is a constant ceiling above any MaxBody so the int(length)
// conversion in handleScan is provably bounded for the static analyzer.
const maxBodyHardLimit = 1 << 30 // 1 GiB

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	ok, configured := s.authed(r)
	if !configured {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "yarad token not configured"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	length, err := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	if err != nil || length <= 0 || length > s.cfg.MaxBody || length > maxBodyHardLimit {
		s.metrics.errors.Add(1)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad length"})
		return
	}

	ctx := r.Context()

	// Admission gate: bounds the number of in-flight request buffers (memory),
	// held for the WHOLE request. It is separate from the scan-CPU gate so a slow
	// body upload or a slow Redis L2 lookup occupies an admission slot but NOT a
	// scarce scan slot. Cancel early if the client has already gone away.
	if !s.acquireOn(ctx, s.admit) {
		if ctx.Err() != nil {
			s.metrics.canceled.Add(1)
			return // client disconnected/timed out while queued
		}
		s.metrics.busy.Add(1)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy"})
		s.errf("/scan 503 busy (max_inflight=%d reached)", s.cfg.MaxInflight)
		return
	}
	defer func() { <-s.admit }()

	buf := make([]byte, int(length))
	if _, err := io.ReadFull(r.Body, buf); err != nil {
		s.metrics.errors.Add(1)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read error"})
		return
	}

	// The client may have timed out / disconnected during a slow body read. Don't
	// burn a scan slot on a verdict nobody will read.
	if ctx.Err() != nil {
		s.metrics.canceled.Add(1)
		return
	}

	t0 := time.Now()
	s.metrics.scans.Add(1)

	// Attachment metadata (filename/extension) the plugin attached to this scan;
	// fed to the YARA `filename`/`extension` external variables so name-keyed
	// rules fire (see ScanMeta).
	meta := scanMetaFromRequest(r)

	// Mix the active ruleset fingerprint AND the metadata into the cache key. The
	// fingerprint invalidates old verdicts on a SIGHUP reload (old keys orphan and
	// TTL-expire; no stale "clean" after a rule update). The metadata is in the key
	// because the verdict now DEPENDS on it: the same bytes with filename
	// "invoice.exe" vs "invoice.pdf" can match different rules, so they must not
	// share a cached verdict.
	key := s.engine.Fingerprint() + ":" + meta.cacheKey() + ":" + sha256key(buf)
	matches, cacheStatus := s.lookupOrScan(ctx, key, buf, meta)

	if len(matches) > 0 {
		s.metrics.matches.Add(1)
	}
	if cacheStatus == "hit" || cacheStatus == "coalesced" {
		w.Header().Set("X-YARAD-Cache", cacheStatus)
	}
	// Always emit a JSON array (never null) so the rspamd plugin can branch on
	// length without a nil check.
	if matches == nil {
		matches = []Match{}
	}
	writeJSON(w, http.StatusOK, scanResponse{Matches: matches})
	// Log the matched rule NAMES (not just a count) whenever something fires, at
	// info level — this is the cheap, accurate way to see which rules fire on
	// real mail and spot over-firing/FP rules to tune or demote. A per-rule
	// Prometheus metric is deliberately avoided: ~10k rules would blow label
	// cardinality. Clean scans stay quiet (verbose-only) to keep logs readable.
	if len(matches) > 0 {
		s.logf("/scan %dB cache=%s %.1fms -> %d matches %s", len(buf), cacheStatus, msSince(t0), len(matches), ruleNames(matches))
	} else {
		s.vlogf("/scan %dB cache=%s %.1fms -> 0 matches", len(buf), cacheStatus, msSince(t0))
	}
}

// lookupOrScan resolves a verdict for buf: cache hit, coalesced wait on an
// in-flight identical scan, or a fresh scan whose result is cached. At high
// volume the cache + coalescing collapse a bulk campaign's N identical messages
// into a single scan. Returns the matches and a cache-status label for logs.
func (s *Server) lookupOrScan(ctx context.Context, key string, buf []byte, meta ScanMeta) ([]Match, string) {
	// Cache lookup (L1 + Redis L2) runs OUTSIDE the scan-CPU gate, so a slow Redis
	// can't hold a scan slot; the L2 circuit breaker bounds it further.
	if m, found := s.cache.Get(key); found {
		s.metrics.cacheHit.Add(1)
		return m, "hit"
	}
	matches, shared := s.flights.Do(key, func() []Match {
		// A leader may have populated the cache between the first lookup and
		// registering this flight.
		if m, found := s.cache.Get(key); found {
			return m
		}
		s.metrics.cacheMiss.Add(1)
		// Take the scan-CPU slot only for the actual libyara scan. If it can't be
		// had within the budget (or the client is gone), fail open as "no match"
		// — never block mail — and do NOT cache (no real verdict was computed).
		if !s.acquireOn(ctx, s.sem) {
			s.metrics.busy.Add(1)
			s.errf("/scan %dB no scan slot within budget (fail-open)", len(buf))
			return nil
		}
		m, scanErr := func() ([]Match, error) {
			defer func() { <-s.sem }()
			return s.dispatch(buf, meta)
		}()
		if scanErr != nil {
			// Fail open: a scan error is "no match" to the plugin so a scanner
			// problem never blocks mail. A failed scan is NOT cached (don't
			// pin a wrong empty verdict for the whole TTL).
			s.metrics.errors.Add(1)
			s.errf("/scan %dB scan error (fail-open): %v", len(buf), scanErr)
			return nil
		}
		// Cache PUT, including optional Redis L2 SET, runs after the scan slot is
		// released. A healthy-but-slow Redis may still delay this response a little
		// but it no longer blocks unrelated libyara work.
		s.cache.Put(key, m)
		return m
	})
	if shared {
		s.metrics.cacheCoalesced.Add(1)
		return matches, "coalesced"
	}
	return matches, "miss"
}

// dispatch runs the scanner and never lets a panic reach the caller: on panic
// it logs and returns a non-nil error. Returning an error (not (nil,nil)) is
// deliberate — the caller treats errors as fail-open "no match" but does NOT
// cache them, so a panicking input is rescanned next time instead of being
// pinned as a clean verdict for the whole cache TTL.
func (s *Server) dispatch(buf []byte, meta ScanMeta) (matches []Match, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			s.errf("scan panic: %v", rec)
			matches, err = nil, fmt.Errorf("scan panic: %v", rec)
		}
	}()
	return s.engine.Scan(buf, meta)
}

// acquireOn takes a slot from sem within BackendTimeout, returning early (false)
// if the client's request context is cancelled — it disconnected or timed out,
// so there is no point queueing work for it. The caller distinguishes "busy"
// from "client gone" via ctx.Err().
func (s *Server) acquireOn(ctx context.Context, sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(s.cfg.BackendTimeout)
	defer timer.Stop()
	select {
	case sem <- struct{}{}:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// metricsAuthed gates /metrics and /version. Open by default (Prometheus scrapes
// without a secret); when YARAD_METRICS_AUTH=1 they require the same token as
// /scan, so an accidentally-published 8079 doesn't leak rule count / fingerprint
// / runtime behaviour. /health and /ready stay open either way (probes).
func (s *Server) metricsAuthed(r *http.Request) bool {
	if !s.cfg.MetricsAuth {
		return true
	}
	ok, configured := s.authed(r)
	return ok && configured
}

// authed validates the shared secret. configured is false when no token is set
// (caller returns 503); ok is the constant-time comparison result. Accepts the
// token as a Bearer Authorization header or X-YARAD-Token.
func (s *Server) authed(r *http.Request) (ok, configured bool) {
	if s.cfg.Token == "" {
		return false, false
	}
	presented := ""
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		presented = strings.TrimSpace(a[len("Bearer "):])
	} else {
		presented = strings.TrimSpace(r.Header.Get("X-YARAD-Token"))
	}
	return hmac.Equal([]byte(presented), []byte(s.cfg.Token)), true
}

func (s *Server) serveMetrics(w http.ResponseWriter) {
	var b strings.Builder
	fm := func(name, help string, v uint64) {
		b.WriteString("# HELP yarad_" + name + " " + help + "\n")
		b.WriteString("# TYPE yarad_" + name + " counter\n")
		b.WriteString("yarad_" + name + " " + strconv.FormatUint(v, 10) + "\n")
	}
	fm("scans_total", "total /scan requests served", s.metrics.scans.Load())
	fm("matches_total", "/scan requests with >=1 rule match", s.metrics.matches.Load())
	fm("errors_total", "scan/read/length errors", s.metrics.errors.Load())
	fm("busy_total", "requests rejected by the concurrency gate", s.metrics.busy.Load())
	fm("canceled_total", "requests abandoned because the client disconnected/timed out", s.metrics.canceled.Load())
	fm("cache_hits_total", "verdicts served from cache", s.metrics.cacheHit.Load())
	fm("cache_misses_total", "scans that ran (cache miss)", s.metrics.cacheMiss.Load())
	fm("cache_coalesced_total", "scans coalesced onto an in-flight identical scan", s.metrics.cacheCoalesced.Load())
	b.WriteString("# HELP yarad_rules loaded YARA rule count\n")
	b.WriteString("# TYPE yarad_rules gauge\n")
	b.WriteString("yarad_rules " + strconv.FormatInt(s.engine.RuleCount(), 10) + "\n")

	// OLE/OOXML pre-extraction counters — visibility into the document path.
	ex := s.engine.ExtractMetrics()
	fm("extract_docs_total", "attachments recognised as OLE2/OOXML containers", ex.Docs)
	fm("extract_macro_docs_total", "documents that yielded >=1 decompressed macro stream", ex.MacroDocs)
	fm("extract_streams_total", "decompressed macro streams scanned", ex.Streams)
	fm("extract_failed_total", "container parse attempts that errored", ex.Failed)
	fm("extract_panicked_total", "parser panics recovered (subset of failed)", ex.Panicked)
	fm("extract_encrypted_total", "ECMA-376 encrypted OOXML seen (not decrypted)", ex.Encrypted)
	fm("extract_msi_total", "OLE2 buffers recognised as MSI installers (streams dumped)", ex.MSI)
	fm("extract_msg_total", "OLE2 buffers recognised as Outlook .msg (nested attachments extracted)", ex.MSG)
	fm("extract_onenote_total", "buffers recognised as OneNote .one sections (embedded files carved)", ex.OneNote)
	fm("extract_archive_total", "buffers recognised as an archive (zip/gz/7z/rar/tar; members unpacked)", ex.Archive)
	fm("extract_ole_package_total", "OLE2 docs with an embedded OLE Package object (Ole10Native carved)", ex.OLEPackage)
	fm("extract_lnk_total", "Windows shell links (.lnk) with StringData (command-line args/paths) surfaced", ex.LNK)
	fm("extract_pdf_total", "PDFs with FlateDecode object streams inflated for scanning", ex.PDF)
	fm("extract_rtf_total", "RTF docs with \\objdata embedded objects hex-decoded and carved", ex.RTF)
	fm("extract_encoded_script_total", "buffers with >=1 decoded MS-Script-Encoder (VBE/JSE) block", ex.EncScript)
	fm("extract_stream_matches_total", "rule hits attributable only to an extracted stream (not raw bytes)", ex.StreamMatches)

	// Rule-reload activity — so a SIGHUP that silently fails to compile is visible
	// to alerting, not just buried in logs.
	rl := s.engine.ReloadMetrics()
	fm("reload_attempts_total", "rule reload attempts (incl. boot load)", rl.Attempts)
	fm("reload_success_total", "successful rule reloads", rl.Successes)
	fm("reload_failure_total", "failed rule reloads (previous set kept)", rl.Failures)
	gauge := func(name, help string, v int64) {
		b.WriteString("# HELP yarad_" + name + " " + help + "\n")
		b.WriteString("# TYPE yarad_" + name + " gauge\n")
		b.WriteString("yarad_" + name + " " + strconv.FormatInt(v, 10) + "\n")
	}
	gauge("reload_last_timestamp_seconds", "unix time of the last successful reload", rl.LastUnix)
	gauge("reload_last_duration_ms", "wall-clock duration of the last reload attempt", rl.LastMillis)

	// Rule staleness — catch a silently-broken daily image rebuild (the running
	// container keeps serving old baked rules with no error). Age is derived from
	// the loaded ruleset's on-disk mtime; rules_stale is 1 only when a max age is
	// configured (YARAD_RULES_MAX_AGE) and exceeded. Both are 0/absent-safe: a
	// mtime of 0 (couldn't stat) reports age 0 and never flags stale.
	gauge("rules_mtime_seconds", "mtime (unix seconds) of the loaded ruleset on disk; 0 if unknown", rl.ModUnix)
	var ageSecs, stale int64
	if rl.ModUnix > 0 {
		if a := time.Now().Unix() - rl.ModUnix; a > 0 {
			ageSecs = a
		}
		if s.cfg.RulesMaxAge > 0 && ageSecs > int64(s.cfg.RulesMaxAge.Seconds()) {
			stale = 1
		}
	}
	gauge("rules_age_seconds", "age of the loaded ruleset (now - mtime); 0 if mtime unknown", ageSecs)
	gauge("rules_stale", "1 if rules_age_seconds exceeds YARAD_RULES_MAX_AGE (0 when unset or fresh)", stale)

	// URLhaus malware-URL lookup (only meaningful when enabled).
	uh := s.engine.URLhausMetrics()
	if uh.Enabled {
		fm("urlhaus_lookups_total", "buffers checked against the URLhaus feed", uh.Lookups)
		fm("urlhaus_hits_total", "buffers with >=1 URLhaus match", uh.Hits)
		fm("urlhaus_refresh_failures_total", "URLhaus feed refresh failures", uh.RefreshFailures)
		gauge("urlhaus_feed_urls", "URLs in the loaded URLhaus feed", uh.FeedURLs)
		gauge("urlhaus_feed_hosts", "hosts in the loaded URLhaus feed", uh.FeedHosts)
		gauge("urlhaus_last_refresh_timestamp_seconds", "unix time of the last successful feed refresh", uh.LastRefreshUnix)
	}

	// MalwareBazaar attachment-hash lookup (only meaningful when enabled).
	mb := s.engine.MBazaarMetrics()
	if mb.Enabled {
		fm("malwarebazaar_lookups_total", "attachments hashed and checked against the MalwareBazaar feed", mb.Lookups)
		fm("malwarebazaar_hits_total", "attachments whose SHA256 matched a known malware sample", mb.Hits)
		fm("malwarebazaar_refresh_failures_total", "MalwareBazaar feed refresh failures", mb.RefreshFailures)
		gauge("malwarebazaar_feed_hashes", "known-malware SHA256 hashes in the loaded feed", mb.FeedHashes)
		gauge("malwarebazaar_last_refresh_timestamp_seconds", "unix time of the last successful feed refresh", mb.LastRefreshUnix)
	}
	writeRaw(w, http.StatusOK, "text/plain; version=0.0.4", []byte(b.String()))
}

// --- response helpers ---

func writeText(w http.ResponseWriter, code int, body string) {
	writeRaw(w, code, "text/plain", []byte(body))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"error":"internal"}`)
	}
	writeRaw(w, code, "application/json", b)
}

func writeRaw(w http.ResponseWriter, code int, ctype string, body []byte) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	_, _ = w.Write(body) // #nosec G705 -- application/json or text/plain API response, not an HTML/XSS sink
}

func sha256key(b []byte) string {
	sum := sha256.Sum256(b)
	return string(sum[:])
}

// filenameHeader carries the attachment filename from the rspamd plugin. The
// value is base64 (std, padding optional, whitespace tolerated): the name comes
// from the email and is attacker-controlled, so encoding it stops an embedded
// CR/LF or control byte from injecting an HTTP header or log line. Absent or
// undecodable ⇒ no metadata, never an error (the scan still runs).
const filenameHeader = "X-YARAD-Filename"

// scanMetaFromRequest extracts and normalizes the attachment metadata the plugin
// attached to the scan. See filenameHeader for the wire format / why base64.
func scanMetaFromRequest(r *http.Request) ScanMeta {
	raw := r.Header.Get(filenameHeader)
	if raw == "" {
		return ScanMeta{}
	}
	dec, ok := decodeFilenameB64(raw)
	if !ok {
		return ScanMeta{}
	}
	return NewScanMeta(string(dec))
}

// decodeFilenameB64 decodes the (possibly whitespace-folded, possibly unpadded)
// base64 filename header. It tolerates both padded and raw std base64 so a small
// difference in how the plugin encodes can't silently drop the filename.
func decodeFilenameB64(s string) ([]byte, bool) {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, true
	}
	return nil, false
}

// ruleNames renders the matched rule identifiers as "[a, b, c]" for the access
// log. Capped so a pathological message matching hundreds of rules can't write a
// multi-kilobyte log line per scan.
func ruleNames(m []Match) string {
	const max = 20
	var b strings.Builder
	b.WriteByte('[')
	for i, x := range m {
		if i == max {
			fmt.Fprintf(&b, ", +%d more", len(m)-max)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(x.Rule)
	}
	b.WriteByte(']')
	return b.String()
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }
