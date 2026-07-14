package mailstrix

import (
	"context"
	"crypto/hmac"
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
	"github.com/myguard-labs/mailstrix/internal/mbazaar"
	"github.com/myguard-labs/mailstrix/internal/threatfox"
	"github.com/myguard-labs/mailstrix/internal/urlhaus"

	_ "net/http/pprof" // #nosec G108 -- handlers on DefaultServeMux; only delegated to when cfg.Pprof is set at runtime
)

// ScanEngine is what the server dispatches a request to. *Scanner is the
// production implementation; tests inject a fake to exercise the HTTP layer
// without libyara.
type ScanEngine interface {
	Scan(buf []byte, meta ScanMeta) ([]Match, error)
	RuleCount() int64
	// BigFileScans reports how many oversized buffers were scanned against the
	// targeted big-file ruleset (MAILSTRIX_BIGFILE_THRESHOLD gate), for /metrics.
	BigFileScans() uint64
	// BigFileStreamScans reports how many oversized extracted streams were scanned
	// against the targeted big-file ruleset instead of the full set, for /metrics.
	BigFileStreamScans() uint64
	// RawChannelScans / StreamChannelScans / MarkerChannelScans report per-channel
	// libyara scan counts (raw body / real-content stream / marker channel), for
	// /metrics (PERF-17).
	RawChannelScans() uint64
	StreamChannelScans() uint64
	MarkerChannelScans() uint64
	// RawScanErrs reports raw-scan failures that fell through to extraction
	// instead of aborting the request, for /metrics.
	RawScanErrs() uint64
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
	// ThreatFoxMetrics reports the ThreatFox checker state for /metrics.
	ThreatFoxMetrics() threatfox.Metrics
	// TopMatches returns the top n most-triggered rule names since last reload.
	TopMatches(n int) []MatchCount
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

	// autoEffort is the smoothed effort level for MAILSTRIX_EFFORT=auto (EFFORT-2). It
	// trails admission-gate pressure by one level per scan (hysteresis). 0 until
	// the first auto scan, then always in [1, EffortMax]. Read/written under the
	// admission slot, so the Load/Store race window is benign (a stale level is at
	// most one scan old and self-corrects next scan).
	autoEffort atomic.Int64
	metrics    struct {
		scans, matches, errors, busy            atomic.Uint64
		canceled                                atomic.Uint64
		cacheHit, cacheMiss, cacheCoalesced     atomic.Uint64
		icapRequests, icapInfected, icapOptions atomic.Uint64
		icapBusy                                atomic.Uint64 // conns refused at the pre-admission cap
	}
	info *log.Logger // access/info — stdout when MAILSTRIX_LOG_STDOUT, else stderr
	errl *log.Logger // errors/warnings — always stderr

	httpSrv  atomic.Pointer[http.Server] // set by ListenAndServe; used by Shutdown
	draining atomic.Bool                 // true once Shutdown begins -> /ready 503s

	icapLn        atomic.Pointer[net.Listener]
	icapWg        sync.WaitGroup
	icapConns     chan struct{} // live-connection cap, taken at accept() (pre-admission)
	icapRefuse    chan struct{} // bounds concurrent 503-refusal goroutines
	icapRefuseLog atomic.Int64  // UnixNano of the last cap-reached log line (throttle)
}

func newLoggers(cfg *Config) (info, errl *log.Logger) {
	var infoW io.Writer = os.Stderr
	if cfg.LogStdout {
		infoW = os.Stdout
	}
	return log.New(infoW, "[mailstrix] ", 0), log.New(os.Stderr, "[mailstrix] ", 0)
}

// NewServer builds the server around an engine (the compiled scanner) and a
// verdict cache built from cfg. The scanner is also used to flush the cache on
// a rules reload when it supports it (see CacheFlusher).
func NewServer(cfg *Config, engine ScanEngine) *Server {
	cfg.sanitize()
	info, errl := newLoggers(cfg)
	s := &Server{
		cfg:        cfg,
		engine:     engine,
		admit:      make(chan struct{}, cfg.MaxInflight),
		sem:        make(chan struct{}, cfg.MaxConcurrent),
		icapConns:  make(chan struct{}, cfg.ICAPMaxConns),
		icapRefuse: make(chan struct{}, icapMaxRefuseInflight),
		info:       info,
		errl:       errl,
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
	if !s.authRequired() {
		s.errf("WARNING: no token set — /scan is OPEN (no authentication). Anyone who can "+
			"reach %s can submit scans (CPU-costly). Intended only for a trusted private "+
			"network; set MAILSTRIX_TOKEN or MAILSTRIX_TOKEN_FILE to require a shared secret.", addr)
	}
	cache := "off"
	if s.cfg.CacheTTL > 0 {
		cache = "memory"
		if s.cfg.RedisURL != "" {
			cache = "redis+memory"
		}
	}
	effort := strconv.Itoa(s.cfg.Effort)
	if s.cfg.EffortAuto {
		effort = "auto(idle=" + strconv.Itoa(s.cfg.Effort) + ")"
	}
	bigfile := "off"
	if s.cfg.BigFileThreshold > 0 {
		bigfile = strconv.FormatInt(s.cfg.BigFileThreshold, 10) + "B"
	}
	s.logf("listening on %s (rules=%d, timeout=%s, scan_timeout=%s, max_concurrent=%d, max_inflight=%d, max_body=%dB, bigfile_threshold=%s, cache=%s ttl=%s size=%d, effort=%s/%d, auth=%t)",
		addr, s.engine.RuleCount(), s.cfg.BackendTimeout, s.cfg.ScanTimeout,
		s.cfg.MaxConcurrent, s.cfg.MaxInflight, s.cfg.MaxBody, bigfile, cache, s.cfg.CacheTTL, s.cfg.CacheSize, effort, s.cfg.EffortMax, s.authRequired())

	// Worst-case request-buffer memory: each in-flight scan can hold a full body
	// plus its extracted macro streams, on top of the loaded-rules RSS. Surface
	// it so an operator can see whether MAX_CONCURRENT × MAX_BODY fits the
	// container limit — with MAX_CONCURRENT=auto (CPU count) a many-core host can
	// reserve far more buffer memory than a small mem_limit allows (memory != rule
	// count). When the cgroup memory limit is known, warn if the buffers alone
	// would exceed 3/4 of it (leaving room for GC headroom + burst); the estimate
	// now includes rules+feed RSS, so it is the full resident peak, not buffers only.
	// In-flight buffers are bounded by the admission gate (MaxInflight), not the
	// scan gate, so size the estimate on that.
	bufMiB := (int64(s.cfg.MaxInflight) * s.cfg.MaxBody) >> 20
	// RSS at startup already holds the loaded rules + mbazaar feed (both built
	// before ListenAndServe), so it captures the two terms the buffers-only
	// estimate omits. peakMiB = resident base + worst-case request buffers; when
	// RSS is unknown (0) fall back to buffers alone.
	rssMiB := procRSSMiB()
	peakMiB := bufMiB + rssMiB
	if rssMiB > 0 {
		s.logf("est. peak memory ~%d MiB (rules+feed RSS=%d MiB + max_inflight=%d × max_body=%d MiB buffers)",
			peakMiB, rssMiB, s.cfg.MaxInflight, s.cfg.MaxBody>>20)
	} else {
		s.logf("est. peak request-buffer memory ~%d MiB (max_inflight=%d × max_body=%d MiB) on top of rules RSS",
			bufMiB, s.cfg.MaxInflight, s.cfg.MaxBody>>20)
	}
	if limitMiB := cgroupMemLimitMiB(); limitMiB > 0 && peakMiB > (limitMiB*3)/4 {
		s.errf("WARNING: est. peak memory (~%d MiB: %d MiB RSS + %d MiB buffers) exceeds 3/4 of the %d MiB container limit; lower MAILSTRIX_MAX_INFLIGHT/MAILSTRIX_MAX_CONCURRENT or MAILSTRIX_MAX_BODY, or raise mem_limit",
			peakMiB, rssMiB, bufMiB, limitMiB)
	} else if limitMiB == 0 && peakMiB > 512 {
		s.errf("WARNING: est. peak memory ~%d MiB (%d MiB RSS + %d MiB buffers); lower MAILSTRIX_MAX_INFLIGHT/MAILSTRIX_MAX_BODY or set a container mem_limit", peakMiB, rssMiB, bufMiB)
	}
	if quota := cgroupCPUQuota(); quota > 0 && float64(s.cfg.MaxConcurrent) > quota*1.5 {
		s.errf("WARNING: max_concurrent=%d but cgroup cpu.max grants only %.1f CPUs; "+
			"over-subscribing by %.1fx increases latency under load (lower MAILSTRIX_MAX_CONCURRENT or raise cpu quota)",
			s.cfg.MaxConcurrent, quota, float64(s.cfg.MaxConcurrent)/quota)
	}
	s.logf("repo: %s  home: %s", RepoURL, HomeURL)
	if s.cfg.ICAPAddr != "" {
		s.errf("WARNING: ICAP listener on %s has no built-in authentication. "+
			"Gate by network/firewall; only trusted proxies should reach this port.", s.cfg.ICAPAddr)
		s.logf("ICAP listener: %s (REQMOD+RESPMOD, Preview:0, Allow:204)", s.cfg.ICAPAddr)
	}
}

// RepoURL is the project's source, logged at startup when log-stdout is on.
const RepoURL = "https://github.com/myguard-labs/mailstrix"

// HomeURL is the project's home page, logged at startup alongside RepoURL.
const HomeURL = "https://mailstrix.com"

// License is yarad's SPDX license id, surfaced by `yarad info`.
const License = "MIT"

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

// procRSSMiB returns this process's resident set size in MiB read from
// /proc/self/statm (field 2 = resident pages × page size), or 0 if it can't be
// read or parsed. Called once at startup AFTER the rule set and mbazaar feed are
// loaded, so the value already includes rules RSS + feed bytes resident — the two
// memory terms the buffer-only estimate omits. Best-effort: a 0 means "unknown",
// and the caller falls back to the buffers-only peak.
func procRSSMiB() int64 {
	b, err := os.ReadFile("/proc/self/statm") // #nosec G304 -- fixed proc pseudo-file path
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	pages, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || pages <= 0 {
		return 0
	}
	return (pages * int64(os.Getpagesize())) >> 20
}

// cgroupCPUQuota returns the cgroup v2 CPU quota in fractional CPUs, or 0 if
// there is no enforced quota or it can't be read. Format: "$quota $period" where
// "max" means unlimited; quota/period gives the number of CPUs allotted.
func cgroupCPUQuota() float64 {
	b, err := os.ReadFile("/sys/fs/cgroup/cpu.max") // #nosec G304 -- fixed cgroup path
	if err != nil {
		return 0
	}
	parts := strings.Fields(strings.TrimSpace(string(b)))
	if len(parts) != 2 || parts[0] == "max" {
		return 0
	}
	quota, err := strconv.ParseFloat(parts[0], 64)
	if err != nil || quota <= 0 {
		return 0
	}
	period, err := strconv.ParseFloat(parts[1], 64)
	if err != nil || period <= 0 {
		return 0
	}
	return quota / period
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
		// for a human/curl; alerting keys off the mailstrix_rules_stale metric instead.
		if s.rulesStale() {
			writeText(w, http.StatusOK, "ready (stale rules)")
			return
		}
		if d := s.cache.Degraded(); d != "" {
			writeText(w, http.StatusOK, "ready ("+d+")")
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
	case s.cfg.Pprof && strings.HasPrefix(r.URL.Path, "/debug/pprof"):
		if !s.metricsAuthed(r) {
			writeText(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		http.DefaultServeMux.ServeHTTP(w, r)
	default:
		writeText(w, http.StatusNotFound, "not found")
	}
}

// rulesStale reports whether the loaded ruleset is older than the configured
// MAILSTRIX_RULES_MAX_AGE. False when the check is disabled (max age 0) or the
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
// correlated with a specific image and rule bundle. Open by default (like
// /health) — it reveals version/rule-count/fingerprint, not message content —
// but gated by the same token as /metrics when MAILSTRIX_METRICS_AUTH is set (the
// ServeHTTP case returns 401 first), so an exposed port doesn't leak it.
func (s *Server) serveVersion(w http.ResponseWriter) {
	rl := s.engine.ReloadMetrics()
	resp := map[string]any{
		"version":           s.cfg.Version,
		"extractor_version": extract.Version,
		"rules":             s.engine.RuleCount(),
		"fingerprint":       s.engine.Fingerprint(),
		"last_reload_unix":  rl.LastUnix,
		"rules_mtime_unix":  rl.ModUnix,
		"rules_stale":       s.rulesStale(),
		"repo":              RepoURL,
		"home":              HomeURL,
		"license":           License,
	}
	if rl.PrevFingerprint != "" {
		resp["prev_fingerprint"] = rl.PrevFingerprint
	}
	if top := s.engine.TopMatches(20); len(top) > 0 {
		resp["top_matches"] = top
	}
	// Provenance of the loaded compiled bundle, when it came from the cache (set
	// by fetch-rules / the seeded manifest): which published rule version, when it
	// was generated, and the libyara it was compiled against.
	if m, ok := LoadManifest(s.cfg.CacheDir); ok {
		resp["rules_manifest"] = map[string]any{
			"version":   m.Version,
			"generated": m.Generated,
			"libyara":   m.Libyara,
			"count":     m.Rules,
		}
		srcs := m.Sources
		if len(srcs) == 0 {
			srcs = LoadSources("/usr/share/mailstrix")
		}
		if len(srcs) > 0 {
			resp["sources"] = srcs
		}
	} else {
		if srcs := LoadSources("/usr/share/mailstrix"); len(srcs) > 0 {
			resp["sources"] = srcs
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// maxBodyHardLimit is a constant ceiling above any MaxBody so the int(length)
// conversion in handleScan is provably bounded for the static analyzer.
const maxBodyHardLimit = 1 << 30 // 1 GiB

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	// Auth is optional: with no token configured (MAILSTRIX_TOKEN unset / none / 0 /
	// off), /scan is OPEN — intended only for a trusted private network, and
	// flagged with a loud startup warning. With a token set, it is required.
	if s.authRequired() && !s.authOK(r) {
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
	meta := scanMetaFromRequest(r, s.cfg.ArchivePW)

	// Resolve the effort tier for this scan (EFFORT-1): X-MAILSTRIX-Effort header,
	// else the configured env default, clamped to [1, EffortMax]. The clamp is the
	// DoS guard — a caller-set header can never exceed the operator's ceiling. The
	// resolved level rides on meta so it folds into the verdict-cache key below.
	hv, hset := effortHeader(r)
	meta.Effort = ResolveEffortLevel(hv, hset, s.autoEnvDefault(!hset), s.cfg.EffortMax)

	// Mix the active ruleset fingerprint AND the metadata into the cache key. The
	// fingerprint invalidates old verdicts on a SIGHUP reload (old keys orphan and
	// TTL-expire; no stale "clean" after a rule update). The metadata is in the key
	// because the verdict now DEPENDS on it: the same bytes with filename
	// "invoice.exe" vs "invoice.pdf" can match different rules, so they must not
	// share a cached verdict.
	// The verdict-cache key uses a FAST non-cryptographic hash of the body
	// (xxhash), NOT SHA256. Under a bulk campaign the cache-hit ratio is high, and
	// hashing a multi-MB body with SHA256 on every hit just to build the lookup key
	// was ~40% of the server's CPU (PERF: blockSHANI hot in pprof). xxhash is
	// allocation-free and orders of magnitude cheaper. Collision safety: the key
	// already mixes the ruleset fingerprint + metadata, and a 128-bit body hash
	// makes an accidental cross-body verdict collision astronomically unlikely; a
	// verdict cache is not a security boundary (a real SHA256 is still computed for
	// the MalwareBazaar lookup, see below). The cryptographic SHA256 the scan path
	// needs (mbazaar lookup key + extracted-stream dedup seed) is computed LAZILY,
	// only on a cache MISS, inside lookupOrScan — so a cache hit never hashes the
	// body cryptographically at all.
	// Compute the raw-body fingerprint ONCE in streamDedupKey's domain (PERF-22).
	// This [16]byte is stored on meta so Scanner.Scan can seed the per-stream dedup
	// set without re-hashing buf, and its string form replaces bodyCacheHash(buf)
	// as the body component of the verdict-cache key. The domain change from
	// bodyCacheHash (prefix 0x9e,0x37,0x79,0xb9) to streamDedupKey (prefix 0x01)
	// alters the cache-key bytes for existing entries, but the verdict cache is
	// ephemeral and already invalidated by any Fingerprint change — a domain-change
	// cold-start is equivalent and safe (L2/Redis keys are also per-Fingerprint so
	// no cross-version collision).
	meta.RawKey = streamDedupKey(buf)
	key := s.engine.Fingerprint() + ":" + meta.cacheKey() + ":" + string(meta.RawKey[:])
	matches, cacheStatus := s.lookupOrScan(ctx, key, buf, meta)

	if len(matches) > 0 {
		s.metrics.matches.Add(1)
	}
	if cacheStatus == "hit" || cacheStatus == "coalesced" {
		w.Header().Set("X-MAILSTRIX-Cache", cacheStatus)
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
	matches, shared, ferr := s.flights.Do(ctx, key, func() (m []Match, aborted bool) {
		// A leader may have populated the cache between the first lookup and
		// registering this flight.
		if m, found := s.cache.Get(key); found {
			return m, false
		}
		s.metrics.cacheMiss.Add(1)
		// Take the scan-CPU slot only for the actual libyara scan. If it can't be
		// had within the budget (or the client is gone), fail open as "no match"
		// — never block mail — and do NOT cache (no real verdict was computed). This
		// is an ABORT, not a verdict: the coalescing layer must not hand this empty
		// non-result to still-connected followers (AUDIT-FLIGHT-CONTEXT) — they
		// re-run instead. (A genuine clean scan returns aborted=false below.)
		if !s.acquireOn(ctx, s.sem) {
			s.metrics.busy.Add(1)
			s.errf("/scan %dB no scan slot within budget (fail-open)", len(buf))
			return nil, true
		}
		scanned, scanErr := func() ([]Match, error) {
			defer func() { <-s.sem }()
			return s.dispatch(buf, meta)
		}()
		if scanErr != nil {
			// Fail open: a scan error is "no match" to the plugin so a scanner
			// problem never blocks mail. A failed scan is NOT cached (don't
			// pin a wrong empty verdict for the whole TTL). This IS a real (if
			// degraded) outcome for THIS body — shareable, so aborted=false: a
			// re-run would hit the same error, and re-running every follower would
			// amplify the failure under load.
			s.metrics.errors.Add(1)
			s.errf("/scan %dB scan error (fail-open): %v", len(buf), scanErr)
			return nil, false
		}
		// Cache PUT, including optional Redis L2 SET, runs after the scan slot is
		// released. A healthy-but-slow Redis may still delay this response a little
		// but it no longer blocks unrelated libyara work.
		s.cache.Put(key, scanned)
		return scanned, false
	})
	if ferr != nil {
		// THIS caller's context was cancelled while coalesced-waiting (client
		// disconnected/timed out). Fail open, don't cache; the handler already
		// counts canceled via ctx.Err() on its own paths.
		s.metrics.canceled.Add(1)
		return nil, "canceled"
	}
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
// without a secret); when MAILSTRIX_METRICS_AUTH=1 they require the same token as
// /scan, so an accidentally-published 8079 doesn't leak rule count / fingerprint
// / runtime behaviour. /health and /ready stay open either way (probes).
func (s *Server) metricsAuthed(r *http.Request) bool {
	// Can't require a token that isn't set; an open scanner has nothing to gate.
	if !s.cfg.MetricsAuth || !s.authRequired() {
		return true
	}
	return s.authOK(r)
}

// authRequired reports whether a shared-secret gate is in force. False when no
// token is configured (MAILSTRIX_TOKEN unset / none / 0 / off) — /scan is then OPEN
// (a trusted-network deployment), flagged with a loud startup warning.
func (s *Server) authRequired() bool { return len(s.cfg.tokens) > 0 }

// authOK validates the presented secret against the configured token in constant
// time. Only meaningful when authRequired(). Accepts the token as a Bearer
// Authorization header or X-MAILSTRIX-Token.
func (s *Server) authOK(r *http.Request) bool {
	presented := ""
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		presented = strings.TrimSpace(a[len("Bearer "):])
	} else {
		presented = strings.TrimSpace(r.Header.Get("X-MAILSTRIX-Token"))
	}
	for _, tok := range s.cfg.tokens {
		if hmac.Equal([]byte(presented), []byte(tok)) {
			return true
		}
	}
	return false
}

func (s *Server) serveMetrics(w http.ResponseWriter) {
	var b strings.Builder
	fm := func(name, help string, v uint64) {
		b.WriteString("# HELP mailstrix_" + name + " " + help + "\n")
		b.WriteString("# TYPE mailstrix_" + name + " counter\n")
		b.WriteString("mailstrix_" + name + " " + strconv.FormatUint(v, 10) + "\n")
	}
	fm("scans_total", "total /scan requests served", s.metrics.scans.Load())
	fm("matches_total", "/scan requests with >=1 rule match", s.metrics.matches.Load())
	fm("errors_total", "scan/read/length errors", s.metrics.errors.Load())
	fm("busy_total", "requests rejected by the concurrency gate", s.metrics.busy.Load())
	fm("canceled_total", "requests abandoned because the client disconnected/timed out", s.metrics.canceled.Load())
	fm("cache_hits_total", "verdicts served from cache", s.metrics.cacheHit.Load())
	fm("cache_misses_total", "scans that ran (cache miss)", s.metrics.cacheMiss.Load())
	fm("cache_coalesced_total", "scans coalesced onto an in-flight identical scan", s.metrics.cacheCoalesced.Load())
	fm("bigfile_scans_total", "oversized buffers scanned against the targeted big-file ruleset instead of the full set (MAILSTRIX_BIGFILE_THRESHOLD gate)", s.engine.BigFileScans())
	fm("bigfile_stream_scans_total", "oversized extracted streams scanned against the targeted big-file ruleset instead of the full set (MAILSTRIX_BIGFILE_THRESHOLD gate)", s.engine.BigFileStreamScans())
	fm("raw_channel_scans_total", "libyara scans run on the raw message/attachment body (includes the big-file subset)", s.engine.RawChannelScans())
	fm("stream_channel_scans_total", "libyara scans run on real-content extracted streams (macros/archives/PDF/decoded; includes the big-file subset)", s.engine.StreamChannelScans())
	fm("marker_channel_scans_total", "libyara scans run on the out-of-band marker channel", s.engine.MarkerChannelScans())
	fm("raw_scan_errs_total", "raw scans that failed (timeout/libyara error) and fell through to extraction instead of aborting the request", s.engine.RawScanErrs())
	if lru, ok := s.cache.(*lruCache); ok {
		fm("cache_evictions_total", "L1 LRU evictions (capacity-driven; not TTL expiry)", lru.Evictions())
	}
	b.WriteString("# HELP mailstrix_rules loaded YARA rule count\n")
	b.WriteString("# TYPE mailstrix_rules gauge\n")
	b.WriteString("mailstrix_rules " + strconv.FormatInt(s.engine.RuleCount(), 10) + "\n")

	// EFFORT-2: the live auto effort level (0 until the first auto scan; static
	// builds leave it 0). Lets an operator watch the dial shed/recover under load.
	if s.cfg.EffortAuto {
		b.WriteString("# HELP mailstrix_effort_auto_level current MAILSTRIX_EFFORT=auto level (trails admission-gate pressure)\n")
		b.WriteString("# TYPE mailstrix_effort_auto_level gauge\n")
		b.WriteString("mailstrix_effort_auto_level " + strconv.FormatInt(s.autoEffort.Load(), 10) + "\n")
	}

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
	fm("extract_archive_decrypted_total", "archives with >=1 password-protected member decrypted via a candidate password", ex.ArchiveDecrypted)
	fm("extract_ole_package_total", "OLE2 docs with an embedded OLE Package object (Ole10Native carved)", ex.OLEPackage)
	fm("extract_lnk_total", "Windows shell links (.lnk) with StringData (command-line args/paths) surfaced", ex.LNK)
	fm("extract_pdf_total", "PDFs with FlateDecode object streams inflated for scanning", ex.PDF)
	fm("extract_rtf_total", "RTF docs with \\objdata embedded objects hex-decoded and carved", ex.RTF)
	fm("extract_slk_total", "SYLK (.slk) spreadsheets whose XLM/DDE cell formulas were extracted for scanning", ex.SLK)
	fm("extract_encoded_script_total", "buffers with >=1 decoded MS-Script-Encoder (VBE/JSE) block", ex.EncScript)
	fm("extract_decoded_total", "buffers with >=1 base64/hex/reversed blob from the static decode pass", ex.Decoded)
	fm("extract_docprops_total", "documents with doc-property strings (OOXML docProps/customXml/docVars or OLE2 SummaryInformation) extracted for scanning", ex.DocProps)
	fm("extract_xlm_fold_total", "documents with XLM formula constant-folding (CHAR/string reassembly) applied", ex.XLMFold)
	fm("extract_stream_matches_total", "rule hits attributable only to an extracted stream (not raw bytes)", ex.StreamMatches)
	fm("extract_deduped_total", "extracted streams skipped before YARA scan (content-hash duplicate of a prior stream or raw buf)", ex.Deduped)
	fm("extract_ext_mismatch_total", "attachments whose real container type contradicts a benign-looking extension (renamed dropper)", ex.ExtMismatch)

	// Rule-reload activity — so a SIGHUP that silently fails to compile is visible
	// to alerting, not just buried in logs.
	rl := s.engine.ReloadMetrics()
	fm("reload_attempts_total", "rule reload attempts (incl. boot load)", rl.Attempts)
	fm("reload_success_total", "successful rule reloads", rl.Successes)
	fm("reload_failure_total", "failed rule reloads (previous set kept)", rl.Failures)
	gauge := func(name, help string, v int64) {
		b.WriteString("# HELP mailstrix_" + name + " " + help + "\n")
		b.WriteString("# TYPE mailstrix_" + name + " gauge\n")
		b.WriteString("mailstrix_" + name + " " + strconv.FormatInt(v, 10) + "\n")
	}
	gauge("reload_last_timestamp_seconds", "unix time of the last successful reload", rl.LastUnix)
	gauge("reload_last_duration_ms", "wall-clock duration of the last reload attempt", rl.LastMillis)

	// Rule staleness — catch a silently-broken daily image rebuild (the running
	// container keeps serving old baked rules with no error). Age is derived from
	// the loaded ruleset's on-disk mtime; rules_stale is 1 only when a max age is
	// configured (MAILSTRIX_RULES_MAX_AGE) and exceeded. Both are 0/absent-safe: a
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
	gauge("rules_stale", "1 if rules_age_seconds exceeds MAILSTRIX_RULES_MAX_AGE (0 when unset or fresh)", stale)

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

	// ThreatFox IOC lookup (only meaningful when enabled).
	tf := s.engine.ThreatFoxMetrics()
	if tf.Enabled {
		fm("threatfox_lookups_total", "buffers checked against the ThreatFox feed", tf.Lookups)
		fm("threatfox_hits_total", "buffers with >=1 ThreatFox match", tf.Hits)
		fm("threatfox_refresh_failures_total", "ThreatFox feed refresh failures", tf.RefreshFailures)
		gauge("threatfox_feed_urls", "URLs in the loaded ThreatFox feed", tf.FeedURLs)
		gauge("threatfox_feed_domains", "domains in the loaded ThreatFox feed", tf.FeedDomains)
		gauge("threatfox_last_refresh_timestamp_seconds", "unix time of the last successful feed refresh", tf.LastRefreshUnix)
	}

	if s.cfg.ICAPAddr != "" {
		fm("icap_requests_total", "total ICAP REQMOD/RESPMOD requests served", s.metrics.icapRequests.Load())
		fm("icap_infected_total", "ICAP requests with >=1 rule match (403 replacement sent)", s.metrics.icapInfected.Load())
		fm("icap_options_total", "ICAP OPTIONS requests served", s.metrics.icapOptions.Load())
		fm("icap_conn_refused_total", "ICAP connections refused at the live-connection cap", s.metrics.icapBusy.Load())
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

// filenameHeader carries the attachment filename from the rspamd plugin. The
// value is base64 (std, padding optional, whitespace tolerated): the name comes
// from the email and is attacker-controlled, so encoding it stops an embedded
// CR/LF or control byte from injecting an HTTP header or log line. Absent or
// undecodable ⇒ no metadata, never an error (the scan still runs).
const filenameHeader = "X-MAILSTRIX-Filename"

// effortHeader is the per-request effort-tier override (EFFORT-1/EFFORT-3). The
// caller (e.g. the rspamd plugin) sets it from sender reputation / prior score:
// a low value for trusted senders (cheap shallow scan), a high value for
// suspicious ones (full-depth). The value is clamped to the operator's
// EffortMax, so it can only ever LOWER effort below the ceiling, never raise it
// past the configured DoS bound (see ResolveEffortLevel).
const effortHeaderName = "X-MAILSTRIX-Effort"

// pwCandidatesHeader carries candidate passwords extracted by the rspamd plugin
// from the mail subject/body, for the opt-in encrypted-archive decrypt feature.
// The value is base64 of a newline-joined list (same base64 transport + control-
// byte safety as filenameHeader — the candidates are attacker-controlled mail
// text). Absent/undecodable ⇒ no candidates, never an error. The list is hard-
// capped on parse (count + per-item length) so a hostile header can't inflate the
// brute-force candidate set; the candidates are only ever decrypt INPUTS, never
// executed.
const pwCandidatesHeader = "X-MAILSTRIX-PWCandidates" // #nosec G101 -- HTTP header NAME, not a credential

const (
	// maxHeaderPWCandidates bounds how many candidate passwords are accepted from
	// the request header (the per-request slice). The scanner re-caps the merged
	// effective list separately; this bounds just the attacker-supplied portion.
	maxHeaderPWCandidates = 32
	// maxHeaderPWCandidateLen caps one candidate length (bytes). Passwords longer
	// than this are dropped — a multi-kilobyte "candidate" is abuse, not a password.
	maxHeaderPWCandidateLen = 64
)

// pwCandidatesFromRequest decodes and bounds the X-MAILSTRIX-PWCandidates header.
// Returns nil when the header is absent/undecodable/empty. Each newline-separated
// candidate is trimmed of surrounding whitespace and control bytes; blank and
// over-long candidates are dropped; duplicates are removed; the result is capped
// at maxHeaderPWCandidates. Fail-soft: any decode problem yields nil (no
// candidates), never an error — the scan still runs.
func pwCandidatesFromRequest(r *http.Request) []string {
	raw := r.Header.Get(pwCandidatesHeader)
	if raw == "" {
		return nil
	}
	dec, ok := decodeFilenameB64(raw) // same whitespace-tolerant std/raw base64 decode
	if !ok {
		return nil
	}
	// Bound the decoded blob before splitting: at most count×(len+1 newline) bytes
	// can yield usable candidates, so a max-folded header full of newlines can't
	// allocate a huge split slice. Excess is truncated (a real candidate list never
	// approaches this).
	if maxBlob := maxHeaderPWCandidates * (maxHeaderPWCandidateLen + 1); len(dec) > maxBlob {
		dec = dec[:maxBlob]
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, maxHeaderPWCandidates)
	for _, line := range strings.Split(string(dec), "\n") {
		// Strip control bytes (incl. CR/NUL) and trim — the decoded blob is
		// attacker-controlled; a candidate is a plain password, never a control seq.
		c := strings.TrimSpace(strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, line))
		if c == "" || len(c) > maxHeaderPWCandidateLen {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
		if len(out) >= maxHeaderPWCandidates {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// autoEnvDefault returns the env-default effort level fed to ResolveEffortLevel.
// With MAILSTRIX_EFFORT=auto (EFFORT-2) and no per-request header overriding it
// (canAuto), it derives the level from current admission-gate pressure and steps
// the smoothed autoEffort one level toward it (hysteresis), so the returned
// "default" tracks load. Otherwise (auto off, or a header is present and takes
// precedence) it returns the static configured level cfg.Effort.
//
// Called while holding an admission slot, so len(s.admit) counts this request.
func (s *Server) autoEnvDefault(canAuto bool) int {
	if !s.cfg.EffortAuto || !canAuto {
		return s.cfg.Effort
	}
	occupied := len(s.admit) // includes our own held slot
	target := autoTargetLevel(occupied, cap(s.admit), s.cfg.Effort, s.cfg.EffortMax)
	// CAS loop: admission slots are concurrent, so a plain Load/Store would let two
	// scans read the same level and lose a step (or both "snap" from 0 to different
	// targets). CAS makes each step atomic — concurrent scans serialise, every one
	// moves at most one level, hysteresis holds. The loop retries until our step
	// commits against the level no other scan changed underneath us.
	for {
		cur := s.autoEffort.Load()
		next := int64(autoStepLevel(int(cur), target))
		if s.autoEffort.CompareAndSwap(cur, next) {
			return int(next)
		}
	}
}

// effortHeader parses the X-MAILSTRIX-Effort request header. It returns the integer
// value and true when the header carried a usable non-negative integer; a
// missing or malformed header returns (0, false) so the caller falls back to the
// configured default. Out-of-range integers are NOT rejected here — clamping is
// ResolveEffortLevel's job (fail-toward-configured, never error a scan over a
// header).
func effortHeader(r *http.Request) (int, bool) {
	raw := strings.TrimSpace(r.Header.Get(effortHeaderName))
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false // not an integer — fall back to the configured default
	}
	// A negative value IS a present header (a caller asking for minimum effort or a
	// typo), not "no header" — return it set so ResolveEffortLevel clamps it UP to
	// 1, rather than silently falling back to the env default (which could be
	// higher, the surprising outcome). Only a missing/non-integer header defaults.
	return n, true
}

// scanMetaFromRequest extracts and normalizes the attachment metadata the plugin
// attached to the scan. See filenameHeader for the wire format / why base64.
func scanMetaFromRequest(r *http.Request, archivePW bool) ScanMeta {
	var meta ScanMeta
	if raw := r.Header.Get(filenameHeader); raw != "" {
		if dec, ok := decodeFilenameB64(raw); ok {
			meta = NewScanMeta(string(dec))
		}
	}
	// Password candidates ride independently of the filename header — a message can
	// carry body-extracted candidates with no attachment-name metadata. Parsed ONLY
	// when the decrypt feature is enabled: when off, the candidates can never affect
	// the verdict, so decoding+keying them would only let an attacker bust the cache
	// (unique passwords per message → forced misses) for no detection benefit.
	if archivePW {
		meta.PWCandidates = pwCandidatesFromRequest(r)
	}
	return meta
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
