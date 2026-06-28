// Package yarad is the out-of-process YARA scanner backend for rspamd. rspamd
// (as of 4.1.0) has no native YARA module, so this service plays the same role
// the gozer DCC/Razor/Pyzor backend does: rspamd's mailstrix.lua plugin POSTs a
// message (or a MIME part) over HTTP, yarad scans the bytes against a set of
// compiled YARA rules and returns the matching rule names as JSON. Scanning out
// of process keeps the rspamd event loop non-blocking and keeps libyara (a CGO
// dependency) out of the rspamd image.
package mailstrix

import (
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Config is yarad's runtime configuration, populated from the environment by
// LoadConfig. Field comments name the env var each value comes from. The
// env-helper style mirrors gozer so the two backends configure identically.
type Config struct {
	Host           string        // MAILSTRIX_HOST            (default 0.0.0.0)
	Port           int           // MAILSTRIX_PORT            (default 8079)
	BackendTimeout time.Duration // MAILSTRIX_BACKEND_TIMEOUT (default 1s)
	MaxConcurrent  int           // MAILSTRIX_MAX_CONCURRENT  (default "auto" = CPU count)
	MaxInflight    int           // MAILSTRIX_MAX_INFLIGHT    (default 2×MaxConcurrent); admission gate
	MaxBody        int64         // MAILSTRIX_MAX_BODY bytes  (default 8 MiB)
	Token          string        // MAILSTRIX_TOKEN[_FILE]    (required for /scan; comma-separated for rotation)
	TokenNext      string        // MAILSTRIX_TOKEN_NEXT[_FILE] (incoming rotation token; empty = no rotation)

	// tokens is the expanded accepted-token set: comma-separated parts of Token
	// plus TokenNext (if set and not a sentinel). Built by sanitize(); never set
	// directly. Use len(tokens)>0 to test whether auth is required.
	tokens []string

	// RulesDir is the directory of *.yar / *.yara source files compiled at boot
	// and on SIGHUP. RulesPath, if set, is a single precompiled (.yac) ruleset
	// loaded instead of compiling sources (faster startup, used when the image
	// bakes a compiled bundle). RulesPath wins when both are set.
	RulesDir  string // MAILSTRIX_RULES_DIR  (default /rules)
	RulesPath string // MAILSTRIX_RULES      (optional precompiled bundle)

	// CacheDir is the writable directory yarad keeps its live, updatable rule
	// bundle in (and later the abuse.ch feed snapshots). SeedRules is the baked,
	// read-only compiled .yac shipped in the image. On startup, when SeedRules is
	// set and CacheDir/compiled.yac is missing or unreadable, the seed is copied
	// into the cache and loaded from there — so a fresh deploy (or a wiped
	// bindmount) always self-heals to a known-good tested ruleset with no network.
	// `--fetch-rules` (a later step) refreshes the cache copy. Both empty keeps the
	// old behaviour (load RulesPath/RulesDir directly).
	CacheDir  string // MAILSTRIX_CACHE_DIR  (e.g. /var/cache/mailstrix; empty = disabled)
	SeedRules string // MAILSTRIX_SEED_RULES (baked read-only .yac to seed the cache from)

	// RulesMaxAge flags the loaded ruleset as STALE once its on-disk mtime is
	// older than this. The image bakes rules and a daily rebuild refreshes them;
	// if that rebuild silently breaks (fetch failed, image not redeployed) the
	// running container keeps serving old rules with no error. When set (>0) and
	// exceeded, /ready reports "stale" (503) so an orchestrator/alert notices —
	// but /health stays OK and scanning continues (fail-open: old rules still
	// catch most malware; a hard-down scanner is worse). 0 disables the check.
	RulesMaxAge time.Duration // MAILSTRIX_RULES_MAX_AGE (seconds; default 0 = off)

	// ScanTimeout bounds a single libyara scan so a pathological rule/input
	// cannot stall a worker (YARA's own internal timeout, seconds).
	ScanTimeout time.Duration // MAILSTRIX_SCAN_TIMEOUT (default 8s)

	// BigFileThreshold gates an oversized-buffer cost defence. A full-ruleset scan
	// of a multi-MB buffer is inherently unbounded (size × ~12k rules) and can
	// time out even at a large ScanTimeout, so the scanner fail-opens and a padded
	// dropper is MISSED. When a scanned buffer is larger than this threshold, the
	// scanner runs the small, high-signal "big-file" ruleset (BigFileRules — our
	// in-repo local rules only) INSTEAD of the full bundle, so the scan completes
	// fast and the local heuristics still fire. Below it, behaviour is unchanged
	// (full ruleset). Default 6 MiB (below the 8 MiB MaxBody default so a file
	// padded toward the body cap hits the gate). 0 disables the gate entirely.
	BigFileThreshold int64 // MAILSTRIX_BIGFILE_THRESHOLD bytes (default 6 MiB; 0 = off)

	// BigFileRules is the targeted ruleset used by the oversized-buffer gate. It is
	// a path to either a precompiled .yac bundle (loaded directly) or a directory
	// of *.yar/*.yara source files (compiled at boot, like RulesDir). It should
	// hold ONLY the in-repo high-signal local rules so the gated scan is cheap.
	// Empty disables the gate even if BigFileThreshold>0 — Scan then falls back to
	// the full ruleset for oversized buffers (logged once), never crashing.
	BigFileRules string // MAILSTRIX_BIGFILE_RULES (default = baked local.yac seed)

	// Verdict cache. At high volume mail is heavily duplicated (bulk campaigns,
	// one body to N recipients, MTA retries), so caching SHA256(body) -> matches
	// turns most scans into a microsecond lookup. The in-process LRU is always
	// on; RedisURL adds a shared layer across replicas (empty => LRU only).
	CacheTTL    time.Duration // MAILSTRIX_CACHE_TTL    (default 3600s; 0 disables caching)
	CacheSize   int           // MAILSTRIX_CACHE_SIZE   (default 65536 in-memory entries)
	RedisURL    string        // MAILSTRIX_REDIS_URL    (empty -> in-process LRU only)
	RedisPrefix string        // MAILSTRIX_REDIS_PREFIX (default yara:scan:)

	Verbose     bool // MAILSTRIX_VERBOSE
	LogStdout   bool // MAILSTRIX_LOG_STDOUT — info/access to stdout; errors stay stderr
	MetricsAuth bool // MAILSTRIX_METRICS_AUTH — require the token for /metrics and /version
	Pprof       bool // MAILSTRIX_PPROF — enable /debug/pprof (off by default, ops-only)
	Canary      bool // MAILSTRIX_CANARY — shadow/observe-only: tag ALL matches mailstrix_canary=1

	// DenylistFile is an optional path to a file of rule names (one per line,
	// # comments, case-insensitive) merged with the env-based RuleDenylist.
	// Re-read on every SIGHUP so rules can be suppressed without a restart.
	// If the file doesn't exist or is unreadable, a warning is logged and
	// scanning continues with the env-only denylist (fail-open).
	DenylistFile string // MAILSTRIX_DENYLIST_FILE (default empty = disabled)

	// URLhaus malware-URL lookup. Disabled unless an abuse.ch Auth-Key is set.
	URLhausKey     string        // MAILSTRIX_URLHAUS_KEY[_FILE] — abuse.ch Auth-Key
	URLhausRefresh time.Duration // MAILSTRIX_URLHAUS_REFRESH (default 360m, floor 5m)
	URLhausMaxURLs int           // MAILSTRIX_URLHAUS_MAX_URLS  (per message, default 64)

	// MalwareBazaar attachment-hash lookup (abuse.ch). The SHA256 of each scanned
	// buffer is matched against a cached set of known-malware sample hashes.
	// Disabled unless an Auth-Key is set (the SAME abuse.ch key as URLhaus).
	MBazaarKey     string        // MAILSTRIX_MBAZAAR_KEY[_FILE] — abuse.ch Auth-Key
	MBazaarRefresh time.Duration // MAILSTRIX_MBAZAAR_REFRESH (default 24h, floor 5m)
	MBazaarFeed    string        // MAILSTRIX_MBAZAAR_FEED (URL override; default full dump)

	// ThreatFox IOC lookup (abuse.ch). URL and domain IOCs from the ThreatFox
	// recent-IOC CSV are matched against URLs extracted from scanned buffers.
	// Complements URLhaus (delivery URLs) with botnet C&C indicators.
	// Disabled unless an Auth-Key is set (same abuse.ch key as URLhaus).
	ThreatFoxKey     string        // MAILSTRIX_THREATFOX_KEY[_FILE] — abuse.ch Auth-Key
	ThreatFoxRefresh time.Duration // MAILSTRIX_THREATFOX_REFRESH (default 360m, floor 5m)
	ThreatFoxMaxURLs int           // MAILSTRIX_THREATFOX_MAX_URLS (per message, default 64)

	// Feodo Tracker IP blocklist (abuse.ch). Public feed of botnet C&C server IPs.
	// Matches URLs with raw IP hosts against the blocklist. No auth required;
	// set MAILSTRIX_FEODO=1 to enable.
	FeodoEnabled bool          // MAILSTRIX_FEODO (0/1, default 0 = disabled)
	FeodoRefresh time.Duration // MAILSTRIX_FEODO_REFRESH (default 360m, floor 5m)

	ICAPAddr string // MAILSTRIX_ICAP_ADDR (empty = disabled; e.g. ":1344")

	// RuleDenylist suppresses matches for these rule names (case-insensitive).
	// Public rulesets ship demo/noise rules that are pure false positives for
	// mail — e.g. Didier Stevens' `http` rule (rtf.yara) is `$="http" nocase`,
	// so it fires on virtually every message. Defaults to "http"; override with a
	// comma-separated list, or set the var empty to disable filtering entirely.
	RuleDenylist map[string]struct{} // MAILSTRIX_RULE_DENYLIST (comma-sep, default "http")

	// RuleAllowlist names rules whose matches are KEPT but tagged log-only
	// (case-insensitive): yarad still reports them (so they show in the mail
	// history) but adds meta `mailstrix_allow=1`, and the rspamd plugin routes those
	// to a 0-weight symbol. This force-demotes a known-FP rule without dropping
	// its visibility (denylist) and without patching the upstream source. Empty
	// by default. A name in BOTH lists is denied (drop wins over demote).
	RuleAllowlist map[string]struct{} // MAILSTRIX_RULE_ALLOWLIST (comma-sep, default empty)

	// Effort tiers (EFFORT-1). A single 1..EffortMax dial scales every bounded
	// extraction/scan cap so one binary serves both a latency-tight front
	// (rspamd, pre-queue) and a deeper backend (LDA/sieve), and can shed work
	// under load. Level 1 = raw + shallowest extraction, EffortMax = everything.
	//
	// Resolution order per request (see ResolveEffort / scanMetaFromRequest):
	// X-MAILSTRIX-Effort header ?? Effort (env default), clamped to [1, EffortMax].
	// EffortMax is the DoS ceiling — an attacker-set header can never raise effort
	// above it. The resolved level folds into the verdict-cache key (the same
	// bytes scanned at effort 2 vs 9 can yield different verdicts).
	//
	// EFFORT-4 made the dial LIVE: a level now resolves to a real cap profile
	// (EffortProfileFor) that scales the MSD decode depth/iterations, the PDF
	// structural-indicator pass, and whether the URLhaus/MalwareBazaar reputation
	// feeds run. A low level is cheaper and shallower; EffortMax runs everything.
	Effort     int  // MAILSTRIX_EFFORT     (default = EffortMax; the env/default level)
	EffortMax  int  // MAILSTRIX_EFFORT_MAX (default 10; hard ceiling for header override)
	EffortAuto bool // MAILSTRIX_EFFORT=auto (EFFORT-2): derive the per-request level from
	// admission-gate pressure instead of a fixed env default — start at EffortMax
	// when idle, shed a level as in-flight scans fill the gate, climb back as it
	// drains. A request-level X-MAILSTRIX-Effort header still overrides auto.

	Version string // build version string, set by main (not from env); for /version
}

// LoadConfig reads the environment into a Config, applying documented defaults,
// then sanitizes invalid numeric values.
func LoadConfig() *Config {
	c := &Config{
		Host:             envStr("MAILSTRIX_HOST", "0.0.0.0"),
		Port:             envInt("MAILSTRIX_PORT", 8079),
		BackendTimeout:   envDur("MAILSTRIX_BACKEND_TIMEOUT", 1),
		MaxConcurrent:    envIntAuto("MAILSTRIX_MAX_CONCURRENT", runtime.NumCPU()),
		MaxInflight:      envIntAuto("MAILSTRIX_MAX_INFLIGHT", 0), // 0 -> sanitize sets 2×MaxConcurrent
		MaxBody:          envInt64("MAILSTRIX_MAX_BODY", 8*1024*1024),
		Token:            envOrFile("MAILSTRIX_TOKEN"),
		TokenNext:        envOrFile("MAILSTRIX_TOKEN_NEXT"),
		RulesDir:         envStr("MAILSTRIX_RULES_DIR", "/rules"),
		RulesPath:        strings.TrimSpace(os.Getenv("MAILSTRIX_RULES")),
		CacheDir:         strings.TrimSpace(os.Getenv("MAILSTRIX_CACHE_DIR")),
		SeedRules:        strings.TrimSpace(os.Getenv("MAILSTRIX_SEED_RULES")),
		RulesMaxAge:      envDur("MAILSTRIX_RULES_MAX_AGE", 0),
		ScanTimeout:      envDur("MAILSTRIX_SCAN_TIMEOUT", 8),
		BigFileThreshold: envInt64("MAILSTRIX_BIGFILE_THRESHOLD", 6*1024*1024),
		BigFileRules:     strings.TrimSpace(os.Getenv("MAILSTRIX_BIGFILE_RULES")),
		CacheTTL:         envDur("MAILSTRIX_CACHE_TTL", 3600),
		CacheSize:        envInt("MAILSTRIX_CACHE_SIZE", 65536),
		RedisURL:         strings.TrimSpace(os.Getenv("MAILSTRIX_REDIS_URL")),
		RedisPrefix:      envStr("MAILSTRIX_REDIS_PREFIX", "yara:scan:"),
		Verbose:          envBool("MAILSTRIX_VERBOSE"),
		LogStdout:        envBool("MAILSTRIX_LOG_STDOUT"),
		MetricsAuth:      envBool("MAILSTRIX_METRICS_AUTH"),
		Pprof:            envBool("MAILSTRIX_PPROF"),
		Canary:           envBool("MAILSTRIX_CANARY"),
		DenylistFile:     envStr("MAILSTRIX_DENYLIST_FILE", ""),
		URLhausKey:       envOrFile("MAILSTRIX_URLHAUS_KEY"),
		URLhausRefresh:   envDur("MAILSTRIX_URLHAUS_REFRESH", 21600),
		URLhausMaxURLs:   envInt("MAILSTRIX_URLHAUS_MAX_URLS", 64),
		MBazaarKey:       envOrFile("MAILSTRIX_MBAZAAR_KEY"),
		MBazaarRefresh:   envDur("MAILSTRIX_MBAZAAR_REFRESH", 86400),
		MBazaarFeed:      strings.TrimSpace(os.Getenv("MAILSTRIX_MBAZAAR_FEED")),
		ThreatFoxKey:     envOrFile("MAILSTRIX_THREATFOX_KEY"),
		ThreatFoxRefresh: envDur("MAILSTRIX_THREATFOX_REFRESH", 21600),
		ThreatFoxMaxURLs: envInt("MAILSTRIX_THREATFOX_MAX_URLS", 64),
		FeodoEnabled:     envBool("MAILSTRIX_FEODO"),
		FeodoRefresh:     envDur("MAILSTRIX_FEODO_REFRESH", 21600),
		ICAPAddr:         strings.TrimSpace(os.Getenv("MAILSTRIX_ICAP_ADDR")),
		RuleDenylist:     envSet("MAILSTRIX_RULE_DENYLIST", "http"),
		RuleAllowlist:    envSet("MAILSTRIX_RULE_ALLOWLIST", ""),
		EffortMax:        envInt("MAILSTRIX_EFFORT_MAX", defaultEffortMax),
		Effort:           envInt("MAILSTRIX_EFFORT", 0), // 0 -> sanitize sets = EffortMax
		// MAILSTRIX_EFFORT=auto (EFFORT-2) flips auto pressure-shedding. The numeric
		// Effort above stays the IDLE ceiling for the auto resolver (with "auto" the
		// Atoi above fails -> Effort==0 -> sanitize sets it = EffortMax, i.e. the
		// idle level is full depth) and is also the fallback level if auto is later
		// disabled by config error.
		EffortAuto: strings.EqualFold(strings.TrimSpace(os.Getenv("MAILSTRIX_EFFORT")), "auto"),
	}
	c.sanitize()
	return c
}

// Finalize re-applies the same clamps as the initial load, so any CLI flag
// overlay that sets a non-positive value (e.g. -scan-timeout=0) is caught and
// reset to its safe default before the scanner or server is constructed.
// Calling it more than once is safe (idempotent: clamping an already-valid
// value leaves it unchanged).
func (c *Config) Finalize() { c.sanitize() }

// sanitize clamps invalid numeric configuration to safe defaults so a bad env
// value cannot disable the service or crash it (negative concurrency panics
// make(chan), an out-of-range port fails to bind). Each clamp is logged.
func (c *Config) sanitize() {
	// Auth is optional: the explicit sentinels normalise to an empty token so an
	// operator can run an OPEN scanner on a trusted network (the server logs a
	// loud warning). Done here so it covers both the env value and a -token flag
	// (NewServer re-sanitizes after flags are applied).
	//
	// Expand the (possibly comma-separated) primary token and the optional
	// next-rotation token (MAILSTRIX_TOKEN_NEXT[_FILE]) into the accepted-token set.
	// Each comma-separated part is trimmed; sentinel/empty parts are dropped.
	// Duplicates (e.g. TokenNext already in the primary list) are skipped.
	rawToken := c.Token
	c.Token = normalizeToken(rawToken) // keep normalised primary for logs/authRequired fallback
	c.tokens = nil
	for _, part := range strings.Split(rawToken, ",") {
		if normalizeToken(part) != "" {
			c.tokens = append(c.tokens, strings.TrimSpace(part))
		}
	}
	if next := normalizeToken(c.TokenNext); next != "" {
		c.TokenNext = next
		dup := false
		for _, t := range c.tokens {
			if t == next {
				dup = true
				break
			}
		}
		if !dup {
			c.tokens = append(c.tokens, next)
		}
	} else {
		c.TokenNext = ""
	}

	clamp := func(name string, got, def int) int {
		log.Printf("[mailstrix] WARNING: invalid %s=%d; using %d", name, got, def)
		return def
	}
	if c.MaxConcurrent < 1 {
		c.MaxConcurrent = clamp("MAILSTRIX_MAX_CONCURRENT", c.MaxConcurrent, runtime.NumCPU())
	}
	// The admission gate bounds in-flight buffers and must be at least the scan
	// concurrency (otherwise scan slots could never all be used). Default to 2×
	// so a slow body read or slow Redis L2 lookup can't starve scan slots.
	if c.MaxInflight < c.MaxConcurrent {
		c.MaxInflight = c.MaxConcurrent * 2
	}
	if c.Port < 1 || c.Port > 65535 {
		c.Port = clamp("MAILSTRIX_PORT", c.Port, 8079)
	}
	if c.BackendTimeout <= 0 {
		log.Printf("[mailstrix] WARNING: invalid MAILSTRIX_BACKEND_TIMEOUT=%s; using 1s", c.BackendTimeout)
		c.BackendTimeout = 1 * time.Second
	}
	if c.ScanTimeout <= 0 {
		log.Printf("[mailstrix] WARNING: invalid MAILSTRIX_SCAN_TIMEOUT=%s; using 8s", c.ScanTimeout)
		c.ScanTimeout = 8 * time.Second
	}
	if c.MaxBody <= 0 {
		c.MaxBody = 8 * 1024 * 1024
	}
	if c.BigFileThreshold < 0 {
		c.BigFileThreshold = 0 // negative is nonsensical; 0 disables the gate
	}
	if c.CacheSize < 1 {
		c.CacheSize = 65536
	}
	if c.CacheTTL < 0 {
		c.CacheTTL = 0 // negative is nonsensical; 0 disables the cache
	}
	if c.RulesMaxAge < 0 {
		c.RulesMaxAge = 0 // negative is nonsensical; 0 disables the staleness check
	}
	// Effort tiers: EffortMax is the ceiling (clamp to [1, maxEffortCeiling]); the
	// env-default Effort then clamps to [1, EffortMax] (0 => "= EffortMax", the
	// full-depth default so an operator who sets nothing keeps today's behaviour).
	if c.EffortMax < 1 || c.EffortMax > maxEffortCeiling {
		c.EffortMax = clamp("MAILSTRIX_EFFORT_MAX", c.EffortMax, defaultEffortMax)
	}
	if c.Effort == 0 {
		c.Effort = c.EffortMax // unset -> full-depth default (today's behaviour)
	}
	// Clamp into [1, EffortMax]. A too-LOW value (incl. a negative typo) floors to
	// 1 — minimum effort, never silently bumped to the ceiling; a too-HIGH value
	// caps at EffortMax.
	if c.Effort < 1 {
		log.Printf("[mailstrix] WARNING: invalid MAILSTRIX_EFFORT=%d; using 1", c.Effort)
		c.Effort = 1
	} else if c.Effort > c.EffortMax {
		c.Effort = clamp("MAILSTRIX_EFFORT", c.Effort, c.EffortMax)
	}
}

// Effort-tier bounds. EffortMax defaults to 10 (the documented 1..10 dial);
// maxEffortCeiling is the absolute upper limit an operator can configure, so the
// level can be used as a small bounded array/profile index without overflow.
const (
	defaultEffortMax = 10
	maxEffortCeiling = 10
)

// normalizeToken maps the explicit "no auth" sentinels (and an unset value) to
// an empty token, so /scan runs OPEN. A real secret equal to one of these words
// is not supported — use a longer, non-sentinel token.
func normalizeToken(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "none", "off", "0", "disabled", "false":
		return ""
	}
	return t
}

// --- env helpers (identical semantics to gozer) ---

// envOrFile returns the trimmed contents of $<name>_FILE if that file exists,
// else the trimmed value of $<name>. Lets a secret be supplied via a mounted
// file (Docker secrets / the 0444 token file pattern) instead of the env.
func envOrFile(name string) string {
	if f := os.Getenv(name + "_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil { // #nosec G304 G703 -- operator-provided secret path (*_FILE env), not attacker input
			return strings.TrimSpace(string(b))
		}
	}
	return strings.TrimSpace(os.Getenv(name))
}

func envStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// envSet parses a comma-separated env var into a case-insensitive set. The
// default is used only when the var is UNSET; an explicitly empty value
// (MAILSTRIX_RULE_DENYLIST=) yields an empty set so an operator can opt out.
func envSet(name, def string) map[string]struct{} {
	v, ok := os.LookupEnv(name)
	if !ok {
		v = def
	}
	out := make(map[string]struct{})
	for _, part := range strings.Split(v, ",") {
		if p := strings.ToLower(strings.TrimSpace(part)); p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

func envInt(name string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil {
		return n
	}
	return def
}

// envIntAuto is envInt that also accepts the literal "auto" (case-insensitive),
// returning the caller's default. Used for MAILSTRIX_MAX_CONCURRENT so operators can
// write "auto" to mean "size to the CPU count" — which sets the number of scans
// run in parallel (and thus the effective scanning thread count) — instead of
// hard-coding a number. Empty or invalid also falls back to the default.
func envIntAuto(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" || strings.EqualFold(v, "auto") {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

func envInt64(name string, def int64) int64 {
	if n, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(name)), 10, 64); err == nil {
		return n
	}
	return def
}

// envDur reads a value expressed in seconds (float) into a Duration.
func envDur(name string, defSecs float64) time.Duration {
	secs := defSecs
	if f, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(name)), 64); err == nil {
		secs = f
	}
	return time.Duration(secs * float64(time.Second))
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
