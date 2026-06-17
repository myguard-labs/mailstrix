// Package yarad is the out-of-process YARA scanner backend for rspamd. rspamd
// (as of 4.1.0) has no native YARA module, so this service plays the same role
// the gozer DCC/Razor/Pyzor backend does: rspamd's yara.lua plugin POSTs a
// message (or a MIME part) over HTTP, yarad scans the bytes against a set of
// compiled YARA rules and returns the matching rule names as JSON. Scanning out
// of process keeps the rspamd event loop non-blocking and keeps libyara (a CGO
// dependency) out of the rspamd image.
package yarad

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
	Host           string        // YARAD_HOST            (default 0.0.0.0)
	Port           int           // YARAD_PORT            (default 8079)
	BackendTimeout time.Duration // YARAD_BACKEND_TIMEOUT (default 6s)
	MaxConcurrent  int           // YARAD_MAX_CONCURRENT  (default "auto" = CPU count)
	MaxInflight    int           // YARAD_MAX_INFLIGHT    (default 2×MaxConcurrent); admission gate
	MaxBody        int64         // YARAD_MAX_BODY bytes  (default 8 MiB)
	Token          string        // YARAD_TOKEN[_FILE]    (required for /scan)

	// RulesDir is the directory of *.yar / *.yara source files compiled at boot
	// and on SIGHUP. RulesPath, if set, is a single precompiled (.yac) ruleset
	// loaded instead of compiling sources (faster startup, used when the image
	// bakes a compiled bundle). RulesPath wins when both are set.
	RulesDir  string // YARAD_RULES_DIR  (default /rules)
	RulesPath string // YARAD_RULES      (optional precompiled bundle)

	// ScanTimeout bounds a single libyara scan so a pathological rule/input
	// cannot stall a worker (YARA's own internal timeout, seconds).
	ScanTimeout time.Duration // YARAD_SCAN_TIMEOUT (default 10s)

	// Verdict cache. At high volume mail is heavily duplicated (bulk campaigns,
	// one body to N recipients, MTA retries), so caching SHA256(body) -> matches
	// turns most scans into a microsecond lookup. The in-process LRU is always
	// on; RedisURL adds a shared layer across replicas (empty => LRU only).
	CacheTTL    time.Duration // YARAD_CACHE_TTL    (default 600s; 0 disables caching)
	CacheSize   int           // YARAD_CACHE_SIZE   (default 65536 in-memory entries)
	RedisURL    string        // YARAD_REDIS_URL    (empty -> in-process LRU only)
	RedisPrefix string        // YARAD_REDIS_PREFIX (default yara:scan:)

	Verbose   bool // YARAD_VERBOSE
	LogStdout bool // YARAD_LOG_STDOUT — info/access to stdout; errors stay stderr

	Version string // build version string, set by main (not from env); for /version
}

// LoadConfig reads the environment into a Config, applying documented defaults,
// then sanitizes invalid numeric values.
func LoadConfig() *Config {
	c := &Config{
		Host:           envStr("YARAD_HOST", "0.0.0.0"),
		Port:           envInt("YARAD_PORT", 8079),
		BackendTimeout: envDur("YARAD_BACKEND_TIMEOUT", 6),
		MaxConcurrent:  envIntAuto("YARAD_MAX_CONCURRENT", runtime.NumCPU()),
		MaxInflight:    envIntAuto("YARAD_MAX_INFLIGHT", 0), // 0 -> sanitize sets 2×MaxConcurrent
		MaxBody:        envInt64("YARAD_MAX_BODY", 8*1024*1024),
		Token:          envOrFile("YARAD_TOKEN"),
		RulesDir:       envStr("YARAD_RULES_DIR", "/rules"),
		RulesPath:      strings.TrimSpace(os.Getenv("YARAD_RULES")),
		ScanTimeout:    envDur("YARAD_SCAN_TIMEOUT", 10),
		CacheTTL:       envDur("YARAD_CACHE_TTL", 600),
		CacheSize:      envInt("YARAD_CACHE_SIZE", 65536),
		RedisURL:       strings.TrimSpace(os.Getenv("YARAD_REDIS_URL")),
		RedisPrefix:    envStr("YARAD_REDIS_PREFIX", "yara:scan:"),
		Verbose:        envBool("YARAD_VERBOSE"),
		LogStdout:      envBool("YARAD_LOG_STDOUT"),
	}
	c.sanitize()
	return c
}

// sanitize clamps invalid numeric configuration to safe defaults so a bad env
// value cannot disable the service or crash it (negative concurrency panics
// make(chan), an out-of-range port fails to bind). Each clamp is logged.
func (c *Config) sanitize() {
	clamp := func(name string, got, def int) int {
		log.Printf("[yarad] WARNING: invalid %s=%d; using %d", name, got, def)
		return def
	}
	if c.MaxConcurrent < 1 {
		c.MaxConcurrent = clamp("YARAD_MAX_CONCURRENT", c.MaxConcurrent, runtime.NumCPU())
	}
	// The admission gate bounds in-flight buffers and must be at least the scan
	// concurrency (otherwise scan slots could never all be used). Default to 2×
	// so a slow body read or slow Redis L2 lookup can't starve scan slots.
	if c.MaxInflight < c.MaxConcurrent {
		c.MaxInflight = c.MaxConcurrent * 2
	}
	if c.Port < 1 || c.Port > 65535 {
		c.Port = clamp("YARAD_PORT", c.Port, 8079)
	}
	if c.BackendTimeout <= 0 {
		log.Printf("[yarad] WARNING: invalid YARAD_BACKEND_TIMEOUT=%s; using 6s", c.BackendTimeout)
		c.BackendTimeout = 6 * time.Second
	}
	if c.ScanTimeout <= 0 {
		log.Printf("[yarad] WARNING: invalid YARAD_SCAN_TIMEOUT=%s; using 10s", c.ScanTimeout)
		c.ScanTimeout = 10 * time.Second
	}
	if c.MaxBody <= 0 {
		c.MaxBody = 8 * 1024 * 1024
	}
	if c.CacheSize < 1 {
		c.CacheSize = 65536
	}
	if c.CacheTTL < 0 {
		c.CacheTTL = 0 // negative is nonsensical; 0 disables the cache
	}
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

func envInt(name string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil {
		return n
	}
	return def
}

// envIntAuto is envInt that also accepts the literal "auto" (case-insensitive),
// returning the caller's default. Used for YARAD_MAX_CONCURRENT so operators can
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
