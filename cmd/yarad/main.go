// Command yarad is the standalone YARA scanner backend for rspamd. rspamd has
// no native YARA module (as of 4.1.0), so the yara.lua plugin POSTs message or
// MIME-part bytes here over HTTP and yarad scans them against a compiled YARA
// rule set, returning the matched rule names. It mirrors the gozer backend's
// shape: one authenticated HTTP endpoint (/scan), /health and /metrics, every
// option settable by env var or CLI flag, and a health subcommand for the
// distroless HEALTHCHECK (no shell or curl in the image).
//
// Usage:
//
//	yarad [serve] [flags]      run the HTTP backend on YARAD_HOST:YARAD_PORT
//	yarad scan [flags] [path…] scan files/dirs (or stdin) locally, print matches
//	yarad check-rules [flags]  compile the rule set, report count, exit non-zero on fail
//	yarad extract [flags][path] dump what the extractor carves from a file (no scan)
//	yarad health               probe the local /health endpoint (HEALTHCHECK)
//	yarad version              print the version
//
// `yarad scan` compiles the same rule set in-process and scans without the HTTP
// server, so it works for one-off triage and pipelines, e.g.
//
//	yarad scan suspicious.doc                 # one file
//	yarad scan /var/mail/cur                  # a maildir (recursed)
//	yarad scan - < /var/mail/cur/123:2,S      # a maildir file on stdin
//	cat msg.eml | yarad scan                  # no path => stdin too
//
// SIGHUP recompiles the rule set without dropping the listener, so a rules
// refresh (new image layer bind-mounted, or an operator edit) takes effect with
// `docker kill -s HUP yarad`.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/eilandert/rspamd-yarad/internal/yarad"
)

var version = "dev"

// libyaraVersion is the libyara release yarad was built/linked against, injected
// at build time via -ldflags "-X main.libyaraVersion=<v>" from the Dockerfile's
// YARA_VERSION. A compiled .yac only loads on a matching libyara, so `fetch-rules`
// compares this against a downloaded bundle's manifest and refuses a mismatch.
// Empty (dev builds) disables the skew check.
var libyaraVersion = ""

func main() {
	log.SetFlags(0) // journald adds its own timestamps
	os.Exit(run(os.Args[1:]))
}

// printUsage lists the subcommands. Per-subcommand flags are shown by passing
// -h to that subcommand (each uses a flag.FlagSet).
func printUsage(w *os.File) {
	fmt.Fprint(w, `yarad — YARA scanning backend for rspamd

usage: yarad <command> [flags]

commands:
  serve        run the HTTP backend (/scan, /metrics, /health) — the default
  scan         scan files/dirs/stdin against the rules in-process
  fetch-rules  download an updated compiled rule bundle into the cache
  check-rules  compile the rules, print the count, exit non-zero on failure
  extract      dump what the container extractor carves from a file (no scan)
  info         print build, libyara, and loaded-rules-bundle identity
  health       probe the local /health endpoint (container HEALTHCHECK)
  version      print the version

Run "yarad <command> -h" for that command's flags.
`)
}

func run(args []string) int {
	cmd := "serve"
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version", "-v":
			fmt.Println("yarad", version)
			return 0
		case "help", "--help", "-h":
			// Caught here, before the leading-dash guard below, so `yarad -h` /
			// `--help` show the command list (exit 0) instead of falling through to
			// the serve FlagSet's own help.
			printUsage(os.Stdout)
			return 0
		}
		if !strings.HasPrefix(args[0], "-") {
			cmd, args = args[0], args[1:]
		}
	}
	switch cmd {
	case "serve":
		return cmdServe(args)
	case "scan":
		return cmdScan(args)
	case "check-rules":
		return cmdCheckRules(args)
	case "extract":
		return cmdExtract(args)
	case "fetch-rules":
		return cmdFetchRules(args)
	case "info":
		return cmdInfo(args)
	case "health":
		return cmdHealth()
	case "help":
		printUsage(os.Stdout)
		return 0
	default:
		printUsage(os.Stderr)
		return 2
	}
}

// cmdHealth probes the local /health endpoint and exits 0/1. It is the
// container HEALTHCHECK in the distroless image (no shell/curl); it reads the
// same YARAD_HOST/YARAD_PORT the server binds.
func cmdHealth() int {
	cfg := yarad.LoadConfig()
	host := cfg.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + host + ":" + strconv.Itoa(cfg.Port) + "/health"
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "health:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "health: status", resp.StatusCode)
		return 1
	}
	return 0
}

// cmdServe loads config from the environment, overlays CLI flags
// (flag > env > default), compiles the rule set, wires a SIGHUP reloader, and
// serves until the process is signalled.
func cmdServe(args []string) int {
	cfg := yarad.LoadConfig()
	cfg.Version = version // build identity, surfaced on /version

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.StringVar(&cfg.Host, "host", cfg.Host, "HTTP bind host (YARAD_HOST); serves /scan,/metrics,/health")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "HTTP bind port (YARAD_PORT, default 8079)")
	fs.DurationVar(&cfg.BackendTimeout, "backend-timeout", cfg.BackendTimeout, "per-request backend budget (YARAD_BACKEND_TIMEOUT)")
	fs.DurationVar(&cfg.ScanTimeout, "scan-timeout", cfg.ScanTimeout, "per-scan libyara timeout (YARAD_SCAN_TIMEOUT)")
	fs.IntVar(&cfg.MaxConcurrent, "max-concurrent", cfg.MaxConcurrent, "max in-flight scans (YARAD_MAX_CONCURRENT)")
	fs.Int64Var(&cfg.MaxBody, "max-body", cfg.MaxBody, "max request body bytes (YARAD_MAX_BODY)")
	fs.StringVar(&cfg.Token, "token", cfg.Token, "shared-secret for /scan (YARAD_TOKEN[_FILE])")
	fs.StringVar(&cfg.RulesDir, "rules-dir", cfg.RulesDir, "dir of *.yar/*.yara to compile (YARAD_RULES_DIR)")
	fs.StringVar(&cfg.RulesPath, "rules", cfg.RulesPath, "precompiled .yac bundle, wins over -rules-dir (YARAD_RULES)")
	fs.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "writable dir for the live rule bundle; seeded from -seed-rules when empty/unreadable (YARAD_CACHE_DIR)")
	fs.StringVar(&cfg.SeedRules, "seed-rules", cfg.SeedRules, "baked read-only .yac used to (re)seed the cache (YARAD_SEED_RULES)")
	fs.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "per-request logging (YARAD_VERBOSE)")
	fs.BoolVar(&cfg.LogStdout, "log-stdout", cfg.LogStdout, "info/access logs to stdout; errors stay stderr (YARAD_LOG_STDOUT)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	logf := func(format string, a ...any) { log.Printf("[yarad] "+format, a...) }

	// Seed-on-startup / self-heal: when a writable cache dir is configured, serve
	// rules from it and reseed from the baked read-only bundle when the cache is
	// missing or unreadable (fresh deploy / wiped bindmount). No-op when no cache
	// dir is set. A seeding failure is not fatal here — fall back to whatever
	// RulesPath/RulesDir NewScanner can load, so a misconfigured cache never takes
	// the scanner fully offline.
	if err := yarad.EnsureCachedRules(cfg, logf); err != nil {
		logf("rules cache unavailable, falling back to baked rules: %v", err)
	}

	scanner, err := yarad.NewScanner(cfg, logf)
	if err != nil {
		log.Printf("[yarad] FATAL: cannot load rules: %v", err)
		return 1
	}
	// Stop the abuse.ch feed refresher goroutines on any exit path (nil-safe
	// when the feeds are disabled), so they don't outlive a graceful shutdown.
	defer scanner.Close()
	if cfg.Canary {
		logf("CANARY MODE: all matches tagged yarad_canary=1 (shadow/observe-only)")
	}

	srv := yarad.NewServer(cfg, scanner)

	// SIGHUP -> recompile rules in place, then flush the verdict cache (old
	// verdicts were computed against the previous rule set). A failed reload
	// keeps the old set active and leaves the cache intact (Reload logs and
	// returns; the listener never drops).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			logf("SIGHUP: reloading rules")
			if err := scanner.Reload(); err != nil {
				logf("reload failed: %v", err)
				continue
			}
			scanner.ReloadDenylist()
			srv.FlushCache()
		}
	}()

	// Graceful shutdown on SIGTERM/SIGINT: stop accepting new scans (/ready 503s)
	// and drain in-flight scans for a bounded window before exiting — important
	// during rolling image/rule updates so a scan in progress isn't dropped. The
	// drain budget covers the longest a single scan can run (ScanTimeout) plus a
	// little slack.
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.ListenAndServe() }()

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-srvErr:
		if err != nil && err != http.ErrServerClosed {
			log.Printf("[yarad] server error: %v", err)
			return 1
		}
		return 0
	case sig := <-term:
		logf("%s: draining (graceful shutdown)", sig)
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout+5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("[yarad] shutdown error: %v", err)
			return 1
		}
		<-srvErr // ListenAndServe returns http.ErrServerClosed once drained
		return 0
	}
}
