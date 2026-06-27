package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/eilandert/rspamd-yarad/internal/yarad"
)

// scanItem is one file's verdict in the JSON output. Err is set (and Matches
// nil) when the file could not be read or scanned; the path still appears so a
// pipeline sees every input accounted for.
type scanItem struct {
	Path    string        `json:"path"`
	Matches []yarad.Match `json:"matches"`
	Err     string        `json:"error,omitempty"`
}

// cmdScan scans files/directories (or stdin) against the compiled rule set in
// process, without starting the HTTP server. It is the local-triage / pipeline
// counterpart to `serve`: point it at a file, a maildir directory (recursed), or
// pipe a single message in on stdin.
//
// Exit codes are scriptable: 0 = all inputs clean, 1 = at least one match, 2 =
// usage / rule-load error. A per-file read/scan error is reported on that file
// (and forces a non-zero overall exit) but does not abort the remaining inputs —
// scanning a maildir shouldn't stop at the first unreadable spool file.
func cmdScan(args []string) int {
	cfg := yarad.LoadConfig()
	cfg.Version = version

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.StringVar(&cfg.RulesDir, "rules-dir", cfg.RulesDir, "dir of *.yar/*.yara to compile (YARAD_RULES_DIR)")
	fs.StringVar(&cfg.RulesPath, "rules", cfg.RulesPath, "precompiled .yac bundle, wins over -rules-dir (YARAD_RULES)")
	fs.DurationVar(&cfg.ScanTimeout, "scan-timeout", cfg.ScanTimeout, "per-scan libyara timeout (YARAD_SCAN_TIMEOUT)")
	fs.Int64Var(&cfg.MaxBody, "max-body", cfg.MaxBody, "max bytes read per file (YARAD_MAX_BODY); larger files are refused, not silently truncated")
	fs.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "writable dir for the live rule bundle (YARAD_CACHE_DIR)")
	fs.StringVar(&cfg.SeedRules, "seed-rules", cfg.SeedRules, "baked read-only .yac used to (re)seed the cache (YARAD_SEED_RULES)")
	asJSON := fs.Bool("json", false, "emit a JSON array of {path,matches,error} instead of text")
	quiet := fs.Bool("quiet", false, "text mode: print only files that matched (skip CLEAN lines)")
	nameOverride := fs.String("filename", "", "override the name used for rule metadata (filename/extension/file_type) for ALL inputs; needed for stdin/piped maildir files that carry no name, so name/extension-keyed rules can still fire")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Re-apply all sanitize clamps after flag overlay so a non-positive flag
	// value (e.g. -scan-timeout=0, -max-body=0) cannot disable safety guards
	// that LoadConfig set on startup. Finalize is idempotent: clamping an
	// already-valid value is a no-op.
	cfg.Finalize()

	logf := func(format string, a ...any) { log.Printf("[yarad] "+format, a...) }

	// Mirror cmdServe: seed the rule cache from YARAD_SEED_RULES when the cache
	// is missing/unreadable, so `yarad scan` works in the Docker final image
	// (YARAD_SEED_RULES + YARAD_CACHE_DIR set, YARAD_RULES unset) without extra
	// operator env. No-op when CacheDir is empty (direct RulesPath/RulesDir use).
	if err := yarad.EnsureCachedRules(cfg, logf); err != nil {
		logf("rules cache unavailable, falling back to baked rules: %v", err)
	}

	scanner, err := yarad.NewScanner(cfg, logf)
	if err != nil {
		log.Printf("[yarad] FATAL: cannot load rules: %v", err)
		return 2
	}

	paths := fs.Args()
	// No path, or an explicit "-", means read one message from stdin — the
	// `yarad scan - < maildir/cur/123:2,S` and `cat msg | yarad scan` cases.
	readStdin := len(paths) == 0
	files := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "-" {
			readStdin = true
			continue
		}
		files = append(files, p)
	}

	var items []scanItem
	matched := false
	hadErr := false
	emit := func(it scanItem) {
		if it.Err != "" {
			hadErr = true
		}
		if len(it.Matches) > 0 {
			matched = true
		}
		if *asJSON {
			items = append(items, it)
			return
		}
		printItem(it, *quiet)
	}

	if readStdin {
		emit(scanItemFromReader("-", os.Stdin, scanner, cfg.MaxBody, *nameOverride))
	}
	for _, p := range files {
		walkPath(p, scanner, cfg.MaxBody, *nameOverride, emit)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if items == nil {
			items = []scanItem{} // marshal as [] not null
		}
		if err := enc.Encode(items); err != nil {
			fmt.Fprintln(os.Stderr, "yarad scan: encode:", err)
			return 2
		}
	}

	switch {
	case hadErr:
		return 2
	case matched:
		return 1
	default:
		return 0
	}
}

// walkPath scans a single path: a regular file directly, or every regular file
// under a directory (recursively). A stat/walk error on the path is reported as
// that path's verdict and does not abort the surrounding scan. nameOverride, when
// non-empty, replaces every input's derived basename for rule metadata.
func walkPath(p string, scanner *yarad.Scanner, maxBody int64, nameOverride string, emit func(scanItem)) {
	info, err := os.Stat(p)
	if err != nil {
		emit(scanItem{Path: p, Err: err.Error()})
		return
	}
	if !info.IsDir() {
		emit(scanFile(p, scanner, maxBody, nameOverride))
		return
	}
	// os.Stat followed a symlink, so a symlinked directory root reaches this
	// branch — but filepath.WalkDir lstats the root, sees the symlink, and (since
	// the callback skips non-regular entries) would exit without descending,
	// silently reporting the tree clean. Resolve the root so WalkDir walks the
	// real directory.
	root := p
	if resolved, rerr := filepath.EvalSymlinks(p); rerr == nil {
		root = resolved
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			emit(scanItem{Path: path, Err: err.Error()})
			return nil // skip this entry, keep walking
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		emit(scanFile(path, scanner, maxBody, nameOverride))
		return nil
	})
	if err != nil {
		emit(scanItem{Path: p, Err: err.Error()})
	}
}

// scanFile reads one file (truncating to maxBody) and scans it, deriving the
// rule metadata (filename/extension/file_type) from the path's basename so
// name/type-keyed rules fire the same way they would in the HTTP path. A
// non-empty nameOverride takes the basename's place.
func scanFile(path string, scanner *yarad.Scanner, maxBody int64, nameOverride string) scanItem {
	// Opening an operator-supplied path is the whole point of `yarad scan`;
	// there is no fixed root to scope to.
	f, err := os.Open(path) // #nosec G304 -- CLI intentionally scans arbitrary paths
	if err != nil {
		return scanItem{Path: path, Err: err.Error()}
	}
	defer f.Close()
	name := nameOverride
	if name == "" {
		name = filepath.Base(path)
	}
	return scanItemFromReader(path, f, scanner, maxBody, name)
}

// scanItemFromReader reads up to maxBody bytes from r and scans them. name is the
// basename used for scan metadata (empty for stdin, where no filename is known).
//
// When maxBody > 0, the function reads up to maxBody+1 bytes to detect overrun.
// If the input exceeds maxBody, the item is returned as an error (not scanned as
// clean) so the caller's hadErr path forces exit 2. Exactly-at-cap inputs scan
// normally. This mirrors the overrun detection in the yarad-scan client (PR #246).
func scanItemFromReader(path string, r io.Reader, scanner *yarad.Scanner, maxBody int64, name string) scanItem {
	var buf []byte
	if maxBody > 0 {
		// Read one byte beyond the cap so we can distinguish "exactly at cap" from
		// "exceeds cap" without consuming the whole stream.
		limited, err := io.ReadAll(io.LimitReader(r, maxBody+1))
		if err != nil {
			return scanItem{Path: path, Err: err.Error()}
		}
		if int64(len(limited)) > maxBody {
			return scanItem{Path: path, Err: fmt.Sprintf("oversized: exceeds max-body %d bytes; not scanned", maxBody)}
		}
		buf = limited
	} else {
		var err error
		buf, err = io.ReadAll(r)
		if err != nil {
			return scanItem{Path: path, Err: err.Error()}
		}
	}
	meta := yarad.NewScanMeta(name)
	meta.RawKey = yarad.StreamDedupKey(buf)
	matches, err := scanner.Scan(buf, sha256.Sum256(buf), meta)
	if err != nil {
		return scanItem{Path: path, Err: err.Error()}
	}
	return scanItem{Path: path, Matches: matches}
}

// printItem renders one file's verdict in text mode. Clean files print a single
// CLEAN line (suppressed under -quiet); a match prints one line per rule with its
// source namespace so the operator sees WHICH ruleset fired.
func printItem(it scanItem, quiet bool) {
	switch {
	case it.Err != "":
		fmt.Printf("%s: ERROR %s\n", it.Path, it.Err)
	case len(it.Matches) == 0:
		if !quiet {
			fmt.Printf("%s: CLEAN\n", it.Path)
		}
	default:
		for _, m := range it.Matches {
			if m.Namespace != "" {
				fmt.Printf("%s: MATCH %s (%s)\n", it.Path, m.Rule, m.Namespace)
			} else {
				fmt.Printf("%s: MATCH %s\n", it.Path, m.Rule)
			}
		}
	}
}
