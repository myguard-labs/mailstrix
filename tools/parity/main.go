// parity evaluates the reproducible inert corpus against Mailstrix itself.
// In-process execution is restricted to generator bytes. Separate opt-in Docker
// commands isolate Mailstrix and native third-party Office observations.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

const scanEffort = 10

type report struct {
	SchemaVersion       int               `json:"schema_version"`
	Scope               string            `json:"scope"`
	ManifestSHA256      string            `json:"manifest_sha256"`
	Generator           string            `json:"generator"`
	GoVersion           string            `json:"go_version"`
	Platform            string            `json:"platform"`
	BuildRevision       string            `json:"build_revision"`
	BuildModified       bool              `json:"build_modified"`
	RulesFingerprint    string            `json:"rules_fingerprint"`
	Effort              int               `json:"effort"`
	ScanBudgetMS        int64             `json:"scan_budget_ms"`
	ElapsedMS           int64             `json:"elapsed_ms"`
	Feeds               string            `json:"feeds"`
	Summary             summary           `json:"summary"`
	Comparators         map[string]string `json:"comparators"`
	RealWorldPrecision  *float64          `json:"real_world_precision"`
	RealWorldThresholds string            `json:"real_world_thresholds"`
}

func main() { os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr)) }

// Error diagnostics are best effort: the caller already returns a failing exit
// status, including when stderr itself cannot be written.
func printError(w io.Writer, message any) {
	if _, err := fmt.Fprintln(w, message); err != nil {
		return
	}
}

func cli(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printError(stderr, "usage: parity generate|check|run|run-isolated|compare|fetch [options]")
		return 2
	}
	if args[0] == "fetch" {
		return fetchCLI(args[1:], stderr, defaultFetchIO())
	}
	if args[0] == "run-isolated" {
		return isolatedCLI(args[1:], stdout, stderr)
	}
	if args[0] == "isolated-worker-v1" && len(args) == 1 {
		return isolatedWorker(os.Stdin, stdout)
	}
	f := flag.NewFlagSet("parity", flag.ContinueOnError)
	f.SetOutput(stderr)
	out := f.String("out", "", "new directory for generated corpus")
	manifestPath := f.String("manifest", "", "v1 corpus manifest")
	rootPath := f.String("corpus-root", "", "caller-owned corpus directory")
	rules := f.String("rules", "docker/local-rules", "trusted local YARA source directory (run)")
	adapter := f.String("adapter", "both", "opt-in local comparator: oletools, olefy or both (compare only)")
	if err := f.Parse(args[1:]); err != nil {
		return 2
	}
	if f.NArg() != 0 {
		printError(stderr, "unexpected positional arguments")
		return 2
	}
	if args[0] == "generate" {
		if *out == "" {
			printError(stderr, "generate requires -out (new directory)")
			return 2
		}
		fixtures, err := syntheticFixtures()
		if err == nil {
			err = generateFixtures(*out, fixtures)
		}
		if err != nil {
			// Retain the operation and OS cause without publishing a caller's path.
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				err = fmt.Errorf("%s: %w", pathErr.Op, pathErr.Err)
			}
			printError(stderr, fmt.Errorf("generation failed: %w", err))
			return 2
		}
		if _, err := fmt.Fprintf(stderr, "generated %d inert fixtures and manifest v1\n", len(fixtures)); err != nil {
			return 2
		}
		return 0
	}
	if args[0] != "check" && args[0] != "run" && args[0] != "compare" {
		printError(stderr, "unknown command")
		return 2
	}
	if *manifestPath == "" || *rootPath == "" {
		printError(stderr, "check/run/compare require -manifest and -corpus-root")
		return 2
	}
	m, hash, err := loadManifest(*manifestPath)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	root, err := os.OpenRoot(*rootPath)
	if err != nil {
		printError(stderr, "cannot open corpus root")
		return 2
	}
	// Read-only handles have no buffered writes to lose on close.
	defer func() { _ = root.Close() }()
	if args[0] == "compare" {
		return compareCLI(root, m, hash, *adapter, stdout, stderr)
	}
	if args[0] == "check" {
		if err := validateFiles(root, m); err != nil {
			printError(stderr, err)
			return 2
		}
		if _, err := fmt.Fprintf(stderr, "manifest v1: %d sample references verified; no scans performed\n", len(m.Samples)); err != nil {
			return 2
		}
		return 0
	}
	r, err := run(root, m, hash, *rules)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	e := json.NewEncoder(stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(r); err != nil {
		printError(stderr, "report write failed")
		return 2
	}
	if _, err := fmt.Fprintf(stderr, "synthetic-only: %d unique samples, %d duplicates; labelled gate=%t; oletools/olefy/ClamAV not run; real-world precision unmeasured\n", r.Summary.UniqueSamples, r.Summary.Duplicates, r.Summary.Pass); err != nil {
		return 2
	}
	if !r.Summary.Pass {
		return 1
	}
	return 0
}

func loadManifest(path string) (manifest, string, error) {
	// #nosec G304 -- path is the caller's explicit local -manifest input, not a name resolved under a trusted root.
	f, err := os.Open(path)
	if err != nil {
		return manifest{}, "", errors.New("cannot open manifest")
	}
	// This read-only handle has no buffered writes to lose on close.
	defer func() { _ = f.Close() }()
	return decodeManifest(f)
}

// requireSynthetic checks bytes against the compiled generator, not provenance
// assertions supplied by a manifest. In-process run remains synthetic-only.
func requireSynthetic(m manifest) error {
	fixtures, err := syntheticFixtures()
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(fixtures))
	for _, f := range fixtures {
		known[digest(f.data)] = true
	}
	for _, s := range m.Samples {
		if !known[s.SHA256] || s.Partition != "synthetic-clean" && s.Partition != "synthetic-indicator" {
			return errors.New("run accepts only verified generator bytes; external execution requires run-isolated")
		}
	}
	return nil
}

// Share the exact diagnostic policy between synthetic runs and isolated workers.
// Only the returned scanner owns resources; callers close it on successful init.
func newParityScanner(cfg *mailstrix.Config) (*mailstrix.Scanner, *atomic.Bool, error) {
	var diagnostic atomic.Bool
	scanner, err := mailstrix.NewScanner(cfg, func(format string, _ ...any) {
		// Only these exact success notifications are routine at startup.
		// Unknown diagnostics fail closed, including skipped/rejected files.
		switch format {
		case "loaded %d YARA rules from %s (fp=%s, deny-disabled=%d)",
			"PERF-18: marker bundle built: %d rules disabled, %d marker rules active; %d pre-disabled by denylist":
			return
		default:
			diagnostic.Store(true)
		}
	})
	return scanner, &diagnostic, err
}

func run(root *os.Root, m manifest, hash, rules string) (report, error) {
	var r report
	if err := requireSynthetic(m); err != nil {
		return r, err
	}
	// Explicit configuration prevents credentials, live feeds, cache state and
	// caller environment variables from changing the baseline's observations.
	cfg := &mailstrix.Config{RulesDir: rules, ScanTimeout: 8 * time.Second, EffortMax: scanEffort}
	scanner, diagnostic, err := newParityScanner(cfg)
	if err != nil {
		return r, errors.New("cannot load trusted local rules")
	}
	defer scanner.Close()
	if diagnostic.Load() {
		return r, errors.New("rule loading produced diagnostics; complete baseline unavailable")
	}
	started := time.Now()
	observations := make(map[string]observation, len(m.Samples))
	for _, s := range m.Samples {
		b, err := readSample(root, s)
		if err != nil {
			observations[s.SHA256] = observation{Status: "integrity_error"}
			continue
		}
		if _, ok := observations[s.SHA256]; ok {
			continue
		}
		diagnostic.Store(false)
		scanStart := time.Now()
		o := observe(scanner, b, s.Format)
		if time.Since(scanStart) >= cfg.ScanTimeout {
			o = observation{Status: "timeout"}
		} else if o.Status == "ok" && diagnostic.Load() {
			// Some extracted-stream failures only reach the scanner's logger.
			// Retain no raw diagnostics; conservatively withhold the verdict.
			o = observation{Status: "indeterminate"}
		}
		observations[s.SHA256] = o
	}
	r = report{SchemaVersion: 1, Scope: "synthetic indicator regression only", ManifestSHA256: hash, Generator: generatorRevision,
		GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH, BuildRevision: "unknown", RulesFingerprint: scanner.Fingerprint(),
		Effort: cfg.EffortMax, ScanBudgetMS: cfg.ScanTimeout.Milliseconds(), ElapsedMS: time.Since(started).Milliseconds(), Feeds: "disabled", Summary: summarize(m, observations),
		Comparators:         map[string]string{"oletools": "not_run: use opt-in compare command", "olefy": "not_run: use opt-in compare command", "clamav": "not_run: complementary comparator pending"},
		RealWorldThresholds: "unmeasured; no representative labelled external corpus"}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				r.BuildRevision = setting.Value
			case "vcs.modified":
				r.BuildModified = setting.Value == "true"
			}
		}
	}
	return r, nil
}

func observe(scanner *mailstrix.Scanner, b []byte, format string) observation {
	ext := map[string]string{"mime": "eml", "office": "docx", "pdf": "pdf", "html": "html", "image": "png"}[format]
	meta := mailstrix.NewScanMeta("synthetic." + ext)
	meta.Effort = scanEffort
	beforeRaw, beforeExtract := scanner.RawScanErrs(), scanner.ExtractMetrics()
	matches, err := scanner.Scan(b, meta)
	afterExtract := scanner.ExtractMetrics()
	if err != nil || scanner.RawScanErrs() != beforeRaw || afterExtract.Failed != beforeExtract.Failed || afterExtract.Panicked != beforeExtract.Panicked {
		return observation{Status: "error"}
	}
	o := observation{Status: "ok", Matches: make([]symbol, 0, len(matches))}
	for _, match := range matches {
		o.Matches = append(o.Matches, symbol{Namespace: match.Namespace, Rule: match.Rule})
	}
	return o
}
