package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

type isolatedReport struct {
	Schema             string           `json:"schema"`
	ManifestSHA256     string           `json:"manifest_sha256"`
	ImageID            string           `json:"local_image_id"`
	Worker             isolatedIdentity `json:"worker"`
	Runtime            isolatedRuntime  `json:"runtime"`
	RuntimeSHA256      string           `json:"runtime_sha256"`
	HostGoVersion      string           `json:"orchestrator_go_version"`
	Envelope           string           `json:"envelope"`
	EnvelopeSHA256     string           `json:"envelope_sha256"`
	Effort             int              `json:"effort"`
	ScanBudgetMS       int64            `json:"scan_budget_ms"`
	HostBudgetMS       int64            `json:"host_budget_ms"`
	ElapsedMS          int64            `json:"elapsed_ms"`
	Summary            summary          `json:"summary"`
	Complete           bool             `json:"all_observations_complete"`
	RealWorldPrecision *float64         `json:"real_world_precision"`
	Limits             string           `json:"interpretation_limits"`
}

const isolatedEnvelope = "docker-local-cgroup2-v1;linux/amd64;network=none;readonly;uid=65534:65534;cap-drop=ALL;no-new-privileges;seccomp=builtin;no-host-mounts;tmpfs=64MiB;memory+swap=512MiB;pids=64;cpu=1;output=1MiB/stream;wall=30s;cleanup=5s+5s;input=16MiB;feeds/cache/guessing=disabled"

func isolatedCorpus(root *os.Root, m manifest, hash string, d isolatedDocker, observe func(sample, []byte) observation) isolatedReport {
	started := time.Now()
	r := isolatedReport{Schema: "mailstrix-isolated-v1", ManifestSHA256: hash, ImageID: d.image, Worker: d.identity, HostGoVersion: runtime.Version(), Envelope: isolatedEnvelope, EnvelopeSHA256: digest([]byte(isolatedEnvelope)), Effort: scanEffort, ScanBudgetMS: 8000, HostBudgetMS: isolatedBudget.Milliseconds(), Complete: true,
		Limits: "explicit symbol labels only; real-world precision and thresholds unmeasured; local image and worker checksums are identity, not source-to-binary attestation; kernel and Docker daemon trusted"}
	r.Runtime = d.runtime
	// This concrete string/slice structure has no fallible JSON marshaler.
	runtimeJSON, _ := json.Marshal(d.runtime)
	r.RuntimeSHA256 = digest(runtimeJSON)
	invalid := make(map[string]bool)
	// Validate every alias before deduplicating or giving the first sample to a parser.
	for _, s := range m.Samples {
		if _, err := readSample(root, s); err != nil {
			invalid[s.SHA256] = true
		}
	}
	observations := make(map[string]observation, len(m.Samples))
	stopped := false
	for _, s := range m.Samples {
		if _, ok := observations[s.SHA256]; ok {
			continue
		}
		o := observation{Status: "not_run"}
		if !stopped {
			data, err := readSample(root, s)
			if invalid[s.SHA256] || err != nil {
				o.Status = "integrity_error"
			} else {
				o = observe(s, data)
			}
		}
		observations[s.SHA256] = o
		if o.Status != "ok" {
			r.Complete = false
		}
		if o.Status == "cleanup_error" || o.Status == "create_uncertain" || o.Status == "setup_error" || o.Status == "identity_error" {
			stopped = true
		}
	}
	r.Summary = summarize(m, observations)
	r.ElapsedMS = time.Since(started).Milliseconds()
	return r
}

func isolatedCLI(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("run-isolated", flag.ContinueOnError)
	f.SetOutput(stderr)
	path := f.String("manifest", "", "v1 corpus manifest")
	rootPath := f.String("corpus-root", "", "caller-owned corpus directory")
	image := f.String("engine-image", "", "trusted immutable local sha256 image ID")
	if f.Parse(args) != nil {
		return 2
	}
	if f.NArg() != 0 || *path == "" || *rootPath == "" || *image == "" {
		printError(stderr, "run-isolated requires -manifest, -corpus-root and -engine-image")
		return 2
	}
	m, hash, err := loadManifest(*path)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	root, err := os.OpenRoot(*rootPath)
	if err != nil {
		printError(stderr, "cannot open corpus root")
		return 2
	}
	defer func() { _ = root.Close() }()
	d := isolatedDocker{image: *image, diagnostics: stderr}
	if err := d.setup(); err != nil {
		printError(stderr, err)
		return 2
	}
	r := isolatedCorpus(root, m, hash, d, d.observe)
	return writeIsolatedReport(r, stdout, stderr)
}

func writeIsolatedReport(r isolatedReport, stdout, stderr io.Writer) int {
	e := json.NewEncoder(stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(r); err != nil {
		printError(stderr, "report write failed")
		return 2
	}
	if _, err := fmt.Fprintf(stderr, "isolated Mailstrix: %d unique samples, %d duplicates; complete=%t; labelled gate=%t; real-world precision unmeasured\n", r.Summary.UniqueSamples, r.Summary.Duplicates, r.Complete, r.Summary.Pass); err != nil {
		return 2
	}
	if !r.Complete || !r.Summary.Pass {
		return 1
	}
	return 0
}
