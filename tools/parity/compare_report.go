package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"time"
)

type nativeSummary struct {
	Statuses          map[string]int      `json:"statuses"`
	Formats           map[string]int      `json:"formats"`
	WithMacros        int                 `json:"with_macros"`
	WithoutMacros     int                 `json:"without_macros"`
	Categories        map[string]int      `json:"category_samples"`
	QualifiedIdentity *comparatorIdentity `json:"qualified_identity"`
}

type comparisonReport struct {
	SchemaVersion     int                       `json:"schema_version"`
	Scope             string                    `json:"scope"`
	ManifestSHA256    string                    `json:"manifest_sha256"`
	Pins              comparatorPins            `json:"pins"`
	PinsSHA256        string                    `json:"pins_sha256"`
	RunnerSHA256      string                    `json:"runner_sha256"`
	AdapterSchema     string                    `json:"adapter_schema"`
	GoVersion         string                    `json:"go_version"`
	Platform          string                    `json:"platform"`
	BuildRevision     string                    `json:"build_revision"`
	BuildModified     bool                      `json:"build_modified"`
	BudgetMS          int64                     `json:"per_container_budget_ms"`
	OlefyMinimumBytes int                       `json:"olefy_minimum_bytes"`
	ElapsedMS         int64                     `json:"elapsed_ms"`
	UniqueSamples     int                       `json:"unique_samples"`
	Duplicates        int                       `json:"duplicates"`
	Adapters          map[string]*nativeSummary `json:"adapters"`
	Agreement         map[string]int            `json:"interface_agreement"`
	Complete          bool                      `json:"all_observations_complete"`
	GroundTruth       string                    `json:"ground_truth"`
}

func selectedAdapters(choice string) []string {
	switch choice {
	case "oletools", "olefy":
		return []string{choice}
	case "both":
		return []string{"oletools", "olefy"}
	default:
		return nil
	}
}

type nativeObserver func(string, []byte) nativeObservation

func compareCorpus(root *os.Root, m manifest, hash string, pins comparatorPins, adapters []string, observe nativeObserver) comparisonReport {
	started := time.Now()
	r := comparisonReport{SchemaVersion: 1, Scope: "native Office macro observations only", ManifestSHA256: hash,
		Pins: pins, PinsSHA256: digest(comparatorPinsJSON), RunnerSHA256: digest([]byte(comparatorRunner)), AdapterSchema: "olevba-native-v1",
		GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH, BudgetMS: comparatorBudget.Milliseconds(), OlefyMinimumBytes: 500,
		Adapters: map[string]*nativeSummary{}, Agreement: map[string]int{}, Complete: len(adapters) > 0,
		GroundTruth: "unmeasured; olefy and direct oletools share one engine; no Mailstrix symbol mapping or independent votes"}
	for _, adapter := range adapters {
		r.Adapters[adapter] = &nativeSummary{Statuses: map[string]int{}, Formats: map[string]int{}, Categories: map[string]int{}}
	}
	r.BuildRevision = "unknown"
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
	// Check every alias before any execution. A bad alias must not be hidden
	// behind deduplication or overwrite a previous sample's valid observation.
	invalid := map[string]bool{}
	for _, s := range m.Samples {
		if _, err := readSample(root, s); err != nil {
			invalid[s.SHA256] = true
		}
	}
	seen := map[string]bool{}
	cleanupUncertain := false
	for _, s := range m.Samples {
		if seen[s.SHA256] {
			r.Duplicates++
			continue
		}
		seen[s.SHA256] = true
		r.UniqueSamples++
		data, err := readSample(root, s)
		results := make([]nativeObservation, 0, len(adapters))
		for _, adapter := range adapters {
			o := nativeObservation{Status: "unsupported"}
			switch {
			case cleanupUncertain:
				o.Status = "not_run"
			case invalid[s.SHA256] || err != nil:
				o.Status = "integrity_error"
			case s.Format == "office" && s.InputUnit == "file":
				o = observe(adapter, data)
			}
			if o.Status == "cleanup_error" {
				cleanupUncertain = true
			}
			results = append(results, o)
			a := r.Adapters[adapter]
			a.Statuses[o.Status]++
			if pins.qualifies(o.Identity) {
				i := o.Identity
				a.QualifiedIdentity = &i
			}
			if o.Status != "ok" {
				r.Complete = false
				continue
			}
			a.Formats[o.Format]++
			if o.HasMacros {
				a.WithMacros++
			} else {
				a.WithoutMacros++
			}
			for _, category := range o.Categories {
				a.Categories[category]++
			}
		}
		if len(results) == 2 {
			left, right := results[0], results[1]
			switch {
			case left.Status != "ok" || right.Status != "ok":
				r.Agreement["excluded"]++
			case left.Format == right.Format && left.HasMacros == right.HasMacros && slices.Equal(left.Categories, right.Categories):
				r.Agreement["equal"]++
			default:
				r.Agreement["different"]++
			}
		}
	}
	r.ElapsedMS = time.Since(started).Milliseconds()
	return r
}

func compareCLI(root *os.Root, m manifest, hash, choice string, stdout, stderr io.Writer) int {
	adapters := selectedAdapters(choice)
	if len(adapters) == 0 {
		printError(stderr, "compare -adapter must be oletools, olefy or both")
		return 2
	}
	pins, err := pinnedComparators()
	if err != nil {
		printError(stderr, "compiled comparator pins invalid")
		return 2
	}
	return compareWithObserver(root, m, hash, pins, adapters, (dockerComparator{pins: pins}).observe, stdout, stderr)
}

func compareWithObserver(root *os.Root, m manifest, hash string, pins comparatorPins, adapters []string, observe nativeObserver, stdout, stderr io.Writer) int {
	r := compareCorpus(root, m, hash, pins, adapters, observe)
	e := json.NewEncoder(stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(r); err != nil {
		printError(stderr, "report write failed")
		return 2
	}
	if _, err := fmt.Fprintf(stderr, "native Office comparison: %d unique samples; complete=%t; one shared engine, ground truth unmeasured\n", r.UniqueSamples, r.Complete); err != nil {
		return 2
	}
	if !r.Complete || r.Agreement["different"] > 0 {
		return 1
	}
	return 0
}
