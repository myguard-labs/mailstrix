package extractionbudget_test

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func TestP17aExtractionRetainedBytesConfig(t *testing.T) {
	const name = "MAILSTRIX_EXTRACTION_RETAINED_BYTES"
	tests := []struct {
		name string
		raw  string
		want int64
		warn bool
	}{
		{name: "default", want: extract.DefaultRetainedBytesLimit},
		{name: "minimum", raw: "1024", want: 1024},
		{name: "maximum", raw: "134217728", want: 134217728},
		{name: "zero", raw: "0", want: extract.DefaultRetainedBytesLimit, warn: true},
		{name: "negative", raw: "-1", want: extract.DefaultRetainedBytesLimit, warn: true},
		{name: "below minimum", raw: "1023", want: extract.DefaultRetainedBytesLimit, warn: true},
		{name: "above maximum", raw: "134217729", want: extract.DefaultRetainedBytesLimit, warn: true},
		{name: "malformed", raw: "2.5MiB", want: extract.DefaultRetainedBytesLimit, warn: true},
		{name: "overflow", raw: "9223372036854775808", want: extract.DefaultRetainedBytesLimit, warn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(name, tt.raw)
			var warnings bytes.Buffer
			old := log.Writer()
			log.SetOutput(&warnings)
			t.Cleanup(func() { log.SetOutput(old) })
			got := ms.LoadConfig().ExtractionRetainedBytes
			if got != tt.want {
				t.Fatalf("ExtractionRetainedBytes=%d want=%d", got, tt.want)
			}
			warned := strings.Contains(warnings.String(), name)
			if warned != tt.warn {
				t.Fatalf("warning presence=%v want=%v; log=%q", warned, tt.warn, warnings.String())
			}
		})
	}
}

func TestP17aOptionsRequestIsolation(t *testing.T) {
	if got := extract.FullOptions(time.Time{}).RetainedBytesLimit; got != extract.DefaultRetainedBytesLimit {
		t.Fatalf("FullOptions retained limit=%d want=%d", got, extract.DefaultRetainedBytesLimit)
	}
	input := []byte("ordinary P17a request")
	explicit := &extract.Options{RetainedBytesLimit: 1024}
	bare := &extract.Options{}
	negative := &extract.Options{RetainedBytesLimit: -1}
	for name, opts := range map[string]*extract.Options{
		"nil": nil, "bare": bare, "explicit": explicit, "negative": negative,
	} {
		t.Run(name, func(t *testing.T) {
			got := extract.ExtractWithOptions(input, opts)
			if len(got.Streams) != 0 || len(got.Markers) != 0 || got.Retained.Bytes() != 0 {
				t.Fatalf("unexpected output change: %+v", got)
			}
		})
	}
	if explicit.RetainedBytesLimit != 1024 || bare.RetainedBytesLimit != 0 || negative.RetainedBytesLimit != -1 {
		t.Fatalf("ExtractWithOptions mutated callers: explicit=%d bare=%d negative=%d",
			explicit.RetainedBytesLimit, bare.RetainedBytesLimit, negative.RetainedBytesLimit)
	}

	shared := &extract.Options{RetainedBytesLimit: 4096}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = extract.ExtractWithOptions(input, shared)
		}()
	}
	wg.Wait()
	if shared.RetainedBytesLimit != 4096 {
		t.Fatalf("concurrent calls mutated shared Options limit=%d", shared.RetainedBytesLimit)
	}
}

func TestP17aGenerationIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p17a.yar"), []byte("rule StableP17a { condition: false }"), 0o600); err != nil {
		t.Fatal(err)
	}
	newScanner := func(limit int64, effort int) *ms.Scanner {
		t.Helper()
		s, err := ms.NewScanner(&ms.Config{
			RulesDir: dir, ExtractionRetainedBytes: limit, EffortMax: effort,
		}, func(string, ...any) {})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	defaulted := newScanner(0, 1)
	explicitDefault := newScanner(extract.DefaultRetainedBytesLimit, 10)
	minimum := newScanner(1024, 1)
	maximum := newScanner(134217728, 10)
	immutableConfig := &ms.Config{RulesDir: dir, ExtractionRetainedBytes: 4096, EffortMax: 10}
	immutable, err := ms.NewScanner(immutableConfig, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(immutable.Close)
	immutableFP := immutable.Fingerprint()
	immutableConfig.ExtractionRetainedBytes = 8192

	if defaulted.Fingerprint() != explicitDefault.Fingerprint() {
		t.Fatal("zero-value Config did not normalize to the calibrated scanner policy")
	}
	if immutable.Fingerprint() != immutableFP {
		t.Fatal("mutating Config after NewScanner changed the immutable policy identity")
	}
	if minimum.Fingerprint() == maximum.Fingerprint() {
		t.Fatal("different retained-byte policies shared one generation fingerprint")
	}
	if before := minimum.Fingerprint(); func() string {
		if err := minimum.Reload(); err != nil {
			t.Fatal(err)
		}
		return minimum.Fingerprint()
	}() != before {
		t.Fatal("stable retained-byte policy changed identity across rule reload")
	}
	if newScanner(1024, 10).Fingerprint() != minimum.Fingerprint() {
		t.Fatal("effort level changed retained-byte policy identity")
	}
	if !strings.HasSuffix(extract.Version, "+retainedlimit+xxh3key") {
		t.Fatalf("extract.Version lacks ordered P17a invalidation token: %q", extract.Version)
	}
}
