package ci

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yara "github.com/hillu/go-yara/v4"
	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

const markerBundleLogFormat = "PERF-18: marker bundle built: %d total rules in separate compiled object; %d dependency rules retained, %d marker-tagged rules retained; safely pre-disabled denied rules: %d"
const markerArtifactLogFormat = "PERF-18: marker artifact loaded: %d total rules in separate compiled object (main ruleset: %d rules; deny policy applied)"

func TestP13MarkerBundleLogContract(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "internal", "mailstrix", "scanner.go"))
	if err != nil {
		t.Fatal(err)
	}
	quoted := fmt.Sprintf("%q", markerBundleLogFormat)
	if !strings.Contains(string(source), quoted) {
		t.Fatalf("fallback full-bundle log no longer reports retained dependency and marker counts: want %s", quoted)
	}
	parity, err := os.ReadFile(filepath.Join("..", "tools", "parity", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(parity), quoted) {
		t.Fatalf("parity scanner does not accept the exact fallback full-bundle success log: want %s", quoted)
	}
	if strings.Contains(string(source), "producing a tiny") || strings.Contains(string(source), "marker rules active") || strings.Contains(string(source), "eligible rules pre-disabled by denylist") {
		t.Fatal("legacy full-bundle description again implies a small allocation, active denied markers, or additive deny counts")
	}
	artifactQuoted := fmt.Sprintf("%q", markerArtifactLogFormat)
	if !strings.Contains(string(source), artifactQuoted) {
		t.Fatalf("native artifact log does not label artifact and main totals separately: want %s", artifactQuoted)
	}
}

func TestReloadMarkerUsesPreparedMain(t *testing.T) {
	for _, compiled := range []bool{false, true} {
		t.Run(fmt.Sprintf("compiled=%v", compiled), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "reload.yar")
			source := `private rule Dependency : marker { condition: true }
rule Marker : marker { strings: $a = "EXT-MISMATCH" condition: $a and Dependency }
rule Plain { strings: $a = "harmless" condition: $a }`
			reloadWrite(t, path, source)
			cfg := &ms.Config{RulesDir: dir}
			if compiled {
				c, err := yara.NewCompiler()
				if err != nil {
					t.Fatal(err)
				}
				defer c.Destroy()
				for name, value := range map[string]any{"filename": "", "extension": "", "file_type": "", "filepath": "", "filetype": "", "VBA": false, "owner": ""} {
					if err := c.DefineVariable(name, value); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.AddString(source, "reload.yar"); err != nil {
					t.Fatal(err)
				}
				r, err := c.GetRules()
				if err != nil {
					t.Fatal(err)
				}
				defer r.Destroy()
				path = filepath.Join(dir, "reload.yac")
				cfg.RulesPath = path
				if err := r.Save(path); err != nil {
					t.Fatal(err)
				}
			}
			warned := false
			// Main acquisition and its content hash have completed at this log. Deleting
			// the source proves marker creation uses exactly that prepared native object.
			s, err := ms.NewScanner(cfg, func(format string, _ ...any) {
				if strings.HasPrefix(format, "loaded %d YARA rules from") {
					if err := os.Remove(path); err != nil {
						t.Error(err)
					}
				}
				warned = warned || strings.Contains(format, "marker bundle build failed")
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if warned {
				t.Fatal("marker builder reopened source after main preparation")
			}
			matches, err := s.Scan([]byte(`{\rtf1 harmless}`), ms.ScanMeta{Extension: ".jpg"})
			if err != nil {
				t.Fatal(err)
			}
			names := map[string]bool{}
			for _, m := range matches {
				names[m.Rule] = true
			}
			if !names["Marker"] || !names["Plain"] || s.MarkerChannelScans() == 0 {
				t.Fatalf("prepared rules lost content or marker matches: %v", matches)
			}
			matches, err = s.Scan([]byte("harmless EXT-MISMATCH"), ms.ScanMeta{})
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 1 || matches[0].Rule != "Plain" {
				t.Fatalf("raw marker collision or main pruning: %v", matches)
			}
			fingerprint := s.Fingerprint()
			// A later malformed source/.yac must fail the main reload, preserving the
			// previously published main/marker generation and its cache identity.
			reloadWrite(t, path, "not a valid rule bundle")
			if err := s.Reload(); err == nil {
				t.Fatal("malformed main source unexpectedly loaded")
			}
			if s.Fingerprint() != fingerprint {
				t.Fatal("failed main reload changed generation fingerprint")
			}
			matches, err = s.Scan([]byte(`{\rtf1 harmless}`), ms.ScanMeta{Extension: ".jpg"})
			if err != nil {
				t.Fatal(err)
			}
			names = map[string]bool{}
			for _, m := range matches {
				names[m.Rule] = true
			}
			if !names["Marker"] || !names["Plain"] {
				t.Fatalf("failed reload lost old verdict: %v", matches)
			}
		})
	}
}

// BenchmarkReloadMarkerBundle measures the complete production reload, including
// per-file validation, hashing and publication. Compare with the parent commit.
func BenchmarkReloadMarkerBundle(b *testing.B) {
	dir := b.TempDir()
	var source strings.Builder
	for i := range 1000 {
		tag := ""
		if i%20 == 0 {
			tag = " : marker"
		}
		fmt.Fprintf(&source, "rule Bench%d%s { strings: $s = \"BENCH-MARKER-%08d\" condition: $s }\n", i, tag, i)
	}
	if err := os.WriteFile(filepath.Join(dir, "bench.yar"), []byte(source.String()), 0600); err != nil {
		b.Fatal(err)
	}
	s, err := ms.NewScanner(&ms.Config{RulesDir: dir}, func(string, ...any) {})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	b.ReportAllocs()
	for b.Loop() {
		if err := s.Reload(); err != nil {
			b.Fatal(err)
		}
	}
}
