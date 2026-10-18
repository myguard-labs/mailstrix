package mailstrix

import (
	"fmt"
	yara "github.com/hillu/go-yara/v4"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cloneFixture = `
global rule Gate : marker { condition: true }
private rule Dependency { condition: true }
rule AllowedMarker : marker { condition: Dependency }
rule IndependentMarker : marker { condition: true }
rule DeniedMarker : marker { condition: true }
rule AllowedPlain { condition: Dependency }
rule DeniedPlain { condition: true }
rule DormantMarker : marker { condition: true }
`

// An unbound source/.yac uses main directly, without a second compilation or
// serialization. Validate and compile the source exactly once per reload.
func TestReloadMarkerCompileCount(t *testing.T) {
	for _, compiled := range []bool{false, true} {
		t.Run(fmt.Sprintf("compiled=%v", compiled), func(t *testing.T) {
			mainDir := writeRules(t, cloneFixture)
			bigDir := writeRules(t, `rule BigKeep { condition: true }`)
			if e := os.WriteFile(filepath.Join(mainDir, "bad.yar"), []byte("rule broken {"), 0600); e != nil {
				t.Fatal(e)
			}
			cfg := &Config{RulesDir: mainDir, BigFileRules: bigDir, BigFileThreshold: 1}
			if compiled {
				for _, entry := range []struct {
					dir string
					dst *string
				}{{mainDir, &cfg.RulesPath}, {bigDir, &cfg.BigFileRules}} {
					r, e := compileDir(entry.dir, func(string, ...any) {})
					if e != nil {
						t.Fatal(e)
					}
					path := filepath.Join(entry.dir, "bundle.yac")
					if e = r.Save(path); e != nil {
						t.Fatal(e)
					}
					r.Destroy()
					*entry.dst = path
				}
			}
			compile, validate, serialize := compileRuleFiles, validateRuleFile, serializeRules
			calls := map[string]int{}
			validations, serializations := 0, 0
			compileRuleFiles = func(dir string, files []string, logf func(string, ...any)) (*yara.Rules, error) {
				calls[dir]++
				return compile(dir, files, logf)
			}
			validateRuleFile = func(path string) error { validations++; return validate(path) }
			serializeRules = func(r *yara.Rules, w io.Writer) error { serializations++; return serialize(r, w) }
			t.Cleanup(func() { compileRuleFiles = compile; validateRuleFile = validate; serializeRules = serialize })
			s, e := NewScanner(cfg, func(string, ...any) {})
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			for reload := 1; reload <= 2; reload++ {
				want := reload
				if compiled {
					want = 0
				}
				if calls[mainDir] != want || calls[bigDir] != want || validations != 3*want || serializations != 0 {
					t.Fatalf("main/big compilations=%v validations=%d serialization=%d want=%d", calls, validations, serializations, want)
				}
				if s.markerRules.Load() != nil || s.markerContent != "" {
					t.Fatal("unbound source published an unauthorized marker object")
				}
				if got := ruleNames(markerArtifactMatches(t, s)); !strings.Contains(got, "AllowedMarker") || !strings.Contains(got, "IndependentMarker") {
					t.Fatalf("full-main fallback lost dependency marker detections: %s", got)
				}
				if got := ruleNames(scanOneRules(t, s.bigRules.Load(), []byte("fixture"))); got != "[BigKeep]" {
					t.Fatalf("marker selection changed big set: %s", got)
				}
				if reload == 1 {
					if e := s.Reload(); e != nil {
						t.Fatal(e)
					}
				}
			}
		})
	}
}
func TestReloadMarkerCloneNativeParity(t *testing.T) {
	for _, compiled := range []bool{false, true} {
		for _, gate := range []bool{false, true} {
			t.Run(fmt.Sprintf("compiled=%v/gate=%v", compiled, gate), func(t *testing.T) {
				dir := writeRules(t, strings.Replace(cloneFixture, "Gate : marker { condition: true }", fmt.Sprintf("Gate : marker { condition: %v }", gate), 1))
				deny := map[string]struct{}{"gate": {}, "dependency": {}, "deniedmarker": {}, "deniedplain": {}}
				cfg := &Config{RulesDir: dir, RuleDenylist: deny}
				if compiled {
					r, e := compileDir(dir, func(string, ...any) {})
					if e != nil {
						t.Fatal(e)
					}
					for _, rule := range r.GetRules() {
						if rule.Identifier() == "DormantMarker" {
							rule.Disable()
						}
					}
					cfg.RulesPath = filepath.Join(dir, "main.yac")
					if e = r.Save(cfg.RulesPath); e != nil {
						t.Fatal(e)
					}
					r.Destroy()
				}
				s, e := NewScanner(cfg, func(string, ...any) {})
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close()
				if s.markerRules.Load() != nil {
					t.Fatal("unbound input did not select full-main fallback")
				}
				names := ruleNames(markerArtifactMatches(t, s))
				if gate {
					for _, name := range []string{"AllowedMarker", "IndependentMarker", "AllowedPlain"} {
						if !strings.Contains(names, name) {
							t.Fatalf("fallback disabled retained dependency/global: %s", names)
						}
					}
					if strings.Contains(names, "Denied") {
						t.Fatalf("deny policy lost: %s", names)
					}
					if strings.Contains(names, "DormantMarker") == compiled {
						t.Fatalf("original compiled disabled marker state changed: %s", names)
					}
				} else if names != "[]" {
					t.Fatalf("false global gate matched: %s", names)
				}
			})
		}
	}
}
func TestReloadMarkerUntaggedGlobalAndEmpty(t *testing.T) {
	for _, marker := range []bool{false, true} {
		source := `global rule Gate { condition: true } rule Plain { condition: true }`
		if marker {
			source += ` rule Marker : marker { strings: $a="EXT-MISMATCH" condition: $a }`
		}
		s := newScannerBudget(t, writeRules(t, source), loadInsensitiveScanTimeout)
		defer s.Close()
		if s.markerRules.Load() != nil {
			t.Fatal("unbound global source did not use fallback")
		}
		names := ruleNames(markerArtifactMatches(t, s))
		if strings.Contains(names, "Marker") != marker || !strings.Contains(names, "Plain") {
			t.Fatalf("untagged global/empty fallback detections: %s", names)
		}
	}
}
