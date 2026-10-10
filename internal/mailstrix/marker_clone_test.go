package mailstrix

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"weak"

	yara "github.com/hillu/go-yara/v4"
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

func cloneNativeNames(t *testing.T, r *yara.Rules) []string {
	t.Helper()
	names := matchRuleNames(scanOneRules(t, r, []byte("harmless fixture")))
	sort.Strings(names)
	return names
}

func TestReloadMarkerCompileCount(t *testing.T) {
	for _, compiled := range []bool{false, true} {
		t.Run(fmt.Sprintf("compiled=%v", compiled), func(t *testing.T) {
			mainDir := writeRules(t, cloneFixture)
			bigDir := writeRules(t, `rule BigKeep { condition: true }`)
			// Invalid files must still be validated and skipped once, before compilation.
			if err := os.WriteFile(filepath.Join(mainDir, "bad.yar"), []byte("rule broken {"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &Config{RulesDir: mainDir, BigFileRules: bigDir, BigFileThreshold: 1}
			if compiled {
				for _, entry := range []struct {
					dir string
					dst *string
				}{{mainDir, &cfg.RulesPath}, {bigDir, &cfg.BigFileRules}} {
					r, err := compileDir(entry.dir, func(string, ...any) {})
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(entry.dir, "bundle.yac")
					if err := r.Save(path); err != nil {
						t.Fatal(err)
					}
					r.Destroy()
					*entry.dst = path
				}
			}
			compile, validate := compileRuleFiles, validateRuleFile
			calls := map[string]int{}
			validations := 0
			compileRuleFiles = func(dir string, files []string, logf func(string, ...any)) (*yara.Rules, error) {
				calls[dir]++
				return compile(dir, files, logf)
			}
			validateRuleFile = func(path string) error { validations++; return validate(path) }
			t.Cleanup(func() { compileRuleFiles = compile; validateRuleFile = validate })
			s, err := NewScanner(cfg, func(string, ...any) {})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for reload := 1; reload <= 2; reload++ {
				want := reload
				if compiled {
					want = 0
				}
				if calls[mainDir] != want || calls[bigDir] != want {
					t.Fatalf("production source compilations: main=%d big=%d, want %d each", calls[mainDir], calls[bigDir], want)
				}
				if validations != 3*want {
					t.Fatalf("validation calls=%d want %d", validations, 3*want)
				}
				if s.markerRules.Load() == nil || s.markerRules.Load() == s.rules.Load() || s.markerRules.Load() == s.bigRules.Load() {
					t.Fatal("marker bundle missing or aliases main/big rules")
				}
				if got := cloneNativeNames(t, s.bigRules.Load()); !reflect.DeepEqual(got, []string{"BigKeep"}) {
					t.Fatalf("marker pruning affected big rules: %v", got)
				}
				if reload == 1 {
					if err := s.Reload(); err != nil {
						t.Fatal(err)
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
					r, err := compileDir(dir, func(string, ...any) {})
					if err != nil {
						t.Fatal(err)
					}
					for _, rule := range r.GetRules() {
						if rule.Identifier() == "DormantMarker" {
							rule.Disable()
						}
					}
					cfg.RulesPath = filepath.Join(dir, "main.yac")
					if err := r.Save(cfg.RulesPath); err != nil {
						t.Fatal(err)
					}
					r.Destroy()
				}
				s, err := NewScanner(cfg, func(string, ...any) {})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				main, marker := s.rules.Load(), s.markerRules.Load()
				if marker == nil || marker == main {
					t.Fatal("marker clone missing or shares Rules ownership")
				}
				reference, err := buildMarkerBundle(cfg.RulesPath, cfg.RulesDir, deny, func(string, ...any) {})
				if err != nil {
					t.Fatal(err)
				}
				defer reference.Destroy()
				got, want := cloneNativeNames(t, marker), cloneNativeNames(t, reference)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("clone/recompile native parity: got %v want %v", got, want)
				}
				if gate {
					// The legacy builder disables untagged private dependencies; retain
					// that behavior while an independent marker proves the set is live.
					expected := []string{"Gate", "IndependentMarker"}
					if !compiled {
						expected = []string{"DormantMarker", "Gate", "IndependentMarker"}
					}
					if !reflect.DeepEqual(got, expected) {
						t.Fatalf("marker dependency or deny state changed: %v want %v", got, expected)
					}
					names := cloneNativeNames(t, main)
					if !strings.Contains(strings.Join(names, ","), "AllowedPlain") || strings.Contains(strings.Join(names, ","), "Denied") {
						t.Fatalf("marker pruning changed main rules or lost native deny: %v", names)
					}
				} else if len(got) != 0 {
					t.Fatalf("false global gate matched: %v", got)
				}
				// Native destruction of the clone must not invalidate the main allocation.
				before := cloneNativeNames(t, main)
				s.markerRules.Store(nil)
				observedRuleGenerations.destroy(marker, weak.Make(marker))
				if got := cloneNativeNames(t, main); !reflect.DeepEqual(got, before) {
					t.Fatalf("destroying marker changed main: %v want %v", got, before)
				}
			})
		}
	}
}

func TestReloadMarkerCloneFailure(t *testing.T) {
	for _, compiled := range []bool{false, true} {
		for _, retained := range []bool{false, true} {
			for _, readFailure := range []bool{false, true} {
				t.Run(fmt.Sprintf("compiled=%v/retained=%v/read=%v", compiled, retained, readFailure), func(t *testing.T) {
					dir := writeRules(t, `rule Marker : marker { strings: $a = "EXT-MISMATCH" condition: $a }
rule Plain { condition: true }`)
					cfg := &Config{RulesDir: dir}
					if compiled {
						r, err := compileDir(dir, func(string, ...any) {})
						if err != nil {
							t.Fatal(err)
						}
						cfg.RulesPath = filepath.Join(dir, "main.yac")
						if err := r.Save(cfg.RulesPath); err != nil {
							t.Fatal(err)
						}
						r.Destroy()
					}
					original := serializeRules
					t.Cleanup(func() { serializeRules = original })
					inject := func() {
						serializeRules = func(_ *yara.Rules, w io.Writer) error {
							if readFailure {
								_, err := w.Write([]byte("truncated"))
								return err
							}
							return errors.New("injected write failure")
						}
					}
					var log strings.Builder
					logf := func(format string, args ...any) { fmt.Fprintf(&log, format, args...) }
					if !retained {
						inject()
					}
					s, err := NewScanner(cfg, logf)
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					if retained {
						previous, identity, fp := s.markerRules.Load(), s.markerContent, s.Fingerprint()
						inject()
						denied := map[string]struct{}{"plain": {}}
						if err := s.reloadLockedCacheDeny(&denied); err != nil {
							t.Fatal(err)
						}
						if s.markerRules.Load() != previous || s.markerContent != identity {
							t.Fatal("clone failure changed retained marker rules or identity")
						}
						if s.Fingerprint() == fp {
							t.Fatal("new main deny policy did not change generation fingerprint")
						}
						if got := cloneNativeNames(t, s.rules.Load()); len(got) != 0 {
							t.Fatalf("new main deny state lost: %v", got)
						}
					} else if s.markerRules.Load() != nil || s.markerContent != "" {
						t.Fatal("first clone failure published a marker bundle or identity")
					}
					if !strings.Contains(log.String(), "marker bundle build failed") {
						t.Fatalf("missing clone failure warning: %s", log.String())
					}
					matches, err := s.Scan([]byte(`{\rtf1 harmless}`), ScanMeta{Extension: ".jpg"})
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, m := range matches {
						found = found || m.Rule == "Marker"
					}
					if !found || s.MarkerChannelScans() == 0 {
						t.Fatalf("marker fallback did not scan extracted marker: %v", matches)
					}
					serializeRules = original
					if err := s.Reload(); err != nil {
						t.Fatal(err)
					}
					if s.markerRules.Load() == nil || s.markerContent == "" {
						t.Fatal("marker bundle did not recover")
					}
				})
			}
		}
	}
}

func TestReloadMarkerUntaggedGlobalAndEmpty(t *testing.T) {
	for _, source := range []string{
		`global rule Gate { condition: true } rule Marker : marker { condition: true }`,
		`rule Plain { condition: true }`,
	} {
		s := newScanner(t, writeRules(t, source))
		defer s.Close()
		reference, err := buildMarkerBundle("", s.srcDir, nil, func(string, ...any) {})
		if err != nil {
			t.Fatal(err)
		}
		got, want := cloneNativeNames(t, s.markerRules.Load()), cloneNativeNames(t, reference)
		reference.Destroy()
		// Existing pruning disables even an untagged global gate, suppressing its
		// namespace. This optimization deliberately preserves that legacy behavior.
		if len(got) != 0 || !reflect.DeepEqual(got, want) {
			t.Fatalf("empty marker/untagged global parity: got %v want %v", got, want)
		}
		if len(cloneNativeNames(t, s.rules.Load())) == 0 {
			t.Fatal("marker pruning disabled the main set")
		}
	}
}
