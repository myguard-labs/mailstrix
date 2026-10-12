package ci

import (
	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkerRuntimeSourceFallbackDependencies(t *testing.T) {
	for _, denied := range []bool{false, true} {
		dir := t.TempDir()
		source := `global rule Gate { condition: true }
private rule PrivateDependency { condition: true }
rule PublicDependency { condition: true }
rule PrivateMarker : marker { strings: $a="EXT-MISMATCH" condition: $a and PrivateDependency }
rule PublicMarker : marker { strings: $a="EXT-MISMATCH" condition: $a and PublicDependency }
rule Content { strings: $a="harmless" condition: $a }`
		if e := os.WriteFile(filepath.Join(dir, "marker.yar"), []byte(source), 0600); e != nil {
			t.Fatal(e)
		}
		cfg := &ms.Config{RulesDir: dir}
		if denied {
			cfg.RuleDenylist = map[string]struct{}{"gate": {}, "privatedependency": {}, "publicdependency": {}}
		}
		s, e := ms.NewScanner(cfg, func(string, ...any) {})
		if e != nil {
			t.Fatal(e)
		}
		out, e := s.Scan([]byte(`{\rtf1 harmless}`), ms.ScanMeta{Extension: ".jpg"})
		if e != nil {
			t.Fatal(e)
		}
		names := map[string]bool{}
		for _, m := range out {
			names[m.Rule] = true
		}
		if !names["PrivateMarker"] || !names["Content"] || names["PublicMarker"] == denied || s.MarkerChannelScans() == 0 {
			t.Fatalf("source fallback dependency/global/deny detection: denied=%v matches=%v", denied, out)
		}
		out, e = s.Scan([]byte("harmless EXT-MISMATCH"), ms.ScanMeta{})
		if e != nil {
			t.Fatal(e)
		}
		for _, m := range out {
			if strings.Contains(m.Rule, "Marker") {
				t.Fatalf("raw channel leaked pure marker: %v", out)
			}
		}
		s.Close()
	}
}
