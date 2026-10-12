package mailstrix

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	yara "github.com/hillu/go-yara/v4"
)

type markerIdentity struct{ namespace, identifier string }

// The default is the CI compiler fixture. Delivery can supply the actual
// immutable shipped envelope; its test binary must carry the linked native ABI
// identities through -ldflags, just like the production binary. Never replace
// those identities with untrusted values from the supplied artifact.
func markerInventoryScanner(t *testing.T, deny map[string]struct{}) (*Scanner, markerBinding) {
	t.Helper()
	root := os.Getenv("MAILSTRIX_MARKER_INVENTORY_ROOT")
	if root == "" {
		root = markerArtifactFixture(t)
	}
	s := markerFixtureScanner(t, root, deny)
	if s.markerRules.Load() == nil || s.markerRules.Load() == s.rules.Load() {
		t.Fatal("inventory/equivalence requires the actual selected narrow artifact")
	}
	var binding markerBinding
	if _, err := markerReadJSON(filepath.Join(root, "marker-artifact/binding.json"), &binding); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]markerFingerprint{"compiled.yac": binding.Main, "marker-artifact/markers.yac": binding.Marker} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || markerBytesIdentity(data) != want {
			t.Fatalf("actual native artifact identity differs: %s: %v", path, err)
		}
	}
	t.Logf("matched main=%s (%d rules) narrow=%s (%d rules)", binding.Main.SHA256, len(s.rules.Load().GetRules()), binding.Marker.SHA256, len(s.markerRules.Load().GetRules()))
	return s, binding
}

// The full native main is the oracle, rather than the producer's binding or
// a rule count: a replacement can keep both of those internally consistent.
func markerCompleteness(main, narrow *yara.Rules) error {
	if main == nil || narrow == nil || main == narrow {
		return fmt.Errorf("independent matched narrow bundle required")
	}
	want := map[markerIdentity]yara.Rule{}
	for _, rule := range main.GetRules() {
		if matchIsMarker(Match{Tags: rule.Tags()}) {
			want[markerIdentity{rule.Namespace(), rule.Identifier()}] = rule
		}
	}
	if len(want) == 0 {
		return fmt.Errorf("full-main marker oracle is empty")
	}
	var snapshot bytes.Buffer
	if err := narrow.Write(&snapshot); err != nil {
		return err
	}
	clone, err := yara.ReadRules(bytes.NewReader(snapshot.Bytes()))
	if err != nil {
		return err
	}
	defer clone.Destroy()
	seen := map[markerIdentity]bool{}
	for _, rule := range clone.GetRules() {
		id := markerIdentity{rule.Namespace(), rule.Identifier()}
		expected, ok := want[id]
		if !ok {
			if matchIsMarker(Match{Tags: rule.Tags()}) {
				return fmt.Errorf("unexpected marker %v", id)
			}
			continue
		}
		if seen[id] || !reflect.DeepEqual(rule.Tags(), expected.Tags()) || rule.IsPrivate() != expected.IsPrivate() || rule.IsGlobal() != expected.IsGlobal() {
			return fmt.Errorf("marker identity/tags/flags differ: %v", id)
		}
		seen[id] = true
		// go-yara has no enabled getter. Serialization retains disabled state;
		// Enable must be a byte-exact no-op on the independent native clone.
		var before, after bytes.Buffer
		if err := clone.Write(&before); err != nil {
			return err
		}
		rule.Enable()
		if err := clone.Write(&after); err != nil {
			return err
		}
		if !bytes.Equal(before.Bytes(), after.Bytes()) {
			return fmt.Errorf("marker is disabled: %v", id)
		}
	}
	for id := range want {
		if !seen[id] {
			return fmt.Errorf("marker is missing: %v", id)
		}
	}
	return nil
}

func TestP12MarkerInventoryCompleteAndEnabled(t *testing.T) {
	s, _ := markerInventoryScanner(t, nil)
	if err := markerCompleteness(s.rules.Load(), s.markerRules.Load()); err != nil {
		t.Fatalf("selected marker inventory completeness: %v", err)
	}
}

func TestP12MarkerEnabledOracleControls(t *testing.T) {
	s := markerFixtureScanner(t, markerArtifactFixture(t), nil)
	main, narrow := s.rules.Load(), s.markerRules.Load()
	if err := markerCompleteness(main, narrow); err != nil {
		t.Fatal(err)
	}
	var original, repeated bytes.Buffer
	if err := narrow.Write(&original); err != nil {
		t.Fatal(err)
	}
	if err := narrow.Write(&repeated); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original.Bytes(), repeated.Bytes()) {
		t.Fatal("native serialization is not deterministic")
	}
	clone, err := yara.ReadRules(bytes.NewReader(original.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer clone.Destroy()
	markers, companions := 0, 0
	for _, rule := range clone.GetRules() {
		if !matchIsMarker(Match{Tags: rule.Tags()}) {
			// Enabling an already enabled companion must not generate variance
			// that the marker enabled-state oracle could mistake for a flag.
			rule.Enable()
			companions++
			continue
		}
		markers++
		rule.Disable()
		if err := markerCompleteness(main, clone); err == nil {
			t.Fatalf("disabled marker accepted: %s/%s", rule.Namespace(), rule.Identifier())
		}
		rule.Enable()
		if err := markerCompleteness(main, clone); err != nil {
			t.Fatalf("restored marker rejected: %v", err)
		}
	}
	var restored bytes.Buffer
	if err := clone.Write(&restored); err != nil {
		t.Fatal(err)
	}
	if markers == 0 || companions == 0 || !bytes.Equal(original.Bytes(), restored.Bytes()) {
		t.Fatal("Disable/Enable and companion no-op did not restore exact native bytes")
	}
	for _, pair := range [][2]*yara.Rules{{nil, narrow}, {main, nil}, {main, main}} {
		if err := markerCompleteness(pair[0], pair[1]); err == nil {
			t.Fatal("missing or fallback bundle accepted as completeness proof")
		}
	}
	empty, err := yara.Compile("rule Plain { condition: true }", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Destroy()
	if err := markerCompleteness(empty, narrow); err == nil {
		t.Fatal("empty full-main marker oracle accepted")
	}
	if err := markerCompleteness(main, empty); err == nil {
		t.Fatal("missing native markers accepted")
	}
}

func TestP12MarkerChannelFullMainEquivalence(t *testing.T) {
	for _, deny := range []map[string]struct{}{nil, {"gate": {}, "privatedependency": {}, "publicdependency": {}, "markerfilename": {}}} {
		s, binding := markerInventoryScanner(t, deny)
		main, narrow := s.rules.Load(), s.markerRules.Load()
		if narrow == nil || narrow == main {
			t.Fatal("equivalence requires the actual selected narrow artifact")
		}
		buffers := []string{"", "EXT-MISMATC", "EXT-MISMATCH", "harmless EXT-MISMATCH EXT-MISMATCH", "harmless"}
		var combined strings.Builder
		for _, rule := range binding.MarkerDescriptors.Rules {
			for _, line := range rule.Lines {
				columns := strings.Split(line, "\t")
				if len(columns) != 5 || columns[0] != "S" {
					continue
				}
				data, err := hex.DecodeString(columns[4])
				if err != nil {
					t.Fatal(err)
				}
				buffers = append(buffers, string(data))
				if len(data) > 0 {
					buffers = append(buffers, string(data[:len(data)-1]))
				}
				combined.Write(data)
				combined.WriteByte('\n')
			}
		}
		buffers = append(buffers, combined.String())
		observed := map[markerIdentity]bool{}
		// Alternating externals also exercises the real pooled scanner's reset.
		for _, vars := range []scanVars{{}, {vba: true}, {extension: ".jpg"}, {extension: ".jpg", fileType: "rtf"}, {filename: "enabled", extension: ".pdf"}, {}} {
			for _, buf := range buffers {
				got, err := s.scanOne(narrow, []byte(buf), vars, 0)
				if err != nil {
					t.Fatal(err)
				}
				want, err := s.scanOne(main, []byte(buf), vars, 0)
				if err != nil {
					t.Fatal(err)
				}
				got = filterDenied(filterMarkerChannel(got, true), s.denylist.Load())
				want = filterDenied(filterMarkerChannel(want, true), s.denylist.Load())
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("marker channel differs from full-main filtered oracle: vars=%+v buf=%q got=%v want=%v", vars, buf, got, want)
				}
				for _, match := range want {
					observed[markerIdentity{match.Namespace, match.Rule}] = true
				}
			}
		}
		t.Logf("marker channel full-main equivalents=%d observed marker identities=%d", 6*len(buffers), len(observed))
		for _, body := range []string{`{\rtf1 harmless}`, "harmless EXT-MISMATCH", "", "harmless"} {
			for _, meta := range []ScanMeta{{}, {Filename: "enabled", Extension: ".jpg"}, {Extension: ".pdf"}} {
				got, err := s.Scan([]byte(body), meta)
				if err != nil {
					t.Fatal(err)
				}
				lease := s.acquireScanLease()
				want, err := s.scanGeneration([]byte(body), meta, scannerGeneration{rules: main, deny: s.denylist.Load()})
				lease.release()
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("selected artifact detection differs from full-main fallback: body=%q meta=%+v got=%v want=%v", body, meta, got, want)
				}
			}
		}
		s.Close()
	}
}

func TestP12MarkerIdentityOracleControls(t *testing.T) {
	main, err := yara.Compile("rule M : marker { condition: false }", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer main.Destroy()
	for _, source := range []string{
		"rule M : changed marker { condition: false }",
		"private rule M : marker { condition: false }",
		"global rule M : marker { condition: false }",
		"rule M { condition: false }",
		"rule M : marker { condition: false } rule Extra : marker { condition: false }",
	} {
		t.Run(source, func(t *testing.T) {
			narrow, err := yara.Compile(source, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer narrow.Destroy()
			if err := markerCompleteness(main, narrow); err == nil {
				t.Fatal("native marker identity/tag/private/global mismatch accepted")
			}
		})
	}
}
