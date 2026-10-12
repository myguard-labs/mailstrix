package mailstrix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type markerClosureExpectation struct{ Markers, Retained []int }

// Package bridge for ci/ci_marker_closure_test.py: the private runtime helper and
// the native capture validator are exercised together, on compiler observations.
func markerClosureFixture(t testing.TB, root string, depth int) (markerGraph, markerClosureExpectation) {
	t.Helper()
	dir := filepath.Join(root, "native-closure", fmt.Sprint(depth))
	var inv markerInvocation
	if _, err := markerReadJSON(filepath.Join(dir, "invocation.json"), &inv); err != nil {
		t.Fatal(err)
	}
	if err := markerVerifyNativeGraph(filepath.Join(dir, "native"), inv); err != nil {
		t.Fatalf("genuine compiler closure graph: %v", err)
	}
	var want markerClosureExpectation
	data, err := os.ReadFile(filepath.Join(dir, "closure.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Namespaces are checked separately; the binding closure contains only indices.
	var expected struct {
		Markers    []int    `json:"markers"`
		Retained   []int    `json:"retained"`
		Namespaces []string `json:"namespaces"`
	}
	if err = json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	want.Markers, want.Retained = expected.Markers, expected.Retained
	if len(inv.Graph.Inventory) != 2*depth+5 || len(want.Markers) != depth || len(want.Retained) != 2*depth+2 || !markerEqual(expected.Namespaces, []string{"a.yar"}) {
		t.Fatal("genuine many-marker/deep-chain fixture shape changed")
	}
	return inv.Graph, want
}

func TestP12eNativeClosure(t *testing.T) {
	root := markerArtifactFixture(t)
	for _, depth := range []int{512, 2048} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			graph, want := markerClosureFixture(t, root, depth)
			markers, retained, namespaces := markerRuleClosure(graph)
			if !markerEqual(markers, want.Markers) {
				t.Fatal("compiler marker ordering mismatch")
			}
			if !markerEqual(retained, want.Retained) {
				t.Fatal("late private/global dependency closure mismatch")
			}
			if !markerEqual(namespaces, map[string]bool{"a.yar": true}) {
				t.Fatal("closure escaped native namespace")
			}
			if !sort.IntsAreSorted(retained) {
				t.Fatal("retained closure ordering mismatch")
			}
		})
	}
}

func TestP12eClosureBoundaries(t *testing.T) {
	root := markerArtifactFixture(t)
	var main, narrow markerManifest
	var binding markerBinding
	if _, err := markerReadJSON(filepath.Join(root, "compiler-inputs/main/manifest.json"), &main); err != nil {
		t.Fatal(err)
	}
	if _, err := markerReadJSON(filepath.Join(root, "marker-artifact/graph/manifest.json"), &narrow); err != nil {
		t.Fatal(err)
	}
	if _, err := markerReadJSON(filepath.Join(root, "marker-artifact/binding.json"), &binding); err != nil {
		t.Fatal(err)
	}
	if err := markerValidateBinding(binding, main, narrow, binding.Main, binding.MainManifest, binding.MarkerManifest); err != nil {
		t.Fatalf("compiler binding equivalence: %v", err)
	}
	for _, graph := range []markerGraph{{Inventory: []markerInventoryRule{}, References: [][2]int{}}, main.Final.Graph} {
		graph.Inventory = append([]markerInventoryRule(nil), graph.Inventory...)
		for i := range graph.Inventory {
			graph.Inventory[i].Tags = []string{}
		}
		markers, retained, namespaces := markerRuleClosure(graph)
		if !markerEqual(markers, []int{}) || !markerEqual(retained, []int{}) || len(namespaces) != 0 {
			t.Fatal("zero-marker closure retained a rule or namespace")
		}
	}
	// Malformed/cross-namespace input is rejected at the binding's graph gate
	// before the indexed helper can use any untrusted ordinal.
	for _, edge := range [][2]int{{len(main.Final.Graph.Inventory), 0}, {0, len(main.Final.Graph.Inventory)}, {0, len(main.Final.Graph.Inventory) - 1}} {
		var m markerManifest
		data, err := json.Marshal(main)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		m.Final.Graph.References = append(m.Final.Graph.References, edge)
		if err = markerValidateBinding(binding, m, narrow, binding.Main, binding.MainManifest, binding.MarkerManifest); err == nil {
			t.Fatal("malformed closure graph reached indexed traversal")
		}
	}
}

func BenchmarkP12eNativeClosure(b *testing.B) {
	root := markerArtifactFixture(b)
	for _, depth := range []int{512, 2048} {
		b.Run(fmt.Sprint(depth), func(b *testing.B) {
			graph, want := markerClosureFixture(b, root, depth)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				markers, retained, _ := markerRuleClosure(graph)
				if len(markers) != len(want.Markers) || len(retained) != len(want.Retained) {
					b.Fatal("benchmark closure changed")
				}
			}
		})
	}
}
