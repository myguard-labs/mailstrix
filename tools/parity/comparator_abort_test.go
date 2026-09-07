package main

import "testing"

func TestCleanupUncertaintyStopsLaterObservers(t *testing.T) {
	m, hash, root := generated(t)
	for _, s := range m.Samples {
		if s.Format == "office" {
			m.Samples = []sample{s}
			break
		}
	}
	second := m.Samples[0]
	data, err := readSample(root, second)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	second.ID, second.Locator = "second", "second.docx"
	second.SHA256, second.Size = digest(data), int64(len(data))
	if err := root.WriteFile(second.Locator, data, 0600); err != nil {
		t.Fatal(err)
	}
	m.Samples = append(m.Samples, second)
	pins := testPins(t)
	for _, failAt := range []int{1, 2, 3} {
		calls := 0
		r := compareCorpus(root, m, hash, pins, selectedAdapters("both"), func(string, []byte) nativeObservation {
			calls++
			if calls == failAt {
				return nativeObservation{Status: "cleanup_error"}
			}
			return nativeObservation{Status: "ok", Format: "OpenXML"}
		})
		if calls != failAt {
			t.Fatalf("observer calls=%d after cleanup_error at %d", calls, failAt)
		}
		equalPairs := (failAt - 1) / 2
		if r.Complete || r.UniqueSamples != 2 || r.Agreement["excluded"] != 2-equalPairs || r.Agreement["equal"] != equalPairs {
			t.Fatalf("incomplete accounting: %+v", r)
		}
		notRun, failures, completed := 0, 0, 0
		for _, a := range r.Adapters {
			notRun += a.Statuses["not_run"]
			failures += a.Statuses["cleanup_error"]
			completed += a.WithoutMacros
		}
		if notRun != 4-failAt || failures != 1 || completed != failAt-1 {
			t.Fatalf("lost observations: not_run=%d failures=%d completed=%d", notRun, failures, completed)
		}
	}
	// Ordinary parser/execution failures do not imply a live leftover container.
	calls := 0
	r := compareCorpus(root, m, hash, pins, selectedAdapters("both"), func(string, []byte) nativeObservation {
		calls++
		return nativeObservation{Status: "tool_error"}
	})
	if calls != 4 || r.Complete || r.Agreement["excluded"] != 2 {
		t.Fatal("ordinary failures incorrectly aborted later observations")
	}
}
