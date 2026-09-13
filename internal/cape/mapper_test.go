package cape

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSignatureMapper(t *testing.T) {
	rules := []SignatureRule{{"bad", "local_bad", EvidenceMalicious}, {"odd", "local_odd", EvidenceSuspicious}}
	m, err := NewSignatureMapper("signals_v1", rules)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Evidence = EvidenceSuspicious // constructor must own its policy
	for _, tc := range []struct {
		name       string
		signatures any
		want       Evidence
		signals    []string
		fail       bool
	}{
		{"empty", []any{}, EvidenceNoSignal, nil, false},
		{"unknown", []any{map[string]any{"name": "other", "score": 100}}, EvidenceNoSignal, nil, false},
		{"malicious", []any{map[string]any{"name": "bad"}, map[string]any{"name": "odd"}, map[string]any{"name": "bad"}}, EvidenceMalicious, []string{"local_bad", "local_odd"}, false},
		{"suspicious", []any{map[string]any{"name": "odd"}}, EvidenceSuspicious, []string{"local_odd"}, false},
		{"null", nil, "", nil, true}, {"object", map[string]any{}, "", nil, true},
		{"entry", []any{"bad"}, "", nil, true}, {"missing-name", []any{map[string]any{}}, "", nil, true},
		{"malformed-after-hit", []any{map[string]any{"name": "bad"}, map[string]any{"name": 2}}, "", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.Normalize(context.Background(), &Report{document: map[string]any{"signatures": tc.signatures}}, "signals_v1")
			if tc.fail {
				if err == nil {
					t.Fatal("malformed signatures accepted")
				}
				return
			}
			if err != nil || got.Evidence != tc.want || !reflect.DeepEqual(got.Signals, tc.signals) {
				t.Fatalf("mapping=%+v err=%v want=%s %v", got, err, tc.want, tc.signals)
			}
		})
	}
	if _, err := m.Normalize(context.Background(), &Report{document: map[string]any{"signatures": []any{}}}, "signals_v2"); err == nil {
		t.Fatal("policy mismatch accepted")
	}
	if _, err := m.Normalize(context.Background(), nil, "signals_v1"); err == nil {
		t.Fatal("nil report accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Normalize(ctx, &Report{document: map[string]any{"signatures": []any{}}}, "signals_v1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled mapping did not return context.Canceled: %v", err)
	}
	for _, rules := range [][]SignatureRule{nil, {{"bad", "bad", EvidenceNoSignal}}, {{"bad", "bad", EvidenceMalicious}, {"bad", "other", EvidenceSuspicious}}, {{"bad", "raw text", EvidenceMalicious}}} {
		if _, err := NewSignatureMapper("v1", rules); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}

func TestSignatureMapperBoundaries(t *testing.T) {
	for _, n := range []int{128, 129} {
		t.Run(fmt.Sprintf("rules-%d", n), func(t *testing.T) {
			rules := make([]SignatureRule, n)
			for i := range rules {
				rules[i] = SignatureRule{fmt.Sprintf("name_%d", i), fmt.Sprintf("signal_%d", i), EvidenceSuspicious}
			}
			_, err := NewSignatureMapper("v1", rules)
			if (err != nil) != (n > 128) {
				t.Fatalf("rule limit %d: err=%v", n, err)
			}
		})
		for _, field := range []string{"name", "signal"} {
			t.Run(fmt.Sprintf("constructor-%s-%d", field, n), func(t *testing.T) {
				rule := SignatureRule{"name", "signal", EvidenceMalicious}
				if field == "name" {
					rule.Name = strings.Repeat("n", n)
				} else {
					rule.Signal = strings.Repeat("s", n)
				}
				_, err := NewSignatureMapper("v1", []SignatureRule{rule})
				if (err != nil) != (n > 128) {
					t.Fatalf("constructor %s length %d: err=%v", field, n, err)
				}
			})
		}
	}
	m, err := NewSignatureMapper("v1", []SignatureRule{{"known", "local_signal", EvidenceMalicious}})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{4096, 4097} {
		t.Run(fmt.Sprintf("signatures-%d", n), func(t *testing.T) {
			signatures := make([]any, n)
			for i := range signatures {
				signatures[i] = map[string]any{"name": "unknown"}
			}
			got, err := m.Normalize(context.Background(), &Report{document: map[string]any{"signatures": signatures}}, "v1")
			if n > 4096 {
				if err == nil {
					t.Fatalf("signature limit %d accepted", n)
				}
			} else if err != nil || got.Evidence != EvidenceNoSignal {
				t.Fatalf("signature boundary %d rejected: %+v %v", n, got, err)
			}
		})
	}
	for _, n := range []int{128, 129} {
		t.Run(fmt.Sprintf("report-name-%d", n), func(t *testing.T) {
			got, err := m.Normalize(context.Background(), &Report{document: map[string]any{"signatures": []any{map[string]any{"name": strings.Repeat("n", n)}}}}, "v1")
			if n > 128 {
				if err == nil {
					t.Fatalf("report name limit %d accepted", n)
				}
			} else if err != nil || got.Evidence != EvidenceNoSignal {
				t.Fatalf("report name boundary %d rejected: %+v %v", n, got, err)
			}
		})
	}
}
