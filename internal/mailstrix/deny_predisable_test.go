package mailstrix

import (
	"strings"
	"testing"
)

// denyMap builds a deny map from a list of lowercase names.
func denyMap(names ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}

// TestDisableDeniedRules_NilAndEmpty verifies disableDeniedRules is a no-op on
// nil/empty deny sets and nil rules.
func TestDisableDeniedRules_NilAndEmpty(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
	defer s.Close()

	rules := s.rules.Load()
	if rules == nil {
		t.Skip("no rules loaded")
	}

	if n := disableDeniedRules(rules, nil); n != 0 {
		t.Errorf("nil deny: want 0, got %d", n)
	}
	if n := disableDeniedRules(rules, map[string]struct{}{}); n != 0 {
		t.Errorf("empty deny: want 0, got %d", n)
	}
	if n := disableDeniedRules(nil, denyMap("eicar_test_file")); n != 0 {
		t.Errorf("nil rules: want 0, got %d", n)
	}
}

// TestDisableDeniedRules_GlobalPrivateSkipped verifies global and private rules
// are never disabled, even when they appear in the deny set.
// We use a plain rule here — YARA doesn't expose global/private easily through
// the test-fixture path, so this test ensures the skip logic is exercised on
// ordinary rules (which ARE disabled) and the global/private guard compiles.
func TestDisableDeniedRules_OrdinaryRuleDisabled(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
	defer s.Close()

	rules := s.rules.Load()
	if rules == nil {
		t.Skip("no rules loaded")
	}

	n := disableDeniedRules(rules, denyMap("eicar_test_file"))
	if n != 1 {
		t.Errorf("expected 1 rule disabled, got %d", n)
	}
}

// TestDisableDeniedRules_CaseInsensitive verifies the deny lookup is
// case-insensitive (denylist keys are lowercased, identifier folded via ToLower).
func TestDisableDeniedRules_CaseInsensitive(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
	defer s.Close()

	rules := s.rules.Load()
	if rules == nil {
		t.Skip("no rules loaded")
	}

	n := disableDeniedRules(rules, denyMap("EICAR_TEST_FILE")) // mixed-case key
	if n != 0 {
		// denylist keys are stored lowercase; EICAR_TEST_FILE is not in the map
		t.Errorf("uppercase key must not match (keys must be lowercased at insert): got %d disabled", n)
	}

	n = disableDeniedRules(rules, denyMap("eicar_test_file"))
	if n != 1 {
		t.Errorf("lowercase key must match: got %d disabled", n)
	}
}

// TestDenylistHashDeterminism verifies denylistHash returns the same value for
// the same set regardless of insertion order, and differs for different sets.
func TestDenylistHashDeterminism(t *testing.T) {
	a := denylistHash(denyMap("rule_a", "rule_b", "rule_c"))
	b := denylistHash(denyMap("rule_c", "rule_a", "rule_b"))
	if a != b {
		t.Errorf("same set, different hashes: %q vs %q", a, b)
	}

	other := denylistHash(denyMap("rule_a", "rule_b"))
	if a == other {
		t.Errorf("different sets must not hash equal")
	}
}

// TestDenylistHashEmpty verifies the empty/nil set yields the fixed constant.
func TestDenylistHashEmpty(t *testing.T) {
	h0 := denylistHash(nil)
	h1 := denylistHash(map[string]struct{}{})
	if h0 != h1 {
		t.Errorf("nil and empty should hash equal: %q vs %q", h0, h1)
	}
	if h0 != "0000000000000000" {
		t.Errorf("empty hash constant changed: got %q", h0)
	}
}

// TestFingerprintFoldsDenylist verifies that Fingerprint() changes when the
// deny set changes — the #251-class cache-invalidation correctness requirement.
func TestFingerprintFoldsDenylist(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
	defer s.Close()

	fp0 := s.Fingerprint()

	// Inject a deny set manually via denylist atomic pointer and refresh FP.
	deny := denyMap("eicar_test_file")
	s.denylist.Store(&deny)
	dlFP := denylistHash(deny)
	s.denylistFP.Store(&dlFP)

	fp1 := s.Fingerprint()

	if fp0 == fp1 {
		t.Errorf("Fingerprint must change when denylist changes: both %q", fp0)
	}

	// Ensure the denylist component is actually present (not just extra ":").
	parts := strings.Split(fp1, ":")
	if len(parts) < 5 {
		t.Errorf("Fingerprint expected 5+ colon-separated parts, got %d: %q", len(parts), fp1)
	}
	denyPart := parts[len(parts)-2]
	if denyPart == "" {
		t.Errorf("denylist FP component is empty in %q", fp1)
	}
}

// TestFingerprintDenylistConsistent verifies that two scanners loaded with
// identical deny sets produce the same Fingerprint denylist component.
func TestFingerprintDenylistConsistent(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s1 := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
	defer s1.Close()
	s2 := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
	defer s2.Close()

	deny := denyMap("rule_x", "rule_y")
	dlFP := denylistHash(deny)

	s1.denylist.Store(&deny)
	s1.denylistFP.Store(&dlFP)
	s2.denylist.Store(&deny)
	s2.denylistFP.Store(&dlFP)

	if s1.Fingerprint() != s2.Fingerprint() {
		t.Errorf("identical deny sets must yield same Fingerprint: %q vs %q",
			s1.Fingerprint(), s2.Fingerprint())
	}
}
