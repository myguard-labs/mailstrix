package mailstrix

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hillu/go-yara/v4"
)

const denyDependencyRules = `
global rule GlobalGate { condition: true }
private rule PrivateGate { condition: true }
rule Referenced { condition: true }
rule Dependent { condition: Referenced }
rule UsesPrivate { condition: PrivateGate }
rule Unreferenced { condition: true }
`

func denyDependencyTestCommand(t *testing.T, testName, helper string) *exec.Cmd {
	t.Helper()
	switch testName {
	case "TestDisableDeniedRules_DependencySafety", "TestLibYARAReferencedRuleDisableInvalidState":
	default:
		t.Fatalf("unsupported subprocess test %q", testName)
	}
	switch helper {
	case "candidate", "assert":
	default:
		t.Fatalf("unsupported subprocess helper %q", helper)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	// #nosec G204 -- executable is this test binary and both arguments are selected above.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(executable, "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), "MAILSTRIX_DENY_DEPENDENCY_HELPER="+helper)
	return cmd
}

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

// TestDisableDeniedRules_OrdinaryRuleRetained verifies public rules remain
// enabled because go-yara does not expose enough dependency information to
// prove that an ordinary rule is unreferenced.
func TestDisableDeniedRules_OrdinaryRuleRetained(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
	defer s.Close()

	rules := s.rules.Load()
	if rules == nil {
		t.Skip("no rules loaded")
	}

	n := disableDeniedRules(rules, denyMap("eicar_test_file"))
	if n != 0 {
		t.Errorf("public rule must remain enabled, got %d disabled", n)
	}
}

func TestDisableDeniedRules_DependencySafety(t *testing.T) {
	if os.Getenv("MAILSTRIX_DENY_DEPENDENCY_HELPER") == "candidate" {
		dir := writeRules(t, denyDependencyRules)
		cfg := &Config{
			RulesDir:    dir,
			ScanTimeout: loadInsensitiveScanTimeout,
			RuleDenylist: denyMap(
				"globalgate",
				"privategate",
				"referenced",
				"unreferenced",
			),
		}
		s, err := NewScanner(cfg, func(string, ...any) {})
		if err != nil {
			t.Fatalf("NewScanner: %v", err)
		}
		defer s.Close()

		matches, err := s.Scan([]byte("harmless"), ScanMeta{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		got := make(map[string]bool, len(matches))
		for _, match := range matches {
			got[match.Rule] = true
		}
		for _, retained := range []string{"Dependent", "UsesPrivate"} {
			if !got[retained] {
				t.Errorf("retained dependency %s missing from %s", retained, ruleNames(matches))
			}
		}
		for _, denied := range []string{"GlobalGate", "PrivateGate", "Referenced", "Unreferenced"} {
			if got[denied] {
				t.Errorf("denied rule %s leaked through post-filter: %s", denied, ruleNames(matches))
			}
		}
		return
	}

	cmd := denyDependencyTestCommand(t, "TestDisableDeniedRules_DependencySafety", "candidate")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dependency-safe deny subprocess failed: %v\n%s", err, out)
	}
}

// TestLibYARAReferencedRuleDisableInvalidState proves the unsafe state in a
// subprocess so a libyara build that aborts cannot terminate the test runner.
// The current assertion-enabled and release 4.5.2 builds instead suppress the
// dependent, which proves the same invalid evaluation state.
func TestLibYARAReferencedRuleDisableInvalidState(t *testing.T) {
	if os.Getenv("MAILSTRIX_DENY_DEPENDENCY_HELPER") == "assert" {
		dir := writeRules(t, denyDependencyRules)
		s := newScannerBudget(t, dir, loadInsensitiveScanTimeout)
		defer s.Close()

		rules := s.rules.Load()
		if rules == nil {
			t.Fatal("assertion helper loaded no rules")
		}
		allRules := rules.GetRules()
		for i := range allRules {
			rule := &allRules[i]
			if rule.Identifier() == "Referenced" {
				rule.Disable()
				var matches yara.MatchRules
				if err := rules.ScanMem([]byte("harmless"), 0, time.Second, &matches); err != nil {
					t.Fatalf("scan disabled referenced rule: %v", err)
				}
				for _, match := range matches {
					if match.Rule == "Dependent" {
						t.Fatal("disabled referenced rule unexpectedly preserved its dependent")
					}
				}
				fmt.Fprintln(os.Stderr, "release-libyara-invalid-state: dependent suppressed")
				os.Exit(86)
			}
		}
		t.Fatal("Referenced rule missing")
	}

	cmd := denyDependencyTestCommand(t, "TestLibYARAReferencedRuleDisableInvalidState", "assert")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("libyara unexpectedly accepted the unsafe state:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unsafe-state subprocess did not return an exit status: %v\n%s", err, out)
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGABRT {
		t.Log("assertion-enabled libyara aborted on a disabled referenced rule")
		return
	}
	if !strings.Contains(string(out), "release-libyara-invalid-state: dependent suppressed") {
		t.Fatalf("unsafe state lacked assertion or release-behavior evidence: %v\n%s", err, out)
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
