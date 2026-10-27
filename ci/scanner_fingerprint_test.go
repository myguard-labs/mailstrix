package ci_test

import (
	"os"
	"path/filepath"
	"testing"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

const (
	fingerprintMainRule = `rule FingerprintMain {
    strings:
        $body = "FINGERPRINT-COVERAGE-BODY"
    condition:
        $body
}`
	fingerprintBigRule = `rule FingerprintBig {
    strings:
        $body = "FINGERPRINT-COVERAGE-BODY"
    condition:
        $body
}`
)

func fingerprintRuleDir(t *testing.T, rule string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fingerprint.yar"), []byte(rule), 0o600); err != nil {
		t.Fatalf("write fingerprint rule: %v", err)
	}
	return dir
}

func fingerprintScanner(t *testing.T, main, big string, threshold int64) *ms.Scanner {
	t.Helper()
	s, err := ms.NewScanner(&ms.Config{
		RulesDir:         main,
		BigFileRules:     big,
		BigFileThreshold: threshold,
	}, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner(threshold=%d, big=%q): %v", threshold, big, err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestScannerFingerprintSeparatesEffectiveCoverageConfiguration(t *testing.T) {
	main := fingerprintRuleDir(t, fingerprintMainRule)
	big := fingerprintRuleDir(t, fingerprintBigRule)

	t.Run("threshold", func(t *testing.T) {
		low := fingerprintScanner(t, main, big, 1)
		high := fingerprintScanner(t, main, big, 4096)
		body := []byte("FINGERPRINT-COVERAGE-BODY")

		lowMatches, err := low.Scan(body, ms.ScanMeta{})
		if err != nil {
			t.Fatalf("low-threshold scan: %v", err)
		}
		highMatches, err := high.Scan(body, ms.ScanMeta{})
		if err != nil {
			t.Fatalf("high-threshold scan: %v", err)
		}
		if len(lowMatches) != 1 || lowMatches[0].Rule != "FingerprintBig" {
			t.Fatalf("low threshold selected %v, want FingerprintBig", lowMatches)
		}
		if len(highMatches) != 1 || highMatches[0].Rule != "FingerprintMain" {
			t.Fatalf("high threshold selected %v, want FingerprintMain", highMatches)
		}
		if low.Fingerprint() == high.Fingerprint() {
			t.Fatal("different effective big-file thresholds shared one Redis/cache fingerprint")
		}
	})

	t.Run("bundle", func(t *testing.T) {
		otherBig := fingerprintRuleDir(t, `rule FingerprintOtherBig { condition: true }`)
		first := fingerprintScanner(t, main, big, 1)
		second := fingerprintScanner(t, main, otherBig, 1)
		if first.Fingerprint() == second.Fingerprint() {
			t.Fatal("different effective big-file bundles shared one Redis/cache fingerprint")
		}
	})
}

func TestScannerFingerprintReusesEquivalentEffectiveConfiguration(t *testing.T) {
	mainA := fingerprintRuleDir(t, fingerprintMainRule)
	mainB := fingerprintRuleDir(t, fingerprintMainRule)
	bigA := fingerprintRuleDir(t, fingerprintBigRule)
	bigB := fingerprintRuleDir(t, fingerprintBigRule)

	first := fingerprintScanner(t, mainA, bigA, 1024)
	second := fingerprintScanner(t, mainB, bigB, 1024)
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("equivalent effective configurations did not reuse identity: %q != %q", first.Fingerprint(), second.Fingerprint())
	}
}

func TestScannerFingerprintCanonicalizesIneffectiveBigFileConfiguration(t *testing.T) {
	main := fingerprintRuleDir(t, fingerprintMainRule)
	validBig := fingerprintRuleDir(t, fingerprintBigRule)
	invalidBig := filepath.Join(t.TempDir(), "invalid.yac")
	if err := os.WriteFile(invalidBig, []byte("not a compiled YARA bundle"), 0o600); err != nil {
		t.Fatalf("write malformed bundle: %v", err)
	}

	base := fingerprintScanner(t, main, "", 0).Fingerprint()
	for _, tc := range []struct {
		name      string
		big       string
		threshold int64
	}{
		{name: "negative threshold", big: validBig, threshold: -1},
		{name: "zero threshold with bundle", big: validBig, threshold: 0},
		{name: "missing bundle", big: filepath.Join(t.TempDir(), "missing.yac"), threshold: 1},
		{name: "malformed bundle", big: invalidBig, threshold: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := fingerprintScanner(t, main, tc.big, tc.threshold).Fingerprint()
			if got != base {
				t.Fatalf("ineffective big-file configuration changed identity: got %q want %q", got, base)
			}
		})
	}
}
