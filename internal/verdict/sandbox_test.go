package verdict

import "testing"

func TestReportOnlySandboxPolicy(t *testing.T) {
	for _, policy := range []SandboxPolicy{"", StaticOnly} {
		if err := ValidateReportOnlyPolicy(policy); err != nil {
			t.Fatal(err)
		}
	}
	for _, policy := range []SandboxPolicy{QuarantinePending, Tempfail, "typo"} {
		if err := ValidateReportOnlyPolicy(policy); err == nil {
			t.Fatalf("unsupported enforcement accepted: %s", policy)
		}
	}
}

func TestCombineSandboxCurrentStatic(t *testing.T) {
	for _, state := range []string{"staging", "queued", "submitting", "submit_uncertain", "remote_pending", "fetching"} {
		v, err := CombineSandbox("clean", state, "no_signal")
		if err != nil || v.Evidence != "pending" || v.Concern != "clean" {
			t.Fatalf("pending mislabeled: %+v %v", v, err)
		}
	}
	for _, state := range []string{"disabled", "failed", "expired", "cancelled", "bogus"} {
		v, err := CombineSandbox("malicious", state, "no_signal")
		if err != nil || v.Evidence != "unavailable" || v.Concern != "malicious" {
			t.Fatalf("unavailable lowered static: %+v %v", v, err)
		}
	}
	for _, tc := range []struct{ static, evidence, want string }{
		{"malicious", "no_signal", "malicious"}, {"suspicious", "no_signal", "suspicious"},
		{"clean", "malicious", "malicious"}, {"unknown", "suspicious", "suspicious"},
		{"unknown", "no_signal", "unknown"}, {"malicious", "suspicious", "malicious"},
	} {
		v, err := CombineSandbox(tc.static, "completed", tc.evidence)
		if err != nil || v.Static != tc.static || v.Concern != tc.want || v.Evidence != tc.evidence {
			t.Fatalf("current static lost: %+v %v", v, err)
		}
	}
	v, err := CombineSandbox("clean", "completed", "clean")
	if err != nil || v.Evidence != "unavailable" {
		t.Fatalf("sandbox clean invented: %+v %v", v, err)
	}
	if _, err := CombineSandbox("invalid", "completed", "no_signal"); err == nil {
		t.Fatal("invalid static accepted")
	}
}

func TestCombineSandboxPreservesUnavailable(t *testing.T) {
	for _, state := range []string{"staging", "queued", "submitting", "submit_uncertain", "remote_pending", "fetching"} {
		got, err := CombineSandbox("suspicious", state, "unavailable")
		if err != nil || got.Evidence != "unavailable" || got.Concern != "suspicious" {
			t.Fatalf("unavailable evidence overwritten: %+v %v", got, err)
		}
	}
}
