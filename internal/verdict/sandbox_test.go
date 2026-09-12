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
