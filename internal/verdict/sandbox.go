package verdict

import "errors"

// SandboxPolicy describes unresolved detonation handling. Existing adapters
// support only StaticOnly until their enforcement/ownership is implemented.
type SandboxPolicy string

const (
	// StaticOnly keeps delivery decisions based solely on the current static verdict.
	StaticOnly SandboxPolicy = "static-only"
	// QuarantinePending reserves a future policy that quarantines while detonation is pending.
	QuarantinePending SandboxPolicy = "quarantine-pending"
	// Tempfail reserves a future policy that defers delivery while detonation is pending.
	Tempfail SandboxPolicy = "tempfail"
)

// ValidateReportOnlyPolicy is a startup gate for report-only adapters.
// Empty selects the backward-compatible disabled/static-only default.
func ValidateReportOnlyPolicy(policy SandboxPolicy) error {
	if policy == "" || policy == StaticOnly {
		return nil
	}
	return errors.New("unsupported sandbox policy: adapter requires static-only")
}

// SandboxView carries already authorized reusable evidence; Static is always
// the current scan's verdict, never an older admission snapshot. Pending and
// unavailable remain separate from concern, including when Static is clean.
type SandboxView struct {
	Static   string `json:"static"`
	State    string `json:"state"`
	Evidence string `json:"evidence"`
	Concern  string `json:"concern"`
}

// CombineSandbox is report-only interpretation. It never directs delivery,
// claims sandbox clean, or reduces the current static concern.
func CombineSandbox(currentStatic, state, evidence string) (SandboxView, error) {
	ranks := map[string]int{"clean": 0, "unknown": 1, "suspicious": 2, "malicious": 3}
	if _, valid := ranks[currentStatic]; !valid {
		return SandboxView{}, errors.New("invalid static verdict")
	}
	v := SandboxView{Static: currentStatic, State: state, Evidence: "unavailable", Concern: currentStatic}
	switch state {
	case "staging", "queued", "submitting", "submit_uncertain", "remote_pending", "fetching":
		if evidence != "unavailable" {
			v.Evidence = "pending"
		}
	case "completed":
		if evidence == "malicious" || evidence == "suspicious" || evidence == "no_signal" {
			v.Evidence = evidence
			if ranks[evidence] > ranks[v.Concern] {
				v.Concern = evidence
			}
		}
	case "disabled", "failed", "expired", "cancelled":
	default:
		v.State = "unavailable"
	}
	return v, nil
}
