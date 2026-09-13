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
