package mailstrix

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCgroupFile writes content to a temp file and returns its path. A nil
// content means "do not create it", so the missing-file branch gets a path that
// definitely does not exist rather than a guess.
func writeCgroupFile(t *testing.T, name string, content *string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if content == nil {
		return p
	}
	if err := os.WriteFile(p, []byte(*content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func strptr(s string) *string { return &s }

func TestCgroupMemLimitMiBFrom(t *testing.T) {
	tests := []struct {
		name    string
		content *string
		want    int64
	}{
		{"unreadable file is unknown", nil, 0},
		// The "" and "max" rows pin the OUTCOME, not the explicit `s == "max"`
		// branch: ParseInt rejects both anyway, so deleting that branch keeps
		// these green. Kept because the outcome is the contract; the branch is
		// a readability shortcut over the parse.
		{"empty is unlimited", strptr(""), 0},
		{"whitespace only is unlimited", strptr("  \n\t "), 0},
		{"v2 max sentinel is unlimited", strptr("max"), 0},
		{"max with trailing newline", strptr("max\n"), 0},
		{"one GiB", strptr("1073741824"), 1024},
		{"one GiB with trailing newline", strptr("1073741824\n"), 1024},
		{"512 MiB", strptr("536870912"), 512},
		{"non-numeric is unknown", strptr("not-a-number"), 0},
		{"negative is unknown", strptr("-1"), 0},
		{"zero is unknown", strptr("0"), 0},
		// The v1 kernel writes a huge value rather than a word to mean "no limit".
		{"kernel no-limit sentinel", strptr("9223372036854771712"), 0},
		{"just under the sentinel threshold", strptr("4611686018427387903"), (1 << 62 >> 20) - 1},
		// Sub-MiB limits floor to 0 because the result is in MiB; the caller
		// treats 0 as "no enforced limit", which is the safe reading.
		{"sub-MiB floors to zero", strptr("1048575"), 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := writeCgroupFile(t, "memory.max", tc.content)
			if got := cgroupMemLimitMiBFrom(p); got != tc.want {
				t.Fatalf("cgroupMemLimitMiBFrom(%q) = %d, want %d", derefOrMissing(tc.content), got, tc.want)
			}
		})
	}
}

func TestCgroupMemLimitMiBFromFallsBackToV1(t *testing.T) {
	missingV2 := writeCgroupFile(t, "memory.max", nil)
	v1 := writeCgroupFile(t, "memory.limit_in_bytes", strptr("2147483648"))

	if got := cgroupMemLimitMiBFrom(missingV2, v1); got != 2048 {
		t.Fatalf("v1 fallback = %d MiB, want 2048", got)
	}
}

// The first READABLE path wins even when it reports unlimited: a present v2 file
// saying "max" means there is no limit, and must not fall through to a stale v1
// file that still holds a number.
func TestCgroupMemLimitMiBFromFirstReadablePathWins(t *testing.T) {
	v2 := writeCgroupFile(t, "memory.max", strptr("max"))
	v1 := writeCgroupFile(t, "memory.limit_in_bytes", strptr("2147483648"))

	if got := cgroupMemLimitMiBFrom(v2, v1); got != 0 {
		t.Fatalf("v2 'max' = %d MiB, want 0 (must not fall through to v1)", got)
	}
}

func TestCgroupMemLimitMiBFromNoPaths(t *testing.T) {
	if got := cgroupMemLimitMiBFrom(); got != 0 {
		t.Fatalf("no paths = %d, want 0", got)
	}
}

func TestCgroupCPUQuotaFrom(t *testing.T) {
	tests := []struct {
		name    string
		content *string
		want    float64
	}{
		{"unreadable file is unknown", nil, 0},
		// As above: ParseFloat also rejects "max", so this row pins the outcome
		// rather than the `parts[0] == "max"` branch.
		{"max sentinel is unlimited", strptr("max 100000"), 0},
		{"one full CPU", strptr("100000 100000"), 1},
		{"half a CPU", strptr("50000 100000"), 0.5},
		{"two and a half CPUs", strptr("250000 100000"), 2.5},
		{"trailing newline", strptr("200000 100000\n"), 2},
		{"extra whitespace between fields", strptr("  200000   100000  "), 2},
		{"missing period field", strptr("100000"), 0},
		{"too many fields", strptr("100000 100000 100000"), 0},
		{"empty is unknown", strptr(""), 0},
		{"non-numeric quota", strptr("abc 100000"), 0},
		{"non-numeric period", strptr("100000 abc"), 0},
		{"zero quota", strptr("0 100000"), 0},
		{"negative quota", strptr("-100000 100000"), 0},
		{"zero period", strptr("100000 0"), 0},
		{"negative period", strptr("100000 -100000"), 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := writeCgroupFile(t, "cpu.max", tc.content)
			if got := cgroupCPUQuotaFrom(p); got != tc.want {
				t.Fatalf("cgroupCPUQuotaFrom(%q) = %v, want %v", derefOrMissing(tc.content), got, tc.want)
			}
		})
	}
}

func derefOrMissing(s *string) string {
	if s == nil {
		return "<missing file>"
	}
	return *s
}
