package mailstrix

import (
	"math"
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
		{"NaN quota", strptr("NaN 100000"), 0},
		{"Inf quota", strptr("Inf 100000"), 0},
		{"Inf period", strptr("100000 +Inf"), 0},
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

func TestCgroupCPUQuotaV1From(t *testing.T) {
	tests := []struct {
		name          string
		quota, period *string
		want          float64
	}{
		{"missing quota", nil, strptr("100000"), 0},
		{"missing period", strptr("200000"), nil, 0},
		{"unlimited -1", strptr("-1\n"), strptr("100000\n"), 0},
		{"two CPUs", strptr("200000\n"), strptr("100000\n"), 2},
		{"half CPU", strptr("50000"), strptr("100000"), 0.5},
		{"garbage quota", strptr("abc"), strptr("100000"), 0},
		{"garbage period", strptr("100000"), strptr("abc"), 0},
		{"zero period", strptr("100000"), strptr("0"), 0},
		{"negative period", strptr("100000"), strptr("-5"), 0},
		{"zero quota", strptr("0"), strptr("100000"), 0},
		{"too many fields", strptr("100000 1"), strptr("100000"), 0},
		{"empty quota", strptr(""), strptr("100000"), 0},
		{"NaN quota", strptr("NaN"), strptr("100000"), 0},
		{"Inf quota", strptr("Inf"), strptr("100000"), 0},
		{"Inf period", strptr("100000"), strptr("Inf"), 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := writeCgroupFile(t, "cpu.cfs_quota_us", tc.quota)
			p := writeCgroupFile(t, "cpu.cfs_period_us", tc.period)
			if got := cgroupCPUQuotaV1From(q, p); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCgroupCPUQuotaAnyPrefersV2ThenV1(t *testing.T) {
	v2 := writeCgroupFile(t, "cpu.max", strptr("300000 100000"))
	q := writeCgroupFile(t, "q", strptr("100000"))
	p := writeCgroupFile(t, "p", strptr("100000"))
	if got := cgroupCPUQuotaAny(v2, q, p); got != 3 {
		t.Fatalf("v2 limited: got %v, want 3", got)
	}
	v2max := writeCgroupFile(t, "cpu.max", strptr("max 100000"))
	if got := cgroupCPUQuotaAny(v2max, q, p); got != 1 {
		t.Fatalf("v2 unlimited falls to v1: got %v, want 1", got)
	}
	missing := writeCgroupFile(t, "none", nil)
	if got := cgroupCPUQuotaAny(missing, missing, missing); got != 0 {
		t.Fatalf("nothing readable: got %v, want 0", got)
	}
}

func TestEffectiveCPUsFrom(t *testing.T) {
	tests := []struct {
		name  string
		host  int
		quota float64
		want  int
	}{
		{"unlimited uses host", 8, 0, 8},
		{"two CPUs", 8, 2, 2},
		{"fractional rounds up", 8, 1.5, 2},
		{"150000/100000", 8, 150000.0 / 100000.0, 2},
		{"half CPU floors at one", 8, 0.5, 1},
		{"tiny quota floors at one", 8, 0.01, 1},
		{"quota above host capped", 4, 16, 4},
		{"exact host", 4, 4, 4},
		{"negative treated as unlimited", 4, -1, 4},
		{"zero host defends", 0, 0, 1},
		{"NaN treated as unlimited", 4, math.NaN(), 4},
		{"+Inf treated as unlimited", 4, math.Inf(1), 4},
		{"huge quota capped without int overflow", 4, 1e20, 4},
		{"just above host-1 rounds to host", 4, 3.01, 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveCPUsFrom(tc.host, tc.quota); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestLoadConfigAutoConcurrencyHonorsCgroupQuota(t *testing.T) {
	old := cpuQuotaSource
	t.Cleanup(func() { cpuQuotaSource = old })
	cpuQuotaSource = func() float64 { return 0.25 } // far below any host CPU count
	t.Setenv("MAILSTRIX_MAX_CONCURRENT", "auto")
	if got := LoadConfig().MaxConcurrent; got != 1 {
		t.Fatalf("auto with 0.25 CPU quota: MaxConcurrent = %d, want 1", got)
	}
	// Negative control: an explicit value is honored regardless of the quota.
	t.Setenv("MAILSTRIX_MAX_CONCURRENT", "6")
	if got := LoadConfig().MaxConcurrent; got != 6 {
		t.Fatalf("explicit 6: MaxConcurrent = %d, want 6", got)
	}
}
