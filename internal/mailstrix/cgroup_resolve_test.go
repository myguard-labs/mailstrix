package mailstrix

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cgTree is a fake sysroot plus proc files.
type cgTree struct {
	t        *testing.T
	sys      string
	cgroup   string
	mountinf string
}

func newCgTree(t *testing.T, procCgroup, mountinfo string) *cgTree {
	t.Helper()
	d := t.TempDir()
	tr := &cgTree{t: t, sys: filepath.Join(d, "sys"), cgroup: filepath.Join(d, "cgroup"), mountinf: filepath.Join(d, "mountinfo")}
	if procCgroup != "" {
		tr.write(tr.cgroup, procCgroup)
	}
	if mountinfo != "" {
		tr.write(tr.mountinf, mountinfo)
	}
	return tr
}

func (tr *cgTree) write(p, content string) {
	tr.t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		tr.t.Fatal(err)
	}
}

// file writes a cgroup file at a path relative to the fake sysroot.
func (tr *cgTree) file(rel, content string) { tr.write(filepath.Join(tr.sys, rel), content) }

func (tr *cgTree) resolve() float64 {
	return resolveCgroupCPUQuota(tr.cgroup, tr.mountinf, tr.sys)
}

const (
	mi2Root   = "30 25 0:26 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw\n"
	mi2Sub    = "30 25 0:26 /docker/abc /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"
	miV1Sep   = "31 25 0:27 / /sys/fs/cgroup/cpu rw shared:5 - cgroup cgroup rw,cpu\n"
	miV1Combo = "31 25 0:27 / /sys/fs/cgroup/cpu,cpuacct rw shared:5 - cgroup cgroup rw,cpu,cpuacct\n"
)

func approx(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestResolveV2NamespacedRoot(t *testing.T) {
	tr := newCgTree(t, "0::/\n", mi2Root)
	tr.file("sys/fs/cgroup/cpu.max", "150000 100000\n")
	approx(t, tr.resolve(), 1.5)
}

func TestResolveV2SubtreeMountRoot(t *testing.T) {
	// mount root is the cgroup itself (container without cgroupns)
	tr := newCgTree(t, "0::/docker/abc\n", mi2Sub)
	tr.file("sys/fs/cgroup/cpu.max", "50000 100000\n")
	approx(t, tr.resolve(), 0.5)
	// cgroup nested below the mount root
	tr = newCgTree(t, "0::/docker/abc/leaf\n", mi2Sub)
	tr.file("sys/fs/cgroup/cpu.max", "200000 100000\n")
	tr.file("sys/fs/cgroup/leaf/cpu.max", "100000 100000\n")
	approx(t, tr.resolve(), 1)
	// cgroup outside the mount root: unresolved, the caller falls back
	tr = newCgTree(t, "0::/elsewhere/x\n", mi2Sub)
	tr.file("sys/fs/cgroup/cpu.max", "300000 100000\n")
	tr.file("sys/fs/cgroup/elsewhere/x/cpu.max", "100000 100000\n")
	approx(t, tr.resolve(), 0)
}

func TestResolveV2NestedMostRestrictive(t *testing.T) {
	cg := "0::/system.slice/mailstrix.service\n"
	// slice tighter than the leaf
	tr := newCgTree(t, cg, mi2Root)
	tr.file("sys/fs/cgroup/system.slice/mailstrix.service/cpu.max", "400000 100000\n")
	tr.file("sys/fs/cgroup/system.slice/cpu.max", "200000 100000\n")
	tr.file("sys/fs/cgroup/cpu.max", "max 100000\n")
	approx(t, tr.resolve(), 2)
	// leaf tighter than the slice
	tr = newCgTree(t, cg, mi2Root)
	tr.file("sys/fs/cgroup/system.slice/mailstrix.service/cpu.max", "50000 100000\n")
	tr.file("sys/fs/cgroup/system.slice/cpu.max", "200000 100000\n")
	approx(t, tr.resolve(), 0.5)
	// only an ancestor limits
	tr = newCgTree(t, cg, mi2Root)
	tr.file("sys/fs/cgroup/system.slice/mailstrix.service/cpu.max", "max 100000\n")
	tr.file("sys/fs/cgroup/system.slice/cpu.max", "250000 100000\n")
	approx(t, tr.resolve(), 2.5)
}

func TestResolveUnlimited(t *testing.T) {
	tr := newCgTree(t, "0::/a/b\n", mi2Root)
	for _, d := range []string{"", "a", "a/b"} {
		tr.file(filepath.Join("sys/fs/cgroup", d, "cpu.max"), "max 100000\n")
	}
	approx(t, tr.resolve(), 0)
}

func TestResolveV1(t *testing.T) {
	for name, mi := range map[string]string{"separate": miV1Sep, "combined": miV1Combo} {
		t.Run(name, func(t *testing.T) {
			point := "sys/fs/cgroup/cpu"
			if name == "combined" {
				point = "sys/fs/cgroup/cpu,cpuacct"
			}
			ctrl := "4:cpu"
			if name == "combined" {
				ctrl = "4:cpu,cpuacct"
			}
			tr := newCgTree(t, "12:memory:/x\n"+ctrl+":/system.slice/m.service\n", mi)
			tr.file(point+"/system.slice/m.service/cpu.cfs_quota_us", "-1\n")
			tr.file(point+"/system.slice/m.service/cpu.cfs_period_us", "100000\n")
			tr.file(point+"/system.slice/cpu.cfs_quota_us", "200000\n")
			tr.file(point+"/system.slice/cpu.cfs_period_us", "100000\n")
			tr.file(point+"/cpu.cfs_quota_us", "-1\n")
			tr.file(point+"/cpu.cfs_period_us", "100000\n")
			approx(t, tr.resolve(), 2)
		})
	}
}

func TestResolveV1AllUnlimited(t *testing.T) {
	tr := newCgTree(t, "4:cpu,cpuacct:/\n", miV1Combo)
	tr.file("sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us", "-1\n")
	tr.file("sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us", "100000\n")
	approx(t, tr.resolve(), 0)
}

func TestResolveHybridPicksTighter(t *testing.T) {
	tr := newCgTree(t, "4:cpu:/\n0::/\n", miV1Sep+mi2Root)
	tr.file("sys/fs/cgroup/cpu/cpu.cfs_quota_us", "100000\n")
	tr.file("sys/fs/cgroup/cpu/cpu.cfs_period_us", "100000\n")
	tr.file("sys/fs/cgroup/cpu.max", "300000 100000\n")
	approx(t, tr.resolve(), 1)
	tr.file("sys/fs/cgroup/cpu.max", "50000 100000\n")
	approx(t, tr.resolve(), 0.5)
}

func TestResolveFallbackNoPanic(t *testing.T) {
	huge := strings.Repeat("9", 400)
	cases := map[string]struct{ cg, mi, cpuMax string }{
		"empty cgroup file":   {"\n", mi2Root, "100000 100000"},
		"malformed cgroup":    {"garbage\n::\n1:2\n", mi2Root, "100000 100000"},
		"v1 without cpu":      {"4:memory:/x\n", miV1Sep, "100000 100000"},
		"malformed mountinfo": {"0::/\n", "junk\n1 2 3 4 5 - cgroup2\n1 2 3 4 5 6 - cgroup2 cgroup2\na b c d e f g\n", "100000 100000"},
		"non-cgroup mounts":   {"0::/\n", "1 2 0:1 / /proc rw - proc proc rw\n32 25 0:9 / /x rw - cgroup cgroup rw,memory\n", "100000 100000"},
		"no mount for v2":     {"0::/\n", miV1Sep, "100000 100000"},
		"malformed cpu.max":   {"0::/\n", mi2Root, "abc def"},
		"one field cpu.max":   {"0::/\n", mi2Root, "100000"},
		"period zero":         {"0::/\n", mi2Root, "100000 0"},
		"negative quota":      {"0::/\n", mi2Root, "-5 100000"},
		"negative period":     {"0::/\n", mi2Root, "100000 -1"},
		"overflow quota":      {"0::/\n", mi2Root, huge + " 100000"},
		"overflow period":     {"0::/\n", mi2Root, "100000 " + huge},
		"NaN":                 {"0::/\n", mi2Root, "NaN 100000"},
		"inf ratio":           {"0::/\n", mi2Root, "1e308 1e-308"},
		"dotdot path cleaned": {"0::/../../etc\n", mi2Root, "abc def"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newCgTree(t, c.cg, c.mi)
			tr.file("sys/fs/cgroup/cpu.max", c.cpuMax)
			got := tr.resolve()
			if got != 0 || math.IsNaN(got) {
				t.Fatalf("got %v, want 0", got)
			}
		})
	}
}

func TestResolveV1Malformed(t *testing.T) {
	cases := map[string][2]string{
		"missing period":    {"100000", ""},
		"multi-field quota": {"1 2", "100000"},
		"multi-field per":   {"100000", "1 2"},
		"text quota":        {"abc", "100000"},
		"zero period":       {"100000", "0"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newCgTree(t, "4:cpu:/\n", miV1Sep)
			tr.file("sys/fs/cgroup/cpu/cpu.cfs_quota_us", c[0])
			if c[1] != "" {
				tr.file("sys/fs/cgroup/cpu/cpu.cfs_period_us", c[1])
			}
			approx(t, tr.resolve(), 0)
		})
	}
	// quota file absent entirely
	tr := newCgTree(t, "4:cpu:/\n", miV1Sep)
	approx(t, tr.resolve(), 0)
}

func TestResolveMissingAndUnreadableFiles(t *testing.T) {
	d := t.TempDir()
	if got := resolveCgroupCPUQuota(filepath.Join(d, "none"), filepath.Join(d, "none2"), d); got != 0 {
		t.Fatalf("missing proc files: %v", got)
	}
	// cgroup readable, mountinfo missing
	tr := newCgTree(t, "0::/\n", "")
	approx(t, tr.resolve(), 0)
	// a directory in place of a file: open succeeds, read fails
	if _, ok := readCgroupFile(d, cgroupReadCap); ok {
		t.Fatal("directory read must fail")
	}
}

func TestResolveReadIsBounded(t *testing.T) {
	// A control file larger than the cap is rejected, not parsed truncated.
	tr := newCgTree(t, "0::/\n", mi2Root)
	tr.file("sys/fs/cgroup/cpu.max", "100000 100000\n"+strings.Repeat("x", 3*cgroupReadCap))
	if got := tr.resolve(); got != 0 {
		t.Fatalf("got %v", got)
	}
	if _, ok := readCgroupFile(filepath.Join(tr.sys, "sys/fs/cgroup/cpu.max"), cgroupReadCap); ok {
		t.Fatal("oversized file must be rejected")
	}
	// Boundary: exactly cap bytes is accepted.
	tr.file("exact", strings.Repeat("y", cgroupReadCap))
	if s, ok := readCgroupFile(filepath.Join(tr.sys, "exact"), cgroupReadCap); !ok || len(s) != cgroupReadCap {
		t.Fatalf("exact cap: len=%d ok=%v", len(s), ok)
	}
}

func TestResolveLargeMountinfo(t *testing.T) {
	// mountinfo past 64 KiB (busy container host) with the cgroup2 mount last
	// must still resolve; a 64 KiB cap would cut it off and fall back.
	pad := strings.Repeat("99 25 0:99 / /var/lib/docker/overlay2/"+strings.Repeat("a", 200)+"/merged rw - overlay overlay rw\n", 1000)
	tr := newCgTree(t, "0::/system.slice/mailstrix.service\n", pad+mi2Root)
	tr.file("sys/fs/cgroup/system.slice/mailstrix.service/cpu.max", "50000 100000\n")
	approx(t, tr.resolve(), 0.5)
	// Negative: a mountinfo past its own cap is rejected and the resolver falls back.
	huge := strings.Repeat("x", mountinfoReadCap) + "\n" + mi2Root
	tr2 := newCgTree(t, "0::/system.slice/mailstrix.service\n", huge)
	tr2.file("sys/fs/cgroup/system.slice/mailstrix.service/cpu.max", "50000 100000\n")
	approx(t, tr2.resolve(), 0)
}

func TestResolveIgnoresUnrelatedBindMount(t *testing.T) {
	// The process cgroup is exposed by the root cgroup2 mount; an extra bind
	// mount of an unrelated subtree must not tighten the result.
	other := "40 25 0:26 /other /mnt/other rw - cgroup2 cgroup2 rw\n"
	tr := newCgTree(t, "0::/system.slice/mailstrix.service\n", mi2Root+other)
	tr.file("sys/fs/cgroup/system.slice/mailstrix.service/cpu.max", "200000 100000\n")
	tr.file("mnt/other/cpu.max", "25000 100000\n")
	approx(t, tr.resolve(), 2)
	// No mount exposes the cgroup: no unrelated quota is borrowed.
	tr = newCgTree(t, "0::/service\n", other)
	tr.file("mnt/other/cpu.max", "25000 100000\n")
	approx(t, tr.resolve(), 0)
}

func TestResolveMountinfoEscapes(t *testing.T) {
	// The kernel writes "/tenant one" as "/tenant\040one" in mountinfo, while
	// /proc/self/cgroup reports the raw path.
	mi := "30 25 0:26 /tenant\\040one /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"
	tr := newCgTree(t, "0::/tenant one/worker\n", mi)
	tr.file("sys/fs/cgroup/worker/cpu.max", "50000 100000\n")
	approx(t, tr.resolve(), 0.5)
	// An escaped mount point is decoded too.
	mi = "30 25 0:26 / /cg\\134x\\040y rw - cgroup2 cgroup2 rw\n"
	tr = newCgTree(t, "0::/\n", mi)
	tr.file(`cg\x y/cpu.max`, "150000 100000\n")
	approx(t, tr.resolve(), 1.5)
}

func TestUnescapeMountinfo(t *testing.T) {
	for in, want := range map[string]string{
		"plain":        "plain",
		`a\040b`:       "a b",
		`\011\012\134`: "\t\n\\",
		`end\040`:      "end ",
		`short\04`:     `short\04`, // truncated escape kept
		`bad\08x`:      `bad\08x`,  // non-octal digit kept
		`big\400`:      `big\400`,  // above one byte kept
		`trail\`:       `trail\`,
	} {
		if got := unescapeMountinfo(in); got != want {
			t.Errorf("unescapeMountinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveDotDotStaysInsideMount(t *testing.T) {
	tr := newCgTree(t, "0::/../../etc\n", mi2Root)
	tr.file("sys/fs/cgroup/cpu.max", "abc def")
	// Without path cleaning, the .. segments would climb out of the mount
	// point to these files.
	tr.file("sys/etc/cpu.max", "100000 100000\n")
	tr.file("etc/cpu.max", "100000 100000\n")
	approx(t, tr.resolve(), 0)
}

func TestResolveMountRootOutsideNamespace(t *testing.T) {
	// Host hierarchy bind-mounted into a private cgroupns: the kernel reports
	// the mount root as "/../.." and the process path relative to its namespace.
	mi := "30 25 0:26 /../.. /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"
	tr := newCgTree(t, "0::/svc\n", mi)
	tr.file("sys/fs/cgroup/svc/cpu.max", "25000 100000\n") // an unrelated host cgroup
	approx(t, tr.resolve(), 0)
	if hasDotDot("/a/b") || !hasDotDot("/a/../b") || hasDotDot("/a..b") {
		t.Fatal("hasDotDot component matching")
	}
}

func TestLevelDirsAndParsers(t *testing.T) {
	got := levelDirs("/r", cgroupMount{root: "/", point: "/sys/fs/cgroup"}, "/a/b")
	want := []string{"/r/sys/fs/cgroup/a/b", "/r/sys/fs/cgroup/a", "/r/sys/fs/cgroup"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("levelDirs = %v, want %v", got, want)
	}
	if v2, v1 := parseProcSelfCgroup("0::/p\n3:cpu,cpuacct:/q\n"); v2 != "/p" || v1 != "/q" {
		t.Fatalf("parseProcSelfCgroup = %q %q", v2, v1)
	}
}

func TestCgroupCPUQuotaRealPathsSane(t *testing.T) {
	q := cgroupCPUQuota()
	if math.IsNaN(q) || math.IsInf(q, 0) || q < 0 {
		t.Fatalf("cgroupCPUQuota() = %v", q)
	}
}
