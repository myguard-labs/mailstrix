package mailstrix

import (
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// cgroupReadCap bounds reads of /proc/self/cgroup and the cgroup control
// files, which are tiny.
const cgroupReadCap = 64 << 10

// mountinfoReadCap bounds /proc/self/mountinfo, which has one line per mount
// in the namespace and can exceed 64 KiB on a busy container host.
const mountinfoReadCap = 4 << 20

// cgroupMount is one cgroup mount from /proc/self/mountinfo.
type cgroupMount struct {
	root  string // mountinfo field 4: the mounted subtree of the hierarchy
	point string // mountinfo field 5: where it is mounted
}

// readCgroupFile reads at most limit bytes. A file larger than limit is
// rejected rather than parsed truncated, so the caller falls back instead of
// silently missing data past the cut.
func readCgroupFile(p string, limit int64) (string, bool) {
	f, err := os.Open(p) // #nosec G304 -- proc/cgroup path built by the resolver
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return "", false
	}
	return string(b), true
}

// parseProcSelfCgroup returns the process's cgroup path for the unified (v2)
// hierarchy and for the v1 hierarchy carrying the cpu controller. Empty means
// not present. Malformed lines are skipped.
func parseProcSelfCgroup(content string) (v2Path, v1Path string) {
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			v2Path = parts[2]
		case parts[1] != "":
			for _, c := range strings.Split(parts[1], ",") {
				if c == "cpu" {
					v1Path = parts[2]
				}
			}
		}
	}
	return v2Path, v1Path
}

// parseMountinfo returns the cgroup2 mounts and the v1 mounts with the cpu
// controller. Malformed lines are skipped.
func parseMountinfo(content string) (v2, v1 []cgroupMount) {
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, tok := range f {
			if tok == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(f) < sep+4 {
			continue
		}
		m := cgroupMount{root: unescapeMountinfo(f[3]), point: unescapeMountinfo(f[4])}
		switch f[sep+1] {
		case "cgroup2":
			v2 = append(v2, m)
		case "cgroup":
			for _, c := range strings.Split(f[sep+3], ",") {
				if c == "cpu" {
					v1 = append(v1, m)
					break
				}
			}
		}
	}
	return v2, v1
}

// unescapeMountinfo decodes the kernel's octal escapes in mountinfo path
// fields (\040 space, \011 tab, \012 newline, \134 backslash). Anything that
// is not a valid three-digit octal escape of one byte (\000-\377) is kept
// verbatim.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] >= '0' && s[i+1] <= '3' && isOctal(s[i+2]) && isOctal(s[i+3]) {
			v := (s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0')
			b.WriteByte(v)
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

func hasDotDot(p string) bool {
	for _, c := range strings.Split(p, "/") {
		if c == ".." {
			return true
		}
	}
	return false
}

// levelDirs returns the directories from the process's cgroup directory up to
// the mount point, leaf first. A path outside the mount's root yields the mount
// point alone; minQuota skips such mounts via mountContains.
func levelDirs(sysroot string, m cgroupMount, cgPath string) []string {
	base := filepath.Join(sysroot, filepath.FromSlash(path.Clean("/"+m.point)))
	root := path.Clean("/" + m.root)
	cg := path.Clean("/" + cgPath)
	rel := ""
	switch {
	case cg == root:
	case root == "/":
		rel = strings.TrimPrefix(cg, "/")
	case strings.HasPrefix(cg, root+"/"):
		rel = strings.TrimPrefix(cg, root+"/")
	}
	dirs := []string{base}
	if rel == "" {
		return dirs
	}
	comps := strings.Split(rel, "/")
	dirs = dirs[:0]
	for i := len(comps); i >= 0; i-- {
		dirs = append(dirs, filepath.Join(append([]string{base}, comps[:i]...)...))
	}
	return dirs
}

// quotaV2At parses "$quota $period" ("max" = unlimited); 0 means no usable limit.
func quotaV2At(dir string) float64 {
	s, ok := readCgroupFile(filepath.Join(dir, "cpu.max"), cgroupReadCap)
	if !ok {
		return 0
	}
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0
	}
	return safeRatio(f[0], f[1])
}

// quotaV1At parses cpu.cfs_quota_us / cpu.cfs_period_us (quota -1 = unlimited).
func quotaV1At(dir string) float64 {
	q, ok := readCgroupFile(filepath.Join(dir, "cpu.cfs_quota_us"), cgroupReadCap)
	if !ok {
		return 0
	}
	p, ok := readCgroupFile(filepath.Join(dir, "cpu.cfs_period_us"), cgroupReadCap)
	if !ok {
		return 0
	}
	qf, pf := strings.Fields(q), strings.Fields(p)
	if len(qf) != 1 || len(pf) != 1 {
		return 0
	}
	return safeRatio(qf[0], pf[0])
}

// safeRatio returns quota/period, or 0 for max, non-numeric, non-finite,
// non-positive or overflowing values.
func safeRatio(quota, period string) float64 {
	q, err := strconv.ParseFloat(quota, 64)
	if err != nil || !(q > 0) || math.IsInf(q, 0) {
		return 0
	}
	p, err := strconv.ParseFloat(period, 64)
	if err != nil || !(p > 0) || math.IsInf(p, 0) {
		return 0
	}
	r := q / p
	if math.IsNaN(r) || math.IsInf(r, 0) || r <= 0 {
		return 0
	}
	return r
}

// mountContains reports whether the cgroup path lies at or below the mount's
// root, i.e. the mount actually exposes the process's cgroup. A ".." component
// in either path means it lies outside the process's cgroup namespace, which
// cannot be mapped reliably, so it never matches.
func mountContains(m cgroupMount, cgPath string) bool {
	if hasDotDot(m.root) || hasDotDot(cgPath) {
		return false
	}
	root := path.Clean("/" + m.root)
	cg := path.Clean("/" + cgPath)
	return root == "/" || cg == root || strings.HasPrefix(cg, root+"/")
}

// minQuota walks every level of each mount that exposes the process's cgroup
// and returns the smallest quota > 0. Mounts of unrelated subtrees are
// skipped; if none exposes the cgroup the result is 0 (unresolved) and the
// caller falls back to the fixed container paths.
func minQuota(sysroot string, mounts []cgroupMount, cgPath string, at func(string) float64) float64 {
	best := 0.0
	for _, m := range mounts {
		if !mountContains(m, cgPath) {
			continue
		}
		for _, dir := range levelDirs(sysroot, m, cgPath) {
			if q := at(dir); q > 0 && (best == 0 || q < best) {
				best = q
			}
		}
	}
	return best
}

// resolveCgroupCPUQuota finds the process's own cgroup (procCgroup =
// /proc/self/cgroup), maps it onto the cgroup mounts (mountinfo =
// /proc/self/mountinfo, mount points prefixed with sysroot) and returns the most
// restrictive CPU quota, in CPUs, found from the cgroup up to the mount root.
// 0 means unlimited or unresolvable; the caller then falls back.
func resolveCgroupCPUQuota(procCgroup, mountinfo, sysroot string) float64 {
	cgc, ok := readCgroupFile(procCgroup, cgroupReadCap)
	if !ok {
		return 0
	}
	mic, ok := readCgroupFile(mountinfo, mountinfoReadCap)
	if !ok {
		return 0
	}
	v2Path, v1Path := parseProcSelfCgroup(cgc)
	v2m, v1m := parseMountinfo(mic)
	best := 0.0
	if v2Path != "" {
		best = minQuota(sysroot, v2m, v2Path, quotaV2At)
	}
	if v1Path != "" {
		if q := minQuota(sysroot, v1m, v1Path, quotaV1At); q > 0 && (best == 0 || q < best) {
			best = q
		}
	}
	return best
}
