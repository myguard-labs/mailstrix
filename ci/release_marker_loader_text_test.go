package ci_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// docker/release-marker-toolchain.sh tells a marker-capable strixd from a
// legacy one by grepping the binary for the loader's fallback log text. If
// that text is reworded, a marker-capable release published without its
// yarac/libyara assets is misread as legacy and ships with no marker
// artifact instead of failing the build. Keep the two in lockstep.
func TestReleaseMarkerHelperMatchesLoaderFallbackText(t *testing.T) {
	script, err := os.ReadFile("../docker/release-marker-toolchain.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`grep -qaF '([^']+)' "\$strixd"`).FindAllSubmatch(script, -1)
	if len(m) != 1 {
		t.Fatalf("want one strixd marker-capability probe in the helper, got %d", len(m))
	}
	probe := string(m[0][1])
	loader, err := os.ReadFile("../internal/mailstrix/marker_artifact.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(loader), `s.logf("PERF-18: `+probe) {
		t.Fatalf("marker loader no longer logs %q; update docker/release-marker-toolchain.sh", probe)
	}
}
