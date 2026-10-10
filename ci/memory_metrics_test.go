package ci_test

import (
	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
	"github.com/myguard-labs/mailstrix/internal/mbazaar"
	"github.com/myguard-labs/mailstrix/internal/threatfox"
	"github.com/myguard-labs/mailstrix/internal/urlhaus"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type memoryEngine struct{ ms.ScanEngine }

func (f *memoryEngine) RuleCount() int64                    { return 7 }
func (f *memoryEngine) BigFileScans() uint64                { return 0 }
func (f *memoryEngine) BigFileStreamScans() uint64          { return 0 }
func (f *memoryEngine) RawChannelScans() uint64             { return 0 }
func (f *memoryEngine) StreamChannelScans() uint64          { return 0 }
func (f *memoryEngine) MarkerChannelScans() uint64          { return 0 }
func (f *memoryEngine) RawScanErrs() uint64                 { return 0 }
func (f *memoryEngine) Fingerprint() string                 { return "test" }
func (f *memoryEngine) ExtractMetrics() ms.ExtractMetrics   { return ms.ExtractMetrics{} }
func (f *memoryEngine) ReloadMetrics() ms.ReloadMetrics     { return ms.ReloadMetrics{} }
func (f *memoryEngine) URLhausMetrics() urlhaus.Metrics     { return urlhaus.Metrics{} }
func (f *memoryEngine) MBazaarMetrics() mbazaar.Metrics     { return mbazaar.Metrics{} }
func (f *memoryEngine) ThreatFoxMetrics() threatfox.Metrics { return threatfox.Metrics{} }
func (f *memoryEngine) TopMatches(n int) []ms.MatchCount    { return nil }

func TestMemoryMetrics(t *testing.T) {
	s := ms.NewServer(&ms.Config{MaxConcurrent: 1, MaxInflight: 1, MaxBody: 4096, CacheSize: 1}, &memoryEngine{})
	scrape := func() map[string]uint64 {
		t.Helper()
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("scrape status=%d", w.Code)
		}
		values := map[string]uint64{}
		for _, line := range strings.Split(w.Body.String(), "\n") {
			parts := strings.Fields(line)
			if len(parts) == 2 && !strings.HasPrefix(line, "#") {
				v, err := strconv.ParseUint(parts[1], 10, 64)
				if err == nil {
					values[parts[0]] = v
				}
			}
		}
		for _, name := range []string{"mailstrix_rss_bytes", "mailstrix_heap_inuse_bytes", "mailstrix_cgroup_mem_limit_bytes"} {
			if _, ok := values[name]; !ok {
				t.Fatalf("missing metric %s", name)
			}
			if !strings.Contains(w.Body.String(), "# TYPE "+name+" gauge\n") {
				t.Fatalf("missing gauge type %s", name)
			}
		}
		if values["mailstrix_rss_bytes"] == 0 || values["mailstrix_heap_inuse_bytes"] == 0 {
			t.Fatal("live memory metrics must be positive")
		}
		if values["mailstrix_rules"] != 7 {
			t.Fatal("existing rules metric changed")
		}
		return values
	}
	// Reclaim allocations from earlier runs before sampling the baseline.
	runtime.GC()
	before := scrape()
	held := make([]byte, 32<<20)
	for i := range held {
		held[i] = byte(i)
	}
	after := scrape()
	runtime.KeepAlive(held)
	if after["mailstrix_heap_inuse_bytes"] <= before["mailstrix_heap_inuse_bytes"] {
		t.Fatal("heap gauge did not sample live allocation on second scrape")
	}
}
