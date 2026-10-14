package ci_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

type byteBoundEngine struct {
	memoryEngine
	scans atomic.Uint64
}

func (e *byteBoundEngine) Scan([]byte, ms.ScanMeta) ([]ms.Match, error) {
	e.scans.Add(1)
	return []ms.Match{{
		Rule:      strings.Repeat("complete-rule-", 70),
		Namespace: "full-ruleset.yar",
		Tags:      []string{"document", "malware"},
		Meta:      map[string]string{"author": "fixture", "description": strings.Repeat("m", 160)},
	}, {
		Rule:      "secondary-rule",
		Namespace: "secondary-ruleset.yar",
		Tags:      []string{"secondary", "ordered"},
		Meta:      map[string]string{"score": "7", "source": "fixture-two"},
	}}, nil
}

func cachePost(t *testing.T, s *ms.Server, body string) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("scan status=%d body=%s", w.Code, w.Body.String())
	}
	return append([]byte(nil), w.Body.Bytes()...)
}

func cacheMetrics(t *testing.T, s *ms.Server) (string, map[string]uint64) {
	t.Helper()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("metrics status=%d", w.Code)
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(w.Body.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.HasPrefix(line, "#") {
			continue
		}
		if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
			values[fields[0]] = value
		}
	}
	return w.Body.String(), values
}

func TestCacheByteBoundCompleteResponseAndMetrics(t *testing.T) {
	engine := &byteBoundEngine{}
	cfg := &ms.Config{
		MaxConcurrent: 1,
		MaxInflight:   2,
		MaxBody:       4096,
		CacheTTL:      time.Minute,
		CacheSize:     10,
		CacheMaxBytes: 2500,
	}
	s := ms.NewServer(cfg, engine)
	miss := cachePost(t, s, "same-body")
	hit := cachePost(t, s, "same-body")
	if string(hit) != string(miss) {
		t.Fatalf("cache hit JSON differs from miss:\nmiss=%s\nhit=%s", miss, hit)
	}
	if engine.scans.Load() != 1 {
		t.Fatalf("same body scanned %d times, want one miss then a hit", engine.scans.Load())
	}
	var decoded struct {
		Matches []ms.Match `json:"matches"`
	}
	if err := json.Unmarshal(hit, &decoded); err != nil {
		t.Fatal(err)
	}
	want := []ms.Match{{
		Rule:      strings.Repeat("complete-rule-", 70),
		Namespace: "full-ruleset.yar",
		Tags:      []string{"document", "malware"},
		Meta:      map[string]string{"author": "fixture", "description": strings.Repeat("m", 160)},
	}, {
		Rule:      "secondary-rule",
		Namespace: "secondary-ruleset.yar",
		Tags:      []string{"secondary", "ordered"},
		Meta:      map[string]string{"score": "7", "source": "fixture-two"},
	}}
	if !reflect.DeepEqual(decoded.Matches, want) {
		t.Fatalf("cache hit lost or reordered complete matches: got=%+v want=%+v", decoded.Matches, want)
	}

	for _, body := range []string{"body-a", "body-b", "body-c"} {
		cachePost(t, s, body)
	}
	metrics, values := cacheMetrics(t, s)
	for _, typ := range []string{
		"# TYPE mailstrix_cache_bytes gauge\n",
		"# TYPE mailstrix_cache_evictions_total counter\n",
		"# TYPE mailstrix_cache_evictions_bytes_total counter\n",
		"# TYPE mailstrix_cache_evictions_count_total counter\n",
	} {
		if !strings.Contains(metrics, typ) {
			t.Fatalf("missing metric type %q", typ)
		}
	}
	if values["mailstrix_cache_bytes"] == 0 || values["mailstrix_cache_bytes"] > 2500 {
		t.Fatalf("cache bytes=%d budget=%d", values["mailstrix_cache_bytes"], cfg.CacheMaxBytes)
	}
	if values["mailstrix_cache_evictions_bytes_total"] == 0 || values["mailstrix_cache_evictions_count_total"] != 0 {
		t.Fatalf("eviction causes byte=%d count=%d", values["mailstrix_cache_evictions_bytes_total"], values["mailstrix_cache_evictions_count_total"])
	}
	if values["mailstrix_cache_evictions_total"] != values["mailstrix_cache_evictions_bytes_total"]+values["mailstrix_cache_evictions_count_total"] {
		t.Fatalf("total eviction compatibility metric disagrees with causes: %+v", values)
	}
}

func TestCacheEntryCountEvictionCause(t *testing.T) {
	engine := &byteBoundEngine{}
	s := ms.NewServer(&ms.Config{
		MaxConcurrent: 1,
		MaxInflight:   2,
		MaxBody:       4096,
		CacheTTL:      time.Minute,
		CacheSize:     1,
		CacheMaxBytes: 1 << 20,
	}, engine)
	cachePost(t, s, "count-a")
	cachePost(t, s, "count-b")
	metrics, values := cacheMetrics(t, s)
	if metrics == "" {
		t.Fatal("empty metrics response")
	}
	if values["mailstrix_cache_evictions_count_total"] != 1 || values["mailstrix_cache_evictions_bytes_total"] != 0 || values["mailstrix_cache_evictions_total"] != 1 {
		t.Fatalf("count eviction metrics: %+v", values)
	}
}
