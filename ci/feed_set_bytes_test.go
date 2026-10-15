package ci

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
	"github.com/myguard-labs/mailstrix/internal/mbazaar"
	"github.com/myguard-labs/mailstrix/internal/threatfox"
	"github.com/myguard-labs/mailstrix/internal/urlhaus"
)

// feedSetPerEntry mirrors the per-entry overhead in feedrefresh.SetBytes
// estimates. The known-size expectations below are written out from literal
// key lengths so a change to either side is visible.
const feedSetPerEntry = 24

// feedSetBase supplies the scan-engine counters the metrics handler reads.
// It mirrors memoryEngine in memory_metrics_test.go, which lives in the
// external ci_test package and cannot be shared with these tests.
type feedSetBase struct{ ms.ScanEngine }

func (feedSetBase) RuleCount() int64                  { return 7 }
func (feedSetBase) BigFileScans() uint64              { return 0 }
func (feedSetBase) BigFileStreamScans() uint64        { return 0 }
func (feedSetBase) RawChannelScans() uint64           { return 0 }
func (feedSetBase) StreamChannelScans() uint64        { return 0 }
func (feedSetBase) MarkerChannelScans() uint64        { return 0 }
func (feedSetBase) RawScanErrs() uint64               { return 0 }
func (feedSetBase) Fingerprint() string               { return "test" }
func (feedSetBase) ExtractMetrics() ms.ExtractMetrics { return ms.ExtractMetrics{} }
func (feedSetBase) ReloadMetrics() ms.ReloadMetrics   { return ms.ReloadMetrics{} }
func (feedSetBase) TopMatches(n int) []ms.MatchCount  { return nil }

// feedSetEngine serves real checkers to the /metrics handler. Only the feed
// under test is non-nil; a nil checker reports the disabled zero Metrics.
type feedSetEngine struct {
	feedSetBase
	uh *urlhaus.Checker
	mb *mbazaar.Checker
	tf *threatfox.Checker
}

func (f *feedSetEngine) URLhausMetrics() urlhaus.Metrics {
	if f.uh == nil {
		return urlhaus.Metrics{}
	}
	return f.uh.Metrics()
}

func (f *feedSetEngine) MBazaarMetrics() mbazaar.Metrics {
	if f.mb == nil {
		return mbazaar.Metrics{}
	}
	return f.mb.Metrics()
}

func (f *feedSetEngine) ThreatFoxMetrics() threatfox.Metrics {
	if f.tf == nil {
		return threatfox.Metrics{}
	}
	return f.tf.Metrics()
}

// setBytes returns the SetBytes snapshot for the named feed.
func (f *feedSetEngine) setBytes(feed string) int64 {
	switch feed {
	case "urlhaus":
		return f.URLhausMetrics().SetBytes
	case "malwarebazaar":
		return f.MBazaarMetrics().SetBytes
	case "threatfox":
		return f.ThreatFoxMetrics().SetBytes
	}
	panic("unknown feed " + feed)
}

func (f *feedSetEngine) closeAll() {
	f.uh.Close()
	f.mb.Close()
	f.tf.Close()
}

// scrapeFeedSetBytes returns the mailstrix_feed_set_bytes series keyed by feed
// label and fails the test when the family header is malformed.
func scrapeFeedSetBytes(t *testing.T, eng ms.ScanEngine) map[string]int64 {
	t.Helper()
	s := ms.NewServer(&ms.Config{MaxConcurrent: 1, MaxInflight: 1, MaxBody: 4096, CacheSize: 1}, eng)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("scrape status=%d", w.Code)
	}
	body := w.Body.String()
	declared := strings.Count(body, "# TYPE mailstrix_feed_set_bytes gauge\n")
	out := map[string]int64{}
	const prefix = `mailstrix_feed_set_bytes{feed="`
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimPrefix(line, prefix)
		feed, value, ok := strings.Cut(rest, `"} `)
		if !ok {
			t.Fatalf("malformed series line %q", line)
		}
		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			t.Fatalf("series %q value: %v", line, err)
		}
		out[feed] = v
	}
	if declared > 1 || (len(out) > 0 && declared != 1) {
		t.Fatalf("feed_set_bytes family declared %d times with %d series, want exactly 1 declaration", declared, len(out))
	}
	return out
}

// feedSetEstimate is the expected estimate for keys of the given lengths in a
// string-keyed set.
func feedSetEstimate(lens ...int) int64 {
	var n int64
	for _, l := range lens {
		n += int64(l + feedSetPerEntry)
	}
	return n
}

type feedSetCase struct {
	feed  string
	rows  []string // two good feed rows, each adding one URL and one host/domain (or one hash)
	empty string   // a 200 body that parses to zero entries
	want  int64    // known estimate for the good rows
	// cache is the file name the constructor warm-starts from in its cache dir.
	cache string
	start func(cacheDir string, logf func(string, ...any)) *feedSetEngine
}

const (
	fsURL1  = "http://fixture.example/x"
	fsURL2  = "http://other.example/y"
	fsHost  = "fixture.example"
	fsHost2 = "other.example"
)

func feedSetCases() []feedSetCase {
	hash1 := fmt.Sprintf("%x", sha256.Sum256([]byte("sample one")))
	hash2 := fmt.Sprintf("%x", sha256.Sum256([]byte("sample two")))
	return []feedSetCase{
		{
			feed: "urlhaus",
			rows: []string{
				fmt.Sprintf("\"1\",\"2024-01-01\",\"%s\",\"online\"\n", fsURL1),
				fmt.Sprintf("\"2\",\"2024-01-01\",\"%s\",\"online\"\n", fsURL2),
			},
			empty: "# no rows\n",
			// urls: two full URLs; hosts: the two bare hosts.
			want:  feedSetEstimate(len(fsURL1), len(fsURL2), len(fsHost), len(fsHost2)),
			cache: "urlhaus.csv",
			start: func(dir string, logf func(string, ...any)) *feedSetEngine {
				return &feedSetEngine{uh: urlhaus.New("fixture-key", time.Hour, dir, logf)}
			},
		},
		{
			feed: "threatfox",
			rows: []string{
				fmt.Sprintf("\"2024-01-01\",\"1\",\"%s\",\"url\"\n", fsURL1),
				fmt.Sprintf("\"2024-01-01\",\"2\",\"%s\",\"url\"\n", fsURL2),
			},
			empty: "# no rows\n",
			want:  feedSetEstimate(len(fsURL1), len(fsURL2), len(fsHost), len(fsHost2)),
			cache: "threatfox.csv",
			start: func(dir string, logf func(string, ...any)) *feedSetEngine {
				return &feedSetEngine{tf: threatfox.New("fixture-key", time.Hour, dir, logf)}
			},
		},
		{
			feed: "malwarebazaar",
			rows: []string{
				fmt.Sprintf("\"2024-01-01\",\"%s\",\"md5\"\n", hash1),
				fmt.Sprintf("\"2024-01-01\",\"%s\",\"md5\"\n", hash2),
			},
			empty: "# no rows\n",
			// Two 32-byte digests in a sorted slice: 2*32 bytes + 24-byte slice
			// header (mbazaar.hashSet.bytes; no per-entry overhead).
			want:  2*32 + 24,
			cache: "malwarebazaar.bin",
			start: func(dir string, logf func(string, ...any)) *feedSetEngine {
				return &feedSetEngine{mb: mbazaar.New("fixture-key", time.Hour, "https://feed.invalid/", dir, logf)}
			},
		},
	}
}

// feedSetServe makes the fake feed return body; the closure reads body on
// every request so a test can change the response between refreshes.
func feedSetServe(t *testing.T, requests *int, status func(int) int, body func(int) string) {
	t.Helper()
	feedUseTransport(t, func(*http.Request) (*http.Response, error) {
		*requests++
		return &http.Response{
			StatusCode: status(*requests),
			Body:       io.NopCloser(strings.NewReader(body(*requests))),
			Header:     make(http.Header),
		}, nil
	})
}

func TestFeedSetBytesKnownSize(t *testing.T) {
	for _, c := range feedSetCases() {
		t.Run(c.feed, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				body := strings.Join(c.rows, "")
				requests := 0
				feedSetServe(t, &requests,
					func(int) int { return http.StatusOK },
					func(int) string { return body })
				loaded := make(chan struct{})
				eng := c.start("", func(msg string, _ ...any) {
					if strings.Contains(msg, "feed loaded") {
						loaded <- struct{}{}
					}
				})
				<-loaded
				defer eng.closeAll()
				if got := eng.setBytes(c.feed); got != c.want {
					t.Fatalf("%s set bytes = %d, want %d", c.feed, got, c.want)
				}
				series := scrapeFeedSetBytes(t, eng)
				if len(series) != 1 || series[c.feed] != c.want {
					t.Fatalf("%s scrape = %v, want only %s=%d", c.feed, series, c.feed, c.want)
				}
			})
		})
	}
}

func TestFeedSetBytesEmptySetIsZero(t *testing.T) {
	for _, c := range feedSetCases() {
		t.Run(c.feed, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				requests := 0
				feedSetServe(t, &requests,
					func(int) int { return http.StatusOK },
					func(int) string { return c.empty })
				rejected := make(chan struct{})
				eng := c.start("", func(msg string, _ ...any) {
					if strings.Contains(msg, "initial feed fetch failed") {
						rejected <- struct{}{}
					}
				})
				<-rejected
				defer eng.closeAll()
				if got := eng.setBytes(c.feed); got != 0 {
					t.Fatalf("empty %s set reports %d bytes, want 0", c.feed, got)
				}
				series := scrapeFeedSetBytes(t, eng)
				v, ok := series[c.feed]
				if !ok {
					t.Fatalf("empty %s has no series; absent is not zero: %v", c.feed, series)
				}
				if v != 0 {
					t.Fatalf("empty %s scrape = %v, want 0", c.feed, series)
				}
			})
		})
	}
}

// A cached snapshot is loaded synchronously by the constructor, so the set and
// the gauge reflect it before any network refresh. The served body is empty, so
// the refresh is rejected and the warm value must survive it.
func TestFeedSetBytesWarmStart(t *testing.T) {
	for _, c := range feedSetCases() {
		t.Run(c.feed, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, c.cache), []byte(strings.Join(c.rows, "")), 0o600); err != nil {
					t.Fatal(err)
				}
				requests := 0
				feedSetServe(t, &requests,
					func(int) int { return http.StatusOK },
					func(int) string { return c.empty })
				warm := make(chan string, 16)
				done := make(chan string, 16)
				eng := c.start(dir, func(msg string, _ ...any) {
					switch {
					case strings.Contains(msg, "warm-start from cache"):
						warm <- msg
					case strings.Contains(msg, "initial feed fetch failed"), strings.Contains(msg, "keeping previous set"):
						done <- msg
					}
				})
				defer eng.closeAll()
				select {
				case msg := <-warm:
					t.Logf("warm start: %s", msg)
				default:
					t.Fatalf("%s constructor did not warm-start from %s", c.feed, c.cache)
				}
				if got := eng.setBytes(c.feed); got != c.want {
					t.Fatalf("warm %s set bytes = %d, want %d", c.feed, got, c.want)
				}
				<-done
				if got := eng.setBytes(c.feed); got != c.want {
					t.Fatalf("rejected refresh changed warm %s bytes to %d, want %d", c.feed, got, c.want)
				}
				if series := scrapeFeedSetBytes(t, eng); series[c.feed] != c.want {
					t.Fatalf("warm %s scrape = %v, want %d", c.feed, series, c.want)
				}
			})
		})
	}
}

// A failed refresh keeps the previous set and the previous gauge value.
func TestFeedSetBytesFailedRefreshKeepsValue(t *testing.T) {
	for _, c := range feedSetCases() {
		for _, failure := range []string{"status", "empty"} {
			t.Run(c.feed+"/"+failure, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					body := strings.Join(c.rows, "")
					requests := 0
					feedSetServe(t, &requests,
						func(n int) int {
							if n > 1 && failure == "status" {
								return http.StatusServiceUnavailable
							}
							return http.StatusOK
						},
						func(n int) string {
							if n > 1 && failure == "empty" {
								return c.empty
							}
							return body
						})
					done := make(chan struct{})
					eng := c.start("", func(msg string, _ ...any) {
						if strings.Contains(msg, "feed loaded") || strings.Contains(msg, "keeping previous set") || strings.Contains(msg, "initial feed fetch failed") {
							done <- struct{}{}
						}
					})
					<-done
					defer eng.closeAll()
					if got := eng.setBytes(c.feed); got != c.want {
						t.Fatalf("initial %s bytes = %d, want %d", c.feed, got, c.want)
					}
					time.Sleep(time.Hour)
					<-done
					if requests != 2 {
						t.Fatalf("refresh did not run again: requests=%d", requests)
					}
					if got := eng.setBytes(c.feed); got != c.want {
						t.Fatalf("failed refresh changed %s bytes to %d, want %d", c.feed, got, c.want)
					}
					if series := scrapeFeedSetBytes(t, eng); series[c.feed] != c.want {
						t.Fatalf("failed refresh changed %s scrape to %v", c.feed, series)
					}
				})
			})
		}
	}
}
