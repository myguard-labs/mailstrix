package ci

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mbazaar"
)

type mbazaarTransport func(*http.Request) (*http.Response, error)

func (f mbazaarTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mbazaarUseTransport(t *testing.T, f mbazaarTransport) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = previous })
}

type mbazaarBlockedBody struct {
	io.Reader
	started chan struct{}
	release chan struct{}
}

func (b *mbazaarBlockedBody) Read(p []byte) (int, error) {
	if b.started != nil {
		close(b.started)
		b.started = nil
		<-b.release
	}
	return b.Reader.Read(p)
}

func (*mbazaarBlockedBody) Close() error { return nil }

func mbazaarCSV(sample string) string {
	return fmt.Sprintf("\"2024-01-01\",\"%x\",\"md5\"\n", sha256.Sum256([]byte(sample)))
}

func TestMBazaarCloseJoinsRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cacheDir := t.TempDir()
		csv := mbazaarCSV("completed before Close returns")
		// Ignore cancellation while reading to model work (including persistence)
		// that must finish before shutdown can relinquish ownership.
		body := &mbazaarBlockedBody{Reader: strings.NewReader(csv), started: make(chan struct{}), release: make(chan struct{})}
		started := body.started
		mbazaarUseTransport(t, func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
		})
		c := mbazaar.New("fixture-key", time.Hour, "https://feed.invalid/", cacheDir, func(string, ...any) {})
		<-started
		closed := make(chan struct{})
		alsoClosed := make(chan struct{})
		go func() { c.Close(); close(closed) }()
		go func() { c.Close(); close(alsoClosed) }()
		synctest.Wait()
		returnedEarly := false
		select {
		case <-closed:
			returnedEarly = true
		default:
		}
		select {
		case <-alsoClosed:
			returnedEarly = true
		default:
		}
		close(body.release)
		<-closed
		<-alsoClosed
		synctest.Wait()
		got, err := os.ReadFile(filepath.Join(cacheDir, "malwarebazaar.bin"))
		if err != nil || string(got) != csv {
			t.Fatalf("refresh did not finish its cache write: bytes=%d err=%v", len(got), err)
		}
		if returnedEarly {
			t.Fatalf("Close returned before the in-flight refresh finished; cache write of %d bytes occurred after Close", len(got))
		}
		c.Close()
	})
}

type mbazaarCanceledBody struct {
	ctx     context.Context
	started chan struct{}
	closed  bool
}

func (b *mbazaarCanceledBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *mbazaarCanceledBody) Close() error { b.closed = true; return nil }

func TestMBazaarCloseCancelsRequest(t *testing.T) {
	for _, tc := range []struct {
		phase    string
		periodic bool
	}{
		{"headers", false}, {"body", false}, {"headers", true}, {"body", true},
	} {
		phase := tc.phase
		t.Run(fmt.Sprintf("%s/periodic=%t", phase, tc.periodic), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := make(chan struct{})
				var request *http.Request
				var body *mbazaarCanceledBody
				loaded := make(chan struct{}, 1)
				requests := 0
				mbazaarUseTransport(t, func(r *http.Request) (*http.Response, error) {
					request = r
					requests++
					if tc.periodic && requests == 1 {
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(mbazaarCSV("last good sample"))), Header: make(http.Header)}, nil
					}
					if phase == "headers" {
						close(started)
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					body = &mbazaarCanceledBody{ctx: r.Context(), started: started}
					return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
				})
				cacheDir := t.TempDir()
				c := mbazaar.New("fixture-key", time.Hour, "https://feed.invalid/", cacheDir, func(string, ...any) { loaded <- struct{}{} })
				if tc.periodic {
					<-loaded
					time.Sleep(time.Hour)
				}
				<-started
				initial := c.Metrics()
				before := time.Now()
				c.Close()
				if elapsed := time.Since(before); elapsed != 0 {
					t.Fatalf("Close waited for request timeout: %v", elapsed)
				}
				if err := request.Context().Err(); !errors.Is(err, context.Canceled) {
					t.Fatalf("Close did not cancel in-flight %s: %v", phase, err)
				}
				if body != nil && !body.closed {
					t.Fatal("Close returned before response body was closed")
				}
				if m := c.Metrics(); m.FeedHashes != initial.FeedHashes || m.RefreshFailures != 0 || m.LastRefreshUnix != initial.LastRefreshUnix {
					t.Fatalf("shutdown cancellation changed feed metrics: %+v", m)
				}
				wantEntries := 0
				if tc.periodic {
					wantEntries = 1
				}
				if entries, err := os.ReadDir(cacheDir); err != nil || len(entries) != wantEntries {
					t.Fatalf("canceled refresh persisted a cache: entries=%v err=%v", entries, err)
				}
				c.Close()
			})
		})
	}
}

func TestMBazaarRefreshFailureKeepsLastGood(t *testing.T) {
	for _, failure := range []string{"status", "malformed", "empty"} {
		t.Run(failure, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				csv := mbazaarCSV("last good sample")
				requests := 0
				completed := make(chan struct{})
				mbazaarUseTransport(t, func(*http.Request) (*http.Response, error) {
					requests++
					status, data := http.StatusOK, csv
					if requests > 1 {
						switch failure {
						case "status":
							status = http.StatusServiceUnavailable
						case "malformed":
							data = "PK\x03\x04broken archive"
						case "empty":
							data = "# no rows\n"
						}
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(data)), Header: make(http.Header)}, nil
				})
				cacheDir := t.TempDir()
				c := mbazaar.New("fixture-key", time.Hour, "https://feed.invalid/", cacheDir, func(string, ...any) { completed <- struct{}{} })
				<-completed
				initial := c.Metrics()
				if initial.FeedHashes != 1 || initial.RefreshFailures != 0 || initial.LastRefreshUnix == 0 {
					t.Fatalf("initial refresh failed: %+v", initial)
				}
				time.Sleep(time.Hour)
				<-completed
				if m := c.Metrics(); m.FeedHashes != 1 || m.RefreshFailures != 1 || m.LastRefreshUnix != initial.LastRefreshUnix {
					t.Fatalf("failed refresh changed last-good feed: %+v", m)
				}
				if got := c.Check([]byte("last good sample")); len(got) != 1 {
					t.Fatalf("last-good lookup lost after refresh error: %v", got)
				}
				c.Close()
				got, err := os.ReadFile(filepath.Join(cacheDir, "malwarebazaar.bin"))
				if err != nil || string(got) != csv {
					t.Fatalf("failed refresh replaced cache: bytes=%d err=%v", len(got), err)
				}
				time.Sleep(time.Hour)
				if requests != 2 {
					t.Fatalf("refresh continued after Close: requests=%d", requests)
				}
			})
		})
	}
}

func TestMBazaarCloseDisabledAndBeforeRefresh(t *testing.T) {
	var disabled *mbazaar.Checker
	disabled.Close()
	if c := mbazaar.New(" ", time.Hour, "", "", nil); c != nil {
		t.Fatal("empty key enabled the checker")
	}
	synctest.Test(t, func(t *testing.T) {
		mbazaarUseTransport(t, func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		c := mbazaar.New("fixture-key", time.Hour, "https://feed.invalid/", "", func(string, ...any) {})
		c.Close()
		c.Close()
		if failures := c.Metrics().RefreshFailures; failures != 0 {
			t.Fatalf("immediate shutdown counted as a failed refresh: %d", failures)
		}
	})
}

func TestMBazaarInitialFailureRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requests := 0
		completed := make(chan struct{})
		mbazaarUseTransport(t, func(*http.Request) (*http.Response, error) {
			requests++
			if requests == 1 {
				return nil, errors.New("fixture feed unavailable")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(mbazaarCSV("recovered sample"))), Header: make(http.Header)}, nil
		})
		c := mbazaar.New("fixture-key", time.Hour, "https://feed.invalid/", "", func(string, ...any) { completed <- struct{}{} })
		<-completed
		if m := c.Metrics(); m.FeedHashes != 0 || m.RefreshFailures != 1 || m.LastRefreshUnix != 0 {
			t.Fatalf("initial failure metrics: %+v", m)
		}
		time.Sleep(time.Hour)
		<-completed
		if m := c.Metrics(); m.FeedHashes != 1 || m.RefreshFailures != 1 || m.LastRefreshUnix == 0 {
			t.Fatalf("feed did not recover after initial error: %+v", m)
		}
		c.Close()
	})
}
