package ci

import (
	"context"
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

	"github.com/myguard-labs/mailstrix/internal/urlhaus"
)

type uhTransport func(*http.Request) (*http.Response, error)

func (f uhTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func uhUseTransport(t *testing.T, f uhTransport) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = previous })
}

// uhBlockedBody ignores cancellation: it models in-flight work (parse and
// cache persistence) that Close must wait for.
type uhBlockedBody struct {
	io.Reader
	started chan struct{}
	release chan struct{}
}

func (b *uhBlockedBody) Read(p []byte) (int, error) {
	if b.started != nil {
		close(b.started)
		b.started = nil
		<-b.release
	}
	return b.Reader.Read(p)
}

func (*uhBlockedBody) Close() error { return nil }

// uhCanceledBody blocks until the request context is canceled.
type uhCanceledBody struct {
	ctx     context.Context
	started chan struct{}
	closed  bool
}

func (b *uhCanceledBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *uhCanceledBody) Close() error { b.closed = true; return nil }

func uhFeed(tag string) string {
	return fmt.Sprintf("\"1\",\"2024-01-01\",\"http://%s.example/x\",\"online\"\n", tag)
}

func uhNew(cacheDir string, logf func(string, ...any)) *urlhaus.Checker {
	return urlhaus.New("fixture-key", time.Hour, cacheDir, logf)
}

func TestURLhausCloseJoinsRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cacheDir := t.TempDir()
		feed := uhFeed("joined")
		body := &uhBlockedBody{Reader: strings.NewReader(feed), started: make(chan struct{}), release: make(chan struct{})}
		started := body.started
		uhUseTransport(t, func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
		})
		c := uhNew(cacheDir, func(string, ...any) {})
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
		got, err := os.ReadFile(filepath.Join(cacheDir, "urlhaus.csv"))
		if err != nil || string(got) != feed {
			t.Fatalf("refresh did not finish its cache write: bytes=%d err=%v", len(got), err)
		}
		if returnedEarly {
			t.Fatal("Close returned before the in-flight refresh finished")
		}
	})
}

func TestURLhausCloseCancelsRequest(t *testing.T) {
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
				var body *uhCanceledBody
				loaded := make(chan struct{}, 1)
				requests := 0
				uhUseTransport(t, func(r *http.Request) (*http.Response, error) {
					request = r
					requests++
					if tc.periodic && requests == 1 {
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(uhFeed("lastgood"))), Header: make(http.Header)}, nil
					}
					if phase == "headers" {
						close(started)
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					body = &uhCanceledBody{ctx: r.Context(), started: started}
					return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
				})
				cacheDir := t.TempDir()
				c := uhNew(cacheDir, func(string, ...any) { loaded <- struct{}{} })
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
				if m := c.Metrics(); m.RefreshFailures != 0 || m.LastRefreshUnix != initial.LastRefreshUnix {
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

func TestURLhausCloseNilAndIdempotent(t *testing.T) {
	var disabled *urlhaus.Checker
	disabled.Close()
	if c := urlhaus.New(" ", time.Hour, "", nil); c != nil {
		t.Fatal("empty key enabled the checker")
	}
	synctest.Test(t, func(t *testing.T) {
		uhUseTransport(t, func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		c := uhNew("", func(string, ...any) {})
		c.Close()
		c.Close()
		if failures := c.Metrics().RefreshFailures; failures != 0 {
			t.Fatalf("immediate shutdown counted as a failed refresh: %d", failures)
		}
	})
}

func TestURLhausCloseAfterSuccessfulRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		feed := uhFeed("ok")
		requests := 0
		loaded := make(chan struct{}, 4)
		uhUseTransport(t, func(*http.Request) (*http.Response, error) {
			requests++
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(feed)), Header: make(http.Header)}, nil
		})
		cacheDir := t.TempDir()
		c := uhNew(cacheDir, func(string, ...any) { loaded <- struct{}{} })
		<-loaded
		if m := c.Metrics(); m.RefreshFailures != 0 || m.LastRefreshUnix == 0 {
			t.Fatalf("refresh did not succeed: %+v", m)
		}
		c.Close()
		c.Close()
		got, err := os.ReadFile(filepath.Join(cacheDir, "urlhaus.csv"))
		if err != nil || string(got) != feed {
			t.Fatalf("cache missing after Close: bytes=%d err=%v", len(got), err)
		}
		time.Sleep(2 * time.Hour)
		if requests != 1 {
			t.Fatalf("refresh continued after Close: requests=%d", requests)
		}
	})
}

func TestURLhausRefreshFailureStillCounted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		uhUseTransport(t, func(*http.Request) (*http.Response, error) {
			return nil, errors.New("fixture feed unavailable")
		})
		failed := make(chan struct{}, 1)
		c := uhNew("", func(string, ...any) { failed <- struct{}{} })
		<-failed
		if m := c.Metrics(); m.RefreshFailures != 1 {
			t.Fatalf("genuine fetch failure not counted: %+v", m)
		}
		c.Close()
	})
}
