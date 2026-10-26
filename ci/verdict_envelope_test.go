package ci_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/verdict"
)

func TestVerdictResponseEnvelope(t *testing.T) {
	const limit = 4 << 20
	clean := `{"matches":[]}`
	for _, tc := range []struct {
		name, body        string
		wantErr, degraded bool
		matches           int
	}{
		{name: "clean", body: clean},
		{name: "optional", body: `{"matches":[],"degraded":"","future":{"nested":true}}`},
		{name: "match", body: `{"matches":[{"rule":"hit","namespace":"local","meta":{"future":"ok"}}]}`, matches: 1},
		{name: "degraded", body: `{"matches":[],"degraded":"busy"}`, wantErr: true, degraded: true},
		{name: "degraded-match", body: `{"matches":[{"rule":"hit"}],"degraded":"incomplete"}`, matches: 1},
		{name: "degraded-log-only", body: `{"matches":[{"rule":"canary","meta":{"mailstrix_canary":"1"}}],"degraded":"busy"}`, wantErr: true, degraded: true, matches: 1},
		{name: "empty", wantErr: true}, {name: "null", body: `null`, wantErr: true},
		{name: "missing", body: `{}`, wantErr: true}, {name: "missing-match", body: `{"degraded":"busy"}`, wantErr: true},
		{name: "null-matches", body: `{"matches":null}`, wantErr: true},
		{name: "wrong-matches", body: `{"matches":{}}`, wantErr: true},
		{name: "wrong-envelope", body: `[]`, wantErr: true},
		{name: "wrong-degraded", body: `{"matches":[],"degraded":true}`, wantErr: true},
		{name: "truncated", body: `{"matches":[`, wantErr: true},
		{name: "trailing-json", body: clean + `{}`, wantErr: true},
		{name: "trailing-text", body: clean + `garbage`, wantErr: true},
		{name: "whitespace", body: clean + " \n\t"},
		{name: "exact-bound", body: clean + strings.Repeat(" ", limit-len(clean))},
		{name: "oversize", body: clean + strings.Repeat(" ", limit-len(clean)+1), wantErr: true},
		{name: "hidden-trailer", body: clean + strings.Repeat(" ", limit-len(clean)) + `{}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			c := verdict.NewClient(srv.URL, "", "envelope-test", time.Second*10)
			defer c.CloseIdle()
			matches, err := c.Scan(context.Background(), "", nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("completed verdict for malformed envelope or rejected valid envelope: error=%v wantError=%v", err, tc.wantErr)
			}
			var de *verdict.DegradedError
			if errors.As(err, &de) != tc.degraded {
				t.Fatalf("degraded error=%v want=%v", err, tc.degraded)
			}
			if len(matches) != tc.matches {
				t.Fatalf("matches=%d want=%d", len(matches), tc.matches)
			}
		})
	}
}

func TestVerdictResponseTransport(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"status", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}},
		{"read-error", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = fmt.Fprint(w, `{"matches":[]}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			c := verdict.NewClient(srv.URL, "", "test", time.Second)
			defer c.CloseIdle()
			if matches, err := c.Scan(context.Background(), "", nil); err == nil || matches != nil {
				t.Fatalf("transport failure completed: %v %v", matches, err)
			}
		})
	}
	c := verdict.NewClient(":invalid", "", "test", time.Second)
	defer c.CloseIdle()
	if _, err := c.Scan(context.Background(), "", nil); err == nil {
		t.Fatal("invalid URL completed")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, `{"matches":[]}`) }))
	defer srv.Close()
	c = verdict.NewClient(srv.URL, "", "test", time.Second)
	defer c.CloseIdle()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Scan(ctx, "", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
