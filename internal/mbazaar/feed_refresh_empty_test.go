package mbazaar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestRefreshEmptyKeepsLastGood (COR-08): a 200 response with no rows does
// not replace the loaded set.
func TestRefreshEmptyKeepsLastGood(t *testing.T) {
	var body atomic.Value
	body.Store(strings.Repeat("a", 64) + "\n" + strings.Repeat("b", 64) + "\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	c := &Checker{key: "k", feedURL: srv.URL, client: srv.Client(), logf: func(string, ...any) {}, stop: make(chan struct{})}
	if err := c.refreshOnce(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if n := len(c.set.Load().m); n != 2 {
		t.Fatalf("loaded %d hashes, want 2", n)
	}
	body.Store("# sha256_hash\n")
	if err := c.refreshOnce(context.Background()); !errors.Is(err, errFeedShrank) {
		t.Fatalf("empty refresh: err=%v, want errFeedShrank", err)
	}
	if n := len(c.set.Load().m); n != 2 {
		t.Fatalf("empty refresh replaced the set: %d hashes", n)
	}
}
