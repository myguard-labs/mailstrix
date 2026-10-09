package ci

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// Helpers shared by the mbazaar, threatfox and urlhaus lifecycle tests.

type feedTransport func(*http.Request) (*http.Response, error)

func (f feedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func feedUseTransport(t *testing.T, f feedTransport) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = previous })
}

// feedBlockedBody ignores cancellation: it models in-flight work (parse and
// cache persistence) that Close must wait for.
type feedBlockedBody struct {
	io.Reader
	started chan struct{}
	release chan struct{}
}

func (b *feedBlockedBody) Read(p []byte) (int, error) {
	if b.started != nil {
		close(b.started)
		b.started = nil
		<-b.release
	}
	return b.Reader.Read(p)
}

func (*feedBlockedBody) Close() error { return nil }

// feedCanceledBody blocks until the request context is canceled.
type feedCanceledBody struct {
	ctx     context.Context
	started chan struct{}
	closed  bool
}

func (b *feedCanceledBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *feedCanceledBody) Close() error { b.closed = true; return nil }
