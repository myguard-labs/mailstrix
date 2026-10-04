package ci_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

type cacheEngine struct {
	ms.ScanEngine
	calls       atomic.Int32
	fingerprint atomic.Pointer[string]
	scan        func([]byte, ms.ScanMeta) ([]ms.Match, error)
}

func (e *cacheEngine) Fingerprint() string { return *e.fingerprint.Load() }
func (e *cacheEngine) Scan(b []byte, m ms.ScanMeta) ([]ms.Match, error) {
	e.calls.Add(1)
	return e.scan(b, m)
}
func cacheService(t *testing.T, e *cacheEngine, ttl time.Duration) string {
	t.Helper()
	fp := "rules-one"
	e.fingerprint.Store(&fp)
	path := filepath.Join(t.TempDir(), "clamd.sock")
	s := ms.NewServer(&ms.Config{ClamdUnixPath: path, ClamdMaxConns: 64, MaxConcurrent: 1, MaxInflight: 64, MaxBody: 4096, CacheTTL: ttl, CacheSize: 64, Effort: 5, EffortMax: 10}, e)
	c, err := s.StartClamd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return path
}
func cacheWire(body string) []byte {
	if len(body) > 4096 {
		panic("test body exceeds configured stream limit")
	}
	var b bytes.Buffer
	b.WriteString("zINSTREAM\x00")
	if len(body) > 0 {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(body))) // #nosec G115 -- body length is bounded to 4096 bytes above.
		b.Write(header[:])
		b.WriteString(body)
	}
	b.Write([]byte{0, 0, 0, 0})
	return b.Bytes()
}
func cacheRequest(path string, body string) (string, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	if err = c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", err
	}
	if _, err = c.Write(cacheWire(body)); err != nil {
		return "", err
	}
	reply, err := io.ReadAll(c)
	return string(reply), err
}
func wantCacheReply(t *testing.T, path, body, want string) {
	t.Helper()
	got, err := cacheRequest(path, body)
	if err != nil || got != want {
		t.Fatalf("reply=%q err=%v want=%q", got, err, want)
	}
}
func TestClamdCacheSuccessAndFingerprint(t *testing.T) {
	for _, body := range []string{"", "same message"} {
		t.Run(body, func(t *testing.T) {
			e := &cacheEngine{scan: func([]byte, ms.ScanMeta) ([]ms.Match, error) { return []ms.Match{{Rule: "detected"}}, nil }}
			path := cacheService(t, e, time.Hour)
			for range 3 {
				wantCacheReply(t, path, body, "stream: Mailstrix.Match FOUND\x00")
			}
			if n := e.calls.Load(); n != 1 {
				t.Fatalf("cached identical INSTREAM engine calls=%d, want 1", n)
			}
			fp := "rules-two"
			e.fingerprint.Store(&fp)
			wantCacheReply(t, path, body, "stream: Mailstrix.Match FOUND\x00")
			if n := e.calls.Load(); n != 2 {
				t.Fatalf("fingerprint changed: calls=%d want 2", n)
			}
		})
	}
}
func TestClamdCacheNeverStoresFailures(t *testing.T) {
	for _, kind := range []string{"error", "panic", "incomplete", "partial-match"} {
		t.Run(kind, func(t *testing.T) {
			e := &cacheEngine{scan: func([]byte, ms.ScanMeta) ([]ms.Match, error) {
				switch kind {
				case "panic":
					panic("scanner panic")
				case "incomplete":
					return nil, ms.ErrScanIncomplete
				case "partial-match":
					return []ms.Match{{Rule: "detected"}}, ms.ErrScanIncomplete
				default:
					return []ms.Match{{Rule: "must-not-leak"}}, errors.New("failure")
				}
			}}
			path := cacheService(t, e, time.Hour)
			want := "stream: scan failed ERROR\x00"
			if kind == "partial-match" {
				want = "stream: Mailstrix.Match FOUND\x00"
			}
			for range 2 {
				wantCacheReply(t, path, "same", want)
			}
			if n := e.calls.Load(); n != 2 {
				t.Fatalf("failed scan cached: calls=%d want 2", n)
			}
		})
	}
}
func TestClamdCacheCoalesces(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e := &cacheEngine{scan: func([]byte, ms.ScanMeta) ([]ms.Match, error) {
		once.Do(func() { close(entered) })
		<-release
		return nil, nil
	}}
	path := cacheService(t, e, 0)
	const clients = 12
	replies := make(chan string, clients)
	for range clients {
		go func() {
			r, err := cacheRequest(path, "concurrent")
			if err != nil {
				r = err.Error()
			}
			replies <- r
		}()
	}
	<-entered
	// Hold the only CPU slot while all followers reach the shared scan path.
	time.Sleep(100 * time.Millisecond)
	close(release)
	for range clients {
		if got := <-replies; got != "stream: OK\x00" {
			t.Fatalf("reply=%q", got)
		}
	}
	if n := e.calls.Load(); n != 1 {
		t.Fatalf("coalesced INSTREAM engine calls=%d, want 1", n)
	}
}
