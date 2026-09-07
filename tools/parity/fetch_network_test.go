package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestFetchPublicAddressPolicy(t *testing.T) {
	for _, s := range []string{"0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.0.0.8", "192.0.2.1", "192.88.99.1", "192.168.0.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "fc00::1", "ff02::1", "64:ff9b::a00:1", "100::1", "2001::1", "2001:db8::1", "2002::1", "3fff::1", "::ffff:10.0.0.1", "::ffff:192.0.2.1"} {
		if publicFetchIP(netip.MustParseAddr(s)) {
			t.Errorf("nonpublic address allowed: %s", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !publicFetchIP(netip.MustParseAddr(s)) {
			t.Errorf("public address rejected: %s", s)
		}
	}
	if publicFetchIP(netip.Addr{}) {
		t.Fatal("invalid address accepted")
	}
}

func TestFetchDialBindsValidatedAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  []netip.Addr
		fail bool
	}{
		{"public", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, false},
		{"empty", nil, true},
		{"private", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, true},
		{"mixed", []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, true},
		{"mixed reverse", []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups, dials := 0, 0
			d := fetchDialer{
				lookup: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
					lookups++
					if network != "ip" || host != "example.invalid" {
						t.Fatal("unexpected resolver input")
					}
					if _, ok := ctx.Deadline(); !ok {
						t.Fatal("unbounded resolution")
					}
					return tc.ips, nil
				},
				dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					dials++
					if address != "8.8.8.8:443" || network != "tcp" {
						t.Fatalf("dial did not bind resolved IP: %s %s", network, address)
					}
					a, b := net.Pipe()
					_ = b.Close()
					return a, nil
				},
			}
			conn, err := d.dialContext(context.Background(), "tcp", "example.invalid:443")
			if tc.fail {
				if err == nil || dials != 0 {
					t.Fatal("forbidden answer dialled")
				}
			} else {
				if err != nil || dials != 1 {
					t.Fatalf("validated dial failed: %v", err)
				}
				_ = conn.Close()
			}
			if lookups != 1 {
				t.Fatalf("resolver called %d times", lookups)
			}
		})
	}
	d := fetchDialer{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("IP literal resolved again")
		return nil, nil
	}, dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("private literal dialled")
		return nil, nil
	}}
	if _, err := d.dialContext(context.Background(), "tcp", "[::ffff:127.0.0.1]:443"); err == nil {
		t.Fatal("mapped loopback accepted")
	}
}

func TestFetchDialErrors(t *testing.T) {
	for _, kind := range []string{"resolver", "connection", "bad address"} {
		t.Run(kind, func(t *testing.T) {
			d := fetchDialer{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				if kind == "resolver" {
					return nil, errors.New("PRIVATE")
				}
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}, dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("PRIVATE") }}
			address := "example.invalid:443"
			if kind == "bad address" {
				address = "PRIVATE"
			}
			if _, err := d.dialContext(context.Background(), "tcp", address); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("dial error privacy: %v", err)
			}
		})
	}
}

type fetchErrorBody struct {
	reader            io.Reader
	readErr, closeErr error
	closed            bool
}

type stalledFetchBody struct {
	ctx    context.Context
	closed bool
}

func (b *stalledFetchBody) Read(_ []byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *stalledFetchBody) Close() error { b.closed = true; return nil }

func (b *fetchErrorBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.reader.Read(p)
}
func (b *fetchErrorBody) Close() error { b.closed = true; return b.closeErr }

func TestFetchResponsePolicy(t *testing.T) {
	data := []byte("inert")
	s := sample{Size: int64(len(data)), SHA256: digest(data)}
	for _, kind := range []string{"ok", "identity", "status", "redirect", "compressed", "uncompressed", "duplicate encoding", "checksum", "short", "long", "read", "close", "length", "error body"} {
		t.Run(kind, func(t *testing.T) {
			body := &fetchErrorBody{reader: bytes.NewReader(data)}
			response := &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: -1, Body: body}
			s := s
			switch kind {
			case "identity":
				response.Header.Set("Content-Encoding", "identity")
			case "status":
				response.StatusCode = 404
			case "redirect":
				response.StatusCode = 302
				response.Header.Set("Location", "https://PRIVATE.invalid")
			case "compressed":
				response.Header.Set("Content-Encoding", "gzip")
			case "uncompressed":
				response.Uncompressed = true
			case "duplicate encoding":
				response.Header["Content-Encoding"] = []string{"identity", "identity"}
			case "checksum":
				s.SHA256 = strings.Repeat("0", 64)
			case "short":
				body.reader = bytes.NewReader(data[:len(data)-1])
			case "long":
				body.reader = io.MultiReader(bytes.NewReader(data), strings.NewReader("extra"))
			case "read":
				body.readErr = errors.New("PRIVATE")
			case "close":
				body.closeErr = errors.New("PRIVATE")
			case "length":
				response.ContentLength = s.Size + 1
			case "error body":
				response.StatusCode = 500
				body.readErr = errors.New("PRIVATE")
			}
			client := newFetchClient(fetchDialer{})
			calls := 0
			client.Transport = fetchRoundTripper(func(r *http.Request) (*http.Response, error) { calls++; return response, nil })
			b, err := fetchBytes(context.Background(), client, fetchTestOrigin+"/inert", s)
			good := kind == "ok" || kind == "identity"
			if good {
				if err != nil || !bytes.Equal(b, data) {
					t.Fatalf("valid response failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid response accepted")
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("private transport detail exposed")
			}
			if !body.closed || calls != 1 {
				t.Fatal("body not closed or redirect followed")
			}
		})
	}
}

func TestFetchBodyBound(t *testing.T) {
	for _, size := range []int{1, maxSample} {
		b := bytes.Repeat([]byte("x"), size)
		s := sample{Size: int64(size), SHA256: digest(b)}
		for _, extra := range []bool{false, true} {
			input := b
			if extra {
				input = append(append([]byte{}, b...), []byte("extra")...)
			}
			reader := bytes.NewReader(input)
			client := &http.Client{Transport: fetchRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: -1, Body: io.NopCloser(reader)}, nil
			})}
			_, err := fetchBytes(context.Background(), client, fetchTestOrigin+"/inert", s)
			if extra {
				if err == nil || reader.Len() != len("extra")-1 {
					t.Fatal("oversized body was accepted or read beyond size+1")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestFetchTimeouts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		client := newFetchClient(fetchDialer{})
		client.Transport = fetchRoundTripper(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
		if _, err := fetchBytes(context.Background(), client, fetchTestOrigin+"/inert", sample{Size: 1}); err == nil {
			t.Fatal("request timeout accepted")
		}
		if elapsed := time.Since(start); elapsed != fetchRequestTimeout {
			t.Fatalf("request deadline %s", elapsed)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		d := fetchDialer{lookup: func(ctx context.Context, _, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }, dial: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dial after resolution timeout")
			return nil, nil
		}}
		if _, err := d.dialContext(context.Background(), "tcp", "example.invalid:443"); err == nil {
			t.Fatal("resolver timeout accepted")
		}
		if time.Since(start) != fetchRequestTimeout {
			t.Fatal("unbounded resolver")
		}
	})
	if fetchPlatformSupported() {
		f := inertFetchFixture(t)
		urls := f.urls(t)
		parent := t.TempDir()
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
			defer cancel()
			ops := f.ops(t)
			get := ops.get
			calls := 0
			ops.get = func(ctx context.Context, u string, s sample) ([]byte, error) {
				calls++
				time.Sleep(4 * time.Minute)
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return get(ctx, u, s)
			}
			if err := fetchCorpus(ctx, f.m, f.raw, urls, filepath.Join(parent, "out"), ops); err == nil || calls != 3 {
				t.Fatalf("whole-operation cancellation not enforced: %v calls=%d", err, calls)
			}
		})
		requireEmptyFetchParent(t, parent)
	}
}

func TestFetchBodyTimeoutPreventsPublication(t *testing.T) {
	if !fetchPlatformSupported() {
		t.Skip("Linux-only publication")
	}
	f := inertFetchFixture(t)
	parent := t.TempDir()
	synctest.Test(t, func(t *testing.T) {
		var body *stalledFetchBody
		client := newFetchClient(fetchDialer{})
		client.Transport = fetchRoundTripper(func(r *http.Request) (*http.Response, error) {
			body = &stalledFetchBody{ctx: r.Context()}
			return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: -1, Body: body}, nil
		})
		ops := f.ops(t)
		ops.get = func(ctx context.Context, u string, s sample) ([]byte, error) { return fetchBytes(ctx, client, u, s) }
		start := time.Now()
		if err := fetchCorpus(context.Background(), f.m, f.raw, f.urls(t), filepath.Join(parent, "out"), ops); err == nil {
			t.Fatal("stalled body published")
		}
		if body == nil || !body.closed || time.Since(start) != fetchRequestTimeout {
			t.Fatal("body timeout or close not enforced")
		}
	})
	requireEmptyFetchParent(t, parent)
}

// Only this synthetic loopback server is contacted. Production resolver and
// literal-IP dial policy run unchanged; the final socket seam routes the test's
// public address to our own server. No external DNS or remote connection occurs.
func TestFetchTLSAndTransportComposition(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	data := []byte("inert TLS fixture")
	var calls atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected network headers")
		}
		w.Header().Set("Set-Cookie", "private=ignored")
		_, _ = w.Write(data)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	cert := server.Certificate()
	if err := cert.VerifyHostname("example.com"); err != nil {
		t.Fatalf("inert test certificate hostname changed: %v", err)
	}
	var lookups, dials atomic.Int64
	d := fetchDialer{lookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		if network != "ip" || host != "example.com" && host != "wrong.invalid" {
			t.Error("resolver host changed")
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if address != "8.8.8.8:443" {
			t.Error("TLS hostname reached dial instead of validated literal")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	client := newFetchClient(d)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport")
	}
	if transport.Proxy != nil || !transport.DisableCompression || !transport.DisableKeepAlives || transport.TLSClientConfig.InsecureSkipVerify || client.Jar != nil {
		t.Fatal("production transport policy changed")
	}
	s := sample{Size: int64(len(data)), SHA256: digest(data)}
	if _, err := fetchBytes(context.Background(), client, "https://example.com/inert", s); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	transport.TLSClientConfig.RootCAs = pool // Trust only our inert fixture's certificate.
	for i := 0; i < 2; i++ {
		b, err := fetchBytes(context.Background(), client, "https://example.com/inert", s)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("TLS fixture failed: %v", err)
		}
	}
	if _, err := fetchBytes(context.Background(), client, "https://wrong.invalid/inert", s); err == nil {
		t.Fatal("TLS hostname mismatch accepted")
	}
	if lookups.Load() != 4 || dials.Load() != 4 || calls.Load() != 2 {
		t.Fatalf("unexpected requests/re-resolution: lookup=%d dial=%d HTTP=%d", lookups.Load(), dials.Load(), calls.Load())
	}
}

func TestFetchSummaryFailurePreservesPublication(t *testing.T) {
	if !fetchPlatformSupported() {
		t.Skip("Linux-only publication")
	}
	f := inertFetchFixture(t)
	out := filepath.Join(t.TempDir(), "out")
	if code := fetchCLI(f.args(t, out), faultyFetchWriter{writeErr: errors.New("PRIVATE")}, f.ops(t)); code != 2 {
		t.Fatalf("summary failure exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(out, "manifest.json")); err != nil {
		t.Fatal("successful publication removed after output error")
	}
}
