package mailstrix

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This private-factory fixture proves TLS/lifecycle wiring. It does not replace
// the physical-volume gate or claim real Store/API/Scheduler composition.
func capeTLSFixture(t *testing.T) (capeResolver, *http.Client) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	pair := server.TLS.Certificates[0]
	client := server.Client()
	client.Timeout = 2 * time.Second
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	server.Close()
	return func(_ context.Context, name string) ([]byte, error) {
		switch name {
		case "cert":
			return certificate, nil
		case "key":
			return private, nil
		default:
			return []byte("fixture-" + name), nil
		}
	}, client
}

func TestCAPEDaemonTLSFactoryMount(t *testing.T) {
	resolve, client := capeTLSFixture(t)
	s := newTestServer(&fakeEngine{}, "tok")
	var closed atomic.Bool
	build := func(ctx context.Context, c *capeDaemonConfig, r capeResolver, _ func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		auth, err := buildCAPEAuth(ctx, c, r, nil)
		if err != nil {
			return nil, err
		}
		return &capeRuntime{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, err := auth(r)
			if err != nil {
				w.WriteHeader(401)
				return
			}
			if r.URL.Path != "/v1/cape/jobs" {
				w.WriteHeader(404)
				return
			}
			_, _ = io.WriteString(w, tenant)
		}), run: func(ctx context.Context) error { <-ctx.Done(); return nil }, close: func() error { closed.Store(true); return nil }}, nil
	}
	service, err := s.startCAPE(capeFixtureConfig(), capeServiceDeps{resolve, build, net.Listen})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		token, tenant string
		status        int
	}{{"fixture-alpha", "alpha", 200}, {"fixture-beta", "beta", 200}, {"wrong", "", 401}} {
		r, err := http.NewRequest("GET", "https://"+service.listener.Addr().String()+"/v1/cape/jobs", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+tc.token)
		r.Header.Set("X-Tenant", "forged")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != tc.status || string(body) != tc.tenant {
			t.Fatal("TLS factory tenant routing failed", response.StatusCode, string(body), err)
		}
	}
	if closed.Load() {
		t.Fatal("runtime closed while service active")
	}
}

func TestCAPEDaemonPreTLSAcceptBound(t *testing.T) {
	resolve, _ := capeTLSFixture(t)
	s := newTestServer(&fakeEngine{}, "tok")
	build := func(context.Context, *capeDaemonConfig, capeResolver, func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		return &capeRuntime{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), run: func(ctx context.Context) error { <-ctx.Done(); return nil }, close: func() error { return nil }}, nil
	}
	cfg := capeFixtureConfig()
	cfg.AcceptLimit = 2
	service, err := s.startCAPE(cfg, capeServiceDeps{resolve, build, net.Listen})
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	defer func() {
		for _, conn := range held {
			_ = conn.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()
	dial := func() net.Conn {
		conn, err := net.DialTimeout("tcp", service.listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	waitSlots := func(want int) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for len(service.accepts.slots) != want && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := len(service.accepts.slots); got != want {
			t.Fatalf("pre-TLS slot count=%d want=%d", got, want)
		}
	}

	t.Run("held connections fill cap", func(t *testing.T) {
		held = append(held, dial(), dial())
		waitSlots(cfg.AcceptLimit)
	})
	t.Run("over-cap connection is refused", func(t *testing.T) {
		conn := dial()
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("over-cap pre-TLS connection remained open")
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Fatal("over-cap pre-TLS connection was held instead of refused")
		}
		waitSlots(cfg.AcceptLimit)
	})
	t.Run("closed connection releases slot", func(t *testing.T) {
		if err := held[0].Close(); err != nil {
			t.Fatal(err)
		}
		waitSlots(cfg.AcceptLimit - 1)
		held = append(held, dial())
		waitSlots(cfg.AcceptLimit)
	})
	t.Run("shutdown closes held connections", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
		waitSlots(0)
		for _, conn := range held[1:] {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("held pre-TLS connection survived shutdown")
			}
		}
	})
}

func TestCAPEDaemonTLSConcreteConnAndAcceptLifecycle(t *testing.T) {
	resolve, client := capeTLSFixture(t)
	s := newTestServer(&fakeEngine{}, "tok")
	type observation struct {
		tls bool
	}
	observed := make(chan observation, 1)
	build := func(context.Context, *capeDaemonConfig, capeResolver, func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		return &capeRuntime{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			observed <- observation{tls: r.TLS != nil}
			w.WriteHeader(http.StatusNoContent)
		}), run: func(ctx context.Context) error { <-ctx.Done(); return nil }, close: func() error { return nil }}, nil
	}
	cfg := capeFixtureConfig()
	cfg.AcceptLimit = 1
	service, err := s.startCAPE(cfg, capeServiceDeps{resolve, build, net.Listen})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})

	held, err := net.DialTimeout("tcp", service.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = held.SetReadDeadline(start.Add(capeReadHeaderTimeout + 10*time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil {
		t.Fatal("incomplete TLS handshake survived server timeout")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("client deadline fired before server TLS handshake timeout")
	}
	_ = held.Close()
	if elapsed := time.Since(start); elapsed < capeReadHeaderTimeout-2*time.Second {
		t.Fatalf("TLS handshake timeout elapsed outside lifecycle bound: %v", elapsed)
	}

	response, err := client.Get("https://" + service.listener.Addr().String() + "/v1/cape/jobs")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	got := <-observed
	if !got.tls || len(service.accepts.slots) != 1 {
		t.Fatalf("net/http lost TLS metadata or released a live keep-alive slot: tls=%v slots=%d", got.tls, len(service.accepts.slots))
	}
	over, err := net.DialTimeout("tcp", service.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	_ = over.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := over.Read(make([]byte, 1)); err == nil {
		t.Fatal("post-response keep-alive connection permitted over-cap acceptance")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("over-cap connection was held instead of refused")
	}
	client.CloseIdleConnections()
	deadline := time.Now().Add(time.Second)
	for len(service.accepts.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(service.accepts.slots); got != 0 {
		t.Fatalf("closed keep-alive connection retained slot: slots=%d", got)
	}
}

func TestCAPEDaemonOperationalFailurePreservesStatic(t *testing.T) {
	resolve, client := capeTLSFixture(t)
	engine := &fakeEngine{count: 1}
	s := newTestServer(engine, "tok")
	build := func(context.Context, *capeDaemonConfig, capeResolver, func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		return nil, ErrCAPEUnavailable
	}
	service, err := s.startCAPE(capeFixtureConfig(), capeServiceDeps{resolve, build, net.Listen})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	if !errors.Is(err, ErrCAPEUnavailable) || service == nil {
		t.Fatal("operational failure lost unavailable listener", err)
	}
	response, err := client.Get("https://" + service.listener.Addr().String() + "/v1/cape/jobs")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatal("unavailable CAPE acknowledged work")
	}
	if w := post(s, "static", map[string]string{"Authorization": "Bearer tok"}); w.Code != 200 || engine.scans.Load() != 1 {
		t.Fatal("CAPE outage disabled static scan", w.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	build = func(context.Context, *capeDaemonConfig, capeResolver, func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		return nil, ErrCAPEConfig
	}
	if service, err := s.startCAPE(capeFixtureConfig(), capeServiceDeps{resolve, build, net.Listen}); !errors.Is(err, ErrCAPEConfig) || service != nil {
		t.Fatal("invalid config accepted", err)
	}
	var malformedClosed atomic.Bool
	build = func(context.Context, *capeDaemonConfig, capeResolver, func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		return &capeRuntime{close: func() error { malformedClosed.Store(true); return nil }}, ErrCAPEUnavailable
	}
	if service, err := s.startCAPE(capeFixtureConfig(), capeServiceDeps{resolve, build, net.Listen}); !errors.Is(err, ErrCAPEConfig) || service != nil || !malformedClosed.Load() {
		t.Fatal("malformed runtime was not rejected and closed", err)
	}
}

func TestCAPEDaemonServiceNativeDrain(t *testing.T) {
	resolve, client := capeTLSFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseNative := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseNative)
	engine := &capeTestEngine{scan: func([]byte, ScanMeta) ([]Match, error) { close(entered); <-release; return nil, nil }}
	s := newTestServer(engine, "tok")
	schedulerStopped := make(chan struct{})
	var runtimeClosed atomic.Bool
	build := func(_ context.Context, _ *capeDaemonConfig, _ capeResolver, scan func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		return &capeRuntime{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = scan(r.Context(), "alpha", r.Body)
			w.WriteHeader(200)
		}), run: func(ctx context.Context) error { <-ctx.Done(); close(schedulerStopped); return nil }, close: func() error { runtimeClosed.Store(true); return nil }}, nil
	}
	service, err := s.startCAPE(capeFixtureConfig(), capeServiceDeps{resolve, build, net.Listen})
	t.Cleanup(func() {
		releaseNative()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := service.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		response, err := client.Post("https://"+service.listener.Addr().String()+"/v1/cape/jobs", "application/octet-stream", strings.NewReader("sample"))
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native request not entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := service.Shutdown(ctx); !errors.Is(err, ErrCAPEDrain) {
		t.Fatal("native shutdown did not report timeout", err)
	}
	if runtimeClosed.Load() || len(s.sem) != 1 {
		t.Fatal("runtime closed before native owner stopped")
	}
	select {
	case <-schedulerStopped:
		t.Fatal("scheduler stopped before classifier joined")
	default:
	}
	releaseNative()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := service.Shutdown(ctx2); err != nil {
		t.Fatal("shutdown did not finish after native release", err)
	}
	if !runtimeClosed.Load() || len(s.sem) != 0 {
		t.Fatal("joined runtime resources not closed")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request did not finish")
	}
}

func TestCAPEDaemonDisabledNoRuntime(t *testing.T) {
	s := newTestServer(&fakeEngine{}, "tok")
	if service, err := s.StartCAPE(); service != nil || err != nil {
		t.Fatal("CAPE enabled without config", err)
	}
	s.cfg.CAPEPolicy = "tempfail"
	if _, err := s.StartCAPE(); !errors.Is(err, ErrCAPEConfig) {
		t.Fatal("unsupported startup policy accepted")
	}
}

func TestCAPEDaemonFailedSchedulerRetainsRuntime(t *testing.T) {
	resolve, _ := capeTLSFixture(t)
	s := newTestServer(&fakeEngine{}, "tok")
	var closed atomic.Bool
	build := func(context.Context, *capeDaemonConfig, capeResolver, func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error) {
		return &capeRuntime{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), run: func(ctx context.Context) error { <-ctx.Done(); return ErrCAPEUnavailable }, close: func() error { closed.Store(true); return nil }}, nil
	}
	service, err := s.startCAPE(capeFixtureConfig(), capeServiceDeps{resolve, build, net.Listen})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		// This fixture intentionally retains its failed scheduler's runtime.
		if err := service.Shutdown(ctx); err != nil && !errors.Is(err, ErrCAPEDrain) {
			t.Error(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); !errors.Is(err, ErrCAPEDrain) || closed.Load() {
		t.Fatal("failed scheduler owner discarded", err)
	}
}
