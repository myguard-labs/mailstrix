package mailstrix

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type capeTestEngine struct {
	fakeEngine
	scan func([]byte, ScanMeta) ([]Match, error)
}

func (e *capeTestEngine) Scan(body []byte, meta ScanMeta) ([]Match, error) {
	if e.scan != nil {
		return e.scan(body, meta)
	}
	return e.fakeEngine.Scan(body, meta)
}

func TestCAPEDaemonStaticClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		matches []Match
		err     error
		panic   bool
		want    string
	}{
		{"unknown", nil, nil, false, "unknown"},
		{"malicious", []Match{{Rule: "hit"}}, nil, false, "malicious"},
		{"canary", []Match{{Rule: "hit", Meta: map[string]string{"mailstrix_canary": "1"}}}, nil, false, "unknown"},
		{"allow", []Match{{Rule: "hit", Meta: map[string]string{"mailstrix_allow": "1"}}}, nil, false, "unknown"},
		{"log-only-first", []Match{{Rule: "canary", Meta: map[string]string{"mailstrix_canary": "1"}}, {Rule: "hit"}}, nil, false, "malicious"},
		{"actionable-first", []Match{{Rule: "hit"}, {Rule: "allow", Meta: map[string]string{"mailstrix_allow": "1"}}}, nil, false, "malicious"},
		{"error", nil, errors.New("fixture"), false, ""},
		// CAPE.md: recovered matches must not rescue an incomplete scan.
		{"error-with-matches", []Match{{Rule: "hit"}}, errors.New("fixture"), false, ""},
		{"panic", nil, nil, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &fakeEngine{matches: tc.matches, err: tc.err, panic: tc.panic}
			s := newTestServer(engine, "tok")
			got, err := s.capeStaticScan(context.Background(), "alpha", strings.NewReader("exact attachment"))
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("classification=%q err=%v want=%q", got, err, tc.want)
			}
			if engine.scans.Load() != 1 {
				t.Fatal("classifier used fail-open cache instead of scan")
			}
			meta := engine.lastMeta.Load()
			if meta == nil || meta.Filename != "" || meta.Extension != "" || len(meta.PWCandidates) != 0 || meta.Effort != s.cfg.EffortMax {
				t.Fatal("classifier inherited request metadata")
			}
		})
	}
}

func TestCAPEDaemonNativeOwnership(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseNative := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseNative)
	engine := &capeTestEngine{scan: func(body []byte, _ ScanMeta) ([]Match, error) {
		if string(body) != "exact attachment" {
			t.Error("staged bytes changed")
		}
		close(entered)
		<-release
		return nil, nil
	}}
	s := newTestServer(engine, "tok")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	joined := make(chan struct{})
	t.Cleanup(func() {
		releaseNative()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("native cleanup did not join")
		}
	})
	go func() {
		defer close(joined)
		_, err := s.capeStaticScan(ctx, "alpha", strings.NewReader("exact attachment"))
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native scan never entered")
	}
	cancel()
	if len(s.sem) != 1 || len(s.admit) != 1 {
		t.Fatal("native gates released before scan stopped")
	}
	select {
	case <-done:
		t.Fatal("native classifier returned before scan stopped")
	default:
	}
	releaseNative()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled native scan admitted")
		}
	case <-time.After(time.Second):
		t.Fatal("native classifier did not join")
	}
	if len(s.sem) != 0 || len(s.admit) != 0 {
		t.Fatal("native gates leaked")
	}
}

func TestCAPEDaemonScanGateAndDeadline(t *testing.T) {
	engine := &fakeEngine{}
	s := newTestServer(engine, "tok")
	for i := 0; i < cap(s.sem); i++ {
		s.sem <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.capeStaticScan(ctx, "alpha", strings.NewReader("sample")); err == nil || engine.scans.Load() != 0 {
		t.Fatal("scan gate bypassed")
	}
	for i := 0; i < cap(s.sem); i++ {
		<-s.sem
	}
	if len(s.admit) != 0 {
		t.Fatal("admission leaked while waiting for CPU")
	}
	if _, err := s.capeStaticScan(ctx, "alpha", strings.NewReader("sample")); err == nil || engine.scans.Load() != 0 {
		t.Fatal("expired ingress reached scanner")
	}
}
