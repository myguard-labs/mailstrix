package mailstrix

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	yara "github.com/hillu/go-yara/v4"
)

// A cache barrier stops the real handler AFTER it forms its key. Reload and
// FlushCache then finish before lookup resumes: the retained third witness.
type generationBarrierCache struct {
	Cache
	once   sync.Once
	key    chan string
	resume chan struct{}
}

func (c *generationBarrierCache) Get(key string) ([]Match, bool) {
	c.once.Do(func() { c.key <- key; <-c.resume })
	return c.Cache.Get(key)
}

func generationWait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("generation barrier did not complete")
		var zero T
		return zero
	}
}

func generationWrite(t *testing.T, dir, source string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationCacheKeyScanInterval(t *testing.T) {
	for _, protocol := range []string{"http", "clamd", "icap"} {
		t.Run(protocol, func(t *testing.T) {
			dir := writeRules(t, "rule Stable { condition: false }")
			s := newScanner(t, dir)
			t.Cleanup(s.Close)
			srv := newCachingServer(s, "generation-test")
			cache := &generationBarrierCache{Cache: srv.cache, key: make(chan string, 1), resume: make(chan struct{})}
			srv.cache = cache
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(cache.resume) }) })
			const body = "ordinary generation fixture"
			oldFP := s.Fingerprint()
			var request func() string
			switch protocol {
			case "http":
				request = func() string {
					w := post(srv, body, map[string]string{"X-MAILSTRIX-Token": "generation-test"})
					var response scanResponse
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
						return err.Error()
					}
					return fmt.Sprintf("%d matches=%d", w.Code, len(response.Matches))
				}
			case "clamd":
				request = func() string {
					_, conn := clamdPipe(t, srv)
					return clamdExchange(t, conn, clamdWire(body))
				}
			case "icap":
				addr := startTestICAPServer(t, srv)
				request = func() string { return doICAP(t, addr, icapRESPMODRequest(addr, body, false)) }
			}
			done := make(chan string, 1)
			go func() { done <- request() }()
			oldKey := generationWait(t, cache.key)
			if !strings.HasPrefix(oldKey, oldFP+":") {
				t.Fatal("request did not construct the old generation key")
			}
			generationWrite(t, dir, "rule Stable { condition: true }")
			if err := s.Reload(); err != nil {
				t.Fatal(err)
			}
			srv.FlushCache()
			runtime.GC() // The request pin must keep retired native bundles reachable.
			newFP := s.Fingerprint()
			if newFP == oldFP {
				t.Fatal("reload did not change fingerprint")
			}
			release.Do(func() { close(cache.resume) })
			oldResponse := generationWait(t, done)
			assertResponse := func(response string, matched bool, fp string) {
				t.Helper()
				switch protocol {
				case "http":
					want := "200 matches=0"
					if matched {
						want = "200 matches=1"
					}
					if response != want {
						t.Fatalf("HTTP verdict = %q, want %q", response, want)
					}
				case "clamd":
					want := "stream: OK\x00"
					if matched {
						want = "stream: Mailstrix.Match FOUND\x00"
					}
					if response != want {
						t.Fatalf("clamd verdict = %q, want %q", response, want)
					}
				case "icap":
					if !strings.Contains(response, "ISTag: "+icapISTag(fp)+"\r\n") {
						t.Fatalf("ISTag does not identify pinned verdict: %q", response)
					}
					if strings.Contains(response, "X-Infection-Found:") != matched {
						t.Fatalf("ICAP verdict = %q, matched=%v", response, matched)
					}
				}
			}
			assertResponse(oldResponse, false, oldFP)
			if cached, ok := cache.Cache.Get(oldKey); !ok || len(cached) != 0 {
				t.Fatalf("old key poisoned after reload/flush: found=%v matches=%v", ok, cached)
			}
			before := s.RawChannelScans()
			assertResponse(request(), true, newFP)
			assertResponse(request(), true, newFP)
			if s.RawChannelScans()-before != 1 {
				t.Fatal("new generation miss then hit did not scan exactly once")
			}
		})
	}
}

func TestGenerationNativeWorkerSurvivesDisconnect(t *testing.T) {
	dir := writeRules(t, "rule Stable { condition: false }")
	reached, resume := make(chan struct{}), make(chan struct{})
	var block sync.Once
	cfg := &Config{RulesDir: dir, BigFileRules: dir, BigFileThreshold: 1}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(format string, _ ...any) {
		if strings.HasPrefix(format, "oversized buffer (") {
			block.Do(func() { close(reached); <-resume })
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	var release sync.Once
	defer release.Do(func() { close(resume) })
	owner := p7Owner(t, s)
	srv := newCachingServer(s, "generation-test")
	const body = "ordinary worker fixture"
	meta := ScanMeta{RawKey: streamDedupKey([]byte(body)), Effort: ResolveEffortLevel(0, false, srv.autoEnvDefault(true), srv.cfg.EffortMax)}
	oldKey := s.Fingerprint() + ":" + meta.cacheKey() + ":" + string(meta.RawKey[:])
	service, conn := clamdPipe(t, srv)
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte(clamdWire(body))); done <- err }()
	generationWait(t, reached)
	if err := generationWait(t, done); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(srv.sem) != 1 || len(srv.admit) != 1 {
		t.Fatal("native worker lost its gates on disconnect")
	}
	generationWrite(t, dir, "rule Stable { condition: true }")
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	srv.FlushCache()
	runtime.GC() // The worker retains its generation independently of connection cancellation.
	p7Alive(t, owner, "detached clamd worker")
	release.Do(func() { close(resume) })
	generationWait(t, service.done)
	p7Dead(t, owner)
	if cached, ok := srv.cache.Get(oldKey); !ok || len(cached) != 0 {
		t.Fatalf("disconnected native worker poisoned old key: found=%v matches=%v", ok, cached)
	}
	if len(srv.sem) != 0 || len(srv.admit) != 0 {
		t.Fatal("completed native worker leaked gates")
	}
}

func TestGenerationPinnedBundlesAndPolicy(t *testing.T) {
	dir := writeRules(t, "rule Main { condition: true } rule Marker : marker { condition: true }")
	bigDir := writeRules(t, "rule Big { condition: true }")
	s, err := NewScanner(&Config{RulesDir: dir, BigFileRules: bigDir, BigFileThreshold: 32}, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := s.acquireScanLease()
	defer old.release()
	generationWrite(t, dir, "rule NewMain { condition: true } rule NewMarker : marker { condition: true }")
	generationWrite(t, bigDir, "rule NewBig { condition: true }")
	deny := map[string]struct{}{"newmain": {}}
	if err := s.reloadWithDenylist(context.Background(), &deny); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		lease      scanLease
		body, want string
	}{
		{old, "small", "[Main]"}, {old, strings.Repeat("x", 32), "[Main]"}, {old, strings.Repeat("x", 33), "[Big]"},
		{s.acquireScanLease(), "small", "[]"}, {s.acquireScanLease(), strings.Repeat("x", 33), "[NewBig]"},
	} {
		t.Cleanup(tc.lease.release)
		matches, err := tc.lease.scan([]byte(tc.body), ScanMeta{})
		if err != nil {
			t.Fatal(err)
		}
		if got := ruleNames(matches); got != tc.want {
			t.Fatalf("pinned scan names=%q, want %q", got, tc.want)
		}
	}
	for _, tc := range []struct {
		lease       scanLease
		marker, big string
	}{
		{old, "[Main, Marker]", "[Big]"},
		{s.acquireScanLease(), "[NewMarker]", "[NewBig]"},
	} {
		t.Cleanup(tc.lease.release)
		before := s.MarkerChannelScans()
		matches, err := tc.lease.scan([]byte("{\\rtf1 ordinary}"), ScanMeta{Filename: "ordinary.jpg", Extension: ".jpg"})
		if err != nil || ruleNames(matches) != tc.marker || s.MarkerChannelScans() == before {
			t.Fatalf("pinned marker channel: %v %v want %s", matches, err, tc.marker)
		}
		before = s.BigFileStreamScans()
		matches, err = tc.lease.scan(zipWithMember(t, "ordinary.txt", []byte(strings.Repeat("x", 33))), ScanMeta{})
		if err != nil || ruleNames(matches) != tc.big || s.BigFileStreamScans() == before {
			t.Fatalf("pinned big stream channel: %v %v want %s", matches, err, tc.big)
		}
	}
}

func TestGenerationCoalescingCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := writeRules(t, "rule Stable { condition: false }")
		reached, resume := make(chan struct{}), make(chan struct{})
		var once sync.Once
		s, err := NewScanner(&Config{RulesDir: dir, BigFileRules: dir, BigFileThreshold: 1}, func(format string, _ ...any) {
			if strings.HasPrefix(format, "oversized buffer (") {
				once.Do(func() { close(reached); <-resume })
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		var release sync.Once
		defer release.Do(func() { close(resume) })
		srv := newCachingServer(s, "generation-test")
		body := []byte("ordinary coalesced fixture")
		meta := ScanMeta{RawKey: streamDedupKey(body)}
		oldFP := s.Fingerprint()
		type reply struct {
			outcome    scanOutcome
			status, fp string
		}
		call := func(ctx context.Context, out chan<- reply) {
			result, status, fp := srv.lookupScanOutcomeStarted(ctx, "", body, meta, nil)
			out <- reply{result, status, fp}
		}
		leader, follower, canceled := make(chan reply, 1), make(chan reply, 1), make(chan reply, 1)
		go call(context.Background(), leader)
		<-reached
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go call(context.Background(), follower)
		go call(ctx, canceled)
		synctest.Wait()
		srv.flights.mu.Lock()
		joined := 0
		for _, fl := range srv.flights.m {
			joined += fl.joiners
		}
		srv.flights.mu.Unlock()
		if joined != 2 {
			t.Fatalf("old generation followers=%d want 2", joined)
		}
		cancel()
		if got := <-canceled; got.status != "canceled" || got.fp != oldFP {
			t.Fatalf("canceled follower=%+v", got)
		}
		generationWrite(t, dir, "rule Stable { condition: true }")
		if err := s.Reload(); err != nil {
			t.Fatal(err)
		}
		srv.FlushCache()
		runtime.GC() // The request pin must keep retired native bundles reachable.
		release.Do(func() { close(resume) })
		for _, ch := range []chan reply{leader, follower} {
			got := <-ch
			if got.status != "coalesced" || got.fp != oldFP || got.outcome.err != nil || len(got.outcome.matches) != 0 {
				t.Fatalf("old generation coalesced result=%+v", got)
			}
		}
		result, status, fp := srv.lookupScanOutcomeStarted(context.Background(), "", body, meta, nil)
		if status != "miss" || fp == oldFP || result.err != nil || len(result.matches) != 1 {
			t.Fatalf("new generation result: %v %s %s", result, status, fp)
		}
	})
}

func TestGenerationAuxiliaryFailureIdentity(t *testing.T) {
	dir := writeRules(t, "rule Main { condition: false } rule Marker : marker { condition: true }")
	bigDir := writeRules(t, "rule Big { condition: true }")
	s, err := NewScanner(&Config{RulesDir: dir, BigFileRules: bigDir, BigFileThreshold: 1}, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	oldFP, oldBig, oldMarker := s.Fingerprint(), s.bigRules.Load(), s.markerRules.Load()
	oldBigID, oldMarkerID := s.bigContent, s.markerContent
	generationWrite(t, dir, "rule NewMain { condition: true } rule NewMarker : marker { condition: true }")
	generationWrite(t, bigDir, "malformed big source")
	// Marker preparation no longer rereads the source. Fail native serialization
	// to exercise the same retained-auxiliary identity contract.
	original := serializeRules
	serializeRules = func(*yara.Rules, io.Writer) error { return fmt.Errorf("injected marker serialization failure") }
	t.Cleanup(func() { serializeRules = original })
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.bigRules.Load() != oldBig || s.markerRules.Load() != oldMarker || s.bigContent != oldBigID || s.markerContent != oldMarkerID {
		t.Fatal("failed auxiliary load discarded retained rules or their identity")
	}
	if s.Fingerprint() == oldFP {
		t.Fatal("new main bundle did not update the generation identity")
	}
	matches, err := s.Scan([]byte("ordinary"), ScanMeta{})
	if err != nil || ruleNames(matches) != "[Big]" {
		t.Fatalf("big fallback service: %v %v", matches, err)
	}
	matches, err = s.scanOne(s.markerRules.Load(), []byte("ordinary"), scanVars{}, 0)
	if err != nil || ruleNames(matches) != "[Marker]" {
		t.Fatalf("marker fallback service: %v %v", matches, err)
	}
}
