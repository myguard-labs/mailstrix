//go:build linux

package cape

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type inertMapper struct{ evidence Evidence }

func (m inertMapper) Normalize(_ context.Context, _ *Report, policy string) (NormalizedResult, error) {
	return NormalizedResult{Version: 1, Policy: policy, Evidence: m.evidence}, nil
}

type mapperFunc func(context.Context, *Report, string) (NormalizedResult, error)

func (f mapperFunc) Normalize(ctx context.Context, r *Report, p string) (NormalizedResult, error) {
	return f(ctx, r, p)
}

func schedulerAdmission(t *testing.T, s *Store, c *Client, tenant, body string) Job {
	t.Helper()
	r := storeRequest(tenant)
	r.Generation = c.generation
	a, err := s.Enqueue(context.Background(), r, source(body))
	if err != nil {
		t.Fatal(err)
	}
	return a.Job
}
func testScheduler(t *testing.T, s *Store, c *Client, mapper ResultMapper, workers int) *Scheduler {
	t.Helper()
	q, err := NewScheduler(s, map[string]*Client{c.generation: c}, mapper, workers)
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func schedulerDispatch(q *Scheduler) (map[string]schedulerLive, chan schedulerResult) {
	live := make(map[string]schedulerLive)
	results := make(chan schedulerResult, q.workers)
	q.dispatch(context.Background(), live, results)
	return live, results
}
func schedulerHarvest(t *testing.T, q *Scheduler, live map[string]schedulerLive, results <-chan schedulerResult) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for len(live) > 0 {
		select {
		case r := <-results:
			live[r.job.ID].cancel()
			delete(live, r.job.ID)
			q.pending = append(q.pending, r)
		case <-deadline.C:
			for _, v := range live {
				v.cancel()
			}
			t.Fatal("scheduler request did not join")
		}
	}
}
func schedulerRound(t *testing.T, q *Scheduler) {
	t.Helper()
	live, results := schedulerDispatch(q)
	schedulerHarvest(t, q, live, results)
	q.persistPending()
	if len(q.pending) != 0 {
		t.Fatal("scheduler outcome did not persist")
	}
}
func schedulerLookup(t *testing.T, s *Store, j Job) Job {
	t.Helper()
	r, e := s.Lookup(context.Background(), j.Tenant, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestSchedulerReportAndCleanup(t *testing.T) {
	for _, mapping := range []string{"valid", "missing", "invalid"} {
		t.Run(mapping, func(t *testing.T) {
			var calls atomic.Int32
			digest := sha256.Sum256([]byte("inert"))
			client, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch {
				case r.Method == http.MethodPost:
					_, _ = io.Copy(io.Discard, r.Body)
					fmt.Fprint(w, success)
				case strings.Contains(r.URL.Path, "/status/"):
					fmt.Fprint(w, `{"error":false,"data":"reported"}`)
				case strings.Contains(r.URL.Path, "/report/"):
					fmt.Fprintf(w, `{"info":{"id":41,"category":"file"},"target":{"category":"file","file":{"sha256":"%x"}},"raw_secret_marker":"never_persist"}`, digest)
				case strings.Contains(r.URL.Path, "/delete/"):
					fmt.Fprint(w, `{"data":"Task(s) ID(s) 41 has been deleted"}`)
				default:
					t.Error("unexpected request")
				}
			})
			clock := newStoreClock()
			s := testStore(t, storeConfig(t.TempDir()), clock)
			j := schedulerAdmission(t, s, client, "alpha", "inert")
			var mapper ResultMapper
			if mapping == "valid" {
				mapper = inertMapper{EvidenceNoSignal}
			}
			if mapping == "invalid" {
				mapper = inertMapper{"clean"}
			}
			q := testScheduler(t, s, client, mapper, 2)
			schedulerRound(t, q) // POST
			schedulerRound(t, q) // status
			if schedulerLookup(t, s, j).State != Fetching {
				t.Fatal("reported did not enter checked fetching")
			}
			clock.advance(5 * time.Minute)
			schedulerRound(t, q) // report
			got := schedulerLookup(t, s, j)
			if mapping == "valid" {
				if got.State != Completed || !strings.Contains(string(got.Result), `"evidence":"no_signal"`) {
					t.Fatal("validated mapped report did not complete")
				}
			} else if got.State != Failed || len(got.Result) != 0 {
				t.Fatal("missing or invalid mapper accepted as evidence")
			}
			if got.StaticVerdict != "unknown" || strings.Contains(string(got.Result), "never_persist") {
				t.Fatal("raw report or replaced static verdict persisted")
			}
			clock.advance(5 * time.Minute)
			schedulerRound(t, q)
			got = schedulerLookup(t, s, j)
			if got.Cleanup != string(DeleteAcknowledgedUnverified) || !got.DedupBarrier {
				t.Fatal("native delete falsely proved purge or lost debt")
			}
			schedulerRound(t, q)
			if calls.Load() != 4 {
				t.Fatalf("network requests=%d, want4", calls.Load())
			}
		})
	}
}

func TestSchedulerBeginErrorNoPOST(t *testing.T) {
	var posts atomic.Int32
	c, _ := fixture(t, func(w http.ResponseWriter, _ *http.Request) { posts.Add(1); fmt.Fprint(w, success) })
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	j := schedulerAdmission(t, s, c, "alpha", "begin")
	armed := false
	s.hooks.crash = func(point string) {
		if point == "submitting_committed" {
			armed = true
		}
	}
	s.hooks.checkpoint = func() error {
		if armed {
			armed = false
			return ErrStoreUnavailable
		}
		return nil
	}
	q := testScheduler(t, s, c, nil, 1)
	schedulerRound(t, q)
	got := schedulerLookup(t, s, j)
	if posts.Load() != 0 {
		t.Fatal("POST occurred after BeginSubmission error")
	}
	if got.State != SubmitUncertain || !got.UnknownDebt || !got.SubmissionRecorded {
		t.Fatal("begin checkpoint error lost possible durable ownership")
	}
	schedulerRound(t, q)
	if posts.Load() != 0 {
		t.Fatal("uncertain begin error automatically retried POST")
	}
}

func TestSchedulerRestartNoPOST(t *testing.T) {
	var posts atomic.Int32
	c, _ := fixture(t, func(w http.ResponseWriter, _ *http.Request) { posts.Add(1); fmt.Fprint(w, success) })
	clock := newStoreClock()
	cfg := storeConfig(t.TempDir())
	s := testStore(t, cfg, clock)
	j := schedulerAdmission(t, s, c, "alpha", "restart")
	if _, e := s.BeginSubmission(context.Background(), j.Tenant, j.ID, j.Version); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s = testStore(t, cfg, clock)
	q := testScheduler(t, s, c, nil, 1)
	schedulerRound(t, q)
	clock.advance(5 * time.Minute)
	schedulerRound(t, q)
	if posts.Load() != 0 {
		t.Fatal("restart automatically repeated POST")
	}
	if schedulerLookup(t, s, j).State != SubmitUncertain {
		t.Fatal("restart lost uncertainty barrier")
	}
}

func TestSchedulerLateCancellationAndOpenFailure(t *testing.T) {
	for _, mode := range []string{"cancel", "open_failure", "storage_retry"} {
		t.Run(mode, func(t *testing.T) {
			var posts atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				fmt.Fprint(w, success)
			})
			s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
			j := schedulerAdmission(t, s, c, "alpha", mode)
			if mode == "open_failure" {
				if e := os.Remove(filepath.Join(s.cfg.Directory, "spool", j.ID+".blob")); e != nil {
					t.Fatal(e)
				}
			}
			q := testScheduler(t, s, c, nil, 1)
			live, results := schedulerDispatch(q)
			schedulerHarvest(t, q, live, results)
			if mode == "cancel" {
				if _, e := s.Cancel(context.Background(), j.Tenant, j.ID); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "storage_retry" {
				// Transaction failure before outcome commit keeps the full packet.
				if _, e := s.db.Exec(`CREATE TRIGGER reject_outcome BEFORE UPDATE ON jobs BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
					t.Fatal(e)
				}
				q.persistPending()
				if len(q.pending) != 1 || len(q.pending[0].submission.Tasks) != 1 {
					t.Fatal("failed persistence discarded late task ownership")
				}
				if _, e := s.db.Exec("DROP TRIGGER reject_outcome"); e != nil {
					t.Fatal(e)
				}
			}
			q.persistPending()
			got := schedulerLookup(t, s, j)
			if len(q.pending) != 0 {
				t.Fatal("repaired store did not record owned outcome")
			}
			if mode == "open_failure" {
				if posts.Load() != 0 || got.State != SubmitUncertain || !got.UnknownDebt {
					t.Fatal("open failure permitted retry or lost possible ownership")
				}
			} else if posts.Load() != 1 || len(got.TaskIDs) != 1 || !got.DedupBarrier {
				t.Fatal("late outcome lost owned task")
			}
			if mode == "cancel" && got.State != Cancelled {
				t.Fatal("late outcome resurrected cancelled job")
			}
		})
	}
}

func TestSchedulerBudgetBackoffHintsAndRestart(t *testing.T) {
	var calls atomic.Int32
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
			fmt.Fprint(w, success)
			return
		}
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	clock := newStoreClock()
	cfg := storeConfig(t.TempDir())
	cfg.SubmitPerMinute = 1
	cfg.TenantSubmitPerMinute = 1
	cfg.RequestsPerMinute = 1
	s := testStore(t, cfg, clock)
	j := schedulerAdmission(t, s, c, "alpha", "budget")
	q := testScheduler(t, s, c, nil, 1)
	schedulerRound(t, q)
	schedulerRound(t, q)
	if calls.Load() != 1 {
		t.Fatal("poll bypassed total budget consumed by POST")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s = testStore(t, cfg, clock)
	q = testScheduler(t, s, c, nil, 1)
	schedulerRound(t, q)
	if calls.Load() != 1 {
		t.Fatal("restart refilled total request bucket")
	}
	clock.advance(time.Minute)
	schedulerRound(t, q)
	got := schedulerLookup(t, s, j)
	if calls.Load() != 2 || got.NextAttempt.Before(clock.Now().Add(120*time.Second)) {
		t.Fatal("throttle did not persist RetryAfter")
	}
	// Model the persisted wake hint. It grants no authority to move retry time.
	if e := s.transaction(context.Background(), func(tx *sql.Tx) error {
		previousJob := got
		got.PollWakeAt = clock.Now()
		got.Version++
		return putJob(tx, got, previousJob)
	}); e != nil {
		t.Fatal(e)
	}
	clock.advance(time.Minute)
	schedulerRound(t, q)
	if calls.Load() != 2 {
		t.Fatal("callback hint bypassed persisted backoff")
	}
	clock.advance(time.Minute)
	schedulerRound(t, q)
	if calls.Load() != 3 {
		t.Fatal("due authoritative polling failed after throttle")
	}
}

func TestSchedulerAuthPauseAndRecovery(t *testing.T) {
	var calls atomic.Int32
	c, _ := fixture(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusUnauthorized) })
	clock := newStoreClock()
	cfg := storeConfig(t.TempDir())
	s := testStore(t, cfg, clock)
	j := schedulerAdmission(t, s, c, "alpha", "auth")
	q := testScheduler(t, s, c, nil, 1)
	schedulerRound(t, q)
	if schedulerLookup(t, s, j).State != SubmitUncertain {
		t.Fatal("unauthorized POST lost ambiguity")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s = testStore(t, cfg, clock)
	r := storeRequest("beta")
	r.Generation = c.generation
	if _, e := s.Enqueue(context.Background(), r, source("new")); outcomeCode(e) != Unauthorized {
		t.Fatal("credential failure did not persist admission pause")
	}
	if e := s.SetGenerationAdmission(context.Background(), c.generation, true); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Enqueue(context.Background(), r, source("new")); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatal("credential recovery unexpectedly sent network request")
	}
}

func TestSchedulerRunMaintenanceAndOwner(t *testing.T) {
	c, _ := fixture(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("expired queue sent request") })
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	j := schedulerAdmission(t, s, c, "alpha", "expired")
	clock.advance(time.Hour)
	q := testScheduler(t, s, c, nil, 1)
	q.interval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for schedulerLookup(t, s, j).State != Expired {
		if time.Now().After(deadline) {
			t.Fatal("outage maintenance did not expire queue")
		}
		time.Sleep(time.Millisecond)
	}
	other := testScheduler(t, s, c, nil, 1)
	if e := other.Run(context.Background()); !errors.Is(e, ErrConflict) {
		t.Fatal("second scheduler owner accepted")
	}
	if e := s.Close(); !errors.Is(e, ErrConflict) {
		t.Fatal("store closed beneath live scheduler")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scheduler shutdown did not join")
	}
}

func TestNormalizedResultBounds(t *testing.T) {
	for _, result := range []NormalizedResult{
		{}, {Version: 2, Policy: "r1", Evidence: EvidenceNoSignal}, {Version: 1, Policy: "wrong", Evidence: EvidenceNoSignal},
		{Version: 1, Policy: "r1", Evidence: EvidenceMalicious}, {Version: 1, Policy: "r1", Evidence: EvidenceNoSignal, Signals: []string{"x"}},
		{Version: 1, Policy: "r1", Evidence: EvidenceSuspicious, Signals: []string{"x", "x"}},
		{Version: 1, Policy: "r1", Evidence: EvidenceSuspicious, Signals: []string{"raw text"}},
	} {
		if _, e := normalizedBytes(result, "r1"); e == nil {
			t.Fatal("invalid normalized result accepted")
		}
	}
	result := NormalizedResult{Version: 1, Policy: "r1", Evidence: EvidenceSuspicious}
	for i := 0; i < 128; i++ {
		result.Signals = append(result.Signals, fmt.Sprintf("%03d%s", i, strings.Repeat("a", 125)))
	}
	if _, e := normalizedBytes(result, "r1"); outcomeCode(e) != TooLarge {
		t.Fatal("oversized typed result accepted")
	}
	if b, e := normalizedBytes(NormalizedResult{Version: 1, Policy: "r1", Evidence: EvidenceMalicious, Signals: []string{"configured_signal"}}, "r1"); e != nil || !json.Valid(b) {
		t.Fatal("valid bounded typed result rejected")
	}
}
