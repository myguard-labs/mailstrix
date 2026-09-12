//go:build linux

package cape

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type schedulerRoundTripFunc func(*http.Request) (*http.Response, error)

func (f schedulerRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func schedulerPhase(t *testing.T, phase <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-phase:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func TestSchedulerRunLiveShutdownHarvest(t *testing.T) {
	started := make(chan struct{})
	var requests atomic.Int32
	c, _ := fixture(t, func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		requests.Add(1)
		close(started)
		<-r.Context().Done()
	})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	// Hold the real TLS transport outcome until Run has entered its shutdown
	// join. This isolates the join path from the ordinary select receive path.
	c.http.Transport = schedulerRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := c.transport.RoundTrip(r)
		<-release
		return response, err
	})
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	j := schedulerAdmission(t, s, c, "alpha", "run-shutdown")
	q := testScheduler(t, s, c, nil, 1)
	joining := make(chan struct{})
	q.beforeJoin = func() { close(joining) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()
	joined := false
	t.Cleanup(func() {
		cancel()
		unblock()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("cleanup could not join Run")
			}
		}
	})
	schedulerPhase(t, started, "Run did not start real TLS POST")
	cancel()
	schedulerPhase(t, joining, "Run did not enter live shutdown join")
	unblock()
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not join cancelled TLS request")
	}
	got := schedulerLookup(t, s, j)
	if requests.Load() != 1 || got.State != SubmitUncertain || !got.SubmissionRecorded || !got.UnknownDebt || !got.DedupBarrier {
		t.Fatal("Run shutdown join discarded live submission outcome ownership")
	}
	s.mu.Lock()
	occupied := len(s.liveAttempts)
	s.mu.Unlock()
	if occupied != 0 {
		t.Fatal("joined submission retained live occupancy")
	}
}

func TestSchedulerRunCancelsStoredJobWhileActive(t *testing.T) {
	started := make(chan struct{})
	transportCancelled := make(chan struct{})
	var requests atomic.Int32
	c, _ := fixture(t, func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		requests.Add(1)
		close(started)
		<-r.Context().Done()
		close(transportCancelled)
	})
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	j := schedulerAdmission(t, s, c, "alpha", "run-job-cancel")
	q := testScheduler(t, s, c, nil, 1)
	q.interval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("cleanup could not join active Run")
		}
	})
	schedulerPhase(t, started, "Run did not start real TLS POST")
	if _, err := s.Cancel(context.Background(), j.Tenant, j.ID); err != nil {
		t.Fatal(err)
	}
	schedulerPhase(t, transportCancelled, "Run watcher did not cancel stored job's live TLS request")
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := schedulerLookup(t, s, j)
		if got.SubmissionRecorded {
			if got.State != Cancelled || !got.UnknownDebt || !got.DedupBarrier || requests.Load() != 1 {
				t.Fatal("Run job cancellation discarded submission debt")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not persist cancelled live request outcome")
		}
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("watcher test cancelled Run instead of the stored job")
	}
}

func TestSchedulerDrainAbsoluteDeadline(t *testing.T) {
	for _, mode := range []string{"remaining", "expired"} {
		t.Run(mode, func(t *testing.T) {
			s, _, j, report, task := fetchingFixture(t)
			deadline := time.Now().Add(2 * time.Second)
			if mode == "expired" {
				deadline = time.Now().Add(-time.Second)
			}
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			var calls int
			var passes int
			q := &Scheduler{store: s, mapper: mapperFunc(func(child context.Context, _ *Report, _ string) (NormalizedResult, error) {
				calls++
				limit, ok := child.Deadline()
				if !ok || limit.After(deadline) {
					t.Error("persistence child deadline exceeds absolute drain budget")
					return NormalizedResult{}, errors.New("fixture")
				}
				cancel()
				<-child.Done()
				return NormalizedResult{}, child.Err()
			}), pending: []schedulerResult{{job: j, kind: "report", task: task, report: report}}, beforePersist: func(context.Context) { passes++ }}
			if err := q.drainPending(ctx); !errors.Is(err, ErrStoreUnavailable) {
				t.Fatal("drain did not retain failed pending outcome")
			}
			if mode == "remaining" && calls != 1 {
				t.Fatal("remaining drain budget did not bound one cooperative mapping pass")
			}
			if mode == "expired" && calls != 0 {
				t.Fatal("expired drain budget started a persistence pass")
			}
			if mode == "expired" && passes != 0 {
				t.Fatal("expired drain budget started a persistence pass")
			}
			if len(q.pending) != 1 || schedulerLookup(t, s, j).State != Fetching {
				t.Fatal("exhausted drain lost pending ownership")
			}
		})
	}
}
