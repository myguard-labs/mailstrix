//go:build linux

package cape

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ownedTerminal(t *testing.T, s *Store, c *Client, tenant, body string, taskID int64) Job {
	t.Helper()
	j := schedulerAdmission(t, s, c, tenant, body)
	a, e := s.BeginSubmission(context.Background(), tenant, j.ID, j.Version)
	if e != nil {
		t.Fatal(e)
	}
	j, e = s.RecordSubmission(context.Background(), tenant, j.ID, a.SubmissionVersion, Submission{Tasks: []TaskRef{{ID: taskID, Generation: c.generation}}}, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	j, e = s.Cancel(context.Background(), tenant, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	return j
}

func TestSchedulerDeletionFirstTenantFairBudget(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	})
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	_ = ownedTerminal(t, s, c, "alpha", "a1", 41)
	clock.advance(time.Second)
	_ = ownedTerminal(t, s, c, "alpha", "a2", 42)
	clock.advance(time.Second)
	_ = ownedTerminal(t, s, c, "beta", "b1", 43)
	_ = schedulerAdmission(t, s, c, "beta", "queued")
	q := testScheduler(t, s, c, nil, 1)
	schedulerRound(t, q)
	schedulerRound(t, q)
	schedulerRound(t, q)
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[0] != "/apiv2/tasks/delete/41/" || paths[1] != "/apiv2/tasks/delete/43/" {
		t.Fatalf("deletion-first tenant request order/budget = %v", paths)
	}
}

func TestSchedulerCleanupDeadlineAndOldGeneration(t *testing.T) {
	var oldCalls, newCalls atomic.Int32
	previousClient, _ := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		oldCalls.Add(1)
		fmt.Fprint(w, `{"data":"Task(s) ID(s) 41 has been deleted"}`)
	})
	unused, cfg := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		newCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	_ = unused
	cfg.Generation = "new-generation"
	newClient, e := New(cfg, credentialFunc(func(context.Context, string) (string, error) { return "inert", nil }))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = newClient.Close() })
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	j := ownedTerminal(t, s, previousClient, "alpha", "old", 41)
	q, e := NewScheduler(s, map[string]*Client{previousClient.generation: previousClient, newClient.generation: newClient}, nil, 1)
	if e != nil {
		t.Fatal(e)
	}
	schedulerRound(t, q)
	if oldCalls.Load() != 1 || newCalls.Load() != 0 {
		t.Fatal("old generation cleanup used new credentials/endpoint")
	}
	clock.advance(48 * time.Hour)
	if e := s.Maintain(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := s.markCleanupDeadlines(context.Background()); e != nil {
		t.Fatal(e)
	}
	schedulerRound(t, q)
	got := schedulerLookup(t, s, j)
	if !got.CleanupDeadlineExceeded || !got.DedupBarrier || got.Cleanup != string(DeleteAcknowledgedUnverified) {
		t.Fatal("48h deadline hid unverified purge debt")
	}
	clock.advance(5 * 24 * time.Hour)
	r := storeRequest("alpha")
	r.Generation = newClient.generation
	if _, e := s.Enqueue(context.Background(), r, source("new")); !errors.Is(e, ErrQuota) {
		t.Fatalf("7day debt did not pause tenant: %v", e)
	}
}

func TestSchedulerDeleteMissingOrphanTimeoutNeverPurge(t *testing.T) {
	for _, mode := range []string{"missing", "orphan", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "missing":
					w.WriteHeader(http.StatusNotFound)
				case "orphan":
					fmt.Fprint(w, `{"data":"orphaned"}`)
				case "timeout":
					<-r.Context().Done()
				}
			})
			if mode == "timeout" {
				c.http.Timeout = 20 * time.Millisecond
			}
			s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
			j := ownedTerminal(t, s, c, "alpha", mode, 41)
			q := testScheduler(t, s, c, nil, 1)
			schedulerRound(t, q)
			got := schedulerLookup(t, s, j)
			if got.Cleanup != "remote_delete_failed/unknown" || !got.DedupBarrier || len(got.DeleteAcknowledgedIDs) != 0 {
				t.Fatal("missing/orphan/timeout falsely confirmed purge")
			}
		})
	}
}

func fetchingFixture(t *testing.T) (*Store, *fakeStoreClock, Job, *Report, TaskRef) {
	t.Helper()
	digest := sha256.Sum256([]byte("report"))
	c, _ := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"info":{"id":41,"category":"file"},"target":{"category":"file","file":{"sha256":"%x"}}}`, digest)
	})
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	j := schedulerAdmission(t, s, c, "alpha", "report")
	a, e := s.BeginSubmission(context.Background(), j.Tenant, j.ID, j.Version)
	if e != nil {
		t.Fatal(e)
	}
	task := TaskRef{ID: 41, Generation: c.generation}
	j, e = s.RecordSubmission(context.Background(), j.Tenant, j.ID, a.SubmissionVersion, Submission{Tasks: []TaskRef{task}}, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	// A completed status is explicitly not a report-availability transition.
	j, e = s.RecordStatus(context.Background(), j.Tenant, j.ID, j.Version, task, "completed")
	if e != nil {
		t.Fatal(e)
	}
	if j.State != RemotePending {
		t.Fatal("completed status invented report availability")
	}
	j, e = s.RecordStatus(context.Background(), j.Tenant, j.ID, j.Version, task, "reported")
	if e != nil {
		t.Fatal(e)
	}
	report, e := c.Report(context.Background(), task, digest)
	if e != nil {
		t.Fatal(e)
	}
	return s, clock, j, report, task
}

func TestReportCheckedIdentityAndMapper(t *testing.T) {
	for _, mode := range []string{"task", "hash", "generation", "category", "unsealed", "stale", "tenant", "cancel_mapper", "deadline_mapper", "callback_mapper"} {
		t.Run(mode, func(t *testing.T) {
			s, clock, j, report, task := fetchingFixture(t)
			var mapped bool
			mapper := mapperFunc(func(ctx context.Context, _ *Report, p string) (NormalizedResult, error) {
				mapped = true
				if mode == "cancel_mapper" {
					if _, e := s.Cancel(ctx, j.Tenant, j.ID); e != nil {
						t.Fatal(e)
					}
				}
				if mode == "deadline_mapper" {
					clock.advance(24 * time.Hour)
				}
				if mode == "callback_mapper" {
					if e := s.transaction(ctx, func(tx *sql.Tx) error {
						fresh, e := readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=?", j.ID))
						if e != nil {
							return e
						}
						previousJob := fresh
						fresh.PollWakeAt = clock.Now()
						fresh.Version++
						return putJob(tx, fresh, previousJob)
					}); e != nil {
						t.Fatal(e)
					}
				}
				return NormalizedResult{Version: 1, Policy: p, Evidence: EvidenceNoSignal}, nil
			})
			tenant := j.Tenant
			version := j.Version
			switch mode {
			case "task":
				report.document["info"].(map[string]any)["id"] = json.Number("42")
			case "hash":
				report.document["target"].(map[string]any)["file"].(map[string]any)["sha256"] = strings.Repeat("a", 64)
			case "generation":
				report.task.Generation = "other"
			case "category":
				report.document["info"].(map[string]any)["category"] = "url"
			case "unsealed":
				report = &Report{document: report.document}
			case "stale":
				version--
			case "tenant":
				tenant = "beta"
			}
			_, e := s.CompleteReport(context.Background(), tenant, j.ID, version, task, report, mapper)
			got := schedulerLookup(t, s, j)
			if got.State == Completed || len(got.Result) != 0 {
				t.Fatal("unchecked identity/state published report evidence")
			}
			if strings.HasSuffix(mode, "mapper") {
				if !mapped || e == nil {
					t.Fatal("late mapper state/deadline race not checked")
				}
			} else if mapped {
				t.Fatal("invalid identity reached trusted mapper")
			} else if mode == "stale" {
				if !errors.Is(e, ErrConflict) {
					t.Fatal("stale store identity did not conflict")
				}
			} else if mode == "tenant" {
				if e == nil {
					t.Fatal("unknown tenant identity did not fail")
				}
			} else if e != nil || got.State != Failed || got.Reason != Protocol {
				t.Fatal("invalid report identity did not publish a protocol failure")
			}
		})
	}
}

func TestReportMapperMutationRejected(t *testing.T) {
	s, _, j, report, task := fetchingFixture(t)
	mapper := mapperFunc(func(_ context.Context, report *Report, p string) (NormalizedResult, error) {
		report.document["info"].(map[string]any)["id"] = json.Number("42")
		return NormalizedResult{Version: 1, Policy: p, Evidence: EvidenceNoSignal}, nil
	})
	got, err := s.CompleteReport(context.Background(), j.Tenant, j.ID, j.Version, task, report, mapper)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != Failed || got.Reason != Protocol || len(got.Result) != 0 {
		t.Fatalf("mapper-mutated report envelope was published: state=%s reason=%s result-bytes=%d", got.State, got.Reason, len(got.Result))
	}
}

func TestSchedulerCancelledRunHarvestsOwnedOutcome(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, success)
	})
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	j := schedulerAdmission(t, s, c, "alpha", "shutdown")
	q := testScheduler(t, s, c, nil, 1)
	live, results := schedulerDispatch(q)
	schedulerHarvest(t, q, live, results)
	if _, e := s.Cancel(context.Background(), j.Tenant, j.ID); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := q.Run(ctx); e != nil {
		t.Fatal(e)
	}
	got := schedulerLookup(t, s, j)
	if got.State != Cancelled || len(got.TaskIDs) != 1 || !got.SubmissionRecorded {
		t.Fatal("shutdown context discarded late ID ownership")
	}
}

func TestSchedulerLiveSubmissionTenantAndGlobalLimits(t *testing.T) {
	var count atomic.Int32
	release := make(chan struct{})
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		select {
		case <-release:
			fmt.Fprint(w, success)
		case <-r.Context().Done():
		}
	})
	defer close(release)
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	_ = schedulerAdmission(t, s, c, "alpha", "a1")
	_ = schedulerAdmission(t, s, c, "alpha", "a2")
	_ = schedulerAdmission(t, s, c, "beta", "b1")
	q := testScheduler(t, s, c, nil, 3)
	live, results := schedulerDispatch(q)
	defer func() {
		for _, v := range live {
			v.cancel()
		}
	}()
	if len(live) != 2 {
		t.Fatal("submission occupancy did not enforce per-tenant/global live limits")
	}
	for _, v := range live {
		if _, e := s.Cancel(context.Background(), v.job.Tenant, v.job.ID); e != nil {
			t.Fatal(e)
		}
	}
	q.dispatch(context.Background(), live, results)
	if len(live) != 2 {
		t.Fatal("cancellation released live submission occupancy")
	}
	for _, v := range live {
		v.cancel()
	}
	schedulerHarvest(t, q, live, results)
	q.persistPending()
}

func TestReportTransportIdentitySeal(t *testing.T) {
	_, _, j, r, task := fetchingFixture(t)
	decoded, e := hex.DecodeString(j.Digest)
	if e != nil {
		t.Fatal(e)
	}
	if r.task != task || !strings.EqualFold(hex.EncodeToString(r.digest[:]), hex.EncodeToString(decoded)) {
		t.Fatal("transport report did not preserve generation/digest identity")
	}
}

func TestSchedulerShutdownStorageFailureRetainsPacket(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, success)
	})
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	j := schedulerAdmission(t, s, c, "alpha", "shutdown-storage")
	q := testScheduler(t, s, c, nil, 1)
	q.drainTimeout = 500 * time.Millisecond
	live, results := schedulerDispatch(q)
	schedulerHarvest(t, q, live, results)
	if _, e := s.db.Exec(`CREATE TRIGGER reject_shutdown BEFORE UPDATE ON jobs BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if e := q.Run(ctx); !errors.Is(e, ErrStoreUnavailable) {
		t.Fatal("shutdown did not report unresolved durable ownership")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("shutdown persistence exceeded bounded drain")
	}
	if len(q.pending) != 1 || len(q.pending[0].submission.Tasks) != 1 || schedulerLookup(t, s, j).State != Submitting {
		t.Fatal("shutdown storage failure discarded pending ownership")
	}
	if _, e := s.db.Exec("DROP TRIGGER reject_shutdown"); e != nil {
		t.Fatal(e)
	}
	if e := q.Run(ctx); e != nil {
		t.Fatal(e)
	}
	if len(q.pending) != 0 || len(schedulerLookup(t, s, j).TaskIDs) != 1 {
		t.Fatal("repaired shutdown retry lost task ID")
	}
}

func TestLiveLookupCancellationRequiresAuthoritativeState(t *testing.T) {
	active := Job{State: Submitting}
	for name, tc := range map[string]struct {
		current Job
		err     error
		want    bool
	}{
		"transient-store": {err: ErrStoreUnavailable},
		"deadline":        {err: context.DeadlineExceeded},
		"not-found":       {err: &Error{Code: NotFound}, want: true},
		"terminal":        {current: Job{State: Failed}, want: true},
		"still-live":      {current: Job{State: RemotePending}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := cancelLiveLookup(active, tc.current, tc.err); got != tc.want {
				t.Fatalf("cancel=%v want=%v", got, tc.want)
			}
		})
	}
}
