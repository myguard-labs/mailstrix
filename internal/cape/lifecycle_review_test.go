//go:build linux

package cape

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestLifecycleLoweredQuota(t *testing.T) {
	ctx := context.Background()
	clock := newStoreClock()
	cfg := storeConfig(t.TempDir())
	s := testStore(t, cfg, clock)
	enqueueBytes(t, s, "alpha", "a")
	enqueueBytes(t, s, "alpha", "b")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.MaxJobs = 1
	cfg.TenantJobs = 1
	s = testStore(t, cfg, clock)
	clock.advance(time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal("lowered admission quota blocked expiry", err)
	}
	clock.advance(24 * time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := storeCount(t, s); n != 0 {
		t.Fatal("lowered quota did not drain expired rows")
	}
}

func TestLifecycleCleanupCursorRollsBackOnTransactionFailure(t *testing.T) {
	ctx := context.Background()
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	j := enqueueBytes(t, s, "alpha", "cursor-rollback").Job
	if _, err := s.Cancel(ctx, j.Tenant, j.ID); err != nil {
		t.Fatal(err)
	}
	clock.advance(25 * time.Hour)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_cursor_delete BEFORE DELETE ON jobs BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	before := s.maintenanceCleanupCursor
	if err := s.Maintain(ctx); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("maintenance error=%v want store unavailable", err)
	}
	if s.maintenanceCleanupCursor != before {
		t.Fatalf("failed cleanup advanced cursor from %q to %q", before, s.maintenanceCleanupCursor)
	}
}

func TestLifecycleRollbackCancel(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "queued", true: "completed"}[completed], func(t *testing.T) {
			ctx := context.Background()
			clock := newStoreClock()
			s := testStore(t, storeConfig(t.TempDir()), clock)
			j := enqueueBytes(t, s, "alpha", "rollback").Job
			first := clock.Now()
			if completed {
				if err := s.transaction(ctx, func(tx *sql.Tx) error {
					previousJob := j
					j.State = Completed
					j.TerminalAt = first
					j.Result = []byte(`{"evidence":"no_signal"}`)
					j.Version++
					return putJob(tx, j, previousJob)
				}); err != nil {
					t.Fatal(err)
				}
			}
			clock.advance(-time.Minute)
			j, err := s.Cancel(ctx, "alpha", j.ID)
			if err != nil || j.State != Cancelled || !j.Suppressed || len(j.Result) != 0 || !j.TerminalAt.Equal(first) {
				t.Fatal("clock rollback prevented restrictive cancellation", err)
			}
			_, err = s.BeginSubmission(ctx, "alpha", j.ID, j.Version)
			if !errors.Is(err, ErrConflict) {
				t.Fatal("cancelled job reopened", err)
			}
			if err = s.TakeRequestToken(ctx); !errors.Is(err, ErrClock) {
				t.Fatal("cancellation unpaused clock rollback", err)
			}
		})
	}
}

func TestLifecycleLiveAttemptOccupancy(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "outcome", true: "restart"}[restart], func(t *testing.T) {
			ctx := context.Background()
			clock := newStoreClock()
			cfg := storeConfig(t.TempDir())
			cfg.SubmissionConcurrency = 1
			cfg.TenantSubmissionConcurrency = 1
			s := testStore(t, cfg, clock)
			a := enqueueBytes(t, s, "alpha", "a").Job
			b := enqueueBytes(t, s, "beta", "b").Job
			a, err := s.BeginSubmission(ctx, a.Tenant, a.ID, a.Version)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Cancel(ctx, a.Tenant, a.ID); err != nil {
				t.Fatal(err)
			}
			if restart {
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				s = testStore(t, cfg, clock)
			} else {
				_, err = s.BeginSubmission(ctx, b.Tenant, b.ID, b.Version)
				assertStoreCode(t, err, Throttled)
				if _, err = s.RecordSubmission(ctx, a.Tenant, a.ID, a.Version, Submission{NoBytesSent: true}, Transport, 0); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = s.BeginSubmission(ctx, b.Tenant, b.ID, b.Version); err != nil {
				t.Fatal("finished/abandoned attempt retained concurrency", err)
			}
		})
	}
}

func TestLifecycleMaintenanceStableVersion(t *testing.T) {
	ctx := context.Background()
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	j := enqueueBytes(t, s, "alpha", "stable").Job
	j, err := s.BeginSubmission(ctx, j.Tenant, j.ID, j.Version)
	if err != nil {
		t.Fatal(err)
	}
	task := TaskRef{ID: 42, Generation: "g1"}
	j, err = s.RecordSubmission(ctx, j.Tenant, j.ID, j.Version, Submission{Tasks: []TaskRef{task}}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	j, err = s.Cancel(ctx, j.Tenant, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(25 * time.Hour)
	if err = s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	j, err = s.Lookup(ctx, j.Tenant, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := s.Lookup(ctx, j.Tenant, j.ID)
	if err != nil || after.Version != j.Version {
		t.Fatal("unchanged maintenance advanced version", err)
	}
	if _, err = s.RecordDeletion(ctx, j.Tenant, j.ID, j.Version, task, DeleteAcknowledgedUnverified, ""); err != nil {
		t.Fatal("unchanged maintenance invalidated deletion outcome", err)
	}
}

// A scheduler cancellation can occur before Query or during row iteration.
// Hold real SQLite rows, then observe cancellation before invoking the scan.
func TestP10CAPEScanJobBatchContext(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("canceled=%v", canceled), func(t *testing.T) {
			s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
			job := enqueueBytes(t, s, "alpha", "payload").Job
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rows, err := s.db.QueryContext(ctx, "SELECT document FROM jobs WHERE id=?", job.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := rows.Close(); err != nil {
					t.Error(err)
				}
			}()
			if canceled {
				cancel()
				deadline := time.Now().Add(2 * time.Second)
				for rows.Err() == nil {
					if time.Now().After(deadline) {
						t.Fatal("SQLite rows never observed context cancellation")
					}
					runtime.Gosched()
				}
				if !errors.Is(rows.Err(), context.Canceled) {
					t.Fatalf("SQLite cancellation fixture error=%v", rows.Err())
				}
			}
			jobs, err := scanJobBatch(rows, 1)
			if canceled {
				if !errors.Is(err, ErrStoreUnavailable) || jobs != nil {
					t.Fatalf("canceled row scan: jobs=%v error=%v", jobs, err)
				}
			} else if err != nil || len(jobs) != 1 || jobs[0].ID != job.ID {
				t.Fatalf("live row scan: jobs=%v error=%v", jobs, err)
			}
		})
	}
}

// Query/scan failures used to be covered only if cancellation won a race.
// A malformed queued document deterministically exercises scan propagation.
func TestP10CAPESchedulerCorruptRow(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed=%v", malformed), func(t *testing.T) {
			s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
			job := enqueueBytes(t, s, "alpha", "payload").Job
			if malformed {
				var original []byte
				if err := s.db.QueryRow("SELECT document FROM jobs WHERE id=?", job.ID).Scan(&original); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := s.db.Exec("UPDATE jobs SET document=? WHERE id=?", original, job.ID); err != nil {
						t.Error(err)
					}
				}()
				if _, err := s.db.Exec("UPDATE jobs SET document=? WHERE id=?", []byte("{"), job.ID); err != nil {
					t.Fatal(err)
				}
			}
			jobs, err := s.schedulerJobs(context.Background())
			if malformed {
				if !errors.Is(err, ErrStoreUnavailable) || jobs != nil {
					t.Fatalf("scheduler malformed row: jobs=%v error=%v", jobs, err)
				}
			} else if err != nil || len(jobs) != 1 || jobs[0].ID != job.ID {
				t.Fatalf("scheduler valid row: jobs=%v error=%v", jobs, err)
			}
		})
	}
}
