//go:build linux

package cape

import (
	"context"
	"database/sql"
	"errors"
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
