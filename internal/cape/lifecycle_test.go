//go:build linux

package cape

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLifecycleLateSubmission(t *testing.T) {
	for _, mode := range []string{"success", "partial", "no_bytes", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			clock := newStoreClock()
			s := testStore(t, storeConfig(t.TempDir()), clock)
			a := enqueueBytes(t, s, "alpha", "late")
			attempt, err := s.BeginSubmission(ctx, "alpha", a.Job.ID, a.Job.Version)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "expired" {
				clock.advance(24 * time.Hour)
				err = s.Maintain(ctx)
			} else {
				_, err = s.Cancel(ctx, "alpha", a.Job.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := s.Lookup(ctx, "alpha", a.Job.ID)
			if err != nil {
				t.Fatal(err)
			}
			sub := Submission{Tasks: []TaskRef{{ID: 42, Generation: "g1"}}}
			var outcome Code
			if mode == "partial" {
				sub.Tasks = append(sub.Tasks, TaskRef{ID: 43, Generation: "g1"})
				sub.UnknownDebt = true
				outcome = Protocol
			}
			if mode == "no_bytes" {
				sub = Submission{NoBytesSent: true}
				outcome = Transport
			}
			_, err = s.RecordSubmission(ctx, "beta", attempt.ID, attempt.Version, sub, outcome, 0)
			assertStoreCode(t, err, NotFound)
			j, err := s.RecordSubmission(ctx, "alpha", attempt.ID, attempt.Version, sub, outcome, 0)
			if err != nil {
				t.Fatal(err)
			}
			if j.State != before.State || !j.TerminalAt.Equal(before.TerminalAt) || len(j.TaskIDs) != len(sub.Tasks) {
				t.Fatal("late outcome resurrected job or discarded IDs/terminal age")
			}
			if mode == "no_bytes" {
				if j.UnknownDebt || j.DedupBarrier || j.Cleanup != "not_submitted" {
					t.Fatal("positive no-send proof did not release debt")
				}
			} else if !j.DedupBarrier || j.Cleanup == "not_submitted" {
				t.Fatal("late task cleanup ownership lost")
			}
			_, err = s.RecordSubmission(ctx, "alpha", attempt.ID, attempt.Version, sub, outcome, 0)
			if !errors.Is(err, ErrConflict) {
				t.Fatal("duplicate attempt outcome accepted")
			}
			if _, err = os.Stat(filepath.Join(s.cfg.Directory, "spool", j.ID+".blob")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("terminal payload retained")
			}
		})
	}
}

func TestLifecycleRetentionAndDebt(t *testing.T) {
	ctx := context.Background()
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	queued := enqueueBytes(t, s, "alpha", "queued").Job
	uncertain := enqueueBytes(t, s, "beta", "uncertain").Job
	attempt, err := s.BeginSubmission(ctx, uncertain.Tenant, uncertain.ID, uncertain.Version)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.RecordSubmission(ctx, attempt.Tenant, attempt.ID, attempt.Version, Submission{}, Transport, 0)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	q, err := s.Lookup(ctx, queued.Tenant, queued.ID)
	if err != nil || q.State != Expired || q.TerminalAt.IsZero() {
		t.Fatal("queue deadline not enforced", err)
	}
	clock.advance(23 * time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	u, err := s.Lookup(ctx, uncertain.Tenant, uncertain.ID)
	if err != nil || u.State != Expired || !u.UnknownDebt || !u.DedupBarrier {
		t.Fatal("uncertain expiry lost debt/barrier", err)
	}
	_, err = s.Cancel(ctx, queued.Tenant, queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = s.Lookup(ctx, queued.Tenant, queued.ID)
	assertStoreCode(t, err, NotFound)
	clock.advance(24 * time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	u, err = s.Lookup(ctx, uncertain.Tenant, uncertain.ID)
	if err != nil || !u.UnknownDebt || !u.DedupBarrier || !u.Suppressed || len(u.Result) != 0 {
		t.Fatal("retention deleted unresolved debt", err)
	}
	duplicate := enqueueBytes(t, s, "beta", "uncertain")
	if !duplicate.Reused || duplicate.Job.ID != u.ID {
		t.Fatal("retained debt allowed resubmission")
	}
}

func TestLifecycleCompletedCancel(t *testing.T) {
	ctx := context.Background()
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	j := enqueueBytes(t, s, "alpha", "result").Job
	first := clock.Now()
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		previousJob := j
		j.State = Completed
		j.TerminalAt = first
		j.Result = []byte(`{"evidence":"no_signal"}`)
		j.Version++
		return putJob(tx, j, previousJob)
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(23 * time.Hour)
	j, err = s.Cancel(ctx, "alpha", j.ID)
	if err != nil || j.State != Cancelled || !j.Suppressed || len(j.Result) != 0 || !j.TerminalAt.Equal(first) {
		t.Fatal("completed cancellation retained result or moved terminal_at", err)
	}
	_, err = s.RecordSubmission(ctx, "alpha", j.ID, 0, Submission{Tasks: []TaskRef{{ID: 42, Generation: "g1"}}}, "", 0)
	if !errors.Is(err, ErrConflict) {
		t.Fatal("nonexistent attempt adopted a task")
	}
	clock.advance(time.Hour)
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = s.Lookup(ctx, "alpha", j.ID)
	assertStoreCode(t, err, NotFound)
}

func TestLifecycleDeleteIsNotPurge(t *testing.T) {
	ctx := context.Background()
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	j := enqueueBytes(t, s, "alpha", "delete").Job
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
	_, err = s.RecordDeletion(ctx, j.Tenant, j.ID, j.Version, TaskRef{ID: 99, Generation: "g1"}, DeleteAcknowledgedUnverified, "")
	if !errors.Is(err, ErrConflict) {
		t.Fatal("unowned deletion accepted")
	}
	j, err = s.RecordDeletion(ctx, j.Tenant, j.ID, j.Version, task, "", NotFound)
	if err != nil || j.Cleanup != "remote_delete_failed/unknown" {
		t.Fatal("missing task treated as purge", err)
	}
	j, err = s.RecordDeletion(ctx, j.Tenant, j.ID, j.Version, task, DeleteAcknowledgedUnverified, "")
	if err != nil || j.Cleanup != string(DeleteAcknowledgedUnverified) || !j.DedupBarrier {
		t.Fatal("native deletion overclaimed purge", err)
	}
	clock.advance(25 * time.Hour)
	if err = s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	j, err = s.Lookup(ctx, j.Tenant, j.ID)
	if err != nil || j.Cleanup != string(DeleteAcknowledgedUnverified) || !j.DedupBarrier {
		t.Fatal("unverified deletion debt expired", err)
	}
}

func TestLifecycleCancelStagingWriter(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	body := newBlockingBody()
	body.release = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(body.release) }) }
	defer release()
	defer body.Close()
	done := make(chan error, 1)
	go func() { _, err := s.Enqueue(ctx, storeRequest("alpha"), body); done <- err }()
	select {
	case <-body.entered:
	case <-time.After(time.Second):
		t.Fatal("staging writer did not enter Read")
	}
	jobs, err := s.List(ctx, "alpha", Staging, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatal("missing staging writer", err)
	}
	_, err = s.Cancel(ctx, "beta", jobs[0].ID)
	assertStoreCode(t, err, NotFound)
	_, err = s.Cancel(ctx, "alpha", jobs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("staging cancellation did not close body")
	}
	if count, _ := storeCount(t, s); count != 1 {
		t.Fatal("cancellation released live writer reservation")
	}
	release()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled ingress published")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled staging writer did not finish")
	}
	if count, _ := storeCount(t, s); count != 0 {
		t.Fatal("stopped cancelled writer retained reservation")
	}
}
