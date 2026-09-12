//go:build linux

package cape

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestMaintainRetriesCommittedSubmissionUnlink(t *testing.T) {
	for _, state := range []JobState{RemotePending, Fetching} {
		t.Run(string(state), func(t *testing.T) {
			ctx := context.Background()
			var posts atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
					_, _ = io.Copy(io.Discard, r.Body)
					fmt.Fprint(w, success)
					return
				}
				// Safe reads can remain unavailable without another submission.
				w.WriteHeader(http.StatusServiceUnavailable)
			})
			clock := newStoreClock()
			s := testStore(t, storeConfig(t.TempDir()), clock)
			j := schedulerAdmission(t, s, c, "alpha", "inert cleanup witness")
			blob := filepath.Join(s.cfg.Directory, "spool", j.ID+".blob")
			saved := blob + ".saved"
			faults := 0
			s.hooks.crash = func(point string) {
				if point != "submission_recorded" {
					return
				}
				faults++
				// Preserve the exact payload, but make unlinkat fail on a real
				// directory at its name. This works even when tests run as root.
				if err := os.Rename(blob, saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(blob, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			q := testScheduler(t, s, c, nil, 1)
			live, results := schedulerDispatch(q)
			schedulerHarvest(t, q, live, results)
			if len(q.pending) != 1 {
				t.Fatal("submission did not produce an outcome")
			}
			if err := q.persist(ctx, q.pending[0]); !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("postcommit unlink failure not surfaced: %v", err)
			}
			j = schedulerLookup(t, s, j)
			if faults != 1 || j.State != RemotePending || !j.SubmissionRecorded || len(j.TaskIDs) != 1 || posts.Load() != 1 {
				t.Fatal("unlink fault did not follow committed single submission")
			}
			q.persistPending()
			if len(q.pending) != 0 {
				t.Fatal("already-recorded packet not drained")
			}
			if state == Fetching {
				var err error
				j, err = s.RecordStatus(ctx, j.Tenant, j.ID, j.Version, TaskRef{ID: j.TaskIDs[0], Generation: j.Generation}, Status("reported"))
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Maintain(ctx); !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("maintenance did not retry active payload unlink: %v", err)
			}
			if got := schedulerLookup(t, s, j); !reflect.DeepEqual(got, j) {
				t.Fatal("failed cleanup changed job ownership, debt, version or deadlines")
			}
			if err := os.Remove(blob); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(saved, blob); err != nil {
				t.Fatal(err)
			}
			if body, err := os.ReadFile(blob); err != nil || string(body) != "inert cleanup witness" {
				t.Fatal("fault recovery did not restore original payload", err)
			}
			for i := 0; i < 2; i++ {
				if err := s.Maintain(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(blob); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("maintenance retained submitted payload", err)
				}
				if got := schedulerLookup(t, s, j); !reflect.DeepEqual(got, j) {
					t.Fatal("successful cleanup changed job ownership, debt, version or deadlines")
				}
			}
			clock.advance(time.Minute)
			schedulerRound(t, q)
			if posts.Load() != 1 {
				t.Fatal("cleanup authorized another POST")
			}
		})
	}
}

func TestMaintainPreservesUnsubmittedPayload(t *testing.T) {
	for _, state := range []JobState{Queued, Submitting, SubmitUncertain} {
		t.Run(string(state), func(t *testing.T) {
			ctx := context.Background()
			s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
			j := enqueueBytes(t, s, "alpha", "keep these bytes").Job
			var err error
			if state != Queued {
				j, err = s.BeginSubmission(ctx, j.Tenant, j.ID, j.Version)
				if err != nil {
					t.Fatal(err)
				}
			}
			if state == SubmitUncertain {
				j, err = s.RecordSubmission(ctx, j.Tenant, j.ID, j.Version, Submission{UnknownDebt: true}, Transport, 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				if err := s.Maintain(ctx); err != nil {
					t.Fatal(err)
				}
				if got := schedulerLookup(t, s, j); !reflect.DeepEqual(got, j) {
					t.Fatal("maintenance changed unsubmitted state")
				}
				body, err := os.ReadFile(filepath.Join(s.cfg.Directory, "spool", j.ID+".blob"))
				if err != nil || string(body) != "keep these bytes" {
					t.Fatal("maintenance removed unsubmitted payload", err)
				}
			}
		})
	}
}

func TestRemovePayloadSyncsDirectoryOnlyAfterUnlink(t *testing.T) {
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	j := enqueueBytes(t, s, "alpha", "conditional-sync").Job
	syncs := 0
	s.hooks.syncSpool = func() error {
		syncs++
		return nil
	}
	if err := s.removePayload(j.ID); err != nil {
		t.Fatal(err)
	}
	if syncs != 1 {
		t.Fatalf("successful unlink directory syncs=%d want 1", syncs)
	}
	if err := s.removePayload(j.ID); err != nil {
		t.Fatal(err)
	}
	if syncs != 1 {
		t.Fatalf("absent payload triggered directory sync: calls=%d", syncs)
	}
}
