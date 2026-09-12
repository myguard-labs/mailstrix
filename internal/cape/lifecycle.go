package cape

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"
)

const maintenanceBatchSize = 256

const (
	deadlineStates        = "'staging','queued','submitting','submit_uncertain','remote_pending','fetching'"
	cleanupStates         = "'remote_pending','fetching','completed','failed','expired','cancelled'"
	cleanupDeadlineStates = "'completed','cancelled','expired','failed'"
)

func scanJobBatch(rows *sql.Rows, limit int) ([]Job, error) {
	defer rows.Close()
	jobs := make([]Job, 0, limit)
	for rows.Next() {
		var raw []byte
		var j Job
		if rows.Scan(&raw) != nil || len(raw) > JobMetadataLimit+JobResultLimit || json.Unmarshal(raw, &j) != nil || len(jobs) >= limit {
			return nil, ErrStoreUnavailable
		}
		jobs = append(jobs, j)
	}
	if rows.Err() != nil {
		return nil, ErrStoreUnavailable
	}
	return jobs, nil
}

// nextMaintenanceBatch selects only lifecycle states owned by the requested
// phase. The state/id index bounds JSON decoding and the cursor prevents an
// unchanged retained tombstone from starving later jobs.
func nextMaintenanceBatch(tx *sql.Tx, states, cursor string) ([]Job, string, error) {
	var query string
	switch states {
	case deadlineStates:
		query = "SELECT document FROM jobs WHERE state IN ('staging','queued','submitting','submit_uncertain','remote_pending','fetching') AND id>? ORDER BY id LIMIT ?"
	case cleanupStates:
		query = "SELECT document FROM jobs WHERE state IN ('remote_pending','fetching','completed','failed','expired','cancelled') AND id>? ORDER BY id LIMIT ?"
	case cleanupDeadlineStates:
		query = "SELECT document FROM jobs WHERE state IN ('completed','cancelled','expired','failed') AND id>? ORDER BY id LIMIT ?"
	default:
		return nil, cursor, ErrStoreUnavailable
	}
	rows, err := tx.Query(query, cursor, maintenanceBatchSize)
	if err != nil {
		return nil, cursor, ErrStoreUnavailable
	}
	jobs, err := scanJobBatch(rows, maintenanceBatchSize)
	if err != nil {
		return nil, cursor, err
	}
	if len(jobs) == 0 && cursor != "" {
		rows, err = tx.Query(query, "", maintenanceBatchSize)
		if err != nil {
			return nil, cursor, ErrStoreUnavailable
		}
		jobs, err = scanJobBatch(rows, maintenanceBatchSize)
		if err != nil {
			return nil, cursor, err
		}
	}
	if len(jobs) == 0 {
		return nil, "", nil
	}
	return jobs, jobs[len(jobs)-1].ID, nil
}

func terminal(state JobState) bool {
	return state == Completed || state == Failed || state == Expired || state == Cancelled
}

func terminate(j *Job, state JobState, reason Code, now time.Time) {
	if j.TerminalAt.IsZero() {
		j.TerminalAt = now
	}
	if j.State == Submitting || j.State == SubmitUncertain {
		j.UnknownDebt = true
		j.DedupBarrier = true
		j.Cleanup = "remote_delete_failed/unknown"
	}
	j.State, j.Reason, j.Result = state, reason, nil
	if state == Cancelled {
		j.Suppressed = true
	}
}

// Cancel suppresses result reuse immediately and preserves the first terminal
// timestamp. Staging cancellation signals its writer; that writer alone removes
// its reservation after stopping. In-flight submissions retain their attempt
// version so RecordSubmission can harvest late task IDs without resurrection.
// As with RecordSubmission, an error after commit does not imply rollback.
func (s *Store) Cancel(ctx context.Context, tenant, id string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Job{}, &Error{Code: Closed}
	}
	var j Job
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		j, err = readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=? AND tenant=?", id, tenant))
		if err != nil {
			return err
		}
		if j.State == Staging {
			if cancel := s.active[id]; cancel != nil {
				cancel()
			}
			return nil
		}
		if j.State == Cancelled {
			return nil
		}
		now, err := s.now(tx)
		if err != nil {
			if err != ErrClock {
				return err
			}
			// Restrictive cancellation is safe while admission stays paused. Use
			// the persisted high-water timestamp rather than moving terminal age
			// backwards or changing the clock record to permit new admission.
			var stamp int64
			if tx.QueryRow("SELECT latest FROM clock WHERE id=1").Scan(&stamp) != nil {
				return ErrStoreUnavailable
			}
			now = time.Unix(0, stamp).UTC()
		}
		previousJob := j
		terminate(&j, Cancelled, "", now)
		j.Version++
		return putJob(tx, j, previousJob)
	})
	if err != nil {
		return Job{}, err
	}
	if j.State != Staging {
		err = s.removePayload(j.ID)
	}
	if err == nil {
		err = s.checkpoint(ctx)
	}
	return j, err
}

func (s *Store) removePayload(id string) error {
	removed, err := removeStoreFile(s.spool, id+".blob")
	if err != nil || removed && s.spool.Sync() != nil {
		return ErrStoreUnavailable
	}
	return nil
}

// RecordDeletion records one native deletion response for a previously owned
// task. It never confirms purge or clears a dedup barrier. Callers retry a stale
// version using Lookup; cancellation may race the request without losing its ID.
// An empty outcome requires the client's exact acknowledged-unverified state.
func (s *Store) RecordDeletion(ctx context.Context, tenant, id string, version int64, task TaskRef, state DeleteState, outcome Code) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Job{}, &Error{Code: Closed}
	}
	if !safeOutcome(outcome) || (outcome == "" && state != DeleteAcknowledgedUnverified) || (outcome != "" && state != "") {
		return Job{}, &Error{Code: Invalid}
	}
	var j Job
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		j, err = readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=? AND tenant=?", id, tenant))
		if err != nil {
			return err
		}
		if j.Version != version || task.Generation != j.Generation || !terminal(j.State) {
			return ErrConflict
		}
		owned := false
		for _, v := range j.TaskIDs {
			if v == task.ID {
				owned = true
			}
		}
		if !owned {
			return ErrConflict
		}
		previousJob := j
		if outcome == "" {
			found := false
			for _, v := range j.DeleteAcknowledgedIDs {
				if v == task.ID {
					found = true
				}
			}
			if !found {
				j.DeleteAcknowledgedIDs = append(j.DeleteAcknowledgedIDs, task.ID)
			}
			j.Cleanup = "remote_delete_pending"
			if len(j.DeleteAcknowledgedIDs) == len(j.TaskIDs) && !j.UnknownDebt {
				j.Cleanup = string(DeleteAcknowledgedUnverified)
			}
		} else {
			j.Cleanup = "remote_delete_failed/unknown"
		}
		if j.UnknownDebt {
			j.Cleanup = "remote_delete_failed/unknown"
		}
		j.DedupBarrier = true
		j.Version++
		return putJob(tx, j, previousJob)
	})
	if err == nil {
		err = s.checkpoint(ctx)
	}
	return j, err
}

// Maintain retries submitted payload cleanup and applies absolute deadlines and
// terminal retention without network traffic. Call regularly even during endpoint
// outages. Unknown or unverified remote debt retains the record and dedup barrier
// until explicit reconciliation.
// Removal is synced before the reservation is released; failed removal is retryable.
func (s *Store) Maintain(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return &Error{Code: Closed}
	}
	var now time.Time
	var deadlineCursor string
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		now, err = s.now(tx)
		if err != nil {
			return err
		}
		var jobs []Job
		jobs, deadlineCursor, err = nextMaintenanceBatch(tx, deadlineStates, s.maintenanceDeadlineCursor)
		if err != nil {
			return err
		}
		for _, j := range jobs {
			previousJob := j
			if j.State == Staging {
				if !now.Before(j.IngressDeadline) {
					if cancel := s.active[j.ID]; cancel != nil {
						cancel()
					}
				}
				continue
			}
			if !terminal(j.State) && (!now.Before(j.AnalysisDeadline) || j.State == Queued && !now.Before(j.QueueDeadline)) {
				terminate(&j, Expired, Deadline, now)
				j.Version++
				if err := putJob(tx, j, previousJob); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.maintenanceDeadlineCursor = deadlineCursor
	// Terminal publication precedes unlink: rollback must never leave a queued
	// or uncertain row referring to a payload that cleanup already removed.
	var cleanupCursor string
	err = s.transaction(ctx, func(tx *sql.Tx) error {
		jobs, cursor, err := nextMaintenanceBatch(tx, cleanupStates, s.maintenanceCleanupCursor)
		if err != nil {
			return err
		}
		cleanupCursor = cursor
		for _, j := range jobs {
			if !terminal(j.State) {
				// Submission publication precedes unlink too. A failed unlink after
				// commit must be retried while remote analysis is still pending.
				// These states never need local bytes for another submission.
				if j.State == RemotePending || j.State == Fetching {
					if err := s.removePayload(j.ID); err != nil {
						return err
					}
				}
				continue
			}
			previousJob := j
			if err := s.removePayload(j.ID); err != nil {
				return err
			}
			if !j.TerminalAt.IsZero() && !now.Before(j.TerminalAt.Add(24*time.Hour)) {
				if !j.UnknownDebt && (j.Cleanup == "not_submitted" || j.Cleanup == "remote_purge_confirmed") {
					if _, err := tx.Exec("DELETE FROM jobs WHERE id=? AND tenant=? AND version=?", j.ID, j.Tenant, previousJob.Version); err != nil {
						return ErrStoreUnavailable
					}
					continue
				}
				j.Result = nil
				j.Suppressed = true
				j.DedupBarrier = true
				// Keep dedup policy identities: they are part of the barrier key.
				j.StaticVerdict = ""
			}
			if reflect.DeepEqual(j, previousJob) {
				continue
			}
			j.Version++
			if err := putJob(tx, j, previousJob); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		s.maintenanceCleanupCursor = cleanupCursor
		err = s.checkpoint(ctx)
	}
	return err
}
