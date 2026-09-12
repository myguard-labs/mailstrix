package cape

import (
	"context"
	"database/sql"
	"time"
)

func admissionGeneration(tx *sql.Tx, generation string) error {
	var n int
	if tx.QueryRow("SELECT COUNT(*) FROM cape_admission_pause WHERE generation=?", generation).Scan(&n) != nil {
		return ErrStoreUnavailable
	}
	if n != 0 {
		return &Error{Code: Unauthorized}
	}
	return nil
}

// SetGenerationAdmission is an explicit administrator recovery/configuration
// operation. enabled=true follows credential repair, never a successful poll.
// The durable pause affects detonation only; there is no static scan integration.
func (s *Store) SetGenerationAdmission(ctx context.Context, generation string, enabled bool) error {
	if !identifier(generation, 128) {
		return &Error{Code: Invalid}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return &Error{Code: Closed}
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		if enabled {
			_, err = tx.Exec("DELETE FROM cape_admission_pause WHERE generation=?", generation)
		} else {
			_, err = tx.Exec("INSERT OR IGNORE INTO cape_admission_pause(generation) VALUES(?)", generation)
		}
		if err != nil {
			return ErrStoreUnavailable
		}
		return nil
	})
}

func (s *Store) schedulerJobs(ctx context.Context) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, &Error{Code: Closed}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT document FROM jobs
		WHERE state IN ('queued','remote_pending','fetching','completed','failed','expired','cancelled') AND id>?
		ORDER BY id LIMIT ?`, s.schedulerCursor, maintenanceBatchSize)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	jobs, err := scanJobBatch(rows, maintenanceBatchSize)
	if err != nil {
		return nil, err
	}
	if len(jobs) == 0 && s.schedulerCursor != "" {
		rows, err = s.db.QueryContext(ctx, `SELECT document FROM jobs
			WHERE state IN ('queued','remote_pending','fetching','completed','failed','expired','cancelled') AND id>?
			ORDER BY id LIMIT ?`, "", maintenanceBatchSize)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		jobs, err = scanJobBatch(rows, maintenanceBatchSize)
		if err != nil {
			return nil, err
		}
	}
	s.schedulerCursor = ""
	if len(jobs) != 0 {
		s.schedulerCursor = jobs[len(jobs)-1].ID
	}
	return jobs, nil
}

// Reserve one safe read/delete BEFORE dispatch. Persisted next-attempt survives
// restart and callbacks; a crash can waste a token but cannot refund one.
func (s *Store) reserveRead(ctx context.Context, snapshot Job, delay time.Duration) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Job{}, &Error{Code: Closed}
	}
	var j Job
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		j, err = readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=? AND tenant=?", snapshot.ID, snapshot.Tenant))
		if err != nil {
			return err
		}
		if j.Version != snapshot.Version || j.State != snapshot.State {
			return ErrConflict
		}
		now, err := s.now(tx)
		if err != nil {
			return err
		}
		if now.Before(j.NextAttempt) {
			return &Error{Code: Throttled}
		}
		if terminal(j.State) {
			if j.AttemptAt.IsZero() || !now.Before(j.AttemptAt.Add(48*time.Hour)) {
				return &Error{Code: Deadline}
			}
		} else if (j.State != RemotePending && j.State != Fetching) || !now.Before(j.AnalysisDeadline) || j.Suppressed {
			return ErrConflict
		}
		if err = takeToken(tx, "requests", s.cfg.RequestsPerMinute, now); err != nil {
			return err
		}
		previousJob := j
		j.NextAttempt = now.Add(delay)
		if j.ReadAttempts < 16 {
			j.ReadAttempts++
		}
		j.PollWakeAt = time.Time{}
		j.Version++
		return putJob(tx, j, previousJob)
	})
	return j, err
}

// ExtendRetry never moves a durable retry time earlier or extends a deadline.
func (s *Store) extendRetry(ctx context.Context, snapshot Job, delay time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return &Error{Code: Closed}
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		j, err := readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=? AND tenant=?", snapshot.ID, snapshot.Tenant))
		if err != nil {
			return err
		}
		now, err := s.now(tx)
		if err != nil {
			return err
		}
		next := now.Add(delay)
		if !next.After(j.NextAttempt) {
			return nil
		}
		previousJob := j
		j.NextAttempt = next
		j.Version++
		return putJob(tx, j, previousJob)
	})
}

func (s *Store) markCleanupDeadlines(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return &Error{Code: Closed}
	}
	var nextCursor string
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		now, err := s.now(tx)
		if err != nil {
			return err
		}
		jobs, cursor, err := nextMaintenanceBatch(tx, cleanupDeadlineStates, s.cleanupDeadlineCursor)
		if err != nil {
			return err
		}
		nextCursor = cursor
		var due []Job
		for _, j := range jobs {
			if !j.CleanupDeadlineExceeded && !j.AttemptAt.IsZero() && !now.Before(j.AttemptAt.Add(48*time.Hour)) && j.DedupBarrier {
				due = append(due, j)
			}
		}
		for _, j := range due {
			previousJob := j
			j.CleanupDeadlineExceeded = true
			j.Version++
			if err = putJob(tx, j, previousJob); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		s.cleanupDeadlineCursor = nextCursor
	}
	return err
}
