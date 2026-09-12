package cape

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

// BeginSubmission commits ownership of one attempt BEFORE the scheduler may
// send bytes. Even a crash before send conservatively recovers as uncertain.
// Only a nil error permits sending. A checkpoint error may follow durable state
// and version advancement; a nonzero returned Job does not authorize a send or
// blind retry. Use tenant-scoped Lookup and reconciliation, treating an ambiguous
// attempt as uncertain until reconciled.
func (s *Store) BeginSubmission(ctx context.Context, tenant, id string, version int64) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Job{}, &Error{Code: Closed}
	}
	var j Job
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var e error
		j, e = readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=? AND tenant=?", id, tenant))
		if e != nil {
			return e
		}
		if j.State != Queued || j.Version != version {
			return ErrConflict
		}
		if e = admissionGeneration(tx, j.Generation); e != nil {
			return e
		}
		now, e := s.now(tx)
		if e != nil {
			return e
		}
		if !now.Before(j.QueueDeadline) || !now.Before(j.AnalysisDeadline) {
			return &Error{Code: Deadline}
		}
		if now.Before(j.NextAttempt) {
			return &Error{Code: Throttled}
		}
		var all, own int
		for _, owner := range s.liveAttempts {
			all++
			if owner == tenant {
				own++
			}
		}
		if all >= s.cfg.SubmissionConcurrency || own >= s.cfg.TenantSubmissionConcurrency {
			return &Error{Code: Throttled}
		}
		for _, b := range []struct {
			name string
			rate int
		}{{"requests", s.cfg.RequestsPerMinute}, {"submits", s.cfg.SubmitPerMinute}, {bucketName("tenant", tenant), s.cfg.TenantSubmitPerMinute}} {
			if e = takeToken(tx, b.name, b.rate, now); e != nil {
				return e
			}
		}
		previous := j
		j.State = Submitting
		j.Version++
		j.SubmissionVersion = j.Version
		j.SubmissionRecorded = false
		j.Attempts++
		j.AttemptAt = now
		j.NextAttempt = time.Time{}
		return putJob(tx, j, previous)
	})
	if err == nil {
		s.liveAttempts[j.ID] = j.Tenant
		s.crash("submitting_committed")
		err = s.checkpoint(ctx)
	}
	return j, err
}

// TakeRequestToken is the separate persisted total request budget used by the
// poll/deletion scheduler. Submission already consumes this same budget.
func (s *Store) TakeRequestToken(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return &Error{Code: Closed}
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		now, e := s.now(tx)
		if e != nil {
			return e
		}
		return takeToken(tx, "requests", s.cfg.RequestsPerMinute, now)
	})
}

func takeToken(tx *sql.Tx, name string, rate int, now time.Time) error {
	tokens := float64(rate)
	stamp := now.UnixNano()
	err := tx.QueryRow("SELECT tokens,stamp FROM buckets WHERE name=?", name).Scan(&tokens, &stamp)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ErrStoreUnavailable
	}
	if tokens < 0 || math.IsNaN(tokens) || math.IsInf(tokens, 0) {
		return ErrStoreUnavailable
	}
	if err == nil {
		elapsed := now.Sub(time.Unix(0, stamp))
		if elapsed < 0 {
			return ErrClock
		}
		if elapsed > time.Minute {
			elapsed = time.Minute
		}
		tokens = math.Min(float64(rate), tokens+elapsed.Seconds()*float64(rate)/60)
	}
	if tokens < 1 {
		return &Error{Code: Throttled}
	}
	if _, err = tx.Exec("INSERT INTO buckets(name,tokens,stamp) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET tokens=excluded.tokens,stamp=excluded.stamp", name, tokens-1, now.UnixNano()); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

// RecordSubmission persists all bounded valid returned IDs, even on failure.
// outcome is a local Code (empty only on valid success), never remote text.
// Only the transport's positive NoBytesSent proof allows a queued retry.
// A payload cleanup or checkpoint error may follow durable state/version and
// task ID updates. Retain ownership of supplied and returned tasks, and use
// tenant-scoped Lookup and reconciliation rather than assuming rollback. A
// nonzero returned Job with an error never authorizes a send or blind retry.
func (s *Store) RecordSubmission(ctx context.Context, tenant, id string, version int64, submission Submission, outcome Code, backoff time.Duration) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Job{}, &Error{Code: Closed}
	}
	if !safeOutcome(outcome) || backoff < 0 {
		return Job{}, &Error{Code: Invalid}
	}
	var j Job
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var txErr error
		j, txErr = s.recordSubmissionTx(tx, tenant, id, version, submission, outcome, backoff)
		return txErr
	})
	if err != nil {
		return Job{}, err
	}
	delete(s.liveAttempts, j.ID)
	s.crash("submission_recorded")
	if j.State == RemotePending || terminal(j.State) {
		if err = s.removePayload(j.ID); err != nil {
			return j, err
		}
	}
	if err = s.checkpoint(ctx); err != nil {
		return j, err
	}
	return j, nil
}

func (s *Store) recordSubmissionTx(tx *sql.Tx, tenant, id string, version int64, submission Submission, outcome Code, backoff time.Duration) (Job, error) {
	j, err := readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=? AND tenant=?", id, tenant))
	if err != nil {
		return Job{}, err
	}
	if version < 1 || j.SubmissionRecorded || (j.State != Submitting && !terminal(j.State) && j.State != SubmitUncertain) ||
		(j.SubmissionVersion != version && !(j.SubmissionVersion == 0 && j.State == Submitting && j.Version == version)) {
		return Job{}, ErrConflict
	}
	previous := j
	j.Version++
	j.SubmissionRecorded = true
	j.Reason = outcome
	invalid := appendSubmissionTasks(&j, submission.Tasks)
	j.UnknownDebt = submission.UnknownDebt || invalid
	j.DedupBarrier = true
	if err = s.applySubmissionOutcome(tx, &j, previous, submission, outcome, invalid, backoff); err != nil {
		return Job{}, err
	}
	return j, putJob(tx, j, previous)
}

func appendSubmissionTasks(j *Job, tasks []TaskRef) bool {
	invalid := len(tasks) > MaxTaskIDs
	seen := make(map[int64]bool)
	for i, task := range tasks {
		if i >= MaxTaskIDs {
			break
		}
		if task.ID < 1 || task.ID > maxTaskID || task.Generation != j.Generation || seen[task.ID] {
			invalid = true
			continue
		}
		seen[task.ID] = true
		j.TaskIDs = append(j.TaskIDs, task.ID)
	}
	return invalid
}

func (s *Store) applySubmissionOutcome(tx *sql.Tx, j *Job, previous Job, submission Submission, outcome Code, invalid bool, backoff time.Duration) error {
	switch {
	case terminal(previous.State):
		applyTerminalSubmission(j, previous, submission, outcome, invalid)
	case len(submission.Tasks) > 1:
		j.State, j.UnknownDebt, j.Reason, j.Cleanup = Failed, true, Protocol, "remote_delete_failed/unknown"
		j.TerminalAt = s.hooks.clock.Now().UTC()
		if j.TerminalAt.Before(j.AttemptAt) {
			j.TerminalAt = j.AttemptAt
		}
	case outcome == "" && !invalid && !submission.UnknownDebt && !submission.NoBytesSent && len(j.TaskIDs) == 1:
		j.State, j.Cleanup = RemotePending, "remote_delete_pending"
	case outcome != "" && submission.NoBytesSent && !invalid && !submission.UnknownDebt && len(submission.Tasks) == 0:
		now, err := s.now(tx)
		if err != nil {
			return err
		}
		backoff = max(5*time.Second, min(backoff, 5*time.Minute))
		j.State, j.Cleanup, j.DedupBarrier, j.NextAttempt = Queued, "not_submitted", false, now.Add(backoff)
	default:
		j.State, j.UnknownDebt, j.Cleanup = SubmitUncertain, true, "remote_delete_failed/unknown"
		if j.Reason == "" {
			j.Reason = Protocol
		}
	}
	return nil
}

func applyTerminalSubmission(j *Job, previous Job, submission Submission, outcome Code, invalid bool) {
	j.Reason = previous.Reason
	noSend := submission.NoBytesSent && len(submission.Tasks) == 0 && !invalid
	j.UnknownDebt = j.UnknownDebt || !noSend && (outcome != "" || len(j.TaskIDs) != 1)
	if noSend && !submission.UnknownDebt {
		j.UnknownDebt, j.DedupBarrier, j.Cleanup = false, false, "not_submitted"
		return
	}
	j.Cleanup = "remote_delete_pending"
	if j.UnknownDebt {
		j.Cleanup = "remote_delete_failed/unknown"
	}
}

func safeOutcome(code Code) bool {
	switch code {
	case "", Invalid, Closed, Credential, Unauthorized, Throttled, Transport, Deadline, Protocol, TooLarge, Remote, NotFound:
		return true
	}
	return false
}

func validJobID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 16 && strings.ToLower(id) == id
}

// Startup holds the OS owner lock throughout reconciliation. Staging is never
// promoted; removed files are directory-synced before reservations are released.
func (s *Store) recover(ctx context.Context) error {
	jobs, err := s.loadRecoveryJobs(ctx)
	if err != nil {
		return err
	}
	if err = s.reconcileRecoveryJobs(ctx, jobs); err != nil {
		return err
	}
	seen, err := s.reconcileRecoverySpool(jobs)
	if err != nil {
		return err
	}
	for id, j := range jobs {
		if (j.State == Queued || j.State == SubmitUncertain) && !seen[id] {
			return ErrStoreUnavailable
		}
	}
	return nil
}

func (s *Store) loadRecoveryJobs(ctx context.Context) (map[string]Job, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT document FROM jobs")
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	jobs := make(map[string]Job)
	for rows.Next() {
		var raw []byte
		var j Job
		if rows.Scan(&raw) != nil || len(raw) > JobMetadataLimit+JobResultLimit || json.Unmarshal(raw, &j) != nil || !validJobID(j.ID) || len(jobs) >= 10000 {
			_ = rows.Close() // scan/validation failure is already the reported store error
			return nil, ErrStoreUnavailable
		}
		jobs[j.ID] = j
	}
	err = rows.Err()
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	return jobs, nil
}

func (s *Store) reconcileRecoveryJobs(ctx context.Context, jobs map[string]Job) error {
	for id, j := range jobs {
		if j.State == Staging {
			if err := s.cleanupStaging(id); err != nil {
				return err
			}
			delete(jobs, id)
			continue
		}
		if j.State == Submitting {
			err := s.transaction(ctx, func(tx *sql.Tx) error {
				previousJob := j
				j.State = SubmitUncertain
				j.Version++
				j.UnknownDebt = true
				j.DedupBarrier = true
				j.Cleanup = "remote_delete_failed/unknown"
				j.Reason = Transport
				return putJob(tx, j, previousJob)
			})
			if err != nil {
				return err
			}
			jobs[id] = j
		}
		if j.State == RemotePending || j.State == Fetching || j.State == Completed || j.State == Cancelled || j.State == Failed || j.State == Expired {
			if _, err := removeStoreFile(s.spool, id+".blob"); err != nil {
				return ErrStoreUnavailable
			}
		}
	}
	return nil
}

func (s *Store) reconcileRecoverySpool(jobs map[string]Job) (map[string]bool, error) {
	// Directory reads are bounded independently of database occupancy.
	if _, err := s.spool.Seek(0, io.SeekStart); err != nil {
		return nil, ErrStoreUnavailable
	}
	seen := make(map[string]bool)
	count := 0
	for {
		entries, readErr := s.spool.ReadDir(128)
		for _, entry := range entries {
			count++
			name := entry.Name()
			id, ext, ok := strings.Cut(name, ".")
			if count > 20000 || !ok || !validJobID(id) || (ext != "tmp" && ext != "blob") || !entry.Type().IsRegular() {
				return nil, ErrStoreUnavailable
			}
			f, openErr := openStoreFile(s.spool, name, os.O_RDONLY)
			if openErr != nil {
				return nil, ErrStoreUnavailable
			}
			info, statErr := f.Stat()
			_ = f.Close()
			if statErr != nil {
				return nil, ErrStoreUnavailable
			}
			j, exists := jobs[id]
			if exists && ext == "blob" && (j.State == Queued || j.State == SubmitUncertain) {
				if info.Size() != j.PayloadBytes || j.PayloadBytes < 1 || j.PayloadBytes > MaxAttachment {
					return nil, ErrStoreUnavailable
				}
				seen[id] = true
			} else if _, err := removeStoreFile(s.spool, name); err != nil {
				return nil, ErrStoreUnavailable
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, ErrStoreUnavailable
		}
	}
	if s.spool.Sync() != nil {
		return nil, ErrStoreUnavailable
	}
	return seen, nil
}
