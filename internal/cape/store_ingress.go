package cape

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Enqueue takes ownership of body, including rejection paths. Its Close must be
// safe concurrently with Read and unblock Read (as net/http request bodies do).
// An uncooperative reader retains its reservation until it actually stops; the
// store never releases capacity underneath a live writer.
func (s *Store) Enqueue(ctx context.Context, request EnqueueRequest, body io.ReadCloser) (Admission, error) {
	return s.enqueue(ctx, request, body, nil)
}

// IngressClassifier is trusted, concurrency-safe local scanning/policy code.
// The reader exposes exactly the immutable staged attachment, is valid only
// during this call and must not be retained. Honor context cancellation; quota
// remains reserved until the call returns even for an uncooperative classifier.
// Errors must be local sanitized errors, never report or sample content.
type IngressClassifier func(context.Context, io.Reader) (string, error)

// EnqueueClassified reserves and streams before invoking classify. Classification
// shares the original ingress deadline and must succeed before queued is visible.
// The caller's static snapshot is ignored; no untrusted snapshot is accepted.
func (s *Store) EnqueueClassified(ctx context.Context, request EnqueueRequest, body io.ReadCloser, classify IngressClassifier) (Admission, error) {
	if classify == nil {
		if body != nil {
			_ = body.Close()
		}
		return Admission{}, &Error{Code: Invalid}
	}
	request.StaticVerdict = "unknown"
	return s.enqueue(ctx, request, body, classify)
}

func (s *Store) enqueue(ctx context.Context, request EnqueueRequest, body io.ReadCloser, classify IngressClassifier) (Admission, error) {
	if body == nil {
		return Admission{}, &Error{Code: Invalid}
	}
	var once sync.Once
	closeBody := func() { once.Do(func() { _ = body.Close() }) }
	defer closeBody()
	if !identifier(request.Tenant, 128) || !identifier(request.Generation, 128) || !identifier(request.SubmissionPolicy, 128) || !identifier(request.ResultPolicy, 128) ||
		(request.StaticVerdict != "clean" && request.StaticVerdict != "unknown" && request.StaticVerdict != "suspicious" && request.StaticVerdict != "malicious") {
		return Admission{}, &Error{Code: Invalid}
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Admission{}, &Error{Code: Closed}
	}
	if !s.tenants[request.Tenant] {
		s.mu.Unlock()
		return Admission{}, &Error{Code: Unauthorized}
	}
	j, err := s.reserve(ctx, request)
	if err != nil {
		s.mu.Unlock()
		return Admission{}, err
	}
	live, cancel := context.WithCancel(ctx)
	s.active[j.ID] = cancel
	s.writers.Add(1)
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); delete(s.active, j.ID); s.mu.Unlock(); s.writers.Done() }()
	s.crash("staging_committed")
	size, digest, err := s.writeIngress(live, j, body, closeBody)
	// writeIngress joins its deadline watcher before any cleanup or publication.
	closeBody()
	currentStatic := request.StaticVerdict
	if err == nil && classify != nil {
		currentStatic, err = s.classifyIngress(live, j, size, classify)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if e := s.cleanupStaging(j.ID); e != nil {
			return Admission{}, e
		}
		return Admission{}, err
	}
	if s.closed || live.Err() != nil {
		if e := s.cleanupStaging(j.ID); e != nil {
			return Admission{}, e
		}
		return Admission{}, &Error{Code: Deadline}
	}
	var result Admission
	err = s.transaction(live, func(tx *sql.Tx) error {
		now, e := s.now(tx)
		if e != nil {
			return e
		}
		if !now.Before(j.IngressDeadline) {
			return &Error{Code: Deadline}
		}
		rows, e := tx.Query("SELECT document FROM jobs WHERE tenant=? AND digest=? AND generation=? AND submission_policy=? AND result_policy=?", j.Tenant, digest, j.Generation, j.SubmissionPolicy, j.ResultPolicy)
		if e != nil {
			return ErrStoreUnavailable
		}
		for rows.Next() {
			var raw []byte
			var existingJob Job
			if rows.Scan(&raw) != nil || len(raw) > JobMetadataLimit+JobResultLimit || json.Unmarshal(raw, &existingJob) != nil {
				_ = rows.Close() // scan/validation failure is already the reported store error
				return ErrStoreUnavailable
			}
			if reusable(existingJob, now) {
				result = Admission{Job: existingJob, Reused: true}
				break
			}
		}
		e = rows.Err()
		if closeErr := rows.Close(); e == nil {
			e = closeErr
		}
		if e != nil {
			return ErrStoreUnavailable
		}
		if result.Reused {
			return nil
		}
		previous := j
		j.StaticVerdict = currentStatic
		j.State = Queued
		j.Version++
		j.PayloadBytes = size
		j.ReservedBytes = size + JobMetadataLimit + JobResultLimit
		j.Digest = digest
		if e = putJob(tx, j, previous); e != nil {
			return e
		}
		s.crash("queued_before_commit")
		result = Admission{Job: j}
		return nil
	})
	if err != nil {
		if e := s.cleanupStaging(j.ID); e != nil {
			return Admission{}, e
		}
		return Admission{}, err
	}
	s.crash("queued_committed")
	if result.Reused {
		if err = s.cleanupStaging(j.ID); err != nil {
			return Admission{}, err
		}
	}
	if err = s.checkpoint(context.Background()); err != nil {
		return Admission{}, err
	}
	result.CurrentStatic = currentStatic
	return result, nil
}

func (s *Store) classifyIngress(ctx context.Context, j Job, size int64, classify IngressClassifier) (string, error) {
	if ctx.Err() != nil || !s.hooks.clock.Now().Before(j.IngressDeadline) {
		return "", &Error{Code: Deadline}
	}
	f, err := openStoreFile(s.spool, j.ID+".blob", os.O_RDONLY)
	if err != nil {
		return "", ErrStoreUnavailable
	}
	defer f.Close()
	live, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := s.hooks.clock.NewTimer(j.IngressDeadline.Sub(s.hooks.clock.Now()))
	defer timer.Stop()
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-timer.C():
			cancel()
		case <-live.Done():
		case <-stop:
		}
	}()
	static, err := classify(live, io.LimitReader(f, size))
	close(stop)
	<-stopped
	if live.Err() != nil || !s.hooks.clock.Now().Before(j.IngressDeadline) {
		return "", &Error{Code: Deadline}
	}
	if err != nil {
		return "", err
	}
	if static != "clean" && static != "unknown" && static != "suspicious" && static != "malicious" {
		return "", &Error{Code: Invalid}
	}
	return static, nil
}

func reusable(j Job, now time.Time) bool {
	if j.DedupBarrier {
		return true
	}
	switch j.State {
	case Queued, Submitting, SubmitUncertain, RemotePending, Fetching:
		return true
	case Completed:
		return !j.Suppressed && !j.TerminalAt.IsZero() && now.Before(j.TerminalAt.Add(24*time.Hour))
	}
	return false
}

func (s *Store) reserve(ctx context.Context, r EnqueueRequest) (Job, error) {
	id, err := opaqueID()
	if err != nil {
		return Job{}, err
	}
	marker, err := opaqueID()
	if err != nil {
		return Job{}, err
	}
	j := Job{ID: id, Tenant: r.Tenant, Generation: r.Generation, SubmissionPolicy: r.SubmissionPolicy, ResultPolicy: r.ResultPolicy, StaticVerdict: r.StaticVerdict, Correlation: marker, State: Staging, Version: 1, Cleanup: "not_submitted", ReservedBytes: s.cfg.MaxAttachment + JobMetadataLimit + JobResultLimit}
	err = s.transaction(ctx, func(tx *sql.Tx) error {
		now, e := s.now(tx)
		if e != nil {
			return e
		}
		if e = admissionGeneration(tx, r.Generation); e != nil {
			return e
		}
		capacityInfo, e := s.hooks.capacity(s.dir, s.cfg.Directory)
		if e != nil || !validCapacity(capacityInfo) {
			return ErrStoreUnavailable
		}
		var count, tenantCount, staging int64
		var used, tenantUsed, pending int64
		if tx.QueryRow("SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM jobs").Scan(&count, &used) != nil ||
			tx.QueryRow("SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM jobs WHERE tenant=?", r.Tenant).Scan(&tenantCount, &tenantUsed) != nil ||
			tx.QueryRow("SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM jobs WHERE state=?", Staging).Scan(&staging, &pending) != nil {
			return ErrStoreUnavailable
		}
		if used < 0 || tenantUsed < 0 || pending < 0 || pending > PhysicalLimit || staging < 0 || staging > 10000 {
			return ErrStoreUnavailable
		}
		if count >= int64(s.cfg.MaxJobs) || tenantCount >= int64(s.cfg.TenantJobs) || used > s.cfg.MaxBytes-j.ReservedBytes || tenantUsed > s.cfg.TenantBytes-j.ReservedBytes {
			return ErrQuota
		}
		if e = checkTenantDebt(tx, r.Tenant, now); e != nil {
			return e
		}
		// Logical staging reservations already include metadata/results. Add block
		// rounding for each live file and worst-case DB + WAL + checkpoint growth.
		needed := StateReserve + 3*databaseLimit + pending + j.ReservedBytes + (staging+1)*capacityInfo.block
		if capacityInfo.available < needed {
			return ErrQuota
		}
		j.CreatedAt = now
		j.IngressDeadline = now.Add(ingressLimit)
		j.QueueDeadline = now.Add(time.Hour)
		j.AnalysisDeadline = now.Add(24 * time.Hour)
		raw, e := encodeJob(j)
		if e != nil {
			return e
		}
		_, e = tx.Exec("INSERT INTO jobs(id,tenant,state,version,reserved,digest,generation,submission_policy,result_policy,document) VALUES(?,?,?,?,?,?,?,?,?,?)", j.ID, j.Tenant, j.State, j.Version, j.ReservedBytes, j.Digest, j.Generation, j.SubmissionPolicy, j.ResultPolicy, raw)
		if e != nil {
			return ErrStoreUnavailable
		}
		return nil
	})
	return j, err
}

func checkTenantDebt(tx *sql.Tx, tenant string, now time.Time) error {
	rows, err := tx.Query("SELECT document FROM jobs WHERE tenant=?", tenant)
	if err != nil {
		return ErrStoreUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var j Job
		if rows.Scan(&raw) != nil || len(raw) > JobMetadataLimit+JobResultLimit || json.Unmarshal(raw, &j) != nil {
			return ErrStoreUnavailable
		}
		if j.Cleanup == "not_submitted" || j.Cleanup == "remote_purge_confirmed" {
			continue
		}
		since := j.AttemptAt
		if since.IsZero() {
			since = j.CreatedAt
		}
		if !now.Before(since.Add(7 * 24 * time.Hour)) {
			return ErrQuota
		}
	}
	if rows.Err() != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) writeIngress(ctx context.Context, j Job, body io.Reader, closeBody func()) (int64, string, error) {
	f, err := openStoreFile(s.spool, j.ID+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return 0, "", ErrStoreUnavailable
	}
	defer f.Close()
	absolute := s.hooks.clock.NewTimer(j.IngressDeadline.Sub(s.hooks.clock.Now()))
	defer absolute.Stop()
	progress := make(chan struct{}, 1)
	stop := make(chan struct{})
	stopped := make(chan struct{})
	var idleMu sync.Mutex
	idleDeadline := s.hooks.clock.Now().Add(ingressIdle)
	idleRemaining := func() time.Duration {
		idleMu.Lock()
		defer idleMu.Unlock()
		return idleDeadline.Sub(s.hooks.clock.Now())
	}
	var timedOut bool
	go func() {
		defer close(stopped)
		for {
			remaining := idleRemaining()
			if remaining <= 0 {
				timedOut = true
				closeBody()
				return
			}
			idle := s.hooks.clock.NewTimer(remaining)
			select {
			case <-stop:
				idle.Stop()
				return
			case <-ctx.Done():
				timedOut = true
			case <-absolute.C():
				timedOut = true
			case <-idle.C():
			case <-progress:
			}
			idle.Stop()
			if timedOut {
				closeBody()
				return
			}
		}
	}()
	hash := sha256.New()
	buf := make([]byte, 32<<10)
	var size int64
	for {
		n, e := body.Read(buf)
		idleMu.Lock()
		now := s.hooks.clock.Now()
		idleExpired := !now.Before(idleDeadline)
		if !idleExpired && n > 0 && n <= len(buf) {
			idleDeadline = now.Add(ingressIdle)
		}
		idleMu.Unlock()
		if idleExpired {
			err = &Error{Code: Deadline}
			break
		}
		if n < 0 || n > len(buf) {
			err = &Error{Code: Invalid}
			break
		}
		if n > 0 {
			select {
			case progress <- struct{}{}:
			default:
			}
			if int64(n) > s.cfg.MaxAttachment-size {
				err = &Error{Code: TooLarge}
				break
			}
			if _, err = f.Write(buf[:n]); err != nil {
				err = ErrStoreUnavailable
				break
			}
			_, _ = hash.Write(buf[:n])
			size += int64(n)
		}
		if e != nil {
			if e != io.EOF {
				err = &Error{Code: Invalid}
			}
			break
		}
		if ctx.Err() != nil || !s.hooks.clock.Now().Before(j.IngressDeadline) {
			err = &Error{Code: Deadline}
			break
		}
	}
	close(stop)
	<-stopped
	if timedOut || ctx.Err() != nil || idleRemaining() <= 0 || !s.hooks.clock.Now().Before(j.IngressDeadline) {
		return 0, "", &Error{Code: Deadline}
	}
	if err != nil {
		return 0, "", err
	}
	if size == 0 {
		return 0, "", &Error{Code: Invalid}
	}
	if f.Sync() != nil {
		return 0, "", ErrStoreUnavailable
	}
	s.crash("file_synced")
	if f.Close() != nil {
		return 0, "", ErrStoreUnavailable
	}
	if renameStoreFile(s.spool, j.ID+".tmp", j.ID+".blob") != nil || s.spool.Sync() != nil {
		return 0, "", ErrStoreUnavailable
	}
	s.crash("rename_synced")
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}

// Called only after the ingress writer has stopped (or under exclusive startup
// ownership). Never erase a queued row after an ambiguous SQL commit outcome.
func (s *Store) cleanupStaging(id string) error {
	return s.transaction(context.Background(), func(tx *sql.Tx) error {
		j, e := readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=?", id))
		if e != nil {
			return e
		}
		if j.State != Staging {
			return ErrStoreUnavailable
		}
		for _, suffix := range []string{".tmp", ".blob"} {
			if _, err := removeStoreFile(s.spool, id+suffix); err != nil {
				return ErrStoreUnavailable
			}
		}
		if s.spool.Sync() != nil {
			return ErrStoreUnavailable
		}
		s.crash("staging_removed")
		r, e := tx.Exec("DELETE FROM jobs WHERE id=? AND state=? AND version=?", id, Staging, j.Version)
		if e != nil {
			return ErrStoreUnavailable
		}
		n, e := r.RowsAffected()
		if e != nil || n != 1 {
			return ErrConflict
		}
		return nil
	})
}
