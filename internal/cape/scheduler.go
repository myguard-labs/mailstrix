package cape

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"sort"
	"sync"
	"time"
)

// Scheduler owns network work for one store. Clients are fixed by generation,
// including old generations retained for cleanup. It neither mounts an API nor
// activates storage. Stop Run before closing the store or its clients.
type Scheduler struct {
	store         *Store
	clients       map[string]*Client
	mapper        ResultMapper
	workers       int
	mu            sync.Mutex
	running       bool
	pending       []schedulerResult
	lastTenant    [2]string
	interval      time.Duration
	drainTimeout  time.Duration
	beforeJoin    func()                // package-private phase barrier for deterministic shutdown fixtures
	beforePersist func(context.Context) // package-private persistence-pass fixture observation
}

// MaxSchedulerWorkers bounds aggregate report fetch and parse memory. Each
// worker can retain a MaxReport-sized response until its result is persisted.
const MaxSchedulerWorkers = 8

// NewScheduler validates and constructs a scheduler for the configured clients.
func NewScheduler(store *Store, clients map[string]*Client, mapper ResultMapper, workers int) (*Scheduler, error) {
	if store == nil || workers < 1 || workers > MaxSchedulerWorkers || len(clients) == 0 || len(clients) > 10000 {
		return nil, &Error{Code: Invalid}
	}
	copyClients := make(map[string]*Client, len(clients))
	for generation, client := range clients {
		if client == nil || client.generation != generation {
			return nil, &Error{Code: Invalid}
		}
		copyClients[generation] = client
	}
	return &Scheduler{store: store, clients: copyClients, mapper: mapper, workers: workers, interval: time.Second, drainTimeout: RequestTimeout}, nil
}

type schedulerResult struct {
	job        Job
	kind       string
	task       TaskRef
	submission Submission
	status     Status
	report     *Report
	deleted    DeleteState
	err        error
}

type schedulerLive struct {
	job    Job
	cancel context.CancelFunc
}

// Run maintains local deadlines during outages and owns bounded request workers.
// Cancellation joins requests and harvests late outcomes using independent
// contexts. If storage remains unavailable after a bounded shutdown drain, Run
// returns ErrStoreUnavailable and retains pending outcomes in this Scheduler;
// repair storage and call Run again before discarding it. Durable submitting rows
// remain uncertain barriers even if the process is lost. Never close a store
// while Run is active. Mapper implementations must honor context cancellation.
func (s *Scheduler) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ErrConflict
	}
	s.running = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()
	s.store.mu.Lock()
	if s.store.closed || s.store.schedulerRunning {
		s.store.mu.Unlock()
		return ErrConflict
	}
	s.store.schedulerRunning = true
	s.store.mu.Unlock()
	defer func() { s.store.mu.Lock(); s.store.schedulerRunning = false; s.store.mu.Unlock() }()
	results := make(chan schedulerResult, s.workers)
	live := make(map[string]schedulerLive)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			for _, active := range live {
				active.cancel()
			}
			if s.beforeJoin != nil {
				s.beforeJoin()
			}
			for len(live) != 0 {
				r := <-results // Client requests have their own 30-second bound.
				live[r.job.ID].cancel()
				delete(live, r.job.ID)
				s.pending = append(s.pending, r)
			}
			drain, done := context.WithTimeout(context.Background(), s.drainTimeout)
			defer done()
			return s.drainPending(drain)
		}
		// Normal persistence has its own bound; shutdown instead shares one
		// absolute drain deadline across every pass and retry wait.
		s.persistPending()
		maintenance, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := s.store.Maintain(maintenance)
		if err == nil {
			err = s.store.markCleanupDeadlines(maintenance)
		}
		cancel()
		// Cancellation/deadline checks run even when maintenance storage fails.
		for id, active := range live {
			check, done := context.WithTimeout(ctx, time.Second)
			current, lookupErr := s.store.Lookup(check, active.job.Tenant, id)
			done()
			if cancelLiveLookup(active.job, current, lookupErr) {
				active.cancel()
			}
		}
		if err == nil && len(s.pending) == 0 {
			s.dispatch(ctx, live, results)
		}
		select {
		case r := <-results:
			live[r.job.ID].cancel()
			delete(live, r.job.ID)
			s.pending = append(s.pending, r)
		case <-ticker.C:
		case <-ctx.Done():
		}
	}
}

func cancelLiveLookup(active, current Job, lookupErr error) bool {
	var storeErr *Error
	gone := errors.As(lookupErr, &storeErr) && storeErr.Code == NotFound
	return gone || lookupErr == nil && terminal(current.State) && !terminal(active.State)
}

func retryDelay(attempt int) time.Duration {
	if attempt > 6 {
		attempt = 6
	}
	if attempt < 0 {
		attempt = 0
	}
	ceiling := 5 * time.Second << attempt
	if ceiling > 5*time.Minute {
		ceiling = 5 * time.Minute
	}
	if ceiling <= 5*time.Second {
		return 5 * time.Second
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(ceiling-5*time.Second)+1))
	if err != nil {
		return ceiling
	}
	return 5*time.Second + time.Duration(n.Int64())
}

func cleanupTask(j Job) (TaskRef, bool) {
	if !terminal(j.State) || j.CleanupDeadlineExceeded {
		return TaskRef{}, false
	}
	for _, id := range j.TaskIDs {
		acked := false
		for _, done := range j.DeleteAcknowledgedIDs {
			if id == done {
				acked = true
			}
		}
		if !acked {
			return TaskRef{ID: id, Generation: j.Generation}, true
		}
	}
	return TaskRef{}, false
}

func (s *Scheduler) dispatch(ctx context.Context, live map[string]schedulerLive, results chan<- schedulerResult) {
	jobs, err := s.store.schedulerJobs(ctx)
	if err != nil {
		return
	}
	// Stable per-tenant queues, rotated after each dispatched request. Separate
	// cursors prevent submission/poll traffic from starving a deletion tenant.
	sort.SliceStable(jobs, func(i, j int) bool {
		if jobs[i].Tenant != jobs[j].Tenant {
			return jobs[i].Tenant < jobs[j].Tenant
		}
		return jobs[i].CreatedAt.Before(jobs[j].CreatedAt)
	})
	for priority := 0; priority < 2; priority++ {
		for len(live) < s.workers {
			selected := -1
			for i, j := range jobs {
				if j.ID == "" || s.clients[j.Generation] == nil {
					continue
				}
				if _, exists := live[j.ID]; exists {
					continue
				}
				now := s.store.hooks.clock.Now()
				callbackWake := !j.PollWakeAt.IsZero() && !now.Before(j.PollWakeAt)
				retryAfter := !j.RetryAfterUntil.IsZero() && now.Before(j.RetryAfterUntil)
				if now.Before(j.NextAttempt) && (!callbackWake || retryAfter) {
					continue
				}
				_, deletion := cleanupTask(j)
				if (priority == 0) != deletion {
					continue
				}
				if !deletion && j.State != Queued && j.State != RemotePending && j.State != Fetching {
					continue
				}
				if selected < 0 {
					selected = i
				}
				if j.Tenant > s.lastTenant[priority] {
					selected = i
					break
				}
			}
			if selected < 0 {
				break
			}
			j := jobs[selected]
			jobs[selected].ID = "" // inspect each candidate at most once per pass
			client := s.clients[j.Generation]
			kind := "status"
			task, deletion := cleanupTask(j)
			if deletion {
				kind = "delete"
			} else if j.State == Fetching {
				kind = "report"
			} else if j.State == Queued {
				kind = "submit"
			}
			if !deletion && len(j.TaskIDs) == 1 {
				task = TaskRef{ID: j.TaskIDs[0], Generation: j.Generation}
			}
			var reserved Job
			if kind == "submit" {
				reserved, err = s.store.BeginSubmission(ctx, j.Tenant, j.ID, j.Version)
				if err != nil {
					// Even post-commit/checkpoint errors MUST NOT send. Retain an
					// outcome packet so ambiguous durable ownership is reconciled.
					packet := schedulerResult{job: j, kind: "begin_error", err: err}
					ownedCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
					reconcileErr := s.persist(ownedCtx, packet)
					done()
					if reconcileErr != nil {
						s.pending = append(s.pending, packet)
						return
					}
					continue
				}
			} else {
				reserved, err = s.store.reserveRead(ctx, j, retryDelay(j.ReadAttempts))
			}
			if err != nil {
				continue
			}
			s.lastTenant[priority] = j.Tenant
			requestCtx, cancel := context.WithCancel(ctx)
			live[j.ID] = schedulerLive{job: reserved, cancel: cancel}
			go s.request(requestCtx, client, schedulerResult{job: reserved, kind: kind, task: task}, results)
		}
	}
}

func (s *Scheduler) request(ctx context.Context, client *Client, r schedulerResult, results chan<- schedulerResult) {
	switch r.kind {
	case "submit":
		payload, err := s.store.OpenPayload(ctx, r.job.Tenant, r.job.ID, r.job.Version)
		if err != nil {
			// Do not assert NoBytesSent on a durable possibly-submitting row.
			r.submission.UnknownDebt, r.err = true, err
		} else {
			r.submission, r.err = client.Submit(ctx, payload, r.job.PayloadBytes, r.job.Correlation)
		}
	case "status":
		r.status, r.err = client.Status(ctx, r.task)
	case "report":
		var digest [32]byte
		b, err := hex.DecodeString(r.job.Digest)
		if err != nil || len(b) != len(digest) {
			r.err = &Error{Code: Protocol}
		} else {
			copy(digest[:], b)
			r.report, r.err = client.Report(ctx, r.task, digest)
		}
	case "delete":
		r.deleted, r.err = client.Delete(ctx, r.task)
	}
	results <- r // bounded buffer, never discard a late submission response
}

func outcomeCode(err error) Code {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) && safeOutcome(e.Code) {
		return e.Code
	}
	return Transport
}

func (s *Scheduler) persistPending() {
	s.persistPendingContext(context.Background())
}

func (s *Scheduler) drainPending(ctx context.Context) error {
	for len(s.pending) != 0 {
		if ctx.Err() != nil {
			return ErrStoreUnavailable
		}
		s.persistPendingContext(ctx)
		if len(s.pending) == 0 {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrStoreUnavailable
		case <-timer.C:
		}
	}
	return nil
}

func (s *Scheduler) persistPendingContext(parent context.Context) {
	if parent.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if s.beforePersist != nil {
		s.beforePersist(ctx)
	}
	remaining := s.pending[:0]
	for _, r := range s.pending {
		if ctx.Err() != nil {
			remaining = append(remaining, r)
			continue
		}
		err := s.persist(ctx, r)
		if err != nil {
			remaining = append(remaining, r)
		}
	}
	// Release raw report pointers in the unused capacity as soon as consumed.
	clear(s.pending[len(remaining):])
	s.pending = remaining
}

func (s *Scheduler) persist(ctx context.Context, r schedulerResult) error {
	if outcomeCode(r.err) == Unauthorized {
		if err := s.store.SetGenerationAdmission(ctx, r.job.Generation, false); err != nil {
			return err
		}
	}
	j, err := s.store.Lookup(ctx, r.job.Tenant, r.job.ID)
	if err != nil {
		return err
	}
	if r.kind == "begin_error" {
		if j.SubmissionVersion <= r.job.Version || j.SubmissionRecorded {
			return nil
		}
		r.job, r.kind = j, "submit"
		r.submission = Submission{UnknownDebt: true}
		r.err = &Error{Code: Transport}
	}
	if r.kind == "submit" {
		if j.SubmissionRecorded {
			return nil
		}
		_, err = s.store.RecordSubmission(ctx, j.Tenant, j.ID, r.job.SubmissionVersion, r.submission, outcomeCode(r.err), retryDelay(int(r.job.Attempts)))
		return err
	}
	if r.kind == "delete" {
		for _, id := range j.DeleteAcknowledgedIDs {
			if id == r.task.ID {
				return nil
			}
		}
		_, err = s.store.RecordDeletion(ctx, j.Tenant, j.ID, j.Version, r.task, r.deleted, outcomeCode(r.err))
		if err != nil {
			return err
		}
	} else if j.State != r.job.State || terminal(j.State) || j.Suppressed {
		return nil
	} else if r.err == nil {
		if r.kind == "status" {
			_, err = s.store.RecordStatus(ctx, j.Tenant, j.ID, j.Version, r.task, r.status)
		} else {
			_, err = s.store.CompleteReport(ctx, j.Tenant, j.ID, j.Version, r.task, r.report, s.mapper)
		}
		if err != nil {
			if outcomeCode(err) == Deadline {
				return nil
			} // Maintain owns expiry.
			return err
		}
	} else if r.kind == "report" {
		_, err = s.store.recordReportError(ctx, j.Tenant, j.ID, j.Version, r.task, outcomeCode(r.err))
		if err != nil {
			if outcomeCode(err) == Deadline {
				return nil // Maintain owns expiry.
			}
			return err
		}
	}
	var remoteErr *Error
	if errors.As(r.err, &remoteErr) && remoteErr.Code == Throttled {
		delay := remoteErr.RetryAfter
		if delay < 5*time.Second {
			delay = 5 * time.Second
		}
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
		return s.store.extendRetry(ctx, j, delay)
	}
	return nil
}
