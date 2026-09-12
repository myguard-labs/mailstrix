//go:build linux

package cape

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var storeEpoch = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

type fakeStoreClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*fakeStoreTimer]time.Time
}
type fakeStoreTimer struct {
	owner *fakeStoreClock
	ch    chan time.Time
}

func newStoreClock() *fakeStoreClock {
	return &fakeStoreClock{now: storeEpoch, timers: make(map[*fakeStoreTimer]time.Time)}
}
func (c *fakeStoreClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeStoreClock) NewTimer(d time.Duration) storeTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeStoreTimer{owner: c, ch: make(chan time.Time, 1)}
	if d <= 0 {
		t.ch <- c.now
	} else {
		c.timers[t] = c.now.Add(d)
	}
	return t
}
func (t *fakeStoreTimer) C() <-chan time.Time { return t.ch }
func (t *fakeStoreTimer) Stop() bool {
	t.owner.mu.Lock()
	defer t.owner.mu.Unlock()
	_, ok := t.owner.timers[t]
	delete(t.owner.timers, t)
	return ok
}
func (c *fakeStoreClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for t, deadline := range c.timers {
		if !c.now.Before(deadline) {
			t.ch <- c.now
			delete(c.timers, t)
		}
	}
}
func (c *fakeStoreClock) hasDeadline(d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, deadline := range c.timers {
		if deadline.Equal(c.now.Add(d)) {
			return true
		}
	}
	return false
}

func testCapacity(*os.File, string) (capacity, error) {
	return capacity{PhysicalLimit, PhysicalLimit, 4096}, nil
}
func storeConfig(dir string) StoreConfig {
	// testing.T.TempDir's leaf may honor a permissive umask; production requires
	// an operator-provisioned 0700 root and does not silently repair permissions.
	if err := os.Chmod(dir, 0o700); err != nil {
		panic(err)
	}
	return StoreConfig{Directory: dir, Tenants: []string{"alpha", "beta"}, MaxAttachment: 32}
}
func testStore(t *testing.T, cfg StoreConfig, clock *fakeStoreClock) *Store {
	t.Helper()
	s, e := openStore(context.Background(), cfg, storeHooks{clock: clock, capacity: testCapacity})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func storeRequest(tenant string) EnqueueRequest {
	return EnqueueRequest{Tenant: tenant, Generation: "g1", SubmissionPolicy: "s1", ResultPolicy: "r1", StaticVerdict: "unknown"}
}
func enqueueBytes(t *testing.T, s *Store, tenant, body string) Admission {
	t.Helper()
	a, e := s.Enqueue(context.Background(), storeRequest(tenant), io.NopCloser(strings.NewReader(body)))
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func storeCount(t *testing.T, s *Store) (int, int64) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	var size int64
	if e := s.db.QueryRow("SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM jobs").Scan(&n, &size); e != nil {
		t.Fatal(e)
	}
	return n, size
}
func waitStore(t *testing.T, f func() bool) {
	t.Helper()
	limit := time.Now().Add(3 * time.Second)
	for !f() {
		if time.Now().After(limit) {
			t.Fatal("store test condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func assertStoreCode(t *testing.T, err error, code Code) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

// The first idle timer expires normally, but its watcher and notification can
// be scheduled independently. All clock advances occur between reader events.
type delayedIdleClock struct {
	*fakeStoreClock
	armed    chan struct{}
	resume   chan struct{}
	rearmed  chan time.Duration
	first    atomic.Bool
	timer    storeTimer
	delivery chan time.Time
}

type delayedIdleTimer struct {
	storeTimer
	delivery <-chan time.Time
}

func (t delayedIdleTimer) C() <-chan time.Time { return t.delivery }

func (c *delayedIdleClock) NewTimer(d time.Duration) storeTimer {
	timer := c.fakeStoreClock.NewTimer(d)
	if d > ingressIdle {
		return timer
	}
	if c.first.CompareAndSwap(false, true) {
		c.timer = timer
		close(c.armed)
		<-c.resume
		return delayedIdleTimer{storeTimer: timer, delivery: c.delivery}
	}
	c.rearmed <- d
	return timer
}

type idleReadResult struct {
	data string
	err  error
}

type controlledIdleBody struct {
	reading chan struct{}
	results chan idleReadResult
	closed  chan struct{}
	once    sync.Once
}

func (b *controlledIdleBody) Read(p []byte) (int, error) {
	select {
	case b.reading <- struct{}{}:
	case <-b.closed:
		return 0, io.ErrClosedPipe
	}
	select {
	case result := <-b.results:
		return copy(p, result.data), result.err
	case <-b.closed:
		return 0, io.ErrClosedPipe
	}
}

func (b *controlledIdleBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func idleEvent[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("idle regression event timed out")
		var zero T
		return zero
	}
}

func TestStoreIngressDelayedIdleWatcher(t *testing.T) {
	for _, name := range []string{"late_eof", "late_bytes", "timely_progress_stale_timer"} {
		t.Run(name, func(t *testing.T) {
			clock := &delayedIdleClock{fakeStoreClock: newStoreClock(), armed: make(chan struct{}), resume: make(chan struct{}), rearmed: make(chan time.Duration, 8), delivery: make(chan time.Time, 1)}
			s, err := openStore(context.Background(), storeConfig(t.TempDir()), storeHooks{clock: clock, capacity: testCapacity})
			if err != nil {
				t.Fatal(err)
			}
			body := &controlledIdleBody{reading: make(chan struct{}, 1), results: make(chan idleReadResult, 1), closed: make(chan struct{})}
			var resume sync.Once
			release := func() { resume.Do(func() { close(clock.resume) }) }
			t.Cleanup(func() { release(); _ = body.Close(); _ = s.Close() })
			type outcome struct {
				admission Admission
				err       error
			}
			done := make(chan outcome, 1)
			go func() {
				a, e := s.Enqueue(context.Background(), storeRequest("alpha"), body)
				done <- outcome{a, e}
			}()
			idleEvent(t, clock.armed)
			idleEvent(t, body.reading)
			if name == "timely_progress_stale_timer" {
				clock.advance(4 * time.Second)
			}
			body.results <- idleReadResult{data: "x"}
			idleEvent(t, body.reading) // The preceding bytes have updated the deadline.
			if name == "timely_progress_stale_timer" {
				clock.advance(2 * time.Second)
				clock.delivery <- idleEvent(t, clock.timer.C())
				release()
				select {
				case <-clock.rearmed:
				case result := <-done:
					t.Fatalf("timely bytes falsely timed out after stale timer: error=%v", result.err)
				case <-time.After(3 * time.Second):
					t.Fatal("watcher did not process stale timer/progress")
				}
				clock.advance(2 * time.Second)
				body.results <- idleReadResult{err: io.EOF}
			} else {
				clock.advance(6 * time.Second)
				last := idleReadResult{err: io.EOF}
				if name == "late_bytes" {
					last.data = "y"
				}
				body.results <- last
				// Timer delivery remains delayed, independently of watcher scheduling.
				release()
			}
			result := idleEvent(t, done)
			if name == "timely_progress_stale_timer" {
				if result.err != nil || result.admission.Job.State != Queued || result.admission.Job.PayloadBytes != 1 {
					t.Fatalf("timely bytes falsely timed out after stale timer: admission=%+v error=%v", result.admission, result.err)
				}
				return
			}
			assertStoreCode(t, result.err, Deadline)
			if n, reserved := storeCount(t, s); n != 0 || reserved != 0 {
				t.Fatalf("idle rejection leaked staged/published jobs: jobs=%d reserved=%d", n, reserved)
			}
			files, err := os.ReadDir(filepath.Join(s.cfg.Directory, "spool"))
			if err != nil || len(files) != 0 {
				t.Fatalf("idle rejection leaked staged/published files: count=%d error=%v", len(files), err)
			}
		})
	}
}

func TestStoreAdmissionDedupTenant(t *testing.T) {
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	a := enqueueBytes(t, s, "alpha", "synthetic")
	if a.Reused || a.Job.State != Queued || a.Job.ReservedBytes != 9+JobMetadataLimit+JobResultLimit || a.Job.Version != 2 {
		t.Fatalf("durable admission mismatch: state=%s reserved=%d", a.Job.State, a.Job.ReservedBytes)
	}
	var wg sync.WaitGroup
	out := make(chan Admission, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, e := s.Enqueue(context.Background(), storeRequest("alpha"), io.NopCloser(strings.NewReader("synthetic")))
			if e != nil {
				errs <- e
			} else {
				out <- result
			}
		}()
	}
	wg.Wait()
	close(out)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	for duplicate := range out {
		if !duplicate.Reused || duplicate.Job.ID != a.Job.ID {
			t.Fatal("concurrent duplicate escaped dedup")
		}
	}
	b := enqueueBytes(t, s, "beta", "synthetic")
	if b.Reused || b.Job.ID == a.Job.ID {
		t.Fatal("cross-tenant dedup reused another tenant job")
	}
	_, e := s.Lookup(context.Background(), "beta", a.Job.ID)
	assertStoreCode(t, e, NotFound)
	_, e = s.Lookup(context.Background(), "beta", "absent")
	assertStoreCode(t, e, NotFound)
	for _, field := range []string{"generation", "submission", "result"} {
		r := storeRequest("alpha")
		switch field {
		case "generation":
			r.Generation = "g2"
		case "submission":
			r.SubmissionPolicy = "s2"
		case "result":
			r.ResultPolicy = "r2"
		}
		result, e := s.Enqueue(context.Background(), r, io.NopCloser(strings.NewReader("synthetic")))
		if e != nil || result.Reused {
			t.Fatalf("policy/generation dedup isolation failed: %s %v", field, e)
		}
	}
	if n, _ := storeCount(t, s); n != 5 {
		t.Fatalf("dedup staging cleanup left %d records, want 5", n)
	}
	files, e := os.ReadDir(filepath.Join(s.cfg.Directory, "spool"))
	if e != nil || len(files) != 5 {
		t.Fatalf("spool cleanup: count=%d error=%v", len(files), e)
	}
	for _, f := range files {
		info, e := f.Info()
		if e != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("payload is not private")
		}
	}
}

type countedBody struct {
	reader        io.Reader
	reads, closes atomic.Int32
}

func (b *countedBody) Read(p []byte) (int, error) { b.reads.Add(1); return b.reader.Read(p) }
func (b *countedBody) Close() error               { b.closes.Add(1); return nil }

func TestStoreQuotaBeforeRead(t *testing.T) {
	for _, boundary := range []string{"global_jobs", "tenant_jobs", "global_bytes", "tenant_bytes"} {
		t.Run(boundary, func(t *testing.T) {
			cfg := storeConfig(t.TempDir())
			reservation := cfg.MaxAttachment + JobMetadataLimit + JobResultLimit
			switch boundary {
			case "global_jobs":
				cfg.MaxJobs = 1
				cfg.TenantJobs = 1
			case "tenant_jobs":
				cfg.TenantJobs = 1
			case "global_bytes":
				cfg.MaxBytes = reservation
				cfg.TenantBytes = reservation
			case "tenant_bytes":
				cfg.TenantBytes = reservation
			}
			s := testStore(t, cfg, newStoreClock())
			enqueueBytes(t, s, "alpha", "duplicate")
			b := &countedBody{reader: strings.NewReader("duplicate")}
			_, e := s.Enqueue(context.Background(), storeRequest("alpha"), b)
			if !errors.Is(e, ErrQuota) || b.reads.Load() != 0 || b.closes.Load() != 1 {
				t.Fatalf("quota must reject before reading even duplicate: error=%v reads=%d closes=%d", e, b.reads.Load(), b.closes.Load())
			}
			if n, _ := storeCount(t, s); n != 1 {
				t.Fatalf("quota transaction admitted %d records, want 1", n)
			}
		})
	}
}

func TestStoreReserveCapacityAndInputErrors(t *testing.T) {
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	for _, data := range []string{"", strings.Repeat("x", 33)} {
		_, e := s.Enqueue(context.Background(), storeRequest("alpha"), io.NopCloser(strings.NewReader(data)))
		if e == nil {
			t.Fatal("invalid size admitted")
		}
		if n, _ := storeCount(t, s); n != 0 {
			t.Fatal("invalid ingress leaked reservation")
		}
	}
	enqueueBytes(t, s, "alpha", strings.Repeat("x", 32))
	s.hooks.capacity = func(*os.File, string) (capacity, error) {
		return capacity{PhysicalLimit, StateReserve + 3*databaseLimit, 4096}, nil
	}
	b := &countedBody{reader: strings.NewReader("x")}
	_, e := s.Enqueue(context.Background(), storeRequest("beta"), b)
	if !errors.Is(e, ErrQuota) || b.reads.Load() != 0 {
		t.Fatalf("physical reserve bypass: %v reads=%d", e, b.reads.Load())
	}
	s.hooks.capacity = func(*os.File, string) (capacity, error) {
		return capacity{PhysicalLimit + 1, PhysicalLimit + 1, 4096}, nil
	}
	_, e = s.Enqueue(context.Background(), storeRequest("beta"), io.NopCloser(strings.NewReader("x")))
	if !errors.Is(e, ErrStoreUnavailable) {
		t.Fatalf("geometry revalidation bypass: %v", e)
	}
}

type blockingBody struct {
	chunks  chan []byte
	closed  chan struct{}
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func newBlockingBody() *blockingBody {
	return &blockingBody{chunks: make(chan []byte), closed: make(chan struct{}), entered: make(chan struct{}, 64)}
}
func (b *blockingBody) Read(p []byte) (int, error) {
	b.entered <- struct{}{}
	select {
	case data := <-b.chunks:
		return copy(p, data), nil
	case <-b.closed:
		if b.release != nil {
			<-b.release
		}
		return 0, io.ErrClosedPipe
	}
}
func (b *blockingBody) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

func TestStoreWriterStopsBeforeRelease(t *testing.T) {
	cfg := storeConfig(t.TempDir())
	cfg.MaxJobs = 1
	cfg.TenantJobs = 1
	s := testStore(t, cfg, newStoreClock())
	b := newBlockingBody()
	b.release = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(b.release) }) }
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := s.Enqueue(ctx, storeRequest("alpha"), b); done <- e }()
	<-b.entered
	if n, size := storeCount(t, s); n != 1 || size != cfg.MaxAttachment+JobMetadataLimit+JobResultLimit {
		t.Fatalf("staging not fully reserved: jobs=%d bytes=%d", n, size)
	}
	cancel()
	<-b.closed
	if n, _ := storeCount(t, s); n != 1 {
		t.Fatal("reservation released before writer stopped")
	}
	probe := &countedBody{reader: strings.NewReader("probe")}
	_, e := s.Enqueue(context.Background(), storeRequest("beta"), probe)
	if !errors.Is(e, ErrQuota) || probe.reads.Load() != 0 {
		t.Fatal("live cancelled writer lost admission occupancy")
	}
	release()
	assertStoreCode(t, <-done, Deadline)
	if n, _ := storeCount(t, s); n != 0 {
		t.Fatal("stopped writer leaked reservation")
	}
}

func TestStoreIngressDeadlines(t *testing.T) {
	for _, mode := range []string{"idle", "absolute"} {
		t.Run(mode, func(t *testing.T) {
			clock := newStoreClock()
			s := testStore(t, storeConfig(t.TempDir()), clock)
			b := newBlockingBody()
			done := make(chan error, 1)
			go func() { _, e := s.Enqueue(context.Background(), storeRequest("alpha"), b); done <- e }()
			<-b.entered
			waitStore(t, func() bool { return clock.hasDeadline(ingressIdle) })
			if mode == "idle" {
				clock.advance(5 * time.Second)
			} else {
				for range 7 {
					clock.advance(4 * time.Second)
					b.chunks <- []byte("x")
					<-b.entered
					waitStore(t, func() bool { return clock.hasDeadline(ingressIdle) })
				}
				clock.advance(2 * time.Second)
			}
			select {
			case e := <-done:
				assertStoreCode(t, e, Deadline)
			case <-time.After(3 * time.Second):
				t.Fatal("ingress deadline did not close reader")
			}
			if n, _ := storeCount(t, s); n != 0 {
				t.Fatal("deadline leaked staging reservation")
			}
		})
	}
}

func TestStoreProcessLockAndStartupRefusal(t *testing.T) {
	cfg := storeConfig(t.TempDir())
	s := testStore(t, cfg, newStoreClock())
	if other, e := openStore(context.Background(), cfg, storeHooks{clock: newStoreClock(), capacity: testCapacity}); e == nil {
		other.Close()
		t.Fatal("second owner acquired live store")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenStore(context.Background(), cfg); !errors.Is(e, ErrStoreUnavailable) {
		t.Fatalf("unverified physical cap accepted: %v", e)
	}
	link := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(cfg.Directory, link); e != nil {
		t.Fatal(e)
	}
	cfg.Directory = link
	if _, e := openStore(context.Background(), cfg, storeHooks{clock: newStoreClock(), capacity: testCapacity}); !errors.Is(e, ErrStoreUnavailable) {
		t.Fatal("symlink directory accepted")
	}
}

func TestStoreSubmissionRestartNoReplay(t *testing.T) {
	cfg := storeConfig(t.TempDir())
	clock := newStoreClock()
	s := testStore(t, cfg, clock)
	a := enqueueBytes(t, s, "alpha", "uncertain")
	j, e := s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version)
	if e != nil {
		t.Fatal(e)
	}
	if j.Attempts != 1 || j.State != Submitting {
		t.Fatal("attempt not durably reserved")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	clock.advance(time.Minute)
	s = testStore(t, cfg, clock)
	recovered, e := s.Lookup(context.Background(), "alpha", j.ID)
	if e != nil {
		t.Fatal(e)
	}
	if recovered.State != SubmitUncertain || !recovered.UnknownDebt || !recovered.DedupBarrier || recovered.Version != j.Version+1 {
		t.Fatalf("restart must retain uncertainty, got state=%s barrier=%v debt=%v version=%d", recovered.State, recovered.DedupBarrier, recovered.UnknownDebt, recovered.Version)
	}
	if !recovered.CreatedAt.Equal(a.Job.CreatedAt) || !recovered.AnalysisDeadline.Equal(a.Job.AnalysisDeadline) {
		t.Fatal("restart reset persisted age")
	}
	_, e = s.BeginSubmission(context.Background(), "alpha", j.ID, recovered.Version)
	if !errors.Is(e, ErrConflict) {
		t.Fatalf("restart authorized blind submission replay: %v", e)
	}
	duplicate := enqueueBytes(t, s, "alpha", "uncertain")
	if !duplicate.Reused || duplicate.Job.ID != j.ID {
		t.Fatal("uncertain barrier allowed replay")
	}
}

func TestStoreSubmissionOutcomesAndVersions(t *testing.T) {
	for _, mode := range []string{"ack", "max_task_id", "ambiguous", "partial", "too_many", "no_bytes"} {
		t.Run(mode, func(t *testing.T) {
			clock := newStoreClock()
			s := testStore(t, storeConfig(t.TempDir()), clock)
			a := enqueueBytes(t, s, "alpha", "data")
			_, e := s.BeginSubmission(context.Background(), "beta", a.Job.ID, a.Job.Version)
			assertStoreCode(t, e, NotFound)
			_, e = s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version-1)
			if !errors.Is(e, ErrConflict) {
				t.Fatal("stale expected version accepted")
			}
			j, e := s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version)
			if e != nil {
				t.Fatal(e)
			}
			f, e := s.OpenPayload(context.Background(), "alpha", j.ID, j.Version)
			if e != nil {
				t.Fatal(e)
			}
			data, e := io.ReadAll(f)
			f.Close()
			if e != nil || string(data) != "data" {
				t.Fatal("owned payload changed")
			}
			sub := Submission{}
			code := Transport
			switch mode {
			case "ack":
				sub.Tasks = []TaskRef{{ID: 42, Generation: "g1"}}
				code = ""
			case "max_task_id":
				sub.Tasks = []TaskRef{{ID: maxTaskID, Generation: "g1"}}
				code = ""
			case "partial":
				sub.Tasks = []TaskRef{{ID: 42, Generation: "g1"}, {ID: 43, Generation: "g1"}}
				sub.UnknownDebt = true
				code = Protocol
			case "too_many":
				for i := 1; i <= 17; i++ {
					sub.Tasks = append(sub.Tasks, TaskRef{ID: int64(i), Generation: "g1"})
				}
				code = Protocol
			case "no_bytes":
				sub.NoBytesSent = true
			}
			j, e = s.RecordSubmission(context.Background(), "alpha", j.ID, j.Version, sub, code, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			_, e = s.RecordSubmission(context.Background(), "alpha", j.ID, j.Version-1, sub, code, time.Second)
			if !errors.Is(e, ErrConflict) {
				t.Fatal("stale submission outcome accepted")
			}
			if mode == "ack" || mode == "max_task_id" {
				wantTaskID := int64(42)
				if mode == "max_task_id" {
					wantTaskID = maxTaskID
				}
				if j.State != RemotePending || len(j.TaskIDs) != 1 || j.TaskIDs[0] != wantTaskID {
					t.Fatal("acknowledged ownership not persisted")
				}
				if _, e = os.Stat(filepath.Join(s.cfg.Directory, "spool", j.ID+".blob")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("acknowledged payload not removed")
				}
			} else if mode == "no_bytes" {
				if j.State != Queued || !j.NextAttempt.Equal(clock.Now().Add(5*time.Second)) || !j.AnalysisDeadline.Equal(a.Job.AnalysisDeadline) {
					t.Fatal("safe retry changed deadlines/backoff")
				}
			} else {
				want := SubmitUncertain
				if mode == "partial" || mode == "too_many" {
					want = Failed
				}
				if j.State != want || !j.UnknownDebt || !j.DedupBarrier {
					t.Fatal("ambiguous outcome lost debt")
				}
				if mode == "partial" && len(j.TaskIDs) != 2 {
					t.Fatal("partial IDs lost")
				}
				if mode == "too_many" && len(j.TaskIDs) != 16 {
					t.Fatal("bounded IDs lost")
				}
			}
		})
	}
}

func TestStoreRatePersistenceClockAndAge(t *testing.T) {
	cfg := storeConfig(t.TempDir())
	cfg.SubmitPerMinute = 2
	cfg.TenantSubmitPerMinute = 2
	cfg.RequestsPerMinute = 2
	clock := newStoreClock()
	s := testStore(t, cfg, clock)
	for _, data := range []string{"first", "second"} {
		a := enqueueBytes(t, s, "alpha", data)
		j, e := s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.RecordSubmission(context.Background(), "alpha", j.ID, j.Version, Submission{}, Transport, 0); e != nil {
			t.Fatal(e)
		}
	}
	a := enqueueBytes(t, s, "beta", "third")
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s = testStore(t, cfg, clock)
	_, e := s.BeginSubmission(context.Background(), "beta", a.Job.ID, a.Job.Version)
	assertStoreCode(t, e, Throttled)
	clock.advance(30 * time.Second)
	j, e := s.BeginSubmission(context.Background(), "beta", a.Job.ID, a.Job.Version)
	if e != nil {
		t.Fatal(e)
	}
	clock.advance(-10 * time.Second)
	_, e = s.Enqueue(context.Background(), storeRequest("beta"), io.NopCloser(strings.NewReader("rollback")))
	if !errors.Is(e, ErrClock) {
		t.Fatalf("clock rollback admitted job: %v", e)
	}
	// Recording ambiguity remains possible during rollback, so ownership is not lost.
	if _, e = s.RecordSubmission(context.Background(), "beta", j.ID, j.Version, Submission{}, Transport, 0); e != nil {
		t.Fatal(e)
	}
	clock.advance(10 * time.Second)
	previousAdmission := enqueueBytes(t, s, "beta", "age")
	clock.advance(time.Hour)
	_, e = s.BeginSubmission(context.Background(), "beta", previousAdmission.Job.ID, previousAdmission.Job.Version)
	assertStoreCode(t, e, Deadline)
}

func TestStoreConcurrentQuota(t *testing.T) {
	cfg := storeConfig(t.TempDir())
	cfg.MaxJobs = 2
	cfg.TenantJobs = 1
	s := testStore(t, cfg, newStoreClock())
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tenant := "alpha"
			if i%2 == 1 {
				tenant = "beta"
			}
			_, e := s.Enqueue(context.Background(), storeRequest(tenant), io.NopCloser(strings.NewReader(fmt.Sprintf("payload-%d", i))))
			if e == nil {
				accepted.Add(1)
			} else if !errors.Is(e, ErrQuota) {
				t.Errorf("concurrent admission: %v", e)
			}
		}()
	}
	wg.Wait()
	if n, _ := storeCount(t, s); n != 2 || accepted.Load() != 2 {
		t.Fatalf("concurrent quota oversubscribed: jobs=%d accepted=%d", n, accepted.Load())
	}
}

func TestStoreTenantAndRequestBudgets(t *testing.T) {
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	for i := range 2 {
		a := enqueueBytes(t, s, "alpha", fmt.Sprintf("tenant-%d", i))
		j, e := s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.RecordSubmission(context.Background(), "alpha", j.ID, j.Version, Submission{}, Transport, 0); e != nil {
			t.Fatal(e)
		}
	}
	a := enqueueBytes(t, s, "alpha", "third")
	_, e := s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version)
	assertStoreCode(t, e, Throttled)
	for range 3 {
		if e = s.TakeRequestToken(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.TakeRequestToken(context.Background()); e == nil {
		t.Fatal("total request budget exceeded five")
	}
	b := enqueueBytes(t, s, "beta", "global")
	_, e = s.BeginSubmission(context.Background(), "beta", b.Job.ID, b.Job.Version)
	assertStoreCode(t, e, Throttled)
	clock.advance(time.Minute)
	if _, e = s.BeginSubmission(context.Background(), "beta", b.Job.ID, b.Job.Version); e != nil {
		t.Fatal(e)
	}
}

func TestStoreDatabaseFullFailsAdmission(t *testing.T) {
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	var pages int
	if e := s.db.QueryRow("PRAGMA page_count").Scan(&pages); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); e != nil {
		t.Fatal(e)
	}
	failed := false
	for i := range 40 {
		b := &countedBody{reader: strings.NewReader(fmt.Sprintf("full-%d", i))}
		_, e := s.Enqueue(context.Background(), storeRequest("alpha"), b)
		if e != nil {
			if !errors.Is(e, ErrStoreUnavailable) {
				t.Fatalf("unexpected full error: %v", e)
			}
			failed = true
			break
		}
	}
	if !failed {
		t.Fatal("SQLite page cap did not cause an observed full error")
	}
	var staging int
	if e := s.db.QueryRow("SELECT COUNT(*) FROM jobs WHERE state=?", Staging).Scan(&staging); e != nil || staging != 0 {
		t.Fatalf("SQLITE_FULL leaked staging: %d %v", staging, e)
	}
}

func TestStoreCrashChild(t *testing.T) {
	dir := os.Getenv("CAPE_STORE_TEST_DIR")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	point := os.Getenv("CAPE_STORE_TEST_POINT")
	s, e := openStore(context.Background(), storeConfig(dir), storeHooks{clock: newStoreClock(), capacity: testCapacity, crash: func(p string) {
		if p == point {
			os.Exit(77)
		}
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	a := enqueueBytes(t, s, "alpha", "crash")
	if point == "submitting_committed" {
		if _, e = s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version); e != nil {
			t.Fatal(e)
		}
	}
	if point == "submission_recorded" {
		j, e := s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.RecordSubmission(context.Background(), "alpha", j.ID, j.Version, Submission{Tasks: []TaskRef{{ID: 42, Generation: "g1"}}}, "", 0); e != nil {
			t.Fatal(e)
		}
	}
	t.Fatalf("crash point %s not reached", point)
}

func TestStoreCrashRecovery(t *testing.T) {
	for _, point := range []string{"staging_committed", "file_synced", "rename_synced", "queued_before_commit", "queued_committed", "submitting_committed", "submission_recorded"} {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestStoreCrashChild$", "-test.v")
			cmd.Env = []string{"CAPE_STORE_TEST_DIR=" + dir, "CAPE_STORE_TEST_POINT=" + point}
			out, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("child did not crash at %s: %v %s", point, e, out)
			}
			s := testStore(t, storeConfig(dir), newStoreClock())
			n, _ := storeCount(t, s)
			want := 0
			state := Queued
			switch point {
			case "queued_committed":
				want = 1
			case "submitting_committed":
				want = 1
				state = SubmitUncertain
			case "submission_recorded":
				want = 1
				state = RemotePending
			}
			if n != want {
				t.Fatalf("recovery at %s retained %d records, want %d", point, n, want)
			}
			jobs, e := s.List(context.Background(), "alpha", state, 10)
			if e != nil || len(jobs) != want {
				t.Fatalf("recovery state %s: count=%d error=%v", state, len(jobs), e)
			}
			files, e := os.ReadDir(filepath.Join(dir, "spool"))
			wantFiles := want
			if point == "submission_recorded" {
				wantFiles = 0
			}
			if e != nil || len(files) != wantFiles {
				t.Fatalf("crash recovery left %d spool files, want %d", len(files), wantFiles)
			}
			if state == SubmitUncertain {
				_, e = s.BeginSubmission(context.Background(), "alpha", jobs[0].ID, jobs[0].Version)
				if !errors.Is(e, ErrConflict) {
					t.Fatal("crash recovery allowed blind retry")
				}
			}
		})
	}
}

func TestStoreOrphanAndCleanupError(t *testing.T) {
	cfg := storeConfig(t.TempDir())
	s := testStore(t, cfg, newStoreClock())
	orphan := strings.Repeat("a", 32) + ".tmp"
	f, e := openStoreFile(s.spool, orphan, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write([]byte("orphan")); e != nil {
		t.Fatal(e)
	}
	f.Sync()
	f.Close()
	s.spool.Sync()
	s.Close()
	s = testStore(t, cfg, newStoreClock())
	files, e := os.ReadDir(filepath.Join(cfg.Directory, "spool"))
	if e != nil || len(files) != 0 {
		t.Fatal("startup orphan not removed")
	}
	// A directory in place of an interrupted file cannot be unlinked as a file.
	// The reservation must survive cleanup failure, so capacity is not reused.
	s.mu.Lock()
	j, e := s.reserve(context.Background(), storeRequest("alpha"))
	s.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(cfg.Directory, "spool", j.ID+".tmp"), 0o700); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	e = s.cleanupStaging(j.ID)
	s.mu.Unlock()
	if e == nil {
		t.Fatal("cleanup error was hidden")
	}
	if n, _ := storeCount(t, s); n != 1 {
		t.Fatal("cleanup failure released staging capacity")
	}
}

func TestStoreMetadataBoundAndReusableResult(t *testing.T) {
	j := Job{ID: strings.Repeat("a", 32), Tenant: "alpha", State: Completed, TerminalAt: storeEpoch}
	if !reusable(j, storeEpoch.Add(24*time.Hour-time.Nanosecond)) || reusable(j, storeEpoch.Add(24*time.Hour)) {
		t.Fatal("result reuse deadline is not absolute")
	}
	j.Suppressed = true
	if reusable(j, storeEpoch) {
		t.Fatal("suppressed result reused")
	}
	j.State = Expired
	j.DedupBarrier = true
	if !reusable(j, storeEpoch.Add(8*24*time.Hour)) {
		t.Fatal("expired uncertainty lost barrier")
	}
	j.StaticVerdict = strings.Repeat("x", JobMetadataLimit)
	if _, e := encodeJob(j); e == nil {
		t.Fatal("oversized metadata admitted")
	}
	j.StaticVerdict = "unknown"
	j.Result = []byte(`"` + strings.Repeat("x", JobResultLimit) + `"`)
	if _, e := encodeJob(j); e == nil {
		t.Fatal("oversized result admitted")
	}
}

func TestStoreOldDebtPausesTenant(t *testing.T) {
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	a := enqueueBytes(t, s, "alpha", "debt")
	j, e := s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RecordSubmission(context.Background(), "alpha", j.ID, j.Version, Submission{}, Transport, 0); e != nil {
		t.Fatal(e)
	}
	clock.advance(7 * 24 * time.Hour)
	b := &countedBody{reader: strings.NewReader("next")}
	_, e = s.Enqueue(context.Background(), storeRequest("alpha"), b)
	if !errors.Is(e, ErrQuota) || b.reads.Load() != 0 {
		t.Fatalf("old cleanup debt did not pause tenant before input: %v", e)
	}
	enqueueBytes(t, s, "beta", "unaffected")
}
