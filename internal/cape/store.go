package cape

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	// Register modernc.org/sqlite as the database/sql driver used by OpenStore.
	_ "modernc.org/sqlite"
)

const (
	// PhysicalLimit is the largest supported physical CAPE volume.
	PhysicalLimit int64 = 2 << 30
	// StateReserve is the minimum physical capacity kept free for state writes.
	StateReserve int64 = 128 << 20
	// JobMetadataLimit bounds serialized metadata for one durable job.
	JobMetadataLimit = 4 << 10
	// JobResultLimit bounds the normalized result stored for one job.
	JobResultLimit       = 16 << 10
	databaseLimit  int64 = 64 << 20
	ingressLimit         = 30 * time.Second
	ingressIdle          = 5 * time.Second
	clockTolerance       = 5 * time.Second
)

var (
	// ErrStoreUnavailable indicates that durable state cannot be trusted or updated.
	ErrStoreUnavailable = errors.New("cape_store_unavailable")
	// ErrQuota indicates that a configured durable capacity limit was reached.
	ErrQuota = errors.New("cape_quota")
	// ErrConflict indicates that the requested lifecycle transition is stale or invalid.
	ErrConflict = errors.New("cape_state_conflict")
	// ErrClock indicates that the durable wall-clock high-water mark moved backwards.
	ErrClock = errors.New("cape_clock_rollback")
)

// JobState describes a durable CAPE job lifecycle state.
type JobState string

const (
	// Staging means attachment ingress is incomplete.
	Staging JobState = "staging"
	// Queued means the attachment is durably ready for submission.
	Queued JobState = "queued"
	// Submitting means remote ownership is being established.
	Submitting JobState = "submitting"
	// SubmitUncertain means a submission outcome may have been lost.
	SubmitUncertain JobState = "submit_uncertain"
	// RemotePending means owned remote analysis has not completed.
	RemotePending JobState = "remote_pending"
	// Fetching means a completed remote report is being collected.
	Fetching JobState = "fetching"
	// Completed means a normalized sandbox result is available.
	Completed JobState = "completed"
	// Failed means analysis ended without available sandbox evidence.
	Failed JobState = "failed"
	// Expired means an absolute lifecycle deadline elapsed.
	Expired JobState = "expired"
	// Cancelled means the tenant suppressed the job and cleanup remains tracked.
	Cancelled JobState = "cancelled"
)

// Job contains only bounded local metadata. Callers must not log identities,
// digests, task references or payloads. Terminal/result lifecycle is scheduler-owned.
type Job struct {
	ID, Tenant, Generation, SubmissionPolicy, ResultPolicy      string
	Digest, StaticVerdict, Correlation                          string
	State                                                       JobState
	Version                                                     int64
	ReservedBytes, PayloadBytes                                 int64
	CreatedAt, IngressDeadline, QueueDeadline, AnalysisDeadline time.Time
	TerminalAt, NextAttempt, AttemptAt                          time.Time
	Attempts                                                    int64
	SubmissionVersion                                           int64
	SubmissionRecorded                                          bool
	TaskIDs                                                     []int64
	DeleteAcknowledgedIDs                                       []int64
	Cleanup                                                     string
	UnknownDebt, DedupBarrier, Suppressed                       bool
	Reason                                                      Code
	Result                                                      json.RawMessage `json:",omitempty"`
	PollWakeAt                                                  time.Time
	ReadAttempts                                                int
	CleanupDeadlineExceeded                                     bool
}

// StoreConfig is trusted administrator configuration, not request input. Zero
// limits select the frozen defaults. Tenants must be explicitly approved.
type StoreConfig struct {
	Directory                                                 string
	Tenants                                                   []string
	MaxAttachment                                             int64
	MaxJobs, TenantJobs                                       int
	MaxBytes, TenantBytes                                     int64
	SubmitPerMinute, TenantSubmitPerMinute, RequestsPerMinute int
	SubmissionConcurrency, TenantSubmissionConcurrency        int
}

// EnqueueRequest contains trusted admission policy for one attachment.
type EnqueueRequest struct {
	Tenant, Generation, SubmissionPolicy, ResultPolicy, StaticVerdict string
}

// Admission reports the admitted job and whether an existing job was reused.
type Admission struct {
	Job    Job
	Reused bool
	// CurrentStatic is the current ingress classification, including on dedup.
	// Job.StaticVerdict remains the original admission snapshot during normal retention;
	// it is empty after tombstone minimization.
	CurrentStatic string
}

type storeTimer interface {
	C() <-chan time.Time
	Stop() bool
}
type storeClock interface {
	Now() time.Time
	NewTimer(time.Duration) storeTimer
}
type realStoreClock struct{}
type realStoreTimer struct{ *time.Timer }

func (realStoreClock) Now() time.Time                      { return time.Now().UTC() }
func (realStoreClock) NewTimer(d time.Duration) storeTimer { return realStoreTimer{time.NewTimer(d)} }
func (t realStoreTimer) C() <-chan time.Time               { return t.Timer.C }

type capacity struct{ total, available, block int64 }
type storeHooks struct {
	clock      storeClock
	capacity   func(*os.File, string) (capacity, error)
	crash      func(string)
	checkpoint func() error // package-private deterministic storage fault fixture
}

// Store owns a process-lifetime file lock and one SQLite connection. All database
// work is serialized, while bounded ingress writers run concurrently.
type Store struct {
	mu                        sync.Mutex
	db                        *sql.DB
	dir, spool, lock          *os.File
	cfg                       StoreConfig
	tenants                   map[string]bool
	hooks                     storeHooks
	closed                    bool
	active                    map[string]context.CancelFunc
	liveAttempts              map[string]string // job -> tenant, until its request outcome is recorded
	writers                   sync.WaitGroup
	schedulerRunning          bool
	maintenanceDeadlineCursor string
	maintenanceCleanupCursor  string
	cleanupDeadlineCursor     string
	schedulerCursor           string
}

// OpenStore validates cfg and opens the durable CAPE job store.
func OpenStore(ctx context.Context, cfg StoreConfig) (*Store, error) {
	return openStore(ctx, cfg, storeHooks{clock: realStoreClock{}, capacity: filesystemCapacity})
}

func validateStoreConfig(c *StoreConfig) error {
	if c.MaxAttachment == 0 {
		c.MaxAttachment = MaxAttachment
	}
	if c.MaxJobs == 0 {
		c.MaxJobs = 1000
	}
	if c.TenantJobs == 0 {
		c.TenantJobs = 100
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 1 << 30
	}
	if c.TenantBytes == 0 {
		c.TenantBytes = 100 << 20
	}
	if c.SubmitPerMinute == 0 {
		c.SubmitPerMinute = 5
	}
	if c.TenantSubmitPerMinute == 0 {
		c.TenantSubmitPerMinute = 2
	}
	if c.RequestsPerMinute == 0 {
		c.RequestsPerMinute = 5
	}
	if c.SubmissionConcurrency == 0 {
		c.SubmissionConcurrency = 2
	}
	if c.TenantSubmissionConcurrency == 0 {
		c.TenantSubmissionConcurrency = 1
	}
	if c.Directory == "" || len(c.Tenants) == 0 || len(c.Tenants) > 10000 ||
		c.MaxAttachment < 1 || c.MaxAttachment > MaxAttachment || c.MaxJobs < 1 || c.MaxJobs > 10000 ||
		c.TenantJobs < 1 || c.TenantJobs > c.MaxJobs || c.MaxBytes < 1 || c.MaxBytes > PhysicalLimit-StateReserve-3*databaseLimit ||
		c.TenantBytes < 1 || c.TenantBytes > c.MaxBytes || c.SubmitPerMinute < 1 || c.SubmitPerMinute > 10000 ||
		c.TenantSubmitPerMinute < 1 || c.TenantSubmitPerMinute > c.SubmitPerMinute ||
		c.RequestsPerMinute < c.SubmitPerMinute || c.RequestsPerMinute > 10000 || c.SubmissionConcurrency < 1 || c.SubmissionConcurrency > 100 || c.TenantSubmissionConcurrency < 1 || c.TenantSubmissionConcurrency > c.SubmissionConcurrency {
		return &Error{Code: Invalid}
	}
	for _, tenant := range c.Tenants {
		if !identifier(tenant, 128) {
			return &Error{Code: Invalid}
		}
	}
	return nil
}

func openStore(ctx context.Context, cfg StoreConfig, hooks storeHooks) (_ *Store, retErr error) {
	if err := validateStoreConfig(&cfg); err != nil {
		return nil, err
	}
	s := &Store{cfg: cfg, hooks: hooks, tenants: make(map[string]bool), active: make(map[string]context.CancelFunc), liveAttempts: make(map[string]string)}
	for _, tenant := range cfg.Tenants {
		s.tenants[tenant] = true
	}
	defer func() {
		if retErr != nil {
			s.closeFiles()
		}
	}()
	var err error
	s.dir, err = openPrivateDirectory(cfg.Directory)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	capacityInfo, err := hooks.capacity(s.dir, cfg.Directory)
	if err != nil || !validCapacity(capacityInfo) {
		return nil, ErrStoreUnavailable
	}
	s.lock, err = lockStore(s.dir)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	s.spool, err = openSpool(s.dir)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	if err = validateDatabaseFiles(s.dir); err != nil {
		return nil, ErrStoreUnavailable
	}
	u := url.URL{Scheme: "file", Path: databasePath(s.dir)}
	q := u.Query()
	for _, p := range []string{"busy_timeout(1000)", "journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(ON)", "temp_store(MEMORY)", "wal_autocheckpoint(32)", "journal_size_limit(0)", "max_page_count(16384)"} {
		q.Add("_pragma", p)
	}
	u.RawQuery = q.Encode()
	s.db, err = sql.Open("sqlite", u.String())
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	s.db.SetMaxOpenConns(1)
	s.db.SetMaxIdleConns(1)
	var mode string
	var synchronous, pageSize, pages int64
	if s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" ||
		s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous) != nil || synchronous != 2 ||
		s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize) != nil || pageSize != 4096 ||
		s.db.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&pages) != nil || pages != databaseLimit/pageSize {
		return nil, ErrStoreUnavailable
	}
	for pragma, want := range map[string]int64{"busy_timeout": 1000, "foreign_keys": 1, "temp_store": 2, "wal_autocheckpoint": 32, "journal_size_limit": 0} {
		var got int64
		if s.db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got) != nil || got != want {
			return nil, ErrStoreUnavailable
		}
	}
	var version int
	if s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil || (version != 0 && version != 1) {
		return nil, ErrStoreUnavailable
	}
	var integrity string
	if s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity) != nil || integrity != "ok" {
		return nil, ErrStoreUnavailable
	}
	if _, err = s.db.ExecContext(ctx, schema); err != nil {
		return nil, ErrStoreUnavailable
	}
	if err = s.recover(ctx); err != nil {
		return nil, err
	}
	if err = s.checkpoint(ctx); err != nil {
		return nil, err
	}
	if err = s.dir.Sync(); err != nil {
		return nil, ErrStoreUnavailable
	}
	capacityInfo, err = hooks.capacity(s.dir, cfg.Directory)
	if err != nil || !validCapacity(capacityInfo) || capacityInfo.available < StateReserve {
		return nil, ErrStoreUnavailable
	}
	return s, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, tenant TEXT NOT NULL, state TEXT NOT NULL,
 version INTEGER NOT NULL, reserved INTEGER NOT NULL CHECK(reserved>=0),
 digest TEXT NOT NULL, generation TEXT NOT NULL, submission_policy TEXT NOT NULL,
 result_policy TEXT NOT NULL, document BLOB NOT NULL CHECK(length(document)<=20480)
);
CREATE INDEX IF NOT EXISTS jobs_dedup ON jobs(tenant,digest,generation,submission_policy,result_policy);
CREATE INDEX IF NOT EXISTS jobs_state_id ON jobs(state,id);
CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY CHECK(id=1), latest INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS buckets (name TEXT PRIMARY KEY, tokens REAL NOT NULL, stamp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cape_admission_pause (generation TEXT PRIMARY KEY);
PRAGMA user_version=1;
`

func validCapacity(c capacity) bool {
	return c.total > StateReserve+3*databaseLimit && c.total <= PhysicalLimit && c.available >= 0 && c.available <= c.total && c.block > 0 && c.block <= 1<<20
}

func (s *Store) crash(point string) {
	if s.hooks.crash != nil {
		s.hooks.crash(point)
	}
}

func (s *Store) closeFiles() {
	if s.db != nil {
		_ = s.db.Close()
	}
	if s.spool != nil {
		_ = s.spool.Close()
	}
	if s.lock != nil {
		_ = s.lock.Close()
	}
	if s.dir != nil {
		_ = s.dir.Close()
	}
}

// Close interrupts ingress and joins every writer before releasing ownership.
// While a scheduler Run is active it returns ErrConflict immediately, leaves
// the store open and does not interrupt ingress. Stop and join Run first.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.schedulerRunning {
		s.mu.Unlock()
		return ErrConflict
	}
	if s.closed {
		s.mu.Unlock()
		return &Error{Code: Closed}
	}
	s.closed = true
	for _, cancel := range s.active {
		cancel()
	}
	s.mu.Unlock()
	s.writers.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.checkpoint(context.Background())
	s.closeFiles()
	return err
}

func (s *Store) checkpoint(ctx context.Context) error {
	if s.hooks.checkpoint != nil {
		if err := s.hooks.checkpoint(); err != nil {
			return err
		}
	}
	var busy, log, done int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); err != nil || busy != 0 {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *Store) transaction(ctx context.Context, f func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStoreUnavailable
	}
	defer tx.Rollback()
	if err = f(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func encodeJob(j Job) ([]byte, error) {
	r := j.Result
	j.Result = nil
	meta, err := json.Marshal(j)
	if err != nil || len(meta) > JobMetadataLimit || len(r) > JobResultLimit || (len(r) != 0 && !json.Valid(r)) {
		return nil, &Error{Code: TooLarge}
	}
	j.Result = r
	return json.Marshal(j)
}

func readJob(row *sql.Row) (Job, error) {
	var raw []byte
	var j Job
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return j, &Error{Code: NotFound}
		}
		return j, ErrStoreUnavailable
	}
	if len(raw) > JobMetadataLimit+JobResultLimit || json.Unmarshal(raw, &j) != nil {
		return j, ErrStoreUnavailable
	}
	return j, nil
}

func putJob(tx *sql.Tx, j Job, expected Job) error {
	raw, err := encodeJob(j)
	if err != nil {
		return err
	}
	r, err := tx.Exec(`UPDATE jobs SET state=?,version=?,reserved=?,digest=?,document=? WHERE id=? AND tenant=? AND state=? AND version=?`, j.State, j.Version, j.ReservedBytes, j.Digest, raw, j.ID, j.Tenant, expected.State, expected.Version)
	if err != nil {
		return ErrStoreUnavailable
	}
	n, err := r.RowsAffected()
	if err != nil {
		return ErrStoreUnavailable
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) now(tx *sql.Tx) (time.Time, error) {
	now := s.hooks.clock.Now().UTC()
	var stamp int64
	err := tx.QueryRow("SELECT latest FROM clock WHERE id=1").Scan(&stamp)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrStoreUnavailable
	}
	previous := time.Unix(0, stamp).UTC()
	if err == nil && now.Before(previous.Add(-clockTolerance)) {
		return time.Time{}, ErrClock
	}
	if err == nil && now.Before(previous) {
		now = previous
	}
	if _, err = tx.Exec("INSERT INTO clock(id,latest) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET latest=excluded.latest", now.UnixNano()); err != nil {
		return time.Time{}, ErrStoreUnavailable
	}
	return now, nil
}

func opaqueID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrStoreUnavailable
	}
	return hex.EncodeToString(b[:]), nil
}

// Lookup returns one tenant-owned job by ID.
func (s *Store) Lookup(ctx context.Context, tenant, id string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Job{}, &Error{Code: Closed}
	}
	return readJob(s.db.QueryRowContext(ctx, "SELECT document FROM jobs WHERE id=? AND tenant=?", id, tenant))
}

// List returns a bounded tenant-authorized snapshot for callers. HTTP adapters
// must never accept a tenant from the payload. Run uses schedulerJobs internally.
func (s *Store) List(ctx context.Context, tenant string, state JobState, limit int) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, &Error{Code: Closed}
	}
	if limit < 1 || limit > 1000 {
		return nil, &Error{Code: Invalid}
	}
	rows, err := s.db.QueryContext(ctx, "SELECT document FROM jobs WHERE tenant=? AND state=? ORDER BY id LIMIT ?", tenant, state, limit)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		var raw []byte
		var j Job
		if rows.Scan(&raw) != nil || len(raw) > JobMetadataLimit+JobResultLimit || json.Unmarshal(raw, &j) != nil {
			return nil, ErrStoreUnavailable
		}
		jobs = append(jobs, j)
	}
	if rows.Err() != nil {
		return nil, ErrStoreUnavailable
	}
	return jobs, nil
}

// OpenPayload opens only a generation-bound, tenant-owned submitting job. The
// scheduler closes the returned file before recording the submission outcome.
func (s *Store) OpenPayload(ctx context.Context, tenant, id string, version int64) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, &Error{Code: Closed}
	}
	j, err := readJob(s.db.QueryRowContext(ctx, "SELECT document FROM jobs WHERE id=? AND tenant=?", id, tenant))
	if err != nil {
		return nil, err
	}
	if j.State != Submitting || j.Version != version {
		return nil, ErrConflict
	}
	f, err := openStoreFile(s.spool, j.ID+".blob", os.O_RDONLY)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	return f, nil
}

func bucketName(kind, tenant string) string {
	return kind + ":" + strconv.Itoa(len(tenant)) + ":" + tenant
}
