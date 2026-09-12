package cape

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// CallbackPath is the fixed HTTP path for authenticated CAPE event hints.
const CallbackPath = "/v1/cape/events"
const callbackLimit = 4096

// BridgeKey is administrator-provisioned material. Secret is copied in memory,
// never persisted. IDs must not be recycled for unrelated keys. Each validity
// window is at most 30 days; overlapping keys sharing authority are limited by
// RotationOverlap. Expiration is exclusive.
type BridgeKey struct {
	ID                   string
	Secret               []byte
	Tenants, Generations []string
	NotBefore, NotAfter  time.Time
}

// CallbackConfig defines the trusted keys accepted by a callback handler.
type CallbackConfig struct {
	Keys            []BridgeKey
	RotationOverlap time.Duration // positive, at most one hour when multiple keys overlap
}

type callbackKey struct {
	BridgeKey
	tenants, generations map[string]bool
}

type callbackHandler struct {
	store *Store
	keys  map[string]callbackKey
}

// NewCallbackHandler returns a disabled (404) receiver without keys. Mount only
// on a directly terminated HTTPS server with bounded headers and read deadlines.
// No proxy header is trusted as proof of TLS. Callbacks only persist a poll hint;
// the scheduler authenticates and validates CAPE evidence separately. The daemon
// does not mount this receiver; its scheduler polls without callback hints.
func NewCallbackHandler(s *Store, cfg CallbackConfig) (http.Handler, error) {
	h := &callbackHandler{store: s, keys: make(map[string]callbackKey)}
	if len(cfg.Keys) == 0 {
		return h, nil
	}
	if s == nil || len(cfg.Keys) > 32 || cfg.RotationOverlap < 0 || cfg.RotationOverlap > time.Hour {
		return nil, &Error{Code: Invalid}
	}
	total := 0
	for _, k := range cfg.Keys {
		if !identifier(k.ID, 64) || len(k.Secret) != 32 || k.NotBefore.IsZero() || !k.NotAfter.After(k.NotBefore) || k.NotAfter.Sub(k.NotBefore) > 30*24*time.Hour || len(k.Tenants) == 0 || len(k.Generations) == 0 {
			return nil, &Error{Code: Invalid}
		}
		if _, ok := h.keys[k.ID]; ok {
			return nil, &Error{Code: Invalid}
		}
		total += len(k.Tenants) + len(k.Generations)
		if total > 4096 {
			return nil, &Error{Code: Invalid}
		}
		ck := callbackKey{BridgeKey: k, tenants: map[string]bool{}, generations: map[string]bool{}}
		ck.Secret = append([]byte(nil), k.Secret...)
		ck.Tenants = nil
		ck.Generations = nil
		for _, v := range k.Tenants {
			if !identifier(v, 128) || !s.tenants[v] {
				return nil, &Error{Code: Invalid}
			}
			ck.tenants[v] = true
		}
		for _, v := range k.Generations {
			if !identifier(v, 128) {
				return nil, &Error{Code: Invalid}
			}
			ck.generations[v] = true
		}
		for _, existingKey := range h.keys {
			if intersects(existingKey.tenants, ck.tenants) && intersects(existingKey.generations, ck.generations) {
				start, end := k.NotBefore, k.NotAfter
				if existingKey.NotBefore.After(start) {
					start = existingKey.NotBefore
				}
				if existingKey.NotAfter.Before(end) {
					end = existingKey.NotAfter
				}
				if end.After(start) && (cfg.RotationOverlap == 0 || end.Sub(start) > cfg.RotationOverlap) {
					return nil, &Error{Code: Invalid}
				}
			}
		}
		h.keys[k.ID] = ck
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreUnavailable
	}
	// Replay rows alone also bound the rate history, including removed key IDs.
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS cape_events(event TEXT PRIMARY KEY,tenant TEXT NOT NULL,key_id TEXT NOT NULL,accepted INTEGER NOT NULL,expires INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS cape_events_expiry ON cape_events(expires);
 CREATE INDEX IF NOT EXISTS cape_events_tenant ON cape_events(tenant);
 CREATE INDEX IF NOT EXISTS cape_events_key_accepted ON cape_events(key_id,accepted);
 CREATE TABLE IF NOT EXISTS cape_event_clock(id INTEGER PRIMARY KEY CHECK(id=1), latest INTEGER NOT NULL);`)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	return h, nil
}

func intersects(a, b map[string]bool) bool {
	for v := range a {
		if b[v] {
			return true
		}
	}
	return false
}

type callbackEvent struct {
	Version    int    `json:"version"`
	EventID    string `json:"event_id"`
	Tenant     string `json:"tenant_id"`
	JobID      string `json:"job_id"`
	Generation string `json:"endpoint_generation"`
	TaskID     int64  `json:"task_id"`
	Timestamp  int64  `json:"timestamp"`
}

func eventID(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == v
}

func callbackMAC(secret, body []byte, stamp, event string) []byte {
	digest := sha256.Sum256(body)
	m := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(m, "mailstrix-cape-v1\nPOST\n"+CallbackPath+"\n"+stamp+"\n"+event+"\n"+hex.EncodeToString(digest[:]))
	return m.Sum(nil)
}

func singleHeader(r *http.Request, name string) string {
	values := r.Header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func callbackMediaType(r *http.Request) bool {
	media, params, err := mime.ParseMediaType(singleHeader(r, "Content-Type"))
	return err == nil && strings.EqualFold(media, "application/json") && len(params) == 0
}

func (h *callbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status := h.receive(r)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
}

func (h *callbackHandler) receive(r *http.Request) int {
	if len(h.keys) == 0 {
		return http.StatusNotFound
	}
	body, status := callbackRequestBody(r)
	if status != 0 {
		return status
	}
	keyID, event, seconds, key, e, ok := h.authenticateCallback(r, body)
	if !ok {
		return http.StatusUnauthorized
	}
	s := h.store
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return http.StatusServiceUnavailable
	}
	s.writers.Add(1)
	s.mu.Unlock()
	defer s.writers.Done()
	s.callbackMu.Lock()
	defer s.callbackMu.Unlock()
	err := s.transaction(r.Context(), func(tx *sql.Tx) error {
		return h.persistCallback(tx, keyID, event, seconds, key, e)
	})
	switch {
	case err == nil:
		return http.StatusAccepted
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrQuota):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrClock), errors.Is(err, ErrStoreUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusUnauthorized
	}
}

func callbackRequestBody(r *http.Request) ([]byte, int) {
	if r.TLS == nil || r.Method != http.MethodPost || r.URL.EscapedPath() != CallbackPath || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Content-Encoding")) > 0 || !callbackMediaType(r) {
		return nil, http.StatusBadRequest
	}
	if r.ContentLength > callbackLimit {
		return nil, http.StatusRequestEntityTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, callbackLimit+1))
	if err != nil {
		return nil, http.StatusBadRequest
	}
	if len(body) > callbackLimit {
		return nil, http.StatusRequestEntityTooLarge
	}
	return body, 0
}

func (h *callbackHandler) authenticateCallback(r *http.Request, body []byte) (string, string, int64, callbackKey, callbackEvent, bool) {
	keyID := singleHeader(r, "X-Cape-Key-ID")
	key, known := h.keys[keyID]
	stamp, event := singleHeader(r, "X-Cape-Timestamp"), singleHeader(r, "X-Cape-Event-ID")
	seconds, stampErr := strconv.ParseInt(stamp, 10, 64)
	mac, macErr := hex.DecodeString(singleHeader(r, "X-Cape-Signature"))
	if !validCallbackSignature(known, stampErr, seconds, stamp, event, macErr, mac, key.Secret, body) {
		return "", "", 0, callbackKey{}, callbackEvent{}, false
	}
	// Authenticate raw bytes before interpreting the body or accessing any job.
	doc, err := jsonDocument(body, nil)
	var e callbackEvent
	if err != nil || len(doc) != 7 || json.Unmarshal(body, &e) != nil || !validCallbackEvent(e, event, seconds, key) {
		return "", "", 0, callbackKey{}, callbackEvent{}, false
	}
	for _, name := range []string{"version", "event_id", "tenant_id", "job_id", "endpoint_generation", "task_id", "timestamp"} {
		if _, present := doc[name]; !present {
			return "", "", 0, callbackKey{}, callbackEvent{}, false
		}
	}
	return keyID, event, seconds, key, e, true
}

func validCallbackSignature(known bool, stampErr error, seconds int64, stamp, event string, macErr error, mac, secret, body []byte) bool {
	return known && stampErr == nil && seconds > 0 && strconv.FormatInt(seconds, 10) == stamp && eventID(event) && macErr == nil && len(mac) == sha256.Size && hmac.Equal(mac, callbackMAC(secret, body, stamp, event))
}

func validCallbackEvent(e callbackEvent, event string, seconds int64, key callbackKey) bool {
	return e.Version == 1 && e.EventID == event && e.Timestamp == seconds && eventID(e.JobID) && key.tenants[e.Tenant] && key.generations[e.Generation] && e.TaskID > 0 && e.TaskID <= 2147483647
}

func (h *callbackHandler) persistCallback(tx *sql.Tx, keyID, event string, seconds int64, key callbackKey, e callbackEvent) error {
	s := h.store
	if s.hooks.callbackTx != nil {
		s.hooks.callbackTx()
	}
	actual := s.hooks.clock.Now().UTC()
	if err := validateCallbackClock(tx, actual, seconds, key); err != nil {
		return err
	}
	now, err := s.now(tx)
	if err != nil {
		return err
	}
	j, err := callbackJob(tx, e)
	if err != nil {
		return err
	}
	if err = reserveCallbackEvent(tx, keyID, event, e.Tenant, now); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO cape_event_clock(id,latest) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET latest=excluded.latest", actual.UnixNano()); err != nil {
		return ErrStoreUnavailable
	}
	if (j.State != RemotePending && j.State != Fetching) || j.Suppressed || !now.Before(j.AnalysisDeadline) {
		return nil
	}
	previous := j
	j.PollWakeAt = now
	j.Version++
	return putJob(tx, j, previous)
}

func validateCallbackClock(tx *sql.Tx, actual time.Time, seconds int64, key callbackKey) error {
	var latest int64
	err := tx.QueryRow("SELECT latest FROM cape_event_clock WHERE id=1").Scan(&latest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ErrStoreUnavailable
	}
	if err == nil && actual.Before(time.Unix(0, latest)) {
		return ErrClock
	}
	signed := time.Unix(seconds, 0)
	if actual.Before(key.NotBefore) || !actual.Before(key.NotAfter) || signed.Before(actual.Add(-5*time.Minute)) || signed.After(actual.Add(5*time.Minute)) {
		return &Error{Code: Invalid}
	}
	return nil
}

func callbackJob(tx *sql.Tx, e callbackEvent) (Job, error) {
	j, err := readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=? AND tenant=?", e.JobID, e.Tenant))
	if err != nil {
		if errors.Is(err, ErrStoreUnavailable) {
			return Job{}, ErrStoreUnavailable
		}
		return Job{}, &Error{Code: Invalid}
	}
	if j.ID != e.JobID || j.Tenant != e.Tenant || j.Generation != e.Generation || len(j.TaskIDs) != 1 || j.TaskIDs[0] != e.TaskID {
		return Job{}, &Error{Code: Invalid}
	}
	return j, nil
}

func reserveCallbackEvent(tx *sql.Tx, keyID, event, tenant string, now time.Time) error {
	if _, err := tx.Exec("DELETE FROM cape_events WHERE expires<=?", now.UnixNano()); err != nil {
		return ErrStoreUnavailable
	}
	var total, own, rate int
	if err := tx.QueryRow("SELECT count(*) FROM cape_events WHERE event=?", event).Scan(&total); err != nil {
		return ErrStoreUnavailable
	}
	if total != 0 {
		return ErrConflict
	}
	if err := tx.QueryRow("SELECT count(*) FROM cape_events").Scan(&total); err != nil {
		return ErrStoreUnavailable
	}
	if err := tx.QueryRow("SELECT count(*) FROM cape_events WHERE tenant=?", tenant).Scan(&own); err != nil {
		return ErrStoreUnavailable
	}
	if err := tx.QueryRow("SELECT count(*) FROM cape_events WHERE key_id=? AND accepted>?", keyID, now.Add(-time.Minute).UnixNano()).Scan(&rate); err != nil {
		return ErrStoreUnavailable
	}
	if total >= 10000 || own >= 1000 || rate >= 10 {
		return ErrQuota
	}
	if _, err := tx.Exec("INSERT INTO cape_events(event,tenant,key_id,accepted,expires) VALUES(?,?,?,?,?)", event, tenant, keyID, now.UnixNano(), now.Add(11*time.Minute).UnixNano()); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}
