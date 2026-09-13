//go:build linux

package cape

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func bridgeConfig(c *fakeStoreClock) CallbackConfig {
	return CallbackConfig{Keys: []BridgeKey{{ID: "bridge", Secret: bytes.Repeat([]byte{0x42}, 32), Tenants: []string{"alpha", "beta"}, Generations: []string{"g1", "g2"}, NotBefore: c.Now().Add(-time.Hour), NotAfter: c.Now().Add(time.Hour)}}}
}
func callbackFixture(t *testing.T) (*Store, *fakeStoreClock, CallbackConfig, Job, http.Handler) {
	t.Helper()
	c := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), c)
	a := enqueueBytes(t, s, "alpha", "callback")
	j, err := s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version)
	if err != nil {
		t.Fatal(err)
	}
	j, err = s.RecordSubmission(context.Background(), "alpha", j.ID, j.Version, Submission{Tasks: []TaskRef{{ID: 42, Generation: "g1"}}}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := bridgeConfig(c)
	h, err := NewCallbackHandler(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s, c, cfg, j, h
}
func bridgeEvent(c *fakeStoreClock, j Job, n int) callbackEvent {
	return callbackEvent{1, fmt.Sprintf("%032x", n), j.Tenant, j.ID, j.Generation, 42, c.Now().Unix()}
}
func bridgeRequest(t *testing.T, cfg CallbackConfig, e callbackEvent, body []byte) *http.Request {
	t.Helper()
	if body == nil {
		var err error
		body, err = json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "https://receiver.invalid"+CallbackPath, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Cape-Key-ID", cfg.Keys[0].ID)
	stamp := strconv.FormatInt(e.Timestamp, 10)
	r.Header.Set("X-Cape-Timestamp", stamp)
	r.Header.Set("X-Cape-Event-ID", e.EventID)
	// Independent bridge-side encoding: do not use the receiver's MAC helper.
	digest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, cfg.Keys[0].Secret)
	fmt.Fprintf(mac, "mailstrix-cape-v1\nPOST\n/v1/cape/events\n%s\n%s\n%x", stamp, e.EventID, digest)
	r.Header.Set("X-Cape-Signature", hex.EncodeToString(mac.Sum(nil)))
	return r
}
func bridgeStatus(h http.Handler, r *http.Request) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}
func requireBridge(t *testing.T, h http.Handler, r *http.Request, want int) {
	t.Helper()
	if got := bridgeStatus(h, r); got != want {
		t.Fatalf("callback status=%d want=%d", got, want)
	}
}

func TestCallbackReplayRestart(t *testing.T) {
	s, c, cfg, j, h := callbackFixture(t)
	e := bridgeEvent(c, j, 1)
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 202)
	first, err := s.Lookup(context.Background(), j.Tenant, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.PollWakeAt.IsZero() || first.State != RemotePending || len(first.Result) != 0 {
		t.Fatal("callback did not persist wakeup-only hint")
	}
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 409)
	sc := s.cfg
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = testStore(t, sc, c)
	h, err = NewCallbackHandler(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 409)
	after, err := s.Lookup(context.Background(), j.Tenant, j.ID)
	if err != nil || after.Version != first.Version || !after.PollWakeAt.Equal(first.PollWakeAt) {
		t.Fatal("replay scheduled duplicate work")
	}
	c.advance(11 * time.Minute)
	e.Timestamp = c.Now().Unix()
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 202)
}

func TestCallbackBinding(t *testing.T) {
	for _, mode := range []string{"tenant", "generation", "task", "job", "key_tenant", "key_generation", "bad_mac"} {
		t.Run(mode, func(t *testing.T) {
			s, c, cfg, j, h := callbackFixture(t)
			e := bridgeEvent(c, j, 1)
			switch mode {
			case "tenant":
				e.Tenant = "beta"
			case "generation":
				e.Generation = "g2"
			case "task":
				e.TaskID = 43
			case "job":
				e.JobID = strings.Repeat("0", 32)
			case "key_tenant":
				cfg.Keys[0].Tenants = []string{"beta"}
			case "key_generation":
				cfg.Keys[0].Generations = []string{"g2"}
			}
			if mode == "key_tenant" || mode == "key_generation" {
				// Keep the event bound to the real job, isolating key authority.
				var err error
				h, err = NewCallbackHandler(s, cfg)
				if err != nil {
					t.Fatal(err)
				}
			}
			r := bridgeRequest(t, cfg, e, nil)
			if mode == "bad_mac" {
				r.Header.Set("X-Cape-Signature", strings.Repeat("00", 32))
			}
			requireBridge(t, h, r, 401)
			got, err := s.Lookup(context.Background(), j.Tenant, j.ID)
			if err != nil || got.Version != j.Version || !got.PollWakeAt.IsZero() {
				t.Fatal("wrong binding scheduled work")
			}
			var n int
			if err = s.db.QueryRow("SELECT count(*) FROM cape_events").Scan(&n); err != nil || n != 0 {
				t.Fatal("rejected callback persisted event")
			}
		})
	}
}

func TestCallbackAcceptsOwnedMaxTaskID(t *testing.T) {
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	a := enqueueBytes(t, s, "alpha", "callback-max-task")
	j, err := s.BeginSubmission(context.Background(), "alpha", a.Job.ID, a.Job.Version)
	if err != nil {
		t.Fatal(err)
	}
	j, err = s.RecordSubmission(context.Background(), "alpha", j.ID, j.Version, Submission{Tasks: []TaskRef{{ID: maxTaskID, Generation: "g1"}}}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := bridgeConfig(clock)
	handler, err := NewCallbackHandler(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	event := bridgeEvent(clock, j, 1)
	event.TaskID = maxTaskID
	requireBridge(t, handler, bridgeRequest(t, cfg, event, nil), http.StatusAccepted)
}

func TestCallbackEnvelope(t *testing.T) {
	for _, mode := range []string{"disabled", "http", "method", "path", "escaped", "query", "content_type", "encoding", "oversized", "chunked", "bad_json", "duplicate", "unknown", "header_event", "header_time", "double_header", "stale", "future", "boundary_old", "boundary_future"} {
		t.Run(mode, func(t *testing.T) {
			_, c, cfg, j, h := callbackFixture(t)
			e := bridgeEvent(c, j, 1)
			want := 400
			var body []byte
			switch mode {
			case "stale":
				e.Timestamp -= 301
				want = 401
			case "future":
				e.Timestamp += 301
				want = 401
			case "boundary_old":
				e.Timestamp -= 300
				want = 202
			case "boundary_future":
				e.Timestamp += 300
				want = 202
			case "bad_json":
				body = []byte("{")
				want = 401
			case "duplicate":
				body, _ = json.Marshal(e)
				body = append([]byte(`{"version":1,`), body[1:]...)
				want = 401
			case "unknown":
				body, _ = json.Marshal(e)
				body = append([]byte(`{"verdict":"clean",`), body[1:]...)
				want = 401
			case "oversized", "chunked":
				body = bytes.Repeat([]byte(" "), 4097)
				want = 413
			}
			r := bridgeRequest(t, cfg, e, body)
			switch mode {
			case "disabled":
				h, _ = NewCallbackHandler(nil, CallbackConfig{})
				want = 404
			case "http":
				r.TLS = nil
			case "method":
				r.Method = "GET"
			case "path":
				r.URL.Path += "/"
			case "escaped":
				r.URL.RawPath = "/v1/cape/%65vents"
			case "query":
				r.URL.RawQuery = "a=1"
			case "content_type":
				r.Header.Set("Content-Type", "text/plain")
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "chunked":
				r.ContentLength = -1
			case "header_event":
				r.Header.Set("X-Cape-Event-ID", strings.Repeat("a", 32))
				want = 401
			case "header_time":
				r.Header.Set("X-Cape-Timestamp", strconv.FormatInt(e.Timestamp+1, 10))
				want = 401
			case "double_header":
				r.Header.Add("X-Cape-Key-ID", "bridge")
				want = 401
			}
			requireBridge(t, h, r, want)
		})
	}
}

func TestCallbackRateCapsClockTerminal(t *testing.T) {
	for _, mode := range []string{"rate", "tenant_cap", "global_cap", "rollback", "terminal", "expired"} {
		t.Run(mode, func(t *testing.T) {
			s, c, cfg, j, h := callbackFixture(t)
			switch mode {
			case "rate":
				for n := 1; n <= 10; n++ {
					requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, n), nil), 202)
				}
				requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 11), nil), 429)
				sc := s.cfg
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				s = testStore(t, sc, c)
				var err error
				h, err = NewCallbackHandler(s, cfg)
				if err != nil {
					t.Fatal(err)
				}
				requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 11), nil), 429)
				c.advance(time.Minute)
				requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 11), nil), 202)
			case "tenant_cap", "global_cap":
				n, tenant := 1000, "alpha"
				if mode == "global_cap" {
					n = 10000
					tenant = "beta"
				}
				tx, err := s.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				for i := 1; i <= n; i++ {
					if _, err = tx.Exec("INSERT INTO cape_events VALUES(?,?,?,?,?)", fmt.Sprintf("%032x", i), tenant, "other", c.Now().UnixNano(), c.Now().Add(11*time.Minute).UnixNano()); err != nil {
						t.Fatal(err)
					}
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 20000), nil), 429)
				c.advance(11 * time.Minute)
				requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 20000), nil), 202)
			case "rollback":
				requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 1), nil), 202)
				c.advance(-time.Nanosecond)
				requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 2), nil), 503)
				c.advance(time.Nanosecond)
				requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 2), nil), 202)
			case "terminal", "expired":
				if mode == "terminal" {
					var err error
					j, err = s.Cancel(context.Background(), j.Tenant, j.ID)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					c.advance(24 * time.Hour)
					cfg = bridgeConfig(c)
					var err error
					h, err = NewCallbackHandler(s, cfg)
					if err != nil {
						t.Fatal(err)
					}
				}
				requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 1), nil), 202)
				got, err := s.Lookup(context.Background(), j.Tenant, j.ID)
				if err != nil || got.State != j.State || !got.PollWakeAt.IsZero() || got.Version != j.Version {
					t.Fatal("terminal or overdue callback resurrected work")
				}
			}
		})
	}
}

func TestCallbackRotationTLS(t *testing.T) {
	s, c, cfg, j, _ := callbackFixture(t)
	previousKey := cfg.Keys[0]
	previousKey.NotAfter = c.Now().Add(30 * time.Minute)
	next := previousKey
	next.ID = "next"
	next.Secret = bytes.Repeat([]byte{0x43}, 32)
	next.NotBefore = c.Now()
	next.NotAfter = c.Now().Add(2 * time.Hour)
	cfg.Keys = []BridgeKey{previousKey, next}
	cfg.RotationOverlap = 30 * time.Minute
	h, err := NewCallbackHandler(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	client.Timeout = 3 * time.Second
	for i, k := range cfg.Keys {
		one := CallbackConfig{Keys: []BridgeKey{k}}
		r := bridgeRequest(t, one, bridgeEvent(c, j, i+1), nil)
		r.RequestURI = ""
		r.URL.Scheme = "https"
		r.URL.Host = strings.TrimPrefix(server.URL, "https://")
		r.TLS = nil
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 202 {
			t.Fatal("TLS bridge did not accept rotated key", err, response.StatusCode)
		}
	}
	c.advance(30 * time.Minute)
	requireBridge(t, h, bridgeRequest(t, CallbackConfig{Keys: []BridgeKey{previousKey}}, bridgeEvent(c, j, 3), nil), 401)
	requireBridge(t, h, bridgeRequest(t, CallbackConfig{Keys: []BridgeKey{next}}, bridgeEvent(c, j, 3), nil), 202)
	cfg.RotationOverlap = time.Minute
	if _, err = NewCallbackHandler(s, cfg); err == nil {
		t.Fatal("unbounded rotation accepted")
	}
}

func TestCallbackAuthenticationAndAtomicity(t *testing.T) {
	for _, mode := range []string{"signed_event_mismatch", "signed_time_mismatch", "exact_limit", "insert_failure", "unauth_before_store", "config_copy"} {
		t.Run(mode, func(t *testing.T) {
			s, c, cfg, j, h := callbackFixture(t)
			e := bridgeEvent(c, j, 1)
			body, _ := json.Marshal(e)
			switch mode {
			case "signed_event_mismatch":
				e.EventID = fmt.Sprintf("%032x", 2)
			case "signed_time_mismatch":
				e.Timestamp++
			case "exact_limit":
				body = append(body, bytes.Repeat([]byte(" "), 4096-len(body))...)
			case "insert_failure":
				if _, err := s.db.Exec(`CREATE TRIGGER fail_event BEFORE INSERT ON cape_events BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
					t.Fatal(err)
				}
			case "unauth_before_store":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			case "config_copy":
				cfg.Keys[0].Secret[0] ^= 1
			}
			r := bridgeRequest(t, cfg, e, body)
			want := 202
			switch mode {
			case "signed_event_mismatch", "signed_time_mismatch", "config_copy":
				want = 401
			case "insert_failure":
				want = 503
			case "unauth_before_store":
				r.Header.Set("X-Cape-Signature", strings.Repeat("00", 32))
				want = 401
			}
			requireBridge(t, h, r, want)
			if mode == "insert_failure" {
				got, err := s.Lookup(context.Background(), j.Tenant, j.ID)
				if err != nil || !got.PollWakeAt.IsZero() || got.Version != j.Version {
					t.Fatal("failed replay transaction published wakeup")
				}
			}
		})
	}
}

func TestCallbackInvalidConfig(t *testing.T) {
	for _, mode := range []string{"secret", "duplicate", "tenant", "generation", "expired_window", "long_window", "many_keys", "many_bindings", "overlap"} {
		t.Run(mode, func(t *testing.T) {
			s, c, _, _, _ := callbackFixture(t)
			cfg := bridgeConfig(c)
			switch mode {
			case "secret":
				cfg.Keys[0].Secret = []byte("inert")
			case "duplicate":
				cfg.Keys = append(cfg.Keys, cfg.Keys[0])
			case "tenant":
				cfg.Keys[0].Tenants = []string{"unknown"}
			case "generation":
				cfg.Keys[0].Generations = []string{"/untrusted"}
			case "expired_window":
				cfg.Keys[0].NotAfter = cfg.Keys[0].NotBefore
			case "long_window":
				cfg.Keys[0].NotAfter = c.Now().Add(31 * 24 * time.Hour)
			case "many_keys":
				cfg.Keys = make([]BridgeKey, 33)
			case "many_bindings":
				cfg.Keys[0].Generations = make([]string, 4097)
			case "overlap":
				cfg.RotationOverlap = 2 * time.Hour
			}
			if _, err := NewCallbackHandler(s, cfg); err == nil {
				t.Fatal("invalid callback config accepted")
			}
		})
	}
}

func TestCallbackCorruptJob(t *testing.T) {
	s, c, cfg, j, h := callbackFixture(t)
	var original []byte
	if err := s.db.QueryRow("SELECT document FROM jobs WHERE id=?", j.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE jobs SET document=? WHERE id=?", []byte("{"), j.ID); err != nil {
		t.Fatal(err)
	}
	e := bridgeEvent(c, j, 1)
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 503)
	var raw []byte
	var version int64
	if err := s.db.QueryRow("SELECT document,version FROM jobs WHERE id=?", j.ID).Scan(&raw, &version); err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{" || version != j.Version {
		t.Fatal("corrupt job callback mutated stored job")
	}
	var events int
	if err := s.db.QueryRow("SELECT count(*) FROM cape_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatal("corrupt job callback consumed replay event")
	}
	if _, err := s.db.Exec("UPDATE jobs SET document=? WHERE id=?", original, j.ID); err != nil {
		t.Fatal(err)
	}
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 202)
}

func TestCallbackLateWriteRollback(t *testing.T) {
	s, c, cfg, j, h := callbackFixture(t)
	requireBridge(t, h, bridgeRequest(t, cfg, bridgeEvent(c, j, 1), nil), 202)
	before, err := s.Lookup(context.Background(), j.Tenant, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	var clockBefore int64
	if err = s.db.QueryRow("SELECT latest FROM cape_event_clock WHERE id=1").Scan(&clockBefore); err != nil {
		t.Fatal(err)
	}
	var storeClockBefore int64
	if err = s.db.QueryRow("SELECT latest FROM clock WHERE id=1").Scan(&storeClockBefore); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Second)
	if _, err = s.db.Exec(`CREATE TRIGGER fail_wakeup BEFORE UPDATE ON jobs BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	e := bridgeEvent(c, j, 2)
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 503)
	after, err := s.Lookup(context.Background(), j.Tenant, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != before.Version || !after.PollWakeAt.Equal(before.PollWakeAt) || after.State != before.State {
		t.Fatal("late failure mutated job")
	}
	var count int
	if err = s.db.QueryRow("SELECT count(*) FROM cape_events WHERE event=?", e.EventID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("late failure committed replay before wakeup")
	}
	var clockAfter int64
	if err = s.db.QueryRow("SELECT latest FROM cape_event_clock WHERE id=1").Scan(&clockAfter); err != nil {
		t.Fatal(err)
	}
	if clockAfter != clockBefore {
		t.Fatal("late failure advanced callback clock")
	}
	var storeClockAfter int64
	if err = s.db.QueryRow("SELECT latest FROM clock WHERE id=1").Scan(&storeClockAfter); err != nil {
		t.Fatal(err)
	}
	if storeClockAfter != storeClockBefore {
		t.Fatal("late failure advanced store clock")
	}
	if _, err = s.db.Exec("DROP TRIGGER fail_wakeup"); err != nil {
		t.Fatal(err)
	}
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 202)
}

func TestCallbackConcurrentAdmission(t *testing.T) {
	for _, mode := range []string{"duplicate", "rate"} {
		t.Run(mode, func(t *testing.T) {
			s, c, cfg, j, h := callbackFixture(t)
			const requests = 16
			start := make(chan struct{})
			results := make(chan int, requests)
			for i := 1; i <= requests; i++ {
				n := i
				if mode == "duplicate" {
					n = 1
				}
				r := bridgeRequest(t, cfg, bridgeEvent(c, j, n), nil)
				go func() { <-start; results <- bridgeStatus(h, r) }()
			}
			close(start)
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			statuses := map[int]int{}
			for i := 0; i < requests; i++ {
				select {
				case status := <-results:
					statuses[status]++
				case <-timer.C:
					t.Fatal("concurrent callbacks did not finish within bound")
				}
			}
			accepted, rejected := 1, 409
			if mode == "rate" {
				accepted, rejected = 10, 429
			}
			if statuses[202] != accepted || statuses[rejected] != requests-accepted || len(statuses) != 2 {
				t.Fatalf("concurrent %s statuses=%v want accepted=%d rejected=%d", mode, statuses, accepted, requests-accepted)
			}
			var count int
			if err := s.db.QueryRow("SELECT count(*) FROM cape_events").Scan(&count); err != nil {
				t.Fatal(err)
			}
			after, err := s.Lookup(context.Background(), j.Tenant, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			if count != accepted || after.Version != j.Version+int64(accepted) || after.PollWakeAt.IsZero() || after.State != j.State {
				t.Fatal("concurrent callback durable count/version mismatch")
			}
		})
	}
}

func TestCallbackTransactionOverlapAndCloseJoin(t *testing.T) {
	s, c, cfg, j, h := callbackFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.hooks.callbackTx = func() {
		once.Do(func() { close(entered) })
		<-release
	}
	request := bridgeRequest(t, cfg, bridgeEvent(c, j, 1), nil)
	callbackDone := make(chan int, 1)
	go func() { callbackDone <- bridgeStatus(h, request) }()
	schedulerPhase(t, entered, "callback did not enter database transaction")
	lookupDone := make(chan error, 1)
	go func() {
		_, err := s.Lookup(context.Background(), j.Tenant, j.ID)
		lookupDone <- err
	}()
	select {
	case err := <-lookupDone:
		if err != nil {
			t.Fatal("concurrent lookup failed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked callback monopolized the database pool")
	}
	closeWaiting := make(chan struct{})
	writersJoined := make(chan struct{})
	s.hooks.beforeWriterWait = func() { close(closeWaiting) }
	s.hooks.afterWriterWait = func() { close(writersJoined) }
	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Close() }()
	schedulerPhase(t, closeWaiting, "Close did not reach callback writer join")
	select {
	case <-writersJoined:
		t.Fatal("Close joined writers before callback completed")
	default:
	}
	unblock()
	if status := <-callbackDone; status != http.StatusAccepted {
		t.Fatalf("callback status=%d want accepted", status)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-writersJoined:
	default:
		t.Fatal("Close returned without completing writer join")
	}
}

func TestCallbackNotBefore(t *testing.T) {
	s, c, cfg, j, _ := callbackFixture(t)
	cfg.Keys[0].NotBefore = c.Now().Add(time.Nanosecond)
	h, err := NewCallbackHandler(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := bridgeEvent(c, j, 1)
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 401)
	var count int
	if err = s.db.QueryRow("SELECT (SELECT count(*) FROM cape_events)+(SELECT count(*) FROM cape_event_clock)").Scan(&count); err != nil {
		t.Fatal(err)
	}
	after, err := s.Lookup(context.Background(), j.Tenant, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || after.Version != j.Version || !after.PollWakeAt.IsZero() {
		t.Fatal("not-yet-valid key persisted callback effects")
	}
	c.advance(time.Nanosecond)
	requireBridge(t, h, bridgeRequest(t, cfg, e, nil), 202)
}

func TestCallbackRepeatedEncodingTLS(t *testing.T) {
	s, c, cfg, j, h := callbackFixture(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	client.Timeout = 3 * time.Second
	e := bridgeEvent(c, j, 1)
	for _, encoded := range []bool{true, false} {
		r := bridgeRequest(t, cfg, e, nil)
		r.RequestURI = ""
		r.URL.Scheme = "https"
		r.URL.Host = strings.TrimPrefix(server.URL, "https://")
		r.TLS = nil
		if encoded {
			r.Header.Add("Content-Encoding", "")
			r.Header.Add("Content-Encoding", "gzip")
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := 202
		if encoded {
			want = 400
		}
		if response.StatusCode != want {
			t.Fatalf("TLS encoding status=%d want=%d", response.StatusCode, want)
		}
		if encoded {
			var count int
			if err = s.db.QueryRow("SELECT count(*) FROM cape_events").Scan(&count); err != nil {
				t.Fatal(err)
			}
			after, err := s.Lookup(context.Background(), j.Tenant, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			if count != 0 || after.Version != j.Version || !after.PollWakeAt.IsZero() {
				t.Fatal("rejected encoding persisted callback effects")
			}
		}
	}
}

func TestCallbackMediaTypeTokenCaseAndMalformedParameters(t *testing.T) {
	for _, tc := range []struct {
		name, media string
		want        int
	}{
		{"mixed-case", "Application/JSON", 202},
		{"parameter", "application/json; charset=utf-8", 400},
		{"malformed", "application/json; charset", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c, cfg, j, h := callbackFixture(t)
			r := bridgeRequest(t, cfg, bridgeEvent(c, j, 1), nil)
			r.Header.Set("Content-Type", tc.media)
			requireBridge(t, h, r, tc.want)
		})
	}
}
