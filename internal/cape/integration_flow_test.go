//go:build linux

package cape

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const flowAttachment = "synthetic\x00attachment\xff"

type capeFlow struct {
	t                                        *testing.T
	clock                                    *fakeStoreClock
	store                                    *Store
	client                                   *Client
	api                                      *APIHandler
	queue                                    *Scheduler
	posts, statuses, reports, deletes, scans atomic.Int32
	// Set before dispatch; never changed while a request is live.
	submit func(http.ResponseWriter, *http.Request, int32)
	status func(http.ResponseWriter, *http.Request)
}

func newCapeFlow(t *testing.T) *capeFlow {
	t.Helper()
	f := &capeFlow{t: t, clock: newStoreClock()}
	taskRoute := func(w http.ResponseWriter, r *http.Request, format string) (int, bool) {
		var id int
		_, err := fmt.Sscanf(r.URL.Path, format, &id)
		if r.Method != http.MethodGet || err != nil || id <= 0 || r.URL.Path != fmt.Sprintf(format, id) {
			t.Errorf("unexpected remote request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return 0, false
		}
		return id, true
	}
	f.client, _ = fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/apiv2/tasks/create/file/":
			n := f.posts.Add(1)
			if r.Method != http.MethodPost {
				t.Error("submission method is not POST")
			}
			mr, err := r.MultipartReader()
			if err != nil {
				t.Error(err)
				return
			}
			files := 0
			for {
				part, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Error(err)
					return
				}
				data, err := io.ReadAll(part)
				if err != nil {
					t.Error(err)
					return
				}
				if part.FormName() == "file" {
					files++
					if string(data) != flowAttachment {
						t.Error("remote bytes differ from staged attachment")
					}
				}
			}
			if files != 1 {
				t.Errorf("submitted files=%d, want 1", files)
			}
			if f.submit != nil {
				f.submit(w, r, n)
				return
			}
			fmt.Fprintf(w, `{"error":[],"errors":[],"data":{"task_ids":[%d]}}`, 40+n)
		case strings.HasPrefix(r.URL.Path, "/apiv2/tasks/status/"):
			if _, ok := taskRoute(w, r, "/apiv2/tasks/status/%d/"); !ok {
				return
			}
			f.statuses.Add(1)
			if f.status != nil {
				f.status(w, r)
				return
			}
			fmt.Fprint(w, `{"error":false,"data":"reported"}`)
		case strings.HasPrefix(r.URL.Path, "/apiv2/tasks/get/report/"):
			id, ok := taskRoute(w, r, "/apiv2/tasks/get/report/%d/json/")
			if !ok {
				return
			}
			f.reports.Add(1)
			digest := sha256.Sum256([]byte(flowAttachment))
			fmt.Fprintf(w, `{"info":{"id":%d,"category":"file"},"target":{"category":"file","file":{"sha256":"%x"}},"signatures":[]}`, id, digest)
		case strings.HasPrefix(r.URL.Path, "/apiv2/tasks/delete/"):
			id, ok := taskRoute(w, r, "/apiv2/tasks/delete/%d/")
			if !ok {
				return
			}
			f.deletes.Add(1)
			fmt.Fprintf(w, `{"data":"Task(s) ID(s) %d has been deleted"}`, id)
		default:
			t.Errorf("unexpected remote request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	f.store = testStore(t, storeConfig(t.TempDir()), f.clock)
	f.wire()
	return f
}

func (f *capeFlow) wire() {
	f.t.Helper()
	cfg := apiFixture(f.t, f.store)
	profile := cfg.Profile
	cfg.Profile = func(ctx context.Context, tenant, name string) (APIProfile, error) {
		p, err := profile(ctx, tenant, name)
		p.Generation = f.client.generation
		return p, err
	}
	cfg.StaticScan = func(_ context.Context, _ string, staged io.Reader) (string, error) {
		f.scans.Add(1)
		data, err := io.ReadAll(staged)
		if string(data) != flowAttachment {
			f.t.Error("classifier bytes differ from selected attachment")
		}
		return "suspicious", err
	}
	var err error
	f.api, err = NewAPIHandler(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	mapper, err := NewSignatureMapper("r1", []SignatureRule{{Name: "fixture_bad", Signal: "local_bad", Evidence: EvidenceMalicious}})
	if err != nil {
		f.t.Fatal(err)
	}
	f.queue = testScheduler(f.t, f.store, f.client, mapper, 2)
}

func (f *capeFlow) restart() {
	f.t.Helper()
	cfg := f.store.cfg
	if err := f.store.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.store = testStore(f.t, cfg, f.clock)
	f.wire()
}

func (f *capeFlow) admit(tenant string, want int) string {
	f.t.Helper()
	w := apiRequest(f.api, http.MethodPost, JobsPath, tenant, flowAttachment)
	if w.Code != want {
		f.t.Fatalf("admission status=%d, want %d: %s", w.Code, want, w.Body.String())
	}
	path := w.Header().Get("Location")
	if !strings.HasPrefix(path, JobsPath+"/") {
		f.t.Fatal("admission lost retained job location")
	}
	if j := f.lookup(tenant, path); j.State == Queued {
		data, err := os.ReadFile(filepath.Join(f.store.cfg.Directory, "spool", j.ID+".blob"))
		if err != nil || string(data) != flowAttachment {
			f.t.Fatalf("queued payload missing or differs from admitted bytes: %v", err)
		}
	}
	return path
}

func (f *capeFlow) lookup(tenant, path string) Job {
	f.t.Helper()
	j, err := f.store.Lookup(context.Background(), tenant, strings.TrimPrefix(path, JobsPath+"/"))
	if err != nil {
		f.t.Fatal(err)
	}
	return j
}

func (f *capeFlow) view(tenant, path string, state JobState, evidence, static string) APIJob {
	f.t.Helper()
	w := apiRequest(f.api, http.MethodGet, path, tenant, "")
	var v APIJob
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		f.t.Fatalf("GET=%d %s", w.Code, w.Body.String())
	}
	if v.State != state || v.Evidence != evidence || v.StaticVerdict != static {
		f.t.Fatalf("public state/evidence/static=%s/%s/%s, want %s/%s/%s", v.State, v.Evidence, v.StaticVerdict, state, evidence, static)
	}
	return v
}

func (f *capeFlow) counts(posts, statuses, reports, deletes int32) {
	f.t.Helper()
	got := [4]int32{f.posts.Load(), f.statuses.Load(), f.reports.Load(), f.deletes.Load()}
	want := [4]int32{posts, statuses, reports, deletes}
	if got != want {
		f.t.Fatalf("POST/status/report/delete=%v, want %v", got, want)
	}
}

func (f *capeFlow) noPayload(path string) {
	f.t.Helper()
	id := strings.TrimPrefix(path, JobsPath+"/")
	_, err := os.Stat(filepath.Join(f.store.cfg.Directory, "spool", id+".blob"))
	if !os.IsNotExist(err) {
		f.t.Fatalf("payload retained or inaccessible: %v", err)
	}
}

func (f *capeFlow) maintain() {
	f.t.Helper()
	if err := f.store.Maintain(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *capeFlow) complete(path string) APIJob {
	f.t.Helper()
	schedulerRound(f.t, f.queue)
	f.view("alpha", path, RemotePending, "pending", "suspicious")
	f.noPayload(path)
	schedulerRound(f.t, f.queue)
	f.view("alpha", path, Fetching, "pending", "suspicious")
	f.clock.advance(5 * time.Minute)
	schedulerRound(f.t, f.queue)
	return f.view("alpha", path, Completed, "no_signal", "suspicious")
}

func TestIntegrationDuplicateTenants(t *testing.T) {
	f := newCapeFlow(t)
	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	for i := 0; i < 2; i++ {
		go func() { <-start; responses <- apiRequest(f.api, "POST", JobsPath, "alpha", flowAttachment) }()
	}
	close(start)
	var path string
	for i := 0; i < 2; i++ {
		select {
		case w := <-responses:
			if w.Code != 202 {
				t.Fatalf("concurrent admission=%d %s", w.Code, w.Body.String())
			}
			if i == 0 {
				path = w.Header().Get("Location")
			} else if w.Header().Get("Location") != path {
				t.Fatal("same tenant created duplicate jobs")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent admission did not finish")
		}
	}
	beta := f.admit("beta", 202)
	if beta == path {
		t.Fatal("cross-tenant attachment reused alpha identity")
	}
	wrong := apiRequest(f.api, "GET", path, "beta", "")
	absent := apiRequest(f.api, "GET", JobsPath+"/"+strings.Repeat("0", 32), "beta", "")
	if wrong.Code != 404 || wrong.Body.String() != absent.Body.String() {
		t.Fatal("cross-tenant lookup exposed attachment job")
	}
	if n, _ := storeCount(t, f.store); n != 2 {
		t.Fatalf("dedup retained %d jobs, want 2", n)
	}
	if f.scans.Load() != 3 {
		t.Fatalf("staged classifications=%d, want 3", f.scans.Load())
	}
	f.counts(0, 0, 0, 0)
	schedulerRound(t, f.queue)
	f.view("alpha", path, RemotePending, "pending", "suspicious")
	f.view("beta", beta, RemotePending, "pending", "suspicious")
	if f.admit("alpha", 202) != path {
		t.Fatal("remote pending dedup lost alpha identity")
	}
	f.counts(2, 0, 0, 0)
	schedulerRound(t, f.queue)
	f.clock.advance(5 * time.Minute)
	schedulerRound(t, f.queue)
	f.view("alpha", path, Completed, "no_signal", "suspicious")
	f.view("beta", beta, Completed, "no_signal", "suspicious")
	if f.admit("alpha", 200) != path {
		t.Fatal("successful result reuse changed identity")
	}
	f.counts(2, 2, 2, 0)
}

func TestIntegrationRestartAfterPOST(t *testing.T) {
	f := newCapeFlow(t)
	path := f.admit("alpha", 202)
	live, results := schedulerDispatch(f.queue)
	schedulerHarvest(t, f.queue, live, results)
	if len(f.queue.pending) != 1 || len(f.queue.pending[0].submission.Tasks) != 1 {
		t.Fatal("real POST response not received before crash boundary")
	}
	f.counts(1, 0, 0, 0)
	f.view("alpha", path, Submitting, "pending", "suspicious")
	// Drop the received response before the durable task-ID commit, as a crash
	// would. Reopening the real database must never reclaim this as queued.
	f.restart()
	f.clock.advance(5 * time.Minute)
	schedulerRound(t, f.queue)
	f.counts(1, 0, 0, 0)
	f.view("alpha", path, SubmitUncertain, "pending", "suspicious")
	j := f.lookup("alpha", path)
	if !j.UnknownDebt || !j.DedupBarrier || len(j.TaskIDs) != 0 {
		t.Fatal("restart lost unknown remote debt")
	}
	if f.admit("alpha", 202) != path {
		t.Fatal("uncertain restart lost dedup barrier")
	}
	f.clock.advance(24 * time.Hour)
	f.maintain()
	f.view("alpha", path, Expired, "unavailable", "suspicious")
	f.noPayload(path)
	if f.admit("alpha", 409) != path {
		t.Fatal("expired uncertainty allowed resubmission")
	}
	schedulerRound(t, f.queue)
	f.counts(1, 0, 0, 0)
}

func TestIntegrationUncertainSubmission(t *testing.T) {
	for _, mode := range []string{"truncated_response", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := newCapeFlow(t)
			received := make(chan struct{}, 4)
			release := make(chan struct{})
			defer close(release)
			if mode == "timeout" {
				f.client.http.Timeout = time.Second
			}
			f.submit = func(w http.ResponseWriter, r *http.Request, _ int32) {
				select {
				case received <- struct{}{}:
				default:
				}
				if mode == "timeout" {
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
				w.Header().Set("Content-Length", "100")
				fmt.Fprint(w, `{"data":`)
			}
			path := f.admit("alpha", 202)
			schedulerRound(t, f.queue)
			select {
			case <-received:
			default:
				t.Fatal("submission failed before selected bytes reached TLS server")
			}
			f.view("alpha", path, SubmitUncertain, "pending", "suspicious")
			j := f.lookup("alpha", path)
			if !j.UnknownDebt || !j.DedupBarrier || !j.SubmissionRecorded {
				t.Fatal("uncertain response lost durable submission debt")
			}
			f.restart()
			f.clock.advance(5 * time.Minute)
			schedulerRound(t, f.queue)
			if f.admit("alpha", 202) != path {
				t.Fatal("uncertain response lost dedup barrier")
			}
			f.view("alpha", path, SubmitUncertain, "pending", "suspicious")
			f.counts(1, 0, 0, 0)
		})
	}
}

func TestIntegrationStatusOutage(t *testing.T) {
	f := newCapeFlow(t)
	f.status = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }
	path := f.admit("alpha", 202)
	schedulerRound(t, f.queue)
	original := f.lookup("alpha", path)
	schedulerRound(t, f.queue)
	f.view("alpha", path, RemotePending, "pending", "suspicious")
	f.clock.advance(5 * time.Minute)
	schedulerRound(t, f.queue)
	if !f.lookup("alpha", path).AnalysisDeadline.Equal(original.AnalysisDeadline) {
		t.Fatal("outage extended analysis deadline")
	}
	f.clock.advance(original.AnalysisDeadline.Sub(f.clock.Now()))
	f.view("alpha", path, RemotePending, "unavailable", "suspicious")
	f.maintain()
	f.view("alpha", path, Expired, "unavailable", "suspicious")
	f.noPayload(path)
	j := f.lookup("alpha", path)
	if len(j.TaskIDs) != 1 || !j.DedupBarrier || j.Cleanup != "remote_delete_pending" {
		t.Fatal("outage expiry lost owned cleanup debt")
	}
	if f.admit("alpha", 409) != path {
		t.Fatal("outage expiry lost retained barrier")
	}
	f.counts(1, 2, 0, 0)
}

func TestIntegrationCallbackReplay(t *testing.T) {
	f := newCapeFlow(t)
	path := f.admit("alpha", 202)
	schedulerRound(t, f.queue)
	j := f.lookup("alpha", path)
	cfg, h, event := callbackForJob(t, f.store, f.clock, j, j.TaskIDs[0])
	requireBridge(t, h, bridgeRequest(t, cfg, event, nil), 202)
	first := f.lookup("alpha", path)
	if first.PollWakeAt.IsZero() || first.State != RemotePending || len(first.Result) != 0 {
		t.Fatal("callback failed wake-only contract")
	}
	f.view("alpha", path, RemotePending, "pending", "suspicious")
	f.counts(1, 0, 0, 0)
	requireBridge(t, h, bridgeRequest(t, cfg, event, nil), 409)
	f.restart()
	cfg, h, event = callbackForJob(t, f.store, f.clock, j, j.TaskIDs[0])
	requireBridge(t, h, bridgeRequest(t, cfg, event, nil), 409)
	if !reflect.DeepEqual(first, f.lookup("alpha", path)) {
		t.Fatal("replay/restart changed durable job")
	}
	schedulerRound(t, f.queue)
	f.view("alpha", path, Fetching, "pending", "suspicious")
	f.clock.advance(5 * time.Minute)
	schedulerRound(t, f.queue)
	f.view("alpha", path, Completed, "no_signal", "suspicious")
	before := f.lookup("alpha", path)
	event.EventID = fmt.Sprintf("%032x", 2)
	event.Timestamp = f.clock.Now().Unix()
	requireBridge(t, h, bridgeRequest(t, cfg, event, nil), 202)
	if !reflect.DeepEqual(before, f.lookup("alpha", path)) {
		t.Fatal("terminal callback changed completed job")
	}
	f.counts(1, 1, 1, 0)
}

func TestIntegrationResultExpiry(t *testing.T) {
	f := newCapeFlow(t)
	path := f.admit("alpha", 202)
	done := f.complete(path)
	f.clock.advance(5 * time.Minute)
	schedulerRound(t, f.queue)
	j := f.lookup("alpha", path)
	if j.Cleanup != string(DeleteAcknowledgedUnverified) || !j.DedupBarrier {
		t.Fatal("native deletion acknowledgement falsely proved purge")
	}
	f.clock.advance(done.TerminalAt.Add(24*time.Hour - time.Nanosecond).Sub(f.clock.Now()))
	f.view("alpha", path, Completed, "no_signal", "suspicious")
	if f.admit("alpha", 200) != path {
		t.Fatal("unexpired result not reusable")
	}
	f.clock.advance(time.Nanosecond)
	f.view("alpha", path, Completed, "unavailable", "suspicious")
	f.maintain()
	f.view("alpha", path, Completed, "unavailable", "")
	j = f.lookup("alpha", path)
	if len(j.Result) != 0 || !j.Suppressed || !j.DedupBarrier || !j.TerminalAt.Equal(done.TerminalAt) || j.Cleanup != string(DeleteAcknowledgedUnverified) {
		t.Fatal("result expiry erased debt or extended first terminal retention")
	}
	f.restart()
	if f.admit("alpha", 409) != path {
		t.Fatal("expired result allowed blind resubmission")
	}
	f.view("alpha", path, Completed, "unavailable", "")
	f.noPayload(path)
	f.counts(1, 1, 1, 1)
}

func TestIntegrationCancellation(t *testing.T) {
	for _, mode := range []string{"queued", "in_flight", "completed"} {
		t.Run(mode, func(t *testing.T) {
			f := newCapeFlow(t)
			path := f.admit("alpha", 202)
			var firstTerminal time.Time
			var live map[string]schedulerLive
			var results chan schedulerResult
			if mode == "completed" {
				firstTerminal = f.complete(path).TerminalAt
				f.clock.advance(time.Minute)
			}
			if mode == "in_flight" {
				received, release := make(chan struct{}), make(chan struct{})
				defer close(release)
				f.submit = func(w http.ResponseWriter, _ *http.Request, _ int32) {
					close(received)
					<-release
					fmt.Fprint(w, success)
				}
				live, results = schedulerDispatch(f.queue)
				select {
				case <-received:
				case <-time.After(3 * time.Second):
					t.Fatal("upload not received")
				}
				f.view("alpha", path, Submitting, "pending", "suspicious")
				// Release only after local cancellation and public suppression below.
				cancelled := apiRequest(f.api, "DELETE", path, "alpha", "")
				if cancelled.Code != 200 {
					t.Fatalf("cancel=%d", cancelled.Code)
				}
				f.view("alpha", path, Cancelled, "unavailable", "suspicious")
				// An unbuffered send handshakes with the waiting server without sleeps.
				release <- struct{}{}
				schedulerHarvest(t, f.queue, live, results)
				f.queue.persistPending()
				if len(f.queue.pending) != 0 {
					t.Fatal("late upload response did not persist")
				}
			} else {
				if w := apiRequest(f.api, "DELETE", path, "alpha", ""); w.Code != 200 {
					t.Fatalf("cancel=%d", w.Code)
				}
			}
			view := f.view("alpha", path, Cancelled, "unavailable", "suspicious")
			if firstTerminal.IsZero() {
				firstTerminal = view.TerminalAt
			}
			j := f.lookup("alpha", path)
			if len(j.Result) != 0 || !j.Suppressed || !j.TerminalAt.Equal(firstTerminal) {
				t.Fatal("cancellation retained result or moved first terminal time")
			}
			f.noPayload(path)
			f.clock.advance(time.Minute)
			if w := apiRequest(f.api, "DELETE", path, "alpha", ""); w.Code != 200 {
				t.Fatal("repeat cancel rejected")
			}
			if !f.lookup("alpha", path).TerminalAt.Equal(firstTerminal) {
				t.Fatal("repeat cancellation extended retention")
			}
			if mode == "queued" {
				schedulerRound(t, f.queue)
				f.counts(0, 0, 0, 0)
				f.clock.advance(firstTerminal.Add(24*time.Hour - time.Nanosecond).Sub(f.clock.Now()))
				f.maintain()
				f.view("alpha", path, Cancelled, "unavailable", "suspicious")
				f.clock.advance(time.Nanosecond)
				f.maintain()
				if w := apiRequest(f.api, "GET", path, "alpha", ""); w.Code != 404 {
					t.Fatal("ordinary cancelled record survived terminal expiry")
				}
			} else {
				if len(j.TaskIDs) != 1 || j.Cleanup != "remote_delete_pending" || !j.DedupBarrier {
					t.Fatal("cancelled remote task lost cleanup debt")
				}
				f.restart()
				if f.admit("alpha", 409) != path {
					t.Fatal("cancelled remote job allowed resubmission")
				}
				schedulerRound(t, f.queue)
				f.view("alpha", path, Cancelled, "unavailable", "suspicious")
				if f.lookup("alpha", path).Cleanup != string(DeleteAcknowledgedUnverified) {
					t.Fatal("cancel cleanup did not retain unverified debt")
				}
				if mode == "completed" {
					f.counts(1, 1, 1, 1)
				} else {
					f.counts(1, 0, 0, 1)
				}
			}
		})
	}
}
