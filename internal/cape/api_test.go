//go:build linux

package cape

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func apiFixture(t *testing.T, s *Store) APIConfig {
	t.Helper()
	return APIConfig{Enabled: true, Store: s,
		Authenticate: func(r *http.Request) (string, error) {
			switch r.Header.Get("Authorization") {
			case "Bearer fixture-alpha":
				return "alpha", nil
			case "Bearer fixture-beta":
				return "beta", nil
			}
			return "", errors.New("denied")
		},
		Profile: func(_ context.Context, tenant, name string) (APIProfile, error) {
			if name != "private" || tenant != "alpha" && tenant != "beta" {
				return APIProfile{}, errors.New("denied")
			}
			return APIProfile{Generation: "g1", SubmissionPolicy: "s1", ResultPolicy: "r1", AllowUnknown: true, AllowSuspicious: true}, nil
		},
		StaticScan: func(_ context.Context, _ string, r io.Reader) (string, error) {
			_, err := io.ReadAll(r)
			return "unknown", err
		},
	}
}
func apiRequest(h http.Handler, method, path, tenant, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer fixture-"+tenant)
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-Mailstrix-CAPE-Profile", "private")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAPIAdmissionAndTenant(t *testing.T) {
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	h, err := NewAPIHandler(apiFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	w := apiRequest(h, "POST", JobsPath, "alpha", "attachment")
	if w.Code != 202 || w.Header().Get("Location") == "" {
		t.Fatalf("durable admission missing: %d %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if got := apiRequest(h, "POST", JobsPath, "alpha", "attachment"); got.Code != 202 || got.Header().Get("Location") != location {
		t.Fatal("same-tenant dedup failed")
	}
	if got := apiRequest(h, "POST", JobsPath, "beta", "attachment"); got.Code != 202 || got.Header().Get("Location") == location {
		t.Fatal("cross-tenant dedup")
	}
	wrong := apiRequest(h, "GET", location, "beta", "")
	absent := apiRequest(h, "GET", JobsPath+"/"+strings.Repeat("0", 32), "beta", "")
	if wrong.Code != 404 || wrong.Body.String() != absent.Body.String() {
		t.Fatalf("tenant lookup exposed job: %d %s", wrong.Code, wrong.Body.String())
	}
	w = apiRequest(h, "GET", location, "alpha", "")
	var view APIJob
	if json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Evidence != "pending" || view.StaticVerdict != "unknown" {
		t.Fatalf("pending missing: %s", w.Body.String())
	}
	for _, secret := range []string{"digest", "task_ids", "correlation", "generation", "submission_policy", "result_policy", "tenant"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("private field exposed: %s", secret)
		}
	}
	for i := 0; i < 2; i++ {
		w = apiRequest(h, "DELETE", location, "alpha", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"evidence":"unavailable"`) {
			t.Fatal("cancel not idempotent/unavailable", w.Code, w.Body.String())
		}
	}
}

func TestAPIResultsAndCancellation(t *testing.T) {
	clock := newStoreClock()
	s := testStore(t, storeConfig(t.TempDir()), clock)
	j := enqueueBytes(t, s, "alpha", "done").Job
	err := s.transaction(context.Background(), func(tx *sql.Tx) error {
		previousJob := j
		j.State = Completed
		j.TerminalAt = clock.Now()
		j.Result = []byte(`{"version":1,"policy":"r1","evidence":"malicious","signals":["local_bad"]}`)
		j.Version++
		return putJob(tx, j, previousJob)
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewAPIHandler(apiFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	path := JobsPath + "/" + j.ID
	w := apiRequest(h, "POST", JobsPath, "alpha", "done")
	if w.Code != 200 {
		t.Fatalf("completed reuse not 200: %d %s", w.Code, w.Body.String())
	}
	w = apiRequest(h, "GET", path, "alpha", "")
	if !strings.Contains(w.Body.String(), `"evidence":"malicious"`) {
		t.Fatal("normalized result missing", w.Body.String())
	}
	clock.advance(24 * time.Hour)
	w = apiRequest(h, "GET", path, "alpha", "")
	if strings.Contains(w.Body.String(), "local_bad") || !strings.Contains(w.Body.String(), `"evidence":"unavailable"`) {
		t.Fatal("expired result leaked", w.Body.String())
	}
	w = apiRequest(h, "DELETE", path, "alpha", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "local_bad") {
		t.Fatal("cancel retained result")
	}
	stored, err := s.Lookup(context.Background(), "alpha", j.ID)
	if err != nil || !stored.TerminalAt.Equal(j.TerminalAt) || len(stored.Result) != 0 {
		t.Fatal("cancel moved retention or retained result", err)
	}
}

func TestAPIRejections(t *testing.T) {
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	base := apiFixture(t, s)
	for _, tc := range []struct {
		name   string
		mutate func(*APIConfig)
		body   string
		want   int
	}{
		{"disabled", func(c *APIConfig) { c.Enabled = false }, "x", 503},
		{"auth", func(c *APIConfig) {
			c.Authenticate = func(*http.Request) (string, error) { return "", errors.New("denied") }
		}, "x", 401},
		{"profile", func(c *APIConfig) {
			c.Profile = func(context.Context, string, string) (APIProfile, error) {
				return APIProfile{}, errors.New("private error")
			}
		}, "x", 400},
		{"clean", func(c *APIConfig) {
			c.StaticScan = func(context.Context, string, io.Reader) (string, error) { return "clean", nil }
		}, "x", 400},
		{"scan-error", func(c *APIConfig) {
			c.StaticScan = func(context.Context, string, io.Reader) (string, error) { return "", errors.New("private error") }
		}, "x", 503},
		{"oversize", func(*APIConfig) {}, strings.Repeat("x", 33), 413},
		{"empty", func(*APIConfig) {}, "", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			h, e := NewAPIHandler(cfg)
			if e != nil {
				t.Fatal(e)
			}
			w := apiRequest(h, "POST", JobsPath, "alpha", tc.body)
			if w.Code != tc.want || strings.Contains(w.Body.String(), "private error") {
				t.Fatalf("rejection=%d %s", w.Code, w.Body.String())
			}
			if n, _ := storeCount(t, s); n != 0 {
				t.Fatal("rejected job queued")
			}
		})
	}
	if _, err := NewAPIHandler(APIConfig{Enabled: true}); err == nil {
		t.Fatal("missing wiring accepted")
	}
	h, err := NewAPIHandler(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ header, value string }{{"Content-Type", "multipart/form-data"}, {"Content-Encoding", "gzip"}, {"X-Mailstrix-CAPE-Profile", ""}} {
		r := httptest.NewRequest("POST", JobsPath, strings.NewReader("x"))
		r.Header.Set("Authorization", "Bearer fixture-alpha")
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("X-Mailstrix-CAPE-Profile", "private")
		r.Header.Set(tc.header, tc.value)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("malformed request accepted", tc.header, w.Code)
		}
	}
	for _, header := range []string{"Content-Type", "X-Mailstrix-CAPE-Profile"} {
		t.Run("duplicate "+header, func(t *testing.T) {
			r := httptest.NewRequest("POST", JobsPath, strings.NewReader("x"))
			r.Header.Set("Authorization", "Bearer fixture-alpha")
			r.Header.Set("Content-Type", "application/octet-stream")
			r.Header.Set("X-Mailstrix-CAPE-Profile", "private")
			r.Header.Add(header, r.Header.Get(header))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("duplicate %s accepted: %d", header, w.Code)
			}
			if n, reserved := storeCount(t, s); n != 0 || reserved != 0 {
				t.Fatalf("duplicate %s admitted work: jobs=%d reserved=%d", header, n, reserved)
			}
		})
	}
}

func TestAPIAdmissionClassPolicy(t *testing.T) {
	for _, tc := range []struct {
		name            string
		static          string
		allowUnknown    bool
		allowSuspicious bool
		want            int
	}{
		{"unknown-disabled", "unknown", false, true, http.StatusBadRequest},
		{"suspicious-disabled", "suspicious", true, false, http.StatusBadRequest},
		{"unknown-enabled", "unknown", true, false, http.StatusAccepted},
		{"suspicious-enabled", "suspicious", false, true, http.StatusAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
			cfg := apiFixture(t, s)
			cfg.Profile = func(context.Context, string, string) (APIProfile, error) {
				return APIProfile{Generation: "g1", SubmissionPolicy: "s1", ResultPolicy: "r1", AllowUnknown: tc.allowUnknown, AllowSuspicious: tc.allowSuspicious}, nil
			}
			scans := 0
			cfg.StaticScan = func(_ context.Context, tenant string, r io.Reader) (string, error) {
				scans++
				body, err := io.ReadAll(r)
				if err != nil || tenant != "alpha" || string(body) != "attachment" {
					t.Fatalf("invalid policy scan fixture: tenant=%q body=%q err=%v", tenant, body, err)
				}
				return tc.static, nil
			}
			h, err := NewAPIHandler(cfg)
			if err != nil {
				t.Fatal(err)
			}
			w := apiRequest(h, "POST", JobsPath, "alpha", "attachment")
			if scans != 1 {
				t.Fatalf("policy admission did not classify: scans=%d", scans)
			}
			if w.Code != tc.want {
				t.Fatalf("class policy admission: static=%s status=%d want=%d body=%s", tc.static, w.Code, tc.want, w.Body.String())
			}
			n, reserved := storeCount(t, s)
			if tc.want == http.StatusBadRequest {
				if n != 0 || reserved != 0 {
					t.Fatalf("rejected class retained job or reservation: jobs=%d reserved=%d", n, reserved)
				}
				if w.Header().Get("Location") != "" {
					t.Fatal("rejected class exposed job location")
				}
				return
			}
			if n != 1 || reserved == 0 {
				t.Fatalf("enabled class missing durable admission: jobs=%d reserved=%d", n, reserved)
			}
			location := w.Header().Get("Location")
			stored, err := s.Lookup(context.Background(), "alpha", strings.TrimPrefix(location, JobsPath+"/"))
			if err != nil || stored.State != Queued || stored.StaticVerdict != tc.static {
				t.Fatalf("enabled class not queued with scan verdict: job=%+v err=%v", stored, err)
			}
		})
	}
}

func TestClassifiedIngressReservationAndSnapshot(t *testing.T) {
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	ctx := context.Background()
	classifier := func(want string) IngressClassifier {
		return func(_ context.Context, r io.Reader) (string, error) {
			n, bytes := storeCount(t, s)
			if n < 1 || bytes < 32+JobMetadataLimit+JobResultLimit {
				t.Fatal("classifier ran without full reservation")
			}
			jobs, err := s.List(ctx, "alpha", Staging, 100)
			if err != nil || len(jobs) != 1 {
				t.Fatal("queued before classification")
			}
			body, err := io.ReadAll(r)
			if err != nil || string(body) != "sample" {
				t.Fatal("classifier bytes differ")
			}
			return want, nil
		}
	}
	a, err := s.EnqueueClassified(ctx, storeRequest("alpha"), io.NopCloser(strings.NewReader("sample")), classifier("unknown"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.EnqueueClassified(ctx, storeRequest("alpha"), io.NopCloser(strings.NewReader("sample")), classifier("suspicious"))
	if err != nil {
		t.Fatal(err)
	}
	if !b.Reused || a.Job.ID != b.Job.ID || b.Job.StaticVerdict != "unknown" || b.CurrentStatic != "suspicious" {
		t.Fatalf("reused job replaced current scan: %+v", b)
	}
}

func TestClassifiedIngressDeadlineAndFailure(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel", "error", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			clock := newStoreClock()
			s := testStore(t, storeConfig(t.TempDir()), clock)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, err := s.EnqueueClassified(ctx, storeRequest("alpha"), io.NopCloser(strings.NewReader("sample")), func(child context.Context, _ io.Reader) (string, error) {
				if mode == "deadline" {
					clock.advance(30 * time.Second)
				}
				if mode == "cancel" {
					cancel()
				}
				if mode == "deadline" || mode == "cancel" {
					select {
					case <-child.Done():
					case <-time.After(time.Second):
						t.Fatal("classifier not cancelled")
					}
				}
				if mode == "error" {
					return "", errors.New("scan failure")
				}
				if mode == "invalid" {
					return "clean-ish", nil
				}
				return "unknown", nil
			})
			if err == nil {
				t.Fatal("failed classification queued")
			}
			if n, _ := storeCount(t, s); n != 0 {
				t.Fatal("classification failure retained staging")
			}
		})
	}
}

func TestClassifiedIngressJoinsBeforeRelease(t *testing.T) {
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := s.EnqueueClassified(ctx, storeRequest("alpha"), io.NopCloser(strings.NewReader("sample")), func(context.Context, io.Reader) (string, error) {
			close(entered)
			<-release // deliberately uncooperative trusted classifier
			return "unknown", nil
		})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("classifier never entered")
	}
	cancel()
	if n, bytes := storeCount(t, s); n != 1 || bytes != 32+JobMetadataLimit+JobResultLimit {
		close(release)
		t.Fatal("released reservation under live classifier")
	}
	select {
	case <-done:
		close(release)
		t.Fatal("admission returned under live classifier")
	default:
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled classifier queued")
		}
	case <-time.After(time.Second):
		t.Fatal("classifier join hung")
	}
	if n, _ := storeCount(t, s); n != 0 {
		t.Fatal("joined classifier retained reservation")
	}
}

type apiUnreadBody struct{ reads int }

func (b *apiUnreadBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*apiUnreadBody) Close() error               { return nil }

func TestAPIQuotaBeforeRead(t *testing.T) {
	cfg := storeConfig(t.TempDir())
	cfg.TenantJobs = 1
	s := testStore(t, cfg, newStoreClock())
	enqueueBytes(t, s, "alpha", "existing")
	c := apiFixture(t, s)
	c.StaticScan = func(context.Context, string, io.Reader) (string, error) {
		t.Fatal("scan before quota")
		return "unknown", nil
	}
	h, err := NewAPIHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", JobsPath, nil)
	body := &apiUnreadBody{}
	r.Body = body
	r.Header.Set("Authorization", "Bearer fixture-alpha")
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-Mailstrix-CAPE-Profile", "private")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 429 || body.reads != 0 {
		t.Fatalf("quota did not precede input: status=%d reads=%d", w.Code, body.reads)
	}
}

func TestAPIUnavailableDedupBarrier(t *testing.T) {
	for _, mode := range []string{"expired", "suppressed", "malformed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			clock := newStoreClock()
			s := testStore(t, storeConfig(t.TempDir()), clock)
			j := enqueueBytes(t, s, "alpha", "done").Job
			err := s.transaction(context.Background(), func(tx *sql.Tx) error {
				previousJob := j
				j.State, j.TerminalAt, j.DedupBarrier = Completed, clock.Now(), true
				j.Cleanup = "remote_delete_acknowledged_unverified"
				j.Result = []byte(`{"version":1,"policy":"r1","evidence":"no_signal"}`)
				if mode == "suppressed" {
					j.Suppressed = true
				}
				if mode == "malformed" {
					j.Result = []byte(`{}`)
				}
				if mode == "cancelled" {
					j.State, j.Suppressed, j.Result = Cancelled, true, nil
				}
				j.Version++
				return putJob(tx, j, previousJob)
			})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "expired" {
				clock.advance(24 * time.Hour)
				if err := s.Maintain(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			h, err := NewAPIHandler(apiFixture(t, s))
			if err != nil {
				t.Fatal(err)
			}
			post := apiRequest(h, "POST", JobsPath, "alpha", "done")
			if post.Code != 409 || !strings.Contains(post.Body.String(), `"error":"unavailable"`) || post.Header().Get("Location") != JobsPath+"/"+j.ID {
				t.Fatalf("unavailable barrier acknowledged as successful work: status=%d body=%s", post.Code, post.Body.String())
			}
			stored, err := s.Lookup(context.Background(), "alpha", j.ID)
			if err != nil || !stored.DedupBarrier {
				t.Fatal("unavailable admission lost barrier", err)
			}
			if n, _ := storeCount(t, s); n != 1 {
				t.Fatal("barrier created duplicate job")
			}
		})
	}
}

func TestAPIPendingDeadlineBoundaries(t *testing.T) {
	for _, state := range []JobState{Staging, Queued, Submitting, SubmitUncertain, RemotePending, Fetching} {
		t.Run(string(state), func(t *testing.T) {
			clock := newStoreClock()
			s := testStore(t, storeConfig(t.TempDir()), clock)
			j := enqueueBytes(t, s, "alpha", "sample").Job
			err := s.transaction(context.Background(), func(tx *sql.Tx) error {
				previousJob := j
				j.State = state
				j.Version++
				return putJob(tx, j, previousJob)
			})
			if err != nil {
				t.Fatal(err)
			}
			deadline := j.AnalysisDeadline
			if state == Staging {
				deadline = j.IngressDeadline
			}
			if state == Queued {
				deadline = j.QueueDeadline
			}
			h, err := NewAPIHandler(apiFixture(t, s))
			if err != nil {
				t.Fatal(err)
			}
			for _, offset := range []time.Duration{-time.Nanosecond, 0} {
				clock.advance(deadline.Add(offset).Sub(clock.Now()))
				response := apiRequest(h, "GET", JobsPath+"/"+j.ID, "alpha", "")
				var view APIJob
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &view) != nil {
					t.Fatal("status lookup failed")
				}
				want := "pending"
				if offset == 0 {
					want = "unavailable"
				}
				if view.Evidence != want {
					t.Fatalf("deadline evidence=%s want=%s", view.Evidence, want)
				}
			}
		})
	}
}

func TestAPIRepeatedContentEncodingTLS(t *testing.T) {
	s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
	h, err := NewAPIHandler(apiFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	for _, tc := range []struct {
		name     string
		encoding []string
		want     int
	}{
		{"repeated", []string{"", "gzip"}, 400},
		{"empty", []string{""}, 400},
		{"unencoded", nil, 202},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest("POST", server.URL+JobsPath, strings.NewReader("attachment"))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Authorization", "Bearer fixture-alpha")
			r.Header.Set("Content-Type", "application/octet-stream")
			r.Header.Set("X-Mailstrix-CAPE-Profile", "private")
			if tc.encoding != nil {
				r.Header["Content-Encoding"] = tc.encoding
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.want {
				t.Fatalf("content encoding %s: status=%d want=%d", tc.name, response.StatusCode, tc.want)
			}
			if tc.want == 400 {
				if n, _ := storeCount(t, s); n != 0 {
					t.Fatal("encoded request admitted")
				}
			}
		})
	}
}

func TestAPIMediaTypeTokenCaseAndMalformedParameters(t *testing.T) {
	for _, tc := range []struct {
		name, media string
		want        int
	}{
		{"mixed-case", "Application/Octet-Stream", 202},
		{"parameter", "application/octet-stream; charset=binary", 400},
		{"malformed", "application/octet-stream; charset", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t, storeConfig(t.TempDir()), newStoreClock())
			h, err := NewAPIHandler(apiFixture(t, s))
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://local.invalid"+JobsPath, strings.NewReader("attachment"))
			r.Header.Set("Authorization", "Bearer fixture-alpha")
			r.Header.Set("Content-Type", tc.media)
			r.Header.Set("X-Mailstrix-CAPE-Profile", "private")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
		})
	}
}
