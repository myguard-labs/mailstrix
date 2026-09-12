//go:build linux

package cape

import (
	"context"
	"database/sql"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func callbackForJob(t *testing.T, s *Store, clock *fakeStoreClock, j Job, taskID int64) (CallbackConfig, http.Handler, callbackEvent) {
	t.Helper()
	cfg := bridgeConfig(clock)
	cfg.Keys[0].Generations = []string{j.Generation}
	h, err := NewCallbackHandler(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	event := bridgeEvent(clock, j, 1)
	event.TaskID = taskID
	return cfg, h, event
}

func TestReportErrorGuards(t *testing.T) {
	for _, mode := range []string{"stale", "task", "generation", "cancel", "expiry", "tenant", "suppressed", "state", "debt"} {
		t.Run(mode, func(t *testing.T) {
			s, clock, j, _, task := fetchingFixture(t)
			version, tenant := j.Version, j.Tenant
			switch mode {
			case "stale":
				version--
			case "task":
				task.ID++
			case "generation":
				task.Generation = "other"
			case "cancel":
				if _, err := s.Cancel(context.Background(), j.Tenant, j.ID); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				clock.advance(24 * time.Hour)
			case "tenant":
				tenant = "other"
			case "suppressed", "state", "debt":
				if err := s.transaction(context.Background(), func(tx *sql.Tx) error {
					previousJob := j
					switch mode {
					case "suppressed":
						j.Suppressed = true
					case "state":
						j.State = RemotePending
					case "debt":
						j.UnknownDebt = true
					}
					return putJob(tx, j, previousJob)
				}); err != nil {
					t.Fatal(err)
				}
			}
			before := schedulerLookup(t, s, j)
			if _, err := s.recordReportError(context.Background(), tenant, j.ID, version, task, Protocol); err == nil {
				t.Fatal("invalid report-error snapshot accepted")
			}
			if after := schedulerLookup(t, s, j); !reflect.DeepEqual(before, after) {
				t.Fatal("rejected report-error changed durable job")
			}
		})
	}
}

func TestReportErrorOnlyChangesEvidence(t *testing.T) {
	s, clock, j, _, task := fetchingFixture(t)
	cfg, h, event := callbackForJob(t, s, clock, j, task.ID)
	requireBridge(t, h, bridgeRequest(t, cfg, event, nil), 202)
	j = schedulerLookup(t, s, j)
	if j.PollWakeAt.IsZero() {
		t.Fatal("callback did not create report wake hint")
	}
	got, err := s.recordReportError(context.Background(), j.Tenant, j.ID, j.Version, task, Code("untrusted remote text"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Reason != Transport || got.Version != j.Version+1 {
		t.Fatal("report error not sanitized or versioned")
	}
	if !got.PollWakeAt.IsZero() {
		t.Fatal("report error did not consume wake hint")
	}
	got.Reason, got.Version, got.PollWakeAt = j.Reason, j.Version, j.PollWakeAt
	if !reflect.DeepEqual(got, j) {
		t.Fatal("report error changed unrelated job fields")
	}
}

func TestReportErrorPersistenceAndRecovery(t *testing.T) {
	s, clock, j, report, task := fetchingFixture(t)
	ctx := context.Background()
	q := &Scheduler{store: s}
	if err := q.persist(ctx, schedulerResult{job: j, task: task, kind: "report", err: &Error{Code: Throttled, RetryAfter: time.Hour}}); err != nil {
		t.Fatal(err)
	}
	got := schedulerLookup(t, s, j)
	if got.Reason != Throttled || got.State != Fetching || publicJob(got, clock.Now()).Evidence != "unavailable" {
		t.Fatal("failed report did not persist unavailable evidence")
	}
	if !got.NextAttempt.Equal(clock.Now().Add(5 * time.Minute)) {
		t.Fatal("report evidence skipped bounded Retry-After")
	}
	if got.StaticVerdict != j.StaticVerdict || got.AnalysisDeadline != j.AnalysisDeadline {
		t.Fatal("report error changed static verdict or deadline")
	}
	// A subsequent outcome uses the fresh version, even with the old dispatched snapshot.
	if err := q.persist(ctx, schedulerResult{job: j, task: task, kind: "report", err: &Error{Code: Protocol}}); err != nil {
		t.Fatal(err)
	}
	got = schedulerLookup(t, s, j)
	if got.Reason != Protocol {
		t.Fatal("fresh version did not retain failed retry evidence")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = testStore(t, s.cfg, clock)
	q.store = s
	got = schedulerLookup(t, s, j)
	if got.Reason != Protocol || publicJob(got, clock.Now()).Evidence != "unavailable" {
		t.Fatal("restart lost unavailable evidence")
	}
	cfg, h, event := callbackForJob(t, s, clock, j, task.ID)
	requireBridge(t, h, bridgeRequest(t, cfg, event, nil), 202)
	afterCallback := schedulerLookup(t, s, j)
	if afterCallback.Reason != Protocol || afterCallback.Version != got.Version+1 || !afterCallback.NextAttempt.Equal(got.NextAttempt) || publicJob(afterCallback, clock.Now()).Evidence != "unavailable" {
		t.Fatal("callback erased failed report evidence or moved retry clock")
	}
	mapper := mapperFunc(func(_ context.Context, _ *Report, p string) (NormalizedResult, error) {
		return NormalizedResult{Version: 1, Policy: p, Evidence: EvidenceNoSignal}, nil
	})
	q.mapper = mapper
	if err := q.persist(ctx, schedulerResult{job: j, task: task, kind: "report", report: report}); err != nil {
		t.Fatal(err)
	}
	got = schedulerLookup(t, s, j)
	if got.State != Completed || got.Reason != "" || publicJob(got, clock.Now()).Evidence != "no_signal" {
		t.Fatal("valid retry failed to replace unavailable evidence")
	}
}
