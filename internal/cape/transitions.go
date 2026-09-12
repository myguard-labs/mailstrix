package cape

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Evidence is sandbox evidence only, never a replacement for the static verdict.
type Evidence string

const (
	// EvidenceMalicious indicates a normalized malicious sandbox outcome.
	EvidenceMalicious Evidence = "malicious"
	// EvidenceSuspicious indicates a normalized suspicious sandbox outcome.
	EvidenceSuspicious Evidence = "suspicious"
	// EvidenceNoSignal indicates that no configured sandbox signal matched.
	EvidenceNoSignal Evidence = "no_signal"
)

// NormalizedResult contains bounded local policy identifiers, never report text.
// Version is the normalization schema; Policy must equal the admitted policy.
type NormalizedResult struct {
	Version  int      `json:"version"`
	Policy   string   `json:"policy"`
	Evidence Evidence `json:"evidence"`
	Signals  []string `json:"signals,omitempty"`
}

// ResultMapper is trusted, administrator-selected code. Implementations validate
// every consumed field and return only configured local signal identifiers.
// No default mapper exists: absence or invalid output fails unavailable.
type ResultMapper interface {
	Normalize(context.Context, *Report, string) (NormalizedResult, error)
}

func normalizedBytes(result NormalizedResult, policy string) ([]byte, error) {
	if result.Version != 1 || result.Policy != policy || !identifier(policy, 128) || len(result.Signals) > 128 {
		return nil, &Error{Code: Protocol}
	}
	switch result.Evidence {
	case EvidenceMalicious, EvidenceSuspicious:
		if len(result.Signals) == 0 {
			return nil, &Error{Code: Protocol}
		}
	case EvidenceNoSignal:
		if len(result.Signals) != 0 {
			return nil, &Error{Code: Protocol}
		}
	default:
		return nil, &Error{Code: Protocol}
	}
	seen := make(map[string]bool, len(result.Signals))
	for _, signal := range result.Signals {
		if !identifier(signal, 128) || seen[signal] {
			return nil, &Error{Code: Protocol}
		}
		seen[signal] = true
	}
	b, err := json.Marshal(result)
	if err != nil || len(b) > JobResultLimit {
		return nil, &Error{Code: TooLarge}
	}
	return b, nil
}

// RecordStatus checks the exact snapshot before accepting an authoritative poll.
// Only reported permits fetching. Other active statuses retain their state;
// completed is not report availability. Callers persist retry timing separately.
func (s *Store) RecordStatus(ctx context.Context, tenant, id string, version int64, task TaskRef, status Status) (Job, error) {
	return s.transitionReport(ctx, tenant, id, version, task, RemotePending, func(j *Job, now time.Time) error {
		switch status {
		case "reported":
			j.State = Fetching
		case "pending", "running", "distributed", "completed", "recovered", "distributed_completed":
		case "banned", "failed_analysis", "failed_processing", "failed_reporting":
			terminate(j, Failed, Remote, now)
		default:
			return &Error{Code: Protocol}
		}
		return nil
	})
}

// CompleteReport validates identity before invoking trusted normalization, then
// checks state/version again under the transaction. Cancellation, expiry and
// concurrent callbacks cannot be overwritten by a late mapper result. Missing
// or invalid mapping creates Failed/unavailable with cleanup debt, never clean.
// An error after commit may be a checkpoint error: reconcile with Lookup.
func (s *Store) CompleteReport(ctx context.Context, tenant, id string, version int64, task TaskRef, report *Report, mapper ResultMapper) (Job, error) {
	j, err := s.Lookup(ctx, tenant, id)
	if err != nil {
		return Job{}, err
	}
	if j.State != Fetching || j.Version != version || j.Suppressed || !singleOwnedTask(j, task) {
		return Job{}, ErrConflict
	}
	var result []byte
	outcome := Protocol
	if reportIdentity(report, task, j.Digest) && mapper != nil {
		normalized, mappingErr := mapper.Normalize(ctx, report, j.ResultPolicy)
		if mappingErr == nil && reportIdentity(report, task, j.Digest) {
			result, err = normalizedBytes(normalized, j.ResultPolicy)
			if err == nil {
				outcome = ""
			}
		}
	}
	return s.transitionReport(ctx, tenant, id, version, task, Fetching, func(j *Job, now time.Time) error {
		if outcome != "" {
			terminate(j, Failed, outcome, now)
		} else {
			terminate(j, Completed, "", now)
			j.Result = result
		}
		return nil
	})
}

// recordReportError retains unavailable evidence while safe report retries continue.
func (s *Store) recordReportError(ctx context.Context, tenant, id string, version int64, task TaskRef, code Code) (Job, error) {
	if code == "" || !safeOutcome(code) {
		code = Transport
	}
	return s.transitionReport(ctx, tenant, id, version, task, Fetching, func(j *Job, _ time.Time) error {
		j.Reason = code
		return nil
	})
}

func singleOwnedTask(j Job, task TaskRef) bool {
	return len(j.TaskIDs) == 1 && j.TaskIDs[0] == task.ID && j.Generation == task.Generation && !j.UnknownDebt
}

func reportIdentity(r *Report, task TaskRef, digest string) bool {
	if r == nil || r.task != task || hex.EncodeToString(r.digest[:]) != digest {
		return false
	}
	info, _ := r.document["info"].(map[string]any)
	target, _ := r.document["target"].(map[string]any)
	file, _ := target["file"].(map[string]any)
	id, ok := taskID(info["id"])
	return ok && id == task.ID && info["category"] == "file" && target["category"] == "file" && file["sha256"] == digest
}

func (s *Store) transitionReport(ctx context.Context, tenant, id string, version int64, task TaskRef, expected JobState, change func(*Job, time.Time) error) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Job{}, &Error{Code: Closed}
	}
	var j Job
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		j, err = readJob(tx.QueryRow("SELECT document FROM jobs WHERE id=? AND tenant=?", id, tenant))
		if err != nil {
			return err
		}
		if j.Version != version || j.State != expected || j.Suppressed || !singleOwnedTask(j, task) {
			return ErrConflict
		}
		now, err := s.now(tx)
		if err != nil {
			return err
		}
		if !now.Before(j.AnalysisDeadline) {
			return &Error{Code: Deadline}
		}
		previousJob := j
		if err := change(&j, now); err != nil {
			return err
		}
		j.PollWakeAt = time.Time{}
		j.Version++
		return putJob(tx, j, previousJob)
	})
	if err == nil {
		err = s.checkpoint(ctx)
	}
	return j, err
}
