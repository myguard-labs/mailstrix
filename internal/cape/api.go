package cape

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

// JobsPath is the fixed HTTP path for CAPE job admission and lookup.
const JobsPath = "/v1/cape/jobs"

// APIProfile is trusted tenant-scoped admission policy. Selecting a name does
// not allow the caller to supply generations, verdicts, or upstream options.
type APIProfile struct {
	Generation, SubmissionPolicy, ResultPolicy string
	AllowUnknown, AllowSuspicious              bool
}

// APIConfig is immutable service wiring. Authenticate and Profile must not
// read the body, must honor context cancellation, and must be concurrency-safe.
// StaticScan sees only the selected attachment after durable staging reservation;
// it follows IngressClassifier's ownership and cancellation contract. No default
// tenant, profile, scanner or activation exists. Listener TLS is caller-owned.
type APIConfig struct {
	Enabled      bool
	Store        *Store
	Authenticate func(*http.Request) (string, error)
	Profile      func(context.Context, string, string) (APIProfile, error)
	StaticScan   func(context.Context, string, io.Reader) (string, error)
}

// APIHandler serves the opt-in CAPE job API.
type APIHandler struct{ cfg APIConfig }

// NewAPIHandler validates cfg and returns a CAPE job API handler.
func NewAPIHandler(cfg APIConfig) (*APIHandler, error) {
	if cfg.Enabled && (cfg.Store == nil || cfg.Authenticate == nil || cfg.Profile == nil || cfg.StaticScan == nil) {
		return nil, &Error{Code: Invalid}
	}
	return &APIHandler{cfg: cfg}, nil
}

// ServeHTTP handles CAPE job admission and lookup requests.
func (h *APIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Body != nil {
		defer r.Body.Close()
	}
	if h == nil || !h.cfg.Enabled {
		apiError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	tenant, err := h.cfg.Authenticate(r)
	if err != nil || !identifier(tenant, 128) {
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, http.StatusBadRequest, "invalid")
		return
	}
	if r.URL.Path == JobsPath {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			apiError(w, http.StatusMethodNotAllowed, "method")
			return
		}
		h.submit(w, r, tenant)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, JobsPath+"/")
	if id == r.URL.Path || !opaqueJobID(id) {
		apiError(w, http.StatusNotFound, "not_found")
		return
	}
	var j Job
	switch r.Method {
	case http.MethodGet:
		j, err = h.cfg.Store.Lookup(r.Context(), tenant, id)
	case http.MethodDelete:
		j, err = h.cfg.Store.Cancel(r.Context(), tenant, id)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		apiError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err != nil {
		apiStoreError(w, err)
		return
	}
	view := publicJob(j, h.cfg.Store.hooks.clock.Now())
	if view.Evidence == "pending" {
		w.Header().Set("Retry-After", "5")
	}
	apiJSON(w, http.StatusOK, view)
}

func opaqueJobID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (h *APIHandler) submit(w http.ResponseWriter, r *http.Request, tenant string) {
	contentTypes := r.Header.Values("Content-Type")
	names := r.Header.Values("X-Mailstrix-CAPE-Profile")
	if len(contentTypes) != 1 || len(names) != 1 {
		apiError(w, http.StatusBadRequest, "invalid")
		return
	}
	media, params, err := mime.ParseMediaType(contentTypes[0])
	name := names[0]
	if err != nil || !strings.EqualFold(media, "application/octet-stream") || len(params) != 0 || len(r.Header.Values("Content-Encoding")) != 0 || !identifier(name, 128) {
		apiError(w, http.StatusBadRequest, "invalid")
		return
	}
	profile, err := h.cfg.Profile(r.Context(), tenant, name)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_profile")
		return
	}
	if !identifier(profile.Generation, 128) || !identifier(profile.SubmissionPolicy, 128) || !identifier(profile.ResultPolicy, 128) || (!profile.AllowUnknown && !profile.AllowSuspicious) {
		apiError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	admission, err := h.cfg.Store.EnqueueClassified(r.Context(), EnqueueRequest{Tenant: tenant, Generation: profile.Generation, SubmissionPolicy: profile.SubmissionPolicy, ResultPolicy: profile.ResultPolicy}, r.Body,
		func(ctx context.Context, body io.Reader) (string, error) {
			static, err := h.cfg.StaticScan(ctx, tenant, body)
			if err != nil {
				return "", ErrStoreUnavailable
			}
			if static == "unknown" && profile.AllowUnknown || static == "suspicious" && profile.AllowSuspicious {
				return static, nil
			}
			return "", &Error{Code: Invalid}
		})
	if err != nil {
		apiStoreError(w, err)
		return
	}
	location := JobsPath + "/" + admission.Job.ID
	w.Header().Set("Location", location)
	status := http.StatusAccepted
	if admission.Reused {
		view := publicJob(admission.Job, h.cfg.Store.hooks.clock.Now())
		switch view.Evidence {
		case "malicious", "suspicious", "no_signal":
			status = http.StatusOK
		case "pending":
		default:
			// The retained identity prevents resubmission. Evidence is unavailable,
			// even when safe report retries remain active.
			apiError(w, http.StatusConflict, "unavailable")
			return
		}
	}
	if status == http.StatusAccepted {
		w.Header().Set("Retry-After", "5")
	}
	apiJSON(w, status, struct {
		ID       string `json:"id"`
		Location string `json:"location"`
	}{admission.Job.ID, location})
}

// APIJob deliberately omits task IDs, digest, tenant, correlation, upstream
// profile/generation and raw report. StaticVerdict is the original snapshot
// while retained; cleanup tombstones carry an empty snapshot after retention.
type APIJob struct {
	ID               string    `json:"id"`
	StaticVerdict    string    `json:"static_verdict"`
	State            JobState  `json:"state"`
	Evidence         string    `json:"evidence"`
	Signals          []string  `json:"signals,omitempty"`
	Reason           Code      `json:"reason,omitempty"`
	Cleanup          string    `json:"cleanup"`
	CreatedAt        time.Time `json:"created_at"`
	TerminalAt       time.Time `json:"terminal_at"`
	AnalysisDeadline time.Time `json:"analysis_deadline"`
}

func publicJob(j Job, now time.Time) APIJob {
	v := APIJob{ID: j.ID, StaticVerdict: j.StaticVerdict, State: j.State, Evidence: "unavailable", Reason: j.Reason, Cleanup: j.Cleanup, CreatedAt: j.CreatedAt, TerminalAt: j.TerminalAt, AnalysisDeadline: j.AnalysisDeadline}
	deadline := j.AnalysisDeadline
	switch j.State {
	case Staging:
		if j.IngressDeadline.Before(deadline) {
			deadline = j.IngressDeadline
		}
	case Queued:
		if j.QueueDeadline.Before(deadline) {
			deadline = j.QueueDeadline
		}
	case Submitting, SubmitUncertain, RemotePending, Fetching:
	default:
		deadline = time.Time{}
	}
	if now.Before(deadline) && !(j.State == Fetching && j.Reason != "") {
		v.Evidence = "pending"
	}
	if j.State == Completed && !j.Suppressed && !j.TerminalAt.IsZero() && now.Before(j.TerminalAt.Add(24*time.Hour)) {
		var result NormalizedResult
		if len(j.Result) <= JobResultLimit && json.Unmarshal(j.Result, &result) == nil {
			if _, err := normalizedBytes(result, j.ResultPolicy); err == nil {
				v.Evidence, v.Signals = string(result.Evidence), result.Signals
			}
		}
	}
	return v
}

func apiStoreError(w http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "unavailable"
	var capeErr *Error
	if errors.Is(err, ErrQuota) {
		status, code = http.StatusTooManyRequests, "quota"
	}
	if errors.As(err, &capeErr) {
		switch capeErr.Code {
		case NotFound:
			status, code = http.StatusNotFound, "not_found"
		case Invalid:
			status, code = http.StatusBadRequest, "invalid"
		case TooLarge:
			status, code = http.StatusRequestEntityTooLarge, "too_large"
		case Unauthorized:
			status, code = http.StatusUnauthorized, "unauthorized"
		case Throttled:
			status, code = http.StatusTooManyRequests, "quota"
		}
	}
	if status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "5")
	}
	apiError(w, status, code)
}

func apiError(w http.ResponseWriter, status int, code string) {
	apiJSON(w, status, struct {
		Error string `json:"error"`
	}{code})
}

func apiJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Status is committed and API response values contain only JSON-safe types.
	_ = json.NewEncoder(w).Encode(value)
}
