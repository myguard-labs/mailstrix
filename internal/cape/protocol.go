package cape

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"
	"unicode/utf8"
)

// jsonDocument rejects duplicate keys, nonfinite numbers, trailing documents and
// excessive nesting. The optional visitor observes only fully decoded elements
// of the root object's data.task_ids array, including before a later parse error.
func jsonDocument(body []byte, visit func(any)) (map[string]any, error) {
	p := jsonParser{decoder: json.NewDecoder(bytes.NewReader(body)), visit: visit}
	p.decoder.UseNumber()
	v, err := p.value(0, nil)
	if err != nil {
		return nil, &Error{Code: Protocol}
	}
	if _, err = p.decoder.Token(); err != io.EOF || p.invalid || !utf8.Valid(body) {
		return nil, &Error{Code: Protocol}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, &Error{Code: Protocol}
	}
	return m, nil
}

type jsonParser struct {
	decoder *json.Decoder
	visit   func(any)
	invalid bool
}

func (p *jsonParser) value(depth int, path []string) (any, error) {
	token, err := p.decoder.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Delim:
		if depth >= MaxDepth {
			return nil, &Error{Code: Protocol}
		}
		switch v {
		case '{':
			m := make(map[string]any)
			for p.decoder.More() {
				key, err := p.decoder.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, &Error{Code: Protocol}
				}
				if _, exists := m[name]; exists {
					p.invalid = true
				}
				var childPath []string
				if p.visit != nil {
					childPath = append(append([]string(nil), path...), name)
				}
				child, err := p.value(depth+1, childPath)
				if err != nil {
					return nil, err
				}
				m[name] = child
			}
			end, err := p.decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, &Error{Code: Protocol}
			}
			return m, nil
		case '[':
			a := make([]any, 0)
			for p.decoder.More() {
				var childPath []string
				if p.visit != nil {
					childPath = append(append([]string(nil), path...), "[]")
				}
				child, err := p.value(depth+1, childPath)
				if err != nil {
					return nil, err
				}
				if p.visit != nil && len(path) == 2 && path[0] == "data" && path[1] == "task_ids" {
					p.visit(child)
				}
				a = append(a, child)
			}
			end, err := p.decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, &Error{Code: Protocol}
			}
			return a, nil
		}
		return nil, &Error{Code: Protocol}
	case json.Number:
		f, err := v.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			p.invalid = true
		}
	}
	return token, nil
}

func taskID(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(string(n), 10, 32)
	return id, err == nil && id > 0
}

func parseSubmission(body []byte, generation string) ([]TaskRef, error) {
	tasks := make([]TaskRef, 0, MaxTaskIDs)
	count := 0
	invalid := false
	doc, err := jsonDocument(body, func(value any) {
		count++
		id, valid := taskID(value)
		if !valid {
			invalid = true
			return
		}
		for _, task := range tasks {
			if task.ID == id {
				invalid = true
				return
			}
		}
		if len(tasks) < MaxTaskIDs {
			tasks = append(tasks, TaskRef{ID: id, Generation: generation})
		}
	})
	if err != nil {
		return tasks, err
	}
	errorList, errorOK := doc["error"].([]any)
	errorsList, errorsOK := doc["errors"].([]any)
	if invalid || count != 1 || len(tasks) != 1 || !errorOK || len(errorList) != 0 || !errorsOK || len(errorsList) != 0 {
		return tasks, &Error{Code: Protocol}
	}
	return tasks, nil
}

func (c *Client) validTask(task TaskRef) bool {
	return task.ID > 0 && task.ID <= math.MaxInt32 && task.Generation == c.generation
}

func (c *Client) read(parent context.Context, task TaskRef, path string, limit int64) (map[string]any, error) {
	if !c.validTask(task) {
		return nil, &Error{Code: Invalid}
	}
	ctx, done, err := c.begin(parent)
	if err != nil {
		return nil, err
	}
	defer done()
	req, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req, limit)
	if err != nil {
		return nil, err
	}
	return jsonDocument(body, nil)
}

// Status is a pinned upstream CAPE task state.
type Status string

// Status returns only pinned upstream states. In particular, completed does not
// mean a report is available, and recovered does not authorize adopting another ID.
func (c *Client) Status(ctx context.Context, task TaskRef) (Status, error) {
	doc, err := c.read(ctx, task, "/apiv2/tasks/status/"+strconv.FormatInt(task.ID, 10)+"/", MaxMetadata)
	if err != nil {
		return "", err
	}
	if failed, ok := doc["error"].(bool); !ok || failed {
		return "", &Error{Code: Protocol}
	}
	s, ok := doc["data"].(string)
	if !ok {
		return "", &Error{Code: Protocol}
	}
	switch s {
	case "pending", "running", "distributed", "completed", "recovered", "reported", "banned",
		"failed_analysis", "failed_processing", "failed_reporting", "distributed_completed":
		return Status(s), nil
	default:
		return "", &Error{Code: Protocol}
	}
}

// Report is a validated in-memory document, not a verdict. The mapper must check
// the types/schema of every signal it consumes and discard the document after
// normalization. Do not persist, log or expose Document to clients.
type Report struct {
	document map[string]any
	// Sealed transport identity prevents cross-generation report reuse.
	task   TaskRef
	digest [32]byte
}

// Document returns the decoded, bounded report for immediate normalization.
func (r *Report) Document() map[string]any { return r.document }

// String returns a redacted report representation.
func (r *Report) String() string { return "cape_report_redacted" }

// GoString returns a redacted report representation.
func (r *Report) GoString() string { return r.String() }

// Report validates the pinned file-report identity envelope. The upstream
// CAPE_current_commit field can be "unknown" (e.g. packed refs); it is not an
// attestation. Deployment revision verification belongs to operator activation.
// Signal semantics and thresholds belong to the separately versioned mapper.
func (c *Client) Report(ctx context.Context, task TaskRef, expectedSHA256 [32]byte) (*Report, error) {
	doc, err := c.read(ctx, task, "/apiv2/tasks/get/report/"+strconv.FormatInt(task.ID, 10)+"/json/", MaxReport)
	if err != nil {
		return nil, err
	}
	info, _ := doc["info"].(map[string]any)
	target, _ := doc["target"].(map[string]any)
	file, _ := target["file"].(map[string]any)
	id, valid := taskID(info["id"])
	hash, ok := file["sha256"].(string)
	if !valid || id != task.ID || !ok || hash != hex.EncodeToString(expectedSHA256[:]) ||
		info["category"] != "file" || target["category"] != "file" {
		return nil, &Error{Code: Protocol}
	}
	return &Report{document: doc, task: task, digest: expectedSHA256}, nil
}

// DeleteState deliberately has no purge-confirmed outcome. Even the pinned
// success response can leave binaries, reports, descendants and backups behind.
type DeleteState string

// DeleteAcknowledgedUnverified means the pinned endpoint accepted deletion.
const DeleteAcknowledgedUnverified DeleteState = "remote_delete_acknowledged_unverified"

// Delete requests deletion of one previously owned task. A timeout, missing task
// or orphaned response requires reconciliation, not an automatic success/retry.
func (c *Client) Delete(ctx context.Context, task TaskRef) (DeleteState, error) {
	id := strconv.FormatInt(task.ID, 10)
	doc, err := c.read(ctx, task, "/apiv2/tasks/delete/"+id+"/", MaxMetadata)
	if err != nil {
		return "", err
	}
	// At the pinned revision successful deletion omits error entirely.
	if len(doc) != 1 || doc["data"] != "Task(s) ID(s) "+id+" has been deleted" {
		return "", &Error{Code: Protocol}
	}
	return DeleteAcknowledgedUnverified, nil
}
