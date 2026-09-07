package main

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"
)

// These are compiled test-tool inputs, never operator-overridable moving tags.
//
//go:embed comparator-pins.json
var comparatorPinsJSON []byte

//go:embed comparator_runner.py
var comparatorRunner string

const (
	comparatorBudget      = 30 * time.Second
	comparatorOutputLimit = 2 << 20
	dockerSocket          = "unix:///var/run/docker.sock"
)

type comparatorPins struct {
	SchemaVersion           int    `json:"schema_version"`
	Image                   string `json:"image"`
	IndexDigest             string `json:"index_digest"`
	Platform                string `json:"platform"`
	PlatformManifestDigest  string `json:"platform_manifest_digest"`
	OletoolsVersion         string `json:"oletools_version"`
	OletoolsCommit          string `json:"oletools_commit"`
	OletoolsWheelSHA256     string `json:"oletools_wheel_sha256"`
	OlefyCommit             string `json:"olefy_commit"`
	OlefySHA256             string `json:"olefy_sha256"`
	OlefyRequirementsSHA256 string `json:"olefy_requirements_sha256"`
}

func pinnedComparators() (comparatorPins, error) {
	var pins comparatorPins
	err := json.Unmarshal(comparatorPinsJSON, &pins)
	return pins, err
}

type comparatorIdentity struct {
	OletoolsVersion string `json:"oletools_version"`
	OlefySHA256     string `json:"olefy_sha256"`
}

func (p comparatorPins) qualifies(i comparatorIdentity) bool {
	return i.OletoolsVersion == p.OletoolsVersion && i.OlefySHA256 == p.OlefySHA256
}

type comparatorEnvelope struct {
	Identity comparatorIdentity `json:"identity"`
	Status   string             `json:"status"`
	Output   string             `json:"output"`
}

// Native categories only: no mapping to Mailstrix rules or malware labels.
type nativeObservation struct {
	Status     string
	Format     string
	HasMacros  bool
	Categories []string
	Identity   comparatorIdentity
}

// strictComparatorJSON rejects duplicate keys, trailing data and excessive
// nesting before typed decoding can turn ambiguous responses into observations.
func strictComparatorJSON(b []byte, out any) error {
	if len(b) == 0 || len(b) > comparatorOutputLimit {
		return errors.New("comparator output size invalid")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if err := checkJSON(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing comparator output")
	}
	return json.Unmarshal(b, out)
}

func normalizeComparator(b []byte, pins comparatorPins) nativeObservation {
	var envelope comparatorEnvelope
	failure := func(status string) nativeObservation {
		o := nativeObservation{Status: status}
		if pins.qualifies(envelope.Identity) {
			o.Identity = envelope.Identity
		}
		return o
	}
	if err := strictComparatorJSON(b, &envelope); err != nil {
		return failure("malformed_output")
	}
	// A failed probe cannot supply qualified identity. Preserve its explicit
	// failure without permitting any successful observation through this path.
	if envelope.Status == "identity_error" {
		return failure("identity_error")
	}
	if !pins.qualifies(envelope.Identity) {
		return failure("pin_mismatch")
	}
	if envelope.Status != "ok" {
		if slices.Contains([]string{"pin_mismatch", "identity_error", "input_error", "tool_error", "timeout", "output_limit", "malformed_output"}, envelope.Status) {
			return nativeObservation{Status: envelope.Status, Identity: envelope.Identity}
		}
		return failure("malformed_output")
	}
	var records []map[string]json.RawMessage
	if err := strictComparatorJSON([]byte(envelope.Output), &records); err != nil {
		return failure("malformed_output")
	}
	// Log entries and explicit upstream error records invalidate even an
	// otherwise successful file record (olevba embeds diagnostics in JSON).
	for _, record := range records {
		if _, ok := record["error"]; ok {
			return failure("tool_error")
		}
		var kind string
		if err := json.Unmarshal(record["type"], &kind); err != nil {
			return failure("malformed_output")
		}
		if kind == "error" || kind == "msg" || kind == "warning" {
			return failure("tool_error")
		}
	}
	// One exact byte input, one metadata record and one complete file record.
	// Recursive/decrypted multi-file outputs need a future, explicit mapping.
	if len(records) != 2 {
		return failure("malformed_output")
	}
	var meta struct {
		Type, Version string
		ScriptName    string `json:"script_name"`
	}
	if err := json.Unmarshal(mustJSON(records[0]), &meta); err != nil || meta.Type != "MetaInformation" || meta.ScriptName != "olevba" || meta.Version != pins.OletoolsVersion {
		return failure("pin_mismatch")
	}
	var file struct {
		Type     string            `json:"type"`
		Complete *bool             `json:"json_conversion_successful"`
		Macros   []json.RawMessage `json:"macros"`
		Analysis []struct {
			Type string `json:"type"`
		} `json:"analysis"`
		Container json.RawMessage `json:"container"`
	}
	if err := json.Unmarshal(mustJSON(records[1]), &file); err != nil || file.Complete == nil || !*file.Complete || file.Macros == nil {
		return failure("malformed_output")
	}
	if _, exists := records[1]["analysis"]; !exists {
		return failure("malformed_output")
	}
	for _, raw := range file.Macros {
		var macro map[string]json.RawMessage
		if err := json.Unmarshal(raw, &macro); err != nil || len(macro) == 0 {
			return failure("malformed_output")
		}
	}
	if !bytes.Equal(bytes.TrimSpace(file.Container), []byte("null")) {
		return failure("unsupported")
	}
	if !slices.Contains([]string{"OLE", "OpenXML", "Word2003_XML", "FlatOPC_XML", "MHTML", "PPT", "SLK"}, file.Type) {
		return failure("unsupported")
	}
	if len(file.Macros) > 0 && file.Analysis == nil || len(file.Macros) == 0 && len(file.Analysis) > 0 {
		return failure("malformed_output")
	}
	o := nativeObservation{Status: "ok", Format: file.Type, HasMacros: len(file.Macros) > 0, Categories: []string{}, Identity: envelope.Identity}
	for _, finding := range file.Analysis {
		if !slices.Contains([]string{"AutoExec", "Suspicious", "IOC", "Hex String", "Base64 String", "Dridex String", "VBA String"}, finding.Type) {
			return failure("unsupported")
		}
		o.Categories = append(o.Categories, finding.Type)
	}
	slices.Sort(o.Categories)
	o.Categories = slices.Compact(o.Categories)
	return o
}

// Maps here contain only json.RawMessage values already validated as JSON.
func mustJSON(v map[string]json.RawMessage) []byte {
	b, _ := json.Marshal(v)
	return b
}

// A bounded writer cancels the Docker client when either stream overflows.
// Only one copy goroutine writes each instance; stdout/stderr use separate ones.
type boundedComparatorOutput struct {
	// Do not embed bytes.Buffer: its promoted ReadFrom lets io.Copy bypass
	// Write's limit when os/exec drains the child process's output pipe.
	buffer   bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	overflow bool
}

func (b *boundedComparatorOutput) Len() int      { return b.buffer.Len() }
func (b *boundedComparatorOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedComparatorOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.overflow = true
		b.cancel()
		return 0, errors.New("comparator output limit")
	}
	return b.buffer.Write(p)
}

type dockerComparator struct {
	pins comparatorPins
	// Optional package-local test seams; production always uses dockerCommand
	// and the fixed budget. Neither is configurable through the CLI.
	command func(context.Context, ...string) *exec.Cmd
	budget  time.Duration
}

func (d dockerComparator) commandContext(ctx context.Context, args ...string) *exec.Cmd {
	if d.command != nil {
		return d.command(ctx, args...)
	}
	return dockerCommand(ctx, args...)
}

// dockerCommand deliberately ignores Docker context/host environment variables:
// caller-owned documents may only go to the host's local Unix socket daemon.
func dockerCommand(ctx context.Context, args ...string) *exec.Cmd {
	// #nosec G204 -- argv uses fixed flags, embedded pins/script, allowlisted adapters and random hex names; document bytes go only to stdin, without a shell.
	cmd := exec.CommandContext(ctx, "docker", append([]string{"--host", dockerSocket}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.WaitDelay = time.Second
	return cmd
}

func (d dockerComparator) args(name, adapter string) []string {
	return []string{"run", "--rm", "--name", name, "--pull=never", "--platform", d.pins.Platform,
		"--network=none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--cap-drop=ALL",
		"--security-opt=no-new-privileges", "--user=65534:65534", "--pids-limit=32", "--cpus=1", "--memory=256m", "--memory-swap=256m",
		"--log-driver=none", "--env=PYTHONDONTWRITEBYTECODE=1", "--interactive", "--entrypoint=python3",
		d.pins.Image + "@" + d.pins.IndexDigest, "-c", comparatorRunner, adapter, d.pins.OletoolsVersion, d.pins.OlefySHA256}
}

func (d dockerComparator) observe(adapter string, data []byte) nativeObservation {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nativeObservation{Status: "unsupported_platform"}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nativeObservation{Status: "setup_error"}
	}
	name := "mailstrix-parity-" + hex.EncodeToString(nonce[:])
	budget := d.budget
	if budget == 0 {
		budget = comparatorBudget
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	stdout := &boundedComparatorOutput{limit: comparatorOutputLimit, cancel: cancel}
	stderr := &boundedComparatorOutput{limit: comparatorOutputLimit, cancel: cancel}
	cmd := d.commandContext(ctx, d.args(name, adapter)...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	status := "ok"
	switch {
	case stdout.overflow || stderr.overflow:
		status = "output_limit"
	case ctx.Err() != nil:
		status = "timeout"
	case err != nil || stderr.Len() > 0:
		status = "execution_error"
	}
	if status != "ok" {
		// Killing a Docker client does not kill its daemon-owned container. Use
		// this exact random name, never a glob or a caller-controlled name.
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		cleanup := d.commandContext(cleanupCtx, "rm", "--force", name)
		// Missing after --rm is expected, but a live container is not. Verify
		// absence with a separately bounded query, including after rm errors.
		_ = cleanup.Run()
		checkCtx, stopCheck := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCheck()
		var remaining bytes.Buffer
		check := d.commandContext(checkCtx, "ps", "--all", "--quiet", "--filter", "name=^/"+name+"$")
		check.Stdout = &remaining
		if check.Run() != nil || strings.TrimSpace(remaining.String()) != "" {
			status = "cleanup_error"
		}
		return nativeObservation{Status: status}
	}
	return normalizeComparator(stdout.Bytes(), d.pins)
}
