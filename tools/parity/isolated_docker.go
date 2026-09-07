package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"
)

const isolatedBudget = 30 * time.Second

func (d isolatedDocker) effectiveBudget() time.Duration {
	if d.budget != 0 {
		return d.budget
	}
	return isolatedBudget
}

// A backend owns a sequential lifecycle: setup -> ready -> created -> verified
// -> running -> removed -> ready. Only this parent talks to Docker. Sample bytes
// are sent after verification. Every launch (including failed create/start)
// requires exact-name removal and a separate successful absence query. Failed
// create is terminal even after current absence: a daemon create may still be
// pending registration. No start/input follows it. Unknown cleanup is likewise
// terminal; callers must not launch another sample. There are no
// retries, host scanner fallback, pulls or mounts. The daemon/kernel and selected
// local image are trusted; a compromised kernel is outside this contract.
type isolatedDocker struct {
	image       string
	identity    isolatedIdentity
	runtime     isolatedRuntime
	diagnostics io.Writer                                  // bounded local lifecycle messages, never child output
	command     func(context.Context, ...string) *exec.Cmd // tests only
	budget      time.Duration                              // tests only
}

type isolatedRuntime struct {
	DockerVersion   string   `json:"docker_version"`
	KernelVersion   string   `json:"kernel_version"`
	CgroupVersion   string   `json:"cgroup_version"`
	SecurityOptions []string `json:"security_options"`
}

func (d isolatedDocker) commandContext(ctx context.Context, args ...string) *exec.Cmd {
	if d.command != nil {
		return d.command(ctx, args...)
	}
	return dockerCommand(ctx, args...)
}

// All daemon operations, including setup and cleanup, bound both output streams.
// Client cancellation is followed by daemon-owned container removal in launch.
func (d isolatedDocker) call(ctx context.Context, input []byte, args ...string) ([]byte, string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := &boundedComparatorOutput{limit: isolatedOutputLimit, cancel: cancel}
	stderr := &boundedComparatorOutput{limit: isolatedOutputLimit, cancel: cancel}
	cmd := d.commandContext(ctx, args...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	switch {
	case stdout.overflow || stderr.overflow:
		return nil, "output_limit"
	case ctx.Err() != nil:
		return stdout.Bytes(), "timeout"
	case err != nil || stderr.Len() > 0:
		return stdout.Bytes(), "execution_error"
	default:
		return stdout.Bytes(), "ok"
	}
}

func (d isolatedDocker) args(name string) []string {
	return []string{"create", "--name", name, "--pull=never", "--platform=linux/amd64",
		"--network=none", "--read-only", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
		"--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534",
		"--pids-limit=64", "--cpus=1", "--memory=512m", "--memory-swap=512m",
		"--cgroupns=private", "--ipc=private", "--ulimit=core=0:0", "--log-driver=none",
		"--no-healthcheck", "--interactive", "--entrypoint=/usr/local/bin/parity",
		d.image, "isolated-worker-v1"}
}

type isolatedContainer struct {
	Image  string
	Config struct {
		User       string
		Entrypoint []string
		Cmd        []string
		OpenStdin  bool
	}
	Mounts     []json.RawMessage
	HostConfig struct {
		NetworkMode    string
		ReadonlyRootfs bool
		Privileged     bool
		Binds          []string
		VolumesFrom    []string
		CapAdd         []string
		CapDrop        []string
		SecurityOpt    []string
		PidMode        string
		IpcMode        string
		CgroupnsMode   string
		PidsLimit      int64
		NanoCpus       int64
		Memory         int64
		MemorySwap     int64
		Tmpfs          map[string]string
		LogConfig      struct{ Type string }
		Ulimits        []struct {
			Name       string
			Soft, Hard int64
		}
	}
}

func (d isolatedDocker) effective(b []byte) bool {
	var c isolatedContainer
	if err := json.Unmarshal(b, &c); err != nil {
		return false
	}
	h := c.HostConfig
	if c.Image != d.image || c.Config.User != "65534:65534" || !c.Config.OpenStdin ||
		!slices.Equal(c.Config.Entrypoint, []string{"/usr/local/bin/parity"}) || !slices.Equal(c.Config.Cmd, []string{"isolated-worker-v1"}) ||
		len(c.Mounts) != 0 || len(h.Binds) != 0 || len(h.VolumesFrom) != 0 || h.Privileged ||
		h.NetworkMode != "none" || !h.ReadonlyRootfs || len(h.CapAdd) != 0 || !slices.Equal(h.CapDrop, []string{"ALL"}) ||
		!slices.Equal(h.SecurityOpt, []string{"no-new-privileges"}) || h.PidMode != "" || h.IpcMode != "private" || h.CgroupnsMode != "private" ||
		h.PidsLimit != 64 || h.NanoCpus != 1000000000 || h.Memory != 512<<20 || h.MemorySwap != 512<<20 ||
		len(h.Tmpfs) != 1 || h.Tmpfs["/tmp"] != "rw,noexec,nosuid,nodev,size=64m" || h.LogConfig.Type != "none" {
		return false
	}
	// Docker may add daemon-default limits (for example nofile). Require our
	// explicit core limit without confusing those additional limits with drift.
	for _, limit := range h.Ulimits {
		if limit.Name == "core" {
			return limit.Soft == 0 && limit.Hard == 0
		}
	}
	return false
}

func (d isolatedDocker) cleanup(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// Check current absence independently of rm's error text. This cannot rule
	// out late registration after an inconclusive create; launch stops that case.
	_, _ = d.call(ctx, nil, "rm", "--force", name)
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, status := d.call(ctx, nil, "ps", "--all", "--quiet", "--filter", "name=^/"+name+"$")
	return status == "ok" && strings.TrimSpace(string(b)) == ""
}

func (d isolatedDocker) launch(input []byte) (output []byte, status string) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "setup_error"
	}
	name := "mailstrix-isolated-" + hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithTimeout(context.Background(), d.effectiveBudget())
	defer cancel()
	defer func() {
		if !d.cleanup(name) {
			output = nil
			status = "cleanup_error"
		}
	}()
	if _, status = d.call(ctx, nil, d.args(name)...); status != "ok" {
		// Cancelling the CLI cannot prove the daemon stopped creating the
		// container. A current empty ps can precede late registration. Retain
		// the exact random name for reconciliation, and never send a sample.
		if d.diagnostics != nil {
			printError(d.diagnostics, "container creation uncertain: "+name+"; no sample sent; reconcile this exact owned name before retrying")
		}
		return nil, "create_uncertain"
	}
	b, status := d.call(ctx, nil, "inspect", "--format={{json .}}", name)
	if status != "ok" {
		return nil, status
	}
	if !d.effective(b) {
		return nil, "setup_error"
	}
	output, status = d.call(ctx, input, "start", "--attach", "--interactive", name)
	if status == "execution_error" {
		stateBytes, stateStatus := d.call(ctx, nil, "inspect", "--format={{json .State}}", name)
		var state struct{ OOMKilled bool }
		if stateStatus == "ok" && json.Unmarshal(stateBytes, &state) == nil && state.OOMKilled {
			status = "memory_limit"
		}
	}
	return output, status
}

func (d *isolatedDocker) setup() error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || !strings.HasPrefix(d.image, "sha256:") || !sha256Text(strings.TrimPrefix(d.image, "sha256:")) {
		return errors.New("run-isolated requires Linux/amd64 and an immutable local sha256 image ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, status := d.call(ctx, nil, "info", "--format={{json .}}")
	var info struct {
		ServerVersion                                  string
		KernelVersion                                  string
		OSType                                         string
		Architecture                                   string
		CgroupVersion                                  string
		MemoryLimit, SwapLimit, CPUCfsQuota, PidsLimit bool
		SecurityOptions                                []string
	}
	if status != "ok" || json.Unmarshal(b, &info) != nil || info.OSType != "linux" || info.Architecture != "x86_64" || info.CgroupVersion != "2" ||
		!info.MemoryLimit || !info.SwapLimit || !info.CPUCfsQuota || !info.PidsLimit || !slices.Contains(info.SecurityOptions, "name=seccomp,profile=builtin") {
		return errors.New("local Docker cgroup v2/resource/seccomp controls unavailable")
	}
	if len(info.ServerVersion) == 0 || len(info.ServerVersion) > 128 || len(info.KernelVersion) == 0 || len(info.KernelVersion) > 128 {
		return errors.New("local Docker runtime identity unavailable")
	}
	slices.Sort(info.SecurityOptions)
	d.runtime = isolatedRuntime{info.ServerVersion, info.KernelVersion, info.CgroupVersion, info.SecurityOptions}
	b, status = d.call(ctx, nil, "image", "inspect", "--format={{json .}}", d.image)
	var image struct {
		Id, Os, Architecture string
		Config               struct{ Volumes map[string]json.RawMessage }
	}
	if status != "ok" || json.Unmarshal(b, &image) != nil || image.Id != d.image || image.Os != "linux" || image.Architecture != "amd64" || len(image.Config.Volumes) != 0 {
		return errors.New("local image identity/platform/volume contract unavailable")
	}
	input, err := encodeIsolatedRequest(isolatedRequest{Version: 1, Operation: "identity"}, nil)
	if err != nil {
		return err
	}
	b, status = d.launch(input)
	if status != "ok" {
		return errors.New("isolated identity setup failed: " + status)
	}
	r, err := decodeIsolatedResponse(b)
	if err != nil || r.Status != "ok" || len(r.Symbols) != 0 {
		return errors.New("isolated worker identity unavailable")
	}
	d.identity = r.Identity
	return nil
}

func (d isolatedDocker) observe(s sample, data []byte) observation {
	input, err := encodeIsolatedRequest(isolatedRequest{1, "scan", s.Format, s.InputUnit, s.Size, s.SHA256}, data)
	if err != nil {
		return observation{Status: "integrity_error"}
	}
	b, status := d.launch(input)
	if status != "ok" {
		return observation{Status: status}
	}
	r, err := decodeIsolatedResponse(b)
	if err != nil {
		return observation{Status: "malformed_output"}
	}
	if r.Identity != d.identity {
		return observation{Status: "identity_error"}
	}
	return observation{Status: r.Status, Matches: r.Symbols}
}
