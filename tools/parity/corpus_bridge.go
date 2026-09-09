package main

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

//go:embed clamav_adapter.py
var clamavAdapterSource []byte

//go:embed clamav_bridge.py
var clamavBridgeSource []byte

const clamBridgeLimit = 64 << 10
const clamBridgeBudget = 100 * time.Second
const clamBridgePython = "/usr/bin/python3"
const clamEnvelope = "clamav-offline-v1;linux/amd64;cgroup2;network=none;readonly;uid=65534:65534;cap-drop=ALL;no-new-privileges;seccomp=builtin;no-mounts;cpu=1;pids=64;memory+swap=4GiB;tmpfs=512MiB,noexec,nosuid,nodev;input=16MiB;output=64KiB/pipe;scan=45s;operation=5s;reap=5s;bridge=100s;legacy-CVD-verification;no-detached-signature-CA;no-freshness-claim"

var statClamBridgePython = os.Stat
var accessClamBridgePython = executableByCaller
var errClamBridgePython = errors.New("ClamAV bridge requires executable /usr/bin/python3")

type clamIdentity struct {
	ImageID            string `json:"image_id"`
	RootfsSHA256       string `json:"rootfs_sha256"`
	EngineAssetsSHA256 string `json:"engine_assets_sha256"`
	DatabaseSHA256     string `json:"database_sha256"`
	Version            string `json:"version"`
}

func (i clamIdentity) valid() bool {
	return strings.HasPrefix(i.ImageID, "sha256:") && sha256Text(strings.TrimPrefix(i.ImageID, "sha256:")) &&
		sha256Text(i.RootfsSHA256) && sha256Text(i.EngineAssetsSHA256) && sha256Text(i.DatabaseSHA256) &&
		strings.HasPrefix(i.Version, "ClamAV 1.5.3/") && len(i.Version) < 180 && !strings.ContainsAny(i.Version, "\r\n")
}

type clamDiagnostic struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

type clamObservation struct {
	Status        string           `json:"status"`
	Detections    []string         `json:"detections"`
	DatabaseStale bool             `json:"database_stale"`
	Diagnostics   []clamDiagnostic `json:"diagnostics"`
	Terminal      bool             `json:"terminal"`
}

type clamBridgeRequest struct {
	Version          int          `json:"version"`
	Operation        string       `json:"operation"`
	Name             string       `json:"name"`
	QualificationDir string       `json:"qualification_dir"`
	Variant          string       `json:"variant"`
	Identity         clamIdentity `json:"identity"`
	ManifestSHA256   string       `json:"manifest_sha256"`
	SampleSHA256     string       `json:"sample_sha256"`
	Size             int64        `json:"size"`
	InputUnit        string       `json:"input_unit"`
	ScanArgs         []string     `json:"scan_args"`
}

type clamBridgeReply struct {
	Version        int          `json:"version"`
	Name           string       `json:"name"`
	ManifestSHA256 string       `json:"manifest_sha256"`
	SampleSHA256   string       `json:"sample_sha256"`
	Size           int64        `json:"size"`
	InputUnit      string       `json:"input_unit"`
	Identity       clamIdentity `json:"identity"`
	ScanArgs       []string     `json:"scan_args"`
	clamObservation
}

var clamDetectionName = regexp.MustCompile(`^[A-Za-z0-9_.:+-]{1,200}$`)

const clamAgeWarning = "LibClamAV Warning: **************************************************\n" +
	"LibClamAV Warning: ***  The virus database is older than 7 days!  ***\n" +
	"LibClamAV Warning: ***   Please update it as soon as possible.    ***\n" +
	"LibClamAV Warning: **************************************************\n"

func decodeClamReply(raw []byte, request clamBridgeRequest) (clamBridgeReply, error) {
	var reply clamBridgeReply
	if len(raw) > clamBridgeLimit || isolatedJSON(raw, &reply) != nil || reply.Version != 1 ||
		reply.Name != request.Name || reply.ManifestSHA256 != request.ManifestSHA256 ||
		reply.SampleSHA256 != request.SampleSHA256 || reply.Size != request.Size || reply.InputUnit != request.InputUnit ||
		!reply.Identity.valid() || reply.Detections == nil || reply.Diagnostics == nil {
		return reply, errors.New("ClamAV bridge reply identity/framing mismatch")
	}
	if request.Operation == "scan" && reply.Identity != request.Identity {
		return reply, errors.New("ClamAV bridge engine identity changed")
	}
	if len(reply.ScanArgs) == 0 || len(reply.ScanArgs) > 128 || request.Operation == "scan" && !slices.Equal(reply.ScanArgs, request.ScanArgs) {
		return reply, errors.New("ClamAV scanner policy changed or missing")
	}
	for _, arg := range reply.ScanArgs {
		if len(arg) == 0 || len(arg) > 256 || strings.ContainsAny(arg, "\r\n\x00") {
			return reply, errors.New("ClamAV scanner argument invalid")
		}
	}
	if reply.DatabaseStale {
		if !slices.Equal(reply.Diagnostics, []clamDiagnostic{{"historical_database_age", clamAgeWarning}}) {
			return reply, errors.New("ClamAV diagnostic policy mismatch")
		}
	} else if len(reply.Diagnostics) != 0 {
		return reply, errors.New("ClamAV unclassified diagnostics")
	}
	if !slices.Contains([]string{"ok", "no_detection", "detection", "setup_error", "execution_error", "identity_error", "input_limit", "input_error", "scan_limit", "timeout", "output_limit", "resource_limit", "heuristic_unknown", "envelope_error", "cleanup_error", "backend_unavailable", "malformed_output"}, reply.Status) {
		return reply, errors.New("ClamAV unknown status")
	}
	if reply.Status == "detection" {
		if len(reply.Detections) == 0 || len(reply.Detections) > 256 || !slices.IsSorted(reply.Detections) {
			return reply, errors.New("ClamAV invalid detection list")
		}
		for n, name := range reply.Detections {
			if !clamDetectionName.MatchString(name) || strings.HasPrefix(name, "Heuristics.") || n > 0 && name == reply.Detections[n-1] {
				return reply, errors.New("ClamAV unmapped detection")
			}
		}
	} else if len(reply.Detections) != 0 {
		return reply, errors.New("ClamAV failure/non-detection contains detections")
	}
	if request.Operation == "identity" && reply.Status != "ok" || request.Operation == "scan" && reply.Status == "ok" ||
		reply.Terminal && slices.Contains([]string{"ok", "no_detection", "detection"}, reply.Status) {
		return reply, errors.New("ClamAV incomplete invocation reported successful")
	}
	return reply, nil
}

// clamBridge is sequential. Go chooses a name before starting Python and owns
// its process group. A normal reply follows Python-owned container cleanup.
// An abnormal reply first kills/reaps the bridge group, then Go attempts exact
// removal plus absence, retains the name, and permanently stops this backend.
// Abrupt death of the Go orchestrator/kernel is outside that ownership guarantee.
type clamBridge struct {
	dir         string
	identity    clamIdentity
	scanArgs    []string
	manifestSHA string
	stopped     bool
	diagnostics io.Writer
	command     func(context.Context, string) *exec.Cmd // inert process tests only
	cleanup     func(string) bool                       // tests only
	budget      time.Duration                           // tests only
}

func prepareClamBridge(diagnostics io.Writer) (*clamBridge, error) {
	dir, err := os.MkdirTemp("", "mailstrix-clamav-bridge-")
	if err != nil {
		return nil, err
	}
	b := &clamBridge{dir: dir, diagnostics: diagnostics}
	for name, source := range map[string][]byte{"clamav_adapter.py": clamavAdapterSource, "clamav_bridge.py": clamavBridgeSource} {
		if err := os.WriteFile(filepath.Join(dir, name), source, 0o600); err != nil {
			return nil, errors.Join(err, b.close())
		}
	}
	return b, nil
}

func (b *clamBridge) close() error {
	return os.RemoveAll(b.dir)
}

func (b *clamBridge) cleanupAfterFailure(name string) bool {
	if b.cleanup != nil {
		return b.cleanup(name)
	}
	d := isolatedDocker{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// Docker removal output has no contract; its status and the independent
	// exact-name absence probe below determine whether cleanup succeeded.
	_, status := d.call(ctx, nil, "rm", "--force", name)
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	absent, absentStatus := d.call(ctx, nil, "ps", "--all", "--quiet", "--filter", "name=^/"+name+"$")
	return status == "ok" && absentStatus == "ok" && len(bytes.TrimSpace(absent)) == 0
}

type clamBridgeOutcome struct {
	groupAbsent        bool
	runErr             error
	groupErr           error
	contextErr         error
	outputOverflow     bool
	diagnosticOverflow bool
	diagnosticBytes    int
}

func clamBridgeFailureCause(outcome clamBridgeOutcome) string {
	switch {
	case outcome.groupErr != nil || !outcome.groupAbsent:
		return "group_cleanup"
	case outcome.outputOverflow || outcome.diagnosticOverflow:
		return "output_limit"
	case outcome.diagnosticBytes != 0:
		return "unexpected_diagnostics"
	case errors.Is(outcome.runErr, context.DeadlineExceeded) || errors.Is(outcome.contextErr, context.DeadlineExceeded):
		return "timeout"
	default:
		return "process"
	}
}

func requireClamBridgePython(path string) error {
	info, err := statClamBridgePython(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || !accessClamBridgePython(path) {
		return errClamBridgePython
	}
	return nil
}

func clamBridgeCommand(ctx context.Context, directory string) *exec.Cmd {
	// Only embedded modules are imported. The executable, flags and inline
	// program are fixed; directory is trusted and passed as argv, not a shell.
	// #nosec G204 -- no caller-controlled executable, program, or shell input.
	return exec.CommandContext(ctx, clamBridgePython, "-I", "-B", "-c", "import sys;sys.path.insert(0,sys.argv[1]);import clamav_bridge;sys.exit(clamav_bridge.main())", directory)
}

func (b *clamBridge) invoke(request clamBridgeRequest, data []byte) (clamBridgeReply, error) {
	var reply clamBridgeReply
	if b.stopped || len(data) > maxSample || request.Size != int64(len(data)) || request.SampleSHA256 != digest(data) {
		return reply, errors.New("ClamAV bridge unavailable or invalid input")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return reply, err
	}
	request.Name = "mailstrix-clamav-" + hex.EncodeToString(random[:])
	header, err := json.Marshal(request)
	if err != nil || len(header) >= clamBridgeLimit {
		return reply, errors.New("ClamAV bridge request too large")
	}
	budget := clamBridgeBudget
	if b.budget != 0 {
		budget = b.budget
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	var cmd *exec.Cmd
	if b.command != nil {
		cmd = b.command(ctx, request.Name)
	} else {
		if err := requireClamBridgePython(clamBridgePython); err != nil {
			b.stopped = true
			if b.diagnostics != nil {
				printError(b.diagnostics, errClamBridgePython)
			}
			return reply, err
		}
		cmd = clamBridgeCommand(ctx, b.dir)
	}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
	cmd.Stdin = io.MultiReader(bytes.NewReader(header), strings.NewReader("\n"), bytes.NewReader(data))
	out := &boundedComparatorOutput{limit: clamBridgeLimit, cancel: cancel}
	diagnostic := &boundedComparatorOutput{limit: clamBridgeLimit, cancel: cancel}
	cmd.Stdout, cmd.Stderr = out, diagnostic
	if err := configureBridgeGroup(cmd); err != nil {
		return reply, err
	}
	// Observe the leader's exit without reaping it. Its zombie pins the numeric
	// PID/PGID while we kill the whole group; only then may Wait release that
	// identity and allow exact-name container cleanup to take ownership.
	groupAbsent, runErr, groupErr := runBridgeGroup(ctx, cmd)
	cause := ""
	if runErr == nil && groupErr == nil && !out.overflow && !diagnostic.overflow && diagnostic.Len() == 0 {
		reply, err = decodeClamReply(out.Bytes(), request)
		if err != nil {
			cause = "invalid_reply"
		}
	} else {
		cause = clamBridgeFailureCause(clamBridgeOutcome{
			groupAbsent: groupAbsent, runErr: runErr, groupErr: groupErr, contextErr: ctx.Err(),
			outputOverflow: out.overflow, diagnosticOverflow: diagnostic.overflow, diagnosticBytes: diagnostic.Len(),
		})
		err = errors.New("ClamAV bridge terminated without a complete reply")
	}
	if err != nil {
		b.stopped = true
		// A surviving client may still operate on the container. Transfer
		// cleanup ownership only after the entire group is confirmed absent.
		clean := groupAbsent && b.cleanupAfterFailure(request.Name)
		if b.diagnostics != nil {
			printError(b.diagnostics, fmt.Sprintf("ClamAV bridge uncertainty: container=%s cause=%s cleanup_confirmed=%t; backend stopped", request.Name, cause, clean))
		}
		return reply, err
	}
	if reply.Terminal {
		b.stopped = true
		if b.diagnostics != nil {
			printError(b.diagnostics, "ClamAV terminal cleanup/create uncertainty: container="+request.Name)
		}
	}
	return reply, nil
}

func (b *clamBridge) setup(directory, variant, manifestSHA string) error {
	if b.command == nil {
		if err := requireClamBridgePython(clamBridgePython); err != nil {
			return err
		}
	}
	b.manifestSHA = manifestSHA
	r, err := b.invoke(clamBridgeRequest{Version: 1, Operation: "identity", QualificationDir: directory, Variant: variant,
		ManifestSHA256: manifestSHA, SampleSHA256: digest(nil)}, nil)
	if err != nil {
		return err
	}
	b.identity = r.Identity
	b.scanArgs = r.ScanArgs
	return nil
}

func (b *clamBridge) observe(s sample, data []byte) clamObservation {
	r, err := b.invoke(clamBridgeRequest{Version: 1, Operation: "scan", Identity: b.identity,
		ManifestSHA256: b.manifestSHA, SampleSHA256: s.SHA256, Size: s.Size, InputUnit: s.InputUnit, ScanArgs: b.scanArgs}, data)
	if err != nil {
		return clamObservation{Status: "bridge_error", Detections: []string{}, Diagnostics: []clamDiagnostic{}, Terminal: b.stopped}
	}
	return r.clamObservation
}
