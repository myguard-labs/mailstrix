package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// This test binary is its own fake Docker executable. It never starts Docker,
// Python or a daemon; it exercises real pipes, exit codes and context kills.
func TestComparatorProcessHelper(t *testing.T) {
	i := slices.Index(os.Args, "--parity-helper")
	if i < 0 {
		return
	}
	mode := os.Args[i+1]
	switch mode {
	case "absent":
		os.Exit(0)
	case "present":
		fmt.Println("inert-container")
		os.Exit(0)
	case "error":
		os.Exit(7)
	case "wait":
		time.Sleep(time.Minute)
		os.Exit(8)
	case "stderr":
		fmt.Fprintln(os.Stderr, "inert diagnostic")
		os.Exit(0)
	case "stdout-limit", "stderr-limit":
		var out io.Writer = os.Stdout
		if mode == "stderr-limit" {
			out = os.Stderr
		}
		_, _ = out.Write(bytes.Repeat([]byte("x"), comparatorOutputLimit+1))
		os.Exit(0)
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil || len(data) == 0 {
		os.Exit(9)
	}
	pins := testPins(t)
	raw := nativeCleanFixture
	if mode == "different" {
		raw = strings.Replace(raw, "OpenXML", "OLE", 1)
	}
	b := fixtureEnvelope(t, "ok", raw, comparatorIdentity{pins.OletoolsVersion, pins.OlefySHA256})
	if _, err := os.Stdout.Write(b); err != nil {
		os.Exit(10)
	}
	os.Exit(0)
}

type processCall struct {
	args []string
	cmd  *exec.Cmd
}

func fakeDocker(t *testing.T, runMode, removeMode, checkMode string) (dockerComparator, *[]processCall) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("comparator supports Linux/amd64 only")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	calls := []processCall{}
	// Coverage-instrumented helper binaries otherwise emit a stderr warning,
	// which the real comparator correctly treats as an execution failure.
	coverDir := t.TempDir()
	d := dockerComparator{pins: testPins(t), budget: 3 * time.Second}
	d.command = func(ctx context.Context, args ...string) *exec.Cmd {
		mode := runMode
		switch args[0] {
		case "rm":
			mode = removeMode
		case "ps":
			mode = checkMode
		case "run":
			if runMode == "pair-difference" {
				mode = "ok"
				if args[len(args)-3] == "olefy" {
					mode = "different"
				}
			}
		default:
			t.Fatalf("unexpected Docker operation %q", args[0])
		}
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestComparatorProcessHelper$", "--", "--parity-helper", mode)
		cmd.Env = []string{"GORACE=atexit_sleep_ms=0", "GOCOVERDIR=" + coverDir}
		cmd.WaitDelay = time.Second
		calls = append(calls, processCall{append([]string(nil), args...), cmd})
		return cmd
	}
	return d, &calls
}

func TestComparatorExecutionAndCleanup(t *testing.T) {
	cases := []struct{ name, run, remove, check, want string }{
		{"success", "ok", "absent", "absent", "ok"},
		{"nonzero", "error", "absent", "absent", "execution_error"},
		{"stderr", "stderr", "absent", "absent", "execution_error"},
		{"stdout overflow", "stdout-limit", "absent", "absent", "output_limit"},
		{"stderr overflow", "stderr-limit", "absent", "absent", "output_limit"},
		{"deadline", "wait", "absent", "absent", "timeout"},
		{"already removed", "error", "error", "absent", "execution_error"},
		{"still present", "error", "absent", "present", "cleanup_error"},
		{"verification failed", "error", "absent", "error", "cleanup_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, calls := fakeDocker(t, tc.run, tc.remove, tc.check)
			if tc.run == "wait" {
				d.budget = 100 * time.Millisecond
			}
			o := d.observe("oletools", []byte("inert sample"))
			if o.Status != tc.want {
				t.Fatalf("status=%s, want %s", o.Status, tc.want)
			}
			wantCalls := 3
			if tc.want == "ok" {
				wantCalls = 1
			}
			if len(*calls) != wantCalls {
				t.Fatalf("calls=%d, want %d", len(*calls), wantCalls)
			}
			for _, call := range *calls {
				if call.cmd.ProcessState == nil {
					t.Fatalf("command %s was not run and waited", call.args[0])
				}
			}
			if wantCalls == 3 {
				name := (*calls)[0].args[3]
				if !strings.HasPrefix(name, "mailstrix-parity-") || !slices.Equal((*calls)[1].args, []string{"rm", "--force", name}) || !slices.Equal((*calls)[2].args, []string{"ps", "--all", "--quiet", "--filter", "name=^/" + name + "$"}) {
					t.Fatal("cleanup did not target the exact run container")
				}
			}
		})
	}
}

func TestCompareReportExitAndIO(t *testing.T) {
	m, hash, root := generated(t)
	for _, s := range m.Samples {
		if s.Format == "office" {
			m.Samples = []sample{s}
			break
		}
	}
	for _, tc := range []struct {
		mode string
		code int
	}{{"ok", 0}, {"error", 1}, {"pair-difference", 1}} {
		t.Run(tc.mode, func(t *testing.T) {
			d, _ := fakeDocker(t, tc.mode, "absent", "absent")
			var output, diagnostic bytes.Buffer
			code := compareWithObserver(root, m, hash, d.pins, selectedAdapters("both"), d.observe, &output, &diagnostic)
			if code != tc.code {
				t.Fatalf("exit=%d, want %d", code, tc.code)
			}
			var report comparisonReport
			if err := json.Unmarshal(output.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if tc.mode == "error" && report.Complete {
				t.Fatal("failed execution reported complete")
			}
			if tc.mode == "pair-difference" && report.Agreement["different"] != 1 {
				t.Fatal("interface difference missing")
			}
		})
	}
	for _, broken := range []string{"report", "summary"} {
		d, _ := fakeDocker(t, "ok", "absent", "absent")
		var output, diagnostic bytes.Buffer
		var stdout, stderr io.Writer = &output, &diagnostic
		if broken == "report" {
			stdout = brokenWriter{}
		} else {
			stderr = brokenWriter{}
		}
		if code := compareWithObserver(root, m, hash, d.pins, selectedAdapters("oletools"), d.observe, stdout, stderr); code != 2 {
			t.Fatalf("%s writer exit=%d", broken, code)
		}
	}
}
