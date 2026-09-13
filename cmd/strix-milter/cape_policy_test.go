package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCAPEMilterStartupPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, env    string
		flags        []string
		valid        bool
		missingToken bool
	}{
		{name: "default", valid: true},
		{name: "empty", flags: []string{"-cape-policy="}, valid: true},
		{name: "static", flags: []string{"-cape-policy=static-only"}, valid: true},
		{name: "env-static", env: "static-only", valid: true},
		{name: "override", env: "tempfail", flags: []string{"-cape-policy="}, valid: true},
		{name: "quarantine", flags: []string{"-cape-policy=quarantine-pending"}},
		{name: "tempfail", flags: []string{"-cape-policy=tempfail"}},
		{name: "unknown", flags: []string{"-cape-policy=typo"}},
		{name: "boolean", flags: []string{"-cape-policy=false"}},
		{name: "whitespace", flags: []string{"-cape-policy= static-only"}},
		{name: "env-invalid", env: "tempfail"},
		{name: "policy-before-token", flags: []string{"-cape-policy=tempfail"}, missingToken: true},
		{name: "policy-before-listen", flags: []string{"-cape-policy=tempfail", "-listen=invalid-protocol:"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MAILSTRIX_CAPE_POLICY", tc.env)
			t.Setenv("MAILSTRIX_TOKEN", "")
			bound := false
			serveListenerHook = func(ln net.Listener) { bound = true; _ = ln.Close() }
			t.Cleanup(func() { serveListenerHook = nil })
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			previousStderr := os.Stderr
			os.Stderr = w
			defer func() { os.Stderr = previousStderr; _ = w.Close() }()
			args := []string{"-url=http://127.0.0.1:1", "-listen=unix:" + filepath.Join(t.TempDir(), "milter.sock")}
			if tc.missingToken {
				// Only a synthetic nonexistent path: resolving it first would return
				// a token error and mask the policy-specific startup rejection.
				args = append(args, "-token-file="+filepath.Join(t.TempDir(), "absent-token"))
			}
			got := run(append(args, tc.flags...))
			_ = w.Close()
			os.Stderr = previousStderr
			output, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if tc.valid {
				if got != 0 || !bound {
					t.Fatalf("supported startup: exit=%d bound=%v output=%s", got, bound, output)
				}
			} else if got != 2 || bound || !strings.Contains(string(output), "unsupported sandbox policy") {
				t.Fatalf("unsupported policy must reject before listening: exit=%d bound=%v output=%s", got, bound, output)
			}
		})
	}
}
