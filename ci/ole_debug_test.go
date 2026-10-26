package ci_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"www.velocidex.com/golang/oleparse"
)

const (
	oleDebugChildEnv    = "MAILSTRIX_OLE_DEBUG_TEST_CHILD"
	oleDebugExpectedEnv = "MAILSTRIX_OLE_DEBUG_TEST_EXPECTED"
	oleDebugOverrideEnv = "MAILSTRIX_OLE_DEBUG_TEST_OVERRIDE"
)

func TestOLEDebugFreshProcess(t *testing.T) {
	tests := []struct {
		name     string
		envValue *string
		override string
		want     bool
	}{
		{name: "unset", want: false},
		{name: "enabled", envValue: stringPtr("1"), want: true},
		{name: "disabled", envValue: stringPtr("0"), want: false},
		{name: "malformed-disabled", envValue: stringPtr("true"), want: false},
		// Preserve the replaced module's historical prefix match. Tightening the
		// parser is a separate compatibility change, not part of the race repair.
		{name: "malformed-enabled-prefix", envValue: stringPtr("1garbage"), want: true},
		{name: "explicit-enabled-override", override: "true", want: true},
		{name: "explicit-disabled-override", envValue: stringPtr("1"), override: "false", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestOLEDebugFreshProcessChild$")
			cmd.Env = withoutEnvironment(os.Environ(),
				"OLE_DEBUG", oleDebugChildEnv, oleDebugExpectedEnv, oleDebugOverrideEnv,
			)
			cmd.Env = append(cmd.Env,
				oleDebugChildEnv+"=1",
				fmt.Sprintf("%s=%t", oleDebugExpectedEnv, test.want),
			)
			if test.envValue != nil {
				cmd.Env = append(cmd.Env, "OLE_DEBUG="+*test.envValue)
			}
			if test.override != "" {
				cmd.Env = append(cmd.Env, oleDebugOverrideEnv+"="+test.override)
			}

			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("fresh-process debug check failed: %v\n%s", err, output)
			}
		})
	}
}

func TestOLEDebugFreshProcessChild(t *testing.T) {
	if os.Getenv(oleDebugChildEnv) != "1" {
		t.Skip("helper process")
	}

	want := os.Getenv(oleDebugExpectedEnv) == "true"
	switch os.Getenv(oleDebugOverrideEnv) {
	case "true":
		value := true
		oleparse.OLE_DEBUG = &value
	case "false":
		value := false
		oleparse.OLE_DEBUG = &value
	}

	const (
		workers    = 32
		iterations = 100
	)
	start := make(chan struct{})
	results := make(chan bool, workers*iterations)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for range iterations {
				results <- oleparse.DebugEnabled()
			}
		}()
	}
	close(start)
	group.Wait()
	close(results)

	for got := range results {
		if got != want {
			t.Fatalf("DebugEnabled() = %t, want %t", got, want)
		}
	}
}

func stringPtr(value string) *string {
	return &value
}

func withoutEnvironment(environment []string, keys ...string) []string {
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		keep := true
		for _, key := range keys {
			if strings.HasPrefix(entry, key+"=") {
				keep = false
				break
			}
		}
		if keep {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
