package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

type capeDrainFixture struct {
	err   error
	calls int
}

func (s *capeDrainFixture) Shutdown(context.Context) error {
	s.calls++
	return s.err
}

func TestCAPEDaemonCommonDrain(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			service := &capeDrainFixture{}
			if fail {
				service.err = mailstrix.ErrCAPEDrain
			}
			drain := &adapterDrain{cape: service}
			if err := drain.shutdown(context.Background()); !errors.Is(err, service.err) {
				t.Fatal("CAPE drain result lost", err)
			}
			// A later successful owner response must not clear a failed drain.
			service.err = nil
			err := drain.shutdown(context.Background())
			if (err != nil) != fail || service.calls != 1 {
				t.Fatal("CAPE drain result was not sticky", err, service.calls)
			}
			closed := false
			drain.closeScanner(func() { closed = true })
			if closed == fail {
				t.Fatal("scanner cleanup ignored CAPE ownership", closed)
			}
		})
	}
}

func TestAdapterDrainPreservesConcurrentFailures(t *testing.T) {
	clamdErr := errors.New("clamd drain diagnostic")
	capeErr := errors.New("CAPE drain diagnostic")
	drain := &adapterDrain{
		service: &capeDrainFixture{err: clamdErr},
		cape:    &capeDrainFixture{err: capeErr},
	}
	err := drain.shutdown(context.Background())
	if !errors.Is(err, clamdErr) || !errors.Is(err, capeErr) {
		t.Fatalf("concurrent drain diagnostics were not both preserved: %v", err)
	}
	closed := false
	drain.closeScanner(func() { closed = true })
	if closed {
		t.Fatal("scanner closed after joined drain failures")
	}
}

func TestCAPEDaemonEarlyPolicyRejection(t *testing.T) {
	t.Setenv("MAILSTRIX_CAPE_CONFIG_FILE", "")
	t.Setenv("MAILSTRIX_CAPE_POLICY", "static-only")
	for _, policy := range []string{"tempfail", "quarantine-pending", "unknown"} {
		if got := cmdServe([]string{"-cape-policy", policy, "-rules", "/nonexistent/fixture.yac"}); got != 2 {
			t.Fatalf("unsupported CAPE policy not rejected before scanner startup: %s exit=%d", policy, got)
		}
	}
}

func TestCAPEDaemonDrainBudget(t *testing.T) {
	c := &mailstrix.Config{ScanTimeout: 8 * time.Second}
	if adapterDrainBudget(c) != 13*time.Second {
		t.Fatal("disabled CAPE changed drain default")
	}
	c.CAPEConfigFile = "fixture.json"
	if adapterDrainBudget(c) != 43*time.Second {
		t.Fatal("CAPE scheduler drain budget missing")
	}
}
