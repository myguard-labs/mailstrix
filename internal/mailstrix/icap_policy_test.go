package mailstrix

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
)

func TestCAPEICAPStartupPolicy(t *testing.T) {
	for _, policy := range []string{"", "static-only", "quarantine-pending", "tempfail", "typo", "false", " static-only"} {
		t.Run(policy, func(t *testing.T) {
			// A cancelled context stops supported startup immediately after binding;
			// unsupported policy must fail before any listener is published.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			s := &Server{cfg: &Config{ICAPAddr: "127.0.0.1:0", CAPEPolicy: policy}, info: log.New(io.Discard, "", 0)}
			err := s.ListenAndServeICAP(ctx)
			bound := s.icapLn.Load() != nil
			if policy == "" || policy == "static-only" {
				if err != nil || !bound {
					t.Fatalf("supported startup: err=%v bound=%v", err, bound)
				}
			} else if err == nil || !strings.Contains(err.Error(), "unsupported sandbox policy") || bound {
				t.Fatalf("unsupported policy must reject before listening: err=%v bound=%v", err, bound)
			}
		})
	}
}

func TestCAPEICAPPolicyBeforeListen(t *testing.T) {
	// The malformed address cannot bind, even with the policy check moved after
	// net.Listen. Assert the policy-specific error rather than a generic failure.
	s := &Server{cfg: &Config{ICAPAddr: "invalid-address", CAPEPolicy: "tempfail"}}
	err := s.ListenAndServeICAP(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unsupported sandbox policy") || s.icapLn.Load() != nil {
		t.Fatalf("policy must reject before malformed bind address: err=%v", err)
	}
}
