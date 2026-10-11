package ci_test

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/cape"
)

type capeResponseCredentials struct{}

func (capeResponseCredentials) Token(context.Context, string) (string, error) {
	return "synthetic-test-token", nil
}

type capeResponseSource struct {
	io.Reader
	closes atomic.Int32
}

func (s *capeResponseSource) Close() error {
	s.closes.Add(1)
	return nil
}

// Exercise the public client over TLS; the native EOF fixtures additionally
// control cancellation at the exact last Read, which a remote peer cannot do.
func TestCAPEResponseCompletion(t *testing.T) {
	for _, mode := range []string{"complete", "malformed", "canceled", "pre-canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				if mode == "complete" {
					_, _ = io.WriteString(w, `{"error":[],"errors":[],"data":{"task_ids":[41]}}`)
					return
				}
				_, _ = io.WriteString(w, `{"data":{"task_ids":[41,42,`)
				if mode == "canceled" {
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Error(err)
					}
					cancel()
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			client, err := cape.New(cape.Config{
				Origin: server.URL, AllowedDestination: netip.MustParseAddrPort(server.Listener.Addr().String()),
				Generation: "ci-response", Machine: "one-vm", CredentialReference: "fixture-account",
				CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
			}, capeResponseCredentials{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			if mode == "pre-canceled" {
				cancel()
			}
			src := &capeResponseSource{Reader: strings.NewReader("x")}
			result, err := client.Submit(ctx, src, 1, "00112233445566778899aabbccddeeff")
			var got *cape.Error
			wantCode := cape.Protocol
			if mode == "canceled" || mode == "pre-canceled" {
				wantCode = cape.Deadline
			}
			if mode == "complete" {
				if err != nil || len(result.Tasks) != 1 || result.Tasks[0] != (cape.TaskRef{ID: 41, Generation: "ci-response"}) {
					t.Fatalf("successful response: result=%+v err=%v", result, err)
				}
			} else if !errors.As(err, &got) || got.Code != wantCode {
				t.Fatalf("response error=%v, want %s", err, wantCode)
			}
			if mode == "malformed" && (len(result.Tasks) != 2 || result.Tasks[0].ID != 41 || result.Tasks[1].ID != 42) {
				t.Fatalf("partial response lost owned task IDs: %+v", result)
			}
			preCanceled := mode == "pre-canceled"
			wantCalls := int32(1)
			if preCanceled {
				wantCalls = 0
			}
			wantDebt := mode == "malformed" || mode == "canceled"
			if result.NoBytesSent != preCanceled || result.UnknownDebt != wantDebt || src.closes.Load() != 1 || calls.Load() != wantCalls {
				t.Fatalf("response cleanup: result=%+v closes=%d calls=%d", result, src.closes.Load(), calls.Load())
			}
		})
	}
}

// Exercise stale payload rejection directly rather than depending on whether
// scheduler cancellation wins a concurrent OpenPayload race.
func TestP10CAPEOpenPayloadVersion(t *testing.T) {
	// Reuse the existing capacity seam: a test directory is not a dedicated
	// production ext4/XFS volume; private-path and database checks still run.
	t.Cleanup(cape.SetStoreCapacityForTest())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := cape.OpenStore(ctx, cape.StoreConfig{Directory: dir, Tenants: []string{"alpha"}, MaxAttachment: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	admission, err := store.Enqueue(ctx, cape.EnqueueRequest{Tenant: "alpha", Generation: "g1", SubmissionPolicy: "s1", ResultPolicy: "r1", StaticVerdict: "unknown"}, io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.BeginSubmission(ctx, "alpha", admission.Job.ID, admission.Job.Version)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := store.OpenPayload(ctx, "alpha", job.ID, job.Version-1); payload != nil || !errors.Is(err, cape.ErrConflict) {
		t.Fatalf("stale payload version: reader=%v error=%v", payload, err)
	}
	payload, err := store.OpenPayload(ctx, "alpha", job.ID, job.Version)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := payload.Close(); err != nil {
			t.Error(err)
		}
	}()
	body, err := io.ReadAll(payload)
	if err != nil || string(body) != "payload" {
		t.Fatalf("current payload version: body=%q error=%v", body, err)
	}
}
