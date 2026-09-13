//go:build linux

package cape

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestIntegrationReportAvailability follows manual admission through staged
// classification, TLS submission, status, report validation and public projection.
// An invalid report must expose unavailable evidence without lowering the current
// suspicious static concern.
func TestIntegrationReportAvailability(t *testing.T) {
	for _, mode := range []string{"valid", "malformed", "wrong_task", "wrong_hash", "missing", "oversized", "transport"} {
		t.Run(mode, func(t *testing.T) {
			const attachment = "synthetic\x00attachment\xff"
			digest := sha256.Sum256([]byte(attachment))
			var posts, statuses, reports, scans atomic.Int32
			client, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/apiv2/tasks/create/file/":
					posts.Add(1)
					if r.Method != http.MethodPost {
						t.Error("submission method is not POST")
					}
					mr, err := r.MultipartReader()
					if err != nil {
						t.Error(err)
						return
					}
					files := 0
					for {
						part, err := mr.NextPart()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Error(err)
							return
						}
						data, err := io.ReadAll(part)
						if err != nil {
							t.Error(err)
							return
						}
						if part.FormName() == "file" {
							files++
							if string(data) != attachment {
								t.Error("remote attachment differs from admitted bytes")
							}
						}
					}
					if files != 1 {
						t.Errorf("remote files=%d, want 1", files)
					}
					fmt.Fprint(w, success)
				case "/apiv2/tasks/status/41/":
					statuses.Add(1)
					fmt.Fprint(w, `{"error":false,"data":"reported"}`)
				case "/apiv2/tasks/get/report/41/json/":
					if reports.Add(1) > 1 {
						fmt.Fprintf(w, `{"info":{"id":41,"category":"file"},"target":{"category":"file","file":{"sha256":"%x"}},"signatures":[]}`, digest)
						return
					}
					if mode == "missing" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if mode == "oversized" {
						fmt.Fprint(w, strings.Repeat(" ", MaxReport+1))
						return
					}
					if mode == "transport" {
						w.Header().Set("Content-Length", "100")
						fmt.Fprint(w, "{")
						return
					}
					if mode == "malformed" {
						fmt.Fprint(w, `{"info":`)
						return
					}
					id, hash := 41, fmt.Sprintf("%x", digest)
					if mode == "wrong_task" {
						id = 42
					}
					if mode == "wrong_hash" {
						hash = strings.Repeat("0", 64)
					}
					fmt.Fprintf(w, `{"info":{"id":%d,"category":"file"},"target":{"category":"file","file":{"sha256":"%s"}},"signatures":[]}`, id, hash)
				default:
					t.Errorf("unexpected remote route %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			clock := newStoreClock()
			store := testStore(t, storeConfig(t.TempDir()), clock)
			cfg := apiFixture(t, store)
			profile := cfg.Profile
			cfg.Profile = func(ctx context.Context, tenant, name string) (APIProfile, error) {
				p, err := profile(ctx, tenant, name)
				p.Generation = client.generation
				return p, err
			}
			cfg.StaticScan = func(_ context.Context, _ string, staged io.Reader) (string, error) {
				scans.Add(1)
				data, err := io.ReadAll(staged)
				if string(data) != attachment {
					t.Error("classifier did not receive exact staged bytes")
				}
				return "suspicious", err
			}
			h, err := NewAPIHandler(cfg)
			if err != nil {
				t.Fatal(err)
			}
			admitted := apiRequest(h, http.MethodPost, JobsPath, "alpha", attachment)
			if admitted.Code != http.StatusAccepted || scans.Load() != 1 || posts.Load() != 0 {
				t.Fatalf("manual admission: status=%d scans=%d posts=%d", admitted.Code, scans.Load(), posts.Load())
			}
			location := admitted.Header().Get("Location")
			assertView := func(wantState JobState, wantEvidence string) {
				t.Helper()
				response := apiRequest(h, http.MethodGet, location, "alpha", "")
				var view APIJob
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &view) != nil {
					t.Fatalf("GET failed: %d %s", response.Code, response.Body.String())
				}
				if view.State != wantState || view.StaticVerdict != "suspicious" {
					t.Fatalf("public state/static=%s/%s, want %s/suspicious", view.State, view.StaticVerdict, wantState)
				}
				if view.Evidence != wantEvidence {
					t.Errorf("public evidence=%q, want %q after %s report", view.Evidence, wantEvidence, mode)
				}
			}
			mapper, err := NewSignatureMapper("r1", []SignatureRule{{Name: "fixture_bad", Signal: "local_bad", Evidence: EvidenceMalicious}})
			if err != nil {
				t.Fatal(err)
			}
			q := testScheduler(t, store, client, mapper, 1)
			assertView(Queued, "pending")
			schedulerRound(t, q)
			assertView(RemotePending, "pending")
			schedulerRound(t, q)
			assertView(Fetching, "pending")
			clock.advance(5 * time.Minute)
			schedulerRound(t, q)
			if posts.Load() != 1 || statuses.Load() != 1 || reports.Load() != 1 {
				t.Fatalf("remote requests POST/status/report=%d/%d/%d, want 1/1/1", posts.Load(), statuses.Load(), reports.Load())
			}
			if mode == "valid" {
				assertView(Completed, "no_signal")
			} else {
				assertView(Fetching, "unavailable")
				clock.advance(5 * time.Minute)
				schedulerRound(t, q)
				assertView(Completed, "no_signal")
				if posts.Load() != 1 || reports.Load() != 2 {
					t.Fatal("report retry replayed submission or missed safe read")
				}
			}
		})
	}
}
