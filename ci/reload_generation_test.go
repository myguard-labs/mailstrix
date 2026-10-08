package ci

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func reloadWrite(t *testing.T, path, source string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
}

// Retains the first two regression schedules: the synchronous main-load log
// callback pauses preparation before big/marker/content publication completes.
func TestReloadGenerationPublication(t *testing.T) {
	for _, renamed := range []bool{false, true} {
		name := "same_name_cache"
		if renamed {
			name = "fingerprint_pair"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "generation.yar")
			reloadWrite(t, path, "rule Stable { condition: false }")
			armed := atomic.Bool{}
			reached, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			var release sync.Once
			cfg := &ms.Config{RulesDir: dir, Token: "generation-test", CacheTTL: time.Hour, CacheSize: 10}
			s, err := ms.NewScanner(cfg, func(format string, _ ...any) {
				if armed.Load() && strings.HasPrefix(format, "loaded %d YARA rules from") {
					close(reached)
					<-resume
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			defer release.Do(func() { close(resume) })
			srv := ms.NewServer(cfg, s)
			request := func(want int, hit bool) {
				t.Helper()
				r := httptest.NewRequest("POST", "/scan", strings.NewReader("ordinary reload fixture"))
				r.Header.Set("X-MAILSTRIX-Token", "generation-test")
				r.Header.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
				w := httptest.NewRecorder()
				srv.ServeHTTP(w, r)
				var response struct {
					Matches []ms.Match `json:"matches"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if w.Code != 200 || len(response.Matches) != want || (w.Header().Get("X-MAILSTRIX-Cache") == "hit") != hit {
					t.Fatalf("HTTP generation mismatch: status=%d matches=%v cache=%q, want %d hit=%v", w.Code, response.Matches, w.Header().Get("X-MAILSTRIX-Cache"), want, hit)
				}
			}
			request(0, false)
			request(0, true)
			oldFP := s.Fingerprint()
			source := "rule Stable { condition: true }"
			if renamed {
				source = "rule NewIdentity { condition: true }"
			}
			reloadWrite(t, path, source)
			armed.Store(true)
			go func() { defer close(done); done <- s.Reload() }()
			t.Cleanup(func() {
				release.Do(func() { close(resume) })
				<-done
			})
			select {
			case <-reached:
			case <-time.After(10 * time.Second):
				t.Fatal("reload did not reach publication witness")
			}
			if got := s.Fingerprint(); got != oldFP {
				t.Errorf("torn generation during preparation: got %s want %s", got, oldFP)
			}
			matches, err := s.Scan([]byte("ordinary reload fixture"), ms.ScanMeta{})
			if err != nil || len(matches) != 0 {
				t.Errorf("rules changed before complete publication: %v %v", matches, err)
			}
			request(0, true)
			release.Do(func() { close(resume) })
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if s.Fingerprint() == oldFP {
				t.Fatal("complete generation did not change fingerprint")
			}
			request(1, false)
			request(1, true)
		})
	}
}

func TestReloadGenerationFailureAndDenyPolicy(t *testing.T) {
	dir := t.TempDir()
	path, denyPath := filepath.Join(dir, "generation.yar"), filepath.Join(dir, "deny.txt")
	source := "rule First { condition: true } rule Second { condition: true }"
	reloadWrite(t, path, source)
	reloadWrite(t, denyPath, "first\n")
	cfg := &ms.Config{RulesDir: dir, DenylistFile: denyPath}
	s, err := ms.NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	check := func(want string) {
		t.Helper()
		matches, err := s.Scan([]byte("ordinary fixture"), ms.ScanMeta{})
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, m := range matches {
			names = append(names, m.Rule)
		}
		if got := strings.Join(names, ","); got != want {
			t.Fatalf("generation names=%q want=%q", got, want)
		}
	}
	check("Second")
	oldFP := s.Fingerprint()
	// A malformed main load keeps service and the existing generation identity.
	reloadWrite(t, path, "not a YARA rule")
	if err := s.Reload(); err == nil {
		t.Fatal("malformed reload succeeded")
	}
	if s.Fingerprint() != oldFP {
		t.Fatal("failed main reload changed generation")
	}
	check("Second")
	// Preserve the previous failure policy: post-filter changes still apply;
	// previously pre-disabled native rules cannot be re-enabled by a failed load.
	reloadWrite(t, denyPath, "second\n")
	// Main rules are still malformed: ReloadAll fails, but the deny update applies.
	if err := s.ReloadAll(); err == nil {
		t.Fatal("ReloadAll with malformed main rules succeeded")
	}
	check("")
	failedFP := s.Fingerprint()
	if failedFP == oldFP {
		t.Fatal("effective deny update kept old cache identity")
	}
	reloadWrite(t, path, source)
	if err := s.ReloadAll(); err != nil {
		t.Fatal(err)
	}
	check("First")
	if s.Fingerprint() == failedFP {
		t.Fatal("successful native re-enable shared failed-reload identity")
	}
	// Missing deny file retains the last working policy and native generation.
	goodFP := s.Fingerprint()
	if err := os.Remove(denyPath); err != nil {
		t.Fatal(err)
	}
	if err := s.ReloadAll(); err != nil {
		t.Fatal(err)
	}
	check("First")
	if s.Fingerprint() != goodFP {
		t.Fatal("missing deny file changed the active generation")
	}
}
