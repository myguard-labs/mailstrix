package mailstrix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	yara "github.com/hillu/go-yara/v4"
)

// nRules returns YARA source defining n always-true rules.
func nRules(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "rule R%d { condition: true }\n", i)
	}
	return b.String()
}

func TestCheckRuleCountDrop(t *testing.T) {
	bg := context.Background()
	allow := WithAllowRuleCountDrop(bg)
	cases := []struct {
		name     string
		ctx      context.Context
		cur, new int
		refuse   bool
	}{
		{"unchanged", bg, 10, 10, false},
		{"increase", bg, 10, 30, false},
		{"small decrease", bg, 10, 9, false},
		{"exactly 50 percent", bg, 10, 5, false},
		{"just below 50 percent", bg, 10, 4, true},
		{"odd boundary accepted", bg, 11, 6, false},
		{"odd boundary refused", bg, 11, 5, true},
		{"first install", bg, 0, 3, false},
		{"first install zero refused", bg, 0, 0, true},
		{"zero over current refused", bg, 10, 0, true},
		{"negative count refused", bg, 10, -1, true},
		{"opt-in accepts sharp drop", allow, 10, 1, false},
		{"opt-in accepts zero", allow, 10, 0, false},
		{"opt-in first install zero", allow, 0, 0, false},
	}
	for _, tc := range cases {
		err := checkRuleCountDrop(tc.ctx, tc.cur, tc.new)
		if (err != nil) != tc.refuse {
			t.Errorf("%s: err=%v, refuse=%v", tc.name, err, tc.refuse)
		}
		if err != nil && !errors.Is(err, ErrRuleCountDrop) {
			t.Errorf("%s: error %v does not wrap ErrRuleCountDrop", tc.name, err)
		}
	}
}

func TestRulesBundleCountCountsLoadedRules(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.yac")
	compiledYac(t, p, nRules(3))
	if n, err := rulesBundleCount(p); err != nil || n != 3 {
		t.Fatalf("count=%d err=%v, want 3", n, err)
	}
	if _, err := rulesBundleCount(filepath.Join(t.TempDir(), "missing.yac")); err == nil {
		t.Fatal("missing bundle must error")
	}
	bad := filepath.Join(t.TempDir(), "bad.yac")
	if err := os.WriteFile(bad, []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rulesBundleCount(bad); err == nil {
		t.Fatal("malformed bundle must error")
	}
}

// seedCountCache installs an N-rule verified bundle at version 1.
func seedCountCache(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	seedVerifiedWithGenerated(t, dir, 1, nRules(n), testRulesManifestGenerated)
	return dir
}

func fetchWith(t *testing.T, ctx context.Context, dir string, newRules int) (FetchResult, string, error) {
	t.Helper()
	srv := rulesServer(t, compiledYacBytes(t, nRules(newRules)), 2, "4.5.2", "")
	defer srv.Close()
	res, err := FetchRules(ctx, srv.URL, dir, "4.5.2", srv.Client(), true)
	return res, srv.URL, err
}

func TestFetchRulesCountDrop(t *testing.T) {
	bg := context.Background()
	cases := []struct {
		name      string
		cur, new  int
		ctx       context.Context
		wantApply bool
	}{
		{"normal update", 4, 4, bg, true},
		{"small decrease", 10, 9, bg, true},
		{"increase", 4, 8, bg, true},
		{"exactly 50 percent", 10, 5, bg, true},
		{"sharp drop refused", 10, 4, bg, false},
		{"zero rules refused", 4, 0, bg, false},
		{"opt-in accepts drop", 10, 1, WithAllowRuleCountDrop(bg), true},
		{"opt-in accepts zero", 4, 0, WithAllowRuleCountDrop(bg), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := seedCountCache(t, tc.cur)
			before := readRuleFile(t, filepath.Join(dir, cachedRulesName))
			res, _, err := fetchWith(t, tc.ctx, dir, tc.new)
			after := readRuleFile(t, filepath.Join(dir, cachedRulesName))
			if tc.wantApply {
				if err != nil || !res.Updated || res.NewVersion != 2 {
					t.Fatalf("res=%+v err=%v, want installed v2", res, err)
				}
				return
			}
			if !errors.Is(err, ErrRuleCountDrop) || res.Updated {
				t.Fatalf("res=%+v err=%v, want ErrRuleCountDrop", res, err)
			}
			if string(before) != string(after) {
				t.Fatal("current bundle was replaced despite refusal")
			}
			if v := readLocalManifest(filepath.Join(dir, manifestName)).Version; v != 1 {
				t.Fatalf("local manifest version=%d, want 1 retained", v)
			}
		})
	}
}

func TestFetchRulesFirstInstallOnlyZeroRefused(t *testing.T) {
	if res, _, err := fetchWith(t, context.Background(), t.TempDir(), 1); err != nil || !res.Updated {
		t.Fatalf("first install of 1 rule: res=%+v err=%v", res, err)
	}
	dir := t.TempDir()
	_, _, err := fetchWith(t, context.Background(), dir, 0)
	if !errors.Is(err, ErrRuleCountDrop) {
		t.Fatalf("first install of 0 rules: err=%v", err)
	}
	if fileExists(filepath.Join(dir, cachedRulesName)) {
		t.Fatal("zero-rule bundle installed on first run")
	}
}

func countUpdater(t *testing.T, url string, cur int, allow bool) *RulesUpdater {
	t.Helper()
	dir := seedCountCache(t, cur)
	cfg := &Config{CacheDir: dir, RulesPath: filepath.Join(dir, cachedRulesName), RulesPollInterval: time.Minute, RulesURL: url, RulesAllowHTTP: true, ScanTimeout: time.Second, AllowRulesCountDrop: allow}
	cfg.Finalize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	srv := NewServer(cfg, s)
	u, err := NewRulesUpdater(cfg, s, "4.5.2", srv.FlushCache)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestRulesUpdaterRefusesCountDropAndReportsState(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, nRules(2)), 2, "4.5.2", "")
	defer source.Close()
	u := countUpdater(t, source.URL, 10, false)
	err := u.Poll(context.Background())
	if !errors.Is(err, ErrRuleCountDrop) {
		t.Fatalf("poll err=%v, want ErrRuleCountDrop", err)
	}
	s := u.Snapshot()
	if s.CountDropRefusals != 1 || s.Failures != 1 || s.LastRefusal == "" || s.LoadedVersion != 1 || s.CachedVersion != 1 {
		t.Fatalf("state=%+v", s)
	}
	if got := u.scanner.RuleCount(); got != 10 {
		t.Fatalf("active rules=%d, want 10 retained", got)
	}
}

func TestRulesUpdaterAllowsCountDropWithOptIn(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, nRules(2)), 2, "4.5.2", "")
	defer source.Close()
	u := countUpdater(t, source.URL, 10, true)
	if err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := u.Snapshot(); s.LoadedVersion != 2 || s.CountDropRefusals != 0 {
		t.Fatalf("state=%+v", s)
	}
	if got := u.scanner.RuleCount(); got != 2 {
		t.Fatalf("active rules=%d, want 2", got)
	}
}

func TestRulesUpdaterAcceptsNormalUpdate(t *testing.T) {
	source := rulesServer(t, compiledYacBytes(t, nRules(9)), 2, "4.5.2", "")
	defer source.Close()
	u := countUpdater(t, source.URL, 10, false)
	if err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := u.scanner.RuleCount(); got != 9 {
		t.Fatalf("active rules=%d, want 9", got)
	}
}

func TestAllowRulesCountDropEnv(t *testing.T) {
	t.Setenv("MAILSTRIX_RULES_ALLOW_COUNT_DROP", "")
	if LoadConfig().AllowRulesCountDrop {
		t.Fatal("default must be off")
	}
	t.Setenv("MAILSTRIX_RULES_ALLOW_COUNT_DROP", "1")
	if !LoadConfig().AllowRulesCountDrop {
		t.Fatal("env 1 must enable")
	}
	t.Setenv("MAILSTRIX_RULES_ALLOW_COUNT_DROP", "nope")
	if LoadConfig().AllowRulesCountDrop {
		t.Fatal("malformed value must stay off")
	}
}

// captureStdLog redirects the standard logger and returns the buffer.
func captureStdLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestFetchRulesMissingManifestLargeBundleRefusesTinyDownload(t *testing.T) {
	dir := seedCountCache(t, 10)
	if err := os.Remove(filepath.Join(dir, manifestName)); err != nil {
		t.Fatal(err)
	}
	before := readRuleFile(t, filepath.Join(dir, cachedRulesName))
	res, _, err := fetchWith(t, context.Background(), dir, 1)
	if !errors.Is(err, ErrRuleCountDrop) || res.Updated {
		t.Fatalf("res=%+v err=%v, want ErrRuleCountDrop", res, err)
	}
	if string(before) != string(readRuleFile(t, filepath.Join(dir, cachedRulesName))) {
		t.Fatal("large bundle replaced despite missing-manifest guard")
	}
	// Boundary: exactly 50% and a normal size are accepted with the same state.
	for _, n := range []int{5, 10} {
		d := seedCountCache(t, 10)
		_ = os.Remove(filepath.Join(d, manifestName))
		if res, _, err := fetchWith(t, context.Background(), d, n); err != nil || !res.Updated {
			t.Fatalf("n=%d res=%+v err=%v, want installed", n, res, err)
		}
	}
	// Override still allows the shrink.
	d := seedCountCache(t, 10)
	_ = os.Remove(filepath.Join(d, manifestName))
	if res, _, err := fetchWith(t, WithAllowRuleCountDrop(context.Background()), d, 1); err != nil || !res.Updated {
		t.Fatalf("override: res=%+v err=%v", res, err)
	}
}

func TestFetchRulesUnreadableExistingBundleFailsClosed(t *testing.T) {
	buf := captureStdLog(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, cachedRulesName)
	if err := os.WriteFile(bad, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _, err := fetchWith(t, context.Background(), dir, 3)
	if !errors.Is(err, ErrRuleCountDrop) || res.Updated {
		t.Fatalf("res=%+v err=%v, want ErrRuleCountDrop", res, err)
	}
	// The underlying load failure stays reachable (multi-%w), not just text.
	_, cause := rulesBundleCount(bad)
	if cause == nil || !errors.Is(err, cause) {
		t.Fatalf("underlying cause %v not wrapped in %v", cause, err)
	}
	var ye yara.Error
	if !errors.As(err, &ye) {
		t.Fatalf("no yara.Error reachable via errors.As in %v", err)
	}
	if !strings.Contains(buf.String(), "WARNING: existing rules bundle") {
		t.Fatalf("no warning logged: %q", buf.String())
	}
	if string(readRuleFile(t, bad)) != "corrupt" {
		t.Fatal("unreadable bundle was replaced without override")
	}
	// Override installs over it (and still warns).
	if res, _, err := fetchWith(t, WithAllowRuleCountDrop(context.Background()), dir, 3); err != nil || !res.Updated {
		t.Fatalf("override: res=%+v err=%v", res, err)
	}
}

func TestFetchRulesLiveCountFloorsBaseline(t *testing.T) {
	cases := []struct {
		name     string
		corrupt  bool // existing bundle unreadable (else absent)
		live, in int
		wantErr  bool
	}{
		{"absent bundle, live 10, new 1 refused", false, 10, 1, true},
		{"absent bundle, live 10, new 5 boundary ok", false, 10, 5, false},
		{"absent bundle, live 0, new 1 first install", false, 0, 1, false},
		{"negative live treated as none", false, -3, 1, false},
		{"unreadable, live 10, new 1 refused", true, 10, 1, true},
		{"unreadable, live 2, new 2 heals", true, 2, 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			captureStdLog(t)
			dir := t.TempDir()
			if tc.corrupt {
				if err := os.WriteFile(filepath.Join(dir, cachedRulesName), []byte("corrupt"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			srv := rulesServer(t, compiledYacBytes(t, nRules(tc.in)), 2, "4.5.2", "")
			defer srv.Close()
			res, err := fetchRules(context.Background(), srv.URL, dir, "4.5.2", srv.Client(), true, 0, tc.live, nil)
			if tc.wantErr {
				if !errors.Is(err, ErrRuleCountDrop) || res.Updated {
					t.Fatalf("res=%+v err=%v, want ErrRuleCountDrop", res, err)
				}
				return
			}
			if err != nil || !res.Updated {
				t.Fatalf("res=%+v err=%v, want installed", res, err)
			}
		})
	}
}

func TestRulesUpdaterFloorsBaselineWithLiveScannerCount(t *testing.T) {
	captureStdLog(t)
	source := rulesServer(t, compiledYacBytes(t, nRules(1)), 2, "4.5.2", "")
	defer source.Close()
	u := countUpdater(t, source.URL, 10, false)
	// Cache bundle and manifest vanish/corrupt after the scanner loaded 10 rules.
	cache := filepath.Join(u.scanner.cacheDir, cachedRulesName)
	if err := os.WriteFile(cache, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(u.scanner.cacheDir, manifestName)); err != nil {
		t.Fatal(err)
	}
	if err := u.Poll(context.Background()); !errors.Is(err, ErrRuleCountDrop) {
		t.Fatalf("poll err=%v, want ErrRuleCountDrop", err)
	}
	if got := u.scanner.RuleCount(); got != 10 {
		t.Fatalf("active rules=%d, want 10 retained", got)
	}
}
