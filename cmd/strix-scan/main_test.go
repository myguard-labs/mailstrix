package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// fakeYarad mimics yarad's /scan: it returns a match when the body contains the
// EICAR pattern, and records the token / filename headers for assertion.
func fakeYarad(t *testing.T, gotToken, gotName *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/scan" {
			http.NotFound(w, r)
			return
		}
		if gotToken != nil {
			*gotToken = r.Header.Get("X-MAILSTRIX-Token")
		}
		if gotName != nil {
			if raw := r.Header.Get("X-MAILSTRIX-Filename"); raw != "" {
				if dec, err := base64.StdEncoding.DecodeString(raw); err == nil {
					*gotName = string(dec)
				}
			}
		}
		body, _ := readAll(r)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "EICAR-STANDARD-ANTIVIRUS-TEST-FILE") {
			_, _ = w.Write([]byte(`{"matches":[{"rule":"EICAR_Test_File","namespace":"eicar.yar"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"matches":[]}`))
	}))
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, r.ContentLength)
	n, _ := r.Body.Read(buf)
	return buf[:n], nil
}

func writeTemp(t *testing.T, data string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "msg.eml")
	if err := os.WriteFile(f, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMatch(t *testing.T) {
	var tok, name string
	srv := fakeYarad(t, &tok, &name)
	defer srv.Close()
	f := writeTemp(t, eicar)
	code := run([]string{"-url", srv.URL, "-token", "secret", "-filename", "x.exe", "-quiet", f})
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if tok != "secret" {
		t.Errorf("token = %q", tok)
	}
	if name != "x.exe" {
		t.Errorf("filename = %q", name)
	}
}

func TestClean(t *testing.T) {
	srv := fakeYarad(t, nil, nil)
	defer srv.Close()
	f := writeTemp(t, "benign")
	if code := run([]string{"-url", srv.URL, f}); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestLogOnlyMatchesExitClean(t *testing.T) {
	for name, body := range map[string]string{
		"canary": `{"matches":[{"rule":"Shadow_Hit","meta":{"mailstrix_canary":"1"}}]}`,
		"allow":  `{"matches":[{"rule":"Noisy_Hit","meta":{"mailstrix_allow":"1"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			f := writeTemp(t, eicar)
			if code := run([]string{"-url", srv.URL, "-quiet", f}); code != 0 {
				t.Fatalf("exit = %d, want 0 for log-only match", code)
			}
		})
	}
}

func TestMixedLogOnlyAndActionableMatchesExitMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"matches":[{"rule":"Shadow","meta":{"mailstrix_canary":"1"}},{"rule":"Real"}]}`))
	}))
	defer srv.Close()
	f := writeTemp(t, eicar)
	if code := run([]string{"-url", srv.URL, "-quiet", f}); code != 1 {
		t.Fatalf("exit = %d, want 1 when any actionable match remains", code)
	}
}

func TestFailOpen(t *testing.T) {
	srv := fakeYarad(t, nil, nil)
	url := srv.URL
	srv.Close() // unreachable
	f := writeTemp(t, eicar)
	if code := run([]string{"-url", url, "-timeout", "1s", f}); code != 0 {
		t.Fatalf("exit = %d, want 0 (fail-open)", code)
	}
}

func TestFailClosed(t *testing.T) {
	srv := fakeYarad(t, nil, nil)
	url := srv.URL
	srv.Close()
	f := writeTemp(t, eicar)
	if code := run([]string{"-url", url, "-fail-open=false", "-timeout", "1s", f}); code != 2 {
		t.Fatalf("exit = %d, want 2 (fail-closed)", code)
	}
}

func TestTokenFile(t *testing.T) {
	var tok string
	srv := fakeYarad(t, &tok, nil)
	defer srv.Close()
	tf := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tf, []byte("filesecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := writeTemp(t, "benign")
	run([]string{"-url", srv.URL, "-token-file", tf, f})
	if tok != "filesecret" {
		t.Errorf("token from file = %q, want trimmed 'filesecret'", tok)
	}
}

// TestNoRedirectTokenLeak: a 3xx from the scan endpoint must not be followed, so
// the token is never copied onto the redirect target (a secret-leak vector).
func TestNoRedirectTokenLeak(t *testing.T) {
	var leaked string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-MAILSTRIX-Token")
		_, _ = w.Write([]byte(`{"matches":[]}`))
	}))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/scan", http.StatusFound)
	}))
	defer redir.Close()
	f := writeTemp(t, eicar)
	code := run([]string{"-url", redir.URL, "-token", "secret", "-fail-open=false", "-timeout", "2s", f})
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (redirect not followed => non-200)", code)
	}
	if leaked != "" {
		t.Fatalf("token leaked to redirect target: %q", leaked)
	}
}

// countingYarad records whether /scan was ever called, so the oversize tests can
// prove the client never POSTs a truncated prefix.
func countingYarad(t *testing.T, called *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"matches":[]}`))
	}))
}

// An input over -max-body must NOT be scanned as a truncated prefix. Default
// fail-open: exit 0 (clean) with a warning, and /scan is never called — a dropper
// past the cap would otherwise be silently missed.
func TestOversizeFailOpenDoesNotScan(t *testing.T) {
	var called bool
	srv := countingYarad(t, &called)
	defer srv.Close()
	f := writeTemp(t, strings.Repeat("A", 100))
	code := run([]string{"-url", srv.URL, "-max-body", "10", f})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (oversize fail-open)", code)
	}
	if called {
		t.Fatal("/scan was called on an oversized input; truncated prefix posted")
	}
}

// Fail-closed: an oversize input exits 2 (visible error for interactive triage)
// and still never posts a truncated prefix.
func TestOversizeFailClosedErrors(t *testing.T) {
	var called bool
	srv := countingYarad(t, &called)
	defer srv.Close()
	f := writeTemp(t, strings.Repeat("A", 100))
	code := run([]string{"-url", srv.URL, "-max-body", "10", "-fail-open=false", f})
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (oversize fail-closed)", code)
	}
	if called {
		t.Fatal("/scan was called on an oversized input; truncated prefix posted")
	}
}

// An input exactly at -max-body is scanned normally (boundary: the +1 read must
// not false-positive on a message that fits).
func TestExactlyMaxBodyScans(t *testing.T) {
	var called bool
	srv := countingYarad(t, &called)
	defer srv.Close()
	f := writeTemp(t, strings.Repeat("A", 10))
	code := run([]string{"-url", srv.URL, "-max-body", "10", f})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (clean)", code)
	}
	if !called {
		t.Fatal("/scan was not called for an input exactly at the cap")
	}
}

func TestStdin(t *testing.T) {
	srv := fakeYarad(t, nil, nil)
	defer srv.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString(eicar)
	w.Close()
	origIn := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origIn }()
	if code := run([]string{"-url", srv.URL, "-quiet", "-"}); code != 1 {
		t.Fatalf("stdin exit = %d, want 1", code)
	}
}

// jsonYarad returns a fixed /scan response body so the -json/-label tests can
// drive specific rule metadata shapes.
func jsonYarad(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it
// wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	out, _ := readAllReader(r)
	return out
}

func readAllReader(r *os.File) (string, error) {
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String(), nil
		}
	}
}

// A family-bearing rule (meta: family=X) -> -json emits family:"X", confidence
// "family", malicious true, exit 1.
func TestJSONFamilyBearing(t *testing.T) {
	srv := jsonYarad(t, `{"matches":[{"rule":"MALPEDIA_Win_Zeus_Auto","meta":{"family":"Zeus"}}]}`)
	defer srv.Close()
	f := writeTemp(t, eicar)
	var code int
	out := captureStdout(t, func() { code = run([]string{"-url", srv.URL, "-json", f}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, `"family":"Zeus"`) || !strings.Contains(out, `"confidence":"family"`) || !strings.Contains(out, `"malicious":true`) {
		t.Fatalf("json out = %q", out)
	}
}

// A generic/technique rule (no family meta) -> empty family, confidence "rule",
// still malicious.
func TestJSONGenericNoFamily(t *testing.T) {
	srv := jsonYarad(t, `{"matches":[{"rule":"meth_get_eip","namespace":"generic.yar"}]}`)
	defer srv.Close()
	f := writeTemp(t, eicar)
	var code int
	out := captureStdout(t, func() { code = run([]string{"-url", srv.URL, "-json", f}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, `"family":""`) || !strings.Contains(out, `"confidence":"rule"`) {
		t.Fatalf("json out = %q", out)
	}
}

// A multi-match file with one generic + one family-bearing rule picks the
// family-bearing one regardless of order.
func TestJSONMultiMatchPicksFamily(t *testing.T) {
	srv := jsonYarad(t, `{"matches":[{"rule":"http"},{"rule":"ELF_Mirai","meta":{"malware_family":"Mirai"}}]}`)
	defer srv.Close()
	f := writeTemp(t, eicar)
	var code int
	out := captureStdout(t, func() { code = run([]string{"-url", srv.URL, "-json", f}) })
	if code != 1 || !strings.Contains(out, `"family":"Mirai"`) {
		t.Fatalf("exit=%d json out = %q", code, out)
	}
}

// A clean result under -json emits malicious:false, empty family, exit 0.
func TestJSONClean(t *testing.T) {
	srv := jsonYarad(t, `{"matches":[]}`)
	defer srv.Close()
	f := writeTemp(t, "benign")
	var code int
	out := captureStdout(t, func() { code = run([]string{"-url", srv.URL, "-json", f}) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, `"malicious":false`) || !strings.Contains(out, `"family":""`) {
		t.Fatalf("json out = %q", out)
	}
}

// -label prints `LABEL <family>` for a family-bearing match and exits 1.
func TestLabelFamily(t *testing.T) {
	srv := jsonYarad(t, `{"matches":[{"rule":"x","meta":{"actor":"APT28"}}]}`)
	defer srv.Close()
	f := writeTemp(t, eicar)
	var code int
	out := captureStdout(t, func() { code = run([]string{"-url", srv.URL, "-label", f}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if strings.TrimSpace(out) != "LABEL APT28" {
		t.Fatalf("label out = %q", out)
	}
}

// -label prints nothing when no family-bearing rule matched (generic-only or
// clean), even though a generic match still exits 1.
func TestLabelNoFamilyPrintsNothing(t *testing.T) {
	srv := jsonYarad(t, `{"matches":[{"rule":"SUSP_generic"}]}`)
	defer srv.Close()
	f := writeTemp(t, eicar)
	var code int
	out := captureStdout(t, func() { code = run([]string{"-url", srv.URL, "-label", f}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("label out = %q, want empty", out)
	}
}

// Log-only canary/allow hits are dropped before the verdict, so -json on a
// canary-only response is clean.
func TestJSONDropsCanary(t *testing.T) {
	srv := jsonYarad(t, `{"matches":[{"rule":"Shadow","meta":{"mailstrix_canary":"1","family":"Ghost"}}]}`)
	defer srv.Close()
	f := writeTemp(t, eicar)
	var code int
	out := captureStdout(t, func() { code = run([]string{"-url", srv.URL, "-json", f}) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, `"malicious":false`) {
		t.Fatalf("json out = %q (canary must not produce a verdict)", out)
	}
}

// -json and -label together is a usage error (exit 2), not a silent precedence.
func TestJSONLabelMutuallyExclusive(t *testing.T) {
	srv := jsonYarad(t, `{"matches":[]}`)
	defer srv.Close()
	f := writeTemp(t, "benign")
	if code := run([]string{"-url", srv.URL, "-json", "-label", f}); code != 2 {
		t.Fatalf("exit = %d, want 2 (conflicting -json/-label)", code)
	}
}

func TestRequiresURL(t *testing.T) {
	t.Setenv("MAILSTRIX_URL", "")
	if code := run([]string{writeTemp(t, "x")}); code != 2 {
		t.Fatalf("exit = %d, want 2 (missing -url)", code)
	}
}
