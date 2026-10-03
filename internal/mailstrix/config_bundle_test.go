package mailstrix

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// TestValidateSecrets (COR-16): an unreadable *_FILE fails startup and names
// only the variable; unset and readable files pass.
func TestValidateSecrets(t *testing.T) {
	for _, n := range secretFileVars {
		t.Setenv(n+"_FILE", "")
	}
	if err := ValidateSecrets(); err != nil {
		t.Fatalf("unset: %v", err)
	}
	good := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(good, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAILSTRIX_TOKEN_FILE", good)
	if err := ValidateSecrets(); err != nil {
		t.Fatalf("readable: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	t.Setenv("MAILSTRIX_URLHAUS_KEY_FILE", missing)
	err := ValidateSecrets()
	if !errors.Is(err, ErrSecretFile) || !strings.Contains(err.Error(), "MAILSTRIX_URLHAUS_KEY_FILE") {
		t.Fatalf("unreadable: %v", err)
	}
	if strings.Contains(err.Error(), missing) {
		t.Fatalf("error leaks the path: %v", err)
	}
}

// TestEnvNumbersWarnOnGarbage (COR-20): non-numeric, NaN and Inf values keep
// the default and log a warning; valid values and unset vars stay silent.
func TestEnvNumbersWarnOnGarbage(t *testing.T) {
	buf := captureLog(t)
	t.Setenv("MX_T_INT", "8s")
	if got := envInt("MX_T_INT", 7); got != 7 {
		t.Errorf("envInt = %d", got)
	}
	t.Setenv("MX_T_I64", "1e3")
	if got := envInt64("MX_T_I64", 9); got != 9 {
		t.Errorf("envInt64 = %d", got)
	}
	for _, raw := range []string{"1h", "NaN", "Inf", "-inf"} {
		t.Setenv("MX_T_DUR", raw)
		if got := envDur("MX_T_DUR", 3); got != 3*time.Second {
			t.Errorf("envDur(%q) = %v", raw, got)
		}
	}
	if n := strings.Count(buf.String(), "WARNING: invalid MX_T_"); n != 6 {
		t.Errorf("warnings = %d, want 6:\n%s", n, buf.String())
	}
	buf.Reset()
	t.Setenv("MX_T_DUR", "2.5")
	t.Setenv("MX_T_INT", "")
	if envDur("MX_T_DUR", 3) != 2500*time.Millisecond || envInt("MX_T_INT", 4) != 4 || buf.Len() != 0 {
		t.Errorf("valid/unset values changed or warned: %q", buf.String())
	}
}

// TestHTTPWriteTimeoutCoversScan (COR-18): the write deadline grows with
// ScanTimeout, so a long scan still gets its verdict written.
func TestHTTPWriteTimeoutCoversScan(t *testing.T) {
	s := &Server{cfg: &Config{BackendTimeout: time.Second, ScanTimeout: 40 * time.Second}}
	if got := s.httpWriteTimeout(); got <= 41*time.Second {
		t.Fatalf("write timeout %v does not cover a 40s scan", got)
	}
}
