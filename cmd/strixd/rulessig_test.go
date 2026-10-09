package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yara "github.com/hillu/go-yara/v4"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

// The CLI verifies a remote manifest against the signing keys compiled into the
// binary, whose private halves exist only on the publisher. These tests
// therefore sign with a throwaway key and trust it the way a real operator
// would: through MAILSTRIX_RULES_EXTRA_SIGNING_KEYS, the supported additive
// trust anchor. Nothing here weakens or bypasses verification — the full
// signature gate runs, which is also what gives these tests coverage of the
// configured-key path through main.
var (
	cliSigningPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	// seed||public: the trailing 32 bytes are the public key, so no unchecked
	// type assertion on Public() is needed.
	cliSigningPub = ed25519.PublicKey(cliSigningPriv[ed25519.SeedSize:])
)

// trustCLISigningKey configures the throwaway key as an additional trust
// anchor for one test.
func trustCLISigningKey(t *testing.T) {
	t.Helper()
	t.Setenv("MAILSTRIX_RULES_EXTRA_SIGNING_KEYS", base64.StdEncoding.EncodeToString(cliSigningPub))
}

// signedManifest marshals the manifest once and returns those exact bytes with
// their detached signature, mirroring what generate-rules.sh publishes.
func signedManifest(t *testing.T, m mailstrix.RulesManifest) ([]byte, string) {
	t.Helper()
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return body, base64.StdEncoding.EncodeToString(ed25519.Sign(cliSigningPriv, body)) + "\n"
}

// serveSignedRules serves a bundle, its manifest and the detached signature.
func serveSignedRules(t *testing.T, m mailstrix.RulesManifest, bundle []byte) *httptest.Server {
	t.Helper()
	body, sig := signedManifest(t, m)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case filepath.Ext(r.URL.Path) == ".sig":
			_, _ = w.Write([]byte(sig))
		case filepath.Ext(r.URL.Path) == ".json":
			_, _ = w.Write(body)
		default:
			_, _ = w.Write(bundle)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchRulesCLIRefusesUnsignedManifest: the CLI exits non-zero and leaves
// the configured cache untouched when the publisher serves no signature.
func TestFetchRulesCLIRefusesUnsignedManifest(t *testing.T) {
	trustCLISigningKey(t)
	bundle := cliCompiledBundle(t, "rule CLIUnsigned { condition: true }")
	m := mailstrix.RulesManifest{
		Version: 7, Generated: "2026-06-18T00:00:00Z",
		Checksum: "sha256:" + cliSum(bundle), Libyara: "4.5.2", Size: int64(len(bundle)),
	}
	body, _ := signedManifest(t, m)
	// Serve manifest + bundle, but 404 the signature.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Ext(r.URL.Path) {
		case ".sig":
			w.WriteHeader(http.StatusNotFound)
		case ".json":
			_, _ = w.Write(body)
		default:
			_, _ = w.Write(bundle)
		}
	}))
	defer srv.Close()

	cache := t.TempDir()
	sentinel := filepath.Join(cache, "compiled.yac")
	if err := os.WriteFile(sentinel, []byte("installed rules"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAILSTRIX_CACHE_DIR", cache)

	if code := cmdFetchRules([]string{"-allow-http", "-url", srv.URL}); code != 2 {
		t.Fatalf("unsigned manifest accepted, exit=%d", code)
	}
	got, err := os.ReadFile(filepath.Clean(sentinel))
	if err != nil || string(got) != "installed rules" {
		t.Fatalf("installed rules were mutated by a refused update: %q %v", got, err)
	}
}

// TestFetchRulesCLIRefusesMalformedOperatorKey: an unusable configured key
// aborts the CLI instead of quietly narrowing trust to the embedded keys.
func TestFetchRulesCLIRefusesMalformedOperatorKey(t *testing.T) {
	t.Setenv("MAILSTRIX_RULES_EXTRA_SIGNING_KEYS", "not-a-key")
	bundle := cliCompiledBundle(t, "rule CLIBadKey { condition: true }")
	m := mailstrix.RulesManifest{
		Version: 7, Generated: "2026-06-18T00:00:00Z",
		Checksum: "sha256:" + cliSum(bundle), Libyara: "4.5.2", Size: int64(len(bundle)),
	}
	srv := serveSignedRules(t, m, bundle)

	cache := t.TempDir()
	t.Setenv("MAILSTRIX_CACHE_DIR", cache)
	var code int
	stderr := captureStderr(t, func() {
		code = cmdFetchRules([]string{"-allow-http", "-url", srv.URL})
	})
	if code != 2 {
		t.Fatalf("malformed configured key accepted, exit=%d", code)
	}
	// The CONFIG gate must own this refusal. Without this assertion the test
	// would also pass when the bad key is silently dropped and the manifest is
	// merely refused as untrusted later — a silent narrowing of trust, which
	// is precisely the failure this test exists to catch.
	if !strings.Contains(stderr, "MAILSTRIX_RULES_EXTRA_SIGNING_KEYS") ||
		!strings.Contains(stderr, "invalid rules signing key") {
		t.Errorf("stderr %q does not report the configured key as unusable", stderr)
	}
	// Nothing was installed on the way out.
	if _, err := os.Stat(filepath.Join(cache, "compiled.yac")); !os.IsNotExist(err) {
		t.Errorf("a bundle was installed despite an unusable key, stat err = %v", err)
	}
}

// TestFetchRulesCLIInstallsOperatorSignedBundle: the happy path through the
// configured additive trust anchor.
func TestFetchRulesCLIInstallsOperatorSignedBundle(t *testing.T) {
	trustCLISigningKey(t)
	bundle := cliCompiledBundle(t, "rule CLISigned { condition: true }")
	m := mailstrix.RulesManifest{
		Version: 11, Generated: "2026-06-18T00:00:00Z",
		Checksum: "sha256:" + cliSum(bundle), Libyara: "4.5.2", Size: int64(len(bundle)),
	}
	srv := serveSignedRules(t, m, bundle)

	cache := t.TempDir()
	t.Setenv("MAILSTRIX_CACHE_DIR", cache)
	if code := cmdFetchRules([]string{"-allow-http", "-url", srv.URL}); code != 0 {
		t.Fatalf("operator-signed bundle refused, exit=%d", code)
	}
	got, err := os.ReadFile(filepath.Join(cache, "compiled.yac")) // #nosec G304 -- test temp cache path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bundle) {
		t.Error("installed bundle does not match the published one")
	}
}

// cliCompiledBundle compiles rule source into a real .yac, so a served bundle
// passes the load-validation the updater performs before any swap.
func cliCompiledBundle(t *testing.T, rule string) []byte {
	t.Helper()
	c, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if err := c.AddString(rule, ""); err != nil {
		t.Fatal(err)
	}
	r, err := c.GetRules()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	path := filepath.Join(t.TempDir(), "compiled.yac")
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cliSum is the manifest checksum form of a bundle's bytes.
func cliSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
