package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/rulespin"
)

// testKeyPEM returns a throwaway ed25519 PKCS#8 PEM key and its public half.
func testKeyPEM(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), pub
}

// TestSignProducesVerifiableDetachedSignature is the end-to-end contract: what
// the signer writes must verify, as base64 raw ed25519, over the EXACT manifest
// bytes — the same predicate the client applies.
func TestSignProducesVerifiableDetachedSignature(t *testing.T) {
	keyPEM, pub := testKeyPEM(t)
	t.Setenv(signingKeyEnv, keyPEM)

	dir := t.TempDir()
	manifest := filepath.Join(dir, "compiled.yac.manifest.json")
	body := []byte(`{"version":42,"checksum":"sha256:deadbeef"}`)
	if err := os.WriteFile(manifest, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sigPath := manifest + ".sig"
	if err := run([]string{"-manifest", manifest, "-out", sigPath}, os.Stdout); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(sigPath) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, body, sig) {
		t.Fatal("published signature does not verify over the manifest bytes")
	}
	// A single trailing byte change must invalidate it.
	if ed25519.Verify(pub, append(body, '\n'), sig) {
		t.Fatal("signature verified over different bytes")
	}
	// The manifest itself must be untouched.
	after, err := os.ReadFile(manifest) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, body) {
		t.Fatal("signing rewrote the manifest; the signed bytes would not be the published bytes")
	}
}

// TestPrintPublicMatchesKey lets a publisher confirm the key matches the pin
// compiled into the client.
func TestPrintPublicMatchesKey(t *testing.T) {
	keyPEM, pub := testKeyPEM(t)
	t.Setenv(signingKeyEnv, keyPEM)

	out := filepath.Join(t.TempDir(), "pub.txt")
	f, err := os.Create(out) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-print-public"}, f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != base64.StdEncoding.EncodeToString(pub) {
		t.Fatalf("printed public key %q != expected", strings.TrimSpace(string(got)))
	}
}

// TestLoadSigningKeyRejects covers every bad key shape and asserts no message
// leaks key material.
func TestLoadSigningKeyRejects(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}))
	goodPEM, _ := testKeyPEM(t)

	cases := map[string]string{
		"empty":           "",
		"not pem":         "this is not a pem block",
		"wrong type":      string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})),
		"bad der":         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})),
		"rsa not ed25519": rsaPEM,
		"truncated pem":   goodPEM[:len(goodPEM)/2],
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadSigningKey(text)
			if err == nil {
				t.Fatal("accepted an unusable signing key")
			}
			if !strings.Contains(err.Error(), signingKeyEnv) {
				t.Errorf("error %v does not name the variable", err)
			}
			// No base64/PEM body may appear in the message.
			for _, line := range strings.Split(text, "\n") {
				if l := strings.TrimSpace(line); len(l) > 16 && !strings.HasPrefix(l, "-----") {
					if strings.Contains(err.Error(), l) {
						t.Errorf("error message leaked key material: %v", err)
					}
				}
			}
		})
	}
}

// TestRunRejectsBadInvocation: the key must never be passable as an argument,
// an empty manifest is never signed, and -manifest is required.
func TestRunRejectsBadInvocation(t *testing.T) {
	keyPEM, _ := testKeyPEM(t)
	t.Setenv(signingKeyEnv, keyPEM)

	if err := run(nil, os.Stdout); err == nil {
		t.Error("missing -manifest accepted")
	}
	// A positional argument — the shape a "key on the command line" mistake
	// takes — is refused rather than silently ignored, and the message says
	// where the key is actually read from.
	if err := run([]string{"-manifest", "x", "some-stray-value"}, os.Stdout); err == nil {
		t.Error("positional argument accepted")
	} else if !strings.Contains(err.Error(), "argv") {
		t.Errorf("error = %v, want it to explain the key comes from the environment", err)
	}
	// A PEM-looking argument cannot be parsed as a flag either, so a key
	// pasted onto the command line never reaches the signer -- and, critically,
	// no part of it may appear in the error, which main prints to stderr.
	err := run([]string{"-manifest", "x", keyPEM}, os.Stdout)
	if err == nil {
		t.Fatal("PEM-shaped argument accepted")
	}
	assertNoKeyMaterial(t, err.Error(), keyPEM)

	empty := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-manifest", empty}, os.Stdout); err == nil {
		t.Error("signed an empty manifest")
	}

	if err := run([]string{"-manifest", filepath.Join(t.TempDir(), "absent.json")}, os.Stdout); err == nil {
		t.Error("signed a missing manifest")
	}
}

// TestSigningRequiresConfiguredKey: with no key set, nothing is produced.
func TestSigningRequiresConfiguredKey(t *testing.T) {
	t.Setenv(signingKeyEnv, "")
	dir := t.TempDir()
	manifest := filepath.Join(dir, "m.json")
	if err := os.WriteFile(manifest, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sigPath := manifest + ".sig"
	if err := run([]string{"-manifest", manifest, "-out", sigPath}, os.Stdout); err == nil {
		t.Fatal("signed without a configured key")
	}
	if _, err := os.Stat(sigPath); !os.IsNotExist(err) {
		t.Errorf("a signature file was created without a key, stat err = %v", err)
	}
}

// assertNoKeyMaterial fails when any non-delimiter line of the PEM key appears
// in text. A parse or validation error is printed to stderr by main and ends up
// in CI logs, so leaking even one base64 line of the private key is a defect.
func assertNoKeyMaterial(t *testing.T, text, keyPEM string) {
	t.Helper()
	for _, line := range strings.Split(keyPEM, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "-----") {
			continue
		}
		if strings.Contains(text, l) {
			t.Errorf("error text leaked private-key material: %q", text)
		}
		// Even a fragment is too much.
		if len(l) >= 16 && strings.Contains(text, l[:16]) {
			t.Errorf("error text leaked a private-key fragment: %q", text)
		}
	}
}

// TestFlagErrorsNeverEchoArgv: no argument-parsing failure may quote argv,
// because a key pasted onto the command line is the exact mistake that would
// otherwise end up in a terminal or CI log.
func TestFlagErrorsNeverEchoArgv(t *testing.T) {
	keyPEM, _ := testKeyPEM(t)
	t.Setenv(signingKeyEnv, keyPEM)

	for name, args := range map[string][]string{
		"pem as positional": {"-manifest", "x", keyPEM},
		"pem as flag":       {keyPEM},
		"unknown flag":      {"-not-a-flag=" + keyPEM},
		"missing value":     {"-manifest"},
	} {
		t.Run(name, func(t *testing.T) {
			err := run(args, os.Stdout)
			if err == nil {
				t.Fatal("bad invocation accepted")
			}
			assertNoKeyMaterial(t, err.Error(), keyPEM)
			if strings.Contains(err.Error(), "-----BEGIN") {
				t.Errorf("error text echoed the PEM header: %q", err)
			}
		})
	}
}

// TestRequireTrustedRejectsUnpinnedKey: signing with a key the client does not
// trust must fail BEFORE a signature is produced, because publishing under it
// would make every client refuse the update.
func TestRequireTrustedRejectsUnpinnedKey(t *testing.T) {
	keyPEM, pub := testKeyPEM(t)
	t.Setenv(signingKeyEnv, keyPEM)

	dir := t.TempDir()
	manifest := filepath.Join(dir, "m.json")
	if err := os.WriteFile(manifest, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sigPath := manifest + ".sig"

	err := run([]string{"-require-trusted", "-manifest", manifest, "-out", sigPath}, os.Stdout)
	if err == nil {
		t.Fatal("signed with a key no client trusts")
	}
	if !strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(pub)) {
		t.Errorf("error %v does not name the offending public key", err)
	}
	if _, statErr := os.Stat(sigPath); !os.IsNotExist(statErr) {
		t.Errorf("a signature was written despite an untrusted key, stat err = %v", statErr)
	}

	// Without the flag the same key signs fine (the publisher opts in).
	if err := run([]string{"-manifest", manifest, "-out", sigPath}, os.Stdout); err != nil {
		t.Errorf("signing without -require-trusted failed: %v", err)
	}
}

// TestCheckTrustedAcceptsAndRejects exercises BOTH branches of the pin check.
// The acceptance branch is the one that matters operationally: if it could not
// pass, every publication would abort.
func TestCheckTrustedAcceptsAndRejects(t *testing.T) {
	keyPEM, pub := testKeyPEM(t)
	key, err := loadSigningKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(pub)

	// Accepted: the key's public half IS in the trusted list, in any position.
	for name, trusted := range map[string][]string{
		"only key":   {encoded},
		"first of 2": {encoded, "AAAA"},
		"second of 2": {
			base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, ed25519.PublicKeySize)),
			encoded,
		},
	} {
		t.Run("accept/"+name, func(t *testing.T) {
			if err := checkTrusted(key, trusted); err != nil {
				t.Errorf("pinned key rejected: %v", err)
			}
		})
	}

	// Rejected: absent, empty list, and a near-miss that differs by one byte.
	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, ed25519.PublicKeySize))
	nearMiss := append([]byte(nil), pub...)
	nearMiss[0] ^= 0x01
	for name, trusted := range map[string][]string{
		"empty list": nil,
		"other key":  {other},
		"near miss":  {base64.StdEncoding.EncodeToString(nearMiss)},
	} {
		t.Run("reject/"+name, func(t *testing.T) {
			err := checkTrusted(key, trusted)
			if err == nil {
				t.Fatal("checkTrusted accepted an unpinned key")
			}
			if !strings.Contains(err.Error(), encoded) {
				t.Errorf("error %v does not name the offending public key", err)
			}
		})
	}
}

// TestShippedPinIsUsableForSigning: the compiled-in list must be parseable and
// non-empty, or -require-trusted could never pass and publication would be
// permanently blocked.
func TestShippedPinIsUsableForSigning(t *testing.T) {
	pinned := rulespin.KeysBase64()
	if len(pinned) == 0 {
		t.Fatal("no signing keys are compiled in; publication could never be verified")
	}
	for i, enc := range pinned {
		k, err := rulespin.Parse(enc)
		if err != nil {
			t.Errorf("pinned key %d does not parse: %v", i, err)
			continue
		}
		if len(k) != ed25519.PublicKeySize {
			t.Errorf("pinned key %d is %d bytes", i, len(k))
		}
	}
}

// TestFileErrorsNeverEchoPaths: a private key mistakenly passed as -manifest or
// -out becomes the path in a filesystem error, so no such error may quote it.
func TestFileErrorsNeverEchoPaths(t *testing.T) {
	keyPEM, _ := testKeyPEM(t)
	t.Setenv(signingKeyEnv, keyPEM)

	// -manifest is an unreadable "path" that is really a key.
	err := run([]string{"-manifest", keyPEM}, os.Stdout)
	if err == nil {
		t.Fatal("a key as -manifest was accepted")
	}
	assertNoKeyMaterial(t, err.Error(), keyPEM)

	// -out is unwritable because its "directory" does not exist.
	good := filepath.Join(t.TempDir(), "m.json")
	if writeErr := os.WriteFile(good, []byte(`{"version":1}`), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	err = run([]string{"-manifest", good, "-out", filepath.Join(keyPEM, "sig")}, os.Stdout)
	if err == nil {
		t.Fatal("a key-derived -out path was accepted")
	}
	assertNoKeyMaterial(t, err.Error(), keyPEM)
}

// TestSignerLinksNoLibyara pins the build contract for this tool: it runs on a
// publisher host that need not have libyara development files, so it must not
// (transitively) depend on the cgo scanner packages. Importing
// internal/mailstrix for the pin list once broke exactly this.
func TestSignerLinksNoLibyara(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch dep := strings.TrimSpace(dep); dep {
		case "github.com/hillu/go-yara/v4",
			"github.com/myguard-labs/mailstrix/internal/mailstrix":
			t.Errorf("rulessign depends on %s; it must build without libyara", dep)
		}
	}
}

// TestOutMustNotBeTheManifest: writing the signature over its own input would
// destroy the manifest and publish a signature that cannot verify over the
// resulting file, so it is refused and the manifest is left intact.
func TestOutMustNotBeTheManifest(t *testing.T) {
	keyPEM, _ := testKeyPEM(t)
	t.Setenv(signingKeyEnv, keyPEM)

	dir := t.TempDir()
	manifest := filepath.Join(dir, "compiled.yac.manifest.json")
	body := []byte(`{"version":42}`)
	if err := os.WriteFile(manifest, body, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(manifest, link); err != nil {
		t.Fatal(err)
	}

	for name, out := range map[string]string{
		"same path":       manifest,
		"dot-slash form":  filepath.Join(dir, ".", "compiled.yac.manifest.json"),
		"through symlink": link,
	} {
		t.Run(name, func(t *testing.T) {
			err := run([]string{"-manifest", manifest, "-out", out}, os.Stdout)
			if err == nil {
				t.Fatal("signed over the manifest itself")
			}
			if !strings.Contains(err.Error(), "refusing to overwrite the manifest") {
				t.Errorf("error = %v, want the overwrite refusal", err)
			}
			got, readErr := os.ReadFile(manifest) // #nosec G304 -- test temp path
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(got, body) {
				t.Errorf("manifest was modified: %q", got)
			}
		})
	}

	// A distinct -out still works, and the manifest is untouched.
	sigPath := manifest + ".sig"
	if err := run([]string{"-manifest", manifest, "-out", sigPath}, os.Stdout); err != nil {
		t.Fatalf("distinct -out refused: %v", err)
	}
	got, err := os.ReadFile(manifest) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Error("manifest changed during a normal signing run")
	}
	if _, err := os.Stat(sigPath); err != nil {
		t.Errorf("signature was not written: %v", err)
	}
}
