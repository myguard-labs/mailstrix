package mailstrix

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/rulespin"
)

// Throwaway keypairs generated from fixed seeds so failures are reproducible.
// These are TEST keys only: none of them is ever added to rulesSigningKeysB64,
// and TestPinnedRulesSigningKeysAreWellFormed proves the shipped list does not
// contain them.
var (
	testRulesSigningPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	// An ed25519 private key is seed||public, so the trailing 32 bytes ARE the
	// public key. Slicing avoids an unchecked type assertion on Public().
	testRulesSigningPub = ed25519.PublicKey(testRulesSigningPriv[ed25519.SeedSize:])

	// testRotationPriv stands in for a pre-published successor key occupying
	// the second ("next") embedded slot.
	testRotationPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	testRotationPub  = ed25519.PublicKey(testRotationPriv[ed25519.SeedSize:])

	// testOperatorPriv stands in for an operator-supplied additional key.
	testOperatorPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	testOperatorPub  = ed25519.PublicKey(testOperatorPriv[ed25519.SeedSize:])

	// testUntrustedPriv is never trusted by any test.
	testUntrustedPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
)

// sha256Hex is the manifest checksum form for a bundle's bytes.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// signTestManifest produces the detached signature the fixtures publish.
func signTestManifest(body []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(testRulesSigningPriv, body)) + "\n"
}

// signedManifestBody marshals a manifest ONCE and signs those exact bytes, so
// a fixture serves a byte sequence whose signature actually covers it. Fixtures
// must never re-encode between signing and serving.
func signedManifestBody(t *testing.T, m RulesManifest) ([]byte, string) {
	t.Helper()
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return body, signTestManifest(body)
}

// TestMain trusts the fixture signing key for this test binary only. It ADDS to
// the embedded list rather than replacing it, mirroring production: every
// existing fetch test therefore exercises the real signed path with a real
// signature over the real served bytes, verified by the real verifier.
func TestMain(m *testing.M) {
	embeddedRulesSigningKeys = append(embeddedRulesSigningKeys, testRulesSigningPub)
	os.Exit(m.Run())
}

// TestEmbeddedKeysComeFromThePinAndHoldNoTestKey guards the TestMain seam: the
// trust floor must be exactly the compiled-in pin plus, in this test binary
// only, the fixture key. The shipped pin list itself is guarded by
// internal/rulespin TestKeysAreWellFormed.
func TestEmbeddedKeysComeFromThePinAndHoldNoTestKey(t *testing.T) {
	pin := rulespin.Keys()
	if len(pin) == 0 {
		t.Fatal("no keys are compiled in")
	}
	// Every pinned key is trusted, in order, ahead of the test fixture key.
	if len(embeddedRulesSigningKeys) < len(pin) {
		t.Fatalf("trust floor has %d keys, fewer than the %d pinned", len(embeddedRulesSigningKeys), len(pin))
	}
	for i, k := range pin {
		if !embeddedRulesSigningKeys[i].Equal(k) {
			t.Errorf("pinned key %d is not trusted in position %d", i, i)
		}
		// A test key must never be in the SHIPPED list.
		for _, bad := range []ed25519.PublicKey{testRulesSigningPub, testRotationPub, testOperatorPub} {
			if k.Equal(bad) {
				t.Errorf("pinned key %d is a TEST key; a test key must never ship", i)
			}
		}
	}
}

// TestParseRulesSigningKey covers the accepted form and every rejected shape,
// including the 63/65-byte boundary around a 32-byte key.
func TestParseRulesSigningKey(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(testRulesSigningPub)
	if k, err := ParseRulesSigningKey("  " + good + "\n"); err != nil {
		t.Errorf("good key with surrounding space: %v", err)
	} else if !k.Equal(testRulesSigningPub) {
		t.Error("parsed key != original")
	}

	for name, raw := range map[string]string{
		"empty":        "",
		"whitespace":   "   \n",
		"not base64":   "!!!!not base64!!!!",
		"31 bytes":     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)),
		"33 bytes":     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33)),
		"zero length":  base64.StdEncoding.EncodeToString(nil),
		"64 byte seed": base64.StdEncoding.EncodeToString(testRulesSigningPriv),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRulesSigningKey(raw); err == nil {
				t.Fatalf("ParseRulesSigningKey(%q) accepted an invalid key", raw)
			} else if !errors.Is(err, ErrRulesSigningKey) {
				t.Errorf("error = %v, want ErrRulesSigningKey", err)
			}
		})
	}
}

// TestVerifyManifestSignatureBoundaries pins the signature-payload boundary:
// exactly 64 bytes verifies, 63 and 65 are refused.
func TestVerifyManifestSignatureBoundaries(t *testing.T) {
	body := []byte(`{"version":7}`)
	keys := []ed25519.PublicKey{testRulesSigningPub}
	valid := ed25519.Sign(testRulesSigningPriv, body)
	if len(valid) != 64 {
		t.Fatalf("ed25519 signature is %d bytes", len(valid))
	}
	if err := verifyManifestSignature(body, base64.StdEncoding.EncodeToString(valid), keys); err != nil {
		t.Errorf("exactly 64 bytes: %v", err)
	}
	for name, sig := range map[string][]byte{
		"63 bytes": valid[:63],
		"65 bytes": append(append([]byte{}, valid...), 0x00),
		"0 bytes":  {},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyManifestSignature(body, base64.StdEncoding.EncodeToString(sig), keys); err == nil {
				t.Fatal("accepted a signature of the wrong length")
			}
		})
	}
}

// TestVerifyManifestSignatureRejects covers every refusal path of the verifier
// itself, including an empty trust set and a non-base64 payload.
func TestVerifyManifestSignatureRejects(t *testing.T) {
	body := []byte(`{"version":7}`)
	keys := []ed25519.PublicKey{testRulesSigningPub}
	valid := base64.StdEncoding.EncodeToString(ed25519.Sign(testRulesSigningPriv, body))

	if err := verifyManifestSignature(body, valid, nil); err == nil {
		t.Error("verified against an empty trust set")
	}
	if err := verifyManifestSignature(body, "", keys); !errors.Is(err, errNoManifestSignature) {
		t.Errorf("empty signature error = %v, want errNoManifestSignature", err)
	}
	if err := verifyManifestSignature(body, "@@@not base64@@@", keys); err == nil {
		t.Error("accepted a non-base64 signature")
	}
	// Right signature, wrong body.
	if err := verifyManifestSignature([]byte(`{"version":8}`), valid, keys); err == nil {
		t.Error("accepted a signature over different bytes")
	}
	// Right body, untrusted signer.
	other := base64.StdEncoding.EncodeToString(ed25519.Sign(testUntrustedPriv, body))
	if err := verifyManifestSignature(body, other, keys); err == nil {
		t.Error("accepted a signature from an untrusted key")
	}
	// A wrong-sized key in the trust set must be skipped, not panic.
	if err := verifyManifestSignature(body, valid, []ed25519.PublicKey{{1, 2, 3}}); err == nil {
		t.Error("verified against a malformed trusted key")
	}
}

// TestRulesTrustedKeysIsAdditive proves configuration cannot shrink the trust
// set: every embedded key survives, extras are appended, and the embedded
// slice itself is not mutated by repeated resolution.
func TestRulesTrustedKeysIsAdditive(t *testing.T) {
	embedded := append([]ed25519.PublicKey(nil), embeddedRulesSigningKeys...)
	got := rulesTrustedKeys([]ed25519.PublicKey{testOperatorPub})
	if len(got) != len(embedded)+1 {
		t.Fatalf("trust set has %d keys, want %d", len(got), len(embedded)+1)
	}
	for i, k := range embedded {
		if !got[i].Equal(k) {
			t.Errorf("embedded key %d was displaced", i)
		}
	}
	if !got[len(got)-1].Equal(testOperatorPub) {
		t.Error("operator key was not appended")
	}
	if len(embeddedRulesSigningKeys) != len(embedded) {
		t.Error("rulesTrustedKeys mutated the embedded key list")
	}
	// Nil extras yield exactly the embedded set.
	if base := rulesTrustedKeys(nil); len(base) != len(embedded) {
		t.Errorf("rulesTrustedKeys(nil) has %d keys, want %d", len(base), len(embedded))
	}
}

// withEmbeddedKeys replaces the embedded trust list for one test, restoring it
// afterwards. Used to exercise the rotation ("next") slot.
func withEmbeddedKeys(t *testing.T, keys ...ed25519.PublicKey) {
	t.Helper()
	prev := embeddedRulesSigningKeys
	embeddedRulesSigningKeys = keys
	t.Cleanup(func() { embeddedRulesSigningKeys = prev })
}

// signedRulesServer serves a bundle plus a manifest signed by signer, with
// optional corruption of the signature payload or the manifest body. A nil
// signer publishes no .sig at all (404).
func signedRulesServer(t *testing.T, yac []byte, ver int, signer ed25519.PrivateKey, mutate func(sig string, body []byte) (string, []byte, bool)) *httptest.Server {
	t.Helper()
	sum := sha256Hex(yac)
	m := RulesManifest{
		Version: ver, Generated: testRulesManifestGenerated,
		Checksum: "sha256:" + sum, Libyara: "4.5.2", Rules: 1, Size: int64(len(yac)),
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig := ""
	publish := signer != nil
	if publish {
		sig = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, body)) + "\n"
	}
	if mutate != nil {
		sig, body, publish = mutate(sig, body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+manifestName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	mux.HandleFunc("/"+cachedRulesName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(yac) })
	if publish {
		mux.HandleFunc("/"+manifestSigName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sig)) })
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// cacheSnapshot records the cache files so a refused update can be proven not
// to have touched them.
type cacheSnapshot struct {
	names map[string][]byte
}

// snapshotCache records the three published cache files. The flock file is
// deliberately excluded: taking the cache lock is expected on every attempt and
// says nothing about whether the bundle was mutated.
func snapshotCache(t *testing.T, dir string) cacheSnapshot {
	t.Helper()
	snap := cacheSnapshot{names: map[string][]byte{}}
	for _, name := range []string{cachedRulesName, manifestName, cachedRulesName + backupSuffix} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		snap.names[name] = b
	}
	return snap
}

func (c cacheSnapshot) assertUnchanged(t *testing.T, dir string) {
	t.Helper()
	now := snapshotCache(t, dir)
	for name, want := range c.names {
		got, ok := now.names[name]
		if !ok {
			t.Errorf("cache file %s disappeared on a refused update", name)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("cache file %s was modified on a refused update", name)
		}
	}
	for name := range now.names {
		if _, ok := c.names[name]; !ok {
			t.Errorf("refused update created cache file %s", name)
		}
	}
}

// --- accepted: one case per trusted-key origin ---

// TestFetchRulesAcceptsEmbeddedCurrentKey: the first embedded key signs.
func TestFetchRulesAcceptsEmbeddedCurrentKey(t *testing.T) {
	withEmbeddedKeys(t, testRulesSigningPub, testRotationPub)
	dir := t.TempDir()
	yac := compiledYacBytes(t, "rule A { condition: true }")
	srv := signedRulesServer(t, yac, 5, testRulesSigningPriv, nil)

	res, err := fetchRules(t.Context(), srv.URL, dir, "4.5.2", srv.Client(), fetchOptions{allowHTTP: true})
	if err != nil {
		t.Fatalf("signed update refused: %v", err)
	}
	if !res.Updated || res.NewVersion != 5 {
		t.Fatalf("res = %+v, want updated v5", res)
	}
}

// TestFetchRulesAcceptsEmbeddedNextKey: the SECOND embedded slot signs, which
// is what makes key rotation possible.
func TestFetchRulesAcceptsEmbeddedNextKey(t *testing.T) {
	withEmbeddedKeys(t, testRulesSigningPub, testRotationPub)
	dir := t.TempDir()
	yac := compiledYacBytes(t, "rule A { condition: true }")
	srv := signedRulesServer(t, yac, 6, testRotationPriv, nil)

	res, err := fetchRules(t.Context(), srv.URL, dir, "4.5.2", srv.Client(), fetchOptions{allowHTTP: true})
	if err != nil {
		t.Fatalf("rotation-key update refused: %v", err)
	}
	if !res.Updated || res.NewVersion != 6 {
		t.Fatalf("res = %+v, want updated v6", res)
	}
}

// TestFetchRulesAcceptsOperatorKeyAndWarns: an operator-supplied additional key
// signs, and the loud startup warning naming it is emitted.
func TestFetchRulesAcceptsOperatorKeyAndWarns(t *testing.T) {
	withEmbeddedKeys(t, testRulesSigningPub)
	dir := t.TempDir()
	yac := compiledYacBytes(t, "rule A { condition: true }")
	srv := signedRulesServer(t, yac, 7, testOperatorPriv, nil)

	res, err := fetchRules(t.Context(), srv.URL, dir, "4.5.2", srv.Client(),
		fetchOptions{allowHTTP: true, extraSigningKeys: []ed25519.PublicKey{testOperatorPub}})
	if err != nil {
		t.Fatalf("operator-key update refused: %v", err)
	}
	if !res.Updated || res.NewVersion != 7 {
		t.Fatalf("res = %+v, want updated v7", res)
	}

	// The same key, configured, must produce the loud trust warning.
	cfg := &Config{RulesExtraSigningKeys: []string{base64.StdEncoding.EncodeToString(testOperatorPub)}}
	buf := captureLog(t)
	if err := cfg.ValidateRulesSigningKeys(); err != nil {
		t.Fatalf("valid operator key rejected: %v", err)
	}
	logged := buf.String()
	for _, want := range []string{"WARNING", rulesExtraSigningKeysEnv, "trust anchor"} {
		if !strings.Contains(logged, want) {
			t.Errorf("startup log %q does not mention %q", logged, want)
		}
	}
}

// TestValidateRulesSigningKeysSilentWithoutExtras: no configured key, no noise.
func TestValidateRulesSigningKeysSilentWithoutExtras(t *testing.T) {
	cfg := &Config{}
	buf := captureLog(t)
	if err := cfg.ValidateRulesSigningKeys(); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	if logged := buf.String(); logged != "" {
		t.Errorf("unconfigured trust logged %q, want silence", logged)
	}
}

// --- refused: each refusal proves the cache was not touched ---

func TestFetchRulesRefusesUntrustedSignatures(t *testing.T) {
	validSig := func(sig string, body []byte) (string, []byte, bool) { return sig, body, true }

	cases := map[string]struct {
		signer ed25519.PrivateKey
		mutate func(string, []byte) (string, []byte, bool)
		want   string
	}{
		"missing .sig": {
			signer: testRulesSigningPriv,
			mutate: func(sig string, body []byte) (string, []byte, bool) { return sig, body, false },
			want:   "fetch manifest signature",
		},
		"empty .sig body": {
			signer: testRulesSigningPriv,
			mutate: func(_ string, body []byte) (string, []byte, bool) { return "", body, true },
			want:   "not signed",
		},
		"whitespace .sig body": {
			signer: testRulesSigningPriv,
			mutate: func(_ string, body []byte) (string, []byte, bool) { return "   \n\t ", body, true },
			want:   "not signed",
		},
		"untrusted signer": {
			signer: testUntrustedPriv,
			mutate: validSig,
			want:   "does not verify under any trusted key",
		},
		"tampered manifest body": {
			signer: testRulesSigningPriv,
			// Signature stays valid for the ORIGINAL bytes; the body changes.
			mutate: func(sig string, body []byte) (string, []byte, bool) {
				return sig, append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"rules":99999}`)...), true
			},
			want: "does not verify under any trusted key",
		},
		"non-base64 signature": {
			signer: testRulesSigningPriv,
			mutate: func(_ string, body []byte) (string, []byte, bool) { return "@@@ not base64 @@@", body, true },
			want:   "not valid base64",
		},
		"short signature": {
			signer: testRulesSigningPriv,
			mutate: func(_ string, body []byte) (string, []byte, bool) {
				return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 63)), body, true
			},
			want: "signature is 63 bytes",
		},
		"long signature": {
			signer: testRulesSigningPriv,
			mutate: func(_ string, body []byte) (string, []byte, bool) {
				return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 65)), body, true
			},
			want: "signature is 65 bytes",
		},
		"oversized .sig body": {
			signer: testRulesSigningPriv,
			mutate: func(_ string, body []byte) (string, []byte, bool) {
				return strings.Repeat("A", maxManifestSigBytes+1), body, true
			},
			want: "exceeds 1024 bytes",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			withEmbeddedKeys(t, testRulesSigningPub)
			dir := t.TempDir()
			oldYac := compiledYacBytes(t, "rule OLD { condition: true }")
			seedLocal(t, dir, 1, oldYac)
			before := snapshotCache(t, dir)

			newYac := compiledYacBytes(t, "rule NEW { condition: true }")
			srv := signedRulesServer(t, newYac, 9, tc.signer, tc.mutate)

			res, err := fetchRules(t.Context(), srv.URL, dir, "4.5.2", srv.Client(), fetchOptions{allowHTTP: true})
			if err == nil {
				t.Fatalf("update ACCEPTED an unverifiable manifest: res = %+v", res)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
			if res.Updated {
				t.Error("res.Updated is true on a refused update")
			}
			// The installed rules must still be the old ones, byte for byte,
			// and no cache file may have been created, replaced or removed.
			before.assertUnchanged(t, dir)
			got, err := os.ReadFile(filepath.Join(dir, cachedRulesName))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, oldYac) {
				t.Error("installed bundle was replaced by a refused update")
			}
		})
	}
}

// TestFetchRulesRefusesUnsignedEvenWhenOperatorKeysConfigured: widening trust
// does not make an unsigned manifest acceptable.
func TestFetchRulesRefusesUnsignedEvenWhenOperatorKeysConfigured(t *testing.T) {
	withEmbeddedKeys(t, testRulesSigningPub)
	dir := t.TempDir()
	yac := compiledYacBytes(t, "rule A { condition: true }")
	srv := signedRulesServer(t, yac, 9, testRulesSigningPriv,
		func(sig string, body []byte) (string, []byte, bool) { return sig, body, false })

	if _, err := fetchRules(t.Context(), srv.URL, dir, "4.5.2", srv.Client(),
		fetchOptions{allowHTTP: true, extraSigningKeys: []ed25519.PublicKey{testOperatorPub}}); err == nil {
		t.Fatal("an unsigned manifest was accepted")
	}
}

// --- cached-manifest compatibility (decision 2) ---

// TestCachedUnsignedManifestKeepsWorking proves an existing deployment is not
// bricked: the locally installed manifest is trusted on its bytes (checksum),
// never on a signature, so a cache written before signing existed still
// suppresses a pointless download and still reports its version.
func TestCachedUnsignedManifestKeepsWorking(t *testing.T) {
	withEmbeddedKeys(t, testRulesSigningPub)
	dir := t.TempDir()
	yac := compiledYacBytes(t, "rule OLD { condition: true }")
	// A real pre-signing cache: bundle + manifest whose checksum matches, and
	// NO .sig file anywhere.
	if err := os.WriteFile(filepath.Join(dir, cachedRulesName), yac, 0o600); err != nil {
		t.Fatal(err)
	}
	m := RulesManifest{Version: 4, Generated: testRulesManifestGenerated,
		Checksum: "sha256:" + sha256Hex(yac), Libyara: "4.5.2", Rules: 1, Size: int64(len(yac))}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, manifestSigName)); !os.IsNotExist(err) {
		t.Fatalf("fixture must have no local signature, stat err = %v", err)
	}

	// The local manifest is accepted as the current version on its own merits.
	if local := trustedLocalManifest(filepath.Join(dir, cachedRulesName), filepath.Join(dir, manifestName)); local.Version != 4 {
		t.Fatalf("cached unsigned manifest version = %d, want 4: existing deployments would be bricked", local.Version)
	}
	// And it is reported to operators.
	got, ok, err := LoadManifest(dir)
	if err != nil || !ok || got.Version != 4 {
		t.Fatalf("LoadManifest = (%+v, %v, %v), want v4 readable", got, ok, err)
	}
	// A correctly signed newer remote manifest still updates it.
	newYac := compiledYacBytes(t, "rule NEW { condition: true }")
	srv := signedRulesServer(t, newYac, 5, testRulesSigningPriv, nil)
	res, err := fetchRules(t.Context(), srv.URL, dir, "4.5.2", srv.Client(), fetchOptions{allowHTTP: true})
	if err != nil || !res.Updated || res.LocalVersion != 4 || res.NewVersion != 5 {
		t.Fatalf("res = %+v, err = %v; want v4 -> v5", res, err)
	}
}

// --- configuration ---

// TestConfigRejectsMalformedExtraKeys: a bad operator key is a hard startup
// error and must NOT silently degrade to embedded-only trust.
func TestConfigRejectsMalformedExtraKeys(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(testOperatorPub)
	for name, raw := range map[string][]string{
		"not base64":             {"!!!!"},
		"too short":              {base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))},
		"too long":               {base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33))},
		"private key by mistake": {base64.StdEncoding.EncodeToString(testOperatorPriv)},
		"second entry bad":       {good, "nonsense!"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{RulesExtraSigningKeys: raw}
			err := cfg.ValidateRulesSigningKeys()
			if err == nil {
				t.Fatal("malformed operator key accepted at startup")
			}
			if !errors.Is(err, ErrRulesSigningKey) {
				t.Errorf("error = %v, want ErrRulesSigningKey", err)
			}
			if !strings.Contains(err.Error(), rulesExtraSigningKeysEnv) {
				t.Errorf("error %v does not name the offending variable", err)
			}
			// No partial trust set is handed back.
			keys, err := cfg.ExtraRulesSigningKeys()
			if err == nil || keys != nil {
				t.Errorf("ExtraRulesSigningKeys = (%v, %v), want (nil, error) — never a silent fallback", keys, err)
			}
			// The updater refuses to start rather than run with ignored trust.
			if _, err := NewRulesUpdater(cfg, &Scanner{}, "4.5.2", nil); err == nil {
				t.Error("NewRulesUpdater started with an unusable configured key")
			}
		})
	}
}

// TestConfigAcceptsExtraKeys covers the parsing of a valid additive list,
// including surrounding whitespace and an empty (unset) value.
func TestConfigAcceptsExtraKeys(t *testing.T) {
	cfg := &Config{RulesExtraSigningKeys: []string{
		" " + base64.StdEncoding.EncodeToString(testOperatorPub) + " ",
		base64.StdEncoding.EncodeToString(testRotationPub),
	}}
	keys, err := cfg.ExtraRulesSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !keys[0].Equal(testOperatorPub) || !keys[1].Equal(testRotationPub) {
		t.Fatalf("parsed %d keys, want the two configured ones in order", len(keys))
	}
	// Backward compatibility: an existing config with the variable absent
	// parses and yields no extra trust at all.
	empty := &Config{}
	keys, err = empty.ExtraRulesSigningKeys()
	if err != nil || keys != nil {
		t.Fatalf("unset config = (%v, %v), want (nil, nil)", keys, err)
	}
}

// TestEnvListPreservesCaseAndDropsEmpties: base64 is case-sensitive, so the
// list parser must not lowercase like envSet does.
func TestEnvListPreservesCaseAndDropsEmpties(t *testing.T) {
	const name = "MAILSTRIX_TEST_ENVLIST"
	t.Setenv(name, " AbC== , ,dEf== ,")
	got := envList(name)
	if len(got) != 2 || got[0] != "AbC==" || got[1] != "dEf==" {
		t.Fatalf("envList = %q, want [AbC== dEf==]", got)
	}
	t.Setenv(name, "")
	if got := envList(name); got != nil {
		t.Errorf("envList on empty = %q, want nil", got)
	}
}

// TestLoadConfigReadsExtraSigningKeys wires the env var through LoadConfig and
// confirms the default is empty (no new trust without explicit opt-in).
func TestLoadConfigReadsExtraSigningKeys(t *testing.T) {
	if cfg := LoadConfig(); len(cfg.RulesExtraSigningKeys) != 0 {
		t.Errorf("default RulesExtraSigningKeys = %q, want empty", cfg.RulesExtraSigningKeys)
	}
	key := base64.StdEncoding.EncodeToString(testOperatorPub)
	t.Setenv(rulesExtraSigningKeysEnv, key)
	cfg := LoadConfig()
	if len(cfg.RulesExtraSigningKeys) != 1 || cfg.RulesExtraSigningKeys[0] != key {
		t.Fatalf("RulesExtraSigningKeys = %q, want [%s]", cfg.RulesExtraSigningKeys, key)
	}
	if err := cfg.ValidateRulesSigningKeys(); err != nil {
		t.Errorf("configured key rejected: %v", err)
	}
}

// TestNoVerificationBypassExists is a source-level guard: the rules trust path
// must expose no skip/disable switch. The user's decision forbids one, and a
// future "temporary" flag here would silently reopen the bypass.
func TestNoVerificationBypassExists(t *testing.T) {
	for _, path := range []string{"rulessig.go", "fetchrules.go", "rulesupdate.go"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{
			"ALLOW_UNSIGNED", "SKIP_SIGNATURE", "SKIP_VERIFY", "NoVerify",
			"noVerify", "InsecureSkipSignature", "DisableSignature",
		} {
			if bytes.Contains(b, []byte(banned)) {
				t.Errorf("%s contains a signature-bypass affordance %q", path, banned)
			}
		}
	}
}
