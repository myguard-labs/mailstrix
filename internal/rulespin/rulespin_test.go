package rulespin

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestKeysAreWellFormed guards the SHIPPED pin list: it must be non-empty (a
// binary trusting nothing could never update) and every entry must be a valid
// 32-byte ed25519 public key. Keys() panics on a bad entry, so this test is
// what keeps that panic from ever reaching a release.
func TestKeysAreWellFormed(t *testing.T) {
	encoded := KeysBase64()
	if len(encoded) == 0 {
		t.Fatal("the pin list is empty: the binary would trust nothing")
	}
	// A rotation is a deliberate act, so it updates wantPinned in the same
	// commit as keysB64. That makes any drift -- a dropped key, an extra key,
	// or a reordering -- fail here instead of shipping silently.
	if len(encoded) != len(wantPinned) {
		t.Fatalf("pin list has %d entries, want %d (%v); update wantPinned in the same commit as keysB64",
			len(encoded), len(wantPinned), encoded)
	}
	for i, want := range wantPinned {
		if encoded[i] != want {
			t.Errorf("pinned key %d (trust order) = %q, want %q", i, encoded[i], want)
		}
	}
	keys := Keys()
	if len(keys) != len(encoded) {
		t.Fatalf("parsed %d keys from %d entries", len(keys), len(encoded))
	}
	for i, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			t.Errorf("pinned key %d is %d bytes, want %d", i, len(k), ed25519.PublicKeySize)
		}
	}
}

// TestKeysBase64IsACopy: a caller must not be able to mutate the pin list and
// silently change what this binary trusts.
func TestKeysBase64IsACopy(t *testing.T) {
	got := KeysBase64()
	original := got[0]
	got[0] = "tampered"
	if KeysBase64()[0] != original {
		t.Fatal("KeysBase64 exposed the backing array; the pin list is mutable")
	}
}

// TestParse covers the accepted form and every rejected shape, including the
// 31/33-byte boundary around a 32-byte key.
func TestParse(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PublicKey(priv[ed25519.SeedSize:])
	good := base64.StdEncoding.EncodeToString(pub)

	k, err := Parse("  " + good + "\n")
	if err != nil {
		t.Fatalf("good key with surrounding space: %v", err)
	}
	if !k.Equal(pub) {
		t.Error("parsed key != original")
	}

	for name, raw := range map[string]string{
		"empty":       "",
		"whitespace":  "   \n",
		"not base64":  "!!!!not base64!!!!",
		"31 bytes":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)),
		"33 bytes":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33)),
		"zero length": base64.StdEncoding.EncodeToString(nil),
		"private key": base64.StdEncoding.EncodeToString(priv),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Fatalf("Parse(%q) accepted an invalid key", raw)
			} else if !errors.Is(err, ErrKey) {
				t.Errorf("error = %v, want ErrKey", err)
			}
		})
	}
}

// TestParseNeverEchoesTheValue: the pin is public, but an operator-supplied key
// flows through the same parser, so its errors must describe shape only.
func TestParseNeverEchoesTheValue(t *testing.T) {
	// Built at runtime, not a literal: a base64 blob in a test file reads like
	// a checked-in credential to secret scanners.
	supplied := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 35))
	_, err := Parse(supplied)
	if err == nil {
		t.Fatal("expected a length error")
	}
	if strings.Contains(err.Error(), supplied) {
		t.Errorf("error echoed the supplied value: %v", err)
	}
}

// TestMustParseAllPanicsOnCorruptPin: a build whose pin list is malformed must
// not start with a silently smaller trust set.
func TestMustParseAllPanicsOnCorruptPin(t *testing.T) {
	for name, list := range map[string][]string{
		"not base64":       {"!!!not base64!!!"},
		"wrong length":     {base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16))},
		"second entry bad": {KeysBase64()[0], "garbage"},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("a malformed pin list did not panic")
				}
				if msg, ok := r.(string); !ok || !strings.Contains(msg, "rules signing key") {
					t.Errorf("panic value %v does not identify the bad key", r)
				}
			}()
			MustParseAll(list)
		})
	}
}

// TestMustParseAllEmptyListIsNotAPanic: an empty list is a (bad) configuration
// the caller must detect, not a crash here.
func TestMustParseAllEmptyListIsNotAPanic(t *testing.T) {
	if got := MustParseAll(nil); len(got) != 0 {
		t.Fatalf("MustParseAll(nil) = %d keys, want 0", len(got))
	}
}

// wantPinned is the shipped pin list this package must contain, in trust order.
// These are PUBLIC keys; no private half of either is in this repository.
var wantPinned = []string{
	// Retired: never signed a published bundle and cannot sign one. Kept until
	// a later release, so removing it early fails TestRetiredKeyIsStillPinned.
	retiredPinB64,
	// Pre-published successor: the key publication actually signs with.
	successorPinB64,
}

const (
	retiredPinB64   = "94jKmUKdYEua82fm1WoQsoHQNLTvjdtyz5MueBwhl7w="
	successorPinB64 = "Iyo+xDtE5R1bpghpOT6p7JUc/gR94KSAqohsYp4Zfas="
)

// TestSuccessorKeyIsPinned is the point of the rotation: the successor must be
// compiled in BEFORE publication switches to it, or every already-deployed
// binary rejects the first bundle signed with the new key. Silently dropping
// the entry from keysB64 fails here.
func TestSuccessorKeyIsPinned(t *testing.T) {
	encoded := KeysBase64()
	if !slices.Contains(encoded, successorPinB64) {
		t.Fatalf("the successor signing key is not pinned; deployed binaries would reject bundles signed with it (pin = %v)", encoded)
	}
	k, err := Parse(successorPinB64)
	if err != nil {
		t.Fatalf("the successor key does not parse: %v", err)
	}
	if len(k) != ed25519.PublicKeySize {
		t.Errorf("the successor key is %d bytes, want %d", len(k), ed25519.PublicKeySize)
	}
	// Keys() must expose it too: KeysBase64 and Keys must not disagree.
	if !slices.ContainsFunc(Keys(), func(p ed25519.PublicKey) bool { return p.Equal(k) }) {
		t.Error("the successor key is in KeysBase64 but not in Keys()")
	}
}

// TestRetiredKeyIsStillPinned: the retired entry stays until a later release
// drops it deliberately. Removing it in the same change that adds the successor
// would be an undeclared trust narrowing, so it fails here.
func TestRetiredKeyIsStillPinned(t *testing.T) {
	encoded := KeysBase64()
	if !slices.Contains(encoded, retiredPinB64) {
		t.Fatalf("the retired signing key was dropped early; retire it in its own release (pin = %v)", encoded)
	}
	k, err := Parse(retiredPinB64)
	if err != nil {
		t.Fatalf("the retired key does not parse: %v", err)
	}
	if !slices.ContainsFunc(Keys(), func(p ed25519.PublicKey) bool { return p.Equal(k) }) {
		t.Error("the retired key is in KeysBase64 but not in Keys()")
	}
}

// TestPinIsInTrustOrder: order is load-bearing (callers try keys in order and
// internal/mailstrix asserts the pin occupies the leading trust positions), so
// a swap must fail even though the set would be unchanged.
func TestPinIsInTrustOrder(t *testing.T) {
	encoded := KeysBase64()
	retired := slices.Index(encoded, retiredPinB64)
	successor := slices.Index(encoded, successorPinB64)
	if retired < 0 || successor < 0 {
		t.Fatalf("both keys must be pinned; got retired at %d, successor at %d", retired, successor)
	}
	if retired >= successor {
		t.Errorf("retired key is at %d and successor at %d; the retired key must come first", retired, successor)
	}
}

// TestPinHoldsNoTestKey is the negative control for the shipped list: the
// deterministic fixture keys used elsewhere in this repo must never appear in
// it. internal/mailstrix TestEmbeddedKeysComeFromThePinAndHoldNoTestKey makes
// the same guarantee at the trust floor; this keeps it true in the leaf package
// that defines the pin, where a bad paste would land first.
func TestPinHoldsNoTestKey(t *testing.T) {
	for _, seed := range []byte{0x11, 0x22, 0x33, 0x44} {
		priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
		// An ed25519 private key is seed||public, so the trailing 32 bytes are
		// the public key.
		pub := ed25519.PublicKey(priv[ed25519.SeedSize:])
		if slices.Contains(KeysBase64(), base64.StdEncoding.EncodeToString(pub)) {
			t.Errorf("a TEST key (seed %#x) is in the shipped pin; a test key must never ship", seed)
		}
	}
}
