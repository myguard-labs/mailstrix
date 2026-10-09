package rulespin

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// TestKeysAreWellFormed guards the SHIPPED pin list: it must be non-empty (a
// binary trusting nothing could never update) and every entry must be a valid
// 32-byte ed25519 public key. Keys() panics on a bad entry, so this test is
// what keeps that panic from ever reaching a release.
func TestKeysAreWellFormed(t *testing.T) {
	const pinned = "94jKmUKdYEua82fm1WoQsoHQNLTvjdtyz5MueBwhl7w="
	encoded := KeysBase64()
	if len(encoded) == 0 {
		t.Fatal("the pin list is empty: the binary would trust nothing")
	}
	if encoded[0] != pinned {
		t.Errorf("first pinned key = %q, want the decided publication key %q", encoded[0], pinned)
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
