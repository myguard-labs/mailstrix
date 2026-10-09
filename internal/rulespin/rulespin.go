// Package rulespin holds the rules-manifest signing public keys compiled into
// the binary.
//
// It is deliberately a dependency-free leaf package: stdlib only, no cgo, no
// libyara. Both the scanner (internal/mailstrix, which links libyara) and the
// host-side publisher tool (cmd/rulessign, which must build on a machine with
// no libyara development files) read the pin from here, so there is exactly
// one copy of the trusted key list and no way for the two to disagree.
package rulespin

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// keysB64 pins the rules-manifest signing public keys, in trust order: the key
// currently used to publish, then the pre-published successor used for
// rotation.
//
// Rotation procedure: append the successor's public key as a second entry and
// ship that build FIRST, so deployed binaries already trust the new key before
// publication switches to it. Once publication has switched, the retired key is
// dropped in a later release. Nothing assumes the list has exactly one entry,
// so adding the successor is a one-line change.
//
// Values are the raw 32-byte ed25519 public key, base64 (standard alphabet).
var keysB64 = []string{
	// current (published 2026-10-09)
	"94jKmUKdYEua82fm1WoQsoHQNLTvjdtyz5MueBwhl7w=",
	// next (rotation slot): add the successor public key here.
}

// ErrKey reports a signing public key that is not a usable ed25519 key.
var ErrKey = errors.New("invalid rules signing key")

// KeysBase64 returns the compiled-in trusted public keys, in trust order.
// The publisher uses it to prove, before uploading, that the key it signed
// with is one clients actually trust.
func KeysBase64() []string {
	return slices.Clone(keysB64)
}

// Keys returns the parsed compiled-in trusted public keys, in trust order.
// These are build constants, so a malformed entry is a build defect that must
// never yield a running binary with a silently smaller trust set: it panics.
// TestKeysAreWellFormed proves the shipped list is valid, so this cannot fire
// in a release.
func Keys() []ed25519.PublicKey {
	return MustParseAll(keysB64)
}

// MustParseAll parses a compiled-in key list, panicking on a malformed entry.
func MustParseAll(encoded []string) []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(encoded))
	for i, raw := range encoded {
		k, err := Parse(raw)
		if err != nil {
			panic(fmt.Sprintf("rulespin: compiled-in rules signing key %d is invalid: %v", i, err))
		}
		keys = append(keys, k)
	}
	return keys
}

// Parse decodes one base64 raw ed25519 public key. The length is enforced here
// so no caller can hand ed25519.Verify a wrong-sized key (which panics).
func Parse(raw string) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("%w: key is empty", ErrKey)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// The value is a PUBLIC key, but it is still operator input; report the
		// shape problem without echoing the value.
		return nil, fmt.Errorf("%w: key is not valid base64", ErrKey)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: key is %d bytes, want %d", ErrKey, len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}
