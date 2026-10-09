package mailstrix

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/myguard-labs/mailstrix/internal/rulespin"
)

// manifestSigName is the detached signature published next to the manifest. It
// holds the base64 (standard alphabet) encoding of the raw 64-byte ed25519
// signature over the EXACT bytes of manifestName as served.
//
// A detached file is used rather than a field inside the manifest JSON so that
// verification never needs a canonical form: there is no self-referential field
// to exclude and no re-marshalling step that could verify a different byte
// sequence than the one that was signed.
const manifestSigName = manifestName + ".sig"

// maxManifestSigBytes caps the detached signature response. A base64 ed25519
// signature is 88 bytes; 1 KiB leaves room for trailing whitespace or a newline
// while keeping the read bounded, so a hostile endpoint cannot stream forever.
const maxManifestSigBytes = 1 << 10

// embeddedRulesSigningKeys is the parsed form of the compiled-in pin list
// (internal/rulespin) and the immovable floor of the trust set: operator
// configuration can only ADD to it.
//
// The pin lives in that dependency-free leaf package so the host-side signing
// tool can read the same list without linking libyara.
var embeddedRulesSigningKeys = rulespin.Keys()

// ErrRulesSigningKey reports an unusable operator-supplied signing key.
var ErrRulesSigningKey = rulespin.ErrKey

// ParseRulesSigningKey decodes one base64 raw ed25519 public key.
func ParseRulesSigningKey(raw string) (ed25519.PublicKey, error) {
	return rulespin.Parse(raw)
}

// parseRulesSigningKeys decodes every operator-supplied key, failing on the
// first bad entry. It never returns a partial list: a malformed key is a hard
// configuration error, never a silent fallback to embedded-only trust.
func parseRulesSigningKeys(raw []string) ([]ed25519.PublicKey, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	keys := make([]ed25519.PublicKey, 0, len(raw))
	for i, entry := range raw {
		k, err := ParseRulesSigningKey(entry)
		if err != nil {
			return nil, fmt.Errorf("%s entry %d: %w", rulesExtraSigningKeysEnv, i+1, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// rulesTrustedKeys returns the trust set used to verify a remote manifest:
// every embedded key first, then any operator-supplied additional key.
// Construction is additive by shape -- extra keys are appended to a fresh slice
// and can neither remove nor shadow an embedded key.
func rulesTrustedKeys(extra []ed25519.PublicKey) []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(embeddedRulesSigningKeys)+len(extra))
	keys = append(keys, embeddedRulesSigningKeys...)
	keys = append(keys, extra...)
	return keys
}

// errNoManifestSignature reports an absent or empty detached signature.
var errNoManifestSignature = errors.New("rules manifest is not signed")

// verifyManifestSignature checks the detached base64 signature over body
// against every trusted key, accepting on the first match.
//
// It fails closed in every other case: no trusted keys, empty payload,
// non-base64 payload, a payload that is not exactly ed25519.SignatureSize
// bytes, or a well-formed signature that no trusted key validates. There is no
// bypass: no flag, environment variable or build tag reaches this function.
func verifyManifestSignature(body []byte, sig string, keys []ed25519.PublicKey) error {
	if len(keys) == 0 {
		// Unreachable while rulesTrustedKeys always seeds the embedded keys;
		// kept so a future caller cannot accidentally verify against nothing.
		return fmt.Errorf("refusing unsigned rules: no trusted signing keys")
	}
	s := strings.TrimSpace(sig)
	if s == "" {
		return errNoManifestSignature
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("rules manifest signature is not valid base64")
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("rules manifest signature is %d bytes, want %d", len(raw), ed25519.SignatureSize)
	}
	for _, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			// Defensive: ed25519.Verify panics on a wrong-sized key. Every
			// constructor validates the length, so skip rather than crash.
			continue
		}
		if ed25519.Verify(k, body, raw) {
			return nil
		}
	}
	return fmt.Errorf("rules manifest signature does not verify under any trusted key")
}

// logRulesSigningTrust warns loudly, once at startup, when the operator has
// widened the rules trust set. Adding a trust anchor for the code that executes
// on every mail scan must never be a quiet config line.
func logRulesSigningTrust(extra []ed25519.PublicKey) {
	if len(extra) == 0 {
		return
	}
	log.Printf("[mailstrix] WARNING: %s adds %d operator-supplied rules-signing trust anchor(s) beside the %d key(s) built into this binary; a rules bundle signed by any of them will be installed and executed",
		rulesExtraSigningKeysEnv, len(extra), len(embeddedRulesSigningKeys))
}
