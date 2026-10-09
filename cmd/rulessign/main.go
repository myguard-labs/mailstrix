// Command rulessign signs a rules manifest for publication.
//
// It writes the detached signature consumed by strixd's rules updater: the
// base64 (standard alphabet) encoding of the raw 64-byte ed25519 signature over
// the EXACT bytes of the manifest file. The manifest is never re-encoded here,
// so the signed bytes are byte-identical to what gets published and to what the
// client verifies.
//
// The private key is read from the MAILSTRIX_RULES_SIGNING_KEY environment
// variable as an ed25519 PKCS#8 PEM block. It is never accepted on the command
// line, so it cannot leak through a process listing or a shell history file,
// and it is never logged.
//
// Usage:
//
//	MAILSTRIX_RULES_SIGNING_KEY="$(cat key.pem)" \
//	  rulessign -manifest compiled.yac.manifest.json -out compiled.yac.manifest.json.sig
//
//	# Print the base64 public key, to confirm it matches the pin compiled
//	# into the binary (internal/mailstrix/rulessig.go rulesSigningKeysB64):
//	MAILSTRIX_RULES_SIGNING_KEY="$(cat key.pem)" rulessign -print-public
//
// This is a host-side release tool. It is pure Go stdlib and links no libyara.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/myguard-labs/mailstrix/internal/rulespin"
)

// signingKeyEnv names the variable holding the PKCS#8 PEM private key. In CI it
// comes from the MAILSTRIX_RULES_SIGNING_KEY repository secret, which must be
// exposed only to publication jobs and never to a pull_request-triggered job.
const signingKeyEnv = "MAILSTRIX_RULES_SIGNING_KEY"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		// The error never embeds key material: loadSigningKey reports only the
		// shape of the failure.
		fmt.Fprintln(os.Stderr, "rulessign:", err)
		os.Exit(2)
	}
}

func run(args []string, stdout *os.File) error {
	fs := flag.NewFlagSet("rulessign", flag.ContinueOnError)
	// The flag package echoes the offending argument in its diagnostics and
	// prints usage to stderr. A PEM key pasted onto the command line starts
	// with "-----", so the default behaviour would print the whole private key
	// to stderr (and into any CI log). Silence the parser and return a fixed,
	// sanitized error instead: no parse failure may ever quote argv.
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "path to the manifest file to sign")
	out := fs.String("out", "", "path to write the base64 detached signature to (default: stdout)")
	printPublic := fs.Bool("print-public", false, "print the base64 public key for the configured private key and exit")
	requireTrusted := fs.Bool("require-trusted", false, "fail unless the signing key's public half is one of the keys compiled into strixd")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(stdout)
			fs.Usage()
			return nil
		}
		// Deliberately NOT wrapping err: it can contain the argument text.
		return fmt.Errorf("invalid arguments; the signing key comes from %s, never argv", signingKeyEnv)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments (%d); the signing key comes from %s, never argv", fs.NArg(), signingKeyEnv)
	}

	key, err := loadSigningKey(os.Getenv(signingKeyEnv))
	if err != nil {
		return err
	}

	if *printPublic {
		pub, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			return errors.New("signing key does not expose an ed25519 public key")
		}
		_, err := fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(pub))
		return err
	}

	if *requireTrusted {
		// Publishing under a key no client trusts produces a bundle that every
		// client correctly refuses, i.e. a silently broken updater. Catch the
		// mismatch here, before anything is uploaded.
		if err := checkTrusted(key, rulespin.KeysBase64()); err != nil {
			return err
		}
	}

	if *manifest == "" {
		return errors.New("-manifest is required")
	}
	// os.ReadFile/WriteFile errors embed the path, and a private key
	// mistakenly passed as -manifest or -out IS that path. Report the failure
	// without the value: main prints these to stderr and into CI logs.
	body, err := os.ReadFile(*manifest) // #nosec G304 -- release-tool argument, run by the publisher
	if err != nil {
		return fmt.Errorf("cannot read the -manifest file: %s", sanitizeFileError(err))
	}
	if len(body) == 0 {
		// Signing an empty file would publish a signature that verifies
		// against nothing useful and mask a broken manifest build.
		return errors.New("the -manifest file is empty; refusing to sign")
	}
	// Writing the signature over its own input would destroy the manifest and
	// publish a signature that cannot verify over the resulting file. Compare
	// resolved paths so a symlink or a "./" spelling cannot slip past.
	if *out != "" {
		same, err := sameFile(*manifest, *out)
		if err != nil {
			return err
		}
		if same {
			return errors.New("-out resolves to the -manifest file; refusing to overwrite the manifest with its signature")
		}
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, body)) + "\n"
	if *out == "" {
		_, err := fmt.Fprint(stdout, sig)
		return err
	}
	// 0o644: the signature is public data published beside the manifest.
	// #nosec G306 G703 -- release-tool output path chosen by the publisher
	// running this command, not attacker input; the signature is public.
	if err := os.WriteFile(*out, []byte(sig), 0o644); err != nil {
		return fmt.Errorf("cannot write the -out signature file: %s", sanitizeFileError(err))
	}
	return nil
}

// checkTrusted verifies the signing key's public half is pinned in the client
// binary. It compares base64 forms of the compiled-in list, so it needs no
// knowledge of how those keys are stored.
func checkTrusted(key ed25519.PrivateKey, trusted []string) error {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("signing key does not expose an ed25519 public key")
	}
	encoded := base64.StdEncoding.EncodeToString(pub)
	if slices.Contains(trusted, encoded) {
		return nil
	}
	// The public key is not secret, so naming it is safe and is exactly what
	// the operator needs to fix the pin.
	return fmt.Errorf(
		"signing key %s is not among the %d public key(s) compiled into strixd; "+
			"add it to internal/rulespin keysB64 and ship that build first",
		encoded, len(trusted))
}

// sameFile reports whether two paths denote the same existing file. A missing
// -out is the normal case and is not "same". Paths are never echoed: either one
// may be a mistakenly pasted key.
func sameFile(manifest, out string) (bool, error) {
	mi, err := os.Stat(manifest)
	if err != nil {
		return false, fmt.Errorf("cannot stat the -manifest file: %s", sanitizeFileError(err))
	}
	oi, err := os.Stat(out)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("cannot stat the -out file: %s", sanitizeFileError(err))
	}
	return os.SameFile(mi, oi), nil
}

// sanitizeFileError reduces a filesystem error to its cause, dropping the path
// *os.PathError carries. The path is operator input and may be a pasted private
// key, so it must never reach stderr.
func sanitizeFileError(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.Err.Error()
	}
	return err.Error()
}

// loadSigningKey decodes an ed25519 PKCS#8 PEM private key. Every failure
// message describes only the shape of the problem, never any byte of the key.
func loadSigningKey(pemText string) (ed25519.PrivateKey, error) {
	if pemText == "" {
		return nil, fmt.Errorf("%s is empty; set it to the ed25519 PKCS#8 PEM private key", signingKeyEnv)
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("%s does not contain a PEM block", signingKeyEnv)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s holds a %q PEM block, want \"PRIVATE KEY\" (PKCS#8)", signingKeyEnv, block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid PKCS#8 private key", signingKeyEnv)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is a %T, want an ed25519 private key", signingKeyEnv, parsed)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s decodes to %d bytes, want %d", signingKeyEnv, len(key), ed25519.PrivateKeySize)
	}
	return key, nil
}
