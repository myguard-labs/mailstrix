package extract

// archivepw.go — bounded password-protected archive decryption (opt-in).
//
// When MAILSTRIX_ARCHIVE_PW is enabled (Options.ArchivePWEnabled) and the request
// carries candidate passwords (Options.PWCandidates, sourced from the mail
// subject/body/filename + an optional wordlist, already capped+deduped by the
// scanner), the archive unpackers try each candidate against a password-protected
// member instead of merely flagging ARCHIVE-ENCRYPTED. A member whose password is
// in the mail body is the classic "payload hidden from the scanner" trick; with
// the password in hand we can crack it and scan the real dropper inside.
//
// This is a brute-force loop over attacker-influenced inputs, so it is the primary
// DoS surface of the whole feature. Three independent bounds, all required:
//
//   1. Candidate-list size cap (≤64) — enforced upstream by the scanner.
//   2. Per-input global attempt cap (archiveBudget.decryptAttempts vs
//      maxDecryptAttempts) — KDF formats additionally get the much lower
//      maxKDFDecryptAttempts sub-cap because each 7z/rar/zip-AES attempt runs a
//      full key-derivation and re-opens the archive header.
//   3. Per-attempt deadline check (expired) INSIDE the candidate loop — a single
//      member with a long candidate list must not overrun the scan deadline (same
//      lesson as the XLM inner-loop deadline fix).
//
// Fail-open is absolute: any error, panic, or cap hit degrades to "skip the
// member, keep ARCHIVE-ENCRYPTED", never fatal, never drops the scan. Every
// third-party decrypt call is wrapped in an unconditional local recover — yeka/zip
// and the 7z/rar libs are fed hostile input, so a panic from any of them must be
// contained regardless of how well-behaved they look in the common case.

import (
	"bytes"
	"io"
	"time"

	"github.com/bodgit/sevenzip"
	rardecode "github.com/nwaples/rardecode/v2"
	yekazip "github.com/yeka/zip"
)

// maxDecryptAttemptTime hard-caps how long we WAIT on a SINGLE decrypt attempt.
// The third-party decrypt libs are fed hostile ciphertext and can spin for seconds
// on a crafted member (a malformed central directory / a decompress loop) — far
// longer than the between-attempt deadline check can catch, since that check only
// fires between attempts, never mid-call. Each attempt therefore runs on a pooled
// worker bounded by this cap (and the remaining scan deadline); if it overruns, we
// stop waiting and count a miss, but the decoder cannot be cancelled and keeps its
// worker slot until it really returns — see archiveworker.go for what that buys and
// why the caller must then stop feeding this archive. Fail-open: an abandoned
// attempt keeps ARCHIVE-ENCRYPTED.
const maxDecryptAttemptTime = 750 * time.Millisecond

const (
	// maxDecryptAttempts is the global per-input ceiling on decrypt attempts
	// (candidates × encrypted members, summed across all archive layers). 256 ≈
	// 64 candidates × 4 members — generous for the cheap ZipCrypto path, hard cap
	// against a zip stuffed with thousands of encrypted members.
	maxDecryptAttempts = 256
	// maxKDFDecryptAttempts is the much lower sub-cap for KDF-bound formats
	// (7z, rar, WinZip-AES zip). Each attempt runs a full PBKDF2/derivation and,
	// for 7z/rar, re-parses the (possibly itself-encrypted) archive header — so a
	// per-candidate full re-open × ≤64 × KDF can burn real seconds. 16 keeps the
	// worst case bounded while still covering a realistic body-extracted password
	// plus a small wordlist.
	maxKDFDecryptAttempts = 16
)

// markDecryptedArchive emits the ARCHIVE-DECRYPTED PURE marker the first time a
// password-protected member is successfully cracked in one input, at most once
// per input (mirrors markEncryptedArchive / the DEFAULTPW-DECRYPTED marker). It
// does NOT clear EncryptedArchive: an input may carry one member we cracked and
// another we did not, and both signals are independently useful.
func markDecryptedArchive(res *Result) {
	if res.DecryptedArchive {
		return
	}
	res.DecryptedArchive = true
	res.Streams = append(res.Streams, []byte("ARCHIVE-DECRYPTED"))
}

// pwCandidates returns the effective candidate list for this request, or nil when
// the feature is off / no candidates were sourced. res.childOpts carries the
// per-request Options down every recursion (set in ExtractWithOptions); nil means
// a top-level Extract / a test that built Result directly — feature off.
func pwCandidates(res *Result) []string {
	if res == nil || res.childOpts == nil || !res.childOpts.ArchivePWEnabled {
		return nil
	}
	return res.childOpts.PWCandidates
}

// kdfExhausted returns true once the KDF-format sub-cap is reached, counting ONLY
// KDF attempts (separate from the global counter, so cheap ZipCrypto attempts don't
// burn this budget). The global cap is still checked separately by the caller.
func (b *archiveBudget) kdfExhausted() bool {
	return b.kdfAttempts >= maxKDFDecryptAttempts
}

// decryptExhausted returns true once the global per-input attempt cap is reached, or
// once an attempt on this input has stalled. A stall latches: the decoder that blew
// its watchdog is still running and unkillable, so launching the next candidate would
// add a SECOND uncancellable worker for the same hostile member — one crafted archive
// would otherwise convert each of its ≤64 candidates into another abandoned decoder
// and drain the whole pool by itself. One stall ends decryption for this input; the
// member keeps ARCHIVE-ENCRYPTED (fail-open).
func (b *archiveBudget) decryptExhausted() bool {
	return b.decryptStalled || b.decryptAttempts >= maxDecryptAttempts
}

// markDecryptStalled latches the stall (see decryptExhausted).
func (b *archiveBudget) markDecryptStalled() {
	b.decryptStalled = true
}

// countAttempt records one decrypt attempt against both the global counter and, if
// the format is KDF-bound, the KDF sub-counter.
func (b *archiveBudget) countAttempt(kdf bool) {
	b.decryptAttempts++
	if kdf {
		b.kdfAttempts++
	}
}

// zipDecryptReader holds the archive buffer plus a one-time probe of the yeka view
// (does it parse? is the named member AES?) so the std-archive/zip unpack loop —
// which cannot decrypt — can crack encrypted members. Each decrypt ATTEMPT builds
// its OWN fresh yeka reader inside the bounded goroutine: yeka's *File carries the
// password as mutable state (SetPassword), so a reader must NEVER be shared across
// the runBounded watchdog boundary, where an abandoned goroutine could still be
// touching the same *File while the next attempt mutates it (a data race). A fresh
// per-attempt reader is the price of the watchdog; the attempt caps bound the count.
type zipDecryptReader struct {
	buf []byte
	ok  bool
}

// hasAESExtra reports whether a zip member's Extra field carries the WinZip-AES
// AE-x extra header (ID 0x9901), the reliable marker of an AES-encrypted (KDF-
// bound) member regardless of the placeholder compression Method. Each extra
// record is [id uint16][size uint16][data...], all little-endian.
func hasAESExtra(extra []byte) bool {
	for len(extra) >= 4 {
		id := uint16(extra[0]) | uint16(extra[1])<<8
		size := int(uint16(extra[2]) | uint16(extra[3])<<8)
		if 4+size > len(extra) {
			break
		}
		if id == 0x9901 {
			// Validate a well-formed AE-x record (APPNOTE 7.0.5 §"Extra field 0x9901":
			// data = [version uint16 (1=AE-1, 2=AE-2)][vendor 'A','E'][strength byte
			// (1=128,2=192,3=256)][actual compression method uint16], 7 bytes total).
			// A bogus 0x9901 stuffed onto a ZipCrypto entry to force the costly KDF
			// sub-cap is rejected here.
			d := extra[4 : 4+size]
			if size == 7 && (d[0] == 1 || d[0] == 2) && d[2] == 'A' && d[3] == 'E' &&
				d[4] >= 1 && d[4] <= 3 {
				return true
			}
		}
		extra = extra[4+size:]
	}
	return false
}

// newZipDecryptReader probes buf with a throwaway yeka reader (recovering from any
// parser panic) to learn whether it parses as a yeka zip at all. A failed probe
// yields a reader whose decryptMember always misses (fail-open) so the caller keeps
// ARCHIVE-ENCRYPTED. The buffer is retained; each attempt re-parses it fresh.
func newZipDecryptReader(buf []byte) (zd *zipDecryptReader) {
	zd = &zipDecryptReader{buf: buf}
	zd.ok = true // every parse is bounded inside runBounded; a bad buffer just misses
	return zd
}

// decryptMember tries each candidate against the encrypted member at std-zip index
// idx under the shared budget + deadline. Returns the plaintext on the first
// candidate that works, or nil (miss / cap / deadline / oversized). The member is
// addressed by INDEX, not name — a zip can carry duplicate member names, and the
// yeka reader walks the central directory in the same order as the std-zip reader,
// so index idx is the SAME member. Each attempt builds its own yeka reader inside
// runBounded (no shared mutable *File across the watchdog; the parse is bounded so
// a malformed central directory can't stall before the attempt caps apply).
func (zd *zipDecryptReader) decryptMember(idx int, kdf bool, declared uint64, cands []string, b *archiveBudget, deadline time.Time) []byte {
	if zd == nil || !zd.ok {
		return nil
	}
	if declared > maxBytesPerMember {
		return nil // implausibly large member (zip-bomb guard), mirrors cleartext path
	}
	// kdf (WinZip-AES vs cheap ZipCrypto) is determined by the caller from the
	// std-zip member's validated AE-x extra — no yeka parse here, so a post-cap
	// member pays nothing before the cap checks below short-circuit.
	for _, pw := range cands {
		if expired(deadline) || b.decryptExhausted() {
			return nil
		}
		if kdf && b.kdfExhausted() {
			return nil
		}
		b.countAttempt(kdf)
		buf, pw := zd.buf, pw
		plain, stalled := runBounded(deadline, func() []byte { return openYekaMemberFresh(buf, idx, pw) })
		if stalled {
			b.markDecryptStalled() // decoder still running: launch nothing more for this input
			return nil
		}
		if plain != nil {
			return plain
		}
	}
	return nil
}

// openYekaMemberFresh builds its OWN yeka reader over buf, takes the member at
// index idx, sets the password, and reads it, bounded by maxBytesPerMember, under
// an unconditional recover. A fresh reader per call means the mutable *File
// password state is never shared with another goroutine (the runBounded watchdog
// can abandon this call mid-flight). Returns the plaintext or nil on any failure.
func openYekaMemberFresh(buf []byte, idx int, pw string) (out []byte) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	r, err := yekazip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil || idx < 0 || idx >= len(r.File) {
		return nil
	}
	if f := r.File[idx]; f.IsEncrypted() {
		return openYekaMember(f, pw)
	}
	return nil
}

// openYekaMember sets the password and reads the member, bounded by
// maxBytesPerMember, with an unconditional recover around the third-party
// decrypt+inflate. The caller MUST own f exclusively (a fresh per-attempt reader);
// f.SetPassword mutates shared state. Returns the plaintext or nil on any failure.
func openYekaMember(f *yekazip.File, pw string) (out []byte) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	f.SetPassword(pw)
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	var buf bytes.Buffer
	// A wrong ZipCrypto password usually fails the 1-byte check at Open or within
	// the first bytes of Read; AES fails the HMAC at EOF. Either way a read error
	// means "wrong password" — fail open to nil.
	if _, err := buf.ReadFrom(io.LimitReader(rc, maxBytesPerMember)); err != nil {
		return nil
	}
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

// crack7zPassword finds the password that decrypts buf, or "" if none in cands do.
// 7z applies ONE password per archive, so a single found password unlocks every
// member. The candidate is VALIDATED by actually reading a member's bytes inside
// the bounded attempt — opening the reader (even NewReaderWithPassword succeeding)
// does NOT prove the password for a content-encrypted 7z, whose decrypt error only
// surfaces on Read. KDF-bound → the lower sub-cap applies. The caller re-opens a
// fresh reader with the returned password to walk the members.
// crack7zPassword finds the password for buf. targetIdx is the index of the member
// that triggered cracking (it failed a no-password read, so it IS encrypted); pass
// -1 for the header-encrypted case (whole listing hidden → any member validates).
// A wrong password is rejected by reading that ENCRYPTED member — never a sibling
// plaintext member, which would read cleanly under any password and false-validate.
func crack7zPassword(buf []byte, targetIdx int, cands []string, b *archiveBudget, deadline time.Time) string {
	for _, pw := range cands {
		if expired(deadline) || b.decryptExhausted() || b.kdfExhausted() {
			return ""
		}
		b.countAttempt(true)
		pw := pw
		ok, stalled := runBounded(deadline, func() bool { return verify7zPassword(buf, targetIdx, pw) })
		if stalled {
			b.markDecryptStalled() // decoder still running: launch nothing more for this input
			return ""
		}
		if ok {
			return pw
		}
	}
	return ""
}

// verify7zPassword reports whether pw decrypts buf, proven by reading the bytes of
// the encrypted member at targetIdx (or, when targetIdx<0, the first regular member
// — only valid for the header-encrypted case where every member is encrypted). A
// wrong password trips the decompressor on Read. Unconditional recover.
func verify7zPassword(buf []byte, targetIdx int, pw string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	r, err := sevenzip.NewReaderWithPassword(bytes.NewReader(buf), int64(len(buf)), pw)
	if err != nil {
		return false
	}
	readOne := func(f *sevenzip.File) bool {
		// Validate only on a member that fits the per-member cap, and read it to
		// EOF: a truncated read at the cap returns no error and could "validate" a
		// wrong password before the format's CRC/HMAC-at-EOF check fires.
		if f.UncompressedSize > maxBytesPerMember {
			return false
		}
		rc, err := f.Open()
		if err != nil {
			return false
		}
		n, rerr := io.Copy(io.Discard, io.LimitReader(rc, maxBytesPerMember+1))
		_ = rc.Close()
		return rerr == nil && n <= maxBytesPerMember
	}
	if targetIdx >= 0 && targetIdx < len(r.File) {
		f := r.File[targetIdx]
		if f.FileInfo().IsDir() {
			return false
		}
		return readOne(f)
	}
	// Header-encrypted: no specific trigger member, every member needs the password.
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		return readOne(f)
	}
	return false
}

// open7zReader builds a 7z reader with a KNOWN-GOOD password (from crack7zPassword)
// under an unconditional recover. Returns nil on any error/panic.
func open7zReader(buf []byte, pw string) (zr *sevenzip.Reader) {
	defer func() {
		if recover() != nil {
			zr = nil
		}
	}()
	r, err := sevenzip.NewReaderWithPassword(bytes.NewReader(buf), int64(len(buf)), pw)
	if err != nil {
		return nil
	}
	return r
}

// crackRarPassword finds the password that decrypts buf, or "" if none do. RAR
// applies one password per archive. The candidate is VALIDATED by reading a
// member's bytes inside the bounded attempt — rar password/KDF validation happens
// on Next/Read, not at NewReader, so construction success alone doesn't prove the
// password (and a wrong first candidate must NOT stop the brute-force). KDF-bound.
func crackRarPassword(buf []byte, cands []string, b *archiveBudget, deadline time.Time) string {
	for _, pw := range cands {
		if expired(deadline) || b.decryptExhausted() || b.kdfExhausted() {
			return ""
		}
		b.countAttempt(true)
		pw := pw
		ok, stalled := runBounded(deadline, func() bool { return verifyRarPassword(buf, pw) })
		if stalled {
			b.markDecryptStalled() // decoder still running: launch nothing more for this input
			return ""
		}
		if ok {
			return pw
		}
	}
	return ""
}

// verifyRarPassword reports whether pw decrypts buf, proven by reading the first
// regular-file member's bytes. A wrong password fails at Next() (header-encrypted)
// or Read() (content-encrypted). Unconditional recover around the third-party lib.
func verifyRarPassword(buf []byte, pw string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	rr, err := rardecode.NewReader(bytes.NewReader(buf), rardecode.Password(pw))
	if err != nil {
		return false
	}
	// Validate against the first ENCRYPTED file member: a plaintext sibling reads
	// cleanly under ANY password and would false-validate a wrong candidate. A
	// header-encrypted RAR reports the encrypted flag on every member (and may even
	// fail Next() with a wrong password), so this still validates correctly.
	for {
		h, err := rr.Next()
		if err != nil {
			return false // wrong password (header-encrypted) or EOF before any encrypted file
		}
		if h.IsDir {
			continue
		}
		// SOLID: give up on the whole archive, do not verify. Decoding a solid member
		// requires inflating every predecessor (the dictionary), which is the
		// uncancellable, time-unbounded decode the extractor refuses to run at all — see
		// the block comment above boundedRarMemberFresh. Verifying here would drag that
		// decode back in through the crack loop, and rardecode's own Next() would inflate
		// the body on the very next iteration regardless of what we read. A solid RAR is
		// simply not unpacked, so there is nothing to unlock: report no match.
		if h.Solid {
			return false
		}
		if !(h.Encrypted || h.HeaderEncrypted) {
			continue // plaintext member — reading it proves nothing about the password
		}
		if h.UnPackedSize > maxBytesPerMember {
			return false // can't validate an oversized member; treat as unverified
		}
		// Read to EOF (cap+1 then check) so a cap-truncated read can't validate a
		// wrong password ahead of the format's end-of-stream integrity check.
		n, rerr := io.Copy(io.Discard, io.LimitReader(rr, maxBytesPerMember+1))
		return rerr == nil && n <= maxBytesPerMember // encrypted member read cleanly => pw correct
	}
}

// openRarReader builds a RAR reader with a KNOWN-GOOD password (from
// crackRarPassword) under an unconditional recover. Returns nil on any error/panic.
func openRarReader(buf []byte, pw string) (rr *rardecode.Reader) {
	defer func() {
		if recover() != nil {
			rr = nil
		}
	}()
	r, err := rardecode.NewReader(bytes.NewReader(buf), rardecode.Password(pw))
	if err != nil {
		return nil
	}
	return r
}
