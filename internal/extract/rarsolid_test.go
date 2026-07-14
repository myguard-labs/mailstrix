package extract

import (
	"bytes"
	"os"
	"testing"
	"time"
)

// rarSolidBitOffset is the offset of the RAR5 main-header ARCHIVE-FLAGS byte in
// testdata/payload.rar:
//
//	sig(8) + crc32(4) + hdrSize varint(1) + htype varint(1) + flags varint(1) + extraSize varint(1)
//
// That last field is the trap this whole test file exists to pin. The fixture's block
// flags are 0x05, which sets block5HasExtra — so an extra-area size varint sits BETWEEN
// the block flags and the archive flags. A parser that forgets to skip it reads the
// extra-size byte (0x06, which happens to have bit 0x04 set) as the archive flags and
// concludes SOLID for every ordinary archive — turning A10's refusal into a blanket
// "no RAR is ever extracted". Verified against the real fixture: byte 16 is 0x00.
const rarSolidBitOffset = 16

// TestRarArchiveIsSolidReadsTheArchiveFlag is the direct unit test for the A10 parser.
//
// It must be asserted at THIS level, not only end-to-end, because flipping the solid bit
// invalidates the header CRC — so a bit-flipped fixture is also a CORRUPT archive, and
// rardecode would refuse it anyway. An end-to-end test alone therefore cannot distinguish
// "refused because solid" (the behaviour we want) from "refused because corrupt" (which
// would pass even if the solid detection were entirely broken).
func TestRarArchiveIsSolidReadsTheArchiveFlag(t *testing.T) {
	clean, err := os.ReadFile("testdata/payload.rar")
	if err != nil {
		t.Skipf("no rar fixture: %v", err)
	}

	if rarArchiveIsSolid(clean) {
		t.Fatal("real non-solid RAR reported SOLID: the parser is misreading the archive-flags field " +
			"(most likely not skipping the extra-area size varint), which would refuse every RAR")
	}

	solid := make([]byte, len(clean))
	copy(solid, clean)
	solid[rarSolidBitOffset] |= rar5ArcSolid

	if !rarArchiveIsSolid(solid) {
		t.Fatal("archive with arc5Solid set reported NON-solid: the A10 guard is inert, and a solid " +
			"archive would reach rardecode, whose Next() drains member bodies on the scan goroutine")
	}
}

// TestRarSolidArchiveIsNotHandedToDecoder is the end-to-end half: a solid archive must be
// marked and counted, but never unpacked.
func TestRarSolidArchiveIsNotHandedToDecoder(t *testing.T) {
	drainPool(t)

	clean, err := os.ReadFile("testdata/payload.rar")
	if err != nil {
		t.Skipf("no rar fixture: %v", err)
	}
	solid := make([]byte, len(clean))
	copy(solid, clean)
	solid[rarSolidBitOffset] |= rar5ArcSolid

	before := PlainDroppedMembers()
	res := &Result{}
	unpackRar(solid, res, &archiveBudget{}, 0, time.Now().Add(5*time.Second))

	if !res.IsArchive {
		t.Fatal("solid RAR was not marked IsArchive: the refusal must keep the signal, not drop it")
	}
	if len(res.Streams) != 0 {
		t.Fatalf("solid RAR produced %d member streams; want 0 — its bytes must never reach the decoder",
			len(res.Streams))
	}
	if got := PlainDroppedMembers() - before; got != 1 {
		t.Fatalf("plainDropped delta = %d; want 1 — the refusal is a real detection loss and must be counted, not silent", got)
	}
	drainPool(t)
}

// TestRarSolidGuardFailsSafe pins the fail-safe direction. Every "cannot parse this"
// path must report SOLID (refuse), never non-solid.
//
// If a malformed header fell through to "not solid", an attacker could bypass the A10
// guard entirely by corrupting a single byte of the main header — and get the
// uncancellable inline drain back on the scan goroutine. Refusing a corrupt archive
// costs nothing: rardecode would have failed on it too.
func TestRarSolidGuardFailsSafe(t *testing.T) {
	clean, err := os.ReadFile("testdata/payload.rar")
	if err != nil {
		t.Skipf("no rar fixture: %v", err)
	}

	// These carry a classifiable signature (so rardecode WOULD try to open them and could
	// reach the solid drain) but a header we cannot parse — they must fail SAFE (refuse).
	refuse := map[string][]byte{
		"rar5 truncated mid main header": clean[:12],
		"rar5 sig then garbage body":     append([]byte("Rar!\x1a\x07\x01\x00"), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
		"rar4 sig then garbage body":     append([]byte("Rar!\x1a\x07\x00"), 0x00, 0x00, 0x73, 0xff),
	}
	for name, buf := range refuse {
		if !rarArchiveIsSolid(buf) {
			t.Errorf("%s: reported NON-solid; a classifiable-but-unparseable RAR header must fail SAFE "+
				"(refuse), or the guard is bypassable by corrupting the header", name)
		}
	}

	// No signature rardecode's findSig would accept anywhere in the buffer ⇒ rardecode
	// returns ErrNoSig and never opens the archive, so the solid drain cannot run. Here
	// non-solid is the correct answer and keeps the plainDropped gauge free of noise.
	// (A buffer that DOES carry a classifiable signature but too short a body to parse is
	// deliberately allowed to fail-safe as solid — that is a harmless rounding of noise,
	// not a bypass, so it is not asserted here.)
	unopenable := map[string][]byte{
		"no signature at all":      []byte("PK\x03\x04not a rar at all, plain zip bytes"),
		"sig prefix but too short": []byte("Rar!\x1a"),
	}
	for name, buf := range unopenable {
		if rarArchiveIsSolid(buf) {
			t.Errorf("%s: reported SOLID; rardecode never finds a signature here so it never reaches "+
				"the drain — refusing it would only add plainDropped noise", name)
		}
	}

	// A non-RAR must NOT be claimed as solid: it never reaches rardecode's RAR path, and
	// claiming it would pollute the plainDropped detection-loss gauge with noise.
	if rarArchiveIsSolid([]byte("PK\x03\x04not a rar at all")) {
		t.Error("a non-RAR buffer was reported solid; the guard must only speak about RAR archives")
	}
}

// TestRarSolidGuardMatchesRardecodeSignatureSearch is the regression guard for the
// signature-offset bypass. rardecode's findSig scans the first 1 MiB for the signature
// (self-extracting-archive support) and skips a decoy "Rar!\x1a\x07" whose version byte
// is not one it accepts. A guard that only inspected offset 0 would call such a buffer
// non-solid and hand it to rardecode, which finds the REAL signature deeper in and drains
// the solid body on the scan goroutine — the DoS A10 closes, reopened for a few bytes.
//
// So: a solid archive with a prepended decoy sig, and one with an arbitrary SFX stub,
// must BOTH be detected as solid and produce zero member streams.
func TestRarSolidGuardMatchesRardecodeSignatureSearch(t *testing.T) {
	clean, err := os.ReadFile("testdata/payload.rar")
	if err != nil {
		t.Skipf("no rar fixture: %v", err)
	}
	solid := make([]byte, len(clean))
	copy(solid, clean)
	solid[rarSolidBitOffset] |= rar5ArcSolid

	prefixes := map[string][]byte{
		// A valid sigPrefix with an invalid version byte (0xff): rardecode's findSig
		// skips it and keeps scanning, landing on the embedded archive.
		"decoy signature with bad version": []byte("Rar!\x1a\x07\x01\xff"),
		// An arbitrary self-extracting stub before the real signature.
		"sfx stub":              []byte("MZ\x90\x00 this is a fake unpacker stub \x00\x00"),
		"decoy prefix byte run": bytes.Repeat([]byte("R"), 64),
	}
	for name, prefix := range prefixes {
		buf := append(append([]byte{}, prefix...), solid...)

		if !rarArchiveIsSolid(buf) {
			t.Errorf("%s: prepended-then-solid archive reported NON-solid; the guard must locate the "+
				"signature the way rardecode does, or it is bypassable by prepending bytes", name)
		}

		drainPool(t)
		res := &Result{}
		unpackRar(buf, res, &archiveBudget{}, 0, time.Now().Add(5*time.Second))
		if len(res.Streams) != 0 {
			t.Errorf("%s: unpackRar produced %d streams; a solid archive behind a prefix must never be decoded",
				name, len(res.Streams))
		}
		drainPool(t)
	}
}

// TestRarSolidGuardCrossChecksRardecode is a differential test against rardecode itself.
// rarFindSig mirrors rardecode's findSig, but the two advance the scan cursor differently
// after rejecting a decoy signature (rardecode steps past the whole prefix; we step one
// byte). That divergence is only safe if it never changes WHICH signature is accepted
// first — so this test pins exactly that: across decoys, overlapping decoys and SFX stubs,
// whatever rardecode opens, our guard must agree on. Concretely: if rardecode opens the
// (non-solid) fixture, we must NOT refuse it (that would mean we parsed a different offset);
// and separately, a solid archive behind the same prefixes must still be refused.
func TestRarSolidGuardCrossChecksRardecode(t *testing.T) {
	clean, err := os.ReadFile("testdata/payload.rar")
	if err != nil {
		t.Skipf("no rar fixture: %v", err)
	}
	solid := make([]byte, len(clean))
	copy(solid, clean)
	solid[rarSolidBitOffset] |= rar5ArcSolid

	prefixes := map[string][]byte{
		"decoy bad version":         []byte("Rar!\x1a\x07\x01\xff"),
		"two decoys":                []byte("Rar!\x1a\x07\x05Rar!\x1a\x07\x03"),
		"overlapping decoys":        []byte("Rar!\x1aRar!\x1a\x07\xff\xffRar!\x1a\x07\x09"),
		"decoy run":                 bytes.Repeat([]byte("Rar!\x1a\x07\xfe"), 8),
		"sfx-ish stub then partial": append([]byte("MZ sfx stub padding "), []byte("Rar!\x1a")...),
	}
	for name, p := range prefixes {
		// Non-solid fixture behind the prefix: we must agree with rardecode that it opens.
		nonSolid := append(append([]byte{}, p...), clean...)
		if rarArchiveIsSolid(nonSolid) {
			t.Errorf("%s: refused a NON-solid archive rardecode would open — the scan-advance "+
				"divergence made us parse the wrong signature offset", name)
		}
		// Solid fixture behind the same prefix: must still be refused (no bypass).
		if !rarArchiveIsSolid(append(append([]byte{}, p...), solid...)) {
			t.Errorf("%s: a SOLID archive behind this prefix slipped past the guard", name)
		}
	}
}

// TestRarSolidGuardRar4 covers the RAR 1.5–4.x framing, whose main-header solid bit is a
// different bit (0x0008) in a different, fixed-width header layout than RAR5's.
func TestRarSolidGuardRar4(t *testing.T) {
	// RAR4 main block: crc16(2) htype(1)=0x73 flags(2,LE) size(2,LE), size counts the
	// whole 7-byte header (13 with the comment field, which we do not set).
	mk := func(flags uint16) []byte {
		b := []byte("Rar!\x1a\x07\x00")
		return append(b, 0x00, 0x00, rar4BlockArc, byte(flags), byte(flags>>8), 0x07, 0x00)
	}

	if rarArchiveIsSolid(mk(0x0000)) {
		t.Error("RAR4 archive without the solid bit reported SOLID; this would refuse every RAR4")
	}
	if !rarArchiveIsSolid(mk(rar4ArcSolid)) {
		t.Error("RAR4 archive WITH arcSolid (0x0008) reported non-solid; the RAR4 arm of the A10 guard is inert")
	}
}
