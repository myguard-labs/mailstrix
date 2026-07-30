package oleparse

import (
	"bytes"
	"testing"
	"time"
)

// miniChainOLE builds an OLEFile exposing only what ReadMiniChain*/ReadMiniSector/
// ReadMiniFat need: a ministream and a MiniFat table. MiniSectorSize mirrors the
// real default (1 << miniSectorShift == 64), matching miniOLE's on-disk layout.
func miniChainOLE(ministream []byte, miniFat []uint32) *OLEFile {
	return &OLEFile{
		ministream:     ministream,
		MiniFat:        miniFat,
		MiniSectorSize: 1 << miniSectorShift,
	}
}

// buildMiniSectors returns n mini-sectors of miniSectorSize bytes each,
// concatenated into a single ministream, with byte i,j = byte(i+j) so a wrong
// sector shows up as wrong content, not just wrong length.
func buildMiniSectors(n int) []byte {
	miniSectorSize := 1 << miniSectorShift
	out := make([]byte, n*miniSectorSize)
	for i := 0; i < n; i++ {
		for j := 0; j < miniSectorSize; j++ {
			out[i*miniSectorSize+j] = byte(i + j)
		}
	}
	return out
}

// linearMiniChain: mini-sectors 0..n-1 chained 0->1->...->(n-1)->ENDOFCHAIN.
func linearMiniChain(n int) (start uint32, ministream []byte, miniFat []uint32) {
	ministream = buildMiniSectors(n)
	miniFat = make([]uint32, n)
	for i := 0; i < n-1; i++ {
		miniFat[i] = uint32(i + 1)
	}
	miniFat[n-1] = ENDOFCHAIN
	return 0, ministream, miniFat
}

// --- ReadMiniChain: happy path -------------------------------------------

func TestReadMiniChainReadsBackExpectedBytes(t *testing.T) {
	start, ministream, miniFat := linearMiniChain(4)
	ole := miniChainOLE(ministream, miniFat)

	got := ole.ReadMiniChain(start)

	if !bytes.Equal(got, ministream) {
		t.Fatalf("ReadMiniChain returned %d bytes, want %d bytes matching the ministream", len(got), len(ministream))
	}
}

func TestReadMiniChainSingleSector(t *testing.T) {
	start, ministream, miniFat := linearMiniChain(1)
	ole := miniChainOLE(ministream, miniFat)

	got := ole.ReadMiniChain(start)

	if !bytes.Equal(got, ministream) {
		t.Fatalf("single mini-sector chain mismatch: got %d bytes want %d", len(got), len(ministream))
	}
}

// --- ReadMiniChain: hostile input ----------------------------------------

func TestReadMiniChainZeroChainStartIsEndOfChain(t *testing.T) {
	ole := miniChainOLE(nil, nil)

	got := ole.ReadMiniChain(ENDOFCHAIN)

	if len(got) != 0 {
		t.Fatalf("ReadMiniChain(ENDOFCHAIN) = %d bytes, want 0", len(got))
	}
}

func TestReadMiniChainCyclicDoesNotHang(t *testing.T) {
	// 0->1->2->0: a cycle back to the start sector. Must terminate.
	ministream := buildMiniSectors(3)
	miniFat := []uint32{1, 2, 0}
	ole := miniChainOLE(ministream, miniFat)

	done := make(chan []byte, 1)
	go func() { done <- ole.ReadMiniChain(0) }()

	select {
	case got := <-done:
		miniSectorSize := 1 << miniSectorShift
		// 0->1->2->0: sectors 0,1,2 are copied, then sector 0 is visited again
		// (its FAT successor `1` was already seen) so the walk detects the
		// cycle only after re-copying sector 0 - four sector-copies total.
		want := 4 * miniSectorSize
		if len(got) != want {
			t.Fatalf("cyclic mini-chain returned %d bytes, want %d", len(got), want)
		}
	case <-timeoutCh(t):
		t.Fatal("ReadMiniChain hung on a cyclic mini-FAT chain")
	}
}

func TestReadMiniChainSelfLoopDoesNotHang(t *testing.T) {
	// sector 0 points at itself immediately.
	ministream := buildMiniSectors(1)
	miniFat := []uint32{0}
	ole := miniChainOLE(ministream, miniFat)

	done := make(chan []byte, 1)
	go func() { done <- ole.ReadMiniChain(0) }()

	select {
	case got := <-done:
		miniSectorSize := 1 << miniSectorShift
		// sector 0 -> 0: copied on the first visit, then copied again before
		// the cycle (next==0 already seen) is detected - two copies.
		want := 2 * miniSectorSize
		if len(got) != want {
			t.Fatalf("self-loop mini-chain returned %d bytes, want %d", len(got), want)
		}
	case <-timeoutCh(t):
		t.Fatal("ReadMiniChain hung on a self-referencing mini-FAT sector")
	}
}

func TestReadMiniChainOutOfRangeSectorStopsCleanly(t *testing.T) {
	// sector 0 -> sector 99, which has no MiniFat entry (out of range).
	ministream := buildMiniSectors(1)
	miniFat := []uint32{99}
	ole := miniChainOLE(ministream, miniFat)

	got := ole.ReadMiniChain(0)

	miniSectorSize := 1 << miniSectorShift
	if len(got) != miniSectorSize {
		t.Fatalf("out-of-range next-sector chain returned %d bytes, want %d (only sector 0 copied)", len(got), miniSectorSize)
	}
}

func TestReadMiniChainStartOutOfRangeReturnsEmpty(t *testing.T) {
	// start sector itself has no mini-sector data and no MiniFat entry.
	ole := miniChainOLE(nil, nil)

	got := ole.ReadMiniChain(5)

	if len(got) != 0 {
		t.Fatalf("ReadMiniChain with out-of-range start = %d bytes, want 0", len(got))
	}
}

func TestReadMiniChainFreesectSentinelInFatStopsChain(t *testing.T) {
	// sector 0 -> FREESECT, an illegal successor (not ENDOFCHAIN). The walk
	// must not treat FREESECT as a valid sector index and must not hang.
	ministream := buildMiniSectors(1)
	miniFat := []uint32{FREESECT}
	ole := miniChainOLE(ministream, miniFat)

	done := make(chan []byte, 1)
	go func() { done <- ole.ReadMiniChain(0) }()

	select {
	case got := <-done:
		miniSectorSize := 1 << miniSectorShift
		if len(got) != miniSectorSize {
			t.Fatalf("FREESECT-terminated mini-chain returned %d bytes, want %d", len(got), miniSectorSize)
		}
	case <-timeoutCh(t):
		t.Fatal("ReadMiniChain hung when FAT successor was FREESECT")
	}
}

func TestReadMiniChainEmptyStreamReturnsEmpty(t *testing.T) {
	start, _, miniFat := linearMiniChain(1)
	ole := miniChainOLE(nil, miniFat) // ministream itself is empty/nil
	got := ole.ReadMiniChain(start)
	if len(got) != 0 {
		t.Fatalf("ReadMiniChain over an empty ministream = %d bytes, want 0", len(got))
	}
}

// --- ReadMiniChainSize: bounded/truncating behavior -----------------------

func TestReadMiniChainSizeTruncatesToRequestedSize(t *testing.T) {
	start, ministream, miniFat := linearMiniChain(4) // 4*64 = 256 bytes available
	ole := miniChainOLE(ministream, miniFat)

	const want = 100
	got := ole.ReadMiniChainSize(start, want)

	if len(got) != want {
		t.Fatalf("ReadMiniChainSize(_, %d) = %d bytes, want exactly %d", want, len(got), want)
	}
	if !bytes.Equal(got, ministream[:want]) {
		t.Fatal("ReadMiniChainSize truncated content mismatch")
	}
}

func TestReadMiniChainSizeCapsAtMinistreamLength(t *testing.T) {
	// declared size (attacker-controlled Directory.Header.Size) exceeds what
	// the ministream actually holds; must cap, not overread/panic.
	start, ministream, miniFat := linearMiniChain(2) // 128 bytes available
	ole := miniChainOLE(ministream, miniFat)

	got := ole.ReadMiniChainSize(start, 1<<40) // huge declared size

	if len(got) != len(ministream) {
		t.Fatalf("ReadMiniChainSize with oversized declared size = %d bytes, want capped to %d", len(got), len(ministream))
	}
}

func TestReadMiniChainSizeZeroReturnsEmpty(t *testing.T) {
	start, ministream, miniFat := linearMiniChain(2)
	ole := miniChainOLE(ministream, miniFat)

	got := ole.ReadMiniChainSize(start, 0)

	if len(got) != 0 {
		t.Fatalf("ReadMiniChainSize(_, 0) = %d bytes, want 0", len(got))
	}
}

func TestReadMiniChainSizeShorterThanChainStopsEarly(t *testing.T) {
	// A malicious/short declared size shorter than the actual chain must not
	// walk past the requested size (verifies early-return, not just capping).
	start, ministream, miniFat := linearMiniChain(4)
	ole := miniChainOLE(ministream, miniFat)

	const want = 10 // smaller than one mini-sector (64 bytes)
	got := ole.ReadMiniChainSize(start, want)

	if len(got) != want {
		t.Fatalf("ReadMiniChainSize truncated-below-one-sector = %d bytes, want %d", len(got), want)
	}
	if !bytes.Equal(got, ministream[:want]) {
		t.Fatal("ReadMiniChainSize content mismatch on short declared size")
	}
}

// --- ReadMiniChainPrefix: bounded/truncating behavior ----------------------

func TestReadMiniChainPrefixTruncatesToLimit(t *testing.T) {
	start, ministream, miniFat := linearMiniChain(4)
	ole := miniChainOLE(ministream, miniFat)

	const limit = 70 // spans into the second mini-sector
	got := ole.ReadMiniChainPrefix(start, limit)

	if len(got) != limit {
		t.Fatalf("ReadMiniChainPrefix(_, %d) = %d bytes, want %d", limit, len(got), limit)
	}
	if !bytes.Equal(got, ministream[:limit]) {
		t.Fatal("ReadMiniChainPrefix content mismatch")
	}
}

func TestReadMiniChainPrefixNegativeLimitReturnsEmpty(t *testing.T) {
	start, ministream, miniFat := linearMiniChain(2)
	ole := miniChainOLE(ministream, miniFat)

	got := ole.ReadMiniChainPrefix(start, -1)

	if len(got) != 0 {
		t.Fatalf("ReadMiniChainPrefix with negative limit = %d bytes, want 0", len(got))
	}
}

func TestReadMiniChainPrefixCapsAtMinistreamLength(t *testing.T) {
	start, ministream, miniFat := linearMiniChain(2) // 128 bytes

	ole := miniChainOLE(ministream, miniFat)

	got := ole.ReadMiniChainPrefix(start, 1<<30)

	if len(got) != len(ministream) {
		t.Fatalf("ReadMiniChainPrefix with huge limit = %d bytes, want capped to %d", len(got), len(ministream))
	}
}

func TestReadMiniChainPrefixLongerThanChainReturnsWholeChain(t *testing.T) {
	// limit exceeds what the chain actually contains (but not the ministream
	// buffer) — must return the whole chain, not hang trying to fill the limit.
	start, ministream, miniFat := linearMiniChain(2) // 128 bytes total
	ole := miniChainOLE(append(ministream, buildMiniSectors(2)...), miniFat)

	got := ole.ReadMiniChainPrefix(start, 1000) // > 128, < len(ministream)=256

	if len(got) != len(ministream) {
		t.Fatalf("ReadMiniChainPrefix chain-shorter-than-limit = %d bytes, want %d (chain length, not limit)",
			len(got), len(ministream))
	}
}

func TestReadMiniChainSizeCyclicBoundedByLimitNotCycleDetection(t *testing.T) {
	// sector 0 -> 1 -> 0. Every sector here yields real bytes, so the limit cap
	// (len(result) >= limit) is what stops this particular cycle. That is NOT
	// true in general: a cycle of empty sectors makes no progress toward the
	// limit and terminates only via the check map. See
	// TestReadMiniChainSizeEmptySectorCycleTerminates.
	ministream := buildMiniSectors(2)
	miniFat := []uint32{1, 0}
	ole := miniChainOLE(ministream, miniFat)

	got := ole.ReadMiniChainSize(0, uint64(1)<<40) // declared size far exceeds the ministream

	if len(got) != len(ministream) {
		t.Fatalf("ReadMiniChainSize on cyclic chain = %d bytes, want capped to ministream length %d", len(got), len(ministream))
	}
}

func TestReadMiniChainPrefixCyclicBoundedByLimitNotCycleDetection(t *testing.T) {
	ministream := buildMiniSectors(2)
	miniFat := []uint32{1, 0}
	ole := miniChainOLE(ministream, miniFat)

	got := ole.ReadMiniChainPrefix(0, 1<<30)

	if len(got) != len(ministream) {
		t.Fatalf("ReadMiniChainPrefix on cyclic chain = %d bytes, want capped to ministream length %d", len(got), len(ministream))
	}
}

// --- shared hostile-chain coverage across all three entry points ----------

func TestReadMiniChainVariantsAgreeOnChainLongerThanDeclaredSize(t *testing.T) {
	// A chain with more sectors than the declared stream size must be
	// truncated to the declared size by both Size and Prefix variants, while
	// the raw ReadMiniChain (no size bound) returns the full chain.
	start, ministream, miniFat := linearMiniChain(8) // 512 bytes
	ole := miniChainOLE(ministream, miniFat)

	const declared = 50
	full := ole.ReadMiniChain(start)
	sized := ole.ReadMiniChainSize(start, declared)
	prefixed := ole.ReadMiniChainPrefix(start, declared)

	if len(full) != len(ministream) {
		t.Fatalf("ReadMiniChain (unbounded) = %d bytes, want full chain %d", len(full), len(ministream))
	}
	if len(sized) != declared {
		t.Fatalf("ReadMiniChainSize did not bound to declared size: got %d want %d", len(sized), declared)
	}
	if len(prefixed) != declared {
		t.Fatalf("ReadMiniChainPrefix did not bound to declared limit: got %d want %d", len(prefixed), declared)
	}
}

// timeoutCh returns a channel that fires after a generous bound, used only to
// turn a hang into a test failure instead of a stuck CI job. These tests only
// distinguish "terminates" from "loops forever", so the bound is deliberately far
// larger than any real run needs: a tight one buys nothing and goes flaky under
// -race on a loaded runner.
func timeoutCh(t *testing.T) <-chan time.Time {
	t.Helper()
	return time.After(5 * time.Second)
}

// A cycle whose sectors all read back ZERO bytes makes no progress toward the
// limit, so `len(result) >= limit` never fires and the limit cap cannot stop it.
// Termination rests entirely on _ReadChainLimit's `check` map. ReadMiniSector
// returns an empty slice for any sector starting at or past len(ministream),
// while ReadMiniFat keeps returning ok=true as long as the index is inside
// MiniFat, so this is reachable from a crafted mini-FAT.
func TestReadMiniChainSizeEmptySectorCycleTerminates(t *testing.T) {
	miniSectorSize := 1 << miniSectorShift
	// Sector 1 begins exactly at len(ministream): ReadMiniSector clamps its
	// read length to 0 and hands back an empty chunk rather than nil-ing out.
	ole := miniChainOLE(make([]byte, miniSectorSize), []uint32{1, 2, 1})

	done := make(chan []byte, 1)
	go func() { done <- ole.ReadMiniChainSize(1, 1<<20) }()

	select {
	case got := <-done:
		if len(got) != 0 {
			t.Fatalf("empty-sector cycle returned %d bytes, want 0", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadMiniChainSize hung on a cycle of empty sectors: the cycle-detection map is the only thing bounding this loop")
	}
}
