package oleparse

import (
	"bytes"
	"testing"
)

// oldReadChain is the upstream (pre-fork) implementation, kept here only to
// prove the fork is byte-for-byte equivalent and to benchmark allocs/op.
func oldReadChain(
	start uint32,
	ReadSector func(uint32) []byte,
	ReadFat func(sector uint32) (uint32, bool),
) []byte {
	check := make(map[uint32]bool)
	result := []byte{}

	for sector := start; sector != ENDOFCHAIN; {
		result = append(result, ReadSector(sector)...)
		next, ok := ReadFat(sector)
		if !ok {
			return result
		}
		_, pres := check[next]
		if pres {
			return result
		}
		check[next] = true
		sector = next
	}
	return result
}

// chainEnv builds in-memory ReadSector/ReadFat closures over a sector table and
// a FAT, mirroring the on-disk layout the real OLEFile walks.
func chainEnv(sectors [][]byte, fat []uint32) (func(uint32) []byte, func(uint32) (uint32, bool)) {
	readSector := func(s uint32) []byte {
		if int(s) >= len(sectors) {
			return nil
		}
		return sectors[s]
	}
	readFat := func(s uint32) (uint32, bool) {
		if int(s) >= len(fat) {
			return 0, false
		}
		return fat[s], true
	}
	return readSector, readFat
}

const sectorSize = 512

func buildSectors(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		b := make([]byte, sectorSize)
		for j := range b {
			b[j] = byte(i + j)
		}
		out[i] = b
	}
	return out
}

// linearChain: sectors 0..n-1 chained 0->1->...->(n-1)->ENDOFCHAIN.
func linearChain(n int) (start uint32, sectors [][]byte, fat []uint32) {
	sectors = buildSectors(n)
	fat = make([]uint32, n)
	for i := 0; i < n-1; i++ {
		fat[i] = uint32(i + 1)
	}
	fat[n-1] = ENDOFCHAIN
	return 0, sectors, fat
}

func TestReadChainEquivalentMultiSector(t *testing.T) {
	start, sectors, fat := linearChain(64)
	rs, rf := chainEnv(sectors, fat)
	self := &OLEFile{}

	got := self._ReadChain(start, rs, rf)
	want := oldReadChain(start, rs, rf)

	if !bytes.Equal(got, want) {
		t.Fatalf("multi-sector chain mismatch: got %d bytes want %d bytes", len(got), len(want))
	}
	if len(got) != 64*sectorSize {
		t.Fatalf("expected %d bytes, got %d", 64*sectorSize, len(got))
	}
}

func TestReadChainCyclicDoesNotHang(t *testing.T) {
	// 0->1->2->0 (cycle back to start). The check map only records `next`
	// values, never `start`, so the cycle is detected when next==1 is seen
	// a second time. Must terminate and match upstream output exactly.
	sectors := buildSectors(3)
	fat := []uint32{1, 2, 0}
	rs, rf := chainEnv(sectors, fat)
	self := &OLEFile{}

	got := self._ReadChain(0, rs, rf)
	want := oldReadChain(0, rs, rf)

	if !bytes.Equal(got, want) {
		t.Fatalf("cyclic chain mismatch: got %d want %d bytes", len(got), len(want))
	}
}

func TestReadChainInvalidSectorEarlyReturn(t *testing.T) {
	// chain 0->1->(invalid: fat too short so ReadFat returns ok=false at 1).
	sectors := buildSectors(3)
	fat := []uint32{1} // only sector 0 has a FAT entry
	rs, rf := chainEnv(sectors, fat)
	self := &OLEFile{}

	got := self._ReadChain(0, rs, rf)
	want := oldReadChain(0, rs, rf)

	if !bytes.Equal(got, want) {
		t.Fatalf("invalid-sector chain mismatch: got %d want %d bytes", len(got), len(want))
	}
	// Should have copied sectors 0 and 1 (ReadFat fails AFTER copying 1).
	if len(got) != 2*sectorSize {
		t.Fatalf("expected early return after 2 sectors, got %d bytes", len(got))
	}
}

func TestReadChainStartIsEndOfChain(t *testing.T) {
	rs, rf := chainEnv(nil, nil)
	self := &OLEFile{}
	got := self._ReadChain(ENDOFCHAIN, rs, rf)
	want := oldReadChain(ENDOFCHAIN, rs, rf)
	if !bytes.Equal(got, want) || len(got) != 0 {
		t.Fatalf("empty chain mismatch: got %d bytes", len(got))
	}
}

func BenchmarkReadChain(b *testing.B) {
	start, sectors, fat := linearChain(256)
	rs, rf := chainEnv(sectors, fat)
	self := &OLEFile{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = self._ReadChain(start, rs, rf)
	}
}

func BenchmarkReadChainOld(b *testing.B) {
	start, sectors, fat := linearChain(256)
	rs, rf := chainEnv(sectors, fat)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = oldReadChain(start, rs, rf)
	}
}
