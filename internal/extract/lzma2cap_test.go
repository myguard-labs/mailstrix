package extract

import (
	"errors"
	"testing"
)

func TestLZMA2DictSize(t *testing.T) {
	cases := []struct {
		p    byte
		want uint64
		bad  bool
	}{
		{0, 4096, false},
		{1, 6144, false},
		{39, 3 << 30, false},
		{40, 0xFFFFFFFF, false},
		{41, 0, true},
		{255, 0, true},
	}
	for _, c := range cases {
		got, err := lzma2DictSize(c.p)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("p=%d: got %d err=%v", c.p, got, err)
		}
	}
}

func TestBoundedLZMA2Dict(t *testing.T) {
	if _, err := boundedLZMA2Dict(nil, 1); err == nil {
		t.Error("empty props accepted")
	}
	if _, err := boundedLZMA2Dict([]byte{1, 2}, 1); err == nil {
		t.Error("long props accepted")
	}
	if _, err := boundedLZMA2Dict([]byte{41}, 1); err == nil {
		t.Error("p=41 accepted")
	}
	if _, err := boundedLZMA2Dict([]byte{40}, 64<<20+1); !errors.Is(err, errLZMADictCap) {
		t.Errorf("p=40 big unpack: %v", err)
	}
	if d, err := boundedLZMA2Dict([]byte{40}, 1000); err != nil || d != lzma2DictCeiling {
		t.Errorf("p=40 small unpack: %d %v", d, err)
	}
	if d, err := boundedLZMA2Dict([]byte{0}, 10); err != nil || d != 4096 {
		t.Errorf("p=0: %d %v", d, err)
	}
	// p=28 declares exactly 64 MiB: at the ceiling passes whatever the unpack
	// size; p=29 (96 MiB, the next prop step) over 64 MiB+1 bytes is refused.
	for _, un := range []uint64{64 << 20, 64<<20 + 1, 1 << 40} {
		if d, err := boundedLZMA2Dict([]byte{28}, un); err != nil || d != lzma2DictCeiling {
			t.Errorf("p=28 unpack=%d: %d %v", un, d, err)
		}
	}
	if d, err := boundedLZMA2Dict([]byte{29}, 64<<20); err != nil || d != lzma2DictCeiling {
		t.Errorf("p=29 unpack=64MiB (effective at ceiling): %d %v", d, err)
	}
	if _, err := boundedLZMA2Dict([]byte{29}, 64<<20+1); !errors.Is(err, errLZMADictCap) {
		t.Errorf("p=29 unpack=64MiB+1: %v", err)
	}
	if _, err := boundedLZMA2Dict([]byte{40}, 64<<20+1); !errors.Is(err, errLZMADictCap) {
		t.Errorf("p=40 unpack=64MiB+1: %v", err)
	}
}
