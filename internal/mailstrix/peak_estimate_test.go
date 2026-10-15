package mailstrix

import (
	"errors"
	"math"
	"testing"
)

const miB = int64(1 << 20)

func TestEstimatePeakBytesHistorical492MiB(t *testing.T) {
	e := int64(2621440)
	got, err := EstimatePeakBytes(344*miB, 8, 16*miB, e)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(492 * miB); got != want {
		t.Fatalf("got %d want %d (492 MiB)", got, want)
	}
	// Negative control: omitting E yields 472 MiB, which must differ.
	noE, err := EstimatePeakBytes(344*miB, 8, 16*miB, 0)
	if err != nil || noE != uint64(472*miB) {
		t.Fatalf("no-E got %d err %v want 472 MiB", noE, err)
	}
	if noE == got {
		t.Fatal("omitting E must change the estimate")
	}
}

func TestEstimatePeakBytesFractionalMiB(t *testing.T) {
	// 0.5 MiB RSS + 3*(1.5 MiB + 0.25 MiB) = 5.75 MiB
	got, err := EstimatePeakBytes(miB/2, 3, miB*3/2, miB/4)
	if err != nil || got != uint64(miB*23/4) {
		t.Fatalf("got %d err %v", got, err)
	}
}

func TestEstimatePeakBytesZeroN(t *testing.T) {
	got, err := EstimatePeakBytes(7, 0, 100, 100)
	if err != nil || got != 7 {
		t.Fatalf("got %d err %v", got, err)
	}
}

func TestEstimatePeakBytesUnknownRSS(t *testing.T) {
	if _, err := EstimatePeakBytes(-1, 8, 1, 1); !errors.Is(err, ErrEstimateRSSUnknown) {
		t.Fatalf("err %v", err)
	}
}

func TestEstimatePeakBytesInvalid(t *testing.T) {
	for _, in := range [][3]int64{{-1, 1, 1}, {1, -1, 1}, {1, 1, -1}} {
		if _, err := EstimatePeakBytes(0, in[0], in[1], in[2]); !errors.Is(err, ErrEstimateInvalid) {
			t.Fatalf("%v err %v", in, err)
		}
	}
}

func TestEstimatePeakBytesOverflow(t *testing.T) {
	m := int64(math.MaxInt64)
	cases := map[string][4]int64{
		"mul":  {0, m, m, 1},
		"mul2": {0, 4, m, 0},
		"add":  {m, 2, m, 0},
	}
	// b+e of two MaxInt64 fits in uint64, so n=1 succeeds exactly.
	if got, err := EstimatePeakBytes(0, 1, m, m); err != nil || got != 2*uint64(m) {
		t.Fatalf("boundary got %d err %v", got, err)
	}
	for name, c := range cases {
		if _, err := EstimatePeakBytes(c[0], c[1], c[2], c[3]); !errors.Is(err, ErrEstimateOverflow) {
			t.Fatalf("%s err %v", name, err)
		}
	}
	// Largest exact result is accepted.
	if got, err := EstimatePeakBytes(m, 1, m, 1); err != nil || got != 2*uint64(m)+1 {
		t.Fatalf("max got %d err %v", got, err)
	}
}
