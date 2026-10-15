package mbazaar

import (
	"bytes"
	"crypto/rand"
	"os"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

const p33N = 1_150_000

func p33Keys() [][32]byte {
	buf := make([]byte, p33N*32)
	_, _ = rand.Read(buf)
	ks := make([][32]byte, p33N)
	for i := range ks {
		copy(ks[i][:], buf[i*32:])
	}
	return ks
}

func p33Heap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// peakSampler polls HeapAlloc; coarse but adequate.
func p33Peak(f func()) uint64 {
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	f()
	close(stop)
	<-done
	return peak.Load()
}

func TestP33Measure(t *testing.T) {
	if os.Getenv("MBAZAAR_P33_MEASURE") == "" {
		t.Skip("set MBAZAAR_P33_MEASURE=1 to run the P33 set-representation measurement")
	}
	keys := p33Keys()
	mb := func(x uint64) float64 { return float64(x) / (1 << 20) }
	type res struct {
		name      string
		retained  uint64
		peakOver  uint64
		hit, miss float64
	}
	var out []res
	misses := p33Keys()[:200000]

	run := func(name string, build func() any, lookup func(any, [32]byte) bool) {
		base := p33Heap()
		var s any
		peak := p33Peak(func() { s = build() })
		after := p33Heap()
		r := res{name: name, retained: after - base, peakOver: peak - base}
		const L = 200000
		st := time.Now()
		for i := 0; i < L; i++ {
			if !lookup(s, keys[(i*5)%p33N]) {
				t.Fatal("hit missing")
			}
		}
		r.hit = float64(time.Since(st).Nanoseconds()) / L
		st = time.Now()
		for i := 0; i < L; i++ {
			lookup(s, misses[i])
		}
		r.miss = float64(time.Since(st).Nanoseconds()) / L
		runtime.KeepAlive(s)
		out = append(out, r)
	}
	mapLookup := func(s any, k [32]byte) bool { _, ok := s.(map[[32]byte]struct{})[k]; return ok }
	sliceLookup := func(s any, k [32]byte) bool {
		_, ok := slices.BinarySearchFunc(*s.(*[][32]byte), k, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
		return ok
	}
	buildSlice := func(capHint int) any {
		var sl [][32]byte
		if capHint > 0 {
			sl = make([][32]byte, 0, capHint)
		}
		sl = append(sl, keys...)
		slices.SortFunc(sl, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
		sl = slices.CompactFunc(sl, func(a, b [32]byte) bool { return a == b })
		return &sl
	}
	run("map presized", func() any {
		m := make(map[[32]byte]struct{}, p33N)
		for _, k := range keys {
			m[k] = struct{}{}
		}
		return m
	}, mapLookup)
	run("map unsized", func() any {
		m := make(map[[32]byte]struct{})
		for _, k := range keys {
			m[k] = struct{}{}
		}
		return m
	}, mapLookup)
	run("slice presized", func() any { return buildSlice(p33N) }, sliceLookup)
	run("slice unsized", func() any { return buildSlice(0) }, sliceLookup)
	for _, r := range out {
		t.Logf("%-15s retained=%.1f MiB peak_over_base=%.1f MiB hit=%.0f ns miss=%.0f ns", r.name, mb(r.retained), mb(r.peakOver), r.hit, r.miss)
	}
}
