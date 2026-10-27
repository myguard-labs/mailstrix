package extract

import (
	"archive/zip"
	"bytes"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bodgit/sevenzip"
	"github.com/nwaples/rardecode/v2"
)

// ArchiveDecoderPoolForTest owns every reserved token until its restore call.
// The exported helper exists only in this overlay test build.
func ArchiveDecoderPoolForTest(t *testing.T) func() {
	t.Helper()
	drainPool(t)
	for i := 0; i < cap(decryptWorkers); i++ {
		decryptWorkers <- struct{}{}
	}
	return func() {
		for i := 0; i < cap(decryptWorkers); i++ {
			<-decryptWorkers
		}
	}
}

func archiveDecoderFixture(t *testing.T, name string) []byte {
	t.Helper()
	buf, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func archiveDecoderHasStop(r Result) bool {
	for _, kind := range r.CapHits {
		if kind == "decoder-unavailable" {
			return true
		}
	}
	return false
}

func TestArchiveDecoderHeaderIncomplete(t *testing.T) {
	for _, name := range []string{"payload.7z", "payload.rar"} {
		t.Run(name, func(t *testing.T) {
			buf := archiveDecoderFixture(t, name)
			healthy := Extract(buf, time.Time{})
			if !healthy.IsArchive || len(healthy.Streams) == 0 || len(healthy.CapHits) != 0 {
				t.Fatalf("healthy fixture not fully extracted: %+v", healthy)
			}
			restore := ArchiveDecoderPoolForTest(t)
			var refused Result
			func() {
				defer restore()
				refused = Extract(buf, time.Time{})
			}()
			if !refused.IsArchive || !archiveDecoderHasStop(refused) {
				t.Fatalf("known header refusal lacks request-local incomplete signal: %+v", refused)
			}
			if recovered := Extract(buf, time.Time{}); len(recovered.Streams) == 0 || len(recovered.CapHits) != 0 {
				t.Fatalf("healthy decoder capacity did not recover: %+v", recovered)
			}
		})
	}
}

func TestArchiveDecoderMemberIncomplete(t *testing.T) {
	for _, name := range []string{"payload.7z", "payload.rar"} {
		t.Run(name, func(t *testing.T) {
			buf := archiveDecoderFixture(t, name)
			res, budget := &Result{}, &archiveBudget{}
			var read func()
			if name == "payload.7z" {
				zr, err := sevenzip.NewReader(bytes.NewReader(buf), int64(len(buf)))
				if err != nil || len(zr.File) == 0 {
					t.Fatalf("open 7z member fixture: %v", err)
				}
				walk := &sevenzipWalk{buf: buf, res: res, b: budget}
				read = func() { walk.member(0, zr.File[0]) }
			} else {
				read = func() {
					rr, err := rardecode.NewReader(bytes.NewReader(buf))
					if err != nil {
						t.Fatal(err)
					}
					emitRarMembers(rr, buf, "", res, budget, 0, time.Time{})
				}
			}
			restore := ArchiveDecoderPoolForTest(t)
			func() { defer restore(); read() }()
			if !archiveDecoderHasStop(*res) || budget.decryptStalled {
				t.Fatalf("member refusal lacks local status or poisoned archive: result=%+v budget=%+v", res, budget)
			}
			read()
			if len(res.Streams) == 0 || !archiveDecoderHasStop(*res) {
				t.Fatal("later member work or earlier incomplete signal was lost")
			}
		})
	}
}

func ArchiveDecoderMixedZIPForTest(t *testing.T) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, item := range []struct {
		name string
		body []byte
	}{{"blocked.7z", archiveDecoderFixture(t, "payload.7z")}, {"later.txt", []byte("RECOVERED_DECODER_HIT")}} {
		w, err := zw.Create(item.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(item.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestArchiveDecoderContinuesAfterRefusal(t *testing.T) {
	buf := ArchiveDecoderMixedZIPForTest(t)
	restore := ArchiveDecoderPoolForTest(t)
	defer restore()
	res := Extract(buf, time.Time{})
	if !archiveDecoderHasStop(res) {
		t.Fatal("nested decoder refusal not propagated")
	}
	for _, stream := range res.Streams {
		if bytes.Contains(stream, []byte("RECOVERED_DECODER_HIT")) {
			return
		}
	}
	t.Fatal("refused decoder suppressed a later ordinary ZIP member")
}

func TestArchiveDecoderRequestIsolation(t *testing.T) {
	buf := archiveDecoderFixture(t, "payload.7z")
	restore := ArchiveDecoderPoolForTest(t)
	defer restore()
	for range 20 {
		var blocked, ordinary Result
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); blocked = Extract(buf, time.Time{}) }()
		go func() { defer wg.Done(); ordinary = Extract([]byte("ordinary plain message"), time.Time{}) }()
		wg.Wait()
		if !archiveDecoderHasStop(blocked) || len(ordinary.CapHits) != 0 {
			t.Fatalf("decoder stop leaked between requests: %v / %v", blocked.CapHits, ordinary.CapHits)
		}
	}
}

func TestArchiveDecoderOrdinaryRefusalPolicy(t *testing.T) {
	for name, buf := range map[string][]byte{
		"corrupt7z":   append([]byte("7z\xbc\xaf\x27\x1c"), bytes.Repeat([]byte{0xff}, 40)...),
		"encrypted7z": archiveDecoderFixture(t, "sevenzip-pw.7z"),
	} {
		res := Extract(buf, time.Time{})
		if archiveDecoderHasStop(res) {
			t.Fatalf("ordinary %s parse/refusal incorrectly became capacity failure", name)
		}
	}
	solid := append([]byte(nil), archiveDecoderFixture(t, "payload.rar")...)
	solid[rarSolidBitOffset] |= rar5ArcSolid
	res := Extract(solid, time.Time{})
	if !res.IsArchive || archiveDecoderHasStop(res) {
		t.Fatal("accepted solid-RAR refusal policy changed")
	}
}

func TestArchiveDecoderContainmentOutcomes(t *testing.T) {
	t.Run("ordinary return", func(t *testing.T) {
		res := &Result{}
		value, ran := runPlainDecoder(res, time.Time{}, func() bool { return false })
		if value || !ran || len(res.CapHits) != 0 {
			t.Fatal("ordinary decoder miss became containment loss")
		}
	})
	t.Run("worker panic", func(t *testing.T) {
		res := &Result{}
		_, ran := runPlainDecoder(res, time.Time{}, func() bool { panic("fixture decoder panic") })
		if ran || !archiveDecoderHasStop(*res) {
			t.Fatal("recovered worker panic lost request-local incomplete signal")
		}
		drainPool(t)
		_, ran = boundedPlain7zMember(nil, res, time.Time{})
		if ran || len(res.CapHits) != 1 {
			t.Fatal("7z member panic was swallowed as ordinary corruption or duplicated the stop")
		}
		drainPool(t)
		// A caller without a Result must retain containment, without a nil write.
		if _, ran := runPlainDecoder[bool](nil, time.Time{}, func() bool { panic("nil-result fixture") }); ran {
			t.Fatal("panic reported as completed without a Result")
		}
		drainPool(t)
	})
	t.Run("expired request deadline", func(t *testing.T) {
		res := &Result{}
		called := false
		_, ran := runPlainDecoder(res, time.Now().Add(-time.Second), func() bool {
			called = true
			return true
		})
		if ran || called || len(res.CapHits) != 0 {
			t.Fatal("expired deadline started work or was relabeled as decoder capacity")
		}
	})
	t.Run("attempt stall keeps ownership", func(t *testing.T) {
		drainPool(t)
		t.Cleanup(SetDecryptAttemptTimeForTest(10 * time.Millisecond))
		res := &Result{}
		entered, release := make(chan struct{}), make(chan struct{})
		defer func() { close(release); drainPool(t) }()
		_, ran := runPlainDecoder(res, time.Now().Add(time.Minute), func() bool {
			close(entered)
			<-release
			return true
		})
		if ran || !archiveDecoderHasStop(*res) {
			t.Fatal("per-attempt stall lost incomplete status")
		}
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("stalled decoder never entered")
		}
		if live, abandoned, _, _ := DecryptWorkerStats(); live != 1 || abandoned != 1 {
			t.Fatalf("abandoned decoder ownership lost: live=%d abandoned=%d", live, abandoned)
		}
	})
}
