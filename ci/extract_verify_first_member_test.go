package ci_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// AUD-04c9 / AUD-04c10: password verification validates on the first IN-CAP
// member instead of giving up when an earlier member is over the per-member cap.

func vfmHasStream(res extract.Result, needle string) bool {
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte(needle)) {
			return true
		}
	}
	return false
}

// Header-encrypted 7z fixtures (password "test"), generated with 7-Zip 25.01:
//
//	vfm-nonsolid.7z: 7z a -p'test' -mhe=on -ms=off -mx=9 vfm-nonsolid.7z a-big.bin b-small.txt
//	vfm-solid.7z:    7z a -p'test' -mhe=on -ms=on  -mx=9 vfm-solid.7z    a-big.bin b-small.txt
//	vfm-onlybig.7z:  7z a -p'test' -mhe=on -mx=9 vfm-onlybig.7z a-big.bin
//
// a-big.bin = 16777217 zero bytes (capMember+1), b-small.txt = "VFM-MARKER-in-cap\n".
func TestVerify7zFirstInCapMember(t *testing.T) {
	t.Cleanup(extract.SetDecryptAttemptTimeForTest(time.Minute))
	for _, name := range []string{"vfm-nonsolid.7z", "vfm-solid.7z"} {
		t.Run(name+"-cracks-and-extracts-in-cap-member", func(t *testing.T) {
			res := capHdrEnc7z(t, name, "wrong", "test")
			if !res.DecryptedArchive {
				t.Fatalf("not decrypted (oversize first member blocked the crack): hits=%v", res.CapHits)
			}
			if !vfmHasStream(res, "VFM-MARKER-in-cap") {
				t.Fatalf("in-cap member not extracted (streams=%d)", len(res.Streams))
			}
			if !capHasHit(res, "member-size") {
				t.Fatalf("oversize member not recorded: %v", res.CapHits)
			}
		})
		t.Run(name+"-wrong-password-stays-encrypted", func(t *testing.T) {
			res := capHdrEnc7z(t, name, "wrong")
			if res.DecryptedArchive || vfmHasStream(res, "VFM-MARKER-in-cap") {
				t.Fatalf("wrong password accepted: decrypted=%v", res.DecryptedArchive)
			}
		})
	}
	t.Run("only-oversize-stays-encrypted", func(t *testing.T) {
		res := capHdrEnc7z(t, "vfm-onlybig.7z", "wrong", "test")
		if res.DecryptedArchive {
			t.Fatal("archive with only an oversize member reported decrypted")
		}
	})
}

func TestVerifyRarFirstInCapMember(t *testing.T) {
	stub := []byte("stub-bytes")
	small := []byte("VFM-MARKER-in-cap")
	smallMember := func() capRarMember {
		return capRarMember{name: "b.txt", data: small, plainLen: len(small), declared: uint64(len(small)), password: "test"}
	}
	t.Run("declared-oversize-first-member", func(t *testing.T) {
		res := capRarExtract(capRar5(t,
			capRarMember{name: "a-big.bin", data: stub, plainLen: len(stub), declared: capMember + 1, password: "test"},
			smallMember(),
		), "wrong", "test")
		if !res.DecryptedArchive {
			t.Fatalf("not decrypted: hits=%v", res.CapHits)
		}
		if !vfmHasStream(res, "VFM-MARKER-in-cap") {
			t.Fatalf("in-cap member not extracted (streams=%d)", len(res.Streams))
		}
	})
	t.Run("unknown-size-over-cap-first-member", func(t *testing.T) {
		body := capRarUnknownBody(capMember+1, 0)
		res := capRarExtract(capRar5(t,
			capRarMember{name: "a-big.bin", data: body, plainLen: len(body), declared: capUnknown, unknownSize: true, password: "test"},
			smallMember(),
		), "wrong", "test")
		if !res.DecryptedArchive {
			t.Fatalf("not decrypted: hits=%v", res.CapHits)
		}
		if !vfmHasStream(res, "VFM-MARKER-in-cap") {
			t.Fatalf("in-cap member not extracted (streams=%d)", len(res.Streams))
		}
	})
	t.Run("wrong-password-after-oversize-stays-encrypted", func(t *testing.T) {
		res := capRarExtract(capRar5(t,
			capRarMember{name: "a-big.bin", data: stub, plainLen: len(stub), declared: capMember + 1, password: "test"},
			smallMember(),
		), "wrong")
		if res.DecryptedArchive {
			t.Fatal("wrong password accepted")
		}
	})
	t.Run("only-oversize-stays-encrypted", func(t *testing.T) {
		res := capRarExtract(capRar5(t,
			capRarMember{name: "a-big.bin", data: stub, plainLen: len(stub), declared: capMember + 1, password: "test"},
		), "wrong", "test")
		if res.DecryptedArchive {
			t.Fatal("archive with only an oversize member reported decrypted")
		}
	})
	t.Run("only-unknown-size-over-cap-stays-encrypted", func(t *testing.T) {
		body := capRarUnknownBody(capMember+1, 0)
		res := capRarExtract(capRar5(t,
			capRarMember{name: "a-big.bin", data: body, plainLen: len(body), declared: capUnknown, unknownSize: true, password: "test"},
		), "test")
		if res.DecryptedArchive {
			t.Fatal("truncated unknown-size read reported decrypted")
		}
	})
}
