package ci_test

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func encryptedRARFixture(t *testing.T) []byte {
	t.Helper()
	buf, err := os.ReadFile("../internal/extract/testdata/fixture-encrypted-files.rar")
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func rarOptions(deadline time.Time, candidates ...string) *extract.Options {
	opts := extract.FullOptions(deadline)
	opts.ArchivePWEnabled = true
	opts.PWCandidates = candidates
	return opts
}

func rarPlaintext() []byte {
	var buf bytes.Buffer
	for i := 0; i < 512; i++ {
		fmt.Fprintf(&buf, "%03d\n", i)
	}
	return buf.Bytes()
}

func hasRARStream(streams [][]byte, want []byte) bool {
	for _, stream := range streams {
		if bytes.Equal(stream, want) {
			return true
		}
	}
	return false
}

func assertEncryptedRAROnly(t *testing.T, got extract.Result) {
	t.Helper()
	if !got.IsArchive || !got.EncryptedArchive || got.DecryptedArchive {
		t.Fatalf("encrypted RAR flags: archive=%v encrypted=%v decrypted=%v", got.IsArchive, got.EncryptedArchive, got.DecryptedArchive)
	}
	if !hasRARStream(got.Markers, []byte("ARCHIVE-ENCRYPTED")) || hasRARStream(got.Markers, []byte("ARCHIVE-DECRYPTED")) {
		t.Fatalf("encrypted RAR markers: %q", got.Markers)
	}
	if hasRARStream(got.Streams, rarPlaintext()) {
		t.Fatal("encrypted RAR plaintext leaked without a successful password")
	}
}

func TestEncryptedRARPublicExtraction(t *testing.T) {
	buf := encryptedRARFixture(t)
	wantPlaintext := rarPlaintext()
	got := extract.ExtractWithOptions(buf, rarOptions(time.Time{}, "wrong-password", "password"))
	if got.TopType != extract.TopTypeArchive || !got.IsArchive || !got.DecryptedArchive || got.Failed || got.Panicked {
		t.Fatalf("RAR extraction flags: top=%q archive=%v decrypted=%v failed=%v panicked=%v", got.TopType, got.IsArchive, got.DecryptedArchive, got.Failed, got.Panicked)
	}
	count := 0
	for _, stream := range got.Streams {
		if bytes.Equal(stream, wantPlaintext) {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("decrypted RAR emitted %d plaintext members, want 2", count)
	}
	if !hasRARStream(got.Markers, []byte("ARCHIVE-DECRYPTED")) {
		t.Fatalf("decrypted RAR marker was not emitted: %q", got.Markers)
	}
}

func TestEncryptedRARPublicRejectionControls(t *testing.T) {
	buf := encryptedRARFixture(t)
	t.Run("feature-off", func(t *testing.T) {
		got := extract.ExtractWithOptions(buf, extract.FullOptions(time.Time{}))
		assertEncryptedRAROnly(t, got)
	})
	t.Run("wrong-password", func(t *testing.T) {
		got := extract.ExtractWithOptions(buf, rarOptions(time.Time{}, "wrong-password"))
		assertEncryptedRAROnly(t, got)
	})
	t.Run("expired-deadline", func(t *testing.T) {
		got := extract.ExtractWithOptions(buf, rarOptions(time.Now().Add(-time.Second), "password"))
		if got.DecryptedArchive || hasRARStream(got.Streams, rarPlaintext()) {
			t.Fatal("expired deadline emitted decrypted RAR content")
		}
	})
	t.Run("last-kdf-attempt", func(t *testing.T) {
		candidates := make([]string, 16)
		for i := range candidates[:15] {
			candidates[i] = "wrong-password"
		}
		candidates[15] = "password"
		got := extract.ExtractWithOptions(buf, rarOptions(time.Time{}, candidates...))
		if !got.DecryptedArchive || !hasRARStream(got.Streams, rarPlaintext()) {
			t.Fatal("correct password at KDF budget boundary did not emit plaintext")
		}
	})
	t.Run("kdf-budget", func(t *testing.T) {
		candidates := make([]string, 17)
		for i := range candidates[:16] {
			candidates[i] = "wrong-password"
		}
		candidates[16] = "password"
		got := extract.ExtractWithOptions(buf, rarOptions(time.Time{}, candidates...))
		assertEncryptedRAROnly(t, got)
	})
	t.Run("truncated", func(t *testing.T) {
		got := extract.ExtractWithOptions(buf[:100], rarOptions(time.Time{}, "password"))
		if got.Panicked || got.DecryptedArchive || hasRARStream(got.Streams, rarPlaintext()) {
			t.Fatal("truncated RAR panicked or emitted decrypted content")
		}
	})
	t.Run("malformed", func(t *testing.T) {
		got := extract.ExtractWithOptions([]byte("Rar!\x1a\x07\x01\x00garbage"), rarOptions(time.Time{}, "password"))
		if got.Panicked || got.DecryptedArchive || hasRARStream(got.Streams, rarPlaintext()) {
			t.Fatal("malformed RAR panicked or emitted decrypted content")
		}
	})
}
