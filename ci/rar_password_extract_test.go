package ci_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// ExtractWithOptions does not expose archive member names. Distinct content
// digests identify the expected payload streams while the fixture manifest
// separately records the upstream member names.
var encryptedRARMembers = []struct {
	name   string
	size   int
	digest string
}{
	{"exe/test.exe", 45056, "8557928804f57ecc340b3bb38b095a3607474ec8deb0076f316fcfe02b562106"},
	{"jpg/test.jpg", 40372, "b251c7501fb0f55dd4a92feabe0a6f5733bc40a02679498155fae9b30138fc53"},
	{"тест.txt", 15498, "4d581d93d369f6e1c9b295ff38d82dabd577f927dfaf0c35818c015c85e322d9"},
}

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

func hasRARMarker(markers [][]byte, want string) bool {
	for _, marker := range markers {
		if bytes.Equal(marker, []byte(want)) {
			return true
		}
	}
	return false
}

func assertRARMembers(t *testing.T, got extract.Result) {
	t.Helper()
	for _, member := range encryptedRARMembers {
		count := 0
		for _, stream := range got.Streams {
			if len(stream) == member.size && fmt.Sprintf("%x", sha256.Sum256(stream)) == member.digest {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("decrypted RAR member %s emitted %d times, want once", member.name, count)
		}
	}
	decrypted, encrypted := 0, 0
	for _, marker := range got.Markers {
		switch string(marker) {
		case "ARCHIVE-DECRYPTED":
			decrypted++
		case "ARCHIVE-ENCRYPTED":
			encrypted++
		}
	}
	if decrypted != 1 || encrypted != 0 || got.EncryptedArchive {
		t.Fatalf("decrypted RAR state: decrypted markers=%d encrypted markers=%d encrypted flag=%v", decrypted, encrypted, got.EncryptedArchive)
	}
}

func assertEncryptedRAROnly(t *testing.T, got extract.Result) {
	t.Helper()
	if !got.IsArchive || !got.EncryptedArchive || got.DecryptedArchive {
		t.Fatalf("encrypted RAR flags: archive=%v encrypted=%v decrypted=%v", got.IsArchive, got.EncryptedArchive, got.DecryptedArchive)
	}
	if !hasRARMarker(got.Markers, "ARCHIVE-ENCRYPTED") || hasRARMarker(got.Markers, "ARCHIVE-DECRYPTED") {
		t.Fatalf("encrypted RAR markers: %q", got.Markers)
	}
	// Every file in this fixture is encrypted. Any content stream, including a
	// truncated or partially decoded member, is plaintext leaked on rejection.
	if len(got.Streams) != 0 {
		t.Fatalf("encrypted RAR emitted %d content streams without a successful password", len(got.Streams))
	}
}

func TestEncryptedRARPublicExtraction(t *testing.T) {
	buf := encryptedRARFixture(t)
	got := extract.ExtractWithOptions(buf, rarOptions(time.Time{}, "wrong-password", "test"))
	assertRARMembers(t, got)
	if got.TopType != extract.TopTypeArchive || !got.IsArchive || !got.DecryptedArchive || got.Failed || got.Panicked {
		t.Fatalf("RAR extraction flags: top=%q archive=%v decrypted=%v failed=%v panicked=%v", got.TopType, got.IsArchive, got.DecryptedArchive, got.Failed, got.Panicked)
	}
}

func TestEncryptedRARPublicRejectionControls(t *testing.T) {
	buf := encryptedRARFixture(t)
	t.Run("feature-off", func(t *testing.T) {
		// Keep the correct password present so this isolates the opt-in gate.
		opts := extract.FullOptions(time.Time{})
		opts.PWCandidates = []string{"test"}
		got := extract.ExtractWithOptions(buf, opts)
		assertEncryptedRAROnly(t, got)
	})
	t.Run("compiled-default", func(t *testing.T) {
		assertEncryptedRAROnly(t, extract.Extract(buf, time.Time{}))
	})
	t.Run("no-candidates", func(t *testing.T) {
		assertEncryptedRAROnly(t, extract.ExtractWithOptions(buf, rarOptions(time.Time{})))
	})
	t.Run("wrong-password", func(t *testing.T) {
		got := extract.ExtractWithOptions(buf, rarOptions(time.Time{}, "wrong-password"))
		assertEncryptedRAROnly(t, got)
	})
	t.Run("expired-deadline", func(t *testing.T) {
		got := extract.ExtractWithOptions(buf, rarOptions(time.Now().Add(-time.Second), "test"))
		if got.DecryptedArchive || len(got.Streams) != 0 {
			t.Fatal("expired deadline emitted decrypted RAR content")
		}
	})
	t.Run("last-kdf-attempt", func(t *testing.T) {
		candidates := make([]string, 16)
		for i := range candidates[:15] {
			candidates[i] = fmt.Sprintf("wrong-%02d", i)
		}
		candidates[15] = "test"
		got := extract.ExtractWithOptions(buf, rarOptions(time.Time{}, candidates...))
		if !got.DecryptedArchive {
			t.Fatal("correct password at KDF budget boundary was not accepted")
		}
		assertRARMembers(t, got)
	})
	t.Run("kdf-budget", func(t *testing.T) {
		candidates := make([]string, 17)
		for i := range candidates[:16] {
			candidates[i] = fmt.Sprintf("wrong-%02d", i)
		}
		candidates[16] = "test"
		got := extract.ExtractWithOptions(buf, rarOptions(time.Time{}, candidates...))
		assertEncryptedRAROnly(t, got)
	})
	t.Run("truncated", func(t *testing.T) {
		got := extract.ExtractWithOptions(buf[:100], rarOptions(time.Time{}, "test"))
		if got.Panicked || got.DecryptedArchive || len(got.Streams) != 0 {
			t.Fatal("truncated RAR panicked or emitted decrypted content")
		}
	})
	t.Run("malformed", func(t *testing.T) {
		got := extract.ExtractWithOptions([]byte("Rar!\x1a\x07\x01\x00garbage"), rarOptions(time.Time{}, "test"))
		if got.Panicked || got.DecryptedArchive || len(got.Streams) != 0 {
			t.Fatal("malformed RAR panicked or emitted decrypted content")
		}
	})
}
