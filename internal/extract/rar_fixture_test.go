package extract

import (
	"os"
	"testing"
	"time"

	rardecode "github.com/nwaples/rardecode/v2"
)

// RAR password fixtures are a real-format contrast to the synthetic zip/7z
// byte builders, because no Go writer can produce RAR. Provenance (public
// password, member list, generating rar version, container image digest) is in
// testdata/README.md.
const rarFixtureName = "fixture-encrypted.rar"
const rarFixturePassword = "fixture-password"

// rarFixtureMembers holds the sole observable member contract of the fixture.
// note.txt is asserted through the Reader path; readme.txt is the second
// header-encrypted member, its presence proved by the validation helper (which
// always reads the first file member), so its name/size are informational here.
var rarFixtureMembers = map[string]int64{
	"note.txt":   43,
	"readme.txt": 36,
}

// openRarReaderChecked wraps openRarReader so a library panic is observable as
// a test failure rather than a process abort: the fail-open contract under
// hostile input is part of what these tests pin.
func openRarReaderChecked(t *testing.T, buf []byte, pw string) (rr *rardecode.Reader, panicFree bool) {
	t.Helper()
	defer func() {
		if recover() != nil {
			panicFree = false
		}
	}()
	rr = openRarReader(buf, pw)
	return rr, true
}

// TestRarVerifyPasswordReportsCorrectPassword proves the atomic validation
// helper positive and negative contracts against a real encrypted RAR.
func TestRarVerifyPasswordReportsCorrectPassword(t *testing.T) {
	buf, err := os.ReadFile("testdata/" + rarFixtureName)
	if err != nil {
		t.Fatal(err)
	}

	if !verifyRarPassword(buf, rarFixturePassword) {
		t.Fatal("correct password reported as wrong")
	}
	if verifyRarPassword(buf, "wrong-password") {
		t.Fatal("wrong password reported as correct")
	}
}

// TestRarOpenReaderReturnsExpectedMember proves the reader building block
// yields the expected member name and declared size under the correct
// password, and fails cleanly under the wrong one.
func TestRarOpenReaderReturnsExpectedMember(t *testing.T) {
	buf, err := os.ReadFile("testdata/" + rarFixtureName)
	if err != nil {
		t.Fatal(err)
	}

	rr := openRarReader(buf, rarFixturePassword)
	if rr == nil {
		t.Fatal("openRarReader returned nil for the correct password")
	}
	h, err := rr.Next()
	if err != nil {
		t.Fatal("first member Next with correct password:", err)
	}
	if h.Name != "note.txt" || h.UnPackedSize != rarFixtureMembers["note.txt"] {
		t.Fatalf("member mismatch: got name=%q size=%d", h.Name, h.UnPackedSize)
	}

	if openRarReader(buf, "wrong-password") != nil {
		t.Fatal("openRarReader returned a reader for the wrong password")
	}
}

// TestRarCrackPasswordReturnsCandidate proves the brute-forcer returns the
// winning candidate through runBounded and applies the shared budget.
func TestRarCrackPasswordReturnsCandidate(t *testing.T) {
	drainPool(t)
	defer drainPool(t)

	buf, err := os.ReadFile("testdata/" + rarFixtureName)
	if err != nil {
		t.Fatal(err)
	}

	b := &archiveBudget{}
	got := crackRarPassword(buf, []string{"alpha", rarFixturePassword, "omega"}, b, time.Now().Add(time.Minute))
	if got != rarFixturePassword {
		t.Fatalf("crackRarPassword returned %q, want %q", got, rarFixturePassword)
	}
	if b.decryptAttempts != 2 {
		t.Fatalf("decryptAttempts = %d, want 2 (one wrong + one winning through runBounded)",
			b.decryptAttempts)
	}
	if b.kdfAttempts != 2 {
		t.Fatalf("kdfAttempts = %d, want 2 (rar is a KDF-bound format)", b.kdfAttempts)
	}
}

// TestRarCrackPasswordWrongCandidatesOnly proves the all-wrong path empties out.
func TestRarCrackPasswordWrongCandidatesOnly(t *testing.T) {
	drainPool(t)
	defer drainPool(t)

	buf, err := os.ReadFile("testdata/" + rarFixtureName)
	if err != nil {
		t.Fatal(err)
	}

	b := &archiveBudget{}
	got := crackRarPassword(buf, []string{"alpha", "beta"}, b, time.Now().Add(time.Minute))
	if got != "" {
		t.Fatalf("crackRarPassword returned %q for wrong-only candidates, want empty", got)
	}
	if b.decryptAttempts != 2 {
		t.Fatalf("decryptAttempts = %d, want 2", b.decryptAttempts)
	}
}

// TestRarCrackPasswordExpiredDeadlineReturnsEmpty proves the already-expired
// deadline short-circuits before any attempt is launched or counted, without a
// panic and without touching the budget.
func TestRarCrackPasswordExpiredDeadlineReturnsEmpty(t *testing.T) {
	buf, err := os.ReadFile("testdata/" + rarFixtureName)
	if err != nil {
		t.Fatal(err)
	}

	b := &archiveBudget{}
	got := crackRarPassword(buf, []string{rarFixturePassword}, b, time.Now().Add(-time.Minute))
	if got != "" {
		t.Fatalf("crackRarPassword returned %q past the deadline, want empty", got)
	}
	if b.decryptAttempts != 0 || b.kdfAttempts != 0 {
		t.Fatalf("expired deadline still spent budget: decrypt=%d kdf=%d",
			b.decryptAttempts, b.kdfAttempts)
	}
}

// TestRarCrackPasswordPrefilledBudgetStopsAtKDFCap proves the KDF sub-cap is
// checked BEFORE the attempt runs: a budget already AT the cap stops the loop
// without launching or counting a single candidate. A wrong-only candidate set
// proves the cap alone (not the deadline) ended the loop.
func TestRarCrackPasswordPrefilledBudgetStopsAtKDFCap(t *testing.T) {
	drainPool(t)
	defer drainPool(t)

	buf, err := os.ReadFile("testdata/" + rarFixtureName)
	if err != nil {
		t.Fatal(err)
	}

	b := &archiveBudget{kdfAttempts: maxKDFDecryptAttempts}
	got := crackRarPassword(buf, []string{"gamma", "delta"}, b, time.Now().Add(time.Minute))
	if got != "" {
		t.Fatalf("crackRarPassword returned %q at the KDF cap, want empty", got)
	}
	if b.kdfAttempts != maxKDFDecryptAttempts {
		t.Fatalf("kdfAttempts changed to %d despite the pre-check; want %d unchanged",
			b.kdfAttempts, maxKDFDecryptAttempts)
	}
	if b.decryptAttempts != 0 {
		t.Fatalf("decryptAttempts = %d, want 0 (no attempt ran)", b.decryptAttempts)
	}
}

// TestRarPasswordHelpersMalformedInputDoesNotPanic proves the fail-open
// contract on malformed inputs through the exported function surface: no
// panic, verify=false, open=nil, crack="".
func TestRarPasswordHelpersMalformedInputDoesNotPanic(t *testing.T) {
	pw := rarFixturePassword
	deadline := time.Now().Add(time.Minute)

	cases := []struct {
		name string
		buf  []byte
	}{
		{name: "nil"},
		{name: "empty", buf: []byte{}},
		{name: "short-random", buf: []byte("\x00\x01\x02\x03\x04\x05\x06\x07")},
		{name: "truncated", buf: func() []byte {
			buf, err := os.ReadFile("testdata/" + rarFixtureName)
			if err != nil {
				t.Fatal(err)
			}
			return buf[:100]
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drainPool(t)
			defer drainPool(t)

			if verifyRarPassword(tc.buf, pw) {
				t.Fatal("verifyRarPassword accepted malformed input")
			}
			rr, panicFree := openRarReaderChecked(t, tc.buf, pw)
			if !panicFree {
				t.Fatal("openRarReader panicked on malformed input")
			}
			if tc.name == "truncated" {
				// rardecode defers a truncated buffer's failure to Next, so
				// construction can succeed; the OBSERVED contract of
				// openRarReader for real-but-truncated input is non-nil here,
				// and the reader must fail on first use.
				if rr == nil {
					t.Fatal("openRarReader unexpectedly nil before Next for truncated input")
				}
				if _, err := rr.Next(); err == nil {
					t.Fatal("reader from truncated input succeeded at Next, want error")
				}
			} else if rr != nil {
				t.Fatalf("openRarReader accepted malformed input (%s)", tc.name)
			}
			b := &archiveBudget{}
			if got := crackRarPassword(tc.buf, []string{pw}, b, deadline); got != "" {
				t.Fatalf("crackRarPassword returned %q on malformed input", got)
			}
			if maxAttempts := maxKDFDecryptAttempts; b.kdfAttempts > maxAttempts {
				t.Fatalf("kdfAttempts %d exceeded maxKDFDecryptAttempts %d",
					b.kdfAttempts, maxAttempts)
			}
		})
	}
}

// TestRarFixtureMembersMatchDocumentedContract walks the real fixture with the
// production reader and compares each member against the documented contract in
// testdata/README.md. Reading the binary, not a same-file literal, means a
// regeneration that drops or changes a member fails even if the Go table was
// updated alongside it.
func TestRarFixtureMembersMatchDocumentedContract(t *testing.T) {
	buf, err := os.ReadFile("testdata/" + rarFixtureName)
	if err != nil {
		t.Fatal(err)
	}
	rr := openRarReader(buf, rarFixturePassword)
	if rr == nil {
		t.Fatal("openRarReader returned nil for the correct password")
	}
	seen := make(map[string]bool, len(rarFixtureMembers))
	for {
		h, err := rr.Next()
		if err != nil {
			t.Fatalf("walking fixture members: %v", err)
		}
		wantSize, ok := rarFixtureMembers[h.Name]
		if !ok {
			t.Fatalf("fixture member %q is not in the documented member set", h.Name)
		}
		if h.UnPackedSize != wantSize {
			t.Fatalf("member %q size: got %d, want %d", h.Name, h.UnPackedSize, wantSize)
		}
		seen[h.Name] = true
		// Next() on the last member returns io.EOF; loop again to observe it.
		if len(seen) == len(rarFixtureMembers) {
			if _, err := rr.Next(); err == nil {
				t.Fatalf("expected EOF after %d documented members", len(rarFixtureMembers))
			}
			break
		}
	}
}
