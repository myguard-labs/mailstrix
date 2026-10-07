package mailstrix

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// pwReq builds a request carrying the raw (already encoded) candidates header
// value; an empty raw leaves the header absent.
func pwReq(raw string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/scan", nil)
	if raw != "" {
		r.Header.Set(pwCandidatesHeader, raw)
	}
	return r
}

func pwB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestPWCandidatesFromRequest(t *testing.T) {
	long64 := strings.Repeat("x", maxHeaderPWCandidateLen)
	long65 := strings.Repeat("y", maxHeaderPWCandidateLen+1)
	var many []string
	for i := 0; i < maxHeaderPWCandidates+10; i++ {
		many = append(many, "p"+strconv.Itoa(i))
	}
	exactly := many[:maxHeaderPWCandidates]

	tests := []struct {
		name string
		raw  string
		want []string
	}{
		// positive
		{"single", pwB64("secret"), []string{"secret"}},
		{"order preserved", pwB64("zeta\nalpha\nmid"), []string{"zeta", "alpha", "mid"}},
		{"std base64 padded", base64.StdEncoding.EncodeToString([]byte("ab")), []string{"ab"}},
		{"raw base64 unpadded", base64.RawStdEncoding.EncodeToString([]byte("ab")), []string{"ab"}},
		{"whitespace in header tolerated", pwB64("one\ntwo")[:4] + " \t\r\n" + pwB64("one\ntwo")[4:], []string{"one", "two"}},
		{"surrounding space trimmed", pwB64("  pad \n\tq\t"), []string{"pad", "q"}},
		{"CR stripped (CRLF list)", pwB64("a\r\nb\r\n"), []string{"a", "b"}},
		{"inner control bytes removed", pwB64("a\x00b\x01c\x7fd"), []string{"abcd"}},
		{"unicode kept", pwB64("pässwörd\n密码"), []string{"pässwörd", "密码"}},
		{"inner space kept", pwB64("two words"), []string{"two words"}},
		// boundary
		{"len exactly max kept", pwB64(long64), []string{long64}},
		{"len max+1 dropped", pwB64(long65 + "\nok"), []string{"ok"}},
		{"len counted in bytes not runes", pwB64(strings.Repeat("é", 33) + "\nok"), []string{"ok"}}, // 66 bytes
		{"32 bytes of runes at limit kept", pwB64(strings.Repeat("é", 32)), []string{strings.Repeat("é", 32)}},
		{"exactly max count", pwB64(strings.Join(exactly, "\n")), exactly},
		{"over max count capped", pwB64(strings.Join(many, "\n")), exactly},
		{"dup removed first wins", pwB64("a\nb\na\nc\nb"), []string{"a", "b", "c"}},
		{"dup after sanitising", pwB64("a\x00\n a \na"), []string{"a"}},
		{"dups do not consume cap", pwB64(strings.Repeat("d\n", 100) + "e"), []string{"d", "e"}},
		{"length measured after control strip", pwB64(long64 + "\x00\x01"), []string{long64}},
		// malformed / error: fail-soft nil
		{"absent", "", nil},
		{"not base64", "!!!not-base64!!!", nil},
		{"bad padding middle", "YQ=Y", nil},
		{"whitespace only header", " \t ", nil},
		{"empty decode of whitespace-only value", "====", nil},
		{"all blank lines", pwB64("\n\n  \n\t\n"), nil},
		{"only control bytes", pwB64("\x00\x01\n\x7f"), nil},
		{"only over-long", pwB64(long65), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pwCandidatesFromRequest(pwReq(tc.raw))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if tc.want == nil && got != nil {
				t.Fatalf("expected nil slice, got %#v", got)
			}
		})
	}
}

// A huge decoded blob is truncated before splitting; no candidate past the
// maxBlob prefix can appear, and the cap still holds.
func TestPWCandidatesFromRequestBlobTruncated(t *testing.T) {
	maxBlob := maxHeaderPWCandidates * (maxHeaderPWCandidateLen + 1)
	// A 1-byte line that lies entirely beyond the prefix must not be returned.
	blob := strings.Repeat("\n", maxBlob) + "late"
	if got := pwCandidatesFromRequest(pwReq(pwB64(blob))); got != nil {
		t.Fatalf("candidate beyond blob bound leaked: %q", got)
	}
	// A candidate wholly inside the prefix is kept; the one straddling the cut is
	// truncated, not dropped wholesale.
	blob = "head\n" + strings.Repeat("\n", maxBlob-5-3) + "abcdef"
	got := pwCandidatesFromRequest(pwReq(pwB64(blob)))
	if want := []string{"head", "abc"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Only the dedicated header is read; others (and repeated headers beyond the
// first value) must not contribute.
func TestPWCandidatesFromRequestSourceNegative(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/scan?pw=qs", strings.NewReader("pw=body"))
	r.Header.Set("X-MAILSTRIX-Filename", pwB64("fname"))
	r.Header.Set("X-Other-PWCandidates", pwB64("other"))
	if got := pwCandidatesFromRequest(r); got != nil {
		t.Fatalf("non-header source leaked: %q", got)
	}
	r.Header.Add(pwCandidatesHeader, pwB64("first"))
	r.Header.Add(pwCandidatesHeader, pwB64("second"))
	if got, want := pwCandidatesFromRequest(r), []string{"first"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q (Header.Get = first value)", got, want)
	}
	// Header name is case-insensitive via canonicalisation.
	r2 := httptest.NewRequest(http.MethodPost, "/scan", nil)
	r2.Header["X-Mailstrix-Pwcandidates"] = []string{pwB64("canon")}
	if got, want := pwCandidatesFromRequest(r2), []string{"canon"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
