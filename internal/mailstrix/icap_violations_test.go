package mailstrix

import (
	"bufio"
	"fmt"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
)

// splitICAPResponse splits a raw infected ICAP response into its header
// block lines and the encapsulated remainder.
func splitICAPResponse(t *testing.T, resp string) (lines []string, rest string) {
	t.Helper()
	i := strings.Index(resp, "\r\n\r\n")
	if i < 0 {
		t.Fatalf("no header terminator:\n%q", resp)
	}
	return strings.Split(resp[:i], "\r\n"), resp[i+4:]
}

func TestICAPViolationsFoundPerViolationLines(t *testing.T) {
	for _, n := range []int{1, 3} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			var ms []Match
			for i := 0; i < n; i++ {
				ms = append(ms, Match{Rule: fmt.Sprintf("RULE_%d", i)})
			}
			s := newTestServer(&fakeEngine{count: 1, fp: "fp", matches: ms}, "")
			addr := startTestICAPServer(t, s)
			resp := doICAP(t, addr, icapRESPMODRequest(addr, "malware payload", true))

			lines, rest := splitICAPResponse(t, resp)
			// Strict line-by-line parse: exactly 4*N continuation lines.
			at := -1
			for i, l := range lines {
				if strings.HasPrefix(l, "X-Violations-Found:") {
					at = i
				}
			}
			if at < 0 {
				t.Fatalf("X-Violations-Found missing:\n%q", resp)
			}
			if got := strings.TrimSpace(strings.TrimPrefix(lines[at], "X-Violations-Found:")); got != strconv.Itoa(n) {
				t.Fatalf("count = %q, want %d", got, n)
			}
			var cont []string
			for _, l := range lines[at+1:] {
				if !strings.HasPrefix(l, "\t") {
					break
				}
				cont = append(cont, l)
			}
			if len(cont) != 4*n {
				t.Fatalf("continuation lines = %d, want %d:\n%q", len(cont), 4*n, lines)
			}
			for i := 0; i < n; i++ {
				want := []string{"\t-", fmt.Sprintf("\tRULE_%d", i), "\t0", "\t2"}
				for j, w := range want {
					if cont[4*i+j] != w {
						t.Errorf("violation %d line %d = %q, want %q", i, j, cont[4*i+j], w)
					}
				}
			}
			if next := lines[at+1+len(cont)]; !strings.HasPrefix(next, "Encapsulated:") {
				t.Errorf("header after violations = %q, want Encapsulated", next)
			}

			// textproto parse: Encapsulated is its own header, offsets locate 403 + body.
			h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(
				strings.SplitN(resp, "\r\n", 2)[1]))).ReadMIMEHeader()
			if err != nil {
				t.Fatalf("ReadMIMEHeader: %v", err)
			}
			enc := h.Get("Encapsulated")
			var hdrOff, bodyOff int
			if _, err := fmt.Sscanf(enc, "res-hdr=%d, res-body=%d", &hdrOff, &bodyOff); err != nil {
				t.Fatalf("Encapsulated %q: %v", enc, err)
			}
			if hdrOff != 0 || !strings.HasPrefix(rest, "HTTP/1.1 403 Forbidden\r\n") {
				t.Errorf("res-hdr offset wrong: %d, rest=%q", hdrOff, rest)
			}
			if !strings.HasPrefix(rest[bodyOff:], strconv.FormatInt(int64(len("Blocked: RULE_0\r\n")), 16)+"\r\nBlocked: RULE_0\r\n") {
				t.Errorf("res-body offset %d does not locate chunked body: %q", bodyOff, rest[bodyOff:])
			}
			if !strings.Contains(h.Get("X-Infection-Found"), "Threat=RULE_0;") {
				t.Errorf("X-Infection-Found changed: %q", h.Get("X-Infection-Found"))
			}
		})
	}
}

func TestICAPViolationLinesSanitizeInjection(t *testing.T) {
	out := icapViolationLines([]Match{{Rule: "evil\r\nEncapsulated: null-body=0\x00\x7f\r\n"}})
	lines := strings.Split(strings.TrimSuffix(out, "\r\n"), "\r\n")
	if len(lines) != 4 {
		t.Fatalf("injection produced %d lines, want 4: %q", len(lines), out)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "\t") {
			t.Errorf("line not a continuation: %q", l)
		}
		if strings.ContainsAny(l[1:], "\r\n\x00\x7f") {
			t.Errorf("control byte survived: %q", l)
		}
	}
}

func TestICAPHeaderValue(t *testing.T) {
	long := strings.Repeat("a", 1000)
	for name, c := range map[string]struct{ in, want string }{
		"empty":     {"", "-"},
		"only ctrl": {"\r\n\x00", "-"},
		"plain":     {"abc", "abc"},
		"c1 ctrl":   {"a\u0085b", "ab"},
		"bounded":   {long, long[:icapViolationMax]},
		"rune edge": {strings.Repeat("a", icapViolationMax-1) + "é", strings.Repeat("a", icapViolationMax-1)},
		"exact":     {long[:icapViolationMax], long[:icapViolationMax]},
	} {
		if got := icapHeaderValue(c.in); got != c.want {
			t.Errorf("%s: got %q want %q", name, got, c.want)
		}
	}
}

func TestICAPViolationsFoundCapped(t *testing.T) {
	long := strings.Repeat("r", 300)
	for _, n := range []int{icapViolationsMaxListed - 1, icapViolationsMaxListed, icapViolationsMaxListed + 1, 500} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			var ms []Match
			for i := 0; i < n; i++ {
				ms = append(ms, Match{Rule: fmt.Sprintf("%d_%s", i, long)})
			}
			var sb strings.Builder
			if err := icapWriteInfected(&sb, "fp", ms); err != nil {
				t.Fatal(err)
			}
			resp := sb.String()
			lines, rest := splitICAPResponse(t, resp)
			want := n
			if want > icapViolationsMaxListed {
				want = icapViolationsMaxListed
			}
			at := -1
			for i, l := range lines {
				if strings.HasPrefix(l, "X-Violations-Found:") {
					at = i
				}
			}
			if at < 0 {
				t.Fatalf("X-Violations-Found missing")
			}
			if got := strings.TrimSpace(strings.TrimPrefix(lines[at], "X-Violations-Found:")); got != strconv.Itoa(want) {
				t.Fatalf("count = %q, want %d", got, want)
			}
			cont := 0
			for _, l := range lines[at+1:] {
				if !strings.HasPrefix(l, "\t") {
					break
				}
				cont++
			}
			if cont != 4*want {
				t.Fatalf("continuation lines = %d, want %d", cont, 4*want)
			}
			if next := lines[at+1+cont]; !strings.HasPrefix(next, "Encapsulated:") {
				t.Fatalf("header after violations = %q", next)
			}
			var hdrOff, bodyOff int
			if _, err := fmt.Sscanf(lines[at+1+cont], "Encapsulated: res-hdr=%d, res-body=%d", &hdrOff, &bodyOff); err != nil {
				t.Fatal(err)
			}
			if hdrOff != 0 || !strings.HasPrefix(rest, "HTTP/1.1 403 Forbidden\r\n") || bodyOff > len(rest) {
				t.Fatalf("bad offsets %d/%d", hdrOff, bodyOff)
			}
			if !strings.Contains(rest[bodyOff:], "Blocked: 0_") {
				t.Errorf("body offset does not locate chunked body")
			}
			hdrEnd := strings.Index(resp, "\r\n\r\n") + 4
			if hdrEnd >= 16*1024 {
				t.Errorf("ICAP header block %d bytes, want < 16 KiB", hdrEnd)
			}
		})
	}
}
