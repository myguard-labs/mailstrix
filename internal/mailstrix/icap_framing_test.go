package mailstrix

import (
	"fmt"
	"strings"
	"testing"
)

func icapPreviewRequest(host, terminalExtension, continuation string) string {
	return "RESPMOD icap://" + host + "/scan ICAP/1.0\r\n" +
		"Host: " + host + "\r\n" +
		"Allow: 204\r\n" +
		"Preview: 0\r\n" +
		"Encapsulated: res-body=0\r\n" +
		"\r\n" +
		"0" + terminalExtension + "\r\n\r\n" + continuation
}

// TestICAPPreviewIEOFRequiresExactExtensionToken is the repair-removal control
// for REL-PARSER-ICAP-IEOF-TOKEN. Substrings, extension values, and malformed
// extension lists must not suppress the preview continuation and its scan.
func TestICAPPreviewIEOFRequiresExactExtensionToken(t *testing.T) {
	for _, tc := range []struct {
		name, extension string
	}{
		{"prefix", "; noieof"},
		{"suffix", "; ieofx"},
		{"other extension value", "; note=ieof"},
		{"ieof with value", "; ieof=yes"},
		{"quoted substring", `; note="value;ieof;still-value"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := &fakeEngine{count: 1, fp: "fp", matches: []Match{{Rule: "MALWARE_TEST"}}}
			addr := startTestICAPServer(t, newTestServer(eng, ""))
			body := "malware payload"
			continuation := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)

			resp := doICAP(t, addr, icapPreviewRequest(addr, tc.extension, continuation))
			if !strings.HasPrefix(resp, "ICAP/1.0 100 Continue\r\n\r\n") {
				t.Fatalf("extension %q suppressed continuation: %q", tc.extension, resp)
			}
			if !strings.Contains(resp, "ICAP/1.0 200 OK") || !strings.Contains(resp, "MALWARE_TEST") {
				t.Errorf("continuation was not scanned and blocked: %q", resp)
			}
			if got := eng.scans.Load(); got != 1 {
				t.Errorf("scan count = %d, want 1", got)
			}
		})
	}
}

func TestICAPPreviewRejectsMalformedChunkExtensions(t *testing.T) {
	for _, extension := range []string{
		";",
		";; ieof",
		"; =ieof",
		"; note=",
		"; ieof garbage",
		`; note="unterminated; ieof`,
	} {
		t.Run(extension, func(t *testing.T) {
			eng := &fakeEngine{count: 1, fp: "fp"}
			addr := startTestICAPServer(t, newTestServer(eng, ""))
			resp := doICAP(t, addr, icapPreviewRequest(addr, extension, ""))
			if !strings.HasPrefix(resp, "ICAP/1.0 400 Bad Request") {
				t.Fatalf("malformed extension %q: want 400, got %q", extension, resp)
			}
			if strings.Contains(resp, "204 No Modification") || eng.scans.Load() != 0 {
				t.Errorf("malformed extension reached clean/scanning path: response=%q scans=%d", resp, eng.scans.Load())
			}
		})
	}
}

// TestICAPChunkExtensionsRejectsInvalidQuotedPairBytes is the repair-removal
// control for quoted-pair validation. RFC 7230 quoted-pair permits HTAB, SP,
// VCHAR, or obs-text after a backslash; all other controls and DEL are invalid.
func TestICAPChunkExtensionsRejectsInvalidQuotedPairBytes(t *testing.T) {
	invalid := make([]byte, 0, 32)
	for c := byte(0); c < 0x20; c++ {
		if c != '\t' {
			invalid = append(invalid, c)
		}
	}
	invalid = append(invalid, 0x7f)

	for _, c := range invalid {
		t.Run(fmt.Sprintf("0x%02x", c), func(t *testing.T) {
			exts := append([]byte(`; note="x\`), c)
			exts = append(exts, []byte(`"; ieof`)...)
			hasIEOF, err := parseICAPChunkExtensions(string(exts))
			if err == nil || hasIEOF {
				t.Fatalf("escaped byte 0x%02x: got ieof=%v err=%v, want rejection", c, hasIEOF, err)
			}
		})
	}
}

func TestICAPPreviewWithoutIEOFAndContinuationIsError(t *testing.T) {
	eng := &fakeEngine{count: 1, fp: "fp"}
	addr := startTestICAPServer(t, newTestServer(eng, ""))
	resp := doICAP(t, addr, icapPreviewRequest(addr, "; noieof", ""))
	if !strings.HasPrefix(resp, "ICAP/1.0 100 Continue\r\n\r\n") || !strings.Contains(resp, "ICAP/1.0 400 Bad Request") {
		t.Fatalf("missing continuation: want interim 100 then final 400, got %q", resp)
	}
	if strings.Contains(resp, "204 No Modification") || eng.scans.Load() != 0 {
		t.Errorf("missing continuation reached clean/scanning path: response=%q scans=%d", resp, eng.scans.Load())
	}
}

func TestICAPPreviewIEOFExactTokenPreservesCompletePreview(t *testing.T) {
	for _, extension := range []string{
		"; ieof",
		"; IeOf",
		"; note=value; IEOF",
		`; note="value;with;semicolons"; iEoF`,
		`; note="escaped\"quote"; ieof`,
		`; note="escaped\\backslash"; ieof`,
	} {
		t.Run(extension, func(t *testing.T) {
			eng := &fakeEngine{count: 1, fp: "fp"}
			addr := startTestICAPServer(t, newTestServer(eng, ""))
			resp := doICAP(t, addr, icapPreviewRequest(addr, extension, ""))
			if !strings.HasPrefix(resp, "ICAP/1.0 204 No Modification") {
				t.Fatalf("valid ieof extension %q: want 204 without continuation, got %q", extension, resp)
			}
			if strings.Contains(resp, "100 Continue") {
				t.Errorf("valid ieof extension %q requested continuation: %q", extension, resp)
			}
		})
	}
}

// TestICAPModRequiresExactlyOneEncapsulatedField is the repair-removal control
// for REL-PARSER-ICAP-ENCAPSULATED-DUP. Header-name casing must not let a second
// field bypass cardinality validation, and malformed combined values stay shut.
func TestICAPModRequiresExactlyOneEncapsulatedField(t *testing.T) {
	for _, method := range []string{"REQMOD", "RESPMOD"} {
		t.Run(method, func(t *testing.T) {
			for _, tc := range []struct {
				name, headers, tail string
			}{
				{"identical duplicate", "Encapsulated: null-body=0\r\nEncapsulated: null-body=0\r\n", ""},
				{"case-varied identical duplicate", "Encapsulated: null-body=0\r\neNcApSuLaTeD: null-body=0\r\n", ""},
				{"conflicting duplicate with unread body", "Encapsulated: null-body=0\r\nEncapsulated: res-body=0\r\n", "f\r\nmalware payload\r\n0\r\n\r\nOPTIONS icap://ignored/scan ICAP/1.0\r\n\r\n"},
				{"case-varied conflicting duplicate", "Encapsulated: null-body=0\r\neNcApSuLaTeD: res-body=0\r\n", ""},
				{"empty duplicate", "Encapsulated: null-body=0\r\nEncapsulated:\r\n", ""},
				{"comma-joined duplicate", "Encapsulated: null-body=0, null-body=0\r\n", ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					eng := &fakeEngine{count: 1, fp: "fp"}
					addr := startTestICAPServer(t, newTestServer(eng, ""))
					req := method + " icap://" + addr + "/scan ICAP/1.0\r\n" +
						"Host: " + addr + "\r\nAllow: 204\r\n" + tc.headers + "\r\n" + tc.tail
					resp := doICAP(t, addr, req)
					if !strings.HasPrefix(resp, "ICAP/1.0 400 Bad Request") {
						t.Fatalf("want 400 before a clean verdict, got %q", resp)
					}
					if strings.Contains(resp, "204 No Modification") || eng.scans.Load() != 0 {
						t.Errorf("malformed Encapsulated fields reached clean/scanning path: response=%q scans=%d", resp, eng.scans.Load())
					}
					if strings.Count(resp, "ICAP/1.0 ") != 1 {
						t.Errorf("connection remained usable after framing rejection: %q", resp)
					}
				})
			}
		})
	}
}

func TestICAPModSingleEncapsulatedFieldPreservesBodyAndNullBody(t *testing.T) {
	t.Run("null body", func(t *testing.T) {
		eng := &fakeEngine{count: 1, fp: "fp"}
		addr := startTestICAPServer(t, newTestServer(eng, ""))
		req := "RESPMOD icap://" + addr + "/scan ICAP/1.0\r\n" +
			"Host: " + addr + "\r\nAllow: 204\r\nEncapsulated: null-body=0\r\n\r\n"
		if resp := doICAP(t, addr, req); !strings.HasPrefix(resp, "ICAP/1.0 204 No Modification") {
			t.Fatalf("single null-body field: want 204, got %q", resp)
		}
	})

	t.Run("body", func(t *testing.T) {
		eng := &fakeEngine{count: 1, fp: "fp"}
		addr := startTestICAPServer(t, newTestServer(eng, ""))
		if resp := doICAP(t, addr, icapRESPMODRequest(addr, "safe body", true)); !strings.HasPrefix(resp, "ICAP/1.0 204 No Modification") {
			t.Fatalf("single body field: want 204, got %q", resp)
		}
		if got := eng.scans.Load(); got != 1 {
			t.Errorf("scan count = %d, want 1", got)
		}
	})
}
