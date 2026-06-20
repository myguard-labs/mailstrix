package extract

import (
	"strings"
	"testing"
	"time"
)

// TestCarveStrings verifies that carveStrings returns runs of printable ASCII
// bytes of length >= minPrintRun and discards shorter runs.
func TestCarveStrings(t *testing.T) {
	t.Run("empty input yields no strings", func(t *testing.T) {
		got := carveStrings(nil)
		if len(got) != 0 {
			t.Fatalf("expected 0 strings, got %d", len(got))
		}
	})

	t.Run("short printable run below threshold", func(t *testing.T) {
		// "hello" is 5 bytes, below minPrintRun (8).
		got := carveStrings([]byte("\x00hello\x00"))
		if len(got) != 0 {
			t.Fatalf("expected 0 strings for short run, got %d: %q", len(got), got)
		}
	})

	t.Run("single long run extracted", func(t *testing.T) {
		want := "powershell -enc ABCD"
		src := append([]byte{0x00, 0x01}, []byte(want)...)
		src = append(src, 0x00)
		got := carveStrings(src)
		if len(got) != 1 {
			t.Fatalf("expected 1 string, got %d", len(got))
		}
		if string(got[0]) != want {
			t.Fatalf("got %q, want %q", got[0], want)
		}
	})

	t.Run("multiple runs separated by non-printable bytes", func(t *testing.T) {
		src := []byte("cmd.exe\x00\x00http://evil.example.com/payload\x00")
		// "cmd.exe" is 7 bytes — below threshold; URL is long enough.
		got := carveStrings(src)
		if len(got) != 1 {
			t.Fatalf("expected 1 string (URL only), got %d: %q", len(got), got)
		}
		if !strings.Contains(string(got[0]), "http://evil.example.com") {
			t.Fatalf("unexpected string: %q", got[0])
		}
	})

	t.Run("URL and command in o stream", func(t *testing.T) {
		// Simulate an "o" stream with two long printable runs embedded in binary.
		url := "https://evil.example.com/stage2.exe"
		cmd := "powershell -nop -w hidden"
		var src []byte
		src = append(src, []byte{0x01, 0x02, 0x03}...)
		src = append(src, []byte(url)...)
		src = append(src, []byte{0x00, 0x00}...)
		src = append(src, []byte(cmd)...)
		src = append(src, 0x00)
		got := carveStrings(src)
		if len(got) != 2 {
			t.Fatalf("expected 2 strings, got %d: %q", len(got), got)
		}
		if string(got[0]) != url {
			t.Errorf("got[0]=%q, want %q", got[0], url)
		}
		if string(got[1]) != cmd {
			t.Errorf("got[1]=%q, want %q", got[1], cmd)
		}
	})

	t.Run("trailing run flushed", func(t *testing.T) {
		want := "wscript.shell.run"
		src := append([]byte{0x00}, []byte(want)...)
		got := carveStrings(src)
		if len(got) != 1 {
			t.Fatalf("expected 1 string (trailing), got %d", len(got))
		}
		if string(got[0]) != want {
			t.Fatalf("got %q, want %q", got[0], want)
		}
	})
}

// TestExtractFStreamValues verifies key=value parsing from f/VBFrame streams.
func TestExtractFStreamValues(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		got := extractFStreamValues(nil)
		if len(got) != 0 {
			t.Fatalf("expected 0 values, got %d", len(got))
		}
	})

	t.Run("values below min length filtered", func(t *testing.T) {
		src := []byte("Caption=hi\nTag=short\n")
		got := extractFStreamValues(src)
		if len(got) != 0 {
			t.Fatalf("expected 0 values (all below threshold), got %d: %q", len(got), got)
		}
	})

	t.Run("long value extracted", func(t *testing.T) {
		val := "https://evil.example.com/payload"
		src := []byte("Caption=" + val + "\nTag=hi\n")
		got := extractFStreamValues(src)
		if len(got) != 1 {
			t.Fatalf("expected 1 value, got %d: %q", len(got), got)
		}
		if string(got[0]) != val {
			t.Fatalf("got %q, want %q", got[0], val)
		}
	})

	t.Run("multiple long values extracted", func(t *testing.T) {
		src := []byte("Caption=powershell -nop -enc ABCDEF\nTag=cmd.exe /c whoami\n")
		got := extractFStreamValues(src)
		if len(got) != 2 {
			t.Fatalf("expected 2 values, got %d: %q", len(got), got)
		}
	})

	t.Run("lines without = are ignored", func(t *testing.T) {
		src := []byte("VERSION 5.00\nCaption=powershell -nop -enc ABCDEF\n")
		got := extractFStreamValues(src)
		if len(got) != 1 {
			t.Fatalf("expected 1 value, got %d", len(got))
		}
	})
}

// TestIsFormStreamName verifies stream name matching.
func TestIsFormStreamName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"o", true},
		{"f", true},
		{"\x03VBFrame", true},
		{"UserForm1\x03VBFrame", true},
		{"VBA", false},
		{"dir", false},
		{"ThisDocument", false},
		{"", false},
	}
	for _, c := range cases {
		got := isFormStreamName(c.name)
		if got != c.want {
			t.Errorf("isFormStreamName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestHasUserFormMarker checks the marker detection helper.
func TestHasUserFormMarker(t *testing.T) {
	if hasUserFormMarker(nil) {
		t.Error("nil streams should return false")
	}
	if hasUserFormMarker([][]byte{[]byte("VBA-STOMPED foo pcode=512 src=0")}) {
		t.Error("non-marker stream should return false")
	}
	if !hasUserFormMarker([][]byte{[]byte("USERFORM-STRINGS")}) {
		t.Error("marker stream should return true")
	}
}

// TestCarveInputClamp verifies the carve input clamp (STAB-8): a printable run
// placed entirely past maxCarveInput is not carved, while content within the
// window still is, and a multi-MiB stream terminates promptly.
func TestCarveInputClamp(t *testing.T) {
	// Run within the window is carved.
	if got := carveStrings([]byte("WITHIN_WINDOW_PRINTABLE")); len(got) != 1 {
		t.Fatalf("run within window: got %d runs, want 1", len(got))
	}

	// A non-printable filler exactly maxCarveInput long, then a printable run:
	// the run sits past the clamp boundary and must be dropped.
	big := make([]byte, maxCarveInput)
	for i := range big {
		big[i] = 0x00 // non-printable
	}
	big = append(big, []byte("PAST_THE_CLAMP_BOUNDARY")...)

	done := make(chan [][]byte, 1)
	go func() { done <- carveStrings(big) }()
	select {
	case got := <-done:
		if len(got) != 0 {
			t.Fatalf("run past clamp boundary was carved: %d runs", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("carveStrings did not terminate on a multi-MiB stream")
	}

	// extractFStreamValues is clamped the same way: a key=value past the boundary
	// is dropped.
	buf := append(append([]byte{}, big...), []byte("\nkey=PAST_BOUNDARY_VALUE")...)
	if got := extractFStreamValues(buf); len(got) != 0 {
		t.Fatalf("value past clamp boundary was extracted: %d", len(got))
	}
}
