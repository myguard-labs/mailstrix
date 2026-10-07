package mailstrix

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// pwfCapture redirects the std logger for the test and returns the buffer.
func pwfCapture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return &buf
}

func pwfWrite(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// pwfLoadTimeout runs loadArchivePWFile in a goroutine so a regression that
// blocks (FIFO open/read) fails the test instead of hanging the suite.
func pwfLoadTimeout(t *testing.T, path string) []string {
	t.Helper()
	ch := make(chan []string, 1)
	go func() { ch <- loadArchivePWFile(path) }()
	select {
	case got := <-ch:
		return got
	case <-time.After(3 * time.Second):
		t.Fatalf("loadArchivePWFile(%q) blocked for 3s", path)
		return nil
	}
}

func TestLoadArchivePWFileEmptyPath(t *testing.T) {
	buf := pwfCapture(t)
	if got := loadArchivePWFile(""); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
	if buf.Len() != 0 {
		t.Fatalf("empty path must not log, got %q", buf.String())
	}
}

func TestLoadArchivePWFileIfDisabledDoesNotTouchPath(t *testing.T) {
	buf := pwfCapture(t)
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	// A readable regular file too: disabled must still return nil.
	reg := pwfWrite(t, "secret\n")
	for _, p := range []string{fifo, reg, filepath.Join(dir, "missing")} {
		ch := make(chan []string, 1)
		go func() { ch <- loadArchivePWFileIf(false, p) }()
		select {
		case got := <-ch:
			if got != nil {
				t.Fatalf("disabled(%q) = %#v, want nil", p, got)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("disabled loadArchivePWFileIf(%q) blocked", p)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("disabled must be side-effect-free (no log), got %q", buf.String())
	}
}

func TestLoadArchivePWFileIfEnabledLoads(t *testing.T) {
	p := pwfWrite(t, "alpha\nbeta\n")
	got := loadArchivePWFileIf(true, p)
	if want := []string{"alpha", "beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if got := loadArchivePWFileIf(true, ""); got != nil {
		t.Fatalf("enabled+empty path = %#v, want nil", got)
	}
}

func TestLoadArchivePWFileNonexistent(t *testing.T) {
	buf := pwfCapture(t)
	if got := loadArchivePWFile(filepath.Join(t.TempDir(), "nope")); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
	if !strings.Contains(buf.String(), "unreadable") {
		t.Fatalf("expected unreadable warning, got %q", buf.String())
	}
}

func TestLoadArchivePWFileDirectory(t *testing.T) {
	buf := pwfCapture(t)
	if got := pwfLoadTimeout(t, t.TempDir()); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
	if !strings.Contains(buf.String(), "not a regular file") {
		t.Fatalf("expected not-a-regular-file warning, got %q", buf.String())
	}
}

func TestLoadArchivePWFileFIFOWithoutWriter(t *testing.T) {
	buf := pwfCapture(t)
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	if got := pwfLoadTimeout(t, fifo); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
	if !strings.Contains(buf.String(), "not a regular file") {
		t.Fatalf("expected not-a-regular-file warning, got %q", buf.String())
	}
}

func TestLoadArchivePWFileCharDevice(t *testing.T) {
	buf := pwfCapture(t)
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skipf("/dev/null unavailable: %v", err)
	}
	if got := pwfLoadTimeout(t, "/dev/null"); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
	if !strings.Contains(buf.String(), "not a regular file") {
		t.Fatalf("expected not-a-regular-file warning, got %q", buf.String())
	}
}

func TestLoadArchivePWFileParsing(t *testing.T) {
	w128 := strings.Repeat("x", archivePWWordMaxLen)
	w129 := w128 + "y"
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"empty file", "", []string{}},
		{"comments and blanks", "# c\n\n   \nword\n#another\n", []string{"word"}},
		{"comment after trim is not a comment", "  # indented\n", nil},
		{"crlf", "one\r\ntwo\r\n", []string{"one", "two"}},
		{"whitespace trim", "  pad  \n\ttab\t\n", []string{"pad", "tab"}},
		{"inner space kept", "a b c\n", []string{"a b c"}},
		{"dedupe keeps first order", "a\nb\na\nc\nb\n", []string{"a", "b", "c"}},
		{"no trailing newline", "a\nb", []string{"a", "b"}},
		{"len 128 untouched", w128 + "\n", []string{w128}},
		{"len 129 truncated", w129 + "\n", []string{w128}},
		{"truncation then dedupe", w129 + "\n" + w128 + "z\n", []string{w128}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := loadArchivePWFile(pwfWrite(t, c.content))
			if c.want == nil {
				if len(got) != 0 {
					t.Fatalf("got %#v, want empty", got)
				}
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestLoadArchivePWFileLineCap(t *testing.T) {
	mk := func(n int) string {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, "w%05d\n", i)
		}
		return sb.String()
	}
	if got := loadArchivePWFile(pwfWrite(t, mk(archivePWFileMaxLines))); len(got) != archivePWFileMaxLines {
		t.Fatalf("exact cap: len = %d, want %d", len(got), archivePWFileMaxLines)
	}
	got := loadArchivePWFile(pwfWrite(t, mk(archivePWFileMaxLines+1)))
	if len(got) != archivePWFileMaxLines {
		t.Fatalf("cap+1: len = %d, want %d", len(got), archivePWFileMaxLines)
	}
	last := fmt.Sprintf("w%05d", archivePWFileMaxLines-1)
	if got[len(got)-1] != last {
		t.Fatalf("last = %q, want %q", got[len(got)-1], last)
	}
	for _, w := range got {
		if w == fmt.Sprintf("w%05d", archivePWFileMaxLines) {
			t.Fatalf("word beyond line cap present: %q", w)
		}
	}
}

func TestLoadArchivePWFileByteCap(t *testing.T) {
	// One comment line fills the byte budget exactly; words after it are beyond
	// the LimitReader and must never be read.
	head := "before\n#" + strings.Repeat("p", archivePWFileMaxBytes-len("before\n#")-1) + "\n"
	if len(head) != archivePWFileMaxBytes {
		t.Fatalf("fixture head = %d bytes, want %d", len(head), archivePWFileMaxBytes)
	}
	got := loadArchivePWFile(pwfWrite(t, head+"BEYONDCAP\nAFTER2\n"))
	if !reflect.DeepEqual(got, []string{"before"}) {
		t.Fatalf("got %#v, want [before] (content past byte cap must not be read)", got)
	}
	// Control: the same word inside the budget IS read.
	got = loadArchivePWFile(pwfWrite(t, "BEYONDCAP\n"))
	if !reflect.DeepEqual(got, []string{"BEYONDCAP"}) {
		t.Fatalf("in-budget control got %#v", got)
	}
}

// archivePWFileFake is an injectable handle for the open seam.
type archivePWFileFake struct {
	r       io.Reader
	statErr error
	info    fs.FileInfo
}

func (f *archivePWFileFake) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *archivePWFileFake) Close() error               { return nil }
func (f *archivePWFileFake) Stat() (fs.FileInfo, error) { return f.info, f.statErr }

// archivePWFileRegularInfo returns a regular-file FileInfo from a real temp file.
func archivePWFileRegularInfo(t *testing.T) fs.FileInfo {
	t.Helper()
	fi, err := os.Stat(pwfWrite(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// archivePWFileInject swaps the open seam for the test (no t.Parallel callers).
func archivePWFileInject(t *testing.T, h archivePWFileHandle) {
	t.Helper()
	old := archivePWFileOpen
	archivePWFileOpen = func(string) (archivePWFileHandle, error) { return h, nil }
	t.Cleanup(func() { archivePWFileOpen = old })
}

// archivePWFileErrReader yields data once, then a hard error.
type archivePWFileErrReader struct {
	data []byte
	err  error
}

func (r *archivePWFileErrReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

func TestLoadArchivePWFileStatError(t *testing.T) {
	buf := pwfCapture(t)
	archivePWFileInject(t, &archivePWFileFake{
		r:       strings.NewReader("alpha\n"),
		statErr: errors.New("boom-stat"),
		info:    archivePWFileRegularInfo(t),
	})
	if got := loadArchivePWFile("/seam/path"); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
	if out := buf.String(); !strings.Contains(out, "not a regular file") || !strings.Contains(out, "boom-stat") {
		t.Fatalf("missing stat warning, got %q", out)
	}
}

func TestLoadArchivePWFileReadErrorMidStream(t *testing.T) {
	buf := pwfCapture(t)
	archivePWFileInject(t, &archivePWFileFake{
		r:    &archivePWFileErrReader{data: []byte("alpha\nbeta\n"), err: errors.New("boom-read")},
		info: archivePWFileRegularInfo(t),
	})
	if got := loadArchivePWFile("/seam/path"); got != nil {
		t.Fatalf("read error must yield nil, not a partial list; got %#v", got)
	}
	if out := buf.String(); !strings.Contains(out, "read error") || !strings.Contains(out, "boom-read") {
		t.Fatalf("missing read warning, got %q", out)
	}
}

func TestLoadArchivePWFileSeamPositiveControl(t *testing.T) {
	buf := pwfCapture(t)
	archivePWFileInject(t, &archivePWFileFake{
		r:    strings.NewReader("alpha\n# c\nbeta\n"),
		info: archivePWFileRegularInfo(t),
	})
	got := loadArchivePWFile("/seam/path")
	if want := []string{"alpha", "beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if buf.Len() != 0 {
		t.Fatalf("unexpected log %q", buf.String())
	}
}
