package cape

import (
	"bytes"
	"errors"
	"mime/multipart"
	"strings"
	"testing"
)

type failFilePartWriter struct{}

func (failFilePartWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`name="file"`)) {
		return 0, errors.New("fixture file-part failure")
	}
	return len(p), nil
}

func TestWriteMultipartCreateFileFailure(t *testing.T) {
	mw := multipart.NewWriter(failFilePartWriter{})
	err := writeMultipart(mw, strings.NewReader("x"), 1, "machine", "marker", "sample.bin")
	if err == nil || err.Error() != "fixture file-part failure" {
		t.Fatalf("CreateFormFile error=%v", err)
	}
}
