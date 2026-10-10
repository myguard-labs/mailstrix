package mailstrix

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"weak"

	yara "github.com/hillu/go-yara/v4"
)

func TestP10MarkerCloneReleasesBackingBuffer(t *testing.T) {
	rules, err := compileDir(writeRules(t, cloneFixture), func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	original := serializeRules
	t.Cleanup(func() { serializeRules = original })
	for _, mode := range []string{"valid", "empty", "malformed", "write-error", "empty-write-error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			var retained *bytes.Buffer
			beforeCapacity := 0
			serializeRules = func(r *yara.Rules, w io.Writer) error {
				retained = w.(*bytes.Buffer)
				defer func() { beforeCapacity = retained.Cap() }()
				switch mode {
				case "valid":
					return original(r, w)
				case "empty":
					return nil
				case "empty-write-error":
					return errors.New("injected serialization failure")
				default:
					if _, err := w.Write(bytes.Repeat([]byte("truncated"), 4096)); err != nil {
						return err
					}
					if mode == "panic" {
						panic("injected serialization panic")
					}
					if mode == "write-error" {
						return errors.New("injected serialization failure")
					}
					return nil
				}
			}
			var bundle *yara.Rules
			var cloneErr error
			var panicked any
			func() {
				defer func() { panicked = recover() }()
				bundle, cloneErr = cloneMarkerBundle(rules, nil, func(string, ...any) {})
			}()
			if bundle != nil {
				defer bundle.Destroy()
			}
			if mode == "valid" {
				if cloneErr != nil || bundle == nil || bundle == rules {
					t.Fatalf("valid clone ownership: bundle=%p main=%p error=%v", bundle, rules, cloneErr)
				}
			} else if mode == "panic" {
				if panicked != "injected serialization panic" {
					t.Fatalf("serialization panic changed: %v", panicked)
				}
			} else {
				stage := "marker bundle read:"
				if strings.Contains(mode, "write-error") {
					stage = "marker bundle serialize:"
				}
				if cloneErr == nil || !strings.Contains(cloneErr.Error(), stage) || bundle != nil {
					t.Fatalf("failure result changed: bundle=%p error=%v, want %s", bundle, cloneErr, stage)
				}
			}
			if mode != "empty" && mode != "empty-write-error" && beforeCapacity == 0 {
				t.Fatal("fixture did not allocate serialization backing storage")
			}
			if retained == nil {
				t.Fatal("production serializer did not receive a buffer")
			}
			if retained.Cap() != 0 || retained.Len() != 0 || retained.Bytes() != nil {
				t.Fatalf("clone retained serialization backing storage: capacity=%d length=%d (before=%d)", retained.Cap(), retained.Len(), beforeCapacity)
			}
		})
	}
}

func TestP10MarkerCloneMalformedReaderBackingStorage(t *testing.T) {
	original := serializeRules
	t.Cleanup(func() { serializeRules = original })
	var reader weak.Pointer[bytes.Buffer]
	serializeRules = func(_ *yara.Rules, w io.Writer) error {
		buf := w.(*bytes.Buffer)
		reader = weak.Make(buf)
		_, err := buf.Write(bytes.Repeat([]byte("truncated"), 4096))
		return err
	}
	bundle, err := cloneMarkerBundle(nil, nil, func(string, ...any) {})
	if err == nil || bundle != nil {
		t.Fatalf("malformed clone result: bundle=%p error=%v", bundle, err)
	}
	runtime.GC()
	// The pinned go-yara error path keeps its cgo reader handle. If upstream
	// releases that handle in future, collection also satisfies this contract.
	if buf := reader.Value(); buf != nil {
		t.Log("native read error retained the reader wrapper after GC")
		if buf.Cap() != 0 || buf.Bytes() != nil {
			t.Fatalf("native read error retained backing storage: capacity=%d", buf.Cap())
		}
	}
}
