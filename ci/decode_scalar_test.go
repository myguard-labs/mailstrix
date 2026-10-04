package ci_test

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func scalarEncodings() []struct {
	name   string
	encode func([]byte) string
} {
	return []struct {
		name   string
		encode func([]byte) string
	}{
		{"netbios", func(b []byte) string {
			out := make([]byte, 0, 2*len(b))
			for _, c := range b {
				out = append(out, 'A'+c>>4, 'A'+c&15)
			}
			return string(out)
		}},
		{"base32", base32.StdEncoding.EncodeToString},
		{"decimal", func(b []byte) string {
			var out strings.Builder
			for i, c := range b {
				if i > 0 {
					out.WriteByte(',')
				}
				out.WriteString(strconv.Itoa(int(c)))
			}
			return out.String()
		}},
	}
}

func TestDecodeScalarPublicContract(t *testing.T) {
	payload := []byte("powershell -command hidden-payload-tail")
	for _, mode := range scalarEncodings() {
		t.Run(mode.name, func(t *testing.T) {
			// Keep the existing sampled prefilter open while placing the target beyond
			// every scalar candidate cap. Searching only a prefix loses this payload.
			src := []byte(base64.StdEncoding.EncodeToString([]byte("first decoded payload")) + "!" + strings.Repeat("!", (4<<20)+1) + mode.encode(payload))
			got := extract.Extract(src, time.Time{})
			found, total := false, 0
			for _, stream := range got.Streams {
				found = found || bytes.Equal(stream, payload)
				total += len(stream)
				if len(stream) > 1<<20 {
					t.Fatal("decoded blob exceeds byte budget")
				}
			}
			if !found {
				t.Fatal("decoded scalar payload after large source prefix was lost")
			}
			if got.DecodedStreams > 32 || total > 4<<20 {
				t.Fatal("decoded stream budget exceeded")
			}
			if got := extract.Extract(src, time.Now().Add(-time.Second)); got.DecodedStreams != 0 {
				t.Fatal("expired extraction decoded a stream")
			}
		})
	}
	for _, src := range []string{"ordinary words only", strings.Repeat("1,", 11) + "256", strings.Repeat("1,", 11) + "1;1"} {
		if got := extract.Extract([]byte(src), time.Time{}); got.DecodedStreams != 0 {
			t.Fatalf("invalid scalar input decoded %d streams", got.DecodedStreams)
		}
	}
}

func TestDecodeScalarPublicAlignedBudget(t *testing.T) {
	payload := bytes.Repeat([]byte("z!"), (1<<19)+9)
	for _, mode := range scalarEncodings() {
		t.Run(mode.name, func(t *testing.T) {
			result := extract.Extract([]byte(mode.encode(payload)), time.Time{})
			found := false
			for _, stream := range result.Streams {
				if len(stream) > 1<<20 {
					t.Fatal("decoded stream exceeds blob budget")
				}
				found = found || bytes.Equal(stream, payload[:1<<20])
			}
			if !found {
				t.Fatal("aligned truncation did not retain the expected decoded prefix")
			}
		})
	}
}
