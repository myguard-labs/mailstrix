package ci_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func TestDecodeRunsPublicContract(t *testing.T) {
	payload := []byte("powershell -command hidden-payload-tail")
	for _, mode := range []struct {
		name   string
		encode func([]byte) string
	}{{"base64", base64.StdEncoding.EncodeToString}, {"hex", hex.EncodeToString}} {
		t.Run(mode.name, func(t *testing.T) {
			// A first candidate opens the existing sampled prefilter. The second sits
			// beyond both candidate caps and the fold scan limit and must still decode.
			src := []byte(base64.StdEncoding.EncodeToString([]byte("first decoded payload")) + "!" + strings.Repeat("!", (2<<20)+1) + mode.encode(payload))
			got := extract.Extract(src, time.Time{})
			found := false
			total := 0
			for _, stream := range got.Streams {
				found = found || bytes.Equal(stream, payload)
				total += len(stream)
				if len(stream) > 1<<20 {
					t.Fatal("decoded blob exceeds byte budget")
				}
			}
			if !found {
				t.Fatal("decoded payload after large source prefix was lost")
			}
			if got.DecodedStreams > 32 || total > 4<<20 {
				t.Fatal("decoded stream budget exceeded")
			}
			expired := extract.Extract(src, time.Now().Add(-time.Second))
			if expired.DecodedStreams != 0 {
				t.Fatal("expired extraction decoded a stream")
			}
		})
	}
	for _, src := range []string{"", "ordinary words only", strings.Repeat("G", 23), strings.Repeat("a", 31), strings.Repeat("G", 25) + "=="} {
		if got := extract.Extract([]byte(src), time.Time{}); got.DecodedStreams != 0 {
			t.Fatalf("malformed/short input decoded %d streams", got.DecodedStreams)
		}
	}
}

func TestDecodeRunsPublicAlignedBudget(t *testing.T) {
	payload := bytes.Repeat([]byte("z!"), (1<<19)+9)
	for _, mode := range []struct {
		name   string
		encode func([]byte) string
	}{{"base64", base64.StdEncoding.EncodeToString}, {"hex", hex.EncodeToString}} {
		t.Run(mode.name, func(t *testing.T) {
			result := extract.Extract([]byte(mode.encode(payload)), time.Time{})
			found := false
			for _, stream := range result.Streams {
				if len(stream) > 1<<20 {
					t.Fatal("decoded stream exceeds blob budget")
				}
				if bytes.Equal(stream, payload[:1<<20]) {
					found = true
				}
			}
			if !found {
				t.Fatal("aligned truncation did not retain the expected decoded prefix")
			}
		})
	}
}
