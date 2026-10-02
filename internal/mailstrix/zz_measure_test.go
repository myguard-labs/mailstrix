package mailstrix

import (
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func TestZZMeasure(t *testing.T) {
	z := paddedDropperZip(t, padCount)
	t0 := time.Now()
	res := extract.ExtractWithOptions(z, extract.FullOptions(time.Now().Add(2*time.Second)))
	t.Logf("extract: %v streams=%d content=%d zip=%dB", time.Since(t0), len(res.Streams), res.ContentStreams, len(z))
}
