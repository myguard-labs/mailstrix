package extract

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func p16dStreamBytes(streams [][]byte) uint64 {
	var total uint64
	for _, stream := range streams {
		total += uint64(len(stream))
	}
	return total
}

func assertP16dLedger(t *testing.T, ledger *retainedBudget, streams [][]byte) {
	t.Helper()
	want := p16dStreamBytes(streams)
	if want == 0 {
		t.Fatal("positive P16d fixture emitted no streams")
	}
	if got := ledger.snapshot().Bytes(); got != want {
		t.Fatalf("P16d retained bytes=%d want independently summed streams=%d", got, want)
	}
}

func TestP16dReviewedSLKFoldedAndDDEAccounting(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want uint64
	}{
		{name: "folded", doc: "ID;PWXL;N;E\nC;Y1;X1;E=EXEC(calc.exe)\n", want: 38},
		{name: "dde", doc: "ID;PWXL;N;E\nC;Y1;X1;E=cmd|'/c calc.exe'!A1\n", want: 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, ledger := p16bResult()
			fromSLK([]byte(tc.doc), res, time.Time{})
			if got := p16dStreamBytes(res.Streams); got != tc.want {
				t.Fatalf("fixture output bytes=%d want reviewed source-bound value=%d; streams=%q", got, tc.want, res.Streams)
			}
			assertP16dLedger(t, ledger, res.Streams)
		})
	}
}

func TestP16dSLKOutputCapAccounting(t *testing.T) {
	fillerLen := maxXLMFoldFormulaLen - 12
	outputLen := fillerLen + 1 // the extracted formula retains its leading '='
	line := "C;Y1;X1;E=" + string(bytes.Repeat([]byte{'A'}, fillerLen)) + "\n"
	accepted := maxXLMFoldOutputLen / outputLen
	doc := "ID;PWXL;N;E\n" + strings.Repeat(line, accepted+2)
	res, ledger := p16bResult()
	fromSLK([]byte(doc), res, time.Time{})
	if got := p16dStreamBytes(res.Streams); got != uint64(accepted*outputLen) {
		t.Fatalf("SLK capped output bytes=%d want accepted formulas=%d", got, accepted*outputLen)
	}
	assertP16dLedger(t, ledger, res.Streams)
}

func TestP16dTextSinkAccounting(t *testing.T) {
	t.Run("script", func(t *testing.T) {
		input := []byte("#@~^DgAAAA==" +
			"\x5c\x6b\x6f\x24\x4b\x36\x2c\x4a\x43\x7f\x56\x5e\x47\x4a\x71\x41\x51\x41\x41\x41\x3d\x3d" +
			"^#~@")
		res, ledger := p16bResult()
		fromEncodedScript(input, res, time.Time{})
		assertP16dLedger(t, ledger, res.Streams)
	})

	t.Run("csv", func(t *testing.T) {
		res, ledger := p16bResult()
		fromCSVDDE([]byte("=cmd|'/c calc.exe'!A1,plain\n"), res, time.Time{})
		assertP16dLedger(t, ledger, res.Streams)
	})

	t.Run("launcher_url", func(t *testing.T) {
		res, ledger := p16bResult()
		fromLauncherFields([]byte(evilURL), res, time.Time{})
		assertP16dLedger(t, ledger, res.Streams)
	})

	t.Run("launcher_transaction", func(t *testing.T) {
		res, ledger := p16bResult()
		fromSettingContent([]byte(evilSettings), res, time.Time{})
		assertP16dLedger(t, ledger, res.Streams)

		malformed, malformedLedger := p16bResult()
		fromSettingContent([]byte(`<PCSettingsFile><DeepLink>calc.exe`), malformed, time.Time{})
		if len(malformed.Streams) != 0 || malformedLedger.snapshot().Bytes() != 0 {
			t.Fatalf("malformed launcher published streams=%q retained=%d", malformed.Streams, malformedLedger.snapshot().Bytes())
		}
	})

	t.Run("html_data_uri", func(t *testing.T) {
		payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{'A'}, 64)...)
		uri := base64.StdEncoding.EncodeToString(payload)
		input := []byte(`<html><a download href="data:application/pdf;base64,` + uri + `">x</a></html>`)
		res, ledger := p16bResult()
		fromHTMLSmuggling(input, res, &archiveBudget{}, 0, time.Time{})
		assertP16dLedger(t, ledger, res.Streams)
	})

	t.Run("svg_script", func(t *testing.T) {
		res, ledger := p16bResult()
		fromHTMLSmuggling([]byte(`<svg onload="alert(1)"></svg>`), res, &archiveBudget{}, 0, time.Time{})
		assertP16dLedger(t, ledger, res.Streams)
	})
}

func TestP16dDecoderAccountingBoundariesAndDedup(t *testing.T) {
	t.Run("utf16_and_defang", func(t *testing.T) {
		wide := []byte{0xff, 0xfe}
		for _, c := range []byte("powershell.exe -nop -w hidden") {
			wide = append(wide, c, 0)
		}
		res, ledger := p16bResult()
		fromEncoded(append(wide, []byte(" hxxps[:]//evil[.]example")...), res, FullOptions(time.Time{}))
		assertP16dLedger(t, ledger, res.Streams)
	})

	t.Run("collision_keeps_distinct", func(t *testing.T) {
		forceDedupCollision(t)
		res, ledger := p16bResult()
		input := []byte(b64Run(auDecoyPayload) + " " + b64Run(auHiddenPayload))
		fromEncoded(input, res, FullOptions(time.Time{}))
		assertP16dLedger(t, ledger, res.Streams)
		for _, payload := range []string{auDecoyPayload, auHiddenPayload} {
			if streamsContainExactlyN(res, payload) != 1 {
				t.Fatalf("collision fixture payload %q count=%d want=1", payload, streamsContainExactlyN(res, payload))
			}
		}
	})

	t.Run("duplicate_charged_once", func(t *testing.T) {
		payload := "P16D-DUPLICATE-PAYLOAD"
		encoded := b64Run(payload)
		res, ledger := p16bResult()
		fromEncoded([]byte(encoded+" "+encoded), res, FullOptions(time.Time{}))
		if streamsContainExactlyN(res, payload) != 1 {
			t.Fatalf("duplicate payload count=%d want=1", streamsContainExactlyN(res, payload))
		}
		assertP16dLedger(t, ledger, res.Streams)
	})

	t.Run("local_tree_and_minimum", func(t *testing.T) {
		res, ledger := p16bResult()
		decodeSourceTree([]byte(b64Run("P16D-LOCAL-TREE-PAYLOAD")), res, FullOptions(time.Time{}))
		assertP16dLedger(t, ledger, res.Streams)

		var out [][]byte
		total := 0
		if !emitFoldedFormula("1234567", &out, &total, false, res) {
			t.Fatal("below-minimum folded input unexpectedly stopped traversal")
		}
		if len(out) != 0 || ledger.snapshot().Bytes() != p16dStreamBytes(res.Streams) {
			t.Fatalf("below-minimum input changed output=%q retained=%d", out, ledger.snapshot().Bytes())
		}
	})

	t.Run("depth_and_deep_marker", func(t *testing.T) {
		payload := []byte("P16D-DEEP-LOCAL-PAYLOAD")
		for range deepDecodeLayer {
			payload = []byte(base64.StdEncoding.EncodeToString(payload))
		}
		shallowRes, shallowLedger := p16bResult()
		shallow := FullOptions(time.Time{})
		shallow.DecodeDepth = 1
		decodeSourceTree(payload, shallowRes, shallow)
		assertP16dLedger(t, shallowLedger, shallowRes.Streams)
		if streamsContain(*shallowRes, "MSD-DEEPDECODE") {
			t.Fatal("depth-one decoder emitted deep marker")
		}

		deepRes, deepLedger := p16bResult()
		deep := FullOptions(time.Time{})
		deep.DecodeDepth = deepDecodeLayer
		decodeSourceTree(payload, deepRes, deep)
		assertP16dLedger(t, deepLedger, deepRes.Streams)
		if !streamsContain(*deepRes, "MSD-DEEPDECODE depth=3") {
			t.Fatalf("deep decoder marker missing: %q", deepRes.Streams)
		}
		if deepLedger.snapshot().Bytes() <= shallowLedger.snapshot().Bytes() {
			t.Fatalf("deep retained=%d want greater than shallow=%d", deepLedger.snapshot().Bytes(), shallowLedger.snapshot().Bytes())
		}
	})

	t.Run("max_streams_boundary", func(t *testing.T) {
		res, ledger := p16bResult()
		res.Streams = make([][]byte, maxStreams)
		fromEncoded([]byte(b64Run("P16D-BOUNDARY-PAYLOAD")), res, FullOptions(time.Time{}))
		if got := ledger.snapshot().Bytes(); got != 0 {
			t.Fatalf("saturated stream set retained=%d want=0", got)
		}
		if len(res.Streams) != maxStreams {
			t.Fatalf("saturated stream count=%d want=%d", len(res.Streams), maxStreams)
		}
	})

	t.Run("direct_caller_without_ledger", func(t *testing.T) {
		var res Result
		decodeSourceTree([]byte(b64Run("P16D-NIL-COMPAT-PAYLOAD")), &res, FullOptions(time.Time{}))
		if !streamsContain(res, "P16D-NIL-COMPAT-PAYLOAD") {
			t.Fatalf("direct nil-ledger caller output changed: %q", res.Streams)
		}
	})
}

func TestP16dPEViewAccountingUsesIndependentSuffix(t *testing.T) {
	pe := minimalPE()
	parent := append(bytes.Repeat([]byte{'P'}, 19), pe...)
	res, ledger := p16bResult()
	if _, ok := ledger.recordBytes(parent); !ok {
		t.Fatal("failed to seed independently accepted parent")
	}
	res.Streams = append(res.Streams, parent)
	carveEmbeddedPEs(res, 0)
	if len(res.Streams) != 3 || !bytes.Equal(res.Streams[1], pe) || string(res.Streams[2]) != b64PECarveMarker {
		t.Fatalf("PE outputs changed: streams=%q", res.Streams)
	}
	if &res.Streams[1][0] != &parent[19] {
		t.Fatal("PE suffix no longer aliases the accepted parent view")
	}
	want := uint64(len(parent) + len(pe) + len(b64PECarveMarker))
	if got := ledger.snapshot().Bytes(); got != want {
		t.Fatalf("PE retained bytes=%d want parent+independent suffix+marker=%d", got, want)
	}
}

func TestP16dPEViewParity(t *testing.T) {
	pe := minimalPE()
	parent := append(bytes.Repeat([]byte{'P'}, 19), pe...)
	res := Result{Streams: [][]byte{parent}}
	carveEmbeddedPEs(&res, 0)
	if len(res.Streams) != 3 || !bytes.Equal(res.Streams[1], pe) || string(res.Streams[2]) != b64PECarveMarker {
		t.Fatalf("PE outputs changed: streams=%q", res.Streams)
	}
	if &res.Streams[1][0] != &parent[19] {
		t.Fatal("PE suffix no longer aliases the accepted parent view")
	}
}
