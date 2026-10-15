package extractionbudget_test

import (
	"bytes"
	"encoding/binary"
	"github.com/myguard-labs/mailstrix/internal/extract"
	yekazip "github.com/yeka/zip"
	"testing"
	"time"
)

func p16ePE() []byte {
	b := make([]byte, 68)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[60:], 64)
	copy(b[64:], "PE\x00\x00")
	return b
}

func p16eEncryptedZip(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := yekazip.NewWriter(&b)
	w, err := zw.Encrypt("member.txt", "p16e-fixture", yekazip.StandardEncryption)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("plain retained archive member")); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func p16eExtract(name string, input []byte) extract.Result {
	if name != "decrypted_archive" {
		return extract.Extract(input, time.Time{})
	}
	opts := extract.FullOptions(time.Time{})
	opts.ArchivePWEnabled = true
	opts.PWCandidates = []string{"p16e-fixture"}
	return extract.ExtractWithOptions(input, opts)
}

func p16eInputs(t *testing.T) map[string][]byte {
	t.Helper()
	elf := make([]byte, 64)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	elf[16] = 2
	elf[18] = 62
	encrypted := p16eEncryptedZip(t)
	return map[string][]byte{
		"encrypted_archive": encrypted,
		"decrypted_archive": encrypted,
		"xll":               append(p16ePE(), []byte("xlAutoOpen")...),
		"polyglot":          append(p16ePE(), p16bZip(t, p16bZipEntry{name: "plain.txt", data: []byte("plain retained member")})...),
		"elf":               elf,
		"joined_xlm":        []byte("ID;PWXL;N;E\nC;Y1;X1;E=EXEC(calc.exe)\nC;Y2;X1;E=CALL(kernel32,WinExec,JC,calc.exe,0)\n"),
	}
}

func TestP16eStructuralAccountingClosure(t *testing.T) {
	for name, input := range p16eInputs(t) {
		t.Run(name, func(t *testing.T) {
			r := p16eExtract(name, input)
			want := p16dFinalBytes(r)
			if want == 0 {
				t.Fatal("positive fixture retained nothing")
			}
			if got := r.Retained.Bytes(); got != want {
				t.Fatalf("P16e retained closure=%d want complete output bytes=%d", got, want)
			}
			if len(r.Markers) == 0 {
				t.Fatal("structural markers lost their channel")
			}
		})
	}
}

func TestP16eCompleteResultParity(t *testing.T) {
	// Baseline digests are generated independently before the recording-only candidate.
	want := map[string]string{"encrypted_archive": "c6efeec4d5deea4bbcaadabab6503c5fe293a5a784d9c7e0265821f132aaa895", "decrypted_archive": "d69a65cad01ea11168fe5a9357fadf85e2677ad34cb50224884e5dff2cb0fa1e", "elf": "0acf8d8b491a9ecdc11f6f4b3560cb3001e2d0588bebd9368fe855e3e4112c86", "joined_xlm": "80fb69adb5f7a19046e576c22194e7cdccf690d55aaff451f35d9014e7108ce6", "xll": "74a97d959541157be30a1b085bdea97df46d10ac9f111e99a3b0e580c5f400aa", "polyglot": "185c615b69807b9e1bd88bae1f3269c59e564502336334907065342196d810d3"}
	for name, input := range p16eInputs(t) {
		t.Run(name, func(t *testing.T) {
			got := p16dResultDigest(t, p16eExtract(name, input))
			if got != want[name] {
				t.Fatalf("complete Result digest=%s want baseline=%s", got, want[name])
			}
		})
	}
}

func TestP16eArchiveWrongPasswordAndMalformed(t *testing.T) {
	input := p16eEncryptedZip(t)
	opts := extract.FullOptions(time.Time{})
	opts.ArchivePWEnabled = true
	opts.PWCandidates = []string{"wrong-fixture"}
	r := extract.ExtractWithOptions(input, opts)
	if !r.EncryptedArchive || r.DecryptedArchive || r.Retained.Bytes() != 17 || r.Retained.Bytes() != p16dFinalBytes(r) {
		t.Fatalf("wrong password changed retained marker signal: %+v", r)
	}
	malformed := extract.Extract(input[:30], time.Time{})
	if malformed.Retained.Bytes() != 0 || malformed.DecryptedArchive {
		t.Fatalf("malformed ZIP admitted output: %+v", malformed)
	}
}
