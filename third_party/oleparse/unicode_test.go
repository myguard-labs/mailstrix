package oleparse

import "testing"

func TestDecodeUnicodeMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "empty", data: nil, want: ""},
		{name: "ASCII", data: []byte{0x41, 0x00}, want: "A"},
		{name: "accented", data: []byte{0xe9, 0x00}, want: "é"},
		{name: "non-Latin", data: []byte{0x22, 0x6f}, want: "漢"},
		{name: "supplementary", data: []byte{0x3d, 0xd8, 0x00, 0xde}, want: "😀"},
		{name: "unpaired surrogate", data: []byte{0x3d, 0xd8}, want: "�"},
		{name: "trailing byte", data: []byte{0x41, 0x00, 0xff}, want: "A�"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := decodeUnicode(test.data, 1252); got != test.want {
				t.Fatalf("decodeUnicode(%x) = %q, want %q", test.data, got, test.want)
			}
		})
	}
}

func TestDecodeUnicodeMetadataDoesNotApplyANSICodePage(t *testing.T) {
	t.Parallel()

	data := []byte{0xe9, 0x00, 0x22, 0x6f, 0x3d, 0xd8, 0x00, 0xde}
	const want = "é漢😀"
	for _, codepage := range []uint16{0, 1252, 65001} {
		if got := decodeUnicode(data, codepage); got != want {
			t.Errorf("decodeUnicode(%x, %d) = %q, want %q", data, codepage, got, want)
		}
	}
}
