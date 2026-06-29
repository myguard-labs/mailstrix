package extract

// OLE2Link URL-moniker detection (CVE-2017-0199).
//
// A malicious document embeds an OLE2Link object whose data stream carries a
// Standard URL Moniker. When the document is opened, Office auto-resolves that
// moniker — fetching and executing a remote HTA/script payload — which is the
// CVE-2017-0199 / CVE-2017-8570 family. yarad already carves embedded OLE
// objects, but it never read the moniker URL, so a remote-payload lure looked
// inert to the rules (noted in oletools-reference §oleobj: oleobj.py reads the
// moniker URL, yarad did not).
//
// This file closes that gap: it scans the OLE2 streams for the StdURLMoniker
// CLSID and surfaces the UTF-16LE URL that follows as an "OLE2LINK-URL <url>"
// marker so a YARA rule can score it. Bounded, deadline-aware, fail-open.

import (
	"bytes"
	"encoding/binary"
	"time"
	"unicode/utf16"

	"www.velocidex.com/golang/oleparse"
)

// stdURLMonikerCLSID is {79EAC9E0-AFF7-11CE-BAC6-00AA00A74CFD} serialised the way
// it appears on the wire — Data1/2/3 little-endian, Data4 big-endian. This is the
// 16-byte class id that prefixes a Standard URL Moniker stream (MS-OLEDS / the
// CVE-2017-0199 OLE2Link object).
var stdURLMonikerCLSID = []byte{
	0xE0, 0xC9, 0xEA, 0x79, 0xF7, 0xAF, 0xCE, 0x11,
	0xBA, 0xC6, 0x00, 0xAA, 0x00, 0xA7, 0x4C, 0xFD,
}

const (
	// maxOLE2LinkStream caps the declared stream size we will load to look for the
	// moniker — oleparse.GetStream materialises the whole stream, so an oversized
	// one is skipped (the raw-bytes scan still covers it). A real OLE2Link object
	// in a mail doc is tiny.
	maxOLE2LinkStream = 8 << 20
	// maxOLE2LinkURL caps the decoded URL length we surface, so a crafted oversized
	// length field can't make us copy a huge blob into a marker.
	maxOLE2LinkURL = 4096
)

// fromOLE2Link scans the OLE2 directory for any stream carrying a StdURLMoniker
// and, for the first one found, appends an "OLE2LINK-URL <url>" marker. Only the
// first hit is emitted (one lure URL is enough to score; the cap keeps a crafted
// many-moniker doc from flooding res.Streams).
func fromOLE2Link(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || len(ole.Directory) == 0 || expired(deadline) {
		return
	}
	for _, d := range ole.Directory {
		if expired(deadline) || len(res.Streams) >= maxStreams {
			return
		}
		if d == nil || d.Header.Mse != 2 || d.Header.Size == 0 || d.Header.Size > maxOLE2LinkStream {
			continue
		}
		data := ole.GetStreamView(d.Index)
		url := monikerURL(data)
		if url == nil {
			continue
		}
		marker := append([]byte("OLE2LINK-URL "), url...)
		res.Streams = append(res.Streams, marker)
		return // first moniker URL is enough
	}
}

// monikerURL returns the UTF-16LE URL carried by a StdURLMoniker inside data, or
// nil if there is none. Layout after the 16-byte CLSID: a DWORD byte-length L
// followed by an L-byte UTF-16LE string (null-terminated; newer serialisers
// append a trailing serialized-GUID, which the trailing-NUL trim drops). We
// validate L against the buffer and the URL cap before decoding, so a bogus
// length can neither over-read nor force a large copy.
func monikerURL(data []byte) []byte {
	// Walk EVERY CLSID occurrence: a decoy/garbage StdURLMoniker CLSID placed
	// before the real one (whose length field doesn't decode) must not mask the
	// genuine moniker further along — so try each hit until one yields a URL.
	off := 0
	for {
		rel := bytes.Index(data[off:], stdURLMonikerCLSID)
		if rel < 0 {
			return nil
		}
		p := off + rel + len(stdURLMonikerCLSID)
		off = off + rel + 1 // next search starts past this CLSID byte
		if p+4 > len(data) {
			continue
		}
		n := int(binary.LittleEndian.Uint32(data[p:]))
		p += 4
		// n is a byte count of UTF-16LE data: must be even, positive, and fit the
		// buffer. The p+n>len guard also covers any p+n wrap on a 32-bit build,
		// because n<0 (from the int conversion) fails the n<2 check first.
		if n < 2 || n%2 != 0 || p+n > len(data) || p+n < p {
			continue
		}
		if n > maxOLE2LinkURL*2 {
			n = maxOLE2LinkURL * 2
		}
		u16 := make([]uint16, n/2)
		for j := range u16 {
			u16[j] = binary.LittleEndian.Uint16(data[p+j*2:])
		}
		url := bytes.TrimRight([]byte(string(utf16.Decode(u16))), "\x00")
		if len(url) == 0 {
			continue
		}
		return url
	}
}
