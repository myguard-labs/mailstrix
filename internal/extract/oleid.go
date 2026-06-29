package extract

// oleid-style structural indicators. oletools' oleid reports a fixed set of
// risk indicators for an OLE2/OOXML document (oleid.py); most of yarad's set is
// already covered by dedicated extractors (encrypted → Result.Encrypted, vba →
// macro streams + intent.yara, xlm → XLM markers, ext_rels → OOXML-EXTERNAL-REL).
// This file adds the two structural ones that had no yarad equivalent:
//
//   - ObjectPool: an OLE2 storage that holds embedded OLE objects. Its presence
//     on a document is a classic embedded-object lure indicator (oleid.py:400).
//   - Flash/SWF: an embedded Shockwave Flash object — a long-running exploit
//     delivery vector oleid flags (oleid.py:490). Detected by SWF magic.
//
// Each is emitted as a synthetic OLEID-* marker stream so a YARA rule can score
// it, matching yarad's marker convention. Reference: memory oletools-reference §2.

import (
	"bytes"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// maxOLEIDFlashScan bounds how many bytes of a stream we sniff for SWF magic.
// The magic is in the first 3 bytes; we only need the head.
const maxOLEIDFlashScan = 8

// maxOLEIDFlashStream caps the declared stream size we are willing to load to
// sniff for SWF magic. oleparse.GetStream materialises the WHOLE stream, so
// without this a crafted multi-GB stream would be read into memory just to
// check 3 bytes. A real SWF object in a mail doc is far smaller; an oversized
// stream is skipped (the raw-bytes scan still covers it).
const maxOLEIDFlashStream = 8 << 20

// swfMagics are the Shockwave Flash file signatures: uncompressed (FWS),
// zlib-compressed (CWS), and LZMA-compressed (ZWS), each followed by a version
// byte. We match the 3-byte prefix.
var swfMagics = [][]byte{
	[]byte("FWS"),
	[]byte("CWS"),
	[]byte("ZWS"),
}

// fromOLEIndicators scans the OLE2 directory for an ObjectPool storage and for
// streams whose head carries SWF magic, emitting an OLEID-OBJECTPOOL and/or
// OLEID-FLASH marker. Fail-open, bounded, deadline-aware.
func fromOLEIndicators(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || len(ole.Directory) == 0 || expired(deadline) {
		return
	}

	objectPoolSeen := false
	flashSeen := false

	for _, d := range ole.Directory {
		if objectPoolSeen && flashSeen {
			return // both found — nothing left to look for
		}
		if expired(deadline) || len(res.Streams) >= maxStreams {
			return
		}
		if d == nil {
			continue
		}

		// ObjectPool is a storage entry (Mse == 1) named "ObjectPool".
		if !objectPoolSeen && d.Header.Mse == 1 && d.Name == "ObjectPool" {
			objectPoolSeen = true
			res.Streams = append(res.Streams, []byte("OLEID-OBJECTPOOL"))
			continue
		}

		// Flash: a stream (Mse == 2) whose head matches SWF magic. GetStream
		// materialises the whole stream, so skip an oversized one — we only need
		// the first few bytes and won't pay to load a multi-GB blob for them.
		if !flashSeen && d.Header.Mse == 2 && d.Header.Size > 0 && d.Header.Size <= maxOLEIDFlashStream {
			head := ole.GetStreamPrefix(d.Index, maxOLEIDFlashScan)
			for _, m := range swfMagics {
				if bytes.HasPrefix(head, m) {
					flashSeen = true
					res.Streams = append(res.Streams, []byte("OLEID-FLASH"))
					break
				}
			}
		}
	}
}
