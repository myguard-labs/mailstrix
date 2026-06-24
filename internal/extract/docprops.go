package extract

// Document-properties string extraction.
//
// Attackers hide C2 URLs, commands, and payload strings in document properties
// that VBA-only scanners never see:
//
//   - OOXML: docProps/core.xml, docProps/app.xml, docProps/custom.xml
//     (OPC core/application/custom properties), customXml/item*.xml (custom XML
//     parts), and word/settings.xml docVars (w:docVar elements whose w:val holds
//     attacker-controlled strings).
//
//   - OLE2: \x05SummaryInformation and \x05DocumentSummaryInformation streams
//     (binary property set streams, MS-OLEPS). The spec format is complex; we
//     just carve printable ASCII runs >= minPrintRun bytes, same approach as
//     userform.go -- sufficient for URL/command detection.
//
// Each non-empty string >= 8 bytes is emitted as a separate stream, preceded by
// a synthetic "DOCPROPS-STRINGS" marker so YARA rules can anchor on it.
// Fail-open: any parse error is silently ignored. Respects deadline and the
// shared maxStreams cap.

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// docpropsCap is the per-file read limit for OOXML property XML parts (zip-bomb
// guard; property files are tiny in practice, rarely > a few KiB).
const docpropsCap = 512 << 10 // 512 KiB

// maxDocPropsStreams caps how many carved strings we emit per document from
// document properties. Guards a crafted file that stuffs megabytes of text into
// custom properties.
const maxDocPropsStreams = 128

// ooxmlPropParts lists the OOXML zip entry names that carry document-property
// strings (OPC core/application properties and custom XML parts).
var ooxmlPropParts = []string{
	"docProps/core.xml",
	"docProps/app.xml",
	"docProps/custom.xml",
}

// fromOOXMLDocProps scans the already-opened OOXML zip for document-property
// parts (docProps/core.xml, docProps/app.xml, docProps/custom.xml,
// customXml/item*.xml) and word/settings.xml (docVars). For each XML file it
// walks the token stream and collects all CharData text nodes. For
// word/settings.xml it additionally extracts w:docVar/@w:val attribute values.
// Each collected string >= minPrintRun bytes is emitted as a separate stream,
// preceded by a "DOCPROPS-STRINGS" marker.
// Fail-open; respects deadline and maxStreams / maxDocPropsStreams caps.
// Uses the same *[][]byte convention as the other fromOOXML* helpers so it
// slots into the fromOOXML local-out accumulator without an extra allocation.
func fromOOXMLDocProps(zr *zip.Reader, out *[][]byte, deadline time.Time) {
	if expired(deadline) {
		return
	}

	var carved [][]byte

	// add appends s (trimmed) to carved if it meets the length threshold and caps.
	// Returns false when the cap is hit (caller should stop iterating).
	add := func(s string) bool {
		s = strings.TrimSpace(s)
		if len(s) < minPrintRun {
			return true
		}
		if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
			return false
		}
		carved = append(carved, []byte(s))
		return true
	}

	// Build a name-to-entry index for O(1) lookup.
	idx := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		idx[f.Name] = f
	}

	// extractXMLText walks an XML token stream and calls add for each CharData node.
	extractXMLText := func(raw []byte) {
		dec := xml.NewDecoder(bytes.NewReader(raw))
		dec.Strict = false
		for {
			if expired(deadline) {
				break
			}
			if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
				break
			}
			tok, err := dec.Token()
			if err != nil {
				break // EOF or malformed -- fail-open
			}
			if cd, ok := tok.(xml.CharData); ok {
				if !add(string(cd)) {
					break
				}
			}
		}
	}

	// readEntry reads a zip entry up to docpropsCap bytes; returns nil on error or
	// if the entry's uncompressed size exceeds the cap.
	readEntry := func(f *zip.File) []byte {
		if f.UncompressedSize64 > docpropsCap {
			return nil
		}
		rc, err := f.Open()
		if err != nil {
			return nil
		}
		raw, err := io.ReadAll(io.LimitReader(rc, docpropsCap))
		rc.Close() // #nosec G104 -- zip entry close; error is unrecoverable here
		if err != nil || len(raw) == 0 {
			return nil
		}
		return raw
	}

	// 1. Fixed property parts.
	for _, name := range ooxmlPropParts {
		if expired(deadline) {
			break
		}
		if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
			break
		}
		f, ok := idx[name]
		if !ok {
			continue
		}
		raw := readEntry(f)
		if raw == nil {
			continue
		}
		extractXMLText(raw)
	}

	// 2. customXml/item*.xml parts (dynamic names -- must walk the zip directory).
	for _, f := range zr.File {
		if expired(deadline) {
			break
		}
		if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
			break
		}
		name := f.Name
		if !strings.HasPrefix(name, "customXml/item") || !strings.HasSuffix(name, ".xml") {
			continue
		}
		raw := readEntry(f)
		if raw == nil {
			continue
		}
		extractXMLText(raw)
	}

	// 3. word/settings.xml -- docVar attribute values + general text nodes.
	if f, ok := idx["word/settings.xml"]; ok && !expired(deadline) {
		raw := readEntry(f)
		if raw != nil {
			// First pass: extract w:docVar/@w:val attribute values.
			dec := xml.NewDecoder(bytes.NewReader(raw))
			dec.Strict = false
		docVarLoop:
			for {
				if expired(deadline) {
					break
				}
				if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
					break
				}
				tok, err := dec.Token()
				if err != nil {
					break
				}
				se, ok := tok.(xml.StartElement)
				if !ok || se.Name.Local != "docVar" {
					continue
				}
				for _, attr := range se.Attr {
					if attr.Name.Local == "val" {
						if !add(attr.Value) {
							break docVarLoop
						}
					}
				}
			}
			// Second pass: general text nodes.
			extractXMLText(raw)
		}
	}

	if len(carved) == 0 {
		return
	}

	// Emit each carved string individually so generic content rules see them,
	// then ONE combined "DOCPROPS-STRINGS\n<carved>" buffer routed to the Markers
	// channel for the marker-tagged Maldoc_DocProps_Payload rule (Phase 2b).
	for _, s := range carved {
		if len(*out) >= maxStreams {
			break
		}
		*out = append(*out, s)
	}
	if len(*out) < maxStreams {
		*out = append(*out, joinMarkerPayload(docPropsMarker, carved))
	}
}

// oleDocPropsStreamNames lists the OLE2 stream names that carry binary
// property-set data (MS-OLEPS SummaryInformation / DocumentSummaryInformation).
var oleDocPropsStreamNames = []string{
	"\x05SummaryInformation",
	"\x05DocumentSummaryInformation",
}

// fromOLEDocProps looks for SummaryInformation and DocumentSummaryInformation
// streams in the already-parsed OLE2 file and carves printable ASCII runs
// >= minPrintRun bytes from their raw bytes. We use the same carveStrings
// approach as userform.go -- the full MS-OLEPS property-set parse is
// unnecessary for payload detection. Emits a "DOCPROPS-STRINGS" marker
// followed by each carved string.
// Fail-open; respects deadline and maxStreams / maxDocPropsStreams.
func fromOLEDocProps(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if expired(deadline) {
		return
	}
	if ole == nil || len(ole.Directory) == 0 {
		return
	}

	var carved [][]byte

	for _, name := range oleDocPropsStreamNames {
		if expired(deadline) {
			break
		}
		s := ole.FindStreamByName(name)
		if s == nil {
			continue
		}
		data := ole.GetStream(s.Index)
		if len(data) == 0 {
			continue
		}
		// Parse DOC_SECURITY (PIDSI 0x13) from SummaryInformation only.
		if name == "\x05SummaryInformation" {
			if v, ok := docSecurityFlags(data); ok {
				if len(res.Streams) < maxStreams {
					res.Streams = append(res.Streams, []byte(fmt.Sprintf("%s%d", oleDocSecMarkerPrefix, v)))
				}
			}
		}
		for _, run := range carveStrings(data) {
			if len(carved) >= maxDocPropsStreams || len(res.Streams)+len(carved) >= maxStreams {
				break
			}
			carved = append(carved, run)
		}
	}

	if len(carved) == 0 {
		return
	}

	// Emit each carved string individually (generic content rules), then ONE
	// combined "DOCPROPS-STRINGS\n<carved>" buffer routed to the Markers channel
	// for the marker-tagged Maldoc_DocProps_Payload rule (Phase 2b).
	res.HasDocProps = true
	for _, s := range carved {
		if len(res.Streams) >= maxStreams {
			break
		}
		res.Streams = append(res.Streams, s)
	}
	if len(res.Streams) < maxStreams {
		res.Streams = append(res.Streams, joinMarkerPayload(docPropsMarker, carved))
	}
}

// oleDocSecMarkerPrefix is the prefix for the DOC_SECURITY protection marker.
const oleDocSecMarkerPrefix = "OLE-DOC-SECURITY-"

// docSecurityFlags parses a raw SummaryInformation property-set stream
// (MS-OLEPS) and returns the DOC_SECURITY bitfield value (PIDSI 0x13) plus
// true when the parse succeeds and the value is non-zero. All reads are
// bounds-checked; any malformation returns (0, false) without panicking.
func docSecurityFlags(data []byte) (uint32, bool) {
	// Property set stream header: minimum 48 bytes
	// [0:2]   ByteOrder (must be 0xFFFE)
	// [24:28] cSections (number of property sets, >= 1)
	// [28:44] FMTID of first section (16 bytes)
	// [44:48] offset of first section (uint32)
	if len(data) < 48 {
		return 0, false
	}
	byteOrder := binary.LittleEndian.Uint16(data[0:2])
	if byteOrder != 0xFFFE {
		return 0, false
	}
	cSections := binary.LittleEndian.Uint32(data[24:28])
	if cSections < 1 {
		return 0, false
	}
	secOff := binary.LittleEndian.Uint32(data[44:48])
	// Section header: cbSection (4) + cProperties (4) = 8 bytes minimum.
	if uint64(secOff)+8 > uint64(len(data)) {
		return 0, false
	}
	cProperties := binary.LittleEndian.Uint32(data[secOff+4 : secOff+8])
	if cProperties == 0 {
		return 0, false
	}
	if cProperties > 1024 {
		cProperties = 1024
	}
	// Each identifier/offset entry is 8 bytes: propID (4) + propOffset (4).
	// They follow the section header at secOff+8.
	arrayStart := uint64(secOff) + 8
	arrayEnd := arrayStart + uint64(cProperties)*8
	if arrayEnd > uint64(len(data)) {
		return 0, false
	}
	var propOff uint32
	found := false
	for i := uint32(0); i < cProperties; i++ {
		base := arrayStart + uint64(i)*8
		propID := binary.LittleEndian.Uint32(data[base : base+4])
		if propID == 0x13 {
			propOff = binary.LittleEndian.Uint32(data[base+4 : base+8])
			found = true
			break
		}
	}
	if !found {
		return 0, false
	}
	// Property value at sectionOffset + propOffset.
	// Layout: type (uint32) + value (uint32/int32).
	valueBase := uint64(secOff) + uint64(propOff)
	if valueBase+8 > uint64(len(data)) {
		return 0, false
	}
	propType := binary.LittleEndian.Uint32(data[valueBase : valueBase+4])
	if propType != 3 { // VT_I4
		return 0, false
	}
	value := binary.LittleEndian.Uint32(data[valueBase+4 : valueBase+8])
	if value == 0 {
		return 0, false
	}
	return value, true
}

// docPropsMarker is the synthetic marker emitted as the first stream when
// document-property strings are found. Used in tests.
const docPropsMarker = "DOCPROPS-STRINGS"

// hasDocPropsMarker reports whether any stream carries the docprops marker —
// either the bare literal or the combined "DOCPROPS-STRINGS\n<carved>" buffer
// (Phase 2b), so it matches on a HasPrefix.
func hasDocPropsMarker(streams [][]byte) bool {
	for _, s := range streams {
		if bytes.HasPrefix(s, []byte(docPropsMarker)) {
			return true
		}
	}
	return false
}
