package extract

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"time"
)

// MSIX uses OPC ZIP packaging, which shares [Content_Types].xml with Office.
// Enrich the existing ZIP walkers without changing their payload classification.
// These are combined marker/value streams, not evidence of trust or malware.
// Schema: https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/schema-root
const (
	msixManifestName = "AppxManifest.xml"
	msixFoundationNS = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
	msixUAPNS        = "http://schemas.microsoft.com/appx/manifest/uap/windows10"
	maxMSIXBytes     = 1 << 20
	maxMSIXTokens    = 4096
	maxMSIXDepth     = 32
	maxMSIXAttrs     = 64
	maxMSIXFields    = 32
	maxMSIXValue     = 2048
	msixIdentityTag  = "MSIX-IDENTITY "
	msixAppTag       = "MSIX-APPLICATION "
	msixProtocolTag  = "MSIX-PROTOCOL "
)

// emitZipMember keeps the existing raw member/recursion accounting. Manifest
// metadata is derived only after that member was accepted against the budget.
func emitZipMember(name string, data []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	before := b.members
	emitMember(data, res, b, depth, deadline)
	if name == msixManifestName && b.members > before {
		res.Streams = append(res.Streams, msixManifestFields(data, maxStreams-len(res.Streams), deadline)...)
	}
}

type msixFrame struct {
	name     xml.Name
	protocol bool
}

// msixManifestFields checks namespaces and selected element paths, not the full
// XSD, package signature or executable existence. Identity values are unverified
// declarations. Malformed XML and input/token/depth/deadline overruns publish no
// fields; field/value caps limit output. The XML decoder never resolves external
// entities. Only UTF-8-compatible XML encodings are supported.
func msixManifestFields(data []byte, limit int, deadline time.Time) [][]byte {
	if len(data) > maxMSIXBytes || limit <= 0 || expired(deadline) {
		return nil
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(data) == 0 || data[0] != '<' {
		return nil
	}
	if limit > maxMSIXFields {
		limit = maxMSIXFields
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	var fields [][]byte
	var path []msixFrame
	rootSeen, identitySeen := false, false
	for n := 0; !expired(deadline); n++ {
		tok, err := d.Token()
		if err == io.EOF {
			if !expired(deadline) && rootSeen && identitySeen && len(path) == 0 {
				return fields
			}
			return nil
		}
		if err != nil || n >= maxMSIXTokens {
			return nil
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			if len(path) >= maxMSIXDepth || !msixAttrsUnique(tok.Attr) {
				return nil
			}
			if len(path) == 0 {
				if rootSeen || tok.Name != (xml.Name{Space: msixFoundationNS, Local: "Package"}) {
					return nil
				}
				rootSeen = true
			}
			path = append(path, msixFrame{name: tok.Name})
			switch len(path) {
			case 2:
				if tok.Name == (xml.Name{Space: msixFoundationNS, Local: "Identity"}) {
					if identitySeen || msixAttr(tok, "Name") == "" || msixAttr(tok, "Publisher") == "" || msixAttr(tok, "Version") == "" {
						return nil
					}
					identitySeen = true
					fields = appendMSIXAttrs(fields, limit, msixIdentityTag, tok, "Name", "Publisher", "Version", "ProcessorArchitecture", "ResourceId")
				}
			case 3:
				if msixApplicationPath(path) {
					fields = appendMSIXAttrs(fields, limit, msixAppTag, tok, "Id", "Executable", "EntryPoint", "StartPage")
				}
			case 5:
				if msixApplicationPath(path[:3]) && path[3].name == (xml.Name{Space: msixFoundationNS, Local: "Extensions"}) && tok.Name == (xml.Name{Space: msixUAPNS, Local: "Extension"}) {
					path[4].protocol = msixAttr(tok, "Category") == "windows.protocol"
				}
			case 6:
				if path[4].protocol && tok.Name == (xml.Name{Space: msixUAPNS, Local: "Protocol"}) {
					fields = appendMSIXAttrs(fields, limit, msixProtocolTag, tok, "Name")
				}
			}
		case xml.CharData:
			if len(path) == 0 && len(bytes.TrimSpace(tok)) != 0 {
				return nil
			}
		case xml.EndElement:
			if len(path) == 0 {
				return nil
			}
			path = path[:len(path)-1]
		}
	}
	return nil
}

func msixApplicationPath(path []msixFrame) bool {
	return len(path) == 3 && path[1].name == (xml.Name{Space: msixFoundationNS, Local: "Applications"}) &&
		path[2].name == (xml.Name{Space: msixFoundationNS, Local: "Application"})
}

// encoding/xml does not enforce unique attributes; reject ambiguous declarations
// rather than selecting whichever duplicate happened to occur first.
func msixAttrsUnique(attrs []xml.Attr) bool {
	if len(attrs) > maxMSIXAttrs {
		return false
	}
	seen := make(map[xml.Name]bool, len(attrs))
	for _, attr := range attrs {
		if seen[attr.Name] {
			return false
		}
		seen[attr.Name] = true
	}
	return true
}

func msixAttr(element xml.StartElement, name string) string {
	for _, attr := range element.Attr {
		if attr.Name.Space == "" && attr.Name.Local == name {
			return strings.TrimSpace(attr.Value)
		}
	}
	return ""
}

// Fixed field order makes attribute reordering immaterial to emitted metadata.
func appendMSIXAttrs(fields [][]byte, limit int, marker string, element xml.StartElement, names ...string) [][]byte {
	for _, name := range names {
		if len(fields) >= limit {
			break
		}
		value := msixAttr(element, name)
		if value == "" {
			continue
		}
		if len(value) > maxMSIXValue {
			value = value[:maxMSIXValue]
		}
		fields = append(fields, []byte(marker+strings.ToLower(name)+"="+value))
	}
	return fields
}
