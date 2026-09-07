package extract

// Windows launcher fields are recognised by content and emitted as combined
// marker/value streams. Format presence never scores; values are neither
// executed nor fetched. Byte, record, depth, field and deadline limits bound
// extraction independently of the caller's input cap.

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// maxLauncherLines caps INI records scanned per .url file.
	maxLauncherLines = 4096
	// maxLauncherLineLen caps a single INI record length (bytes) inspected.
	maxLauncherLineLen = 8 << 10
	// maxLauncherFields bounds how many launcher markers we emit per file.
	maxLauncherFields = 32
	// maxLauncherValue caps one emitted field value length.
	maxLauncherValue  = 4 << 10
	maxLauncherBytes  = 1 << 20
	maxLauncherTokens = 4096
	maxLauncherDepth  = 64
)

// Marker tags. Each is a yarad literal followed by attacker-supplied field
// content, so these are COMBINED markers (markers.go) and stay in Streams.
const (
	urlShortcutMarker  = "URL-SHORTCUT "
	settingsDeepMarker = "SETTINGCONTENT-DEEPLINK "
	settingsIconMarker = "SETTINGCONTENT-ICON "
)

// urlShortcutKeys selects target and invocation metadata for content scanning.
// Keys are compared case-insensitively; numeric and IDList values remain text.
var urlShortcutKeys = []string{
	"url",
	"iconfile",
	"workingdirectory",
	"showcommand",
	"hotkey",
	"idlist",
}

// isURLShortcut reports whether buf is a Windows Internet Shortcut. The
// recogniser is the format's mandatory section header, "[InternetShortcut]",
// which must appear at the start of a line within the leading bytes. Matching a
// section header (rather than a bare "URL=" key) keeps ordinary INI/config text
// from being misclassified. Filename plays no part.
func isURLShortcut(buf []byte) bool {
	return launcherHeadHasLine(buf, "[internetshortcut]")
}

// fromLauncherFields adds bounded field streams at both top-level and nested
// text entry points. It never displaces the existing script/text extractors.
func fromLauncherFields(buf []byte, res *Result, deadline time.Time) {
	if expired(deadline) || len(res.Streams) >= maxStreams {
		return
	}
	buf = launcherText(buf, deadline)
	if isSettingContent(buf) {
		fromSettingContent(buf, res, deadline)
	} else if isURLShortcut(buf) {
		fromURLShortcut(buf, res, deadline)
	}
}

// launcherText normalizes only BOM-signalled UTF-16. Invalid units, odd input,
// either byte cap or the deadline discard enrichment, not generic text recovery.
// UTF-8 input retains the existing recognizer and extraction limits.
func launcherText(buf []byte, deadline time.Time) []byte {
	if !bytes.HasPrefix(buf, utf16LEBOM) && !bytes.HasPrefix(buf, utf16BEBOM) {
		return buf
	}
	if len(buf) > maxLauncherBytes || len(buf)%2 != 0 || expired(deadline) {
		return nil
	}
	order := binary.ByteOrder(binary.LittleEndian)
	charset := "utf-16le"
	if buf[0] == 0xfe {
		order, charset = binary.BigEndian, "utf-16be"
	}
	out := make([]byte, 0, len(buf))
	for i := 2; i < len(buf); i += 2 {
		if expired(deadline) {
			return nil
		}
		u := order.Uint16(buf[i:])
		r := rune(u)
		if u >= 0xd800 && u <= 0xdbff {
			if i+3 >= len(buf) {
				return nil
			}
			v := order.Uint16(buf[i+2:])
			if v < 0xdc00 || v > 0xdfff {
				return nil
			}
			r = utf16.DecodeRune(r, rune(v))
			i += 2
		} else if u >= 0xdc00 && u <= 0xdfff {
			return nil
		}
		if len(out)+utf8.RuneLen(r) > maxLauncherBytes {
			return nil
		}
		out = utf8.AppendRune(out, r)
	}
	return launcherXMLDeclaration(out, charset)
}

var launcherEncoding = regexp.MustCompile(`(?:^|[\t\r\n ])encoding[\t\r\n ]*=[\t\r\n ]*(?:"([^"]*)"|'([^']*)')`)

// Keep the XML declaration intact except for its encoding value: the ordinary
// XML decoder receives the normalized input. An encoding label must agree with
// the observed BOM. No declaration, or one without an encoding, needs rewriting.
func launcherXMLDeclaration(buf []byte, charset string) []byte {
	if !bytes.HasPrefix(buf, []byte("<?xml")) || len(buf) > 5 && !bytes.ContainsAny(buf[5:6], " \t\r\n") {
		return buf
	}
	head := buf
	if len(head) > maxLauncherLineLen {
		head = head[:maxLauncherLineLen]
	}
	end := bytes.Index(head, []byte("?>"))
	if end < 0 {
		return nil
	}
	matches := launcherEncoding.FindAllSubmatchIndex(head[:end], 2)
	if len(matches) == 0 {
		return buf
	}
	if len(matches) != 1 {
		return nil
	}
	m := matches[0]
	start, stop := m[2], m[3]
	if start < 0 {
		start, stop = m[4], m[5]
	}
	label := string(buf[start:stop])
	if !strings.EqualFold(label, "utf-16") && !strings.EqualFold(label, charset) {
		return nil
	}
	// All accepted source labels are longer than UTF-8, so replacement shrinks.
	out := append(buf[:start], []byte("utf-8")...)
	return append(out, buf[stop:]...)
}

// launcherHeadHasLine reports whether want (lowercase) appears as a trimmed,
// case-insensitively equal line within the bounded launcher input.
func launcherHeadHasLine(buf []byte, want string) bool {
	head := bytes.TrimPrefix(buf, utf8BOM)
	if len(head) > maxLauncherBytes {
		head = head[:maxLauncherBytes]
	}
	rest := head
	for len(rest) > 0 {
		var raw []byte
		raw, rest, _ = bytes.Cut(rest, []byte("\n"))
		if len(raw) > maxLauncherLineLen {
			continue
		}
		if bytes.EqualFold(bytes.TrimSpace(raw), []byte(want)) {
			return true
		}
	}
	return false
}

// isSettingContent reports whether buf is a Windows settings shortcut
// (.settingcontent-ms). The recogniser is the format's document element,
// <PCSettingsFile>, together with a <DeepLink> or <Icon> element — the pair that makes the
// file a launcher rather than arbitrary XML. Content only; filename plays no
// part.
func isSettingContent(buf []byte) bool {
	head := bytes.TrimPrefix(buf, utf8BOM)
	if len(head) > maxLauncherBytes {
		head = head[:maxLauncherBytes]
	}
	head = bytes.TrimSpace(head)
	if len(head) == 0 || head[0] != '<' {
		return false
	}
	d := xml.NewDecoder(bytes.NewReader(head))
	root := false
	for n := 0; n < maxLauncherTokens; n++ {
		tok, err := d.Token()
		if err != nil {
			return false
		}
		if text, ok := tok.(xml.CharData); ok && !root && len(bytes.TrimSpace(text)) != 0 {
			return false
		}
		if start, ok := tok.(xml.StartElement); ok {
			if !root {
				if start.Name.Local != "PCSettingsFile" {
					return false
				}
				root = true
			} else if start.Name.Local == "DeepLink" || start.Name.Local == "Icon" {
				return true
			}
		}
	}
	return false
}

// fromURLShortcut extracts the [InternetShortcut] launcher fields of a Windows
// Internet Shortcut and emits each as a "URL-SHORTCUT <key>=<value>" marker.
// Scoring is left entirely to the content rules that
// match the emitted value — the presence of the format is not itself a verdict.
// Fail-open; bounded; respects deadline.
func fromURLShortcut(buf []byte, res *Result, deadline time.Time) {
	if expired(deadline) {
		return
	}
	rest := bytes.TrimPrefix(buf, utf8BOM)
	if len(rest) > maxLauncherBytes {
		rest = rest[:maxLauncherBytes]
	}
	lines, emitted := 0, 0
	inSection := false
	for len(rest) > 0 {
		if lines >= maxLauncherLines || emitted >= maxLauncherFields ||
			len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		lines++
		var raw []byte
		raw, rest, _ = bytes.Cut(rest, []byte("\n"))
		if len(raw) > maxLauncherLineLen {
			raw = raw[:maxLauncherLineLen]
		}
		line := strings.TrimSpace(string(bytes.TrimRight(raw, "\r")))
		if line == "" || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			inSection = strings.EqualFold(line, "[InternetShortcut]")
			continue
		}
		if !inSection {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue // malformed / truncated record
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if val == "" || !launcherKeyWanted(key) {
			continue
		}
		if len(val) > maxLauncherValue {
			val = val[:maxLauncherValue]
		}
		res.Streams = append(res.Streams, []byte(urlShortcutMarker+key+"="+val))
		emitted++
	}
}

// launcherKeyWanted reports whether an InternetShortcut metadata key is selected.
func launcherKeyWanted(key string) bool {
	for _, k := range urlShortcutKeys {
		if key == k {
			return true
		}
	}
	return false
}

// fromSettingContent extracts bounded DeepLink/Icon text with the standard XML
// decoder (entities and CDATA included; no external entity resolution). Only
// observed parse errors discard fields; budget stops retain fields that already
// closed cleanly. Nested field markup is skipped.
func fromSettingContent(buf []byte, res *Result, deadline time.Time) {
	if expired(deadline) || len(buf) > maxLauncherBytes {
		return
	}
	d := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(buf, utf8BOM)))
	var fields [][]byte
	var value strings.Builder
	depth, fieldDepth := 0, 0
	rootSeen, nested := false, false
	marker := ""
	publishFields := func() {
		res.Streams = append(res.Streams, fields...)
	}
	for tokens := 0; tokens < maxLauncherTokens; tokens++ {
		if expired(deadline) {
			publishFields()
			return
		}
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			if rootSeen && depth == 0 {
				publishFields()
			}
			return
		}
		if err != nil {
			return
		} // Do not publish fields from malformed XML.
		switch tok := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > maxLauncherDepth {
				publishFields()
				return
			}
			if depth == 1 {
				if rootSeen || tok.Name.Local != "PCSettingsFile" {
					return
				}
				rootSeen = true
			}
			if fieldDepth != 0 {
				nested = true
				continue
			}
			if len(fields) >= maxLauncherFields || len(res.Streams)+len(fields) >= maxStreams {
				continue
			}
			switch tok.Name.Local {
			case "DeepLink":
				marker = settingsDeepMarker
			case "Icon":
				marker = settingsIconMarker
			default:
				continue
			}
			fieldDepth, nested = depth, false
			value.Reset()
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(tok)) != 0 {
				return
			}
			if fieldDepth != 0 {
				remaining := maxLauncherValue - value.Len()
				if len(tok) > remaining {
					tok = tok[:remaining]
				}
				value.Write(tok)
			}
		case xml.EndElement:
			if depth == fieldDepth {
				if val := strings.TrimSpace(value.String()); !nested && val != "" {
					fields = append(fields, []byte(marker+val))
				}
				fieldDepth = 0
			}
			depth--
		}
	}
	publishFields()
}
