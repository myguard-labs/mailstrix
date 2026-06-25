package extract

// UserForm / VBFrame string extraction.
//
// Attackers hide payload strings (URLs, commands, paths) in VBA UserForm
// control properties — Caption, Tag, Text, ControlTipText — that are stored
// in the OLE2 project as binary "f"/"o" stream pairs and a "\x03VBFrame"
// property bag stream, NOT in the VBA macro source text. Static source
// scanners (olevba, VBA-keyword rules) are blind to these values.
//
// This extractor walks all OLE2 directory entries, finds streams associated
// with UserForm data (names containing byte 0x03, or named "f" / "o" inside
// form-like parent storages), and carves printable strings from them:
//
//   - "o" streams (binary OLE form control serialisation): walk bytes and
//     collect runs of printable ASCII >= minPrintRun bytes.
//   - "f" streams (text-mode property bags, key=value lines): extract the
//     value after the first "=" on each line.
//
// Each carved string is emitted as a separate stream. A synthetic
// "USERFORM-STRINGS" marker is emitted first so a YARA rule can key on it.
// Fail-open: any parse error is silently ignored.

import (
	"bytes"
	"strings"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// minPrintRun is the minimum length of a printable-ASCII run (in bytes) we
// consider worth emitting. Shorter runs produce too much noise (field headers,
// padding bytes that happen to be printable). 8 is the same threshold used by
// most string-carvers for payload hunting.
const minPrintRun = 8

// maxUserFormStreams caps how many carved string streams we emit per document
// from UserForm data. Form controls are small; this guards a crafted file with
// thousands of tiny forms from flooding Streams.
const maxUserFormStreams = 128

// maxCarveInput bounds the per-stream bytes scanned by carveStrings /
// extractFStreamValues. An OLE2 form or doc-property stream can be arbitrarily
// large (GetStream returns the whole stream), so without this a single crafted
// stream forces a full-length printable-run walk and per-line Split alloc. A
// real UserForm/property stream is tiny; the prefix keeps the common case
// identical. Mirrors maxFoldInput / maxReverseInput.
const maxCarveInput = 1 << 20

// isPrintable reports whether b is a printable ASCII byte (0x20–0x7E).
func isPrintable(b byte) bool {
	return b >= 0x20 && b <= 0x7E
}

// carveStrings walks src and returns all runs of printable ASCII bytes of
// length >= minPrintRun. Each run is returned as a separate []byte.
func carveStrings(src []byte) [][]byte {
	if len(src) > maxCarveInput {
		src = src[:maxCarveInput]
	}
	var out [][]byte
	start := -1
	for i, b := range src {
		if isPrintable(b) {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= minPrintRun {
				run := make([]byte, i-start)
				copy(run, src[start:i])
				out = append(out, run)
			}
			start = -1
		}
	}
	// flush trailing run
	if start >= 0 && len(src)-start >= minPrintRun {
		run := make([]byte, len(src)-start)
		copy(run, src[start:])
		out = append(out, run)
	}
	// Also carve UTF-16 runs: an OLE UserForm caption/tag or an OLE SummaryInfo
	// VT_LPWSTR property is stored wide (UTF-16LE), so the ASCII walk above sees
	// each char as a length-1 run separated by NULs and recovers nothing — a real
	// miss for wide captions/URLs. carveWideStrings strips the NUL bytes from wide
	// runs and appends the ASCII text so the same keyword/URL rules fire.
	out = append(out, carveWideStrings(src)...)
	return out
}

// carveWideStrings returns the ASCII text of every UTF-16 run (LE or BE) of at
// least minPrintRun characters in src, with the NUL bytes stripped. It looks for
// sequences of (printable, 0x00) pairs (UTF-16LE) or (0x00, printable) pairs
// (UTF-16BE). Only ASCII-range characters are recovered, which is all the
// keyword/URL rules need; non-ASCII wide chars terminate a run. Bounded by
// maxCarveInput like carveStrings.
func carveWideStrings(src []byte) [][]byte {
	if len(src) > maxCarveInput {
		src = src[:maxCarveInput]
	}
	carve := func(hiNulOdd bool) [][]byte {
		// hiNulOdd=true → UTF-16LE: char byte at even offset, 0x00 at odd.
		var out [][]byte
		var run []byte
		flush := func() {
			if len(run) >= minPrintRun {
				cp := make([]byte, len(run))
				copy(cp, run)
				out = append(out, cp)
			}
			run = run[:0]
		}
		for i := 0; i+1 < len(src); i += 2 {
			var ch, nul byte
			if hiNulOdd {
				ch, nul = src[i], src[i+1]
			} else {
				nul, ch = src[i], src[i+1]
			}
			if nul == 0x00 && isPrintable(ch) {
				run = append(run, ch)
			} else {
				flush()
			}
		}
		flush()
		return out
	}
	out := carve(true)                 // UTF-16LE
	out = append(out, carve(false)...) // UTF-16BE
	return out
}

// extractFStreamValues parses a text-mode VBFrame/f-stream property bag
// (key=value lines) and returns the value portion after the first "=" on each
// non-empty line. Only values of length >= minPrintRun are returned.
func extractFStreamValues(src []byte) [][]byte {
	if len(src) > maxCarveInput {
		src = src[:maxCarveInput]
	}
	var out [][]byte
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= minPrintRun {
			out = append(out, []byte(val))
		}
	}
	return out
}

// isFormStreamName reports whether the OLE2 directory entry name looks like a
// UserForm data stream. We match:
//   - Any name containing byte 0x03 (VBFrame property stream naming convention)
//   - Exactly "f" or "o" (binary form layout / control data streams that live
//     inside a form storage directory)
func isFormStreamName(name string) bool {
	if name == "f" || name == "o" {
		return true
	}
	return strings.ContainsRune(name, 0x03)
}

// fromUserForms walks all OLE2 directory entries looking for UserForm data
// streams ("o", "f", streams with byte 0x03 in their name). It carves
// printable strings from "o" streams and extracts key=value pairs from "f"
// and 0x03-named streams, emitting each as a separate stream for YARA
// matching. A synthetic "USERFORM-STRINGS" marker is emitted first.
//
// Fail-open: any per-stream error is silently ignored. Respects deadline and
// maxStreams / maxUserFormStreams caps.
func fromUserForms(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if expired(deadline) {
		return
	}
	if ole == nil || len(ole.Directory) == 0 {
		return
	}

	var carved [][]byte
	emitted := 0

	for _, d := range ole.Directory {
		if expired(deadline) {
			break
		}
		if d == nil {
			continue
		}
		// Only process stream entries (Mse == 2) with content.
		if d.Header.Mse != 2 || d.Header.Size == 0 {
			continue
		}
		if !isFormStreamName(d.Name) {
			continue
		}
		if emitted >= maxUserFormStreams || len(res.Streams)+len(carved) >= maxStreams {
			break
		}

		data := ole.GetStream(d.Index)
		if len(data) == 0 {
			continue
		}

		var strs [][]byte
		// "o" streams are binary OLE form control serialisation — carve raw printable runs.
		// "f" streams and 0x03-named streams are text-mode property bags — extract values.
		if d.Name == "o" {
			strs = carveStrings(data)
		} else {
			// "f" and \x03VBFrame-style streams: try property-bag parsing first;
			// fall back to raw carving for any non-text content.
			strs = extractFStreamValues(data)
			if len(strs) == 0 {
				strs = carveStrings(data)
			}
		}

		for _, s := range strs {
			if emitted >= maxUserFormStreams || len(res.Streams)+len(carved) >= maxStreams {
				break
			}
			carved = append(carved, s)
			emitted++
		}
	}

	if len(carved) == 0 {
		return
	}

	// Emit each carved string individually so generic content rules see them
	// (URL/keyword rules etc.). Then emit ONE combined "USERFORM-STRINGS\n<carved>"
	// buffer — splitPureMarkers routes it to the Markers channel, where the
	// marker-tagged Maldoc_UserForm_Payload rule needs the marker AND a carved IOC
	// co-located (Phase 2b; previously dead — separate entries never matched).
	for _, s := range carved {
		if len(res.Streams) >= maxStreams {
			break
		}
		res.Streams = append(res.Streams, s)
	}
	if len(res.Streams) < maxStreams {
		res.Streams = append(res.Streams, joinMarkerPayload(userFormMarker, carved))
	}
}

// userFormMarker is the synthetic marker emitted as the first stream when
// UserForm strings are found. Used in tests.
const userFormMarker = "USERFORM-STRINGS"

// hasUserFormMarker reports whether any stream carries the UserForm marker —
// either the bare literal or the combined "USERFORM-STRINGS\n<carved>" buffer
// (Phase 2b), so it matches on a HasPrefix.
func hasUserFormMarker(streams [][]byte) bool {
	for _, s := range streams {
		if bytes.HasPrefix(s, []byte(userFormMarker)) {
			return true
		}
	}
	return false
}
