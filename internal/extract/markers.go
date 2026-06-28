package extract

import "bytes"

// PLAN-marker-channel Phase 1: yarad emits two kinds of synthetic entries into
// Result.Streams — PURE markers (a fixed yarad literal, no attacker bytes) and
// COMBINED markers (a marker tag concatenated with a real attacker IOC). Only
// PURE markers are safe to route to the out-of-band Markers channel; COMBINED
// ones carry attacker data a content rule keys on, so they stay in Streams until
// the Phase 2 per-rule split. Real extracted content (macro source, carved
// strings, decoded blobs) is never a marker.

// pureMarkerLiterals is the exact set of yarad PURE marker strings. Each is an
// emitted-as-is constant with no variable data. Keep in sync with the emit
// sites (encsig.go, oleid.go, userform.go, docprops.go, ppt.go, rtf.go,
// xlm.go, defaultpw.go).
var pureMarkerLiterals = map[string]struct{}{
	"USERFORM-STRINGS":        {}, // userform.go
	"DOCPROPS-STRINGS":        {}, // docprops.go
	"OLEID-OBJECTPOOL":        {}, // oleid.go
	"OLEID-FLASH":             {}, // oleid.go
	"OLEID-VBA-PRESENT":       {}, // extract.go appendOLEIDMarker
	"OLEID-EXTREL":            {}, // extract.go appendOLEIDMarker
	"OLEID-DDE":               {}, // extract.go appendOLEIDMarker
	"OLEID-XLM-PRESENT":       {}, // extract.go appendOLEIDMarker
	"PPT-VBA-EXTRACTED":       {}, // ppt.go
	"RTF-OBJUPDATE":           {}, // rtf.go
	"DEFAULTPW-DECRYPTED":     {}, // defaultpw.go
	"DIGITAL-SIGNATURE":       {}, // encsig.go
	"ENCRYPTION-AES":          {}, // encsig.go
	"ENCRYPTION-RC4":          {}, // encsig.go
	"ENCRYPTION-XOR":          {}, // encsig.go
	"XLM-AUTO-OPEN":           {}, // xlm.go
	"XLM-AUTO-CLOSE":          {}, // xlm.go
	"HTML-SMUGGLING-BLOB":     {}, // html.go
	"HTML-SMUGGLING-DATAURI":  {}, // html.go
	"HTML-DATAURI-CONTAINER":  {}, // html.go
	"SVG-SCRIPT":              {}, // html.go
	"SVG-EMBEDDED-PAYLOAD":    {}, // html.go
	"ARCHIVE-ENCRYPTED":       {}, // archive.go
	"POLYGLOT-PE-ZIP":         {}, // polyglot.go
	"XLL-ADDIN":               {}, // xll.go
	"BASE64-PE-CARVE":         {}, // pecarve.go
	"PE-SECTION-PACKED":       {}, // binanalyze.go
	"PE-SECTION-HIGH-ENTROPY": {}, // binanalyze.go
	"PE-OVERLAY":              {}, // binanalyze.go
	"PE-VIRTUAL-SECTION":      {}, // binanalyze.go
	"PE-DOTNET":               {}, // binanalyze.go
	"PE-ANOMALY":              {}, // binanalyze.go
	"ELF-EXECUTABLE":          {}, // binanalyze.go
}

// msdDeepDecodePrefix is the PURE marker emitted by the static-decode pass; the
// trailing "depth=N" is a yarad-derived integer, not attacker bytes.
const msdDeepDecodePrefix = "MSD-DEEPDECODE depth="

// pureMarkerPrefixes are PURE markers of the form <yarad-literal><yarad-number>
// or <yarad-literal>\n<carved payload> (the DocProps/UserForm combined buffer —
// the literal is yarad-synthetic; the carved tail is real content the consuming
// marker-tagged rule needs co-located, see joinMarkerPayload + Phase 2b).
var pureMarkerPrefixes = []string{
	msdDeepDecodePrefix,   // decode.go
	oleDocSecMarkerPrefix, // docprops.go ("OLE-DOC-SECURITY-")
	oleMetaTag + "\n",     // docprops.go OLE-META combined buffer
	docPropsMarker + "\n", // docprops.go combined buffer
	userFormMarker + "\n", // userform.go combined buffer
	xlmStackerPrefix,      // joinXLMStackerMarkers combined buffer
	behaviorScorePrefix,   // joinBehaviorScore combined buffer
}

// xlmStackerPrefix tags the document-level combined XLM-marker buffer built by
// joinXLMStackerMarkers. It is a yarad-synthetic literal, so the buffer routes
// to the out-of-band Markers channel like the other PURE markers.
const xlmStackerPrefix = "XLM-STACK\n"

// xlmStackerMarkerPrefixes are the XLM marker entries the multi-marker stacker
// rules (XLM_AutoOpen_Dropper, XLM_Hidden_Dangerous_Dropper,
// XLM_Emulator_Deep_Exec) must see CO-LOCATED to fire. yarad emits each as a
// separate Streams entry (each scanned independently), so the `(open|close) and
// (hidden|danger)` style conjunctions were structurally dead — same cross-entry
// root cause as the DocProps/UserForm case fixed in Phase 2b. joinXLMStackerMarkers
// collects every present XLM marker into one document-level buffer so the
// (: marker)-tagged stacker rules can satisfy their conjunction on the Markers
// channel. The individual marker entries are LEFT in Streams untouched, so the
// self-contained rules (XLM_Hidden_Macrosheet, XLM_Dangerous_Function) keep
// firing there with no detection change.
var xlmStackerMarkerPrefixes = []string{
	"XLM-AUTO-OPEN",
	"XLM-AUTO-CLOSE",
	"XLM-HIDDEN-MACROSHEET ",
	"XLM-DANGEROUS-FUNC ",
	"XLM-EMUL-DEPTH ",
}

// joinXLMStackerMarkers scans streams for XLM marker entries and, when at least
// two distinct stacker markers are present, returns ONE combined buffer
// "XLM-STACK\n<marker>\n<marker>..." for the Markers channel. Returns nil when
// fewer than two are found (a single marker can never satisfy a stacker rule's
// conjunction, so no buffer is needed). The source entries are copied, not
// moved — they stay in Streams for the self-contained marker rules.
func joinXLMStackerMarkers(streams [][]byte) []byte {
	var collected [][]byte
	for _, s := range streams {
		for _, p := range xlmStackerMarkerPrefixes {
			if bytes.HasPrefix(s, []byte(p)) {
				collected = append(collected, s)
				break
			}
		}
	}
	if len(collected) < 2 {
		return nil
	}
	n := len(xlmStackerPrefix)
	for _, c := range collected {
		n += len(c) + 1
	}
	b := make([]byte, 0, n)
	b = append(b, xlmStackerPrefix...)
	for _, c := range collected {
		b = append(b, c...)
		b = append(b, '\n')
	}
	return b
}

// joinMarkerPayload builds a single buffer "<marker>\n<carved...>" so a YARA
// rule that needs the marker AND a carved IOC co-located in one buffer (e.g.
// Maldoc_DocProps_Payload: `$marker and any of ($url,...)`) can match. yarad
// emits the marker and carved strings as separate Streams entries (each scanned
// independently), so such conjunctions were structurally dead until Phase 2b.
// The buffer is prefixed by the marker literal so splitPureMarkers routes it to
// the out-of-band Markers channel, where the (: marker)-tagged rule fires.
func joinMarkerPayload(marker string, carved [][]byte) []byte {
	n := len(marker)
	for _, c := range carved {
		n += 1 + len(c)
	}
	b := make([]byte, 0, n)
	b = append(b, marker...)
	for _, c := range carved {
		b = append(b, '\n')
		b = append(b, c...)
	}
	return b
}

// behaviorScorePrefix tags the document-level "weight of evidence" buffer built
// by joinBehaviorScore. It is a Mailstrix-synthetic literal, so the buffer routes
// to the out-of-band Markers channel like the other PURE markers. The trailing
// "n=N" count is a Mailstrix-derived integer, not attacker bytes.
const behaviorScorePrefix = "MALDOC-BEHAVIOR-SCORE n="

// behaviorWeakMarkers are the LOW-confidence structural "stacking" indicators
// (each scored <=25 on its own, presence-only — see oleid_indicators.yara). Any
// single one is benign noise; olevba's "weight of evidence" model treats a
// CO-OCCURRENCE of several independent weak markers as suspicious even when no
// single rule fires. joinBehaviorScore emits an aggregate marker when at least
// behaviorScoreMin DISTINCT classes are present in one document, so a novel
// maldoc that trips several weak markers with no strong rule still gets scored.
//
// Each entry is matched as a prefix so the value-carrying ones (OLE-DOC-SECURITY-,
// OLETIMES-*) collapse to their class. Strong/exploit markers (OLE2LINK-URL,
// PPT-VBA-EXTRACTED, ENCRYPTION-XOR, the XLM stacker set) are deliberately NOT
// here — they already fire a high-score rule, so counting them would double-count
// and is unnecessary for the weak-evidence tier.
var behaviorWeakMarkers = []string{
	"OLEID-OBJECTPOOL",
	"OLEID-FLASH",
	"OLEID-VBA-PRESENT",
	"OLEID-EXTREL",
	"OLEID-DDE",
	"OLEID-XLM-PRESENT",
	"DIGITAL-SIGNATURE",
	"ENCRYPTION-RC4",
	"ENCRYPTION-AES",
	"DEFAULTPW-DECRYPTED",
	"OLE-DOC-SECURITY-",
	"OLETIMES-FUTURE ",
	"OLETIMES-SYNTHETIC ",
	"OLE2-EXTRA-DATA",
	"USERFORM-STRINGS",
	"DOCPROPS-STRINGS",
}

// behaviorScoreMin is the minimum number of DISTINCT weak-marker classes that
// must co-occur in one document before joinBehaviorScore emits the aggregate
// marker. Chosen at 3: the parity corpus (761 real malware samples) surfaced no
// benign document tripping three independent structural indicators at once, so
// this is a low-FP "novel maldoc" backstop, not a tuned detector.
const behaviorScoreMin = 3

// joinBehaviorScore counts how many DISTINCT behaviorWeakMarkers classes appear
// across streams and, when at least behaviorScoreMin are present, returns ONE
// aggregate buffer "MALDOC-BEHAVIOR-SCORE n=<count>\n<class>\n<class>..." for the
// Markers channel. Returns nil below the threshold (no aggregate signal). The
// source entries are NOT moved — they stay in Streams for their own marker rules,
// so this only ADDS a stacking verdict, never removes one. Each class is counted
// at most once even if its marker appears in several streams.
func joinBehaviorScore(streams [][]byte) []byte {
	seen := make(map[string]struct{}, len(behaviorWeakMarkers))
	var present []string // preserve behaviorWeakMarkers order for deterministic output
	for _, p := range behaviorWeakMarkers {
		for _, s := range streams {
			if bytes.HasPrefix(s, []byte(p)) {
				if _, dup := seen[p]; !dup {
					seen[p] = struct{}{}
					present = append(present, p)
				}
				break
			}
		}
	}
	if len(present) < behaviorScoreMin {
		return nil
	}
	head := behaviorScorePrefix + smallItoa(len(present)) + "\n"
	n := len(head)
	for _, p := range present {
		n += len(p) + 1
	}
	b := make([]byte, 0, n)
	b = append(b, head...)
	for _, p := range present {
		b = append(b, p...)
		b = append(b, '\n')
	}
	return b
}

// smallItoa renders a small non-negative int without importing strconv into this
// hot-path file (counts here are bounded by len(behaviorWeakMarkers)).
func smallItoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// isPureMarker reports whether s is a yarad-emitted PURE marker entry.
func isPureMarker(s []byte) bool {
	if _, ok := pureMarkerLiterals[string(s)]; ok {
		return true
	}
	for _, p := range pureMarkerPrefixes {
		if bytes.HasPrefix(s, []byte(p)) {
			return true
		}
	}
	return false
}

// splitPureMarkers partitions streams into real content vs PURE markers,
// preserving order within each. decodeMoved counts how many moved entries were
// MSD-DEEPDECODE markers (those were tallied into Result.DecodedStreams), so the
// caller can keep that metric exact after the markers leave Streams. Phase 1:
// both slices are scanned against the full ruleset; the split is the
// prerequisite for the Phase 2 collision filter and Phase 3 compiled partition.
func splitPureMarkers(streams [][]byte) (content, markers [][]byte, decodeMoved int) {
	for _, s := range streams {
		if isPureMarker(s) {
			markers = append(markers, s)
			if bytes.HasPrefix(s, []byte(msdDeepDecodePrefix)) {
				decodeMoved++
			}
			continue
		}
		content = append(content, s)
	}
	return content, markers, decodeMoved
}
