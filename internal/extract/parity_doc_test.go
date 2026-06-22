package extract

// PARITY-1 — extractor marker ↔ YARA-rule contract doc-check.
//
// Every synthetic marker the extractor emits into res.Streams is one of two
// kinds:
//
//   - CONTRACT: a structural/intent indicator (e.g. XLM-DANGEROUS-FUNC,
//     OLE2LINK-URL, the PDF-* / OLEID-* / *-DDE family). A CONTRACT marker is
//     only useful if a local YARA rule actually SCORES it — the carve happens
//     in Go, but nothing fires unless a rule references the marker prefix. A
//     CONTRACT marker with no rule is a silent detection gap.
//
//   - INTERNAL: a carved-PAYLOAD marker (DOCPROPS-STRINGS, USERFORM-STRINGS).
//     The marker line is a label prepended to extracted cleartext that the
//     EXISTING keyword/IOC rules then scan; it intentionally has no dedicated
//     scoring rule of its own.
//
// This test pins that contract two ways so it can't silently drift:
//
//  1. Every CONTRACT marker prefix is referenced by at least one rule in
//     docker/local-rules/*.yara (the carve is actually scored).
//  2. Every marker prefix emitted in internal/extract/*.go is accounted for in
//     the table below — a NEW marker added without a table entry fails the test,
//     forcing the author to classify it (and add a rule if CONTRACT).
//
// The table is the durable parity-matrix record (mirrors the §6 "yarad >=
// oletools" matrix in memory/.../PLAN-gap-closure.md). Keep it in sync when a
// marker lands or a rule is renamed.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// markerKind classifies a marker for the contract check.
type markerKind int

const (
	contractMarker markerKind = iota // must be scored by a local rule
	internalMarker                   // payload label; scanned by existing rules, no own rule
)

// parityMarkers is the canonical inventory of every marker prefix the extractor
// emits. Adding an emit site without adding a row here fails TestParityMarkerInventory.
var parityMarkers = map[string]markerKind{
	// --- structural / intent indicators (must have a scoring rule) ---
	"CSV-DDE":               contractMarker, // ooxml_dde.yara CSV_DDE_Command
	"SLK-DDE":               contractMarker, // ooxml_dde.yara SLK_DDE_Command
	"OOXML-DDE-FIELD":       contractMarker, // ooxml_dde.yara Maldoc_DDE_Field
	"OOXML-EXTERNAL-REL":    contractMarker, // ooxml_template_injection.yara
	"RTF-DDE-FIELD":         contractMarker, // rtf_tricks.yara RTF_DDE_Field
	"RTF-OBJUPDATE":         contractMarker, // rtf_tricks.yara RTF_ObjUpdate
	"XLM-DANGEROUS-FUNC":    contractMarker, // xlm_macrosheet.yara XLM_Dangerous_Function
	"XLM-HIDDEN-MACROSHEET": contractMarker, // xlm_macrosheet.yara
	"XLM-AUTO-OPEN":         contractMarker, // xlm_macrosheet.yara XLM_AutoOpen_Dropper
	"XLM-AUTO-CLOSE":        contractMarker, // xlm_macrosheet.yara XLM_AutoOpen_Dropper
	"OLEID-OBJECTPOOL":      contractMarker, // oleid_indicators.yara OLEID_ObjectPool
	"OLEID-FLASH":           contractMarker, // oleid_indicators.yara OLEID_Flash
	"OLE2LINK-URL":          contractMarker, // oleid_indicators.yara OLE2Link_URL_Moniker
	"OLETIMES-FUTURE":       contractMarker, // oleid_indicators.yara OLETimes_FutureStamp
	"OLETIMES-SYNTHETIC":    contractMarker, // oleid_indicators.yara OLETimes_SyntheticStamps
	"DEFAULTPW-DECRYPTED":   contractMarker, // oleid_indicators.yara DefaultPW_Decrypted
	"ENCRYPTION-XOR":        contractMarker, // oleid_indicators.yara Encrypted_XOR_Obfuscation
	"ENCRYPTION-RC4":        contractMarker, // oleid_indicators.yara Encrypted_Document
	"ENCRYPTION-AES":        contractMarker, // oleid_indicators.yara Encrypted_Document
	"DIGITAL-SIGNATURE":     contractMarker, // oleid_indicators.yara Document_DigitalSignature
	"VBA-ENVIRON":           contractMarker, // intent.yara VBA_Environ_Probe
	"VBA-STOMPED":           contractMarker, // vba_stomping.yara
	"MSD-DEEPDECODE":        contractMarker, // intent.yara Multilayer_Encoded_Payload
	"PDF-OPENACTION-JS":     contractMarker, // pdf_indicators.yara PDF_OpenAction_JS
	"PDF-AA-ACTION":         contractMarker, // pdf_indicators.yara PDF_Additional_Actions
	"PDF-LAUNCH":            contractMarker, // pdf_indicators.yara PDF_Launch_Action
	"PDF-EMBEDDEDFILE":      contractMarker, // pdf_indicators.yara PDF_EmbeddedFile
	"PDF-JBIG2":             contractMarker, // pdf_indicators.yara PDF_JBIG2
	"PDF-OBJSTM":            contractMarker, // pdf_indicators.yara PDF_ObjStm
	"PDF-HEXOBFUSC":         contractMarker, // pdf_indicators.yara PDF_HexObfuscatedName

	// --- carved-payload labels (scanned by existing keyword/IOC rules; no own rule) ---
	"DOCPROPS-STRINGS": internalMarker,
	"USERFORM-STRINGS": internalMarker,
}

// markerEmitRe matches a synthetic marker prefix inside a Go string or []byte
// literal: an UPPERCASE token containing at least one '-' (so it is a marker, not
// an arbitrary capitalised word), terminated by either a space (markers that
// carry a value tail, []byte("CSV-DDE "+c)) or the closing quote (bare markers,
// []byte("OLEID-FLASH"), emit("PDF-LAUNCH")).
var markerEmitRe = regexp.MustCompile(`"([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)( |")`)

// discoverEmittedMarkers scans every non-test .go file in this package for
// emitted marker prefixes.
func discoverEmittedMarkers(t *testing.T) map[string]string {
	t.Helper()
	found := make(map[string]string) // prefix -> first file:match
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) // #nosec G304 -- fixed package-local source file
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range markerEmitRe.FindAllStringSubmatch(string(src), -1) {
			prefix := m[1]
			if _, ok := found[prefix]; !ok {
				found[prefix] = name
			}
		}
	}
	return found
}

// loadRuleCorpus concatenates every docker/local-rules/*.yara file so a marker
// prefix can be substring-tested against the whole rule set.
func loadRuleCorpus(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "docker", "local-rules")
	matches, err := filepath.Glob(filepath.Join(dir, "*.yara"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("glob %s: err=%v n=%d", dir, err, len(matches))
	}
	var sb strings.Builder
	for _, p := range matches {
		b, err := os.ReadFile(p) // #nosec G304 -- fixed in-repo rules path
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// TestParityContractMarkersHaveRules asserts every CONTRACT marker is referenced
// by at least one local YARA rule — i.e. the Go carve is actually scored.
func TestParityContractMarkersHaveRules(t *testing.T) {
	corpus := loadRuleCorpus(t)
	for prefix, kind := range parityMarkers {
		if kind != contractMarker {
			continue
		}
		// A rule references the marker via its prefix string (with the trailing
		// space the emit uses, e.g. $marker = "CSV-DDE " ascii). Test both the
		// spaced and bare forms so a rule that anchors on the bare prefix also
		// counts.
		if !strings.Contains(corpus, prefix+" ") && !strings.Contains(corpus, prefix) {
			t.Errorf("CONTRACT marker %q has no referencing rule in docker/local-rules/*.yara — carve is unscored", prefix)
		}
	}
}

// TestParityMarkerInventory asserts the parityMarkers table is exhaustive: every
// marker emitted in the package source has a table row. A new emit site without a
// row fails here, forcing classification (and a rule if CONTRACT).
func TestParityMarkerInventory(t *testing.T) {
	emitted := discoverEmittedMarkers(t)
	for prefix, file := range emitted {
		if _, ok := parityMarkers[prefix]; !ok {
			t.Errorf("emitted marker %q (%s) is not in parityMarkers — classify it contract/internal (and add a scoring rule if contract)", prefix, file)
		}
	}
	// Reverse direction: a table entry whose emit site was removed is stale.
	for prefix := range parityMarkers {
		if _, ok := emitted[prefix]; !ok {
			t.Errorf("parityMarkers lists %q but no emit site was found in package source — remove the stale row", prefix)
		}
	}
}
