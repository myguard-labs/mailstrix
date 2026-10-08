package extract

import (
	"encoding/binary"

	spe "github.com/saferwall/pe"
)

const (
	binAnalyzeMax = 8

	// Marker constants — registered in pureMarkerLiterals AND parityMarkers.
	binMarkerPESectionPacked   = "PE-SECTION-PACKED"
	binMarkerPESectionHighEntr = "PE-SECTION-HIGH-ENTROPY"
	binMarkerPEOverlay         = "PE-OVERLAY"
	binMarkerPEVirtualSection  = "PE-VIRTUAL-SECTION"
	binMarkerPEDotNet          = "PE-DOTNET"
	binMarkerPEAnomaly         = "PE-ANOMALY"
	binMarkerELFExecutable     = "ELF-EXECUTABLE"
)

// isValidELFAt reports whether buf starts with a structurally valid ELF header.
// Validates magic, EI_CLASS, EI_DATA and e_type; accepts ET_REL/EXEC/DYN/CORE.
func isValidELFAt(buf []byte) bool {
	if len(buf) < 18 {
		return false
	}
	if buf[0] != 0x7F || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F' {
		return false
	}
	class := buf[4] // EI_CLASS: 1=32-bit, 2=64-bit
	data := buf[5]  // EI_DATA: 1=LE, 2=BE
	if class < 1 || class > 2 || data < 1 || data > 2 {
		return false
	}
	// e_type is at offset 16, uint16, endian-dependent.
	var etype uint16
	if data == 1 {
		etype = binary.LittleEndian.Uint16(buf[16:18])
	} else {
		etype = binary.BigEndian.Uint16(buf[16:18])
	}
	// Valid e_type: ET_REL(1), ET_EXEC(2), ET_DYN(3), ET_CORE(4).
	return etype >= 1 && etype <= 4
}

// analyzeBinaries scans buf and res.Streams for embedded PE and ELF executables
// and emits structural-anomaly markers. buf is the original input (a standalone
// PE/ELF that did not enter any format path still needs analysis). res.Streams
// is snapshotted before iterating to avoid rescanning appended markers.
func analyzeBinaries(buf []byte, res *Result) {
	// Preflight: skip all allocations when neither buf nor any current stream
	// contains a PE (findPE>=0) or ELF (isValidELFAt at offset 0) candidate.
	// Uses the same predicates as the loop below, so any candidate the loop
	// would process is guaranteed to be seen here first.
	{
		hasCandidate := isValidELFAt(buf) || findPE(buf, 0) >= 0
		if !hasCandidate {
			for _, s := range res.Streams {
				if isValidELFAt(s) || findPE(s, 0) >= 0 {
					hasCandidate = true
					break
				}
			}
		}
		if !hasCandidate {
			return
		}
	}

	// Build the scan set: original buf first, then all current streams.
	// Deduplicate by pointer: if buf is already stream[0] (some paths alias it),
	// the PE/ELF check is idempotent (emit deduplicates by marker string).
	scan := make([][]byte, 0, 1+len(res.Streams))
	scan = append(scan, buf)
	snap := res.Streams[:len(res.Streams)] // snapshot; appends grow res.Streams
	scan = append(scan, snap...)

	// dedup: emit each marker at most once per document
	emitted := make(map[string]bool)
	emit := func(m string) {
		if !emitted[m] && len(res.Streams) < maxStreams {
			emitted[m] = true
			res.Streams = append(res.Streams, []byte(m))
		}
	}

	peCnt := 0
	for _, s := range scan {
		if len(res.Streams) >= maxStreams {
			break
		}

		// --- ELF detection (at offset 0 of a stream) ---
		if isValidELFAt(s) {
			emit(binMarkerELFExecutable)
		}

		// --- PE structural analysis ---
		if peCnt >= binAnalyzeMax {
			continue
		}
		off := findPE(s, 0)
		if off < 0 {
			continue
		}
		peCnt++
		blob := s[off:]
		analyzePEBlob(blob, emit)
	}
}

// analyzePEBlob runs saferwall/pe structural analysis on a PE blob (MZ at offset 0).
// All calls are wrapped fail-open: malformed/partial PE must not panic or propagate errors.
func analyzePEBlob(blob []byte, emit func(string)) {
	defer func() { recover() }() //nolint:errcheck // intentional fail-open

	pef, err := spe.NewBytes(blob, &spe.Options{SectionEntropy: true})
	if err != nil {
		return
	}
	if err := pef.Parse(); err != nil && len(pef.Sections) == 0 {
		return // completely unparsable; no sections to analyze
	}

	// Section entropy + virtual section check
	for _, sec := range pef.Sections {
		raw := sec.Header.SizeOfRawData
		virt := sec.Header.VirtualSize
		if raw == 0 && virt > 0 {
			emit(binMarkerPEVirtualSection)
		}
		if sec.Entropy != nil {
			switch {
			case *sec.Entropy >= 7.2:
				emit(binMarkerPESectionPacked)
			case *sec.Entropy >= 7.0:
				emit(binMarkerPESectionHighEntr)
			}
		}
	}

	// Overlay: data past the end of the last section
	if pef.OverlayOffset > 0 && pef.OverlayOffset < int64(len(blob)) {
		emit(binMarkerPEOverlay)
	}

	// CLR / .NET assembly
	if pef.HasCLR {
		emit(binMarkerPEDotNet)
	}

	// Anomalies
	_ = pef.GetAnomalies()
	if len(pef.Anomalies) > 0 {
		emit(binMarkerPEAnomaly)
	}
}
