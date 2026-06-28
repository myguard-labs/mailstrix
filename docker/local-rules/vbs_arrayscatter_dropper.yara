/*
  VBS array-scatter dropper heuristic — pure YARA over the raw .vbs body (and any
  single-layer-decoded blob from decode.go). Targets a .vbs family the upstream
  feeds (yaraforge / signature-base / anyrun / yaraify) miss on the live mail
  stream:

    A char lookup table is scattered across per-index single-char array
    assignments (`v5(57) = "Y"`, `v5(1) = "!"`, … ~95 cells, declared out of
    order), the real command is a separate array of numeric offsets, and a decode
    loop reassembles the payload via an offset-indexed table lookup
    (`buf = buf & v5(idx(i) - 5188)`) which is then handed to `WScript.Shell.Run`.
    No clear-text command, API name, or Chr()/Execute primitive ever appears —
    defeating keyword and family scanners.

  The rule pairs the SPECIFIC offset-indexed decode shape (`& tbl(idx(i) - N`)
  with a large COUNT of single-char table-cell assignments and a `.Run`
  execution primitive, so ordinary VBS that assigns a few array elements never
  fires. Tagged `suspicious heuristic` so mailstrix.lua classify() routes to
  STRIX_SUSPICIOUS. Heuristic, NOT family attribution.

  References:
    MalwareBazaar live .vbs corpus 2026 (420b9bc8… MassLogger — 0-hit miss
    before this rule)
*/

rule VBS_ArrayScatter_OffsetTable_Dropper : vbs dropper heuristic suspicious
{
    meta:
        author      = "mailstrix"
        description = "VBS array-scatter dropper: per-index single-char lookup table reassembled via offset-indexed decode loop then .Run"
        reference   = "MalwareBazaar live .vbs corpus 2026"
        score       = "65"
    strings:
        // one scattered table cell: `<arr>(<int>) = "<single char>"`. Idents and
        // the index are length-bounded so the regex stays linear.
        $scatter = /[A-Za-z_]\w{0,40}\(\d{1,3}\) = "[^"]"/ ascii wide nocase
        // the offset-indexed decode accumulate: `& tbl(idx(var) - <num>`. This is
        // the family's distinguishing mechanic — a nested array lookup minus a
        // base offset, accumulated into the payload buffer.
        $decode  = /& [A-Za-z_]\w{0,40}\([A-Za-z_]\w{0,40}\([A-Za-z_]\w{0,40}\) - \d/ ascii wide nocase
        // the WSH execution primitive the rebuilt payload is handed to
        $run     = /\.Run / ascii wide nocase
    condition:
        // the decode shape + execution primitive pin the dropper; the COUNT is the
        // FP guard — the live sample carries 94 single-char cells, so 50 is a wide
        // margin above anything benign VBS produces.
        filesize < 16MB and #scatter > 50 and $decode and $run
}
