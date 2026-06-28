/*
  PowerShell control-flow-flattening dropper heuristic — pure YARA over the raw
  .ps1 body (and any single-layer-decoded blob from decode.go). Targets a .ps1
  family the upstream feeds (yaraforge / signature-base / anyrun / yaraify) miss
  on the live mail stream:

    A dispatcher loop `while ($v -ne -1) { switch ($v) { <bignum>{ ... } } }`
    flattens all control flow into a numeric state machine, and every API name
    / string literal is rebuilt at runtime from `.Insert(N,'..').Remove(N,M)`
    char-surgery chains (thousands per file) so no clear-text keyword ever
    appears — defeating keyword and family scanners alike.

  The rule pairs the SPECIFIC flattening shape (the `-ne -1` dispatcher + a
  `switch ($v)`) with a large COUNT of the char-surgery primitive so ordinary
  hand-written or minified-but-benign PowerShell (which uses a stray Insert/
  switch but never thousands) does not fire. Tagged `suspicious heuristic` so
  mailstrix.lua classify() routes to STRIX_SUSPICIOUS. Heuristic, NOT family attribution.

  References:
    MalwareBazaar live .ps1 corpus 2026 (1eb89fbb…, 77525609… — both 0-hit
    misses before this rule)
*/

rule PS1_ControlFlowFlatten_CharSurgery : powershell obfuscation heuristic suspicious
{
    meta:
        author      = "mailstrix"
        description = "PowerShell control-flow-flattening (while $v -ne -1 then switch $v) state machine plus heavy .Insert char-surgery string rebuild"
        reference   = "MalwareBazaar live .ps1 corpus 2026"
        score       = "65"
    strings:
        // the dispatcher loop sentinel: `while ($var -ne -1)`. Bounded ident so
        // the match stays linear (no catastrophic-backtracking class, #174/#177).
        $flat = /while \(\$[A-Za-z0-9_]{1,40} -ne -1\)/ ascii wide nocase
        // the paired state dispatch over the same loop variable
        $sw   = /switch \(\$[A-Za-z0-9_]{1,40}\)/ ascii wide nocase
        // the char-surgery primitive — `.Insert(<int>,'<short literal>')`. Both
        // the int and the literal are length-bounded so the regex is linear.
        // `ascii wide` because these scripts ship UTF-16LE as often as ASCII.
        $ins  = /\.Insert\(\d{1,6},'[^']{0,40}'\)/ ascii wide nocase
    condition:
        // 16MB cap matches the other local rules. The flattener + dispatch pin the
        // obfuscation shape; the COUNT is the FP guard — the live samples carry
        // ~5000+ Insert calls, so 50 is a wide margin above anything a benign
        // hand-written or normally-minified .ps1 produces.
        filesize < 16MB and $flat and $sw and #ins > 50
}
