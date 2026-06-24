/*
  VBScript split-delimited char-code dropper.

  Closes a live-corpus .vbs MISS (sample 4c6c3fb4...): ~2000 decoy
  `ident = "junk"` assignments hide one payload string of the form
  `<delim1><junk><N><delim2>` repeated, where N is an ASCII code. A loop
  Split()s on the two random per-sample delimiters, strips the junk prefix with
  Mid(), gates each token with IsNumeric(), rebuilds the payload with ChrW(), and
  runs it via Execute. The decoder mechanic is the signature — the delimiters are
  random per sample so they cannot be pinned; the Split -> ChrW-accumulate ->
  IsNumeric -> Execute combination is what stays constant and is essentially
  never produced by benign VBScript.

  Reference: MalwareBazaar live .vbs corpus 2024-2026 (sample 4c6c3fb4).
*/

rule VBS_CharCode_Split_Dropper : maldoc dropper vbscript heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "VBScript dropper: payload Split() into tokens, each ChrW(IsNumeric)-decoded and accumulated, then run via Execute"
        reference   = "MalwareBazaar live .vbs corpus 2024-2026 (4c6c3fb4)"
        score       = "70"
    strings:
        // the four decode-loop primitives, co-located. ascii+wide because VBS
        // droppers ship UTF-16LE as often as ASCII; nocase because VBScript is
        // case-insensitive. All linear — no nested unbounded quantifiers (avoids
        // the catastrophic-backtracking class fixed in #174/#177).
        $split = "Split(" ascii wide nocase
        // ChrW accumulation onto a running buffer: `<buf> & ChrW(`
        $acc   = /&[ ]{0,4}ChrW\(/ ascii wide nocase
        $isnum = "IsNumeric" ascii wide nocase
        // Execute of a bare variable (the rebuilt payload), not Execute "literal"
        $exec  = /Execute[ ]{1,4}[A-Za-z_]/ ascii wide nocase
    condition:
        // The conjunction is the FP guard: benign VBScript essentially never
        // Split-decodes a numeric array via ChrW and Executes the result. 16MB
        // cap matches the other local rules.
        filesize < 16MB and all of them
}
