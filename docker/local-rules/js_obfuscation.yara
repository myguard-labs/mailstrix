/*
  JavaScript obfuscation / dropper heuristics — pure YARA over the raw script
  body (and any single-layer-decoded blob from decode.go). Targets two families
  the upstream feeds (yaraforge / signature-base / anyrun / yaraify) miss on the
  live mail stream:

    1. Self-accumulating string-concatenation builders that stash an obfuscated
       payload in thousands of `this.X = this.X + "<non-ASCII junk>"` lines
       (the "salmon" obfuscator) — defeats keyword scanners because no API name
       ever appears in clear text; the payload is high-codepoint Unicode.

    2. Additive-cipher droppers: a decimal int array decoded with
       `String.fromCharCode((arr[i] - N + 256) % 256)` to reconstruct WSH API
       names (ActiveXObject / WScript.Shell / .Run) at runtime — a fake-library
       wrapper (jQuery/EventBus look-alike) hiding a char-code-array payload.

  Each rule pairs a SPECIFIC obfuscation mechanic with a count or second
  indicator so ordinary minified/packed-but-benign JS does not fire. Tagged
  `suspicious heuristic` so mailstrix.lua classify() routes to STRIX_SUSPICIOUS.
  Heuristics, NOT family attribution.

  References:
    https://github.com/decalage2/oletools/wiki  (script-carrier lore)
    MalwareBazaar live corpus (.js droppers, 2024-2026)
*/

rule JS_Obfusc_StringConcat_Accumulate : javascript obfuscation heuristic suspicious
{
    meta:
        author      = "mailstrix"
        description = "JS payload built by thousands of self-concatenating assignments (salmon-style string-concat obfuscator)"
        reference   = "MalwareBazaar live .js corpus 2024-2026"
        score       = "60"
    strings:
        // self-accumulate: `this.ident = this.ident + "` — the obfuscator appends
        // one junk literal per line. Same ident on both sides keeps it specific
        // (benign builder code rarely self-concats this exact form en masse).
        // YARA forbids backreferences, so we cannot assert "same ident both
        // sides" in one regex; instead we require the `this.<id> = this.<id>`
        // self-append shape (both sides start `this.`) which the salmon family
        // uses, gated by a large COUNT so a few benign `this.x = this.y + "..."`
        // lines never trip it.
        $acc = /this\.[a-zA-Z_$][\w$]* = this\.[a-zA-Z_$][\w$]* \+ "/ ascii wide
    condition:
        // 16MB cap matches the other local rules. The COUNT is the FP guard:
        // legitimate code does not self-concatenate hundreds of times. The real
        // sample sits at ~33k; 200 is a wide safety margin below that yet far
        // above anything a hand-written or normally-minified file produces.
        filesize < 16MB and #acc > 200
}

rule JS_Dropper_CharCodeArray_ActiveX : javascript dropper heuristic suspicious
{
    meta:
        author      = "mailstrix"
        description = "JS additive-cipher dropper: int-array decoded via fromCharCode((n - K + 256) % 256) to rebuild ActiveXObject/WScript.Run at runtime"
        reference   = "MalwareBazaar live .js corpus 2024-2026"
        score       = "65"
    strings:
        // the exact additive-decode mechanic: fromCharCode of (elem - K + 256) % 256.
        // Highly specific — benign code essentially never reconstructs strings this way.
        // strings carry `ascii wide` because these droppers ship as UTF-16LE
        // (BOM ff fe) as often as ASCII — the 74c761 live sample is UTF-16LE.
        $dec = /String\.fromCharCode\(\([a-zA-Z_$][\w$]*\[[a-zA-Z_$][\w$]*\] - \d{1,3} \+ 256\) % 256\)/ ascii wide nocase
        // runtime WSH primitives the decoded names resolve to (the payload's purpose)
        $ax  = "ActiveXObject" ascii wide nocase
        $run = /\.Run\(/ ascii wide nocase
        $ws  = "WScript" ascii wide nocase
    condition:
        // the additive-decode mechanic plus at least one WSH execution primitive
        // — well outside benign-JS territory. (An earlier `$blob` regex matching
        // the giant "dddd..."+ concat carrier was REMOVED: its nested unbounded
        // quantifiers caused catastrophic backtracking — ~100s on the 8.86MB
        // UTF-16 sample — which blew the scan_timeout and fail-opened the file.
        // $dec + WSH primitive already identifies the dropper in linear time.)
        filesize < 16MB and $dec and $ax and ($run or $ws)
}

rule JS_Dropper_XorArray_ActiveX : javascript dropper heuristic suspicious
{
    meta:
        author      = "mailstrix"
        description = "JS XOR-array dropper: int-array decoded via fromCharCode(arr[i] ^ key.charCodeAt(i % len)) to rebuild ActiveXObject at runtime"
        reference   = "MalwareBazaar live .js corpus 2026 (a630ae17… 0-hit miss)"
        score       = "65"
    strings:
        // the XOR-decode mechanic: fromCharCode(arr[i] ^ key.charCodeAt(...)).
        // Distinct from the additive variant above (n - K + 256) % 256 — this
        // family XORs each array element against a rolling key char. Idents and
        // the optional space around `^` are length-bounded so the regex stays
        // linear (no #174/#177 catastrophic-backtracking class). `ascii wide`
        // because these droppers ship UTF-16LE as often as ASCII.
        $xor = /String\.fromCharCode\([a-zA-Z_$][\w$]{0,40}\[[a-zA-Z_$][\w$]{0,40}\] ?\^ ?[a-zA-Z_$][\w$]{0,40}\.charCodeAt\(/ ascii wide nocase
        // runtime WSH primitive the decoded names resolve to
        $ax  = "ActiveXObject" ascii wide nocase
    condition:
        // the XOR-decode mechanic plus the WSH object primitive — benign JS does
        // not reconstruct ActiveXObject names through an XOR-array decoder.
        filesize < 16MB and $xor and $ax
}
