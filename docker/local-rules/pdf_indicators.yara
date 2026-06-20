/*
  PDF dropper indicator rules -- score yarad's PDF-DEEPEN structural markers.

  yarad's extract.fromPDFIndicators surfaces the high-risk pdfid keyword set
  (pdfid.py) as synthetic marker streams. These are name tokens in the PDF body
  (auto-run actions, script bodies, launch/embedded-file/exploit vectors), and
  yarad de-obfuscates hex-escaped names (/J#61vaScript -> /JavaScript) before
  matching, so an evasive sample is normalised first.

  Markers (each emitted only by yarad, so matching the literal is zero-FP):
    PDF-OPENACTION-JS  -- /OpenAction + a /JS|/JavaScript body: JavaScript that
                          auto-runs when the document is opened. Strongest signal.
    PDF-LAUNCH         -- /Launch action runs an external program.
    PDF-AA-ACTION      -- /AA additional-actions dictionary (auto-fire on open/page).
    PDF-EMBEDDEDFILE   -- carries an embedded file (dropper container).
    PDF-JBIG2          -- /JBIG2Decode, the CVE-2009-3459 exploit vector.
    PDF-OBJSTM         -- /ObjStm object stream (hides objects from naive scanners).
    PDF-HEXOBFUSC      -- a name token used #XX hex-escape obfuscation (evasion).

  Presence indicators STACK with other signals (inflated JS, suspicious
  keywords) the same scan surfaces. Tagged `suspicious heuristic` so yara.lua
  routes them to YARA_SUSPICIOUS (operator-tunable); the auto-run/launch ones
  are scored higher.

  Reference: https://github.com/DidierStevens/DidierStevensSuite (pdfid.py)
*/

rule PDF_OpenAction_JS : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "PDF auto-runs JavaScript on open (/OpenAction + /JS) -- pdfid indicator"
        reference   = "https://blog.didierstevens.com/programs/pdf-tools/"
        score       = "60"
    strings:
        $marker = "PDF-OPENACTION-JS" ascii
    condition:
        filesize < 16MB and $marker
}

rule PDF_Launch_Action : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "PDF /Launch action (runs an external program) -- pdfid indicator"
        reference   = "https://blog.didierstevens.com/programs/pdf-tools/"
        score       = "50"
    strings:
        $marker = "PDF-LAUNCH" ascii
    condition:
        filesize < 16MB and $marker
}

rule PDF_JBIG2 : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "PDF /JBIG2Decode filter (CVE-2009-3459 exploit vector) -- pdfid indicator"
        reference   = "https://www.cve.org/CVERecord?id=CVE-2009-3459"
        score       = "40"
    strings:
        $marker = "PDF-JBIG2" ascii
    condition:
        filesize < 16MB and $marker
}

rule PDF_Additional_Actions : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "PDF /AA additional-actions dictionary (auto-fire on open/page) -- pdfid indicator"
        reference   = "https://blog.didierstevens.com/programs/pdf-tools/"
        score       = "30"
    strings:
        $marker = "PDF-AA-ACTION" ascii
    condition:
        filesize < 16MB and $marker
}

rule PDF_EmbeddedFile : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "PDF carries an embedded file (/EmbeddedFile) -- pdfid indicator"
        reference   = "https://blog.didierstevens.com/programs/pdf-tools/"
        score       = "30"
    strings:
        $marker = "PDF-EMBEDDEDFILE" ascii
    condition:
        filesize < 16MB and $marker
}

rule PDF_HexObfuscatedName : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "PDF name token used #XX hex-escape obfuscation (evasion) -- pdfid indicator"
        reference   = "https://blog.didierstevens.com/programs/pdf-tools/"
        score       = "30"
    strings:
        $marker = "PDF-HEXOBFUSC" ascii
    condition:
        filesize < 16MB and $marker
}

rule PDF_ObjStm : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "PDF object stream /ObjStm (hides objects from naive scanners) -- pdfid indicator"
        reference   = "https://blog.didierstevens.com/programs/pdf-tools/"
        score       = "10"
    strings:
        $marker = "PDF-OBJSTM" ascii
    condition:
        filesize < 16MB and $marker
}
