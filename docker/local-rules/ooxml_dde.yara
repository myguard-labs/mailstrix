/*
  Maldoc_DDE_Field -- OOXML DDE/DDEAUTO field injection heuristic.

  Fires when an OOXML document (Word) contains a DDE or DDEAUTO field
  instruction. The extract package reads word/document.xml (and related parts),
  concatenates split w:instrText runs, and emits a synthetic
  "OOXML-DDE-FIELD <instr>" stream for any instruction that begins with DDE or
  DDEAUTO. This rule matches that stream.

  Why it matters: DDE (Dynamic Data Exchange) field injection is a well-known
  maldoc vector that allows command execution without macros. A Word document
  containing a field like:
      { DDEAUTO c:\\Windows\\System32\\cmd.exe /k calc }
  will launch cmd.exe when the document is opened (with or without macros
  enabled). Because DDE fields are XML text rather than binary VBA, they survive
  simple macro-scan filters — the yarad extractor surfaces them explicitly.

  FP mitigation:
  - Requires the literal "OOXML-DDE-FIELD " prefix (only emitted by yarad's
    extract package, never present in raw document bytes or the zip binary).
  - AND requires a DDE or DDEAUTO token in the same stream.
  - The two-part AND keeps it off ordinary documents that happen to match one
    term in raw bytes.
  - filesize cap keeps it off large binaries that cannot be OOXML.

  Heuristic, not family attribution — tagged `suspicious heuristic` so
  yara.lua classify() routes it to YARA_SUSPICIOUS (operator-tunable).
  score 55 = mid-high confidence (DDE fields are rarely benign; legitimate
  linked spreadsheet data uses OLE objects, not DDE field codes).

  References:
    https://attack.mitre.org/techniques/T1559/002/
    https://www.bleepingcomputer.com/news/security/microsoft-office-dde-dynamic-data-exchange-attack-used-in-phishing/
*/
rule Maldoc_DDE_Field : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "OOXML document contains a DDE/DDEAUTO field instruction (command injection heuristic)"
        reference   = "https://attack.mitre.org/techniques/T1559/002/"
        date        = "2026-06-18"
        score       = "55"
        tags        = "maldoc heuristic suspicious"
    strings:
        // The synthetic marker prefix emitted by extract.fromOOXMLDDE -- never
        // present in raw document bytes, so matching it is zero-FP by construction.
        $marker = "OOXML-DDE-FIELD " ascii

        // DDE and DDEAUTO are the two field instruction types that trigger execution.
        $dde     = "DDE "     ascii nocase
        $ddeauto = "DDEAUTO " ascii nocase
    condition:
        filesize < 16MB and
        $marker and
        any of ($dde, $ddeauto)
}
