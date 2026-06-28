/*
  OOXML_Remote_Template -- remote-template-injection and external-object heuristic.

  Fires when an OOXML document (Word, Excel, PowerPoint) contains an external
  relationship pointing to a remote URI (http/https/smb/UNC).  The
  extract package surfaces these as synthetic "OOXML-EXTERNAL-REL <type> <target>"
  streams (one per suspicious <Relationship> entry in any _rels/*.rels part)
  so this rule can match what is invisible in the raw zip bytes.

  Why it matters: remote-template injection (CVE-2017-0199 and countless kin)
  works by embedding an attachedTemplate or oleObject relationship that points to
  an attacker-controlled URL.  Word/Excel fetches the remote template at open time
  and executes any macros inside it -- without any embedded macro in the original
  document.  Legitimate documents almost never carry an external attachedTemplate
  or oleObject pointing to an http/https/smb host; when they do, it is the attack.

  FP mitigation:
  - Requires the literal "OOXML-EXTERNAL-REL " prefix (only emitted by mailstrix's
    extract package, never present in raw document bytes).
  - AND requires one of the remote URI schemes -- plain local file paths are
    excluded; only UNC paths (NTLM relay vector) are included.
  - filesize cap keeps it off large binaries that cannot be OOXML.

  Heuristic, not family attribution -- tagged `suspicious heuristic` so
  mailstrix.lua classify() routes it to STRIX_SUSPICIOUS (operator-tunable).
  score 50 = mid-high confidence (external template is very rarely benign).

  Reference: https://attack.mitre.org/techniques/T1221/
*/
rule OOXML_Remote_Template : maldoc heuristic suspicious
{
    meta:
        author      = "mailstrix"
        description = "OOXML external relationship points to a remote URI (template/OLE injection heuristic)"
        reference   = "https://attack.mitre.org/techniques/T1221/"
        score       = "50"
    strings:
        // The synthetic marker prefix emitted by extract.fromOOXMLRels -- never
        // present in raw document bytes, so matching it is zero-FP by construction.
        $marker = "OOXML-EXTERNAL-REL " ascii

        // Remote URI schemes in the Target attribute.
        $http  = "http://"  ascii nocase
        $https = "https://" ascii nocase
        $smb   = "smb://"   ascii nocase
        $unc   = "file://\\" ascii nocase
        $unc2  = "\\\\" ascii
    condition:
        filesize < 16MB and
        $marker and
        any of ($http, $https, $smb, $unc, $unc2)
}

/*
  OOXML_MHTML_Scheme -- CVE-2021-40444 (MSHTML) relationship-Target detector.

  The 2021 MSHTML zero-day shipped a .docx whose word/_rels/document.xml.rels
  carried an oleObject relationship with TargetMode="External" and a Target of
  the form  mhtml:http://attacker/file.html!x-usc:http://attacker/file.html .
  Opening the document made Office fetch that URL through the MSHTML/ActiveX
  path, which loaded a remote .cab -> .inf -> DLL with no macro and no prompt.

  extract.fromOOXMLRels surfaces such a Target as a synthetic
  "OOXML-MHTML-REL <type> <target>" stream (distinct from the generic
  OOXML-EXTERNAL-REL because an mhtml:/!x-usc: scheme in a relationship is the
  exploit, never benign). Matching the prefix is zero-FP by construction -- the
  literal is mailstrix-synthetic and never present in raw document bytes.

  score 80 = high confidence (no legitimate use of mhtml:/!x-usc: in a rel).
  Reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444
*/
rule OOXML_MHTML_Scheme : maldoc exploit cve_2021_40444
{
    meta:
        author      = "mailstrix"
        description = "OOXML relationship Target uses the CVE-2021-40444 mhtml:/!x-usc: MSHTML scheme"
        reference   = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444"
        score       = "80"
    strings:
        // The synthetic marker prefix emitted by extract.fromOOXMLRels -- never
        // present in raw document bytes, so matching it is zero-FP by construction.
        $marker = "OOXML-MHTML-REL " ascii
    condition:
        filesize < 16MB and $marker
}
