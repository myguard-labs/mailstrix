// Archive structural indicators emitted by internal/extract/archive.go.
// Each marker is a mailstrix-synthetic PURE literal routed to the out-of-band
// Markers channel, so the rule is zero-FP by construction: it fires only when
// the extractor positively identified the condition while unpacking.
//
// meta.tier is honoured authoritatively by the rspamd mailstrix.lua plugin
// (classify()): this self-declares "suspicious" so it scores in STRIX_SUSPICIOUS
// regardless of name/tag heuristics.

rule Archive_Encrypted : archive evasion heuristic suspicious marker
{
    meta:
        author      = "mailstrix"
        description = "Password-protected archive member (zip/rar/7z) — payload hidden from the scanner; password typically supplied in the mail body"
        reference   = "https://attack.mitre.org/techniques/T1027/002/"
        tier        = "suspicious"
        score       = "55"
    strings:
        $marker = "ARCHIVE-ENCRYPTED" ascii
    condition:
        filesize < 16MB and $marker
}

rule Polyglot_PE_ZIP : polyglot evasion heuristic malware marker
{
    meta:
        author      = "mailstrix"
        description = "File-type confusion: buffer is simultaneously a valid PE image and a valid ZIP (gateway parses ZIP, endpoint runs PE)"
        reference   = "https://attack.mitre.org/techniques/T1027/001/"
        tier        = "malware"
        score       = "90"
    strings:
        $marker = "POLYGLOT-PE-ZIP" ascii
    condition:
        filesize < 16MB and $marker
}

rule XLL_AddIn : xll office heuristic suspicious marker
{
    meta:
        author      = "mailstrix"
        description = "Excel XLL add-in (PE DLL exporting xlAutoOpen) — runs code on load with no macro prompt; an emailed .xll is a known phishing vector"
        reference   = "https://attack.mitre.org/techniques/T1137/006/"
        tier        = "suspicious"
        score       = "70"
    strings:
        $marker = "XLL-ADDIN" ascii
    condition:
        filesize < 16MB and $marker
}

rule Base64_Stuffed_PE : evasion heuristic malware marker
{
    meta:
        author      = "mailstrix"
        description = "A full Windows PE was base64/hex-encoded into a document text field (e.g. OOXML docProps) with a pad so the MZ header lands at a non-zero offset, evading the pe module's MZ@0 anchor. mailstrix decodes the run, carves an MZ-aligned copy for the pe rules, and flags the staged executable"
        reference   = "https://attack.mitre.org/techniques/T1027/"
        tier        = "malware"
        score       = "85"
    strings:
        $marker = "BASE64-PE-CARVE" ascii
    condition:
        filesize < 16MB and $marker
}

rule Renamed_Container : evasion heuristic suspicious marker
{
    meta:
        author      = "mailstrix"
        description = "Renamed container: the real parsed type (OLE/OOXML/RTF/archive/LNK/MSI/OneNote) contradicts a benign-looking attachment extension — a classic dropper rename evasion. mailstrix analog of SpamAssassin OLEMACRO_RENAME / MIME_BAD_EXTENSION, driven by the actual extracted type, not a magic-byte grep"
        reference   = "https://attack.mitre.org/techniques/T1036/008/"
        tier        = "suspicious"
        score       = "55"
    strings:
        $marker = "EXT-MISMATCH " ascii
    condition:
        filesize < 16MB and $marker
}
