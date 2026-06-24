// Archive structural indicators emitted by internal/extract/archive.go.
// Each marker is a yarad-synthetic PURE literal routed to the out-of-band
// Markers channel, so the rule is zero-FP by construction: it fires only when
// the extractor positively identified the condition while unpacking.
//
// meta.tier is honoured authoritatively by the rspamd yara.lua plugin
// (classify()): this self-declares "suspicious" so it scores in YARA_SUSPICIOUS
// regardless of name/tag heuristics.

rule Archive_Encrypted : archive evasion heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "Password-protected archive member (zip/rar/7z) — payload hidden from the scanner; password typically supplied in the mail body"
        reference   = "https://attack.mitre.org/techniques/T1027/002/"
        tier        = "suspicious"
        score       = "55"
    strings:
        $marker = "ARCHIVE-ENCRYPTED" ascii
    condition:
        filesize < 16MB and $marker
}
