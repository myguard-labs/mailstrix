// HTML smuggling + scripted-SVG markers emitted by internal/extract/html.go.
// Each marker is a yarad-synthetic PURE literal routed to the out-of-band
// Markers channel, so these rules are zero-FP by construction: they fire only
// when the extractor's gated combo (blob-reconstruct + forced download, a
// force-downloaded base64 data: URI, or a scripted <svg>) was satisfied.
//
// meta.tier is honoured authoritatively by the rspamd yara.lua plugin
// (classify()): these self-declare "suspicious" so they score in YARA_SUSPICIOUS
// regardless of name/tag heuristics.

rule HTML_Smuggling_Blob : html smuggling heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "HTML smuggling: script reconstructs a Blob/object-URL and force-downloads it"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"
        tier        = "suspicious"
        score       = "65"
    strings:
        $marker = "HTML-SMUGGLING-BLOB" ascii
    condition:
        filesize < 16MB and $marker
}

rule HTML_Smuggling_DataURI : html smuggling heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "HTML smuggling: force-downloaded base64 data: URI payload (decoded + carved)"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"
        tier        = "suspicious"
        score       = "60"
    strings:
        $marker = "HTML-SMUGGLING-DATAURI" ascii
    condition:
        filesize < 16MB and $marker
}

rule SVG_Scripted : svg smuggling heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "Scripted SVG: <svg> root carrying <script>/onload/<foreignObject> (redirect/smuggling vector)"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"
        tier        = "suspicious"
        score       = "40"
    strings:
        $marker = "SVG-SCRIPT" ascii
    condition:
        filesize < 16MB and $marker
}
