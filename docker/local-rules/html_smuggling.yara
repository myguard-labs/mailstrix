// HTML smuggling + scripted-SVG markers emitted by internal/extract/html.go.
// Each marker is a mailstrix-synthetic PURE literal routed to the out-of-band
// Markers channel, so these rules are zero-FP by construction: they fire only
// when the extractor's gated combo (blob-reconstruct + forced download, a
// force-downloaded base64 data: URI, or a scripted <svg>) was satisfied.
//
// meta.tier is honoured authoritatively by the rspamd mailstrix.lua plugin
// (classify()): these self-declare "suspicious" so they score in STRIX_SUSPICIOUS
// regardless of name/tag heuristics.

rule HTML_Smuggling_Blob : html smuggling heuristic suspicious marker
{
    meta:
        author      = "mailstrix"
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
        author      = "mailstrix"
        description = "HTML smuggling: force-downloaded base64 data: URI payload (decoded + carved)"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"
        tier        = "suspicious"
        score       = "60"
    strings:
        $marker = "HTML-SMUGGLING-DATAURI" ascii
    condition:
        filesize < 16MB and $marker
}

rule HTML_DataURI_Container : html smuggling heuristic suspicious marker
{
    meta:
        author      = "mailstrix"
        description = "HTML smuggling: base64 data: URI in plain HTML decoding to a container payload (PK/OLE2/MZ/%PDF) without a download attribute"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"
        tier        = "suspicious"
        score       = "60"
    strings:
        $marker = "HTML-DATAURI-CONTAINER" ascii
    condition:
        filesize < 16MB and $marker
}

rule SVG_Scripted : svg smuggling heuristic suspicious marker
{
    meta:
        author      = "mailstrix"
        description = "Scripted SVG: <svg> root carrying <script>/onload/<foreignObject> (redirect/smuggling vector)"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"
        tier        = "suspicious"
        score       = "40"
    strings:
        $marker = "SVG-SCRIPT" ascii
    condition:
        filesize < 16MB and $marker
}

rule SVG_Embedded_Payload : svg smuggling heuristic suspicious marker
{
    meta:
        author      = "mailstrix"
        description = "SVG <image href> base64 data: URI decodes to a container magic (PK/OLE2/MZ/%PDF) — smuggled dropper, not raster art"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"
        tier        = "suspicious"
        score       = "70"
    strings:
        // PURE mailstrix-synthetic literal: only emitted when the decoded data: URI
        // carried a real container magic, so matching it is zero-FP by construction.
        $marker = "SVG-EMBEDDED-PAYLOAD" ascii
    condition:
        filesize < 16MB and $marker
}
