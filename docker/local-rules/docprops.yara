rule Maldoc_DocProps_Payload
{
    meta:
        description = "Suspicious strings hidden in document properties or custom XML"
        score       = 35
        author      = "yarad"

    strings:
        $marker  = "DOCPROPS-STRINGS"
        $url     = /https?:\/\/[a-zA-Z0-9\-\.]{1,253}\.[a-zA-Z]{2,24}/
        $cmd     = "cmd.exe" nocase
        $ps      = "powershell" nocase
        $wscript = "wscript" nocase
        $mshta   = "mshta" nocase

    condition:
        $marker and any of ($url, $cmd, $ps, $wscript, $mshta)
}
