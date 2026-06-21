/*
  Intent rules — macro/script behaviour heuristics (olevba "suspicious" + LOLBin
  lore), expressed as pure YARA over every buffer yarad scans: the decompressed
  VBA macro stream, raw body / script carriers, and the single-layer-decoded
  blobs from decode.go. Each rule pairs a tool/keyword with a SPECIFIC abusive
  argument so a bare mention (security docs, newsletters) does not fire — the
  combination is what keeps the false-positive rate low. All tagged `suspicious
  heuristic` so yara.lua classify() routes them to YARA_SUSPICIOUS (tunable).
  Heuristics, NOT family attribution; NOT emulation.
  Reference: https://lolbas-project.github.io/ , https://github.com/decalage2/oletools/wiki/olevba
*/

rule LOLBins_Invocation : lolbin heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Living-off-the-land binary invoked with a download/execute argument"
        reference   = "https://lolbas-project.github.io/"
        score       = "50"
    strings:
        // each = a LOLBin tied to its abusive argument form (name alone is noise)
        $l1 = /regsvr32(\.exe)?[^\n]{0,40}\/i:?[^\n]{0,8}(http|scrobj)/ ascii wide nocase
        $l2 = /rundll32(\.exe)?[^\n]{0,40}(javascript:|url\.dll|shell32\.dll[^\n]{0,20}ShellExec)/ ascii wide nocase
        $l3 = /mshta(\.exe)?[^\n]{0,40}(http|javascript:|vbscript:)/ ascii wide nocase
        $l4 = /certutil(\.exe)?[^\n]{0,40}(-decode|-urlcache|-f -split)/ ascii wide nocase
        $l5 = /bitsadmin(\.exe)?[^\n]{0,40}\/transfer/ ascii wide nocase
        $l6 = /msiexec(\.exe)?[^\n]{0,20}\/i[^\n]{0,20}http/ ascii wide nocase
        $l7 = /(schtasks|at)(\.exe)?[^\n]{0,40}\/create[^\n]{0,80}(powershell|http|cmd)/ ascii wide nocase
    condition:
        filesize < 16MB and any of them
}

rule WMI_Process_Spawn : wmi heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "WMI Win32_Process.Create — process spawn via WMI (common macro dropper technique)"
        reference   = "https://github.com/decalage2/oletools/wiki/olevba"
        score       = "55"
    strings:
        $w  = "winmgmts:" ascii wide nocase
        $p  = "Win32_Process" ascii wide nocase
        $c  = ".Create" ascii wide nocase
    condition:
        filesize < 16MB and $w and $p and $c
}

rule PowerShell_Abuse_Flags : powershell heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "PowerShell launched with encoded/hidden/download flags"
        reference   = "https://github.com/decalage2/oletools/wiki/olevba"
        score       = "50"
    strings:
        $ps  = "powershell" ascii wide nocase
        $f1  = /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/]{20,}/ ascii wide nocase
        $f2  = "-w hidden" ascii wide nocase
        $f3  = "-windowstyle hidden" ascii wide nocase
        $f4  = "-nop" ascii wide nocase
        $f5  = "-ep bypass" ascii wide nocase
        $f6  = "-executionpolicy bypass" ascii wide nocase
        $f7  = "IEX" ascii wide
        $f8  = "Invoke-Expression" ascii wide nocase
        $f9  = "DownloadString" ascii wide nocase
        $f10 = "FromBase64String" ascii wide nocase
    condition:
        filesize < 16MB and $ps and any of ($f*)
}

rule Maldoc_AntiAnalysis_Evasion : evasion heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Macro combines two or more anti-analysis / sandbox-evasion primitives"
        reference   = "https://github.com/decalage2/oletools/wiki/olevba"
        score       = "30"
    strings:
        $e1 = "On Error Resume Next"        ascii wide nocase
        $e2 = "Application.Visible = False" ascii wide nocase
        $e3 = "RecentFiles.Count"           ascii wide nocase
        $e4 = "GetTickCount"                ascii wide nocase
        $e5 = /Environ\(?\s*"?(USERNAME|COMPUTERNAME|USERDOMAIN)/ ascii wide nocase
        $e6 = "Sleep "                       ascii wide nocase
        $e7 = "Wscript.Sleep"                ascii wide nocase
    condition:
        filesize < 16MB and 2 of them
}

// VBA-ENVIRON %NAME% markers are emitted by the VBA string-fold
// (internal/extract/decode.go foldVBAStrings) when an Environ("NAME") lookup is
// folded — INCLUDING when the call was reassembled from Chr()/concat obfuscation,
// where the raw "Environ(" keyword the heuristic rules grep for is gone. The
// marker prefix is emitted only by yarad, so the literal is zero-FP. Env-var
// probing alone is recon (path-building, sandbox checks), so a modest score; it
// stacks with the anti-analysis / dropper rules above when present together.
rule VBA_Environ_Probe : maldoc heuristic suspicious {
    meta:
        description = "VBA macro probes an environment variable (Environ), incl. obfuscation-folded"
        score       = "20"
    strings:
        $marker = "VBA-ENVIRON %"
    condition:
        $marker
}
