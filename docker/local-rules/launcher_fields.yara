/*
  Settings DeepLink heuristic. The extractor supplies a combined marker/value
  stream; format presence alone does not score. Internet Shortcut URL/IconFile
  values have no dedicated score: remote icons can be legitimate intranet assets.
*/

rule SettingContent_DeepLink_EncodedPowerShell : maldoc heuristic suspicious
{
    meta:
        author      = "mailstrix"
        description = ".settingcontent-ms DeepLink launching PowerShell with an encoded/bypass command line -- macro-less execution carrier"
        reference   = "https://attack.mitre.org/techniques/T1204/002/"
        tier        = "suspicious"
        score       = "50"
    strings:
        // mailstrix's own marker tag: the value that follows is the shell-executed
        // DeepLink command line. Anchors the rule to the extracted field, so it
        // cannot fire on a mention of PowerShell elsewhere in a document.
        $marker = "SETTINGCONTENT-DEEPLINK " ascii

        // The abusive command form, within the same extracted marker buffer.
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase

        $f1 = /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/]{20,}/ ascii nocase
        $f2 = "-w hidden" ascii nocase
        $f3 = "-windowstyle hidden" ascii nocase
        $f4 = "-nop" ascii nocase
        $f5 = "-ep bypass" ascii nocase
        $f6 = "-executionpolicy bypass" ascii nocase
        $f7 = "FromBase64String" ascii nocase
        $f8 = "DownloadString" ascii nocase
    condition:
        filesize < 1MB and $marker and any of ($ps*) and any of ($f*)
}
