/*
  Tiny script-stub downloader / executor heuristics — pure YARA over the raw
  .ps1/.vbs/.bat body. Targets the small first-stage stubs (55-152 bytes) the
  upstream feeds (yaraforge / signature-base / anyrun / yaraify) miss on the live
  mail stream: no obfuscation, just one or two lines that fetch+run a second
  stage. Each rule pins a SPECIFIC malicious construct (not a lone keyword) so
  benign admin one-liners do not fire. Tagged `suspicious heuristic` so mailstrix.lua
  classify() routes to STRIX_SUSPICIOUS. Heuristics, NOT family attribution.

  Closed live MalwareBazaar 0-hit misses (.ps1/.vbs corpus 2026):
    f9bfd95b (iex irm cradle); 846a1b1c/8a588666/81a5042f/b4d94ab1 (GetObject
    scriptlet self-delete); badbafb9/0f090af0/19aacecf (msiexec remote /q,
    unicode-homoglyph -Package evasion); b9d3147f/217d39d1 (WScript.Run Temp .bat).
*/

rule PS1_IEX_IRM_DownloadCradle : powershell downloader heuristic suspicious
{
    meta:
        author="mailstrix"
        description="PowerShell one-line download cradle: iex(irm <url>) / Invoke-Expression(Invoke-RestMethod)"
        score="65"
    strings:
        $a = /iex\s*\(\s*irm[ (]/ ascii wide nocase
        $b = /Invoke-Expression\s*\(\s*Invoke-RestMethod/ ascii wide nocase
        $c = /iex\s*\(\s*iwr[ (]/ ascii wide nocase
    condition:
        filesize < 64KB and any of them
}

rule VBS_GetObject_Scriptlet_SelfDelete : vbs downloader heuristic suspicious
{
    meta:
        author="mailstrix"
        description="VBS remote scriptlet loader GetObject(\"script:http...\") that self-deletes via DeleteFile WScript.ScriptFullName"
        score="70"
    strings:
        $g = /GetObject\(\s*"script:https?:\/\//  ascii wide nocase
        $d = "DeleteFile WScript.ScriptFullName" ascii wide nocase
    condition:
        filesize < 64KB and $g and $d
}

rule Script_MSIExec_Remote_Package_Silent : downloader heuristic suspicious
{
    meta:
        author="mailstrix"
        description="msiexec installing a remote package over http(s) silently (/q) — incl unicode-homoglyph -Package evasion"
        score="65"
    strings:
        $m = /msiexec/ ascii wide nocase
        $u = /https?:\/\// ascii wide nocase
        $q = /\s\/q\b/ ascii wide nocase
    condition:
        filesize < 4KB and $m and $u and $q
}

rule VBS_WScriptShell_Run_TempBat_Hidden : vbs dropper heuristic suspicious
{
    meta:
        author="mailstrix"
        description="VBS WScript.Shell.Run launching a .bat from AppData\\Local\\Temp hidden and non-blocking (0, False)"
        score="65"
    strings:
        $shell = "WScript.Shell" ascii wide nocase
        $run  = /\.Run\b/ ascii wide nocase
        $temp = /AppData\\Local\\Temp\\/ ascii wide nocase
        $bat  = ".bat" ascii wide nocase
        $hid  = /,\s*0,\s*False/ ascii wide nocase
    condition:
        filesize < 64KB and $shell and $run and $temp and $bat and $hid
}

/*
  Second batch (s31): four single-family live MalwareBazaar 0-hit misses, each a
  distinct ASCII PS/VBS first-stage stub the upstream feeds miss. One rule per
  family; every rule keys on a SPECIFIC malicious construct-conjunction (never a
  lone keyword) so benign admin scripts do not fire. ascii wide on every string
  (family variants may ship UTF-16LE -- GOTCHA-2, #172). No backreferences, no
  nested unbounded quantifiers (#174/#177).

  Closed 0-hit misses (corpus 2026):
    2c41d4f8 (curl -> rundll32 a .png as a DLL); 9f0a17d4 (PSCredential
    password-spray loop); 3ae711ab (Defender-exclusion cleanup + self-delete
    loader); f6438c51 (custom-alphabet base64 + MSXML ExecuteGlobal downloader).
*/

rule PS1_Curl_Rundll32_PNG_Loader : powershell loader heuristic suspicious
{
    meta:
        author="mailstrix"
        description="PowerShell curl.exe downloads a .png then runs it as a DLL via rundll32 <file>.png,<export> -- image-as-DLL execution (2c41d4f8)"
        score="75"
    strings:
        // curl.exe used as the downloader (the stub aliases it to $c).
        $curl = "curl.exe" ascii wide nocase
        // rundll32 invoked on a .png with an export name -- a PNG is never a real
        // DLL, so rundll32 of one is the decisive malicious construct.
        $png  = /rundll32\s+[^\r\n,]{0,260}\.png["']?\s*,/ ascii wide nocase
    condition:
        filesize < 16KB and $curl and $png
}

rule PS1_PSCredential_Password_Spray : powershell heuristic suspicious
{
    meta:
        author="mailstrix"
        description="PowerShell credential password-spray: ConvertTo-SecureString -AsPlainText -Force fed into a PSCredential, Start-Process -Credential in a loop over a password array (9f0a17d4)"
        score="70"
    strings:
        $plain = /ConvertTo-SecureString\b[^\r\n]{0,120}-AsPlainText/ ascii wide nocase
        $cred  = "System.Management.Automation.PSCredential" ascii wide nocase
        $start = /Start-Process\b[^\r\n]{0,200}-Credential\b/ ascii wide nocase
    condition:
        filesize < 16KB and $plain and $cred and $start
}

rule PS1_Defender_Exclusion_Cleanup_Loader : powershell loader heuristic suspicious
{
    meta:
        author="mailstrix"
        description="PowerShell loader that runs a dropped Temp .exe then removes the Defender exclusion path and self-deletes via $MyInvocation.MyCommand.Path (3ae711ab)"
        score="75"
    strings:
        // tears down the Defender exclusion it (or its loader) added.
        $excl = /Remove-MpPreference\b[^\r\n]{0,80}-ExclusionPath/ ascii wide nocase
        // launches a payload .exe out of a user Temp/AppData path.
        $exe  = /Start-Process\b[^\r\n]{0,200}AppData\\[^\r\n]{0,80}\.exe/ ascii wide nocase
        // self-delete of the script itself -- anti-forensics tell.
        $self = "$MyInvocation.MyCommand.Path" ascii wide nocase
    condition:
        filesize < 16KB and $excl and $exe and $self
}

rule VBS_CustomBase64_MSXML_ExecuteGlobal : vbs downloader heuristic suspicious
{
    meta:
        author="mailstrix"
        description="VBS custom-alphabet base64 decoder + MSXML2.ServerXMLHTTP GET of a remote payload, decoded and run via ExecuteGlobal (f6438c51)"
        score="75"
    strings:
        // MSXML server-side HTTP transport used to fetch the stage.
        $http = "MSXML2.ServerXMLHTTP" ascii wide nocase
        // custom-alphabet base64: a Dictionary char map + per-char lookup -- the
        // hand-rolled decoder that defeats base64 string scanners.
        $map  = /CreateObject\(\s*"Scripting\.Dictionary"/ ascii wide nocase
        $resp = ".responseText" ascii wide nocase
        // dynamic execution of the decoded payload -- the delivery primitive.
        $exec = "ExecuteGlobal" ascii wide nocase
    condition:
        filesize < 32KB and $http and $map and $resp and $exec
}

/*
  Third batch (s31): a 3-member PowerShell dropper family the sweep found firing
  only the generic Sus_CMD_Powershell_Usage heuristic (0f21d86b, 2033921b,
  d3fd81d8). Same actor (GitHub raw payload host, a split-string GitHub PAT in
  the Authorization header). Upgrades these from a generic catch-all to a specific,
  higher-confidence family rule. Mechanic shared by all members:
    - a `Get-RandomName` builder picking from a scrambled alphabet via
      `Get-Random -Minimum 0 -Maximum 61` to forge an 8-char temp filename;
    - the random name is written under `$env:TEMP` via `Join-Path`;
    - download-execute-delete: `-OutFile` to that path, `& $path`, then
      `Remove-Item` to clean up.
  The 4-way conjunction (random-name builder + TEMP path + download-to-file +
  self-delete) is the FP guard; no benign script combines all four.
*/

rule PS1_RandomName_Temp_Download_Exec_Delete : powershell loader heuristic suspicious
{
    meta:
        author="mailstrix"
        description="PowerShell dropper: Get-RandomName (Get-Random 0-61) temp filename, Join-Path $env:TEMP, Invoke-WebRequest -OutFile, execute, Remove-Item -- GitHub-raw payload family (0f21d86b/2033921b/d3fd81d8)"
        score="75"
    strings:
        // forge a random filename from a scrambled alphabet.
        $rnd  = /Get-Random\s+-Min(imum)?\s+0\s+-Max(imum)?\s+61/ ascii wide nocase
        // drop it under the user temp dir.
        $temp = /Join-Path[^\r\n]{0,40}\$env:TEMP/ ascii wide nocase
        // download the second stage to that file.
        $out  = "-OutFile" ascii wide nocase
        // anti-forensics cleanup of the dropped payload.
        $rm   = /Remove-Item\b/ ascii wide nocase
    condition:
        filesize < 32KB and $rnd and $temp and $out and $rm
}
