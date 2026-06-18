/*
  Maldoc suspicious-keyword tier — olevba-style keyword heuristics.

  Companion to Maldoc_AutoExec_Write_Execute (maldoc_autoexec.yara, the strict
  mraptor-style autoexec AND write AND execute rule). These two rules cover the
  olevba "Suspicious" keyword surface that the strict triple-AND misses:

    * Maldoc_Suspicious_VBA_Keywords — a COUNT heuristic. olevba flags individual
      suspicious VBA keywords (Shell, CreateObject, Environ, FileSystemObject,
      Chr/StrReverse obfuscation, …); a single keyword is noise, so this rule
      only fires when a buffer combines many of them at once. The "6 of them"
      threshold is what keeps the false-positive rate low — a benign macro rarely
      reaches for half a dozen exec/persist/network/evasion/obfuscation
      primitives together. Mid-LOW confidence -> score 25.

    * Maldoc_VBA_Shellcode_API — a specific high-signal pattern: a VBA `Declare`
      (Win32 API import, with or without PtrSafe) combined with a process-
      injection / shellcode primitive (VirtualAlloc, RtlMoveMemory, CreateThread,
      a hook/callback installer). Benign Office macros almost never allocate
      executable memory or install threads; this is the classic VBA-stomping /
      shellcode-runner shape. Higher confidence -> score 60.

  Both run over every buffer yarad scans — crucially the DECOMPRESSED VBA macro
  stream the extract package surfaces (MS-OVBA), plus raw body / script carriers
  (HTA/WSF/JS) and the single-layer-decoded blobs from decode.go. No VBA external-
  variable gate (same reasoning as maldoc_autoexec.yara): yarad only sets VBA=1
  on decompressed macro streams, and gating would miss non-Office droppers and
  make the rules untestable against a raw buffer. This is keyword heuristics, NOT
  emulation — Chr() concat chains, XLM/Excel-4.0 execution and multi-stage
  unpacking stay with olevba / ViperMonkey (rspamd-olefy).

  Tagged `suspicious heuristic` so yara.lua classify() routes them to
  YARA_SUSPICIOUS (operator-tunable in groups.conf).
  Reference: https://github.com/decalage2/oletools/wiki/olevba
*/

rule Maldoc_Suspicious_VBA_Keywords : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Macro/script combines many suspicious VBA keywords (olevba-style count heuristic)"
        reference   = "https://github.com/decalage2/oletools/wiki/olevba"
        score       = "25"
    strings:
        // execution / launch
        $k01 = "WScript.Shell"              ascii wide nocase
        $k02 = "Shell("                     ascii wide nocase
        $k03 = "ShellExecute"               ascii wide nocase
        $k04 = "vbNormalFocus"              ascii wide nocase
        $k05 = "vbHide"                     ascii wide nocase
        $k06 = "powershell"                 ascii wide nocase
        $k07 = "cmd.exe"                    ascii wide nocase
        // object instantiation / scripting hosts
        $k08 = "CreateObject"               ascii wide nocase
        $k09 = "GetObject"                  ascii wide nocase
        $k10 = "Scripting.FileSystemObject" ascii wide nocase
        $k11 = "Shell.Application"          ascii wide nocase
        // file write / persistence
        $k12 = "SaveToFile"                 ascii wide nocase
        $k13 = "CreateTextFile"             ascii wide nocase
        $k14 = "ADODB.Stream"               ascii wide nocase
        $k15 = "RegWrite"                   ascii wide nocase
        $k16 = " For Output"                ascii wide nocase
        $k17 = " For Binary"                ascii wide nocase
        // network / download
        $k18 = "URLDownloadToFile"          ascii wide nocase
        $k19 = "MSXML2.XMLHTTP"             ascii wide nocase
        $k20 = "Microsoft.XMLHTTP"          ascii wide nocase
        $k21 = "WinHttp.WinHttpRequest"     ascii wide nocase
        $k22 = "InternetOpenUrl"            ascii wide nocase
        // environment / evasion
        $k23 = "Environ"                    ascii wide nocase
        $k24 = "GetSpecialFolder"           ascii wide nocase
        $k25 = "Application.Run"            ascii wide nocase
        // obfuscation primitives
        $k26 = "StrReverse"                 ascii wide nocase
        $k27 = "ChrW("                      ascii wide nocase
        $k28 = "Chr("                       ascii wide nocase
        $k29 = "Xor "                       ascii wide nocase
        $k30 = "ExecuteGlobal"              ascii wide nocase
    condition:
        filesize < 16MB and 6 of them
}

rule Maldoc_VBA_Shellcode_API : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "VBA Declare of a Win32 API combined with a process-injection/shellcode primitive"
        reference   = "https://github.com/decalage2/oletools/wiki/olevba"
        score       = "60"
    strings:
        // a VBA Win32 API import (PtrSafe is the 64-bit form)
        $decl1 = "Declare Function"  ascii wide nocase
        $decl2 = "Declare PtrSafe"   ascii wide nocase
        $decl3 = "Declare Sub"       ascii wide nocase
        // process-injection / shellcode / hook primitives
        $api1  = "VirtualAlloc"       ascii wide nocase
        $api2  = "VirtualProtect"     ascii wide nocase
        $api3  = "RtlMoveMemory"      ascii wide nocase
        $api4  = "CreateThread"       ascii wide nocase
        $api5  = "CreateRemoteThread" ascii wide nocase
        $api6  = "WriteProcessMemory" ascii wide nocase
        $api7  = "SetWindowsHookEx"   ascii wide nocase
        $api8  = "CallWindowProc"     ascii wide nocase
        $api9  = "EnumWindows"        ascii wide nocase
        $api10 = "NtAllocateVirtualMemory" ascii wide nocase
    condition:
        filesize < 16MB and
        any of ($decl*) and
        any of ($api*)
}