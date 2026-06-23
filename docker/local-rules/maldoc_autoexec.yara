/*
  Maldoc_AutoExec_Write_Execute — mraptor-equivalent maldoc heuristic.

  Fires when a single buffer combines all three macro-malware primitive
  classes: an auto-execution trigger, a file-write/drop primitive, and an
  execution/launch primitive. This is the (AutoExec AND Write AND Execute)
  logic of oletools' mraptor, expressed as a YARA rule so it applies to every
  buffer yarad scans — the decompressed VBA macro stream surfaced by the
  extract package AND the raw body / script carriers. There is deliberately NO
  VBA external-variable gate (unlike Didier's vba.yara): yarad only sets VBA=1
  on decompressed macro streams, and gating on it would miss non-Office droppers
  (HTA/WSF/JS, RTF-embedded scripts) and make the rule untestable against a raw
  buffer. The three-category AND is what keeps the false-positive rate low — a
  benign document rarely auto-runs, writes a file, AND launches a process at
  once; that is exactly mraptor's low-FP premise.

  Heuristic, not family/exploit attribution -> tagged `suspicious heuristic`
  so yara.lua's classify() routes it to YARA_SUSPICIOUS (operator-tunable in
  groups.conf), and meta.score is a mid-confidence 0..100 value.
  Reference: https://github.com/decalage2/oletools/wiki/mraptor
*/
rule Maldoc_AutoExec_Write_Execute : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Macro/script combines auto-exec + file-write + execute (mraptor-style heuristic)"
        reference   = "https://github.com/decalage2/oletools/wiki/mraptor"
        score       = "55"
    strings:
        // auto-execution triggers (Word/Excel/VBA entry points)
        $auto1  = "AutoOpen"             ascii wide nocase
        $auto2  = "Auto_Open"            ascii wide nocase
        $auto3  = "AutoExec"             ascii wide nocase
        $auto4  = "AutoClose"            ascii wide nocase
        $auto5  = "Auto_Close"           ascii wide nocase
        $auto6  = "Document_Open"        ascii wide nocase
        $auto7  = "DocumentOpen"         ascii wide nocase
        $auto8  = "Workbook_Open"        ascii wide nocase
        $auto9  = "Document_BeforeClose" ascii wide nocase
        $auto10 = "Workbook_Activate"    ascii wide nocase
        // Template-injection / normal-template hijack entry points.
        // AutoExit/AutoNew fire on document close/new-document-from-template;
        // NewDocument fires on the Normal.dot template path (template injection).
        $auto11 = "AutoExit"             ascii wide nocase
        $auto12 = "AutoNew"              ascii wide nocase
        $auto13 = "NewDocument"          ascii wide nocase
        // Workbook_BeforeClose fires when the workbook is being closed — used by
        // droppers that execute payloads or wipe traces on close (safer than the
        // full close family; mraptor classifies it as auto-exec).
        $auto14 = "Workbook_BeforeClose" ascii wide nocase
        // ActiveX control event handlers abused as autorun (Emotet/Trickbot
        // InkPicture1_Painted era). Suffix-matched and FP-prone on their own —
        // they only ever fire here gated by the write AND execute categories.
        $auto15 = "_Painted"             ascii wide nocase
        $auto16 = "_GotFocus"            ascii wide nocase
        $auto17 = "_LostFocus"           ascii wide nocase
        // file-write / drop primitives
        $write1  = "SaveToFile"           ascii wide nocase
        $write2  = "ADODB.Stream"         ascii wide nocase
        $write3  = "RegWrite"             ascii wide nocase
        $write4  = "CreateTextFile"       ascii wide nocase
        $write5  = "FileCopy"             ascii wide nocase
        $write6  = "CopyHere"             ascii wide nocase
        $write7  = " For Output"          ascii wide nocase
        $write8  = " For Binary"          ascii wide nocase
        $write9  = " For Append"          ascii wide nocase
        // Anti-forensics / XLA persistence primitives.
        // Kill deletes files (trace-removal); AltStartupPath redirects Excel's
        // startup folder so a dropped XLA persists across reboots.
        $write10 = "Kill "               ascii wide nocase
        $write11 = "AltStartupPath"      ascii wide nocase
        // execution / launch / download primitives. Deliberately NOT bare
        // "CreateObject" — that just instantiates a COM object (incl. the write
        // objects like ADODB.Stream), so it would let a writer satisfy the
        // execute category and collapse the three-way AND. Real execution via
        // CreateObject still trips a specific object name below (WScript.Shell,
        // Shell.Application→ShellExecute, MSXML2.XMLHTTP, …).
        $exec1  = "WScript.Shell"          ascii wide nocase
        $exec2  = "ShellExecute"           ascii wide nocase
        $exec3  = "URLDownloadToFile"      ascii wide nocase
        $exec4  = "powershell"             ascii wide nocase
        $exec5  = "cmd.exe"                ascii wide nocase
        $exec6  = "MSXML2.XMLHTTP"         ascii wide nocase
        $exec7  = "WinHttp.WinHttpRequest" ascii wide nocase
        $exec8  = "Shell("                 ascii wide nocase
        // SetTimer schedules an AddressOf callback (timer shellcode runner);
        // ExecuteExcel4Macro runs an XLM string from VBA (VBA->XLM bridge).
        // Both are execution primitives rare in benign VBA.
        $exec9  = "SetTimer"             ascii wide nocase
        $exec10 = "ExecuteExcel4Macro"   ascii wide nocase
        // FollowHyperlink opens a URL/file via the Windows shell (browser or
        // ShellExecute path) — used by droppers to launch a download or spawn
        // a remote payload. Only meaningful stacked with auto-exec + write, which
        // the three-category AND enforces.
        $exec11 = "FollowHyperlink"      ascii wide nocase
    condition:
        filesize < 16MB and
        any of ($auto*) and
        any of ($write*) and
        any of ($exec*)
}
