rule RTF_DDE_Field : maldoc heuristic suspicious {
    meta:
        description = "RTF document contains a DDE/DDEAUTO field instruction"
        score = 55
    strings:
        $marker = "RTF-DDE-FIELD " ascii
        $dde = "DDE " ascii nocase
        $ddeauto = "DDEAUTO " ascii nocase
    condition:
        $marker
        and any of ($dde, $ddeauto)
}

rule RTF_ObjUpdate : maldoc heuristic suspicious {
    meta:
        description = "RTF document with \\objupdate auto-fetch (CVE-2017-0199 vector)"
        score = 45
    strings:
        $marker = "RTF-OBJUPDATE" ascii
    condition:
        $marker
}
