/*
  CANONSTAGER — DLL side-loading shellcode stager (PRC-Nexus / SOGU.SEC).

  CANONSTAGER (MITRE S1237) is a small loader Google/Mandiant attribute to a
  PRC-nexus espionage cluster. It is delivered as a malicious DLL that is
  side-loaded by a legitimate, signed Canon printer-utility EXE
  ("CNMPLog.exe" / Canon IJ tools), abusing the EXE's implicit DLL search order.
  The DLL exports the function names the host Canon binary imports, then loads
  and runs an embedded/next-stage shellcode payload (SOGU.SEC, a PlugX variant).

  ClamAV flags the loaders (Win.Loader.CanonStager) by signature; the structural
  YARA bundle misses them because the payload is a packed/side-loaded PE with no
  document/macro structure to parse. This rule restores family coverage for the
  mail vector (the loader DLL arrives zipped alongside the bait Canon EXE).

  Discriminator: a PE that is NOT the real Canon utility (no Canon company name
  in version info) yet exports the Canon-host import names AND references the
  CNMPLog side-load host — combined with a small DLL footprint. The Canon export
  stub names + the CNMPLog host string together have no benign analogue in an
  email attachment.

  FP-safety: requires the MZ/PE magic, a DLL (not the signed EXE — gated on the
  absence of a Canon legalcopyright), the CNMPLog side-load anchor, AND at least
  two of the side-load export stubs, under a 5 MB size cap. The genuine Canon
  DLLs carry "Canon Inc." in their version resource, which excludes them.

  References:
    https://attack.mitre.org/software/S1237/
    https://cloud.google.com/blog/topics/threat-intelligence/prc-nexus-espionage-targets-diplomats
*/

import "pe"

rule CanonStager_SideLoad_Loader : loader canonstager sogu plugx malware heuristic
{
    meta:
        author      = "mailstrix"
        description = "CANONSTAGER DLL side-loading shellcode stager (PRC-Nexus / SOGU.SEC / PlugX loader)"
        reference   = "https://attack.mitre.org/software/S1237/"
        score       = "80"
    strings:
        // Side-load host: the legitimate Canon utility CANONSTAGER rides on.
        $host1 = "CNMPLog.exe" nocase ascii wide
        $host2 = "CNMPLog" nocase ascii wide
        // Canon utility module/log artifacts the loader masquerades around.
        $art1  = "CNMPLog.dll" nocase ascii wide
        $art2  = "Canon IJ" nocase ascii wide
        // Export-name stubs the loader implements to satisfy the host EXE's
        // imports (Canon utility logging API surface).
        $exp1  = "cnmplog_init" nocase ascii
        $exp2  = "cnmplog_write" nocase ascii
        $exp3  = "cnmplog_close" nocase ascii
        // SOGU.SEC / PlugX next-stage shellcode loader breadcrumbs sometimes
        // present in the stager (decrypt-and-jump scaffolding markers).
        $sg1   = "SOGU" ascii wide
        $sg2   = "DECRYPT_SHELLCODE" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        // Exclude the genuine signed Canon DLL/EXE (carries Canon company info).
        not pe.version_info["CompanyName"] contains "Canon" and
        (
            // Host anchor + at least one export stub or SOGU breadcrumb.
            (any of ($host*) and (2 of ($exp*) or any of ($sg*))) or
            // Or the explicit log-DLL artifact plus an export stub.
            (any of ($art*) and any of ($exp*))
        )
}
