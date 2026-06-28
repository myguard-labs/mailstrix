/*
  OLE CLSID exploit rules — known-malicious class identifiers embedded in Office
  documents (OLE2/RTF/OOXML), matched as raw binary bytes (LE wire format) or as
  the hex-encoded form that appears inside RTF \objdata streams.

  CLSID byte order (OLE LE wire / GUID serialisation):
    Data1 (DWORD) LE | Data2 (WORD) LE | Data3 (WORD) LE | Data4 (8 bytes) BE

  These rules fire on the raw scan surface mailstrix presents to YARA — the
  decompressed/extracted streams from CFB (OLE2) files, the raw RTF body, and
  OOXML ZIP entries. The binary form covers OLE2 directory entries and embedded-
  object headers; the hex form covers RTF \objdata. Both are highly specific
  16-byte sequences with no benign analogue.

  Heuristic confidence varies per CLSID; scored relative to exploit impact.
  Tagged `exploit maldoc` so mailstrix.lua routes to the STRIX_MALWARE tier.
*/

/*
  Shell.Explorer.2 / IE WebBrowser ActiveX control — CVE-2026-21509.

  CLSID {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B} ("Shell.Explorer.2") is the
  Internet Explorer WebBrowser ActiveX control. Embedding it in an Office
  document triggers the CVE-2026-21509 exploit chain on unpatched hosts: the
  control loads a remote URL (embedded in the same object stream) without
  further interaction, fetching and executing an attacker-controlled payload.

  Match targets:
    * Binary CLSID in an OLE2 directory entry / embedded-object header.
    * ASCII hex form in RTF \objdata or OOXML OLE bin entries.

  No benign document legitimately embeds a raw ShellExplorer CLSID.
  Scored HIGH (70) — direct exploit-delivery mechanism.

  Reference: https://www.cve.org/CVERecord?id=CVE-2026-21509
*/
rule OLE_ShellExplorer_CLSID : maldoc exploit cve
{
    meta:
        author      = "mailstrix"
        description = "Shell.Explorer CLSID {EAB22AC3-…} in OLE2/RTF/OOXML — CVE-2026-21509 IE WebBrowser exploit lure"
        reference   = "https://www.cve.org/CVERecord?id=CVE-2026-21509"
        score       = "70"
    strings:
        // {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B} — OLE LE wire bytes
        $clsid_bin = { C3 2A B2 EA C1 30 CF 11 A7 EB 00 00 C0 5B AE 0B }
        // same CLSID ASCII-hex in RTF \objdata or OOXML embedded-OLE bins
        $clsid_hex = "c32ab2eac130cf11a7eb0000c05bae0b" ascii nocase
    condition:
        filesize < 16MB and any of them
}
