/*
  OLEID indicator rules -- score yarad's oleid-style structural markers.

  yarad's extract.fromOLEIndicators surfaces two structural indicators that
  oletools' oleid reports (oleid.py) as synthetic marker streams, invisible in
  the raw OLE2 bytes:

    - "OLEID-OBJECTPOOL" -- the document carries an ObjectPool storage, i.e. it
      embeds OLE objects (oleid.py:400). A common lure mechanism (embedded
      packager / OLE object that drops or launches a payload).
    - "OLEID-FLASH" -- an embedded Shockwave Flash (SWF) object (oleid.py:490),
      a long-lived exploit-delivery vector.

  Both are presence indicators, NOT conclusive on their own -- a benign document
  can legitimately embed an OLE object. So these are scored LOW; the value is
  that they STACK with other signals (macros, external rels, suspicious
  keywords) the same scan already surfaces. Matching the marker prefix is
  zero-FP by construction (the literal is only ever emitted by yarad).

  Heuristic, tagged `suspicious heuristic` so yara.lua routes them to
  YARA_SUSPICIOUS (operator-tunable).

  Reference: https://github.com/decalage2/oletools/wiki/oleid
*/
rule OLEID_ObjectPool : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Document embeds OLE objects (ObjectPool storage present) -- oleid indicator"
        reference   = "https://github.com/decalage2/oletools/wiki/oleid"
        score       = "10"
    strings:
        $marker = "OLEID-OBJECTPOOL" ascii
    condition:
        filesize < 16MB and $marker
}

rule OLEID_Flash : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Document embeds a Shockwave Flash (SWF) object -- oleid indicator"
        reference   = "https://github.com/decalage2/oletools/wiki/oleid"
        score       = "30"
    strings:
        $marker = "OLEID-FLASH" ascii
    condition:
        filesize < 16MB and $marker
}

/*
  OLE2Link URL moniker -- CVE-2017-0199 / CVE-2017-8570.

  yarad's extract.fromOLE2Link surfaces the URL carried by a Standard URL Moniker
  inside an embedded OLE2Link object as "OLE2LINK-URL <url>". When Office opens
  such a document it auto-resolves that moniker, fetching and executing a remote
  HTA/script payload -- the CVE-2017-0199 family. The marker is only emitted when
  the StdURLMoniker CLSID and a decodable URL are present, so this is an active
  remote-payload lure, not a mere presence indicator: scored HIGH.

  The literal prefix is emitted only by yarad, so matching it is zero-FP by
  construction. An http(s)/file URL inside the marker raises the score further.
*/
rule OLE2Link_URL_Moniker : maldoc exploit malware
{
    meta:
        author      = "yarad"
        description = "Embedded OLE2Link URL moniker (CVE-2017-0199 remote payload auto-load)"
        reference   = "https://www.cve.org/CVERecord?id=CVE-2017-0199"
        score       = "80"
    strings:
        $marker = "OLE2LINK-URL " ascii
        $u_http = "OLE2LINK-URL http" ascii nocase
        $u_smb  = "OLE2LINK-URL \\\\" ascii
    condition:
        filesize < 16MB and $marker and any of ($u_http, $u_smb)
}

/*
  OLETIMES anomaly -- oletools' oletimes (oletimes.py) reports CFB directory-entry
  CreateTime/ModifyTime FILETIMEs. yarad's extract.fromOLETimes surfaces only the
  two anomalies with no benign analogue:

    - "OLETIMES-FUTURE ..."    -- an entry stamped beyond now + 48h clock-skew
      slack. A real document cannot be authored in the future; a fabricated CFB
      with a mis-set builder clock can.
    - "OLETIMES-SYNTHETIC ..." -- >=3 directory entries share one identical
      non-zero (create,modify) pair. Office sets per-entry varied stamps (or
      zero); a mass-fabricated CFB stamps every entry the same.

  Both are heuristic stacking signals, not conclusive alone -- scored LOW. The
  marker prefix is emitted only by yarad, so matching it is zero-FP by
  construction.

  Reference: https://github.com/decalage2/oletools/wiki/oletimes
*/
rule OLETimes_FutureStamp : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "CFB directory entry stamped in the future -- oletimes anomaly"
        reference   = "https://github.com/decalage2/oletools/wiki/oletimes"
        score       = "20"
    strings:
        $marker = "OLETIMES-FUTURE " ascii
    condition:
        filesize < 16MB and $marker
}

rule OLETimes_SyntheticStamps : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Multiple CFB entries share one identical timestamp -- oletimes fabrication tell"
        reference   = "https://github.com/decalage2/oletools/wiki/oletimes"
        score       = "20"
    strings:
        $marker = "OLETIMES-SYNTHETIC " ascii
    condition:
        filesize < 16MB and $marker
}

/*
  Encryption-type + digital-signature markers.

  yarad's extract.fromOLEEncType / fromOLEEncInfo classify the encryption kind
  rather than reporting presence only:

    - "ENCRYPTION-XOR" -- a BIFF8 FILEPASS record using XOR obfuscation. This is
      trivially reversible, NOT real encryption: it is a known trick to slip a
      macro past a naive scanner while looking "protected". Scored higher than
      genuine encryption because it signals intent, not confidentiality.
    - "ENCRYPTION-RC4" / "ENCRYPTION-AES" -- real stream/block ciphers (legacy
      FILEPASS RC4, or an ECMA-376 encrypted OOXML wrapper). The encryption
      itself is the signal (legit senders rarely default-password-encrypt), but
      it is presence-level, so scored LOW.

  extract.fromOLEDigSig emits "DIGITAL-SIGNATURE" when the OLE2 carries a
  _signatures/_xmlsignatures storage. Benign on its own, so scored LOW; the value
  is that it STACKS with macro/keyword signals (a code-signed-looking maldoc).

  All three literals are emitted only by yarad -> matching is zero-FP.

  Reference: https://github.com/decalage2/oletools/wiki/oleid
*/
rule Encrypted_XOR_Obfuscation : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Document uses reversible XOR FILEPASS obfuscation (scanner-evasion tell)"
        reference   = "https://github.com/decalage2/oletools/wiki/oleid"
        score       = "40"
    strings:
        $marker = "ENCRYPTION-XOR" ascii
    condition:
        filesize < 16MB and $marker
}

// extract.fromDefaultPWXOR emits "DEFAULTPW-DECRYPTED" when a BIFF8 workbook
// was encrypted with the VelvetSweatshop transparent password (XOR Method 1)
// AND the decrypted Workbook stream was successfully recovered. The fact that
// the file uses default-password XOR encryption is itself suspicious (it hides
// content from naive scanners while Excel opens it silently), but the real
// weight comes from the recovered XLM macro markers that follow in the stream.
// Scored modestly: DEFAULTPW-DECRYPTED alone just means "interesting"; stacked
// with XLM-HIDDEN-MACROSHEET or XLM-AUTO-OPEN it becomes actionable.
rule DefaultPW_Decrypted : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "BIFF8 workbook decrypted with VelvetSweatshop default password -- scanner-evasion tell"
        reference   = "https://github.com/decalage2/oletools/blob/master/oletools/crypto.py"
        score       = "25"
    strings:
        $marker = "DEFAULTPW-DECRYPTED" ascii
    condition:
        filesize < 16MB and $marker
}

rule Encrypted_Document : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Document is encrypted (RC4/AES) -- presence indicator"
        reference   = "https://github.com/decalage2/oletools/wiki/oleid"
        score       = "15"
    strings:
        $rc4 = "ENCRYPTION-RC4" ascii
        $aes = "ENCRYPTION-AES" ascii
    condition:
        filesize < 16MB and any of them
}

rule Document_DigitalSignature : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Document carries a digital-signature storage -- oleid indicator (stacks with macros)"
        reference   = "https://github.com/decalage2/oletools/wiki/oleid"
        score       = "10"
    strings:
        $marker = "DIGITAL-SIGNATURE" ascii
    condition:
        filesize < 16MB and $marker
}

rule PPT_VBA_Macro : maldoc heuristic
{
    meta:
        author      = "yarad"
        description = "Legacy PowerPoint (.ppt/.pps) file with an embedded VBA macro project (ExternalObjectStorage)"
        reference   = "https://github.com/decalage2/oletools/wiki/ppt_parser"
        score       = "60"
    strings:
        $marker = "PPT-VBA-EXTRACTED" ascii
    condition:
        filesize < 64MB and $marker
}
