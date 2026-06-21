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
