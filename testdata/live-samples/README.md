# Live malware sample corpus

**Real, working malware** pulled from [MalwareBazaar](https://bazaar.abuse.ch/)
(abuse.ch) on 2026-06-23 for testing the yarad scanner against the actual
threat spread that hits the DEB mailscreen stack.

## Safety

- Every sample is stored **zip-wrapped, password `infected`** — exactly as
  MalwareBazaar serves them. **Do NOT unzip on the build host.**
- `*.zip` are **gitignored** (never committed). `MANIFEST.json` (SHA256 +
  metadata only) is tracked.
- To feed yarad without detonating: pass the zip to `/scan`, or unzip in a
  throwaway container only.

## Contents (14 samples)

Spread matches what the mail scanner sees:

| family | types |
|---|---|
| QuasarRAT, PhantomStealer | xlsm (OOXML macros → yarad extract path) |
| AgentTesla | docm (OOXML macros) |
| RemcosRAT | xls (OLE2 macros → yarad extract path), vbs |
| MassLogger | js droppers |
| XWorm | vbs |
| AZORult | OneNote (.one) dropper |
| (unsigned) | lnk, pdf, html phishing |

See `MANIFEST.json` for per-file sha256 / signature / original filename.

## Refresh

```sh
# requires YARAD_MBAZAAR_KEY in env (/etc/myguard-build-env)
python3 <pull script>   # query=get_file_type per type, query=get_file per sha
```

The xls/xlsm/docm samples exercise yarad's OLE/OOXML macro decompressor
(`internal/extract`); the hash set also validates the MalwareBazaar
SHA256-lookup feed (`internal/mbazaar`) — every sample here is a known-bad hash.
