#!/bin/sh
# fetch-rules.sh — download the public YARA rulesets baked into the yarad image.
#
# Run at image-build time (after CACHEBUST so a daily rebuild re-pulls the
# latest). Output goes to $1 (default /rules). Each source is fetched into its
# own subtree, then the *.yar/*.yara files we want are flattened into the rules
# dir. A source that 404s or yields no rules is fatal (the build must not
# silently ship fewer rules), unless YARAD_RULES_OPTIONAL=1.
#
# Sources (override with env to pin a tag/commit):
#   YARAFORGE_SET  — YARA-Forge package: core (default), extended, or full
#   YARAFORGE_URL  — explicit YARA-Forge package URL (wins over YARAFORGE_SET)
#   SIGBASE_REF    — Neo23x0/signature-base git ref (default master)
#   ANYRUN_REF     — anyrun/YARA git ref (default main); ANYRUN=0 to skip
#   DIDIER_REF     — DidierStevens/DidierStevensSuite git ref (default master);
#                    DIDIER=0 to skip. Public-domain OLE/RTF/maldoc rules.
#   BARTBLAZE_REF  — bartblaze/Yara-rules git ref (default master); BARTBLAZE=0
#                    to skip. MIT; maldoc/RTF/phishing + malware families. NOT in
#                    YARA-Forge (ReversingLabs/Trellix-ATR already are — don't add
#                    those raw, they'd duplicate Forge core under prefixed names).
#   INQUEST_REF    — InQuest/yara-rules-vt git ref (default main); INQUEST=0 to
#                    skip. MIT; curated mail-carrier rules (PDF/LNK/OneNote/RTF).
set -eu

OUT="${1:-/rules}"
mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "fetch-rules: $*" >&2; [ "${YARAD_RULES_OPTIONAL:-0}" = "1" ] || exit 1; }

# 1) YARA-Forge bundle — one curated .yar of vetted public rules. Core stays the
#    default for production stability; extended/full are opt-in build profiles.
YARAFORGE_SET="${YARAFORGE_SET:-core}"
case "$YARAFORGE_SET" in
    core|extended|full) ;;
    *) fail "invalid YARAFORGE_SET=$YARAFORGE_SET (want core, extended, or full)" ;;
esac
if [ -z "${YARAFORGE_URL:-}" ]; then
    YARAFORGE_URL="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-${YARAFORGE_SET}.zip"
fi
echo "fetch-rules: YARA-Forge $YARAFORGE_SET <- $YARAFORGE_URL"
if curl -fsSL "$YARAFORGE_URL" -o "$TMP/forge.zip"; then
    unzip -o -q "$TMP/forge.zip" -d "$TMP/forge" || fail "unzip yara-forge failed"
    find "$TMP/forge" \( -name '*.yar' -o -name '*.yara' \) | while read -r f; do
        cp "$f" "$OUT/yaraforge-$(basename "$f")"
    done
else
    fail "download yara-forge failed"
fi

# 2) Neo23x0 signature-base — broad community malware/phishing rules.
SIGBASE_REF="${SIGBASE_REF:-master}"
echo "fetch-rules: signature-base <- Neo23x0@$SIGBASE_REF"
if curl -fsSL "https://github.com/Neo23x0/signature-base/archive/${SIGBASE_REF}.tar.gz" -o "$TMP/sigbase.tgz"; then
    tar -xzf "$TMP/sigbase.tgz" -C "$TMP"
    # Only the yara/ subtree; skip rules that reference external modules we
    # don't load (cuckoo/androguard) by leaving those to compile-time pruning.
    find "$TMP"/signature-base-*/yara \( -name '*.yar' -o -name '*.yara' \) | while read -r f; do
        cp "$f" "$OUT/sigbase-$(basename "$f")"
    done
else
    fail "download signature-base failed"
fi

# 3) ANY.RUN — actively maintained malware-family + phishing rules (repo root).
#    Mail-relevant (html_phishing_campaign, corrupted_docs, loader families).
if [ "${ANYRUN:-1}" = "1" ]; then
    ANYRUN_REF="${ANYRUN_REF:-main}"
    echo "fetch-rules: anyrun <- anyrun/YARA@$ANYRUN_REF"
    if curl -fsSL "https://github.com/anyrun/YARA/archive/${ANYRUN_REF}.tar.gz" -o "$TMP/anyrun.tgz"; then
        tar -xzf "$TMP/anyrun.tgz" -C "$TMP"
        find "$TMP"/YARA-* \( -name '*.yar' -o -name '*.yara' \) | while read -r f; do
            cp "$f" "$OUT/anyrun-$(basename "$f")"
        done
    else
        fail "download anyrun failed"
    fi
fi

# 4) Didier Stevens Suite — public-domain ("Source code put in public domain by
#    Didier Stevens, no Copyright") OLE/RTF/maldoc inspection rules. The repo is
#    his whole tool suite; we take only the mail-relevant maldoc/VBA/RTF files and
#    deliberately SKIP the rest — especially the two peid-userdb-rules-*.yara
#    files, which are thousands of PEiD packer signatures (server/PE forensics,
#    not mail) that ballooned the bundle past 18k rules and that yarac flags as
#    slow. Curated list keeps the count and tail-latency sane for 1000 msg/s.
if [ "${DIDIER:-1}" = "1" ]; then
    DIDIER_REF="${DIDIER_REF:-master}"
    echo "fetch-rules: didier <- DidierStevens/DidierStevensSuite@$DIDIER_REF (curated)"
    if curl -fsSL "https://github.com/DidierStevens/DidierStevensSuite/archive/${DIDIER_REF}.tar.gz" -o "$TMP/didier.tgz"; then
        tar -xzf "$TMP/didier.tgz" -C "$TMP"
        for r in vba rtf maldoc contains_vbe_file contains_pe_file; do
            f="$(find "$TMP"/DidierStevensSuite-* -name "${r}.yara" 2>/dev/null | head -1)"
            if [ -n "$f" ]; then
                cp "$f" "$OUT/didier-${r}.yara"
            else
                echo "fetch-rules: didier ${r}.yara not found (upstream layout changed?)" >&2
            fi
        done
        cat > "$OUT/didier-pdf-activemime.yara" <<'YARA'
/*
  PDF/ActiveMime polyglot maldoc detector, based on Didier Stevens' public
  PDF/ActiveMime write-up. Kept tiny and mail-focused: a PDF header plus the
  ActiveMime base64 marker. The chunk markers catch simple whitespace-split
  base64 without adding broad regexes that yarac flags as slow.
  Reference: https://blog.didierstevens.com/2023/08/29/quickpost-pdf-activemime-maldocs-yara-rule/
*/
rule Didier_PDF_ActiveMime_Maldoc : pdf maldoc activemime
{
    meta:
        author = "Didier Stevens concept, yarad curated packaging"
        description = "Detects PDF/ActiveMime polyglot maldocs"
        reference = "https://blog.didierstevens.com/2023/08/29/quickpost-pdf-activemime-maldocs-yara-rule/"
        license = "public domain"
    strings:
        $pdf = "%PDF-"
        $activemime_b64 = "ActiveMime" base64 ascii
        $am_chunk1 = "QWN0"
        $am_chunk2 = "aXZl"
        $am_chunk3 = "TWlt"
    condition:
        filesize < 25MB and
        $pdf at 0 and
        ($activemime_b64 or all of ($am_chunk*))
}
YARA
    else
        fail "download didier suite failed"
    fi
fi

# 5) bartblaze/Yara-rules — MIT; maldoc/RTF (RoyalRoad_RTF, OLEfile_in_CAD),
#    phishing-doc/PDF + malware-family rules. NOT aggregated by YARA-Forge, so it
#    adds non-duplicate coverage. Modules used (dotnet/hash/math/pe) are all
#    default-built in our libyara.
if [ "${BARTBLAZE:-1}" = "1" ]; then
    BARTBLAZE_REF="${BARTBLAZE_REF:-master}"
    echo "fetch-rules: bartblaze <- bartblaze/Yara-rules@$BARTBLAZE_REF"
    if curl -fsSL "https://github.com/bartblaze/Yara-rules/archive/${BARTBLAZE_REF}.tar.gz" -o "$TMP/bartblaze.tgz"; then
        tar -xzf "$TMP/bartblaze.tgz" -C "$TMP"
        find "$TMP"/Yara-rules-* \( -name '*.yar' -o -name '*.yara' \) | while read -r f; do
            cp "$f" "$OUT/bartblaze-$(basename "$f")"
        done
    else
        fail "download bartblaze failed"
    fi
fi

# 6) InQuest/yara-rules-vt — MIT, small, and particularly useful once yarad can
#    surface Windows/mail carriers. Curated instead of whole-repo: skip pure file
#    identifiers, broad informational rules, and rules yarac flags as slow (e.g.
#    PDF_with_Embedded_RTF_OLE_Newlines.yar).
if [ "${INQUEST:-1}" = "1" ]; then
    INQUEST_REF="${INQUEST_REF:-main}"
    echo "fetch-rules: inquest <- InQuest/yara-rules-vt@$INQUEST_REF (curated)"
    if curl -fsSL "https://github.com/InQuest/yara-rules-vt/archive/${INQUEST_REF}.tar.gz" -o "$TMP/inquest.tgz"; then
        tar -xzf "$TMP/inquest.tgz" -C "$TMP"
        for r in \
            CVE_2014_1761.yar \
            Hex_Encoded_Link_in_RTF.yar \
            JS_PDF_Data_Submission.yar \
            Microsoft_LNK_with_CMD_EXE_Reference.yar \
            Microsoft_LNK_with_PowerShell_Shortcut_References.yar \
            Microsoft_LNK_with_Windows_Management_Instrumentation_Reference.yar \
            Microsoft_OneNote_with_Suspicious_String.yar \
            Microsoft_Outlook_Phish.yar \
            PDF_Launch_Action_EXE.yar \
            PDF_Launch_Function.yar \
            PDF_with_Launch_Action_Function.yar \
            Powershell_Command_Fileless_August_Malware.yar \
            RTF_Composite_Moniker.yar \
            RTF_Embedded_OLE_Header_Obfuscated.yar \
            RTF_Memory_Corruption_Vulnerability.yar \
            RTF_with_Suspicious_File_Extension.yar \
            Suspicious_CLSID_RTF.yar
        do
            f="$(find "$TMP"/yara-rules-vt-* -name "$r" 2>/dev/null | head -1)"
            if [ -n "$f" ]; then
                cp "$f" "$OUT/inquest-$r"
            else
                echo "fetch-rules: inquest $r not found (upstream layout changed?)" >&2
            fi
        done
    else
        fail "download inquest yara-rules-vt failed"
    fi
fi

# 7) abuse.ch YARAify (YARAhub) — community malware-family rules curated from
#    live ThreatFox/MalwareBazaar hunting. Fresh family coverage (stealers,
#    loaders, RATs, ransomware) that complements the broader forge/sigbase sets.
#    Whole-zip: per-file test-compile in compile-rules.sh prunes any rule that
#    references a module we don't load or fails yarac, so a noisy community rule
#    can't break the bundle. YARAIFY=0 to skip; YARAIFY_URL to override.
if [ "${YARAIFY:-1}" = "1" ]; then
    YARAIFY_URL="${YARAIFY_URL:-https://yaraify.abuse.ch/yarahub/yaraify-rules.zip}"
    echo "fetch-rules: yaraify <- $YARAIFY_URL"
    if curl -fsSL "$YARAIFY_URL" -o "$TMP/yaraify.zip"; then
        unzip -o -q "$TMP/yaraify.zip" -d "$TMP/yaraify" || fail "unzip yaraify failed"
        find "$TMP/yaraify" \( -name '*.yar' -o -name '*.yara' \) | while read -r f; do
            cp "$f" "$OUT/yaraify-$(basename "$f")"
        done
    else
        fail "download yaraify failed"
    fi
fi

COUNT="$(find "$OUT" -name '*.yar' -o -name '*.yara' | wc -l)"
echo "fetch-rules: $COUNT rule files in $OUT"
[ "$COUNT" -gt 0 ] || fail "no rule files fetched"

# Write sources.json — per-ruleset provenance for `yarad info` / /version.
# Only includes sources that were actually fetched (respects ANYRUN=0 etc).
{
    printf '[\n'
    printf '  {"name":"yaraforge","repo":"https://github.com/YARAHQ/yara-forge","license":"mixed (see repo)","ref":"latest","set":"%s"}' "${YARAFORGE_SET}"
    printf ',\n  {"name":"signature-base","repo":"https://github.com/Neo23x0/signature-base","license":"CC BY-NC 4.0","ref":"%s"}' "${SIGBASE_REF}"
    if [ "${ANYRUN:-1}" = "1" ]; then
        printf ',\n  {"name":"anyrun","repo":"https://github.com/anyrun/YARA","license":"MIT","ref":"%s"}' "${ANYRUN_REF:-main}"
    fi
    if [ "${DIDIER:-1}" = "1" ]; then
        printf ',\n  {"name":"didier","repo":"https://github.com/DidierStevens/DidierStevensSuite","license":"public domain","ref":"%s"}' "${DIDIER_REF:-master}"
    fi
    if [ "${BARTBLAZE:-1}" = "1" ]; then
        printf ',\n  {"name":"bartblaze","repo":"https://github.com/bartblaze/Yara-rules","license":"MIT","ref":"%s"}' "${BARTBLAZE_REF:-master}"
    fi
    if [ "${INQUEST:-1}" = "1" ]; then
        printf ',\n  {"name":"inquest","repo":"https://github.com/InQuest/yara-rules-vt","license":"MIT","ref":"%s"}' "${INQUEST_REF:-main}"
    fi
    if [ "${YARAIFY:-1}" = "1" ]; then
        printf ',\n  {"name":"yaraify","repo":"https://yaraify.abuse.ch/yarahub/","license":"CC0","ref":"latest"}'
    fi
    printf ',\n  {"name":"local","repo":"https://github.com/eilandert/rspamd-yarad","license":"MIT","ref":"baked"}'
    printf '\n]\n'
} > "$OUT/sources.json"
echo "fetch-rules: wrote $OUT/sources.json"
