#!/bin/sh
# fetch-rules.sh — download the public YARA rulesets baked into the strixd image.
#
# Run at image-build time (after CACHEBUST so a daily rebuild re-pulls the
# latest). Output goes to $1 (default /rules). Each source is fetched into its
# own subtree, then the *.yar/*.yara files we want are flattened into the rules
# dir. A source that 404s or yields no rules is fatal (the build must not
# silently ship fewer rules), unless MAILSTRIX_RULES_OPTIONAL=1.
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

fail() { echo "fetch-rules: $*" >&2; [ "${MAILSTRIX_RULES_OPTIONAL:-0}" = "1" ] || exit 1; }

# LOCAL_ONLY=1 — skip ALL network rule sources (the 8 public feeds) and produce
# an empty fetched set. The compile step still copies docker/local-rules/ in, so
# the resulting .yac is a valid, loadable bundle of our own heuristics only.
# Used by GitHub CI + release builds, where fetching/compiling the full public
# ruleset is too heavy: the real public bundle is built by the local nightly cron
# (docker/generate-rules.sh) and published to the `rules-current` release, which
# strixd pulls at runtime via `--fetch-rules`. The cron does NOT set LOCAL_ONLY.
if [ "${LOCAL_ONLY:-0}" = "1" ]; then
    echo "fetch-rules: LOCAL_ONLY=1 — skipping all network sources (public rules come from the rules-current release)"
    printf '[\n  {"name":"local","repo":"https://github.com/eilandert/mailstrix","license":"MIT","ref":"baked"}\n]\n' > "$OUT/sources.json"
    echo "fetch-rules: wrote $OUT/sources.json (local-only)"
    exit 0
fi

# 1) YARA-Forge bundle — one big .yar of vetted public rules. We pull the FULL
#    tier (~11.7k rules) and run it through filter-yaraforge.py, which prunes
#    per-rule (the bundle is ONE file, so file-level dropping can't touch it):
#      - license: drop MALPEDIA (research-access) + CC-BY-NC; keep permissive +
#        DRL + unresolved (workspace policy 2026-06-29).
#      - mail-relevance (moderate): drop host/runtime-only rules (memory-dump,
#        kernel drivers, Linux/ELF-only, sandbox post-exec); keep maldoc/script
#        + PE dropper/loader/stealer families (closes the clamav-only 35-gap:
#        Hancitor, CVE-2017-11882, LokiBot, Nanocore, AgentTesla, Formbook,
#        Bumblebee, Mallox, …). All private helper rules are preserved (dropping
#        one dangles its referencing rules → compile error).
#    YARAFORGE_SET=core|extended falls back to the UNFILTERED bundle (the filter
#    targets the full tier's breadth); set YARAFORGE_FILTER=0 to skip filtering.
YARAFORGE_SET="${YARAFORGE_SET:-full}"
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
    FILTER_PY="$(dirname "$0")/filter-yaraforge.py"
    find "$TMP/forge" \( -name '*.yar' -o -name '*.yara' \) | while read -r f; do
        dest="$OUT/yaraforge-$(basename "$f")"
        if [ "$YARAFORGE_SET" = "full" ] && [ "${YARAFORGE_FILTER:-1}" = "1" ] \
           && [ -f "$FILTER_PY" ]; then
            python3 "$FILTER_PY" "$f" "$dest" || fail "filter-yaraforge failed"
        else
            cp "$f" "$dest"
        fi
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
        author = "Didier Stevens concept, strixd curated packaging"
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

# 6) InQuest/yara-rules-vt — MIT, small, and particularly useful once strixd can
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

# 8) kevoreilly/CAPEv2 — BSD-3-Clause; the CAPE sandbox's family payload rules.
#    Curated raw-fetch of a handful of files instead of the whole repo tarball:
#    CAPEv2 is a full analysis sandbox (hundreds of MB) and most of its YARA is
#    post-execution / memory-dump rules that never fire on the mail vector. We
#    take only mail-relevant droppers/loaders that add non-duplicate coverage:
#    Guloader (non-PE shellcode trap blobs — complements our Shellcode_GetEIP),
#    Formbook/AgentTesla (stealer payload byte-sigs), Obfuscar (.NET xor stub).
#    All four are module-free (no `import pe`/dotnet), so they compile cleanly in
#    our libyara; compile-rules.sh still test-compiles each file alone and prunes
#    any that fail. Patterns are bounded hex/string atoms — low slow-rule risk;
#    re-profile after adding (run-profile.sh) and add to SLOW_RULE_DENYLIST if any
#    show up hot. CAPE=0 to skip; CAPE_REF to pin a ref.
if [ "${CAPE:-1}" = "1" ]; then
    CAPE_REF="${CAPE_REF:-master}"
    CAPE_RAW="https://raw.githubusercontent.com/kevoreilly/CAPEv2/${CAPE_REF}/data/yara/CAPE"
    echo "fetch-rules: cape <- kevoreilly/CAPEv2@$CAPE_REF (curated)"
    cape_got=0
    for r in Guloader Formbook AgentTesla Obfuscar; do
        if curl -fsSL "$CAPE_RAW/${r}.yar" -o "$OUT/cape-${r}.yar"; then
            cape_got=$((cape_got + 1))
        else
            rm -f "$OUT/cape-${r}.yar"
            echo "fetch-rules: cape ${r}.yar not found (upstream layout changed?)" >&2
        fi
    done
    [ "$cape_got" -gt 0 ] || fail "download cape rules failed (0 of 4 fetched)"
fi

# Build-time rule denylist: rules pruned from the fetched bundle before
# compilation so they are never loaded or run at all.
#
# PERF-12 (2026-06-25): THREE public yaraify rules = 99.3% of ALL scan cost on
# the 14 live samples — each an unanchored short-atom regex on a PE/ELF binary
# rule whose slow string phase runs on every TEXT buffer before its magic
# condition can reject it, matching NOTHING on the mail corpus.
#
# Each entry MUST be a rule that upstream ships in its OWN single-rule file, so
# whole-file removal drops exactly that rule. The three PERF-12 offenders are
# yaraify rules and yaraify splits one rule per file (yaraify-<name>.yar) — safe.
#
# DO NOT add FP/noise rules that live in a shared multi-rule BUNDLE here. The
# pruner removes the whole file, and e.g. yaraforge ships its entire core set
# (5153 rules) as ONE file `yaraforge-yara-rules-core.yar`; a denied rule that
# upstream later bundles into that file would nuke ALL 5153. This actually
# happened: the #223 entry SIGNATURE_BASE_SUSP_Encoded_Discord_Attachment_Oct21_1
# is bundled inside yaraforge core, so the build dropped the whole forge core set
# (live fell 11878 -> 6721 rules) until this guard was added. Suppress benign-mail
# FP/noise rules at RUNTIME via MAILSTRIX_RULE_DENYLIST (comma-sep rule names) in the
# deploy compose instead — that drops match RESULTS without unloading siblings.
#
# Pruned by RULE NAME (robust to upstream file renames). The bundle guard below
# REFUSES to remove any file declaring >1 rule, so a mis-targeted entry can never
# silently blind a whole ruleset. Re-profile after each yaraify refetch (it pulls
# latest daily): new offenders → add here (single-rule files only).
# Full data: memory/eilandert/mailstrix/issues.md "PERF-12".
SLOW_RULE_DENYLIST="Luckyware_Infection_Detection kryptina_encryptor DLL_DiceLoader_Fin7_Feb2024"
for bad in $SLOW_RULE_DENYLIST; do
    # files that DECLARE this rule (anchored `rule <name>` token, not a substring)
    hits="$(grep -rlE "^[[:space:]]*(private[[:space:]]+|global[[:space:]]+)*rule[[:space:]]+${bad}([[:space:]{:]|\$)" "$OUT" 2>/dev/null || true)"
    if [ -z "$hits" ]; then
        echo "fetch-rules: PERF-12 denylist: '$bad' not present (upstream dropped/renamed it?)" >&2
        continue
    fi
    for f in $hits; do
        n="$(grep -cE "^[[:space:]]*(private[[:space:]]+|global[[:space:]]+)*rule[[:space:]]" "$f" 2>/dev/null || echo 0)"
        if [ "$n" -gt 1 ]; then
            # BUNDLE GUARD: refuse to drop a shared multi-rule file — removing it
            # would unload $((n-1)) innocent siblings (e.g. the 5153-rule forge
            # core bundle). Suppress this one at runtime via MAILSTRIX_RULE_DENYLIST.
            echo "fetch-rules: WARNING PERF-12 denylist: SKIP '$bad' — shares $(basename "$f") with $((n-1)) other rule(s); not removing the bundle (use runtime MAILSTRIX_RULE_DENYLIST)" >&2
            continue
        fi
        rm -f "$f"
        echo "fetch-rules: PERF-12 denylist: dropped slow rule '$bad' ($(basename "$f"))"
    done
done

COUNT="$(find "$OUT" -name '*.yar' -o -name '*.yara' | wc -l)"
echo "fetch-rules: $COUNT rule files in $OUT"
[ "$COUNT" -gt 0 ] || fail "no rule files fetched"

# Write sources.json — per-ruleset provenance for `strixd info` / /version.
# Only includes sources that were actually fetched (respects ANYRUN=0 etc).
{
    printf '[\n'
    printf '  {"name":"yaraforge","repo":"https://github.com/YARAHQ/yara-forge","license":"mixed permissive+DRL (MALPEDIA/CC-BY-NC filtered)","ref":"latest","set":"%s","filter":"%s"}' "${YARAFORGE_SET}" "$([ "$YARAFORGE_SET" = full ] && [ "${YARAFORGE_FILTER:-1}" = 1 ] && echo mail-relevance+license || echo none)"
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
    if [ "${CAPE:-1}" = "1" ]; then
        printf ',\n  {"name":"cape","repo":"https://github.com/kevoreilly/CAPEv2","license":"BSD-3-Clause","ref":"%s"}' "${CAPE_REF:-master}"
    fi
    if [ "${YARAIFY:-1}" = "1" ]; then
        printf ',\n  {"name":"yaraify","repo":"https://yaraify.abuse.ch/yarahub/","license":"CC0","ref":"latest"}'
    fi
    printf ',\n  {"name":"local","repo":"https://github.com/eilandert/mailstrix","license":"MIT","ref":"baked"}'
    printf '\n]\n'
} > "$OUT/sources.json"
echo "fetch-rules: wrote $OUT/sources.json"
