#!/usr/bin/env python3
"""filter-rules.py — conservative mail-relevance rule filter (the `mail` profile).

PERF-25: the `mail` rule profile prunes, per-rule, only the rules that can NEVER
fire on an email attachment's bytes (host/runtime-only artifacts), leaving every
rule that *might* match mail content. This is the `MAILSTRIX_PROFILE=mail` knob;
`full` skips this filter (every fetched rule kept). Applied to EVERY fetched
source .yar (was yara-forge-only) — the non-forge sources are already hand-curated
at fetch, so the prune mostly bites the broad forge+sigbase sets, but running it
everywhere makes the profile uniform.

CONSERVATIVE by construction — if there is ANY doubt a rule could match mail,
it stays in `mail`:
  - KEEP override wins over every mail-relevance heuristic drop (a maldoc/script/
    dropper/loader/stealer/RAT token in the name keeps the rule).
  - `private` helper rules are ALWAYS kept (dropping one dangles its referencing
    rules → compile error; near-zero match cost anyway).
  - Only host/runtime-ONLY classes are dropped: MEMORY/LOG-tagged, kernel drivers
    (LOLDRIVERS), Linux/ELF/Unix-only families, memory config scanners, pcap /
    network-traffic rules. Everything else is kept.

Two filters, both per-rule, driven by the rule name/tags (+ the meta block where
YARA-Forge embeds it):

  1. LICENSE (yara-forge-scoped) — YARA-Forge prefixes every rule name with its
     upstream source in CAPS, so we can drop MALPEDIA (research-access, not
     redistributable) by prefix and CC-BY-NC by `license_url`. Other sources are
     curated/permissive at fetch, so this gate is a no-op for them (their rule
     names carry no MALPEDIA_ prefix).

  2. MAIL-RELEVANCE (all sources) — the conservative host-only drop above.

A dropped rule is replaced by nothing (the import lines + remaining rules stay a
valid bundle). Reports kept/dropped with reason breakdown. Idempotent; reads one
.yar, writes one filtered .yar.

Usage: filter-rules.py IN.yar OUT.yar
"""
import re
import sys
from collections import Counter

# --- source prefix (rule-name leading TOKEN) → redistribution verdict ----------
# YARA-Forge prefixes every rule name with its upstream source in CAPS.
# Only HARD-DROP sources listed; everything else is kept under the
# "permissive + DRL + N/A" policy.
DROP_SOURCES = {
    "MALPEDIA",  # research access only — not redistributable (license_url N/A)
}

# license_url substrings that mark a non-redistributable (non-commercial) license.
DROP_LICENSE_SUBSTR = (
    "by-nc",            # CC BY-NC*
    "creativecommons.org/licenses/by-nc",
    "noncommercial",
)

# --- mail-relevance: DROP signals (host/runtime-only, never an attachment) -----
# Matched against the rule's tags + name (case-insensitive whole-word where sane).
DROP_TAGS = {
    "MEMORY",      # memory-dump only
    "LOG",         # log-artifact rules
}
# Rule-name / tag tokens that mark host-only classes.
DROP_NAME_SUBSTR = (
    "LOLDRIVERS",      # kernel driver allow/deny — not a mail vector
    "_DRIVER_",
    "MALCONFSCAN",     # memory config scanner
    "_MEMORY_",
    "_PCAP_",
    "_NETWORK_TRAFFIC",
)
# Linux/ELF-only families: e.g. "Linux_", "_ELF_", "Unix_". Mail to a Windows
# user base; keep cross-platform loaders but drop pure-ELF host implants.
LINUX_ONLY_RE = re.compile(r"(?:^|_)(LINUX|ELF|UNIX|FREEBSD)_", re.I)

# --- mail-relevance: KEEP signals (override; the 35-gap + carrier families) ----
# If a rule matches any KEEP token it is kept even if a soft DROP signal hits
# (KEEP wins over the heuristic drops, NOT over license/MALPEDIA/MEMORY).
KEEP_SUBSTR = tuple(s.upper() for s in (
    # document/script carriers
    "MALDOC", "MACRO", "VBA", "OOXML", "RTF", "DOCM", "XLSM", "XLSB", "XLS",
    "DOC_", "PDF", "ONENOTE", "LNK", "HTA", "VBS", "JS_", "JSE", "WSF",
    "POWERSHELL", "PS1", "SCRIPT", "DDE", "EQUATION", "CVE_2017_11882",
    "CVE_2017_8759", "CVE_2022_30190", "FOLLINA", "PHISH", "DROPPER",
    "DOWNLOADER", "LOADER", "STEALER", "RAT_", "_RAT", "KEYLOGGER",
    # 35-gap families
    "HANCITOR", "LOKIBOT", "NANOCORE", "AGENTTESLA", "AGENT_TESLA", "FORMBOOK",
    "BUMBLEBEE", "MALLOX", "TARGETCOMPANY", "GULOADER", "EMOTET", "QAKBOT",
    "ICEDID", "REMCOS", "ASYNCRAT", "SNAKE", "GuLoader".upper(),
))


def split_rules(text):
    """Yield (preamble_or_rule_text, is_rule, name, tags, license_url) chunks.

    Brace-balanced scan: handles `{...}` inside strings/conditions. Comments and
    string literals are NOT brace-counted (a `{` inside a // or "…" must not
    open a block)."""
    # Header (imports/comments) up to first `rule `.
    m = re.search(r"^\s*(?:private\s+|global\s+)*rule\s", text, re.M)
    if not m:
        yield text, False, None, None, None, False
        return
    header = text[:m.start()]
    yield header, False, None, None, None, False

    i = m.start()
    n = len(text)
    rule_re = re.compile(
        r"(?:private\s+|global\s+)*rule\s+([A-Za-z_][\w]*)", re.M)
    while i < n:
        rm = rule_re.search(text, i)
        if not rm:
            # trailing whitespace/comments
            yield text[i:], False, None, None, None, False
            break
        # emit any inter-rule gap (whitespace/comments) as a non-rule chunk
        if rm.start() > i:
            yield text[i:rm.start()], False, None, None, None, False
            i = rm.start()
        name = rm.group(1)
        # find opening brace of the rule body
        brace = text.find("{", rm.end())
        if brace == -1:
            yield text[i:], False, None, None, None, False
            break
        depth = 0
        j = brace
        in_str = None  # quote char or None
        in_regex = False  # inside a /.../ regex literal
        in_line_comment = False
        in_block_comment = False
        prev_sig = "{"  # last significant (non-space) char — to disambiguate `/`
        while j < n:
            c = text[j]
            nx = text[j + 1] if j + 1 < n else ""
            if in_line_comment:
                if c == "\n":
                    in_line_comment = False
            elif in_block_comment:
                if c == "*" and nx == "/":
                    in_block_comment = False
                    j += 1
            elif in_str is not None:
                if c == "\\":
                    j += 1
                elif c == in_str:
                    in_str = None
            elif in_regex:
                # A regex ends at an unescaped `/`. `[...]` classes may contain
                # an escaped `/`; we only honor `\/` as escaped, good enough for
                # YARA's flat regexes (no nested unescaped `/` in a class here).
                if c == "\\":
                    j += 1
                elif c == "/":
                    in_regex = False
            else:
                if c == "/" and nx == "/":
                    in_line_comment = True
                    j += 1
                elif c == "/" and nx == "*":
                    in_block_comment = True
                    j += 1
                elif c == "/" and prev_sig in ("=", "(", ",", "|", "&"):
                    # `/` after an operator/'(' starts a regex literal
                    # ($re = /.../, condition: ... matches /.../ ).
                    in_regex = True
                elif c == '"':
                    in_str = '"'
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
            if not c.isspace():
                prev_sig = c
            j += 1
        body = text[i:j]
        tags_m = re.search(r'tags = "([^"]*)"', body)
        lic_m = re.search(r'license_url = "([^"]*)"', body)
        tags = tags_m.group(1) if tags_m else ""
        lic = lic_m.group(1) if lic_m else ""
        # `private`/`global` keywords sit in rm.group(0) before `rule`.
        is_private = "private" in rm.group(0)
        yield body, True, name, tags, lic, is_private
        # consume inter-rule whitespace into next chunk start
        i = j


def source_prefix(name):
    return name.split("_", 1)[0].upper() if name else ""


def verdict(name, tags, lic):
    """Return (keep: bool, reason: str)."""
    up_name = name.upper()
    up_tags = (tags or "").upper()
    src = source_prefix(name)

    # --- license gate (hard) ---
    if src in DROP_SOURCES:
        return False, "license:malpedia"
    low_lic = (lic or "").lower()
    if any(s in low_lic for s in DROP_LICENSE_SUBSTR):
        return False, "license:non-commercial"

    # --- KEEP override (mail carriers / 35-gap families) ---
    keep_hit = any(k in up_name for k in KEEP_SUBSTR)

    # --- mail-relevance drops (host/runtime only) ---
    tagset = {t.strip() for t in up_tags.split(",") if t.strip()}
    if tagset & DROP_TAGS:
        return False, "mail:memory/log"
    if any(s in up_name for s in DROP_NAME_SUBSTR):
        return False, "mail:host-artifact"
    if not keep_hit and LINUX_ONLY_RE.search(name):
        return False, "mail:linux-only"

    return True, "keep"


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: filter-rules.py IN.yar OUT.yar")
    src_path, out_path = sys.argv[1], sys.argv[2]
    text = open(src_path, encoding="utf-8", errors="replace").read()

    kept_chunks = []
    reasons = Counter()
    n_rules = 0
    for chunk, is_rule, name, tags, lic, is_private in split_rules(text):
        if not is_rule:
            kept_chunks.append(chunk)
            continue
        n_rules += 1
        if is_private:
            # Always keep private helper rules: they never match on their own
            # (tiny cost) and dropping one dangles every public rule that
            # references it → compile error.
            reasons["keep:private"] += 1
            kept_chunks.append(chunk)
            continue
        keep, reason = verdict(name, tags, lic)
        reasons[reason] += 1
        if keep:
            kept_chunks.append(chunk)

    out = "".join(kept_chunks)
    open(out_path, "w", encoding="utf-8").write(out)

    kept = reasons["keep"] + reasons["keep:private"]
    dropped = n_rules - kept
    print(f"filter-rules: {n_rules} rules in → {kept} kept "
          f"({reasons['keep:private']} private) → {dropped} dropped")
    for r, c in reasons.most_common():
        if not r.startswith("keep"):
            print(f"  drop {r}: {c}")


if __name__ == "__main__":
    main()
