#!/bin/sh
# filter_rules_test.sh — assert docker/filter-rules.py (the PERF-25 `mail` profile
# per-rule filter) is CONSERVATIVE: it drops only host/runtime-only rules and
# keeps everything that could plausibly fire on mail.
#
# Pins the four invariants that make the profile safe to ship:
#   1. KEEP-wins — a mail-carrier/family token (STEALER, MALDOC, …) keeps a rule
#      even when a host-only heuristic (Linux-only) would otherwise drop it.
#   2. private helper rules are ALWAYS kept (dropping one dangles referencers).
#   3. genuine host-only classes ARE dropped (MEMORY tag, LOLDRIVERS, MALPEDIA
#      license, pure Linux/ELF with no KEEP token).
#   4. ordinary Windows-family rules with no host-only signal are kept.
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
py="$root/docker/filter-rules.py"
[ -f "$py" ] || { echo "FAIL - $py missing"; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
in="$work/in.yar"
out="$work/out.yar"

cat > "$in" <<'YARA'
rule MALPEDIA_win_foo { meta: license_url = "N/A" strings: $a = "x" condition: $a }
rule SIGBASE_Linux_Implant_ELF { strings: $a = "x" condition: $a }
rule ANYRUN_Maldoc_VBA_Dropper { strings: $a = "x" condition: $a }
rule VENDOR_Linux_AgentTesla_Stealer { strings: $a = "x" condition: $a }
private rule helper_Linux_priv { condition: true }
rule SIGBASE_MEMORY_Cobalt : MEMORY { strings: $a = "x" condition: $a }
rule Generic_Win_Backdoor { strings: $a = "x" condition: $a }
rule SIGBASE_LOLDRIVERS_evil { strings: $a = "x" condition: $a }
YARA

python3 "$py" "$in" "$out" >/dev/null

bad="$work/bad"
: > "$bad"
kept() { grep -qE "(^|[[:space:]])rule[[:space:]]+$1([[:space:]{:]|\$)" "$out"; }

# (1) KEEP-wins: STEALER family token keeps it despite the Linux-only name
kept VENDOR_Linux_AgentTesla_Stealer || echo "KEEP-wins broken: dropped a STEALER family rule" >> "$bad"
# (1) plain maldoc carrier kept
kept ANYRUN_Maldoc_VBA_Dropper || echo "dropped a maldoc carrier rule" >> "$bad"
# (2) private always kept (even with a host-only name)
grep -qE "private[[:space:]]+rule[[:space:]]+helper_Linux_priv" "$out" \
    || echo "private helper dropped (dangling-ref hazard)" >> "$bad"
# (4) ordinary Windows family kept
kept Generic_Win_Backdoor || echo "dropped an ordinary Windows-family rule" >> "$bad"

# (3) host-only classes dropped
kept MALPEDIA_win_foo && echo "MALPEDIA (non-redistributable) not dropped" >> "$bad"
kept SIGBASE_Linux_Implant_ELF && echo "pure Linux/ELF implant not dropped" >> "$bad"
kept SIGBASE_MEMORY_Cobalt && echo "MEMORY-tagged rule not dropped" >> "$bad"
kept SIGBASE_LOLDRIVERS_evil && echo "LOLDRIVERS kernel-driver rule not dropped" >> "$bad"

if [ -s "$bad" ]; then
    echo "FAIL - filter-rules.py is not behaving conservatively:"
    sed 's/^/  /' "$bad"
    exit 1
fi
echo "ok   - filter-rules.py: KEEP-wins + private-kept + host-only-dropped"
echo "ALL OK"
