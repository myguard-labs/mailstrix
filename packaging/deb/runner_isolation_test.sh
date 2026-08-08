#!/bin/sh
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
r="$root/.github/runner"
tmp="$(mktemp -d "$root/.runner-isolation-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
python3 - "$root/.github/workflows" "$r/runner-policy.json" <<'PY'
import pathlib,sys,yaml
w,p=map(pathlib.Path,sys.argv[1:]); policy=yaml.safe_load(p.read_text())
assert policy["runner_group"]["name"]=="mailstrix-jit" and not policy["runner_group"]["default"]
for f in w.glob("*.y*ml"):
 d=yaml.safe_load(f.read_text()) or {}; workflow=d.get("name"); expr="$"+"{{ matrix.profile }}"
 for n,j in d.get("jobs",{}).items():
  x=j.get("runs-on")
  if x is None: continue
  if isinstance(x,dict):
   assert x.get("group")=="mailstrix-jit",f"{f}:{n}"
   a=x.get("labels",[]); assert isinstance(a,list),f"{f}:{n}: labels"
   assert not (isinstance(x.get("group"),str) and "${{" in x["group"])
   assert not any(isinstance(z,str) and "$"+"{{" in z and z!=expr for z in a)
   assert {"self-hosted","mailstrix","ephemeral"}<=set(a)
   dynamic=expr in a
   assert dynamic != bool(set(a)&{"lxc","docker"})
   if dynamic: assert set(j.get("strategy",{}).get("matrix",{}).get("profile",[]))=={"lxc","docker"}
   else: assert len(set(a)&{"lxc","docker"})==1
   roles=set(a)&{"canary-leave","canary-prove"}
   if roles: assert f.name=="runner-isolation.yml" and ((n=="leave-state-outside-work" and roles=={"canary-leave"}) or (n=="prove-state-was-restored" and roles=={"canary-prove"}))
   else: assert not (set(a)-{"self-hosted","mailstrix","ephemeral","lxc","docker"}),f"{f}:{n}: custom"
   role=next(iter(roles),"generic"); route=policy["dispatcher"]["routes"][workflow][n]
   assert route[1]==role and (route[0]=="matrix" or route[0] in a),f"{f}:{n}: route"
   expected={"self-hosted","mailstrix","ephemeral",expr if route[0]=="matrix" else route[0]}
   if role!="generic": expected.add(role)
   assert set(a)==expected,f"{f}:{n}: resolved labels"
  elif isinstance(x,str): assert x=="ubuntu-24.04-arm",f"{f}:{n}: scalar route"
  else: raise AssertionError(f"{f}:{n}: list/custom route")
PY
grep -F "lxc launch \"\$snapshot\" \"\$instance\" --ephemeral -c \"user.mailstrix.jit-key=\$key\"" "$r/jit-lxc-runner.sh" >/dev/null
grep -F 'claim-recorded partial LXC' "$r/reconcile-jit-lxc.sh" >/dev/null
grep -F 'renew_lease' "$r/jit-lxc-runner.sh" >/dev/null
b="$tmp/bin"; mkdir "$b"
cat > "$b/gh" <<'EOF'
#!/bin/sh
cat > "$RUNNER_TEST_TMP/gh"; echo test-jit-config
EOF
cat > "$b/lxc" <<'EOF'
#!/bin/sh
set -eu; d="$RUNNER_TEST_TMP"; echo "$*" >> "$d/calls"
case "$1:$2" in
config:get) case "$3" in *lxc/clean) echo test-lxc-sha;; *docker/clean) echo test-docker-sha;; *) cat "$d/marker";; esac;;
config:set) printf %s "$5" > "$d/marker";;
launch:*) : > "$d/alive"; case "${6:-}" in user.mailstrix.jit-key=*) printf %s "${6#*=}" > "$d/marker";; *) exit 1;; esac;;
list:--format) printf '[{"name":"%s","status":"Running"}]\n' "$RUNNER_TEST_ORPHAN";;
list:*) [ "$RUNNER_TEST_INFO_ERROR" = 0 ] || exit 9; if [ -f "$d/alive" ]; then printf '[{"name":"%s"}]\n' "$2"; else echo '[]'; fi;;
delete:--force) n=0; [ -f "$d/del" ] && n="$(cat "$d/del")"; n=$((n+1)); echo "$n" > "$d/del"; [ "$n" -gt "$RUNNER_TEST_DELETE_FAILS" ] || exit 1; rm -f "$d/alive";;
exec:*) x="$(cat)"; echo "$x" >> "$d/inputs"; if [ "$x" = test-jit-config ]; then [ "$RUNNER_TEST_HANG" = 1 ] && : > "$d/started" && sleep 3; exit "$RUNNER_TEST_RUN_STATUS"; fi;;
*) exit 1;; esac
EOF
chmod 755 "$b/gh" "$b/lxc"
base() {
 RUNNER_TEST_TMP="$tmp"; PATH="$b:$PATH"; RUNNER_GROUP_ID=4242; RUNNER_ATTESTATION_DIR="$tmp/state"
 RUNNER_LXC_SNAPSHOT_SHA256=test-lxc-sha; RUNNER_DOCKER_SNAPSHOT_SHA256=test-docker-sha; GH_TOKEN='test'
 RUNNER_TEST_INFO_ERROR=0; RUNNER_TEST_DELETE_FAILS=0; RUNNER_TEST_HANG=0; RUNNER_TEST_RUN_STATUS=0; RUNNER_TEST_ORPHAN=""
 export RUNNER_TEST_TMP PATH RUNNER_GROUP_ID RUNNER_ATTESTATION_DIR RUNNER_LXC_SNAPSHOT_SHA256 RUNNER_DOCKER_SNAPSHOT_SHA256 GH_TOKEN RUNNER_TEST_INFO_ERROR RUNNER_TEST_DELETE_FAILS RUNNER_TEST_HANG RUNNER_TEST_RUN_STATUS RUNNER_TEST_ORPHAN
}
run() { base; "$r/jit-lxc-runner.sh" --profile "$1" --run-id "$2" --run-attempt 1 --job-id "$3" --role "${4:-generic}" ${5:+--predecessor-key "$5"}; }
run lxc 10 100 canary-leave
leave=r10-a1-j100-lxc-canary-leave
run docker 10 101
jq -e '.schema==2 and .deleted and .key=="r10-a1-j101-docker-generic"' "$tmp/state/receipts/r10-a1-j101-docker-generic.json" >/dev/null
run lxc 10 102 canary-prove "$leave"
tail -n2 "$tmp/inputs"|head -n1|jq -e '.predecessor.key=="r10-a1-j100-lxc-canary-leave"' >/dev/null
base; RUNNER_TEST_INFO_ERROR=1; export RUNNER_TEST_INFO_ERROR
if "$r/jit-lxc-runner.sh" --profile lxc --run-id 11 --run-attempt 1 --job-id 103; then exit 1; fi
[ ! -e "$tmp/state/receipts/r11-a1-j103-lxc-generic.json" ]
base; "$r/jit-lxc-runner.sh" --profile lxc --run-id 11 --run-attempt 1 --job-id 103
[ -e "$tmp/state/receipts/r11-a1-j103-lxc-generic.json" ]
rm -f "$tmp/del"; base; RUNNER_TEST_DELETE_FAILS=1; export RUNNER_TEST_DELETE_FAILS
"$r/jit-lxc-runner.sh" --profile docker --run-id 12 --run-attempt 1 --job-id 104
[ "$(cat "$tmp/del")" -eq 2 ]
base; RUNNER_TEST_RUN_STATUS=42; export RUNNER_TEST_RUN_STATUS
if "$r/jit-lxc-runner.sh" --profile lxc --run-id 13 --run-attempt 1 --job-id 105; then exit 1; else s=$?; fi; [ "$s" -eq 42 ]
rm -f "$tmp/started"; base; RUNNER_TEST_HANG=1; export RUNNER_TEST_HANG
"$r/jit-lxc-runner.sh" --profile docker --run-id 14 --run-attempt 1 --job-id 106 & pid=$!
while [ ! -e "$tmp/started" ]; do sleep 1; done
kill -TERM "$pid"; if wait "$pid"; then exit 1; else s=$?; fi; [ "$s" -eq 143 ]
printf '%s\n' '{"action":"queued","repository":{"full_name":"myguard-labs/mailstrix"},"workflow_job":{"workflow_name":"ci","name":"docker","run_id":20,"run_attempt":2,"id":200,"head_branch":"grind-test","labels":["self-hosted","mailstrix","ephemeral","docker"]}}' > "$tmp/event"
base; "$r/dispatch-workflow-job.sh" --delivery-id 11111111-1111-1111-1111-111111111111 --event "$tmp/event"
[ -f "$tmp/state/receipts/r20-a2-j200-docker-generic.json" ]
n="$(wc -l < "$tmp/calls")"; base; "$r/dispatch-workflow-job.sh" --delivery-id 11111111-1111-1111-1111-111111111111 --event "$tmp/event"; [ "$(wc -l < "$tmp/calls")" -eq "$n" ]
mkdir -p "$tmp/state/deliveries/33333333-3333-3333-3333-333333333333"; printf launching > "$tmp/state/deliveries/33333333-3333-3333-3333-333333333333/state"
base; "$r/dispatch-workflow-job.sh" --delivery-id 33333333-3333-3333-3333-333333333333 --event "$tmp/event"
[ "$(cat "$tmp/state/deliveries/33333333-3333-3333-3333-333333333333/state")" = completed ]
sed 's/myguard-labs\/mailstrix/evil\/repo/' "$tmp/event" > "$tmp/bad"; base; if "$r/dispatch-workflow-job.sh" --delivery-id 22222222-2222-2222-2222-222222222222 --event "$tmp/bad"; then exit 1; fi
old=$(( $(date +%s)-5000 )); base; RUNNER_TEST_ORPHAN="mailstrix-jit-lxc-30-1-300-generic-$old-resume"; export RUNNER_TEST_ORPHAN
echo r30-a1-j300-lxc-generic > "$tmp/marker"; "$r/reconcile-jit-lxc.sh" --dry-run; n="$(cat "$tmp/del")"; "$r/reconcile-jit-lxc.sh" --apply; [ "$(cat "$tmp/del")" -gt "$n" ]
# Claim-recorded partial launches are recovered even when a SIGKILL prevented a
# receipt/marker handoff; a live renewable lease prevents that cleanup.
claim="$tmp/state/claims/r31-a1-j301-lxc-generic"; mkdir -p "$claim/lease"
old_claim=$(( $(date +%s)-5000 )); partial="mailstrix-jit-lxc-31-1-301-generic-$old_claim-resume"
printf '{"key":"r31-a1-j301-lxc-generic","instance":"%s","started_epoch":%s}\n' "$partial" "$old_claim" > "$claim/identity.json"
printf '{"expires_epoch":0}\n' > "$claim/lease/metadata.json"; : > "$tmp/alive"; echo r31-a1-j301-lxc-generic > "$tmp/marker"
base; RUNNER_TEST_ORPHAN=""; export RUNNER_TEST_ORPHAN; "$r/reconcile-jit-lxc.sh" --dry-run
[ -d "$claim" ] && [ -e "$tmp/alive" ]
base; RUNNER_TEST_ORPHAN=""; export RUNNER_TEST_ORPHAN; "$r/reconcile-jit-lxc.sh" --apply
[ ! -d "$claim" ]
[ ! -e "$tmp/alive" ]
failed_claim="$tmp/state/claims/r33-a1-j303-lxc-generic"; mkdir -p "$failed_claim/lease"
printf '{"key":"r33-a1-j303-lxc-generic","instance":"mailstrix-jit-lxc-33-1-303-generic-%s-resume","started_epoch":%s}\n' "$old_claim" "$old_claim" > "$failed_claim/identity.json"
printf '{"expires_epoch":0}\n' > "$failed_claim/lease/metadata.json"; : > "$tmp/alive"; echo r33-a1-j303-lxc-generic > "$tmp/marker"
base; RUNNER_TEST_ORPHAN=""; RUNNER_TEST_DELETE_FAILS=999; export RUNNER_TEST_ORPHAN RUNNER_TEST_DELETE_FAILS
if "$r/reconcile-jit-lxc.sh" --apply; then exit 1; fi
[ -d "$failed_claim" ] && [ -e "$tmp/alive" ]
live="$tmp/state/claims/r32-a1-j302-lxc-generic"; mkdir -p "$live/lease"
printf '{"key":"r32-a1-j302-lxc-generic","instance":"mailstrix-jit-lxc-32-1-302-generic-%s-resume","started_epoch":%s}\n' "$old_claim" "$old_claim" > "$live/identity.json"
printf '{"expires_epoch":9999999999}\n' > "$live/lease/metadata.json"; base; RUNNER_TEST_ORPHAN=""; export RUNNER_TEST_ORPHAN; "$r/reconcile-jit-lxc.sh" --apply
[ -d "$live" ]
echo "ok - structural policy, authoritative absence, retry/status/signal, dedup, and owned reconciliation"
