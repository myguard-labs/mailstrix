#!/usr/bin/env bash
# Real final-image contract: inherited daily polling starts; explicit 0 is offline.
set -euo pipefail
image=${1:-strixd:ci}
name="mailstrix-polling-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

for mode in default disabled; do
	override=()
	if [[ $mode == disabled ]]; then
		override=(-e MAILSTRIX_RULES_POLL_INTERVAL=0)
	fi
	# No external service is contacted: a refused loopback connection proves the
	# startup attempt while retaining the baked rules. Match Compose hardening.
	docker run -d --name "$name" --read-only --cap-drop ALL \
		--security-opt no-new-privileges:true \
		--tmpfs /tmp:mode=1777 \
		--tmpfs /var/cache/mailstrix:uid=65532,gid=65532,mode=0755 \
		-p 127.0.0.1::8079 -e MAILSTRIX_TOKEN=ci \
		-e MAILSTRIX_RULES_URL=http://127.0.0.1:1 \
		"${override[@]}" "$image" >/dev/null
	port=$(docker port "$name" 8079/tcp)
	state=''
	# Bound readiness, not test coverage: failure to reach the asserted state
	# fails the test and includes daemon logs. Polling errors must be observable.
	for ((i = 0; i < 60; i++)); do
		state=$(curl -fsS "http://$port/version" 2>/dev/null || true)
		if [[ -n $state ]] && python3 -c '
import json, sys
s = json.load(sys.stdin)["rules_update"]
sys.exit(0 if sys.argv[1] == "disabled" or not s["enabled"] or s["last_failure_unix"] > 0 else 1)
' "$mode" <<<"$state"; then
			break
		fi
		if [[ $(docker inspect -f '{{.State.Running}}' "$name") != true ]]; then
			break
		fi
		sleep 1
	done
	if ! python3 -c '
import json, sys
s = json.load(sys.stdin)["rules_update"]
if sys.argv[1] == "default":
    assert s["enabled"] is True, "packaged default must enable polling"
    assert s["last_check_unix"] > 0, "startup must attempt a rules check"
    assert s["last_failure_unix"] > 0 and s["failures"] >= 1, "offline endpoint must record failure"
else:
    assert s["enabled"] is False, "explicit 0 must disable polling"
    assert s["last_check_unix"] == 0 and s["failures"] == 0, "explicit 0 must perform no startup check"
print("PASS:", sys.argv[1], s)
' "$mode" <<<"$state"; then
		docker logs "$name"
		exit 1
	fi
	curl -fsS "http://$port/ready" >/dev/null
	cleanup
done
