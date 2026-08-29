#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 leave|prove lxc|docker" >&2
	exit 64
}
[ "$#" -eq 2 ] || usage
mode="$1"
profile="$2"
case "$mode:$profile" in
leave:lxc | leave:docker | prove:lxc | prove:docker) ;;
*) usage ;;
esac

state_root="$(dirname "$(dirname "$RUNNER_TEMP")")"
case "$state_root" in
*/_work | */_work/*)
	echo "runner state root resolves inside _work: $state_root" >&2
	exit 1
	;;
esac
canary="$state_root/.mailstrix-runner-isolation-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${profile}"

if [ "$mode" = leave ]; then
	test ! -e "$canary"
	install -d -m 700 "$canary"
	printf 'must disappear before the next job\n' >"$canary/probe"
	exit 0
fi

if [ -e "$canary" ]; then
	echo "runner state from the previous job survived pristine restore" >&2
	exit 1
fi
