#!/usr/bin/env bash
# Sourced by docker/generate-rules_test.sh, using its isolated command fixtures.
# shellcheck disable=SC2154  # here/test_root/EVENTS/actual are owned by the harness.
assert_loaded_rules_count() {
    local rules="$1" actual count_event
    # An environment override must never replace the count of the loaded bundle.
    run_script RULES_COUNT=999 COUNT_REPORT="check-rules: OK — ${rules} rules loaded (fingerprint fixture)"
    [ "$actual" -eq 0 ] || assert_event "loaded count ${rules} failed"
    assert_receipt verify success "$rules"
    jq -e --argjson expected "$rules" '.rules == $expected' "${EVENTS}.manifest" >/dev/null || assert_event "loaded count ${rules} manifest"
    assert_success_notification_body "loaded count ${rules}" "$rules"
    assert_success_event_order "loaded count ${rules}" 1
    [ "$(grep -c '^count ' "$EVENTS")" -eq 1 ] || assert_event 'local load count'
    count_event="$(grep '^count ' "$EVENTS")"
    [[ "$count_event" == *'--read-only --network none --tmpfs /tmp:rw,nosuid,nodev,size=2g'* ]] || assert_event 'local load isolation'
    [[ "$count_event" == *'--mount type=bind,src='*'/compiled.yac,dst=/compiled.yac,readonly'* ]] || assert_event 'local load exact exported bundle'
    [[ "$count_event" == *"--entrypoint /usr/local/bin/strixd sha256:fixture check-rules -rules /compiled.yac -cache-dir  -seed-rules "* ]] || assert_event 'local load command'
    [ "$(head -n1 "$EVENTS")" = "$count_event" ] || assert_event 'local load must precede publication'
}

assert_bad_count_stops_publication() {
    local actual
    run_script "$@"
    [ "$actual" -eq 1 ] || assert_event "bad count exit: ${actual}"
    assert_receipt build failed
    assert_notification bad-count build failed
    [ "$(grep -Ec '^(create$|upload |verify )' "$EVENTS" || true)" -eq 0 ] || assert_event 'bad count reached publication or download verifier'
}

assert_loaded_rules_count 42
assert_loaded_rules_count 1
assert_loaded_rules_count 2147483647
assert_bad_count_stops_publication COUNT_REPORT='check-rules: OK — 0 rules loaded (fingerprint fixture)'
for invalid_rules in '' -1 +1 01 1.5 1e2 2147483648 9223372036854775808 ' 42' '42 ' $'4\n2'; do
    assert_bad_count_stops_publication COUNT_REPORT="check-rules: OK — ${invalid_rules} rules loaded (fingerprint fixture)"
done
for invalid_report in '' '42' 'check-rules: FAILED' $'check-rules: OK — 42 rules loaded (fingerprint fixture)\nextra'; do
    assert_bad_count_stops_publication COUNT_REPORT="$invalid_report"
done
assert_bad_count_stops_publication FAIL_COUNT=1 COUNT_REPORT='check-rules: OK — 42 rules loaded (fingerprint fixture)'
printf 'PASS: loaded bundle count controls manifest and receipt; invalid count prevents publication\n'
