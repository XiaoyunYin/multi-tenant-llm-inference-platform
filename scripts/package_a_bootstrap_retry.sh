#!/bin/sh
# Shared bounded retry primitive used by the host bootstrap and its sh tests.
retry_step() {
    step=$1
    attempts=$2
    attempt_cap_s=$3
    backoff_s=$4
    deadline_epoch=$5
    shift 5
    attempt=1
    while [ "$attempt" -le "$attempts" ]; do
        now_epoch=$(date +%s)
        if [ "$deadline_epoch" != "-" ] && [ $((now_epoch + attempt_cap_s)) -gt "$deadline_epoch" ]; then
            remaining_s=$((deadline_epoch - now_epoch))
            printf 'bootstrap_deadline:%s attempt=%s cap_s=%s remaining_s=%s\n' "$step" "$attempt" "$attempt_cap_s" "$remaining_s" >&2
            return 1
        fi
        started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        printf 'step=%s attempt=%s cap_s=%s start_utc=%s\n' "$step" "$attempt" "$attempt_cap_s" "$started"
        set +e
        timeout "$attempt_cap_s" "$@"
        code=$?
        set -e
        ended=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        printf 'step=%s attempt=%s end_utc=%s exit_code=%s\n' "$step" "$attempt" "$ended" "$code"
        if [ "$code" -eq 0 ]; then
            return 0
        fi
        if [ "$attempt" -eq "$attempts" ]; then
            printf 'bootstrap_retry_exhausted:%s exit_code=%s\n' "$step" "$code" >&2
            return 1
        fi
        sleep "$backoff_s"
        attempt=$((attempt + 1))
    done
}

timed_step() {
    step=$1
    requested_cap_s=$2
    deadline_epoch=$3
    shift 3
    now_epoch=$(date +%s)
    if [ "$requested_cap_s" = "to_deadline" ]; then
        attempt_cap_s=$((deadline_epoch - now_epoch))
        if [ "$attempt_cap_s" -le 0 ]; then
            printf 'bootstrap_deadline:%s attempt=1 cap_s=0 remaining_s=0\n' "$step" >&2
            return 1
        fi
    else
        attempt_cap_s=$requested_cap_s
    fi
    if [ "$deadline_epoch" != "-" ] && [ $((now_epoch + attempt_cap_s)) -gt "$deadline_epoch" ]; then
        remaining_s=$((deadline_epoch - now_epoch))
        printf 'bootstrap_deadline:%s attempt=1 cap_s=%s remaining_s=%s\n' "$step" "$attempt_cap_s" "$remaining_s" >&2
        return 1
    fi
    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf 'step=%s attempt=1 cap_s=%s start_utc=%s\n' "$step" "$attempt_cap_s" "$started"
    set +e
    timeout "$attempt_cap_s" "$@"
    code=$?
    set -e
    ended=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf 'step=%s attempt=1 end_utc=%s exit_code=%s\n' "$step" "$ended" "$code"
    return "$code"
}
