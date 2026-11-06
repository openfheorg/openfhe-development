#!/usr/bin/env bash
# Runs one unit-test binary under GNU time and reports memory usage:
#   - the test process's own peak RSS
#   - the highest sampled machine-wide memory use while the test ran, which
#     also covers anything else active on a shared runner. Sampling every
#     5 seconds makes this a lower bound on the true high-water mark.
# Both are printed to the step log and appended as a table row to the job
# summary shown on the workflow run page. If GNU time is not installed on the
# runner, the test runs exactly as before and only a notice is printed.
#
# Usage: run-test-with-memory.sh <label> <test-binary> [args...]

set -uo pipefail

label="$1"
shift

if ! /usr/bin/time --version 2>&1 | grep -qi "GNU time"; then
    echo "GNU time not found; running the test without memory reporting"
    exec "$@"
fi

workdir="$(mktemp -d)"
sampler=""

stop_sampler() {
    if [[ -n "$sampler" ]]; then
        kill "$sampler" 2>/dev/null || true
        wait "$sampler" 2>/dev/null || true
        sampler=""
    fi
}

cleanup() {
    stop_sampler
    rm -rf -- "$workdir"
}

trap cleanup EXIT

# Sample MemAvailable every 5 seconds for the sampled machine-wide high.
(
    while :; do
        awk '/^MemAvailable:/{print $2}' /proc/meminfo
        sleep 5
    done
) > "$workdir/available" &
sampler=$!

/usr/bin/time --format="peak_rss_kib=%M elapsed=%E cpu=%P" \
    --output="$workdir/time" "$@"
status=$?

stop_sampler

# On an OOM kill this also prints GNU time's "Command terminated by ..." line.
cat "$workdir/time"

total_kib=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
min_available_kib=$(sort -n "$workdir/available" | head -n1)
peak_rss_kib=$(grep -o 'peak_rss_kib=[0-9]*' "$workdir/time" | cut -d= -f2)
elapsed=$(grep -o 'elapsed=[^ ]*' "$workdir/time" | cut -d= -f2)

if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -n "$peak_rss_kib" && -n "$min_available_kib" ]]; then
    {
        echo ""
        echo "### Unit-test memory usage"
        echo ""
        echo "| Test | Result | Peak RSS | System high (sampled) | Elapsed |"
        echo "|------|--------|---------:|----------------------:|--------:|"
    } >> "$GITHUB_STEP_SUMMARY"
    result="passed"
    [[ "$status" -ne 0 ]] && result="failed ($status)"
    echo "| $label | $result | $((peak_rss_kib / 1024)) MiB | $(((total_kib - min_available_kib) / 1024)) MiB | $elapsed |" \
        >> "$GITHUB_STEP_SUMMARY"
fi

exit "$status"
