#!/usr/bin/env bash
# Healthy while every standby in LICASH_STANDBYS took a round within
# LICASH_SYNC_STALE seconds (300): one that has not runs on an old ledger.
set -euo pipefail
read -r -a targets <<<"${LICASH_STANDBYS:?}"
stale="${LICASH_SYNC_STALE:-300}"
stage="${LICASH_SYNC_STAGE:-/stage}"
now=$(date +%s)
for i in $(seq 1 "${#targets[@]}"); do
    ok=$(cat "$stage/.ok-$i" 2>/dev/null || echo 0)
    if ((now - ok > stale)); then
        echo "${targets[$((i - 1))]}: last fed $((now - ok))s ago" >&2
        exit 1
    fi
done
