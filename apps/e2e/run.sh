#!/usr/bin/env bash
# Bring the regtest ecosystem of docker-compose.yml up, run the end-to-end
# tests against it, save its logs and remove it. Arguments go to the test
# binary, such as a test's name. LICASH_E2E_KEEP=1 keeps the stack up.
set -euo pipefail
cd "$(dirname "$0")"
export LICASH_E2E_PROJECT="${LICASH_E2E_PROJECT:-licash-e2e}"
logs="${LICASH_E2E_LOGS:-$PWD/../target/e2e}"
compose=(docker compose -p "$LICASH_E2E_PROJECT" -f docker-compose.yml)
cleanup() {
    mkdir -p "$logs"
    "${compose[@]}" logs --no-color >"$logs/stack.log" 2>&1 || true
    if [[ -z "${LICASH_E2E_KEEP:-}" ]]; then
        "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
"${compose[@]}" up -d --build --wait
# Bounded, if LICASH_E2E_TIMEOUT says how long (as `timeout` takes it):
# tests out of time are stopped, and the stack's logs kept all the same.
bound=()
if [[ -n "${LICASH_E2E_TIMEOUT:-}" ]]; then
    bound=(timeout "$LICASH_E2E_TIMEOUT")
fi
"${bound[@]}" cargo test --locked -p licash-e2e -- --ignored --test-threads=1 "$@"
