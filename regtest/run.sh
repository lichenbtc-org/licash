#!/usr/bin/env bash
# The contracts played on a throwaway Bitcoin Core regtest node: the hub
# service's ignored tests (apps/hub/tests/contracts.rs), a release build.
# Arguments go to the test binary: a test's name, --nocapture.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/tmp/regtest"
export TMPDIR="$root/tmp/regtest"
export LICHEN_BITCOIND="${LICHEN_BITCOIND:-$root/regtest/bitcoind-docker.sh}"

if [[ "$LICHEN_BITCOIND" == "$root/regtest/bitcoind-docker.sh" ]]; then
    image="${LICASH_BITCOIN_IMAGE:-bitcoin/bitcoin:30.0}"
    docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
    docker image inspect "$image" --format 'Bitcoin image: {{.Id}}'
fi
export LICASH_LITESTREAM="${LICASH_LITESTREAM:-$root/regtest/litestream-docker.sh}"
if [[ "$LICASH_LITESTREAM" == "$root/regtest/litestream-docker.sh" ]]; then
    image="${LICASH_LITESTREAM_IMAGE:-litestream/litestream:0.5.18}"
    docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
    docker image inspect "$image" --format 'Litestream image: {{.Id}}'
fi

cd "$root"
exec cargo test --release --locked --manifest-path apps/Cargo.toml \
    -p licash-hub-service --test contracts -- --ignored --test-threads=1 "$@"
