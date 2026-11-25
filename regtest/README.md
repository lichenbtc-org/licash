# The contract's crates, and the contracts on Bitcoin

`regtest/Cargo.toml` is the workspace of the recovery contract's crates,
`crates/licash-contract` (Licash's front on Lichen's BABE graph, its
opening and its dispute) and `crates/licash-hp` (the hub's statement),
kept apart from the library's: they pull Lichen from git, at the revision
`regtest/Cargo.lock` pins.

The contracts are played on Bitcoin by the hub service's tests
(`apps/hub/tests/contracts.rs`): a wallet opens contracts at the hub
service over HTTP on a fresh Bitcoin Core 30 regtest node, under the mock
authority (the garbled circuits are real; proofs are mocked), and forces
them closed.

## Prerequisites

Rust and Docker. Each node runs in its own throwaway `bitcoin/bitcoin:30.0` container with a
fresh datadir under `tmp/`. `LICHEN_BITCOIND` selects another `bitcoind`
binary and `LICASH_BITCOIN_IMAGE` another image.

The test of a hub restored from a Litestream replica runs Litestream in
throwaway `litestream/litestream:0.5.18` containers, `tmp/regtest`
mounted at its own path (`regtest/litestream-docker.sh`).
`LICASH_LITESTREAM` selects another `litestream` binary and
`LICASH_LITESTREAM_IMAGE` another image.

## Run

From the repository root:

```sh
cargo test --release --locked --manifest-path regtest/Cargo.toml -p licash-contract -p licash-hp
regtest/run.sh                    # the contracts on Bitcoin Core
regtest/run.sh --nocapture        # with their output
```
