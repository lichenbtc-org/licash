# Hub service

`licash-hub` runs a Licash hub. It issues and reissues ecash notes, takes
deposits and Lightning payments, and opens the recovery contracts that
protect its users' notes on Bitcoin. When a user recovers, the hub proves
on Bitcoin what her claim is owed. Its users get private, instant payments
and an exit on Bitcoin. In exchange, the hub earns fees on payments and on
the contracts it opens.

## Run it

Use the image `ghcr.io/lichenbtc-org/licash-hub` (it includes the prover),
or build it with `cargo build --release --manifest-path apps/Cargo.toml -p
licash-hub-service`.

```sh
licash-hub --data ./hub init
licash-hub --data ./hub run --network signet --listen 0.0.0.0:8338 \
  --chain http://user:pass@127.0.0.1:38332/wallet/hub --contracts
licash-hub --data ./hub dashboard --network signet
```

`--chain` names a Bitcoin Core node's JSON-RPC (with a wallet, which funds
the contracts' collateral) or an Esplora API. Without it, the hub serves
payments but refuses locks. Keep a copy of `<data>/seed` offline and back up
`<data>/hub.sqlite`.

`licash-hub --help` lists every command, flag and environment variable.
Fees, contracts, Lightning, Tor, Nostr announcements, notifications and
operations are covered in [docs/hub.md](../../docs/hub.md). To deploy a hub
with a hidden standby over WireGuard, and rented GPUs to prove on, follow
[docs/deploy.md](../../docs/deploy.md) with the files in
[deploy/](../../deploy).
