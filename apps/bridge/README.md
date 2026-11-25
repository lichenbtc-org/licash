# NWC bridge

`licash-bridge` lets apps pay and be paid through Nostr Wallet Connect,
out of accounts it keeps over a Licash wallet of its own at one hub, with
optional Lightning Addresses and zaps. It is custodial: the bridge holds
what its accounts do. Run it for yourself, paired with your wallet, or,
with `--open`, for anyone, within limits, announced on Nostr for wallets
to find. Its notes can be exported to a wallet with a recovery contract at
its hub, should the hub stop cooperating.

## Run it

Use the image `ghcr.io/lichenbtc-org/licash-bridge`, or build it with
`cargo build --release --manifest-path apps/Cargo.toml -p licash-bridge`.

```sh
licash-bridge --data ./bridge init --network signet --hub https://hub.example
licash-bridge --data ./bridge run --listen 0.0.0.0:8090 --relay wss://relay.example
licash-wallet bridge add http://127.0.0.1:8090 --pairing CODE
licash-wallet bridge top-up 10000
licash-wallet bridge connect "my app" --pay --budget 5000 --qr
```

`licash-bridge --help` lists every command, flag and environment variable.
Accounts, apps, limits, Lightning Addresses, announcements and exports
are covered in [docs/bridge.md](../../docs/bridge.md).
