# Wallet CLI

`licash-wallet` is a Licash wallet for the command line. It is the same
wallet as the Android app, for scripts, servers and tests. It holds your
notes at one or more hubs, pays and receives within a hub, over Lightning
and onchain, and opens the contracts that let you recover your notes on
Bitcoin.

## Try it

Build it with `cargo build --release --manifest-path apps/Cargo.toml -p
licash-wallet-cli`, or run the image `ghcr.io/lichenbtc-org/licash-wallet`.

```sh
licash-wallet init --network signet
licash-wallet discover --relay wss://relay.primal.net   # hubs announced on Nostr
licash-wallet add-hub <URL>
licash-wallet deposit 50000 --via <PROVIDER>  # a Bitcoin address that pays you notes
licash-wallet address                # where other wallets pay you
licash-wallet send <address> 1000 > payment.json
licash-wallet receive payment.json
licash-wallet open-contract <URL>    # protect your notes on Bitcoin
```

Back up the wallet file (`$XDG_DATA_HOME/licash/wallet.sqlite` unless
`--wallet` names another): the seed alone does not restore its notes.

`licash-wallet --help` lists every command. The full reference, covering
payments, Lightning, swaps, contracts and recovery, is in
[docs/wallet-cli.md](../../docs/wallet-cli.md).
