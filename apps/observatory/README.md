# Observatory

`licash-observatory` watches the Licash services of one network (Bitcoin,
signet, mutinynet or regtest) and shows what it sees on a web page:
each hub's and swap provider's uptime, latency and terms, leaderboards,
and what moving value between them costs. It finds services on Nostr and
asks them directly, over Tor, so every service is measured the same way.
Given a monthly budget, it also moves a small balance of its own between
them, at random times, to measure whether payments go through and what
they cost: cheap moves often, dear ones rarely.

## Run it

Use the image `ghcr.io/lichenbtc-org/licash-observatory`, or build it with
`cargo build --release --manifest-path apps/Cargo.toml -p licash-observatory`.

```sh
licash-observatory --data ./observatory run --network signet --budget 5000
LICASH_WALLET=./observatory/signet/wallet.sqlite licash-wallet invoice 20000 --hub https://hub.example --via https://swaps.example
docker run -d -p 8350:8350 -v licash-observatory:/data \
  ghcr.io/lichenbtc-org/licash-observatory run --network signet
```

Open `http://127.0.0.1:8350`. `licash-observatory run --help` lists every
flag and environment variable. What it measures, and how, is in
[docs/observatory.md](../../docs/observatory.md).
