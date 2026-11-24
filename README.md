# Licash

![Licash](assets/brand/banner.png)

**A private Bitcoin checking account that you can always take back on
Bitcoin.**

Licash is ecash with an exit. A hub issues notes that you pay with
instantly, privately and almost for free. Unlike ordinary ecash, you hold an
individual Bitcoin contract with the hub. It lets you recover your notes on
Bitcoin without the hub's cooperation, up to a limit you choose, like
insurance. You never prove anything to recover: the hub must prove,
with a payment you signed, that you are owed less.

It is not meant for your savings. Keep those in cold storage, and use Licash
for day-to-day spending, as a checking account.

|                                          | Lightning (phone wallet + LSP)      | Ark                             | Ecash mint         | Licash                                                     |
| ---------------------------------------- | ----------------------------------- | ------------------------------- | ------------------ | ---------------------------------------------------------- |
| Back on Bitcoin without the operator     | Yes                                 | Yes, if refreshed before expiry | No                 | Yes, up to the cap you chose                               |
| What staying safe needs                  | Watch the chain or use a watchtower | Refresh every few weeks         | Trust in the mint  | Come back before the contract ends (you pick the duration) |
| The operator can force you onchain       | Yes, by force-closing               | Yes, at expiry                  | No                 | No, only you can start a recovery                          |
| Inbound liquidity                        | Bought from the LSP                 | Not needed                      | Not needed         | Not needed                                                 |
| Receive while offline                    | No                                  | Yes                             | Yes                | Yes, within a hub or onchain                               |
| A payment is safe from operator collusion | Yes                                | After the next round            | No                 | Yes, immediately                                           |
| The operator sees                        | Your balance and every payment      | Inputs, outputs and amounts     | Only anonymous notes | Only anonymous notes, not your balance or who pays whom  |
| Cost of an exit without the operator     | One small transaction               | Your branch of the tree         | No exit            | About 15 kvB and a few days, more if disputed              |

## Why

- **No consolidation, no toxic change.** Each coin you receive is swapped in
  on its own, and you pay out onchain exactly the amount you need. Your
  coins never get spent together, so they can't be clustered.
- **Lightning without a node.** Pay and receive over Lightning with no
  channels, no inbound liquidity and no watchtower, through your hub or a
  swap provider, which can't take the money.
- **Private payments.** The hub cannot link a note's spending to its
  issuance, and payments leave nothing on Bitcoin.
- **Receive while offline.** Within a hub or onchain, a payer can pay you
  while your phone is off.
- **Fast and cheap.** Payments within a hub are instant and use no
  blockspace.
- **You keep custody, up to your limit.** Value within your contracts can
  always be recovered on Bitcoin. A stale backup is paid exactly what is
  still unspent, never punished.
- **No shared hub needed.** Two people can pay each other from different
  hubs: swap providers move the money between them, or over Lightning.

### What protection costs

A hub prices a contract by an opening fee and yearly interest on the part
of the cover it locks up. At a hub asking 3,000 sat and 1% a year,
protecting 131,071 sat for six months costs 3,000 + 655 = 3,655 sat. You
also put in a reserve, say 20,000 sat: it is yours, pays the Bitcoin fees
if you ever recover without the hub, and comes back otherwise.

### Limits

- Above your cap, your balance rests on the hub's word, as with any ecash.
- A contract lasts a set time. Open the app now and then, and before it
  ends, protect again or cash out.
- Recovering without the hub takes days and pays Bitcoin fees.
- No hub runs on Bitcoin yet, and the code has had no security review.

The [paper](paper/licash.pdf) describes the protocol, its security and its
privacy.

## Try it

Licash runs on signet and Mutinynet. Contracts there are a trial: the
code has not had a security review, so do not use real funds. The signets'
headers are checked by their work alone, not by the network's signature of
each block, so headers that fool a contract's statement cost little to make,
and a contract's recovery there is only as strong as that work.

- **Android:** install `licash-main.apk` from the
  [`main-build` release](https://github.com/lichenbtc-org/licash/releases/tag/main-build).
  On the last slide of the tour, tap "Use a test network", pick Mutinynet,
  create the wallet and use the hub it recommends.
- **Command line:**

  ```sh
  docker run --rm -it -v licash:/data ghcr.io/lichenbtc-org/licash-wallet init --network signet
  docker run --rm -it -v licash:/data ghcr.io/lichenbtc-org/licash-wallet \
    discover --relay wss://relay.primal.net
  docker run --rm -it -v licash:/data ghcr.io/lichenbtc-org/licash-wallet add-hub <URL>
  ```

  See [apps/wallet-cli](apps/wallet-cli/README.md) for receiving and paying.
- **Everything locally**, with Docker: `apps/e2e/run.sh` brings up a regtest
  network with hubs, a Lightning gateway, swap providers and wallets, and
  runs the end-to-end tests against it.

## Components

[Wallet CLI](apps/wallet-cli/README.md) ·
[Android app](apps/mobile/android/README.md) ·
[Hub](apps/hub/README.md) ·
[Swap provider](apps/swaps/README.md) ·
[Observatory](apps/observatory/README.md) ·
[Proving](r0/README.md) ·
[Contracts on regtest](regtest/README.md)

To build and test the library, run `cargo test --locked`. For the
applications, run `cargo test --locked --manifest-path apps/Cargo.toml`.

## License

MIT, see [LICENSE](LICENSE).
