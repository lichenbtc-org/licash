# NWC bridge reference

`licash-bridge` serves Nostr Wallet Connect (NIP-47) for apps out of
accounts it keeps, over a Licash wallet of its own at one hub: it pays
invoices through the hub's Lightning gateway, or else a swap provider's,
and takes payments there.
Optionally it gives its accounts Lightning Addresses, with zaps. It is
custodial: the bridge holds what its accounts hold. Anyone can run one,
for themselves or as a provider for others, and a wallet can use several.
`licash-bridge --help` lists the commands, flags and environment variables.

## Run it

Use the image `ghcr.io/lichenbtc-org/licash-bridge`, or build it with
`cargo build --release --manifest-path apps/Cargo.toml -p licash-bridge`.

```sh
licash-bridge --data ./bridge init --network signet --hub https://hub.example
# prints the pairing code its owner registers with
licash-bridge --data ./bridge run --listen 0.0.0.0:8090 \
  --relay wss://relay.example --name "my bridge" --max-payment 50000
licash-bridge --data ./bridge status
licash-bridge --data ./bridge pairing --renew  # hand the account to a new wallet
```

At a hub that runs no Lightning gateway, `run --via URL` (or
`LICASH_BRIDGE_VIA`) names a swap provider ([swaps.md](swaps.md)) to pay
and be paid through instead: it pays the bridge's invoices for a lock of
their amount and its fee, and makes its invoices, locking what they are
paid to the bridge at the hub. The provider is trusted for its fees and
sees each payment's amount, and links the bridge's receipts. Its terms
are asked again each round: its fee on receiving is what the bridge's info
names, and its limits are the Lightning Addresses'. Invoices through a
provider ask whole satoshis: a top-up or a Lightning Address payment of a
part of one is refused. The provider must name the feature
`receive-exact` for the bridge to be paid through it. A hub with a gateway
is always paid through it.

Back up `<data>/wallet.sqlite`: it holds the bridge's wallet and its
accounts, connections, payments and invoices in one SQLite database.
`status` shows the accounts, what they are owed, what the wallet holds,
and whether it is short or frozen.

### Owner and open bridges

By default the bridge keeps one account, its owner's: the wallet that
registers with the pairing code `init` printed (`licash-wallet bridge add
URL --pairing CODE`, or the Android app). `pairing --renew` makes a new
code that hands the same account to whoever registers next, such as the
owner's restored or new wallet.

With `--open` anyone registers an account with their wallet's key: a
provider's bridge. Limits bound it:

- `--max-balance` sat any account holds, invoices still open counted;
- `--max-payment` sat any one payment pays;
- `--max-accounts` accounts in all;
- `--registrations-per-hour` new accounts in any hour (60 by default).

Each management request is signed by the account's key and answered once;
the bridge remembers up to 65,536 recent signatures and refuses more as
unavailable until older ones expire, rather than forgetting any early.

### Lightning Addresses and zaps

With `--public-url https://domain`, the bridge serves LNURL-pay at
`/.well-known/lnurlp/NAME` for each account that picked a name
(`licash-wallet bridge address NAME`), so payers reach it at `NAME@domain`.
It accepts NIP-57 zap requests and publishes the zap receipt on the
requested relays once paid. The hub's fee on receiving comes out of what
the account is paid.

Anyone may ask an address for invoices, so each address has at most 64
unpaid and unexpired at once (its top-ups included). Past that it refuses
until some are paid or expire, so a flood fills that address alone. The
hub takes at most 8 unpaid receipts from one source, and the bridge is one
source unless the hub trusts it as a proxy. The bridge asks for each
address's invoices as a proxy of its caller would: it names the caller in
`X-Forwarded-For`, after whatever the caller's own proxy forwarded. Run the
hub with `--trusted-proxy <the bridge's address>` (and that of any proxy
in front of the bridge, which must replace rather than append to its
clients' `X-Forwarded-For`, as [docs/hub.md](hub.md) says of Traefik), so
that each caller counts apart. Otherwise every caller shares the bridge's
8. NWC invoices are asked for no caller, and count as the bridge's own.

### Announcing

An open bridge with a public URL announces itself on its relays with
`--announce` (role `bridge`, tag `licash-bridge`), naming the key its info
names. `licash-wallet discover --bridges` lists the open bridges announced
there that answer as the key that announced them, those at hubs the wallet
trusts first.

## Accounts and apps

Amounts are kept in msat. A wallet tops its account up by paying an
invoice of the bridge from any of its hubs, by hand or by rules (below a
balance, up to another, at most so much a day), and withdraws by having
the bridge pay an invoice of its own.

Each app gets a connection: a `nostr+walletconnect://` URI shown once, with
its own key, the methods it may use (paying, receiving, or both), the most
one payment may be and a budget per day, week, month, year or in all. The
bridge answers `pay_invoice`, `make_invoice`, `lookup_invoice`,
`list_transactions`, `get_balance` and `get_info`, encrypted with NIP-44
or NIP-04 as the request was, and publishes its info event hourly. A
payment reserves its amount and the most fee first; what it did not spend
returns once settled. Revoking a connection ends it for good.

## When the hub stops cooperating

The notes the bridge holds are at its hub. Should the hub stop
cooperating, they can go to a wallet with a recovery contract at that hub,
which claims them with its own:

1. `licash-wallet bridge export --yes` (owner bridges), or, for an open
   bridge, its operator stops `run` and runs `licash-bridge export KEY
   --out FILE` with KEY the operator wallet's key there (`licash-wallet
   bridge show` names it), then `licash-wallet bridge import FILE`.
2. The export freezes the bridge first: it pays, receives and unlinks
   nothing from then on, and refuses to export only while a payment is
   being sent, before its lock is made. Each note is sealed to the
   wallet's key with its hold key; the export holds no seed.
3. A payment stuck on the hub, its lock made but never settled, is
   exported too: the lock's signed body, its certificate if the hub
   certified it, and the openings and hold keys of its refund to the
   bridge. An export with such locks is of a newer format (2) than one of
   notes alone (1): a wallet too old to read it refuses it whole, never
   importing part of it. Payments into the bridge still under way are not
   exported.
4. The wallet keeps the notes and refunds imported apart from its own:
   never in its balance, never spent. A recovery claims the notes only
   within the cap its own notes, locks and funding leave, then each
   refund whole, once its lock expired at depth on Bitcoin, if it still
   fits. A claim that would not be owed whole is made again without the
   refunds, then without the notes, which are dropped for good.
   `licash-wallet bridge imported` shows them.

Should the hub carry on after all, the wallet forgets them with
`licash-wallet bridge discard SOURCE` (refused while a recovery claims
them), and the operator unfreezes the bridge with `licash-bridge unfreeze
--yes`. A note claimed by both is lost to both: unfreeze only once the
wallet discarded the import. The signed export is refused by open bridges:
their notes are every account's, so only their operator exports them.
