# Swap provider reference

`licash-swaps` serves a swap provider (`crates/licash-swaps`) over the HTTP
API of `licash_api::swaps`: clients swap notes at one hub for notes at
another, with a timed lock at each under the client's hash.
`licash-swaps --help` lists the commands, flags and environment variables.

```sh
licash-swaps --data ./swaps init --network signet  # prints the provider's address
export LICASH_WALLET=./swaps/wallet.sqlite LICASH_WALLET_CHAIN=URL
licash-wallet add-hub https://hub-a.example
licash-wallet add-hub https://hub-b.example
licash-wallet receive payment.json              # fund it at each hub
licash-swaps --data ./swaps address --chain URL # fund it on Bitcoin
licash-wallet open-contract https://hub-a.example  # protect its notes there
licash-wallet open-contract https://hub-b.example
licash-swaps --data ./swaps run --listen 0.0.0.0:8340 --fee-ppm 2000 \
  --chain URL --notify tgram://BOT_TOKEN/CHAT_ID
licash-swaps --data ./swaps status
licash-swaps --data ./swaps events --follow
licash-swaps --data ./swaps dashboard
licash-swaps lnurl --lnurl-url https://swaps.example CODE  # a static donation LNURL
```

`status` shows earnings, aggregate balances, swap outcomes and losses,
without listing transactions or identity details. `status --details` adds
per-hub balances, the address and ten recent swaps; `status --swaps N`
requests a particular number. `status --json` retains the full structured
output and its default of ten swaps. Individual fees show their share of
the swap amount, including miner fees for Bitcoin payouts. Normal text
logs omit timestamps and Rust targets; `RUST_LOG=debug` reveals diagnostic
configuration, and `--log json` retains structured logging. Warnings remain
visible.

`dashboard` draws the provider's dashboard in the terminal: swaps by route,
failures by reason and those under way, fees less what lost swaps cost, the
notes held at each hub with the days they last at the rate they fell, what
is free to lock and reserved, the coins on Bitcoin, health checks, among
them whether the provider at `--url` answers `/health` and whether its
hubs answer it, and below the overview its recent events, newest first:
each swap taken, done, failed or lost, with its route, and its alerts. It
reads `<data>` only, beside the running provider or without it, and never
writes or migrates its files. History comes from the records themselves,
over a range of 24 hours to all of it (30 days at first, or `--range`)
against the range before. Arrows or digits turn the pages, `[` and `]` the
range; `--json` prints the range's view once instead.
A read failure keeps the last good data and the help/quit keys; `?` shows
the error detail.

`init --network` names the network of its hubs, `bitcoin` by default.
The provider swaps between the hubs its wallet added, up to what it holds
at the destination hub; an alert says when that falls below `--min`, once
a start until it recovers. Back up `<data>/wallet.sqlite`: it holds
the wallet's tables and the provider's swaps in one SQLite database, so that
one snapshot of it (`sqlite3 wallet.sqlite ".backup FILE"`, or a copy with
the provider stopped) is the whole of them, the contracts it keeps included
(and `<data>/contracts`, their instances). A directory with a `swaps.sqlite`
or a `contracts.sqlite` of an earlier layout is refused by name, never read
nor replaced: there is no migration. A stopped provider takes its swaps on when
started again, but a swap whose client lock expires before it claims it is
lost (`status` counts it, and a high-priority notification says so):
`--margin` sets the blocks it keeps for that. Its wallet unlinks the notes
it is paid each round, and renews those a hub no longer unlinks since it
restarted, once, if the hub's fee on them is at most `--renew-ppm` parts
per million of their value, or a spending schedule of at most 1 sat base,
that rate and 0.1 sat per output (1000 by default, 0 for free renewals only).
Each round after the swaps it also reshapes the notes it was paid, as the
wallet CLI reference (docs/wallet-cli.md) says: at most one remint per hub, after a privacy rest,
within that fee authority and 1% of what it holds there a day. A failed
remint is only logged and never holds a swap up. The same applies to the
provider a hub embeds (`licash-hub run --swaps`).

With `--chain URL` (Bitcoin Core's RPC, `http://user:password@host:8332`, or
Esplora, `esplora+https://esplora.example/api`), the provider also pays notes
out on Bitcoin: a client locks the coin's value and the fees to it at a hub,
the provider pays a coin of its own to an HTLC under the lock's hash, timed
out `--payout-margin` blocks before the lock expires, and claims the lock
with the preimage the client's claim of the coin reveals on chain. A client
paying out to a silent payment address sends its scan key blinded, and the
provider answers its share of it by the coin's refund key, with a proof: the
client's claim then pays the output its payee finds by the claim's tweak,
while the provider never learns the address. A coin
never claimed comes back to the provider once timed out. Each coin is paid at
the chain's estimate when taken (no payout on mainnet without one); a coin in
no block 12 blocks before its timeout is canceled, its coins paid back to the
provider in its place, and a refund in no block is made again at a higher rate
as the client's lock's expiry nears, all of the coin at most. A refund is
followed until six blocks deep: one a reorganization takes out of the chain is
alerted and taken on again, the coin refunded anew or the client's claim taken
on the hub. Fund it on chain at
the address `licash-swaps --data ./swaps address --chain URL` prints: its
wallet watches the chain from its tip when first started with `--chain`, or
from `--chain-from`. `--payout-fee-base`, `--payout-fee-ppm`,
`--payout-miner` (the coin's miners, on top), `--payout-rate` (sat/vB, the
least its transactions pay and the hint its clients budget claims at, else the
chain's estimate at start), `--payout-min` and `--payout-max` set the
terms; `status` shows the coins, and an alert says when they pay out less
than `--payout-min`, once a start until they pay enough again. A provider
with payouts under way refuses to start without `--chain`.

The coin's claim script checks that the preimage is 32 bytes
(`OP_SIZE 32 OP_EQUALVERIFY`), as every lock's preimage is. Without that
check a client, who chose the hash, could claim the coin with a longer
preimage of it that no lock takes, keeping both the coin and its notes.
A wallet from before the check does not claim the coin of a provider after
it. A wallet after it claims the unsized coin of a provider before it, as
the coin on chain pays, and a provider upgraded with payouts open reads
the claims of the coins it made unsized, or takes them back, by the script
it recorded each paying.

A wallet pays for a coin to open a recovery contract with as any payout, to
its own address (see `open-contract --with-notes` in the wallet's reference),
then opens the contract on it. Lightning pays for such a coin in two steps:
notes received at a hub over Lightning first, then locked to the provider as
any.

A client who never claims its coin costs the provider the fees of that coin
and of its refund, and holds the coin until it times out, while its own
lock simply expires back to it. So the provider bounds what such payouts can
cost: it takes at most `--payout-max-open` (32) payouts at once, declines a
hub's payouts once `--payout-max-unclaimed` (8) of them went unclaimed in the
last day, declines a lock whose coin would be held more than
`--payout-max-blocks` (144) blocks, and pays out no coin worth less than
`--payout-fee-share` (20) times what it and its refund pay in fees at the
rate the last one was paid at (or `--payout-min`, if larger). Each limit is a
plain decline (`declined`), never a charge: nothing is paid up front.

With `--lnd URL --lnd-macaroon FILE` (and `--lnd-cert FILE` to pin LND's
certificate), the provider also pays Lightning invoices from that LND node,
for clients' locks at any of its hubs (`POST /v1/swaps/lightning`). A client
locks the invoice's amount and the fee (`--ln-fee-base`, 2 sat, and
`--ln-fee-ppm`, 5000, routing fees included) to the provider under the
invoice's hash; the provider pays invoices up to `--ln-max` sat, and no more
than its node's channels pay now with the fee (all of them together, which
reserves and routes may cut further; nothing while the node does not
answer), as `/v1/swaps/info` says, along routes
whose timelock ends `--ln-slack` blocks (80 by default, 18 at least) before
that lock expires, and claims the lock with the preimage the payment buys.
The slack is the provider's time to learn the preimage, on Bitcoin if a
channel closes, and claim while its node or the hub is down: past the
lock's expiry the provider cannot claim it, having paid. When the invoice is
a hub's, asked for by a wallet under a hash of its own, notes at one hub pay
notes at another with no notes of the provider at the other. A payment that
fails leaves the client's lock to be refunded once expired. These locks
count like swaps against what the contracts at the source hub protect. A
provider with Lightning payments under way refuses to start without `--lnd`.

With `--lnd` and `--lnurl-url URL`, the provider's public URL, it also
takes donations to the wallets of Licash codes over LNURL-pay (LUD-06), for
payees that need not be online. `licash-swaps lnurl --lnurl-url URL CODE`
prints a code's static LNURL, to show as a QR code: any Lightning wallet
pays it, again and again. Its info (`/v1/swaps/info`) names the URL and the
terms under `donations`, for a Licash wallet to show its own. Its pay request (`GET /v1/lnurlp/CODE`) offers
from `--donation-min` (100 sat) up to `--donation-max` (1,000,000 sat), or
what the provider holds at a hub of the code if less, and its callback
(`GET /v1/lnurlp/CODE/callback?amount=MSAT`) a held invoice of the node.
Once that invoice is paid, the provider pays the donation, less its fee
(`--donation-fee-base`, 2 sat, and `--donation-fee-ppm`, 5000, the hub's
fee included), to the code's wallet in notes at that hub, kept there for
the payee to collect for 14 days, or mailed to its mailbox; then it
settles the invoice. While nothing is released to the payee, the invoice is
canceled and the payer refunded: a donation whose fee does not cover the
hub's, or paid too close to its HTLCs' expiry, is never paid on. A payment
signed but not released 18 blocks before the HTLCs expire is settled all
the same and followed until released; one given up after that alerts the
operator. At most `--donation-max-open` invoices are open at once (100
by default), whoever asked: anyone may ask for them, of any code naming a
hub the provider holds notes at, and not pay, each holding its place for
about 11 minutes, until its invoice expires and is canceled. Past them, new
donations are refused, not those under way. An unpaid one holds none of
the provider's notes, only its place, and one source (a client's address,
or its Tor circuit over the onion service) holds at most 8 unpaid at once,
leaving the rest to paying donors. A provider with donations under way refuses to start without `--lnurl-url`
and `--lnd`. The provider must stay up while donations are under way: down
past an HTLC's expiry, it may have paid the payee and lose the donation.

With `--lnd` and `--receive`, it also takes payments over Lightning for
wallets, as a hub's gateway does, so that a wallet can be paid over
Lightning at a hub without one. Its info names the terms under `receive`.
A wallet asks (`POST /v1/swaps/receive`) for an invoice of `amount` under
a hash of its own, to its address at a hub the provider swaps at; the
invoice asks the amount and the provider's fee (`--receive-fee-base`, 2
sat, and `--receive-fee-ppm`, 5000, the hub's fee on the lock included),
from `--receive-min` (100 sat) to `--receive-max` (1,000,000 sat), and
`GET /v1/swaps/receive/HASH` says where it stands. A provider whose info
names the feature `receive-exact` also takes `asks`, what the invoice asks
in whole satoshis, at least the amount and its fee, the rest its own, and
`description_hash`, the hash of a description given elsewhere that the
invoice commits to instead of a memo: as LNURL-pay wants, for a bridge's
Lightning Addresses. Once the invoice is paid,
the provider locks the amount to the wallet under that hash, for at most 15
blocks; the wallet claims it with the preimage, which the hub shows the
provider, who settles. Unclaimed, the lock is refunded once expired and the
payment fails back to its payer. Nothing is trusted to the provider, but it
sees which receipts go to one wallet's address. The lock expires early
enough for the provider to force the preimage out on Bitcoin, should the
hub keep it, and settle 18 blocks before the HTLCs expire: the invoice's
final CLTV delta is the hub's lead (the refund request's confirmation, the
hub's response window, a block to read the preimage, the provider's margin
and one), 18 blocks, 15 for the wallet to claim and 3 of slack, about 230
blocks on a hub with a day's window. A lock that expired, neither paid nor
refunded, alerts the operator and never cancels the invoice. At most
`--receive-max-open` receipts are under way at once (100 by default), and
one source holds at most 8 of them unpaid at once, as donations. An unpaid
receipt holds none of the provider's notes, only its place: a receipt is
asked only if the provider holds its amount at the hub then, and once
paid, its amount is set aside from what the provider swaps there, if it
still holds it; if not, the invoice is canceled and the payer refunded.
A provider with receipts under way refuses to start without
`--receive` and `--lnd`. Receipts are kept in tables of their own, made in
the provider's file when first taken: an existing provider's file is
otherwise as it was.

A hub could withhold the notes it holds of the provider's: a recovery
contract at the hub (`licash-wallet open-contract`) recovers them, up to
its cap, from its collateral. By default `run` takes in at each hub only
what the live contracts there protect, declining each swap or payout that
would bring what it holds and is owed there past that, and keeps them on
the chain of `--chain`, a round a minute:

- `--contract-successor-days` (14) before a contract's safe deadline, a
  successor is opened at the hub, from the wallet's coins on Bitcoin, for
  at most `--contract-max-price` sat or a quarter more than the contract
  cost (as much more again as it is larger); it counts in its stead while
  it opens. Its cap follows what the provider holds there: twice the
  contract's while that is three quarters of what is protected or more,
  half while under a quarter, within the hub's range (which a hub narrows
  to what its wallet funds) and what the largest free coin pays for.
- Where the provider holds nine tenths of what its contracts at a hub
  protect, none being opened or replaced, one more is opened there, of as
  much as they protect, for at most `--contract-max-price` sat.
- Its safe deadline comes a day before its claim would have to confirm,
  keeping `--contract-exit-days` (14), the exit margin, for a forced close
  to play out in. There it is
  forced closed, whatever its hub says, if the other contracts at the hub
  cannot recover every note held there.
- A failed replacement is retried after growing waits. Meanwhile nothing
  more is taken in there, and with `--drain-via URL` what the hub holds
  beyond what is protected is paid out through the provider at URL to the
  provider's own address on Bitcoin.

The first contract at each hub is the operator's to open, with
`licash-wallet --wallet <data>/wallet.sqlite open-contract HUB --chain URL`:
until one is, the provider takes none of that hub's notes in. With
`--contract-open-cap SAT` (and `--contract-max-price`), the keeper opens it
itself, of up to SAT protected, from the provider's coins on Bitcoin, and
again at a hub where all its contracts ended; a failure is retried after
growing waits, and alerted. Alerts name
the hubs without contracts, notes beyond what is protected, recoveries
whose collateral was lost, hubs silent for
an hour, and fees raised beyond what the contracts agreed to
(`approve-fees`). Contracts open on regtest, under the mock authority, and
on signet and Mutinynet only for now: on other networks, or without `--chain`, `run` refuses
to start unless `--no-contracts` runs it unprotected, which is reckless. A
provider upgraded to this version takes nothing more in at a hub until a
contract there is live; what it holds stays, and its payouts go on. The
contracts and the payouts spend the same coins on Bitcoin, which the
operator's `licash-wallet` should leave alone while the provider runs.

The client reveals its preimage to the destination hub, which issues the
provider's lock there and could keep the preimage from it. The provider
would then learn it only from a refund request of its lock on Bitcoin,
which the hub voids only by publishing the preimage within its response
window. So its lock expires earlier than the client's by that window,
`--confirm` (the blocks to get the request confirmed, 36 by default) and
`--margin`, and `/v1/swaps/info` gives that margin for each hub. A swap is
declined unless the source hub admits a lock that late, which takes a
source hub with a longer window than the destination's: between hubs of
equal windows, the provider swaps nothing. It makes no refund request
itself: a high-priority alert names the provider's lock left neither paid
nor refunded after it expired, and the height the request must confirm by.
A hub can provide the swaps into it instead, issuing the provider's lock
itself, with no such risk: see `licash-hub run --swaps`.

With `--nostr-relay URL --announce-url URL`, the provider announces itself on
Nostr relays for wallets to discover, under the key `/v1/swaps/info` names.
With `--tor`, it reaches hubs and relays, onion services included, through a
Tor client of its own, which keeps its state in `<data>/tor`; `--proxy
socks5h://...` goes through a Tor daemon instead. With `--onion`, it also
serves its API as an onion service, announced like `--announce-url`'s; back
up `<data>/tor/state` to keep the address. Under load, the service asks its
clients for a proof of work (Tor's onion service defense) unless
`--onion-pow false`.

Sources are counted as the hub counts them (see its `--trusted-proxy` in
`docs/hub.md`): an onion service's circuit, or else a client's IP address.
Behind a reverse proxy, name it with `--trusted-proxy`
(`LICASH_SWAPS_TRUSTED_PROXY`), an address or a CIDR block, repeated or
comma separated, and firewall `--listen` so only the proxy reaches it: the
provider then reads the client from `X-Forwarded-For`, and refuses a
receipt or donation whose header from that proxy does not parse. Without
it, every client behind the proxy is one source. At most 256 requests are
served at once, `/health` aside, and a body still arriving 60 seconds after
its head is refused.

Notification targets are Apprise URLs, as for the hub; `test-notify` checks
them. `--notify-kinds` picks the kinds of event: by default all but swaps
accepted (`accepted`), still under way. Each notification lists the swap's
route and figures, ids cut to 12 characters. A swap done shows its income
(what the client's lock paid beyond the amount), its costs (the fee its
lock at the destination hub paid) and its profit, with their rates as a
percentage of the amount; the wallet's unlinking is not counted against any one swap.
A payout shows what it charged instead, the miner fee it pays included,
since miner fees go unrecorded. A refunded swap is one whose client never
claimed the provider's lock, which cost its refund fee; a lost one, at high
priority, one the client was paid for but whose lock the provider did not
claim in return. Swaps and payouts under way resume when a stopped
provider starts again.

```sh
docker build -f apps/swaps/Dockerfile -t licash-swaps .
docker run --rm -v licash-swaps:/data licash-swaps init --network signet
docker run --rm -v licash-swaps:/data --entrypoint licash-wallet licash-swaps add-hub https://hub-a.example
docker run --rm -v licash-swaps:/data --entrypoint licash-wallet licash-swaps open-contract https://hub-a.example --chain URL
docker run -d -p 8340:8340 -v licash-swaps:/data licash-swaps run --chain URL
```
