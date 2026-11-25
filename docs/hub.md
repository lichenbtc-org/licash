# Hub service reference

`licash-hub` serves a hub (`crates/licash-hub`) over the HTTP API of
`crates/licash-api`. `licash-hub --help` lists the commands, flags and
environment variables.

```sh
licash-hub --data ./hub init
licash-hub --data ./hub run --listen 0.0.0.0:8338 --chain esplora+https://esplora.example/api \
  --notify tgram://BOT_TOKEN/CHAT_ID
licash-hub --data ./hub status
licash-hub --data ./hub events --follow
licash-hub --data ./hub dashboard
```

A hub charges for what it does unless told otherwise. A payment, and each
branch of a lock, pays `base + ppm of the notes spent + a fee for each note
made for others than the hub`: by default 1 sat, 100 ppm (rounded up) and
0.1 sat a note (their sum rounded to the nearest sat). `--spend-fee-base`
and `--spend-fee-ppm` set the first two on a payment, `--lock-fee-*` and
`--refund-fee-*` in a lock's pay and refund branches, `--output-fee-msat`
the fee on a note, in thousandths of a sat, for all three. A payment
received over Lightning costs `--ln-receive-fee-base` and
`--ln-receive-fee-ppm`, 1 sat and 100 ppm by default. A hub that ran
without these flags charged nothing: upgraded, it charges the defaults
(`run` logs what it charges as it starts), and 0 on each keeps it free.
Wallets that predate the fee on notes do not pay it, so a payment of theirs
that makes five notes or more is refused until they upgrade:
`--output-fee-msat 0` spares them.

Fees may change at any restart, but a wallet holding a recovery contract
agreed to those charged as it opened, and no more: it stops paying a hub
that charges more, in any fee, until its owner approves the new fees by
hand. With `--contracts`, the hub keeps what it charged with each opening
(in `<data>/hub.sqlite`) and `run` warns, as it starts, of how many
contracts it signed opened for less than it charges now. Nothing else is
done with it.

`status` shows income, released payments and open locks. `status --details`
adds the internal note and event counts; `status --json` keeps the full
machine-readable statistics. `audit` lists the spends the ledger retired
notes for that no contract's dispute can cite, and fails if there are any
(see [Upgrading](#upgrading)). Normal text logs omit timestamps and Rust
targets. Configuration is diagnostic detail (`RUST_LOG=debug`); warnings
remain visible. `--log json` retains structured logging.

`dashboard` draws the hub's dashboard in the terminal: payments by kind
(transfers, locks, Lightning out and in, deposits), their failures by
reason and those under way, the fees earned, the notes outstanding and the
collateral of the contracts that protect them, the notes' anonymity sets,
health checks, among them whether the hub at `--url` answers `/health`,
and below the overview its recent events, newest first: each transfer,
lock, payment, invoice, deposit and contract as it moved, and the hub's
alerts. It reads the files in `<data>` only, beside the running hub or
without it, and never writes or migrates them. History comes from the
records themselves, over a range of 24 hours to all of it (30 days at
first, or `--range`) against the range before; what no record dates, such
as the collateral, is as it stands now. Arrows or digits turn the pages,
`[` and `]` the range; `--json` prints the range's view once instead.
Transaction fees include their share of the processed input, while contract
prices are relative to their cap. A read failure keeps the last good data
and the help/quit keys; `?` shows the error detail.

`--network` (`bitcoin` by default, or `regtest`, `signet`, `mutinynet`) is
the chain `--chain` must follow: the hub scans no other. The signets are for
testing only: header checks cannot tell their blocks from forged ones.
Mutinynet's blocks come every 30 seconds, 20 times as quick as signet's.
The hub counts every window, depth and margin in blocks all the same, as on
signet, so that they last a twentieth of the time there: for its tests to
meet reorganizations with. What is told in time is told in its blocks':
the dashboard (give it `--network`, or `LICASH_HUB_NETWORK`), and a
contract's interest by the year, which counts the year of its blocks
(1,051,200 on Mutinynet, 52,560 elsewhere).

The hub takes the chain `--chain` serves as the best chain, and checks only
that each block extends the last one it scanned (a reorganization is
rewound). It does not check that the source is up to date: a node that is
stalled, or on a minority chain, shows the hub a stale tip, and the hub
times its locks, refunds and deposits by it. Keeping the node synced to
the network, and well connected, is the operator's job: name a node you
run, and watch its tip against others.

`<data>/seed` makes every key of the hub: those its notes are issued
under, its own address, its Nostr key and its deposits' keys. Keep a copy
offline. Whoever else reads it makes notes the hub takes for its own, and
spends them at the hub for what it pays out, over Lightning or from its
contracts' collateral. It is not all there is to guard. Worth funds to
whoever reads them too: `hub.sqlite` (the ledger, and the openings and the
pinned responses the hub signs its contracts with), the LND macaroon, the login of the Bitcoin
Core wallet that funds contracts (it spends that wallet),
`swaps/wallet.sqlite` (the provider's notes at other hubs) and `tor/state`
(the onion address). `init` makes `<data>` its user's alone: keep it so, on
an encrypted disk, and keep on this host only what the hub needs there:

- Channels that hold what the hub pays out in days, not its reserves.
  `--ln-max-pay` bounds an invoice and `--ln-max-pay-day` a day's (below).
- A Core wallet of its own for contracts (`--contracts-wallet`), funded
  with what the hub may lock, and what contracts return paid to a wallet
  whose keys are offline (`--contracts-payout-wallet`, below).
- A macaroon and a Core login that do only what the hub does (below).

Back up `<data>` continuously, to another host. `hub.sqlite` holds the
ledger, the deposits, the Lightning receipts, the inbox, the openings of
contracts and the responses pinned, in one SQLite database, so that one
consistent copy of it (`sqlite3 hub.sqlite ".backup FILE"` or
`VACUUM INTO 'FILE'` while the hub runs, or its files copied with the hub
stopped) holds all of them as of one moment. It is not all of `<data>`:

- `seed`, once.
- `hub.sqlite` and `swaps/wallet.sqlite`, each copied as above, never as
  bare files while the hub runs (they are in WAL mode).
- `opening-instances/`: the garbled instances each contract kept, the
  largest part of `<data>`. Without them the hub still responds and
  asserts, but answers no challenge of its assertion, and a challenge
  costs the holder only its fees, so every holder who claims more than
  she is owed is paid all she claims, with the hub's reserve. The hub
  alerts at start for each contract whose instances are missing.
- `header-chain/` and `hp-proofs/`: the header chain's receipts and the
  proofs of disputes under way. Without them the chain is proven again
  from its start ([The header chain](#the-header-chain)).
- `payouts.json`, `notify.json` and `tor/state`.

Copy the database first, then the files: an instance or a receipt is
written before the database names it, and none is removed, so files
copied after the database cover all it names. Outside `<data>`, back up
the Bitcoin Core wallet that funds contracts (`backupwallet`; its keys are
not made from `seed`, and it holds the fee coins the hub's answers need)
and LND's channel backup.

What a copy loses grows with its age, so take it as often as the hub
changes, not daily. Litestream (0.5.18, tested in regtest under payments
and disputes, to a file replica) ships each database's WAL to its replica
every second; its other replica types (S3 and the like) are in its own
documentation:

```yaml
dbs:
  - path: /DATA/hub.sqlite
    replica:
      type: file
      path: /REPLICA/hub
  - path: /DATA/swaps/wallet.sqlite
    replica:
      type: file
      path: /REPLICA/swaps
```

Sync the other files of `<data>` beside it, every few seconds (as with
`rsync`), leaving out the databases, their `-wal`, `-shm` and `.lock`
files, and Litestream's `.hub.sqlite-litestream`: a file synced later
than the database that names it is missing from a restore, which the
hub's alert at start tells of. Restore with `litestream restore -o
<data>/hub.sqlite file:///REPLICA/hub` first, then the files. Keep Litestream
running whenever the hub is: it takes over the checkpoints, and commits
made while it was stopped may be missing from the replica (upstream issue
1540). Whatever it had not shipped when the machine is lost, a second's
writes, is lost with it, as with any copy.

Each paragraph below says what an older copy loses;
for contracts, the worst is an opening signed after the copy. A copy older
than an answer of a one-time key is answered again from the hub's
witnesses ([Contract witnesses](#contract-witnesses)), not decided anew. The hub's
keys for each opening come from a secret drawn for it alone and kept only
in `hub.sqlite`, not from `seed`: a hub restored without it neither answers
its holder's request (her timeout pays her all she claims, with the hub's
reserve) nor posts its default at the close. Spends made after the copy
are lost too: the notes they spent are taken again, and claims of them are
paid in full.

Restoring on another host, while contracts may be in dispute:

1. Fence the old host first: stop it for good, and revoke its Core and
   LND logins. Two hubs answering one claim may sign two different
   responses with one one-time key, which gives the holder the hub's
   outputs. Witnesses ([Contract witnesses](#contract-witnesses)) keep
   them to the same response, but fencing stays mandatory: the old host
   still spends the wallet and plays the ledger. Never start the hub from
   a snapshot of a live VM, nor keep one running beside it.
2. Restore the newest copy into `<data>`, with the same Core wallet.
3. On other hardware, delete `hp-proofs/bench.json`: it is the old
   device's speed, matched by kind (`cuda` or `cpu`) alone, and the hub
   admits and proves by it (below).
4. Start the hub without its public route (its proxy or onion off; it
   listens on `127.0.0.1` unless told). It plays the disputes that began
   while it was down, however long ago, as far as their windows allow.
   Read its alerts: missing instances, its header chain, its prover.
5. Open its public route only once the copy is known to be the newest:
   an older ledger takes spent notes again.

A contract's response window (12 blocks at least on signet) is how long
the hub may be down while a holder exits, from her request to its response
confirming: a restore must fit within it.

Never replace `<data>/hub.sqlite` while the hub runs: the hub halts, and
`/health` answers 503, until it is restarted. There is no migration: a
database or file of an earlier layout (`deposits.sqlite`, `lightning.sqlite`,
`inbox.sqlite`, `openings.sqlite` or `responses.sqlite` in `<data>`, a
`hub.sqlite` of an earlier schema) is refused by name, never read nor
replaced, and a hub is made anew.

An output unlinks once, to whoever asks first with its capability (a payment's
payer has it, having made the output). A payer may therefore use up her payee's
single unlink: the note stays spendable and is never lost, but it stays linked
to her spend. Unlinking is a privacy aid against a hub that colludes with
payers, not a guarantee against a malicious payer.

A spend's offer (its grant) its payer never released within a day is
deleted, so that offers never made into spends cost no row for good; a
wallet releasing it later offers the spend again. One note is offered in at
most 8 spends not released per run of the hub, and in as many again whose
offer each note's hold key signed (`holds` in `POST /v1/offer`): its
owner's, which a payer who knows the note, having made it, can't sign, so
can't use up.

Notes the hub locks for a deposit, a Lightning receipt or a swap into it
are backed by that payment, recorded in `hub.sqlite` (the deposits and
the receipts) or in the provider's `swaps/wallet.sqlite`. The hub refuses
to start while it may yet pay such a lock that none of these records, as
when the provider's file was restored older than `hub.sqlite`, and names
the locks: restore `swaps/wallet.sqlite` as recent as `hub.sqlite`.
`--allow-unbacked-locks` runs it anyway, alerting the operator: it would pay
those notes unbacked.

It also refuses to run with `--lnd` or `--deposit-sweep-address` disabled
while that gateway still has obligations to collect, including deposits
settled but not swept and locks left between writes by an interruption.
The refusal names the file and count. Idle files are inspected read-only,
never created or upgraded; open unpaid requests only warn. Enable the
gateway to finish its work. This also applies when upgrading an existing
installation; no records are discarded or migrated.

With `--lnd URL --lnd-macaroon FILE` (and `--chain`), the hub also runs a
Lightning gateway over LND: it pays invoices for locks that pay the hub,
and makes hold invoices paid with locks of its notes. An invoice of its
own node, a receipt still open, is paid inside the hub for its amount
alone: the payer's lock backs the receipt instead of an HTLC, and its
invoice is canceled. `--lnd-cert` pins
LND's certificate. The gateway keeps its invoices in
`hub.sqlite`, with the ledger's records. An alert says when
LND's channels can no longer pay or receive the most it takes.
`--ln-max-receipts` bounds open and locked receipts (1024 by default). A
receipt's invoice may be paid for 15 minutes (`--ln-invoice-expiry`, 900
seconds), after which an unpaid one frees its place.
Lowering it blocks new receipts, not retries or following existing ones.
A receipt may ask for a memo (at most 100 characters, its words one space
apart, no control characters), which its invoice says to the payer as its
description; the gateway names the `memo` feature in `/v1/info`, so wallets
ask older hubs for none. The memo is part of the receipt: the same hash
asked again with another is refused.

`--ln-max-pay-day SAT` bounds what the gateway pays out over the node in
any 24 hours: the sum of what the locks of the invoices paid, or under way,
pay the hub, the gateway's fee in it. Past it an invoice is refused and its
lock refunded, until earlier payments are a day old, and an alert says so
once a day. Without it there is no limit. It bounds what leaves over
Lightning in a day whoever asks, a thief of the seed too: set it to a few
times a busy day's payments.

The hub watches for notes made with its seed outside its ledger. It cannot
tell one from its own, but it counts: once it retired more notes of a
denomination than it ever issued to holders, some were forged. It looks
every 30 seconds. On more such notes than it knows of, it alerts the
operator and the Lightning gateway pays no more invoices: each is refused
and its lock refunded, `/v1/info` says it pays none, and payments under way
and receipts go on. The dashboard's health shows it. Treat the seed as
stolen: look at the alert and the ledger, then `licash-hub resume-payouts`
resumes, beside the running hub (within 30 seconds) or without it, taking
what the ledger shows then as known. This tells late, only once forged
notes outnumber all the outstanding notes of a denomination, and stops
only what leaves over Lightning from the hub, not swaps, contract claims
or the invoices a `licash-swaps --lnd` pays from the same node: it limits
a theft under way, and is no reason to keep the seed less safe. What it
knows is in `<data>/payouts.json` (`baseline`, and `paused` with the
reason). A hub upgraded to this version has none: it takes what its ledger
shows at its first look as known, alerts if that is any, and pauses
nothing. A file that does not read pauses, and is left as it is.

Only a hub that knows of no such note is told of forged ones alone. A
`hub.sqlite` restored from an older copy shows the same as a theft: the
notes it issued since that copy come back to it, never issued as far as it
remembers (and it takes again those spent since). And once some are known,
their count rises as holders spend the hub's own notes, so a resumed hub
pauses again, and is resumed again, until the most there ever were are
known. From then on it tells only of more of them.

The gateway calls eight of LND's RPCs: bake it a macaroon for those
rather than give it `admin.macaroon`.

```sh
lncli bakemacaroon --save_to=hub.macaroon \
  uri:/lnrpc.Lightning/GetInfo uri:/lnrpc.Lightning/ChannelBalance \
  uri:/routerrpc.Router/SendPaymentV2 uri:/routerrpc.Router/TrackPaymentV2 \
  uri:/invoicesrpc.Invoices/AddHoldInvoice uri:/lnrpc.Lightning/LookupInvoice \
  uri:/invoicesrpc.Invoices/SettleInvoice uri:/invoicesrpc.Invoices/CancelInvoice
```

It still pays invoices, so whoever reads it empties the channels' outbound
side, but it sends no coin on Bitcoin, opens or closes no channel, makes
no address and bakes no other macaroon.

With `--tweaks` (and `--chain`), the hub indexes the silent payment
(BIP352) tweaks of the chain's blocks from `--tweaks-from` (by default, the
tip at the first start) in `<data>/tweaks.sqlite`, and serves them to light
wallets at `/v1/chain/tweaks`. Deleting the file only loses the index.
A block the index fails on is tried again after a wait that doubles each
time, up to 5 minutes; stuck at one block for 30 minutes, the hub alerts
its operator (`--notify`). An Esplora that tells part of a transaction's
spends in a block's pages, as mempool's backend does past its 13th
input, is asked for that transaction alone.

The hub keeps the payments it releases for their payees when their payers
ask, for 14 days, in `hub.sqlite`: payees collect them at
`/v1/inbox` and tell their payers they have them, through the hub, without
Nostr. Anyone sees the inbox's feed, which tells how many payments were
kept, not whom they pay or how much. Losing the inbox's rows only loses the
payments kept: their payers send them to the payees' mailboxes on Nostr
once no acknowledgment comes.
A payment kept may carry a note its payer sealed for its payee: always
528 bytes, whatever it says or if it says nothing, so the hub reads nothing
of it; the hub names the `note` feature in `/v1/info` and refuses a note
of any other size. Payers ask a hub not naming it to keep none.

With `--deposit-sweep-address ADDRESS` (and `--chain`), the hub takes
deposits on Bitcoin: a payment to a deposit's address, once confirmed,
locks the hub's own notes to its payer, and the preimage the payer claims
them with lets the hub claim the coins to the sweep address. Unclaimed
deposits return to their payer after a timeout. `--deposit-*` flags set
the fee, amounts and timing (a deposit's lock lasts 36 blocks by
default, room for the payer to activate it on Bitcoin should the hub keep
its notes). `--deposit-max-open` bounds deposits asked and
not yet paid (1024 by default): past it, new ones are refused as
unavailable, never retries or deposits under way. A deposit's payment must
confirm within 72 blocks (`--deposit-window`, half a day) of the request,
after which an unpaid one frees its place. A deposit is named at
its hub by its payer's refund key, x-only, under which the hub takes one
deposit and refuses another: its status (`/v1/deposit/{refund}`) also
answers what was asked and the terms answered, so that a wallet restored
from its seed, which derives its deposits' refund keys from it, finds them
again by those keys, and takes on only what is under the hash its seed
gives for the notes and the payment answered. Deposits are kept in
`hub.sqlite`.

A contract's default close pays the holder's reserve to a deposit asked with
`close` terms (`CloseTerms`: the reserve as the payment, and `until`, the
block the hub watches for the close's payment until, `CLOSE_BLOCKS` after the
contract's close): its notes are the most the payment covers beside the
deposit fee. The hub keeps it for a deposit window only until an opening
names its script and binds it to the contract (`bind_close`, with the fee the
deposit asked, else the opening is refused); one whose opening is given up is
given up too, unless a payment was seen. The hub locks the notes only when
the wallet asks (`POST /v1/deposit/{refund}/lock`, once the payment is seen),
when it comes back after the close, and a deposit nobody asked for is given
up once its payer may take the coins back.

Its address is of the payer's seed, the coin that opens the contract (with a
small attempt number, for an opening asked again) and the hub's published
root alone. A coin is spent whole in the contract's funding, so it funds at
most one contract: two contracts' defaults never pay one deposit, even when
a hub hides a restored wallet's earlier deposits from it. The
hub's info names a deposit root (`deposits.close_root`, an x-only key; none,
and no contract opens), the hub claims such a deposit under that root tweaked
by the deposit's hash and its payer's refund key (`close_claim_key`), and the
refund leaf waits `CLOSE_WAIT` (2016) blocks after the payment confirms, a
relative lock (`OP_CHECKSEQUENCEVERIFY`) naming no height, which holds
however late the default is posted. So a wallet restored from its seed, with
the hub's address and root (`licash-wallet hubs --json`), finds its payments
on Bitcoin and takes them back with no word from the hub
(`licash-wallet recover`). The hub's claims and deadlines count from the
payment's block. The deposit's rows are in `deposit_closes` in `hub.sqlite`,
a table of its own that a file made before it creates on first use: the
deposits before are ordinary ones, claimed under the keys they were.
A claim left unmined is made again at a
higher fee rate as the timeout nears (twice the estimate once fewer than 12 blocks
are left, doubling every 3 blocks, all of the coin but dust at most), and
whichever of them is mined is the hub's. Alerts say when a claim is late or lost. With
the gateways and swap issuer sharing one turn, one payment backs each
lock of the hub's notes. New gateway requests refuse hashes already
reserved by another service, and a payment made under a hash
the other already locked for returns to its payer (an alert says so).
Reservations remain visible while a service is disabled. A swap's hash
reservation is not by itself proof that it owns a gateway's existing lock:
the recorded lock id decides ownership during recovery.

The hub serves at most 256 requests at once (`/health` aside); any past
them, of its own API or its swaps', receive 503 at once rather than wait
in a queue. A request whose body is still arriving 60 seconds after its
head is refused, so stalled uploads keep no place for longer. A swap
provider serving on its own bounds its requests alike. Contract requests
are outside those 256, under budgets and times of their own.

Contract HTTP requests have separate admission budgets for new openings,
progress and instance downloads; excess requests receive 503 before body
buffering or node RPC. Four concurrent instance downloads remain supported.
Admission lasts through response delivery, with a five-minute deadline for
request handling. Onion services accept at most 128 streams and allow two minutes
to receive HTTP headers, without limiting a valid response's duration.

With `--nostr-relay URL --announce-url URL` (and `--chain`), the hub
announces itself on Nostr relays for wallets to discover, under a key
derived from its seed that `/v1/info` names. `/v1/info` also names the
relays of its wallets' mailboxes, where payers send them payments: those
of `--nostr-relay` unless `--mailbox-relay` names others.

With `--contracts` (and `--chain` naming a Bitcoin Core node's JSON-RPC,
with a wallet), the hub opens recovery contracts with its wallets: each
locks collateral of the node's wallet behind the wallet's notes at the hub,
up to a cap, until the contract's close. `--contracts-wallet URL` names
another node's wallet instead, by its JSON-RPC as `--chain` takes it
(`http://host:port/wallet/NAME?cookie=PATH`), on the same network: the hub
may then follow the chain through an Esplora API. The hub hands each fee
coin its wallet funds to that chain itself, and again each round the coin
waits for a block, since a disclosure or fee child spending it is refused
where its funding never arrived; the operator is told if the chain does not
take one. A wallet of its own,
funded with what the hub may lock, bounds the collateral at stake.
`/v1/info` names its fixed terms: the cap (131,071 sat), the price a wallet
pays to open one (the holder's 20,000 sat reserve and the hub's opening fee,
`--contracts-fee`, 3,000 sat by default, what it charges for what it brings)
and the blocks to its close (1,000); the openings take
`/v1/contracts`. With `--contracts-max-cap SAT`, wallets may also choose a
contract's cap up to that and how long it lasts up to
`--contracts-max-blocks` (`/v1/contracts/quote?cap=SAT&blocks=N`), its cap
one of the sizes (`2^n - 1` sat, 131,071 to 2,147,483,647; the operator's
largest rounded down to one) whatever the coin the wallet deposits (any
coin paying the price, the hub funding the rest of the cap), at the reserve
and opening fee plus
`--contracts-rate` millionths of the part of the cap the hub funds a year
(of its network's blocks, 52,560 or Mutinynet's 1,051,200; 10,000, 1% a
year, by default). A wallet funds part of the cap itself
(`&funded=SAT`, every contract): its coin is spent whole in F, paying the
price and, as that part, all the rest of it but less than dust (no change
comes back), `--contracts-rate-funded` millionths of it a year (none by
default), and once F is 3 blocks deep (and as deep as the hub's funding
depth) the hub issues it notes of that value at
`/v1/contracts/openings/{id}/funded`, through a lock of its own settled at
once; never issued, the wallet's claim names them, and a recovery pays
them. A hub that takes no deposits (`--deposit-sweep-address`) opens no
contract and says so at startup: every contract's default returns the
holder's reserve to a deposit of the hub's (below). `/v1/info` then names that range,
its largest cap no more than the contracts' wallet funds (its confirmed
balance, asked each minute with `getbalances`, less the hub's 100,000 sat
reserve and 50,000 for fees): a larger cap is refused as unavailable. A
login limited by `-rpcwhitelist` needs `getbalances` among its calls, or
the hub advertises the range's largest cap whatever its wallet holds.
The collateral of a contract is its cap exactly, every size of all ones in
as many bits. A contract
opens on a block as deep in the hub's scan as its lock checkpoints, which
it takes as one when the contract opens if newer, so that every lock
named after it can be claimed in it: the hub offers no contract until its
scan of the chain has begun, nor while it lags the tip by more than that
depth. F, a contract's
funding, spends the wallet's coins, which stay locked while the opening
lives. A wallet that has the hub sign F and never broadcasts it holds
those coins locked, so the hub frees them itself. Once a coin F spends is
spent elsewhere 6 blocks deep (her deposit, say), it gives the opening up
and unlocks them. If F is still in no block 144 blocks (a day) after the
hub first saw it, or once F may no longer fund its contract, the hub
spends one of its own coins F spends back to its wallet, then gives the
opening up once that is deep. At most 16 signed openings may wait unfunded
like this; past that, new openings are refused as unavailable, and the
operator is alerted once. F's fee stays within the quote's ceiling (10
sat/vB) over F unsigned, as wallets check it: when the node estimates a rate
near or above the ceiling, F is funded again at a lower one. Since graph id 8,
a contract's graph returns
the hub its reserve if it never responds. Apps older than the graph id a
hub quotes open no contract at it until they are updated, while contracts
opened before keep their terms (see [Upgrading](#upgrading)). Openings are kept in `hub.sqlite`, as sensitive as the seed. Each
opening receives the kept garbled instances from
the holder's wallet, kept in `<data>/opening-instances/`. The hub takes one opening's step, or
builds one instance, at a time, the others waiting their turn: each opening
takes about 30 CPU seconds over a few threads, and the hub holds about
700 MB once it has opened a few: allow it 2 GB of memory.

With `--contracts-payout-wallet URL` (a wallet's JSON-RPC, as
`--contracts-wallet` takes one), each contract opened from then on pays the
hub's share to a new address of that wallet instead of the one that funds
it: what a contract returns at its close, its fold or a default. Make it a
wallet without private keys watching a descriptor whose keys are offline,
on this node or another of the same network:

```sh
bitcoin-cli -named createwallet wallet_name=payout disable_private_keys=true blank=true
bitcoin-cli -rpcwallet=payout importdescriptors \
  '[{"desc": "tr([FINGERPRINT/86h/0h/0h]XPUB/0/*)#CHECKSUM", "active": true, "timestamp": "now"}]'
```

The hub asks it `getnewaddress "" bech32m` for each opening, so it needs
an active ranged `tr()` descriptor; a wallet that holds private keys is
taken with a warning. Spend from it with a PSBT signed where the keys are
(`walletcreatefundedpsbt`, the signer, `finalizepsbt`). What this leaves
on this host: the funding wallet's balance, the collateral of contracts
opened before the option (they keep the address they were signed with),
and the fee coins' change, the outputs a dispute leaves the hub and coins
spent back, which the funding wallet signs for. What contracts return no
longer refills the wallet that funds new ones: top it up from the payout
wallet by hand, or the largest cap `/v1/info` names shrinks with its
balance. No contract opens while the payout wallet gives no address, and
none is ever paid to the funding wallet instead. An opening never funded
leaves its address unused: a signer that looks only 20 addresses past the
last one used may need a wider gap to find them all.

A Core login of the hub's own (`-rpcauth`) can be limited to the calls it
makes with `-rpcwhitelist=USER:CALLS`. Without contracts:
`getblockchaininfo,getblockhash,getblockheader,getblock,estimatesmartfee,sendrawtransaction`.
With `--contracts`, also
`submitpackage,gettxout,getbalances,fundrawtransaction,signrawtransactionwithwallet,gettransaction,lockunspent,sendtoaddress,getnewaddress,listtransactions,getmempoolentry,abandontransaction`.
The payout wallet's login, if another:
`getwalletinfo,getnewaddress,getblockchaininfo,getblockhash`. A call left
out is refused by the node (HTTP 403). This limits the calls, not the wallet: a login that funds contracts still spends its
wallet, which is why that wallet holds no more than contracts need.

Every live contract (signed and not ended, or under way) is an exit the hub
may have to prove at once, should all its holders force their contracts
closed together. `--contracts-max-live` (32 by default, sized for a prover
with a GPU) bounds them. Up to half of it, contracts cost what the hub's
terms say. Past half, the hub's fee (the fixed one and its yearly rate
alike, not the holder's reserve) doubles at each eighth more: 2, 4, 8, then
16 times at 87.5%. At the maximum it opens none until one ends. So the half
it can always defend pays its way, and the rest pays for more or better
hardware. `/v1/info` prices contracts as surcharged now, and a quote made
at another step is refused with 409: wallets give that opening up and ask
for a quote once more, opening at the new price if within what their
holder agreed to pay. An alert says when
the surcharge rises or the hub is full. An upgraded hub already past the
maximum keeps its contracts and opens no new ones until some end.

On regtest, contracts are under a mock proof authority: such a contract
protects nothing. On signet and Mutinynet they are under the genuine programs
kept in `r0/programs/` (new contracts under the newest, those opened before
under theirs, each played to its end), a trial: RISC Zero's shared Groth16
setup, the signets' headers checked by their work alone and not the
network's signature of each block. The hub's terms there are signet's least:
144 blocks (a day, on signet) for the wallet to answer a challenge and for
each party's outputs to wait, 3 blocks deep, 12 blocks at least to respond to
a request, 144 for the holder to contest a response and 48 for the hub to
prove and assert it once contested (a proof takes hours on a CPU). On
Mutinynet the same blocks, a twentieth of the time, but for what a proof
takes: 960 blocks to prove and assert, hours as signet's 48 are, with the
fixed contract and the shortest chosen as many blocks longer (1,912 and
1,488). A proof's cost follows the contract's blocks (7.2 k cycles each) in
the graphs before id 11, so a contract's length is chosen in blocks, not in time;
in id 11 on it does not (below). No other network yet.

A proof reads Bitcoin through block headers, so a hub's statement asks for
work on top of a holder's request's response: a chain mined in private
would have to carry that much to fool it. By default it asks the network's
floor (6 blocks on signet, 1 on regtest). The more value its contracts
protect, the more an operator should ask: `--contracts-work-depth` sets it
for the contracts quoted from then on, up to 144 blocks beyond the floor.
The assertion window and the shortest contract a holder may choose grow by
as many blocks, so the prover keeps as long to prove; contracts already
open keep their terms.

A hub with contracts plays its holders' exits itself, polling its
contracts' Core wallet at `--chain-poll`. When a wallet forces its contract
closed, its request R and its publication (the claim it files) come on
Bitcoin. Once the publication is as deep as a contract's funding, the hub
records every note the claim names as spent in `hub.sqlite`, whatever the
dispute pays her: no spend takes them after, and her claim of them is
evidence against any other claim of the same notes, in any contract. It
reads her filing as the contract's statement does
(`licash::recovery::named`): under the lean filing an item that is not valid
(a note never issued, a hold signature not its note's) is worth nothing and
leaves the rest a claim, which the hub answers and whose notes it records,
each that its hold key signed for, the one never issued too. A note named
with a signature that is not its hold key's is nobody's to give up, and is
not recorded. One exception, of the lean filing: the statement verifies no
hold signature of the notes a lock of hers spends, so it owes her the refund
of a lock the hub never certified whether or not their hold keys signed her
claim. The lock in her filing is signed by their owners all the same, so a
hub retires each such note by it (the component `shown` of `hub.sqlite`,
made empty when a hub of an earlier release opens its file): no spend takes
the note after, the lock itself is never served, and it is the hub's
evidence against any other claim of the note. Then
it decides what the claim is owed against its ledger: the spends it retired
the claimed notes for (owner-signed, a granted one with its unlock), the locks other claims
gave them up by, other claims of them, and, for each timed lock the claim names, the branch it did
not settle it on (its preimage, or its expiry). A candidate its statement
refuses, or that voids nothing but items not valid anyway, is left out
alone, and the others cited. So that each spend is one it can cite, the
hub releases and locks none of more than 64 notes or whose evidence (its
notes and signed proposal) is over 64,000 bytes: refused as invalid
(`licash::spend::MAX_INPUTS`, `licash_hub::MAX_EVIDENCE_BYTES`), its notes
not retired. A record its ledger holds against the claim and cannot cite
(one it cannot read back, or one its statement cannot) is evidence lost:
an alert names the contract and why at once, on the first round it
decides, since nothing the hub does by itself will cite it. `licash-hub
audit` lists such spends of a ledger beforehand. While its ledger gives it
no evidence (its scan behind the claim's block, a halt), it responds
nothing and tries again at each poll; once half the blocks it may respond
in are gone, an alert names the contract and why, and the hub answers on
what its statement decides with no evidence at all, if that is less than
she asks (an item not valid, a refund not yet expired): less than its
ledger would have saved it, more than no answer. The same alert tells of a
publication or headers the hub cannot read, and another of a prover that by
then has not said whether it can prove the answer. Owed all it asks, the hub lets
the holder's timeout pay her. Owed less (a claim of notes that are not the
keyset's, or spent), it responds with what is owed, publishes in the
response's disclose slot what that evidence needs public (a granted spend's
unlock, a preimage), and waits. Its disclosure is due before her wallet,
finding none, contests the response (a block before the last she may, its
margin aside), its fee rising as that nears and a larger fee coin funded
when it pays too little, up to what a contest would put at stake; once
contested, before the proof needs it deep enough. The operator is told
when it is in no block halfway there, and again past it. The holder, shown that evidence at
`/v1/contracts/openings/{id}/evidence` under a signature of the contract's
claim key (nobody else is), checks it herself, and leaves the response
alone if it bears out, which pays her what it says once her contest window
has passed and which the hub posts itself, no proof made. Contested, the
hub proves that statement and asserts the proof; challenged, it answers
with a kept instance, on the proof of the assertion it signed (pinned in
`hub.sqlite` before it signs). The assertion's leaf checks π1's digits but
not π2 and π3 beside them, so whoever relays or mines it can replace those
without changing its txid; the hub answers whatever the block shows. Its
answer needs only some π2 and π3 that prove the statement with the chain's
π1, so the holder, finding an assertion that does not verify as mined,
first asks the hub for the π2 and π3 it signed
(`/v1/contracts/openings/{id}/proof`, under a signature of her claim key
over the assertion's txid, 96 bytes back) and leaves the assertion alone if
they prove it; if the hub shows none that do by halfway through her
challenge window, she challenges as ever. On regtest the proof is the
mock authority's; on signet the hub proves with `licash-r0` (docs/r0.md,
`LICASH_HP_PROVER` names another), as described below. It sweeps its outputs of each payout to its
wallet; a payout's rest and the holder's reserve pay each party's wallet
directly. A holder may close her contract early, and be paid her claim in
the same transaction: she POSTs her nonce, the amount she claims and the
notes it is made of to `/v1/contracts/openings/{id}/fold/claim`, signed
with her payment key in the contract (so that nobody else replaces or
asks for the fold offered to her), and the hub answers its nonce and its fee at its fee rate if its ledger holds
nothing against those notes (none spent, none claimed in another claim).
She then POSTs her partial signature and the filing of her claim (settled
notes of its keyset alone, worth the amount or more) to `.../fold/sign`.
The hub retires the notes in its ledger, all or none, and only then signs
the fold with her (MuSig2, its nonce kept in memory and used at most once;
a partial signature that does not check leaves it offered),
paying her the claim and her reserve back and the rest to the hub less the
fee, and broadcasts it. A note anything spent is refused, not disputed: no
dispute follows a fold to cite the spend in. The holder then asks the
ledger, at `/v1/inquire` (notes of one keyset, each signed for by its hold
key, so that only its holder learns anything of it), for what it holds
against them: the owner-signed spend, with its unlock, or the claim signed
elsewhere. She checks that herself, drops the notes it proves spent, takes
the change of those spends and folds again on the rest; the ledger is
read, nothing retired. Should a fold not confirm
after the hub retired the notes, she files the same claim on Bitcoin by a
forced close, which the hub pays as ever; a contract that ends by its
default or by a fold that pays no claim leaves them retired, as it leaves
the claims of any dispute. The same routes without a claim
(`.../fold` with her nonce alone, signed, `.../fold/sign` with her
signature alone)
fold paying her reserve back only, for the wallets that close that way. Any
key-path spend of a contract output is such a fold, and ends the contract.
A contract no one exited ends at its close: the hub posts its
default, which pays the holder her reserve and the hub its collateral back,
to its wallet. The fee coins its wallet funds for these transactions are
kept in `hub.sqlite` before use, and funded again only once one is gone:
its funding in conflict with a block, or refused by the hub's node when
broadcast again as spending inputs spent or missing (after a reorg, or
another spend of the wallet's coins). The operator is told, once a
contract, and the wallet's funding abandoned so its coins are free; the
coin gone is kept on, and taken back should its funding confirm after all.
A funding refused by the node's policy (its fee, a full mempool), or for a
reason it does not tell, or one the wallet no longer knows (restored older
than `hub.sqlite`) while the coin is in no block or mempool, is not proven
gone: the hub funds no other for it and waits, its operator told, and
told again 12 blocks before the transaction's deadline. Each coin is
funded under a tag of its own, the wallet's comment of its funding, so a
hub stopped between funding one and keeping it finds it again in its
wallet's last 1000 transactions rather than fund another. A contract ended 6 blocks deep is
not looked at again. The same database pins the evidence each response is
decided on and each one-time signature (the response, the assertion) before
it is made, with the openings, so that one copy holds both as of one moment:
a second answer signed with a one-time key over other evidence gives the
holder the hub's outputs. A request is the one pinned when it is the same
transaction claiming the same `b` with the same `E`, however its witness
writes them: a request mined again after a reorg, its digits written
otherwise or her signatures made again, is answered as pinned. So the hub signs none where it can tell one was:
the openings keep each answer before it is signed, and one kept with nothing
pinned for it, as when the pins' rows were lost, is not decided anew. Nor is
one neither keeps (the whole database restored older) while a transaction in
the node's mempool already spends what only that answer can. Where neither
tells (the database restored older and that transaction gone from the
mempool) it decides anew: nothing replaces the backup. A response in a block
whose evidence is lost is not asserted on. Where it signs none the operator
is alerted, and her timeout pays her what she claims, with the hub's reserve
once a response is in a block: restoring the newer `hub.sqlite` is the only
way back without witnesses.

### Contract witnesses

A witness (`licash-witness`, a service of its own) keeps each one-time
answer apart from `hub.sqlite`, so that neither a restore of it older than
an answer nor a second copy of the hub can sign another. Before it signs a
response or an assertion, the hub writes what it signs (its `b′`, the
request's txid, `b` and `E`, and the evidence pinned; for an assertion, π1's
digits and its proof) to every witness of its set, in a fixed order, and
signs only what all of them keep alike: the first decision any of them
kept, which a hub restored older is given back, and signs again the same.
It enrolls each contract in every witness before it signs its F: a witness
keeps no decision of a contract it never enrolled, and the hub opens none
while any witness is unreachable or refuses. A witness unreachable, of
another set, of a sequence lower than the hub last saw (restored older),
or not sealed alike (made anew) stops all signing until it is mended, and
the operator is alerted; two witnesses holding two decisions stop that
contract for good. A witness holds no key of the hub's: each entry is
signed with the hub's witness key (of `seed`, `licash-hub witness-key`)
and checked by the witness; the hub reaches each over TLS to the
certificate it pins.

Set up, each witness on a host apart from the hub and from the others
(another provider, another power and network), two at least on mainnet:

```sh
licash-hub witness-key                      # the hub's witness key
licash-witness --data W init --hub-key KEY  # the first: prints set_id and pin
licash-witness --data W2 init --hub-key KEY --set-id SET_ID
licash-witness --data W run --listen 0.0.0.0:8339
licash-hub run --contracts --contracts-witness-set SET_ID \
    --contracts-witness https://w1.example:8339#PIN1 \
    --contracts-witness https://w2.example:8339#PIN2 ...
```

A hub that never signed a contract seals its new set as it enrolls its
first. One that signed contracts before it had witnesses imports them
first, the hub stopped (signet and regtest only): `licash-hub
contracts-witness-import --network signet --contracts-witness-set ...`
enrolls every contract, keeps each answer it signed as it signed it and
each it may have signed with what it no longer knows (begun, nothing
pinned) never to be signed, then seals the set and binds `hub.sqlite` to
it. Run it again if it fails before its seal. `--contracts-witnesses none`
keeps the answers in `hub.sqlite` alone, as before witnesses: on regtest
and signet only, and refused once `hub.sqlite` is bound to a set.

A witness's database only grows. Back it up as the hub's (`licash-witness
backup --to FILE` while it runs) for its own sake, but never restore it: a
witness restored older is refused. A witness lost is made again from one
that survives, `licash-witness --data NEW clone --from SURVIVOR.sqlite`
(the survivor's database, or a backup of it taken after its last entry),
under a TLS identity of its own whose pin replaces the lost one's in the
hub's `--contracts-witness`. A survivor restored to an earlier point, or a
witness made anew, is never a replacement: with every witness lost, the
hub signs no answer of the contracts it enrolled. Two witnesses that
disagree are never mended by cloning one over the other: the hub would
sign whichever was cloned.

A dispute's links are presigned at 1 sat/vB, each with a 330 sat anchor
only its poster spends. The hub posts its response and its assertion with
a fee child spending the anchor and fee coins of its wallet, as one package
(Core's `submitpackage`, else each in turn): at the node's estimate for
half the blocks left before the link's deadline, doubled for each 3 blocks
fewer than 12 left, 16 times at most, and made again at the higher rate
while the link is in no block. The pair pays at most what missing the
deadline costs the hub (the claim it would pay beyond what it responded,
and its reserve for the assertion); the hub alerts once above that, and
once a link is in no block halfway to its deadline. Its answer to a
challenge and its terminals take a larger fee coin the same way. Its
children and their coins are kept in `hub.sqlite` before broadcast. A
wallet that funds no fee coin (out of coins, locked, not loaded) takes
nothing from a link: the hub posts it with the child its other coins make,
or alone at its presigned fee, and alerts once a contract. Its terminals pay
no fee of their own and wait for a coin, so keep the wallet funded.

A response commits the hub to a proof: its assertion must confirm within
the assert window (48 blocks on signet, 2 of them to confirm in), or the
holder's timeout pays her what she claims, as if it had not responded. So
the hub proves one statement at a time, earliest deadline first, and
responds to a claim only if its prover can still make that proof in time
without making one it committed to late; contested by more holders at once
than it can prove for, it proves for the largest stakes and lets the others'
timeouts pay them (a claim is decided on the poll after the one that first
saw it, all of them known). It plans with its prover's speed, measured at
startup (`licash-r0 probe <program>`, then `licash-r0 bench` once per device, kept in
`<data>/hp-proofs/bench.json`: delete it to measure again, as after
changing the GPU). The probe also executes the program contracts open
under on the benchmark's input, which the image's own library made: a
program built before a change of the format of notes, spends or Bases
panics reading it, and leaves the prover not ready. Before it keeps or
signs anything of a new opening, the hub executes the program the
opening's Base names on an input of that Base (`licash-r0 hp-reads`), and
refuses the opening with 503, and alerts, if the program can't read it: it
could prove nothing of such a contract, and each claim of it would be paid
all it asks. A hub of the mock authority has no prover and checks neither. So that no claim it could reduce is paid by a timeout,
it opens a contract only if its prover could make, one after another in an
assert window, the largest proof of an exit of every contract it is
committed to and of the new one (all its headers to the close, and the
most its publication and evidence may carry; of a chained contract, its
tail and openings, and not its age), and the one batch of its header chain
a dispute may wait for: its holders may all exit at once. It checks this as a holder opens and again, holding its funding lock,
as it funds F, and refuses an opening with 503 when there is no room, or
while its prover is not ready. `--contracts-proof-scale` scales each
proof's estimate (1 by default): above 1 for a prover slower than its
benchmark, below 1 to admit more than it can surely defend. Long contracts
take the most room, as a proof grows with the headers it checks, but those
of a chained graph, which take no more than short ones. A prover not ready (none installed, no
Groth16 setup, under 8.5 GB of memory, a failed benchmark) responds to no
contested claim. The hub's notifications alert it, a prover that fails, a
proof the plan would make late, an assertion's deadline 6 blocks away
unproven, the claims a round gave no response to, and more contracts open
than proofs of the smallest one its prover makes in an assert window (the
exits it can contest at once). Each proof's work is
in `<data>/hp-proofs/<id>/`: its input, frozen once it first holds, the
prover's progress, carried on across restarts, its `prover.log` and
`proof.json`. The proof is pinned in `hub.sqlite` before the assertion
is signed.

### The header chain

A contract of graph id 11 on is decided on the hub's header chain, proven once
(docs/r0.md, The header chain), so that its proof does not grow with its age:
contracts of 6 to 24 months cost the hub what a new one does. The hub keeps
the chain in `hub.sqlite` (the component `header_chain`: its start, every header
after it, the receipts of the chain program) and the receipts' files in
`<data>/header-chain/<chain program's image id>/`, beside it.

- **Start.** At the first quote of a chained contract, 144 blocks below its
  checkpoint (a holder can name a block near the tip, which a reorg could take
  back, and nothing authenticates a start). A hub quotes a checkpoint only if
  it is a block of the chain in the state its Base binds (it follows the node's
  as it quotes), and refuses with 503 otherwise.
- **Following.** Each poll of the responder follows the node's chain through
  the blocks 6 deep, in the hub's process, with no proof. A reorg cuts the chain
  back to the last block it and the node agree on, and the receipts, and the work
  kept of batches, beyond it; the chain is cut back only on what the node says of
  its blocks, never on what it fails to say. Its operator is told of a chain that
  cannot follow the node's (a start no longer on it, a reorg of 1,000 blocks).
- **Proving.** A batch is proven by the hub's prover when no dispute's proof
  can run, for a day of blocks since the last receipt, or for the blocks a
  dispute asks for at once, which is made before another dispute's proof, as that
  one cannot start without it. A batch of the day is stopped for a dispute, and
  proven again from the segments it kept. A receipt is kept only if the chain still
  commits it and its file is the one that was made (a digest is kept); the newest
  four are, and the newest that is 100 blocks below the tip, so that a reorg
  does not leave the chain to be proven again from its start. The prover is not
  ready without the chain program installed (`r0/programs/<image id>.bin`).
- **A dispute** asks for the receipt through the last block of its exit (its
  request, publication, response and disclosure), takes the few headers after
  it that carry the work its contract asks, and opens what the judgment reads. Its
  proof is frozen with that receipt (`<data>/hp-proofs/<id>/chain.receipt`) and
  proves it alone. Behind by more than a day (the hub down for days), a
  dispute waits for the batches that catch up, which no admission has reserved
  for: keep the hub running, and its chain proven.

Back up `hub.sqlite` and `header-chain/` as above. A hub without its header chain (its component
lost, a restore older than the chain) cannot prove a chained dispute and is
told so; its holders' claims are then paid by their timeouts. Upgrading from a
release before graph id 11 starts no chain until the first chained quote and
changes no contract opened before: they keep their programs and their
reserves. A release that changes the chain program (a change to `licash-chain`,
or to the zkVM's recursion) is a new chain, proven from its start, and its
statement a new program; the receipts of the old chain are for the contracts
opened under it.

The image of apps/hub/Dockerfile (x86-64) has the prover: its CPU build,
its CUDA build, which it proves on when the container has a GPU (`--gpus
all`, or a Compose `deploy.resources.reservations.devices` entry with the
NVIDIA runtime; drivers 550 or newer, Turing or newer, 6 GB of memory are
enough), RISC Zero's Groth16 setup and the programs contracts open and
opened under: the prover is not ready without the one they open under,
and responds to no claim of a contract whose program it lacks (alerting
the operator).
On an RTX 2060 (measured, under the load of a shared machine) a chained
contract's proof takes about 12 minutes whatever its age (the Groth16 wrap about
1 of them, on the CPU), and a batch of the header chain of 1,500 headers about
4.5 minutes. A contract of an earlier graph (id 10 and below) takes the same
and about 1.6 minutes more for each 1,000 headers since its checkpoint (17 minutes
with 3,015): one of signet's longest, 26,280 headers (half a year), about 55
minutes, and two years of them (105,120) about 3 hours, so a hub proves only
a few such in an assert window, where chained contracts of any length cost it
12 minutes each. The programs before the compact filing's (graph id 8 and
below) took three times the cycles of a header. On a CPU alone a proof takes
hours, too slow for signet's window but for the smallest contracts. Give it
10 GB of memory or more. ARM images have no prover: their hubs respond to no
contested claim on signet.

The hub stops, with an error, when one of its loops stops: the chain's
watch, the tweaks' index, the gateways, the contracts' responder and
sweeper, the swaps. Run it under a supervisor that starts it again (as
Docker's `restart: unless-stopped`).

With `--swaps` (and `--chain`), the hub provides the swaps into it from the
hubs of `--swaps-from URL=CAP`: a wallet locks its notes at such a hub to
the hub's provider, and the hub locks notes it issues to the wallet under
the same hash. The wallet reveals the preimage to the hub itself, so the
provider always learns it in time to claim the wallet's lock. The hub's
lock expires `--swaps-confirm` (36 by default), `--swaps-margin` and two
blocks before the wallet's. `--swaps-fee-base`, `--swaps-fee-ppm`,
`--swaps-min` and `--swaps-max` set the terms. CAP bounds the notes the
provider holds at that hub, or is owed by the swaps under way: past it,
swaps from that hub are declined. A cap holds for every URL the provider's
wallet knows the hub by, such as the URL given and the `https` one it
moves to, and counts the swaps recorded at each of them. By default it
also takes in only what recovery contracts at that hub protect, keeping
them as a standalone provider does (see `docs/swaps.md`): the first
at each hub opened by the operator with `licash-wallet --wallet
<data>/swaps/wallet.sqlite open-contract URL --chain URL`, then replaced
before they end and forced closed at their safe deadline if needed, the
provider's wallet looking for its coins on the hub's chain. The
`--swaps-contract-successor-days`, `--swaps-contract-exit-days`,
`--swaps-contract-max-price` and `--swaps-drain-via` flags match the
provider's. The hub's own notes, which it issues, need no contract. With
`--swaps-from`, a hub on a network where no contract opens (only regtest,
signet and Mutinynet do for now) refuses to start, unless `--swaps-no-contracts`
runs it unprotected, which is reckless; a hub upgraded to this version
takes nothing more in from a hub until a contract there is live. Back up
the contracts (kept in `<data>/swaps/wallet.sqlite`, their instances in
`<data>/swaps/contracts`) with the provider's wallet. The
hub locks no hash its Lightning receipts or deposits hold. The provider's
wallet and swaps are kept in `<data>/swaps/wallet.sqlite`, one file made on
the first start: back it up with `hub.sqlite`, since an older copy loses
the claims backing notes the hub locked. The hub refuses to start without `--swaps` while swaps are under
way. Each round, the provider's wallet also reshapes the notes it was paid,
as a standalone provider's does (see `docs/swaps.md`). To move the provider's notes out, stop the hub and run `licash-wallet
--wallet <data>/swaps/wallet.sqlite`. The provider's wallet reaches hubs
directly, so it cannot swap from a hub at an onion service only, unless
with `--swaps-tor`: then through a Tor client of the hub's own, that of
`--onion` (its state in `<data>/tor`), to onion services and to the clear
web alike.

With `--onion`, the hub also serves its API as an onion service of a Tor
client of its own (Arti), and announces its URL, reaching the relays
through Tor too. The service's key is in `<data>/tor/state`: back it up to
keep the address. Under load, the service asks its clients for a proof of
work (Tor's onion service defense), unless `--onion-pow false`: each new
circuit to it then costs work, and the hub caps the deposits and receipts
asked and unpaid over one circuit (see below). Licash's own clients solve
it, as do Tor clients from 0.4.8 on.

From one source, the hub takes at most 8 deposits asked and not paid, and
apart 8 Lightning receipts: past them it refuses as unavailable, until one
is paid or its window ends. A source is an onion service's circuit (every
stream of one rendezvous shares it, another circuit is another source), or
else a client's IP address, whatever its ports: an IPv4 address over IPv6
is that IPv4 address, an IPv6 address is taken exactly. Clients behind one
NAT share a source. Asking for many thus costs many circuits (over Tor,
many proofs of work while the service is under load) or many addresses.
Since addresses are cheap to a botnet or an IPv6 block, the global caps
(`--deposit-max-open`, and the gateway's for receipts) remain the bound on
everything asked and not paid.

Behind a reverse proxy, the hub's TCP peer is the proxy: every client
would share its one address. Name the proxy with `--trusted-proxy`
(`LICASH_HUB_TRUSTED_PROXY`), an address or a CIDR block, repeated or
comma separated. From a trusted peer only, the hub reads
`X-Forwarded-For`, from the right while each address is trusted: the
first that is not is the client (the leftmost if all are). It ignores the
header from any other peer. A trusted proxy's header that does not parse
(an entry that is not a bare IP address, such as one with a port, or more
than 16 entries) has deposits and receipts refused as invalid, so a
misconfigured proxy shows at once. For Traefik:

- set the entry point's `forwardedHeaders.trustedIPs` to nothing (the
  default), so Traefik replaces any `X-Forwarded-For` its clients send
  with the address it saw, rather than appending to theirs;
- run `licash-hub run --listen <private address>:8338 --trusted-proxy
  <Traefik's address or network>`;
- firewall `--listen` so only Traefik reaches it: a client reaching the
  hub directly from within a trusted block could name any source.

Deposits and receipts recorded by an older release keep the source it
stored, its peer's address and port: they count against that address
until paid or ended.

Notification targets are Apprise URLs (`gotify[s]://`, `tgram://`,
`ntfy[s]://`, `json[s]://`, `apprise[s]://`); `test-notify` checks them.
Each notification lists the event's figures, ids cut to 12 characters as
on the dashboard: a spend released or a lock paid or refunded shows the
hub's income, its fee, and its rate as a percentage of the amount. Costs,
such as Lightning routing fees, go unrecorded, so no profit is shown.
`--notify-kinds` picks the kinds of event: by default all but locks
admitted (`locked`), still under way, whose fee is the hub's only if they
pay. The high-priority ones need
a look: a double spend refused; a lock activated on Bitcoin (its preimage
published in time, so it pays), or one the hub had refunded already, after
a reorganization (it owes the payee too: check the reserves); a
reorganization at or below a checkpoint (the hub follows Bitcoin no more,
taking and refunding no locks, until you act); a halt; and alerts.

```sh
docker build -f apps/hub/Dockerfile -t licash-hub .
docker run --rm -v licash-hub:/data licash-hub init
docker run -d -p 8338:8338 -v licash-hub:/data licash-hub
```

## Upgrading

Stop the hub, back up `<data>` (see the backups above), replace the binary and start it
again, except from a ledger of schema 3, 2 or 1, whose hub is not replaced (below).
Before starting it:

- Install every program of `r0/programs/` (see `docs/r0.md`): a contract
  keeps the program it opened under for as long as it lives, and a prover
  lacking one responds to none of its contested claims.
- Expect no migration: a database or file of an earlier layout is refused
  by name, never read nor replaced.
- A Core login of the hub's limited by `-rpcwhitelist` needs, with
  `--contracts`, `listtransactions`, `getmempoolentry` and
  `abandontransaction` too (above). Without `listtransactions` its operator
  is told, and a hub stopped between funding a fee coin and keeping it
  funds another.
- A hub of `--contracts` started without witnesses refuses to start:
  name its witnesses ([Contract witnesses](#contract-witnesses)), and on
  signet, with contracts signed before, import them first; or, on regtest
  and signet, keep them in `hub.sqlite` alone with
  `--contracts-witnesses none` (`LICASH_HUB_CONTRACTS_WITNESSES=none`).
  Its contracts under way are answered only once it runs again, so do this
  before their deadlines. Never start an earlier release on a `hub.sqlite`
  bound to witnesses: it knows none, and signs as if it had none.

### From a ledger of schema 3

A hub of note format v5 reads a `hub.sqlite` of ledger schema 4 only. A
note's message is its denomination, owner key and hold key, without the
nonce that made nothing unique that the one-time owner key did not, so
every note identifier differs; it issues a blinded point once whatever
its keyset, and its contracts run a rebuilt program. A ledger of schema 3
is refused at start, saying so, and left as it is, as from schema 2
(below): its contracts end under the hub that opened them, which keeps
its binary, its programs and its URL, and a Docker hub that follows `main`
must be pinned to its own `sha-` tag first. The steps are those below:
`licash-hub audit` reads ledgers of schema 1 to 4, and the swaps wallet
of that release is of wallet schema 5.

### From a ledger of schema 2

A hub of note format v4 reads a `hub.sqlite` of ledger schema 3 only. Its
grants are ones anyone verifies, and it cites a spend against a claim by
the signatures of the owners the claim relies on, so that its proof costs
what the claim names, not what the spend took and made; its contracts run
a rebuilt program (graph id 14). A ledger of schema 2 is refused at start,
saying so, and left as it is. Nothing of it carries over, as from schema 1
(below): its contracts end under the hub that opened them, which keeps its
binary, its programs and its URL. A Docker hub that follows `main` would
take the new image and refuse its ledger: pin it to its own `sha-` tag
first.

The steps are those below: stop new openings with
`--contracts-max-live 1`, run `licash-hub audit` (it reads ledgers of
schema 1 to 3), let every contract close, then make a hub anew with `init`
in a new `<data>` and a new seed. The provider's swaps wallet,
`<data>/swaps/wallet.sqlite`, is a wallet of the same release (wallet
schema 4): spend or pay out its notes at the other hubs with the old
binary, then move it aside with the rest of `<data>`; the new hub's
`--swaps` makes a new one.

### From a ledger of schema 1

A hub of note format v3 reads a `hub.sqlite` of ledger schema 2 only, and
its contracts run a rebuilt program, whose statement reads no proposal of
more than 64 inputs or 128 outputs a branch. Nothing of a schema 1 ledger
carries over: its contracts end under the hub that opened them, which
keeps its binary, its programs (none of them is in `r0/programs/` any
more) and its URL, where its holders' wallets reach it. A Docker hub that
follows `main` would take the new image and refuse its ledger: pin it to
its own `sha-` tag first.

1. On the old binary, stop new openings: restart it with
   `--contracts-max-live 1`, which refuses an opening while any contract is
   live.
2. Find the spends its ledger retired notes for that no dispute can cite
   (a release before refused none): `licash-hub audit` (read-only; beside
   the running hub or without it, `--json` for a list). Each of these
   spends' notes, claimed on Bitcoin, goes unanswered and its holder's
   timeout pays her for it: the loss is the hub's. The command fails while
   it finds any. Back up `hub.sqlite` with the list.
3. Have every contract closed. The hub closes none by itself: each holder
   closes hers early from her app (her claim folded into the close), or it
   ends at its close height. Keep the old hub running, answering, until
   each close and each claim under way is buried.
4. Once holders have spent their notes of it down, stop it, move `<data>`
   aside (keep it: its seed and ledger), and make a hub anew with `init` in
   a new `<data>`, its programs installed. Never copy the old `seed` into
   it: v3 derives the same note keys from a seed, and the new ledger's
   empty spend log would accept the old notes' identifiers again.

Contracts opened before keep their graph, program and reserve; only new openings take the new
graph, and apps older than it open none until they are updated. Read the
notes of each paragraph above that names a graph id or a release for what
else an upgrade changes (fees, the header chain, the gateway's records).
