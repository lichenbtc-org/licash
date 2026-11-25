# Wallet CLI reference

`licash-wallet` keeps a wallet (`crates/licash-wallet`) in one file and
pays through the hubs it trusts. `licash-wallet --help` lists the commands.

```sh
licash-wallet init
licash-wallet add-hub https://hub.example
licash-wallet receive payment.json        # or from stdin
licash-wallet send <address> 1000 > payment.json
licash-wallet resume                      # after a payment ended pending
```

A wallet trusts hubs of one network, `bitcoin` unless `init --network`
names `regtest`, `signet` or `mutinynet`.

`address`, `code`, `invoice` and `deposit` take `--qr` to also draw what
they print as a QR code, black on white, for a payer's phone to scan off
the screen. It is drawn only when stdout is a terminal and without `--json`:
a script reading stdout gets the same text as without `--qr`. `code --qr`
prints the code in upper case too, which the QR code holds in fewer modules.

A payment is JSON that only its payee can open: hand it over by any
channel. `send` and `resume` exit with 75 when a payment is recorded but its
hub has not answered; `resume` finishes it. Back up the wallet file: its
seed alone does not restore its notes. After restoring an old copy, `check`
drops the notes its hub proves spent since (it shows the spend, which the
wallet verifies: a hub's word alone drops nothing) and takes the change
those spends paid the wallet. Only the notes' own holder can ask.

Notes are unlinked from the payment that made them as they are received,
and a payment's change as it is sent, so that their hub cannot tell where
one came from when it is spent; `unlink` asks again for those left linked.
A hub that restarted no longer unlinks the notes it issued before: the
wallet renews them, paying them to itself for notes it unlinks, once, if
the hub's fee on them is at most `--renew-ppm` parts per million of their
value, or its spending schedule is at most 1 sat base, that relative rate,
and 0.1 sat per output (`LICASH_WALLET_RENEW_PPM`, 1000 by default, 0 for
free renewals only). Live contract ceilings take precedence. `history`
lists a renewal as a payment to the wallet's own address.

Ordinary payments opportunistically consolidate already unlinked notes and
shape their change toward 18 to 24 notes, using the smallest feasible
largest denomination. This leaves receiving room below the 32-note claim
limit without tying a distribution to a contract's cap. Linked notes are
not added merely to consolidate. Any increase in the payment's fee must
fit its live contract ceilings or the automatic fee allowance above.
The resulting denominations can change whether a later Lightning lock
needs a paid self-payment to make exact notes. Consolidation also consumes
old notes: keep wallet backups current, since a stale copy does not know
the replacement notes and cannot recover them from the seed alone.

A wallet that mostly receives gathers many small notes, so `unlink`,
`receive`, `claim` and `resume` also maintain them: at most one remint per hub
of unlinked notes to itself, toward the same distribution. Notes rest 1 to 6
hours after unlinking (a few minutes when nearing the 32-note limit), as
does the hub after each remint, so that a remint follows no payment closely.
Its fee must fit the live contract ceilings or the automatic allowance
above, and at most 1% of the notes held at that hub (at least 1 sat) is
spent on it in any 24 hours. A failed remint never fails the command, and
one refused for its fee is not retried at a higher one. `optimize <hub>`
previews a remint with its fee; `optimize <hub> --max-fee SAT` makes it
now, within that fee and the contract ceilings, bypassing the rests and the
daily budget. `history` lists a remint as `optimized notes`, with its fee.
A wallet file is never migrated: one of another version is refused and left
as it is. A wallet of the release before note format v3 (wallet schema 3)
holds notes whose issuance proofs this version does not verify: spend or pay
out its notes, and let its contracts close, with that release's binary, then
`init` a new wallet in another file. Hubs of v3 are new hubs, and refuse
wallets of v2, which refuse them in turn. So, likewise, is a wallet of the
release before note format v4 (wallet schema 4), whose notes and grants
this version does not read, and hubs of v4 are new hubs, and one of the
release before note format v5 (wallet schema 5), whose notes' messages
carry a nonce this version does not read: hubs of v5 are new hubs.

`code` prints a payment code (a BIP321 URI, `--qr` for a QR code) naming the
wallet, the hubs it is paid at and its Nostr mailbox, if they name relays.
`pay <code> [amount]` pays it at a hub it names that the wallet trusts and
holds enough at, and is done once the hub releases the payment: the hub
keeps it for the payee, who collects it there and tells the payer so
through the hub, signed with a secret only the two share. A payment not
collected within an hour is sent to the payee's mailbox on Nostr by
`deliver`, by `watch`, or after `mailbox` and `resume`; one the hub
does not keep is sent there at once. A code naming no mailbox has its
payment printed to hand over as well, as has one no relay took: a payment
of many notes can be larger than the 64 KB relays commonly take, which
the warning then says. `mailbox` (or `collect`) receives
what the hubs keep for the wallet and what was sent to its mailbox (the
newest 500 messages on each relay: a relay answering that many is warned
of, since anyone can send to a mailbox and newer junk can hide an older
payment there); `watch` keeps receiving and delivering, every `--every` seconds (60), until
stopped. Other commands that open an existing wallet start a one-shot
collection as they exit, with one collection pass per wallet at a time.
The next command can see any receipts it collected and reports collection
failures on stderr. Use `--no-collect` or
`LICASH_WALLET_NO_COLLECT=true` to skip the background check. Run `collect`
to wait for collection to finish now. Keep `watch` running, or schedule
`deliver`, to send fallback mail while the wallet is otherwise idle.
Restart an existing `watch` process after upgrading so it shares the
collection lock with the new CLI.
`pay` does not mail older receipts:
a slow relay must not delay a new payment kept at its hub. Its change is
still unlinked before exit. Payments kept at the hub appear on Nostr only
if they missed the hour. `pay --note TEXT` tells the payee TEXT (its words
one space apart, at most 200 bytes), and `--share-code` the wallet's own
code, proved to the payee alone (a proof they could have forged
themselves, so it convinces no one else): both sealed for the payee, of one
size whatever they say, so neither the hub nor a relay reads them. Every
payment to a code at a hub naming the `note` feature in its info carries
one, empty if nothing is said; a note is asked only of such a hub, its info
fetched again first if it named none (so the first note after a hub's
upgrade may stand out), and another refuses the payment, nothing paid.
`history` shows sends and collected receipts together, newest first, in
local time. Scripts can use `--json history` for sends and `--json received`
for receipts, both with Unix timestamps. `mailbox` shows what it collects.
`new-code LABEL` makes an extra code, numbered from 1, of keys of its own
derived from the seed, naming no mailbox: no one can tell it is the
wallet's, or another extra code's. `codes` lists them, what each received
and its fees; `code --extra N` shows one, and `pay --share-extra N` shares
it instead of the wallet's own. `mailbox`, `collect` and `watch` (any
inbox collect) take what each was paid at its hubs first, from a wallet
file of its own (`WALLET.codes/N.sqlite`), and pay it on to the wallet's
own code after a delay of between 1 and 30 minutes of each payment's own
(at once on regtest), less the hub's fee (an amount below the fee waits):
shown as
received at the extra code, the payment on as moved in. A hub keeps a
payment in its inbox for 14 days, after which its payer must hand it over.
A wallet restored from its seed has no extra codes until made again, in
the same order.
Where the wallet holds
too little, it swaps what it lacks there first through a provider
announced on its hubs' relays, only if given `--max-fee` (all fees,
swap included): without it, it says what the payment would cost. A code
naming no hub the wallet trusts is paid so at a hub it says where to reach,
visited only if it proves it is the hub the code names: what the swap brings
past the payment stays there, apart from the hubs added, until `add-hub`:
`balance` shows it after the total, outside it and its `--json` rows.

Normal output stays short: `balance` shows the available amount and any
pending or uncounted funds; `balance --details` adds the full per-hub
breakdown. `pay` reports where the payment went (kept at the hub, or sent
to the mailbox) and the fee bound (sat and a percentage of the payment),
not whether the recipient has collected it yet; `deliver` says how many
payments are still on their way.
`pay --details` adds the payment ID and hub URL. Payments that must be
handed over still go unchanged to stdout or `--out`, with instructions on
stderr. Progress appears on an interactive terminal only. Diagnostic logs
are off unless requested with `--log text`, `--log json`, or `RUST_LOG`;
delivery failures and actionable warnings remain visible without logging.

A lock pays its payee on a secret's preimage until it expires, then returns
to the payer: the payee runs `secret` and hands over the hash, the payer
runs `lock <address> <amount> <hash>`, and the payee runs `claim <id>
<preimage>`. `resume` follows the payer's locks to their end. A claim reveals
the preimage to the hub only once the wallet recorded what proves the lock
on Bitcoin, its payer's signatures and the checkpoint it names, both served
with the lock's state (`/v1/lock/{id}`): a hub leaving either out is
retried, and learns nothing.

Through a hub with a Lightning gateway, `pay-invoice <bolt11>` pays an
invoice with a lock refunded if the payment fails, and `invoice <amount>`
prints an invoice paying the wallet; `resume` takes the payment once made.
With `--chain <url>`, `invoice` protects the payment where it can: with a
contract of the wallet's at the hub (v4 or later) whose forced close is
planned 36 blocks on or later, a coin to activate the lock with, and an
amount worth more than the activation, the lock's preimage is revealed
only with 6 blocks left, so a hub keeping the notes is met on Bitcoin
(`recoveries --chain` activates the lock and the contract's recovery claims
it); a lock shown later is left to expire and the payment fails back.
The 6 blocks are counted at the chain's height as the wallet knows it of
itself, never on its hub's word alone: `resume --chain <url>` tells it, as
does the last block it scanned, and a protected payment waits, unclaimed,
for a `resume` that knows neither.
Without `--chain`, or where it can't, the hub is trusted with the notes.
`invoice <amount> --memo TEXT` has the invoice say TEXT to its payer (its
words one space apart, at most 100 characters): asked only of a hub naming
the `memo` feature in its info, and an invoice without it is canceled, never
printed. The hub and its Lightning node read it too. `invoices` lists it.
An invoice another wallet asked the same hub for is paid inside the hub,
for its amount alone, with no gateway fee.
`invoice <amount> --via <provider>` has a swap provider taking payments
for wallets (`licash-swaps run --receive`) make the invoice from its own
node instead, for a hub without a gateway: it asks the amount and the
provider's fee exactly, and once paid the provider locks its notes to the
wallet at `--hub`, which `resume` claims as it claims a hub's. Nothing is
trusted to the provider, but it sees the amount, the memo and which
payments go to the wallet. Not with `--chain`.
`pay-invoice <bolt11> --via <provider>` has a swap provider that pays
Lightning invoices pay it from its own node instead, for a lock of notes
at `--hub` to the provider, its fee on top (at most `--max-fee`, 1% and 100
sat by default). The lock expires soon after the provider's routes end: a
payment that fails or the provider declines leaves it to be refunded then.
The wallet records the provider with the lock, and `resume` asks the
provider again until the payment settles or fails, so a payment interrupted
before the provider heard of it is still made. Running it again for the
same invoice follows the same lock. The invoice is not paid through a hub's
gateway while a provider's lock pays it, nor the other way around. An invoice another wallet asked
its hub for pays that wallet notes there: notes at one hub pay notes at
another, with no notes of the provider at the other.

Through a hub taking deposits, `deposit <amount>` prints a BIP21 URI to pay
on Bitcoin, the hub's fee on top; `resume` takes the notes once the payment
confirmed. A deposit never received is taken back after its timeout with
`refund <hash> --to <address> --chain <url>`. A deposit's lock's preimage
is revealed only with 6 blocks left, at the higher of its hub's height and
the chain's as the wallet knows it of itself (`resume --chain <url>`, or the
last block it scanned); a wallet that knows neither trusts its hub's word
for the height, as it trusts it with the notes. A deposit's refund key derives
from the seed, the hub and its number there, and its preimage from those,
a key drawn for it, the notes asked and the payment: a wallet restored from
its seed finds the deposits it asked at a hub by their refund keys as it
adds it (until 20 numbers in a row are unknown there), keeps those the hub
answers as they were asked (other notes or another payment are another
hash, and not kept), then takes them on or refunds them as any.

`code` prints `licash:<code>`, naming the wallet's mailbox and at most three
of its hubs: by default those whose contracts have the most room to protect
more than is held there, then those holding the least. `code --onchain`
prints instead `bitcoin:<address>?sp=<address>`, the wallet's silent payment
address and a fallback address any wallet pays. `onchain --chain <url> scan` finds what
they pay with the tweaks of every hub trusted serving them, asked at once,
those of a block any of them serves (fetching only the blocks whose
filters match from a node with `-blockfilterindex`): one lagging or not
answering within 10 s of another that served every block asked for is
passed over. In blocks no
hub trusted serves tweaks of, it finds what the fallback addresses are
paid only, looking in them again for silent payments once a hub serves
their tweaks; with no such hub, the first scan needs `--from <height>`,
unless the wallet was made with `init --chain <url>` (or
`LICASH_WALLET_CHAIN`). Such a wallet looks from that chain's tip, its
seed new: its first scan reads no older block (one from a Mutinynet hub's
first tweaks took 40 minutes). Should the chain not answer, or be of
another network than `--network`, `init` warns and the wallet looks from
the hubs' first tweaks, as one made without it.
`onchain coins`
lists the coins, `onchain send <to> <amount>` pays an address, a silent
payment address or a code on Bitcoin, and `onchain move` deposits a coin
for notes at a hub taking deposits. With `--chain`, each of these looks for
coins first up to the chain's height, as `scan` does. Coins are never joined: a send spends
one coin alone (`--coin TXID:VOUT`, by default the largest, `--all` all of
it), and a move deposits one coin whole, leaving no change (`--coin`, by
default the largest), refused if the hub takes less than all of it.

A broadcast error can follow successful relay. The signed transaction and
its inputs stay reserved, and `onchain scan` rebroadcasts that same spend.
Do not make a replacement payment merely because the response was lost.
Existing pending spends need no conversion; transactions abandoned by an
older version cannot be reconstructed automatically.

`swap <amount> --to <hub> --provider <url>` swaps notes at another hub for
`amount` at `<hub>` through a swap provider, with a lock at each hub:
nothing is revealed until the provider's lock pays the wallet, and a swap
that fails leaves the wallet's lock to return once expired. `resume` takes
a pending swap on. Without `--provider`, the wallet takes one announced on
Nostr (on `--relay`, else the relays its hubs name) that swaps the amount
within `--max-fee` and `--max-margin` (200 blocks by default: what a
provider other than the hub swapped to needs at a hub of the usual
144-block window): one it swapped through before, else the cheapest. A
swap is refused before anything is locked unless the source hub admits a
lock that outlasts the provider's by that margin. The provider's lock is
claimed only with more than 3 blocks left at the highest of the heights
both hubs say and the wallet's own: with `--chain` (or
`LICASH_WALLET_CHAIN`), its tip, else the last block it scanned. So a
provider and its hub saying the chain is behind cannot have an expired
lock's preimage revealed unless the source hub says so too, or the wallet
knows the tip itself.

`payout <amount> --to <address> --chain <url>` pays
`amount` to an address on Bitcoin, a silent payment address, or a
`bitcoin:` code naming either (its silent payment address first), from
notes at a hub, through a provider
paying out on chain: the wallet locks the amount and the fees to the
provider, which locks a coin under the lock's hash, and the wallet claims
that coin, paying the address exactly `amount`, once it finds it confirmed
on its own chain source. Nothing is revealed before; a payout that fails
leaves the lock to return once expired. The chain source is trusted for
that confirmation, and its claim reveals the lock's preimage: use your
own node or one you trust, never one the provider runs or names, or the
provider could show a coin that is not on Bitcoin and take the lock. `--max-fee` bounds everything on
top of the amount (the claim's fee, the provider's and the hub's). Without
`--provider`, the wallet takes one announced on Nostr (on `--relay`, else
the relays its hubs name) that pays the amount out within `--max-fee`: one
it paid out through before, else the cheapest.
`payouts --chain <url>` takes the payouts under way on and broadcasts their
claims: run it until the payout is done. A claim still in no block fewer
than 12 blocks before the provider may take its coin back is made again at
twice its fee, doubling every 3 blocks (16 times at most), the address paid
that much less: the preimage is out by then, and the provider's refund would
lose the whole amount.

`cold set <key> --threshold <sat>` withdraws to cold storage, an external
wallet named by the extended public key of its account: a `zpub` (`vpub`
off mainnet) for native segwit addresses, or an `xpub` (`tpub`) with
`--script wpkh` or `--script tr` (taproot, BIP86). Each withdrawal pays an
address of the key's receiving chain (`0/i`) never paid before nor found
holding a coin. `cold --chain <url> run` looks in the blocks from
`--birthday` (by default the chain's height when set) for what its
addresses hold, follows the payouts, and once the notes exceed the
threshold pays all but `--keep` out from the hub holding the most, through
the provider announced asking least within `--max-fee-percent` of it (1% by
default), one withdrawal at a time: run it now and then, as with `cron`.
`cold show` prints the balance found and the next address (looked for first
with `--chain`), `cold clear` stops withdrawing. To bring funds back, pay an
address of `code --onchain` from the cold wallet: the coin is found by
`onchain scan` and moved to notes or a contract from there.

`open-contract <hub> --chain <url>` opens a recovery contract at a hub the
wallet trusts that opens them and takes deposits: its collateral protects
the wallet's notes there, up to its cap, until the contract's deadline. The
wallet spends one coin on Bitcoin whole, the smallest that a contract of the
hub takes (`--coin TXID:VOUT` names another): the coin pays the hub's price
(the reserve and the hub's fee) and all the rest of it funds your part of the
contract, issued back to the wallet as notes at the hub once the contract's
funding is 3 blocks deep (`contracts --chain` collects them), the hub's
interest charged on its own part only (and its rate for yours, often none).
No change comes back from the coin, so what the contract takes of it is all
of it but less than dust: a coin short of the price, or beyond what the hub's
largest contract takes, opens none, and says so. Until the notes come the
contract can't be closed early, and should the hub never issue them, forcing
it closed claims them. It uploads about 250 MB to the hub, the garbled
instances the hub keeps (25 MB each), and keeps none of them: it derives
them again when needed. The contracts are in the wallet file (a snapshot of
it, such as `sqlite3 wallet.sqlite ".backup FILE"`, holds the wallet and its
contracts as one); `contracts/` next to it holds what a forced close under way uses. `--blocks` sets the blocks to its close (by default the most the hub
allows), `--max-price` the most to pay besides your part (by default no more
than sane fees make it). At a hub that lets wallets choose (its info names a
range), `--cap` with `--blocks` sets the least the contract protects, one of
the hub's sizes (`2^n - 1` sat, 131,071 to 2,147,483,647, those the hub
allows): the contract is the smallest of them at least that large that takes
the coin, at the price the range gives.
`contract-terms <hub> [--cap <sat>] [--blocks <n>] [--funded <sat>]` shows
what a contract costs before opening it, itemized: the hub's opening fee, its
yearly interest on its part and on yours, your reserve (returned as it
closes, as notes) and your part for the `--funded` you name, with the sizes
and durations the hub allows; `open-contract` prints the same, of the
contract that opened. While it opens, on an interactive terminal and
without `--json`, a line on stderr says how it goes each second: the
wallet preparing a step, then, once its upload starts, the megabytes sent
of about how many, the speed in kbps and about how long the rest takes.
Several contracts, at one hub or several, each take
their own coin. No contract opens at a hub charging more than is sane (over
10 sat or 1% on a payment, lock or refund, over 1 sat for each note made, or
over 20% of a chosen cap a year) unless `--any-fees` asks all the same.

With no coin on Bitcoin, `open-contract <hub> --with-notes --chain <url>` pays
for one with notes instead, in two steps. First a payout: a swap provider
(`--provider <url>`, or by default one announced on the relays the wallet's
hubs name or `--relay` names, as `payout` finds it) pays the wallet's own
fallback address a coin worth the contract's price and 1,000 sat of it yours
(the hub funds the rest), more of it yours if that is less than the least
coin the provider pays out now (its `--payout-min`, risen with fees; of
those announced, the lowest), for notes locked to it at `--from` (by default the
hub holding the most; another hub's notes do, the provider swapping them), the
claim's, provider's and lock's fees
at most `--max-fee` (by default 1% and 2,000), the claim budgeted at
`--fee-rate`. Then, once the claim is buried and the wallet found the coin
(looking for it in the blocks since it last looked), the contract opens on it
as on any coin, as `contracts --chain` carries it on (the command does both at
once if it can). Each step is the usual one, trusting nobody new: should the
opening fail three times, or a claim bumped to a higher fee leave a coin that
no longer fits the contract (about all of your part spent on fees), the coin
stays yours to open with or spend. Notes on Lightning pay for it once received
at a hub (`receive`). A wallet file without paid openings is unchanged by
them: their table is made with the first one.

A contract that runs out with no claim ends by default, and your reserve goes
to a deposit of the hub's that the contract names, not to a coin of yours:
the contract's end then pays your wallet nothing that links it to your other
coins. The wallet finds the deposit paid when it next resumes after the
close, asks the hub for notes worth the reserve less the fee the contract
agreed to, and claims them. A close deposit nobody asked for is taken back
2016 blocks after the close paid it, like any deposit, with `refund <hash> --to
<address> --chain <url>`, and the hub is paid nothing.

Its address is of the wallet's seed, the coin that opened the contract and the
hub's published root alone. With the wallet's file and the hub both gone,
keep the seed, each hub's `address` and `deposits.close_root` from `hubs
--json`, find your coins again (`onchain scan`, which needs a hub serving
silent payment tweaks, any hub), and run `recover --hub-address <hex>
--claim-root <hex> --chain <url>` (or `--hub <url>` where a file records the
hub): it finds on Bitcoin the payments of contracts' defaults to the close
deposits of the wallet's coins (`--from` a block, `--coin <txid:vout>` for a
coin the scan cannot find, repeated) and, with `--to <address>`, takes back
those 2016 blocks old. A
payment the hub already claimed, with the notes it locked, shows as spent.

The fees a hub charges as a contract opens there are the most the wallet
agreed to pay it, kept with the contract in the wallet file. A hub may
raise its fees whenever it likes: while it charges more than agreed (at
several live contracts, the least of each fee), payments and locks there
are refused, its notes are not renewed, and `hubs` says so. `approve-fees
<hub>` asks the hub again and shows what it charges beside what was agreed;
`approve-fees <hub> --yes` agrees to what was last shown, each fee raised to
it and none lowered. Contracts opened before fees were kept with them hold
their hub to nothing, as does a hub with no live contract. `contracts` lists them; with `--chain`, it carries on those under
way, sees where each one's funding stands, and says what each live one
would claim of the wallet's notes now (`claims`, also in `--json`): the
notes at a hub are shared out among the contracts there so that together
they recover the most, the one ending first served first. On regtest, contracts are
under a mock proof authority: such a contract protects nothing. On signet
and Mutinynet they are under the genuine programs, a trial: `force-close`
below recovers from them, not yet tried on signet itself (docs/hub.md
says what else it lacks). No other network for now. A contract's length is
told in the days of its network's blocks (144 a day, Mutinynet's 2,880).

`close <id> --chain <url>` closes a live contract early with its hub,
cooperatively, and claims what the wallet's notes at the hub come to, the
contract's cap at most, as `force-close` would (below), but paid in the same
transaction: the wallet asks the hub, which says whether anything spent
those notes, then signs a claim of them and the hub's fold together
(MuSig2). The hub retires the notes and signs: the fold pays the wallet the
claim and its reserve on Bitcoin and the rest to the hub, less the fee,
which the hub pays from its share. A hub that finds a note spent refuses
it before anything leaves the wallet, which then asks the hub for its
evidence: the owner-signed spend, or the claim the note's hold key signed
elsewhere. The wallet checks that itself, drops the notes it proves spent,
takes the change those spends paid it, and makes its claim again without
them. A note the hub calls spent without proof stays in the claim: `close`
stops, and `force-close` claims it. One that took the claim and does not fold
leaves it to `recoveries`, which files the same claim on Bitcoin by itself
a little before its last block, as a forced close would (`force-close`
does it at once). The claim takes settled notes only: a contract that locks
owed to the wallet depend on must be forced closed, and so must one too
near its end for that. A wallet holding no notes at the hub gets its
reserve back and no more. The contract protects nothing from then on
(`contracts` shows it `closed early`); `recoveries` shows the close as
`folding` until the fold is in a block, then `done`. Hubs that do not yet
take a claim with their fold refuse `close`: `force-close` stays.

`force-close <id> --chain <url>` forces a live contract closed when its hub
stopped answering (`<id>` is the contract's id, or its start): its share
of the wallet's notes at that hub (as `contracts --chain` shows it) leaves
its balance and is claimed on Bitcoin for their value, the contract's cap
at most. A note worth more than the cap left is claimed for the cap when
nothing else recovers as much: its excess is lost. Until its request may be in the next block (a day
after the contract's funding on signet), `give-up-recovery <id>` gives
them back; from then on it is irrevocable. The wallet pays its fees from
its coins on Bitcoin at `--fee-rate` sat/vB (by default the chain's
estimate), but the publication of its claim only from the contract's
reserve: never more than it holds, whatever the rate, starting at a
quarter of it and paying more as its window runs out while no block
holds it. Should all of it fall short, `recoveries` says so, and
`allow-publication-fee <id> <sats>` lets it pay that much in all, the rest
from one coin of the wallet's, never two together; if none holds enough,
`recoveries --chain` pays a coin out of notes (at the richest hub, if it
holds that much, raised to the least coin an announced provider pays out,
the rest coming back as change) to the
wallet's own silent payment address through a swap provider announced on
its hubs' relays, the request waiting for it until six blocks before its
deadline. Only as an exception, no payout made in time, are the wallet's
coins joined to pay. The same pays out a coin for a challenge's fee when
the wallet holds none to set aside. `recoveries --chain <url>` carries
every forced close on as far as the chain lets it, following payouts and
looking for the wallet's coins first, and shows the block its next step
waits for: run
it until it is `done`, when the claimed notes' value and the wallet's
reserve are back in it on Bitcoin (with the hub's reserve too on a
contract opened before graph id 8, or once the hub answered and failed to
prove its answer). A hub that answers the request instead
(`answered`) says what the claim is owed and shows its evidence: the
wallet checks it, and if it bears the answer out leaves it alone, paid
what it says by the answer's own terminal. Whatever pays the claim on
Bitcoin pays it in whole units of the contract's smallest output (512 sat
on current hubs): the part below goes to the hub, up to 511 sat, as an
answer of 35,322 sat pays 34,816. Otherwise, or if the evidence
cannot be had in time, the wallet contests it (`contesting`, `contested`),
and the hub must prove its answer on Bitcoin before the block `recoveries`
shows, or the wallet's timeout pays the whole claim. `recoveries` shows
what the hub said was owed and, once `done`, what the wallet received
(`corrected` and `received` with `--json`): its sweep's output, after
the sweep's fee, besides the wallet's reserve, which is paid to it
directly. Should the hub post the payout, the fee coin the publication
kept for the wallet's own (up to half its reserve) is swept with it; the
330 sat anchors of the wallet's contest or challenge stay unspent, a
cost of contesting. The wallet proves nothing: it checks the hub's proof once
asserted (`asserted`), challenges one that does not verify (`challenging`,
`challenged`), and carries the payout on to `done` (`succeeding`, `paid`,
`sweeping`), collecting what the outcome pays it and its reserve. From the
publication of its claim until the hub's proof verifies, the wallet sets a
coin of its own aside for a challenge's fee (for twice a challenge's fee
at the rate, about 42,000 vB): `force-close` warns first if it holds none
besides the others. A challenge is posted with a fee child spending its
anchor and that coin, at the chain's estimate for the blocks left before
the hub's payout becomes valid, made again at a higher rate while it is in
no block, and paying at most what the challenge wins.

`discover --relay wss://relay.example` lists the hubs announced on Nostr,
at the URLs that answer as the hub that announced them; with `--swaps`, the
swap providers.

With `--tor`, the wallet reaches hubs, swap providers and Nostr relays,
onion services included, through a Tor client of its own (Arti), which
keeps its state in `tor/` next to the wallet file. Each payment it takes
from an inbox, each payment on from an extra code, each check of whether a
payee collected a payment and each unlinking at a hub runs on circuits and
connections of its own; the rest shares one circuit per host. `--proxy
socks5h://127.0.0.1:9050` goes through a Tor daemon instead, without
that split.
