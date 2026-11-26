# Android app reference

The Licash wallet for Android: the wallet core (`apps/mobile/core`, Rust
over UniFFI) and the light client (`apps/mobile/chain`, Go over gomobile)
under a Jetpack Compose UI.

## What it shows

### First run

With no wallet, the app opens on a five-slide tour, skippable, that tells
Licash with gold: bitcoin is gold in a vault, too slow, costly and public
to pay a baker with, so people pay with ecash tokens a hub (a vault
company) issues, alone only its promise; Licash tokens come with the
user's own vault (a contract) of real bitcoin, redeemed for sure; and that
vault is her insurance: she chooses how much it protects, locks bitcoin in
it, her hub can add its own, and her tokens are protected up to that
amount (said as what it protects, so what is beyond it is plainly not).
Its last slide creates or restores the wallet (and picks a test network,
"Use mainnet" going back). It never shows for a wallet already there.
Settings replays it as "How Licash works", ending on "Guide me to a vault",
which sets a vault up as below even for a wallet in use, until a vault
asked for since protects or "Hide guide" is tapped. The pictures are drawn
in Compose, the same shapes in the dark and light themes.

A new wallet is then set up a screen at a time, with nothing else on the
screen (`ui/Setup.kt`), in Home's place:

1. **Back up.** For a wallet made here, before anything is in it: its
   recovery words bring back its keys and what it holds on Bitcoin, but
   not its balance, which hubs hold; the automatic backup does, encrypted
   with the words, to a folder a sync app copies off the phone. Restoring
   takes both. "Later" puts it off; Home still suggests the words once
   the wallet holds something.
2. **Choose a hub.** On a network with recommended hubs (Mutinynet only,
   for now), each is asked what it says of itself: the first with room
   for a vault is "Recommended" and added in a tap, one saying it has
   none (`full`, or its wallet funding none: see [the hub](hub.md)) is
   grayed, with why, and still usable ("Use it anyway": a vault funded
   whole by its holder opens there). A hub saying nothing of it, as hubs
   of earlier versions, reads as having room. "Choose another", or a
   failure, lists the hubs announced on Nostr, those with no room grayed
   too, and takes one by its address; the back gesture returns to those
   recommended. None found says "No hubs available".
3. **Fund.** "Send at least 50,000 sat. It opens your vault and covers its
   reserve and fees.": one figure at every hub; folded under "How much to
   send", a bit more than she expects to spend, the vault sized by the
   deposit, room to swap some out later to receive more; the address as a
   QR code with a copy button, and where it stands (Waiting, Seen, In a block,
   Opening vault, Ready), the marks joined by a line. One block is all a
   deposit is said to need, and "In a block" is done once reached; how
   deep it is is under "Details". Nothing opens without a tap: "Open your
   vault" is under "In a block", disabled until then.
4. **Open your vault.** The offer on a page of its own, its protected
   amount under More. A hub refusing for want of room says "This hub
   can't open new vaults right now" and offers another hub.
5. **Opening.** What it waits on, how much of its download is done, its
   protected amount, what goes into the balance and its hub, kept in
   sight until it protects.
6. **Ready.** Said once, with a check drawn and a haptic.

"Not now" (and the back gesture) leaves for Home, whose step card ("Set up
your vault", where it stands) leads back. A wallet in use is never set up
unasked: one with a hub that holds or ever paid with notes goes to Home as
before, and so does every wallet of an earlier version past its first
funding. Send is grayed while there is nothing to send (no balance and no
vault) and, tapped, leads to the funding with why. Receive says, under
what is paid into a hub with no vault, "No vault yet: what you receive is
held by your hub, not protected.", each time.

Progress is felt and seen: a haptic and a check drawn when the wallet is
made, its words shown, a hub chosen, a deposit seen, the vault opening and
ready; money in, on any screen, is said from the top with a check and a
haptic.

### Home

Home is the balance, a gauge of how much of it is protected, one line while
something is going on, at most one suggested next step, Receive and Send.
The step is, the most pressing first: setting up the first vault, above; the offer
for bitcoin that arrived; bitcoin too little for a vault, to add; saving
the recovery words of a wallet made here, once it holds something (a
wallet restored, or of an earlier version, is never asked); renewing a
vault ending within two weeks of blocks, unless another at its hub takes
over; protecting what a hub holds beyond its vaults. The rest waits behind a tap: where the money
is behind the balance (a page for each hub, to cash out and protect, and
one for what is on Bitcoin), the history behind Activity (or a swipe up),
and behind its chart button Stats, what the history came to, what a payment
cost and how it was made behind its line, what a word means
behind its (i). Times are said as times, never as blocks; ids, notes and
providers show in advanced mode only. With no hub yet, Home lists the hubs
announced on Nostr to pick from, or takes one by its address. While a new
wallet first catches up with Bitcoin, Home says the step under way in
plain words and how far (each step, block numbers and all, in advanced
mode), the headers this release pins counted as downloaded, then as
stored; once caught up, never again. A dot beside the network shows how
the connections stand (Tor if on, Bitcoin, up once caught up while it
keeps up with new blocks as usual and only behind once 30 s behind or with
no node, each hub as it answered when
last asked, every 5 minutes, and the mailbox's relays as last looked in,
a problem if one answered the 500 messages a look asks for, since newer
mail, junk anyone can send, can then hide an older payment, all kept in
memory only); tapped, it says each with how long it took to
answer (Bitcoin's nodes' shortest ping, a hub's fastest answer of the last
minutes, a round trip on a circuit already open, a look in the
mailbox finding nothing to redeem), lists Bitcoin's steps under it while catching up in advanced
mode, and offers turning Tor off once Tor keeps the app from Bitcoin for
3 minutes (not connected, or no node answering through it, not counting
the minutes importing pinned headers before any node is asked), or says
it is stuck. Notifications are asked for once a wallet
is made or restored. A hub, or any host, that did not answer is passed
over by what the app does by itself (looking for payments, finishing what
is under way, the inbox, learning what each hub serves) for 30 s, then 1,
2 and 5 minutes while it keeps not answering, rather than waited on again
for up to two minutes with the wallet held; what the user asks for asks
it still, and any answer ends the rest. Looking for payments on Bitcoin
asks every hub it trusts serving silent payment tweaks at once, without
holding the wallet while they answer, and looks in each block with the
tweaks any of them serves: one that lags, is stuck or does not answer
within 10 s of another that served every block asked for holds nothing
back while another serves them, and each of them learns how far the
wallet has looked, as the one asked alone did before.

Protection is offered for a coin at a trusted hub that takes it whole in
the smallest vault it fills, its fee and interest (not its reserve, which
comes back) no more than half the coin: the largest vault first, then the
cheapest. Home says when bitcoin paid to the wallet waits outside the
balance and no protection is offered for it ("N sat on Bitcoin", its card's
button "See it"); it
opens the page for what is on Bitcoin, which lists each hub's protection to
open. That page is always one tap from the balance: its row says "Add it
to your balance, protected or not" while bitcoin is held and nothing is
being added, and the Bitcoin address in Receive points there. A payment that finds too little to pay with, in notes or none, while
bitcoin is held or coming, says so in plain words and offers to fix it:
"Add to balance, protected" opens the protection offered for it, if any,
and "Add without protection" (or "Add to balance" with none offered) moves
the largest coin in; a coin still on its way gets no button, and with
nothing held, Receive. While protection is being set up, Home says
so instead of how much is protected.

Every tap answers. A button doing work shows it, with the seconds; a sheet
that starts work stays open on it and gives the reason in place if it
fails; a close of a protection goes on in the background if the sheet is
left. Moving notes to another hub (advanced mode, on a hub's page) opens
the move's line of the history once it starts, so its progress shows until
it arrives. A payment's outcome, a finished action and a switch are felt as a
short haptic, which follows the system's touch feedback setting and asks no
permission, and an outcome's title is announced by a screen reader. Screens
fade and slide a little the way they go, and the steps of a payment fade;
the system's animation setting scales both, or turns them off.

### Fees and Stats

Tap a fee in a payment review or its history for the amount, percentage,
and supplied recipient split. Current direct-payment estimates show base
plus percentage times amount, rounded up like the hub. Payouts and moves
split their fee by who gets it, as quoted or recorded: the hub, the payout
or swap provider, and the Bitcoin network for a payout's claim. Historical
rates or splits that were not saved are identified as unavailable, never
reconstructed from today's terms.

Stats covers a day, week, month, year or all of it, each stepped back to
the one before: the fees paid (with their share of what was sent), the
balance over the period, what came in and went out and how many, each by
way (in Licash, over Lightning, on Bitcoin), and what each way of paying
usually cost and took, the cheapest first, its average a tap away. Fees are
by purpose (sending, moving, keeping notes in shape, protection) and, folded,
by whom they were paid; times are how long each kind of payment, optimizing
and unlinking took. It is worked out on the phone from the wallet's own
records when it opens: nothing is stored or asked of the network, so a wallet
of an earlier version has all its past at once. Fees count once settled (a
payment that failed costs nothing), and the usual is the median. Renewals and
the notes made for exact amounts, which the history hides, count as upkeep.
A payment's time is known only for those done, and the balance is replayed
from when notes came and were spent and coins were found and spent, so it is
about, not exact, around a move from Bitcoin into notes. The notes a swap
brings, and the part of a protection returned as notes, are not counted as
received (the latter is found as the receipt of exactly that amount at that
hub, after the contract was asked for).

How much of the balance was protected on average (all protected over all
held, so a dust balance does not weigh as a large one) cannot be known after
the fact, since coverage is worked out live. The app writes its balance down
as it changes (within a minute of the last, one row; an unchanged balance
once a day), in a `stats` component of `wallet.sqlite` that the first sample
makes: opening, reading or restoring a wallet makes none, so a wallet of an
earlier version has nothing before the first run of this one, which Stats
says, with how much of the period was written down. A sample holds until the
next; across more than a day and a half with a changed balance at the end,
nothing is claimed. The table is in backups and restored with them, but its
rows alone are no reason to write one, and an unreadable `stats` component
(another version, or half made) leaves everything else working.

### Settings

Settings is one page: the hubs (each tapped for its fees, more added by
address or found on Nostr; one added from those found goes by the name it
announced, kept in the app's settings, in the hubs, the balance and
protecting; its address under it in the hubs), Backup, Bitcoin (each step of catching up:
Tor, the nodes, the block headers and filters against the best peer's
height, and the wallet's payments from its birthday, with their progress),
Tor (on or off, and a page with its bootstrap progress, what it is doing,
why it seems stuck, and a confirmed reset forgetting only its state and
directory cache), About (the
version, the storage used and the logs to export) and advanced mode, whose
own page holds the notes, the log, the limit for renewing notes, the light
client's settings, resetting its chain state and deleting the wallet.
The app runs one Tor client and starts the light client
through it at launch, wallet or not: catching up starts before a wallet is
made. A wallet made before it caught up is born at the block the release
pins for its network (regtest: the first), never scanned from the start.
Its state lives in `files/tor`; an earlier version's, in the wallet's
directory, moves there once (left where it is if it cannot).

Cold storage, in advanced mode (or once set up), is a page of its own in
Settings: the extended public key of an external wallet's account (a zpub,
or an xpub with native segwit or taproot addresses chosen), a threshold,
an amount kept and a fee limit in percent, and an optional wallet birthday
(by default the chain's height then). On each sync, once the notes exceed
the threshold, all but what is kept is paid out from the hub holding the
most, through the provider preferred within the fee limit, to an address
of the key never used before, one withdrawal at a time; the page shows
what the key's addresses hold from the birthday (found with block filters),
the next address, and how to bring funds back: send them to a Bitcoin
address shown in Receive. How the app looks and speaks, and the shared parts to build a screen of, are in
[apps/DESIGN.md](../apps/DESIGN.md).

## Networks and advanced mode

A wallet is made on Bitcoin unless "Use a test network", on the first
screen, picks signet, Mutinynet or regtest first: a wallet keeps the network
it is made on. Settings shows the backup, the hubs, the tour and About;
Bitcoin and Tor are folded under Network, a problem with them in sight. The Advanced mode switch in Settings turns on
advanced mode: the networks on the first screen, the light client's peers and
its block-dn server, the block explorer transactions link to, the most the
app pays, on its own, to renew notes a hub that restarted no longer unlinks
(1000 parts per million of them unless set, or a spending schedule of at
most 1 sat base, that rate and 0.1 sat per output; live contract ceilings
take precedence, and contracts that cannot be read hold every hub to no fee
until they can, under Privacy), the notes of
each denomination, and how each payment was made: its transactions, block
heights and providers.

### Notes and background work

Like the CLI, each sync reshapes the notes of a wallet that mostly
receives, within the same fee authority and the rolling 1% daily budget
(see [the wallet CLI reference](wallet-cli.md)). While notes wait
out their privacy rest, a periodic job (about every 15 minutes, as Android
allows) keeps looking after the app is closed, without the foreground
service; it stops once nothing is left to do, or when what is left is
beyond the fee authority. Apart from it, a job every 4 hours or so while
the phone rests (idle, with a network) syncs a round with Bitcoin, so coins
paid to the wallet are found without opening the app. Behind Bitcoin in
sight for more than 15 seconds (a first start, or days away), the app
starts its foreground service, so catching up continues should she leave
it: its notification shows the step and how far, and it stops once caught
up, or after an hour. History shows each
remint as "Optimized notes",
its fee alone. In advanced mode, a hub's sheet in Settings offers "Optimize
notes": a preview, then a remint within the fee shown, bypassing the rests
and the daily budget but never the contract ceilings.

## Hubs and payments

The app needs a hub taking deposits on the same network: `licash-hub run
--network signet --chain URL --deposit-sweep-address ADDRESS`, with
`--nostr-relay` (or `--mailbox-relay`) for payments between wallets through
their mailboxes, `--tweaks` for silent payments: the app's code holds a
silent payment address only if a hub it uses serves tweaks, and `--lnd URL
--lnd-macaroon FILE` for Lightning: the app pays invoices through the hub,
and Receive, given an amount, shows an invoice the hub makes, whose
notes the app takes once paid. With the amount, a memo may be typed for the
payer, at a hub that puts one in its invoices (it and its Lightning node
read it too); the history shows it, as it shows the description of an
invoice the app paid. Where no hub it trusts takes Lightning, a swap
provider announced on the hubs' relays that takes payments for wallets
(`licash-swaps run` with `--lnd` and `--receive`) makes the invoice
instead, its node holding the payment until the provider locks its notes
to the app at a hub it trusts, which the app claims as it claims a hub's:
nothing is trusted to the provider, but it sees the amount, the memo and
which payments go to one wallet. Receive says the provider's fee taken.
Receive has a tab each for the Licash address (the wallet's payment code,
as the app calls it everywhere: its hubs, and its silent
payment address), Lightning (asking an amount first) and Bitcoin (the bare
address any wallet pays, handed out only once asked for); the code alone,
the silent payment address alone and which identity the code is of are
under More.
Once a swap provider announced on the hubs' relays takes donations
(`licash-swaps run` with `--lnd` and `--lnurl-url URL`) at a hub of the code, More also
offers a donation address: a static LNURL any Lightning wallet pays, again
and again, while the phone is offline, the provider paying each donation in
notes at the code's hub, less its fee. Once shown, its provider and code
are kept and shown again, even unreachable, as an address handed out stays:
the code while all its hubs are trusted, hubs added since or not; another
takes its place only once it takes no more donations, or has failed to for a
week while another can. A way not open says why under More, grayed
out (no hub or provider taking Lightning, no hub indexing silent payments,
no provider taking donations, or still looking for one). Tapping a hub in Settings lists its fees. Silent payments
before the first block the hub indexed are not found; payments to the
fallback address are, from the day before the wallet was made.

Send pays Bitcoin addresses and silent payment addresses from notes too (a
`bitcoin:` code at its `sp=` address first), through a swap provider paying
out on Bitcoin (`licash-swaps run --chain URL`) announced on a relay a hub of
the app names (`--nostr-relay URL --announce-url URL`); a hub's page, behind
the balance, cashes out notes there to an address that way, all of them or
an amount chosen. A `licash:` code is paid in notes only, through a swap to
a hub it names if the app trusts none. An amount no provider pays out offers
about the most one does instead (its largest coin less the claim's fee, and
no more than the notes there pay), with a button to send that.

Lightning invoices are paid the cheapest way found: through a trusted hub's
gateway, or through a swap provider announced the same way that pays
invoices from its own node (`licash-swaps run --lnd URL --lnd-macaroon
FILE`) for a lock of notes at a hub holding enough. Gateways come first
among equal fees. The confirm screen names the provider and says how long
the sats wait should it decline or fail the payment: they return only once
the lock expires, about a day or more, where a hub's gateway refunds at once.
The app records the provider with the lock and asks it again on each round
until the payment settles, so one interrupted before the provider heard of
it is still made. In advanced mode, "All providers" lists every way to pay
it, to choose another.

A code naming no hub the app trusts, but saying where to reach the payee's,
is paid there in notes once the owner agrees: the hub proves it is the one the
code names, a swap brings notes there from a hub of the app's, and the payment
shows its fees for review first. What the swap brought past the payment stays
at that hub, shown apart behind the balance, as not in it, where adding the
hub counts it.

Payout deadlines are checked for every pending payout, independently of
the ordinary progress display limit. A payment to a payment code is done
once its hub releases it, kept there for the payee, who collects it at the
hub and tells the payer so through it. One not collected within an hour,
or that its hub does not keep, is sent to the payee's mailbox by the app
in the background: the periodic job runs while any is on its way. The
wallet file records where each stands; a `deliveries.json` left by an
earlier version is no longer read.

Paying a code, a note may be typed for the payee, and "Share my address"
(off by default) tells them who paid, proved to them alone: both sealed
for the payee, the hub and relays reading neither. A hub that would not
keep a note with a payment refuses it, nothing paid, and the app offers
to send it without the note. The history shows a payment's note, and its
details who paid: a contact, or a code to save as one. A payment made to a
contact's wallet, or by one whose shared code is a contact's, says "To" or
"From" that contact on its line.

A contract is three lines of the history: "Protection", its price paid on
Bitcoin, its details splitting it into the cost and the reserve that comes
back, listed from the start of its opening ("Being set up" while it is
opened, Home showing its steps instead, then confirming until its funding
is in a block; failed with why if given up before its funding was signed,
nothing taken, or if its funding can never confirm); "From Bitcoin, protected", the rest of the coin it took, issued back
as notes once its funding confirmed (the earliest receipt at its hub of
exactly that amount after it began, as nothing kept says which), rather
than a payment received; and "Protection closed", what it paid back to the
wallet's Bitcoin (closed early with the hub, or forced closed), from the
contract at its hub, rather than a coin received. The move set up to take
its reserve back as notes when it closes is no line until a close pays it.

Receive, showing the Licash code, lets the user pick which identity: the
main one (the wallet's own code), or an anonymous identity, a separate
code made there under a name only the user sees, the sheet staying open
with the seconds counted while its hubs are asked. A separate code has keys of its own, derived from the seed by its
number, and names no mailbox, so no one can tell it belongs to the wallet
or to another of its codes: two pseudonyms posted online share nothing.
What it is paid is collected with the wallet's payments, from the inbox
of its hub (which keeps a payment there for 14 days; after that the payer
still holds it and must hand it over), and paid on to the wallet's own
code after a delay of between 1 and 30 minutes, a different one for each
payment, less the hub's fee: an amount below that fee waits for more. The
history shows each payment at the code, named "To" it, its fee
that of moving it to the balance. "Share my address" may share a separate
code instead ("Share as"). Each code is kept in a wallet file of its own
beside the wallet's (`wallet.sqlite.codes/`), deleted with it, outside
the state bundle and the automatic backup: a wallet restored from either
makes the files again, and one restored from the seed shows no separate
codes until made again, numbered as before. Over Tor, each payment taken
and each payment on runs on a circuit and connection of its own (see
below), but a hub can still link a code to the wallet by the amount paid
on and its timing, more easily when payments are few.

### Connected apps

Settings, "Connected apps", keeps accounts at NWC bridges
([docs/bridge.md](bridge.md)), for apps to pay and be paid through Nostr
Wallet Connect: a bridge added by its URL, with the pairing code its
operator printed if it is its owner's only. Each bridge's page shows the
balance in sat, tops it up from the hub holding the most or withdraws to
it, and sets the top-up rules (below so much, up to so much, at most so
much a day, the most fee), which each sync applies after moving notes,
a failure logged without failing the sync. An app connected gets a
`nostr+walletconnect://` URI, as a QR code on a screen that cannot be
captured, shown once, with what it may do (pay, receive), the most one
payment may be and a budget per period; it can be revoked. A bridge with
a public URL gives the account a Lightning Address, which Receive shows
under "More". Custodial: the bridge holds what the account does.

Should the bridge's hub stop cooperating, "Freeze and export its notes"
freezes an owner bridge for good and imports its notes; those an open
bridge's operator exported to the app's key there are pasted under "Notes
imported". They
are never in the balance nor spent: a recovery contract at their hub
claims them only within the cap the app's own notes, locks and funding
leave. They can be discarded, unless a recovery claims them, for the
operator to unfreeze the bridge.

### Tor

Over the app's own Tor client, every operation you start (a payment, an
invoice, adding a hub, a payout, moving notes) runs on Tor circuits and
connections of its own, shared with no other operation's, so a hub or exit
cannot link two operations by their circuit. Background polling shares
one circuit per host, as the inbox's feed is public, and asks for what
the wallet was paid each on a circuit of its own, only when there is
something to take; checking whether a payee collected a payment also uses
a circuit per payment. So that this costs no wait, the app keeps a spare
circuit (with its connection open) to each hub it uses, taken by the next
operation and replaced in the background, and has Tor build a few more
exit circuits ahead. A new circuit to an onion service under load costs a
proof of work. With Tor off, or through an external SOCKS proxy, requests
are not split this way.

### Testing against the command line

A counterpart on the command line:

```sh
export LICASH_WALLET_NETWORK=signet LICASH_WALLET_CHAIN=URL
licash-wallet init && licash-wallet add-hub HUB_URL
licash-wallet code                # for the app to scan and pay in notes
licash-wallet code --onchain      # for the app to pay on Bitcoin
licash-wallet mailbox             # the payments it sent
licash-wallet pay 'CODE' 1000     # pay the code the app shows
licash-wallet onchain scan        # coins paid on Bitcoin
```

## Protection

A hub's page sets up protection, a recovery contract, at the hubs that open
them (`licash-hub run --contracts`: under the mock authority on regtest,
where such a contract protects nothing, and of genuine programs on signet and Mutinynet).
A contract locks the hub's collateral on Bitcoin behind the notes there, up
to its cap, until its last block to recover in, then closes by itself, its
collateral back to the hub, and its reserve to a deposit of the hub's that
swaps it for notes, not to a coin of the wallet's. Its price is paid from one
coin of the wallet's on Bitcoin, spent whole: it pays the reserve and the hub's
fee, and all the rest of it is the owner's part of the contract, issued back
to her as notes at that hub once its funding is 3 blocks deep (or claimed by a
recovery should the hub never issue it), the hub charging its interest on its
own part only. No change comes back from the coin. The sheet shows first
what the hub would hold protected once it opens (its cover bar, then in
words), then the cover: at first of the smallest coin a contract takes
whole, her part of it alone, the hub funding only what makes it a cap (the
least, 131,071 sat, or under 512 sat more; a hub may bound the cap by the
coin paying, as it announces). Under More, what it is for sizes it otherwise
(Yours, Pay, Both or Receive: room for what is put in and held at the hub,
half again, or three times it, the hub funding the rest at its interest),
the choice kept once tapped, and a slider asks any cover from her part's to
the largest the hub allows for the coin, in steps of 1,000 sat. Chips choose
the coin paying it when several do, the smallest at first. Then its cost, the
reserve, and "Into your balance", her part; why no coin pays any, each short
of the price or beyond what the hub's largest contract takes; and one line
of what it asks of her, opening the app now and then and before the day it
ends. Under More, a slider chooses how long it lasts (at first half a
year), with the hub's part and the cost itemized.
With no coin
on Bitcoin paying any, opened from a hub's page, the sheet offers a coin to
cash out to the wallet first (or pay for with notes) of what is not
protected there, less a hundredth and 5,000 sat for the cash-out's fees: its
price paid from it and the rest the owner's part, in the smallest cover it
fills, the hub funding the rest. Under More, mostly the hub's: a coin of the
price and a 1,000 sat part, the hub funding nearly all of a cover half again
what is not protected (the largest smaller cover a hub bounding it by the
coin allows), the part larger if a provider pays out no coin that small
(the least an announced one pays out, its minimum risen with fees). Paid as quoted: the
coin quoted must still open the contract quoted, else it is quoted again.
Once the coin arrives, Protect opens on it. Priced live as the
hub prices it: its cost (the hub's opening fee and its yearly interest on each
part, itemized on a tap) apart from her reserve, "refundable", each with an
(i) saying what it is. Its button says "Protect for" the cost, or "Add for"
it when offered for a coin on Bitcoin (titled "Add to balance, protected":
the coin is safe already on Bitcoin, what it gains is being spendable in
Licash), and "Waiting for Bitcoin" until the app is caught up, as opening
needs. A hub's "Fees and limits" lists its opening fee, interest, reserve,
covers and length a short row each. Opening uploads about 250 MB (the garbled instances the hub keeps, 25 MB each) and takes a few minutes, then a confirmation on Bitcoin,
in the background, one at a time, the step it is at shown; several
contracts at a hub, and at several hubs, add up. Each says what it covers
now of the hub's notes once unfolded: what its recovery would claim of them
now, the notes at a hub shared out among its contracts so that together
they recover the most, those ending first served first. Notes still
arriving count as not protected until they settle. The hub's page says how
much of what it holds they protect; what they cover counts as protected,
on Home and behind the balance, where bitcoin held ("On Bitcoin", safe
already) is said apart from what contracts protect, and notes not
protected, with bitcoin held, link to protecting them with it;
what a contract is worth for now (nothing, under the mock authority) is said
wherever one shows. The fees a hub charges as a contract opens there are
the most the app pays it from then on: a hub that raised them since is not
paid, and its notes not renewed, until the owner approves the new fees,
asked when a payment there is refused for it (old beside new, then paid)
and on the hub's page in Settings. A contract may be closed early with its
hub, never without what it covers: Close says what the hub pays, the notes
held there up to its cap and the reserve, in one transaction on Bitcoin,
and how much beyond the cap stays at the hub unprotected, which cashing out
first takes too. The hub is asked whether anything spent those notes, then
retires them as it signs the fold; they leave the balance as the close is
signed, and the row says it is closing until the fold is in a block. Should
the hub not fold, the app files the same claim on Bitcoin by itself a little
before its request's last block: a forced close on the notes already
claimed. A contract that locks owed to the app depend on, or one too near
its end, is forced closed instead; so is one whose hub does not take a claim
with its fold yet. In advanced mode, a contract whose hub stopped
answering can be forced closed: the notes it covers are claimed on Bitcoin
(a note worth more than its cap for the cap, its excess lost) and paid back
there once the hub's window to answer passed. A hub that answers instead
says what the claim is owed, and must prove it on Bitcoin by a deadline the
row shows: the app checks the hub's proof, challenges one that does not
verify, and is paid what the outcome says. Its publication's
fees come from the contract's reserve alone (paying more past it is allowed
on the command line only). A coin for a challenge's fee, when the wallet
holds none to set aside, is cashed out of notes at the richest hub to the
wallet's own silent payment address through a swap provider. The phone proves nothing, and no
root key of the wallet is revealed: the claim's notes are tied to no key
that owns the contract. The contracts are kept beside the wallet's file, made
only once one is asked for.

Coverage uses the actual whole-note recovery selection, not nominal caps:
only settled, unreserved notes of the opening's keyset, at most 32 or its
lower signed note limit. Notes are allocated once, earliest deadline first.
Genuine current-image contracts count; unreadable or unsupported openings count as zero. Balance details show the
total number of held notes.

Unfold a signed contract for its locked value, payout-pool and reserve
diagram, and a link to the contract address in the configured explorer.
The claim cap is a limit inside the payout pool, not extra collateral.
Technical details reveal the signed note limit, denominations, keyset,
graph version and program identities. Earlier opening stages show progress
rather than guessed signed details.
Answered recoveries show what the hub says is owed separately from the
original claim. Once done, the returned amount is the actual sweep output, including
the effect of reserves and fees, not the original claimed amount.

Before its request is signed, Cancel closing asks for confirmation and
releases the notes reserved by that attempt. It does not close the contract
or recover Bitcoin; another attempt is possible while the contract permits
it. Once signed, even an unconfirmed request cannot be canceled.

A forced close's claim pays its fee from the contract's reserve, never
more on its own. Should fees on Bitcoin outrun it, the row says so, a
notification asks her to act, and Allow a higher fee lets her set a total
fee for the claim, the rest from her coins on Bitcoin: it must be in a
block within its window, about an hour, or the notes it claimed are lost.
A protection ending soon without her consent to exit also tells of the
payments owed to her that only forcing it closed recovers.

Advanced settings has a holder-owned recovery planning margin (14 estimated
days by default). An unfolded contract reads the signed terms to show when
its request should confirm. The margin alone authorizes nothing.
A late hub answer remains possible until the holder's timeout wins on
chain, so the margin requires online monitoring and prompt confirmation.

Below it, Exits asks for the holder's consent, given once a contract
protects her notes, with a Bitcoin address. With it, as a contract nears
its end (three days before its request should confirm) and no other
contract at its hub protects her notes there, the app pays those notes out
to that address through the cheapest provider within 1% and 1,000 sat,
then closes the contract early. Not paid out a day before, the contract is
forced closed. Without consent, including on upgraded installs and after
a restore (consent is not carried in a backup bundle), nothing is done:
a high-priority notification asks her to act. Revoking stops new steps;
those under way are finished. The consent keeps the exit margin given with
it; saving a new margin gives it again. While any contract protects notes
the periodic job looks every 15 minutes or so, and a disputed forced close
notifies her to keep the app online until its challenge window passes.
A lock of her notes at a hub where a contract protects them expires early
enough for that forced close to claim its refund should the hub never
settle it; a payment needing a later expiry (near the contract's end) is
refused there until a contract lasting longer protects her notes.
A lock paying her whose hub never issues it once told its preimage is
activated on Bitcoin with a coin of her wallet as its expiry nears, if a
contract of hers there can still claim it; that contract is then not
closed early but forced closed, its claim taking the lock's pay branch.

### Recovering a reserve from the seed

The core can find a contract's reserve with only the seed when the wallet
file and the hub are both gone: `hub_keys` lists each hub's address and
deposit root (keep them with the seed), and once the wallet found its coins
again, `recover_closes(chain, address, root, from)` finds the payments of
defaults to the close deposits of the contracts those coins opened and hands the network a refund of each 2016 blocks old, paid to the
fallback address. The app has no screen for it yet.

## Backup and restore

- **Recovery words**: 24 words, shown after a warning, kept out of
  screenshots, with a button copying them marked sensitive (no clipboard
  preview). They encode the wallet's existing 256-bit seed as BIP39
  entropy (not a BIP39 PBKDF seed, so other wallets do not read them). They
  bring back the keys and coins on Bitcoin only: notes held at hubs and
  contracts need the backup file. They are shown with the wallet's birthday,
  the first block its payments are looked for from (learned on its first
  scan if not known when it was made); restoring with it scans from there,
  without it from block 1. A restored wallet watches its fallback addresses
  from the first, and 20 past the last one paid, so coins its copy received
  there (a contract's reserve returned, a payout to itself) are found.
- **Backup file**: everything the wallet holds as of when it is saved (the
  wallet's database, which holds its contracts too, the birthday, the
  instances a contract's recovery needs, contacts), in a checksummed,
  unencrypted tar (format 2: a backup of an earlier format, which kept the
  contracts in a database of their own, is refused) the user saves through the
  system file picker. Tor state, proofs made on the phone and the light
  client's blocks are left out. Payments after it are not in it. Restore a
  backup on one phone only: two live copies can reuse one-time recovery
  keys and lose money.
- **Automatic backup**: off until the user chooses a folder (through the
  system folder picker), meant for one a sync app such as Syncthing or
  Nextcloud carries off the phone. From then on, each change worth a backup
  (anything but the progress of looking through Bitcoin) is written once
  the wallet rests for 30 seconds, 5 minutes after the change at the
  latest, at once when the app leaves the screen, once a day if nothing
  changed, and as soon as the folder no longer holds the last one. A
  failed backup is tried again 5 minutes later. The backups are in `Licash-<id>/` in that folder, `id`
  of the seed and network, telling nothing of the wallet; every file is
  written once under a new name and never changed, so a sync app never
  sees half a file nor two versions of one:
  - `s-<generation>-<writer>.lcb`: a snapshot of everything the backup file
    holds, gzipped, but the contract states of 64 KiB or more (each
    megabytes that do not compress), which it names. The newest three of
    the phone are kept.
  - `b-<name>.lcb`: one such state, named by a keyed hash of its bytes,
    written once however many snapshots name it.

  Each file is sealed with XChaCha20-Poly1305 under a key of the seed and
  network, its header (generation and writer included) authenticated: a
  file cut short, renamed or of another wallet is refused whole. A
  snapshot of a wallet without contracts is tens to hundreds of KB. The
  phone records what it wrote in `autobackup.json` beside the wallet,
  before writing, and deletes only its own files no kept snapshot names.
  Contract work under way delays a backup until it is done.
- **Restore**, from the first screen: from a backup folder (with the
  recovery words, the newest snapshot that restores whole, its date shown,
  and told when newer ones there do not, as when still syncing, or when
  several phones backed up there; automatic
  backups go on to that folder), from a backup file (its network is
  the wallet's) or from the recovery words (of the network chosen). It never
  lands over existing wallet state; a backup this build cannot carry on
  ("needs a newer version of the app") or one missing a file a recovery
  needs is refused before anything is installed.
- **Reset chain state**, in advanced mode, after a confirmation: the wallet
  looks for payments again from its first block and the light client's
  blocks are fetched afresh. Notes, contracts, recoveries and payments under
  way are untouched. Nothing runs on its own: existing wallets see no change
  until a backup, restore or reset is asked for.

## Upgrading from note format v4

A wallet of the release before note format v5 (wallet schema 5) holds notes
whose messages carry a nonce, which this version does not read. As from v3
(below), it is refused when the app starts and its file left as it is:
before updating, spend or pay out its notes, and let its contracts close,
with the release before, then clear the app's data and create a new
wallet. Hubs of v5 are new hubs.

## Upgrading from note format v3

A wallet of the release before note format v4 (wallet schema 4) holds notes
and grants this version does not read. As from v2 (below), it is refused
when the app starts and its file left as it is: before updating, spend or
pay out its notes, and let its contracts close, with the release before,
then clear the app's data and create a new wallet. Hubs of v4 are new
hubs.

## Upgrading from note format v2

A wallet of the release before note format v3 (wallet schema 3) holds notes
whose issuance proofs this version does not verify. It is refused when the
app starts ("a wallet of an earlier version"), said on the first screen
in place of creating or restoring a wallet (with clearing the app's
storage as the way to start over), and its file is left as it is; a backup of one is refused on
restore. Before updating, spend or pay out its notes, and let its contracts
close, with the release before. Its APK installs over this one with the
wallet's files kept (the version code does not change), so keep a copy.
Then clear the app's data and create a new wallet: hubs of v3 are new hubs.

## Build

Needs a JDK 17 or later, the Android SDK (platform 37) with the NDK at
`ANDROID_NDK_HOME`, Rust with the `aarch64-linux-android` and
`x86_64-linux-android` targets, Go and gomobile.

```sh
./native.sh                 # the core, its Kotlin bindings and the chain AAR
./gradlew assembleDebug     # app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Releases

Once every CI job passes on main, CI publishes the app signed, as
`licash-main.apk` with its `SHA256SUMS`, on the `main-build` prerelease,
replaced on each push. The `android` job builds the release APK unsigned;
only `publish-app` signs it, with the key in two repository secrets: the
debug key the app has been signed with so far, from the machine that built
it, so that the published app installs as an update over those builds (its
certificate's SHA-256 is `0bfd0c83...d474c1e2`, as `apksigner verify
--print-certs` shows):

```sh
base64 -w0 ~/.android/debug.keystore | gh secret set ANDROID_KEYSTORE
gh secret set ANDROID_KEYSTORE_PASSWORD --body android
```

Android updates an app only with an APK signed by the same key: keep that
keystore backed up, since without it every user must uninstall (and restore
the wallet from its backup). Its password is the debug default, so whoever
has the file can sign updates.

## Logs and tests

Settings, About, Export logs shares the app's log and the light client's as
one file; Storage shows what the app keeps on the phone: the wallet, the Bitcoin
light client (each network's in advanced mode), Tor's state, logs, caches and
the app itself. The end-to-end test drives the app on the emulator or phone adb
picks, among the regtest ecosystem of `apps/e2e`:

```sh
LICASH_E2E_APP=$PWD/app/build/outputs/apk/debug/app-debug.apk ../../e2e/run.sh the_app_is
```

It types as on a hardware keyboard: give the emulator one (`hw.keyboard =
yes` in its AVD's `config.ini`), as CI does, so that no on-screen keyboard
covers the buttons it taps.
