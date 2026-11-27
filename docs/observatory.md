# Observatory reference

`licash-observatory` watches the hubs and swap providers of one or more
networks and serves what it sees as a web page and a JSON API. Anyone can run one: the
page is read-only, and nothing on it can make the observatory act.
`licash-observatory run --help` lists every flag and environment variable.

```sh
licash-observatory --data ./observatory run --network signet --listen 0.0.0.0:8350
licash-observatory --data ./observatory run --network bitcoin,signet,mutinynet
```

Each network is served under its name (`/signet`, `/mutinynet/hubs`), with a
switch between them in the header; `/` leads to the first, or to the funded
one. Each has its own records and, if funded, its own wallet, in
`<data>/<network>/`; Tor's state is shared in `<data>/tor`. `--hub`,
`--provider` and `--relay` name one network's services, so they take one
network only.

## Finding services

Every ten minutes, the observatory reads hub and provider announcements
(Nostr kind 38338) for its network from the usual relays, or from those
given with `--relay`. `--hub URL` and `--provider URL` add services that do
not announce themselves; such a service is known by its URL.

An announced service counts as up only if its info names the key that
announced it, so a URL cannot answer for another service. A service is
still probed for seven days after its last announcement, so going away
shows as downtime rather than vanishing. Probes are kept for 90 days.

Announcing is free, so a flood of announcements must not hide or delay
the services that work. Those that answered as themselves in the last
seven days are asked of the relays by their keys too, so newer
announcements filling what a relay answers cannot hide them. They are
also probed apart: at most 8 of them at once, and 4 of all the others,
so a flood of services that never answer delays only its own probes.
At most 2,000 services of a role seen in the last seven days may not have
answered in them: past that, announcements of new keys are passed over,
with a warning in the log, while known ones and those configured with
`--hub` or `--provider` are kept up to date. An announced service that
never answered is forgotten, with its probes, seven days after it was
last seen, making room for others.

## Probes, and Tor

Each service's URLs are probed every `--probe-every` seconds (300 by
default), each at a random moment in the first half of the round, so no
service can tell a probe from a user. Every probe goes over Tor, on its own
circuit, so every service is measured from the same place and none sees
the observatory's address. One probe makes three timings on one connection:

- **Setup**: the Tor circuit, the stream and TLS. This is mostly Tor's,
  and is shown apart.
- **Round trip**: `GET /health`. This is the service as seen through Tor,
  and leaderboards rank by its median.
- **Work**: `GET /v1/info` (or `/v1/swaps/info`) less the round trip, which
  is the time the service took to answer.

Onion URLs are reached the same way. `--direct` reaches services without
Tor, for regtest or a VPN of one's own: onion URLs are then skipped, and
services see the observatory's address. Anyone may announce a URL, so
outside regtest a direct probe connects only to public addresses, as the
host resolves: none on the observatory's own machine or network, unless
given with `--hub` or `--provider`.

## What the page shows

- **Overview**: a banner saying how many services answer, services up,
  median latencies, where the time goes (Tor's setup, the round trip, the
  service's work, in one bar), leaderboards (uptime, round trip, success of
  measured moves) with a bar for each, and the fees of each kind of
  payment on 10,000 sat, at their cheapest and median.
- **Hubs** and **Swap providers**: each service's state, a strip of its
  probes over the range (green all answered, amber some, red none), uptime,
  round trip and terms. *Into it* is what providers can move into a hub now, in
  all, which is the liquidity they offer it.
- **A service's page**: its URLs, a latency chart, its terms in full
  (Licash, Lightning, Bitcoin, protection and its interest), how far its
  chain is behind the other hubs', and the moves that used it.

Uptime is the share of probes that answered. A service with fewer than
three probes in the range is not ranked. The range is 24 hours, 7 days or
30 days (`?range=24h|7d|30d`).

Terms are read part by part. A service running another version, whose info
has a part this one cannot read, shows that part as not known, and is still
counted as up.

## Moving a balance

With `--budget SAT`, the observatory also keeps a wallet,
`<data>/<network>/wallet.sqlite`, made with a seed of its own on the first
run, and moves part of it between the services of one network. With several
networks, `--funded NETWORK` says which: the others are watched, and show
no moves. This
measures what probes cannot: whether payments go through, how long they
take, and what they cost.

| Move | What it does | Share of the budget | At most every |
| --- | --- | --- | --- |
| In Licash | pays itself at a hub | 10% | 10 minutes |
| Between hubs | swaps through a provider from one hub to another | 30% | 30 minutes |
| Over Lightning | no longer made (see below), shown for the moves recorded before | 30% | 30 minutes |
| On Bitcoin | pays out of a hub through a provider to the address of a deposit a provider takes for notes at a hub, then claims the notes | 30% | 24 hours |

A move on Bitcoin is timed by its swap: from asking the provider to the
moment its coin is on the network. The blocks waited for after that, and the
deposit's claim, are not counted in its time, only in what it
costs; the page shows the swap's time and the whole apart. A move made
before this was timed, or that failed before the provider's coin, shows no
time.

Each move moves `--amount` sat (2,000 by default), and a move on Bitcoin
at least the smallest deposit its provider takes (10,000 sat by default). Moves on
Bitcoin are made only with `--chain URL`, Bitcoin Core's JSON-RPC
(`http://user:pass@host:8332`) or Esplora (`esplora+https://host/api`),
which the observatory reads directly, not over Tor, to follow its payouts
and broadcast their claims. Such a move costs the provider's and the
hub's fees and two transactions' miners, around 2,000 sat on signet: with
a budget of 10,000 sat a month, its 3,000 sat share pays for one every
twenty days or so. A kind of move whose single move costs more than its
share is never made. How often a kind of
move comes is its share of the budget over what its last moves cost: a
move costing 3 sat comes far more often than one costing 300, and none
more often than the table's limit. Each wait is drawn between half and one
and a half times that mean, so no service can tell when the next comes.
A move is made only if the 30 days before it, with its quote, stay within
its share and the whole budget, and it costs no more than its quote: a
provider asking more by the time the move is made, for a swap or a
deposit, is refused before anything is locked or paid out, and the move
fails.

Moves over Lightning are no longer made: hubs pay and make no invoices,
and a provider's invoice for a wallet can't be paid through another
provider, so no route over Lightning starts and ends in Licash. The kind
stays, disabled, for the moves recorded before, and its share of the
budget is left unspent. A kind that waits shows why on the Moves page.

A swap is quoted at a few providers at random until one agrees to its
limits: a fee of 1% and 100 sat, and a margin (how long the notes stay
locked if the provider never pays) of 200 blocks or twelve hours of blocks,
whichever is more, so that on a network of 30 second blocks a provider asking
for 482 is not refused for a few hours of a few thousand sat.

Moves are made one at a time, and each costs what the wallet holds less
after it: fees, and anything lost. Only services that answered their last
probe are used, a source hub only if it holds enough, and the rest at
random. A move not done in time (2 minutes in Licash, 15 between hubs, 6
hours on Bitcoin) counts as failed; the wallet takes it
on later, as it does moves under way when the observatory stops. A move on
Bitcoin that failed after its payout is counted at its quote, as its value
may still be on its way.

Fund the wallet at any hub the observatory watches, with the `licash-wallet`
CLI beside it, and let the observatory take the payment on:

```sh
export LICASH_WALLET=./observatory/signet/wallet.sqlite
licash-wallet invoice 20000 --hub https://hub.example --via https://swaps.example   # pay it from any node
licash-wallet balance
```

The *Moves* page shows the budget, what each kind spent, when the next
comes, and every move with its route, time, quote and cost. The success
leaderboard ranks services by the share of moves through them that went
through.

The balance is unprotected, like any hub's notes without a contract:
keep it small, as a hub that stops paying loses it. Pay it out with
`licash-wallet` when the observatory stops.

## JSON API

`GET /signet/api/v1/view?range=7d` returns everything the pages of a network
show.
`GET /health` answers `ok`.

## Records

`<data>/<network>/observatory.sqlite` holds the services, probes,
terms and moves. Its schema is versioned; an observatory refuses records
written by a later version rather than misreading them. A column added
later (as the swap's time of a move on Bitcoin) is nullable and added when
a file is opened, so an older image still opens the file after a rollback.

## Docker

```sh
docker build -f apps/observatory/Dockerfile -t licash-observatory .
docker run -d --name observatory -p 8350:8350 -v licash-observatory:/data \
  licash-observatory run --network signet --budget 5000
docker exec -e LICASH_WALLET=/data/signet/wallet.sqlite observatory \
  licash-wallet invoice 20000 --hub https://hub.example --via https://swaps.example
```

The image listens on `0.0.0.0:8350` and keeps its records, wallet and
Tor's state in `/data`; point `licash-wallet` in it at the wallet with
`LICASH_WALLET`.
