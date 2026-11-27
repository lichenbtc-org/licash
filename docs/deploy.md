# Deploying a hub with its standby

A layout for a hub that serves contracts with a standby nobody can find:
the hub on a machine of the operator's (a GPU there proves its disputes),
and a standby without the hub's seed on a rented server, reached only over
WireGuard. The files are in `deploy/`; [the hub's reference](hub.md)
says what each setting does. Mutinynet runs it as mainnet will, in
blocks 20 times as quick.

```
 the hub's machine (GPU)                     the standby's machine (VPS)
 +-----------------------+    WireGuard     +------------------------+
 | hub        (onion)    |  10.73.0.1 ->    | standby  (no port)     |
 | litestream -> replica |  10.73.0.2       |   restores the replica |
 | standby-sync ---------+--- rsync/SSH --->|   at each start        |
 | node, fee wallet      |                  | node, its fee wallet   |
 +-----------------------+                  +------------------------+
        |   \_____ witnesses (2 or more, HTTPS) _____/   |
        rented GPUs, over SSH, while a proof is due (either side)
```

A spare standby is fed as the main one is (another peer, `10.73.0.3`),
and its standby started there by hand if the main one is lost too.

## What each machine holds

- The hub: `seed` (keep a copy offline), `hub.sqlite`, the Core wallet
  that funds contracts, the WireGuard key that reaches each standby and
  the SSH key that feeds them.
- A standby: `standby.json` (the witness key and what the standby signs
  with, no seed), a copy of `hub.sqlite`, and its own Core wallet for the
  fees of its answers. Whoever reads its disk can answer the hub's disputes
  as the hub, and be paid with the hub's reserve for a contract they also
  hold ([The standby](hub.md#the-standby)): keep its disk encrypted.

Nothing names a standby: its address is in the hub's WireGuard file only.
WireGuard answers no packet without a peer's key, so a scan of its
address finds no service, and its SSH listens on the WireGuard address
alone. The hub dials out to it, so the hub's machine opens no port either.

## The standby's machine

1. Run a node of the hub's network, and a Core wallet of its own
   (`createwallet licash-standby`) with a few transactions' worth of fees.
2. WireGuard, as `deploy/wireguard/standby-wg0.conf.example` (keys from
   `wg genkey`, `wg pubkey` and `wg genpsk`), and a firewall that lets in
   UDP 51820 and nothing else from outside.
3. A user for the hub's feed, of the standby image's UID, and its files:

   ```sh
   useradd --uid 10001 --create-home --shell /bin/sh licash
   install -d -o licash -m 700 /srv/licash-standby /srv/licash-standby/data /srv/licash-standby/replica
   ```

   Put the hub's feed key (below) in `~licash/.ssh/authorized_keys`, and
   set `ListenAddress 10.73.0.2` in `sshd_config`.
4. `deploy/standby/compose.yml` with `standby.env` from its example, then
   `docker compose up -d` once the hub has fed it and `standby.json` is in
   `/srv/licash-standby` (below).

## The hub's machine

1. A node, the Core wallet that funds contracts, the NVIDIA driver (550 or
   newer) and the NVIDIA container toolkit, and two witnesses or more on
   machines of their own ([Contract witnesses](hub.md#contract-witnesses)).
2. WireGuard, as `deploy/wireguard/hub-wg0.conf.example`, a peer for each
   standby.
3. In `deploy/hub`, `.env` and `hub.env` from their examples, then the
   data directory, the hub's key, and the standby's keys:

   ```sh
   install -d -o 10001 -m 700 data data/opening-instances data/header-chain data/hp-proofs replica
   docker compose run --rm hub init
   docker compose run --rm hub standby-keys /data/standby.json
   scp data/standby.json licash@10.73.0.2:/srv/licash-standby/ && rm data/standby.json
   ```

4. The feed's key: `ssh-keygen -t ed25519 -N '' -f ssh/id_ed25519`, its
   public half on each standby, and each standby's host key in
   `ssh/known_hosts` (`ssh-keyscan 10.73.0.2 >> ssh/known_hosts` over the
   tunnel). Make `ssh/` readable by UID 10001.
5. `docker compose up -d`. Litestream replicates `hub.sqlite` into
   `replica/`, and `standby-sync` feeds each standby in `LICASH_STANDBYS`
   every 10 seconds. First the finished files (each opening's instances,
   the header chain's receipts, each dispute's frozen input and proof), a
   file the hub replaced replacing the standby's and none deleted there.
   Then the replica as it was before those files were read, so that a
   standby restores no ledger naming a file it lacks. A standby that acted
   is sent the replica alone: its files are its own. The feed turns
   unhealthy when a standby has gone 5 minutes unfed.

`deploy/test.sh` runs that feed on one machine, with Litestream's image:
a ledger written as the hub writes it, fed and restored after every round.

## Proving on rented GPUs

A dispute's proof is due once a holder contests a response: within the
assert window for the hub (144 blocks on mainnet), and within its second
half for a standby, which leaves each step to a live hub until halfway.
The hub's own GPU proves its usual load. For more at once, a mass exit,
name rented machines in `LICASH_R0_WORKERS` (`licash-r0-remote
root@gpu-1; ...`, [docs/r0.md](r0.md)): each needs `licash-r0` and
`licash-r0-cuda` on its `PATH` (the hub's image has them), an NVIDIA
driver and SSH, and holds no state. Its SSH key goes in `<data>/.ssh`.
Rent them per hour or minute, as a proof is due: a worker that fails or
times out has its jobs proved elsewhere or locally, so name more than one
provider. Raise `LICASH_HUB_CONTRACTS_PROOF_SCALE` by what they add to
the hub's own capacity; the hub plans which contracts it can prove in time
by it, and is never told what was rented.

The standby has no GPU: name the workers in its `standby.env` too. A
rented machine sees the address the standby connects from: rent from a
provider that asks for no identity, and only once a proof is due.

## Watching it

- The hub's alerts (`LICASH_HUB_NOTIFY`) and `/health`.
- `standby-sync`'s health: unhealthy, a standby is on an older ledger.
- The standby's alerts: it starts on a ledger it could not restore, runs
  without its entrypoint, or acts, which it does only once the hub has
  not acted by halfway through a step's window. Its starts are routine:
  it stops for a newer ledger every quarter of a response window (36
  blocks on mainnet) and before a step whose midpoint is past its restore.
- Each node's tip against others.

## Rehearsing on Mutinynet

Open a contract, have its holder claim more than she is owed, and stop
the hub (`docker compose stop hub`) once she contests. The standby takes
the step due halfway through its window, 72 blocks (36 minutes) into the
144 to respond or answer in, 1,440 (12 hours) into Mutinynet's assert
window, and alerts that it acted. Then
recover as below. Stop the standby too, start the spare's, and see it
restore and play the same dispute from where the main one left it.

## When the hub is lost

The standby answers what is due, on its own from then on (its
`standby-acted`): never restore the hub from its copy. Restore the hub
from its seed and its newest backup (the standby's `replica/` is one, as
of the last feed), take its contracts over, promote its ledger
(`licash-hub ledger-promote`, as a restored ledger serves no wallet
until then) and start it ([Taking over](hub.md#taking-over)). Leave the standby running until the
contracts it acted on have ended, then remove its `standby-acted` and
`hub.sqlite`: it is restored from the hub's replica again at its next
start. What it swept or collected is in its own wallet.

## Upgrading

Pull both images (`LICASH_TAG`) and restart the hub, then the standby.
A standby of an earlier release, on a `hub.sqlite` its entrypoint did not
restore, is never restored over: adopt that ledger with `touch
/srv/licash-standby/data/standby-restored` if it never answered on it.

Contracts open on Mutinynet and signet only for now: mainnet waits for
its programs to be trusted.
