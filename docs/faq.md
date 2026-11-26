# FAQ

Short answers. The [paper](../paper/licash.pdf) has the protocol and its
arguments.

## Your money

### Can other users take what my contract protects?

No. Its bitcoin is locked for you alone until it ends, and nothing another
holder does can reduce your claim.

### What happens when a contract ends?

Your notes stay valid; only the guarantee stops. Beyond your open
contracts, notes rest on the hub's word, as at any ecash mint, until you
spend them, cash out or protect them again. You choose how long a contract
lasts, and nothing needs refreshing meanwhile.

### Do I have to stay online?

No. Come back before your contract ends. Only during a recovery you
started must the wallet be online for its deadlines, and the app tells you.

### Who pays the Bitcoin fees of a recovery?

Each side pays for its own moves. A recovery the hub does not dispute is
about 7 kvB in all, and you pay it, partly from the reserve you put in
the contract. A dispute adds the hub's proof and, only against a false one,
your challenge. A close you both sign is a single transaction.

## Hubs

### Can a hub or a user grief the other?

A hub can refuse service, but cannot force you onchain or close your
contract: only you start a recovery. A user can overstate a claim, making
the hub prove her wrong, but a contract pays once and she pays her own
fees. A hub that answers a claim and then fails to prove it loses its
reserve. Paper, Recovery.

### What if the hub goes offline?

You recover on Bitcoin without it. The risk is the hub's: a claim it leaves
unanswered is paid in full after a timeout, so a hub must stay online.

### How many users can a hub serve?

As many contracts as it could defend at once, should every holder exit
together: 32 live contracts by default, more with faster provers. Hubs
stay small, and payments cross between hubs.

### How much must a hub lock up?

Its reserve (100,000 sat on signet, 60,000 on Mutinynet, as planned for
Bitcoin's network) and the part of the cap you do not fund yourself. By default it charges interest only on its own part.

### What does the hub see?

Which notes are spent together, and their denominations (powers of two).
Not your balance, nor who pays whom: it cannot link a note's spending to
its issuance. Paper, Privacy.

## Under the hood

### What does my phone do?

It signs; it never proves anything. The hub carries the burden of proof.
Opening a contract garbles the hub's statement on the phone and uploads
about 250 MB to the hub. Paper, Light clients.

### Who makes the proof, and how heavy is it?

The hub, only in a dispute: minutes on a consumer GPU, hours on a CPU
([measured](r0.md#measured)).

### Is there a trusted setup?

Yes, for the Groth16 wrapper of the hub's proof: RISC Zero's public
ceremonies, safe if any one contributor was honest
([details](r0.md#setup-trust)).

## Status

### Only Bitcoin?

Yes. It runs on Bitcoin's signet, Mutinynet and regtest today.

### How mature is it?

A trial. The code has had no security review: do not use real funds.
