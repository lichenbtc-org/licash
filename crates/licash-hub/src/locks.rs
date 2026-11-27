//! Timed locks and the view of Bitcoin that decides them.
//!
//! A lock's notes pay its outputs on the preimage of its hash, or refund
//! the payer once it expired unactivated. The hub owes one branch only: it
//! pays unless it refunded, and refunds only once its scan shows the lock
//! expired at depth with no activation of the hash between the lock's
//! checkpoint and its expiry, on any branch of the chain it ever scanned.

use std::time::{Duration, Instant};

use bitcoin::{block::Header, consensus::deserialize, hashes::Hash, Block};
use licash::{
    address::{Ephemeral, REFUND_INDEX},
    authorization::{Authorization, SignedProposal},
    chain::{activation_secret, Checkpoint},
    claim::Branch,
    crypto::{Point, Signature},
    note::{MintResponse, Note},
    route::Hop,
    source::Certificate,
    spend::{lock_hash, Output, Proposal, ProposalId, TimedLock, TimedTerms},
    unlink::Nonce,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::citable::Citable;
use crate::{forwards, notify, now, retire, sql, Error, Hub, Notice, Refusal};

/// The timing of the locks a hub admits, in blocks unless named.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Timing {
    /// The blocks a lock lives at most from its admission: its expiry,
    /// depth and the hub's reaction fit within them. A refund is owed on
    /// Bitcoin only once its lock expired at depth (under a v4 Base), so
    /// this bounds how long the hub holds a lock open, not a response.
    pub window: u32,
    /// Blocks the hub needs to produce and confirm a response.
    pub reaction: u32,
    /// Least activation depth of a lock. Above 1 on mainnet: forks the
    /// hub never saw are covered by depth only.
    pub min_depth: u32,
    /// Header budget of the hub's contracts from their checkpoint, within
    /// which every lock is decided.
    pub max_headers: u32,
    /// Confirmations of a checkpoint before locks may name it.
    pub bury: u32,
    /// Seconds since the scan last reached the chain's tip after which
    /// the hub admits no lock.
    pub max_lag: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            window: 144,
            reaction: 6,
            min_depth: 3,
            max_headers: 4032,
            bury: 6,
            max_lag: 120,
        }
    }
}

/// The branch of a lock the hub issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Settled {
    Pay,
    Refund,
}

impl Settled {
    fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "pay" => Ok(Self::Pay),
            "refund" => Ok(Self::Refund),
            _ => Err(Error::Halted),
        }
    }
}

/// A lock as the hub holds it.
#[derive(Clone, Debug)]
pub struct Lock {
    pub proposal: Proposal,
    pub certificate: Certificate,
    pub settled: Option<Settled>,
    /// Once known, from a settlement or an activation on Bitcoin.
    pub preimage: Option<[u8; 32]>,
    /// Whether the hub locked notes it issued itself ([`Hub::lock_own`]).
    pub own: bool,
}

impl Lock {
    fn terms(&self) -> &TimedTerms {
        self.proposal.lock().expect("a lock").terms()
    }
}

/// A lock with what deciding it needs.
struct Row {
    lock: Lock,
    keyset: [u8; 32],
    /// The height of its checkpoint.
    anchor: u32,
}

/// The hub's view of Bitcoin.
impl Hub {
    /// Name `checkpoint` in locks from now on. The first checkpoint starts
    /// the scan at its block, as the operator's backend reports it; a later
    /// one must be a scanned block with [`Timing::bury`] confirmations.
    pub fn add_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), Error> {
        let header: Header = deserialize(checkpoint.header()).expect("a checkpoint's header");
        let hash = header.block_hash().to_byte_array();
        let prev = header.prev_blockhash.to_byte_array();
        let height = checkpoint.height();
        let added = self.store.write(|tx| {
            let commitment = checkpoint.commitment();
            if checkpoint_of(tx, &commitment)?.is_some() {
                return Ok(false);
            }
            if let Some(other) = newest_checkpoint(tx)? {
                if other.profile() != checkpoint.profile() {
                    return Err(Refusal::Checkpoint("another chain").into());
                }
            }
            match tip(tx)? {
                None => {
                    tx.execute(
                        "INSERT INTO blocks (height, hash, prev) VALUES (?1, ?2, ?3)",
                        params![height, hash, prev],
                    )?;
                }
                Some((top, _)) => {
                    if block_at(tx, height)? != Some(hash) {
                        return Err(Refusal::Checkpoint("not in the scanned chain").into());
                    }
                    if top - height + 1 < self.policy.timing.bury {
                        return Err(Refusal::Checkpoint("not buried").into());
                    }
                }
            }
            tx.execute(
                "INSERT INTO checkpoints (commitment, height, bytes, added_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![commitment, height, checkpoint.to_bytes(), now()],
            )?;
            Ok(true)
        })?;
        if added {
            tracing::info!(height, "checkpoint added");
            let mut newest = self.newest.lock().unwrap_or_else(|e| e.into_inner());
            if newest.as_ref().is_none_or(|c| c.height() < height) {
                *newest = Some(checkpoint.clone());
            }
        }
        Ok(())
    }

    /// The checkpoint of `commitment`, one locks named, if the hub added it.
    pub fn checkpoint_named(&self, commitment: &[u8; 32]) -> Result<Option<Checkpoint>, Error> {
        self.store.read(|c| checkpoint_of(c, commitment))
    }

    /// The newest checkpoint, which new locks should name.
    pub fn checkpoint(&self) -> Option<Checkpoint> {
        self.newest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The scanned tip: its height and block hash, in Bitcoin's byte order.
    pub fn scanned(&self) -> Result<Option<(u32, [u8; 32])>, Error> {
        self.store.read(tip)
    }

    /// The hash of the scanned block at `height`.
    pub fn scanned_at(&self, height: u32) -> Result<Option<[u8; 32]>, Error> {
        self.store.read(|c| block_at(c, height))
    }

    /// Scan `block`, which must extend the scanned tip at `height`. The
    /// activations it carries are kept for good, and give the preimage of
    /// the locks under their hash. A block scanned already is ignored.
    pub fn observe(&self, height: u32, block: &Block) -> Result<(), Error> {
        if !block.check_merkle_root() {
            return Err(Refusal::Block("merkle root").into());
        }
        let hash = block.block_hash().to_byte_array();
        let prev = block.header.prev_blockhash.to_byte_array();
        let mut found = Vec::new();
        for tx in &block.txdata {
            for (output, out) in (0u32..).zip(&tx.output) {
                if let Some(secret) = activation_secret(out.script_pubkey.as_bytes()) {
                    found.push((tx.compute_txid().to_byte_array(), output, secret));
                }
            }
        }
        let activated = self.store.write(|tx| {
            let (top, top_hash) = tip(tx)?.ok_or(Refusal::NoChain)?;
            if height <= top {
                return match block_at(tx, height)? {
                    Some(seen) if seen == hash => Ok(Vec::new()),
                    _ => Err(Refusal::Block("another block at its height: rewind first").into()),
                };
            }
            if height != top + 1 || prev != top_hash {
                return Err(Refusal::Block("does not extend the scanned tip").into());
            }
            tx.execute(
                "INSERT INTO blocks (height, hash, prev) VALUES (?1, ?2, ?3)",
                params![height, hash, prev],
            )?;
            let mut activated = Vec::new();
            for (txid, output, secret) in &found {
                let lock = lock_hash(secret);
                let new = tx.execute(
                    "INSERT INTO activations (block, txid, output, hash, secret, height)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
                    params![hash, txid, output, lock, secret, height],
                )?;
                tx.execute(
                    "UPDATE locks SET preimage = ?2 WHERE hash = ?1 AND preimage IS NULL",
                    params![lock, secret],
                )?;
                if new == 0 {
                    continue;
                }
                // The locks it makes pay: a refunded one is owed twice,
                // unless the hub gave up its pay branch on a failed forward.
                let hit: Vec<([u8; 32], bool)> = tx
                    .prepare(
                        "SELECT l.id, l.settled IS 'refund' FROM locks l
                         JOIN checkpoints c ON c.commitment = l.checkpoint
                         WHERE l.hash = ?1 AND c.height < ?2 AND ?2 < l.expiry_height
                           AND l.settled IS NOT 'pay'
                           AND NOT EXISTS (SELECT 1 FROM forwards f
                                           WHERE f.lock = l.id AND f.state = 'failed')",
                    )?
                    .query_map(params![lock, height], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                for (id, refunded) in hit {
                    let proposal = hex::encode(id);
                    notify(
                        tx,
                        &Notice::Activated {
                            proposal,
                            height,
                            refunded,
                        },
                    )?;
                    activated.push((id, refunded));
                }
            }
            Ok(activated)
        })?;
        for (id, refunded) in activated {
            let proposal = hex::encode(id);
            if refunded {
                tracing::error!(%proposal, height, "a refunded lock was activated in time");
            } else {
                tracing::warn!(%proposal, height, "lock activated on Bitcoin");
            }
        }
        Ok(())
    }

    /// Forget the scanned blocks from `height` on, which left the best
    /// chain. Their activations are kept. A reorganization of a checkpoint
    /// is refused and alerted: the operator must decide what follows.
    pub fn rewind(&self, height: u32) -> Result<(), Error> {
        let deep = self.store.write(|tx| {
            let anchored: Option<u32> =
                tx.query_row("SELECT max(height) FROM checkpoints", [], |r| r.get(0))?;
            if anchored.is_some_and(|a| height <= a) {
                if !self
                    .reorg_alerted
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    notify(tx, &Notice::Reorg { height })?;
                }
                return Ok(true);
            }
            tx.execute("DELETE FROM blocks WHERE height >= ?1", [height])?;
            Ok(false)
        })?;
        if deep {
            *self.synced_at.lock().unwrap_or_else(|e| e.into_inner()) = None;
            tracing::error!(height, "Bitcoin reorganized a checkpoint: the scan stops");
            return Err(Refusal::Block("a reorganization of a checkpoint").into());
        }
        tracing::warn!(height, "rewound the scan");
        Ok(())
    }

    /// The operator's backend has its best chain's tip at `height`, block
    /// `hash`: the scan is synced while it reached that tip, for at most
    /// [`Timing::max_lag`], and while that block stays scanned, and not at
    /// all otherwise. Whether it reached it.
    pub fn synced(&self, height: u32, hash: &[u8; 32]) -> Result<bool, Error> {
        let reached = self.store.read(tip)? == Some((height, *hash));
        let until = Instant::now() + Duration::from_secs(self.policy.timing.max_lag);
        let synced = reached.then_some(SyncedTip {
            until,
            height,
            hash: *hash,
        });
        *self.synced_at.lock().unwrap_or_else(|e| e.into_inner()) = synced;
        Ok(reached)
    }

    /// The tip the scan last reached, to tell whether it is synced in the
    /// transaction deciding by it ([`SyncedTip::holds`]).
    pub(crate) fn synced_tip(&self) -> Option<SyncedTip> {
        *self.synced_at.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The chain's tip the scan reached, as the operator's backend said:
/// synced while it is still scanned, the scan rewound below it never, and
/// until [`Timing::max_lag`] after.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SyncedTip {
    until: Instant,
    height: u32,
    hash: [u8; 32],
}

impl SyncedTip {
    /// Whether `tip` holds in `c`, the transaction that decides by it: a
    /// rewind that took its block meanwhile is seen.
    pub(crate) fn holds(tip: Option<Self>, c: &Connection) -> Result<bool, Error> {
        let Some(tip) = tip.filter(|t| Instant::now() <= t.until) else {
            return Ok(false);
        };
        Ok(block_at(c, tip.height)? == Some(tip.hash))
    }
}

/// Timed locks.
impl Hub {
    /// The certificate of the timed lock `signed` makes of `notes`, plainly
    /// authorized: its inputs are retired and both branches' outputs
    /// reserved. Its pay branch pays the hub [`crate::Policy::lock`], its
    /// refund branch [`crate::Policy::refund`]. The same lock gets the
    /// same certificate.
    pub fn lock(&self, signed: &SignedProposal, notes: &[Note]) -> Result<Certificate, Error> {
        let proposal = signed.proposal();
        let (keys, keyset) = self.keys(proposal.keyset_id())?;
        let timed = proposal.lock().ok_or(Refusal::NotALock)?;
        if !matches!(signed.authorization(), Authorization::Plain) {
            return Err(Refusal::NotALock.into());
        }
        let id = proposal.id();
        // Admitted under whatever policy held then.
        if let Some(row) = self.store.read(|c| self.row(c, &id))? {
            return Ok(row.lock.certificate);
        }
        // Verified as it would be cited, its owners' signatures and notes.
        let citable = Citable::check(keyset, signed, notes, None)?;
        let charge = self.lock_charge(proposal)?;
        let fees = self.policy.fees();
        let made =
            |branch: Branch, outputs: &[Output]| outputs.len().saturating_sub(charge.count(branch));
        let (pay, refund) = (
            made(Branch::Pay, proposal.outputs()),
            made(Branch::Refund, timed.refund()),
        );
        for (paid, due) in [
            (charge.pay, fees.locking().due(charge.amount, pay)),
            (charge.refund, fees.refunding().due(charge.amount, refund)),
        ] {
            if paid < due {
                return Err(Refusal::Fee { due, paid }.into());
            }
        }
        let certificate = Certificate::attest(keys, signed, notes)?;
        let mut spent_by = None;
        let locked = self.store.write(|tx| {
            if let Some(row) = self.row(tx, &id)? {
                return Ok((row.lock.certificate, false));
            }
            let decide_by = self.admit(tx, timed.terms())?;
            self.record(tx, signed, &certificate, charge.amount, decide_by, false)?;
            if let Some(by) = retire(tx, &id, &citable)? {
                spent_by = Some(by);
                return Err(Refusal::Spent.into());
            }
            notify(
                tx,
                &Notice::Locked {
                    proposal: hex::encode(id.as_bytes()),
                    amount: charge.amount,
                    fee: charge.pay,
                    expiry: timed.terms().expiry(),
                    own: false,
                },
            )?;
            Ok((certificate, true))
        });
        if let Some(by) = spent_by {
            let (proposal, spent_by) = (hex::encode(id.as_bytes()), hex::encode(by));
            tracing::warn!(%proposal, %spent_by, "double spend refused");
        }
        let (certificate, new) = locked?;
        if new {
            let expiry = timed.terms().expiry();
            tracing::info!(proposal = %hex::encode(id.as_bytes()), amount = charge.amount, expiry, "locked");
        }
        Ok(certificate)
    }

    /// Lock notes the hub issues itself, of `pay`'s denominations, to
    /// `pay` under `terms`, with `ephemeral` the payee derived `pay` with;
    /// the refund branch returns to the hub, which issues nothing on it.
    /// The notes are backed by what the caller holds for the hash, such as
    /// an accepted HTLC, which it must keep until the lock is settled or
    /// refunded. One own lock per hash, ever: the same request gets it
    /// again, settled or not, so that no retry backs a second payment with
    /// what the caller holds.
    pub fn lock_own(
        &self,
        keyset: &[u8; 32],
        ephemeral: Point,
        pay: Vec<Output>,
        terms: TimedTerms,
    ) -> Result<Lock, Error> {
        let (keys, keyset) = self.keys(keyset)?;
        let same = |lock: &Lock| {
            lock.proposal.keyset_id() == keyset.id()
                && lock.proposal.ephemeral() == ephemeral
                && lock.proposal.outputs() == pay.as_slice()
                && *lock.terms() == terms
        };
        let existing = self.store.read(|c| self.own_lock(c, terms.hash()))?;
        if let Some(lock) = existing {
            return if same(&lock) {
                Ok(lock)
            } else {
                Err(Refusal::Exists.into())
            };
        }
        let owner = &self.secrets()?.owner;
        let address = self.address;
        let (minting, back) = (Ephemeral::random(), Ephemeral::random());
        let (mut notes, mut owners, mut refund) = (Vec::new(), Vec::new(), Vec::new());
        for (i, output) in pay.iter().enumerate() {
            let denom = output.denomination();
            let d = minting.derive(&address, denom, Branch::Pay, i)?;
            let note = Nonce::new(keyset, &Output::from_derivation(&d)?)?
                .issue(keys)?
                .open(keyset, &d)?;
            notes.push(note);
            owners.push(d.ownership().owner_secret(owner.spend_secret())?);
            let r = back.derive(&address, denom, Branch::Refund, i)?;
            refund.push(Output::from_derivation(&r)?);
        }
        let amount = pay
            .iter()
            .fold(0u64, |sum, o| sum.saturating_add(o.denomination()));
        let expiry = terms.expiry();
        let lock = TimedLock::new(terms.clone(), refund)?;
        let proposal = Proposal::new(keyset, &notes, ephemeral, pay.clone(), Some(lock))?;
        let signed = SignedProposal::sign(keyset, proposal, &notes, Authorization::Plain, &owners)?;
        let citable = Citable::check(keyset, &signed, &notes, None)?;
        let certificate = Certificate::attest(keys, &signed, &notes)?;
        let id = signed.proposal().id();
        let terms = signed.proposal().lock().expect("a lock").terms();
        let lock = self.store.write(|tx| {
            if let Some(lock) = self.own_lock(tx, terms.hash())? {
                return if same(&lock) {
                    Ok(lock)
                } else {
                    Err(Refusal::Exists.into())
                };
            }
            let decide_by = self.admit(tx, terms)?;
            self.record(tx, &signed, &certificate, amount, decide_by, true)?;
            if retire(tx, &id, &citable)?.is_some() {
                // Fresh notes: a spent one would be a broken ledger.
                return Err(Error::Halted);
            }
            let proposal = hex::encode(id.as_bytes());
            notify(
                tx,
                &Notice::Locked {
                    proposal,
                    amount,
                    fee: 0,
                    expiry,
                    own: true,
                },
            )?;
            Ok(self.row(tx, &id)?.ok_or(Error::Halted)?.lock)
        })?;
        tracing::info!(proposal = %hex::encode(id.as_bytes()), amount, expiry, "locked own notes");
        Ok(lock)
    }

    /// The issuances of the pay branch of lock `id`, for the preimage of
    /// its hash, unless the hub refunded it. Where the payee is not the
    /// hub, only while the lock has not expired or once an activation
    /// published the preimage in time: the payer may count on a refund.
    /// A payment under way for the lock is paid ([`Hub::forward`]).
    pub fn settle(&self, id: &ProposalId, preimage: &[u8; 32]) -> Result<Vec<MintResponse>, Error> {
        let Row {
            lock,
            keyset,
            anchor,
        } = self
            .store
            .read(|c| self.row(c, id))?
            .ok_or(Refusal::UnknownLock)?;
        let terms = lock.terms().clone();
        if lock_hash(preimage) != *terms.hash() {
            return Err(Refusal::Preimage.into());
        }
        let (keys, keyset) = self.keys(&keyset)?;
        let outputs = lock.proposal.outputs();
        let charge = self.lock_charge(&lock.proposal)?;
        let hub_payee = charge.count(Branch::Pay) == outputs.len();
        let nonces = self.nonce_secret(id.as_bytes())?;
        let issuances = outputs
            .iter()
            .map(|o| Nonce::derive(&nonces, keyset, o)?.issue(keys))
            .collect::<Result<Vec<_>, _>>()?;
        let income = if lock.own {
            Vec::new()
        } else {
            charge.received(Branch::Pay, |i, d| issuances[i].open(keyset, d))?
        };
        let synced = self.synced_tip();
        let settled = self.store.write(|tx| {
            match settled_of(tx, id)? {
                Some(Settled::Pay) => return Ok(None),
                Some(Settled::Refund) => return Err(Refusal::Settled.into()),
                None => {}
            }
            if !hub_payee && !activated(tx, &terms, anchor)? {
                let (top, _) = tip(tx)?.ok_or(Refusal::NoChain)?;
                if top >= terms.expiry() {
                    return Err(Refusal::LockExpired.into());
                }
                // It may have expired on a chain the hub has not scanned.
                if !SyncedTip::holds(synced, tx)? {
                    return Err(Refusal::Unsynced.into());
                }
            }
            self.issue(tx, id, keyset, outputs, &issuances, &income)?;
            tx.execute(
                "UPDATE locks SET preimage = ?2, settled = 'pay', settled_at = ?3 WHERE id = ?1",
                params![id.as_bytes(), preimage, now()],
            )?;
            forwards::paid(tx, id, preimage)?;
            let proposal = hex::encode(id.as_bytes());
            let (amount, fee) = (lock_amount(tx, id)?, charge.pay);
            notify(
                tx,
                &Notice::Settled {
                    proposal,
                    amount,
                    fee,
                    branch: Settled::Pay,
                },
            )?;
            Ok(Some(()))
        })?;
        if settled.is_some() {
            tracing::info!(proposal = %hex::encode(id.as_bytes()), "lock paid");
        }
        self.store
            .read(|c| self.issued_branch(c, id, keyset, Branch::Pay))
    }

    /// The issuances of the refund branch of lock `id`, once the scan shows
    /// it expired at depth unactivated, unless the hub paid it, or a
    /// payment for it is under way ([`Hub::forward`]). An own lock's refund
    /// returns to the hub, which issues nothing.
    pub fn refund(&self, id: &ProposalId) -> Result<Vec<MintResponse>, Error> {
        self.refund_as(id, None)
    }

    /// Refund lock `id`, of which the hub gets `amount`, at once: its
    /// forward failed for `reason`, recorded in the same transaction if
    /// `new`.
    ///
    /// Safe before expiry only because a forward's lock pays the hub: its
    /// Pay output is the hub's own, which no holder's claim can name, so a
    /// holder can't be owed that Pay on Bitcoin after this refund. A lock
    /// whose Pay a holder owns is refunded only once expired at depth.
    pub(crate) fn refund_failed(
        &self,
        id: &ProposalId,
        reason: &str,
        amount: u64,
        new: Option<&forwards::New<'_>>,
    ) -> Result<(), Error> {
        self.refund_as(id, Some((reason, amount, new))).map(drop)
    }

    fn refund_as(
        &self,
        id: &ProposalId,
        failed: Option<(&str, u64, Option<&forwards::New<'_>>)>,
    ) -> Result<Vec<MintResponse>, Error> {
        let Row {
            lock,
            keyset,
            anchor,
        } = self
            .store
            .read(|c| self.row(c, id))?
            .ok_or(Refusal::UnknownLock)?;
        let terms = lock.terms().clone();
        let (keys, keyset) = self.keys(&keyset)?;
        let outputs = lock.proposal.lock().expect("a lock").refund();
        let charge = self.lock_charge(&lock.proposal)?;
        let (issuances, income) = if lock.own {
            (Vec::new(), Vec::new())
        } else {
            let nonces = self.nonce_secret(id.as_bytes())?;
            let issuances = outputs
                .iter()
                .map(|o| Nonce::derive(&nonces, keyset, o)?.issue(keys))
                .collect::<Result<Vec<_>, _>>()?;
            let income = charge.received(Branch::Refund, |i, d| issuances[i].open(keyset, d))?;
            (issuances, income)
        };
        let refunded = self.store.write(|tx| {
            if let Some((_, _, Some(new))) = failed {
                forwards::record(tx, new)?;
            }
            match settled_of(tx, id)? {
                Some(Settled::Refund) => return Ok(false),
                Some(Settled::Pay) => return Err(Refusal::Settled.into()),
                None => {}
            }
            match failed {
                // The hub gives up its claim, which it never paid for.
                Some((reason, amount, _)) => forwards::fail(tx, id, reason, amount)?,
                None => self.expired(tx, id, &terms, anchor)?,
            }
            if !lock.own {
                self.issue(tx, id, keyset, outputs, &issuances, &income)?;
            }
            tx.execute(
                "UPDATE locks SET settled = 'refund', settled_at = ?2 WHERE id = ?1",
                params![id.as_bytes(), now()],
            )?;
            let proposal = hex::encode(id.as_bytes());
            let (amount, fee) = (
                lock_amount(tx, id)?,
                if lock.own { 0 } else { charge.refund },
            );
            notify(
                tx,
                &Notice::Settled {
                    proposal,
                    amount,
                    fee,
                    branch: Settled::Refund,
                },
            )?;
            Ok(true)
        })?;
        if refunded {
            tracing::info!(proposal = %hex::encode(id.as_bytes()), "lock refunded");
        }
        self.store
            .read(|c| self.issued_branch(c, id, keyset, Branch::Refund))
    }

    /// Check that lock `id`, of `terms` from the checkpoint at `anchor`, is
    /// refunded: expired at depth unactivated on every block scanned, and
    /// no payment for it under way.
    fn expired(
        &self,
        tx: &Transaction<'_>,
        id: &ProposalId,
        terms: &TimedTerms,
        anchor: u32,
    ) -> Result<(), Error> {
        if forwards::pending(tx, id)? {
            return Err(Refusal::Forwarding.into());
        }
        expired_at_depth(tx, terms, anchor)
    }

    /// The hub's own locks it may yet pay ([`Hub::lock_own`]), whose
    /// backing must be kept until they are settled: unsettled, and not
    /// refundable, expired at depth unactivated on every block scanned.
    pub fn live_own_locks(&self) -> Result<Vec<Lock>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT id FROM locks WHERE own = 1 AND settled IS NULL ORDER BY expiry_height, id",
            )?;
            let ids = stmt.query_map([], |r| r.get::<_, [u8; 32]>(0))?;
            let ids: Vec<[u8; 32]> = ids.collect::<Result<_, _>>()?;
            let mut live = Vec::new();
            for id in ids {
                let Some(Row { lock, anchor, .. }) = self.row(c, &ProposalId::from_bytes(id))?
                else {
                    continue;
                };
                match expired_at_depth(c, lock.terms(), anchor) {
                    Ok(()) => {}
                    // Not known refundable, as with a gap in the scan: live.
                    Err(
                        Error::Refused(Refusal::Unexpired | Refusal::Activated) | Error::Halted,
                    ) => live.push(lock),
                    Err(e) => return Err(e),
                }
            }
            Ok(live)
        })
    }

    /// Lock `id` as the hub holds it.
    pub fn locked(&self, id: &ProposalId) -> Result<Lock, Error> {
        let row = self.store.read(|c| self.row(c, id))?;
        Ok(row.ok_or(Refusal::UnknownLock)?.lock)
    }

    /// The owner signatures the lock `id` was made with, for its payee to
    /// prove it on Bitcoin with its certificate: the hub's own too (a
    /// deposit's or a Lightning receipt's, [`Hub::lock_own`]), Plain as
    /// any, for its payee to activate it should the hub keep its notes.
    pub fn lock_signatures(&self, id: &ProposalId) -> Result<Vec<Signature>, Error> {
        let signed: Option<Vec<u8>> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT signed FROM locks WHERE id = ?1",
                [id.as_bytes()],
                |r| r.get(0),
            )
            .optional()?)
        })?;
        let signed = signed.ok_or(Refusal::UnknownLock)?;
        Ok(SignedProposal::plain_signatures(&signed)?)
    }

    /// The hub's own lock under `hash`, if any ([`Hub::lock_own`]).
    pub fn own_lock_of(&self, hash: &[u8; 32]) -> Result<Option<Lock>, Error> {
        self.store.read(|c| self.own_lock(c, hash))
    }
}

impl Hub {
    /// Check `terms` against the hub's chain and timing: the height by
    /// which it decides the lock, expired at depth, with its reaction.
    fn admit(&self, tx: &Transaction<'_>, terms: &TimedTerms) -> Result<u32, Error> {
        let t = self.policy.timing;
        let checkpoint =
            checkpoint_of(tx, terms.checkpoint())?.ok_or(Refusal::Checkpoint("unknown"))?;
        if checkpoint.profile() != terms.profile() {
            return Err(Refusal::Checkpoint("another chain").into());
        }
        if terms.depth() < t.min_depth {
            return Err(Refusal::Timing("depth below the hub's least").into());
        }
        if !SyncedTip::holds(self.synced_tip(), tx)? {
            return Err(Refusal::Unsynced.into());
        }
        let (now, _) = tip(tx)?.ok_or(Refusal::NoChain)?;
        let hop = Hop {
            window: t.window,
            confirm: 0,
            detect: 0,
            margin: 0,
            depth: terms.depth(),
            reaction: t.reaction,
        };
        if !hop.admits(now, terms.expiry()) {
            return Err(Refusal::Timing("expiry outside the hub's response window").into());
        }
        // Admitted, so this sum fits.
        let decide_by = terms.expiry() + terms.depth() + t.reaction;
        if u64::from(decide_by) > u64::from(checkpoint.height()) + u64::from(t.max_headers) {
            return Err(Refusal::Timing("beyond the checkpoint's header budget").into());
        }
        Ok(decide_by)
    }

    /// Record lock `signed` and reserve its outputs, before its inputs are
    /// retired. Its preimage is known if an activation published it.
    fn record(
        &self,
        tx: &Transaction<'_>,
        signed: &SignedProposal,
        certificate: &Certificate,
        amount: u64,
        decide_by: u32,
        own: bool,
    ) -> Result<(), Error> {
        let proposal = signed.proposal();
        let timed = proposal.lock().expect("a lock");
        let terms = timed.terms();
        let id = proposal.id();
        tx.execute(
            "INSERT INTO proposals (id, keyset, created_at) VALUES (?1, ?2, ?3)",
            params![id.as_bytes(), proposal.keyset_id(), now()],
        )?;
        for (branch, outputs) in [
            (Branch::Pay, proposal.outputs()),
            (Branch::Refund, timed.refund()),
        ] {
            for (i, output) in outputs.iter().enumerate() {
                let inserted = tx.execute(
                    "INSERT INTO issued (keyset, denom, blinded, commitment, proposal, position)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
                    params![
                        proposal.keyset_id(),
                        sql(output.denomination())?,
                        &output.blinded().0,
                        output.unlink_commitment(),
                        id.as_bytes(),
                        licash::address::index(branch, i)?,
                    ],
                )?;
                if inserted == 0 {
                    return Err(Refusal::Reissued.into());
                }
            }
        }
        let preimage: Option<[u8; 32]> = tx
            .query_row(
                "SELECT secret FROM activations WHERE hash = ?1 LIMIT 1",
                [terms.hash()],
                |r| r.get(0),
            )
            .optional()?;
        tx.execute(
            "INSERT INTO locks (id, hash, checkpoint, expiry_height, depth, decide_by_height, proposal, signed,
                                certificate, amount, own, preimage)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                id.as_bytes(),
                terms.hash(),
                terms.checkpoint(),
                terms.expiry(),
                terms.depth(),
                decide_by,
                proposal.commitment_bytes(),
                signed.to_bytes(),
                certificate.to_bytes(),
                sql(amount)?,
                own,
                preimage,
            ],
        )?;
        Ok(())
    }

    fn row(&self, c: &Connection, id: &ProposalId) -> Result<Option<Row>, Error> {
        type Raw = (
            [u8; 32],
            Vec<u8>,
            Vec<u8>,
            u32,
            bool,
            Option<[u8; 32]>,
            Option<String>,
        );
        let raw: Option<Raw> = c
            .query_row(
                "SELECT p.keyset, l.proposal, l.certificate, c.height, l.own, l.preimage, l.settled
                 FROM locks l JOIN proposals p ON p.id = l.id
                 JOIN checkpoints c ON c.commitment = l.checkpoint
                 WHERE l.id = ?1",
                [id.as_bytes()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((keyset, proposal, certificate, anchor, own, preimage, settled)) = raw else {
            return Ok(None);
        };
        let decoded = self.keyset_of(&keyset)?;
        let lock = Lock {
            proposal: Proposal::from_commitment_bytes(&proposal)?,
            certificate: Certificate::from_bytes(decoded, &certificate)?,
            settled: settled.as_deref().map(Settled::parse).transpose()?,
            preimage,
            own,
        };
        Ok(Some(Row {
            lock,
            keyset,
            anchor,
        }))
    }

    fn own_lock(&self, c: &Connection, hash: &[u8; 32]) -> Result<Option<Lock>, Error> {
        let id: Option<[u8; 32]> = c
            .query_row(
                "SELECT id FROM locks WHERE hash = ?1 AND own = 1",
                [hash],
                |r| r.get(0),
            )
            .optional()?;
        let Some(id) = id else { return Ok(None) };
        Ok(self
            .row(c, &ProposalId::from_bytes(id))?
            .map(|row| row.lock))
    }

    /// Fill the reserved `outputs` of lock `id` with their `issuances`,
    /// and book the hub's `income` of them.
    fn issue(
        &self,
        tx: &Transaction<'_>,
        id: &ProposalId,
        keyset: &licash::note::Keyset,
        outputs: &[Output],
        issuances: &[MintResponse],
        income: &[(u32, Note)],
    ) -> Result<(), Error> {
        for (output, issuance) in outputs.iter().zip(issuances) {
            let updated = tx.execute(
                "UPDATE issued SET boot = ?5, issuance = ?6
                 WHERE keyset = ?1 AND denom = ?2 AND blinded = ?3 AND proposal = ?4
                   AND boot IS NULL",
                params![
                    keyset.id(),
                    sql(output.denomination())?,
                    &output.blinded().0,
                    id.as_bytes(),
                    self.boot,
                    issuance.to_bytes(),
                ],
            )?;
            if updated != 1 {
                return Err(Error::Halted);
            }
        }
        for (position, note) in income {
            tx.execute(
                "INSERT INTO income (proposal, position, denom, note) VALUES (?1, ?2, ?3, ?4)",
                params![
                    id.as_bytes(),
                    position,
                    sql(note.message().denomination())?,
                    note.to_bytes()
                ],
            )?;
        }
        Ok(())
    }

    /// The stored issuances of `branch` of lock `id`, in output order.
    fn issued_branch(
        &self,
        c: &Connection,
        id: &ProposalId,
        keyset: &licash::note::Keyset,
        branch: Branch,
    ) -> Result<Vec<MintResponse>, Error> {
        let range = match branch {
            Branch::Pay => (0, i64::from(REFUND_INDEX)),
            Branch::Refund => (i64::from(REFUND_INDEX), i64::MAX),
        };
        let mut rows = c.prepare(
            "SELECT issuance FROM issued
             WHERE proposal = ?1 AND position >= ?2 AND position < ?3 AND issuance IS NOT NULL
             ORDER BY position",
        )?;
        let rows = rows.query_map(params![id.as_bytes(), range.0, range.1], |r| {
            r.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|bytes| Ok(MintResponse::from_bytes(keyset, &bytes?)?))
            .collect()
    }

    /// What `proposal`, a lock, moves, and the hub's outputs in each branch.
    pub(crate) fn lock_charge(&self, proposal: &Proposal) -> Result<Charge, Error> {
        let amount = proposal
            .inputs()
            .iter()
            .fold(0u64, |sum, m| sum.saturating_add(m.denomination()));
        let received = self.secrets()?.owner.scan_key().receive(proposal)?;
        let value = |branch: Branch| {
            received
                .iter()
                .filter(|r| r.branch == branch)
                .fold(0u64, |sum, r| {
                    sum.saturating_add(r.derivation.message().denomination())
                })
        };
        Ok(Charge {
            amount,
            pay: value(Branch::Pay),
            refund: value(Branch::Refund),
            received,
        })
    }
}

/// A lock's amount and the hub's outputs in it.
pub(crate) struct Charge {
    amount: u64,
    /// The value of the hub's outputs in each branch.
    pub(crate) pay: u64,
    refund: u64,
    received: Vec<licash::address::Received>,
}

impl Charge {
    pub(crate) fn count(&self, branch: Branch) -> usize {
        self.received.iter().filter(|r| r.branch == branch).count()
    }

    /// The hub's notes of `branch` as `open` makes them from the output's
    /// position and derivation, by their position in the ledger.
    fn received(
        &self,
        branch: Branch,
        open: impl Fn(usize, &licash::note::Derivation) -> Result<Note, licash::Error>,
    ) -> Result<Vec<(u32, Note)>, Error> {
        self.received
            .iter()
            .filter(|r| r.branch == branch)
            .map(|r| {
                let position = licash::address::index(branch, r.position as usize)?;
                Ok((position, open(r.position as usize, &r.derivation)?))
            })
            .collect()
    }
}

pub(crate) fn tip(c: &Connection) -> Result<Option<(u32, [u8; 32])>, Error> {
    Ok(c.query_row(
        "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?)
}

fn block_at(c: &Connection, height: u32) -> Result<Option<[u8; 32]>, Error> {
    Ok(
        c.query_row("SELECT hash FROM blocks WHERE height = ?1", [height], |r| {
            r.get(0)
        })
        .optional()?,
    )
}

fn checkpoint_of(c: &Connection, commitment: &[u8; 32]) -> Result<Option<Checkpoint>, Error> {
    let bytes: Option<Vec<u8>> = c
        .query_row(
            "SELECT bytes FROM checkpoints WHERE commitment = ?1",
            [commitment],
            |r| r.get(0),
        )
        .optional()?;
    bytes.map(|b| Ok(Checkpoint::from_bytes(&b)?)).transpose()
}

pub(crate) fn newest_checkpoint(c: &Connection) -> Result<Option<Checkpoint>, Error> {
    let bytes: Option<Vec<u8>> = c
        .query_row(
            "SELECT bytes FROM checkpoints ORDER BY height DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    bytes.map(|b| Ok(Checkpoint::from_bytes(&b)?)).transpose()
}

pub(crate) fn settled_of(c: &Connection, id: &ProposalId) -> Result<Option<Settled>, Error> {
    let settled: Option<String> = c.query_row(
        "SELECT settled FROM locks WHERE id = ?1",
        [id.as_bytes()],
        |r| r.get(0),
    )?;
    settled.as_deref().map(Settled::parse).transpose()
}

/// Whether an activation of the lock's hash was ever scanned between its
/// checkpoint and its expiry, on any branch.
/// Check that a lock of `terms` from the checkpoint at `anchor` expired at
/// depth unactivated on every block scanned.
fn expired_at_depth(c: &Connection, terms: &TimedTerms, anchor: u32) -> Result<(), Error> {
    let decided = terms.expiry().checked_add(terms.depth());
    let (top, _) = tip(c)?.ok_or(Error::Halted)?;
    if decided.is_none_or(|at| top < at) {
        return Err(Refusal::Unexpired.into());
    }
    // Every block from the checkpoint to the tip was scanned.
    let scanned: u32 = c.query_row(
        "SELECT count(*) FROM blocks WHERE height > ?1 AND height <= ?2",
        params![anchor, top],
        |r| r.get(0),
    )?;
    if scanned != top - anchor {
        return Err(Error::Halted);
    }
    if activated(c, terms, anchor)? {
        return Err(Refusal::Activated.into());
    }
    Ok(())
}

fn activated(c: &Connection, terms: &TimedTerms, anchor: u32) -> Result<bool, Error> {
    Ok(c.query_row(
        "SELECT 1 FROM activations WHERE hash = ?1 AND height > ?2 AND height < ?3 LIMIT 1",
        params![terms.hash(), anchor, terms.expiry()],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

fn lock_amount(c: &Connection, id: &ProposalId) -> Result<u64, Error> {
    Ok(c.query_row(
        "SELECT amount FROM locks WHERE id = ?1",
        [id.as_bytes()],
        |r| r.get::<_, i64>(0),
    )? as u64)
}
