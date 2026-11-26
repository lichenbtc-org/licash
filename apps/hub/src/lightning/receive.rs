//! Receipts: the hub's own notes, locked to a payee for a held invoice
//! paid, settled with the preimage that claims them.

use std::{
    collections::HashSet,
    path::Path,
    sync::{Mutex, MutexGuard},
};

use licash::spend::{ProposalId, TimedTerms};
use licash_api::{Code, Hex, Paying, Problem, Receive, ReceiveState, ReceiveStatus, Receiving};
use licash_hub::{Error, Forward, Forwarded, Refusal, Settled, LOCAL};
use licash_lightning::{expires, Description};
use licash_store::Kind;
use lightning_invoice::Bolt11Invoice;
use rusqlite::{params, Connection, OptionalExtension, Row};

use super::{node_down, now, refused, Gateway, HeldState, View};
use crate::{
    peer::{self, Recorded},
    Failure,
};

/// The component the receipts' table is, and its version.
pub(crate) const COMPONENT: &str = "lightning";
pub(crate) const VERSION: i64 = 2;

const SCHEMA: &str = "
-- Notes asked for over Lightning: recorded before their invoice exists,
-- locked once it is paid, and settled or canceled with their lock, which
-- is when they are done.
CREATE TABLE lightning_receipts (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    -- The receipt asked for, as JSON.
    body TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    msat INTEGER NOT NULL CHECK (msat >= 0),
    request TEXT,
    lock BLOB,
    state TEXT NOT NULL CHECK (state IN ('open', 'locked', 'settled', 'canceled')),
    created_at INTEGER NOT NULL,
    done_at INTEGER,
    -- Where it was asked from (crate::AdmissionSource), if known.
    source BLOB,
    CHECK ((state IN ('settled', 'canceled')) = (done_at IS NOT NULL))
) STRICT;
CREATE INDEX live_receipts ON lightning_receipts (state) WHERE state IN ('open', 'locked');
CREATE INDEX receipt_sources ON lightning_receipts (source) WHERE state = 'open';
";

/// Refused as one too many, if a new receipt asked from `source` would
/// be: past `most` open or locked, or past [`crate::PER_SOURCE`] asked
/// from `source` and not paid.
fn full(
    conn: &Connection,
    most: u32,
    source: Option<&crate::AdmissionSource>,
) -> Result<(), Failure> {
    let live: u32 = conn
        .query_row(
            "SELECT count(*) FROM lightning_receipts WHERE state IN ('open', 'locked')",
            [],
            |r| r.get(0),
        )
        .map_err(store_down)?;
    if live >= most {
        return Err(Failure(Problem::new(
            Code::Unavailable,
            "too many receipts under way: retry later",
        )));
    }
    let Some(source) = source else {
        return Ok(());
    };
    let unpaid: u32 = conn
        .query_row(
            "SELECT count(*) FROM lightning_receipts WHERE state = 'open' AND source = ?1",
            [source.as_bytes()],
            |r| r.get(0),
        )
        .map_err(store_down)?;
    if unpaid >= crate::PER_SOURCE {
        return Err(Failure(Problem::new(
            Code::Unavailable,
            "too many receipts asked from this source and not paid: retry later",
        )));
    }
    Ok(())
}

/// The gateway's receipts, in the hub's database.
pub(super) struct Store(Mutex<Connection>);

/// A receipt as recorded.
#[derive(Clone, Debug)]
pub(super) struct Receipt {
    hash: [u8; 32],
    body: String,
    amount: u64,
    msat: u64,
    request: Option<String>,
    lock: Option<ProposalId>,
    state: ReceiveState,
    created_at: u64,
}

impl Store {
    /// The receipts in the hub's database at `path`, made if the gateway
    /// never ran there.
    pub(super) fn open(path: &Path) -> anyhow::Result<Self> {
        let mut conn = licash_store::open(path, Kind::Hub)?;
        licash_store::component(&mut conn, COMPONENT, VERSION, SCHEMA)?;
        Ok(Self(Mutex::new(conn)))
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn get(&self, hash: &[u8; 32]) -> Result<Option<Receipt>, Failure> {
        let conn = self.conn();
        let receipt = conn
            .query_row(&format!("{RECEIPTS} WHERE hash = ?1"), [hash], receipt)
            .optional();
        receipt.map_err(store_down)
    }

    /// The receipts open or locked, oldest first.
    fn live(&self) -> Result<Vec<Receipt>, Failure> {
        let conn = self.conn();
        let live = conn
            .prepare(&format!(
                "{RECEIPTS} WHERE state IN ('open', 'locked') ORDER BY created_at, rowid"
            ))
            .and_then(|mut stmt| stmt.query_map([], receipt)?.collect());
        live.map_err(store_down)
    }

    /// Record a receipt asked from `source` unless one under its hash is.
    fn insert(
        &self,
        hash: &[u8; 32],
        body: &str,
        amount: u64,
        msat: u64,
        most: u32,
        source: Option<&crate::AdmissionSource>,
    ) -> Result<(), Failure> {
        let conn = self.conn();
        let known = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM lightning_receipts WHERE hash = ?1)",
                [hash],
                |r| r.get::<_, bool>(0),
            )
            .map_err(store_down)?;
        if known {
            return Ok(());
        }
        full(&conn, most, source)?;
        conn.execute(
            "INSERT INTO lightning_receipts (hash, body, amount, msat, state, created_at, source)
             VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6)",
            params![
                hash,
                body,
                sql(amount)?,
                sql(msat)?,
                sql(now())?,
                source.map(crate::AdmissionSource::as_bytes)
            ],
        )
        .map_err(store_down)?;
        Ok(())
    }

    /// Refused as one too many, if a new receipt asked from `source`
    /// would be: checked again as it is recorded.
    fn full(&self, most: u32, source: Option<&crate::AdmissionSource>) -> Result<(), Failure> {
        full(&self.conn(), most, source)
    }

    fn update(
        &self,
        hash: &[u8; 32],
        set: &str,
        value: &dyn rusqlite::ToSql,
    ) -> Result<(), Failure> {
        self.conn()
            .execute(
                &format!("UPDATE lightning_receipts SET {set} = ?2 WHERE hash = ?1"),
                params![hash, value],
            )
            .map(drop)
            .map_err(store_down)
    }

    fn finish(&self, hash: &[u8; 32], state: &str) -> Result<(), Failure> {
        self.conn()
            .execute(
                "UPDATE lightning_receipts SET state = ?2, done_at = ?3 WHERE hash = ?1",
                params![hash, state, sql(now())?],
            )
            .map(drop)
            .map_err(store_down)
    }
}

const RECEIPTS: &str =
    "SELECT hash, body, amount, msat, request, lock, state, created_at FROM lightning_receipts";

fn receipt(r: &Row<'_>) -> rusqlite::Result<Receipt> {
    let state = match r.get::<_, String>(6)?.as_str() {
        "open" => ReceiveState::Open,
        "locked" => ReceiveState::Locked,
        "settled" => ReceiveState::Settled,
        _ => ReceiveState::Canceled,
    };
    Ok(Receipt {
        hash: r.get(0)?,
        body: r.get(1)?,
        amount: r.get::<_, i64>(2)? as u64,
        msat: r.get::<_, i64>(3)? as u64,
        request: r.get(4)?,
        lock: r.get::<_, Option<[u8; 32]>>(5)?.map(ProposalId::from_bytes),
        state,
        created_at: r.get::<_, i64>(7)? as u64,
    })
}

fn sql(n: u64) -> Result<i64, Failure> {
    licash_store::sat(n).map_err(store_down)
}

fn store_down(e: rusqlite::Error) -> Failure {
    tracing::error!(error = %e, "the receipts cannot be read or written");
    Failure(Problem::new(
        Code::Unavailable,
        "the gateway cannot serve now",
    ))
}

impl Gateway {
    /// Whether a receipt is under `hash`, which no other lock of the hub's
    /// own notes may take.
    pub fn holds(&self, hash: &[u8; 32]) -> Result<bool, String> {
        Ok(self.recorded(hash)?.is_some())
    }

    /// Which of `hashes` the receipts in the hub's database at `db` hold, if
    /// the gateway ever ran there.
    pub fn holding(db: &Path, hashes: &[[u8; 32]]) -> anyhow::Result<HashSet<[u8; 32]>> {
        peer::recorded_in(
            db,
            COMPONENT,
            "SELECT 1 FROM lightning_receipts WHERE hash = ?1",
            hashes,
        )
    }

    /// The receipt under `hash`, if any, and the lock it backs once
    /// locked.
    pub fn recorded(&self, hash: &[u8; 32]) -> Result<Recorded, String> {
        match self.receipts.get(hash) {
            Ok(receipt) => Ok(receipt.map(|receipt| receipt.lock)),
            Err(Failure(problem)) => Err(problem.message),
        }
    }

    /// The invoice whose payment locks the hub's notes to the outputs of
    /// `body`: the same again for the same receipt.
    pub async fn receive(
        &self,
        body: &Receive,
        source: Option<&crate::AdmissionSource>,
    ) -> Result<Receiving, Failure> {
        let outputs = body.outputs()?;
        let (keyset, ephemeral, hash) = body.terms()?;
        if self.hub.keyset(&keyset).is_none() {
            return Err(Failure(Problem::new(Code::UnknownKeyset, "unknown keyset")));
        }
        let amount = outputs
            .iter()
            .try_fold(0u64, |sum, o| sum.checked_add(o.denomination()))
            .ok_or_else(|| Failure(Problem::invalid("the outputs overflow")))?;
        let c = &self.config;
        if outputs.is_empty() || amount < c.min_receive || amount > c.max_receive {
            return Err(refused("outside the amounts the gateway receives"));
        }
        let msat = body.asks(amount, &c.receive)?;
        let memo = body.checked_memo()?;
        let described = body.checked_description_hash()?;
        let canonical = Receive::new(&keyset, &ephemeral, &outputs, &hash)
            .with_memo(memo.clone())
            .with_lnurl(body.msat, described);
        let canonical = serde_json::to_string(&canonical).expect("a receipt serializes");
        let turn = self.peer.turn().await;
        if self.receipts.get(&hash)?.is_none() {
            // Refused before any work, if it would be at the end.
            self.receipts.full(c.max_receipts, source)?;
            if self.peer.recorded(&hash)?.is_some() || self.peer.holds_swap(&hash)? {
                return Err(refused("the hub holds this hash for another payment"));
            }
            if self
                .on_hub(move |hub| hub.own_lock_of(&hash))
                .await?
                .is_some()
            {
                return Err(refused("the hub locked notes under this hash before"));
            }
            self.receipts
                .insert(&hash, &canonical, amount, msat, c.max_receipts, source)?;
        }
        drop(turn);
        let receipt = self.receipts.get(&hash)?.ok_or_else(store_gone)?;
        if receipt.body != canonical {
            return Err(refused("another receipt under this hash"));
        }
        if let Some(request) = receipt.request {
            return Ok(Receiving { request });
        }
        let cltv = c.receive_cltv(self.hub.info().policy.timing.min_depth);
        let held = self
            .node
            .hold(
                hash,
                receipt.msat,
                cltv,
                c.invoice_expiry,
                match described {
                    Some(hash) => Some(Description::Hash(hash)),
                    None => memo.map(Description::Text),
                },
            )
            .await;
        let request = match held {
            Ok(request) => request,
            // Made by an attempt that did not hear back.
            Err(e) => match self.node.invoice(hash).await {
                Ok(Some(held)) => held.request,
                _ => return Err(node_down(e)),
            },
        };
        self.receipts.update(&hash, "request", &request)?;
        tracing::info!(hash = %hex::encode(hash), amount, msat, "invoice issued");
        Ok(Receiving { request })
    }

    /// Where the receipt under `hash` stands.
    pub fn receive_status(&self, hash: &[u8; 32]) -> Result<ReceiveStatus, Failure> {
        let receipt = self.receipts.get(hash)?.ok_or_else(|| {
            Failure(Problem::new(
                Code::UnknownLock,
                "no receipt under this hash",
            ))
        })?;
        Ok(ReceiveStatus {
            state: receipt.state,
            lock: receipt.lock.map(|id| Hex(id.as_bytes().to_vec())),
        })
    }

    /// Lock the receipts paid, and settle or cancel those decided.
    pub(super) async fn follow_receipts(&self) -> Result<(), Failure> {
        for receipt in self.receipts.live()? {
            if let Err(e) = self.follow_receipt(receipt.hash).await {
                let hash = hex::encode(receipt.hash);
                tracing::warn!(%hash, error = %e.0.message, "cannot follow a receipt");
            }
        }
        Ok(())
    }

    /// Act on the receipt under `hash`, as it stands once no one else
    /// does: backed by a lock paying it inside the hub, or by an HTLC.
    async fn follow_receipt(&self, hash: [u8; 32]) -> Result<(), Failure> {
        let _turn = self.receiving.lock().await;
        let Some(receipt) = self.receipts.get(&hash)? else {
            return Ok(());
        };
        // Inside the hub: a forward of the receipt's own invoice, for at
        // least its amount.
        let held: Option<Bolt11Invoice> = receipt.request.as_deref().and_then(|r| r.parse().ok());
        let least = receipt.msat.div_ceil(1000);
        let mut local = self
            .on_hub(move |hub| hub.live_forward(&hash))
            .await?
            .filter(|forward| forward.node == LOCAL);
        if let Some(forward) = local.take_if(|forward| {
            let paid: Option<Bolt11Invoice> = forward.request.parse().ok();
            paid.is_none() || paid != held || forward.amount < least
        }) {
            // Backing nothing: never taken for the receipt.
            if forward.state == Forwarded::Pending {
                self.give_up_local(&receipt, &forward, "not the receipt's invoice")
                    .await?;
            }
        }
        match (receipt.state, local) {
            (ReceiveState::Open, Some(forward)) => self.back_locally(&receipt, &forward).await,
            (ReceiveState::Open, None) => self.accept(&receipt).await,
            (ReceiveState::Locked, Some(forward)) => self.decide_local(&receipt, &forward).await,
            (ReceiveState::Locked, None) => self.decide(&receipt).await,
            // Decided meanwhile.
            _ => Ok(()),
        }
    }
}

/// Invoices of receipts paid inside the hub, for locks at it.
impl Gateway {
    /// Pay `invoice`, of the gateway's own node, for lock `id` expiring at
    /// `expiry`, inside the hub, at `view`: if it is a receipt's still
    /// open, which no HTLC paid yet, and the lock outlasts the receipt's
    /// own lock by its depth and the gateway's downtime. Anything else is
    /// refused, which refunds the lock.
    pub(super) async fn fulfill(
        &self,
        id: ProposalId,
        invoice: &Bolt11Invoice,
        view: &View,
        expiry: u32,
    ) -> Result<Paying, Failure> {
        let (hash, request) = (*invoice.payment_hash().as_ref(), invoice.to_string());
        // Refused as by the node, never as inside the hub: a forward by
        // LOCAL is only recorded once checked here, holding the receipts.
        let node = view.info.pubkey.clone();
        let turn = self.receiving.lock().await;
        let sat = match self.fulfillable(invoice, view, expiry).await? {
            Ok(sat) => sat,
            Err(why) => {
                drop(turn);
                return self.refuse(id, hash, request, node, why).await;
            }
        };
        let paid = request.clone();
        match self
            .on_hub(move |hub| hub.forward(&id, &hash, &paid, LOCAL, sat))
            .await
        {
            Ok(_) => {}
            Err(Error::Refused(Refusal::Fee { .. })) => {
                drop(turn);
                let why = "the lock pays less than the invoice";
                return self.refuse(id, hash, request, node, why).await;
            }
            Err(e) => return Err(e.into()),
        }
        tracing::info!(lock = %hex::encode(id.as_bytes()), hash = %hex::encode(hash), sat, "paying a receipt inside the hub");
        if let Some(receipt) = self.receipts.get(&hash)? {
            let forward = self.on_hub(move |hub| hub.forward_of(&id)).await?;
            if let Err(e) = self
                .back_locally(&receipt, &forward.ok_or_else(store_gone)?)
                .await
            {
                // Resumed by the receipts' follower.
                tracing::warn!(hash = %hex::encode(hash), error = %e.0.message, "cannot back a receipt yet");
            }
        }
        drop(turn);
        self.paying_of(id).await
    }

    /// Resume backing the receipt under `hash` with the lock paying it
    /// inside the hub, as its payer asks again.
    pub(super) async fn resume_local(&self, hash: [u8; 32]) {
        if let Err(e) = self.follow_receipt(hash).await {
            tracing::warn!(hash = %hex::encode(hash), error = %e.0.message, "cannot follow a receipt");
        }
    }

    /// The satoshis a lock pays for `invoice` inside the hub, or why it is
    /// not paid there: while holding the receipts.
    async fn fulfillable(
        &self,
        invoice: &Bolt11Invoice,
        view: &View,
        expiry: u32,
    ) -> Result<Result<u64, &'static str>, Failure> {
        let hash: [u8; 32] = *invoice.payment_hash().as_ref();
        let Some(msat) = invoice.amount_milli_satoshis().filter(|msat| *msat > 0) else {
            return Ok(Err("an invoice without an amount"));
        };
        if invoice.currency() != view.info.currency {
            return Ok(Err("an invoice of another network"));
        }
        if expires(invoice, 0) {
            return Ok(Err("the invoice expires"));
        }
        let receipt = self.receipts.get(&hash)?;
        let Some(receipt) = receipt.filter(|r| r.state == ReceiveState::Open) else {
            return Ok(Err("an invoice of the hub's own node it does not wait for"));
        };
        let held: Option<Bolt11Invoice> = receipt.request.as_deref().and_then(|r| r.parse().ok());
        if held.as_ref() != Some(invoice) {
            return Ok(Err("another invoice of the receipt"));
        }
        if self.room(view.tip, expiry).is_none() {
            return Ok(Err("the lock expires too soon for the invoice"));
        }
        if self
            .on_hub(move |hub| hub.own_lock_of(&hash))
            .await?
            .is_some()
        {
            return Ok(Err("the invoice is paid"));
        }
        match self.node.invoice(hash).await.map_err(node_down)? {
            Some(held) if held.state == HeldState::Open => Ok(Ok(msat.div_ceil(1000))),
            _ => Ok(Err("the invoice is paid or canceled")),
        }
    }

    /// The expiry of a receipt's own lock made at `tip`, if a lock paying
    /// it inside the hub, expiring at `expiry`, outlasts it, its refund at
    /// depth and the gateway's downtime: the hub learns the preimage that
    /// pays the payer's lock before it may be refunded.
    fn room(&self, tip: u32, expiry: u32) -> Option<u32> {
        let depth = self.hub.info().policy.timing.min_depth;
        let own = tip.checked_add(self.config.receive_blocks)?;
        let needed = [depth, self.config.downtime, 1]
            .iter()
            .try_fold(own, |at, b| at.checked_add(*b))?;
        (expiry >= needed).then_some(own)
    }

    /// Back open `receipt` with the lock of `forward`, which pays it inside
    /// the hub: its invoice canceled, so that no HTLC backs it too, then
    /// the hub's own notes locked to its payee. Each step is resumed until
    /// the lock no longer outlasts the receipt's, when the payer's lock is
    /// refunded.
    async fn back_locally(&self, receipt: &Receipt, forward: &Forward) -> Result<(), Failure> {
        let (hash, name) = (receipt.hash, hex::encode(receipt.hash));
        let body: Receive = serde_json::from_str(&receipt.body).map_err(|_| store_gone())?;
        let ((keyset, ephemeral, _), outputs) = (body.terms()?, body.outputs()?);
        let turn = self.peer.turn().await;
        // Made before the gateway stopped.
        if let Some(lock) = self.on_hub(move |hub| hub.own_lock_of(&hash)).await? {
            if lock.proposal.outputs() != outputs.as_slice() {
                let message = format!("The hash of receipt {name} is locked to other notes.");
                self.alert(format!("taken {name}"), message).await;
                drop(turn);
                return self
                    .give_up_local(
                        receipt,
                        forward,
                        "the receipt's hash is locked to other notes",
                    )
                    .await;
            }
            self.receipts
                .update(&hash, "lock", &lock.proposal.id().as_bytes())?;
            return self.finish(receipt, "locked");
        }
        let (scanned, checkpoint) = self
            .on_hub(|hub| Ok((hub.scanned()?, hub.checkpoint())))
            .await?;
        let (Some((tip, _)), Some(checkpoint)) = (scanned, checkpoint) else {
            return Ok(());
        };
        let Some(expiry) = self.room(tip, forward.expiry) else {
            drop(turn);
            return self
                .give_up_local(
                    receipt,
                    forward,
                    "the lock expires too soon for the invoice",
                )
                .await;
        };
        // No HTLC may back the receipt from here.
        if let Err(e) = self.node.cancel(hash).await {
            let held = self.node.invoice(hash).await.map_err(node_down)?;
            if held.is_some_and(|held| held.state != HeldState::Canceled) {
                return Err(node_down(e));
            }
        }
        let depth = self.hub.info().policy.timing.min_depth;
        let terms = TimedTerms::new(
            checkpoint.profile(),
            checkpoint.commitment(),
            expiry,
            depth,
            hash,
        )
        .map_err(|e| Failure(Problem::invalid(e.to_string())))?;
        let locked = self
            .on_hub(move |hub| hub.lock_own(&keyset, ephemeral, outputs, terms))
            .await;
        match locked {
            Ok(lock) => {
                let id = lock.proposal.id();
                self.receipts.update(&hash, "lock", &id.as_bytes())?;
                self.finish(receipt, "locked")?;
                tracing::info!(hash = %name, lock = %hex::encode(id.as_bytes()), expiry, "receipt locked inside the hub");
                Ok(())
            }
            Err(Error::Refused(Refusal::Unsynced | Refusal::NoChain | Refusal::Exists)) => Ok(()),
            Err(Error::Refused(refusal)) => {
                drop(turn);
                tracing::warn!(hash = %name, %refusal, "the hub refuses to lock a receipt");
                self.give_up_local(receipt, forward, "the hub cannot lock the receipt")
                    .await?;
                self.finish(receipt, "canceled")
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Refund the payer's lock of `forward`, which no longer backs
    /// `receipt`: the receipt is then followed as any, its invoice canceled
    /// or still open. Paid meanwhile by its preimage, which only the payee
    /// knew, the lock is the hub's: the receipt, open, is canceled, as it
    /// can no longer be backed.
    async fn give_up_local(
        &self,
        receipt: &Receipt,
        forward: &Forward,
        why: &'static str,
    ) -> Result<(), Failure> {
        let id = forward.lock;
        match self.on_hub(move |hub| hub.forward_failed(&id, why)).await {
            Ok(()) => {
                tracing::warn!(lock = %hex::encode(id.as_bytes()), why, "payment inside the hub given up, lock refunded");
                Ok(())
            }
            Err(Error::Refused(Refusal::Settled)) if receipt.state == ReceiveState::Open => {
                tracing::warn!(lock = %hex::encode(id.as_bytes()), why, "payment inside the hub paid but not backed");
                self.cancel(receipt).await
            }
            Err(Error::Refused(Refusal::Settled)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Pay or refund the payer's lock of `forward` as the own lock of
    /// locked `receipt`, which it backs, is settled. The payer's lock
    /// follows the preimage: once known, by the own lock's claim, an
    /// activation on Bitcoin or the payer's lock paid with it, it pays;
    /// never known, it is refunded with the own lock.
    async fn decide_local(&self, receipt: &Receipt, forward: &Forward) -> Result<(), Failure> {
        let id = receipt.lock.ok_or_else(store_gone)?;
        let payer = forward.lock;
        let lock = self.on_hub(move |hub| hub.locked(&id)).await?;
        let terms = lock.proposal.lock().ok_or_else(store_gone)?.terms().clone();
        let known = lock.preimage.or(match forward.state {
            Forwarded::Paid(preimage) => Some(preimage),
            _ => None,
        });
        let preimage = match (lock.settled, known) {
            (Some(Settled::Pay), Some(preimage)) => preimage,
            (Some(Settled::Pay), None) => return Err(store_gone()),
            (Some(Settled::Refund), known) => {
                return self.refund_local(receipt, payer, known).await
            }
            (None, Some(preimage)) => {
                match self.on_hub(move |hub| hub.settle(&id, &preimage)).await {
                    Ok(_) => preimage,
                    // Known too late for the own lock, which is refunded.
                    Err(Error::Refused(Refusal::LockExpired)) => {
                        return self.expire_local(receipt, &terms, payer, known).await
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            (None, None) => return self.expire_local(receipt, &terms, payer, None).await,
        };
        self.on_hub(move |hub| hub.forward_paid(&payer, &preimage))
            .await?;
        tracing::info!(hash = %hex::encode(receipt.hash), "receipt settled inside the hub");
        self.finish(receipt, "settled")
    }

    /// Refund the own lock of `receipt`, of `terms`, once expired at
    /// depth, then resolve the payer's lock as `known` says.
    async fn expire_local(
        &self,
        receipt: &Receipt,
        terms: &TimedTerms,
        payer: ProposalId,
        known: Option<[u8; 32]>,
    ) -> Result<(), Failure> {
        let id = receipt.lock.ok_or_else(store_gone)?;
        let tip = self
            .on_hub(|hub| hub.scanned())
            .await?
            .map_or(0, |(h, _)| h);
        if tip < terms.expiry().saturating_add(terms.depth()) {
            return Ok(());
        }
        match self.on_hub(move |hub| hub.refund(&id)).await {
            Ok(_) => self.refund_local(receipt, payer, known).await,
            Err(Error::Refused(Refusal::Unexpired | Refusal::Activated)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The own lock of `receipt` refunded unclaimed: so is the payer's,
    /// unless the preimage is `known`, which pays it.
    async fn refund_local(
        &self,
        receipt: &Receipt,
        payer: ProposalId,
        known: Option<[u8; 32]>,
    ) -> Result<(), Failure> {
        let resolved = match known {
            Some(preimage) => {
                self.on_hub(move |hub| hub.forward_paid(&payer, &preimage))
                    .await
            }
            None => {
                let why = "the payee did not claim the payment";
                match self
                    .on_hub(move |hub| hub.forward_failed(&payer, why))
                    .await
                {
                    // Paid by the preimage meanwhile.
                    Err(Error::Refused(Refusal::Settled)) => Ok(()),
                    resolved => resolved,
                }
            }
        };
        resolved?;
        tracing::info!(hash = %hex::encode(receipt.hash), "receipt canceled inside the hub");
        self.finish(receipt, "canceled")
    }
}

impl Gateway {
    /// Lock the hub's notes for `receipt` once its invoice is paid, if
    /// its HTLCs outlast the lock, its refund and the gateway's downtime
    /// by the node's hold delta.
    async fn accept(&self, receipt: &Receipt) -> Result<(), Failure> {
        let hash = receipt.hash;
        let name = hex::encode(hash);
        let Some(held) = self.node.invoice(hash).await.map_err(node_down)? else {
            // Never made, or lost by the node: given up once expired.
            let expired = receipt.created_at + self.config.invoice_expiry + self.config.grace;
            if now() > expired {
                self.finish(receipt, "canceled")?;
            }
            return Ok(());
        };
        match held.state {
            HeldState::Open => return Ok(()),
            HeldState::Canceled => return self.finish(receipt, "canceled"),
            HeldState::Settled => {
                let message = format!("The invoice of receipt {name} was settled unlocked.");
                self.alert(format!("settled {name}"), message).await;
                return Ok(());
            }
            HeldState::Accepted => {}
        }
        let body: Receive = serde_json::from_str(&receipt.body).map_err(|_| store_gone())?;
        let ((keyset, ephemeral, _), outputs) = (body.terms()?, body.outputs()?);
        let Some(least_expiry) = held.min_expiry else {
            return Ok(());
        };
        let info = self.node.info().await.map_err(node_down)?;
        let c = &self.config;
        let depth = self.hub.info().policy.timing.min_depth;
        // The latest a lock may expire, its HTLCs outlasting it, its refund
        // and the gateway's downtime by the node's hold delta.
        let latest = [c.hold_delta, depth, c.downtime, 1]
            .iter()
            .try_fold(least_expiry, |at, b| at.checked_sub(*b));
        // Until the lock under the hash is recorded.
        let turn = self.peer.turn().await;
        // A lock made before the gateway stopped, or for a deposit under the
        // same hash, which backs it once the deposits recorded it: one
        // payment per lock.
        if let Some(lock) = self.on_hub(move |hub| hub.own_lock_of(&hash)).await? {
            let deposit = self.peer.recorded(&hash)? == Some(Some(lock.proposal.id()));
            if deposit || self.peer.swap_owns(&hash, &lock.proposal.id())? {
                drop(turn);
                let owner = if deposit { "a deposit" } else { "a swap" };
                let message = format!(
                    "The hash of receipt {name} is locked for {owner}: its invoice is canceled."
                );
                self.alert(format!("taken {name}"), message).await;
                return self.cancel(receipt).await;
            }
            let expiry = lock
                .proposal
                .lock()
                .ok_or_else(store_gone)?
                .terms()
                .expiry();
            if lock.proposal.outputs() != outputs.as_slice()
                || latest.is_none_or(|latest| expiry > latest)
            {
                let message = format!(
                    "The hash of receipt {name} is locked to other notes, or for longer than its \
                     HTLCs last."
                );
                self.alert(format!("taken {name}"), message).await;
                return Ok(());
            }
            self.receipts
                .update(&hash, "lock", &lock.proposal.id().as_bytes())?;
            return self.finish(receipt, "locked");
        }
        let (scanned, checkpoint) = self
            .on_hub(|hub| Ok((hub.scanned()?, hub.checkpoint())))
            .await?;
        let (Some((tip, _)), Some(checkpoint)) = (scanned, checkpoint) else {
            return Ok(());
        };
        let expiry = tip.max(info.height).saturating_add(c.receive_blocks);
        if latest.is_none_or(|latest| expiry > latest) {
            drop(turn);
            tracing::warn!(hash = %name, least_expiry, expiry, "HTLCs expire too soon");
            return self.cancel(receipt).await;
        }
        let terms = TimedTerms::new(
            checkpoint.profile(),
            checkpoint.commitment(),
            expiry,
            depth,
            hash,
        )
        .map_err(|e| Failure(Problem::invalid(e.to_string())))?;
        let locked = self
            .on_hub(move |hub| hub.lock_own(&keyset, ephemeral, outputs, terms))
            .await;
        match locked {
            Ok(lock) => {
                let id = lock.proposal.id();
                self.receipts.update(&hash, "lock", &id.as_bytes())?;
                self.finish(receipt, "locked")?;
                tracing::info!(hash = %name, lock = %hex::encode(id.as_bytes()), expiry, "receipt locked");
                Ok(())
            }
            // Retried: the hub catches up, or adopts its lock above.
            Err(Error::Refused(Refusal::Unsynced | Refusal::NoChain | Refusal::Exists)) => Ok(()),
            Err(Error::Refused(refusal)) => {
                drop(turn);
                tracing::warn!(hash = %name, %refusal, "the hub refuses to lock a receipt");
                self.cancel(receipt).await
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Settle the invoice of locked `receipt` once its lock paid, or
    /// cancel it once its lock is refunded, which the gateway asks for
    /// once the lock expired at depth.
    async fn decide(&self, receipt: &Receipt) -> Result<(), Failure> {
        let id = receipt.lock.ok_or_else(store_gone)?;
        let name = hex::encode(receipt.hash);
        let lock = self.on_hub(move |hub| hub.locked(&id)).await?;
        let terms = lock.proposal.lock().ok_or_else(store_gone)?.terms().clone();
        match (lock.settled, lock.preimage) {
            (Some(Settled::Refund), _) => self.cancel(receipt).await,
            (Some(Settled::Pay), Some(preimage)) => self.settle_invoice(receipt, preimage).await,
            // Activated on Bitcoin: the lock pays.
            (None, Some(preimage)) => {
                self.on_hub(move |hub| hub.settle(&id, &preimage)).await?;
                self.settle_invoice(receipt, preimage).await
            }
            (None, None) => {
                let tip = self
                    .on_hub(|hub| hub.scanned())
                    .await?
                    .map_or(0, |(h, _)| h);
                let decided = terms.expiry().saturating_add(terms.depth());
                if tip < decided {
                    return Ok(());
                }
                match self.on_hub(move |hub| hub.refund(&id)).await {
                    Ok(_) => self.cancel(receipt).await,
                    Err(Error::Refused(Refusal::Unexpired | Refusal::Activated)) => Ok(()),
                    Err(e) => {
                        if tip >= decided.saturating_add(self.config.downtime) {
                            let message = format!(
                                "The lock of receipt {name} is unrefunded past block {decided}: \
                                 its invoice may be canceled before."
                            );
                            self.alert(format!("unrefunded {name}"), message).await;
                        }
                        Err(e.into())
                    }
                }
            }
            (Some(Settled::Pay), None) => Err(store_gone()),
        }
    }

    async fn settle_invoice(&self, receipt: &Receipt, preimage: [u8; 32]) -> Result<(), Failure> {
        let settled = self.node.settle(preimage).await;
        let state = match settled {
            Ok(()) => HeldState::Settled,
            Err(e) => match self.node.invoice(receipt.hash).await {
                Ok(Some(held)) => held.state,
                _ => return Err(node_down(e)),
            },
        };
        match state {
            HeldState::Settled => {
                tracing::info!(hash = %hex::encode(receipt.hash), "receipt settled");
                self.finish(receipt, "settled")
            }
            HeldState::Canceled => {
                let name = hex::encode(receipt.hash);
                let message = format!(
                    "The invoice of receipt {name} was canceled after its lock paid: the hub \
                     lost {}.",
                    licash_notify::sat(receipt.amount)
                );
                self.alert(format!("lost {name}"), message).await;
                self.finish(receipt, "canceled")
            }
            _ => Ok(()),
        }
    }

    async fn cancel(&self, receipt: &Receipt) -> Result<(), Failure> {
        if let Err(e) = self.node.cancel(receipt.hash).await {
            let held = self.node.invoice(receipt.hash).await.map_err(node_down)?;
            if held.is_none_or(|held| held.state != HeldState::Canceled) {
                return Err(node_down(e));
            }
        }
        tracing::info!(hash = %hex::encode(receipt.hash), "receipt canceled");
        self.finish(receipt, "canceled")
    }

    fn finish(&self, receipt: &Receipt, state: &str) -> Result<(), Failure> {
        if state == "locked" {
            return self.receipts.update(&receipt.hash, "state", &state);
        }
        self.receipts.finish(&receipt.hash, state)
    }
}

/// The receipts do not read as written.
fn store_gone() -> Failure {
    tracing::error!("a receipt does not read as written");
    Failure(Problem::new(
        Code::Unavailable,
        "the gateway cannot serve now",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_admission_is_atomic_and_never_blocks_existing_obligations() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::testing::hub_file(dir.path());
        let store = std::sync::Arc::new(Store::open(&path).unwrap());
        let admitted = std::thread::scope(|scope| {
            let requests: Vec<_> = (0u8..32)
                .map(|n| {
                    let store = store.clone();
                    scope.spawn(move || (n, store.insert(&[n; 32], "{}", 5, 5000, 2, None).is_ok()))
                })
                .collect();
            requests
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|(_, accepted)| *accepted)
                .map(|(n, _)| n)
                .collect::<Vec<_>>()
        });
        assert_eq!(admitted.len(), 2);
        // Lowering the limit does not discard old receipts or prevent retries.
        store
            .insert(&[admitted[0]; 32], "{}", 5, 5000, 1, None)
            .unwrap();
        store
            .update(&[admitted[0]; 32], "state", &"locked")
            .unwrap();
        assert_eq!(store.live().unwrap().len(), 2);
        assert!(store.insert(&[99; 32], "{}", 5, 5000, 2, None).is_err());
        store.finish(&[admitted[0]; 32], "settled").unwrap();
        store.insert(&[99; 32], "{}", 5, 5000, 2, None).unwrap();
        drop(store);
        assert_eq!(Store::open(&path).unwrap().live().unwrap().len(), 2);
    }

    /// From one address only so many receipts are asked and not paid: from
    /// another address, or once one is paid, more.
    #[test]
    fn receipts_asked_and_not_paid_from_one_source_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::hub_file(dir.path())).unwrap();
        let ip = |s: &str| crate::AdmissionSource::of_ip(s.parse().unwrap());
        let (one, other) = (ip("127.0.0.1"), ip("127.0.0.2"));
        let insert = |n: u8, source: Option<&crate::AdmissionSource>| {
            store.insert(&[n; 32], "{}", 5, 5000, 1024, source)
        };
        for n in 0..crate::PER_SOURCE as u8 {
            insert(n, Some(&one)).unwrap();
        }
        let refused = insert(100, Some(&one)).unwrap_err().0;
        assert_eq!(refused.code, Code::Unavailable);
        assert!(refused.message.contains("source"), "{refused:?}");
        // One recorded, asked again: the same.
        insert(2, Some(&one)).unwrap();
        insert(100, Some(&other)).unwrap();
        insert(101, None).unwrap();
        store.update(&[0; 32], "state", &"locked").unwrap();
        insert(102, Some(&one)).unwrap();
    }

    #[test]
    fn the_receipts_are_kept_across_a_reopening_and_refused_where_not_the_hubs() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::testing::hub_file(dir.path());
        let store = Store::open(&path).unwrap();
        store.insert(&[1; 32], "{}", 5, 6000, 1024, None).unwrap();
        store
            .insert(&[1; 32], "{\"other\":1}", 7, 8000, 1024, None)
            .unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        let receipt = store.get(&[1; 32]).unwrap().unwrap();
        assert_eq!(
            (receipt.body.as_str(), receipt.amount, receipt.msat),
            ("{}", 5, 6000)
        );
        assert_eq!(receipt.state, ReceiveState::Open);
        assert_eq!(store.live().unwrap().len(), 1);
        store.finish(&[1; 32], "canceled").unwrap();
        assert!(store.live().unwrap().is_empty());
        drop(store);

        let other = dir.path().join("other.sqlite");
        let conn = Connection::open(&other).unwrap();
        conn.execute_batch("CREATE TABLE t (x INTEGER)").unwrap();
        drop(conn);
        assert!(Store::open(&other).is_err());
        // Tables of a version this gateway does not read.
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE schema_versions SET version = ?1 WHERE component = 'lightning'",
            [VERSION + 1],
        )
        .unwrap();
        drop(conn);
        assert!(Store::open(&path).is_err());
    }
}
