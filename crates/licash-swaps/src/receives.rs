//! Receipts over Lightning for wallets that ask ([`Provider::receive`]):
//! a payer pays a held invoice of the provider's node, under the wallet's
//! hash, and the provider pays the amount on as a lock of its notes to the
//! wallet at a hub it swaps at, under that hash. The wallet claims the lock
//! with its preimage, which the hub shows the provider, who settles the
//! invoice with it. Unclaimed, the lock is refunded once expired and the
//! invoice canceled, the payment failing back to its payer: nothing is
//! taken on trust, as with a hub's own receipts, but the provider links the
//! receipts of one wallet, paid to one address.
//!
//! The lock expires early enough for the provider to learn the preimage
//! before the payer's HTLCs do, should the hub keep it: by forcing it out
//! on Bitcoin with the lock's refund request ([`crate::Config::lead`]), then
//! settling with [`SETTLE_MARGIN`] blocks left, as donations do. The
//! invoice's final CLTV delta leaves room for that and for the wallet to
//! claim ([`RECEIVE_BLOCKS`]).
//!
//! The invoice is canceled only while the provider's own records show it
//! locked nothing, or its lock refunded or refused: a lock expired, neither
//! paid nor refunded, may yet be paid, so the operator is alerted instead.
//!
//! Receipts live in tables of their own, made in the provider's file once
//! it first takes them: a file of an older provider opens as it was.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, PoisonError},
};

use licash::address::Address;
use licash_api::{
    swaps::{ReceiveRequest, Receives},
    Fee, Problem, ReceiveState, ReceiveStatus, Receiving,
};
use licash_lightning::{Description, Held, HeldState, Node};
use licash_wallet::{LockState, Transport};
use rusqlite::{params, Connection, OptionalExtension};

use crate::{declined, now, store, unavailable, Error, Hold, Provider, MIN_ROOM, SETTLE_MARGIN};

/// Blocks the provider's lock lives at most past the payer's HTLCs'
/// arrival: the wallet's time to claim it, within its hub's window.
pub const RECEIVE_BLOCKS: u32 = 12;

/// Blocks the node's and the hub's heights may differ by.
const TIP_SLACK: u32 = 3;

/// Seconds a receipt's invoice is payable for.
pub const RECEIVE_EXPIRY: u64 = 600;

/// Seconds after which a receipt recorded but never made an invoice of is
/// given up: the wallet never had it.
const UNMADE_AFTER: i64 = 60;

/// The component the receipts' tables are, and its version.
pub(crate) const COMPONENT: &str = "provider_receives";
const VERSION: i64 = 1;

const SCHEMA: &str = "
-- Receipts over Lightning for wallets (`crate::receives`). Each is a held
-- invoice of the provider's node under the wallet's `hash`, asking `sat`,
-- recorded before the node makes it, then its `request`. Once paid, the
-- provider locks `amount` to `address` at hub `hub` (its URL) expiring at
-- `expiry`, recorded before it locks, then its `lock`. The wallet's claim
-- shows the `preimage`, which settles the invoice. `state` is open (not
-- paid, or the lock not certified yet), locked, paid (the preimage known,
-- not settled yet), settled, canceled or lost (paid on and not settled).
CREATE TABLE provider_receives (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    hub TEXT NOT NULL,
    address BLOB NOT NULL,
    amount INTEGER NOT NULL CHECK (amount > 0),
    sat INTEGER NOT NULL CHECK (sat >= amount),
    memo TEXT,
    request TEXT,
    expiry INTEGER,
    lock BLOB CHECK (lock IS NULL OR length(lock) = 32),
    preimage BLOB CHECK (preimage IS NULL OR length(preimage) = 32),
    state TEXT NOT NULL
        CHECK (state IN ('open', 'locked', 'paid', 'settled', 'canceled', 'lost')),
    reason TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE INDEX provider_receives_state ON provider_receives (state);
";

/// Under way: the invoice open or held, or its preimage not settled with.
const UNDER_WAY: &str = "state IN ('open', 'locked', 'paid')";

/// What the provider takes receipts on, as its operator set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveTerms {
    /// Its fee on the amount, asked on top: the hub's fee on the lock
    /// comes out of it.
    pub fee: Fee,
    /// The least and the most received at once, in satoshis.
    pub min: u64,
    pub max: u64,
    /// The most receipts under way at once.
    pub max_open: u64,
}

impl Default for ReceiveTerms {
    fn default() -> Self {
        Self {
            fee: Fee {
                base: 2,
                ppm: 5_000,
            },
            min: 100,
            max: 1_000_000,
            max_open: 100,
        }
    }
}

/// Where a receipt stands at the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptState {
    Open,
    Locked,
    Paid,
    Settled,
    Canceled,
    Lost,
}

impl ReceiptState {
    fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Paid => "paid",
            Self::Settled => "settled",
            Self::Canceled => "canceled",
            Self::Lost => "lost",
        }
    }

    fn of(name: &str) -> Self {
        match name {
            "locked" => Self::Locked,
            "paid" => Self::Paid,
            "settled" => Self::Settled,
            "canceled" => Self::Canceled,
            "lost" => Self::Lost,
            _ => Self::Open,
        }
    }
}

/// A receipt as the provider recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub hash: [u8; 32],
    /// The hub's URL, as the provider's wallet knows it.
    pub hub: String,
    pub address: Vec<u8>,
    /// What it locks to the wallet.
    pub amount: u64,
    /// What its invoice asks: `amount` and the provider's fee.
    pub sat: u64,
    pub memo: Option<String>,
    pub request: Option<String>,
    /// Its lock's expiry, recorded before locking.
    pub expiry: Option<u32>,
    pub lock: Option<[u8; 32]>,
    preimage: Option<[u8; 32]>,
    pub state: ReceiptState,
    pub reason: Option<String>,
    pub created_at: i64,
}

impl Receipt {
    /// Where it stands, as its wallet is told: paid on once the preimage
    /// is out, whether settled or lost to the provider.
    fn status(&self) -> ReceiveStatus {
        let state = match self.state {
            ReceiptState::Open => ReceiveState::Open,
            ReceiptState::Locked => ReceiveState::Locked,
            ReceiptState::Paid | ReceiptState::Settled | ReceiptState::Lost => {
                ReceiveState::Settled
            }
            ReceiptState::Canceled => ReceiveState::Canceled,
        };
        let lock = match state {
            ReceiveState::Locked | ReceiveState::Settled => self.lock,
            _ => None,
        };
        ReceiveStatus {
            state,
            lock: lock.map(|l| licash_api::Hex(l.to_vec())),
        }
    }
}

const RECEIPTS: &str = "SELECT hash, hub, address, amount, sat, memo, request, expiry, lock,
    preimage, state, reason, created_at FROM provider_receives";

fn receipt_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<Receipt> {
    Ok(Receipt {
        hash: r.get(0)?,
        hub: r.get(1)?,
        address: r.get(2)?,
        amount: r.get::<_, i64>(3)? as u64,
        sat: r.get::<_, i64>(4)? as u64,
        memo: r.get(5)?,
        request: r.get(6)?,
        expiry: r.get(7)?,
        lock: r.get(8)?,
        preimage: r.get(9)?,
        state: ReceiptState::of(&r.get::<_, String>(10)?),
        reason: r.get(11)?,
        created_at: r.get(12)?,
    })
}

/// Whether the receipts' tables are in the provider's file.
pub(crate) fn kept(c: &Connection) -> Result<bool, Error> {
    Ok(licash_store::component_version(c, COMPONENT)
        .map_err(store::setup)?
        .is_some())
}

/// Whether a receipt was recorded under `hash`, in the file of `c`.
pub(crate) fn holds_hash(c: &Connection, hash: &[u8; 32]) -> Result<bool, Error> {
    if !kept(c)? {
        return Ok(false);
    }
    Ok(
        c.prepare("SELECT 1 FROM provider_receives WHERE hash = ?1")?
            .exists([hash])?,
    )
}

/// What receipts not locked yet will lock at hub `url`, in the file of `c`.
pub(crate) fn reserved(c: &Connection, url: &str) -> Result<u64, Error> {
    if !kept(c)? {
        return Ok(0);
    }
    Ok(c.query_row(
        "SELECT coalesce(sum(amount), 0) FROM provider_receives
         WHERE hub = ?1 AND state = 'open' AND lock IS NULL",
        [url],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

/// What a provider takes receipts on, and through which node.
pub(crate) struct Taker {
    node: Arc<dyn Node>,
    terms: ReceiveTerms,
    /// What the operator was alerted of, once each.
    alerted: Mutex<HashSet<String>>,
}

/// Receipts over Lightning taken.
impl<T: Transport> Provider<T> {
    /// Take receipts over Lightning on `terms`, through `node`: the
    /// provider takes none otherwise. Its tables are made in its file if
    /// missing. Not of the hub of an [`crate::Issuer`].
    pub fn take_receives(
        mut self,
        node: Arc<dyn Node>,
        terms: ReceiveTerms,
    ) -> Result<Self, Error> {
        if self.issuer.is_some() {
            return Err(Error::Setup(
                "a hub providing swaps takes receipts through its own gateway".into(),
            ));
        }
        if terms.min == 0 || terms.min > terms.max || terms.max_open == 0 {
            return Err(Error::Setup(
                "receipts of at least 1 sat, at most the largest, and some under way at once"
                    .into(),
            ));
        }
        self.store.write(|tx| {
            licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA).map_err(store::setup)
        })?;
        self.receives = Some(Taker {
            node,
            terms,
            alerted: Mutex::default(),
        });
        Ok(self)
    }

    /// The receipts it takes, as its info tells wallets: none if it takes
    /// none.
    pub fn receive_terms(&self) -> Option<Receives> {
        self.receives.as_ref().map(|t| Receives {
            fee: t.terms.fee,
            min: t.terms.min,
            max: t.terms.max,
        })
    }

    /// Receipts under way. Each needs the node, and the provider following
    /// it.
    pub fn open_receives(&self) -> Result<u64, Error> {
        self.store.read(|c| {
            if !kept(c)? {
                return Ok(0);
            }
            Ok(c.query_row(
                &format!("SELECT count(*) FROM provider_receives WHERE {UNDER_WAY}"),
                [],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
    }

    /// The receipt under `hash`, if one is.
    pub fn receipt(&self, hash: &[u8; 32]) -> Result<Option<Receipt>, Error> {
        self.store.read(|c| {
            if !kept(c)? {
                return Ok(None);
            }
            Ok(
                c.query_row(&format!("{RECEIPTS} WHERE hash = ?1"), [hash], receipt_of)
                    .optional()?,
            )
        })
    }

    /// Where the receipt under `hash` stands, as its wallet is told.
    pub fn receive_status(&self, hash: &[u8; 32]) -> Result<Option<ReceiveStatus>, Error> {
        Ok(self.receipt(hash)?.map(|r| r.status()))
    }

    /// The invoice of the receipt `request` asks for, recorded before the
    /// node makes it; the same invoice if asked before. Declined unless the
    /// provider swaps at the hub, holds enough there beside what it is to
    /// lock, and the hash is the receipt's alone.
    pub async fn receive(&self, request: &ReceiveRequest) -> Result<Receiving, Problem> {
        let taker = self
            .receives
            .as_ref()
            .ok_or_else(|| declined("the provider takes no receipts over Lightning"))?;
        let hash = request.hash()?;
        let memo = request.checked_memo()?;
        let committed = request.checked_description_hash()?;
        let terms = &taker.terms;
        let offered = Receives {
            fee: terms.fee,
            min: terms.min,
            max: terms.max,
        };
        let sat = request.asks_under(&offered)?;
        if let Some(receipt) = self.receipt(&hash).map_err(unavailable)? {
            return self.receipt_again(&receipt, request, sat, committed);
        }
        if !(terms.min..=terms.max).contains(&request.amount) {
            return Err(Problem::invalid(format!(
                "receipts of {} to {} sat",
                terms.min, terms.max
            )));
        }
        // As the hubs last said of themselves: the request reaches none.
        let hubs = self.wallet.hubs().map_err(unavailable)?;
        if hubs.iter().any(|(_, info)| info.address == request.address) {
            return Err(Problem::invalid("a hub's address is not a wallet's"));
        }
        let Some((url, locks)) = hubs
            .iter()
            .find(|(_, info)| info.address == request.hub)
            .and_then(|(url, info)| Some((url.clone(), info.locks.clone()?)))
        else {
            return Err(declined("no receipts at this hub"));
        };
        let Some(lead) = self.config.lead(&locks) else {
            return Err(declined("no receipts at this hub now"));
        };
        let at = now();
        let max_open = i64::try_from(terms.max_open).unwrap_or(i64::MAX);
        {
            let _taking = self.taking.lock().unwrap_or_else(PoisonError::into_inner);
            let free = self
                .stock()
                .map_err(unavailable)?
                .into_iter()
                .find(|s| s.url == url)
                .map_or(0, |s| s.free);
            if free < request.amount {
                return Err(declined("the provider holds too little at this hub now"));
            }
            let taken = self
                .store
                .write(|tx| {
                    let other = tx
                        .prepare("SELECT 1 FROM provider_swaps WHERE hash = ?1")?
                        .exists([hash])?
                        || tx
                            .prepare("SELECT 1 FROM provider_donations WHERE hash = ?1")?
                            .exists([hash])?;
                    if other {
                        return Ok(Some(declined("a hash taken before")));
                    }
                    let open: i64 = tx.query_row(
                        &format!("SELECT count(*) FROM provider_receives WHERE {UNDER_WAY}"),
                        [],
                        |r| r.get(0),
                    )?;
                    if open >= max_open {
                        return Ok(Some(unavailable(
                            "too many receipts under way: try again later",
                        )));
                    }
                    tx.execute(
                        "INSERT INTO provider_receives (hash, hub, address, amount, sat, memo,
                            state, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7, ?7)",
                        params![
                            hash,
                            url,
                            request.address.to_bytes(),
                            store::sat(request.amount)?,
                            store::sat(sat)?,
                            memo,
                            at
                        ],
                    )?;
                    Ok(None)
                })
                .map_err(unavailable)?;
            if let Some(refused) = taken {
                return Err(refused);
            }
        }
        let cltv = SETTLE_MARGIN
            .saturating_add(lead)
            .saturating_add(RECEIVE_BLOCKS)
            .saturating_add(TIP_SLACK);
        let made = taker
            .node
            .hold(
                hash,
                sat.saturating_mul(1000),
                cltv,
                RECEIVE_EXPIRY,
                committed
                    .map(Description::Hash)
                    .or(memo.map(Description::Text)),
            )
            .await;
        let request_text = match made {
            Ok(made) => made,
            Err(e) => {
                tracing::warn!(hash = %hex::encode(hash), error = %e, "no invoice for a receipt");
                self.finish_receipt(&hash, ReceiptState::Canceled, "the node made no invoice")
                    .map_err(unavailable)?;
                return Err(unavailable(format!("the Lightning node: {e}")));
            }
        };
        self.store
            .write(|tx| {
                tx.execute(
                    "UPDATE provider_receives SET request = ?2, updated_at = ?3 WHERE hash = ?1",
                    params![hash, request_text, now()],
                )?;
                Ok(())
            })
            .map_err(unavailable)?;
        tracing::info!(hash = %hex::encode(hash), %url, amount = request.amount, sat, cltv, "receipt invoice made");
        Ok(Receiving {
            request: request_text,
        })
    }

    /// The receipt `receipt` asked for again: its invoice, if the same,
    /// asking `sat` and committing to `committed`.
    fn receipt_again(
        &self,
        receipt: &Receipt,
        request: &ReceiveRequest,
        sat: u64,
        committed: Option<[u8; 32]>,
    ) -> Result<Receiving, Problem> {
        let hubs = self.wallet.hubs().map_err(unavailable)?;
        let hub = hubs
            .iter()
            .find(|(url, _)| *url == receipt.hub)
            .map(|(_, info)| info.address);
        let same = hub == Some(request.hub)
            && receipt.address == request.address.to_bytes()
            && receipt.amount == request.amount
            // Its fee as it was then, unless the wallet named what it asks.
            && request.asks.is_none_or(|_| receipt.sat == sat)
            && receipt.memo == request.memo
            && receipt.request.as_deref().is_none_or(|r| commits(r) == committed);
        if !same {
            return Err(declined("another receipt under this hash"));
        }
        match (&receipt.request, receipt.state) {
            (_, ReceiptState::Canceled) => Err(declined(format!(
                "the receipt was canceled: {}",
                receipt.reason.as_deref().unwrap_or("")
            ))),
            (Some(request), _) => Ok(Receiving {
                request: request.clone(),
            }),
            (None, _) => Err(unavailable("its invoice is being made: ask again")),
        }
    }

    /// Take every receipt under way on, as the provider's node and wallet
    /// know it. The receipts that could not move now, by hash and why;
    /// `node` if the node did not answer.
    pub async fn follow_receives(&self) -> Result<Vec<(String, String)>, Error> {
        let Some(taker) = &self.receives else {
            return Ok(Vec::new());
        };
        let open: Vec<[u8; 32]> = self.store.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT hash FROM provider_receives WHERE {UNDER_WAY} ORDER BY created_at, rowid"
            ))?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut pending = Vec::new();
        if open.is_empty() {
            return Ok(pending);
        }
        let tip = match taker.node.info().await {
            Ok(info) => info.height,
            Err(e) => {
                tracing::warn!(error = %e, "the Lightning node does not answer");
                pending.push(("node".to_owned(), e));
                return Ok(pending);
            }
        };
        for hash in open {
            let Some(_hold) = Hold::take(&self.busy, hash) else {
                continue;
            };
            if let Err(e) = self.follow_receipt(taker, &hash, tip).await {
                tracing::warn!(hash = %hex::encode(hash), "receipt pending: {e}");
                pending.push((hex::encode(hash), e.to_string()));
            }
        }
        Ok(pending)
    }

    /// Act on the receipt `hash` under way at height `tip` of the node.
    async fn follow_receipt(&self, taker: &Taker, hash: &[u8; 32], tip: u32) -> Result<(), Error> {
        let Some(receipt) = self.receipt(hash)? else {
            return Ok(());
        };
        if receipt.state == ReceiptState::Paid {
            return self.settle_receipt(taker, &receipt).await;
        }
        let held = taker.node.invoice(*hash).await.map_err(Error::Lightning)?;
        let age = now() - receipt.created_at;
        let tried = receipt.expiry.is_some() || receipt.lock.is_some();
        let Some(held) = held else {
            if tried {
                let message = format!(
                    "Receipt {} locked notes, but the Lightning node knows no invoice of it: \
                     resolve it by hand.",
                    hex::encode(hash)
                );
                return self.alert_receipt(
                    taker,
                    format!("unknown {}", hex::encode(hash)),
                    &message,
                );
            }
            if receipt.request.is_some() || age > UNMADE_AFTER {
                return self.finish_receipt(hash, ReceiptState::Canceled, "unknown to the node");
            }
            return Ok(());
        };
        match held.state {
            HeldState::Open => {
                let unmade = receipt.request.is_none() && age > UNMADE_AFTER;
                let expired =
                    age > i64::try_from(RECEIVE_EXPIRY).unwrap_or(i64::MAX) + UNMADE_AFTER;
                if !tried && (unmade || expired) {
                    self.cancel_receipt(taker, hash, "not paid in time").await?;
                }
                Ok(())
            }
            HeldState::Accepted => self.accepted_receipt(taker, &receipt, &held, tip).await,
            // Settled by the provider alone, with the preimage it learned.
            HeldState::Settled => self.finish_receipt(hash, ReceiptState::Settled, "paid"),
            HeldState::Canceled => {
                if !tried {
                    return self.finish_receipt(hash, ReceiptState::Canceled, "canceled");
                }
                match self.lock_state(&receipt).await? {
                    Some(LockState::Refunded | LockState::Abandoned(_)) | None => {
                        self.finish_receipt(hash, ReceiptState::Canceled, "canceled")
                    }
                    Some(LockState::Paid(_)) => {
                        self.lost_receipt(taker, hash, "its invoice was canceled after paying it")
                    }
                    Some(_) => {
                        let message = format!(
                            "The invoice of receipt {} was canceled while the provider's lock \
                             of it stands: resolve it by hand.",
                            hex::encode(hash)
                        );
                        self.alert_receipt(
                            taker,
                            format!("canceled {}", hex::encode(hash)),
                            &message,
                        )
                    }
                }
            }
        }
    }

    /// The receipt's HTLCs held: lock its amount to the wallet, then follow
    /// that lock to the preimage, or to its refund.
    async fn accepted_receipt(
        &self,
        taker: &Taker,
        receipt: &Receipt,
        held: &Held,
        tip: u32,
    ) -> Result<(), Error> {
        let hash = &receipt.hash;
        let settle_by = held.min_expiry.unwrap_or(0).saturating_sub(SETTLE_MARGIN);
        let lock = match (receipt.lock, receipt.expiry) {
            (Some(lock), _) => lock,
            (None, None) => {
                let Some(expiry) = self.receipt_expiry(receipt, settle_by, tip)? else {
                    return self
                        .cancel_receipt(taker, hash, "its payment expires too soon to lock")
                        .await;
                };
                // Recorded before locking: a lock made, then the provider
                // stopped, is looked for, never made again blindly.
                self.store.write(|tx| {
                    tx.execute(
                        "UPDATE provider_receives SET expiry = ?2, updated_at = ?3
                         WHERE hash = ?1 AND expiry IS NULL",
                        params![hash, expiry, now()],
                    )?;
                    Ok(())
                })?;
                return self.lock_receipt(taker, receipt, expiry).await;
            }
            (None, Some(expiry)) => {
                let locks = self.wallet.locks()?;
                let found = locks
                    .iter()
                    .find(|l| l.hub == receipt.hub && l.hash == receipt.hash);
                match found {
                    Some(found) => {
                        let lock = crate::lock_id(&found.id)?;
                        self.set_receipt_lock(hash, &lock)?;
                        lock
                    }
                    // Stopped before the wallet recorded a lock: none made.
                    None => return self.lock_receipt(taker, receipt, expiry).await,
                }
            }
        };
        let state = match self.wallet.follow_lock(&hex::encode(lock)).await {
            Ok(lock) => lock.state,
            Err(licash_wallet::Error::Abandoned { reason, .. }) => LockState::Abandoned(reason),
            Err(e) => {
                if let licash_wallet::Error::Refused { .. } = e {
                    let record = self
                        .wallet
                        .lock_record(&licash::spend::ProposalId::from_bytes(lock))?;
                    if let LockState::Abandoned(reason) = record.state {
                        let why = format!("its hub refused the lock: {reason}");
                        return self.cancel_receipt(taker, hash, &why).await;
                    }
                }
                self.check_withheld_receipt(taker, receipt, &lock, settle_by)?;
                return Err(e.into());
            }
        };
        match state {
            LockState::Requested => Ok(()),
            LockState::Locked => {
                if receipt.state == ReceiptState::Open {
                    self.finish_receipt(hash, ReceiptState::Locked, "locked")?;
                    tracing::info!(hash = %hex::encode(hash), lock = %hex::encode(lock), "receipt locked");
                }
                self.check_withheld_receipt(taker, receipt, &lock, settle_by)
            }
            LockState::Paid(preimage) => {
                self.store.write(|tx| {
                    tx.execute(
                        "UPDATE provider_receives SET preimage = ?2, state = 'paid', updated_at = ?3
                         WHERE hash = ?1",
                        params![hash, preimage, now()],
                    )?;
                    Ok(())
                })?;
                let receipt = self.receipt(hash)?.expect("recorded");
                self.settle_receipt(taker, &receipt).await
            }
            LockState::Refunded => {
                self.cancel_receipt(taker, hash, "its lock was refunded: never claimed")
                    .await
            }
            LockState::Abandoned(reason) => {
                let why = format!("its hub refused the lock: {reason}");
                self.cancel_receipt(taker, hash, &why).await
            }
            _ => Ok(()),
        }
    }

    /// The expiry of the receipt's lock, to settle by `settle_by`, at the
    /// node's `tip`: the preimage forced out on Bitcoin in time should the
    /// hub keep it, within the hub's window. None if too soon to lock.
    fn receipt_expiry(
        &self,
        receipt: &Receipt,
        settle_by: u32,
        tip: u32,
    ) -> Result<Option<u32>, Error> {
        let hubs = self.wallet.hubs()?;
        let Some(locks) = hubs
            .iter()
            .find(|(url, _)| *url == receipt.hub)
            .and_then(|(_, info)| info.locks.as_ref())
        else {
            return Ok(None);
        };
        let Some(lead) = self.config.lead(locks) else {
            return Ok(None);
        };
        let latest = locks
            .latest_expiry(locks.min_depth.max(1))
            .map_err(|p| Error::Setup(p.message))?;
        let expiry = settle_by.saturating_sub(lead).min(latest);
        let room = tip.max(locks.height).saturating_add(MIN_ROOM);
        Ok((expiry >= room).then_some(expiry))
    }

    /// Lock the receipt's amount to its wallet, expiring at `expiry`:
    /// cancel its invoice if nothing was locked.
    async fn lock_receipt(
        &self,
        taker: &Taker,
        receipt: &Receipt,
        expiry: u32,
    ) -> Result<(), Error> {
        let hash = &receipt.hash;
        let address = Address::from_bytes(&receipt.address).map_err(licash_wallet::Error::from)?;
        let mut tries = 0;
        let locked = loop {
            let locked = self
                .wallet
                .lock(&receipt.hub, &address, receipt.amount, *hash, Some(expiry))
                .await;
            match locked {
                Err(licash_wallet::Error::NoteTaken) if tries < 3 => tries += 1,
                locked => break locked,
            }
        };
        match locked {
            Ok(lock) => {
                let id = crate::lock_id(&lock.id)?;
                self.set_receipt_lock(hash, &id)?;
                if lock.state == LockState::Locked {
                    self.finish_receipt(hash, ReceiptState::Locked, "locked")?;
                }
                tracing::info!(hash = %hex::encode(hash), lock = %lock.id, expiry, "receipt locked");
                Ok(())
            }
            // Recorded, its outcome unknown: followed next time.
            Err(licash_wallet::Error::Pending { id, reason }) => {
                tracing::warn!(hash = %hex::encode(hash), %id, reason, "receipt lock pending");
                self.set_receipt_lock(hash, &crate::lock_id(&id)?)
            }
            Err(e) => {
                self.cancel_receipt(taker, hash, &format!("not locked: {e}"))
                    .await
            }
        }
    }

    /// The state of the receipt's lock as the wallet recorded it, if one.
    async fn lock_state(&self, receipt: &Receipt) -> Result<Option<LockState>, Error> {
        let lock = match receipt.lock {
            Some(lock) => lock,
            None => {
                let locks = self.wallet.locks()?;
                let found = locks
                    .iter()
                    .find(|l| l.hub == receipt.hub && l.hash == receipt.hash);
                match found {
                    Some(found) => crate::lock_id(&found.id)?,
                    None => return Ok(None),
                }
            }
        };
        let record = self
            .wallet
            .lock_record(&licash::spend::ProposalId::from_bytes(lock))?;
        Ok(Some(record.state))
    }

    /// Alert the operator, once, if the receipt's certified `lock` expired
    /// long enough ago for its hub to refund it plainly, neither paid nor
    /// refunded: the hub may keep the preimage the wallet revealed to it.
    /// The invoice is never canceled then.
    fn check_withheld_receipt(
        &self,
        taker: &Taker,
        receipt: &Receipt,
        lock: &[u8; 32],
        settle_by: u32,
    ) -> Result<(), Error> {
        let Some(expiry) = receipt.expiry else {
            return Ok(());
        };
        let hubs = self.wallet.hubs()?;
        let locks = hubs
            .iter()
            .find(|(url, _)| *url == receipt.hub)
            .and_then(|(_, info)| info.locks.as_ref());
        // A hub that follows no chain now says nothing of when it refunds:
        // the operator is told early rather than late.
        let (depth, reaction, height) = locks.map_or((1, 0, u32::MAX), |l| {
            (l.min_depth.max(1), l.reaction, l.height)
        });
        if height < expiry.saturating_add(depth).saturating_add(reaction) {
            return Ok(());
        }
        let message = format!(
            "Hub {} has neither paid nor refunded the provider's lock {} of receipt {}, expired \
             at {expiry}: it may keep the preimage. Request the lock's refund on Bitcoin, \
             confirmed after height {} and by height {}, for the hub to publish the preimage, \
             and settle the invoice with it by height {settle_by}.",
            receipt.hub,
            hex::encode(lock),
            hex::encode(receipt.hash),
            expiry.saturating_add(depth),
            expiry.saturating_add(self.config.confirm),
        );
        self.alert_receipt(
            taker,
            format!("withheld {}", hex::encode(receipt.hash)),
            &message,
        )
    }

    async fn settle_receipt(&self, taker: &Taker, receipt: &Receipt) -> Result<(), Error> {
        let hash = &receipt.hash;
        let preimage = receipt.preimage.expect("paid on it");
        if let Err(e) = taker.node.settle(preimage).await {
            let held = taker.node.invoice(*hash).await.map_err(Error::Lightning)?;
            match held.map(|h| h.state) {
                Some(HeldState::Settled) => {}
                Some(HeldState::Canceled) | None => {
                    return self.lost_receipt(
                        taker,
                        hash,
                        "its invoice was canceled after paying it",
                    )
                }
                _ => return Err(Error::Lightning(e)),
            }
        }
        tracing::info!(hash = %hex::encode(hash), amount = receipt.amount, sat = receipt.sat, "receipt settled");
        self.finish_receipt(hash, ReceiptState::Settled, "paid")
    }

    /// Cancel the receipt's invoice: called only once nothing was locked,
    /// or the lock was refunded or refused.
    async fn cancel_receipt(&self, taker: &Taker, hash: &[u8; 32], why: &str) -> Result<(), Error> {
        if let Err(e) = taker.node.cancel(*hash).await {
            let held = taker.node.invoice(*hash).await.map_err(Error::Lightning)?;
            if held.is_some_and(|h| h.state != HeldState::Canceled) {
                return Err(Error::Lightning(e));
            }
        }
        tracing::info!(hash = %hex::encode(hash), why, "receipt canceled");
        self.finish_receipt(hash, ReceiptState::Canceled, why)
    }

    fn lost_receipt(&self, taker: &Taker, hash: &[u8; 32], why: &str) -> Result<(), Error> {
        let name = hex::encode(hash);
        let message = format!("Receipt {name} is lost: {why}. Resolve it by hand.");
        self.alert_receipt(taker, format!("lost {name}"), &message)?;
        self.finish_receipt(hash, ReceiptState::Lost, why)
    }

    fn alert_receipt(&self, taker: &Taker, what: String, message: &str) -> Result<(), Error> {
        let first = taker
            .alerted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(what);
        if first {
            tracing::error!("{message}");
            self.alert(message)?;
        }
        Ok(())
    }

    fn set_receipt_lock(&self, hash: &[u8; 32], lock: &[u8; 32]) -> Result<(), Error> {
        self.store.write(|tx| {
            tx.execute(
                "UPDATE provider_receives SET lock = ?2, updated_at = ?3
                 WHERE hash = ?1 AND lock IS NULL",
                params![hash, lock, now()],
            )?;
            Ok(())
        })
    }

    fn finish_receipt(&self, hash: &[u8; 32], state: ReceiptState, why: &str) -> Result<(), Error> {
        self.store.write(|tx| {
            tx.execute(
                "UPDATE provider_receives SET state = ?2, reason = ?3, updated_at = ?4
                 WHERE hash = ?1",
                params![hash, state.name(), why, now()],
            )?;
            Ok(())
        })
    }
}

/// The description hash the invoice `request` commits to, if any.
fn commits(request: &str) -> Option<[u8; 32]> {
    use bitcoin::hashes::Hash as _;
    let invoice: lightning_invoice::Bolt11Invoice = request.parse().ok()?;
    match invoice.description() {
        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(h) => Some(h.0.to_byte_array()),
        lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(_) => None,
    }
}
