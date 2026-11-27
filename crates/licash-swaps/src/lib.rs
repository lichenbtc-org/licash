//! A Licash swap provider: it swaps its notes at one hub for a client's
//! notes at another ([`licash_api::swaps`]), with a timed lock at each under
//! the client's hash, from its own [`Wallet`].
//!
//! A client locks the amount and the provider's fee to the provider at hub
//! `from`, then asks for the swap. The provider checks that lock as its hub
//! holds it, records the swap and locks the amount to the client at hub
//! `to`, expiring earlier. Once the client claimed that lock, revealing the
//! preimage, the provider claims the client's lock with it. Unclaimed, its
//! own lock is refunded once expired: either way the provider holds what it
//! held, or more, unless it claims too late ([`Stage::Lost`]).
//!
//! The client reveals the preimage to hub `to`, which issues the
//! provider's lock, and that hub can keep it from the provider. The
//! provider then obtains it only by requesting the lock's refund on
//! Bitcoin, which the hub voids only by publishing the preimage, within its
//! response window. So the provider's lock expires that window, the
//! request's confirmation ([`Config::confirm`]) and [`Config::margin`]
//! blocks before the client's at least ([`licash::route::Hop::forced_lead`]),
//! and the provider swaps only between hubs where that fits: hub `from`'s
//! window must be the longer. The provider makes no such request itself:
//! it alerts its operator with the deadline.
//!
//! The provider swaps between the hubs its wallet added. Each step is
//! recorded before the next is asked for, so a provider stopped at any
//! point takes its swaps on with [`Provider::step`]. What its operator is
//! told of is kept in order: [`Provider::events`].
//!
//! A provider may pay notes out on Bitcoin too ([`Provider::pay_out`]): it
//! takes payouts with [`Provider::take_payout`], locking a coin on chain
//! under the client's hash, and follows them with
//! [`Provider::follow_payouts`], given a view of the chain ([`Chain`]).
//!
//! A provider may pay Lightning invoices too ([`Provider::pay_lightning`]):
//! it takes them with [`Provider::take_invoice`], paying each from its own
//! node under the client's lock's hash, and follows them with
//! [`Provider::follow_invoices`]. The preimage the payment buys claims the
//! client's lock.
//!
//! A hub may be the provider of the swaps into it ([`Issuer`],
//! [`Provider::open_issuing`]): its lock there is of notes it issues
//! itself, and it keeps no preimage from itself, so its lock expires only
//! [`Config::own_lead`] blocks before the client's, between hubs of any
//! windows.

mod donations;
mod invoices;
mod issue;
mod payouts;
mod receives;
mod store;

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex, PoisonError},
};

use licash::{address::Address, route::Hop, spend::ProposalId};
use licash_api::{
    swaps::{self, Hub, Request, State},
    Code, Fee, Locks, Problem,
};
use licash_wallet::{LockState, Transport, Wallet};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

/// The receipts over Lightning, and apart the donations, one source may
/// have asked and not paid: the rest of `max_open` is left to others. A
/// source is opaque here, as the service resolves it per request (an onion
/// circuit, a client's address): one with many addresses is bounded by
/// `max_open` alone.
pub const PER_SOURCE: u32 = 8;

pub use donations::{
    Donation, DonationState, DonationTerms, INVOICE_CLTV, INVOICE_EXPIRY, METADATA, SETTLE_MARGIN,
    START_ROOM,
};
pub use invoices::MIN_SLACK;
pub use issue::Issuer;
use issue::{Issue, Issued};
pub use payouts::{Chain, PayoutLimits, NO_SHOW_VSIZE, PAYOUT_ROOM};
pub use receives::{Receipt, ReceiptState, ReceiveTerms, RECEIVE_BLOCKS, RECEIVE_EXPIRY};
use store::{now, Store};

/// Blocks a provider's lock leaves at least before it expires: for the
/// client to claim it, and for the provider to follow it.
pub const MIN_ROOM: u32 = licash_wallet::SWAP_ROOM;

/// Blocks to read a preimage the hub published on Bitcoin.
pub const DETECT: u32 = 1;

/// Why a provider call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The swaps file is missing, exists already or does not match.
    #[error("{0}")]
    Setup(String),
    #[error("swaps database: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error(transparent)]
    Wallet(#[from] licash_wallet::Error),
    /// The provider's own hub, issuing its locks ([`Issuer`]).
    #[error("its hub: {0}")]
    Hub(Problem),
    /// Its Lightning node ([`Provider::pay_lightning`]).
    #[error("its Lightning node: {0}")]
    Lightning(String),
}

/// What a provider swaps, and on what terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Its fee on the amount swapped, which the client pays on top.
    pub fee: Fee,
    /// The least and the most it swaps at once.
    pub min: u64,
    pub max: u64,
    /// Blocks to claim the client's lock once the provider holds the
    /// preimage.
    pub margin: u32,
    /// Blocks within which a refund request of the provider's lock
    /// confirms once it expired: the operator's time to make it, after the
    /// provider alerted it the hub keeps the preimage.
    #[serde(default = "Config::default_confirm")]
    pub confirm: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fee: Fee { base: 0, ppm: 2000 },
            min: 1_000,
            max: 1_000_000,
            margin: 12,
            confirm: Self::default_confirm(),
        }
    }
}

impl Config {
    fn default_confirm() -> u32 {
        36
    }

    /// Blocks by which the client's lock outlives the provider's at a hub
    /// of `locks` at least, if the provider may lock there: once its lock
    /// expires, the provider learns the hub keeps the preimage before the
    /// refund request is due, past the lock's expiry at depth, before
    /// which a refund is owed nothing on Bitcoin.
    pub fn lead(&self, locks: &Locks) -> Option<u32> {
        let seen = locks.min_depth.max(1).saturating_add(locks.reaction);
        if self.confirm <= seen {
            return None;
        }
        self.hop(locks).forced_lead()
    }

    /// Blocks by which the client's lock outlives the provider's at its
    /// own hub, of `locks`, at least: the hub shows the provider the
    /// preimage once the client claims, or once it is published on Bitcoin
    /// in time ([`Hop::lead`]).
    pub fn own_lead(&self, locks: &Locks) -> Option<u32> {
        self.hop(locks).lead()
    }

    fn hop(&self, locks: &Locks) -> Hop {
        Hop {
            window: locks.window,
            confirm: self.confirm,
            detect: DETECT,
            margin: self.margin,
            depth: locks.min_depth,
            reaction: locks.reaction,
        }
    }
}

/// Where a swap stands at the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Taken: the provider is locking.
    Accepted,
    /// Its lock is certified: the client claims it.
    Locked,
    /// The client claimed it: the provider claims the client's lock.
    Paid,
    Done,
    /// The client never claimed: the provider's lock was refunded.
    Refunded,
    /// The provider did not lock.
    Failed,
    /// The provider paid, but did not claim the client's lock in time.
    Lost,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Locked => "locked",
            Self::Paid => "paid",
            Self::Done => "done",
            Self::Refunded => "refunded",
            Self::Failed => "failed",
            Self::Lost => "lost",
        }
    }

    fn parse(name: &str) -> rusqlite::Result<Self> {
        Ok(match name {
            "accepted" => Self::Accepted,
            "locked" => Self::Locked,
            "paid" => Self::Paid,
            "done" => Self::Done,
            "refunded" => Self::Refunded,
            "failed" => Self::Failed,
            "lost" => Self::Lost,
            _ => return Err(rusqlite::Error::InvalidQuery),
        })
    }

    /// As the client is told: a swap lost to the provider is paid to the
    /// client.
    fn state(self) -> State {
        match self {
            Self::Accepted => State::Accepted,
            Self::Locked => State::Locked,
            Self::Paid => State::Paid,
            Self::Done | Self::Lost => State::Done,
            Self::Refunded => State::Refunded,
            Self::Failed => State::Failed,
        }
    }

    fn open(self) -> bool {
        matches!(self, Self::Accepted | Self::Locked | Self::Paid)
    }
}

/// A swap as the provider recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Record {
    /// The client's lock at `from`, in hex.
    pub id: String,
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    /// What the client's lock pays the provider.
    pub paid: u64,
    /// The provider's lock at `to`, once recorded, and its expiry.
    pub lock: Option<String>,
    pub expiry: u32,
    pub stage: Stage,
    pub reason: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A swap as its operator reads it once it ended: its record and what the
/// provider's lock at `to` paid that hub ([`Provider::outcome`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub record: Record,
    /// The hub's fee on the provider's lock at `to` once it paid, or its
    /// refund fee once refunded; none into the provider's own hub. Unknown
    /// while the lock is unsettled, and for a payout, whose miner fees go
    /// unrecorded. The wallet's unlinking is not counted against a swap.
    pub hub_fee: Option<u64>,
}

/// What the operator is told of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Notice {
    /// A swap of `amount` from hub `from` to hub `to` was taken, for `fee`.
    Accepted {
        id: String,
        amount: u64,
        fee: u64,
        from: String,
        to: String,
    },
    /// Both locks paid: the provider earned `fee`.
    Done { id: String, amount: u64, fee: u64 },
    /// The client never claimed: the provider's lock was refunded.
    Refunded { id: String, amount: u64 },
    /// The provider did not lock, and why.
    Failed { id: String, reason: String },
    /// The provider paid `amount` at hub `to` but did not claim the
    /// client's lock: lost.
    Lost {
        id: String,
        amount: u64,
        reason: String,
    },
    /// Something the operator should look at.
    Alert { message: String },
}

impl Notice {
    /// Its kind, as its [`Event`] names it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Accepted { .. } => "accepted",
            Self::Done { .. } => "done",
            Self::Refunded { .. } => "refunded",
            Self::Failed { .. } => "failed",
            Self::Lost { .. } => "lost",
            Self::Alert { .. } => "alert",
        }
    }
}

/// A [`Notice`] in the provider's outbox, in order of `seq`: its kind and
/// its JSON as stored, which a provider of another version may have
/// written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    /// Unix seconds.
    pub at: u64,
    pub kind: String,
    pub data: serde_json::Value,
}

impl Event {
    /// The notice, if this version knows it.
    pub fn notice(&self) -> Option<Notice> {
        serde_json::from_value(self.data.clone()).ok()
    }
}

/// Counts over the swaps, by stage, and the fees earned.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub open: u64,
    pub done: u64,
    pub refunded: u64,
    pub failed: u64,
    pub lost: u64,
    /// The fees of the swaps done.
    pub earned: u64,
    /// What the swaps lost cost.
    pub lost_amount: u64,
    /// The last event's `seq`.
    pub events: u64,
}

/// A swap as stored, to take it on.
struct Row {
    id: [u8; 32],
    hash: [u8; 32],
    from: String,
    to: String,
    address: Vec<u8>,
    amount: u64,
    fee: u64,
    paid: u64,
    /// The client's lock's expiry at `from`.
    expiry_from: u32,
    expiry: u32,
    lock: Option<[u8; 32]>,
    preimage: Option<[u8; 32]>,
    stage: Stage,
    reason: Option<String>,
    created_at: i64,
    updated_at: i64,
    /// A payout on Bitcoin, not a swap of notes.
    chain: bool,
    /// A swap into the provider's own hub, of notes it issues ([`Issuer`]).
    own: bool,
    /// An invoice paid over Lightning, not a swap of notes.
    lightning: bool,
}

impl Row {
    fn record(&self) -> Record {
        Record {
            id: hex::encode(self.id),
            hash: hex::encode(self.hash),
            from: self.from.clone(),
            to: self.to.clone(),
            amount: self.amount,
            fee: self.fee,
            paid: self.paid,
            lock: self.lock.map(hex::encode),
            expiry: self.expiry,
            stage: self.stage,
            reason: self.reason.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    fn swap(&self) -> swaps::Swap {
        swaps::Swap {
            id: licash_api::Hex(self.id.to_vec()),
            state: self.stage.state(),
            amount: self.amount,
            lock: self.lock.map(|l| licash_api::Hex(l.to_vec())),
            expiry: self.expiry,
            reason: self.reason.clone(),
        }
    }
}

const LAST_EVENT: &str = "SELECT coalesce(max(seq), 0) FROM provider_events";

const ROWS: &str = "SELECT id, hash, from_url, to_url, address, amount, fee, paid, expiry_height,
    lock, preimage, state, reason, created_at, updated_at, kind = 'chain', expiry_from_height,
    kind = 'own', kind = 'lightning'
    FROM provider_swaps";

fn row_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        id: r.get(0)?,
        hash: r.get(1)?,
        from: r.get(2)?,
        to: r.get(3)?,
        address: r.get(4)?,
        amount: r.get::<_, i64>(5)? as u64,
        fee: r.get::<_, i64>(6)? as u64,
        paid: r.get::<_, i64>(7)? as u64,
        expiry: r.get(8)?,
        lock: r.get(9)?,
        preimage: r.get(10)?,
        stage: Stage::parse(&r.get::<_, String>(11)?)?,
        reason: r.get(12)?,
        created_at: r.get(13)?,
        updated_at: r.get(14)?,
        chain: r.get(15)?,
        expiry_from: r.get(16)?,
        own: r.get(17)?,
        lightning: r.get(18)?,
    })
}

/// What the provider can lock at a hub, by URL and address.
struct Stock {
    url: String,
    address: Address,
    free: u64,
    /// [`Config::lead`] there.
    lead: Option<u32>,
}

/// A swap in hand, so that no other task takes it on meanwhile.
struct Hold<'a> {
    busy: &'a Mutex<HashSet<[u8; 32]>>,
    id: [u8; 32],
}

impl<'a> Hold<'a> {
    fn take(busy: &'a Mutex<HashSet<[u8; 32]>>, id: [u8; 32]) -> Option<Self> {
        let mut held = busy.lock().unwrap_or_else(PoisonError::into_inner);
        // Not `then_some`: a hold made only to be dropped would lock again,
        // and release the other task's.
        held.insert(id).then(|| Self { busy, id })
    }
}

impl Drop for Hold<'_> {
    fn drop(&mut self) {
        let mut held = self.busy.lock().unwrap_or_else(PoisonError::into_inner);
        held.remove(&self.id);
    }
}

pub(crate) fn declined(message: impl Into<String>) -> Problem {
    Problem::new(Code::Declined, message)
}

/// A problem of the provider's own, for the client to retry.
pub(crate) fn unavailable(e: impl std::fmt::Display) -> Problem {
    Problem::new(Code::Unavailable, e.to_string())
}

/// A client's request refused, as a wallet error says it.
pub(crate) fn refused(e: licash_wallet::Error) -> Problem {
    match e {
        licash_wallet::Error::Refused { hub, problem } => {
            declined(format!("hub {hub} refused: {}", problem.message))
        }
        licash_wallet::Error::PaysNothing => declined("the lock pays the provider nothing"),
        licash_wallet::Error::UnknownHub(hub) => declined(format!("no swaps at hub {hub}")),
        licash_wallet::Error::Invalid(why) => Problem::invalid(why),
        e => unavailable(e),
    }
}

/// A swap provider: its wallet, which holds its notes at each hub, its
/// swaps file and its [`Config`].
pub struct Provider<T: Transport> {
    wallet: Wallet<T>,
    store: Arc<Store>,
    config: Config,
    /// Swaps in hand, by the client's lock.
    busy: Mutex<HashSet<[u8; 32]>>,
    /// Held while one request is checked against what the provider holds
    /// and recorded.
    taking: Mutex<()>,
    /// The hubs the operator was told the provider holds too little at.
    short: Mutex<HashSet<String>>,
    /// Whether the operator was told its coins pay out too little.
    short_on_chain: std::sync::atomic::AtomicBool,
    /// What it pays out on Bitcoin, if it does.
    payouts: Option<swaps::Chain>,
    /// What payouts whose clients never claim may cost it, if bounded
    /// ([`Provider::limit_payouts`]).
    payout_limits: Option<payouts::PayoutLimits>,
    /// The rate it last paid a payout's coin at, by which
    /// [`payouts::PayoutLimits::fee_share`] bounds the least it pays out.
    payout_rate: Mutex<Option<bitcoin::FeeRate>>,
    /// The swaps whose hub the operator was told keeps the preimage.
    withheld: Mutex<HashSet<[u8; 32]>>,
    /// The swaps the operator was told the provider claims late.
    late: Mutex<HashSet<[u8; 32]>>,
    /// The provider's own hub, if it is one, which issues its locks there.
    issuer: Option<Arc<Issuer>>,
    /// The most it may come to hold at each hub, if limited
    /// ([`Provider::limit_intake`]).
    intake: Mutex<Option<HashMap<String, u64>>>,
    /// What it pays over Lightning, and through which node, if it does.
    lightning: Option<invoices::Payer>,
    /// Donations taken, if any ([`Provider::take_donations`]).
    donations: Option<donations::Receiver>,
    /// Receipts over Lightning taken, if any ([`Provider::take_receives`]).
    receives: Option<receives::Taker>,
}

/// The swaps into the provider's own hub under way, whose clients' locks
/// back the hub's: those the provider follows until it claimed them.
const OWN_UNDER_WAY: &str = "kind = 'own' AND state IN ('accepted', 'locked', 'paid')";

/// Which of `hashes` the provider in the wallet's file at `path`, if there
/// is one, holds swaps into its own hub under way of: the hub's locks under
/// them are backed by the clients' locks the provider claims. Read only,
/// beside the provider running on the file or without it.
pub fn backing_own(path: &Path, hashes: &[[u8; 32]]) -> Result<HashSet<[u8; 32]>, Error> {
    let mut found = HashSet::new();
    let Some(conn) = read_swaps(path)? else {
        return Ok(found);
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT 1 FROM provider_swaps WHERE hash = ?1 AND {OWN_UNDER_WAY}"
    ))?;
    for hash in hashes {
        if stmt.exists([hash])? {
            found.insert(*hash);
        }
    }
    Ok(found)
}

/// How many swaps into its own hub the provider in the wallet's file at
/// `path`, if there is one, has under way: the hub's locks for them are
/// backed once the provider claims the clients' locks. Read only, creating
/// and upgrading nothing.
pub fn own_under_way(path: &Path) -> Result<usize, Error> {
    let Some(conn) = read_swaps(path)? else {
        return Ok(0);
    };
    let count: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM provider_swaps WHERE {OWN_UNDER_WAY}"),
        [],
        |r| r.get(0),
    )?;
    Ok(usize::try_from(count).unwrap_or(usize::MAX))
}

/// The provider's tables in the wallet's file at `path`, read only: none
/// if there is no file, or the provider never made its tables in it.
fn read_swaps(path: &Path) -> Result<Option<rusqlite::Connection>, Error> {
    let Some(conn) =
        licash_store::inspect(path, licash_store::Kind::Wallet).map_err(store::setup)?
    else {
        return Ok(None);
    };
    match licash_store::component_version(&conn, store::COMPONENT).map_err(store::setup)? {
        Some(store::VERSION) => Ok(Some(conn)),
        Some(v) => Err(Error::Setup(format!(
            "swaps schema {v}, this version reads {}",
            store::VERSION
        ))),
        None => Ok(None),
    }
}

/// Any recorded swap, donation or receipt reserves its hash, even terminal or not
/// yet locked: a donation's invoice, public, must never back a receipt of
/// a gateway sharing the provider's node, whose notes its settling would
/// pay.
pub fn holds_hash(path: &Path, hash: &[u8; 32]) -> Result<bool, Error> {
    let Some(conn) = read_swaps(path)? else {
        return Ok(false);
    };
    let swap = conn
        .prepare("SELECT 1 FROM provider_swaps WHERE hash = ?1")?
        .exists([hash])?;
    let donation = conn
        .prepare("SELECT 1 FROM provider_donations WHERE hash = ?1")?
        .exists([hash])?;
    Ok(swap || donation || receives::holds_hash(&conn, hash)?)
}

/// A recorded lock id proves swap ownership. A reserved hash alone does
/// not: a gateway may need to recover its own lock after a crash.
pub fn owns_hash_lock(
    path: &Path,
    hash: &[u8; 32],
    lock: &licash::spend::ProposalId,
) -> Result<bool, Error> {
    let Some(conn) = read_swaps(path)? else {
        return Ok(false);
    };
    let owns = conn
        .prepare("SELECT 1 FROM provider_swaps WHERE hash = ?1 AND lock = ?2")?
        .exists(params![hash, lock.as_bytes()])?;
    Ok(owns)
}

/// Setup and what the provider says of itself.
impl<T: Transport> Provider<T> {
    /// A new provider on `wallet`: its tables made in the wallet's file,
    /// which holds them as one with the wallet's own.
    pub fn create(wallet: Wallet<T>, config: Config) -> Result<Self, Error> {
        Ok(Self::with(Self::created(&wallet)?, wallet, config, None))
    }

    /// The provider of `wallet`, whose file holds its tables. Refused while
    /// swaps into a hub's own notes are under way: only that hub takes them
    /// on ([`Provider::open_issuing`]).
    pub fn open(wallet: Wallet<T>, config: Config) -> Result<Self, Error> {
        let store = Store::open(wallet.path())?;
        let provider = Self::with(store, wallet, config, None);
        let open = provider.open_own()?;
        if open > 0 {
            return Err(Error::Setup(format!(
                "{open} swaps into a hub's own notes are under way in {}: only that hub takes \
                 them on",
                provider.wallet.path().display()
            )));
        }
        Ok(provider)
    }

    /// A new provider on `wallet` that is the hub of `issuer`.
    pub fn create_issuing(
        wallet: Wallet<T>,
        config: Config,
        issuer: Issuer,
    ) -> Result<Self, Error> {
        Ok(Self::with(
            Self::created(&wallet)?,
            wallet,
            config,
            Some(issuer),
        ))
    }

    /// The provider of `wallet` that is the hub of `issuer`.
    pub fn open_issuing(wallet: Wallet<T>, config: Config, issuer: Issuer) -> Result<Self, Error> {
        let store = Store::open(wallet.path())?;
        Ok(Self::with(store, wallet, config, Some(issuer)))
    }

    fn created(wallet: &Wallet<T>) -> Result<Store, Error> {
        let mut nostr = [0; 32];
        OsRng.fill_bytes(&mut nostr);
        Store::create(wallet.path(), &nostr)
    }

    fn with(store: Store, wallet: Wallet<T>, config: Config, issuer: Option<Issuer>) -> Self {
        Self {
            wallet,
            store: Arc::new(store),
            config,
            busy: Mutex::default(),
            taking: Mutex::default(),
            short: Mutex::default(),
            short_on_chain: Default::default(),
            payouts: None,
            payout_limits: None,
            payout_rate: Mutex::default(),
            withheld: Mutex::default(),
            late: Mutex::default(),
            issuer: issuer.map(Arc::new),
            intake: Mutex::default(),
            lightning: None,
            donations: None,
            receives: None,
        }
    }

    /// Swaps into the provider's own hub under way.
    fn open_own(&self) -> Result<u64, Error> {
        self.store.read(|c| {
            Ok(c.query_row(
                &format!("SELECT count(*) FROM provider_swaps WHERE {OWN_UNDER_WAY}"),
                [],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
    }

    /// The hub the provider is, if it is one.
    pub fn issuer(&self) -> Option<&Issuer> {
        self.issuer.as_deref()
    }

    /// Its wallet, which holds its notes at each hub.
    pub fn wallet(&self) -> &Wallet<T> {
        &self.wallet
    }

    /// What it charges and swaps.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The secret key the provider announces itself under on Nostr.
    pub fn nostr_secret(&self) -> Result<[u8; 32], Error> {
        self.store
            .read(|c| Ok(c.query_row("SELECT nostr FROM provider_meta", [], |r| r.get(0))?))
    }

    /// What the provider swaps now, as its hubs last said of themselves:
    /// at each hub that follows a chain, the most it can lock there and by
    /// how much the client's lock must outlive its own ([`Config::lead`]),
    /// nothing where it may not lock. The margin it gives for every hub, to
    /// clients that read no other, is the most of them.
    ///
    /// The hub of an [`Issuer`] locks at itself alone: as much as it may
    /// still take of the notes of a hub it swaps from, by
    /// [`Config::own_lead`].
    ///
    /// It reads the provider's files, and its hub's ledger: call it off
    /// the async runtime.
    pub fn info(&self) -> Result<swaps::Info, Error> {
        let hubs: Vec<Hub> = match &self.issuer {
            Some(issuer) => self.issuing(issuer)?,
            None => self
                .stock()?
                .into_iter()
                .map(|s| Hub {
                    address: s.address,
                    max: if s.lead.is_some() {
                        s.free.min(self.config.max)
                    } else {
                        0
                    },
                    margin: s.lead,
                })
                .collect(),
        };
        let margin = hubs
            .iter()
            .filter_map(|h| h.margin)
            .max()
            .unwrap_or(self.config.margin);
        Ok(swaps::Info {
            address: self.wallet.address(),
            fee: self.config.fee,
            min: self.config.min,
            max: self.config.max,
            margin,
            hubs,
            nostr: None,
            chain: self.chain_info()?,
            donations: self.donations(),
            receive: self.receive_terms(),
            lightning: self.lightning_terms().cloned(),
            features: (self.receive_terms().iter())
                .map(|_| swaps::FEATURE_RECEIVE_EXACT.to_owned())
                .collect(),
        })
    }

    /// At each hub that follows a chain, the most the provider can lock
    /// there: what it holds, less what the swaps it took will lock and the
    /// most the hub's fee comes to.
    fn stock(&self) -> Result<Vec<Stock>, Error> {
        let balance = self.wallet.balance()?;
        let mut stock = Vec::new();
        for (url, info) in self.wallet.hubs()? {
            let Some(locks) = &info.locks else {
                continue;
            };
            let available = balance
                .iter()
                .find(|b| b.hub == url)
                .map_or(0, |b| b.available);
            let free = available
                .saturating_sub(self.reserved(&url)?)
                .saturating_sub(info.fees.locking().at_most(available));
            let lead = self.config.lead(locks);
            stock.push(Stock {
                url,
                address: info.address,
                free,
                lead,
            });
        }
        Ok(stock)
    }

    /// The hubs of an issuing provider, its own first.
    fn issuing(&self, issuer: &Issuer) -> Result<Vec<Hub>, Error> {
        let own = issuer.info().map_err(Error::Hub)?;
        let (mut room, mut hubs) = (0, Vec::new());
        for (url, info) in self.wallet.hubs()? {
            if info.address == own.address {
                continue;
            }
            if self.source(issuer, &url)?.is_some() {
                room = room.max(self.room(&url)?.unwrap_or(u64::MAX));
            }
            hubs.push(Hub {
                address: info.address,
                max: 0,
                margin: None,
            });
        }
        let lead = own.locks.as_ref().and_then(|l| self.config.own_lead(l));
        let max = match lead {
            Some(_) => room.min(self.config.max),
            None => 0,
        };
        hubs.insert(
            0,
            Hub {
                address: own.address,
                max,
                margin: lead,
            },
        );
        Ok(hubs)
    }

    /// The most of hub `url`'s notes the issuing provider may hold, if it
    /// takes swaps from there, and every URL its wallet knows that hub by:
    /// a cap may name any of them, as may the swaps recorded from there.
    fn source(&self, issuer: &Issuer, url: &str) -> Result<Option<(u64, Vec<String>)>, Error> {
        let urls = self.wallet.hub_urls(url)?;
        let cap = urls.iter().find_map(|url| issuer.cap_of(url));
        Ok(cap.map(|cap| (cap, urls)))
    }

    /// Limit what the provider may come to hold at each hub, through the
    /// swaps and payouts it takes there, to `limits`, by the hub's URL as
    /// its wallet knows it ([`Wallet::hubs`]): none at a hub not named.
    /// None lifts the limit. As the contracts protecting its notes at each
    /// hub allow: what a hub holds back is lost unless a contract recovers
    /// it. Not limited until limited, which a provider required to be
    /// protected is before it serves; what it holds already stays, and
    /// what it pays out from there goes on.
    pub fn limit_intake(&self, limits: Option<HashMap<String, u64>>) {
        *self.intake.lock().unwrap_or_else(PoisonError::into_inner) = limits;
    }

    /// What [`Provider::limit_intake`] last set.
    pub fn intake(&self) -> Option<HashMap<String, u64>> {
        self.intake
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What the provider holds of the notes of the hub at `url`, by any
    /// URL its wallet knows it by, and is owed there by the clients of the
    /// swaps and payouts it took from there: what it would lose if the hub
    /// held them back.
    pub fn exposure(&self, url: &str) -> Result<u64, Error> {
        self.held(&self.wallet.hub_urls(url)?)
    }

    /// How much more of the notes of the hub at `url` the provider may
    /// take: within its issuer's cap of that hub's notes, if it issues, and
    /// within [`Provider::limit_intake`], beside what it holds and is owed
    /// there already. None if neither limits it.
    fn room(&self, url: &str) -> Result<Option<u64>, Error> {
        let urls = self.wallet.hub_urls(url)?;
        let mut most = (self.issuer.as_ref())
            .map(|issuer| urls.iter().find_map(|u| issuer.cap_of(u)).unwrap_or(0));
        let intake = self.intake.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(limits) = intake.as_ref() {
            let limit = urls.iter().find_map(|u| limits.get(u)).copied();
            let limit = limit.unwrap_or(0);
            most = Some(most.map_or(limit, |most| most.min(limit)));
        }
        drop(intake);
        match most {
            Some(most) => Ok(Some(most.saturating_sub(self.held(&urls)?))),
            None => Ok(None),
        }
    }

    /// Whether the provider may take `paid` more of the notes of the hub
    /// at `from` ([`Provider::room`]): declined if not. Called while
    /// [`Provider::taking`] is held, as what it holds and is owed there
    /// cannot grow between the check and the record.
    fn admit(&self, from: &str, paid: u64) -> Result<(), Problem> {
        match self.room(from).map_err(unavailable)? {
            Some(room) if paid > room => {
                let who = if self.issuer.is_some() {
                    "hub"
                } else {
                    "provider"
                };
                Err(declined(format!(
                    "the {who} takes no more of hub {from}'s notes now"
                )))
            }
            _ => Ok(()),
        }
    }

    /// What the provider holds of the notes of the hub at `urls`, and is
    /// owed there by the clients of the swaps and payouts under way it took
    /// from there.
    fn held(&self, urls: &[String]) -> Result<u64, Error> {
        let listed = serde_json::to_string(urls).map_err(|e| Error::Setup(e.to_string()))?;
        // Owed first: a swap claimed between the reads is counted twice,
        // never not at all.
        let owed = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT coalesce(sum(paid), 0) FROM provider_swaps
                 WHERE state IN ('accepted', 'locked', 'paid')
                    AND from_url IN (SELECT value FROM json_each(?1))",
                [listed],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })?;
        let holds = self
            .wallet
            .balance()?
            .iter()
            .filter(|b| urls.contains(&b.hub))
            .fold(0u64, |sum, b| {
                sum.saturating_add(b.available.saturating_add(b.pending))
            });
        Ok(holds.saturating_add(owed))
    }

    /// Alert the operator of each hub the provider can no longer swap to,
    /// holding less there than the least it swaps: once, until it holds
    /// enough again. The hubs it alerted of now: none of an issuing
    /// provider, which locks notes its hub issues.
    pub fn check_stock(&self) -> Result<Vec<String>, Error> {
        if self.issuer.is_some() {
            return Ok(Vec::new());
        }
        let stock = self.stock()?;
        let mut short = self.short.lock().unwrap_or_else(PoisonError::into_inner);
        let mut alerted = Vec::new();
        for Stock { url, free, .. } in stock {
            if free >= self.config.min {
                short.remove(&url);
            } else if !short.contains(&url) {
                self.alert(&format!(
                    "No swaps to {url} for now: the provider holds {} free there, less than \
                     the {} it swaps at least. Fund its account there.",
                    sat(free),
                    sat(self.config.min)
                ))?;
                short.insert(url.clone());
                alerted.push(url);
            }
        }
        Ok(alerted)
    }

    /// Alert the operator when the provider's coins on Bitcoin pay out
    /// less than the least payout it takes: once, until they pay enough
    /// again. Whether it alerted now: never if it pays nothing out on
    /// Bitcoin, or its wallet watches no chain yet.
    pub fn check_payouts(&self) -> Result<bool, Error> {
        use std::sync::atomic::Ordering;
        let Some(terms) = self.chain_info()? else {
            return Ok(false);
        };
        if terms.max >= terms.min {
            self.short_on_chain.store(false, Ordering::Relaxed);
            return Ok(false);
        }
        if self.short_on_chain.swap(true, Ordering::Relaxed) {
            return Ok(false);
        }
        self.alert(&format!(
            "No payouts on Bitcoin for now: the provider's coins pay out {} at most, \
             less than the {} it pays out at least. Send coins to its wallet.",
            sat(terms.max),
            sat(terms.min)
        ))?;
        Ok(true)
    }

    /// What the swaps accepted and the receipts paid, not locked yet,
    /// will lock at `url`.
    fn reserved(&self, url: &str) -> Result<u64, Error> {
        self.store.read(|c| {
            let swaps = c.query_row(
                "SELECT coalesce(sum(amount), 0) FROM provider_swaps
                 WHERE to_url = ?1 AND state = 'accepted'",
                [url],
                |r| r.get::<_, i64>(0),
            )? as u64;
            Ok(swaps.saturating_add(receives::reserved(c, url)?))
        })
    }
}

/// Swaps taken.
impl<T: Transport> Provider<T> {
    /// Take the swap `request` asks for, or answer where it stands if taken
    /// already. Declined unless the client's lock, as its hub holds it,
    /// pays the provider the amount and its fee, unsettled, and leaves the
    /// provider room to lock earlier at a hub where it holds enough.
    pub async fn take(&self, request: &Request) -> Result<swaps::Swap, Problem> {
        let id = request.lock()?;
        let key = *id.as_bytes();
        if let Some(row) = self.row(&key).map_err(unavailable)? {
            return self.again(&row, request);
        }
        let config = &self.config;
        if request.amount < config.min || request.amount > config.max {
            return Err(declined(format!(
                "swaps of {} to {}",
                config.min, config.max
            )));
        }
        let hubs = self.wallet.hubs().map_err(unavailable)?;
        let at = |address: &Address| {
            hubs.iter()
                .find(|(_, info)| info.address == *address)
                .map(|(url, _)| url.as_str())
        };
        // The hub of an issuer swaps into itself alone, from the hubs it
        // takes notes of.
        let own = match &self.issuer {
            Some(issuer) => Some((issuer, issuer.blocking(Issuer::info).await?)),
            None => None,
        };
        let (from, to) = match &own {
            Some((issuer, info)) if request.to == info.address && request.from != info.address => {
                (at(&request.from), Some(issuer.url()))
            }
            Some(_) => (None, None),
            None => (at(&request.from), at(&request.to)),
        };
        let (Some(from), Some(to)) = (from, to) else {
            return Err(declined("no swaps between these hubs"));
        };
        if from == to {
            return Err(declined("a swap is between two hubs"));
        }
        let own_address = own.as_ref().map(|(_, info)| info.address);
        if at(&request.address).is_some() || own_address == Some(request.address) {
            return Err(Problem::invalid("a hub's address is not a client's"));
        }
        if let Some((issuer, _)) = &own {
            if self.source(issuer, from).map_err(unavailable)?.is_none() {
                return Err(declined(format!("no swaps from hub {from}")));
            }
        }
        let Some(_hold) = Hold::take(&self.busy, key) else {
            return Err(unavailable("the swap is under way"));
        };
        let incoming = self
            .wallet
            .incoming(from, &hex::encode(key))
            .await
            .map_err(refused)?;
        let fee = config.fee.due(request.amount);
        let due = request.amount.saturating_add(fee);
        if incoming.amount < due {
            return Err(declined(format!(
                "the lock pays {}, the swap {due}",
                incoming.amount
            )));
        }
        if incoming.settled.is_some() || incoming.preimage.is_some() {
            return Err(declined("the lock is settled"));
        }
        let to_info = match own {
            Some((_, info)) => info,
            None => self.wallet.add_hub(to).await.map_err(refused)?,
        };
        let Some(locks) = to_info.locks.as_ref() else {
            return Err(declined(format!("hub {to} follows no chain")));
        };
        let lead = match own_address {
            Some(_) => config.own_lead(locks),
            None => config.lead(locks),
        };
        let Some(lead) = lead else {
            return Err(declined(format!(
                "no swaps to hub {to}: a refund request there confirms within {} blocks, \
                 before the provider sees the hub keep the preimage",
                config.confirm
            )));
        };
        let latest = locks
            .latest_expiry(locks.min_depth.max(1))
            .map_err(unavailable)?;
        let expiry = incoming.expiry.saturating_sub(lead).min(latest);
        let room = locks.height.max(incoming.height).saturating_add(MIN_ROOM);
        if expiry < room {
            return Err(declined(format!(
                "the lock expires at {}: too soon to lock at hub {to} {lead} blocks earlier",
                incoming.expiry
            )));
        }
        let terms = Terms {
            from,
            to,
            hash: incoming.hash,
            fee,
            paid: incoming.amount,
            expiry_from: incoming.expiry,
            expiry,
        };
        self.record(request, &key, &terms, &to_info, own_address.is_some())?;
        tracing::info!(id = %hex::encode(key), %from, %to, amount = request.amount, fee, expiry, "swap accepted");
        self.lock(&key).await.map_err(unavailable)?;
        Ok(self
            .row(&key)
            .map_err(unavailable)?
            .expect("recorded")
            .swap())
    }

    /// The swap `row` asked for again: where it stands, if it is the same.
    fn again(&self, row: &Row, request: &Request) -> Result<swaps::Swap, Problem> {
        let hubs = self.wallet.hubs().map_err(unavailable)?;
        let address = |url: &str| hubs.iter().find(|(u, _)| u == url).map(|(_, i)| i.address);
        let to = match &self.issuer {
            Some(issuer) if row.own => Some(issuer.address()),
            _ => address(&row.to),
        };
        let same = address(&row.from) == Some(request.from)
            && to == Some(request.to)
            && row.address == request.address.to_bytes()
            && row.amount == request.amount;
        if !same {
            return Err(declined("another swap of this lock"));
        }
        Ok(row.swap())
    }
}

/// What the provider checked of a client's lock, and the expiry of its own.
struct Terms<'a> {
    from: &'a str,
    to: &'a str,
    hash: [u8; 32],
    fee: u64,
    paid: u64,
    expiry_from: u32,
    expiry: u32,
}

/// Recording and locking.
impl<T: Transport> Provider<T> {
    /// Record the swap `request` asks for on `terms`, if the provider holds
    /// enough at hub `to` beside the swaps it has yet to lock there. Into
    /// its `own` hub, if it may yet take as many of hub `from`'s notes, its
    /// lock's ephemeral secret with it.
    fn record(
        &self,
        request: &Request,
        id: &[u8; 32],
        terms: &Terms<'_>,
        to_info: &licash_api::Info,
        own: bool,
    ) -> Result<(), Problem> {
        let _taking = self.taking.lock().unwrap_or_else(PoisonError::into_inner);
        self.admit(terms.from, terms.paid)?;
        // A hub issues its own lock: it pays from no stock of its notes.
        if !(own && self.issuer.is_some()) {
            let balance = self.wallet.balance().map_err(unavailable)?;
            let available = balance
                .iter()
                .find(|b| b.hub == terms.to)
                .map_or(0, |b| b.available);
            let reserved = self.reserved(terms.to).map_err(unavailable)?;
            let needed = reserved
                .saturating_add(request.amount)
                .saturating_add(to_info.fees.locking().at_most(available));
            if available < needed {
                return Err(declined(format!(
                    "the provider holds too little at hub {} now",
                    terms.to
                )));
            }
        }
        let notice = Notice::Accepted {
            id: hex::encode(id),
            amount: request.amount,
            fee: terms.fee,
            from: terms.from.to_owned(),
            to: terms.to.to_owned(),
        };
        let recorded = self.store.write(|tx| {
            let at = now();
            let inserted = tx.execute(
                "INSERT INTO provider_swaps (id, hash, from_url, to_url, address, amount, fee, paid,
                    expiry_from_height, expiry_height, state, created_at, updated_at, kind)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'accepted', ?11, ?11, ?12)
                 ON CONFLICT DO NOTHING",
                params![
                    id,
                    terms.hash,
                    terms.from,
                    terms.to,
                    request.address.to_bytes(),
                    store::sat(request.amount)?,
                    store::sat(terms.fee)?,
                    store::sat(terms.paid)?,
                    terms.expiry_from,
                    terms.expiry,
                    at,
                    if own { "own" } else { "notes" }
                ],
            )?;
            if inserted == 1 {
                if own {
                    tx.execute(
                        "INSERT INTO provider_issues (id, ephemeral) VALUES (?1, ?2)",
                        params![id, Issue::new_ephemeral()],
                    )?;
                }
                emit(tx, &notice)?;
            }
            Ok(inserted == 1)
        });
        match recorded {
            Ok(true) => Ok(()),
            Ok(false) => Err(declined("a swap under this hash was taken before")),
            Err(e) => Err(unavailable(e)),
        }
    }

    /// Lock the amount of the swap `id` to its client, as recorded: give
    /// it up if nothing was locked.
    async fn lock(&self, id: &[u8; 32]) -> Result<(), Error> {
        let row = self.row(id)?.expect("recorded");
        if row.own {
            return self.lock_own(id, &row).await;
        }
        let address = Address::from_bytes(&row.address).map_err(licash_wallet::Error::from)?;
        let mut tries = 0;
        let locked = loop {
            let locked = self
                .wallet
                .lock(&row.to, &address, row.amount, row.hash, Some(row.expiry))
                .await;
            // Another payment of the wallet, such as an unlinking, took a
            // note it chose: nothing was locked.
            match locked {
                Err(licash_wallet::Error::NoteTaken) if tries < 3 => tries += 1,
                locked => break locked,
            }
        };
        match locked {
            Ok(lock) => {
                let lock_id = lock_id(&lock.id)?;
                self.store.set_lock(id, &lock_id)?;
                if lock.state == LockState::Locked {
                    self.advance(id, Stage::Accepted, Stage::Locked, None, None)?;
                }
            }
            // Recorded, its outcome unknown: taken on by `step`.
            Err(licash_wallet::Error::Pending { id: lock, reason }) => {
                tracing::warn!(id = %hex::encode(id), %lock, reason, "lock pending");
                self.store.set_lock(id, &lock_id(&lock)?)?;
            }
            Err(e) => {
                self.fail(id, &row, &format!("not locked: {e}"))?;
            }
        }
        Ok(())
    }

    /// Have the provider's hub lock the notes of the swap `row` it issues:
    /// give it up if declined. Its outcome unknown, `step` adopts the lock
    /// the hub made, or gives the swap up.
    async fn lock_own(&self, id: &[u8; 32], row: &Row) -> Result<(), Error> {
        let issue = self.issue_of(id, row)?;
        let locked = self.issuer_of(row)?;
        let turn = locked.turn().await;
        let store = self.store.clone();
        let key = *id;
        match locked
            .blocking(move |issuer| {
                // This guard belongs to the blocking operation, not its
                // cancelable caller. Recording is part of the same turn.
                let _turn = turn;
                let lock = issuer.lock(&issue)?;
                store.set_lock(&key, &lock).map_err(unavailable)
            })
            .await
        {
            Ok(()) => {
                self.advance(id, Stage::Accepted, Stage::Locked, None, None)?;
            }
            Err(problem) if problem.code == Code::Declined => {
                self.fail(id, row, &format!("not locked: {}", problem.message))?;
            }
            Err(problem) => {
                tracing::warn!(id = %hex::encode(id), %problem, "own lock pending");
            }
        }
        Ok(())
    }

    /// The issuer of the swap `row`, into its own hub: the provider's, at
    /// whatever URL it is reached now, as only that hub opens a file
    /// holding such swaps ([`Provider::open`]).
    fn issuer_of(&self, row: &Row) -> Result<&Arc<Issuer>, Error> {
        self.issuer.as_ref().ok_or_else(|| {
            Error::Setup(format!(
                "a swap into hub {}'s own notes: only that hub takes it on",
                row.to
            ))
        })
    }

    /// The own lock of the swap `row`, as recorded.
    fn issue_of(&self, id: &[u8; 32], row: &Row) -> Result<Issue, Error> {
        let ephemeral = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT ephemeral FROM provider_issues WHERE id = ?1",
                [id],
                |r| r.get(0),
            )?)
        })?;
        Ok(Issue {
            address: Address::from_bytes(&row.address).map_err(licash_wallet::Error::from)?,
            amount: row.amount,
            hash: row.hash,
            expiry: row.expiry,
            ephemeral,
        })
    }

    /// Move the swap `id` from stage `from` to `to`, recording `preimage`
    /// and `notice` with it. False if it had moved meanwhile.
    fn advance(
        &self,
        id: &[u8; 32],
        from: Stage,
        to: Stage,
        preimage: Option<&[u8; 32]>,
        notice: Option<(&Notice, &str)>,
    ) -> Result<bool, Error> {
        self.store.write(|tx| {
            let moved = tx.execute(
                "UPDATE provider_swaps SET state = ?3, preimage = coalesce(?4, preimage),
                    reason = coalesce(?5, reason), updated_at = ?6
                 WHERE id = ?1 AND state = ?2",
                params![
                    id,
                    from.name(),
                    to.name(),
                    preimage,
                    notice.map(|(_, reason)| reason).filter(|r| !r.is_empty()),
                    now()
                ],
            )?;
            if moved == 1 {
                if let Some((notice, _)) = notice {
                    emit(tx, notice)?;
                }
            }
            Ok(moved == 1)
        })
    }

    /// Give the swap `row` up: the provider did not lock.
    fn fail(&self, id: &[u8; 32], row: &Row, reason: &str) -> Result<(), Error> {
        tracing::warn!(id = %hex::encode(id), reason, "swap failed");
        let notice = Notice::Failed {
            id: hex::encode(id),
            reason: reason.to_owned(),
        };
        self.advance(id, row.stage, Stage::Failed, None, Some((&notice, reason)))?;
        Ok(())
    }
}

fn lock_id(text: &str) -> Result<[u8; 32], Error> {
    let mut id = [0; 32];
    hex::decode_to_slice(text, &mut id)
        .map_err(|_| licash_wallet::Error::Invalid(format!("not a lock id: {text}")))?;
    Ok(id)
}

/// Whether claiming a client's lock failed for good with `e`: refunded,
/// paying the provider nothing, or expired unactivated at its hub.
fn refused_for_good(e: &licash_wallet::Error) -> bool {
    match e {
        licash_wallet::Error::Invalid(_) | licash_wallet::Error::PaysNothing => true,
        licash_wallet::Error::Refused { problem, .. } => problem.code == Code::LockExpired,
        _ => false,
    }
}

fn emit(tx: &rusqlite::Transaction<'_>, notice: &Notice) -> Result<(), Error> {
    let json = serde_json::to_string(notice).expect("a notice serializes");
    tx.execute(
        "INSERT INTO provider_events (at, kind, json) VALUES (?1, ?2, ?3)",
        params![now(), notice.kind(), json],
    )?;
    Ok(())
}

/// Swaps taken on.
impl<T: Transport> Provider<T> {
    /// Take every swap under way on: follow the provider's locks, and
    /// claim the clients' once they revealed their preimages. Its hubs are
    /// asked again what they say of themselves, with the hubs an issuing
    /// provider swaps from, and its wallet's other payments taken on. The
    /// swaps that could not move now, by id and why.
    pub async fn step(&self) -> Result<Vec<(String, String)>, Error> {
        let mut urls: Vec<String> = self
            .wallet
            .hubs()?
            .into_iter()
            .map(|(url, _)| url)
            .collect();
        for url in self.issuer.iter().flat_map(|issuer| issuer.sources()) {
            if !urls.iter().any(|u| u == url) {
                urls.push(url.to_owned());
            }
        }
        for url in urls {
            if let Err(e) = self.wallet.add_hub(&url).await {
                tracing::warn!(%url, "hub unavailable: {e}");
            }
        }
        let resumed = self.wallet.resume().await?;
        for (id, reason) in &resumed.pending {
            tracing::debug!(%id, reason, "payment pending");
        }
        if let Err(e) = self.wallet.unlink().await {
            tracing::warn!("notes stay linked for now: {e}");
        }
        // Of payouts, those whose clients claimed their coins only: the rest
        // follow the chain (Provider::follow_payouts).
        let open: Vec<[u8; 32]> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT id FROM provider_swaps WHERE state IN ('accepted', 'locked', 'paid')
                    AND (kind IN ('notes', 'own') OR state = 'paid')
                 ORDER BY created_at, rowid",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut pending = Vec::new();
        for id in open {
            let Some(_hold) = Hold::take(&self.busy, id) else {
                continue;
            };
            if let Err(e) = self.step_one(&id).await {
                tracing::warn!(id = %hex::encode(id), "swap pending: {e}");
                pending.push((hex::encode(id), e.to_string()));
            }
        }
        Ok(pending)
    }

    async fn step_one(&self, id: &[u8; 32]) -> Result<(), Error> {
        let Some(row) = self.row(id)? else {
            return Ok(());
        };
        match row.stage {
            Stage::Paid => self.claim(id, &row).await,
            // Payouts and invoices follow the chain or the node instead.
            Stage::Accepted | Stage::Locked if !row.chain && !row.lightning => {
                self.follow(id, &row).await
            }
            _ => Ok(()),
        }
    }

    /// Follow the provider's lock of the swap `row` to its settlement.
    async fn follow(&self, id: &[u8; 32], row: &Row) -> Result<(), Error> {
        if row.own {
            return self.follow_own(id, row).await;
        }
        let lock = match row.lock {
            Some(lock) => lock,
            // Stopped after the wallet recorded the lock, or before.
            None => {
                let locks = self.wallet.locks()?;
                let found = locks.iter().find(|l| l.hub == row.to && l.hash == row.hash);
                let Some(found) = found else {
                    return self.fail(id, row, "stopped before locking");
                };
                let lock = lock_id(&found.id)?;
                self.store.set_lock(id, &lock)?;
                lock
            }
        };
        let state = match self.wallet.follow_lock(&hex::encode(lock)).await {
            Ok(lock) => lock.state,
            Err(licash_wallet::Error::Abandoned { reason, .. }) => LockState::Abandoned(reason),
            Err(e) => {
                // Refused for good only once the wallet gave the lock up,
                // its hub having refused to take it. Refused at any later
                // step, by a hub holding it, the lock stands: followed on.
                if let licash_wallet::Error::Refused { .. } = e {
                    let record = self.wallet.lock_record(&ProposalId::from_bytes(lock))?;
                    if let LockState::Abandoned(reason) = record.state {
                        return self.fail(id, row, &format!("its hub refused the lock: {reason}"));
                    }
                }
                if row.stage == Stage::Locked {
                    self.check_withheld(id, row, &lock)?;
                }
                return Err(e.into());
            }
        };
        match state {
            LockState::Locked => {
                if row.stage == Stage::Accepted {
                    self.advance(id, Stage::Accepted, Stage::Locked, None, None)?;
                    tracing::info!(id = %hex::encode(id), lock = %hex::encode(lock), "locked");
                }
                self.check_withheld(id, row, &lock)?;
            }
            LockState::Paid(preimage) => {
                self.advance(id, row.stage, Stage::Paid, Some(&preimage), None)?;
                let row = self.row(id)?.expect("recorded");
                return self.claim(id, &row).await;
            }
            LockState::Refunded => {
                tracing::info!(id = %hex::encode(id), "refunded: the client never claimed");
                let notice = Notice::Refunded {
                    id: hex::encode(id),
                    amount: row.amount,
                };
                self.advance(id, row.stage, Stage::Refunded, None, Some((&notice, "")))?;
            }
            LockState::Abandoned(reason) => {
                return self.fail(id, row, &format!("its hub refused the lock: {reason}"));
            }
            _ => {}
        }
        Ok(())
    }

    /// Follow the own lock of the swap `row`, which its hub issued, to its
    /// settlement. Stopped before its lock was recorded, the provider
    /// adopts the lock the hub holds under its hash if the swap made it,
    /// and never locks again.
    async fn follow_own(&self, id: &[u8; 32], row: &Row) -> Result<(), Error> {
        let issuer = self.issuer_of(row)?;
        let lock = match row.lock {
            Some(lock) => lock,
            None => {
                let issue = self.issue_of(id, row)?;
                let turn = issuer.turn().await;
                // A canceled take may still be locking on the blocking
                // pool. Wait for its turn, then keep it through adoption
                // or failure so that a late lock cannot land on a failed row.
                let (found, _turn) = issuer
                    .blocking(move |issuer| Ok((issuer.find(&issue), turn)))
                    .await
                    .map_err(Error::Hub)?;
                match found {
                    Ok(Some(lock)) => {
                        self.store.set_lock(id, &lock)?;
                        lock
                    }
                    Ok(None) => return self.fail(id, row, "stopped before locking"),
                    Err(problem) if problem.code == Code::Declined => {
                        let reason = format!("not locked: {}", problem.message);
                        self.alert(&format!(
                            "Swap {} was not locked: hub {} holds another lock under its hash.",
                            hex::encode(id),
                            row.to
                        ))?;
                        return self.fail(id, row, &reason);
                    }
                    Err(problem) => return Err(Error::Hub(problem)),
                }
            }
        };
        let issued = issuer.blocking(move |issuer| issuer.follow(&lock)).await;
        match issued.map_err(Error::Hub)? {
            Issued::Locked => {
                if row.stage == Stage::Accepted {
                    self.advance(id, Stage::Accepted, Stage::Locked, None, None)?;
                    tracing::info!(id = %hex::encode(id), lock = %hex::encode(lock), "locked");
                }
            }
            Issued::Paid(preimage) => {
                self.advance(id, row.stage, Stage::Paid, Some(&preimage), None)?;
                let row = self.row(id)?.expect("recorded");
                return self.claim(id, &row).await;
            }
            Issued::Refunded => {
                tracing::info!(id = %hex::encode(id), "refunded: the client never claimed");
                let notice = Notice::Refunded {
                    id: hex::encode(id),
                    amount: row.amount,
                };
                self.advance(id, row.stage, Stage::Refunded, None, Some((&notice, "")))?;
            }
        }
        Ok(())
    }

    /// Alert the operator, once, if hub `to` of the swap `row` has neither
    /// paid nor refunded the provider's certified `lock` though it expired
    /// long enough ago for the hub to refund it plainly: the hub may keep
    /// the preimage the client revealed to it. Its refund requested on
    /// Bitcoin in time, the hub must publish the preimage or refund, and
    /// the provider claims the client's lock with it.
    fn check_withheld(&self, id: &[u8; 32], row: &Row, lock: &[u8; 32]) -> Result<(), Error> {
        let hubs = self.wallet.hubs()?;
        let locks = |url: &str| {
            hubs.iter()
                .find(|(u, _)| u == url)
                .and_then(|(_, info)| info.locks.as_ref())
        };
        // A hub that follows no chain now says nothing of when it refunds:
        // the operator is told early rather than late.
        let to = locks(&row.to);
        let (depth, reaction, height) =
            to.map_or((1, 0, 0), |l| (l.min_depth.max(1), l.reaction, l.height));
        let height = locks(&row.from).map_or(height, |l| l.height.max(height));
        if height < row.expiry.saturating_add(depth).saturating_add(reaction) {
            return Ok(());
        }
        let mut withheld = self.withheld.lock().unwrap_or_else(PoisonError::into_inner);
        if withheld.contains(id) {
            return Ok(());
        }
        // As the provider times its locks now, and as the hub's window
        // leaves time to read the preimage before the client's lock expires.
        let mut deadline = row.expiry.saturating_add(self.config.confirm);
        if let Some(to) = to {
            let after = Hop {
                confirm: 0,
                ..self.config.hop(to)
            }
            .forced_lead();
            deadline = deadline.min(row.expiry_from.saturating_sub(after.unwrap_or(u32::MAX)));
        }
        // Told past the lock's expiry at depth: a refund requested now is
        // owed, one confirmed before would have been given up.
        let message = format!(
            "Hub {} has neither paid nor refunded the provider's lock {} of swap {}, expired \
             at {}: it may keep the preimage. Request the lock's refund on Bitcoin, confirmed \
             after height {} and by height {deadline}, for the hub to publish the preimage, \
             and claim the client's lock at {} with it before it expires at {}.",
            row.to,
            hex::encode(lock),
            hex::encode(id),
            row.expiry,
            row.expiry.saturating_add(depth),
            row.from,
            row.expiry_from
        );
        tracing::error!(id = %hex::encode(id), "{message}");
        self.alert(&message)?;
        withheld.insert(*id);
        Ok(())
    }

    /// Claim the client's lock of the swap `row` with the preimage it
    /// revealed, late as hub `from` takes it: the provider paid the client
    /// already, so the preimage is out and buys nothing more. Lost once
    /// the hub refuses for good, the lock expired or refunded.
    async fn claim(&self, id: &[u8; 32], row: &Row) -> Result<(), Error> {
        let preimage = row.preimage.expect("paid on it");
        let key = hex::encode(id);
        match self.wallet.claim_revealed(&row.from, &key, &preimage).await {
            Ok(_) | Err(licash_wallet::Error::AlreadyReceived) => {
                tracing::info!(id = %key, amount = row.amount, fee = row.fee, "swap done");
                let notice = Notice::Done {
                    id: key,
                    amount: row.amount,
                    fee: row.fee,
                };
                self.advance(id, Stage::Paid, Stage::Done, None, Some((&notice, "")))?;
            }
            Err(e) if refused_for_good(&e) => {
                let reason = format!("the client's lock was not claimed: {e}");
                tracing::error!(id = %key, amount = row.amount, reason, "swap lost");
                let notice = Notice::Lost {
                    id: key,
                    amount: row.amount,
                    reason: reason.clone(),
                };
                self.advance(id, Stage::Paid, Stage::Lost, None, Some((&notice, &reason)))?;
            }
            Err(e) => {
                self.check_late(id, row).await?;
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Alert the operator, once, if the provider paid the swap `row` but
    /// has yet to claim the client's lock within its margin, and the time
    /// to confirm on Bitcoin, of that lock's expiry: lost once it expires.
    async fn check_late(&self, id: &[u8; 32], row: &Row) -> Result<(), Error> {
        // Not hub `from`'s height alone, which may stop answering, or lag:
        // the highest of either hub, or of the provider's own.
        let hubs = self.wallet.hubs()?;
        let at = |url: &str| {
            hubs.iter()
                .find(|(u, _)| u == url)
                .and_then(|(_, info)| info.locks.as_ref())
                .map(|l| l.height)
        };
        let own = match self.issuer.as_ref().filter(|_| row.own) {
            Some(issuer) => issuer.blocking(|issuer| Ok(issuer.height())).await,
            None => Ok(None),
        };
        let height = [at(&row.from), at(&row.to), own.ok().flatten()]
            .into_iter()
            .flatten()
            .max();
        let late = self.config.margin.saturating_add(self.config.confirm);
        // A hub that follows no chain now says nothing of its height: the
        // operator is told early rather than late.
        if height.is_some_and(|h| h < row.expiry_from.saturating_sub(late)) {
            return Ok(());
        }
        let mut alerted = self.late.lock().unwrap_or_else(PoisonError::into_inner);
        if !alerted.insert(*id) {
            return Ok(());
        }
        let message = format!(
            "The provider paid swap {} at {} but has not claimed the client's lock at {} yet, \
             which expires at {}: unclaimed by then, the swap is lost. Check that hub.",
            hex::encode(id),
            row.to,
            row.from,
            row.expiry_from
        );
        tracing::error!(id = %hex::encode(id), "{message}");
        self.alert(&message)
    }
}

/// What the provider recorded.
impl<T: Transport> Provider<T> {
    fn row(&self, id: &[u8; 32]) -> Result<Option<Row>, Error> {
        self.store.read(|c| {
            Ok(c.query_row(&format!("{ROWS} WHERE id = ?1"), [id], row_of)
                .optional()?)
        })
    }

    /// The swap of the client's lock `id`, as its client is told: none of
    /// a payout ([`Provider::payout`]) or an invoice ([`Provider::invoice`]).
    pub fn swap(&self, id: &ProposalId) -> Result<Option<swaps::Swap>, Error> {
        let row = self.row(id.as_bytes())?;
        Ok(row
            .filter(|row| !row.chain && !row.lightning)
            .map(|row| row.swap()))
    }

    /// The swap or payout of the client's lock `id`, in hex, and what it
    /// paid hubs, if the provider recorded it.
    pub fn outcome(&self, id: &str) -> Result<Option<Outcome>, Error> {
        let mut key = [0; 32];
        if hex::decode_to_slice(id, &mut key).is_err() {
            return Ok(None);
        }
        let Some(row) = self.row(&key)? else {
            return Ok(None);
        };
        let hub_fee = match (row.chain, row.own, row.lock) {
            (true, ..) | (false, false, None) => None,
            (false, true, _) => Some(0),
            (false, false, Some(lock)) => {
                match self.wallet.lock_record(&ProposalId::from_bytes(lock)) {
                    Ok(lock) => match lock.state {
                        LockState::Paid(_) => Some(lock.fee),
                        LockState::Refunded => lock.cost,
                        _ => None,
                    },
                    Err(licash_wallet::Error::UnknownPayment(_)) => None,
                    Err(e) => return Err(e.into()),
                }
            }
        };
        Ok(Some(Outcome {
            record: row.record(),
            hub_fee,
        }))
    }

    /// The swaps, newest first, at most `limit`.
    pub fn records(&self, limit: u32) -> Result<Vec<Record>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(&format!(
                "{ROWS} ORDER BY created_at DESC, rowid DESC LIMIT ?1"
            ))?;
            let rows = stmt.query_map([limit], row_of)?;
            rows.map(|row| Ok(row?.record())).collect()
        })
    }

    /// Counts over its swaps, and the fees earned.
    pub fn stats(&self) -> Result<Stats, Error> {
        self.store.read(|c| {
            let mut stats = Stats {
                events: c.query_row(LAST_EVENT, [], |r| r.get::<_, i64>(0))? as u64,
                ..Stats::default()
            };
            let mut stmt = c.prepare(
                "SELECT state, count(*), sum(fee), sum(amount) FROM provider_swaps GROUP BY state",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    Stage::parse(&r.get::<_, String>(0)?)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)? as u64,
                ))
            })?;
            for row in rows {
                let (stage, count, fees, amount) = row?;
                match stage {
                    _ if stage.open() => stats.open += count,
                    Stage::Done => {
                        stats.done += count;
                        stats.earned += fees;
                    }
                    Stage::Refunded => stats.refunded += count,
                    Stage::Failed => stats.failed += count,
                    Stage::Lost => {
                        stats.lost += count;
                        stats.lost_amount += amount;
                    }
                    _ => {}
                }
            }
            Ok(stats)
        })
    }

    /// The events after `after`, oldest first, at most `limit`.
    pub fn events(&self, after: u64, limit: u32) -> Result<Vec<Event>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT seq, at, kind, json FROM provider_events WHERE seq > ?1 ORDER BY seq LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![after as i64, limit], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            rows.map(|row| {
                let (seq, at, kind, json) = row?;
                Ok(Event {
                    seq: seq as u64,
                    at: at as u64,
                    kind,
                    data: serde_json::from_str(&json).unwrap_or(serde_json::Value::Null),
                })
            })
            .collect()
        })
    }

    /// The last event's `seq`, or 0.
    pub fn last_event(&self) -> Result<u64, Error> {
        self.store
            .read(|c| Ok(c.query_row(LAST_EVENT, [], |r| r.get::<_, i64>(0))? as u64))
    }

    /// Tell the operator `message`.
    pub fn alert(&self, message: &str) -> Result<(), Error> {
        let notice = Notice::Alert {
            message: message.to_owned(),
        };
        self.store.write(|tx| emit(tx, &notice))
    }
}

/// `amount` sat as an operator reads it: `12,345 sat`.
fn sat(amount: u64) -> String {
    let digits = amount.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3 + 4);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped + " sat"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_read_with_commas_between_thousands() {
        assert_eq!(sat(0), "0 sat");
        assert_eq!(sat(999), "999 sat");
        assert_eq!(sat(1_000), "1,000 sat");
        assert_eq!(sat(1_234_567), "1,234,567 sat");
    }

    #[test]
    fn a_swap_in_hand_is_held_until_dropped() {
        let busy = Mutex::new(HashSet::new());
        let first = Hold::take(&busy, [1; 32]).unwrap();
        assert!(Hold::take(&busy, [1; 32]).is_none());
        assert!(Hold::take(&busy, [1; 32]).is_none());
        let other = Hold::take(&busy, [2; 32]).unwrap();
        drop(first);
        assert!(Hold::take(&busy, [1; 32]).is_some());
        drop(other);
        assert!(busy.lock().unwrap().is_empty());
    }
}
