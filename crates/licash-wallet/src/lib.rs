//! A Licash wallet: an owner's notes at the hubs it trusts, and the
//! payments it makes and takes, in one SQLite file.
//!
//! A payment is recorded before its hub hears of it, and each step before
//! the next is asked for, so a wallet stopped at any point finishes or
//! gives it up on [`Wallet::resume`]: a hub answers the same offer and the
//! same release again. A send its hub refuses before it is signed is
//! given up and its notes freed; a signed one is only retried, unless its
//! hub shows it can never be released. Notes its hub shows spent by a copy
//! of the wallet are dropped.
//!
//! Notes are unlinked from the payments that made them ([`Wallet::unlink`]):
//! those a hub no longer unlinks since it restarted are renewed, paid to
//! the wallet itself within a fee limit ([`Wallet::set_renew_limit`]).
//! Ordinary payments also shape change toward a common 18 to 24-note
//! distribution with small denominations. Additional consolidation inputs
//! must already be unlinked, and any increased fee must be allowed by
//! contract ceilings or the automatic fee limit.
//!
//! A timed lock pays a payee on the preimage of a hash, or returns to the
//! wallet once it expired unpaid: see [`Wallet::lock`] and
//! [`Wallet::claim`]. Through a swap provider, the wallet pays Lightning
//! invoices with locks and is paid with locks of the provider's notes: see
//! [`Wallet::pay_invoice_via`] and [`Wallet::invoice_through`]. It also
//! swaps notes at one hub for notes at another with a lock at each: see
//! [`Wallet::swap`]. Silent payments to its address are found
//! with a hub's tweaks and the application's light client: see
//! [`Wallet::scan_silent`].
//!
//! The wallet reaches hubs through the application's [`Transport`]: HTTP
//! over TCP or Tor, or a test. Its seed alone does not restore its notes:
//! back up its file.

mod backup;
mod bridges;
mod claims;
mod closes;
mod code;
mod codes;
mod coins;
mod cold;
mod delivery;
mod deposits;
mod deposits_via;
mod imports;
mod inquiry;
mod journal;
mod lane;
mod lightning;
mod lnurl;
mod locks;
mod payment_note;
mod payouts;
mod renewals;
mod shaping;
mod silent;
mod store;
mod swaps;

use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    future::Future,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Mutex,
    },
    task::Poll,
};

use licash::{
    address::{Address, Ephemeral, OwnerKeys},
    authorization::{Authorization, Grant, SignedProposal, Unlock},
    claim::Branch,
    crypto::Point,
    note::{Derivation, Keyset, Note},
    spend::{ChainProfile, Output, Proposal, ProposalId},
    unlink::Session,
};
use licash_api::{Code, Info, Offer, Offered, Payment, Problem, Release, Unlink, Unlinked};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Serialize};

pub use bridges::{AddedBridge, BridgeRules, BridgeTopUp};
pub use claims::{ClaimNote, ClaimSlot, FundedNote, LockClaim, OwedLock, SlotPays};
pub use closes::ClosePayment;
pub use code::{
    ContractSecrets, DonationAddress, HubId, LicashCode, PaymentCode, CODE_HUBS, MAX_HUBS,
};
pub use codes::{CodeActivity, CodesCollected, ExtraCode, MAX_LABEL};
pub use coins::MAX_INPUTS;
pub use cold::{Cold, ColdRules, ColdScript, ColdWithdrawal, GAP as COLD_GAP};
pub use delivery::{Delivery, Due, Inboxed, ACK_WITHIN, PAGES_AT_ONCE};
pub use deposits::{
    Close, CloseDeposit, Deposit, DepositState, DepositTerms, CLOSE_ATTEMPTS, GAP as DEPOSIT_GAP,
};
pub use deposits_via::DepositOffer;
pub use imports::{Imported, ImportedSource, SealedNotes};
pub use inquiry::Checked;
pub use journal::{CoinSpan, Journal, NoteSpan};
pub use lane::{current_lane, in_background, in_background_now, in_lane, Background, Lane};
pub use lightning::{
    refund_blocks, Invoice, InvoiceState, Payable, ReceiveOffer, ViaQuote, ROUTE_BLOCKS,
};
pub use lnurl::{pay_target as lnurl_pay_target, PayRequest as LnurlPayRequest};
pub use locks::{Incoming, Lock, LockState, Via, CLAIM_MARGIN, PROTECTED_MARGIN};
pub use payment_note::{note_text, PaymentNote, MAX_NOTE};
pub use payouts::{
    checked_block, first_spend, payout_depth, Payout, PayoutProgress, PayoutQuote, PayoutState,
    CLAIM_ROOM, PAYOUT_WINDOW,
};
pub use shaping::{Optimization, OptimizationQuote};
pub use silent::{
    least_deposited, least_deposited_through, Blocks, Payee, Scanned, SilentCoin, SilentSpend,
    SilentTweaks,
};
use store::{now, sql, Owner, Store};
pub use swaps::{Swap, SwapLimits, SwapQuote, SwapState, SWAP_ROOM, SWAP_WINDOW, TERMS_FRESH};

/// The default relative limit for automatic renewal without contract
/// ceilings ([`Wallet::set_renew_limit`]), in parts per million. A modest
/// spending schedule is allowed too, as that setter describes.
pub const RENEW_PPM: u32 = 1_000;

/// Why a note stays linked: its hub refused to renew it.
const RENEWAL_REFUSED: &str = "renewal_refused";

/// How many notes a wallet asks a hub to unlink at once: each request
/// waits for its answer, over Tor half a second or more, and a payment
/// leaves a few notes to unlink.
const UNLINKING_AT_ONCE: usize = 4;

/// A hub's answer: its HTTP status and body.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// How the wallet reaches its hubs.
///
/// A hub, and anyone on the path to one reached over plain HTTP, says what
/// it answers: an implementation bounds the answers it reads, as it reads
/// them, refusing one larger than a few MiB, far above any of the wallet's
/// own (`licash-transport`'s takes 4 MiB), and one of a
/// [`Transport::download`] larger than its `max`. The wallet holds what it
/// is given.
pub trait Transport: Send + Sync {
    /// GET `url`, or POST `body` to it as JSON. `Err` when no answer came,
    /// so that the request may or may not have taken effect.
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<Response, String>> + Send;

    /// GET `url`, an answer far larger than any of the wallet's own: of up
    /// to `max` bytes, given the time a download of it takes. As
    /// [`Transport::request`], and bounded as it is, unless the transport
    /// bounds such answers apart.
    fn download(
        &self,
        url: &str,
        max: usize,
    ) -> impl Future<Output = Result<Response, String>> + Send {
        let _ = max;
        self.request(url, None)
    }

    /// That the wallet stopped waiting on the answer from the host of
    /// `url`, another host having answered long before: a transport that
    /// passes over hosts that did not answer lately may count it as one
    /// that did not. Nothing by default.
    fn gave_up(&self, url: &str) {
        let _ = url;
    }
}

/// Why a wallet call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The wallet file is missing, exists already or does not match.
    #[error("{0}")]
    Setup(String),
    /// The wallet file could not be read or written.
    #[error("wallet database: {0}")]
    Storage(#[from] rusqlite::Error),
    /// Data failed the protocol's checks.
    #[error("protocol: {0}")]
    Protocol(#[from] licash::Error),
    /// No answer, or none that makes sense: retry later.
    #[error("hub {hub} is unavailable: {reason}")]
    Unavailable { hub: String, reason: String },
    /// Nothing was paid: a payment its hub refused is given up, its notes
    /// freed, and may be made again.
    #[error("hub {hub} refused: {problem}")]
    Refused { hub: String, problem: Problem },
    /// The payment is recorded, its outcome unknown: [`Wallet::resume`]
    /// finishes it.
    #[error("payment {id} is pending ({reason}): resume finishes it")]
    Pending { id: String, reason: String },
    /// The payment was given up before, its notes freed: nothing was paid.
    #[error("payment {id} was given up: {reason}")]
    Abandoned { id: String, reason: String },
    /// Not a hub this wallet added. With a payment, the hub its payer
    /// names: add it only if the owner trusts it.
    #[error("unknown hub {0}: add it first")]
    UnknownHub(String),
    #[error("no payment {0}")]
    UnknownPayment(String),
    #[error("{needed} needed, {available} available in one payment")]
    Insufficient { needed: u64, available: u64 },
    /// More than the wallet agreed to pay there
    /// ([`Wallet::set_fee_ceilings`]): its owner's to approve.
    #[error("hub {hub} charges more than agreed: approve its fees to pay there")]
    FeesRaised { hub: String },
    /// A swap provider, or a hub's gateway, `who`, asks `asked` sat in
    /// fees where the quote agreed to at most `agreed`: nothing was
    /// locked. Its owner's to accept, asking for a quote again.
    #[error("{reason}")]
    FeeRose {
        who: String,
        agreed: u64,
        asked: u64,
        reason: String,
    },
    /// Another payment took a note meanwhile: nothing was paid.
    #[error("another payment took a note meanwhile: try again")]
    NoteTaken,
    #[error("the payment is received already")]
    AlreadyReceived,
    #[error("the payment pays this wallet nothing")]
    PaysNothing,
    #[error("{0}")]
    Invalid(String),
    /// The hub at `hub` keeps no note with a payment it keeps, so its payee
    /// may take the payment without its note: nothing was paid. Its
    /// owner's to pay without the note, or elsewhere.
    #[error("hub {hub} keeps no note with a payment: pay without the note")]
    NoteUnkept { hub: String },
    /// The application's view of Bitcoin failed, or served a block that
    /// is not the one asked for: retry later.
    #[error("chain source failed: {0}")]
    Chain(String),
}

/// `run` on each of `items`, at most `most` under way at once: what each
/// made, in no particular order. Once one failed, no other is started,
/// and those under way are finished: its error then.
async fn each_at_most<I, T, E, F>(
    most: usize,
    items: impl IntoIterator<Item = I>,
    run: impl Fn(I) -> F,
) -> Result<Vec<T>, E>
where
    F: Future<Output = Result<T, E>>,
{
    let mut items = items.into_iter();
    let mut running: Vec<Pin<Box<F>>> = Vec::new();
    let (mut made, mut failed) = (Vec::new(), None);
    std::future::poll_fn(|cx| loop {
        if failed.is_none() {
            let room = most.max(1) - running.len();
            running.extend(items.by_ref().take(room).map(|item| Box::pin(run(item))));
        }
        if running.is_empty() {
            return Poll::Ready(());
        }
        let before = running.len();
        running.retain_mut(|one| match one.as_mut().poll(cx) {
            Poll::Ready(Ok(one)) => {
                made.push(one);
                false
            }
            Poll::Ready(Err(e)) => {
                failed.get_or_insert(e);
                false
            }
            Poll::Pending => true,
        });
        // Each still under way woken when it can go on.
        if running.len() == before {
            return Poll::Pending;
        }
    })
    .await;
    failed.map_or(Ok(made), Err)
}

/// `a` and `b` under way at once, each to its end: what each made.
async fn both<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (std::pin::pin!(a), std::pin::pin!(b));
    let (mut made_a, mut made_b) = (None, None);
    std::future::poll_fn(|cx| {
        if made_a.is_none() {
            if let Poll::Ready(made) = a.as_mut().poll(cx) {
                made_a = Some(made);
            }
        }
        if made_b.is_none() {
            if let Poll::Ready(made) = b.as_mut().poll(cx) {
                made_b = Some(made);
            }
        }
        match (made_a.is_some(), made_b.is_some()) {
            (true, true) => Poll::Ready((made_a.take().unwrap(), made_b.take().unwrap())),
            _ => Poll::Pending,
        }
    })
    .await
}

fn invalid(e: impl std::fmt::Display) -> Error {
    Error::Invalid(e.to_string())
}

/// `code` as the API names it, as the wallet records it.
fn code_name(code: Code) -> String {
    match serde_json::to_value(code) {
        Ok(serde_json::Value::String(name)) => name,
        _ => format!("{code:?}"),
    }
}

/// Whether the hub `hub` is trusted, and what it last said of itself.
fn kept_hub(tx: &rusqlite::Transaction, hub: i64) -> Result<(bool, Info), Error> {
    let (trusted, info): (bool, String) =
        tx.query_row("SELECT trusted, info FROM hubs WHERE id = ?1", [hub], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    Ok((trusted, serde_json::from_str(&info).map_err(invalid)?))
}

/// How [`Wallet::keep_info`] keeps what a hub says of itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Keep {
    /// Trusted from now on: the owner added it.
    Add,
    /// Visited, unless added already: it proved it is the hub of this id.
    Visit(HubId),
    /// As it was kept; a hub new to the wallet trusted, as one the owner
    /// named.
    Refresh,
}

/// What the wallet holds at one hub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balance {
    pub hub: String,
    /// Spendable now.
    pub available: u64,
    /// Held by payments and locks under way.
    pub pending: u64,
}

/// How many notes of one denomination the wallet can spend at one hub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notes {
    pub hub: String,
    pub denomination: u64,
    pub count: u64,
}

/// A payment made, and where it stands.
#[derive(Clone, Debug)]
pub struct Sent {
    pub id: String,
    pub hub: String,
    pub payee: Address,
    pub amount: u64,
    pub fee: u64,
    pub state: State,
    pub created_at: i64,
}

/// Where a payment stands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Not signed yet: its hub may refuse it, which frees its notes.
    Offered,
    /// Signed, waiting for its hub's release.
    Signed,
    /// Released by its hub: paid.
    Done,
    /// Given up, its notes freed, and why.
    Abandoned(String),
}

/// A payment made, by its id, with the payment to hand its payee.
#[derive(Clone, Debug)]
pub struct Paid {
    pub id: String,
    pub payment: Payment,
    /// Whether its hub keeps it for its payee to collect there
    /// ([`Wallet::pay_code`]): not yet collected.
    pub kept: bool,
}

/// A payment's notes paying the wallet, opened ([`Wallet::receive`]): of
/// a keyset of the hub at `url`.
struct Opened {
    keyset: Keyset,
    url: String,
    signed: SignedProposal,
    ours: Vec<(licash::address::Received, Note)>,
}

/// A payment taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    pub id: String,
    pub hub: String,
    pub amount: u64,
    pub received_at: i64,
}

/// The notes one payment, lock or receipt of the wallet spent, and those
/// it made the wallet's: its change, its settled branch, or what it was
/// paid ([`Wallet::operation_notes`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperationNotes {
    pub spent: Vec<NoteRecord>,
    pub made: Vec<NoteRecord>,
}

/// Part of what the notes a payment or lock of the wallet spent paid
/// ([`Wallet::operation_parts`]): to whom, and in which notes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Part {
    pub to: PartTo,
    pub amount: u64,
    /// The amounts of the notes made for it, the largest first.
    pub notes: Vec<u64>,
}

/// Whom a [`Part`] pays.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PartTo {
    /// The payment's payee, which may be the wallet itself.
    Payee(Address),
    /// Its hub, as its fee.
    Hub,
    /// The wallet, as its change or its refund.
    Kept,
}

/// A note the wallet holds or held, as an application shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NoteRecord {
    /// Its identifier, the same at its hub once unlinked: in hex.
    pub id: String,
    pub hub: String,
    pub amount: u64,
    /// The payment, lock or receipt that made it, in hex.
    pub made_by: String,
    /// The payment or lock that spends it, from when it chose it, in hex.
    pub spent_by: Option<String>,
    pub unlinked: Unlinking,
    /// Spent by a copy of the wallet, as its hub showed: never here.
    pub gone: bool,
    pub added_at: i64,
}

/// Whether a note's hub can tell which payment it came from when it is
/// spent ([`Wallet::unlink`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unlinking {
    /// As issued: its hub can tell. The wallet unlinks it next time.
    Linked,
    /// Signed again blindly by its hub: it cannot tell.
    Unlinked,
    /// Its hub refused to unlink it: it stays linked.
    StaysLinked,
}

/// What [`Wallet::resume`] did with the payments and locks under way.
#[derive(Debug, Default)]
pub struct Resumed {
    pub paid: Vec<Paid>,
    /// Locks taken on, where each stands now.
    pub locks: Vec<Lock>,
    /// Invoices taken on, where each stands now.
    pub invoices: Vec<Invoice>,
    /// Swaps taken on, where each stands now.
    pub swaps: Vec<Swap>,
    /// Deposits taken on, where each stands now.
    pub deposits: Vec<Deposit>,
    /// Given up, their notes freed, by id and why.
    pub abandoned: Vec<(String, String)>,
    /// Still under way, by id and why.
    pub pending: Vec<(String, String)>,
}

/// The step of a payment its hub refused, past which it is not given up:
/// a send unsigned, a send signed whose hub proves an input spent otherwise
/// or refuses the offer it forgot, a lock its hub has not certified.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Offer,
    Release,
    Lock,
}

impl Step {
    /// Give the payment `?1` up for reason `?2`.
    fn give_up(self) -> &'static str {
        match self {
            Self::Offer => {
                "UPDATE sends SET abandoned = ?2
                 WHERE id = ?1 AND done_at IS NULL AND abandoned IS NULL AND release IS NULL"
            }
            Self::Release => {
                "UPDATE sends SET abandoned = ?2
                 WHERE id = ?1 AND done_at IS NULL AND abandoned IS NULL"
            }
            // A lock a recovery claims the refund of is its own.
            Self::Lock => {
                "UPDATE locks SET abandoned = ?2
                 WHERE id = ?1 AND certificate IS NULL AND abandoned IS NULL
                 AND claimed_by IS NULL"
            }
        }
    }

    /// Why the payment `?1` was given up, if it was.
    fn abandoned(self) -> &'static str {
        match self {
            Self::Offer | Self::Release => "SELECT abandoned FROM sends WHERE id = ?1",
            Self::Lock => "SELECT abandoned FROM locks WHERE id = ?1",
        }
    }
}

/// An owner's wallet: its keys, derived from its seed, and its notes and
/// payments, in one SQLite file. It reaches hubs and swap providers
/// through `T`, the application's [`Transport`].
pub struct Wallet<T> {
    store: Store,
    owner: OwnerKeys,
    keys: code::CodeKeys,
    network: ChainProfile,
    transport: T,
    /// The hubs reached over plain HTTP asked over HTTPS since opened.
    asked_secure: Mutex<HashSet<i64>>,
    /// The coins of payouts as their providers told of them since opened,
    /// confirmed or not, and their blocks if confirmed: by payout hash.
    told_coins: Mutex<HashMap<[u8; 32], Told>>,
    /// The most it pays to renew notes, in parts per million of their value.
    renew_ppm: AtomicU32,
    /// The most each hub may charge ([`Wallet::set_fee_ceilings`]).
    ceilings: Mutex<HashMap<i64, licash_api::Fees>>,
    /// What keeps its locks claimable ([`Wallet::guard_locks`]).
    horizon: Mutex<Option<LockHorizon>>,
    /// The chain's height as its application told it since opened, the
    /// highest ([`Wallet::saw_tip`]): 0 if never.
    told_tip: AtomicU32,
    /// Whether the wallet's extra codes are being collected
    /// ([`Wallet::collect_codes`]): once at a time.
    collecting_codes: std::sync::atomic::AtomicBool,
    /// The invoices being advanced, each by one caller at a time
    /// ([`Wallet::advance_invoice`]): by hash.
    advancing: Mutex<HashMap<[u8; 32], std::sync::Arc<tokio::sync::Mutex<()>>>>,
    /// Each swap provider's terms as it last answered, and when, by URL:
    /// what quotes read for as long as they are kept ([`Wallet::keep_terms`]),
    /// in memory only.
    terms: Mutex<HashMap<String, (licash_api::swaps::Info, std::time::Instant)>>,
    /// How long quotes read terms kept, in seconds: 0, asked each time,
    /// unless the application keeps them.
    terms_for: std::sync::atomic::AtomicU64,
}

/// The height by which a lock at the hub reached at any of the URLs given,
/// at the chain's height given, must have expired at depth for its refund
/// to be claimed on Bitcoin, by the contracts protecting its payer there
/// ([`Wallet::guard_locks`]): none if none does. An error refuses the
/// lock.
pub type LockHorizon =
    std::sync::Arc<dyn Fn(&[String], u32) -> Result<Option<u32>, String> + Send + Sync>;

/// A payout's coin as its provider told of it: its transaction, and its
/// block once confirmed.
type Told = (bitcoin::Txid, Option<u32>);

/// A note the wallet holds, with where it was made: the scan key derives
/// it again from there.
struct Held {
    note: Note,
    ephemeral: Point,
    branch: Branch,
    position: u32,
}

impl<T: Transport> Wallet<T> {
    /// A new wallet file at `path`, holding `seed`, its owner's, for hubs
    /// on `network`.
    pub fn create(
        path: &Path,
        seed: &[u8; 32],
        network: ChainProfile,
        transport: T,
    ) -> Result<Self, Error> {
        Self::created(path, seed, true, network, transport)
    }

    /// A new wallet file at `path` for the owner of `seed`, which the
    /// application keeps, as in a phone's keystore: it opens the wallet
    /// with [`Wallet::open_with_seed`].
    pub fn create_without_seed(
        path: &Path,
        seed: &[u8; 32],
        network: ChainProfile,
        transport: T,
    ) -> Result<Self, Error> {
        Self::created(path, seed, false, network, transport)
    }

    fn created(
        path: &Path,
        seed: &[u8; 32],
        keep: bool,
        network: ChainProfile,
        transport: T,
    ) -> Result<Self, Error> {
        let owner = OwnerKeys::from_seed(seed)?;
        let address = owner.address().to_bytes();
        let keys = code::CodeKeys::from_seed(seed, network)?;
        let store = Store::create(path, keep.then_some(seed), &address, network.name())?;
        Ok(Self {
            store,
            owner,
            keys,
            network,
            transport,
            asked_secure: Mutex::default(),
            told_coins: Mutex::default(),
            renew_ppm: AtomicU32::new(RENEW_PPM),
            ceilings: Mutex::default(),
            horizon: Mutex::default(),
            told_tip: AtomicU32::new(0),
            collecting_codes: Default::default(),
            advancing: Mutex::default(),
            terms: Mutex::default(),
            terms_for: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// The wallet file at `path`, which holds its seed.
    pub fn open(path: &Path, transport: T) -> Result<Self, Error> {
        let (store, owner) = Store::open(path)?;
        let seed = owner.seed.ok_or_else(|| {
            Error::Setup("the wallet's seed is kept elsewhere: open it with its seed".into())
        })?;
        Self::opened(store, &seed, &owner, transport)
    }

    /// The wallet file at `path`, of the owner of `seed`.
    pub fn open_with_seed(path: &Path, seed: &[u8; 32], transport: T) -> Result<Self, Error> {
        let (store, owner) = Store::open(path)?;
        Self::opened(store, seed, &owner, transport)
    }

    fn opened(store: Store, seed: &[u8; 32], kept: &Owner, transport: T) -> Result<Self, Error> {
        let owner = OwnerKeys::from_seed(seed)?;
        if owner.address().to_bytes()[..] != *kept.address {
            return Err(Error::Setup("not this wallet's seed".into()));
        }
        let network = kept
            .network
            .parse()
            .map_err(|_| Error::Setup(format!("the wallet's network {}", kept.network)))?;
        Ok(Self {
            store,
            keys: code::CodeKeys::from_seed(seed, network)?,
            owner,
            network,
            transport,
            asked_secure: Mutex::default(),
            told_coins: Mutex::default(),
            renew_ppm: AtomicU32::new(RENEW_PPM),
            ceilings: Mutex::default(),
            horizon: Mutex::default(),
            told_tip: AtomicU32::new(0),
            collecting_codes: Default::default(),
            advancing: Mutex::default(),
            terms: Mutex::default(),
            terms_for: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Tell the wallet the height of Bitcoin's chain as its application
    /// sees it, by a source of its own: kept while the wallet is open, the
    /// highest told. What a hub says of the chain is checked against it
    /// ([`Wallet::tip`]).
    pub fn saw_tip(&self, height: u32) {
        self.told_tip.fetch_max(height, Ordering::Relaxed);
    }

    /// The height of Bitcoin's chain as the wallet knows it of itself, not
    /// from a hub: the highest its application told it since it was opened
    /// ([`Wallet::saw_tip`]), or the last block it looked in
    /// ([`Wallet::scan_silent`]) if that is higher. None if neither is
    /// known. Never ahead of the chain, and behind it by as much as the
    /// wallet was last told or looked.
    pub fn tip(&self) -> Result<Option<u32>, Error> {
        let looked = self.silent_next()?.map(|next| next.saturating_sub(1));
        let told = Some(self.told_tip.load(Ordering::Relaxed)).filter(|told| *told > 0);
        Ok(told.max(looked))
    }

    /// The network of the hubs the wallet trusts: a hub following another
    /// chain is refused.
    pub fn network(&self) -> ChainProfile {
        self.network
    }

    /// Renew notes their hub no longer unlinks ([`Wallet::unlink`]) only
    /// if its fee on them is at most `ppm` parts per million of their
    /// value, or its advertised spending fees are at most 1 sat base,
    /// `ppm` millionths and 0.1 sat per output. With 0, only where the
    /// renewal costs nothing. Contract ceilings take precedence.
    /// [`RENEW_PPM`] until set.
    pub fn set_renew_limit(&self, ppm: u32) {
        self.renew_ppm.store(ppm, Ordering::Relaxed);
    }

    /// The most the wallet pays to renew notes ([`Wallet::set_renew_limit`]).
    pub fn renew_limit(&self) -> u32 {
        self.renew_ppm.load(Ordering::Relaxed)
    }

    /// Pay the hub at `url`, a hub the wallet knows, no fee above its
    /// like in `ceilings`, as its owner agreed to there (the fees a
    /// recovery contract opened under, say): while it charges more,
    /// payments and locks there are refused as [`Error::FeesRaised`] and
    /// its notes are not renewed, until the ceilings are raised. Under
    /// them, notes are renewed whatever [`Wallet::set_renew_limit`] says.
    /// None lifts them. Kept while the wallet is open only: whoever opens
    /// it sets them.
    pub fn set_fee_ceilings(
        &self,
        url: &str,
        ceilings: Option<licash_api::Fees>,
    ) -> Result<(), Error> {
        let (hub, _) = self.hub(&hub_url(url)?)?;
        let mut kept = self.ceilings.lock().unwrap_or_else(|e| e.into_inner());
        match ceilings {
            Some(ceilings) => kept.insert(hub, ceilings),
            None => kept.remove(&hub),
        };
        Ok(())
    }

    /// Keep each lock the wallet makes claimable on Bitcoin by the
    /// contracts protecting it, as `horizon` says: one of no expiry asked
    /// expires early enough, one asked to expire later is refused. Kept
    /// while the wallet is open only: whoever opens it sets it.
    pub fn guard_locks(&self, horizon: LockHorizon) {
        *self.horizon.lock().unwrap_or_else(|e| e.into_inner()) = Some(horizon);
    }

    /// [`Wallet::guard_locks`]' horizon of the hub at `url` at `tip`.
    pub(crate) fn lock_horizon(&self, url: &str, tip: u32) -> Result<Option<u32>, Error> {
        let horizon = self
            .horizon
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(horizon) = horizon else {
            return Ok(None);
        };
        let urls = self.hub_urls(url)?;
        horizon(&urls, tip).map_err(|why| {
            Error::Invalid(format!(
                "no lock at {url}: its protection is unknown, {why}"
            ))
        })
    }

    /// The most the hub at `url` may charge, if set
    /// ([`Wallet::set_fee_ceilings`]).
    pub fn fee_ceilings(&self, url: &str) -> Result<Option<licash_api::Fees>, Error> {
        let (hub, _) = self.hub(&hub_url(url)?)?;
        Ok(self.ceilings_of(hub))
    }

    fn ceilings_of(&self, hub: i64) -> Option<licash_api::Fees> {
        let kept = self.ceilings.lock().unwrap_or_else(|e| e.into_inner());
        kept.get(&hub).copied()
    }

    /// What the hub `hub`, at `url`, charges, as `info` says: refused if
    /// more than its ceilings.
    fn agreed_fees(&self, hub: i64, url: &str, info: &Info) -> Result<licash_api::Fees, Error> {
        match self.ceilings_of(hub) {
            Some(ceilings) if info.fees.above(&ceilings) => Err(Error::FeesRaised {
                hub: url.to_owned(),
            }),
            _ => Ok(info.fees),
        }
    }

    /// How the wallet reaches its hubs, for what it does not ask itself.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The file the wallet is kept in, which the modules of the same actor
    /// (a swap provider's, a holder's contracts) keep their tables in too.
    pub fn path(&self) -> &Path {
        self.store.path()
    }

    /// When the wallet file was made, in seconds since the Unix epoch: of
    /// a new seed, no payment to it is older.
    pub fn created_at(&self) -> Result<i64, Error> {
        self.store
            .read(|c| Ok(c.query_row("SELECT created_at FROM meta", [], |r| r.get(0))?))
    }

    /// Where others pay this wallet.
    pub fn address(&self) -> Address {
        self.owner.address()
    }

    /// Trust the hub at `url`, and learn its keysets and fees. Again, to
    /// learn what changed. Refused if it follows another network than the
    /// wallet's. A hub reached over plain HTTP is asked over HTTPS too,
    /// once a wallet is opened, even if unavailable over plain HTTP: the
    /// same hub there is reached there from then on, and still known at
    /// the other URL.
    pub async fn add_hub(&self, url: &str) -> Result<Info, Error> {
        let url = hub_url(url)?;
        let refreshed = self.learn(&url, Keep::Add).await;
        // Added anew, as a wallet restored from its seed does: the
        // deposits it asked there before, if any, found.
        if let Ok((hub, info)) = &refreshed {
            if info.deposits.is_some() && self.deposit_next(*hub)?.is_none() {
                if let Err(e) = self.find_deposits_at(*hub, &url, info).await {
                    tracing::warn!(%url, "looking for the deposits asked there: {e}");
                }
            }
        }
        let hub = match &refreshed {
            Ok((hub, _)) => Some(*hub),
            Err(Error::Unavailable { .. }) => self.hub(&url).ok().map(|(hub, _)| hub),
            Err(_) => None,
        };
        if let Some(info) = match hub {
            Some(hub) => self.secure(hub).await,
            None => None,
        } {
            return Ok(info);
        }
        refreshed.map(|(_, info)| info)
    }

    /// The hubs added, by URL, and what each last said of itself.
    pub fn hubs(&self) -> Result<Vec<(String, Info)>, Error> {
        self.hubs_trusted(true)
    }

    /// Every URL the wallet knows the hub at `url` by, such as over plain
    /// HTTP and over HTTPS, the one it reaches it at first: none if it
    /// knows no hub at `url`.
    pub fn hub_urls(&self, url: &str) -> Result<Vec<String>, Error> {
        let url = hub_url(url)?;
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT u.url FROM hub_urls k JOIN hub_urls u ON u.hub = k.hub
                 WHERE k.url = ?1 ORDER BY u.rowid",
            )?;
            let rows = stmt.query_map([url], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The hubs visited to pay a payee there ([`Wallet::visit`]), not
    /// added: by URL, and what each last said of itself.
    pub fn visited(&self) -> Result<Vec<(String, Info)>, Error> {
        self.hubs_trusted(false)
    }

    fn hubs_trusted(&self, trusted: bool) -> Result<Vec<(String, Info)>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT r.url, h.info FROM hubs h JOIN reach r ON r.hub = h.id
                 WHERE h.trusted = ?1 ORDER BY r.url",
            )?;
            let rows = stmt.query_map([trusted], |r| Ok((r.get(0)?, r.get::<_, String>(1)?)))?;
            rows.map(|row| {
                let (url, info) = row?;
                Ok((url, serde_json::from_str(&info).map_err(invalid)?))
            })
            .collect()
        })
    }

    /// What the wallet holds at each hub it added, by URL.
    pub fn balance(&self) -> Result<Vec<Balance>, Error> {
        self.balance_trusted(true)
    }

    /// What the wallet holds at each hub it visited ([`Wallet::visit`]),
    /// by URL: what a swap there brought past a payment, say, for the
    /// owner to add the hub to count, or to pay out.
    pub fn visited_balance(&self) -> Result<Vec<Balance>, Error> {
        self.balance_trusted(false)
    }

    fn balance_trusted(&self, trusted: bool) -> Result<Vec<Balance>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT r.url,
                    COALESCE(SUM(CASE WHEN n.spent_by IS NULL AND n.gone_at IS NULL
                        THEN n.denom END), 0),
                    COALESCE(SUM(CASE WHEN (s.id IS NOT NULL AND s.done_at IS NULL)
                        OR (l.id IS NOT NULL AND ls.id IS NULL) THEN n.denom END), 0)
                 FROM hubs h
                 JOIN reach r ON r.hub = h.id
                 LEFT JOIN keysets k ON k.hub = h.id
                 LEFT JOIN notes n ON n.keyset = k.id
                 LEFT JOIN sends s ON s.id = n.spent_by AND n.spent_kind = 'send'
                 LEFT JOIN locks l ON l.id = n.spent_by AND n.spent_kind = 'lock'
                 LEFT JOIN lock_settlements ls ON ls.id = l.id
                 WHERE h.trusted = ?1
                 GROUP BY h.id ORDER BY r.url",
            )?;
            let rows = stmt.query_map([trusted], |r| {
                Ok(Balance {
                    hub: r.get(0)?,
                    available: r.get::<_, i64>(1)? as u64,
                    pending: r.get::<_, i64>(2)? as u64,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// How many notes the wallet can spend now of each denomination, at
    /// each hub it added: by URL, then largest denomination first.
    pub fn notes(&self) -> Result<Vec<Notes>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT r.url, n.denom, COUNT(*)
                 FROM hubs h
                 JOIN reach r ON r.hub = h.id
                 JOIN keysets k ON k.hub = h.id
                 JOIN notes n ON n.keyset = k.id
                 WHERE n.spent_by IS NULL AND n.gone_at IS NULL AND h.trusted = 1
                 GROUP BY h.id, n.denom ORDER BY r.url, n.denom DESC",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(Notes {
                    hub: r.get(0)?,
                    denomination: r.get::<_, i64>(1)? as u64,
                    count: r.get::<_, i64>(2)? as u64,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The fee of the hub at `url`, added, on the notes a payment of
    /// `amount` there spends now, as it charges on all they hold: refused
    /// as [`Error::Insufficient`] if it holds not that much in notes it
    /// can spend together.
    pub fn send_fee(&self, url: &str, amount: u64) -> Result<u64, Error> {
        let (hub, info) = self.hub(&hub_url(url)?)?;
        Ok(self.payment_plan(hub, amount, &info.fees)?.1.selection.fee)
    }

    /// [`Wallet::send_fee`] of a lock of `amount` to another than the hub.
    pub fn lock_fee(&self, url: &str, amount: u64) -> Result<u64, Error> {
        let (hub, info) = self.hub(&hub_url(url)?)?;
        Ok(self.select(hub, amount, &info.fees.locking())?.1.fee)
    }

    /// What more the wallet needs at the hub at `url`, added, to pay
    /// `amount` there, the hub's fee on what it spends on top: none if it
    /// holds that much in notes it can spend together.
    pub fn lacks(&self, url: &str, amount: u64) -> Result<u64, Error> {
        let (hub, info) = self.hub(&hub_url(url)?)?;
        let fee = info.fees.spending();
        let available = match self.select(hub, amount, &fee) {
            Ok(_) => return Ok(0),
            Err(Error::Insufficient { available, .. }) => available,
            Err(e) => return Err(e),
        };
        // The fee grows with what is spent: more until it is covered. The
        // notes made are counted as every power of two makes them.
        let made = |value: u64| value.count_ones() as usize;
        let mut more = 0u64;
        for _ in 0..64 {
            let held = available.saturating_add(more);
            match coins::settle(held, amount, made(amount), &fee, made) {
                Ok(_) => break,
                Err(due) => more = amount.saturating_add(due).saturating_sub(available),
            }
        }
        Ok(more)
    }

    /// Learn the hub at `url` to pay a payee there, without trusting it:
    /// what it says of itself, kept as a hub visited with its keysets and
    /// fees. Refused unless it proves it is the hub of `id`, the one the
    /// payee's code names, and takes locks, for a swap to bring notes
    /// there. Its notes count apart ([`Wallet::visited_balance`]) and no
    /// payment is taken there until the owner adds it; a hub added stays
    /// so.
    pub async fn visit(&self, url: &str, id: HubId) -> Result<Info, Error> {
        let url = hub_url(url)?;
        Ok(self.learn(&url, Keep::Visit(id)).await?.1)
    }

    /// What the hub at `url` says of itself, nothing kept: to show before
    /// adding it. Refused as [`Wallet::add_hub`] refuses it, if it follows
    /// another network or proves another identity.
    pub async fn hub_info(&self, url: &str) -> Result<Info, Error> {
        self.info(&hub_url(url)?).await
    }

    /// What the hub at `url` says of itself, kept: its id and info.
    async fn refresh(&self, url: &str) -> Result<(i64, Info), Error> {
        self.learn(url, Keep::Refresh).await
    }

    /// What the hub at `url` says of itself, kept as `keep` says: its id
    /// and info. A hub known at `url` is asked where the wallet reaches it.
    async fn learn(&self, url: &str, keep: Keep) -> Result<(i64, Info), Error> {
        let reached: Option<String> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT r.url FROM hub_urls u JOIN reach r ON r.hub = u.hub WHERE u.url = ?1",
                [url],
                |r| r.get(0),
            )
            .optional()?)
        })?;
        let url = reached.as_deref().unwrap_or(url);
        let info = self.info(url).await?;
        if let Keep::Visit(id) = keep {
            self.visitable(url, &info, id)?;
        }
        Ok((self.keep_info(url, &info, keep)?, info))
    }

    /// Refused unless the hub at `url`, saying `info` of itself, proves it
    /// is the hub of `id` and takes locks.
    fn visitable(&self, url: &str, info: &Info, id: HubId) -> Result<(), Error> {
        let proved = info.proved(self.network);
        if !proved.map_err(|p| Error::Invalid(format!("hub {url}: {}", p.message)))? {
            return Err(Error::Invalid(format!(
                "hub {url} proves no identity: only a hub added is paid at without"
            )));
        }
        if HubId::of(&info.address) != id {
            return Err(Error::Invalid(format!(
                "hub {url} is not the hub the code names"
            )));
        }
        if info.locks.is_none() {
            return Err(Error::Invalid(format!(
                "hub {url} follows no chain: no swap brings notes there"
            )));
        }
        Ok(())
    }

    /// The hub `hub` asked over HTTPS, at most once since the wallet was
    /// opened, if reached over plain HTTP: what it says there, if it is
    /// the same hub, reached there from now on.
    async fn secure(&self, hub: i64) -> Option<Info> {
        let reached = self.reached(hub).ok()?;
        let url = secure_url(&reached)?;
        if !self.asked_secure.lock().ok()?.insert(hub) {
            return None;
        }
        let info = match self.info(&url).await {
            Ok(info) => info,
            Err(e) => {
                tracing::debug!(%url, "hub not reached over HTTPS: {e}");
                return None;
            }
        };
        // Not keysets all new to the wallet: another hub, or one it would
        // take as a hub of its own.
        let known = self.keysets(hub).ok()?;
        let theirs = info.keysets().ok()?;
        if !theirs
            .iter()
            .any(|k| known.iter().any(|o| o.id() == k.id()))
        {
            tracing::warn!(%url, http = %reached, "another hub over HTTPS than over HTTP");
            return None;
        }
        // Only adding a hub asks: the owner's.
        match self.keep_info(&url, &info, Keep::Add) {
            Ok(kept) if kept == hub => Some(info),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(%url, "hub not reached over HTTPS: {e}");
                None
            }
        }
    }

    /// The URL the wallet reaches the hub `hub` at.
    fn reached(&self, hub: i64) -> Result<String, Error> {
        self.store
            .read(|c| Ok(c.query_row("SELECT url FROM reach WHERE hub = ?1", [hub], |r| r.get(0))?))
    }

    /// What the hub at `url` says of itself, if it follows the wallet's
    /// network.
    async fn info(&self, url: &str) -> Result<Info, Error> {
        let info: Info = self.get(url, licash_api::INFO).await?;
        if let Some(locks) = &info.locks {
            let profile = locks
                .checkpoint()
                .map_err(|p| unavailable(url, p))?
                .profile();
            if profile != self.network {
                return Err(Error::Invalid(format!(
                    "hub {url} follows {profile}, not this wallet's network, {}",
                    self.network
                )));
            }
        }
        // A proof of another identity: not the hub's info, whoever made it.
        info.proved(self.network)
            .map_err(|p| Error::Invalid(format!("hub {url}: {}", p.message)))?;
        Ok(info)
    }

    /// Keep `info`, what the hub at `url` says of itself: its id. A keyset
    /// belongs to the hub that first advertised it: another URL advertising
    /// it is not that hub, unless it is the URL the hub is reached at, over
    /// HTTPS rather than plain HTTP. The hub is reached there from then on,
    /// and still known at the other URL. A hub known, added or visited,
    /// stays the one it proved it is: what it says is kept only with the
    /// proof of that identity, and a hub new to the wallet only with one.
    fn keep_info(&self, url: &str, info: &Info, keep: Keep) -> Result<i64, Error> {
        let keysets = info.keysets().map_err(|p| unavailable(url, p))?;
        let text = serde_json::to_string(info).map_err(invalid)?;
        let proved = info.proved(self.network).unwrap_or(false);
        let hub = self.store.write(|tx| {
            let mut known: Option<i64> = tx
                .query_row("SELECT hub FROM hub_urls WHERE url = ?1", [url], |r| {
                    r.get(0)
                })
                .optional()?;
            let mut others: Vec<(i64, String)> = Vec::new();
            for keyset in &keysets {
                let other = tx
                    .query_row(
                        "SELECT r.hub, r.url FROM keysets k JOIN reach r ON r.hub = k.hub
                         WHERE k.id = ?1 AND k.hub IS NOT ?2",
                        params![keyset.id(), known],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                if let Some(other) = other.filter(|o| !others.contains(o)) {
                    others.push(other);
                }
            }
            // A hub visited, the same, at a URL the owner adds or another
            // code names: reached there from now on, its identity proven.
            let adopted = match (known, others.as_slice()) {
                (None, [(hub, _)]) if keep != Keep::Refresh => {
                    let (trusted, kept) = kept_hub(tx, *hub)?;
                    !trusted && HubId::of(&kept.address) == HubId::of(&info.address)
                }
                _ => false,
            };
            match (known, others.as_slice()) {
                (_, []) => {}
                (None, [(hub, other)])
                    if adopted || secure_url(other).as_deref() == Some(url) =>
                {
                    // The row's id keeps the URL first, the one reached.
                    tx.execute(
                        "UPDATE hub_urls SET url = ?1 WHERE url = ?2",
                        params![url, other],
                    )?;
                    tx.execute(
                        "INSERT INTO hub_urls (url, hub) VALUES (?1, ?2)",
                        params![other, hub],
                    )?;
                    match adopted {
                        true => tracing::info!(%url, %other, "hub visited reached here from now on"),
                        false => tracing::info!(%url, http = %other, "hub reached over HTTPS from now on"),
                    }
                    known = Some(*hub);
                }
                (_, [(_, other), ..]) => {
                    return Err(Error::Invalid(format!(
                        "hub {url} advertises a keyset of hub {other}"
                    )));
                }
            }
            let hub = match known {
                Some(hub) => {
                    let (trusted, kept) = kept_hub(tx, hub)?;
                    // Unavailable, not invalid: what is under way there
                    // waits for it to prove it again.
                    if !proved || HubId::of(&kept.address) != HubId::of(&info.address) {
                        return Err(unavailable(url, "no longer proves it is the hub known there"));
                    }
                    tx.execute(
                        "UPDATE hubs SET info = ?2, updated_at = ?3, trusted = ?4 WHERE id = ?1",
                        params![hub, text, now(), trusted || keep == Keep::Add],
                    )?;
                    hub
                }
                None => {
                    // Its keysets are its own by its proof alone: without
                    // one, nothing tells them from another server's later.
                    if !proved {
                        return Err(Error::Invalid(format!("hub {url} proves no identity")));
                    }
                    let trusted = !matches!(keep, Keep::Visit(_));
                    tx.execute(
                        "INSERT INTO hubs (info, updated_at, trusted) VALUES (?1, ?2, ?3)",
                        params![text, now(), trusted],
                    )?;
                    let hub = tx.last_insert_rowid();
                    tx.execute(
                        "INSERT INTO hub_urls (url, hub) VALUES (?1, ?2)",
                        params![url, hub],
                    )?;
                    hub
                }
            };
            for keyset in &keysets {
                tx.execute(
                    "INSERT INTO keysets (id, hub, bytes) VALUES (?1, ?2, ?3)
                     ON CONFLICT DO NOTHING",
                    params![keyset.id(), hub, keyset.to_bytes()],
                )?;
            }
            Ok(hub)
        })?;
        tracing::info!(%url, keysets = keysets.len(), "hub info");
        Ok(hub)
    }

    /// Refused if the hub at `url` is one only visited: what only the
    /// owner's hubs are asked for, whose terms its proof does not cover.
    fn not_visited(&self, url: &str) -> Result<(), Error> {
        let trusted: Option<bool> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT h.trusted FROM hub_urls u JOIN hubs h ON h.id = u.hub WHERE u.url = ?1",
                [url],
                |r| r.get(0),
            )
            .optional()?)
        })?;
        match trusted {
            Some(false) => Err(Error::Invalid(format!(
                "hub {url} is only visited, to pay at: add it first"
            ))),
            _ => Ok(()),
        }
    }

    /// The hub at `url`: its id and what it last said of itself.
    fn hub(&self, url: &str) -> Result<(i64, Info), Error> {
        let row: Option<(i64, String)> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT h.id, h.info FROM hub_urls u JOIN hubs h ON h.id = u.hub
                 WHERE u.url = ?1",
                [url],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
        })?;
        let (hub, info) = row.ok_or_else(|| Error::UnknownHub(url.to_owned()))?;
        Ok((hub, serde_json::from_str(&info).map_err(invalid)?))
    }

    fn keysets(&self, hub: i64) -> Result<Vec<Keyset>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare("SELECT bytes FROM keysets WHERE hub = ?1")?;
            let rows = stmt.query_map([hub], |r| r.get::<_, Vec<u8>>(0))?;
            rows.map(|bytes| Ok(Keyset::from_bytes(&bytes?)?)).collect()
        })
    }

    async fn get<A: DeserializeOwned>(&self, hub: &str, path: &str) -> Result<A, Error> {
        self.exchange(hub, path, None).await
    }

    async fn post<A: DeserializeOwned>(
        &self,
        hub: &str,
        path: &str,
        body: &impl Serialize,
    ) -> Result<A, Error> {
        let body = serde_json::to_vec(body).map_err(invalid)?;
        self.exchange(hub, path, Some(body)).await
    }

    async fn exchange<A: DeserializeOwned>(
        &self,
        hub: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<A, Error> {
        let response = self
            .transport
            .request(&format!("{hub}{path}"), body)
            .await
            .map_err(|reason| unavailable(hub, reason))?;
        answer(hub, path, &response)
    }
}

/// What the hub at `hub` answered at `path`: its body, or its problem.
fn answer<A: DeserializeOwned>(hub: &str, path: &str, response: &Response) -> Result<A, Error> {
    if (200..300).contains(&response.status) {
        return serde_json::from_slice(&response.body)
            .map_err(|e| unavailable(hub, format!("{path}: {e}")));
    }
    match serde_json::from_slice::<Problem>(&response.body) {
        Ok(problem) if problem.code != Code::Unavailable => Err(Error::Refused {
            hub: hub.to_owned(),
            problem,
        }),
        Ok(problem) => Err(unavailable(hub, problem.message)),
        Err(_) => Err(unavailable(
            hub,
            format!("{path}: status {}", response.status),
        )),
    }
}

/// Payments made.
impl<T: Transport> Wallet<T> {
    /// Pay `amount` to `payee` through the hub at `url`, the hub's fee on
    /// top. A hub that refuses the fee it advertised is asked again for its
    /// fees, and paid them, once.
    pub async fn send(&self, url: &str, payee: &Address, amount: u64) -> Result<Paid, Error> {
        self.send_with(url, payee, amount, None, None, None).await
    }

    /// [`Wallet::send`], its hub asked to keep the payment for its payee if
    /// `delivered`, then mailed to the payee's mailbox it holds, if any,
    /// unless the payee collects it ([`delivery`]), with `note` if any.
    /// Refused as [`Error::FeeRose`], nothing paid, if its fee would pass
    /// `max_fee`, the new fees of a hub refusing the first included.
    pub(crate) async fn send_with(
        &self,
        url: &str,
        payee: &Address,
        amount: u64,
        delivered: Option<Option<[u8; 32]>>,
        note: Option<&PaymentNote>,
        max_fee: Option<u64>,
    ) -> Result<Paid, Error> {
        let url = hub_url(url)?;
        if amount == 0 {
            return Err(Error::Invalid("nothing to pay".into()));
        }
        let once = || self.send_once(&url, payee, amount, delivered, None, note, max_fee);
        match once().await {
            Err(Error::Refused { problem, .. }) if problem.code == Code::Fee => {
                tracing::info!(%url, %problem, "fees changed, paying the new ones");
                self.refresh(&url).await?;
                once().await
            }
            sent => sent,
        }
    }

    /// One payment, under `key` if given, recorded with it, refused if its
    /// fee passes `max_fee`. One to a code
    /// (`delivered`) goes with a note, sealed to the size of any other and
    /// saying `note` if any, unless the wallet's file keeps another
    /// version of notes: kept by its hub with it too if the hub says it
    /// does.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_once(
        &self,
        url: &str,
        payee: &Address,
        amount: u64,
        delivered: Option<Option<[u8; 32]>>,
        key: Option<[u8; 32]>,
        note: Option<&PaymentNote>,
        max_fee: Option<u64>,
    ) -> Result<Paid, Error> {
        let (hub, info) = self.hub(url)?;
        let noted = delivered.is_some() && self.notes_on()?;
        let fees = self.agreed_fees(hub, url, &info)?;
        let (keyset, plan) = self.payment_plan(hub, amount, &fees)?;
        let selection = plan.selection;
        if let Some(agreed) = max_fee.filter(|most| selection.fee > *most) {
            let asked = selection.fee;
            return Err(Error::FeeRose {
                who: url.to_owned(),
                agreed,
                asked,
                reason: format!("hub {url} asks {asked} sat to pay {amount}, more than {agreed}"),
            });
        }
        let inputs = self.notes_of(&keyset, &selection.inputs)?;
        let me = self.address();
        let ephemeral = Ephemeral::random();
        let parts = [
            (payee, denominations(&keyset, amount)?),
            (&info.address, denominations(&keyset, selection.fee)?),
            (&me, plan.change),
        ];
        let outputs = denominated_outputs(&ephemeral, Branch::Pay, &parts)?;
        let proposal = Proposal::new(&keyset, &inputs, ephemeral.public(), outputs, None)?;
        let id = proposal.id();
        let offer = self.offer_of(&keyset, &proposal, &inputs)?;
        let offer = serde_json::to_string(&offer).map_err(invalid)?;
        let shared = match delivered {
            Some(_) => Some(ephemeral.shared(payee)?),
            None => None,
        };
        let note = note.cloned().unwrap_or_default();
        let sealed = match shared {
            Some(shared) if noted => Some(self.seal_note(&shared, &id, payee, &note)?),
            _ => None,
        };
        self.store.write(|tx| {
            tx.execute(
                "INSERT INTO sends (id, hub, payee, amount, fee, offer, created_at, key)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id.as_bytes(),
                    hub,
                    payee.to_bytes(),
                    sql(amount)?,
                    sql(selection.fee)?,
                    offer,
                    now(),
                    key
                ],
            )?;
            if let (Some(mailbox), Some(shared)) = (delivered, shared) {
                delivery::record(tx, &id, mailbox, &shared)?;
            }
            if let Some(sealed) = &sealed {
                let keep = payment_note::kept_by(&info);
                payment_note::record_sent(tx, &id, sealed, keep, &note)?;
            }
            take(tx, &id, Spender::Send, &selection.inputs)
        })?;
        let key = hex::encode(id.as_bytes());
        tracing::info!(id = %key, %url, amount, fee = selection.fee, "sending");
        self.advance(&id).await
    }

    /// The wallet's notes `ys` of `keyset`.
    fn notes_of(&self, keyset: &Keyset, ys: &[[u8; 33]]) -> Result<Vec<Note>, Error> {
        self.store
            .read(|c| ys.iter().map(|y| Ok(held(c, keyset, y)?.note)).collect())
    }

    /// The notes of one keyset of `hub` that pay `amount` and `fee`, on
    /// them and on the notes `amount` and the change are made in.
    fn select(
        &self,
        hub: i64,
        amount: u64,
        fee: &licash_api::NoteFee,
    ) -> Result<(Keyset, coins::Selection<[u8; 33]>), Error> {
        let mut short = Error::Insufficient {
            needed: amount.saturating_add(fee.due(amount, 0)),
            available: 0,
        };
        let mut keysets = self.keysets(hub)?;
        let notes = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT y, keyset, denom FROM notes
                 WHERE spent_by IS NULL AND session IS NULL AND gone_at IS NULL",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, [u8; 33]>(0)?,
                    r.get::<_, [u8; 32]>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?;
        let of = |keyset: &Keyset| {
            notes
                .iter()
                .filter(|(_, id, _)| id == keyset.id())
                .map(|&(y, _, denom)| (denom as u64, y))
                .collect::<Vec<_>>()
        };
        keysets.sort_by_cached_key(|k| Reverse(of(k).iter().map(|n| n.0).sum::<u64>()));
        for keyset in keysets {
            let held = of(&keyset);
            match coins::select(&held, amount, fee, |value| made(&keyset, value)) {
                Ok(selection) => return Ok((keyset, selection)),
                Err(needed) => {
                    if let Error::Insufficient { available: 0, .. } = short {
                        let available = held.iter().take(MAX_INPUTS).map(|n| n.0).sum();
                        short = Error::Insufficient { needed, available };
                    }
                }
            }
        }
        Err(short)
    }

    /// Take send `id` on from where it stands: ask for its offer, sign it,
    /// ask for its release, then keep its change. Refused only if given up
    /// here; any other failure leaves it pending.
    async fn advance(&self, id: &ProposalId) -> Result<Paid, Error> {
        let pending = |e: Error| match e {
            Error::Refused { .. } | Error::Pending { .. } | Error::Abandoned { .. } => e,
            e => Error::Pending {
                id: hex::encode(id.as_bytes()),
                reason: e.to_string(),
            },
        };
        self.advance_from(id).await.map_err(pending)
    }

    async fn advance_from(&self, id: &ProposalId) -> Result<Paid, Error> {
        type Row = (
            i64,
            String,
            String,
            Option<String>,
            Option<[u8; 32]>,
            Option<String>,
        );
        let row: Row = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT s.hub, r.url, s.offer, s.release, s.unlock, s.abandoned
                 FROM sends s JOIN reach r ON r.hub = s.hub WHERE s.id = ?1",
                [id.as_bytes()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )?)
        })?;
        let (hub, url, offer, release, mut unlock, abandoned) = row;
        let keep = self.store.read(|c| delivery::keep(c, id))?;
        let sealed_note = self.store.read(|c| payment_note::sealed(c, id))?;
        let sealed_note = sealed_note.map(|(sealed, _)| sealed);
        if let Some(reason) = abandoned {
            return Err(Error::Abandoned {
                id: hex::encode(id.as_bytes()),
                reason,
            });
        }
        let keysets = self.keysets(hub)?;
        let lookup = |id: &[u8; 32]| keysets.iter().find(|k| k.id() == id);
        let offer: Offer = serde_json::from_str(&offer).map_err(invalid)?;
        let mut release: Release = match release {
            Some(release) => serde_json::from_str(&release).map_err(invalid)?,
            None => self.sign(&url, id, &offer, lookup).await?,
        };
        let mut offered_again = false;
        let (signed, notes, keyset, unlock, kept) = loop {
            let (signed, notes) = release.decode(lookup).map_err(invalid)?;
            let keyset = lookup(signed.proposal().keyset_id()).ok_or_else(|| {
                Error::Invalid("a send under a keyset its hub no longer has".into())
            })?;
            let Authorization::Granted(grant) = signed.authorization() else {
                return Err(Error::Invalid("a send without a grant".into()));
            };
            // Whether its hub keeps it for its payee, if asked here.
            let (unlock, kept) = match unlock {
                Some(unlock) => (unlock, None),
                None => match self
                    .release(&url, id, &release, keep.clone(), keyset, grant)
                    .await
                {
                    Ok((unlock, kept)) => (unlock, Some(kept)),
                    // Its hub forgot the offer, left unreleased long: offered
                    // and signed again, once.
                    Err(Error::Refused { problem, .. })
                        if problem.code == Code::UnknownOffer && !offered_again =>
                    {
                        offered_again = true;
                        release = self.offer_again(&url, id, &offer, &release, lookup).await?;
                        continue;
                    }
                    Err(Error::Refused { problem, .. }) if problem.code == Code::UnknownOffer => {
                        return Err(Error::Pending {
                            id: hex::encode(id.as_bytes()),
                            reason: format!("hub {url} refused its release: {problem}"),
                        });
                    }
                    // Released already, as its hub proves: finished with
                    // the release and the unlock it shows.
                    Err(Error::Refused { problem, .. }) if problem.code == Code::Spent => {
                        let shown = self.spent_release(&url, id, problem).await?;
                        (release, unlock) = (shown.0, Some(shown.1));
                        continue;
                    }
                    Err(e) => return Err(e),
                },
            };
            break (signed, notes, keyset, unlock, kept);
        };
        let change = self
            .owner
            .scan_key()
            .receive(signed.proposal())?
            .into_iter()
            .map(|r| {
                let note = signed.open_granted_output(
                    keyset,
                    &notes,
                    r.position as usize,
                    &r.derivation,
                    &unlock,
                )?;
                Ok((r, note))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let ephemeral = signed.proposal().ephemeral();
        let inputs = (notes.iter())
            .map(|n| Ok(n.message().identifier()?.0))
            .collect::<Result<Vec<_>, Error>>()?;
        let kept = self.store.write(|tx| {
            tx.execute(
                "UPDATE sends SET unlock = ?2, done_at = COALESCE(done_at, ?3) WHERE id = ?1",
                params![id.as_bytes(), unlock, now()],
            )?;
            for (r, note) in &change {
                insert_note(tx, keyset, note, id, &ephemeral, r.branch, r.position)?;
            }
            claims::finished_while_claimed(tx, id, &inputs)?;
            delivery::released(tx, id, kept)
        })?;
        Ok(Paid {
            id: hex::encode(id.as_bytes()),
            payment: Payment::new(&url, &signed, &notes, &unlock).with_note(sealed_note),
            kept,
        })
    }

    /// Send `id` offered and signed again, its hub having forgotten the
    /// offer `release` was signed under: a hub deletes those left
    /// unreleased long. An honest hub can never release that signature
    /// now, its offer's salt gone, but one that kept it could: it is kept
    /// until the new one replaces it, and with the send if the new offer
    /// is refused, which gives the send up as [`Self::sign`]'s would.
    async fn offer_again<'k>(
        &self,
        url: &str,
        id: &ProposalId,
        offer: &Offer,
        release: &Release,
        keysets: impl Fn(&[u8; 32]) -> Option<&'k Keyset>,
    ) -> Result<Release, Error> {
        let signed = serde_json::to_string(release).map_err(invalid)?;
        self.sign_over(url, id, offer, keysets, Some(&signed)).await
    }

    /// The hub's offer for `offer`, signed and recorded: from then on the
    /// send is given up only once its hub proves an input spent otherwise
    /// ([`Self::spent_release`]). Refused, the send is given up.
    async fn sign<'k>(
        &self,
        url: &str,
        id: &ProposalId,
        offer: &Offer,
        keysets: impl Fn(&[u8; 32]) -> Option<&'k Keyset>,
    ) -> Result<Release, Error> {
        self.sign_over(url, id, offer, keysets, None).await
    }

    /// [`Self::sign`], in place of the release `over` if given, signed
    /// under an offer its hub forgot.
    async fn sign_over<'k>(
        &self,
        url: &str,
        id: &ProposalId,
        offer: &Offer,
        keysets: impl Fn(&[u8; 32]) -> Option<&'k Keyset>,
        over: Option<&str>,
    ) -> Result<Release, Error> {
        let (proposal, notes) = offer.decode(&keysets).map_err(invalid)?;
        let keyset = keysets(proposal.keyset_id())
            .ok_or_else(|| Error::Invalid("a send under a keyset its hub no longer has".into()))?;
        let grant = match self.post::<Offered>(url, licash_api::OFFER, offer).await {
            Ok(offered) => offered.decode().map_err(|p| unavailable(url, p))?,
            Err(Error::Refused { problem, .. }) => {
                let step = match over {
                    Some(_) => Step::Release,
                    None => Step::Offer,
                };
                return Err(self.refused(url, id, problem, step).await?);
            }
            Err(e) => return Err(e),
        };
        grant
            .verify(keyset, &proposal)
            .map_err(|e| unavailable(url, format!("its offer: {e}")))?;
        let signed = self.sign_as_owner(
            keyset,
            proposal,
            &notes,
            Authorization::Granted(Box::new(grant)),
        )?;
        let release = serde_json::to_string(&Release::new(&signed, &notes)).map_err(invalid)?;
        // Another process may have signed it first: its signature stands.
        let (release, abandoned): (String, Option<String>) = self.store.write(|tx| {
            tx.execute(
                "UPDATE sends SET release = ?2
                 WHERE id = ?1 AND (release IS NULL OR release = ?3)
                    AND unlock IS NULL AND abandoned IS NULL",
                params![id.as_bytes(), release, over],
            )?;
            Ok(tx.query_row(
                "SELECT COALESCE(release, ''), abandoned FROM sends WHERE id = ?1",
                [id.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })?;
        if let Some(reason) = abandoned {
            return Err(Error::Abandoned {
                id: hex::encode(id.as_bytes()),
                reason,
            });
        }
        serde_json::from_str(&release).map_err(invalid)
    }

    /// The hub's unlock for the signed `release`, checked to open its
    /// grant, and whether it keeps the payment for its payee, asked to if
    /// `keep`. A hub that says an input is spent, or that it forgot its
    /// offer, is refused as such, for the caller to ask what it proves
    /// ([`Self::spent_release`]) or to offer it again. Any other refusal
    /// leaves it pending.
    async fn release(
        &self,
        url: &str,
        id: &ProposalId,
        release: &Release,
        keep: Option<licash_api::inbox::Keep>,
        keyset: &Keyset,
        grant: &Grant,
    ) -> Result<(Unlock, bool), Error> {
        let asked = keep.is_some();
        let release = licash_api::inbox::Release {
            release: release.clone(),
            keep,
        };
        let released = match self
            .post::<licash_api::inbox::Released>(url, licash_api::RELEASE, &release)
            .await
        {
            Ok(released) => released,
            // An input said spent, or its offer forgotten: the caller's.
            Err(Error::Refused { hub, problem })
                if matches!(problem.code, Code::Spent | Code::UnknownOffer) =>
            {
                return Err(Error::Refused { hub, problem });
            }
            Err(Error::Refused { problem, .. }) => {
                return Err(Error::Pending {
                    id: hex::encode(id.as_bytes()),
                    reason: format!("hub {url} refused its release: {problem}"),
                });
            }
            Err(e) => return Err(e),
        };
        let unlock = released
            .released
            .decode()
            .map_err(|p| unavailable(url, p))?;
        grant
            .verify_unlock(keyset, &unlock)
            .map_err(|e| unavailable(url, format!("its unlock: {e}")))?;
        Ok((unlock, asked && released.kept))
    }

    /// What the hub at `url` proves of the signed send `id` it refuses to
    /// release as spent, with `problem`. It holds her signature, so its
    /// word frees none of her notes:
    /// - the send released already, shown with its unlock: the release and
    ///   the unlock to finish it with, recorded (those of an offer it said
    ///   it forgot, [`Self::offer_again`], may be the ones it released);
    /// - an input spent otherwise, or claimed on Bitcoin: the send is
    ///   given up, as [`Self::refused`] gives one up, for its hub can
    ///   release it no more;
    /// - nothing: the send stays pending, its notes with it, as its hub
    ///   may release it yet.
    async fn spent_release(
        &self,
        url: &str,
        id: &ProposalId,
        problem: Problem,
    ) -> Result<(Release, Unlock), Error> {
        let shown = self.spent_inputs(url, id).await;
        let released = shown.payments.iter().find(|(spend, _)| spend == id);
        if let Some((_, payment)) = released {
            let unlock: Unlock = (payment.unlock.0.as_slice().try_into())
                .map_err(|_| unavailable(url, "an unlock of another width"))?;
            let release = serde_json::to_string(&payment.release).map_err(invalid)?;
            self.store.write(|tx| {
                tx.execute(
                    "UPDATE sends SET release = ?2
                     WHERE id = ?1 AND unlock IS NULL AND abandoned IS NULL",
                    params![id.as_bytes(), release],
                )?;
                Ok(())
            })?;
            return Ok((payment.release.clone(), unlock));
        }
        if shown.spent.is_empty() {
            return Err(Error::Pending {
                id: hex::encode(id.as_bytes()),
                reason: format!("hub {url} refused its release, proving no input spent: {problem}"),
            });
        }
        Err(self.given_up(url, id, problem, Step::Release, &shown)?)
    }

    /// Give payment `id` up on its hub's refusal `problem` of `step`, unless
    /// it went past it: its notes freed, but those the hub shows spent
    /// dropped. The error to answer with.
    ///
    /// Of a signed send, only one whose hub forgot its offer and refuses
    /// it again ([`Self::offer_again`]): its signature is kept, as its hub
    /// may have kept it too.
    pub(crate) async fn refused(
        &self,
        url: &str,
        id: &ProposalId,
        problem: Problem,
        step: Step,
    ) -> Result<Error, Error> {
        let shown = match problem.code == Code::Spent {
            true => self.spent_inputs(url, id).await,
            false => inquiry::Shown::default(),
        };
        // Its hub shows this very lock made: it is kept.
        if step == Step::Lock && shown.locks.iter().any(|(lock, _)| lock == id) {
            return Ok(Error::Pending {
                id: hex::encode(id.as_bytes()),
                reason: format!("hub {url} refused it, showing it made: {problem}"),
            });
        }
        self.given_up(url, id, problem, step, &shown)
    }

    /// [`Self::refused`], on what its hub showed of its notes.
    fn given_up(
        &self,
        url: &str,
        id: &ProposalId,
        problem: Problem,
        step: Step,
        shown: &inquiry::Shown,
    ) -> Result<Error, Error> {
        let reason = problem.to_string();
        if self.give_up(step, id, &reason, &shown.spent, &shown.locks)? {
            return Ok(Error::Refused {
                hub: url.to_owned(),
                problem,
            });
        }
        // Another process took it on, or gave it up, meanwhile.
        let abandoned: Option<String> = self
            .store
            .read(|c| Ok(c.query_row(step.abandoned(), [id.as_bytes()], |r| r.get(0))?))?;
        let id = hex::encode(id.as_bytes());
        Ok(match abandoned {
            Some(reason) => Error::Abandoned { id, reason },
            None => Error::Pending { id, reason },
        })
    }

    /// What its hub proves of the inputs of payment `id`: nothing if it
    /// cannot tell.
    async fn spent_inputs(&self, url: &str, id: &ProposalId) -> inquiry::Shown {
        let inputs = self.inputs_of(id);
        match inputs {
            Ok(inputs) => self.shown(url, &inputs).await,
            Err(e) => Err(e),
        }
        .unwrap_or_else(|e| {
            tracing::warn!(%url, error = %e, "cannot tell which notes are spent");
            inquiry::Shown::default()
        })
    }

    /// Give payment `id` up at `step`, unless it went past it, and free its
    /// notes but drop those `gone`, save those spent by one of the wallet's
    /// own `locks` under way, which are that lock's.
    fn give_up(
        &self,
        step: Step,
        id: &ProposalId,
        reason: &str,
        gone: &[[u8; 33]],
        locks: &[(ProposalId, Vec<[u8; 33]>)],
    ) -> Result<bool, Error> {
        let given_up = self.store.write(|tx| {
            let given_up = tx.execute(step.give_up(), params![id.as_bytes(), reason])? == 1;
            if given_up {
                let locked = |y: &[u8; 33]| locks.iter().any(|(_, ys)| ys.contains(y));
                for y in gone.iter().filter(|y| !locked(y)) {
                    // Or a recovery's that took it from the payment: what
                    // it claims of it is the hub's to answer.
                    tx.execute(
                        "UPDATE notes SET gone_at = ?3
                         WHERE y = ?1 AND (spent_by = ?2 OR spent_kind = ?4) AND gone_at IS NULL",
                        params![y, id.as_bytes(), now(), Spender::Recovery.name()],
                    )?;
                }
                tx.execute(
                    "UPDATE notes SET spent_by = NULL, spent_kind = NULL WHERE spent_by = ?1",
                    [id.as_bytes()],
                )?;
                for (lock, ys) in locks.iter().filter(|(lock, _)| lock != id) {
                    inquiry::reserve_for_lock(tx, lock, ys)?;
                }
            }
            Ok(given_up)
        })?;
        if given_up {
            let id = hex::encode(id.as_bytes());
            tracing::warn!(%id, reason, gone = gone.len(), "payment given up");
        }
        Ok(given_up)
    }

    /// Finish every payment under way, or give up those their hubs refuse,
    /// and take every lock, invoice and swap under way on. Renewals of
    /// notes are no payment: [`Wallet::unlink`] finishes them.
    pub async fn resume(&self) -> Result<Resumed, Error> {
        let ids: Vec<([u8; 32], bool)> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT id, amount = 0 AND payee = ?1 FROM sends
                 WHERE done_at IS NULL AND abandoned IS NULL AND renewal = 0
                 ORDER BY created_at",
            )?;
            let rows =
                stmt.query_map([self.address().to_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut resumed = Resumed::default();
        for (id, optimization) in ids {
            let key = hex::encode(id);
            match self.advance(&ProposalId::from_bytes(id)).await {
                Ok(paid) if !optimization => resumed.paid.push(paid),
                Ok(_) => {}
                Err(Error::Refused { problem, .. }) => {
                    resumed.abandoned.push((key, problem.to_string()));
                }
                Err(Error::Abandoned { reason, .. }) => resumed.abandoned.push((key, reason)),
                Err(Error::Pending { reason, .. }) => resumed.pending.push((key, reason)),
                Err(e) => resumed.pending.push((key, e.to_string())),
            }
        }
        let ids: Vec<[u8; 32]> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT id FROM locks
                 WHERE abandoned IS NULL AND id NOT IN (SELECT id FROM lock_settlements)
                 ORDER BY created_at",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        for id in ids {
            let key = hex::encode(id);
            match self.advance_lock(&ProposalId::from_bytes(id), None).await {
                Ok(lock) => resumed.locks.push(lock),
                Err(Error::Refused { problem, .. }) => {
                    resumed.abandoned.push((key, problem.to_string()));
                }
                Err(Error::Abandoned { reason, .. }) => resumed.abandoned.push((key, reason)),
                Err(Error::Pending { reason, .. }) => resumed.pending.push((key, reason)),
                Err(e) => resumed.pending.push((key, e.to_string())),
            }
        }
        for hash in self.open_invoices()? {
            match self.advance_invoice(&hash).await {
                Ok(invoice) => resumed.invoices.push(invoice),
                Err(Error::Pending { reason, .. }) => {
                    resumed.pending.push((hex::encode(hash), reason));
                }
                Err(e) => resumed.pending.push((hex::encode(hash), e.to_string())),
            }
        }
        for hash in self.open_deposits()? {
            match self.advance_deposit(&hash).await {
                Ok(deposit) => resumed.deposits.push(deposit),
                Err(Error::Pending { reason, .. }) => {
                    resumed.pending.push((hex::encode(hash), reason));
                }
                Err(e) => resumed.pending.push((hex::encode(hash), e.to_string())),
            }
        }
        for hash in self.open_swaps()? {
            match self.advance_swap(&hash).await {
                Ok(swap) => resumed.swaps.push(swap),
                Err(Error::Pending { reason, .. }) => {
                    resumed.pending.push((hex::encode(hash), reason));
                }
                Err(e) => resumed.pending.push((hex::encode(hash), e.to_string())),
            }
        }
        Ok(resumed)
    }

    /// Finish the payment `id` under way, as [`Wallet::resume`] does each:
    /// given up if its hub refuses it.
    pub async fn finish_send(&self, id: &str) -> Result<Paid, Error> {
        self.advance(&payment_id(id)?).await
    }

    /// Give up the payment `id`, not signed yet, and free its notes: for a
    /// hub gone for good. A signed payment its hub may have released. The
    /// notes of a renewal given up are not renewed again.
    pub fn abandon(&self, id: &str) -> Result<(), Error> {
        let id = payment_id(id)?;
        let renewal: bool = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT EXISTS (SELECT 1 FROM sends WHERE id = ?1 AND renewal = 1)",
                [id.as_bytes()],
                |r| r.get(0),
            )?)
        })?;
        let ys = match renewal {
            true => self.inputs_of(&id)?,
            false => Vec::new(),
        };
        if self.give_up(Step::Offer, &id, "abandoned by its owner", &[], &[])? {
            return self.renewal_refused(&ys);
        }
        Err(Error::Invalid(
            "not a payment under way and unsigned: its hub may have released it".into(),
        ))
    }

    /// The payment `id`, once done, to hand its payee again.
    pub fn payment(&self, id: &str) -> Result<Payment, Error> {
        let key = id;
        let id = payment_id(id)?;
        type Row = (
            i64,
            String,
            Option<String>,
            Option<[u8; 32]>,
            Option<String>,
        );
        let row: Option<Row> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT s.hub, r.url, s.release, s.unlock, s.abandoned
                 FROM sends s JOIN reach r ON r.hub = s.hub WHERE s.id = ?1",
                [id.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?)
        })?;
        let (hub, url, release, unlock, abandoned) =
            row.ok_or_else(|| Error::UnknownPayment(key.to_owned()))?;
        let note = self.store.read(|c| payment_note::sealed(c, &id))?;
        let id = hex::encode(id.as_bytes());
        let (release, unlock) = match (release, unlock, abandoned) {
            (_, _, Some(reason)) => return Err(Error::Abandoned { id, reason }),
            (Some(release), Some(unlock), None) => (release, unlock),
            _ => {
                let reason = "under way".into();
                return Err(Error::Pending { id, reason });
            }
        };
        let release: Release = serde_json::from_str(&release).map_err(invalid)?;
        let keysets = self.keysets(hub)?;
        let (signed, notes) = release
            .decode(|id| keysets.iter().find(|k| k.id() == id))
            .map_err(invalid)?;
        let payment = Payment::new(&url, &signed, &notes, &unlock);
        Ok(payment.with_note(note.map(|(sealed, _)| sealed)))
    }

    /// The payments made, newest first.
    pub fn sends(&self) -> Result<Vec<Sent>, Error> {
        self.sends_under(None)
    }

    /// The payment made under `key` ([`Wallet::pay_code_keyed`]), if one
    /// was: where it stands decides what its payer does, whatever the call
    /// that made it returned.
    pub fn sent_by_key(&self, key: &[u8; 32]) -> Result<Option<Sent>, Error> {
        Ok(self.sends_under(Some(key))?.pop())
    }

    /// The payments made, latest first: those under `key` only if given.
    fn sends_under(&self, key: Option<&[u8; 32]>) -> Result<Vec<Sent>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT s.id, r.url, s.payee, s.amount, s.fee, s.release IS NOT NULL,
                    s.done_at IS NOT NULL, s.abandoned, s.created_at
                 FROM sends s JOIN reach r ON r.hub = s.hub
                 WHERE ?1 IS NULL OR s.key = ?1
                 ORDER BY s.created_at DESC, s.rowid DESC",
            )?;
            let rows = stmt.query_map([key], |r| {
                let state = match (r.get::<_, Option<String>>(7)?, r.get(6)?, r.get(5)?) {
                    (Some(reason), _, _) => State::Abandoned(reason),
                    (None, true, _) => State::Done,
                    (None, false, true) => State::Signed,
                    (None, false, false) => State::Offered,
                };
                Ok((
                    r.get::<_, [u8; 32]>(0)?,
                    r.get(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    state,
                    r.get(8)?,
                ))
            })?;
            rows.map(|row| {
                let (id, hub, payee, amount, fee, state, created_at) = row?;
                Ok(Sent {
                    id: hex::encode(id),
                    hub,
                    payee: Address::from_bytes(&payee)?,
                    amount: amount as u64,
                    fee: fee as u64,
                    state,
                    created_at,
                })
            })
            .collect()
        })
    }
}

/// Payments taken, unlinking and checking.
impl<T: Transport> Wallet<T> {
    /// Take `payment`: keep the notes it pays this wallet, its unlock
    /// checked to open them. It must be under a keyset of a hub added
    /// here, not only visited, as the wallet takes no hub's notes unasked.
    pub fn receive(&self, payment: &Payment) -> Result<Received, Error> {
        let opened = self.open_payment(payment)?;
        self.keep(
            &opened.keyset,
            opened.url,
            opened.signed.proposal(),
            &opened.ours,
            payment.note.as_ref(),
        )
    }

    /// [`Wallet::receive`], or what it took of `payment` if it did already:
    /// the same receipt however often it is given, its note kept if it
    /// came with one now.
    pub fn receive_once(&self, payment: &Payment) -> Result<Received, Error> {
        match self.receive(payment) {
            Err(Error::AlreadyReceived) => {}
            received => return received,
        }
        let opened = self.open_payment(payment)?;
        let pid = opened.signed.proposal().id();
        let kept: Option<(i64, i64)> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT amount, received_at FROM receipts WHERE id = ?1",
                [pid.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
        })?;
        let (amount, received_at) = kept.ok_or(Error::AlreadyReceived)?;
        Ok(Received {
            id: hex::encode(pid.as_bytes()),
            hub: opened.url,
            amount: amount as u64,
            received_at,
        })
    }

    /// The notes `payment` pays this wallet, opened, under a keyset of a
    /// hub added here.
    fn open_payment(&self, payment: &Payment) -> Result<Opened, Error> {
        let id: [u8; 32] = payment
            .release
            .keyset
            .0
            .as_slice()
            .try_into()
            .map_err(invalid)?;
        let known: Option<(Vec<u8>, String)> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT k.bytes, r.url FROM keysets k
                 JOIN hubs h ON h.id = k.hub AND h.trusted = 1
                 JOIN reach r ON r.hub = k.hub
                 WHERE k.id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
        })?;
        let (keyset, url) = known.ok_or_else(|| Error::UnknownHub(payment.hub.clone()))?;
        let keyset = Keyset::from_bytes(&keyset)?;
        let (signed, notes, unlock) = payment
            .decode(|id| (id == keyset.id()).then_some(&keyset))
            .map_err(invalid)?;
        let proposal = signed.proposal();
        let ours = self
            .owner
            .scan_key()
            .receive(proposal)?
            .into_iter()
            .map(|r| {
                let note = signed.open_granted_output(
                    &keyset,
                    &notes,
                    r.position as usize,
                    &r.derivation,
                    &unlock,
                )?;
                Ok((r, note))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Opened {
            keyset,
            url,
            signed,
            ours,
        })
    }

    /// Keep the notes `ours` of `proposal` paid this wallet, with a
    /// receipt: unless they are kept already. What its payer's sealed
    /// `note` says is kept either way, if anything.
    fn keep(
        &self,
        keyset: &Keyset,
        url: String,
        proposal: &Proposal,
        ours: &[(licash::address::Received, Note)],
        note: Option<&licash_api::Hex>,
    ) -> Result<Received, Error> {
        if ours.is_empty() {
            return Err(Error::PaysNothing);
        }
        let (pid, ephemeral) = (proposal.id(), proposal.ephemeral());
        let received_at = now();
        let amount = self.store.write(|tx| {
            let mut amount = 0u64;
            for (r, note) in ours {
                if insert_note(tx, keyset, note, &pid, &ephemeral, r.branch, r.position)? {
                    amount += note.message().denomination();
                }
            }
            if amount == 0 {
                return Err(Error::AlreadyReceived);
            }
            tx.execute(
                "INSERT INTO receipts (id, keyset, amount, received_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT DO NOTHING",
                params![pid.as_bytes(), keyset.id(), sql(amount)?, received_at],
            )?;
            Ok(amount)
        });
        if matches!(amount, Ok(_) | Err(Error::AlreadyReceived)) {
            self.keep_note(proposal, note);
        }
        let amount = amount?;
        let id = hex::encode(pid.as_bytes());
        tracing::info!(%id, amount, "received");
        Ok(Received {
            id,
            hub: url,
            amount,
            received_at,
        })
    }

    /// The notes the payment, lock or receipt `id` (in hex) spent, and
    /// those it made the wallet's, the largest first: none of either if it
    /// is none of the wallet's.
    pub fn operation_notes(&self, id: &str) -> Result<OperationNotes, Error> {
        let id = payment_id(id)?;
        self.store.read(|c| {
            let of = |column: &str| -> Result<Vec<NoteRecord>, Error> {
                let mut stmt = c.prepare(&format!(
                    "SELECT n.y, r.url, n.denom, n.proposal, n.spent_by, n.unlinked,
                        n.gone_at IS NOT NULL, n.added_at
                     FROM notes n JOIN keysets k ON k.id = n.keyset JOIN reach r ON r.hub = k.hub
                     WHERE n.{column} = ?1 ORDER BY n.denom DESC, n.added_at, n.y"
                ))?;
                let rows = stmt.query_map([id.as_bytes()], |r| {
                    Ok(NoteRecord {
                        id: hex::encode(r.get::<_, Vec<u8>>(0)?),
                        hub: r.get(1)?,
                        amount: r.get::<_, i64>(2)? as u64,
                        made_by: hex::encode(r.get::<_, Vec<u8>>(3)?),
                        spent_by: r.get::<_, Option<Vec<u8>>>(4)?.map(hex::encode),
                        unlinked: match r.get::<_, i64>(5)? {
                            1 => Unlinking::Unlinked,
                            -1 => Unlinking::StaysLinked,
                            _ => Unlinking::Linked,
                        },
                        gone: r.get(6)?,
                        added_at: r.get(7)?,
                    })
                })?;
                Ok(rows.collect::<Result<_, _>>()?)
            };
            Ok(OperationNotes {
                spent: of("spent_by")?,
                made: of("proposal")?,
            })
        })
    }

    /// What the notes the payment or lock `id` (in hex) spent pay: its
    /// payee, its hub's fee and what the wallet keeps, each in the notes
    /// made for it. A lock refunded pays its hub's refund fee and the rest
    /// back; one not settled yet, what it pays if paid. None for a receipt,
    /// for anything spending none of the wallet's notes, or once given up.
    pub fn operation_parts(&self, id: &str) -> Result<Vec<Part>, Error> {
        let id = payment_id(id)?;
        self.store.read(|c| {
            let id = id.as_bytes();
            // A proposal spends notes of one keyset, which makes its outputs.
            let keyset: Option<Vec<u8>> = c
                .query_row(
                    "SELECT k.bytes FROM notes n JOIN keysets k ON k.id = n.keyset
                     WHERE n.spent_by = ?1 LIMIT 1",
                    [id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(keyset) = keyset else {
                return Ok(Vec::new());
            };
            let keyset = Keyset::from_bytes(&keyset)?;
            let sum = |column: &str| -> rusqlite::Result<u64> {
                let sql = format!("SELECT COALESCE(SUM(denom), 0) FROM notes WHERE {column} = ?1");
                Ok(c.query_row(&sql, [id], |r| r.get::<_, i64>(0))? as u64)
            };
            let spent = sum("spent_by")?;
            let row = |r: &rusqlite::Row| -> rusqlite::Result<_> {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            };
            let of = |table: &str| {
                let sql = match table {
                    "locks" => {
                        "SELECT l.payee, l.amount, l.fee, s.branch, NULL FROM locks l
                         LEFT JOIN lock_settlements s ON s.id = l.id
                         WHERE l.id = ?1 AND l.abandoned IS NULL"
                    }
                    _ => {
                        "SELECT payee, amount, fee, NULL, offer FROM sends
                         WHERE id = ?1 AND abandoned IS NULL"
                    }
                };
                c.query_row(sql, [id], row).optional()
            };
            let operation = match of("sends")? {
                Some(send) => Some(send),
                None => of("locks")?,
            };
            let Some((payee, amount, fee, settled, offer)) = operation else {
                return Ok(Vec::new());
            };
            // Change may deliberately use more, smaller notes than the
            // greedy split. Read its exact denominations from the kept
            // proposal, including before the hub has released them.
            let change = match offer {
                Some(offer) => {
                    let offer: Offer = serde_json::from_str(&offer).map_err(invalid)?;
                    let proposal = Proposal::from_commitment_bytes(&offer.proposal.0)?;
                    let mut ours: Vec<_> = self
                        .owner
                        .scan_key()
                        .receive(&proposal)?
                        .into_iter()
                        .map(|r| r.derivation.message().denomination())
                        .collect();
                    if payee == self.address().to_bytes() {
                        // A user self-payment has both ordinary payment
                        // outputs and change to this same address.
                        for denom in denominations(&keyset, amount)? {
                            let at = ours.iter().position(|&d| d == denom).ok_or_else(|| {
                                Error::Invalid("a self-payment is missing an output".into())
                            })?;
                            ours.swap_remove(at);
                        }
                    }
                    ours.sort_unstable_by(|a, b| b.cmp(a));
                    Some(ours)
                }
                None => None,
            };
            let shares = match settled.as_deref() {
                // The refund branch: what came back is known, the rest the fee.
                Some("refund") => {
                    let kept = sum("proposal")?;
                    vec![
                        (PartTo::Hub, spent.saturating_sub(kept)),
                        (PartTo::Kept, kept),
                    ]
                }
                _ => vec![
                    (PartTo::Payee(Address::from_bytes(&payee)?), amount),
                    (PartTo::Hub, fee),
                    (PartTo::Kept, spent.saturating_sub(amount + fee)),
                ],
            };
            Ok(shares
                .into_iter()
                .filter(|(_, amount)| *amount > 0)
                .map(|(to, amount)| Part {
                    notes: match (&to, &change) {
                        (PartTo::Kept, Some(change)) => change.clone(),
                        _ => coins::split(amount, keyset.denominations()).unwrap_or_default(),
                    },
                    to,
                    amount,
                })
                .collect())
        })
    }

    /// The payments taken, newest first.
    pub fn receipts(&self) -> Result<Vec<Received>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT p.id, r.url, p.amount, p.received_at
                 FROM receipts p JOIN keysets k ON k.id = p.keyset JOIN reach r ON r.hub = k.hub
                 ORDER BY p.received_at DESC, p.rowid DESC",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(Received {
                    id: hex::encode(r.get::<_, [u8; 32]>(0)?),
                    hub: r.get(1)?,
                    amount: r.get::<_, i64>(2)? as u64,
                    received_at: r.get(3)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Unlink the notes held linked to their issuance, so that their hub
    /// cannot tell which payment one came from when it is spent. A note its
    /// hub refuses to unlink stays linked, but one it no longer unlinks
    /// since it restarted is renewed: paid to the wallet itself, for notes
    /// unlinked then, if the hub's fee on it is within the wallet's limit
    /// ([`Wallet::set_renew_limit`]). Once only: a renewal's notes stay
    /// linked if their hub restarted meanwhile. The notes of one payment
    /// are renewed together, apart from others', so that a renewal tells
    /// their hub nothing it did not know.
    ///
    /// The number of notes unlinked. On an error at a hub, its other notes
    /// are asked again next time, the other hubs' still now: the first
    /// error then.
    pub async fn unlink(&self) -> Result<usize, Error> {
        let hubs: Vec<(i64, String)> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT k.hub, r.url FROM notes n
                 JOIN keysets k ON k.id = n.keyset JOIN reach r ON r.hub = k.hub
                 WHERE n.spent_by IS NULL AND n.gone_at IS NULL
                    AND (n.unlinked = 0 OR n.stays_linked = ?1)
                 UNION
                 SELECT s.hub, r.url FROM sends s JOIN reach r ON r.hub = s.hub
                 WHERE s.renewal = 1 AND s.done_at IS NULL AND s.abandoned IS NULL
                 ORDER BY 2",
            )?;
            let rows =
                stmt.query_map([code_name(Code::Expired)], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut unlinked = 0;
        let mut failed = None;
        for (hub, url) in hubs {
            // Apart from what else the wallet asks of the hub: only once
            // there is something to unlink.
            match in_lane(Lane::Fresh, self.unlink_at(hub, &url)).await {
                Ok(n) => unlinked += n,
                Err(e) => {
                    tracing::info!(%url, %e, "notes stay linked for now");
                    failed.get_or_insert(e);
                }
            }
        }
        failed.map_or(Ok(unlinked), Err)
    }

    /// [`Wallet::unlink`] at the hub `hub`, reached at `url`.
    async fn unlink_at(&self, hub: i64, url: &str) -> Result<usize, Error> {
        let mut unlinked = self.unlink_linked(hub, url).await?;
        if self.renew(hub, url).await? {
            unlinked += self.unlink_linked(hub, url).await?;
        }
        Ok(unlinked)
    }

    /// Unlink the linked notes held at the hub `hub`, reached at `url`:
    /// those asked before first, to ask the same again.
    async fn unlink_linked(&self, hub: i64, url: &str) -> Result<usize, Error> {
        let todo: Vec<[u8; 33]> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT n.y FROM notes n JOIN keysets k ON k.id = n.keyset
                 WHERE k.hub = ?1 AND n.unlinked = 0 AND n.spent_by IS NULL
                    AND n.gone_at IS NULL
                 ORDER BY n.session IS NULL, n.added_at",
            )?;
            let rows = stmt.query_map([hub], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut todo = todo.into_iter();
        // The first alone: a hub not answering is asked nothing more.
        let Some(first) = todo.next() else {
            return Ok(0);
        };
        let first = self.unlink_one(url, &first).await?;
        let rest = each_at_most(UNLINKING_AT_ONCE, todo, |y| async move {
            self.unlink_one(url, &y).await
        });
        let unlinked = rest.await?.into_iter().filter(|&unlinked| unlinked).count();
        Ok(usize::from(first) + unlinked)
    }

    async fn unlink_one(&self, url: &str, y: &[u8; 33]) -> Result<bool, Error> {
        let row: Option<(Vec<u8>, Option<String>)> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT k.bytes, n.session FROM notes n JOIN keysets k ON k.id = n.keyset
                 WHERE n.y = ?1 AND n.unlinked = 0 AND n.spent_by IS NULL AND n.gone_at IS NULL",
                [y],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
        })?;
        let Some((keyset, session)) = row else {
            return Ok(false);
        };
        let keyset = Keyset::from_bytes(&keyset)?;
        let session: Session = match session {
            Some(session) => serde_json::from_str(&session).map_err(invalid)?,
            None => {
                let held = self.store.read(|c| held(c, &keyset, y))?;
                let session = Session::start(&keyset, &held.note, &self.derivation(&held)?)?;
                let text = serde_json::to_string(&session).map_err(invalid)?;
                let started = self.store.write(|tx| {
                    Ok(tx.execute(
                        "UPDATE notes SET session = ?2
                         WHERE y = ?1 AND session IS NULL AND unlinked = 0 AND spent_by IS NULL",
                        params![y, text],
                    )? == 1)
                })?;
                if !started {
                    return Ok(false);
                }
                session
            }
        };
        let answer = match self
            .post::<Unlinked>(url, licash_api::UNLINK, &Unlink::new(session.request()))
            .await
        {
            Ok(answer) => answer.decode().map_err(|p| unavailable(url, p))?,
            // It answers the same request the same: it will never unlink it.
            Err(Error::Refused { problem, .. }) => {
                tracing::info!(%url, %problem, "a note stays linked");
                self.stay_linked(y, Some(problem.code))?;
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        let note = match session.finish(&keyset, &answer) {
            Ok(note) if note.message().identifier()?.0 == *y => note,
            _ => {
                tracing::warn!(%url, "its unlink answer does not open: a note stays linked");
                self.stay_linked(y, None)?;
                return Ok(false);
            }
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE notes SET note = ?2, unlinked = 1, session = NULL, unlinked_at = ?3
                 WHERE y = ?1",
                params![y, note.to_bytes(), now()],
            )?;
            Ok(())
        })?;
        Ok(true)
    }

    /// Keep the note `y` linked for good: for the refusal `code`, if its
    /// hub refused to unlink it.
    fn stay_linked(&self, y: &[u8; 33], code: Option<Code>) -> Result<(), Error> {
        let why = code.map(code_name);
        self.store.write(|tx| {
            tx.execute(
                "UPDATE notes SET unlinked = -1, session = NULL, stays_linked = ?2
                 WHERE y = ?1 AND unlinked = 0",
                params![y, why],
            )?;
            Ok(())
        })
    }

    /// The offer of `proposal`, spending the wallet's `notes`, signed by
    /// each note's hold key: its owner's, which no one else knowing the
    /// notes, their payer say, can have its hub refuse ([`licash::offer`]).
    fn offer_of(
        &self,
        keyset: &Keyset,
        proposal: &Proposal,
        notes: &[Note],
    ) -> Result<Offer, Error> {
        let id = proposal.id();
        let holds = self.store.read(|c| {
            notes
                .iter()
                .map(|note| {
                    let held = held(c, keyset, &note.message().identifier()?.0)?;
                    let key = self.derivation(&held)?.hold_key(self.owner.hold_root())?;
                    Ok(licash::offer::sign(&id, note.message(), &key)?)
                })
                .collect::<Result<Vec<_>, Error>>()
        })?;
        Ok(Offer::held(proposal, notes, &holds))
    }

    /// `proposal`, spending the wallet's `notes`, signed by their owner.
    fn sign_as_owner(
        &self,
        keyset: &Keyset,
        proposal: Proposal,
        notes: &[Note],
        authorization: Authorization,
    ) -> Result<SignedProposal, Error> {
        let owners = self.store.read(|c| {
            notes
                .iter()
                .map(|note| {
                    let y = note.message().identifier()?.0;
                    let held = held(c, keyset, &y)?;
                    Ok(self
                        .derivation(&held)?
                        .ownership()
                        .owner_secret(self.owner.spend_secret())?)
                })
                .collect::<Result<Vec<_>, Error>>()
        })?;
        Ok(SignedProposal::sign(
            keyset,
            proposal,
            notes,
            authorization,
            &owners,
        )?)
    }

    fn derivation(&self, held: &Held) -> Result<Derivation, Error> {
        Ok(self.owner.scan_key().derive(
            &held.ephemeral,
            held.note.message().denomination(),
            held.branch,
            held.position as usize,
        )?)
    }
}

/// What spends a note: the kind of the id its `spent_by` holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Spender {
    Send,
    Lock,
    /// The recovery of a contract, which claims it.
    Recovery,
}

impl Spender {
    fn name(self) -> &'static str {
        match self {
            Spender::Send => "send",
            Spender::Lock => "lock",
            Spender::Recovery => "recovery",
        }
    }
}

/// Take the notes `ys` for payment `id`, which `by` says what is: none
/// taken if another payment took one meanwhile.
fn take(tx: &Transaction<'_>, id: &ProposalId, by: Spender, ys: &[[u8; 33]]) -> Result<(), Error> {
    for y in ys {
        let taken = tx.execute(
            "UPDATE notes SET spent_by = ?1, spent_kind = ?3
             WHERE y = ?2 AND spent_by IS NULL AND session IS NULL AND gone_at IS NULL",
            params![id.as_bytes(), y, by.name()],
        )?;
        if taken != 1 {
            return Err(Error::NoteTaken);
        }
    }
    Ok(())
}

/// The outputs of a lock's pay branch paying `amount` to `to`, under
/// `keyset`, derived from `ephemeral`, as a wallet paying `to` makes them:
/// the same for the same `ephemeral`, so that whoever kept it can tell them
/// again.
pub fn pay_outputs(
    keyset: &Keyset,
    ephemeral: &Ephemeral,
    to: &Address,
    amount: u64,
) -> Result<Vec<Output>, Error> {
    outputs(keyset, ephemeral, Branch::Pay, &[(to, amount)])
}

/// How many notes [`outputs`] makes of `value` under `keyset`: what a fee
/// on the notes made counts.
fn made(keyset: &Keyset, value: u64) -> usize {
    coins::split(value, keyset.denominations()).map_or(0, |notes| notes.len())
}

/// The outputs of `branch` paying each of `parts` its value, under
/// `keyset`, derived from `ephemeral`: largest first, and equal ones in
/// random order, so that their order tells no one whose they are.
fn outputs(
    keyset: &Keyset,
    ephemeral: &Ephemeral,
    branch: Branch,
    parts: &[(&Address, u64)],
) -> Result<Vec<Output>, Error> {
    let parts = parts
        .iter()
        .map(|&(to, value)| Ok((to, denominations(keyset, value)?)))
        .collect::<Result<Vec<_>, Error>>()?;
    denominated_outputs(ephemeral, branch, &parts)
}

/// The minimum-note representation of `value`, or why it cannot be made.
fn denominations(keyset: &Keyset, value: u64) -> Result<Vec<u64>, Error> {
    coins::split(value, keyset.denominations())
        .ok_or_else(|| Error::Invalid(format!("the keyset cannot make {value}")))
}

/// Construct exactly the planned denominations, retaining the common
/// largest-first and randomized equal-denomination ordering.
fn denominated_outputs(
    ephemeral: &Ephemeral,
    branch: Branch,
    parts: &[(&Address, Vec<u64>)],
) -> Result<Vec<Output>, Error> {
    let mut outputs = Vec::new();
    for (to, denoms) in parts {
        outputs.extend(denoms.iter().map(|&denom| (OsRng.next_u64(), denom, *to)));
    }
    outputs.sort_by_key(|&(order, denom, _)| (Reverse(denom), order));
    Ok(outputs
        .iter()
        .enumerate()
        .map(|(position, &(_, denom, to))| {
            Output::from_derivation(&ephemeral.derive(to, denom, branch, position)?)
        })
        .collect::<Result<Vec<_>, _>>()?)
}

fn held(c: &Connection, keyset: &Keyset, y: &[u8]) -> Result<Held, Error> {
    let (note, ephemeral, branch, position): (Vec<u8>, [u8; 33], i64, u32) = c.query_row(
        "SELECT note, ephemeral, branch, position FROM notes WHERE y = ?1 AND keyset = ?2",
        params![y, keyset.id()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    Ok(Held {
        note: Note::from_bytes(keyset, &note)?,
        ephemeral: Point(ephemeral),
        branch: match branch {
            0 => Branch::Pay,
            _ => Branch::Refund,
        },
        position,
    })
}

/// Keep `note`, made at `position` of `branch` of proposal `proposal`
/// with ephemeral key `ephemeral`. False if it is kept already.
fn insert_note(
    tx: &Transaction<'_>,
    keyset: &Keyset,
    note: &Note,
    proposal: &ProposalId,
    ephemeral: &Point,
    branch: Branch,
    position: u32,
) -> Result<bool, Error> {
    let branch = match branch {
        Branch::Pay => 0,
        Branch::Refund => 1,
    };
    let inserted = tx.execute(
        "INSERT INTO notes (y, keyset, denom, note, proposal, ephemeral, branch, position, added_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT DO NOTHING",
        params![
            note.message().identifier()?.0,
            keyset.id(),
            sql(note.message().denomination())?,
            note.to_bytes(),
            proposal.as_bytes(),
            ephemeral.0,
            branch,
            position,
            now()
        ],
    )?;
    Ok(inserted == 1)
}

fn payment_id(id: &str) -> Result<ProposalId, Error> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(id, &mut bytes)
        .map_err(|_| Error::Invalid(format!("not a payment id: {id}")))?;
    Ok(ProposalId::from_bytes(bytes))
}

fn unavailable(hub: &str, reason: impl std::fmt::Display) -> Error {
    Error::Unavailable {
        hub: hub.to_owned(),
        reason: reason.to_string(),
    }
}

/// A hub's URL as the wallet keys it: http or https, no trailing slash.
fn hub_url(url: &str) -> Result<String, Error> {
    let url = url.trim().trim_end_matches('/');
    if !(url.starts_with("http://") || url.starts_with("https://"))
        || url.contains(char::is_whitespace)
    {
        return Err(Error::Invalid(format!("not a hub URL: {url}")));
    }
    Ok(url.to_owned())
}

/// The hub URL `url`, of plain HTTP, over HTTPS instead: not of an onion
/// service, which Tor authenticates already.
fn secure_url(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let host = rest.split(['/', ':']).next().unwrap_or(rest);
    (!host.ends_with(".onion")).then(|| format!("https://{rest}"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// A task that yields a few times, counting those under way at once.
    async fn counted(under_way: &AtomicUsize, most: &AtomicUsize, fails: bool) -> Result<u8, u8> {
        let now = under_way.fetch_add(1, Ordering::SeqCst) + 1;
        most.fetch_max(now, Ordering::SeqCst);
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        under_way.fetch_sub(1, Ordering::SeqCst);
        if fails {
            Err(1)
        } else {
            Ok(1)
        }
    }

    #[tokio::test]
    async fn each_runs_with_at_most_so_many_under_way() {
        let (under_way, most) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let ran = each_at_most(4, 0..11, |_| counted(&under_way, &most, false));
        assert_eq!(ran.await, Ok(vec![1; 11]));
        assert_eq!(most.load(Ordering::SeqCst), 4);
        let none = each_at_most(4, 0..0, |_| counted(&under_way, &most, false));
        assert_eq!(none.await, Ok(vec![]));
    }

    #[tokio::test]
    async fn none_starts_once_one_failed_those_under_way_finishing() {
        let (under_way, most) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let started = AtomicUsize::new(0);
        let ran = each_at_most(2, 0..10, |i| {
            started.fetch_add(1, Ordering::SeqCst);
            counted(&under_way, &most, i == 2)
        });
        assert_eq!(ran.await, Err(1));
        // 0 and 1 done, then 2 failed with 3 under way, which finished.
        assert_eq!(started.load(Ordering::SeqCst), 4);
        assert_eq!(under_way.load(Ordering::SeqCst), 0);
    }
}
