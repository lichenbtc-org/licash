//! The hub's side of openings: its [`Offer`], each opening kept in
//! the hub's database, F funded and signed by its node's wallet, and the
//! routes a holder reaches it at ([`router`]).
//!
//! Each opening is one machine, stepped by one task at a time. A step is
//! stored before its effects run, and an effect's result (F funded, F
//! signed) is stored as the step it feeds: the holder sending a message
//! again gets the answer the stored machine gives ([`Hub::pending`]), and
//! effects cut short by a restart run again then.

mod chain;
mod dispute;
mod fold;
mod funded;
mod node;
mod prover;
mod responses;
mod run;
mod store;
pub mod terms;
mod witness;

pub use witness::Witnesses;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{ensure, Context as _, Result};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path as UrlPath, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
pub use dispute::{Claims, Evidencer, Found, LockCheckpoints, Played};
pub use fold::FoldLedger;
pub use funded::{FundedIssue, Issuer, FUNDED_DEPTH};
/// How the hub tells its operator what needs them ([`Openings::alert_with`]).
pub type Alert = dyn Fn(&str) + Send + Sync;

/// Binds the deposit paid to a script to a contract, whose default pays it
/// the reserve, the hub keeping a fee of it, timing out at a height:
/// `(script, contract, reserve, fee, timeout)`. Refused, with why, unless
/// it is the hub's, asked for just so.
pub type Closer = dyn Fn(&[u8], [u8; 32], u64, u64, u32) -> Result<(), String> + Send + Sync;

/// Gives up the deposit bound to a contract whose opening was given up,
/// unless a payment was seen for it.
pub type Releaser = dyn Fn(&[u8; 32]) + Send + Sync;
use futures_util::StreamExt;
use licash::chain::Checkpoint;
use licash::note::Keyset;
use licash::spend::ChainProfile;
use licash_chain_client::Source;
pub use licash_contract::opening::HubPhase;
use licash_contract::opening::{Context, Hub, Trust};

use crate::{
    Frame, Offer, EVIDENCE, FOLD, FOLD_CLAIM, FOLD_SIGN, FUNDED, INSTANCE, MAX_BODY, OPEN, PROOF,
    QUOTE, STEP,
};
use store::Store;
use terms::{Range, Timing};

/// The most openings short of the hub's signatures at once.
pub const MAX_UNDER_WAY: usize = 16;

/// The most contracts live at once by default: signed and not ended, or
/// under way. Past half of them, the hub's fee doubles at each eighth more
/// ([`terms::step`]), so that the half it can prove the exits of at once
/// with room to spare pays for the hardware the rest need. Sized for a
/// prover with a GPU; [`Openings::limit_live`] sets another.
pub const MAX_LIVE: usize = 32;

/// The most openings signed whose F is in no block, as the responder last
/// saw, before new ones are refused: each holds coins of the hub's locked
/// until it confirms or is made never to (a day after the hub first saw
/// it unconfirmed).
pub const MAX_UNFUNDED: usize = 16;

/// The most steps of openings and instances built at once. Each takes
/// hundreds of MB, and anyone may start an opening (a confirmed coin is all
/// it asks): one at a time bounds the hub's memory, the others waiting
/// their turn (answered 202 meanwhile).
pub const HEAVY: usize = 1;

/// How long an opening short of the hub's signatures may wait for the
/// holder's next message before it is given up, its coins freed.
pub const IDLE: Duration = Duration::from_secs(3_600);

/// How deep a block is buried before the hub's header chain takes it: a
/// batch proven is of the chain as it was, and one that a reorg takes back
/// is a chain cut back, its receipts with it (`chain::HubChain`).
const CHAIN_BURY: u32 = 6;

/// How many blocks below the checkpoint of the first contract the hub's header
/// chain starts.
const CHAIN_START_BELOW: u32 = 144;

/// How long a request waits for its step before answering 202.
const WAIT: Duration = Duration::from_secs(20);

/// How long a request to the openings' routes may take, its body read.
const REQUEST_TIME: Duration = Duration::from_secs(300);

/// How long an instance's upload may take, its body read and stepped: 25
/// MB over Tor from a phone, at 15 KB/s at worst.
const INSTANCE_TIME: Duration = Duration::from_secs(30 * 60);

/// A hub's openings, with its node, whose wallet funds and signs F.
pub struct Openings {
    data: PathBuf,
    store: Mutex<Store>,
    /// The chain followed: its tip, checkpoints and fee rates, and
    /// broadcasting.
    source: Source,
    /// The node whose wallet funds and signs F, and locks its coins.
    wallet: Source,
    /// The wallet new contracts pay the hub's share to, if another than
    /// `wallet` ([`Openings::pay_out_to`]).
    payout: std::sync::OnceLock<Source>,
    keyset: Keyset,
    trust: Trust,
    /// Its terms: set once, with the work they ask
    /// ([`Openings::ask_work`]).
    timing: std::sync::RwLock<Timing>,
    /// The openings a task is stepping.
    busy: Mutex<HashSet<[u8; 32]>>,
    /// A permit for each step or instance built at once: [`HEAVY`].
    heavy: Arc<tokio::sync::Semaphore>,
    /// Held from funding an F to locking its coins: no two take the same.
    funding: tokio::sync::Mutex<()>,
    /// The responder's caches.
    watch: dispute::Watch,
    /// Where the responder finds its evidence against a filing.
    evidencer: std::sync::OnceLock<Arc<Evidencer>>,
    /// Where the responder retires the notes a filing names.
    claims: std::sync::OnceLock<Arc<Claims>>,
    /// Where a fold finds whether the notes of her claim are open to it,
    /// and retires them.
    fold_ledger: std::sync::OnceLock<Arc<FoldLedger>>,
    /// Where her funded notes are issued ([`Openings::issue_with`]).
    issuer: std::sync::OnceLock<Arc<Issuer>>,
    /// Where the deposit her default pays her reserve to is bound to the
    /// contract ([`Openings::close_with`]).
    closer: std::sync::OnceLock<(Arc<Closer>, Arc<Releaser>)>,
    /// The ledger's lock checkpoints, which new contracts open on.
    checkpoints: std::sync::OnceLock<LockCheckpoints>,
    /// The prover of the hub's statement: none where proofs are the mock
    /// authority's.
    prover: Option<prover::Prover>,
    /// What the operator is told of the hub's header chain, once there is a
    /// way to tell them, and again only when it changes.
    chain_told: Mutex<Option<String>>,
    /// The hub's header chain, which contracts of a graph that reads their
    /// exit on it are quoted on and proven with: none where the program
    /// trusted reads every header.
    chain: Option<Arc<chain::HubChain>>,
    /// How the operator is told what needs them.
    alert: std::sync::OnceLock<Arc<Alert>>,
    /// The claims given no response this round, for want of the prover.
    withheld: Mutex<Vec<String>>,
    /// What the operator scales the prover's estimates by, as it admits
    /// openings ([`Openings::scale_proofs`]): 1 unless told.
    proof_scale: std::sync::OnceLock<f64>,
    /// Whether more contracts are open than its prover can contest the
    /// exits of at once, as last told.
    over_capacity: std::sync::atomic::AtomicBool,
    /// The error each contract last failed to play with, told once.
    failing: Mutex<HashMap<[u8; 32], String>>,
    /// Whether [`MAX_UNFUNDED`] was told reached, not since left.
    unfunded_full: std::sync::atomic::AtomicBool,
    /// The most contracts live at once: [`MAX_LIVE`] unless set.
    max_live: std::sync::atomic::AtomicUsize,
    /// The step of the surcharge last told, one past [`terms::MAX_STEP`]
    /// once full: told again only as it rises.
    load_told: std::sync::atomic::AtomicU32,
    /// Each contract's fold offered, until its holder signs or asks again.
    folds: Mutex<HashMap<[u8; 32], dispute::PendingFold>>,
    /// What the node's wallet last said it holds, in sat: the most it
    /// funds an F with ([`terms::fundable`]). None until it says.
    funds: Mutex<Option<u64>>,
    /// Whom the hub writes each one-time answer to before it signs it
    /// ([`Openings::witnessed_by`]): until told, it signs no contract.
    witnesses: std::sync::OnceLock<Witnesses>,
}

/// How full the hub's contracts are ([`Openings::load`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Load {
    /// Contracts live: signed and not ended, or under way.
    pub live: usize,
    /// The most it opens ([`Openings::limit_live`]).
    pub max: usize,
    /// The step its fee is surcharged at ([`terms::step`]): none once
    /// full.
    pub step: Option<u32>,
}

/// One responder poll. A bad opening never hides the others; errors are
/// also logged with the opening id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResponseRound {
    /// Openings whose exit the hub contested or settled: a response, an
    /// assertion, an answer to a challenge, a reclaimed slot.
    pub answered: usize,
    /// Openings whose payout outputs of the hub's it swept to its wallet.
    pub swept: usize,
    /// Contracts it ended by default at their close.
    pub closed: usize,
    pub failed: usize,
}

/// Why a request was not answered with frames.
#[derive(Debug)]
pub struct Refused {
    pub status: StatusCode,
    pub reason: String,
}

impl Refused {
    pub(crate) fn bad(reason: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            reason: format!("{reason:#}"),
        }
    }

    /// A quote the hub no longer makes: 409, for her to ask again.
    pub(crate) fn stale(reason: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            reason: format!("{reason:#}"),
        }
    }

    pub(crate) fn unavailable(reason: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            reason: format!("{reason:#}"),
        }
    }
}

/// What a message is answered with.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Frames(Vec<Frame>),
    /// Still working on it: send it again later.
    Working,
}

/// How many openings in `data` the hub signed: a hub run without its
/// contracts warns of them. Nothing is made in `data`.
pub fn signed(data: &Path) -> Result<u64> {
    Store::signed(data)
}

/// How many openings in `data` the hub signed started while it charged
/// less, in some fee, than `fees`, what it charges now: their holders
/// agreed to no more, and pay it nothing until they agree to these
/// ([`Openings::charging`]). Those started before what it charged was
/// kept are not counted. Nothing is made in `data`.
pub fn opened_for_less(data: &Path, fees: &licash_api::Fees) -> Result<u64> {
    let charged = Store::charged(data)?;
    Ok(charged.iter().filter(|was| fees.above(was)).count() as u64)
}

/// An opening as the hub's operator sees it ([`openings`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub id: [u8; 32],
    /// How far it went.
    pub phase: Option<HubPhase>,
    /// Opened under mock proofs: it protects nothing.
    pub mock: bool,
    /// The hub signed F: the contract may stand, and is never given up.
    pub signed: bool,
    /// Given up short of the hub's signatures, its coins freed.
    pub abandoned: bool,
    /// Seconds since 1970.
    pub created_at: u64,
    pub updated_at: u64,
    /// Its terms, unchecked: none if its stored state does not read.
    pub terms: Option<Terms>,
}

/// What an opening's stored state says of it ([`Hub::peek`]), unchecked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The most of the holder's notes it protects, in sat.
    pub cap: u64,
    /// The height its graph closes at, which ends the contract.
    pub close: u32,
    /// The hub's fee for it, in sat.
    pub fee: u64,
    /// Her reserve, from her deposit, in sat.
    pub reserve: u64,
    /// The value its graph holds, in sat: its collateral, and her reserve.
    pub graph: u64,
    /// F's id, from the hub's commitment to F on.
    pub funding: Option<bitcoin::Txid>,
}

/// The openings in `data`, oldest first, read only: none if no opening
/// was ever stored there. Their secrets stay in their states.
pub fn openings(data: &Path) -> Result<Vec<Summary>> {
    let rows = Store::listed(data)?;
    Ok(rows
        .into_iter()
        .map(|row| Summary {
            id: row.id,
            phase: HubPhase::ALL.get(usize::from(row.phase)).copied(),
            mock: row.mock,
            signed: row.irrevocable,
            abandoned: row.abandoned,
            created_at: row.created_at.max(0) as u64,
            updated_at: row.updated_at.max(0) as u64,
            terms: (row.format == store::FORMAT)
                .then(|| peek(&row.state))
                .flatten(),
        })
        .collect())
}

fn peek(state: &[u8]) -> Option<Terms> {
    let peek = Hub::peek(state).ok()?;
    let p = peek.base.parts();
    Some(Terms {
        cap: u64::from(p.cap),
        close: p.graph.close_height,
        fee: p.fees.opening_fee_quote,
        reserve: p.graph.reserve_alice,
        graph: p.graph.graph_value().ok()?,
        funding: peek.funding.map(|tx| tx.compute_txid()),
    })
}

impl Openings {
    /// The openings in `data`, opened under `keyset` and funded by the
    /// wallet of the node `source` names (its JSON-RPC), as
    /// [`Openings::with_wallet`].
    pub async fn new(data: &Path, source: Source, keyset: Keyset) -> Result<Arc<Self>> {
        Self::with_wallet(data, source.clone(), source, keyset, None).await
    }

    /// The openings in `data` on the chain `source` follows, opened under
    /// `keyset` and funded by the node's wallet `wallet` names (its
    /// JSON-RPC, as `http://host:port/wallet/NAME`), which may be another
    /// node's on the same network. Holders choose their terms within
    /// `range`, if any, else open on its fixed ones. Refused on a network
    /// the hub has no terms or programs for: [`Timing::of`],
    /// [`crate::trust`].
    pub async fn with_wallet(
        data: &Path,
        source: Source,
        wallet: Source,
        keyset: Keyset,
        range: Option<Range>,
    ) -> Result<Arc<Self>> {
        let profile: ChainProfile = source.profile().await?;
        let trust = crate::trust(profile)?;
        let timing = Timing::of(profile, range)?;
        // Not fatal: a node may load its wallet after the hub starts. F
        // goes unfunded, and its openings given up, until it does. Fatal
        // on another network: no F it funds could be the chain's.
        match wallet.profile().await {
            Ok(theirs) => ensure!(
                theirs == profile,
                "the contracts' wallet, {wallet}, is on {theirs}, the chain on {profile}"
            ),
            Err(e) => tracing::warn!("the contracts' wallet, {wallet}: {e:#}"),
        }
        let store = Store::open(data)?;
        for (id, format) in store.unreadable_signed()? {
            tracing::warn!(
                id = %crate::hex_id(&id),
                format,
                "a signed contract stored in a format this build doesn't read: its exit isn't played"
            );
        }
        // The chain program's headers are the hub's, kept from the first
        // contract's checkpoint.
        let mut chain_told = None;
        let chain = match (trust.mock, trust.chained) {
            (false, Some(program)) => {
                let (chain, told) = chain::HubChain::open(data, program, profile)?;
                chain_told = told
                    .map(|why| format!("a receipt of the hub's header chain is not kept: {why}"));
                Some(Arc::new(chain))
            }
            _ => None,
        };
        let openings = Arc::new(Self {
            data: data.to_owned(),
            store: Mutex::new(store),
            source,
            wallet,
            payout: std::sync::OnceLock::new(),
            keyset,
            trust,
            timing: std::sync::RwLock::new(timing),
            busy: Mutex::new(HashSet::new()),
            heavy: Arc::new(tokio::sync::Semaphore::new(HEAVY)),
            funding: tokio::sync::Mutex::new(()),
            watch: dispute::Watch::default(),
            evidencer: std::sync::OnceLock::new(),
            claims: std::sync::OnceLock::new(),
            fold_ledger: std::sync::OnceLock::new(),
            issuer: std::sync::OnceLock::new(),
            closer: std::sync::OnceLock::new(),
            checkpoints: std::sync::OnceLock::new(),
            prover: (!trust.mock).then(|| {
                let before = crate::programs_before(profile);
                let spacing = prover::spacing(profile);
                let chain = chain.clone().zip(trust.chained);
                prover::Prover::start(data, trust.program, before, spacing, chain)
            }),
            chain,
            chain_told: Mutex::new(chain_told),
            alert: std::sync::OnceLock::new(),
            withheld: Mutex::default(),
            proof_scale: std::sync::OnceLock::new(),
            over_capacity: Default::default(),
            failing: Mutex::default(),
            unfunded_full: Default::default(),
            max_live: std::sync::atomic::AtomicUsize::new(MAX_LIVE),
            load_told: Default::default(),
            folds: Mutex::default(),
            funds: Mutex::new(None),
            witnesses: std::sync::OnceLock::new(),
        });
        if let Err(e) = openings.learn_funds().await {
            tracing::warn!("contracts need the node's wallet, to fund F: {e:#}");
        }
        // A node restarted forgets the coins it locked without persisting.
        let locked = openings.store().locked()?;
        openings.relock_coins(&locked).await;
        Ok(openings)
    }

    /// Write each one-time answer to `witnesses` before signing it, and
    /// enroll each contract in them before signing its funding: until
    /// told, the hub signs neither. Refused where [`Witnesses::admit`]
    /// refuses them. Set once.
    pub async fn witnessed_by(&self, witnesses: Witnesses) -> Result<()> {
        let profile: ChainProfile = self.source.profile().await?;
        witnesses.admit(profile, &self.data)?;
        self.witnesses
            .set(witnesses)
            .map_err(|_| anyhow::anyhow!("the hub's witnesses are set already"))
    }

    fn witnesses(&self) -> Result<&Witnesses> {
        self.witnesses.get().context(
            "the hub has no contract witnesses configured (--contracts-witness, or \
             --contracts-witnesses none): it signs no contract",
        )
    }

    /// Whether the hub never signed a funding nor a one-time answer, as its
    /// database tells: on which a witness set is sealed as its first.
    fn never_signed(&self) -> Result<bool> {
        Ok(self.store().never_signed()? && responses::Responses::open(&self.data)?.is_empty()?)
    }

    /// Pay the hub's share of each contract opened from now on to a new
    /// script of the wallet `wallet` names (its JSON-RPC, as
    /// [`Openings::with_wallet`] takes one), rather than of the wallet that
    /// funds F: one that watches a descriptor whose keys are kept offline,
    /// so that what contracts return at their close, their fold or a
    /// default is out of reach of this host. Contracts opened before pay
    /// the script they were signed with; fee coins' change, the outputs a
    /// dispute leaves the hub and coins spent back stay with the funding
    /// wallet, which signs for them. Set once.
    ///
    /// Refused on another network than the chain's. A wallet that does not
    /// answer is not fatal, as the funding wallet's: no contract opens
    /// until it gives a script, and none is ever paid to the funding
    /// wallet instead.
    pub async fn pay_out_to(&self, wallet: Source) -> Result<()> {
        let profile: ChainProfile = self.source.profile().await?;
        match wallet.profile().await {
            Ok(theirs) => ensure!(
                theirs == profile,
                "the contracts' payout wallet, {wallet}, is on {theirs}, the chain on {profile}"
            ),
            Err(e) => tracing::warn!("the contracts' payout wallet, {wallet}: {e:#}"),
        }
        let info: Result<serde_json::Value> =
            wallet.rpc("getwalletinfo", serde_json::json!([])).await;
        match info {
            Ok(info) if info["private_keys_enabled"].as_bool() != Some(false) => tracing::warn!(
                "the contracts' payout wallet, {wallet}, holds private keys: what contracts \
                 return is only out of this host's reach in a wallet that watches a \
                 descriptor (createwallet with disable_private_keys)"
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!("the contracts' payout wallet, {wallet}: {e:#}"),
        }
        tracing::info!(%wallet, "new contracts pay the hub's share to another wallet");
        let _ = self.payout.set(wallet);
        Ok(())
    }

    /// Scale the prover's estimate of each proof by `by` as openings are
    /// admitted ([`Openings::open`]): above 1 for a prover slower than its
    /// benchmark says, below 1 to admit more contracts than it can be
    /// sure to defend at once. 1 unless told; set once.
    pub fn scale_proofs(&self, by: f64) -> Result<()> {
        ensure!(by.is_finite() && by > 0.0, "a proof scale of {by}: above 0");
        let _ = self.proof_scale.set(by);
        Ok(())
    }

    /// Charge `fee` sat for an opening, before its surcharge, in the
    /// contracts quoted from now on ([`Timing::with_opening_fee`]),
    /// [`terms::OPENING_FEE`] unless told.
    pub fn charge_opening(&self, fee: u64) {
        let mut timing = self.timing.write().unwrap_or_else(|e| e.into_inner());
        *timing = timing.with_opening_fee(fee);
    }

    /// Ask `depth` blocks of work on top of a request's response in the
    /// contracts quoted from now on ([`Timing::with_work_depth`]), the
    /// network's floor unless told: those open already keep theirs.
    pub fn ask_work(&self, depth: u32) -> Result<()> {
        let mut timing = self.timing.write().unwrap_or_else(|e| e.into_inner());
        *timing = timing.with_work_depth(depth)?;
        Ok(())
    }

    /// That the hub's locks, living `window` blocks at most, outlive its
    /// contracts' response window ([`Timing::covers_locks`]).
    pub fn check_lock_window(&self, window: u32) -> Result<()> {
        self.timing().covers_locks(window)
    }

    /// Its terms now.
    fn timing(&self) -> Timing {
        *self.timing.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Keep `fees`, what the hub charges, with each opening that starts
    /// from now on: what its holder agrees to pay at most
    /// ([`opened_for_less`]). Nothing is kept until told.
    pub fn charging(&self, fees: licash_api::Fees) {
        self.store().charging(fees);
    }

    /// Open at most `max` contracts at once, 1 at least, from now on
    /// ([`MAX_LIVE`]). Those live past it stay: new ones wait for them to
    /// end.
    pub fn limit_live(&self, max: usize) {
        (self.max_live).store(max.max(1), std::sync::atomic::Ordering::Relaxed);
    }

    /// How full the hub's contracts are: those live now, signed and not
    /// ended or under way, and the most it opens.
    pub fn load(&self) -> Result<Load> {
        let store = self.store();
        let live = store.signed_ids()?.len() + store.under_way()?;
        let max = self.max_live.load(std::sync::atomic::Ordering::Relaxed);
        Ok(Load {
            live,
            max,
            step: terms::step(live, max),
        })
    }

    /// The step the hub's fee is surcharged at now, as its contracts fill
    /// up: refused as unavailable once full.
    fn step_now(&self) -> Result<u32, Refused> {
        let load = self.load().map_err(Refused::unavailable)?;
        load.step.ok_or_else(|| {
            Refused::unavailable(format!(
                "the hub has {} contracts live, its most: later",
                load.live
            ))
        })
    }

    /// Of a contract that reads its exit on the hub's header chain: the chain
    /// started at `checkpoint` if it has not, followed through it, and the
    /// checkpoint a block of it in the state it binds, which the statement
    /// opens (else refused as unavailable). Nothing of another.
    pub(crate) async fn on_chain(&self, checkpoint: &Checkpoint) -> Result<(), Refused> {
        let Some(chain) = &self.chain else {
            return Ok(());
        };
        // Started well below the first checkpoint: a holder may name a block
        // near the tip, which a reorg could take back, and a chain whose start
        // is gone can't be followed. Nothing authenticates a start.
        if chain.tip().is_none() {
            let below = checkpoint.height().saturating_sub(CHAIN_START_BELOW);
            let start = self.source.checkpoint(below).await;
            chain
                .begin(&start.map_err(Refused::unavailable)?)
                .map_err(Refused::unavailable)?;
        }
        chain
            .follow(&self.source, checkpoint.height())
            .await
            .map_err(Refused::unavailable)?;
        chain.covers(checkpoint).map_err(Refused::unavailable)
    }

    /// Follow the node's chain with the hub's header chain, through the blocks
    /// buried [`CHAIN_BURY`] deep: what a reorg that deep alone could take
    /// back, which no batch proven is of.
    async fn follow_chain(&self) {
        let Some(chain) = &self.chain else { return };
        let followed = async {
            let tip = self.source.tip().await?;
            chain
                .follow(&self.source, tip.height.saturating_sub(CHAIN_BURY))
                .await
        };
        if let Err(e) = followed.await {
            let message = format!("the hub's header chain can't follow the node's: {e:#}");
            let told = self
                .chain_told
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .replace(message.clone());
            match told.as_deref() == Some(&message) {
                true => tracing::warn!("{message}"),
                false => self.alert(&message),
            }
        }
    }

    /// The hub's offer now, checkpointed at the block the ledger would
    /// take as its newest lock checkpoint ([`Openings::checkpoints_with`]),
    /// kept as one once a contract opens on it, else at its tip: its
    /// quote of `cap` sat over `blocks` she chose, if within its terms,
    /// else its fixed one; `funded` sat of it hers, the rest the hub's.
    pub async fn offer(&self, chosen: Option<(u32, u32)>, funded: u32) -> Result<Offer, Refused> {
        let (cap, blocks) = chosen.unwrap_or((terms::CAP, self.timing().lock()));
        self.timing().allows(cap, blocks).map_err(Refused::bad)?;
        if funded > cap {
            return Err(Refused::bad(format!(
                "{funded} sat funded, more than the {cap} sat contract"
            )));
        }
        let most = self.most_funded(terms::MAX_CAP);
        if cap - funded > most {
            return Err(Refused::unavailable(format!(
                "the hub's wallet funds {most} sat of a contract at most now"
            )));
        }
        let tip = self.source.tip().await.map_err(Refused::unavailable)?;
        let height = self.opening_height(tip.height)?;
        let checkpoint = self.source.checkpoint(height).await;
        let checkpoint = checkpoint.map_err(Refused::unavailable)?;
        self.on_chain(&checkpoint).await?;
        let timing = self.timing().at_step(self.step_now()?);
        let quote = timing.quote_for(self.keyset.clone(), checkpoint, cap, blocks, funded);
        let bounds = self.timing().bounds(&quote);
        Ok(Offer { quote, bounds })
    }

    /// What the hub's info says of its contracts: its fixed terms, as
    /// apps installed open on, and those holders may choose, if any.
    /// Its range's largest cap, as much as its wallet funds now; its
    /// prices as surcharged now, at the highest step once full or if its
    /// load is unknown. And whether a wallet finds room there now, to
    /// choose a hub by before paying a deposit: what its wallet funds
    /// (`funds`), of the caps it offers and no more of its balance than
    /// those tell, and whether a new opening is refused now (`full`), as
    /// [`run::admits`] and [`Openings::step_now`] refuse one.
    pub fn advertise(&self) -> licash_api::Contracts {
        let step = match self.load() {
            Ok(load) => load.step,
            Err(e) => {
                tracing::warn!("the contracts' load: {e:#}");
                None
            }
        };
        let full = step.is_none() || run::admits(&self.store()).is_err();
        let timing = self.timing().at_step(step.unwrap_or(terms::MAX_STEP));
        let offered = timing.range();
        let most = offered.map_or(terms::CAP, |r| r.max_cap);
        let known = self.funds().is_some();
        let range = offered.map(|mut r| {
            r.max_cap = self.most_funded(r.max_cap).max(r.min_cap);
            r
        });
        licash_api::Contracts {
            cap: terms::CAP,
            price: timing.price(terms::CAP, timing.lock(), 0),
            reserve: terms::RESERVE_ALICE,
            blocks: timing.lock(),
            mock: self.trust.mock,
            range,
            funds: known.then(|| self.most_funded(most)),
            full,
        }
    }

    /// What the node's wallet held when last asked, in sat: none before.
    fn funds(&self) -> Option<u64> {
        *self.funds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Give up the openings short of the hub's signatures idle for
    /// [`IDLE`], freeing their coins: how many.
    pub async fn sweep(&self) -> Result<usize> {
        let before = crate::now() - IDLE.as_secs() as i64;
        let stale = self.store().stale(before)?;
        let mut abandoned = 0;
        for id in &stale {
            let coins = self.abandon_idle(id, before)?;
            let Some(coins) = coins else { continue };
            self.unlock_coins(&coins).await;
            abandoned += 1;
            tracing::info!(id = %crate::hex_id(id), "an opening given up, idle");
        }
        Ok(abandoned)
    }

    fn abandon_idle(&self, id: &[u8; 32], before: i64) -> Result<Option<Vec<bitcoin::OutPoint>>> {
        // A step takes this same mark before loading its row. Hold the
        // mutex through the conditional write, never through node I/O.
        let busy = self.busy();
        if busy.contains(id) {
            return Ok(None);
        }
        let coins = self.store().abandon(id, before)?;
        if let (Some(_), Some((_, release))) = (&coins, self.closer.get()) {
            release(id);
        }
        Ok(coins)
    }

    /// `most`, or less if the node's wallet, as it last said, funds no F
    /// of a cap so large: none if it funds none. As `most` if not known.
    fn most_funded(&self, most: u32) -> u32 {
        match self.funds() {
            Some(balance) => terms::fundable(balance).unwrap_or(0).min(most),
            None => most,
        }
    }

    /// Ask the node's wallet what it holds, confirmed or its own
    /// (`getbalances`, its `mine.trusted`): logged when the largest cap
    /// it funds changes. Its balance, in sat.
    pub async fn learn_funds(&self) -> Result<u64> {
        let balances: serde_json::Value = self
            .wallet
            .rpc("getbalances", serde_json::json!([]))
            .await?;
        let btc = balances["mine"]["trusted"]
            .as_f64()
            .context("a wallet's balances, none trusted")?;
        let balance = bitcoin::Amount::from_btc(btc)?.to_sat();
        let before = self
            .funds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(balance);
        let cap = terms::fundable(balance);
        if before.map(terms::fundable) != Some(cap) {
            match cap {
                Some(cap) => tracing::info!(balance, cap, "the contracts' wallet funds caps up to"),
                None => tracing::warn!(balance, "the contracts' wallet funds no contract"),
            }
        }
        Ok(balance)
    }

    /// Sweep, and learn what the node's wallet holds, every minute, for
    /// as long as the hub runs: never returns.
    pub async fn sweep_every_minute(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if let Err(e) = self.sweep().await {
                tracing::error!("giving up idle openings: {e:#}");
            }
            if let Err(e) = self.learn_funds().await {
                tracing::warn!("what the contracts' wallet holds: {e:#}");
            }
        }
    }

    /// Find the evidence against holders' claims with `f` from now on: the
    /// hub's ledger of the spends it retired notes for and the locks it
    /// settled. Without, a claim is owed what its notes are worth, and
    /// only claims that are none are answered.
    pub fn evidence_with(&self, f: Arc<Evidencer>) {
        let _ = self.evidencer.set(f);
    }

    /// Open contracts from now on on the newest block the ledger takes as
    /// a lock checkpoint, kept first as its newest. Every lock named after
    /// a contract opens then names its checkpoint or a later one, a block
    /// of the chain its statement reads, so the lock's activation can be
    /// judged in it. Without, contracts open at the tip.
    pub fn checkpoints_with(&self, checkpoints: LockCheckpoints) {
        let _ = self.checkpoints.set(checkpoints);
    }

    /// The height new contracts open at, the chain's tip at `tip`.
    pub(crate) fn opening_height(&self, tip: u32) -> Result<u32, Refused> {
        match self.checkpoints.get() {
            Some(c) => (c.height)(tip)
                .map_err(|e| Refused::unavailable(format!("the ledger's lock checkpoint: {e:#}"))),
            None => Ok(tip),
        }
    }

    /// Keep `checkpoint`, of a contract opening, as the ledger's lock
    /// checkpoint if it is newer than its newest.
    pub(crate) fn keep_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), Refused> {
        match self.checkpoints.get() {
            Some(c) => (c.keep)(checkpoint)
                .map_err(|e| Refused::unavailable(format!("the ledger's lock checkpoint: {e:#}"))),
            None => Ok(()),
        }
    }

    /// Retire the notes of each holder's published claim with `f` from
    /// now on: the hub's ledger, which then spends them for nobody.
    /// Without, the ledger may let her spend notes the hub pays her for on
    /// Bitcoin.
    pub fn claims_with(&self, f: Arc<Claims>) {
        let _ = self.claims.set(f);
    }

    /// Fold contracts on the claims of their holders from now on, their
    /// notes read and retired in `ledger`: the hub's. Without, it answers
    /// a fold that asks a claim paid with 503, and folds only as it
    /// always did, her reserve alone.
    pub fn folds_with(&self, ledger: Arc<FoldLedger>) {
        let _ = self.fold_ledger.set(ledger);
    }

    /// Bind the deposit that a contract's default pays her reserve to,
    /// through `f` from now on, when an opening names one: without, an
    /// opening that names one is refused, the hub taking no such deposit.
    /// `release` gives the deposit up again if the opening is.
    pub fn close_with(&self, bind: Arc<Closer>, release: Arc<Releaser>) {
        let _ = self.closer.set((bind, release));
    }

    /// Tell the operator through `f` from now on (the hub's notifications):
    /// its prover is not ready or fails, a claim is answered with no
    /// response for want of it, an assertion's deadline nears unproven.
    pub fn alert_with(&self, f: Arc<Alert>) {
        if let Some(prover) = &self.prover {
            prover.alert_with(f.clone());
        }
        // what was found at startup, as the prover's not-ready is
        if let Some(message) = self
            .chain_told
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            f(&message);
        }
        let _ = self.alert.set(f);
    }

    fn alert(&self, message: &str) {
        match self.alert.get() {
            Some(alert) => alert(message),
            None => tracing::error!("alert: {message}"),
        }
    }

    /// `id`'s claim of `b` units, owed `owed`, gets no response: `why`.
    /// Told the operator at the end of the round, with the others.
    fn withheld(&self, id: &[u8; 32], b: u32, owed: u32, why: &str) {
        let message = format!(
            "contract {} (claims {b} units, owed {owed}): {why}",
            crate::hex_id(id)
        );
        tracing::warn!("no response: {message}");
        self.withheld
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(message);
    }

    /// Whether contract `id` failing to play with `error` is news: not if
    /// it failed with it last, which was told.
    fn newly_failing(&self, id: &[u8; 32], error: &str) -> bool {
        let mut failing = self.failing.lock().unwrap_or_else(PoisonError::into_inner);
        failing.insert(*id, error.to_owned()).as_deref() != Some(error)
    }

    /// Contract `id` played a round: a failure after is news.
    fn played(&self, id: &[u8; 32]) {
        let mut failing = self.failing.lock().unwrap_or_else(PoisonError::into_inner);
        failing.remove(id);
    }

    /// Play each signed opening's exit, if any, one step
    /// (`dispute`). Each opening's error is reported independently.
    pub async fn answer_requests(&self) -> Result<ResponseRound> {
        self.follow_chain().await;
        let ids = self.store().signed_ids()?;
        self.keep_loaded(&ids);
        let round_open = ids.len();
        // Of those no longer played, nothing more to tell.
        (self.failing.lock().unwrap_or_else(PoisonError::into_inner))
            .retain(|id, _| ids.contains(id));
        let mut round = ResponseRound::default();
        for id in ids {
            match self.play(&id).await {
                Ok(Played::Posted(what)) => {
                    self.played(&id);
                    match what {
                        "sweep" => round.swept += 1,
                        "default" => round.closed += 1,
                        _ => round.answered += 1,
                    }
                    tracing::info!(id = %crate::hex_id(&id), what, "contract exit played");
                }
                Ok(Played::Idle) => self.played(&id),
                Err(e) => {
                    round.failed += 1;
                    let e = format!("{e:#}");
                    match self.newly_failing(&id, &e) {
                        true => {
                            tracing::error!(id = %crate::hex_id(&id), "playing a contract exit: {e}")
                        }
                        false => {
                            tracing::debug!(id = %crate::hex_id(&id), "playing a contract exit: {e}")
                        }
                    }
                }
            }
        }
        if let Some(prover) = &self.prover {
            prover.polled();
            let blocks = self.timing().proof_blocks();
            if let Some(defendable) = prover.defendable(blocks) {
                let open = round_open as u64;
                let over = open > defendable;
                if over
                    && !self
                        .over_capacity
                        .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    self.alert(&format!(
                        "{open} contracts are open, and the hub's prover makes about {defendable} \
                         proofs of the smallest in an assert window ({blocks} blocks): exits by \
                         more of their holders at once than it can prove for are paid what they \
                         claim"
                    ));
                }
                if !over {
                    self.over_capacity
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        let load = self.load()?;
        let level = load.step.unwrap_or(terms::MAX_STEP + 1);
        let told = self
            .load_told
            .swap(level, std::sync::atomic::Ordering::Relaxed);
        if level > told {
            self.alert(&match load.step {
                Some(step) => format!(
                    "{} of the hub's most {} contracts are live: its fee is {} times its own \
                     for new ones (--contracts-max-live)",
                    load.live,
                    load.max,
                    1u32 << step
                ),
                None => format!(
                    "{} contracts are live, the hub's most: it opens no more until some end \
                     (--contracts-max-live)",
                    load.live
                ),
            });
        }
        let unfunded = self.store().unfunded_count()?;
        let full = unfunded >= MAX_UNFUNDED;
        if self
            .unfunded_full
            .swap(full, std::sync::atomic::Ordering::Relaxed)
            != full
            && full
        {
            self.alert(&format!(
                "{unfunded} openings are signed and their F in no block: new openings are \
                 refused until they confirm or are made never to, {} blocks after",
                dispute::UNFUNDED_FOR
            ));
        }
        let withheld =
            std::mem::take(&mut *self.withheld.lock().unwrap_or_else(PoisonError::into_inner));
        if let Some(first) = withheld.first() {
            self.alert(&format!(
                "{} contested claims get no response, for want of the hub's prover (their \
                 timeouts pay what they claim): {first}{}",
                withheld.len(),
                match withheld.len() {
                    1 => String::new(),
                    n => format!(", and {} more", n - 1),
                }
            ));
        }
        Ok(round)
    }

    /// Play the exits every `every` while the hub runs: never returns.
    pub async fn respond_every(self: Arc<Self>, every: Duration) {
        loop {
            if let Err(e) = self.answer_requests().await {
                tracing::error!("automatic contract responder: {e:#}");
            }
            tokio::time::sleep(every).await;
        }
    }

    async fn context(&self) -> Result<Context, Refused> {
        let tip = self.source.tip().await.map_err(Refused::unavailable)?;
        Ok(Context {
            tip: tip.height,
            trust: self.trust,
        })
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn busy(&self) -> MutexGuard<'_, HashSet<[u8; 32]>> {
        self.busy.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The routes of `openings`, at [`QUOTE`], [`OPEN`], [`STEP`],
/// [`INSTANCE`], [`FOLD`], [`FOLD_SIGN`] and [`FUNDED`].
pub fn router(openings: Arc<Openings>) -> Router {
    // Separate budgets let existing openings progress while new opens or
    // instance uploads are saturated. Body permits precede extraction and
    // last until the response body is dropped, not merely constructed.
    let budget = |count, time| {
        let limit = Arc::new(tokio::sync::Semaphore::new(count));
        middleware::from_fn_with_state((limit, time), admit)
    };
    Router::new()
        .route(QUOTE, get(quote).layer(budget(2, REQUEST_TIME)))
        .route(OPEN, post(open).layer(budget(2, REQUEST_TIME)))
        .route(STEP, post(step).layer(budget(2, REQUEST_TIME)))
        // A holder uploads three at a time: two holders at once.
        .route(INSTANCE, post(instance).layer(budget(6, INSTANCE_TIME)))
        .route(FOLD, post(offer_fold).layer(budget(2, REQUEST_TIME)))
        .route(
            FOLD_CLAIM,
            post(offer_fold_claim).layer(budget(2, REQUEST_TIME)),
        )
        .route(FOLD_SIGN, post(sign_fold).layer(budget(2, REQUEST_TIME)))
        .route(EVIDENCE, post(show_evidence).layer(budget(2, REQUEST_TIME)))
        .route(PROOF, post(show_proof).layer(budget(2, REQUEST_TIME)))
        .route(FUNDED, post(funded).layer(budget(2, REQUEST_TIME)))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(openings)
}

async fn admit(
    State((limit, time)): State<(Arc<tokio::sync::Semaphore>, Duration)>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(permit) = limit.try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many contract requests: retry later",
        )
            .into_response();
    };
    let response = match tokio::time::timeout(time, next.run(request)).await {
        Ok(response) => response,
        Err(_) => return StatusCode::REQUEST_TIMEOUT.into_response(),
    };
    response.map(|body| {
        Body::from_stream(body.into_data_stream().map(move |chunk| {
            let _held = &permit;
            chunk
        }))
    })
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        (self.status, self.reason).into_response()
    }
}

impl IntoResponse for Answer {
    fn into_response(self) -> Response {
        match self {
            Answer::Frames(frames) => (StatusCode::OK, Frame::encode_all(&frames)).into_response(),
            Answer::Working => StatusCode::ACCEPTED.into_response(),
        }
    }
}

/// The hub's quote, of the terms she chose (`?cap=SAT&blocks=N`, both or
/// neither), else its fixed one, `funded=SAT` of it hers if asked.
async fn quote(
    State(openings): State<Arc<Openings>>,
    Query(asked): Query<HashMap<String, String>>,
) -> Result<Vec<u8>, Refused> {
    let number = |name: &str| {
        let value = asked.get(name).map(|v| v.parse::<u32>());
        value
            .transpose()
            .map_err(|e| Refused::bad(format!("{name}: {e}")))
    };
    let chosen = match (number("cap")?, number("blocks")?) {
        (Some(cap), Some(blocks)) => Some((cap, blocks)),
        (None, None) => None,
        _ => return Err(Refused::bad("a cap and blocks, both or neither")),
    };
    let funded = number("funded")?.unwrap_or(0);
    Ok(openings.offer(chosen, funded).await?.encode())
}

async fn funded(
    State(openings): State<Arc<Openings>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Vec<u8>, Refused> {
    let id = crate::parse_id(&id).map_err(Refused::bad)?;
    Ok(openings.funded(id).await?.encode())
}

async fn open(State(openings): State<Arc<Openings>>, body: Bytes) -> Result<Answer, Refused> {
    openings.open(&body).await
}

async fn step(
    State(openings): State<Arc<Openings>>,
    UrlPath(id): UrlPath<String>,
    body: Bytes,
) -> Result<Answer, Refused> {
    let id = crate::parse_id(&id).map_err(Refused::bad)?;
    openings.step(id, body.to_vec()).await
}

async fn instance(
    State(openings): State<Arc<Openings>>,
    UrlPath(id): UrlPath<String>,
    body: Bytes,
) -> Result<Answer, Refused> {
    let id = crate::parse_id(&id).map_err(Refused::bad)?;
    if licash_contract::wire::Kind::peek(&body) != Some(licash_contract::wire::Kind::Instance) {
        return Err(Refused::bad(
            "an instance upload requires an Instance envelope",
        ));
    }
    openings.step(id, body.to_vec()).await
}

/// Her nonce for contract `id`'s fold: the hub's, and the fee.
async fn offer_fold(
    State(openings): State<Arc<Openings>>,
    UrlPath(id): UrlPath<String>,
    body: Bytes,
) -> Result<Vec<u8>, Refused> {
    let id = crate::parse_id(&id).map_err(Refused::bad)?;
    Ok(openings.offer_fold(&id, &body).await?.encode())
}

/// Her nonce, the claim she asks paid and its notes, for contract `id`'s
/// fold: the hub's nonce, and the fee.
async fn offer_fold_claim(
    State(openings): State<Arc<Openings>>,
    UrlPath(id): UrlPath<String>,
    body: Bytes,
) -> Result<Vec<u8>, Refused> {
    let id = crate::parse_id(&id).map_err(Refused::bad)?;
    Ok(openings.offer_fold_claim(&id, &body).await?.encode())
}

/// Her signature as the contract's claim key, for contract `id`'s evidence:
/// what the hub responded to her claim on.
async fn show_evidence(
    State(openings): State<Arc<Openings>>,
    UrlPath(id): UrlPath<String>,
    body: Bytes,
) -> Result<Vec<u8>, Refused> {
    let id = crate::parse_id(&id).map_err(Refused::bad)?;
    openings.show_evidence(&id, &body).await
}

async fn show_proof(
    State(openings): State<Arc<Openings>>,
    UrlPath(id): UrlPath<String>,
    body: Bytes,
) -> Result<Vec<u8>, Refused> {
    let id = crate::parse_id(&id).map_err(Refused::bad)?;
    openings.show_proof(&id, &body).await
}

/// Her partial signature on contract `id`'s fold, with her claim's filing
/// if she asked it paid: the fold, broadcast.
async fn sign_fold(
    State(openings): State<Arc<Openings>>,
    UrlPath(id): UrlPath<String>,
    body: Bytes,
) -> Result<Vec<u8>, Refused> {
    let id = crate::parse_id(&id).map_err(Refused::bad)?;
    let fold = openings.sign_fold(&id, &body).await?;
    Ok(bitcoin::consensus::serialize(&fold))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn admission_precedes_body_buffering_and_lasts_through_response_delivery() {
        use axum::http::Request as HttpRequest;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let limit = Arc::new(tokio::sync::Semaphore::new(1));
        let app = Router::new()
            .route("/", post(|_: Bytes| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                (limit.clone(), REQUEST_TIME),
                admit,
            ));
        let response = app
            .clone()
            .oneshot(HttpRequest::post("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(limit.available_permits(), 0);
        let polled = Arc::new(AtomicUsize::new(0));
        let seen = polled.clone();
        let body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
        }));
        let refused = app
            .clone()
            .oneshot(HttpRequest::post("/").body(body).unwrap())
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(polled.load(Ordering::SeqCst), 0);
        drop(response);
        assert_eq!(limit.available_permits(), 1);
        let response = app
            .oneshot(HttpRequest::post("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    fn funded() -> &'static [u8] {
        &crate::testing::opened().hub
    }

    fn deposit(vout: u32) -> bitcoin::OutPoint {
        use bitcoin::hashes::Hash as _;
        bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([9; 32]),
            vout,
        }
    }

    fn test_openings(dir: &Path) -> Openings {
        let profile = ChainProfile::Core30DefaultRegtest;
        let keyset = Hub::peek(funded()).unwrap().base.parts().keyset.clone();
        let source: Source = "http://127.0.0.1:1".parse().unwrap();
        Openings {
            data: dir.to_owned(),
            store: Mutex::new(Store::open(&crate::testing::hub_data(dir)).unwrap()),
            source: source.clone(),
            wallet: source,
            payout: std::sync::OnceLock::new(),
            keyset,
            trust: crate::trust(profile).unwrap(),
            timing: std::sync::RwLock::new(Timing::of(profile, None).unwrap()),
            busy: Mutex::new(HashSet::new()),
            heavy: Arc::new(tokio::sync::Semaphore::new(HEAVY)),
            funding: tokio::sync::Mutex::new(()),
            watch: dispute::Watch::default(),
            evidencer: std::sync::OnceLock::new(),
            claims: std::sync::OnceLock::new(),
            fold_ledger: std::sync::OnceLock::new(),
            issuer: std::sync::OnceLock::new(),
            closer: std::sync::OnceLock::new(),
            checkpoints: std::sync::OnceLock::new(),
            prover: None,
            chain: None,
            chain_told: Mutex::default(),
            alert: std::sync::OnceLock::new(),
            withheld: Mutex::default(),
            proof_scale: std::sync::OnceLock::new(),
            over_capacity: Default::default(),
            failing: Mutex::default(),
            unfunded_full: Default::default(),
            max_live: std::sync::atomic::AtomicUsize::new(MAX_LIVE),
            load_told: Default::default(),
            folds: Mutex::default(),
            funds: Mutex::new(None),
            witnesses: std::sync::OnceLock::from(Witnesses::none()),
        }
    }

    #[tokio::test]
    async fn an_instance_waits_for_its_opening_where_a_step_is_answered_202() {
        use licash_contract::wire::{Envelope, Kind};
        let dir = tempfile::tempdir().unwrap();
        let openings = Arc::new(test_openings(dir.path()));
        let id = [9; 32];
        let message = move |kind| {
            Envelope {
                id,
                kind,
                body: vec![],
            }
            .to_bytes()
        };
        openings.busy().insert(id);
        // Another task steps the opening: a step is told to ask again.
        let answer = openings.step(id, message(Kind::Consent)).await.unwrap();
        assert_eq!(answer, Answer::Working);
        // An instance, which she would send whole again, waits its turn.
        let waiting = openings.clone();
        let instance = tokio::spawn(async move { waiting.step(id, message(Kind::Instance)).await });
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!instance.is_finished());
        openings.busy().remove(&id);
        // Stepped then, not 202: refused here, of no chain to ask.
        let answer = instance.await.unwrap();
        assert!(answer.is_err(), "{answer:?}");
    }

    /// A contract failing each round the same way is told of once, not
    /// each round: again once its error changes, or once it fails anew
    /// after a round played.
    #[test]
    fn a_contract_failing_alike_each_round_is_told_of_once() {
        let dir = tempfile::tempdir().unwrap();
        let openings = test_openings(dir.path());
        let (a, b) = ([1; 32], [2; 32]);
        assert!(openings.newly_failing(&a, "no node"));
        assert!(!openings.newly_failing(&a, "no node"));
        assert!(openings.newly_failing(&b, "no node"));
        assert!(openings.newly_failing(&a, "no proof"));
        assert!(!openings.newly_failing(&a, "no proof"));
        openings.played(&a);
        assert!(openings.newly_failing(&a, "no proof"));
        assert!(!openings.newly_failing(&b, "no node"));
    }

    #[test]
    fn its_range_is_as_large_as_its_wallet_funds() {
        let dir = tempfile::tempdir().unwrap();
        let mut openings = test_openings(dir.path());
        let range = Range {
            max_cap: 100_000_000,
            max_blocks: 52_560,
            ppm_year: 10_000,
            ppm_year_funded: 0,
        };
        *openings.timing.get_mut().unwrap() =
            Timing::of(ChainProfile::Core30DefaultRegtest, Some(range)).unwrap();
        let max = |o: &Openings| o.advertise().range.unwrap().max_cap;
        // Not known yet: as the operator set it, down to a size.
        assert_eq!(max(&openings), 67_108_863);
        *openings.funds.lock().unwrap() = Some(50_000_000);
        assert_eq!(max(&openings), 33_554_431);
        *openings.funds.lock().unwrap() = Some(1_000_000);
        assert_eq!(max(&openings), 524_287);
        // None funded: its least, and opening one is refused.
        *openings.funds.lock().unwrap() = Some(200_000);
        assert_eq!(max(&openings), terms::CAP);
        assert_eq!(openings.most_funded(terms::CAP), 0);
    }

    /// What its wallet funds now is said beside its range, for a wallet to
    /// tell a hub with no room before paying a deposit: unknown until
    /// asked, none once short of the least, and never more of its balance
    /// than the largest cap it offers tells.
    #[test]
    fn its_info_says_what_its_wallet_funds_now_and_no_more_than_it_offers() {
        use licash_api::Room;
        let dir = tempfile::tempdir().unwrap();
        let mut openings = test_openings(dir.path());
        // Fixed terms only: all of its one cap, or none.
        assert_eq!(openings.advertise().funds, None);
        assert_eq!(openings.advertise().room(), Room::Open);
        *openings.funds.lock().unwrap() = Some(10_000_000);
        assert_eq!(openings.advertise().funds, Some(terms::CAP));
        *openings.funds.lock().unwrap() = Some(200_000);
        assert_eq!(openings.advertise().funds, Some(0));
        assert_eq!(openings.advertise().room(), Room::Unfunded);

        let range = Range {
            max_cap: 100_000_000,
            max_blocks: 52_560,
            ppm_year: 10_000,
            ppm_year_funded: 0,
        };
        *openings.timing.get_mut().unwrap() =
            Timing::of(ChainProfile::Core30DefaultRegtest, Some(range)).unwrap();
        *openings.funds.lock().unwrap() = None;
        let said = |o: &Openings| (o.advertise().funds, o.advertise().room());
        assert_eq!(said(&openings), (None, Room::Open));
        *openings.funds.lock().unwrap() = Some(200_000);
        assert_eq!(said(&openings), (Some(0), Room::Unfunded));
        // Its range still reads as one: wallets before this check it.
        let advertised = openings.advertise().range.unwrap();
        assert_eq!(advertised.max_cap, advertised.min_cap);
        *openings.funds.lock().unwrap() = Some(1_000_000);
        assert_eq!(said(&openings), (Some(524_287), Room::Open));
        // Ten bitcoin: the most it offers, not what it holds.
        *openings.funds.lock().unwrap() = Some(1_000_000_000);
        assert_eq!(said(&openings), (Some(67_108_863), Room::Open));
        assert!(!openings.advertise().full);
    }

    /// Past half its most contracts live, the hub's info prices new ones
    /// higher at each eighth more; once all are, it opens none until one
    /// ends or is given up.
    #[test]
    fn contracts_cost_more_as_they_fill_up_and_none_open_once_full() {
        let dir = tempfile::tempdir().unwrap();
        let openings = test_openings(dir.path());
        assert_eq!(openings.load().unwrap().max, MAX_LIVE);
        openings.limit_live(8);
        let price = |o: &Openings| o.advertise().price;
        let mut prices = vec![price(&openings)];
        for n in 0..8u8 {
            let store = openings.store();
            let id = [n; 32];
            store
                .insert(&id, 0, true, &deposit(u32::from(n)), &[0; 32], funded())
                .unwrap();
            // Signed or under way alike.
            if n % 2 == 0 {
                store.save(&id, 0, true, &[0; 32], funded()).unwrap();
            }
            drop(store);
            prices.push(price(&openings));
            // Full exactly when a new opening is refused.
            assert_eq!(
                openings.advertise().full,
                openings.step_now().is_err(),
                "{n}"
            );
        }
        let fee = terms::OPENING_FEE;
        let at = |m: u64| terms::RESERVE_ALICE + fee * m;
        assert_eq!(prices, [1, 1, 1, 1, 2, 4, 8, 16, 16].map(at), "{prices:?}");
        let load = openings.load().unwrap();
        assert_eq!((load.live, load.max, load.step), (8, 8, None));
        let refused = openings.step_now().unwrap_err();
        assert_eq!(refused.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(openings.advertise().full);
        assert_eq!(openings.advertise().room(), licash_api::Room::Full);
        // One ended, one under way given up: two free, at 8 times again.
        openings.store().end(&[0; 32], 100).unwrap();
        openings.store().abandon(&[1; 32], i64::MAX).unwrap();
        assert_eq!(openings.step_now().unwrap(), 3);
        assert!(!openings.advertise().full);
        assert_eq!(price(&openings), at(8));
        // More allowed: cheaper at once.
        openings.limit_live(64);
        assert_eq!(openings.step_now().unwrap(), 0);
    }

    #[test]
    fn sweeping_holds_the_busy_mutex_until_the_abandonment_write_completes() {
        let dir = tempfile::tempdir().unwrap();
        let openings = test_openings(dir.path());
        let id = [5; 32];
        let store = openings.store();
        store
            .insert(&id, 0, true, &deposit(0), &[0; 32], funded())
            .unwrap();
        store.set_coins(&id, &[deposit(1)]).unwrap();
        std::thread::scope(|scope| {
            let sweeping = scope.spawn(|| openings.abandon_idle(&id, i64::MAX));
            let started = std::time::Instant::now();
            loop {
                match openings.busy.try_lock() {
                    Err(std::sync::TryLockError::WouldBlock) => break,
                    Ok(_) => {}
                    Err(e) => panic!("busy mutex: {e}"),
                }
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "sweep released busy before its write"
                );
                std::thread::yield_now();
            }
            drop(store);
            assert_eq!(sweeping.join().unwrap().unwrap(), Some(vec![deposit(1)]));
        });
    }

    /// A contract's largest proof takes 1,000 s; regtest's assert window
    /// leaves the prover 8 blocks, 4,800 s.
    #[test]
    fn an_opening_is_admitted_only_if_the_prover_can_defend_every_contract_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut openings = test_openings(dir.path());
        let base = Hub::peek(funded()).unwrap().base;
        let largest = run::base_cycles(&base);
        // Estimated from its quote before her Base is, no less.
        let p = base.parts();
        let mut quote = openings
            .timing()
            .quote(p.keyset.clone(), p.chain.checkpoint.clone());
        // The fixture's own limits, its header budget (the hub's quotes
        // reach past their lock, which the fixture's does not), and its
        // graph's id (the program it is proven with sets the cycles of a
        // header).
        quote.limits = p.limits.clone();
        quote.chain.max_headers = p.chain.max_headers;
        quote.graph.id = p.graph.id;
        assert!(run::quote_cycles(&quote) >= largest);
        let speed = prover::Speed {
            device: "cuda".into(),
            segment_cycles: largest,
            segment: 1_000.0 / prover::MARGIN,
            tail: 0.0,
        };
        // Without a prover, room for any.
        assert!(openings.room_for(&[0; 32], u64::MAX).is_ok());
        openings.prover = Some(prover::Prover::ready_at(dir.path(), speed));
        let commit = |n: u8| {
            let id = [n; 32];
            let store = openings.store();
            store
                .insert(&id, 0, false, &deposit(u32::from(n)), &[0; 32], funded())
                .unwrap();
            store
                .set_coins(&id, &[deposit(100 + u32::from(n))])
                .unwrap();
        };
        let room = |openings: &Openings| openings.room_for(&[0; 32], largest);
        for n in 1..=3 {
            commit(n);
        }
        assert!(room(&openings).is_ok());
        commit(4);
        let full = room(&openings).unwrap_err();
        assert_eq!(full.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(full.reason.contains("no room"), "{}", full.reason);
        // Not counted: an opening not funded, given up, ended, or the mock
        // authority's, nor the opening asking itself.
        assert!(openings.room_for(&[4; 32], largest).is_ok());
        openings
            .store()
            .insert(&[5; 32], 0, false, &deposit(5), &[0; 32], funded())
            .unwrap();
        openings
            .store()
            .insert(&[6; 32], 0, true, &deposit(6), &[0; 32], funded())
            .unwrap();
        openings
            .store()
            .set_coins(&[6; 32], &[deposit(106)])
            .unwrap();
        assert!(room(&openings).is_err());
        openings.store().end(&[4; 32], 100).unwrap();
        assert!(room(&openings).is_ok());
        commit(7);
        assert!(openings.abandon_idle(&[7; 32], i64::MAX).unwrap().is_some());
        assert!(room(&openings).is_ok());
        // The operator's scale: a slower prover than measured.
        commit(8);
        assert!(room(&openings).is_err());
        let mut scaled = test_openings(dir.path());
        scaled.prover = openings.prover.take();
        scaled.scale_proofs(0.5).unwrap();
        assert!(room(&scaled).is_ok());
        assert!(scaled.scale_proofs(0.0).is_err());
        // Not ready: nothing admitted, and why.
        scaled.prover.as_ref().unwrap().not_ready("no GPU");
        let why = room(&scaled).unwrap_err().reason;
        assert!(why.contains("not ready (no GPU)"), "{why}");
    }

    #[test]
    fn sweeping_cannot_abandon_a_busy_opening_or_unlock_one_signed_since_selection() {
        let dir = tempfile::tempdir().unwrap();
        let openings = test_openings(dir.path());
        let id = [3; 32];
        openings
            .store()
            .insert(&id, 0, true, &deposit(0), &[0; 32], funded())
            .unwrap();
        openings.store().set_coins(&id, &[deposit(1)]).unwrap();
        assert_eq!(openings.store().stale(i64::MAX).unwrap(), vec![id]);
        openings.busy().insert(id);
        assert!(openings.abandon_idle(&id, i64::MAX).unwrap().is_none());
        openings
            .store()
            .save(&id, HubPhase::Funded as u8, true, &[0; 32], funded())
            .unwrap();
        openings.busy().remove(&id);
        assert!(openings.abandon_idle(&id, i64::MAX).unwrap().is_none());
        assert_eq!(openings.store().locked().unwrap(), vec![deposit(1)]);
        drop(openings);
        assert_eq!(
            Store::open(&crate::testing::hub_data(dir.path()))
                .unwrap()
                .locked()
                .unwrap(),
            vec![deposit(1)]
        );
    }

    /// An opening refused before it was stored gives up the deposit bound
    /// to it; not one stored, nor one another task steps.
    #[test]
    fn a_refused_opening_unbinds_its_deposit_only_if_never_stored() {
        let dir = tempfile::tempdir().unwrap();
        let openings = test_openings(dir.path());
        let released = Arc::new(Mutex::new(Vec::new()));
        let told = released.clone();
        openings.close_with(
            Arc::new(|_: &[u8], _, _, _, _| Ok(())),
            Arc::new(move |id: &[u8; 32]| told.lock().unwrap().push(*id)),
        );
        let (stored, busy, refused) = ([1; 32], [2; 32], [3; 32]);
        openings
            .store()
            .insert(&stored, 0, true, &deposit(0), &[0; 32], funded())
            .unwrap();
        openings.busy().insert(busy);
        for id in [stored, busy, refused] {
            openings.unbind(&id);
        }
        assert_eq!(*released.lock().unwrap(), vec![refused]);
    }

    /// The openings under way, or signed and not funded, are counted at
    /// the store: one started meanwhile counts against the next.
    #[test]
    fn openings_are_admitted_only_below_both_caps() {
        let dir = tempfile::tempdir().unwrap();
        let openings = test_openings(dir.path());
        for n in 0..MAX_UNDER_WAY as u8 {
            assert!(!openings.advertise().full);
            let store = openings.store();
            assert!(run::admits(&store).is_ok());
            store
                .insert(&[n; 32], 0, true, &deposit(n.into()), &[0; 32], funded())
                .unwrap();
        }
        let why = run::admits(&openings.store()).unwrap_err().reason;
        assert!(why.contains("under way"), "{why}");
        // Said in its info, for a wallet to choose another hub by.
        assert!(openings.advertise().full);
    }

    #[test]
    fn abandonment_rechecks_activity_and_returns_only_the_coins_actually_abandoned() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::hub_data(dir.path())).unwrap();
        let id = [4; 32];
        store
            .insert(&id, 0, true, &deposit(0), &[0; 32], funded())
            .unwrap();
        store.set_coins(&id, &[deposit(1)]).unwrap();
        let db = rusqlite::Connection::open(dir.path().join("hub.sqlite")).unwrap();
        db.execute("UPDATE openings SET updated_at = 0", [])
            .unwrap();
        let before = crate::now() - 1;
        assert_eq!(store.stale(before).unwrap(), vec![id]);
        store.save(&id, 0, false, &[1; 32], funded()).unwrap();
        assert!(store.abandon(&id, before).unwrap().is_none());
        assert!(!store.row(&id).unwrap().unwrap().abandoned);
        // A candidate's coin snapshot is not an authorization to unlock it.
        store.set_coins(&id, &[deposit(2)]).unwrap();
        assert_eq!(
            store.abandon(&id, i64::MAX).unwrap(),
            Some(vec![deposit(2)])
        );
        assert!(store.abandon(&id, i64::MAX).unwrap().is_none());
        assert!(store.locked().unwrap().is_empty());
    }

    #[test]
    fn what_the_hub_charged_is_kept_with_the_openings_started_once_told() {
        let fee = |base, ppm| licash_api::Fee { base, ppm };
        let fees = |base, ppm, output_msat| licash_api::Fees {
            spend: fee(base, ppm),
            lock: fee(base, ppm),
            refund: fee(base, ppm),
            output_msat,
        };
        let dir = tempfile::tempdir().unwrap();
        let now = fees(1, 100, 100);
        assert_eq!(opened_for_less(dir.path(), &now).unwrap(), 0);
        assert!(!dir.path().join("hub.sqlite").exists());
        let openings = test_openings(dir.path());
        let sign = |id: u8| {
            let store = openings.store();
            assert!(store
                .insert(
                    &[id; 32],
                    0,
                    true,
                    &deposit(u32::from(id)),
                    &[0; 32],
                    funded()
                )
                .unwrap());
            store
                .save(&[id; 32], HubPhase::Funded as u8, true, &[0; 32], funded())
                .unwrap();
        };
        // Not told what it charges: nothing kept.
        sign(1);
        assert_eq!(opened_for_less(dir.path(), &now).unwrap(), 0);
        let kept = || -> i64 {
            let db = rusqlite::Connection::open(dir.path().join("hub.sqlite")).unwrap();
            db.query_row(
                "SELECT count(*) FROM openings WHERE fees IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(kept(), 0);

        openings.charging(fees(1, 50, 100));
        sign(2);
        assert_eq!(kept(), 1);
        // One never signed, one whose deposit is another's, one given up.
        assert!(openings
            .store()
            .insert(&[3; 32], 0, true, &deposit(3), &[0; 32], funded())
            .unwrap());
        assert!(!openings
            .store()
            .insert(&[4; 32], 0, true, &deposit(3), &[0; 32], funded())
            .unwrap());
        openings.store().abandon(&[3; 32], i64::MAX).unwrap();
        openings.charging(now);
        sign(5);

        // Only the one signed for less, in one fee, than it charges now.
        assert_eq!(opened_for_less(dir.path(), &now).unwrap(), 1);
        assert_eq!(opened_for_less(dir.path(), &fees(1, 50, 100)).unwrap(), 0);
        assert_eq!(opened_for_less(dir.path(), &fees(1, 100, 101)).unwrap(), 2);
        assert_eq!(opened_for_less(dir.path(), &fees(0, 0, 0)).unwrap(), 0);
        // Read by a hub that reopens them, and still of its version.
        drop(openings);
        let reopened = test_openings(dir.path());
        assert_eq!(reopened.store().signed_ids().unwrap().len(), 3);
        assert_eq!(signed(dir.path()).unwrap(), 3);
    }

    #[test]
    fn openings_read_as_stored_with_their_terms_and_none_are_made() {
        let dir = tempfile::tempdir().unwrap();
        assert!(openings(dir.path()).unwrap().is_empty());
        assert!(!dir.path().join("hub.sqlite").exists());
        let store = Store::open(&crate::testing::hub_data(dir.path())).unwrap();
        assert!(openings(dir.path()).unwrap().is_empty());
        store
            .insert(&[1; 32], 0, true, &deposit(0), &[0; 32], funded())
            .unwrap();
        store
            .save(&[1; 32], HubPhase::Funded as u8, true, &[0; 32], funded())
            .unwrap();
        // A state that does not read, given up.
        store
            .insert(&[2; 32], 0, true, &deposit(1), &[0; 32], b"state")
            .unwrap();
        store.abandon(&[2; 32], i64::MAX).unwrap();
        let all = openings(dir.path()).unwrap();
        let [funded, abandoned] = &all[..] else {
            panic!("two openings, not {all:?}");
        };
        assert_eq!(funded.id, [1; 32]);
        assert_eq!(funded.phase, Some(HubPhase::Funded));
        assert!(funded.mock && funded.signed && !funded.abandoned);
        assert!(funded.updated_at >= funded.created_at && funded.created_at > 0);
        let terms = funded.terms.as_ref().unwrap();
        let peek = Hub::peek(&crate::testing::opened().hub).unwrap();
        let parts = peek.base.parts();
        assert_eq!(
            (terms.cap, terms.close, terms.fee, terms.reserve),
            (
                u64::from(parts.cap),
                parts.graph.close_height,
                parts.fees.opening_fee_quote,
                parts.graph.reserve_alice
            )
        );
        // A 17-bit graph, her reserve 20 000 sat and the hub's 100 000.
        assert_eq!(
            (
                terms.cap,
                terms.close,
                terms.fee,
                terms.reserve,
                terms.graph
            ),
            (131_071, 504, 3_000, 20_000, (1 << 17) - 1 + 120_000)
        );
        assert_eq!(terms.funding, peek.funding.map(|tx| tx.compute_txid()));
        assert!(terms.funding.is_some());
        assert_eq!(abandoned.phase, Some(HubPhase::Termed));
        assert!(abandoned.abandoned && !abandoned.signed);
        assert_eq!(abandoned.terms, None);
    }
}
