//! The contracts protecting a provider's notes at the hubs it takes them
//! from, kept: what it takes in at a hub is held to what the contracts
//! there protect, each is replaced before it ends, what failed to be
//! replaced is drained, and one is forced closed at its safe deadline if
//! the others at its hub cannot recover all the notes held there. The
//! first contract at a hub is its operator's to open (`licash-wallet
//! open-contract`), or the keeper's where its operator said of what cap
//! ([`Settings::open_cap`]): until then, the provider takes none of that
//! hub's notes in.
//!
//! What it decides is [`plan`], of what it reads ([`Hub`], [`Kept`]);
//! [`Keeper`] reads, applies the plan and alerts the operator.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use bitcoin::FeeRate;
use licash_contracts::holder::{
    self,
    recovery::{self, Stage},
    safety, Ask, Contract, Fate, Node,
};
use licash_swaps::Provider;
use licash_wallet::{Blocks as _, PayoutState, Transport};

/// When the keeper acts on a live contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadlines {
    /// From this block on, a successor is opened to it.
    pub renew_at: u32,
    /// From this block on, it claims what the others at its hub cannot
    /// recover.
    pub claim_at: u32,
}

impl Deadlines {
    /// Of a contract whose claim request must confirm by `request_by`
    /// ([`safety::Safety::request_by`]), or none if its margin does not
    /// fit: claimed a `day` of blocks before, at once if it does not fit,
    /// and replaced `lead` blocks before that.
    pub fn new(request_by: Option<u32>, day: u32, lead: u32) -> Self {
        let claim_at = request_by.map_or(0, |by| by.saturating_sub(day));
        Self {
            renew_at: claim_at.saturating_sub(lead),
            claim_at,
        }
    }
}

/// A hub whose notes contracts must protect, as the keeper reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hub {
    /// The hub's URL, as the provider's wallet names it.
    pub url: String,
    /// Every URL the wallet knows it by.
    pub urls: Vec<String>,
    /// What the provider holds and is owed there
    /// ([`Provider::exposure`]).
    pub exposure: u64,
    /// The notes it holds there now: what a recovery claims of.
    pub notes: u64,
    /// The caps the provider may open a contract of there now: none if
    /// the hub offers its fixed terms only.
    pub sizes: Option<Sizes>,
}

/// The caps a contract the provider opens at a hub may be now, in sat:
/// at least the hub's least, and at most both the hub's most, as its
/// wallet funds it, and what the provider's largest free coin pays for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizes {
    pub least: u32,
    pub most: u32,
}

impl Sizes {
    /// Of a hub's `range`, the provider's largest free coin holding
    /// `coin` sat: none if that coin pays for none.
    pub fn of(range: licash_api::ContractRange, coin: u64) -> Option<Self> {
        let most = range.max_cap_for(coin)?;
        Some(Self {
            least: range.min_cap,
            most,
        })
    }
}

/// A contract's cap, sized to what it protects: about twice `cap` while
/// what the provider holds at its hub (`exposure`) is three quarters of
/// the `limit` its contracts there protect or more, about half while it is
/// less than a quarter, else `cap`, down to a cap
/// ([`licash_api::cap_at_most`]); within `sizes`.
pub fn resize(cap: u32, exposure: u64, limit: u64, sizes: Option<Sizes>) -> u32 {
    let Some(Sizes { least, most }) = sizes else {
        return cap;
    };
    let sized = if exposure.saturating_mul(4) >= limit.saturating_mul(3) {
        u64::from(cap) * 2 + 1
    } else if exposure.saturating_mul(4) < limit {
        u64::from(cap) / 2
    } else {
        u64::from(cap)
    };
    let sized = licash_api::cap_at_most(sized).unwrap_or(least);
    sized.clamp(least, most.max(least))
}

/// What a contract of `cap` costs at most, of one of `old_cap` costing
/// `old_price`: a quarter more, as much more again as it is larger.
fn scaled_price(old_price: u64, old_cap: u32, cap: u32) -> u64 {
    let quarter_more = old_price.saturating_mul(5) / 4;
    if cap <= old_cap || old_cap == 0 {
        return quarter_more;
    }
    let scaled = u128::from(quarter_more) * u128::from(cap) / u128::from(old_cap);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

/// A contract of the provider's, as the keeper reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    pub contract: Contract,
    /// Of a live one, when the keeper acts on it: none if its terms could
    /// not be read, which leaves it out.
    pub deadlines: Option<Deadlines>,
    /// Forced closed: a recovery of it under way, or over.
    pub recovering: bool,
    /// Of a live one past its `claim_at`: what the others at its hub,
    /// claiming later, would recover of the notes there now.
    pub others_recover: u64,
}

impl Kept {
    /// Protecting notes now, as the keeper counts it.
    fn live(&self, tip: u32) -> bool {
        !self.recovering && self.contract.live(tip) && self.deadlines.is_some()
    }

    /// Being opened: neither live nor over.
    fn opening(&self, tip: u32) -> bool {
        !self.recovering
            && !self.contract.over(tip)
            && matches!(self.contract.fate, None | Some(Fate::Open))
    }

    fn deadlines(&self) -> Deadlines {
        self.deadlines.unwrap_or(Deadlines {
            renew_at: 0,
            claim_at: 0,
        })
    }
}

/// A contract to open in place of one ending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Successor {
    /// At the hub, as the wallet names it.
    pub hub: String,
    pub replaces: [u8; 32],
    pub cap: u32,
    pub max_price: u64,
}

/// What the operator is told of, while it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alert {
    /// No contract protects notes at the hub, nor is one being opened.
    NoContract { hub: String },
    /// The provider holds or is owed more at the hub than its contracts
    /// there protect.
    Unprotected {
        hub: String,
        exposure: u64,
        limit: u64,
    },
}

impl Alert {
    /// What tells it apart from others, as it changes.
    pub fn key(&self) -> String {
        match self {
            Alert::NoContract { hub } => format!("no contract {hub}"),
            Alert::Unprotected { hub, .. } => format!("unprotected {hub}"),
        }
    }
}

/// What the keeper does in a round ([`plan`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// The most the provider may hold at each hub
    /// ([`Provider::limit_intake`]).
    pub limits: HashMap<String, u64>,
    /// Contracts to force closed now: past their `claim_at`, the others
    /// at their hubs recovering less than the notes held there.
    pub force_close: Vec<[u8; 32]>,
    /// Successors to open, in turn.
    pub successors: Vec<Successor>,
    /// Contracts to open besides, at hubs whose contracts protect too
    /// little of what is offered to the provider there: of what cap.
    pub grows: Vec<(String, u32)>,
    /// What to pay out to Bitcoin of each hub's notes, by its URL: what
    /// the provider holds there beyond its limit, a contract there having
    /// failed to be replaced.
    pub drains: Vec<(String, u64)>,
    pub alerts: Vec<Alert>,
}

/// What to do at block `tip` of the contracts `kept` at `hubs`, the
/// replacements of those `failed` having failed, those `waiting` not to
/// be tried again yet, a successor costing `max_price` at most if given,
/// else its predecessor's price and a quarter.
///
/// At each hub, the provider may hold what its live contracts there
/// protect, up to their caps: those not yet to be replaced
/// ([`Deadlines::renew_at`]), and those to be whose successor is being
/// opened, in its stead. A successor is a contract at the hub that
/// started opening as the one it replaces was to be replaced, or later;
/// each replaces one. A contract with none gets one, unless waiting:
/// of its cap, resized to what the provider holds there ([`resize`]).
/// Where the provider holds nine tenths of what its contracts protect,
/// none being opened, one more is opened, of as much as they protect. Its hub is drained once its replacement failed, or it is
/// past its `claim_at`. Past it, it is forced closed if the others there
/// claiming later would recover less than the notes held there.
pub fn plan(
    tip: u32,
    hubs: &[Hub],
    kept: &[Kept],
    failed: &HashSet<[u8; 32]>,
    waiting: &HashSet<[u8; 32]>,
    max_price: Option<u64>,
) -> Plan {
    let mut plan = Plan::default();
    for hub in hubs {
        let here: Vec<&Kept> = (kept.iter())
            .filter(|k| k.contract.at(&hub.urls) && !k.contract.over(tip))
            .collect();
        let mut limit: u64 = (here.iter())
            .filter(|k| k.live(tip) && tip < k.deadlines().renew_at)
            .map(|k| u64::from(k.contract.cap))
            .sum();
        let mut ending: Vec<&Kept> = (here.iter().copied())
            .filter(|k| k.live(tip) && k.deadlines().renew_at <= tip)
            .collect();
        ending.sort_by_key(|k| (k.deadlines().claim_at, k.contract.id));
        let mut successors: Vec<&Kept> = (here.iter().copied())
            .filter(|k| k.live(tip) || k.opening(tip))
            .collect();
        successors.sort_by_key(|k| (k.contract.since, k.contract.id));
        let mut drain = false;
        for old in ending {
            let Deadlines { renew_at, claim_at } = old.deadlines();
            let due = claim_at <= tip;
            // Past it, what the others there do not protect goes, whether
            // or not its successor is still being opened.
            drain |= due;
            let found = (successors.iter()).position(|new| {
                new.contract.id != old.contract.id && new.contract.since >= renew_at
            });
            match found.map(|at| successors.remove(at)) {
                Some(new) => {
                    if !due && new.opening(tip) {
                        limit += u64::from(old.contract.cap);
                    }
                }
                None => {
                    drain |= failed.contains(&old.contract.id);
                    if !waiting.contains(&old.contract.id) {
                        let total = limit + u64::from(old.contract.cap);
                        let cap = resize(old.contract.cap, hub.exposure, total, hub.sizes);
                        let price = scaled_price(old.contract.price, old.contract.cap, cap);
                        plan.successors.push(Successor {
                            hub: hub.url.clone(),
                            replaces: old.contract.id,
                            cap,
                            max_price: max_price.unwrap_or(price),
                        });
                    }
                }
            }
            if due && hub.notes > old.others_recover {
                plan.force_close.push(old.contract.id);
            }
        }
        let protecting = here.iter().any(|k| k.live(tip) || k.opening(tip));
        let opening = here.iter().any(|k| k.opening(tip));
        let replacing = plan.successors.iter().any(|s| s.hub == hub.url);
        let full = limit > 0 && hub.exposure.saturating_mul(10) >= limit.saturating_mul(9);
        let grow = protecting && !opening && !replacing && full && !drain;
        if let Some(sizes) = hub.sizes.filter(|_| grow) {
            let cap = u32::try_from(limit).unwrap_or(u32::MAX);
            plan.grows.push((
                hub.url.clone(),
                cap.clamp(sizes.least, sizes.most.max(sizes.least)),
            ));
        }
        if !protecting {
            plan.alerts.push(Alert::NoContract {
                hub: hub.url.clone(),
            });
        } else if hub.exposure > limit {
            plan.alerts.push(Alert::Unprotected {
                hub: hub.url.clone(),
                exposure: hub.exposure,
                limit,
            });
        }
        if drain && hub.exposure > limit {
            plan.drains.push((hub.url.clone(), hub.exposure - limit));
        }
        plan.limits.insert(hub.url.clone(), limit);
    }
    plan
}

/// What the keeper is told.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The hubs whose notes contracts must protect, by URL: every hub the
    /// provider's wallet knows, if none named.
    pub hubs: Option<Vec<String>>,
    /// Blocks kept for a forced close to play out in, and for its timeout
    /// to confirm ([`safety::of`]).
    pub exit_margin: u32,
    pub timeout_slack: u32,
    /// Blocks it counts as a day, the same on every network
    /// ([`holder::exit::DAY`]).
    pub day: u32,
    /// Blocks from a contract's successor opening to its `claim_at`.
    pub successor_lead: u32,
    /// The most a successor costs, if not its predecessor's price and a
    /// quarter: the most a contract the keeper opens first costs.
    pub max_price: Option<u64>,
    /// With [`Settings::max_price`], the cap of a contract the keeper
    /// opens at each kept hub where none protects notes nor is being
    /// opened: the first, or one after all ended. None leaves those to
    /// the operator.
    pub open_cap: Option<u32>,
    /// The provider to pay out to Bitcoin through what a contract that
    /// failed to be replaced leaves unprotected: none drains passively
    /// only, taking nothing more in.
    pub drain_via: Option<String>,
    /// Whether to look for the wallet's coins on the chain itself, as
    /// nothing else does.
    pub scan: bool,
    /// How the operator opens a contract at a hub, `{hub}` its URL.
    pub open_hint: String,
}

impl Settings {
    /// Every hub the provider's wallet knows kept, with `exit_days` for a
    /// forced close to play out in and a successor opened `successor_days`
    /// before its predecessor's safe deadline, each [`holder::exit::DAY`]
    /// blocks; told to open a first contract at a hub with `open_hint`. Its
    /// successors cost a quarter more than their predecessors at most, it
    /// drains nothing, and looks for no coins.
    pub fn new(exit_days: u32, successor_days: u32, open_hint: String) -> Self {
        let day = holder::exit::DAY;
        Self {
            hubs: None,
            exit_margin: exit_days.saturating_mul(day),
            timeout_slack: TIMEOUT_SLACK,
            day,
            successor_lead: successor_days.saturating_mul(day),
            max_price: None,
            open_cap: None,
            drain_via: None,
            scan: false,
            open_hint,
        }
    }
}

/// Blocks kept for a recovery's timeout to confirm in, as the wallet apps
/// keep them.
pub const TIMEOUT_SLACK: u32 = 6;

/// How often the keeper keeps the contracts ([`Keeper::run`]).
pub const EVERY: Duration = Duration::from_secs(60);

/// How long a hub may answer nothing before the operator hears of it.
const SILENCE: Duration = Duration::from_secs(60 * 60);

/// The first wait before a failed replacement is tried again, doubled
/// each time up to [`MAX_RETRY`].
const RETRY: Duration = Duration::from_secs(10 * 60);
const MAX_RETRY: Duration = Duration::from_secs(6 * 60 * 60);

/// Blocks a scan looks in at once.
const SCAN_BATCH: u32 = 1_000;

/// A keeper running on its own thread ([`Keeper::spawn`]), until dropped.
pub struct Running {
    _stop: tokio::sync::oneshot::Sender<()>,
    ended: tokio::sync::oneshot::Receiver<()>,
}

impl Running {
    /// Done once the keeper's thread ends: by a panic, as it never returns
    /// otherwise while running.
    pub async fn ended(&mut self) {
        let _ = (&mut self.ended).await;
    }
}

/// A replacement, or a first contract, that failed to open.
struct Failure {
    attempts: u32,
    retry_at: Instant,
    error: String,
}

impl Failure {
    fn new() -> Self {
        Self {
            attempts: 0,
            retry_at: Instant::now(),
            error: String::new(),
        }
    }

    /// Failed once more, with `error`: tried again later, the wait
    /// doubled each time up to [`MAX_RETRY`].
    fn again(&mut self, error: String) {
        self.attempts += 1;
        let wait = RETRY.saturating_mul(1 << self.attempts.min(16).saturating_sub(1));
        self.retry_at = Instant::now() + wait.min(MAX_RETRY);
        self.error = error;
    }
}

/// The keeper of a provider's contracts, kept in its wallet's file `wallet_file`.
pub struct Keeper<T: Transport> {
    provider: Arc<Provider<T>>,
    chain: Node,
    wallet_file: PathBuf,
    settings: Settings,
    /// Each live contract's [`safety::Safety::request_by`]: its signed
    /// terms never change.
    request_by: HashMap<[u8; 32], Option<u32>>,
    failures: HashMap<[u8; 32], Failure>,
    /// The first contracts that failed to open, by hub.
    first_failures: HashMap<String, Failure>,
    /// The alerts told of, by key, while they hold: those of a round's
    /// start, and of its end, after its openings.
    told: HashSet<String>,
    told_late: HashSet<String>,
    /// When each hub last answered, or the keeper started.
    answered: HashMap<String, Instant>,
    /// The caps and durations each hub last said it offers.
    ranges: HashMap<String, licash_api::ContractRange>,
    /// The chain's last estimate, for a round it gives none in.
    last_rate: Option<FeeRate>,
}

impl<T: Transport + 'static> Keeper<T> {
    /// The keeper of `provider`'s contracts in `wallet_file`, on `chain`: from now
    /// on, the provider takes no notes in at any hub until the keeper
    /// says what its contracts there protect.
    pub fn new(
        provider: Arc<Provider<T>>,
        chain: Node,
        wallet_file: PathBuf,
        settings: Settings,
    ) -> Self {
        provider.limit_intake(Some(HashMap::new()));
        Self {
            provider,
            chain,
            wallet_file,
            settings,
            request_by: HashMap::new(),
            failures: HashMap::new(),
            first_failures: HashMap::new(),
            told: HashSet::new(),
            told_late: HashSet::new(),
            answered: HashMap::new(),
            ranges: HashMap::new(),
            last_rate: None,
        }
    }

    /// Keep the contracts every `every` on a thread of its own, as their
    /// files are not shared between threads, until the handle returned is
    /// dropped: stopped at the next step it awaits, as a task aborted.
    pub fn spawn(self, every: Duration) -> std::io::Result<Running>
    where
        Self: Send,
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        // Dropped as the thread ends, however it does: told to `ended`.
        let (end, ended) = tokio::sync::oneshot::channel::<()>();
        std::thread::Builder::new()
            .name("contracts".into())
            .spawn(move || {
                let _end = end;
                runtime.block_on(async move {
                    tokio::select! {
                        () = self.run(every) => {}
                        _ = stopped => {}
                    }
                });
            })?;
        Ok(Running { _stop: stop, ended })
    }

    /// Keep the contracts every `every`, for good.
    pub async fn run(mut self, every: Duration) {
        loop {
            if let Err(e) = self.round().await {
                tracing::warn!("keeping the contracts: {e:#}");
            }
            tokio::time::sleep(every).await;
        }
    }

    /// One round: recoveries carried on, then the plan applied, the
    /// limits and forced closes first, then the openings, which take
    /// longest.
    pub async fn round(&mut self) -> Result<Plan> {
        let provider = self.provider.clone();
        let wallet = provider.wallet();
        let tip = self.chain.height().await.map_err(|e| anyhow!(e))?;
        let mut alerts: Vec<(String, String)> = Vec::new();
        if self.settings.scan {
            if let Err(e) = self.scan(tip).await {
                tracing::warn!("looking for the wallet's coins: {e:#}");
            }
        }
        // Read from the contracts alone: nothing here stops a forced close.
        if let Err(e) = holder::fees::agree(wallet, &self.wallet_file, Some(tip)) {
            tracing::warn!("agreeing to the fees the contracts opened under: {e:#}");
        }
        let rate = self.rate().await;
        match recovery::advance(wallet, &self.chain, &self.wallet_file, rate).await {
            Ok(recoveries) => {
                for r in recoveries.iter().filter(|r| r.stage == Stage::Lost) {
                    let id = licash_contracts::hex_id(&r.id);
                    alerts.push((
                        format!("lost {id}"),
                        format!(
                            "contract {id}'s forced close lost its collateral to an \
                             unrecognized transaction: look at it on Bitcoin"
                        ),
                    ));
                }
            }
            Err(e) => tracing::warn!("carrying the recoveries on: {e:#}"),
        }

        let contracts = holder::list(&self.wallet_file)?;
        let kept = self.read(&contracts, tip, &mut alerts)?;
        let hubs = self.hubs()?;
        let kept = self.others_recover(kept, &hubs, tip)?;
        let now = Instant::now();
        self.failures
            .retain(|id, _| kept.iter().any(|k| k.contract.id == *id));
        let failed: HashSet<_> = self.failures.keys().copied().collect();
        let waiting = (self.failures.iter())
            .filter(|(_, f)| f.retry_at > now)
            .map(|(id, _)| *id)
            .collect();
        let plan = plan(
            tip,
            &hubs,
            &kept,
            &failed,
            &waiting,
            self.settings.max_price,
        );

        self.provider.limit_intake(Some(plan.limits.clone()));
        for id in &plan.force_close {
            let hex = licash_contracts::hex_id(id);
            let told = match recovery::force_close(wallet, &self.chain, &self.wallet_file, id, rate).await
            {
                Ok(r) => format!(
                    "forced contract {hex} closed at its safe deadline: claiming {} sat in {} notes \
                     the others at its hub cannot recover",
                    r.claimed, r.notes
                ),
                Err(e) => format!("could not force contract {hex} closed at its safe deadline: {e:#}"),
            };
            alerts.push((format!("force close {hex}"), told));
        }
        for alert in &plan.alerts {
            alerts.push((alert.key(), self.say(alert)));
        }
        for hub in &hubs {
            self.listen(hub, &mut alerts).await;
        }
        tell(&self.provider, &mut self.told, alerts);

        if let Err(e) = holder::resume(wallet, &self.chain, &self.wallet_file).await {
            tracing::warn!("carrying the contracts being opened on: {e:#}");
        }
        let mut alerts = Vec::new();
        if let Some(via) = self.settings.drain_via.clone() {
            for (hub, excess) in &plan.drains {
                self.drain(&via, &hubs, hub, *excess, rate, &mut alerts)
                    .await;
            }
        }
        if let Err(e) = self.follow_payouts().await {
            tracing::warn!("following the drains' payouts: {e:#}");
        }
        for successor in &plan.successors {
            self.replace(successor, &mut alerts).await;
        }
        self.open_firsts(&plan, &mut alerts).await;
        for (id, failure) in &self.failures {
            let hex = licash_contracts::hex_id(id);
            alerts.push((
                format!("replace {hex}"),
                format!(
                    "could not replace contract {hex} ({} tries): {}; its hub is drained",
                    failure.attempts, failure.error
                ),
            ));
        }
        for (hub, failure) in &self.first_failures {
            alerts.push((
                format!("open at {hub}"),
                format!(
                    "could not open a contract at hub {hub} ({} tries): {}",
                    failure.attempts, failure.error
                ),
            ));
        }
        tell(&self.provider, &mut self.told_late, alerts);
        Ok(plan)
    }

    /// The contracts as the keeper counts them, each live one's deadlines
    /// read once.
    fn read(
        &mut self,
        contracts: &[Contract],
        tip: u32,
        alerts: &mut Vec<(String, String)>,
    ) -> Result<Vec<Kept>> {
        let wallet = self.provider.wallet();
        let recovering: HashSet<[u8; 32]> = (recovery::recoveries(&self.wallet_file)?.into_iter())
            .map(|r| r.id)
            .collect();
        let (margin, slack) = (self.settings.exit_margin, self.settings.timeout_slack);
        let mut kept = Vec::new();
        for contract in contracts {
            let hex = licash_contracts::hex_id(&contract.id);
            let deadlines = match contract.live(tip) {
                false => None,
                true => {
                    let request_by = match self.request_by.get(&contract.id) {
                        Some(by) => Ok(*by),
                        None => {
                            safety::of(wallet, &self.wallet_file, &contract.id, tip, margin, slack)
                                .map(|s| s.request_by)
                        }
                    };
                    match request_by {
                        Ok(by) => {
                            self.request_by.insert(contract.id, by);
                            if by.is_none() {
                                alerts.push((
                                    format!("margin {hex}"),
                                    format!(
                                        "contract {hex} leaves no room for a forced close to play out: \
                                         claiming from it at once, if needed"
                                    ),
                                ));
                            }
                            Some(Deadlines::new(
                                by,
                                self.settings.day,
                                self.settings.successor_lead,
                            ))
                        }
                        Err(e) => {
                            alerts.push((
                                format!("unreadable {hex}"),
                                format!("contract {hex}'s terms cannot be read, so it counts for nothing: {e:#}"),
                            ));
                            None
                        }
                    }
                }
            };
            kept.push(Kept {
                contract: contract.clone(),
                deadlines,
                recovering: recovering.contains(&contract.id),
                others_recover: 0,
            });
        }
        Ok(kept)
    }

    /// The hubs whose notes contracts must protect, as they stand.
    fn hubs(&self) -> Result<Vec<Hub>> {
        let wallet = self.provider.wallet();
        let named = match &self.settings.hubs {
            Some(hubs) => hubs.clone(),
            None => wallet.hubs()?.into_iter().map(|(url, _)| url).collect(),
        };
        let balance = wallet.balance()?;
        let stored: HashMap<String, licash_api::Info> = wallet.hubs()?.into_iter().collect();
        let largest = holder::coins(wallet, &self.wallet_file)?
            .first()
            .map_or(0, |c| c.value);
        let mut hubs = Vec::new();
        for url in named {
            let urls = wallet.hub_urls(&url)?;
            if urls.is_empty() {
                tracing::warn!(%url, "no hub the provider's wallet knows");
                continue;
            }
            let notes = (balance.iter())
                .filter(|b| urls.contains(&b.hub))
                .map(|b| b.available)
                .sum();
            // As it last said, else as the wallet keeps it.
            let range = (self.ranges.get(&url).copied()).or_else(|| {
                stored
                    .get(&url)
                    .and_then(|i| i.contracts)
                    .and_then(|c| c.range)
            });
            hubs.push(Hub {
                exposure: self.provider.exposure(&url)?,
                sizes: range.and_then(|r| Sizes::of(r, largest)),
                url,
                urls,
                notes,
            });
        }
        Ok(hubs)
    }

    /// `kept`, with what the others at its hub claiming later would
    /// recover of each live one past its `claim_at`.
    fn others_recover(&self, mut kept: Vec<Kept>, hubs: &[Hub], tip: u32) -> Result<Vec<Kept>> {
        let due: Vec<usize> = (0..kept.len())
            .filter(|&i| kept[i].live(tip) && kept[i].deadlines().claim_at <= tip)
            .collect();
        for i in due {
            let Some(hub) = hubs.iter().find(|h| kept[i].contract.at(&h.urls)) else {
                continue;
            };
            let others: Vec<Contract> = (kept.iter())
                .filter(|k| k.contract.at(&hub.urls) && k.live(tip))
                .filter(|k| k.deadlines().claim_at > tip)
                .map(|k| k.contract.clone())
                .collect();
            let each = holder::coverage(self.provider.wallet(), &self.wallet_file, &others, tip)?;
            kept[i].others_recover = each.values().sum();
        }
        Ok(kept)
    }

    /// The operator's words for `alert`.
    fn say(&self, alert: &Alert) -> String {
        match alert {
            Alert::NoContract { hub } if self.settings.open_cap.is_some() => format!(
                "no contract protects the notes at hub {hub}: none are taken in there until \
                 the one the keeper opens is"
            ),
            Alert::NoContract { hub } => format!(
                "no contract protects the notes at hub {hub}: none are taken in there until \
                 one is opened, with `{}`",
                self.settings.open_hint.replace("{hub}", hub)
            ),
            Alert::Unprotected {
                hub,
                exposure,
                limit,
            } => format!(
                "{exposure} sat held at or owed by hub {hub}, where contracts protect {limit} \
                 sat: none more are taken in there"
            ),
        }
    }

    /// Ask `hub` how it stands: whether it answers, and charges no more
    /// than its contracts agreed.
    async fn listen(&mut self, hub: &Hub, alerts: &mut Vec<(String, String)>) {
        let wallet = self.provider.wallet();
        let now = Instant::now();
        match wallet.hub_info(&hub.url).await {
            Ok(info) => {
                self.answered.insert(hub.url.clone(), now);
                match info.contracts.and_then(|c| c.range) {
                    Some(range) => self.ranges.insert(hub.url.clone(), range),
                    None => self.ranges.remove(&hub.url),
                };
                let ceilings = wallet.fee_ceilings(&hub.url).ok().flatten();
                if ceilings.is_some_and(|c| info.fees.above(&c)) {
                    alerts.push((
                        format!("fees {}", hub.url),
                        format!(
                            "hub {} charges more than its contracts agreed: nothing is paid there \
                             until its fees are approved, with `licash-wallet approve-fees {}`",
                            hub.url, hub.url
                        ),
                    ));
                }
            }
            Err(e) => {
                let since = *self.answered.entry(hub.url.clone()).or_insert(now);
                if now.duration_since(since) >= SILENCE {
                    alerts.push((
                        format!("silent {}", hub.url),
                        format!(
                            "hub {} has not answered for over an hour: {e}. Its contracts are \
                             forced closed at their safe deadlines all the same, if needed",
                            hub.url
                        ),
                    ));
                }
            }
        }
    }

    /// Pay out what the provider holds at `url` beyond its limit there
    /// through the provider at `via`, to its own address on Bitcoin: one
    /// payout under way from a hub at once.
    async fn drain(
        &self,
        via: &str,
        hubs: &[Hub],
        url: &str,
        excess: u64,
        rate: FeeRate,
        alerts: &mut Vec<(String, String)>,
    ) {
        let wallet = self.provider.wallet();
        let Some(hub) = hubs.iter().find(|h| h.url == url) else {
            return;
        };
        let under_way = |p: &licash_wallet::Payout| {
            matches!(p.state, PayoutState::Open | PayoutState::Claimed)
                && hub.urls.contains(&p.from)
        };
        // Its fees are locked beside it, from the same notes: at most 1% of
        // them, or 1 000 sat if that is more.
        let max_fee = (hub.notes / 100).max(1_000);
        let amount = excess.min(hub.notes.saturating_sub(max_fee));
        let paid = async {
            if wallet.payouts()?.iter().any(under_way) || amount == 0 {
                return Ok(None);
            }
            let to = wallet.fallback_address()?.to_string();
            let quote = wallet
                .payout_quote(via, url, &to, amount, max_fee, rate)
                .await?;
            wallet.payout(&quote).await.map(Some)
        };
        match paid.await {
            Ok(Some(payout)) => alerts.push((
                format!("drain {}", payout.hash),
                format!("draining {amount} sat of hub {url}'s notes to Bitcoin through {via}"),
            )),
            Ok(None) => {}
            Err(e) => alerts.push((
                format!("drain failed {url}"),
                format!("could not drain {amount} sat of hub {url}'s notes through {via}: {e}"),
            )),
        }
    }

    /// Carry the wallet's payouts on, its claims broadcast.
    async fn follow_payouts(&self) -> Result<()> {
        let wallet = self.provider.wallet();
        let open =
            |p: &licash_wallet::Payout| matches!(p.state, PayoutState::Open | PayoutState::Claimed);
        if !wallet.payouts()?.iter().any(open) {
            return Ok(());
        }
        let (_, pending) = wallet.follow_payouts(&self.chain).await?;
        for (id, reason) in pending {
            tracing::debug!(%id, reason, "drain pending");
        }
        for claim in wallet.payout_claims()? {
            if let Err(e) = holder::Chain::broadcast(&self.chain, &claim).await {
                tracing::warn!(txid = %claim.compute_txid(), "broadcasting a drain's claim: {e}");
            }
        }
        Ok(())
    }

    /// Open a contract at each hub the plan says none protects notes at,
    /// where the operator said of what cap ([`Settings::open_cap`]), and
    /// one more where the plan grows what is protected ([`Plan::grows`]),
    /// each costing [`Settings::max_price`] at most: a failure kept to
    /// try again later.
    async fn open_firsts(&mut self, plan: &Plan, alerts: &mut Vec<(String, String)>) {
        let Some(max_price) = self.settings.max_price else {
            return;
        };
        let firsts = (plan.alerts.iter())
            .filter_map(|a| match a {
                Alert::NoContract { hub } => Some(hub),
                Alert::Unprotected { .. } => None,
            })
            .filter_map(|hub| {
                Some((
                    hub.clone(),
                    self.settings.open_cap?,
                    "none protecting notes there",
                ))
            });
        let grows =
            (plan.grows.iter()).map(|(hub, cap)| (hub.clone(), *cap, "those there nearly full"));
        let opens: Vec<(String, u32, &str)> = firsts.chain(grows).collect();
        self.first_failures
            .retain(|hub, _| opens.iter().any(|(h, _, _)| h == hub));
        let now = Instant::now();
        for (hub, cap, why) in opens {
            if (self.first_failures.get(&hub)).is_some_and(|f| f.retry_at > now) {
                continue;
            }
            match self.open(&hub, cap, max_price).await {
                Ok(new) => {
                    self.first_failures.remove(&hub);
                    alerts.push((
                        format!("opened at {hub}"),
                        format!(
                            "opening contract {} at hub {hub}, {why}: {} sat for {} sat protected",
                            licash_contracts::hex_id(&new.id),
                            new.price,
                            new.cap
                        ),
                    ));
                }
                Err(e) => {
                    tracing::warn!(%hub, "opening a contract: {e:#}");
                    let failure = self.first_failures.entry(hub);
                    failure.or_insert_with(Failure::new).again(format!("{e:#}"));
                }
            }
        }
    }

    /// Open a contract at `hub` of `cap`, or as near as it and the
    /// wallet's largest free coin let it be now ([`Sizes`]), of the
    /// longest term it offers, costing `max_price` at most, from a coin
    /// of the wallet's own.
    async fn open(&self, hub: &str, cap: u32, max_price: u64) -> Result<Contract> {
        let wallet = self.provider.wallet();
        if !wallet.hubs()?.iter().any(|(url, _)| url == hub) {
            return Err(anyhow!("the wallet no longer trusts {hub}"));
        }
        let info = wallet.hub_info(hub).await?;
        let offered = (info.contracts).ok_or_else(|| anyhow!("{hub} opens no contracts now"))?;
        let (blocks, cap) = match offered.range {
            Some(range) => {
                let largest = holder::coins(wallet, &self.wallet_file)?
                    .first()
                    .map_or(0, |c| c.value);
                let sizes = Sizes::of(range, largest)
                    .ok_or_else(|| anyhow!("no free coin pays for a contract at {hub}"))?;
                (
                    range.max_blocks,
                    Some(cap.clamp(sizes.least, sizes.most.max(sizes.least))),
                )
            }
            None => (offered.blocks, None),
        };
        let ask = Ask {
            blocks,
            max_price,
            cap,
            // the cap is the liquidity it asks of the hub
            inbound: 0,
            deposit: None,
        };
        holder::open_with(wallet, &self.chain, &self.wallet_file, hub, ask).await
    }

    /// Open `successor`, of the longest term its hub offers: a failure
    /// kept to try again later.
    async fn replace(&mut self, successor: &Successor, alerts: &mut Vec<(String, String)>) {
        let hex = licash_contracts::hex_id(&successor.replaces);
        let opened = self.open(&successor.hub, successor.cap, successor.max_price);
        match opened.await {
            Ok(new) => {
                self.failures.remove(&successor.replaces);
                alerts.push((
                    format!("replaced {hex}"),
                    format!(
                        "opening contract {} at hub {} to replace contract {hex}: {} sat for {} sat \
                         protected",
                        licash_contracts::hex_id(&new.id),
                        successor.hub,
                        new.price,
                        new.cap
                    ),
                ));
            }
            Err(e) => {
                let failure = self.failures.entry(successor.replaces);
                failure.or_insert_with(Failure::new).again(format!("{e:#}"));
                tracing::warn!(contract = %hex, hub = %successor.hub, "replacing a contract: {e:#}");
            }
        }
    }

    /// Look for the wallet's coins up to `tip`: from it, the first time.
    async fn scan(&self, tip: u32) -> Result<()> {
        let wallet = self.provider.wallet();
        if wallet.silent_next()?.is_none() {
            wallet.watch_silent(None, tip)?;
        }
        loop {
            let scanned = wallet.scan_silent(None, &self.chain, SCAN_BATCH).await?;
            if scanned.next > scanned.height {
                return Ok(());
            }
        }
    }

    /// The chain's estimate of a rate confirming within 6 blocks, at least
    /// the least relayed: its last one if it gives none now.
    async fn rate(&mut self) -> FeeRate {
        let estimate = self.chain.0.fee_rate(6).await.unwrap_or_else(|e| {
            tracing::warn!("no fee estimate: {e:#}");
            None
        });
        let rate = round_rate(estimate, self.last_rate);
        self.last_rate = Some(rate);
        rate
    }
}

/// The rate of a round the chain estimated at `estimate`, its last one
/// `last`: a forced close's transactions wait on no estimate for the least
/// rate relayed, which may confirm too late.
fn round_rate(estimate: Option<FeeRate>, last: Option<FeeRate>) -> FeeRate {
    estimate
        .or(last)
        .unwrap_or(FeeRate::BROADCAST_MIN)
        .max(FeeRate::BROADCAST_MIN)
}

/// Tell the operator through `provider` of the `alerts` not in `told`,
/// by key, and forget those that no longer hold: told again if they hold
/// again.
fn tell<T: Transport>(
    provider: &Provider<T>,
    told: &mut HashSet<String>,
    alerts: Vec<(String, String)>,
) {
    let holding: HashSet<&String> = alerts.iter().map(|(key, _)| key).collect();
    told.retain(|key| holding.contains(key));
    for (key, message) in alerts {
        if told.insert(key) {
            tracing::warn!("{message}");
            if let Err(e) = provider.alert(&message) {
                tracing::warn!("alerting the operator: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::OutPoint;
    use licash_contracts::holder::Phase;

    #[test]
    fn a_round_without_an_estimate_pays_the_last_one() {
        let rate = |sat| FeeRate::from_sat_per_vb(sat).unwrap();
        assert_eq!(round_rate(Some(rate(20)), Some(rate(50))), rate(20));
        assert_eq!(round_rate(None, Some(rate(50))), rate(50));
        assert_eq!(round_rate(None, None), FeeRate::BROADCAST_MIN);
        assert_eq!(
            round_rate(Some(FeeRate::ZERO), None),
            FeeRate::BROADCAST_MIN
        );
    }

    #[tokio::test]
    async fn a_keepers_thread_ending_in_a_panic_is_told() {
        let (stop, _stopped) = tokio::sync::oneshot::channel();
        let (end, ended) = tokio::sync::oneshot::channel::<()>();
        let mut running = Running { _stop: stop, ended };
        let thread = std::thread::spawn(move || {
            let _end = end;
            panic!("a bug");
        });
        assert!(thread.join().is_err());
        let told = tokio::time::timeout(std::time::Duration::from_secs(1), running.ended());
        assert!(told.await.is_ok());
    }

    const HUB: &str = "https://hub.example";
    const OTHER: &str = "https://other.example";
    const DAY: u32 = 144;
    const LEAD: u32 = 14 * DAY;

    /// A contract of `cap` at HUB whose claim request must confirm by
    /// `request_by`, started opening at `since`, live.
    fn kept(id: u8, cap: u32, since: u32, request_by: u32) -> Kept {
        Kept {
            contract: Contract {
                id: [id; 32],
                hub: HUB.into(),
                phase: Phase::Funded,
                mock: true,
                deposit: OutPoint::null(),
                value: 100_000,
                price: 1_000,
                cap,
                assert_height: request_by + 3 * DAY,
                close_height: request_by + 10 * DAY,
                since,
                funding: None,
                fate: Some(Fate::Live),
                abandoned: None,
                created_at: 0,
                folded: None,
                funded: 0,
                funded_received: false,
            },
            deadlines: Some(Deadlines::new(Some(request_by), DAY, LEAD)),
            recovering: false,
            others_recover: 0,
        }
    }

    /// As [`kept`], being opened.
    fn opening(id: u8, cap: u32, since: u32) -> Kept {
        let mut k = kept(id, cap, since, 1_000_000);
        k.contract.fate = None;
        k.contract.phase = Phase::Signing;
        k.deadlines = None;
        k
    }

    fn hub(exposure: u64, notes: u64) -> Hub {
        Hub {
            url: HUB.into(),
            urls: vec![HUB.into(), "http://hub.example".into()],
            exposure,
            notes,
            sizes: None,
        }
    }

    fn none() -> HashSet<[u8; 32]> {
        HashSet::new()
    }

    fn planned(tip: u32, hubs: &[Hub], kept: &[Kept]) -> Plan {
        plan(tip, hubs, kept, &none(), &none(), None)
    }

    fn sized(exposure: u64, notes: u64, least: u32, most: u32) -> Hub {
        Hub {
            sizes: Some(Sizes { least, most }),
            ..hub(exposure, notes)
        }
    }

    #[test]
    fn caps_double_while_nearly_full_and_halve_while_nearly_empty_within_sizes() {
        let sizes = Some(Sizes {
            least: 131_071,
            most: 4_194_303,
        });
        let cap = 1_048_575;
        assert_eq!(resize(cap, 75_000, 100_000, sizes), 2_097_151);
        assert_eq!(resize(cap, 74_999, 100_000, sizes), cap);
        assert_eq!(resize(cap, 25_000, 100_000, sizes), cap);
        assert_eq!(resize(cap, 24_999, 100_000, sizes), 524_287);
        // Within what the hub and the provider's coin let it be.
        assert_eq!(resize(4_194_303, 800_000, 800_000, sizes), 4_194_303);
        assert_eq!(resize(131_071, 0, 6_000, sizes), 131_071);
        // Any cap kept as it is; one its payout pays not exactly (a rest
        // under 512 sat), down to one.
        assert_eq!(resize(1_500_000, 50, 100, sizes), 1_500_000);
        assert_eq!(resize(1_048_575 + 100, 50, 100, sizes), 1_048_575);
        assert_eq!(resize(1_500_000, 75, 100, sizes), 3_000_001);
        // Of fixed terms only: as it was.
        assert_eq!(resize(131_071, 4_096, 4_096, None), 131_071);
        // A coin of 1 000 000 sat, twice it at most, at a hub funding
        // 33 554 431: twice it.
        let range = licash_api::ContractRange {
            min_cap: 131_071,
            max_cap: 33_554_431,
            min_blocks: 432,
            max_blocks: 52_560,
            per_coin: 2,
            reserve: 20_000,
            fee: 3_000,
            ppm_year: 10_000,
            ppm_year_funded: 0,
            year_blocks: licash_api::YEAR_BLOCKS,
        };
        assert_eq!(
            Sizes::of(range, 1_000_000),
            Some(Sizes {
                least: 131_071,
                most: 2_000_000
            })
        );
        assert_eq!(Sizes::of(range, 65_535), None);
    }

    #[test]
    fn a_successor_is_sized_to_what_its_hub_holds_and_priced_as_much_more() {
        let old = kept(1, 131_071, 0, 50_000);
        let renew_at = old.deadlines.unwrap().renew_at;
        let full = planned(
            renew_at,
            &[sized(100_000, 100_000, 131_071, 4_194_303)],
            std::slice::from_ref(&old),
        );
        // The next size up, about twice it.
        assert_eq!(full.successors[0].cap, 262_143);
        let price = old.contract.price * 5 / 4 * 2;
        assert_eq!(full.successors[0].max_price, price);
        // Being replaced: none more besides.
        assert!(full.grows.is_empty());
        let old = kept(1, 262_143, 0, 50_000);
        let idle = planned(
            renew_at,
            &[sized(500, 500, 131_071, 4_194_303)],
            std::slice::from_ref(&old),
        );
        assert_eq!(idle.successors[0].cap, 131_071);
        assert_eq!(idle.successors[0].max_price, old.contract.price * 5 / 4);
    }

    #[test]
    fn a_hub_nearly_full_gets_one_more_contract_of_as_much() {
        let live = kept(1, 100_000, 0, 50_000);
        let plan = planned(
            100,
            &[sized(90_000, 90_000, 4_096, 1_000_000)],
            std::slice::from_ref(&live),
        );
        assert_eq!(plan.grows, [(HUB.to_owned(), 100_000)]);
        // Not yet nearly full, of fixed terms only, or one being opened: none.
        let plan = planned(
            100,
            &[sized(89_999, 89_999, 4_096, 1_000_000)],
            std::slice::from_ref(&live),
        );
        assert!(plan.grows.is_empty());
        let plan = planned(100, &[hub(100_000, 100_000)], std::slice::from_ref(&live));
        assert!(plan.grows.is_empty());
        let both = [live, opening(2, 100_000, 90)];
        let plan = planned(100, &[sized(100_000, 100_000, 4_096, 1_000_000)], &both);
        assert!(plan.grows.is_empty());
    }

    #[test]
    fn deadlines_come_a_day_before_the_request_and_a_lead_before_that() {
        let d = Deadlines::new(Some(10_000), DAY, LEAD);
        assert_eq!(
            (d.claim_at, d.renew_at),
            (10_000 - DAY, 10_000 - DAY - LEAD)
        );
        // A margin that does not fit: claimed at once.
        let d = Deadlines::new(None, DAY, LEAD);
        assert_eq!((d.claim_at, d.renew_at), (0, 0));
        assert_eq!(Deadlines::new(Some(100), DAY, LEAD).renew_at, 0);
    }

    #[test]
    fn a_day_is_the_same_blocks_on_every_network() {
        // Counted in blocks, Mutinynet's too: its quicker blocks are for
        // its tests to meet reorganizations with.
        let settings = Settings::new(2, 1, String::new());
        assert_eq!(
            (settings.day, settings.exit_margin, settings.successor_lead),
            (DAY, 2 * DAY, DAY)
        );
    }

    #[test]
    fn a_hub_without_contracts_takes_nothing_in_and_is_told_of() {
        let plan = planned(100, &[hub(500, 500)], &[]);
        assert_eq!(plan.limits, HashMap::from([(HUB.to_owned(), 0)]));
        assert_eq!(plan.alerts, [Alert::NoContract { hub: HUB.into() }]);
        assert!(plan.successors.is_empty() && plan.force_close.is_empty());
        // Nor is it drained: nothing was replaced, nothing failed.
        assert!(plan.drains.is_empty());
        // One being opened is no alert: the operator is opening it.
        let plan = planned(100, &[hub(0, 0)], &[opening(1, 4_096, 90)]);
        assert_eq!(plan.limits[HUB], 0);
        assert!(plan.alerts.is_empty(), "{:?}", plan.alerts);
    }

    #[test]
    fn a_hub_takes_in_up_to_the_caps_of_its_live_contracts() {
        let at_other = Kept {
            contract: Contract {
                hub: OTHER.into(),
                ..kept(3, 8_192, 0, 50_000).contract
            },
            ..kept(3, 8_192, 0, 50_000)
        };
        let mut recovering = kept(4, 2_048, 0, 50_000);
        recovering.recovering = true;
        let mut dead = opening(5, 2_048, 0);
        dead.contract.fate = Some(Fate::Dead);
        let mut unread = kept(6, 2_048, 0, 50_000);
        unread.deadlines = None;
        let all = [
            kept(1, 4_096, 0, 50_000),
            kept(2, 1_024, 0, 60_000),
            at_other,
            recovering,
            dead,
            unread,
        ];
        let plan = planned(100, &[hub(5_000, 4_000)], &all);
        assert_eq!(plan.limits, HashMap::from([(HUB.to_owned(), 5_120)]));
        assert!(plan.alerts.is_empty() && plan.successors.is_empty());
        // Beyond them: told of.
        let plan = planned(100, &[hub(6_000, 6_000)], &all);
        assert_eq!(
            plan.alerts,
            [Alert::Unprotected {
                hub: HUB.into(),
                exposure: 6_000,
                limit: 5_120
            }]
        );
        assert!(plan.drains.is_empty());
    }

    #[test]
    fn a_contract_to_be_replaced_gets_a_successor_of_its_cap_and_counts_while_it_opens() {
        let old = kept(1, 4_096, 0, 50_000);
        let renew_at = old.deadlines.unwrap().renew_at;
        // Not yet: counted, no successor.
        let plan = planned(
            renew_at - 1,
            &[hub(4_000, 4_000)],
            std::slice::from_ref(&old),
        );
        assert_eq!(plan.limits[HUB], 4_096);
        assert!(plan.successors.is_empty());
        // Due to be replaced: not counted, a successor asked for at its
        // price and a quarter, or the most given.
        let plan = planned(renew_at, &[hub(4_000, 4_000)], std::slice::from_ref(&old));
        assert_eq!(plan.limits[HUB], 0);
        let successor = Successor {
            hub: HUB.into(),
            replaces: [1; 32],
            cap: 4_096,
            max_price: 1_250,
        };
        assert_eq!(plan.successors, [successor]);
        assert!(plan.drains.is_empty() && plan.force_close.is_empty());
        let most = super::plan(
            renew_at,
            &[hub(4_000, 4_000)],
            std::slice::from_ref(&old),
            &none(),
            &none(),
            Some(900),
        );
        assert_eq!(most.successors[0].max_price, 900);
        // Its successor being opened: counted in its stead.
        let new = opening(2, 4_096, renew_at);
        let plan = planned(renew_at + 5, &[hub(4_000, 4_000)], &[old.clone(), new]);
        assert_eq!(plan.limits[HUB], 4_096);
        assert!(plan.successors.is_empty() && plan.alerts.is_empty());
        // Its successor live: that counts, the old one not.
        let new = kept(2, 4_096, renew_at, 90_000);
        let plan = planned(renew_at + 5, &[hub(4_000, 4_000)], &[old, new]);
        assert_eq!(plan.limits[HUB], 4_096);
        assert!(plan.successors.is_empty() && plan.alerts.is_empty());
    }

    #[test]
    fn a_contract_opened_before_another_was_to_be_replaced_is_not_its_successor() {
        let old = kept(1, 4_096, 0, 50_000);
        let renew_at = old.deadlines.unwrap().renew_at;
        // Opened beside it, before: each replaced in turn.
        let beside = kept(2, 4_096, renew_at - 1, 90_000);
        let plan = planned(renew_at, &[hub(0, 0)], &[old.clone(), beside.clone()]);
        assert_eq!(plan.successors.len(), 1);
        assert_eq!(plan.successors[0].replaces, [1; 32]);
        assert_eq!(plan.limits[HUB], 4_096);
        // Two ending, one successor: the first ending replaced by it.
        let other = kept(3, 2_048, 0, 51_000);
        let new = opening(4, 4_096, renew_at + 2_000);
        let tip = renew_at + 2_000;
        let plan = planned(tip, &[hub(0, 0)], &[other, old, new, beside]);
        assert_eq!(plan.successors.len(), 1);
        assert_eq!(plan.successors[0].replaces, [3; 32]);
        assert_eq!(plan.successors[0].cap, 2_048);
        // The beside one, and the old one in place of its opening one.
        assert_eq!(plan.limits[HUB], 4_096 + 4_096);
    }

    #[test]
    fn a_hub_is_drained_once_a_replacement_failed_and_retried_once_waited() {
        let old = kept(1, 4_096, 0, 50_000);
        let renew_at = old.deadlines.unwrap().renew_at;
        let failed = HashSet::from([[1; 32]]);
        let hubs = [hub(3_000, 2_500)];
        let plan = super::plan(
            renew_at + 1,
            &hubs,
            std::slice::from_ref(&old),
            &failed,
            &failed,
            None,
        );
        assert_eq!(plan.drains, [(HUB.to_owned(), 3_000)]);
        assert!(plan.successors.is_empty());
        // Waited: tried again, still draining.
        let plan = super::plan(
            renew_at + 1,
            &hubs,
            std::slice::from_ref(&old),
            &failed,
            &none(),
            None,
        );
        assert_eq!(plan.drains, [(HUB.to_owned(), 3_000)]);
        assert_eq!(plan.successors.len(), 1);
        // Within what the others there protect: nothing to drain.
        let beside = kept(2, 4_096, 0, 90_000);
        let plan = super::plan(renew_at + 1, &hubs, &[old, beside], &failed, &failed, None);
        assert!(plan.drains.is_empty());
    }

    #[test]
    fn at_its_claim_deadline_a_contract_claims_only_what_the_others_cannot_recover() {
        let mut old = kept(1, 4_096, 0, 50_000);
        let claim_at = old.deadlines.unwrap().claim_at;
        // A successor live, recovering all the notes there: no claim.
        old.others_recover = 4_000;
        let new = kept(2, 4_096, claim_at - LEAD, 90_000);
        let all = [old.clone(), new.clone()];
        let plan = planned(claim_at, &[hub(4_000, 4_000)], &all);
        assert!(plan.force_close.is_empty() && plan.drains.is_empty());
        assert_eq!(plan.limits[HUB], 4_096);
        // Recovering less than the notes there: claimed, whatever the
        // successor, and drained.
        old.others_recover = 3_999;
        let all = [old.clone(), new];
        let plan = planned(claim_at, &[hub(4_000, 4_000)], &all);
        assert_eq!(plan.force_close, [[1; 32]]);
        // Its successor still being opened: no longer counted in its
        // stead, so its hub is drained, and no other successor asked for.
        let late = opening(2, 4_096, claim_at - LEAD);
        let plan = planned(claim_at, &[hub(4_000, 4_000)], &[old.clone(), late]);
        assert_eq!(plan.force_close, [[1; 32]]);
        assert_eq!(plan.limits[HUB], 0);
        assert_eq!(plan.drains, [(HUB.to_owned(), 4_000)]);
        assert!(plan.successors.is_empty());
        // No successor: claimed, drained, replaced all the same.
        old.others_recover = 0;
        let plan = planned(
            claim_at + 3,
            &[hub(4_000, 4_000)],
            std::slice::from_ref(&old),
        );
        assert_eq!(plan.force_close, [[1; 32]]);
        assert_eq!(plan.drains, [(HUB.to_owned(), 4_000)]);
        assert_eq!(plan.successors.len(), 1);
        assert_eq!(plan.limits[HUB], 0);
        // No notes there: nothing to claim.
        let plan = planned(claim_at, &[hub(0, 0)], std::slice::from_ref(&old));
        assert!(plan.force_close.is_empty());
        // Forced closed already: never again, nor replaced.
        old.recovering = true;
        let plan = planned(
            claim_at + 3,
            &[hub(4_000, 4_000)],
            std::slice::from_ref(&old),
        );
        assert!(plan.force_close.is_empty() && plan.successors.is_empty());
        // Past its assertion deadline: nothing left to do with it.
        old.recovering = false;
        let past = old.contract.assert_height;
        let plan = planned(past, &[hub(4_000, 4_000)], &[old]);
        assert!(plan.force_close.is_empty() && plan.successors.is_empty());
    }

    #[test]
    fn a_contract_without_room_to_prove_in_is_claimed_from_at_once() {
        let mut short = kept(1, 4_096, 0, 50_000);
        short.deadlines = Some(Deadlines::new(None, DAY, LEAD));
        let plan = planned(100, &[hub(1_000, 1_000)], &[short]);
        assert_eq!(plan.force_close, [[1; 32]]);
        assert_eq!(plan.limits[HUB], 0);
    }

    #[test]
    fn each_hub_is_planned_apart() {
        let mut other = hub(100, 100);
        other.url = OTHER.into();
        other.urls = vec![OTHER.into()];
        let plan = planned(100, &[hub(0, 0), other], &[kept(1, 4_096, 0, 50_000)]);
        assert_eq!(
            plan.limits,
            HashMap::from([(HUB.to_owned(), 4_096), (OTHER.to_owned(), 0)])
        );
        assert_eq!(plan.alerts, [Alert::NoContract { hub: OTHER.into() }]);
    }
}
