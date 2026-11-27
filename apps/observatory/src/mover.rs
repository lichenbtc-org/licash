//! The observatory's own balance, moved between the hubs it watches at
//! random times, as often as the budget allows (see [`crate::budget`]),
//! each move timed, its cost measured and its outcome kept.
//!
//! Moves are made one at a time, so that what the wallet holds less after
//! one is what that one cost, its losses included. Only services that
//! answered their last probe are used: a service down is told by the
//! probes, without spending on it.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use bitcoin::{BlockHash, FeeRate};
use licash_chain_client::Source;
use licash_wallet::{DepositState, PayoutState, SwapLimits, SwapState, Transport, Wallet};
use rand_core::{OsRng, RngCore};

use crate::{
    budget::{self, Budget, Kind},
    observer::millis,
    store::{self, Action, Outcome, Role, Store},
    terms::{self, HubTerms, ProviderTerms},
};

/// How often the mover looks whether a move is due.
const TICK: Duration = Duration::from_secs(20);

/// Why no move over Lightning is made: hubs pay and make no invoices, and
/// a provider's invoice is not paid through another provider, so no route
/// starts and ends in Licash. Its kind stays for the moves recorded before.
const NO_LIGHTNING: &str =
    "hubs pay and make no Lightning invoices, and no route over Lightning stays in Licash";

/// How often moves left under way are taken on again.
const RESUME_EVERY: Duration = Duration::from_secs(10 * 60);

/// How long a move of each kind may take before it is counted failed.
fn patience(kind: Kind) -> Duration {
    match kind {
        Kind::Hub => Duration::from_secs(120),
        Kind::Swap => Duration::from_secs(15 * 60),
        Kind::Lightning => Duration::from_secs(5 * 60),
        Kind::Chain => Duration::from_secs(6 * 3600),
    }
}

/// How far a move has come, as `carry` tells `make`.
#[derive(Default)]
struct Progress {
    /// A payout was made: its value may be on its way out of the wallet.
    paid: AtomicBool,
    /// How long the swap took, in ms plus one, once it was done: 0 until.
    swapped: AtomicU64,
    /// The provider's coin was seen, timed or not.
    coin_seen: AtomicBool,
}

impl Progress {
    fn paid(&self) -> bool {
        self.paid.load(Ordering::Relaxed)
    }

    fn set_paid(&self) {
        self.paid.store(true, Ordering::Relaxed);
    }

    fn swapped(&self) -> Option<u64> {
        self.swapped.load(Ordering::Relaxed).checked_sub(1)
    }

    fn coin_seen(&self) -> bool {
        self.coin_seen.load(Ordering::Relaxed)
    }

    /// The provider's coin was seen: its swap took `took` if the coin was
    /// still unconfirmed. One first seen in a block (the polls failed until
    /// then) says nothing of the swap, only of the wait for the block, so
    /// it is not timed.
    fn see_coin(&self, took: Duration, confirmed: bool) {
        if self.coin_seen.swap(true, Ordering::Relaxed) {
            return;
        }
        if !confirmed {
            self.swap_done(took);
        }
    }

    fn swap_done(&self, took: Duration) {
        let ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX - 1);
        self.swapped.store(ms + 1, Ordering::Relaxed);
    }
}

/// A payout's claim, in virtual bytes, at most: one input of a lock's
/// claim path, one output.
const CLAIM_VBYTES: u64 = 160;

/// How long a move's locks may take to be known paid, once it is made,
/// for its cost to be measured.
const SETTLE: Duration = Duration::from_secs(3 * 60);

/// When a move would overspend the budget, look again this much later: its
/// kind's next move is paced by its share, and a month's costs only age out
/// slowly.
const RETRY: Duration = Duration::from_secs(30 * 60);

/// When no route was found, look again this much later: nothing was spent,
/// and a probe, a balance or a swap may change that within minutes.
const RETRY_ROUTE: Duration = Duration::from_secs(5 * 60);

/// How the mover moves.
pub struct Moving {
    pub store: Arc<Store>,
    /// Sat a month.
    pub monthly: u64,
    /// What a move moves, at least.
    pub amount: u64,
    /// A service is used only if it answered a probe this recently, in ms.
    pub fresh: i64,
    /// Where the budget is shown.
    pub shown: Arc<Mutex<Option<Budget>>>,
    /// The chain to follow payouts on and broadcast their claims to: moves
    /// on Bitcoin are made only with one.
    pub chain: Option<Source>,
    /// Seconds between two blocks of the network: what a number of blocks
    /// is worth in time, for the limits on how long notes may be locked.
    pub block_secs: u64,
}

/// The most routes quoted before a swap gives up: each asks a provider, over
/// Tor.
const QUOTES: usize = 4;

/// How long the notes of a move may stay locked should a provider never
/// pay, at most, whatever a block takes: a move moves a few thousand sat.
const LOCKED: Duration = Duration::from_secs(12 * 3600);

/// A chain source as the wallet reads Bitcoin through it.
struct Blocks<'a>(&'a Source);

fn text(e: anyhow::Error) -> String {
    format!("{e:#}")
}

impl licash_wallet::Blocks for Blocks<'_> {
    async fn height(&self) -> Result<u32, String> {
        Ok(self.0.tip().await.map_err(text)?.height)
    }

    async fn hash(&self, height: u32) -> Result<BlockHash, String> {
        self.0.hash(height).await.map_err(text)
    }

    async fn filter(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, String> {
        self.0.filter(hash).await.map_err(text)
    }

    async fn block(&self, hash: &BlockHash) -> Result<bitcoin::Block, String> {
        self.0.block(hash).await.map_err(text)
    }
}

/// A hub or provider that answered lately, with its terms.
#[derive(Clone, Debug)]
struct Live<T> {
    id: String,
    /// The URL that answered.
    url: String,
    terms: T,
}

/// The services that answered lately.
#[derive(Default)]
struct Network {
    hubs: Vec<Live<HubTerms>>,
    providers: Vec<Live<ProviderTerms>>,
}

fn network(store: &Store, fresh: i64) -> anyhow::Result<Network> {
    let now = store::now();
    let services = store.services()?;
    let probes = store.probes_since(now - fresh)?;
    let terms: HashMap<String, String> = store
        .latest_terms()?
        .into_iter()
        .map(|(id, _, info)| (id, info))
        .collect();
    // The last probe of each URL.
    let mut last: HashMap<(&str, &str), bool> = HashMap::new();
    for p in &probes {
        last.insert((&p.service, &p.url), p.ok);
    }
    let mut network = Network::default();
    for service in &services {
        let Some(url) = service
            .urls
            .iter()
            .find(|u| last.get(&(service.id.as_str(), u.as_str())) == Some(&true))
        else {
            continue;
        };
        let Some(info) = terms.get(&service.id) else {
            continue;
        };
        let (id, url) = (service.id.clone(), url.clone());
        match service.role {
            Role::Hub => {
                if let Some(terms) = terms::hub(info) {
                    network.hubs.push(Live { id, url, terms });
                }
            }
            Role::Provider => {
                if let Some(terms) = terms::provider(info) {
                    network.providers.push(Live { id, url, terms });
                }
            }
        }
    }
    Ok(network)
}

/// A move planned: what it is, where, and what it was quoted to cost.
struct Plan {
    kind: Kind,
    source: String,
    target: String,
    via: Option<String>,
    /// The provider taking the deposit of a move out on Bitcoin and back.
    deposit_via: Option<String>,
    amount: u64,
    quoted: u64,
}

/// Why no move of a kind was made now.
#[derive(Debug, PartialEq, Eq)]
pub enum Skipped {
    /// No route: too few services, or too little held where they are.
    NoRoute(String),
    /// It would spend beyond the budget.
    Unaffordable(u64),
}

impl Skipped {
    /// Why, in a line.
    pub fn said(&self) -> String {
        match self {
            Self::NoRoute(why) => format!("No route: {why}"),
            Self::Unaffordable(cost) => {
                format!("A move quoted at {cost} sat would pass its share of the budget")
            }
        }
    }

    /// How long before a move of the kind is tried again.
    pub fn retry(&self) -> Duration {
        match self {
            Self::NoRoute(_) => RETRY_ROUTE,
            Self::Unaffordable(_) => RETRY,
        }
    }
}

pub struct Mover<T: Transport> {
    wallet: Arc<Wallet<T>>,
    moving: Moving,
    /// The wallet's URL of each hub it added, by service id.
    added: HashMap<String, String>,
    /// Hubs the wallet could not add, by id, and why.
    refused: HashMap<String, String>,
    next: HashMap<Kind, i64>,
    /// Why the last try of each kind made no move, until one is made.
    waiting: HashMap<Kind, String>,
    last_resume: i64,
    /// What the operator should know, said on the page.
    notes: Vec<String>,
}

impl<T: Transport + 'static> Mover<T> {
    pub fn new(wallet: Wallet<T>, moving: Moving) -> anyhow::Result<Self> {
        let now = store::now();
        let month = moving.store.actions_since(now - millis(budget::MONTH))?;
        let mut next = HashMap::new();
        for kind in Kind::ALL {
            let last = month.iter().rfind(|a| a.kind == kind.key());
            // A first move soon, so that an operator sees one; after a
            // restart, as if it had not stopped.
            let at = match last {
                None => now + (OsRng.next_u64() % 300_000) as i64,
                Some(last) => last.started + millis(kind.floor()) / 2,
            };
            next.insert(kind, at);
        }
        Ok(Self {
            wallet: Arc::new(wallet),
            moving,
            added: HashMap::new(),
            refused: HashMap::new(),
            next,
            waiting: HashMap::new(),
            last_resume: 0,
            notes: Vec::new(),
        })
    }

    /// Move, until dropped.
    pub async fn run(mut self) {
        let interrupted = self.moving.store.interrupted(store::now());
        if let Ok(n @ 1..) = interrupted {
            tracing::info!(n, "moves interrupted by the last stop, counted failed");
        }
        loop {
            if let Err(e) = self.tick().await {
                tracing::warn!("moving: {e:#}");
            }
            tokio::time::sleep(TICK).await;
        }
    }

    /// One look: take on what was left under way, add the hubs found, then
    /// make the move most overdue, if one is.
    pub async fn tick(&mut self) -> anyhow::Result<()> {
        let now = store::now();
        if now - self.last_resume >= millis(RESUME_EVERY) {
            self.last_resume = now;
            if let Err(e) = self.wallet.resume().await {
                tracing::debug!("taking moves under way on: {e}");
            }
            if let Some(chain) = &self.moving.chain {
                if let Err(e) = self.wallet.follow_payouts(&Blocks(chain)).await {
                    tracing::debug!("taking payouts under way on: {e}");
                }
                broadcast_claims(&self.wallet, chain).await;
            }
        }
        let network = network(&self.moving.store, self.moving.fresh)?;
        self.add_hubs(&network).await;
        let due = Kind::ALL
            .into_iter()
            .filter(|&k| self.enabled(k))
            .filter(|k| self.next.get(k).is_some_and(|&at| at <= now))
            .min_by_key(|k| self.next[k]);
        if let Some(kind) = due {
            let wait = match self.attempt(kind, &network).await {
                Ok(cost) => {
                    self.waiting.remove(&kind);
                    self.mean(kind, cost)?
                }
                Err(skipped) => {
                    tracing::info!(kind = kind.key(), "no move: {skipped:?}");
                    self.waiting.insert(kind, skipped.said());
                    skipped.retry()
                }
            };
            let wait = budget::jitter(wait, OsRng.next_u64());
            self.next.insert(kind, store::now() + millis(wait));
        }
        self.show(&network)
    }

    /// Whether moves of `kind` are made: on Bitcoin only with a chain.
    fn enabled(&self, kind: Kind) -> bool {
        match kind {
            Kind::Chain => self.moving.chain.is_some(),
            Kind::Lightning => false,
            Kind::Hub | Kind::Swap => true,
        }
    }

    /// What a swap of `amount` may cost and lock: the wallet's usual
    /// limits, and as long a margin as [`LOCKED`] is in blocks if more, so
    /// that on a network of quick blocks a provider asking for many of them
    /// is not refused for what is a few hours.
    fn limits(&self, amount: u64) -> SwapLimits {
        limits_for(amount, self.moving.block_secs)
    }

    /// Make a move of `kind` now, as the budget allows: what it was
    /// quoted, once made, its outcome recorded.
    pub async fn move_now(&mut self, kind: Kind) -> Result<u64, Skipped> {
        let network = network(&self.moving.store, self.moving.fresh)
            .map_err(|e| Skipped::NoRoute(format!("{e:#}")))?;
        self.add_hubs(&network).await;
        let made = self.attempt(kind, &network).await;
        match &made {
            Ok(_) => self.waiting.remove(&kind),
            Err(skipped) => self.waiting.insert(kind, skipped.said()),
        };
        let _ = self.show(&network);
        made
    }

    /// The mean wait before the next move of `kind`, after one quoted at
    /// `cost`: by the median of what its last ones cost, if known.
    fn mean(&self, kind: Kind, cost: u64) -> anyhow::Result<Duration> {
        let since = store::now() - millis(budget::MONTH);
        let mut costs: Vec<u64> = self
            .moving
            .store
            .actions_since(since)?
            .iter()
            .rev()
            .filter(|a| a.kind == kind.key() && a.outcome == Outcome::Done)
            .filter_map(|a| a.cost)
            .take(5)
            .collect();
        let cost = crate::view::median(&mut costs).unwrap_or(cost);
        Ok(budget::interval(kind, cost, self.moving.monthly).unwrap_or(RETRY))
    }

    async fn add_hubs(&mut self, network: &Network) {
        let known: HashSet<String> = match self.wallet.hubs() {
            Ok(hubs) => hubs.into_iter().map(|(url, _)| url).collect(),
            Err(e) => return tracing::warn!("reading the wallet's hubs: {e}"),
        };
        for hub in &network.hubs {
            if self.added.contains_key(&hub.id) || self.refused.contains_key(&hub.id) {
                continue;
            }
            if let Some(url) = known.iter().find(|u| same_url(u, &hub.url)) {
                self.added.insert(hub.id.clone(), url.clone());
                continue;
            }
            match self.wallet.add_hub(&hub.url).await {
                Ok(_) => {
                    tracing::info!(url = %hub.url, "hub added to the wallet");
                    let url = hub.url.trim_end_matches('/').to_owned();
                    self.added.insert(hub.id.clone(), url);
                }
                Err(e) => {
                    tracing::warn!(url = %hub.url, "the wallet can't use this hub: {e}");
                    self.refused.insert(hub.id.clone(), e.to_string());
                }
            }
        }
    }

    /// What the wallet holds at each hub it added, available, by id.
    fn available(&self) -> HashMap<String, u64> {
        let balance = self.wallet.balance().unwrap_or_default();
        self.added
            .iter()
            .filter_map(|(id, url)| {
                let b = balance.iter().find(|b| same_url(&b.hub, url))?;
                Some((id.clone(), b.available))
            })
            .collect()
    }

    fn total(&self) -> Option<u64> {
        self.held().map(|(available, pending)| available + pending)
    }

    /// What the wallet holds, available and pending, at all its hubs.
    fn held(&self) -> Option<(u64, u64)> {
        let balance = self.wallet.balance().ok()?;
        let available = balance.iter().map(|b| b.available).sum();
        let pending = balance.iter().map(|b| b.pending).sum();
        Some((available, pending))
    }

    /// Wait, up to [`SETTLE`], until no more is pending than `before`: a
    /// lock the wallet made stays pending until it learns that its payee
    /// claimed it, though its value is gone. Whether it settled.
    async fn settle(&self, before: u64) -> bool {
        let until = tokio::time::Instant::now() + SETTLE;
        loop {
            if self.held().is_some_and(|(_, pending)| pending <= before) {
                return true;
            }
            if tokio::time::Instant::now() >= until {
                return false;
            }
            if let Err(e) = self.wallet.resume().await {
                tracing::debug!("following locks: {e}");
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    fn url(&self, id: &str) -> &str {
        self.added.get(id).map_or("", String::as_str)
    }

    /// Plan a move of `kind` and make it: what it was quoted, once made.
    async fn attempt(&mut self, kind: Kind, network: &Network) -> Result<u64, Skipped> {
        let plan = match kind {
            Kind::Hub => self.plan_hub(network),
            Kind::Swap => self.plan_swap(network).await,
            Kind::Lightning => Err(Skipped::NoRoute(NO_LIGHTNING.into())),
            Kind::Chain => self.plan_chain(network),
        }?;
        let month = self
            .moving
            .store
            .actions_since(store::now() - millis(budget::MONTH))
            .unwrap_or_default();
        if !budget::affordable(kind, plan.quoted, self.moving.monthly, &month) {
            return Err(Skipped::Unaffordable(plan.quoted));
        }
        let quoted = plan.quoted;
        self.make(plan).await;
        Ok(quoted)
    }

    fn plan_hub(&self, network: &Network) -> Result<Plan, Skipped> {
        let available = self.available();
        let amount = self.moving.amount;
        let hubs: Vec<(&Live<HubTerms>, u64)> = network
            .hubs
            .iter()
            .filter(|h| self.added.contains_key(&h.id))
            .filter_map(|h| {
                let fee = self.wallet.send_fee(self.url(&h.id), amount).ok()?;
                let held = available.get(&h.id).copied().unwrap_or(0);
                (held >= amount + fee).then_some((h, fee))
            })
            .collect();
        let (hub, fee) = pick(&hubs)
            .ok_or_else(|| Skipped::NoRoute(format!("no hub holds {amount} sat and its fee")))?;
        Ok(Plan {
            kind: Kind::Hub,
            source: hub.id.clone(),
            target: hub.id.clone(),
            via: None,
            deposit_via: None,
            amount,
            quoted: *fee,
        })
    }

    async fn plan_swap(&self, network: &Network) -> Result<Plan, Skipped> {
        let available = self.available();
        let amount = self.moving.amount;
        let mut routes = Vec::new();
        for provider in &network.providers {
            let at = |hub: &Live<HubTerms>| {
                let address = hub.terms.address.as_ref()?;
                provider
                    .terms
                    .hubs
                    .iter()
                    .find(|(a, _)| a == address)
                    .map(|(_, max)| *max)
            };
            for from in network
                .hubs
                .iter()
                .filter(|h| self.added.contains_key(&h.id))
            {
                let held = available.get(&from.id).copied().unwrap_or(0);
                if at(from).is_none() || held < amount {
                    continue;
                }
                for to in network
                    .hubs
                    .iter()
                    .filter(|h| self.added.contains_key(&h.id))
                {
                    if to.id != from.id && at(to).is_some_and(|max| max >= amount) {
                        routes.push((provider, from, to));
                    }
                }
            }
        }
        if routes.is_empty() {
            return Err(Skipped::NoRoute(format!(
                "no provider moves {amount} sat between two hubs, from one holding it"
            )));
        }
        // At random, until a provider quotes: one asking more than the
        // limits is not the end of the others.
        shuffle(&mut routes);
        let limits = self.limits(amount);
        let mut refused = String::new();
        let mut quoted = None;
        for (provider, from, to) in routes.into_iter().take(QUOTES) {
            let quote = self
                .wallet
                .swap_quote(
                    &provider.url,
                    self.url(&from.id),
                    self.url(&to.id),
                    amount,
                    limits,
                )
                .await;
            match quote {
                Ok(quote) => {
                    quoted = Some((provider, from, to, quote));
                    break;
                }
                Err(e) => refused = format!("no quote: {e}"),
            }
        }
        let (provider, from, to, quote) = quoted.ok_or(Skipped::NoRoute(refused))?;
        let locked = quote.amount.saturating_add(quote.fee);
        let lock_fee = self
            .wallet
            .lock_fee(self.url(&from.id), locked)
            .map_err(|e| Skipped::NoRoute(e.to_string()))?;
        if available.get(&from.id).copied().unwrap_or(0) < locked.saturating_add(lock_fee) {
            return Err(Skipped::NoRoute("too little held to swap".into()));
        }
        Ok(Plan {
            kind: Kind::Swap,
            source: from.id.clone(),
            target: to.id.clone(),
            via: Some(provider.id.clone()),
            deposit_via: None,
            amount: quote.amount,
            quoted: quote.fee.saturating_add(lock_fee),
        })
    }

    /// Make `plan`, timed, and record how it went.
    async fn make(&self, plan: Plan) {
        let before = self.held();
        let started = store::now();
        let action = Action {
            id: 0,
            kind: plan.kind.key().into(),
            started,
            ended: None,
            source: Some(plan.source.clone()),
            target: Some(plan.target.clone()),
            via: plan.via.clone(),
            amount: plan.amount,
            quoted: Some(plan.quoted),
            cost: None,
            outcome: Outcome::Running,
            detail: None,
            swapped: None,
        };
        let id = match self.moving.store.action_started(&action) {
            Ok(id) => id,
            Err(e) => return tracing::warn!("recording a move: {e:#}"),
        };
        let progress = Progress::default();
        let made = within(patience(plan.kind), self.carry(&plan, &progress)).await;
        let ended = store::now();
        // Its change unlinked, as any wallet does after a payment: part of
        // what it costs.
        if let Err(e) = self.wallet.unlink().await {
            tracing::debug!("unlinking after a move: {e}");
        }
        // What it cost: what the wallet holds less, once what it locked is
        // known paid or refunded. If that takes too long, the quote, at
        // least, so that the budget is not overspent.
        let settled = match before {
            Some((_, pending)) => self.settle(pending).await,
            None => false,
        };
        let measured = before
            .zip(self.total())
            .map(|((available, pending), after)| (available + pending).saturating_sub(after));
        let cost = match (settled, &made) {
            // Its value may be on its way on Bitcoin still, out of the
            // wallet's sight: the quote, for want of better.
            (_, Err(_)) if progress.paid() => Some(plan.quoted),
            (true, _) => measured,
            (false, _) => Some(measured.unwrap_or(0).max(plan.quoted)),
        };
        let (outcome, detail) = match &made {
            Ok(()) => (Outcome::Done, None),
            Err(why) => (Outcome::Failed, Some(why.as_str())),
        };
        tracing::info!(
            kind = plan.kind.key(),
            ms = ended - started,
            cost,
            quoted = plan.quoted,
            "moved: {}",
            detail.unwrap_or("done")
        );
        if let Err(e) =
            self.moving
                .store
                .action_ended(id, ended, outcome, cost, detail, progress.swapped())
        {
            tracing::warn!("recording a move: {e:#}");
        }
    }

    async fn carry(&self, plan: &Plan, progress: &Progress) -> Result<(), String> {
        let wallet = &self.wallet;
        let (from, to) = (self.url(&plan.source), self.url(&plan.target));
        match plan.kind {
            Kind::Hub => {
                let paid = wallet
                    .send(from, &wallet.address(), plan.amount)
                    .await
                    .map_err(said)?;
                // Kept as it is made, paying the wallet itself: received
                // here only if it was not.
                match wallet.receive(&paid.payment) {
                    Ok(_) | Err(licash_wallet::Error::AlreadyReceived) => Ok(()),
                    Err(e) => Err(said(e)),
                }
            }
            Kind::Swap => {
                let provider = self.provider_url(plan)?;
                let limits = self.limits(plan.amount);
                // Within what the budget took it for: a provider asking
                // more since is refused, nothing locked.
                let mut swap = wallet
                    .swap_within(&provider, from, to, plan.amount, limits, Some(plan.quoted))
                    .await
                    .map_err(said)?;
                loop {
                    match &swap.state {
                        SwapState::Done => return Ok(()),
                        SwapState::Failed(why) => return Err(why.clone()),
                        _ => {}
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    match wallet.follow_swap(&swap.hash).await {
                        Ok(followed) => swap = followed,
                        Err(licash_wallet::Error::Pending { .. }) => {}
                        Err(e) => return Err(said(e)),
                    }
                }
            }
            Kind::Lightning => Err(NO_LIGHTNING.into()),
            Kind::Chain => self.carry_chain(plan, (from, to), progress).await,
        }
    }

    /// Out of a hub through a provider, onto Bitcoin, into a hub again
    /// through a provider taking deposits there: a payout to a deposit's
    /// address, estimated from their terms, as the deposit is asked for
    /// only once the move is made.
    fn plan_chain(&self, network: &Network) -> Result<Plan, Skipped> {
        let available = self.available();
        let mut routes = Vec::new();
        let added = |h: &&Live<HubTerms>| self.added.contains_key(&h.id);
        // Each hub a provider takes deposits at, and the most it locks there.
        let mut intakes = Vec::new();
        for taker in &network.providers {
            let Some(deposits) = &taker.terms.deposits else {
                continue;
            };
            for to in network.hubs.iter().filter(added) {
                let at = taker.terms.hubs.iter().find_map(|(address, max)| {
                    (Some(address) == to.terms.address.as_ref()).then_some(*max)
                });
                if let Some(max) = at {
                    intakes.push((taker, deposits, to, max.min(deposits.max)));
                }
            }
        }
        for provider in &network.providers {
            let Some(chain) = &provider.terms.chain else {
                continue;
            };
            for (taker, deposits, to, max) in &intakes {
                let amount = self.moving.amount.max(deposits.min);
                let pays = deposits.pays(amount);
                // The wallet's claim, budgeted as the wallet does, at the
                // provider's rate.
                let claim = (CLAIM_VBYTES.saturating_mul(chain.rate.max(1_000)))
                    .saturating_mul(3)
                    .div_ceil(1000);
                let value = pays.saturating_add(claim);
                if amount > *max || value < chain.min || value > chain.max {
                    continue;
                }
                for from in network.hubs.iter().filter(added) {
                    let swaps_at = from
                        .terms
                        .address
                        .as_ref()
                        .is_some_and(|a| provider.terms.hubs.iter().any(|(at, _)| at == a));
                    let held = available.get(&from.id).copied().unwrap_or(0);
                    let locked = chain.pays(value);
                    let lock = self
                        .wallet
                        .lock_fee(self.url(&from.id), locked)
                        .unwrap_or(0);
                    // The provider's fee and its miners', the claim's and
                    // the lock's; then the deposit's.
                    let costs = locked.saturating_sub(pays).saturating_add(lock);
                    if swaps_at && held >= pays.saturating_add(costs) {
                        let quoted = costs.saturating_add(pays.saturating_sub(amount));
                        routes.push((provider, taker, from, to, amount, quoted));
                    }
                }
            }
        }
        let (via, taker, from, to, amount, quoted) = pick(&routes).ok_or_else(|| {
            Skipped::NoRoute(
                "no provider pays out of a hub holding enough to a provider taking deposits".into(),
            )
        })?;
        Ok(Plan {
            kind: Kind::Chain,
            source: from.id.clone(),
            target: to.id.clone(),
            via: Some(via.id.clone()),
            deposit_via: Some(taker.id.clone()),
            amount: *amount,
            quoted: *quoted,
        })
    }

    /// The payout, then the deposit it pays: `progress` told once the payout
    /// is made, its value then on its way out of the wallet's sight, and how
    /// long the swap took, from asking the provider to its coin being on
    /// the network: what follows, blocks and the hub's claim, is waiting for
    /// the chain.
    async fn carry_chain(
        &self,
        plan: &Plan,
        (from, to): (&str, &str),
        progress: &Progress,
    ) -> Result<(), String> {
        let wallet = &self.wallet;
        let chain = self.moving.chain.as_ref().ok_or("no chain")?;
        let provider = self.provider_url(plan)?;
        let taker = self.url_of(plan.deposit_via.as_deref())?;
        let mut deposit = (wallet.deposit_through(&taker, to, plan.amount))
            .await
            .map_err(said)?;
        let terms = match (&deposit.terms, &deposit.state) {
            (_, DepositState::Canceled(why)) => return Err(format!("no deposit: {why}")),
            (Some(terms), _) => terms.clone(),
            _ => return Err("the deposit has no terms".into()),
        };
        let rate = match chain.fee_rate(6).await {
            Ok(Some(rate)) => rate.max(FeeRate::BROADCAST_MIN),
            _ => FeeRate::BROADCAST_MIN,
        };
        // Within what was planned, but for the deposit's fee, as it asks it
        // now: refused, nothing paid, if that alone is more.
        let max_fee = payout_allowance(plan.quoted, plan.amount, terms.pays).ok_or_else(|| {
            format!(
                "the deposit's fee, {} sat, passes what the move was quoted, {} sat",
                terms.pays.saturating_sub(plan.amount),
                plan.quoted
            )
        })?;
        let swap_began = tokio::time::Instant::now();
        let quote = wallet
            .payout_quote(&provider, from, &terms.address, terms.pays, max_fee, rate)
            .await
            .map_err(said)?;
        progress.set_paid();
        let mut payout = wallet.payout(&quote).await.map_err(said)?;
        loop {
            if let PayoutState::Failed(why) = &payout.state {
                return Err(format!("the payout failed: {why}"));
            }
            match &deposit.state {
                DepositState::Received => return Ok(()),
                DepositState::Canceled(why) => return Err(format!("the deposit failed: {why}")),
                DepositState::Refunded(_) => return Err("the deposit was refunded".into()),
                _ => {}
            }
            // Closely until the provider's coin is out, so that the swap is
            // timed to the second; then as the chain moves.
            let wait = match progress.coin_seen() {
                false => Duration::from_secs(2),
                true => Duration::from_secs(10),
            };
            tokio::time::sleep(wait).await;
            if !matches!(payout.state, PayoutState::Done) {
                match wallet.follow_payout(&payout.hash, &Blocks(chain)).await {
                    Ok(followed) => payout = followed,
                    Err(licash_wallet::Error::Pending { .. }) => {}
                    Err(e) => tracing::debug!("following a payout: {e}"),
                }
                broadcast_claims(wallet, chain).await;
                if let Ok(seen) = wallet.payout_progress(&payout.hash) {
                    if seen.coin.is_some() {
                        let confirmed = seen.coin_height.is_some();
                        progress.see_coin(swap_began.elapsed(), confirmed);
                    }
                }
            }
            // Its payment found once deep enough, told to the provider.
            if let Err(e) = wallet.find_deposit_payments(&Blocks(chain)).await {
                tracing::debug!("looking for a deposit's payment: {e}");
            }
            if let Ok(followed) = wallet.follow_deposit(&deposit.hash).await {
                deposit = followed;
            }
        }
    }

    fn provider_url(&self, plan: &Plan) -> Result<String, String> {
        self.url_of(plan.via.as_deref())
    }

    /// The URL of the provider of `id`, as it answered last.
    fn url_of(&self, id: Option<&str>) -> Result<String, String> {
        let id = id.ok_or("no provider")?;
        let services = self.moving.store.services().map_err(|e| e.to_string())?;
        let service = services.into_iter().find(|s| s.id == id);
        // The URL it answered at last: the one it was planned with.
        let network = network(&self.moving.store, self.moving.fresh).map_err(|e| e.to_string())?;
        network
            .providers
            .into_iter()
            .find(|p| p.id == id)
            .map(|p| p.url)
            .or_else(|| service.and_then(|s| s.urls.into_iter().next()))
            .ok_or_else(|| "the provider is gone".into())
    }

    /// Tell the page where the budget stands.
    fn show(&mut self, network: &Network) -> anyhow::Result<()> {
        let now = store::now();
        let month = self
            .moving
            .store
            .actions_since(now - millis(budget::MONTH))?;
        let plans: Vec<(Kind, bool, Option<i64>)> = Kind::ALL
            .into_iter()
            .map(|k| (k, self.enabled(k), self.next.get(&k).copied()))
            .collect();
        let balance = self.total();
        let mut budget = Budget::new(self.moving.monthly, &month, balance, &plans);
        for kind in &mut budget.kinds {
            kind.waiting = self.waiting.get(&kind.kind).cloned();
        }
        self.notes.clear();
        if balance.unwrap_or(0) < self.moving.amount {
            self.notes.push(format!(
                "The wallet holds less than a move, {}: fund it at a hub.",
                crate::format::sat(self.moving.amount)
            ));
        }
        if network.hubs.is_empty() {
            self.notes.push("No hub answers now.".into());
        }
        for (id, why) in &self.refused {
            let host = network
                .hubs
                .iter()
                .find(|h| &h.id == id)
                .map_or_else(|| crate::format::short(id), |h| crate::view::host(&h.url));
            self.notes
                .push(format!("The wallet can't use {host}: {why}"));
        }
        budget.notes = self.notes.clone();
        *self.moving.shown.lock().unwrap_or_else(|e| e.into_inner()) = Some(budget);
        Ok(())
    }
}

/// The claims of payouts not done broadcast: one the chain refuses is
/// broadcast again next time, as its coin may not be in its view yet.
async fn broadcast_claims<T: Transport>(wallet: &Wallet<T>, chain: &Source) {
    for claim in wallet.payout_claims().unwrap_or_default() {
        if let Err(e) = chain.broadcast(&claim).await {
            tracing::debug!(txid = %claim.compute_txid(), "claim not broadcast: {e:#}");
        }
    }
}

/// `run` within `patience`, or why not.
async fn within(
    patience: Duration,
    run: impl Future<Output = Result<(), String>>,
) -> Result<(), String> {
    tokio::time::timeout(patience, run)
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "not done in {}",
                crate::format::millis(patience.as_millis() as u64)
            ))
        })
}

fn said(e: licash_wallet::Error) -> String {
    e.to_string()
}

fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// The limits of a swap of `amount` on a network whose blocks take
/// `block_secs`.
fn limits_for(amount: u64, block_secs: u64) -> SwapLimits {
    let mut limits = SwapLimits::usual(amount);
    let blocks = LOCKED.as_secs() / block_secs.max(1);
    limits.margin = limits.margin.max(u32::try_from(blocks).unwrap_or(u32::MAX));
    limits
}

/// `items` in a random order.
fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let j = (OsRng.next_u64() % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

/// What a payout may cost on top of what it pays, `pays`, for a deposit of
/// `amount` whose move was quoted `quoted` in all: none if the deposit's
/// own fee, which its provider names when asked, leaves nothing.
fn payout_allowance(quoted: u64, amount: u64, pays: u64) -> Option<u64> {
    quoted.checked_sub(pays.checked_sub(amount)?)
}

/// One of `items`, at random.
fn pick<T>(items: &[T]) -> Option<&T> {
    if items.is_empty() {
        return None;
    }
    items.get((OsRng.next_u64() % items.len() as u64) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payout may cost what the move was quoted less the deposit's fee
    /// as its provider asks it: nothing, refused, if that fee is more,
    /// however much more, rather than a ceiling wrapping around.
    #[test]
    fn a_payout_may_cost_what_the_deposit_leaves_of_the_quote() {
        // 300 sat quoted, a deposit of 2,000 asking 2,100: 200 left.
        assert_eq!(payout_allowance(300, 2_000, 2_100), Some(200));
        assert_eq!(payout_allowance(300, 2_000, 2_300), Some(0));
        assert_eq!(payout_allowance(300, 2_000, 2_301), None);
        assert_eq!(payout_allowance(300, 2_000, u64::MAX), None);
        // Asking less than it locks is no deposit's.
        assert_eq!(payout_allowance(300, 2_000, 1_999), None);
    }

    #[test]
    fn no_route_is_tried_again_sooner_than_no_budget() {
        let route = Skipped::NoRoute("none".into()).retry();
        let budget = Skipped::Unaffordable(100).retry();
        assert!(route < budget);
        assert!(route >= Duration::from_secs(60), "not a busy loop");
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    #[test]
    fn a_margin_is_as_many_blocks_as_twelve_hours_where_blocks_are_quick() {
        // Bitcoin's 10 minutes: 72 blocks, below the wallet's usual 200.
        assert_eq!(
            limits_for(2_000, 600).margin,
            SwapLimits::usual(2_000).margin
        );
        // Mutinynet's 30 seconds: 1,440, so a provider asking for 482 is not
        // refused for what is a few hours.
        assert_eq!(limits_for(2_000, 30).margin, 1_440);
        assert_eq!(limits_for(2_000, 0).margin, 43_200, "no division by zero");
    }

    #[test]
    fn a_shuffle_keeps_every_route() {
        let mut routes: Vec<u32> = (0..20).collect();
        shuffle(&mut routes);
        routes.sort_unstable();
        assert_eq!(routes, (0..20).collect::<Vec<_>>());
        let mut none: Vec<u32> = Vec::new();
        shuffle(&mut none);
        assert!(none.is_empty());
    }

    #[test]
    fn a_swap_is_timed_by_its_coin_seen_unconfirmed_and_only_once() {
        let progress = Progress::default();
        assert_eq!(progress.swapped(), None);
        progress.see_coin(Duration::from_millis(38_000), false);
        progress.see_coin(Duration::from_millis(90_000), false);
        assert_eq!(progress.swapped(), Some(38_000), "the first sight");
        assert!(progress.coin_seen());
    }

    #[test]
    fn a_coin_first_seen_in_a_block_leaves_the_swap_untimed() {
        let progress = Progress::default();
        progress.see_coin(Duration::from_millis(95_000), true);
        assert!(progress.coin_seen(), "the polls relax");
        assert_eq!(progress.swapped(), None, "a block wait is not the swap");
        progress.see_coin(Duration::from_millis(100_000), false);
        assert_eq!(progress.swapped(), None, "nor is a later sight");
    }
}
