//! A [`Wallet`]'s payments through mailboxes: paying a payment code, and
//! taking what its own mailbox holds; and the swap providers announced
//! that swap between two of its hubs, or pay notes out on Bitcoin.

use std::{
    collections::{hash_map::RandomState, HashMap, HashSet},
    future::Future,
    hash::BuildHasher,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure};
use bitcoin::FeeRate;
use futures_util::{
    future::{join, join_all},
    stream::{self, StreamExt},
};
use licash_api::{Info, Payment};
use licash_wallet::{
    DepositOffer, DonationAddress, Error, HubId, LicashCode, Paid, PaymentCode, PaymentNote,
    PayoutQuote, PayoutState, ReceiveOffer, Received, SwapLimits, SwapQuote, SwapState, Transport,
    ViaQuote, Wallet,
};

use crate::{mailbox, watch::Watch, Found, Role, Route, LIFETIME};

/// How long a service announced has to answer, at all its URLs together:
/// one announcing URLs that never answer holds a look no longer.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the other swap providers asked for a quote have to answer once
/// one did, at most: those slower are left out rather than hold up the
/// owner, as one gone (say, the onion service of a provider redeployed
/// under a new key, its old announcement still valid) never answers and
/// would hold each quote [`ANSWER_TIMEOUT`]. At least [`QUOTE_GRACE_LEAST`],
/// else as long again as the first took: providers reached the same way
/// answer in comparable times.
const QUOTE_GRACE: Duration = Duration::from_secs(4);

/// How long the other swap providers asked have to answer once one did, at
/// least ([`QUOTE_GRACE`]).
const QUOTE_GRACE_LEAST: Duration = Duration::from_secs(1);

/// The most services announced asked at once: hubs are all asked, and
/// providers the wallet heard from besides [`STRANGERS`].
const ASKED_AT_ONCE: usize = 32;

/// The most hubs announced asked in one look for them, in an order of its
/// own: announcing is free, so a flood of announcements, each naming URLs
/// that never answer, holds a look [`ANSWER_TIMEOUT`] for each
/// [`ASKED_AT_ONCE`] of these at most. The others are told of as not
/// answering.
const HUBS_ASKED: usize = 2 * ASKED_AT_ONCE;

/// How long the swap providers announced, as last found, are used without
/// looking for them again: well within an announcement's [`LIFETIME`].
const KEPT_FOR: Duration = Duration::from_secs(30 * 60);

/// How long what a hub said of itself serves a quote: its height is the
/// one a swap's lock is judged by, and a block comes in 30 s on Mutinynet.
const HUB_FRESH: Duration = Duration::from_secs(60);

/// The most providers asked at once that the wallet neither went through
/// before nor heard answer within [`KEPT_FOR`]: announcing is free, so a
/// flood of announcements, each naming URLs that never answer, costs each
/// quote this many askings at most, not one for each.
const STRANGERS: usize = 16;

/// How long a provider the wallet's last swap or payout through failed
/// is offered after the others: one that took its notes locked and never
/// went on is not chosen again first, while it may have failed by chance.
const FAILED_FOR: Duration = Duration::from_secs(7 * 24 * 3600);

/// The swap providers announced, as last found on some relays for a
/// network: quotes ask them without looking for them first, as the
/// wallet's owner waits, once looked for out of sight
/// ([`Announcements::refresh`]). What they say is only where to ask them:
/// each is still asked, and must answer as the key that announced it.
/// None kept, or none of those answering, a quote looks for them as it
/// did: one never refreshed keeps none, each quote looking. Each provider
/// is asked first at the URL it last answered at, for half an hour after,
/// while it still announces it: one of its URLs down (say, an onion
/// service not opening) is not waited on again for each quote. The relays
/// stay connected between refreshes, pushing each provider announced
/// since as it is ([`Watch`]).
#[derive(Default)]
pub struct Announcements {
    kept: Mutex<Option<Kept>>,
    /// The relays watched for providers, once refreshed.
    watch: Mutex<Option<Arc<Watch>>>,
    /// By the key that announced it, the URL each provider last answered
    /// at as that key, and since when.
    answered: Mutex<HashMap<String, (String, Instant)>>,
    /// By URL, when each hub was last asked what it says of itself before
    /// a quote ([`swap_providers_with`]).
    hubs: Mutex<HashMap<String, Instant>>,
    /// The order the [`STRANGERS`] asked are taken in: this wallet's
    /// own, which no announcer can choose its keys to come first in.
    order: RandomState,
}

/// Announcements found, and where and when.
struct Kept {
    found: Vec<Found>,
    relays: Vec<String>,
    network: String,
    at: Instant,
}

/// `relays` in order, once each: the same set however listed.
fn set_of(relays: &[String]) -> Vec<String> {
    let mut set = relays.to_vec();
    set.sort();
    set.dedup();
    set
}

impl Announcements {
    /// Whether the hub at `url` was not asked what it says of itself within
    /// [`HUB_FRESH`], for a quote.
    fn hub_stale(&self, url: &str) -> bool {
        let hubs = self.hubs.lock().unwrap_or_else(|e| e.into_inner());
        hubs.get(url).is_none_or(|at| at.elapsed() >= HUB_FRESH)
    }

    fn hub_asked(&self, url: &str) {
        let mut hubs = self.hubs.lock().unwrap_or_else(|e| e.into_inner());
        hubs.insert(url.to_owned(), Instant::now());
    }

    /// Look for the swap providers announced on `relays` for `network`,
    /// through `route`, and keep them: how many. Those kept before stay,
    /// should none answer.
    pub async fn refresh(
        &self,
        relays: &[String],
        route: &Route,
        network: &str,
    ) -> anyhow::Result<usize> {
        let relays = set_of(relays);
        let kept = (self.watch.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .filter(|w| w.is(&relays, Role::Swaps, network));
        let watch = match kept {
            Some(watch) => watch,
            None => {
                let watch = Arc::new(Watch::open(&relays, route, Role::Swaps, network).await?);
                *self.watch.lock().unwrap_or_else(|e| e.into_inner()) = Some(watch.clone());
                watch
            }
        };
        let found = watch.found().await?;
        let count = found.len();
        let kept = Kept {
            found,
            relays,
            network: network.to_owned(),
            at: Instant::now(),
        };
        *self.kept.lock().unwrap_or_else(|e| e.into_inner()) = Some(kept);
        Ok(count)
    }

    /// Those kept from `relays` for `network`, found within [`KEPT_FOR`],
    /// those expired since left out: none if none is left.
    fn kept(&self, relays: &[String], network: &str) -> Option<Vec<Found>> {
        let kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        let kept = kept.as_ref()?;
        if kept.network != network || kept.relays != set_of(relays) || kept.at.elapsed() >= KEPT_FOR
        {
            return None;
        }
        // What the relays watched pushed since, too.
        let watched = (self.watch.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .filter(|w| w.is(&kept.relays, Role::Swaps, network))
            .map(|w| w.kept());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let found: Vec<Found> = (watched.as_ref().unwrap_or(&kept.found).iter())
            .filter(|f| f.at.saturating_add(LIFETIME.as_secs()) > now)
            .cloned()
            .collect();
        (!found.is_empty()).then_some(found)
    }

    /// The swap providers announced on `relays` for `network` that answer
    /// `ask` as the key that announced them, as `nostr` reads it
    /// ([`answering`]): those kept, else those looked for now through
    /// `route`, should none be kept or none of those answer. Only
    /// [`Announcements::refresh`] keeps them: looking for them here keeps
    /// nothing, so that one never refreshing sees each provider announced
    /// since. Each is asked first where it last answered
    /// ([`Announcements::asked`]).
    async fn answering<Q, Fut>(
        &self,
        (relays, route, network): (&[String], &Route, &str),
        used: &HashSet<String>,
        ask: impl Fn(String) -> Fut,
        nostr: fn(&Q) -> Option<&str>,
    ) -> anyhow::Result<Vec<(Found, String, Q)>>
    where
        Fut: Future<Output = Result<Q, Error>>,
    {
        if let Some(found) = self.kept(relays, network) {
            let found = self.chosen(found, used);
            let answered = self
                .asked(found, &ask, nostr, Some(QUOTE_GRACE_LEAST))
                .await?;
            if !answered.is_empty() {
                return Ok(answered);
            }
            tracing::info!("no swap provider kept answered: looking for them again");
        }
        let found = crate::discover(relays, route, Role::Swaps, network).await?;
        let found = self.chosen(found, used);
        Ok(self
            .asked(found, &ask, nostr, Some(QUOTE_GRACE_LEAST))
            .await?)
    }

    /// Ask each swap provider kept from `relays` for `wallet`'s network,
    /// as a quote would choose them, what it says of itself, waiting on
    /// each: out of sight, so that the next quote finds its connections
    /// open (the Tor client keeps them a while), not opening a circuit to
    /// an onion service, and asks each first where it answered. How many
    /// answered; none asked if none is kept.
    pub async fn warm<T: Transport>(
        &self,
        wallet: &Wallet<T>,
        relays: &[String],
    ) -> Result<usize, Error> {
        Ok(self.infos(wallet, relays).await?.len())
    }

    /// What each swap provider kept from `relays` for `wallet`'s network
    /// says of itself, as [`Announcements::warm`] asks them: those that
    /// answered, none if none is kept.
    pub async fn infos<T: Transport>(
        &self,
        wallet: &Wallet<T>,
        relays: &[String],
    ) -> Result<Vec<licash_api::swaps::Info>, Error> {
        let Some(found) = self.kept(relays, wallet.network().name()) else {
            return Ok(Vec::new());
        };
        let found = self.chosen(found, &HashSet::new());
        let ask = |url: String| async move { wallet.provider_info(&url).await };
        let nostr: fn(&licash_api::swaps::Info) -> Option<&str> = |i| i.nostr.as_deref();
        let answered = self.asked(found, ask, nostr, None).await?;
        Ok(answered.into_iter().map(|(_, _, info)| info).collect())
    }

    /// Those of `found` to ask: each the wallet went through before (at a
    /// URL of `used`) or heard answer within [`KEPT_FOR`], and
    /// [`STRANGERS`] of the others at most, in an order of its own, as
    /// found.
    fn chosen(&self, found: Vec<Found>, used: &HashSet<String>) -> Vec<Found> {
        let mut ask: Vec<bool> = {
            let answered = self.answered.lock().unwrap_or_else(|e| e.into_inner());
            let heard =
                |f: &Found| (answered.get(&f.key)).is_some_and(|(_, at)| at.elapsed() < KEPT_FOR);
            found.iter().map(|f| known(f, used) || heard(f)).collect()
        };
        let mut strangers: Vec<(u64, usize)> = (found.iter().enumerate())
            .filter(|(i, _)| !ask[*i])
            .map(|(i, f)| (self.order.hash_one(&f.key), i))
            .collect();
        if strangers.len() <= STRANGERS {
            return found;
        }
        strangers.sort_unstable();
        for (_, i) in &strangers[..STRANGERS] {
            ask[*i] = true;
        }
        tracing::debug!(
            found = found.len(),
            "{} providers never heard from not asked",
            strangers.len() - STRANGERS
        );
        (found.into_iter().zip(ask))
            .filter_map(|(f, ask)| ask.then_some(f))
            .collect()
    }

    /// Those of `found` answering `ask` ([`answering`], waiting on the
    /// others no longer than `least` says), each asked first at the URL it
    /// last answered at, within [`KEPT_FOR`] and while it still announces
    /// it, then at the others in the order announced: where each answers
    /// kept for the next, forgotten for one that does not.
    async fn asked<Q, Fut>(
        &self,
        mut found: Vec<Found>,
        ask: impl Fn(String) -> Fut,
        nostr: fn(&Q) -> Option<&str>,
        least: Option<Duration>,
    ) -> Result<Vec<(Found, String, Q)>, Error>
    where
        Fut: Future<Output = Result<Q, Error>>,
    {
        let lock = || self.answered.lock().unwrap_or_else(|e| e.into_inner());
        {
            let answered = lock();
            for service in &mut found {
                let Some((url, at)) = answered.get(&service.key) else {
                    continue;
                };
                let urls = &mut service.announcement.urls;
                match urls.iter().position(|u| u == url) {
                    Some(i) if at.elapsed() < KEPT_FOR => urls[..=i].rotate_right(1),
                    _ => {}
                }
            }
        }
        let keys: Vec<String> = found.iter().map(|f| f.key.clone()).collect();
        let answering = answering(found, ask, nostr, least).await?;
        let mut answered = lock();
        // Those heard from too long ago count for nothing: forgotten, so
        // that keys announcing once each are kept no longer.
        answered.retain(|_, (_, at)| at.elapsed() < KEPT_FOR);
        for key in keys {
            let at = answering.iter().find(|(f, ..)| f.key == key);
            let Some((_, url, _)) = at else {
                answered.remove(&key);
                continue;
            };
            let same = |(kept, at): &(String, Instant)| kept == url && at.elapsed() < KEPT_FOR;
            if !answered.get(&key).is_some_and(same) {
                answered.insert(key, (url.clone(), Instant::now()));
            }
        }
        Ok(answering)
    }
}

/// A payment made to a payment code, its hub keeping it for the payee if
/// [`Paid::kept`]: [`deliver`] mails it to the payee's mailbox once due.
#[derive(Debug)]
pub struct CodePaid {
    pub paid: Paid,
    pub hub: String,
    pub amount: u64,
}

/// Pay `amount`, or the amount the code asks, to the wallet of `code` in
/// notes, at a hub it names that `wallet` trusts and holds enough at, its
/// hub asked to keep the payment for the payee, with `note`
/// ([`Wallet::pay_code_saying`]).
/// Returned once its hub released it: nothing is mailed here, but by
/// [`deliver`]. Refused, saying where to pay on Bitcoin if the code says,
/// when no such hub is named.
pub async fn pay<T: Transport>(
    wallet: &Wallet<T>,
    code: &PaymentCode,
    amount: Option<u64>,
    note: &PaymentNote,
) -> anyhow::Result<CodePaid> {
    let amount = asked(wallet, code, amount)?;
    let hub = match &code.licash {
        Some(licash) => wallet.hub_to_pay(licash, amount)?,
        None => None,
    };
    let Some(hub) = hub else {
        return Err(unpayable(code, amount));
    };
    send(wallet, code, hub, amount, note, None).await
}

/// How [`pay_planned`] pays a payment code in notes.
#[derive(Clone, Debug)]
pub struct Plan {
    /// The hub to pay at: one the code names.
    pub hub: String,
    pub amount: u64,
    /// The hub's fee on the notes the payment spends: at most this once a
    /// swap brought more.
    pub fee: u64,
    /// The swap bringing what the wallet lacks there first, if it does.
    pub swap: Option<PlannedSwap>,
    /// Whether the wallet trusts the hub, else only visited it
    /// ([`Wallet::visit`]): what the swap brings past the payment stays
    /// there, counted apart, until the owner adds it.
    pub trusted: bool,
}

/// A swap to make before paying ([`Plan::swap`]).
#[derive(Clone, Debug)]
pub struct PlannedSwap {
    /// The hub swapped from: the wallet's other one holding the most.
    pub from: String,
    pub provider: SwapProvider,
    /// The fee of the hub swapped from on the swap's lock.
    pub lock_fee: u64,
}

impl Plan {
    /// Every fee it pays: the hub's on the payment, and on a swap the
    /// provider's and the lock's.
    pub fn fees(&self) -> u64 {
        let swap = self
            .swap
            .as_ref()
            .map_or(0, |s| s.provider.quote.fee.saturating_add(s.lock_fee));
        self.fee.saturating_add(swap)
    }
}

/// How to pay `amount`, or the amount the code asks, to the wallet of
/// `code` in notes: at a hub it names that `wallet` trusts and holds
/// enough at, else at one it names and `wallet` trusts once a swap brings
/// what the wallet lacks there, from its other hub holding the most,
/// through a provider announced on the relays its hubs name, reached
/// through `route` ([`swap_providers`]), within [`SwapLimits::usual`];
/// else so at a hub the code says where to reach, visited
/// ([`Wallet::visit`]) as the hub it names, by a swap bringing at most
/// twice what the wallet lacks there.
/// Refused as [`pay`] refuses when neither is possible, or while a swap
/// to that hub is under way.
pub async fn plan<T: Transport>(
    wallet: &Wallet<T>,
    code: &PaymentCode,
    amount: Option<u64>,
    route: &Route,
) -> anyhow::Result<Plan> {
    let mut plans = plans(wallet, code, amount, route).await?;
    Ok(plans.remove(0))
}

/// The ways [`plan`] finds of paying `code`: the one it picks first, then
/// those through each other swap provider it could pick instead, in the
/// order it prefers them. Never none: refused as [`plan`] is.
pub async fn plans<T: Transport>(
    wallet: &Wallet<T>,
    code: &PaymentCode,
    amount: Option<u64>,
    route: &Route,
) -> anyhow::Result<Vec<Plan>> {
    plans_with(wallet, code, amount, route, &Announcements::default()).await
}

/// [`plans`], the swap providers announced as `announced` keeps them.
pub async fn plans_with<T: Transport>(
    wallet: &Wallet<T>,
    code: &PaymentCode,
    amount: Option<u64>,
    route: &Route,
    announced: &Announcements,
) -> anyhow::Result<Vec<Plan>> {
    let amount = asked(wallet, code, amount)?;
    let Some(licash) = &code.licash else {
        return Err(unpayable(code, amount));
    };
    if let Some(hub) = wallet.hub_to_pay(licash, amount)? {
        let fee = wallet.send_fee(&hub, amount)?;
        return Ok(vec![Plan {
            hub,
            amount,
            fee,
            swap: None,
            trusted: true,
        }]);
    }
    let relays = hub_relays(wallet)?;
    if relays.is_empty() {
        tracing::info!("no swap: no hub trusted names relays to find a provider on");
        return Err(unpayable(code, amount));
    }
    // Swaps lock at both hubs: of those following a chain.
    let hubs: Vec<_> = wallet
        .hubs()?
        .into_iter()
        .filter(|(_, i)| i.locks.is_some())
        .collect();
    let mut held = wallet.balance()?;
    held.extend(wallet.visited_balance()?);
    let available = |hub: &str| {
        let held = held.iter().find(|b| b.hub == hub);
        held.map_or(0, |b| b.available)
    };
    // Pass 1, the hubs it names that the wallet trusts; pass 2, those it
    // says where to reach, visited, proving they are the ones it names.
    let named = licash.hubs.iter().map(|id| (*id, None));
    let located = licash.locations.iter().map(|(id, url)| (*id, Some(url)));
    for (id, at) in named.chain(located) {
        let trusted = hubs.iter().find(|(_, i)| HubId::of(&i.address) == id);
        let (to, to_info, trusted) = match (trusted, at) {
            (Some((to, info)), None) => (to.clone(), info.clone(), true),
            (None, Some(url)) => match visit(wallet, url, id).await {
                Some((to, info)) => (to, info, false),
                None => continue,
            },
            _ => continue,
        };
        let to = &to;
        if swapping_to(wallet, to)? {
            return Err(under_way(to, None));
        }
        let lacks = wallet.lacks(to, amount)?;
        // Held enough at a hub visited, a swap there brought before.
        if lacks == 0 {
            return Ok(vec![Plan {
                hub: to.clone(),
                amount,
                fee: wallet.send_fee(to, amount)?,
                swap: None,
                trusted,
            }]);
        }
        let others = hubs.iter().map(|(url, _)| url).filter(|url| *url != to);
        let Some(from) = others.max_by_key(|url| available(url)) else {
            continue;
        };
        let limits = SwapLimits::usual(lacks);
        let pair = (from.as_str(), to.as_str());
        let found =
            swap_providers_with(wallet, announced, &relays, route, pair, lacks, limits).await;
        let found = match found {
            Ok(found) => found,
            Err(e) => {
                tracing::info!(%from, %to, "no swap: {e:#}");
                continue;
            }
        };
        let mut plans = Vec::new();
        for provider in found {
            let quote = &provider.quote;
            // Left at a hub not trusted: not much more than needed.
            if !trusted && quote.amount > lacks.saturating_mul(2) {
                tracing::info!(url = %provider.url, swaps = quote.amount, lacks, "skipped: brings too much to a hub not trusted");
                continue;
            }
            let lock_fee = match wallet.lock_fee(from, quote.amount.saturating_add(quote.fee)) {
                Ok(fee) => fee,
                Err(Error::Insufficient { .. }) => continue,
                // None found yet: refused, as when it was the first.
                Err(e) if plans.is_empty() => return Err(e.into()),
                Err(e) => {
                    tracing::info!(url = %provider.url, "skipped: {e}");
                    continue;
                }
            };
            // At most all it holds there then, in as many notes as it takes.
            let fee = to_info
                .fees
                .spending()
                .at_most(available(to).saturating_add(quote.amount));
            plans.push(Plan {
                hub: to.clone(),
                amount,
                fee,
                swap: Some(PlannedSwap {
                    from: from.clone(),
                    provider,
                    lock_fee,
                }),
                trusted,
            });
        }
        if !plans.is_empty() {
            return Ok(plans);
        }
        tracing::info!(%from, %to, lacks, "no swap: no provider found that it can pay");
    }
    Err(unpayable(code, amount))
}

/// The hub of `id`, one the wallet does not trust, visited where it was
/// before, else at `url`, where the code says to reach it: as the wallet
/// reaches it, and what it said of itself, once it proves it is that hub.
async fn visit<T: Transport>(wallet: &Wallet<T>, url: &str, id: HubId) -> Option<(String, Info)> {
    let found = || {
        let visited = wallet.visited().ok()?;
        visited
            .into_iter()
            .find(|(_, i)| HubId::of(&i.address) == id)
    };
    let kept = found().map(|(url, _)| url);
    let same =
        |a: &str| kept.as_deref().map(|k| k.trim_end_matches('/')) == Some(a.trim_end_matches('/'));
    let code = Some(url).filter(|url| !same(url));
    for at in kept.as_deref().into_iter().chain(code) {
        match wallet.visit(at, id).await {
            Ok(_) => return found(),
            Err(e) => tracing::info!(url = %at, "not visited: {e}"),
        }
    }
    None
}

/// Refused unless the hub of `plan`, if visited, visited again, proves it
/// is the one visited and charges no more than planned.
async fn charges_as_planned<T: Transport>(wallet: &Wallet<T>, plan: &Plan) -> anyhow::Result<()> {
    let visited = wallet.visited()?;
    let Some((_, kept)) = visited.into_iter().find(|(url, _)| *url == plan.hub) else {
        // Added since: trusted.
        return Ok(());
    };
    let info = wallet.visit(&plan.hub, HubId::of(&kept.address)).await?;
    // Reckoned as planned ([`plans_with`]): without a swap, on the notes
    // held there now; once a swap brought more, the most a spend of all
    // held there may owe, however it parts them.
    let fee = match &plan.swap {
        None => wallet.send_fee(&plan.hub, plan.amount)?,
        Some(swap) => {
            let held = wallet.visited_balance()?;
            let held = (held.into_iter().find(|b| b.hub == plan.hub)).map_or(0, |b| b.available);
            let swapped = swap.provider.quote.amount;
            info.fees.spending().at_most(held.saturating_add(swapped))
        }
    };
    if fee > plan.fee {
        bail!(
            "nothing paid: hub {} charges {fee} now, more than the {} planned",
            plan.hub,
            plan.fee
        );
    }
    Ok(())
}

/// Pay as `plan` says, to the wallet of `code`: swap first if it says, on
/// the provider's terms as quoted, then pay as [`pay`] does at the hub it
/// names. Refused, nothing paid, if the swap fails or is still under way:
/// paying again once it is done pays from what it brought. Refused before
/// any swap if the hub keeps no `note` ([`Wallet::note_for`]).
pub async fn pay_planned<T: Transport>(
    wallet: &Wallet<T>,
    code: &PaymentCode,
    plan: &Plan,
    note: &PaymentNote,
) -> anyhow::Result<CodePaid> {
    let amount = asked(wallet, code, Some(plan.amount))?;
    if !plan.trusted {
        charges_as_planned(wallet, plan).await?;
    }
    let note = wallet.note_for(&plan.hub, note).await?;
    if let Some(swap) = &plan.swap {
        let (provider, hub) = (&swap.provider, &plan.hub);
        let quote = &provider.quote;
        if swapping_to(wallet, hub)? {
            return Err(under_way(hub, None));
        }
        let limits = SwapLimits {
            fee: quote.fee,
            margin: quote.margin,
        };
        // Held to what was quoted in all: the hub's lock fee included.
        let costs = Some(quote.fee.saturating_add(swap.lock_fee));
        let swapped =
            wallet.swap_within(&provider.url, &swap.from, hub, quote.amount, limits, costs);
        let swapped = swapped.await.map_err(|e| match e {
            Error::Pending { reason, .. } => under_way(hub, Some(&reason)),
            e => e.into(),
        })?;
        match swapped.state {
            SwapState::Done => {}
            SwapState::Failed(why) => bail!(
                "nothing paid: the swap to {hub} failed ({why}), its lock returns once expired"
            ),
            _ => return Err(under_way(hub, None)),
        }
    }
    if plan.trusted && plan.swap.is_none() {
        // Held to what was quoted: the notes held or the hub's terms may
        // have changed since.
        let fee = wallet.send_fee(&plan.hub, amount)?;
        ensure!(
            fee <= plan.fee,
            "nothing paid: the fee is {fee} sat now, not the {} quoted: quote again",
            plan.fee
        );
    }
    // Held to its fee as planned, whatever fees the hub learns of refusing.
    send(
        wallet,
        code,
        plan.hub.clone(),
        amount,
        &note,
        Some(plan.fee),
    )
    .await
}

/// Whether a swap to the hub at `hub` is under way.
fn swapping_to<T: Transport>(wallet: &Wallet<T>, hub: &str) -> Result<bool, Error> {
    let swaps = wallet.swaps()?.into_iter();
    Ok(swaps
        .filter(|s| s.state == SwapState::Open)
        .any(|s| s.to == hub))
}

/// Nothing paid while a swap to `hub` is under way, for `reason` if known.
fn under_way(hub: &str, reason: Option<&str>) -> anyhow::Error {
    let why = reason.map_or(String::new(), |r| format!(" ({r})"));
    anyhow::anyhow!(
        "nothing paid: a swap to {hub} is under way{why}: once `resume` finishes it, pay again"
    )
}

/// What the payer of `code` pays: `amount`, if the code asks no other.
fn asked<T: Transport>(
    wallet: &Wallet<T>,
    code: &PaymentCode,
    amount: Option<u64>,
) -> anyhow::Result<u64> {
    code.check(wallet.network())?;
    Ok(match (amount, code.amount) {
        (Some(amount), Some(asked)) if amount != asked => {
            bail!("the code asks for {asked}, not {amount}")
        }
        (Some(amount), _) | (None, Some(amount)) => amount,
        (None, None) => bail!("how much to pay: the code does not say"),
    })
}

/// Why `code` cannot be paid `amount` in notes: where to pay it on
/// Bitcoin, if it says.
fn unpayable(code: &PaymentCode, amount: u64) -> anyhow::Error {
    let none = format!("no hub it names is one trusted holding {amount} and the fee");
    let onchain = match (&code.silent, &code.address) {
        (Some(silent), _) => Some(silent.to_string()),
        (None, Some(address)) => Some(address.assume_checked_ref().to_string()),
        (None, None) => None,
    };
    match onchain {
        Some(to) => anyhow::anyhow!("{none}: pay {to} on Bitcoin"),
        None => anyhow::anyhow!("{none}"),
    }
}

/// Pay `amount` to the wallet of `code` at `hub`, kept there for the
/// payee if the hub does, with `note`, its fee at most `max_fee` if given.
async fn send<T: Transport>(
    wallet: &Wallet<T>,
    code: &PaymentCode,
    hub: String,
    amount: u64,
    note: &PaymentNote,
    max_fee: Option<u64>,
) -> anyhow::Result<CodePaid> {
    let Some(licash) = &code.licash else {
        return Err(unpayable(code, amount));
    };
    let started = Instant::now();
    let paid = wallet
        .pay_code_within(&hub, licash, amount, note, max_fee)
        .await?;
    tracing::info!(
        hub = %hub,
        took = ?started.elapsed(),
        kept = paid.kept,
        "paid a payment code"
    );
    Ok(CodePaid { paid, hub, amount })
}

/// Payments mailed at once, at most.
const MAILING_AT_ONCE: usize = 4;

/// What [`deliver`] mailed.
#[derive(Debug, Default)]
pub struct Delivered {
    /// The payments mailed, by id, with how many relays took each.
    pub mailed: Vec<(String, usize)>,
    /// The payments not mailed, by id, and why: mailed again later.
    pub failed: Vec<(String, String)>,
}

/// Mail the payments due to their payees' mailboxes ([`Wallet::due`]) on
/// the relays their hubs name, reached through `route`, asked only if any
/// is due, and record how it went. A while: call it out of the payer's
/// way, now and then while [`Wallet::delivering`].
pub async fn deliver<T: Transport>(
    wallet: &Wallet<T>,
    route: impl FnOnce() -> anyhow::Result<Route>,
) -> anyhow::Result<Delivered> {
    let due = wallet.due().await?;
    let mut delivered = Delivered::default();
    if due.is_empty() {
        return Ok(delivered);
    }
    let route = match route() {
        Ok(route) => route,
        Err(e) => {
            let why = format!("{e:#}");
            for due in due {
                wallet.mailed(&due.id, Err(why.clone()))?;
                delivered.failed.push((due.id, why.clone()));
            }
            return Ok(delivered);
        }
    };
    let started = Instant::now();
    for due in due.chunks(MAILING_AT_ONCE) {
        let mailing = due.iter().map(|due| async {
            let content = serde_json::to_string(&due.payment)?;
            mailbox::send(&due.mailbox, &content, &due.relays, &route).await
        });
        for (due, mailed) in due.iter().zip(join_all(mailing).await) {
            let mailed = mailed.map_err(|e| format!("{e:#}"));
            wallet.mailed(&due.id, mailed.clone())?;
            match mailed {
                Ok(relays) => delivered.mailed.push((due.id.clone(), relays)),
                Err(why) => delivered.failed.push((due.id.clone(), why)),
            }
        }
    }
    tracing::info!(
        took = ?started.elapsed(),
        mailed = delivered.mailed.len(),
        failed = delivered.failed.len(),
        "mailed payments due"
    );
    Ok(delivered)
}

/// What [`collect`] found at the hubs and in the mailbox.
#[derive(Debug, Default)]
pub struct Collected {
    /// The payments taken: those the hubs kept first ([`Wallet::collect_inbox`]),
    /// then those mailed, oldest first.
    pub received: Vec<Received>,
    /// Mail not taken, by its identifier, and why.
    pub skipped: Vec<(String, String)>,
    /// Where payments were not looked for, a hub's URL or [`MAILBOX`], and
    /// why: looked for again next time.
    pub failed: Vec<(String, String)>,
    /// What the wallet's extra codes were paid, and paid on to it: taken
    /// among [`Collected::received`] ([`licash_wallet::Inboxed::codes`]).
    pub codes: licash_wallet::CodesCollected,
    /// The mailbox relays whose answer was all a look asks for, where
    /// newer mail may hide an older payment ([`mailbox::Mailbox::full`]).
    pub full: Vec<String>,
}

/// Where [`Collected::failed`] names the mailbox.
pub const MAILBOX: &str = "mailbox";

/// Take the payments the hubs `wallet` trusts keep for it, and those in
/// its mailbox, on the relays its hubs name, reached through `route`, at
/// once: each once, whenever asked again. Refused only if the mailbox
/// was not looked through and no hub keeps payments.
pub async fn collect<T: Transport>(wallet: &Wallet<T>, route: &Route) -> anyhow::Result<Collected> {
    let fetch = async {
        let relays = mailbox_relays(wallet)?;
        let mailbox = mailbox::Mailbox::open(&wallet.mailbox_secret(), &relays, route).await?;
        let mail = mailbox.fetch().await.map(|mail| (mail, mailbox.full()));
        mailbox.close().await;
        mail
    };
    let (inboxed, mail) = join(wallet.collect_inbox(), fetch).await;
    collected(wallet, inboxed?, mail, |_| {})
}

/// [`collect`], looking through `kept`, the mailbox kept connected between
/// calls ([`mailbox::Mailbox`]): opened the first time, and anew once the
/// relays its hubs name change, or when none of those kept answers (their
/// connections gone with the network, say). Mail taken, or taken before,
/// is not opened again while it is kept.
pub async fn collect_kept<T: Transport>(
    wallet: &Wallet<T>,
    route: &Route,
    kept: &mut Option<mailbox::Mailbox>,
) -> anyhow::Result<Collected> {
    let fetch = async {
        let relays = mailbox_relays(wallet)?;
        let secret = wallet.mailbox_secret();
        let fetched = match kept.as_ref().filter(|m| m.is(&secret, &relays)) {
            Some(mailbox) => (mailbox.fetch().await)
                .map(|mail| (mail, mailbox.full()))
                .map_err(|e| tracing::info!("the mailbox kept, opened anew: {e:#}")),
            None => Err(()),
        };
        match fetched {
            Ok(mail) => anyhow::Ok(mail),
            Err(()) => {
                if let Some(old) = kept.take() {
                    old.close().await;
                }
                let mailbox = kept.insert(mailbox::Mailbox::open(&secret, &relays, route).await?);
                let mail = mailbox.fetch().await?;
                Ok((mail, mailbox.full()))
            }
        }
    };
    let (inboxed, mail) = join(wallet.collect_inbox(), fetch).await;
    let mailbox = kept.as_ref();
    collected(wallet, inboxed?, mail, |id| {
        if let Some(mailbox) = mailbox {
            mailbox.done(id);
        }
    })
}

/// What `inboxed` took, and the payments of `mail` taken as [`take`] does:
/// refused for the mailbox's failure if no hub keeps payments.
fn collected<T: Transport>(
    wallet: &Wallet<T>,
    inboxed: licash_wallet::Inboxed,
    mail: anyhow::Result<(Vec<mailbox::Mail>, Vec<String>)>,
    done: impl FnMut(&str),
) -> anyhow::Result<Collected> {
    let mut collected = Collected {
        received: inboxed.received,
        skipped: Vec::new(),
        failed: inboxed.failed,
        codes: inboxed.codes,
        full: Vec::new(),
    };
    match mail {
        Ok((mail, full)) => {
            collected.full = full;
            take(wallet, mail, done, &mut collected)
        }
        Err(e) if inboxed.served == 0 => return Err(e),
        Err(e) => collected.failed.push((MAILBOX.into(), format!("{e:#}"))),
    }
    Ok(collected)
}

/// The relays `wallet`'s mailbox is on: those its hubs name.
fn mailbox_relays<T: Transport>(wallet: &Wallet<T>) -> anyhow::Result<Vec<String>> {
    let relays = hub_relays(wallet)?;
    if relays.is_empty() {
        bail!("no hub trusted names mailbox relays: adding a hub again learns them");
    }
    Ok(relays)
}

/// The payments of `mail` `wallet` takes, each once, into `collected`,
/// told to `done` by their mail's identifier as are those taken before and
/// those that are no payment: none of which to take again.
fn take<T: Transport>(
    wallet: &Wallet<T>,
    mail: Vec<mailbox::Mail>,
    mut done: impl FnMut(&str),
    collected: &mut Collected,
) {
    for mail in mail {
        let Ok(payment) = serde_json::from_str::<Payment>(&mail.content) else {
            done(&mail.id);
            collected.skipped.push((mail.id, "is not a payment".into()));
            continue;
        };
        match wallet.receive(&payment) {
            Ok(received) => {
                done(&mail.id);
                collected.received.push(received);
            }
            Err(Error::AlreadyReceived) => done(&mail.id),
            // Perhaps once its hub is trusted, say.
            Err(e) => collected.skipped.push((mail.id, format!("not taken: {e}"))),
        }
    }
}

/// The relays `wallet`'s hubs name, each once, in the order of its hubs.
pub fn hub_relays<T: Transport>(wallet: &Wallet<T>) -> Result<Vec<String>, Error> {
    let mut relays: Vec<String> = Vec::new();
    for (_, info) in wallet.hubs()? {
        for relay in info.relays {
            if !relays.contains(&relay) {
                relays.push(relay);
            }
        }
    }
    Ok(relays)
}

/// A swap provider announced on Nostr, and what it asks for a swap.
#[derive(Clone, Debug)]
pub struct SwapProvider {
    /// The URL that answered as the provider: the first announced that
    /// does, or where it last answered ([`Announcements`]).
    pub url: String,
    /// The key that announced it, x-only in hex.
    pub key: String,
    pub name: Option<String>,
    pub quote: SwapQuote,
    /// Whether the wallet swapped through it before.
    pub known: bool,
}

/// The swap providers announced on `relays` for `wallet`'s network, asked
/// through `route`, that swap at least `amount` from hub `from` to hub
/// `to`, both added, within `limits` ([`Wallet::swap_quote`]): `amount`,
/// or the least one swaps if more. Each is at the first URL
/// it was announced at that answers as the key that announced it. Those
/// the wallet swapped through before first, then the cheapest, then the
/// soonest to free its notes should they never lock.
pub async fn swap_providers<T: Transport>(
    wallet: &Wallet<T>,
    relays: &[String],
    route: &Route,
    pair: (&str, &str),
    amount: u64,
    limits: SwapLimits,
) -> anyhow::Result<Vec<SwapProvider>> {
    let announced = Announcements::default();
    swap_providers_with(wallet, &announced, relays, route, pair, amount, limits).await
}

/// [`swap_providers`], those announced as `announced` keeps them, each
/// asked first where it last answered.
pub async fn swap_providers_with<T: Transport>(
    wallet: &Wallet<T>,
    announced: &Announcements,
    relays: &[String],
    route: &Route,
    (from, to): (&str, &str),
    amount: u64,
    limits: SwapLimits,
) -> anyhow::Result<Vec<SwapProvider>> {
    let network = wallet.network().name();
    let (used, failed) = standing(
        wallet.swaps()?.into_iter().filter_map(|s| match s.state {
            SwapState::Done => Some((s.provider, s.created_at, true)),
            SwapState::Failed(_) => Some((s.provider, s.created_at, false)),
            _ => None,
        }),
        now(),
    );
    let ask = |url: String| async move { wallet.swap_quote(&url, from, to, amount, limits).await };
    // A quote judges a lock by the height its hubs last said they followed,
    // behind by now on quick blocks, and so refuses what would go through:
    // each asked again what it says, unless lately, before the providers
    // are. Refused, every provider kept would fail, and the relays be
    // looked in again for nothing. A hub that does not answer keeps what it
    // said.
    let again = |hub: &str| {
        let hub = hub.to_owned();
        async move {
            if !announced.hub_stale(&hub) {
                return;
            }
            match wallet.refresh_hub(&hub).await {
                Ok(()) => announced.hub_asked(&hub),
                Err(e) => tracing::debug!(%hub, "not asked again before a swap: {e}"),
            }
        }
    };
    join(again(from), again(to)).await;
    let on = (relays, route, network);
    let answering = announced.answering(on, &used, ask, |q: &SwapQuote| q.info.nostr.as_deref());
    let answering = answering.await?;
    let mut providers: Vec<(bool, SwapProvider)> = answering
        .into_iter()
        .map(|(service, url, quote)| {
            let provider = SwapProvider {
                known: known(&service, &used),
                url,
                key: service.key.clone(),
                name: service.announcement.name.clone(),
                quote,
            };
            (known(&service, &failed), provider)
        })
        .collect();
    // Stable: the newest announced first among equals.
    providers.sort_by_key(|(failed, p)| (*failed, !p.known, p.quote.fee, p.quote.margin));
    Ok(providers.into_iter().map(|(_, p)| p).collect())
}

/// A hub announced on Nostr, and what it says of itself.
#[derive(Clone, Debug)]
pub struct AnnouncedHub {
    /// The first URL announced that answered as the hub.
    pub url: String,
    /// The key that announced it, x-only in hex.
    pub key: String,
    pub name: Option<String>,
    pub info: Info,
}

/// The hubs announced on `relays` for `wallet`'s network, asked through
/// `route`, but those the wallet trusts: each at the first URL it was
/// announced at that answers as the key that announced it. What a hub says
/// of itself there is only shown: adding it is the owner's call.
pub async fn hubs_announced<T: Transport>(
    wallet: &Wallet<T>,
    relays: &[String],
    route: &Route,
) -> anyhow::Result<Vec<AnnouncedHub>> {
    Ok(hubs_found(wallet, relays, route).await?.hubs)
}

/// What looking for hubs found ([`hubs_found`]).
#[derive(Clone, Debug)]
pub struct HubsFound {
    /// Those answering, as [`hubs_announced`] finds them.
    pub hubs: Vec<AnnouncedHub>,
    /// The announcements of the others, but those naming a URL of a hub the
    /// wallet trusts or found: answering as the key that announced them at
    /// none of their URLs, they are only told of, never to be added.
    pub silent: Vec<Found>,
}

/// [`hubs_announced`], and the announcements of hubs that did not answer:
/// down, refusing the route, or reached only through Tor.
pub async fn hubs_found<T: Transport>(
    wallet: &Wallet<T>,
    relays: &[String],
    route: &Route,
) -> anyhow::Result<HubsFound> {
    let network = wallet.network().name();
    let found = crate::discover(relays, route, Role::Hub, network).await?;
    let hubs_used = wallet.hubs()?;
    let trusted: HashSet<_> = hubs_used.iter().map(|(_, info)| info.address).collect();
    let ask = |url: String| async move { wallet.hub_info(&url).await };
    let asked = few(found.clone(), HUBS_ASKED);
    // Each hub waited for: all those answering are shown.
    let answering = answering(asked, ask, |i: &Info| i.nostr.as_deref(), None).await?;
    let mut hubs: Vec<AnnouncedHub> = answering
        .into_iter()
        .filter(|(_, _, info)| !trusted.contains(&info.address))
        .map(|(service, url, info)| AnnouncedHub {
            url,
            key: service.key,
            name: service.announcement.name,
            info,
        })
        .collect();
    // One hub announced by two keys: once.
    let mut seen = HashSet::new();
    hubs.retain(|h| seen.insert(h.info.address));
    let answered: HashSet<String> = (hubs.iter().map(|h| h.url.clone()))
        .chain(hubs_used.into_iter().map(|(url, _)| url))
        .map(|url| url.trim().trim_end_matches('/').to_owned())
        .collect();
    let silent = found
        .into_iter()
        .filter(|service| {
            let mut urls = service.announcement.urls.iter();
            !hubs.iter().any(|h| h.key == service.key)
                && !urls.any(|u| answered.contains(u.trim().trim_end_matches('/')))
        })
        .collect();
    Ok(HubsFound { hubs, silent })
}

/// `most` of `found` at most, in an order of their own, as found.
fn few(found: Vec<Found>, most: usize) -> Vec<Found> {
    if found.len() <= most {
        return found;
    }
    let order = RandomState::new();
    let mut by: Vec<(u64, usize)> = (found.iter().enumerate())
        .map(|(i, f)| (order.hash_one(&f.key), i))
        .collect();
    by.sort_unstable();
    let ask: HashSet<usize> = by[..most].iter().map(|(_, i)| *i).collect();
    tracing::debug!(
        found = found.len(),
        "{} hubs announced not asked",
        found.len() - most
    );
    (found.into_iter().enumerate())
        .filter_map(|(i, f)| ask.contains(&i).then_some(f))
        .collect()
}

/// A swap provider announced on Nostr that pays notes out on Bitcoin, and
/// what it asks for a payout.
#[derive(Clone, Debug)]
pub struct PayoutProvider {
    /// The URL that answered as the provider: the first announced that
    /// does, or where it last answered ([`Announcements`]).
    pub url: String,
    /// The key that announced it, x-only in hex.
    pub key: String,
    pub name: Option<String>,
    pub quote: PayoutQuote,
    /// Whether the wallet paid out through it before.
    pub known: bool,
}

/// The swap providers announced on `relays` for `wallet`'s network, asked
/// through `route`, that pay `amount` out to `to`, an address on Bitcoin,
/// from notes at hub `from`, added, within `max_fee`, a claim confirming
/// soon at `rate` ([`Wallet::payout_quote`]). Each is at the first URL it
/// was announced at that answers as the key that announced it. Those the
/// wallet paid out through before first, then the cheapest.
pub async fn payout_providers<T: Transport>(
    wallet: &Wallet<T>,
    relays: &[String],
    route: &Route,
    pair: (&str, &str),
    amount: u64,
    limits: (u64, FeeRate),
) -> anyhow::Result<Vec<PayoutProvider>> {
    let announced = Announcements::default();
    payout_providers_with(wallet, &announced, relays, route, pair, amount, limits).await
}

/// [`payout_providers`], those announced as `announced` keeps them, each
/// asked first where it last answered.
pub async fn payout_providers_with<T: Transport>(
    wallet: &Wallet<T>,
    announced: &Announcements,
    relays: &[String],
    route: &Route,
    (from, to): (&str, &str),
    amount: u64,
    (max_fee, rate): (u64, FeeRate),
) -> anyhow::Result<Vec<PayoutProvider>> {
    let network = wallet.network().name();
    let (used, failed) = standing(
        wallet.payouts()?.into_iter().filter_map(|p| match p.state {
            PayoutState::Done => Some((p.provider, p.created_at, true)),
            PayoutState::Failed(_) => Some((p.provider, p.created_at, false)),
            _ => None,
        }),
        now(),
    );
    let ask = |url: String| async move {
        let quote = wallet.payout_quote(&url, from, to, amount, max_fee, rate);
        quote.await
    };
    let on = (relays, route, network);
    let answering = announced.answering(on, &used, ask, |q: &PayoutQuote| q.info.nostr.as_deref());
    let answering = answering.await?;
    let mut providers: Vec<(bool, PayoutProvider)> = answering
        .into_iter()
        .map(|(service, url, quote)| {
            let provider = PayoutProvider {
                known: known(&service, &used),
                url,
                key: service.key.clone(),
                name: service.announcement.name.clone(),
                quote,
            };
            (known(&service, &failed), provider)
        })
        .collect();
    // Stable: the newest announced first among equals.
    providers.sort_by_key(|(failed, p)| (*failed, !p.known, p.quote.costs()));
    Ok(providers.into_iter().map(|(_, p)| p).collect())
}

/// A swap provider announced on Nostr that pays Lightning invoices from
/// its own node, and what it asks to pay one.
#[derive(Clone, Debug)]
pub struct InvoiceProvider {
    /// The URL that answered as the provider: the first announced that
    /// does, or where it last answered ([`Announcements`]).
    pub url: String,
    /// The key that announced it, x-only in hex.
    pub key: String,
    pub name: Option<String>,
    pub quote: ViaQuote,
}

/// The swap providers announced on `relays` for `wallet`'s network, as
/// `announced` keeps them, asked through `route`, that pay `request`, a
/// BOLT11 invoice, for a lock of notes at hub `from`, added, for at most
/// `max_fee` ([`Wallet::invoice_quote_via`]). Each is at the first URL it
/// was announced at that answers as the key that announced it, or where it
/// last answered. The cheapest first.
pub async fn invoice_providers_with<T: Transport>(
    wallet: &Wallet<T>,
    announced: &Announcements,
    (relays, route): (&[String], &Route),
    from: &str,
    request: &str,
    max_fee: u64,
) -> anyhow::Result<Vec<InvoiceProvider>> {
    let network = wallet.network().name();
    // One of several ways to pay, beside the hubs' gateways: a provider
    // not answering lately is passed over, not waited on again.
    let ask = |url: String| async move {
        let quote = wallet.invoice_quote_via(&url, from, request, max_fee);
        licash_wallet::in_background(quote).await
    };
    let on = (relays, route, network);
    let none = HashSet::new();
    let answering = announced.answering(on, &none, ask, |q: &ViaQuote| q.info.nostr.as_deref());
    let mut providers: Vec<InvoiceProvider> = (answering.await?.into_iter())
        .map(|(service, url, quote)| InvoiceProvider {
            url,
            key: service.key,
            name: service.announcement.name,
            quote,
        })
        .collect();
    // Stable: the newest announced first among equals.
    providers.sort_by_key(|p| p.quote.costs());
    Ok(providers)
}

/// A swap provider announced on Nostr that has the wallet paid over
/// Lightning at a hub of its ([`Wallet::invoice_through`]).
#[derive(Clone, Debug)]
pub struct ReceiveProvider {
    /// The URL that answered as the provider: the first announced that
    /// does, or where it last answered ([`Announcements`]).
    pub url: String,
    /// The key that announced it, x-only in hex.
    pub key: String,
    pub name: Option<String>,
    pub offer: ReceiveOffer,
}

/// The swap providers announced on `relays` for `wallet`'s network, as
/// `announced` keeps them, asked through `route`, that have the wallet paid
/// over Lightning at hub `at` now ([`Wallet::receive_offer`]), the newest
/// announced first.
pub async fn receive_providers_with<T: Transport>(
    wallet: &Wallet<T>,
    announced: &Announcements,
    (relays, route): (&[String], &Route),
    at: &str,
) -> anyhow::Result<Vec<ReceiveProvider>> {
    let network = wallet.network().name();
    // Asked while the wallet waits for an invoice: a provider not
    // answering lately is passed over.
    let ask = |url: String| async move {
        licash_wallet::in_background(wallet.receive_offer(&url, at)).await
    };
    let on = (relays, route, network);
    let none = HashSet::new();
    let answering = announced.answering(on, &none, ask, |o: &ReceiveOffer| o.info.nostr.as_deref());
    let providers = (answering.await?.into_iter())
        .map(|(service, url, offer)| ReceiveProvider {
            url,
            key: service.key,
            name: service.announcement.name,
            offer,
        })
        .collect();
    Ok(providers)
}

/// A swap provider announced on Nostr taking deposits on Bitcoin for notes
/// at a hub of the wallet's ([`Wallet::deposit_through`]).
#[derive(Clone, Debug)]
pub struct DepositProvider {
    /// The URL that answered as the provider: the first announced that
    /// does, or where it last answered ([`Announcements`]).
    pub url: String,
    /// The key that announced it, x-only in hex.
    pub key: String,
    pub name: Option<String>,
    pub offer: DepositOffer,
}

/// The swap providers announced on `relays` for `wallet`'s network, as
/// `announced` keeps them, asked through `route`, that take deposits on
/// Bitcoin for notes at hub `at` now ([`Wallet::deposit_offer`]), the
/// newest announced first.
pub async fn deposit_providers_with<T: Transport>(
    wallet: &Wallet<T>,
    announced: &Announcements,
    (relays, route): (&[String], &Route),
    at: &str,
) -> anyhow::Result<Vec<DepositProvider>> {
    let network = wallet.network().name();
    // Asked while the wallet's owner waits: a provider not answering
    // lately is passed over.
    let ask = |url: String| async move {
        licash_wallet::in_background(wallet.deposit_offer(&url, at)).await
    };
    let on = (relays, route, network);
    let none = HashSet::new();
    let answering = announced.answering(on, &none, ask, |o: &DepositOffer| o.info.nostr.as_deref());
    let providers = (answering.await?.into_iter())
        .map(|(service, url, offer)| DepositProvider {
            url,
            key: service.key,
            name: service.announcement.name,
            offer,
        })
        .collect();
    Ok(providers)
}

/// A swap provider announced on Nostr taking donations to the wallet's
/// code, and the wallet's static address of donations through it.
#[derive(Clone, Debug)]
pub struct DonationProvider {
    /// The URL that answered as the provider: the first announced that
    /// does, or where it last answered ([`Announcements`]).
    pub url: String,
    /// The key that announced it, x-only in hex.
    pub key: String,
    pub name: Option<String>,
    pub address: DonationAddress,
}

/// The swap providers announced on `relays` for `wallet`'s network, as
/// `announced` keeps them, asked through `route`, that take donations to
/// `code`, `wallet`'s ([`Wallet::donation_code`]), at a hub of it
/// ([`Wallet::donation_address`]). Those
/// holding enough there to take one first, then the cheapest on a
/// donation of 10,000 sat, then by public URL: the same one while nothing
/// changes, as an address handed out stays.
pub async fn donation_providers_with<T: Transport>(
    wallet: &Wallet<T>,
    announced: &Announcements,
    (relays, route): (&[String], &Route),
    code: &LicashCode,
) -> anyhow::Result<Vec<DonationProvider>> {
    let network = wallet.network().name();
    // Looked for out of sight: a provider not answering lately is passed over.
    let ask = |url: String| async move {
        licash_wallet::in_background(wallet.donation_address(&url, code)).await
    };
    let on = (relays, route, network);
    let none = HashSet::new();
    let answering = announced.answering(on, &none, ask, |a: &DonationAddress| {
        a.info.nostr.as_deref()
    });
    let mut providers: Vec<DonationProvider> = (answering.await?.into_iter())
        .map(|(service, url, address)| DonationProvider {
            url,
            key: service.key,
            name: service.announcement.name,
            address,
        })
        .collect();
    providers.sort_by(|a, b| {
        let key = |p: &DonationProvider| {
            let (stocked, donations) = (p.address.stocked, &p.address.donations);
            (!stocked, donations.fee.due(10_000), donations.url.clone())
        };
        key(a).cmp(&key(b))
    });
    Ok(providers)
}

/// Of the providers the wallet's swaps or payouts went through, by URL, as
/// `finished` says of each (its provider's URL, when it was made, in
/// seconds, and whether it was done) at `now`: those it went through, and
/// those whose last one failed within [`FAILED_FOR`].
fn standing(
    finished: impl IntoIterator<Item = (String, i64, bool)>,
    now: i64,
) -> (HashSet<String>, HashSet<String>) {
    let url = |u: &str| u.trim().trim_end_matches('/').to_owned();
    let mut last: HashMap<String, (i64, bool)> = HashMap::new();
    let mut used = HashSet::new();
    for (provider, at, done) in finished {
        let provider = url(&provider);
        if done {
            used.insert(provider.clone());
        }
        let latest = last.entry(provider).or_insert((at, done));
        if at >= latest.0 {
            *latest = (at, done);
        }
    }
    let since = now.saturating_sub(FAILED_FOR.as_secs() as i64);
    let failed = (last.into_iter())
        .filter(|(_, (at, done))| !done && *at >= since)
        .map(|(provider, _)| provider)
        .collect();
    (used, failed)
}

/// Now, in seconds since the epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Whether `service` announced a URL of those in `used`.
fn known(service: &Found, used: &HashSet<String>) -> bool {
    let mut urls = service.announcement.urls.iter();
    urls.any(|u| used.contains(u.trim().trim_end_matches('/')))
}

/// Each service of `found` at the first URL it announced whose answer to
/// `ask` names the key that announced it (as `nostr` reads it), with that
/// answer: only then may its URL be used. The others are skipped, as are
/// those not answering in time, [`ANSWER_TIMEOUT`] at all its URLs
/// together, but [`Error::UnknownHub`] fails them all: no service is one
/// to ask. [`ASKED_AT_ONCE`] are asked at once. Given `least`, those not
/// answered once one did are waited for no longer than as long again as
/// the first took, `least` to [`QUOTE_GRACE`]; else each is waited for.
/// In the order found.
async fn answering<Q, Fut>(
    found: Vec<Found>,
    ask: impl Fn(String) -> Fut,
    nostr: fn(&Q) -> Option<&str>,
    least: Option<Duration>,
) -> Result<Vec<(Found, String, Q)>, Error>
where
    Fut: Future<Output = Result<Q, Error>>,
{
    let ask = &ask;
    let started = tokio::time::Instant::now();
    let count = found.len();
    let asked = found.into_iter().enumerate().map(|(i, service)| async move {
        let mut answered = None;
        let by = tokio::time::Instant::now() + ANSWER_TIMEOUT;
        for url in &service.announcement.urls {
            let asking = Instant::now();
            match tokio::time::timeout_at(by, ask(url.clone())).await {
                Ok(Ok(answer)) if service.named_by(nostr(&answer)) => {
                    tracing::debug!(%url, took = ?asking.elapsed(), "answered");
                    answered = Some((url.clone(), answer));
                    break;
                }
                Ok(Ok(_)) => tracing::warn!(%url, "skipped: not the provider that announced it"),
                Ok(Err(e @ Error::UnknownHub(_))) => return Err(e),
                Ok(Err(e)) => tracing::debug!(%url, took = ?asking.elapsed(), "skipped: {e}"),
                Err(_) => {
                    tracing::debug!(%url, took = ?asking.elapsed(), "skipped: no answer in time")
                }
            }
        }
        Ok((i, answered.map(|(url, answer)| (service, url, answer))))
    });
    let mut asked = stream::iter(asked).buffer_unordered(ASKED_AT_ONCE);
    let mut answering = Vec::new();
    let mut until = None;
    loop {
        let next = match until {
            None => asked.next().await,
            Some(until) => match tokio::time::timeout_at(until, asked.next()).await {
                Ok(next) => next,
                Err(_) => break,
            },
        };
        let Some(next) = next else { break };
        let (i, Some(answer)) = next? else { continue };
        if let (None, Some(least)) = (until, least) {
            let now = tokio::time::Instant::now();
            until = Some(now + (now - started).clamp(least, QUOTE_GRACE));
        }
        answering.push((i, answer));
    }
    answering.sort_unstable_by_key(|(i, _)| *i);
    tracing::info!(
        asked = count,
        answered = answering.len(),
        took = ?started.elapsed(),
        "services announced asked"
    );
    Ok(answering.into_iter().map(|(_, answer)| answer).collect())
}

#[cfg(test)]
mod tests {
    use nostr_sdk::prelude::MockRelay;

    use super::*;
    use crate::{Announcement, Announcer};

    fn provider(at: u64) -> Found {
        Found {
            key: "a".repeat(64),
            announcement: Announcement {
                urls: vec!["https://swaps.example".into()],
                network: "regtest".into(),
                name: None,
            },
            at,
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A provider's answer: the key it names.
    struct Answer(String);

    fn named(answer: &Answer) -> Option<&str> {
        Some(&answer.0)
    }

    /// A provider announced under `key` at `url`.
    fn at(key: usize, url: &str) -> Found {
        let mut found = provider(0);
        found.key = format!("{key:064}");
        found.announcement.urls = vec![url.into()];
        found
    }

    #[test]
    fn a_flood_of_providers_never_heard_from_is_asked_a_few_at_a_time() {
        let announced = Announcements::default();
        let mut found: Vec<Found> = (0..100)
            .map(|i| at(i, &format!("https://{i}.test")))
            .collect();
        // One gone through before, one heard answer lately: both asked.
        found[70].announcement.urls = vec!["https://used.test/".into()];
        (announced.answered.lock().unwrap()).insert(
            found[90].key.clone(),
            ("https://90.test".into(), Instant::now()),
        );
        let used = HashSet::from(["https://used.test".to_owned()]);
        let keys = |found: &[Found]| found.iter().map(|f| f.key.clone()).collect::<Vec<_>>();
        let chosen = announced.chosen(found.clone(), &used);
        assert_eq!(chosen.len(), STRANGERS + 2);
        assert!(keys(&chosen).contains(&found[70].key));
        assert!(keys(&chosen).contains(&found[90].key));
        // In the order found, the same ones each time for this wallet.
        let order: Vec<usize> = (chosen.iter())
            .map(|c| found.iter().position(|f| f.key == c.key).unwrap())
            .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
        assert_eq!(keys(&announced.chosen(found.clone(), &used)), keys(&chosen));
        // A few: all asked.
        let few = found[..STRANGERS].to_vec();
        assert_eq!(
            keys(&announced.chosen(few.clone(), &HashSet::new())),
            keys(&few)
        );
    }

    #[test]
    fn a_flood_of_hubs_announced_is_asked_a_few_of_at_most() {
        let found: Vec<Found> = (0..3 * HUBS_ASKED)
            .map(|i| at(i, &format!("https://{i}.test")))
            .collect();
        let asked = few(found.clone(), HUBS_ASKED);
        assert_eq!(asked.len(), HUBS_ASKED);
        // As found, each once.
        let at_index = |f: &Found| found.iter().position(|g| g.key == f.key).unwrap();
        let indices: Vec<usize> = asked.iter().map(at_index).collect();
        assert!(indices.windows(2).all(|w| w[0] < w[1]), "{indices:?}");
        // A few: all asked.
        let some = found[..HUBS_ASKED].to_vec();
        assert_eq!(few(some.clone(), HUBS_ASKED).len(), some.len());
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_announcing_urls_that_never_answer_holds_a_look_no_longer_than_one() {
        // One announcing URLs that never answer, the others answering.
        let mut found: Vec<Found> = (0..3)
            .map(|i| at(i, &format!("https://{i}.test")))
            .collect();
        found[0].announcement.urls = (0..4).map(|i| format!("https://slow{i}.test")).collect();
        let keys: HashMap<String, String> = (found.iter())
            .flat_map(|f| {
                f.announcement
                    .urls
                    .iter()
                    .map(|u| (u.clone(), f.key.clone()))
            })
            .collect();
        let ask = |url: String| {
            let key = keys[&url].clone();
            async move {
                if url.contains("slow") {
                    std::future::pending::<()>().await;
                }
                Ok(Answer(key))
            }
        };
        let started = tokio::time::Instant::now();
        let answered = answering(found, ask, named, None).await.unwrap();
        assert_eq!(answered.len(), 2);
        assert_eq!(started.elapsed(), ANSWER_TIMEOUT);
    }

    /// Providers each answering after `ms` (never, if none) under its key,
    /// at its URL: those that answered a quote, and how long it took.
    async fn quoted(ms: &[Option<u64>]) -> (Vec<usize>, Duration) {
        let found: Vec<Found> = (0..ms.len())
            .map(|i| at(i, &format!("https://{i}.test")))
            .collect();
        let ask = |url: String| {
            let i: usize = url["https://".len()..url.len() - ".test".len()]
                .parse()
                .unwrap();
            let (key, after) = (found[i].key.clone(), ms[i]);
            async move {
                match after {
                    Some(after) => tokio::time::sleep(Duration::from_millis(after)).await,
                    None => std::future::pending::<()>().await,
                }
                Ok(Answer(key))
            }
        };
        let started = tokio::time::Instant::now();
        let answered = answering(found.clone(), ask, named, Some(QUOTE_GRACE_LEAST))
            .await
            .unwrap();
        let order = (answered.iter())
            .map(|(f, ..)| found.iter().position(|g| g.key == f.key).unwrap())
            .collect();
        (order, started.elapsed())
    }

    #[tokio::test(start_paused = true)]
    async fn a_quote_goes_on_without_a_provider_never_answering_once_others_did() {
        // A provider gone, its announcement still valid, first and last.
        let (order, took) = quoted(&[None, Some(2000), Some(3500), None]).await;
        assert_eq!(order, [1, 2]);
        // As long again as the first took.
        assert_eq!(took, Duration::from_secs(4));
        // The first quick: those answering within a second still heard.
        let (order, took) = quoted(&[Some(900), None, Some(100)]).await;
        assert_eq!(order, [0, 2]);
        assert_eq!(took, Duration::from_millis(100) + QUOTE_GRACE_LEAST);
        // The first slow: the others wait no longer than the grace.
        let (order, took) = quoted(&[Some(20_000), Some(10_000), Some(13_000)]).await;
        assert_eq!(order, [1, 2]);
        assert_eq!(took, Duration::from_secs(10) + QUOTE_GRACE);
        let (order, _) = quoted(&[Some(20_000), Some(10_000), Some(15_000)]).await;
        assert_eq!(order, [1]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_quote_none_answered_is_given_up_on_no_sooner_than_before() {
        let (order, took) = quoted(&[None, None]).await;
        assert!(order.is_empty());
        assert_eq!(took, ANSWER_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn services_announced_are_asked_a_few_dozen_at_a_time() {
        let found: Vec<Found> = (0..3 * ASKED_AT_ONCE)
            .map(|i| at(i, &format!("https://{i}.test")))
            .collect();
        let (now, most) = (Arc::new(Mutex::new(0)), Arc::new(Mutex::new(0)));
        let ask = |url: String| {
            let (now, most) = (now.clone(), most.clone());
            let key = found.iter().find(|f| f.announcement.urls[0] == url);
            let key = key.unwrap().key.clone();
            async move {
                let at_once = {
                    let mut now = now.lock().unwrap();
                    *now += 1;
                    *now
                };
                {
                    let mut most = most.lock().unwrap();
                    *most = (*most).max(at_once);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                *now.lock().unwrap() -= 1;
                Ok(Answer(key))
            }
        };
        let answered = answering(found.clone(), ask, named, None).await.unwrap();
        assert_eq!(answered.len(), found.len());
        assert_eq!(*most.lock().unwrap(), ASKED_AT_ONCE);
        // In the order found.
        assert!(answered.iter().zip(&found).all(|(a, f)| a.0.key == f.key));
    }

    #[tokio::test]
    async fn providers_heard_from_long_ago_are_forgotten() {
        let announced = Announcements::default();
        let Some(long_ago) = Instant::now().checked_sub(KEPT_FOR) else {
            return;
        };
        for i in 0..100 {
            (announced.answered.lock().unwrap())
                .insert(format!("{i:064}"), (format!("https://{i}.test"), long_ago));
        }
        let found = vec![at(200, "https://200.test")];
        let key = found[0].key.clone();
        let ask = |_: String| {
            let key = key.clone();
            async move { Ok(Answer(key)) }
        };
        announced.asked(found, ask, named, None).await.unwrap();
        let answered = announced.answered.lock().unwrap();
        assert_eq!(answered.keys().collect::<Vec<_>>(), [&key]);
    }

    #[test]
    fn a_provider_last_failed_through_lately_is_offered_last() {
        const DAY: i64 = 24 * 3600;
        let now = 100 * DAY;
        let (used, failed) = standing(
            [
                // Failed once, done since.
                ("https://a.test".to_owned(), now - 3 * DAY, false),
                ("https://a.test/".to_owned(), now - DAY, true),
                // Done once, failed since.
                ("https://b.test".to_owned(), now - 3 * DAY, true),
                ("https://b.test".to_owned(), now - DAY, false),
                // Failed long ago.
                ("https://c.test".to_owned(), now - 8 * DAY, false),
            ],
            now,
        );
        let set = |urls: &[&str]| urls.iter().map(|u| u.to_string()).collect::<HashSet<_>>();
        assert_eq!(used, set(&["https://a.test", "https://b.test"]));
        assert_eq!(failed, set(&["https://b.test"]));
    }

    #[tokio::test]
    async fn providers_found_are_kept_for_quotes_without_the_relays() {
        let relay = MockRelay::run().await.unwrap();
        let relays = [relay.url().await.to_string()];
        let announcer = Announcer::new(&[9; 32], Role::Swaps, &relays, &Route::Direct);
        let announcement = provider(0).announcement;
        announcer
            .await
            .unwrap()
            .announce(&announcement)
            .await
            .unwrap();
        let key = crate::public_key(&[9; 32]).unwrap();
        let answers = |_: String| {
            let key = key.clone();
            async move { Ok(Answer(key)) }
        };
        let down = |_: String| async { Err::<Answer, _>(Error::Invalid("down".into())) };
        let route = Route::Direct;
        let announced = Announcements::default();
        let none = HashSet::new();

        // Looked for as asked, but not kept: a provider announced since
        // would be found the next time.
        let found = announced
            .answering((&relays[..], &route, "regtest"), &none, answers, named)
            .await;
        assert_eq!(found.unwrap()[0].1, "https://swaps.example");
        assert!(announced.kept(&relays, "regtest").is_none());
        let found = announced.refresh(&relays, &Route::Direct, "regtest");
        assert_eq!(found.await.unwrap(), 1);

        // The relay gone, those kept answer, however its URL is listed.
        relay.shutdown();
        let twice = [relays[0].clone(), relays[0].clone()];
        let found = announced
            .answering((&twice[..], &route, "regtest"), &none, answers, named)
            .await;
        assert_eq!(found.unwrap().len(), 1);
        // None of those kept answering, they are looked for again.
        assert!(announced
            .answering((&relays[..], &route, "regtest"), &none, down, named)
            .await
            .is_err());
        // Not for another network, nor other relays: those are asked.
        assert!(announced.kept(&relays, "signet").is_none());
        let others = ["ws://127.0.0.1:1".to_owned()];
        assert!(announced.kept(&others, "regtest").is_none());
        assert!(announced
            .answering((&others[..], &route, "regtest"), &none, answers, named)
            .await
            .is_err());
        // Failing to find them again, those kept stay: the watch answers
        // with them.
        let found = announced.refresh(&relays, &Route::Direct, "regtest");
        assert_eq!(found.await.unwrap(), 1);
        assert_eq!(announced.kept(&relays, "regtest").unwrap().len(), 1);
    }

    #[test]
    fn providers_kept_too_long_or_expired_since_are_not_used() {
        let relays = ["ws://relay.example".to_owned()];
        let keep = |found: Vec<Found>, at: Instant| {
            let announced = Announcements::default();
            let relays = set_of(&relays);
            let network = "regtest".to_owned();
            *announced.kept.lock().unwrap() = Some(Kept {
                found,
                relays,
                network,
                at,
            });
            announced
        };
        let fresh = keep(vec![provider(now())], Instant::now());
        assert_eq!(fresh.kept(&relays, "regtest").unwrap().len(), 1);
        // Found a while ago: looked for again.
        if let Some(then) = Instant::now().checked_sub(KEPT_FOR) {
            assert!(keep(vec![provider(now())], then)
                .kept(&relays, "regtest")
                .is_none());
        }
        // Announced so long ago that it expired since: left out.
        let old = now() - LIFETIME.as_secs();
        let kept = keep(vec![provider(old), provider(now())], Instant::now());
        assert_eq!(kept.kept(&relays, "regtest").unwrap().len(), 1);
        assert!(keep(vec![provider(old)], Instant::now())
            .kept(&relays, "regtest")
            .is_none());
        // None found: looked for again, a provider may have announced since.
        assert!(keep(Vec::new(), Instant::now())
            .kept(&relays, "regtest")
            .is_none());
    }

    #[tokio::test]
    async fn providers_are_asked_first_where_they_last_answered_as_themselves() {
        const ONION: &str = "http://swaps.onion";
        const CLEAR: &str = "https://swaps.example";
        let announced = Announcements::default();
        let mut two = provider(now());
        two.announcement.urls = vec![ONION.into(), CLEAR.into()];
        let key = two.key.clone();
        // Those down, those answering as another key, and each URL asked.
        let down: Mutex<HashSet<&str>> = Mutex::new(HashSet::new());
        let other: Mutex<HashSet<&str>> = Mutex::new(HashSet::new());
        let asked: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let ask = |url: String| {
            asked.lock().unwrap().push(url.clone());
            let up = !down.lock().unwrap().contains(url.as_str());
            let named = match other.lock().unwrap().contains(url.as_str()) {
                true => "b".repeat(64),
                false => key.clone(),
            };
            async move {
                match up {
                    true => Ok(Answer(named)),
                    false => Err(Error::Invalid("down".into())),
                }
            }
        };
        let quote = async |set: (&[&'static str], &[&'static str])| {
            *down.lock().unwrap() = set.0.iter().copied().collect();
            *other.lock().unwrap() = set.1.iter().copied().collect();
            let found = vec![two.clone()];
            let answered = announced
                .asked(found, &ask, named, Some(QUOTE_GRACE_LEAST))
                .await;
            let at = answered.unwrap().first().map(|(_, url, _)| url.clone());
            (at, std::mem::take(&mut *asked.lock().unwrap()))
        };
        let both = || vec![ONION.to_owned(), CLEAR.to_owned()];

        // Its onion service down: asked there, then at its other URL, where
        // it is asked first from then on.
        assert_eq!(quote((&[ONION], &[])).await, (Some(CLEAR.into()), both()));
        assert_eq!(
            quote((&[], &[])).await,
            (Some(CLEAR.into()), vec![CLEAR.into()])
        );
        // Answering there as another key: not where it answered, forgotten.
        let back = || vec![CLEAR.to_owned(), ONION.to_owned()];
        assert_eq!(quote((&[ONION], &[CLEAR])).await, (None, back()));
        assert_eq!(
            quote((&[], &[])).await,
            (Some(ONION.into()), vec![ONION.into()])
        );
        // Down where it last answered: the others, in the order announced.
        assert_eq!(quote((&[ONION], &[])).await, (Some(CLEAR.into()), both()));
        assert_eq!(quote((&[CLEAR], &[])).await, (Some(ONION.into()), back()));
        assert_eq!(
            quote((&[], &[])).await,
            (Some(ONION.into()), vec![ONION.into()])
        );

        // Kept for so long: asked in the order announced again.
        let since = |url: &str, at| {
            let kept = (url.to_owned(), at);
            announced.answered.lock().unwrap().insert(key.clone(), kept);
        };
        if let Some(then) = Instant::now().checked_sub(KEPT_FOR) {
            since(CLEAR, then);
            assert_eq!(
                quote((&[], &[])).await,
                (Some(ONION.into()), vec![ONION.into()])
            );
        }
        // No longer announced there: neither.
        since("https://moved.example", Instant::now());
        assert_eq!(
            quote((&[], &[])).await,
            (Some(ONION.into()), vec![ONION.into()])
        );
    }
}
