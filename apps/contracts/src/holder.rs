//! The holder's side of openings, in her wallet: [`open`] a contract at
//! a hub she trusts, [`resume`] those under way and watch their F, and
//! [`list`] them. Her deposit is a coin of the wallet's, signed into F by
//! it; her change returns to its fallback address. She may fund part of
//! the contract herself, the hub issuing her notes of as much once F is
//! buried ([`funded`]). One her hub left silent she forces closed, in
//! [`recovery`]. What a hub charged as a contract opened there is the most
//! it may charge her since, until she agrees to more: [`fees`]. Her
//! contracts at a hub share her notes there out, to show and to claim
//! alike: [`claims`].

pub mod activation;
mod chain;
pub mod claims;
mod driver;
pub mod exit;
pub mod fees;
mod fold;
pub mod funded;
#[cfg(feature = "node")]
pub(crate) mod node;
pub mod paid;
pub mod recovery;
pub mod safety;
mod store;

use std::{collections::HashSet, path::Path};

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use bitcoin::OutPoint;
use licash_contract::opening::{Holder, Quote, Start};
use licash_contract::wire::Wanted;
use licash_wallet::{SilentCoin, Transport, Wallet};

pub use chain::Chain;
use driver::Driver;
pub use driver::{latest_opening, stepping, traffic, Traffic};
pub use fold::close;
pub use licash_contract::opening::{Fate, Phase};
#[cfg(feature = "node")]
pub use node::Node;
pub use store::{kept, Contract};
use store::{New, Store};

use crate::{Offer, QUOTE};

/// Blocks from a recovery's assertion deadline to the close, at least:
/// as the regtest fixture has.
pub const AFTER_ASSERT: u32 = 140;

/// Blocks to spare beyond the windows after an assertion, for what is
/// published in them to confirm.
const SPARE: u32 = 12;

/// Blocks from a recovery's assertion deadline to the close on `quote`:
/// the hub's challenge, her answer to it and the delays on what she is
/// paid after, with `SPARE` blocks to confirm in; [`AFTER_ASSERT`] at
/// least.
pub fn after_assert(quote: &Quote) -> u32 {
    let g = &quote.graph;
    let windows: u32 = [g.challenge_window, g.answer_window, g.delta, g.delta_prime]
        .map(u32::from)
        .iter()
        .sum();
    (windows + SPARE).max(AFTER_ASSERT)
}

/// The blocks she has to respond to the hub's request, at least.
pub const RESPONSE_WINDOW: u16 = 8;

/// What she asks of a hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask {
    /// Blocks from now to the close, when the hub's collateral returns
    /// to it: at most what the hub offers.
    pub blocks: u32,
    /// The most she pays to open, in sat: `u64::MAX` for no ceiling of
    /// hers, a price no one saw, bounded then by what is sane of her coin
    /// ([`fees::costly`]).
    pub max_price: u64,
    /// The least notes it protects, in sat, of terms she chooses within
    /// the hub's range (its info's), over `blocks` from the hub's quote: any
    /// number, up to a cap the hub takes ([`licash_api::cap_at_least`]);
    /// none for her part and `inbound` only ([`fit`]), and its fixed terms
    /// at a hub with no range.
    pub cap: Option<u32>,
    /// The notes past her part it protects, in sat, the hub funding them
    /// on its terms (its interest on its part): liquidity she may receive
    /// in. 0 for none, the contract all hers but what makes it a cap the
    /// hub takes (under [`licash_api::MIN_REST`] sat, or the least).
    pub inbound: u32,
    /// The coin she deposits: none for the smallest free that a contract
    /// absorbs whole ([`fit`]). Her coin pays the price and all the rest
    /// she funds of the contract herself, issued her as notes at the hub
    /// once F is buried: no change comes back from it.
    pub deposit: Option<OutPoint>,
}

/// Open a contract at `hub`, a hub `wallet` trusts, on its offer now:
/// its keyset one the hub shows the wallet, its terms as `ask`ed, its
/// price within it, her deposit the coin she names or else the smallest
/// free that a contract absorbs whole ([`fit`]). Kept in `wallet_file`, the wallet's directory,
/// from her first message on, with the fees the hub charges now: the most
/// it may charge her since ([`fees`]). Refused at a hub charging more
/// than is sane ([`fees::abusive`]), or, of no ceiling of hers on its
/// price, for a contract costing more than is sane of her coin
/// ([`fees::costly`]).
/// Driven once: an upload dropped leaves it to [`resume`].
pub async fn open<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &Path,
    hub: &str,
    ask: Ask,
) -> Result<Contract> {
    open_at(wallet, chain, wallet_file, hub, ask, true, 0).await
}

/// How many times [`open_with`] resumes an opening that failed short of
/// F but for a refusal: over Tor, a 25 MB instance's upload drops now and
/// then, a step's answer too.
const RESUMES: u32 = 2;

/// [`open`], resumed at once, up to `RESUMES` times, should it fail
/// short of F but for a refusal.
pub async fn open_with<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &Path,
    hub: &str,
    ask: Ask,
) -> Result<Contract> {
    open_at(wallet, chain, wallet_file, hub, ask, true, RESUMES).await
}

/// [`open_with`], at a hub charging more than is sane too
/// ([`fees::abusive`]), or of a contract costing more than is sane of her
/// coin ([`fees::costly`]): for her who was told, and asks all the same.
pub async fn open_anyway<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &Path,
    hub: &str,
    ask: Ask,
) -> Result<Contract> {
    open_at(wallet, chain, wallet_file, hub, ask, false, RESUMES).await
}

/// One opening as [`open_once`], or, refused as the hub quotes otherwise
/// now (its fee surcharged since, say), given up and made once more on a
/// quote asked anew: within her ceilings still. Turned away busy at its
/// start, made anew a while later, as [`driver::Busy`] waits.
async fn open_at<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &Path,
    hub: &str,
    ask: Ask,
    sane: bool,
    resumes: u32,
) -> Result<Contract> {
    let (mut requoted, mut busy, mut again) = (false, driver::Busy::default(), 0);
    loop {
        match open_once(wallet, chain, wallet_file, hub, ask, sane, resumes).await {
            Err(e) if !requoted && e.downcast_ref::<driver::Requote>().is_some() => {
                tracing::info!(%hub, "its quote refused as the hub's no longer: asked again: {e:#}");
                requoted = true;
            }
            Err(e)
                if e.downcast_ref::<driver::Later>().is_some()
                    && again < driver::OPENS_AGAIN
                    && busy.wait().await =>
            {
                again += 1;
                tracing::info!(%hub, again, "turned away busy: opening again: {e:#}");
            }
            opened => return opened,
        }
    }
}

async fn open_once<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &Path,
    hub: &str,
    ask: Ask,
    sane: bool,
    resumes: u32,
) -> Result<Contract> {
    let hub = hub.trim_end_matches('/').to_owned();
    let trust = crate::trust(wallet.network())?;
    let trusted = wallet.hubs()?;
    let (_, info) = trusted
        .iter()
        .find(|(url, _)| *url == hub)
        .with_context(|| format!("{hub} is no hub this wallet trusts"))?;
    // What it charges now, not as the wallet last heard: her ceilings.
    let now = wallet.hub_info(&hub).await;
    let now = now.map_err(|e| anyhow!("{hub}'s fees: {e}"))?;
    let range = now.contracts.and_then(|c| c.range);
    if let Some(why) = fees::abusive(&now.fees).filter(|_| sane) {
        bail!("{hub} charges more than is sane, {why}: no contract opens there unless asked all the same");
    }
    // Her reserve returns at the close to a deposit of the hub's that swaps
    // it for notes, not to a coin of hers that the close would link to her
    // wallet: no contract opens where the hub takes none.
    ensure!(
        now.deposits.is_some(),
        "{hub} takes no deposits, which her reserve returns to: no contract opens there"
    );
    let store = Store::open(wallet_file)?;
    // Its fixed quote prices a contract where the hub has no range, and
    // tells the notes her part is funded in.
    let fixed = offer(wallet, &hub, None, 0).await?;
    let (denominations, notes) = funding_notes(&fixed.quote);
    let pricing = match &range {
        Some(range) => Pricing::Range(range),
        None => Pricing::Fixed {
            cap: fixed.quote.cap,
            price: fixed.price(),
        },
    };
    let dust = fixed.quote.graph.dust;
    let least = ask.cap.unwrap_or(0);
    let free = free(wallet, &store)?;
    let (coin, fitted) = match ask.deposit {
        Some(named) => {
            let coin = free.into_iter().find(|c| c.outpoint == named);
            let coin = coin.with_context(|| format!("{named}: no coin free to deposit"))?;
            let notes = (&denominations[..], notes);
            let fitted = fit(
                &pricing,
                ask.blocks,
                coin.value,
                dust,
                notes,
                least,
                ask.inbound,
            )
            .with_context(|| format!("{named}: {NO_FIT}"))?;
            (coin, fitted)
        }
        None => {
            let notes = (&denominations[..], notes);
            smallest_fit(free, &pricing, ask.blocks, dust, notes, least, ask.inbound)
                .with_context(|| format!("no coin free to deposit: {NO_FIT}"))?
        }
    };
    let chosen = range.map(|_| (fitted.cap, ask.blocks));
    let offer = offer(wallet, &hub, chosen, u64::from(fitted.funded)).await?;
    let keysets = info
        .keysets()
        .map_err(|e| anyhow!("{hub}'s keysets: {e:?}"))?;
    ensure!(
        keysets.contains(&offer.quote.keyset),
        "{hub} quotes on a keyset it does not show its wallets"
    );
    let price = offer.price();
    ensure!(
        price <= ask.max_price,
        "{hub} asks {price} sat to open, more than {}",
        ask.max_price
    );
    // Of a price she bounded, she chose it: the bound is hers.
    let reserve = offer.quote.graph.reserve_alice;
    let unbounded = ask.max_price == u64::MAX;
    if let Some(why) = fees::costly(price, reserve, coin.value).filter(|_| sane && unbounded) {
        bail!(
            "{hub}'s contract costs more than is sane, {why}: it opens only if asked all the same"
        );
    }
    let funded = u64::from(fitted.funded);
    // Quoted as she priced it: her coin is spent whole.
    let left = coin.value.checked_sub(price + funded);
    ensure!(
        left.is_some_and(|left| left < dust),
        "{hub} quotes {price} sat and her part of {funded} for a coin of {}, not what it \
         absorbs: ask again",
        coin.value
    );
    tracing::info!(
        %hub,
        rate = offer.forced_close_rate(),
        "her reserve affords a forced close of the most notes at this rate (sat/vB)"
    );
    let tip = chain.height().await.map_err(|e| anyhow!(e))?;
    let at = offer.quote.chain.checkpoint.height();
    ensure!(
        at <= tip,
        "{hub} is at block {at}, the chain at {tip}: try again"
    );
    // Hers: the hub's quote is checked against it.
    let checkpoint = chain.checkpoint(at).await.map_err(|e| anyhow!(e))?;
    let wanted = wanted(&offer, tip, ask.blocks)?;
    let deposit = coin.outpoint;
    let coin = wallet
        .silent_coin_output(&deposit)?
        .context("a coin gone")?;
    let funded_notes = funded_notes(wallet, &offer.quote, funded)?;
    let timeout = wanted
        .close_height
        .checked_add(crate::CLOSE_BLOCKS)
        .context("the close deposit's timeout overflows")?;
    let deposit_for_reserve = wallet
        .close_deposit(&hub, deposit, offer.quote.graph.reserve_alice, timeout)
        .await;
    let deposit_for_reserve =
        deposit_for_reserve.map_err(|e| anyhow!("{hub}'s deposit for her reserve: {e}"))?;
    let close = licash_contract::wire::CloseOffer {
        script: deposit_for_reserve.script,
        fee: deposit_for_reserve.fee,
    };
    let secrets = wallet.contract_secrets();
    let start = Start {
        seed: secrets.seed,
        quote: offer.quote.clone(),
        deposit,
        coin: coin.clone(),
        // Her reserve back after a corrected payout, and what her claim
        // pays: to her wallet, which finds it as any payment.
        payout: wallet.fallback_address()?.script_pubkey(),
        wanted,
        checkpoint,
        funded: funded_notes,
        close,
    };
    let ctx = licash_contract::opening::Context { tip, trust };
    let (holder, outs) = Holder::start(start, &ctx)?;
    let id = holder.id();
    let new = New {
        id,
        hub: &hub,
        mock: trust.mock,
        deposit,
        value: coin.value.to_sat(),
        price,
        cap: offer.quote.cap,
        assert_height: wanted.request_height,
        close_height: wanted.close_height,
        since: tip,
        state: &holder.to_bytes(),
    };
    store.insert_under(&new, &now.fees, funded)?;
    tracing::info!(id = %crate::hex_id(&id), %hub, %deposit, price, funded, mock = trust.mock, "opening a contract");
    let mut driver = Driver {
        wallet,
        chain,
        store: &store,
        trust,
        hub,
        id,
        holder: Some(holder),
        quote: Some(offer.quote),
        took_f: Default::default(),
    };
    let driven = driver.drive(outs).await;
    let driven = driver.carry_on(driven, resumes).await;
    driver.settle(driven)?;
    refresh(&driver, chain).await?;
    found(&store, &id)
}

/// How long an opening may take, from her first message to her signing
/// F: over Tor, minutes, an hour at worst. Its hub gives up one idle for
/// an hour; resumed past this, an upload dropped would be sent again and
/// again, 25 MB at a time.
pub const OPENS_WITHIN: i64 = 86_400;

/// The openings this process found it cannot load: those whose F she
/// signed, kept as they are, not read again at each of the app's syncs
/// for nothing. Not stored: a later build may read them.
fn unreadable() -> std::sync::MutexGuard<'static, std::collections::BTreeSet<[u8; 32]>> {
    static UNREADABLE: std::sync::Mutex<std::collections::BTreeSet<[u8; 32]>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    UNREADABLE.lock().unwrap_or_else(|e| e.into_inner())
}

/// An opening at `phase`, begun at `began`, still short of her signing F
/// [`OPENS_WITHIN`] later, at `now`: to give up. She never signed her
/// deposit into an F, so none can confirm, and her coin is free.
fn overdue(phase: Phase, began: i64, now: i64) -> bool {
    phase < Phase::Signing && now - began > OPENS_WITHIN
}

/// Carry on with the openings in `wallet_file` under way, and see where the F
/// of each signed stands: every contract, the newest first. Nothing is
/// made in `wallet_file` if none was ever opened there.
pub async fn resume<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &Path,
) -> Result<Vec<Contract>> {
    let Some(store) = Store::existing(wallet_file)? else {
        return Ok(Vec::new());
    };
    let tip = chain.height().await.map_err(|e| anyhow!(e))?;
    let trust = crate::trust(wallet.network())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    for contract in store.list()? {
        let id = contract.id;
        if contract.over(tip) || contract.fate == Some(Fate::Dead) {
            continue;
        }
        // Live: carried on, F broadcast again and its fate found anew, only
        // once its block left the chain.
        if contract.fate == Some(Fate::Live) {
            match unburied_f(&store, chain, &id).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!(id = %crate::hex_id(&id), "following F's block: {e:#}");
                    continue;
                }
            }
        }
        if unreadable().contains(&id) {
            continue;
        }
        if overdue(contract.phase, contract.created_at, now) {
            tracing::warn!(id = %crate::hex_id(&id), "an opening not opened in a day: given up");
            store.abandon(&id, "not opened in a day")?;
            // Reserved if she signed her deposit into F, a step unstored:
            // her signature never left.
            if let Some(f) = contract.funding {
                let _ = wallet.abandon_silent(&f);
            }
            continue;
        }
        let (state, _) = store.state(&id)?;
        let secrets = wallet.contract_secrets();
        let ctx = licash_contract::opening::Context { tip, trust };
        let holder = match Holder::load(&state, &secrets.seed, &ctx) {
            Ok(holder) => holder,
            Err(e) => {
                // One that cannot be read (opened under programs this build
                // does not name, say) holds up none of the others: given up
                // if she never signed its F, else kept as it is.
                tracing::warn!(id = %crate::hex_id(&id), "loading an opening: {e:#}");
                store.abandon(&id, &format!("cannot be carried on: {e}"))?;
                unreadable().insert(id);
                continue;
            }
        };
        let mut driver = Driver {
            wallet,
            chain,
            store: &store,
            trust,
            hub: contract.hub.clone(),
            id,
            holder: Some(holder),
            quote: None,
            took_f: Default::default(),
        };
        // Her coin taken back from F, which she signed first: nothing more
        // to tell its hub.
        let resumed = match canceled(wallet, driver.holder()) {
            Some(_) => Ok(()),
            None => driver.resume().await,
        };
        if let Err(e) = driver.settle(resumed) {
            tracing::warn!(id = %crate::hex_id(&id), "resuming an opening: {e:#}");
            // Her deposit signed into F: watched all the same, and her
            // coin taken back if the hub never answers F whole.
            if driver.holder().phase() < Phase::Funded {
                continue;
            }
        }
        if let Err(e) = refresh(&driver, chain).await {
            tracing::warn!(id = %crate::hex_id(&id), "watching F: {e:#}");
        }
    }
    funded::collect(wallet, &store, tip).await;
    // Openings paid for with notes: opened once their coin is hers.
    paid::carry_on(wallet, chain, wallet_file, &store).await;
    let all = store.list()?;
    drop(store);
    // As they stand now: one newly buried, or past its time.
    if let Err(e) = fees::agree(wallet, wallet_file, Some(tip)) {
        tracing::warn!("what her contracts' hubs may charge: {e:#}");
    }
    Ok(all)
}

/// Whether F of the live contract `id` left the chain since found buried:
/// the block it was found in, followed for as long as the contract lasts
/// however deep (a reorganization deeper than any expected takes it out
/// all the same), replaced. Its fate is then open again, to be found
/// anew. One found live by a build before, or buried deep under one, is
/// not followed: trusted as it stands.
async fn unburied_f(store: &Store, chain: &impl Chain, id: &[u8; 32]) -> Result<bool> {
    let Some((height, hash)) = store.fate_block(id)? else {
        return Ok(false);
    };
    match chain.hash(height).await {
        Ok(now) if now == hash => Ok(false),
        Ok(_) => {
            tracing::warn!(id = %crate::hex_id(id), height, "F's block left the chain: its fate found again");
            store.unbury(id)?;
            Ok(true)
        }
        // A chain shorter, or not read: looked at again next time.
        Err(e) => {
            tracing::debug!(id = %crate::hex_id(id), "no block at {height}: {e}");
            Ok(false)
        }
    }
}

/// The contracts in `wallet_file`, the newest first: none if none was ever
/// opened there.
pub fn list(wallet_file: &Path) -> Result<Vec<Contract>> {
    match Store::existing(wallet_file)? {
        Some(store) => store.list(),
        None => Ok(Vec::new()),
    }
}

/// The hubs `wallet` trusts in the order its payment codes name them: those
/// whose contracts in `wallet_file`, live at `tip`, have the most room to protect
/// more than is held there first, then those holding the least, so that
/// what payers pay is protected and does not pile up at one hub; then by
/// URL.
pub fn code_hubs<T: Transport>(
    wallet: &Wallet<T>,
    wallet_file: &Path,
    tip: u32,
) -> Result<Vec<String>> {
    let contracts = list(wallet_file)?;
    let balance = wallet.balance()?;
    let mut hubs = Vec::new();
    for (url, _) in wallet.hubs()? {
        let urls = wallet.hub_urls(&url)?;
        let at = |hub: &str| {
            urls.iter()
                .any(|u| u.trim_end_matches('/') == hub.trim_end_matches('/'))
        };
        let held = |b: &licash_wallet::Balance| at(&b.hub).then_some(b.available + b.pending);
        let held: u64 = balance.iter().filter_map(held).sum();
        let live = contracts.iter().filter(|c| c.live(tip) && c.at(&urls));
        let caps: u64 = live.map(|c| u64::from(c.cap)).sum();
        hubs.push((url, held, caps));
    }
    Ok(rank_code_hubs(hubs))
}

/// `hubs`, each with what is held there and the caps of its live
/// contracts, as [`code_hubs`] orders them.
fn rank_code_hubs(mut hubs: Vec<(String, u64, u64)>) -> Vec<String> {
    hubs.sort_by(|(a, held_a, caps_a), (b, held_b, caps_b)| {
        let room = |held: &u64, caps: &u64| caps.saturating_sub(*held);
        (room(held_b, caps_b).cmp(&room(held_a, caps_a)))
            .then(held_a.cmp(held_b))
            .then(a.cmp(b))
    });
    hubs.into_iter().map(|(url, ..)| url).collect()
}

/// A live contract of hers at `hub`, F buried, its hub held to `fees`, kept
/// in the wallet's file `wallet_file` as opening one leaves it: for tests of
/// what such a contract holds a wallet to, which need none opened.
#[cfg(feature = "testing")]
#[doc(hidden)]
pub fn seed_contract(wallet_file: &Path, hub: &str, fees: &licash_api::Fees) -> Result<()> {
    use bitcoin::hashes::Hash as _;
    let store = Store::open(wallet_file)?;
    let new = New {
        id: [1; 32],
        hub,
        mock: true,
        deposit: OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        },
        value: 60_000,
        price: 23_000,
        cap: 4_096,
        assert_height: 360,
        close_height: 500,
        since: 200,
        state: b"",
    };
    store.insert_under(&new, fees, 0)?;
    store.settle_fate(&new.id, Fate::Live, None)
}

/// Check a restored store before installing it, without advancing a driver
/// or touching the chain: every recovery row must be one this build carries
/// on, and every signed opening it can read must have the instances its
/// recovery needs. An opening this build cannot read is carried as it was,
/// as on the phone it came from; it covers nothing here either.
pub fn validate_backup<T: Transport>(wallet: &Wallet<T>, wallet_file: &Path) -> Result<()> {
    let Some(store) = Store::existing(wallet_file)? else {
        return Ok(());
    };
    recovery::validate_backup(&store).context("this backup needs a newer version of the app")?;
    let ctx = licash_contract::opening::Context {
        tip: 0,
        trust: crate::trust(wallet.network())?,
    };
    let keys = wallet.contract_secrets();
    for c in store.list()? {
        if c.phase < Phase::Funded {
            continue;
        }
        let (state, _) = store.state(&c.id)?;
        if let Err(e) = Holder::load(&state, &keys.seed, &ctx).and_then(|holder| holder.signed()) {
            tracing::warn!(id = %crate::hex_id(&c.id), "restoring an unreadable opening as is: {e:#}");
        }
    }
    Ok(())
}

/// Financial and technical details from the holder's kept signed opening.
pub struct Inspection {
    pub address: String,
    pub locked: u64,
    pub payout_pool: u64,
    pub holder_reserve: u64,
    pub hub_reserve: u64,
    /// What her reserve affords a forced close of the most notes, sat/vB.
    pub forced_close_rate: f64,
    pub claim_limit: u32,
    pub note_limit: u32,
    pub denominations: Vec<u64>,
    pub keyset: String,
    pub graph_version: u32,
    pub program: String,
}

/// Read only when requested. Earlier opening stages may not have a signed
/// graph yet, in which case these details are unavailable rather than guessed.
pub fn inspect<T: Transport>(
    wallet: &Wallet<T>,
    wallet_file: &Path,
    id: &[u8; 32],
    tip: u32,
) -> Result<Inspection> {
    let store = Store::existing(wallet_file)?.context("no contracts")?;
    let (state, _) = store.state(id)?;
    let secrets = wallet.contract_secrets();
    let ctx = licash_contract::opening::Context {
        tip,
        trust: crate::trust(wallet.network())?,
    };
    let opening = Holder::load(&state, &secrets.seed, &ctx)?.signed()?;
    let network = match wallet.network() {
        licash::spend::ChainProfile::Core30Mainnet => bitcoin::Network::Bitcoin,
        licash::spend::ChainProfile::Core30DefaultRegtest => bitcoin::Network::Regtest,
        _ => bitcoin::Network::Signet,
    };
    inspection(&opening, network)
}

fn inspection(
    opening: &licash_contract::opening::Opening,
    network: bitcoin::Network,
) -> Result<Inspection> {
    let parts = opening.base.parts();
    let script = opening.babe.tree()?.script_pubkey();
    let locked = opening
        .funding
        .output
        .iter()
        .find(|out| out.script_pubkey == script)
        .context("no contract output")?
        .value
        .to_sat();
    ensure!(
        locked == parts.graph_value()?,
        "contract lock disagrees with its signed terms"
    );
    Ok(Inspection {
        address: bitcoin::Address::from_script(&script, network)?.to_string(),
        locked,
        payout_pool: u64::from(parts.pool()?),
        holder_reserve: parts.graph.reserve_alice,
        hub_reserve: parts.graph.reserve_hub,
        forced_close_rate: licash_contract::reserve::affordable_rate_at_most(&parts.graph) as f64
            / 1_000.0,
        claim_limit: parts.cap,
        note_limit: parts
            .limits
            .max_authorizations
            .min(licash::claim::MAX_ITEMS as u32),
        denominations: parts.keyset.denominations().collect(),
        keyset: crate::hex_id(parts.keyset.id()),
        graph_version: parts.recipe.graph_version,
        program: crate::hex_id(&parts.recipe.program),
    })
}

/// Precisely what live contracts can claim now, by id: what their
/// recoveries would claim of the notes at their hubs, shared out among
/// them ([`claims`]), from the terms they opened with rather than current
/// hub offers. One under recovery shows none: its recovery fixes its notes
/// once, and it cannot also protect those left over or received after.
/// It still takes its share, which the others then cannot claim. Each
/// claims the lock branches owed first, which leave less of its cap to
/// notes: the refunds owed, and the pays owed that it is the one to
/// claim. One whose opening cannot be read or is of
/// an untrusted holder program covers nothing; this never triggers
/// recovery or reserves notes.
pub fn coverage<T: Transport>(
    wallet: &Wallet<T>,
    wallet_file: &Path,
    contracts: &[Contract],
    tip: u32,
) -> Result<std::collections::HashMap<[u8; 32], u64>> {
    let Some(store) = Store::existing(wallet_file)?.filter(|_| tip > 0) else {
        return Ok(std::collections::HashMap::new());
    };
    let held = wallet.balance()?;
    let live = coverage_order(contracts, tip, &held, &HashSet::new());
    let terms = claims::terms(wallet, &store, &live, tip)?;
    let mut hubs = Vec::new();
    for (url, _) in wallet.hubs()? {
        hubs.push(wallet.hub_urls(&url)?);
    }
    let mut claimants = std::collections::BTreeMap::new();
    for o in wallet.owed_locks()? {
        if let Some(id) = activation::claimant(wallet, &store, wallet_file, &o, tip)? {
            claimants.insert(o.id, id);
        }
    }
    let pays =
        |slot: &[u8; 32], pay: &licash_wallet::LockClaim| claimants.get(&pay.id) == Some(slot);
    let mut amounts = claims::shared_out(&live, &terms, &hubs, |slots| {
        Ok::<_, anyhow::Error>(wallet.recoverable(slots, tip, Some(&pays))?)
    })?;
    let recovering: HashSet<_> = store.recoveries()?.into_iter().map(|r| r.id).collect();
    amounts.retain(|id, _| !recovering.contains(id));
    Ok(amounts)
}

fn coverage_order<'a>(
    contracts: &'a [Contract],
    tip: u32,
    held: &[licash_wallet::Balance],
    recovering: &HashSet<[u8; 32]>,
) -> Vec<&'a Contract> {
    let mut live: Vec<_> = contracts
        .iter()
        .filter(|c| {
            tip > 0
                && c.live(tip)
                && !recovering.contains(&c.id)
                && held
                    .iter()
                    .any(|at| at.hub.trim_end_matches('/') == c.hub.trim_end_matches('/'))
        })
        .collect();
    live.sort_by_key(|c| (c.assert_height, c.id));
    live
}

/// The coin of `wallet`'s that [`open`] would deposit of `least` sat at
/// least (`least`), with the contracts in `wallet_file`: the smallest free.
/// None if no coin does.
pub fn coin<T: Transport>(
    wallet: &Wallet<T>,
    wallet_file: &Path,
    least: u64,
) -> Result<Option<SilentCoin>> {
    Ok(smallest(coins(wallet, wallet_file)?, least))
}

/// The coins of `wallet`'s free to deposit, with the contracts in `wallet_file`:
/// confirmed on Bitcoin, unspent and no other contract's deposit, the
/// largest first.
pub fn coins<T: Transport>(wallet: &Wallet<T>, wallet_file: &Path) -> Result<Vec<SilentCoin>> {
    let mut coins = match Store::existing(wallet_file)? {
        Some(store) => free(wallet, &store)?,
        None => free_of(wallet, &[])?,
    };
    coins.sort_by_key(|c| std::cmp::Reverse(c.value));
    Ok(coins)
}

/// The most of `wanted` sat a contract can be funded with by its holder,
/// in `notes` notes at most of `denominations` (a keyset's, the fewest
/// notes largest first): what a funding of `wanted` rounds down to, that
/// a claim names them all should the hub never issue them.
pub fn fundable(denominations: &[u64], notes: usize, wanted: u64) -> u64 {
    let mut sorted = denominations.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let (mut left, mut taken, mut made) = (wanted, 0, 0);
    for denom in sorted.into_iter().filter(|&d| d > 0) {
        while left >= denom && made < notes {
            left -= denom;
            taken += denom;
            made += 1;
        }
    }
    taken
}

/// What a contract on `quote` can be funded with by its holder: the
/// denominations of its keyset and the most notes, those a claim names
/// ([`fundable`]).
pub fn funding_notes(quote: &Quote) -> (Vec<u64>, usize) {
    let terms = claims::ClaimTerms::new(*quote.keyset.id(), quote.limits.max_authorizations);
    (quote.keyset.denominations().collect(), terms.max)
}

/// What a hub charges for a contract, as her coin is fitted to one.
#[derive(Clone, Copy, Debug)]
pub enum Pricing<'a> {
    /// Terms she chooses within its range.
    Range(&'a licash_api::ContractRange),
    /// Its fixed terms only: its cap, and its price, which her part of the
    /// contract changes not at all.
    Fixed { cap: u32, price: u64 },
}

impl Pricing<'_> {
    /// What a contract of `cap` sat over `blocks` costs besides her part of
    /// it, `funded` sat, which her coin pays too.
    fn price(&self, cap: u32, blocks: u32, funded: u32) -> u64 {
        match self {
            Self::Fixed { price, .. } => *price,
            Self::Range(range) => range.price(cap, blocks, funded),
        }
    }

    /// The cap of a contract of a coin of `coin` sat that protects `want`
    /// sat, `least` at least: the smallest the hub takes, or its fixed one
    /// if that is enough. None if none is.
    fn cap_for(&self, coin: u64, want: u64, least: u32) -> Option<u32> {
        match self {
            Self::Fixed { cap, .. } => (want <= u64::from(*cap) && least <= *cap).then_some(*cap),
            Self::Range(range) => {
                let cap = range.cap_at_least(want.max(u64::from(least)))?;
                // Its cap at most so many times her coin, but the least,
                // which any coin may take.
                (cap == range.min_cap
                    || u64::from(cap) <= coin.saturating_mul(u64::from(range.per_coin)))
                .then_some(cap)
            }
        }
    }
}

/// A contract that absorbs a coin whole: its cap and her part of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fit {
    pub cap: u32,
    pub funded: u32,
}

/// Why no contract absorbs a coin.
pub const NO_FIT: &str =
    "no contract of this hub absorbs it whole: a coin pays the price and funds \
     the rest of its part of the contract, leaving less than dust, and is not below the price or \
     beyond what its largest contract takes";

/// The smallest of `coins` that a contract absorbs whole ([`fit`]), with
/// the contract.
pub fn smallest_fit(
    mut coins: Vec<SilentCoin>,
    pricing: &Pricing,
    blocks: u32,
    dust: u64,
    notes: (&[u64], usize),
    least: u32,
    inbound: u32,
) -> Option<(SilentCoin, Fit)> {
    coins.sort_by_key(|c| c.value);
    coins.into_iter().find_map(|coin| {
        let fitted = fit(pricing, blocks, coin.value, dust, notes, least, inbound)?;
        Some((coin, fitted))
    })
}

/// The contract that absorbs a coin of `coin` sat whole, over `blocks`:
/// her part the most her coin pays beyond the price, that its keyset's
/// notes make exactly in `notes` notes at most (`denominations`,
/// [`fundable`]), leaving less than `dust`; its cap the smallest the hub
/// takes of her part and `inbound` sat more, `least` at least. So with no
/// inbound, the hub funds nothing of it but what makes a cap. No change
/// comes back from her coin, so what is left of it is below what an
/// output is worth. None if no contract does.
pub fn fit(
    pricing: &Pricing,
    blocks: u32,
    coin: u64,
    dust: u64,
    (denominations, notes): (&[u64], usize),
    least: u32,
    inbound: u32,
) -> Option<Fit> {
    let cap_of = |funded: u32| pricing.cap_for(coin, u64::from(funded) + u64::from(inbound), least);
    // What her coin pays for her part, `funded`: it grows with it, by no
    // more than 2 sat for each, the interest on the hub's part falling as
    // it rises and rounded down, and its cap rising with it.
    let pays = |funded: u32| {
        let cap = cap_of(funded)?;
        Some(u64::from(funded) + pricing.price(cap, blocks, funded))
    };
    let affords = |funded| pays(funded).is_some_and(|paid| paid <= coin);
    if !affords(1) {
        return None;
    }
    let (mut low, mut high) = (1, u32::try_from(coin).unwrap_or(u32::MAX));
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        match affords(mid) {
            true => low = mid,
            false => high = mid - 1,
        }
    }
    for funded in (1..=low).rev() {
        // A hub's interest may fall faster than her part rises: a smaller
        // part may cost more than her coin.
        let Some(left) = pays(funded).and_then(|paid| coin.checked_sub(paid)) else {
            continue;
        };
        if left >= dust {
            // Less of her part leaves more of her coin.
            break;
        }
        if fundable(denominations, notes, u64::from(funded)) == u64::from(funded) {
            return Some(Fit {
                cap: cap_of(funded)?,
                funded,
            });
        }
    }
    None
}

/// The offer of `hub` now: of `chosen` terms, a cap in sat over blocks,
/// if any, else its fixed ones, `funded` sat of it hers. Refused unless
/// of those terms exactly, as a hub offering no others answers.
pub async fn offer<T: Transport>(
    wallet: &Wallet<T>,
    hub: &str,
    chosen: Option<(u32, u32)>,
    funded: u64,
) -> Result<Offer> {
    let mut url = format!("{}{QUOTE}", hub.trim_end_matches('/'));
    let mut asked = Vec::new();
    if let Some((cap, blocks)) = chosen {
        asked.push(format!("cap={cap}&blocks={blocks}"));
    }
    if funded > 0 {
        asked.push(format!("funded={funded}"));
    }
    if !asked.is_empty() {
        url.push_str(&format!("?{}", asked.join("&")));
    }
    // Turned away busy, asked again a while: see [`driver::Busy`].
    let mut busy = driver::Busy::default();
    let response = loop {
        let response = wallet.transport().request(&url, None).await;
        let response = response.map_err(|e| anyhow!("{hub}: {e}"))?;
        if response.status != 503 || !busy.wait().await {
            break response;
        }
    };
    ensure!(
        response.status == 200,
        "{hub} offers no contracts{}: status {}: {}",
        match chosen {
            Some((cap, blocks)) => format!(" of {cap} sat over {blocks} blocks"),
            None => String::new(),
        },
        response.status,
        String::from_utf8_lossy(&response.body[..response.body.len().min(500)])
    );
    let offer = Offer::decode(&response.body).with_context(|| format!("{hub}'s offer"))?;
    if let Some((cap, blocks)) = chosen {
        let (quoted, lock) = (offer.quote.cap, offer.bounds.lock);
        ensure!(
            (quoted, lock) == (cap, blocks),
            "{hub} offers contracts of {quoted} sat over {lock} blocks, not {cap} over {blocks}"
        );
    }
    ensure!(
        offer.funded() == funded,
        "{hub} offers contracts {} sat of which she funds, not {funded}",
        offer.funded()
    );
    Ok(offer)
}

/// Her deadlines on `offer` at `tip`: the close `blocks` ahead, no later
/// than the hub's bounds allow, the assertion deadline before it, her
/// window to contest the hub's response before that.
fn wanted(offer: &Offer, tip: u32, blocks: u32) -> Result<Wanted> {
    let bounds = &offer.bounds;
    ensure!(
        blocks <= bounds.lock,
        "{blocks} blocks, more than the hub's {}",
        bounds.lock
    );
    // The hub counts from its tip, at its checkpoint or past it.
    let latest = offer
        .quote
        .chain
        .checkpoint
        .height()
        .saturating_add(bounds.lock);
    let close_height = tip.saturating_add(blocks).min(latest);
    let response_window = RESPONSE_WINDOW
        .max(bounds.response_window)
        .max(offer.quote.graph.publication_window.saturating_add(2));
    let request_height = close_height
        .checked_sub(after_assert(&offer.quote))
        .and_then(|h| h.checked_sub(u32::from(response_window)))
        .and_then(|h| h.checked_sub(u32::from(offer.quote.graph.contest_window)))
        .and_then(|h| h.checked_sub(u32::from(offer.quote.graph.assert_window)))
        .filter(|a| *a > tip)
        .with_context(|| format!("{blocks} blocks leave no time to recover in"))?;
    Ok(Wanted {
        request_height,
        close_height,
        response_window,
    })
}

/// The notes she funds `funded` sat of a contract on `quote` with: refused
/// unless as few as a claim names, should the hub never issue them.
fn funded_notes<T: Transport>(
    wallet: &Wallet<T>,
    quote: &Quote,
    funded: u64,
) -> Result<licash_contract::wire::FundedNotes> {
    ensure!(
        funded <= u64::from(quote.cap),
        "{funded} sat funded, more than the {} sat contract",
        quote.cap
    );
    let (ephemeral, outputs) = wallet.funded_outputs(&quote.keyset, funded)?;
    let most = claims::ClaimTerms::new(*quote.keyset.id(), quote.limits.max_authorizations).max;
    ensure!(
        outputs.len() <= most,
        "{funded} sat are {} notes at the hub, more than the {most} a claim names: fund {} \
         sat, say",
        outputs.len(),
        fundable(
            &quote.keyset.denominations().collect::<Vec<_>>(),
            most,
            funded
        )
    );
    Ok(licash_contract::wire::FundedNotes { ephemeral, outputs })
}

/// The coins of `wallet` free to deposit: unspent and no other
/// contract's deposit.
fn free<T: Transport>(wallet: &Wallet<T>, store: &Store) -> Result<Vec<SilentCoin>> {
    let taken: Vec<OutPoint> = store
        .list()?
        .into_iter()
        .filter(|c| c.abandoned.is_none() && c.fate != Some(Fate::Dead))
        .map(|c| c.deposit)
        .collect();
    free_of(wallet, &taken)
}

fn free_of<T: Transport>(wallet: &Wallet<T>, taken: &[OutPoint]) -> Result<Vec<SilentCoin>> {
    let mut coins = wallet.silent_coins()?;
    coins.retain(|c| c.spending.is_none() && !taken.contains(&c.outpoint));
    Ok(coins)
}

/// The smallest of `coins` of `least` sat at least.
fn smallest(coins: Vec<SilentCoin>, least: u64) -> Option<SilentCoin> {
    coins
        .into_iter()
        .filter(|c| c.value >= least)
        .min_by_key(|c| c.value)
}

/// How many blocks after she signed her deposit into F first, F in none
/// and in no mempool her chain sees, she takes her coin back
/// (`refresh`): the hub, which alone holds F whole, withholds it, or
/// never heard.
pub const F_UNSEEN: u32 = 6;

/// Watch the F of the opening `driver` drives, once she signed it: its
/// fate stored, her coin freed if F can never confirm, or once it lapsed
/// unconfirmed; or spent back to her, if she signed first and F is seen
/// nowhere [`F_UNSEEN`] blocks on.
async fn refresh<T: Transport, C: Chain>(driver: &Driver<'_, T, C>, chain: &C) -> Result<()> {
    let holder = driver.holder();
    if holder.phase() != Phase::Funded {
        return Ok(());
    }
    let (_, since) = driver.store.state(&driver.id)?;
    let Some((fate, block)) = chain::fate(holder, chain, since).await? else {
        return Ok(());
    };
    driver.store.settle_fate(&driver.id, fate, block)?;
    if fate == Fate::Dead {
        driver.store.forget(&driver.id)?;
    }
    let tip = chain.height().await.map_err(|e| anyhow!(e))?;
    let free = fate == Fate::Dead || (fate == Fate::Open && holder.lapsed(tip));
    let Some(f) = holder.funding() else {
        return Ok(());
    };
    let txid = f.tx.compute_txid();
    if free {
        // Freed already, or spent: nothing to free.
        let _ = driver.wallet.abandon_silent(&txid);
        tracing::warn!(id = %crate::hex_id(&driver.id), %txid, ?fate, "F will not confirm: her coin freed");
    } else if fate == Fate::Open && cancel(driver, chain, holder, tip, block.is_some()).await? {
        // Canceled: F confirms no more, but a block taking it before.
    } else if fate == Fate::Open {
        // Her coin kept for F: a wallet rewinding past it, as a reorg
        // makes it, forgets what reserved it. Refused once a block
        // spends it, which is no matter.
        if let Err(e) = driver.wallet.sign_input(f.tx, f.prevouts, f.deposit) {
            tracing::debug!(id = %crate::hex_id(&driver.id), %txid, "her coin not kept again: {e}");
        }
    }
    Ok(())
}

/// Whether she canceled F, which she signed first: her deposit spent by
/// her wallet otherwise, with the height of the block it is spent in, if
/// any.
fn canceled<T: Transport>(wallet: &Wallet<T>, holder: &Holder) -> Option<Option<u32>> {
    let f = holder.funding()?;
    holder.signed_at()?;
    let deposit = f.tx.input[f.deposit].previous_output;
    match wallet.silent_spender(&deposit) {
        Ok(Some((by, at))) if by != f.tx.compute_txid() => Some(at),
        _ => None,
    }
}

/// Her coin spent back to her wallet, the cancel broadcast, if she signed
/// her deposit into F first and F is in no block (`in_block`, however
/// shallow) nor in a mempool her chain sees, [`F_UNSEEN`] blocks after she
/// signed: whether she canceled, now or before. F answered whole is handed
/// to the network first, and canceled only if refused (signed otherwise
/// by the hub, say): she never checks its signatures. The cancel pays at
/// most F's rate, so that it never takes the place of an F a mempool
/// holds, which may confirm still: it is left waiting there. One her
/// wallet cannot make (her coin no longer kept for F) is left undone.
async fn cancel<T: Transport, C: Chain>(
    driver: &Driver<'_, T, C>,
    chain: &C,
    holder: &Holder,
    tip: u32,
    in_block: bool,
) -> Result<bool> {
    let (Some(f), Some(at)) = (holder.funding(), holder.signed_at()) else {
        return Ok(false);
    };
    let txid = f.tx.compute_txid();
    let id = crate::hex_id(&driver.id);
    match canceled(driver.wallet, holder) {
        // In a block: nothing more to do.
        Some(Some(_)) => return Ok(true),
        // Broadcast again below.
        Some(None) => {}
        None => {
            if in_block || tip < at.saturating_add(F_UNSEEN) {
                return Ok(false);
            }
            match chain.in_mempool(&txid).await {
                Ok(Some(true)) => return Ok(false),
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(%id, %txid, "is F in a mempool: {e}");
                    return Ok(false);
                }
            }
            // F whole, taken from her this time already, or now: it may
            // confirm still.
            if holder.wholly_funded() {
                if driver.took_f.load(std::sync::atomic::Ordering::Relaxed) {
                    return Ok(false);
                }
                match chain.broadcast(f.tx).await {
                    Ok(()) => {
                        tracing::warn!(%id, %txid, "F seen nowhere since she signed it: broadcast again");
                        return Ok(false);
                    }
                    Err(e) => tracing::warn!(%id, %txid, "F answered whole, refused: {e}"),
                }
            }
        }
    }
    let paid = (f.prevouts.iter().map(|o| o.value.to_sat()).sum::<u64>())
        .saturating_sub(f.tx.output.iter().map(|o| o.value.to_sat()).sum());
    // F's rate as she holds it, the hub's inputs unsigned: more than it
    // pays, yet her cancel, smaller, pays less than F in all, as one
    // taking its place must not.
    let most =
        bitcoin::FeeRate::from_sat_per_kwu((paid * 1_000 / f.tx.weight().to_wu().max(1)).max(250));
    let rate = match chain.fee_rate(6).await {
        Ok(Some(rate)) => rate.min(most),
        _ => most,
    };
    let tx = match driver.wallet.cancel_signed(f.tx, f.deposit, rate) {
        Ok(tx) => tx,
        Err(e) => {
            tracing::debug!(%id, %txid, "her coin not canceled: {e}");
            return Ok(false);
        }
    };
    let by = tx.compute_txid();
    match chain.broadcast(&tx).await {
        Ok(()) => {
            tracing::warn!(%id, %txid, cancel = %by, "F seen nowhere since she signed it: her coin spent back")
        }
        Err(e) => tracing::warn!(%id, %txid, cancel = %by, "broadcasting her cancel of F: {e}"),
    }
    Ok(true)
}

fn found(store: &Store, id: &[u8; 32]) -> Result<Contract> {
    store
        .list()?
        .into_iter()
        .find(|c| c.id == *id)
        .context("the contract just stored")
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash as _, Block, BlockHash, Transaction, TxOut, Txid};
    use licash::{chain::Checkpoint, spend::ChainProfile};
    use licash_wallet::{Blocks, Response};

    use super::*;

    #[test]
    fn codes_name_the_hubs_with_room_to_protect_more_then_the_least_held() {
        let hub = |url: &str, held: u64, caps: u64| (url.to_owned(), held, caps);
        let hubs = vec![
            // Room for 50 more: first.
            hub("http://d.test", 50, 100),
            // Unprotected, or full: by what they hold, the least first.
            hub("http://c.test", 300, 0),
            hub("http://b.test", 10, 0),
            hub("http://e.test", 100, 100),
            // Room for 10 more: after the room for 50.
            hub("http://a.test", 0, 10),
            // As much as another: by URL.
            hub("http://f.test", 10, 0),
        ];
        let ranked = rank_code_hubs(hubs);
        let wanted = ["d", "a", "b", "f", "e", "c"].map(|h| format!("http://{h}.test"));
        assert_eq!(ranked, wanted);
    }

    #[test]
    fn a_funding_rounds_down_to_as_many_notes_as_a_claim_names() {
        let twos: Vec<u64> = (0..12).map(|i| 1 << i).collect();
        assert_eq!(fundable(&twos, 32, 4_095), 4_095);
        // 2 048 at most a note: 31 of them, and 1 024 of the 2 047 left.
        assert_eq!(fundable(&twos, 32, 65_535), 2_048 * 31 + 1_024);
        assert_eq!(fundable(&twos, 3, 7_000), 2_048 * 3);
        assert_eq!(fundable(&twos, 3, 5), 5);
        assert_eq!(fundable(&twos, 0, 5), 0);
        let wide: Vec<u64> = (0..32).map(|i| 1 << i).collect();
        assert_eq!(fundable(&wide, 16, 1_000_000), 1_000_000);
    }

    fn range() -> licash_api::ContractRange {
        licash_api::ContractRange {
            min_cap: 131_071,
            max_cap: 16_777_215,
            min_blocks: 300,
            max_blocks: 52_560,
            per_coin: 4,
            reserve: 20_000,
            fee: 3_000,
            ppm_year: 20_000,
            ppm_year_funded: 0,
            year_blocks: licash_api::YEAR_BLOCKS,
        }
    }

    /// What her coin pays in a contract: her part and the price.
    fn pays(range: &licash_api::ContractRange, fit: Fit) -> u64 {
        u64::from(fit.funded) + range.price(fit.cap, 52_560, fit.funded)
    }

    /// Interest on her part and on the hub's that all but cancel her part
    /// out: rounded down, what her coin pays goes up and down by a sat as
    /// her part rises. Never taken past her coin.
    #[test]
    fn a_price_not_rising_with_her_part_never_takes_more_than_her_coin() {
        let range = licash_api::ContractRange {
            ppm_year: 1_299_900,
            ppm_year_funded: 300_000,
            ..range()
        };
        let year = licash_api::YEAR_BLOCKS;
        let cap = 131_071;
        let pays = |funded| u64::from(funded) + range.price(cap, year, funded);
        let coin = 193_378;
        assert!(pays(4_096) <= coin && pays(7) > coin);
        // No notes make her part: each looked at, down from the most.
        let fitted = fit(
            &Pricing::Range(&range),
            year,
            coin,
            330,
            (&[1 << 40], 1),
            0,
            0,
        );
        assert_eq!(fitted, None);
    }

    #[test]
    fn a_coin_is_absorbed_whole_by_a_contract_of_her_part() {
        let range = range();
        let wide: Vec<u64> = (0..32).map(|i| 1 << i).collect();
        let fits = |coin| {
            fit(
                &Pricing::Range(&range),
                52_560,
                coin,
                330,
                (&wide, 32),
                0,
                0,
            )
        };
        // 1 M sat: the price, and her part all the rest, the cap that part
        // (or under 512 sat more, a cap whose payout pays it exactly).
        let fitted = fits(1_000_000).unwrap();
        assert!(licash_api::is_cap(fitted.cap));
        assert!(
            fitted.cap - fitted.funded < licash_api::MIN_REST,
            "{fitted:?}"
        );
        assert!(fitted.funded > 1_000_000 - 24_000, "{fitted:?}");
        let left = 1_000_000 - pays(&range, fitted);
        assert!(left < 330, "{left} sat left over");
        // A part below the least cap: the least.
        let small = fits(150_000).unwrap();
        assert_eq!(small.cap, 131_071);
        assert!(150_000 - pays(&range, small) < 330);
        // A coin short of the price, and one beyond the largest contract.
        assert_eq!(fits(25_000), None);
        assert_eq!(fits(100_000_000), None);
        // Or of the cap she asks at least: a cover at most 4 times the coin.
        let asked = |least| {
            fit(
                &Pricing::Range(&range),
                52_560,
                1_000_000,
                330,
                (&wide, 32),
                least,
                0,
            )
        };
        assert_eq!(asked(2_000_000).map(|f| f.cap), Some(2_000_000));
        assert_eq!(asked(5_000_000), None);
        // Or inbound she asks of the hub past her part, at its interest.
        let inbound = |inbound| {
            fit(
                &Pricing::Range(&range),
                52_560,
                1_000_000,
                330,
                (&wide, 32),
                0,
                inbound,
            )
        };
        let more = inbound(500_000).unwrap();
        assert!(
            more.cap - more.funded - 500_000 < licash_api::MIN_REST,
            "{more:?}"
        );
        assert!(
            more.funded < fitted.funded,
            "the hub's interest on its part"
        );
        assert!(1_000_000 - pays(&range, more) < 330);
        assert_eq!(inbound(4_000_000), None, "a cover at most 4 times the coin");
    }

    #[test]
    fn every_coin_between_the_price_and_what_the_largest_contract_takes_is_absorbed() {
        let range = range();
        let wide: Vec<u64> = (0..32).map(|i| 1 << i).collect();
        for coin in (26_000..8_000_000).step_by(99_991) {
            let fitted = fit(
                &Pricing::Range(&range),
                52_560,
                coin,
                330,
                (&wide, 32),
                0,
                0,
            )
            .unwrap_or_else(|| panic!("no contract absorbs {coin}"));
            let paid = pays(&range, fitted);
            assert!(
                paid <= coin && coin - paid < 330,
                "{coin}: {fitted:?} pays {paid}"
            );
            assert!(fitted.funded >= 1 && fitted.funded <= fitted.cap);
            assert!(licash_api::is_cap(fitted.cap));
            // The hub's part only what makes a cap.
            assert!(
                fitted.cap == range.min_cap || fitted.cap - fitted.funded < licash_api::MIN_REST,
                "{coin}: {fitted:?}"
            );
        }
    }

    #[test]
    fn her_part_is_made_of_notes_a_claim_names() {
        let range = range();
        // 2 048 at most a note: not every amount is as few as 32 notes of it.
        let twos: Vec<u64> = (0..12).map(|i| 1 << i).collect();
        for coin in (26_000..400_000).step_by(7_919) {
            let Some(fitted) = fit(
                &Pricing::Range(&range),
                52_560,
                coin,
                330,
                (&twos, 32),
                0,
                0,
            ) else {
                continue;
            };
            let funded = u64::from(fitted.funded);
            assert_eq!(fundable(&twos, 32, funded), funded, "{coin}: {fitted:?}");
            assert!(coin - pays(&range, fitted) < 330);
        }
        // A coin that only a part too large for them takes fits none.
        assert_eq!(
            fit(
                &Pricing::Range(&range),
                52_560,
                8_000_000,
                330,
                (&twos, 32),
                0,
                0
            ),
            None
        );
    }

    #[test]
    fn a_hub_of_one_contract_takes_the_coins_that_contract_absorbs() {
        let wide: Vec<u64> = (0..32).map(|i| 1 << i).collect();
        let fixed = Pricing::Fixed {
            cap: 3_584,
            price: 21_000,
        };
        let fits = |coin| fit(&fixed, 1_000, coin, 330, (&wide, 32), 0, 0);
        assert_eq!(
            fits(24_000),
            Some(Fit {
                cap: 3_584,
                funded: 3_000
            })
        );
        // The price is not paid, or more than the cap takes is left.
        assert_eq!(fits(21_000), None);
        assert_eq!(fits(30_000), None);
        // The most it takes, and the dust that may stay unspent.
        assert!(fits(21_000 + 3_584 + 329).is_some());
        assert_eq!(fits(21_000 + 3_584 + 330), None);
    }

    #[test]
    fn an_opening_short_of_her_signing_f_a_day_on_is_given_up() {
        let began = 1_794_900_000;
        let day = began + OPENS_WITHIN;
        for phase in [
            Phase::Started,
            Phase::Committed,
            Phase::Chosen,
            Phase::Consented,
        ] {
            assert!(!overdue(phase, began, day), "{phase:?} within a day");
            assert!(overdue(phase, began, day + 1), "{phase:?} past a day");
        }
        // Her deposit signed into F: never given up for its age.
        for phase in [Phase::Signing, Phase::Funded] {
            assert!(!overdue(phase, began, day + 365 * 86_400), "{phase:?}");
        }
    }

    #[test]
    fn inspection_uses_the_funded_graph_not_the_deposit_and_never_adds_the_cap_twice() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[7; 32],
            ChainProfile::Core30DefaultRegtest,
            Nowhere,
        )
        .unwrap();
        let keys = wallet.contract_secrets();
        let holder = Holder::load(
            &crate::testing::opened().holder,
            &keys.seed,
            &licash_contract::opening::Context {
                tip: 0,
                trust: crate::trust(ChainProfile::Core30DefaultRegtest).unwrap(),
            },
        )
        .unwrap();
        let opening = holder.signed().unwrap();
        let info = inspection(&opening, bitcoin::Network::Regtest).unwrap();
        assert_eq!(
            info.locked,
            info.payout_pool + info.holder_reserve + info.hub_reserve
        );
        assert!(u64::from(info.claim_limit) <= info.payout_pool);
        assert_eq!(
            info.note_limit,
            32.min(opening.base.parts().limits.max_authorizations)
        );
        assert_eq!(
            info.denominations,
            opening
                .base
                .parts()
                .keyset
                .denominations()
                .collect::<Vec<_>>()
        );
        let address = info
            .address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .unwrap()
            .require_network(bitcoin::Network::Regtest)
            .unwrap();
        assert_eq!(
            address.script_pubkey(),
            opening.babe.tree().unwrap().script_pubkey()
        );
        assert_eq!(
            info.graph_version,
            opening.base.parts().recipe.graph_version
        );
    }

    #[test]
    fn coverage_uses_live_trusted_contracts_in_deadline_and_id_order() {
        let contract = |id, deadline, fate| Contract {
            id: [id; 32],
            hub: "http://hub.example".into(),
            phase: Phase::Funded,
            mock: false,
            deposit: OutPoint::null(),
            value: 60_000,
            price: 23_000,
            cap: 4_096,
            assert_height: deadline,
            close_height: 500,
            since: 200,
            funding: None,
            fate: Some(fate),
            abandoned: None,
            created_at: 0,
            folded: None,
            funded: 0,
            funded_received: false,
        };
        let mut other = contract(5, 320, Fate::Live);
        other.hub = "http://other.example".into();
        let all = [
            contract(3, 400, Fate::Live),
            contract(2, 380, Fate::Live),
            contract(1, 400, Fate::Live),
            contract(4, 350, Fate::Open),
            other,
        ];
        let held = [licash_wallet::Balance {
            hub: "http://hub.example/".into(),
            available: 104,
            pending: 1_000,
        }];
        let ids = |tip| {
            coverage_order(&all, tip, &held, &HashSet::new())
                .iter()
                .map(|c| c.id[0])
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(300), [2, 1, 3]);
        assert_eq!(ids(380), [1, 3]);
        assert!(ids(400).is_empty());
        assert!(ids(0).is_empty());
        assert_eq!(
            coverage_order(&all, 300, &held, &HashSet::from([[2; 32]]))
                .iter()
                .map(|c| c.id[0])
                .collect::<Vec<_>>(),
            [1, 3]
        );
    }

    #[test]
    fn a_restored_garbler_needs_no_instance_files_and_an_unreadable_opening_is_carried() {
        let dir = tempfile::tempdir().unwrap();
        let regtest = ChainProfile::Core30DefaultRegtest;
        let wallet = Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[7; 32],
            regtest,
            Nowhere,
        )
        .unwrap();
        // No contracts kept at all: nothing to check.
        validate_backup(&wallet, &dir.path().join("wallet.sqlite")).unwrap();
        let keys = wallet.contract_secrets();
        let ctx = licash_contract::opening::Context {
            tip: 0,
            trust: crate::trust(regtest).unwrap(),
        };
        let bytes = &crate::testing::opened().holder;
        let o = Holder::load(bytes, &keys.seed, &ctx)
            .unwrap()
            .signed()
            .unwrap();
        let id = o.base.parts().nonce;
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        let insert = |id: [u8; 32], vout: u32, state: &[u8]| {
            store
                .insert(&New {
                    id,
                    hub: "http://hub.example",
                    mock: true,
                    deposit: OutPoint {
                        txid: bitcoin::Txid::all_zeros(),
                        vout,
                    },
                    value: 60_000,
                    price: 23_000,
                    cap: 4_096,
                    assert_height: 300,
                    close_height: 500,
                    since: 0,
                    state,
                })
                .unwrap();
            store.save(&id, Phase::Funded, None, state).unwrap();
        };
        insert(id, 0, bytes);
        // The backed-up wallet seed regenerates the holder's circuits.
        validate_backup(&wallet, &dir.path().join("wallet.sqlite")).unwrap();
        // One this build cannot read is restored as it was, not refused.
        insert([9; 32], 1, b"of a later version");
        validate_backup(&wallet, &dir.path().join("wallet.sqlite")).unwrap();
    }

    /// No hub to reach.
    struct Nowhere;

    impl Transport for Nowhere {
        async fn request(&self, _: &str, _: Option<Vec<u8>>) -> Result<Response, String> {
            Err("no hub here".into())
        }
    }

    /// A chain at height 250, asked nothing else.
    struct Tip;

    impl Blocks for Tip {
        async fn height(&self) -> Result<u32, String> {
            Ok(250)
        }
        async fn hash(&self, _: u32) -> Result<BlockHash, String> {
            Err("not asked".into())
        }
        async fn filter(&self, _: &BlockHash) -> Result<Option<Vec<u8>>, String> {
            Err("not asked".into())
        }
        async fn block(&self, _: &BlockHash) -> Result<Block, String> {
            Err("not asked".into())
        }
    }

    impl Chain for Tip {
        async fn checkpoint(&self, _: u32) -> Result<Checkpoint, String> {
            Err("not asked".into())
        }
        async fn broadcast(&self, _: &Transaction) -> Result<(), String> {
            Err("not asked".into())
        }
    }

    #[cfg(feature = "node")]
    #[test]
    fn her_deadlines_leave_each_window_whole_on_the_hubs_terms() {
        use crate::hub::terms::Timing;
        let keyset = licash::note::IssuerKeys::from_seed(&[1; 32], 0, 4).unwrap();
        let keyset = keyset.keyset().unwrap();
        let regtest = ChainProfile::Core30DefaultRegtest;
        let signet = ChainProfile::Core30Signet;
        let mutinynet = ChainProfile::Mutinynet;
        // At the floor's work and at the most a hub asks beyond it.
        let deepest = |profile| {
            let floor = licash_contract::opening::Floors::of(profile).work_depth;
            let timing = Timing::of(profile, None).unwrap();
            (timing.with_work_depth(floor + crate::hub::terms::MAX_EXTRA_WORK)).unwrap()
        };
        let timings = [regtest, signet, mutinynet]
            .into_iter()
            .flat_map(|profile| {
                [
                    (profile, Timing::of(profile, None).unwrap()),
                    (profile, deepest(profile)),
                ]
            });
        for (profile, timing) in timings {
            let checkpoint = Checkpoint::genesis(profile).unwrap();
            let tip = checkpoint.height();
            let quote = timing.quote(keyset.clone(), checkpoint);
            let offer = Offer {
                bounds: timing.bounds(&quote),
                quote,
            };
            offer.quote.check(profile).unwrap();
            // Bounds past any height: refused, never overflowed.
            let mut endless = offer.clone();
            endless.bounds.lock = u32::MAX;
            assert!(wanted(&endless, u32::MAX - 1, u32::MAX).is_err());
            let wanted = wanted(&offer, tip, timing.lock()).unwrap();
            offer.bounds.check(&wanted, tip).unwrap();
            let (g, c) = (&offer.quote.graph, &offer.quote.chain);
            let window = u32::from(wanted.response_window);
            // After the assertion deadline: the hub's challenge, her answer
            // and the delays on what she is paid, whole.
            let after = [g.challenge_window, g.answer_window, g.delta, g.delta_prime];
            let after: u32 = after.map(u32::from).iter().sum();
            let gap = wanted.close_height - wanted.request_height;
            assert!(gap > after, "{profile}: {gap} blocks after asserting");
            // Before it, Base's funding gate: F and a request deep enough,
            // her outputs' delay and the window to respond.
            let delay = u32::from(g.to_self_delay);
            let gate = c.funding_depth + delay + c.work_depth + window + g.deadline_margin;
            assert!(wanted.request_height - tip >= gate, "{profile}");
            // A publication confirmed deep enough within the window.
            assert!(window > u32::from(g.publication_window) + 1, "{profile}");
        }
        // Regtest's as before; signet's 180 blocks after asserting, of
        // its 1 000, and 12 to respond; Mutinynet's the same blocks, of
        // its 1 912.
        let gap = |profile| {
            let timing = Timing::of(profile, None).unwrap();
            let quote = timing.quote(keyset.clone(), Checkpoint::genesis(profile).unwrap());
            (after_assert(&quote), timing.bounds(&quote).response_window)
        };
        assert_eq!(gap(regtest), (AFTER_ASSERT, 2));
        assert_eq!(gap(signet), (180, 12));
        assert_eq!(gap(mutinynet), (180, 12));
        assert!(Timing::of(ChainProfile::Core30Mainnet, None).is_err());
    }

    /// Of terms she chose within the hub's range, the fewest blocks it
    /// lets her ask for and the most leave each window whole too, on a
    /// quote as old as the hub takes one (6 blocks).
    #[cfg(feature = "node")]
    #[test]
    fn her_deadlines_leave_each_window_whole_on_terms_she_chose() {
        use crate::hub::terms::{Range, Timing, CAP};
        let keyset = licash::note::IssuerKeys::from_seed(&[1; 32], 0, 4).unwrap();
        let keyset = keyset.keyset().unwrap();
        let range = Range {
            max_cap: 100_000_000,
            max_blocks: 26_280,
            ppm_year: 10_000,
            ppm_year_funded: 0,
        };
        for profile in [
            ChainProfile::Core30DefaultRegtest,
            ChainProfile::Core30Signet,
            ChainProfile::Mutinynet,
        ] {
            let timing = Timing::of(profile, Some(range)).unwrap();
            let r = timing.range().unwrap();
            let checkpoint = Checkpoint::genesis(profile).unwrap();
            for (cap, blocks) in [
                (CAP, r.min_blocks),
                (16_777_215, 26_280),
                (r.max_cap, r.max_blocks),
            ] {
                let quote = timing.quote_for(keyset.clone(), checkpoint.clone(), cap, blocks, 0);
                quote.check(profile).unwrap();
                let offer = Offer {
                    bounds: timing.bounds(&quote),
                    quote,
                };
                let (g, c) = (&offer.quote.graph, &offer.quote.chain);
                for age in [0, 6] {
                    let tip = checkpoint.height() + age;
                    let wanted = wanted(&offer, tip, blocks).unwrap();
                    offer.bounds.check(&wanted, tip).unwrap();
                    // Her headers reach the assertion deadline.
                    assert!(checkpoint.height() + c.max_headers >= wanted.request_height);
                    let window = u32::from(wanted.response_window);
                    let delay = u32::from(g.to_self_delay);
                    let gate = c.funding_depth + delay + c.work_depth + window + g.deadline_margin;
                    let before = wanted.request_height - tip;
                    assert!(before >= gate, "{profile} {blocks}: {before} blocks");
                }
            }
            // One block fewer than the least leaves less than that.
            assert!(timing.allows(CAP, r.min_blocks - 1).is_err());
        }
    }

    #[tokio::test]
    async fn an_opening_that_cannot_be_loaded_holds_up_no_other() {
        let dir = tempfile::tempdir().unwrap();
        let regtest = ChainProfile::Core30DefaultRegtest;
        let path = dir.path().join("wallet.sqlite");
        let wallet = Wallet::create(&path, &[7; 32], regtest, Nowhere).unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        let new = |id: u8, vout: u32| New {
            id: [id; 32],
            hub: "http://hub.example",
            mock: true,
            deposit: OutPoint {
                txid: Txid::from_byte_array([9; 32]),
                vout,
            },
            value: 60_000,
            price: 23_000,
            cap: 4_096,
            assert_height: 360,
            close_height: 500,
            since: 200,
            state: b"not a state",
        };
        // One she never signed F for, then one she did: neither loads.
        store.insert(&new(1, 0)).unwrap();
        store.insert(&new(2, 1)).unwrap();
        let f = Some(Txid::from_byte_array([8; 32]));
        store.save(&[2; 32], Phase::Funded, f, b"nor this").unwrap();

        let contracts = resume(&wallet, &Tip, &dir.path().join("wallet.sqlite"))
            .await
            .unwrap();
        let of = |id: u8| contracts.iter().find(|c| c.id == [id; 32]).unwrap();
        // The first given up, its coin free again; the other kept as it is.
        let reason = of(1).abandoned.as_deref().unwrap();
        assert!(reason.starts_with("cannot be carried on"), "{reason}");
        assert_eq!(of(2).abandoned, None);
        assert_eq!(of(2).phase, Phase::Funded);
        // Not read again at each sync of the app: one found unreadable
        // is passed over, even one she never signed F for that loading
        // would give up.
        assert!(unreadable().contains(&[2; 32]));
        store.insert(&new(3, 2)).unwrap();
        unreadable().insert([3; 32]);
        let again = resume(&wallet, &Tip, &dir.path().join("wallet.sqlite"))
            .await
            .unwrap();
        assert_eq!(
            again.iter().find(|c| c.id == [3; 32]).unwrap().abandoned,
            None
        );
    }

    /// A chain made up to `tip`, of the fork `fork`, with `f` in the block
    /// at `at` if given: what is broadcast kept, the hashes asked counted.
    struct Fork {
        tip: u32,
        fork: u32,
        f: Option<(u32, Transaction)>,
        asked: std::sync::atomic::AtomicU32,
        sent: std::sync::Mutex<Vec<Transaction>>,
        /// Its blocks' filters, of the coins `spends` its F spends.
        filters: Option<Vec<TxOut>>,
        fetched: std::sync::atomic::AtomicU32,
    }

    impl Fork {
        fn new(tip: u32, fork: u32, f: Option<(u32, &Transaction)>) -> Self {
            Self {
                tip,
                fork,
                f: f.map(|(at, tx)| (at, tx.clone())),
                asked: Default::default(),
                sent: Default::default(),
                filters: None,
                fetched: Default::default(),
            }
        }

        fn filtered(mut self, spends: &[TxOut]) -> Self {
            self.filters = Some(spends.to_vec());
            self
        }

        fn at(&self, height: u32) -> Block {
            let mut header = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
            (header.nonce, header.time) = (height, self.fork);
            // A filter reads the coins a block spends but for its first
            // transaction's, a coinbase's: F comes after one.
            let coinbase = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn::default()],
                output: vec![],
            };
            let txdata = match &self.f {
                Some((at, tx)) if *at == height => vec![coinbase, tx.clone()],
                _ => vec![],
            };
            Block { header, txdata }
        }
    }

    impl Blocks for Fork {
        async fn height(&self) -> Result<u32, String> {
            Ok(self.tip)
        }
        async fn hash(&self, height: u32) -> Result<BlockHash, String> {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match height <= self.tip {
                true => Ok(self.at(height).block_hash()),
                false => Err(format!("no block {height}")),
            }
        }
        async fn filter(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, String> {
            let Some(spends) = &self.filters else {
                return Ok(None);
            };
            let block = (0..=self.tip)
                .map(|h| self.at(h))
                .find(|b| b.block_hash() == *hash);
            let block = block.ok_or_else(|| format!("no block {hash}"))?;
            let filter = bitcoin::bip158::BlockFilter::new_script_filter(&block, |o| {
                let i = (self.f.iter().flat_map(|(_, tx)| &tx.input))
                    .position(|i| i.previous_output == *o)
                    .ok_or(bitcoin::bip158::Error::UtxoMissing(*o))?;
                Ok(spends[i].script_pubkey.clone())
            })
            .map_err(|e| e.to_string())?;
            Ok(Some(filter.content))
        }
        async fn block(&self, hash: &BlockHash) -> Result<Block, String> {
            self.fetched
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            (0..=self.tip)
                .map(|h| self.at(h))
                .find(|b| b.block_hash() == *hash)
                .ok_or_else(|| format!("no block {hash}"))
        }
    }

    impl Chain for Fork {
        async fn checkpoint(&self, _: u32) -> Result<Checkpoint, String> {
            Err("not asked".into())
        }
        async fn broadcast(&self, tx: &Transaction) -> Result<(), String> {
            self.sent.lock().unwrap().push(tx.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_live_f_whose_block_leaves_the_chain_however_deep_is_watched_again() {
        let dir = tempfile::tempdir().unwrap();
        let regtest = ChainProfile::Core30DefaultRegtest;
        let path = dir.path().join("wallet.sqlite");
        let wallet = Wallet::create(&path, &[7; 32], regtest, Nowhere).unwrap();
        let bytes = &crate::testing::opened().holder;
        let ctx = licash_contract::opening::Context {
            tip: 0,
            trust: crate::trust(regtest).unwrap(),
        };
        let holder = Holder::load(bytes, &wallet.contract_secrets().seed, &ctx).unwrap();
        let f = holder.funding().unwrap().tx.clone();
        let id = holder.signed().unwrap().base.parts().nonce;
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store
            .insert(&New {
                id,
                hub: "http://hub.example",
                mock: true,
                deposit: f.input[0].previous_output,
                value: 60_000,
                price: 23_000,
                cap: 4_096,
                assert_height: 300,
                close_height: 500,
                since: 240,
                state: bytes,
            })
            .unwrap();
        store
            .save(&id, Phase::Funded, Some(f.compute_txid()), bytes)
            .unwrap();
        async fn fate_of(
            wallet: &Wallet<Nowhere>,
            chain: &Fork,
            dir: &Path,
            id: [u8; 32],
        ) -> Option<Fate> {
            let all = resume(wallet, chain, dir).await.unwrap();
            all.iter().find(|c| c.id == id).unwrap().fate
        }
        let file = dir.path().join("wallet.sqlite");
        let fate = |chain| fate_of(&wallet, chain, &file, id);

        // Found live by a build before: trusted, its chain not asked.
        store.set_fate(&id, Fate::Live).unwrap();
        let chain = Fork::new(250, 0, Some((247, &f)));
        assert_eq!(fate(&chain).await, Some(Fate::Live));
        assert_eq!(chain.asked.load(std::sync::atomic::Ordering::SeqCst), 0);

        // Found live in its block: followed while that block stands. Of
        // a chain serving filters, only the block spending her coins read.
        store.set_fate(&id, Fate::Open).unwrap();
        let spends = holder.funding().unwrap().prevouts.to_vec();
        let filtered = Fork::new(250, 0, Some((247, &f))).filtered(&spends);
        assert_eq!(fate(&filtered).await, Some(Fate::Live));
        assert_eq!(
            filtered.fetched.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        store.set_fate(&id, Fate::Open).unwrap();
        assert_eq!(fate(&chain).await, Some(Fate::Live));
        let block = (247, chain.at(247).block_hash());
        assert_eq!(store.fate_block(&id).unwrap(), Some(block));
        // Not carried on: F not broadcast again.
        chain.sent.lock().unwrap().clear();
        assert_eq!(fate(&chain).await, Some(Fate::Live));
        assert_eq!(store.fate_block(&id).unwrap(), Some(block));
        assert!(chain.sent.lock().unwrap().is_empty());

        // Its block replaced, F in none: open again, and broadcast again.
        let replaced = Fork::new(250, 1, None);
        assert_eq!(fate(&replaced).await, Some(Fate::Open));
        assert_eq!(store.fate_block(&id).unwrap(), None);
        assert_eq!(*replaced.sent.lock().unwrap(), std::slice::from_ref(&f));

        // Mined again in another block: live, followed there, however
        // deep.
        let again = Fork::new(250, 1, Some((249, &f)));
        assert_eq!(fate(&again).await, Some(Fate::Live));
        let block = (249, again.at(249).block_hash());
        assert_eq!(store.fate_block(&id).unwrap(), Some(block));
        let buried = Fork::new(270, 1, Some((249, &f)));
        assert_eq!(fate(&buried).await, Some(Fate::Live));
        assert_eq!(store.fate_block(&id).unwrap(), Some(block));
        // A reorganization deeper than any expected: open again, found
        // anew.
        let deep = Fork::new(280, 2, None);
        assert_eq!(fate(&deep).await, Some(Fate::Open));
        assert_eq!(store.fate_block(&id).unwrap(), None);
    }

    /// The chain `from`, become `to` once a block spending a coin is read
    /// from it: a reorganization in the middle of a scan.
    struct Reorganizing {
        from: Fork,
        to: Fork,
        moved: std::sync::atomic::AtomicBool,
    }

    impl Reorganizing {
        fn now(&self) -> &Fork {
            match self.moved.load(std::sync::atomic::Ordering::SeqCst) {
                true => &self.to,
                false => &self.from,
            }
        }
    }

    impl Blocks for Reorganizing {
        async fn height(&self) -> Result<u32, String> {
            self.now().height().await
        }
        async fn hash(&self, height: u32) -> Result<BlockHash, String> {
            self.now().hash(height).await
        }
        async fn filter(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, String> {
            self.now().filter(hash).await
        }
        async fn block(&self, hash: &BlockHash) -> Result<Block, String> {
            let block = self.now().block(hash).await?;
            if block.txdata.len() > 1 {
                self.moved.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(block)
        }
    }

    impl Chain for Reorganizing {
        async fn checkpoint(&self, _: u32) -> Result<Checkpoint, String> {
            Err("not asked".into())
        }
        async fn broadcast(&self, _: &Transaction) -> Result<(), String> {
            Err("not asked".into())
        }
    }

    #[tokio::test]
    async fn a_chain_reorganized_while_scanned_gives_f_no_fate() {
        let dir = tempfile::tempdir().unwrap();
        let regtest = ChainProfile::Core30DefaultRegtest;
        let wallet = Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[7; 32],
            regtest,
            Nowhere,
        )
        .unwrap();
        let ctx = licash_contract::opening::Context {
            tip: 0,
            trust: crate::trust(regtest).unwrap(),
        };
        let bytes = &crate::testing::opened().holder;
        let holder = Holder::load(bytes, &wallet.contract_secrets().seed, &ctx).unwrap();
        let f = holder.funding().unwrap().tx.clone();
        // Another transaction spending F's coins.
        let mut conflict = f.clone();
        conflict.lock_time = bitcoin::absolute::LockTime::from_height(1).unwrap();
        assert_ne!(conflict.compute_txid(), f.compute_txid());

        // Each chain alone: dead on the one, live on the other.
        let fate_on = |chain: Fork| {
            let holder = &holder;
            async move {
                chain::fate(holder, &chain, 240)
                    .await
                    .unwrap()
                    .map(|(f, _)| f)
            }
        };
        let dead = Fork::new(250, 0, Some((247, &conflict)));
        assert_eq!(fate_on(dead).await, Some(Fate::Dead));
        let live = Fork::new(250, 1, Some((247, &f)));
        assert_eq!(fate_on(live).await, Some(Fate::Live));

        // The conflict read on the one, the rest on the other: no fate of
        // either, refused, to be looked at again.
        let chain = Reorganizing {
            from: Fork::new(250, 0, Some((247, &conflict))),
            to: Fork::new(250, 1, Some((247, &f))),
            moved: Default::default(),
        };
        let e = chain::fate(&holder, &chain, 240).await.unwrap_err();
        assert!(chain.moved.load(std::sync::atomic::Ordering::SeqCst));
        assert!(e.to_string().contains("reorganized"), "{e}");
    }
}
