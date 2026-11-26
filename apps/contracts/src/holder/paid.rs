//! Openings paid for with notes, for a wallet with no coin of its own, in
//! two steps: a swap provider pays her own fallback address a coin worth
//! the contract's price and a small part of it hers ([`PART`]; the hub
//! funds the rest), for notes she locks to it at a hub, its own or another
//! (notes from Lightning first received as any). Once her claim of that
//! coin is buried, the contract opens on it as on any coin of hers. Each
//! step is the usual one: should the opening fail, she keeps the coin.
//!
//! [`coin`] says what coin to pay for, [`pay`] keeps the opening, then
//! makes the payout (of a quote the caller asked, of a provider it chose
//! or found announced); [`super::resume`]
//! carries it on (`carry_on`): it follows the payout, finds its coin
//! among her wallet's, and opens the contract on it.

use std::path::Path;

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use licash_wallet::{
    Error as WalletError, PayoutQuote, PayoutState, Transport, Wallet, PAYOUT_WINDOW,
};

use super::chain::Chain;
use super::store::Store;
use super::{fees, fit, fundable, funding_notes, offer, open_at, Ask, Fit, Pricing, RESUMES};

/// Her part of a contract paid for with notes, in sat, at least: what the
/// coin holds beyond the price. Room for her claim of it to pay a higher
/// fee than budgeted, the coin then worth less, and still fit a contract:
/// the hub funds the rest of its cap.
pub const PART: u64 = 1_000;

/// A coin to pay for, to open a contract on ([`coin`]): what it is worth,
/// paid to her wallet's own address, and the contract it fits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub hub: String,
    pub ask: Ask,
    /// What the coin is worth: the price and her part.
    pub value: u64,
    pub price: u64,
    pub fit: Fit,
    /// Her wallet's own address, the coin's.
    pub to: String,
}

/// An opening paid for: the payout's ticket, and the contract it pays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paid {
    pub ticket: String,
    /// What the coin is worth: the price and her part.
    pub value: u64,
    pub price: u64,
    pub fit: Fit,
}

pub use super::store::PaidRow;

/// The openings paid for kept in `wallet_file`, the oldest first, those over
/// with why ([`PaidRow::ended`]).
pub fn list(wallet_file: &Path) -> Result<Vec<PaidRow>> {
    match Store::existing(wallet_file)? {
        Some(store) => store.paid(),
        None => Ok(Vec::new()),
    }
}

/// How many times an opening on a coin paid for fails before it is left
/// to her: the coin is hers, to open with by hand.
const TRIES: u32 = 3;

/// Blocks of the chain looked in for the coin at most, each time an opening
/// paid for is carried on: its claim is in one of the last few.
const SCAN: u32 = 144;

/// The coin to pay for to open a contract at `hub` as `ask`ed, but for its
/// deposit (that coin): the smallest contract of `ask`'s cap at least, her
/// part of it [`PART`], more for the coin to be worth `floor` at least (the
/// least a provider pays out). Refused at a hub charging more than is sane,
/// or pricing it beyond `ask.max_price`. A payout of [`Coin::value`] to
/// [`Coin::to`] pays for it ([`pay`]).
pub async fn coin<T: Transport>(
    wallet: &Wallet<T>,
    hub: &str,
    ask: Ask,
    floor: u64,
) -> Result<Coin> {
    let planned = |pricing: &Pricing, dust: u64, notes: (&[u64], usize), least: u32| {
        plan(
            pricing,
            ask.blocks,
            dust,
            notes,
            (least, ask.inbound, floor),
        )
    };
    sized(wallet, hub, ask, planned).await
}

/// The coin of [`coin`], worth `value` exactly, as quoted before: the
/// contract it fits now ([`fit`]), refused if none of `ask`'s cap. Of the
/// same terms, the same contract as quoted, whatever the least a provider
/// pays out is now.
pub async fn coin_worth<T: Transport>(
    wallet: &Wallet<T>,
    hub: &str,
    ask: Ask,
    value: u64,
) -> Result<Coin> {
    let fitted = |pricing: &Pricing, dust: u64, notes: (&[u64], usize), least: u32| {
        fit(pricing, ask.blocks, value, dust, notes, least, ask.inbound)
            .map(|fitted| (value, fitted))
    };
    sized(wallet, hub, ask, fitted).await
}

/// The coin to pay for to open a contract at `hub` as `ask`ed, of the value
/// and contract `size` chooses of its terms: of its pricing, dust, funding
/// notes and least cap.
async fn sized<T: Transport>(
    wallet: &Wallet<T>,
    hub: &str,
    ask: Ask,
    size: impl FnOnce(&Pricing, u64, (&[u64], usize), u32) -> Option<(u64, Fit)>,
) -> Result<Coin> {
    ensure!(
        ask.deposit.is_none(),
        "a coin paid for is the deposit: none other to name"
    );
    let hub = hub.trim_end_matches('/').to_owned();
    ensure!(
        wallet.hubs()?.iter().any(|(url, _)| *url == hub),
        "{hub} is no hub this wallet trusts"
    );
    let now = wallet.hub_info(&hub).await;
    let now = now.map_err(|e| anyhow!("{hub}'s fees: {e}"))?;
    let range = now.contracts.and_then(|c| c.range);
    // Its cost is not judged against the coin ([`fees::costly`]): a coin
    // paid for may be its price and a little of her own, the hub funding
    // the rest, and costs what she was quoted at most ([`ceiling`]).
    if let Some(why) = fees::abusive(&now.fees) {
        bail!("{hub} charges more than is sane, {why}: no contract opens there");
    }
    ensure!(
        now.deposits.is_some(),
        "{hub} takes no deposits, which her reserve returns to: no contract opens there"
    );
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
    let notes = (&denominations[..], notes);
    let (value, fitted) = size(&pricing, dust, notes, least)
        .context("no contract of this hub to pay for: none of the cap asked")?;
    let price = pricing.price(fitted.cap, ask.blocks, fitted.funded);
    ensure!(
        price <= ask.max_price,
        "{hub} asks {price} sat to open, more than {}",
        ask.max_price
    );
    Ok(Coin {
        hub,
        ask,
        value,
        price,
        fit: fitted,
        to: wallet.fallback_address()?.to_string(),
    })
}

/// Pay for `coin` as `quote` says, a payout of its value to its address:
/// the opening kept in `wallet_file` before the payout is made, opened by
/// [`super::resume`] once the coin is her wallet's.
pub async fn pay<T: Transport>(
    wallet: &Wallet<T>,
    wallet_file: &Path,
    coin: &Coin,
    quote: &PayoutQuote,
) -> Result<Paid> {
    ensure!(
        quote.amount == coin.value && quote.address == coin.to,
        "a payout of {} sat to {}, not the coin's {} to {}",
        quote.amount,
        quote.address,
        coin.value,
        coin.to
    );
    let store = Store::open(wallet_file)?;
    let ask = &coin.ask;
    // Its cap as planned, the inbound asked in it: the opening, carried on,
    // asks that cap and no inbound more.
    store.insert_paid(
        &quote.ticket,
        &coin.hub,
        (ask.blocks, ceiling(ask, coin.price), Some(coin.fit.cap)),
        coin.value,
    )?;
    tracing::info!(
        ticket = %quote.ticket, hub = %coin.hub, provider = %quote.provider, from = %quote.from,
        value = coin.value, price = coin.price, funded = coin.fit.funded, costs = quote.costs(),
        "paying for a contract's coin with notes"
    );
    wallet
        .payout(quote)
        .await
        .map_err(|e| anyhow!("paying for the coin: {e}"))?;
    Ok(Paid {
        ticket: quote.ticket.clone(),
        value: coin.value,
        price: coin.price,
        fit: coin.fit,
    })
}

/// The most a contract opened on a coin paid for at `price` may cost, as
/// `ask`ed: her own ceiling, or with none that price, quoted to her before
/// she paid. Never none: a coin paid for is judged by what she accepted,
/// not by what is sane of it ([`fees::costly`]), which it may well be
/// past, its price and a little of hers.
fn ceiling(ask: &Ask, price: u64) -> u64 {
    if ask.max_price == u64::MAX {
        price
    } else {
        ask.max_price
    }
}

/// The coin to pay for, and the contract it fits ([`fit`]): her part
/// [`PART`] at least, the cap the smallest of it and `inbound` sat more,
/// `least` at least, that a coin of its price and her part fits whole; her
/// part more if the hub takes contracts of so many times a coin at most
/// and the cap needs it, or for the coin to be worth `floor` at least.
fn plan(
    pricing: &Pricing,
    blocks: u32,
    dust: u64,
    (denominations, notes): (&[u64], usize),
    (least, inbound, floor): (u32, u32, u64),
) -> Option<(u64, Fit)> {
    let makes = |f: u64| fundable(denominations, notes, f) == f;
    let mut funded = PART;
    for _ in 0..PLANS {
        while funded <= u64::from(licash_api::MAX_CAP) && !makes(funded) {
            funded += 1;
        }
        let part = u32::try_from(funded).ok()?;
        let cap = pricing.cap_for(u64::MAX, funded + u64::from(inbound), least)?;
        // The least coin a contract of this cap takes.
        let needed = match pricing {
            Pricing::Range(range) if cap != range.min_cap => {
                u64::from(cap).div_ceil(u64::from(range.per_coin.max(1)))
            }
            _ => 0,
        };
        let needed = needed.max(floor);
        let value = funded + pricing.price(cap, blocks, part);
        if value < needed {
            funded += needed - value;
            continue;
        }
        // As the opening fits it.
        match fit(
            pricing,
            blocks,
            value,
            dust,
            (denominations, notes),
            least,
            inbound,
        ) {
            Some(fitted) => return Some((value, fitted)),
            None => funded += 1,
        }
    }
    None
}

/// How many parts of hers are tried, each the next she may fund: the
/// price falling as her part rises, and the cap rising with it, are all
/// that moves them.
const PLANS: usize = 64;

/// Carry on with the openings paid for in `store`, at `tip`: follow each
/// payout, its claim broadcast, and open the contract on its coin once it
/// is hers; end those whose payout or opening is over.
pub(super) async fn carry_on<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &Path,
    store: &Store,
) {
    let open: Vec<PaidRow> = match store.paid() {
        Ok(paid) => paid.into_iter().filter(|p| p.ended.is_none()).collect(),
        Err(e) => {
            tracing::warn!("openings paid for with notes: {e:#}");
            return;
        }
    };
    for row in &open {
        if let Err(e) = carry_on_one(wallet, chain, wallet_file, store, row).await {
            tracing::warn!(ticket = %row.ticket, "an opening paid for with notes: {e:#}");
        }
    }
}

async fn carry_on_one<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &Path,
    store: &Store,
    row: &PaidRow,
) -> Result<()> {
    let ticket = &row.ticket;
    // Kept, then never paid: the quote's preimage was in memory only.
    if !wallet.payouts()?.iter().any(|p| p.hash == *ticket) {
        store.end_paid(ticket, "its payout was never made")?;
        return Ok(());
    }
    let followed = wallet.follow_payout(ticket, chain).await;
    // Its claim out, should the coin be claimed now.
    for claim in wallet.payout_claims()? {
        if let Err(e) = chain.broadcast(&claim).await {
            tracing::debug!(txid = %claim.compute_txid(), "a payout's claim: {e}");
        }
    }
    let payout = match followed {
        Ok(payout) => payout,
        Err(WalletError::Pending { reason, .. }) => {
            tracing::debug!(%ticket, reason, "an opening paid for with notes waits for its coin");
            return Ok(());
        }
        Err(e) => return Err(anyhow!("following its payout: {e}")),
    };
    match &payout.state {
        PayoutState::Failed(why) => {
            store.end_paid(ticket, &format!("its payout failed: {why}"))?;
            return Ok(());
        }
        PayoutState::Done => {}
        _ => return Ok(()),
    }
    let claim = payout.claim.context("a payout done with no claim")?;
    let Some(coin) = found(wallet, chain, ticket, claim).await? else {
        tracing::info!(%ticket, %claim, "a coin paid for with notes not found yet");
        return Ok(());
    };
    if coin.spending.is_some() {
        store.end_paid(ticket, "its coin was spent otherwise")?;
        return Ok(());
    }
    // An opening on it already, made before a restart: carried on as any.
    if store.list()?.iter().any(|c| c.deposit == coin.outpoint) {
        store.end_paid(ticket, "opened")?;
        return Ok(());
    }
    let ask = Ask {
        blocks: row.blocks,
        max_price: row.max_price,
        cap: row.cap,
        inbound: 0,
        deposit: Some(coin.outpoint),
    };
    match open_at(wallet, chain, wallet_file, &row.hub, ask, true, RESUMES).await {
        Ok(contract) => {
            let id = crate::hex_id(&contract.id);
            tracing::info!(%ticket, %id, coin = %coin.outpoint, "opened on a coin paid for with notes");
            store.end_paid(ticket, "opened")?;
        }
        Err(e) => {
            let tries = store.paid_tried(ticket)?;
            tracing::warn!(%ticket, tries, "opening on a coin paid for with notes: {e:#}");
            if tries >= TRIES {
                let why = format!("not opened: {e:#}: its coin {} kept", coin.outpoint);
                store.end_paid(ticket, &why)?;
            }
        }
    }
    Ok(())
}

/// The coin the claim `claim` of the payout `ticket` paid her, once her
/// wallet found it: looked for in the blocks since it last looked, from the
/// coin's window on in a wallet that never looked for its coins.
async fn found<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    ticket: &str,
    claim: bitcoin::Txid,
) -> Result<Option<licash_wallet::SilentCoin>> {
    let mine = |wallet: &Wallet<T>| -> Result<Option<licash_wallet::SilentCoin>> {
        let coins = wallet.silent_coins()?;
        Ok(coins.into_iter().find(|c| c.outpoint.txid == claim))
    };
    if let Some(coin) = mine(wallet)? {
        return Ok(Some(coin));
    }
    if wallet.silent_next()?.is_none() {
        // Its coin is in no block before its window.
        let timeout = wallet.payout_progress(ticket)?.timeout;
        let from = timeout.map_or(0, |t| t.saturating_sub(2 * PAYOUT_WINDOW));
        wallet.watch_silent(None, from)?;
    }
    let scanned = wallet.scan_silent(None, chain, SCAN).await;
    scanned.map_err(|e| anyhow!("looking for its coin: {e}"))?;
    mine(wallet)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A coin paid for opens at her ceiling at most, or with none at the
    /// price quoted: never unbounded, which would judge it by what is sane
    /// of it after it was paid for.
    #[test]
    fn a_coin_paid_for_opens_at_her_ceiling_or_its_quoted_price() {
        let ask = |max_price| Ask {
            blocks: 1_000,
            max_price,
            cap: None,
            inbound: 0,
            deposit: None,
        };
        assert_eq!(ceiling(&ask(u64::MAX), 31_000), 31_000);
        assert_eq!(ceiling(&ask(40_000), 31_000), 40_000);
        assert_eq!(ceiling(&ask(30_000), 31_000), 30_000);
    }

    /// The coin paid for is the price and her part, of the smallest
    /// contract: the hub funds the rest.
    #[test]
    fn a_coin_paid_for_is_the_price_and_her_part_of_the_smallest_contract() {
        let wide: Vec<u64> = (0..32).map(|i| 1 << i).collect();
        let fixed = Pricing::Fixed {
            cap: 3_584,
            price: 21_000,
        };
        let (value, fitted) = plan(&fixed, 1_000, 330, (&wide, 32), (0, 0, 0)).unwrap();
        let part = PART as u32;
        assert_eq!(
            (value, fitted),
            (
                21_000 + PART,
                Fit {
                    cap: 3_584,
                    funded: part
                }
            )
        );
        // Notes of 16 sat at the least: her part the next they make.
        let coarse: Vec<u64> = (4..32).map(|i| 1 << i).collect();
        let (value, fitted) = plan(&fixed, 1_000, 330, (&coarse, 32), (0, 0, 0)).unwrap();
        assert_eq!((value, fitted.funded), (21_008 + PART, part + 8));

        let range = range();
        let pricing = Pricing::Range(&range);
        let (value, fitted) = plan(&pricing, 52_560, 330, (&wide, 32), (0, 0, 0)).unwrap();
        assert_eq!(
            (fitted.cap, u64::from(fitted.funded)),
            (range.min_cap, PART)
        );
        let pays = u64::from(fitted.funded) + range.price(fitted.cap, 52_560, fitted.funded);
        assert!(value - pays < 330, "{value} for {pays}");
        // Of a larger cap asked: the smallest of it at least, the coin
        // large enough for it.
        let (value, larger) = plan(&pricing, 52_560, 330, (&wide, 32), (200_000, 0, 0)).unwrap();
        assert!(larger.cap >= 200_000);
        assert!(value * u64::from(range.per_coin) >= u64::from(larger.cap));
    }

    /// A provider paying out no coin as small as the price and her part:
    /// the coin worth its least, the rest her part, of the same contract.
    /// On Mutinynet one paid out 31,760 sat at least, not 24,466.
    #[test]
    fn a_coin_paid_for_is_worth_the_least_a_provider_pays_out() {
        let wide: Vec<u64> = (0..32).map(|i| 1 << i).collect();
        let range = range();
        let pricing = Pricing::Range(&range);
        let (usual, planned) = plan(&pricing, 52_560, 330, (&wide, 32), (0, 0, 0)).unwrap();
        let floor = usual + 7_294;
        let (value, fitted) = plan(&pricing, 52_560, 330, (&wide, 32), (0, 0, floor)).unwrap();
        assert!(value >= floor && value - floor < 330, "{value} for {floor}");
        assert_eq!(fitted.cap, planned.cap);
        assert!(fitted.funded > planned.funded + 7_000, "{fitted:?}");
        assert_eq!(
            fit(&pricing, 52_560, value, 330, (&wide, 32), 0, 0),
            Some(fitted)
        );
        // A floor below the usual coin changes nothing.
        let lower = plan(&pricing, 52_560, 330, (&wide, 32), (0, 0, usual - 1));
        assert_eq!(lower, Some((usual, planned)));
        let fixed = Pricing::Fixed {
            cap: 3_584,
            price: 21_000,
        };
        let (value, fitted) = plan(&fixed, 1_000, 330, (&wide, 32), (0, 0, 23_000)).unwrap();
        assert_eq!((value, fitted.funded), (23_000, 2_000));
        // Her part larger than the contract: none to pay for.
        assert_eq!(plan(&fixed, 1_000, 330, (&wide, 32), (0, 0, 25_000)), None);
    }

    /// A claim paying a higher fee than budgeted leaves her a coin worth
    /// less than paid for: still a contract of the same cap, her part less.
    /// Bumped by about all of her part, it fits none: the coin is hers.
    #[test]
    fn a_coin_paid_for_fits_its_contract_however_its_claim_was_bumped() {
        let wide: Vec<u64> = (0..32).map(|i| 1 << i).collect();
        let range = range();
        let pricing = Pricing::Range(&range);
        let (value, planned) = plan(&pricing, 52_560, 330, (&wide, 32), (0, 0, 0)).unwrap();
        // The hub's interest rising as her part falls: a little less than
        // her part is room to spare.
        for less in [1, 100, PART / 2] {
            let fitted = fit(&pricing, 52_560, value - less, 330, (&wide, 32), 0, 0).unwrap();
            assert_eq!(fitted.cap, planned.cap, "{less} sat less");
            assert!(fitted.funded < planned.funded);
        }
        assert_eq!(
            fit(&pricing, 52_560, value - PART, 330, (&wide, 32), 0, 0),
            None
        );
    }
}
