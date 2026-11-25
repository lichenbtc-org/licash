//! `licash-wallet payout` and `payouts`: notes paid out to an address on
//! Bitcoin through a swap provider, which locks a coin on chain for the
//! wallet's lock, and the wallet's claims of those coins.

use anyhow::{bail, Context};
use bitcoin::FeeRate;
use licash_chain_client::Source;
use licash_nostr::{
    wallet::{payout_providers, Announcements},
    Route,
};
use licash_transport::Http;
use licash_wallet::{Payout, PayoutQuote, PayoutState, Wallet};
use serde_json::json;

use crate::{onchain, show};

/// The payout's costs at most on top of its amount by default: 1% and
/// this, room for the coin's claim at a few times the fee rate.
pub(crate) const USUAL_MAX_FEE: u64 = 2_000;

pub(crate) fn source(chain: &str) -> anyhow::Result<Source> {
    chain.parse().context("--chain")
}

/// The provider to pay out through: at its URL, or the one announced on
/// relays, reached through a route, asking least.
pub enum Provider {
    At(String),
    Announced(Vec<String>, Route),
}

/// Pay `amount` to `to` from notes at `from` through `provider`, the
/// claim budgeted at `fee_rate` or the chain's estimate, and take the
/// payout on once.
pub async fn pay(
    wallet: &Wallet<Http>,
    chain: &str,
    (provider, from, to): (Provider, &str, &str),
    amount: u64,
    (max_fee, fee_rate): (Option<u64>, Option<u64>),
    json: bool,
) -> anyhow::Result<()> {
    let source = source(chain)?;
    let rate = onchain::rate(&source, fee_rate).await?;
    let max_fee = max_fee.unwrap_or(amount / 100 + USUAL_MAX_FEE);
    let quote = quote(wallet, provider, (from, to), amount, (max_fee, rate), json).await?;
    let payout = match wallet.payout(&quote).await {
        // Asked again, its fee risen: quoted again within it, if accepted.
        Err(e @ licash_wallet::Error::FeeRose { .. }) => {
            let max_fee = crate::accept_raise(e, json)?;
            let (provider, from) = (&quote.provider, &quote.from);
            let again = wallet.payout_quote(provider, from, to, amount, max_fee, rate);
            wallet.payout(&again.await?).await?
        }
        payout => payout?,
    };
    if let PayoutState::Failed(reason) = &payout.state {
        show(json, payout_json(&payout), payout_line(&payout));
        bail!("the payout failed ({reason}): its lock, if made, returns once expired");
    }
    let payout = follow(wallet, &source, &payout.hash).await?;
    show(
        json,
        payout_json(&payout),
        format!(
            "{}\nfollow it with `licash-wallet payouts --chain` until done",
            payout_line(&payout)
        ),
    );
    Ok(())
}

/// The quote of paying `amount` to `to` from notes at `from` through
/// `provider`, within `max_fee`, the claim budgeted at `rate`: a provider's
/// at its URL asked again within a risen fee, if accepted.
pub(crate) async fn quote(
    wallet: &Wallet<Http>,
    provider: Provider,
    (from, to): (&str, &str),
    amount: u64,
    (max_fee, rate): (u64, FeeRate),
    json: bool,
) -> anyhow::Result<PayoutQuote> {
    Ok(match provider {
        Provider::At(url) => {
            let quoting = |max_fee| wallet.payout_quote(&url, from, to, amount, max_fee, rate);
            match quoting(max_fee).await {
                Err(e @ licash_wallet::Error::FeeRose { .. }) => {
                    quoting(crate::accept_raise(e, json)?).await?
                }
                quote => quote?,
            }
        }
        Provider::Announced(relays, route) => {
            let relays = relays_or_hubs(wallet, relays)?;
            let limits = (max_fee, rate);
            let found = payout_providers(wallet, &relays, &route, (from, to), amount, limits);
            let found = found.await?.into_iter().next().with_context(|| {
                format!("no provider announced pays {amount} out from {from} within --max-fee")
            })?;
            let (costs, known) = (found.quote.costs(), found.known);
            tracing::info!(provider = %found.url, costs, known, "provider found");
            found.quote
        }
    })
}

/// The least `provider` pays out to `to`, the wallet's own, from notes at
/// `from`, the claim budgeted at `rate` ([`Wallet::payout_least`]): of
/// those announced, the least any does. A payout to herself raised to it
/// is one a provider makes, as one of what she needs may not be: a coin of
/// a contract's price and her part was refused on Mutinynet, its smallest
/// coin risen with fees. None if no provider says.
pub(crate) async fn least(
    wallet: &Wallet<Http>,
    provider: &Provider,
    (from, to): (&str, &str),
    rate: FeeRate,
) -> anyhow::Result<Option<u64>> {
    let infos = match provider {
        Provider::At(url) => vec![wallet.provider_info(url).await?],
        Provider::Announced(relays, route) => {
            let relays = relays_or_hubs(wallet, relays.clone())?;
            let announced = Announcements::default();
            (announced.refresh(&relays, route, wallet.network().name())).await?;
            announced.infos(wallet, &relays).await?
        }
    };
    let mut least = None;
    for info in &infos {
        if let Some(one) = wallet.payout_least(info, from, to, rate)? {
            least = Some(least.map_or(one, |l: u64| l.min(one)));
        }
    }
    Ok(least)
}

/// `relays`, or those the trusted hubs name if none: refused if neither.
fn relays_or_hubs(wallet: &Wallet<Http>, relays: Vec<String>) -> anyhow::Result<Vec<String>> {
    let relays = match relays {
        relays if !relays.is_empty() => relays,
        _ => licash_nostr::wallet::hub_relays(wallet)?,
    };
    if relays.is_empty() {
        bail!("no relay to find a provider on: name one with --relay, or a provider");
    }
    Ok(relays)
}

/// Take the payout `hash` on, then broadcast the wallet's claims.
async fn follow(wallet: &Wallet<Http>, source: &Source, hash: &str) -> anyhow::Result<Payout> {
    let blocks = onchain::Blocks(source.clone());
    let followed = wallet.follow_payout(hash, &blocks).await;
    broadcast(wallet, source).await?;
    match followed {
        Ok(payout) => Ok(payout),
        Err(licash_wallet::Error::Pending { reason, .. }) => {
            tracing::info!(hash, reason, "payout pending");
            let payouts = wallet.payouts()?;
            Ok(payouts
                .into_iter()
                .find(|p| p.hash == hash)
                .context("the payout is not recorded")?)
        }
        Err(e) => Err(e.into()),
    }
}

/// Broadcast the claims of payouts not done: one the chain refuses is
/// broadcast again next time, as its coin may not be in the chain's view
/// yet.
async fn broadcast(wallet: &Wallet<Http>, source: &Source) -> anyhow::Result<()> {
    for claim in wallet.payout_claims()? {
        match source.broadcast(&claim).await {
            Ok(txid) => tracing::info!(%txid, "claim broadcast"),
            Err(e) => tracing::warn!(txid = %claim.compute_txid(), "claim not broadcast: {e:#}"),
        }
    }
    Ok(())
}

/// Take the payouts under way on, on `source`, and broadcast their claims.
pub async fn follow_all(wallet: &Wallet<Http>, source: &Source) -> anyhow::Result<()> {
    let (_, pending) = wallet
        .follow_payouts(&onchain::Blocks(source.clone()))
        .await?;
    for (hash, reason) in pending {
        tracing::info!(hash, reason, "payout pending");
    }
    broadcast(wallet, source).await
}

/// Pay `amount` out of notes at the richest hub to the wallet's own silent
/// payment address, through the provider announced on its hubs' relays,
/// reached through `route`, asking least within the usual fees: a coin for
/// a forced close's fees. Its claim made as the payouts are followed.
pub async fn for_fees(
    wallet: &Wallet<Http>,
    route: &Route,
    amount: u64,
    rate: bitcoin::FeeRate,
    record: impl FnOnce(&str) -> anyhow::Result<()>,
) -> anyhow::Result<Payout> {
    let balance = wallet.balance()?;
    let from = fees_from(balance.clone(), amount)?;
    let to = wallet.silent_keys().address().to_string();
    // As much as a provider pays out at least: the rest comes back as
    // change.
    let announced = Provider::Announced(Vec::new(), route.clone());
    let least = least(wallet, &announced, (&from, &to), rate).await?;
    let amount = amount.max(least.unwrap_or(0));
    fees_from(balance, amount)?;
    let max_fee = amount / 100 + USUAL_MAX_FEE;
    let limits = (max_fee, rate);
    recorded(wallet, route, (&from, &to), amount, limits, record).await
}

/// The hub to pay `amount` out of for a forced close's fees: the one
/// holding most, refused before a provider is asked or a payout recorded
/// if it holds less than `amount`, as a wallet whose notes are all spent
/// would on every run, a failed payout made each time.
fn fees_from(balance: Vec<licash_wallet::Balance>, amount: u64) -> anyhow::Result<String> {
    let richest = balance.into_iter().max_by_key(|b| b.available);
    let richest = richest.context("no hub to pay at: `licash-wallet add-hub URL` trusts one")?;
    if richest.available < amount {
        bail!(
            "{} needed, {} available at {}, the most at any hub",
            crate::say::sat(amount),
            crate::say::sat(richest.available),
            richest.hub
        );
    }
    Ok(richest.hub)
}

/// Pay `amount` out of notes at `from` to `to` through the provider
/// announced on the wallet's hubs' relays, reached through `route`, asking
/// least within `max_fee`, its claim budgeted at `rate`; refused if it
/// failed at once. Its claim made as the payouts are followed.
pub async fn announced(
    wallet: &Wallet<Http>,
    route: &Route,
    (from, to): (&str, &str),
    amount: u64,
    limits: (u64, bitcoin::FeeRate),
) -> anyhow::Result<Payout> {
    recorded(wallet, route, (from, to), amount, limits, |_| Ok(())).await
}

/// [`announced`], `record` told the payout's hash before it is made: none
/// made unless recorded.
async fn recorded(
    wallet: &Wallet<Http>,
    route: &Route,
    (from, to): (&str, &str),
    amount: u64,
    (max_fee, rate): (u64, bitcoin::FeeRate),
    record: impl FnOnce(&str) -> anyhow::Result<()>,
) -> anyhow::Result<Payout> {
    let relays = licash_nostr::wallet::hub_relays(wallet)?;
    if relays.is_empty() {
        bail!("no hub trusted names relays to find a swap provider on");
    }
    let limits = (max_fee, rate);
    let found = payout_providers(wallet, &relays, route, (from, to), amount, limits);
    let found = found.await?.into_iter().next().with_context(|| {
        format!("no provider announced pays {amount} out from {from} within {max_fee} sat of fees")
    })?;
    record(&found.quote.ticket)?;
    let payout = wallet.payout(&found.quote).await?;
    if let PayoutState::Failed(reason) = &payout.state {
        bail!("the payout failed ({reason}): its lock, if made, returns once expired");
    }
    Ok(payout)
}

/// The payouts, newest first: taken on first with `chain`, their claims
/// broadcast.
pub async fn list(wallet: &Wallet<Http>, chain: Option<&str>, json: bool) -> anyhow::Result<()> {
    if let Some(chain) = chain {
        follow_all(wallet, &source(chain)?).await?;
    }
    let payouts = wallet.payouts()?;
    let lines: Vec<String> = payouts.iter().map(payout_line).collect();
    show(
        json,
        payouts.iter().map(payout_json).collect(),
        lines.join("\n"),
    );
    Ok(())
}

fn state(state: &PayoutState) -> String {
    match state {
        PayoutState::Open => "open".into(),
        PayoutState::Claimed => "claimed".into(),
        PayoutState::Done => "done".into(),
        PayoutState::Failed(reason) => format!("failed ({reason})"),
        _ => "unknown".into(),
    }
}

fn payout_json(payout: &Payout) -> serde_json::Value {
    json!({
        "hash": payout.hash, "provider": payout.provider, "from": payout.from,
        "address": payout.address, "amount": payout.amount, "budget": payout.budget,
        "fee": payout.fee, "lock": payout.lock,
        "funding": payout.funding.map(|o| o.to_string()),
        "claim": payout.claim.map(|t| t.to_string()),
        "state": state(&payout.state), "created_at": payout.created_at,
    })
}

fn payout_line(payout: &Payout) -> String {
    format!(
        "{}  payout {}  {}  {} → {}  {}",
        crate::say::when(payout.created_at),
        state(&payout.state),
        crate::say::plus(payout.amount, payout.budget + payout.fee),
        payout.from,
        payout.address,
        payout.hash
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use licash_wallet::Balance;

    fn at(hub: &str, available: u64) -> Balance {
        Balance {
            hub: hub.into(),
            available,
            pending: 0,
        }
    }

    /// A forced close's fees are paid out of the hub holding most, and
    /// asked of no provider when it holds less than they need: a wallet
    /// whose notes are spent once made a failed payout on every run.
    #[test]
    fn fees_are_paid_out_of_the_richest_hub_or_not_asked_for() {
        let two = vec![at("http://a.test", 30_000), at("http://b.test", 50_000)];
        assert_eq!(fees_from(two.clone(), 42_000).unwrap(), "http://b.test");
        assert_eq!(fees_from(two.clone(), 50_000).unwrap(), "http://b.test");
        let short = fees_from(two, 50_001).unwrap_err().to_string();
        assert!(
            short.contains("50,000 sat available at http://b.test"),
            "{short}"
        );
        assert!(fees_from(vec![at("http://a.test", 0)], 42_000).is_err());
        assert!(fees_from(Vec::new(), 42_000).is_err());
    }
}
