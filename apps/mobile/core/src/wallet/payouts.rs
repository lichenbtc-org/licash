//! Notes paid out to addresses on Bitcoin through swap providers announced
//! on Nostr: how the app pays an address, or cashes out a hub's notes.

use std::sync::Arc;

use bitcoin::FeeRate;
use licash_nostr::wallet::{hub_relays, payout_providers_with};
use licash_transport::Http;
use licash_wallet::{payout_depth, LockState, Payout, PayoutProgress, PayoutState};

use super::Wallet;
use crate::{
    chain::Chain, Activity, ChainSource, Details, Kind, LicashError, LockStep, PayoutQuote,
    PayoutSteps, State,
};

/// The fee rate a claim confirms at soon, in sat/vB, as the app judges it
/// knowing no estimates: a claim is budgeted at a few times this or the
/// provider's rate, the higher.
const CLAIM_RATE: u64 = 2;

/// Quotes fitted again at most, to pay out all a hub's notes pay.
const FIT_ROUNDS: usize = 6;

pub(super) fn claim_rate() -> FeeRate {
    FeeRate::from_sat_per_vb(CLAIM_RATE).expect("a rate")
}

/// What a payout of `amount` may cost on top to be quoted at all: 5% and
/// 5000 sat. The user sees what it costs before paying.
pub(super) fn max_fee(amount: u64) -> u64 {
    amount / 20 + 5_000
}

/// A first guess at what `held` pays out, fees aside: 2% and 2000 less.
fn all_but_fees(held: u64) -> u64 {
    held.saturating_sub(held / 50 + 2_000)
}

/// What the lock of a payout quoted pays its provider: the coin's value
/// and the provider's fee.
fn locked(quote: &licash_wallet::PayoutQuote) -> u64 {
    quote.value().saturating_add(quote.fee)
}

/// Payouts on Bitcoin.
#[uniffi::export]
impl Wallet {
    /// What paying `amount` to `address`, on Bitcoin, costs from notes at
    /// `hub`, else at the hub trusted holding the most, through the swap
    /// provider announced on the relays the hubs name that asks least: of
    /// all the notes there, what they pay out once its fees are paid if
    /// `amount` is none. Refused unless the notes there pay it all.
    pub fn payout_quote(
        &self,
        address: String,
        amount: Option<u64>,
        hub: Option<String>,
    ) -> Result<PayoutQuote, LicashError> {
        let _timed = crate::log::timed("payout_quote");
        let (asked, found) = self.payout_found(&address, amount, hub)?;
        let Some(best) = found.into_iter().next() else {
            return Err(no_provider(asked.first));
        };
        self.payout_offer(&asked, best)
    }

    /// About the most [`Wallet::payout_quote`] pays out to `address` from
    /// `hub`, else the hub trusted holding the most: the most of the swap
    /// providers kept, by their own terms, and no more than all the notes
    /// there pay. None if none kept pays out from there. Asked once none
    /// pays an amount out, to offer the most instead.
    pub fn payout_most(
        &self,
        address: String,
        hub: Option<String>,
    ) -> Result<Option<u64>, LicashError> {
        let _timed = crate::log::timed("payout_most");
        let hub = match hub {
            Some(hub) => hub,
            None => self.richest()?,
        };
        let held = all_but_fees(self.held(&hub)?);
        let relays = hub_relays(&self.wallet)?;
        let infos = self.operation(self.announced.infos(&self.wallet, &relays))?;
        let mut most = None;
        for info in &infos {
            let one = (self.wallet).payout_most(info, &hub, address.trim(), claim_rate())?;
            most = most.max(one);
        }
        Ok(most.map(|m| m.min(held)).filter(|m| *m > 0))
    }

    /// The quotes of [`Wallet::payout_quote`] through each swap provider
    /// that pays it out, in the order it prefers them: to choose from.
    /// Those that cannot are left out; refused if none can.
    pub fn payout_offers(
        &self,
        address: String,
        amount: Option<u64>,
        hub: Option<String>,
    ) -> Result<Vec<PayoutQuote>, LicashError> {
        let _timed = crate::log::timed("payout_offers");
        let (asked, found) = self.payout_found(&address, amount, hub)?;
        let mut offers = Vec::new();
        for provider in found {
            let url = provider.url.clone();
            match self.payout_offer(&asked, provider) {
                Ok(quote) => offers.push(quote),
                Err(e) => tracing::info!(%url, "no payout offer: {e}"),
            }
        }
        match offers.is_empty() {
            true => Err(no_provider(asked.first)),
            false => Ok(offers),
        }
    }

    /// Pay out as `quote` says, costing at most its fee: the payout, under
    /// way until [`Wallet::follow_payouts`] finds its claim confirmed. A
    /// payout whose lock was made but which fails gets its notes back once
    /// the lock expires.
    pub fn pay_out(&self, quote: PayoutQuote) -> Result<Activity, LicashError> {
        let _timed = crate::log::timed("pay_out");
        let ticketed = self.ticketed(&quote)?;
        self.pay_ticketed(&ticketed)
    }

    /// Pay out as `quote` says, as [`Wallet::pay_out`]; if its provider
    /// fails before the wallet's notes are locked to it, through the next
    /// found paying `asked` (all the notes, if none) from the same hub to
    /// the same address for no more in fees, and so on: never once a lock
    /// was made, whose notes come back only once it expires.
    pub fn pay_out_or_another(
        &self,
        quote: PayoutQuote,
        asked: Option<u64>,
    ) -> Result<Activity, LicashError> {
        let _timed = crate::log::timed("pay_out_or_another");
        self.pay_out_recorded(quote, asked, &|_| Ok(()))
    }

    /// Take the payouts under way on, on `chain`: claim each provider's
    /// coin once confirmed, then broadcast through `chain` the claims of
    /// those not done, again each time, as a claim dropped loses its coin
    /// once it times out. Whether any is under way still.
    pub fn follow_payouts(&self, chain: Arc<dyn ChainSource>) -> Result<bool, LicashError> {
        let _timed = crate::log::timed("follow_payouts");
        let followed = self.runtime.block_on(
            self.wallet
                .follow_payouts(&Chain(chain.clone(), self.wallet.network())),
        );
        // Whatever the follow made, even if it failed after.
        for claim in self.wallet.payout_claims()? {
            if let Err(e) = chain.broadcast(bitcoin::consensus::serialize(&claim)) {
                tracing::debug!(txid = %claim.compute_txid(), %e, "broadcasting a claim");
            }
        }
        let (payouts, pending) = followed?;
        for (id, reason) in pending {
            tracing::info!(%id, %reason, "payout pending");
        }
        Ok(payouts
            .iter()
            .any(|p| matches!(p.state, PayoutState::Open | PayoutState::Claimed)))
    }
}

/// A payout asked for ([`Wallet::payout_quote`]).
struct Asked {
    address: String,
    amount: Option<u64>,
    hub: String,
    held: u64,
    /// What the providers were asked to pay out first.
    first: u64,
}

fn no_provider(amount: u64) -> LicashError {
    LicashError::invalid(format!(
        "no swap provider found pays {amount} sat out on Bitcoin now"
    ))
}

impl Wallet {
    /// The wallet's quote of `quote`, asked again, under a ticket of its
    /// own: what pays it out, once.
    pub(super) fn ticketed(
        &self,
        quote: &PayoutQuote,
    ) -> Result<licash_wallet::PayoutQuote, LicashError> {
        let ask = self.wallet.payout_quote(
            &quote.provider,
            &quote.hub,
            &quote.address,
            quote.amount,
            quote.fee,
            claim_rate(),
        );
        Ok(self.operation(ask)?)
    }

    fn pay_ticketed(&self, quote: &licash_wallet::PayoutQuote) -> Result<Activity, LicashError> {
        let payout = self.operation(self.wallet.payout(quote))?;
        tracing::info!(hash = %payout.hash, address = %payout.address, "paying out");
        Ok(activity(&payout, self.lock_fee(&payout)?))
    }

    /// The payout asked for, and the providers announced that quote it,
    /// the one to prefer first.
    fn payout_found(
        &self,
        address: &str,
        amount: Option<u64>,
        hub: Option<String>,
    ) -> Result<(Asked, Vec<licash_nostr::wallet::PayoutProvider>), LicashError> {
        let address = address.trim();
        let hub = match hub {
            Some(hub) => hub,
            None => self.richest()?,
        };
        let held = self.held(&hub)?;
        let first = amount.unwrap_or_else(|| all_but_fees(held));
        if first == 0 {
            return Err(LicashError::Insufficient {
                needed: held + 1,
                available: held,
            });
        }
        let relays = hub_relays(&self.wallet)?;
        if relays.is_empty() {
            return Err(LicashError::invalid(
                "no hub you trust names relays to find swap providers on",
            ));
        }
        let limits = (max_fee(first), claim_rate());
        let found = payout_providers_with(
            &self.wallet,
            &self.announced,
            &relays,
            &self.route,
            (&hub, address),
            first,
            limits,
        );
        let found = self
            .operation(found)
            .map_err(|e| LicashError::from_any(e, |reason| LicashError::Unavailable { reason }))?;
        let asked = Asked {
            address: address.to_owned(),
            amount,
            hub,
            held,
            first,
        };
        Ok((asked, found))
    }

    /// The quote of paying out as `asked` through `provider`: all the notes
    /// at the hub pay, fitted to them, if no amount was asked.
    fn payout_offer(
        &self,
        asked: &Asked,
        provider: licash_nostr::wallet::PayoutProvider,
    ) -> Result<PayoutQuote, LicashError> {
        let hub = &asked.hub;
        let mut quote = match asked.amount {
            Some(_) => provider.quote,
            None => self.fit(
                &provider.url,
                (hub, asked.held),
                &asked.address,
                provider.quote,
            )?,
        };
        // The hub charges on the selected notes, which can exceed the
        // value locked to the provider. Include that fee before consent.
        let selected_fee = self.wallet.lock_fee(hub, locked(&quote))?;
        quote.lock_fee = quote.lock_fee.max(selected_fee);
        let fee = quote.costs();
        if fee > quote.max_fee {
            return Err(LicashError::invalid(format!(
                "payout costs {fee} sat, more than {}",
                quote.max_fee
            )));
        }
        Ok(PayoutQuote {
            address: asked.address.clone(),
            amount: quote.amount,
            fee,
            provider_fee: quote.fee,
            claim_fee: quote.budget,
            lock_fee: quote.lock_fee,
            hub: hub.clone(),
            provider: provider.url,
            provider_name: provider.name,
            depth: payout_depth(self.wallet.network()),
        })
    }

    /// The hub trusted holding the most.
    pub(super) fn richest(&self) -> Result<String, LicashError> {
        let balance = self.wallet.balance()?.into_iter();
        let richest = balance.max_by_key(|b| b.available).map(|b| b.hub);
        richest.ok_or_else(|| LicashError::invalid("no hub trusted holds notes"))
    }

    /// What the wallet holds at `hub` to pay with.
    pub(super) fn held(&self, hub: &str) -> Result<u64, LicashError> {
        let balance = self.wallet.balance()?.into_iter();
        let held = balance.filter(|b| b.hub == hub).map(|b| b.available);
        held.max()
            .ok_or_else(|| LicashError::invalid(format!("no hub trusted is {hub}")))
    }

    /// The quote of `provider` paying out the most the notes `held` at
    /// `hub` pay with its fees: from `quote`, fitted again to what the
    /// lock spends.
    fn fit(
        &self,
        provider: &str,
        (hub, held): (&str, u64),
        address: &str,
        mut quote: licash_wallet::PayoutQuote,
    ) -> Result<licash_wallet::PayoutQuote, LicashError> {
        let mut best: Option<licash_wallet::PayoutQuote> = None;
        let mut short = None;
        for _ in 0..FIT_ROUNDS {
            let amount = match self.wallet.lock_fee(hub, locked(&quote)) {
                Ok(lock_fee) => {
                    let spends = locked(&quote).saturating_add(lock_fee);
                    let room = held.saturating_sub(spends);
                    if best.as_ref().is_none_or(|b| b.amount < quote.amount) {
                        best = Some(quote.clone());
                    }
                    quote.amount + room
                }
                Err(licash_wallet::Error::Insufficient { needed, available }) => {
                    short = Some(licash_wallet::Error::Insufficient { needed, available });
                    let over = needed.saturating_sub(available).max(1);
                    quote.amount.saturating_sub(over)
                }
                Err(e) => return Err(e.into()),
            };
            // No more to find: what fits already pays as much.
            let fitting = best.as_ref().is_some_and(|b| b.amount >= amount);
            if amount == quote.amount || amount == 0 || fitting {
                break;
            }
            let asked = self.wallet.payout_quote(
                provider,
                hub,
                address,
                amount,
                max_fee(amount),
                claim_rate(),
            );
            quote = match self.operation(asked) {
                Ok(quote) => quote,
                // Past what the provider pays out, say.
                Err(e) if best.is_some() => {
                    tracing::debug!(amount, %e, "paying out all: no more");
                    break;
                }
                Err(e) => return Err(e.into()),
            };
        }
        match (best, short) {
            (Some(best), _) => Ok(best),
            (None, Some(short)) => Err(short.into()),
            (None, None) => Err(LicashError::Insufficient {
                needed: held + 1,
                available: held,
            }),
        }
    }

    /// [`Wallet::pay_out_or_another`], `record` told each payout's hash
    /// before it is made: none made unless recorded.
    pub(super) fn pay_out_recorded(
        &self,
        quote: PayoutQuote,
        asked: Option<u64>,
        record: &dyn Fn(&str) -> Result<(), LicashError>,
    ) -> Result<Activity, LicashError> {
        let most = quote.fee;
        let mut tried = vec![quote.provider.clone()];
        let mut last = match self.try_pay_out(&quote, record)? {
            Ok(paying) => return Ok(paying),
            Err(e) => e,
        };
        let others = self.payout_offers(quote.address.clone(), asked, Some(quote.hub.clone()));
        let others = match others {
            Ok(others) => others,
            Err(e) => {
                tracing::info!("no other payout offer: {e}");
                return Err(last);
            }
        };
        // The chosen provider's fee rising is the user's to accept, said
        // over whatever failed after.
        let rose = matches!(last, LicashError::FeeRose { .. });
        for offer in others {
            if offer.fee > most || tried.contains(&offer.provider) {
                continue;
            }
            tried.push(offer.provider.clone());
            match self.try_pay_out(&offer, record)? {
                Ok(paying) => return Ok(paying),
                Err(e) if !rose => last = e,
                Err(e) => tracing::info!(provider = %offer.provider, "paying out failed: {e}"),
            }
        }
        Err(last)
    }

    /// Paying out as `quote` says, its hash told `record` first: the
    /// payout, under way, else why it failed with nothing locked, to try
    /// another provider. Refused if it failed once a lock was made, or if
    /// not recorded, nothing paid.
    fn try_pay_out(
        &self,
        quote: &PayoutQuote,
        record: &dyn Fn(&str) -> Result<(), LicashError>,
    ) -> Result<Result<Activity, LicashError>, LicashError> {
        let ticketed = match self.ticketed(quote) {
            Ok(ticketed) => ticketed,
            // Nothing recorded, nothing locked.
            Err(e) => {
                tracing::info!(provider = %quote.provider, "paying out failed, not quoted: {e}");
                return Ok(Err(e));
            }
        };
        record(&ticketed.ticket)?;
        let e = match self.pay_ticketed(&ticketed) {
            Ok(paying) => return Ok(Ok(paying)),
            Err(e) => e,
        };
        // The one this attempt recorded, by its ticket, if any.
        let payouts = self.wallet.payouts()?;
        match payouts.into_iter().find(|p| p.hash == ticketed.ticket) {
            // Under way: it is followed, never replaced.
            Some(payout) if matches!(payout.state, PayoutState::Open | PayoutState::Claimed) => {
                tracing::info!(hash = %payout.hash, "paying out, pending: {e}");
                Ok(Ok(activity(&payout, self.lock_fee(&payout)?)))
            }
            Some(payout) if payout.lock.is_some() => Err(e),
            _ => {
                tracing::info!(provider = %quote.provider, "paying out failed, nothing locked: {e}");
                Ok(Err(e))
            }
        }
    }

    /// The hub's fee on the lock of `payout`, once made.
    fn lock_fee(&self, payout: &Payout) -> Result<u64, LicashError> {
        let Some(id) = &payout.lock else {
            return Ok(0);
        };
        let locks = self.wallet.locks()?;
        Ok(locks.iter().find(|l| &l.id == id).map_or(0, |l| l.fee))
    }
}

/// The payouts, as lines of the history.
pub(super) fn activities(
    wallet: &licash_wallet::Wallet<Http>,
) -> Result<Vec<Activity>, LicashError> {
    let locks = wallet.locks()?;
    let fee = |p: &Payout| {
        let lock = p
            .lock
            .as_ref()
            .and_then(|id| locks.iter().find(|l| &l.id == id));
        lock.map_or(0, |l| l.fee)
    };
    Ok(wallet
        .payouts()?
        .iter()
        .map(|p| activity(p, fee(p)))
        .collect())
}

/// More of the payout of `hash`, `tip` the chain's height as last seen.
pub(super) fn details(
    wallet: &licash_wallet::Wallet<Http>,
    hash: &str,
    tip: u32,
) -> Result<Details, LicashError> {
    let payout = wallet.payouts()?.into_iter().find(|p| p.hash == hash);
    let payout =
        payout.ok_or_else(|| LicashError::invalid(format!("nothing in the history is {hash}")))?;
    let failure = match &payout.state {
        PayoutState::Failed(why) => Some(why.clone()),
        _ => None,
    };
    let locks = wallet.locks()?;
    let lock = payout.lock.as_ref();
    let lock_fee = lock
        .and_then(|id| locks.iter().find(|l| &l.id == id))
        .map_or(0, |l| l.fee);
    Ok(Details::Payout {
        hub: payout.from,
        provider: payout.provider,
        address: payout.address,
        coin: payout.funding.map(|o| o.txid.to_string()),
        claim: payout.claim.map(|t| t.to_string()),
        failure,
        progress: steps(wallet.payout_progress(hash)?, tip),
        provider_fee: payout.fee,
        claim_fee: payout.budget,
        lock_fee,
    })
}

/// The steps of `progress`, `tip` the chain's height as last seen.
fn steps(progress: PayoutProgress, tip: u32) -> PayoutSteps {
    let (lock, lock_expiry) = match progress.lock {
        Some((state, expiry)) => {
            let step = match state {
                LockState::Requested => LockStep::Requested,
                LockState::Locked => LockStep::Locked,
                LockState::Paid(_) => LockStep::Paid,
                LockState::Refunded => LockStep::Refunded,
                LockState::Abandoned(_) => LockStep::Abandoned,
                // A state of a later library: under way still.
                _ => LockStep::Requested,
            };
            (Some(step), Some(expiry))
        }
        None => (None, None),
    };
    PayoutSteps {
        lock,
        lock_expiry,
        timeout: progress.timeout,
        claim_by: progress.claim_by,
        coin: progress.coin.map(|t| t.to_string()),
        coin_height: progress.coin_height,
        claim: progress.claim.map(|t| t.to_string()),
        claim_height: progress.claim_height,
        depth: progress.depth,
        tip,
    }
}

/// The line of the history of `payout`: what the address gets, and what
/// it costs on top, `lock_fee` the hub's; nothing once it failed, its
/// notes back once its lock expires.
fn activity(payout: &Payout, lock_fee: u64) -> Activity {
    let fee = payout
        .budget
        .saturating_add(payout.fee)
        .saturating_add(lock_fee);
    let (state, detail, fee) = match &payout.state {
        PayoutState::Done => (State::Done, payout.address.clone(), fee),
        PayoutState::Failed(why) => (State::Failed, why.clone(), 0),
        _ => (State::Pending, payout.address.clone(), fee),
    };
    Activity {
        id: payout.hash.clone(),
        kind: Kind::Payout,
        state,
        amount: payout.amount,
        fee,
        detail,
        at: Some(payout.created_at),
        memo: None,
        from: None,
        code: None,
    }
}
