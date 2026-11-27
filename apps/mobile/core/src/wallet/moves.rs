//! Notes moved between the wallet's own hubs, through a swap provider: the
//! provider takes the wallet's lock at one hub and locks as much to it at
//! the other, less its fee.

use std::sync::PoisonError;

use licash_nostr::wallet::{hub_relays, swap_providers_with, SwapProvider};
use licash_transport::Http;
use licash_wallet::{Swap, SwapLimits, SwapQuote, SwapState};

use super::Wallet;
use crate::{Activity, Details, Kind, LicashError, MoveQuote, State};

/// Rounds of asking a provider again to fit a move of all the notes at a
/// hub to what its lock spends there.
const FIT_ROUNDS: usize = 4;

/// Moves between the wallet's hubs.
#[uniffi::export]
impl Wallet {
    /// What moving `amount` of the notes at hub `from` to hub `to`, both
    /// trusted, costs through each swap provider announced on the relays
    /// the hubs name, in the order it prefers them (those it moved through
    /// before, then the cheapest): of all the notes at `from`, what reaches
    /// `to` once the fees are paid if `amount` is none. Those that cannot
    /// are left out; refused if none can.
    pub fn move_offers(
        &self,
        from: String,
        to: String,
        amount: Option<u64>,
    ) -> Result<Vec<MoveQuote>, LicashError> {
        let _timed = crate::log::timed("move_offers");
        if from == to {
            return Err(LicashError::invalid("a move is between two hubs"));
        }
        self.held(&to)?;
        let held = self.held(&from)?;
        let first = amount.unwrap_or_else(|| held.saturating_sub(SwapLimits::usual(held).fee));
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
        let found = swap_providers_with(
            &self.wallet,
            &self.announced,
            &relays,
            &self.route,
            (&from, &to),
            first,
            SwapLimits::usual(first),
        );
        let found = self
            .operation(found)
            .map_err(|e| LicashError::from_any(e, |reason| LicashError::Unavailable { reason }))?;
        let mut offers = Vec::new();
        for provider in found {
            let url = provider.url.clone();
            match self.move_offer((&from, &to), held, amount, provider) {
                Ok(offer) => offers.push(offer),
                Err(e) => tracing::info!(%url, "no move offer: {e}"),
            }
        }
        match offers.is_empty() {
            true => Err(LicashError::invalid(format!(
                "no swap provider found moves {first} sat from {from} to {to} now"
            ))),
            false => Ok(offers),
        }
    }

    /// Move as the first of `offers` says, costing at most its fee. If its
    /// provider fails before the wallet's notes are locked to it, through
    /// the next that costs no more, and so on: never once a lock was made,
    /// whose notes come back only once it expires. The move, under way
    /// until the wallet holds the notes at the other hub.
    pub fn move_notes(&self, offers: Vec<MoveQuote>) -> Result<Activity, LicashError> {
        let _timed = crate::log::timed("move_notes");
        let Some(chosen) = offers.first() else {
            return Err(LicashError::invalid("no move offer to take"));
        };
        let _one_at_a_time = self.moving.lock().unwrap_or_else(PoisonError::into_inner);
        let most = chosen.fee;
        let mut last = None;
        for offer in offers.iter().filter(|o| o.fee <= most) {
            let before: Vec<String> = self.wallet.swaps()?.into_iter().map(|s| s.hash).collect();
            let limits = SwapLimits {
                fee: offer.fee.saturating_sub(offer.lock_fee),
                margin: offer.margin,
            };
            // Held to what was confirmed in all, the hub's lock fee too.
            let moving = self.wallet.swap_within(
                &offer.provider,
                &offer.from,
                &offer.to,
                offer.amount,
                limits,
                Some(most),
            );
            match self.operation(moving) {
                Ok(swap) => return Ok(activity(&swap, self.swap_lock_fee(&swap)?)),
                Err(e) => {
                    // Newest first: the one this attempt recorded, if any.
                    let swaps = self.wallet.swaps()?;
                    let made = swaps.into_iter().find(|s| !before.contains(&s.hash));
                    match made {
                        // Under way: it is followed, never replaced.
                        Some(swap) if swap.state == SwapState::Open => {
                            tracing::info!(hash = %swap.hash, "moving, pending: {e}");
                            return Ok(activity(&swap, self.swap_lock_fee(&swap)?));
                        }
                        // A lock made: its notes are tied up until it
                        // expires, so the move is not tried again.
                        Some(swap) if swap.lock.is_some() => return Err(e.into()),
                        _ => {
                            tracing::info!(provider = %offer.provider, "moving failed, nothing locked: {e}");
                            // The chosen provider's fee rising is the
                            // user's to accept, said over what failed after.
                            let rose = matches!(last, Some(licash_wallet::Error::FeeRose { .. }));
                            if !rose {
                                last = Some(e);
                            }
                        }
                    }
                }
            }
        }
        Err(last.map_or_else(|| LicashError::invalid("no move offer to take"), Into::into))
    }
}

impl Wallet {
    /// The quote of moving as asked through `provider`: all the notes
    /// `held` at `from` move, fitted to them, if no amount was asked.
    fn move_offer(
        &self,
        (from, to): (&str, &str),
        held: u64,
        amount: Option<u64>,
        provider: SwapProvider,
    ) -> Result<MoveQuote, LicashError> {
        let url = provider.url;
        let quote = match amount {
            Some(_) => provider.quote,
            None => self.fit_move(&url, (from, to), held, provider.quote)?,
        };
        let lock_fee = self
            .wallet
            .lock_fee(from, quote.amount.saturating_add(quote.fee))?;
        Ok(MoveQuote {
            from: from.to_owned(),
            to: to.to_owned(),
            amount: quote.amount,
            fee: quote.fee.saturating_add(lock_fee),
            lock_fee,
            margin: quote.margin,
            provider: url,
            provider_name: provider.name,
        })
    }

    /// The quote of `provider` moving the most the notes `held` at `from`
    /// pay with its fees: from `quote`, asked again to fit what the lock
    /// spends.
    fn fit_move(
        &self,
        provider: &str,
        (from, to): (&str, &str),
        held: u64,
        mut quote: SwapQuote,
    ) -> Result<SwapQuote, LicashError> {
        let mut best: Option<SwapQuote> = None;
        let mut short = None;
        for _ in 0..FIT_ROUNDS {
            let locked = quote.amount.saturating_add(quote.fee);
            let amount = match self.wallet.lock_fee(from, locked) {
                Ok(lock_fee) => {
                    let room = held.saturating_sub(locked.saturating_add(lock_fee));
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
            let fitting = best.as_ref().is_some_and(|b| b.amount >= amount);
            if amount == quote.amount || amount == 0 || fitting {
                break;
            }
            let asked =
                self.wallet
                    .swap_quote(provider, from, to, amount, SwapLimits::usual(amount));
            quote = match self.operation(asked) {
                Ok(quote) => quote,
                Err(e) if best.is_some() => {
                    tracing::debug!(amount, %e, "moving all: no more");
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

    /// The hub's fee on the lock of `swap`, once made.
    fn swap_lock_fee(&self, swap: &Swap) -> Result<u64, LicashError> {
        let Some(id) = &swap.lock else {
            return Ok(0);
        };
        let locks = self.wallet.locks()?;
        Ok(locks.iter().find(|l| &l.id == id).map_or(0, |l| l.fee))
    }
}

/// The moves, as lines of the history.
pub(super) fn activities(
    wallet: &licash_wallet::Wallet<Http>,
) -> Result<Vec<Activity>, LicashError> {
    let locks = wallet.locks()?;
    let fee = |s: &Swap| {
        let lock = s
            .lock
            .as_ref()
            .and_then(|id| locks.iter().find(|l| &l.id == id));
        lock.map_or(0, |l| l.fee)
    };
    Ok(wallet
        .swaps()?
        .iter()
        .map(|s| activity(s, fee(s)))
        .collect())
}

/// More of the move of `hash`.
pub(super) fn details(
    wallet: &licash_wallet::Wallet<Http>,
    hash: &str,
) -> Result<Details, LicashError> {
    let swap = wallet.swaps()?.into_iter().find(|s| s.hash == hash);
    let swap =
        swap.ok_or_else(|| LicashError::invalid(format!("nothing in the history is {hash}")))?;
    let failure = match &swap.state {
        SwapState::Failed(why) => Some(why.clone()),
        _ => None,
    };
    let locks = wallet.locks()?;
    let lock = (swap.lock.as_ref()).and_then(|id| locks.iter().find(|l| &l.id == id));
    let lock_fee = lock.map_or(0, |l| l.fee);
    Ok(Details::Swap {
        from: swap.from,
        to: swap.to,
        provider: swap.provider,
        lock: swap.lock,
        theirs: swap.theirs,
        failure,
        provider_fee: swap.fee,
        lock_fee,
        expiry: lock.map(|l| l.expiry),
    })
}

/// The line of the history of `swap`: what reaches the other hub, and
/// what it costs on top, `lock_fee` the hub's; nothing once it failed, its
/// notes back once its lock expires.
fn activity(swap: &Swap, lock_fee: u64) -> Activity {
    let (state, detail) = match &swap.state {
        SwapState::Done => (State::Done, swap.to.clone()),
        SwapState::Failed(why) => (State::Failed, why.clone()),
        _ => (State::Pending, swap.to.clone()),
    };
    let fee = match state {
        State::Failed => 0,
        _ => swap.fee.saturating_add(lock_fee),
    };
    Activity {
        id: swap.hash.clone(),
        kind: Kind::Swap,
        state,
        amount: swap.amount,
        fee,
        detail,
        at: Some(swap.created_at),
        memo: None,
        from: None,
        code: None,
    }
}
