//! Recovery contracts with the hubs trusted, opened from a coin of the
//! wallet's on Bitcoin, carried on and watched as the chain moves: each
//! protects the wallet's notes at its hub, up to its cap, until its last
//! block to recover in; its collateral returns to the hub at its close.
//! There is no closing one sooner: the notes it protects are cashed out
//! instead, and it lapses.
//!
//! Kept in the wallet's file, `wallet.sqlite`, and in `contracts/` beside it,
//! made only once a first contract is asked for.

use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc, PoisonError},
};

use bitcoin::{OutPoint, Txid};
use licash_contracts::holder::{self, Ask, Fate, Phase};

use super::Wallet;
use crate::{
    chain::Chain, Activity, Balance, ChainSource, Contract, ContractQuote, ContractState,
    DepositCoin, Details, Kind, LicashError, OpeningStep, PayoutQuote, State, Transfer,
};

/// How large an instance of a contract's opening is, about: her wallet
/// uploads each the hub keeps.
const INSTANCE: u64 = 25_100_000;

/// What opening a contract sends, in bytes, about: the `kept` instances
/// the hub keeps of its quote's.
fn upload(kept: u16) -> u64 {
    u64::from(kept) * INSTANCE
}

/// Recovery contracts.
#[uniffi::export]
impl Wallet {
    pub fn contract_inspection(
        &self,
        id: String,
    ) -> Result<crate::ContractInspection, LicashError> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(id, &mut bytes)
            .map_err(|_| LicashError::invalid("not a contract id"))?;
        let info = holder::inspect(&self.wallet, self.wallet.path(), &bytes, self.tip())
            .map_err(failed)?;
        Ok(crate::ContractInspection {
            address: info.address,
            locked: info.locked,
            payout_pool: info.payout_pool,
            holder_reserve: info.holder_reserve,
            hub_reserve: info.hub_reserve,
            claim_limit: info.claim_limit,
            note_limit: info.note_limit,
            denominations: info.denominations,
            keyset: info.keyset,
            graph_version: info.graph_version,
            program: info.program,
        })
    }

    /// What opening a contract at `hub`, a hub trusted, costs now, as it
    /// offers, and the coin on Bitcoin that would pay it.
    pub fn contract_quote(&self, hub: String) -> Result<ContractQuote, LicashError> {
        let (hub, terms) = self.contracting_hub(&hub)?;
        let trust = licash_contracts::trust(self.wallet.network());
        let trust = trust.map_err(|e| LicashError::invalid(format!("{e:#}")))?;
        let offer = holder::offer(&self.wallet, &hub, None, 0);
        let offer = self.operation(offer).map_err(unavailable)?;
        let price = offer.price();
        let coins = holder::coins(&self.wallet, self.wallet.path()).map_err(failed)?;
        let blocks = offer.bounds.lock;
        let after_assert = holder::after_assert(&offer.quote);
        let largest = coins.first().map(|c| c.value);
        let (denominations, funded_notes) = holder::funding_notes(&offer.quote);
        // The coin that would pay it: the smallest a contract at its fixed
        // terms takes whole.
        let pricing = holder::Pricing::Fixed {
            cap: offer.quote.cap,
            price,
        };
        let coin = holder::smallest_fit(
            coins.clone(),
            &pricing,
            blocks,
            offer.quote.graph.dust,
            (&denominations, funded_notes),
            0,
        )
        .map(|(coin, _)| coin);
        let (suggested_cap, suggested_blocks) = match &terms.range {
            Some(range) => suggested(range, largest),
            None => (offer.quote.cap, blocks),
        };
        Ok(ContractQuote {
            hub,
            price,
            cap: u64::from(offer.quote.cap),
            blocks,
            protects_for: blocks.saturating_sub(after_assert),
            mock: trust.mock,
            coin: coin.map(|c| c.value),
            download: upload(offer.quote.recipe.kept),
            range: terms.range.map(Into::into),
            after_assert,
            coins: coins
                .iter()
                .map(|c| DepositCoin {
                    outpoint: c.outpoint.to_string(),
                    value: c.value,
                })
                .collect(),
            suggested_cap: u64::from(suggested_cap),
            suggested_blocks,
            dust: offer.quote.graph.dust,
            denominations,
            funded_notes: u32::try_from(funded_notes).unwrap_or(u32::MAX),
        })
    }

    /// The contract to offer the wallet, if any: for its largest coin on
    /// Bitcoin, at the trusted hub letting it choose terms that protects
    /// the most for the least (`best`), none at a hub it has one live or
    /// being opened. Its quote, at first of the suggested terms; opened
    /// only once she accepts them ([`Wallet::open_chosen_contract`]). None
    /// if no hub offers one, no coin pays one for a tenth of it at most
    /// (`SHARE`), or no hub answers.
    pub fn contract_offer(&self) -> Result<Option<ContractQuote>, LicashError> {
        let all = holder::list(self.wallet.path()).map_err(failed)?;
        let tip = self.tip();
        let busy: Vec<&str> = all
            .iter()
            .filter(|c| {
                matches!(
                    state(c, tip),
                    ContractState::Opening | ContractState::Confirming | ContractState::Protecting
                )
            })
            .map(|c| c.hub.trim_end_matches('/'))
            .collect();
        let coins = holder::coins(&self.wallet, self.wallet.path()).map_err(failed)?;
        let Some(coin) = coins.first().map(|c| c.value) else {
            return Ok(None);
        };
        let hubs: Vec<Offering> = self
            .wallet
            .hubs()?
            .into_iter()
            .filter(|(url, _)| !busy.contains(&url.trim_end_matches('/')))
            .filter_map(|(url, info)| Some((url, info.contracts?.range?)))
            .filter(|(_, range)| check_range(range).is_ok())
            .collect();
        for hub in best(&hubs, coin) {
            match self.contract_quote(hub.to_owned()) {
                Ok(quote) => return Ok(Some(quote)),
                Err(e) => tracing::info!(hub, "no contract offered there now: {e}"),
            }
        }
        Ok(None)
    }

    /// Open a contract at `hub`, a hub trusted, closing `blocks` from now
    /// (by default, as late as it allows), for at most `max_price` (by
    /// default, what its info says), broadcasting its funding through
    /// `chain`: the contract, confirming once its funding is signed.
    /// Paid from the smallest coin on Bitcoin that pays it, its change
    /// back to the wallet on Bitcoin. Takes minutes: its uploads are
    /// large. One at a time; under way, [`Wallet::resume_contracts`]
    /// carries it on.
    pub fn open_contract(
        &self,
        chain: Arc<dyn ChainSource>,
        hub: String,
        blocks: Option<u32>,
        max_price: Option<u64>,
    ) -> Result<Contract, LicashError> {
        let (hub, terms) = self.contracting_hub(&hub)?;
        let ask = Ask {
            blocks: blocks.unwrap_or(terms.blocks),
            max_price: max_price.unwrap_or(terms.price),
            cap: None,
            deposit: None,
        };
        let _contracting = self
            .contracting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.opened(chain, &hub, ask)
    }

    /// Open a contract at `hub`, a hub trusted that lets the wallet
    /// choose (its terms' range), protecting `cap` sat at least and closing
    /// `blocks` from now, for at most `max_price`, paid from `coin`
    /// (`txid:vout`; by default the smallest that a contract takes whole),
    /// as [`Wallet::open_contract`]. The coin is spent whole: it pays the
    /// price and funds the rest of her part of the contract, issued her as
    /// notes at the hub once its funding is buried ([`crate::contract_fit`]
    /// says what contract a coin takes). No change comes back from it.
    pub fn open_chosen_contract(
        &self,
        chain: Arc<dyn ChainSource>,
        hub: String,
        cap: u64,
        blocks: u32,
        max_price: u64,
        coin: Option<String>,
    ) -> Result<Contract, LicashError> {
        let (hub, terms) = self.contracting_hub(&hub)?;
        if terms.range.is_none() {
            return Err(LicashError::invalid(format!(
                "{hub} offers contracts of {} sat over {} blocks only",
                terms.cap, terms.blocks
            )));
        }
        let cap = u32::try_from(cap)
            .map_err(|_| LicashError::invalid(format!("a cap of {cap} sat: too large")))?;
        let _contracting = self
            .contracting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let deposit = coin
            .map(|coin| {
                coin.parse::<OutPoint>()
                    .map_err(|e| LicashError::invalid(format!("a coin {coin}: {e}")))
            })
            .transpose()?;
        let ask = Ask {
            blocks,
            max_price,
            cap: Some(cap),
            deposit,
        };
        self.opened(chain, &hub, ask)
    }

    /// What a contract at `hub` costs paid for with notes, for a wallet with
    /// no coin on Bitcoin to open it with: a coin worth its price and a
    /// small part of it the wallet's (the hub funding the rest), paid out to
    /// the wallet's own address from notes at `from` (by default, the hub
    /// trusted holding the most) through the swap provider announced on the
    /// relays the hubs name that asks least: the smallest contract of `cap`
    /// at least (by default, the smallest), closing `blocks` from now (by
    /// default, as late as it allows). Notes on Lightning are received at a
    /// hub first. [`Wallet::open_paid_contract`] pays it, at no higher
    /// price.
    pub fn paid_contract_quote(
        &self,
        hub: String,
        from: Option<String>,
        cap: Option<u64>,
        blocks: Option<u32>,
    ) -> Result<PaidContractQuote, LicashError> {
        let _timed = crate::log::timed("paid_contract_quote");
        let (hub, terms) = self.contracting_hub(&hub)?;
        let cap = cap
            .map(|c| u32::try_from(c).map_err(|_| LicashError::invalid(format!("a cap of {c}"))))
            .transpose()?;
        let ask = Ask {
            blocks: blocks.unwrap_or(terms.blocks),
            max_price: u64::MAX,
            cap,
            deposit: None,
        };
        // As large as a provider pays out at least, the rest hers.
        let to = self.wallet.fallback_address()?.to_string();
        let floor = match &from {
            Some(from) => self.payout_least(&to, from)?,
            None => self.payout_least(&to, &self.richest()?)?,
        };
        let coin = holder::paid::coin(&self.wallet, &hub, ask, floor.unwrap_or(0));
        let coin = self.operation(coin).map_err(unavailable)?;
        let payout = self.payout_quote(coin.to.clone(), Some(coin.value), from)?;
        Ok(PaidContractQuote {
            hub,
            blocks: ask.blocks,
            least: cap.map(u64::from),
            value: coin.value,
            price: coin.price,
            cap: u64::from(coin.fit.cap),
            funded: u64::from(coin.fit.funded),
            payout,
        })
    }

    /// Pay for a contract as `quote` says, costing at most its payout's
    /// fee: the payout made, under way as any, and the contract opened on
    /// its coin by [`Wallet::resume_contracts`] once the wallet found it;
    /// should it not, the coin stays the wallet's. Refused if the hub's
    /// terms changed since: to be quoted again.
    pub fn open_paid_contract(
        &self,
        quote: PaidContractQuote,
    ) -> Result<PaidContract, LicashError> {
        let _timed = crate::log::timed("open_paid_contract");
        let (hub, _) = self.contracting_hub(&quote.hub)?;
        let cap = quote.least.and_then(|c| u32::try_from(c).ok());
        let ask = Ask {
            blocks: quote.blocks,
            max_price: quote.price,
            cap,
            deposit: None,
        };
        let _contracting = self
            .contracting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // The coin quoted, of the contract quoted: the hub's terms the same.
        let coin = holder::paid::coin_worth(&self.wallet, &hub, ask, quote.value);
        let coin = self.operation(coin).map_err(unavailable)?;
        let fitted = (u64::from(coin.fit.cap), u64::from(coin.fit.funded));
        if fitted != (quote.cap, quote.funded) || coin.to != quote.payout.address {
            return Err(LicashError::invalid(format!(
                "a coin of {} sat now opens a contract of {} sat, not {}: ask again",
                quote.value, fitted.0, quote.cap
            )));
        }
        let ticketed = self.ticketed(&quote.payout)?;
        let paid = holder::paid::pay(&self.wallet, self.wallet.path(), &coin, &ticketed);
        let paid = self.operation(paid).map_err(unavailable)?;
        tracing::info!(ticket = %paid.ticket, %hub, value = paid.value, "paying for a contract's coin");
        Ok(PaidContract {
            ticket: paid.ticket,
            hub,
            value: paid.value,
        })
    }

    /// The contracts paid for with notes not opened yet, nor given up: each
    /// waits for its payout's coin, then opens on it as
    /// [`Wallet::resume_contracts`] carries it on. The oldest first.
    pub fn paid_contracts(&self) -> Result<Vec<PaidContract>, LicashError> {
        let all = holder::paid::list(self.wallet.path()).map_err(failed)?;
        Ok(all
            .into_iter()
            .filter(|p| p.ended.is_none())
            .map(|p| PaidContract {
                ticket: p.ticket,
                hub: p.hub,
                value: p.value,
            })
            .collect())
    }

    /// The contracts, the newest first, as last seen.
    pub fn contracts(&self) -> Result<Vec<Contract>, LicashError> {
        let all = holder::list(self.wallet.path()).map_err(failed)?;
        self.listed(&all)
    }

    /// Carry on with the contracts being opened, see where the funding of
    /// each signed stands on `chain`, and carry on those forced closed:
    /// every contract, the newest first. While one is being opened, as
    /// last seen.
    pub fn resume_contracts(
        &self,
        chain: Arc<dyn ChainSource>,
    ) -> Result<Vec<Contract>, LicashError> {
        let Ok(_contracting) = self.contracting.try_lock() else {
            return self.contracts();
        };
        let chain = Chain(chain, self.wallet.network());
        if let Ok(tip) = self.runtime.block_on(licash_wallet::Blocks::height(&chain)) {
            self.saw(tip);
        }
        let all = holder::resume(&self.wallet, &chain, self.wallet.path());
        let all = self.runtime.block_on(all);
        // Carried on even if the others could not be: a forced close
        // has deadlines of its own. Its fees paid out of notes first, if
        // its coins pay too little.
        self.fund_recoveries(&chain);
        self.advance_recoveries(&chain);
        self.listed(&all.map_err(unavailable)?)
    }
}

impl Wallet {
    /// Open a contract at `hub` as `ask`ed, through `chain`, the wallet
    /// contracting.
    fn opened(
        &self,
        chain: Arc<dyn ChainSource>,
        hub: &str,
        ask: Ask,
    ) -> Result<Contract, LicashError> {
        let chain = Chain(chain, self.wallet.network());
        let tip = self.operation(licash_wallet::Blocks::height(&chain));
        self.saw(tip.map_err(|reason| LicashError::Unavailable { reason })?);
        let opened = holder::open_with(&self.wallet, &chain, self.wallet.path(), hub, ask);
        let opened = self.operation(opened).map_err(unavailable)?;
        // Protecting nothing before its funding is buried.
        Ok(self.contract(&opened, 0))
    }

    /// `hub`, a hub trusted that opens contracts, by its URL as contracts
    /// keep it, and its terms as its info says.
    fn contracting_hub(&self, hub: &str) -> Result<(String, licash_api::Contracts), LicashError> {
        let hub = hub.trim().trim_end_matches('/');
        let trusted = self.wallet.hubs()?.into_iter();
        let mut trusted = trusted.filter(|(url, _)| url.trim_end_matches('/') == hub);
        let Some((_, info)) = trusted.next() else {
            return Err(LicashError::invalid(format!("{hub} is no hub you use")));
        };
        match info.contracts {
            Some(terms) => {
                if let Some(range) = &terms.range {
                    check_range(range)?;
                }
                Ok((hub.to_owned(), terms))
            }
            None => Err(LicashError::invalid(format!("{hub} opens no contracts"))),
        }
    }

    /// The chain's height, as last seen at least: 0 if never.
    pub(super) fn saw(&self, tip: u32) {
        self.tip.fetch_max(tip, Ordering::Relaxed);
        // What its protected locks' preimages are revealed against.
        self.wallet.saw_tip(tip);
    }

    /// The chain's height as the wallet last saw it, or the last block it
    /// looked in: 0 if neither is known.
    pub(super) fn tip(&self) -> u32 {
        let looked = self.wallet.silent_next().ok().flatten();
        let looked = looked.map_or(0, |next| next.saturating_sub(1));
        self.tip.load(Ordering::Relaxed).max(looked)
    }

    /// Ask the hub at `url` for an invoice paying `amount`, protected where
    /// a contract of the wallet's there would claim its lock's notes should
    /// the hub keep them, at the chain's height last seen, and a coin of the
    /// wallet's activates the lock at the rate last read
    /// ([`holder::activation::protects`]); else trusting the hub. Saying
    /// `memo` to its payer, if given.
    pub(super) fn invoice_at(
        &self,
        url: &str,
        amount: u64,
        memo: Option<&str>,
    ) -> Result<licash_wallet::Invoice, licash_wallet::Error> {
        let rate = super::recoveries::last_rate();
        let protects = holder::activation::protects(
            &self.wallet,
            self.wallet.path(),
            url,
            amount,
            rate,
            self.tip(),
        );
        let protected = protects.unwrap_or_else(|e| {
            tracing::warn!("whether a contract protects an invoice: {e:#}");
            false
        });
        // Protected only against a height the wallet knows of itself.
        let protected = protected && matches!(self.wallet.tip(), Ok(Some(_)));
        let asked = self.wallet.invoice_saying(url, amount, memo, protected);
        self.operation(asked)
    }

    /// `all`, each with what it protects of the notes held now.
    fn listed(&self, all: &[holder::Contract]) -> Result<Vec<Contract>, LicashError> {
        let covers =
            holder::coverage(&self.wallet, self.wallet.path(), all, self.tip()).map_err(failed)?;
        let covered = |c: &holder::Contract| covers.get(&c.id).copied().unwrap_or(0);
        Ok(all.iter().map(|c| self.contract(c, covered(c))).collect())
    }

    fn contract(&self, c: &holder::Contract, covers: u64) -> Contract {
        let (tip, state) = (self.tip(), state(c, self.tip()));
        let step = match state {
            ContractState::Opening => Some(match (c.phase, holder::stepping(&c.id)) {
                // Its terms got: working out what it commits to on them.
                (Phase::Started, Some(took)) => OpeningStep::Preparing {
                    seconds: took.as_secs(),
                },
                (phase, _) => opening_step(phase),
            }),
            ContractState::Confirming => {
                // As deep as the wallet saw her coin's spend: F, which
                // spends it.
                let spent_at = self.wallet.silent_spent_at(&c.deposit).ok().flatten();
                let confirmations = confirmations(spent_at, tip);
                Some(OpeningStep::Confirming { confirmations })
            }
            _ => None,
        };
        let transfer = (matches!(state, ContractState::Opening))
            .then(|| holder::traffic(&c.id))
            .flatten()
            .map(|t| Transfer {
                bytes: t.bytes,
                seconds: t.since.elapsed().as_secs(),
                // As a hub keeps on signet or mainnet, until it builds one.
                expected: t.expected.unwrap_or(upload(10)).max(t.bytes),
            });
        Contract {
            id: hex(&c.id),
            hub: c.hub.clone(),
            state,
            step,
            transfer,
            mock: c.mock,
            cap: u64::from(c.cap),
            covers,
            price: c.price,
            funded: c.funded,
            funded_received: c.funded_received,
            paid_from: c.value,
            protects_until: c.assert_height,
            closes_at: c.close_height,
            funding: c.funding.map(|t| t.to_string()),
            created_at: c.created_at,
        }
    }

    /// Of `balance`, `held` at each hub, what contracts protect, and what
    /// the contracts being opened hold on Bitcoin: its `covered` and
    /// `opening`. `reserved` are the coins of the wallet's that pending
    /// transactions spend, by those transactions' ids, with their values.
    pub(super) fn contracted(
        &self,
        balance: &mut Balance,
        _held: &[licash_wallet::Balance],
        reserved: &[(Txid, u64)],
    ) -> Result<(), LicashError> {
        let all = holder::list(self.wallet.path()).map_err(failed)?;
        if !all.is_empty() {
            let covered = holder::coverage(&self.wallet, self.wallet.path(), &all, self.tip())
                .map_err(failed)?;
            contracted(balance, &all, covered.values().sum(), reserved);
        }
        Ok(())
    }

    /// The transactions contracts paid the wallet back by as they closed,
    /// each with its contract's hub: closed early with the hub, or forced
    /// closed. A coin of one is the wallet's own money back, not a payment.
    pub(super) fn returning(&self) -> Result<HashMap<Txid, String>, LicashError> {
        let all = holder::list(self.wallet.path()).map_err(failed)?;
        let recovered: Vec<_> = holder::recovery::recoveries(self.wallet.path())
            .map_err(failed)?
            .into_iter()
            .map(|r| {
                (
                    r.id,
                    [r.fold, r.payout, r.sweep].into_iter().flatten().collect(),
                )
            })
            .collect();
        Ok(returned(&all, &recovered))
    }

    /// Every contract, as a line of the history ([`activity`]).
    pub(super) fn contract_activities(&self) -> Result<Vec<Activity>, LicashError> {
        let all = holder::list(self.wallet.path()).map_err(failed)?;
        Ok(all.iter().map(activity).collect())
    }

    /// More of the line of the history of the contract `id`, if any.
    pub(super) fn contract_details(&self, id: &str) -> Result<Option<Details>, LicashError> {
        let all = holder::list(self.wallet.path()).map_err(failed)?;
        let found = all.into_iter().find(|c| hex(&c.id) == id);
        Ok(found.map(|c| Details::Contract {
            hub: c.hub,
            funding: c.funding.map(|f| f.to_string()),
        }))
    }

    /// The transactions funding contracts, those signed: their change is
    /// the wallet's, to keep on Bitcoin.
    pub(super) fn fundings(&self) -> Result<Vec<Txid>, LicashError> {
        let all = holder::list(self.wallet.path()).map_err(failed)?;
        Ok(all.iter().filter_map(|c| c.funding).collect())
    }

    /// The coins contracts being opened will deposit, not reserved for
    /// their funding yet: no move is to take them. Those older than an
    /// opening may take ([`holder::OPENS_WITHIN`]), given up, keep none.
    pub(super) fn opening_coins(&self) -> Result<Vec<OutPoint>, LicashError> {
        let all = holder::list(self.wallet.path()).map_err(failed)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let opening = all.iter().filter(|c| {
            c.abandoned.is_none()
                && c.phase < Phase::Funded
                && now - c.created_at < holder::OPENS_WITHIN
        });
        Ok(opening.map(|c| c.deposit).collect())
    }
}

/// Refuse malformed advertised ranges before choosing or pricing terms.
fn check_range(range: &licash_api::ContractRange) -> Result<(), LicashError> {
    if range.min_blocks > range.max_blocks || range.min_cap > range.max_cap {
        return Err(LicashError::invalid(
            "the hub offers an inverted contract range",
        ));
    }
    Ok(())
}

/// What a contract chosen within the checked `range` is at first: half
/// again `coin`, up to a size, over half a year of its network's blocks,
/// within the advertised bounds.
fn suggested(range: &licash_api::ContractRange, coin: Option<u64>) -> (u32, u32) {
    let blocks = (range.year_blocks / 2).clamp(range.min_blocks, range.max_blocks);
    let most = coin.and_then(|c| range.max_cap_for(c).map(|most| (c, most)));
    let cap = match most {
        Some((coin, most)) => {
            let half_again = coin.saturating_add(coin / 2);
            let up = licash_api::sizes().find(|&s| u64::from(s) >= half_again);
            up.unwrap_or(most).clamp(range.min_cap, most)
        }
        None => range.min_cap,
    };
    (cap, blocks)
}

/// The most of a coin a contract offered unasked costs: a tenth.
const SHARE: u64 = 10;

/// A hub letting the wallet choose terms: its URL and its range.
type Offering = (String, licash_api::ContractRange);

/// Of `hubs`, those to offer a contract at, paid from a `coin` of so many
/// sat, of the suggested terms ([`suggested`]) as the least protected, the
/// coin spent whole in it: the one protecting the most first, then the
/// cheapest. None whose price is past a [`SHARE`] of the coin, or that
/// takes no contract of the coin.
fn best(hubs: &[Offering], coin: u64) -> Vec<&str> {
    let mut offers: Vec<(&str, u32, u64)> = hubs
        .iter()
        .filter_map(|(hub, range)| {
            let (least, blocks) = suggested(range, Some(coin));
            // Its keyset is not known until it is asked: notes of every power
            // of two, as the hubs' are.
            let wide: Vec<u64> = (0..32).map(|i| 1u64 << i).collect();
            let fitted = holder::fit(
                &holder::Pricing::Range(range),
                blocks,
                coin,
                330,
                (&wide, 32),
                least,
            )?;
            let price = range.price(fitted.cap, blocks, fitted.funded);
            (price <= coin / SHARE).then_some((hub.as_str(), fitted.cap, price))
        })
        .collect();
    offers.sort_by_key(|&(_, cap, price)| (std::cmp::Reverse(cap), price));
    offers.into_iter().map(|(hub, ..)| hub).collect()
}

/// Of `balance`, the precisely claimable `covered`, and what contracts
/// being opened hold of the coins `reserved`
/// for transactions, by their ids: its `covered`, and its `opening` rather
/// than `moving`.
fn contracted(
    balance: &mut Balance,
    contracts: &[holder::Contract],
    covered: u64,
    reserved: &[(Txid, u64)],
) {
    balance.covered += covered;
    for c in contracts.iter().filter(|c| c.abandoned.is_none()) {
        let Some(funding) = c.funding else { continue };
        for (_, value) in reserved.iter().filter(|(by, _)| *by == funding) {
            // Its price paid once signed: the rest is her part, issued back.
            balance.moving = balance.moving.saturating_sub(*value);
            balance.opening += value.saturating_sub(c.price);
        }
    }
}

/// The transactions of `contracts` that paid the wallet back, each with
/// its contract's hub: a fold, or those of a forced close, `recovered` by
/// contract id.
fn returned(
    contracts: &[holder::Contract],
    recovered: &[([u8; 32], Vec<Txid>)],
) -> HashMap<Txid, String> {
    let mut by: HashMap<Txid, String> = contracts
        .iter()
        .filter_map(|c| c.folded.map(|txid| (txid, c.hub.clone())))
        .collect();
    for (id, txids) in recovered {
        let Some(c) = contracts.iter().find(|c| &c.id == id) else {
            continue;
        };
        by.extend(txids.iter().map(|txid| (*txid, c.hub.clone())));
    }
    by
}

fn hex(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why a contract whose funding can never confirm failed.
const DEAD: &str = "its funding can never confirm: its coin was spent otherwise";

/// `c` as a line of the history from the start of its opening: under way
/// while opened, then until its funding is in a block, when it has paid
/// its price; failed if given up short of signing it, saying why, or if
/// its funding can never confirm.
fn activity(c: &holder::Contract) -> Activity {
    let state = match (&c.abandoned, c.fate) {
        (Some(_), _) | (None, Some(Fate::Dead)) => State::Failed,
        (None, Some(Fate::Live)) if c.phase == Phase::Funded => State::Done,
        _ => State::Pending,
    };
    let detail = match (&c.abandoned, state) {
        (Some(why), _) => why.clone(),
        (None, State::Failed) => DEAD.into(),
        _ => c.hub.clone(),
    };
    Activity {
        id: hex(&c.id),
        kind: Kind::Contract,
        state,
        amount: c.price,
        fee: 0,
        detail,
        at: Some(c.created_at),
        memo: None,
        from: None,
        code: None,
    }
}

/// What an opening at `phase` waits on: what follows the last step done.
fn opening_step(phase: Phase) -> OpeningStep {
    match phase {
        Phase::Started => OpeningStep::Terms,
        Phase::Committed => OpeningStep::Choosing,
        Phase::Chosen => OpeningStep::Uploading,
        Phase::Consented => OpeningStep::Signatures,
        Phase::Signing => OpeningStep::Signing,
        Phase::Funded => OpeningStep::Confirming { confirmations: 0 },
    }
}

/// How deep a transaction in block `at`, if any, is at `tip`: 1 in the
/// tip, and at least 1 in a block the wallet saw, its tip behind.
fn confirmations(at: Option<u32>, tip: u32) -> u32 {
    at.map_or(0, |at| tip.saturating_sub(at) + 1)
}

/// Where `c` stands at `tip`.
fn state(c: &holder::Contract, tip: u32) -> ContractState {
    if let Some(reason) = &c.abandoned {
        return ContractState::Failed {
            reason: reason.clone(),
        };
    }
    if c.folded.is_some() {
        return ContractState::Closed;
    }
    match c.fate {
        Some(Fate::Dead) => ContractState::Failed {
            reason: DEAD.into(),
        },
        Some(Fate::Live) if tip >= c.close_height => ContractState::Closed,
        Some(Fate::Live) if tip >= c.assert_height => ContractState::Ending,
        Some(Fate::Live) => ContractState::Protecting,
        _ if c.phase < Phase::Funded => ContractState::Opening,
        _ => ContractState::Confirming,
    }
}

/// What a contract paid for with notes costs ([`Wallet::paid_contract_quote`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PaidContractQuote {
    pub hub: String,
    pub blocks: u32,
    /// The least cap asked, if any.
    pub least: Option<u64>,
    /// What the coin is worth: the price and the wallet's part.
    pub value: u64,
    /// The hub's fee, interest and reserve.
    pub price: u64,
    pub cap: u64,
    /// The wallet's part of the contract.
    pub funded: u64,
    /// The coin's payout to the wallet's own address: what it costs on top
    /// of its value, and through whom.
    pub payout: PayoutQuote,
}

/// A contract paid for with notes ([`Wallet::open_paid_contract`]): its
/// coin's payout, by its ticket, and the contract it opens once the wallet
/// found the coin.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PaidContract {
    /// The payout's ticket: its hash among the payouts.
    pub ticket: String,
    pub hub: String,
    /// What the coin is worth.
    pub value: u64,
}

fn unavailable(e: anyhow::Error) -> LicashError {
    LicashError::from_any(e, |reason| LicashError::Unavailable { reason })
}

fn failed(e: anyhow::Error) -> LicashError {
    LicashError::from_any(e, |reason| LicashError::Failed { reason })
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;

    use super::*;

    const HUB: &str = "https://hub.example";

    fn contract(id: u8, phase: Phase, fate: Option<Fate>) -> holder::Contract {
        holder::Contract {
            id: [id; 32],
            hub: HUB.into(),
            phase,
            mock: true,
            deposit: OutPoint::null(),
            value: 60_000,
            price: 23_000,
            cap: 4_096,
            assert_height: 360,
            close_height: 500,
            since: 200,
            funding: (phase == Phase::Funded).then(|| Txid::from_byte_array([id; 32])),
            fate,
            abandoned: None,
            created_at: 0,
            folded: None,
            funded: 0,
            funded_received: false,
        }
    }

    #[test]
    fn contracts_stand_as_their_phase_fate_and_the_chain_say() {
        let live = contract(1, Phase::Funded, Some(Fate::Live));
        assert_eq!(state(&live, 359), ContractState::Protecting);
        assert_eq!(state(&live, 360), ContractState::Ending);
        assert_eq!(state(&live, 500), ContractState::Closed);
        let state_of = |phase, fate| state(&contract(2, phase, fate), 300);
        assert_eq!(state_of(Phase::Consented, None), ContractState::Opening);
        assert_eq!(state_of(Phase::Funded, None), ContractState::Confirming);
        assert_eq!(
            state_of(Phase::Funded, Some(Fate::Open)),
            ContractState::Confirming
        );
        let dead = state_of(Phase::Funded, Some(Fate::Dead));
        assert!(matches!(dead, ContractState::Failed { .. }), "{dead:?}");
        let mut refused = contract(3, Phase::Committed, None);
        refused.abandoned = Some("refused".into());
        let reason = "refused".to_owned();
        assert_eq!(state(&refused, 300), ContractState::Failed { reason });
    }

    #[test]
    fn an_opening_waits_on_what_follows_its_last_step() {
        use OpeningStep::*;
        let steps = Phase::ALL.map(opening_step);
        let confirming = Confirming { confirmations: 0 };
        assert_eq!(
            steps,
            [Terms, Choosing, Uploading, Signatures, Signing, confirming]
        );
        // Its funding in no block yet, in the tip, deeper.
        assert_eq!(confirmations(None, 300), 0);
        assert_eq!(confirmations(Some(300), 300), 1);
        assert_eq!(confirmations(Some(298), 300), 3);
        assert_eq!(confirmations(Some(301), 300), 1);
    }

    #[test]
    fn what_a_contract_paid_back_is_known_by_its_fold_or_forced_close() {
        let txid = |b: u8| Txid::from_byte_array([b; 32]);
        let mut folded = contract(1, Phase::Funded, Some(Fate::Live));
        folded.folded = Some(txid(10));
        let mut forced = contract(2, Phase::Funded, Some(Fate::Live));
        forced.hub = "https://other.example".into();
        let live = contract(3, Phase::Funded, Some(Fate::Live));
        let recovered = [
            ([2; 32], vec![txid(20), txid(21)]),
            // A recovery of no contract kept: nothing to say it was.
            ([9; 32], vec![txid(90)]),
        ];
        let by = returned(&[folded, forced, live], &recovered);
        assert_eq!(by.len(), 3, "{by:?}");
        assert_eq!(by[&txid(10)], HUB);
        assert_eq!(by[&txid(20)], "https://other.example");
        assert_eq!(by[&txid(21)], "https://other.example");
    }

    #[test]
    fn contracts_are_in_the_history_from_their_opening_done_once_confirmed() {
        // Being opened: under way, at its hub, from its start.
        let opening = activity(&contract(1, Phase::Consented, None));
        assert_eq!(
            (opening.kind, opening.state, opening.detail.as_str()),
            (Kind::Contract, State::Pending, HUB)
        );
        assert_eq!(
            opening.at,
            Some(contract(1, Phase::Started, None).created_at)
        );
        // Given up short of signing: failed, saying why.
        let mut refused = contract(2, Phase::Chosen, None);
        refused.abandoned = Some("refused".into());
        let refused = activity(&refused);
        assert_eq!(
            (refused.state, refused.detail.as_str()),
            (State::Failed, "refused")
        );
        // Not done before its funding is signed, whatever its fate says.
        let early = activity(&contract(4, Phase::Signing, Some(Fate::Live)));
        assert_eq!(early.state, State::Pending);
        let line = |fate| activity(&contract(3, Phase::Funded, fate));
        let confirming = line(None);
        assert_eq!(
            (confirming.kind, confirming.state, confirming.amount),
            (Kind::Contract, State::Pending, 23_000)
        );
        assert_eq!(
            (confirming.id, confirming.detail),
            (hex(&[3; 32]), HUB.into())
        );
        assert_eq!(line(Some(Fate::Open)).state, State::Pending);
        assert_eq!(line(Some(Fate::Live)).state, State::Done);
        let dead = line(Some(Fate::Dead));
        assert_eq!((dead.state, dead.detail.as_str()), (State::Failed, DEAD));
    }

    #[test]
    fn balance_uses_claimable_coverage_instead_of_nominal_caps() {
        let contracts = [
            contract(1, Phase::Funded, Some(Fate::Live)),
            contract(2, Phase::Funded, Some(Fate::Live)),
            // Not yet, or no longer, protecting.
            contract(3, Phase::Funded, Some(Fate::Open)),
            contract(4, Phase::Consented, None),
        ];
        let covered = |claimable| {
            let mut balance = Balance::default();
            contracted(&mut balance, &contracts, claimable, &[]);
            balance.covered
        };
        assert_eq!(covered(68), 68);
        assert_eq!(covered(0), 0);
    }

    #[test]
    fn aggregate_coverage_preserves_opening_coin_accounting() {
        let ending = |id, assert_height| holder::Contract {
            assert_height,
            ..contract(id, Phase::Funded, Some(Fate::Live))
        };
        // The latest first by id, the earliest first by deadline.
        let contracts = [ending(1, 400), ending(2, 380), ending(3, 400)];
        let other = holder::Contract {
            hub: "https://other.example".into(),
            ..ending(4, 370)
        };
        let all = [&contracts[..], &[other]].concat();
        let mut balance = Balance {
            covered: 2,
            ..Balance::default()
        };
        contracted(&mut balance, &all, 68, &[]);
        assert_eq!(balance.covered, 70);
        assert_eq!(balance.opening, 0);
    }

    #[test]
    fn genuine_claimable_coverage_is_not_gated_on_phone_proving() {
        let genuine = holder::Contract {
            mock: false,
            ..contract(1, Phase::Funded, Some(Fate::Live))
        };
        let mock = contract(2, Phase::Funded, Some(Fate::Live));
        let covered = |contracts: &[holder::Contract]| {
            let mut balance = Balance::default();
            contracted(&mut balance, contracts, 68, &[]);
            balance.covered
        };
        assert_eq!(covered(std::slice::from_ref(&genuine)), 68);
        assert_eq!(covered(&[genuine, mock]), 68);
    }

    #[test]
    fn a_coin_paying_for_a_contract_shows_as_its_change_to_come() {
        let signed = contract(1, Phase::Funded, None);
        let f = signed.funding.unwrap();
        let other = Txid::from_byte_array([9; 32]);
        let mut balance = Balance {
            moving: 60_000 + 10_000,
            ..Balance::default()
        };
        let reserved = [(f, 60_000), (other, 10_000)];
        contracted(&mut balance, &[signed], 0, &reserved);
        assert_eq!((balance.moving, balance.opening), (10_000, 37_000));
    }

    fn range() -> licash_api::ContractRange {
        licash_api::ContractRange {
            min_cap: 131_071,
            max_cap: 67_108_863,
            min_blocks: 432,
            max_blocks: 26_280,
            per_coin: 2,
            reserve: 20_000,
            fee: 3_000,
            ppm_year: 10_000,
            ppm_year_funded: 0,
            year_blocks: licash_api::YEAR_BLOCKS,
        }
    }

    #[test]
    fn a_contract_chosen_is_at_first_half_again_the_largest_coin_for_half_a_year() {
        // The 10 M sat coin: 15 M sat, up to a size.
        assert_eq!(suggested(&range(), Some(10_000_000)), (16_777_215, 26_280));
        assert_eq!(suggested(&range(), Some(5_000_000)), (8_388_607, 26_280));
        // Within the hub's range and twice the coin.
        assert_eq!(suggested(&range(), Some(90_000_000)), (67_108_863, 26_280));
        assert_eq!(suggested(&range(), Some(100_000)), (131_071, 26_280));
        // No coin, or none large enough: the least.
        assert_eq!(suggested(&range(), None), (131_071, 26_280));
        assert_eq!(suggested(&range(), Some(2_000)), (131_071, 26_280));
        // Half a year, or as long as the hub lets.
        let short = licash_api::ContractRange {
            max_blocks: 4_000,
            ..range()
        };
        assert_eq!(suggested(&short, Some(10_000_000)).1, 4_000);
        // Half a year of Mutinynet's blocks, 20 times as many, as far as
        // the hub lets.
        let quick = licash_api::ContractRange {
            max_blocks: 1_000_000,
            year_blocks: licash::spend::ChainProfile::Mutinynet.blocks_a_year(),
            ..range()
        };
        assert_eq!(suggested(&quick, Some(10_000_000)).1, 525_600);
        let capped = licash_api::ContractRange {
            max_blocks: 52_560,
            ..quick
        };
        assert_eq!(suggested(&capped, Some(10_000_000)).1, 52_560);
    }

    #[test]
    fn a_contract_is_offered_where_it_protects_the_most_for_the_least() {
        let hub = |name: &str, range| (format!("https://{name}"), range);
        let dear = licash_api::ContractRange {
            ppm_year: 20_000,
            ..range()
        };
        let small = licash_api::ContractRange {
            max_cap: 1_000_000,
            ..range()
        };
        let hubs = [
            hub("small", small),
            hub("dear", dear),
            hub("cheap", range()),
        ];
        // The 10 M sat coin, spent whole: 16 777 215 sat protected where it
        // can be, for 106 886 sat at the cheaper. Where 1 M sat is the most
        // a contract protects, none takes so large a coin.
        assert_eq!(best(&hubs, 10_000_000), ["https://cheap", "https://dear"]);
        // A coin of 500 k sat is taken whole there too.
        assert_eq!(best(&hubs[..1], 500_000), ["https://small"]);
        // And 800 k sat is too much for the 524 287 sat it is suggested.
        assert!(best(&hubs[..1], 800_000).is_empty());
        // Costing past a tenth of the coin: none offered.
        assert!(best(&hubs, 200_000).is_empty());
        assert_eq!(best(&hubs[2..], 300_000), ["https://cheap"]);
        // A coin paying none: none.
        assert!(best(&hubs, 2_000).is_empty());
        assert!(best(&[], 10_000_000).is_empty());
    }

    #[test]
    fn a_contract_chosen_is_the_smallest_its_coin_takes_whole() {
        let range = crate::ContractRange::from(range());
        let wide: Vec<u64> = (0..32).map(|i| 1 << i).collect();
        let fit =
            |coin, least| crate::contract_fit(range, 26_280, coin, least, 330, wide.clone(), 32);
        let pays = |cap, funded: u64| funded + crate::contract_price(range, cap, 26_280, funded);
        // A coin of 70 k sat takes the least, 131 071 sat, all but the
        // price hers, and none of it left over.
        let small = fit(70_000, 131_071).unwrap();
        assert_eq!(small.cap, 131_071);
        assert!(70_000 - pays(small.cap, small.funded) < 330);
        // The 10 M sat coin, a size above half again itself asked at least:
        // that size, the coin spent whole.
        let big = fit(10_000_000, 16_777_215).unwrap();
        assert_eq!(big.cap, 16_777_215);
        assert!(10_000_000 - pays(big.cap, big.funded) < 330);
        // Too small a coin for the least, or beyond the largest contract.
        assert_eq!(fit(23_000, 131_071), None);
        assert_eq!(fit(1_000_000_000, 131_071), None);
        // A hub of notes 2 048 at most: 32 of them at most.
        let twos: Vec<u64> = (0..12).map(|i| 1 << i).collect();
        assert_eq!(crate::contract_fundable(twos.clone(), 32, 65_535), 64_512);
        if let Some(rounded) =
            crate::contract_fit(range, 26_280, 100_000, 131_071, 330, twos.clone(), 32)
        {
            assert_eq!(
                crate::contract_fundable(twos, 32, rounded.funded),
                rounded.funded
            );
        }
    }

    #[test]
    fn inverted_contract_ranges_are_refused_before_suggesting_terms() {
        assert!(check_range(&range()).is_ok());
        let mut inverted = range();
        inverted.min_blocks = inverted.max_blocks + 1;
        assert!(check_range(&inverted).is_err());
        let mut inverted = range();
        inverted.min_cap = inverted.max_cap + 1;
        assert!(check_range(&inverted).is_err());
        let mut single = range();
        single.min_blocks = single.max_blocks;
        single.min_cap = single.max_cap;
        assert!(check_range(&single).is_ok());
        assert_eq!(
            suggested(&single, None),
            (single.min_cap, single.min_blocks)
        );
    }

    #[test]
    fn the_app_prices_a_contract_chosen_as_its_hub_does() {
        let range = crate::ContractRange::from(range());
        assert_eq!(range.api(), super::tests::range());
        // 16 777 215 sat for half a year at 1% a year, over the reserve
        // and fee.
        assert_eq!(crate::contract_price(range, 16_777_215, 26_280, 0), 106_886);
        assert_eq!(crate::contract_price(range, 131_071, 1_000, 0), 23_024);
        // Half of it hers: interest on the hub's half only.
        let fee = crate::contract_fee(range, 16_777_215, 26_280, 8_388_607);
        assert_eq!(
            (fee.opening, fee.interest, fee.interest_funded),
            (3_000, 41_943, 0)
        );
        assert_eq!(
            crate::contract_price(range, 16_777_215, 26_280, 8_388_607),
            20_000 + 3_000 + 41_943
        );
        assert_eq!(crate::contract_sizes(range).len(), 10);
        // A cap past what a hub could offer: priced as the most.
        let most = crate::contract_price(range, u64::from(u32::MAX), 26_280, 0);
        assert_eq!(crate::contract_price(range, u64::MAX, 26_280, 0), most);
        assert_eq!(crate::contract_max_cap(range, 10_000_000), Some(16_777_215));
        assert_eq!(crate::contract_max_cap(range, 65_535), None);
    }
}
