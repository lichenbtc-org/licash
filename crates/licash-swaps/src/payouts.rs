//! Payouts on Bitcoin ([`swaps::ChainRequest`]): the provider pays a
//! client's lock at one of its hubs out as a coin on chain, a reverse
//! submarine swap.
//!
//! A client locks a coin's value and the provider's fees to the provider at
//! hub `from`, then asks for the payout. The provider checks that lock as
//! its hub holds it, draws a refund key and records the payout, then pays
//! the coin of its wallet's coins ([`Wallet::spend_silent`]) to an [`Htlc`]
//! under the lock's hash: claimed with the client's key and the preimage,
//! taken back with the provider's key after its timeout, [`swaps::Chain`]'s
//! margin blocks before the client's lock expires. Once the client claimed
//! the coin, revealing the preimage on chain, the provider claims the
//! client's lock with it. Unclaimed, the provider takes the coin back once
//! timed out.
//!
//! Each transaction races a deadline, past which the provider could lose
//! the coin to a client who also keeps its lock: so each is paid at the
//! chain's estimate, made again at a higher rate as the deadline nears
//! ([`deadline`]). The coin is paid at the estimate when taken (declined on
//! mainnet without one); in no block [`CANCEL_LEFT`] blocks before its
//! timeout, it is canceled ([`Wallet::replace_silent`]) lest it be mined
//! after the client's lock expires; its refund is made again until it is
//! mined before the client's lock expires, all of the coin at most.
//!
//! The provider's wallet watches the chain for its coins from a block its
//! operator chose ([`Wallet::watch_silent`], without a hub): coins paid to
//! its fallback addresses ([`Wallet::fallback_address`]), the change of its
//! spends and the coins it takes back. [`Provider::follow_payouts`] scans
//! for them and broadcasts the provider's transactions until a block holds
//! them.
//!
//! [`Wallet::spend_silent`]: licash_wallet::Wallet::spend_silent
//! [`Wallet::watch_silent`]: licash_wallet::Wallet::watch_silent
//! [`Wallet::fallback_address`]: licash_wallet::Wallet::fallback_address
//! [`Wallet::replace_silent`]: licash_wallet::Wallet::replace_silent

use std::{future::Future, sync::PoisonError};

use bitcoin::{
    absolute::LOCK_TIME_THRESHOLD,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey},
    Amount, BlockHash, FeeRate, OutPoint, ScriptBuf, Transaction,
};
use licash::spend::{ChainProfile, ProposalId};
use licash_api::{
    swaps::{self, ChainRequest, ChainSwap},
    Funding, Hex, Problem,
};
use licash_onchain::{deadline, deposit::Htlc, silent_claim::Share};
use licash_wallet::{first_spend, payout_depth, Blocks, Payee, Transport};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension};

use crate::{declined, emit, now, refused, unavailable, Error, Hold, Notice, Provider, Row, Stage};

/// Blocks a payout's coin leaves at least, past the confirmations its
/// client waits for, before it times out: for the client to claim it.
pub const PAYOUT_ROOM: u32 = 18;

/// Blocks scanned for the wallet's coins at once.
const SCAN_BATCH: u32 = 100;

/// Blocks before a payout's coin times out from which, in no block yet, it
/// is canceled: its coins paid back to the provider in its place, before
/// it could be mined too late for the provider.
pub const CANCEL_LEFT: u32 = 12;

/// Virtual bytes of a payout's coin and of its refund, about: what a
/// payout whose client never claims costs the provider, at its rate.
pub const NO_SHOW_VSIZE: u64 = 320;

/// How long a payout refunded, its client never claiming, counts against
/// its hub ([`PayoutLimits::no_shows`]): a day.
const NO_SHOW_FOR: i64 = 24 * 3600;

/// What payouts whose clients never claim their coins may cost a
/// provider: each costs the fees of its coin and of the refund taking it
/// back, and holds its coin until it times out, at no cost to its client,
/// whose lock expires back to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutLimits {
    /// Payouts from one hub refunded within a day from which more from
    /// there are declined, as a client paying from there never claims.
    pub no_shows: u32,
    /// Payouts under way at once, from which it pays out nothing more.
    pub open: u64,
    /// The most blocks after the chain's tip a payout's coin may time out.
    pub max_blocks: u32,
    /// The least a payout's coin is worth: this many times what it and its
    /// refund pay in fees ([`NO_SHOW_VSIZE`]) at the rate it is paid at.
    pub fee_share: u64,
}

impl PayoutLimits {
    /// The least a payout's coin is worth at `rate`, at `min` at least.
    fn least(&self, min: u64, rate: FeeRate) -> u64 {
        let fees = rate
            .fee_vb(NO_SHOW_VSIZE)
            .map_or(u64::MAX, |fee| fee.to_sat());
        fees.saturating_mul(self.fee_share).max(min)
    }
}

/// Bitcoin, as a provider paying out on it sees it: the blocks a wallet
/// reads ([`Blocks`]), a way to broadcast, and the fee rates it estimates.
pub trait Chain: Blocks + Sync {
    /// Hand `tx` to the network.
    fn broadcast(&self, tx: &Transaction) -> impl Future<Output = Result<(), String>> + Send;

    /// The fee rate a transaction confirms at within `blocks` blocks, as
    /// the chain estimates it, if it does.
    fn fee_rate(&self, blocks: u16)
        -> impl Future<Output = Result<Option<FeeRate>, String>> + Send;
}

/// The rate to pay a payout's coin at, `left` blocks before it would be
/// canceled ([`deadline::rate`]), at the operator's rate `floor` at least:
/// none without the chain's `estimate` on mainnet, where a rate fixed
/// beforehand could leave it unmined, to be canceled at a loss.
fn funding_rate(
    estimate: Option<FeeRate>,
    floor: FeeRate,
    left: u32,
    network: ChainProfile,
) -> Option<FeeRate> {
    if estimate.is_none() && network == ChainProfile::Core30Mainnet {
        return None;
    }
    Some(deadline::rate(estimate, floor, left))
}

/// A payout's coin as recorded.
struct Coin {
    htlc: Htlc,
    refund_key: SecretKey,
    funding: Option<(Transaction, u32)>,
    refund: Option<Transaction>,
    scanned: Option<u32>,
}

impl Coin {
    fn outpoint(&self) -> Option<OutPoint> {
        self.funding
            .as_ref()
            .map(|(tx, vout)| OutPoint::new(tx.compute_txid(), *vout))
    }
}

fn x_only(key: &SecretKey) -> XOnlyPublicKey {
    key.x_only_public_key(&Secp256k1::new()).0
}

fn random_key() -> SecretKey {
    loop {
        let mut bytes = [0; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            return key;
        }
    }
}

/// A fee rate in sat per 1000 virtual bytes, as [`swaps::Chain::rate`].
fn rate(per_kvb: u64) -> FeeRate {
    FeeRate::from_sat_per_kwu(per_kvb.div_ceil(4))
}

/// Payouts taken.
impl<T: Transport> Provider<T> {
    /// Pay out on Bitcoin what pays this provider at hub `from`, on
    /// `terms`: the provider pays nothing out on chain otherwise.
    pub fn pay_out(mut self, terms: swaps::Chain) -> Self {
        self.payouts = Some(terms);
        self
    }

    /// What it pays out on Bitcoin, as its operator set it.
    pub fn payout_terms(&self) -> Option<&swaps::Chain> {
        self.payouts.as_ref()
    }

    /// Bound what payouts whose clients never claim cost it to `limits`:
    /// unbounded until bounded.
    pub fn limit_payouts(mut self, limits: PayoutLimits) -> Self {
        self.payout_limits = Some(limits);
        self
    }

    /// What it pays out on Bitcoin now: nothing until its wallet watches
    /// the chain, and coins up to what its coins free now pay.
    pub(crate) fn chain_info(&self) -> Result<Option<swaps::Chain>, Error> {
        let Some(terms) = self.payouts else {
            return Ok(None);
        };
        if self.wallet.silent_next()?.is_none() {
            return Ok(None);
        }
        let mut min = terms.min;
        if let Some(limits) = self.payout_limits {
            if self.open_payouts()? >= limits.open {
                return Ok(None);
            }
            let rate = *self
                .payout_rate
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            min = limits.least(min, rate.unwrap_or(self.floor()).max(self.floor()));
        }
        Ok(Some(swaps::Chain {
            min,
            max: terms.max.min(self.free_on_chain(&terms)?),
            ..terms
        }))
    }

    /// The operator's rate: the least the provider pays its transactions.
    fn floor(&self) -> FeeRate {
        rate(self.payouts.map_or(1_000, |t| t.rate))
    }

    /// The fee rate `chain` estimates for [`deadline::target`] of `left`
    /// blocks, if it does.
    async fn estimate(&self, chain: &impl Chain, left: u32) -> Option<FeeRate> {
        chain
            .fee_rate(deadline::target(left))
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("no fee estimate: {e}");
                None
            })
    }

    /// The rate to pay a transaction at, `left` blocks before its deadline
    /// ([`deadline::rate`]).
    pub(crate) async fn deadline_rate(&self, chain: &impl Chain, left: u32) -> FeeRate {
        deadline::rate(self.estimate(chain, left).await, self.floor(), left)
    }

    /// What the wallet's coins no transaction spends pay, less the fee of
    /// spending them all at the terms' rate: the most a coin is worth now.
    fn free_on_chain(&self, terms: &swaps::Chain) -> Result<u64, Error> {
        let free: Vec<u64> = self
            .wallet
            .silent_coins()?
            .into_iter()
            .filter(|c| c.spending.is_none())
            .map(|c| c.value)
            .collect();
        // A key spend of each coin, and a coin and change, taproot both.
        let vsize = 11 + 58 * free.len() as u64 + 2 * 43;
        let fee = vsize.saturating_mul(terms.rate).div_ceil(1000);
        Ok(free.iter().sum::<u64>().saturating_sub(fee))
    }

    /// Take the payout `request` asks for, or answer where it stands if
    /// taken already. Declined unless the client's lock, as its hub holds
    /// it, pays the provider the coin's value and its fees, unsettled, and
    /// leaves the coin [`PAYOUT_ROOM`] blocks past its client's
    /// confirmations at least before it times out, [`swaps::Chain`]'s
    /// margin before the lock expires; or if the provider's coins pay too
    /// little now. `chain` is the provider's view of Bitcoin, which the
    /// coin is broadcast to.
    pub async fn take_payout(
        &self,
        request: &ChainRequest,
        chain: &impl Chain,
    ) -> Result<ChainSwap, Problem> {
        let id = request.lock()?;
        let key = *id.as_bytes();
        let scan = blinded_scan(request)?;
        if let Some(row) = self.row(&key).map_err(unavailable)? {
            return self.payout_again(&row, request, scan.as_ref());
        }
        let Some(terms) = self.chain_info().map_err(unavailable)? else {
            return Err(declined("no payouts on Bitcoin"));
        };
        if request.value < terms.min || request.value > terms.max {
            return Err(declined(format!(
                "coins of {} to {} now",
                terms.min, terms.max
            )));
        }
        let claim = XOnlyPublicKey::from_slice(&request.claim()?)
            .map_err(|_| Problem::invalid("the claim key is no key"))?;
        let hubs = self.wallet.hubs().map_err(unavailable)?;
        let Some((from, _)) = hubs.iter().find(|(_, info)| info.address == request.from) else {
            return Err(declined("no payouts from this hub"));
        };
        let Some(_hold) = Hold::take(&self.busy, key) else {
            return Err(unavailable("the payout is under way"));
        };
        let incoming = self
            .wallet
            .incoming(from, &hex::encode(key))
            .await
            .map_err(refused)?;
        let due = terms.pays(request.value);
        if incoming.amount < due {
            return Err(declined(format!(
                "the lock pays {}, the payout {due}",
                incoming.amount
            )));
        }
        if incoming.settled.is_some() || incoming.preimage.is_some() {
            return Err(declined("the lock is settled"));
        }
        let tip = chain.height().await.map_err(unavailable)?;
        let tip = tip.max(incoming.height);
        let timeout = incoming.expiry.saturating_sub(terms.margin);
        let room = tip
            .saturating_add(payout_depth(self.wallet.network()))
            .saturating_add(PAYOUT_ROOM);
        if timeout < room || timeout >= LOCK_TIME_THRESHOLD {
            return Err(declined(format!(
                "the lock expires at {}: too soon to time a coin out {} blocks earlier",
                incoming.expiry, terms.margin
            )));
        }
        let limits = self.payout_limits;
        if let Some(most) = limits.map(|l| l.max_blocks) {
            if timeout.saturating_sub(tip) > most {
                return Err(declined(format!(
                    "the lock expires at {}: a coin timed out {} blocks earlier would be held \
                     more than {most} blocks",
                    incoming.expiry, terms.margin
                )));
            }
        }
        // To confirm before it would be canceled.
        let left = timeout.saturating_sub(CANCEL_LEFT).saturating_sub(tip);
        let estimate = self.estimate(chain, left).await;
        let Some(rate) = funding_rate(estimate, self.floor(), left, self.wallet.network()) else {
            return Err(declined("no fee estimate now"));
        };
        if let Some(limits) = limits {
            *self
                .payout_rate
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(rate);
            let least = limits.least(terms.min, rate);
            if request.value < least {
                return Err(declined(format!("coins of {least} to {} now", terms.max)));
            }
        }
        let refund_key = random_key();
        let htlc = Htlc {
            hash: incoming.hash,
            claim,
            refund: x_only(&refund_key),
            timeout,
            wait: None,
            sized: true,
        };
        let taken = Taken {
            from,
            value: request.value,
            fee: due - request.value,
            paid: incoming.amount,
            expiry_from: incoming.expiry,
        };
        let funding = self.fund(&key, &taken, &htlc, &refund_key, &terms, rate)?;
        if let Some(tx) = funding {
            if let Err(e) = chain.broadcast(&tx).await {
                tracing::warn!(id = %hex::encode(key), "payout's coin not broadcast yet: {e}");
            }
        }
        let answer = self
            .payout_answer(&key)
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("the payout is not recorded"))?;
        with_share(answer, scan.as_ref(), &refund_key)
    }

    /// The payout `row` asked for again: where it stands, if it is the
    /// same.
    fn payout_again(
        &self,
        row: &Row,
        request: &ChainRequest,
        scan: Option<&PublicKey>,
    ) -> Result<ChainSwap, Problem> {
        let hubs = self.wallet.hubs().map_err(unavailable)?;
        let from = hubs
            .iter()
            .find(|(u, _)| *u == row.from)
            .map(|(_, i)| i.address);
        let coin = self.coin(&row.id).map_err(unavailable)?;
        let coin = coin.filter(|c| Some(c.htlc.claim.serialize()) == request.claim().ok());
        let (true, true, true, Some(coin)) = (
            row.chain,
            from == Some(request.from),
            row.amount == request.value,
            coin,
        ) else {
            return Err(declined("another swap of this lock"));
        };
        let answer = self
            .payout_answer(&row.id)
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("the payout is not recorded"))?;
        with_share(answer, scan, &coin.refund_key)
    }

    /// Record the payout `id` on `taken`, its coin `htlc`, and pay the coin
    /// of the wallet's coins at `rate`, if they pay enough: the coin, for
    /// the caller to broadcast, unless the payout failed. Recorded before
    /// the coin is made, which is recorded once made.
    fn fund(
        &self,
        id: &[u8; 32],
        taken: &Taken<'_>,
        htlc: &Htlc,
        refund_key: &SecretKey,
        terms: &swaps::Chain,
        rate: FeeRate,
    ) -> Result<Option<Transaction>, Problem> {
        let _taking = self.taking.lock().unwrap_or_else(PoisonError::into_inner);
        self.admit(taken.from, taken.paid)?;
        if let Some(limits) = self.payout_limits {
            if self.open_payouts().map_err(unavailable)? >= limits.open {
                return Err(declined("too many payouts under way now"));
            }
            let no_shows = self.no_shows(taken.from).map_err(unavailable)?;
            if no_shows >= u64::from(limits.no_shows) {
                tracing::warn!(
                    from = taken.from,
                    no_shows,
                    "payouts from a hub declined: too many of its clients never claimed lately"
                );
                return Err(declined(format!(
                    "too many payouts from hub {} went unclaimed lately",
                    taken.from
                )));
            }
        }
        if self.free_on_chain(terms).map_err(unavailable)? < taken.value {
            return Err(declined("the provider holds too little on chain now"));
        }
        let script = htlc.script_pubkey();
        let to = format!("bitcoin:{}", licash_onchain::network(self.wallet.network()));
        let notice = Notice::Accepted {
            id: hex::encode(id),
            amount: taken.value,
            fee: taken.fee,
            from: taken.from.to_owned(),
            to: to.clone(),
        };
        let recorded = self.store.write(|tx| {
            let at = now();
            let inserted = tx.execute(
                "INSERT INTO provider_swaps (id, hash, from_url, to_url, address, amount, fee, paid,
                    expiry_from_height, expiry_height, state, kind, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'accepted', 'chain', ?11, ?11)
                 ON CONFLICT DO NOTHING",
                params![
                    id,
                    htlc.hash,
                    taken.from,
                    to,
                    script.as_bytes(),
                    crate::store::sat(taken.value)?,
                    crate::store::sat(taken.fee)?,
                    crate::store::sat(taken.paid)?,
                    taken.expiry_from,
                    htlc.timeout,
                    at
                ],
            )?;
            if inserted == 1 {
                tx.execute(
                    "INSERT INTO provider_payouts (id, claim_key, refund_key) VALUES (?1, ?2, ?3)",
                    params![id, htlc.claim.serialize(), refund_key.secret_bytes()],
                )?;
                emit(tx, &notice)?;
            }
            Ok(inserted == 1)
        });
        match recorded {
            Ok(true) => {}
            Ok(false) => return Err(declined("a swap under this hash was taken before")),
            Err(e) => return Err(unavailable(e)),
        }
        tracing::info!(
            id = %hex::encode(id), from = taken.from, value = taken.value, fee = taken.fee,
            timeout = htlc.timeout, "payout accepted"
        );
        let paid = self
            .wallet
            .spend_silent(Payee::Script(script.clone()), Some(taken.value), rate);
        let row = self.row(id).map_err(unavailable)?.expect("recorded");
        let tx = match paid {
            Ok(tx) => tx,
            Err(e) => {
                self.fail(id, &row, &format!("no coin paid: {e}"))
                    .map_err(unavailable)?;
                return Ok(None);
            }
        };
        self.set_funding(id, &tx, &script, taken.value)
            .map_err(unavailable)?;
        Ok(Some(tx))
    }

    /// Record `tx`, the wallet's, as the coin of the payout `id`: its
    /// output paying `value` to `script`.
    fn set_funding(
        &self,
        id: &[u8; 32],
        tx: &Transaction,
        script: &ScriptBuf,
        value: u64,
    ) -> Result<(), Error> {
        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == *script && o.value == Amount::from_sat(value))
            .ok_or_else(|| licash_wallet::Error::Invalid("a coin paying no payout".into()))?;
        self.store.write(|t| {
            t.execute(
                "INSERT INTO provider_payout_fundings (id, tx, vout) VALUES (?1, ?2, ?3)
                 ON CONFLICT (id) DO NOTHING",
                params![id, serialize(tx), vout as u32],
            )?;
            Ok(())
        })
    }
}

/// What the provider checked of a client's lock for a payout.
struct Taken<'a> {
    from: &'a str,
    value: u64,
    fee: u64,
    paid: u64,
    expiry_from: u32,
}

/// The blinded scan key `request` asks the provider's share of, if any.
fn blinded_scan(request: &ChainRequest) -> Result<Option<PublicKey>, Problem> {
    request
        .scan()?
        .map(|s| PublicKey::from_slice(&s).map_err(|_| Problem::invalid("the scan key is no key")))
        .transpose()
}

/// `answer` with the share of `scan` by `refund_key`, if asked: the same
/// each time asked, of the same key.
fn with_share(
    mut answer: ChainSwap,
    scan: Option<&PublicKey>,
    refund_key: &SecretKey,
) -> Result<ChainSwap, Problem> {
    if let Some(scan) = scan {
        let share = Share::new(refund_key, scan).map_err(|e| Problem::invalid(e.to_string()))?;
        answer.share = Some(swaps::Share {
            point: Hex(share.point.serialize().to_vec()),
            e: Hex(share.e.to_vec()),
            s: Hex(share.s.to_vec()),
        });
    }
    Ok(answer)
}

/// What the provider recorded of payouts.
impl<T: Transport> Provider<T> {
    /// The payout of the client's lock `id`, as its client is told.
    pub fn payout(&self, id: &ProposalId) -> Result<Option<ChainSwap>, Error> {
        self.payout_answer(id.as_bytes())
    }

    fn payout_answer(&self, id: &[u8; 32]) -> Result<Option<ChainSwap>, Error> {
        let (Some(row), Some(coin)) = (self.row(id)?, self.coin(id)?) else {
            return Ok(None);
        };
        if !row.chain {
            return Ok(None);
        }
        let funding = match (&coin.funding, self.funding_height(&coin)?) {
            (Some((tx, vout)), Some(height)) => Some(Funding {
                txid: tx.compute_txid().to_string(),
                vout: *vout,
                height,
            }),
            _ => None,
        };
        Ok(Some(ChainSwap {
            id: Hex(id.to_vec()),
            state: row.stage.state(),
            value: row.amount,
            refund: Hex(coin.htlc.refund.serialize().to_vec()),
            timeout: coin.htlc.timeout,
            funding,
            txid: coin
                .funding
                .as_ref()
                .map(|(tx, _)| tx.compute_txid().to_string()),
            reason: row.reason.clone(),
            share: None,
        }))
    }

    /// The block the coin is in, as the wallet's last scan saw it.
    fn funding_height(&self, coin: &Coin) -> Result<Option<u32>, Error> {
        let Some((tx, _)) = &coin.funding else {
            return Ok(None);
        };
        let txid = tx.compute_txid();
        let spends = self
            .wallet
            .silent_spends_paying(&coin.htlc.script_pubkey())?;
        Ok(spends
            .iter()
            .find(|s| s.tx.compute_txid() == txid)
            .and_then(|s| s.height))
    }

    fn coin(&self, id: &[u8; 32]) -> Result<Option<Coin>, Error> {
        type Raw = (
            [u8; 32],
            u32,
            [u8; 32],
            [u8; 32],
            Option<Vec<u8>>,
            Option<u32>,
            Option<Vec<u8>>,
            Option<u32>,
            Vec<u8>,
        );
        let raw: Option<Raw> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT s.hash, s.expiry_height, p.claim_key, p.refund_key, f.tx,
                    f.vout, p.refund_tx, c.height, s.address
                 FROM provider_payouts p JOIN provider_swaps s ON s.id = p.id
                 LEFT JOIN provider_payout_fundings f ON f.id = p.id
                 LEFT JOIN provider_payout_scans c ON c.id = p.id
                 WHERE p.id = ?1",
                [id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )
            .optional()?)
        })?;
        let Some((hash, timeout, claim, refund_key, funding, vout, refund, scanned, address)) = raw
        else {
            return Ok(None);
        };
        let bad = |what: &str| licash_wallet::Error::Invalid(format!("a payout's {what}"));
        let refund_key = SecretKey::from_slice(&refund_key).map_err(|_| bad("refund key"))?;
        let terms = Htlc {
            hash,
            claim: XOnlyPublicKey::from_slice(&claim).map_err(|_| bad("claim key"))?,
            refund: x_only(&refund_key),
            timeout,
            wait: None,
            sized: true,
        };
        // As its coin was made: unsized by a provider before sized coins.
        let htlc = terms
            .sized_or_not()
            .into_iter()
            .find(|h| h.script_pubkey().as_bytes() == address)
            .ok_or_else(|| bad("coin of other terms than its own"))?;
        let tx = |raw: Option<Vec<u8>>| -> Result<Option<Transaction>, Error> {
            raw.map(|raw| deserialize(&raw).map_err(|_| bad("transaction").into()))
                .transpose()
        };
        let funding = match (tx(funding)?, vout) {
            (Some(tx), Some(vout)) => Some((tx, vout)),
            _ => None,
        };
        Ok(Some(Coin {
            htlc,
            refund_key,
            funding,
            refund: tx(refund)?,
            scanned,
        }))
    }
}

/// Payouts taken on.
impl<T: Transport> Provider<T> {
    /// Take every payout under way on, `chain` the provider's view of
    /// Bitcoin: scan for the wallet's coins, broadcast its transactions in
    /// no block yet, and follow each coin until its client's claim reveals
    /// the preimage, which claims the client's lock, or the provider takes
    /// it back once timed out. The payouts that could not move now, by id
    /// and why; `chain` if the scan failed.
    pub async fn follow_payouts(&self, chain: &impl Chain) -> Result<Vec<(String, String)>, Error> {
        let mut pending = Vec::new();
        if let Err(e) = self.scan(chain).await {
            tracing::warn!("no scan for the provider's coins: {e}");
            pending.push(("chain".to_owned(), e.to_string()));
        }
        for tx in self.wallet.silent_spends()? {
            if let Err(e) = chain.broadcast(&tx).await {
                tracing::debug!(txid = %tx.compute_txid(), "not broadcast: {e}");
            }
        }
        let open: Vec<[u8; 32]> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT id FROM provider_swaps WHERE kind = 'chain' AND state IN ('accepted', 'locked')
                 ORDER BY created_at, rowid",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        for id in open {
            let Some(_hold) = Hold::take(&self.busy, id) else {
                continue;
            };
            if let Err(e) = self.follow_payout(&id, chain).await {
                tracing::warn!(id = %hex::encode(id), "payout pending: {e}");
                pending.push((hex::encode(id), e.to_string()));
            }
        }
        // Refunded lately: until their refunds are buried.
        let refunded: Vec<[u8; 32]> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT s.id FROM provider_swaps s
                    JOIN provider_payout_scans a ON a.id = s.id AND a.hash IS NOT NULL
                 WHERE s.kind = 'chain' AND s.state = 'refunded'
                 ORDER BY s.created_at, s.rowid",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        for id in refunded {
            let Some(_hold) = Hold::take(&self.busy, id) else {
                continue;
            };
            if let Err(e) = self.recheck_refund(&id, chain).await {
                tracing::warn!(id = %hex::encode(id), "refund not looked at again: {e}");
                pending.push((hex::encode(id), e.to_string()));
            }
        }
        Ok(pending)
    }

    /// Payouts from the hub at `from`, by any URL the wallet knows it by,
    /// refunded within [`NO_SHOW_FOR`]: their clients never claimed.
    fn no_shows(&self, from: &str) -> Result<u64, Error> {
        let urls = self.wallet.hub_urls(from)?;
        let listed = serde_json::to_string(&urls).map_err(|e| Error::Setup(e.to_string()))?;
        self.store.read(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM provider_swaps WHERE kind = 'chain' AND state = 'refunded'
                    AND updated_at >= ?2 AND from_url IN (SELECT value FROM json_each(?1))",
                params![listed, now() - NO_SHOW_FOR],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
    }

    /// Payouts under way, which only [`Provider::follow_payouts`] takes on.
    pub fn open_payouts(&self) -> Result<u64, Error> {
        self.store.read(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM provider_swaps WHERE kind = 'chain'
                 AND state IN ('accepted', 'locked')",
                [],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
    }

    async fn scan(&self, chain: &impl Chain) -> Result<(), Error> {
        if self.wallet.silent_next()?.is_none() {
            return Ok(());
        }
        loop {
            let scanned = self.wallet.scan_silent(None, chain, SCAN_BATCH).await?;
            if scanned.next > scanned.height {
                return Ok(());
            }
        }
    }

    async fn follow_payout(&self, id: &[u8; 32], chain: &impl Chain) -> Result<(), Error> {
        let (Some(row), Some(coin)) = (self.row(id)?, self.coin(id)?) else {
            return Ok(());
        };
        match row.stage {
            Stage::Accepted if coin.funding.is_none() => {
                // Stopped after the wallet paid the coin, or before.
                let script = coin.htlc.script_pubkey();
                let spends = self.wallet.silent_spends_paying(&script)?;
                match spends.first() {
                    Some(spend) => self.set_funding(id, &spend.tx, &script, row.amount),
                    None => self.fail(id, &row, "stopped before paying the coin"),
                }
            }
            Stage::Accepted => {
                if self.funding_height(&coin)?.is_none() {
                    return self.cancel_late(id, &row, &coin, chain).await;
                }
                self.advance(id, Stage::Accepted, Stage::Locked, None, None)?;
                tracing::info!(id = %hex::encode(id), "payout's coin confirmed");
                self.watch_coin(id, &row, &coin, chain).await
            }
            Stage::Locked => self.watch_coin(id, &row, &coin, chain).await,
            _ => Ok(()),
        }
    }

    /// Cancel the coin of the payout `row`, in no block yet, once
    /// [`CANCEL_LEFT`] blocks or fewer are left before it times out: mined
    /// later, its client could claim it once the provider can no longer
    /// claim the client's lock. Its coins are paid back to the provider in
    /// its place ([`Wallet::replace_silent`]), made again at a higher rate
    /// as the blocks left to the timeout run out. The payout fails once the
    /// cancel is buried; mined after all, the coin is taken on as ever.
    ///
    /// [`Wallet::replace_silent`]: licash_wallet::Wallet::replace_silent
    async fn cancel_late(
        &self,
        id: &[u8; 32],
        row: &Row,
        coin: &Coin,
        chain: &impl Chain,
    ) -> Result<(), Error> {
        let Some((funding, _)) = &coin.funding else {
            return Ok(());
        };
        let Some(input) = funding.input.first() else {
            return Ok(());
        };
        let Some((by, at)) = self.wallet.silent_spender(&input.previous_output)? else {
            // Its coins' block replaced: waited for.
            return Ok(());
        };
        let txid = funding.compute_txid();
        let tip = chain.height().await.map_err(licash_wallet::Error::Chain)?;
        if let Some(at) = at {
            let need = payout_depth(self.wallet.network());
            if by != txid && confirmations(tip, at) >= need {
                tracing::info!(id = %hex::encode(id), %by, "payout's coin canceled");
                return self.fail(id, row, "its coin was canceled, in no block in time");
            }
            return Ok(());
        }
        let left = coin.htlc.timeout.saturating_sub(tip);
        if left > CANCEL_LEFT {
            return Ok(());
        }
        let rate = self.deadline_rate(chain, left).await;
        if by != txid {
            // Canceled already: made again once the rate rises past its.
            let paid = self.wallet.silent_spend(&by)?.and_then(|s| {
                let fee = Amount::from_sat(s.fee?);
                Some(fee >= rate.fee_wu(s.tx.weight())?)
            });
            if paid != Some(false) {
                return Ok(());
            }
        }
        let cancel = self.wallet.replace_silent(&by, rate)?;
        tracing::info!(
            id = %hex::encode(id), txid = %cancel.compute_txid(), left,
            "canceling a payout's coin in no block yet"
        );
        if let Err(e) = chain.broadcast(&cancel).await {
            tracing::debug!(id = %hex::encode(id), "cancel not broadcast: {e}");
        }
        Ok(())
    }

    /// Follow the coin of the payout `row`, confirmed, until spent: by its
    /// client's claim, whose preimage claims the client's lock, or by the
    /// provider's taking it back, made once it timed out and broadcast
    /// until buried.
    async fn watch_coin(
        &self,
        id: &[u8; 32],
        row: &Row,
        coin: &Coin,
        chain: &impl Chain,
    ) -> Result<(), Error> {
        let (Some(outpoint), Some(height)) = (coin.outpoint(), self.funding_height(coin)?) else {
            // Out of the chain in a reorganization: waited for again.
            return Ok(());
        };
        let script = coin.htlc.script_pubkey();
        let tip = chain.height().await.map_err(licash_wallet::Error::Chain)?;
        // Read before looking, so that a block replaced meanwhile is looked
        // in again next time.
        let through = (
            tip,
            chain.hash(tip).await.map_err(licash_wallet::Error::Chain)?,
        );
        let Some(scanned) = self.looked_through(id, coin.scanned, tip, chain).await? else {
            return Ok(());
        };
        let first = first_to_scan(scanned, height);
        let Some((at, spend)) = first_spend(chain, outpoint, &script, first..=tip).await? else {
            self.set_scanned(id, through)?;
            if tip >= coin.htlc.timeout {
                self.refund(id, row, coin, chain).await?;
            }
            return Ok(());
        };
        if let Some(preimage) = coin.htlc.preimage_in(&spend, outpoint) {
            tracing::info!(id = %hex::encode(id), height = at, "payout's coin claimed");
            self.advance(id, Stage::Locked, Stage::Paid, Some(&preimage), None)?;
            let row = self.row(id)?.expect("recorded");
            return self.claim(id, &row).await;
        }
        // Its only other spend: the provider's.
        let need = payout_depth(self.wallet.network());
        if confirmations(tip, at) < need {
            // Looked for again next time, to count its confirmations.
            if let Some(tx) = &coin.refund {
                self.broadcast_refund(id, tx, chain).await;
            }
            return Ok(());
        }
        // Looked at again until buried (Provider::recheck_refund).
        self.set_scanned(id, through)?;
        tracing::info!(id = %hex::encode(id), "refunded: the client never claimed the coin");
        let notice = Notice::Refunded {
            id: hex::encode(id),
            amount: row.amount,
        };
        self.advance(
            id,
            Stage::Locked,
            Stage::Refunded,
            None,
            Some((&notice, "")),
        )?;
        Ok(())
    }

    /// Take the coin of the payout `row` back, timed out, to the wallet's
    /// fallback address: before the client's lock expires, after which the
    /// client's claim would pay the provider nothing. At the rate the
    /// blocks left before then call for ([`deadline::rate`]), all of the
    /// coin but dust at most, and made again in place of the one before as
    /// that rate rises. Recorded once made, broadcast each time.
    async fn refund(
        &self,
        id: &[u8; 32],
        row: &Row,
        coin: &Coin,
        chain: &impl Chain,
    ) -> Result<(), Error> {
        let Some((funding, vout)) = &coin.funding else {
            return Ok(());
        };
        let outpoint = OutPoint::new(funding.compute_txid(), *vout);
        let value = funding.output[*vout as usize].value;
        let to = match &coin.refund {
            Some(old) => old.output[0].script_pubkey.clone(),
            None => self.wallet.fallback_address()?.script_pubkey(),
        };
        let tip = chain.height().await.map_err(licash_wallet::Error::Chain)?;
        let left = row
            .expiry_from
            .saturating_sub(licash_wallet::CLAIM_MARGIN)
            .saturating_sub(tip);
        let rate = self.deadline_rate(chain, left).await;
        let build = |rate| {
            coin.htlc
                .refund_capped(outpoint, value, to.clone(), rate, &coin.refund_key)
                .map_err(|e| licash_wallet::Error::Invalid(e.to_string()))
        };
        let tx = match deadline::remake(coin.refund.as_ref(), value, rate, build)? {
            Some(tx) => {
                self.store.write(|t| {
                    t.execute(
                        "UPDATE provider_payouts SET refund_tx = ?2 WHERE id = ?1",
                        params![id, serialize(&tx)],
                    )?;
                    Ok(())
                })?;
                tracing::info!(
                    id = %hex::encode(id), txid = %tx.compute_txid(), %rate, left,
                    "taking a payout's coin back"
                );
                tx
            }
            None => coin.refund.clone().expect("a refund made before"),
        };
        self.broadcast_refund(id, &tx, chain).await;
        Ok(())
    }

    async fn broadcast_refund(&self, id: &[u8; 32], tx: &Transaction, chain: &impl Chain) {
        if let Err(e) = chain.broadcast(tx).await {
            tracing::debug!(id = %hex::encode(id), "refund not broadcast: {e}");
        }
    }

    /// The coin of payout `id` looked through to block `through`, its
    /// height and hash: none of its spends in the chain ending there, but
    /// the provider's refund once refunded.
    fn set_scanned(&self, id: &[u8; 32], (height, hash): (u32, BlockHash)) -> Result<(), Error> {
        self.store.write(|t| {
            t.execute(
                "INSERT INTO provider_payout_scans (id, height, hash) VALUES (?1, ?2, ?3)
                 ON CONFLICT (id) DO UPDATE SET height = ?2, hash = ?3",
                params![id, height, hash.as_byte_array()],
            )?;
            Ok(())
        })
    }

    /// The block of payout `id` to be anchored at, its hash, if recorded at
    /// `scanned`: none once a refund buried deep cleared it.
    fn anchor(&self, id: &[u8; 32], scanned: u32) -> Result<Option<BlockHash>, Error> {
        let hash: Option<[u8; 32]> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT hash FROM provider_payout_scans
                 WHERE id = ?1 AND height = ?2 AND hash IS NOT NULL",
                params![id, scanned],
                |r| r.get(0),
            )
            .optional()?)
        })?;
        Ok(hash.map(BlockHash::from_byte_array))
    }

    /// How far the coin of payout `id`, looked through to `scanned`, was
    /// looked through in the chain as it is at `tip`: as far, if the block
    /// it was looked through to is still the chain's there; not at all if
    /// replaced, from its own block again. Without that block's hash, as
    /// a provider of a version before left it, [`REORG`] blocks less. None
    /// while the chain is shorter than that, or its block unknown: waited
    /// for.
    async fn looked_through(
        &self,
        id: &[u8; 32],
        scanned: Option<u32>,
        tip: u32,
        chain: &impl Chain,
    ) -> Result<Option<Option<u32>>, Error> {
        let Some(scanned) = scanned else {
            return Ok(Some(None));
        };
        let Some(hash) = self.anchor(id, scanned)? else {
            return Ok(Some(Some(scanned.saturating_sub(REORG))));
        };
        if scanned > tip {
            return Ok(None);
        }
        match chain.hash(scanned).await {
            Ok(now) if now == hash => Ok(Some(Some(scanned))),
            Ok(_) => {
                tracing::info!(id = %hex::encode(id), scanned, "payout's coin looked for again: its blocks replaced");
                Ok(Some(None))
            }
            Err(e) => {
                tracing::debug!(id = %hex::encode(id), "no block at {scanned}: {e}");
                Ok(None)
            }
        }
    }

    /// Look again at payout `id`, refunded, its refund seen buried in the
    /// chain ending at the block it is anchored at, until that block is
    /// [`REORG`] deep. Replaced, the coin is looked for from its own block:
    /// its refund found again, anchored anew; else the payout is taken on
    /// again, locked, its refund made again or its client's claim taken,
    /// which the claim's lack of a timelock still allows.
    async fn recheck_refund(&self, id: &[u8; 32], chain: &impl Chain) -> Result<(), Error> {
        let (Some(row), Some(coin)) = (self.row(id)?, self.coin(id)?) else {
            return Ok(());
        };
        let (Some(scanned), Some(outpoint)) = (coin.scanned, coin.outpoint()) else {
            return Ok(());
        };
        let Some(hash) = self.anchor(id, scanned)? else {
            return Ok(());
        };
        let tip = chain.height().await.map_err(licash_wallet::Error::Chain)?;
        let through = (
            tip,
            chain.hash(tip).await.map_err(licash_wallet::Error::Chain)?,
        );
        if scanned > tip {
            return Ok(());
        }
        let now = chain
            .hash(scanned)
            .await
            .map_err(licash_wallet::Error::Chain)?;
        if now == hash {
            if tip >= scanned + REORG {
                self.store.write(|t| {
                    t.execute(
                        "UPDATE provider_payout_scans SET hash = NULL WHERE id = ?1",
                        [id],
                    )?;
                    Ok(())
                })?;
            }
            return Ok(());
        }
        let Some(height) = self.funding_height(&coin)? else {
            // Its coin out of the chain too: waited for.
            return Ok(());
        };
        let script = coin.htlc.script_pubkey();
        let spend = first_spend(chain, outpoint, &script, height..=tip).await?;
        if let Some((_, spend)) = &spend {
            if coin.htlc.preimage_in(spend, outpoint).is_none() {
                // Its refund, in another block.
                return self.set_scanned(id, through);
            }
        }
        let name = hex::encode(id);
        tracing::warn!(id = %name, "payout's refund out of the chain: taken on again");
        self.store.write(|t| {
            t.execute("DELETE FROM provider_payout_scans WHERE id = ?1", [id])?;
            Ok(())
        })?;
        if self.advance(id, Stage::Refunded, Stage::Locked, None, None)? {
            self.alert(&format!(
                "Payout {name} of {} was refunded, then its refund left the chain: taken on again.",
                row.amount
            ))?;
        }
        Ok(())
    }
}

/// How deep a reorganization a payout's coin is looked back through for,
/// where the block it was looked through to is not known; and how deep its
/// refund is followed once buried.
const REORG: u32 = 6;

/// The first block to look in for the spend of a coin mined at `funding`,
/// blocks up to `scanned` looked in already: the coin's own block first,
/// as a claim broadcast before the coin confirmed may be mined with it.
fn first_to_scan(scanned: Option<u32>, funding: u32) -> u32 {
    scanned.map_or(funding, |scanned| (scanned + 1).max(funding))
}

/// The confirmations at `tip` of a transaction the wallet found in the
/// block at `at`: none while the chain asked is behind the wallet, or
/// replaced the block, whatever the wallet last saw.
fn confirmations(tip: u32, at: u32) -> u32 {
    tip.saturating_add(1).saturating_sub(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_coin_is_paid_on_mainnet_only_at_the_chains_estimate() {
        let (one, three) = (rate(1_000), rate(3_000));
        let mainnet = ChainProfile::Core30Mainnet;
        assert_eq!(funding_rate(None, one, 50, mainnet), None);
        assert_eq!(funding_rate(Some(three), one, 50, mainnet), Some(three));
        // Elsewhere the operator's rate stands in for it.
        let regtest = ChainProfile::Core30DefaultRegtest;
        assert_eq!(funding_rate(None, three, 50, regtest), Some(three));
        assert_eq!(funding_rate(Some(one), three, 50, regtest), Some(three));
        // Paying more as the blocks left to confirm in run out.
        assert_eq!(funding_rate(Some(one), one, 8, mainnet), Some(rate(4_000)));
    }

    #[test]
    fn a_coins_own_block_is_looked_in_for_its_spend() {
        assert_eq!(first_to_scan(None, 100), 100);
        // Looked in up to before it: from it.
        assert_eq!(first_to_scan(Some(99), 100), 100);
        assert_eq!(first_to_scan(Some(100), 100), 101);
        assert_eq!(first_to_scan(Some(120), 100), 121);
        // Mined again higher in a reorganization: from its new block.
        assert_eq!(first_to_scan(Some(90), 100), 100);
    }
}
