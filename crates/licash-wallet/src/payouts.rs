//! Payouts: notes paid out on Bitcoin through a swap provider
//! ([`licash_api::swaps`]), as a reverse submarine swap.
//!
//! The wallet draws a preimage when it is quoted ([`PayoutQuote::ticket`]
//! is its hash), and a key to claim with when it pays the quote out. It
//! records them with the payee, the lock of the coin's value and the
//! provider's fee to the provider at hub `from`, under the preimage's
//! hash, and the notes that lock takes, at once, before it sends anything. The provider
//! then locks a coin on Bitcoin under the same hash ([`Htlc`]): the
//! wallet's key and the preimage claim it, the provider's key takes it back
//! after its timeout. Once the wallet found the coin on its own view of the
//! chain, confirmed and worth what was asked, with room left before its
//! timeout, it claims it, paying the payee exactly the amount asked and the
//! rest of the coin as the claim's fee; should the claim be in no block as
//! the timeout nears, it is made again at a higher fee, the payee paid
//! less ([`Wallet::payout_claims`]). The claim reveals the preimage,
//! with which the provider claims the wallet's lock. Nothing is revealed
//! before: if the provider never locks a coin the wallet takes, the
//! wallet's lock is refunded once expired.
//!
//! The wallet broadcasts nothing: its claims ([`Wallet::payout_claims`])
//! are the application's to broadcast, again after each follow, until they
//! confirm.

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{LazyLock, Mutex, PoisonError},
};

use bitcoin::{
    absolute::LOCK_TIME_THRESHOLD,
    bip158::BlockFilter,
    consensus::{deserialize, serialize},
    hashes::Hash,
    key::TweakedPublicKey,
    secp256k1::{PublicKey, SecretKey, XOnlyPublicKey},
    Amount, Block, FeeRate, OutPoint, ScriptBuf, Transaction, Txid,
};
use licash::spend::{lock_hash, ChainProfile, ProposalId};
use licash_api::{
    swaps::{self, State as Theirs},
    Info,
};
use licash_onchain::{
    deadline,
    deposit::{self, Htlc},
    silent::SpAddress,
    silent_claim::{self, Share},
};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension, Row};

use crate::{
    deposits::{random_key, x_only},
    hub_url, invalid,
    locks::Pays,
    now, sql, unavailable, Blocks, Error, LockState, PaymentCode, Transport, Wallet,
};

/// `share`, as the provider answered it, if a share of `blinded` proven
/// of the secret of `refund`.
fn proven_share(
    share: &swaps::Share,
    refund: &XOnlyPublicKey,
    blinded: &PublicKey,
) -> Option<Share> {
    let share = Share {
        point: PublicKey::from_slice(&share.point.0).ok()?,
        e: share.e.0.as_slice().try_into().ok()?,
        s: share.s.0.as_slice().try_into().ok()?,
    };
    share.verify(refund, blinded).then_some(share)
}

/// Blocks a payout's coin must have left before its timeout when the
/// wallet claims it, for its claim to confirm before the provider may take
/// the coin back.
pub const CLAIM_ROOM: u32 = 12;

/// Blocks a payout's coin is quoted to time out after, at most, past the
/// height of the hub its lock is at: room for the lock to be made and the
/// coin to be paid and claimed, and no more, so that the provider's coin
/// and the wallet's notes are held no longer than that should either side
/// never go on. Within the most a hub admits.
pub const PAYOUT_WINDOW: u32 = 72;

/// A claim is budgeted at this many times the fee rate judged when it was
/// asked for: the rate may be higher once it is broadcast.
const HEADROOM: u64 = 3;

/// The least rate a claim is budgeted at, in sat per 1000 virtual bytes.
const MIN_RATE: u64 = 1_000;

/// The blocks looked in again for a coin's spend, for a reorganization.
const REORG: u32 = 6;

/// Confirmations a coin needs before the wallet claims it, and its claim
/// before the payout is done: a reorganization deeper than that could take
/// the coin away once the preimage is out.
pub fn payout_depth(network: ChainProfile) -> u32 {
    match network {
        ChainProfile::Core30Mainnet => 2,
        _ => 1,
    }
}

/// What a provider asks to pay notes out on Bitcoin
/// ([`Wallet::payout_quote`]), and the payout it is for: what
/// [`Wallet::payout`] pays, once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutQuote {
    /// The payout's id once paid ([`Payout::hash`]), known before: the
    /// hash of the preimage it is drawn under.
    pub ticket: String,
    /// The provider's URL, normalized.
    pub provider: String,
    /// The URL of the hub the notes are at, normalized.
    pub from: String,
    /// The payee, an address on Bitcoin, as shown.
    pub address: String,
    /// The most the payout may cost on top of the amount, the hub's lock
    /// fee as signed included.
    pub max_fee: u64,
    /// The rate the claim was budgeted for.
    pub rate: FeeRate,
    /// The height the wallet's lock expires at, at the latest: how long
    /// its notes may stay locked if the provider never pays.
    pub expiry: u32,
    /// What the provider said of itself, with what it pays out.
    pub info: swaps::Info,
    /// What the payee gets.
    pub amount: u64,
    /// The claim's fee: the coin is worth the amount and this.
    pub budget: u64,
    /// The provider's fee, its coin's miners included.
    pub fee: u64,
    /// The hub's fee on the wallet's lock, as it charges now: on what is
    /// locked, in as many notes as it may take.
    pub lock_fee: u64,
    preimage: Preimage,
}

/// A payout's preimage, secret until its claim: never shown.
#[derive(Clone, PartialEq, Eq)]
struct Preimage([u8; 32]);

impl std::fmt::Debug for Preimage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Preimage(..)")
    }
}

impl Preimage {
    fn draw() -> Self {
        let mut preimage = [0; 32];
        OsRng.fill_bytes(&mut preimage);
        Self(preimage)
    }
}

impl PayoutQuote {
    /// What the provider's coin is worth.
    pub fn value(&self) -> u64 {
        self.amount.saturating_add(self.budget)
    }

    /// What the payout costs on top of the amount.
    pub fn costs(&self) -> u64 {
        self.signed_costs(self.lock_fee)
    }

    /// What it costs on top of the amount, its lock's fee `lock_fee`.
    fn signed_costs(&self, lock_fee: u64) -> u64 {
        self.budget
            .saturating_add(self.fee)
            .saturating_add(lock_fee)
    }
}

/// A payout of notes at hub `from` to an address on Bitcoin, and where it
/// stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// The hash of the wallet's preimage, in hex: the payout's id here.
    pub hash: String,
    pub provider: String,
    pub from: String,
    /// The payee's address.
    pub address: String,
    /// What the payee gets.
    pub amount: u64,
    /// The claim's fee.
    pub budget: u64,
    /// The provider's fee, which the wallet's lock pays on top.
    pub fee: u64,
    /// The wallet's lock to the provider at `from`, once made.
    pub lock: Option<String>,
    /// The provider's coin, once found.
    pub funding: Option<OutPoint>,
    /// The wallet's claim of it, once made.
    pub claim: Option<Txid>,
    pub state: PayoutState,
    pub created_at: i64,
}

/// How far a payout has come, step by step, as the wallet last saw it:
/// for an application to show where it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PayoutProgress {
    /// The wallet's lock to the provider once made, where it stands, and
    /// the block from which its hub refunds it unpaid.
    pub lock: Option<(LockState, u32)>,
    /// The block from which the provider may take its coin back, once the
    /// provider took the payout.
    pub timeout: Option<u32>,
    /// The last block the wallet claims the coin at: [`CLAIM_ROOM`] before
    /// the timeout, for the claim to confirm in time. Past it, the payout
    /// fails and the lock is refunded.
    pub claim_by: Option<u32>,
    /// The provider's coin: as found on chain, or else as the provider told
    /// of it since the wallet was opened, maybe not confirmed yet.
    pub coin: Option<Txid>,
    /// The block the coin is in: as found, or else as the provider told.
    pub coin_height: Option<u32>,
    /// The wallet's claim of the coin, once made.
    pub claim: Option<Txid>,
    /// The block the claim is in, once found.
    pub claim_height: Option<u32>,
    /// The confirmations awaited: of the coin before it is claimed, of the
    /// claim before the payout is done.
    pub depth: u32,
}

/// Where a payout stands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PayoutState {
    /// Under way, nothing revealed yet.
    Open,
    /// The coin claimed: the claim is broadcast until it confirms.
    Claimed,
    /// The claim confirmed: the payee is paid.
    Done,
    /// Given up, and why. Before a claim, nothing was revealed: the
    /// wallet's lock, if made, is refunded once expired. After one, the
    /// provider took its coin back first.
    Failed(String),
}

/// A payout as recorded, to take it on.
struct Record {
    provider: String,
    preimage: [u8; 32],
    claim_key: [u8; 32],
    from: (i64, String),
    script: ScriptBuf,
    /// Paying a silent payment address: it, the secret its scan key is
    /// blinded by, and the provider's share of it once proven.
    silent: Option<(SpAddress, SecretKey, Option<PublicKey>)>,
    amount: u64,
    budget: u64,
    refund: Option<([u8; 32], u32)>,
    /// The coin, the block it is in and its value.
    funding: Option<(OutPoint, u32, u64)>,
    claim: Option<Vec<u8>>,
    scanned: Option<u32>,
    open: bool,
}

impl Record {
    fn value(&self) -> u64 {
        self.amount.saturating_add(self.budget)
    }

    fn claim_key(&self) -> Result<SecretKey, Error> {
        SecretKey::from_slice(&self.claim_key).map_err(invalid)
    }

    /// The coin's terms, once the provider named its own: sized, as a
    /// coin found is claimed only if it pays them or, from a provider
    /// before sized coins, them unsized ([`Wallet::claim_payout`]); once
    /// claimed, those its claim spends it by.
    fn htlc(&self) -> Result<Option<Htlc>, Error> {
        let Some((refund, timeout)) = self.refund else {
            return Ok(None);
        };
        let htlc = Htlc {
            hash: lock_hash(&self.preimage),
            claim: x_only(&self.claim_key()?),
            refund: XOnlyPublicKey::from_slice(&refund).map_err(invalid)?,
            timeout,
            wait: None,
            sized: true,
        };
        let (Some(claim), Some((funding, _, _))) = (&self.claim, self.funding) else {
            return Ok(Some(htlc));
        };
        let claim: Transaction = deserialize(claim).map_err(invalid)?;
        let claimed = htlc
            .sized_or_not()
            .into_iter()
            .find(|h| h.claimed_by(&claim, funding));
        claimed
            .map(Some)
            .ok_or_else(|| invalid("a payout's claim of other terms than its coin's"))
    }
}

/// Payouts.
impl<T: Transport> Wallet<T> {
    /// What the provider at `provider` asks to pay `amount` to `to`, an
    /// address on Bitcoin, from notes at the hub at `from`, added, as it
    /// last said of itself. `rate` is the fee rate the wallet judges a
    /// claim confirms at soon: the claim is budgeted at a few times that or
    /// the provider's, the higher. Refused as [`Error::Invalid`] if the
    /// provider pays nothing out on Bitcoin, takes no lock at `from`, pays
    /// out not that much, or the payout costs more than `max_fee` on top of
    /// the amount ([`PayoutQuote::costs`]): which bounds the claim's fee
    /// too, whatever rate the provider names. Nothing is recorded or
    /// locked: [`Wallet::payout`] checks it again.
    pub async fn payout_quote(
        &self,
        provider: &str,
        from: &str,
        to: &str,
        amount: u64,
        max_fee: u64,
        rate: FeeRate,
    ) -> Result<PayoutQuote, Error> {
        let provider = hub_url(provider)?;
        let from = hub_url(from)?;
        let (script, address, _) = self.payout_payee(to)?;
        self.hub(&from)?;
        let (_, from_info) = self.refresh(&from).await?;
        let info = self.quoted_terms(&provider).await?;
        let terms = Terms {
            provider: &provider,
            from: (&from, &from_info),
            script: &script,
            address: &address,
            amount,
            max_fee,
            rate,
            expiry: None,
        };
        terms.quote(info, Preimage::draw())
    }

    /// The most the provider saying `info` of itself pays out to `to`
    /// from a lock at hub `from`, added, by its terms as said: its largest
    /// coin less what the coin holds for its claim's fee at `rate` at
    /// least. None if it pays nothing out on Bitcoin, or takes no lock at
    /// `from`. A quote may still refuse it, for its timing or its fees.
    pub fn payout_most(
        &self,
        info: &swaps::Info,
        from: &str,
        to: &str,
        rate: FeeRate,
    ) -> Result<Option<u64>, Error> {
        let from = hub_url(from)?;
        let (script, _, _) = self.payout_payee(to)?;
        let (_, from_info) = self.hub(&from)?;
        let Some(chain) = info.chain else {
            return Ok(None);
        };
        if info.hub(&from_info.address).is_none() || info.address == from_info.address {
            return Ok(None);
        }
        let budget = claim_budget(&script, chain.max, &chain, rate)?;
        let most = chain.max.saturating_sub(budget);
        Ok((most > 0 && chain.max >= chain.min).then_some(most))
    }

    /// The least the provider saying `info` of itself pays out to `to`
    /// from a lock at hub `from`, added, by its terms as said: its smallest
    /// coin less what the coin holds for its claim's fee at `rate` at
    /// least, and no dust at `to`. None if it pays nothing out on Bitcoin,
    /// takes no lock at `from`, or pays out nothing at all. A quote may
    /// still refuse it, for its timing or its fees.
    pub fn payout_least(
        &self,
        info: &swaps::Info,
        from: &str,
        to: &str,
        rate: FeeRate,
    ) -> Result<Option<u64>, Error> {
        let from = hub_url(from)?;
        let (script, _, _) = self.payout_payee(to)?;
        let (_, from_info) = self.hub(&from)?;
        let Some(chain) = info.chain else {
            return Ok(None);
        };
        if info.hub(&from_info.address).is_none() || info.address == from_info.address {
            return Ok(None);
        }
        // A claim's size is the same whatever it pays.
        let budget = claim_budget(&script, chain.max, &chain, rate)?;
        let dust = script.minimal_non_dust().to_sat();
        let least = chain.min.saturating_sub(budget).max(dust);
        Ok((least.saturating_add(budget) <= chain.max).then_some(least))
    }

    /// Pay out as `quote` says, under its ticket: lock the coin's value and
    /// the fees to the provider at its hub, then claim the coin it locks
    /// on Bitcoin. The provider is asked again: refused as
    /// [`Error::Invalid`] if it now asks more than the quote's `max_fee`,
    /// the hub's lock fee as signed included, or its coin would time out
    /// too soon for a lock expiring by the quote's `expiry`, or the quote
    /// was paid already. Where the payout stands once its lock is made,
    /// whatever the provider answered; [`Wallet::follow_payout`] takes it
    /// on. Failed before any lock was made, the payout is recorded failed
    /// all the same, nothing locked.
    pub async fn payout(&self, quote: &PayoutQuote) -> Result<Payout, Error> {
        let (provider, from) = (&quote.provider, &quote.from);
        let preimage = quote.preimage.0;
        let hash = lock_hash(&preimage);
        let paid = self.store.read(|c| {
            Ok(
                c.query_row("SELECT 1 FROM payouts WHERE hash = ?1", [hash], |_| Ok(()))
                    .optional()?
                    .is_some(),
            )
        })?;
        if paid {
            return Err(Error::Invalid(format!(
                "payout {} was made already: ask for another quote",
                quote.ticket
            )));
        }
        let (script, address, silent) = self.payout_payee(&quote.address)?;
        let blind = silent.map(|_| random_key().secret_bytes());
        let from_hub = self.hub(from)?.0;
        // Asked at once, each a round trip over Tor; failed as when asked
        // in turn, the hub's failure first.
        let (said, info) = crate::both(self.refresh(from), self.fresh_terms(provider)).await;
        let (_, from_info) = said?;
        let info = info?;
        let terms = Terms {
            provider,
            from: (from, &from_info),
            script: &script,
            address: &address,
            amount: quote.amount,
            max_fee: quote.max_fee,
            rate: quote.rate,
            expiry: Some(quote.expiry),
        };
        // Asked again, within the quote's bounds.
        let quote = terms.quote(info, quote.preimage.clone())?;
        let locks = from_info.locks.as_ref().ok_or_else(|| {
            Error::Invalid(format!("hub {from} follows no chain: it takes no locks"))
        })?;
        let amount = quote.amount;
        let claim_key = random_key().secret_bytes();
        let insert = |tx: &rusqlite::Transaction<'_>| -> Result<(), Error> {
            tx.execute(
                "INSERT INTO payouts (hash, provider, preimage, claim_key, from_hub, address,
                    script, amount, budget, fee, created_at, blind)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    hash,
                    provider,
                    preimage,
                    claim_key,
                    from_hub,
                    address,
                    script.as_bytes(),
                    sql(amount)?,
                    sql(quote.budget)?,
                    sql(quote.fee)?,
                    now(),
                    blind
                ],
            )?;
            Ok(())
        };
        let total = quote.value().saturating_add(quote.fee);
        let at = (from.as_str(), from_hub, &from_info);
        // Its lock prepared first, then the payout, its lock and its notes
        // taken at once: no follower ever sees the payout without its lock.
        let admitted = match self
            .prepare_lock(
                at,
                &quote.info.address,
                total,
                hash,
                Some(quote.expiry),
                Pays::Nothing,
            )
            .await
        {
            // Its fee as the hub's lock signs it, not as estimated.
            Ok(prepared) if quote.signed_costs(prepared.fee) > quote.max_fee => {
                let asked = quote.signed_costs(prepared.fee);
                Err(Error::FeeRose {
                    who: provider.clone(),
                    agreed: quote.max_fee,
                    asked,
                    reason: format!(
                        "provider {provider} and hub {from} ask {asked} sat to pay out {amount}, more than {}",
                        quote.max_fee
                    ),
                })
            }
            Ok(prepared) => self
                .store
                .write(|tx| {
                    insert(tx)?;
                    prepared.record(tx)
                })
                .map(|()| prepared),
            Err(e) => Err(e),
        };
        let prepared = match admitted {
            Ok(prepared) => prepared,
            // A line of the history all the same, failed, nothing locked.
            Err(e) => {
                self.store.write(insert)?;
                self.fail_payout(&hash, &format!("its lock was not made: {e}"))?;
                return Err(e);
            }
        };
        tracing::info!(
            hash = %hex::encode(hash), %provider, %from, %address, amount,
            budget = quote.budget, fee = quote.fee, "paying out"
        );
        match self.send_lock(from, &prepared).await {
            Ok(_) | Err(Error::Pending { .. }) => {}
            Err(e) => {
                self.fail_payout(&hash, &format!("its lock was not made: {e}"))?;
                return Err(e);
            }
        }
        // Asked again by each follow, if this fails.
        let height = locks.height;
        if let Err(e) = self
            .ask_payout(&hash, &self.payout_row(&hash)?, Some(height))
            .await
        {
            tracing::debug!(hash = %hex::encode(hash), reason = %e, "payout waits");
        }
        self.payout_record(&hash)
    }

    /// Take the payout of `hash` on, `chain` the application's view of
    /// Bitcoin: have the provider lock its coin, claim it once confirmed
    /// where the provider says, and follow the claim until it confirms.
    /// Where it stands: broadcast [`Wallet::payout_claims`] after.
    pub async fn follow_payout(&self, hash: &str, chain: &impl Blocks) -> Result<Payout, Error> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(hash, &mut bytes)
            .map_err(|_| Error::Invalid(format!("not a payout's hash: {hash}")))?;
        let advanced = self.advance_payout(&bytes, chain).await;
        self.payout_after(&bytes, advanced)
    }

    /// How far the payout of `hash` has come, step by step. Reads only what
    /// the wallet holds and was told since opened: following it learns more.
    pub fn payout_progress(&self, hash: &str) -> Result<PayoutProgress, Error> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(hash, &mut bytes)
            .map_err(|_| Error::Invalid(format!("not a payout's hash: {hash}")))?;
        let payout = self.payout_record(&bytes)?;
        type Heights = (Option<u32>, Option<u32>, Option<u32>);
        let (timeout, found_height, spent_height): Heights = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT t.timeout_height, c.funding_height, c.spent_height FROM payouts p
                 LEFT JOIN payout_terms t ON t.hash = p.hash
                 LEFT JOIN payout_claims c ON c.hash = p.hash
                 WHERE p.hash = ?1",
                [bytes],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?)
        })?;
        let lock = match &payout.lock {
            Some(id) => {
                let mut lock = [0; 32];
                hex::decode_to_slice(id, &mut lock).map_err(invalid)?;
                let lock = self.lock_record(&ProposalId::from_bytes(lock))?;
                Some((lock.state, lock.expiry))
            }
            None => None,
        };
        let told = self
            .told_coins
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&bytes)
            .copied();
        let (coin, coin_height) = match payout.funding {
            Some(funding) => (Some(funding.txid), found_height),
            None => told.map_or((None, None), |(txid, height)| (Some(txid), height)),
        };
        // The coin's spend is the claim's unless the payout failed after.
        let claim_height = match payout.state {
            PayoutState::Failed(_) => None,
            _ if payout.claim.is_some() => spent_height,
            _ => None,
        };
        Ok(PayoutProgress {
            lock,
            timeout,
            claim_by: timeout.and_then(|t| t.checked_sub(CLAIM_ROOM)),
            coin,
            coin_height,
            claim: payout.claim,
            claim_height,
            depth: payout_depth(self.network()),
        })
    }

    /// Take every payout under way on, as [`Wallet::follow_payout`]: where
    /// each stands, and why those still under way wait.
    pub async fn follow_payouts(
        &self,
        chain: &impl Blocks,
    ) -> Result<(Vec<Payout>, Vec<(String, String)>), Error> {
        let (mut followed, mut pending) = (Vec::new(), Vec::new());
        let tip = chain.height().await.map_err(Error::Chain)?;
        for hash in self.settling_payouts(tip)? {
            self.recheck_payout(&hash, chain).await?;
        }
        for hash in self.open_payouts()? {
            match self.payout_after(&hash, self.advance_payout(&hash, chain).await) {
                Ok(payout) => followed.push(payout),
                Err(Error::Pending { id, reason }) => {
                    pending.push((id, reason));
                    followed.push(self.payout_record(&hash)?);
                }
                Err(e) => return Err(e),
            }
        }
        // The provider claims a payout's lock once its claim reveals the
        // preimage, so after the payout is done here: its lock is followed
        // until settled, the change of its notes back.
        for id in self.done_payouts_unsettled_locks()? {
            if let Err(e) = self.advance_lock(&ProposalId::from_bytes(id), None).await {
                pending.push((hex::encode(id), e.to_string()));
            }
        }
        Ok((followed, pending))
    }

    /// The locks of payouts done, not settled or given up.
    fn done_payouts_unsettled_locks(&self) -> Result<Vec<[u8; 32]>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT l.id FROM payouts p JOIN locks l ON l.hash = p.hash AND l.hub = p.from_hub
                 WHERE p.done_at IS NOT NULL AND p.failed IS NULL AND l.abandoned IS NULL
                   AND l.id NOT IN (SELECT id FROM lock_settlements)
                 ORDER BY l.created_at, l.rowid",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The claims of payouts not done, to broadcast: again after each
    /// follow, as a claim dropped or not confirmed yet loses the coin to
    /// the provider once it times out. A follow near the timeout may make
    /// a claim again at a higher fee, in place of the one before: the
    /// latest is returned.
    pub fn payout_claims(&self) -> Result<Vec<Transaction>, Error> {
        let claims: Vec<Vec<u8>> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT c.claim_tx FROM payout_claims c JOIN payouts p ON p.hash = c.hash
                 WHERE p.done_at IS NULL AND p.failed IS NULL ORDER BY p.created_at, p.rowid",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        claims
            .iter()
            .map(|tx| deserialize(tx).map_err(invalid))
            .collect()
    }

    /// The payouts made, newest first.
    pub fn payouts(&self) -> Result<Vec<Payout>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(&format!(
                "{PAYOUTS} ORDER BY p.created_at DESC, p.rowid DESC"
            ))?;
            let rows = stmt.query_map([], payout_of)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    fn payout_record(&self, hash: &[u8; 32]) -> Result<Payout, Error> {
        self.store.read(|c| {
            c.query_row(&format!("{PAYOUTS} WHERE p.hash = ?1"), [hash], payout_of)
                .optional()?
                .ok_or_else(|| Error::UnknownPayment(hex::encode(hash)))
        })
    }

    /// The payouts done whose claim is in a block fewer than [`REORG`]
    /// deep at `tip`: a reorganization could take it out still.
    fn settling_payouts(&self, tip: u32) -> Result<Vec<[u8; 32]>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT p.hash FROM payouts p JOIN payout_claims c ON c.hash = p.hash
                 WHERE p.done_at IS NOT NULL AND p.failed IS NULL
                   AND c.spent_height + ?1 > ?2 + 1
                 ORDER BY p.created_at, p.rowid",
            )?;
            let rows = stmt.query_map([REORG, tip], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Look again at the payout `hash`, done with its claim in a block
    /// fewer than [`REORG`] deep: under way again, its claim broadcast
    /// again, unless a claim is still in the chain as deep as a payout
    /// needs. Whether it is under way again.
    async fn recheck_payout(&self, hash: &[u8; 32], chain: &impl Blocks) -> Result<bool, Error> {
        let record = self.payout_row(hash)?;
        let spent: Option<(u32, bool)> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT c.spent_height, p.done_at IS NOT NULL AND p.failed IS NULL
                 FROM payouts p JOIN payout_claims c ON c.hash = p.hash WHERE p.hash = ?1",
                [hash],
                |r| Ok((r.get::<_, Option<u32>>(0)?, r.get::<_, bool>(1)?)),
            )
            .optional()?
            .and_then(|(height, done)| height.map(|h| (h, done))))
        })?;
        let (Some((height, true)), Some(claim), Some((funding, funding_height, _)), Some(htlc)) =
            (spent, &record.claim, record.funding, record.htlc()?)
        else {
            return Ok(false);
        };
        let tip = chain.height().await.map_err(Error::Chain)?;
        if (tip + 1).saturating_sub(height) >= REORG {
            return Ok(false);
        }
        let claim: Transaction = deserialize(claim).map_err(invalid)?;
        let first = height.saturating_sub(REORG).max(funding_height) + 1;
        let need = payout_depth(self.network());
        let kept = first_spend(chain, funding, &htlc.script_pubkey(), first..=tip)
            .await?
            .filter(|(at, spend)| {
                (spend.compute_txid() == claim.compute_txid() || htlc.claimed_by(spend, funding))
                    && (tip + 1).saturating_sub(*at) >= need
            });
        let reopened = self.store.write(|tx| {
            if let Some((at, _)) = kept {
                tx.execute(
                    "UPDATE payout_claims SET spent_height = ?2 WHERE hash = ?1",
                    params![hash, at],
                )?;
                return Ok(false);
            }
            let reopened = tx.execute(
                "UPDATE payouts SET done_at = NULL
                 WHERE hash = ?1 AND done_at IS NOT NULL AND failed IS NULL",
                [hash],
            )?;
            tx.execute(
                "UPDATE payout_claims SET spent_height = NULL, scanned_height = ?2
                 WHERE hash = ?1",
                params![hash, first - 1],
            )?;
            Ok(reopened == 1)
        })?;
        if reopened {
            tracing::warn!(
                hash = %hex::encode(hash), height,
                "a payout's claim left the chain: under way again"
            );
        }
        Ok(reopened)
    }

    /// The payouts under way, oldest first.
    pub(crate) fn open_payouts(&self) -> Result<Vec<[u8; 32]>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT hash FROM payouts WHERE done_at IS NULL AND failed IS NULL
                 ORDER BY created_at, rowid",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Where the payout of `hash` stands after `advanced`: an error but
    /// those that end it as pending.
    fn payout_after(&self, hash: &[u8; 32], advanced: Result<(), Error>) -> Result<Payout, Error> {
        match advanced {
            Ok(()) => self.payout_record(hash),
            Err(e @ (Error::Pending { .. } | Error::UnknownPayment(_))) => Err(e),
            Err(e) => Err(Error::Pending {
                id: hex::encode(hash),
                reason: e.to_string(),
            }),
        }
    }

    async fn advance_payout(&self, hash: &[u8; 32], chain: &impl Blocks) -> Result<(), Error> {
        let mut record = self.payout_row(hash)?;
        if !record.open {
            if !self.recheck_payout(hash, chain).await? {
                return Ok(());
            }
            record = self.payout_row(hash)?;
        }
        if record.claim.is_some() {
            return self.watch_claim(hash, &record, chain).await;
        }
        let Some((funding, hub_height)) = self.ask_payout(hash, &record, None).await? else {
            return Ok(());
        };
        // Its terms, as recorded first.
        let record = self.payout_row(hash)?;
        self.claim_payout(hash, &record, (&funding, hub_height), chain)
            .await
    }

    /// Ask the provider for the payout of the wallet's lock, and record its
    /// terms: its coin, as it says, once confirmed, with its hub's height
    /// as it says then; `None` once the payout failed. `height`, the hub's
    /// as it said in this same step, follows the lock ([`Wallet::advance_lock`]).
    async fn ask_payout(
        &self,
        hash: &[u8; 32],
        record: &Record,
        height: Option<u32>,
    ) -> Result<Option<(licash_api::Funding, u32)>, Error> {
        let from_hub = record.from.0;
        let lock: Option<[u8; 32]> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT id FROM locks WHERE hash = ?1 AND hub = ?2
                 ORDER BY created_at DESC, rowid DESC LIMIT 1",
                params![hash, from_hub],
                |r| r.get(0),
            )
            .optional()?)
        })?;
        // Recorded before its lock, which was never made.
        let Some(lock) = lock else {
            self.fail_payout(hash, "its lock was not made")?;
            return Ok(None);
        };
        let id = ProposalId::from_bytes(lock);
        let ours = match self.advance_lock(&id, height).await {
            Ok(ours) => ours,
            Err(Error::Refused { problem, .. }) => {
                self.fail_payout(hash, &format!("its hub refused its lock: {problem}"))?;
                return Ok(None);
            }
            Err(Error::Abandoned { reason, .. }) => {
                self.fail_payout(hash, &format!("its lock was given up: {reason}"))?;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        match ours.state {
            LockState::Requested => {
                return Err(Error::Pending {
                    id: hex::encode(hash),
                    reason: "its lock is not certified yet".into(),
                });
            }
            LockState::Refunded => {
                self.fail_payout(hash, "no coin was claimed: its lock was refunded")?;
                return Ok(None);
            }
            _ => {}
        }
        let provider = &record.provider;
        // Its identity, as kept: its height is asked once a coin is named.
        let (_, from_info) = self.hub(&record.from.1)?;
        let claim = x_only(&record.claim_key()?).serialize();
        let mut request = swaps::ChainRequest::new(&from_info.address, &id, claim, record.value());
        if let Some((address, rho, _)) = &record.silent {
            let blinded = silent_claim::blind(&address.scan, rho).map_err(invalid)?;
            request = request.with_scan(blinded.serialize());
        }
        let answer: swaps::ChainSwap = match self.post(provider, swaps::CHAIN_SWAPS, &request).await
        {
            Ok(answer) => answer,
            // Refused before the provider took it.
            Err(Error::Refused { problem, .. }) => {
                self.fail_payout(hash, &format!("the provider declined: {problem}"))?;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if answer.id.0 != id.as_bytes() {
            return Err(unavailable(provider, "it answered with another payout"));
        }
        // Where the provider says its coin is, to show before it is checked.
        let told = match (&answer.funding, &answer.txid) {
            (Some(funding), _) => Txid::from_str(&funding.txid)
                .ok()
                .map(|t| (t, Some(funding.height))),
            (None, Some(txid)) => Txid::from_str(txid).ok().map(|t| (t, None)),
            (None, None) => None,
        };
        if let Some(told) = told {
            self.told_coins
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(*hash, told);
        }
        if let Theirs::Failed | Theirs::Refunded = answer.state {
            let reason = answer.reason.as_deref().unwrap_or("no reason given");
            self.fail_payout(hash, &format!("the provider gave the payout up: {reason}"))?;
            return Ok(None);
        }
        if answer.value < record.value() {
            let reason = format!(
                "the provider locks a coin of {} of {}",
                answer.value,
                record.value()
            );
            self.fail_payout(hash, &reason)?;
            return Ok(None);
        }
        let refund = answer.refund().map_err(|p| unavailable(provider, p))?;
        let refund_key = XOnlyPublicKey::from_slice(&refund)
            .map_err(|_| unavailable(provider, "its refund key is no key"))?;
        // Paying a silent payment address: the provider's share of its
        // scan key, proven of its refund key, or nothing claimed.
        let share = match &record.silent {
            None => None,
            Some((address, rho, _)) => {
                let blinded = silent_claim::blind(&address.scan, rho).map_err(invalid)?;
                match answer
                    .share
                    .as_ref()
                    .and_then(|s| proven_share(s, &refund_key, &blinded))
                {
                    Some(share) => Some(
                        share
                            .unblind(rho, &refund_key)
                            .map_err(invalid)?
                            .serialize(),
                    ),
                    None => {
                        let reason =
                            "the provider's share of the payee's scan key is missing or false";
                        self.fail_payout(hash, reason)?;
                        return Ok(None);
                    }
                }
            }
        };
        // A time, not a height, under OP_CHECKLOCKTIMEVERIFY: refundable at
        // once.
        if answer.timeout >= LOCK_TIME_THRESHOLD || answer.timeout > ours.expiry {
            let reason = format!(
                "the provider's coin times out at {}, not a block before its lock expires at {}",
                answer.timeout, ours.expiry
            );
            self.fail_payout(hash, &reason)?;
            return Ok(None);
        }
        // Its first terms stand: a coin on others is not taken.
        self.store.write(|tx| {
            tx.execute(
                "INSERT INTO payout_terms (hash, refund_key, timeout_height, share)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT (hash) DO NOTHING",
                params![hash, refund, answer.timeout, share],
            )?;
            Ok(())
        })?;
        match answer.funding {
            Some(funding) => {
                let (_, from_info) = self.refresh(&record.from.1).await?;
                Ok(Some((funding, from_info.locks.map_or(0, |l| l.height))))
            }
            None => Err(Error::Pending {
                id: hex::encode(hash),
                reason: "the provider's coin is not confirmed yet".into(),
            }),
        }
    }

    /// Claim the provider's coin, once found where it says on the wallet's
    /// own view of the chain: confirmed, worth what was asked, with room
    /// left before its timeout, at the higher of the wallet's tip and
    /// `hub_height`, its lock's hub's: a view behind the chain sees more
    /// room than there is. Recorded with the claim, before anything is
    /// broadcast.
    async fn claim_payout(
        &self,
        hash: &[u8; 32],
        record: &Record,
        (hint, hub_height): (&licash_api::Funding, u32),
        chain: &impl Blocks,
    ) -> Result<(), Error> {
        let provider = &record.provider;
        let pending = |reason: String| Error::Pending {
            id: hex::encode(hash),
            reason,
        };
        let htlc = record
            .htlc()?
            .ok_or_else(|| invalid("a payout on no terms"))?;
        let txid = Txid::from_str(&hint.txid)
            .map_err(|_| unavailable(provider, "its coin's txid is none"))?;
        let tip = chain.height().await.map_err(Error::Chain)?;
        if hint.height > tip {
            let reason = format!(
                "the provider's coin is in block {}, past the tip {tip}",
                hint.height
            );
            return Err(pending(reason));
        }
        let block = block_at(chain, hint.height).await?;
        // Paying its terms, or them unsized, as providers paid before sized
        // coins: claimed and followed as it pays.
        let found = block
            .txdata
            .iter()
            .find(|tx| tx.compute_txid() == txid)
            .and_then(|tx| tx.output.get(hint.vout as usize))
            .and_then(|o| {
                let mut terms = htlc.sized_or_not().into_iter();
                Some((o, terms.find(|h| h.script_pubkey() == o.script_pubkey)?))
            });
        let Some((output, htlc)) = found else {
            let reason = format!(
                "the provider's coin is not in block {} as it says",
                hint.height
            );
            return Err(pending(reason));
        };
        let value = output.value.to_sat();
        if value < record.value() {
            let reason = format!("the provider's coin is worth {value} of {}", record.value());
            return self.fail_payout(hash, &reason);
        }
        let (depth, need) = (tip + 1 - hint.height, payout_depth(self.network()));
        if depth < need {
            let reason = format!("the provider's coin has {depth} of {need} confirmations");
            return Err(pending(reason));
        }
        let at = tip.max(hub_height);
        if htlc.timeout >= LOCK_TIME_THRESHOLD || htlc.timeout < at.saturating_add(CLAIM_ROOM) {
            let reason = format!(
                "too late to claim the provider's coin: it times out at block {}, \
                 the chain is at {at}",
                htlc.timeout
            );
            return self.fail_payout(hash, &reason);
        }
        let funding = OutPoint {
            txid,
            vout: hint.vout,
        };
        // To a silent payment address: its output, of the coin's key, the
        // claim key's secret and the provider's share.
        let script = match &record.silent {
            None => record.script.clone(),
            Some((address, _, share)) => {
                let share = share.ok_or_else(|| invalid("a silent payout of no share"))?;
                let key = &record.claim_key()?;
                let output = silent_claim::claim_output(&htlc, key, &share, funding, address)
                    .map_err(invalid)?;
                ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output))
            }
        };
        let claim = htlc
            .claim_exact(
                funding,
                output.value,
                script.clone(),
                Amount::from_sat(record.amount),
                &record.claim_key()?,
                &record.preimage,
            )
            .map_err(invalid)?;
        self.store.write(|tx| {
            let claimed = tx.execute(
                "INSERT INTO payout_claims (hash, funding_txid, funding_vout, funding_height,
                    value, claim_tx, revealed_at, scanned_height)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?4
                 WHERE EXISTS (SELECT 1 FROM payouts WHERE hash = ?1 AND failed IS NULL)
                 ON CONFLICT (hash) DO NOTHING",
                params![
                    hash,
                    txid.to_byte_array(),
                    hint.vout,
                    hint.height,
                    sql(value)?,
                    serialize(&claim),
                    now()
                ],
            )?;
            if claimed == 1 {
                tx.execute(
                    "UPDATE payouts SET script = ?2 WHERE hash = ?1",
                    params![hash, script.as_bytes()],
                )?;
            }
            Ok(())
        })?;
        tracing::info!(
            hash = %hex::encode(hash), claim = %claim.compute_txid(),
            "claiming the provider's coin"
        );
        Ok(())
    }

    /// Follow the claim of the payout `hash` until it confirms at depth, or
    /// another spend of the coin, the provider's refund, does.
    async fn watch_claim(
        &self,
        hash: &[u8; 32],
        record: &Record,
        chain: &impl Blocks,
    ) -> Result<(), Error> {
        let claim: Transaction =
            deserialize(record.claim.as_deref().unwrap_or_default()).map_err(invalid)?;
        let (funding, funding_height, _) = record
            .funding
            .ok_or_else(|| invalid("a claim of no coin"))?;
        let htlc = record
            .htlc()?
            .ok_or_else(|| invalid("a claim on no terms"))?;
        let script = htlc.script_pubkey();
        let tip = chain.height().await.map_err(Error::Chain)?;
        let scanned = record.scanned.unwrap_or(funding_height);
        let first = scanned.saturating_sub(REORG).max(funding_height) + 1;
        // The first spend of the coin, and whether it is a claim.
        let spent = first_spend(chain, funding, &script, first..=tip)
            .await?
            .map(|(height, spend)| {
                let claimed = spend.compute_txid() == claim.compute_txid()
                    || htlc.claimed_by(&spend, funding);
                (height, claimed)
            });
        let need = payout_depth(self.network());
        let (scanned, reason) = match spent {
            Some((height, false)) if tip + 1 - height >= need => {
                return self.lose_payout(hash, "the provider took its coin back first");
            }
            // Its claim broadcast still, should the spend leave the chain.
            Some((height, false)) => (
                height - 1,
                format!(
                    "the provider's coin was spent otherwise, {} of {need} confirmations",
                    tip + 1 - height
                ),
            ),
            Some((height, true)) if tip + 1 - height >= need => {
                self.store.write(|tx| {
                    let done = tx.execute(
                        "UPDATE payouts SET done_at = ?2
                         WHERE hash = ?1 AND done_at IS NULL AND failed IS NULL",
                        params![hash, now()],
                    )?;
                    if done == 1 {
                        tx.execute(
                            "UPDATE payout_claims SET spent_height = ?2, scanned_height = ?3
                             WHERE hash = ?1",
                            params![hash, height, tip],
                        )?;
                    }
                    Ok(())
                })?;
                tracing::info!(hash = %hex::encode(hash), height, "paid out");
                return Ok(());
            }
            // Looked for again next time, to count its confirmations.
            Some((height, true)) => (
                height - 1,
                format!("its claim has {} of {need} confirmations", tip + 1 - height),
            ),
            None => {
                self.remake_claim(hash, record, &htlc, &claim, tip)?;
                (tip, "its claim is not confirmed yet".to_string())
            }
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE payout_claims SET scanned_height = ?2, spent_height = ?3 WHERE hash = ?1",
                params![hash, scanned, spent.map(|(height, _)| height)],
            )?;
            Ok(())
        })?;
        Err(Error::Pending {
            id: hex::encode(hash),
            reason,
        })
    }

    /// Make the claim of the payout `hash` again in place of `claim`, still
    /// in no block at `tip`, once its coin's timeout nears: at twice its
    /// first rate from fewer than [`CLAIM_ROOM`] blocks before it, doubling
    /// every 3 blocks to 16 times ([`deadline::rate`]), the payee's output
    /// lowered to pay it (dust at least). The preimage is out: the payee
    /// paid less beats the provider taking its coin back with the wallet's
    /// lock paid. Recorded before anything is broadcast; kept while it pays
    /// that rate.
    fn remake_claim(
        &self,
        hash: &[u8; 32],
        record: &Record,
        htlc: &Htlc,
        claim: &Transaction,
        tip: u32,
    ) -> Result<(), Error> {
        let (funding, _, value) = record
            .funding
            .ok_or_else(|| invalid("a claim of no coin"))?;
        let value = Amount::from_sat(value);
        let weight = claim.weight();
        // Its first rate: the coin less the amount, over its weight.
        let first = value.to_sat().saturating_sub(record.amount);
        let base = FeeRate::from_sat_per_kwu((first * 1000 / weight.to_wu().max(1)).max(1));
        let rate = deadline::rate(Some(base), base, htlc.timeout.saturating_sub(tip));
        let (key, dust) = (record.claim_key()?, record.script.minimal_non_dust());
        let amount = Amount::from_sat(record.amount);
        let build = |rate: FeeRate| {
            let fee = rate.fee_wu(weight).unwrap_or(Amount::MAX);
            let pays = value.checked_sub(fee).unwrap_or(Amount::ZERO);
            let pays = pays.max(dust).min(amount);
            htlc.claim_exact(
                funding,
                value,
                record.script.clone(),
                pays,
                &key,
                &record.preimage,
            )
        };
        let Some(remade) = deadline::remake(Some(claim), value, rate, build).map_err(invalid)?
        else {
            return Ok(());
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE payout_claims SET claim_tx = ?2
                 WHERE hash = ?1 AND EXISTS (
                    SELECT 1 FROM payouts p
                    WHERE p.hash = ?1 AND p.done_at IS NULL AND p.failed IS NULL)",
                params![hash, serialize(&remade)],
            )?;
            Ok(())
        })?;
        tracing::warn!(
            hash = %hex::encode(hash), claim = %remade.compute_txid(), %rate,
            pays = %remade.output[0].value, timeout = htlc.timeout, tip,
            "claiming the provider's coin again, at a higher fee, the payee paid less"
        );
        Ok(())
    }

    /// Give the payout of `hash` up, unless its claim was made: nothing
    /// was revealed.
    fn fail_payout(&self, hash: &[u8; 32], reason: &str) -> Result<(), Error> {
        tracing::warn!(hash = %hex::encode(hash), reason, "payout failed");
        self.store.write(|tx| {
            tx.execute(
                "UPDATE payouts SET failed = ?2
                 WHERE hash = ?1 AND done_at IS NULL AND failed IS NULL
                    AND NOT EXISTS (SELECT 1 FROM payout_claims c WHERE c.hash = payouts.hash)",
                params![hash, reason],
            )?;
            Ok(())
        })
    }

    /// Record the payout of `hash` lost, its claim made: the provider's
    /// refund of its coin confirmed first.
    fn lose_payout(&self, hash: &[u8; 32], reason: &str) -> Result<(), Error> {
        tracing::warn!(hash = %hex::encode(hash), reason, "payout lost");
        self.store.write(|tx| {
            tx.execute(
                "UPDATE payouts SET failed = ?2
                 WHERE hash = ?1 AND done_at IS NULL AND failed IS NULL",
                params![hash, reason],
            )?;
            Ok(())
        })
    }

    fn payout_row(&self, hash: &[u8; 32]) -> Result<Record, Error> {
        let record = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT p.provider, p.preimage, p.claim_key, p.from_hub, r.url, p.script,
                    p.amount, p.budget, t.refund_key, t.timeout_height, c.funding_txid,
                    c.funding_vout, c.funding_height, c.value, c.claim_tx, c.scanned_height,
                    p.done_at IS NULL AND p.failed IS NULL, p.address, p.blind, t.share
                 FROM payouts p JOIN reach r ON r.hub = p.from_hub
                 LEFT JOIN payout_terms t ON t.hash = p.hash
                 LEFT JOIN payout_claims c ON c.hash = p.hash
                 WHERE p.hash = ?1",
                [hash],
                |r| {
                    let refund = match (r.get(8)?, r.get(9)?) {
                        (Some(key), Some(timeout)) => Some((key, timeout)),
                        _ => None,
                    };
                    let funding = match (r.get(10)?, r.get(11)?, r.get(12)?, r.get(13)?) {
                        (Some(txid), Some(vout), Some(height), Some(value)) => {
                            let txid = Txid::from_byte_array(txid);
                            let value: i64 = value;
                            Some((OutPoint { txid, vout }, height, value as u64))
                        }
                        _ => None,
                    };
                    let silent = match r.get::<_, Option<[u8; 32]>>(18)? {
                        Some(blind) => Some((
                            r.get::<_, String>(17)?,
                            blind,
                            r.get::<_, Option<[u8; 33]>>(19)?,
                        )),
                        None => None,
                    };
                    Ok((
                        Record {
                            provider: r.get(0)?,
                            preimage: r.get(1)?,
                            claim_key: r.get(2)?,
                            from: (r.get(3)?, r.get(4)?),
                            script: ScriptBuf::from_bytes(r.get(5)?),
                            amount: r.get::<_, i64>(6)? as u64,
                            budget: r.get::<_, i64>(7)? as u64,
                            refund,
                            funding,
                            claim: r.get(14)?,
                            scanned: r.get(15)?,
                            open: r.get(16)?,
                            silent: None,
                        },
                        silent,
                    ))
                },
            )
            .optional()?)
        })?;
        let (mut record, silent) =
            record.ok_or_else(|| Error::UnknownPayment(hex::encode(hash)))?;
        if let Some((address, blind, share)) = silent {
            let address = SpAddress::from_str(&address).map_err(invalid)?;
            let blind = SecretKey::from_slice(&blind).map_err(invalid)?;
            let share = share
                .map(|s| PublicKey::from_slice(&s))
                .transpose()
                .map_err(invalid)?;
            record.silent = Some((address, blind, share));
        }
        Ok(record)
    }

    /// The output script of `to`, an address on the wallet's network, a
    /// silent payment address, or a code naming either (the silent payment
    /// address first), and the address as shown. Of a silent payment
    /// address, its output is known once the coin claimed is: a taproot
    /// script of no key stands for it, to weigh the claim, with the address.
    fn payout_payee(&self, to: &str) -> Result<(ScriptBuf, String, Option<SpAddress>), Error> {
        let network = self.network();
        let code = PaymentCode::from_str(to.trim())
            .map_err(|e| Error::Invalid(format!("not an address on Bitcoin: {e}")))?;
        code.check(network)
            .map_err(|_| Error::Invalid(format!("an address not on {network}")))?;
        if let Some(silent) = code.silent {
            let any = ScriptBuf::from_bytes([&[0x51, 0x20][..], &[0; 32]].concat());
            return Ok((any, silent.to_string(), Some(silent)));
        }
        let Some(address) = code.address else {
            return Err(Error::Invalid(
                "not an address on Bitcoin: no address it names".into(),
            ));
        };
        let address = address
            .require_network(licash_onchain::network(network))
            .map_err(|_| Error::Invalid(format!("an address not on {network}")))?;
        Ok((address.script_pubkey(), address.to_string(), None))
    }
}

/// What a payout is asked on, to judge a provider's offer by.
struct Terms<'a> {
    provider: &'a str,
    from: (&'a str, &'a Info),
    script: &'a ScriptBuf,
    address: &'a str,
    amount: u64,
    max_fee: u64,
    rate: FeeRate,
    /// The latest the wallet's lock may expire at, if bounded.
    expiry: Option<u32>,
}

impl Terms<'_> {
    /// The quote of the provider saying `info` of itself, for a payout
    /// drawn under `preimage`, unless it pays out nothing for a lock at
    /// `from`, not that much now, times its coin out too soon for a lock
    /// expiring by the bound, or asks more than allowed.
    fn quote(&self, info: swaps::Info, preimage: Preimage) -> Result<PayoutQuote, Error> {
        let (provider, (from, from_info)) = (self.provider, self.from);
        let refuse = |why: String| Err(Error::Invalid(format!("provider {provider} {why}")));
        if self.amount == 0 {
            return Err(Error::Invalid("nothing to pay out".into()));
        }
        let Some(chain) = info.chain else {
            return refuse("pays nothing out on Bitcoin".into());
        };
        if info.hub(&from_info.address).is_none() {
            return refuse(format!("takes no lock at {from}"));
        }
        // A lock to a hub's own address is the hub's to settle.
        if info.address == from_info.address {
            return refuse("names a hub's address as its own".into());
        }
        let locks = from_info.locks.as_ref().ok_or_else(|| {
            Error::Invalid(format!("hub {from} follows no chain: it takes no locks"))
        })?;
        let latest = locks
            .latest_expiry(locks.min_depth.max(1))
            .map_err(|p| unavailable(from, p))?;
        let latest = self.expiry.map_or(latest, |bound| bound.min(latest));
        let soonest = (locks.height.saturating_add(chain.margin)).saturating_add(PAYOUT_WINDOW);
        let latest = latest.min(soonest);
        if latest.saturating_sub(chain.margin) < locks.height.saturating_add(2 * CLAIM_ROOM) {
            return refuse(format!(
                "times its coin out {} blocks before a lock at {from} expires: too soon to claim it",
                chain.margin
            ));
        }
        let budget = claim_budget(self.script, self.amount, &chain, self.rate)?;
        let value = self.amount.saturating_add(budget);
        if value < chain.min || value > chain.max {
            return refuse(format!(
                "pays out coins of {} to {} sat now, not {value}",
                chain.min, chain.max
            ));
        }
        let fee = chain.pays(value) - value;
        let lock_fee = from_info.fees.locking().at_most(value.saturating_add(fee));
        let quote = PayoutQuote {
            ticket: hex::encode(lock_hash(&preimage.0)),
            provider: provider.into(),
            from: from.into(),
            address: self.address.into(),
            max_fee: self.max_fee,
            rate: self.rate,
            expiry: latest,
            info,
            amount: self.amount,
            budget,
            fee,
            lock_fee,
            preimage,
        };
        if quote.costs() > self.max_fee {
            return Err(Error::FeeRose {
                who: provider.into(),
                agreed: self.max_fee,
                asked: quote.costs(),
                reason: format!(
                    "provider {provider} asks {} sat to pay out {}, more than {}",
                    quote.costs(),
                    self.amount,
                    self.max_fee
                ),
            });
        }
        Ok(quote)
    }
}

/// The virtual size of a claim paying `amount` to `script`, refused if
/// that is dust: the same whatever its keys and coin.
/// What a coin of `chain`'s paying `amount` to `script` holds on top for
/// its claim's fee: at the provider's rate or `rate`, whichever is more,
/// with headroom.
fn claim_budget(
    script: &ScriptBuf,
    amount: u64,
    chain: &swaps::Chain,
    rate: FeeRate,
) -> Result<u64, Error> {
    let rate = chain
        .rate
        .max(MIN_RATE)
        .max(rate.to_sat_per_kwu().saturating_mul(4));
    Ok(claim_vsize(script, amount)?
        .saturating_mul(rate)
        .saturating_mul(HEADROOM)
        .div_ceil(1000))
}

fn claim_vsize(script: &ScriptBuf, amount: u64) -> Result<u64, Error> {
    let key = SecretKey::from_slice(&[1; 32]).expect("a secret key");
    let preimage = [0; 32];
    let htlc = Htlc {
        hash: lock_hash(&preimage),
        claim: x_only(&key),
        refund: x_only(&key),
        timeout: 0,
        wait: None,
        sized: true,
    };
    let to = script.clone();
    let paid = Amount::from_sat(amount);
    match htlc.claim_exact(
        OutPoint::null(),
        Amount::MAX_MONEY,
        to,
        paid,
        &key,
        &preimage,
    ) {
        Ok(claim) => Ok(claim.vsize() as u64),
        Err(deposit::Error::Exact { .. }) => Err(Error::Invalid(format!(
            "{amount} sat is too little to pay on Bitcoin"
        ))),
        Err(e) => Err(invalid(e)),
    }
}

/// The first spend of `coin`, paid to `script`, in the best chain's blocks
/// at `heights`, and the block it is in: blocks whose filter matches
/// `script` are fetched, and checked against their hashes.
///
/// A search that stopped partway, as on a chain source limiting its rate,
/// goes on from where it stopped the next time, in this process: the
/// blocks found holding no spend of `coin` are remembered while the last
/// of them is still the best chain's (`UNSPENT`).
pub async fn first_spend(
    chain: &impl Blocks,
    coin: OutPoint,
    script: &bitcoin::Script,
    heights: std::ops::RangeInclusive<u32>,
) -> Result<Option<(u32, Transaction)>, Error> {
    let (start, end) = heights.into_inner();
    let key = (coin, script.to_owned());
    let (mut from, mut height) = (start, start);
    let known = unspent().get(&key).copied();
    if let Some(known) = known.filter(|k| k.from <= start && start <= k.to && k.to <= end) {
        if chain.hash(known.to).await.map_err(Error::Chain)? == known.hash {
            (from, height) = (known.from, known.to.saturating_add(1));
        }
    }
    while height <= end {
        let block_hash = chain.hash(height).await.map_err(Error::Chain)?;
        let matched = match chain.filter(&block_hash).await.map_err(Error::Chain)? {
            None => true,
            Some(filter) => BlockFilter::new(&filter)
                .match_any(&block_hash, std::iter::once(script.as_bytes()))
                .map_err(|e| Error::Chain(format!("the filter of block {block_hash}: {e}")))?,
        };
        if matched {
            let block = checked_block(chain, &block_hash).await?;
            let spend = block
                .txdata
                .into_iter()
                .find(|tx| tx.input.iter().any(|i| i.previous_output == coin));
            if let Some(spend) = spend {
                return Ok(Some((height, spend)));
            }
        }
        let mut unspent = unspent();
        if unspent.len() >= UNSPENT_KEPT && !unspent.contains_key(&key) {
            unspent.clear();
        }
        let to = height;
        let hash = block_hash;
        unspent.insert(key.clone(), Unspent { from, to, hash });
        match height.checked_add(1) {
            Some(next) => height = next,
            None => break,
        }
    }
    Ok(None)
}

/// Blocks from `from` to `to`, then of hash `hash`, hold no spend of a coin.
#[derive(Clone, Copy)]
struct Unspent {
    from: u32,
    to: u32,
    hash: bitcoin::BlockHash,
}

/// The coins searched for the spend of lately ([`first_spend`]), by coin
/// and the script it pays, and the blocks found holding none.
static UNSPENT: LazyLock<Mutex<HashMap<(OutPoint, ScriptBuf), Unspent>>> =
    LazyLock::new(Mutex::default);

/// The most coins [`UNSPENT`] keeps: all forgotten past it.
const UNSPENT_KEPT: usize = 4096;

fn unspent() -> std::sync::MutexGuard<'static, HashMap<(OutPoint, ScriptBuf), Unspent>> {
    UNSPENT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The best chain's block at `height`, checked against its hash.
async fn block_at(chain: &impl Blocks, height: u32) -> Result<Block, Error> {
    let hash = chain.hash(height).await.map_err(Error::Chain)?;
    checked_block(chain, &hash).await
}

/// The block of `hash`, checked against it: its header's hash and its
/// transactions' merkle root.
pub async fn checked_block(chain: &impl Blocks, hash: &bitcoin::BlockHash) -> Result<Block, Error> {
    let block = chain.block(hash).await.map_err(Error::Chain)?;
    if block.block_hash() != *hash || !block.check_merkle_root() {
        return Err(Error::Chain(format!(
            "block {hash} does not match its header"
        )));
    }
    Ok(block)
}

const PAYOUTS: &str = "SELECT p.hash, p.provider, r.url, p.address, p.amount, p.budget, p.fee,
    (SELECT l.id FROM locks l WHERE l.hash = p.hash AND l.hub = p.from_hub
        ORDER BY l.created_at DESC, l.rowid DESC LIMIT 1),
    c.funding_txid, c.funding_vout, c.claim_tx, p.done_at IS NOT NULL, p.failed, p.created_at
    FROM payouts p JOIN reach r ON r.hub = p.from_hub
    LEFT JOIN payout_claims c ON c.hash = p.hash";

fn payout_of(r: &Row<'_>) -> rusqlite::Result<Payout> {
    let claim: Option<Vec<u8>> = r.get(10)?;
    let state = match (r.get::<_, bool>(11)?, r.get::<_, Option<String>>(12)?) {
        (_, Some(reason)) => PayoutState::Failed(reason),
        (true, None) => PayoutState::Done,
        (false, None) if claim.is_some() => PayoutState::Claimed,
        (false, None) => PayoutState::Open,
    };
    let funding = match (r.get::<_, Option<[u8; 32]>>(8)?, r.get(9)?) {
        (Some(txid), Some(vout)) => Some(OutPoint {
            txid: Txid::from_byte_array(txid),
            vout,
        }),
        _ => None,
    };
    let claim = claim
        .and_then(|tx| deserialize::<Transaction>(&tx).ok())
        .map(|tx| tx.compute_txid());
    Ok(Payout {
        hash: hex::encode(r.get::<_, [u8; 32]>(0)?),
        provider: r.get(1)?,
        from: r.get(2)?,
        address: r.get(3)?,
        amount: r.get::<_, i64>(4)? as u64,
        budget: r.get::<_, i64>(5)? as u64,
        fee: r.get::<_, i64>(6)? as u64,
        lock: r.get::<_, Option<[u8; 32]>>(7)?.map(hex::encode),
        funding,
        claim,
        state,
        created_at: r.get(13)?,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute::LockTime,
        block::{Header, Version},
        hashes::Hash,
        pow::CompactTarget,
        transaction, Block, BlockHash, Sequence, TxIn, TxMerkleNode, TxOut, Witness,
    };

    use super::*;

    /// A chain without filters, as an Esplora's: each block fetched, the
    /// fetch of one failing once if asked.
    struct Chain {
        blocks: Mutex<Vec<Block>>,
        failing: Mutex<Option<u32>>,
        fetched: Mutex<Vec<BlockHash>>,
    }

    impl Blocks for Chain {
        async fn height(&self) -> Result<u32, String> {
            Ok(self.blocks.lock().unwrap().len() as u32 - 1)
        }

        async fn hash(&self, height: u32) -> Result<BlockHash, String> {
            let blocks = self.blocks.lock().unwrap();
            let block = blocks.get(height as usize).ok_or("no block")?;
            Ok(block.block_hash())
        }

        async fn filter(&self, _: &BlockHash) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }

        async fn block(&self, hash: &BlockHash) -> Result<Block, String> {
            let blocks = self.blocks.lock().unwrap();
            let at = blocks.iter().position(|b| b.block_hash() == *hash);
            let at = at.ok_or("no block")? as u32;
            if *self.failing.lock().unwrap() == Some(at) {
                *self.failing.lock().unwrap() = None;
                return Err("HTTP 429 Too Many Requests".into());
            }
            self.fetched.lock().unwrap().push(*hash);
            Ok(blocks[at as usize].clone())
        }
    }

    fn tx(input: OutPoint, tag: u8) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: input,
                script_sig: ScriptBuf::from_bytes(vec![tag]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_op_return([tag]),
            }],
        }
    }

    /// Blocks 0 to `count - 1` after `previous`, of a transaction tagged
    /// `tag` each, block `spending` spending `coin`.
    fn mine(blocks: &mut Vec<Block>, count: u32, tag: u8, coin: OutPoint, spending: u32) {
        for _ in 0..count {
            let height = blocks.len() as u32;
            let input = match height == spending {
                true => coin,
                false => OutPoint::new(Txid::all_zeros(), height),
            };
            let prev = blocks
                .last()
                .map_or(BlockHash::all_zeros(), Block::block_hash);
            let mut block = Block {
                header: Header {
                    version: Version::TWO,
                    prev_blockhash: prev,
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: height,
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                    nonce: 0,
                },
                txdata: vec![tx(input, tag)],
            };
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            blocks.push(block);
        }
    }

    #[tokio::test]
    async fn a_search_for_a_spend_failing_partway_goes_on_where_it_stopped() {
        let coin = OutPoint::new(Txid::from_byte_array([7; 32]), 1);
        let script = ScriptBuf::new_op_return([9]);
        let mut blocks = Vec::new();
        mine(&mut blocks, 10, 0, coin, 8);
        let chain = Chain {
            blocks: Mutex::new(blocks),
            failing: Mutex::new(Some(6)),
            fetched: Mutex::default(),
        };
        let fetched = || std::mem::take(&mut *chain.fetched.lock().unwrap()).len();
        first_spend(&chain, coin, &script, 2..=9).await.unwrap_err();
        assert_eq!(fetched(), 4);
        // From block 6 on, where it stopped.
        let (at, spend) = first_spend(&chain, coin, &script, 2..=9)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((at, fetched()), (8, 3));
        assert_eq!(spend.input[0].previous_output, coin);
        // Searched again, from a later block among those: from the block
        // of its spend. Another coin, or from an earlier block: all of it.
        assert_eq!(
            first_spend(&chain, coin, &script, 4..=9)
                .await
                .unwrap()
                .unwrap()
                .0,
            8
        );
        assert_eq!(fetched(), 1);
        assert_eq!(
            first_spend(&chain, coin, &script, 1..=9)
                .await
                .unwrap()
                .unwrap()
                .0,
            8
        );
        assert_eq!(fetched(), 8);
        let other = OutPoint::new(coin.txid, 2);
        assert_eq!(
            first_spend(&chain, other, &script, 2..=9).await.unwrap(),
            None
        );
        assert_eq!(fetched(), 8);

        // The blocks from 5 on replaced, the spend in block 7 now: none
        // passed over, nor any block of the chain replaced remembered.
        let mut blocks = chain.blocks.lock().unwrap().clone();
        blocks.truncate(5);
        mine(&mut blocks, 5, 1, coin, 7);
        *chain.blocks.lock().unwrap() = blocks;
        assert_eq!(
            first_spend(&chain, coin, &script, 1..=9)
                .await
                .unwrap()
                .unwrap()
                .0,
            7
        );
        assert_eq!(fetched(), 7);
        assert_eq!(
            first_spend(&chain, other, &script, 2..=9).await.unwrap(),
            None
        );
        assert_eq!(fetched(), 8);
    }
}
