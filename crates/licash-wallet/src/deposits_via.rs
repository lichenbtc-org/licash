//! Deposits on Bitcoin through a swap provider ([`swaps::Deposits`]): a
//! coin hash-locked to the provider under the wallet's hash, paid on with a
//! lock of the provider's notes at the hub, which the wallet claims with
//! the preimage, as a hub's own deposit. The provider looks for no coin:
//! the wallet finds the payment in the blocks it follows and tells the
//! provider of it once deep enough ([`Wallet::follow_deposits_through`]),
//! which checks it there before it locks.
//!
//! Recorded as the hub's deposits are, their payment refunded alike after
//! the timeout ([`Wallet::deposits_to_refund`]), and the provider each was
//! asked of kept beside them, in a table made when the first is asked: a
//! file whose wallet never asked one has none, and holds no such deposit.
//! Their preimage and refund key are drawn at random, as the provider knows
//! no deposit by its refund key: a wallet that lost its file can neither
//! find one again nor take its coin back, so a deposit is paid only from
//! this wallet's file, and its notes claimed within the blocks after.

use bitcoin::{bip158::BlockFilter, hashes::Hash, secp256k1::XOnlyPublicKey, OutPoint, Txid};
use licash::spend::lock_hash;
use licash_api::{
    swaps::{self, DepositRequest},
    Code, Depositing, Funding, Hex, ReceiveState, ReceiveStatus,
};
use licash_onchain::deposit::Htlc;
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension};

use crate::{
    deposits::{keep_terms, random_key, x_only, TIP_MARGIN},
    hub_url, invalid, now,
    payouts::checked_block,
    sql, unavailable, Blocks, Deposit, Error, Transport, Wallet,
};

/// The component of the providers deposits were asked of, and its version.
const VIA_COMPONENT: &str = "deposit_providers";
const VIA_VERSION: i64 = 1;
const VIA_SCHEMA: &str = "
-- The swap provider asked for a deposit in place of its hub, by the
-- deposit's hash: its payment is looked for from block `from_height`, at
-- `depth` confirmations, as the provider asks.
CREATE TABLE deposit_providers (
    hash BLOB PRIMARY KEY REFERENCES deposits (hash),
    provider TEXT NOT NULL,
    from_height INTEGER NOT NULL,
    depth INTEGER NOT NULL CHECK (depth > 0)
) STRICT;
";

/// A deposit's provider, as recorded.
pub(crate) struct Via {
    pub(crate) provider: String,
    from_height: u32,
    depth: u32,
}

/// Whether the file keeps the providers of deposits: none if its wallet
/// never asked one.
pub(crate) fn kept(c: &rusqlite::Connection) -> Result<bool, Error> {
    let version = licash_store::component_version(c, VIA_COMPONENT)
        .map_err(|e| Error::Setup(e.to_string()))?;
    Ok(version.is_some())
}

/// The provider the deposit of `hash` was asked of, if one was.
pub(crate) fn via(c: &rusqlite::Connection, hash: &[u8; 32]) -> Result<Option<Via>, Error> {
    if !kept(c)? {
        return Ok(None);
    }
    Ok(c.query_row(
        "SELECT provider, from_height, depth FROM deposit_providers WHERE hash = ?1",
        [hash],
        |r| {
            Ok(Via {
                provider: r.get(0)?,
                from_height: r.get(1)?,
                depth: r.get(2)?,
            })
        },
    )
    .optional()?)
}

/// What a swap provider takes for a deposit on Bitcoin at a hub
/// ([`Wallet::deposit_offer`]).
#[derive(Clone, Debug)]
pub struct DepositOffer {
    pub info: swaps::Info,
    pub terms: swaps::Deposits,
    /// The most it locks there now: its terms, and what it holds there.
    pub max: u64,
}

impl<T: Transport> Wallet<T> {
    /// What the provider at `provider` takes for a deposit on Bitcoin at
    /// the hub at `hub`, trusted: refused if it takes none, or none there
    /// now.
    pub async fn deposit_offer(&self, provider: &str, hub: &str) -> Result<DepositOffer, Error> {
        let provider = hub_url(provider)?;
        let url = hub_url(hub)?;
        let (_, hub_info) = self.hub(&url)?;
        let info: swaps::Info = self.get(&provider, swaps::SWAPS_INFO).await?;
        let terms = info.deposits.ok_or_else(|| {
            Error::Invalid(format!("provider {provider} takes no deposits on Bitcoin"))
        })?;
        let max = match info.hub(&hub_info.address) {
            Some(at) => terms.max.min(at.max),
            None => 0,
        };
        if max < terms.min {
            return Err(Error::Invalid(format!(
                "provider {provider} takes no deposits on Bitcoin at hub {url} now"
            )));
        }
        Ok(DepositOffer { info, terms, max })
    }

    /// Ask the provider at `provider` for a deposit on Bitcoin locking
    /// notes worth `amount` to this wallet at the hub at `url`: where to
    /// pay, and how much, its fee and its claim's miners on top. The
    /// provider sees the amount and the wallet's address.
    /// [`Wallet::follow_deposits_through`] tells it of the payment once
    /// deep enough, and claims the notes it locks.
    pub async fn deposit_through(
        &self,
        provider: &str,
        url: &str,
        amount: u64,
    ) -> Result<Deposit, Error> {
        let provider = hub_url(provider)?;
        let url = hub_url(url)?;
        self.not_visited(&url)?;
        let (hub, info) = self.refresh(&url).await?;
        let offer = self.deposit_offer(&provider, &url).await?;
        if amount < offer.terms.min || amount > offer.max {
            return Err(Error::Invalid(format!(
                "provider {provider} takes deposits of {} to {} at hub {url}",
                offer.terms.min, offer.max
            )));
        }
        let height = (info.locks.as_ref().map(|l| l.height))
            .ok_or_else(|| Error::Invalid(format!("hub {url} follows no chain")))?;
        let pays = offer.terms.pays(amount);
        let mut preimage = [0; 32];
        OsRng.fill_bytes(&mut preimage);
        let refund = random_key();
        let hash = lock_hash(&preimage);
        let body = DepositRequest {
            hub: info.address,
            address: self.address(),
            amount,
            hash: Hex(hash.to_vec()),
            refund: Hex(x_only(&refund).serialize().to_vec()),
        };
        let body = serde_json::to_string(&body).map_err(invalid)?;
        // A payment confirms after the tip the provider saw, which the
        // hub's may trail.
        let from = height.saturating_sub(TIP_MARGIN);
        let depth = offer.terms.depth.max(1);
        self.store.write(|tx| {
            licash_store::component_in(tx, VIA_COMPONENT, VIA_VERSION, VIA_SCHEMA)
                .map_err(|e| Error::Setup(e.to_string()))?;
            tx.execute(
                "INSERT INTO deposits
                     (hash, hub, preimage, refund_key, amount, pays, body, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    hash,
                    hub,
                    preimage,
                    refund.secret_bytes(),
                    sql(amount)?,
                    sql(pays)?,
                    body,
                    now()
                ],
            )?;
            tx.execute(
                "INSERT INTO deposit_providers (hash, provider, from_height, depth)
                 VALUES (?1, ?2, ?3, ?4)",
                params![hash, provider, from, depth],
            )?;
            Ok(())
        })?;
        tracing::info!(hash = %hex::encode(hash), %url, %provider, amount, "asking a provider for a deposit");
        self.advance_deposit(&hash).await
    }

    /// Take every deposit asked of a provider and under way on, `chain`
    /// the application's view of Bitcoin: look there for its payment, tell
    /// the provider of it once deep enough, and claim the notes it locks.
    /// Where each stands, and why those still under way wait.
    pub async fn follow_deposits_through(
        &self,
        chain: &impl Blocks,
    ) -> Result<(Vec<Deposit>, Vec<(String, String)>), Error> {
        let (mut followed, mut pending) = (Vec::new(), Vec::new());
        let tip = chain.height().await.map_err(Error::Chain)?;
        self.saw_tip(tip);
        for hash in self.open_deposits()? {
            let Some(via) = self.store.read(|c| via(c, &hash))? else {
                continue;
            };
            if let Err(e) = self.find_deposit_payment(&hash, &via, chain, tip).await {
                pending.push((hex::encode(hash), e.to_string()));
            }
            match self.advance_deposit(&hash).await {
                Ok(deposit) => followed.push(deposit),
                Err(Error::Pending { id, reason }) => {
                    pending.push((id, reason));
                    followed.push(self.deposit_record(&hash)?);
                }
                Err(e) => return Err(e),
            }
        }
        Ok((followed, pending))
    }

    /// Look in `chain`, whose tip is `tip`, for the payment of the deposit
    /// of `hash`, asked of a provider as `via` says, unless one was found:
    /// an output paying its address exactly what it asks, confirmed by its
    /// `fund_by` at the depth the provider asks, recorded once found.
    async fn find_deposit_payment(
        &self,
        hash: &[u8; 32],
        via: &Via,
        chain: &impl Blocks,
        tip: u32,
    ) -> Result<(), Error> {
        type Row = (Option<String>, Option<u32>, i64, bool);
        let (address, fund_by, pays, found): Row = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT t.address, t.fund_by_height, d.pays,
                    d.lock IS NOT NULL
                        OR EXISTS (SELECT 1 FROM deposit_fundings f WHERE f.hash = d.hash)
                 FROM deposits d LEFT JOIN deposit_terms t ON t.hash = d.hash
                 WHERE d.hash = ?1",
                [hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?)
        })?;
        let (Some(address), Some(fund_by), false) = (address, fund_by, found) else {
            return Ok(());
        };
        let network = licash_onchain::network(self.network());
        let script = address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(invalid)?
            .require_network(network)
            .map_err(invalid)?
            .script_pubkey();
        let Some(deep) = tip.checked_add(1).and_then(|t| t.checked_sub(via.depth)) else {
            return Ok(());
        };
        for height in via.from_height..=fund_by.min(deep) {
            let block_hash = chain.hash(height).await.map_err(Error::Chain)?;
            let matched = match chain.filter(&block_hash).await.map_err(Error::Chain)? {
                None => true,
                Some(filter) => BlockFilter::new(&filter)
                    .match_any(&block_hash, std::iter::once(script.as_bytes()))
                    .map_err(|e| Error::Chain(format!("the filter of block {block_hash}: {e}")))?,
            };
            if !matched {
                continue;
            }
            let block = checked_block(chain, &block_hash).await?;
            let paid = block.txdata.iter().find_map(|tx| {
                let vout = tx
                    .output
                    .iter()
                    .position(|o| o.script_pubkey == script && o.value.to_sat() == pays as u64)?;
                Some(OutPoint::new(tx.compute_txid(), vout as u32))
            });
            if let Some(coin) = paid {
                self.store.write(|tx| {
                    tx.execute(
                        "INSERT INTO deposit_fundings (hash, txid, vout, height)
                         VALUES (?1, ?2, ?3, ?4) ON CONFLICT (hash) DO NOTHING",
                        params![hash, coin.txid.to_byte_array(), coin.vout, height],
                    )?;
                    Ok(())
                })?;
                tracing::info!(hash = %hex::encode(hash), %coin, height, "deposit's payment found");
                return Ok(());
            }
        }
        Ok(())
    }

    /// [`Wallet::advance_deposit`] of the deposit of `hash` asked of a
    /// provider, paying at the hub at `url`: of `preimage`, taken back
    /// with `refund`, locking `amount` for a payment of `pays`; `body`
    /// what it asks the provider, `answered` once the provider's terms are
    /// kept.
    pub(crate) async fn advance_deposit_via(
        &self,
        hash: &[u8; 32],
        (url, via): (&str, &Via),
        (preimage, refund, (amount, pays)): ([u8; 32], &bitcoin::secp256k1::SecretKey, (u64, u64)),
        body: &str,
        answered: bool,
    ) -> Result<(), Error> {
        let provider = via.provider.as_str();
        if !answered {
            let body: DepositRequest = serde_json::from_str(body).map_err(invalid)?;
            let asked = self
                .post::<Depositing>(provider, swaps::DEPOSITS, &body)
                .await;
            let terms = match asked {
                Ok(terms) => terms,
                // Refused before the provider named an address.
                Err(Error::Refused { problem, .. }) => {
                    return self.cancel_deposit(hash, &format!("refused: {problem}"));
                }
                Err(e) => return Err(e),
            };
            let htlc = match self
                .check_terms_via(url, provider, hash, refund, pays, &terms)
                .await
            {
                Ok(htlc) => htlc,
                Err(Error::Invalid(reason)) => return self.cancel_deposit(hash, &reason),
                Err(e) => return Err(e),
            };
            let network = licash_onchain::network(self.network());
            self.store
                .write(|tx| keep_terms(tx, hash, &htlc, &terms, network))?;
            let (address, pays) = (&terms.address, terms.amount);
            tracing::info!(hash = %hex::encode(hash), %provider, %address, pays, "deposit terms");
        }
        type Told = (Option<[u8; 32]>, Option<u32>, Option<u32>, bool);
        let (txid, vout, height, locked): Told = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT f.txid, f.vout, f.height, d.lock IS NOT NULL
                 FROM deposits d LEFT JOIN deposit_fundings f ON f.hash = d.hash
                 WHERE d.hash = ?1",
                [hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?)
        })?;
        let path = swaps::deposit_state(hash);
        let status: ReceiveStatus = match (txid, vout, height, locked) {
            (Some(txid), Some(vout), Some(height), false) => {
                let funding = Funding {
                    txid: Txid::from_byte_array(txid).to_string(),
                    vout,
                    height,
                };
                match self.post::<ReceiveStatus>(provider, &path, &funding).await {
                    Ok(status) => status,
                    // Not found where the wallet found it, as after a
                    // reorganization, or not deep enough yet where the
                    // provider looks: looked for again.
                    Err(Error::Refused { problem, .. }) if problem.code == Code::Invalid => {
                        self.store.write(|tx| {
                            tx.execute("DELETE FROM deposit_fundings WHERE hash = ?1", [hash])?;
                            Ok(())
                        })?;
                        return Err(unavailable(provider, problem));
                    }
                    // Paid too late, say: its coin is the payer's after
                    // its timeout.
                    Err(Error::Refused { problem, .. }) => {
                        return self
                            .cancel_deposit(hash, &format!("its payment refused: {problem}"));
                    }
                    Err(e) => return Err(e),
                }
            }
            _ => self.get(provider, &path).await?,
        };
        let lock = status.lock().map_err(|p| unavailable(provider, p))?;
        let lock = match (status.state, lock) {
            (ReceiveState::Open, _) => return Ok(()),
            (ReceiveState::Canceled, _) => {
                return self.cancel_deposit(hash, "canceled by its provider");
            }
            (_, None) => return Err(unavailable(provider, "a deposit locked to no lock")),
            (_, Some(lock)) => lock,
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE deposits SET lock = ?2 WHERE hash = ?1",
                params![hash, lock.as_bytes()],
            )?;
            Ok(())
        })?;
        // As a hub's deposit: the preimage revealed only while the wallet
        // can still activate the lock, should the hub keep the notes.
        let lock = hex::encode(lock.as_bytes());
        let claimed = match self.tip()? {
            Some(_) => self.claim_protected(url, &lock, &preimage, amount).await,
            None => self.claim_paying(url, &lock, &preimage, amount).await,
        };
        match claimed {
            Ok(_) | Err(Error::AlreadyReceived) => {}
            Err(Error::Invalid(reason)) => return self.cancel_deposit(hash, &reason),
            Err(Error::PaysNothing) => {
                return self.cancel_deposit(hash, "its lock pays this wallet nothing");
            }
            Err(e) => return Err(e),
        }
        self.store.write(|tx| {
            tx.execute(
                "UPDATE deposits SET done_at = ?2 WHERE hash = ?1 AND done_at IS NULL",
                params![hash, now()],
            )?;
            Ok(())
        })?;
        tracing::info!(hash = %hex::encode(hash), %url, %provider, amount, "deposit received");
        Ok(())
    }

    /// The deposit `terms` the provider at `provider` answers for `hash`,
    /// for a payment of `pays` to lock notes at the hub at `url`: its
    /// address that of the provider's claim and the wallet's `refund`, its
    /// amount the payment asked, its timeout no later than the provider
    /// promises from the hub's tip. Other terms get nothing paid to them:
    /// the deposit is canceled unpaid.
    async fn check_terms_via(
        &self,
        url: &str,
        provider: &str,
        hash: &[u8; 32],
        refund: &bitcoin::secp256k1::SecretKey,
        pays: u64,
        terms: &Depositing,
    ) -> Result<Htlc, Error> {
        let (_, hub_info) = self.refresh(url).await?;
        let wrong =
            |why: String| Error::Invalid(format!("provider {provider} answered a deposit {why}"));
        let info: swaps::Info = self.get(provider, swaps::SWAPS_INFO).await?;
        let deposits = info
            .deposits
            .ok_or_else(|| wrong("but takes none".into()))?;
        let height = (hub_info.locks.as_ref().map(|l| l.height))
            .ok_or_else(|| Error::Invalid(format!("hub {url} follows no chain")))?;
        let claim = XOnlyPublicKey::from_slice(&terms.claim.0)
            .map_err(|_| wrong("claimed by no key".into()))?;
        let htlc = Htlc {
            hash: *hash,
            claim,
            refund: x_only(refund),
            timeout: terms.timeout,
            wait: None,
            sized: false,
        };
        let network = licash_onchain::network(self.network());
        let address = terms
            .address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .ok()
            .and_then(|a| a.require_network(network).ok());
        if address.is_none_or(|a| a.script_pubkey() != htlc.script_pubkey()) {
            return Err(wrong(format!("at {}, not its terms", terms.address)));
        }
        if terms.amount != pays {
            return Err(wrong(format!("of {} for {pays}", terms.amount)));
        }
        let latest = height
            .saturating_add(deposits.timeout)
            .saturating_add(TIP_MARGIN);
        if terms.timeout > latest || terms.fund_by.saturating_add(deposits.depth) > terms.timeout {
            return Err(wrong(format!(
                "timing out at block {}, paid by {}",
                terms.timeout, terms.fund_by
            )));
        }
        Ok(htlc)
    }
}
