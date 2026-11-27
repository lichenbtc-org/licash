//! Deposits on Bitcoin for wallets that ask ([`Provider::deposit`]): a payer
//! pays a coin to a hash-locked output ([`Htlc`]) under the wallet's hash,
//! which the provider claims with the preimage and a key of its own, and
//! the payer takes back with the wallet's refund key once timed out. Once
//! the coin is deep enough, the wallet tells the provider of it
//! ([`Provider::deposit_funded`]), and the provider locks the amount to the
//! wallet, as its notes at a hub it swaps at, under that hash. The wallet
//! claims the lock with its preimage, which the hub shows the provider,
//! who claims the coin with it. Unclaimed, the lock is refunded once
//! expired, and the payer takes the coin back: nothing is taken on trust,
//! as with a hub's own deposits, but the provider links the deposits of one
//! wallet, paid to one address.
//!
//! The lock expires early enough for the provider to learn the preimage
//! and claim the coin before it times out, should the hub keep it: by
//! forcing it out on Bitcoin with the lock's refund request
//! ([`crate::Config::lead`]), which the operator is alerted to make, then
//! claiming within [`DepositTerms::sweep`] blocks. So the coin times out
//! that lead, the sweep, the coin's window and depth and
//! [`RECEIVE_BLOCKS`] for the wallet to claim after the request at least:
//! declined where that exceeds [`DepositTerms::timeout`].
//!
//! The provider locks only once told of the coin, never on finding it: a
//! wallet that pays and never says so takes its coin back once timed out.
//! A provider holding too little at the hub by then locks nothing either.
//!
//! Deposits live in a table of their own, made in the provider's file once
//! it first takes them: a file of an older provider opens as it was.

use std::{
    collections::HashSet,
    sync::{Mutex, PoisonError},
};

use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    key::Secp256k1,
    secp256k1::SecretKey,
    Amount, OutPoint, Transaction, Txid, XOnlyPublicKey,
};
use licash::address::Address;
use licash_api::{
    swaps::{DepositRequest, Deposits},
    Depositing, Fee, Funding, Hex, Locks, Problem, ReceiveState, ReceiveStatus,
};
use licash_onchain::{deadline, deposit::Htlc};
use licash_wallet::{checked_block, first_spend, LockState, Transport};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};

use crate::{
    declined, now, store, unavailable, Chain, Error, Hold, Provider, MIN_ROOM, RECEIVE_BLOCKS,
};

/// Blocks the provider's and the wallet's heights may differ by.
const TIP_SLACK: u32 = 3;

/// The component the deposits' table is, and its version.
pub(crate) const COMPONENT: &str = "provider_deposits";
const VERSION: i64 = 1;

const SCHEMA: &str = "
-- Deposits on Bitcoin for wallets (`crate::deposits`). Each is a coin of
-- `pays` paid to the output claimed with the preimage of the wallet's
-- `hash` and the provider's `claim_key` (a secret key), taken back with
-- the wallet's `refund` key (x-only) after block `timeout`, and confirmed
-- by `fund_by`. Once the wallet tells of it, its `funding_*` is recorded,
-- then `expiry`, before the provider locks `amount` to `address` at hub
-- `hub` (its URL), then its `lock`. The wallet's claim shows the
-- `preimage`, which claims the coin with `sweep_tx`. `state` is open (not
-- told of, or the lock not certified yet), locked, paid (the preimage
-- known, the coin not claimed yet), swept, canceled (nothing locked, or
-- the lock refunded) or lost (the coin taken back after paying it on).
-- `source` is where it was asked from, as the service tells it, if known.
CREATE TABLE provider_deposits (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    hub TEXT NOT NULL,
    address BLOB NOT NULL,
    amount INTEGER NOT NULL CHECK (amount > 0),
    pays INTEGER NOT NULL CHECK (pays >= amount),
    refund BLOB NOT NULL CHECK (length(refund) = 32),
    claim_key BLOB NOT NULL CHECK (length(claim_key) = 32),
    timeout INTEGER NOT NULL,
    fund_by INTEGER NOT NULL,
    funding_txid BLOB CHECK (funding_txid IS NULL OR length(funding_txid) = 32),
    funding_vout INTEGER,
    funding_height INTEGER,
    expiry INTEGER,
    lock BLOB CHECK (lock IS NULL OR length(lock) = 32),
    preimage BLOB CHECK (preimage IS NULL OR length(preimage) = 32),
    sweep_tx BLOB,
    state TEXT NOT NULL
        CHECK (state IN ('open', 'locked', 'paid', 'swept', 'canceled', 'lost')),
    reason TEXT,
    source BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE INDEX provider_deposits_state ON provider_deposits (state);
";

/// Under way: the coin not told of, the lock not claimed or refunded, or
/// the coin not claimed.
const UNDER_WAY: &str = "state IN ('open', 'locked', 'paid')";

/// What the provider takes deposits on, as its operator set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositTerms {
    /// Its fee on the amount, paid on top: the hub's fee on the lock comes
    /// out of it.
    pub fee: Fee,
    /// What the coin pays on top for the miners of the provider's claim.
    pub miner: u64,
    /// The least and the most locked at once, in satoshis.
    pub min: u64,
    pub max: u64,
    /// Confirmations the coin needs before the provider locks.
    pub depth: u32,
    /// Blocks from the request within which the coin must confirm.
    pub window: u32,
    /// The most blocks from the request to the coin's timeout.
    pub timeout: u32,
    /// Blocks within which the provider's claim of the coin confirms once
    /// it holds the preimage, its fee rising as they run out.
    pub sweep: u32,
    /// The most deposits under way at once.
    pub max_open: u64,
}

impl Default for DepositTerms {
    fn default() -> Self {
        Self {
            fee: Fee {
                base: 0,
                ppm: 5_000,
            },
            miner: 500,
            min: 10_000,
            max: 1_000_000,
            depth: 3,
            window: 12,
            timeout: 1_008,
            sweep: 24,
            max_open: 100,
        }
    }
}

impl DepositTerms {
    fn offered(&self) -> Deposits {
        Deposits {
            fee: self.fee,
            miner: self.miner,
            min: self.min,
            max: self.max,
            depth: self.depth,
            window: self.window,
            timeout: self.timeout,
        }
    }
}

/// Where a deposit stands at the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositState {
    Open,
    Locked,
    Paid,
    Swept,
    Canceled,
    Lost,
}

impl DepositState {
    fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Paid => "paid",
            Self::Swept => "swept",
            Self::Canceled => "canceled",
            Self::Lost => "lost",
        }
    }

    fn of(name: &str) -> Self {
        match name {
            "locked" => Self::Locked,
            "paid" => Self::Paid,
            "swept" => Self::Swept,
            "canceled" => Self::Canceled,
            "lost" => Self::Lost,
            _ => Self::Open,
        }
    }
}

/// A deposit as the provider recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub hash: [u8; 32],
    /// The hub's URL, as the provider's wallet knows it.
    pub hub: String,
    pub address: Vec<u8>,
    /// What it locks to the wallet.
    pub amount: u64,
    /// What its coin pays: `amount`, the provider's fee and its claim's
    /// miners.
    pub pays: u64,
    pub refund: [u8; 32],
    claim_key: [u8; 32],
    pub timeout: u32,
    pub fund_by: u32,
    /// Its coin, and the block it confirmed in, once told of.
    pub funding: Option<(OutPoint, u32)>,
    /// Its lock's expiry, recorded before locking.
    pub expiry: Option<u32>,
    pub lock: Option<[u8; 32]>,
    preimage: Option<[u8; 32]>,
    /// The provider's claim of its coin, as last made.
    pub sweep: Option<Transaction>,
    pub state: DepositState,
    pub reason: Option<String>,
    pub created_at: i64,
}

impl Deposit {
    /// The output its coin pays.
    pub fn htlc(&self) -> Result<Htlc, Error> {
        let key = |bytes: &[u8; 32]| {
            XOnlyPublicKey::from_slice(bytes).map_err(|e| Error::Setup(e.to_string()))
        };
        Ok(Htlc {
            hash: self.hash,
            claim: key(&self.claim_public()?)?,
            refund: key(&self.refund)?,
            timeout: self.timeout,
            wait: None,
            // As a hub's deposits: the provider claims with the preimage
            // the wallet's claim of its lock showed, whatever its size.
            sized: false,
        })
    }

    fn claim_secret(&self) -> Result<SecretKey, Error> {
        SecretKey::from_slice(&self.claim_key).map_err(|e| Error::Setup(e.to_string()))
    }

    fn claim_public(&self) -> Result<[u8; 32], Error> {
        let secret = self.claim_secret()?;
        Ok(secret.x_only_public_key(&Secp256k1::new()).0.serialize())
    }

    /// Where it stands, as its wallet is told: paid on once the preimage
    /// is out, whether its coin was claimed or lost to the provider.
    fn status(&self) -> ReceiveStatus {
        let state = match self.state {
            DepositState::Open => ReceiveState::Open,
            DepositState::Locked => ReceiveState::Locked,
            DepositState::Paid | DepositState::Swept | DepositState::Lost => ReceiveState::Settled,
            DepositState::Canceled => ReceiveState::Canceled,
        };
        let lock = match state {
            ReceiveState::Locked | ReceiveState::Settled => self.lock,
            _ => None,
        };
        ReceiveStatus {
            state,
            lock: lock.map(|l| Hex(l.to_vec())),
        }
    }

    /// Its terms, as its wallet was answered.
    fn terms(&self, network: bitcoin::Network) -> Result<Depositing, Error> {
        Ok(Depositing {
            address: self.htlc()?.address(network).to_string(),
            amount: self.pays,
            claim: Hex(self.claim_public()?.to_vec()),
            timeout: self.timeout,
            fund_by: self.fund_by,
        })
    }
}

const DEPOSITS: &str = "SELECT hash, hub, address, amount, pays, refund, claim_key, timeout,
    fund_by, funding_txid, funding_vout, funding_height, expiry, lock, preimage, sweep_tx, state,
    reason, created_at FROM provider_deposits";

fn deposit_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<Deposit> {
    let txid: Option<[u8; 32]> = r.get(9)?;
    let vout: Option<u32> = r.get(10)?;
    let height: Option<u32> = r.get(11)?;
    let funding = match (txid, vout, height) {
        (Some(txid), Some(vout), Some(height)) => {
            Some((OutPoint::new(Txid::from_byte_array(txid), vout), height))
        }
        _ => None,
    };
    let sweep: Option<Vec<u8>> = r.get(15)?;
    Ok(Deposit {
        hash: r.get(0)?,
        hub: r.get(1)?,
        address: r.get(2)?,
        amount: r.get::<_, i64>(3)? as u64,
        pays: r.get::<_, i64>(4)? as u64,
        refund: r.get(5)?,
        claim_key: r.get(6)?,
        timeout: r.get(7)?,
        fund_by: r.get(8)?,
        funding,
        expiry: r.get(12)?,
        lock: r.get(13)?,
        preimage: r.get(14)?,
        sweep: sweep.and_then(|tx| deserialize(&tx).ok()),
        state: DepositState::of(&r.get::<_, String>(16)?),
        reason: r.get(17)?,
        created_at: r.get(18)?,
    })
}

/// Whether the deposits' table is in the provider's file.
pub(crate) fn kept(c: &Connection) -> Result<bool, Error> {
    Ok(licash_store::component_version(c, COMPONENT)
        .map_err(store::setup)?
        .is_some())
}

/// Whether a deposit was recorded under `hash`, in the file of `c`.
pub(crate) fn holds_hash(c: &Connection, hash: &[u8; 32]) -> Result<bool, Error> {
    if !kept(c)? {
        return Ok(false);
    }
    Ok(
        c.prepare("SELECT 1 FROM provider_deposits WHERE hash = ?1")?
            .exists([hash])?,
    )
}

/// What deposits told of and not locked yet will lock at hub `url`, in the
/// file of `c`: those whose expiry is recorded. A coin not told of sets
/// nothing aside, as anyone may ask for a deposit for free.
pub(crate) fn reserved(c: &Connection, url: &str) -> Result<u64, Error> {
    if !kept(c)? {
        return Ok(0);
    }
    Ok(c.query_row(
        "SELECT coalesce(sum(amount), 0) FROM provider_deposits
         WHERE hub = ?1 AND state = 'open' AND lock IS NULL AND expiry IS NOT NULL",
        [url],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

/// The deposits a provider takes.
pub(crate) struct Taker {
    terms: DepositTerms,
    /// What the operator was alerted of, once each.
    alerted: Mutex<HashSet<String>>,
}

fn random_key() -> [u8; 32] {
    loop {
        let mut bytes = [0; 32];
        OsRng.fill_bytes(&mut bytes);
        if SecretKey::from_slice(&bytes).is_ok() {
            return bytes;
        }
    }
}

/// Deposits on Bitcoin taken.
impl<T: Transport> Provider<T> {
    /// Take deposits on Bitcoin on `terms`: the provider takes none
    /// otherwise. Its table is made in its file if missing. Not of the hub
    /// of an [`crate::Issuer`].
    pub fn take_deposits(mut self, terms: DepositTerms) -> Result<Self, Error> {
        if self.issuer.is_some() {
            return Err(Error::Setup(
                "a hub providing swaps takes no deposits for others".into(),
            ));
        }
        if terms.min == 0
            || terms.min > terms.max
            || terms.max_open == 0
            || terms.depth == 0
            || terms.window == 0
            || terms.sweep == 0
        {
            return Err(Error::Setup(
                "deposits of at least 1 sat, at most the largest, some under way at once, and \
                 a depth, a window and sweep blocks of at least 1"
                    .into(),
            ));
        }
        self.store.write(|tx| {
            licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA).map_err(store::setup)
        })?;
        self.deposits = Some(Taker {
            terms,
            alerted: Mutex::default(),
        });
        Ok(self)
    }

    /// The deposits it takes, as its info tells wallets: none if it takes
    /// none.
    pub fn deposit_terms(&self) -> Option<Deposits> {
        self.deposits.as_ref().map(|t| t.terms.offered())
    }

    /// Deposits under way, in the provider's file whether it takes them now
    /// or not. Each needs a view of the chain, and the provider following
    /// it.
    pub fn open_deposits(&self) -> Result<u64, Error> {
        self.store.read(|c| {
            if !kept(c)? {
                return Ok(0);
            }
            Ok(c.query_row(
                &format!("SELECT count(*) FROM provider_deposits WHERE {UNDER_WAY}"),
                [],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
    }

    /// The deposit under `hash`, if one is.
    pub fn deposit_record(&self, hash: &[u8; 32]) -> Result<Option<Deposit>, Error> {
        self.store.read(|c| {
            if !kept(c)? {
                return Ok(None);
            }
            Ok(
                c.query_row(&format!("{DEPOSITS} WHERE hash = ?1"), [hash], deposit_of)
                    .optional()?,
            )
        })
    }

    /// Where the deposit under `hash` stands, as its wallet is told.
    pub fn deposit_status(&self, hash: &[u8; 32]) -> Result<Option<ReceiveStatus>, Error> {
        Ok(self.deposit_record(hash)?.map(|d| d.status()))
    }

    fn network(&self) -> bitcoin::Network {
        licash_onchain::network(self.wallet.network())
    }

    /// The terms of the deposit `request` asks for, recorded; the same
    /// terms if asked before. Declined unless the provider swaps at the hub,
    /// holds enough there now, the coin's timeout falls within its terms,
    /// and the hash is the deposit's alone. Unavailable past `max_open`
    /// under way, or past [`crate::PER_SOURCE`] asked and not told of from
    /// `source`, if known. `chain` is the provider's view of Bitcoin.
    pub async fn deposit(
        &self,
        request: &DepositRequest,
        source: Option<&[u8]>,
        chain: &impl Chain,
    ) -> Result<Depositing, Problem> {
        let taker = self
            .deposits
            .as_ref()
            .ok_or_else(|| declined("the provider takes no deposits on Bitcoin"))?;
        let hash = request.hash()?;
        let refund = request.refund()?;
        XOnlyPublicKey::from_slice(&refund).map_err(|_| Problem::invalid("not an x-only key"))?;
        let terms = &taker.terms;
        if let Some(deposit) = self.deposit_record(&hash).map_err(unavailable)? {
            return self.deposit_again(&deposit, request, &refund);
        }
        if !(terms.min..=terms.max).contains(&request.amount) {
            return Err(Problem::invalid(format!(
                "deposits of {} to {} sat",
                terms.min, terms.max
            )));
        }
        // As the hubs last said of themselves: the request reaches none.
        let hubs = self.wallet.hubs().map_err(unavailable)?;
        if hubs.iter().any(|(_, info)| info.address == request.address) {
            return Err(Problem::invalid("a hub's address is not a wallet's"));
        }
        let Some((url, locks)) = hubs
            .iter()
            .find(|(_, info)| info.address == request.hub)
            .and_then(|(url, info)| Some((url.clone(), info.locks.clone()?)))
        else {
            return Err(declined("no deposits at this hub"));
        };
        let Some(lead) = self.config.lead(&locks) else {
            return Err(declined("no deposits at this hub now"));
        };
        let tip = chain.height().await.map_err(unavailable)?;
        let blocks = [
            terms.window,
            terms.depth,
            RECEIVE_BLOCKS,
            lead,
            terms.sweep,
            TIP_SLACK,
        ]
        .iter()
        .fold(0u32, |sum, b| sum.saturating_add(*b));
        if blocks > terms.timeout {
            return Err(declined(format!(
                "deposits at this hub time out {blocks} blocks out, past the {} the provider \
                 takes",
                terms.timeout
            )));
        }
        let timeout = tip.saturating_add(blocks);
        let fund_by = tip.saturating_add(terms.window);
        let pays = terms.offered().pays(request.amount);
        let at = now();
        let max_open = i64::try_from(terms.max_open).unwrap_or(i64::MAX);
        let claim_key = random_key();
        {
            let _taking = self.taking.lock().unwrap_or_else(PoisonError::into_inner);
            let free = self
                .stock()
                .map_err(unavailable)?
                .into_iter()
                .find(|s| s.url == url)
                .map_or(0, |s| s.free);
            if free < request.amount {
                return Err(declined("the provider holds too little at this hub now"));
            }
            let taken = self
                .store
                .write(|tx| {
                    let other = tx
                        .prepare("SELECT 1 FROM provider_swaps WHERE hash = ?1")?
                        .exists([hash])?
                        || tx
                            .prepare("SELECT 1 FROM provider_donations WHERE hash = ?1")?
                            .exists([hash])?
                        || crate::receives::holds_hash(tx, &hash)?;
                    if other {
                        return Ok(Some(declined("a hash taken before")));
                    }
                    let open: i64 = tx.query_row(
                        &format!("SELECT count(*) FROM provider_deposits WHERE {UNDER_WAY}"),
                        [],
                        |r| r.get(0),
                    )?;
                    if open >= max_open {
                        return Ok(Some(unavailable(
                            "too many deposits under way: try again later",
                        )));
                    }
                    if let Some(source) = source {
                        let untold: u32 = tx.query_row(
                            "SELECT count(*) FROM provider_deposits
                             WHERE state = 'open' AND funding_txid IS NULL AND source = ?1",
                            [source],
                            |r| r.get(0),
                        )?;
                        if untold >= crate::PER_SOURCE {
                            return Ok(Some(unavailable(
                                "too many deposits asked from this source and not paid: try \
                                 again later",
                            )));
                        }
                    }
                    tx.execute(
                        "INSERT INTO provider_deposits (hash, hub, address, amount, pays, refund,
                            claim_key, timeout, fund_by, state, source, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'open', ?10, ?11, ?11)",
                        params![
                            hash,
                            url,
                            request.address.to_bytes(),
                            store::sat(request.amount)?,
                            store::sat(pays)?,
                            refund,
                            claim_key,
                            timeout,
                            fund_by,
                            source,
                            at
                        ],
                    )?;
                    Ok(None)
                })
                .map_err(unavailable)?;
            if let Some(refused) = taken {
                return Err(refused);
            }
        }
        let deposit = self
            .deposit_record(&hash)
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("the deposit was not recorded"))?;
        tracing::info!(hash = %hex::encode(hash), %url, amount = request.amount, pays, timeout, "deposit taken");
        deposit.terms(self.network()).map_err(unavailable)
    }

    /// The deposit `deposit` asked for again: its terms, if the same.
    fn deposit_again(
        &self,
        deposit: &Deposit,
        request: &DepositRequest,
        refund: &[u8; 32],
    ) -> Result<Depositing, Problem> {
        let hubs = self.wallet.hubs().map_err(unavailable)?;
        let hub = hubs
            .iter()
            .find(|(url, _)| *url == deposit.hub)
            .map(|(_, info)| info.address);
        let same = hub == Some(request.hub)
            && deposit.address == request.address.to_bytes()
            && deposit.amount == request.amount
            && deposit.refund == *refund;
        if !same {
            return Err(declined("another deposit under this hash"));
        }
        if deposit.state == DepositState::Canceled && deposit.funding.is_none() {
            return Err(declined(format!(
                "the deposit was canceled: {}",
                deposit.reason.as_deref().unwrap_or("")
            )));
        }
        deposit.terms(self.network()).map_err(unavailable)
    }

    /// The wallet tells of the coin of the deposit under `hash`: checked
    /// in the best chain's block at its height, paying exactly what the
    /// deposit asked to its output by `fund_by`, and deep enough; then the
    /// provider locks to the wallet, if it may still. Where the deposit
    /// stands then.
    pub async fn deposit_funded(
        &self,
        hash: &[u8; 32],
        funding: &Funding,
        chain: &impl Chain,
    ) -> Result<ReceiveStatus, Problem> {
        let taker = self
            .deposits
            .as_ref()
            .ok_or_else(|| declined("the provider takes no deposits on Bitcoin"))?;
        let Some(deposit) = self.deposit_record(hash).map_err(unavailable)? else {
            return Err(declined("no such deposit"));
        };
        let txid: Txid = funding
            .txid
            .parse()
            .map_err(|_| Problem::invalid("not a transaction id"))?;
        let outpoint = OutPoint::new(txid, funding.vout);
        match deposit.funding {
            Some((known, _)) if known == outpoint => return Ok(deposit.status()),
            Some(_) => return Err(declined("the deposit was paid by another coin")),
            None if deposit.state != DepositState::Open => return Ok(deposit.status()),
            None => {}
        }
        if funding.height > deposit.fund_by {
            return Err(declined(format!(
                "a coin confirmed after block {}",
                deposit.fund_by
            )));
        }
        let tip = chain.height().await.map_err(unavailable)?;
        let depth = taker.terms.depth;
        if tip.saturating_add(1) < funding.height.saturating_add(depth) {
            return Err(Problem::invalid(format!(
                "a coin confirmed {depth} blocks deep first"
            )));
        }
        let htlc = deposit.htlc().map_err(unavailable)?;
        let block_hash = chain.hash(funding.height).await.map_err(unavailable)?;
        let block = checked_block(chain, &block_hash)
            .await
            .map_err(unavailable)?;
        let paid = block
            .txdata
            .iter()
            .find(|tx| tx.compute_txid() == txid)
            .and_then(|tx| tx.output.get(funding.vout as usize));
        let pays = paid.is_some_and(|out| {
            out.script_pubkey == htlc.script_pubkey() && out.value == Amount::from_sat(deposit.pays)
        });
        if !pays {
            return Err(Problem::invalid(format!(
                "no coin of {} sat to the deposit's address there",
                deposit.pays
            )));
        }
        {
            let Some(_hold) = Hold::take(&self.busy, *hash) else {
                return Err(unavailable("the deposit is in hand: ask again"));
            };
            self.store
                .write(|tx| {
                    tx.execute(
                        "UPDATE provider_deposits SET funding_txid = ?2, funding_vout = ?3,
                            funding_height = ?4, updated_at = ?5
                         WHERE hash = ?1 AND funding_txid IS NULL",
                        params![
                            hash,
                            txid.to_byte_array(),
                            funding.vout,
                            funding.height,
                            now()
                        ],
                    )?;
                    Ok(())
                })
                .map_err(unavailable)?;
            tracing::info!(hash = %hex::encode(hash), %outpoint, height = funding.height, "deposit paid");
            if let Err(e) = self.follow_deposit(taker, hash, chain, tip).await {
                tracing::warn!(hash = %hex::encode(hash), "deposit pending: {e}");
            }
        }
        Ok(self
            .deposit_status(hash)
            .map_err(unavailable)?
            .expect("recorded"))
    }

    /// Take every deposit under way on, as `chain` and the provider's wallet
    /// know it. The deposits that could not move now, by hash and why;
    /// `chain` if its height is unknown.
    pub async fn follow_deposits(
        &self,
        chain: &impl Chain,
    ) -> Result<Vec<(String, String)>, Error> {
        let Some(taker) = &self.deposits else {
            return Ok(Vec::new());
        };
        let open: Vec<[u8; 32]> = self.store.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT hash FROM provider_deposits WHERE {UNDER_WAY} ORDER BY created_at, rowid"
            ))?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut pending = Vec::new();
        if open.is_empty() {
            return Ok(pending);
        }
        let tip = match chain.height().await {
            Ok(tip) => tip,
            Err(e) => {
                tracing::warn!(error = %e, "no height for the provider's deposits");
                pending.push(("chain".to_owned(), e));
                return Ok(pending);
            }
        };
        for hash in open {
            let Some(_hold) = Hold::take(&self.busy, hash) else {
                continue;
            };
            if let Err(e) = self.follow_deposit(taker, &hash, chain, tip).await {
                tracing::warn!(hash = %hex::encode(hash), "deposit pending: {e}");
                pending.push((hex::encode(hash), e.to_string()));
            }
        }
        Ok(pending)
    }

    /// Act on the deposit `hash` under way at height `tip` of `chain`.
    async fn follow_deposit(
        &self,
        taker: &Taker,
        hash: &[u8; 32],
        chain: &impl Chain,
        tip: u32,
    ) -> Result<(), Error> {
        let Some(deposit) = self.deposit_record(hash)? else {
            return Ok(());
        };
        match deposit.state {
            DepositState::Paid => return self.sweep_deposit(taker, &deposit, chain, tip).await,
            DepositState::Open | DepositState::Locked => {}
            _ => return Ok(()),
        }
        let lock = match (deposit.lock, deposit.expiry, deposit.funding) {
            (Some(lock), _, _) => lock,
            // Told of no coin: given up once a lock would come too late.
            (None, None, None) => {
                let last = deposit
                    .fund_by
                    .saturating_add(taker.terms.depth)
                    .saturating_add(RECEIVE_BLOCKS);
                if tip > last {
                    return self.finish_deposit(hash, DepositState::Canceled, "never told paid");
                }
                return Ok(());
            }
            (None, None, Some(_)) => {
                let Some(expiry) = self.deposit_expiry(&deposit, taker, tip)? else {
                    return self.finish_deposit(
                        hash,
                        DepositState::Canceled,
                        "told paid too late to lock",
                    );
                };
                // Set aside from what swaps lock at its hub only now it is
                // paid, if the provider holds enough there still: else
                // nothing locked, and the payer takes the coin back once
                // timed out. Recorded before locking: a lock made, then the
                // provider stopped, is looked for, never made again blindly.
                let enough = {
                    let _taking = self.taking.lock().unwrap_or_else(PoisonError::into_inner);
                    let free = self
                        .stock()?
                        .into_iter()
                        .find(|s| s.url == deposit.hub)
                        .map_or(0, |s| s.free);
                    if free >= deposit.amount {
                        self.store.write(|tx| {
                            tx.execute(
                                "UPDATE provider_deposits SET expiry = ?2, updated_at = ?3
                                 WHERE hash = ?1 AND expiry IS NULL",
                                params![hash, expiry, now()],
                            )?;
                            Ok(())
                        })?;
                    }
                    free >= deposit.amount
                };
                if !enough {
                    let why = "the provider holds too little at its hub now";
                    return self.finish_deposit(hash, DepositState::Canceled, why);
                }
                return self.lock_deposit(&deposit, expiry).await;
            }
            (None, Some(expiry), _) => {
                let locks = self.wallet.locks()?;
                let found = locks
                    .iter()
                    .find(|l| l.hub == deposit.hub && l.hash == deposit.hash);
                match found {
                    Some(found) => {
                        let lock = crate::lock_id(&found.id)?;
                        self.set_deposit_lock(hash, &lock)?;
                        lock
                    }
                    // Stopped before the wallet recorded a lock: none made.
                    None => return self.lock_deposit(&deposit, expiry).await,
                }
            }
        };
        let state = match self.wallet.follow_lock(&hex::encode(lock)).await {
            Ok(lock) => lock.state,
            Err(licash_wallet::Error::Abandoned { reason, .. }) => LockState::Abandoned(reason),
            Err(e) => {
                if let licash_wallet::Error::Refused { .. } = e {
                    let record = self
                        .wallet
                        .lock_record(&licash::spend::ProposalId::from_bytes(lock))?;
                    if let LockState::Abandoned(reason) = record.state {
                        let why = format!("its hub refused the lock: {reason}");
                        return self.finish_deposit(hash, DepositState::Canceled, &why);
                    }
                }
                self.check_withheld_deposit(taker, &deposit, &lock)?;
                return Err(e.into());
            }
        };
        match state {
            LockState::Locked => {
                if deposit.state == DepositState::Open {
                    self.finish_deposit(hash, DepositState::Locked, "locked")?;
                    tracing::info!(hash = %hex::encode(hash), lock = %hex::encode(lock), "deposit locked");
                }
                self.check_withheld_deposit(taker, &deposit, &lock)
            }
            LockState::Paid(preimage) => {
                self.store.write(|tx| {
                    tx.execute(
                        "UPDATE provider_deposits SET preimage = ?2, state = 'paid', updated_at = ?3
                         WHERE hash = ?1",
                        params![hash, preimage, now()],
                    )?;
                    Ok(())
                })?;
                let deposit = self.deposit_record(hash)?.expect("recorded");
                self.sweep_deposit(taker, &deposit, chain, tip).await
            }
            LockState::Refunded => self.finish_deposit(
                hash,
                DepositState::Canceled,
                "its lock was refunded: never claimed",
            ),
            LockState::Abandoned(reason) => {
                let why = format!("its hub refused the lock: {reason}");
                self.finish_deposit(hash, DepositState::Canceled, &why)
            }
            _ => Ok(()),
        }
    }

    /// The expiry of the deposit's lock at `tip`: the preimage forced out
    /// on Bitcoin in time should the hub keep it, and the coin claimed
    /// before it times out, within the hub's window. None if too soon to
    /// lock.
    fn deposit_expiry(
        &self,
        deposit: &Deposit,
        taker: &Taker,
        tip: u32,
    ) -> Result<Option<u32>, Error> {
        let Some(locks) = self.locks_at(&deposit.hub)? else {
            return Ok(None);
        };
        let Some(lead) = self.config.lead(&locks) else {
            return Ok(None);
        };
        let latest = locks
            .latest_expiry(locks.min_depth.max(1))
            .map_err(|p| Error::Setup(p.message))?;
        let expiry = deposit
            .timeout
            .saturating_sub(taker.terms.sweep)
            .saturating_sub(lead)
            .min(latest);
        let room = tip.max(locks.height).saturating_add(MIN_ROOM);
        Ok((expiry >= room).then_some(expiry))
    }

    fn locks_at(&self, url: &str) -> Result<Option<Locks>, Error> {
        Ok(self
            .wallet
            .hubs()?
            .into_iter()
            .find(|(u, _)| u == url)
            .and_then(|(_, info)| info.locks))
    }

    /// Lock the deposit's amount to its wallet, expiring at `expiry`:
    /// canceled if nothing was locked.
    async fn lock_deposit(&self, deposit: &Deposit, expiry: u32) -> Result<(), Error> {
        let hash = &deposit.hash;
        let address = Address::from_bytes(&deposit.address).map_err(licash_wallet::Error::from)?;
        let mut tries = 0;
        let locked = loop {
            let locked = self
                .wallet
                .lock(&deposit.hub, &address, deposit.amount, *hash, Some(expiry))
                .await;
            match locked {
                Err(licash_wallet::Error::NoteTaken) if tries < 3 => tries += 1,
                locked => break locked,
            }
        };
        match locked {
            Ok(lock) => {
                let id = crate::lock_id(&lock.id)?;
                self.set_deposit_lock(hash, &id)?;
                if lock.state == LockState::Locked {
                    self.finish_deposit(hash, DepositState::Locked, "locked")?;
                }
                tracing::info!(hash = %hex::encode(hash), lock = %lock.id, expiry, "deposit locked");
                Ok(())
            }
            // Recorded, its outcome unknown: followed next time.
            Err(licash_wallet::Error::Pending { id, reason }) => {
                tracing::warn!(hash = %hex::encode(hash), %id, reason, "deposit lock pending");
                self.set_deposit_lock(hash, &crate::lock_id(&id)?)
            }
            Err(e) => {
                self.finish_deposit(hash, DepositState::Canceled, &format!("not locked: {e}"))
            }
        }
    }

    /// Alert the operator, once, if the deposit's certified `lock` expired
    /// long enough ago for its hub to refund it plainly, neither paid nor
    /// refunded: the hub may keep the preimage the wallet revealed to it.
    fn check_withheld_deposit(
        &self,
        taker: &Taker,
        deposit: &Deposit,
        lock: &[u8; 32],
    ) -> Result<(), Error> {
        let Some(expiry) = deposit.expiry else {
            return Ok(());
        };
        let locks = self.locks_at(&deposit.hub)?;
        // A hub that follows no chain now says nothing of when it refunds:
        // the operator is told early rather than late.
        let (depth, reaction, height) = locks.map_or((1, 0, u32::MAX), |l| {
            (l.min_depth.max(1), l.reaction, l.height)
        });
        if height < expiry.saturating_add(depth).saturating_add(reaction) {
            return Ok(());
        }
        let message = format!(
            "Hub {} has neither paid nor refunded the provider's lock {} of deposit {}, expired \
             at {expiry}: it may keep the preimage. Request the lock's refund on Bitcoin, \
             confirmed after height {} and by height {}, for the hub to publish the preimage, \
             and claim the deposit's coin with it by height {}.",
            deposit.hub,
            hex::encode(lock),
            hex::encode(deposit.hash),
            expiry.saturating_add(depth),
            expiry.saturating_add(self.config.confirm),
            deposit.timeout,
        );
        self.alert_deposit(
            taker,
            format!("withheld {}", hex::encode(deposit.hash)),
            &message,
        )
    }

    /// Claim the coin of the deposit paid on, with the preimage, to the
    /// wallet's fallback address: at the rate the blocks left before it
    /// times out call for ([`deadline::rate`]), all of the coin but dust at
    /// most, made again in place of the one before as that rate rises.
    /// Swept once the claim is deep enough; lost if its payer took the
    /// coin back.
    async fn sweep_deposit(
        &self,
        taker: &Taker,
        deposit: &Deposit,
        chain: &impl Chain,
        tip: u32,
    ) -> Result<(), Error> {
        let hash = &deposit.hash;
        let name = hex::encode(hash);
        let (outpoint, height) = deposit
            .funding
            .ok_or_else(|| Error::Setup(format!("deposit {name} paid on with no coin")))?;
        let preimage = deposit
            .preimage
            .ok_or_else(|| Error::Setup(format!("deposit {name} paid on with no preimage")))?;
        let htlc = deposit.htlc()?;
        let script = htlc.script_pubkey();
        if let Some((at, spend)) = first_spend(chain, outpoint, &script, height..=tip).await? {
            if !htlc.claimed_by(&spend, outpoint) {
                let why = "its payer took the coin back after the lock was claimed";
                return self.lost_deposit(taker, hash, why);
            }
            if tip.saturating_add(1) >= at.saturating_add(taker.terms.depth) {
                tracing::info!(hash = %name, txid = %spend.compute_txid(), "deposit swept");
                return self.finish_deposit(hash, DepositState::Swept, "claimed");
            }
            return Ok(());
        }
        let left = deposit.timeout.saturating_sub(tip);
        let rate = self.deadline_rate(chain, left).await;
        let to = match &deposit.sweep {
            Some(old) => old.output[0].script_pubkey.clone(),
            None => self.wallet.fallback_address()?.script_pubkey(),
        };
        let secret = deposit.claim_secret()?;
        let value = Amount::from_sat(deposit.pays);
        let build = |rate| {
            htlc.claim_capped(outpoint, value, to.clone(), rate, &secret, &preimage)
                .map_err(|e| licash_wallet::Error::Invalid(e.to_string()))
        };
        let tx = match deadline::remake(deposit.sweep.as_ref(), value, rate, build)? {
            Some(tx) => {
                self.store.write(|t| {
                    t.execute(
                        "UPDATE provider_deposits SET sweep_tx = ?2, updated_at = ?3
                         WHERE hash = ?1",
                        params![hash, serialize(&tx), now()],
                    )?;
                    Ok(())
                })?;
                tracing::info!(hash = %name, txid = %tx.compute_txid(), %rate, left, "claiming a deposit's coin");
                tx
            }
            None => deposit.sweep.clone().expect("a claim made before"),
        };
        if let Err(e) = chain.broadcast(&tx).await {
            tracing::debug!(hash = %name, "claim not broadcast: {e}");
        }
        if left <= taker.terms.sweep / 2 {
            let message = format!(
                "The claim {} of deposit {name}'s coin is unconfirmed {left} blocks before its \
                 payer may take the coin back.",
                tx.compute_txid()
            );
            self.alert_deposit(taker, format!("unclaimed {name}"), &message)?;
        }
        Ok(())
    }

    fn lost_deposit(&self, taker: &Taker, hash: &[u8; 32], why: &str) -> Result<(), Error> {
        let name = hex::encode(hash);
        let message = format!("Deposit {name} is lost: {why}.");
        self.alert_deposit(taker, format!("lost {name}"), &message)?;
        self.finish_deposit(hash, DepositState::Lost, why)
    }

    fn alert_deposit(&self, taker: &Taker, what: String, message: &str) -> Result<(), Error> {
        let first = taker
            .alerted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(what);
        if first {
            tracing::error!("{message}");
            self.alert(message)?;
        }
        Ok(())
    }

    fn set_deposit_lock(&self, hash: &[u8; 32], lock: &[u8; 32]) -> Result<(), Error> {
        self.store.write(|tx| {
            tx.execute(
                "UPDATE provider_deposits SET lock = ?2, updated_at = ?3
                 WHERE hash = ?1 AND lock IS NULL",
                params![hash, lock, now()],
            )?;
            Ok(())
        })
    }

    fn finish_deposit(&self, hash: &[u8; 32], state: DepositState, why: &str) -> Result<(), Error> {
        tracing::info!(hash = %hex::encode(hash), state = state.name(), why, "deposit");
        self.store.write(|tx| {
            tx.execute(
                "UPDATE provider_deposits SET state = ?2, reason = ?3, updated_at = ?4
                 WHERE hash = ?1",
                params![hash, state.name(), why, now()],
            )?;
            Ok(())
        })
    }
}
