//! The swap provider API, version 1: a provider swaps notes at one hub for
//! notes at another, atomically, with a timed lock at each under one hash.
//!
//! | Path | Body | Answer |
//! |------|------|--------|
//! | `GET /v1/swaps/info` |  | [`Info`] |
//! | `POST /v1/swaps`     | [`Request`] | [`Swap`] |
//! | `GET /v1/swaps/{id}` |  | [`Swap`] |
//! | `POST /v1/swaps/chain` | [`ChainRequest`] | [`ChainSwap`] |
//! | `GET /v1/swaps/chain/{id}` |  | [`ChainSwap`] |
//! | `POST /v1/swaps/lightning` | [`LightningRequest`] | [`LightningSwap`] |
//! | `GET /v1/swaps/lightning/{id}` |  | [`LightningSwap`] |
//! | `POST /v1/swaps/receive` | [`ReceiveRequest`] | [`crate::Receiving`] |
//! | `GET /v1/swaps/receive/{hash}` |  | [`crate::ReceiveStatus`] |
//! | `POST /v1/swaps/deposit` | [`DepositRequest`] | [`crate::Depositing`] |
//! | `GET /v1/swaps/deposit/{hash}` |  | [`crate::ReceiveStatus`] |
//! | `POST /v1/swaps/deposit/{hash}` | [`crate::Funding`] | [`crate::ReceiveStatus`] |
//!
//! The client draws a preimage and locks, at hub `from`, the amount and the
//! provider's fee to [`Info::address`] under its hash, then asks for the
//! swap. Once the provider checked that lock, it locks the amount at hub
//! `to` to the client under the same hash, expiring [`Info::margin`]
//! blocks earlier at least. The client claims that lock with the preimage,
//! which its hub then shows the provider, who claims the client's lock with
//! it. A lock unclaimed is refunded once expired: if the provider never
//! locks, or the client never claims, each gets its own notes back.
//!
//! A provider with [`Info::chain`] pays notes out on Bitcoin the same way:
//! the client locks a coin's value and the provider's fee to it at hub
//! `from`, and the provider locks a coin on chain under the same hash
//! (licash_onchain's `Htlc`: the client's key and the preimage claim it,
//! the provider's key takes it back after its timeout). The client's claim
//! pays its payee, and shows the provider the preimage it claims the
//! client's lock with.
//!
//! A provider with [`Info::lightning`] pays Lightning invoices from its own
//! node the same way: the client locks the invoice's amount and the
//! provider's fee to it at hub `from`, under the invoice's hash, and the
//! provider pays the invoice along routes whose timelock ends
//! [`Lightning::slack`] blocks before that lock expires. The preimage the
//! payment buys claims the client's lock. When the invoice is a hub's,
//! asked for by a wallet under a hash of its own, that wallet claims what
//! the hub locks to it with its own preimage: notes at one hub pay notes at
//! another, with no notes of the provider at the other. A payment that
//! fails leaves the client's lock to be refunded once expired.
//!
//! Hubs are named by their addresses ([`crate::Info::address`]), as client
//! and provider may reach one hub at different URLs. Anything else is a
//! [`Problem`]; [`crate::Code::Declined`] when the provider takes no such
//! swap.

use licash::{address::Address, spend::ProposalId};
use serde::{Deserialize, Serialize};

use crate::{Fee, Funding, Hex, Problem};

pub const SWAPS: &str = "/v1/swaps";
pub const SWAPS_INFO: &str = "/v1/swaps/info";
/// The path of [`swap_state`], as a route.
pub const SWAP_STATE: &str = "/v1/swaps/{id}";
pub const CHAIN_SWAPS: &str = "/v1/swaps/chain";
/// The path of [`chain_swap_state`], as a route.
pub const CHAIN_SWAP_STATE: &str = "/v1/swaps/chain/{id}";
/// Where invoices are paid over Lightning ([`LightningRequest`]).
pub const LIGHTNING_SWAPS: &str = "/v1/swaps/lightning";
/// The path of [`lightning_swap_state`], as a route.
pub const LIGHTNING_SWAP_STATE: &str = "/v1/swaps/lightning/{id}";

/// Where a wallet asks a provider for an invoice paying it in notes
/// ([`ReceiveRequest`], [`Info::receive`]).
pub const RECEIVES: &str = "/v1/swaps/receive";
/// The path of [`receive_state`], as a route.
pub const RECEIVE_STATE: &str = "/v1/swaps/receive/{hash}";

/// Where a wallet asks a provider for a deposit on Bitcoin paid on in notes
/// ([`DepositRequest`], [`Info::deposits`]).
pub const DEPOSITS: &str = "/v1/swaps/deposit";
/// The path of [`deposit_state`], as a route: where the deposit stands,
/// and where its wallet tells the provider of its payment.
pub const DEPOSIT_STATE: &str = "/v1/swaps/deposit/{hash}";

/// Where a provider taking donations ([`Info::donations`]) serves the
/// LNURL-pay request (LUD-06) of donations to the wallet of a Licash code,
/// its text in place of `{code}`.
pub const DONATE: &str = "/v1/lnurlp/{code}";
/// Where a payer asks for the invoice of a donation (LNURL-pay's callback),
/// its amount in millisatoshis as `?amount=`.
pub const DONATE_CALLBACK: &str = "/v1/lnurlp/{code}/callback";

/// Where a wallet registers the name of its Lightning Address of donations
/// at a provider serving them ([`Donations::names`]): [`NameRequest`],
/// answered [`Named`].
pub const NAMES: &str = "/v1/names";
/// Where a provider serves the LNURL-pay request (LUD-16) of the Lightning
/// Address `{name}@` its [`Donations::names`], and its invoices.
pub const NAMED: &str = "/.well-known/lnurlp/{name}";
pub const NAMED_CALLBACK: &str = "/.well-known/lnurlp/{name}/callback";

/// A wallet's code, to be paid donations at the Lightning Address of the
/// name made of it ([`NAMES`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRequest {
    pub code: String,
}

/// The name a code's Lightning Address of donations is under, registered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Named {
    pub name: String,
}

/// The URL of [`DONATE`] for `code` at the provider whose public URL is
/// `base` ([`Donations::url`]).
pub fn donation_url(base: &str, code: &str) -> String {
    format!(
        "{}{}",
        base.trim_end_matches('/'),
        DONATE.replace("{code}", code)
    )
}

/// Where the swap of the client's lock `id` stands.
pub fn swap_state(id: &ProposalId) -> String {
    format!("{SWAPS}/{}", hex::encode(id.as_bytes()))
}

/// Where the payout of the client's lock `id` stands.
pub fn chain_swap_state(id: &ProposalId) -> String {
    format!("{CHAIN_SWAPS}/{}", hex::encode(id.as_bytes()))
}

/// Where the invoice payment for the client's lock `id` stands.
pub fn lightning_swap_state(id: &ProposalId) -> String {
    format!("{LIGHTNING_SWAPS}/{}", hex::encode(id.as_bytes()))
}

/// Where the receipt over Lightning under `hash` stands at a provider.
pub fn receive_state(hash: &[u8; 32]) -> String {
    format!("{RECEIVES}/{}", hex::encode(hash))
}

/// Where the deposit under `hash` stands at a provider.
pub fn deposit_state(hash: &[u8; 32]) -> String {
    format!("{DEPOSITS}/{}", hex::encode(hash))
}

/// What a provider swaps, and on what terms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    /// The address the client's lock pays.
    pub address: Address,
    /// Its fee on the amount swapped, which the client's lock pays on top.
    pub fee: Fee,
    /// The least and the most it swaps.
    pub min: u64,
    pub max: u64,
    /// Its lock expires this many blocks before the client's, at least, at
    /// every hub: the most of [`Hub::margin`].
    pub margin: u32,
    /// The hubs it swaps between.
    pub hubs: Vec<Hub>,
    /// The key it announces itself under on Nostr, x-only in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr: Option<String>,
    /// What it pays out on Bitcoin, if it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Chain>,
    /// What it pays over Lightning, if it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lightning: Option<Lightning>,
    /// The donations it takes over Lightning for the wallets of Licash
    /// codes, if it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub donations: Option<Donations>,
    /// The payments over Lightning it takes for wallets, paid on in notes
    /// at a hub it swaps at, if it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive: Option<Receives>,
    /// The deposits on Bitcoin it takes for wallets, paid on in notes at a
    /// hub it swaps at, if it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposits: Option<Deposits>,
    /// What it takes beyond this version of the protocol, by name, such
    /// as a later way of paying for swaps: a client uses one only if it
    /// names it. Empty from older providers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

impl Info {
    /// The hub at `address`, if the provider swaps there.
    pub fn hub(&self, address: &Address) -> Option<&Hub> {
        self.hubs.iter().find(|h| h.address == *address)
    }

    /// Blocks its lock at `hub` expires before the client's, at least.
    pub fn margin_at(&self, hub: &Hub) -> u32 {
        hub.margin.unwrap_or(self.margin)
    }
}

/// A hub a provider swaps at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hub {
    pub address: Address,
    /// The most it locks to a client there now.
    pub max: u64,
    /// Its lock there expires this many blocks before the client's, at
    /// least; [`Info::margin`] if not given. A provider that is not the
    /// hub learns the preimage from it only by forcing it out on Bitcoin,
    /// so this covers the hub's response window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub margin: Option<u32>,
}

/// What a provider pays out on Bitcoin: coins it locks to clients on
/// chain, for their locks at any of its hubs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    /// Its fee on a coin's value, which the client's lock pays on top.
    pub fee: Fee,
    /// What the client's lock pays on top for the miners of the coin.
    pub miner: u64,
    /// The fee rate it judges a claim confirms at soon, in sat per 1000
    /// virtual bytes: a hint, which a client budgets its claim at at least,
    /// within the fee it allows.
    pub rate: u64,
    /// The least and the most a coin it locks is worth.
    pub min: u64,
    pub max: u64,
    /// The coin's timeout is this many blocks before the client's lock
    /// expires, at least.
    pub margin: u32,
}

impl Chain {
    /// What a lock pays to have a coin worth `value` locked on chain: the
    /// value, the provider's fee and the miners'.
    pub fn pays(&self, value: u64) -> u64 {
        value
            .saturating_add(self.fee.due(value))
            .saturating_add(self.miner)
    }
}

/// What a provider takes donations on: over LNURL-pay at [`donation_url`]
/// of its public `url`, for the wallet of any Licash code naming a hub it
/// swaps at, paid there in notes less its fee, while its payee is offline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Donations {
    /// Where payers reach it, which may differ from where the wallet does.
    pub url: String,
    /// Its fee on each donation, taken from it.
    pub fee: Fee,
    /// The least and the most donated at once, in satoshis: at most what
    /// it holds at the payee's hub, too.
    pub min: u64,
    pub max: u64,
    /// The domain of the Lightning Addresses of donations it serves
    /// ([`NAMES`]), `host` or `host:port`, if it serves them: unknown to a
    /// provider of an older version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<String>,
}

/// What a provider takes over Lightning for a wallet that asks
/// ([`ReceiveRequest`]): a held invoice of its node, under the wallet's
/// hash, asking the amount and its fee. Once paid, the provider locks the
/// amount to the wallet at the hub under that hash, and settles with the
/// preimage the wallet's claim shows it: unclaimed, its lock is refunded
/// and the payment fails back to its payer. Nothing is taken on trust, but
/// the provider links the receipts of one wallet, paid to one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receives {
    /// Its fee on the amount, which the invoice asks on top.
    pub fee: Fee,
    /// The least and the most received at once, in satoshis.
    pub min: u64,
    pub max: u64,
}

impl Receives {
    /// What the invoice of a receipt of `amount` asks, in satoshis.
    pub fn asks(&self, amount: u64) -> u64 {
        amount.saturating_add(self.fee.due(amount))
    }
}

/// The [`Info::features`] of a provider whose receipts' invoices may ask
/// an amount of the wallet's and commit to a description's hash
/// ([`ReceiveRequest::asks`], [`ReceiveRequest::description_hash`]), as
/// LNURL-pay wants.
pub const FEATURE_RECEIVE_EXACT: &str = "receive-exact";

/// Ask a provider for an invoice whose payment it pays on as a lock of
/// `amount` to `address` at hub `hub`, under `hash`, the wallet's: the
/// invoice says `memo`, if given, to its payer. The same request again
/// answers the same invoice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveRequest {
    pub hub: Address,
    pub address: Address,
    pub amount: u64,
    pub hash: Hex,
    /// As [`crate::memo`] makes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// What the invoice asks, in satoshis, of a provider naming
    /// [`FEATURE_RECEIVE_EXACT`]: at least `amount` and its fee, the rest
    /// the provider's. Without, it asks exactly those ([`Receives::asks`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asks: Option<u64>,
    /// The SHA-256 hash of a description given elsewhere, which the
    /// invoice commits to instead of a memo, of a provider naming
    /// [`FEATURE_RECEIVE_EXACT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<Hex>,
}

impl ReceiveRequest {
    pub fn hash(&self) -> Result<[u8; 32], Problem> {
        self.hash.array("hash")
    }

    /// Its description hash, if it commits to one: never with a memo.
    pub fn checked_description_hash(&self) -> Result<Option<[u8; 32]>, Problem> {
        match &self.description_hash {
            None => Ok(None),
            Some(_) if self.memo.is_some() => {
                Err(Problem::invalid("a memo or a description hash, not both"))
            }
            Some(hash) => hash.array("description_hash").map(Some),
        }
    }

    /// What its invoice asks under `terms`: refused if less than the amount
    /// and the fee.
    pub fn asks_under(&self, terms: &Receives) -> Result<u64, Problem> {
        let least = terms.asks(self.amount);
        match self.asks {
            None => Ok(least),
            Some(asks) if asks >= least => Ok(asks),
            Some(asks) => Err(Problem::invalid(format!(
                "an invoice asking {asks} sat, less than {least} with the fee"
            ))),
        }
    }

    /// Its memo, if it says one, checked as [`crate::memo`] makes it.
    pub fn checked_memo(&self) -> Result<Option<String>, Problem> {
        match &self.memo {
            None => Ok(None),
            Some(text) => match crate::memo(text)? {
                normal if normal == *text => Ok(Some(normal)),
                _ => Err(Problem::invalid("a memo not as `memo` makes it")),
            },
        }
    }
}

/// What a provider takes on Bitcoin for a wallet that asks
/// ([`DepositRequest`]): a coin paid to a hash-locked output (licash_onchain's
/// `Htlc`) under the wallet's hash, which the provider claims with the
/// preimage and its key, and its payer takes back with the wallet's refund
/// key after the timeout. Once the coin is `depth` deep, the wallet tells
/// the provider of it, and the provider locks the amount to the wallet at
/// the hub under that hash: the wallet's claim of that lock shows the
/// provider the preimage it claims the coin with. Unclaimed, its lock is
/// refunded and the payer takes the coin back once timed out. Nothing is
/// taken on trust, but the provider links the deposits of one wallet, paid
/// to one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposits {
    /// Its fee on the amount, which the coin pays on top.
    pub fee: Fee,
    /// What the coin pays on top for the miners of the provider's claim.
    pub miner: u64,
    /// The least and the most locked to the wallet, in satoshis.
    pub min: u64,
    pub max: u64,
    /// Confirmations the coin needs before the provider locks.
    pub depth: u32,
    /// Blocks from the request within which the coin must confirm.
    pub window: u32,
    /// Blocks from the request to the coin's timeout, at most.
    pub timeout: u32,
}

impl Deposits {
    /// What the coin of a deposit locking `amount` pays: the amount, the
    /// provider's fee and its claim's miners.
    pub fn pays(&self, amount: u64) -> u64 {
        amount
            .saturating_add(self.fee.due(amount))
            .saturating_add(self.miner)
    }
}

/// Ask a provider for a deposit on Bitcoin, whose coin it pays on as a lock
/// of `amount` to `address` at hub `hub`, under `hash`, the wallet's. The
/// coin's payer takes it back with `refund`, an x-only key, after its
/// timeout. Answered with [`crate::Depositing`]: pay exactly its amount to
/// its address, under the provider's key `claim`, by `fund_by`. The same
/// request again answers the same terms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositRequest {
    pub hub: Address,
    pub address: Address,
    pub amount: u64,
    pub hash: Hex,
    pub refund: Hex,
}

impl DepositRequest {
    pub fn hash(&self) -> Result<[u8; 32], Problem> {
        self.hash.array("hash")
    }

    pub fn refund(&self) -> Result<[u8; 32], Problem> {
        self.refund.array("refund")
    }
}

/// What a provider pays over Lightning: invoices it pays from its own node,
/// for clients' locks at any of its hubs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lightning {
    /// Its node's public key, in hex: it pays no invoice of its own.
    pub node: String,
    /// Its fee on an invoice's amount, in whole satoshis rounded up,
    /// routing fees included, which the client's lock pays on top.
    pub fee: Fee,
    /// The most an invoice it pays may ask, in satoshis.
    pub max: u64,
    /// The client's lock expires at least this many blocks plus the
    /// invoice's final CLTV delta, and 3, above the tip: its routes'
    /// timelock ends this many blocks before the lock expires. The
    /// provider claims the lock with the preimage before it expires, which
    /// may reach it only on Bitcoin, once a route's last HTLC times out:
    /// these blocks are its time to, its node's and the hub's downtime
    /// included, as a routing node's CLTV delta.
    pub slack: u32,
}

impl Lightning {
    /// What a lock pays to have an invoice of `msat` paid: its amount in
    /// whole satoshis and the provider's fee.
    pub fn pays(&self, msat: u64) -> u64 {
        let sat = msat.div_ceil(1000);
        sat.saturating_add(self.fee.due(sat))
    }
}

/// Swap the client's `lock` at hub `from`, which pays the provider, for a
/// lock of `amount` to `address` at hub `to` under the same hash. The same
/// request again answers where the swap stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub from: Address,
    pub lock: Hex,
    pub to: Address,
    pub address: Address,
    pub amount: u64,
}

impl Request {
    pub fn new(
        from: &Address,
        lock: &ProposalId,
        to: &Address,
        address: &Address,
        amount: u64,
    ) -> Self {
        Self {
            from: *from,
            lock: Hex(lock.as_bytes().to_vec()),
            to: *to,
            address: *address,
            amount,
        }
    }

    pub fn lock(&self) -> Result<ProposalId, Problem> {
        Ok(ProposalId::from_bytes(self.lock.array("lock")?))
    }
}

/// Where a swap stands, by the client's lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Swap {
    /// The client's lock at `from`.
    pub id: Hex,
    pub state: State,
    pub amount: u64,
    /// The provider's lock at `to`, once made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<Hex>,
    /// Its expiry.
    pub expiry: u32,
    /// Why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Swap {
    /// The provider's lock, decoded.
    pub fn lock(&self) -> Result<Option<ProposalId>, Problem> {
        self.lock
            .as_ref()
            .map(|l| Ok(ProposalId::from_bytes(l.array("lock")?)))
            .transpose()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Taken: the provider is locking at `to`.
    Accepted,
    /// The provider's lock is certified: the client claims it.
    Locked,
    /// The client claimed it: the provider claims the client's lock.
    Paid,
    /// Both locks paid.
    Done,
    /// The client never claimed: the provider's lock is refunded, and the
    /// client's will be once expired.
    Refunded,
    /// The provider did not lock: the client's lock is refunded once
    /// expired.
    Failed,
    /// A state of a later version of the protocol: read as the swap under
    /// way, nothing of it final.
    #[serde(other)]
    Unknown,
}

/// Pay the client's `lock` at hub `from`, which pays the provider, out on
/// Bitcoin: lock a coin worth `value` under the lock's hash, claimed with
/// the client's key `claim`, x-only. The same request again answers where
/// the payout stands. For a claim paying a silent payment address, `scan`,
/// its scan key blinded (33 bytes), which the provider answers its
/// [`Share`] of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainRequest {
    pub from: Address,
    pub lock: Hex,
    pub claim: Hex,
    pub value: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<Hex>,
}

/// The provider's share of a client's blinded scan key `B'`: `x_r B'`,
/// `x_r` the secret of its refund key (that of even y), with a proof of it,
/// `(e, s)` (see `licash_onchain::silent_claim::Share`), each 32 bytes but
/// the point's 33.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    pub point: Hex,
    pub e: Hex,
    pub s: Hex,
}

impl ChainRequest {
    pub fn new(from: &Address, lock: &ProposalId, claim: [u8; 32], value: u64) -> Self {
        Self {
            from: *from,
            lock: Hex(lock.as_bytes().to_vec()),
            claim: Hex(claim.to_vec()),
            value,
            scan: None,
        }
    }

    /// Asking the provider's share of `scan`, a blinded scan key.
    pub fn with_scan(mut self, scan: [u8; 33]) -> Self {
        self.scan = Some(Hex(scan.to_vec()));
        self
    }

    pub fn scan(&self) -> Result<Option<[u8; 33]>, Problem> {
        self.scan.as_ref().map(|s| s.array("scan")).transpose()
    }

    pub fn lock(&self) -> Result<ProposalId, Problem> {
        Ok(ProposalId::from_bytes(self.lock.array("lock")?))
    }

    pub fn claim(&self) -> Result<[u8; 32], Problem> {
        self.claim.array("claim")
    }
}

/// Where a payout stands, by the client's lock: `Accepted` while its coin
/// is not confirmed, `Locked` once it is, `Paid` once the client claimed
/// it, `Done` once the provider claimed the client's lock, `Refunded` once
/// the provider took the coin back, `Failed` if it never locked one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSwap {
    /// The client's lock at `from`.
    pub id: Hex,
    pub state: State,
    pub value: u64,
    /// The provider's key, x-only, that takes the coin back after block
    /// `timeout`.
    pub refund: Hex,
    /// A block height, before the client's lock expires: never a time.
    pub timeout: u32,
    /// The coin, once confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding: Option<Funding>,
    /// The coin's transaction once broadcast, confirmed or not: for the
    /// client to show it before `funding` says where it is. Providers
    /// before it say nothing of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// Why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Its share of the request's `scan`, if it asked one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<Share>,
}

impl ChainSwap {
    /// The provider's refund key, decoded.
    pub fn refund(&self) -> Result<[u8; 32], Problem> {
        self.refund.array("refund")
    }
}

/// Pay `request`, a BOLT11 invoice, for the client's `lock` at hub `from`,
/// which pays the provider the invoice's amount and its fee on the preimage
/// of the invoice's hash. The same request again answers where the payment
/// stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningRequest {
    pub from: Address,
    pub lock: Hex,
    pub request: String,
}

impl LightningRequest {
    pub fn new(from: &Address, lock: &ProposalId, request: &str) -> Self {
        Self {
            from: *from,
            lock: Hex(lock.as_bytes().to_vec()),
            request: request.to_owned(),
        }
    }

    pub fn lock(&self) -> Result<ProposalId, Problem> {
        Ok(ProposalId::from_bytes(self.lock.array("lock")?))
    }
}

/// Where an invoice payment stands, by the client's lock: `Accepted` while
/// the provider pays it, `Paid` once paid, `Done` once the provider claimed
/// the client's lock, `Failed` if it was not paid: the client's lock is
/// refunded once expired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningSwap {
    /// The client's lock at `from`.
    pub id: Hex,
    pub state: State,
    /// The invoice's amount, in satoshis rounded up.
    pub amount: u64,
    /// The preimage the payment bought, once paid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<Hex>,
    /// Why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LightningSwap {
    /// The preimage, decoded.
    pub fn preimage(&self) -> Result<Option<[u8; 32]>, Problem> {
        self.preimage
            .as_ref()
            .map(|p| p.array("preimage"))
            .transpose()
    }
}
