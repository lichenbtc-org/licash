//! A Licash bridge's management API: a wallet of its own that pays and
//! takes Lightning payments for Nostr Wallet Connect clients, out of
//! accounts it keeps for their owners, custodially.
//!
//! An account is a key: each request but [`INFO`] is a [`Signed`] body
//! by it, POSTed. A wallet derives the key from its seed for each bridge,
//! so that one wallet's accounts at two bridges are not linked by it.
//! Amounts are in millisatoshis, as NIP-47 has them; Licash notes are
//! whole satoshis.

use serde::{Deserialize, Serialize};

use crate::{Code, Fee, Hex, Problem};

/// GET: the bridge's [`Info`].
pub const INFO: &str = "/v1/bridge/info";
/// [`Register`]: an account for the signing key. Answers [`Account`].
pub const REGISTER: &str = "/v1/bridge/register";
/// [`Empty`]: the signing key's [`Account`].
pub const ACCOUNT: &str = "/v1/bridge/account";
/// [`Connect`]: a new NWC connection, [`Connected`].
pub const CONNECT: &str = "/v1/bridge/connect";
/// [`Revoke`]: a connection revoked, answering its [`Connection`].
pub const REVOKE: &str = "/v1/bridge/revoke";
/// [`TopUp`]: an invoice crediting the account once paid, [`Invoice`].
pub const TOP_UP: &str = "/v1/bridge/top-up";
/// [`Withdraw`]: an invoice paid out of the account, [`Payment`].
pub const WITHDRAW: &str = "/v1/bridge/withdraw";
/// [`Username`]: the account named, [`Account`].
pub const USERNAME: &str = "/v1/bridge/username";
/// [`Empty`]: the bridge frozen for good, paying nothing out, and its
/// notes sealed to the signing key, its owner's, for its wallet to claim
/// in a recovery should its hub stop cooperating: [`Exported`]. Of a
/// bridge for its owner alone.
pub const EXPORT: &str = "/v1/bridge/export";

/// How far a [`Signed`] request's time may be from the bridge's, in
/// seconds, either way.
pub const MAX_SKEW: i64 = 300;

/// What a bridge is, and on what terms it keeps accounts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The Bitcoin network its hub is on.
    pub network: String,
    /// The hub its wallet pays and is paid through.
    pub hub: String,
    /// The Nostr key its NWC service answers as, in hex.
    pub nostr: String,
    /// The relays its NWC service listens on.
    pub relays: Vec<String>,
    /// Whether anyone may register an account, or only its owner, paired
    /// once.
    pub open: bool,
    /// The most an account may hold, if bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_balance: Option<u64>,
    /// The most one payment may be, if bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payment: Option<u64>,
    /// Its hub's fee on receiving, which a payment to an account pays
    /// out of its amount, in satoshis.
    pub receive_fee: Fee,
    /// The domain of its Lightning Addresses, if it serves them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lightning_address: Option<String>,
}

/// A request body, `request` as JSON, signed by `key` at `at` for the
/// path it is POSTed to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    /// An x-only public key.
    pub key: Hex,
    /// Unix seconds.
    pub at: i64,
    pub request: String,
    /// BIP340, over [`Signed::digest`].
    pub signature: Hex,
}

impl Signed {
    /// `request`, JSON, signed with `secret` for `path` at `at`.
    pub fn sign(secret: &[u8; 32], path: &str, at: i64, request: String) -> Result<Self, Problem> {
        let scalar = licash::crypto::ScalarBytes(*secret)
            .to_scalar()
            .map_err(|_| Problem::invalid("not a secret key"))?;
        let digest = Self::digest(path, at, &request);
        let signature = licash::crypto::schnorr_sign(&scalar, &digest)
            .map_err(|_| Problem::invalid("not a secret key"))?;
        Ok(Self {
            key: Hex(licash::crypto::x_only_pub(&scalar).to_vec()),
            at,
            request,
            signature: Hex(signature.0.to_vec()),
        })
    }

    /// What is signed: the path, the time and the request, tagged.
    pub fn digest(path: &str, at: i64, request: &str) -> [u8; 32] {
        licash::crypto::tagged_hash(
            "licash/bridge/request",
            &[path.as_bytes(), &[0], &at.to_be_bytes(), request.as_bytes()],
        )
    }

    /// The key that signed it for `path`, within [`MAX_SKEW`] of `now`.
    pub fn verify(&self, path: &str, now: i64) -> Result<[u8; 32], Problem> {
        if (self.at - now).abs() > MAX_SKEW {
            return Err(Problem::invalid(
                "a request signed too long ago, or ahead: check the clock",
            ));
        }
        let key: [u8; 32] = self.key.array("key")?;
        let signature = licash::crypto::Signature(self.signature.array("signature")?);
        let digest = Self::digest(path, self.at, &self.request);
        licash::crypto::schnorr_verify(&key, &digest, &signature)
            .map_err(|_| Problem::invalid("a request not signed by its key"))?;
        Ok(key)
    }
}

/// A request of nothing but its signer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

/// Register the signing key's account. At a bridge not [`Info::open`],
/// only with the pairing code its operator was given, once.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing: Option<String>,
}

/// What a connection may do: pay invoices, or ask for them. A connection
/// that only receives is what Stacker News and the like take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Pay,
    Receive,
}

/// How often a [`Budget`] starts again, from the connection's making.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Period {
    Daily,
    Weekly,
    Monthly,
    Yearly,
    Never,
}

impl Period {
    /// Its length in seconds, if it renews: a month of 30 days, a year
    /// of 365.
    pub fn seconds(self) -> Option<i64> {
        const DAY: i64 = 86_400;
        match self {
            Self::Daily => Some(DAY),
            Self::Weekly => Some(7 * DAY),
            Self::Monthly => Some(30 * DAY),
            Self::Yearly => Some(365 * DAY),
            Self::Never => None,
        }
    }
}

/// The most a connection pays in each period, fees included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    pub amount: u64,
    pub period: Period,
}

/// Make an NWC connection, of a fresh key the bridge draws.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connect {
    /// What the owner calls it: the app it is for.
    pub name: String,
    pub permissions: Vec<Permission>,
    /// The most one payment may be, fees included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payment: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    /// Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// An NWC connection, and where its budget stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// Its client's Nostr key, in hex.
    pub key: String,
    pub name: String,
    pub permissions: Vec<Permission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payment: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    /// Paid in its budget's current period, fees and payments under way
    /// included.
    pub spent: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub created_at: i64,
}

/// A connection made: `uri`, `nostr+walletconnect://`, carries its secret,
/// which the bridge keeps no copy of. Shown once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connected {
    pub connection: Connection,
    pub uri: String,
}

/// Revoke the connection of `key`, for good.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoke {
    pub key: String,
}

/// An account: its balance, connections and latest payments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub balance: u64,
    /// Held for payments under way, out of the balance.
    pub reserved: u64,
    pub connections: Vec<Connection>,
    /// Newest first, at most 50.
    pub activity: Vec<Activity>,
    /// Its Lightning Address, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lightning_address: Option<String>,
}

/// Where a payment or an invoice stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Settled,
    Failed,
    Expired,
}

/// Which way a payment went.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Incoming,
    Outgoing,
}

/// A payment out of an account, or an invoice paying into it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Activity {
    pub direction: Direction,
    pub state: State,
    /// The payment hash, in hex.
    pub hash: String,
    pub invoice: String,
    /// What the invoice asks.
    pub amount: u64,
    /// Outgoing: what was paid on top. Incoming: what the hub kept of it.
    pub fee: u64,
    /// The connection it was over, if any: a top-up or withdrawal is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<i64>,
}

/// An invoice paying `amount` into the signing key's account, less its
/// hub's receive fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopUp {
    pub amount: u64,
}

/// An invoice to pay into an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invoice {
    pub invoice: String,
    pub hash: String,
    pub amount: u64,
    /// What the account is credited once it is paid.
    pub credits: u64,
    pub expires_at: i64,
}

/// Pay `invoice` out of the signing key's account, for at most `max_fee`
/// on top if given.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdraw {
    pub invoice: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee: Option<u64>,
}

/// The notes of a frozen bridge, sealed to a wallet's key there
/// ([`EXPORT`]): what they are worth, in sat; and the locks of its
/// payments under way whose refunds it seals with them, and what those
/// are worth, none from a bridge sealing no lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exported {
    pub export: Hex,
    pub notes: u64,
    pub amount: u64,
    #[serde(default)]
    pub locks: u64,
    #[serde(default)]
    pub locked: u64,
}

/// A payment out of an account, as it stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payment {
    pub state: State,
    pub hash: String,
    pub amount: u64,
    pub fee: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

/// Name the account's Lightning Address `username`, at a bridge serving
/// them ([`Info::lightning_address`]), or none. Of `a-z`, `0-9`, `-`, `_`
/// and `.`, at most 64.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Username {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// A refusal for an account's reasons: not registered, not its
/// connection, short of its balance or outside the bridge's limits.
pub fn declined(message: impl Into<String>) -> Problem {
    Problem::new(Code::Declined, message)
}
