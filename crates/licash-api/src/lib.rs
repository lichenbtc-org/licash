//! The Licash hub API, version 1: JSON bodies that carry the protocol's
//! canonical bytes as hex, the paths they go to and the problems a hub
//! answers with. The transport is the application's: HTTP over TCP or Tor.
//!
//! | Path        | Body       | Answer      |
//! |-------------|------------|-------------|
//! | `GET /v1/info`     |     | [`Info`]     |
//! | `POST /v1/offer`   | [`Offer`]   | [`Offered`]  |
//! | `POST /v1/release` | [`Release`] | [`Released`] |
//! | `POST /v1/unlink`  | [`Unlink`]  | [`Unlinked`] |
//! | `POST /v1/inquire` | [`Inquire`] | [`Evidenced`] |
//! | `POST /v1/lock`    | [`Lock`]    | [`Locked`]   |
//! | `GET /v1/lock/{id}` |            | [`LockState`] |
//! | `POST /v1/settle`  | [`Settle`]  | [`Issued`]   |
//! | `POST /v1/refund`  | [`Refund`]  | [`Issued`]   |
//! | `POST /v1/ln/pay`  | [`Pay`]     | [`Paying`]   |
//! | `POST /v1/ln/receive` | [`Receive`] | [`Receiving`] |
//! | `GET /v1/ln/receive/{hash}` |    | [`ReceiveStatus`] |
//!
//! The Lightning paths are served by hubs that advertise
//! [`Info::lightning`].
//!
//! Anything else is a [`Problem`], with the HTTP status of its [`Code`].
//!
//! A payer hands its payee a [`Payment`], by whatever channel they share:
//! the hub's [`inbox`] if it keeps payments for their payees.
//!
//! Swap providers serve the API of [`swaps`].

pub mod bridge;
pub mod inbox;
pub mod swaps;

use licash::{
    address::Address,
    authorization::{Authorization, Grant, SignedProposal, Unlock},
    chain::Checkpoint,
    crypto::{schnorr_verify, tagged_hash, Point, Signature},
    note::{Keyset, Message, MintResponse, Note},
    recovery::Evidence,
    source::Certificate,
    spend::{lock_hash, ChainProfile, Output, Proposal, ProposalId},
    unlink::{Answer, Request},
};
use serde::{Deserialize, Serialize};

pub const INFO: &str = "/v1/info";
pub const OFFER: &str = "/v1/offer";
pub const RELEASE: &str = "/v1/release";
pub const UNLINK: &str = "/v1/unlink";
/// What the hub holds against notes a holder names ([`Inquire`]).
pub const INQUIRE: &str = "/v1/inquire";
pub const LOCK: &str = "/v1/lock";
/// A lock's state, at [`lock_state`] for a lock's identifier.
pub const LOCK_STATE: &str = "/v1/lock/{id}";
pub const SETTLE: &str = "/v1/settle";
pub const REFUND: &str = "/v1/refund";
pub const LN_PAY: &str = "/v1/ln/pay";
pub const LN_RECEIVE: &str = "/v1/ln/receive";
/// The path of [`ln_receive_state`], as a route.
pub const LN_RECEIVE_STATE: &str = "/v1/ln/receive/{hash}";
pub const DEPOSIT: &str = "/v1/deposit";
/// The path of [`deposit_state`], as a route.
pub const DEPOSIT_STATE: &str = "/v1/deposit/{refund}";
/// Ask the hub to lock its notes to the deposit of the refund key `refund`
/// that returns a contract's reserve ([`CloseTerms`]), as a route: POST,
/// answered with its [`DepositStatus`].
pub const DEPOSIT_LOCK: &str = "/v1/deposit/{refund}/lock";
/// The [`BlockTweaks`] of the blocks a [`TweaksQuery`] names, as a list,
/// up to the newest the hub indexed.
pub const TWEAKS: &str = "/v1/chain/tweaks";
/// Most blocks a [`TweaksQuery`] names.
pub const MAX_TWEAK_BLOCKS: u32 = 144;

/// Where the deposit whose refund key, x-only, is `refund` stands: a hub
/// takes one deposit under a refund key, which a wallet derives from its
/// seed before it knows the deposit's hash.
pub fn deposit_state(refund: &[u8; 32]) -> String {
    format!("{DEPOSIT}/{}", hex::encode(refund))
}

/// Where to ask for the lock of the deposit of the refund key `refund`
/// that returns a contract's reserve.
pub fn deposit_lock(refund: &[u8; 32]) -> String {
    format!("{DEPOSIT}/{}/lock", hex::encode(refund))
}

/// Where a receipt over Lightning of `hash` stands.
pub fn ln_receive_state(hash: &[u8; 32]) -> String {
    format!("{LN_RECEIVE}/{}", hex::encode(hash))
}

/// A hash as [`ln_receive_state`] writes it.
pub fn hash_of(text: &str) -> Result<[u8; 32], Problem> {
    let bytes = hex::decode(text).map_err(|e| Problem::invalid(format!("hash: {e}")))?;
    Hex(bytes).array("hash")
}

/// The path of lock `id`'s state.
pub fn lock_state(id: &ProposalId) -> String {
    format!("{LOCK}/{}", hex::encode(id.as_bytes()))
}

/// The identifier of a lock as [`lock_state`] writes it.
pub fn lock_id(text: &str) -> Result<ProposalId, Problem> {
    let bytes = hex::decode(text).map_err(|e| Problem::invalid(format!("lock: {e}")))?;
    Ok(ProposalId::from_bytes(Hex(bytes).array("lock")?))
}

/// Bytes, as hex in JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct Hex(pub Vec<u8>);

impl std::fmt::Debug for Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hex({} bytes)", self.0.len())
    }
}

impl Serialize for Hex {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(text)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl Hex {
    fn array<const N: usize>(&self, what: &str) -> Result<[u8; N], Problem> {
        self.0
            .as_slice()
            .try_into()
            .map_err(|_| Problem::invalid(format!("{what} must be {N} bytes")))
    }
}

/// A fee: `base` plus `ppm` parts per million of the amount moved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fee {
    pub base: u64,
    pub ppm: u64,
}

impl Fee {
    /// The fee on moving `amount`, rounded up, saturating.
    pub fn due(&self, amount: u64) -> u64 {
        let rate = (u128::from(amount) * u128::from(self.ppm)).div_ceil(1_000_000);
        u64::try_from(rate).map_or(u64::MAX, |rate| rate.saturating_add(self.base))
    }

    /// The most an amount moved may be for it and its fee to come to at
    /// most `total`: none if not even nothing does.
    pub fn most_within(&self, total: u64) -> Option<u64> {
        let with_fee = |amount: u64| amount.checked_add(self.due(amount));
        // It and its fee only grow with it: the last at most `total`,
        // found halving.
        with_fee(0).filter(|paid| *paid <= total)?;
        let (mut low, mut high) = (0, total);
        while low < high {
            let mid = low + (high - low).div_ceil(2);
            match with_fee(mid) {
                Some(paid) if paid <= total => low = mid,
                _ => high = mid - 1,
            }
        }
        Some(low)
    }
}

/// What a hub charges, in outputs to [`Info::address`]: a spend's fee in
/// its outputs, a lock's in each branch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Fees {
    pub spend: Fee,
    /// In a lock's pay branch.
    pub lock: Fee,
    /// In a lock's refund branch.
    pub refund: Fee,
    /// Charged besides, in thousandths of a sat, for each note a spend or
    /// a branch of a lock makes for others than the hub ([`NoteFee`]).
    /// None from a hub that predates it.
    #[serde(skip_serializing_if = "is_zero")]
    pub output_msat: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Fees {
    /// What a spend owes.
    pub fn spending(&self) -> NoteFee {
        self.with_outputs(self.spend)
    }

    /// What a lock's pay branch owes.
    pub fn locking(&self) -> NoteFee {
        self.with_outputs(self.lock)
    }

    /// What a lock's refund branch owes.
    pub fn refunding(&self) -> NoteFee {
        self.with_outputs(self.refund)
    }

    /// Whether any of these fees is more than its like in `other`: a hub
    /// charging them asks more, of some payment, than one charging
    /// `other`.
    pub fn above(&self, other: &Fees) -> bool {
        self.parts().iter().zip(other.parts()).any(|(a, b)| *a > b)
    }

    /// The lesser of each fee of the two.
    pub fn least(&self, other: &Fees) -> Fees {
        self.each(other, u64::min)
    }

    /// The greater of each fee of the two.
    pub fn most(&self, other: &Fees) -> Fees {
        self.each(other, u64::max)
    }

    fn parts(&self) -> [u64; 7] {
        let (s, l, r) = (self.spend, self.lock, self.refund);
        [
            s.base,
            s.ppm,
            l.base,
            l.ppm,
            r.base,
            r.ppm,
            self.output_msat,
        ]
    }

    fn each(&self, other: &Fees, pick: fn(u64, u64) -> u64) -> Fees {
        let (a, b) = (self.parts(), other.parts());
        let p: [u64; 7] = std::array::from_fn(|i| pick(a[i], b[i]));
        let fee = |base, ppm| Fee { base, ppm };
        Fees {
            spend: fee(p[0], p[1]),
            lock: fee(p[2], p[3]),
            refund: fee(p[4], p[5]),
            output_msat: p[6],
        }
    }

    fn with_outputs(&self, fee: Fee) -> NoteFee {
        NoteFee {
            fee,
            output_msat: self.output_msat,
        }
    }
}

/// What a spend, or one branch of a lock, owes its hub: `fee` on the value
/// of the notes it spends, and `output_msat` thousandths of a sat for each
/// note it makes for others than the hub. The hub's own notes, which pay
/// it, are not charged for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoteFee {
    pub fee: Fee,
    pub output_msat: u64,
}

impl NoteFee {
    /// The fee on spending notes worth `value` for `outputs` notes made
    /// for others than the hub: the part on the notes made rounded to the
    /// nearest sat, saturating.
    pub fn due(&self, value: u64, outputs: usize) -> u64 {
        let made = (u128::from(self.output_msat) * outputs as u128 + 500) / 1000;
        u64::try_from(made).map_or(u64::MAX, |made| self.fee.due(value).saturating_add(made))
    }

    /// The most a spend of notes worth `value` owes, however it parts them
    /// between a payee and change, each in the fewest notes of any power
    /// of two: what an estimate made before the notes are known counts,
    /// not to fall short. A keyset with no note that large makes more.
    pub fn at_most(&self, value: u64) -> u64 {
        let bits = (u64::BITS - value.leading_zeros()) as usize;
        self.due(value, 2 * bits)
    }
}

/// The locks a hub admits, as of its scan of Bitcoin, in blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locks {
    /// The checkpoint new locks name.
    pub checkpoint: Hex,
    /// The height the hub scanned to.
    pub height: u32,
    /// A lock's expiry, depth and `reaction` fit within `window` of the
    /// height the hub admits it at.
    pub window: u32,
    pub reaction: u32,
    /// Least activation depth.
    pub min_depth: u32,
    /// A lock is decided within this many blocks of its checkpoint.
    pub max_headers: u32,
}

impl Locks {
    pub fn checkpoint(&self) -> Result<Checkpoint, Problem> {
        Ok(Checkpoint::from_bytes(&self.checkpoint.0)?)
    }

    /// The latest expiry the hub admits now for a lock of `depth`: decided
    /// within its response window and its checkpoint's header budget.
    pub fn latest_expiry(&self, depth: u32) -> Result<u32, Problem> {
        let slack = depth.saturating_add(self.reaction);
        let window = self.height.saturating_add(self.window);
        let budget = self.checkpoint()?.height().saturating_add(self.max_headers);
        Ok(window.min(budget).saturating_sub(slack))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Info {
    pub keysets: Vec<Hex>,
    pub address: Address,
    pub fees: Fees,
    /// None while the hub follows no chain.
    #[serde(default)]
    pub locks: Option<Locks>,
    /// None unless the hub runs a Lightning gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lightning: Option<Lightning>,
    /// None unless the hub takes deposits on Bitcoin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposits: Option<Deposits>,
    /// The key the hub announces itself under on Nostr, x-only in hex: an
    /// announcement of its URL by another key is not the hub's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr: Option<String>,
    /// The first block whose silent payment tweaks the hub serves, at
    /// [`TWEAKS`], if it serves any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tweaks: Option<u32>,
    /// Nostr relays its wallets' mailboxes are on: where payers send the
    /// payments of notes at this hub (NIP-17).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<String>,
    /// None unless the hub opens recovery contracts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contracts: Option<Contracts>,
    /// The URLs the hub says it is reached at, such as its onion
    /// service's beside its clearnet one. Not part of its
    /// [`Info::identity`]: a wallet takes them only from a hub it trusts,
    /// as other ways to it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// That the hub of [`Info::address`] says the rest of its
    /// [`Info::identity`] is its own: a BIP340 signature by its spend key.
    /// None from hubs following no chain: a wallet keeps what a hub says
    /// only with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Hex>,
    /// What the hub takes beyond this version of the protocol, by name,
    /// such as a later way of paying for contracts: a wallet uses one only
    /// if it names it. Not part of its [`Info::identity`]. Empty from
    /// older hubs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

impl Info {
    pub fn new(keysets: &[Keyset], address: Address, fees: Fees, locks: Option<Locks>) -> Self {
        Self {
            keysets: keysets.iter().map(|k| Hex(k.to_bytes())).collect(),
            address,
            fees,
            locks,
            lightning: None,
            deposits: None,
            nostr: None,
            tweaks: None,
            relays: Vec::new(),
            contracts: None,
            urls: Vec::new(),
            proof: None,
            features: Vec::new(),
        }
    }

    /// What [`Info::proof`] signs: on `network`, the hub's address, the
    /// key it announces itself under on Nostr and its keysets, in order. A
    /// payer knowing a hub by its address only tells by it the hub's
    /// keysets from those another server says under the same address.
    ///
    /// It authenticates which keysets are the hub's, not that the hub
    /// holds their keys or uses no other: that each note is issued under
    /// its denomination's key is proved by each grant and issuance itself
    /// (their seal and DLEQ proofs), which wallets verify before they sign
    /// or keep anything.
    pub fn identity(&self, network: ChainProfile) -> Result<[u8; 32], Problem> {
        let (named, nostr) = match &self.nostr {
            Some(key) => {
                let bytes =
                    hex::decode(key).map_err(|e| Problem::invalid(format!("nostr: {e}")))?;
                ([1u8], Hex(bytes).array::<32>("nostr")?)
            }
            None => ([0], [0; 32]),
        };
        let keysets = self.keysets()?;
        let count = u32::try_from(keysets.len())
            .map_err(|_| Problem::invalid("too many keysets"))?
            .to_be_bytes();
        let (tag, address) = ([network.tag()], self.address.to_bytes());
        let mut parts: Vec<&[u8]> = vec![&tag, &address, &named, &nostr, &count];
        parts.extend(keysets.iter().map(|k| k.id().as_slice()));
        Ok(tagged_hash("licash/hub/identity/v1", &parts))
    }

    /// Whether [`Info::proof`] proves the hub's [`Info::identity`] on
    /// `network`: false if it has none, an error if it has one that does
    /// not.
    pub fn proved(&self, network: ChainProfile) -> Result<bool, Problem> {
        let Some(proof) = &self.proof else {
            return Ok(false);
        };
        let signature = Signature(proof.array::<64>("proof")?);
        let key = self.address.spend().x_only();
        schnorr_verify(&key, &self.identity(network)?, &signature).map_err(|_| {
            Problem::invalid("the proof is not the hub's: it does not sign its identity")
        })?;
        Ok(true)
    }

    pub fn keysets(&self) -> Result<Vec<Keyset>, Problem> {
        self.keysets
            .iter()
            .map(|k| Keyset::from_bytes(&k.0).map_err(Problem::from))
            .collect()
    }
}

/// The blocks of [`TWEAKS`]: `count` from height `from`, at most
/// [`MAX_TWEAK_BLOCKS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TweaksQuery {
    pub from: u32,
    pub count: u32,
}

/// A block's silent payment tweaks (BIP352): one for each of its
/// transactions that may pay a silent payment, in the block's order. A
/// light wallet derives from each the output that would pay it, and looks
/// for it in the block's compact filter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTweaks {
    pub height: u32,
    /// The block's hash, as Bitcoin shows it.
    pub hash: String,
    /// Each a compressed point.
    pub tweaks: Vec<Hex>,
}

/// Ask for a grant on `proposal`, spending `notes`: signed by each note's
/// hold key, in their order, if `holds`, the owner's offer, which a hub
/// counts apart from those of anyone else knowing the notes
/// ([`licash::offer`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offer {
    pub proposal: Hex,
    pub notes: Vec<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holds: Option<Vec<Hex>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offered {
    pub grant: Hex,
}

/// Ask for the unlock of the grant that `signed` authorizes. `keyset` is
/// the one its proposal names.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Release {
    pub keyset: Hex,
    pub signed: Hex,
    pub notes: Vec<Hex>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Released {
    pub unlock: Hex,
}

/// A released spend and its unlock, as its payer hands it to a payee at
/// the hub `hub`: the payee opens the outputs to its address. Only an
/// output's owner can open it, so a payment is safe to send in the clear.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payment {
    pub hub: String,
    #[serde(flatten)]
    pub release: Release,
    pub unlock: Hex,
    /// A note for the payee, sealed under the receipt secret
    /// ([`inbox::Keep::note`]): one of any other size says nothing, and the
    /// payment stands without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<Hex>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Unlink {
    pub request: Hex,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Unlinked {
    pub answer: Hex,
}

/// Ask what the hub holds against notes of one keyset, at most
/// [`licash::inquiry::MAX_NOTES`]: each named by its public fields and
/// asked about under its hold key's signature, so that only a holder who
/// can sign for a note learns anything of it ([`licash::inquiry`]). The hub
/// learns that one party holds them all.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inquire {
    pub keyset: Hex,
    /// When it was signed, in unix seconds.
    pub at: u64,
    pub notes: Vec<Inquired>,
}

/// A note an [`Inquire`] asks about, and its hold key's signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inquired {
    pub note: Hex,
    pub signature: Hex,
}

/// What the hub holds against each note asked about, in the order asked: its
/// evidence, as [`licash::recovery::evidence_to_bytes`] writes it, none for a
/// note nothing is held against. The asker verifies it
/// ([`licash::recovery::voids_note`]) and takes no word of the hub's.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidenced {
    pub evidence: Vec<Hex>,
}

/// Lock `notes` as `signed`, a plainly authorized timed spend, makes them.
/// `keyset` is the one its proposal names.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lock {
    pub keyset: Hex,
    pub signed: Hex,
    pub notes: Vec<Hex>,
}

/// The hub's certificate of a lock: its acknowledgment of the debt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Locked {
    pub certificate: Hex,
}

/// A lock as its hub holds it. The preimage is known once the lock was
/// paid or activated on Bitcoin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockState {
    pub proposal: Hex,
    pub certificate: Hex,
    pub settled: Option<Settled>,
    pub preimage: Option<Hex>,
    /// Its payer's owner signatures, which with its certificate prove it on
    /// Bitcoin to its payee, the hub's own for a lock of its own notes:
    /// none from a hub older than them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<Hex>,
    /// The checkpoint its terms name, which anchors its proof on Bitcoin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Hex>,
}

/// The branch of a lock its hub issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Settled {
    Pay,
    Refund,
}

/// A [`LockState`], decoded and checked.
#[derive(Clone, Debug)]
pub struct LockView {
    pub proposal: Proposal,
    pub certificate: Certificate,
    pub settled: Option<Settled>,
    pub preimage: Option<[u8; 32]>,
    /// Its payer's owner signatures, checked against its certificate, if
    /// its hub gave them ([`LockState::signatures`]).
    pub signatures: Option<Vec<Signature>>,
    /// The checkpoint its terms name, checked to be that one, if its hub
    /// gave it ([`LockState::checkpoint`]).
    pub checkpoint: Option<Checkpoint>,
}

/// Issue the pay branch of `lock` for `preimage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settle {
    pub lock: Hex,
    pub preimage: Hex,
}

/// Issue the refund branch of `lock`, once it expired unactivated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Refund {
    pub lock: Hex,
}

/// The issuances of a branch, in output order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Issued {
    pub issuances: Vec<Hex>,
}

/// Why a hub did not serve a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    /// The request does not decode or verify.
    Invalid,
    UnknownKeyset,
    UnknownOffer,
    NotIssued,
    UnknownLock,
    /// A timed spend, served at [`LOCK`] only.
    Timed,
    /// An input is already spent.
    Spent,
    /// An output is already issued.
    Reissued,
    /// The fee paid to the hub is below its fees ([`Info::fees`]).
    Fee,
    /// Already unlinked under another request.
    Unlinked,
    /// Unlinking closed by a hub restart: swap the note instead.
    Expired,
    /// Not a plainly authorized timed spend.
    NotALock,
    /// The lock names a checkpoint the hub does not follow.
    Checkpoint,
    /// The lock's expiry or depth is outside [`Info::locks`].
    Timing,
    /// Not the preimage of the lock's hash.
    Preimage,
    /// The lock was settled the other way.
    Settled,
    /// The lock expired before it was paid: it is refunded.
    LockExpired,
    /// The lock has not expired at depth: retry later.
    Unexpired,
    /// The lock was activated on Bitcoin in time: it pays.
    Activated,
    /// The hub cannot serve now, or is behind the chain; retry later.
    Unavailable,
    /// The hub does not make this payment outside its ledger for the lock.
    Forward,
    /// A swap provider takes no such swap: outside its limits, its hubs or
    /// what it holds.
    Declined,
    /// A code of a later version of the protocol: a refusal, read by its
    /// message alone.
    #[serde(other)]
    Unknown,
}

impl Code {
    /// The HTTP status a hub answers with.
    pub fn status(self) -> u16 {
        match self {
            Self::Invalid => 400,
            Self::UnknownKeyset | Self::UnknownOffer | Self::NotIssued | Self::UnknownLock => 404,
            Self::Unavailable => 503,
            _ => 409,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct Problem {
    pub code: Code,
    pub message: String,
}

impl Problem {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(Code::Invalid, message)
    }
}

impl From<licash::Error> for Problem {
    fn from(e: licash::Error) -> Self {
        Self::invalid(e.to_string())
    }
}

fn notes(keyset: &Keyset, notes: &[Hex]) -> Result<Vec<Note>, Problem> {
    notes
        .iter()
        .map(|n| Note::from_bytes(keyset, &n.0).map_err(Problem::from))
        .collect()
}

/// A hub's Lightning gateway: what it charges, in satoshis, the smallest
/// unit, and the amounts it takes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lightning {
    /// Its node's public key, in hex.
    pub node: String,
    /// On top of an invoice's amount, in whole satoshis rounded up, in a
    /// lock that pays the hub only: routing fees included.
    pub pay: Fee,
    /// On top of the notes a receipt pays, in the invoice's amount.
    pub receive: Fee,
    /// A lock paying an invoice expires at least this many blocks plus
    /// the invoice's final CLTV delta, and 3, above the tip.
    pub pay_slack: u32,
    /// The most an invoice paid for a lock may ask.
    pub max_pay: u64,
    /// The notes a receipt pays: at least and at most.
    pub min_receive: u64,
    pub max_receive: u64,
}

impl Lightning {
    /// What a lock paying an invoice of `msat` must pay the hub.
    pub fn pay_lock(&self, msat: u64) -> u64 {
        let sat = msat.div_ceil(1000);
        sat.saturating_add(self.pay.due(sat))
    }
}

/// Pay `request`, a BOLT11 invoice, for `lock`, which pays the hub only
/// on the preimage of the invoice's hash. The same request again answers
/// where the payment stands.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pay {
    pub lock: Hex,
    pub request: String,
}

impl Pay {
    pub fn new(lock: &ProposalId, request: &str) -> Self {
        Self {
            lock: Hex(lock.as_bytes().to_vec()),
            request: request.to_owned(),
        }
    }

    pub fn lock(&self) -> Result<ProposalId, Problem> {
        Ok(ProposalId::from_bytes(self.lock.array("lock")?))
    }
}

/// Where a payment for a lock stands. Its lock settles with it: it pays
/// the hub once paid, and is refunded once failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Paying {
    pub state: PayState,
    /// Once paid: the proof of payment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<Hex>,
    /// Once failed: why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayState {
    Pending,
    Paid,
    Failed,
}

/// An output of a lock the hub makes of its own notes, as its payee
/// derived it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockOutput {
    pub denomination: u64,
    pub blinded: Hex,
    pub commitment: Hex,
}

/// The [`Info::features`] of a hub whose invoices say a [`Receive::memo`].
/// Older hubs ignore one: a wallet asks for it only of a hub naming this.
pub const FEATURE_MEMO: &str = "memo";

/// The most characters of a [`Receive::memo`]: well within the 639 bytes
/// of an invoice's description.
pub const MAX_MEMO: usize = 100;

/// `text` as a memo: its words, one space apart, of 1 to [`MAX_MEMO`]
/// characters, none a control character.
pub fn memo(text: &str) -> Result<String, Problem> {
    let memo = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if memo.is_empty() || memo.chars().count() > MAX_MEMO {
        return Err(Problem::invalid(format!(
            "a memo of 1 to {MAX_MEMO} characters"
        )));
    }
    if memo.chars().any(char::is_control) {
        return Err(Problem::invalid("a memo of no control characters"));
    }
    Ok(memo)
}

/// The [`Info::features`] of a hub whose invoices ask a
/// [`Receive::msat`] and commit to a [`Receive::description_hash`], as
/// LNURL-pay and Nostr zaps want them. Older hubs ignore both: a wallet
/// asks for them only of a hub naming this.
pub const FEATURE_LNURL: &str = "lnurl";

/// The most a [`Receive::msat`] may ask beyond what a receipt's outputs
/// and the hub's fee on them come to, in millisatoshis: under 2 sat, all
/// a payee choosing whole notes for a total in millisatoshis needs.
pub const MAX_RECEIVE_SURPLUS: u64 = 1_999;

/// The most notes, in satoshis, an invoice asking exactly `msat` pays at a
/// hub charging `fee` on what it receives ([`Receive::msat`]): none if the
/// fee takes it all.
pub fn receivable(msat: u64, fee: &Fee) -> Option<u64> {
    let notes = fee.most_within(msat / 1000).filter(|notes| *notes > 0)?;
    let least = (notes + fee.due(notes)) * 1000;
    (msat - least <= MAX_RECEIVE_SURPLUS).then_some(notes)
}

/// Ask for an invoice whose payment locks the hub's own notes to
/// `outputs`, under `keyset`, derived with `ephemeral`, on the preimage of
/// `hash`. The invoice asks for their value and the hub's receive fee, and
/// says `memo`, if given, to its payer: seen by the hub and its node too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receive {
    pub keyset: Hex,
    pub ephemeral: Hex,
    pub outputs: Vec<LockOutput>,
    pub hash: Hex,
    /// As [`memo`] makes it, at a hub naming [`FEATURE_MEMO`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// What the invoice asks, in millisatoshis, at a hub naming
    /// [`FEATURE_LNURL`]: at least the outputs' value and the hub's fee on
    /// them, at most [`MAX_RECEIVE_SURPLUS`] more, which is the hub's.
    /// Without, the invoice asks exactly those.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msat: Option<u64>,
    /// The SHA-256 hash of a description given elsewhere (LNURL-pay's
    /// metadata, a Nostr zap request), which the invoice commits to
    /// instead of saying a memo, at a hub naming [`FEATURE_LNURL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<Hex>,
}

impl Receive {
    pub fn new(keyset: &[u8; 32], ephemeral: &Point, outputs: &[Output], hash: &[u8; 32]) -> Self {
        let outputs = outputs
            .iter()
            .map(|o| LockOutput {
                denomination: o.denomination(),
                blinded: Hex(o.blinded().0.to_vec()),
                commitment: Hex(o.unlink_commitment().to_vec()),
            })
            .collect();
        Self {
            keyset: Hex(keyset.to_vec()),
            ephemeral: Hex(ephemeral.0.to_vec()),
            outputs,
            hash: Hex(hash.to_vec()),
            memo: None,
            msat: None,
            description_hash: None,
        }
    }

    /// The same, saying `memo` to its payer.
    pub fn with_memo(self, memo: Option<String>) -> Self {
        Self { memo, ..self }
    }

    /// The same, its invoice asking `msat` and committing to
    /// `description_hash`, if given ([`FEATURE_LNURL`]).
    pub fn with_lnurl(self, msat: Option<u64>, description_hash: Option<[u8; 32]>) -> Self {
        Self {
            msat,
            description_hash: description_hash.map(|h| Hex(h.to_vec())),
            ..self
        }
    }

    /// What its invoice asks, in millisatoshis, for outputs worth `amount`
    /// at a hub charging `fee` on them: its [`Receive::msat`], refused
    /// unless it is within [`MAX_RECEIVE_SURPLUS`] above those, or exactly
    /// those without one.
    pub fn asks(&self, amount: u64, fee: &Fee) -> Result<u64, Problem> {
        let least = amount
            .checked_add(fee.due(amount))
            .and_then(|sat| sat.checked_mul(1000))
            .ok_or_else(|| Problem::invalid("the amount overflows"))?;
        match self.msat {
            None => Ok(least),
            Some(msat) if msat >= least && msat - least <= MAX_RECEIVE_SURPLUS => Ok(msat),
            Some(_) => Err(Problem::invalid(format!(
                "an invoice of {least} to {} msat for these notes",
                least + MAX_RECEIVE_SURPLUS
            ))),
        }
    }

    /// Its description hash, if it commits to one: never with a memo.
    pub fn checked_description_hash(&self) -> Result<Option<[u8; 32]>, Problem> {
        match &self.description_hash {
            None => Ok(None),
            Some(_) if self.memo.is_some() => {
                Err(Problem::invalid("a memo or a description hash, not both"))
            }
            Some(hash) => Ok(Some(hash.array("description hash")?)),
        }
    }

    /// Its memo, if it says one, checked as [`memo`] makes it.
    pub fn checked_memo(&self) -> Result<Option<String>, Problem> {
        match &self.memo {
            None => Ok(None),
            Some(text) => match memo(text)? {
                normal if normal == *text => Ok(Some(normal)),
                _ => Err(Problem::invalid("a memo not as `memo` makes it")),
            },
        }
    }

    /// The outputs to lock, decoded: at most
    /// [`licash::spend::MAX_INPUTS`], since the hub locks a note of its own
    /// to each, all of them inputs of one lock.
    pub fn outputs(&self) -> Result<Vec<Output>, Problem> {
        if self.outputs.len() > licash::spend::MAX_INPUTS {
            return Err(Problem::invalid(format!(
                "more than {} outputs to lock",
                licash::spend::MAX_INPUTS
            )));
        }
        self.outputs
            .iter()
            .map(|o| {
                let blinded = Point(o.blinded.array("blinded")?);
                Ok(Output::new(
                    o.denomination,
                    blinded,
                    o.commitment.array("commitment")?,
                )?)
            })
            .collect()
    }

    /// The keyset, ephemeral key and hash, decoded.
    pub fn terms(&self) -> Result<([u8; 32], Point, [u8; 32]), Problem> {
        Ok((
            self.keyset.array("keyset")?,
            Point(self.ephemeral.array("ephemeral")?),
            self.hash.array("hash")?,
        ))
    }
}

/// The invoice to hand the payer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receiving {
    pub request: String,
}

/// Where a receipt over Lightning stands: once the invoice is paid, its
/// `lock` of the hub's notes, which the payee claims with the preimage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveStatus {
    pub state: ReceiveState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<Hex>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveState {
    /// Not paid yet.
    Open,
    /// Paid, and the hub's notes locked to the payee.
    Locked,
    /// Claimed: the invoice is settled.
    Settled,
    /// Expired or canceled unpaid, or the lock refunded.
    Canceled,
}

impl ReceiveStatus {
    pub fn lock(&self) -> Result<Option<ProposalId>, Problem> {
        self.lock
            .as_ref()
            .map(|l| Ok(ProposalId::from_bytes(l.array("lock")?)))
            .transpose()
    }
}

/// The recovery contracts a hub opens, in its info, as it offers them
/// now: the terms an opening binds are those of its quote then.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contracts {
    /// Under the mock authority, for regtest only: anyone "proves"
    /// anything, and a contract protects nothing.
    pub mock: bool,
    /// The caps and durations a holder chooses her contract's among, and
    /// what each costs.
    pub range: ContractRange,
    /// The most of one contract's cap the hub lends now, in sat: the part
    /// of it its holder does not fund. None if not known. Below
    /// [`MIN_REST`], the hub lends none but what rounds her part up to a
    /// cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funds: Option<u32>,
    /// Whether it refuses new openings now: as many live or under way as
    /// it takes, or its wallet short of its own reserve for one more. Not
    /// said while it opens them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub full: bool,
}

/// Whether a hub has room for a new contract now, as its info says: a
/// hint to choose a hub by, a minute old or more, and no promise. Its
/// offer is what binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Room {
    /// It opens them, and lends to them, as far as it says: also what a
    /// hub saying nothing of it reads as.
    Open,
    /// It refuses new openings now ([`Contracts::full`]).
    Full,
    /// It lends nothing now: only a contract its holder funds whole, but
    /// for what rounds her part up to a cap, opens there.
    Unfunded,
}

impl Room {
    /// Of a hub saying it is `full` or not, lending `funds` sat of a
    /// contract at most if it says.
    pub fn of(full: bool, funds: Option<u32>) -> Self {
        match funds {
            _ if full => Self::Full,
            Some(funds) if funds < MIN_REST => Self::Unfunded,
            _ => Self::Open,
        }
    }
}

impl Contracts {
    /// Whether the hub has room for a new contract now, as it says.
    pub fn room(&self) -> Room {
        Room::of(self.full, self.funds)
    }
}

/// Blocks in a year of Bitcoin's, 144 a day: what a contract's price counts
/// a year by, unless its hub says another ([`ContractRange::year_blocks`]).
pub const YEAR_BLOCKS: u32 = 144 * 365;

fn bitcoins_year() -> u32 {
    YEAR_BLOCKS
}

fn is_bitcoins_year(year: &u32) -> bool {
    *year == YEAR_BLOCKS
}

/// The least and most notes a contract protects, its cap, in sat: a
/// graph of 17 bits all ones, and of 31.
pub const MIN_CAP: u32 = (1 << 17) - 1;
pub const MAX_CAP: u32 = (1 << 31) - 1;

/// The least a contract's payout pays in one output of the rest of its
/// cap ([`payout_bits`]), in sat: its graph's least bit, `2^low_bits`.
pub const MIN_REST: u32 = 1 << 9;

/// The bits of the payout of a contract of `cap` sat: the most whose
/// outputs, `2^i` sat each, pay at most the cap all together; one output
/// more, of the rest, pays what they leave of it (`cap - (2^bits - 1)`,
/// below `2^bits`).
pub fn payout_bits(cap: u32) -> u8 {
    (u64::from(cap) + 1).ilog2() as u8
}

/// What the payout's binary outputs leave of a contract of `cap` sat,
/// paid by one output more: 0 where they pay it all.
pub fn payout_rest(cap: u32) -> u32 {
    let binary = ((1u64 << payout_bits(cap)) - 1) as u32;
    cap - binary
}

/// Whether a contract may be of `cap` sat: from [`MIN_CAP`] to [`MAX_CAP`],
/// and the rest its binary outputs leave none, or an output of
/// [`MIN_REST`] at least (one below would be dust, or near it). Any other
/// cap is one: the payout pays exactly what the hub locks.
pub fn is_cap(cap: u32) -> bool {
    let rest = payout_rest(cap);
    (MIN_CAP..=MAX_CAP).contains(&cap) && (rest == 0 || rest >= MIN_REST)
}

/// The smallest cap of at least `sat` ([`is_cap`]): `sat` itself, or
/// [`MIN_CAP`], or up to [`MIN_REST`] sat more. None past [`MAX_CAP`].
pub fn cap_at_least(sat: u64) -> Option<u32> {
    let cap = u32::try_from(sat.max(u64::from(MIN_CAP))).ok()?;
    let cap = match payout_rest(cap) {
        rest if rest > 0 && rest < MIN_REST => cap - rest + MIN_REST,
        _ => cap,
    };
    (cap <= MAX_CAP).then_some(cap)
}

/// The largest cap of at most `sat` ([`is_cap`]): `sat` itself, or
/// [`MAX_CAP`], or up to [`MIN_REST`] sat less. None below [`MIN_CAP`].
pub fn cap_at_most(sat: u64) -> Option<u32> {
    let cap = u32::try_from(sat.min(u64::from(MAX_CAP))).ok()?;
    let cap = match payout_rest(cap) {
        rest if rest > 0 && rest < MIN_REST => cap - rest,
        _ => cap,
    };
    (cap >= MIN_CAP).then_some(cap)
}

/// What a contract's opening costs its holder, besides her reserve,
/// itemized: the hub's fixed fee and its interest by the year on the
/// part of the contract it funds, and on hers if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractFee {
    /// The fixed part.
    pub opening: u64,
    /// Interest on the hub's part: `ppm_year` of it by the year.
    pub interest: u64,
    /// Interest on the part she funds herself, if any.
    pub interest_funded: u64,
}

impl ContractFee {
    pub fn total(&self) -> u64 {
        self.opening
            .saturating_add(self.interest)
            .saturating_add(self.interest_funded)
    }
}

/// The caps and durations a hub lets holders choose, and what each costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRange {
    /// The notes a contract protects, in sat: at least, at most, each a
    /// cap ([`is_cap`]), and any cap between.
    pub min_cap: u32,
    pub max_cap: u32,
    /// Blocks from its opening to its close: at least, at most.
    pub min_blocks: u32,
    pub max_blocks: u32,
    /// Its cap at most this many times the value of the coin its holder
    /// deposits: a bound hubs before none was announce and enforce. Hubs
    /// since announce `u32::MAX`, none, what she pays pricing their part;
    /// kept for wallets that read it, which need it there.
    pub per_coin: u32,
    /// Her reserve, from her deposit, returned as it closes.
    pub reserve: u64,
    /// The hub's fixed fee for an opening, from her deposit.
    pub fee: u64,
    /// Millionths of the part of its cap the hub funds for each year of
    /// blocks ([`year_blocks`](Self::year_blocks)) it lasts, rounded down.
    pub ppm_year: u32,
    /// Millionths of the part she funds herself, likewise.
    pub ppm_year_funded: u32,
    /// The blocks in the year its interest counts by, those of its
    /// network's time: [`YEAR_BLOCKS`] on Bitcoin's, and left out of its
    /// info then, as hubs before it said none. The same real year of
    /// interest is many more blocks on a chain of quicker ones.
    #[serde(default = "bitcoins_year", skip_serializing_if = "is_bitcoins_year")]
    pub year_blocks: u32,
}

impl ContractRange {
    /// The hub's fee for a contract of `cap` sat over `blocks`, `funded`
    /// sat of it funded by its holder.
    pub fn fee(&self, cap: u32, blocks: u32, funded: u32) -> ContractFee {
        let funded = funded.min(cap);
        ContractFee {
            opening: self.fee,
            interest: rate(self.ppm_year, cap - funded, blocks, self.year_blocks),
            interest_funded: rate(self.ppm_year_funded, funded, blocks, self.year_blocks),
        }
    }

    /// What opening a contract of `cap` sat over `blocks` costs, `funded`
    /// of it hers: her reserve and the hub's fee (not what she funds,
    /// paid back to her in notes).
    pub fn price(&self, cap: u32, blocks: u32, funded: u32) -> u64 {
        self.reserve
            .saturating_add(self.fee(cap, blocks, funded).total())
    }

    /// Whether a holder may choose a contract of `cap` sat: a cap
    /// ([`is_cap`]) within the range.
    pub fn allows_cap(&self, cap: u32) -> bool {
        (self.min_cap..=self.max_cap).contains(&cap) && is_cap(cap)
    }

    /// The smallest cap a holder may choose of at least `sat`: none past
    /// the most.
    pub fn cap_at_least(&self, sat: u64) -> Option<u32> {
        cap_at_least(sat.max(u64::from(self.min_cap))).filter(|&c| c <= self.max_cap)
    }

    /// The largest cap a contract may have, its holder depositing a
    /// coin of `coin` sat: none less than the least.
    pub fn max_cap_for(&self, coin: u64) -> Option<u32> {
        let most = coin
            .saturating_mul(u64::from(self.per_coin))
            .min(u64::from(self.max_cap));
        cap_at_most(most).filter(|&s| s >= self.min_cap)
    }
}

/// `ppm` millionths of `cap` for each year of `blocks`, a year being
/// `year_blocks` of them, rounded down.
pub fn rate(ppm: u32, cap: u32, blocks: u32, year_blocks: u32) -> u64 {
    let n = u128::from(ppm) * u128::from(cap) * u128::from(blocks);
    let year = 1_000_000 * u128::from(year_blocks.max(1));
    u64::try_from(n / year).unwrap_or(u64::MAX)
}

/// What a hub takes on Bitcoin, in its info: deposits whose payment, once
/// confirmed, locks the hub's own notes to their payer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposits {
    /// On top of the notes a deposit locks.
    pub fee: Fee,
    /// The notes a deposit locks: at least and at most.
    pub min: u64,
    pub max: u64,
    /// Confirmations its payment needs.
    pub depth: u32,
    /// Blocks from the request within which its payment must confirm.
    pub window: u32,
    /// Blocks from the request to its timeout, after which its payer may
    /// take the coins back.
    pub timeout: u32,
    /// Its deposit root, an x-only key, from which anyone derives the key it
    /// claims a deposit that returns a contract's reserve with
    /// (`licash_onchain::deposit::close_claim_key`): a hub with none opens
    /// no contract, and a wallet restored from its seed rebuilds every
    /// address of such a deposit from the root alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_root: Option<XOnly>,
}

/// An x-only public key, as hex in JSON.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XOnly(pub [u8; 32]);

impl std::fmt::Debug for XOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XOnly({})", hex::encode(self.0))
    }
}

impl Serialize for XOnly {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for XOnly {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut key = [0; 32];
        hex::decode_to_slice(&text, &mut key)
            .map_err(|_| serde::de::Error::custom("an x-only key is 32 bytes of hex"))?;
        Ok(Self(key))
    }
}

impl Deposits {
    /// What a deposit of notes worth `amount` pays on Bitcoin.
    pub fn pays(&self, amount: u64) -> Option<u64> {
        amount.checked_add(self.fee.due(amount))
    }

    /// The notes a deposit paying exactly `pays` on Bitcoin locks, its fee
    /// in it: none if none does, rounding the fee up leaving a gap there,
    /// whatever the limits.
    pub fn paid_by(&self, pays: u64) -> Option<u64> {
        self.most_for(pays)
            .filter(|amount| self.pays(*amount) == Some(pays))
    }

    /// The most notes a deposit locks that a payment of `pays` on Bitcoin
    /// covers, its fee in it: what a payment fixed beforehand, a contract's
    /// reserve, locks, the rest of it the hub's. None if not even none are
    /// covered.
    pub fn most_for(&self, pays: u64) -> Option<u64> {
        self.fee.most_within(pays)
    }
}

/// Ask for a deposit: an address on Bitcoin whose payment locks the hub's
/// own notes to the outputs of `receive`, as over Lightning, on the
/// preimage of its hash. `refund`, an x-only key, takes the coins back
/// after the deposit's timeout, and names the deposit at its hub
/// ([`deposit_state`]): one a hub took a deposit under is refused for
/// another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    #[serde(flatten)]
    pub receive: Receive,
    pub refund: Hex,
    /// Set for the deposit a contract's default pays her reserve to
    /// ([`CloseTerms`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close: Option<CloseTerms>,
}

/// What a deposit asks besides when a contract's default close returns the
/// holder's reserve to it. Its payment is that reserve exactly, the notes
/// it locks the most that covers (`Deposits::most_for`), and she takes the
/// coins back `licash_onchain::deposit::CLOSE_WAIT` blocks after it confirms,
/// whenever the default is posted. Its notes are locked once she asks, when
/// she comes back after the close, not when the payment confirms. Until the
/// hub's contracts bind it to the contract that names it, the hub keeps it
/// for the deposit window only, and then until `until`, the block the
/// contract's Base gives, for the default's payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseTerms {
    /// What its payment is.
    pub pays: u64,
    /// The block the hub gives up watching for its payment at.
    pub until: u32,
}

/// A deposit's terms: pay exactly `amount` to `address`, in a block up to
/// `fund_by`. The address is that of the taproot output a hub claims with
/// the preimage of the hash and its key `claim`, x-only, and its payer
/// takes back with the key `refund` after block `timeout`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Depositing {
    pub address: String,
    pub amount: u64,
    pub claim: Hex,
    pub timeout: u32,
    pub fund_by: u32,
}

/// Where a deposit stands: as a receipt over Lightning, with its payment
/// once confirmed. With what was asked, `request`, and the terms answered,
/// `terms`: a wallet that lost its record of the deposit finds it again by
/// its refund key, derived from its seed, and takes it on if what is
/// answered is under the hash its seed gives for just that.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositStatus {
    #[serde(flatten)]
    pub status: ReceiveStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding: Option<Funding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Deposit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<Depositing>,
}

/// A deposit's payment: output `vout` of transaction `txid`, confirmed in
/// the block at `height`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Funding {
    pub txid: String,
    pub vout: u32,
    pub height: u32,
}

fn hexes(notes: &[Note]) -> Vec<Hex> {
    notes.iter().map(|n| Hex(n.to_bytes())).collect()
}

impl Offer {
    pub fn new(proposal: &Proposal, notes: &[Note]) -> Self {
        Self {
            proposal: Hex(proposal.commitment_bytes()),
            notes: hexes(notes),
            holds: None,
        }
    }

    /// [`Offer::new`], signed by each of `notes`' hold key: `holds`, in
    /// their order ([`licash::offer::sign`]).
    pub fn held(proposal: &Proposal, notes: &[Note], holds: &[Signature]) -> Self {
        Self {
            holds: Some(holds.iter().map(|s| Hex(s.0.to_vec())).collect()),
            ..Self::new(proposal, notes)
        }
    }

    /// Its notes' hold keys' signatures, if signed: not verified.
    pub fn holds(&self) -> Result<Option<Vec<Signature>>, Problem> {
        let Some(holds) = &self.holds else {
            return Ok(None);
        };
        if holds.len() != self.notes.len() {
            return Err(Problem::invalid(
                "an offer's holds are not one for each note",
            ));
        }
        let holds = holds.iter().map(|h| {
            let bytes = <[u8; 64]>::try_from(h.0.as_slice())
                .map_err(|_| Problem::invalid("an offer's hold is not a signature"))?;
            Ok(Signature(bytes))
        });
        Ok(Some(holds.collect::<Result<_, Problem>>()?))
    }

    /// The proposal and its notes, under the keyset the proposal names
    /// among `keysets`.
    pub fn decode<'k>(
        &self,
        keysets: impl Fn(&[u8; 32]) -> Option<&'k Keyset>,
    ) -> Result<(Proposal, Vec<Note>), Problem> {
        let proposal = Proposal::from_commitment_bytes(&self.proposal.0)?;
        let keyset = keysets(proposal.keyset_id())
            .ok_or_else(|| Problem::new(Code::UnknownKeyset, "unknown keyset"))?;
        let notes = notes(keyset, &self.notes)?;
        Ok((proposal, notes))
    }
}

impl Offered {
    pub fn new(grant: &Grant) -> Result<Self, Problem> {
        Ok(Self {
            grant: Hex(grant.to_bytes()?),
        })
    }

    pub fn decode(&self) -> Result<Grant, Problem> {
        Ok(Grant::from_bytes(&self.grant.0)?)
    }
}

impl Release {
    pub fn new(signed: &SignedProposal, notes: &[Note]) -> Self {
        Self {
            keyset: Hex(signed.proposal().keyset_id().to_vec()),
            signed: Hex(signed.to_bytes()),
            notes: hexes(notes),
        }
    }

    /// The signed proposal and its notes, under `keyset` among `keysets`.
    pub fn decode<'k>(
        &self,
        keysets: impl Fn(&[u8; 32]) -> Option<&'k Keyset>,
    ) -> Result<(SignedProposal, Vec<Note>), Problem> {
        signed(&self.keyset, &self.signed, &self.notes, keysets)
    }
}

fn signed<'k>(
    keyset: &Hex,
    signed: &Hex,
    notes: &[Hex],
    keysets: impl Fn(&[u8; 32]) -> Option<&'k Keyset>,
) -> Result<(SignedProposal, Vec<Note>), Problem> {
    let keyset = keysets(&keyset.array("keyset")?)
        .ok_or_else(|| Problem::new(Code::UnknownKeyset, "unknown keyset"))?;
    let notes = self::notes(keyset, notes)?;
    let signed = SignedProposal::from_bytes(keyset, &notes, &signed.0)?;
    Ok((signed, notes))
}

impl Payment {
    pub fn new(hub: &str, signed: &SignedProposal, notes: &[Note], unlock: &Unlock) -> Self {
        Self {
            hub: hub.to_owned(),
            release: Release::new(signed, notes),
            unlock: Hex(unlock.to_vec()),
            note: None,
        }
    }

    /// The same, with the sealed `note`.
    pub fn with_note(self, note: Option<Vec<u8>>) -> Self {
        Self {
            note: note.map(Hex),
            ..self
        }
    }

    /// The granted spend, its notes and its unlock, under `keyset` among
    /// `keysets`: the unlock checked to open every output of the grant.
    pub fn decode<'k>(
        &self,
        keysets: impl Fn(&[u8; 32]) -> Option<&'k Keyset>,
    ) -> Result<(SignedProposal, Vec<Note>, Unlock), Problem> {
        let id = self.release.keyset.array("keyset")?;
        let keyset =
            keysets(&id).ok_or_else(|| Problem::new(Code::UnknownKeyset, "unknown keyset"))?;
        let (signed, notes) = self.release.decode(|_| Some(keyset))?;
        let Authorization::Granted(grant) = signed.authorization() else {
            return Err(Problem::invalid("not a granted spend"));
        };
        let unlock = self.unlock.array("unlock")?;
        grant.verify_unlock(keyset, &unlock)?;
        Ok((signed, notes, unlock))
    }
}

impl Released {
    pub fn new(unlock: &Unlock) -> Self {
        Self {
            unlock: Hex(unlock.to_vec()),
        }
    }

    pub fn decode(&self) -> Result<Unlock, Problem> {
        self.unlock.array("unlock")
    }
}

impl Unlink {
    pub fn new(request: &Request) -> Self {
        Self {
            request: Hex(request.to_bytes().to_vec()),
        }
    }

    pub fn decode(&self) -> Result<Request, Problem> {
        Ok(Request::from_bytes(&self.request.0)?)
    }
}

impl Unlinked {
    pub fn new(answer: &Answer) -> Self {
        Self {
            answer: Hex(answer.to_bytes().to_vec()),
        }
    }

    pub fn decode(&self) -> Result<Answer, Problem> {
        Ok(Answer::from_bytes(self.answer.array("answer")?)?)
    }
}

impl Inquire {
    /// An inquiry of `keyset` at `at`, of `notes` each with its signature.
    pub fn new(keyset: &[u8; 32], at: u64, notes: &[(Message, Signature)]) -> Self {
        Self {
            keyset: Hex(keyset.to_vec()),
            at,
            notes: notes
                .iter()
                .map(|(note, signature)| Inquired {
                    note: Hex(note.to_bytes().to_vec()),
                    signature: Hex(signature.0.to_vec()),
                })
                .collect(),
        }
    }

    /// The keyset, the time and each note with its signature, unchecked.
    #[allow(clippy::type_complexity)]
    pub fn decode(&self) -> Result<([u8; 32], u64, Vec<(Message, Signature)>), Problem> {
        if self.notes.len() > licash::inquiry::MAX_NOTES {
            return Err(Problem::invalid(format!(
                "at most {} notes an inquiry",
                licash::inquiry::MAX_NOTES
            )));
        }
        let notes = self
            .notes
            .iter()
            .map(|n| {
                Ok((
                    Message::from_bytes(&n.note.0)?,
                    Signature(n.signature.array("signature")?),
                ))
            })
            .collect::<Result<_, Problem>>()?;
        Ok((self.keyset.array("keyset")?, self.at, notes))
    }
}

impl Evidenced {
    pub fn new(evidence: &[Vec<Evidence>]) -> Self {
        Self {
            evidence: evidence
                .iter()
                .map(|e| Hex(licash::recovery::evidence_to_bytes(e)))
                .collect(),
        }
    }

    /// The evidence of each of `asked` notes under `keyset`, each piece
    /// decoded and its notes and signatures checked, not yet what it shows.
    pub fn decode(&self, keyset: &Keyset, asked: usize) -> Result<Vec<Vec<Evidence>>, Problem> {
        if self.evidence.len() != asked {
            return Err(Problem::invalid("it answered other notes than asked"));
        }
        self.evidence
            .iter()
            .map(|e| {
                Ok(licash::recovery::evidence_from_bytes(
                    keyset,
                    licash::recovery::MAX_EVIDENCE,
                    &e.0,
                )?)
            })
            .collect()
    }
}

impl Lock {
    pub fn new(signed: &SignedProposal, notes: &[Note]) -> Self {
        Self {
            keyset: Hex(signed.proposal().keyset_id().to_vec()),
            signed: Hex(signed.to_bytes()),
            notes: hexes(notes),
        }
    }

    /// The signed lock and its notes, under `keyset` among `keysets`.
    pub fn decode<'k>(
        &self,
        keysets: impl Fn(&[u8; 32]) -> Option<&'k Keyset>,
    ) -> Result<(SignedProposal, Vec<Note>), Problem> {
        signed(&self.keyset, &self.signed, &self.notes, keysets)
    }
}

impl Locked {
    pub fn new(certificate: &Certificate) -> Self {
        Self {
            certificate: Hex(certificate.to_bytes()),
        }
    }

    /// The certificate, checked to be `keyset`'s of the lock `signed`
    /// makes of `notes`.
    pub fn decode(
        &self,
        keyset: &Keyset,
        signed: &SignedProposal,
        notes: &[Note],
    ) -> Result<Certificate, Problem> {
        let certificate = Certificate::from_bytes(keyset, &self.certificate.0)?;
        certificate.verify_source(keyset, signed, notes)?;
        Ok(certificate)
    }
}

impl LockState {
    pub fn new(
        proposal: &Proposal,
        certificate: &Certificate,
        settled: Option<Settled>,
        preimage: Option<[u8; 32]>,
    ) -> Self {
        Self {
            proposal: Hex(proposal.commitment_bytes()),
            certificate: Hex(certificate.to_bytes()),
            settled,
            preimage: preimage.map(|p| Hex(p.to_vec())),
            signatures: vec![],
            checkpoint: None,
        }
    }

    /// With `checkpoint`, the one its terms name ([`LockState::checkpoint`]).
    pub fn with_checkpoint(mut self, checkpoint: &Checkpoint) -> Self {
        self.checkpoint = Some(Hex(checkpoint.to_bytes()));
        self
    }

    /// With its payer's owner `signatures` ([`LockState::signatures`]).
    pub fn with_signatures(mut self, signatures: &[Signature]) -> Self {
        self.signatures = signatures.iter().map(|s| Hex(s.0.to_vec())).collect();
        self
    }

    /// The lock under the keyset its proposal names among `keysets`, its
    /// certificate checked to be that keyset's of it and its preimage to
    /// be of its hash.
    pub fn decode<'k>(
        &self,
        keysets: impl Fn(&[u8; 32]) -> Option<&'k Keyset>,
    ) -> Result<LockView, Problem> {
        let proposal = Proposal::from_commitment_bytes(&self.proposal.0)?;
        let terms = proposal
            .lock()
            .ok_or_else(|| Problem::invalid("not a lock"))?
            .terms();
        let hash = *terms.hash();
        let checkpoint = match &self.checkpoint {
            Some(bytes) => {
                let checkpoint = Checkpoint::from_bytes(&bytes.0)?;
                if checkpoint.commitment() != *terms.checkpoint() {
                    return Err(Problem::invalid("not the checkpoint the lock names"));
                }
                Some(checkpoint)
            }
            None => None,
        };
        let keyset = keysets(proposal.keyset_id())
            .ok_or_else(|| Problem::new(Code::UnknownKeyset, "unknown keyset"))?;
        let certificate = Certificate::from_bytes(keyset, &self.certificate.0)?;
        certificate.verify(keyset)?;
        if certificate.metadata().source_id() != proposal.id() {
            return Err(Problem::invalid("the certificate is of another proposal"));
        }
        let preimage = match &self.preimage {
            Some(p) => Some(p.array("preimage")?),
            None => None,
        };
        if preimage.is_some_and(|p| lock_hash(&p) != hash) {
            return Err(Problem::invalid("not the preimage of the lock's hash"));
        }
        let signatures = match self.signatures.is_empty() {
            true => None,
            false => {
                let signatures = (self.signatures.iter())
                    .map(|s| s.array::<64>("signature").map(Signature))
                    .collect::<Result<Vec<_>, _>>()?;
                certificate.authenticate_source(keyset, &proposal, &signatures)?;
                Some(signatures)
            }
        };
        Ok(LockView {
            proposal,
            certificate,
            settled: self.settled,
            preimage,
            signatures,
            checkpoint,
        })
    }
}

impl Settle {
    pub fn new(lock: &ProposalId, preimage: &[u8; 32]) -> Self {
        Self {
            lock: Hex(lock.as_bytes().to_vec()),
            preimage: Hex(preimage.to_vec()),
        }
    }

    pub fn decode(&self) -> Result<(ProposalId, [u8; 32]), Problem> {
        let lock = ProposalId::from_bytes(self.lock.array("lock")?);
        Ok((lock, self.preimage.array("preimage")?))
    }
}

impl Refund {
    pub fn new(lock: &ProposalId) -> Self {
        Self {
            lock: Hex(lock.as_bytes().to_vec()),
        }
    }

    pub fn decode(&self) -> Result<ProposalId, Problem> {
        Ok(ProposalId::from_bytes(self.lock.array("lock")?))
    }
}

impl Issued {
    pub fn new(issued: &[MintResponse]) -> Self {
        Self {
            issuances: issued.iter().map(|i| Hex(i.to_bytes())).collect(),
        }
    }

    /// The issuances under `keyset`, the lock's.
    pub fn decode(&self, keyset: &Keyset) -> Result<Vec<MintResponse>, Problem> {
        self.issuances
            .iter()
            .map(|i| MintResponse::from_bytes(keyset, &i.0).map_err(Problem::from))
            .collect()
    }
}
