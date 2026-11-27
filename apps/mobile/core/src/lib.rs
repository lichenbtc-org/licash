//! The Licash wallet of the mobile apps: [`Wallet`], over the SDK's wallet,
//! with blocking methods for the apps to call off their main thread, and
//! Bitcoin read through the app's light client ([`ChainSource`]).
//!
//! What a user sees is notes at hubs, and coins paid on Bitcoin to the
//! wallet's silent payment address, which [`Wallet::move_to_licash`] turns
//! into notes. One payment code ([`Wallet::payment_code`]) takes both.

mod chain;
mod log;
mod tor;
mod wallet;

pub use chain::{ChainError, ChainSource};
pub use log::{set_logger, Logger};
pub use tor::TorClient;
pub use wallet::{
    wallet_exists, AppTerms, BalancePoint, BalanceSample, Bridge, BridgeAccount, BridgeApp,
    BridgeLine, BridgeTopUp, BudgetPeriod, ConnectedApp, Contact, ExportedNotes, Flow, HubAmount,
    ImportSource, ImportedNotes, StatEvent, Stats, TopUpRules, Unlink, Wallet, Way,
};

uniffi::setup_scaffolding!();

/// The networks a wallet can be of. Every one but Bitcoin is for testing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Network {
    Bitcoin,
    Signet,
    Mutinynet,
    Regtest,
}

impl Network {
    fn profile(self) -> licash::spend::ChainProfile {
        use licash::spend::ChainProfile::*;
        match self {
            Self::Bitcoin => Core30Mainnet,
            Self::Signet => Core30Signet,
            Self::Mutinynet => Mutinynet,
            Self::Regtest => Core30DefaultRegtest,
        }
    }

    fn of(profile: licash::spend::ChainProfile) -> Self {
        use licash::spend::ChainProfile::*;
        match profile {
            Core30Mainnet => Self::Bitcoin,
            Core30Signet => Self::Signet,
            Mutinynet => Self::Mutinynet,
            Core30DefaultRegtest => Self::Regtest,
        }
    }
}

/// The name the light client knows `network` by.
#[uniffi::export]
pub fn chain_name(network: Network) -> String {
    match network {
        Network::Bitcoin => "bitcoin",
        Network::Signet => "signet",
        Network::Mutinynet => "mutinynet",
        Network::Regtest => "regtest",
    }
    .into()
}

/// The seconds a block of `network` takes: what the app says a count of
/// blocks lasts in. 600 on Bitcoin's networks, 30 on Mutinynet. Protocol
/// windows and margins are counted in blocks, the same on each.
#[uniffi::export]
pub fn block_seconds(network: Network) -> u32 {
    network.profile().block_seconds()
}

/// What went wrong, as the app tells its user.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LicashError {
    /// Not something the wallet can do: as the user asked it, never.
    #[error("{reason}")]
    Invalid { reason: String },
    /// A hub, relay or the chain could not be reached: later, perhaps.
    #[error("{reason}")]
    Unavailable { reason: String },
    /// Under way, and finished by [`Wallet::resume`].
    #[error("{reason}")]
    Pending { reason: String },
    #[error("{needed} sat needed, {available} sat available")]
    Insufficient { needed: u64, available: u64 },
    /// A hub at an onion address, and the wallet opened without Tor.
    #[error("an onion hub is reached through Tor: turn it on")]
    NeedsTor,
    /// A payment of notes at the hub at `url`, which the wallet does not
    /// trust: [`Wallet::receive`] it trusting the hub to take it.
    #[error("a payment at hub {url}, not trusted yet")]
    UnknownHub { url: String },
    /// The hub at `hub` charges more than the wallet agreed to pay it, as
    /// its contracts there opened: nothing is paid there until the user
    /// approves its fees ([`Wallet::fees_raised`],
    /// [`Wallet::approve_fees`]).
    #[error("hub {hub} charges more than agreed: approve its fees to pay there")]
    FeesRaised { hub: String },
    /// A swap provider, or a hub's gateway, at `who`, asks `asked` sat in
    /// fees where the quote said `agreed`: nothing was paid. Quote again,
    /// and pay at the new fee only once the user accepts it.
    #[error("{reason}")]
    FeeRose {
        who: String,
        agreed: u64,
        asked: u64,
        reason: String,
    },
    /// The wallet's own storage failed.
    #[error("{reason}")]
    Failed { reason: String },
    /// The hub at `hub` would not keep a payment's note with it: nothing
    /// was paid. Pay without the note ([`Wallet::pay`]), if the user
    /// chooses.
    #[error("hub {hub} keeps no note with a payment")]
    NoteUnkept { hub: String },
}

impl From<licash_wallet::Error> for LicashError {
    fn from(e: licash_wallet::Error) -> Self {
        use licash_wallet::Error as E;
        let reason = e.to_string();
        match e {
            E::Unavailable { .. } => Self::Unavailable { reason },
            E::Pending { .. } | E::NoteTaken => Self::Pending { reason },
            E::Insufficient { needed, available } => Self::Insufficient { needed, available },
            E::UnknownHub(url) => Self::UnknownHub { url },
            E::FeesRaised { hub } => Self::FeesRaised { hub },
            E::NoteUnkept { hub } => Self::NoteUnkept { hub },
            E::FeeRose {
                who, agreed, asked, ..
            } => Self::FeeRose {
                who,
                agreed,
                asked,
                reason,
            },
            E::Setup(_) | E::Storage(_) => Self::Failed { reason },
            _ => Self::Invalid { reason },
        }
    }
}

impl LicashError {
    /// `e`, a wallet's error if it is one, else as `other`.
    fn from_any(e: anyhow::Error, other: fn(String) -> Self) -> Self {
        match e.downcast::<licash_wallet::Error>() {
            Ok(e) => e.into(),
            Err(e) => other(format!("{e:#}")),
        }
    }

    fn invalid(reason: impl ToString) -> Self {
        Self::Invalid {
            reason: reason.to_string(),
        }
    }

    fn failed(reason: impl ToString) -> Self {
        Self::Failed {
            reason: reason.to_string(),
        }
    }
}

/// A hub the wallet trusts.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Hub {
    pub url: String,
    /// Its fee on a payment: `base` plus `ppm` millionths of it.
    pub fee_base: u64,
    pub fee_ppm: u64,
    /// And, on a payment or a lock, for each note it makes for others
    /// than the hub, in thousandths of a sat.
    pub fee_output_msat: u64,
    /// The least and most it turns into notes from Bitcoin, if it does.
    pub deposits: Option<Range>,
    /// Whether it serves what finds silent payments.
    pub silent: bool,
    /// Whether it names relays for mailboxes.
    pub mailbox: bool,
    /// Its fees on a lock, which holds notes until a condition is met (as
    /// paying a Lightning invoice does), and on refunding one.
    pub lock_fee: Rate,
    pub refund_fee: Rate,
    /// On top of the notes moving Bitcoin into them makes, if it does.
    pub deposit_fee: Option<Rate>,
    /// The recovery contracts it opens now, if it does.
    pub contracts: Option<ContractTerms>,
}

/// The recovery contracts a hub opens, as its info says. A contract locks
/// the hub's collateral on Bitcoin behind the wallet's notes there, up to
/// `cap`: if the hub fails them, the wallet recovers them from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ContractTerms {
    /// The least of the notes at the hub one protects, in sat: its
    /// range's least cap.
    pub cap: u64,
    /// What opening the least one costs, in sat, paid from a coin on
    /// Bitcoin, all of it hers: its reserve and the hub's fee.
    pub price: u64,
    /// Blocks from opening the least one to its close: its range's fewest.
    pub blocks: u32,
    /// Under the mock authority, for regtest only: such a contract
    /// protects nothing.
    pub mock: bool,
    /// The caps and durations the wallet chooses among: always said.
    pub range: Option<ContractRange>,
    /// The most of a contract's cap the hub lends now, in sat, as it last
    /// said: none if it did not, as hubs before any did.
    #[uniffi(default = None)]
    pub funds: Option<u64>,
    /// Whether it refuses new contracts now, as it last said.
    #[uniffi(default = false)]
    pub full: bool,
}

/// Whether a hub has room for a new contract, as it last said
/// ([`contract_room`]): a hint to choose a hub by, not a promise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HubRoom {
    /// It opens them, as far as it says, or says nothing of it.
    Open,
    /// It refuses new contracts now: as many as it takes.
    Full,
    /// It funds none of even the smallest now: only one its holder funds
    /// whole opens there.
    Unfunded,
}

/// Whether the hub offering `terms` has room for a new contract now, as
/// it last said: what a wallet goes by before a deposit is paid for one.
/// Open unless it says otherwise.
#[uniffi::export]
pub fn contract_room(terms: ContractTerms) -> HubRoom {
    let sat = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
    match licash_api::Room::of(terms.full, terms.funds.map(sat)) {
        licash_api::Room::Open => HubRoom::Open,
        licash_api::Room::Full => HubRoom::Full,
        licash_api::Room::Unfunded => HubRoom::Unfunded,
    }
}

/// The caps and durations a hub lets a wallet choose for a contract, and
/// what each costs ([`contract_price`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ContractRange {
    /// The most of the notes at the hub one protects, in sat: at least,
    /// at most.
    pub min_cap: u64,
    pub max_cap: u64,
    /// Blocks from opening one to its close: at least, at most.
    pub min_blocks: u32,
    pub max_blocks: u32,
    /// Its cap at most this many times the coin paying for it: of hubs
    /// before none was, which enforce it; `u32::MAX`, none, of those since.
    pub per_coin: u32,
    /// Its holder's reserve, in sat, paid back as it closes.
    pub reserve: u64,
    /// The hub's fixed fee for one, in sat.
    pub fee: u64,
    /// Millionths of the part of its cap the hub funds it charges for
    /// each year it lasts, and of the part its holder funds.
    pub ppm_year: u32,
    pub ppm_year_funded: u32,
    /// The blocks in the year of its interest: its network's, 144 a day on
    /// Bitcoin ([`block_seconds`] says the time they take).
    pub year_blocks: u32,
}

impl From<licash_api::ContractRange> for ContractRange {
    fn from(r: licash_api::ContractRange) -> Self {
        Self {
            min_cap: u64::from(r.min_cap),
            max_cap: u64::from(r.max_cap),
            min_blocks: r.min_blocks,
            max_blocks: r.max_blocks,
            per_coin: r.per_coin,
            reserve: r.reserve,
            fee: r.fee,
            ppm_year: r.ppm_year,
            ppm_year_funded: r.ppm_year_funded,
            year_blocks: r.year_blocks,
        }
    }
}

impl ContractRange {
    /// As the hub's info says it: a cap past a `u32` none a hub offers.
    pub(crate) fn api(&self) -> licash_api::ContractRange {
        let sat = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
        licash_api::ContractRange {
            min_cap: sat(self.min_cap),
            max_cap: sat(self.max_cap),
            min_blocks: self.min_blocks,
            max_blocks: self.max_blocks,
            per_coin: self.per_coin,
            reserve: self.reserve,
            fee: self.fee,
            ppm_year: self.ppm_year,
            ppm_year_funded: self.ppm_year_funded,
            year_blocks: self.year_blocks,
        }
    }
}

/// What opening a contract within `range` protecting up to `cap` sat over
/// `blocks` costs, in sat, `funded` of it hers: as its hub prices it (her
/// part, paid beside it, is not in it).
#[uniffi::export]
pub fn contract_price(range: ContractRange, cap: u64, blocks: u32, funded: u64) -> u64 {
    range.api().price(sat32(cap), blocks, sat32(funded))
}

/// What opening a contract costs besides its holder's reserve, itemized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ContractFee {
    /// The hub's fixed fee.
    pub opening: u64,
    /// Its interest on the part it funds: the range's `ppm_year` of it by
    /// the year.
    pub interest: u64,
    /// Its interest on the part she funds herself: `ppm_year_funded`.
    pub interest_funded: u64,
}

/// What opening a contract within `range` of `cap` sat over `blocks`,
/// `funded` of it hers, costs besides her reserve, itemized.
#[uniffi::export]
pub fn contract_fee(range: ContractRange, cap: u64, blocks: u32, funded: u64) -> ContractFee {
    let fee = range.api().fee(sat32(cap), blocks, sat32(funded));
    ContractFee {
        opening: fee.opening,
        interest: fee.interest,
        interest_funded: fee.interest_funded,
    }
}

/// The smallest cap a contract within `range` may have of `sat` at least,
/// in sat: `sat` itself, or the least, or under 512 sat more (a cap whose
/// payout pays exactly what the hub locks). None past the most.
#[uniffi::export]
pub fn contract_cap_at_least(range: ContractRange, sat: u64) -> Option<u64> {
    range.api().cap_at_least(sat).map(u64::from)
}

/// The most a contract within `range` protects, paid from a coin of
/// `coin` sat: the largest cap it covers, none if less than the least.
#[uniffi::export]
pub fn contract_max_cap(range: ContractRange, coin: u64) -> Option<u64> {
    range.api().max_cap_for(coin).map(u64::from)
}

/// The contract a coin pays for whole: its cap, and her part of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ContractFit {
    pub cap: u64,
    pub funded: u64,
}

/// The contract within `range` over `blocks` that a coin of `coin` sat
/// pays for whole: her part the most the coin pays beside the price, as
/// many notes of her hub's `denominations` as a claim names (`notes`)
/// making it exactly, and leaving less than `dust`; its cap the smallest of
/// her part and `inbound` sat more (liquidity asked of the hub, at its
/// interest), `least_cap` sat at least. With no inbound, the hub funds
/// nothing of it but what makes a cap. No change comes back from a coin,
/// so what its contract does not take, it does not take. None if no
/// contract does.
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn contract_fit(
    range: ContractRange,
    blocks: u32,
    coin: u64,
    least_cap: u64,
    inbound: u64,
    dust: u64,
    denominations: Vec<u64>,
    notes: u32,
) -> Option<ContractFit> {
    let notes = usize::try_from(notes).unwrap_or(usize::MAX);
    let range = range.api();
    let fitted = licash_contracts::holder::fit(
        &licash_contracts::holder::Pricing {
            range: &range,
            lends: None,
        },
        blocks,
        coin,
        dust,
        (&denominations, notes),
        sat32(least_cap),
        sat32(inbound),
    )?;
    Some(ContractFit {
        cap: u64::from(fitted.cap),
        funded: u64::from(fitted.funded),
    })
}

/// What a holder's funding of `wanted` sat rounds down to: as much as her
/// hub's `denominations` make in `notes` notes, those a claim names should
/// the hub never issue them.
#[uniffi::export]
pub fn contract_fundable(denominations: Vec<u64>, notes: u32, wanted: u64) -> u64 {
    let notes = usize::try_from(notes).unwrap_or(usize::MAX);
    licash_contracts::holder::fundable(&denominations, notes, wanted)
}

/// `sat` as a contract's terms count it: none past a `u32` is offered.
fn sat32(sat: u64) -> u32 {
    u32::try_from(sat).unwrap_or(u32::MAX)
}

/// A fee, in sat: `base` plus `ppm` millionths of what it is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Rate {
    pub base: u64,
    pub ppm: u64,
}

/// All a hub charges on notes: on a payment and in each branch of a lock,
/// and for each note it makes for others than the hub, in thousandths of
/// a sat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Fees {
    pub spend: Rate,
    pub lock: Rate,
    pub refund: Rate,
    pub output_msat: u64,
}

/// A hub charging more than the wallet agreed to pay it
/// ([`Wallet::fees_raised`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FeesRaised {
    pub hub: String,
    /// What it charges now, as the wallet last heard.
    pub charged: Fees,
    /// The most the wallet agreed to: its fees as the wallet's contracts
    /// there opened, or approved since.
    pub agreed: Fees,
}

/// A note optimization, previewed with no `id` or completed with one.
/// `value` is reminted, not paid away; only `fee` leaves the balance.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NoteOptimization {
    pub id: Option<String>,
    pub hub: String,
    pub value: u64,
    pub fee: u64,
    pub notes_before: u64,
    pub notes_after: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Range {
    pub min: u64,
    pub max: u64,
}

/// A hub announced on Nostr, not used yet.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FoundHub {
    /// The name it announced itself under, if any.
    pub name: Option<String>,
    /// What it says of itself, at the URL it answered at.
    pub hub: Hub,
}

/// What looking for hubs on Nostr found ([`Wallet::find_hubs`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct HubsFound {
    /// Those answering, not used yet.
    pub hubs: Vec<FoundHub>,
    /// How many others were announced that answered at none of their URLs:
    /// down, refusing the route, or reached only through Tor.
    pub silent: u32,
    /// How many of those are onion services only, reached through Tor only.
    pub silent_onion: u32,
}

/// The relays to look for hubs and swap providers on besides those the
/// hubs used name: relays that serve readers over Tor, the onion services
/// among them only if `tor`. None on regtest, whose services are local.
#[uniffi::export]
pub fn default_relays(network: Network, tor: bool) -> Vec<String> {
    licash_nostr::default_relays(network.profile().name(), tor)
}

/// What the wallet holds, in sat.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct Balance {
    /// In notes, to pay with.
    pub notes: u64,
    /// In notes under way: change of a payment not finished.
    pub notes_pending: u64,
    /// Paid on Bitcoin, confirmed, to move to notes but `kept`.
    pub onchain: u64,
    /// Paid on Bitcoin and being moved to notes.
    pub moving: u64,
    /// Of `onchain`, what the wallet's own payouts paid it, and the change
    /// of its contracts' funding: cashed out to the wallet, and not moved
    /// back to notes unless asked.
    pub kept: u64,
    /// On Bitcoin, in the funding of contracts being opened: what comes
    /// back to the wallet once it confirms, their price paid.
    pub opening: u64,
    /// Of `notes`, what contracts protect: what their recoveries would
    /// claim now, each up to its cap. The rest, and `notes_pending`, is on
    /// credit.
    pub covered: u64,
}

/// A recovery contract with a hub, as the wallet keeps it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Contract {
    /// Its id, in hex.
    pub id: String,
    pub hub: String,
    pub state: ContractState,
    /// Under the mock authority, for regtest only: it protects nothing.
    pub mock: bool,
    /// The most of the notes at its hub it protects, in sat.
    pub cap: u64,
    /// Of the notes at its hub now, what it protects, in sat: what its
    /// recovery would claim, up to its cap, sharing them with the live
    /// contracts there (those whose deadlines come first served first on
    /// a tie); none of one under recovery, or of a holder program this
    /// app does not trust. Together, [`Balance::covered`] at its hub.
    pub covers: u64,
    /// What opening it cost, in sat, from the coin it was paid from.
    pub price: u64,
    /// What she funded of it herself, in sat, paid from that coin beside
    /// the price: issued her as notes at its hub once its funding is
    /// buried, or claimed by its recovery.
    pub funded: u64,
    /// Whether her wallet holds the notes of what she funded.
    pub funded_received: bool,
    /// That coin's value, in sat: the rest came back as change.
    pub paid_from: u64,
    /// The block from which it protects nothing: the last a recovery
    /// can start by.
    pub protects_until: u32,
    /// The block from which its collateral returns to the hub: closed.
    pub closes_at: u32,
    /// The transaction funding it, once known, its id in hex.
    pub funding: Option<String>,
    /// When it was asked for, in seconds since the Unix epoch.
    pub created_at: i64,
    /// While [`ContractState::Opening`] or [`ContractState::Confirming`]:
    /// what it waits on now.
    pub step: Option<OpeningStep>,
    /// While [`ContractState::Opening`], what it sent to and got from its
    /// hub so far, if this run of the app drove it.
    pub transfer: Option<Transfer>,
}

/// What an opening sent to and got from its hub so far: `bytes` in
/// `seconds`, of about `expected` in all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Transfer {
    pub bytes: u64,
    pub seconds: u64,
    pub expected: u64,
}

/// What a contract being opened waits on now, in order: each step done
/// as the wallet last saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OpeningStep {
    /// The hub's terms, for the wallet's open.
    Terms,
    /// The wallet preparing the contract on those terms, garbling the
    /// instances it commits to: minutes on a phone, `seconds` so far.
    Preparing { seconds: u64 },
    /// The hub's choice of the instances the wallet garbled it keeps.
    Choosing,
    /// Those instances, sent to the hub, then the contract's transactions
    /// built.
    Uploading,
    /// The hub's signatures of those transactions.
    Signatures,
    /// The wallet's signature of the funding.
    Signing,
    /// The funding, broadcast, buried deep enough: `confirmations` so
    /// far, 0 while in no block the wallet has seen.
    Confirming { confirmations: u32 },
}

/// How far a payout has come, step by step, as the wallet last saw it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PayoutSteps {
    /// The wallet's notes locked for the provider at the hub: none before.
    pub lock: Option<LockStep>,
    /// The block from which the hub gives the locked notes back unpaid.
    pub lock_expiry: Option<u32>,
    /// The block from which the provider may take its coin back.
    pub timeout: Option<u32>,
    /// The last block the wallet claims the provider's coin at: past it,
    /// the payout fails and the notes come back once the lock expires.
    pub claim_by: Option<u32>,
    /// The provider's coin on Bitcoin, as found or as the provider told
    /// of it, maybe not confirmed yet; its block once in one.
    pub coin: Option<String>,
    pub coin_height: Option<u32>,
    /// The wallet's claim of the coin, paying the address, once made; its
    /// block once in one.
    pub claim: Option<String>,
    pub claim_height: Option<u32>,
    /// The confirmations awaited: of the coin before it is claimed, of the
    /// claim before the payout is done.
    pub depth: u32,
    /// The chain's height as the wallet last saw it: 0 if never.
    pub tip: u32,
}

/// Where the notes a payout locked stand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LockStep {
    /// Asked of the hub, not certified yet.
    Requested,
    /// Certified: the provider is paid once the wallet claims its coin.
    Locked,
    /// Paid to the provider.
    Paid,
    /// Given back to the wallet, unpaid.
    Refunded,
    /// Never made: the notes stayed the wallet's.
    Abandoned,
}

/// Where a contract stands.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ContractState {
    /// Being opened with its hub.
    Opening,
    /// Signed and broadcast, its funding not confirmed yet.
    Confirming,
    /// Protecting the notes at its hub, up to its cap.
    Protecting,
    /// Past [`Contract::protects_until`]: protecting nothing, its
    /// collateral back to its hub at its close.
    Ending,
    /// Closed: its collateral back to its hub.
    Closed,
    /// Never opened, so nothing paid: `reason`.
    Failed { reason: String },
}

/// Signed financial layout and technical details, fetched on request.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ContractInspection {
    pub address: String,
    pub locked: u64,
    pub payout_pool: u64,
    pub holder_reserve: u64,
    pub hub_reserve: u64,
    pub claim_limit: u32,
    pub note_limit: u32,
    pub denominations: Vec<u64>,
    pub keyset: String,
    pub graph_version: u32,
    /// The image id of the program the hub proves its answers with.
    pub program: String,
}

/// What opening a contract at a hub costs now, and what pays it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ContractQuote {
    pub hub: String,
    /// In sat, from one coin of the wallet's on Bitcoin.
    pub price: u64,
    /// The most of the notes at the hub it protects, in sat.
    pub cap: u64,
    /// Blocks from now to its close.
    pub blocks: u32,
    /// Blocks from now it protects for: until its last block to recover in.
    pub protects_for: u32,
    /// Under the mock authority, for regtest only: it protects nothing.
    pub mock: bool,
    /// The value of the coin that would pay it, if one does: the rest
    /// comes back as change.
    pub coin: Option<u64>,
    /// What opening it uploads to the hub, in bytes, about: the instances
    /// the hub keeps. Nothing of it is kept on the phone.
    pub download: u64,
    /// The caps and durations the wallet may choose instead, if the hub
    /// lets it ([`Wallet::open_chosen_contract`]).
    pub range: Option<ContractRange>,
    /// Blocks before its close that a contract stops protecting: it
    /// protects for its blocks less these.
    pub after_assert: u32,
    /// The coins on Bitcoin free to pay for one, the largest first.
    pub coins: Vec<DepositCoin>,
    /// What a contract chosen is at first, within the range: half again
    /// the largest coin, for its value moved into Licash and as much
    /// again to receive, over half a year. The fixed terms without one.
    pub suggested_cap: u64,
    pub suggested_blocks: u32,
    /// The least an output of its funding holds: change less than this
    /// goes to its fee.
    pub dust: u64,
    /// What she may fund of one herself is made of: its hub's
    /// denominations, `funded_notes` of them at most
    /// ([`contract_fundable`]).
    pub denominations: Vec<u64>,
    pub funded_notes: u32,
}

/// A coin of the wallet's on Bitcoin.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DepositCoin {
    /// As `txid:vout`.
    pub outpoint: String,
    pub value: u64,
}

/// What the wallet holds at one hub it trusts, in sat.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Holding {
    pub hub: String,
    /// To pay with.
    pub available: u64,
    /// Held by payments under way.
    pub pending: u64,
}

/// How many notes of one denomination the wallet can pay with at a hub.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Notes {
    pub hub: String,
    pub denomination: u64,
    pub count: u64,
}

/// A Lightning invoice to pay from notes at `hub`: `amount` it asks, and
/// `fee`, all paying it costs on top, with the notes held now. Paid by
/// `provider` for a lock of notes at `hub`: hubs pay no invoices.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct InvoiceQuote {
    pub hub: String,
    pub amount: u64,
    pub fee: u64,
    pub description: Option<String>,
    pub provider: ViaProvider,
}

/// The wallet's static address of donations ([`crate::Wallet::
/// donation_address`]): an LNURL any Lightning wallet pays, through a swap
/// provider that pays each donation in notes, less its fee.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DonationAddress {
    /// The LNURL, upper case, as a QR code holds it best.
    pub lnurl: String,
    /// The same address as a Lightning Address, `name@domain`, to write
    /// or copy: once registered at the provider and resolved there
    /// ([`crate::Wallet::keep_donation_address`]), else none.
    #[uniffi(default = None)]
    pub address: Option<String>,
    /// The provider's URL, and the name it announced, if any.
    pub provider: String,
    pub name: Option<String>,
    /// Its fee on each donation: `base` plus `ppm` millionths of it.
    pub fee_base: u64,
    pub fee_ppm: u64,
    /// The least and the most donated at once, in satoshis.
    pub min: u64,
    pub max: u64,
    /// Whether it holds enough to take a donation now: if not, payers are
    /// refused until it does.
    pub stocked: bool,
    /// Whether it answered now: if not, it is shown as last kept, and
    /// payers may be refused until it answers again.
    pub reachable: bool,
}

/// A swap provider paying a Lightning invoice from its own node for a lock
/// of notes ([`InvoiceQuote`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ViaProvider {
    /// Its URL, and the name it announced, if any.
    pub url: String,
    pub name: Option<String>,
    /// The parts of the quote's fee: the provider's, routing included,
    /// and the hub's on the lock, which [`crate::Wallet::pay_invoice_via`]
    /// pays at most, the first alone and both together.
    pub fee: u64,
    pub lock_fee: u64,
    /// Blocks until a failed payment's notes return, as its lock expires.
    pub refund_blocks: u32,
}

/// Notes paid out to `address`, on Bitcoin, through a swap provider: what
/// the address gets, `amount`, from notes at `hub`, and `fee`, all it costs
/// on top: the miners of the claim of the provider's coin, the provider's
/// fee, its coin's miners in it, and the hub's ([`Wallet::payout_quote`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PayoutQuote {
    pub address: String,
    pub amount: u64,
    pub fee: u64,
    /// The parts of `fee`, as quoted: the provider's (its coin's miners
    /// in it), the claim's miners and the hub's on the wallet's lock.
    pub provider_fee: u64,
    pub claim_fee: u64,
    pub lock_fee: u64,
    pub hub: String,
    /// The provider, by its URL, and the name it announced, if any.
    pub provider: String,
    pub provider_name: Option<String>,
    /// The blocks confirming the provider's coin before the wallet claims
    /// it: the claim reaches the address after.
    pub depth: u32,
}

/// What moving notes from one of the wallet's hubs to another costs
/// through `provider` ([`Wallet::move_offers`]): `amount` reaching `to`,
/// and `fee` on top, the provider's and `lock_fee`, the hub's at `from`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MoveQuote {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub lock_fee: u64,
    /// Blocks past the usual the notes stay locked at `from` should the
    /// provider never lock to the wallet at `to`.
    pub margin: u32,
    /// The provider, by its URL, and the name it announced, if any.
    pub provider: String,
    pub provider_name: Option<String>,
}

/// How a payment code is paid in notes ([`Wallet::pay_quote`]): `amount`
/// at `hub`, with `fee`, all it costs on top: the hub's, and on a swap
/// bringing notes there first, `swapped` from `swap_from`, the provider's
/// and the lock's.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PayQuote {
    pub hub: String,
    pub amount: u64,
    pub fee: u64,
    pub swap_from: Option<String>,
    pub swapped: u64,
    /// Whether the wallet trusts `hub`, else only visited it, the payee's
    /// hub proving it is the one their code names: what the swap brings
    /// past the payment stays there, apart ([`Wallet::visited`]).
    pub trusted: bool,
}

/// A way of paying a payment code ([`Wallet::pay_offers`]): through the
/// swap provider at `provider`, if a swap brings what the wallet lacks at
/// the payee's hub first.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PayOffer {
    pub provider: Option<String>,
    /// The name it announced itself under, if any.
    pub provider_name: Option<String>,
    /// Whether the wallet swapped through it before.
    pub known: bool,
    pub quote: PayQuote,
}

/// A payment code to show: `text` to share, `qr` to draw, `address`, the
/// plain address on Bitcoin in it, for payers that take no codes, and
/// `silent`, its silent payment address, if a hub trusted finds payments
/// to it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Code {
    pub text: String,
    pub qr: String,
    pub address: Option<String>,
    pub silent: Option<String>,
}

/// What a text scanned or pasted is.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Scanned {
    /// A payment code: to pay, `amount` if it says.
    Code {
        amount: Option<u64>,
        /// Whether it names a hub the wallet trusts, to pay in notes.
        notes: bool,
    },
    /// A payment code naming no hub the wallet trusts that says where to
    /// reach its hubs: to pay in notes at one, visited, proving it is the
    /// one named, if the owner agrees ([`Wallet::pay_quote`]); `amount` if
    /// it says.
    Visit { amount: Option<u64> },
    /// An address on Bitcoin, a silent payment address, or a `bitcoin:`
    /// code naming either (the silent payment address first, as
    /// `address`): to pay out to from notes, through a swap provider
    /// ([`Wallet::payout_quote`]), `amount` if it says.
    Bitcoin {
        address: String,
        amount: Option<u64>,
    },
    /// A payment handed over, to [`Wallet::receive`].
    Payment,
    /// A Lightning invoice, to pay through a hub: what it asks.
    Invoice {
        amount: u64,
        description: Option<String>,
    },
    /// An LNURL-pay code or a Lightning Address, naming `payee`: what it
    /// takes asked of its service ([`Wallet::lnurl_pay`]), then an invoice
    /// of the amount chosen ([`Wallet::lnurl_invoice`]), paid as any.
    Lnurl { payee: String },
}

/// What the payee of an LNURL-pay code or a Lightning Address takes, as its
/// service answered ([`Wallet::lnurl_pay`]): handed back as is to ask it for
/// an invoice ([`Wallet::lnurl_invoice`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LnurlPay {
    /// The Lightning Address, or the service's host.
    pub payee: String,
    /// The least and the most it takes, in whole sat.
    pub min: u64,
    pub max: u64,
    /// What it says is paid for, if it says.
    pub description: Option<String>,
    /// Where its invoices are asked for, and the metadata they commit to.
    pub callback: String,
    pub metadata: String,
}

impl LnurlPay {
    fn of(pay: licash_wallet::LnurlPayRequest) -> Self {
        LnurlPay {
            min: pay.min_sat(),
            max: pay.max_sat(),
            payee: pay.payee,
            description: pay.description,
            callback: pay.callback,
            metadata: pay.metadata,
        }
    }

    fn request(&self) -> licash_wallet::LnurlPayRequest {
        licash_wallet::LnurlPayRequest {
            callback: self.callback.clone(),
            min_msat: self.min * 1000,
            max_msat: self.max * 1000,
            metadata: self.metadata.clone(),
            description: self.description.clone(),
            payee: self.payee.clone(),
        }
    }
}

/// A Lightning invoice the wallet asked a hub for, to be paid with
/// ([`Wallet::ask_invoice`]), and where it stands.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LightningInvoice {
    /// Its payment hash, in hex: to follow it by.
    pub hash: String,
    pub hub: String,
    /// What it pays the wallet, in notes.
    pub amount: u64,
    /// The BOLT11 invoice to hand the payer, once its hub made it, and
    /// what it asks of them: `amount` and the hub's fee.
    pub request: Option<String>,
    pub asks: Option<u64>,
    /// Done once its notes are taken.
    pub state: State,
    /// Why it was canceled, or why it waits on its hub, if it does.
    pub reason: Option<String>,
}

/// The notes one line of the history spent, and those it made the
/// wallet's ([`Wallet::notes_of`]), the largest first, and whom those spent
/// paid.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct NotesOf {
    pub spent: Vec<NoteLine>,
    pub made: Vec<NoteLine>,
    /// What those spent pay, part by part: its payee, its hub's fee, and
    /// what the wallet keeps, the notes kept among `made` once made.
    pub paid: Vec<NotesPaid>,
}

/// Part of what the notes a line of the history spent pay.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NotesPaid {
    pub to: PaidTo,
    pub hub: String,
    pub amount: u64,
    /// The amounts of the notes made for it, the largest first.
    pub notes: Vec<u64>,
}

/// Whom a part of a payment pays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PaidTo {
    /// Its payee: a person, a provider, or the hub paying an invoice.
    Payee,
    /// The wallet itself, as payee: notes of the amounts it needs.
    Itself,
    /// Its hub, as its fee.
    Hub,
    /// The wallet, as its change or what a refund returned.
    Kept,
}

/// A note the wallet holds or held.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NoteLine {
    /// Its identifier at its hub, in hex: the same once unlinked.
    pub id: String,
    pub hub: String,
    pub amount: u64,
    /// The payment, lock or receipt that made it, in hex.
    pub made_by: String,
    /// Made by a payment of the wallet to itself, for notes of the
    /// amounts it needed: not a line of the history.
    pub made_by_itself: bool,
    /// The payment or lock that spends it, in hex, if any.
    pub spent_by: Option<String>,
    pub linking: Linking,
    /// Spent by a copy of the wallet, as its hub showed: never here.
    pub gone: bool,
    /// When the wallet got it, in seconds since the Unix epoch.
    pub added_at: i64,
}

/// Whether a note's hub can tell which payment it came from when it is
/// spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Linking {
    /// As issued: its hub can tell. The wallet unlinks it next time.
    Linked,
    /// Signed again blindly by its hub: it cannot tell.
    Unlinked,
    /// Its hub refused to unlink it: it stays linked.
    StaysLinked,
}

/// A payment made.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Paid {
    pub id: String,
    pub amount: u64,
    pub hub: String,
    /// Kept at its hub for the payee to collect there: not yet collected.
    pub kept: bool,
    /// Sent to the payee's mailbox.
    pub delivered: bool,
    /// Else the payment, for the payee to receive by hand.
    pub handover: Option<String>,
    /// Why it was not delivered.
    pub undelivered: Option<String>,
}

/// One line of the wallet's history.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Activity {
    pub id: String,
    pub kind: Kind,
    pub state: State,
    /// In sat, fees aside.
    pub amount: u64,
    pub fee: u64,
    /// The hub, or why it failed.
    pub detail: String,
    /// When, in seconds since 1970, if known.
    pub at: Option<i64>,
    /// What it says it was for: the memo of an invoice paid or asked for,
    /// or the note of a payment made or taken.
    #[uniffi(default = None)]
    pub memo: Option<String>,
    /// Who paid it, as they proved to this wallet alone: their payment
    /// code, of a payment taken whose note shared it. A contact's if
    /// [`Wallet::contact_of`] finds one.
    #[uniffi(default = None)]
    pub from: Option<String>,
    /// The label of the extra code it was paid at ([`Wallet::codes`]),
    /// whence it was paid on to the wallet, its hub's fee taken.
    #[uniffi(default = None)]
    pub code: Option<String>,
}

/// An extra code of the wallet ([`Wallet::add_code`]): a code of keys of
/// its own, that no one can tell is the wallet's or another code's.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ExtraCode {
    /// Its number, from 1: the same code again, from the same seed.
    pub index: u32,
    pub label: String,
    /// When made, in seconds since 1970.
    pub created_at: i64,
    /// The code to show: none while the wallet trusts no hub.
    pub code: Option<Code>,
    /// What it was paid, in how many payments, and the fees of paying it
    /// on to the wallet.
    pub received: u64,
    pub payments: u32,
    pub fees: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Kind {
    Sent,
    Received,
    /// Bitcoin moved to notes.
    Moved,
    /// A coin paid on Bitcoin, not moved yet.
    Onchain,
    /// A Lightning invoice paid through a hub.
    Lightning,
    /// Paid over Lightning: an invoice the wallet asked a hub for.
    Invoice,
    /// Notes paid out to an address on Bitcoin, through a swap provider.
    Payout,
    /// A recovery contract opened at a hub: its price, paid on Bitcoin
    /// from a coin of the wallet's, the rest back to it.
    Contract,
    /// Notes moved from one of the wallet's hubs to another, through a
    /// swap provider: `amount` reaching the other hub, `fee` on top.
    Swap,
    /// Notes rearranged at a hub: no amount paid away, only a fee.
    Optimized,
    /// Her part of the coin a recovery contract took, issued to her as
    /// notes at its hub once its funding confirmed: a receipt, by its id.
    Funded,
    /// What a recovery contract gave back on Bitcoin as it closed (its
    /// reserve, and any notes it recovered): a coin of the wallet's, by
    /// its outpoint as [`Kind::Onchain`], its `detail` the contract's hub.
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum State {
    Done,
    Pending,
    Failed,
}

/// More of one line of the history ([`Wallet::details`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Details {
    /// A payment in notes, at `hub`.
    Notes { hub: String },
    /// Bitcoin moved to notes: a deposit for notes at `hub`, by its
    /// `hash`, taken by the swap `provider`, at its URL, or by the hub
    /// itself (as before hubs left that to providers).
    Moved {
        hub: String,
        hash: String,
        provider: Option<String>,
        /// What to pay on Bitcoin, the fee of whoever took it in it, and
        /// where, once answered.
        pays: Option<u64>,
        address: Option<String>,
        /// The payment, once made or seen.
        payment: Option<Onchain>,
        /// The confirmations the hub waits for, as it says now: unknown of
        /// a provider's.
        depth: Option<u32>,
        /// The block its payment must confirm by, and the one after which
        /// a payment whose notes were never claimed is the wallet's again.
        fund_by: Option<u32>,
        timeout: Option<u32>,
        /// The transaction taking it back, if one did.
        refund: Option<String>,
    },
    /// A Lightning invoice paid through `hub`: the `preimage` its payment
    /// bought once paid, or why it was not. Paid by `hub`'s gateway, or by
    /// the swap `provider`, at its URL, for a lock of notes at `hub` that
    /// expires at block `expiry`: a payment it failed returns its notes
    /// only then, `refund_blocks` from the hub's tip while under way.
    Lightning {
        hub: String,
        invoice: String,
        preimage: Option<String>,
        failure: Option<String>,
        provider: Option<String>,
        expiry: Option<u32>,
        refund_blocks: Option<u32>,
    },
    /// Paid over Lightning, through `hub`: its `invoice`, once the hub
    /// made it, and what it `asks` of the payer, the hub's fee on top; why
    /// it was canceled, if it was.
    Invoice {
        hub: String,
        invoice: Option<String>,
        asks: Option<u64>,
        failure: Option<String>,
    },
    /// Notes moved from hub `from` to hub `to` through `provider`: the
    /// wallet's lock at `from` once made, the provider's at `to` once made;
    /// why it failed, if it did, the notes locked back once the lock
    /// expires.
    /// Its fee's parts as recorded: the provider's, and the hub's on the
    /// lock, 0 until the lock is made. The block the wallet's lock expires
    /// at, once made: should the move fail, its notes come back then.
    Swap {
        from: String,
        to: String,
        provider: String,
        lock: Option<String>,
        theirs: Option<String>,
        failure: Option<String>,
        provider_fee: u64,
        lock_fee: u64,
        expiry: Option<u32>,
    },
    /// Notes at `hub` paid out to `address`, on Bitcoin, through
    /// `provider`: the transaction of its coin, once the wallet found it,
    /// and of the wallet's claim paying the address, once made; why it
    /// failed, if it did, its notes back once the lock expires. `progress`
    /// tells each step. Its fee's parts as recorded: the provider's (its
    /// coin's miners in it), the claim's miners, and the hub's on the lock,
    /// 0 until the lock is made.
    Payout {
        hub: String,
        provider: String,
        address: String,
        coin: Option<String>,
        claim: Option<String>,
        failure: Option<String>,
        progress: PayoutSteps,
        provider_fee: u64,
        claim_fee: u64,
        lock_fee: u64,
    },
    /// A recovery contract opened at `hub`, by its `funding`'s id once
    /// signed: none while it is being opened, or if given up before.
    Contract {
        hub: String,
        funding: Option<String>,
    },
    /// A coin on Bitcoin, output `vout` of `tx`: `change` of the wallet's
    /// own, and `moving`, the transaction spending it, if one is.
    Coin {
        tx: Onchain,
        vout: u32,
        change: bool,
        moving: Option<String>,
    },
}

/// A transaction on Bitcoin, as far as the wallet looked.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Onchain {
    pub txid: String,
    /// Paid to its miners, if the wallet knows.
    pub fee: Option<u64>,
    /// The block it is in, if in one.
    pub height: Option<u32>,
    /// How many blocks confirm it: 0 while in none.
    pub confirmations: u32,
}

/// The block explorer of `network`, to show a transaction at
/// `{explorer}/tx/{txid}`: none for regtest.
#[uniffi::export]
pub fn explorer(network: Network) -> Option<String> {
    match network {
        Network::Bitcoin => Some("https://mempool.space".into()),
        Network::Signet => Some("https://mempool.space/signet".into()),
        Network::Mutinynet => Some("https://mutinynet.com".into()),
        Network::Regtest => None,
    }
}

/// How far the app's Tor client is in connecting to the Tor network.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TorStatus {
    /// Of the way, 0 to 100.
    pub percent: u8,
    /// Whether it can carry what the wallet sends.
    pub ready: bool,
    /// What it is doing.
    pub summary: String,
    /// Why it seems stuck, if it does.
    pub blocked: Option<String>,
}

/// How far looking for payments on Bitcoin got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Scan {
    /// The wallet's first block, where looking started: 0 if unknown.
    pub from: u32,
    /// The next block to look in.
    pub next: u32,
    /// The chain's height, as far as it could look: behind the light
    /// client's while the hubs' tweaks are.
    pub height: u32,
    /// Whether a hub's tweaks were used: without, only the fallback
    /// addresses and the coins held are looked for.
    pub tweaks: bool,
    /// The coins found, and their worth.
    pub found: u32,
    pub found_value: u64,
}
