//! A holder's hub-proves exit. The filing and request are pinned before
//! one-time signing; each transaction is durable before broadcast. The
//! holder verifies the hub's proof, but never computes a recovery proof.
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use bitcoin::{
    Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use licash::claim::{self, Branch, Item, Source, UnsignedClaim};
use licash::recovery::{Filing, Format, Publication, Witness as FilingWitness};
use licash::request::Request;
use licash::spend::ChainProfile;
use licash_contract::graph::{self, link_args, HubProves, PURSE_VOUT};
use licash_contract::{
    dispute::{self, presign, Payout},
    keys::HolderKeys,
    opening::{Context, Holder, Opening},
};
use licash_onchain::deadline;
use licash_wallet::{
    first_spend, ClaimNote, ClaimSlot, FundedNote, LockClaim, PayoutState, Transport, Wallet,
};
use lichen_contract::Role;
use serde::{Deserialize, Serialize};

use super::activation;
use super::claims::{self, ClaimTerms};
use super::store::{RecoveryRow, Store};
use super::{Chain, Fate};

/// The format of a recovery's stored state.
const FORMAT: i64 = 2;
const TIMEOUT_FEE_MARGIN: u64 = 2;
const OVERLAP: u32 = 3;
const DUST: Amount = Amount::from_sat(330);
/// About a challenge's virtual size, its revealed secrets among it (20,717
/// vB measured), and its fee child's.
const CHALLENGE_VB: u64 = 21_000;

/// The coin of hers to set aside, at the forced close of a contract, for
/// a challenge's fee child should the hub's assertion be false: for twice
/// the challenge's fee at `rate`, her rate, the rate rising meanwhile.
pub fn challenge_reserve(rate: FeeRate) -> Amount {
    rate.fee_vb(CHALLENGE_VB * 2).unwrap_or(Amount::MAX)
}

/// The txid of no transaction her coin for the challenge of contract `id`
/// is set aside under ([`Wallet::reserve_silent`]), until its fee child
/// takes it or no challenge is left to make: a coin of hers spending
/// nothing else under it is that coin, set aside.
pub fn challenge_marker(id: &[u8; 32]) -> Txid {
    use bitcoin::hashes::{sha256, Hash};
    let hash = sha256::Hash::hash(&[b"licash/challenge-coin/".as_slice(), id].concat());
    Txid::from_byte_array(hash.to_byte_array())
}

/// Whether her coins hold one to set aside for a challenge at `rate`
/// ([`challenge_reserve`]): the least it must hold if not, for her to be
/// told before she forces a close.
pub fn challenge_shortfall<T: Transport>(
    wallet: &Wallet<T>,
    wallet_file: &std::path::Path,
    rate: FeeRate,
) -> Result<Option<Amount>> {
    let need = challenge_reserve(rate);
    let coins = super::coins(wallet, wallet_file)?;
    // Her publication may need one of her coins too, the smallest that
    // pays its fee: one besides it.
    let enough = coins.iter().filter(|c| c.value >= need.to_sat()).count();
    let held = enough >= 2 || (enough == 1 && coins.len() >= 2);
    Ok((!held).then_some(need))
}

/// Blocks before the request's deadline her request is no longer held
/// back for her fee payout ([`FeeNeed`]): its coin late, her coins pay as
/// they can.
const FEE_WAIT_MARGIN: u32 = 6;

/// Blocks a payout of her notes takes at most, as asked for her fees: its
/// provider's coin confirmed, and her claim of it.
fn payout_blocks(profile: ChainProfile) -> u32 {
    match profile {
        ChainProfile::Core30DefaultRegtest | ChainProfile::Core30Signet => 6,
        _ => 12,
    }
}

/// What a fee payout is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeFor {
    /// Her publication of her claim, should her purse and any one coin of
    /// hers pay too little of its fees.
    Publication,
    /// A challenge's fee child, should the hub's assertion be false and
    /// no coin of hers be set aside for it ([`challenge_reserve`]).
    Challenge,
}

/// A coin a recovery needs of hers on Bitcoin: to be paid out of her notes
/// to an address of her own, through a swap provider, worth `amount` at
/// least, in a block by `by` if that bounds it. Recorded with
/// [`expect_fee`] once asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeNeed {
    pub id: [u8; 32],
    pub purpose: FeeFor,
    pub amount: Amount,
    pub by: Option<u32>,
}

/// Her coins hold too little, alone, to pay her request's fees.
#[derive(Debug)]
struct Short {
    needed: u64,
    most: u64,
}

impl std::fmt::Display for Short {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "too little of hers on Bitcoin to pay her request's fees: \
             about {} sat needed in one coin, her largest {} sat",
            self.needed, self.most
        )
    }
}

impl std::error::Error for Short {}

/// The coins to try, in order, beside her purse to pay her publication's
/// fees, of `free`, her coins and their values: none; then each alone, the
/// coin of `paid` (her fee payout's claim) first, then the smallest first;
/// then, if `joined`, more and more of them together, the coin of `paid`
/// first, then the largest, until one adds no more than `input_fee`, its
/// input's fee.
fn fee_inputs(
    free: &[(OutPoint, u64)],
    paid: Option<Txid>,
    input_fee: u64,
    joined: bool,
) -> Vec<Vec<OutPoint>> {
    let other = |c: &(OutPoint, u64)| Some(c.0.txid) != paid;
    let mut alone = free.to_vec();
    alone.sort_by_key(|c| (other(c), c.1));
    let mut tries = vec![vec![]];
    tries.extend(alone.iter().map(|c| vec![c.0]));
    if joined {
        let mut most = free.to_vec();
        most.sort_by_key(|c| (other(c), std::cmp::Reverse(c.1)));
        let mut together = Vec::new();
        for (coin, value) in most {
            if value <= input_fee {
                break;
            }
            together.push(coin);
            if together.len() > 1 {
                tries.push(together.clone());
            }
        }
    }
    tries
}

/// Whether a challenge may still be hers to make, its coin not taken yet.
fn challenge_possible(stage: Stage, state: &State) -> bool {
    match stage {
        Stage::Published
        | Stage::Requested
        | Stage::Answered
        | Stage::Contesting
        | Stage::Contested => true,
        Stage::Asserted => state.verified != Some(true),
        Stage::Challenging => state.challenge_child.is_none(),
        _ => false,
    }
}

/// Whether her request waits on her fee payout: under way, and more than
/// a block left before the margin before the request's deadline.
fn waits_for_payout(pending: bool, tip: u32, request_height: u32) -> bool {
    pending && tip.saturating_add(1) < request_height.saturating_sub(FEE_WAIT_MARGIN)
}

fn rescan(from: u32, tip: u32) -> u32 {
    tip.saturating_add(1).saturating_sub(OVERLAP).max(from)
}

/// Whether a transaction mined at `height` is `depth` deep at `tip`, one
/// at least: a reorganization no longer expected to take it out.
fn deep(height: u32, tip: u32, depth: u32) -> bool {
    tip.saturating_add(1).saturating_sub(height) >= depth.max(1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Claiming,
    Claimed,
    Irrevocable,
    Signing,
    Published,
    Requested,
    TimingOut,
    TimedOut,
    Sweeping,
    Done,
    /// The hub responded: she checks its evidence, and leaves the response
    /// alone, paid what it says by its terminal, or contests it.
    Answered,
    Lost,
    GivingUp,
    Asserted,
    Succeeding,
    Challenging,
    Challenged,
    Paid,
    /// Closed cooperatively on her claim (`super::fold`): a fold she
    /// signed may confirm, paying it. Until then it holds the claim her
    /// forced close would file, the same.
    Folding,
    /// Her contest of the hub's response is made, and posted until it is in
    /// a block.
    Contesting,
    /// Her contest is in a block: the hub asserts its proof, or her
    /// timeout pays her claim.
    Contested,
}
impl Stage {
    const ALL: [Self; 21] = [
        Self::Claiming,
        Self::Claimed,
        Self::Irrevocable,
        Self::Signing,
        Self::Published,
        Self::Requested,
        Self::TimingOut,
        Self::TimedOut,
        Self::Sweeping,
        Self::Done,
        Self::Answered,
        Self::Lost,
        Self::GivingUp,
        Self::Asserted,
        Self::Succeeding,
        Self::Challenging,
        Self::Challenged,
        Self::Paid,
        Self::Folding,
        Self::Contesting,
        Self::Contested,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claiming => "claiming",
            Self::Claimed => "claimed",
            Self::Irrevocable => "irrevocable",
            Self::Signing => "signing",
            Self::Published => "published",
            Self::Requested => "requested",
            Self::TimingOut => "timing-out",
            Self::TimedOut => "timed-out",
            Self::Sweeping => "sweeping",
            Self::Done => "done",
            Self::Answered => "answered",
            Self::Lost => "lost",
            Self::GivingUp => "giving-up",
            Self::Asserted => "asserted",
            Self::Succeeding => "succeeding",
            Self::Challenging => "challenging",
            Self::Challenged => "challenged",
            Self::Paid => "paid",
            Self::Folding => "folding",
            Self::Contesting => "contesting",
            Self::Contested => "contested",
        }
    }
    fn parse(text: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|s| s.as_str() == text)
            .with_context(|| format!("a recovery at stage {text}, unknown"))
    }
    pub fn over(self) -> bool {
        matches!(self, Self::Done | Self::Lost)
    }
    pub fn disputed(self) -> bool {
        matches!(
            self,
            Self::Answered
                | Self::Contesting
                | Self::Contested
                | Self::Asserted
                | Self::Succeeding
                | Self::Challenging
                | Self::Challenged
                | Self::Paid
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub id: [u8; 32],
    pub stage: Stage,
    pub irrevocable: bool,
    /// What her claim recovers, in sat (her notes' face value, the cap at
    /// most), and how many notes it holds.
    pub claimed: u64,
    /// The hub's proposed reduced principal, not an entitlement until
    /// verified. `received` is the actual confirmed sweep output.
    pub corrected: Option<u64>,
    pub received: Option<u64>,
    pub notes: usize,
    pub request: Option<Txid>,
    pub publication: Option<Txid>,
    pub requested_at: Option<u32>,
    pub timeout: Option<Txid>,
    pub timed_out_at: Option<u32>,
    pub sweep: Option<Txid>,
    pub swept_at: Option<u32>,
    pub next_at: Option<u32>,
    pub error: Option<String>,
    pub response: Option<Txid>,
    pub deadline: Option<u32>,
    /// Whether the hub's observed assertion verifies.
    pub proved: bool,
    pub assertion: Option<Txid>,
    pub asserted_at: Option<u32>,
    pub challenge: Option<Txid>,
    pub payout: Option<Txid>,
    pub paid_at: Option<u32>,
    /// The last fold she signed of her claim, and the block it confirmed
    /// in, once it did ([`Stage::Folding`]).
    pub fold: Option<Txid>,
    pub folded_at: Option<u32>,
    /// Her publication held back by the fee it may pay: more allowed
    /// with [`allow_publication_fee`] gets it on.
    pub fee_capped: bool,
}

/// What every refusal for want of a publication fee she allows names.
const ALLOW_FEE: &str = "allow-publication-fee";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct State {
    notes: Vec<String>,
    amount: u32,
    /// The whole public Filing, not just its signed claim.
    filing: Option<String>,
    #[serde(with = "consensus")]
    r: Option<Transaction>,
    #[serde(with = "consensus")]
    p: Option<Transaction>,
    /// Under a leaf carrier, her commitment to the filing
    /// ([`licash_contract::opening::Opening::commitment`]), spending her
    /// purse: made once, kept with P before either is posted, and spent by
    /// P's every version. None of a nulldata carrier's, or of a state an
    /// older release kept: its P carries the filing in nulldata.
    #[serde(with = "consensus", skip_serializing_if = "Option::is_none")]
    c: Option<Transaction>,
    #[serde(with = "consensus_all")]
    prevouts: Vec<TxOut>,
    f_height: Option<u32>,
    r_height: Option<u32>,
    p_height: Option<u32>,
    /// Her claim's slot taken by the hub's reclaim, P never published:
    /// her terminals' fee coin is her purse, and `success` the hub's to
    /// post.
    reclaimed: bool,
    #[serde(with = "consensus")]
    response: Option<Transaction>,
    response_height: Option<u32>,
    reduced: Option<u32>,
    deadline: Option<u32>,
    /// What her check of the hub's response came to: it bore out her
    /// claim's reduction (true), or she contests it (false). None while she
    /// cannot tell.
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<bool>,
    /// Her contest of the response, made once and posted as it was, and
    /// the block it is in.
    #[serde(with = "consensus", skip_serializing_if = "Option::is_none")]
    contest: Option<Transaction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contest_height: Option<u32>,
    #[serde(with = "consensus")]
    assertion: Option<Transaction>,
    assertion_height: Option<u32>,
    verified: Option<bool>,
    #[serde(with = "consensus")]
    challenge: Option<Transaction>,
    challenge_height: Option<u32>,
    /// The challenge's fee child, the last made, its inputs of her wallet
    /// with a placeholder signature: signed again at each broadcast,
    /// which sets its coins aside again.
    #[serde(with = "consensus", skip_serializing_if = "Option::is_none")]
    challenge_child: Option<Transaction>,
    #[serde(with = "consensus")]
    payout: Option<Transaction>,
    payout_name: Option<String>,
    payout_height: Option<u32>,
    #[serde(with = "consensus")]
    sweep: Option<Transaction>,
    swept_height: Option<u32>,
    from: Option<u32>,
    next_at: Option<u32>,
    /// What her publication may pay in fees in all, set by her
    /// ([`allow_publication_fee`]): absent, what its reserve hands it.
    #[serde(skip_serializing_if = "Option::is_none")]
    p_allowance: Option<u64>,
    /// The folds she signed of her claim, each by its txid in hex: every
    /// one pays her the claim and her reserve, and any may confirm, even
    /// after she forced the close on the same claim. None for a recovery
    /// that was never a fold: written only by one that was.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    folds: Vec<String>,
    /// The last fold the hub signed, broadcast again until it is deep.
    #[serde(with = "consensus", skip_serializing_if = "Option::is_none")]
    fold: Option<Transaction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fold_height: Option<u32>,
    /// Her payout of notes, by its hash, to a coin of hers paying her
    /// publication's fees ([`expect_fee`]): waited for while under way and
    /// time is left, its coin tried first. None of an older state.
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_payout: Option<String>,
    /// Her payout of notes to a coin of hers for a challenge's fee.
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_payout: Option<String>,
}
impl State {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("recovery state")
    }
    fn decode(row: &RecoveryRow) -> Result<Self> {
        ensure!(
            row.format == FORMAT,
            "unsupported recovery format {}",
            row.format
        );
        Stage::parse(&row.stage)?;
        let state: Self = serde_json::from_slice(&row.state)?;
        ensure!(
            state.payout.is_some() == state.payout_name.is_some(),
            "payout provenance missing"
        );
        Ok(state)
    }
}
mod consensus {
    use bitcoin::consensus::{
        encode::{deserialize_hex, serialize_hex},
        Decodable, Encodable,
    };
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<T: Encodable, S: Serializer>(v: &Option<T>, s: S) -> Result<S::Ok, S::Error> {
        v.as_ref().map(serialize_hex).serialize(s)
    }
    pub fn deserialize<'de, T: Decodable, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<T>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|h| deserialize_hex(&h).map_err(D::Error::custom))
            .transpose()
    }
}
mod consensus_all {
    use bitcoin::consensus::{
        encode::{deserialize_hex, serialize_hex},
        Decodable, Encodable,
    };
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<T: Encodable, S: Serializer>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
        v.iter().map(serialize_hex).collect::<Vec<_>>().serialize(s)
    }
    pub fn deserialize<'de, T: Decodable, D: Deserializer<'de>>(d: D) -> Result<Vec<T>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|h| deserialize_hex(h).map_err(D::Error::custom))
            .collect()
    }
}

/// What a dishonest holder files instead of the bytes of her claim's
/// filing ([`forge_filings`]).
#[cfg(feature = "faults")]
pub type Forge = Box<dyn Fn(&Filing, Vec<u8>) -> Vec<u8> + Send + Sync>;

#[cfg(feature = "faults")]
static FORGE: std::sync::RwLock<Option<Forge>> = std::sync::RwLock::new(None);

/// Publish, of every claim filed from now on in this process, what `forge`
/// makes of its filing's bytes, as a dishonest holder would to have her
/// hub read her claim wrong; with none, the bytes again. Her claim's
/// digest and amount stay those of the filing: for tests of the hub's
/// answer to bytes no wallet of this code files.
#[cfg(feature = "faults")]
pub fn forge_filings(forge: Option<Forge>) {
    *FORGE.write().unwrap_or_else(|e| e.into_inner()) = forge;
}

#[cfg(feature = "faults")]
static DOUBT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Take, if `doubt`, every assertion seen from now on in this process for
/// one that does not verify, as a holder who challenges whatever the hub
/// proves would: for tests of the hub's answer to a wrong challenge.
#[cfg(feature = "faults")]
pub fn doubt_assertions(doubt: bool) {
    DOUBT.store(doubt, std::sync::atomic::Ordering::SeqCst);
}

/// Whether the statement of the contract of `base` would owe the claim
/// filed as `filed` under `request` whole, should the hub show nothing
/// against it: its own judgment ([`licash::recovery::owed`]), on the
/// chain from her Base's checkpoint through `tip`, of which it is shown
/// the blocks it reads. If not, why.
///
/// Made before she publishes anything, as a claim its statement finds
/// wrong is owed nothing, whatever her notes are worth, and one it values
/// less retires what it does not pay. What a later block of her
/// publication's adds to the chain only buries an activation deeper and a
/// refund's expiry further, so a claim owed whole at `tip` is from then
/// on. An error is the chain's: to try again.
async fn owed_whole<C: Chain>(
    chain: &C,
    base: &licash::base::Base,
    request: &Request,
    filed: &[u8],
    tip: u32,
) -> Result<std::result::Result<(), String>> {
    let checkpoint = &base.parts().chain.checkpoint;
    let mut shown = std::collections::BTreeMap::new();
    loop {
        let read = licash::chain::Chain::sparse(checkpoint.clone(), tip, shown.clone())?;
        let owed = licash::recovery::owed(base, request, filed, &[], &read);
        let unshown = read.unshown();
        if unshown.is_empty() {
            let owed = owed?;
            return Ok(match (&owed.ineligible, owed.owed == request.amount) {
                (Some(why), _) => Err(format!("its statement would owe her claim nothing: {why}")),
                (None, false) => Err(format!(
                    "its statement would owe her claim {} of {} sat",
                    owed.owed, request.amount
                )),
                (None, true) => Ok(()),
            });
        }
        // Each a block inside the chain it was not shown yet.
        for height in unshown {
            let header = chain.header(height).await.map_err(|e| anyhow!(e))?;
            let bytes: [u8; 80] = bitcoin::consensus::serialize(&header)
                .try_into()
                .map_err(|_| anyhow!("a header of 80 bytes"))?;
            shown.insert(height, bytes);
        }
    }
}

pub(super) fn validate_backup(store: &Store) -> Result<()> {
    for row in store.recoveries()? {
        State::decode(&row)?;
    }
    Ok(())
}

pub async fn force_close<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &std::path::Path,
    id: &[u8; 32],
    rate: FeeRate,
) -> Result<Recovery> {
    let store = Store::existing(wallet_file)?.context("no contracts")?;
    let contract = store
        .list()?
        .into_iter()
        .find(|c| &c.id == id)
        .context("no such contract")?;
    if store
        .recovery(id)?
        .is_some_and(|r| r.stage == Stage::GivingUp.as_str())
    {
        finish_giving_up(wallet, &store, id)?;
    }
    if let Some(row) = (store.recovery(id)?).filter(|r| r.stage == Stage::Folding.as_str()) {
        if row.irrevocable {
            // Closed on her claim, and not folded: the same claim, filed
            // on Bitcoin by her request. Any fold she signed may still
            // confirm first, and then pays the same.
            ensure!(
                store.save_recovery(
                    id,
                    (&row.stage, &row.state),
                    Stage::Claimed.as_str(),
                    true,
                    &row.state
                )?,
                "the recovery kept moving on: try again"
            );
        } else if store.revoke_recovery(id, Stage::GivingUp.as_str(), Some("a close not signed"))? {
            // A close that never signed its fold: nothing of hers is spent.
            finish_giving_up(wallet, &store, id)?;
        }
    }
    if store.recovery(id)?.is_none() {
        let tip = chain.height().await.map_err(|e| anyhow!(e))?;
        ensure!(
            contract.fate == Some(Fate::Live),
            "its F is not buried in the chain yet"
        );
        // Closed early too: a fold that never confirmed leaves it to
        // recover, and one that did makes the recovery give back.
        ensure!(
            tip < contract.assert_height,
            "its protection ended at block {}",
            contract.assert_height
        );
        store.start_recovery(
            id,
            FORMAT,
            Stage::Claiming.as_str(),
            &State::default().encode(),
        )?;
    }
    Run::load(wallet, chain, &store, wallet_file, id, rate)
        .await?
        .steps()
        .await?;
    view(&store.recovery(id)?.context("given up")?)
}
pub async fn advance<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &std::path::Path,
    rate: FeeRate,
) -> Result<Vec<Recovery>> {
    let Some(store) = Store::existing(wallet_file)? else {
        return Ok(vec![]);
    };
    // Before a recovery claims them: as provable as they can be.
    if let Err(e) = activation::keep(wallet, chain, wallet_file, rate).await {
        tracing::warn!("keeping the locks owed to her provable: {e:#}");
    }
    for row in store.recoveries()? {
        if Stage::parse(&row.stage).is_ok_and(Stage::over) {
            continue;
        }
        if row.stage == Stage::GivingUp.as_str() {
            if let Err(e) = finish_giving_up(wallet, &store, &row.id) {
                store.recovery_error(&row.id, Some(&format!("{e:#}")))?;
            }
            continue;
        }
        let result = match Run::load(wallet, chain, &store, wallet_file, &row.id, rate).await {
            Ok(run) => run.steps().await,
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            tracing::warn!(id = %crate::hex_id(&row.id), "recovering a contract: {e:#}");
            store.recovery_error(&row.id, Some(&format!("{e:#}")))?;
        }
    }
    list(&store)
}
/// The coins her recoveries in `wallet_file` need of hers on Bitcoin now, each to
/// be paid out of her notes to an address of her own, through a swap
/// provider, and recorded with [`expect_fee`]: for her publication, should
/// her purse and no coin of hers alone pay its fees, time left for a
/// payout; for a challenge, should no coin of hers be set aside for it.
/// None for a recovery whose payout for it is under way.
pub async fn fee_needs<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &std::path::Path,
    rate: FeeRate,
) -> Result<Vec<FeeNeed>> {
    let Some(store) = Store::existing(wallet_file)? else {
        return Ok(vec![]);
    };
    let tip = chain.height().await.map_err(|e| anyhow!(e))?;
    let mut needs = Vec::new();
    for row in store.recoveries()? {
        let Ok(stage) = Stage::parse(&row.stage) else {
            continue;
        };
        if stage.over() || stage == Stage::GivingUp {
            continue;
        }
        let state = State::decode(&row)?;
        let run = Run::load(wallet, chain, &store, wallet_file, &row.id, rate).await?;
        needs.extend(run.fee_need(stage, &state, tip)?);
    }
    Ok(needs)
}

/// Record `hash`, a payout of her notes to an address of her own, as the
/// one recovery `id` awaits for `purpose` ([`fee_needs`]).
pub fn expect_fee(
    wallet_file: &std::path::Path,
    id: &[u8; 32],
    purpose: FeeFor,
    hash: &str,
) -> Result<()> {
    let store = Store::existing(wallet_file)?.context("no contracts")?;
    // Saved only over the state read: a step meanwhile is read again.
    for _ in 0..3 {
        let row = store.recovery(id)?.context("no such recovery")?;
        let mut state = State::decode(&row)?;
        match purpose {
            FeeFor::Publication => state.fee_payout = Some(hash.to_owned()),
            FeeFor::Challenge => state.challenge_payout = Some(hash.to_owned()),
        }
        if store.save_recovery(
            id,
            (&row.stage, &row.state),
            &row.stage,
            false,
            &state.encode(),
        )? {
            return Ok(());
        }
    }
    bail!("the recovery kept changing meanwhile")
}

pub fn recoveries(wallet_file: &std::path::Path) -> Result<Vec<Recovery>> {
    match Store::existing(wallet_file)? {
        Some(store) => list(&store),
        None => Ok(vec![]),
    }
}
pub fn give_up<T: Transport>(
    wallet: &Wallet<T>,
    wallet_file: &std::path::Path,
    id: &[u8; 32],
) -> Result<()> {
    let store = Store::existing(wallet_file)?.context("no contracts")?;
    if store.recovery(id)?.is_none() {
        // Given up already, asked twice (a second tap waiting behind the
        // first, say): nothing left to give back.
        ensure!(
            store.list()?.iter().any(|c| &c.id == id),
            "no such contract"
        );
        return Ok(());
    }
    ensure!(
        store.revoke_recovery(id, Stage::GivingUp.as_str(), Some("given up"))?,
        "past giving up: her request is signed"
    );
    finish_giving_up(wallet, &store, id)
}
fn finish_giving_up<T: Transport>(wallet: &Wallet<T>, store: &Store, id: &[u8; 32]) -> Result<()> {
    wallet.unclaim_notes(id)?;
    // Nothing set aside under it, or freed already: no error.
    let _ = wallet.abandon_silent(&challenge_marker(id));
    store.drop_recovery(id)?;
    Ok(())
}
/// The claim a cooperative close folds the contract on ([`super::fold`]).
pub(super) struct FoldClaim {
    pub filing: Filing,
    pub amount: u32,
    /// The notes it names, each by its identifier.
    pub notes: Vec<licash::crypto::Point>,
    /// Taken by this close, not by one before: given back should it not
    /// go on to sign its fold ([`give_up`]).
    pub fresh: bool,
}

/// The rate her recovery's fees are planned at when it is not one of a
/// forced close: none is spent, only a challenge's coin set aside.
const FOLD_RATE: u64 = 2;

/// The block from which a fold of contract `id` not seen on Bitcoin gives
/// way to her request, filing the claim the hub took: the last height her
/// request may confirm at, less a twelfth of a day's blocks (12), for it, her
/// publication and a fee bumped. None of the room a day the exit keeps: a
/// contract on a chain of fast blocks is shorter than that.
pub(super) fn fold_by(
    seed: &[u8; 32],
    network: licash::spend::ChainProfile,
    wallet_file: &std::path::Path,
    id: &[u8; 32],
    tip: u32,
) -> Result<u32> {
    let terms = (0, super::exit::TIMEOUT_SLACK);
    let safety = super::safety::of_seed(seed, network, wallet_file, id, tip, terms)?;
    let room = super::exit::DAY / 12;
    Ok(safety.request_by.unwrap_or(0).saturating_sub(room))
}

/// Her notes at the hub of contract `id` taken, so far as it can claim
/// them, and her claim of them pinned, for its fold to pay: or the claim a
/// close pinned before, asked again. None if she holds none there. Her
/// close stays one she may give up, notes back in her balance, until
/// [`fold_signing`]; refused for a contract being forced closed.
pub(super) async fn fold_claim<T: Transport, C: Chain>(
    wallet: &Wallet<T>,
    chain: &C,
    wallet_file: &std::path::Path,
    id: &[u8; 32],
) -> Result<Option<FoldClaim>> {
    let store = Store::existing(wallet_file)?.context("no contracts")?;
    let rate = FeeRate::from_sat_per_vb(FOLD_RATE).expect("a rate");
    if let Some(row) = store.recovery(id)? {
        ensure!(
            row.stage == Stage::Folding.as_str(),
            "forced closed already: its recovery goes on"
        );
        if row.irrevocable {
            let run = Run::load(wallet, chain, &store, wallet_file, id, rate).await?;
            return run.claim_of_fold(&State::decode(&row)?).map(Some);
        }
        // A close that never signed its fold: its notes back first.
        ensure!(
            store.revoke_recovery(id, Stage::GivingUp.as_str(), Some("a close not signed"))?,
            "closing already: try again in a moment"
        );
        finish_giving_up(wallet, &store, id)?;
    }
    ensure!(
        store.start_recovery(
            id,
            FORMAT,
            Stage::Folding.as_str(),
            &State::default().encode()
        )?,
        "closing already: try again in a moment"
    );
    let run = Run::load(wallet, chain, &store, wallet_file, id, rate).await?;
    match run.take_for_fold().await {
        Ok(Some(claim)) => Ok(Some(claim)),
        Ok(None) => {
            store.drop_recovery(id)?;
            Ok(None)
        }
        Err(e) => {
            run.give_back(&format!("{e:#}"))?;
            Err(e)
        }
    }
}

/// Her fold of the claim of contract `id`, `txid`, kept before her partial
/// signature leaves: the hub may sign and broadcast it from then on, so her
/// close is past giving up, and the contract counts as closed for good.
/// Refused once the recovery was given up or moved on.
pub(super) fn fold_signing(store: &Store, id: &[u8; 32], txid: &Txid) -> Result<()> {
    let row = store.recovery(id)?.context("the close was given up")?;
    ensure!(
        row.stage == Stage::Folding.as_str(),
        "the contract's recovery moved on: {}",
        row.stage
    );
    let mut state = State::decode(&row)?;
    let hex = txid.to_string();
    if !state.folds.contains(&hex) {
        state.folds.push(hex);
    }
    ensure!(
        store.save_recovery(
            id,
            (&row.stage, &row.state),
            Stage::Folding.as_str(),
            true,
            &state.encode()
        )?,
        "the close kept moving on: try again"
    );
    store.fold(id, txid)
}

/// The fold the hub signed, kept to be broadcast again until it is deep.
/// Not an error to fail: it is looked for on the chain all the same.
pub(super) fn fold_signed(store: &Store, id: &[u8; 32], fold: &Transaction) -> Result<()> {
    let row = store.recovery(id)?.context("no recovery")?;
    if row.stage != Stage::Folding.as_str() {
        return Ok(());
    }
    let mut state = State::decode(&row)?;
    state.fold = Some(fold.clone());
    store.save_recovery(
        id,
        (&row.stage, &row.state),
        Stage::Folding.as_str(),
        true,
        &state.encode(),
    )?;
    Ok(())
}

fn list(store: &Store) -> Result<Vec<Recovery>> {
    Ok(store
        .recoveries()?
        .iter()
        .filter_map(|r| match view(r) {
            Ok(view) => Some(view),
            Err(e) => {
                tracing::warn!(id = %crate::hex_id(&r.id), "a recovery not read: {e:#}");
                None
            }
        })
        .collect())
}
fn view(row: &RecoveryRow) -> Result<Recovery> {
    let state = State::decode(row)?;
    let stage = Stage::parse(&row.stage)?;
    let txid = |tx: &Option<Transaction>| tx.as_ref().map(Transaction::compute_txid);
    let timed = state
        .payout_name
        .as_deref()
        .is_some_and(|n| matches!(n, "request_timeout" | "contest_timeout" | "failure"));
    Ok(Recovery {
        id: row.id,
        stage,
        irrevocable: row.irrevocable,
        claimed: state.amount as u64,
        corrected: state.reduced.map(u64::from),
        received: if stage == Stage::Done {
            // Her sweep's output, or of a fold, the claim and her reserve
            // as it paid them.
            Some(
                state
                    .sweep
                    .as_ref()
                    .or_else(|| state.fold_height.and(state.fold.as_ref()))
                    .and_then(|t| t.output.first())
                    .map_or(0, |o| o.value.to_sat()),
            )
        } else {
            None
        },
        notes: state.notes.len(),
        request: txid(&state.r),
        publication: txid(&state.p),
        requested_at: state.r_height,
        timeout: timed.then(|| txid(&state.payout)).flatten(),
        timed_out_at: timed.then_some(state.payout_height).flatten(),
        sweep: txid(&state.sweep),
        swept_at: state.swept_height,
        next_at: state.next_at,
        error: row.error.clone(),
        fee_capped: !stage.over() && (row.error.as_deref()).is_some_and(|e| e.contains(ALLOW_FEE)),
        response: txid(&state.response),
        deadline: state.deadline,
        proved: state.verified == Some(true),
        assertion: txid(&state.assertion),
        asserted_at: state.assertion_height,
        challenge: txid(&state.challenge),
        payout: txid(&state.payout),
        paid_at: state.payout_height,
        fold: txid(&state.fold),
        folded_at: state.fold_height,
    })
}

enum Next {
    Wait,
    Save,
    To(Stage),
}

/// A link of hers posted with a fee child ([`Run::post_link`]): her
/// challenge, or her contest.
struct Link {
    name: &'static str,
    tx: Transaction,
    /// The stage that posts it again, round after round.
    stage: Stage,
    /// The block its window opened at, and the last tip it confirms in
    /// time from.
    opened: u32,
    deadline: u32,
    /// What missing the deadline costs her: its fee at most.
    stake: Amount,
    /// Whether it takes the coin set aside for a challenge's fee.
    set_aside: bool,
}
struct Run<'a, T: Transport, C: Chain> {
    wallet: &'a Wallet<T>,
    chain: &'a C,
    store: &'a Store,
    wallet_file: &'a std::path::Path,
    id: [u8; 32],
    rate: FeeRate,
    o: Opening,
    keys: HolderKeys,
    since: u32,
    took: AtomicBool,
    rebuilt: AtomicBool,
    refused: std::sync::Mutex<Vec<String>>,
}
impl<'a, T: Transport, C: Chain> Run<'a, T, C> {
    async fn load(
        wallet: &'a Wallet<T>,
        chain: &'a C,
        store: &'a Store,
        wallet_file: &'a std::path::Path,
        id: &[u8; 32],
        rate: FeeRate,
    ) -> Result<Self> {
        let (state, since) = store.state(id)?;
        let tip = chain.height().await.map_err(|e| anyhow!(e))?;
        let secrets = wallet.contract_secrets();
        let holder = Holder::load(
            &state,
            &secrets.seed,
            &Context {
                tip,
                trust: crate::trust(wallet.network())?,
            },
        )?;
        let o = holder.signed()?;
        let keys = HolderKeys::derive(&secrets.seed, &o.base.parts().nonce);
        Ok(Self {
            wallet,
            chain,
            store,
            wallet_file,
            id: *id,
            rate,
            o,
            keys,
            since,
            took: AtomicBool::new(false),
            rebuilt: AtomicBool::new(false),
            refused: Default::default(),
        })
    }
    async fn steps(&self) -> Result<()> {
        loop {
            let row = self.store.recovery(&self.id)?.context("given up")?;
            let stage = Stage::parse(&row.stage)?;
            ensure!(stage != Stage::GivingUp, "given up");
            if stage == Stage::Folding && !row.irrevocable {
                // A close that did not sign its fold before it stopped:
                // nothing of hers is spent, and her notes come back.
                self.give_back("a close that did not finish")?;
                return Ok(());
            }
            let mut state = State::decode(&row)?;
            let tip = self.chain.height().await.map_err(|e| anyhow!(e))?;
            if let Some(stood) = self.reorganized(stage, tip).await? {
                let to = rewind(stage, &mut state, stood);
                tracing::warn!(
                    id = %crate::hex_id(&self.id), stood, from = stage.as_str(), to = to.as_str(),
                    "blocks she saw left the chain: what she saw in them found again"
                );
                if !self.store.save_recovery(
                    &self.id,
                    (stage.as_str(), &row.state),
                    to.as_str(),
                    true,
                    &state.encode(),
                )? {
                    return self.outrun();
                }
                self.store.forget_recovery_tips(&self.id, stood)?;
                continue;
            }
            self.hold_challenge_coin(stage, &state)?;
            let next = match stage {
                Stage::Claiming => self.claim(&mut state, tip).await?,
                Stage::Claimed => self.commit(&mut state, tip).await?,
                Stage::Irrevocable => self.request(&mut state)?,
                Stage::Signing => self.sign(&mut state)?,
                Stage::Published => self.publish(&mut state, tip).await?,
                Stage::Requested
                | Stage::Answered
                | Stage::Contested
                | Stage::Asserted
                | Stage::Challenging
                | Stage::Challenged => self.watch(stage, &mut state, tip).await?,
                Stage::Contesting => self.contesting(&mut state, tip).await?,
                Stage::TimingOut | Stage::Succeeding => self.finishing(&mut state, tip).await?,
                Stage::TimedOut | Stage::Paid => self.sweep(&mut state, tip)?,
                Stage::Sweeping => self.swept(&mut state, tip).await?,
                Stage::Folding => self.folding(&mut state, tip).await?,
                Stage::Done | Stage::Lost | Stage::GivingUp => Next::Wait,
            };
            let to = match next {
                Next::Wait => return self.report(),
                Next::Save => stage,
                Next::To(to) => to,
            };
            let irrevocable = !matches!(to, Stage::Claiming | Stage::Claimed);
            if !self.store.save_recovery(
                &self.id,
                (stage.as_str(), &row.state),
                to.as_str(),
                irrevocable,
                &state.encode(),
            )? {
                return self.outrun();
            }
            if to != stage {
                tracing::info!(id = %crate::hex_id(&self.id), stage = to.as_str(), "recovering a contract");
            }
            if matches!(next, Next::Save) {
                return self.report();
            }
        }
    }
    fn outrun(&self) -> Result<()> {
        if self.took.load(Ordering::SeqCst)
            && self
                .store
                .recovery(&self.id)?
                .is_none_or(|r| r.stage == Stage::GivingUp.as_str())
        {
            self.wallet.unclaim_notes(&self.id)?;
        }
        Ok(())
    }
    /// Whether blocks she saw since she published left the chain: the
    /// height of the newest she saw that stands, if so. Each round the tip
    /// she sees is kept ([`Store::see_recovery_tip`]), the first once she
    /// published ([`watched`]); none kept, as of a build before, tells
    /// nothing. Should none she kept stand, the oldest is taken to be the
    /// last that did. A tip lower than one she saw is no sign yet: looked
    /// at again once the chain is as long.
    async fn reorganized(&self, stage: Stage, tip: u32) -> Result<Option<u32>> {
        if !watched(stage) {
            return Ok(None);
        }
        // Read before the others: a chain replaced meanwhile shows as one
        // of them gone, never as a tip of it kept above them.
        let at_tip = self.chain.hash(tip).await.map_err(|e| anyhow!(e))?;
        let seen = self.store.recovery_tips(&self.id)?;
        let mut gone = false;
        for &(height, hash) in &seen {
            if height > tip {
                continue;
            }
            if self.chain.hash(height).await.map_err(|e| anyhow!(e))? == hash {
                if gone {
                    return Ok(Some(height));
                }
                break;
            }
            gone = true;
        }
        if gone {
            return Ok(seen.last().map(|(height, _)| height.saturating_sub(1)));
        }
        self.store.see_recovery_tip(&self.id, tip, at_tip)?;
        Ok(None)
    }
    fn trouble(&self, why: String) {
        tracing::warn!(id = %crate::hex_id(&self.id), "recovering a contract: {why}");
        self.refused.lock().expect("refusals").push(why);
    }
    fn report(&self) -> Result<()> {
        let refused = self.refused.lock().expect("refusals").join("; ");
        self.store
            .recovery_error(&self.id, (!refused.is_empty()).then_some(refused.as_str()))?;
        Ok(())
    }
    async fn broadcast(&self, tx: &Transaction) {
        if let Err(e) = self.chain.broadcast(tx).await {
            self.trouble(format!("{}: {e}", tx.compute_txid()));
        }
    }
    fn give_back(&self, why: &str) -> Result<()> {
        if self
            .store
            .revoke_recovery(&self.id, Stage::GivingUp.as_str(), Some(why))?
        {
            finish_giving_up(self.wallet, self.store, &self.id)?;
        }
        Ok(())
    }

    /// Her notes of the hub's keyset taken, its share of them with her
    /// other contracts there ([`claims`]), and claimed: the claim signed
    /// by each note's hold key, for their face value, its cap at most.
    /// The notes she funded it with that her wallet never received are
    /// claimed first ([`super::funded`]), then the branches of her locks
    /// there owed on Bitcoin ([`LockClaim`]), within its cap: the refunds
    /// of those she made that expired at depth unsettled (certified by
    /// the hub or not: those it never certified on their own inputs), and
    /// the pay
    /// branches of those paying her whose activation its statement shows
    /// ([`activation::shown`]).
    ///
    /// What is left of its cap, the notes she imported from a bridge of
    /// hers fill, then the refunds of its locks owed on Bitcoin
    /// ([`licash_wallet::Wallet::claim_imported_locks`]).
    ///
    /// Nothing of it is published before its statement would owe it whole
    /// ([`owed_whole`]): a claim that would not be is made again without
    /// the payments under way (the locks its hub never certified, and the
    /// sends signed, unfinished, whose notes it claims after the others,
    /// their outputs to her as fallbacks), then without the locks paying
    /// her, then without any lock of hers; then without the locks
    /// imported, then without the notes imported, and one of her notes
    /// alone that still would not be gives her recovery up, nothing spent.
    async fn claim(&self, state: &mut State, tip: u32) -> Result<Next> {
        // Before any note of hers is taken.
        self.o.forcible()?;
        let parts = self.o.base.parts();
        let keyset = *parts.keyset.id();
        let funded = super::funded::unreceived(self.wallet, self.o.funded.as_ref())?;
        let mut notes = self.wallet.claimed_notes(&self.id, &keyset)?;
        let mut locks = self.wallet.claimed_locks(&self.id, &keyset)?;
        if notes.is_empty() && locks.is_empty() {
            let shown = activation::shown(self.wallet, self.chain, &self.o.base, tip).await?;
            let pays = |p: &LockClaim| shown.contains(&p.id);
            let slots = self.slots(tip, &funded)?;
            (notes, locks) =
                self.wallet
                    .claim_with_locks(&self.id, &slots, tip, Some(&pays), true)?;
            // Narrowed while a lock is left to leave out: the payments
            // under way (sends signed, locks its hub never certified),
            // then those paying her, then every one.
            for _ in 0..3 {
                if locks.is_empty() {
                    break;
                }
                let Err(why) = self.sound(&notes, &funded, &locks, tip).await? else {
                    break;
                };
                // Of a payment under way: a lock its hub never certified,
                // or a send's fallbacks.
                let own = |r: &LockClaim| {
                    matches!(r.source, Source::OwnInputs { .. } | Source::Plain { .. })
                };
                let uncertified = locks.iter().any(own);
                let paying = locks.iter().any(|r| r.branch == Branch::Pay);
                tracing::warn!(
                    id = %crate::hex_id(&self.id), uncertified, paying,
                    "a claim filed without locks of hers: {why}"
                );
                self.wallet.unclaim_notes(&self.id)?;
                let wallet = self.wallet;
                (notes, locks) = match (uncertified, paying) {
                    (true, _) => {
                        wallet.claim_with_locks(&self.id, &slots, tip, Some(&pays), false)?
                    }
                    (false, true) => wallet.claim_with_locks(&self.id, &slots, tip, None, false)?,
                    (false, false) => (wallet.claim_notes(&self.id, &slots)?, vec![]),
                };
            }
            // What hers leave of her cap, the notes she imported from a
            // bridge of hers fill ([`licash_wallet::Wallet::import_notes`]),
            // then the refunds of its locks owed.
            if let Some(slot) = slots.iter().find(|s| s.id == self.id) {
                let (cap, max) = left_of(slot, &notes, &locks);
                let imported = self.wallet.claim_imported(&self.id, &keyset, cap, max)?;
                notes.extend(imported);
                let (cap, max) = left_of(slot, &notes, &locks);
                let imported =
                    (self.wallet).claim_imported_locks(&self.id, &keyset, tip, cap, max)?;
                locks.extend(imported);
            }
            self.took
                .store(!(notes.is_empty() && locks.is_empty()), Ordering::SeqCst);
        }
        if notes.is_empty() && locks.is_empty() && funded.is_empty() {
            self.give_back("no notes at its hub to claim")?;
            bail!("no notes at its hub to claim");
        }
        state.amount = self.amount(&notes, &funded, &locks);
        let mut sound = self.sound(&notes, &funded, &locks, tip).await?;
        if let Err(why) = &sound {
            // The locks imported are left out first, given back: the rest
            // may be owed whole.
            let released = self.wallet.release_imported_locks(&self.id, why)?;
            if !released.is_empty() {
                locks.retain(|l| !released.contains(&l.id));
                if !(notes.is_empty() && locks.is_empty() && funded.is_empty()) {
                    state.amount = self.amount(&notes, &funded, &locks);
                    sound = self.sound(&notes, &funded, &locks, tip).await?;
                }
            }
        }
        if let Err(why) = &sound {
            // The notes imported are dropped next, for good: hers alone may
            // be owed whole.
            let dropped = self.wallet.void_imported(&self.id, why)?;
            if !dropped.is_empty() {
                notes.retain(|n| {
                    (n.note.message().identifier()).map_or(true, |y| !dropped.contains(&y.0))
                });
                if !(notes.is_empty() && locks.is_empty() && funded.is_empty()) {
                    state.amount = self.amount(&notes, &funded, &locks);
                    sound = self.sound(&notes, &funded, &locks, tip).await?;
                }
            }
        }
        let filing = match sound {
            Ok(filing) => filing,
            Err(why) => {
                self.give_back(&why)?;
                bail!(why);
            }
        };
        state.notes = notes.iter().map(|n| hex::encode(n.to_bytes())).collect();
        state.filing = Some(hex::encode(filing.to_bytes(Format::of(&self.o.base))));
        Ok(Next::To(Stage::Claimed))
    }

    /// The filing of a claim of `notes`, `funded` and `locks`, which its
    /// statement would owe whole at `tip` ([`owed_whole`]); or why there
    /// is none. An error is the chain's: to try again.
    async fn sound(
        &self,
        notes: &[ClaimNote],
        funded: &[FundedNote],
        locks: &[LockClaim],
        tip: u32,
    ) -> Result<std::result::Result<Filing, String>> {
        let amount = self.amount(notes, funded, locks);
        let filing = match self.filing(notes, funded, locks, amount) {
            Ok(filing) => filing,
            Err(e) => return Ok(Err(format!("{e:#}"))),
        };
        let request = Request {
            amount,
            claim_digest: *filing.publication().claim().digest(),
        };
        let filed = filing.to_bytes(Format::of(&self.o.base));
        let owed = owed_whole(self.chain, &self.o.base, &request, &filed, tip).await?;
        Ok(owed.map(|()| filing))
    }

    /// What a claim of `notes`, `funded` and `locks` is for: their face
    /// value, its cap at most, as a note beyond what is left of the cap
    /// is claimed for that much.
    fn amount(&self, notes: &[ClaimNote], funded: &[FundedNote], locks: &[LockClaim]) -> u32 {
        let held: u64 = (notes.iter().map(|n| n.note.message().denomination()))
            .chain(funded.iter().map(|f| f.derivation.message().denomination()))
            .chain(locks.iter().map(|r| r.value))
            .sum();
        self.o
            .base
            .parts()
            .cap
            .min(u32::try_from(held).unwrap_or(u32::MAX))
    }

    /// The slots her notes at its hub are shared out to: its own, less
    /// what its `funded` notes claim of it, and those of her other
    /// contracts there protecting notes at `tip`.
    fn slots(&self, tip: u32, funded: &[FundedNote]) -> Result<Vec<ClaimSlot>> {
        let all = self.store.list()?;
        let this = (all.iter().find(|c| c.id == self.id)).context("a contract not stored")?;
        let urls = self.wallet.hub_urls(&this.hub).unwrap_or_default();
        let others: Vec<_> = (all.iter())
            .filter(|c| c.id != self.id && c.live(tip) && c.at(&urls))
            .collect();
        let mut terms = claims::terms(self.wallet, self.store, &others, tip)?;
        terms.insert(self.id, ClaimTerms::of(&self.o));
        let mine = others.into_iter().chain([this]);
        let mut slots = claims::claim_slots(mine, &terms);
        let owed: u64 = (funded.iter())
            .map(|f| f.derivation.message().denomination())
            .sum();
        for slot in slots.iter_mut().filter(|s| s.id == self.id) {
            // Not lowered twice: the store's record of her funded part is
            // replaced by what her wallet holds of it.
            slot.cap = u64::from(this.cap).saturating_sub(owed);
            slot.max = slot.max.saturating_sub(funded.len());
        }
        Ok(slots)
    }

    fn filing(
        &self,
        notes: &[ClaimNote],
        funded: &[FundedNote],
        locks: &[LockClaim],
        amount: u32,
    ) -> Result<Filing> {
        let p = self.o.base.parts();
        let limit = p.limits.max_authorizations as usize;
        // In the claim's order of sources, which their witnesses follow.
        let mut locks = locks.to_vec();
        locks.sort_by_key(|r| r.id);
        let messages: Vec<_> = notes.iter().map(|n| n.note.message().clone()).collect();
        let mut keys = self.wallet.hold_keys(notes)?;
        keys.extend((funded.iter()).map(|f| (f.derivation.message().clone(), f.hold_key)));
        keys.extend(locks.iter().flat_map(|r| r.keys.iter().cloned()));
        let mut authorizations: Vec<_> = keys.iter().map(|(m, _)| m.clone()).collect();
        authorizations.sort_by_key(|m| m.identifier().ok());
        let items = (messages.into_iter().map(Item::Settled))
            .chain(funded.iter().map(|f| Item::Funded {
                message: f.derivation.message().clone(),
                index: f.index,
                blinding: *f.derivation.blinding(),
            }))
            .chain(locks.iter().flat_map(|r| r.items.iter().cloned()))
            .collect();
        let witnessed = match funded.is_empty() {
            true => vec![],
            false => (self.o.funded.as_ref())
                .context("funded notes of a contract funding none")?
                .outputs
                .clone(),
        };
        let claim = UnsignedClaim::new(
            claim::Context {
                base: self.o.base.digest(),
                deposit: p.deposit,
                cap: p.cap,
            },
            &p.keyset,
            amount,
            claim::Parts {
                items,
                sources: locks.iter().map(|r| r.source.clone()).collect(),
                activations: (locks.iter())
                    .filter_map(|r| r.activation.as_ref().map(|(a, _)| *a))
                    .collect(),
                authorizations,
            },
            limit,
        )?;
        let publication = Publication::sign(claim, &keys, limit)?;
        let filing = Filing::new(
            publication,
            FilingWitness {
                notes: notes.iter().map(|n| n.note.clone()).collect(),
                sources: locks.iter().map(|r| r.witness.clone()).collect(),
                activations: (locks.iter())
                    .filter_map(|r| r.activation.as_ref().map(|(_, w)| w.clone()))
                    .collect(),
                funded: witnessed,
            },
        )?;
        ensure!(
            filing.to_bytes(Format::of(&self.o.base)).len()
                <= p.limits.max_publication_bytes as usize,
            "the whole filing exceeds the publication limit"
        );
        Ok(filing)
    }
    /// The bytes of `filing` as her publication carries them, and as she
    /// judges the hub's response to it on.
    fn filed(&self, filing: &Filing) -> Vec<u8> {
        let bytes = filing.to_bytes(Format::of(&self.o.base));
        #[cfg(feature = "faults")]
        if let Some(forge) = FORGE.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            return forge(filing, bytes);
        }
        bytes
    }

    fn filing_of(&self, state: &State) -> Result<Filing> {
        let p = self.o.base.parts();
        let bytes = hex::decode(state.filing.as_deref().context("no filing")?)?;
        let format = Format::of(&self.o.base);
        let filing = Filing::from_bytes(
            format,
            &p.keyset,
            p.limits.max_authorizations as usize,
            &bytes,
        )?;
        let claim = filing.publication().claim();
        ensure!(
            claim.context()
                == &claim::Context {
                    base: self.o.base.digest(),
                    deposit: p.deposit,
                    cap: p.cap
                }
                && claim.amount() == state.amount,
            "filing differs from pinned request"
        );
        Ok(filing)
    }
    fn requested(&self, state: &State) -> Result<Request> {
        Ok(Request {
            amount: state.amount,
            claim_digest: *self.filing_of(state)?.publication().claim().digest(),
        })
    }
    fn request_matches(&self, state: &State, tx: &Transaction) -> Result<bool> {
        let r = self.requested(state)?;
        Ok(graph::requested(&self.o.base, tx)? == (r.amount, r.claim_digest))
    }
}

impl<T: Transport, C: Chain> Run<'_, T, C> {
    async fn commit(&self, state: &mut State, tip: u32) -> Result<Next> {
        let p = presign(&self.o.set, "request")?;
        let coin = p.tx.input[0].previous_output;
        let f_height = match state.f_height {
            Some(height) => height,
            None => confirmed_at(
                self.chain,
                coin.txid,
                &p.prevout.script_pubkey,
                self.since..=tip,
            )
            .await?
            .context("F in no block")?,
        };
        state.f_height = Some(f_height);
        let due = f_height
            .checked_add(blocks(p.tx.input[0].sequence)?)
            .context("request delay overflow")?;
        state.next_at = Some(due);
        let from = state.from.unwrap_or(f_height);
        if let Some((height, tx)) =
            first_spend(self.chain, coin, &p.prevout.script_pubkey, from..=tip).await?
        {
            if tx.compute_txid() != p.tx.compute_txid() {
                // A fold she signed of this claim, confirmed after all:
                // her notes are paid for, not given back.
                if !state.folds.is_empty() {
                    return self.folded(state, &tx, height, tip);
                }
                let why = format!(
                    "its collateral is spent already, by {}: closed otherwise",
                    tx.compute_txid()
                );
                self.give_back(&why)?;
                bail!(why);
            }
            if !self.request_matches(state, &tx)? {
                self.trouble("another copy of this wallet requested it, of other notes".into());
                return Ok(Next::To(Stage::Lost));
            }
            state.r = Some(tx);
            state.r_height = Some(height);
            return Ok(Next::To(Stage::Irrevocable));
        }
        state.from = Some(rescan(from, tip));
        if tip.saturating_add(1) < due {
            return Ok(Next::Save);
        }
        ensure!(
            tip.saturating_add(1) <= self.o.base.parts().graph.request_height,
            "past the request deadline"
        );
        let request = self.requested(state)?;
        // Dry construction is private. No signature leaves before the CAS
        // to Irrevocable pins this filing, amount and E durably.
        let r = self
            .o
            .request(&self.keys, request.amount, &request.claim_digest)?;
        let filing = self.filing_of(state)?;
        if let Err(e) = self.build_p(&r, &filing, None, state, false) {
            // Past what she allowed, or failing otherwise: she is told.
            if e.downcast_ref::<Short>().is_none() {
                return Err(e);
            }
            // Her purse and no coin of hers alone pay what she allowed:
            // the coin of her fee payout awaited while under way, time
            // left; else her coins joined.
            let pending = self.payout_pending(state.fee_payout.as_deref())?;
            let deadline = self.o.base.parts().graph.request_height;
            if waits_for_payout(pending, tip, deadline) {
                self.trouble(format!(
                    "waiting for her payout of notes to pay her request's fees, \
                     until block {}",
                    deadline.saturating_sub(FEE_WAIT_MARGIN)
                ));
                return Ok(Next::Save);
            }
            self.build_p(&r, &filing, None, state, true)?;
        }
        Ok(Next::To(Stage::Irrevocable))
    }
    fn request(&self, state: &mut State) -> Result<Next> {
        let request = self.requested(state)?;
        let r = match &state.r {
            // Pinned under an older build of the graph: never valid now.
            Some(r) => {
                self.o.forcible()?;
                r.clone()
            }
            None => self
                .o
                .request(&self.keys, request.amount, &request.claim_digest)?,
        };
        ensure!(
            self.request_matches(state, &r)?,
            "pinned R reads another claim"
        );
        let (p, prevouts, c) = self.build_p(&r, &self.filing_of(state)?, None, state, true)?;
        state.r = Some(r);
        state.p = Some(p);
        state.c = c;
        state.prevouts = prevouts;
        Ok(Next::To(Stage::Signing))
    }
    fn terminal_fee(&self) -> Result<Amount> {
        let dummy = OutPoint::null();
        let coin = TxOut {
            value: DUST,
            script_pubkey: dispute::fee_script(&self.keys.party.payment)?,
        };
        let mut max_vsize = 0;
        for name in [
            "request_timeout",
            "respond_timeout",
            "contest_timeout",
            "failure",
            "success",
        ] {
            let p = presign(&self.o.set, name)?;
            let tx = dispute::add_fee(
                self.o.finish(name, vec![])?,
                p.prevout.clone(),
                (dummy, coin.clone()),
                &self.keys.party.payment,
            )?;
            max_vsize = max_vsize.max(tx.vsize() as u64);
        }
        Ok(self
            .rate
            .fee_vb(max_vsize * TIMEOUT_FEE_MARGIN)
            .context("terminal fee overflow")?
            .max(DUST))
    }
    /// Her commitment to the filing `bytes` (a leaf carrier's), spending
    /// `r`'s purse: its fee its own at the round's rate, 1 sat/vB at least,
    /// a quarter of the purse at most.
    fn commitment(&self, r: &Transaction, bytes: &[u8]) -> Result<Transaction> {
        let purse = self.o.babe.purse().context("no purse to commit from")?;
        let weighed = self.o.commitment(&self.keys, r, bytes, Amount::ZERO)?;
        let vsize = weighed.vsize() as u64;
        let least = FeeRate::from_sat_per_vb_u32(1)
            .fee_vb(vsize)
            .context("commitment fee")?;
        let fee = (self.rate.fee_vb(vsize).context("commitment fee")?)
            .min(purse / 4)
            .max(least);
        self.o.commitment(&self.keys, r, bytes, fee)
    }
    /// Her publication of `filing`, spending `r`'s slot, its anchor and her
    /// purse, its fee within her allowance in all (`state`'s), else what
    /// those hold besides the fee coin it pays her terminals (her reserve's,
    /// so a wrong rate or a bug spends no more): a quarter of that at most
    /// at the round's rate, or, `bump`ing one made before, exactly the fee
    /// given, its fee coin kept. Coins of hers too only should an allowance
    /// ask more than they hold ([`fee_inputs`]): the coin of her fee payout
    /// first, then one alone, the smallest that pays; joined only if
    /// `joined`, as an exception, funds mattering more than her coins not
    /// being tied together on Bitcoin.
    ///
    /// Under a leaf carrier, her purse is spent first by her commitment to
    /// the filing (`state`'s, else made, and returned to keep with P): P
    /// spends its coin carrying the filing and its change in the purse's
    /// place, and pays for it too, as its child.
    fn build_p(
        &self,
        r: &Transaction,
        filing: &Filing,
        bump: Option<(&Transaction, Amount)>,
        state: &State,
        joined: bool,
    ) -> Result<(Transaction, Vec<TxOut>, Option<Transaction>)> {
        let allowance = state.p_allowance;
        let leaf = self.o.carrier() == licash_statement::Carrier::Leaf;
        let fee_vout = if leaf { 0 } else { 1 };
        let bytes = self.filed(filing);
        let request = presign(&self.o.set, "request")?;
        let slot = request.tx.output.get(2).context("no claim slot")?.clone();
        let anchor = r.output.get(1).context("no request anchor")?.clone();
        let fee_script = dispute::fee_script(&self.keys.party.payment)?;
        ensure!(
            anchor.script_pubkey == fee_script,
            "request anchor is not hers"
        );
        let c = match (leaf, &state.c) {
            (false, _) => None,
            (true, Some(c)) => Some(c.clone()),
            (true, None) => Some(self.commitment(r, &bytes)?),
        };
        let c_fee = match &c {
            Some(c) => (self.o.babe.purse().context("no purse to commit from")?)
                .checked_sub(c.output.iter().map(|o| o.value).sum())
                .context("her commitment creates money")?,
            None => Amount::ZERO,
        };
        let held = (slot.value + anchor.value + self.o.babe.purse().unwrap_or(Amount::ZERO))
            .checked_sub(c_fee)
            .context("her commitment pays more than her purse")?;
        let fee_coin = match bump {
            Some((old, _)) => {
                let kept = old.output.get(fee_vout).context("no fee coin to keep")?;
                ensure!(kept.script_pubkey == fee_script, "a fee coin not hers");
                kept.clone()
            }
            // Half of what R hands her at most, whatever the rate says.
            None => TxOut {
                value: self.terminal_fee()?.min(held / 2).max(DUST),
                script_pubkey: fee_script,
            },
        };
        let limit = match allowance {
            Some(sats) => Amount::from_sat(sats),
            None => held.checked_sub(fee_coin.value).unwrap_or(Amount::ZERO),
        };
        let change = self.wallet.fallback_address()?.script_pubkey();
        let r_total: Amount = r.output.iter().map(|o| o.value).sum();
        let r_fee = request
            .prevout
            .value
            .checked_sub(r_total)
            .context("R creates money")?;
        let at = |vout| OutPoint {
            txid: r.compute_txid(),
            vout,
        };
        let mut base = vec![(at(2), slot), (at(1), anchor)];
        // Her commitment's coins: the filing's, and her purse's rest, which
        // pays it unless the fees run past it.
        if let Some(c) = &c {
            for vout in [dispute::COMMITTED, dispute::COMMITTED + 1] {
                let op = OutPoint {
                    txid: c.compute_txid(),
                    vout,
                };
                base.push((op, c.output[vout as usize].clone()));
            }
        }
        // Her purse, R's, pays it unless the fees run past it.
        if let (None, Some(value)) = (&c, self.o.babe.purse()) {
            let purse = r.output.get(PURSE_VOUT as usize).context("no purse")?;
            ensure!(
                purse.value == value && purse.script_pubkey == fee_coin.script_pubkey,
                "request purse is not hers"
            );
            base.push((at(PURSE_VOUT), purse.clone()));
        }
        let coins = super::coins(self.wallet, self.wallet_file)?;
        let most = coins.first().map_or(0, |c| c.value);
        let paid = self.payout_claim(state.fee_payout.as_deref())?;
        let input_fee = self.rate.fee_vb(58).context("input fee")?;
        let free: Vec<_> = coins.iter().map(|c| (c.outpoint, c.value)).collect();
        let mut outputs = std::collections::HashMap::new();
        // What one coin more must hold, of R's own paying too little: its
        // shortfall, the coin's input's fee and its change's dust limit.
        let mut needed = None;
        for chosen in fee_inputs(&free, paid, input_fee.to_sat(), joined) {
            let alone = chosen.is_empty();
            let mut inputs = base.clone();
            for coin in chosen {
                let output = match outputs.get(&coin) {
                    Some(output) => output,
                    None => {
                        let output =
                            (self.wallet.silent_coin_output(&coin)?).context("unknown fee coin")?;
                        outputs.entry(coin).or_insert(output)
                    }
                };
                inputs.push((coin, output.clone()));
            }
            let prevouts: Vec<_> = inputs.iter().map(|(_, out)| out.clone()).collect();
            let total: Amount = prevouts.iter().map(|out| out.value).sum();
            let mut p = self.o.publication(
                &self.keys,
                &bytes,
                vec![
                    fee_coin.clone(),
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: change.clone(),
                    },
                ],
            )?;
            p.input.extend(inputs.iter().skip(1).map(|(op, _)| TxIn {
                previous_output: *op,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            }));
            let mut weighed = p.clone();
            for i in 1..weighed.input.len() {
                if prevouts[i].script_pubkey == fee_coin.script_pubkey {
                    dispute::sign_fee_input(&self.keys.party.payment, &mut weighed, i, &prevouts)?;
                } else if c.is_none() || i != 2 {
                    weighed.input[i].witness = Witness::from_slice(&[[0u8; 64]]);
                }
            }
            // The filing's coin, revealed: what it weighs, its envelope.
            if c.is_some() {
                self.o
                    .sign_publication(&self.keys, &mut weighed, &prevouts, &bytes)?;
            }
            let own = self
                .rate
                .fee_vb(weighed.vsize() as u64)
                .context("publication fee")?;
            let c_vsize = c.as_ref().map_or(0, |c| c.vsize() as u64);
            let package = self
                .rate
                .fee_vb(weighed.vsize() as u64 + r.vsize() as u64 + c_vsize)
                .context("request package fee")?;
            let least = FeeRate::from_sat_per_vb_u32(1)
                .fee_vb(weighed.vsize() as u64)
                .context("publication fee")?;
            let fee = match bump {
                Some((_, fee)) => fee,
                None => (own.max(package.checked_sub(r_fee + c_fee).unwrap_or(Amount::ZERO)))
                    .min(limit / 4)
                    .max(least),
            };
            ensure!(
                fee <= limit,
                "her publication would pay {fee} in fees, more than the {limit} {}: \
                 allow more with `licash-wallet {ALLOW_FEE} {} <sat>`",
                match allowance {
                    Some(_) => "she allowed",
                    None => "its reserve holds",
                },
                crate::hex_id(&self.id)
            );
            let Some(left) = total.checked_sub(fee_coin.value + fee) else {
                if alone {
                    needed = Some(fee_coin.value + fee + input_fee - total + DUST);
                }
                continue;
            };
            let max_bytes = self.o.base.parts().limits.max_transaction_bytes;
            if weighed.total_size() > max_bytes as usize {
                continue;
            }
            if left >= DUST {
                p.output[fee_vout + 1].value = left;
            } else {
                p.output.pop();
            }
            // Over its every input and final output: none can be added.
            self.o
                .sign_publication(&self.keys, &mut p, &prevouts, &bytes)?;
            return Ok((p, prevouts, c));
        }
        let needed = needed.map_or(0, |n| n.to_sat());
        Err(Short { needed, most }.into())
    }

    /// The claim of her fee payout of `hash`, if claimed.
    fn payout_claim(&self, hash: Option<&str>) -> Result<Option<Txid>> {
        let Some(hash) = hash else { return Ok(None) };
        let payouts = self.wallet.payouts()?;
        Ok(payouts
            .into_iter()
            .find(|p| p.hash == hash)
            .and_then(|p| p.claim))
    }

    /// Whether her payout of `hash` is under way: neither done nor failed.
    fn payout_pending(&self, hash: Option<&str>) -> Result<bool> {
        let Some(hash) = hash else { return Ok(false) };
        let payouts = self.wallet.payouts()?;
        Ok(payouts
            .iter()
            .find(|p| p.hash == hash)
            .is_some_and(|p| matches!(p.state, PayoutState::Open | PayoutState::Claimed)))
    }

    /// What of [`fee_needs`] this recovery, at `stage` of `state`, needs.
    fn fee_need(&self, stage: Stage, state: &State, tip: u32) -> Result<Option<FeeNeed>> {
        if stage == Stage::Claimed {
            if self.payout_pending(state.fee_payout.as_deref())? {
                return Ok(None);
            }
            let deadline = self.o.base.parts().graph.request_height;
            let by = deadline.saturating_sub(FEE_WAIT_MARGIN);
            if tip.saturating_add(payout_blocks(self.wallet.network())) > by {
                return Ok(None);
            }
            let request = self.requested(state)?;
            let r = self
                .o
                .request(&self.keys, request.amount, &request.claim_digest)?;
            let Err(e) = self.build_p(&r, &self.filing_of(state)?, None, state, false) else {
                return Ok(None);
            };
            let Some(short) = e.downcast_ref::<Short>() else {
                return Err(e);
            };
            return Ok(Some(FeeNeed {
                id: self.id,
                purpose: FeeFor::Publication,
                amount: Amount::from_sat(short.needed),
                by: Some(by),
            }));
        }
        if !challenge_possible(stage, state)
            || self.payout_pending(state.challenge_payout.as_deref())?
        {
            return Ok(None);
        }
        let marker = challenge_marker(&self.id);
        if (self.wallet.silent_coins()?.iter()).any(|c| c.spending == Some(marker)) {
            return Ok(None);
        }
        let need = challenge_reserve(self.rate);
        let free = super::coins(self.wallet, self.wallet_file)?;
        if free.iter().any(|c| c.value >= need.to_sat()) {
            return Ok(None);
        }
        Ok(Some(FeeNeed {
            id: self.id,
            purpose: FeeFor::Challenge,
            amount: need,
            by: None,
        }))
    }
    fn sign(&self, state: &mut State) -> Result<Next> {
        let mut p = state.p.clone().context("no publication transaction")?;
        let fee_script = dispute::fee_script(&self.keys.party.payment)?;
        let committed = committed_script(state);
        for i in 1..p.input.len() {
            if state.prevouts[i].script_pubkey == fee_script {
                dispute::sign_fee_input(&self.keys.party.payment, &mut p, i, &state.prevouts)?;
                continue;
            }
            // Her filing's coin, signed with P's slot ([`Self::build_p`]).
            if Some(&state.prevouts[i].script_pubkey) == committed.as_ref() {
                continue;
            }
            match self.wallet.sign_input(&p, &state.prevouts, i) {
                Ok(signed) => p.input[i].witness = signed.input[i].witness.clone(),
                Err(e @ (licash_wallet::Error::Invalid(_) | licash_wallet::Error::NoteTaken)) => {
                    ensure!(
                        !self.rebuilt.swap(true, Ordering::SeqCst),
                        "a coin of P's again: {e}"
                    );
                    let _ = self.wallet.abandon_silent(&p.compute_txid());
                    state.p = None;
                    state.prevouts.clear();
                    return Ok(Next::To(Stage::Irrevocable));
                }
                Err(e) => return Err(e.into()),
            }
        }
        ensure!(
            bitcoin::consensus::serialize(&p).len()
                <= self.o.base.parts().limits.max_transaction_bytes as usize,
            "publication transaction exceeds contract limit"
        );
        state.p = Some(p);
        Ok(Next::To(Stage::Published))
    }
    /// Her coin paying P, if any, kept from her other spends.
    fn keep_p(&self, p: &Transaction, prevouts: &[TxOut], committed: Option<&ScriptBuf>) {
        let Ok(fee_script) = dispute::fee_script(&self.keys.party.payment) else {
            return;
        };
        for i in 1..p.input.len() {
            if prevouts.get(i).is_none_or(|o| {
                o.script_pubkey == fee_script || Some(&o.script_pubkey) == committed
            }) {
                continue;
            }
            if let Err(e) = self.wallet.sign_input(p, prevouts, i) {
                tracing::debug!(id = %crate::hex_id(&self.id), "a fee coin not reserved again: {e}");
            }
        }
    }
    async fn publish(&self, state: &mut State, tip: u32) -> Result<Next> {
        let r = state.r.clone().context("no R")?;
        let p = state.p.clone().context("no P")?;
        if state.r_height.is_none() {
            let request = presign(&self.o.set, "request")?;
            let from = state.from.or(state.f_height).unwrap_or(self.since);
            match first_spend(
                self.chain,
                request.tx.input[0].previous_output,
                &request.prevout.script_pubkey,
                from..=tip,
            )
            .await?
            {
                Some((height, tx)) if tx.compute_txid() == r.compute_txid() => {
                    if !self.request_matches(state, &tx)? {
                        let _ = self.wallet.abandon_silent(&p.compute_txid());
                        self.trouble(
                            "another copy of this wallet requested it, of other notes".into(),
                        );
                        return Ok(Next::To(Stage::Lost));
                    }
                    state.r = Some(tx);
                    state.r_height = Some(height);
                }
                // A fold she signed of this claim confirmed before her
                // request: it pays the claim, and her publication is moot.
                Some((height, tx)) if !state.folds.is_empty() => {
                    let _ = self.wallet.abandon_silent(&p.compute_txid());
                    return self.folded(state, &tx, height, tip);
                }
                Some((_, tx)) => {
                    let _ = self.wallet.abandon_silent(&p.compute_txid());
                    self.trouble(format!("collateral went to {} instead", tx.compute_txid()));
                    return Ok(Next::To(Stage::Lost));
                }
                None => {
                    state.from = Some(rescan(from, tip));
                }
            }
        }
        let Some(r_height) = state.r_height else {
            if state.next_at.is_none_or(|due| tip.saturating_add(1) >= due) {
                if let Some(next) = self.bump(state, &r, &p, tip)? {
                    return Ok(next);
                }
                self.keep_p(&p, &state.prevouts, committed_script(state).as_ref());
                self.broadcast(&r).await;
                if let Some(c) = &state.c {
                    self.broadcast(c).await;
                }
                self.broadcast(&p).await;
            }
            return Ok(Next::Save);
        };
        let slot = OutPoint {
            txid: r.compute_txid(),
            vout: 2,
        };
        let spent =
            first_spend(self.chain, slot, &r.output[2].script_pubkey, r_height..=tip).await?;
        // A version of hers, the last or one it took the place of: what she
        // publishes, whichever spends the slot, carries her claim and pays
        // her fee coin alike.
        let hers = match &spent {
            Some((_, tx)) => {
                let kept = p_fee_vout(state) as usize + 1;
                !self.reclaimed(tx)? && tx.output.get(..kept) == p.output.get(..kept)
            }
            None => false,
        };
        match spent {
            Some((height, tx)) if hers => {
                if tx.compute_txid() != p.compute_txid() {
                    let _ = self.wallet.abandon_silent(&p.compute_txid());
                    state.p = Some(tx);
                }
                state.p_height = Some(height);
                state.from = Some(r_height);
                state.next_at = Some(
                    r_height
                        + blocks(presign(&self.o.set, "request_timeout")?.tx.input[0].sequence)?,
                );
                Ok(Next::To(Stage::Requested))
            }
            // The hub's reclaim, P too late: her claim reads as empty, owed
            // nothing, and the hub's answer to it pays her reserve back
            // (less her purse), or its silence her request. Followed so.
            Some((_, tx)) if self.reclaimed(&tx)? => {
                let _ = self.wallet.abandon_silent(&p.compute_txid());
                self.trouble(format!(
                    "her claim was not published in time: the hub took its slot ({}), so it reads as empty",
                    tx.compute_txid()
                ));
                state.reclaimed = true;
                state.from = Some(r_height);
                state.next_at = Some(
                    r_height
                        + blocks(presign(&self.o.set, "request_timeout")?.tx.input[0].sequence)?,
                );
                Ok(Next::To(Stage::Requested))
            }
            Some((_, tx)) => bail!("claim slot spent by {}, not P", tx.compute_txid()),
            None => {
                if let Some(next) = self.bump(state, &r, &p, tip)? {
                    return Ok(next);
                }
                self.keep_p(&p, &state.prevouts, committed_script(state).as_ref());
                if let Some(c) = &state.c {
                    self.broadcast(c).await;
                }
                self.broadcast(&p).await;
                Ok(Next::Save)
            }
        }
    }

    /// Her publication `p`, in no block at `tip`, made again to pay more
    /// as its window runs out, then signed ([`Stage::Signing`]): its fee
    /// the limit [`Self::build_p`] keeps to, a quarter of it once a quarter
    /// of its window passed, half at half, all of it at three quarters,
    /// whatever the chain says fees are (a hub serving the chain could say
    /// anything). Told then, if still in no block, so that she may allow
    /// more ([`allow_publication_fee`]). Its window: until the request
    /// deadline while `r` is in no block, else its publication window from
    /// `r`'s block. None if it pays enough already.
    fn bump(
        &self,
        state: &mut State,
        r: &Transaction,
        p: &Transaction,
        tip: u32,
    ) -> Result<Option<Next>> {
        let graph = &self.o.base.parts().graph;
        let (start, end) = match state.r_height {
            Some(at) => (at, at.saturating_add(u32::from(graph.publication_window))),
            None => (state.next_at.unwrap_or(tip), graph.request_height),
        };
        let paid = (state.prevouts.iter().map(|o| o.value).sum::<Amount>())
            .checked_sub(p.output.iter().map(|o| o.value).sum())
            .context("her publication creates money")?;
        let c = state.c.as_ref().map(Transaction::compute_txid);
        let held: Amount = (p.input.iter().zip(&state.prevouts))
            .filter(|(i, _)| {
                let from = i.previous_output.txid;
                from == r.compute_txid() || Some(from) == c
            })
            .map(|(_, o)| o.value)
            .sum();
        let fee_vout = p_fee_vout(state) as usize;
        let limit = match state.p_allowance {
            Some(sats) => Amount::from_sat(sats),
            None => held
                .checked_sub(p.output[fee_vout].value)
                .unwrap_or(Amount::ZERO),
        };
        let rung = rung(start, end, tip);
        if rung == 3 {
            // Signed so that others could add inputs to it, by a release
            // before: one of more fee at a lower rate may hold it out.
            let pinnable = p.input[0].witness.nth(0).is_some_and(|s| s.len() == 65);
            self.trouble(format!(
                "her publication {} is in no block, {} blocks left to it, paying {paid} of the \
                 {limit} it may: allow more with `licash-wallet {ALLOW_FEE} {} <sat>`{}",
                p.compute_txid(),
                end.saturating_sub(tip),
                crate::hex_id(&self.id),
                if pinnable {
                    " (signed by an older release, others may hold it out)"
                } else {
                    ""
                },
            ));
        }
        let target = match rung {
            0 => return Ok(None),
            rung => Amount::from_sat(limit.to_sat() >> (3 - rung)),
        };
        if !deadline::replaces(target, p.vsize() as u64, paid) {
            return Ok(None);
        }
        let filing = self.filing_of(state)?;
        let (bumped, prevouts, _) = match self.build_p(r, &filing, Some((p, target)), state, true) {
            Ok(made) => made,
            Err(e) => {
                self.trouble(format!("{e:#}"));
                return Ok(None);
            }
        };
        tracing::info!(id = %crate::hex_id(&self.id), from = %paid, to = %target, "her publication bumped");
        let _ = self.wallet.abandon_silent(&p.compute_txid());
        state.p = Some(bumped);
        state.prevouts = prevouts;
        Ok(Some(Next::To(Stage::Signing)))
    }
}

/// The rung of a window from `start` to `end` at `tip`: 0 in its first
/// quarter, then 1, 2 and 3 in its last, and after.
fn rung(start: u32, end: u32, tip: u32) -> u32 {
    let len = u64::from(end.saturating_sub(start).max(1));
    let gone = u64::from(tip.saturating_sub(start));
    (gone * 4 / len).min(3) as u32
}

/// Her recovery at `stage` taken back to what blocks up to `stood` show,
/// those above it replaced: what she saw in a block above it forgotten
/// (each link the hub or she posted, from the first, and all after it),
/// the stage that watches for the first of them again, and her scan from
/// the block after `stood` at the latest. What she signed or revealed is
/// kept, to be posted again as it was: her request and publication, her
/// challenge and its child, her sweep.
fn rewind(stage: Stage, state: &mut State, stood: u32) -> Stage {
    let gone = |height: Option<u32>| height.is_some_and(|h| h > stood);
    state.from = state.from.map(|from| from.min(stood.saturating_add(1)));
    let (to, first) = if gone(state.r_height) {
        (Stage::Published, 0)
    } else if gone(state.p_height) || state.reclaimed {
        // The hub's reclaim, its height not kept: found again too.
        (Stage::Published, 1)
    } else if gone(state.response_height) {
        (Stage::Requested, 2)
    } else if gone(state.contest_height) {
        (Stage::Answered, 3)
    } else if gone(state.assertion_height) {
        (Stage::Contested, 4)
    } else if gone(state.challenge_height) {
        (Stage::Asserted, 5)
    } else if gone(state.payout_height) {
        let watching = if state.challenge_height.is_some() {
            Stage::Challenged
        } else if state.assertion_height.is_some() {
            Stage::Asserted
        } else if state.contest_height.is_some() {
            Stage::Contested
        } else if state.response_height.is_some() {
            Stage::Answered
        } else {
            Stage::Requested
        };
        (watching, 6)
    } else {
        return stage;
    };
    if first == 0 {
        state.r_height = None;
    }
    if first <= 1 {
        state.p_height = None;
        state.reclaimed = false;
    }
    if first <= 2 {
        state.response = None;
        state.response_height = None;
        state.reduced = None;
        state.deadline = None;
        // What she made of a response in a block gone: of the one found
        // again, not this.
        state.accepted = None;
    }
    // Her contest is kept, to be posted again as it was.
    if first <= 3 {
        state.contest_height = None;
    }
    if first <= 4 {
        state.assertion = None;
        state.assertion_height = None;
        state.verified = None;
    }
    if first <= 5 {
        state.challenge_height = None;
    }
    state.payout = None;
    state.payout_name = None;
    state.payout_height = None;
    state.swept_height = None;
    state.next_at = None;
    if first == 0 {
        // Her request in no block now, nor any before the next: her
        // publication's fee climbs again from there.
        state.from = Some(stood.saturating_add(1));
        state.next_at = Some(stood.saturating_add(1));
    }
    to
}

/// Whether her recovery at `stage` follows the tips it sees: from her
/// publication's on, while not over, but while it is signed again.
fn watched(stage: Stage) -> bool {
    !matches!(
        stage,
        Stage::Claiming
            | Stage::Claimed
            | Stage::Irrevocable
            | Stage::Signing
            | Stage::GivingUp
            | Stage::Folding
            | Stage::Done
            | Stage::Lost
    )
}

/// Let the recovery of contract `id` in `wallet_file` pay `sats` in all for its
/// publication's fees, more than its reserve holds: her call, once told it
/// falls short, or before. Refused above what her contract holds, a typo
/// as like as not.
pub fn allow_publication_fee(
    wallet_file: &std::path::Path,
    id: &[u8; 32],
    sats: u64,
) -> Result<()> {
    let store = Store::existing(wallet_file)?.context("no contracts")?;
    let contract = (store.list()?.into_iter().find(|c| &c.id == id)).context("no such contract")?;
    ensure!(
        sats <= contract.value,
        "{sats} sat is more than the contract holds ({} sat)",
        contract.value
    );
    for _ in 0..8 {
        let row = store.recovery(id)?.context("not forced closed")?;
        let mut state = State::decode(&row)?;
        state.p_allowance = Some(sats);
        if store.save_recovery(
            id,
            (&row.stage, &row.state),
            &row.stage,
            false,
            &state.encode(),
        )? {
            return Ok(());
        }
    }
    bail!("the recovery kept moving on: try again")
}

impl<T: Transport, C: Chain> Run<'_, T, C> {
    fn parent(&self, stage: Stage, state: &State) -> Result<(Transaction, u32)> {
        let pair = match stage {
            Stage::Requested => (&state.r, state.r_height),
            Stage::Answered | Stage::Contesting => (&state.response, state.response_height),
            Stage::Contested => (&state.contest, state.contest_height),
            Stage::Asserted | Stage::Challenging => (&state.assertion, state.assertion_height),
            Stage::Challenged => (&state.challenge, state.challenge_height),
            _ => bail!("no parent to watch at {}", stage.as_str()),
        };
        Ok((
            pair.0.clone().context("missing watched transaction")?,
            pair.1.context("watched transaction is unconfirmed")?,
        ))
    }
    fn is_link(&self, name: &str, tx: &Transaction) -> Result<bool> {
        Ok(tx.compute_txid() == presign(&self.o.set, name)?.tx.compute_txid())
    }
    /// Whether `tx`, spending her request's claim slot, is the hub's
    /// reclaim of it: its one output paying the hub's payout script.
    fn reclaimed(&self, tx: &Transaction) -> Result<bool> {
        let hub = licash_contract::graph::party_pub(&self.o.base.parts().parties[1])?;
        Ok(matches!(&tx.output[..], [out] if out.script_pubkey == hub.payout_spk))
    }
    fn is_terminal(&self, name: &str, tx: &Transaction) -> Result<bool> {
        let p = presign(&self.o.set, name)?;
        Ok(tx.output == p.tx.output
            && tx
                .input
                .iter()
                .any(|i| i.previous_output == p.tx.input[0].previous_output))
    }
    fn paid(&self, state: &mut State, name: &str, tx: Transaction, height: u32) -> Next {
        state.payout = Some(tx);
        state.payout_name = Some(name.into());
        state.payout_height = Some(height);
        state.from = Some(height);
        state.next_at = None;
        Next::To(
            if matches!(name, "request_timeout" | "contest_timeout" | "failure") {
                Stage::TimedOut
            } else {
                Stage::Paid
            },
        )
    }
    fn observed(
        &self,
        stage: Stage,
        state: &mut State,
        height: u32,
        tx: Transaction,
    ) -> Result<Next> {
        match stage {
            Stage::Requested => {
                if self.is_link("respond", &tx)? {
                    state.reduced = Some(graph::responded(&self.o.base, &tx)?);
                    state.response = Some(tx);
                    state.response_height = Some(height);
                    state.payout = None;
                    state.payout_name = None;
                    state.payout_height = None;
                    state.from = Some(height);
                    let due = height
                        + blocks(presign(&self.o.set, "respond_timeout")?.tx.input[0].sequence)?;
                    state.deadline = Some(due);
                    state.next_at = Some(due);
                    return Ok(Next::To(Stage::Answered));
                }
                if self.is_terminal("request_timeout", &tx)? {
                    return Ok(self.paid(state, "request_timeout", tx, height));
                }
            }
            Stage::Answered | Stage::Contesting => {
                if self.is_link("contest", &tx)? {
                    state.contest = Some(tx);
                    state.contest_height = Some(height);
                    state.challenge_child = None;
                    state.payout = None;
                    state.payout_name = None;
                    state.payout_height = None;
                    state.from = Some(height);
                    let due = height
                        + blocks(presign(&self.o.set, "contest_timeout")?.tx.input[0].sequence)?;
                    state.deadline = Some(due);
                    state.next_at = Some(due);
                    return Ok(Next::To(Stage::Contested));
                }
                if self.is_terminal("respond_timeout", &tx)? {
                    return Ok(self.paid(state, "respond_timeout", tx, height));
                }
            }
            Stage::Contested => {
                if self.is_link("assert", &tx)? {
                    let verified = self.o.verify_assertion(&tx)?;
                    #[cfg(feature = "faults")]
                    let verified = verified && !DOUBT.load(std::sync::atomic::Ordering::SeqCst);
                    state.verified = Some(verified);
                    state.assertion = Some(tx);
                    state.assertion_height = Some(height);
                    state.payout = None;
                    state.payout_name = None;
                    state.payout_height = None;
                    state.from = Some(height);
                    state.next_at = None;
                    return Ok(Next::To(Stage::Asserted));
                }
                if self.is_terminal("contest_timeout", &tx)? {
                    return Ok(self.paid(state, "contest_timeout", tx, height));
                }
            }
            Stage::Asserted | Stage::Challenging => {
                if self.is_link("challenge_assert", &tx)? {
                    state.challenge = Some(tx);
                    state.challenge_height = Some(height);
                    state.payout = None;
                    state.payout_name = None;
                    state.payout_height = None;
                    state.from = Some(height);
                    state.next_at = Some(
                        height + blocks(presign(&self.o.set, "failure")?.tx.input[0].sequence)?,
                    );
                    return Ok(Next::To(Stage::Challenged));
                }
                if self.is_terminal("success", &tx)? {
                    if state.verified == Some(false) {
                        self.trouble(
                            "the hub's invalid assertion paid out before a challenge confirmed"
                                .into(),
                        );
                    }
                    return Ok(self.paid(state, "success", tx, height));
                }
            }
            Stage::Challenged => {
                if self.is_terminal("failure", &tx)? {
                    return Ok(self.paid(state, "failure", tx, height));
                }
                for p in self
                    .o
                    .set
                    .iter()
                    .filter(|p| p.name.starts_with("wrongly_challenged_"))
                {
                    if self.is_terminal(&p.name, &tx)? {
                        return Ok(self.paid(state, &p.name, tx, height));
                    }
                }
            }
            _ => bail!("unexpected observation stage"),
        }
        self.trouble(format!(
            "the dispute output went to an unrecognized transaction {}",
            tx.compute_txid()
        ));
        Ok(Next::To(Stage::Lost))
    }
    /// The hub responded, `height` the response's block: she checks what it
    /// responded on, and leaves it alone, to pay her what it says at its
    /// terminal once her contest window has passed, if it bears out her
    /// claim's reduction, else contests it before that terminal can be
    /// posted. A response she cannot check in time she contests.
    async fn answered(&self, state: &mut State, height: u32, tip: u32) -> Result<Next> {
        let g = &self.o.base.parts().graph;
        let due = height
            .checked_add(blocks(
                presign(&self.o.set, "respond_timeout")?.tx.input[0].sequence,
            )?)
            .context("deadline overflow")?;
        // The last tip her contest still confirms in before the terminal.
        let by = due.saturating_sub(1).saturating_sub(g.deadline_margin);
        if state.accepted.is_none() {
            let may_wait = tip.saturating_add(1) < by;
            match self.check_response(state, may_wait).await {
                Ok(verdict) => state.accepted = verdict,
                Err(e) => self.trouble(format!("her check of the hub's response failed: {e:#}")),
            }
            if state.accepted.is_none() && !may_wait {
                self.trouble("the hub's response is not borne out in time: she contests it".into());
                state.accepted = Some(false);
            }
        }
        match state.accepted {
            Some(false) => {
                let contest = match state.contest.clone() {
                    Some(contest) => contest,
                    None => self.o.contest(&self.keys)?,
                };
                state.contest = Some(contest);
                state.next_at = Some(by);
                Ok(Next::To(Stage::Contesting))
            }
            Some(true) => {
                state.next_at = Some(due);
                if tip.saturating_add(1) < due {
                    return Ok(Next::Save);
                }
                self.plan_terminal(state, "respond_timeout", due)
            }
            None => {
                state.next_at = Some(by);
                Ok(Next::Save)
            }
        }
    }

    /// Whether the hub's assertion proves its statement with the π2 and π3
    /// the hub shows her of it ([`crate::PROOF`]), its π1 the one the
    /// chain shows: then the hub answers any challenge of it (any valid π2
    /// and π3 decrypt for that π1), and she leaves it alone. Not asked of
    /// a holder doubting every assertion (tests).
    async fn hub_proves(&self, state: &State) -> Result<bool> {
        #[cfg(feature = "faults")]
        if DOUBT.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let assertion = state.assertion.as_ref().context("no assertion")?;
        let hub = self.hub_url()?;
        let digest = crate::proof_digest(&self.id, &assertion.compute_txid());
        let url = format!(
            "{hub}{}",
            crate::PROOF.replace("{id}", &crate::hex_id(&self.id))
        );
        let body = self.keys.sign_as_claim(&digest).to_vec();
        let bytes = super::fold::post(self.wallet, &hub, &url, body).await?;
        ensure!(bytes.len() == 96, "{} bytes, not π2 and π3", bytes.len());
        let (pi2, pi3) = bytes.split_at(64);
        self.o
            .verify_assertion(&HubProves::with_pair(assertion, pi2, pi3)?)
    }

    /// The hub's address her contract was opened with.
    fn hub_url(&self) -> Result<String> {
        let contract = (self.store.list()?.into_iter().find(|c| c.id == self.id))
            .context("no such contract")?;
        Ok(contract.hub.trim_end_matches('/').to_owned())
    }

    /// Whether the hub's response bears out the reduction of her claim,
    /// from the evidence it shows her under her claim key and what Bitcoin
    /// shows of the claim and the response's disclosure: the statement's
    /// own test ([`licash_hp::bears_out`]), so that none the hub could
    /// prove says otherwise. None if it cannot be told yet, and `may_wait`:
    /// the disclosure its evidence needs not in a block.
    async fn check_response(&self, state: &State, may_wait: bool) -> Result<Option<bool>> {
        let response = state.response.as_ref().context("no response")?;
        let response_height = state.response_height.context("no response height")?;
        let reduced = graph::responded(&self.o.base, response)?;
        let (amount, claim_digest) =
            graph::requested(&self.o.base, state.r.as_ref().context("no R")?)?;
        let request = Request {
            amount,
            claim_digest,
        };
        let filed = self.filed(&self.filing_of(state)?);
        let parts = self.o.base.parts();

        // What the hub responded on.
        let hub = &self.hub_url()?;
        let digest = crate::evidence_digest(&self.id, &response.compute_txid());
        let url = format!(
            "{hub}{}",
            crate::EVIDENCE.replace("{id}", &crate::hex_id(&self.id))
        );
        let body = self.keys.sign_as_claim(&digest).to_vec();
        let bytes = super::fold::post(self.wallet, hub, &url, body).await?;
        let evidence = match bytes.is_empty() {
            true => Vec::new(),
            false => licash::recovery::evidence_from_bytes(
                &parts.keyset,
                parts.limits.max_authorizations as usize,
                &bytes,
            )?,
        };

        // The headers through her publication's block, from Base's checkpoint.
        let published = state.p_height.context("no publication height")?;
        let from = parts.chain.checkpoint.height().saturating_add(1);
        let mut headers = Vec::new();
        for height in from..=published.min(from.saturating_add(parts.chain.max_headers)) {
            let header = self.chain.header(height).await.map_err(|e| anyhow!(e))?;
            let bytes: [u8; 80] = bitcoin::consensus::serialize(&header)
                .try_into()
                .map_err(|_| anyhow!("a header of 80 bytes"))?;
            headers.push(bytes);
        }

        // What the response disclosed, once its block is known.
        let tip = self.chain.height().await.map_err(|e| anyhow!(e))?;
        let slot = OutPoint {
            txid: response.compute_txid(),
            // Lichen's `SLOT_VOUT`: the response's disclose slot.
            vout: 2,
        };
        let out = response
            .output
            .get(slot.vout as usize)
            .context("no disclose slot")?;
        let disclosed =
            match first_spend(self.chain, slot, &out.script_pubkey, response_height..=tip).await? {
                None => None,
                Some((at, spend)) => {
                    let hash = self.chain.hash(at).await.map_err(|e| anyhow!(e))?;
                    let block = self.chain.block(&hash).await.map_err(|e| anyhow!(e))?;
                    let carrier = licash_hp::carrier(&self.o.base);
                    Some(dispute::disclosed(
                        carrier,
                        response,
                        &block,
                        &spend.compute_txid(),
                    )?)
                }
            };

        match licash_hp::bears_out(
            &self.o.base,
            &request,
            &filed,
            &evidence,
            &headers,
            reduced,
            disclosed.as_deref(),
        ) {
            Ok(()) => Ok(Some(true)),
            Err(licash_hp::Refusal::Undisclosed) if disclosed.is_none() && may_wait => Ok(None),
            Err(refusal) => {
                tracing::warn!(
                    id = %crate::hex_id(&self.id),
                    "the hub's response is not borne out by its evidence: {refusal}"
                );
                Ok(Some(false))
            }
        }
    }

    /// Her contest is made: posted, with its fee child, until it is in a
    /// block, or the hub's terminal is first.
    async fn contesting(&self, state: &mut State, tip: u32) -> Result<Next> {
        let (parent, height) = self.parent(Stage::Contesting, state)?;
        let op = OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        };
        let from = state.from.unwrap_or(height).max(height);
        if let Some((at, tx)) =
            first_spend(self.chain, op, &parent.output[0].script_pubkey, from..=tip).await?
        {
            return self.observed(Stage::Contesting, state, at, tx);
        }
        state.from = Some(rescan(from, tip));
        let due = height
            .checked_add(blocks(
                presign(&self.o.set, "respond_timeout")?.tx.input[0].sequence,
            )?)
            .context("deadline overflow")?;
        self.post_contest(state, due, tip).await
    }

    fn plan_terminal(&self, state: &mut State, name: &str, due: u32) -> Result<Next> {
        let p = presign(&self.o.set, name)?;
        let tx = dispute::add_fee(
            self.o.finish(name, vec![])?,
            p.prevout.clone(),
            fee_coin(state)?,
            &self.keys.party.payment,
        )?;
        state.payout = Some(tx);
        state.payout_name = Some(name.into());
        state.payout_height = None;
        state.next_at = Some(due);
        // Broadcast happens only in the subsequent, durably stored stage.
        Ok(Next::To(if name == "success" {
            Stage::Succeeding
        } else {
            Stage::TimingOut
        }))
    }
    async fn watch(&self, stage: Stage, state: &mut State, tip: u32) -> Result<Next> {
        let (parent, height) = self.parent(stage, state)?;
        let op = OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        };
        let from = state.from.unwrap_or(height).max(height);
        if let Some((height, tx)) =
            first_spend(self.chain, op, &parent.output[0].script_pubkey, from..=tip).await?
        {
            return self.observed(stage, state, height, tx);
        }
        state.from = Some(rescan(from, tip));
        if stage == Stage::Answered {
            return self.answered(state, height, tip).await;
        }
        if stage == Stage::Challenging {
            if state.next_at.is_none_or(|due| tip.saturating_add(1) >= due) {
                return self.post_challenge(state, height, tip).await;
            }
            return Ok(Next::Save);
        }
        if stage == Stage::Asserted && state.verified == Some(false) && state.challenge.is_none() {
            // Its π2 and π3 the block shows may be a relayer's or a
            // miner's: she asks the hub for its own first, a while.
            let due = height
                .checked_add(blocks(
                    presign(&self.o.set, "success")?.tx.input[0].sequence,
                )?)
                .context("deadline overflow")?;
            let by = due
                .saturating_sub(1)
                .saturating_sub(self.o.base.parts().graph.deadline_margin);
            let wait_until = height.saturating_add(by.saturating_sub(height) / 2);
            let unproved = match self.hub_proves(state).await {
                Ok(true) => None,
                Ok(false) => Some("the hub shows no π2 and π3 that prove it".to_owned()),
                Err(e) => Some(format!("the hub shows no π2 and π3 of it: {e:#}")),
            };
            match unproved {
                None => state.verified = Some(true),
                Some(_) if tip < wait_until => {
                    state.next_at = Some(tip.saturating_add(1));
                    return Ok(Next::Save);
                }
                Some(why) => self.trouble(format!(
                    "the hub's assertion does not prove its statement as mined, and {why}: \
                     she challenges it"
                )),
            }
        }
        if stage == Stage::Asserted && state.verified == Some(false) {
            // One made before, its assertion's block since replaced: the
            // same again, never revealed anew.
            let challenge = match state.challenge.take() {
                Some(made) => made,
                None => self.o.challenge(
                    &self.keys,
                    state.assertion.as_ref().context("no assertion")?,
                )?,
            };
            state.next_at = Some(height + blocks(challenge.input[0].sequence)?);
            state.challenge = Some(challenge);
            return Ok(Next::To(Stage::Challenging));
        }
        let name = match stage {
            Stage::Requested => "request_timeout",
            Stage::Contested => "contest_timeout",
            Stage::Asserted => {
                ensure!(
                    state.verified == Some(true),
                    "assertion validity is unknown"
                );
                // Her claim never published (the hub reclaimed its slot):
                // nothing of it hers but her reserve's dust, so the hub
                // posts it, its reserve paid by it.
                if state.reclaimed {
                    return Ok(Next::Save);
                }
                "success"
            }
            Stage::Challenged => "failure",
            _ => bail!("no timeout at {}", stage.as_str()),
        };
        let due = height
            .checked_add(blocks(presign(&self.o.set, name)?.tx.input[0].sequence)?)
            .context("deadline overflow")?;
        state.next_at = Some(due);
        if tip.saturating_add(1) < due {
            return Ok(Next::Save);
        }
        self.plan_terminal(state, name, due)
    }
    /// Her coin for a challenge's fee child set aside while a false
    /// assertion may still call for one: from her publication until the
    /// hub's assertion verifies, or the child takes it. Set aside again at
    /// each round, as a reorganization frees it; freed otherwise, and the
    /// child's coins once the challenge is over. Without such a coin, she
    /// is told. Left as it is while her publication is signed, the first
    /// time or bumped: neither set aside nor freed for her publication to
    /// take.
    fn hold_challenge_coin(&self, stage: Stage, state: &State) -> Result<()> {
        if stage == Stage::Signing {
            return Ok(());
        }
        let marker = challenge_marker(&self.id);
        if !challenge_possible(stage, state) {
            // Nothing under it, or freed already: no error.
            let _ = self.wallet.abandon_silent(&marker);
            if let Some(child) = state.challenge_child.as_ref() {
                if stage != Stage::Challenging {
                    let _ = self.wallet.abandon_silent(&child.compute_txid());
                }
            }
            return Ok(());
        }
        let coins = self.wallet.silent_coins()?;
        if coins.iter().any(|c| c.spending == Some(marker)) {
            return Ok(());
        }
        let need = challenge_reserve(self.rate);
        let free = super::coins(self.wallet, self.wallet_file)?;
        match free
            .iter()
            .filter(|c| c.value >= need.to_sat())
            .min_by_key(|c| c.value)
        {
            // Taken meanwhile by a spend of hers: set aside next round.
            Some(coin) => match self.wallet.reserve_silent(&coin.outpoint, &marker) {
                Ok(()) => tracing::info!(
                    id = %crate::hex_id(&self.id), coin = %coin.outpoint, value = coin.value,
                    "a coin set aside for a challenge's fee"
                ),
                Err(e) => tracing::warn!(
                    id = %crate::hex_id(&self.id), coin = %coin.outpoint,
                    "a coin not set aside for a challenge's fee: {e}"
                ),
            },
            // Not what stops a step: she was told before forcing the close
            // ([`challenge_shortfall`]).
            None => tracing::warn!(
                id = %crate::hex_id(&self.id), need = need.to_sat(),
                "no coin of hers to set aside for a challenge's fee: a challenge pays what her coins hold"
            ),
        }
        Ok(())
    }

    /// What her challenge wins, its fee child's fee at most: her claim
    /// past the hub's response, and the hub's reserve.
    fn challenge_stake(&self, state: &State) -> Result<Amount> {
        let (b, _) = graph::requested(&self.o.base, state.r.as_ref().context("no R")?)?;
        let responded = graph::responded(
            &self.o.base,
            state.response.as_ref().context("no response")?,
        )?;
        let unit = Amount::from_sat(self.o.base.parts().graph.unit_sats);
        Ok(unit * u64::from(b.saturating_sub(responded)) + self.o.babe.spec.terms.reserve_hub)
    }

    /// Her challenge, once valid, posted with a fee child as one package:
    /// at the rate [`deadline::rate`] gives for the blocks left until the
    /// hub's `success` is valid, made again at a higher one while it is in
    /// no block, its fee at most what the challenge wins
    /// ([`Self::challenge_stake`]), she told above that. Its coins: the
    /// one set aside, else her smallest that pays; a replacement spends
    /// the last child's, and one more of hers if short (her coins are in
    /// blocks: BIP125 takes them). A child made is kept, its coins freed
    /// of the last, before a signature of them leaves; the next round
    /// signs and broadcasts it.
    async fn post_challenge(&self, state: &mut State, asserted_at: u32, tip: u32) -> Result<Next> {
        let challenge = state.challenge.clone().context("no pinned challenge")?;
        let g = &self.o.base.parts().graph;
        let wait = blocks(presign(&self.o.set, "success")?.tx.input[0].sequence)?;
        let deadline = asserted_at
            .saturating_add(wait)
            .saturating_sub(1)
            .saturating_sub(g.deadline_margin);
        let link = Link {
            name: "challenge_assert",
            tx: challenge,
            stage: Stage::Challenging,
            opened: state.next_at.unwrap_or(asserted_at),
            deadline,
            stake: self.challenge_stake(state)?,
            set_aside: true,
        };
        self.post_link(state, link, tip).await
    }

    /// Her contest, once decided on, posted as her challenge is
    /// ([`Self::post_link`]): in a block before the hub's terminal can be,
    /// `due` blocks after the response, which her check of its evidence
    /// did not bear out. It costs her only its fee, and the hub a proof.
    async fn post_contest(&self, state: &mut State, due: u32, tip: u32) -> Result<Next> {
        let g = &self.o.base.parts().graph;
        let link = Link {
            name: "contest",
            tx: state.contest.clone().context("no pinned contest")?,
            stage: Stage::Contesting,
            opened: state.response_height.unwrap_or(tip),
            deadline: due.saturating_sub(1).saturating_sub(g.deadline_margin),
            stake: self.challenge_stake(state)?,
            set_aside: false,
        };
        self.post_link(state, link, tip).await
    }

    /// `link` broadcast with a fee child, as [`Self::post_challenge`]
    /// describes of her challenge.
    async fn post_link(&self, state: &mut State, link: Link, tip: u32) -> Result<Next> {
        let Link {
            name,
            tx: challenge,
            stage,
            opened,
            deadline,
            stake,
            set_aside,
        } = link;
        let left = deadline.saturating_sub(tip);
        if tip >= opened.saturating_add(deadline.saturating_sub(opened) / 2) {
            self.trouble(format!(
                "her {name} is in no block halfway to block {deadline}, when the hub's \
                 payout becomes valid: its fee rises as that nears"
            ));
        }
        let estimate = self
            .chain
            .fee_rate(deadline::target(left))
            .await
            .ok()
            .flatten();
        let one = FeeRate::from_sat_per_vb_u32(1);
        let mut rate = deadline::rate(
            estimate,
            if estimate.is_some() { one } else { self.rate },
            left,
        );
        let old = state.challenge_child.clone();
        if rate <= one && old.is_none() {
            self.broadcast(&challenge).await;
            return Ok(Next::Save);
        }
        let presigned = presign(&self.o.set, name)?;
        let paid: Amount = challenge.output.iter().map(|o| o.value).sum();
        let link_fee = presigned
            .prevout
            .value
            .checked_sub(paid)
            .with_context(|| format!("a {name} paying out more"))?;
        let fee_script = dispute::fee_script(&self.keys.party.payment)?;
        let anchor = challenge
            .output
            .get(dispute::ANCHOR_VOUT as usize)
            .with_context(|| format!("a {name} without an anchor"))?;
        ensure!(
            anchor.script_pubkey == fee_script,
            "the {name}'s anchor is not hers"
        );
        let output = |op: &OutPoint| -> Result<Option<(OutPoint, TxOut)>> {
            Ok(self.wallet.silent_coin_output(op)?.map(|out| (*op, out)))
        };
        // Its coins: the last child's still hers, else the one set aside.
        let mut coins = Vec::new();
        match &old {
            Some(old) => {
                for input in old.input.iter().skip(1) {
                    coins.extend(output(&input.previous_output)?);
                }
            }
            // The coin set aside is a challenge's: a contest takes another.
            None if set_aside => {
                let marker = challenge_marker(&self.id);
                let held = self.wallet.silent_coins()?;
                if let Some(c) = held.iter().find(|c| c.spending == Some(marker)) {
                    coins.extend(output(&c.outpoint)?);
                }
            }
            None => {}
        }
        let change = match &old {
            Some(old) => old.output[0].script_pubkey.clone(),
            None => self.wallet.fallback_address()?.script_pubkey(),
        };
        let key = &self.keys.party.payment;
        let sign = |tx: &mut Transaction, prevouts: &[TxOut]| {
            for i in 0..tx.input.len() {
                if prevouts[i].script_pubkey == fee_script {
                    dispute::sign_fee_input(key, tx, i, prevouts)?;
                } else {
                    // Her wallet's signature, of a key spend, at broadcast.
                    tx.input[i].witness = Witness::from_slice(&[[0u8; 64]]);
                }
            }
            Ok(())
        };
        let pair_vb = |child: &Transaction| challenge.vsize() as u64 + child.vsize() as u64;
        let build = |coins: &[(OutPoint, TxOut)], rate| {
            dispute::link_child(&challenge, link_fee, coins, change.clone(), rate, sign)
        };
        // Short: one coin more of hers, the smallest that pays, else her
        // largest.
        if build(&coins, rate).is_err() {
            let have: Amount = coins.iter().map(|c| c.1.value).sum();
            let need = rate
                .fee_vb(challenge.vsize() as u64 + 200)
                .context("fee overflow")?
                .checked_sub(link_fee + have)
                .unwrap_or(Amount::ZERO)
                + DUST;
            let mut free = super::coins(self.wallet, self.wallet_file)?;
            // None it spends already: a coin twice is no transaction.
            free.retain(|c| !coins.iter().any(|(op, _)| *op == c.outpoint));
            free.sort_by_key(|c| c.value);
            let pick = (free.iter().find(|c| c.value >= need.to_sat())).or(free.last());
            if let Some(c) = pick {
                coins.extend(output(&c.outpoint)?);
            }
        }
        // Its rate the stake's at most, and what her coins pay at most:
        // weighed at the floor, its size the same at any rate.
        let child = build(&coins, one).and_then(|sized| {
            let pair = (pair_vb(&sized) * 4).max(1);
            let per_kwu = |sat: Amount| FeeRate::from_sat_per_kwu(sat.to_sat() * 1_000 / pair);
            let most = per_kwu(stake + link_fee);
            if rate > most {
                self.trouble(format!(
                    "her {name} would pay {rate} to be in a block by block {deadline}, \
                     more than the {stake} it wins: it pays {most}"
                ));
                rate = most;
            }
            let have: Amount = coins.iter().map(|c| c.1.value).sum::<Amount>() + anchor.value;
            let dust = change.minimal_non_dust();
            let afford = per_kwu((have + link_fee).checked_sub(dust).unwrap_or(Amount::ZERO));
            if rate > afford {
                self.trouble(format!(
                    "too little of hers on Bitcoin for her {name} to pay {rate} to be in a \
                     block by block {deadline}: it pays {afford}"
                ));
                rate = afford;
            }
            build(&coins, rate)
        });
        let child = match child {
            Ok(child) => child,
            Err(e) => {
                self.trouble(format!(
                    "too little of hers on Bitcoin to pay her {name}'s fee: {e:#}"
                ));
                return self.post_child(state, &challenge, stage).await;
            }
        };
        let fee = |tx: &Transaction| {
            let value: Amount = tx
                .input
                .iter()
                .filter_map(|i| {
                    let op = i.previous_output;
                    let anchor = (op.txid == challenge.compute_txid()).then(|| anchor.clone());
                    anchor.or_else(|| coins.iter().find(|c| c.0 == op).map(|c| c.1.clone()))
                })
                .map(|o| o.value)
                .sum();
            let paid: Amount = tx.output.iter().map(|o| o.value).sum();
            value.checked_sub(paid).unwrap_or(Amount::ZERO)
        };
        let child = match &old {
            None => Some(child),
            Some(old) => {
                let (new, before) = (fee(&child), fee(old));
                if new <= before {
                    None
                } else if deadline::replaces(new, child.vsize() as u64, before) {
                    Some(child)
                } else {
                    // The least that replaces it, as a rate of the pair.
                    let least = before.to_sat() + child.vsize() as u64 + link_fee.to_sat();
                    let least =
                        FeeRate::from_sat_per_kwu((least * 1_000).div_ceil(pair_vb(&child) * 4));
                    build(&coins, least).ok().filter(|c| {
                        fee(c) <= stake && deadline::replaces(fee(c), c.vsize() as u64, before)
                    })
                }
            }
        };
        let Some(child) = child else {
            return self.post_child(state, &challenge, stage).await;
        };
        // Its coins freed of the last child, or of being set aside, and the
        // new one kept: signed and broadcast next round.
        if let Some(old) = &old {
            let _ = self.wallet.abandon_silent(&old.compute_txid());
        }
        if set_aside {
            let _ = self.wallet.abandon_silent(&challenge_marker(&self.id));
        }
        tracing::info!(
            id = %crate::hex_id(&self.id), txid = %child.compute_txid(), %rate,
            "her {name}'s fee child made"
        );
        state.challenge_child = Some(child);
        Ok(Next::To(stage))
    }

    /// Her link `link` (a challenge, or her contest) broadcast with its last
    /// fee child, if any, as one package: the child's coins of her wallet
    /// signed again, which sets them aside again. A coin of it taken
    /// meanwhile, the child is made again (once a run), at `stage`.
    async fn post_child(
        &self,
        state: &mut State,
        challenge: &Transaction,
        stage: Stage,
    ) -> Result<Next> {
        let Some(mut child) = state.challenge_child.clone() else {
            self.broadcast(challenge).await;
            return Ok(Next::Save);
        };
        let fee_script = dispute::fee_script(&self.keys.party.payment)?;
        let mut prevouts = Vec::new();
        for input in &child.input {
            let op = input.previous_output;
            let out = match op.txid == challenge.compute_txid() {
                true => challenge.output.get(op.vout as usize).cloned(),
                false => self.wallet.silent_coin_output(&op)?,
            };
            prevouts.push(out);
        }
        let prevouts: Option<Vec<TxOut>> = prevouts.into_iter().collect();
        let mut taken = prevouts.is_none();
        if let Some(prevouts) = &prevouts {
            for i in 0..child.input.len() {
                if prevouts[i].script_pubkey == fee_script {
                    continue;
                }
                match self.wallet.sign_input(&child, prevouts, i) {
                    Ok(signed) => child.input[i].witness = signed.input[i].witness.clone(),
                    Err(
                        e @ (licash_wallet::Error::Invalid(_) | licash_wallet::Error::NoteTaken),
                    ) => {
                        tracing::warn!(id = %crate::hex_id(&self.id), "a coin of her challenge's child taken: {e}");
                        taken = true;
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if taken {
            ensure!(
                !self.rebuilt.swap(true, Ordering::SeqCst),
                "a coin of her challenge's child taken again"
            );
            let _ = self.wallet.abandon_silent(&child.compute_txid());
            state.challenge_child = None;
            return Ok(Next::To(stage));
        }
        if let Err(e) = self
            .chain
            .broadcast_package(&[challenge.clone(), child.clone()])
            .await
        {
            self.trouble(format!("{} and its child: {e}", challenge.compute_txid()));
        }
        Ok(Next::Save)
    }

    async fn finishing(&self, state: &mut State, tip: u32) -> Result<Next> {
        let name = state.payout_name.as_deref().context("no pinned terminal")?;
        let stage = match name {
            "request_timeout" => Stage::Requested,
            "respond_timeout" => Stage::Answered,
            "contest_timeout" => Stage::Contested,
            "failure" => Stage::Challenged,
            "success" => Stage::Asserted,
            _ => bail!("not a locally posted terminal"),
        };
        let (parent, height) = self.parent(stage, state)?;
        let from = state.from.unwrap_or(height).max(height);
        let op = OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        };
        if let Some((height, tx)) =
            first_spend(self.chain, op, &parent.output[0].script_pubkey, from..=tip).await?
        {
            return self.observed(stage, state, height, tx);
        }
        state.from = Some(rescan(from, tip));
        if state.next_at.is_none_or(|due| tip.saturating_add(1) >= due) {
            // Her fee coin her commitment's, her claim's slot reclaimed: it
            // may be in no block, P never was.
            if let (true, Some(c)) = (state.reclaimed, &state.c) {
                self.broadcast(c).await;
            }
            self.broadcast(state.payout.as_ref().context("no pinned payout")?)
                .await;
        }
        Ok(Next::Save)
    }
    fn sweep(&self, state: &mut State, tip: u32) -> Result<Next> {
        let payout = state.payout.as_ref().context("no payout")?;
        let paid = payout.compute_txid();
        let height = state.payout_height.context("payout is unconfirmed")?;
        let name = state
            .payout_name
            .as_deref()
            .context("payout provenance is unknown")?;
        // The words signed, as the chain shows them: their bits select the
        // outputs.
        let (word, wire, value_key, signer) = match name {
            "request_timeout" | "contest_timeout" | "failure" => {
                let r = state.r.as_ref().context("no R")?;
                let (b, _) = HubProves::read_request(&link_args(r))?;
                (
                    HubProves::requested_word(r)?.0,
                    HubProves::b_wire(&b),
                    &self.o.holder.b_key,
                    Role::User,
                )
            }
            "success" | "respond_timeout" => {
                let (b, wire) =
                    HubProves::responded_word(state.response.as_ref().context("no response")?)?;
                (b, wire, &self.o.hub.b_key, Role::Hub)
            }
            n if n.starts_with("wrongly_challenged_") => {
                presign(&self.o.set, n)?;
                let (b, wire) =
                    HubProves::responded_word(state.response.as_ref().context("no response")?)?;
                (b, wire, &self.o.hub.b_key, Role::Hub)
            }
            _ => bail!("unknown payout provenance"),
        };
        let payout = Payout {
            transaction: payout,
            value_key,
            signer,
            word,
            wire: &wire,
        };
        let owned = self.o.babe.core().owned(
            payout.transaction,
            payout.value_key,
            payout.signer,
            payout.word,
            Role::User,
        )?;
        let left = left_over(state, self.rate)?;
        let to = self.wallet.fallback_address()?.script_pubkey();
        let key = &self.keys.party.payment;
        let sweep = |left: &[(OutPoint, TxOut)]| {
            let payout = Payout { ..payout };
            dispute::sweep_with(
                &self.o.babe,
                key,
                payout,
                Role::User,
                to.clone(),
                self.rate,
                left,
            )
        };
        let sweep = match owned.is_empty() && left.is_empty() {
            true => None,
            false => match sweep(&left) {
                Ok(sweep) => Some(sweep),
                // What is left her is worth less than its fee: the payout's
                // swept alone, if hers is any.
                Err(e) if !left.is_empty() => {
                    tracing::debug!(id = %crate::hex_id(&self.id), "left over not swept: {e:#}");
                    (!owned.is_empty()).then(|| sweep(&[])).transpose()?
                }
                Err(e) => return Err(e),
            },
        };
        let Some(sweep) = sweep else {
            // Nothing of the payout is hers (a corrected zero): done.
            state.swept_height = Some(height);
            state.next_at = None;
            return Ok(Next::To(Stage::Done));
        };
        let delay = sweep
            .input
            .iter()
            .map(|i| blocks(i.sequence))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        let due = height.checked_add(delay).context("sweep delay overflow")?;
        state.next_at = Some(due);
        if tip.saturating_add(1) < due {
            return Ok(Next::Save);
        }
        // One made before of the same payout, or of what is left her alone,
        // its block since replaced: the same again, as a block may hold it.
        let leftover = |op: &OutPoint| left.iter().any(|(o, _)| o == op);
        let made = (state.sweep.take()).filter(|old| {
            (old.input.iter()).any(|i| i.previous_output.txid == paid)
                || (old.input.first()).is_some_and(|i| leftover(&i.previous_output))
        });
        state.sweep = Some(made.unwrap_or(sweep));
        state.from = Some(height);
        state.next_at = None;
        Ok(Next::To(Stage::Sweeping))
    }
    async fn swept(&self, state: &mut State, tip: u32) -> Result<Next> {
        let sweep = state.sweep.as_ref().context("no pinned sweep")?;
        let payout = state.payout.as_ref().context("no payout")?;
        let coin = sweep.input.first().context("empty sweep")?.previous_output;
        // A payout's output, or her request's left to her (its purse), or
        // P's fee coin.
        let r = state.r.as_ref().context("no R")?;
        let from_tx = [Some(payout), Some(r), state.p.as_ref()]
            .into_iter()
            .flatten()
            .find(|tx| tx.compute_txid() == coin.txid)
            .context("unknown sweep input")?;
        let script = &from_tx
            .output
            .get(coin.vout as usize)
            .context("unknown sweep input")?
            .script_pubkey;
        let from = state
            .from
            .unwrap_or(state.payout_height.context("payout is unconfirmed")?);
        match first_spend(self.chain, coin, script, from..=tip).await? {
            Some((height, tx)) if tx.compute_txid() == sweep.compute_txid() => {
                // Done once as deep as F had to be: looked for again until
                // then, from where it was, and broadcast again if it left
                // the chain.
                if !deep(height, tip, self.o.base.parts().chain.funding_depth) {
                    return Ok(Next::Wait);
                }
                state.swept_height = Some(height);
                state.next_at = None;
                Ok(Next::To(Stage::Done))
            }
            Some((_, tx)) => {
                self.trouble(format!("her payout went to {} instead", tx.compute_txid()));
                Ok(Next::To(Stage::Lost))
            }
            None => {
                state.from = Some(rescan(from, tip));
                self.broadcast(sweep).await;
                Ok(Next::Save)
            }
        }
    }
}

/// What `notes` and `locks` leave of `slot`'s cap and count.
fn left_of(slot: &ClaimSlot, notes: &[ClaimNote], locks: &[LockClaim]) -> (u64, usize) {
    let held = (notes.iter().map(|n| n.note.message().denomination()))
        .chain(locks.iter().map(|l| l.value))
        .fold(0u64, u64::saturating_add);
    let keys = notes.len() + locks.iter().map(|l| l.keys.len()).sum::<usize>();
    (slot.cap.saturating_sub(held), slot.max.saturating_sub(keys))
}

/// Her close on a fold of her claim ([`Stage::Folding`]).
impl<T: Transport, C: Chain> Run<'_, T, C> {
    /// Her notes taken as a forced close would take them, her contract's
    /// slot alone, the claim of them filed and pinned: settled notes only,
    /// the locks left to a forced close. None if the wallet holds none.
    async fn take_for_fold(&self) -> Result<Option<FoldClaim>> {
        // The close it falls back to must be one she can make.
        self.o.forcible()?;
        let parts = self.o.base.parts();
        let slot = self.own_slot()?;
        let notes = self.wallet.claim_notes(&self.id, &[slot])?;
        self.took.store(!notes.is_empty(), Ordering::SeqCst);
        if notes.is_empty() {
            return Ok(None);
        }
        let held: u64 = (notes.iter())
            .map(|n| n.note.message().denomination())
            .sum();
        let mut state = State {
            amount: parts.cap.min(u32::try_from(held).unwrap_or(u32::MAX)),
            ..State::default()
        };
        let filing = self.filing(&notes, &[], &[], state.amount)?;
        state.notes = notes.iter().map(|n| hex::encode(n.to_bytes())).collect();
        state.filing = Some(hex::encode(filing.to_bytes(Format::of(&self.o.base))));
        let row = self.store.recovery(&self.id)?.context("given up")?;
        ensure!(
            self.store.save_recovery(
                &self.id,
                (&row.stage, &row.state),
                Stage::Folding.as_str(),
                false,
                &state.encode()
            )?,
            "the close kept moving on: try again"
        );
        let mut claim = self.claim_of_fold(&state)?;
        claim.fresh = true;
        Ok(Some(claim))
    }

    /// The claim pinned in `state`.
    fn claim_of_fold(&self, state: &State) -> Result<FoldClaim> {
        let filing = self.filing_of(state)?;
        let notes = (filing.publication().claim().parts().items.iter())
            .map(|item| item.message().identifier())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(FoldClaim {
            filing,
            amount: state.amount,
            notes,
            fresh: false,
        })
    }

    /// The slot her contract claims in, its own: a fold takes what it can
    /// of her notes, not leaving them to the others she holds there.
    fn own_slot(&self) -> Result<ClaimSlot> {
        let all = self.store.list()?;
        let this = (all.iter().find(|c| c.id == self.id)).context("a contract not stored")?;
        let mut terms = std::collections::HashMap::new();
        terms.insert(self.id, ClaimTerms::of(&self.o));
        (claims::claim_slots([this], &terms).into_iter().next()).context("a contract with no slot")
    }

    /// What the fold of her claim pays her: its first output, her claim and
    /// her reserve, to her wallet. The fee comes of the hub's share.
    fn fold_output(&self, state: &State) -> Result<TxOut> {
        let b = Amount::from_sat(u64::from(state.amount) * self.o.base.parts().graph.unit_sats);
        let fold = crate::fold(&self.o.babe, &self.o.funding, b, Amount::ZERO)?;
        fold.tx
            .output
            .first()
            .cloned()
            .context("a fold of no output")
    }

    /// The block from which a fold not seen on Bitcoin gives way to her
    /// request. The hub holds her claim's notes retired: filing it is all
    /// that pays her then.
    fn force_at(&self, tip: u32) -> Result<u32> {
        let seed = self.wallet.contract_secrets().seed;
        fold_by(
            &seed,
            self.wallet.network(),
            self.wallet_file,
            &self.id,
            tip,
        )
    }

    /// Her contract's collateral still unspent: the hub folds it, or the
    /// claim is filed on Bitcoin at the block a forced close is planned
    /// for, before the contract's default would pay the hub all.
    async fn folding(&self, state: &mut State, tip: u32) -> Result<Next> {
        let p = presign(&self.o.set, "request")?;
        let coin = p.tx.input[0].previous_output;
        let f_height = match state.f_height {
            Some(height) => height,
            None => confirmed_at(
                self.chain,
                coin.txid,
                &p.prevout.script_pubkey,
                self.since..=tip,
            )
            .await?
            .context("F in no block")?,
        };
        state.f_height = Some(f_height);
        let from = state.from.unwrap_or(f_height);
        if let Some((height, tx)) =
            first_spend(self.chain, coin, &p.prevout.script_pubkey, from..=tip).await?
        {
            return self.folded(state, &tx, height, tip);
        }
        state.from = Some(rescan(from, tip));
        if tip.saturating_add(1) >= self.force_at(tip)? {
            self.trouble(
                "the hub did not fold her contract in time: her claim is filed on Bitcoin".into(),
            );
            return Ok(Next::To(Stage::Claimed));
        }
        // Signed by both: broadcast again, as it may have left the mempool.
        if let Some(fold) = &state.fold {
            self.broadcast(fold).await;
        }
        Ok(Next::Save)
    }

    /// Her contract's collateral spent by `tx`, mined at `height`, while
    /// she held a claim of notes the hub retired: the fold of her claim if
    /// it pays what she claimed, else her notes are paid for by none. Done
    /// once as deep as F had to be.
    fn folded(&self, state: &mut State, tx: &Transaction, height: u32, tip: u32) -> Result<Next> {
        let p = presign(&self.o.set, "request")?;
        let coin = p.tx.input[0].previous_output;
        let key_path = tx
            .input
            .first()
            .is_some_and(|i| i.previous_output == coin && i.witness.len() == 1);
        if !key_path || tx.output.first() != Some(&self.fold_output(state)?) {
            self.trouble(format!(
                "her contract's collateral went to {}, which does not pay what she claimed",
                tx.compute_txid()
            ));
            return Ok(Next::To(Stage::Lost));
        }
        state.fold = Some(tx.clone());
        state.from = Some(height);
        if !deep(height, tip, self.o.base.parts().chain.funding_depth) {
            return Ok(Next::Save);
        }
        state.fold_height = Some(height);
        state.next_at = None;
        Ok(Next::To(Stage::Done))
    }
}

fn blocks(sequence: Sequence) -> Result<u32> {
    match sequence.to_relative_lock_time() {
        Some(bitcoin::relative::LockTime::Blocks(h)) => Ok(h.value() as u32),
        None => Ok(0),
        Some(other) => bail!("a relative lock of {other}, not in blocks"),
    }
}
/// What is left hers alone once her payout confirmed, swept with it, each
/// worth more than its input's fee at `rate`: her request's anchor and
/// purse, if her claim's slot was reclaimed, P never published to spend
/// them, or else P's fee coin, unless her payout spent it (hers, as its
/// fee coin). Only her terminals spend P's, each spending the dispute's
/// coin the confirmed payout spent: once the hub's terminal pays her, it
/// was left hers, up to half her reserve on Mutinynet. Her links'
/// anchors are not: a fee child of hers no longer kept may still
/// confirm.
fn left_over(state: &State, rate: FeeRate) -> Result<Vec<(OutPoint, TxOut)>> {
    let payout = state.payout.as_ref().context("no payout")?;
    let spent: Vec<OutPoint> = payout.input.iter().map(|i| i.previous_output).collect();
    let coins: Vec<(OutPoint, TxOut)> = match state.reclaimed {
        true => {
            let r = state.r.as_ref().context("no R")?;
            let anchor = OutPoint {
                txid: r.compute_txid(),
                vout: 1,
            };
            let anchor = r.output.get(1).map(|out| (anchor, out.clone()));
            anchor.into_iter().chain(Some(purse_coin(state)?)).collect()
        }
        false if state.p_height.is_some() => vec![fee_coin(state)?],
        false => Vec::new(),
    };
    Ok(coins
        .into_iter()
        .filter(|(op, out)| {
            // Its fee leaf spent: a signature, the script and a control
            // block, about 75 vB.
            let worth = rate.fee_vb(75).is_some_and(|fee| out.value > fee);
            worth && !spent.contains(op)
        })
        .collect())
}

/// Where P pays her terminals' fee coin: after its nulldata under a
/// nulldata carrier, first under a leaf one (no nulldata, her commitment
/// kept), its change next.
fn p_fee_vout(state: &State) -> u32 {
    match state.c {
        Some(_) => 0,
        None => 1,
    }
}
/// The script of her commitment's coin carrying her filing, if she made one.
fn committed_script(state: &State) -> Option<ScriptBuf> {
    let c = state.c.as_ref()?;
    Some(
        c.output
            .get(dispute::COMMITTED as usize)?
            .script_pubkey
            .clone(),
    )
}
/// Her purse as it is: R's, or, her commitment made (it may be in blocks,
/// or posted), the commitment's change, which she posts before what spends
/// it. Its coin carrying the filing, dust, is left.
fn purse_coin(state: &State) -> Result<(OutPoint, TxOut)> {
    let (tx, vout) = match &state.c {
        Some(c) => (c, dispute::COMMITTED + 1),
        None => (state.r.as_ref().context("no R")?, PURSE_VOUT),
    };
    let out = tx.output.get(vout as usize).context("no purse")?.clone();
    let op = OutPoint {
        txid: tx.compute_txid(),
        vout,
    };
    Ok((op, out))
}
/// Her terminal's fee coin: P's, or, P never published (her claim's slot
/// reclaimed), her purse ([`purse_coin`]).
fn fee_coin(state: &State) -> Result<(OutPoint, TxOut)> {
    if state.reclaimed {
        return purse_coin(state);
    }
    let (tx, vout) = (state.p.as_ref().context("no P")?, p_fee_vout(state));
    Ok((
        OutPoint {
            txid: tx.compute_txid(),
            vout,
        },
        tx.output
            .get(vout as usize)
            .context("no terminal fee coin")?
            .clone(),
    ))
}
async fn confirmed_at(
    chain: &impl Chain,
    txid: Txid,
    script: &bitcoin::Script,
    heights: std::ops::RangeInclusive<u32>,
) -> Result<Option<u32>> {
    for height in heights {
        let hash = chain.hash(height).await.map_err(|e| anyhow!(e))?;
        if let Some(filter) = chain.filter(&hash).await.map_err(|e| anyhow!(e))? {
            if !bitcoin::bip158::BlockFilter::new(&filter)
                .match_any(&hash, std::iter::once(script.as_bytes()))?
            {
                continue;
            }
        }
        let block = chain.block(&hash).await.map_err(|e| anyhow!(e))?;
        ensure!(
            block.block_hash() == hash && block.check_merkle_root(),
            "block {hash} does not match its header"
        );
        if block.txdata.iter().any(|tx| tx.compute_txid() == txid) {
            return Ok(Some(height));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod driver_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;
    #[test]
    fn a_watch_looks_again_at_the_last_blocks_it_saw() {
        assert_eq!(rescan(100, 200), 198);
        assert_eq!(rescan(199, 200), 199);
        assert_eq!(rescan(0, 1), 0);
        assert_eq!(rescan(150, 150), 150);
    }
    #[test]
    fn a_sweep_is_done_only_as_deep_as_f_had_to_be() {
        // Two deep wanted: mined at the tip, not yet; one block on, done.
        assert!(!deep(100, 100, 2));
        assert!(deep(100, 101, 2));
        // One at least, whatever the chain's terms say.
        assert!(deep(100, 100, 0));
        assert!(deep(100, 100, 1));
        // A tip below it, after a reorganization: not deep.
        assert!(!deep(100, 99, 1));
    }
    #[test]
    fn every_stage_reads_back_and_only_done_or_lost_is_over() {
        for stage in Stage::ALL {
            assert_eq!(Stage::parse(stage.as_str()).unwrap(), stage);
            assert_eq!(stage.over(), matches!(stage, Stage::Done | Stage::Lost));
        }
        assert!(Stage::parse("forgotten").is_err());
    }
    #[test]
    fn state_is_whole_versioned_and_requires_payout_provenance() {
        let mut row = RecoveryRow {
            id: [1; 32],
            format: FORMAT,
            stage: Stage::Requested.as_str().into(),
            irrevocable: true,
            error: None,
            state: State::default().encode(),
            created_at: 0,
        };
        assert_eq!(State::decode(&row).unwrap().encode(), row.state);
        row.format = 1;
        assert!(State::decode(&row).is_err());
        row.format = FORMAT;
        row.state = br#"{"later":1}"#.to_vec();
        assert!(State::decode(&row).is_err());
        row.state = vec![];
        assert!(State::decode(&row).is_err());
    }
    #[test]
    fn a_fold_is_written_only_once_signed_so_a_forced_close_reads_as_before() {
        let row = |stage: Stage, state: Vec<u8>| RecoveryRow {
            id: [1; 32],
            format: FORMAT,
            stage: stage.as_str().into(),
            irrevocable: true,
            error: None,
            state,
            created_at: 0,
        };
        // None of its fields in a recovery that was never a fold: a build
        // before this one reads it, and one of before reads as none.
        let plain = String::from_utf8(State::default().encode()).unwrap();
        for key in ["folds", "fold", "fold_height"] {
            assert!(!plain.contains(&format!("\"{key}\"")), "{plain}");
        }
        let old = row(Stage::Claimed, br#"{"amount":5}"#.to_vec());
        let state = State::decode(&old).unwrap();
        assert!(state.folds.is_empty() && state.fold.is_none() && state.fold_height.is_none());
        // One of a fold keeps what it signed, read again as written.
        let signed = State {
            amount: 5_000,
            folds: vec!["ab".repeat(32), "cd".repeat(32)],
            fold_height: Some(100),
            ..State::default()
        };
        let back = State::decode(&row(Stage::Folding, signed.encode())).unwrap();
        assert_eq!((back.amount, back.fold_height), (5_000, Some(100)));
        assert_eq!(back.folds, signed.folds);
    }
    #[test]
    fn a_publication_fee_allowed_is_written_only_once_set() {
        let plain = String::from_utf8(State::default().encode()).unwrap();
        assert!(!plain.contains("p_allowance"));
        let state = State {
            p_allowance: Some(40_000),
            ..State::default()
        };
        let row = RecoveryRow {
            id: [1; 32],
            format: FORMAT,
            stage: Stage::Published.as_str().into(),
            irrevocable: true,
            error: None,
            state: state.encode(),
            created_at: 0,
        };
        assert_eq!(State::decode(&row).unwrap().p_allowance, Some(40_000));
    }
    #[test]
    fn a_recovery_held_back_by_its_publication_fee_says_so_while_not_over() {
        let row = |stage: Stage, error: Option<&str>| RecoveryRow {
            id: [1; 32],
            format: FORMAT,
            stage: stage.as_str().into(),
            irrevocable: true,
            error: error.map(str::to_owned),
            state: State::default().encode(),
            created_at: 0,
        };
        let capped = format!("her publication would pay 9 in fees, more than the 8: allow more with `licash-wallet {ALLOW_FEE} 00 <sat>`");
        assert!(
            view(&row(Stage::Published, Some(&capped)))
                .unwrap()
                .fee_capped
        );
        assert!(
            !view(&row(Stage::Published, Some("offline")))
                .unwrap()
                .fee_capped
        );
        assert!(!view(&row(Stage::Published, None)).unwrap().fee_capped);
        assert!(!view(&row(Stage::Lost, Some(&capped))).unwrap().fee_capped);
    }
    #[test]
    fn a_rewind_forgets_what_she_saw_above_the_block_that_stood_and_keeps_what_she_signed() {
        let tx = |n: u8| Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_consensus(u32::from(n)),
            input: vec![],
            output: vec![],
        };
        let paid = State {
            r: Some(tx(1)),
            r_height: Some(100),
            p: Some(tx(2)),
            p_height: Some(101),
            response: Some(tx(3)),
            response_height: Some(105),
            reduced: Some(7),
            deadline: Some(150),
            contest: Some(tx(9)),
            contest_height: Some(107),
            assertion: Some(tx(4)),
            assertion_height: Some(110),
            verified: Some(false),
            challenge: Some(tx(5)),
            challenge_child: Some(tx(6)),
            challenge_height: Some(115),
            payout: Some(tx(7)),
            payout_name: Some("failure".into()),
            payout_height: Some(120),
            sweep: Some(tx(8)),
            from: Some(125),
            next_at: Some(126),
            ..State::default()
        };
        let signed = |s: &State| {
            assert_eq!((&s.r, &s.p), (&paid.r, &paid.p));
            assert_eq!(
                (&s.challenge, &s.challenge_child),
                (&paid.challenge, &paid.challenge_child)
            );
            assert_eq!(&s.sweep, &paid.sweep);
        };
        // All she saw stands: her scan only looks again from there.
        let mut s = paid.clone();
        assert_eq!(rewind(Stage::Sweeping, &mut s, 122), Stage::Sweeping);
        assert_eq!(
            (s.from, s.payout_height, s.next_at),
            (Some(123), Some(120), Some(126))
        );
        // Its payout's block replaced: watched for again from its challenge.
        let mut s = paid.clone();
        assert_eq!(rewind(Stage::Sweeping, &mut s, 119), Stage::Challenged);
        assert_eq!(
            (&s.payout, &s.payout_name, s.payout_height),
            (&None, &None, None)
        );
        assert_eq!(
            (s.challenge_height, s.from, s.next_at),
            (Some(115), Some(120), None)
        );
        signed(&s);
        // Its challenge's: watched for from the assertion, kept to post.
        let mut s = paid.clone();
        assert_eq!(rewind(Stage::Sweeping, &mut s, 112), Stage::Asserted);
        assert_eq!((s.challenge_height, s.assertion_height), (None, Some(110)));
        signed(&s);
        // The assertion's: what it verified to forgotten too.
        let mut s = paid.clone();
        assert_eq!(rewind(Stage::Challenged, &mut s, 107), Stage::Contested);
        assert_eq!(
            (&s.assertion, s.verified, s.contest_height),
            (&None, None, Some(107))
        );
        signed(&s);
        // Her contest's: watched for from the response, kept to post again,
        // and what she made of the response stands.
        let mut s = State {
            accepted: Some(false),
            ..paid.clone()
        };
        assert_eq!(rewind(Stage::Contested, &mut s, 106), Stage::Answered);
        assert_eq!(
            (s.contest_height, s.assertion_height, s.response_height),
            (None, None, Some(105))
        );
        assert_eq!((&s.contest, s.accepted), (&paid.contest, Some(false)));
        signed(&s);
        // The answer's: what it said she is owed.
        let mut s = paid.clone();
        assert_eq!(rewind(Stage::Asserted, &mut s, 104), Stage::Requested);
        assert_eq!(
            (&s.response, s.reduced, s.deadline, s.p_height),
            (&None, None, None, Some(101))
        );
        signed(&s);
        // Her publication's, or her request's: published again.
        let mut s = paid.clone();
        assert_eq!(rewind(Stage::Answered, &mut s, 100), Stage::Published);
        assert_eq!((s.r_height, s.p_height), (Some(100), None));
        let mut s = State {
            reclaimed: true,
            ..paid.clone()
        };
        assert_eq!(rewind(Stage::Requested, &mut s, 99), Stage::Published);
        assert_eq!((s.r_height, s.reclaimed, s.from), (None, false, Some(100)));
        assert_eq!(s.next_at, Some(100));
        signed(&s);
        // Her slot reclaimed, at a height not kept: found again however
        // little was replaced.
        let mut s = State {
            reclaimed: true,
            p_height: None,
            ..paid.clone()
        };
        assert_eq!(rewind(Stage::Asserted, &mut s, 130), Stage::Published);
        assert_eq!(
            (s.r_height, s.reclaimed, s.next_at),
            (Some(100), false, None)
        );
        // Her request's own block replaced, her scan not started: from the
        // block after the one that stood, not from F.
        let mut s = State {
            from: None,
            ..paid.clone()
        };
        assert_eq!(rewind(Stage::Requested, &mut s, 90), Stage::Published);
        assert_eq!((s.from, s.next_at), (Some(91), Some(91)));
        // Paid with no answer: watched for from her request.
        let mut s = State {
            r: Some(tx(1)),
            r_height: Some(100),
            p_height: Some(101),
            payout: Some(tx(7)),
            payout_name: Some("request_timeout".into()),
            payout_height: Some(120),
            ..State::default()
        };
        assert_eq!(rewind(Stage::TimedOut, &mut s, 110), Stage::Requested);
        assert_eq!((s.payout_height, s.from), (None, None));
    }
    #[test]
    fn only_a_recovery_published_and_not_over_follows_its_tips() {
        let follows: Vec<_> = (Stage::ALL.into_iter()).filter(|&s| watched(s)).collect();
        assert_eq!(
            follows,
            [
                Stage::Published,
                Stage::Requested,
                Stage::TimingOut,
                Stage::TimedOut,
                Stage::Sweeping,
                Stage::Answered,
                Stage::Asserted,
                Stage::Succeeding,
                Stage::Challenging,
                Stage::Challenged,
                Stage::Paid,
                Stage::Contesting,
                Stage::Contested,
            ]
        );
    }
    #[test]
    fn a_publication_climbs_a_rung_a_quarter_of_its_window() {
        // Window 100..=108: quarters at 102, 104 and 106.
        assert_eq!(rung(100, 108, 100), 0);
        assert_eq!(rung(100, 108, 101), 0);
        assert_eq!(rung(100, 108, 102), 1);
        assert_eq!(rung(100, 108, 104), 2);
        assert_eq!(rung(100, 108, 106), 3);
        assert_eq!(rung(100, 108, 200), 3);
        // A tip before it, or a window of nothing: at once the last rung,
        // or none, never a panic.
        assert_eq!(rung(100, 108, 90), 0);
        assert_eq!(rung(100, 100, 100), 0);
        assert_eq!(rung(100, 100, 101), 3);
        assert_eq!(rung(108, 100, 101), 0);
    }

    #[test]
    fn a_state_of_no_fee_payout_reads_as_awaiting_none_and_writes_none() {
        let old = State::default().encode();
        assert!(!String::from_utf8_lossy(&old).contains("fee_payout"));
        let row = RecoveryRow {
            id: [1; 32],
            format: FORMAT,
            stage: Stage::Claimed.as_str().into(),
            irrevocable: false,
            error: None,
            state: old,
            created_at: 0,
        };
        let state = State::decode(&row).unwrap();
        assert_eq!((state.fee_payout, state.challenge_payout), (None, None));
        let awaiting = State {
            fee_payout: Some("ab".into()),
            ..State::default()
        };
        let row = RecoveryRow {
            state: awaiting.encode(),
            ..row
        };
        assert_eq!(
            State::decode(&row).unwrap().fee_payout.as_deref(),
            Some("ab")
        );
    }

    #[test]
    fn fees_are_paid_by_the_purse_then_one_coin_the_payouts_first_then_coins_joined() {
        let coin = |n: u8| OutPoint::new(Txid::from_byte_array([n; 32]), 0);
        let free = [
            (coin(1), 5_000),
            (coin(2), 900),
            (coin(3), 40),
            (coin(4), 2_000),
        ];
        // Each alone, the smallest first; never two together unless asked.
        assert_eq!(
            fee_inputs(&free, None, 100, false),
            vec![
                vec![],
                vec![coin(3)],
                vec![coin(2)],
                vec![coin(4)],
                vec![coin(1)]
            ]
        );
        // The payout's coin first, alone and joined; then the largest, until
        // one adds no more than its input's fee.
        let paid = Some(coin(2).txid);
        assert_eq!(
            fee_inputs(&free, paid, 100, true),
            vec![
                vec![],
                vec![coin(2)],
                vec![coin(3)],
                vec![coin(4)],
                vec![coin(1)],
                vec![coin(2), coin(1)],
                vec![coin(2), coin(1), coin(4)],
            ]
        );
        assert_eq!(
            fee_inputs(&[], paid, 100, true),
            vec![Vec::<OutPoint>::new()]
        );
    }

    #[test]
    fn a_request_waits_on_its_fee_payout_only_while_under_way_and_time_is_left() {
        let deadline = 100;
        assert!(waits_for_payout(true, 90, deadline));
        assert!(waits_for_payout(true, 92, deadline));
        assert!(!waits_for_payout(true, 93, deadline));
        assert!(!waits_for_payout(false, 10, deadline));
        assert!(!waits_for_payout(true, 0, 5));
    }
}
