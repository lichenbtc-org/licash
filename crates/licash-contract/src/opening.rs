//! The holder garbles, the hub chooses and proves. A driver first persists
//! every `Keep` artifact, then state, then sends, signatures, or broadcasts.
use anyhow::{bail, ensure, Context as _, Result};
use licash::{
    base::{Base, ChainTerms, Close, Fees, GraphTerms, Limits, Parts, Recipe},
    chain::Checkpoint,
    note::Keyset,
    spend::ChainProfile,
};
use lichen_babe::{
    opening::{self as cut, Garbler},
    reveal::{check_presigs, points},
    setup::{par, Hash, Instance},
};
use lichen_btc::bitcoin::{
    consensus::serialize,
    hashes::Hash as _,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
};
use lichen_contract::{sig_name, sign_all, PartyPubKeys, Presign};
use rand_core::{OsRng, RngCore};
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{
    graph::{self, contract_output, HolderPub, HubProves, HubPub, FUNDING_VOUT},
    keys::{HolderKeys, HubKeys},
    wire::{self, Envelope, Kind},
    MAX_INSTANCES,
};

mod fate;
mod state;
pub use fate::{Fate, Funding, Spent};
pub use graph::journal;
pub use state::Peek;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trust {
    pub program: [u8; 32],
    pub mock: bool,
    /// Whether its program decides the compact filing
    /// ([`licash::recovery::Format`]), which a contract of graph id
    /// [`licash::recovery::COMPACT_FROM`] on files: under one that doesn't,
    /// her claim would decode to nothing, and be owed nothing.
    pub compact: bool,
    /// Whether its program decides the lean filing
    /// ([`licash::recovery::Format::Lean`]), which a contract of graph id
    /// [`licash::recovery::LEAN_FROM`] on files, and judges item by item: one
    /// that doesn't would owe her claim nothing, or the Hub could not prove
    /// it owed less. A program that does decides the compact one too.
    pub lean: bool,
    /// The chain program whose receipts its statement verifies, if it reads
    /// a contract's exit through the hub's header chain
    /// ([`licash::recovery::chained`]), which a contract of graph id
    /// [`licash::recovery::CHAINED_FROM`] on does: under one that doesn't, it
    /// would read no exit, and the hub could not prove her claim owed less.
    /// A program that does decides the lean filing too.
    pub chained: Option<[u8; 32]>,
    /// Whether its statement leaves a claim of the same contract no
    /// evidence against another ([`licash::recovery::own_claims_void`]),
    /// which a contract of graph id [`licash::recovery::OWN_CLAIMS_FROM`] on
    /// does: under one that doesn't, her claim made again in place of one
    /// before would be owed less by the notes both hold. A program that
    /// does reads the exit on the header chain too.
    pub own_claims: bool,
}
impl Trust {
    pub fn mock() -> Self {
        Self {
            program: [11; 32],
            mock: true,
            compact: true,
            lean: true,
            chained: None,
            own_claims: false,
        }
    }
}
#[derive(Clone, Copy)]
pub struct Context {
    pub tip: u32,
    pub trust: Trust,
}

pub enum Input {
    Message(Vec<u8>),
    Funded {
        funding: Transaction,
        prevouts: Vec<TxOut>,
    },
    Signed(Transaction),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    Send(Vec<u8>),
    Serve {
        i: u32,
    },
    Keep {
        i: u32,
        bytes: Vec<u8>,
    },
    Fund {
        deposit: OutPoint,
        coin: TxOut,
        outputs: Vec<TxOut>,
    },
    Sign {
        funding: Transaction,
        prevouts: Vec<TxOut>,
        inputs: Vec<usize>,
    },
    Broadcast(Transaction),
}
fn send(id: [u8; 32], kind: Kind, body: Vec<u8>) -> Out {
    Out::Send(Envelope { id, kind, body }.to_bytes())
}
fn same_kind(mock: bool, ctx: &Context) -> Result<()> {
    ensure!(
        mock == ctx.trust.mock,
        "mock and genuine proof trust differ"
    );
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Quote {
    pub keyset: Keyset,
    pub cap: u32,
    pub graph: GraphTerms,
    pub recipe: Recipe,
    pub chain: ChainTerms,
    pub limits: Limits,
    pub fees: Fees,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Floors {
    pub challenge_window: u16,
    /// Her window to contest a response: as long as she has to challenge
    /// a false assertion, for it is the same duty to be online.
    pub contest_window: u16,
    pub publication_window: u16,
    pub to_self_delay: u16,
    pub funding_depth: u32,
    pub work_depth: u32,
    /// The rate in sat per 1,000 vB her reserve must afford a forced close
    /// of the most notes a claim files ([`crate::reserve`]); none asked on
    /// the test networks, whose fees are what they are.
    pub reserve_rate: u64,
}
impl Floors {
    pub fn of(profile: ChainProfile) -> Self {
        let (challenge_window, publication_window, to_self_delay, funding_depth, work_depth) =
            match profile {
                ChainProfile::Core30DefaultRegtest => (6, 6, 6, 1, 1),
                // Counted in blocks, the same on every network that is not
                // regtest: Mutinynet's blocks are 20 times as quick, which
                // is for its tests to meet reorganizations with.
                ChainProfile::Core30Mainnet
                | ChainProfile::Core30Signet
                | ChainProfile::Mutinynet => (144, 6, 144, 3, 6),
            };
        // Mainnet: 10 sat/vB, so that a forced close of the filing at its
        // widest gets confirmed in a fee market short of a spike. A bug or
        // a wrong estimate can spend no more than the reserve in any case.
        let reserve_rate = match profile {
            ChainProfile::Core30Mainnet => 10_000,
            _ => 0,
        };
        Self {
            challenge_window,
            contest_window: challenge_window,
            publication_window,
            to_self_delay,
            funding_depth,
            work_depth,
            reserve_rate,
        }
    }
}
impl Quote {
    pub fn from_base(base: &Base) -> Self {
        let p = base.parts();
        Self {
            keyset: p.keyset.clone(),
            cap: p.cap,
            graph: p.graph.clone(),
            recipe: p.recipe.clone(),
            chain: p.chain.clone(),
            limits: p.limits.clone(),
            fees: p.fees.clone(),
        }
    }
    pub fn check(&self, profile: ChainProfile) -> Result<()> {
        let f = Floors::of(profile);
        ensure!(
            self.graph.challenge_window >= f.challenge_window,
            "challenge window below floor"
        );
        ensure!(
            self.graph.contest_window >= f.contest_window,
            "contest window below floor"
        );
        ensure!(
            self.graph.publication_window >= f.publication_window,
            "publication window below floor"
        );
        ensure!(
            self.graph.to_self_delay >= f.to_self_delay,
            "funding delay below floor"
        );
        ensure!(
            self.chain.funding_depth >= f.funding_depth,
            "funding depth below floor"
        );
        ensure!(
            self.chain.work_depth >= f.work_depth,
            "work depth below floor"
        );
        ensure!(
            self.recipe.instances <= MAX_INSTANCES,
            "too many garbled instances"
        );
        let afforded = crate::reserve::affordable_rate_at_most(&self.graph);
        ensure!(
            afforded >= f.reserve_rate,
            "her reserve affords a forced close {:.1} sat/vB, not {:.1} at least",
            afforded as f64 / 1_000.0,
            f.reserve_rate as f64 / 1_000.0
        );
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub lock: u32,
    pub response_window: u16,
}
impl Bounds {
    pub fn check(&self, wanted: &wire::Wanted, tip: u32) -> Result<()> {
        let lock = wanted.close_height.saturating_sub(tip);
        ensure!(
            lock <= self.lock,
            "collateral locked {lock} blocks, not {} at most",
            self.lock
        );
        ensure!(
            wanted.response_window >= self.response_window,
            "a response window of {} blocks, not {} at least",
            wanted.response_window,
            self.response_window
        );
        Ok(())
    }
}
fn offer(
    quote: &Quote,
    id: [u8; 32],
    open: &wire::Open,
    program: [u8; 32],
    checkpoint: &Checkpoint,
    hub: licash::base::Party,
) -> Result<Base> {
    let mut graph = quote.graph.clone();
    graph.request_height = open.wanted.request_height;
    graph.close_height = open.wanted.close_height;
    graph.response_window = open.wanted.response_window;
    let mut recipe = quote.recipe.clone();
    recipe.program = program;
    let mut chain = quote.chain.clone();
    chain.checkpoint = checkpoint.clone();
    ensure!(
        graph.deposit_units > 0,
        "her part of the contract is funded: a quote of none opens nothing"
    );
    check_funded(
        &open.funded.outputs,
        &quote.keyset,
        &quote.limits,
        graph.deposit_units,
    )?;
    Ok(Base::new(Parts {
        nonce: id,
        holder_wots: open.request_keys,
        funded: licash::spend::funded_root(&open.funded.outputs)?,
        claim_key: open.claim_key.serialize(),
        keyset: quote.keyset.clone(),
        deposit: serialize(&open.deposit).try_into().expect("outpoint"),
        cap: quote.cap,
        parties: [graph::party(&open.party), hub],
        graph,
        recipe,
        chain,
        limits: quote.limits.clone(),
        fees: quote.fees.clone(),
        close: Close {
            script: open.close.script.to_bytes(),
            fee: open.close.fee,
        },
    })?)
}

/// The outputs she funds her part with: notes the keyset issues, at most
/// as many as one claim can hold, worth exactly her part.
fn check_funded(
    outputs: &[licash::spend::Output],
    keyset: &licash::note::Keyset,
    limits: &licash::base::Limits,
    units: u32,
) -> Result<()> {
    let most = licash::claim::MAX_ITEMS.min(limits.max_authorizations as usize);
    ensure!(
        !outputs.is_empty() && outputs.len() <= most,
        "{} funded outputs, not 1 to {most}",
        outputs.len()
    );
    let mut worth = 0u64;
    for output in outputs {
        keyset
            .key(output.denomination())
            .context("a funded output the keyset doesn't issue")?;
        worth = worth
            .checked_add(output.denomination())
            .context("funded outputs overflow")?;
    }
    ensure!(
        worth == u64::from(units),
        "funded outputs worth {worth}, not her part of {units}"
    );
    Ok(())
}

fn segwit(script: &ScriptBuf) -> bool {
    script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr()
}
/// What her deposit pays: her reserve, the fee, and her part of the
/// contract, which the Hub issues back to her as notes. Her coin pays no
/// more: it is spent whole, and what is left of it is below dust.
fn price(g: &GraphTerms, f: &Fees) -> Result<u64> {
    g.reserve_alice
        .checked_add(f.opening_fee_quote)
        .and_then(|p| p.checked_add(u64::from(g.deposit_units)))
        .context("price overflow")
}
fn check_deposit(open: &wire::Open, g: &GraphTerms, f: &Fees) -> Result<()> {
    ensure!(open.coin.script_pubkey.is_p2tr(), "deposit must be taproot");
    ensure!(
        segwit(&open.party.payout_spk),
        "the holder's payout must be native segwit"
    );
    let left = open
        .coin
        .value
        .to_sat()
        .checked_sub(price(g, f)?)
        .context("deposit below price")?;
    // No change comes back to her: the coin pays the price and, in her part
    // of the contract, all it can, so that what is left is no output's worth.
    ensure!(
        left < g.dust,
        "deposit cannot be absorbed by this contract: {left} sat of it beyond the price, \
         not below dust"
    );
    Ok(())
}
fn at(funding: &Transaction, deposit: OutPoint) -> usize {
    funding
        .input
        .iter()
        .position(|i| i.previous_output == deposit)
        .expect("checked deposit")
}
fn unsigned(tx: &Transaction) -> Result<()> {
    ensure!(
        !tx.input.is_empty()
            && tx
                .input
                .iter()
                .all(|i| i.script_sig.is_empty() && i.witness.is_empty()),
        "F must be unsigned"
    );
    Ok(())
}
fn whole(funding: &Transaction, signed: &Transaction) -> Result<()> {
    ensure!(
        funding.compute_txid() == signed.compute_txid()
            && funding.input.len() == signed.input.len(),
        "another F signed"
    );
    ensure!(
        signed
            .input
            .iter()
            .all(|i| i.script_sig.is_empty() && !i.witness.is_empty()),
        "F not wholly signed"
    );
    Ok(())
}
fn complete_deposit(
    signed: &Transaction,
    supplied: &Transaction,
    deposit: usize,
    prevouts: &[TxOut],
) -> Result<Transaction> {
    ensure!(
        signed.compute_txid() == supplied.compute_txid(),
        "another F"
    );
    let mut complete = signed.clone();
    complete.input[deposit].witness = supplied.input[deposit].witness.clone();
    whole(signed, &complete)?;
    check_key_spend(&complete, deposit, prevouts)?;
    Ok(complete)
}
fn check_funds(
    base: &Base,
    open: &wire::Open,
    funding: &Transaction,
    prevouts: &[TxOut],
    output: &TxOut,
) -> Result<()> {
    unsigned(funding)?;
    ensure!(
        prevouts.len() == funding.input.len(),
        "prevout count differs"
    );
    let mut seen = HashSet::new();
    for (input, coin) in funding.input.iter().zip(prevouts) {
        ensure!(
            seen.insert(input.previous_output),
            "duplicate funding input"
        );
        ensure!(segwit(&coin.script_pubkey), "non-segwit funding input");
        ensure!(
            input.previous_output != open.deposit || *coin == open.coin,
            "another deposit coin"
        );
    }
    ensure!(seen.contains(&open.deposit), "F omits deposit");
    ensure!(
        funding.output.first() == Some(output),
        "contract must be F:0"
    );
    ensure!(
        funding
            .output
            .iter()
            .filter(|o| o.script_pubkey == output.script_pubkey)
            .count()
            == 1,
        "contract paid more than once"
    );
    let sum = |outputs: &[TxOut]| {
        outputs.iter().try_fold(0u64, |s, o| {
            s.checked_add(o.value.to_sat()).context("value overflow")
        })
    };
    let fee = sum(prevouts)?
        .checked_sub(sum(&funding.output)?)
        .context("F creates money")?;
    // Unsigned virtual size is a conservative lower bound. The driver can
    // select a lower fee, never charge more than this bound.
    let max = base
        .parts()
        .fees
        .max_rate_sat_per_kvb
        .checked_mul(funding.vsize() as u64)
        .context("fee overflow")?
        / 1000;
    ensure!(fee <= max, "F exceeds fee ceiling");
    Ok(())
}
fn check_key_spend(funding: &Transaction, index: usize, prevouts: &[TxOut]) -> Result<()> {
    let script = prevouts[index].script_pubkey.as_bytes();
    ensure!(
        prevouts[index].script_pubkey.is_p2tr(),
        "deposit not taproot"
    );
    let key = XOnlyPublicKey::from_slice(&script[2..])?;
    let witness = &funding.input[index].witness;
    ensure!(witness.len() == 1, "deposit must use key path");
    let sig = taproot::Signature::from_slice(&witness[0])?;
    ensure!(
        matches!(
            sig.sighash_type,
            TapSighashType::Default | TapSighashType::All
        ),
        "deposit signature omits inputs"
    );
    let hash = SighashCache::new(funding).taproot_key_spend_signature_hash(
        index,
        &Prevouts::All(prevouts),
        sig.sighash_type,
    )?;
    Secp256k1::verification_only().verify_schnorr(
        &sig.signature,
        &Message::from_digest(hash.to_byte_array()),
        &key,
    )?;
    Ok(())
}
fn check_sigs(
    set: &[Presign],
    pk: &XOnlyPublicKey,
    sigs: &HashMap<String, Vec<u8>>,
    skip: impl Fn(&str) -> bool,
) -> Result<()> {
    let mut expected = 0;
    for p in set {
        for i in 0..p.inputs() {
            let name = sig_name(&p.name, i);
            if skip(&name) {
                continue;
            }
            expected += 1;
            p.verify_input(
                pk,
                i,
                sigs.get(&name)
                    .with_context(|| format!("missing {name} signature"))?,
            )?;
        }
    }
    ensure!(sigs.len() == expected, "unexpected signatures");
    Ok(())
}
fn check_kept(kept: &[u32], base: &Base) -> Result<()> {
    let r = &base.parts().recipe;
    ensure!(
        kept.len() == r.kept as usize
            && kept.iter().all(|i| *i > 0 && *i <= r.instances as u32)
            && kept.windows(2).all(|v| v[0] < v[1]),
        "invalid kept indices"
    );
    Ok(())
}
fn compile(
    base: &Base,
    holder: &HolderPub,
    hub: &HubPub,
    hmsg: Vec<Hash>,
    funding: &Transaction,
) -> Result<(HubProves, Vec<Presign>)> {
    let babe = graph::build(base, holder, hub, hmsg)?;
    let op = OutPoint {
        txid: funding.compute_txid(),
        vout: FUNDING_VOUT,
    };
    let set = babe.presign(op)?;
    Ok((babe, set))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Phase {
    Started,
    Committed,
    Chosen,
    Consented,
    Signing,
    Funded,
}
impl Phase {
    pub const ALL: [Self; 6] = [
        Self::Started,
        Self::Committed,
        Self::Chosen,
        Self::Consented,
        Self::Signing,
        Self::Funded,
    ];
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum HubPhase {
    Termed,
    Chosen,
    Offered,
    Consented,
    Signed,
    Funded,
}
impl HubPhase {
    pub const ALL: [Self; 6] = [
        Self::Termed,
        Self::Chosen,
        Self::Offered,
        Self::Consented,
        Self::Signed,
        Self::Funded,
    ];
}

pub struct Start {
    pub seed: [u8; 32],
    pub quote: Quote,
    pub checkpoint: Checkpoint,
    pub deposit: OutPoint,
    pub coin: TxOut,
    /// Her wallet's script, which every payout and the default pay her
    /// reserve to: no sweep of hers needed.
    pub payout: ScriptBuf,
    pub wanted: wire::Wanted,
    /// The notes she funds her part of the contract with, worth the
    /// quote's `deposit_units`.
    pub funded: wire::FundedNotes,
    /// Where the default returns her reserve instead of `payout`: the Hub's
    /// deposit that swaps it for notes.
    pub close: wire::CloseOffer,
}

/// What the holder keeps to play a funded contract. She needs no uploaded
/// instances: her seed rebuilds them, including her challenge secrets.
pub struct Opening {
    pub mock: bool,
    pub base: Base,
    pub babe: HubProves,
    pub set: Vec<Presign>,
    pub hub: HubPub,
    pub holder: HolderPub,
    pub kept: Vec<u32>,
    pub offer: wire::Offer,
    pub consent: wire::Consent,
    pub funding: Transaction,
    /// What she funded of it herself.
    pub funded: Option<wire::FundedNotes>,
}
pub struct HubOpening {
    pub mock: bool,
    pub base: Base,
    pub babe: HubProves,
    pub set: Vec<Presign>,
    pub hub: HubPub,
    pub holder: HolderPub,
    pub kept: Vec<u32>,
    pub opened: wire::Opened,
    pub offer: wire::Offer,
    pub consent: wire::Consent,
    pub sigs: HashMap<String, Vec<u8>>,
    pub funding: Transaction,
    /// What she funded of it herself: the Hub issues it her.
    pub funded: Option<wire::FundedNotes>,
}

pub struct Holder {
    id: [u8; 32],
    keys: HolderKeys,
    quote: Quote,
    checkpoint: Checkpoint,
    open: wire::Open,
    terms: Option<wire::Terms>,
    commit: Option<wire::Commit>,
    hmsg: Vec<Hash>,
    kept: Option<Vec<u32>>,
    offer: Option<wire::Offer>,
    consent: Option<wire::Consent>,
    signed: Option<Transaction>,
    funded: Option<Transaction>,
}
impl Holder {
    pub fn start(s: Start, ctx: &Context) -> Result<(Self, Vec<Out>)> {
        Self::start_with_id(s, Base::fresh_nonce(), ctx)
    }
    /// Deterministic IDs are for fixtures only. Reusing a garbler's ID
    /// under another choice can disclose all of its kept secrets.
    #[cfg(test)]
    pub fn with_id(s: Start, id: [u8; 32], ctx: &Context) -> Result<(Self, Vec<Out>)> {
        Self::start_with_id(s, id, ctx)
    }
    fn start_with_id(s: Start, id: [u8; 32], ctx: &Context) -> Result<(Self, Vec<Out>)> {
        s.quote.check(s.checkpoint.profile())?;
        ensure!(
            s.quote.graph.id < licash::recovery::COMPACT_FROM || ctx.trust.compact,
            "a graph of id {} files a compact claim, which the program trusted doesn't decide",
            s.quote.graph.id
        );
        ensure!(
            s.quote.graph.id < licash::recovery::LEAN_FROM || ctx.trust.lean,
            "a graph of id {} files a lean claim, which the program trusted doesn't decide",
            s.quote.graph.id
        );
        ensure!(
            !licash::recovery::chained(s.quote.graph.id) || ctx.trust.chained.is_some(),
            "a graph of id {} reads the exit on the hub's header chain, which the program \
             trusted doesn't",
            s.quote.graph.id
        );
        ensure!(
            licash::recovery::own_claims_void(s.quote.graph.id) || ctx.trust.own_claims,
            "a graph of id {} owes a claim all its notes, though another claim of the contract \
             holds them, which the program trusted doesn't",
            s.quote.graph.id
        );
        let keys = HolderKeys::derive(&s.seed, &id);
        let open = wire::Open {
            party: PartyPubKeys {
                payout_spk: s.payout,
                ..keys.party.public()
            },
            claim_key: keys.claim_key(),
            deposit: s.deposit,
            coin: s.coin,
            wanted: s.wanted,
            mock: ctx.trust.mock,
            request_keys: keys.public().request_keys()?.digest(),
            funded: s.funded,
            close: s.close,
        };
        check_deposit(&open, &s.quote.graph, &s.quote.fees)?;
        let h = Self {
            id,
            keys,
            quote: s.quote,
            checkpoint: s.checkpoint,
            open,
            terms: None,
            commit: None,
            hmsg: vec![],
            kept: None,
            offer: None,
            consent: None,
            signed: None,
            funded: None,
        };
        let out = h.pending()?;
        Ok((h, out))
    }
    fn expected_base(&self, program: [u8; 32], hub: licash::base::Party) -> Result<Base> {
        offer(
            &self.quote,
            self.id,
            &self.open,
            program,
            &self.checkpoint,
            hub,
        )
    }
    pub fn base(&self) -> Option<&Base> {
        self.terms.as_ref().map(|t| &t.base)
    }
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    /// What she funds of the contract herself: the notes the Hub issues her
    /// once F confirms, else her claim names.
    pub fn funded_notes(&self) -> Option<&wire::FundedNotes> {
        Some(&self.open.funded)
    }
    fn garbler(&self) -> Garbler {
        let b = self.base().expect("terms first");
        let r = &b.parts().recipe;
        Garbler::new(
            &self.keys.garbler,
            r.instances as u32,
            r.kept as u32,
            &graph::kind(b, self.open.mock),
            &journal(b),
        )
    }
    fn graph(&self, funding: &Transaction) -> Result<(HubProves, Vec<Presign>)> {
        let t = self.terms.as_ref().context("no terms")?;
        let kept = self.kept.as_ref().context("no choice")?;
        compile(
            &t.base,
            &self.keys.public(),
            &t.hub,
            kept.iter().map(|i| self.hmsg[*i as usize - 1]).collect(),
            funding,
        )
    }
    pub fn phase(&self) -> Phase {
        if self.funded.is_some() {
            Phase::Funded
        } else if self.signed.is_some() {
            Phase::Signing
        } else if self.consent.is_some() {
            Phase::Consented
        } else if self.kept.is_some() {
            Phase::Chosen
        } else if self.commit.is_some() {
            Phase::Committed
        } else {
            Phase::Started
        }
    }
    pub fn abandonable(&self) -> bool {
        self.phase() < Phase::Funded
    }
    pub fn deposit(&self) -> OutPoint {
        self.open.deposit
    }
    pub fn funding_tx(&self) -> Option<&Transaction> {
        self.funded
            .as_ref()
            .or(self.signed.as_ref())
            .or(self.offer.as_ref().map(|o| &o.funding))
    }
    pub fn pending(&self) -> Result<Vec<Out>> {
        Ok(match self.phase() {
            Phase::Started => vec![send(self.id, Kind::Open, self.open.encode())],
            Phase::Committed => vec![send(
                self.id,
                Kind::Commit,
                self.commit.as_ref().unwrap().encode(),
            )],
            Phase::Chosen => {
                let kept = self.kept.as_ref().unwrap();
                let mut out = vec![send(
                    self.id,
                    Kind::Opened,
                    wire::Opened {
                        opened: self.garbler().open(kept)?,
                    }
                    .encode(),
                )];
                out.extend(kept.iter().map(|i| Out::Serve { i: *i }));
                out
            }
            Phase::Consented => vec![send(
                self.id,
                Kind::Consent,
                self.consent.as_ref().unwrap().encode(),
            )],
            Phase::Signing => {
                let o = self.offer.as_ref().unwrap();
                vec![Out::Sign {
                    funding: self.signed.as_ref().unwrap().clone(),
                    prevouts: o.prevouts.clone(),
                    inputs: vec![at(&o.funding, self.deposit())],
                }]
            }
            Phase::Funded => vec![send(
                self.id,
                Kind::Funded,
                wire::Funded {
                    funding: self.funded.as_ref().unwrap().clone(),
                }
                .encode(),
            )],
        })
    }
    pub fn instance(&self, i: u32) -> Result<Vec<u8>> {
        ensure!(
            self.kept.as_ref().is_some_and(|k| k.contains(&i)),
            "instance not kept"
        );
        Ok(self.garbler().instance(i).to_bytes())
    }
    pub fn step(&mut self, input: Input, ctx: &Context) -> Result<Vec<Out>> {
        same_kind(self.open.mock, ctx)?;
        match input {
            Input::Message(bytes) => {
                let m = Envelope::from_bytes(&bytes)?;
                ensure!(m.id == self.id, "another opening");
                match m.kind {
                    Kind::Terms => {
                        let t = wire::Terms::decode(&m.body)?;
                        if let Some(previous) = &self.terms {
                            ensure!(previous.encode() == t.encode(), "another terms message");
                            return self.pending();
                        }
                        ensure!(self.phase() == Phase::Started, "terms out of order");
                        self.check_terms(&t, ctx)?;
                        let b = &t.base;
                        let r = &b.parts().recipe;
                        let garbler = Garbler::new(
                            &self.keys.garbler,
                            r.instances as u32,
                            r.kept as u32,
                            &graph::kind(b, self.open.mock),
                            &journal(b),
                        );
                        let pairs = par(r.instances as usize, |i| {
                            let inst = garbler.instance(i as u32 + 1);
                            (inst.commitment(), inst.hmsg)
                        });
                        let commit = wire::Commit {
                            holder: self.keys.public(),
                            commitments: pairs.iter().map(|p| p.0).collect(),
                            dealing: garbler.dealing().clone(),
                        };
                        self.hmsg = pairs.iter().map(|p| p.1).collect();
                        self.commit = Some(commit);
                        self.terms = Some(t);
                    }
                    Kind::Choose => {
                        let k = wire::Choose::decode(&m.body)?.kept;
                        if let Some(previous) = &self.kept {
                            // Releasing a second complement reveals kept seeds.
                            // Persist this choice before sending any Opened.
                            ensure!(*previous == k, "another choice for this opening");
                            return self.pending();
                        }
                        ensure!(self.phase() == Phase::Committed, "choice out of order");
                        check_kept(&k, self.base().unwrap())?;
                        self.kept = Some(k);
                    }
                    Kind::Offer => {
                        let o = wire::Offer::decode(&m.body)?;
                        if let Some(previous) = &self.offer {
                            ensure!(*previous == o, "another offer");
                            return self.pending();
                        }
                        ensure!(self.phase() == Phase::Chosen, "offer out of order");
                        let (babe, set) = self.graph(&o.funding)?;
                        self.base().unwrap().check(&ctx.trust.program, ctx.tip)?;
                        check_funds(
                            self.base().unwrap(),
                            &self.open,
                            &o.funding,
                            &o.prevouts,
                            &contract_output(&babe)?,
                        )?;
                        let hub = graph::party_pub(&self.base().unwrap().parts().parties[1])?;
                        check_sigs(&set, &hub.payment, &o.sigs, HubProves::withheld)?;
                        let t = self.terms.as_ref().unwrap();
                        ensure!(
                            check_presigs(
                                &t.hub.adaptor,
                                &HubProves::challenge_sighash(&set)?,
                                &points(&self.commit.as_ref().unwrap().dealing),
                                &o.presigs
                            ),
                            "invalid adaptor presignatures"
                        );
                        let consent = wire::Consent {
                            sigs: sign_all(&set, &self.keys.party.payment)?,
                        };
                        self.offer = Some(o);
                        self.consent = Some(consent);
                    }
                    Kind::Signed => {
                        let tx = wire::Signed::decode(&m.body)?.funding;
                        if let Some(previous) = &self.signed {
                            ensure!(*previous == tx, "another signed F");
                            return self.pending();
                        }
                        ensure!(self.phase() == Phase::Consented, "signed F out of order");
                        let o = self.offer.as_ref().unwrap();
                        ensure!(tx.compute_txid() == o.funding.compute_txid(), "another F");
                        let mine = at(&o.funding, self.deposit());
                        ensure!(
                            tx.input[mine].witness.is_empty()
                                && tx
                                    .input
                                    .iter()
                                    .enumerate()
                                    .all(|(i, input)| input.script_sig.is_empty()
                                        && (i == mine || !input.witness.is_empty())),
                            "hub inputs not signed"
                        );
                        self.base().unwrap().check(&ctx.trust.program, ctx.tip)?;
                        self.signed = Some(tx);
                    }
                    _ => bail!("holder not sent {:?}", m.kind),
                }
            }
            Input::Signed(tx) => {
                ensure!(
                    self.phase() == Phase::Signing,
                    "deposit signature out of order"
                );
                let o = self.offer.as_ref().unwrap();
                self.base().unwrap().check(&ctx.trust.program, ctx.tip)?;
                self.funded = Some(complete_deposit(
                    self.signed.as_ref().unwrap(),
                    &tx,
                    at(&o.funding, self.deposit()),
                    &o.prevouts,
                )?);
            }
            Input::Funded { .. } => bail!("holder does not fund"),
        }
        self.pending()
    }
    fn check_terms(&self, t: &wire::Terms, ctx: &Context) -> Result<()> {
        t.hub.check()?;
        // Her payouts pay the hub's share to it: one that doesn't relay
        // would keep them off the chain.
        ensure!(
            segwit(&ScriptBuf::from_bytes(
                t.base.parts().parties[1].payout_script.clone()
            )),
            "the hub's payout must be native segwit"
        );
        let expected = self.expected_base(ctx.trust.program, t.base.parts().parties[1].clone())?;
        ensure!(
            expected.to_bytes() == t.base.to_bytes(),
            "terms differ from quote"
        );
        t.base.check(&ctx.trust.program, ctx.tip)?;
        // Reject insufficient graph collateral before spending time garbling.
        graph::build(
            &t.base,
            &self.keys.public(),
            &t.hub,
            graph::draft_hmsg(t.base.parts().recipe.kept),
        )?
        .presign(OutPoint::null())?;
        Ok(())
    }
    pub fn signed(&self) -> Result<Opening> {
        let o = self.offer.as_ref().context("no offer")?;
        let (babe, set) = self.graph(&o.funding)?;
        Ok(Opening {
            mock: self.open.mock,
            base: self.base().context("no terms")?.clone(),
            babe,
            set,
            hub: self.terms.as_ref().unwrap().hub.clone(),
            holder: self.keys.public(),
            kept: self.kept.clone().context("no choice")?,
            offer: o.clone(),
            consent: self.consent.clone().context("no consent")?,
            funding: self.funded.clone().context("F not signed")?,
            funded: Some(self.open.funded.clone()),
        })
    }
}

pub struct Hub {
    secret: [u8; 32],
    keys: HubKeys,
    quote: Quote,
    bounds: Option<Bounds>,
    id: Option<[u8; 32]>,
    open: Option<wire::Open>,
    base: Option<Base>,
    commit: Option<wire::Commit>,
    kept: Option<Vec<u32>>,
    /// The contract's output, of the draft built once on her commitment:
    /// building it again on every step, or load, would cost the hub a
    /// statement's compilation each time.
    draft: Option<TxOut>,
    opened: Option<wire::Opened>,
    received: BTreeMap<u32, Hash>,
    funds: Option<(Transaction, Vec<TxOut>)>,
    offer: Option<wire::Offer>,
    consent: Option<wire::Consent>,
    signed: Option<Transaction>,
    funded: Option<Transaction>,
    /// Its wallet's script, which the default and its share of every
    /// payout pay to: given new, read from its terms once stored.
    payout: Option<ScriptBuf>,
}
impl Hub {
    /// The hub's own one-time keys. The driver must durably pin each
    /// response and assertion before using them to sign.
    pub fn keys(&self) -> &HubKeys {
        &self.keys
    }

    /// A new opening of `quote`, paying the hub's share to `payout`, a
    /// script of its wallet.
    pub fn new(quote: Quote, bounds: Bounds, payout: ScriptBuf) -> Self {
        let mut secret = [0; 32];
        OsRng.fill_bytes(&mut secret);
        let mut hub = Self::with(&secret, quote, Some(bounds));
        hub.payout = Some(payout);
        hub
    }
    /// The hub as a party of the terms: its keys and its payout script.
    fn party(&self) -> Result<licash::base::Party> {
        let payout = self.payout.clone().context("no payout script")?;
        ensure!(segwit(&payout), "the hub's payout must be native segwit");
        Ok(graph::party(&PartyPubKeys {
            payout_spk: payout,
            ..self.keys.party.public()
        }))
    }
    fn with(secret: &[u8; 32], quote: Quote, bounds: Option<Bounds>) -> Self {
        Self {
            secret: *secret,
            keys: HubKeys::from_secret(secret),
            quote,
            bounds,
            id: None,
            open: None,
            base: None,
            commit: None,
            kept: None,
            draft: None,
            opened: None,
            received: BTreeMap::new(),
            funds: None,
            offer: None,
            consent: None,
            signed: None,
            funded: None,
            payout: None,
        }
    }
    pub fn phase(&self) -> HubPhase {
        if self.funded.is_some() {
            HubPhase::Funded
        } else if self.signed.is_some() {
            HubPhase::Signed
        } else if self.consent.is_some() {
            HubPhase::Consented
        } else if self.offer.is_some() {
            HubPhase::Offered
        } else if self.kept.is_some() {
            HubPhase::Chosen
        } else {
            HubPhase::Termed
        }
    }
    pub fn abandonable(&self) -> bool {
        self.phase() < HubPhase::Signed
    }
    /// What she funds of the contract herself: the notes the Hub issues her
    /// once F confirms.
    pub fn funded_notes(&self) -> Option<&wire::FundedNotes> {
        Some(&self.open.as_ref()?.funded)
    }
    /// The preimage the Hub issues her funded notes under, its own lock's:
    /// of this opening's secret alone, so that every issuance asked is
    /// the same lock, and no other contract's.
    pub fn funded_preimage(&self) -> [u8; 32] {
        licash::crypto::tagged_hash("licash/funded-preimage/v1", &[&self.secret])
    }
    pub fn base(&self) -> Option<&Base> {
        self.base.as_ref()
    }
    pub fn funding_tx(&self) -> Option<&Transaction> {
        self.funded
            .as_ref()
            .or(self.signed.as_ref())
            .or(self.funds.as_ref().map(|f| &f.0))
    }
    pub fn missing(&self) -> Vec<u32> {
        self.kept
            .iter()
            .flatten()
            .filter(|i| !self.received.contains_key(i))
            .copied()
            .collect()
    }
    fn graph(&self, funding: &Transaction) -> Result<(HubProves, Vec<Presign>)> {
        let base = self.base.as_ref().context("no terms")?;
        let commit = self.commit.as_ref().context("no commitments")?;
        let kept = self.kept.as_ref().context("no choice")?;
        let hmsg = kept
            .iter()
            .map(|i| self.received.get(i).copied().context("missing instance"))
            .collect::<Result<_>>()?;
        compile(base, &commit.holder, &self.keys.public(), hmsg, funding)
    }
    fn draft_output(&self) -> Result<TxOut> {
        self.draft.clone().context("no commitments")
    }
    fn fund_out(&self) -> Result<Out> {
        let open = self.open.as_ref().context("no Open")?;
        let outputs = vec![self.draft_output()?];
        Ok(Out::Fund {
            deposit: open.deposit,
            coin: open.coin.clone(),
            outputs,
        })
    }
    pub fn pending(&self) -> Result<Vec<Out>> {
        let Some(id) = self.id else {
            return Ok(vec![]);
        };
        Ok(match self.phase() {
            HubPhase::Termed => vec![send(
                id,
                Kind::Terms,
                wire::Terms {
                    base: self.base.clone().context("no terms")?,
                    hub: self.keys.public(),
                }
                .encode(),
            )],
            HubPhase::Chosen => {
                let mut out = vec![send(
                    id,
                    Kind::Choose,
                    wire::Choose {
                        kept: self.kept.clone().unwrap(),
                    }
                    .encode(),
                )];
                if self.funds.is_none() {
                    out.push(self.fund_out()?);
                }
                out
            }
            HubPhase::Offered => vec![send(id, Kind::Offer, self.offer.as_ref().unwrap().encode())],
            HubPhase::Consented => {
                let o = self.offer.as_ref().unwrap();
                let open = self.open.as_ref().unwrap();
                vec![Out::Sign {
                    funding: o.funding.clone(),
                    prevouts: o.prevouts.clone(),
                    inputs: (0..o.funding.input.len())
                        .filter(|i| o.funding.input[*i].previous_output != open.deposit)
                        .collect(),
                }]
            }
            HubPhase::Signed => vec![send(
                id,
                Kind::Signed,
                wire::Signed {
                    funding: self.signed.as_ref().unwrap().clone(),
                }
                .encode(),
            )],
            HubPhase::Funded => vec![Out::Broadcast(self.funded.as_ref().unwrap().clone())],
        })
    }
    fn maybe_offer(&mut self) -> Result<()> {
        if self.offer.is_some()
            || self.funds.is_none()
            || self.opened.is_none()
            || !self.missing().is_empty()
        {
            return Ok(());
        }
        let (funding, prevouts) = self.funds.as_ref().unwrap();
        let (_, set) = self.graph(funding)?;
        let mut sigs = sign_all(&set, &self.keys.party.payment)?;
        sigs.retain(|n, _| !HubProves::withheld(n));
        let presigs = self.keys.adaptor.presign(
            &HubProves::challenge_sighash(&set)?,
            &points(&self.commit.as_ref().unwrap().dealing),
        );
        self.offer = Some(wire::Offer {
            funding: funding.clone(),
            prevouts: prevouts.clone(),
            sigs,
            presigs,
        });
        Ok(())
    }
    pub fn step(&mut self, input: Input, ctx: &Context) -> Result<Vec<Out>> {
        if let Some(open) = &self.open {
            same_kind(open.mock, ctx)?;
        }
        let mut keep = None;
        let mut announce_choice = false;
        match input {
            Input::Message(bytes) => {
                let m = Envelope::from_bytes(&bytes)?;
                ensure!(self.id.is_none_or(|id| id == m.id), "another opening");
                match m.kind {
                    Kind::Open => {
                        let o = wire::Open::decode(&m.body)?;
                        same_kind(o.mock, ctx)?;
                        if let Some(previous) = &self.open {
                            ensure!(*previous == o, "another Open");
                            return self.pending();
                        }
                        self.bounds
                            .context("no opening bounds")?
                            .check(&o.wanted, ctx.tip)?;
                        self.quote.check(self.quote.chain.checkpoint.profile())?;
                        check_deposit(&o, &self.quote.graph, &self.quote.fees)?;
                        let b = offer(
                            &self.quote,
                            m.id,
                            &o,
                            ctx.trust.program,
                            &self.quote.chain.checkpoint,
                            self.party()?,
                        )?;
                        b.check(&ctx.trust.program, ctx.tip)?;
                        self.id = Some(m.id);
                        self.open = Some(o);
                        self.base = Some(b);
                    }
                    Kind::Commit => {
                        let c = wire::Commit::decode(&m.body)?;
                        if let Some(previous) = &self.commit {
                            ensure!(*previous == c, "another commitment for this opening");
                            return self.pending();
                        }
                        ensure!(self.base.is_some(), "commit out of order");
                        ensure!(
                            c.holder.request_keys()?.digest()
                                == self.base.as_ref().unwrap().parts().holder_wots,
                            "her request's keys aren't those Base binds"
                        );
                        let r = &self.base.as_ref().unwrap().parts().recipe;
                        ensure!(
                            c.commitments.len() == r.instances as usize,
                            "wrong commitment count"
                        );
                        ensure!(
                            c.dealing
                                .commitments
                                .iter()
                                .flatten()
                                .all(|v| v.len() == (r.instances - r.kept) as usize + 1),
                            "wrong dealing degree"
                        );
                        let draft = graph::build(
                            self.base.as_ref().unwrap(),
                            &c.holder,
                            &self.keys.public(),
                            graph::draft_hmsg(r.kept),
                        )?;
                        draft.presign(OutPoint::null())?;
                        let kept = cut::choose(r.instances as u32, r.kept as u32, &mut OsRng);
                        self.draft = Some(contract_output(&draft)?);
                        self.commit = Some(c);
                        self.kept = Some(kept);
                        announce_choice = true;
                    }
                    Kind::Opened => {
                        let o = wire::Opened::decode(&m.body)?;
                        if let Some(previous) = &self.opened {
                            ensure!(*previous == o, "another opened set");
                            return if self.phase() == HubPhase::Chosen {
                                Ok(vec![])
                            } else {
                                self.pending()
                            };
                        }
                        ensure!(
                            self.kept.is_some() && self.offer.is_none(),
                            "opened out of order"
                        );
                        let c = self.commit.as_ref().unwrap();
                        let b = self.base.as_ref().unwrap();
                        cut::check(
                            &c.commitments,
                            self.kept.as_ref().unwrap(),
                            &c.dealing,
                            &o.opened,
                            &graph::kind(b, self.open.as_ref().unwrap().mock),
                            &journal(b),
                            &mut OsRng,
                        )?;
                        self.opened = Some(o);
                    }
                    Kind::Instance => {
                        let inst = wire::Instance::decode(&m.body)?;
                        ensure!(
                            self.kept.as_ref().is_some_and(|k| k.contains(&inst.i)),
                            "instance not kept"
                        );
                        let parsed =
                            Instance::from_bytes(&inst.bytes).context("invalid instance")?;
                        ensure!(
                            parsed.commitment()
                                == self.commit.as_ref().unwrap().commitments[inst.i as usize - 1],
                            "instance differs from commitment"
                        );
                        self.received.insert(inst.i, parsed.hmsg);
                        keep = Some(Out::Keep {
                            i: inst.i,
                            bytes: inst.bytes,
                        });
                    }
                    Kind::Consent => {
                        let c = wire::Consent::decode(&m.body)?;
                        if let Some(previous) = &self.consent {
                            ensure!(*previous == c, "another consent");
                            return self.pending();
                        }
                        ensure!(self.phase() == HubPhase::Offered, "consent out of order");
                        let (_, set) = self.graph(&self.offer.as_ref().unwrap().funding)?;
                        let b = self.base.as_ref().unwrap();
                        b.check(&ctx.trust.program, ctx.tip)?;
                        check_sigs(
                            &set,
                            &graph::party_pub(&b.parts().parties[0])?.payment,
                            &c.sigs,
                            |_| false,
                        )?;
                        self.consent = Some(c);
                    }
                    Kind::Funded => {
                        let tx = wire::Funded::decode(&m.body)?.funding;
                        if let Some(previous) = &self.funded {
                            ensure!(*previous == tx, "another funded F");
                            return self.pending();
                        }
                        ensure!(self.phase() == HubPhase::Signed, "funded out of order");
                        let o = self.offer.as_ref().unwrap();
                        self.funded = Some(complete_deposit(
                            self.signed.as_ref().unwrap(),
                            &tx,
                            at(&o.funding, self.open.as_ref().unwrap().deposit),
                            &o.prevouts,
                        )?);
                    }
                    _ => bail!("hub not sent {:?}", m.kind),
                }
            }
            Input::Funded { funding, prevouts } => {
                ensure!(
                    self.kept.is_some() && self.funds.is_none() && self.offer.is_none(),
                    "funding out of order"
                );
                let b = self.base.as_ref().unwrap();
                b.check(&ctx.trust.program, ctx.tip)?;
                check_funds(
                    b,
                    self.open.as_ref().unwrap(),
                    &funding,
                    &prevouts,
                    &self.draft_output()?,
                )?;
                self.funds = Some((funding, prevouts));
            }
            Input::Signed(tx) => {
                ensure!(
                    self.phase() == HubPhase::Consented,
                    "signature out of order"
                );
                let o = self.offer.as_ref().unwrap();
                let mine = at(&o.funding, self.open.as_ref().unwrap().deposit);
                ensure!(tx.compute_txid() == o.funding.compute_txid(), "another F");
                ensure!(
                    tx.input[mine].witness.is_empty()
                        && tx
                            .input
                            .iter()
                            .enumerate()
                            .all(|(i, v)| v.script_sig.is_empty()
                                && (i == mine || !v.witness.is_empty())),
                    "hub inputs not signed"
                );
                self.base
                    .as_ref()
                    .unwrap()
                    .check(&ctx.trust.program, ctx.tip)?;
                self.signed = Some(tx);
            }
        }
        self.maybe_offer()?;
        let mut out: Vec<_> = keep.into_iter().collect();
        // Acknowledging each upload with Choose would make the holder
        // reopen and upload forever. Choice is announced only for Commit.
        if self.phase() != HubPhase::Chosen || announce_choice {
            out.extend(self.pending()?);
        }
        Ok(out)
    }
    pub fn signed(&self) -> Result<HubOpening> {
        let funding = self.signed.as_ref().context("hub has not signed F")?;
        let (babe, set) = self.graph(funding)?;
        let sigs = sign_all(&set, &self.keys.party.payment)?;
        Ok(HubOpening {
            mock: self.open.as_ref().unwrap().mock,
            base: self.base.clone().unwrap(),
            babe,
            set,
            hub: self.keys.public(),
            holder: self.commit.as_ref().unwrap().holder.clone(),
            kept: self.kept.clone().unwrap(),
            opened: self.opened.clone().unwrap(),
            offer: self.offer.clone().unwrap(),
            consent: self.consent.clone().unwrap(),
            sigs,
            funding: self.funded.as_ref().unwrap_or(funding).clone(),
            funded: Some(self.open.as_ref().unwrap().funded.clone()),
        })
    }
}

/// Small deterministic regtest terms for consumers' protocol tests.
pub mod testing {
    use super::*;

    /// The notes the fixtures' holder funds her part of the contract with,
    /// 12 sat of the keyset's.
    pub fn funded() -> wire::FundedNotes {
        let output = |n: u64| {
            let point = licash::crypto::generator_mul(&n.into());
            licash::spend::Output::new(
                n,
                licash::crypto::Point::from_projective(&point),
                [n as u8; 32],
            )
            .unwrap()
        };
        wire::FundedNotes {
            ephemeral: output(3).blinded(),
            outputs: vec![output(8), output(4)],
        }
    }

    /// Where the fixtures' default returns her reserve, and the fee the hub
    /// keeps of it.
    pub fn close() -> wire::CloseOffer {
        wire::CloseOffer {
            script: ScriptBuf::from_bytes(vec![0x51, 0x20, 9, 9, 9]),
            fee: 1_000,
        }
    }

    pub fn base(id: &[u8; 32]) -> Base {
        let holder = HolderKeys::derive(&[1; 32], id);
        let hub = HubKeys::from_secret(&[2; 32]);
        let close = close();
        Base::new(Parts {
            nonce: *id,
            holder_wots: holder.public().request_keys().unwrap().digest(),
            funded: licash::spend::funded_root(&funded().outputs).unwrap(),
            claim_key: holder.claim_key().serialize(),
            keyset: licash::note::IssuerKeys::from_seed(&[7; 32], 0, 3)
                .unwrap()
                .keyset()
                .unwrap(),
            deposit: serialize(&OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            })
            .try_into()
            .unwrap(),
            cap: 3584,
            parties: [
                graph::party(&holder.party.public()),
                graph::party(&hub.party.public()),
            ],
            graph: GraphTerms {
                id: 0,
                unit_sats: 1,
                bits: 12,
                low_bits: 9,
                deposit_units: 12,
                close_height: 1000,
                reserve_alice: 1000000,
                reserve_hub: 1000000,
                to_self_delay: 6,
                commit_fee: 0,
                presign_fee: 0,
                dust: 330,
                delta: 6,
                delta_prime: 6,
                deadline_margin: 10,
                request_height: 100,
                response_window: 24,
                publication_window: 6,
                contest_window: 12,
                assert_window: 12,
                challenge_window: 12,
                answer_window: 12,
            },
            recipe: Recipe {
                graph_version: 2,
                program: [11; 32],
                instances: 4,
                kept: 2,
            },
            chain: ChainTerms {
                checkpoint: Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap(),
                funding_depth: 1,
                work_depth: 1,
                max_headers: 128,
            },
            limits: Limits {
                max_transaction_bytes: 100000,
                max_publication_bytes: 90000,
                max_authorizations: 128,
                max_source_inputs: 128,
            },
            fees: Fees {
                max_rate_sat_per_kvb: 10000,
                opening_fee_quote: 1000,
            },
            close: Close {
                script: close.script.to_bytes(),
                fee: close.fee,
            },
        })
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_btc::bitcoin::{
        absolute, key::TapTweak, secp256k1::SECP256K1, transaction, Amount, TxIn, Witness,
    };
    fn message(id: [u8; 32], kind: Kind, body: Vec<u8>) -> Input {
        Input::Message(Envelope { id, kind, body }.to_bytes())
    }
    fn sent(out: &[Out], kind: Kind) -> Vec<u8> {
        out.iter()
            .find_map(|o| match o {
                Out::Send(b) if Kind::peek(b) == Some(kind) => Some(b.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no {kind:?} in {out:?}"))
    }
    /// A wallet's script (P2WSH), told apart by `n`.
    fn wallet_script(n: u8) -> ScriptBuf {
        ScriptBuf::from_bytes([&[0x00, 0x20][..], &[n; 32]].concat())
    }
    fn reload(holder: &mut Holder, hub: &mut Hub, ctx: &Context) {
        let a = holder.to_bytes();
        let h = hub.to_bytes();
        *holder = Holder::load(&a, &[1; 32], ctx).unwrap();
        *hub = Hub::load(&h, ctx).unwrap();
        assert_eq!(holder.to_bytes(), a);
        assert_eq!(hub.to_bytes(), h);
    }
    fn sign_deposit(
        tx: &mut Transaction,
        i: usize,
        prevouts: &[TxOut],
        key: &lichen_btc::bitcoin::key::Keypair,
    ) {
        let hash = SighashCache::new(&*tx)
            .taproot_key_spend_signature_hash(i, &Prevouts::All(prevouts), TapSighashType::Default)
            .unwrap();
        let tweaked = key.tap_tweak(SECP256K1, None);
        let sig = SECP256K1.sign_schnorr_no_aux_rand(
            &Message::from_digest(hash.to_byte_array()),
            tweaked.as_keypair(),
        );
        tx.input[i].witness = Witness::from_slice(&[sig.as_ref()]);
    }
    #[test]
    fn a_hub_bounds_how_long_she_locks_it_and_how_soon_it_answers() {
        let bounds = Bounds {
            lock: 100,
            response_window: 6,
        };
        let wanted = |close_height, response_window| wire::Wanted {
            request_height: 1_010,
            close_height,
            response_window,
        };
        assert!(bounds.check(&wanted(1_100, 6), 1_000).is_ok());
        // A block longer locked, at the same tip or one sooner.
        let error = bounds.check(&wanted(1_101, 6), 1_000).unwrap_err();
        assert!(error.to_string().contains("locked 101 blocks"), "{error}");
        assert!(bounds.check(&wanted(1_100, 6), 999).is_err());
        assert!(bounds.check(&wanted(1_100, 6), 1_001).is_ok());
        // A block shorter to answer in.
        let error = bounds.check(&wanted(1_100, 5), 1_000).unwrap_err();
        assert!(error.to_string().contains("window of 5 blocks"), "{error}");
        assert!(bounds.check(&wanted(1_100, 7), 1_000).is_ok());
    }

    /// A compact filing under a program that doesn't decode it is owed
    /// nothing, and a hub could answer so: holders refuse such a quote.
    #[test]
    fn a_graph_of_the_compact_filing_opens_only_under_a_program_that_decodes_it() {
        let id = [3; 32];
        let mut q = Quote::from_base(&testing::base(&id));
        let key = HolderKeys::derive(&[1; 32], &id).party.funding;
        let coin = TxOut {
            // Her reserve, the fee and her part: her coin is spent whole.
            value: Amount::from_sat(1_001_012),
            script_pubkey: ScriptBuf::new_p2tr(SECP256K1, key.x_only_public_key().0, None),
        };
        let start = |q: &Quote| Start {
            seed: [1; 32],
            quote: q.clone(),
            checkpoint: q.chain.checkpoint.clone(),
            deposit: OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            },
            coin: coin.clone(),
            payout: wallet_script(5),
            wanted: wire::Wanted {
                request_height: q.graph.request_height,
                close_height: q.graph.close_height,
                response_window: q.graph.response_window,
            },
            funded: testing::funded(),
            close: testing::close(),
        };
        let trust = |compact, lean| Context {
            tip: 1,
            trust: Trust {
                program: [11; 32],
                mock: true,
                compact,
                lean,
                chained: None,
                own_claims: false,
            },
        };
        // A program that decides the lean filing decides the compact too.
        for (graph, compact, lean, opens) in [
            (licash::recovery::COMPACT_FROM - 1, false, false, true),
            (licash::recovery::COMPACT_FROM, false, false, false),
            (licash::recovery::COMPACT_FROM, true, false, true),
            (licash::recovery::LEAN_FROM - 1, true, false, true),
            (licash::recovery::LEAN_FROM, true, false, false),
            (licash::recovery::LEAN_FROM, true, true, true),
            (licash::recovery::LEAN_FROM + 1, true, false, false),
        ] {
            q.graph.id = graph;
            let started = Holder::start(start(&q), &trust(compact, lean));
            assert_eq!(
                started.is_ok(),
                opens,
                "graph {graph}, compact {compact}, lean {lean}"
            );
        }
        // A graph that reads the exit on the hub's header chain is opened only
        // under a program that does, whatever else it decides.
        let chained = |chain| Context {
            trust: Trust {
                chained: chain,
                ..trust(true, true).trust
            },
            ..trust(true, true)
        };
        for (graph, chain, opens) in [
            (licash::recovery::CHAINED_FROM - 1, None, true),
            (licash::recovery::CHAINED_FROM, None, false),
            (licash::recovery::CHAINED_FROM, Some([7; 32]), true),
            (licash::recovery::CHAINED_FROM + 1, None, false),
        ] {
            q.graph.id = graph;
            let started = Holder::start(start(&q), &chained(chain));
            assert_eq!(started.is_ok(), opens, "graph {graph}, chain {chain:?}");
        }
        // A graph whose claims no claim of the same contract voids is opened
        // only under a program that decides so, which reads the chain too.
        let own = |chain, own_claims| Context {
            trust: Trust {
                own_claims,
                ..chained(chain).trust
            },
            ..chained(chain)
        };
        for (graph, chain, own_claims, opens) in [
            (
                licash::recovery::OWN_CLAIMS_FROM - 1,
                Some([7; 32]),
                false,
                true,
            ),
            (
                licash::recovery::OWN_CLAIMS_FROM,
                Some([7; 32]),
                false,
                false,
            ),
            (licash::recovery::OWN_CLAIMS_FROM, None, true, false),
            (licash::recovery::OWN_CLAIMS_FROM, Some([7; 32]), true, true),
        ] {
            q.graph.id = graph;
            let started = Holder::start(start(&q), &own(chain, own_claims));
            assert_eq!(
                started.is_ok(),
                opens,
                "graph {graph}, chain {chain:?}, own claims {own_claims}"
            );
        }
    }

    #[test]
    fn each_party_is_paid_to_a_native_segwit_script() {
        let id = [3; 32];
        let q = Quote::from_base(&testing::base(&id));
        let keys = HolderKeys::derive(&[1; 32], &id);
        let mut open = wire::Open {
            party: PartyPubKeys {
                payout_spk: wallet_script(5),
                ..keys.party.public()
            },
            claim_key: keys.claim_key(),
            deposit: OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            },
            coin: TxOut {
                value: Amount::from_sat(1_001_012),
                script_pubkey: ScriptBuf::new_p2tr(SECP256K1, keys.claim_key(), None),
            },
            wanted: wire::Wanted {
                request_height: 100,
                close_height: 1000,
                response_window: 24,
            },
            mock: true,
            request_keys: keys.public().request_keys().unwrap().digest(),
            funded: testing::funded(),
            close: testing::close(),
        };
        assert!(check_deposit(&open, &q.graph, &q.fees).is_ok());
        // A bare script relays no payout of hers.
        let bare = ScriptBuf::from_bytes(vec![0x51]);
        open.party.payout_spk = bare.clone();
        let error = check_deposit(&open, &q.graph, &q.fees).unwrap_err();
        assert!(error.to_string().contains("holder's payout"), "{error}");
        let mut hub = Hub::with(&[2; 32], q, None);
        assert!(hub.party().is_err(), "no payout script");
        hub.payout = Some(bare);
        assert!(hub.party().is_err());
        hub.payout = Some(wallet_script(6));
        assert_eq!(
            hub.party().unwrap().payout_script,
            wallet_script(6).to_bytes()
        );
    }

    /// Her coin is spent whole: it pays her reserve, the fee and her part of
    /// the contract, and what is left of it is below dust, none of it
    /// coming back as change.
    #[test]
    fn her_coin_pays_the_price_and_the_rest_of_it_is_her_part_and_below_dust() {
        let id = [3; 32];
        let q = Quote::from_base(&testing::base(&id));
        let keys = HolderKeys::derive(&[1; 32], &id);
        let open = |value| wire::Open {
            party: keys.party.public(),
            claim_key: keys.claim_key(),
            deposit: OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            },
            coin: TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new_p2tr(SECP256K1, keys.claim_key(), None),
            },
            wanted: wire::Wanted {
                request_height: 100,
                close_height: 1000,
                response_window: 24,
            },
            mock: true,
            request_keys: keys.public().request_keys().unwrap().digest(),
            funded: testing::funded(),
            close: testing::close(),
        };
        // 1 000 000 of reserve, 1 000 of fee, 12 of her part.
        assert_eq!(price(&q.graph, &q.fees).unwrap(), 1_001_012);
        for value in [1_001_012, 1_001_012 + 329] {
            check_deposit(&open(value), &q.graph, &q.fees).unwrap();
        }
        // Short of the price, or more than a contract takes of it: refused.
        let short = check_deposit(&open(1_001_011), &q.graph, &q.fees).unwrap_err();
        assert!(short.to_string().contains("below price"), "{short}");
        let long = check_deposit(&open(1_001_012 + 330), &q.graph, &q.fees).unwrap_err();
        assert!(long.to_string().contains("absorbed"), "{long}");
    }

    /// Her Base commits to the notes she funds her part with, worth exactly
    /// her part, and to the script she names for the default and the fee
    /// the hub keeps of her reserve there; the graph's default returns her
    /// reserve to that script, the hub's share and every dispute payout
    /// still to the payout scripts.
    #[test]
    fn a_base_commits_to_her_funded_notes_and_the_script_her_default_pays_her_reserve_to() {
        let id = [3; 32];
        let q = Quote::from_base(&testing::base(&id));
        let keys = HolderKeys::derive(&[1; 32], &id);
        let digest = keys.public().request_keys().unwrap().digest();
        let close = wallet_script(9);
        let offer_close = wire::CloseOffer {
            script: close.clone(),
            fee: 700,
        };
        let open = wire::Open {
            party: keys.party.public(),
            claim_key: keys.claim_key(),
            deposit: OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            },
            coin: TxOut {
                value: Amount::from_sat(1_001_012),
                script_pubkey: ScriptBuf::new_p2tr(SECP256K1, keys.claim_key(), None),
            },
            wanted: wire::Wanted {
                request_height: 100,
                close_height: 1000,
                response_window: 24,
            },
            mock: true,
            request_keys: digest,
            funded: testing::funded(),
            close: offer_close.clone(),
        };
        let hub_keys = HubKeys::from_secret(&[2; 32]);
        let hub = graph::party(&hub_keys.party.public());
        let checkpoint = q.chain.checkpoint.clone();
        let b = offer(&q, id, &open, [11; 32], &checkpoint, hub.clone()).unwrap();
        assert_eq!(b.parts().holder_wots, digest);
        assert_eq!(
            b.parts().funded,
            licash::spend::funded_root(&open.funded.outputs).unwrap()
        );
        let committed = b.parts().close.clone();
        assert_eq!(committed.script, close.to_bytes());
        assert_eq!(committed.fee, 700);
        // Her payout script is not what she named, and the open survives the
        // wire.
        assert_ne!(open.party.payout_spk, close);
        assert_eq!(wire::Open::decode(&open.encode()).unwrap(), open);
        for cut in [1, 9, 33] {
            assert!(wire::Open::decode(&open.encode()[..open.encode().len() - cut]).is_err());
        }

        // The default pays her reserve to the script she named, the hub its
        // share to its own.
        let (holder, hub_pub) = (keys.public(), hub_keys.public());
        let babe = graph::build(
            &b,
            &holder,
            &hub_pub,
            graph::draft_hmsg(b.parts().recipe.kept),
        )
        .unwrap();
        let set = babe.presign(OutPoint::null()).unwrap();
        let default = set.iter().find(|p| p.name == "default").unwrap();
        assert_eq!(default.tx.output.len(), 2);
        assert_eq!(default.tx.output[0].script_pubkey, close);
        assert_eq!(
            default.tx.output[0].value.to_sat(),
            b.parts().graph.reserve_alice
        );
        assert_eq!(
            default.tx.output[1].script_pubkey,
            graph::party_pub(&hub).unwrap().payout_spk
        );

        // Outputs worth other than her part, not the keyset's, too few or
        // too many: nothing opens.
        let output = |n: u64| {
            let point = licash::crypto::generator_mul(&n.into());
            licash::spend::Output::new(
                n,
                licash::crypto::Point::from_projective(&point),
                [n as u8; 32],
            )
            .unwrap()
        };
        for (outputs, error) in [
            (vec![output(8)], "worth 8"),
            (vec![output(8), output(4), output(1)], "worth 13"),
            (vec![output(12)], "keyset"),
            (vec![], "1 to"),
            ((0..33).map(|_| output(1)).collect(), "1 to"),
        ] {
            let other = wire::Open {
                funded: wire::FundedNotes {
                    ephemeral: output(3).blinded(),
                    outputs,
                },
                ..open.clone()
            };
            let e = offer(&q, id, &other, [11; 32], &checkpoint, hub.clone()).unwrap_err();
            assert!(e.to_string().contains(error), "{e}");
        }
        // A quote of no part of hers opens nothing.
        let mut none = q.clone();
        none.graph.deposit_units = 0;
        let e = offer(&none, id, &open, [11; 32], &checkpoint, hub.clone()).unwrap_err();
        assert!(e.to_string().contains("funded"), "{e}");
        // Neither does a fee that leaves no notes worth a dust output.
        let dear = wire::Open {
            close: wire::CloseOffer {
                fee: b.parts().graph.reserve_alice,
                ..offer_close
            },
            ..open.clone()
        };
        let e = offer(&q, id, &dear, [11; 32], &checkpoint, hub).unwrap_err();
        assert!(e.to_string().contains("default close"), "{e}");
    }

    #[test]
    fn funding_keeps_the_deposit_whole_and_the_segwit_txid() {
        let id = [3; 32];
        let base = testing::base(&id);
        let keys = HolderKeys::derive(&[1; 32], &id);
        let hub = HubKeys::from_secret(&[2; 32]);
        let coin = TxOut {
            value: Amount::from_sat(1_001_012),
            script_pubkey: ScriptBuf::new_p2tr(SECP256K1, keys.claim_key(), None),
        };
        let open = wire::Open {
            party: keys.party.public(),
            claim_key: keys.claim_key(),
            deposit: OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            },
            coin: coin.clone(),
            wanted: wire::Wanted {
                request_height: 100,
                close_height: 1000,
                response_window: 24,
            },
            mock: true,
            request_keys: keys.public().request_keys().unwrap().digest(),
            funded: testing::funded(),
            close: testing::close(),
        };
        let graph =
            graph::build(&base, &keys.public(), &hub.public(), graph::draft_hmsg(2)).unwrap();
        let out = contract_output(&graph).unwrap();
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: open.deposit,
                    ..Default::default()
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([8; 32]),
                        vout: 0,
                    },
                    ..Default::default()
                },
            ],
            // Her coin is spent whole: no change of hers comes of it.
            output: vec![out.clone()],
        };
        let total: u64 = funding.output.iter().map(|o| o.value.to_sat()).sum();
        let hub_coin = TxOut {
            value: Amount::from_sat(total + 100 - coin.value.to_sat()),
            script_pubkey: coin.script_pubkey.clone(),
        };
        let prevouts = vec![coin, hub_coin];
        check_funds(&base, &open, &funding, &prevouts, &out).unwrap();
        let mut bad = funding.clone();
        bad.input[1].previous_output = open.deposit;
        assert!(check_funds(&base, &open, &bad, &prevouts, &out).is_err());
        let mut bad = funding.clone();
        bad.output[0].value -= Amount::from_sat(1);
        assert!(check_funds(&base, &open, &bad, &prevouts, &out).is_err());
        let mut bad = funding.clone();
        bad.input[1].script_sig = ScriptBuf::from_bytes(vec![0x51]);
        assert!(check_funds(&base, &open, &bad, &prevouts, &out).is_err());
        let mut bad = prevouts.clone();
        bad[1].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        assert!(check_funds(&base, &open, &funding, &bad, &out).is_err());
        let mut bad = prevouts.clone();
        bad[0].value += Amount::from_sat(1);
        assert!(check_funds(&base, &open, &funding, &bad, &out).is_err());
        let mut bad = prevouts;
        bad[1].value += Amount::from_sat(100000);
        assert!(check_funds(&base, &open, &funding, &bad, &out).is_err());
    }
    /// One complete opening, restarted at every boundary. It also exercises
    /// both parties' mock dispute and the one-choice-per-ID secrecy rule.
    #[test]
    fn opening_resumes_without_regarbling_and_the_hub_proves_the_dispute() {
        let id = [3; 32];
        let b = testing::base(&id);
        let q = Quote::from_base(&b);
        let ctx = Context {
            tip: 1,
            trust: Trust::mock(),
        };
        let key = HolderKeys::derive(&[1; 32], &id).party.funding;
        let coin = TxOut {
            value: Amount::from_sat(1_001_012),
            script_pubkey: ScriptBuf::new_p2tr(SECP256K1, key.x_only_public_key().0, None),
        };
        let wanted = wire::Wanted {
            request_height: q.graph.request_height,
            close_height: q.graph.close_height,
            response_window: q.graph.response_window,
        };
        let (mut a, first) = Holder::with_id(
            Start {
                seed: [1; 32],
                quote: q.clone(),
                checkpoint: q.chain.checkpoint.clone(),
                deposit: OutPoint {
                    txid: Txid::from_byte_array([4; 32]),
                    vout: 0,
                },
                coin: coin.clone(),
                payout: wallet_script(5),
                wanted,
                funded: testing::funded(),
                close: testing::close(),
            },
            id,
            &ctx,
        )
        .unwrap();
        let bounds = Bounds {
            lock: 2000,
            response_window: 24,
        };
        let mut h = Hub::with(&[2; 32], q.clone(), Some(bounds));
        h.payout = Some(wallet_script(6));
        // An Open that binds no request keys opens nothing: the statement
        // could be proved of an exit she never started.
        let open = Envelope::from_bytes(&sent(&first, Kind::Open))
            .unwrap()
            .body;
        let unbound = wire::Open {
            request_keys: [0; 32],
            ..wire::Open::decode(&open).unwrap()
        };
        let mut fresh = Hub::with(&[2; 32], q, Some(bounds));
        fresh.payout = Some(wallet_script(6));
        let error = fresh
            .step(message(id, Kind::Open, unbound.encode()), &ctx)
            .unwrap_err();
        assert!(error.to_string().contains("identity"), "{error}");
        let terms = h
            .step(Input::Message(sent(&first, Kind::Open)), &ctx)
            .unwrap();
        // Bound, Base is on her keys.
        let request_keys = a.keys.public().request_keys().unwrap();
        assert_eq!(h.base().unwrap().parts().holder_wots, request_keys.digest());
        reload(&mut a, &mut h, &ctx);
        let commit = a
            .step(Input::Message(sent(&terms, Kind::Terms)), &ctx)
            .unwrap();
        reload(&mut a, &mut h, &ctx);
        // A commitment under other keys than Base binds is refused.
        let body = Envelope::from_bytes(&sent(&commit, Kind::Commit))
            .unwrap()
            .body;
        let swapped = wire::Commit {
            holder: HolderKeys::derive(&[8; 32], &id).public(),
            ..wire::Commit::decode(&body).unwrap()
        };
        let mut other = Hub::load(&h.to_bytes(), &ctx).unwrap();
        let error = other
            .step(message(id, Kind::Commit, swapped.encode()), &ctx)
            .unwrap_err();
        assert!(error.to_string().contains("Base binds"), "{error}");
        let chosen = h
            .step(Input::Message(sent(&commit, Kind::Commit)), &ctx)
            .unwrap();
        // Replayed, or the hub loaded again, it compiles no statement: the
        // draft is kept.
        let builds = graph::BUILDS.with(std::cell::Cell::get);
        let replay = h
            .step(Input::Message(sent(&commit, Kind::Commit)), &ctx)
            .unwrap();
        assert_eq!(replay, chosen);
        h = Hub::load(&h.to_bytes(), &ctx).unwrap();
        assert_eq!(graph::BUILDS.with(std::cell::Cell::get), builds);
        reload(&mut a, &mut h, &ctx);
        let opened = a
            .step(Input::Message(sent(&chosen, Kind::Choose)), &ctx)
            .unwrap();
        reload(&mut a, &mut h, &ctx);
        assert_eq!(
            a.step(Input::Message(sent(&chosen, Kind::Choose)), &ctx)
                .unwrap(),
            opened
        );
        let original = a.to_bytes();
        let different: Vec<_> = (1..=4)
            .filter(|i| !a.kept.as_ref().unwrap().contains(i))
            .collect();
        assert!(a
            .step(
                message(id, Kind::Choose, wire::Choose { kept: different }.encode()),
                &ctx
            )
            .is_err());
        assert_eq!(a.to_bytes(), original);
        let Out::Fund { outputs, .. } = chosen
            .iter()
            .find(|o| matches!(o, Out::Fund { .. }))
            .unwrap()
        else {
            unreachable!()
        };
        let hub_coin = TxOut {
            value: Amount::from_sat(2000000),
            script_pubkey: coin.script_pubkey.clone(),
        };
        let total_out: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
        let mut outputs = outputs.clone();
        outputs.push(TxOut {
            value: Amount::from_sat(3_001_012 - total_out - 100),
            script_pubkey: graph::party_pub(&h.base().unwrap().parts().parties[1])
                .unwrap()
                .payout_spk,
        });
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: a.deposit(),
                    ..Default::default()
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([8; 32]),
                        vout: 0,
                    },
                    ..Default::default()
                },
            ],
            output: outputs,
        };
        let prevouts = vec![coin, hub_coin];
        let ack = h
            .step(
                Input::Funded {
                    funding: funding.clone(),
                    prevouts: prevouts.clone(),
                },
                &ctx,
            )
            .unwrap();
        assert!(ack.is_empty());
        reload(&mut a, &mut h, &ctx);
        assert!(h
            .step(Input::Message(sent(&opened, Kind::Opened)), &ctx)
            .unwrap()
            .is_empty());
        assert!(h
            .step(Input::Message(sent(&opened, Kind::Opened)), &ctx)
            .unwrap()
            .is_empty());
        let mut offer = vec![];
        let kept = a.kept.clone().unwrap();
        let mut stored_instance = vec![];
        for i in kept {
            let bytes = a.instance(i).unwrap();
            // Even if a malformed circuit was committed before the choice,
            // keeping it must fail before any funding signature leaves.
            let mut bad = Instance::from_bytes(&bytes).unwrap();
            bad.gc.ands.pop();
            let mut adversarial = Hub::load(&h.to_bytes(), &ctx).unwrap();
            adversarial.commit.as_mut().unwrap().commitments[i as usize - 1] = bad.commitment();
            let before = adversarial.to_bytes();
            let err = adversarial
                .step(
                    message(
                        id,
                        Kind::Instance,
                        wire::Instance {
                            i,
                            bytes: bad.to_bytes(),
                        }
                        .encode(),
                    ),
                    &ctx,
                )
                .unwrap_err();
            assert!(err.to_string().contains("invalid instance"), "{err}");
            assert_eq!(adversarial.to_bytes(), before);
            stored_instance.push((i, bytes.clone()));
            offer = h
                .step(
                    message(id, Kind::Instance, wire::Instance { i, bytes }.encode()),
                    &ctx,
                )
                .unwrap();
            assert!(matches!(offer.first(), Some(Out::Keep { i: n, .. }) if *n == i));
            reload(&mut a, &mut h, &ctx);
        }
        let consent = a
            .step(Input::Message(sent(&offer, Kind::Offer)), &ctx)
            .unwrap();
        reload(&mut a, &mut h, &ctx);
        let sign = h
            .step(Input::Message(sent(&consent, Kind::Consent)), &ctx)
            .unwrap();
        let Out::Sign { mut funding, .. } = sign[0].clone() else {
            panic!("not signing");
        };
        sign_deposit(&mut funding, 1, &prevouts, &key);
        let signed = h.step(Input::Signed(funding), &ctx).unwrap();
        reload(&mut a, &mut h, &ctx);
        let sign = a
            .step(Input::Message(sent(&signed, Kind::Signed)), &ctx)
            .unwrap();
        let Out::Sign { mut funding, .. } = sign[0].clone() else {
            panic!("not signing");
        };
        sign_deposit(&mut funding, 0, &prevouts, &key);
        // A wallet's result cannot overwrite the hub's signed witnesses.
        funding.input[1].witness = Witness::from_slice(&[b"spoiled"]);
        let funded = a.step(Input::Signed(funding), &ctx).unwrap();
        reload(&mut a, &mut h, &ctx);
        assert!(!a.abandonable());
        assert!(!h.abandonable());
        let envelope = Envelope::from_bytes(&sent(&funded, Kind::Funded)).unwrap();
        let mut poisoned = wire::Funded::decode(&envelope.body).unwrap();
        poisoned.funding.input[1].witness = Witness::from_slice(&[b"spoiled"]);
        h.step(message(id, Kind::Funded, poisoned.encode()), &ctx)
            .unwrap();
        reload(&mut a, &mut h, &ctx);
        assert_eq!(Hub::peek(&h.to_bytes()).unwrap().phase, HubPhase::Funded);
        let ao = a.signed().unwrap();
        let ho = h.signed().unwrap();
        assert_eq!(ao.funding, ho.funding);
        // Ended with no exit, the default pays her reserve to the script her
        // Base names and the hub its wallet's, signed by both: the hub adds
        // a fee coin to it.
        let default = ho.default_close().unwrap();
        let reserve = Amount::from_sat(ao.base.parts().graph.reserve_alice);
        assert_eq!(default.output[0].script_pubkey, testing::close().script);
        assert_eq!(default.output[0].value, reserve);
        assert_eq!(default.output[1].script_pubkey, wallet_script(6));
        assert_eq!(
            default.output[0].value + default.output[1].value,
            ao.babe.value()
        );
        assert_eq!(
            default.input[0].witness.len(),
            4,
            "both signatures, the leaf, its control"
        );
        let request = ao.request(&a.keys, 3072, &[9; 32]).unwrap();
        assert_eq!(ho.requested_b(&request).unwrap(), (3072, [9; 32]));
        // Her publication, a fee input added, signed over every input: its
        // carrier's signature commits to them, so none can be added.
        let slot = crate::dispute::presign(&ao.set, "request")
            .unwrap()
            .tx
            .output[licash_statement::SLOT_VOUT as usize]
            .clone();
        let fee = TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: wallet_script(5),
        };
        let mut p = ao
            .publication(&a.keys, &[1, 2, 3], vec![fee.clone()])
            .unwrap();
        p.input.push(TxIn::default());
        let prevouts = [slot.clone(), fee.clone()];
        assert!(ao
            .sign_publication(&a.keys, &mut p, &prevouts[..1])
            .is_err());
        ao.sign_publication(&a.keys, &mut p, &prevouts).unwrap();
        let sig = p.input[0].witness.nth(0).unwrap();
        assert_eq!(sig.len(), 64, "SIGHASH_DEFAULT, no sighash byte");
        let sig = lichen_btc::bitcoin::secp256k1::schnorr::Signature::from_slice(sig).unwrap();
        let leaf = ao
            .babe
            .slot()
            .unwrap()
            .leaf("publish")
            .unwrap()
            .script
            .clone();
        let verify = |tx: &Transaction, prevouts: &[TxOut]| {
            lichen_btc::sighash::verify_tapscript(&a.keys.claim_key(), &sig, tx, 0, prevouts, &leaf)
        };
        verify(&p, &prevouts).unwrap();
        let mut pinned = p.clone();
        pinned.input.push(TxIn::default());
        assert!(verify(&pinned, &[slot.clone(), fee.clone(), fee.clone()]).is_err());
        // The hub's reclaim and disclosure alike, sealed once their fee
        // coin is in.
        let hub_key = h.keys().party.payment.x_only_public_key().0;
        let disclose = crate::dispute::presign(&ho.set, "respond")
            .unwrap()
            .tx
            .output[licash_statement::SLOT_VOUT as usize]
            .clone();
        for (mut tx, spent, tree, name) in [
            (
                ho.reclaim(h.keys()).unwrap(),
                slot,
                ho.babe.slot().unwrap(),
                "reclaim",
            ),
            (
                ho.disclosure(h.keys(), &[4, 5, 6], vec![]).unwrap(),
                disclose,
                ho.babe.disclose().unwrap(),
                "disclose",
            ),
        ] {
            tx.input.push(TxIn::default());
            let prevouts = [spent, fee.clone()];
            ho.seal(h.keys(), &mut tx, &prevouts).unwrap();
            let sig = tx.input[0].witness.nth(0).unwrap();
            assert_eq!(sig.len(), 64, "{name}: SIGHASH_DEFAULT");
            let sig = lichen_btc::bitcoin::secp256k1::schnorr::Signature::from_slice(sig).unwrap();
            let leaf = tree.leaf(name).unwrap().script.clone();
            let verify = |tx: &Transaction, prevouts: &[TxOut]| {
                lichen_btc::sighash::verify_tapscript(&hub_key, &sig, tx, 0, prevouts, &leaf)
            };
            verify(&tx, &prevouts).unwrap();
            let mut pinned = tx.clone();
            pinned.input.push(TxIn::default());
            let more = [prevouts[0].clone(), fee.clone(), fee.clone()];
            assert!(verify(&pinned, &more).is_err(), "{name}");
            assert!(ho.seal(h.keys(), &mut tx, &prevouts[..1]).is_err());
        }
        let mut other = default.clone();
        assert!(
            ho.seal(h.keys(), &mut other, std::slice::from_ref(&fee))
                .is_err(),
            "not a slot's spend"
        );
        // Bitcoin accepts a digit of 15 written as 16 (the script clamps it
        // with OP_MIN): read as 15, as the statement does. A negative
        // digit fails the script, and the read.
        let fifteens = ao.request(&a.keys, 3072, &[0xff; 32]).unwrap();
        let rewrite = |to: &[u8]| {
            let mut tx = fifteens.clone();
            let items: Vec<Vec<u8>> = tx.input[0]
                .witness
                .iter()
                .map(|i| if i == [15] { to.to_vec() } else { i.to_vec() })
                .collect();
            tx.input[0].witness = items.into();
            tx
        };
        assert_ne!(rewrite(&[16]), fifteens);
        assert_eq!(ho.requested_b(&rewrite(&[16])).unwrap(), (3072, [0xff; 32]));
        assert!(ho.requested_b(&rewrite(&[0x81])).is_err());
        // The hub's statement checks her request against the keys the graph
        // compiles with (lichen_wots's signatures, as the script does).
        let keys = ho.holder.request_keys().unwrap();
        let signed = |tx: &Transaction| {
            let witness: Vec<&[u8]> = tx.input[0].witness.iter().collect();
            keys.signed(&witness)
        };
        assert!(signed(&request) && signed(&fifteens) && signed(&rewrite(&[16])));
        assert!(!signed(&rewrite(&[14])));
        let stranger = HolderKeys::derive(&[8; 32], &[1; 32]).public();
        let theirs = stranger.request_keys().unwrap();
        let witness: Vec<&[u8]> = request.input[0].witness.iter().collect();
        assert!(!theirs.signed(&witness));
        assert!(ao.offer.sigs.keys().all(|n| !HubProves::withheld(n)));
        assert!(ao.consent.sigs.keys().any(|n| HubProves::withheld(n)));
        let response = ho.respond(&h.keys, 1024).unwrap();
        assert_eq!(HubProves::responded_word(&response).unwrap().0, 1024);
        assert_eq!(crate::graph::responded(&ho.base, &response).unwrap(), 1024);
        let proof = lichen_babe::statement::mock_prove(&journal(&ao.base));
        let asserted = ho.assert(&h.keys, &proof).unwrap();
        assert!(ao.verify_assertion(&asserted).unwrap());
        let challenge = ao.challenge(&a.keys, &asserted).unwrap();
        // A contract opened before Lichen bound her dealing to the
        // journal: the hub pre-signed for the dealing of her garbler seed
        // alone, and her challenge reveals that one's secrets, valid
        // signatures under the hub's adaptor keys. Pre-signatures for
        // neither, no challenge.
        let r = &ao.base.parts().recipe;
        let unbound = |seed: [u8; 32]| {
            lichen_babe::vsss::deal(
                lichen_babe::setup::DIGITS,
                (r.instances - r.kept) as usize,
                &mut <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed(seed),
            )
            .1
        };
        let sighash = HubProves::challenge_sighash(&ao.set).unwrap();
        let mut legacy = a.signed().unwrap();
        legacy.offer.presigs = h.keys.adaptor.presign(
            &sighash,
            &points(&unbound(a.keys.garbler.derive_bytes("dealing"))),
        );
        let c = legacy.challenge(&a.keys, &asserted).unwrap();
        let args = graph::link_args(&c);
        let digits = legacy.assertion(&asserted).unwrap().digits;
        for (j, v) in digits.iter().enumerate() {
            let sig =
                lichen_btc::bitcoin::secp256k1::schnorr::Signature::from_slice(&args[2 * j + 1])
                    .unwrap();
            SECP256K1
                .verify_schnorr(&sig, &sighash, &ao.hub.adaptor[j][*v as usize])
                .unwrap();
        }
        legacy.offer.presigs = h.keys.adaptor.presign(&sighash, &points(&unbound([7; 32])));
        assert!(legacy.challenge(&a.keys, &asserted).is_err());
        let (i, bytes) = &stored_instance[0];
        assert!(ho
            .answer(&asserted, None, &challenge, *i, bytes)
            .unwrap()
            .is_some());
        // Mined with π2 and π3 replaced (the same txid): no proof read
        // from the block, but the hub's, of the assertion it signed.
        let mut mined = asserted.clone();
        let mut items = mined.input[0].witness.to_vec();
        items[0] = vec![0xff; items[0].len()];
        items[1] = vec![0xff; items[1].len()];
        mined.input[0].witness = lichen_btc::bitcoin::Witness::from_slice(&items);
        assert_eq!(mined.compute_txid(), asserted.compute_txid());
        assert!(ho.babe.assertion(&mined).unwrap().proof.is_none());
        assert!(!ao.verify_assertion(&mined).unwrap());
        let challenged = ao.challenge(&a.keys, &mined).unwrap();
        assert!(ho
            .answer(&mined, None, &challenged, *i, bytes)
            .unwrap()
            .is_none());
        assert!(ho
            .answer(&mined, Some(&asserted), &challenged, *i, bytes)
            .unwrap()
            .is_some());
        // Not the one in the block: the proof read from the block.
        let mut other = asserted.clone();
        other.lock_time = lichen_btc::bitcoin::absolute::LockTime::from_consensus(1);
        assert!(ho
            .answer(&mined, Some(&other), &challenged, *i, bytes)
            .unwrap()
            .is_none());
        let mut bad = Instance::from_bytes(bytes).unwrap();
        bad.gc.ands.pop();
        assert!(ho
            .answer(&asserted, None, &challenge, *i, &bad.to_bytes())
            .unwrap()
            .is_none());
        let mut bad = Instance::from_bytes(bytes).unwrap();
        bad.hmsg[0] ^= 1;
        assert!(ho
            .answer(&asserted, None, &challenge, *i, &bad.to_bytes())
            .unwrap()
            .is_none());
        let rotated = Context {
            tip: 2000,
            trust: Trust {
                program: [99; 32],
                mock: true,
                compact: true,
                lean: true,
                chained: None,
                own_claims: false,
            },
        };
        assert!(Holder::load(&a.to_bytes(), &[1; 32], &rotated).is_ok());
        assert!(Hub::load(&h.to_bytes(), &rotated).is_ok());
        assert!(Holder::load(&a.to_bytes(), &[6; 32], &ctx).is_err());
        let mut corrupt = a.to_bytes();
        corrupt[20] ^= 1;
        assert!(Holder::load(&corrupt, &[1; 32], &ctx).is_err());
        assert!(Holder::load(b"LCOS\0\x01", &[1; 32], &ctx).is_err());
        assert!(Holder::load(
            &a.to_bytes(),
            &[1; 32],
            &Context {
                tip: 1,
                trust: Trust {
                    program: [11; 32],
                    mock: false,
                    compact: false,
                    lean: false,
                    chained: None,
                    own_claims: false,
                }
            }
        )
        .is_err());
    }
}
