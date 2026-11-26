//! The graph both parties build: Lichen's BABE graph (`lichen_babe::graph`)
//! behind Licash's front, the exit where only the hub proves, of Base's
//! terms and parties, the holder's one-time keys and the hub's prover
//! keys, and the kept instances' hashlocks:
//!
//! ```text
//! request (the holder: b, E; her claim published by spending its slot;
//!  │         her purse, of her reserve, for her fees)
//!  ├─ request_timeout (after w_H)          → the holder: b
//!  └─ respond (the hub: b′; its disclose slot)
//!      ├─ respond_timeout (after w_X)      → the holder: b′, the rest the hub's
//!      └─ contest (the holder: she does not accept b′)
//!          ├─ contest_timeout (after w_A)  → the holder: b
//!          └─ assert (the hub: π1, Lamport)
//!              ├─ success (after Δ2)       → the holder: b′, the rest the hub's
//!              └─ challenge_assert (the holder)
//!                  ├─ wrongly_challenged_k → as success (the proof was valid)
//!                  └─ failure (after Δ1)   → the holder: b
//! ```
//!
//! A response she leaves alone pays what it says, and nobody proves
//! anything: she contests only a response her own check of the hub's
//! evidence does not bear out, and the hub then proves it or pays her `b`.
//!
//! Paying `b`, the hub forfeits its reserve, but on `request_timeout` of
//! graphs from id [`RETURNING`] on, where the hub only kept silent, it
//! gets its reserve back less her request's fees (her purse); paying `b′`,
//! each party keeps its own. Each value is read from the chain, signed under a one-time key
//! in a link's witness: `b` under the holder's in `request`'s, `b′` under
//! the hub's in `respond`'s, so the statement reads `b′` from Bitcoin as it
//! reads the claim (`licash_statement`).
//!
//! The contract output (F's output [`FUNDING_VOUT`]) depends only on
//! Base and the one-time keys for `b` and `E`, not on the hub's prover
//! keys or the hashlocks: F can be funded before the instances are in.
//!
//! The statement is fixed by Base alone ([`journal`], [`kind`]): the
//! holder garbles for it as soon as she has Base.

use anyhow::{bail, ensure, Context, Result};
use ark_bn254::Bn254;
use ark_groth16::Proof;
use licash::base::{Base, GraphTerms, Parts, Party};
use licash_statement::{script_digit, JOURNAL_LEN, SLOT_VOUT};
use lichen_babe::graph::{link_leaf, verify_drop, Front, FrontLink, Graph, Payout, Tail};
use lichen_babe::reveal::{complete, reveal_args, LamportPub, Preimage};
use lichen_babe::setup::{Hash, Secret, DIGITS, VALUES};
use lichen_babe::statement::Kind;
use lichen_btc::adaptor::AdaptorSig;
use lichen_btc::bitcoin::key::Keypair;
use lichen_btc::bitcoin::opcodes::all::OP_CHECKSIG;
use lichen_btc::bitcoin::script::Builder;
use lichen_btc::bitcoin::secp256k1::{Message, XOnlyPublicKey};
use lichen_btc::bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use lichen_btc::script::BuilderExt;
use lichen_btc::sighash::sign_tapscript_acp;
use lichen_btc::taptree::{Leaf, TapTree};
use lichen_btc::tx::{build_spend, Timelock};
use lichen_btc::witness::tapscript_witness;
use lichen_contract::{
    anchor_tree, payout_less_signed, wots_shape, ContractParams, Core, PartyPubKeys, Presign, Role,
    Terms, POST_CSV,
};
use lichen_wots::{WotsParams, WotsPublic, WotsSig};

pub use lichen_babe::graph::link_args;

/// F's output the graph spends, as the statement reads it.
pub const FUNDING_VOUT: u32 = 0;

/// A standard, non-dust P2TR publication slot.
pub const SLOT: Amount = Amount::from_sat(330);

/// What `success` pays: `b′`, read from the hub's signature in `respond`.
const REDUCED: Payout = Payout::Other("reduced");

/// What `request_timeout` pays from graph id [`RETURNING`] on: `b`, read
/// from the holder's signature in `request`, all her reserve (her purse
/// refunded of the hub's), and the hub's reserve back to the hub less what
/// the links took, her purse among it.
const RETURNED: Payout = Payout::Other("returned");

/// The first graph id whose `request_timeout` returns the hub its reserve
/// ([`RETURNED`]): a hub that never responds pays `b` and the fees of her
/// request, but forfeits no more of its reserve to a holder who may have
/// asked only to tie it up. Graphs of
/// earlier ids (contracts opened before) pay her both reserves, as they
/// were signed.
pub const RETURNING: u32 = 8;

/// The purse of a graph with these reserves ([`Spec::purse`]): her reserve
/// less the dust limit, half of the hub's at most; none if it would be dust.
pub fn purse(reserve_alice: Amount, reserve_hub: Amount, dust: Amount) -> Option<Amount> {
    let purse = (reserve_alice.checked_sub(dust)?).min(reserve_hub / 2);
    (purse >= dust).then_some(purse)
}

/// Where `request` pays the holder her purse ([`Spec::purse`]), after its
/// slot.
pub const PURSE_VOUT: u32 = SLOT_VOUT + 1;

/// The holder's one-time keys: for `b`, which her payout's bits read,
/// and for `E`, her claim's digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderPub {
    pub b_key: WotsPublic,
    pub e_key: WotsPublic,
}

/// The hub's keys as the prover: its one-time key for `b′`, its Lamport
/// key for π1 and its adaptor keys for her challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubPub {
    pub b_key: WotsPublic,
    pub lamport: LamportPub,
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
}

fn wots_of(key: &WotsPublic, bytes: u32, what: &str) -> Result<()> {
    let params = WotsParams::for_bytes(bytes);
    ensure!(
        key.params == params && key.digits.len() == params.total_digits() as usize,
        "{what} of other parameters"
    );
    Ok(())
}

impl HolderPub {
    pub fn check(&self) -> Result<()> {
        wots_of(&self.b_key, 4, "a key for b")?;
        wots_of(&self.e_key, 32, "a key for E")
    }

    /// Her request's keys as the hub's statement checks her request
    /// against them; a v4 Base binds their digest.
    pub fn request_keys(&self) -> Result<licash_hp::RequestKeys> {
        self.check()?;
        licash_hp::RequestKeys::new(self.b_key.digits.clone(), self.e_key.digits.clone())
            .context("her request's keys")
    }
}

impl HubPub {
    pub fn check(&self) -> Result<()> {
        wots_of(&self.b_key, 4, "a key for b′")?;
        ensure!(
            self.lamport.0.len() == DIGITS && self.adaptor.len() == DIGITS,
            "a Lamport and an adaptor key set per digit of π1"
        );
        Ok(())
    }
}

/// What the instances are garbled for: a genuine proof by Base's program
/// (the hub's statement's guest), or, under mock trust, anyone's.
pub fn kind(base: &Base, mock: bool) -> Kind {
    match mock {
        true => Kind::Mock,
        false => Kind::Risc0(base.parts().recipe.program),
    }
}

/// The statement's journal, fixed by Base.
pub fn journal(base: &Base) -> [u8; JOURNAL_LEN] {
    licash_hp::contract(base).journal()
}

pub fn party(keys: &PartyPubKeys) -> Party {
    Party {
        funding: keys.funding.serialize(),
        payment: keys.payment.serialize(),
        delayed: keys.delayed.serialize(),
        payout_script: keys.payout_spk.to_bytes(),
    }
}

pub fn party_pub(p: &Party) -> Result<PartyPubKeys> {
    Ok(PartyPubKeys {
        funding: XOnlyPublicKey::from_slice(&p.funding)?,
        payment: XOnlyPublicKey::from_slice(&p.payment)?,
        delayed: XOnlyPublicKey::from_slice(&p.delayed)?,
        payout_spk: ScriptBuf::from_bytes(p.payout_script.clone()),
    })
}

/// Base's graph terms as Lichen's payout reads them: its rest that of the
/// cap past the binary outputs ([`Parts::rest`]).
pub fn terms(p: &Parts) -> Result<Terms> {
    let g = &p.graph;
    Ok(Terms {
        id: g.id,
        unit: Amount::from_sat(g.unit_sats),
        bits: g.bits.into(),
        low_bits: g.low_bits.into(),
        deposit: g.deposit_units,
        t_close: g.close_height,
        reserve_alice: Amount::from_sat(g.reserve_alice),
        reserve_hub: Amount::from_sat(g.reserve_hub),
        rest: p.rest()?,
    })
}

/// `request`'s `b`, as the payout of `base` counts the word she signed
/// (the statement's [`licash_hp::payout`]), and `E`.
pub fn requested(base: &Base, request: &Transaction) -> Result<(u32, [u8; 32])> {
    let (word, e) = HubProves::requested_word(request)?;
    Ok((licash_hp::payout(base).amount(word), e))
}

/// `respond`'s `b′`, as the payout of `base` counts the word the hub
/// signed.
pub fn responded(base: &Base, respond: &Transaction) -> Result<u32> {
    let (word, _) = HubProves::responded_word(respond)?;
    Ok(licash_hp::payout(base).amount(word))
}

/// The word that signs `amount` units of the payout of `terms`: what both
/// parties sign, the same of the same amount after any restart
/// (`Terms::word`).
pub fn word(terms: &Terms, amount: u32) -> Result<u32> {
    terms.word(u64::from(amount))
}

/// The dispute's windows, relative, in blocks: `w_H` for the hub's
/// response, `k` for her claim's publication (after it the hub may reclaim
/// an unspent slot), `w_X` for her contest of the response, `w_A` for the
/// hub's assertion after her contest; and BABE's tail's, `Δ2` her
/// challenge, `Δ1` its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Windows {
    pub w_h: u16,
    pub k: u16,
    pub w_x: u16,
    pub w_a: u16,
    pub tail: lichen_babe::graph::Windows,
}

/// The windows of Base's terms.
pub fn windows(g: &GraphTerms) -> Windows {
    Windows {
        w_h: g.response_window,
        k: g.publication_window,
        w_x: g.contest_window,
        w_a: g.assert_window,
        tail: lichen_babe::graph::Windows {
            delta2: g.challenge_window,
            delta1: g.answer_window,
        },
    }
}

#[cfg(test)]
thread_local! {
    /// How many statements [`build`] compiled on this thread, for tests of
    /// what does not compile one.
    pub(crate) static BUILDS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// The graph of `base` with the holder's and the hub's keys and the kept
/// instances' hashlocks, in the order of the instances kept.
pub fn build(base: &Base, holder: &HolderPub, hub: &HubPub, hmsg: Vec<Hash>) -> Result<HubProves> {
    #[cfg(test)]
    BUILDS.with(|b| b.set(b.get() + 1));
    let p = base.parts();
    let g = &p.graph;
    let windows = windows(g);
    let pubs = [party_pub(&p.parties[0])?, party_pub(&p.parties[1])?];
    HubProves::new(
        Spec {
            terms: terms(p)?,
            // The default returns her reserve to the script her Base names,
            // not her payout script.
            close_spk: ScriptBuf::from_bytes(p.close.script.clone()),
            // The graph reads neither the contract's funding amount nor its
            // deadline margin (Base's, for the request's latest height).
            params: ContractParams {
                funding_amount: Amount::ZERO,
                to_self_delay: g.to_self_delay,
                commit_fee: Amount::from_sat(g.commit_fee),
                presign_fee: Amount::from_sat(g.presign_fee),
                dust: Amount::from_sat(g.dust),
                delta: g.delta,
                delta_prime: g.delta_prime,
                deadline_margin: 0,
            },
            pubs,
            b_key: holder.b_key.clone(),
            e_key: holder.e_key.clone(),
            claim_key: XOnlyPublicKey::from_slice(&p.claim_key)?,
            hub_b: hub.b_key.clone(),
            windows,
        },
        Tail {
            lamport: hub.lamport.clone(),
            adaptor: hub.adaptor.clone(),
            hmsg,
            windows: windows.tail,
        },
    )
}

/// Hashlocks for a graph built before the instances are kept, one per
/// kept instance (the leaves must differ): its contract output is the
/// graph's.
pub fn draft_hmsg(kept: u16) -> Vec<Hash> {
    (0..kept).map(|i| [i as u8 ^ 0xa5; 32]).collect()
}

/// F's output the graph spends.
pub fn contract_output(graph: &HubProves) -> Result<TxOut> {
    Ok(TxOut {
        value: graph.value(),
        script_pubkey: graph.tree()?.script_pubkey(),
    })
}

/// What Licash's front is built from, besides BABE's tail.
#[derive(Clone, Debug)]
pub struct Spec {
    pub terms: Terms,
    pub params: ContractParams,
    /// The holder's keys, then the hub's.
    pub pubs: [PartyPubKeys; 2],
    /// Where the default returns the holder's reserve.
    pub close_spk: ScriptBuf,
    /// The holder's one-time keys for `b` (the payout's bit outputs read
    /// it) and for `E`.
    pub b_key: WotsPublic,
    pub e_key: WotsPublic,
    /// The holder's key authorizing the complete claim publication.
    pub claim_key: XOnlyPublicKey,
    /// The hub's one-time key for `b′` (the reduced payout's bit outputs
    /// read it).
    pub hub_b: WotsPublic,
    pub windows: Windows,
}

impl Spec {
    fn view(&self) -> Core<'_> {
        Core {
            terms: &self.terms,
            params: &self.params,
            pubs: &self.pubs,
            close_spk: &self.close_spk,
        }
    }

    fn hub_key(&self) -> XOnlyPublicKey {
        self.pubs[Role::Hub.idx()].payment
    }

    /// What `request` pays the holder of her reserve at once, to her
    /// anchor's script, for the fees of her forced close: all of it but
    /// the dust limit, so that she needs no coin of her own on Bitcoin to
    /// force it (her reserve has no other use on that path). Taken in
    /// `request`, it is short of her reserve wherever it is paid after
    /// ([`Front::pay`]): each party ends with what it would have. Where
    /// her claim stands and the hub forfeits its reserve it counts among
    /// the floors that reserve pays, so at most half of it, the other half
    /// for the links' floors (on [`RETURNED`] too, which refunds it of the
    /// hub's reserve). None if it would be dust.
    fn purse(&self) -> Option<Amount> {
        purse(
            self.terms.reserve_alice,
            self.terms.reserve_hub,
            self.params.dust,
        )
    }

    /// `request`'s slot: the holder's `publish`, any time, a transaction
    /// whose outputs carry her claim under her signature; or, after `k`,
    /// the hub's `reclaim` of a slot she left unspent (then her claim
    /// reads as malformed).
    fn slot(&self) -> Result<TapTree> {
        let publish = Builder::new()
            .push_x_only_key(&self.claim_key)
            .push_opcode(OP_CHECKSIG);
        let k = self.windows.k;
        let reclaim = Builder::new()
            .csv(k)
            .push_x_only_key(&self.hub_key())
            .push_opcode(OP_CHECKSIG);
        TapTree::new(vec![
            Leaf::new("publish", publish.into_script(), Timelock::NONE),
            Leaf::new("reclaim", reclaim.into_script(), Timelock::csv(k)),
        ])
    }

    /// `respond`'s disclose slot: the hub's, any time, to publish what its
    /// proof cites; or never.
    fn disclose(&self) -> Result<TapTree> {
        let disclose = Builder::new()
            .push_x_only_key(&self.hub_key())
            .push_opcode(OP_CHECKSIG);
        TapTree::new(vec![Leaf::new(
            "disclose",
            disclose.into_script(),
            Timelock::NONE,
        )])
    }
}

impl Front for Spec {
    fn core(&self) -> Core<'_> {
        self.view()
    }

    /// `request` (the holder's script-checked signatures on `b` and `E`;
    /// her claim's slot) and `respond` (the hub's on `b′`; its disclose
    /// slot), each slot at the statement's `SLOT_VOUT`.
    fn links(&self) -> Result<Vec<FrontLink>> {
        let ctx = self.view().ctx();
        let slot = |tree: TapTree| TxOut {
            value: SLOT,
            script_pubkey: tree.script_pubkey(),
        };
        let mut request = vec![slot(self.slot()?)];
        if let Some(value) = self.purse() {
            request.push(TxOut {
                value,
                script_pubkey: anchor_tree(&ctx, Role::User)?.script_pubkey(),
            });
        }
        Ok(vec![
            FrontLink {
                name: "request",
                poster: Role::User,
                leaf: link_leaf(&ctx, "request", true, |b| {
                    verify_drop(verify_drop(b, &self.b_key), &self.e_key)
                }),
                shape: wots_shape([&self.e_key, &self.b_key]),
                extra: request,
                terminal: "request_timeout",
                window: self.windows.w_h,
                pays: match self.terms.id >= RETURNING {
                    true => RETURNED,
                    false => Payout::User,
                },
            },
            FrontLink {
                name: "respond",
                poster: Role::Hub,
                leaf: link_leaf(&ctx, "respond", false, |b| verify_drop(b, &self.hub_b)),
                shape: wots_shape([&self.hub_b]),
                extra: vec![slot(self.disclose()?)],
                terminal: "respond_timeout",
                window: self.windows.w_x,
                pays: REDUCED,
            },
            FrontLink {
                name: "contest",
                poster: Role::User,
                leaf: link_leaf(&ctx, "contest", false, |b| b),
                shape: vec![],
                extra: vec![],
                terminal: "contest_timeout",
                window: self.windows.w_a,
                pays: Payout::User,
            },
        ])
    }

    fn pay(&self, which: Payout, available: Amount) -> Result<Vec<TxOut>> {
        match which {
            Payout::User => self.view().pay_alice(&self.b_key, available),
            Payout::Hub => Ok(self.view().pay_hub(available)),
            // Her purse paid already (`request`'s): of her reserve, not
            // of the hub's, which counts it among its floors.
            REDUCED => {
                let purse = self.purse().unwrap_or(Amount::ZERO);
                let terms = Terms {
                    reserve_alice: self.terms.reserve_alice - purse,
                    reserve_hub: self.terms.reserve_hub + purse,
                    ..self.terms
                };
                let core = Core {
                    terms: &terms,
                    ..self.view()
                };
                core.pay_reduced(&self.hub_b, available)
            }
            // Her claim stands, the hub silent: all her reserve, her purse
            // refunded (a reserve output of the holder's, as
            // `Payout::User`'s); the rest, the hub's reserve less what the
            // links took, her purse, floors and anchors, the hub's.
            RETURNED => {
                let terms = Terms {
                    reserve_hub: Amount::ZERO,
                    ..self.terms
                };
                let ctx = self.view().ctx();
                payout_less_signed(
                    &ctx,
                    &terms,
                    &self.b_key,
                    Role::User,
                    available,
                    Amount::ZERO,
                    Amount::ZERO,
                )
            }
            Payout::Other(other) => bail!("no payout {other}"),
        }
    }

    fn success(&self) -> Payout {
        REDUCED
    }

    /// A valid proof challenged pays as `success` does, not everything to
    /// the hub (Lichen's default): a holder's challenge may be her
    /// wallet's mistake (a proof it failed to check, a stale view of the
    /// chain), which shouldn't cost her her balance. Every contract open
    /// was signed so: another choice is another graph version.
    fn wrongly_challenged(&self) -> Payout {
        REDUCED
    }
}

/// A contract's graph: Licash's front ([`Spec`]), then BABE's tail.
pub struct HubProves {
    pub spec: Spec,
    graph: Graph,
}

impl HubProves {
    pub fn new(spec: Spec, tail: Tail) -> Result<HubProves> {
        ensure!(
            spec.b_key.params == WotsParams::for_bytes(4),
            "the key for b signs a 4-byte word"
        );
        ensure!(
            spec.hub_b.params == WotsParams::for_bytes(4),
            "the key for b′ signs a 4-byte word"
        );
        ensure!(
            spec.e_key.params == WotsParams::for_bytes(32),
            "the key for E signs 32 bytes"
        );
        let w = spec.windows;
        ensure!(
            w.k > POST_CSV && u32::from(w.w_h) > u32::from(w.k) + u32::from(POST_CSV),
            "publication must precede reclaim and the response deadline"
        );
        ensure!(
            w.w_x > POST_CSV,
            "her contest window must outlast a link's lock"
        );
        let graph = Graph::new(Box::new(spec.clone()), tail)?;
        Ok(HubProves { spec, graph })
    }
    pub fn core(&self) -> Core<'_> {
        self.spec.view()
    }
    pub fn value(&self) -> Amount {
        self.graph.value()
    }
    /// The kept instances' hashlocks, the holder's.
    pub fn hmsg(&self) -> &[Hash] {
        &self.graph.tail.hmsg
    }
    /// The contract output's tree: the parties' MuSig2 key, `default`, and
    /// `request`.
    pub fn tree(&self) -> Result<TapTree> {
        self.graph.tree()
    }
    /// `request`'s slot output's tree ([`SLOT`], at `SLOT_VOUT`).
    pub fn slot(&self) -> Result<TapTree> {
        self.spec.slot()
    }
    /// What `request` pays the holder at [`PURSE_VOUT`] for her forced
    /// close's fees, to her anchor's script ([`Spec::purse`]): none if it
    /// would be dust.
    pub fn purse(&self) -> Option<Amount> {
        self.spec.purse()
    }
    /// `respond`'s disclose slot output's tree ([`SLOT`], at `SLOT_VOUT`).
    pub fn disclose(&self) -> Result<TapTree> {
        self.spec.disclose()
    }
    /// The outputs paying `b` in bits and the reserves to the holder.
    pub fn pay_alice(&self, available: Amount) -> Result<Vec<TxOut>> {
        self.spec.pay(Payout::User, available)
    }
    /// The outputs paying `b′` in bits, each party its reserve.
    pub fn pay_reduced(&self, available: Amount) -> Result<Vec<TxOut>> {
        self.spec.pay(REDUCED, available)
    }
    /// The outputs paying `b` in bits and her reserve to the holder, the
    /// hub's reserve less what the links took back to the hub
    /// ([`RETURNING`]).
    pub fn pay_returned(&self, available: Amount) -> Result<Vec<TxOut>> {
        self.spec.pay(RETURNED, available)
    }

    /// Every transaction the parties pre-sign, the contract output at
    /// `funding` ([`Graph::presign`]).
    pub fn presign(&self, funding: OutPoint) -> Result<Vec<Presign>> {
        let set = self.graph.presign(funding)?;
        for name in ["request", "respond"] {
            let link = set
                .iter()
                .find(|p| p.name == name)
                .with_context(|| format!("no {name}"))?;
            ensure!(
                link.tx
                    .output
                    .get(SLOT_VOUT as usize)
                    .is_some_and(|o| o.value == SLOT),
                "{name}'s slot at the statement's vout"
            );
        }
        Ok(set)
    }

    /// Who posts link `name`.
    pub fn poster(name: &str) -> Role {
        match name {
            "request" | "contest" | "challenge_assert" => Role::User,
            _ => Role::Hub,
        }
    }
    /// Whether the hub keeps its signature on `name` from the holder.
    pub fn withheld(name: &str) -> bool {
        Graph::withheld(name)
    }
    /// `challenge_assert`'s sighash in `set`, which the hub's adaptor
    /// pre-signatures sign.
    pub fn challenge_sighash(set: &[Presign]) -> Result<Message> {
        Graph::link_sighash(set, "challenge_assert")
    }

    // ----- the links' witnesses, below both signatures -----

    /// `request`'s script-checked signatures on `E` and on `b`.
    pub fn request_wire(b: &WotsSig, e: &WotsSig) -> Vec<Vec<u8>> {
        e.consumption_order()
            .into_iter()
            .rev()
            .chain(b.consumption_order().into_iter().rev())
            .collect()
    }
    /// Read `request`'s arguments (consumption order, below both
    /// signatures): her signatures on `b` and `E`.
    pub fn read_request(args: &[Vec<u8>]) -> Result<(WotsSig, WotsSig)> {
        let (bp, ep) = (WotsParams::for_bytes(4), WotsParams::for_bytes(32));
        let (nb, ne) = (
            2 * bp.total_digits() as usize,
            2 * ep.total_digits() as usize,
        );
        ensure!(
            args.len() == nb + ne,
            "a request of {} arguments",
            args.len()
        );
        let b = script_signature(bp, &args[..nb])?;
        let e = script_signature(ep, &args[nb..])?;
        Ok((b, e))
    }
    /// A signature on `b` or `b′` as the payout's leaves take it (bottom
    /// first: each digit's hash, then the digit).
    pub fn b_wire(b: &WotsSig) -> Vec<Vec<u8>> {
        b.consumption_order().into_iter().rev().collect()
    }
    /// `respond`'s: the hub's script-checked signature on `b′`.
    pub fn respond_wire(b: &WotsSig) -> Vec<Vec<u8>> {
        Self::b_wire(b)
    }
    /// Read `respond`'s arguments (consumption order, below both
    /// signatures): the hub's signature on `b′`.
    pub fn read_respond(args: &[Vec<u8>]) -> Result<WotsSig> {
        let params = WotsParams::for_bytes(4);
        let n = 2 * params.total_digits() as usize;
        ensure!(args.len() == n, "a respond of {} arguments", args.len());
        script_signature(params, args)
    }
    /// `assert`'s: π1's digits, Lamport-signed, then π2 and π3.
    pub fn assert_wire(preimages: &[Preimage], pi2: &[u8], pi3: &[u8]) -> Vec<Vec<u8>> {
        Graph::assert_wire(preimages, pi2, pi3)
    }
    /// `challenge_assert`'s: the reveal.
    pub fn challenge_wire(args: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        Graph::challenge_wire(args)
    }
    /// `wrongly_challenged`'s: `msg`.
    pub fn wrongly_wire(msg: &[u8; 32]) -> Vec<Vec<u8>> {
        Graph::wrongly_wire(msg)
    }

    // ----- the links as the chain shows them -----

    /// `request`'s script-checked `b` and `E`, `b` the word she signed:
    /// what the payout pays her is that word ([`requested`] reads what
    /// it counts).
    pub fn requested_word(request: &Transaction) -> Result<(u32, [u8; 32])> {
        let (b, e) = Self::read_request(&link_args(request))?;
        let b = u32::from_be_bytes(
            b.message()
                .try_into()
                .map_err(|_| anyhow::anyhow!("b's signature signs 4 bytes"))?,
        );
        let e = e
            .message()
            .try_into()
            .map_err(|_| anyhow::anyhow!("E's signature signs 32 bytes"))?;
        Ok((b, e))
    }
    /// `respond`'s script-checked `b′`, the word the hub signed, and its
    /// signature on it as the payout's leaves take it ([`responded`] reads
    /// what the word counts).
    pub fn responded_word(respond: &Transaction) -> Result<(u32, Vec<Vec<u8>>)> {
        let sig = Self::read_respond(&link_args(respond))?;
        let b = u32::from_be_bytes(
            sig.message()
                .try_into()
                .map_err(|_| anyhow::anyhow!("b′'s signature signs 4 bytes"))?,
        );
        Ok((b, Self::b_wire(&sig)))
    }
    /// `assert`'s π2 and π3 as it shows them: the two arguments its leaf
    /// drops unchecked, which whoever relays or mines it may replace
    /// without changing its id.
    pub fn asserted_pair(assert: &Transaction) -> Result<(Vec<u8>, Vec<u8>)> {
        let args = link_args(assert);
        let (_, pi2, pi3) = Graph::read_assert(&args).context("assert's arguments")?;
        Ok((pi2.to_vec(), pi3.to_vec()))
    }
    /// `assert` with π2 and π3 `pi2` and `pi3`, all else (π1's digits, its
    /// signatures) as it is: the same transaction by its id.
    pub fn with_pair(assert: &Transaction, pi2: &[u8], pi3: &[u8]) -> Result<Transaction> {
        Self::asserted_pair(assert)?;
        // The deepest of its stack: π3, then π2 (`assert_wire`).
        let mut items = assert.input[0].witness.to_vec();
        items[0] = pi3.to_vec();
        items[1] = pi2.to_vec();
        let mut tx = assert.clone();
        tx.input[0].witness = lichen_btc::bitcoin::Witness::from_slice(&items);
        ensure!(
            Self::asserted_pair(&tx)? == (pi2.to_vec(), pi3.to_vec()),
            "π2 and π3 not where assert's leaf takes them"
        );
        Ok(tx)
    }
    /// What `assert` put on chain.
    pub fn assertion(&self, assert: &Transaction) -> Result<Assertion> {
        let args = link_args(assert);
        let (signed, pi2, pi3) = Graph::read_assert(&args).context("assert's arguments")?;
        let preimages: Vec<Preimage> = signed
            .iter()
            .map(|a| a[..].try_into().context("a preimage's length"))
            .collect::<Result<_>>()?;
        let lamport = &self.graph.tail.lamport;
        let digits: Vec<u8> = preimages
            .iter()
            .enumerate()
            .map(|(d, p)| lamport.read(d, p).context("a preimage of no digit"))
            .collect::<Result<_>>()?;
        let bits: Vec<bool> = digits
            .iter()
            .flat_map(|v| [v & 1 == 1, v & 2 == 2])
            .collect();
        Ok(Assertion {
            proof: lichen_babe::statement::proof_from_chain(&bits, pi2, pi3),
            digits,
            bits,
            preimages,
        })
    }
    /// Her publication of the claim `posted`: the spend of `request`'s
    /// slot (`slot`, paying `out`) by its `publish` leaf, one nulldata
    /// output carrying it, signed `ALL|ANYONECANPAY` with her claim key
    /// (its outputs committed) so that a fee input can be added.
    pub fn publication(
        &self,
        key: &Keypair,
        slot: OutPoint,
        out: &TxOut,
        posted: &[u8],
    ) -> Result<Transaction> {
        let script =
            licash_statement::claim_script(posted).context("the claim is too large to publish")?;
        nulldata_spend(&self.slot()?, "publish", key, slot, out, script)
    }
    /// The hub's disclosure of `bytes` (what its proof cites): the spend
    /// of `respond`'s disclose slot (`slot`, paying `out`), one nulldata
    /// output carrying them, signed `ALL|ANYONECANPAY` with its payment
    /// key so that a fee input can be added.
    pub fn disclosure(
        &self,
        key: &Keypair,
        slot: OutPoint,
        out: &TxOut,
        bytes: &[u8],
    ) -> Result<Transaction> {
        let script = licash_statement::claim_script(bytes)
            .context("the disclosure is too large to publish")?;
        nulldata_spend(&self.disclose()?, "disclose", key, slot, out, script)
    }
}

/// A slot's spend by its leaf `name`, one nulldata output carrying
/// `script`, signed `ALL|ANYONECANPAY` (a fee input can be added).
fn nulldata_spend(
    tree: &TapTree,
    name: &str,
    key: &Keypair,
    slot: OutPoint,
    out: &TxOut,
    script: Vec<u8>,
) -> Result<Transaction> {
    let leaf = tree.leaf(name)?;
    let carrier = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    };
    let mut tx = build_spend(slot, &leaf.timelock, vec![carrier]);
    let sig = sign_tapscript_acp(key, &tx, 0, out, &leaf.script)?;
    tx.input[0].witness = tapscript_witness(&[sig], &leaf.script, &tree.control_block(name)?);
    Ok(tx)
}

/// What `assert` put on chain: π1's digits (read under the hub's Lamport
/// key), their preimages, and the proof, if its points are points.
pub struct Assertion {
    pub digits: Vec<u8>,
    pub bits: Vec<bool>,
    pub preimages: Vec<Preimage>,
    pub proof: Option<Proof<Bn254>>,
}

impl Assertion {
    /// `challenge_assert`'s witness: each digit's preimage and the hub's
    /// pre-signature on it completed by its `revealed` secret (hers,
    /// `lichen_babe::opening::Garbler::reveal`).
    pub fn challenge_wire(
        &self,
        presigs: &[[AdaptorSig; VALUES]],
        revealed: &[Secret],
    ) -> Vec<Vec<u8>> {
        HubProves::challenge_wire(reveal_args(
            &self.preimages,
            &complete(presigs, &self.digits, revealed),
        ))
    }
}

/// A one-time signature from a link's arguments (consumption order: each
/// digit, then its hash), each digit read as the verifying script reads it
/// (`licash_statement::script_digit`): Bitcoin accepts a 15 written as 16,
/// so the hub and holder must read it as the statement does.
fn script_signature(params: WotsParams, args: &[Vec<u8>]) -> Result<WotsSig> {
    let items = args
        .iter()
        .enumerate()
        .map(|(k, item)| match k % 2 {
            0 => script_digit(item)
                .map(|d| vec![d])
                .context("a digit the script refuses"),
            _ => Ok(item.clone()),
        })
        .collect::<Result<Vec<_>>>()?;
    WotsSig::from_consumption_order(params, &items)
}
#[cfg(test)]
mod tests {
    use super::*;

    /// The words both parties sign (Lichen's `Terms::word`, which builds
    /// the payout) are read by the statement as what they sign, and any
    /// word as Lichen counts it: the payout and the statement agree.
    #[test]
    fn the_statement_counts_a_word_as_the_payout_does() {
        for bits in 1..=8u32 {
            for low_bits in [0, 1, 3].into_iter().filter(|l| *l < bits) {
                for rest in std::iter::once(0).chain((1u32 << low_bits)..(1 << bits)) {
                    let terms = Terms {
                        id: 1,
                        unit: Amount::from_sat(1),
                        bits,
                        low_bits,
                        deposit: 0,
                        t_close: 0,
                        reserve_alice: Amount::ZERO,
                        reserve_hub: Amount::ZERO,
                        rest,
                    };
                    let payout = licash_statement::Payout { bits, rest };
                    for amount in 0..=terms.v_max_units() as u32 {
                        assert_eq!(payout.amount(word(&terms, amount).unwrap()), amount);
                    }
                    assert!(word(&terms, terms.v_max_units() as u32 + 1).is_err());
                    for w in 0..(4u32 << bits) {
                        assert_eq!(
                            u64::from(payout.amount(w)),
                            terms.amount(w),
                            "{terms:?}: {w}"
                        );
                    }
                }
            }
        }
        // the extremes of the word
        let payout = licash_statement::Payout {
            bits: 31,
            rest: (1 << 31) - 1,
        };
        assert_eq!(payout.amount(u32::MAX), u32::MAX - 1);
        assert_eq!(
            licash_statement::Payout { bits: 32, rest: 0 }.amount(u32::MAX),
            u32::MAX
        );
    }
    use crate::keys::{HolderKeys, HubKeys};

    /// F's output stands before the instances are in: neither the hub's
    /// prover keys nor the hashlocks change it.
    #[test]
    fn the_contract_output_is_of_base_and_her_one_time_keys_only() {
        let base = crate::opening::testing::base(&[3; 32]);
        let holder = HolderKeys::derive(&[1; 32], &[3; 32]).public();
        let hub = HubKeys::from_secret(&[2; 32]).public();
        let other = HubKeys::from_secret(&[9; 32]).public();
        let out = |hub: &HubPub, hmsg| {
            contract_output(&build(&base, &holder, hub, hmsg).unwrap()).unwrap()
        };
        let draft = out(&hub, draft_hmsg(2));
        assert_eq!(draft, out(&other, vec![[7; 32], [8; 32]]));
        assert_eq!(draft.value.to_sat(), base.parts().graph_value().unwrap());
        let mut theirs = holder.clone();
        theirs.b_key = HolderKeys::derive(&[1; 32], &[4; 32]).public().b_key;
        assert_ne!(
            draft,
            contract_output(&build(&base, &theirs, &hub, draft_hmsg(2)).unwrap()).unwrap()
        );
    }

    /// A valid proof challenged pays as `success` does (Lichen's default
    /// would pay the hub everything): the graph every open contract
    /// signed. Only the hub's reserve is less, by what `challenge_assert`
    /// took (its floor and anchor).
    #[test]
    fn wrongly_challenged_pays_as_success() {
        let base = crate::opening::testing::base(&[3; 32]);
        let holder = HolderKeys::derive(&[1; 32], &[3; 32]).public();
        let hub = HubKeys::from_secret(&[2; 32]).public();
        let set = build(&base, &holder, &hub, draft_hmsg(2))
            .unwrap()
            .presign(OutPoint::null())
            .unwrap();
        let named = |name: &str| set.iter().find(|p| p.name == name).unwrap();
        let success = named("success");
        for k in 0..2 {
            let w = named(&format!("wrongly_challenged_{k}"));
            let (wo, so) = (&w.tx.output, &success.tx.output);
            let scripts = |o: &[TxOut]| {
                o.iter()
                    .map(|o| o.script_pubkey.clone())
                    .collect::<Vec<_>>()
            };
            assert_eq!(scripts(wo), scripts(so));
            // her bits and reserve, and the rest, as success; the hub's
            // reserve less what the challenge took
            let differ: Vec<usize> = (0..so.len())
                .filter(|i| wo[*i].value != so[*i].value)
                .collect();
            assert_eq!(differ, [so.len() - 2]);
            let i = differ[0];
            assert_eq!(
                so[i].value - wo[i].value,
                success.prevout.value - w.prevout.value
            );
        }
    }
}
