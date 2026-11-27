//! Pure transaction builders and readers for both sides of a hub-proves
//! dispute. Chain observation, durable intent, fee selection and broadcast
//! remain the driver's responsibility.
use anyhow::{ensure, Context, Result};
use ark_bn254::Bn254;
use ark_groth16::Proof;
use licash_statement::Carrier;
use lichen_babe::{
    gadget,
    opening::{self, Garbler},
    reveal,
    setup::{Instance, Secret, DIGITS},
    vsss::{deal, Dealing},
};
use lichen_btc::{
    bitcoin::{
        absolute::LockTime, key::Keypair, Amount, Block, FeeRate, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid,
    },
    sighash::{sign_tapscript, sign_tapscript_acp},
    taptree::{Leaf, TapTree},
    tx::{build_spend, build_tx, Timelock},
    witness::tapscript_witness,
};
use lichen_contract::payout::Word;
use lichen_contract::{anchor_tree_for, Owned, Presign, Role};
use lichen_wots::WotsPublic;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::collections::HashMap;

use crate::{
    graph::{self, link_args, Assertion, HubProves},
    keys::{HolderKeys, HubKeys},
    opening::{HubOpening, Opening},
};

/// The digits of π1 of `proof` the hub's assertion signs with its
/// one-time Lamport key: two proofs of the same digits sign the same.
pub fn asserted_digits(proof: &Proof<Bn254>) -> Vec<u8> {
    lichen_babe::setup::digits(&gadget::input(&proof.a))
}

pub fn presign<'a>(set: &'a [Presign], name: &str) -> Result<&'a Presign> {
    set.iter()
        .find(|p| p.name == name)
        .with_context(|| format!("no {name} transaction"))
}
fn check_link(set: &[Presign], name: &str, tx: &Transaction) -> Result<()> {
    let p = presign(set, name)?;
    ensure!(
        !tx.input.is_empty() && tx.compute_txid() == p.tx.compute_txid(),
        "not this contract's {name}"
    );
    Ok(())
}
fn finish(
    set: &[Presign],
    hub: &HashMap<String, Vec<u8>>,
    holder: &HashMap<String, Vec<u8>>,
    name: &str,
    wire: Vec<Vec<u8>>,
) -> Result<Transaction> {
    Ok(presign(set, name)?.finish(
        wire,
        hub.get(name).context("missing hub signature")?,
        holder.get(name).context("missing holder signature")?,
    ))
}
fn carrier_outputs(
    mut tx: Transaction,
    key: &Keypair,
    tree: &TapTree,
    leaf_name: &str,
    prevout: &TxOut,
    outputs: Vec<TxOut>,
) -> Result<Transaction> {
    if outputs.is_empty() {
        return Ok(tx);
    }
    tx.output.extend(outputs);
    let leaf = tree.leaf(leaf_name)?;
    let signature = sign_tapscript_acp(key, &tx, 0, prevout, &leaf.script)?;
    tx.input[0].witness =
        tapscript_witness(&[signature], &leaf.script, &tree.control_block(leaf_name)?);
    Ok(tx)
}
impl Opening {
    pub fn finish(&self, name: &str, wire: Vec<Vec<u8>>) -> Result<Transaction> {
        finish(&self.set, &self.offer.sigs, &self.consent.sigs, name, wire)
    }
    /// Whether she can force it closed: refused unless the hub's
    /// signature kept signs `request` as this build of the graph makes it,
    /// as of a contract opened under an older one (say, before `request`
    /// paid her purse), whose request would never be valid.
    pub fn forcible(&self) -> Result<()> {
        let signed = self
            .offer
            .sigs
            .get("request")
            .context("missing hub signature")?;
        presign(&self.set, "request")?
            .verify_input(&self.babe.core().pubs[1].payment, 0, signed)
            .map_err(|_| {
                anyhow::anyhow!(
                    "opened under an older protocol: no forced close, close it with the hub"
                )
            })
    }
    /// Her request of `b`, her claim's digest `e`, if she can force it
    /// closed ([`Opening::forcible`]).
    pub fn request(&self, keys: &HolderKeys, b: u32, e: &[u8; 32]) -> Result<Transaction> {
        ensure!(keys.public() == self.holder, "another holder's keys");
        ensure!(
            b <= self.base.parts().cap,
            "claim exceeds contract capacity"
        );
        self.forcible()?;
        let word = graph::word(&self.babe.spec.terms, b)?;
        self.finish(
            "request",
            HubProves::request_wire(
                &keys.b.sign(&word.to_u32().to_be_bytes())?,
                &keys.e.sign(e)?,
            ),
        )
    }
    /// Publish the claim with optional fee coins and change outputs, all
    /// fixed before its claim-key signature is made. Fee inputs may follow.
    pub fn publication(
        &self,
        keys: &HolderKeys,
        bytes: &[u8],
        outputs: Vec<TxOut>,
    ) -> Result<Transaction> {
        ensure!(
            keys.claim_key().serialize() == self.base.parts().claim_key,
            "another claim key"
        );
        ensure!(
            bytes.len() <= self.base.parts().limits.max_publication_bytes as usize,
            "publication exceeds limit"
        );
        let request = presign(&self.set, "request")?;
        let slot = OutPoint {
            txid: request.tx.compute_txid(),
            vout: licash_statement::SLOT_VOUT,
        };
        let prevout = &request.tx.output[slot.vout as usize];
        if self.carrier() == Carrier::Leaf {
            // No signature yet, the claim's not in it: its commitment's
            // input follows, and the slot is signed over every input
            // ([`Self::sign_publication`]), never so that one may change.
            return unsigned_spend(&self.babe.slot()?, "publish", slot, outputs);
        }
        let tx = self.babe.publication(&keys.claim, slot, prevout, bytes)?;
        carrier_outputs(
            tx,
            &keys.claim,
            &self.babe.slot()?,
            "publish",
            prevout,
            outputs,
        )
    }
    /// Where the contract's links carry their bytes ([`licash_hp::carrier`]).
    pub fn carrier(&self) -> Carrier {
        licash_hp::carrier(&self.base)
    }
    /// Under a leaf carrier, her commitment to the filing `bytes` before
    /// she publishes it: the spend of `r`'s purse ([`graph::PURSE_VOUT`])
    /// paying [`COMMITTED`] the coin that carries them ([`envelope_tree`]),
    /// the dust limit, and [`COMMITTED`] + 1 the rest less `fee`, to her
    /// fee script, signed. Her publication spends both: the one reveals
    /// the bytes, the other pays its fee as her purse did.
    pub fn commitment(
        &self,
        keys: &HolderKeys,
        r: &Transaction,
        bytes: &[u8],
        fee: Amount,
    ) -> Result<Transaction> {
        let key = &keys.party.payment;
        let purse = r
            .output
            .get(graph::PURSE_VOUT as usize)
            .context("no purse to commit from")?;
        ensure!(
            purse.script_pubkey == fee_script(key)?,
            "request purse is not hers"
        );
        let dust = Amount::from_sat(330);
        let rest = purse
            .value
            .checked_sub(dust + fee)
            .filter(|rest| *rest >= dust)
            .context("her purse pays no commitment")?;
        let spent = OutPoint {
            txid: r.compute_txid(),
            vout: graph::PURSE_VOUT,
        };
        let mut tx = build_tx(
            &[(spent, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![
                TxOut {
                    value: dust,
                    script_pubkey: envelope_tree(key, bytes)?.script_pubkey(),
                },
                TxOut {
                    value: rest,
                    script_pubkey: fee_script(key)?,
                },
            ],
            LockTime::ZERO,
        );
        sign_fee_input(key, &mut tx, 0, std::slice::from_ref(purse))?;
        Ok(tx)
    }
    /// Sign `tx`, a [`Opening::publication`] with every input it spends
    /// (`prevouts`, in order) and its outputs final, over all of them: no
    /// one else can add an input to it, as one could to its
    /// `ALL|ANYONECANPAY` carrier, and so pin it with a conflict of a
    /// larger fee at a lower rate until its window passes. Its fee inputs
    /// are signed after, and may not change.
    /// Under a leaf carrier, the inputs spending her commitment's coin
    /// carrying `bytes` (the filing) are signed too, by its envelope.
    pub fn sign_publication(
        &self,
        keys: &HolderKeys,
        tx: &mut Transaction,
        prevouts: &[TxOut],
        bytes: &[u8],
    ) -> Result<()> {
        ensure!(
            keys.claim_key().serialize() == self.base.parts().claim_key,
            "another claim key"
        );
        ensure!(
            tx.input.len() == prevouts.len(),
            "a publication's inputs and their coins differ"
        );
        let tree = self.babe.slot()?;
        let leaf = tree.leaf("publish")?;
        let sig = sign_tapscript(&keys.claim, tx, 0, prevouts, &leaf.script)?;
        tx.input[0].witness = tapscript_witness(
            &[sig.as_ref().to_vec()],
            &leaf.script,
            &tree.control_block("publish")?,
        );
        if self.carrier() == Carrier::Leaf {
            let envelope = envelope_tree(&keys.party.payment, bytes)?;
            let spk = envelope.script_pubkey();
            let carrying: Vec<usize> = (1..tx.input.len())
                .filter(|i| prevouts[*i].script_pubkey == spk)
                .collect();
            ensure!(
                carrying.len() == 1,
                "a publication spends no commitment to her claim"
            );
            for i in carrying {
                sign_leaf_input(&keys.party.payment, tx, i, prevouts, &envelope, ENVELOPE)?;
            }
        }
        Ok(())
    }
    /// Her contest of the hub's response: the link that makes it prove
    /// what it says she is owed. It carries nothing of hers but the
    /// signatures made when the contract opened; its fee is its child's.
    pub fn contest(&self, keys: &HolderKeys) -> Result<Transaction> {
        ensure!(keys.public() == self.holder, "another holder's keys");
        self.finish("contest", vec![])
    }
    pub fn assertion(&self, tx: &Transaction) -> Result<Assertion> {
        check_link(&self.set, "assert", tx)?;
        self.babe.assertion(tx)
    }
    /// Whether `assert`'s proof as the chain shows it verifies: none, in a
    /// graph whose `assert` carries π1 alone.
    pub fn verify_assertion(&self, tx: &Transaction) -> Result<bool> {
        let a = self.assertion(tx)?;
        Ok(a.proof.as_ref().is_some_and(|p| self.verifies(p)))
    }
    /// Whether `assert`'s proof verifies, its π1 the chain's and π2 and π3
    /// `pair` (96 bytes), as the hub hands them over.
    pub fn verify_assertion_with(&self, tx: &Transaction, pair: &[u8]) -> Result<bool> {
        let a = self.assertion(tx)?;
        Ok(a.proof_with(pair).is_some_and(|p| self.verifies(&p)))
    }
    fn verifies(&self, proof: &Proof<Bn254>) -> bool {
        graph::kind(&self.base, self.mock).verify(&graph::journal(&self.base), proof)
    }
    pub fn challenge(&self, keys: &HolderKeys, asserted: &Transaction) -> Result<Transaction> {
        ensure!(keys.public() == self.holder, "another holder's keys");
        let a = self.assertion(asserted)?;
        let secrets = self.revealed(keys, &a.digits)?;
        self.finish(
            "challenge_assert",
            a.challenge_wire(&self.offer.presigs, &secrets),
        )
    }
    /// The secrets of π1's `digits`, as her challenge reveals them: of the
    /// dealing bound to the contract's journal (`Garbler`) or, for a
    /// contract opened before Lichen bound it, of the one from her
    /// garbler seed alone; whichever the hub's pre-signatures on
    /// `challenge_assert` are adapted to.
    fn revealed(&self, keys: &HolderKeys, digits: &[u8]) -> Result<Vec<Secret>> {
        let r = &self.base.parts().recipe;
        let (n, m) = (r.instances as u32, r.kept as u32);
        let garbler = Garbler::new(
            &keys.garbler,
            n,
            m,
            &graph::kind(&self.base, self.mock),
            &graph::journal(&self.base),
        );
        let sighash = HubProves::challenge_sighash(&self.set)?;
        let adapted = |d: &Dealing| {
            reveal::check_presigs(
                &self.hub.adaptor,
                &sighash,
                &reveal::points(d),
                &self.offer.presigs,
            )
        };
        if adapted(garbler.dealing()) {
            return Ok(garbler.reveal(digits));
        }
        let (dealer, dealing) = deal(
            DIGITS,
            (n - m) as usize,
            &mut ChaCha20Rng::from_seed(keys.garbler.derive_bytes("dealing")),
        );
        ensure!(
            adapted(&dealing),
            "the hub's pre-signatures are adapted to neither of her dealings"
        );
        Ok(digits
            .iter()
            .enumerate()
            .map(|(j, v)| dealer.reveal(j, *v))
            .collect())
    }
}
impl HubOpening {
    pub fn finish(&self, name: &str, wire: Vec<Vec<u8>>) -> Result<Transaction> {
        finish(&self.set, &self.sigs, &self.consent.sigs, name, wire)
    }
    /// The contract's end with no exit: after the close, the default pays
    /// her reserve to her payout script and the rest to the hub's. It pays
    /// no fee: the hub adds a fee coin ([`add_fee`]).
    pub fn default_close(&self) -> Result<Transaction> {
        self.finish("default", vec![])
    }
    /// `request`'s `b`, as the payout counts it, and `E`.
    pub fn requested_b(&self, request: &Transaction) -> Result<(u32, [u8; 32])> {
        check_link(&self.set, "request", request)?;
        graph::requested(&self.base, request)
    }
    pub fn respond(&self, keys: &HubKeys, b_prime: u32) -> Result<Transaction> {
        ensure!(keys.public() == self.hub, "another hub's keys");
        ensure!(
            b_prime <= self.base.parts().cap,
            "response exceeds capacity"
        );
        let word = graph::word(&self.babe.spec.terms, b_prime)?;
        self.finish(
            "respond",
            HubProves::respond_wire(&keys.b.sign(&word.to_u32().to_be_bytes())?),
        )
    }
    pub fn disclosure(
        &self,
        keys: &HubKeys,
        bytes: &[u8],
        outputs: Vec<TxOut>,
    ) -> Result<Transaction> {
        ensure!(keys.public() == self.hub, "another hub's keys");
        let respond = presign(&self.set, "respond")?;
        let slot = OutPoint {
            txid: respond.tx.compute_txid(),
            vout: licash_statement::SLOT_VOUT,
        };
        let prevout = &respond.tx.output[slot.vout as usize];
        if licash_hp::carrier(&self.base) == Carrier::Leaf {
            // Its fee coin, which carries the bytes ([`envelope_tree`]),
            // follows; its slot signed over both ([`Self::seal`]). One
            // output, none of value: the coin is all fee.
            let mut sink = vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
            }];
            sink.extend(outputs);
            return unsigned_spend(&self.babe.disclose()?, "disclose", slot, sink);
        }
        let tx = self
            .babe
            .disclosure(&keys.party.payment, slot, prevout, bytes)?;
        carrier_outputs(
            tx,
            &keys.party.payment,
            &self.babe.disclose()?,
            "disclose",
            prevout,
            outputs,
        )
    }
    pub fn assert(&self, keys: &HubKeys, proof: &Proof<Bn254>) -> Result<Transaction> {
        ensure!(keys.public() == self.hub, "another hub's keys");
        let digits = asserted_digits(proof);
        self.finish(
            "assert",
            self.babe.assert_wire(&keys.lamport.sign(&digits), proof),
        )
    }
    /// Answer with a committed kept instance. Its index in `kept` selects
    /// the graph's wrongly_challenged leaf, not the instance's number.
    ///
    /// On `own`, the proof the hub made and asserted, when it is of the π1
    /// in the block (`asserted`): where `assert` carries π2 and π3, they sit
    /// in its witness unsigned and unchecked by its leaf, so whoever relays
    /// or mines it can replace them, and where it doesn't, the block has
    /// none. Else on the proof read from the block, if any.
    pub fn answer(
        &self,
        asserted: &Transaction,
        own: Option<Proof<Bn254>>,
        challenge: &Transaction,
        i: u32,
        bytes: &[u8],
    ) -> Result<Option<Transaction>> {
        let k = self
            .kept
            .iter()
            .position(|n| *n == i)
            .context("instance not kept")?;
        let Some(inst) = Instance::from_bytes(bytes) else {
            return Ok(None);
        };
        if inst.hmsg != self.babe.hmsg()[k] {
            return Ok(None);
        }
        check_link(&self.set, "assert", asserted)?;
        check_link(&self.set, "challenge_assert", challenge)?;
        let a = self.babe.assertion(asserted)?;
        ensure!(!challenge.input.is_empty(), "challenge has no input");
        let args = link_args(challenge);
        let (digits, secrets) = reveal::extract(&self.hub.lamport, &self.offer.presigs, &args)
            .context("challenge does not reveal secrets")?;
        ensure!(digits == a.digits, "challenge of another assertion");
        let Some(proof) = a.answered_on(own) else {
            return Ok(None);
        };
        // a malformed instance, or one whose evaluation panics, answers
        // nothing: the caller tries the next
        let mut failed = None;
        let answered = opening::answer(
            [(i, Ok(bytes.to_vec()))],
            &self.opened.opened,
            &a.bits,
            &secrets,
            &proof,
            |_, e| failed = Some(format!("{e:#}")),
        );
        match (answered, failed) {
            (Some((_, m)), _) => self
                .finish(
                    &format!("wrongly_challenged_{k}"),
                    HubProves::wrongly_wire(&m),
                )
                .map(Some),
            (None, Some(why)) => anyhow::bail!("kept instance {i} doesn't answer: {why}"),
            (None, None) => Ok(None),
        }
    }
    /// The hub's disclosure or reclaim, its inputs final (`prevouts`, in
    /// order, its fee coin's too): its slot's input signed again over
    /// every input and output (SIGHASH_DEFAULT), so that none can be added
    /// to hold it out of blocks at a lower rate.
    pub fn seal(&self, keys: &HubKeys, tx: &mut Transaction, prevouts: &[TxOut]) -> Result<()> {
        ensure!(keys.public() == self.hub, "another hub's keys");
        ensure!(
            !tx.input.is_empty() && tx.input.len() == prevouts.len(),
            "a spend's inputs and their coins differ"
        );
        let slot_of = |name| -> Result<OutPoint> {
            Ok(OutPoint {
                txid: presign(&self.set, name)?.tx.compute_txid(),
                vout: licash_statement::SLOT_VOUT,
            })
        };
        let spent = tx.input[0].previous_output;
        let (tree, name) = if spent == slot_of("respond")? {
            (self.babe.disclose()?, "disclose")
        } else if spent == slot_of("request")? {
            (self.babe.slot()?, "reclaim")
        } else {
            anyhow::bail!("not a spend of a slot of the hub's");
        };
        let leaf = tree.leaf(name)?;
        let sig = sign_tapscript(&keys.party.payment, tx, 0, prevouts, &leaf.script)?;
        tx.input[0].witness = tapscript_witness(
            &[sig.as_ref().to_vec()],
            &leaf.script,
            &tree.control_block(name)?,
        );
        Ok(())
    }
    pub fn reclaim(&self, keys: &HubKeys) -> Result<Transaction> {
        ensure!(keys.public() == self.hub, "another hub's keys");
        let r = presign(&self.set, "request")?;
        let slot = self.babe.slot()?;
        let prevout = &r.tx.output[licash_statement::SLOT_VOUT as usize];
        let op = OutPoint {
            txid: r.tx.compute_txid(),
            vout: licash_statement::SLOT_VOUT,
        };
        let mut tx = build_spend(
            op,
            &Timelock::csv(self.babe.spec.windows.k),
            vec![TxOut {
                value: prevout.value,
                script_pubkey: self.keys_payout()?,
            }],
        );
        let leaf = slot.leaf("reclaim")?;
        let sig = sign_tapscript_acp(&keys.party.payment, &tx, 0, prevout, &leaf.script)?;
        tx.input[0].witness =
            tapscript_witness(&[sig], &leaf.script, &slot.control_block("reclaim")?);
        Ok(tx)
    }
    fn keys_payout(&self) -> Result<ScriptBuf> {
        Ok(graph::party_pub(&self.base.parts().parties[1])?.payout_spk)
    }
}

/// An exact fee coin is appended to a terminal (ALL|ANYONECANPAY).
pub fn add_fee(
    tx: Transaction,
    prevout: TxOut,
    fee: (OutPoint, TxOut),
    key: &Keypair,
) -> Result<Transaction> {
    add_fee_of(tx, prevout, fee, key, &CoinTree::Fee)
}

/// What a fee coin of a key is: of its fee script ([`fee_script`]), or of
/// an envelope carrying bytes ([`envelope_tree`]), as the hub's disclosure
/// under a leaf carrier pays with. Lent, never kept in bulk: its size is
/// no cost.
#[allow(clippy::large_enum_variant)]
pub enum CoinTree {
    Fee,
    Envelope(TapTree),
}

impl CoinTree {
    /// The coin's script, of `key`.
    pub fn script(&self, key: &Keypair) -> Result<ScriptBuf> {
        match self {
            CoinTree::Fee => fee_script(key),
            CoinTree::Envelope(tree) => Ok(tree.script_pubkey()),
        }
    }
}

/// [`add_fee`] of a coin of `tree`, spent by its leaf: its envelope's, for
/// one carrying bytes.
pub fn add_fee_of(
    mut tx: Transaction,
    prevout: TxOut,
    fee: (OutPoint, TxOut),
    key: &Keypair,
    tree: &CoinTree,
) -> Result<Transaction> {
    ensure!(
        tx.input.len() == 1,
        "fee coin only for a one-input terminal"
    );
    tx.input.push(TxIn {
        previous_output: fee.0,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    });
    match tree {
        CoinTree::Fee => sign_fee_input(key, &mut tx, 1, &[prevout, fee.1])?,
        CoinTree::Envelope(t) => sign_leaf_input(key, &mut tx, 1, &[prevout, fee.1], t, ENVELOPE)?,
    }
    Ok(tx)
}

/// The leaf of an [`envelope_tree`].
pub const ENVELOPE: &str = "envelope";

/// The vout of [`Opening::commitment`]'s coin carrying her filing; its
/// change to her fee script follows.
pub const COMMITTED: u32 = 0;

/// The tree of a coin that carries `bytes` in the witness of its spend:
/// one leaf ([`ENVELOPE`], [`licash_statement::envelope_script`]) that
/// `key` alone signs. The output commits to the leaf, so a spend by it
/// reveals those bytes, and no other, whoever relays it. Its key path is
/// `key`'s too ([`sign_key_input`]), so that a coin not spent to carry
/// them (the hub's fee coin a larger one replaced) is swept for a
/// signature's weight, not theirs.
pub fn envelope_tree(key: &Keypair, bytes: &[u8]) -> Result<TapTree> {
    let x = key.x_only_public_key().0;
    let script =
        licash_statement::envelope_script(&x.serialize(), bytes).context("too large to carry")?;
    TapTree::with_internal_key(
        x,
        vec![Leaf::new(
            ENVELOPE,
            ScriptBuf::from_bytes(script),
            Timelock::NONE,
        )],
    )
}

/// Sign input `i` of `tx`, spending a coin of `tree` by its key path, whose
/// internal key is `key`'s ([`envelope_tree`]), over every input and
/// output (SIGHASH_DEFAULT): `prevouts` in order.
pub fn sign_key_input(
    key: &Keypair,
    tx: &mut Transaction,
    i: usize,
    prevouts: &[TxOut],
    tree: &TapTree,
) -> Result<()> {
    use lichen_btc::bitcoin::{
        hashes::Hash as _,
        key::TapTweak as _,
        secp256k1::{Message, SECP256K1},
        sighash::{Prevouts, SighashCache, TapSighashType},
        Witness,
    };
    ensure!(
        prevouts.len() == tx.input.len() && i < prevouts.len(),
        "fee prevout count"
    );
    ensure!(
        prevouts[i].script_pubkey == tree.script_pubkey()
            && tree.internal_key() == key.x_only_public_key().0,
        "another key's coin"
    );
    let hash = SighashCache::new(&*tx).taproot_key_spend_signature_hash(
        i,
        &Prevouts::All(prevouts),
        TapSighashType::Default,
    )?;
    let tweaked = key.tap_tweak(SECP256K1, tree.merkle_root());
    let sig = SECP256K1.sign_schnorr_no_aux_rand(
        &Message::from_digest(hash.to_byte_array()),
        tweaked.as_keypair(),
    );
    tx.input[i].witness = Witness::from_slice(&[sig.as_ref()]);
    Ok(())
}

/// A spend of `slot` by `tree`'s leaf `name`, paying `outputs`, its
/// signature not made yet: a placeholder of a signature's size, so it
/// weighs what it will, valid for nothing.
fn unsigned_spend(
    tree: &TapTree,
    name: &str,
    slot: OutPoint,
    outputs: Vec<TxOut>,
) -> Result<Transaction> {
    let leaf = tree.leaf(name)?;
    let mut tx = build_spend(slot, &leaf.timelock, outputs);
    tx.input[0].witness =
        tapscript_witness(&[vec![0; 64]], &leaf.script, &tree.control_block(name)?);
    Ok(tx)
}
/// A presigned link's anchor output: only its poster's payment key spends
/// it ([`fee_script`]), in its fee child ([`link_child`]).
pub const ANCHOR_VOUT: u32 = 1;

/// The fee child of `link`, which pays `link_fee` itself: it spends the
/// link's anchor ([`ANCHOR_VOUT`]) and `coins`, pays the rest to `change`,
/// and brings the pair to `rate`, its own relay floor (1 sat/vB) at least.
/// `sign` signs every input, given the prevouts in order. Refused if the
/// coins fall short of its fee and a change output of dust.
pub fn link_child(
    link: &Transaction,
    link_fee: Amount,
    coins: &[(OutPoint, TxOut)],
    change: ScriptBuf,
    rate: FeeRate,
    sign: impl Fn(&mut Transaction, &[TxOut]) -> Result<()>,
) -> Result<Transaction> {
    let anchor = link
        .output
        .get(ANCHOR_VOUT as usize)
        .context("a link without an anchor")?;
    let anchor = (
        OutPoint {
            txid: link.compute_txid(),
            vout: ANCHOR_VOUT,
        },
        anchor.clone(),
    );
    let inputs: Vec<&(OutPoint, TxOut)> = std::iter::once(&anchor).chain(coins).collect();
    let prevouts: Vec<TxOut> = inputs.iter().map(|(_, out)| out.clone()).collect();
    let value: Amount = prevouts.iter().map(|o| o.value).sum();
    let dust = change.minimal_non_dust();
    let make = |fee: Amount| -> Result<Transaction> {
        let pays = value
            .checked_sub(fee)
            .filter(|pays| *pays >= dust)
            .with_context(|| format!("fee coins of {value} short of a child's fee of {fee}"))?;
        let mut tx = Transaction {
            version: lichen_btc::bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(outpoint, _)| TxIn {
                    previous_output: *outpoint,
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                })
                .collect(),
            output: vec![TxOut {
                value: pays,
                script_pubkey: change.clone(),
            }],
        };
        sign(&mut tx, &prevouts)?;
        Ok(tx)
    };
    // Signed at no fee for its size: signatures of a fixed size.
    let size = make(Amount::ZERO)?.vsize() as u64;
    let pair = rate
        .fee_vb(link.vsize() as u64 + size)
        .context("fee overflow")?;
    let fee = pair
        .checked_sub(link_fee)
        .unwrap_or(Amount::ZERO)
        .max(Amount::from_sat(size));
    make(fee)
}

pub fn fee_script(key: &Keypair) -> Result<ScriptBuf> {
    Ok(anchor_tree_for(&key.x_only_public_key().0)?.script_pubkey())
}
pub fn sign_fee_input(
    key: &Keypair,
    tx: &mut Transaction,
    i: usize,
    prevouts: &[TxOut],
) -> Result<()> {
    let tree = anchor_tree_for(&key.x_only_public_key().0)?;
    sign_leaf_input(key, tx, i, prevouts, &tree, "fee")
}

/// Sign input `i` of `tx`, spending a coin of `tree` by its leaf `name`
/// (one signature of `key`, `<key> OP_CHECKSIG` first) over every input
/// and output (SIGHASH_DEFAULT): `prevouts` in order.
pub fn sign_leaf_input(
    key: &Keypair,
    tx: &mut Transaction,
    i: usize,
    prevouts: &[TxOut],
    tree: &TapTree,
    name: &str,
) -> Result<()> {
    ensure!(
        prevouts.len() == tx.input.len() && i < prevouts.len(),
        "fee prevout count"
    );
    ensure!(
        prevouts[i].script_pubkey == tree.script_pubkey(),
        "another fee key"
    );
    let leaf = tree.leaf(name)?;
    let sig = sign_tapscript(key, tx, i, prevouts, &leaf.script)?;
    tx.input[i].witness = tapscript_witness(
        &[sig.as_ref().to_vec()],
        &leaf.script,
        &tree.control_block(name)?,
    );
    Ok(())
}
/// A payout's value and the on-chain signature its bit leaves read.
pub struct Payout<'a> {
    pub transaction: &'a Transaction,
    pub value_key: &'a WotsPublic,
    pub signer: Role,
    /// The word signed, as the chain shows it: its bits select the outputs.
    pub word: Word,
    pub wire: &'a [Vec<u8>],
}

/// Collect the graph-owned bits and reserve for either party.
pub fn sweep(
    babe: &HubProves,
    key: &Keypair,
    payout: Payout<'_>,
    party: Role,
    to: ScriptBuf,
    rate: FeeRate,
) -> Result<Transaction> {
    sweep_with(babe, key, payout, party, to, rate, &[])
}
/// [`sweep`], `coins` of `key`'s fee script ([`fee_script`]) swept with
/// what the payout owes: a request's anchor and purse, say, no claim
/// published to spend them. Of those alone if the payout owes nothing.
pub fn sweep_with(
    babe: &HubProves,
    key: &Keypair,
    payout: Payout<'_>,
    party: Role,
    to: ScriptBuf,
    rate: FeeRate,
    coins: &[(OutPoint, TxOut)],
) -> Result<Transaction> {
    let owned = babe.core().owned(
        payout.transaction,
        payout.value_key,
        payout.signer,
        payout.word,
        party,
    )?;
    sweep_owned(&owned, coins, key, payout.wire, to, rate)
}
/// `owned`, outputs of a payout of the word she signed ([`equivocated`]),
/// swept by their `equiv_b` leaves with her two signatures on different
/// words, `wires` (each as the payout's leaves take it,
/// [`HubProves::b_wire`]): the request she signed one, and the one a
/// reorganization mined in its place, its txid the same, the other. They
/// take no wait, so the hub sweeps them before hers end.
pub fn sweep_equivocated(
    owned: &[Owned],
    key: &Keypair,
    wires: [&[Vec<u8>]; 2],
    to: ScriptBuf,
    rate: FeeRate,
) -> Result<Transaction> {
    ensure!(wires[0] != wires[1], "one signature, not two");
    ensure!(!owned.is_empty(), "no output to sweep");
    sweep_owned(owned, &[], key, &wires.concat(), to, rate)
}

/// Every output of `payout`, a terminal paying the word she signed under
/// `b_key` (`request_timeout`, `contest_timeout`, `failure`), that reads
/// that signature: each bit's and the reserve output, hers as much as the
/// hub's, by their `equiv_b` leaves ([`sweep_equivocated`]). In output
/// order; an output not of its script (none paid) is skipped.
pub fn equivocated(
    babe: &HubProves,
    payout: &Transaction,
    b_key: &WotsPublic,
) -> Result<Vec<Owned>> {
    let core = babe.core();
    let (t, ctx) = (core.terms, core.ctx());
    let txid = payout.compute_txid();
    let bits = t.payout().paid_bits();
    // Her reserve's output follows the bits' (Lichen's `Core::owned`), its
    // `equiv_b` index the first after theirs.
    let reserve = (
        bits.len() as u32,
        lichen_contract::reserve_tree_signed(&ctx, t, b_key, Role::User)?,
        bits.end,
    );
    let outputs = (bits.clone())
        .map(|i| {
            let tree = lichen_contract::bit_tree_signed(&ctx, i, b_key, Role::User)?;
            Ok((i - t.low_bits, tree, i))
        })
        .chain(std::iter::once(Ok(reserve)))
        .collect::<Result<Vec<_>>>()?;
    Ok(outputs
        .into_iter()
        .filter_map(|(vout, tree, i)| {
            let out = (payout.output.get(vout as usize))
                .filter(|o| o.script_pubkey == tree.script_pubkey())?
                .clone();
            Some(Owned {
                op: OutPoint { txid, vout },
                out,
                tree,
                leaf: format!("equiv_b_{i}"),
                with_value: true,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            })
        })
        .collect())
}

fn sweep_owned(
    owned: &[Owned],
    coins: &[(OutPoint, TxOut)],
    key: &Keypair,
    wire: &[Vec<u8>],
    to: ScriptBuf,
    rate: FeeRate,
) -> Result<Transaction> {
    ensure!(!owned.is_empty() || !coins.is_empty(), "no owned outputs");
    let prevouts: Vec<_> = (owned.iter().map(|o| o.out.clone()))
        .chain(coins.iter().map(|(_, out)| out.clone()))
        .collect();
    let total = prevouts.iter().try_fold(Amount::ZERO, |s, o| {
        s.checked_add(o.value).context("sweep overflow")
    })?;
    let inputs: Vec<_> = (owned.iter().map(|o| (o.op, o.sequence)))
        .chain(
            coins
                .iter()
                .map(|(op, _)| (*op, Sequence::ENABLE_RBF_NO_LOCKTIME)),
        )
        .collect();
    let mut tx = build_tx(
        &inputs,
        vec![TxOut {
            value: total,
            script_pubkey: to,
        }],
        LockTime::ZERO,
    );
    let sign = |tx: &mut Transaction| -> Result<()> {
        for (i, o) in owned.iter().enumerate() {
            tx.input[i].witness = o.witness(tx, i, &prevouts, key, wire)?;
        }
        for i in owned.len()..tx.input.len() {
            sign_fee_input(key, tx, i, &prevouts)?;
        }
        Ok(())
    };
    sign(&mut tx)?;
    let fee = rate
        .fee_vb(tx.vsize() as u64)
        .context("sweep fee overflow")?;
    tx.output[0].value = total.checked_sub(fee).context("sweep cannot pay fee")?;
    ensure!(
        tx.output[0].value >= tx.output[0].script_pubkey.minimal_non_dust(),
        "dust sweep"
    );
    sign(&mut tx)?;
    Ok(tx)
}

#[allow(clippy::too_many_arguments)]
pub fn exit(
    carrier: Carrier,
    headers: Vec<[u8; 80]>,
    funding: &Transaction,
    request: (&Block, &Txid),
    publish: (&Block, &Txid),
    respond: (&Block, &Txid),
    disclosure: Option<(&Block, &Txid)>,
) -> Result<licash_statement::Exit> {
    Ok(licash_statement::Exit {
        headers,
        request: crate::exit::request(funding, request.0, request.1)?,
        publish: crate::exit::slot_spend(publish.0, publish.1, carrier)?,
        respond: crate::exit::respond(respond.0, respond.1)?,
        disclosure: disclosure
            .map(|(b, t)| crate::exit::slot_spend(b, t, carrier))
            .transpose()?,
    })
}

/// The claim bytes `publication` carries in the request's slot, read as
/// the contract's `carrier` carries them.
pub fn published(
    carrier: Carrier,
    request: &Transaction,
    publication: &Block,
    txid: &Txid,
) -> Result<Vec<u8>> {
    carried(carrier, request, publication, txid)
        .context("the publication carries no claim in the request's slot")
}

/// The bytes `disclosure` carries in the response's disclose slot: what
/// the hub made public of its evidence.
pub fn disclosed(
    carrier: Carrier,
    response: &Transaction,
    disclosure: &Block,
    txid: &Txid,
) -> Result<Vec<u8>> {
    carried(carrier, response, disclosure, txid)
        .context("the disclosure carries nothing in the response's slot")
}

/// What the spend `txid` in `block` of `link`'s slot carries.
fn carried(carrier: Carrier, link: &Transaction, block: &Block, txid: &Txid) -> Option<Vec<u8>> {
    let spend = crate::exit::slot_spend(block, txid, carrier).ok()?;
    let slot = licash_statement::btc::OutPoint {
        txid: lichen_btc::bitcoin::hashes::Hash::to_byte_array(link.compute_txid()),
        vout: licash_statement::SLOT_VOUT,
    };
    spend.carrying(&slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_btc::bitcoin::{secp256k1::Secp256k1, transaction::Version, Witness};

    fn key() -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[7; 32]).unwrap()
    }

    /// A link of about 1 000 vB, its anchor the key's.
    fn link() -> Transaction {
        let mut witness = Witness::new();
        witness.push(vec![0; 3_900]);
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                witness,
                ..Default::default()
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: ScriptBuf::new_op_return([]),
                },
                TxOut {
                    value: Amount::from_sat(330),
                    script_pubkey: fee_script(&key()).unwrap(),
                },
            ],
        }
    }

    fn coin(value: u64) -> (OutPoint, TxOut) {
        let txid = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(value as u32),
            input: vec![],
            output: vec![],
        }
        .compute_txid();
        (
            OutPoint { txid, vout: 0 },
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: fee_script(&key()).unwrap(),
            },
        )
    }

    fn sign(tx: &mut Transaction, prevouts: &[TxOut]) -> Result<()> {
        (0..tx.input.len()).try_for_each(|i| sign_fee_input(&key(), tx, i, prevouts))
    }

    fn fee(child: &Transaction, coins: &[(OutPoint, TxOut)]) -> u64 {
        let value: u64 = 330 + coins.iter().map(|c| c.1.value.to_sat()).sum::<u64>();
        value - child.output[0].value.to_sat()
    }

    #[test]
    fn a_links_child_brings_the_pair_to_the_rate_crediting_the_links_fee() {
        let (link, coins) = (link(), [coin(20_000)]);
        // At 1 sat/vB of its own size, as a link pays its floor.
        let floor = Amount::from_sat(link.vsize() as u64);
        let change = fee_script(&key()).unwrap();
        let rate = FeeRate::from_sat_per_vb_u32(5);
        let fee_of = |rate| {
            let child = link_child(&link, floor, &coins, change.clone(), rate, sign).unwrap();
            assert_eq!(child.input[0].previous_output.txid, link.compute_txid());
            assert_eq!(child.input[0].previous_output.vout, ANCHOR_VOUT);
            assert_eq!(child.input[1].previous_output, coins[0].0);
            (fee(&child, &coins), child.vsize() as u64)
        };
        let (paid, size) = fee_of(rate);
        let pair = link.vsize() as u64 + size;
        assert_eq!(paid + floor.to_sat(), 5 * pair);
        // At the link's own rate or less: its own relay floor.
        assert_eq!(fee_of(FeeRate::from_sat_per_vb_u32(1)).0, size);
    }

    #[test]
    fn a_child_whose_coins_fall_short_is_refused() {
        let change = fee_script(&key()).unwrap();
        let rate = FeeRate::from_sat_per_vb_u32(50);
        let short = link_child(
            &link(),
            Amount::from_sat(1_000),
            &[coin(20_000)],
            change.clone(),
            rate,
            sign,
        );
        assert!(format!("{:#}", short.unwrap_err()).contains("short"));
        // Two coins pay it.
        let coins = [coin(20_000), coin(60_000)];
        let child =
            link_child(&link(), Amount::from_sat(1_000), &coins, change, rate, sign).unwrap();
        assert_eq!(child.input.len(), 3);
    }
}
