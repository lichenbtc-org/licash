//! The hub's side of a holder's exit, played from the chain on each poll.
//!
//! Her request names a claim `b`; her publication carries the filing. The
//! hub decides what the filing is owed against its evidence
//! ([`licash::recovery::owed`]), what its ledger holds against the claim
//! ([`Evidencer`]) that the statement accepts: owed all of `b`, it lets her
//! timeout pay her; owed less, it pins that evidence, responds `b′`,
//! discloses what the evidence needs published (a granted spend's unlock,
//! a preimage) in the response's disclose slot, proves its statement
//! ([`licash_hp::check`]) and asserts the proof. Challenged, it answers
//! with a kept instance whose circuit opens on the proof. Its evidence and
//! one-time signatures (`b′`, the proof's digits) are pinned in
//! the response pins before they are made. Outputs of a payout that are
//! the hub's are swept to its wallet.
//!
//! Once her publication is as deep as the hub decides on, the hub's ledger
//! retires the notes it names ([`Claims`]), on every path of the dispute:
//! whatever it pays her, she gave them up for it.
//!
//! Every step reads the chain again: nothing here is state but caches and
//! the pins. A stopped prover or a failed broadcast is retried on the next
//! poll.
//!
//! Before any of it, she may close her contract early with the hub: its
//! fold, on the contract output's key path ([`Openings::offer_fold`],
//! [`Openings::sign_fold`]). Only both parties sign a key-path spend: the
//! watcher takes any as the fold, and the contract as ended.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use bitcoin::block::Header;
use bitcoin::{Amount, Block, BlockHash, FeeRate, OutPoint, ScriptBuf, Transaction, TxOut};
use licash::claim::UnsignedClaim;
use licash::disclosure::Disclosures;
use licash::recovery::{self, Evidence, Named};
use licash::request::Request;
use licash_contract::dispute::{self, presign, CoinTree, Payout};
use licash_contract::graph;
use licash_contract::graph::{link_args, HubProves};
use licash_contract::opening::{Hub, HubOpening};
use licash_onchain::deadline;
use licash_statement::Carrier;
use licash_wallet::first_spend;
use lichen_contract::Role;
use sha2::{Digest, Sha256};

use super::prover::{self, Admission};
use super::witness::Decision;
use super::{responses::Responses, Openings, Refused};
use crate::holder::node::Node;
use crate::FoldOffer;
use bitcoin::hashes::Hash as _;
use licash_witness::slot;

/// What the hub's ledger holds against a claim published in the block at
/// a height ([`Found`]): candidates, of which the responder cites those the
/// statement accepts. None known is no error: the claim is then owed what
/// its notes are worth. An error if the ledger hasn't seen that block yet:
/// an activation in it, or before, gives a preimage that voids her refund.
pub type Evidencer = dyn Fn(&UnsignedClaim, u32) -> Result<Found> + Send + Sync;

/// What the hub's ledger holds against a claim ([`Evidencer`]): its
/// candidates, and why each record of it the ledger could not read back
/// was left out. Each of those is evidence the hub had and cannot cite,
/// which the operator is told of at once.
#[derive(Default)]
pub struct Found {
    pub evidence: Vec<Evidence>,
    pub unread: Vec<String>,
}

/// The hub ledger's lock checkpoints, as new contracts open on them
/// ([`Openings::checkpoints_with`]).
pub struct LockCheckpoints {
    /// The height of the newest block the ledger takes as a lock
    /// checkpoint, the chain's tip at the height given: buried in its scan.
    pub height: Box<dyn Fn(u32) -> Result<u32> + Send + Sync>,
    /// Keep a contract's checkpoint as the newest lock checkpoint, if it
    /// is newer than that.
    pub keep: Box<KeepCheckpoint>,
}

/// Keep a contract's checkpoint as a lock checkpoint ([`LockCheckpoints`]).
pub type KeepCheckpoint = dyn Fn(&licash::chain::Checkpoint) -> Result<()> + Send + Sync;

/// Where the hub's ledger retires the notes that a holder's published
/// claim in a contract names ([`Openings::claims_with`]): spent by nothing
/// else from then on. Again is nothing new. The claim as the contract's
/// statement reads it ([`recovery::named`]): every note she signed for,
/// whether or not each item of hers is valid.
pub type Claims = dyn Fn(&[u8; 32], &Named) -> Result<()> + Send + Sync;

/// A coin's first spend, once found: its block's height and it.
type Spend = Option<(u32, Transaction)>;

/// How far a coin's blocks were looked through: the last one's height and
/// hash. Still the chain's at that height, so are all those before it, and
/// what was found in them stands.
type Through = (u32, BlockHash);

/// A signed opening as loaded, checked and its graph built: by the digest
/// of the state it was loaded from.
type Loaded = ([u8; 32], Arc<(Hub, HubOpening)>);

/// The caches of the responder: each signed opening as loaded, while its
/// state is unchanged; each coin's first spend once seen, and how far its
/// blocks were looked through; each header by its hash; what was noted
/// once.
#[derive(Default)]
pub(super) struct Watch {
    loaded: Mutex<HashMap<[u8; 32], Loaded>>,
    spends: Mutex<HashMap<OutPoint, (Through, Spend)>>,
    headers: Mutex<HashMap<BlockHash, Header>>,
    noted: Mutex<HashSet<([u8; 32], &'static str)>>,
    /// A dishonest hub's, for tests: it asserts proofs of another
    /// statement ([`Openings::assert_false_proofs`]).
    #[cfg(feature = "faults")]
    false_proofs: std::sync::atomic::AtomicBool,
    /// A hub shows no one the evidence of its responses, so that holders
    /// cannot check them and contest every one
    /// ([`Openings::refuse_evidence`]).
    #[cfg(feature = "faults")]
    no_evidence: std::sync::atomic::AtomicBool,
    /// A hub shows no one the π2 and π3 of its assertions, as one offline
    /// would ([`Openings::refuse_proofs`]).
    #[cfg(feature = "faults")]
    no_proofs: std::sync::atomic::AtomicBool,
    /// The hub's wallet funds no fee coin, as one out of coins or locked
    /// ([`Openings::fund_no_fee_coins`]).
    #[cfg(feature = "faults")]
    no_coins: std::sync::atomic::AtomicBool,
    /// The next fee coin the hub's wallet funds is lost before it is kept,
    /// as by a crash between the two ([`Openings::lose_next_fee_coin`]).
    #[cfg(feature = "faults")]
    lose_coin: std::sync::atomic::AtomicBool,
}

/// A fold offered a holder: the hub's secret nonce, its holder's public
/// one then the hub's, and the fee. Kept in memory only, and taken out
/// before the hub signs: no nonce of it ever signs twice.
pub(super) struct PendingFold {
    sec: lichen_btc::musig::SecNonce,
    nonces: [lichen_btc::musig::PubNonce; 2],
    fee: Amount,
    /// What it pays her besides her reserve, if she asked a claim paid.
    claim: Option<super::fold::Claim>,
}

/// What a poll of one opening did.
#[derive(Debug, PartialEq, Eq)]
pub enum Played {
    /// Nothing to do yet.
    Idle,
    /// It broadcast `name`.
    Posted(&'static str),
}

impl Openings {
    /// Opening `id` loaded from `state`: checked, its graph built and
    /// signed, which takes seconds, once for each state it is in rather
    /// than every poll. Its checks see nothing but `state` and the trusted
    /// program.
    fn loaded(
        &self,
        id: &[u8; 32],
        state: &[u8],
        ctx: &licash_contract::opening::Context,
    ) -> Result<Arc<(Hub, HubOpening)>> {
        let digest: [u8; 32] = Sha256::digest(state).into();
        let cache = || {
            self.watch
                .loaded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        };
        if let Some((seen, loaded)) = cache().get(id) {
            if *seen == digest {
                return Ok(loaded.clone());
            }
        }
        let hub = Hub::load(state, ctx)?;
        let o = hub.signed()?;
        let loaded = Arc::new((hub, o));
        cache().insert(*id, (digest, loaded.clone()));
        Ok(loaded)
    }

    /// Tell the operator, if any of signed opening `id`'s kept instances
    /// `kept` are not in the data directory, as of one restored from a
    /// backup of its database alone: the hub still responds and asserts,
    /// but answers no challenge, and her challenge of its assertion pays
    /// her all she claims.
    fn missing_instances(&self, id: &[u8; 32], kept: &[u32]) {
        let missing = self.store().missing_instances(id, kept);
        if missing.is_empty() {
            return;
        }
        let id = crate::hex_id(id);
        tracing::error!(%id, ?missing, "kept instances missing");
        self.alert(&format!(
            "contract {id}: {} of its {} kept instances are missing from \
             opening-instances/{id} in the hub's data directory: restore them \
             from a backup, or a challenge of its assertion goes unanswered and \
             pays its holder all she claims",
            missing.len(),
            kept.len()
        ));
    }

    /// Forget the openings loaded but those of `ids`: played no more.
    pub(super) fn keep_loaded(&self, ids: &[[u8; 32]]) {
        let mut cache = self
            .watch
            .loaded
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        cache.retain(|id, _| ids.contains(id));
    }

    pub(super) async fn play(&self, id: &[u8; 32]) -> Result<Played> {
        let ctx = self.context().await.map_err(|e| anyhow!(e.reason))?;
        let row = self.store().row(id)?.context("no signed opening")?;
        ensure!(!row.abandoned, "an opening given up");
        let loaded = self.loaded(id, &row.state, &ctx)?;
        let (hub, o) = (&loaded.0, &loaded.1);
        if self.once(id, "instances checked") {
            self.missing_instances(id, &o.kept);
        }
        let tip = ctx.tip;
        let funding = &o.funding;
        let contract = OutPoint {
            txid: funding.compute_txid(),
            vout: 0,
        };
        let from = o.base.parts().chain.checkpoint.height();
        // The cheap check first: her contract stands, and past its close
        // the default ends it.
        if self.unspent(contract, true).await? {
            let was = self.store().was_unfunded(id)?;
            if was && self.unspent(contract, false).await? {
                self.store().funded(id)?;
            }
            return self.close(id, hub, o, tip).await;
        }
        let Some((r_at, r)) = self.spend(contract, &funding.output[0], from, tip).await? else {
            return self.unfunded(id, hub, o, contract, tip).await;
        };
        self.store().funded(id)?;
        let default = presign(&o.set, "default")?;
        let folded = r
            .input
            .iter()
            .any(|i| i.previous_output == contract && i.witness.len() == 1);
        if folded
            || r.input.first().map(|i| i.previous_output) == Some(contract)
                && r.output == default.tx.output
        {
            // Each party's share went to its wallet: nothing left to play.
            self.end_if_deep(id, hub, o, r_at, tip).await?;
            return Ok(Played::Idle);
        }
        let request = presign(&o.set, "request")?;
        if r.compute_txid() != request.tx.compute_txid() {
            self.note_once(id, "unknown", "her contract went to an unknown transaction");
            return Ok(Played::Idle);
        }
        self.retire_claimed(id, o, &r, r_at, tip).await;
        let main = |tx: &Transaction| OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        };
        // Whatever followed her request, then what follows that.
        let Some((x_at, x)) = self.spend(main(&r), &r.output[0], r_at, tip).await? else {
            return self.decide(id, hub, o, &r, r_at, tip).await;
        };
        let respond = presign(&o.set, "respond")?;
        if x.compute_txid() != respond.tx.compute_txid() {
            return self.collect(id, hub, o, &r, None, (x_at, &x), tip).await;
        }
        // Left alone for `w_X` blocks, her response pays what it says: the
        // hub posts that, and proves nothing.
        let Some((c_at, c)) = self.spend(main(&x), &x.output[0], x_at, tip).await? else {
            // Not posted, the terminal is all the same.
            if let Err(e) = self.redisclose(id, hub, o, &r, (&x, x_at), tip).await {
                tracing::warn!(id = %crate::hex_id(id), "its disclosure not posted again: {e:#}");
            }
            return self.settle(id, hub, o, "respond_timeout", x_at, tip).await;
        };
        let contest = presign(&o.set, "contest")?;
        if c.compute_txid() != contest.tx.compute_txid() {
            return self
                .collect(id, hub, o, &r, Some(&x), (c_at, &c), tip)
                .await;
        }
        // She contested: the hub proves, from her contest on.
        let Some((y_at, y)) = self.spend(main(&c), &c.output[0], c_at, tip).await? else {
            return self
                .assert(id, hub, o, &r, r_at, (&x, x_at), (&c, c_at), tip)
                .await;
        };
        let assert = presign(&o.set, "assert")?;
        if y.compute_txid() != assert.tx.compute_txid() {
            return self
                .collect(id, hub, o, &r, Some(&x), (y_at, &y), tip)
                .await;
        }
        let Some((z_at, z)) = self.spend(main(&y), &y.output[0], y_at, tip).await? else {
            return self.settle(id, hub, o, "success", y_at, tip).await;
        };
        let challenge = presign(&o.set, "challenge_assert")?;
        if z.compute_txid() != challenge.tx.compute_txid() {
            return self
                .collect(id, hub, o, &r, Some(&x), (z_at, &z), tip)
                .await;
        }
        match self.spend(main(&z), &z.output[0], z_at, tip).await? {
            None => {
                // Missing its deadline pays her claim and the hub's reserve.
                let stake = assert_stake(o, &r, &x)?;
                let g = &o.base.parts().graph;
                let deadline = z_at
                    .saturating_add(u32::from(g.answer_window))
                    .saturating_sub(1)
                    .saturating_sub(g.deadline_margin);
                self.answer(id, hub, o, &y, &z, (deadline, stake), tip)
                    .await
            }
            Some((end_at, end)) => {
                self.collect(id, hub, o, &r, Some(&x), (end_at, &end), tip)
                    .await
            }
        }
    }

    /// The first round of contract `id`'s fold: her public nonce taken,
    /// signed by her ([`crate::fold_ask_digest`]), the hub's made, and the
    /// fee it takes from its share at the rate of the day. Kept until she
    /// signs, or asks again.
    pub(super) async fn offer_fold(
        &self,
        id: &[u8; 32],
        body: &[u8],
    ) -> Result<FoldOffer, Refused> {
        let nonce = self.asked_by_her(id, crate::FOLD, body).await?;
        let hers = lichen_btc::musig::PubNonce::from_slice(nonce).map_err(Refused::bad)?;
        self.offered(id, hers, None).await
    }

    /// `body` less her signature, which it ends with: of `route`, by the
    /// holder of contract `id`, with her payment key. Checked before the
    /// hub does any work for it, or replaces the fold it offered her.
    async fn asked_by_her<'a>(
        &self,
        id: &[u8; 32],
        route: &str,
        body: &'a [u8],
    ) -> Result<&'a [u8], Refused> {
        let (asked, signature) = body
            .split_last_chunk::<64>()
            .ok_or_else(|| Refused::bad("no signature of the fold asked"))?;
        // Her key from its terms: the contract compiled only once she
        // proves she asked.
        let hub = self.stored(id).await?;
        let base = hub
            .base()
            .ok_or_else(|| Refused::bad("not a signed contract"))?;
        let hers = graph::party_pub(&base.parts().parties[0]).map_err(Refused::unavailable)?;
        let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(signature)
            .map_err(|_| Refused::bad("not her signature of the fold asked"))?;
        let digest = crate::fold_ask_digest(id, route, asked);
        bitcoin::secp256k1::Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &bitcoin::secp256k1::Message::from_digest(digest),
                &hers.payment,
            )
            .map_err(|_| Refused::bad("not her signature of the fold asked"))?;
        Ok(asked)
    }

    /// The first round of a fold that pays her claim: as [`Self::offer_fold`],
    /// once the ledger holds nothing against the notes she names (it
    /// retires none yet: that waits for her signature).
    pub(super) async fn offer_fold_claim(
        &self,
        id: &[u8; 32],
        body: &[u8],
    ) -> Result<FoldOffer, Refused> {
        let ask = self.asked_by_her(id, crate::FOLD_CLAIM, body).await?;
        let ask = crate::FoldAsk::decode(ask).map_err(Refused::bad)?;
        let hers = lichen_btc::musig::PubNonce::from_slice(&ask.nonce).map_err(Refused::bad)?;
        self.offered(id, hers, Some((ask.amount, ask.notes))).await
    }

    async fn offered(
        &self,
        id: &[u8; 32],
        hers: lichen_btc::musig::PubNonce,
        asked: Option<(u32, Vec<licash::crypto::Point>)>,
    ) -> Result<FoldOffer, Refused> {
        let (hub, o) = self.standing(id).await?;
        let claim = match asked {
            None => None,
            Some((amount, notes)) => {
                let ledger = self.fold_ledger.get().ok_or_else(|| {
                    Refused::unavailable("this hub's ledger holds no claims for folds")
                })?;
                let claim = super::fold::Claim::asked(&o, amount, notes).map_err(Refused::bad)?;
                (ledger.claimable)(id, &claim.notes)
                    .map_err(|e| Refused::bad(format!("{}: {e:#}", crate::NOTES_REFUSED)))?;
                Some(claim)
            }
        };
        let paid = claim.as_ref().map_or(Amount::ZERO, |claim| claim.sats(&o));
        let fee = fold_fee(&o, self.fee_rate().await).map_err(Refused::unavailable)?;
        let fold = crate::fold(&o.babe, &o.funding, paid, fee).map_err(Refused::bad)?;
        // Its share above dust, or the fee would take it whole.
        if fold.tx.output.len() != 2 {
            return Err(Refused::unavailable("fees too high to fold now: later"));
        }
        let (sec, mine) = fold
            .nonce(&hub.keys().party.payment, id)
            .map_err(Refused::unavailable)?;
        let pending = PendingFold {
            sec,
            nonces: [hers, mine],
            fee,
            claim,
        };
        let claimed = pending.claim.as_ref().map(|c| c.amount);
        self.folds().insert(*id, pending);
        tracing::info!(id = %crate::hex_id(id), %fee, ?claimed, "a fold offered");
        Ok(FoldOffer {
            nonce: mine.0,
            fee: fee.to_sat(),
        })
    }

    /// The second round of contract `id`'s fold: her partial signature
    /// on the fold last offered checked, the hub's added, the fold
    /// broadcast. Its nonce is taken out once her partial signature checks,
    /// whatever follows: asked again, it is offered anew. A partial that
    /// does not check leaves it, for her to sign.
    pub(super) async fn sign_fold(
        &self,
        id: &[u8; 32],
        body: &[u8],
    ) -> Result<Transaction, Refused> {
        let (partial, filed) = body
            .split_at_checked(32)
            .ok_or_else(|| Refused::bad("a partial signature is 32 bytes"))?;
        let partial: lichen_btc::musig::Partial = partial
            .try_into()
            .map_err(|_| Refused::bad("a partial signature is 32 bytes"))?;
        let (hub, o) = self.standing(id).await?;
        let (pending, fold) = {
            let mut folds = self.folds();
            let Some(pending) = folds.get(id) else {
                return Err(Refused::bad("no fold offered: POST a nonce first"));
            };
            let paid = pending
                .claim
                .as_ref()
                .map_or(Amount::ZERO, |claim| claim.sats(&o));
            let fold = crate::fold(&o.babe, &o.funding, paid, pending.fee).map_err(Refused::bad)?;
            let holder = &o.babe.core().pubs[0].payment;
            let nonces = &pending.nonces;
            fold.verify_partial(holder, &nonces[0], nonces, &partial)
                .map_err(|e| Refused::bad(format!("her partial signature: {e:#}")))?;
            (folds.remove(id).expect("held under the lock"), fold)
        };
        let nonces = &pending.nonces;
        // Her claim's notes retired before the hub signs, none that anything
        // spent: it holds her signature, so it may fold from here on.
        match (&pending.claim, filed) {
            (None, []) => {}
            (None, _) => return Err(Refused::bad("a fold asked without a claim takes none")),
            (Some(claim), filed) => {
                let ledger = self.fold_ledger.get().ok_or_else(|| {
                    Refused::unavailable("this hub's ledger holds no claims for folds")
                })?;
                let publication = claim
                    .filed(&o, filed)
                    .map_err(|e| Refused::bad(format!("her claim: {e:#}")))?;
                (ledger.retire)(id, &publication)
                    .map_err(|e| Refused::bad(format!("{}: {e:#}", crate::NOTES_REFUSED)))?;
            }
        }
        let signed = fold
            .sign(&hub.keys().party.payment, pending.sec, nonces)
            .and_then(|mine| fold.finish(nonces, &[partial, mine]))
            .map_err(Refused::unavailable)?;
        // Hers to broadcast too: a failure here is no reason to keep it.
        if self.post(&signed).await {
            tracing::info!(id = %crate::hex_id(id), txid = %signed.compute_txid(), "contract folded");
        }
        Ok(signed)
    }

    /// Opening `id`, as the hub stores it: not given up.
    async fn stored(&self, id: &[u8; 32]) -> Result<Hub, Refused> {
        let ctx = self.context().await?;
        let row = self.store().row(id).map_err(Refused::unavailable)?;
        let row = row.ok_or_else(|| Refused::bad("no such contract"))?;
        if row.abandoned {
            return Err(Refused::bad("an opening given up"));
        }
        Hub::load(&row.state, &ctx).map_err(Refused::unavailable)
    }

    /// Opening `id`, signed, as the hub holds it.
    async fn signed_opening(&self, id: &[u8; 32]) -> Result<(Hub, HubOpening), Refused> {
        let hub = self.stored(id).await?;
        let o = hub
            .signed()
            .map_err(|_| Refused::bad("not a signed contract"))?;
        Ok((hub, o))
    }

    /// What the hub's response to contract `id`'s claim was decided on,
    /// for the holder who signs for the contract's claim key
    /// ([`crate::evidence_digest`]) and so can check it: its evidence,
    /// pinned before the response was signed, as
    /// [`recovery::evidence_to_bytes`] writes it. Nobody else is shown it:
    /// it holds the spends of her notes.
    pub(super) async fn show_evidence(
        &self,
        id: &[u8; 32],
        body: &[u8],
    ) -> Result<Vec<u8>, Refused> {
        #[cfg(feature = "faults")]
        if self
            .watch
            .no_evidence
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(Refused::unavailable("no evidence to show"));
        }
        let (_, o) = self.signed_opening(id).await?;
        let pins = Responses::open(&self.data).map_err(Refused::unavailable)?;
        let response = pins
            .response(id)
            .map_err(Refused::unavailable)?
            .ok_or_else(|| Refused::bad("no response to show the evidence of"))?;
        let signature = licash::crypto::Signature(
            body.try_into()
                .map_err(|_| Refused::bad("a signature is 64 bytes"))?,
        );
        licash::crypto::schnorr_verify(
            &o.base.parts().claim_key,
            &crate::evidence_digest(id, &response.compute_txid()),
            &signature,
        )
        .map_err(|_| Refused::bad("not signed with the contract's claim key"))?;
        self.responded_on(id)
            .await
            .map_err(Refused::unavailable)?
            .ok_or_else(|| Refused::bad("no evidence pinned"))
    }

    /// The evidence the hub's response to contract `id` was decided on, as
    /// pinned, else as its witnesses keep it (its pin lost, or restored
    /// older): none where neither holds any.
    async fn responded_on(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        if let Some(pinned) = Responses::open(&self.data)?.evidence(id)? {
            return Ok(Some(pinned));
        }
        let kept = self
            .witnesses()?
            .recover(&self.data, id, slot::RESPOND)
            .await?;
        Ok(match kept {
            Some(Decision::Respond { evidence, .. }) => Some(evidence),
            _ => None,
        })
    }

    /// The π2 and π3 of the assertion the hub signed in contract `id`, as
    /// pinned before it was, for the holder who signs for the contract's
    /// claim key ([`crate::proof_digest`]): 64 bytes then 32. Its leaf
    /// does not check them, so the block may show others (a relayer's, a
    /// miner's) that prove nothing; she checks these instead before she
    /// challenges. They were public as the hub broadcast them, but only
    /// she has a use for them, so only she is shown them.
    pub(super) async fn show_proof(&self, id: &[u8; 32], body: &[u8]) -> Result<Vec<u8>, Refused> {
        #[cfg(feature = "faults")]
        if self
            .watch
            .no_proofs
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(Refused::unavailable("no proof to show"));
        }
        let signature = licash::crypto::Signature(
            body.try_into()
                .map_err(|_| Refused::bad("a signature is 64 bytes"))?,
        );
        let (_, o) = self.signed_opening(id).await?;
        let pins = Responses::open(&self.data).map_err(Refused::unavailable)?;
        let tag = tagged(id, b"assert");
        let assertion = pins
            .response(&tag)
            .map_err(Refused::unavailable)?
            .ok_or_else(|| Refused::bad("no assertion to show the proof of"))?;
        licash::crypto::schnorr_verify(
            &o.base.parts().claim_key,
            &crate::proof_digest(id, &assertion.compute_txid()),
            &signature,
        )
        .map_err(|_| Refused::bad("not signed with the contract's claim key"))?;
        let own = self.own_proof(id, &o).map_err(Refused::unavailable)?;
        let a = o.babe.assertion(&assertion).map_err(Refused::unavailable)?;
        let proof = a
            .answered_on(own)
            .ok_or_else(|| Refused::unavailable("no proof of the assertion pinned"))?;
        let (pi2, pi3) = lichen_babe::statement::pi23_to_bytes(&proof);
        Ok([pi2, pi3].concat())
    }

    /// Opening `id`, signed, its contract output unspent, even by the
    /// mempool: one to fold.
    async fn standing(&self, id: &[u8; 32]) -> Result<(Hub, HubOpening), Refused> {
        let (hub, o) = self.signed_opening(id).await?;
        let contract = OutPoint {
            txid: o.funding.compute_txid(),
            vout: 0,
        };
        if !self
            .unspent(contract, true)
            .await
            .map_err(Refused::unavailable)?
        {
            return Err(Refused::bad(
                "its contract output is spent, or not yet funded",
            ));
        }
        Ok((hub, o))
    }

    fn folds(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], PendingFold>> {
        self.folds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Show holders no evidence of its responses from now on, as a hub
    /// would that cannot back them: for tests of the holder's contest.
    #[cfg(feature = "faults")]
    pub fn refuse_evidence(&self) {
        self.watch
            .no_evidence
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Show holders no π2 and π3 of its assertions from now on, as a hub
    /// offline would: for tests of the holder's challenge.
    #[cfg(feature = "faults")]
    pub fn refuse_proofs(&self) {
        self.watch
            .no_proofs
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the hub's wallet funds no fee coin from now on, as one out
    /// of coins or locked would: for tests of what the hub posts without.
    #[cfg(feature = "faults")]
    pub fn fund_no_fee_coins(&self, none: bool) {
        self.watch
            .no_coins
            .store(none, std::sync::atomic::Ordering::Relaxed);
    }

    /// The next fee coin funded is lost before it is kept, as by a crash
    /// between its funding and its keeping: for tests that the hub finds
    /// it again rather than funding another.
    #[cfg(feature = "faults")]
    pub fn lose_next_fee_coin(&self) {
        self.watch
            .lose_coin
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Assert proofs of another statement from now on, as a dishonest hub
    /// would: for tests of the holder's challenge.
    #[cfg(feature = "faults")]
    pub fn assert_false_proofs(&self) {
        self.watch
            .false_proofs
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Her contract stands: past its close, the default, with a fee coin,
    /// pays each party its share (the hub `V_max` and its reserve).
    async fn close(&self, id: &[u8; 32], hub: &Hub, o: &HubOpening, tip: u32) -> Result<Played> {
        if tip < o.base.parts().graph.close_height {
            return Ok(Played::Idle);
        }
        let prevout = presign(&o.set, "default")?.prevout.clone();
        let tx = self
            .with_fee(
                id,
                hub,
                "default",
                o.default_close()?,
                prevout,
                None,
                &CoinTree::Fee,
            )
            .await?;
        if self.post(&tx).await && self.once(id, "default") {
            return Ok(Played::Posted("default"));
        }
        Ok(Played::Idle)
    }

    /// The notes her publication names, retired in the hub's ledger once
    /// it is as deep as the hub decides on: before it decides, and
    /// whatever ends the dispute. Once a run; the ledger keeps them. A
    /// reclaim, or bytes its statement reads no claim in, name nothing: a
    /// claim it reads, of items valid or not, names all she signed for.
    /// Not retired, the dispute goes on, the operator is told, and the
    /// next poll tries again.
    async fn retire_claimed(
        &self,
        id: &[u8; 32],
        o: &HubOpening,
        r: &Transaction,
        r_at: u32,
        tip: u32,
    ) {
        let Some(claims) = self.claims.get() else {
            return;
        };
        if self.seen(id, "retired") {
            return;
        }
        match self.claimed(o, r, r_at, tip).await {
            Ok(None) => {}
            Ok(Some(Some(named))) => {
                if let Err(e) = claims(id, &named) {
                    if self.once(id, "unretired") {
                        self.alert(&format!(
                            "contract {}: her claimed notes are not retired, so the hub may \
                             accept spends of notes it pays her for on Bitcoin: {e:#}",
                            crate::hex_id(id)
                        ));
                    }
                    return;
                }
                self.once(id, "retired");
            }
            Ok(Some(None)) => {
                self.once(id, "retired");
            }
            Err(e) => tracing::warn!(id = %crate::hex_id(id), "reading her publication: {e:#}"),
        }
    }

    /// Her publication, once as deep as the hub decides on: none yet, or
    /// the claim it carries, if any, read as the hub's statement reads it
    /// ([`recovery::named`]).
    async fn claimed(
        &self,
        o: &HubOpening,
        r: &Transaction,
        r_at: u32,
        tip: u32,
    ) -> Result<Option<Option<Named>>> {
        let slot = OutPoint {
            txid: r.compute_txid(),
            vout: SLOT,
        };
        let Some((p_at, p)) = self
            .spend(slot, &r.output[slot.vout as usize], r_at, tip)
            .await?
        else {
            return Ok(None);
        };
        let depth = o.base.parts().chain.funding_depth.max(1);
        if tip.saturating_add(1) < p_at.saturating_add(depth) {
            return Ok(None);
        }
        let request = presign(&o.set, "request")?;
        let block = self.block_at(p_at).await?;
        let carrier = licash_hp::carrier(&o.base);
        let named = dispute::published(carrier, &request.tx, &block, &p.compute_txid())
            .ok()
            .and_then(|filed| recovery::named(&o.base, &filed).ok());
        Ok(Some(named))
    }

    /// Her request stands: what her publication is owed, and the response
    /// if less than she claims.
    async fn decide(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        r: &Transaction,
        r_at: u32,
        tip: u32,
    ) -> Result<Played> {
        let slot = OutPoint {
            txid: r.compute_txid(),
            vout: SLOT,
        };
        let Some((p_at, p)) = self
            .spend(slot, &r.output[slot.vout as usize], r_at, tip)
            .await?
        else {
            // She never published: the slot is the hub's after k.
            let k = u32::from(o.babe.spec.windows.k);
            if tip.saturating_add(1) >= r_at.saturating_add(k) {
                // Its slot's value alone pays no fee: a fee coin with it.
                let prevout = r.output[slot.vout as usize].clone();
                let tx = o.reclaim(hub.keys())?;
                let tx = self
                    .with_fee(
                        id,
                        hub,
                        "reclaim",
                        tx,
                        prevout.clone(),
                        None,
                        &CoinTree::Fee,
                    )
                    .await?;
                let tx = self.sealed(id, hub, o, "reclaim", tx, prevout)?;
                if self.post(&tx).await {
                    return Ok(Played::Posted("reclaim"));
                }
            }
            return Ok(Played::Idle);
        };
        let request = presign(&o.set, "request")?;
        if p.input.iter().all(|i| i.previous_output != slot) {
            return Ok(Played::Idle);
        }
        // Her slot spent by her publication, or by the hub's reclaim: then
        // her claim reads as empty, owed nothing, and is answered so.
        let depth = o.base.parts().chain.funding_depth.max(1);
        if tip.saturating_add(1) < p_at.saturating_add(depth) {
            return Ok(Played::Idle);
        }
        // Her publication past the headers a proof can carry: nothing to
        // judge it on, and a response on the short chain would commit the
        // hub to a proof it can never make. Unanswered, her timeout pays
        // her what she claims, which the hub keeps its reserve against.
        let chain_terms = &o.base.parts().chain;
        if past_the_headers(
            chain_terms.checkpoint.height(),
            chain_terms.max_headers,
            p_at,
        ) {
            if self.once(id, "past-headers") {
                self.alert(&format!(
                    "contract {}: her publication is in block {p_at}, past the {} headers \
                     after its checkpoint a proof can carry: the hub cannot judge her claim, \
                     and does not respond to it.",
                    crate::hex_id(id),
                    chain_terms.max_headers
                ));
            }
            return Ok(Played::Idle);
        }
        // Her claim as filed and the chain it is judged on. Whatever keeps
        // the hub from reading them keeps it from answering: told, as a
        // ledger that gives no evidence is, while there is time to mend it.
        let read = async {
            let block = self.block_at(p_at).await?;
            let carrier = licash_hp::carrier(&o.base);
            let filed = dispute::published(carrier, &request.tx, &block, &p.compute_txid())?;
            let (b, e) = o.requested_b(r)?;
            let headers = self.headers(o, p_at).await?;
            let chain = licash_hp::chain(&o.base, &headers).map_err(|e| anyhow!("{e}"))?;
            anyhow::Ok((filed, b, e, chain))
        };
        let (filed, b, e, chain) = match read.await {
            Ok(read) => read,
            Err(e) => {
                self.undecided(id, &e, r_at, respond_deadline(o, r_at), tip);
                return Err(e);
            }
        };
        let request = Request {
            amount: b,
            claim_digest: e,
        };
        let owed = |evidence: &[Evidence]| {
            recovery::owed(&o.base, &request, &filed, evidence, &chain).map_err(|e| anyhow!("{e}"))
        };
        let pins = Responses::open(&self.data)?;
        let spends = OutPoint {
            txid: r.compute_txid(),
            vout: 0,
        };
        // Hers after `w_H` blocks: until then only a response spends it.
        let hers_at = r_at.saturating_add(u32::from(o.base.parts().graph.response_window));
        let lone = tip.saturating_add(1) < hers_at;
        let pinned = pins.evidence(id)?.is_some();
        if !pinned
            && self
                .unpinned(id, slot::RESPOND, id, r, spends, lone)
                .await?
        {
            return Ok(Played::Idle);
        }
        // What its ledger holds against her claim that the hub cannot cite.
        let mut missed = Vec::new();
        let evidence = match pins.evidence(id)? {
            Some(pinned) => pinned_evidence(o, &pinned)?,
            None => match self.select(o, &filed, p_at, owed) {
                Ok(selected) => {
                    missed = selected.uncited;
                    selected.kept
                }
                Err(e) => {
                    // Its ledger may yet answer: the hub waits for it while
                    // half the blocks to respond in are left. Then it
                    // answers on what it proves without, if that is less
                    // than she asks: an answer of less evidence saves less,
                    // none saves nothing.
                    let deadline = respond_deadline(o, r_at);
                    let alone = owed(&[])
                        .ok()
                        .filter(|alone| unevidenced(alone.owed, b, half_gone(r_at, deadline, tip)));
                    let Some(alone) = alone else {
                        self.undecided(id, &e, r_at, deadline, tip);
                        return Err(e);
                    };
                    if self.once(id, "unevidenced") {
                        self.alert(&format!(
                            "contract {}: the hub cannot read its ledger's evidence against \
                             her claim ({e:#}), and {} blocks are left to respond in. It \
                             answers on what it proves without: {} of the {b} she claims.",
                            crate::hex_id(id),
                            deadline.saturating_sub(tip),
                            alone.owed
                        ));
                    }
                    Vec::new()
                }
            },
        };
        let mut decided = owed(&evidence)?;
        if !missed.is_empty() {
            self.uncited(id, &missed, b, decided.owed, respond_deadline(o, r_at), tip);
        }
        if decided.owed >= b {
            self.note_once(
                id,
                "owed",
                "her claim is owed all she asks: her timeout pays her",
            );
            return Ok(Played::Idle);
        }
        // A response commits the hub to a proof in time: none unless its
        // prover has room for it (once signed, it is posted again whatever).
        let prover = self.prover.as_ref().filter(|_| !o.mock);
        let responded = pins.response(id)?.is_some();
        // At the earliest, its response confirms in the next block.
        let job = |evidence: &[Evidence]| {
            let x_at = tip.saturating_add(1);
            let release = x_at.saturating_add(o.base.parts().chain.work_depth);
            (
                assert_deadline(o, x_at),
                release,
                estimated_cycles(o, evidence, release),
            )
        };
        if let Some(prover) = prover.filter(|_| !responded) {
            let (deadline, release, cycles) = job(&evidence);
            // In sats: what responding saves the hub.
            let unit = o.base.parts().graph.unit_sats;
            let stake = u64::from(b.saturating_sub(decided.owed)) * unit;
            let program = &o.base.parts().recipe.program;
            match prover.admit(id, program, stake, cycles, deadline, release, tip) {
                Admission::Admit => {}
                Admission::Wait => {
                    // A poll's wait as a rule. A prover that never says
                    // whether it can prove leaves her claim unanswered as
                    // surely as one that says it cannot: told as that is.
                    let respond_by = respond_deadline(o, r_at);
                    if half_gone(r_at, respond_by, tip) && self.once(id, "unadmitted") {
                        self.alert(&format!(
                            "contract {}: her claim is owed {} of the {b} she asks, and the \
                             hub's prover has not said whether it can prove that: no response \
                             yet, and {} blocks are left to respond in. Unanswered, her \
                             timeout pays her all she claims.",
                            crate::hex_id(id),
                            decided.owed,
                            respond_by.saturating_sub(tip)
                        ));
                    }
                    return Ok(Played::Idle);
                }
                Admission::Withhold(why) => {
                    if self.once(id, "withheld") {
                        self.withheld(id, b, decided.owed, &why);
                    }
                    return Ok(Played::Idle);
                }
            }
        }
        // What is pinned first is what the hub answers on, unless its
        // witnesses agreed on another before.
        let mut pinned = pins.pin(id, r, &recovery::evidence_to_bytes(&evidence))?;
        let mut evidence = pinned_evidence(o, &pinned)?;
        decided = owed(&evidence)?;
        ensure!(
            decided.owed < b,
            "the pinned evidence leaves her claim owed"
        );
        let response = match pins.response(id)? {
            // Signed: posted again as it is.
            Some(response) => response,
            None => {
                let ours = Decision::Respond {
                    request: r.compute_txid().to_byte_array(),
                    b,
                    e,
                    owed: decided.owed,
                    evidence: pinned.clone(),
                };
                let Some(agreed) = self.authorized(id, slot::RESPOND, &ours).await? else {
                    return Ok(Played::Idle);
                };
                let Decision::Respond {
                    request,
                    b: agreed_b,
                    e: agreed_e,
                    owed: b_prime,
                    evidence: agreed_evidence,
                } = agreed
                else {
                    bail!("the witnesses keep another kind of decision for its response");
                };
                ensure!(
                    request == r.compute_txid().to_byte_array() && (agreed_b, agreed_e) == (b, e),
                    "the witnesses keep a response to another request: it signs none"
                );
                if agreed_evidence != pinned {
                    pins.adopt(id, r, &agreed_evidence)?;
                    pinned = agreed_evidence;
                    evidence = pinned_evidence(o, &pinned)?;
                    decided = owed(&evidence)?;
                }
                // Signed only as its witnesses keep it, and as its evidence
                // decides it.
                ensure!(
                    decided.owed == b_prime && b_prime < b,
                    "the response its witnesses keep, b′ = {b_prime}, is not what its evidence \
                     decides ({}): it signs none",
                    decided.owed
                );
                tracing::warn!(
                    id = %crate::hex_id(id),
                    claimed = b,
                    owed = decided.owed,
                    cited = evidence.len(),
                    "a contract claim is owed less than it asks: responding"
                );
                self.store().begin_signing(id, "respond")?;
                let keys = hub.keys();
                pins.answer(id, r, || {
                    let tx = o.respond(keys, b_prime)?;
                    ensure!(
                        graph::responded(&o.base, &tx)? == b_prime,
                        "the response signs another b′ than its witnesses keep"
                    );
                    Ok(tx)
                })?
            }
        };
        if let Some(prover) = prover {
            let (deadline, release, cycles) = job(&evidence);
            let program = o.base.parts().recipe.program;
            prover.commit(id, program, deadline, release, cycles, false, false, tip);
        }
        let window = (r_at, respond_deadline(o, r_at));
        let unit = Amount::from_sat(o.base.parts().graph.unit_sats);
        let stake = unit * u64::from(b.saturating_sub(decided.owed));
        let prevout = &r.output[0];
        self.post_link(id, hub, "respond", &response, prevout, window, stake, tip)
            .await?;
        // Its disclosure with it: the statement wants the contract's work
        // on top of both, within the assertion window. In a block at the
        // earliest the next, as its response.
        let x_at = tip.saturating_add(1);
        let reserve = o.babe.spec.terms.reserve_hub;
        let by = (x_at, disclose_deadline(o, x_at)?, stake + reserve);
        self.disclose(id, hub, o, &decided.disclosures, by, tip)
            .await?;
        Ok(Played::Posted("respond"))
    }

    /// Of the ledger's candidates against her filing, those the statement
    /// accepts, in order ([`cited`]). None against a claim ineligible or
    /// owed nothing. Her filing is read as the statement reads it
    /// ([`recovery::named`]): one it decides on is one the hub finds its
    /// evidence against.
    ///
    /// With them, why each record of its ledger against her claim that the
    /// hub cannot cite was left out: one it could not read back, or one its
    /// statement could not ([`Cited::uncited`]).
    fn select(
        &self,
        o: &HubOpening,
        filed: &[u8],
        published_at: u32,
        owed: impl Fn(&[Evidence]) -> Result<recovery::Owed>,
    ) -> Result<Cited> {
        let Some(ledger) = self.evidencer.get() else {
            return Ok(Cited::default());
        };
        let none = owed(&[])?;
        if none.ineligible.is_some() || none.owed == 0 {
            return Ok(Cited::default());
        }
        let named = recovery::named(&o.base, filed).map_err(|e| anyhow!("{e}"))?;
        let found = ledger(named.claim(), published_at)?;
        // Each spend by the signatures her claim makes it rely on, so that
        // its proof costs what she names, not what the spend took and made.
        let mut unread = found.unread;
        let candidates = (found.evidence.into_iter())
            .filter_map(|e| match recovery::cite(named.claim(), e) {
                Ok(e) => Some(e),
                Err(e) => {
                    unread.push(format!("a spend not cited by its signatures: {e}"));
                    None
                }
            })
            .collect();
        let mut selected = cited(candidates, &none, owed, |evidence| {
            pinned_evidence(o, &recovery::evidence_to_bytes(evidence))
        });
        selected.uncited.splice(0..0, unread);
        Ok(selected)
    }

    /// The hub's ledger holds evidence against her claim of `b`, owed
    /// `owed` on the rest, that it cannot cite, for each of `why`: the
    /// operator is told at once, whatever is left of the blocks to respond
    /// in to `deadline`, since nothing the hub does by itself will cite it.
    /// Its notes were retired, and her claim may be paid for them.
    fn uncited(&self, id: &[u8; 32], why: &[String], b: u32, owed: u32, deadline: u32, tip: u32) {
        if !self.once(id, "uncited") {
            return;
        }
        let shown = 3;
        let mut reasons = why[..why.len().min(shown)].join("; ");
        if why.len() > shown {
            reasons.push_str(&format!("; and {} more", why.len() - shown));
        }
        let outcome = match owed >= b {
            true => "Without it her claim is owed all she asks: unanswered, her timeout pays her \
                     all she claims."
                .to_owned(),
            false => format!("It answers on the rest: {owed} of the {b} she claims."),
        };
        self.alert(&format!(
            "contract {}: the hub's ledger holds evidence against her claim that it cannot \
             cite ({reasons}), and {} blocks are left to respond in. {outcome}",
            crate::hex_id(id),
            deadline.saturating_sub(tip)
        ));
    }

    /// The hub could not decide its answer to her request of `r_at`, for
    /// `why`, and proves her owed no less than she asks without its
    /// ledger: no response is made, and it tries again every round. While
    /// its ledger's scan is a few blocks behind her claim's that passes;
    /// once half the blocks to `deadline`, the last at which a response
    /// still confirms in time, are gone, the operator is alerted, once.
    fn undecided(&self, id: &[u8; 32], why: &anyhow::Error, r_at: u32, deadline: u32, tip: u32) {
        if !half_gone(r_at, deadline, tip) || !self.once(id, "undecided") {
            return;
        }
        self.alert(&format!(
            "contract {}: the hub cannot decide its answer to her claim ({why:#}), and {} \
             blocks are left to respond in. Unanswered, her timeout pays her all she claims.",
            crate::hex_id(id),
            deadline.saturating_sub(tip)
        ));
    }

    /// Post the disclosure of `disclosures` in the response's disclose
    /// slot, with a fee coin of the hub's, to be in a block by `by`'s
    /// deadline, its fee `by`'s stake at most ([`Self::with_fee_by`]):
    /// nothing if there is none to make. In no block halfway from `by`'s
    /// first block it may be in to its deadline, and again past that
    /// deadline, the operator is told, once each. Whether it was broadcast.
    async fn disclose(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        disclosures: &Disclosures,
        (from, deadline, stake): (u32, u32, Amount),
        tip: u32,
    ) -> Result<bool> {
        if *disclosures == Disclosures::empty() {
            return Ok(false);
        }
        let halfway = from.saturating_add(deadline.saturating_sub(from) / 2);
        if tip > from && tip >= halfway && tip <= deadline && self.once(id, "disclose slow") {
            self.alert(&format!(
                "contract {}: its disclosure is in no block yet, halfway to block {deadline} \
                 (now {tip}), the last it is in time from: its fee rises as that nears; \
                 check the hub's wallet funds its fee coins",
                crate::hex_id(id)
            ));
        }
        if tip > deadline && self.once(id, "disclose late") {
            self.alert(&format!(
                "contract {}: its disclosure is in no block by block {} (now {tip}), the \
                 last it is in time from: she may contest its response, and then it must \
                 prove what it responded",
                crate::hex_id(id),
                deadline
            ));
        }
        let by = (deadline, stake);
        let respond = presign(&o.set, "respond")?;
        let prevout = respond.tx.output[SLOT as usize].clone();
        let bytes = disclosures.encode(licash::recovery::Format::of(&o.base).lean());
        let tx = o.disclosure(hub.keys(), &bytes, vec![])?;
        // Under a leaf carrier its fee coin carries the bytes: its coins
        // kept under a name of theirs, so that other bytes (none are, the
        // evidence pinned) take a coin of their own, not one of others.
        let (name, tree) = match licash_hp::carrier(&o.base) {
            Carrier::Nulldata => ("disclose".to_string(), CoinTree::Fee),
            Carrier::Leaf => {
                let key = &hub.keys().party.payment;
                let digest = bitcoin::hashes::sha256::Hash::hash(&bytes);
                let name = format!("disclose {}", &digest.to_string()[..16]);
                (
                    name,
                    CoinTree::Envelope(dispute::envelope_tree(key, &bytes)?),
                )
            }
        };
        let tx = self
            .with_fee_by(id, hub, &name, tx, prevout.clone(), by, tip, &tree)
            .await?;
        let tx = self.sealed(id, hub, o, &name, tx, prevout)?;
        Ok(self.post(&tx).await)
    }

    /// Her response in a block at `x_at` and no contest in one yet: its
    /// disclosure posted again, if its evidence needs one in none yet, to
    /// be in a block before her wallet, finding none, contests it
    /// ([`disclose_deadline`]).
    async fn redisclose(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        r: &Transaction,
        (x, x_at): (&Transaction, u32),
        tip: u32,
    ) -> Result<()> {
        // Her contest window over, none is needed.
        if tip.saturating_add(1) >= x_at.saturating_add(waits(o, "respond_timeout")?) {
            return Ok(());
        }
        let slot = OutPoint {
            txid: x.compute_txid(),
            vout: SLOT,
        };
        if (self
            .spend(slot, &x.output[SLOT as usize], x_at, tip)
            .await?)
            .is_some()
        {
            return Ok(());
        }
        let Some(pinned) = self.responded_on(id).await? else {
            return Ok(());
        };
        let evidence = pinned_evidence(o, &pinned)?;
        let disclosures = recovery::disclosures(&evidence).map_err(|e| anyhow!("{e}"))?;
        let by = (x_at, disclose_deadline(o, x_at)?, assert_stake(o, r, x)?);
        self.disclose(id, hub, o, &disclosures, by, tip).await?;
        Ok(())
    }

    /// She contested the hub's response, `x` in a block at `x_at`, with `c`
    /// at `c_at`: its proof that her claim is owed no more, once the
    /// response is deep enough, then its assertion. What it decides on,
    /// first found first: the assertion signed, the proof pinned for it,
    /// the proof made of the input frozen for it.
    #[allow(clippy::too_many_arguments)]
    async fn assert(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        r: &Transaction,
        r_at: u32,
        (x, x_at): (&Transaction, u32),
        (c, c_at): (&Transaction, u32),
        tip: u32,
    ) -> Result<Played> {
        let tag = tagged(id, b"assert");
        let pins = Responses::open(&self.data)?;
        // Missing its deadline pays her claim and the hub's reserve.
        let stake = assert_stake(o, r, x)?;
        let window = (c_at, assert_deadline(o, c_at));
        let post = |tx: Transaction| async move {
            self.post_link(id, hub, "assert", &tx, &c.output[0], window, stake, tip)
                .await
        };
        let spends = OutPoint {
            txid: c.compute_txid(),
            vout: 0,
        };
        if let Some(tx) = pins.response(&tag)? {
            self.store().begin_signing(id, "assert")?;
            post(tx).await?;
            return Ok(Played::Posted("assert"));
        }
        // Hers after `w_A` blocks: until then only an assertion spends it.
        let hers_at = c_at.saturating_add(u32::from(o.base.parts().graph.assert_window));
        let lone = tip.saturating_add(1) < hers_at;
        let pinned = pins.evidence(&tag)?.is_some();
        if !pinned
            && self
                .unpinned(id, slot::ASSERT, &tag, r, spends, lone)
                .await?
        {
            return Ok(Played::Idle);
        }
        let journal = graph::journal(&o.base);
        let kind = graph::kind(&o.base, o.mock);
        let proof = match pins.evidence(&tag)?.filter(|p| !p.is_empty()) {
            Some(pinned) => lichen_babe::statement::proof_from_bytes(&pinned)
                .context("the pinned proof does not decode")?,
            None => match self
                .prove(id, o, r, r_at, (x, x_at), c_at, tip, hub)
                .await?
            {
                Ok(proof) => proof,
                Err(played) => return Ok(played),
            },
        };
        ensure!(
            kind.verify(&journal, &proof) || self.false_proofs(),
            "the proof does not verify for this contract"
        );
        let ours = Decision::Assert {
            request: r.compute_txid().to_byte_array(),
            digits: dispute::asserted_digits(&proof),
            proof: lichen_babe::statement::proof_to_bytes(&proof),
        };
        let Some(agreed) = self.authorized(id, slot::ASSERT, &ours).await? else {
            return Ok(Played::Idle);
        };
        let Decision::Assert {
            request,
            digits,
            proof: agreed_proof,
        } = agreed
        else {
            bail!("the witnesses keep another kind of decision for its assertion");
        };
        ensure!(
            request == r.compute_txid().to_byte_array(),
            "the witnesses keep an assertion against another request: it signs none"
        );
        let proof = match ours {
            Decision::Assert {
                proof: ref mine, ..
            } if *mine == agreed_proof => proof,
            _ => {
                pins.adopt(&tag, r, &agreed_proof)?;
                lichen_babe::statement::proof_from_bytes(&agreed_proof)
                    .context("the proof its witnesses keep does not decode")?
            }
        };
        // Signed only as its witnesses keep it, and as it verifies.
        ensure!(
            dispute::asserted_digits(&proof) == digits,
            "the assertion its witnesses keep signs other digits than its proof's: it signs none"
        );
        ensure!(
            kind.verify(&journal, &proof) || self.false_proofs(),
            "the proof its witnesses keep does not verify for this contract: it signs none"
        );
        self.store().begin_signing(id, "assert")?;
        let tx = pins.answer(&tag, r, || o.assert(hub.keys(), &proof))?;
        post(tx).await?;
        Ok(Played::Posted("assert"))
    }

    /// What the hub's witnesses agree it signs in `slot` of contract `id`,
    /// `ours` unless they hold another: none, the operator told, where
    /// they keep it never to be signed. An error, told too, where they
    /// cannot agree: nothing is signed then.
    async fn authorized(
        &self,
        id: &[u8; 32],
        slot: &'static str,
        ours: &Decision,
    ) -> Result<Option<Decision>> {
        let agreed = async {
            self.witnesses()?
                .authorize(&self.data, id, slot, ours)
                .await
        };
        match agreed.await {
            Ok(Decision::Burnt) => {
                self.burnt(id, slot);
                Ok(None)
            }
            Ok(agreed) => Ok(Some(agreed)),
            Err(e) => {
                self.unwitnessed(id, slot, &e);
                Err(e)
            }
        }
    }

    fn burnt(&self, id: &[u8; 32], slot: &str) {
        if self.once(id, "burnt") {
            self.alert(&format!(
                "contract {}: the hub's witnesses keep its {slot} never to be signed: it may \
                 have signed it with what it no longer knows. It signs none: her timeout pays \
                 her what she claims, and the hub's reserve once a response is in a block.",
                crate::hex_id(id)
            ));
        }
    }

    /// Told once a contract, slot and cause: a witness unreachable told
    /// hides no disagreement found later.
    fn unwitnessed(&self, id: &[u8; 32], name: &str, e: &anyhow::Error) {
        let disagreed = super::witness::disagreed(e);
        let what = match (name == slot::RESPOND, disagreed) {
            (true, true) => "respond disagreed",
            (true, false) => "respond unwitnessed",
            (false, true) => "assert disagreed",
            (false, false) => "assert unwitnessed",
        };
        if self.once(id, what) {
            self.alert(&format!(
                "contract {}: the hub signs no {name} until its witnesses agree on it: {e:#}. \
                 Unanswered by its deadline, her timeout pays her what she claims.",
                crate::hex_id(id)
            ));
        }
    }

    /// Whether answer `name` of opening `id`, of the request `request`, is
    /// not to be signed, nothing pinned for it (in `pin`): what its
    /// witnesses keep pinned again where they keep any, then signed as
    /// any; else as [`Self::pin_lost`] tells, its witnesses then told to
    /// keep it never to be signed, against a hub restored older than its
    /// mark.
    #[allow(clippy::too_many_arguments)]
    async fn unpinned(
        &self,
        id: &[u8; 32],
        name: &'static str,
        pin: &[u8; 32],
        request: &Transaction,
        coin: OutPoint,
        lone: bool,
    ) -> Result<bool> {
        let witnesses = self.witnesses()?;
        let kept = match witnesses.recover(&self.data, id, name).await {
            Ok(kept) => kept,
            Err(e) => {
                self.unwitnessed(id, name, &e);
                return Err(e);
            }
        };
        let pins = Responses::open(&self.data)?;
        match kept {
            Some(Decision::Burnt) => {
                self.burnt(id, name);
                return Ok(true);
            }
            Some(Decision::Respond { evidence, .. }) if name == slot::RESPOND => {
                pins.adopt(pin, request, &evidence)?;
                return Ok(false);
            }
            Some(Decision::Assert { proof, .. }) if name == slot::ASSERT => {
                pins.adopt(pin, request, &proof)?;
                return Ok(false);
            }
            Some(_) => bail!("the witnesses keep another kind of decision for its {name}"),
            None => {}
        }
        if !self.pin_lost(id, name, coin, lone).await? {
            return Ok(false);
        }
        if witnesses.count() > 0 {
            if let Err(e) = witnesses
                .authorize(&self.data, id, name, &Decision::Burnt)
                .await
            {
                self.unwitnessed(id, name, &e);
            }
        }
        Ok(true)
    }

    /// Whether the hub signed answer `name` of opening `id`, or was about
    /// to: asked while the response pins hold nothing it answered on, as
    /// once their rows are lost, or the database restored older. Another
    /// answer, decided
    /// anew, could differ from the one signed with the same one-time key,
    /// which gives her the hub's outputs: then none is signed, her timeout
    /// pays her what she claims, and the operator is told, once a run.
    ///
    /// Told by the openings' signing marks, which keep each answer before it
    /// is signed ([`Store::begin_signing`]). Where they keep none (the
    /// database restored older, marks and pins together), by the mempool while
    /// `lone`: nothing but this answer can spend `coin` yet, her timeout
    /// being some blocks away, so a transaction spending it there is one
    /// the hub signed. Kept then, to stand past her timeout's first block,
    /// from which the mempool tells nothing.
    async fn pin_lost(
        &self,
        id: &[u8; 32],
        name: &'static str,
        coin: OutPoint,
        lone: bool,
    ) -> Result<bool> {
        let mut lost = self.store().began_signing(id, name)?;
        if !lost && lone && !self.unspent(coin, true).await? && self.unspent(coin, false).await? {
            self.store().begin_signing(id, name)?;
            lost = true;
        }
        if lost && self.once(id, "pin lost") {
            self.alert(&format!(
                "contract {}: the hub signed its {name} with a one-time key, or was about \
                 to, and its response pins no longer hold what it answered on, as when \
                 their rows are lost. It signs no other: her timeout pays her what she \
                 claims, and the hub's reserve once a response is in a block. Restore \
                 hub.sqlite as recent as the hub's last answer.",
                crate::hex_id(id)
            ));
        }
        Ok(lost)
    }

    /// Whether this hub asserts proofs of another statement (tests).
    fn false_proofs(&self) -> bool {
        #[cfg(feature = "faults")]
        return self
            .watch
            .false_proofs
            .load(std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(feature = "faults"))]
        false
    }

    /// The proof of the hub's statement for its assertion, pinned: once its
    /// response is deep enough, its disclosure too (else what it played
    /// instead), its input frozen, and its prover made it (the mock
    /// authority's at once), by the deadline her contest, in a block at
    /// `c_at`, gives.
    #[allow(clippy::too_many_arguments)]
    async fn prove(
        &self,
        id: &[u8; 32],
        o: &HubOpening,
        r: &Transaction,
        r_at: u32,
        (x, x_at): (&Transaction, u32),
        c_at: u32,
        tip: u32,
        hub: &Hub,
    ) -> Result<std::result::Result<ark_groth16::Proof<ark_bn254::Bn254>, Played>> {
        let parts = o.base.parts();
        let depth = parts.chain.work_depth;
        let prover = self.prover.as_ref().filter(|_| !o.mock);
        let deadline = assert_deadline(o, c_at);
        let program = parts.recipe.program;
        let commit = |release: u32, cycles: u64, frozen: bool, proven: bool| {
            let Some(prover) = prover else { return };
            let fits = prover.commit(id, program, deadline, release, cycles, frozen, proven, tip);
            if proven {
                return;
            }
            if !fits && self.once(id, "late") {
                self.alert(&format!(
                    "contract {}: its proof may not be made before its assertion's deadline, \
                     block {deadline} (now {tip}): her timeout would pay her what she claims",
                    crate::hex_id(id)
                ));
            }
            if tip.saturating_add(NEAR) >= deadline && self.once(id, "near") {
                self.alert(&format!(
                    "contract {}: its assertion's deadline, block {deadline}, is near (now \
                     {tip}), and its proof not made",
                    crate::hex_id(id)
                ));
            }
        };
        let frozen = prover.and_then(|p| p.frozen(id));
        let bytes = match frozen {
            Some(bytes) => bytes,
            None => {
                let pinned = self.responded_on(id).await?;
                if pinned.is_none() && self.once(id, "pin lost") {
                    // Its response is in a block: no answer of another
                    // kept tells of this, and nothing else alerts.
                    self.alert(&format!(
                        "contract {}: the hub responded, and its response pins no longer hold \
                         the evidence it responded on, as when their rows are lost. It asserts \
                         nothing without it: her timeout pays her what she claims and the \
                         hub's reserve. Restore hub.sqlite as recent as the hub's last \
                         response.",
                        crate::hex_id(id)
                    ));
                }
                let pinned = pinned.context("responded on no pinned evidence")?;
                let release = x_at.saturating_add(depth);
                // Unread, all its bytes as others': it is not proven anyway.
                let cycles = match pinned_evidence(o, &pinned) {
                    Ok(evidence) => estimated_cycles(o, &evidence, release),
                    Err(_) => estimated_bytes_cycles(o, pinned.len(), 0, release),
                };
                commit(release, cycles, false, false);
                if tip < release {
                    return Ok(Err(Played::Idle));
                }
                let (input, receipt) = match self
                    .input(id, hub, o, r, r_at, x, x_at, c_at, tip, &pinned)
                    .await?
                {
                    Ok(input) => input,
                    Err(played) => return Ok(Err(played)),
                };
                let bytes = input.to_bytes();
                match prover {
                    Some(prover) => prover.freeze(id, &bytes, receipt.as_deref())?,
                    None => bytes,
                }
            }
        };
        let journal = graph::journal(&o.base);
        let kind = graph::kind(&o.base, o.mock);
        let proof = match prover {
            None => lichen_babe::statement::mock_prove(&journal),
            Some(prover) => {
                let seal = prover.proof(id, &program)?;
                let proof = match seal {
                    Some(seal) => lichen_babe::risc0::proof_from_seal(&seal)?,
                    None => {
                        commit(
                            tip,
                            prover::input_cycles(&bytes, o.base.parts().graph.id),
                            true,
                            false,
                        );
                        return Ok(Err(Played::Idle));
                    }
                };
                if !kind.verify(&journal, &proof) {
                    prover.reject(id, "it does not verify for this contract")?;
                    return Ok(Err(Played::Idle));
                }
                commit(
                    tip,
                    prover::input_cycles(&bytes, o.base.parts().graph.id),
                    true,
                    true,
                );
                proof
            }
        };
        let proof = match self.false_proofs() {
            true => lichen_babe::statement::mock_prove(b"another statement"),
            false => proof,
        };
        let tag = tagged(id, b"assert");
        let pinned = Responses::open(&self.data)?
            .pin_proof(&tag, r, &lichen_babe::statement::proof_to_bytes(&proof))?
            .context("an assertion signed before its proof was pinned")?;
        let proof = lichen_babe::statement::proof_from_bytes(&pinned)
            .context("the pinned proof does not decode")?;
        Ok(Ok(proof))
    }

    /// The statement's input for the hub's assertion on `pinned` evidence,
    /// checked: once its disclosure, if the evidence needs one, is deep
    /// enough (else what it played instead).
    #[allow(clippy::too_many_arguments)]
    async fn input(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        r: &Transaction,
        r_at: u32,
        x: &Transaction,
        x_at: u32,
        c_at: u32,
        tip: u32,
        pinned: &[u8],
    ) -> Result<std::result::Result<(licash_hp::HubInput, Option<std::path::PathBuf>), Played>>
    {
        let depth = o.base.parts().chain.work_depth;
        let slot = OutPoint {
            txid: r.compute_txid(),
            vout: SLOT,
        };
        let (p_at, p) = self
            .spend(slot, &r.output[slot.vout as usize], r_at, tip)
            .await?
            .context("responded with no publication")?;
        let evidence = pinned_evidence(o, pinned)?;
        let disclosures = recovery::disclosures(&evidence).map_err(|e| anyhow!("{e}"))?;
        let disclosure = if disclosures == Disclosures::empty() {
            None
        } else {
            let slot = OutPoint {
                txid: x.compute_txid(),
                vout: SLOT,
            };
            match self
                .spend(slot, &x.output[SLOT as usize], x_at, tip)
                .await?
            {
                None => {
                    let deadline = contested_disclose_deadline(o, c_at);
                    let by = (c_at, deadline, assert_stake(o, r, x)?);
                    let posted = self.disclose(id, hub, o, &disclosures, by, tip).await?;
                    return Ok(Err(if posted {
                        Played::Posted("disclose")
                    } else {
                        Played::Idle
                    }));
                }
                Some((d_at, _)) if tip < d_at.saturating_add(depth) => {
                    return Ok(Err(Played::Idle))
                }
                Some((d_at, d)) => Some((self.block_at(d_at).await?, d.compute_txid(), d_at)),
            }
        };
        let (r_block, p_block, x_block) = (
            self.block_at(r_at).await?,
            self.block_at(p_at).await?,
            self.block_at(x_at).await?,
        );
        let keys = o.holder.request_keys()?;
        let disclosure_block = disclosure.as_ref().map(|(block, txid, _)| (block, txid));
        if recovery::chained(o.base.parts().graph.id) {
            let last = [r_at, p_at, x_at]
                .into_iter()
                .chain(disclosure.as_ref().map(|(_, _, at)| *at))
                .max()
                .expect("three blocks");
            return self
                .chained_input(
                    o,
                    keys,
                    evidence,
                    (&r_block, &r.compute_txid()),
                    (&p_block, &p.compute_txid()),
                    (&x_block, &x.compute_txid()),
                    disclosure_block,
                    (last, tip),
                )
                .await;
        }
        let headers = self.headers(o, tip).await?;
        let exit = dispute::exit(
            licash_hp::carrier(&o.base),
            headers,
            &o.funding,
            (&r_block, &r.compute_txid()),
            (&p_block, &p.compute_txid()),
            (&x_block, &x.compute_txid()),
            disclosure_block,
        )?;
        // The items of her filing it proves invalid, which it finds itself.
        let invalid =
            licash_hp::flagged(&o.base, &keys, &exit, &evidence).map_err(|e| anyhow!("{e}"))?;
        let input = licash_hp::HubInput {
            base: o.base.clone(),
            exit,
            evidence,
            keys,
            invalid,
            chain: None,
        };
        match licash_hp::check(&input) {
            Ok(j) if j == graph::journal(&o.base) => Ok(Ok((input, None))),
            Ok(_) => bail!("the statement's journal is not the contract's"),
            Err(e) => bail!("the hub's statement does not hold: {e}"),
        }
    }

    /// The statement's input of a contract that reads its exit on the hub's
    /// header chain: the receipt of the chain through the exit's last block
    /// (`last`; the hub's prover makes it, if it has not, and the dispute
    /// waits), the few headers after that carry the work the contract asks on
    /// it, and openings of the blocks the exit and the claim's judgment read.
    /// With the file of the receipt, which the proof verifies.
    #[allow(clippy::too_many_arguments)]
    async fn chained_input(
        &self,
        o: &HubOpening,
        keys: licash_hp::RequestKeys,
        evidence: Vec<Evidence>,
        request: (&Block, &bitcoin::Txid),
        publish: (&Block, &bitcoin::Txid),
        respond: (&Block, &bitcoin::Txid),
        disclosure: Option<(&Block, &bitcoin::Txid)>,
        (last, tip): (u32, u32),
    ) -> Result<std::result::Result<(licash_hp::HubInput, Option<std::path::PathBuf>), Played>>
    {
        let chain = self
            .chain
            .as_ref()
            .context("a chained contract, and the hub keeps no header chain")?;
        let depth = o.base.parts().chain.work_depth;
        // the blocks the work on top of the last one comes from, then
        chain
            .follow(&self.source, tip.min(last.saturating_add(depth)))
            .await?;
        chain.demand(last);
        if o.mock {
            chain.mock_through(last)?;
        }
        let Some(receipt) = chain.receipt_through(last) else {
            // the hub's prover makes it, with no dispute to prove before
            return Ok(Err(Played::Idle));
        };
        let contract = licash_hp::contract(&o.base);
        let tail = chain.tail(&receipt, last, contract.work);
        let exit = dispute::exit(
            licash_hp::carrier(&o.base),
            tail,
            &o.funding,
            request,
            publish,
            respond,
            disclosure,
        )?;
        let program = licash_hp::Program {
            id: chain.program(),
            verify: &|_, _| {},
        };
        let proof = chain
            .with(|lineage| {
                let proven = licash_hp::headers::Proven {
                    lineage,
                    journal: &receipt.journal,
                    tip: &receipt.tip,
                };
                licash_hp::open_chain(proven, &o.base, &keys, &exit, &evidence, &program)
            })
            .context("the hub's header chain is gone")?
            .map_err(|e| anyhow!("the chain's openings: {e}"))?;
        let chained = licash_hp::Chained {
            proof: &proof,
            program: &program,
        };
        // The items of her filing it proves invalid, which it finds itself.
        let invalid = licash_hp::flagged_on(&o.base, &keys, &exit, &evidence, chained)
            .map_err(|e| anyhow!("{e}"))?;
        let input = licash_hp::HubInput {
            base: o.base.clone(),
            exit,
            evidence,
            keys,
            invalid,
            chain: Some(proof),
        };
        match licash_hp::check_on(&input, &program) {
            Ok(j) if j == graph::journal(&o.base) => Ok(Ok((input, Some(receipt.file)))),
            Ok(_) => bail!("the statement's journal is not the contract's"),
            Err(e) => bail!("the hub's statement does not hold: {e}"),
        }
    }

    /// Her response left uncontested past `respond_timeout`'s wait, or its
    /// assertion unchallenged past `success`'s: that terminal, `name`, with
    /// a fee coin, paying her `b′` and the hub its reserve, `parent_at` the
    /// block of the link it waits on. She may post it too, but need not:
    /// with no claim published (the slot reclaimed), she has no fee coin of
    /// her own for it.
    async fn settle(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        name: &'static str,
        parent_at: u32,
        tip: u32,
    ) -> Result<Played> {
        let terminal = presign(&o.set, name)?;
        let wait = waits(o, name)?;
        if tip.saturating_add(1) < parent_at.saturating_add(wait) {
            return Ok(Played::Idle);
        }
        let prevout = terminal.prevout.clone();
        let tx = o.finish(name, vec![])?;
        let tx = (self.with_fee(id, hub, name, tx, prevout, None, &CoinTree::Fee)).await?;
        if self.post(&tx).await && self.once(id, name) {
            return Ok(Played::Posted(name));
        }
        Ok(Played::Idle)
    }

    /// The proof the hub asserted in opening `id`'s dispute: the one
    /// pinned before it signed, or, for an assertion signed before proofs
    /// were pinned (of a graph before 16, then), the one its signed
    /// `assert` carries. None before it asserts.
    fn own_proof(
        &self,
        id: &[u8; 32],
        o: &HubOpening,
    ) -> Result<Option<ark_groth16::Proof<ark_bn254::Bn254>>> {
        let pins = Responses::open(&self.data)?;
        let tag = tagged(id, b"assert");
        let pinned = pins.evidence(&tag)?;
        if let Some(proof) = pinned.and_then(|p| lichen_babe::statement::proof_from_bytes(&p)) {
            return Ok(Some(proof));
        }
        Ok(pins
            .response(&tag)?
            .and_then(|signed| o.babe.assertion(&signed).ok())
            .and_then(|a| a.proof))
    }

    /// She challenged the assertion: answered with the first kept
    /// instance whose circuit opens on the proof, in a block by `by`'s
    /// deadline, its fee `by`'s stake at most ([`Self::with_fee_by`]).
    #[allow(clippy::too_many_arguments)]
    async fn answer(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        asserted: &Transaction,
        challenge: &Transaction,
        by: (u32, Amount),
        tip: u32,
    ) -> Result<Played> {
        // The proof the hub asserted, pinned before it signed: whatever π2
        // and π3 the block shows, if any. One signed before proofs were
        // pinned carries its own.
        let own = match self.own_proof(id, o) {
            Ok(own) => own,
            Err(e) => {
                tracing::error!(id = %crate::hex_id(id), "the assertion pinned: {e:#}");
                None
            }
        };
        for &i in &o.kept {
            let bytes = match self.store().kept_instance(id, i) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(id = %crate::hex_id(id), i, "a kept instance: {e:#}");
                    continue;
                }
            };
            match o.answer(asserted, own.clone(), challenge, i, &bytes) {
                Ok(Some(tx)) => {
                    let name = format!(
                        "wrongly_challenged_{}",
                        o.kept.iter().position(|n| *n == i).unwrap_or(0)
                    );
                    let prevout = presign(&o.set, &name)?.prevout.clone();
                    let tx = self
                        .with_fee_by(id, hub, &name, tx, prevout, by, tip, &CoinTree::Fee)
                        .await?;
                    self.post(&tx).await;
                    return Ok(Played::Posted("wrongly_challenged"));
                }
                Ok(None) => continue,
                Err(e) => {
                    tracing::error!(id = %crate::hex_id(id), i, "answering with an instance: {e:#}");
                    continue;
                }
            }
        }
        self.note_once(id, "unanswered", "no kept instance answers her challenge");
        Ok(Played::Idle)
    }

    /// The one-input `tx` named `name`, spending `prevout`, with an exact
    /// fee coin of the hub's wallet appended: made once, kept in
    /// the hub's database before it is used, and made again only once
    /// that one is gone ([`Self::gone`]), `by` its deadline and the tip if
    /// it has one. Then one gone before it, its funding in a block or the
    /// mempool after all, is taken in its place before another is funded.
    #[allow(clippy::too_many_arguments)]
    async fn with_fee(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        name: &str,
        tx: Transaction,
        prevout: TxOut,
        by: Option<(u32, u32)>,
        tree: &CoinTree,
    ) -> Result<Transaction> {
        let key = &hub.keys().party.payment;
        let script = tree.script(key)?;
        let cached = self.store().fee_coin(id, name)?;
        let coin = match cached {
            Some(c) if !self.gone(id, name, c.0, by).await => c,
            cached => 'coin: {
                if let Some(gone) = &cached {
                    if let Some(back) = self.standing_extra(id, name, gone).await {
                        tracing::warn!(
                            id = %crate::hex_id(id), gone = %gone.0, back = %back.0,
                            "{name}'s fee coin taken back in place of one gone"
                        );
                        break 'coin self.store().replace_fee_coin(id, name, gone, &back)?;
                    }
                }
                let dummy = TxOut {
                    value: Amount::from_sat(330),
                    script_pubkey: script.clone(),
                };
                let dummy = (OutPoint::null(), dummy);
                let size = dispute::add_fee_of(tx.clone(), prevout.clone(), dummy, key, tree)?
                    .vsize() as u64;
                let rate = self.fee_rate().await;
                let value = rate
                    .fee_vb(size * 2)
                    .context("fee overflow")?
                    .max(Amount::from_sat(330));
                let funded = self.fund_coin(id, name, &script, value).await;
                // Kept at once: a restart pays with this one, not another.
                match (cached, funded) {
                    (None, funded) => self.store().keep_fee_coin(id, name, &funded?)?,
                    (Some(gone), Ok(coin)) => {
                        tracing::warn!(
                            id = %crate::hex_id(id), gone = %gone.0, funded = %coin.0,
                            "{name}'s fee coin funded again in place of one gone"
                        );
                        self.store().replace_fee_coin(id, name, &gone, &coin)?
                    }
                    // None funded (its operator told): posted with the one
                    // it has, which is better than not posted.
                    (Some(gone), Err(_)) => gone,
                }
            }
        };
        dispute::add_fee_of(tx, prevout, coin, key, tree)
    }

    /// A fee coin of `name` kept beside `gone`, its first, that stands: in
    /// a block or the mempool, and spent by neither. One gone before it
    /// whose funding confirmed after all, as a replaced one may.
    async fn standing_extra(
        &self,
        id: &[u8; 32],
        name: &str,
        gone: &(OutPoint, TxOut),
    ) -> Option<(OutPoint, TxOut)> {
        let extra = self.store().extra_coins(id, name).ok()?;
        for coin in extra.into_iter().rev() {
            if coin.0 != gone.0 && self.unspent(coin.0, true).await.unwrap_or(false) {
                return Some(coin);
            }
        }
        None
    }

    /// `tx` named `name`, its slot's input spending `prevout`, its fee coin
    /// added ([`Self::with_fee`]): sealed, none other to be added
    /// ([`HubOpening::seal`]).
    fn sealed(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        name: &str,
        mut tx: Transaction,
        prevout: TxOut,
    ) -> Result<Transaction> {
        // The coin it spends: the first kept, or a larger one since.
        let spent = tx.input.last().context("no fee input")?.previous_output;
        let store = self.store();
        let kept = store.fee_coin(id, name)?.into_iter();
        let (_, coin) = (kept.chain(store.extra_coins(id, name)?))
            .find(|(c, _)| *c == spent)
            .context("no fee coin")?;
        drop(store);
        o.seal(hub.keys(), &mut tx, &[prevout, coin])?;
        Ok(tx)
    }

    /// [`Self::with_fee`], for a terminal to be in a block by `deadline`,
    /// the last tip it confirms in time from: while it is in none, once the
    /// rate [`deadline::rate`] gives for the blocks left pays more than its
    /// coin, a larger coin is funded, `stake` at most, what missing the
    /// deadline costs the hub, and taken in place of the first once it is
    /// in a block (a replacement spends no other unconfirmed coin,
    /// BIP125). Kept beside the first, which stays valid. A larger coin
    /// its wallet does not fund, or one of those kept whose state its node
    /// does not tell, takes nothing from the terminal: it pays with the
    /// best coin it has.
    #[allow(clippy::too_many_arguments)]
    async fn with_fee_by(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        name: &str,
        tx: Transaction,
        prevout: TxOut,
        (deadline, stake): (u32, Amount),
        tip: u32,
        tree: &CoinTree,
    ) -> Result<Transaction> {
        let by = Some((deadline, tip));
        let first = self
            .with_fee(id, hub, name, tx.clone(), prevout.clone(), by, tree)
            .await?;
        let first_coin = self.store().fee_coin(id, name)?.context("no fee coin")?;
        let mut extra = Vec::new();
        let kept = self.store().extra_coins(id, name)?;
        for c in kept {
            // In a block and unspent, else in the mempool, unspent. Not
            // told which: as one in the mempool, neither spent yet nor
            // funded again.
            let waits = |e: anyhow::Error| {
                self.unknown_coin(id, name, &format!("{e:#}"), by);
                Some(false)
            };
            let state = match self.unspent(c.0, false).await {
                Ok(true) => Some(true),
                Ok(false) => match self.unspent(c.0, true).await {
                    Ok(unspent) => unspent.then_some(false),
                    Err(e) => waits(e),
                },
                Err(e) => waits(e),
            };
            // Neither: spent, or gone, its funding then abandoned.
            if state.is_none() {
                self.gone(id, name, c.0, by).await;
            }
            extra.push((c, state));
        }
        let left = deadline.saturating_sub(tip);
        let estimate = self
            .source
            .fee_rate(deadline::target(left))
            .await
            .ok()
            .flatten();
        let floor = FeeRate::from_sat_per_vb_u32(if estimate.is_some() { 1 } else { 2 });
        let rate = deadline::rate(estimate, floor, left);
        let needed = rate.fee_vb(first.vsize() as u64).context("fee overflow")?;
        let (coin, fund) = terminal_coin(first_coin, &extra, needed, stake);
        if let Some(value) = fund {
            let key = &hub.keys().party.payment;
            // Not funded, or funded and not kept: posted with the coin it
            // has, which is better than not posted.
            let funded = async {
                let more = self.fund_coin(id, name, &tree.script(key)?, value).await?;
                self.store().keep_extra_coin(id, name, &more)
            };
            match funded.await {
                Ok(_) => tracing::warn!(
                    id = %crate::hex_id(id), %rate, %value, deadline, tip,
                    "{name} pays too little to be in a block in time: a larger fee coin funded"
                ),
                Err(e) => tracing::warn!(
                    id = %crate::hex_id(id), %rate, %value, deadline, tip,
                    "{name} pays too little to be in a block in time, and no larger fee \
                     coin is funded: {e:#}"
                ),
            }
        }
        dispute::add_fee_of(tx, prevout, coin, &hub.keys().party.payment, tree)
    }

    /// A coin of `value` paying `script`, from the hub's wallet, for a
    /// transaction of the contract `id`. A wallet that funds none (out of
    /// coins, locked, not loaded) is told its operator, once a contract:
    /// its links are posted at their presigned fee and no more, and its
    /// terminals, which pay no fee of their own, are not posted at all.
    ///
    /// Each is funded under a tag of its own, the contract's, `name`'s and
    /// how many coins of `name` are kept, the wallet's comment of its
    /// funding: one funded and not kept (the hub stopped between the two,
    /// or its wallet's answer lost) is found again by it, not funded twice.
    async fn fund_coin(
        &self,
        id: &[u8; 32],
        name: &str,
        script: &ScriptBuf,
        value: Amount,
    ) -> Result<(OutPoint, TxOut)> {
        let tag = format!(
            "licash fee coin {} {name} {}",
            crate::hex_id(id),
            self.store().fee_coins_kept(id, name)?
        );
        let funded = match self.tagged(&tag).await {
            // Found, read: taken. Found and not read: nothing funded this
            // round, as another would be a coin too many.
            Ok(Some(txid)) => self.coin_of(&txid, script).await.inspect(|coin| {
                tracing::warn!(id = %crate::hex_id(id), coin = %coin.0, "{name}'s fee coin funded before and not kept: taken");
            }),
            Ok(None) => self.funded_coin(script, value, &tag).await,
            // Not listed (a login without `listtransactions`): funded, as
            // a transaction not posted in time costs more than a coin too
            // many, its operator told.
            Err(e) => {
                tracing::warn!(id = %crate::hex_id(id), "{name}'s fee coins funded before not listed: {e:#}");
                if self.once(id, "fee coins unlisted") {
                    self.alert(&format!(
                        "contract {}: the hub's wallet does not list its transactions ({e:#}): \
                         a hub stopped between funding a fee coin and keeping it funds another, \
                         lost to it. Allow `listtransactions` to its Core login.",
                        crate::hex_id(id)
                    ));
                }
                self.funded_coin(script, value, &tag).await
            }
        };
        if let Err(e) = &funded {
            if self.once(id, "unfunded") {
                self.alert(&format!(
                    "contract {}: the hub's wallet funds no fee coin of {value} ({e:#}). \
                     Without one its response and assertion are posted at their presigned \
                     fee, which may not be in a block in time, and its payouts are not \
                     posted at all.",
                    crate::hex_id(id)
                ));
            }
        }
        funded
    }

    /// The txid of the transaction the hub's wallet funded a fee coin
    /// with under `tag` ([`Self::fund_coin`]), if it is among its last.
    async fn tagged(&self, tag: &str) -> Result<Option<String>> {
        let listed: Vec<serde_json::Value> = self
            .wallet
            .rpc("listtransactions", serde_json::json!(["*", 1000]))
            .await?;
        Ok((listed.iter())
            .rev()
            .filter(|t| t["comment"].as_str() == Some(tag))
            .find_map(|t| t["txid"].as_str())
            .map(str::to_owned))
    }

    async fn funded_coin(
        &self,
        script: &ScriptBuf,
        value: Amount,
        tag: &str,
    ) -> Result<(OutPoint, TxOut)> {
        #[cfg(feature = "faults")]
        if self
            .watch
            .no_coins
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            bail!("no coins, for a test");
        }
        let network = self.source.network().await?;
        let address = bitcoin::Address::from_script(script, network)?;
        let txid: String = self
            .wallet
            .rpc(
                "sendtoaddress",
                serde_json::json!([address.to_string(), value.to_btc(), tag]),
            )
            .await
            .context("fund a fee coin")?;
        #[cfg(feature = "faults")]
        if self
            .watch
            .lose_coin
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            bail!("a fee coin funded and lost, for a test");
        }
        self.coin_of(&txid, script).await
    }

    /// The coin paying `script` of the hub's wallet's transaction `txid`,
    /// handed to the chain it posts to.
    async fn coin_of(&self, txid: &str, script: &ScriptBuf) -> Result<(OutPoint, TxOut)> {
        let funded: serde_json::Value = self
            .wallet
            .rpc("gettransaction", serde_json::json!([txid, false, true]))
            .await?;
        let raw: Transaction = bitcoin::consensus::encode::deserialize_hex(
            funded["hex"].as_str().context("no fee coin transaction")?,
        )?;
        let vout = raw
            .output
            .iter()
            .position(|o| &o.script_pubkey == script)
            .context("no fee coin output")?;
        // Handed to the chain the hub posts to as well, which may be
        // another node than its wallet's: else what spends the coin is
        // refused there. Once more each round it waits ([`Self::funding`]).
        if let Err(e) = self.source.broadcast(&raw).await {
            tracing::debug!(%txid, "a fee coin's funding not taken by the chain: {e:#}");
        }
        Ok((
            OutPoint {
                txid: raw.compute_txid(),
                vout: vout as u32,
            },
            raw.output[vout].clone(),
        ))
    }

    /// Post link `name` of contract `id`, presigned at its floor, spending
    /// `prevout`, to be in a block by `deadline`, the last tip it confirms
    /// in time from, its window open since `opened`: with its fee child
    /// ([`dispute::link_child`]) while the rate [`deadline::rate`] gives
    /// for the blocks left is above its floor, made again at a higher one,
    /// in place of the one before, as the deadline nears. The pair pays
    /// `stake` at most, what missing the deadline costs the hub: past it,
    /// the operator is told, as when the link is in no block halfway
    /// through its window. The child's fee coins come from the hub's
    /// wallet, each kept before it is used; the child is kept before it is
    /// broadcast. A coin its wallet does not fund, or one whose state its
    /// node does not tell, takes nothing from the link: it is posted with
    /// the child its other coins make, or the one made before, or alone at
    /// its presigned fee. Whether the node took the link.
    #[allow(clippy::too_many_arguments)]
    async fn post_link(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        name: &'static str,
        link: &Transaction,
        prevout: &TxOut,
        (opened, deadline): (u32, u32),
        stake: Amount,
        tip: u32,
    ) -> Result<bool> {
        if tip >= opened.saturating_add(deadline.saturating_sub(opened) / 2) && self.once(id, name)
        {
            self.alert(&format!(
                "contract {}: its {name} is in no block halfway to its deadline, block \
                 {deadline} (now {tip}): its fee is raised as the deadline nears",
                crate::hex_id(id)
            ));
        }
        let left = deadline.saturating_sub(tip);
        let estimate = self
            .source
            .fee_rate(deadline::target(left))
            .await
            .ok()
            .flatten();
        // Without an estimate, as `fee_rate`'s: 2 sat/vB.
        let floor = FeeRate::from_sat_per_vb_u32(if estimate.is_some() { 1 } else { 2 });
        let mut rate = deadline::rate(estimate, floor, left);
        let paid: Amount = link.output.iter().map(|o| o.value).sum();
        let link_fee = prevout
            .value
            .checked_sub(paid)
            .context("a link paying out more")?;
        let stored = self.store().child(id, name)?;
        let mut kept = Vec::new();
        let mut gone = HashSet::new();
        let coins = self.store().extra_coins(id, name)?;
        for coin in coins {
            if self.gone(id, name, coin.0, Some((deadline, tip))).await {
                gone.insert(coin.0);
            } else {
                kept.push(coin);
            }
        }
        // One spending a coin gone never relays: made anew, as if none was
        // (none is in the mempool for another to replace).
        let old = stored
            .clone()
            .filter(|old| !old.input.iter().any(|i| gone.contains(&i.previous_output)));
        let one = FeeRate::from_sat_per_vb_u32(1);
        if rate <= one && old.is_none() {
            return Ok(self.post(link).await);
        }
        // The coins a child may spend: any while none was made; then those
        // the last one spent and those in a block (a replacement spends no
        // other unconfirmed coin, BIP125).
        let mut usable = Vec::new();
        let waiting = kept.len();
        for coin in kept {
            let spent_before = old
                .as_ref()
                .is_some_and(|old| old.input.iter().any(|i| i.previous_output == coin.0));
            // Not told whether it is in a block: as one that waits for a
            // block, neither spent by a replacement nor funded again.
            let confirmed = || async {
                let confirmed = self.unspent(coin.0, false).await;
                confirmed.unwrap_or_else(|e| {
                    self.unknown_coin(id, name, &format!("{e:#}"), Some((deadline, tip)));
                    false
                })
            };
            if old.is_none() || spent_before || confirmed().await {
                usable.push(coin);
            }
        }
        let link_vb = link.vsize() as u64;
        let pair = |inputs: usize, rate: FeeRate| {
            let fee = rate
                .fee_vb(link_vb + child_vb(inputs))
                .unwrap_or(Amount::MAX);
            fee.checked_sub(link_fee).unwrap_or(Amount::ZERO)
        };
        // At most the stake, the link's fee among it.
        let inputs = usable.len().max(1) + 1;
        let most = stake.to_sat().saturating_add(link_fee.to_sat()) * 1_000
            / ((link_vb + child_vb(inputs)) * 4).max(1);
        let most = FeeRate::from_sat_per_kwu(most);
        if rate > most {
            let capped = match name {
                "respond" => "respond capped",
                _ => "assert capped",
            };
            if self.once(id, capped) {
                self.alert(&format!(
                    "contract {}: its {name} would pay {rate} to be in a block by block \
                     {deadline} (now {tip}), more than the {stake} at stake: it pays {most}",
                    crate::hex_id(id)
                ));
            }
            rate = most;
        }
        let have: Amount = usable.iter().map(|c| c.1.value).sum();
        // One coin more, for twice the rate too, the stake at most: unless
        // one funded already waits for a block.
        let waiting = waiting > usable.len();
        if have < pair(inputs, rate) && !waiting {
            let value = pair(
                inputs + 1,
                FeeRate::from_sat_per_kwu(rate.to_sat_per_kwu() * 2),
            )
            .checked_sub(have)
            .unwrap_or(Amount::ZERO)
            .clamp(Amount::from_sat(1_000), stake.max(Amount::from_sat(1_000)));
            let key = &hub.keys().party.payment;
            // Not funded, or funded and not kept, so not used: the link
            // goes with what it has.
            let funded = async {
                let coin = self
                    .fund_coin(id, name, &dispute::fee_script(key)?, value)
                    .await?;
                self.store().keep_extra_coin(id, name, &coin)?;
                anyhow::Ok(coin)
            };
            match funded.await {
                Ok(coin) if old.is_none() => usable.push(coin),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    id = %crate::hex_id(id), %rate, %value, deadline, tip,
                    "{name}'s fee child is short of a coin, and none is funded: {e:#}"
                ),
            }
        }
        let change = match &stored {
            Some(old) => old.output[0].script_pubkey.clone(),
            None => self.payout_script().await?,
        };
        let key = &hub.keys().party.payment;
        let sign = |tx: &mut Transaction, prevouts: &[TxOut]| {
            (0..tx.input.len()).try_for_each(|i| dispute::sign_fee_input(key, tx, i, prevouts))
        };
        let build = |rate| dispute::link_child(link, link_fee, &usable, change.clone(), rate, sign);
        let child = match (build(rate), &old) {
            (Ok(child), None) => Some(child),
            (Ok(child), Some(old)) => {
                let coins = self.store().extra_coins(id, name)?;
                let fee = |tx: &Transaction| child_fee(tx, &link.output, &coins);
                let (new, before) = (fee(&child), fee(old));
                if new <= before {
                    None
                } else if deadline::replaces(new, child.vsize() as u64, before) {
                    Some(child)
                } else {
                    // The least that replaces it, as a rate of the pair.
                    let least = before.to_sat() + child.vsize() as u64 + link_fee.to_sat();
                    let weight = (link_vb + child.vsize() as u64) * 4;
                    let least = FeeRate::from_sat_per_kwu((least * 1_000).div_ceil(weight));
                    build(least)
                        .ok()
                        .filter(|c| deadline::replaces(fee(c), c.vsize() as u64, before))
                }
            }
            // Its coins short until the one funded is in a block.
            (Err(e), _) => {
                tracing::debug!(id = %crate::hex_id(id), "{name}'s child waits: {e:#}");
                None
            }
        };
        let child = match child {
            Some(child) => {
                self.store().keep_child(id, name, &child)?;
                tracing::info!(
                    id = %crate::hex_id(id), txid = %child.compute_txid(), %rate,
                    "{name}'s fee child made"
                );
                child
            }
            None => match old {
                Some(old) => old,
                None => return Ok(self.post(link).await),
            },
        };
        match self.source.broadcast_package(&[link.clone(), child]).await {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::debug!(txid = %link.compute_txid(), "not broadcast yet: {e:#}");
                Ok(false)
            }
        }
    }

    /// A payout ended the exit: the hub's outputs of it, swept to its
    /// wallet once their waits are over.
    #[allow(clippy::too_many_arguments)]
    async fn collect(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        r: &Transaction,
        response: Option<&Transaction>,
        (paid_at, payout): (u32, &Transaction),
        tip: u32,
    ) -> Result<Played> {
        let spent = payout
            .input
            .first()
            .context("an empty payout")?
            .previous_output;
        let terminal = o
            .set
            .iter()
            .find(|p| {
                p.tx.input
                    .first()
                    .is_some_and(|i| i.previous_output == spent)
                    && p.tx.output == payout.output
            })
            .map(|p| p.name.clone())
            .context("the exit went to an unknown transaction")?;
        // The words signed, as the chain shows them: their bits select the
        // outputs.
        let (word, wire, value_key, signer) = match terminal.as_str() {
            "request_timeout" | "contest_timeout" | "failure" => {
                let (b, _) = HubProves::read_request(&link_args(r))?;
                o.requested_b(r)?;
                let (word, _) = HubProves::requested_word(r)?;
                (word, HubProves::b_wire(&b), &o.holder.b_key, Role::User)
            }
            n if n == "success"
                || n == "respond_timeout"
                || n.starts_with("wrongly_challenged_") =>
            {
                let (b, wire) = HubProves::responded_word(response.context("no response")?)?;
                (b, wire, &o.hub.b_key, Role::Hub)
            }
            _ => bail!("not a payout: {terminal}"),
        };
        let owned = o
            .babe
            .core()
            .owned(payout, value_key, signer, word, Role::Hub)?;
        if owned.is_empty() {
            self.note_once(id, "nothing", "nothing of the payout is the hub's");
            self.end_if_deep(id, hub, o, paid_at, tip).await?;
            return Ok(Played::Idle);
        }
        // Swept, in a block: ended once the payout is deep. The sweep pays
        // the hub's wallet, whose node posts it again should a
        // reorganization drop it.
        let mut swept = true;
        for out in &owned {
            swept &= !self.unspent(out.op, false).await?;
        }
        if swept {
            self.end_if_deep(id, hub, o, paid_at, tip).await?;
            return Ok(Played::Idle);
        }
        let to = self.payout_script().await?;
        let rate = self.fee_rate().await;
        let sweep = dispute::sweep(
            &o.babe,
            &hub.keys().party.payment,
            Payout {
                transaction: payout,
                value_key,
                signer,
                word,
                wire: &wire,
            },
            Role::Hub,
            to,
            rate,
        )?;
        // Its inputs' waits may not be over: the node says so, and the next
        // poll tries again. Swept once, the outputs are spent and this
        // payout is never looked at again.
        if self.post(&sweep).await {
            return Ok(Played::Posted("sweep"));
        }
        Ok(Played::Idle)
    }

    /// Signed opening `id`, `hub` and `o`, whose F is in no block at `tip`
    /// (its `contract` output neither unspent nor spent in one). Given up,
    /// its coins unlocked, once a coin F spends is spent in a block by
    /// another transaction [`ENDED_DEPTH`] deep (her funding depth, if
    /// deeper): F can never confirm then. Short of it, F is made so
    /// [`UNFUNDED_FOR`] blocks after it was first seen in no block, or once
    /// it may no longer fund its contract: one of the hub's coins F spends
    /// is spent back to its wallet, while nothing spends any, in the
    /// mempool either. F confirming first, the contract stands. Its coins
    /// are never unlocked before: F, signed by the hub, binds them until
    /// it may never confirm.
    async fn unfunded(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        contract: OutPoint,
        tip: u32,
    ) -> Result<Played> {
        // Unspent in the blocks, spent in the mempool: F is in a block,
        // her request not yet. Played once it is.
        if self.unspent(contract, false).await? {
            return Ok(Played::Idle);
        }
        let since = self.store().unfunded(id, tip)?;
        let Some(f) = hub.funding() else {
            return Ok(Played::Idle);
        };
        let txid = f.tx.compute_txid();
        let from = o.base.parts().chain.checkpoint.height();
        let deep = o.base.parts().chain.funding_depth.max(ENDED_DEPTH);
        let mut untouched = true;
        for (input, coin) in f.tx.input.iter().zip(f.prevouts) {
            let outpoint = input.previous_output;
            if self.unspent(outpoint, false).await? {
                untouched &= self.unspent(outpoint, true).await?;
                continue;
            }
            untouched = false;
            let Some((at, by)) = self.spend(outpoint, coin, from, tip).await? else {
                continue;
            };
            let by = by.compute_txid();
            if by == txid || tip.saturating_sub(at) + 1 < deep {
                continue;
            }
            // Read again, as cached spends are kept: a reorganization may
            // have taken it out of its block.
            let block = self.block_at(at).await?;
            if !block.txdata.iter().any(|tx| tx.compute_txid() == by) {
                self.forget_spend(outpoint);
                continue;
            }
            return self.give_up_unfunded(id, outpoint, by).await;
        }
        // F whole, as the hub holds it once she signed first, in no
        // mempool of its node: broadcast again, as after a restart of the
        // node or an eviction.
        let whole = f.tx.input.iter().all(|i| !i.witness.is_empty());
        if untouched && whole && !hub.lapsed(tip) {
            match self.source.broadcast(f.tx).await {
                Ok(_) => {
                    tracing::info!(id = %crate::hex_id(id), %txid, "F in no mempool: broadcast again");
                    return Ok(Played::Idle);
                }
                Err(e) => {
                    tracing::debug!(id = %crate::hex_id(id), %txid, "broadcasting F again: {e:#}")
                }
            }
        }
        let due = tip >= since.saturating_add(UNFUNDED_FOR) || hub.lapsed(tip);
        if !due || !untouched {
            return Ok(Played::Idle);
        }
        let Some((outpoint, coin)) = f.hub_coins().into_iter().next() else {
            return Ok(Played::Idle);
        };
        let spent = self.spend_back(outpoint, coin).await?;
        tracing::warn!(
            id = %crate::hex_id(id), %txid, since, coin = %outpoint, spent = %spent,
            "a signed opening's F in no block: a coin of the hub's it spends spent back, so that it never confirms"
        );
        Ok(Played::Idle)
    }

    /// Spend the hub's `coin` at `outpoint` whole back to its wallet, at
    /// the node's rate: the transaction, broadcast.
    async fn spend_back(&self, outpoint: OutPoint, coin: &TxOut) -> Result<bitcoin::Txid> {
        let to = self.payout_script().await?;
        let make = |fee: Amount| -> Result<Transaction> {
            let value = coin
                .value
                .checked_sub(fee)
                .context("a coin smaller than its fee")?;
            ensure!(
                value >= to.minimal_non_dust(),
                "a coin worth no more than its fee"
            );
            Ok(Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: outpoint,
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                }],
                output: vec![TxOut {
                    value,
                    script_pubkey: to.clone(),
                }],
            })
        };
        // Signed once to weigh it, its size the same at any fee.
        let weighed = self.sign(&make(Amount::ZERO)?, &[]).await?;
        let rate = self.fee_rate().await;
        let fee = rate
            .fee_vb(weighed.vsize() as u64)
            .context("a fee too large")?;
        let tx = self.sign(&make(fee)?, &[]).await?;
        ensure!(self.post(&tx).await, "{} not broadcast", tx.compute_txid());
        Ok(tx.compute_txid())
    }

    /// Give up signed opening `id`, its F never to confirm, `outpoint`
    /// spent by `by` deep in a block: its coins unlocked. Not while a step
    /// of its holder's runs: tried again next poll.
    async fn give_up_unfunded(
        &self,
        id: &[u8; 32],
        outpoint: OutPoint,
        by: bitcoin::Txid,
    ) -> Result<Played> {
        let coins = {
            let busy = self.busy();
            if busy.contains(id) {
                return Ok(Played::Idle);
            }
            self.store().give_up_unfunded(id)?
        };
        if let Some(coins) = coins {
            self.unlock_coins(&coins).await;
            tracing::warn!(
                id = %crate::hex_id(id), coin = %outpoint, %by,
                "a signed opening given up, its F never to confirm: its coins unlocked"
            );
        }
        Ok(Played::Idle)
    }

    /// Look for `coin`'s spend again from the start: the one found left
    /// its block.
    fn forget_spend(&self, coin: OutPoint) {
        (self
            .watch
            .spends
            .lock()
            .unwrap_or_else(PoisonError::into_inner))
        .remove(&coin);
    }

    /// A new script of the hub's wallet: what its sweeps pay the hub to,
    /// and its openings unless they pay another wallet
    /// ([`Openings::opening_payout_script`]).
    pub(super) async fn payout_script(&self) -> Result<ScriptBuf> {
        new_script(&self.wallet)
            .await
            .context("a new address of the hub's wallet")
    }

    /// A new script for the hub's share of a contract opening now: of its
    /// payout wallet, if it has one ([`Openings::pay_out_to`]), else of
    /// the wallet that funds it. Never of the funding wallet for want of
    /// an answer from the payout wallet: the opening is refused then.
    pub(super) async fn opening_payout_script(&self) -> Result<ScriptBuf> {
        match self.payout.get() {
            Some(payout) => new_script(payout)
                .await
                .context("a new address of the contracts' payout wallet"),
            None => self.payout_script().await,
        }
    }

    /// Whether `coin` is unspent: by the blocks, and by the mempool too
    /// if `mempool`.
    pub(super) async fn unspent(&self, coin: OutPoint, mempool: bool) -> Result<bool> {
        let out: Option<serde_json::Value> = self
            .wallet
            .rpc_optional(
                "gettxout",
                serde_json::json!([coin.txid.to_string(), coin.vout, mempool]),
            )
            .await?;
        Ok(out.is_some())
    }

    /// Whether fee coin `coin` of transaction `name` of contract `id` is
    /// gone ([`Self::funding`]): what spends it never relays, so it is to
    /// be funded again. The operator is told, once a contract. One not
    /// told waits, its operator told as [`Self::unknown_coin`] says, `by`
    /// its deadline and the tip if it has one.
    async fn gone(
        &self,
        id: &[u8; 32],
        name: &str,
        coin: OutPoint,
        by: Option<(u32, u32)>,
    ) -> bool {
        let why = match self.funding(id, name, coin).await {
            Funding::Stands => return false,
            // Not told as its deadline nears: funded again, lest what
            // spends it miss it. Should it confirm after all, it is the
            // hub's still, swept once the contract ends.
            Funding::Waits(why) => {
                if !funded_again_unknown(by) {
                    self.unknown_coin(id, name, &why, by);
                    return false;
                }
                let left = by.map_or(0, |(deadline, tip)| deadline.saturating_sub(tip));
                tracing::warn!(id = %crate::hex_id(id), %coin, "a fee coin of {name} of unknown state near its deadline: funded again: {why}");
                if self.once(id, "fee coin funded again near") {
                    self.alert(&format!(
                        "contract {}: a fee coin of its {name} is of unknown state {left} blocks \
                         before its deadline ({why}): another is funded, lest it miss it. Should \
                         the first confirm after all, it is swept back to the hub's wallet once \
                         the contract ends.",
                        crate::hex_id(id)
                    ));
                }
                return true;
            }
            Funding::Gone(why) => why,
        };
        tracing::debug!(id = %crate::hex_id(id), %coin, "a fee coin of {name} is gone: {why}");
        if self.once(id, "fee coin gone") {
            tracing::warn!(id = %crate::hex_id(id), %coin, "a fee coin of {name} is gone: {why}");
            self.alert(&format!(
                "contract {}: a fee coin of its {name} is gone, in no block and in no \
                 mempool of the hub's node ({why}), as after a reorg or another spend of its \
                 wallet's coins: what spends it never relays, so the hub's wallet is asked \
                 for another. Should the one gone confirm after all, it is taken back",
                crate::hex_id(id)
            ));
        }
        true
    }

    /// The state of fee coin `coin`'s funding, by the hub's wallet and its
    /// node: in a block or the mempool, it stands; gone only on their
    /// affirmative word, its inputs spent by another transaction in a
    /// block (the wallet's negative confirmations) or refused when
    /// broadcast again as spending inputs spent or missing ([`refusal`]),
    /// then abandoned, its inputs free again. Refused by policy (its fee,
    /// a full mempool), or for a reason not told, or unknown to the
    /// wallet (one restored older), it waits: one coin too many funded for
    /// a funding that confirms after all costs the hub more than a round's
    /// wait.
    async fn funding(&self, id: &[u8; 32], name: &str, coin: OutPoint) -> Funding {
        let txid = coin.txid.to_string();
        let funding: Result<serde_json::Value> = self
            .wallet
            .rpc("gettransaction", serde_json::json!([txid]))
            .await;
        let funding = match funding {
            Ok(funding) => funding,
            Err(e) if rpc_code(&e) == Some(-5) => return self.funding_unknown(coin).await,
            Err(e) => return Funding::Waits(format!("its wallet not asked: {e:#}")),
        };
        match funding["confirmations"].as_i64() {
            Some(c) if c > 0 => return Funding::Stands,
            Some(c) if c < 0 => {
                return Funding::Gone(format!(
                    "its funding {txid} conflicts with a transaction {} blocks deep",
                    -c
                ))
            }
            Some(_) => {}
            None => return Funding::Waits(format!("its wallet tells no depth of {txid}")),
        }
        let tx = funding["hex"]
            .as_str()
            .and_then(|hex| bitcoin::consensus::encode::deserialize_hex::<Transaction>(hex).ok());
        let Some(tx) = tx else {
            return Funding::Waits(format!("its wallet holds no transaction {txid}"));
        };
        let refused = match self.wallet.broadcast(&tx).await {
            Ok(_) => {
                self.relay_funding(id, name, &tx).await;
                return Funding::Stands;
            }
            Err(e) => e,
        };
        match refusal(&refused) {
            Refusal::Taken => {
                self.relay_funding(id, name, &tx).await;
                Funding::Stands
            }
            Refusal::Policy => Funding::Waits(format!(
                "its funding {txid} refused by its node's policy, to be taken later: {refused:#}"
            )),
            Refusal::Unknown => Funding::Waits(format!(
                "its funding {txid} refused, for a reason not told: {refused:#}"
            )),
            Refusal::Conflict => {
                let abandoned: Result<Option<serde_json::Value>> = self
                    .wallet
                    .rpc_optional("abandontransaction", serde_json::json!([txid]))
                    .await;
                if let Err(e) = abandoned {
                    tracing::debug!(%txid, "a fee coin's funding not abandoned: {e:#}");
                }
                Funding::Gone(format!("{refused:#}"))
            }
        }
    }

    /// Hand `funding`, of a fee coin of transaction `name` of contract
    /// `id`, which the hub's wallet's node holds unconfirmed, to the chain
    /// the hub posts to: another node, or an Esplora, may lack it (they
    /// are not peers, or one dropped it), and refuse what spends the coin.
    /// Its node's own answer is "already known". Refused, the operator is
    /// told, once a contract: the coin is not gone, as the wallet's node
    /// holds it, and another funded would wait the same.
    async fn relay_funding(&self, id: &[u8; 32], name: &str, funding: &Transaction) {
        let Err(e) = self.source.broadcast(funding).await else {
            return;
        };
        let txid = funding.compute_txid();
        tracing::debug!(id = %crate::hex_id(id), %txid, "a fee coin's funding not taken by the chain: {e:#}");
        if self.once(id, "funding unrelayed") {
            self.alert(&format!(
                "contract {}: the chain the hub posts to does not take the funding of a fee \
                 coin of its {name}, {txid}, which its wallet's node holds ({e:#}): what \
                 spends that coin is refused there until it does. Check that the two nodes \
                 relay to each other.",
                crate::hex_id(id)
            ));
        }
    }

    /// Say that the state of a fee coin of `name` of contract `id` is not
    /// told (`why`): it is neither spent by another nor funded again. Each
    /// poll at debug; its operator told once a contract, and once more as
    /// `by`, its deadline and the tip, leaves fewer than [`UNKNOWN_NEAR`]
    /// blocks.
    fn unknown_coin(&self, id: &[u8; 32], name: &str, why: &str, by: Option<(u32, u32)>) {
        tracing::debug!(id = %crate::hex_id(id), "a fee coin of {name} of unknown state: {why}");
        let left = by.map(|(deadline, tip)| deadline.saturating_sub(tip));
        let (what, more) = match left {
            Some(left) if left < UNKNOWN_NEAR => (
                "fee coin unknown near",
                format!(", {left} blocks before its deadline"),
            ),
            Some(left) => (
                "fee coin unknown",
                format!(", {left} blocks before its deadline"),
            ),
            None => ("fee coin unknown", String::new()),
        };
        if self.once(id, what) {
            tracing::warn!(id = %crate::hex_id(id), "a fee coin of {name} of unknown state: {why}");
            self.alert(&format!(
                "contract {}: the state of a fee coin of its {name} is not told ({why}){more}. \
                 It is not funded again while it may yet confirm, until {UNKNOWN_NEAR} blocks \
                 before its deadline, and what spends it may not be in a block in time: check \
                 the hub's node and wallet (a wallet restored older than hub.sqlite knows not \
                 what it funded).",
                crate::hex_id(id)
            ));
        }
    }

    /// [`Self::funding`] of a coin whose funding the hub's wallet does not
    /// know: it stands in a block or in its node's mempool, else waits, as
    /// nothing proves it gone. It may be in another's mempool, and confirm.
    async fn funding_unknown(&self, coin: OutPoint) -> Funding {
        match self.unspent(coin, false).await {
            Ok(true) => return Funding::Stands,
            Ok(false) => {}
            Err(e) => return Funding::Waits(format!("its node not asked: {e:#}")),
        }
        let entry: Result<serde_json::Value> = self
            .wallet
            .rpc(
                "getmempoolentry",
                serde_json::json!([coin.txid.to_string()]),
            )
            .await;
        match entry {
            Ok(_) => Funding::Stands,
            Err(e) if rpc_code(&e) == Some(-5) => Funding::Waits(format!(
                "its funding {} unknown to the hub's wallet, as one restored older than \
                 hub.sqlite, and in no block or mempool of its node: nothing proves it gone",
                coin.txid
            )),
            Err(e) => Funding::Waits(format!("its node not asked: {e:#}")),
        }
    }

    /// Opening `id` of `hub` ended at block `at`: not looked at again once
    /// that block is [`ENDED_DEPTH`] deep at `tip`, and its fee coins left
    /// in a block swept to the hub's wallet ([`Self::swept_fee_coins`]).
    async fn end_if_deep(
        &self,
        id: &[u8; 32],
        hub: &Hub,
        o: &HubOpening,
        at: u32,
        tip: u32,
    ) -> Result<()> {
        if tip.saturating_sub(at) + 1 >= ENDED_DEPTH && self.swept_fee_coins(id, hub, o).await? {
            self.store().end(id, at)?;
            tracing::info!(id = %crate::hex_id(id), at, "contract ended");
        }
        Ok(())
    }

    /// Whether no fee coin of opening `id` is left unspent in a block: each
    /// left is the hub's, paying its fee key, which none but the hub spends.
    /// Those left are swept to the hub's wallet, and the contract ends once
    /// the sweep is in a block. One funded and in no block is not waited
    /// for. Left worth less than their sweep, they are left.
    ///
    /// Under a leaf carrier, its disclosure's coins carry its bytes
    /// ([`dispute::envelope_tree`]): swept by their key path, the bytes
    /// those of the evidence it responded on, as it disclosed them.
    async fn swept_fee_coins(&self, id: &[u8; 32], hub: &Hub, o: &HubOpening) -> Result<bool> {
        let mut left: Vec<(OutPoint, TxOut)> = Vec::new();
        let kept = self.store().all_fee_coins(id)?;
        for coin in kept {
            if !left.iter().any(|l| l.0 == coin.0) && self.unspent(coin.0, false).await? {
                left.push(coin);
            }
        }
        if left.is_empty() {
            return Ok(true);
        }
        let key = &hub.keys().party.payment;
        let mut trees = vec![CoinTree::Fee];
        if licash_hp::carrier(&o.base) == Carrier::Leaf {
            if let Some(pinned) = self.responded_on(id).await? {
                let evidence = pinned_evidence(o, &pinned)?;
                let disclosures = recovery::disclosures(&evidence).map_err(|e| anyhow!("{e}"))?;
                let bytes = disclosures.encode(licash::recovery::Format::of(&o.base).lean());
                trees.push(CoinTree::Envelope(dispute::envelope_tree(key, &bytes)?));
            }
        }
        let scripts = (trees.iter().map(|t| t.script(key))).collect::<Result<Vec<_>>>()?;
        // One of none it knows the tree of is left, not sweeping the rest.
        let (left, unknown): (Vec<_>, Vec<_>) =
            (left.into_iter()).partition(|(_, out)| scripts.contains(&out.script_pubkey));
        for (coin, _) in &unknown {
            tracing::warn!(id = %crate::hex_id(id), %coin, "a fee coin of no script it signs for: left");
        }
        if left.is_empty() {
            return Ok(true);
        }
        let to = self.payout_script().await?;
        let rate = self.fee_rate().await;
        let Some(sweep) = fee_sweep(key, &trees, &left, to, rate)? else {
            self.note_once(
                id,
                "fee coins left",
                "its fee coins left are worth less than a sweep",
            );
            return Ok(true);
        };
        if self.post(&sweep).await && self.once(id, "fee coins swept") {
            let value: Amount = left.iter().map(|c| c.1.value).sum();
            tracing::info!(
                id = %crate::hex_id(id), coins = left.len(), %value,
                txid = %sweep.compute_txid(), "fee coins left swept to the hub's wallet"
            );
        }
        Ok(false)
    }

    /// The first spend of `coin` (paying `out`) in blocks `from..=tip`,
    /// looked up once each block while the chain stands: from `from` again
    /// once the last block looked through left it, which a spend found may
    /// have left with it, as after a restart.
    async fn spend(
        &self,
        coin: OutPoint,
        out: &TxOut,
        from: u32,
        tip: u32,
    ) -> Result<Option<(u32, Transaction)>> {
        let seen = self
            .watch
            .spends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&coin)
            .cloned();
        let now = match &seen {
            Some(((through, _), _)) if *through <= tip => Some(self.source.hash(*through).await?),
            _ => None,
        };
        let start = match looked(seen, now, from) {
            Ok(found) => return Ok(Some(found)),
            Err(start) => start,
        };
        if start > tip {
            return Ok(None);
        }
        // Read before looking, so that blocks replaced meanwhile are looked
        // through again next time.
        let through = (tip, self.source.hash(tip).await?);
        let node = Node(self.source.clone());
        let found = first_spend(&node, coin, &out.script_pubkey, start..=tip)
            .await
            .map_err(|e| anyhow!("{e}"))?;
        self.watch
            .spends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(coin, (through, found.clone()));
        Ok(found)
    }

    async fn block_at(&self, height: u32) -> Result<Block> {
        let hash = self.source.hash(height).await?;
        let block = self.source.block(&hash).await?;
        ensure!(
            block.block_hash() == hash && block.check_merkle_root(),
            "block {hash}"
        );
        Ok(block)
    }

    /// The headers after `o`'s checkpoint through block `to`: back from
    /// `to`'s, each its parent's child, those seen before not fetched again
    /// (a header is its hash's).
    async fn headers(&self, o: &HubOpening, to: u32) -> Result<Vec<[u8; 80]>> {
        let parts = o.base.parts();
        let from = parts.chain.checkpoint.height().saturating_add(1);
        let to = to.min(
            from.saturating_add(parts.chain.max_headers)
                .saturating_sub(1),
        );
        if to < from {
            return Ok(Vec::new());
        }
        let mut hash = self.source.hash(to).await?;
        let mut headers = Vec::with_capacity((to - from + 1) as usize);
        for _ in from..=to {
            let cached = self.header_cache().get(&hash).copied();
            let header = match cached {
                Some(header) => header,
                None => {
                    let header = self.source.header(&hash).await?;
                    ensure!(header.block_hash() == hash, "header {hash}");
                    self.header_cache().insert(hash, header);
                    header
                }
            };
            let bytes = bitcoin::consensus::serialize(&header);
            headers.push(
                bytes
                    .try_into()
                    .map_err(|_| anyhow!("a header of 80 bytes"))?,
            );
            hash = header.prev_blockhash;
        }
        headers.reverse();
        Ok(headers)
    }

    fn header_cache(&self) -> std::sync::MutexGuard<'_, HashMap<BlockHash, Header>> {
        self.watch
            .headers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    async fn fee_rate(&self) -> FeeRate {
        match self.source.fee_rate(6).await {
            Ok(Some(rate)) => rate.max(FeeRate::from_sat_per_vb_u32(1)),
            _ => FeeRate::from_sat_per_vb_u32(2),
        }
    }

    /// Broadcast `tx`: whether the node took it.
    async fn post(&self, tx: &Transaction) -> bool {
        match self.source.broadcast(tx).await {
            Ok(txid) => {
                tracing::info!(%txid, "contract transaction broadcast");
                true
            }
            Err(e) => {
                tracing::debug!(txid = %tx.compute_txid(), "not broadcast yet: {e:#}");
                false
            }
        }
    }

    fn note_once(&self, id: &[u8; 32], what: &'static str, message: &str) {
        if self.once(id, what) {
            tracing::info!(id = %crate::hex_id(id), "{message}");
        }
    }

    /// Whether `what` happened to `id` since the hub started.
    fn seen(&self, id: &[u8; 32], what: &'static str) -> bool {
        self.watch
            .noted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(*id, what))
    }

    /// Whether this is the first time `what` happened to `id` since the
    /// hub started.
    fn once(&self, id: &[u8; 32], what: &'static str) -> bool {
        self.watch
            .noted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((*id, what))
    }
}

/// A new taproot script of the wallet `wallet` names.
async fn new_script(wallet: &licash_chain_client::Source) -> Result<ScriptBuf> {
    let address: String = wallet
        .rpc("getnewaddress", serde_json::json!(["", "bech32m"]))
        .await?;
    Ok(address
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()?
        .assume_checked()
        .script_pubkey())
}

/// How many blocks before an assertion's deadline its operator is told
/// its proof is not made.
const NEAR: u32 = 6;

/// The fee coin a terminal pays with, needing `needed` to be in a block in
/// time, of `stake` at most: the largest of `first` and the `extra` ones in
/// a block (`Some(true)`), and the value of a larger one to fund, unless
/// one is in the mempool only (`Some(false)`) or pays enough already (none
/// are spent ones).
fn terminal_coin(
    first: (OutPoint, TxOut),
    extra: &[((OutPoint, TxOut), Option<bool>)],
    needed: Amount,
    stake: Amount,
) -> ((OutPoint, TxOut), Option<Amount>) {
    let needed = needed.min(stake);
    let confirmed = extra
        .iter()
        .filter(|(_, s)| *s == Some(true))
        .map(|(c, _)| c);
    let coin = confirmed.fold(first, |best, c| match c.1.value > best.1.value {
        true => c.clone(),
        false => best,
    });
    let waiting = extra
        .iter()
        .any(|(c, s)| *s == Some(false) && c.1.value >= needed);
    let fund = (coin.1.value < needed && !waiting).then(|| (needed * 2).min(stake.max(needed)));
    (coin, fund)
}

/// A sweep of fee coins `coins`, each paying a script of `key`'s of one of
/// `trees` (its fee script, spent by its leaf, or an envelope's, by its key
/// path), to `to` at `rate`: none if they are worth less than its fee and a
/// change of dust.
fn fee_sweep(
    key: &bitcoin::secp256k1::Keypair,
    trees: &[CoinTree],
    coins: &[(OutPoint, TxOut)],
    to: ScriptBuf,
    rate: FeeRate,
) -> Result<Option<Transaction>> {
    let prevouts: Vec<TxOut> = coins.iter().map(|c| c.1.clone()).collect();
    let value: Amount = prevouts.iter().map(|o| o.value).sum();
    let dust = to.minimal_non_dust();
    let make = |fee: Amount| -> Result<Option<Transaction>> {
        let Some(pays) = value.checked_sub(fee).filter(|pays| *pays >= dust) else {
            return Ok(None);
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: (coins.iter())
                .map(|c| bitcoin::TxIn {
                    previous_output: c.0,
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                })
                .collect(),
            output: vec![TxOut {
                value: pays,
                script_pubkey: to.clone(),
            }],
        };
        for i in 0..coins.len() {
            let tree = (trees.iter())
                .find(|t| t.script(key).is_ok_and(|s| s == prevouts[i].script_pubkey))
                .context("a fee coin of no tree it knows")?;
            match tree {
                CoinTree::Fee => dispute::sign_fee_input(key, &mut tx, i, &prevouts)?,
                CoinTree::Envelope(t) => dispute::sign_key_input(key, &mut tx, i, &prevouts, t)?,
            }
        }
        Ok(Some(tx))
    };
    let Some(free) = make(Amount::ZERO)? else {
        return Ok(None);
    };
    let size = free.vsize() as u64;
    let fee = (rate.fee_vb(size).context("fee overflow")?).max(Amount::from_sat(size));
    make(fee)
}

/// What the state of a fee coin's funding is, as [`Openings::funding`]
/// tells it.
#[derive(Debug)]
enum Funding {
    /// In a block or its node's mempool.
    Stands,
    /// Proven never to be in a block: why.
    Gone(String),
    /// Neither told: why. Neither spent by another nor funded again.
    Waits(String),
}

/// What a node's refusal of a fee coin's funding, broadcast again, proves
/// ([`refusal`]).
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// In a block already, or its mempool: the coin stands.
    Taken,
    /// Refused by policy (its fee, a full mempool, a chain too long, not
    /// final yet): it may be taken later.
    Policy,
    /// Its inputs spent by another transaction, in a block or its
    /// mempool, or missing: it never relays.
    Conflict,
    /// Anything else: nothing told.
    Unknown,
}

/// What node refusal `e` proves of a transaction broadcast again: only
/// a conflict or inputs missing or spent prove it gone. Any other refusal
/// of mempool policy (-26) waits.
fn refusal(e: &anyhow::Error) -> Refusal {
    let message = format!("{e:#}");
    let says = |words: &[&str]| words.iter().any(|w| message.contains(w));
    match rpc_code(e) {
        Some(-27) => Refusal::Taken,
        Some(-25) if says(&["missingorspent", "missing-inputs"]) => Refusal::Conflict,
        Some(-26)
            if says(&[
                "txn-already-known",
                "txn-already-in-mempool",
                "txn-same-nonwitness-data-in-mempool",
            ]) =>
        {
            Refusal::Taken
        }
        Some(-26)
            if says(&[
                "txn-mempool-conflict",
                "rejecting replacement",
                "missingorspent",
            ]) =>
        {
            Refusal::Conflict
        }
        Some(-26) => Refusal::Policy,
        _ => Refusal::Unknown,
    }
}

/// Whether a fee coin of unknown state is funded again, `by` its deadline
/// and the tip if it has one: once fewer than [`UNKNOWN_NEAR`] blocks are
/// left, as missing the deadline costs more than a coin too many.
fn funded_again_unknown(by: Option<(u32, u32)>) -> bool {
    by.is_some_and(|(deadline, tip)| deadline.saturating_sub(tip) < UNKNOWN_NEAR)
}

/// Blocks before its deadline under which a fee coin of unknown state is
/// told its operator once more ([`Openings::unknown_coin`]), and funded
/// again ([`Openings::gone`]).
const UNKNOWN_NEAR: u32 = 12;

/// The code of a node's JSON-RPC error, as its message ends: `(-25)`.
/// None for a failure to ask it.
fn rpc_code(e: &anyhow::Error) -> Option<i64> {
    let e = format!("{e:#}");
    let code = e.strip_suffix(')')?.rsplit_once('(')?.1;
    code.parse().ok()
}

/// About the virtual size of a link's fee child of `inputs` inputs, each
/// a script spend of the hub's fee key, and one output.
fn child_vb(inputs: usize) -> u64 {
    54 + 76 * inputs as u64
}

/// The fee of `child`, spending the anchor of a link of `outputs` and some
/// of `coins`.
fn child_fee(child: &Transaction, outputs: &[TxOut], coins: &[(OutPoint, TxOut)]) -> Amount {
    let anchor = outputs
        .get(dispute::ANCHOR_VOUT as usize)
        .map_or(Amount::ZERO, |o| o.value);
    let spent: Amount = coins
        .iter()
        .filter(|c| child.input.iter().any(|i| i.previous_output == c.0))
        .map(|c| c.1.value)
        .sum();
    let paid: Amount = child.output.iter().map(|o| o.value).sum();
    (anchor + spent).checked_sub(paid).unwrap_or(Amount::ZERO)
}

/// Of `candidates` against a filing owed `none` with no evidence, those
/// the hub cites, in order: each as `owed` decides on it with the ones
/// before, and voiding something they did not.
///
/// A candidate is judged as `pinned` reads it back, which is how the hub
/// reads its evidence every round from its response on: one its pins do
/// not carry, or the statement refuses, is left out alone, and the rest
/// stand. So is one that voids only items already invalid, worth nothing
/// without it: the spend of a note she names and holds no key of is
/// another's, and is not made public for her naming it.
///
/// Of these, one the statement refuses or that voids nothing new is the
/// ledger's to offer and the statement's to decline. One its pins cannot
/// carry is evidence the hub holds and cannot cite at all, as a spend of
/// more than a statement reads: said in [`Cited::uncited`].
fn cited(
    candidates: Vec<Evidence>,
    none: &recovery::Owed,
    owed: impl Fn(&[Evidence]) -> Result<recovery::Owed>,
    pinned: impl Fn(&[Evidence]) -> Result<Vec<Evidence>>,
) -> Cited {
    let mut selected = Cited::default();
    let kept = &mut selected.kept;
    let mut voided = none.mask;
    for candidate in candidates {
        kept.push(candidate);
        let read = match pinned(kept) {
            Ok(read) => read,
            Err(e) => {
                kept.pop();
                selected.uncited.push(format!("{e:#}"));
                continue;
            }
        };
        match owed(&read) {
            Ok(with) if !idle(voided, &with) => voided = with.mask,
            _ => {
                kept.pop();
            }
        }
    }
    selected
}

/// What [`cited`] cites, in order, and why each candidate it could not
/// carry, whatever it would void, was left out.
#[derive(Default)]
struct Cited {
    kept: Vec<Evidence>,
    uncited: Vec<String>,
}

/// Whether the evidence `with` was decided on voids, beyond the items
/// `voided` before it, only items invalid anyway.
fn idle(voided: u32, with: &recovery::Owed) -> bool {
    let fresh = with.mask & !voided;
    fresh != 0 && fresh & !with.invalid == 0
}

/// Whether the hub answers a claim of `b` on the `alone` it proves her
/// owed with no evidence of its ledger's, which it could not read: only
/// once it is `late` to wait for it, and only if that is less than she
/// asks, as of a claim with an item not valid.
fn unevidenced(alone: u32, b: u32, late: bool) -> bool {
    late && alone < b
}

/// Whether at `tip` half the blocks are gone from her request at `r_at`
/// to `deadline`, the last tip at which the hub's answer still confirms.
fn half_gone(r_at: u32, deadline: u32, tip: u32) -> bool {
    tip >= r_at.saturating_add(deadline.saturating_sub(r_at) / 2)
}

/// The last tip at which the hub's response, broadcast, still confirms
/// before her `request_timeout`, `w_h` blocks after her request at `r_at`:
/// `deadline_margin` blocks to confirm in.
fn respond_deadline(o: &HubOpening, r_at: u32) -> u32 {
    let g = &o.base.parts().graph;
    r_at.saturating_add(u32::from(g.response_window))
        .saturating_sub(1)
        .saturating_sub(g.deadline_margin)
}

/// The blocks terminal `name` of `o` waits after its parent (its CSV).
fn waits(o: &HubOpening, name: &str) -> Result<u32> {
    match presign(&o.set, name)?.tx.input[0]
        .sequence
        .to_relative_lock_time()
    {
        Some(bitcoin::relative::LockTime::Blocks(h)) => Ok(u32::from(h.value())),
        _ => bail!("{name} waits for no number of blocks"),
    }
}

/// The last tip at which the hub's disclosure, broadcast, still confirms
/// before her wallet, finding it in no block, contests the response in a
/// block at `x_at`: at tip `by - 1`, `by` the last tip her contest
/// confirms in before `respond_timeout` (`answered` in
/// `holder/recovery.rs`), so in a block by `by - 1`, broadcast by `by - 2`.
fn disclose_deadline(o: &HubOpening, x_at: u32) -> Result<u32> {
    let margin = o.base.parts().graph.deadline_margin;
    Ok(x_at
        .saturating_add(waits(o, "respond_timeout")?)
        .saturating_sub(1)
        .saturating_sub(margin)
        .saturating_sub(2))
}

/// Her contest in a block at `c_at`, the last tip at which the hub's
/// disclosure, broadcast, still leaves its proof [`NEAR`] blocks before
/// its assertion's deadline once deep enough to prove on.
fn contested_disclose_deadline(o: &HubOpening, c_at: u32) -> u32 {
    let depth = o.base.parts().chain.work_depth;
    assert_deadline(o, c_at)
        .saturating_sub(depth)
        .saturating_sub(NEAR)
}

/// What the hub's assertion missing its deadline costs it, her request
/// `r` met with response `x`: her claim beyond what it responded, and its
/// reserve.
fn assert_stake(o: &HubOpening, r: &Transaction, x: &Transaction) -> Result<Amount> {
    let unit = Amount::from_sat(o.base.parts().graph.unit_sats);
    let (b, _) = o.requested_b(r)?;
    let responded = graph::responded(&o.base, x)?;
    Ok(unit * u64::from(b.saturating_sub(responded)) + o.babe.spec.terms.reserve_hub)
}

/// The last tip at which the hub's assertion, broadcast, still confirms
/// before her `contest_timeout`, `w_a` blocks after her contest at `c_at`
/// (or, as a plan, after the response it would answer at the earliest):
/// `deadline_margin` blocks to confirm in.
fn assert_deadline(o: &HubOpening, c_at: u32) -> u32 {
    let g = &o.base.parts().graph;
    c_at.saturating_add(u32::from(g.assert_window))
        .saturating_sub(1)
        .saturating_sub(g.deadline_margin)
}

/// The cycles of the proof of `o`'s statement on `evidence`, its input made
/// at `at`: until its input is, from its headers and its size (the exit's
/// transactions and proofs about 8 kB), the bodies of the spends it cites
/// by their signatures at what hashing them costs.
fn estimated_cycles(o: &HubOpening, evidence: &[Evidence], at: u32) -> u64 {
    let bytes = recovery::evidence_to_bytes(evidence).len();
    estimated_bytes_cycles(o, bytes, prover::body_bytes(evidence), at)
}

/// [`estimated_cycles`] of `evidence` bytes of evidence, `bodies` of them
/// spends' bodies.
fn estimated_bytes_cycles(o: &HubOpening, evidence: usize, bodies: u64, at: u32) -> u64 {
    let chain = &o.base.parts().chain;
    let other = (o.base.to_bytes().len() + evidence + 8_192) as u64;
    let per_header = prover::header_cycles(o.base.parts().graph.id);
    if recovery::chained(o.base.parts().graph.id) {
        // not of the contract's age: its tail, openings and receipt
        return prover::cycles_with_bodies(per_header, prover::TAIL_HEADERS, other, bodies)
            + prover::SIGNATURE_CYCLES
            + prover::OPENING_CYCLES
            + prover::RESOLVE_CYCLES;
    }
    let from = chain.checkpoint.height().saturating_add(1);
    let headers = at
        .saturating_sub(from)
        .saturating_add(1)
        .min(chain.max_headers);
    prover::cycles_with_bodies(per_header, u64::from(headers), other, bodies)
        + prover::SIGNATURE_CYCLES
}

/// The evidence pinned as `bytes`: none for empty bytes (a response pinned
/// before evidence was).
fn pinned_evidence(o: &HubOpening, bytes: &[u8]) -> Result<Vec<Evidence>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let p = o.base.parts();
    recovery::evidence_from_bytes(&p.keyset, p.limits.max_authorizations as usize, bytes)
        .map_err(|e| anyhow!("the pinned evidence: {e}"))
}

pub(super) fn tagged(id: &[u8; 32], tag: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"licash/contracts/hub-pin");
    h.update(id);
    h.update(tag);
    h.finalize().into()
}

/// How many confirmations an end of a contract takes to be final for the
/// responder.
const ENDED_DEPTH: u32 = 6;

/// Blocks after a signed opening's F was first seen in no block from which
/// the hub makes sure it never confirms: a day. Its holder broadcasts it
/// once signed.
pub(super) const UNFUNDED_FOR: u32 = 144;

/// The slot output of a request, her publication spending it, and of a
/// response, the hub's disclosure spending it (Lichen's `SLOT_VOUT`).
const SLOT: u32 = 2;

/// The fee of `o`'s fold at `rate`: of its size signed, one key-path
/// signature its witness.
fn fold_fee(o: &HubOpening, rate: FeeRate) -> Result<Amount> {
    let mut tx = crate::fold(&o.babe, &o.funding, Amount::ZERO, Amount::ZERO)?.tx;
    tx.input[0].witness = bitcoin::Witness::from_slice(&[[0u8; 64]]);
    rate.fee_vb(tx.vsize() as u64).context("fee overflow")
}

/// A coin's spend as `seen` before, if the chain still has the block it was
/// looked through to, `now` that block's hash at its height (none if past
/// the tip): else the first block to look in for it, `from` if the chain
/// moved under what was seen.
fn looked(
    seen: Option<(Through, Spend)>,
    now: Option<BlockHash>,
    from: u32,
) -> std::result::Result<(u32, Transaction), u32> {
    match seen {
        Some(((through, hash), found)) if now == Some(hash) => found.ok_or(through + 1),
        _ => Err(from),
    }
}

/// Whether block `at` is past the last of the `max_headers` headers after
/// a checkpoint at `checkpoint`.
fn past_the_headers(checkpoint: u32, max_headers: u32, at: u32) -> bool {
    u64::from(at) > u64::from(checkpoint) + u64::from(max_headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_publication_is_past_the_headers_after_the_last_of_them() {
        // The headers after a checkpoint at 100, 30 of them: through 130.
        assert!(!past_the_headers(100, 30, 101));
        assert!(!past_the_headers(100, 30, 130));
        assert!(past_the_headers(100, 30, 131));
        assert!(!past_the_headers(u32::MAX, u32::MAX, u32::MAX));
        assert!(!past_the_headers(u32::MAX - 1, 5, u32::MAX));
    }

    /// The disclosure's deadlines. Uncontested: it is in a block by the
    /// tip before the one her wallet contests a response with none at
    /// (`by - 1`, `by` the last tip her contest confirms in before
    /// `respond_timeout`), so broadcast a block earlier still. Contested:
    /// deep enough to prove on, [`NEAR`] blocks before the assertion's.
    #[test]
    fn a_disclosure_is_due_before_she_contests_and_after_her_contest_in_time_to_prove() {
        let ctx = licash_contract::opening::Context {
            tip: 0,
            trust: licash_contract::opening::Trust::mock(),
        };
        let o = Hub::load(&crate::testing::opened().hub, &ctx)
            .unwrap()
            .signed()
            .unwrap();
        let g = &o.base.parts().graph;
        let wait = waits(&o, "respond_timeout").unwrap();
        assert_eq!(wait, u32::from(g.contest_window));
        let by = 100 + wait - 1 - g.deadline_margin;
        assert_eq!(disclose_deadline(&o, 100).unwrap() + 2, by);
        let depth = o.base.parts().chain.work_depth;
        assert_eq!(
            contested_disclose_deadline(&o, 200) + depth + NEAR,
            assert_deadline(&o, 200)
        );
    }

    /// A coin of unknown state waits while its deadline is far, and is
    /// funded again once near, or past; never one of no deadline.
    #[test]
    fn a_coin_of_unknown_state_is_funded_again_only_near_its_deadline() {
        assert!(!funded_again_unknown(None));
        assert!(!funded_again_unknown(Some((200, 100))));
        assert!(!funded_again_unknown(Some((100 + UNKNOWN_NEAR, 100))));
        assert!(funded_again_unknown(Some((100 + UNKNOWN_NEAR - 1, 100))));
        assert!(funded_again_unknown(Some((100, 100))));
        assert!(funded_again_unknown(Some((90, 100))));
    }

    /// Fee coins left are swept whole to one output, at the rate asked;
    /// none worth less than the sweep's fee and dust.
    #[test]
    fn fee_coins_left_are_swept_unless_worth_less_than_the_sweep() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let key = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &[3; 32]).unwrap();
        let script = dispute::fee_script(&key).unwrap();
        let coin = |n: u8, sat: u64| {
            (
                OutPoint::new(bitcoin::Txid::from_byte_array([n; 32]), 0),
                TxOut {
                    value: Amount::from_sat(sat),
                    script_pubkey: script.clone(),
                },
            )
        };
        let to = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(key.x_only_public_key().0),
        );
        let rate = FeeRate::from_sat_per_vb_u32(2);
        let coins = [coin(1, 5_000), coin(2, 20_000)];
        let fee_only = [CoinTree::Fee];
        let tx = fee_sweep(&key, &fee_only, &coins, to.clone(), rate)
            .unwrap()
            .unwrap();
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].script_pubkey, to);
        let fee = Amount::from_sat(25_000) - tx.output[0].value;
        assert_eq!(fee, rate.fee_vb(tx.vsize() as u64).unwrap());
        assert!(tx.input.iter().all(|i| !i.witness.is_empty()));
        assert!(
            fee_sweep(&key, &fee_only, &[coin(1, 400)], to.clone(), rate)
                .unwrap()
                .is_none()
        );
        // An envelope's coin beside: by its key path, a signature alone,
        // not the bytes it carries; of a tree not given, refused.
        let tree = dispute::envelope_tree(&key, &[0xab; 3_000]).unwrap();
        let carrying = (
            OutPoint::new(bitcoin::Txid::from_byte_array([3; 32]), 0),
            TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: tree.script_pubkey(),
            },
        );
        let coins = [coin(1, 5_000), carrying.clone()];
        assert!(fee_sweep(&key, &fee_only, &coins, to.clone(), rate).is_err());
        let both = [CoinTree::Fee, CoinTree::Envelope(tree)];
        let tx = fee_sweep(&key, &both, &coins, to, rate).unwrap().unwrap();
        assert_eq!(tx.input[1].witness.len(), 1);
        assert!(tx.vsize() < 200, "{} vB", tx.vsize());
        let prevouts = [coins[0].1.clone(), carrying.1];
        let hash = bitcoin::sighash::SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(
                1,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                bitcoin::TapSighashType::Default,
            )
            .unwrap();
        let sig =
            bitcoin::secp256k1::schnorr::Signature::from_slice(tx.input[1].witness.nth(0).unwrap())
                .unwrap();
        let output_key = prevouts[1].script_pubkey.as_bytes()[2..].to_vec();
        let output_key = bitcoin::XOnlyPublicKey::from_slice(&output_key).unwrap();
        let message = bitcoin::secp256k1::Message::from_digest(hash.to_byte_array());
        secp.verify_schnorr(&sig, &message, &output_key).unwrap();
    }

    /// A funding broadcast again is gone only on a conflict or inputs
    /// missing or spent; refused by policy, or otherwise, it waits.
    #[test]
    fn a_funding_is_gone_only_as_its_node_proves_it() {
        let of = |m: &str| refusal(&anyhow!("sendrawtransaction: http://n: {m}"));
        for gone in [
            "bad-txns-inputs-missingorspent (-25)",
            "txn-mempool-conflict (-26)",
            "insufficient fee, rejecting replacement 00ab; new feerate 0.00001 <= old \
             feerate 0.00002 (-26)",
        ] {
            assert_eq!(of(gone), Refusal::Conflict, "{gone}");
        }
        for waits in [
            "mempool min fee not met, 100 < 200 (-26)",
            "min relay fee not met, 100 < 110 (-26)",
            "mempool full (-26)",
            "too-long-mempool-chain, too many unconfirmed ancestors [limit: 25] (-26)",
            "non-BIP68-final (-26)",
        ] {
            assert_eq!(of(waits), Refusal::Policy, "{waits}");
        }
        for taken in [
            "Transaction outputs already in utxo set (-27)",
            "txn-already-known (-26)",
            "txn-same-nonwitness-data-in-mempool (-26)",
        ] {
            assert_eq!(of(taken), Refusal::Taken, "{taken}");
        }
        for unknown in [
            "Fee exceeds maximum configured by user (-25)",
            "error sending request",
            "HTTP 500 (internal)",
            "Work queue depth exceeded (-32603)",
        ] {
            assert_eq!(of(unknown), Refusal::Unknown, "{unknown}");
        }
    }

    /// A node's error is told by its code, a failure to ask it by none.
    #[test]
    fn a_nodes_error_is_told_by_its_code() {
        let code = |m: &str| rpc_code(&anyhow!("broadcast: http://n: {m}"));
        assert_eq!(
            code("sendrawtransaction: bad-txns-inputs-missingorspent (-25)"),
            Some(-25)
        );
        assert_eq!(
            code("sendrawtransaction: mempool min fee not met (-26)"),
            Some(-26)
        );
        assert_eq!(
            code("gettransaction: Invalid or non-wallet transaction id (-5)"),
            Some(-5)
        );
        assert_eq!(code("sendrawtransaction: error sending request"), None);
        assert_eq!(code("sendrawtransaction: HTTP 500 (internal)"), None);
    }

    fn coin(n: u8, sat: u64) -> (OutPoint, TxOut) {
        let txid = bitcoin::hashes::Hash::from_byte_array([n; 32]);
        let out = TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: ScriptBuf::new(),
        };
        (OutPoint { txid, vout: 0 }, out)
    }

    #[test]
    fn a_terminal_pays_with_its_largest_coin_in_a_block_and_funds_a_larger_one_once() {
        let sat = Amount::from_sat;
        let (first, stake) = (coin(1, 1_000), sat(50_000));
        // Its first pays enough: nothing funded.
        assert_eq!(
            terminal_coin(first.clone(), &[], sat(800), stake),
            (first.clone(), None)
        );
        // Too little: twice what it needs, the stake at most.
        assert_eq!(
            terminal_coin(first.clone(), &[], sat(3_000), stake).1,
            Some(sat(6_000))
        );
        assert_eq!(
            terminal_coin(first.clone(), &[], sat(30_000), stake).1,
            Some(stake)
        );
        assert_eq!(
            terminal_coin(first.clone(), &[], sat(90_000), stake).1,
            Some(stake)
        );
        // One funded, in the mempool only: waited for, the first paid with.
        let pending = [(coin(2, 6_000), Some(false))];
        assert_eq!(
            terminal_coin(first.clone(), &pending, sat(3_000), stake),
            (first.clone(), None)
        );
        // The rate rose past it meanwhile: a larger one more.
        assert_eq!(
            terminal_coin(first.clone(), &pending, sat(8_000), stake).1,
            Some(sat(16_000))
        );
        // In a block: the largest paid with; a spent one never.
        let extra = [
            (coin(2, 6_000), Some(true)),
            (coin(3, 4_000), Some(true)),
            (coin(4, 9_000), None),
        ];
        assert_eq!(
            terminal_coin(first, &extra, sat(3_000), stake),
            (coin(2, 6_000), None)
        );
    }

    fn decided(owed: u32, mask: u32, invalid: u32) -> recovery::Owed {
        recovery::Owed {
            owed,
            mask,
            invalid,
            disclosures: Disclosures::empty(),
            ineligible: None,
        }
    }

    fn candidate(n: u8) -> Evidence {
        Evidence::Expired {
            source: licash::spend::ProposalId::from_bytes([n; 32]),
        }
    }

    fn names(evidence: &[Evidence]) -> Vec<u8> {
        (evidence.iter())
            .map(|e| match e {
                Evidence::Expired { source } => source.as_bytes()[0],
                _ => unreachable!(),
            })
            .collect()
    }

    /// Of a claim of four items of 10, the second not valid: a candidate
    /// the statement refuses, one the hub's pins do not carry and one
    /// that voids nothing but the item not valid are each left out, and
    /// the others cited all the same, on what they void together.
    #[test]
    fn a_candidate_refused_unpinned_or_idle_is_left_out_alone() {
        const INVALID: u32 = 0b0010;
        // What each voids: 1 the first item, 3 the invalid one alone, 5
        // the invalid one and the third, 6 the first again.
        let voids = |n: u8| match n {
            1 | 6 => 0b0001,
            3 => 0b0010,
            5 => 0b0110,
            _ => 0,
        };
        let owed = |evidence: &[Evidence]| {
            let mut mask = 0;
            for n in names(evidence) {
                ensure!(n != 2, "refused by the statement");
                ensure!(voids(n) & !mask != 0, "voids nothing");
                mask |= voids(n);
            }
            let live = !(mask | INVALID) & 0b1111;
            Ok(decided(10 * live.count_ones(), mask, INVALID))
        };
        let pinned = |evidence: &[Evidence]| {
            ensure!(!names(evidence).contains(&4), "not carried");
            Ok(evidence.to_vec())
        };
        let none = owed(&[]).unwrap();
        assert_eq!(none.owed, 30);
        let all = || (1..=6).map(candidate).collect::<Vec<_>>();
        let kept = cited(all(), &none, owed, pinned);
        assert_eq!(names(&kept.kept), [1, 5]);
        assert_eq!(owed(&kept.kept).unwrap().owed, 10);
        // The one that fails first costs the hub none of the rest.
        let last_first = all().into_iter().rev().collect();
        assert_eq!(names(&cited(last_first, &none, owed, pinned).kept), [6, 5]);
        // Nothing to cite is no error.
        assert!(cited(Vec::new(), &none, owed, pinned).kept.is_empty());
        assert!(cited(vec![candidate(2)], &none, owed, pinned)
            .kept
            .is_empty());
        // Of those left out, only the one its pins cannot carry is
        // evidence the hub holds and cannot cite: the statement declining
        // the others is no news.
        assert_eq!(kept.uncited.len(), 1);
        assert!(
            kept.uncited[0].contains("not carried"),
            "{:?}",
            kept.uncited
        );
        assert!(cited(vec![candidate(2)], &none, owed, pinned)
            .uncited
            .is_empty());
        let alone = cited(vec![candidate(4)], &none, owed, pinned);
        assert!(alone.kept.is_empty());
        assert_eq!(alone.uncited.len(), 1);
    }

    /// Evidence is idle that voids only items not valid: one that voids a
    /// valid item with them, or no item at all (as a spend that values a
    /// fallback), is not.
    #[test]
    fn evidence_is_idle_that_voids_only_items_not_valid() {
        assert!(idle(0, &decided(0, 0b10, 0b10)));
        assert!(idle(0b01, &decided(0, 0b11, 0b10)));
        assert!(!idle(0, &decided(0, 0b11, 0b10)));
        assert!(!idle(0, &decided(0, 0b01, 0)));
        assert!(!idle(0b01, &decided(0, 0b01, 0b10)));
        // Where no item is invalid, nothing is.
        for mask in 0..16 {
            assert!(!idle(0, &decided(0, mask, 0)));
        }
    }

    /// A hub that cannot read its ledger answers on what it proves alone
    /// only once late, and only if that is less than she asks: early, its
    /// ledger may yet give more, and a claim owed whole has no answer.
    #[test]
    fn a_hub_without_its_ledger_answers_late_on_what_it_proves_alone() {
        assert!(unevidenced(98_304, 131_071, true));
        assert!(unevidenced(0, 131_071, true));
        assert!(!unevidenced(98_304, 131_071, false));
        assert!(!unevidenced(131_071, 131_071, true));
        assert!(!unevidenced(131_072, 131_071, true));
    }

    /// A ledger a few blocks behind her claim is no alert; one still
    /// giving nothing half way to the last block to respond at is.
    #[test]
    fn an_answer_undecided_is_told_once_half_its_blocks_are_gone() {
        // Requested at 100, a response confirming in time until 140.
        assert!(!half_gone(100, 140, 100));
        assert!(!half_gone(100, 140, 119));
        assert!(half_gone(100, 140, 120));
        assert!(half_gone(100, 140, 500));
        // No room left, as when the hub was away: at once.
        assert!(half_gone(100, 100, 100));
        assert!(half_gone(100, 90, 100));
        assert!(half_gone(100, 101, 100));
    }

    #[test]
    fn a_spend_seen_stands_only_while_the_blocks_looked_through_do() {
        let hash = |n: u8| bitcoin::hashes::Hash::from_byte_array([n; 32]);
        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let found = Some((105, spend.clone()));
        // Never looked for: from the start.
        assert_eq!(looked(None, None, 100), Err(100));
        // Found, its blocks still the chain's: kept.
        let seen = |found: &Spend| Some(((110, hash(1)), found.clone()));
        assert_eq!(looked(seen(&found), Some(hash(1)), 100), Ok((105, spend)));
        // None found: on from the block after the last looked through.
        assert_eq!(looked(seen(&None), Some(hash(1)), 100), Err(111));
        // The chain moved under them, however deep, or is shorter now:
        // looked for again from the start, found or not.
        for found in [found, None] {
            assert_eq!(looked(seen(&found), Some(hash(2)), 100), Err(100));
            assert_eq!(looked(seen(&found), None, 100), Err(100));
        }
    }
}
