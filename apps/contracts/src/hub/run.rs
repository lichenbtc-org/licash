//! Stepping an opening: one task at a time, each step stored before the
//! effects it asks for run.

use std::collections::VecDeque;
use std::sync::Arc;

use bitcoin::{OutPoint, TxOut};
use licash::base::Base;
use licash_contract::opening::{Context, Hub, HubPhase, Input, Out, Quote};
use licash_contract::wire::{self, Envelope, Kind, Writer};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use super::store::Store;
use super::{prover, terms, Answer, Openings, Refused, MAX_UNDER_WAY, MAX_UNFUNDED, WAIT};
use crate::{Frame, Opening};

/// How often a patient step looks whether the opening is still busy.
const BUSY_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// How many blocks deeper than a new one a quote's checkpoint may be.
const MAX_AGE: u32 = 6;

/// Clears an opening's busy mark however its task ends.
struct Busy(Arc<Openings>, [u8; 32]);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.busy().remove(&self.1);
    }
}

/// What a message steps: the stored opening, or a new one on `quote`.
enum Start {
    Stored,
    New {
        quote: Box<Quote>,
        deposit: OutPoint,
    },
}

fn not_found() -> Refused {
    Refused {
        status: axum::http::StatusCode::NOT_FOUND,
        reason: "no such opening".into(),
    }
}

impl Openings {
    /// A holder's [`Opening`]: refused unless on the hub's terms, at a
    /// recent block of its chain, of a deposit confirmed as she says.
    pub async fn open(self: &Arc<Self>, body: &[u8]) -> Result<Answer, Refused> {
        let opening = Opening::decode(body).map_err(Refused::bad)?;
        let envelope = Envelope::from_bytes(&opening.open).map_err(Refused::bad)?;
        if !matches!(envelope.kind, Kind::Open) {
            return Err(Refused::bad("an opening starts with an Open"));
        }
        let open = wire::Open::decode(&envelope.body).map_err(Refused::bad)?;
        let new = (self.store().row(&envelope.id))
            .map_err(Refused::unavailable)?
            .is_none();
        // Its terms at the surcharge now, if new; if sent again, at
        // whichever it started at.
        let steps = match new {
            true => {
                admits(&self.store())?;
                let step = self.step_now()?;
                step..=step
            }
            false => 0..=terms::MAX_STEP,
        };
        // Reject cheap size/collateral and policy failures before node RPC.
        self.timing()
            .allows(opening.quote.cap, terms::lock_of(&opening.quote))
            .map_err(Refused::bad)?;
        self.terms_of(&opening.quote, steps).await?;
        // Before she garbles for it; again, held, as it is funded.
        self.room_for(&envelope.id, quote_cycles(&opening.quote))?;
        let confirmed = self.confirmed(open.deposit, &open.coin).await;
        if !confirmed.map_err(Refused::unavailable)? {
            return Err(Refused::bad(
                "her deposit is no confirmed coin of the chain as she says",
            ));
        }
        // Her reserve returns to a deposit of the hub's that swaps it for
        // notes: bound to this contract, or refused, before she garbles.
        let (bind, _) = self
            .closer
            .get()
            .ok_or_else(|| Refused::bad("this hub takes no deposit for her reserve"))?;
        let timeout = (open.wanted.close_height)
            .checked_add(crate::CLOSE_BLOCKS)
            .ok_or_else(|| Refused::bad("the close deposit's timeout overflows"))?;
        let reserve = opening.quote.graph.reserve_alice;
        bind(
            open.close.script.as_bytes(),
            envelope.id,
            reserve,
            open.close.fee,
            timeout,
        )
        .map_err(Refused::bad)?;
        let start = Start::New {
            quote: Box::new(opening.quote),
            deposit: open.deposit,
        };
        let answer = self.take(envelope.id, opening.open, start, false).await;
        if answer.is_err() {
            self.unbind(&envelope.id);
        }
        answer
    }

    /// Give up the deposit bound to opening `id`, refused before it was
    /// stored: no opening is given up for it later. Not while another
    /// task steps it, as [`Self::abandon_idle`].
    pub(super) fn unbind(&self, id: &[u8; 32]) {
        let busy = self.busy();
        if busy.contains(id) {
            return;
        }
        match self.store().row(id) {
            Ok(None) => {
                if let Some((_, release)) = self.closer.get() {
                    release(id);
                }
            }
            Ok(Some(_)) => {}
            Err(e) => {
                tracing::warn!(id = %crate::hex_id(id), "a refused opening's deposit kept: {e:#}")
            }
        }
    }

    /// The holder's next message of opening `id`. An instance, large and
    /// slow to send again, is answered once stepped, never 202: after
    /// another task stepping the opening if one is.
    pub async fn step(self: &Arc<Self>, id: [u8; 32], message: Vec<u8>) -> Result<Answer, Refused> {
        let envelope = Envelope::from_bytes(&message).map_err(Refused::bad)?;
        if envelope.id != id {
            return Err(Refused::bad("a message of another opening"));
        }
        let patient = envelope.kind == Kind::Instance;
        self.take(id, message, Start::Stored, patient).await
    }

    /// Refused, as stepping it would refuse it, unless opening `id` waits
    /// for her kept instances, or took them already (one sent again): told
    /// before an upload's body, 25 MB, is read.
    pub fn awaits_instances(&self, id: &[u8; 32]) -> Result<(), Refused> {
        let row = self.store().row(id).map_err(Refused::unavailable)?;
        let row = row.ok_or_else(not_found)?;
        if row.abandoned {
            return Err(Refused::bad("an opening given up"));
        }
        let peek = Hub::peek(&row.state).map_err(Refused::unavailable)?;
        match peek.phase {
            HubPhase::Chosen | HubPhase::Offered => Ok(()),
            phase => Err(Refused::bad(format!("no instance awaited at {phase:?}"))),
        }
    }

    /// Refused unless `quote` is the hub's: its terms surcharged at one of
    /// `steps`, checkpointed at a block of its best chain buried as a new
    /// quote's, at most [`MAX_AGE`] deeper, and kept as a lock checkpoint.
    async fn terms_of(
        &self,
        quote: &Quote,
        steps: std::ops::RangeInclusive<u32>,
    ) -> Result<(), Refused> {
        let height = quote.chain.checkpoint.height();
        let tip = self
            .source
            .tip()
            .await
            .map_err(Refused::unavailable)?
            .height;
        let newest = self.opening_height(tip)?;
        if height > tip || newest.saturating_sub(height) > MAX_AGE {
            return Err(Refused::stale(format!(
                "a quote of block {height}, the tip at {tip}: ask again"
            )));
        }
        // The terms she chose, if within the hub's: those of the quote,
        // and what she funds of it (`deposit_units`, of 1-sat units).
        let (cap, blocks) = (quote.cap, terms::lock_of(quote));
        let funded = quote.graph.deposit_units;
        self.timing().allows(cap, blocks).map_err(Refused::bad)?;
        let checkpoint = self.source.checkpoint(height).await;
        let checkpoint = checkpoint.map_err(Refused::unavailable)?;
        let bytes = |q: &Quote| {
            let mut w = Writer(Vec::new());
            w.quote(q);
            w.0
        };
        let theirs = bytes(quote);
        // One quoted at another surcharge than now: asked again.
        for step in steps {
            let timing = self.timing().at_step(step);
            let ours =
                timing.quote_for(self.keyset.clone(), checkpoint.clone(), cap, blocks, funded);
            if bytes(&ours) == theirs {
                // the node's block, as the hub quoted it: of its header chain too
                self.on_chain(&ours.chain.checkpoint).await?;
                return self.keep_checkpoint(&ours.chain.checkpoint);
            }
        }
        Err(Refused::stale("not the hub's quote: ask again"))
    }

    /// Step opening `id` with `message` in a task of its own, answering
    /// its frames, or 202 if it takes longer than [`WAIT`] or another task
    /// steps the opening; if `patient`, its frames once the other task
    /// and its own are done, however long they take.
    async fn take(
        self: &Arc<Self>,
        id: [u8; 32],
        message: Vec<u8>,
        start: Start,
        patient: bool,
    ) -> Result<Answer, Refused> {
        while !self.busy().insert(id) {
            if !patient {
                return Ok(Answer::Working);
            }
            tokio::time::sleep(BUSY_POLL).await;
        }
        let busy = Busy(self.clone(), id);
        let this = self.clone();
        let task = tokio::spawn(async move {
            let _busy = busy;
            this.run(id, message, start).await
        });
        let waited = match patient {
            true => Ok(task.await),
            false => tokio::time::timeout(WAIT, task).await,
        };
        match waited {
            Ok(Ok(answer)) => answer,
            Ok(Err(e)) => Err(Refused::unavailable(e)),
            Err(_) => Ok(Answer::Working),
        }
    }

    async fn run(&self, id: [u8; 32], message: Vec<u8>, start: Start) -> Result<Answer, Refused> {
        let ctx = self.context().await?;
        let last: [u8; 32] = Sha256::digest(&message).into();
        let row = self.store().row(&id).map_err(Refused::unavailable)?;
        let (hub, out) = match (row, start) {
            (Some(row), _) if row.abandoned => return Err(Refused::bad("an opening given up")),
            (Some(row), _) => {
                let hub = Hub::load(&row.state, &ctx).map_err(Refused::unavailable)?;
                if row.last == last {
                    // Asked again: answered as before, its effects run.
                    let mut out = hub.pending().map_err(Refused::unavailable)?;
                    if matches!(Kind::peek(&message), Some(Kind::Opened | Kind::Instance)) {
                        out.retain(
                            |o| !matches!(o, Out::Send(b) if Kind::peek(b) == Some(Kind::Choose)),
                        );
                    }
                    (hub, out)
                } else {
                    let (hub, out) =
                        stepped(&self.heavy, hub, Input::Message(message), ctx).await?;
                    let out = self.keep(&id, out)?;
                    self.save(&id, &hub, &last)?;
                    (hub, out)
                }
            }
            (None, Start::Stored) => return Err(not_found()),
            (None, Start::New { quote, deposit }) => {
                admits(&self.store())?;
                self.step_now()?;
                let bounds = self.timing().bounds(&quote);
                let payout = self
                    .opening_payout_script()
                    .await
                    .map_err(Refused::unavailable)?;
                let hub = Hub::new(*quote, bounds, payout);
                let (hub, out) = stepped(&self.heavy, hub, Input::Message(message), ctx).await?;
                self.reads(&hub).await?;
                let out = self.keep(&id, out)?;
                let state = hub.to_bytes();
                // Counted again as stored, in one hold of the store: others
                // started meanwhile.
                let inserted = {
                    let store = self.store();
                    admits(&store)?;
                    store
                        .insert(&id, phase(&hub), ctx.trust.mock, &deposit, &last, &state)
                        .map_err(Refused::unavailable)?
                };
                if !inserted {
                    return Err(Refused::bad("her deposit is another opening's"));
                }
                tracing::info!(id = %crate::hex_id(&id), mock = ctx.trust.mock, "an opening started");
                (hub, out)
            }
        };
        self.effects(id, hub, out, last, ctx).await
    }

    /// Carry out effects only after artifacts and state are durable.
    async fn effects(
        &self,
        id: [u8; 32],
        mut hub: Hub,
        out: Vec<Out>,
        last: [u8; 32],
        ctx: Context,
    ) -> Result<Answer, Refused> {
        let mut queue: VecDeque<Out> = out.into();
        let mut frames = Vec::new();
        while let Some(out) = queue.pop_front() {
            match out {
                Out::Send(bytes) => frames.push(Frame::Message(bytes)),
                Out::Fund {
                    deposit,
                    coin,
                    outputs,
                } => {
                    let _funding = self.funding.lock().await;
                    // Held until its coins are kept: no two openings
                    // take the same room.
                    let base = hub
                        .base()
                        .ok_or_else(|| Refused::unavailable("F before Base"))?;
                    self.room_for(&id, base_cycles(base))?;
                    let funded = self.fund(deposit, &coin, outputs).await;
                    let (funding, prevouts) = funded.map_err(Refused::unavailable)?;
                    let coins: Vec<OutPoint> = funding
                        .input
                        .iter()
                        .map(|i| i.previous_output)
                        .filter(|o| *o != deposit)
                        .collect();
                    let (next, more) =
                        stepped(&self.heavy, hub, Input::Funded { funding, prevouts }, ctx).await?;
                    hub = next;
                    let more = self.keep(&id, more)?;
                    self.store()
                        .set_coins(&id, &coins)
                        .map_err(Refused::unavailable)?;
                    // A crash may over-lock an unsigned selection, never
                    // leave durable F inputs absent from restart locking.
                    self.save(&id, &hub, &last)?;
                    self.lock_coins(&coins).await;
                    tracing::info!(id = %crate::hex_id(&id), coins = coins.len(), "F funded");
                    queue.extend(more);
                }
                Out::Sign {
                    funding,
                    prevouts,
                    inputs,
                } => {
                    let theirs: Vec<(OutPoint, TxOut)> = funding
                        .input
                        .iter()
                        .zip(&prevouts)
                        .enumerate()
                        .filter(|(i, _)| !inputs.contains(i))
                        .map(|(_, (input, coin))| (input.previous_output, coin.clone()))
                        .collect();
                    // Her deposit, which she signed into F, is still hers
                    // to spend as the hub signs: else F never confirms,
                    // and the hub's coins wait on it.
                    for (deposit, _) in &theirs {
                        let unspent = self.unspent(*deposit, true).await;
                        if !unspent.map_err(Refused::unavailable)? {
                            return Err(Refused::bad("her deposit is spent"));
                        }
                    }
                    // No contract is signed that its witnesses would not keep
                    // the answers of.
                    let witnesses = self.witnesses().map_err(Refused::unavailable)?;
                    witnesses
                        .enroll(&self.data, &id, || self.never_signed())
                        .await
                        .map_err(Refused::unavailable)?;
                    let signed = self.sign(&funding, &theirs).await;
                    let signed = signed.map_err(Refused::unavailable)?;
                    let tip = ctx.tip;
                    let (next, more) =
                        stepped(&self.heavy, hub, Input::Signed(signed), ctx).await?;
                    hub = next;
                    let more = self.keep(&id, more)?;
                    self.save(&id, &hub, &last)?;
                    // Counted signed and unfunded now, as admission counts
                    // it ([`MAX_UNFUNDED`]), not at the responder's next pass:
                    // till then, past its signatures, no longer under way,
                    // it was counted in neither.
                    self.store()
                        .unfunded(&id, tip)
                        .map_err(Refused::unavailable)?;
                    tracing::info!(id = %crate::hex_id(&id), "F signed");
                    queue.extend(more);
                }
                Out::Broadcast(tx) => match self.source.broadcast(&tx).await {
                    Ok(txid) => tracing::info!(id = %crate::hex_id(&id), %txid, "F broadcast"),
                    Err(e) => tracing::warn!(id = %crate::hex_id(&id), "broadcasting F: {e:#}"),
                },
                Out::Keep { .. } | Out::Serve { .. } => {
                    return Err(Refused::unavailable(
                        "unexpected instance effect after state was saved",
                    ));
                }
            }
        }
        Ok(Answer::Frames(frames))
    }

    /// Refused 503 unless the hub's prover makes, in an assert window, the
    /// largest proof of an exit of each contract it committed to and one of
    /// `cycles` for opening `id`, one after another: their holders may all
    /// exit at once, and a claim it does not prove in time is paid all it
    /// asks. Without a prover (the mock authority's proofs), room for any.
    pub(super) fn room_for(&self, id: &[u8; 32], cycles: u64) -> Result<(), Refused> {
        let Some(prover) = &self.prover else {
            return Ok(());
        };
        let states = self.store().committed(id).map_err(Refused::unavailable)?;
        let mut all = vec![cycles];
        // The header chain's batch a dispute may wait for, made once for all
        // of them: the blocks since the last receipt are at most a day's.
        if let Some(chain) = &self.chain {
            all.push(prover::chain_batch_cycles(chain.batch_blocks()));
        }
        for state in states {
            let peek = Hub::peek(&state).map_err(|e| {
                Refused::unavailable(format!("a contract the hub committed to is unread: {e:#}"))
            })?;
            all.push(base_cycles(&peek.base));
        }
        let blocks = self.timing().proof_blocks();
        let (need, have) = prover.room(&all, blocks).map_err(|why| {
            Refused::unavailable(format!("the hub's prover is not ready ({why}): later"))
        })?;
        let need = need * self.proof_scale.get().copied().unwrap_or(1.0);
        if need > have {
            return Err(Refused::unavailable(format!(
                "no room for another contract: the hub proves an exit of each of {} at once in \
                 about {need:.0} s, and has {have:.0} s ({blocks} blocks): later",
                all.len()
            )));
        }
        Ok(())
    }

    /// Refused 503, and its operator told, unless the hub's prover reads a
    /// statement's input of `hub`'s Base with the program it names: before
    /// the hub keeps or signs anything of it. Without a prover (the mock
    /// authority's proofs), no program to read it.
    async fn reads(&self, hub: &Hub) -> Result<(), Refused> {
        let (Some(prover), Some(base)) = (&self.prover, hub.base()) else {
            return Ok(());
        };
        let Err(e) = prover.reads(base).await else {
            return Ok(());
        };
        let why = format!(
            "the hub's program reads no statement of the contract it was asked to open \
             ({e:#}): it opens none, as it could prove nothing of them"
        );
        prover.alert(&why);
        Err(Refused::unavailable(why))
    }

    /// A state must never reference an artifact that has not reached disk.
    fn keep(&self, id: &[u8; 32], out: Vec<Out>) -> Result<Vec<Out>, Refused> {
        let mut effects = Vec::with_capacity(out.len());
        for o in out {
            match o {
                Out::Keep { i, bytes } => self
                    .store()
                    .keep(id, i, &bytes)
                    .map_err(Refused::unavailable)?,
                effect => effects.push(effect),
            }
        }
        Ok(effects)
    }

    /// Store `hub` after a step that took the message of digest `last`.
    fn save(&self, id: &[u8; 32], hub: &Hub, last: &[u8; 32]) -> Result<(), Refused> {
        let state = hub.to_bytes();
        // Past its signatures, it is the holder's to fund F.
        let irrevocable = !hub.abandonable();
        self.store()
            .save(id, phase(hub), irrevocable, last, &state)
            .map_err(Refused::unavailable)
    }
}

/// The cycles of the largest proof of an exit of a contract of `base`.
pub(super) fn base_cycles(base: &Base) -> u64 {
    let p = base.parts();
    let (headers, publication) = (p.chain.max_headers, p.limits.max_publication_bytes);
    prover::worst_cycles(headers, publication, base.to_bytes().len(), p.graph.id)
}

/// As [`base_cycles`], of a contract on `quote`, before its Base is: the
/// quote, as large as its keyset and terms, and 4 kB for the rest.
pub(super) fn quote_cycles(quote: &Quote) -> u64 {
    let mut w = Writer(Vec::new());
    w.quote(quote);
    let base = w.0.len() + 4_096;
    let (headers, publication) = (quote.chain.max_headers, quote.limits.max_publication_bytes);
    prover::worst_cycles(headers, publication, base, quote.graph.id)
}

fn phase(hub: &Hub) -> u8 {
    hub.phase() as u8
}

/// `hub` stepped with `input` off the async threads, in its turn
/// ([`heavy`]): refused as the machine refuses it, unchanged.
async fn stepped(
    limit: &Arc<Semaphore>,
    mut hub: Hub,
    input: Input,
    ctx: Context,
) -> Result<(Hub, Vec<Out>), Refused> {
    let stepped = heavy(limit, move || {
        let out = hub.step(input, &ctx);
        (hub, out)
    });
    let (hub, out) = stepped.await?;
    Ok((hub, out.map_err(Refused::bad)?))
}

/// `work` off the async threads once `limit` has a permit free, held until
/// the work is done, even if no one waits for it any more: the most at once
/// ([`super::HEAVY`]).
async fn heavy<T: Send + 'static>(
    limit: &Arc<Semaphore>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Refused> {
    let permit = limit.clone().acquire_owned().await;
    let permit = permit.map_err(Refused::unavailable)?;
    let done = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    });
    done.await.map_err(Refused::unavailable)
}

/// Refused if `store` holds as many openings under way as the hub takes,
/// or signed and not funded.
pub(super) fn admits(store: &Store) -> Result<(), Refused> {
    if store.under_way().map_err(Refused::unavailable)? >= MAX_UNDER_WAY {
        return Err(Refused::unavailable("too many openings under way: later"));
    }
    if store.unfunded_count().map_err(Refused::unavailable)? >= MAX_UNFUNDED {
        return Err(Refused::unavailable(
            "too many openings signed and not funded: later",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn heavy_work_runs_one_at_a_time_even_once_no_one_waits_for_it() {
        let limit = Arc::new(Semaphore::new(super::super::HEAVY));
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let work = || {
            let (running, most) = (running.clone(), most.clone());
            move || {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(100));
                running.fetch_sub(1, Ordering::SeqCst);
            }
        };
        // One whose request was answered 202: no one waits for it, and it
        // keeps its turn.
        let unwaited = heavy(&limit, work());
        let waited = tokio::time::timeout(Duration::from_millis(20), unwaited).await;
        assert!(waited.is_err());
        let others: Vec<_> = (0..4)
            .map(|_| {
                let (limit, work) = (limit.clone(), work());
                tokio::spawn(async move { heavy(&limit, work).await })
            })
            .collect();
        for other in others {
            other.await.unwrap().unwrap();
        }
        assert_eq!(most.load(Ordering::SeqCst), 1);
        assert_eq!(running.load(Ordering::SeqCst), 0);
    }
}
