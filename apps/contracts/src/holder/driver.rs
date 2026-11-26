//! One opening driven by its holder: her machine stepped with the hub's
//! answers, each step stored before its disclosures, instance uploads,
//! signatures or other effects leave the wallet.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _, Result};
use licash_contract::opening::{Context, Holder, Input, Out, Phase, Quote, Trust};
use licash_contract::wire::{self, Envelope, Kind};
use licash_wallet::{Transport, Wallet};

use super::chain::Chain;
use super::store::Store;
use crate::{Frame, Opening, INSTANCE, OPEN, STEP};

/// How long to wait before asking a working hub again.
const RETRY: Duration = Duration::from_secs(2);

/// How many times to ask a working hub again before trying later.
const PATIENCE: u32 = 900;

/// How long a holder turned away busy (503) keeps asking again: a hub
/// answers so, before it keeps anything, when its requests of the kind
/// are all taken or it has as many openings as it admits, and either is
/// over within minutes (a block confirming the openings it signed).
const BUSY_PATIENCE: Duration = Duration::from_secs(180);

/// The longest wait between two asks of a hub turned busy.
const BUSY_MOST: Duration = Duration::from_secs(30);

/// A hub's 503s to one request: asked again after a wait doubling from
/// [`RETRY`] to [`BUSY_MOST`], up to [`BUSY_PATIENCE`] since the first.
#[derive(Default)]
pub(super) struct Busy {
    since: Option<tokio::time::Instant>,
    times: u32,
}

impl Busy {
    /// Waited before asking again, unless patience ran out: then false.
    pub(super) async fn wait(&mut self) -> bool {
        let since = *self.since.get_or_insert_with(tokio::time::Instant::now);
        let wait = busy_wait(self.times, jitter());
        if since.elapsed() + wait > BUSY_PATIENCE {
            return false;
        }
        self.times += 1;
        tokio::time::sleep(wait).await;
        true
    }
}

/// The wait before the `n`th ask again of a hub turned busy, of a jitter
/// `j` in [0, 1): half the doubled wait, and up to half again, so that
/// holders turned away at once come back apart.
fn busy_wait(n: u32, j: f64) -> Duration {
    let doubled = RETRY.saturating_mul(1 << n.min(8)).min(BUSY_MOST);
    doubled.mul_f64(0.5 + j / 2.0)
}

/// A number in [0, 1), of the process's random hashing keys.
fn jitter() -> f64 {
    use std::hash::BuildHasher;
    let hashed = std::collections::hash_map::RandomState::new().hash_one(Instant::now());
    (hashed >> 11) as f64 / (1u64 << 53) as f64
}

/// How many times a step that never reached the hub, or whose answer
/// never came back, is sent again at once: a circuit over Tor drops now
/// and then, and the hub takes a step it has again as it took it. Not an
/// instance's upload, 25 MB on signet: sent again only as one cut short
/// ([`cut_short`]), as one turned away busy ([`Busy`]), else left to the
/// opening's resumption, which sends none the hub answered.
const RECONNECTS: u32 = 3;

/// How many instances are uploaded beside each other, each on a circuit
/// of its own over Tor: one carries only so much.
const UPLOADS: usize = 3;

/// What an opening sent to and got from its hub since this process
/// started driving it, in bytes, and since when: its speed. Kept in
/// memory only, lost with the process, which says nothing of it then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Traffic {
    pub bytes: u64,
    pub since: Instant,
    /// About how many bytes it sends and gets in all, once it builds the
    /// first of the instances it uploads, most of it.
    pub expected: Option<u64>,
}

static TRAFFIC: LazyLock<Mutex<HashMap<[u8; 32], Traffic>>> = LazyLock::new(Mutex::default);

/// The opening `id`'s [`Traffic`], if this process drove it.
pub fn traffic(id: &[u8; 32]) -> Option<Traffic> {
    let all = TRAFFIC.lock().unwrap_or_else(PoisonError::into_inner);
    all.get(id).copied()
}

/// The openings whose holder works out a step of her own now, by when
/// she started it: a long one, garbling her instances, takes minutes on
/// a phone. In memory only, as [`TRAFFIC`].
static STEPPING: LazyLock<Mutex<HashMap<[u8; 32], Instant>>> = LazyLock::new(Mutex::default);

/// How long the holder of opening `id` has been working out a step of her
/// own, if she is.
pub fn stepping(id: &[u8; 32]) -> Option<std::time::Duration> {
    let all = STEPPING.lock().unwrap_or_else(PoisonError::into_inner);
    all.get(id).map(Instant::elapsed)
}

/// The opening this process drives that went on last: of those whose
/// holder works out a step now, the latest begun, else the one whose
/// traffic with its hub began last. None before one asked its hub anything.
pub fn latest_opening() -> Option<[u8; 32]> {
    let stepping = STEPPING.lock().unwrap_or_else(PoisonError::into_inner);
    let traffic = TRAFFIC.lock().unwrap_or_else(PoisonError::into_inner);
    latest_of(&stepping, &traffic)
}

fn latest_of(
    stepping: &HashMap<[u8; 32], Instant>,
    traffic: &HashMap<[u8; 32], Traffic>,
) -> Option<[u8; 32]> {
    let stepped = stepping.iter().max_by_key(|(_, at)| **at);
    let talked = || traffic.iter().max_by_key(|(_, t)| t.since);
    stepped
        .map(|(id, _)| *id)
        .or_else(|| talked().map(|(id, _)| *id))
}

/// Marks opening `id` as stepping until dropped.
struct Stepping([u8; 32]);

impl Stepping {
    fn start(id: [u8; 32]) -> Self {
        let mut all = STEPPING.lock().unwrap_or_else(PoisonError::into_inner);
        all.insert(id, Instant::now());
        Self(id)
    }
}

impl Drop for Stepping {
    fn drop(&mut self) {
        let mut all = STEPPING.lock().unwrap_or_else(PoisonError::into_inner);
        all.remove(&self.0);
    }
}

fn count(id: &[u8; 32], bytes: usize) {
    let mut all = TRAFFIC.lock().unwrap_or_else(PoisonError::into_inner);
    let traffic = all.entry(*id).or_insert_with(|| Traffic {
        bytes: 0,
        since: Instant::now(),
        expected: None,
    });
    traffic.bytes = traffic.bytes.saturating_add(bytes as u64);
}

/// The opening `id` has `instances` of `bytes` each to upload still, from
/// now: what it sends in all, about, unless known already.
fn expect(id: &[u8; 32], instances: usize, bytes: usize) {
    let mut all = TRAFFIC.lock().unwrap_or_else(PoisonError::into_inner);
    let traffic = all.entry(*id).or_insert_with(|| Traffic {
        bytes: 0,
        since: Instant::now(),
        expected: None,
    });
    let rest = (instances as u64).saturating_mul(bytes as u64);
    traffic
        .expected
        .get_or_insert(traffic.bytes.saturating_add(rest));
}

/// The hub refused what she sent, or she what it sent: the opening goes
/// no further.
#[derive(Debug)]
pub(super) struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

/// A step taken but not stored: nothing it says leaves, and the opening
/// goes no further this time, carried on from what is stored.
#[derive(Debug)]
pub(super) struct Unsaved;

impl std::fmt::Display for Unsaved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an opening's step not stored")
    }
}

/// A [`Refusal`] of a quote the hub no longer makes (409): its fee rose
/// as its contracts filled up, or the quote's block is too old. Asked
/// again, it quotes anew.
#[derive(Debug)]
pub(super) struct Requote;

impl std::fmt::Display for Requote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the hub quotes otherwise now")
    }
}

/// The hub turned an opening away busy (503) at its start, its deposit
/// for her reserve given up with it: the opening goes no further, and is
/// made anew a while later, of a quote and deposit asked again.
#[derive(Debug)]
pub(super) struct Later;

/// How many times an opening turned away busy at its start ([`Later`]) is
/// made anew: each asks the hub for another deposit for her reserve, of
/// which a coin has only [`licash_wallet::CLOSE_ATTEMPTS`] at a hub, and
/// most of those are left for her later openings and a restored wallet.
/// The hub refuses its quote while it admits no opening, so one turned
/// away at its start lost a race for the last place, or the hub is amiss.
pub(super) const OPENS_AGAIN: u8 = 2;
const _: () = assert!(OPENS_AGAIN < licash_wallet::CLOSE_ATTEMPTS / 2);

/// Whether the transport's error `e` is of a request whose body was cut
/// short, its connection closed while it was being written: the hub took
/// none of it. As the hub closes one it turns away busy (503) before it
/// reads the body, which a body as large as an instance learns of so.
fn cut_short(e: &str) -> bool {
    e.contains("error writing a body")
}

impl std::fmt::Display for Later {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the hub is busy: to open again later")
    }
}

pub(super) struct Driver<'a, T, C> {
    pub wallet: &'a Wallet<T>,
    pub chain: &'a C,
    pub store: &'a Store,
    pub trust: Trust,
    /// The hub's URL.
    pub hub: String,
    pub id: [u8; 32],
    /// Her machine, but while a step takes it.
    pub holder: Option<Holder>,
    /// The quote she opens on, sent with her Open the first time.
    pub quote: Option<Quote>,
    /// Whether her chain took F whole from her this time.
    pub took_f: std::sync::atomic::AtomicBool,
}

impl<T: Transport, C: Chain> Driver<'_, T, C> {
    pub fn holder(&self) -> &Holder {
        self.holder.as_ref().expect("a holder between steps")
    }

    /// Carry out `outs`, and what the hub's answers to them ask, until
    /// nothing is left to do.
    pub async fn drive(&mut self, outs: Vec<Out>) -> Result<()> {
        let mut queue: VecDeque<Out> = outs.into();
        while let Some(out) = queue.pop_front() {
            match out {
                Out::Send(message) if matches!(Kind::peek(&message), Some(Kind::Funded)) => {
                    self.funded().await;
                    // The hub broadcasts F too, once told: it may not hear.
                    if let Err(e) = self.post(message).await {
                        tracing::warn!(id = %crate::hex_id(&self.id), "telling the hub F is signed: {e:#}");
                    }
                }
                // Her opened instances, which the hub checks at length,
                // beside her kept ones' uploads: it takes them in any
                // order, and offers once it has all.
                Out::Send(message)
                    if Kind::peek(&message) == Some(Kind::Opened)
                        && matches!(queue.front(), Some(Out::Serve { .. })) =>
                {
                    let mut batch = vec![];
                    while let Some(&Out::Serve { i }) = queue.front() {
                        batch.push(i);
                        queue.pop_front();
                    }
                    for frame in self.serve(Some(message), batch).await? {
                        let Frame::Message(bytes) = frame;
                        queue.extend(self.step(Input::Message(bytes)).await?);
                    }
                }
                Out::Send(message) => {
                    let frames = self.post(message).await?;
                    for frame in frames {
                        let Frame::Message(bytes) = frame;
                        queue.extend(self.step(Input::Message(bytes)).await?);
                    }
                }
                Out::Serve { i } => {
                    // With those after it, sent beside each other.
                    let mut batch = vec![i];
                    while let Some(&Out::Serve { i }) = queue.front() {
                        batch.push(i);
                        queue.pop_front();
                    }
                    for frame in self.serve(None, batch).await? {
                        let Frame::Message(bytes) = frame;
                        queue.extend(self.step(Input::Message(bytes)).await?);
                    }
                }
                Out::Sign {
                    funding,
                    prevouts,
                    inputs,
                } => {
                    let mut signed = funding;
                    for index in inputs {
                        signed = self.wallet.sign_input(&signed, &prevouts, index)?;
                    }
                    queue.extend(self.step(Input::Signed(signed)).await?);
                }
                Out::Broadcast(tx) => {
                    self.chain.broadcast(&tx).await.map_err(|e| anyhow!(e))?;
                }
                Out::Keep { .. } | Out::Fund { .. } => {
                    bail!("the holder asked to do the hub's part")
                }
            }
        }
        Ok(())
    }

    /// Carry on from her stored state. The pinned choice is stored before
    /// either its opening shares or any rebuilt kept instance is uploaded:
    /// but those the hub answered as had, until it has them all and still
    /// waits, as if it lost one. Then all of them again, the next time.
    pub async fn resume(&mut self) -> Result<()> {
        let outs = self
            .holder()
            .pending()
            .map_err(|e| Refusal(format!("{e:#}")))?;
        let served = self.store.served_of(&self.id)?;
        let had = |o: &Out| matches!(o, Out::Serve { i } if served.contains(i));
        let serves = outs
            .iter()
            .filter(|o| matches!(o, Out::Serve { .. }))
            .count();
        let all_served = serves > 0 && outs.iter().filter(|o| had(o)).count() == serves;
        let outs: Vec<Out> = outs.into_iter().filter(|o| !had(o)).collect();
        self.drive(outs).await?;
        if all_served && self.holder().phase() == Phase::Chosen {
            tracing::warn!(id = %crate::hex_id(&self.id), "the hub has every instance, yet waits: all again");
            self.store.unserve(&self.id)?;
        }
        Ok(())
    }

    /// `driven`, or, where it failed short of F whole but for a refusal (an
    /// instance's upload dropped over Tor, say), the opening resumed up to
    /// `tries` times, sending none the hub answered.
    pub async fn carry_on(&mut self, mut driven: Result<()>, tries: u32) -> Result<()> {
        for n in 1..=tries {
            match &driven {
                Err(e)
                    if e.downcast_ref::<Refusal>().is_none()
                        && e.downcast_ref::<Unsaved>().is_none()
                        && !self.holder().wholly_funded() =>
                {
                    let id = crate::hex_id(&self.id);
                    tracing::warn!(%id, n, "carrying an opening on: {e:#}");
                    tokio::time::sleep(RETRY * n).await;
                    driven = self.resume().await;
                }
                _ => break,
            }
        }
        driven
    }

    /// Give the opening up if `result` says the hub or she refused, short
    /// of her signing F: her coin freed if she signed it into F.
    pub fn settle(&self, result: Result<()>) -> Result<()> {
        let Err(e) = result else {
            return Ok(());
        };
        let holder = self.holder();
        if e.downcast_ref::<Refusal>().is_some() && holder.abandonable() {
            self.store.abandon(&self.id, &format!("{e:#}"))?;
            if matches!(holder.phase(), Phase::Consented | Phase::Signing) {
                if let Some(f) = holder.funding() {
                    // Not reserved unless she signed before stopping: at
                    // Consented, her signature never left, the step it
                    // made unstored.
                    let _ = self.wallet.abandon_silent(&f.tx.compute_txid());
                }
            }
            tracing::warn!(id = %crate::hex_id(&self.id), "an opening given up: {e:#}");
        }
        Err(e)
    }

    async fn context(&self) -> Result<Context> {
        let tip = self.chain.height().await.map_err(|e| anyhow!(e))?;
        Ok(Context {
            tip,
            trust: self.trust,
        })
    }

    /// Her machine stepped with `input`, with state durable before effects.
    async fn step(&mut self, input: Input) -> Result<Vec<Out>> {
        let ctx = self.context().await?;
        let started = Instant::now();
        let mut holder = self.holder.take().expect("a holder between steps");
        let stepping = Stepping::start(self.id);
        let stepped = tokio::task::spawn_blocking(move || {
            let out = holder.step(input, &ctx);
            (holder, out)
        });
        let stepped = stepped.await;
        drop(stepping);
        let (holder, out) = stepped?;
        self.holder = Some(holder);
        let out = out.map_err(|e| Refusal(format!("{e:#}")))?;
        let holder = self.holder();
        let funding = holder.funding().map(|f| f.tx.compute_txid());
        let state = holder.to_bytes();
        if let Err(e) = self.store.save(&self.id, holder.phase(), funding, &state) {
            // Her signature, say, never sent unless stored: her machine as
            // stored again, if it can be read.
            let stored = self.store.state(&self.id).and_then(|(state, _)| {
                Holder::load(&state, &self.wallet.contract_secrets().seed, &ctx)
            });
            match stored {
                Ok(stored) => self.holder = Some(stored),
                Err(e) => {
                    tracing::warn!(id = %crate::hex_id(&self.id), "reloading an opening: {e:#}")
                }
            }
            return Err(e.context(Unsaved));
        }
        // Where an opening's time goes, step by step.
        let (id, phase) = (crate::hex_id(&self.id), holder.phase());
        tracing::info!(%id, ?phase, took = ?started.elapsed(), "an opening's step taken");
        Ok(out)
    }

    /// F signed whole: broadcast, and watched from now on.
    async fn funded(&self) {
        let id = crate::hex_id(&self.id);
        let Some(f) = self.holder().funding() else {
            return;
        };
        let txid = f.tx.compute_txid();
        match self.chain.broadcast(f.tx).await {
            Ok(()) => {
                self.took_f
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                tracing::info!(%id, %txid, "F broadcast")
            }
            Err(e) => tracing::warn!(%id, %txid, "broadcasting F: {e}"),
        }
    }

    /// Her instances `batch` built and uploaded, [`UPLOADS`] at a time,
    /// and `beside`, if any, sent meanwhile: the hub's answers to it, then
    /// to them, once all are, or the first failure. Each the hub answered
    /// is kept as served, whatever the others do.
    async fn serve(&mut self, beside: Option<Vec<u8>>, batch: Vec<u32>) -> Result<Vec<Frame>> {
        use futures_util::StreamExt as _;
        let holder = std::sync::Arc::new(self.holder.take().expect("a holder between steps"));
        let (id, total) = (self.id, batch.len());
        let this = &*self;
        let uploads = futures_util::stream::iter(batch).map(|i| {
            let holder = holder.clone();
            async move {
                let built = tokio::task::spawn_blocking(move || holder.instance(i)).await;
                let bytes = built.map_err(|e| anyhow!(e))??;
                expect(&id, total, bytes.len());
                let message = Envelope {
                    id,
                    kind: Kind::Instance,
                    body: wire::Instance { i, bytes }.encode(),
                }
                .to_bytes();
                let frames = this.send(message).await.inspect_err(|e| {
                    tracing::warn!(id = %crate::hex_id(&id), i, "an instance not uploaded: {e:#}");
                })?;
                // The hub has it: not sent again if the opening resumes.
                this.store.served(&id, i)?;
                Ok::<_, anyhow::Error>(frames)
            }
        });
        let beside = async {
            match beside {
                Some(message) => this.send(message).await,
                None => Ok(Vec::new()),
            }
        };
        let (beside, answers): (_, Vec<Result<Vec<Frame>>>) =
            tokio::join!(beside, uploads.buffer_unordered(UPLOADS).collect());
        let holder = std::sync::Arc::try_unwrap(holder);
        self.holder = Some(holder.unwrap_or_else(|_| unreachable!("every upload done")));
        let mut frames = beside?;
        for answer in answers {
            for frame in answer? {
                // The hub's offer, say, answering more than one of them:
                // stepped once, or her consent, then F's signing, twice.
                if !frames.contains(&frame) {
                    frames.push(frame);
                }
            }
        }
        Ok(frames)
    }

    /// POST `message` to the hub: its answer, asked again while it works.
    async fn post(&mut self, message: Vec<u8>) -> Result<Vec<Frame>> {
        if let Some(quote) = self.quote.take() {
            if matches!(Kind::peek(&message), Some(Kind::Open)) {
                let opening = Opening {
                    quote,
                    open: message,
                };
                let url = format!("{}{OPEN}", self.hub);
                return self.ask(url, opening.encode(), true).await;
            }
        }
        self.send(message).await
    }

    /// POST `message`, of an opening under way, to the hub: its answer,
    /// asked again while it works.
    async fn send(&self, message: Vec<u8>) -> Result<Vec<Frame>> {
        let route = if Kind::peek(&message) == Some(Kind::Instance) {
            INSTANCE
        } else {
            STEP
        };
        let path = route.replace("{id}", &crate::hex_id(&self.id));
        self.ask(format!("{}{path}", self.hub), message, false)
            .await
    }

    /// POST `body` to `url`: the hub's answer, asked again while it works,
    /// and while it is busy unless `start`, the opening's first message:
    /// turned away then, it keeps nothing of it ([`Later`]).
    async fn ask(&self, url: String, body: Vec<u8>, start: bool) -> Result<Vec<Frame>> {
        let started = Instant::now();
        let instance = Kind::peek(&body) == Some(Kind::Instance);
        let mut dropped = if instance { RECONNECTS } else { 0 };
        let mut busy = Busy::default();
        for _ in 0..PATIENCE {
            let request = Some(body.clone());
            let response = match self.wallet.transport().request(&url, request).await {
                Ok(response) => response,
                Err(e) if dropped < RECONNECTS => {
                    dropped += 1;
                    let id = crate::hex_id(&self.id);
                    tracing::warn!(%id, dropped, "asking the hub again: {e}");
                    tokio::time::sleep(RETRY * dropped).await;
                    continue;
                }
                // An instance's upload cut short, which the hub took none
                // of: sent again, a while later, as any turned away busy.
                // Not one whose answer alone was lost: left to resumption.
                Err(e) if instance && cut_short(&e) && busy.wait().await => {
                    let id = crate::hex_id(&self.id);
                    tracing::info!(%id, "an instance's upload cut short, sent again: {e}");
                    continue;
                }
                Err(e) => bail!("{}: {e}", self.hub),
            };
            count(&self.id, body.len() + response.body.len());
            match response.status {
                200 => {
                    let (id, took) = (crate::hex_id(&self.id), started.elapsed());
                    tracing::info!(%id, ?took, "the hub answered an opening's step");
                    return Frame::decode_all(&response.body).context("the hub's answer");
                }
                202 => tokio::time::sleep(RETRY).await,
                503 if start => {
                    let refused = failed(&self.hub, 400, &response.body);
                    return Err(refused.context(Later));
                }
                503 if busy.wait().await => {}
                status => return Err(failed(&self.hub, status, &response.body)),
            }
        }
        bail!("{}: still working on the opening: later", self.hub)
    }
}

/// The hub's answer of `status`: refused if it will refuse it again.
pub(super) fn failed(hub: &str, status: u16, body: &[u8]) -> anyhow::Error {
    let reason = String::from_utf8_lossy(&body[..body.len().min(500)]).into_owned();
    let refusal = Refusal(format!("{hub} refused it: {reason}"));
    if status == 409 {
        anyhow::Error::new(refusal).context(Requote)
    } else if (400..500).contains(&status) {
        refusal.into()
    } else {
        anyhow!("{hub}: status {status}: {reason}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 409 is a refusal, its opening given up, of a quote to ask again;
    /// another 4xx a refusal alone; a 5xx neither.
    #[test]
    fn a_stale_quote_is_refused_to_be_asked_again() {
        let stale = failed("hub", 409, b"not the hub's quote: ask again");
        assert!(stale.downcast_ref::<Refusal>().is_some());
        assert!(stale.downcast_ref::<Requote>().is_some());
        assert!(format!("{stale:#}").contains("not the hub's quote"));
        let bad = failed("hub", 400, b"no");
        assert!(bad.downcast_ref::<Refusal>().is_some());
        assert!(bad.downcast_ref::<Requote>().is_none());
        let down = failed("hub", 503, b"later");
        assert!(down.downcast_ref::<Refusal>().is_none());
        assert!(down.downcast_ref::<Requote>().is_none());
    }

    /// Turned away busy, a holder waits half to all of a wait doubling
    /// from two seconds to thirty, and asks again within three minutes.
    #[test]
    fn a_holder_turned_away_busy_comes_back_later_and_apart() {
        let s = Duration::from_secs;
        assert_eq!(busy_wait(0, 0.0), s(1));
        assert_eq!(busy_wait(0, 0.999_999), s(2) - Duration::from_micros(1));
        assert_eq!(busy_wait(2, 0.0), s(4));
        assert_eq!(busy_wait(4, 0.0), s(15));
        assert_eq!(busy_wait(40, 0.0), s(15));
        assert!(busy_wait(40, 0.999) <= BUSY_MOST);
        let j = jitter();
        assert!((0.0..1.0).contains(&j));
    }

    /// Only a body cut short as it was written, as the hub closes one it
    /// turns away unread: not one whose answer was lost after it was sent.
    #[test]
    fn an_upload_is_cut_short_only_as_its_body_was_written() {
        let pipe = "error sending request: client error (SendRequest): \
                    error writing a body to connection: Broken pipe (os error 32)";
        assert!(cut_short(pipe));
        assert!(!cut_short("no answer over Tor in 120 s"));
        assert!(!cut_short("error sending request: operation timed out"));
        assert!(!cut_short(
            "error sending request: client error (Connect): Connection refused"
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_holder_turned_away_busy_gives_up_after_three_minutes() {
        let start = tokio::time::Instant::now();
        let mut busy = Busy::default();
        let mut asked = 0;
        while busy.wait().await {
            asked += 1;
        }
        let waited = start.elapsed();
        assert!(waited <= BUSY_PATIENCE, "{waited:?}");
        assert!(waited >= BUSY_PATIENCE - BUSY_MOST, "{waited:?}");
        assert!((6..=20).contains(&asked), "{asked}");
    }

    #[test]
    fn an_opening_is_stepping_while_its_holder_works_out_a_step() {
        let id = [7; 32];
        assert_eq!(stepping(&id), None);
        let marked = Stepping::start(id);
        assert!(stepping(&id).is_some());
        assert_eq!(stepping(&[8; 32]), None);
        drop(marked);
        assert_eq!(stepping(&id), None);
    }

    #[test]
    fn the_latest_opening_is_one_stepping_else_the_last_to_talk_to_its_hub() {
        let start = Instant::now();
        let at = |s| start + std::time::Duration::from_secs(s);
        let talked = |s| Traffic {
            bytes: 1,
            since: at(s),
            expected: None,
        };
        let mut stepping = HashMap::new();
        let mut traffic = HashMap::new();
        assert_eq!(latest_of(&stepping, &traffic), None);
        traffic.insert([1; 32], talked(1));
        traffic.insert([2; 32], talked(5));
        assert_eq!(latest_of(&stepping, &traffic), Some([2; 32]));
        stepping.insert([1; 32], at(9));
        assert_eq!(latest_of(&stepping, &traffic), Some([1; 32]));
        stepping.insert([3; 32], at(10));
        assert_eq!(latest_of(&stepping, &traffic), Some([3; 32]));
    }
}
