//! The hub service: a [`Hub`] behind the v1 HTTP API of [`licash_api`],
//! and the [`Services`] it runs beside it.

pub mod admission;
pub mod announce;
pub mod dashboard;
pub mod deposit;
pub mod inbox;
pub mod lightning;
pub mod notify;
pub mod payouts;
pub mod peer;
pub mod tweaks;
pub mod watch;

/// Fixtures of the hub's database for unit tests.
#[cfg(test)]
pub(crate) mod testing {
    /// The hub's database in `dir`: made once, of the hub's kind, holding no
    /// component yet, for a module's tables to be made in.
    pub(crate) fn hub_file(dir: &std::path::Path) -> std::path::PathBuf {
        let file = dir.join("hub.sqlite");
        if !file.exists() {
            drop(licash_store::create(&file, licash_store::Kind::Hub).unwrap());
        }
        file
    }
}

use std::sync::Arc;

use admission::Admission;
pub use admission::{AdmissionSource, Ingress, PER_SOURCE};
use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        DefaultBodyLimit, Path, Query, State,
    },
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use inbox::Inbox;
use licash_api::{
    Code, Deposit, DepositStatus, Depositing, Evidenced, Info, Inquire, Issued, Lock, LockState,
    Locked, Offer, Offered, Pay, Paying, Problem, Receive, ReceiveStatus, Receiving, Refund,
    Released, Settle, TweaksQuery, Unlink, Unlinked,
};
use licash_hub::{Error, Hub, Settled};
use lightning::Gateway;
use tower_http::trace::TraceLayer;
use tweaks::Tweaks;

/// The largest request body: a spend of the most inputs and outputs the
/// protocol allows (`licash::spend::MAX_INPUTS`, `MAX_OUTPUTS`) fits well
/// within it. What the hub retires notes for is bounded apart, by what a
/// dispute can cite (`licash_hub::MAX_EVIDENCE_BYTES`).
pub const BODY_LIMIT: usize = 1 << 20;

/// `ok`, or 503 once the hub halted.
pub const HEALTH: &str = "/health";

/// The most requests it serves at once: those past it are answered
/// unavailable at once, rather than queued for the threads verifying
/// proofs and waiting on fsyncs without bound.
pub const MAX_SERVING: usize = 256;

/// Blocks below the newest indexed from which tweaks are answered as
/// never changing: no reorganization reaches so deep.
pub const IMMUTABLE_DEPTH: u32 = 144;

/// Holders' claims in `openings` answered from `hub`'s ledger: decided
/// against the spends and locks it holds, and the notes of each published
/// claim retired, spent by nobody else, since she may be paid for them on
/// Bitcoin. The notes she funds a contract with are issued there too.
pub fn answer_from(openings: &licash_contracts::hub::Openings, hub: Arc<Hub>) {
    let issuer = hub.clone();
    openings.issue_with(Arc::new(move |issue, new| {
        issue_funded(&issuer, issue, new)
    }));
    let ledger = hub.clone();
    openings.evidence_with(Arc::new(move |claim, published_at| {
        let timed = claim.parts().sources.iter().any(|s| s.terms().is_some());
        let top = ledger.scanned()?.map(|(top, _)| top);
        scanned_for(timed, top, published_at)?;
        let found = ledger.found(claim)?;
        Ok(licash_contracts::hub::Found {
            evidence: found.evidence,
            unread: found.unread,
        })
    }));
    let ledger = hub.clone();
    openings.claims_with(Arc::new(move |contract, named| {
        Ok(hub.retire_claimed(contract, named.held(), named.locks())?)
    }));
    let reader = ledger.clone();
    openings.folds_with(Arc::new(licash_contracts::hub::FoldLedger {
        claimable: Box::new(move |contract, notes| Ok(reader.fold_claimable(contract, notes)?)),
        retire: Box::new(move |contract, publication| {
            Ok(ledger.claim_for_fold(contract, publication)?)
        }),
    }));
}

/// The deposit a contract's default pays her reserve to bound to the
/// contract in `openings`, from `deposits`: the hub's own, asked for as the
/// contract names it, else the opening is refused.
pub fn close_with_deposits(
    openings: &licash_contracts::hub::Openings,
    deposits: Arc<deposit::Gateway>,
) {
    let release = deposits.clone();
    openings.close_with(
        Arc::new(move |script, contract, pays, fee, timeout| {
            deposits.bind_close(script, contract, pays, fee, timeout)
        }),
        Arc::new(move |contract| release.release_close(contract)),
    );
}

/// Her funded notes `issue` on `hub`'s ledger, by its own lock under the
/// hash of her issue's preimage, settled at once: the lock's id. Of a lock
/// under that hash already, that one, settled; else none unless `new`.
/// The lock expires as late as the hub admits, though it never waits.
fn issue_funded(
    hub: &Hub,
    issue: &licash_contracts::hub::FundedIssue,
    new: bool,
) -> anyhow::Result<Option<[u8; 32]>> {
    let hash = licash::spend::lock_hash(&issue.preimage);
    let lock = match hub.own_lock_of(&hash)? {
        Some(lock) => lock,
        None if !new => return Ok(None),
        None => {
            let (top, _) = hub
                .scanned()?
                .ok_or_else(|| anyhow::anyhow!("the hub follows no chain yet"))?;
            let checkpoint = hub
                .checkpoint()
                .ok_or_else(|| anyhow::anyhow!("the hub has no lock checkpoint yet"))?;
            let t = hub.info().policy.timing;
            let expiry = t
                .window
                .checked_sub(t.min_depth.saturating_add(t.reaction))
                .filter(|left| *left > 0)
                .and_then(|left| top.checked_add(left))
                .ok_or_else(|| anyhow::anyhow!("the hub's window admits no lock"))?;
            let terms = licash::spend::TimedTerms::new(
                checkpoint.profile(),
                checkpoint.commitment(),
                expiry,
                t.min_depth,
                hash,
            )?;
            hub.lock_own(&issue.keyset, issue.ephemeral, issue.outputs.clone(), terms)?
        }
    };
    let id = lock.proposal.id();
    hub.settle(&id, &issue.preimage)?;
    Ok(Some(*id.as_bytes()))
}

/// New contracts in `openings` opened on `hub`'s lock checkpoints: on a
/// block buried as one, kept as its newest if newer. Every lock named
/// after a contract opens is then judged on the chain its statement
/// reads.
pub fn open_on_lock_checkpoints(openings: &licash_contracts::hub::Openings, hub: Arc<Hub>) {
    let bury = hub.info().policy.timing.bury;
    let scan = hub.clone();
    openings.checkpoints_with(licash_contracts::hub::LockCheckpoints {
        height: Box::new(move |tip| {
            let (top, _) = scan
                .scanned()?
                .ok_or_else(|| anyhow::anyhow!("the hub follows no chain yet"))?;
            lock_checkpoint_height(top, tip, bury)
        }),
        keep: Box::new(move |checkpoint| {
            if hub
                .checkpoint()
                .is_some_and(|newest| newest.height() >= checkpoint.height())
            {
                return Ok(());
            }
            Ok(hub.add_checkpoint(checkpoint)?)
        }),
    });
}

/// Whether a ledger scanned to `top`, if it follows a chain, may give its
/// evidence against a claim published at `published_at`, which cites a
/// lock if `timed`. Its evidence is pinned once given, and an activation
/// up to that block gives a preimage that voids her refund: a claim of a
/// lock waits for the scan. One of none needs no chain, nor does a
/// ledger following none, which admitted no lock.
fn scanned_for(timed: bool, top: Option<u32>, published_at: u32) -> anyhow::Result<()> {
    if let (true, Some(top)) = (timed, top) {
        anyhow::ensure!(
            top >= published_at,
            "the ledger has scanned to {top}, not yet the claim's block {published_at}"
        );
    }
    Ok(())
}

/// The height of the newest lock checkpoint of a ledger scanned to `top`,
/// the chain's tip at `tip`: buried `bury` deep in its scan. None while
/// its scan lags the tip by more than `bury` blocks: a contract opened on
/// it would be shortened by as many, or refused by her wallet.
fn lock_checkpoint_height(top: u32, tip: u32, bury: u32) -> anyhow::Result<u32> {
    anyhow::ensure!(
        tip.saturating_sub(top) <= bury,
        "the hub's scan of the chain is at {top}, the tip at {tip}: it opens no contract until it catches up"
    );
    Ok((top.min(tip) + 1).saturating_sub(bury))
}

/// What a hub serves beside its ledger, each if it runs it.
#[derive(Clone, Default)]
pub struct Services {
    pub gateway: Option<Arc<Gateway>>,
    pub deposits: Option<Arc<deposit::Gateway>>,
    pub tweaks: Option<Arc<Tweaks>>,
    /// The payments it keeps for their payees, as their payers ask.
    pub inbox: Option<Arc<Inbox>>,
    /// The Nostr relays of its wallets' mailboxes, named in its info.
    pub relays: Vec<String>,
    /// The recovery contracts it opens, funded by its node's wallet.
    pub contracts: Option<Arc<licash_contracts::hub::Openings>>,
    /// The API of the provider of the swaps into it, if it is one.
    pub swaps: Option<Router>,
    /// The URLs wallets reach it at, named in its info: those it
    /// announces, and its onion service's once that runs.
    pub urls: Arc<std::sync::RwLock<Vec<String>>>,
    /// The proxies in front of it whose clients it admits by.
    pub ingress: Arc<Ingress>,
}

/// The API of `hub`, with the paths of its `services`.
pub fn router(hub: Arc<Hub>, services: Services) -> Router {
    let Services {
        gateway,
        deposits,
        tweaks,
        inbox,
        contracts,
        swaps,
        ingress,
        ..
    } = services.clone();
    let info_of = Router::new()
        .route(licash_api::INFO, get(info))
        .with_state((hub.clone(), services));
    let release_of = Router::new()
        .route(licash_api::RELEASE, post(release))
        .with_state((hub.clone(), inbox.clone()));
    let mut api = Router::new()
        .route(licash_api::OFFER, post(offer))
        .route(licash_api::UNLINK, post(unlink))
        .route(licash_api::INQUIRE, post(inquire))
        .route(licash_api::LOCK, post(lock))
        .route(licash_api::LOCK_STATE, get(lock_state))
        .route(licash_api::SETTLE, post(settle))
        .route(licash_api::REFUND, post(refund))
        .route(HEALTH, get(health))
        .with_state(hub)
        .merge(info_of)
        .merge(release_of);
    if let Some(gateway) = gateway {
        api = api.merge(
            Router::new()
                .route(licash_api::LN_PAY, post(ln_pay))
                .route(licash_api::LN_RECEIVE, post(ln_receive))
                .route(licash_api::LN_RECEIVE_STATE, get(ln_receive_state))
                .with_state(gateway),
        );
    }
    if let Some(deposits) = deposits {
        api = api.merge(
            Router::new()
                .route(licash_api::DEPOSIT, post(deposit))
                .route(licash_api::DEPOSIT_STATE, get(deposit_state))
                .route(licash_api::DEPOSIT_LOCK, post(deposit_lock))
                .with_state(deposits),
        );
    }
    if let Some(inbox) = inbox {
        api = api.merge(
            Router::new()
                .route(licash_api::inbox::INBOX, get(inbox_feed))
                .route(licash_api::inbox::TAKE, post(inbox_take))
                .route(licash_api::inbox::ACK, post(inbox_ack))
                .route(licash_api::inbox::ACKS, post(inbox_acks))
                .with_state(inbox),
        );
    }
    if let Some(index) = tweaks {
        api = api.merge(
            Router::new()
                .route(licash_api::TWEAKS, get(chain_tweaks))
                .with_state(index),
        );
    }
    if let Some(swaps) = swaps {
        // Its own body limit, of a provider's requests.
        api = api.merge(swaps);
    }
    let mut api = shed(api.layer(DefaultBodyLimit::max(BODY_LIMIT)), MAX_SERVING);
    if let Some(openings) = contracts {
        // Its own body limit, budgets and times: an opening's messages are
        // large, and arrive slowly over Tor.
        api = api.merge(licash_contracts::hub::router(openings));
    }
    // Each request's source, resolved once, before any handler admits by it.
    api.layer(axum::middleware::from_fn_with_state(
        ingress,
        admission::resolve,
    ))
    .layer(TraceLayer::new_for_http())
}

/// `router`, serving at most `most` requests at once but its [`HEALTH`]:
/// any past them answered unavailable (503) at once, and any whose body is
/// still arriving [`licash_swaps_service::BODY_TIME`] after its head
/// refused.
pub fn shed(router: Router, most: usize) -> Router {
    licash_swaps_service::shed_saying(router, most, "the hub is too busy now")
}

/// A [`Problem`] answered with its status.
#[derive(Debug)]
pub struct Failure(pub Problem);

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self.0)).into_response()
    }
}

impl From<Problem> for Failure {
    fn from(problem: Problem) -> Self {
        Self(problem)
    }
}

impl From<JsonRejection> for Failure {
    fn from(rejection: JsonRejection) -> Self {
        Self(Problem::invalid(rejection.body_text()))
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        let code = match &e {
            Error::Refused(refusal) => refusal.code(),
            Error::Invalid(_) => Code::Invalid,
            _ => {
                tracing::error!(error = %e, "request failed");
                return Self(Problem::new(Code::Unavailable, "the hub cannot serve now"));
            }
        };
        tracing::debug!(error = %e, "request refused");
        Self(Problem::new(code, e.to_string()))
    }
}

type Answer<T> = Result<Json<T>, Failure>;

/// Run `op` off the async workers: it verifies curve proofs and waits on
/// the ledger's fsync.
async fn blocking<T: Send + 'static>(
    hub: Arc<Hub>,
    op: impl FnOnce(&Hub) -> Result<T, Failure> + Send + 'static,
) -> Answer<T> {
    tokio::task::spawn_blocking(move || op(&hub))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "request task failed");
            Failure(Problem::new(Code::Unavailable, "the hub cannot serve now"))
        })?
        .map(Json)
}

async fn health(State(hub): State<Arc<Hub>>) -> Result<&'static str, Failure> {
    if hub.halted() {
        return Err(Failure(Problem::new(Code::Unavailable, "the hub halted")));
    }
    Ok("ok")
}

async fn info(State((hub, services)): State<(Arc<Hub>, Services)>) -> Answer<Info> {
    let tweaks = services.tweaks.clone();
    let Json(mut info) = blocking(hub, move |hub| {
        let mut info = hub.advertise()?;
        info.tweaks = match tweaks.map(|tweaks| tweaks.first()) {
            Some(Ok(first)) => first,
            Some(Err(e)) => {
                tracing::error!("reading the tweak index: {e:#}");
                None
            }
            None => None,
        };
        Ok(info)
    })
    .await?;
    info.lightning = services.gateway.and_then(|gateway| gateway.advertise());
    if info.lightning.is_some() {
        info.features.push(licash_api::FEATURE_MEMO.into());
        info.features.push(licash_api::FEATURE_LNURL.into());
    }
    if services.inbox.is_some() {
        info.features.push(licash_api::inbox::FEATURE_NOTE.into());
    }
    info.deposits = services.deposits.map(|deposits| deposits.advertise());
    info.contracts = services.contracts.map(|openings| openings.advertise());
    info.relays = services.relays;
    info.urls = (services.urls.read()).map_or_else(|e| e.into_inner().clone(), |urls| urls.clone());
    Ok(Json(info))
}

async fn offer(
    State(hub): State<Arc<Hub>>,
    body: Result<Json<Offer>, JsonRejection>,
) -> Answer<Offered> {
    let Json(body) = body?;
    blocking(hub, move |hub| {
        let (proposal, notes) = body.decode(|id| hub.keyset(id))?;
        let holds = body.holds()?;
        let grant = hub.offer_held(&proposal, &notes, holds.as_deref())?;
        Ok(Offered::new(&grant)?)
    })
    .await
}

/// Released, then kept for its payee if asked and the hub keeps payments:
/// the unlock answered even if the inbox fails, the payment then not kept.
async fn release(
    State((hub, inbox)): State<(Arc<Hub>, Option<Arc<Inbox>>)>,
    body: Result<Json<licash_api::inbox::Release>, JsonRejection>,
) -> Answer<licash_api::inbox::Released> {
    let Json(body) = body?;
    blocking(hub, move |hub| {
        let (signed, notes) = body.release.decode(|id| hub.keyset(id))?;
        let keep = match (&inbox, &body.keep) {
            (Some(inbox), Some(keep)) => {
                keep.decode()?;
                Some((inbox, keep))
            }
            _ => None,
        };
        let unlock = hub.release(&signed, &notes)?;
        let kept = keep.is_some_and(|(inbox, keep)| {
            let proposal = signed.proposal();
            let receipt = licash_api::inbox::Receipt {
                release: body.release.clone(),
                unlock: licash_api::Hex(unlock.to_vec()),
                note: keep.note.clone(),
            };
            let kept = inbox.keep(&proposal.id(), &proposal.ephemeral().0, keep, &receipt);
            kept.inspect_err(|e| tracing::error!("keeping a payment: {e:#}"))
                .is_ok()
        });
        Ok(licash_api::inbox::Released {
            released: Released::new(&unlock),
            kept,
        })
    })
    .await
}

async fn unlink(
    State(hub): State<Arc<Hub>>,
    body: Result<Json<Unlink>, JsonRejection>,
) -> Answer<Unlinked> {
    let Json(body) = body?;
    blocking(hub, move |hub| {
        Ok(Unlinked::new(&hub.unlink(&body.decode()?)?))
    })
    .await
}

async fn inquire(
    State(hub): State<Arc<Hub>>,
    body: Result<Json<Inquire>, JsonRejection>,
) -> Answer<Evidenced> {
    let Json(body) = body?;
    blocking(hub, move |hub| {
        let (keyset, at, notes) = body.decode()?;
        Ok(Evidenced::new(&hub.inquire(&keyset, at, &notes)?))
    })
    .await
}

async fn lock(
    State(hub): State<Arc<Hub>>,
    body: Result<Json<Lock>, JsonRejection>,
) -> Answer<Locked> {
    let Json(body) = body?;
    blocking(hub, move |hub| {
        let (signed, notes) = body.decode(|id| hub.keyset(id))?;
        Ok(Locked::new(&hub.lock(&signed, &notes)?))
    })
    .await
}

async fn lock_state(State(hub): State<Arc<Hub>>, Path(id): Path<String>) -> Answer<LockState> {
    blocking(hub, move |hub| {
        let id = licash_api::lock_id(&id)?;
        let lock = hub.locked(&id)?;
        let signatures = hub.lock_signatures(&id)?;
        let settled = lock.settled.map(|branch| match branch {
            Settled::Pay => licash_api::Settled::Pay,
            Settled::Refund => licash_api::Settled::Refund,
        });
        let terms = lock.proposal.lock().map(|l| *l.terms().checkpoint());
        let checkpoint = terms.map(|c| hub.checkpoint_named(&c)).transpose()?;
        let state = LockState::new(&lock.proposal, &lock.certificate, settled, lock.preimage)
            .with_signatures(&signatures);
        Ok(match checkpoint.flatten() {
            Some(checkpoint) => state.with_checkpoint(&checkpoint),
            None => state,
        })
    })
    .await
}

async fn settle(
    State(hub): State<Arc<Hub>>,
    body: Result<Json<Settle>, JsonRejection>,
) -> Answer<Issued> {
    let Json(body) = body?;
    blocking(hub, move |hub| {
        let (id, preimage) = body.decode()?;
        Ok(Issued::new(&hub.settle(&id, &preimage)?))
    })
    .await
}

async fn refund(
    State(hub): State<Arc<Hub>>,
    body: Result<Json<Refund>, JsonRejection>,
) -> Answer<Issued> {
    let Json(body) = body?;
    blocking(hub, move |hub| {
        Ok(Issued::new(&hub.refund(&body.decode()?)?))
    })
    .await
}

async fn ln_pay(
    State(gateway): State<Arc<Gateway>>,
    body: Result<Json<Pay>, JsonRejection>,
) -> Answer<Paying> {
    let Json(body) = body?;
    Ok(Json(gateway.pay(&body).await?))
}

async fn ln_receive(
    State(gateway): State<Arc<Gateway>>,
    Admission(source): Admission,
    body: Result<Json<Receive>, JsonRejection>,
) -> Answer<Receiving> {
    let Json(body) = body?;
    Ok(Json(gateway.receive(&body, source.as_ref()).await?))
}

async fn deposit(
    State(deposits): State<Arc<deposit::Gateway>>,
    Admission(source): Admission,
    body: Result<Json<Deposit>, JsonRejection>,
) -> Answer<Depositing> {
    let Json(body) = body?;
    Ok(Json(deposits.deposit(&body, source.as_ref()).await?))
}

async fn deposit_state(
    State(deposits): State<Arc<deposit::Gateway>>,
    Path(refund): Path<String>,
) -> Answer<DepositStatus> {
    let hash = deposits.deposit_of(&licash_api::hash_of(&refund)?)?;
    Ok(Json(deposits.deposit_status(&hash)?))
}

async fn deposit_lock(
    State(deposits): State<Arc<deposit::Gateway>>,
    Path(refund): Path<String>,
) -> Answer<DepositStatus> {
    let hash = deposits.deposit_of(&licash_api::hash_of(&refund)?)?;
    Ok(Json(deposits.ask_lock(&hash)?))
}

/// The tweaks of the blocks asked for, answered as never changing once
/// [`IMMUTABLE_DEPTH`] below the newest indexed, so that a cache in front
/// of the hub serves the same ranges to every wallet.
async fn chain_tweaks(
    State(tweaks): State<Arc<Tweaks>>,
    query: Result<Query<TweaksQuery>, QueryRejection>,
) -> Result<Response, Failure> {
    let Query(TweaksQuery { from, count }) = query.map_err(|e| Problem::invalid(e.body_text()))?;
    if !(1..=licash_api::MAX_TWEAK_BLOCKS).contains(&count) {
        return Err(Problem::invalid(format!(
            "count: 1 to {} blocks",
            licash_api::MAX_TWEAK_BLOCKS
        ))
        .into());
    }
    let unavailable = |e: anyhow::Error| {
        tracing::error!("reading the tweak index: {e:#}");
        Failure(Problem::new(Code::Unavailable, "the hub cannot serve now"))
    };
    let read = tokio::task::spawn_blocking(move || {
        let first = tweaks.first()?;
        let top = tweaks.top()?.map(|(height, _)| height);
        anyhow::Ok((first, top, tweaks.blocks(from, count)?))
    });
    let (first, top, blocks) = read
        .await
        .map_err(|e| unavailable(e.into()))?
        .map_err(unavailable)?;
    match first {
        None => {
            return Err(Problem::new(Code::Unavailable, "no tweaks indexed yet").into());
        }
        Some(first) if from < first => {
            return Err(
                Problem::invalid(format!("tweaks are served from block {first} on")).into(),
            );
        }
        Some(_) => {}
    }
    let last = from.saturating_add(count - 1);
    let settled = top.is_some_and(|top| last.saturating_add(IMMUTABLE_DEPTH) <= top);
    let cache = match settled && blocks.len() == count as usize {
        true => "public, max-age=31536000, immutable",
        false => "no-cache",
    };
    Ok(([(header::CACHE_CONTROL, cache)], Json(blocks)).into_response())
}

async fn ln_receive_state(
    State(gateway): State<Arc<Gateway>>,
    Path(hash): Path<String>,
) -> Answer<ReceiveStatus> {
    let hash = licash_api::hash_of(&hash)?;
    Ok(Json(gateway.receive_status(&hash)?))
}

/// Run `op` on the inbox, off the async workers: it waits on its fsync.
async fn inboxed<T: Send + 'static>(
    inbox: Arc<Inbox>,
    op: impl FnOnce(&Inbox) -> Result<T, Failure> + Send + 'static,
) -> Answer<T> {
    let unavailable = || Failure(Problem::new(Code::Unavailable, "the hub cannot serve now"));
    tokio::task::spawn_blocking(move || op(&inbox))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "inbox task failed");
            unavailable()
        })?
        .map(Json)
}

fn inbox_failed(e: anyhow::Error) -> Failure {
    tracing::error!("the inbox: {e:#}");
    Failure(Problem::new(Code::Unavailable, "the hub cannot serve now"))
}

async fn inbox_feed(
    State(inbox): State<Arc<Inbox>>,
    query: Result<Query<licash_api::inbox::Query>, QueryRejection>,
) -> Answer<licash_api::inbox::Feed> {
    let Query(query) = query.map_err(|e| Problem::invalid(e.body_text()))?;
    inboxed(inbox, move |inbox| {
        inbox.feed(query.after).map_err(inbox_failed)
    })
    .await
}

async fn inbox_take(
    State(inbox): State<Arc<Inbox>>,
    body: Result<Json<licash_api::inbox::Take>, JsonRejection>,
) -> Answer<licash_api::inbox::Taken> {
    let Json(body) = body?;
    let keys = body.payments.iter().map(|p| &p.key);
    let keys = licash_api::inbox::arrays::<32>(keys, "key")?;
    let asked: Vec<(u64, [u8; 32])> = body.payments.iter().map(|p| p.seq).zip(keys).collect();
    inboxed(inbox, move |inbox| {
        let payments = inbox.take(&asked).map_err(inbox_failed)?;
        Ok(licash_api::inbox::Taken { payments })
    })
    .await
}

async fn inbox_ack(
    State(inbox): State<Arc<Inbox>>,
    body: Result<Json<licash_api::inbox::Acknowledge>, JsonRejection>,
) -> Answer<licash_api::inbox::Acknowledged> {
    let Json(body) = body?;
    let keys = licash_api::inbox::arrays::<32>(body.acks.iter().map(|a| &a.key), "key")?;
    let acks = licash_api::inbox::arrays::<32>(body.acks.iter().map(|a| &a.ack), "ack")?;
    let told: Vec<_> = keys.into_iter().zip(acks).collect();
    inboxed(inbox, move |inbox| {
        let acked = inbox.acknowledge(&told).map_err(inbox_failed)?;
        Ok(licash_api::inbox::Acknowledged { acked })
    })
    .await
}

async fn inbox_acks(
    State(inbox): State<Arc<Inbox>>,
    body: Result<Json<licash_api::inbox::AskAcks>, JsonRejection>,
) -> Answer<licash_api::inbox::Acks> {
    let Json(body) = body?;
    let keys = licash_api::inbox::arrays::<32>(body.keys.iter(), "key")?;
    inboxed(inbox, move |inbox| {
        let acks = inbox.acks(&keys).map_err(inbox_failed)?;
        let acks = acks
            .into_iter()
            .map(|ack| ack.map(|ack| licash_api::Hex(ack.to_vec())))
            .collect();
        Ok(licash_api::inbox::Acks { acks })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claim_of_a_lock_waits_for_the_scan_of_its_block() {
        assert!(scanned_for(true, Some(99), 100).is_err());
        assert!(scanned_for(true, Some(100), 100).is_ok());
        // Of no lock, or following no chain: at once.
        assert!(scanned_for(false, Some(10), 100).is_ok());
        assert!(scanned_for(true, None, 100).is_ok());
    }

    #[test]
    fn contracts_open_buried_in_a_scan_that_keeps_up_with_the_tip() {
        assert_eq!(lock_checkpoint_height(100, 100, 6).unwrap(), 95);
        assert_eq!(lock_checkpoint_height(100, 106, 6).unwrap(), 95);
        // A tip behind the scan (a node of another view): from the tip.
        assert_eq!(lock_checkpoint_height(100, 98, 6).unwrap(), 93);
        assert!(lock_checkpoint_height(100, 107, 6).is_err());
        assert_eq!(lock_checkpoint_height(3, 3, 6).unwrap(), 0);
    }
}
