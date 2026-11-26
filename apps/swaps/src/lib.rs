//! The swap provider service: a [`Provider`] behind the HTTP API of
//! [`licash_api::swaps`], the steps that take its swaps on, the chain its
//! payouts on Bitcoin follow, the node its Lightning payments and receipts
//! follow, the donations it takes over LNURL-pay (`lnurl`), and its
//! announcement on Nostr.

pub mod dashboard;
pub mod keeper;
pub mod notify;

use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bitcoin::{BlockHash, Transaction};
use licash_api::{
    swaps::{
        self, ChainRequest, ChainSwap, LightningRequest, LightningSwap, ReceiveRequest, Request,
        Swap,
    },
    Code, Problem, ReceiveStatus, Receiving,
};
use licash_chain_client::Source;
use licash_nostr::{Announcement, Announcer, Role, Route};
use licash_serve::{Admission, AdmissionSource};
use licash_swaps::{Chain, Provider};
use licash_wallet::Transport;
use serde_json::{json, Value};
use tower_http::trace::TraceLayer;

/// The largest request body: a swap request is far smaller.
pub const BODY_LIMIT: usize = 64 * 1024;

/// `ok` while the service serves: never shed.
pub const HEALTH: &str = licash_serve::HEALTH;

/// The most requests it serves at once: those past it are answered
/// unavailable at once, rather than queued without bound.
pub const MAX_SERVING: usize = 256;

/// A chain source, as the provider reads Bitcoin and broadcasts through it.
pub struct ChainView(pub Source);

fn text(e: anyhow::Error) -> String {
    format!("{e:#}")
}

impl licash_wallet::Blocks for ChainView {
    async fn height(&self) -> Result<u32, String> {
        Ok(self.0.tip().await.map_err(text)?.height)
    }

    async fn hash(&self, height: u32) -> Result<BlockHash, String> {
        self.0.hash(height).await.map_err(text)
    }

    async fn filter(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, String> {
        self.0.filter(hash).await.map_err(text)
    }

    async fn block(&self, hash: &BlockHash) -> Result<bitcoin::Block, String> {
        self.0.block(hash).await.map_err(text)
    }
}

impl Chain for ChainView {
    async fn broadcast(&self, tx: &Transaction) -> Result<(), String> {
        self.0.broadcast(tx).await.map(|_| ()).map_err(text)
    }

    async fn fee_rate(&self, blocks: u16) -> Result<Option<bitcoin::FeeRate>, String> {
        self.0.fee_rate(blocks).await.map_err(text)
    }
}

struct Served<T: Transport, C> {
    provider: Arc<Provider<T>>,
    nostr: Option<String>,
    /// The chain payouts are paid on, if the provider pays out.
    chain: Option<Arc<C>>,
}

/// How a provider serves its API, beside what it takes.
#[derive(Default)]
pub struct Serving {
    /// The key it announces itself under on Nostr, which its info names.
    pub nostr: Option<String>,
    /// The chain it pays out on Bitcoin on ([`Provider::pay_out`]), if it
    /// does.
    pub chain: Option<Arc<ChainView>>,
    /// The proxies in front of it whose clients it admits by: the receipts
    /// and donations asked and not paid are bounded by source
    /// ([`licash_swaps::PER_SOURCE`]).
    pub ingress: Arc<licash_serve::Ingress>,
}

/// The API of `provider`, as `serving` says, its donations over LNURL-pay
/// (`lnurl`) if it takes them, and [`HEALTH`]: at most [`MAX_SERVING`]
/// requests at once, each body still arriving
/// [`licash_serve::BODY_TIME`] after its head refused, each request's
/// source resolved before any handler.
pub fn router<T: Transport + 'static>(provider: Arc<Provider<T>>, serving: Serving) -> Router {
    let Serving {
        nostr,
        chain,
        ingress,
    } = serving;
    let mut routes = paths(provider.clone(), nostr, chain).route(HEALTH, get(|| async { "ok" }));
    if provider.donations().is_some() {
        routes = routes.merge(lnurl(provider));
    }
    let routes = licash_serve::shed(routes, MAX_SERVING, "the provider is too busy now");
    licash_serve::resolving(routes, ingress).layer(TraceLayer::new_for_http())
}

/// The paths of [`router`] alone, without [`HEALTH`], donations, limits
/// or traces: for a hub serving the swaps into it beside its own API,
/// which has them, and resolves each request's source.
pub fn api<T: Transport + 'static>(provider: Arc<Provider<T>>, nostr: Option<String>) -> Router {
    paths::<T, ChainView>(provider, nostr, None)
}

fn paths<T: Transport + 'static, C: Chain + Send + 'static>(
    provider: Arc<Provider<T>>,
    nostr: Option<String>,
    chain: Option<Arc<C>>,
) -> Router {
    let served = Served {
        provider,
        nostr,
        chain,
    };
    Router::new()
        .route(swaps::SWAPS_INFO, get(info::<T, C>))
        .route(swaps::SWAPS, post(take::<T, C>))
        .route(swaps::SWAP_STATE, get(state::<T, C>))
        .route(swaps::CHAIN_SWAPS, post(take_payout::<T, C>))
        .route(swaps::CHAIN_SWAP_STATE, get(payout_state::<T, C>))
        .route(swaps::LIGHTNING_SWAPS, post(take_invoice::<T, C>))
        .route(swaps::LIGHTNING_SWAP_STATE, get(invoice_state::<T, C>))
        .route(swaps::RECEIVES, post(take_receive::<T, C>))
        .route(swaps::RECEIVE_STATE, get(receive_state::<T, C>))
        .with_state(Arc::new(served))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

/// Donations to the wallets of Licash codes over LNURL-pay (LUD-06), for
/// `provider` taking them ([`Provider::take_donations`]):
/// [`swaps::DONATE`] answers the pay request of a code, at the provider's
/// public URL, [`swaps::DONATE_CALLBACK`] a donation's invoice. Answered
/// as LNURL asks, `{"status": "ERROR", "reason": ...}` when refused, to
/// any origin.
fn lnurl<T: Transport + 'static>(provider: Arc<Provider<T>>) -> Router {
    Router::new()
        .route(swaps::DONATE, get(pay_request::<T>))
        .route(swaps::DONATE_CALLBACK, get(donate::<T>))
        .with_state(provider)
}

/// An answer of LNURL: `body`, or why not.
fn lnurl_answer(body: Result<Value, Problem>) -> Response {
    let body = body.unwrap_or_else(|p| {
        tracing::debug!(code = ?p.code, message = %p.message, "donation declined");
        json!({ "status": "ERROR", "reason": p.message })
    });
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], Json(body)).into_response()
}

async fn pay_request<T: Transport + 'static>(
    State(provider): State<Arc<Provider<T>>>,
    Path(code): Path<String>,
) -> Response {
    let range = provider.donation_range(&code);
    let request = range.and_then(|(min, max)| {
        let declined = || Problem::new(Code::Declined, "the provider takes no donations");
        let url = provider.donations().ok_or_else(declined)?.url;
        Ok(json!({
            "tag": "payRequest",
            "callback": format!("{}/callback", swaps::donation_url(&url, &code)),
            "minSendable": min * 1000,
            "maxSendable": max * 1000,
            "metadata": licash_swaps::METADATA,
        }))
    });
    lnurl_answer(request)
}

async fn donate<T: Transport + 'static>(
    State(provider): State<Arc<Provider<T>>>,
    Path(code): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    admission: Result<Admission, licash_serve::Malformed>,
) -> Response {
    let source = match admission {
        Ok(Admission(source)) => source,
        Err(licash_serve::Malformed(problem)) => return lnurl_answer(Err(problem)),
    };
    let Some(msat) = query.get("amount").and_then(|a| a.parse::<u64>().ok()) else {
        return lnurl_answer(Err(Problem::invalid("an amount in millisatoshis")));
    };
    let source = source.as_ref().map(AdmissionSource::as_bytes);
    let invoice = provider.donate(&code, msat, source).await;
    lnurl_answer(invoice.map(|pr| json!({ "pr": pr, "routes": [] })))
}

/// A [`Problem`] answered with its status.
#[derive(Debug)]
struct Failure(Problem);

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

impl From<licash_swaps::Error> for Failure {
    fn from(e: licash_swaps::Error) -> Self {
        tracing::error!(error = %e, "request failed");
        Self(Problem::new(
            Code::Unavailable,
            "the provider cannot serve now",
        ))
    }
}

type Answer<T> = Result<Json<T>, Failure>;

type Shared<T, C> = State<Arc<Served<T, C>>>;

async fn info<T: Transport + 'static, C>(State(served): Shared<T, C>) -> Answer<swaps::Info> {
    let provider = Arc::clone(&served.provider);
    let mut info = tokio::task::spawn_blocking(move || provider.info())
        .await
        .map_err(|e| Failure(Problem::new(Code::Unavailable, e.to_string())))??;
    if served.chain.is_none() {
        info.chain = None;
    }
    // Up to what its node's channels pay now.
    info.lightning = served.provider.lightning_now().await;
    info.nostr = served.nostr.clone();
    Ok(Json(info))
}

async fn take<T: Transport + 'static, C>(
    State(served): Shared<T, C>,
    body: Result<Json<Request>, JsonRejection>,
) -> Answer<Swap> {
    let Json(request) = body?;
    let swap = served.provider.take(&request).await.inspect_err(|p| {
        tracing::debug!(code = ?p.code, message = %p.message, "swap declined");
    })?;
    Ok(Json(swap))
}

async fn state<T: Transport + 'static, C>(
    State(served): Shared<T, C>,
    Path(id): Path<String>,
) -> Answer<Swap> {
    let id = licash_api::lock_id(&id)?;
    match served.provider.swap(&id)? {
        Some(swap) => Ok(Json(swap)),
        None => Err(Problem::new(Code::UnknownLock, "no such swap").into()),
    }
}

async fn take_payout<T: Transport + 'static, C: Chain>(
    State(served): Shared<T, C>,
    body: Result<Json<ChainRequest>, JsonRejection>,
) -> Answer<ChainSwap> {
    let Json(request) = body?;
    let Some(chain) = &served.chain else {
        return Err(Problem::new(Code::Declined, "no payouts on Bitcoin").into());
    };
    let payout = served
        .provider
        .take_payout(&request, chain.as_ref())
        .await
        .inspect_err(|p| {
            tracing::debug!(code = ?p.code, message = %p.message, "payout declined");
        })?;
    Ok(Json(payout))
}

async fn payout_state<T: Transport + 'static, C>(
    State(served): Shared<T, C>,
    Path(id): Path<String>,
) -> Answer<ChainSwap> {
    let id = licash_api::lock_id(&id)?;
    match served.provider.payout(&id)? {
        Some(payout) => Ok(Json(payout)),
        None => Err(Problem::new(Code::UnknownLock, "no such payout").into()),
    }
}

/// Pay an invoice, declined unless the provider pays them
/// ([`Provider::pay_lightning`]).
async fn take_invoice<T: Transport + 'static, C>(
    State(served): Shared<T, C>,
    body: Result<Json<LightningRequest>, JsonRejection>,
) -> Answer<LightningSwap> {
    let Json(request) = body?;
    let payment = served
        .provider
        .take_invoice(&request)
        .await
        .inspect_err(|p| {
            tracing::debug!(code = ?p.code, message = %p.message, "invoice declined");
        })?;
    Ok(Json(payment))
}

async fn invoice_state<T: Transport + 'static, C>(
    State(served): Shared<T, C>,
    Path(id): Path<String>,
) -> Answer<LightningSwap> {
    let id = licash_api::lock_id(&id)?;
    match served.provider.invoice(&id)? {
        Some(payment) => Ok(Json(payment)),
        None => Err(Problem::new(Code::UnknownLock, "no such payment").into()),
    }
}

async fn take_receive<T: Transport + 'static, C>(
    State(served): Shared<T, C>,
    Admission(source): Admission,
    body: Result<Json<ReceiveRequest>, JsonRejection>,
) -> Answer<Receiving> {
    let Json(request) = body?;
    let source = source.as_ref().map(AdmissionSource::as_bytes);
    let receiving = served
        .provider
        .receive(&request, source)
        .await
        .inspect_err(|p| {
            tracing::debug!(code = ?p.code, message = %p.message, "receipt declined");
        })?;
    Ok(Json(receiving))
}

async fn receive_state<T: Transport + 'static, C>(
    State(served): Shared<T, C>,
    Path(hash): Path<String>,
) -> Answer<ReceiveStatus> {
    let hash = licash_api::hash_of(&hash)?;
    match served.provider.receive_status(&hash)? {
        Some(status) => Ok(Json(status)),
        None => Err(Problem::new(Code::UnknownLock, "no receipt under this hash").into()),
    }
}

/// Take the swaps of `provider` on every `every`, and alert of the hubs it
/// holds too little at to swap to, for good.
pub async fn step<T: Transport + 'static>(provider: Arc<Provider<T>>, every: Duration) {
    loop {
        match provider.step().await {
            Ok(pending) => {
                for (id, reason) in pending {
                    tracing::debug!(%id, reason, "swap pending");
                }
            }
            Err(e) => tracing::warn!("taking the swaps on: {e}"),
        }
        // Shared by standalone and hub-embedded providers. Maintenance
        // never prevents pending swaps from being advanced next round.
        if let Err(e) = provider.wallet().maintain_notes().await {
            tracing::info!("note maintenance deferred: {e}");
        }
        match provider.check_stock() {
            Ok(short) => {
                for hub in short {
                    tracing::warn!(%hub, "too little held to swap to it");
                }
            }
            Err(e) => tracing::warn!("checking what it holds: {e}"),
        }
        match provider.check_payouts() {
            Ok(true) => tracing::warn!("too few coins on Bitcoin to pay out"),
            Ok(false) => {}
            Err(e) => tracing::warn!("checking its coins on Bitcoin: {e}"),
        }
        tokio::time::sleep(every).await;
    }
}

/// Follow the payouts of `provider` on `chain` every `every`, for good.
pub async fn follow<T: Transport + 'static, C: Chain>(
    provider: Arc<Provider<T>>,
    chain: Arc<C>,
    every: Duration,
) {
    loop {
        match provider.follow_payouts(chain.as_ref()).await {
            Ok(pending) => {
                for (id, reason) in pending {
                    tracing::debug!(%id, reason, "payout pending");
                }
            }
            Err(e) => tracing::warn!("following the payouts: {e}"),
        }
        tokio::time::sleep(every).await;
    }
}

/// Follow the Lightning payments of `provider` on its node every `every`,
/// for good: a payment's preimage claims its client's lock as soon as it
/// is bought.
pub async fn pay_invoices<T: Transport + 'static>(provider: Arc<Provider<T>>, every: Duration) {
    loop {
        match provider.follow_invoices().await {
            Ok(pending) => {
                for (id, reason) in pending {
                    tracing::debug!(%id, reason, "payment pending");
                }
            }
            Err(e) => tracing::warn!("following the Lightning payments: {e}"),
        }
        tokio::time::sleep(every).await;
    }
}

/// Follow the receipts over Lightning of `provider` every `every`, for
/// good: lock each paid on to its wallet, settle or cancel.
pub async fn take_receives<T: Transport + 'static>(provider: Arc<Provider<T>>, every: Duration) {
    loop {
        match provider.follow_receives().await {
            Ok(pending) => {
                for (hash, reason) in pending {
                    tracing::debug!(%hash, reason, "receipt pending");
                }
            }
            Err(e) => tracing::warn!("following the receipts: {e}"),
        }
        tokio::time::sleep(every).await;
    }
}

/// Follow the donations of `provider` every `every`, for good: pay each
/// payee once its invoice is paid, settle or cancel, and mail the payments
/// due to their payees' mailboxes on relays reached through `route`.
pub async fn take_donations<T: Transport + 'static>(
    provider: Arc<Provider<T>>,
    route: Route,
    every: Duration,
) {
    loop {
        match provider.follow_donations().await {
            Ok(pending) => {
                for (hash, reason) in pending {
                    tracing::debug!(%hash, reason, "donation pending");
                }
            }
            Err(e) => tracing::warn!("following the donations: {e}"),
        }
        match provider.wallet().delivering() {
            Ok(0) => {}
            Ok(_) => {
                let route = route.clone();
                match licash_nostr::wallet::deliver(provider.wallet(), || Ok(route)).await {
                    Ok(delivered) => {
                        for (id, why) in delivered.failed {
                            tracing::warn!(%id, why, "a payment to mail to its payee, again later");
                        }
                    }
                    Err(e) => tracing::warn!("mailing payments to their payees: {e:#}"),
                }
            }
            Err(e) => tracing::warn!("payments to mail: {e}"),
        }
        tokio::time::sleep(every).await;
    }
}

/// Announce `provider` at `urls`, named `name`, on `relays` reached through
/// `route`, for good, for its wallet's network.
pub async fn announce<T: Transport + 'static>(
    provider: Arc<Provider<T>>,
    relays: Vec<String>,
    route: Route,
    urls: Vec<String>,
    name: Option<String>,
) {
    let network = provider.wallet().network().name().to_owned();
    let secret = match provider.nostr_secret() {
        Ok(secret) => secret,
        Err(e) => return tracing::error!("announcing on Nostr: {e}"),
    };
    let announcement = Announcement {
        urls,
        network,
        name,
    };
    match Announcer::new(&secret, Role::Swaps, &relays, &route).await {
        Ok(announcer) => announcer.run(announcement).await,
        Err(e) => tracing::error!("announcing on Nostr: {e:#}"),
    }
}
