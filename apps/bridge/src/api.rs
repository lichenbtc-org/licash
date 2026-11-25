//! The management API ([`licash_api::bridge`]): an account's owner signs
//! each request with its key, which the bridge checks, and answers it
//! once: the same signed request again is refused.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use licash_api::{
    bridge::{self, Signed, MAX_SKEW},
    Problem,
};
use licash_wallet::Transport;
use serde::{de::DeserializeOwned, Serialize};

use crate::{now, Bridge, Error};

/// The most a request body may be.
const MAX_BODY: usize = 64 * 1024;

struct Shared<T> {
    bridge: Arc<Bridge<T>>,
    /// The signatures of the requests answered within [`MAX_SKEW`] of now,
    /// and their times.
    seen: Mutex<HashMap<Vec<u8>, i64>>,
}

type Answer<R> = Result<Json<R>, Failure>;

/// A refusal, as a [`Problem`].
struct Failure(Problem);

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Failure(e.problem())
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self.0)).into_response()
    }
}

/// The management API of `bridge`, and a health check at `/health`.
pub fn router<T: Transport + 'static>(bridge: Arc<Bridge<T>>) -> Router {
    let shared = Arc::new(Shared {
        bridge,
        seen: Mutex::new(HashMap::new()),
    });
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(bridge::INFO, get(info::<T>))
        .route(bridge::REGISTER, post(register::<T>))
        .route(bridge::ACCOUNT, post(account::<T>))
        .route(bridge::CONNECT, post(connect::<T>))
        .route(bridge::REVOKE, post(revoke::<T>))
        .route(bridge::TOP_UP, post(top_up::<T>))
        .route(bridge::WITHDRAW, post(withdraw::<T>))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(shared)
}

impl<T> Shared<T> {
    /// The key that signed `body` for `path`, and its request: once.
    fn open<R: DeserializeOwned>(
        &self,
        path: &str,
        body: Result<Json<Signed>, JsonRejection>,
    ) -> Result<([u8; 32], R), Failure> {
        let Json(signed) = body.map_err(|e| Failure(Problem::invalid(e.body_text())))?;
        let at = now();
        let key = signed.verify(path, at).map_err(Failure)?;
        let request = serde_json::from_str(&signed.request)
            .map_err(|e| Failure(Problem::invalid(format!("the request: {e}"))))?;
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, then| (at - *then).abs() <= 2 * MAX_SKEW);
        if seen.insert(signed.signature.0.clone(), signed.at).is_some() {
            return Err(Failure(Problem::invalid("a request answered already")));
        }
        Ok((key, request))
    }
}

fn json<R: Serialize>(r: Result<R, Error>) -> Answer<R> {
    r.map(Json).map_err(Failure::from)
}

async fn info<T: Transport>(State(s): State<Arc<Shared<T>>>) -> Answer<bridge::Info> {
    json(s.bridge.info())
}

async fn register<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Account> {
    let (key, r): (_, bridge::Register) = s.open(bridge::REGISTER, body)?;
    json(s.bridge.register(&key, r.pairing.as_deref()))
}

async fn account<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Account> {
    let (key, bridge::Empty {}) = s.open(bridge::ACCOUNT, body)?;
    json(s.bridge.account(&key))
}

async fn connect<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Connected> {
    let (key, connect): (_, bridge::Connect) = s.open(bridge::CONNECT, body)?;
    json(s.bridge.connect(&key, &connect))
}

async fn revoke<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Connection> {
    let (key, revoke): (_, bridge::Revoke) = s.open(bridge::REVOKE, body)?;
    json(s.bridge.revoke(&key, &revoke.key))
}

async fn top_up<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Invoice> {
    let (key, top_up): (_, bridge::TopUp) = s.open(bridge::TOP_UP, body)?;
    json(s.bridge.top_up(&key, top_up.amount).await)
}

async fn withdraw<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Payment> {
    let (key, withdraw): (_, bridge::Withdraw) = s.open(bridge::WITHDRAW, body)?;
    json(s.bridge.withdraw(&key, &withdraw).await)
}
