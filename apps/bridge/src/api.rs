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

/// The most requests it serves at once, its Lightning Addresses' included:
/// those past it are answered unavailable at once, rather than queued
/// without bound.
pub const MAX_SERVING: usize = 256;

/// The most signatures of requests answered kept, for [`MAX_SKEW`] twice:
/// more are refused until older ones are let go, never forgotten early,
/// which would let them be replayed.
const MAX_SEEN: usize = 65_536;

struct Shared<T> {
    bridge: Arc<Bridge<T>>,
    seen: Mutex<Seen>,
}

/// The signatures of the requests answered within [`MAX_SKEW`] of now,
/// and their times.
#[derive(Default)]
struct Seen(HashMap<Vec<u8>, i64>);

impl Seen {
    /// Note the request signed `signature` at `at` answered now: refused
    /// if it was already, or while [`MAX_SEEN`] others are kept.
    fn admit(&mut self, signature: &[u8], at: i64, now: i64) -> Result<(), Problem> {
        // Those past their skew let go only once full: a request of theirs
        // is refused by its time anyway.
        if self.0.len() >= MAX_SEEN {
            self.0.retain(|_, then| (now - *then).abs() <= 2 * MAX_SKEW);
        }
        if self.0.contains_key(signature) {
            return Err(Problem::invalid("a request answered already"));
        }
        if self.0.len() >= MAX_SEEN {
            return Err(Problem::new(
                licash_api::Code::Unavailable,
                "too many requests lately: try again in a few minutes",
            ));
        }
        self.0.insert(signature.to_vec(), at);
        Ok(())
    }
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

/// The management API of `bridge`, its Lightning Addresses, and a health
/// check at [`licash_serve::HEALTH`]: at most [`MAX_SERVING`] requests at
/// once, each body still arriving [`licash_serve::BODY_TIME`] after its
/// head refused.
pub fn router<T: Transport + 'static>(bridge: Arc<Bridge<T>>) -> Router {
    let shared = Arc::new(Shared {
        bridge,
        seen: Mutex::new(Seen::default()),
    });
    let api = Router::new()
        .route(licash_serve::HEALTH, get(|| async { "ok" }))
        .route(bridge::INFO, get(info::<T>))
        .route(bridge::REGISTER, post(register::<T>))
        .route(bridge::ACCOUNT, post(account::<T>))
        .route(bridge::CONNECT, post(connect::<T>))
        .route(bridge::REVOKE, post(revoke::<T>))
        .route(bridge::TOP_UP, post(top_up::<T>))
        .route(bridge::WITHDRAW, post(withdraw::<T>))
        .route(bridge::USERNAME, post(username::<T>))
        .route(bridge::EXPORT, post(export::<T>))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(shared.clone())
        .merge(crate::lnurl::router(shared.bridge.clone()));
    licash_serve::shed(api, MAX_SERVING, "the bridge is too busy now")
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
        seen.admit(&signed.signature.0, signed.at, at)
            .map_err(Failure)?;
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

async fn username<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Account> {
    let (key, named): (_, bridge::Username) = s.open(bridge::USERNAME, body)?;
    json(s.bridge.set_username(&key, named.username.as_deref()))
}

async fn export<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Exported> {
    let (key, bridge::Empty {}) = s.open(bridge::EXPORT, body)?;
    // Its notes are every account's: only its owner's, of a bridge for its
    // owner alone. An open bridge's operator exports them on its command
    // line.
    if s.bridge.config().open {
        return Err(Error::Restricted("an open bridge exports to its operator only".into()).into());
    }
    s.bridge.account(&key)?;
    json(s.bridge.export(&key).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_answered_once_and_none_past_the_most_kept() {
        let mut seen = Seen::default();
        seen.admit(b"a", 100, 100).unwrap();
        assert!(seen.admit(b"a", 100, 101).is_err());
        for i in 1..MAX_SEEN {
            seen.admit(&i.to_be_bytes(), 1_000, 1_000).unwrap();
        }
        // Full, "a" past its skew twice let go: one more.
        seen.admit(b"b", 1_000, 1_000).unwrap();
        let full = seen.admit(b"c", 1_000, 1_000).unwrap_err();
        assert_eq!(full.code, licash_api::Code::Unavailable);
        // Never forgotten early: one kept still refused.
        let kept = seen.admit(&1usize.to_be_bytes(), 1_000, 1_000).unwrap_err();
        assert_eq!(kept.code, licash_api::Code::Invalid);
        seen.admit(b"c", 1_000, 1_000 + 2 * MAX_SKEW + 1).unwrap();
    }
}
