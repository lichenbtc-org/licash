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

/// The most of those one key's: a wallet asks a few a minute at most, so
/// that one account fills no more than its share of [`MAX_SEEN`].
const PER_SIGNER: usize = 256;

struct Shared<T> {
    bridge: Arc<Bridge<T>>,
    seen: Mutex<Seen>,
}

/// The signatures of the requests answered within [`MAX_SKEW`] of now, by
/// the key that signed them, and their times.
#[derive(Default)]
struct Seen {
    by: HashMap<[u8; 32], HashMap<Vec<u8>, i64>>,
    total: usize,
}

impl Seen {
    /// Note the request `key` signed `signature` at `at` answered now:
    /// refused if it was already, or while [`PER_SIGNER`] others of `key`,
    /// or [`MAX_SEEN`] in all, are kept.
    fn admit(
        &mut self,
        key: &[u8; 32],
        signature: &[u8],
        at: i64,
        now: i64,
    ) -> Result<(), Problem> {
        let live = |then: &i64| (now - *then).abs() <= 2 * MAX_SKEW;
        // Those past their skew let go only once full: a request of theirs
        // is refused by its time anyway.
        if self.total >= MAX_SEEN {
            self.by.retain(|_, signed| {
                signed.retain(|_, then| live(then));
                !signed.is_empty()
            });
            self.total = self.by.values().map(HashMap::len).sum();
        }
        let signed = self.by.entry(*key).or_default();
        if signed.contains_key(signature) {
            return Err(Problem::invalid("a request answered already"));
        }
        if signed.len() >= PER_SIGNER {
            let before = signed.len();
            signed.retain(|_, then| live(then));
            self.total -= before - signed.len();
        }
        let busy = |why: &str| Err(Problem::new(licash_api::Code::Unavailable, why));
        if signed.len() >= PER_SIGNER {
            return busy("too many requests of this key lately: try again in a few minutes");
        }
        if self.total >= MAX_SEEN {
            if signed.is_empty() {
                self.by.remove(key);
            }
            return busy("too many requests lately: try again in a few minutes");
        }
        signed.insert(signature.to_vec(), at);
        self.total += 1;
        Ok(())
    }

    /// Let go of `signature` of `key`, as if never answered.
    fn forget(&mut self, key: &[u8; 32], signature: &[u8]) {
        let Some(signed) = self.by.get_mut(key) else {
            return;
        };
        if signed.remove(signature).is_some() {
            self.total -= 1;
        }
        if signed.is_empty() {
            self.by.remove(key);
        }
    }
}

/// A signed request admitted, under way: once answered (or given up), its
/// signature is kept only if its key holds an account then. A key of none
/// is refused whatever it asks but to register, and a registration that
/// failed may be asked again, so what it signed needs no keeping: no
/// stranger fills [`Seen`].
struct Admitted<'a, T: Transport> {
    shared: &'a Shared<T>,
    key: [u8; 32],
    signature: Vec<u8>,
}

impl<T: Transport> Drop for Admitted<'_, T> {
    fn drop(&mut self) {
        // Its store unread, kept: never forgotten early.
        if let Err(Error::Unauthorized(_)) = self.shared.bridge.account_id(&self.key) {
            let mut seen = self
                .shared
                .seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            seen.forget(&self.key, &self.signature);
        }
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
        .route(bridge::DEPOSIT, post(deposit::<T>))
        .route(bridge::PAYOUT, post(payout::<T>))
        .route(bridge::USERNAME, post(username::<T>))
        .route(bridge::EXPORT, post(export::<T>))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(shared.clone())
        .merge(crate::lnurl::router(shared.bridge.clone()));
    licash_serve::shed(api, MAX_SERVING, "the bridge is too busy now")
}

impl<T: Transport> Shared<T> {
    /// The request signed in `body` for `path`, and the key that signed it
    /// ([`Admitted::key`]): once.
    fn open<R: DeserializeOwned>(
        &self,
        path: &str,
        body: Result<Json<Signed>, JsonRejection>,
    ) -> Result<(Admitted<'_, T>, R), Failure> {
        let Json(signed) = body.map_err(|e| Failure(Problem::invalid(e.body_text())))?;
        let at = now();
        let key = signed.verify(path, at).map_err(Failure)?;
        let request = serde_json::from_str(&signed.request)
            .map_err(|e| Failure(Problem::invalid(format!("the request: {e}"))))?;
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.admit(&key, &signed.signature.0, signed.at, at)
            .map_err(Failure)?;
        let admitted = Admitted {
            shared: self,
            key,
            signature: signed.signature.0,
        };
        Ok((admitted, request))
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
    let (admitted, r): (_, bridge::Register) = s.open(bridge::REGISTER, body)?;
    let key = admitted.key;
    json(s.bridge.register(&key, r.pairing.as_deref()))
}

async fn account<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Account> {
    let (admitted, bridge::Empty {}) = s.open(bridge::ACCOUNT, body)?;
    let key = admitted.key;
    json(s.bridge.account(&key))
}

async fn connect<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Connected> {
    let (admitted, connect): (_, bridge::Connect) = s.open(bridge::CONNECT, body)?;
    let key = admitted.key;
    json(s.bridge.connect(&key, &connect))
}

async fn revoke<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Connection> {
    let (admitted, revoke): (_, bridge::Revoke) = s.open(bridge::REVOKE, body)?;
    let key = admitted.key;
    json(s.bridge.revoke(&key, &revoke.key))
}

async fn top_up<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Invoice> {
    let (admitted, top_up): (_, bridge::TopUp) = s.open(bridge::TOP_UP, body)?;
    let key = admitted.key;
    json(s.bridge.top_up(&key, top_up.amount).await)
}

async fn withdraw<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Payment> {
    let (admitted, withdraw): (_, bridge::Withdraw) = s.open(bridge::WITHDRAW, body)?;
    let key = admitted.key;
    json(s.bridge.withdraw(&key, &withdraw).await)
}

async fn deposit<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Deposited> {
    let (admitted, deposit): (_, bridge::Deposit) = s.open(bridge::DEPOSIT, body)?;
    let key = admitted.key;
    json(s.bridge.deposit(&key, &deposit).await)
}

async fn payout<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::PaidOut> {
    let (admitted, payout): (_, bridge::Payout) = s.open(bridge::PAYOUT, body)?;
    let key = admitted.key;
    json(s.bridge.payout(&key, &payout).await)
}

async fn username<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Account> {
    let (admitted, named): (_, bridge::Username) = s.open(bridge::USERNAME, body)?;
    let key = admitted.key;
    json(s.bridge.set_username(&key, named.username.as_deref()))
}

async fn export<T: Transport>(
    State(s): State<Arc<Shared<T>>>,
    body: Result<Json<Signed>, JsonRejection>,
) -> Answer<bridge::Exported> {
    let (admitted, bridge::Empty {}) = s.open(bridge::EXPORT, body)?;
    let key = admitted.key;
    // Its notes are every account's: only its owner's, of a bridge for its
    // owner alone, its one account. An open bridge's operator, or that of
    // one open before, exports them on its command line.
    if s.bridge.config().open {
        return Err(Error::Restricted("an open bridge exports to its operator only".into()).into());
    }
    s.bridge.sole_account(&key)?;
    json(s.bridge.export(&key).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: usize) -> [u8; 32] {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&n.to_be_bytes());
        key
    }

    /// Each signature is answered once; past [`PER_SIGNER`] of one key or
    /// [`MAX_SEEN`] in all, more are refused until older ones are past
    /// their skew twice, and none is forgotten early.
    #[test]
    fn a_request_is_answered_once_and_none_past_the_most_kept() {
        let mut seen = Seen::default();
        let (a, b) = (key(0), key(1));
        seen.admit(&a, b"a", 100, 100).unwrap();
        let again = seen.admit(&a, b"a", 100, 101).unwrap_err();
        assert_eq!(again.code, licash_api::Code::Invalid);
        // Another key's signature is its own.
        seen.admit(&b, b"a", 1_000, 1_000).unwrap();
        // One key's places: a few minutes' worth.
        for i in 1..PER_SIGNER {
            seen.admit(&a, &i.to_be_bytes(), 1_000, 1_000).unwrap();
        }
        // Full, "a" past its skew twice let go: one more of the key.
        seen.admit(&a, b"b", 1_000, 1_000).unwrap();
        let full = seen.admit(&a, b"c", 1_000, 1_000).unwrap_err();
        assert_eq!(full.code, licash_api::Code::Unavailable);
        assert!(full.message.contains("this key"), "{full:?}");
        let kept = seen.admit(&a, &1usize.to_be_bytes(), 1_000, 1_000);
        assert_eq!(kept.unwrap_err().code, licash_api::Code::Invalid);
        // Others are served all the while...
        seen.admit(&b, b"c", 1_000, 1_000).unwrap();
        // ... until every place is taken, in all.
        let mut n = 2;
        while seen.total < MAX_SEEN {
            for i in 0..PER_SIGNER.min(MAX_SEEN - seen.total) {
                seen.admit(&key(n), &i.to_be_bytes(), 1_000, 1_000).unwrap();
            }
            n += 1;
        }
        let full = seen.admit(&key(n), b"d", 1_000, 1_000).unwrap_err();
        assert_eq!(full.code, licash_api::Code::Unavailable);
        assert!(!seen.by.contains_key(&key(n)));
        // Never forgotten early; once past their skew twice, let go.
        let kept = seen.admit(&key(2), &0usize.to_be_bytes(), 1_000, 1_000);
        assert_eq!(kept.unwrap_err().code, licash_api::Code::Invalid);
        seen.admit(&key(n), b"d", 1_000, 1_000 + 2 * MAX_SKEW + 1)
            .unwrap();
        assert_eq!(seen.total, 1);
    }

    /// A signature let go may be admitted again, and leaves no trace.
    #[test]
    fn a_signature_forgotten_is_as_never_answered() {
        let mut seen = Seen::default();
        seen.admit(&key(0), b"a", 100, 100).unwrap();
        seen.forget(&key(0), b"a");
        seen.forget(&key(0), b"a");
        seen.forget(&key(1), b"a");
        assert_eq!(seen.total, 0);
        assert!(seen.by.is_empty());
        seen.admit(&key(0), b"a", 100, 100).unwrap();
        assert_eq!(seen.total, 1);
    }
}
