//! How many requests for what the hub holds a place for until paid one
//! source may have: unpaid deposits and Lightning receipts
//! ([`PER_SOURCE`]), contract requests in flight
//! ([`CONTRACTS_PER_SOURCE`]). The source is [`licash_serve`]'s, resolved
//! once per request in the router.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use licash_serve::{Admission, AdmissionSource};

/// The deposits, and the Lightning receipts, one source may have asked
/// and not paid.
pub const PER_SOURCE: u32 = 8;

/// The contract requests one source has in flight at most: a holder
/// uploads three instances at once.
pub const CONTRACTS_PER_SOURCE: usize = 8;

/// The contract requests each source has in flight.
#[derive(Debug, Default)]
pub struct InFlight(Mutex<HashMap<Vec<u8>, usize>>);

impl InFlight {
    /// A place for a request of `source`, held until dropped: none if it
    /// has [`CONTRACTS_PER_SOURCE`] already.
    fn take(self: &Arc<Self>, source: &AdmissionSource) -> Option<Place> {
        let mut counts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(source.as_bytes().to_vec()).or_default();
        if *count >= CONTRACTS_PER_SOURCE {
            return None;
        }
        *count += 1;
        Some(Place(self.clone(), source.as_bytes().to_vec()))
    }
}

struct Place(Arc<InFlight>, Vec<u8>);

impl Drop for Place {
    fn drop(&mut self) {
        let mut counts = (self.0).0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.1) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.1);
            }
        }
    }
}

/// Middleware, behind [`licash_serve::resolving`]: a contract request answered only if its
/// source has fewer than [`CONTRACTS_PER_SOURCE`] in flight (else 503 at
/// once), its place held until its answer is sent. One of no source, as
/// served in process, is not counted.
pub async fn contracts_per_source(
    State(in_flight): State<Arc<InFlight>>,
    Admission(source): Admission,
    request: Request,
    next: Next,
) -> Response {
    use axum::response::IntoResponse as _;
    let place = match source {
        None => None,
        Some(source) => match in_flight.take(&source) {
            Some(place) => Some(place),
            None => {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "too many contract requests of yours at once: retry later",
                )
                    .into_response()
            }
        },
    };
    next.run(request).await.map(|body| {
        use futures_util::StreamExt as _;
        axum::body::Body::from_stream(body.into_data_stream().map(move |chunk| {
            let _held = &place;
            chunk
        }))
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::extract::ConnectInfo;

    use super::*;

    #[tokio::test]
    async fn a_source_has_a_few_contract_requests_in_flight_at_most() {
        use tower::ServiceExt as _;

        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let held = release.clone();
        let in_flight = Arc::new(InFlight::default());
        let app = axum::Router::new()
            .route(
                "/wait",
                axum::routing::get(move || async move {
                    let _ = held.acquire().await.unwrap();
                    "waited"
                }),
            )
            .route("/now", axum::routing::get(|| async { "now" }))
            .layer(axum::middleware::from_fn_with_state(
                in_flight.clone(),
                contracts_per_source,
            ));
        let app = licash_serve::resolving(app, Arc::default());
        let ask = |path: &str, peer: &str| {
            let request = axum::http::Request::get(path)
                .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
                .body(axum::body::Body::empty())
                .unwrap();
            app.clone().oneshot(request)
        };
        let waiting: Vec<_> = (0..CONTRACTS_PER_SOURCE)
            .map(|n| tokio::spawn(ask("/wait", &format!("1.2.3.4:{}", 1000 + n))))
            .collect();
        let full = || {
            let counts = in_flight.0.lock().unwrap();
            counts.get(b"ip 1.2.3.4".as_slice()) == Some(&CONTRACTS_PER_SOURCE)
        };
        while !full() {
            tokio::task::yield_now().await;
        }
        // Its address, from any port, has no more places; another has.
        let refused = ask("/now", "1.2.3.4:2000").await.unwrap();
        assert_eq!(
            refused.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let other = ask("/now", "5.6.7.8:2000").await.unwrap();
        assert_eq!(other.status(), axum::http::StatusCode::OK);
        drop((refused, other));
        // Its places free once answered, and none kept of a source idle.
        release.add_permits(CONTRACTS_PER_SOURCE);
        for response in futures_util::future::join_all(waiting).await {
            let response = response.unwrap().unwrap();
            let body = axum::body::to_bytes(response.into_body(), 64)
                .await
                .unwrap();
            assert_eq!(body, "waited");
        }
        assert!(in_flight.0.lock().unwrap().is_empty());
        let again = ask("/now", "1.2.3.4:2000").await.unwrap();
        assert_eq!(again.status(), axum::http::StatusCode::OK);
    }
}
