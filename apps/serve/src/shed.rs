//! Requests shed past the most served at once, and bodies that stall.

use std::{sync::Arc, time::Duration};

use axum::{extract::Request, middleware::Next, Router};
use licash_api::{Code, Problem};

/// `ok` while a service serves: never shed.
pub const HEALTH: &str = "/health";

/// How long a request's body may take to arrive in [`shed`]: a hub's
/// largest (1 MiB) at 17 KB/s, a provider's (64 KiB) at 1 KB/s.
pub const BODY_TIME: Duration = Duration::from_secs(60);

/// `router`, serving at most `most` requests at once but its [`HEALTH`]:
/// any past them answered `busy`, unavailable (503), at once, rather than
/// queued without bound. A request's body still arriving [`BODY_TIME`]
/// after its head fails, the request refused: a client stalling its
/// bodies holds its places no longer.
pub fn shed(router: Router, most: usize, busy: &'static str) -> Router {
    let serving = Arc::new(tokio::sync::Semaphore::new(most));
    router.layer(axum::middleware::from_fn(
        move |request: Request, next: Next| {
            let serving = serving.clone();
            async move {
                if request.uri().path() == HEALTH {
                    return next.run(request).await;
                }
                let Ok(_serving) = serving.try_acquire_owned() else {
                    tracing::warn!(path = %request.uri().path(), "too busy to serve");
                    return crate::problem(Problem::new(Code::Unavailable, busy));
                };
                next.run(within(request, BODY_TIME)).await
            }
        },
    ))
}

/// `router`, each request's body failing if still arriving `time` after
/// its head: for a service bounding its requests by its connections alone.
pub fn bodies_within(router: Router, time: Duration) -> Router {
    router.layer(axum::middleware::from_fn(
        move |request: Request, next: Next| async move { next.run(within(request, time)).await },
    ))
}

/// `request`, its body failing if still arriving `time` from now.
fn within(request: Request, time: Duration) -> Request {
    use futures_util::StreamExt as _;
    let until = tokio::time::Instant::now() + time;
    request.map(|body| {
        let data = body.into_data_stream();
        axum::body::Body::from_stream(futures_util::stream::unfold(
            Some(data),
            move |data| async move {
                let mut data = data?;
                match tokio::time::timeout_at(until, data.next()).await {
                    Ok(Some(chunk)) => Some((chunk, Some(data))),
                    Ok(None) => None,
                    Err(_) => {
                        let late = axum::Error::new("the request's body came too slowly");
                        Some((Err(late), None))
                    }
                }
            },
        ))
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, Bytes},
        http::StatusCode,
        routing::{get, post},
    };
    use tower::ServiceExt as _;

    use super::*;

    async fn body_of(response: axum::response::Response) -> Bytes {
        axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap()
    }

    /// Requests past the most it serves at once are answered at once,
    /// unavailable, rather than queued without bound; its health is still
    /// told, and a request is served again once one ends.
    #[tokio::test]
    async fn requests_past_the_most_at_once_are_unavailable() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let held = gate.clone();
        let app = Router::new()
            .route(
                "/slow",
                get(move || {
                    let held = held.clone();
                    async move {
                        held.notified().await;
                        "done"
                    }
                }),
            )
            .route("/fast", get(|| async { "fast" }))
            .route(HEALTH, get(|| async { "ok" }));
        let app = shed(app, 1, "busy now");
        let get = |path: &str| Request::get(path).body(Body::empty()).unwrap();
        let slow = tokio::spawn(app.clone().oneshot(get("/slow")));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let busy = app.clone().oneshot(get("/fast")).await.unwrap();
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        let problem: Problem = serde_json::from_slice(&body_of(busy).await).unwrap();
        assert_eq!(problem.code, Code::Unavailable);
        assert_eq!(problem.message, "busy now");
        let health = app.clone().oneshot(get(HEALTH)).await;
        assert_eq!(health.unwrap().status(), StatusCode::OK);
        gate.notify_one();
        assert_eq!(slow.await.unwrap().unwrap().status(), StatusCode::OK);
        let served = app.oneshot(get("/fast")).await.unwrap();
        assert_eq!(served.status(), StatusCode::OK);
    }

    /// A body still arriving [`BODY_TIME`] after its request came is
    /// refused, its place freed: requests whose bodies stall keep no other
    /// out for longer. One arriving slowly but in time is served.
    #[tokio::test(start_paused = true)]
    async fn a_body_stalled_past_its_time_frees_its_place() {
        let app = Router::new().route(
            "/",
            post(|body: Bytes| async move { body.len().to_string() }),
        );
        let app = shed(app, 1, "busy now");
        let post = |body: Body| Request::post("/").body(body).unwrap();
        let stalled =
            Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
        let stalled = tokio::spawn(app.clone().oneshot(post(stalled)));
        tokio::time::sleep(BODY_TIME - Duration::from_secs(1)).await;
        let busy = app.clone().oneshot(post(Body::from("x"))).await.unwrap();
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        let refused = tokio::time::timeout(Duration::from_secs(2), stalled).await;
        let refused = refused.expect("still held").unwrap().unwrap();
        assert!(refused.status().is_client_error(), "{}", refused.status());
        let served = app.clone().oneshot(post(Body::from("x"))).await.unwrap();
        assert_eq!(served.status(), StatusCode::OK);
        // A chunk every tenth of its time: all of it in time.
        let slow = futures_util::stream::unfold(0, |sent| async move {
            if sent == 9 {
                return None;
            }
            tokio::time::sleep(BODY_TIME / 10).await;
            Some((Ok::<_, std::io::Error>(Bytes::from_static(b"ab")), sent + 1))
        });
        let served = app.oneshot(post(Body::from_stream(slow))).await.unwrap();
        assert_eq!(served.status(), StatusCode::OK);
        assert_eq!(&body_of(served).await[..], b"18");
    }

    /// Bounded in time alone: a stalled body is refused once late, however
    /// many are served at once.
    #[tokio::test(start_paused = true)]
    async fn bodies_within_their_time_alone() {
        let app = Router::new().route(
            "/",
            post(|body: Bytes| async move { body.len().to_string() }),
        );
        let app = bodies_within(app, Duration::from_secs(5));
        let stalled = || {
            let body =
                Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
            tokio::spawn(app.clone().oneshot(Request::post("/").body(body).unwrap()))
        };
        let (one, two) = (stalled(), stalled());
        let served = app
            .clone()
            .oneshot(Request::post("/").body(Body::from("x")).unwrap())
            .await
            .unwrap();
        assert_eq!(served.status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_secs(6)).await;
        for stalled in [one, two] {
            let refused = stalled.await.unwrap().unwrap();
            assert!(refused.status().is_client_error(), "{}", refused.status());
        }
    }
}
