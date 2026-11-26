//! An axum router served as an onion service, or on the clear web.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use futures_util::{future::Either, FutureExt, StreamExt};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use safelog::DisplayRedacted;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{
    config::{OnionServiceConfig, OnionServiceConfigBuilder},
    HsNickname, RendRequest, RunningOnionService, StreamRequest,
};
use tor_proto::stream::IncomingStreamRequest;

use crate::Tor;

/// The port the service answers on.
const PORT: u16 = 80;

/// How soon to try connecting to the Tor network again.
const RETRY: Duration = Duration::from_secs(60);

/// Bound accepted streams, including clients that never send HTTP headers.
const MAX_STREAMS: usize = 128;
const HEADERS: Duration = Duration::from_secs(120);

/// Clear-web connections served at once: one more is closed as accepted.
const MAX_CONNECTIONS: usize = 1024;

/// How long a clear-web client may take to send a request's headers, or
/// stay idle before its next request.
const CLEAR_HEADERS: Duration = Duration::from_secs(30);

/// How long the connections still open when the server stops may take to
/// end, before they are cut.
const DRAIN: Duration = Duration::from_secs(30);

/// Serve `router` over HTTP/1.1 on `listener` until `stop`, each request
/// carrying its peer as [`axum::extract::ConnectInfo`]: unlike
/// `axum::serve`, a client stalling its headers, or idle, is let go
/// ([`CLEAR_HEADERS`]), and at most [`MAX_CONNECTIONS`] are served at
/// once. Once `stop`, the requests under way are answered, for up to
/// [`DRAIN`].
pub async fn listen(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    stop: impl std::future::Future<Output = ()>,
) {
    listen_with(listener, router, stop, CLEAR_HEADERS, MAX_CONNECTIONS).await
}

async fn listen_with(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    stop: impl std::future::Future<Output = ()>,
    headers: Duration,
    most: usize,
) {
    let (stopping, stopped) = tokio::sync::watch::channel(false);
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(stop);
    loop {
        let (stream, peer) = tokio::select! {
            () = &mut stop => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    // Out of file descriptors, say: not in a busy loop.
                    tracing::warn!("accepting a connection: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        while connections.try_join_next().is_some() {}
        if connections.len() >= most {
            tracing::debug!(%peer, "a connection past {most} closed");
            continue;
        }
        let router = router
            .clone()
            .layer(axum::Extension(axum::extract::ConnectInfo(peer)));
        let mut stopped = stopped.clone();
        connections.spawn(async move {
            let connection = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(headers)
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(router));
            tokio::pin!(connection);
            let served = tokio::select! {
                served = connection.as_mut() => served,
                // Told once, after every connection is made.
                _ = stopped.changed() => {
                    connection.as_mut().graceful_shutdown();
                    connection.await
                }
            };
            if let Err(e) = served {
                tracing::debug!(%peer, "a connection: {e}");
            }
        });
    }
    drop(listener);
    let _ = stopping.send(true);
    let drained = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(DRAIN, drained).await.is_err() {
        tracing::warn!("connections still open {DRAIN:?} after stopping, cut");
    }
}

/// The rendezvous circuit an onion request came over, as an
/// [`axum::Extension`] of the request: one introduction, which the
/// service's proof of work prices while it is under load. Random, so
/// never the same as one before a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Circuit(pub [u8; 16]);

impl Circuit {
    fn new() -> Self {
        let mut id = [0; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        Self(id)
    }
}

/// An onion service, served until dropped.
pub struct Onion {
    url: String,
    _service: Arc<RunningOnionService>,
    serving: tokio::task::JoinHandle<()>,
}

impl Onion {
    /// Where it answers: `http://<address>.onion`.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for Onion {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

impl Tor {
    /// Serve `router` on port 80 of the onion service `nickname`, at the
    /// same address on every start: the client keeps its key in its state.
    /// With `pow`, clients must solve a proof of work to reach it while it
    /// is under load. Each request carries its [`Circuit`]. Within a Tokio
    /// runtime.
    pub fn serve(&self, nickname: &str, router: axum::Router, pow: bool) -> anyhow::Result<Onion> {
        let config = config(nickname, pow)?;
        let (service, requests) = self
            .client
            .launch_onion_service(config)?
            .context("the onion service is disabled")?;
        let address = service
            .onion_address()
            .context("the onion service has no address")?;
        let url = format!("http://{}", address.display_unredacted());
        let mut streams = Box::pin(requests.flat_map_unordered(None, by_circuit));
        let client = self.client.clone();
        let serving = tokio::spawn(async move {
            // The service publishes itself once the client holds the
            // network's directory, which only a bootstrap fetches.
            while let Err(e) = client.bootstrap().await {
                tracing::warn!("Tor, for the onion service: {e}");
                tokio::time::sleep(RETRY).await;
            }
            let mut tasks = tokio::task::JoinSet::new();
            while let Some(request) = streams.next().await {
                while tasks.try_join_next().is_some() {}
                if tasks.len() >= MAX_STREAMS {
                    // No task is spawned for an excess stream. Bound even
                    // rejection so the accept loop cannot hang on a peer.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        request
                            .1
                            .reject(End::new_with_reason(EndReason::RESOURCELIMIT)),
                    )
                    .await;
                    continue;
                }
                let (circuit, request) = request;
                tasks.spawn(answer(
                    request,
                    router.clone().layer(axum::Extension(circuit)),
                ));
            }
        });
        Ok(Onion {
            url,
            _service: service,
            serving,
        })
    }
}

/// The onion service `nickname`'s configuration, with a proof of work
/// asked under load if `pow`.
fn config(nickname: &str, pow: bool) -> anyhow::Result<OnionServiceConfig> {
    let nickname: HsNickname = nickname.parse().context("an onion service's nickname")?;
    Ok(OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .enable_pow(pow)
        .build()?)
}

/// The streams of the rendezvous `rend` once accepted, each with its
/// [`Circuit`].
fn by_circuit(
    rend: RendRequest,
) -> std::pin::Pin<Box<dyn futures_util::Stream<Item = (Circuit, StreamRequest)> + Send>> {
    let circuit = Circuit::new();
    Box::pin(
        rend.accept()
            .map(move |accepted| match accepted {
                Ok(streams) => Either::Left(streams.map(move |s| (circuit, s))),
                Err(e) => {
                    tracing::debug!("a rendezvous not accepted: {e}");
                    Either::Right(futures_util::stream::empty())
                }
            })
            .flatten_stream(),
    )
}

/// Serve `router` on the stream `request` asks for, if it asks for port 80.
async fn answer(request: StreamRequest, router: axum::Router) {
    let port = match request.request() {
        IncomingStreamRequest::Begin(begin) => Some(begin.port()),
        _ => None,
    };
    if port != Some(PORT) {
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            request.reject(End::new_with_reason(EndReason::DONE)),
        )
        .await;
        return;
    }
    let stream = match tokio::time::timeout(HEADERS, request.accept(Connected::new_empty())).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tracing::debug!("an onion stream not accepted: {e}");
            return;
        }
        Err(_) => return,
    };
    http(stream, router).await;
}

/// A header deadline releases idle streams without limiting the duration
/// of a legitimate response (contract downloads can take minutes).
async fn http(
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    router: axum::Router,
) {
    let service = TowerToHyperService::new(router);
    let connection = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADERS)
        .serve_connection(TokioIo::new(stream), service)
        .await;
    if let Err(e) = connection {
        tracing::debug!("an onion connection: {e}");
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Built with Arti's proof of work, which a service asks for only if
    /// it is.
    #[test]
    fn an_onion_service_may_ask_for_a_proof_of_work() {
        config("licash-test", true).unwrap();
        config("licash-test", false).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_http_stream_times_out_and_a_normal_request_still_works() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let router = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
        let (_client, server) = tokio::io::duplex(4096);
        let idle = tokio::spawn(http(server, router.clone()));
        tokio::task::yield_now().await;
        tokio::time::advance(HEADERS + Duration::from_secs(1)).await;
        idle.await.unwrap();

        let (mut client, server) = tokio::io::duplex(4096);
        let served = tokio::spawn(http(server, router));
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("ok"), "{response}");
        served.await.unwrap();
    }

    /// What `url` answers on a connection of its own, which the server ends
    /// (`Connection: close`): empty if it closed it unanswered.
    async fn ask(at: std::net::SocketAddr, path: &str) -> (String, std::net::SocketAddr) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut client = tokio::net::TcpStream::connect(at).await.unwrap();
        let local = client.local_addr().unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
        // Written to a connection already closed, it fails: nothing read.
        let _ = client.write_all(request.as_bytes()).await;
        let mut response = String::new();
        let _ = client.read_to_string(&mut response).await;
        (response, local)
    }

    fn peer_router() -> axum::Router {
        use axum::extract::ConnectInfo;
        axum::Router::new()
            .route(
                "/peer",
                axum::routing::get(
                    |ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>| async move {
                        peer.to_string()
                    },
                ),
            )
            .route(
                "/slow",
                axum::routing::get(|| async {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    "done"
                }),
            )
    }

    #[tokio::test]
    async fn the_clear_web_is_served_to_a_bounded_number_of_clients_never_idle_for_long() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let headers = Duration::from_millis(500);
        let serving = tokio::spawn(listen_with(
            listener,
            peer_router(),
            std::future::pending(),
            headers,
            2,
        ));
        // Each request knows its peer.
        let (response, local) = ask(at, "/peer").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with(&local.to_string()), "{response}");
        // Two clients sending nothing hold both places...
        let started = std::time::Instant::now();
        let mut idle = Vec::new();
        for _ in 0..2 {
            idle.push(tokio::net::TcpStream::connect(at).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // ... so a third is closed unanswered...
        let (response, _) = ask(at, "/peer").await;
        assert_eq!(response, "");
        // ... until they are let go, their headers late.
        for mut stream in idle {
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest).await;
        }
        assert!(started.elapsed() >= headers);
        assert!(started.elapsed() < headers * 4);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (response, _) = ask(at, "/peer").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        serving.abort();
    }

    #[tokio::test]
    async fn the_clear_web_stops_once_the_requests_under_way_are_answered() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(listen_with(
            listener,
            peer_router(),
            async move {
                let _ = stopped.await;
            },
            Duration::from_secs(5),
            8,
        ));
        let slow = tokio::spawn(ask(at, "/slow"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send(()).unwrap();
        let (response, _) = slow.await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("done"), "{response}");
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .unwrap()
            .unwrap();
        assert!(tokio::net::TcpStream::connect(at).await.is_err());
    }

    /// One Tor client serves a router, another reaches it once its service
    /// is published.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "reaches the Tor network"]
    async fn a_router_answers_as_an_onion_service() {
        let (served, asking) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let router = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
        let onion = Tor::new(served.path())
            .unwrap()
            .serve("licash-test", router, true)
            .unwrap();
        assert!(onion.url().ends_with(".onion"), "{}", onion.url());
        let client = Tor::new(asking.path()).unwrap();
        let url = format!("{}/health", onion.url());
        let mut last = String::new();
        for _ in 0..20 {
            match client.request(&url, None, 1024).await {
                Ok((200, body)) => return assert_eq!(body, b"ok"),
                answer => last = format!("{answer:?}"),
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
        panic!("{url}: {last}");
    }
}
