//! A router served on a TCP listener, in the clear or over TLS.

use std::{future::Future, time::Duration};

use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};

/// Connections served at once: one more is closed as accepted.
pub const MAX_CONNECTIONS: usize = 1024;

/// How long a client may take to finish its TLS handshake, to send a
/// request's headers, or stay idle before its next request.
pub const HEADERS: Duration = Duration::from_secs(30);

/// How long the connections still open when the server stops may take to
/// end, before they are cut.
const DRAIN: Duration = Duration::from_secs(30);

/// Serve `router` over HTTP/1.1 on `listener` until `stop`, each request
/// carrying its peer as [`axum::extract::ConnectInfo`]: unlike
/// `axum::serve`, a client stalling its headers, or idle, is let go
/// ([`HEADERS`]), and at most [`MAX_CONNECTIONS`] are served at once. Once
/// `stop`, the requests under way are answered, for up to 30 seconds.
pub async fn listen(listener: TcpListener, router: axum::Router, stop: impl Future<Output = ()>) {
    serve(
        listener,
        router,
        stop,
        Limits::default(),
        |stream| async move { Some(stream) },
    )
    .await
}

/// [`listen`], over TLS by `tls`: a handshake not finished within
/// [`HEADERS`] lets the connection go.
pub async fn listen_tls(
    listener: TcpListener,
    tls: tokio_rustls::TlsAcceptor,
    router: axum::Router,
    stop: impl Future<Output = ()>,
) {
    serve(listener, router, stop, Limits::default(), move |stream| {
        let accepting = tls.accept(stream);
        async move {
            accepting
                .await
                .inspect_err(|e| tracing::debug!("a TLS handshake failed: {e}"))
                .ok()
        }
    })
    .await
}

#[derive(Clone, Copy)]
struct Limits {
    headers: Duration,
    most: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            headers: HEADERS,
            most: MAX_CONNECTIONS,
        }
    }
}

async fn serve<S, H>(
    listener: TcpListener,
    router: axum::Router,
    stop: impl Future<Output = ()>,
    limits: Limits,
    handshake: impl Fn(TcpStream) -> H,
) where
    H: Future<Output = Option<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
        if connections.len() >= limits.most {
            tracing::debug!(%peer, "a connection past {} closed", limits.most);
            continue;
        }
        let shaking = handshake(stream);
        let router = router
            .clone()
            .layer(axum::Extension(axum::extract::ConnectInfo(peer)));
        let mut stopped = stopped.clone();
        connections.spawn(async move {
            let Ok(Some(stream)) = tokio::time::timeout(limits.headers, shaking).await else {
                return;
            };
            let connection = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(limits.headers)
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

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use futures_util::FutureExt as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn plain(stream: TcpStream) -> Option<TcpStream> {
        Some(stream)
    }

    /// What `path` answers on a connection of its own, which the server
    /// ends (`Connection: close`): empty if it closed it unanswered.
    async fn ask(at: SocketAddr, path: &str) -> (String, SocketAddr) {
        let mut client = TcpStream::connect(at).await.unwrap();
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
                axum::routing::get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
                    peer.to_string()
                }),
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
    async fn a_bounded_number_of_clients_is_served_never_idle_for_long() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let headers = Duration::from_millis(500);
        let limits = Limits { headers, most: 2 };
        let serving = tokio::spawn(serve(
            listener,
            peer_router(),
            std::future::pending(),
            limits,
            plain,
        ));
        // Each request knows its peer.
        let (response, local) = ask(at, "/peer").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with(&local.to_string()), "{response}");
        // Two clients sending nothing hold both places...
        let started = std::time::Instant::now();
        let mut idle = Vec::new();
        for _ in 0..2 {
            idle.push(TcpStream::connect(at).await.unwrap());
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
    async fn it_stops_once_the_requests_under_way_are_answered() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let limits = Limits {
            headers: Duration::from_secs(5),
            most: 8,
        };
        let serving = tokio::spawn(serve(
            listener,
            peer_router(),
            async move {
                let _ = stopped.await;
            },
            limits,
            plain,
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
        assert!(TcpStream::connect(at).await.is_err());
    }

    fn tls() -> (tokio_rustls::TlsAcceptor, tokio_rustls::TlsConnector) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = CertificateDer::from(made.cert.der().to_vec());
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(made.key_pair.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (
            tokio_rustls::TlsAcceptor::from(Arc::new(server)),
            tokio_rustls::TlsConnector::from(Arc::new(client)),
        )
    }

    /// Over TLS: a client that never finishes its handshake holds its
    /// place no longer than the headers' deadline, one that does is served.
    #[tokio::test]
    async fn over_tls_a_stalled_handshake_is_let_go() {
        let (acceptor, connector) = tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let headers = Duration::from_millis(500);
        let limits = Limits { headers, most: 1 };
        let serving = tokio::spawn(serve(
            listener,
            peer_router(),
            std::future::pending(),
            limits,
            move |stream| acceptor.accept(stream).map(Result::ok),
        ));
        let started = std::time::Instant::now();
        let mut stalled = TcpStream::connect(at).await.unwrap();
        let mut rest = Vec::new();
        let _ = stalled.read_to_end(&mut rest).await;
        assert!(started.elapsed() >= headers);
        assert!(started.elapsed() < headers * 4);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stream = TcpStream::connect(at).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut stream = connector.connect(name, stream).await.unwrap();
        stream
            .write_all(b"GET /peer HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        serving.abort();
    }
}
