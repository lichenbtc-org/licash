//! A witness's service: its [`Store`] over HTTPS, under a self-signed
//! certificate whose SHA-256 (of its DER) the hub pins.

use std::{future::Future, path::Path, sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Path as UrlPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use crate::{store::Store, valid, Write, MAX_BODY};

/// The paths a witness serves.
pub const STATUS: &str = "/v1/status";
pub const ENTRIES: &str = "/v1/entries";

/// The path of `slot` of `contract`.
pub fn entry_path(contract: &[u8; 32], slot: &str) -> String {
    format!("{ENTRIES}/{}/{slot}", hex::encode(contract))
}

/// Its certificate and key, in its data directory.
const CERT: &str = "tls.crt";
const KEY: &str = "tls.key";

/// How long a request's body may take to arrive: as long as a hub waits
/// for its answer (an entry of [`MAX_BODY`] at 35 KB/s).
pub const BODY_TIME: Duration = Duration::from_secs(15);

/// The SHA-256 of a certificate's DER: what a hub pins a witness by.
pub fn pin_of(cert: &[u8]) -> [u8; 32] {
    Sha256::digest(cert).into()
}

/// Make a TLS identity in `dir`, which must hold none: its pin.
pub fn make_identity(dir: &Path) -> Result<[u8; 32]> {
    let (cert, key) = (dir.join(CERT), dir.join(KEY));
    ensure!(
        !cert.exists() && !key.exists(),
        "{} holds a TLS identity",
        dir.display()
    );
    let made = rcgen::generate_simple_self_signed(vec!["licash-witness".to_owned()])?;
    std::fs::write(&cert, made.cert.pem())?;
    write_private(&key, made.key_pair.serialize_pem().as_bytes())?;
    Ok(pin_of(made.cert.der()))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(bytes)?;
    Ok(())
}

/// The TLS identity in `dir`: its certificate and key.
pub fn identity(dir: &Path) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert = CertificateDer::from_pem_file(dir.join(CERT))
        .with_context(|| format!("read {}", dir.join(CERT).display()))?;
    let key = PrivateKeyDer::from_pem_file(dir.join(KEY))
        .with_context(|| format!("read {}", dir.join(KEY).display()))?;
    Ok((cert, key))
}

/// What a witness answers when it does not keep what it is asked to.
fn refused(status: StatusCode, why: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": why.into() }))).into_response()
}

fn failed(e: anyhow::Error) -> Response {
    tracing::error!("the witness's store: {e:#}");
    refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "the witness cannot answer now",
    )
}

async fn blocking<T: Send + 'static>(
    store: Arc<Store>,
    op: impl FnOnce(&Store) -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(move || op(&store)).await?
}

async fn status(State(store): State<Arc<Store>>) -> Response {
    match blocking(store, |s| s.status()).await {
        Ok(status) => Json(status).into_response(),
        Err(e) => failed(e),
    }
}

async fn read(
    State(store): State<Arc<Store>>,
    UrlPath((contract, slot)): UrlPath<(String, String)>,
) -> Response {
    let Ok(contract) = <[u8; 32]>::try_from(hex::decode(&contract).unwrap_or_default()) else {
        return refused(StatusCode::BAD_REQUEST, "a contract's id: 32 bytes in hex");
    };
    if !valid(&contract, &slot) {
        return refused(StatusCode::BAD_REQUEST, format!("no slot {slot:?}"));
    }
    match blocking(store, move |s| s.read(&contract, &slot)).await {
        Ok(read) => Json(read).into_response(),
        Err(e) => failed(e),
    }
}

async fn write(State(store): State<Arc<Store>>, body: axum::body::Bytes) -> Response {
    let Ok(write) = serde_json::from_slice::<Write>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "not a write");
    };
    match blocking(store, move |s| s.write(&write)).await {
        Ok(Ok(read)) => Json(read).into_response(),
        Ok(Err(why)) => refused(StatusCode::CONFLICT, why),
        Err(e) => failed(e),
    }
}

/// The witness's API over `store`: a request's body still arriving
/// [`BODY_TIME`] after its head is refused.
pub fn router(store: Arc<Store>) -> Router {
    let api = Router::new()
        .route(STATUS, get(status))
        .route(&format!("{ENTRIES}/{{contract}}/{{slot}}"), get(read))
        .route(ENTRIES, post(write))
        // An entry, in hex, and its envelope.
        .layer(DefaultBodyLimit::max(2 * MAX_BODY + 4096))
        .with_state(store);
    licash_serve::bodies_within(api, BODY_TIME)
}

/// Serve `store` over TLS on `listener` with the identity in `dir`, until
/// `stop`: [`licash_serve::listen_tls`], at most
/// [`licash_serve::MAX_CONNECTIONS`] at once, each let go if its handshake
/// or a request's head takes longer than [`licash_serve::HEADERS`].
pub async fn serve(
    listener: tokio::net::TcpListener,
    dir: &Path,
    store: Arc<Store>,
    stop: impl Future<Output = ()>,
) -> Result<()> {
    let (cert, key) = identity(dir)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    licash_serve::listen_tls(listener, acceptor, router(store), stop).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, Bytes};
    use tower::ServiceExt as _;

    use super::*;

    /// An entry whose body stalls is refused once [`BODY_TIME`] passed,
    /// rather than holding its connection and its task for good.
    #[tokio::test(start_paused = true)]
    async fn an_entry_whose_body_stalls_is_refused_in_time() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("witness.sqlite");
        Store::create(&db, &[3; 32], &crate::public_key(&[7; 32]).unwrap()).unwrap();
        let app = router(Arc::new(Store::open(&db).unwrap()));
        let stalled =
            Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
        let request = axum::http::Request::post(ENTRIES).body(stalled).unwrap();
        let writing = tokio::spawn(app.oneshot(request));
        tokio::time::sleep(BODY_TIME - Duration::from_secs(1)).await;
        assert!(!writing.is_finished());
        tokio::time::sleep(Duration::from_secs(2)).await;
        let refused = writing.await.unwrap().unwrap();
        assert!(refused.status().is_client_error(), "{}", refused.status());
    }
}
