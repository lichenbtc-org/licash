//! A hub's client of one witness: over TLS to the certificate it pins
//! alone, whatever the certificate names or when it expires.

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, ensure, Context, Result};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};

use crate::{
    server::{entry_path, pin_of, ENTRIES, STATUS},
    Read, Status, Write,
};

/// How long a witness has to connect, and to answer.
const CONNECT: Duration = Duration::from_secs(5);
const ANSWER: Duration = Duration::from_secs(15);

/// A witness's refusal of what it was asked: given for good, unlike its
/// silence.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// A witness, by its URL and the pin of its certificate.
#[derive(Clone, Debug)]
pub struct Client {
    url: String,
    pin: [u8; 32],
    http: reqwest::Client,
}

/// Accepts the certificate of one pin alone, the handshake's signatures
/// checked as any.
#[derive(Debug)]
struct Pinned {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match pin_of(end_entity) == self.pin {
            true => Ok(ServerCertVerified::assertion()),
            false => Err(rustls::Error::General(
                "not the certificate this witness is pinned to".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl Client {
    /// A witness as configured: `https://host:port#<pin>`, its pin the
    /// SHA-256 of its certificate's DER in hex.
    pub fn parse(s: &str) -> Result<Self> {
        let (url, pin) = s
            .rsplit_once('#')
            .ok_or_else(|| anyhow!("{s:?}: a witness is https://host:port#<pin>"))?;
        let pin = <[u8; 32]>::try_from(hex::decode(pin).unwrap_or_default())
            .map_err(|_| anyhow!("{s:?}: its pin is 32 bytes in hex"))?;
        Self::new(url, pin)
    }

    /// The witness at `url` (`https://`) of certificate pinned `pin`.
    pub fn new(url: &str, pin: [u8; 32]) -> Result<Self> {
        let url = url.trim_end_matches('/');
        ensure!(
            url.starts_with("https://"),
            "{url}: a witness is reached over https"
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(Pinned {
            pin,
            provider: provider.clone(),
        });
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .connect_timeout(CONNECT)
            .timeout(ANSWER)
            .build()?;
        Ok(Self {
            url: url.to_owned(),
            pin,
            http,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn pin(&self) -> [u8; 32] {
        self.pin
    }

    pub async fn status(&self) -> Result<Status> {
        self.answer(self.http.get(format!("{}{STATUS}", self.url)))
            .await
    }

    /// What it holds of `slot` of `contract`.
    pub async fn read(&self, contract: &[u8; 32], slot: &str) -> Result<Read> {
        let url = format!("{}{}", self.url, entry_path(contract, slot));
        self.answer(self.http.get(url)).await
    }

    /// Ask it to keep `write`: what it keeps in its slot.
    pub async fn write(&self, write: &Write) -> Result<Read> {
        let url = format!("{}{ENTRIES}", self.url);
        self.answer(self.http.post(url).json(write)).await
    }

    async fn answer<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T> {
        let response = request
            .send()
            .await
            .with_context(|| format!("witness {}", self.url))?;
        let status = response.status();
        if !status.is_success() {
            let why: serde_json::Value = response.json().await.unwrap_or_default();
            let why = why["error"]
                .as_str()
                .unwrap_or("no reason given")
                .to_owned();
            return Err(Refused(format!("witness {} refused ({status}): {why}", self.url)).into());
        }
        response
            .json()
            .await
            .with_context(|| format!("witness {}: an answer that does not read", self.url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{signed, slot, store::Store};

    const SECRET: [u8; 32] = [7; 32];
    const SET: [u8; 32] = [3; 32];

    /// A witness served on a local port: its directory, URL and pin.
    async fn serve() -> (tempfile::TempDir, String, [u8; 32]) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("witness.sqlite");
        Store::create(&db, &SET, &crate::public_key(&SECRET).unwrap()).unwrap();
        let pin = crate::server::make_identity(dir.path()).unwrap();
        let store = Arc::new(Store::open(&db).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        let path = dir.path().to_owned();
        tokio::spawn(async move {
            crate::server::serve(listener, &path, store, std::future::pending())
                .await
                .unwrap()
        });
        (dir, url, pin)
    }

    #[tokio::test]
    async fn a_hub_reaches_the_witness_it_pins_and_no_other() {
        let (_dir, url, pin) = serve().await;
        let witness = Client::parse(&format!("{url}#{}", hex::encode(pin))).unwrap();
        let status = witness.status().await.unwrap();
        assert_eq!((status.set_id, status.sequence), (SET, 0));
        let enroll = signed(&SECRET, &SET, &[1; 32], slot::ENROLL, vec![]).unwrap();
        assert!(witness.write(&enroll).await.unwrap().enrolled);
        let first = signed(&SECRET, &SET, &[1; 32], slot::RESPOND, b"one".to_vec()).unwrap();
        let other = signed(&SECRET, &SET, &[1; 32], slot::RESPOND, b"two".to_vec()).unwrap();
        witness.write(&first).await.unwrap();
        let kept = witness.write(&other).await.unwrap();
        assert_eq!(kept.entry, Some(first.entry));
        let read = witness.read(&[1; 32], slot::RESPOND).await.unwrap();
        assert_eq!(read, kept);
        // Refused, with its reason.
        let unenrolled = signed(&SECRET, &SET, &[2; 32], slot::ASSERT, vec![]).unwrap();
        let why = witness.write(&unenrolled).await.unwrap_err().to_string();
        assert!(why.contains("not enrolled"), "{why}");
        // Another certificate than the one pinned is never spoken to.
        let wrong = Client::new(&url, [0; 32]).unwrap();
        assert!(wrong.status().await.is_err());
        assert!(Client::parse(&url).is_err());
        assert!(Client::parse(&format!("http://x#{}", hex::encode(pin))).is_err());
    }
}
