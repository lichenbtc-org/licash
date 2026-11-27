//! Paying a Lightning Address or an LNURL-pay code: what its service
//! takes, then an invoice of it, checked before it is paid.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Secp256k1, SecretKey},
};
use licash::spend::ChainProfile;
use licash_wallet::{lnurl_pay_target, Error, Response, Transport, Wallet};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use serde_json::json;

const ADDRESS: &str = "alice@pay.example";
const ASKED: &str = "https://pay.example/.well-known/lnurlp/alice";
const CALLBACK: &str = "https://pay.example/cb?alice=1";
const METADATA: &str =
    r#"[["text/plain","Tips for Alice"],["text/identifier","alice@pay.example"]]"#;

/// What a URL answers: its status and body.
type Answers = HashMap<String, (u16, String)>;

/// A payee's service, answering each URL as told, and the URLs asked.
#[derive(Clone, Default)]
struct Service(Arc<Mutex<(Answers, Vec<String>)>>);

impl Service {
    fn answer(&self, url: &str, status: u16, body: serde_json::Value) {
        let mut s = self.0.lock().unwrap();
        s.0.insert(url.to_owned(), (status, body.to_string()));
    }

    fn asked(&self) -> Vec<String> {
        self.0.lock().unwrap().1.clone()
    }
}

impl Transport for Service {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        assert!(body.is_none(), "LNURL is asked with GET");
        let mut s = self.0.lock().unwrap();
        s.1.push(url.to_owned());
        let answer = s.0.get(url).cloned();
        async move {
            let (status, body) = answer.ok_or("unreachable")?;
            Ok(Response {
                status,
                body: body.into_bytes(),
            })
        }
    }
}

fn wallet(service: &Service) -> (tempfile::TempDir, Wallet<Service>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let network = ChainProfile::Core30Signet;
    let wallet = Wallet::create(&path, &[0x11; 32], network, service.clone()).unwrap();
    (dir, wallet)
}

fn pay_request(min: u64, max: u64) -> serde_json::Value {
    json!({
        "tag": "payRequest",
        "callback": CALLBACK,
        "minSendable": min,
        "maxSendable": max,
        "metadata": METADATA,
    })
}

/// An invoice of `msat` on `currency`, committing to `metadata`.
fn invoice(currency: Currency, msat: u64, metadata: &str) -> String {
    let key = SecretKey::from_slice(&[0x42; 32]).unwrap();
    InvoiceBuilder::new(currency)
        .description_hash(sha256::Hash::hash(metadata.as_bytes()))
        .payment_hash(sha256::Hash::hash(b"preimage"))
        .payment_secret(PaymentSecret([7; 32]))
        .duration_since_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap(),
        )
        .expiry_time(Duration::from_secs(600))
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(msat)
        .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &key))
        .unwrap()
        .to_string()
}

fn invalid(result: Result<impl std::fmt::Debug, Error>) -> String {
    match result {
        Err(Error::Invalid(why)) => why,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_lightning_address_is_paid_by_an_invoice_its_service_makes() {
    let service = Service::default();
    service.answer(ASKED, 200, pay_request(1_000, 1_000_000_000));
    let (_dir, wallet) = wallet(&service);

    let pay = wallet.lnurl_pay_request(ADDRESS).await.unwrap();
    assert_eq!(pay.payee, ADDRESS);
    assert_eq!((pay.min_sat(), pay.max_sat()), (1, 1_000_000));
    assert_eq!(pay.description.as_deref(), Some("Tips for Alice"));
    assert_eq!(pay.callback, CALLBACK);

    // Asked for 2,100 sat, in msat, after what the callback already says.
    let made = invoice(Currency::Signet, 2_100_000, METADATA);
    let asking = format!("{CALLBACK}&amount=2100000");
    service.answer(&asking, 200, json!({ "pr": made, "routes": [] }));
    assert_eq!(wallet.lnurl_invoice(&pay, 2_100).await.unwrap(), made);
    assert_eq!(service.asked(), [ASKED.to_owned(), asking]);
    // Read as any invoice, to pay through a provider.
    assert_eq!(wallet.read_invoice(&made).unwrap().amount, 2_100);
}

#[tokio::test]
async fn an_invoice_not_for_what_was_shown_or_asked_is_refused() {
    let service = Service::default();
    service.answer(ASKED, 200, pay_request(1_000, 1_000_000_000));
    let (_dir, wallet) = wallet(&service);
    let pay = wallet.lnurl_pay_request(ADDRESS).await.unwrap();
    let asking = format!("{CALLBACK}&amount=2100000");
    let answers = |pr: String| json!({ "pr": pr });

    // Another amount than asked.
    service.answer(
        &asking,
        200,
        answers(invoice(Currency::Signet, 2_000_000, METADATA)),
    );
    let why = invalid(wallet.lnurl_invoice(&pay, 2_100).await);
    assert!(why.contains("not the 2100000 asked"), "{why}");
    // For something else than shown: the service could swap what is paid for.
    service.answer(
        &asking,
        200,
        answers(invoice(Currency::Signet, 2_100_000, "[]")),
    );
    let why = invalid(wallet.lnurl_invoice(&pay, 2_100).await);
    assert!(why.contains("not for what it showed"), "{why}");
    // Of another network.
    service.answer(
        &asking,
        200,
        answers(invoice(Currency::Bitcoin, 2_100_000, METADATA)),
    );
    let why = invalid(wallet.lnurl_invoice(&pay, 2_100).await);
    assert!(why.contains("another network"), "{why}");
    // Refused, in LNURL's words.
    service.answer(
        &asking,
        200,
        json!({ "status": "ERROR", "reason": "no route" }),
    );
    let why = invalid(wallet.lnurl_invoice(&pay, 2_100).await);
    assert_eq!(why, "pay.example refused: no route");
    // More or less than it takes: not asked at all.
    let before = service.asked().len();
    invalid(wallet.lnurl_invoice(&pay, 1_000_001).await);
    invalid(wallet.lnurl_invoice(&pay, 0).await);
    assert_eq!(service.asked().len(), before);
}

#[tokio::test]
async fn a_service_not_taking_payments_is_refused() {
    let service = Service::default();
    let (_dir, wallet) = wallet(&service);
    // Of another kind.
    service.answer(ASKED, 200, json!({ "tag": "withdrawRequest", "callback": CALLBACK, "minSendable": 1, "maxSendable": 2, "metadata": "[]" }));
    assert!(invalid(wallet.lnurl_pay_request(ADDRESS).await).contains("another kind"));
    // Taking nothing.
    service.answer(ASKED, 200, pay_request(5_000, 1_000));
    assert!(invalid(wallet.lnurl_pay_request(ADDRESS).await).contains("takes no amount"));
    // Its invoices asked over plain HTTP.
    let mut plain = pay_request(1_000, 2_000);
    plain["callback"] = json!("http://pay.example/cb");
    service.answer(ASKED, 200, plain);
    assert!(invalid(wallet.lnurl_pay_request(ADDRESS).await).contains("over HTTPS"));
    // Refusing, or not an LNURL service.
    service.answer(
        ASKED,
        200,
        json!({ "status": "ERROR", "reason": "no such user" }),
    );
    assert_eq!(
        invalid(wallet.lnurl_pay_request(ADDRESS).await),
        "pay.example refused: no such user"
    );
    service.answer(ASKED, 404, json!({ "error": "not found" }));
    assert!(invalid(wallet.lnurl_pay_request(ADDRESS).await).contains("HTTP 404"));
    // Neither an address nor an LNURL: nothing asked.
    let before = service.asked().len();
    invalid(wallet.lnurl_pay_request("lnbc1").await);
    assert_eq!(service.asked().len(), before);
    assert_eq!(lnurl_pay_target("lnbc1", ChainProfile::Core30Signet), None);
}
