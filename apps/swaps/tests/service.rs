//! The provider's API and notifications over a provider whose wallet
//! reaches no hub, and its binary's commands that need none.

use std::{
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use http_body_util::BodyExt;
use licash::spend::ChainProfile;
use licash_api::{swaps, Code, Problem};
use licash_lightning::fake::{Fake, Outcome};
use licash_swaps::{Config, Provider};
use licash_wallet::{Response, Transport, Wallet};
use tower::ServiceExt;

struct Offline;

impl Transport for Offline {
    fn request(
        &self,
        _: &str,
        _: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        std::future::ready(Err("offline".into()))
    }
}

fn router(dir: &tempfile::TempDir) -> (Router, Arc<Provider<Offline>>) {
    let wallet = Wallet::create(
        &dir.path().join("wallet.sqlite"),
        &[5; 32],
        ChainProfile::Core30DefaultRegtest,
        Offline,
    )
    .unwrap();
    let provider = Provider::create(wallet, Config::default());
    let provider = Arc::new(provider.unwrap());
    let router = licash_swaps_service::router(provider.clone(), Some("ab".repeat(32)));
    (router, provider)
}

async fn call(router: &Router, path: &str, body: Option<&str>) -> (StatusCode, Vec<u8>) {
    let request = match body {
        Some(body) => Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned())),
        None => Request::get(path).body(Body::empty()),
    };
    let response = router.clone().oneshot(request.unwrap()).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

fn problem(body: &[u8]) -> Problem {
    serde_json::from_slice(body).unwrap()
}

#[tokio::test]
async fn the_api_answers_what_the_provider_swaps_and_declines_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let (router, provider) = router(&dir);

    let (status, body) = call(&router, swaps::SWAPS_INFO, None).await;
    assert_eq!(status, StatusCode::OK);
    let info: swaps::Info = serde_json::from_slice(&body).unwrap();
    assert_eq!(info.address, provider.wallet().address());
    assert_eq!((info.fee, info.margin), (Config::default().fee, 12));
    assert!(info.hubs.is_empty());
    assert_eq!(info.nostr, Some("ab".repeat(32)));

    let address = provider.wallet().address();
    let id = licash::spend::ProposalId::from_bytes([1; 32]);
    let request = swaps::Request::new(&address, &id, &address, &address, 5000);
    let body = serde_json::to_string(&request).unwrap();
    let (status, answer) = call(&router, swaps::SWAPS, Some(&body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem(&answer).code, Code::Declined);

    let (status, answer) = call(&router, swaps::SWAPS, Some("{\"from\": 1}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem(&answer).code, Code::Invalid);

    let (status, answer) = call(&router, &swaps::swap_state(&id), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem(&answer).code, Code::UnknownLock);
    let (status, _) = call(&router, "/v1/swaps/zz", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Paying nothing out on Bitcoin: no payout taken, none known.
    assert_eq!(info.chain, None);
    let payout = swaps::ChainRequest::new(&address, &id, [2; 32], 20_000);
    let body = serde_json::to_string(&payout).unwrap();
    let (status, answer) = call(&router, swaps::CHAIN_SWAPS, Some(&body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let declined = problem(&answer);
    assert_eq!(declined.code, Code::Declined);
    assert!(declined.message.contains("no payouts"), "{declined:?}");
    let (status, answer) = call(&router, &swaps::chain_swap_state(&id), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem(&answer).code, Code::UnknownLock);

    // Paying nothing over Lightning: no invoice paid, none known.
    assert_eq!(info.lightning, None);
    let node = Fake::new();
    let invoice = node.invoice(10_000_000, [3; 32], 18, Outcome::Hang);
    let pay = swaps::LightningRequest::new(&address, &id, &invoice);
    let body = serde_json::to_string(&pay).unwrap();
    let (status, answer) = call(&router, swaps::LIGHTNING_SWAPS, Some(&body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let declined = problem(&answer);
    assert!(declined.message.contains("no Lightning"), "{declined:?}");
    let garbled = swaps::LightningRequest::new(&address, &id, "lnbcrt1nothing");
    let body = serde_json::to_string(&garbled).unwrap();
    let (status, answer) = call(&router, swaps::LIGHTNING_SWAPS, Some(&body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem(&answer).code, Code::Invalid);
    let (status, answer) = call(&router, &swaps::lightning_swap_state(&id), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem(&answer).code, Code::UnknownLock);

    let (status, body) = call(&router, licash_swaps_service::HEALTH, None).await;
    assert_eq!(
        (status, body.as_slice()),
        (StatusCode::OK, b"ok".as_slice())
    );
}

#[tokio::test]
async fn a_provider_paying_over_lightning_says_so_and_takes_invoices_from_its_hubs_only() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(
        &dir.path().join("wallet.sqlite"),
        &[5; 32],
        ChainProfile::Core30DefaultRegtest,
        Offline,
    )
    .unwrap();
    let node = Arc::new(Fake::new());
    let terms = swaps::Lightning {
        node: node.pubkey(),
        fee: licash_api::Fee { base: 2, ppm: 5000 },
        max: 100_000,
        slack: 80,
    };
    let provider = Provider::create(wallet, Config::default())
        .unwrap()
        .pay_lightning(node.clone(), terms.clone())
        .unwrap();
    let address = provider.wallet().address();
    let router = licash_swaps_service::router(Arc::new(provider), None);
    let (status, body) = call(&router, swaps::SWAPS_INFO, None).await;
    assert_eq!(status, StatusCode::OK);
    let info: swaps::Info = serde_json::from_slice(&body).unwrap();
    assert_eq!(info.lightning, Some(terms.clone()));
    // No more than its node's channels pay, its fee in it: 9,948 and 2 and
    // 0.5% on it pay 10,000.
    node.channels(10_000, 0);
    let (_, body) = call(&router, swaps::SWAPS_INFO, None).await;
    let info: swaps::Info = serde_json::from_slice(&body).unwrap();
    let max = info.lightning.map(|l| l.max);
    assert_eq!(max, Some(9_948));

    // From a hub it does not know.
    let id = licash::spend::ProposalId::from_bytes([1; 32]);
    let invoice = node.invoice(10_000_000, [3; 32], 18, Outcome::Hang);
    let pay = swaps::LightningRequest::new(&address, &id, &invoice);
    let body = serde_json::to_string(&pay).unwrap();
    let (status, answer) = call(&router, swaps::LIGHTNING_SWAPS, Some(&body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let declined = problem(&answer);
    assert!(declined.message.contains("from this hub"), "{declined:?}");
    assert!(node.sent().is_empty());
}

fn licash_swaps(dir: &tempfile::TempDir, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_licash-swaps"))
        .arg("--data")
        .arg(dir.path().join("data"))
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
}

#[test]
fn a_directory_of_an_earlier_layout_is_refused_by_name_and_left_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let init = licash_swaps(&dir, &["init"]);
    assert!(init.status.success(), "{init:?}");
    let old = dir.path().join("data/swaps.sqlite");
    std::fs::write(&old, b"an earlier provider's file").unwrap();
    for args in [&["status"][..], &["init"], &["address"]] {
        let out = licash_swaps(&dir, args);
        assert!(!out.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("earlier layout") && stderr.contains("swaps.sqlite"),
            "{args:?}: {stderr}"
        );
    }
    assert_eq!(std::fs::read(&old).unwrap(), b"an earlier provider's file");
}

#[test]
fn init_creates_the_provider_once_and_status_reads_it() {
    let dir = tempfile::tempdir().unwrap();
    let init = licash_swaps(&dir, &["init"]);
    assert!(init.status.success(), "{init:?}");
    let address = String::from_utf8(init.stdout).unwrap();
    let message = String::from_utf8_lossy(&init.stderr);
    assert!(
        message.starts_with("Provider created. Back up wallet.sqlite in "),
        "{message}"
    );
    assert!(
        !message.contains(address.trim()) && !message.contains("schema migrated"),
        "{message}"
    );
    assert_eq!(
        address.trim().len(),
        2 * licash::address::ADDRESS_BYTES,
        "{address}"
    );
    let machine = tempfile::tempdir().unwrap();
    let created = licash_swaps(&machine, &["--log", "json", "init"]);
    assert!(created.status.success(), "{created:?}");
    let event = String::from_utf8_lossy(&created.stderr)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|line| line["fields"]["message"] == "provider created: back up its wallet file")
        .unwrap();
    assert_eq!(event["level"], "INFO");
    assert_eq!(
        event["fields"]["address"],
        String::from_utf8_lossy(&created.stdout).trim()
    );
    let again = licash_swaps(&dir, &["init"]);
    assert!(!again.status.success());

    let status = licash_swaps(&dir, &["status", "--json"]);
    assert!(status.status.success(), "{status:?}");
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["address"], address.trim());
    assert_eq!(status["network"], "bitcoin");
    assert_eq!(status["stats"]["open"], 0);
    assert_eq!(status["swaps"], serde_json::json!([]));
    // Read by a person: what it earned first, in sat; what it did, in words.
    let text = licash_swaps(&dir, &["status"]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.starts_with("earned "), "{text}");
    let said = |label: &str| {
        let line = text.lines().find(|l| l.starts_with(label));
        line.map(|l| l[label.len()..].trim().to_owned())
    };
    assert_eq!(said("earned").as_deref(), Some("0 sat"), "{text}");
    assert_eq!(said("swaps").as_deref(), Some("none"), "{text}");
    assert_eq!(said("lost").as_deref(), Some("none"), "{text}");
    assert_eq!(said("balance").as_deref(), Some("0 sat"), "{text}");
    assert_eq!(said("address"), None, "{text}");
    assert_eq!(said("events"), None, "{text}");
    let detailed = licash_swaps(&dir, &["status", "--details"]);
    assert!(detailed.status.success(), "{detailed:?}");
    let detailed = String::from_utf8(detailed.stdout).unwrap();
    assert!(detailed.contains(address.trim()), "{detailed}");
    assert!(
        detailed.lines().any(|line| line.starts_with("events")),
        "{detailed}"
    );
    let missing = licash_swaps(&tempfile::tempdir().unwrap(), &["status"]);
    assert!(!missing.status.success());
    let error = String::from_utf8_lossy(&missing.stderr);
    assert!(error.starts_with("error: "), "{error}");
    assert_eq!(error.lines().count(), 1, "{error}");
    let events = licash_swaps(&dir, &["events"]);
    assert!(events.status.success() && events.stdout.is_empty());
    // An address on Bitcoin to fund payouts at, watched from a first block,
    // given once: the same until paid.
    let unwatched = licash_swaps(&dir, &["address"]);
    assert!(!unwatched.status.success());
    assert!(String::from_utf8_lossy(&unwatched.stderr).contains("--chain-from"));
    let funding = licash_swaps(&dir, &["address", "--chain-from", "900000"]);
    assert!(funding.status.success(), "{funding:?}");
    let funding = String::from_utf8(funding.stdout).unwrap();
    assert!(funding.starts_with("bc1p"), "{funding}");
    let again = licash_swaps(&dir, &["address"]);
    assert_eq!(String::from_utf8(again.stdout).unwrap(), funding);

    let signet = tempfile::tempdir().unwrap();
    let init = licash_swaps(&signet, &["init", "--network", "signet"]);
    assert!(init.status.success(), "{init:?}");
    let status = licash_swaps(&signet, &["status", "--json"]);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["network"], "signet");
    let unknown = licash_swaps(&signet, &["init", "--network", "testnet3"]);
    assert_eq!(unknown.status.code(), Some(2));

    let bad = licash_swaps(&dir, &["run", "--margin", "4"]);
    assert!(!bad.status.success());
    assert!(String::from_utf8(bad.stderr).unwrap().contains("--margin"));
    let bad = licash_swaps(&dir, &["run", "--confirm", "0"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8(bad.stderr).unwrap().contains("--confirm"));
}

#[test]
fn the_dashboard_reads_the_provider_as_json_and_draws_on_a_terminal_only() {
    let dir = tempfile::tempdir().unwrap();
    assert!(licash_swaps(&dir, &["init", "--network", "regtest"])
        .status
        .success());
    let no_service = ["--url", "http://127.0.0.1:1"];
    let json = licash_swaps(
        &dir,
        &[&["dashboard", "--json", "--range", "7d"][..], &no_service].concat(),
    );
    assert!(json.status.success(), "{json:?}");
    let view: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        (&view["title"], &view["range"]),
        (&"licash swaps".into(), &"7d".into())
    );
    let pages: Vec<_> = view["pages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| &p["title"])
        .collect();
    assert_eq!(pages, ["Overview", "Swaps", "Liquidity", "Fees", "Health"]);
    // A provider of no hub swaps nothing.
    assert_eq!(view["health"], "bad");
    let drawn = licash_swaps(&dir, &[&["dashboard"][..], &no_service].concat());
    assert!(!drawn.status.success());
    assert!(String::from_utf8(drawn.stderr).unwrap().contains("--json"));
}

#[test]
fn a_provider_runs_unprotected_by_contracts_only_when_told_to() {
    let dir = tempfile::tempdir().unwrap();
    assert!(licash_swaps(&dir, &["init"]).status.success());
    let listen = ["--listen", "127.0.0.1:0"];
    // None opens on Bitcoin yet: refused before it serves.
    let out = licash_swaps(&dir, &[&["run"], &listen[..]].concat());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("none opens on bitcoin") && stderr.contains("--no-contracts"),
        "{stderr}"
    );
    assert!(!stderr.contains("serving at"), "{stderr}");
    // Nor kept without a chain to follow.
    let regtest = tempfile::tempdir().unwrap();
    let init = licash_swaps(&regtest, &["init", "--network", "regtest"]);
    assert!(init.status.success());
    let out = licash_swaps(&regtest, &[&["run"], &listen[..]].concat());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("kept with --chain") && stderr.contains("--no-contracts"),
        "{stderr}"
    );
}

#[test]
fn lightning_payments_need_their_node_and_enough_slack() {
    let dir = tempfile::tempdir().unwrap();
    assert!(licash_swaps(&dir, &["init", "--network", "regtest"])
        .status
        .success());
    let listen = ["--listen", "127.0.0.1:0", "--no-contracts"];
    // Too little slack to claim the client's lock in.
    let out = licash_swaps(&dir, &[&["run", "--ln-slack", "17"], &listen[..]].concat());
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--ln-slack"));
    let out = licash_swaps(
        &dir,
        &[&["run", "--lnd-macaroon", "m"], &listen[..]].concat(),
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--lnd"));

    // A payment under way, recorded by a provider with a node: refused
    // without one, before it serves.
    let swaps = rusqlite::Connection::open(dir.path().join("data/wallet.sqlite")).unwrap();
    swaps
        .execute_batch(
            "INSERT INTO provider_swaps (id, hash, from_url, to_url, address, amount, fee, paid,
                expiry_from_height, expiry_height, state, kind, created_at, updated_at)
             VALUES (x'01', zeroblob(32), 'http://a.test', 'lightning:regtest', x'03', 1000, 7,
                1007, 300, 200, 'accepted', 'lightning', 0, 0);
             INSERT INTO provider_invoices (id, request, node) VALUES (x'01', 'lnbcrt', x'02');",
        )
        .unwrap();
    drop(swaps);
    let out = licash_swaps(&dir, &[&["run"], &listen[..]].concat());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 Lightning payments under way: they need --lnd"),
        "{stderr}"
    );
    assert!(!stderr.contains("serving at"), "{stderr}");
}

#[test]
fn announcements_are_checked_before_anything_runs() {
    let dir = tempfile::tempdir().unwrap();
    let relay = ["--nostr-relay", "ws://127.0.0.1:1"];
    for (args, says) in [
        (
            &["--announce-url", "https://swaps.example"][..],
            "needs --nostr-relay",
        ),
        (&relay[..], "--announce-url"),
        (
            &[relay[0], relay[1], "--onion", "--announce-url", "ftp://x"][..],
            "ftp://",
        ),
        // An onion service may be the only URL announced.
        (&[relay[0], relay[1], "--onion"][..], "no provider"),
    ] {
        let out = licash_swaps(&dir, &[&["run"], args].concat());
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(says), "{args:?}: {stderr}");
    }
    assert!(!dir.path().join("data").exists());
}

#[tokio::test]
async fn a_new_target_hears_of_what_the_provider_says_from_its_start_on() {
    let dir = tempfile::tempdir().unwrap();
    let (_, provider) = router(&dir);
    let heard = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = {
        let heard = heard.clone();
        Router::new().route(
            "/",
            post(move |body: String| async move { heard.lock().unwrap().push(body) }),
        )
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("json://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, sink).await });

    provider.alert("before its start").unwrap();
    let notifier = licash_swaps_service::notify::Notifier::new(
        provider.clone(),
        "swaps",
        vec![target.parse().unwrap()],
        &dir.path().join("notify.json"),
        Vec::new(),
    )
    .unwrap();
    // Raised as it starts, before its notifications run.
    provider.alert("as it starts").unwrap();
    tokio::spawn(notifier.run());
    for _ in 0..100 {
        if !heard.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let heard = heard.lock().unwrap();
    assert_eq!(heard.len(), 1, "{heard:?}");
    assert!(heard[0].contains("as it starts"), "{}", heard[0]);
}

#[tokio::test]
async fn donations_over_lnurl_answer_as_lnurl_asks() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(
        &dir.path().join("wallet.sqlite"),
        &[5; 32],
        ChainProfile::Core30DefaultRegtest,
        Offline,
    )
    .unwrap();
    let code = a_code(&wallet);
    let node = Arc::new(Fake::new());
    let provider = Provider::create(wallet, Config::default())
        .unwrap()
        .take_donations(
            node.clone(),
            licash_swaps::DonationTerms::default(),
            "https://swaps.test/",
        )
        .unwrap();
    let provider = Arc::new(provider);
    let router = licash_swaps_service::lnurl(provider.clone())
        .merge(licash_swaps_service::router(provider, None));
    let ask = |path: String| {
        let router = router.clone();
        async move {
            let request = Request::get(path).body(Body::empty()).unwrap();
            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let origin = response.headers()["access-control-allow-origin"].clone();
            assert_eq!(origin, "*");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        }
    };
    let refused = |answer: &serde_json::Value, why: &str| {
        assert_eq!(answer["status"], "ERROR", "{answer}");
        let reason = answer["reason"].as_str().unwrap();
        assert!(reason.contains(why), "{reason}");
    };
    // Its info tells wallets where payers reach it.
    let (status, info) = call(&router, swaps::SWAPS_INFO, None).await;
    assert_eq!(status, StatusCode::OK);
    let info: serde_json::Value = serde_json::from_slice(&info).unwrap();
    assert_eq!(info["donations"]["url"], "https://swaps.test", "{info}");
    assert_eq!(info["donations"]["min"], 100, "{info}");
    // Not a code.
    let answer = ask("/v1/lnurlp/nonsense".into()).await;
    refused(&answer, "not a Licash code");
    let answer = ask("/v1/lnurlp/nonsense/callback?amount=100000".into()).await;
    refused(&answer, "not a Licash code");
    // No amount asked.
    let answer = ask("/v1/lnurlp/nonsense/callback".into()).await;
    refused(&answer, "millisatoshis");
    // A code of a hub where the provider holds nothing: none taken.
    let answer = ask(format!("/v1/lnurlp/{code}")).await;
    refused(&answer, "holds too little");
    let answer = ask(format!("/v1/lnurlp/{code}/callback?amount=100000")).await;
    refused(&answer, "holds too little");
    assert!(node.sent().is_empty());
}

#[tokio::test]
async fn receipts_over_lightning_are_asked_and_followed_through_the_api() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(
        &dir.path().join("wallet.sqlite"),
        &[5; 32],
        ChainProfile::Core30DefaultRegtest,
        Offline,
    )
    .unwrap();
    let address = wallet.address();
    let node = Arc::new(Fake::new());
    let provider = Provider::create(wallet, Config::default())
        .unwrap()
        .take_receives(node.clone(), licash_swaps::ReceiveTerms::default())
        .unwrap();
    let router = licash_swaps_service::router(Arc::new(provider), None);
    // Its info tells wallets its terms.
    let (status, info) = call(&router, swaps::SWAPS_INFO, None).await;
    assert_eq!(status, StatusCode::OK);
    let info: serde_json::Value = serde_json::from_slice(&info).unwrap();
    assert_eq!(info["receive"]["min"], 100, "{info}");
    // At a hub it does not swap at: declined, no invoice made.
    let request = swaps::ReceiveRequest {
        hub: address,
        address,
        amount: 1_000,
        hash: licash_api::Hex(vec![1; 32]),
        memo: None,
        asks: None,
        description_hash: None,
    };
    let body = serde_json::to_string(&request).unwrap();
    let (status, answer) = call(&router, swaps::RECEIVES, Some(&body)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(problem(&answer).code, Code::Declined);
    assert!(node.sent().is_empty());
    // Not JSON of one.
    let (status, _) = call(&router, swaps::RECEIVES, Some("{}")).await;
    assert!(status.is_client_error(), "{status}");
    // None under a hash never asked; not a hash.
    let (status, answer) = call(&router, &swaps::receive_state(&[1; 32]), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem(&answer).code, Code::UnknownLock);
    let (status, _) = call(&router, "/v1/swaps/receive/nonsense", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[test]
fn receipts_need_a_node_and_one_under_way_needs_them() {
    let dir = tempfile::tempdir().unwrap();
    assert!(licash_swaps(&dir, &["init", "--network", "regtest"])
        .status
        .success());
    let listen = ["--listen", "127.0.0.1:0", "--no-contracts"];
    let out = licash_swaps(&dir, &[&["run", "--receive"], &listen[..]].concat());
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--lnd"));
    // A receipt under way, recorded by a provider taking them: refused
    // without its node, before it serves.
    let wallet = Wallet::open(&dir.path().join("data/wallet.sqlite"), Offline).unwrap();
    let provider = Provider::open(wallet, Config::default())
        .unwrap()
        .take_receives(Arc::new(Fake::new()), licash_swaps::ReceiveTerms::default())
        .unwrap();
    drop(provider);
    let swaps = rusqlite::Connection::open(dir.path().join("data/wallet.sqlite")).unwrap();
    swaps
        .execute_batch(
            "INSERT INTO provider_receives (hash, hub, address, amount, sat, request, state,
                created_at, updated_at)
             VALUES (zeroblob(32), 'http://a.test', x'00', 100, 102, 'lnbcrt', 'open', 0, 0);",
        )
        .unwrap();
    drop(swaps);
    let out = licash_swaps(&dir, &[&["run"], &listen[..]].concat());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 receipts over Lightning under way: they need --receive and --lnd"),
        "{stderr}"
    );
    assert!(!stderr.contains("serving at"), "{stderr}");
}

/// A Licash code of `wallet`'s, paid at a hub of its own address.
fn a_code<T: Transport>(wallet: &Wallet<T>) -> String {
    let code = licash_wallet::LicashCode {
        network: ChainProfile::Core30DefaultRegtest,
        address: wallet.address(),
        mailbox: None,
        hubs: vec![licash_wallet::HubId::of(&wallet.address())],
        locations: Vec::new(),
    };
    code.to_string()
}

#[test]
fn donations_need_a_node_and_the_lnurl_of_a_code_is_printed() {
    let dir = tempfile::tempdir().unwrap();
    assert!(licash_swaps(&dir, &["init", "--network", "regtest"])
        .status
        .success());
    let listen = ["--listen", "127.0.0.1:0", "--no-contracts"];
    let out = licash_swaps(
        &dir,
        &[&["run", "--lnurl-url", "https://swaps.test"], &listen[..]].concat(),
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--lnd"));

    // A donation under way, recorded by a provider taking them: refused
    // without its node, before it serves.
    let swaps = rusqlite::Connection::open(dir.path().join("data/wallet.sqlite")).unwrap();
    swaps
        .execute_batch(
            "INSERT INTO provider_donations (hash, preimage, code, sat, amount, request, state,
                created_at, updated_at)
             VALUES (zeroblob(32), zeroblob(32), 'licash1', 100, 98, 'lnbcrt', 'open', 0, 0);",
        )
        .unwrap();
    drop(swaps);
    let out = licash_swaps(&dir, &[&["run"], &listen[..]].concat());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 donations under way: they need --lnurl-url and --lnd"),
        "{stderr}"
    );
    assert!(!stderr.contains("serving at"), "{stderr}");

    // The static LNURL of a code: its donation URL, in bech32.
    let out = licash_swaps(
        &dir,
        &["lnurl", "--lnurl-url", "https://swaps.test/", "nonsense"],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("a Licash code"));
    let wallet = Wallet::create(
        &dir.path().join("payee.sqlite"),
        &[6; 32],
        ChainProfile::Core30DefaultRegtest,
        Offline,
    )
    .unwrap();
    let code = a_code(&wallet);
    let out = licash_swaps(
        &dir,
        &["lnurl", "--lnurl-url", "https://swaps.test/", &code],
    );
    assert!(out.status.success());
    let lnurl = String::from_utf8(out.stdout).unwrap();
    let (_, url) = bitcoin::bech32::decode(lnurl.trim()).unwrap();
    assert_eq!(
        String::from_utf8(url).unwrap(),
        format!("https://swaps.test/v1/lnurlp/{code}")
    );
}

/// Requests past the most it serves at once are answered at once,
/// unavailable, rather than queued without bound; its health is still
/// told, and a request is served again once one ends.
#[tokio::test]
async fn requests_past_the_most_at_once_are_unavailable() {
    use axum::routing::get;
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
        .route(licash_swaps_service::HEALTH, get(|| async { "ok" }));
    let app = licash_swaps_service::shed(app, 1);
    let get = |path: &str| Request::builder().uri(path).body(Body::empty()).unwrap();
    let slow = tokio::spawn(app.clone().oneshot(get("/slow")));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let busy = app.clone().oneshot(get("/fast")).await.unwrap();
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = busy.into_body().collect().await.unwrap().to_bytes();
    let problem: Problem = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem.code, Code::Unavailable);
    let health = app.clone().oneshot(get(licash_swaps_service::HEALTH)).await;
    assert_eq!(health.unwrap().status(), StatusCode::OK);
    gate.notify_one();
    assert_eq!(slow.await.unwrap().unwrap().status(), StatusCode::OK);
    let served = app.oneshot(get("/fast")).await.unwrap();
    assert_eq!(served.status(), StatusCode::OK);
}

/// A body still arriving [`licash_swaps_service::BODY_TIME`] after its
/// request came is refused, its place freed: requests whose bodies stall
/// keep no other out for longer. One arriving slowly but in time is served.
#[tokio::test(start_paused = true)]
async fn a_body_stalled_past_its_time_frees_its_place() {
    use axum::body::Bytes;
    use licash_swaps_service::BODY_TIME;
    let app = Router::new().route(
        "/",
        post(|body: Bytes| async move { body.len().to_string() }),
    );
    let app = licash_swaps_service::shed(app, 1);
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
    let body = served.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"18");
}
