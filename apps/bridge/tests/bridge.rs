//! The bridge over a hub in process whose gateway pays and is paid through
//! a fake node: accounts paired and topped up, NWC requests answered within
//! their connections' limits, and payments decided once their locks are.

#[path = "../../hub/tests/chain/mod.rs"]
mod chain;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{header, Method, Request},
    Router,
};
use http_body_util::BodyExt;
use licash::spend::{lock_hash, ChainProfile};
use licash_api::{
    bridge::{self, Budget, Connect, Period, Permission, Signed, State},
    Fee,
};
use licash_bridge::{nwc, Bridge, Config, Error};
use licash_hub::{Hub, Policy, Timing};
use licash_hub_service::lightning::{
    fake::{Fake, Outcome},
    Config as Gateway_, Gateway,
};
use licash_wallet::{Response, Transport, Wallet};
use nostr::nips::nip47::{
    self, ErrorCode, LookupInvoiceRequest, MakeInvoiceRequest, Nip47Ciphers, NostrWalletConnectUri,
    PayInvoiceRequest, ResponseResult, TransactionState,
};
use tower::ServiceExt;

const HUB: &str = "http://hub.test";

const TIMING: Timing = Timing {
    window: 40,
    reaction: 2,
    min_depth: 1,
    max_headers: 4032,
    bury: 6,
    max_lag: 120,
};

/// The hub's router, reached at [`HUB`].
#[derive(Clone)]
struct Local(Router);

impl Transport for Local {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let path = url.strip_prefix(HUB).unwrap_or(url).to_owned();
        let app = self.0.clone();
        async move { Ok(call(&app, &path, body).await) }
    }
}

async fn call(app: &Router, path: &str, body: Option<Vec<u8>>) -> Response {
    let request = match body {
        Some(body) => Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body)),
        None => Request::builder().uri(path).body(Body::empty()),
    };
    let response = app.clone().oneshot(request.unwrap()).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Response {
        status,
        body: body.to_vec(),
    }
}

struct Net {
    node: Arc<Fake>,
    gateway: Arc<Gateway>,
    bridge: Arc<Bridge<Local>>,
    pairing: String,
    chain: chain::Chain,
    rounds: tokio::task::JoinHandle<()>,
    dir: tempfile::TempDir,
}

impl Drop for Net {
    fn drop(&mut self) {
        self.rounds.abort();
    }
}

impl Net {
    /// A hub whose gateway charges 2 sat to pay and 1 sat to receive, and
    /// a bridge over a wallet of it, open if `open`.
    async fn new(open: bool) -> Self {
        Self::with(Config {
            open,
            ..Config::default()
        })
        .await
    }

    async fn with(config: Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, 6).unwrap();
        let policy = Policy {
            timing: TIMING,
            ..Policy::default()
        };
        let hub = Arc::new(Hub::open(&seed, &db, policy).unwrap());
        let mut chain = chain::Chain::new();
        hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
        let node = Arc::new(Fake::new());
        let config_ = Gateway_ {
            pay: Fee { base: 2, ppm: 0 },
            receive: Fee { base: 1, ppm: 0 },
            max_pay: 100_000,
            min_receive: 1,
            max_receive: 100_000,
            pay_slack: 4,
            hold_delta: 3,
            downtime: 2,
            receive_blocks: 6,
            grace: 0,
            ..Gateway_::default()
        };
        let gateway = Arc::new(Gateway::open(hub.clone(), node.clone(), config_, &db).unwrap());
        let app = licash_hub_service::router(
            hub.clone(),
            licash_hub_service::Services {
                gateway: Some(gateway.clone()),
                ..Default::default()
            },
        );
        for _ in 0..3 {
            let block = chain.mine(None).clone();
            hub.observe(chain.height(), &block).unwrap();
        }
        assert!(hub.synced(chain.height(), &chain.tip()).unwrap());
        node.tip(chain.height(), chain.tip());
        gateway.round().await;

        let path = dir.path().join("bridge.sqlite");
        let regtest = ChainProfile::Core30DefaultRegtest;
        let wallet = Wallet::create(&path, &[7; 32], regtest, Local(app)).unwrap();
        wallet.add_hub(HUB).await.unwrap();
        let pairing = Bridge::init(&wallet).unwrap();
        let config = Config {
            hub: HUB.into(),
            relays: vec!["wss://relay.test".into()],
            ..config
        };
        let bridge = Arc::new(Bridge::open(wallet, config).unwrap());
        // The gateway pays and settles as a running hub does.
        let rounds = {
            let gateway = gateway.clone();
            tokio::spawn(async move {
                loop {
                    gateway.round().await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
        };
        Self {
            node,
            gateway,
            bridge,
            pairing,
            chain,
            rounds,
            dir,
        }
    }

    /// Another node pays the bridge's invoice of `hash`, which it claims.
    async fn pay_in(&self, hash: &str) {
        let mut bytes = [0; 32];
        hex::decode_to_slice(hash, &mut bytes).unwrap();
        let cltv = self.node.held_cltv(bytes).unwrap() as u32;
        self.node.pay_held(bytes, self.chain.height() + cltv);
        self.gateway.round().await;
        self.bridge.round().await.unwrap();
    }

    /// The owner of [`key`] registered, holding `msat` topped up.
    async fn owner(&self, msat: u64) -> [u8; 32] {
        let owner = key(3);
        self.bridge.register(&owner, Some(&self.pairing)).unwrap();
        if msat > 0 {
            let invoice = self.bridge.top_up(&owner, msat).await.unwrap();
            self.pay_in(&invoice.hash).await;
        }
        owner
    }
}

fn secret(n: u8) -> [u8; 32] {
    [n; 32]
}

/// The x-only key of [`secret`] `n`.
fn key(n: u8) -> [u8; 32] {
    let signed = Signed::sign(&secret(n), "/", 0, String::new()).unwrap();
    signed.key.0.try_into().unwrap()
}

fn connect(permissions: &[Permission], budget: Option<Budget>) -> Connect {
    Connect {
        name: "An app".into(),
        permissions: permissions.to_vec(),
        max_payment: None,
        budget,
        expires_at: None,
    }
}

/// What the bridge answers `request` over `uri`, in `cipher`.
async fn ask(
    net: &Net,
    uri: &NostrWalletConnectUri,
    request: nip47::Request,
    cipher: Nip47Ciphers,
) -> nip47::Response {
    let event = request.to_event(uri, cipher).unwrap();
    let answer = nwc::answer(&net.bridge, &event).await.expect("an answer");
    assert!(answer.tags.event_ids().any(|id| id == event.id));
    nip47::Response::from_event(uri, &answer, cipher).unwrap()
}

fn balance(net: &Net, owner: &[u8; 32]) -> u64 {
    net.bridge.account(owner).unwrap().balance
}

#[tokio::test]
async fn only_the_pairing_code_registers_the_owner_and_hands_the_account_on() {
    let net = Net::new(false).await;
    let (owner, other) = (key(3), key(4));
    let refused = net.bridge.register(&owner, None);
    assert!(
        matches!(refused, Err(Error::Unauthorized(_))),
        "{refused:?}"
    );
    let wrong = net.bridge.register(&owner, Some("0000000000000000"));
    assert!(matches!(wrong, Err(Error::Unauthorized(_))));
    let account = net.bridge.register(&owner, Some(&net.pairing)).unwrap();
    assert_eq!((account.balance, account.connections.len()), (0, 0));
    // Used: none other registers with it, and the owner again is the same.
    assert!(net.bridge.register(&other, Some(&net.pairing)).is_err());
    assert_eq!(net.bridge.pairing(false).unwrap(), None);
    net.bridge.register(&owner, None).unwrap();

    // Topped up, then handed to a new wallet's key with a new code.
    let invoice = net.bridge.top_up(&owner, 10_000).await.unwrap();
    // 10 sat, the hub's 1 sat fee out of it.
    assert_eq!((invoice.amount, invoice.credits), (10_000, 9_000));
    net.pay_in(&invoice.hash).await;
    assert_eq!(balance(&net, &owner), 9_000);
    let code = net.bridge.pairing(true).unwrap().unwrap();
    net.bridge.register(&other, Some(&code)).unwrap();
    assert_eq!(balance(&net, &other), 9_000);
    assert!(matches!(
        net.bridge.account(&owner),
        Err(Error::Unauthorized(_))
    ));
    let status = net.bridge.status().unwrap();
    assert_eq!((status.accounts, status.owed, status.held), (1, 9_000, 9));
}

#[tokio::test]
async fn an_open_bridge_registers_anyone_within_its_limit() {
    let net = Net::with(Config {
        open: true,
        max_balance: Some(20_000),
        ..Config::default()
    })
    .await;
    let (alice, bob) = (key(3), key(4));
    net.bridge.register(&alice, None).unwrap();
    net.bridge.register(&bob, None).unwrap();
    let invoice = net.bridge.top_up(&alice, 15_000).await.unwrap();
    // Beyond the most an account holds, the invoice still open counted.
    // 14 sat it credits, and 7 sat less the hub's 1.
    let refused = net.bridge.top_up(&alice, 7_000).await;
    assert!(matches!(refused, Err(Error::Quota(_))), "{refused:?}");
    net.pay_in(&invoice.hash).await;
    assert_eq!((balance(&net, &alice), balance(&net, &bob)), (14_000, 0));
}

#[tokio::test]
async fn nwc_pays_within_its_connections_budget_in_either_cipher() {
    let net = Net::new(false).await;
    let owner = net.owner(50_000).await;
    assert_eq!(balance(&net, &owner), 49_000);
    let budget = Budget {
        amount: 30_000,
        period: Period::Daily,
    };
    let connected = net
        .bridge
        .connect(&owner, &connect(&[Permission::Pay], Some(budget)))
        .unwrap();
    let uri = NostrWalletConnectUri::parse(&connected.uri).unwrap();
    assert_eq!(uri.public_key, net.bridge.keys().public_key());
    let client = nostr::prelude::Keys::new(uri.secret.clone()).public_key();
    assert_eq!(client.to_hex(), connected.connection.key);

    // What it serves, in either cipher.
    for cipher in [Nip47Ciphers::NIP44V2, Nip47Ciphers::NIP04] {
        let info = ask(&net, &uri, nip47::Request::get_info(), cipher).await;
        let Some(ResponseResult::GetInfo(info)) = info.result else {
            panic!("{info:?}");
        };
        assert!(info.methods.contains(&nip47::Method::PayInvoice));
        assert!(!info.methods.contains(&nip47::Method::MakeInvoice));
        assert_eq!(info.network.as_deref(), Some("regtest"));
    }

    let preimage = [5; 32];
    let request = net
        .node
        .invoice(20_000, lock_hash(&preimage), 18, Outcome::Pay(preimage));
    let pay = nip47::Request::pay_invoice(PayInvoiceRequest {
        id: None,
        invoice: request.clone(),
        amount: None,
    });
    let paid = ask(&net, &uri, pay.clone(), Nip47Ciphers::NIP44V2).await;
    let Some(ResponseResult::PayInvoice(paid)) = paid.result else {
        panic!("{paid:?}");
    };
    assert_eq!(paid.preimage, hex::encode(preimage));
    assert_eq!(paid.fees_paid, Some(2_000));
    assert_eq!(balance(&net, &owner), 49_000 - 22_000);
    // Asked again: the same payment, paid once.
    let again = ask(&net, &uri, pay, Nip47Ciphers::NIP04).await;
    assert!(matches!(again.result, Some(ResponseResult::PayInvoice(_))));
    assert_eq!(net.node.sent().len(), 1);
    assert_eq!(balance(&net, &owner), 27_000);

    // Beyond the budget: 22 of 30 spent.
    let other = net.node.invoice(7_000, [8; 32], 18, Outcome::Hang);
    let pay = nip47::Request::pay_invoice(PayInvoiceRequest {
        id: None,
        invoice: other,
        amount: None,
    });
    let refused = ask(&net, &uri, pay, Nip47Ciphers::NIP44V2).await;
    assert_eq!(refused.error.unwrap().code, ErrorCode::QuotaExceeded);
    assert_eq!(net.node.sent().len(), 1);
    let account = net.bridge.account(&owner).unwrap();
    assert_eq!(account.connections[0].spent, 22_000);
    assert_eq!(account.activity.len(), 2);

    let balance_ = ask(
        &net,
        &uri,
        nip47::Request::get_balance(),
        Nip47Ciphers::NIP04,
    )
    .await;
    let Some(ResponseResult::GetBalance(b)) = balance_.result else {
        panic!("{balance_:?}");
    };
    assert_eq!(b.balance, 27_000);

    // Revoked: refused.
    net.bridge
        .revoke(&owner, &connected.connection.key)
        .unwrap();
    let refused = ask(
        &net,
        &uri,
        nip47::Request::get_balance(),
        Nip47Ciphers::NIP44V2,
    )
    .await;
    assert_eq!(refused.error.unwrap().code, ErrorCode::Unauthorized);
}

#[tokio::test]
async fn a_receiving_connection_makes_invoices_and_pays_none() {
    let net = Net::new(false).await;
    let owner = net.owner(0).await;
    let connected = net
        .bridge
        .connect(&owner, &connect(&[Permission::Receive], None))
        .unwrap();
    let uri = NostrWalletConnectUri::parse(&connected.uri).unwrap();
    let make = nip47::Request::make_invoice(MakeInvoiceRequest {
        amount: 21_000,
        description: Some("A zap".into()),
        description_hash: None,
        expiry: None,
    });
    let made = ask(&net, &uri, make, Nip47Ciphers::NIP04).await;
    let Some(ResponseResult::MakeInvoice(made)) = made.result else {
        panic!("{made:?}");
    };
    let invoice: lightning_invoice::Bolt11Invoice = made.invoice.parse().unwrap();
    assert_eq!(invoice.amount_milli_satoshis(), Some(21_000));
    let hash = made.payment_hash.unwrap();
    let lookup = nip47::Request::lookup_invoice(LookupInvoiceRequest {
        payment_hash: Some(hash.clone()),
        invoice: None,
    });
    let open = ask(&net, &uri, lookup.clone(), Nip47Ciphers::NIP44V2).await;
    let Some(ResponseResult::LookupInvoice(open)) = open.result else {
        panic!("{open:?}");
    };
    assert_eq!(open.state, Some(TransactionState::Pending));

    net.pay_in(&hash).await;
    let settled = ask(&net, &uri, lookup, Nip47Ciphers::NIP44V2).await;
    let Some(ResponseResult::LookupInvoice(settled)) = settled.result else {
        panic!("{settled:?}");
    };
    assert_eq!(settled.state, Some(TransactionState::Settled));
    assert_eq!(settled.description.as_deref(), Some("A zap"));
    assert_eq!(balance(&net, &owner), 20_000);

    // Paying: refused before anything is held.
    let preimage = [6; 32];
    let request = net
        .node
        .invoice(1_000, lock_hash(&preimage), 18, Outcome::Pay(preimage));
    let pay = nip47::Request::pay_invoice(PayInvoiceRequest {
        id: None,
        invoice: request,
        amount: None,
    });
    let refused = ask(&net, &uri, pay, Nip47Ciphers::NIP44V2).await;
    assert_eq!(refused.error.unwrap().code, ErrorCode::Restricted);
    assert!(net.node.sent().is_empty());
    assert_eq!(balance(&net, &owner), 20_000);
}

#[tokio::test]
async fn a_failed_payment_gives_its_hold_back() {
    let net = Net::new(false).await;
    let owner = net.owner(30_000).await;
    let failing = net
        .node
        .invoice(10_000, [9; 32], 18, Outcome::Fail("no route".into()));
    let withdraw = bridge::Withdraw {
        invoice: failing,
        max_fee: None,
    };
    let failed = net.bridge.withdraw(&owner, &withdraw).await.unwrap();
    assert_eq!(failed.state, State::Failed);
    assert!(failed.failure.is_some());
    assert_eq!(balance(&net, &owner), 29_000);
    // More than it holds: refused, nothing held.
    let big = net.node.invoice(40_000, [10; 32], 18, Outcome::Hang);
    let refused = net
        .bridge
        .withdraw(
            &owner,
            &bridge::Withdraw {
                invoice: big,
                max_fee: None,
            },
        )
        .await;
    assert!(
        matches!(refused, Err(Error::Insufficient(_))),
        "{refused:?}"
    );
    assert_eq!(balance(&net, &owner), 29_000);
}

#[tokio::test]
async fn a_payment_recorded_but_never_sent_is_given_back_by_a_round() {
    let net = Net::new(false).await;
    let owner = net.owner(30_000).await;
    // As a bridge stopped between holding and asking its hub leaves it.
    let request = net.node.invoice(10_000, [11; 32], 18, Outcome::Hang);
    let db = rusqlite::Connection::open(net.dir.path().join("bridge.sqlite")).unwrap();
    db.execute("UPDATE bridge_accounts SET balance = balance - 12000", [])
        .unwrap();
    db.execute(
        "INSERT INTO bridge_payments (hash, account, connection, invoice, amount, reserved,
            state, started_at, created_at)
         VALUES (?1, 1, NULL, ?2, 10000, 12000, 'pending', ?3, ?3)",
        rusqlite::params![[11u8; 32], request, licash_store::now()],
    )
    .unwrap();
    assert_eq!(net.bridge.account(&owner).unwrap().reserved, 12_000);
    assert_eq!(net.bridge.round().await.unwrap(), 1);
    let account = net.bridge.account(&owner).unwrap();
    assert_eq!((account.balance, account.reserved), (29_000, 0));
    assert_eq!(account.activity[0].state, State::Failed);
    assert!(net.node.sent().is_empty());
}

/// The management API: signed requests, each answered once.
#[tokio::test]
async fn the_management_api_answers_signed_requests_once() {
    let net = Net::new(false).await;
    let app = licash_bridge::router(net.bridge.clone());
    let info: bridge::Info = {
        let r = call(&app, bridge::INFO, None).await;
        assert_eq!(r.status, 200);
        serde_json::from_slice(&r.body).unwrap()
    };
    assert_eq!(info.nostr, net.bridge.keys().public_key().to_hex());
    assert_eq!(info.receive_fee, Fee { base: 1, ppm: 0 });
    assert!(!info.open);
    let signed = |path: &str, request: &str| {
        let at = licash_store::now();
        let body = Signed::sign(&secret(3), path, at, request.into()).unwrap();
        serde_json::to_vec(&body).unwrap()
    };
    let register = serde_json::to_string(&bridge::Register {
        pairing: Some(net.pairing.clone()),
    })
    .unwrap();
    let body = signed(bridge::REGISTER, &register);
    let r = call(&app, bridge::REGISTER, Some(body.clone())).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    // The same again: refused.
    let r = call(&app, bridge::REGISTER, Some(body)).await;
    assert_eq!(r.status, 400);
    // Signed for another path: refused.
    let body = signed(bridge::REGISTER, "{}");
    assert_eq!(call(&app, bridge::ACCOUNT, Some(body)).await.status, 400);

    let request = serde_json::to_string(&connect(&[Permission::Receive], None)).unwrap();
    let r = call(
        &app,
        bridge::CONNECT,
        Some(signed(bridge::CONNECT, &request)),
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let connected: bridge::Connected = serde_json::from_slice(&r.body).unwrap();
    assert!(connected.uri.starts_with("nostr+walletconnect://"));
    let r = call(&app, bridge::ACCOUNT, Some(signed(bridge::ACCOUNT, "{}"))).await;
    let account: bridge::Account = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(account.connections, vec![connected.connection]);
    // Another key: no account.
    let at = licash_store::now();
    let stranger = Signed::sign(&secret(4), bridge::ACCOUNT, at, "{}".into()).unwrap();
    let r = call(
        &app,
        bridge::ACCOUNT,
        Some(serde_json::to_vec(&stranger).unwrap()),
    )
    .await;
    assert_eq!(r.status, 409);
}
