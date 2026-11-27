//! The bridge over a hub in process, paying and paid through a swap
//! provider's fake node: accounts paired and topped up, NWC requests
//! answered within their connections' limits, and payments decided once
//! their locks are.

#[path = "../../hub/tests/chain/mod.rs"]
mod chain;
#[path = "../../hub/tests/mint/mod.rs"]
mod mint;

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
use licash_lightning::fake::{Fake, Outcome};
use licash_swaps::{Provider, ReceiveTerms};
use licash_wallet::{Response, Transport, Wallet};
use nostr::nips::nip47::{
    self, ErrorCode, LookupInvoiceRequest, MakeInvoiceRequest, Nip47Ciphers, NostrWalletConnectUri,
    PayInvoiceRequest, ResponseResult, TransactionState,
};
use tower::ServiceExt;

const HUB: &str = "http://hub.test";
const PROVIDER: &str = "http://provider.test";

const TIMING: Timing = Timing {
    window: 144,
    reaction: 2,
    min_depth: 1,
    max_headers: 4032,
    bury: 6,
    max_lag: 120,
};

/// The hub's router, reached at [`HUB`], and a swap provider's at
/// [`PROVIDER`], if any.
#[derive(Clone)]
struct Local(Router, Option<Router>);

impl Transport for Local {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let (app, path) = match (url.strip_prefix(PROVIDER), &self.1) {
            (Some(path), Some(provider)) => (provider.clone(), path.to_owned()),
            _ => (
                self.0.clone(),
                url.strip_prefix(HUB).unwrap_or(url).to_owned(),
            ),
        };
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
    /// The hub's API, no Lightning in it.
    app: Router,
    hub: Arc<Hub>,
    seed: std::path::PathBuf,
    /// The node of the bridge's provider, paying and paid for the bridge.
    node: Arc<Fake>,
    /// The provider the bridge pays and is paid through.
    provider: Arc<Provider<Local>>,
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

/// The hub's API and `provider`'s, as the bridge reaches them.
fn reaching(app: &Router, provider: &Arc<Provider<Local>>) -> Local {
    let provider = licash_swaps_service::router(provider.clone(), Default::default());
    Local(app.clone(), Some(provider))
}

/// A provider over `node`, its wallet of seed `seed` at the hub holding
/// `stock` sat, charging 2 sat to pay and 1 to receive.
async fn provider_over(
    net: (&Hub, &std::path::Path, &Router),
    (seed, stock): (u8, u64),
    node: &Arc<Fake>,
) -> Provider<Local> {
    let (hub, dir, app) = net;
    let path = dir.join(format!("provider-{seed}.sqlite"));
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(&path, &[seed; 32], regtest, Local(app.clone(), None)).unwrap();
    wallet.add_hub(HUB).await.unwrap();
    if stock > 0 {
        let stock = mint::pay(hub, (&dir.join("seed"), 6), HUB, &wallet.address(), stock);
        wallet.receive(&stock).unwrap();
    }
    let swaps = licash_swaps::Config {
        margin: 6,
        confirm: 4,
        ..licash_swaps::Config::default()
    };
    let receives = ReceiveTerms {
        fee: Fee { base: 1, ppm: 0 },
        min: 1,
        max: 50_000,
        max_open: 100,
    };
    let pays = licash_api::swaps::Lightning {
        node: node.pubkey(),
        fee: Fee { base: 2, ppm: 0 },
        max: 50_000,
        slack: 24,
    };
    Provider::create(wallet, swaps)
        .unwrap()
        .take_receives(node.clone(), receives)
        .unwrap()
        .pay_lightning(node.clone(), pays)
        .unwrap()
}

impl Net {
    /// A hub, and a bridge over a wallet of it, open if `open`.
    async fn new(open: bool) -> Self {
        Self::with(Config {
            open,
            ..Config::default()
        })
        .await
    }

    /// A bridge at a hub, paying and paid through a provider at
    /// [`PROVIDER`] charging 2 sat to pay and 1 to receive, over its own
    /// node.
    async fn with(config: Config) -> Self {
        Self::stocked(config, 500).await
    }

    /// As [`Net::with`], the provider holding `stock` sat at the hub.
    async fn stocked(config: Config, stock: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, 6).unwrap();
        // 1 sat on a payment in notes.
        let policy = Policy {
            timing: TIMING,
            spend: licash_hub::Fee { base: 1, ppm: 0 },
            ..Policy::default()
        };
        let hub = Arc::new(Hub::open(&seed, &db, policy).unwrap());
        let mut chain = chain::Chain::new();
        hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
        let app = licash_hub_service::router(hub.clone(), Default::default());
        for _ in 0..3 {
            let block = chain.mine(None).clone();
            hub.observe(chain.height(), &block).unwrap();
        }
        assert!(hub.synced(chain.height(), &chain.tip()).unwrap());

        let node = Arc::new(Fake::new());
        node.tip(chain.height(), chain.tip());
        let at = (hub.as_ref(), dir.path(), &app);
        let provider = Arc::new(provider_over(at, (0x50, stock), &node).await);

        let path = dir.path().join("bridge.sqlite");
        let reaches = reaching(&app, &provider);
        let regtest = ChainProfile::Core30DefaultRegtest;
        let wallet = Wallet::create(&path, &[7; 32], regtest, reaches).unwrap();
        wallet.add_hub(HUB).await.unwrap();
        let pairing = Bridge::init(&wallet).unwrap();
        let config = Config {
            hub: HUB.into(),
            via: Some(PROVIDER.into()),
            relays: vec!["wss://relay.test".into()],
            ..config
        };
        let bridge = Arc::new(Bridge::open(wallet, config).unwrap());
        // Its provider's offer known.
        bridge.round().await.unwrap();
        // The provider pays and settles as a running one does.
        let rounds = {
            let provider = provider.clone();
            tokio::spawn(async move {
                loop {
                    let _ = provider.follow_invoices().await;
                    let _ = provider.follow_receives().await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
        };
        Self {
            app,
            hub,
            seed,
            node,
            provider,
            bridge,
            pairing,
            chain,
            rounds,
            dir,
        }
    }

    /// Mine `blocks`, which the hub and the nodes follow.
    fn mine(&mut self, blocks: u32) {
        for _ in 0..blocks {
            let block = self.chain.mine(None).clone();
            self.hub.observe(self.chain.height(), &block).unwrap();
        }
        self.node.tip(self.chain.height(), self.chain.tip());
    }

    /// Another node pays the bridge's invoice of `hash`, which it claims.
    async fn pay_in(&self, hash: &str) {
        let mut bytes = [0; 32];
        hex::decode_to_slice(hash, &mut bytes).unwrap();
        let cltv = self.node.held_cltv(bytes).unwrap() as u32;
        self.node.pay_held(bytes, self.chain.height() + cltv);
        // Locked to the bridge, claimed, then settled.
        self.provider.follow_receives().await.unwrap();
        self.bridge.round().await.unwrap();
        self.provider.follow_receives().await.unwrap();
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

const BRIDGE: &str = "http://bridge.test";

/// The hub's router and the bridge's, each at its own host.
#[derive(Clone)]
struct Both {
    hub: Router,
    bridge: Router,
    /// Whether the bridge's answers to deposits paid are lost: as a bridge
    /// down once paid would be.
    deaf: Arc<std::sync::atomic::AtomicBool>,
}

impl Transport for Both {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let paid = |body: &Option<Vec<u8>>| {
            body.as_ref()
                .is_some_and(|b| String::from_utf8_lossy(b).contains("unlock"))
        };
        let deaf = self.deaf.load(std::sync::atomic::Ordering::SeqCst);
        let lost = deaf && url.ends_with(bridge::DEPOSIT) && paid(&body);
        let (app, path) = match url.strip_prefix(BRIDGE) {
            Some(path) => (self.bridge.clone(), path.to_owned()),
            None => (
                self.hub.clone(),
                url.strip_prefix(HUB).unwrap_or(url).to_owned(),
            ),
        };
        async move {
            let answered = call(&app, &path, body).await;
            match lost {
                true => Err("the bridge did not answer".into()),
                false => Ok(answered),
            }
        }
    }
}

impl Net {
    /// A wallet of `seed` at the hub, reaching the bridge too, holding
    /// `amount` sat if any.
    async fn user(&self, seed: u8, amount: u64) -> Wallet<Both> {
        let path = self
            .dir
            .path()
            .join(format!("user-{seed}-{}.sqlite", rand_name()));
        let both = Both {
            hub: self.app.clone(),
            bridge: licash_bridge::router(self.bridge.clone()),
            deaf: Arc::default(),
        };
        let regtest = ChainProfile::Core30DefaultRegtest;
        let wallet = Wallet::create(&path, &[seed; 32], regtest, both).unwrap();
        wallet.add_hub(HUB).await.unwrap();
        if amount > 0 {
            let paid = mint::pay(&self.hub, (&self.seed, 6), HUB, &wallet.address(), amount);
            wallet.receive(&paid).unwrap();
        }
        wallet
    }
}

fn rand_name() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::SeqCst).to_string()
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

/// The hub's router, each request with a body held until a second one
/// comes, or a while: requests made at once reach it at once.
#[derive(Clone)]
struct Gated(Local, Arc<(std::sync::Mutex<usize>, tokio::sync::Notify)>);

impl Transport for Gated {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let (this, url) = (self.clone(), url.to_owned());
        async move {
            if body.is_some() {
                let (count, both) = &*this.1;
                let notified = both.notified();
                let arrived = {
                    let mut count = count.lock().unwrap();
                    *count += 1;
                    *count
                };
                if arrived >= 2 {
                    both.notify_waiters();
                } else {
                    let _ = tokio::time::timeout(Duration::from_millis(500), notified).await;
                }
            }
            this.0.request(&url, body).await
        }
    }
}

/// Invoices asked at once are admitted within the most an account holds,
/// as one after the other: the second waits for none of the first's round
/// trips to its hub to be counted.
#[tokio::test]
async fn invoices_asked_at_once_are_admitted_within_the_most_an_account_holds() {
    let net = Net::with(Config {
        max_balance: Some(50_000),
        ..Config::default()
    })
    .await;
    let owner = net.owner(0).await;
    let path = net.dir.path().join("bridge.sqlite");
    let gate = Arc::new((std::sync::Mutex::new(0), tokio::sync::Notify::new()));
    let reaches = reaching(&net.app, &net.provider);
    let wallet = Wallet::open(&path, Gated(reaches, gate.clone())).unwrap();
    let gated = Bridge::open(wallet, net.bridge.config().clone()).unwrap();
    // Its provider's offer known, then the two asked at once.
    gated.round().await.unwrap();
    *gate.0.lock().unwrap() = 0;
    let (one, two) = tokio::join!(gated.top_up(&owner, 30_000), gated.top_up(&owner, 30_000));
    let refused = [&one, &two]
        .into_iter()
        .filter(|r| matches!(r, Err(Error::Quota(_))))
        .count();
    assert_eq!(
        (refused, one.is_ok() || two.is_ok()),
        (1, true),
        "{one:?} {two:?}"
    );
    // Refused, it no longer counts; recorded, the other counts what it
    // credits, 29 sat, the hub's 1 sat less: 19 more fit, 3 then do not.
    gated.top_up(&owner, 20_000).await.unwrap();
    let over = gated.top_up(&owner, 3_000).await;
    assert!(matches!(over, Err(Error::Quota(_))), "{over:?}");
}

/// What a payment under way took from an account may come back to it,
/// should it fail: counted toward the most it holds, as an open invoice.
#[tokio::test]
async fn a_payment_under_way_counts_toward_the_most_an_account_holds() {
    let net = Net::with(Config {
        max_balance: Some(50_000),
        ..Config::default()
    })
    .await;
    let owner = net.owner(0).await;
    let request = net.node.invoice(30_000, [12; 32], 18, Outcome::Hang);
    let db = rusqlite::Connection::open(net.dir.path().join("bridge.sqlite")).unwrap();
    db.execute(
        "INSERT INTO bridge_payments (hash, account, connection, invoice, amount, reserved,
            state, started_at, created_at)
         VALUES (?1, 1, NULL, ?2, 30000, 30000, 'pending', ?3, ?3)",
        rusqlite::params![[12u8; 32], request, licash_store::now()],
    )
    .unwrap();
    let refused = net.bridge.top_up(&owner, 30_000).await;
    assert!(matches!(refused, Err(Error::Quota(_))), "{refused:?}");
    net.bridge.top_up(&owner, 20_000).await.unwrap();
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
    let mut net = Net::new(false).await;
    let owner = net.owner(30_000).await;
    let failing = net
        .node
        .invoice(10_000, [9; 32], 18, Outcome::Fail("no route".into()));
    let withdraw = bridge::Withdraw {
        invoice: failing,
        max_fee: None,
    };
    // Through a provider, its lock refunded once expired.
    let failing = net.bridge.withdraw(&owner, &withdraw).await.unwrap();
    assert_eq!(failing.state, State::Pending);
    net.mine(TIMING.window);
    for _ in 0..50 {
        net.bridge.round().await.unwrap();
        let account = net.bridge.account(&owner).unwrap();
        if account.activity[0].state != State::Pending {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let account = net.bridge.account(&owner).unwrap();
    assert_eq!(account.activity[0].state, State::Failed);
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
    // Another key: no account. What it signed is not kept, so strangers
    // fill none of the places of the signatures kept: the same again is
    // refused as it was, not as answered already.
    let at = licash_store::now();
    let stranger = Signed::sign(&secret(4), bridge::ACCOUNT, at, "{}".into()).unwrap();
    let stranger = serde_json::to_vec(&stranger).unwrap();
    for _ in 0..2 {
        let r = call(&app, bridge::ACCOUNT, Some(stranger.clone())).await;
        assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
    }
    // Nor a registration refused, which may be asked again.
    let wrong = serde_json::to_string(&bridge::Register {
        pairing: Some("not the code".into()),
    })
    .unwrap();
    let wrong = Signed::sign(&secret(4), bridge::REGISTER, at, wrong).unwrap();
    let wrong = serde_json::to_vec(&wrong).unwrap();
    let refused = call(&app, bridge::REGISTER, Some(wrong.clone())).await;
    assert_ne!(refused.status, 200);
    let again = call(&app, bridge::REGISTER, Some(wrong)).await;
    assert_eq!((again.status, again.body), (refused.status, refused.body));
}

#[tokio::test]
async fn a_wallet_pairs_tops_up_by_its_rules_and_withdraws() {
    let net = Net::new(false).await;
    let wallet = net.user(9, 200).await;
    let refused = wallet.add_bridge(BRIDGE, None).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(wallet.bridges().unwrap().is_empty());
    let (added, account) = wallet.add_bridge(BRIDGE, Some(&net.pairing)).await.unwrap();
    assert_eq!((added.url.as_str(), account.balance), (BRIDGE, 0));
    assert_eq!(added.rules, None);

    // In notes at the bridge's hub: credited whole, the hub's fee on top.
    let before = held(&wallet);
    let topped = wallet.top_up_bridge(BRIDGE, 30, None).await.unwrap();
    assert_eq!((topped.amount, topped.credited), (30, Some(30_000)));
    assert_eq!(held(&wallet), before - 30 - topped.fee);
    let account = wallet.bridge_account(BRIDGE).await.unwrap();
    assert_eq!(account.balance, 30_000);
    assert_eq!(
        (account.activity[0].hash.as_str(), account.activity[0].state),
        (topped.id.as_str(), State::Settled)
    );

    // Below 40: up to 60, but 50 a day, 30 of it topped up already.
    let rules = licash_wallet::BridgeRules {
        below: 40,
        up_to: 60,
        daily: 50,
        max_fee: Some(5),
    };
    let wrong = licash_wallet::BridgeRules { below: 70, ..rules };
    assert!(wallet.set_bridge_rules(BRIDGE, Some(wrong)).is_err());
    wallet.set_bridge_rules(BRIDGE, Some(rules)).unwrap();
    assert_eq!(wallet.bridge(BRIDGE).unwrap().rules, Some(rules));
    let done = wallet.top_up_bridges().await.unwrap();
    assert_eq!(done.len(), 1);
    let topped = done[0].1.as_ref().unwrap();
    assert_eq!((topped.amount, topped.credited), (20, Some(20_000)));
    assert_eq!(wallet.bridge_account(BRIDGE).await.unwrap().balance, 50_000);
    // Above the rules: none; below them, the day's limit reached: none.
    assert!(wallet.top_up_bridges().await.unwrap().is_empty());
    let higher = licash_wallet::BridgeRules {
        below: 100,
        up_to: 200,
        ..rules
    };
    wallet.set_bridge_rules(BRIDGE, Some(higher)).unwrap();
    assert!(wallet.top_up_bridges().await.unwrap().is_empty());

    // The same seed, restored: the same account, no pairing needed.
    let restored = net.user(9, 0).await;
    let (_, again) = restored.add_bridge(BRIDGE, None).await.unwrap();
    assert_eq!(again.balance, 50_000);

    // Back to the wallet in notes, the bridge's hub's fee out of the
    // account too.
    let before = held(&wallet);
    let paid = wallet.withdraw_bridge(BRIDGE, 10).await.unwrap();
    assert_eq!((paid.state, paid.amount), (State::Settled, 10_000));
    assert!(paid.payment.is_some() && paid.fee > 0, "{paid:?}");
    assert_eq!(held(&wallet), before + 10);
    let account = wallet.bridge_account(BRIDGE).await.unwrap();
    assert_eq!(account.balance, 50_000 - 10_000 - paid.fee);
    // Asked again under its id: the same payout, not another.
    let key = wallet.bridge_key(&net.bridge.info().unwrap()).unwrap();
    let mut key_ = [0u8; 32];
    hex::decode_to_slice(&key, &mut key_).unwrap();
    let reached = wallet.hub_urls(HUB).unwrap();
    let code = wallet.payment_code(&reached[..1]).unwrap().licash.unwrap();
    let payout = bridge::Payout {
        id: paid.id.clone(),
        amount: 10,
        code: code.to_string(),
    };
    let same = net.bridge.payout(&key_, &payout).await.unwrap();
    assert_eq!((same.state, same.fee), (State::Settled, paid.fee));
    assert_eq!(
        wallet.bridge_account(BRIDGE).await.unwrap().balance,
        account.balance
    );
    // To a code not naming its hub: refused, nothing taken.
    let elsewhere = licash_wallet::LicashCode {
        hubs: Vec::new(),
        locations: Vec::new(),
        ..code
    };
    let elsewhere = bridge::Payout {
        id: hex::encode([7; 32]),
        amount: 10,
        code: elsewhere.to_string(),
    };
    let refused = net.bridge.payout(&key_, &elsewhere).await;
    assert!(
        matches!(&refused, Err(Error::Invalid(m)) if m.contains("hub")),
        "{refused:?}"
    );
    // More than it holds: refused, nothing taken.
    let more = wallet.withdraw_bridge(BRIDGE, 1_000).await;
    assert!(more.is_err(), "{more:?}");
    assert_eq!(
        wallet.bridge_account(BRIDGE).await.unwrap().balance,
        account.balance
    );

    let connected = wallet
        .bridge_connect(BRIDGE, &connect(&[Permission::Pay], None))
        .await
        .unwrap();
    let revoked = wallet
        .bridge_revoke(BRIDGE, &connected.connection.key)
        .await
        .unwrap();
    assert!(revoked.revoked);
    wallet.remove_bridge(BRIDGE).unwrap();
    assert!(wallet.bridges().unwrap().is_empty());
}

/// A deposit's payment credits the account its payer's note names, once,
/// whoever hands it in: not another account, its hub's say, nor twice.
#[tokio::test]
async fn a_deposit_credits_the_account_its_note_names_once_whoever_hands_it_in() {
    let net = Net::new(true).await;
    let (alice, mallory) = (net.user(9, 200).await, net.user(10, 0).await);
    alice.add_bridge(BRIDGE, None).await.unwrap();
    mallory.add_bridge(BRIDGE, None).await.unwrap();
    let topped = alice.top_up_bridge(BRIDGE, 30, None).await.unwrap();
    let payment = alice.payment(&topped.id).unwrap();
    let info = net.bridge.info().unwrap();
    let key = |wallet: &Wallet<Both>| {
        let mut key = [0u8; 32];
        hex::decode_to_slice(wallet.bridge_key(&info).unwrap(), &mut key).unwrap();
        key
    };
    let deposit = bridge::Deposit {
        amount: 30,
        payment: Some(payment.clone()),
    };
    // Handed in by another account, as its hub could: credited to none.
    let stolen = net.bridge.deposit(&key(&mallory), &deposit).await;
    assert!(matches!(&stolen, Err(Error::Unauthorized(_))), "{stolen:?}");
    // Its note stripped: the same.
    let stripped = bridge::Deposit {
        amount: 30,
        payment: Some(licash_api::Payment {
            note: None,
            ..payment
        }),
    };
    let none = net.bridge.deposit(&key(&mallory), &stripped).await;
    assert!(matches!(&none, Err(Error::Unauthorized(_))), "{none:?}");
    assert_eq!(mallory.bridge_account(BRIDGE).await.unwrap().balance, 0);
    // Again by its payer: the same deposit, credited once.
    let again = net.bridge.deposit(&key(&alice), &deposit).await.unwrap();
    let credited = again.credited.unwrap();
    assert_eq!((credited.id, credited.amount), (topped.id, 30_000));
    assert_eq!(alice.bridge_account(BRIDGE).await.unwrap().balance, 30_000);
}

#[tokio::test]
async fn top_ups_count_against_the_daily_limit_whatever_the_bridge_answers() {
    let net = Net::new(false).await;
    let wallet = net.user(9, 60).await;
    wallet.add_bridge(BRIDGE, Some(&net.pairing)).await.unwrap();
    // Refused before anything was paid: never counted.
    let short = wallet.top_up_bridge(BRIDGE, 90, None).await;
    assert!(short.is_err(), "{short:?}");

    // Paid, the bridge's answer lost: not credited yet, still counted.
    wallet
        .transport()
        .deaf
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let topped = wallet.top_up_bridge(BRIDGE, 30, None).await.unwrap();
    assert_eq!(topped.credited, None);
    wallet
        .transport()
        .deaf
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let rules = licash_wallet::BridgeRules {
        below: 40,
        up_to: 50,
        daily: 40,
        max_fee: None,
    };
    wallet.set_bridge_rules(BRIDGE, Some(rules)).unwrap();
    // Told the bridge first, credited; then 20 short of 50, but 40 a day,
    // 30 of it topped up.
    let done = wallet.top_up_bridges().await.unwrap();
    assert_eq!(done[0].1.as_ref().unwrap().amount, 10);
    assert_eq!(wallet.bridge_account(BRIDGE).await.unwrap().balance, 40_000);
}

/// What `wallet` holds in notes, available.
fn held<T: Transport>(wallet: &Wallet<T>) -> u64 {
    wallet.balance().unwrap().iter().map(|b| b.available).sum()
}

async fn get_json(app: &Router, path: &str) -> serde_json::Value {
    let r = call(app, path, None).await;
    assert_eq!(
        r.status,
        200,
        "{path}: {}",
        String::from_utf8_lossy(&r.body)
    );
    serde_json::from_slice(&r.body).unwrap()
}

/// `text` percent-encoded, as a query's value.
fn encoded(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    use bitcoin::hashes::{sha256, Hash};
    sha256::Hash::hash(bytes).to_string()
}

fn committed(invoice: &lightning_invoice::Bolt11Invoice) -> String {
    match invoice.description() {
        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(h) => h.0.to_string(),
        lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(d) => panic!("says {d}"),
    }
}

#[tokio::test]
async fn a_lightning_address_is_paid_and_zapped() {
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
    let net = Net::with(Config {
        public_url: Some("https://Pay.test/".into()),
        ..Config::default()
    })
    .await;
    let owner = net.owner(0).await;
    let app = licash_bridge::router(net.bridge.clone());
    assert_eq!(
        get_json(&app, "/.well-known/lnurlp/alice").await["status"],
        "ERROR"
    );
    assert!(net.bridge.set_username(&owner, Some("not ok!")).is_err());
    let account = net.bridge.set_username(&owner, Some("Alice")).unwrap();
    assert_eq!(account.lightning_address.as_deref(), Some("alice@pay.test"));

    let pay = get_json(&app, "/.well-known/lnurlp/alice").await;
    assert_eq!(pay["tag"], "payRequest");
    assert_eq!(pay["callback"], "https://Pay.test/lnurlp/alice/callback");
    // 1 sat of notes at least, the hub's 1 on top.
    assert_eq!(
        (pay["minSendable"].as_u64(), pay["allowsNostr"].as_bool()),
        (Some(2_000), Some(true))
    );
    assert_eq!(pay["nostrPubkey"], net.bridge.keys().public_key().to_hex());
    let metadata = pay["metadata"].as_str().unwrap();
    assert!(metadata.contains("alice@pay.test"));

    let refused = get_json(&app, "/lnurlp/alice/callback?amount=1000").await;
    assert_eq!(refused["status"], "ERROR");
    let paid = get_json(&app, "/lnurlp/alice/callback?amount=21000&comment=Thanks").await;
    let invoice: lightning_invoice::Bolt11Invoice = paid["pr"].as_str().unwrap().parse().unwrap();
    assert_eq!(invoice.amount_milli_satoshis(), Some(21_000));
    assert_eq!(committed(&invoice), sha256(metadata.as_bytes()));
    let hash = hex::encode(invoice.payment_hash().as_ref() as &[u8]);
    let verify = paid["verify"]
        .as_str()
        .unwrap()
        .strip_prefix("https://Pay.test")
        .unwrap()
        .to_owned();
    assert_eq!(get_json(&app, &verify).await["settled"], false);
    net.pay_in(&hash).await;
    assert_eq!(get_json(&app, &verify).await["settled"], true);
    assert_eq!(balance(&net, &owner), 20_000);
    let activity = &net.bridge.account(&owner).unwrap().activity[0];
    assert_eq!(activity.description.as_deref(), Some("Thanks"));

    // Zapped: the invoice commits to the zap request, whose receipt is
    // published once paid, to the relays it names.
    let (zapper, recipient) = (Keys::generate(), Keys::generate());
    let request = EventBuilder::new(Kind::ZapRequest, "Great post")
        .tags([
            Tag::public_key(recipient.public_key()),
            Tag::custom("relays", ["wss://zaps.test"]),
            Tag::custom("amount", ["5000"]),
        ])
        .finalize(&zapper)
        .unwrap();
    let json = request.as_json();
    let wrong = format!(
        "/lnurlp/alice/callback?amount=6000&nostr={}",
        encoded(&json)
    );
    assert_eq!(get_json(&app, &wrong).await["status"], "ERROR");
    let zap = format!(
        "/lnurlp/alice/callback?amount=5000&nostr={}",
        encoded(&json)
    );
    let zapped = get_json(&app, &zap).await;
    let pr = zapped["pr"].as_str().unwrap();
    let invoice: lightning_invoice::Bolt11Invoice = pr.parse().unwrap();
    assert_eq!(committed(&invoice), sha256(json.as_bytes()));
    assert!(net.bridge.zap_receipts().unwrap().is_empty());
    net.pay_in(&hex::encode(invoice.payment_hash().as_ref() as &[u8]))
        .await;
    let receipts = net.bridge.zap_receipts().unwrap();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.event.kind, Kind::ZapReceipt);
    assert_eq!(receipt.event.pubkey, net.bridge.keys().public_key());
    assert!(receipt.event.verify().is_ok());
    let tag = |kind: &str| {
        receipt
            .event
            .tags
            .iter()
            .find(|t| t.as_slice()[0] == kind)
            .map(|t| t.as_slice()[1].clone())
    };
    assert_eq!(tag("description").as_deref(), Some(json.as_str()));
    assert_eq!(tag("bolt11").as_deref(), Some(pr));
    assert_eq!(tag("p"), Some(recipient.public_key().to_hex()));
    assert_eq!(tag("P"), Some(zapper.public_key().to_hex()));
    assert_eq!(
        receipt.relays[0].as_str().trim_end_matches('/'),
        "wss://zaps.test"
    );
    net.bridge.zap_published(&receipt.hash).unwrap();
    assert!(net.bridge.zap_receipts().unwrap().is_empty());
    assert_eq!(balance(&net, &owner), 24_000);
}

/// Anyone may ask an address for invoices: past 64 unpaid it refuses,
/// so that they fill that address alone.
#[tokio::test]
async fn an_address_refuses_more_invoices_than_so_many_unpaid() {
    let net = Net::with(Config {
        public_url: Some("https://pay.test/".into()),
        ..Config::default()
    })
    .await;
    let owner = net.owner(0).await;
    net.bridge.set_username(&owner, Some("alice")).unwrap();
    let app = licash_bridge::router(net.bridge.clone());
    for n in 0..64 {
        let paid = get_json(
            &app,
            &format!("/lnurlp/alice/callback?amount={}", 2_000 + n * 1_000),
        )
        .await;
        assert!(paid["pr"].is_string(), "{n}: {paid}");
    }
    let refused = get_json(&app, "/lnurlp/alice/callback?amount=2000").await;
    assert_eq!(refused["status"], "ERROR", "{refused}");
    assert!(
        refused["reason"].as_str().unwrap().contains("unpaid"),
        "{refused}"
    );
}

#[tokio::test]
async fn an_owner_freezes_the_bridge_and_imports_its_notes_to_claim() {
    let net = Net::new(false).await;
    let wallet = net.user(9, 200).await;
    wallet.add_bridge(BRIDGE, Some(&net.pairing)).await.unwrap();
    wallet.top_up_bridge(BRIDGE, 30, None).await.unwrap();
    let held = net.bridge.status().unwrap().held;
    assert!(held >= 30, "{held}");

    // Not while a payment is under way, whose notes are its lock's; frozen
    // from the first ask all the same.
    let request = net.node.invoice(1_000, [12; 32], 18, Outcome::Hang);
    let db = rusqlite::Connection::open(net.dir.path().join("bridge.sqlite")).unwrap();
    db.execute(
        "INSERT INTO bridge_payments (hash, account, connection, invoice, amount, reserved,
            state, started_at, created_at)
         VALUES (?1, 1, NULL, ?2, 1000, 0, 'pending', ?3, ?3)",
        rusqlite::params![[12u8; 32], request, licash_store::now()],
    )
    .unwrap();
    let early = wallet.export_bridge(BRIDGE).await;
    assert!(
        matches!(&early, Err(licash_wallet::Error::Unavailable { .. })),
        "{early:?}"
    );
    assert!(net.bridge.status().unwrap().frozen);
    net.bridge.round().await.unwrap();

    let (imported, export) = wallet.export_bridge(BRIDGE).await.unwrap();
    assert_eq!(imported.amount, held);
    assert_eq!(imported.source, net.bridge.keys().public_key().to_hex());
    assert_eq!(wallet.imported_notes().unwrap()[0].amount, held);
    // Frozen: nothing paid out, no invoice made; the same export again.
    let paid = wallet.withdraw_bridge(BRIDGE, 5).await;
    assert!(
        matches!(&paid, Err(licash_wallet::Error::Invalid(m)) if m.contains("exported")),
        "{paid:?}"
    );
    assert!(wallet.top_up_bridge(BRIDGE, 5, None).await.is_err());
    let again = wallet.export_bridge(BRIDGE).await.unwrap().0;
    assert_eq!((again.added, again.known), (0, imported.added));
    assert!(wallet.import_notes(&export).is_ok());

    // Discarded by its owner, unfrozen by its operator: it pays again.
    wallet.discard_imported(&imported.source).unwrap();
    assert!(net.bridge.unfreeze().unwrap());
    assert!(!net.bridge.unfreeze().unwrap());
    wallet.withdraw_bridge(BRIDGE, 5).await.unwrap();
}

/// A payment its hub holds, and may never decide should it stop
/// answering: once its lock is made, the bridge exports its refund with its
/// notes, for its owner to claim on Bitcoin.
#[tokio::test]
async fn a_bridge_stuck_on_a_payment_exports_its_lock_with_its_notes() {
    let net = Net::new(false).await;
    let wallet = net.user(9, 200).await;
    wallet.add_bridge(BRIDGE, Some(&net.pairing)).await.unwrap();
    wallet.top_up_bridge(BRIDGE, 30, None).await.unwrap();
    let mut key = [0u8; 32];
    let info = net.bridge.info().unwrap();
    hex::decode_to_slice(wallet.bridge_key(&info).unwrap(), &mut key).unwrap();

    let request = net.node.invoice(10_000, [13; 32], 18, Outcome::Hang);
    let bridge_ = net.bridge.clone();
    let paying = tokio::spawn(async move {
        let withdraw = bridge::Withdraw {
            invoice: request,
            max_fee: None,
        };
        bridge_.withdraw(&key, &withdraw).await
    });
    let mut locked = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let locks = net.bridge.wallet().locks().unwrap();
        if locks
            .iter()
            .any(|l| l.state == licash_wallet::LockState::Locked)
        {
            locked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(locked, "no lock made");

    // Under way, its lock made: exported, the lock's refund with it.
    let (imported, _) = wallet.export_bridge(BRIDGE).await.unwrap();
    assert!(net.bridge.status().unwrap().frozen);
    assert_eq!(imported.locks, 1);
    assert!(imported.locked >= 10, "{imported:?}");
    let listed = &wallet.imported_notes().unwrap()[0];
    assert_eq!((listed.locks, listed.locked), (1, imported.locked));
    assert!(!paying.is_finished());
    paying.abort();
}

#[tokio::test]
async fn an_open_bridge_exports_to_its_operator_only() {
    let net = Net::new(true).await;
    let wallet = net.user(9, 50).await;
    wallet.add_bridge(BRIDGE, None).await.unwrap();
    let refused = wallet.export_bridge(BRIDGE).await;
    assert!(
        matches!(&refused, Err(licash_wallet::Error::Invalid(m)) if m.contains("operator")),
        "{refused:?}"
    );
    assert!(!net.bridge.status().unwrap().frozen);
    // Its operator's, on the command line: to a key of its choosing.
    let key = wallet.bridge_key(&net.bridge.info().unwrap()).unwrap();
    let mut to = [0u8; 32];
    hex::decode_to_slice(&key, &mut to).unwrap();
    let exported = net.bridge.export(&to).await.unwrap();
    assert!(net.bridge.status().unwrap().frozen);
    assert_eq!(
        wallet.import_notes(&exported.export.0).unwrap().added as u64,
        exported.notes
    );
}

/// An open bridge run again for its owner alone keeps the accounts anyone
/// registered: none of them exports every account's notes by signing, and
/// the bridge is not frozen. Its operator still exports them.
#[tokio::test]
async fn a_bridge_once_open_exports_to_its_operator_only_run_closed() {
    let net = Net::new(true).await;
    let (one, two) = (net.user(9, 50).await, net.user(10, 50).await);
    one.add_bridge(BRIDGE, None).await.unwrap();
    two.add_bridge(BRIDGE, None).await.unwrap();
    // Run again over the same file, without --open.
    let path = net.dir.path().join("bridge.sqlite");
    let wallet = Wallet::open(&path, reaching(&net.app, &net.provider)).unwrap();
    let config = Config {
        open: false,
        ..net.bridge.config().clone()
    };
    let closed = Arc::new(Bridge::open(wallet, config).unwrap());
    closed.round().await.unwrap();
    let both = Both {
        hub: net.app.clone(),
        bridge: licash_bridge::router(closed.clone()),
        deaf: Arc::default(),
    };
    for user in [&one, &two] {
        let user = Wallet::open(user.path(), both.clone()).unwrap();
        let refused = user.export_bridge(BRIDGE).await;
        assert!(
            matches!(&refused, Err(licash_wallet::Error::Invalid(m)) if m.contains("operator")),
            "{refused:?}"
        );
    }
    assert!(!closed.status().unwrap().frozen);
    let key = one.bridge_key(&closed.info().unwrap()).unwrap();
    let mut to = [0u8; 32];
    hex::decode_to_slice(&key, &mut to).unwrap();
    closed.export(&to).await.unwrap();
    assert!(closed.status().unwrap().frozen);
}

#[tokio::test]
async fn an_open_bridge_registers_so_many_accounts_an_hour_and_in_all() {
    let net = Net::with(Config {
        open: true,
        max_accounts: Some(3),
        registrations_per_hour: Some(2),
        ..Config::default()
    })
    .await;
    net.bridge.register(&key(3), None).unwrap();
    net.bridge.register(&key(4), None).unwrap();
    let hourly = net.bridge.register(&key(5), None);
    assert!(
        matches!(&hourly, Err(Error::Quota(m)) if m.contains("hour")),
        "{hourly:?}"
    );
    // An account registered again is no new one.
    net.bridge.register(&key(3), None).unwrap();
    // An hour on, one more; then no more at all.
    let db = rusqlite::Connection::open(net.dir.path().join("bridge.sqlite")).unwrap();
    db.execute(
        "UPDATE bridge_accounts SET created_at = created_at - 3601",
        [],
    )
    .unwrap();
    net.bridge.register(&key(5), None).unwrap();
    let full = net.bridge.register(&key(6), None);
    assert!(
        matches!(&full, Err(Error::Quota(m)) if m.contains("at most")),
        "{full:?}"
    );
}

#[tokio::test]
async fn a_bridge_is_topped_up_and_pays_through_its_provider() {
    let net = Net::with(Config::default()).await;
    // Its provider's terms, once asked.
    net.bridge.round().await.unwrap();
    assert_eq!(
        net.bridge.info().unwrap().receive_fee,
        Fee { base: 1, ppm: 0 }
    );
    // Topped up through the provider: 100 sat asked, 99 credited.
    let owner = net.owner(100_000).await;
    assert_eq!(balance(&net, &owner), 99_000);
    // Of a part of a sat: refused, a provider's invoices asking whole ones.
    let sub_sat = net.bridge.top_up(&owner, 10_500).await;
    assert!(matches!(sub_sat, Err(Error::Invalid(_))), "{sub_sat:?}");

    let connected = net
        .bridge
        .connect(&owner, &connect(&[Permission::Pay], None))
        .unwrap();
    let uri = NostrWalletConnectUri::parse(&connected.uri).unwrap();
    let preimage = [5; 32];
    let request = net
        .node
        .invoice(20_000, lock_hash(&preimage), 18, Outcome::Pay(preimage));
    let pay = nip47::Request::pay_invoice(PayInvoiceRequest {
        id: None,
        invoice: request,
        amount: None,
    });
    let paid = ask(&net, &uri, pay, Nip47Ciphers::NIP44V2).await;
    let Some(ResponseResult::PayInvoice(paid)) = paid.result else {
        panic!("{paid:?}");
    };
    assert_eq!(paid.preimage, hex::encode(preimage));
    // The provider's 2 sat, and the hub's on the lock, if any.
    let fees = paid.fees_paid.unwrap();
    assert!(fees >= 2_000, "{fees}");
    assert_eq!(balance(&net, &owner), 99_000 - 20_000 - fees);
    assert_eq!(net.node.sent().len(), 1);
    let locks = net.bridge.wallet().locks().unwrap();
    assert!(locks[0].via.is_some(), "{locks:?}");
}

/// Its provider holding nothing at its hub yet: the bridge still says what
/// it is, its provider's fee on receiving named, and its addresses take
/// nothing at once.
#[tokio::test]
async fn a_bridge_whose_provider_holds_nothing_at_its_hub_still_answers() {
    let net = Net::stocked(
        Config {
            public_url: Some("https://pay.test".into()),
            ..Config::default()
        },
        0,
    )
    .await;
    let owner = net.owner(0).await;
    net.bridge.round().await.unwrap();
    assert_eq!(
        net.bridge.info().unwrap().receive_fee,
        Fee { base: 1, ppm: 0 }
    );
    net.bridge.set_username(&owner, Some("alice")).unwrap();
    let app = licash_bridge::router(net.bridge.clone());
    let pay = get_json(&app, "/.well-known/lnurlp/alice").await;
    assert_eq!(pay["tag"], "payRequest", "{pay}");
    assert_eq!(pay["maxSendable"], pay["minSendable"], "{pay}");
    let refused = net.bridge.top_up(&owner, 10_000).await;
    assert!(refused.is_err(), "{refused:?}");
}

#[tokio::test]
async fn a_lightning_address_is_paid_through_the_provider() {
    let net = Net::with(Config {
        public_url: Some("https://pay.test".into()),
        ..Config::default()
    })
    .await;
    let owner = net.owner(0).await;
    net.bridge.round().await.unwrap();
    net.bridge.set_username(&owner, Some("alice")).unwrap();
    let app = licash_bridge::router(net.bridge.clone());
    let pay = get_json(&app, "/.well-known/lnurlp/alice").await;
    // 1 sat of notes at least, the provider's 1 on top.
    assert_eq!(pay["minSendable"].as_u64(), Some(2_000));
    let metadata = pay["metadata"].as_str().unwrap();
    // Of a part of a sat: refused.
    let refused = get_json(&app, "/lnurlp/alice/callback?amount=21500").await;
    assert_eq!(refused["status"], "ERROR");
    let paid = get_json(&app, "/lnurlp/alice/callback?amount=21000").await;
    let invoice: lightning_invoice::Bolt11Invoice = paid["pr"].as_str().unwrap().parse().unwrap();
    assert_eq!(invoice.amount_milli_satoshis(), Some(21_000));
    assert_eq!(committed(&invoice), sha256(metadata.as_bytes()));
    let hash = hex::encode(invoice.payment_hash().as_ref() as &[u8]);
    net.pay_in(&hash).await;
    assert_eq!(balance(&net, &owner), 20_000);
}

/// Its Lightning Addresses are served within the most requests at once,
/// as its management API is: requests whose bodies stall take every place,
/// an address's pay request is then unavailable, its health still told,
/// and served again once they are gone.
#[tokio::test]
async fn stalled_requests_hold_no_more_places_than_the_most_served_at_once() {
    use axum::body::Bytes;
    let net = Net::with(Config {
        public_url: Some("https://pay.test/".into()),
        ..Config::default()
    })
    .await;
    let app = licash_bridge::router(net.bridge.clone());
    let stalled: Vec<_> = (0..licash_bridge::MAX_SERVING)
        .map(|_| {
            let body =
                Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
            let request = Request::post(licash_api::bridge::REGISTER)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap();
            tokio::spawn(app.clone().oneshot(request))
        })
        .collect();
    let pay_request = "/.well-known/lnurlp/alice";
    let busy = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let busy = call(&app, pay_request, None).await;
            if busy.status == 503 {
                break busy;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("its pay request shed once every place is held");
    let problem: licash_api::Problem = serde_json::from_slice(&busy.body).unwrap();
    assert_eq!(problem.message, "the bridge is too busy now");
    assert_eq!(call(&app, licash_serve::HEALTH, None).await.status, 200);
    for stalled in &stalled {
        stalled.abort();
    }
    for stalled in stalled {
        let _ = stalled.await;
    }
    assert_eq!(call(&app, pay_request, None).await.status, 200);
}

/// A request older than five minutes is not answered: what the bridge
/// answered is remembered only so long, so one replayed later is refused
/// by its age. One not quite so old is answered.
#[tokio::test]
async fn an_nwc_request_older_than_five_minutes_is_not_answered() {
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
    let net = Net::new(false).await;
    let owner = net.owner(0).await;
    let connected = net
        .bridge
        .connect(&owner, &connect(&[Permission::Receive], None))
        .unwrap();
    let uri = NostrWalletConnectUri::parse(&connected.uri).unwrap();
    let sent = |ago: u64| {
        let request = nip47::Request::get_balance();
        let content = Nip47Ciphers::NIP04
            .encrypt(&uri.secret, &uri.public_key, &request.as_json())
            .unwrap();
        EventBuilder::new(Kind::WalletConnectRequest, content)
            .tag(Tag::public_key(uri.public_key))
            .custom_created_at(Timestamp::from_secs(Timestamp::now().as_secs() - ago))
            .finalize(&Keys::new(uri.secret.clone()))
            .unwrap()
    };
    assert!(nwc::answer(&net.bridge, &sent(310)).await.is_none());
    let answered = nwc::answer(&net.bridge, &sent(290)).await;
    assert!(answered.is_some());
}
