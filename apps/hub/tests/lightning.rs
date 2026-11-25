//! The Lightning gateway over a fake node, in process: wallets pay
//! invoices and get paid through it, and its failures end in refunds.

mod chain;

use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{header, Method, Request},
    Router,
};
use http_body_util::BodyExt;
use licash::spend::{lock_hash, ChainProfile, ProposalId};
use licash_api::{Fee, Info, Pay, PayState, Paying, Problem, ReceiveState};
use licash_hub::{Hub, Policy, Timing};
use licash_hub_service::lightning::{
    fake::{Fake, Outcome},
    Config, Gateway, HeldState,
};
use licash_wallet::{InvoiceState, LockState, Response, Transport, Wallet};
use lightning_invoice::Bolt11Invoice;
use tower::ServiceExt;

const HUB: &str = "http://hub.test";
const MAX_POW: u32 = 6;

/// Short, to expire locks in a test.
const TIMING: Timing = Timing {
    window: 40,
    reaction: 2,
    min_depth: 1,
    max_headers: 4032,
    bury: 6,
    max_lag: 120,
};

fn config() -> Config {
    Config {
        pay: Fee { base: 2, ppm: 0 },
        receive: Fee { base: 1, ppm: 0 },
        max_pay: 100,
        min_receive: 1,
        max_receive: 100,
        pay_slack: 4,
        hold_delta: 3,
        downtime: 2,
        receive_blocks: 6,
        grace: 0,
        ..Config::default()
    }
}

/// A hub with a gateway over a fake node, both following one chain.
struct Net {
    hub: Arc<Hub>,
    node: Arc<Fake>,
    gateway: Arc<Gateway>,
    app: Router,
    chain: Mutex<chain::Chain>,
    dir: tempfile::TempDir,
}

impl Net {
    /// A hub without fees, its gateway's node known.
    async fn new() -> Self {
        let net = Self::with(Policy {
            timing: TIMING,
            ..Policy::default()
        });
        net.gateway.round().await;
        net
    }

    fn with(policy: Policy) -> Self {
        Self::configured(policy, config())
    }

    /// A hub of `policy` whose gateway is of `config`.
    fn configured(policy: Policy, config: Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, MAX_POW).unwrap();
        let hub = Arc::new(Hub::open(&seed, &db, policy).unwrap());
        let chain = chain::Chain::new();
        hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
        let node = Arc::new(Fake::new());
        let path = dir.path().join("hub.sqlite");
        let gateway = Gateway::open(hub.clone(), node.clone(), config, &path).unwrap();
        let gateway = Arc::new(gateway);
        let net = Self {
            app: licash_hub_service::router(
                hub.clone(),
                licash_hub_service::Services {
                    gateway: Some(gateway.clone()),
                    ..Default::default()
                },
            ),
            hub,
            node,
            gateway,
            chain: Mutex::new(chain),
            dir,
        };
        net.mine(3, None);
        net
    }

    /// Mine `blocks`, the first with an activation of `secret` if given,
    /// which the hub scans and the node follows.
    fn mine(&self, blocks: u32, mut secret: Option<[u8; 32]>) {
        let mut chain = self.chain.lock().unwrap();
        for _ in 0..blocks {
            let block = chain.mine(secret.take()).clone();
            self.hub.observe(chain.height(), &block).unwrap();
        }
        assert!(self.hub.synced(chain.height(), &chain.tip()).unwrap());
        self.node.tip(chain.height(), chain.tip());
    }

    fn height(&self) -> u32 {
        self.chain.lock().unwrap().height()
    }

    fn wallet(&self, name: &str) -> Wallet<Local> {
        let path = self.dir.path().join(format!("{name}.sqlite"));
        let mut seed = [0; 32];
        seed[..name.len()].copy_from_slice(name.as_bytes());
        Wallet::create(
            &path,
            &seed,
            ChainProfile::Core30DefaultRegtest,
            Local(self.app.clone()),
        )
        .unwrap()
    }

    /// A wallet holding `amount`, paid to it over Lightning.
    async fn funded(&self, name: &str, amount: u64) -> Wallet<Local> {
        let wallet = self.wallet(name);
        let invoice = wallet.invoice(HUB, amount).await.unwrap();
        self.pay_held(&invoice.hash);
        self.gateway.round().await;
        let invoice = wallet.follow_invoice(&invoice.hash).await.unwrap();
        assert_eq!(invoice.state, InvoiceState::Received);
        self.gateway.round().await;
        wallet
    }

    /// Another node pays the held invoice of `hash`, its HTLCs lasting
    /// the invoice's final delta.
    fn pay_held(&self, hash: &str) {
        let hash = bytes(hash);
        let cltv = self.node.held_cltv(hash).unwrap() as u32;
        self.node.pay_held(hash, self.height() + cltv);
    }

    async fn info(&self) -> Info {
        let response = Local(self.app.clone())
            .request(&format!("{HUB}{}", licash_api::INFO), None)
            .await
            .unwrap();
        serde_json::from_slice(&response.body).unwrap()
    }
}

fn bytes(hash: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    hex::decode_to_slice(hash, &mut bytes).unwrap();
    bytes
}

fn available(wallet: &Wallet<Local>) -> u64 {
    wallet.balance().unwrap().iter().map(|b| b.available).sum()
}

/// The service's router, reached at [`HUB`].
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
        async move {
            let request = match body {
                Some(body) => Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body)),
                None => Request::builder().uri(path).body(Body::empty()),
            };
            let response = app.oneshot(request.unwrap()).await.unwrap();
            let status = response.status().as_u16();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            Ok(Response {
                status,
                body: body.to_vec(),
            })
        }
    }
}

/// The service as a hub of before memos: naming no such feature, or
/// naming it while leaving memos out of its invoices as that hub did.
#[derive(Clone)]
struct Memoless {
    local: Local,
    names: bool,
}

impl Transport for Memoless {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let (this, url) = (self.clone(), url.to_owned());
        async move {
            let body = body.map(|body| {
                let mut asked: serde_json::Value = serde_json::from_slice(&body).unwrap();
                asked.as_object_mut().map(|a| a.remove("memo"));
                serde_json::to_vec(&asked).unwrap()
            });
            let mut response = this.local.request(&url, body).await?;
            if url.ends_with(licash_api::INFO) && !this.names {
                let mut info: Info = serde_json::from_slice(&response.body).unwrap();
                info.features.retain(|f| f != licash_api::FEATURE_MEMO);
                response.body = serde_json::to_vec(&info).unwrap();
            }
            Ok(response)
        }
    }
}

fn proposal_id(id: &str) -> ProposalId {
    ProposalId::from_bytes(bytes(id))
}

async fn call(net: &Net, path: &str, body: &impl serde::Serialize) -> Response {
    let body = serde_json::to_vec(body).unwrap();
    let url = format!("{HUB}{path}");
    Local(net.app.clone())
        .request(&url, Some(body))
        .await
        .unwrap()
}

async fn post<T: serde::de::DeserializeOwned>(
    net: &Net,
    path: &str,
    body: &impl serde::Serialize,
) -> T {
    let response = call(net, path, body).await;
    let text = String::from_utf8_lossy(&response.body);
    assert_eq!(response.status, 200, "{text}");
    serde_json::from_slice(&response.body).unwrap()
}

async fn refused(net: &Net, path: &str, body: &impl serde::Serialize) -> Problem {
    let response = call(net, path, body).await;
    let problem: Problem = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response.status, problem.code.status(), "{problem:?}");
    problem
}

fn alerts(hub: &Hub) -> usize {
    let events = hub.events(0, 1000).unwrap();
    events.iter().filter(|e| e.kind == "alert").count()
}

/// The preimage `wallet` drew for its invoice of `hash`.
fn preimage_of(net: &Net, name: &str, hash: &str) -> [u8; 32] {
    let db = rusqlite::Connection::open(net.dir.path().join(format!("{name}.sqlite"))).unwrap();
    db.query_row(
        "SELECT preimage FROM invoices WHERE hash = ?1",
        [bytes(hash)],
        |r| r.get(0),
    )
    .unwrap()
}

#[tokio::test]
async fn a_short_receipt_lock_does_not_receive_the_invoices_preimage() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let invoice = alice.invoice(HUB, 10).await.unwrap();
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    let body: String = db
        .query_row(
            "SELECT body FROM lightning_receipts WHERE hash = ?1",
            [bytes(&invoice.hash)],
            |r| r.get(0),
        )
        .unwrap();
    let body: licash_api::Receive = serde_json::from_str(&body).unwrap();
    let ((keyset, ephemeral, hash), outputs) = (body.terms().unwrap(), body.outputs().unwrap());
    assert!(outputs.len() > 1);
    let amount = outputs[0].denomination();
    let terms = licash::spend::TimedTerms::new(
        ChainProfile::Core30DefaultRegtest,
        net.hub.checkpoint().unwrap().commitment(),
        net.height() + 6,
        1,
        hash,
    )
    .unwrap();
    let lock = net
        .hub
        .lock_own(&keyset, ephemeral, vec![outputs[0]], terms)
        .unwrap();
    let id = lock.proposal.id();
    db.execute(
        "UPDATE lightning_receipts SET lock = ?1, state = 'locked' WHERE hash = ?2",
        rusqlite::params![id.as_bytes(), hash],
    )
    .unwrap();
    assert_eq!(
        alice.follow_invoice(&invoice.hash).await.unwrap().state,
        InvoiceState::Canceled(format!("its lock pays {amount} of 10"))
    );
    let lock = net.hub.locked(&id).unwrap();
    assert_eq!((lock.preimage, lock.settled), (None, None));
}

#[tokio::test]
async fn a_payment_received_is_claimed_and_settles_its_invoice() {
    let net = Net::new().await;
    let lightning = net.info().await.lightning.unwrap();
    assert_eq!(lightning.node, net.node.pubkey());
    assert_eq!(lightning.receive, Fee { base: 1, ppm: 0 });
    let wallet = net.wallet("alice");
    assert!(matches!(
        wallet.invoice(HUB, 101).await,
        Err(licash_wallet::Error::Invalid(_))
    ));
    let invoice = wallet.invoice(HUB, 20).await.unwrap();
    assert_eq!(invoice.state, InvoiceState::Open);
    let request: Bolt11Invoice = invoice.request.clone().unwrap().parse().unwrap();
    assert_eq!(request.amount_milli_satoshis(), Some(21_000));
    let hash = bytes(&invoice.hash);
    // Its life, depth, downtime and hold delta, and 4.
    assert_eq!(net.node.held_cltv(hash), Some(6 + 1 + 2 + 3 + 4));
    net.gateway.round().await;
    let open = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(open.state, InvoiceState::Open);
    assert_eq!(open.request, invoice.request);

    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    let status = net.gateway.receive_status(&hash).unwrap();
    assert_eq!(status.state, ReceiveState::Locked);
    let received = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(received.state, InvoiceState::Received);
    assert_eq!(available(&wallet), 20);
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Accepted);
    net.gateway.round().await;
    assert_eq!(net.node.held(hash).unwrap(), (HeldState::Settled, 21_000));
    assert_eq!(
        net.gateway.receive_status(&hash).unwrap().state,
        ReceiveState::Settled
    );
    let resumed = wallet.resume().await.unwrap();
    assert!(resumed.invoices.is_empty() && resumed.pending.is_empty());
    assert_eq!(wallet.invoices().unwrap(), vec![received]);
}

/// What `request` says it pays for, in words, if anything.
/// The service, its answers coming after others have had their turn, and
/// counting the requests about invoices: as over a network.
#[derive(Clone)]
struct Slow {
    local: Local,
    receives: Arc<std::sync::atomic::AtomicUsize>,
}

impl Transport for Slow {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let (this, url) = (self.clone(), url.to_owned());
        async move {
            if url.contains(licash_api::LN_RECEIVE) {
                this.receives
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            tokio::task::yield_now().await;
            this.local.request(&url, body).await
        }
    }
}

#[tokio::test]
async fn an_invoice_followed_and_resumed_at_once_is_claimed_once() {
    let net = Net::new().await;
    let receives = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let slow = Slow {
        local: Local(net.app.clone()),
        receives: receives.clone(),
    };
    let path = net.dir.path().join("alice.sqlite");
    let wallet = Wallet::create(&path, &[7; 32], ChainProfile::Core30DefaultRegtest, slow).unwrap();
    let invoice = wallet.invoice(HUB, 20).await.unwrap();
    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    let asked = receives.load(std::sync::atomic::Ordering::SeqCst);
    // The app follows it while its round resumes what is under way: one
    // advances it, the other then finds it done, asking its hub nothing.
    let (followed, resumed) = tokio::join!(wallet.follow_invoice(&invoice.hash), wallet.resume());
    assert_eq!(followed.unwrap().state, InvoiceState::Received);
    let resumed = resumed.unwrap();
    assert!(resumed.pending.is_empty(), "{:?}", resumed.pending);
    assert!(resumed
        .invoices
        .iter()
        .all(|i| i.state == InvoiceState::Received));
    assert_eq!(
        receives.load(std::sync::atomic::Ordering::SeqCst) - asked,
        1
    );
    assert_eq!(
        wallet
            .balance()
            .unwrap()
            .iter()
            .map(|b| b.available)
            .sum::<u64>(),
        20
    );
    net.gateway.round().await;
    assert_eq!(
        net.node.held(bytes(&invoice.hash)).unwrap(),
        (HeldState::Settled, 21_000)
    );
}

fn description(request: &str) -> Option<String> {
    let invoice: Bolt11Invoice = request.parse().unwrap();
    match invoice.description() {
        lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(d) => Some(d.to_string()),
        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(_) => None,
    }
    .filter(|d| !d.is_empty())
}

#[tokio::test]
async fn an_invoice_says_the_memo_its_wallet_asked_for_and_no_other() {
    let net = Net::new().await;
    let features = net.info().await.features;
    assert!(features.iter().any(|f| f == licash_api::FEATURE_MEMO));
    let alice = net.wallet("alice");
    let asked = alice.invoice_saying(HUB, 20, Some("  Lunch\n on\tFriday "), false);
    let invoice = asked.await.unwrap();
    assert_eq!(invoice.memo.as_deref(), Some("Lunch on Friday"));
    let request = invoice.request.clone().unwrap();
    assert_eq!(description(&request).as_deref(), Some("Lunch on Friday"));
    assert_eq!(alice.invoices().unwrap()[0].memo, invoice.memo);
    // None asked: none said.
    let plain = alice.invoice(HUB, 20).await.unwrap();
    assert_eq!(plain.memo, None);
    assert_eq!(description(&plain.request.unwrap()), None);
    // Refused by the wallet before the hub hears of it.
    for memo in ["", " ", &"x".repeat(licash_api::MAX_MEMO + 1), "a\u{7}b"] {
        let refused = alice.invoice_saying(HUB, 20, Some(memo), false).await;
        assert!(
            matches!(refused, Err(licash_wallet::Error::Invalid(_))),
            "{memo:?}"
        );
    }
    // Paid as any other: the memo stays with it.
    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    let received = alice.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(received.state, InvoiceState::Received);
    assert_eq!(received.memo.as_deref(), Some("Lunch on Friday"));

    // At the hub: the same receipt with another memo, or one not as a
    // wallet makes it, is refused, and its invoice never says another.
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    let body: String = db
        .query_row(
            "SELECT body FROM lightning_receipts WHERE hash = ?1",
            [bytes(&plain.hash)],
            |r| r.get(0),
        )
        .unwrap();
    let body: licash_api::Receive = serde_json::from_str(&body).unwrap();
    assert_eq!(body.memo, None);
    let other = body.clone().with_memo(Some("Rent".into()));
    let problem = refused(&net, licash_api::LN_RECEIVE, &other).await;
    assert!(problem.message.contains("another receipt"), "{problem:?}");
    for memo in [" Rent", "a\u{7}b", ""] {
        let bad = body.clone().with_memo(Some(memo.into()));
        let problem = refused(&net, licash_api::LN_RECEIVE, &bad).await;
        assert!(problem.message.contains("memo"), "{memo:?}: {problem:?}");
    }
}

fn committed(request: &str) -> Option<[u8; 32]> {
    use bitcoin::hashes::Hash as _;
    let invoice: Bolt11Invoice = request.parse().unwrap();
    match invoice.description() {
        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(h) => Some(h.0.to_byte_array()),
        lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(_) => None,
    }
}

#[tokio::test]
async fn an_exact_invoice_asks_its_total_and_commits_to_its_description() {
    let net = Net::new().await;
    let features = net.info().await.features;
    assert!(features.iter().any(|f| f == licash_api::FEATURE_LNURL));
    let alice = net.wallet("alice");
    // 12.5 sat: 11 in notes, the 1 sat fee, and half a sat the hub's.
    let invoice = alice
        .invoice_exact(HUB, 12_500, None, Some([7; 32]))
        .await
        .unwrap();
    assert_eq!(invoice.amount, 11);
    let request = invoice.request.clone().unwrap();
    let parsed: Bolt11Invoice = request.parse().unwrap();
    assert_eq!(parsed.amount_milli_satoshis(), Some(12_500));
    assert_eq!(committed(&request), Some([7; 32]));
    assert_eq!(description(&request), None);
    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    let received = alice.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(received.state, InvoiceState::Received);
    assert_eq!(available(&alice), 11);
    // What the fee takes all of is refused before the hub hears of it.
    let refused_here = alice.invoice_exact(HUB, 1_999, None, None).await;
    assert!(matches!(
        refused_here,
        Err(licash_wallet::Error::Invalid(_))
    ));

    // Paid inside the hub, as a top-up from another wallet of it is.
    let bob = net.funded("bob", 40).await;
    let carol = net.wallet("carol");
    let invoice = carol
        .invoice_exact(HUB, 10_000, Some("Top up"), None)
        .await
        .unwrap();
    assert_eq!(invoice.amount, 9);
    let said = description(invoice.request.as_deref().unwrap());
    assert_eq!(said.as_deref(), Some("Top up"));
    let lock = bob
        .pay_invoice(HUB, invoice.request.as_deref().unwrap())
        .await
        .unwrap();
    assert_eq!(lock.amount, 10);
    let received = carol.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(received.state, InvoiceState::Received);
    assert_eq!(available(&carol), 9);

    // At the hub: a total outside what the notes and their fee ask, or a
    // description hash with a memo, is refused.
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    let body: String = db
        .query_row(
            "SELECT body FROM lightning_receipts WHERE hash = ?1",
            [bytes(&invoice.hash)],
            |r| r.get(0),
        )
        .unwrap();
    let body: licash_api::Receive = serde_json::from_str(&body).unwrap();
    assert_eq!(body.msat, Some(10_000));
    let mut other = body.clone().with_lnurl(None, None);
    other.hash = licash_api::Hex(vec![8; 32]);
    for msat in [9_999, 10_000 + licash_api::MAX_RECEIVE_SURPLUS + 1] {
        let bad = other.clone().with_lnurl(Some(msat), None);
        let problem = refused(&net, licash_api::LN_RECEIVE, &bad).await;
        assert!(problem.message.contains("msat"), "{msat}: {problem:?}");
    }
    let both = other
        .with_memo(Some("Rent".into()))
        .with_lnurl(None, Some([7; 32]));
    let problem = refused(&net, licash_api::LN_RECEIVE, &both).await;
    assert!(problem.message.contains("not both"), "{problem:?}");
}

#[tokio::test]
async fn a_memo_is_never_asked_of_a_hub_that_would_leave_it_out() {
    let net = Net::new().await;
    for names in [false, true] {
        let name = if names { "bob" } else { "carol" };
        let path = net.dir.path().join(format!("{name}.sqlite"));
        let local = Local(net.app.clone());
        let regtest = ChainProfile::Core30DefaultRegtest;
        let wallet = Wallet::create(
            &path,
            &[names as u8 + 1; 32],
            regtest,
            Memoless { local, names },
        );
        let wallet = wallet.unwrap();
        let asked = wallet.invoice_saying(HUB, 20, Some("Rent"), false).await;
        match names {
            // Asked of it nonetheless, it answers an invoice without:
            // never handed out.
            true => {
                let invoice = asked.unwrap();
                assert!(invoice.request.is_none(), "{invoice:?}");
                let reason = "its hub left the memo out of the invoice".to_owned();
                assert_eq!(invoice.state, InvoiceState::Canceled(reason));
            }
            false => {
                let refused = asked.unwrap_err().to_string();
                assert!(refused.contains("puts no memo"), "{refused}");
            }
        }
        // Without one, as before.
        assert!(wallet.invoice(HUB, 20).await.unwrap().request.is_some());
    }
}

#[tokio::test]
async fn an_invoice_paid_through_the_hub_settles_its_lock() {
    let net = Net::new().await;
    let wallet = net.funded("alice", 40).await;
    let preimage = [5; 32];
    let request = net
        .node
        .invoice(20_000, lock_hash(&preimage), 18, Outcome::Pay(preimage));
    let lock = wallet.pay_invoice(HUB, &request).await.unwrap();
    // The invoice and the gateway's fee.
    assert_eq!((lock.amount, lock.state.clone()), (22, LockState::Locked));
    assert_eq!(lock.invoice.as_deref(), Some(request.as_str()));
    let sent = net.node.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].cltv_limit, lock.expiry - net.height() - 4);
    assert_eq!(sent[0].fee_limit, 2);
    net.gateway.round().await;
    let lock = wallet.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
    assert_eq!(lock.failure, None);
    assert_eq!(available(&wallet), 18);
    // Asked again, the same; for another invoice, refused.
    let id = proposal_id(&lock.id);
    let paying: Paying = post(&net, licash_api::LN_PAY, &Pay::new(&id, &request)).await;
    assert_eq!(paying.state, PayState::Paid);
    assert_eq!(paying.preimage.unwrap().0, preimage.to_vec());
    let other = net.node.invoice(20_000, [9; 32], 18, Outcome::Hang);
    let problem = refused(&net, licash_api::LN_PAY, &Pay::new(&id, &other)).await;
    assert_eq!(problem.code, licash_api::Code::Forward);
    assert_eq!(net.node.sent().len(), 1);
}

#[tokio::test]
async fn an_invoice_is_read_and_what_paying_it_costs_said_before_paying() {
    let net = Net::with(Policy {
        spend: Fee { base: 1, ppm: 0 },
        timing: TIMING,
        ..Policy::default()
    });
    net.gateway.round().await;
    let wallet = net.funded("alice", 40).await;
    let preimage = [5; 32];
    let request = net
        .node
        .invoice(20_500, lock_hash(&preimage), 18, Outcome::Pay(preimage));
    // Bare, as a URI, or in a Bitcoin URI, any case.
    for text in [
        request.clone(),
        format!("lightning:{request}"),
        format!("LIGHTNING:{}", request.to_uppercase()),
        format!("bitcoin:bcrt1qexample?amount=0.00000021&lightning={request}"),
    ] {
        let payable = wallet.read_invoice(&text).unwrap();
        assert_eq!(payable.request, request, "{text}");
        assert_eq!((payable.amount, payable.description), (21, None));
        assert!(payable.expires_at > 0);
    }
    for text in ["bitcoin:bcrt1qexample?amount=1", "lnbcrt1nonsense", ""] {
        assert!(wallet.read_invoice(text).is_err(), "{text}");
    }
    // Not for a wallet of another network.
    let path = net.dir.path().join("signet.sqlite");
    let signet = Wallet::create(
        &path,
        &[7; 32],
        ChainProfile::Core30Signet,
        Local(net.app.clone()),
    )
    .unwrap();
    let refused = signet.read_invoice(&request).unwrap_err().to_string();
    assert!(refused.contains("another network"), "{refused}");
    // Read as it is, as for the history, by any wallet.
    let read = licash_wallet::Payable::read(&format!("lightning:{request}")).unwrap();
    assert_eq!(read, wallet.read_invoice(&request).unwrap());

    // The gateway's 2 on the 21 asked, and 1 to the hub: the lock of 23
    // needs exact notes, made by a payment to itself.
    assert_eq!(wallet.invoice_fee(HUB, &request).unwrap(), 3);
    let lock = wallet.pay_invoice(HUB, &request).await.unwrap();
    assert_eq!(lock.amount, 23);
    net.gateway.round().await;
    let lock = wallet.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
    assert_eq!(available(&wallet), 40 - 23 - 1);
    // The lock's own cost: the notes made for it exactly.
    assert_eq!(lock.cost, Some(23));
    // Exact notes held, 8: the gateway's fee alone.
    let exact = net.node.invoice(6_000, [4; 32], 18, Outcome::Hang);
    assert_eq!(wallet.invoice_fee(HUB, &exact).unwrap(), 2);
    // Too much for the wallet, then for the gateway.
    let more = net.node.invoice(30_000, [6; 32], 18, Outcome::Hang);
    assert!(matches!(
        wallet.invoice_fee(HUB, &more),
        Err(licash_wallet::Error::Insufficient { .. })
    ));
    let most = net.node.invoice(101_000, [8; 32], 18, Outcome::Hang);
    assert!(wallet.invoice_fee(HUB, &most).is_err());
    // A final delta longer than the hub's locks leave its gateway.
    let long = net.node.invoice(6_000, [3; 32], 40, Outcome::Hang);
    let refused = wallet.invoice_fee(HUB, &long).unwrap_err().to_string();
    assert!(refused.contains("final delta"), "{refused}");
}

/// The service, advertising a spend fee older than it charges until it
/// refuses an offer for its fee: a hub that raised it since.
#[derive(Clone)]
struct Raising {
    local: Local,
    advertised: Arc<Mutex<Option<Fee>>>,
}

impl Transport for Raising {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let (this, url) = (self.clone(), url.to_owned());
        async move {
            let mut response = this.local.request(&url, body).await?;
            let advertised = *this.advertised.lock().unwrap();
            if let (true, Some(fee)) = (url.ends_with(licash_api::INFO), advertised) {
                let mut info: Info = serde_json::from_slice(&response.body).unwrap();
                info.fees.spend = fee;
                response.body = serde_json::to_vec(&info).unwrap();
            }
            let refused = serde_json::from_slice::<Problem>(&response.body);
            if refused.is_ok_and(|p| p.code == licash_api::Code::Fee) {
                *this.advertised.lock().unwrap() = None;
            }
            Ok(response)
        }
    }
}

/// An invoice whose lock needs exact notes made first pays its hub's fee
/// on them only within the fee approved: a hub raising it after the quote
/// is paid nothing. Within it, the invoice is paid.
#[tokio::test]
async fn exact_notes_for_an_invoice_are_made_only_within_its_approved_fee() {
    let net = Net::with(Policy {
        spend: Fee { base: 3, ppm: 0 },
        timing: TIMING,
        ..Policy::default()
    });
    net.gateway.round().await;
    // Free to spend, it said when its fee was quoted.
    let advertised = Arc::new(Mutex::new(Some(Fee { base: 0, ppm: 0 })));
    let local = Local(net.app.clone());
    let path = net.dir.path().join("alice.sqlite");
    let raising = Raising {
        local,
        advertised: advertised.clone(),
    };
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(&path, &[1; 32], regtest, raising).unwrap();
    let invoice = wallet.invoice(HUB, 40).await.unwrap();
    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    let invoice = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(invoice.state, InvoiceState::Received);
    net.gateway.round().await;

    let preimage = [5; 32];
    let request = net
        .node
        .invoice(21_000, lock_hash(&preimage), 18, Outcome::Pay(preimage));
    // The gateway's 2, and nothing for the exact notes of 23, it says.
    assert_eq!(wallet.invoice_fee(HUB, &request).unwrap(), 2);
    let refused = wallet.pay_invoice_within(HUB, &request, Some(2)).await;
    match refused {
        Err(licash_wallet::Error::FeeRose { agreed, asked, .. }) => {
            assert_eq!((agreed, asked), (2, 5))
        }
        other => panic!("{other:?}"),
    }
    let held =
        |w: &Wallet<Raising>| -> u64 { w.balance().unwrap().iter().map(|b| b.available).sum() };
    assert_eq!(held(&wallet), 40, "nothing paid");
    assert!(wallet.locks().unwrap().is_empty());
    assert!(net.node.sent().is_empty());

    // Its fee learned, 5 in all: paid within it.
    assert_eq!(wallet.invoice_fee(HUB, &request).unwrap(), 5);
    let lock = wallet.pay_invoice_within(HUB, &request, Some(5)).await;
    let lock = lock.unwrap();
    assert_eq!(lock.amount, 23);
    net.gateway.round().await;
    let lock = wallet.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
    assert_eq!(held(&wallet), 40 - 23 - 3);
}

#[tokio::test]
async fn a_failed_payment_refunds_its_lock_at_once() {
    let net = Net::new().await;
    let wallet = net.funded("alice", 40).await;
    let reason = "FAILURE_REASON_NO_ROUTE".to_owned();
    let request = net.node.invoice(
        20_000,
        lock_hash(&[6; 32]),
        18,
        Outcome::Fail(reason.clone()),
    );
    let lock = wallet.pay_invoice(HUB, &request).await.unwrap();
    assert_eq!(lock.state, LockState::Locked);
    net.gateway.round().await;
    let lock = wallet.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert_eq!(lock.failure, Some(reason));
    assert_eq!(available(&wallet), 40);
}

#[tokio::test]
async fn an_invoice_of_a_receipt_at_the_same_hub_is_paid_inside_it() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    let (request, hash) = (invoice.request.clone().unwrap(), bytes(&invoice.hash));
    // The invoice's 11, its receipt fee in it, and no gateway fee.
    assert_eq!(alice.invoice_fee(HUB, &request).unwrap(), 0);
    let lock = alice.pay_invoice(HUB, &request).await.unwrap();
    assert_eq!((lock.amount, lock.state.clone()), (11, LockState::Locked));
    assert_eq!(lock.failure, None);
    // No HTLC backs the receipt any more: one arriving now is failed back.
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Canceled);
    assert!(!net.node.try_pay_held(hash, net.height() + 100));
    let status = net.gateway.receive_status(&hash).unwrap();
    assert_eq!(status.state, ReceiveState::Locked);

    let received = bob.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(received.state, InvoiceState::Received);
    assert_eq!(available(&bob), 10);
    net.gateway.round().await;
    assert_eq!(
        net.gateway.receive_status(&hash).unwrap().state,
        ReceiveState::Settled
    );
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    let preimage = preimage_of(&net, "bob", &invoice.hash);
    assert_eq!(lock.state, LockState::Paid(preimage));
    assert_eq!(available(&alice), 40 - 11);
    // Nothing went over Lightning, and no one was alerted.
    assert!(net.node.sent().is_empty());
    assert_eq!(alerts(&net.hub), 0);
    net.gateway.round().await;
    assert!(net.node.sent().is_empty());
}

#[tokio::test]
async fn an_invoice_paid_over_lightning_first_is_refused_for_a_lock() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    let hash = bytes(&invoice.hash);
    net.pay_held(&invoice.hash);
    let lock = alice
        .pay_invoice(HUB, invoice.request.as_deref().unwrap())
        .await
        .unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert!(lock.failure.unwrap().contains("paid or canceled"));
    assert_eq!(available(&alice), 40);
    // The HTLC backs the receipt, as ever.
    net.gateway.round().await;
    let received = bob.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(received.state, InvoiceState::Received);
    net.gateway.round().await;
    assert_eq!(net.node.held(hash).unwrap(), (HeldState::Settled, 11_000));
}

#[tokio::test]
async fn an_invoice_of_the_hubs_own_node_but_no_receipt_is_refused() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    // Another invoice of the receipt's hash, by the same node.
    let hash = bytes(&invoice.hash);
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    db.execute("DELETE FROM lightning_receipts WHERE hash = ?1", [hash])
        .unwrap();
    let lock = alice
        .pay_invoice(HUB, invoice.request.as_deref().unwrap())
        .await
        .unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert!(lock.failure.unwrap().contains("does not wait for"));
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Open);
    assert_eq!(available(&alice), 40);
}

#[tokio::test]
async fn a_receipt_is_paid_inside_the_hub_once_of_two_payers() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let carol = net.funded("carol", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    let request = invoice.request.clone().unwrap();
    let first = alice.pay_invoice(HUB, &request).await.unwrap();
    assert_eq!((first.state, first.failure), (LockState::Locked, None));
    let second = carol.pay_invoice(HUB, &request).await.unwrap();
    // Refused: its notes return once its lock expired.
    assert!(second.failure.is_some(), "{second:?}");
    bob.follow_invoice(&invoice.hash).await.unwrap();
    net.gateway.round().await;
    let first = alice.follow_lock(&first.id).await.unwrap();
    assert!(matches!(first.state, LockState::Paid(_)));
    assert_eq!(available(&bob), 10);
    let id = proposal_id(&second.id);
    assert!(!matches!(
        net.hub.forward_of(&id).unwrap().map(|f| f.state),
        Some(licash_hub::Forwarded::Paid(_) | licash_hub::Forwarded::Pending)
    ));
    assert_eq!(net.hub.locked(&id).unwrap().settled, None);
}

#[tokio::test]
async fn a_receipt_paid_inside_the_hub_and_unclaimed_refunds_its_payer() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    let hash = bytes(&invoice.hash);
    let lock = alice
        .pay_invoice(HUB, invoice.request.as_deref().unwrap())
        .await
        .unwrap();
    assert_eq!(lock.state, LockState::Locked);
    // The receipt's lock expired at depth, unclaimed.
    net.mine(6 + 1, None);
    net.gateway.round().await;
    assert_eq!(
        net.gateway.receive_status(&hash).unwrap().state,
        ReceiveState::Canceled
    );
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert_eq!(
        lock.failure.as_deref(),
        Some("the payee did not claim the payment")
    );
    assert_eq!(available(&alice), 40);
    let invoice = bob.follow_invoice(&invoice.hash).await.unwrap();
    assert!(matches!(invoice.state, InvoiceState::Canceled(_)));
    assert_eq!(available(&bob), 0);
    assert_eq!(alerts(&net.hub), 0);
}

#[tokio::test]
async fn a_lock_made_inside_the_hub_before_a_crash_is_taken_for_its_receipt() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    let hash = bytes(&invoice.hash);
    let lock = alice
        .pay_invoice(HUB, invoice.request.as_deref().unwrap())
        .await
        .unwrap();
    let locked = net.gateway.receive_status(&hash).unwrap().lock;
    assert!(locked.is_some());
    // As if the gateway stopped between locking and recording the lock.
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    db.execute(
        "UPDATE lightning_receipts SET state = 'open', lock = NULL WHERE hash = ?1",
        [hash],
    )
    .unwrap();
    net.gateway.round().await;
    let status = net.gateway.receive_status(&hash).unwrap();
    assert_eq!((status.state, status.lock), (ReceiveState::Locked, locked));
    bob.follow_invoice(&invoice.hash).await.unwrap();
    net.gateway.round().await;
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert!(matches!(lock.state, LockState::Paid(_)));
    assert_eq!(available(&bob), 10);
    assert!(net.node.sent().is_empty());
}

#[tokio::test]
async fn a_forward_inside_the_hub_short_of_its_receipt_backs_nothing() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    let (request, hash) = (invoice.request.clone().unwrap(), bytes(&invoice.hash));
    // A lock of 1 to the hub, recorded paying the receipt inside the hub,
    // as a refusal's first write once was.
    let address = net.info().await.address;
    let lock = alice.lock(HUB, &address, 1, hash, None).await.unwrap();
    let id = proposal_id(&lock.id);
    net.hub
        .forward(&id, &hash, &request, licash_hub::LOCAL, 0)
        .unwrap();
    net.gateway.round().await;
    let status = net.gateway.receive_status(&hash).unwrap();
    assert_eq!((status.state, status.lock), (ReceiveState::Open, None));
    assert!(net.hub.own_lock_of(&hash).unwrap().is_none());
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Open);
    let given_up = net.hub.forward_of(&id).unwrap().unwrap().state;
    assert!(matches!(given_up, licash_hub::Forwarded::Failed(_)));
    // The receipt still open, a lock paying its invoice in full backs it.
    let paying = alice.pay_invoice(HUB, &request).await.unwrap();
    assert_eq!((paying.state, paying.failure), (LockState::Locked, None));
    let paid = net.hub.forward_of(&proposal_id(&paying.id)).unwrap();
    assert_eq!(paid.unwrap().node, licash_hub::LOCAL);
    let status = net.gateway.receive_status(&hash).unwrap();
    assert_eq!(status.state, ReceiveState::Locked);
}

#[tokio::test]
async fn a_preimage_activated_after_the_receipts_lock_expired_pays_the_payer() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    let hash = bytes(&invoice.hash);
    let lock = alice
        .pay_invoice(HUB, invoice.request.as_deref().unwrap())
        .await
        .unwrap();
    assert_eq!(
        net.gateway.receive_status(&hash).unwrap().state,
        ReceiveState::Locked
    );
    // Activated at the receipt's lock's expiry: too late for it.
    net.mine(6, None);
    let preimage = preimage_of(&net, "bob", &invoice.hash);
    net.mine(1, Some(preimage));
    net.gateway.round().await;
    net.gateway.round().await;
    assert_eq!(
        net.gateway.receive_status(&hash).unwrap().state,
        ReceiveState::Canceled
    );
    let id = proposal_id(&lock.id);
    let resolved = net.hub.forward_of(&id).unwrap().unwrap().state;
    assert_eq!(resolved, licash_hub::Forwarded::Paid(preimage));
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
}

#[tokio::test]
async fn a_receipt_whose_payer_lock_is_settled_before_it_is_backed_is_canceled() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    let (request, hash) = (invoice.request.clone().unwrap(), bytes(&invoice.hash));
    net.node.down(true);
    let lock = alice.pay_invoice(HUB, &request).await.unwrap();
    let id = proposal_id(&lock.id);
    net.hub
        .forward(&id, &hash, &request, licash_hub::LOCAL, 11)
        .unwrap();
    // The payee settles the payer's lock itself, before its own is made.
    let preimage = preimage_of(&net, "bob", &invoice.hash);
    net.hub.settle(&id, &preimage).unwrap();
    net.mine(lock.expiry - net.height() - 9, None);
    net.node.down(false);
    net.gateway.round().await;
    assert_eq!(
        net.gateway.receive_status(&hash).unwrap().state,
        ReceiveState::Canceled
    );
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Canceled);
    assert!(net.hub.own_lock_of(&hash).unwrap().is_none());
    let paid = net.hub.forward_of(&id).unwrap().unwrap().state;
    assert_eq!(paid, licash_hub::Forwarded::Paid(preimage));
}

#[tokio::test]
async fn a_receipt_the_node_cannot_cancel_is_left_to_lightning_once_too_late() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let bob = net.wallet("bob");
    let invoice = bob.invoice(HUB, 10).await.unwrap();
    let (request, hash) = (invoice.request.clone().unwrap(), bytes(&invoice.hash));
    // The node is down: the lock waits for its payment.
    net.node.down(true);
    let lock = alice.pay_invoice(HUB, &request).await.unwrap();
    assert_eq!(
        (lock.state.clone(), lock.failure.clone()),
        (LockState::Locked, None)
    );
    // As if the gateway recorded the payment inside the hub, then stopped
    // before canceling the invoice.
    let id = proposal_id(&lock.id);
    net.hub
        .forward(&id, &hash, &request, licash_hub::LOCAL, 11)
        .unwrap();
    net.gateway.round().await;
    assert_eq!(
        net.gateway.receive_status(&hash).unwrap().state,
        ReceiveState::Open
    );
    // Too late for the receipt's lock to end before the payer's: given up.
    net.mine(lock.expiry - net.height() - 9, None);
    net.gateway.round().await;
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert_eq!(available(&alice), 40);
    // The invoice is still open, and paid over Lightning.
    net.node.down(false);
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Open);
    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    let received = bob.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(received.state, InvoiceState::Received);
    net.gateway.round().await;
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Settled);
}

#[tokio::test]
async fn a_payment_in_flight_holds_its_lock_past_expiry_until_resolved() {
    let net = Net::new().await;
    let wallet = net.funded("alice", 40).await;
    let preimage = [7; 32];
    let hash = lock_hash(&preimage);
    let request = net.node.invoice(20_000, hash, 18, Outcome::Hang);
    // The node is down: the lock waits, and is paid once asked again.
    net.node.down(true);
    let lock = wallet.pay_invoice(HUB, &request).await.unwrap();
    assert_eq!(
        (lock.state.clone(), lock.failure.clone()),
        (LockState::Locked, None)
    );
    assert!(net.node.sent().is_empty());
    net.node.down(false);
    wallet.follow_lock(&lock.id).await.unwrap();
    assert_eq!(net.node.sent().len(), 1);
    net.gateway.round().await;
    // Expired at depth, it is not refunded while the payment is in flight.
    net.mine(lock.expiry + 1 - net.height(), None);
    assert_eq!(alerts(&net.hub), 0);
    // An alert the hub cannot keep is told again the next round.
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER no_alert BEFORE INSERT ON events WHEN NEW.kind = 'alert'
         BEGIN SELECT RAISE(ABORT, 'full'); END;",
    )
    .unwrap();
    net.gateway.round().await;
    assert_eq!(alerts(&net.hub), 0);
    db.execute_batch("DROP TRIGGER no_alert").unwrap();
    net.gateway.round().await;
    net.gateway.round().await;
    assert_eq!(alerts(&net.hub), 1, "alerted once of a late payment");
    assert!(matches!(
        wallet.follow_lock(&lock.id).await,
        Err(licash_wallet::Error::Pending { .. })
    ));
    net.node.resolve(hash, Outcome::Pay(preimage));
    net.gateway.round().await;
    let lock = wallet.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
    assert_eq!(net.node.sent().len(), 1);
}

#[tokio::test]
async fn a_payment_the_node_lost_is_sent_again_or_given_up_once_too_late() {
    let net = Net::new().await;
    let wallet = net.funded("alice", 40).await;
    let hash = lock_hash(&[8; 32]);
    let request = net.node.invoice(20_000, hash, 18, Outcome::Hang);
    let lock = wallet.pay_invoice(HUB, &request).await.unwrap();
    let id = proposal_id(&lock.id);
    net.node.forget(hash);
    net.gateway.round().await;
    let sent = net.node.sent();
    assert_eq!(sent.len(), 2, "sent again while in time");
    assert_eq!(sent[1], sent[0]);
    // Too late to send: its route would outlast the lock.
    net.node.forget(hash);
    net.mine(lock.expiry - 24 - net.height(), None);
    net.gateway.round().await;
    assert_eq!(net.node.sent().len(), 2);
    let pending = net.hub.forward_of(&id).unwrap().unwrap().state;
    assert_eq!(
        pending,
        licash_hub::Forwarded::Pending,
        "one miss is not enough"
    );
    net.gateway.round().await;
    let lock = wallet.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert_eq!(lock.failure.as_deref(), Some("not started in time"));
}

#[tokio::test]
async fn a_refusal_left_pending_by_an_earlier_hub_is_never_paid() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let hash = lock_hash(&[8; 32]);
    let request = net.node.invoice(20_000, hash, 18, Outcome::Hang);
    // A lock of 1 for an invoice of 20, recorded pending as a refusal's
    // first write once was, the gateway stopped before the second.
    let address = net.info().await.address;
    let lock = alice.lock(HUB, &address, 1, hash, None).await.unwrap();
    let id = proposal_id(&lock.id);
    let node = net.node.pubkey();
    net.hub.forward(&id, &hash, &request, &node, 0).unwrap();
    net.gateway.round().await;
    assert!(net.node.sent().is_empty());
    net.gateway.round().await;
    assert!(net.node.sent().is_empty());
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert_eq!(
        net.hub.forward_of(&id).unwrap().unwrap().state,
        licash_hub::Forwarded::Failed("not started in time".into())
    );
}

#[tokio::test]
async fn an_invoice_refused_for_a_lock_refunds_it_at_once_and_is_never_paid() {
    let net = Net::new().await;
    let alice = net.funded("alice", 40).await;
    let hash = lock_hash(&[8; 32]);
    let request = net.node.invoice(20_000, hash, 18, Outcome::Hang);
    let address = net.info().await.address;
    let lock = alice.lock(HUB, &address, 1, hash, None).await.unwrap();
    let id = proposal_id(&lock.id);
    let paying: Paying = post(&net, licash_api::LN_PAY, &Pay::new(&id, &request)).await;
    assert_eq!(paying.state, PayState::Failed);
    assert!(net.hub.forwards().unwrap().is_empty());
    net.gateway.round().await;
    assert!(net.node.sent().is_empty());
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert_eq!(available(&alice), 40);
}

#[tokio::test]
async fn htlcs_expiring_too_soon_cancel_the_invoice() {
    let net = Net::new().await;
    let wallet = net.wallet("alice");
    let invoice = wallet.invoice(HUB, 20).await.unwrap();
    let hash = bytes(&invoice.hash);
    // The lock would outlast them, with its depth, downtime and hold delta.
    net.node.pay_held(hash, net.height() + 6 + 1 + 2 + 3);
    net.gateway.round().await;
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Canceled);
    let invoice = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert!(matches!(invoice.state, InvoiceState::Canceled(_)));
    assert_eq!(available(&wallet), 0);
}

/// The expiry of the lock paying the invoice of `hash`.
fn expiry_of(net: &Net, hash: &str) -> u32 {
    let status = net.gateway.receive_status(&bytes(hash)).unwrap();
    let id = status.lock().unwrap().unwrap();
    let lock = net.hub.locked(&id).unwrap();
    lock.proposal.lock().unwrap().terms().expiry()
}

#[tokio::test]
async fn a_protected_invoice_lets_a_lock_shown_late_expire_where_a_trusting_one_claims() {
    use licash_wallet::PROTECTED_MARGIN;
    let net = Net::new().await;
    let alice = net.wallet("alice");
    // Protected only against a height the wallet knows of itself.
    assert!(matches!(
        alice.invoice_protected(HUB, 20).await,
        Err(licash_wallet::Error::Chain(_))
    ));
    assert!(alice.invoices().unwrap().is_empty());
    alice.saw_tip(net.height());
    // Shown in time: claimed as any.
    let invoice = alice.invoice_protected(HUB, 20).await.unwrap();
    assert!(invoice.protected);
    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    let received = alice.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(received.state, InvoiceState::Received);
    assert_eq!(available(&alice), 20);

    // A lock shown with fewer blocks left than an activation needs: its
    // preimage kept, the lock left to expire and the payment to fail back,
    // where an invoice trusting the hub still claims.
    let late = alice.invoice_protected(HUB, 20).await.unwrap();
    let trusted = alice.invoice(HUB, 20).await.unwrap();
    assert!(!trusted.protected);
    net.pay_held(&late.hash);
    net.pay_held(&trusted.hash);
    net.gateway.round().await;
    let expiry = expiry_of(&net, &late.hash);
    assert_eq!(expiry_of(&net, &trusted.hash), expiry);
    net.mine(expiry - PROTECTED_MARGIN + 1 - net.height(), None);
    let refused = alice.follow_invoice(&late.hash).await.unwrap();
    assert!(
        matches!(&refused.state, InvoiceState::Canceled(r) if r.contains("too late")),
        "{refused:?}"
    );
    let id = proposal_id(refused.lock.as_ref().unwrap());
    let lock = net.hub.locked(&id).unwrap();
    assert_eq!((lock.preimage, lock.settled), (None, None));
    let claimed = alice.follow_invoice(&trusted.hash).await.unwrap();
    assert_eq!(claimed.state, InvoiceState::Received);
    assert_eq!(available(&alice), 40);
    // Expired at depth: refunded, the payment failed back.
    net.mine(PROTECTED_MARGIN + 1, None);
    net.gateway.round().await;
    assert_eq!(
        net.node.held(bytes(&late.hash)).unwrap().0,
        HeldState::Canceled
    );
    let listed = alice.invoices().unwrap();
    assert!(listed.iter().any(|i| i.hash == late.hash && i.protected));
}

/// A hub's word for the chain's height protects nothing from that hub: a
/// wallet that knows the chain further on than its hub says keeps a
/// protected lock's preimage, and one that does not know the chain of
/// itself keeps it until it does.
#[tokio::test]
async fn a_protected_invoice_is_claimed_only_at_a_height_the_wallet_knows_of_itself() {
    use licash_wallet::PROTECTED_MARGIN;
    let net = Net::new().await;
    let path = net.dir.path().join("alice.sqlite");
    let alice = net.wallet("alice");
    alice.saw_tip(net.height());
    let (late, kept) = (
        alice.invoice_protected(HUB, 20).await.unwrap(),
        alice.invoice_protected(HUB, 20).await.unwrap(),
    );
    net.pay_held(&late.hash);
    net.pay_held(&kept.hash);
    net.gateway.round().await;
    // Whether her hub was never told the preimage of the invoice's lock.
    let unrevealed = |alice: &Wallet<Local>, hash: &str| {
        let invoice = alice.invoices().unwrap();
        let invoice = invoice.iter().find(|i| i.hash == hash).unwrap();
        let lock = net.hub.locked(&proposal_id(invoice.lock.as_ref().unwrap()));
        lock.unwrap().preimage.is_none()
    };
    // The chain as her own source shows it, inside the margin: her hub,
    // which says it is not, is not believed.
    let expiry = expiry_of(&net, &late.hash);
    assert!(net.height() + PROTECTED_MARGIN <= expiry);
    alice.saw_tip(expiry - PROTECTED_MARGIN + 1);
    let refused = alice.follow_invoice(&late.hash).await.unwrap();
    assert!(
        matches!(&refused.state, InvoiceState::Canceled(r) if r.contains("too late")),
        "{refused:?}"
    );
    assert!(unrevealed(&alice, &late.hash));
    drop(alice);

    // Opened again, told nothing of the chain yet: the payment waits.
    let alice = Wallet::open(&path, Local(net.app.clone())).unwrap();
    let waiting = alice.follow_invoice(&kept.hash).await;
    assert!(
        matches!(&waiting, Err(licash_wallet::Error::Pending { reason, .. }) if reason.contains("height")),
        "{waiting:?}"
    );
    assert!(unrevealed(&alice, &kept.hash));
    alice.saw_tip(net.height());
    let received = alice.follow_invoice(&kept.hash).await.unwrap();
    assert_eq!(received.state, InvoiceState::Received);
    assert_eq!(available(&alice), 20);
}

#[tokio::test]
async fn a_lock_unclaimed_is_refunded_and_cancels_its_invoice() {
    let net = Net::new().await;
    let wallet = net.wallet("alice");
    let invoice = wallet.invoice(HUB, 20).await.unwrap();
    let hash = bytes(&invoice.hash);
    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    assert_eq!(
        net.gateway.receive_status(&hash).unwrap().state,
        ReceiveState::Locked
    );
    // Expired at depth.
    net.mine(6 + 1, None);
    net.gateway.round().await;
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Canceled);
    assert_eq!(
        net.gateway.receive_status(&hash).unwrap().state,
        ReceiveState::Canceled
    );
    let invoice = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert!(matches!(invoice.state, InvoiceState::Canceled(_)));
    assert_eq!(available(&wallet), 0);
}

#[tokio::test]
async fn a_preimage_activated_on_bitcoin_settles_the_invoice() {
    let net = Net::new().await;
    let wallet = net.wallet("alice");
    let invoice = wallet.invoice(HUB, 20).await.unwrap();
    let hash = bytes(&invoice.hash);
    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    net.mine(1, Some(preimage_of(&net, "alice", &invoice.hash)));
    net.gateway.round().await;
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Settled);
    let invoice = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(invoice.state, InvoiceState::Received);
    assert_eq!(available(&wallet), 20);
}

#[tokio::test]
async fn a_lock_made_before_a_crash_is_taken_for_its_receipt() {
    let net = Net::new().await;
    let wallet = net.wallet("alice");
    let invoice = wallet.invoice(HUB, 20).await.unwrap();
    let hash = bytes(&invoice.hash);
    net.pay_held(&invoice.hash);
    net.gateway.round().await;
    let locked = net.gateway.receive_status(&hash).unwrap().lock;
    // As if the gateway stopped between locking and recording the lock.
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    let reset = db
        .execute(
            "UPDATE lightning_receipts SET state = 'open', lock = NULL WHERE hash = ?1",
            [hash],
        )
        .unwrap();
    assert_eq!(reset, 1);
    net.gateway.round().await;
    let status = net.gateway.receive_status(&hash).unwrap();
    assert_eq!((status.state, status.lock), (ReceiveState::Locked, locked));
    let invoice = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(invoice.state, InvoiceState::Received);
    net.gateway.round().await;
    assert_eq!(net.node.held(hash).unwrap().0, HeldState::Settled);
}

#[tokio::test]
async fn an_invoice_asked_to_be_paid_again_is_paid_by_its_one_lock() {
    let net = Net::new().await;
    let wallet = net.funded("alice", 100).await;
    let preimage = [12; 32];
    let request = net
        .node
        .invoice(20_000, lock_hash(&preimage), 18, Outcome::Hang);
    let first = wallet.pay_invoice(HUB, &request).await.unwrap();
    // Asked again while it is under way, alone or twice at once: the same
    // lock, as one preimage settles every lock of its hash.
    let again = wallet.pay_invoice(HUB, &request).await.unwrap();
    assert_eq!(again.id, first.id);
    let (a, b) = tokio::join!(
        wallet.pay_invoice(HUB, &request),
        wallet.pay_invoice(HUB, &request)
    );
    for paid in [a, b] {
        assert_eq!(paid.unwrap().id, first.id);
    }
    let hash = lock_hash(&preimage);
    let locks = wallet.locks().unwrap();
    assert_eq!(locks.iter().filter(|l| l.hash == hash).count(), 1);
    assert_eq!(available(&wallet), 100 - 22);
    // Paid, asked again: the same, paid.
    net.node.resolve(hash, Outcome::Pay(preimage));
    net.gateway.round().await;
    let paid = wallet.pay_invoice(HUB, &request).await.unwrap();
    assert_eq!((paid.id, paid.state), (first.id, LockState::Paid(preimage)));
    assert_eq!(net.node.sent().len(), 1);
}

#[tokio::test]
async fn a_failure_of_an_earlier_payment_of_its_hash_is_not_the_forwards() {
    let net = Net::new().await;
    let wallet = net.funded("alice", 60).await;
    let preimage = [10; 32];
    let hash = lock_hash(&preimage);
    let failing = net.node.invoice(
        20_000,
        hash,
        18,
        Outcome::Fail("FAILURE_REASON_TIMEOUT".into()),
    );
    let first = wallet.pay_invoice(HUB, &failing).await.unwrap();
    net.gateway.round().await;
    let first = wallet.follow_lock(&first.id).await.unwrap();
    assert_eq!(first.state, LockState::Refunded);
    // The node keeps that failed attempt; a later payment of the hash
    // starts its own.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let paying = net.node.invoice(21_000, hash, 18, Outcome::Pay(preimage));
    let second = wallet.pay_invoice(HUB, &paying).await.unwrap();
    assert_eq!(second.state, LockState::Locked);
    assert_eq!(net.node.sent().len(), 2);
    net.gateway.round().await;
    let second = wallet.follow_lock(&second.id).await.unwrap();
    assert_eq!(second.state, LockState::Paid(preimage));
}

#[tokio::test]
async fn the_operator_is_alerted_once_of_each_way_the_node_moves_too_little() {
    let net = Net::new().await;
    let said = || -> Vec<String> {
        let events = net.hub.events(0, 1000).unwrap();
        let notices = events.iter().filter_map(|e| e.notice());
        notices
            .filter_map(|n| match n {
                licash_hub::Notice::Alert { message } => Some(message),
                _ => None,
            })
            .collect()
    };
    assert!(said().is_empty());
    // config() takes invoices and receipts of up to 100 sat.
    net.node.channels(99, 100);
    net.gateway.round().await;
    net.gateway.round().await;
    let alerts = said();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].contains("can pay 99 sat"), "{}", alerts[0]);
    assert!(alerts[0].contains("--ln-max-pay"), "{}", alerts[0]);

    net.node.channels(100, 0);
    net.gateway.round().await;
    net.node.channels(50, 0);
    net.gateway.round().await;
    let alerts = said();
    assert_eq!(alerts.len(), 3, "{alerts:?}");
    assert!(alerts[1].contains("can receive 0 sat"), "{}", alerts[1]);
    assert!(alerts[2].contains("can pay 50 sat"), "{}", alerts[2]);

    // Unread channels say nothing.
    net.node.down(true);
    net.gateway.round().await;
    assert_eq!(said().len(), 3);
}

/// The value of the facts of `series` under `label`, in `report`.
fn summed(report: &licash_dashboard::Report, series: &str, label: &str) -> (usize, i64) {
    let series = report.series.iter().find(|s| s.id == series).unwrap();
    let Some(label) = series.labels.iter().position(|l| l == label) else {
        return (0, 0);
    };
    let facts = series.facts.iter().filter(|f| f.label as usize == label);
    facts.fold((0, 0), |(n, sum), f| (n + 1, sum + f.value))
}

#[tokio::test]
async fn the_dashboard_reads_payments_fees_failures_and_notes_from_the_records() {
    let net = Net::with(Policy {
        spend: Fee { base: 1, ppm: 0 },
        timing: TIMING,
        ..Policy::default()
    });
    net.gateway.round().await;
    // In: 40 sat, of an invoice of 41.
    let wallet = net.funded("alice", 40).await;
    // Out: 20 sat, in a lock of 22 with the gateway's fee, of notes made
    // exact by a transfer to itself, paying the hub 1.
    let preimage = [5; 32];
    let paid = net
        .node
        .invoice(20_000, lock_hash(&preimage), 18, Outcome::Pay(preimage));
    let lock = wallet.pay_invoice(HUB, &paid).await.unwrap();
    net.gateway.round().await;
    let lock = wallet.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
    // Failed: refunded.
    let reason = "FAILURE_REASON_NO_ROUTE".to_owned();
    let failed = net
        .node
        .invoice(10_000, lock_hash(&[6; 32]), 18, Outcome::Fail(reason));
    let lock = wallet.pay_invoice(HUB, &failed).await.unwrap();
    net.gateway.round().await;
    let failed = wallet.follow_lock(&lock.id).await.unwrap();
    assert_eq!(failed.state, LockState::Refunded);

    let report = licash_hub_service::dashboard::report(net.dir.path(), None).unwrap();
    assert_eq!(summed(&report, "volume", "lightning in"), (1, 41));
    assert_eq!(summed(&report, "fees", "lightning in"), (1, 1));
    assert_eq!(summed(&report, "volume", "lightning out"), (1, 22));
    assert_eq!(summed(&report, "fees", "lightning out"), (1, 2));
    let (transfers, fees) = summed(&report, "fees", "transfers");
    assert!(
        transfers >= 1 && fees == transfers as i64,
        "{transfers} {fees}"
    );
    assert_eq!(
        summed(&report, "failures", "no route"),
        (1, failed.amount as i64)
    );
    // A lock paying out is no plain lock, settled or refunded.
    assert_eq!(summed(&report, "volume", "locks"), (0, 0));
    assert_eq!(summed(&report, "failures", "lock refunded"), (0, 0));
    // Every note the hub issued since its ledger began: the 40 paid in,
    // the wallet's and the hub's fees and payments out, none behind a lock.
    let (_, holders) = summed(&report, "ecash", "holders");
    let (_, own) = summed(&report, "ecash", "hub's own");
    assert_eq!(summed(&report, "ecash", "behind locks").1, 0);
    assert_eq!(holders, available(&wallet) as i64);
    assert_eq!(holders + own, 40);
    let notes = report.series.iter().find(|s| s.id == "notes").unwrap();
    assert!(notes.facts.iter().map(|f| f.value).sum::<i64>() > 0);
    let pages: Vec<_> = report.pages.iter().map(|p| p.title.as_str()).collect();
    assert_eq!(
        pages,
        [
            "Overview",
            "Payments",
            "Fees",
            "Reserves",
            "Contracts",
            "Privacy",
            "Health"
        ]
    );
    assert!(report.since <= report.now && report.now - report.since < 600);

    // Below the overview, what happened, newest first: each payment out
    // as its forward ended, never again as its lock settling.
    use licash_dashboard::{Cell, Panel};
    let Some([Panel::Table(recent)]) = report.pages[0].rows.last().map(|r| &r[..]) else {
        panic!("no recent events below the overview");
    };
    assert_eq!(recent.title, "Recent events");
    let text = |c: &Cell| match c {
        Cell::Text(s) => s.clone(),
        Cell::Sat(v) => v.to_string(),
        _ => String::new(),
    };
    let said: Vec<[String; 4]> = recent
        .rows
        .iter()
        .map(|r| [&r.cells[1], &r.cells[2], &r.cells[3], &r.cells[4]].map(text))
        .collect();
    let has = |kind: &str, event: &str| said.iter().any(|s| s[0] == kind && s[1] == event);
    let out = |event: &'static str| {
        let said = said.iter();
        said.filter(move |s| s[0] == "lightning out" && s[1] == event)
    };
    assert_eq!(out("locked").count(), 2, "{said:?}");
    assert_eq!(out("paid").map(|s| &s[2]).collect::<Vec<_>>(), ["22"]);
    let failures: Vec<_> = out("failed").collect();
    assert_eq!(failures.len(), 1, "{said:?}");
    assert_eq!(failures[0][2], failed.amount.to_string());
    assert_eq!(failures[0][3], "no route");
    assert!(!has("lightning out", "settled") && !has("lightning out", "refunded"));
    assert!(has("lightning in", "asked") && has("lightning in", "settled"));
    assert!(
        has("transfer", "released") && has("hub", "started"),
        "{said:?}"
    );
    let at: Vec<_> = recent.rows.iter().map(|r| r.at.unwrap()).collect();
    assert!(at.is_sorted_by(|a, b| a >= b), "{at:?}");
}

/// A payment of `amount` to `to`, its fee paid, from notes made with the
/// hub's seed outside its ledger: as whoever else held the seed would.
fn forged(net: &Net, to: &licash::address::Address, amount: u64) -> licash_api::Payment {
    use licash::address::{Ephemeral, OwnerKeys};
    use licash::authorization::{Authorization, SignedProposal};
    use licash::claim::Branch;
    use licash::note::{Evidence, IssuerKeys, Note};
    use licash::spend::{Output, Proposal};
    use licash::unlink::Nonce;

    let split = |mut amount: u64| {
        let mut denoms = Vec::new();
        while amount > 0 {
            let d = 1u64 << (63 - amount.leading_zeros());
            denoms.push(d);
            amount -= d;
        }
        denoms
    };
    let text = std::fs::read_to_string(net.dir.path().join("seed")).unwrap();
    let mut seed = [0; 32];
    hex::decode_to_slice(text.trim(), &mut seed).unwrap();
    let keys = IssuerKeys::from_seed(&seed, 0, MAX_POW).unwrap();
    let keyset = keys.keyset().unwrap();
    let info = net.hub.info();
    let mut total = amount;
    while amount + info.policy.spend.due(total) != total {
        total = amount + info.policy.spend.due(total);
    }
    let payer = OwnerKeys::from_seed(&[0xfa; 32]).unwrap();
    let mut inputs = Vec::new();
    for denom in split(total) {
        let d = Ephemeral::random()
            .derive(&payer.address(), denom, Branch::Pay, 0)
            .unwrap();
        let output = Output::from_derivation(&d).unwrap();
        let proof = keys.prove_blinded(denom, output.blinded()).unwrap();
        let note = Note::from_parts(
            &keyset,
            *keyset.id(),
            d.message().clone(),
            proof.open_point(&keyset, &d).unwrap(),
            Evidence::Linked {
                dleq: proof.dleq(),
                blinding: *d.blinding(),
                commit: Nonce::new(&keyset, &output).unwrap().commit().unwrap(),
            },
        )
        .unwrap();
        inputs.push((note, d));
    }
    let notes: Vec<Note> = inputs.iter().map(|(note, _)| note.clone()).collect();
    let ephemeral = Ephemeral::random();
    let to_hub = split(total - amount)
        .into_iter()
        .map(|d| (d, &info.address));
    let outputs = split(amount)
        .into_iter()
        .map(|d| (d, to))
        .chain(to_hub)
        .enumerate()
        .map(|(i, (d, to))| {
            Output::from_derivation(&ephemeral.derive(to, d, Branch::Pay, i).unwrap()).unwrap()
        })
        .collect();
    let proposal = Proposal::new(&keyset, &notes, ephemeral.public(), outputs, None).unwrap();
    let grant = net.hub.offer(&proposal, &notes).unwrap();
    let owners: Vec<_> = inputs
        .iter()
        .map(|(_, d)| d.ownership().owner_secret(payer.spend_secret()).unwrap())
        .collect();
    let signed = SignedProposal::sign(
        &keyset,
        proposal,
        &notes,
        Authorization::Granted(Box::new(grant)),
        &owners,
    )
    .unwrap();
    let unlock = net.hub.release(&signed, &notes).unwrap();
    licash_api::Payment::new(HUB, &signed, &notes, &unlock)
}

/// Notes made with the hub's seed outside its ledger, paid out over
/// Lightning, pause the gateway's payments out once the ledger retired
/// more than it issued: invoices are refused, their locks refunded, and
/// wallets told it pays none, until the operator resumes them. What the
/// ledger issued itself, paid in, paid out and refunded, pauses nothing.
#[tokio::test]
async fn notes_the_ledger_never_issued_pause_payments_out_until_resumed() {
    use licash_hub_service::payouts::{self, Guard};

    let net = Net::new().await;
    let guard = Guard::open(net.dir.path());
    net.gateway.guard_with(guard.clone());
    let excess = || {
        let ledger = licash_hub::Ledger::open(&net.dir.path().join("hub.sqlite")).unwrap();
        ledger.notes().unwrap().excess()
    };
    let invoice = |sat: u64, n: u8, outcome: fn([u8; 32]) -> Outcome| {
        let preimage = [n; 32];
        let request = net
            .node
            .invoice(sat * 1000, lock_hash(&preimage), 18, outcome(preimage));
        (request, preimage)
    };
    let fail = |_| Outcome::Fail("FAILURE_REASON_NO_ROUTE".to_owned());

    // Paid in, paid out and refunded, of notes the ledger issued.
    let alice = net.funded("alice", 40).await;
    let (request, preimage) = invoice(10, 1, Outcome::Pay);
    let lock = alice.pay_invoice(HUB, &request).await.unwrap();
    net.gateway.round().await;
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
    let (request, _) = invoice(10, 2, fail);
    let lock = alice.pay_invoice(HUB, &request).await.unwrap();
    net.gateway.round().await;
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert_eq!(excess(), []);
    assert_eq!(guard.check(), Vec::<String>::new());
    assert!(!guard.paused());
    assert_eq!(net.info().await.lightning.unwrap().max_pay, 100);

    // Mallory's 60, of notes the ledger never issued, paid out 18 at a
    // time: more than Alice holds, so more than the ledger issued.
    let mallory = net.wallet("mallory");
    mallory.add_hub(HUB).await.unwrap();
    mallory
        .receive(&forged(&net, &mallory.address(), 60))
        .unwrap();
    let mut alerts = Vec::new();
    let mut paid = 0;
    for n in 3..6 {
        let (request, preimage) = invoice(18, n, Outcome::Pay);
        let lock = mallory.pay_invoice(HUB, &request).await.unwrap();
        net.gateway.round().await;
        let lock = mallory.follow_lock(&lock.id).await.unwrap();
        assert_eq!(lock.state, LockState::Paid(preimage));
        paid += 1;
        alerts = guard.check();
        if !alerts.is_empty() {
            break;
        }
    }
    assert!(
        alerts.len() == 1 && alerts[0].contains("payments out are paused"),
        "{paid} paid: {alerts:?}"
    );
    assert!(guard.paused() && !excess().is_empty());
    // Told once, and kept across a restart.
    assert_eq!(guard.check(), Vec::<String>::new());
    assert!(Guard::open(net.dir.path()).paused());

    // Wallets are told it pays none; a lock made anyway is refunded.
    assert_eq!(net.info().await.lightning.unwrap().max_pay, 0);
    let (request, _) = invoice(10, 7, Outcome::Pay);
    assert!(alice.pay_invoice(HUB, &request).await.is_err());
    let before = available(&alice);
    let sent = net.node.sent().len();
    let address = net.info().await.address;
    let hash = *request
        .parse::<Bolt11Invoice>()
        .unwrap()
        .payment_hash()
        .as_ref();
    let lock = alice.lock(HUB, &address, 12, hash, None).await.unwrap();
    let id = proposal_id(&lock.id);
    let paying: Paying = post(&net, licash_api::LN_PAY, &Pay::new(&id, &request)).await;
    assert_eq!(paying.state, PayState::Failed);
    assert_eq!(
        net.hub.forward_of(&id).unwrap().unwrap().state,
        licash_hub::Forwarded::Failed("the gateway's payments out are paused".into())
    );
    net.gateway.round().await;
    assert_eq!(net.node.sent().len(), sent);
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert_eq!(available(&alice), before);
    // Receipts are taken as ever.
    net.funded("bob", 10).await;

    // Resumed by the operator, beside the running hub: at its next look.
    let (was, now) = payouts::resume(net.dir.path()).unwrap();
    assert!(was.unwrap().contains("never issued"));
    assert_eq!((now.baseline, now.paused), (excess(), None));
    assert!(guard.paused());
    assert_eq!(guard.check(), Vec::<String>::new());
    assert!(!guard.paused());
    assert_eq!(net.info().await.lightning.unwrap().max_pay, 100);
    let (request, preimage) = invoice(10, 8, Outcome::Pay);
    let lock = alice.pay_invoice(HUB, &request).await.unwrap();
    net.gateway.round().await;
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
}

/// Past what the gateway may pay out in a day, invoices are refused and
/// their locks refunded, the operator alerted once: what was paid or is
/// under way counts, the gateway's fee in it, not what failed or was paid
/// inside the hub.
#[tokio::test]
async fn invoices_past_the_most_paid_in_a_day_are_refused_and_refunded() {
    let policy = Policy {
        timing: TIMING,
        ..Policy::default()
    };
    let config = Config {
        max_pay_day: Some(50),
        ..config()
    };
    let net = Net::configured(policy, config);
    net.gateway.round().await;
    let alice = net.funded("alice", 90).await;
    let since = || net.hub.forwarded_since(0).unwrap();
    let invoice = |sat: u64, n: u8, outcome: Outcome| {
        net.node
            .invoice(sat * 1000, lock_hash(&[n; 32]), 18, outcome)
    };

    // Failed, and paid inside the hub: neither counts.
    let request = invoice(18, 1, Outcome::Fail("FAILURE_REASON_NO_ROUTE".into()));
    let lock = alice.pay_invoice(HUB, &request).await.unwrap();
    net.gateway.round().await;
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    let bob = net.wallet("bob");
    let inside = bob.invoice(HUB, 10).await.unwrap();
    let lock = alice
        .pay_invoice(HUB, inside.request.as_ref().unwrap())
        .await
        .unwrap();
    assert_eq!(lock.state, LockState::Locked);
    assert_eq!(since(), 0);

    // Paid, and under way: 20 each, of an invoice of 18 and the fee.
    let lock = alice
        .pay_invoice(HUB, &invoice(18, 2, Outcome::Pay([2; 32])))
        .await
        .unwrap();
    net.gateway.round().await;
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid([2; 32]));
    let hung = alice
        .pay_invoice(HUB, &invoice(18, 3, Outcome::Hang))
        .await
        .unwrap();
    assert_eq!(hung.state, LockState::Locked);
    assert_eq!(since(), 40);
    assert_eq!(net.hub.forwarded_since(i64::MAX).unwrap(), 0);
    assert_eq!(alerts(&net.hub), 0);

    // 20 more would be 60: refused, refunded, the node never asked.
    let sent = net.node.sent().len();
    let before = available(&alice);
    for n in [4, 5] {
        let lock = alice
            .pay_invoice(HUB, &invoice(18, n, Outcome::Pay([n; 32])))
            .await
            .unwrap();
        net.gateway.round().await;
        let lock = alice.follow_lock(&lock.id).await.unwrap();
        assert_eq!(lock.state, LockState::Refunded);
        assert_eq!(
            lock.failure.as_deref(),
            Some("above the most the gateway pays in a day")
        );
    }
    assert_eq!(net.node.sent().len(), sent);
    assert_eq!((available(&alice), since()), (before, 40));
    // Told once.
    assert_eq!(alerts(&net.hub), 1);
    let events = net.hub.events(0, 1000).unwrap();
    let alert = events.iter().rfind(|e| e.kind == "alert").unwrap();
    let told = alert.data.to_string();
    assert!(told.contains("--ln-max-pay-day 50"), "{told}");

    // 10 more are exactly 50: paid.
    let lock = alice
        .pay_invoice(HUB, &invoice(8, 6, Outcome::Pay([6; 32])))
        .await
        .unwrap();
    net.gateway.round().await;
    let lock = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid([6; 32]));
    assert_eq!(since(), 50);
}
