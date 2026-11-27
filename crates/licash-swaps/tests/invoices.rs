//! Lightning invoices paid through a provider in process, for its clients'
//! locks at hub A, from an in-memory Lightning node.

#[allow(dead_code)]
#[path = "../../licash-wallet/tests/net/mod.rs"]
mod net;

use std::sync::Arc;

use licash::spend::{lock_hash, ChainProfile, ProposalId};
use licash_api::{
    swaps::{self, LightningRequest, State},
    Code, Fee,
};
use licash_hub::Timing;
use licash_lightning::{
    fake::{Fake, Outcome},
    Node,
};
use licash_swaps::{Config, Notice, Provider, Stage, MIN_SLACK};
use licash_wallet::{Error, Lock, LockState, Response, Transport, Wallet, ROUTE_BLOCKS};
use net::{Link, Net, TIMING};

const A: &str = "http://a.test";
const PROVIDER: &str = "http://swaps.test";
const FEE: Fee = Fee { base: 1, ppm: 0 };
/// Locks of up to 141 blocks: room for an invoice's routes and the slack.
const TIMED: Timing = Timing {
    window: 144,
    ..TIMING
};
const CONFIG: Config = Config {
    fee: Fee { base: 1, ppm: 0 },
    min: 5,
    max: 150,
    margin: 6,
    confirm: 4,
};
/// The invoices' final CLTV delta.
const DELTA: u64 = 18;
/// What the client holds at A to start with.
const HELD: u64 = 3_000;

fn terms(node: &Fake) -> swaps::Lightning {
    swaps::Lightning {
        node: node.pubkey(),
        fee: Fee {
            base: 2,
            ppm: 10_000,
        },
        max: 2_000,
        slack: 24,
    }
}

struct Eco {
    net: Arc<Net>,
    dir: tempfile::TempDir,
    node: Arc<Fake>,
    provider: Option<Provider<Link>>,
    client: Wallet<Link>,
}

impl Eco {
    /// Hub A, a provider paying invoices through its node, and a client
    /// holding 3,000 at A.
    async fn new() -> Self {
        let net = Net::new();
        net.start_timed(A, FEE, TIMED);
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[0x50; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        wallet.add_hub(A).await.unwrap();
        let node = Arc::new(Fake::new());
        let provider = Provider::create(wallet, CONFIG)
            .unwrap()
            .pay_lightning(node.clone(), terms(&node))
            .unwrap();
        let client = Wallet::create(
            &dir.path().join("client.sqlite"),
            &[0xc1; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        client.add_hub(A).await.unwrap();
        client
            .receive(&net.pay(A, &client.address(), HELD))
            .unwrap();
        let eco = Self {
            net,
            dir,
            node,
            provider: Some(provider),
            client,
        };
        eco.sync_node();
        eco
    }

    fn provider(&self) -> &Provider<Link> {
        self.provider.as_ref().unwrap()
    }

    /// The provider, stopped and opened again over the same node.
    fn restart(&mut self) {
        drop(self.provider.take());
        let wallet = Wallet::open(
            &self.dir.path().join("wallet.sqlite"),
            Link(self.net.clone()),
        )
        .unwrap();
        let provider = Provider::open(wallet, CONFIG)
            .unwrap()
            .pay_lightning(self.node.clone(), terms(&self.node))
            .unwrap();
        self.provider = Some(provider);
    }

    fn height(&self) -> u32 {
        self.net.view(A).height()
    }

    /// The node follows the hub's chain.
    fn sync_node(&self) {
        self.node.tip(self.height(), [0; 32]);
    }

    fn mine(&self, blocks: u32) {
        self.net.mine(A, blocks, None);
        self.sync_node();
    }

    /// An invoice of another node for `sat` under the hash of `preimage`,
    /// paid as `outcome` says, and a lock of the client paying it and the
    /// provider's fee to the provider, expiring at `expiry`.
    async fn lock(
        &self,
        sat: u64,
        preimage: [u8; 32],
        outcome: Outcome,
        expiry: u32,
    ) -> (String, Lock) {
        let hash = lock_hash(&preimage);
        let request = self.node.invoice(sat * 1000, hash, DELTA, outcome);
        let pays = terms(&self.node).pays(sat * 1000);
        let address = self.provider().wallet().address();
        let lock = self
            .client
            .lock(A, &address, pays, hash, Some(expiry))
            .await
            .unwrap();
        (request, lock)
    }

    fn request(&self, lock: &Lock, request: &str) -> LightningRequest {
        let address = self.net.hub(A).info().address;
        LightningRequest::new(&address, &lock_id(lock), request)
    }

    /// The provider follows its payments and swaps: none pending.
    async fn follow(&self) {
        let pending = self.provider().follow_invoices().await.unwrap();
        assert!(pending.is_empty(), "{pending:?}");
        self.provider().step().await.unwrap();
    }

    fn stage(&self) -> Stage {
        self.provider().records(1).unwrap()[0].stage
    }

    /// What the provider holds at A.
    fn provider_held(&self) -> u64 {
        let balance = self.provider().wallet().balance().unwrap();
        balance
            .iter()
            .find(|b| b.hub == A)
            .map_or(0, |b| b.available)
    }

    fn alerts(&self) -> Vec<String> {
        let events = self.provider().events(0, 100).unwrap();
        events
            .iter()
            .filter_map(|e| match e.notice() {
                Some(Notice::Alert { message }) => Some(message),
                _ => None,
            })
            .collect()
    }
}

fn lock_id(lock: &Lock) -> ProposalId {
    ProposalId::from_bytes(hex::decode(&lock.id).unwrap().try_into().unwrap())
}

/// The latest expiry the routes of an invoice of [`DELTA`] leave the
/// provider's slack before, at the hub's height `tip`: one block more is
/// enough.
fn soonest(tip: u32) -> u32 {
    tip + 24 + DELTA as u32 + 3
}

#[tokio::test]
async fn an_invoice_paid_pays_the_provider_the_clients_lock() {
    let eco = Eco::new().await;
    let info = eco.provider().info().unwrap();
    assert_eq!(info.lightning, Some(terms(&eco.node)));
    let preimage = [7; 32];
    let expiry = eco.height() + 100;
    let (request, lock) = eco
        .lock(1_000, preimage, Outcome::Pay(preimage), expiry)
        .await;
    let asked = eco.request(&lock, &request);
    let answer = eco.provider().take_invoice(&asked).await.unwrap();
    assert_eq!((answer.state, answer.amount), (State::Accepted, 1_000));
    assert_eq!(answer.preimage, None);
    // Along routes ending the slack before the lock expires, for at most
    // the provider's fee.
    let sent = eco.node.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].cltv_limit, expiry - eco.height() - 24);
    assert_eq!(sent[0].fee_limit, 2 + 10);
    let record = eco.provider().records(1).unwrap().remove(0);
    assert_eq!(record.to, "lightning:regtest");
    assert_eq!((record.amount, record.fee, record.paid), (1_000, 12, 1_012));
    assert_eq!(record.expiry, expiry - 24);
    assert_eq!(eco.provider().open_invoices().unwrap(), 1);

    // Paid: the preimage claims the client's lock.
    eco.follow().await;
    assert_eq!(eco.stage(), Stage::Done);
    assert_eq!(eco.provider_held(), 1_012);
    let id = lock_id(&lock);
    let answer = eco.provider().invoice(&id).unwrap().unwrap();
    assert_eq!(answer.state, State::Done);
    assert_eq!(answer.preimage().unwrap(), Some(preimage));
    assert!(eco.provider().swap(&id).unwrap().is_none());
    assert!(eco.provider().payout(&id).unwrap().is_none());
    let lock = eco.client.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
    let stats = eco.provider().stats().unwrap();
    assert_eq!((stats.done, stats.earned), (1, 12));
    assert_eq!(eco.provider().open_invoices().unwrap(), 0);

    // The same request again, its invoice written otherwise, answers where
    // it stands; another invoice for the lock is declined.
    let again = LightningRequest {
        request: format!(" {}\n", request.to_uppercase()),
        ..asked
    };
    let answer = eco.provider().take_invoice(&again).await.unwrap();
    assert_eq!(answer.state, State::Done);
    let other = eco.node.invoice(1_000_000, [9; 32], DELTA, Outcome::Hang);
    let problem = eco
        .provider()
        .take_invoice(&eco.request(&lock, &other))
        .await
        .unwrap_err();
    assert_eq!(problem.code, Code::Declined);
}

#[tokio::test]
async fn a_failed_payment_leaves_the_lock_to_be_refunded_once_expired() {
    let eco = Eco::new().await;
    let expiry = eco.height() + 60;
    let failed = Outcome::Fail("FAILURE_REASON_NO_ROUTE".into());
    let (request, lock) = eco.lock(500, [3; 32], failed, expiry).await;
    let answer = eco
        .provider()
        .take_invoice(&eco.request(&lock, &request))
        .await
        .unwrap();
    assert_eq!(answer.state, State::Accepted);
    eco.follow().await;
    assert_eq!(eco.stage(), Stage::Failed);
    let answer = eco.provider().invoice(&lock_id(&lock)).unwrap().unwrap();
    assert_eq!(answer.state, State::Failed);
    assert!(answer.reason.unwrap().contains("NO_ROUTE"));
    assert_eq!(eco.provider().stats().unwrap().failed, 1);

    // The client's notes wait for the lock to expire at depth.
    let lock = eco.client.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Locked);
    eco.mine(expiry - eco.height() + 1);
    let lock = eco.client.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Refunded);
    assert_eq!(eco.provider_held(), 0);
}

#[tokio::test]
async fn a_payment_the_node_lost_is_started_again_after_a_restart() {
    let mut eco = Eco::new().await;
    let preimage = [5; 32];
    let hash = lock_hash(&preimage);
    let expiry = eco.height() + 100;
    let (request, lock) = eco.lock(800, preimage, Outcome::Hang, expiry).await;
    eco.provider()
        .take_invoice(&eco.request(&lock, &request))
        .await
        .unwrap();
    eco.follow().await;
    assert_eq!(eco.stage(), Stage::Accepted);

    // Stopped, its node restored from a backup that never heard of the
    // payment: the provider asks it again, in time still.
    eco.restart();
    eco.node.resolve(hash, Outcome::Pay(preimage));
    eco.node.forget(hash);
    eco.mine(10);
    eco.follow().await;
    let sent = eco.node.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].cltv_limit, expiry - 24 - eco.height());
    eco.follow().await;
    assert_eq!(eco.stage(), Stage::Done);
    let lock = eco.client.follow_lock(&lock.id).await.unwrap();
    assert_eq!(lock.state, LockState::Paid(preimage));
}

#[tokio::test]
async fn a_payment_unresolved_past_its_routes_alerts_the_operator_once() {
    let eco = Eco::new().await;
    let preimage = [6; 32];
    let expiry = soonest(eco.height()) + 2;
    let (request, lock) = eco.lock(300, preimage, Outcome::Hang, expiry).await;
    eco.provider()
        .take_invoice(&eco.request(&lock, &request))
        .await
        .unwrap();
    let deadline = eco.provider().records(1).unwrap()[0].expiry;
    eco.mine(deadline - eco.height());
    eco.follow().await;
    eco.follow().await;
    let alerts = eco.alerts();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].contains("unresolved"), "{alerts:?}");
    // Still in flight: the node's word alone resolves it.
    assert_eq!(eco.stage(), Stage::Accepted);
    eco.node
        .resolve(lock_hash(&preimage), Outcome::Pay(preimage));
    eco.follow().await;
    assert_eq!(eco.stage(), Stage::Done);
}

#[tokio::test]
async fn invoices_the_provider_does_not_pay_for_a_lock_are_declined() {
    let eco = Eco::new().await;
    let declined = |problem: licash_api::Problem, why: &str| {
        assert_eq!(problem.code, Code::Declined, "{problem:?}");
        assert!(problem.message.contains(why), "{why}: {problem:?}");
    };
    let tip = eco.height();

    // A lock under another hash than the invoice's.
    let (_, lock) = eco.lock(100, [1; 32], Outcome::Hang, tip + 100).await;
    let other = eco.node.invoice(100_000, [0xee; 32], DELTA, Outcome::Hang);
    let problem = eco
        .provider()
        .take_invoice(&eco.request(&lock, &other))
        .await
        .unwrap_err();
    declined(problem, "hash");

    // One paying less than the invoice and the fee.
    let hash = lock_hash(&[2; 32]);
    let request = eco.node.invoice(200_000, hash, DELTA, Outcome::Hang);
    let address = eco.provider().wallet().address();
    let short = eco
        .client
        .lock(A, &address, 200, hash, Some(tip + 100))
        .await
        .unwrap();
    let problem = eco
        .provider()
        .take_invoice(&eco.request(&short, &request))
        .await
        .unwrap_err();
    declined(problem, "pays");

    // One expiring too soon for routes ending the slack before.
    let (request, early) = eco
        .lock(100, [3; 32], Outcome::Hang, soonest(tip) - 1)
        .await;
    let problem = eco
        .provider()
        .take_invoice(&eco.request(&early, &request))
        .await
        .unwrap_err();
    declined(problem, "too soon");

    // An invoice above the most it pays, or of its own node.
    let (request, big) = eco.lock(2_001, [4; 32], Outcome::Hang, tip + 100).await;
    let problem = eco
        .provider()
        .take_invoice(&eco.request(&big, &request))
        .await
        .unwrap_err();
    declined(problem, "most");
    let hash = lock_hash(&[8; 32]);
    let own = eco.node.hold(hash, 100_000, 40, 3600, None).await.unwrap();
    let pays = terms(&eco.node).pays(100_000);
    let lock = eco
        .client
        .lock(A, &address, pays, hash, Some(tip + 100))
        .await
        .unwrap();
    let problem = eco
        .provider()
        .take_invoice(&eco.request(&lock, &own))
        .await
        .unwrap_err();
    declined(problem, "own node");

    // Nothing was recorded, nor paid.
    assert!(eco.provider().records(10).unwrap().is_empty());
    assert!(eco.node.sent().is_empty());
    // Not an invoice at all.
    let problem = eco
        .provider()
        .take_invoice(&eco.request(&lock, "lnbcrt1nothing"))
        .await
        .unwrap_err();
    assert_eq!(problem.code, Code::Invalid, "{problem:?}");
}

#[tokio::test]
async fn a_provider_without_lightning_terms_pays_no_invoice() {
    let net = Net::new();
    net.start_timed(A, FEE, TIMED);
    let dir = tempfile::tempdir().unwrap();
    let wallet = |name: &str| {
        Wallet::create(
            &dir.path().join(name),
            &[0x50; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap()
    };
    let provider = Provider::create(wallet("w.sqlite"), CONFIG).unwrap();
    assert_eq!(provider.info().unwrap().lightning, None);
    let node = Arc::new(Fake::new());
    let request = node.invoice(1_000, [1; 32], DELTA, Outcome::Hang);
    let asked = LightningRequest::new(
        &net.hub(A).info().address,
        &ProposalId::from_bytes([1; 32]),
        &request,
    );
    let problem = provider.take_invoice(&asked).await.unwrap_err();
    assert_eq!(problem.code, Code::Declined);
    // Nor with too little slack to claim in.
    let slack = MIN_SLACK - 1;
    let too_little = swaps::Lightning {
        slack,
        ..terms(&node)
    };
    let other = Provider::create(wallet("o.sqlite"), CONFIG).unwrap();
    assert!(matches!(
        other.pay_lightning(node, too_little),
        Err(licash_swaps::Error::Setup(_))
    ));
}

/// A client's way to the hub and the provider.
#[derive(Clone)]
struct Via(Arc<Net>, Arc<Provider<Link>>);

/// [`Via`], but the provider never hears what it is asked to pay.
#[derive(Clone)]
struct Unheard(Via);

impl Transport for Unheard {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let asked = url == format!("{PROVIDER}{}", swaps::LIGHTNING_SWAPS);
        let answer = self.0.request(url, body);
        async move {
            match asked {
                true => Err("connection reset".into()),
                false => answer.await,
            }
        }
    }
}

impl Transport for Via {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let (net, provider, url) = (self.0.clone(), self.1.clone(), url.to_owned());
        async move {
            let Some(path) = url.strip_prefix(PROVIDER) else {
                return net.serve(&url, body);
            };
            let answer = match (path, body) {
                (swaps::SWAPS_INFO, None) => {
                    Ok(serde_json::to_vec(&provider.info().unwrap()).unwrap())
                }
                (swaps::LIGHTNING_SWAPS, Some(body)) => {
                    let request: LightningRequest = serde_json::from_slice(&body).unwrap();
                    provider
                        .take_invoice(&request)
                        .await
                        .map(|answer| serde_json::to_vec(&answer).unwrap())
                }
                _ => Err(licash_api::Problem::invalid("no such route")),
            };
            Ok(match answer {
                Ok(body) => Response { status: 200, body },
                Err(problem) => Response {
                    status: problem.code.status(),
                    body: serde_json::to_vec(&problem).unwrap(),
                },
            })
        }
    }
}

/// Hub A, a provider paying invoices through its node, and a client
/// holding 3,000 at A reaching both.
async fn via() -> (
    Arc<Net>,
    tempfile::TempDir,
    Arc<Fake>,
    Arc<Provider<Link>>,
    Wallet<Via>,
) {
    let net = Net::new();
    net.start_timed(A, FEE, TIMED);
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(
        &dir.path().join("wallet.sqlite"),
        &[0x50; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(net.clone()),
    )
    .unwrap();
    wallet.add_hub(A).await.unwrap();
    let node = Arc::new(Fake::new());
    node.tip(net.view(A).height(), [0; 32]);
    let provider = Provider::create(wallet, CONFIG)
        .unwrap()
        .pay_lightning(node.clone(), terms(&node))
        .unwrap();
    let provider = Arc::new(provider);
    let client = Wallet::create(
        &dir.path().join("client.sqlite"),
        &[0xc1; 32],
        ChainProfile::Core30DefaultRegtest,
        Via(net.clone(), provider.clone()),
    )
    .unwrap();
    client.add_hub(A).await.unwrap();
    client
        .receive(&net.pay(A, &client.address(), HELD))
        .unwrap();
    (net, dir, node, provider, client)
}

#[tokio::test]
async fn a_wallet_pays_an_invoice_through_a_provider_once() {
    let (net, _dir, node, provider, client) = via().await;
    let preimage = [7; 32];
    let request = node.invoice(
        1_000_000,
        lock_hash(&preimage),
        DELTA,
        Outcome::Pay(preimage),
    );
    let tip = net.view(A).height();
    let lock = client
        .pay_invoice_via(PROVIDER, A, &request, 100)
        .await
        .unwrap();
    // To the provider, the invoice and its fee, expiring once its routes
    // and its slack end, and a hop more.
    assert_eq!(lock.state, LockState::Locked);
    assert_eq!(lock.payee, provider.wallet().address());
    assert_eq!(lock.amount, terms(&node).pays(1_000_000));
    assert_eq!(lock.expiry, tip + 24 + DELTA as u32 + 3 + ROUTE_BLOCKS);
    assert_eq!(lock.invoice, None);
    assert_eq!(node.sent().len(), 1);

    provider.follow_invoices().await.unwrap();
    let paid = client.follow_lock(&lock.id).await.unwrap();
    assert_eq!(paid.state, LockState::Paid(preimage));
    // Asked again: the same lock, paid, and nothing more locked or paid.
    let again = client
        .pay_invoice_via(PROVIDER, A, &request, 100)
        .await
        .unwrap();
    assert_eq!(
        (again.id, again.state),
        (lock.id, LockState::Paid(preimage))
    );
    assert_eq!(client.locks().unwrap().len(), 1);
    assert_eq!(node.sent().len(), 1);
}

/// A payment whose record cannot be read is told pending; the others
/// are followed all the same.
#[tokio::test]
async fn a_payment_unread_holds_back_none_of_the_others() {
    let (_net, dir, node, provider, client) = via().await;
    let preimage = [7; 32];
    let request = node.invoice(
        1_000_000,
        lock_hash(&preimage),
        DELTA,
        Outcome::Pay(preimage),
    );
    let lock = client
        .pay_invoice_via(PROVIDER, A, &request, 100)
        .await
        .unwrap();
    // A paid one, followed first, its lock unreadable.
    let db = rusqlite::Connection::open(dir.path().join("wallet.sqlite")).unwrap();
    db.execute(
        "INSERT INTO provider_swaps (id, hash, from_url, to_url, address, amount, fee, paid,
             expiry_from_height, expiry_height, lock, preimage, state, created_at, updated_at,
             kind)
         VALUES (?1, ?1, 'a', 'b', X'00', 0, 0, 0, 0, 0, X'00', ?1, 'paid', 0, 0, 'lightning')",
        [[9u8; 32]],
    )
    .unwrap();
    let pending = provider.follow_invoices().await.unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0].0, hex::encode([9; 32]));
    let paid = client.follow_lock(&lock.id).await.unwrap();
    assert_eq!(paid.state, LockState::Paid(preimage));
}

#[tokio::test]
async fn a_payment_a_provider_gave_up_leaves_one_lock_to_expire() {
    let (_net, _dir, node, provider, client) = via().await;
    let failed = Outcome::Fail("FAILURE_REASON_NO_ROUTE".into());
    let request = node.invoice(500_000, lock_hash(&[3; 32]), DELTA, failed);
    let lock = client
        .pay_invoice_via(PROVIDER, A, &request, 100)
        .await
        .unwrap();
    assert_eq!((lock.state, lock.failure), (LockState::Locked, None));
    provider.follow_invoices().await.unwrap();
    // Asked again: the provider says it failed, which the lock records.
    let again = client
        .pay_invoice_via(PROVIDER, A, &request, 100)
        .await
        .unwrap();
    assert_eq!((&again.id, &again.state), (&lock.id, &LockState::Locked));
    assert!(again.failure.unwrap().contains("NO_ROUTE"));
    assert_eq!(client.locks().unwrap().len(), 1);
}

#[tokio::test]
async fn a_wallet_locks_nothing_for_a_provider_asking_too_much() {
    let (_net, _dir, node, _provider, client) = via().await;
    let request = node.invoice(1_000_000, lock_hash(&[4; 32]), DELTA, Outcome::Hang);
    // Its fee is 2 sat and 1%: 12.
    match client.pay_invoice_via(PROVIDER, A, &request, 11).await {
        Err(Error::FeeRose {
            agreed: 11,
            asked: 12,
            reason,
            ..
        }) => assert!(reason.contains("fee of 12 sat"), "{reason}"),
        other => panic!("{other:?}"),
    }
    // Nor for an invoice whose final delta outlasts the hub's locks.
    let long = node.invoice(1_000_000, lock_hash(&[5; 32]), 200, Outcome::Hang);
    match client.pay_invoice_via(PROVIDER, A, &long, 100).await {
        Err(Error::Invalid(why)) => assert!(why.contains("outlast"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(client.locks().unwrap().is_empty());
    assert!(node.sent().is_empty());
}

/// A payment through a provider whose lock, as its hub's fee on it signs
/// it, costs more than was quoted in all locks nothing: its hub raising its
/// fee after the quote is not paid it. Within the quote, it is paid.
#[tokio::test]
async fn a_wallet_locks_nothing_for_a_lock_fee_past_what_was_quoted_in_all() {
    let (_net, _dir, node, _provider, client) = via().await;
    let request = node.invoice(1_000_000, lock_hash(&[6; 32]), DELTA, Outcome::Hang);
    let quote = client
        .invoice_quote_via(PROVIDER, A, &request, 100)
        .await
        .unwrap();
    assert!(quote.lock_fee > 0, "{quote:?}");
    let all = quote.costs();
    let refused = client
        .pay_invoice_via_within(PROVIDER, A, &request, 100, Some(all - 1))
        .await;
    match refused {
        Err(Error::FeeRose { agreed, asked, .. }) => assert_eq!((agreed, asked), (all - 1, all)),
        other => panic!("{other:?}"),
    }
    assert!(client.locks().unwrap().is_empty());
    assert!(node.sent().is_empty());
    assert_eq!(client.balance().unwrap()[0].available, HELD);

    let lock = client
        .pay_invoice_via_within(PROVIDER, A, &request, 100, Some(all))
        .await
        .unwrap();
    assert_eq!(lock.fee, quote.lock_fee);
}

#[tokio::test]
async fn a_payment_the_provider_never_heard_of_is_asked_for_again() {
    let (net, dir, node, provider, client) = via().await;
    let path = dir.path().join("client.sqlite");
    drop(client);
    let unheard = Unheard(Via(net.clone(), provider.clone()));
    let client = Wallet::open(&path, unheard).unwrap();
    let preimage = [8; 32];
    let request = node.invoice(
        1_000_000,
        lock_hash(&preimage),
        DELTA,
        Outcome::Pay(preimage),
    );
    let tip = net.view(A).height();
    let quote = client
        .invoice_quote_via(PROVIDER, A, &request, 100)
        .await
        .unwrap();
    let lock = client
        .pay_invoice_via(PROVIDER, A, &request, 100)
        .await
        .unwrap();
    // As quoted: the invoice and the provider's fee locked, expiring then,
    // its notes back that many blocks from now should it fail.
    assert_eq!(lock.amount, quote.amount + quote.fee);
    assert_eq!(lock.expiry, quote.expiry);
    assert_eq!(quote.refund_blocks, quote.expiry - tip + TIMED.min_depth);
    // Locked, but the provider never heard of it: recorded with the lock.
    assert_eq!((&lock.state, &lock.failure), (&LockState::Locked, &None));
    let recorded = lock.via.clone().unwrap();
    assert_eq!(recorded.provider, PROVIDER);
    assert_eq!(recorded.invoice, request);
    assert!(node.sent().is_empty());

    // Opened again, as once the app is back: resuming asks the provider.
    drop(client);
    let client = Wallet::open(&path, Via(net, provider.clone())).unwrap();
    client.resume().await.unwrap();
    assert_eq!(node.sent().len(), 1);
    provider.follow_invoices().await.unwrap();
    let paid = client.follow_lock(&lock.id).await.unwrap();
    assert_eq!(paid.state, LockState::Paid(preimage));
    assert_eq!(paid.via, Some(recorded));
}

#[tokio::test]
async fn the_provider_pays_no_more_than_its_channels_do() {
    let eco = Eco::new().await;
    // As the operator set it, while the channels pay more.
    assert_eq!(eco.provider().lightning_now().await, Some(terms(&eco.node)));
    // 988 and the fee of 2 and 1% on it pay 1,000, all the channels hold.
    eco.node.channels(1_000, 0);
    let now = eco.provider().lightning_now().await.unwrap();
    assert_eq!(now.max, 988);
    assert_eq!(now.pays(988_000), 1_000);
    assert_eq!(
        eco.provider().info().unwrap().lightning,
        Some(terms(&eco.node))
    );

    // One more is declined before the node is asked, nothing recorded.
    let expiry = eco.height() + 100;
    let (request, lock) = eco.lock(989, [4; 32], Outcome::Hang, expiry).await;
    let problem = eco
        .provider()
        .take_invoice(&eco.request(&lock, &request))
        .await
        .unwrap_err();
    assert_eq!(problem.code, Code::Declined);
    assert!(problem.message.contains("channels"), "{}", problem.message);
    assert!(eco.node.sent().is_empty());
    assert!(eco.provider().records(1).unwrap().is_empty());
    // As much is paid.
    let (request, lock) = eco.lock(988, [5; 32], Outcome::Hang, expiry).await;
    let answer = eco
        .provider()
        .take_invoice(&eco.request(&lock, &request))
        .await
        .unwrap();
    assert_eq!(answer.state, State::Accepted);
    assert_eq!(eco.node.sent().len(), 1);

    // A node not answering pays nothing, as far as clients are told.
    eco.node.down(true);
    assert_eq!(eco.provider().lightning_now().await.unwrap().max, 0);
}

#[tokio::test]
async fn an_invoice_under_way_for_one_lock_is_not_paid_for_another() {
    let eco = Eco::new().await;
    let preimage = [6; 32];
    let expiry = eco.height() + 100;
    let (request, first) = eco.lock(500, preimage, Outcome::Hang, expiry).await;
    let answer = eco
        .provider()
        .take_invoice(&eco.request(&first, &request))
        .await
        .unwrap();
    assert_eq!(answer.state, State::Accepted);
    // Another lock of the client's, under the same hash, for the same
    // invoice: declined before the node is asked to pay it again.
    let address = eco.provider().wallet().address();
    let pays = terms(&eco.node).pays(500_000);
    let second = eco
        .client
        .lock(A, &address, pays, lock_hash(&preimage), Some(expiry))
        .await
        .unwrap();
    assert_ne!(second.id, first.id);
    let problem = eco
        .provider()
        .take_invoice(&eco.request(&second, &request))
        .await
        .unwrap_err();
    assert_eq!(problem.code, Code::Declined);
    assert_eq!(eco.node.sent().len(), 1);
    assert_eq!(eco.provider().records(2).unwrap().len(), 1);
}
