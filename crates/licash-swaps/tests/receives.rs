//! Receipts over Lightning for wallets: a held invoice of the provider's
//! node under the wallet's hash, paid on as a lock of the provider's notes
//! to the wallet, settled with the preimage its claim shows; canceled
//! while nothing was locked, or once the lock is refunded.

#[allow(dead_code)]
#[path = "../../licash-wallet/tests/net/mod.rs"]
mod net;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use bitcoin::hashes::Hash;
use licash::spend::{lock_hash, ChainProfile};
use licash_api::{swaps, Problem, Receiving};
use licash_api::{swaps::ReceiveRequest, Code, Fee, Hex, ReceiveState};
use licash_lightning::{fake::Fake, HeldState};
use licash_swaps::{
    Config, DonationTerms, Notice, Provider, ReceiptState, ReceiveTerms, RECEIVE_BLOCKS,
    SETTLE_MARGIN,
};
use licash_wallet::{InvoiceState, Response, Transport, Wallet};
use lightning_invoice::Bolt11Invoice;
use net::{Fault, Link, Net};

const A: &str = "http://a.test";
const FEE: Fee = Fee { base: 1, ppm: 0 };
const TERMS: ReceiveTerms = ReceiveTerms {
    fee: Fee { base: 2, ppm: 0 },
    min: 10,
    max: 500,
    max_open: 3,
};
/// What the provider holds at A to start with.
const HELD: u64 = 1_000;
/// Blocks the payer's HTLCs outlive the provider's lock by, at least: the
/// refund request's confirmation (36), A's window (20), reading the
/// preimage, the provider's margin (12) and one.
const LEAD: u32 = 36 + 20 + 1 + 12 + 1;

struct Eco {
    net: Arc<Net>,
    dir: tempfile::TempDir,
    node: Arc<Fake>,
    provider: Option<Arc<Provider<Link>>>,
    payee: Wallet<Link>,
}

impl Eco {
    /// Hub A, a provider holding 1,000 there taking receipts through its
    /// node, and a payee at A.
    async fn new() -> Self {
        let net = Net::new();
        net.start(A, FEE);
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[0x50; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        wallet.add_hub(A).await.unwrap();
        wallet
            .receive(&net.pay(A, &wallet.address(), HELD))
            .unwrap();
        let node = Arc::new(Fake::new());
        let provider = Provider::create(wallet, Config::default())
            .unwrap()
            .take_receives(node.clone(), TERMS)
            .unwrap();
        let payee = Wallet::create(
            &dir.path().join("payee.sqlite"),
            &[0xd0; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        payee.add_hub(A).await.unwrap();
        let eco = Self {
            net,
            dir,
            node,
            provider: Some(Arc::new(provider)),
            payee,
        };
        eco.mine(0).await;
        eco
    }

    fn provider(&self) -> &Provider<Link> {
        self.provider.as_deref().unwrap()
    }

    fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("wallet.sqlite")
    }

    /// The provider, stopped and opened again over the same node.
    fn restart(&mut self) {
        self.restart_with(TERMS);
    }

    /// [`Self::restart`], taking receipts on `terms`.
    fn restart_with(&mut self, terms: ReceiveTerms) {
        drop(self.provider.take());
        let wallet = Wallet::open(&self.path(), Link(self.net.clone())).unwrap();
        let provider = Provider::open(wallet, Config::default())
            .unwrap()
            .take_receives(self.node.clone(), terms)
            .unwrap();
        self.provider = Some(Arc::new(provider));
    }

    /// Hub A's address, as the provider knows it.
    fn hub_address(&self) -> licash::address::Address {
        self.payee.hubs().unwrap()[0].1.address
    }

    fn height(&self) -> u32 {
        self.net.view(A).height()
    }

    /// `blocks` mined, the node and the provider's view of A following.
    async fn mine(&self, blocks: u32) {
        if blocks > 0 {
            self.net.mine(A, blocks, None);
        }
        self.node.tip(self.height(), [0; 32]);
        if let Some(provider) = &self.provider {
            provider.wallet().add_hub(A).await.unwrap();
        }
    }

    /// The payee's request of a receipt of `amount` under the preimage
    /// `[seed; 32]`.
    fn request(&self, amount: u64, seed: u8) -> ReceiveRequest {
        ReceiveRequest {
            hub: self.hub_address(),
            address: self.payee.address(),
            amount,
            hash: Hex(lock_hash(&[seed; 32]).to_vec()),
            memo: None,
            asks: None,
            description_hash: None,
        }
    }

    /// A receipt of `amount` asked for: its invoice and hash.
    async fn receive(&self, amount: u64, seed: u8) -> (Bolt11Invoice, [u8; 32]) {
        let receiving = self
            .provider()
            .receive(&self.request(amount, seed), None)
            .await
            .unwrap();
        (receiving.request.parse().unwrap(), lock_hash(&[seed; 32]))
    }

    /// The receipt's invoice paid, its HTLCs expiring `blocks` from now.
    fn pay(&self, hash: [u8; 32], blocks: u32) {
        self.node.pay_held(hash, self.height() + blocks);
    }

    async fn follow(&self) {
        let pending = self.provider().follow_receives().await.unwrap();
        assert!(pending.is_empty(), "{pending:?}");
    }

    fn state(&self, hash: &[u8; 32]) -> ReceiptState {
        self.provider().receipt(hash).unwrap().unwrap().state
    }

    fn held(&self) -> u64 {
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

    /// The lock the provider tells the payee to claim.
    fn lock(&self, hash: &[u8; 32]) -> String {
        let status = self.provider().receive_status(hash).unwrap().unwrap();
        assert_eq!(status.state, ReceiveState::Locked);
        hex::encode(status.lock().unwrap().unwrap().as_bytes())
    }
}

/// The final CLTV delta of a receipt's invoice at A.
const CLTV: u32 = SETTLE_MARGIN + LEAD + RECEIVE_BLOCKS + 3;

#[tokio::test]
async fn a_receipt_paid_is_locked_to_the_wallet_and_settled_once_it_claims() {
    let eco = Eco::new().await;
    // Its info tells wallets its terms.
    let receive = eco.provider().info().unwrap().receive.unwrap();
    assert_eq!(
        (receive.fee, receive.min, receive.max),
        (TERMS.fee, 10, 500)
    );
    let (invoice, hash) = eco.receive(100, 5).await;
    // The amount and the provider's fee, under the payee's hash, held long
    // enough to force the preimage out on Bitcoin should A keep it.
    assert_eq!(invoice.amount_milli_satoshis(), Some(102_000));
    assert_eq!(invoice.payment_hash().as_ref() as &[u8], &hash[..]);
    assert_eq!(eco.node.held_cltv(hash), Some(CLTV.into()));
    assert!(licash_swaps::holds_hash(&eco.path(), &hash).unwrap());
    // What it is to lock is set aside from what it swaps.
    let max = |eco: &Eco| eco.provider().info().unwrap().hubs[0].max;
    let before = max(&eco);
    eco.provider()
        .receive(&eco.request(10, 9), None)
        .await
        .unwrap();
    assert_eq!(max(&eco), before - 10);
    // Nothing is locked until its invoice is paid.
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Open);
    assert_eq!(eco.held(), HELD);
    let status = eco.provider().receive_status(&hash).unwrap().unwrap();
    assert_eq!((status.state, status.lock), (ReceiveState::Open, None));
    let paid_at = eco.height();
    eco.pay(hash, CLTV);
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Locked);
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Accepted);
    // Locked to expire RECEIVE_BLOCKS and the slack past the payment.
    let receipt = eco.provider().receipt(&hash).unwrap().unwrap();
    assert_eq!(receipt.expiry, Some(paid_at + RECEIVE_BLOCKS + 3));
    // The amount locked, and the hub's fee on it.
    assert!(eco.held() < HELD - 100, "{}", eco.held());
    // The payee claims, showing the provider the preimage, which settles.
    let lock = eco.lock(&hash);
    let received = eco.payee.claim(A, &lock, &[5; 32]).await.unwrap();
    assert_eq!(received.amount, 100);
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Settled);
    assert_eq!(eco.node.held(hash), Some((HeldState::Settled, 102_000)));
    let status = eco.provider().receive_status(&hash).unwrap().unwrap();
    assert_eq!(status.state, ReceiveState::Settled);
    // Only the other, unpaid, is under way.
    assert_eq!(eco.provider().open_receives().unwrap(), 1);
    assert!(eco.alerts().is_empty());
}

#[tokio::test]
async fn a_receipt_never_claimed_is_refunded_then_canceled() {
    let eco = Eco::new().await;
    let (_, hash) = eco.receive(100, 5).await;
    eco.pay(hash, CLTV);
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Locked);
    // Expired, the lock is refunded, and only then the payment failed back.
    eco.mine(RECEIVE_BLOCKS + 3).await;
    eco.follow().await;
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Accepted);
    for _ in 0..3 {
        eco.mine(1).await;
        eco.follow().await;
    }
    assert_eq!(eco.state(&hash), ReceiptState::Canceled);
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Canceled);
    let status = eco.provider().receive_status(&hash).unwrap().unwrap();
    assert_eq!(status.state, ReceiveState::Canceled);
    // The provider holds what it held, but the hub's fees.
    assert!(eco.held() >= HELD - 2, "{}", eco.held());
}

#[tokio::test]
async fn a_payment_expiring_too_soon_to_lock_is_failed_back_unlocked() {
    let eco = Eco::new().await;
    let (_, hash) = eco.receive(100, 5).await;
    // HTLCs held by an older invoice's delta, too short for the lead.
    eco.pay(hash, SETTLE_MARGIN + LEAD);
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Canceled);
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Canceled);
    assert!(eco.provider().wallet().locks().unwrap().is_empty());
    assert_eq!(eco.held(), HELD);
}

#[tokio::test]
async fn a_provider_stopped_while_locking_adopts_its_lock_never_locking_again() {
    let mut eco = Eco::new().await;
    let (_, hash) = eco.receive(100, 5).await;
    eco.pay(hash, CLTV);
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Locked);
    // As if it stopped once its wallet recorded the lock, before it did.
    let db = rusqlite::Connection::open(eco.path()).unwrap();
    db.execute(
        "UPDATE provider_receives SET lock = NULL, state = 'open' WHERE hash = ?1",
        [hash],
    )
    .unwrap();
    eco.restart();
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Locked);
    assert_eq!(eco.provider().wallet().locks().unwrap().len(), 1);
    let lock = eco.lock(&hash);
    eco.payee.claim(A, &lock, &[5; 32]).await.unwrap();
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Settled);

    // Stopped once it timed its lock, before its wallet recorded one:
    // locked then, once.
    let (_, other) = eco.receive(50, 6).await;
    eco.pay(other, CLTV);
    let expiry = eco.height() + RECEIVE_BLOCKS;
    db.execute(
        "UPDATE provider_receives SET expiry = ?2 WHERE hash = ?1",
        rusqlite::params![other, expiry],
    )
    .unwrap();
    eco.restart();
    eco.follow().await;
    assert_eq!(eco.state(&other), ReceiptState::Locked);
    let locks = eco.provider().wallet().locks().unwrap();
    assert_eq!(locks.len(), 2);
    assert_eq!(locks[0].expiry, expiry);
}

#[tokio::test]
async fn a_hub_neither_paying_nor_refunding_a_receipts_lock_is_alerted_never_canceled() {
    let eco = Eco::new().await;
    let (_, hash) = eco.receive(100, 5).await;
    eco.pay(hash, CLTV);
    eco.follow().await;
    let withhold = |fault| eco.net.fail(licash_api::REFUND, fault);
    // Expired at depth and A's reaction: A owes the refund, and withholds it.
    eco.mine(RECEIVE_BLOCKS + 3 + 1 + 2).await;
    withhold(Fault::Lost);
    let pending = eco.provider().follow_receives().await.unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let alerts = eco.alerts();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].contains("may keep the preimage"), "{alerts:?}");
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Accepted);
    // Told once.
    withhold(Fault::Refused(Code::Unexpired));
    eco.follow().await;
    assert_eq!(eco.alerts().len(), 1);
    assert_eq!(eco.state(&hash), ReceiptState::Locked);
    // Refunded at last: failed back.
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Canceled);
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Canceled);
}

#[tokio::test]
async fn receipts_are_asked_within_the_terms_once_under_each_hash() {
    let eco = Eco::new().await;
    let provider = eco.provider();
    let (invoice, hash) = eco.receive(100, 5).await;
    // The same request again: the same invoice.
    let again = provider.receive(&eco.request(100, 5), None).await.unwrap();
    assert_eq!(again.request, invoice.to_string());
    let refused = |r: Result<licash_api::Receiving, licash_api::Problem>| r.unwrap_err().code;
    // Another under its hash.
    assert_eq!(
        refused(provider.receive(&eco.request(101, 5), None).await),
        Code::Declined
    );
    // Beyond the terms.
    assert_eq!(
        refused(provider.receive(&eco.request(9, 6), None).await),
        Code::Invalid
    );
    assert_eq!(
        refused(provider.receive(&eco.request(501, 6), None).await),
        Code::Invalid
    );
    // To a hub's address, or at a hub the provider does not swap at.
    let to_hub = ReceiveRequest {
        address: eco.hub_address(),
        ..eco.request(100, 6)
    };
    assert_eq!(
        refused(provider.receive(&to_hub, None).await),
        Code::Invalid
    );
    let elsewhere = ReceiveRequest {
        hub: eco.payee.address(),
        ..eco.request(100, 6)
    };
    assert_eq!(
        refused(provider.receive(&elsewhere, None).await),
        Code::Declined
    );
    // A memo not as made.
    let memo = ReceiveRequest {
        memo: Some(" Lunch".into()),
        ..eco.request(100, 6)
    };
    assert_eq!(refused(provider.receive(&memo, None).await), Code::Invalid);
    // More than the provider holds beside what it is to lock.
    eco.receive(500, 6).await;
    assert_eq!(
        refused(provider.receive(&eco.request(450, 7), None).await),
        Code::Declined
    );
    // At most three under way.
    eco.receive(10, 7).await;
    assert_eq!(
        refused(provider.receive(&eco.request(10, 8), None).await),
        Code::Unavailable
    );
    assert_eq!(provider.open_receives().unwrap(), 3);
    assert!(licash_swaps::holds_hash(&eco.path(), &hash).unwrap());
}

/// From one source only so many receipts are asked and not paid, the
/// rest of those under way left to others: from another source, or none
/// known, more, and once one is paid, its place is free.
#[tokio::test]
async fn receipts_asked_and_not_paid_from_one_source_are_bounded() {
    let mut eco = Eco::new().await;
    eco.restart_with(ReceiveTerms {
        max_open: 100,
        ..TERMS
    });
    let eco = &eco;
    let (one, other) = (b"ip 192.0.2.1".as_slice(), b"ip 192.0.2.2".as_slice());
    let ask = |seed: u8, source: Option<&'static [u8]>| {
        let request = eco.request(10, seed);
        async move { eco.provider().receive(&request, source).await }
    };
    for seed in 0..licash_swaps::PER_SOURCE as u8 {
        ask(10 + seed, Some(one)).await.unwrap();
    }
    let refused = ask(50, Some(one)).await.unwrap_err();
    assert_eq!(refused.code, Code::Unavailable, "{refused:?}");
    assert!(refused.message.contains("source"), "{refused:?}");
    // One asked, asked again: the same.
    ask(10, Some(one)).await.unwrap();
    ask(50, Some(other)).await.unwrap();
    ask(51, None).await.unwrap();
    // Paid, one is no longer counted.
    let hash = lock_hash(&[10; 32]);
    eco.pay(hash, CLTV);
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Locked);
    ask(52, Some(one)).await.unwrap();
    assert_eq!(
        ask(53, Some(one)).await.unwrap_err().code,
        Code::Unavailable
    );
}

#[tokio::test]
async fn a_hash_of_a_donation_is_no_receipts() {
    let mut eco = Eco::new().await;
    drop(eco.provider.take());
    let wallet =
        Wallet::open(&eco.dir.path().join("wallet.sqlite"), Link(eco.net.clone())).unwrap();
    let provider = Provider::open(wallet, Config::default())
        .unwrap()
        .take_donations(
            eco.node.clone(),
            DonationTerms::default(),
            "https://swaps.test",
        )
        .unwrap()
        .take_receives(eco.node.clone(), TERMS)
        .unwrap();
    let code = eco
        .payee
        .payment_code(&[A.into()])
        .unwrap()
        .licash
        .unwrap()
        .to_string();
    let donation: Bolt11Invoice = provider
        .donate(&code, 100_000, None)
        .await
        .unwrap()
        .parse()
        .unwrap();
    let hash = donation.payment_hash().to_byte_array();
    let request = ReceiveRequest {
        hub: eco.hub_address(),
        address: eco.payee.address(),
        amount: 100,
        hash: Hex(hash.to_vec()),
        memo: None,
        asks: None,
        description_hash: None,
    };
    let refused = provider.receive(&request, None).await.unwrap_err();
    assert_eq!(refused.code, Code::Declined, "{refused:?}");
    assert!(provider.receipt(&hash).unwrap().is_none());
}

#[tokio::test]
async fn a_file_of_an_older_provider_opens_and_takes_receipts_once_asked() {
    let eco = Eco::new().await;
    let net = eco.net.clone();
    let path = eco.dir.path().join("older.sqlite");
    let wallet = Wallet::create(
        &path,
        &[0x51; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(net.clone()),
    )
    .unwrap();
    let older = Provider::create(wallet, Config::default()).unwrap();
    // As an older provider's file: no receipts' tables.
    let tables = |path: &std::path::Path| {
        let db = rusqlite::Connection::open(path).unwrap();
        db.query_row(
            "SELECT count(*) FROM schema_versions WHERE component = 'provider_receives'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
    };
    assert_eq!(tables(&path), 0);
    assert_eq!(older.open_receives().unwrap(), 0);
    assert!(older.receipt(&[1; 32]).unwrap().is_none());
    assert!(!licash_swaps::holds_hash(&path, &[1; 32]).unwrap());
    assert!(older.info().unwrap().receive.is_none());
    assert!(older.follow_receives().await.unwrap().is_empty());
    let declined = older.receive(&eco.request(100, 5), None).await.unwrap_err();
    assert_eq!(declined.code, Code::Declined);
    drop(older);
    // Opened by this version, taking receipts: made then, once.
    for _ in 0..2 {
        let wallet = Wallet::open(&path, Link(net.clone())).unwrap();
        let provider = Provider::open(wallet, Config::default())
            .unwrap()
            .take_receives(eco.node.clone(), TERMS)
            .unwrap();
        assert_eq!(provider.open_receives().unwrap(), 0);
        assert!(provider.info().unwrap().receive.is_some());
    }
    assert_eq!(tables(&path), 1);
}

/// Where a wallet reaches the provider.
const PROVIDER: &str = "http://provider.test";

/// A wallet's way to the hubs and the provider, which answers `lie`, once
/// set, to the next request for an invoice, and loses the next one while
/// `lose`.
#[derive(Clone)]
struct Client {
    net: Arc<Net>,
    provider: Arc<Provider<Link>>,
    lie: Arc<Mutex<Option<Receiving>>>,
    lose: Arc<AtomicBool>,
}

impl Client {
    async fn serve(&self, path: &str, body: Option<Vec<u8>>) -> Result<Vec<u8>, Problem> {
        let provider = &self.provider;
        match (path, body) {
            (swaps::SWAPS_INFO, None) => Ok(json(&provider.info().unwrap())),
            (swaps::RECEIVES, Some(body)) => {
                let request: ReceiveRequest = serde_json::from_slice(&body).unwrap();
                let receiving = provider.receive(&request, None).await?;
                Ok(json(&self.lie.lock().unwrap().take().unwrap_or(receiving)))
            }
            (path, None) => {
                let hash = licash_api::hash_of(&path[swaps::RECEIVES.len() + 1..])?;
                match provider.receive_status(&hash).unwrap() {
                    Some(status) => Ok(json(&status)),
                    None => Err(Problem::new(Code::UnknownLock, "no receipt")),
                }
            }
            _ => Err(Problem::invalid("no such route")),
        }
    }
}

fn json(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

impl Transport for Client {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let (client, url) = (self.clone(), url.to_owned());
        async move {
            let Some(path) = url.strip_prefix(PROVIDER) else {
                return client.net.serve(&url, body);
            };
            if path == swaps::RECEIVES && client.lose.swap(false, Ordering::Relaxed) {
                return Err("connection refused".into());
            }
            Ok(match client.serve(path, body).await {
                Ok(body) => Response { status: 200, body },
                Err(problem) => Response {
                    status: problem.code.status(),
                    body: serde_json::to_vec(&problem).unwrap(),
                },
            })
        }
    }
}

impl Eco {
    /// A wallet at A reaching the provider at [`PROVIDER`].
    async fn client(&self, seed: u8) -> (Wallet<Client>, Client) {
        let client = Client {
            net: self.net.clone(),
            provider: self.provider.clone().unwrap(),
            lie: Arc::default(),
            lose: Arc::default(),
        };
        let wallet = Wallet::create(
            &self.dir.path().join(format!("client-{seed}.sqlite")),
            &[seed; 32],
            ChainProfile::Core30DefaultRegtest,
            client.clone(),
        )
        .unwrap();
        wallet.add_hub(A).await.unwrap();
        (wallet, client)
    }
}

#[tokio::test]
async fn a_wallet_at_a_hub_without_a_gateway_is_paid_through_a_provider() {
    let eco = Eco::new().await;
    let (wallet, _) = eco.client(0x61).await;
    let offer = wallet.receive_offer(PROVIDER, A).await.unwrap();
    assert_eq!((offer.terms.min, offer.max), (10, 500));
    let invoice = wallet
        .invoice_through(PROVIDER, A, 100, Some("Lunch"))
        .await
        .unwrap();
    assert_eq!(invoice.state, InvoiceState::Open);
    assert_eq!(invoice.memo.as_deref(), Some("Lunch"));
    // What the provider asks exactly: the amount and its fee.
    let request: Bolt11Invoice = invoice.request.unwrap().parse().unwrap();
    assert_eq!(request.amount_milli_satoshis(), Some(102_000));
    let hash: [u8; 32] = request.payment_hash().to_byte_array();
    // Unpaid, nothing to claim yet.
    let open = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!((open.state, open.lock), (InvoiceState::Open, None));
    eco.pay(hash, CLTV);
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Locked);
    // The wallet claims the provider's lock, which settles the invoice.
    let paid = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(paid.state, InvoiceState::Received, "{paid:?}");
    assert!(paid.lock.is_some());
    let balance = wallet.balance().unwrap();
    assert_eq!(balance[0].available, 100);
    eco.follow().await;
    assert_eq!(eco.state(&hash), ReceiptState::Settled);
    assert_eq!(eco.node.held(hash), Some((HeldState::Settled, 102_000)));
}

#[tokio::test]
async fn an_invoice_asked_of_a_provider_is_resumed_and_checked_as_offered() {
    let eco = Eco::new().await;
    let (wallet, client) = eco.client(0x62).await;
    // Beyond what it takes: refused, nothing asked.
    let refused = wallet.invoice_through(PROVIDER, A, 501, None).await;
    assert!(refused.is_err());
    assert_eq!(eco.provider().open_receives().unwrap(), 0);
    // The provider answering an invoice of another payment: dropped,
    // never handed out.
    let other = eco
        .provider()
        .receive(&eco.request(100, 9), None)
        .await
        .unwrap();
    *client.lie.lock().unwrap() = Some(other);
    let lied = wallet
        .invoice_through(PROVIDER, A, 100, None)
        .await
        .unwrap();
    assert!(
        matches!(&lied.state, InvoiceState::Canceled(why) if why.contains("another payment")),
        "{lied:?}"
    );
    assert!(lied.request.is_none());
    // Its request lost: pending, made on resuming.
    let before = eco.provider().open_receives().unwrap();
    client.lose.store(true, Ordering::Relaxed);
    let pending = wallet.invoice_through(PROVIDER, A, 50, None).await;
    assert!(
        matches!(pending, Err(licash_wallet::Error::Pending { .. })),
        "{pending:?}"
    );
    assert_eq!(eco.provider().open_receives().unwrap(), before);
    wallet.resume().await.unwrap();
    let invoices = wallet.invoices().unwrap();
    let resumed = invoices.iter().find(|i| i.amount == 50).unwrap();
    assert!(resumed.request.is_some(), "{resumed:?}");
    assert_eq!(resumed.state, InvoiceState::Open);
    assert_eq!(eco.provider().open_receives().unwrap(), before + 1);
}

#[tokio::test]
async fn an_invoice_of_an_exact_amount_is_asked_of_a_provider_naming_it() {
    let eco = Eco::new().await;
    let (wallet, _) = eco.client(0x63).await;
    let offer = wallet.receive_offer(PROVIDER, A).await.unwrap();
    assert!(offer
        .info
        .features
        .iter()
        .any(|f| f == swaps::FEATURE_RECEIVE_EXACT));
    // Whole satoshis only, and a memo or a description hash.
    let sub_sat = wallet
        .invoice_exact_through(PROVIDER, A, 105_500, None, None)
        .await;
    assert!(sub_sat.is_err(), "{sub_sat:?}");
    let both = wallet
        .invoice_exact_through(PROVIDER, A, 105_000, Some("Lunch"), Some([5; 32]))
        .await;
    assert!(both.is_err(), "{both:?}");
    assert_eq!(eco.provider().open_receives().unwrap(), 0);
    // Asking exactly 105 sat, committing to the hash: 103 sat paid, the
    // provider's fee of 2 the rest.
    let invoice = wallet
        .invoice_exact_through(PROVIDER, A, 105_000, None, Some([5; 32]))
        .await
        .unwrap();
    assert_eq!(
        (invoice.state.clone(), invoice.amount),
        (InvoiceState::Open, 103)
    );
    let request: Bolt11Invoice = invoice.request.clone().unwrap().parse().unwrap();
    assert_eq!(request.amount_milli_satoshis(), Some(105_000));
    match request.description() {
        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(h) => {
            assert_eq!(h.0.to_byte_array(), [5; 32])
        }
        other => panic!("{other:?}"),
    }
    let hash: [u8; 32] = request.payment_hash().to_byte_array();
    eco.pay(hash, CLTV);
    eco.follow().await;
    let paid = wallet.follow_invoice(&invoice.hash).await.unwrap();
    assert_eq!(paid.state, InvoiceState::Received, "{paid:?}");
    assert_eq!(wallet.balance().unwrap()[0].available, 103);
    eco.follow().await;
    assert_eq!(eco.node.held(hash), Some((HeldState::Settled, 105_000)));
}

#[tokio::test]
async fn a_provider_makes_an_invoice_asking_what_the_wallet_names_once() {
    let eco = Eco::new().await;
    let provider = eco.provider();
    let refused = |r: Result<Receiving, Problem>| r.unwrap_err().code;
    // Less than the amount and its fee, or a hash with a memo: refused.
    let short = ReceiveRequest {
        asks: Some(101),
        ..eco.request(100, 7)
    };
    assert_eq!(refused(provider.receive(&short, None).await), Code::Invalid);
    let both = ReceiveRequest {
        memo: Some("Lunch".into()),
        description_hash: Some(Hex(vec![5; 32])),
        ..eco.request(100, 7)
    };
    assert_eq!(refused(provider.receive(&both, None).await), Code::Invalid);
    let exact = ReceiveRequest {
        asks: Some(104),
        description_hash: Some(Hex(vec![5; 32])),
        ..eco.request(100, 7)
    };
    let made = provider.receive(&exact, None).await.unwrap();
    let invoice: Bolt11Invoice = made.request.parse().unwrap();
    assert_eq!(invoice.amount_milli_satoshis(), Some(104_000));
    // The same again, the same invoice; asking otherwise under its hash,
    // declined.
    assert_eq!(
        provider.receive(&exact, None).await.unwrap().request,
        made.request
    );
    let other = ReceiveRequest {
        asks: Some(105),
        ..exact.clone()
    };
    assert_eq!(
        refused(provider.receive(&other, None).await),
        Code::Declined
    );
    let uncommitted = ReceiveRequest {
        description_hash: None,
        ..exact.clone()
    };
    assert_eq!(
        refused(provider.receive(&uncommitted, None).await),
        Code::Declined
    );
}
