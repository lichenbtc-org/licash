//! Deposits on Bitcoin over a mock Esplora, in process: wallets pay them,
//! claim the hub's notes and the hub claims the coins; payments not as
//! asked, late or reorganized away lock nothing, and return to the payer.

mod chain;
mod esplora;

use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};

use axum::{
    body::Body,
    http::{header, Method, Request},
    Router,
};
use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    key::TweakedPublicKey,
    secp256k1::{Secp256k1, SecretKey},
    transaction, Address, Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use http_body_util::BodyExt;
use licash::spend::ChainProfile;
use licash_api::{Code, DepositStatus, Fee, Hex, Info, Problem, ReceiveState};
use licash_chain_client::Source;
use licash_hub::{Hub, Policy, Timing};
use licash_hub_service::{
    deposit,
    lightning::{self, fake::Fake, HeldState},
    peer, AdmissionSource, Services, PER_SOURCE,
};
use licash_wallet::{DepositState, Transport, Wallet};
use serde_json::json;
use tower::ServiceExt;

const HUB: &str = "http://hub.test";

/// Short, to expire locks in a test.
const TIMING: Timing = Timing {
    window: 40,
    reaction: 2,
    min_depth: 1,
    max_headers: 4032,
    bury: 6,
    max_lag: 120,
};

/// Where the hub's claims pay.
fn sweep_to() -> ScriptBuf {
    let key = SecretKey::from_slice(&[9; 32]).unwrap();
    let key = key.x_only_public_key(&Secp256k1::new()).0;
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key))
}

fn config() -> deposit::Config {
    deposit::Config {
        fee: Fee { base: 100, ppm: 0 },
        min: 1_000,
        max: 4_000,
        depth: 2,
        window: 10,
        lock_blocks: 6,
        downtime: 2,
        sweep_blocks: 6,
        min_fee_rate: FeeRate::from_sat_per_vb_u32(1),
        ..deposit::Config::new(sweep_to())
    }
}

/// Its window, depth, lock blocks, the lock's depth, downtime and sweep
/// blocks.
const TIMEOUT: u32 = 10 + 2 + 6 + 1 + 2 + 6;

/// A hub taking deposits, it and its gateway following one chain.
struct Net {
    hub: Arc<Hub>,
    deposits: Arc<deposit::Gateway>,
    source: Source,
    app: Router,
    backend: esplora::Shared,
    dir: tempfile::TempDir,
}

impl Net {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, 12).unwrap();
        let policy = Policy {
            timing: TIMING,
            ..Policy::default()
        };
        let hub = Arc::new(Hub::open(&seed, &db, policy).unwrap());
        let chain = chain::Chain::new();
        hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
        let backend = esplora::backend(chain);
        let source: Source = esplora::serve(backend.clone()).parse().unwrap();
        let deposits = Arc::new(gateway(&hub, &source, &dir.path().join("hub.sqlite")));
        let services = Services {
            deposits: Some(deposits.clone()),
            ..Default::default()
        };
        let net = Self {
            app: licash_hub_service::router(hub.clone(), services),
            hub,
            deposits,
            source,
            backend,
            dir,
        };
        net.mine(3, Vec::new());
        // Scanning from the tip on.
        net.deposits.round().await;
        net
    }

    /// Mine `blocks`, the first with `txs`, which the hub scans.
    fn mine(&self, blocks: u32, mut txs: Vec<Transaction>) {
        let mut backend = self.backend.lock().unwrap();
        for _ in 0..blocks {
            let txs = std::mem::take(&mut txs);
            let ids: Vec<Txid> = txs.iter().map(Transaction::compute_txid).collect();
            backend.mempool.retain(|t| !ids.contains(&t.compute_txid()));
            let block = backend.chain.mine_with(None, txs).clone();
            self.hub.observe(backend.chain.height(), &block).unwrap();
        }
        let (height, tip) = (backend.chain.height(), backend.chain.tip());
        assert!(self.hub.synced(height, &tip).unwrap());
    }

    /// Mine what was sent, in one block.
    fn confirm_sent(&self) -> Vec<Transaction> {
        let sent = std::mem::take(&mut self.backend.lock().unwrap().mempool);
        self.mine(1, sent.clone());
        sent
    }

    /// Leave the blocks from `height` on, for others mined after.
    fn fork(&self, height: u32) {
        let mut backend = self.backend.lock().unwrap();
        backend.chain.blocks.truncate(height as usize);
        self.hub.rewind(height).unwrap();
    }

    fn height(&self) -> u32 {
        self.backend.lock().unwrap().chain.height()
    }

    fn sent(&self) -> Vec<Transaction> {
        self.backend.lock().unwrap().mempool.clone()
    }

    fn wallet(&self, name: &str) -> Wallet<Local> {
        let path = self.dir.path().join(format!("{name}.sqlite"));
        let mut seed = [0; 32];
        seed[..name.len()].copy_from_slice(name.as_bytes());
        let network = ChainProfile::Core30DefaultRegtest;
        Wallet::create(&path, &seed, network, Local(self.app.clone())).unwrap()
    }

    /// What the wallet `name` recorded of its deposit of `hash`: the
    /// preimage and the body it asked with.
    fn asked(&self, name: &str, hash: &str) -> ([u8; 32], licash_api::Deposit) {
        let path = self.dir.path().join(format!("{name}.sqlite"));
        let db = rusqlite::Connection::open(path).unwrap();
        let (preimage, body): ([u8; 32], String) = db
            .query_row(
                "SELECT preimage, body FROM deposits WHERE hash = ?1",
                [bytes(hash)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        (preimage, serde_json::from_str(&body).unwrap())
    }

    async fn info(&self) -> Info {
        let response = Local(self.app.clone())
            .request(&format!("{HUB}{}", licash_api::INFO), None)
            .await
            .unwrap();
        serde_json::from_slice(&response.body).unwrap()
    }
}

/// A gateway of `hub`'s deposits over `source`, kept at `path`.
fn gateway(hub: &Arc<Hub>, source: &Source, path: &std::path::Path) -> deposit::Gateway {
    let profile = ChainProfile::Core30DefaultRegtest;
    deposit::Gateway::open(hub.clone(), source.clone(), profile, config(), path).unwrap()
}

/// A payment of `value` to `address`, from coins of the `n`th payer.
fn payment(address: &str, value: u64, n: u8) -> Transaction {
    let address: Address<_> = address.parse().unwrap();
    Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([n; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: address.assume_checked().script_pubkey(),
        }],
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

fn alerts(hub: &Hub) -> Vec<String> {
    let events = hub.events(0, 1000).unwrap();
    let alerts = events.into_iter().filter(|e| e.kind == "alert");
    alerts.map(|e| e.data.to_string()).collect()
}

/// The service's router, reached at [`HUB`].
#[derive(Clone)]
struct Local(Router);

impl Transport for Local {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<licash_wallet::Response, String>> + Send {
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
            Ok(licash_wallet::Response {
                status,
                body: body.to_vec(),
            })
        }
    }
}

fn lightning(net: &Net) -> (Arc<Fake>, Arc<lightning::Gateway>) {
    let node = Arc::new(Fake::new());
    let backend = net.backend.lock().unwrap();
    node.tip(backend.chain.height(), backend.chain.tip());
    drop(backend);
    let config = lightning::Config {
        hold_delta: 3,
        downtime: 2,
        receive_blocks: 6,
        ..lightning::Config::default()
    };
    let gateway = lightning::Gateway::open(
        net.hub.clone(),
        node.clone(),
        config,
        &net.dir.path().join("hub.sqlite"),
    )
    .unwrap();
    (node, Arc::new(gateway))
}

fn swap_record(net: &Net, hash: [u8; 32], state: &str, lock: Option<licash::spend::ProposalId>) {
    let dir = net.dir.path().join("swaps");
    std::fs::create_dir(&dir).unwrap();
    // As the swap provider keeps its swaps, in its wallet's file: but for
    // the columns these gateways read.
    let mut db =
        licash_store::create(&dir.join("wallet.sqlite"), licash_store::Kind::Wallet).unwrap();
    licash_store::component(
        &mut db,
        "provider",
        1,
        "CREATE TABLE provider_swaps (hash BLOB PRIMARY KEY, state TEXT, lock BLOB) STRICT;
         CREATE TABLE provider_donations (hash BLOB PRIMARY KEY) STRICT;",
    )
    .unwrap();
    db.execute(
        "INSERT INTO provider_swaps (hash, state, lock) VALUES (?1, ?2, ?3)",
        rusqlite::params![hash, state, lock.map(|id| *id.as_bytes())],
    )
    .unwrap();
}

/// One snapshot of the hub's database holds its ledger and its deposits
/// alike, as of one moment: a hub restored from it, with its seed, answers
/// a deposit asked before as it did, and records no other.
#[tokio::test]
async fn one_snapshot_of_the_hubs_database_restores_its_deposits_with_its_ledger() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &deposit.hash);
    let answered = net.deposits.deposit(&body, None).await.unwrap();

    // A connection of its own to the running hub's file: its snapshot.
    let conn =
        licash_store::open(&net.dir.path().join("hub.sqlite"), licash_store::Kind::Hub).unwrap();
    let copy = tempfile::tempdir().unwrap();
    let snapshot = copy.path().join("hub.sqlite");
    licash_store::backup(&conn, &snapshot).unwrap();
    std::fs::copy(net.dir.path().join("seed"), copy.path().join("seed")).unwrap();

    let policy = Policy {
        timing: TIMING,
        ..Policy::default()
    };
    let hub = Arc::new(Hub::open(&copy.path().join("seed"), &snapshot, policy).unwrap());
    let restored = gateway(&hub, &net.source, &snapshot);
    assert_eq!(restored.deposit(&body, None).await.unwrap(), answered);
    let held = rusqlite::Connection::open(&snapshot)
        .unwrap()
        .query_row("SELECT count(*) FROM deposits", [], |r| r.get::<_, i64>(0))
        .unwrap();
    assert_eq!(held, 1);
}

#[tokio::test]
async fn gateways_refuse_every_hash_reserved_by_a_swap_even_when_swaps_are_off() {
    for state in ["accepted", "locked", "failed", "done"] {
        let net = Net::new().await;
        let alice = net.wallet("alice");
        let deposit = alice.deposit(HUB, 3_000).await.unwrap();
        let (_, body) = net.asked("alice", &deposit.hash);
        let hash = bytes(&deposit.hash);
        // Reuse the request, but no gateway has reserved it yet.
        let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
        db.execute("DELETE FROM deposits WHERE hash = ?1", [hash])
            .unwrap();
        swap_record(&net, hash, state, None);
        let (_, lightning) = lightning(&net);
        peer::coordinate(
            Some(&lightning),
            Some(&net.deposits),
            net.dir.path(),
            Arc::new(tokio::sync::Mutex::new(())),
        );
        assert!(net
            .deposits
            .deposit(&body, None)
            .await
            .unwrap_err()
            .0
            .message
            .contains("another payment"));
        assert!(lightning
            .receive(&body.receive, None)
            .await
            .unwrap_err()
            .0
            .message
            .contains("another payment"));
    }
}

#[tokio::test]
async fn a_disabled_receipt_gateway_still_reserves_its_hashes() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &deposit.hash);
    let hash = bytes(&deposit.hash);
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    db.execute("DELETE FROM deposits WHERE hash = ?1", [hash])
        .unwrap();
    let (_, lightning) = lightning(&net);
    lightning.receive(&body.receive, None).await.unwrap();
    drop(lightning);
    peer::coordinate(
        None,
        Some(&net.deposits),
        net.dir.path(),
        Arc::new(tokio::sync::Mutex::new(())),
    );
    assert!(net
        .deposits
        .deposit(&body, None)
        .await
        .unwrap_err()
        .0
        .message
        .contains("another payment"));
    assert!(!net.dir.path().join("swaps").exists());
}

#[tokio::test]
async fn a_gateway_waits_for_the_issuers_turn_and_then_sees_its_reservation() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &deposit.hash);
    let hash = bytes(&deposit.hash);
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    db.execute("DELETE FROM deposits WHERE hash = ?1", [hash])
        .unwrap();
    let turn = Arc::new(tokio::sync::Mutex::new(()));
    peer::coordinate(None, Some(&net.deposits), net.dir.path(), turn.clone());
    let held = turn.lock_owned().await;
    let gateway = net.deposits.clone();
    let receiving = tokio::spawn(async move { gateway.deposit(&body, None).await });
    tokio::task::yield_now().await;
    assert!(!receiving.is_finished());
    swap_record(&net, hash, "accepted", None);
    drop(held);
    assert!(receiving
        .await
        .unwrap()
        .unwrap_err()
        .0
        .message
        .contains("another payment"));
}

async fn adoption_with_a_swap_row(state: &str, recorded: bool) {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &deposit.hash);
    let ((keyset, ephemeral, hash), outputs) = (
        body.receive.terms().unwrap(),
        body.receive.outputs().unwrap(),
    );
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
        .lock_own(&keyset, ephemeral, outputs, terms)
        .unwrap();
    let id = lock.proposal.id();
    swap_record(&net, hash, state, recorded.then_some(id));
    peer::coordinate(
        None,
        Some(&net.deposits),
        net.dir.path(),
        Arc::new(tokio::sync::Mutex::new(())),
    );
    net.mine(2, vec![payment(&deposit.terms.unwrap().address, 3_100, 1)]);
    net.deposits.round().await;
    let status = net.deposits.deposit_status(&hash).unwrap().status;
    if recorded {
        assert_eq!(status.state, ReceiveState::Canceled);
        assert!(status.lock.is_none());
        assert!(alerts(&net.hub)
            .iter()
            .any(|a| a.contains("locked for a swap")));
    } else {
        assert_eq!(status.state, ReceiveState::Locked);
        assert_eq!(status.lock().unwrap(), Some(id));
    }
}

#[tokio::test]
async fn a_gateway_never_adopts_a_lock_the_swap_store_recorded() {
    adoption_with_a_swap_row("locked", true).await;
}

#[tokio::test]
async fn a_gateway_recovers_its_own_unrecorded_lock_beside_an_accepted_or_failed_swap() {
    adoption_with_a_swap_row("accepted", false).await;
    adoption_with_a_swap_row("failed", false).await;
}

/// A dishonest status is not proof that the preimage is already public.
#[derive(Clone)]
struct PaidView(Local);

impl Transport for PaidView {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        let mut response = self.0.request(url, body).await?;
        if url.contains("/v1/lock/") && response.status == 200 {
            let mut state: licash_api::LockState = serde_json::from_slice(&response.body).unwrap();
            state.settled = Some(licash_api::Settled::Pay);
            response.body = serde_json::to_vec(&state).unwrap();
        }
        Ok(response)
    }
}

async fn short_deposit_lock(claimed_paid: bool) {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &deposit.hash);
    let ((keyset, ephemeral, hash), outputs) = (
        body.receive.terms().unwrap(),
        body.receive.outputs().unwrap(),
    );
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
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    db.execute(
        "UPDATE deposits SET lock = ?1, state = 'locked' WHERE hash = ?2",
        rusqlite::params![id.as_bytes(), hash],
    )
    .unwrap();
    let expected = DepositState::Canceled(format!("its lock pays {amount} of 3000"));
    if claimed_paid {
        drop(alice);
        let alice = Wallet::open(
            &net.dir.path().join("alice.sqlite"),
            PaidView(Local(net.app.clone())),
        )
        .unwrap();
        assert_eq!(
            alice.follow_deposit(&deposit.hash).await.unwrap().state,
            expected
        );
    } else {
        assert_eq!(
            alice.follow_deposit(&deposit.hash).await.unwrap().state,
            expected
        );
        let timeout = deposit.terms.unwrap().timeout;
        assert!(alice
            .deposits_to_refund(timeout)
            .unwrap()
            .iter()
            .any(|d| d.hash == deposit.hash));
    }
    let lock = net.hub.locked(&id).unwrap();
    assert_eq!((lock.preimage, lock.settled), (None, None));
}

#[tokio::test]
async fn a_short_deposit_lock_does_not_receive_the_full_deposits_preimage() {
    short_deposit_lock(false).await;
}

#[tokio::test]
async fn a_hubs_paid_status_does_not_bypass_the_deposit_value_check() {
    short_deposit_lock(true).await;
}

#[tokio::test]
async fn deposits_and_receipts_refuse_hashes_held_by_the_other_gateway() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &deposit.hash);
    let (_, lightning) = lightning(&net);
    peer::pair(&lightning, &net.deposits);
    let refused = lightning.receive(&body.receive, None).await.unwrap_err().0;
    assert_eq!(refused.code, Code::Forward);
    assert!(refused.message.contains("another payment"));
    let mut other = body.clone();
    other.receive.hash = licash_api::Hex(vec![42; 32]);
    lightning.receive(&other.receive, None).await.unwrap();
    let refused = net.deposits.deposit(&other, None).await.unwrap_err().0;
    assert_eq!(refused.code, Code::Forward);
    assert!(refused.message.contains("another payment"));
}

#[tokio::test]
async fn a_duplicate_deposit_is_canceled_when_its_receipt_locked_first() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &deposit.hash);
    let hash = bytes(&deposit.hash);
    let (node, lightning) = lightning(&net);
    lightning.receive(&body.receive, None).await.unwrap();
    peer::pair(&lightning, &net.deposits);
    let cltv = node.held_cltv(hash).unwrap() as u32;
    node.pay_held(hash, net.height() + cltv);
    lightning.round().await;
    let receipt = lightning.receive_status(&hash).unwrap();
    assert_eq!(receipt.state, ReceiveState::Locked);
    let lock = receipt.lock().unwrap().unwrap();
    net.mine(2, vec![payment(&deposit.terms.unwrap().address, 3_100, 1)]);
    net.deposits.round().await;
    let status = net.deposits.deposit_status(&hash).unwrap().status;
    assert_eq!(status.state, ReceiveState::Canceled);
    assert_eq!(status.lock, None);
    assert_eq!(
        net.hub.own_lock_of(&hash).unwrap().unwrap().proposal.id(),
        lock
    );
    assert!(alerts(&net.hub)
        .iter()
        .any(|a| a.contains("locked for a Lightning receipt")));
}

#[tokio::test]
async fn a_duplicate_receipt_is_canceled_when_its_deposit_locked_first() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &deposit.hash);
    let hash = bytes(&deposit.hash);
    let (node, lightning) = lightning(&net);
    lightning.receive(&body.receive, None).await.unwrap();
    peer::pair(&lightning, &net.deposits);
    net.mine(2, vec![payment(&deposit.terms.unwrap().address, 3_100, 1)]);
    net.deposits.round().await;
    let status = net.deposits.deposit_status(&hash).unwrap().status;
    assert_eq!(status.state, ReceiveState::Locked);
    let lock = status.lock().unwrap().unwrap();
    let cltv = node.held_cltv(hash).unwrap() as u32;
    node.pay_held(hash, net.height() + cltv);
    lightning.round().await;
    let receipt = lightning.receive_status(&hash).unwrap();
    assert_eq!(receipt.state, ReceiveState::Canceled);
    assert_eq!(receipt.lock, None);
    assert_eq!(node.held(hash).unwrap().0, HeldState::Canceled);
    assert_eq!(
        net.hub.own_lock_of(&hash).unwrap().unwrap().proposal.id(),
        lock
    );
    assert!(alerts(&net.hub)
        .iter()
        .any(|a| a.contains("locked for a deposit")));
}

/// A deposit asked while the hub's scan is behind its node gets its whole
/// window from the node's tip: not from where the scan is, which would
/// leave it none once the scan caught up.
#[tokio::test]
async fn a_deposit_asked_while_the_scan_lags_keeps_its_whole_window() {
    let net = Net::new().await;
    let deposits = net.info().await.deposits.unwrap();
    // Blocks the node has and the hub has not scanned.
    let lag = 4;
    {
        let mut backend = net.backend.lock().unwrap();
        for _ in 0..lag {
            backend.chain.mine_with(None, Vec::new());
        }
    }
    let tip = net.backend.lock().unwrap().chain.height();
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let terms = deposit.terms.unwrap();
    assert_eq!(terms.fund_by, tip + deposits.window);
}

#[tokio::test]
async fn a_deposit_paid_at_depth_is_received_and_its_coins_claimed() {
    let net = Net::new().await;
    let asked_at = net.height();
    let deposits = net.info().await.deposits.unwrap();
    assert_eq!(
        (deposits.fee, deposits.min, deposits.max),
        (Fee { base: 100, ppm: 0 }, 1_000, 4_000)
    );
    assert_eq!(
        (deposits.depth, deposits.window, deposits.timeout),
        (2, 10, TIMEOUT)
    );
    let alice = net.wallet("alice");
    // Outside what the hub takes, refused before asking.
    for amount in [999, 4_001] {
        let refused = alice.deposit(HUB, amount).await;
        assert!(
            matches!(refused, Err(licash_wallet::Error::Invalid(_))),
            "{refused:?}"
        );
    }
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    assert_eq!(deposit.state, DepositState::Open);
    let terms = deposit.terms.clone().unwrap();
    assert!(terms.address.starts_with("bcrt1p"), "{}", terms.address);
    assert_eq!(terms.pays, 3_100);
    assert_eq!(
        (terms.fund_by, terms.timeout),
        (asked_at + 10, asked_at + TIMEOUT)
    );
    // The same deposit asked again: the same terms; another under its
    // hash, refused.
    let (preimage, body) = net.asked("alice", &deposit.hash);
    let again = net.deposits.deposit(&body, None).await.unwrap();
    assert_eq!(
        (again.address.as_str(), again.amount),
        (terms.address.as_str(), 3_100)
    );
    let mut other = body.clone();
    other.refund = licash_api::Hex(vec![2; 32]);
    let refused = net.deposits.deposit(&other, None).await.unwrap_err();
    assert_eq!(refused.0.code, Code::Forward);

    // Paid: seen, but not at depth.
    net.mine(1, vec![payment(&terms.address, 3_100, 1)]);
    net.deposits.round().await;
    let paid = alice.follow_deposit(&deposit.hash).await.unwrap();
    assert_eq!(paid.state, DepositState::Open);
    let (funding, height) = paid.funding.unwrap();
    assert_eq!(height, asked_at + 1);
    assert_eq!(available(&alice), 0);
    // At depth: the hub's notes, claimed.
    net.mine(1, Vec::new());
    net.deposits.round().await;
    let hash = bytes(&deposit.hash);
    assert_eq!(
        net.deposits.deposit_status(&hash).unwrap().status.state,
        ReceiveState::Locked
    );
    let received = alice.follow_deposit(&deposit.hash).await.unwrap();
    assert_eq!(received.state, DepositState::Received);
    assert_eq!(available(&alice), 3_000);
    // Claimed, its coins are the hub's.
    let refund = alice.refund_deposit(
        &deposit.hash,
        funding,
        Amount::from_sat(3_100),
        sweep_to(),
        FeeRate::from_sat_per_vb_u32(1),
    );
    assert!(
        matches!(refund, Err(licash_wallet::Error::Invalid(_))),
        "{refund:?}"
    );

    // The hub settles, then claims the coins with the preimage, at the
    // rate the chain estimates.
    net.deposits.round().await;
    assert_eq!(
        net.deposits.deposit_status(&hash).unwrap().status.state,
        ReceiveState::Settled
    );
    net.deposits.round().await;
    let sent = net.sent();
    assert_eq!(sent.len(), 1);
    let claim = &sent[0];
    assert_eq!(claim.input[0].previous_output, funding);
    assert_eq!(claim.input[0].witness.nth(1).unwrap(), preimage);
    assert_eq!(claim.output[0].script_pubkey, sweep_to());
    let fee = 3_100 - claim.output[0].value.to_sat();
    assert_eq!(
        FeeRate::from_sat_per_vb_u32(3)
            .fee_wu(claim.weight())
            .unwrap()
            .to_sat(),
        fee
    );
    // Sent again each round until confirmed, the same.
    net.deposits.round().await;
    assert_eq!(net.sent(), sent);
    net.confirm_sent();
    net.deposits.round().await;
    net.deposits.round().await;
    assert!(net.sent().is_empty());
    assert_eq!(
        net.deposits.deposit_status(&hash).unwrap().status.state,
        ReceiveState::Settled
    );
    assert!(alerts(&net.hub).is_empty(), "{:?}", alerts(&net.hub));
    let resumed = alice.resume().await.unwrap();
    assert!(resumed.deposits.is_empty() && resumed.pending.is_empty());
    assert_eq!(alice.deposits().unwrap(), vec![received]);
}

#[tokio::test]
async fn a_deposit_claim_left_unmined_pays_more_as_its_timeout_nears_and_any_of_them_is_the_hubs() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let terms = deposit.terms.clone().unwrap();
    net.mine(1, vec![payment(&terms.address, 3_100, 1)]);
    net.mine(1, Vec::new());
    net.deposits.round().await;
    // Its notes claimed, the hub settles and claims the coins.
    let received = alice.follow_deposit(&deposit.hash).await.unwrap();
    assert_eq!(received.state, DepositState::Received);
    net.deposits.round().await;
    net.deposits.round().await;
    let hash = bytes(&deposit.hash);
    let fee = |tx: &Transaction| 3_100 - tx.output[0].value.to_sat();
    let at = |rate, tx: &Transaction| {
        let rate = FeeRate::from_sat_per_vb_u32(rate);
        rate.fee_wu(tx.weight()).unwrap().to_sat()
    };
    let sent = net.sent();
    assert_eq!(sent.len(), 1);
    let first = sent[0].clone();
    // Far from its timeout, at the estimate.
    assert_eq!(fee(&first), at(3, &first));
    // Unmined until 11 blocks are left: made again, at twice it.
    net.mine(terms.timeout - 11 - net.height(), Vec::new());
    net.deposits.round().await;
    let sent = net.sent();
    assert_eq!(sent.len(), 2);
    let second = &sent[1];
    assert_eq!(
        second.input[0].previous_output,
        first.input[0].previous_output
    );
    assert_eq!(fee(second), at(6, second));
    // Broadcast again, not made again, while the rate is its own.
    net.deposits.round().await;
    assert_eq!(net.sent().len(), 2);
    // The first mined after all: the hub's still.
    net.mine(1, vec![first]);
    net.deposits.round().await;
    assert_eq!(
        net.deposits.deposit_status(&hash).unwrap().status.state,
        ReceiveState::Settled
    );
    assert!(alerts(&net.hub).is_empty(), "{:?}", alerts(&net.hub));
}

#[tokio::test]
async fn deposits_paid_wrong_late_or_never_lock_nothing_and_are_refunded() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let short = alice.deposit(HUB, 2_000).await.unwrap();
    let never = alice.deposit(HUB, 2_000).await.unwrap();
    let late = alice.deposit(HUB, 2_000).await.unwrap();
    let address = |d: &licash_wallet::Deposit| d.terms.clone().unwrap().address;
    let underpaid = payment(&address(&short), 2_099, 1);
    net.mine(1, vec![underpaid.clone()]);
    // Paid one block after the last it may confirm in.
    let fund_by = late.terms.clone().unwrap().fund_by;
    net.mine(fund_by - net.height(), Vec::new());
    net.deposits.round().await;
    net.mine(1, vec![payment(&address(&late), 2_100, 2)]);
    net.mine(2, Vec::new());
    net.deposits.round().await;
    for deposit in [&short, &never, &late] {
        let hash = bytes(&deposit.hash);
        let status = net.deposits.deposit_status(&hash).unwrap();
        assert_eq!(
            status.status.state,
            ReceiveState::Canceled,
            "{}",
            deposit.hash
        );
        assert_eq!(status.funding, None);
        let followed = alice.follow_deposit(&deposit.hash).await.unwrap();
        assert_eq!(
            followed.state,
            DepositState::Canceled("canceled by its hub".into())
        );
    }
    assert_eq!(available(&alice), 0);
    assert!(alice.resume().await.unwrap().deposits.is_empty());

    // Taken back after the timeout, again at a higher rate.
    let funding = OutPoint {
        txid: underpaid.compute_txid(),
        vout: 0,
    };
    let to = payment(&address(&never), 0, 0).output[0]
        .script_pubkey
        .clone();
    let refund = |rate| {
        let value = Amount::from_sat(2_099);
        alice.refund_deposit(
            &short.hash,
            funding,
            value,
            to.clone(),
            FeeRate::from_sat_per_vb_u32(rate),
        )
    };
    let first = refund(1).unwrap();
    let timeout = short.terms.clone().unwrap().timeout;
    assert_eq!(first.lock_time.to_consensus_u32(), timeout);
    assert_eq!(first.input[0].previous_output, funding);
    assert_eq!(first.output[0].script_pubkey, to);
    assert_eq!(first.input[0].witness.len(), 3);
    let state = alice.deposit_of(&short.hash).unwrap().state;
    assert_eq!(state, DepositState::Refunded(first.compute_txid()));
    let second = refund(5).unwrap();
    assert!(second.output[0].value < first.output[0].value);
    let state = alice.deposit_of(&short.hash).unwrap().state;
    assert_eq!(state, DepositState::Refunded(second.compute_txid()));
    // Too small to pay its fee.
    let dust = alice.refund_deposit(
        &never.hash,
        funding,
        Amount::from_sat(400),
        to,
        FeeRate::from_sat_per_vb_u32(5),
    );
    assert!(
        matches!(dust, Err(licash_wallet::Error::Invalid(_))),
        "{dust:?}"
    );
}

#[tokio::test]
async fn a_deposit_paid_an_amount_exactly_is_given_up_unpaid_or_refunded_once_due() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    // Paid 3,100 exactly: 3,000 in notes, the hub's 100 in it.
    let paid = alice.deposit_paying(HUB, 3_100).await.unwrap();
    let terms = paid.terms.clone().unwrap();
    assert_eq!((paid.amount, terms.pays), (3_000, 3_100));
    // No notes within its limits come to it, the fee in it.
    for pays in [50, 1_099, 4_101] {
        let refused = alice.deposit_paying(HUB, pays).await;
        assert!(
            matches!(refused, Err(licash_wallet::Error::Invalid(_))),
            "{refused:?}"
        );
    }
    // Given up unpaid, once.
    let unpaid = alice.deposit_paying(HUB, 2_100).await.unwrap();
    alice
        .give_up_deposit(&unpaid.hash, "its F given up")
        .unwrap();
    let state = alice.deposit_of(&unpaid.hash).unwrap().state;
    assert_eq!(state, DepositState::Canceled("its F given up".into()));
    assert!(alice.give_up_deposit(&unpaid.hash, "again").is_err());

    // Paid, seen by its hub: not given up.
    let tx = payment(&terms.address, 3_100, 1);
    net.mine(1, vec![tx.clone()]);
    net.deposits.round().await;
    let seen = alice.follow_deposit(&paid.hash).await.unwrap();
    let funding = OutPoint {
        txid: tx.compute_txid(),
        vout: 0,
    };
    assert_eq!(seen.funding.map(|(f, _)| f), Some(funding));
    assert!(alice.give_up_deposit(&paid.hash, "too late").is_err());
    // At depth its notes are locked, and left unclaimed until the hub
    // takes them back: canceled.
    net.mine(1, Vec::new());
    net.deposits.round().await;
    for _ in 0..8 {
        net.mine(1, Vec::new());
        net.deposits.round().await;
    }
    let over = alice.follow_deposit(&paid.hash).await.unwrap();
    assert!(
        matches!(over.state, DepositState::Canceled(_)),
        "{:?}",
        over.state
    );
    assert_eq!(over.funding.map(|(f, _)| f), Some(funding));
    assert_eq!(available(&alice), 0);

    // Due once past its timeout, with the payment its hub saw; the one
    // given up too, unpaid as far as the wallet knows.
    let due = |tip| -> Vec<String> {
        let due = alice.deposits_to_refund(tip).unwrap();
        due.into_iter().map(|d| d.hash).collect()
    };
    assert!(due(terms.timeout - 1).is_empty());
    let both = due(terms.timeout + 1);
    assert!(
        both.contains(&paid.hash) && both.contains(&unpaid.hash),
        "{both:?}"
    );
    assert_eq!(alice.deposit_refund(&paid.hash).unwrap(), None);
    let to = payment(&terms.address, 0, 0).output[0]
        .script_pubkey
        .clone();
    let rate = FeeRate::from_sat_per_vb_u32(1);
    let value = Amount::from_sat(3_100);
    let refund = alice
        .refund_deposit(&paid.hash, funding, value, to, rate)
        .unwrap();
    assert_eq!(alice.deposit_refund(&paid.hash).unwrap(), Some(refund));
    assert_eq!(due(terms.timeout + 1), std::slice::from_ref(&unpaid.hash));
    assert!(alice.deposit_refund("00").is_err());
}

#[tokio::test]
async fn a_wallet_restored_from_its_seed_finds_the_deposits_it_asked_and_takes_them_on() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    // Two asked, one paid, then the wallet's file lost.
    let paid = alice.deposit(HUB, 3_000).await.unwrap();
    let unpaid = alice.deposit_paying(HUB, 2_100).await.unwrap();
    let terms = paid.terms.clone().unwrap();
    net.mine(1, vec![payment(&terms.address, 3_100, 1)]);
    net.deposits.round().await;
    let asked = alice.deposits().unwrap();
    drop(alice);

    // The same seed, a new file: adding the hub finds both, as they were
    // asked and answered, the payment as its hub saw it.
    let path = net.dir.path().join("restored.sqlite");
    let mut seed = [0; 32];
    seed[..5].copy_from_slice(b"alice");
    let network = ChainProfile::Core30DefaultRegtest;
    let restored = Wallet::create(&path, &seed, network, Local(net.app.clone())).unwrap();
    restored.add_hub(HUB).await.unwrap();
    let found = restored.deposits().unwrap();
    let key = |d: &licash_wallet::Deposit| (d.hash.clone(), d.amount, d.terms.clone());
    let mut want: Vec<_> = asked.iter().map(key).collect();
    let mut got: Vec<_> = found.iter().map(key).collect();
    want.sort_by(|a, b| a.0.cmp(&b.0));
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(got, want);
    // Taken on: the paid one received at depth.
    net.mine(1, Vec::new());
    net.deposits.round().await;
    let received = restored.follow_deposit(&paid.hash).await.unwrap();
    assert_eq!(received.state, DepositState::Received);
    assert_eq!(available(&restored), 3_000);
    // Looked for again, none new; the next one asked under a hash of its
    // own, the hub answering it.
    assert!(restored.find_deposits(HUB).await.unwrap().is_empty());
    let next = restored.deposit(HUB, 1_000).await.unwrap();
    assert!(next.terms.is_some(), "{next:?}");
    assert!(![&paid.hash, &unpaid.hash].contains(&&next.hash));

    // Another seed's wallet finds none of them.
    let bob = net.wallet("bob");
    bob.add_hub(HUB).await.unwrap();
    assert!(bob.deposits().unwrap().is_empty());
}

/// What a hub answers of where a deposit stands, of what the hub behind it
/// answered.
type Stands = Box<dyn Fn(licash_wallet::Response) -> licash_wallet::Response + Send + Sync>;

/// The hub behind a front that answers what it likes of where a deposit
/// stands, counting the times it is asked: a hub lying to a wallet looking
/// for the deposits of its seed.
struct Lying {
    hub: Local,
    stands: Stands,
    asked: Arc<AtomicU32>,
}

impl Transport for Lying {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        let stands = body.is_none() && url.contains("/v1/deposit/");
        let response = self.hub.request(url, body).await?;
        if !stands {
            return Ok(response);
        }
        // A wallet asking without end fails its test, rather than never
        // ending it.
        let asked = self.asked.fetch_add(1, Ordering::SeqCst);
        assert!(asked < 1_000, "asked where a deposit stands without end");
        Ok((self.stands)(response))
    }
}

/// A wallet of the seed of the wallet `name`, its file lost, kept at `file`
/// and reaching the hub through a front answering `stands` of where a
/// deposit stands; and the times the front was asked that.
fn restored_behind(
    net: &Net,
    name: &str,
    file: &str,
    stands: Stands,
) -> (Wallet<Lying>, Arc<AtomicU32>) {
    let mut seed = [0; 32];
    seed[..name.len()].copy_from_slice(name.as_bytes());
    let asked = Arc::new(AtomicU32::new(0));
    let front = Lying {
        hub: Local(net.app.clone()),
        stands,
        asked: asked.clone(),
    };
    let path = net.dir.path().join(file);
    let network = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(&path, &seed, network, front).unwrap();
    (wallet, asked)
}

/// Record `coin` as one the wallet of the file at `path` found and spent,
/// as a scan of its payments finds it again: one that may have opened a
/// contract.
fn found_spent(path: &std::path::Path, coin: OutPoint) {
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute(
        "INSERT INTO silent_coins (txid, vout, value, output, tweak, height, spent_by, spent_height)
         VALUES (?1, ?2, 10000, x'00', x'00', 1, ?3, 2)",
        rusqlite::params![coin.txid.to_byte_array(), coin.vout, [9u8; 32]],
    )
    .unwrap();
}

/// A hub's answer of where a deposit stands, changed by `change` if it
/// answered one.
fn changed(change: impl Fn(&mut DepositStatus) + Send + Sync + 'static) -> Stands {
    Box::new(move |response| {
        let Ok(mut status) = serde_json::from_slice::<DepositStatus>(&response.body) else {
            return response;
        };
        change(&mut status);
        licash_wallet::Response {
            status: response.status,
            body: serde_json::to_vec(&status).unwrap(),
        }
    })
}

#[tokio::test]
async fn a_deposit_answered_other_than_asked_is_not_taken_on_by_a_wallet_restored_from_its_seed() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let asked = alice.deposit(HUB, 3_000).await.unwrap();
    let (close, _) = close_deposit(&net, &alice).await;
    drop(alice);
    let other = licash::address::Ephemeral::random().public();
    let lies: Vec<(&str, Stands)> = vec![
        // Fewer notes for the same payment: the rest of it its hub's.
        (
            "fewer notes",
            changed(|s| {
                s.request.as_mut().unwrap().receive.outputs.pop();
            }),
        ),
        (
            "a larger payment",
            changed(|s| s.terms.as_mut().unwrap().amount += 1),
        ),
        (
            "a smaller payment",
            changed(|s| s.terms.as_mut().unwrap().amount -= 1),
        ),
        (
            "outputs under another key",
            changed(move |s| {
                s.request.as_mut().unwrap().receive.ephemeral = Hex(other.0.to_vec());
            }),
        ),
        // One a contract's close as one that is none, and the other way.
        (
            "another kind",
            changed(|s| {
                let request = s.request.as_mut().unwrap();
                let pays = s.terms.as_ref().unwrap().amount;
                request.close = match request.close {
                    Some(_) => None,
                    None => Some(licash_api::CloseTerms { pays, until: 500 }),
                };
            }),
        ),
        ("nothing asked", changed(|s| s.request = None)),
    ];
    for (n, (what, stands)) in lies.into_iter().enumerate() {
        let file = format!("lied{n}.sqlite");
        let (restored, _) = restored_behind(&net, "alice", &file, stands);
        found_spent(&net.dir.path().join(file), opening_coin());
        restored.add_hub(HUB).await.unwrap();
        assert_eq!(restored.deposits().unwrap(), Vec::new(), "{what}");
    }
    // As they were asked, both are found: the close, by its hub's root and
    // the coin, found again, that opened its contract.
    let (restored, _) = restored_behind(&net, "alice", "told.sqlite", changed(|_| ()));
    found_spent(&net.dir.path().join("told.sqlite"), opening_coin());
    restored.add_hub(HUB).await.unwrap();
    let found = restored.deposits().unwrap();
    let mut got: Vec<_> = found.iter().map(|d| (d.hash.clone(), d.amount)).collect();
    got.sort();
    let mut want = vec![(asked.hash.clone(), 3_000), (close.hash.clone(), 2_900)];
    want.sort();
    assert_eq!(got, want);
    let pays = |hash: &str| restored.deposit_of(hash).unwrap().terms.unwrap().pays;
    assert_eq!((pays(&asked.hash), pays(&close.hash)), (3_100, 3_000));
}

#[tokio::test]
async fn a_number_asked_again_of_a_hub_that_hid_its_deposit_is_under_another_hash() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let first = alice.deposit(HUB, 3_000).await.unwrap();
    drop(alice);
    // Her file lost, her hub answers that it knows no deposit of hers.
    let hidden: Stands = Box::new(|_| {
        let problem = Problem::new(Code::UnknownLock, "no deposit under this refund key");
        licash_wallet::Response {
            status: problem.code.status(),
            body: serde_json::to_vec(&problem).unwrap(),
        }
    });
    let (restored, _) = restored_behind(&net, "alice", "restored.sqlite", hidden);
    restored.add_hub(HUB).await.unwrap();
    assert_eq!(restored.deposits().unwrap(), Vec::new());
    // The same number, so the same refund key, and the same notes for the
    // same payment: yet no hash of the first, whose preimage would claim
    // the first's coins as it claims the second's notes.
    let again = restored.deposit(HUB, 3_000).await.unwrap();
    assert_ne!(again.hash, first.hash);
    // A hub that hid nothing takes one deposit under a refund key.
    assert!(
        matches!(&again.state, DepositState::Canceled(why) if why.contains("refund key")),
        "{again:?}"
    );
}

#[tokio::test]
async fn a_coin_asks_a_close_deposit_again_under_an_attempt_neither_wallet_nor_hub_knows() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    // Her opening asked again of the same coin: another deposit.
    let (first, until) = close_deposit(&net, &alice).await;
    let again = alice.close_deposit(HUB, opening_coin(), 3_000, until).await;
    let again = again.unwrap();
    assert_ne!(again.hash, first.hash);
    drop(alice);
    // Her file lost, the coin found again: both found at her hub, and the
    // next asked under neither.
    let (restored, _) = restored_behind(&net, "alice", "restored.sqlite", changed(|_| ()));
    found_spent(&net.dir.path().join("restored.sqlite"), opening_coin());
    restored.add_hub(HUB).await.unwrap();
    let mut found: Vec<_> = (restored.deposits().unwrap().into_iter())
        .map(|d| (d.hash, d.close))
        .collect();
    found.sort();
    let mut want = vec![(first.hash.clone(), true), (again.hash.clone(), true)];
    want.sort();
    assert_eq!(found, want);
    let third = restored
        .close_deposit(HUB, opening_coin(), 3_000, until)
        .await;
    let third = third.unwrap();
    assert!(![&first.hash, &again.hash].contains(&&third.hash));
    // Another coin's first is another deposit still.
    let other = OutPoint::new(opening_coin().txid, 2);
    let other = restored.close_deposit(HUB, other, 3_000, until).await;
    assert!(![&first.hash, &again.hash, &third.hash].contains(&&other.unwrap().hash));

    // A hub hiding hers has her ask again what she first asked of the coin:
    // the same deposit, shared by no other coin's contract.
    let hidden: Stands = Box::new(|_| {
        let problem = Problem::new(Code::UnknownLock, "no deposit under this refund key");
        licash_wallet::Response {
            status: problem.code.status(),
            body: serde_json::to_vec(&problem).unwrap(),
        }
    });
    let (hiding, _) = restored_behind(&net, "alice", "hidden.sqlite", hidden);
    hiding.add_hub(HUB).await.unwrap();
    let same = hiding
        .close_deposit(HUB, opening_coin(), 3_000, until)
        .await;
    assert_eq!(same.unwrap().hash, first.hash);
    // One answering a deposit for each attempt has her give up the coin
    // after a few.
    let stands = Local(net.app.clone())
        .request(&licash_api::deposit_state(&[0; 32]), None)
        .await
        .unwrap();
    let first_body = net.asked("alice", &first.hash).1;
    let refund: [u8; 32] = first_body.refund.0.clone().try_into().unwrap();
    let known = Local(net.app.clone())
        .request(&licash_api::deposit_state(&refund), None)
        .await
        .unwrap();
    assert_ne!(stands.status, 200);
    assert_eq!(known.status, 200);
    let every: Stands = Box::new(move |_| licash_wallet::Response {
        status: 200,
        body: known.body.clone(),
    });
    let (crowded, asked) = restored_behind(&net, "alice", "crowded.sqlite", every);
    crowded.add_hub(HUB).await.unwrap();
    let before = asked.load(Ordering::SeqCst);
    let given_up = crowded
        .close_deposit(HUB, opening_coin(), 3_000, until)
        .await;
    let reason = given_up.unwrap_err().to_string();
    assert!(reason.contains("another coin"), "{reason}");
    assert_eq!(
        asked.load(Ordering::SeqCst) - before,
        u32::from(licash_wallet::CLOSE_ATTEMPTS)
    );
}

#[tokio::test]
async fn a_hub_answering_for_every_deposit_looked_for_is_asked_a_bounded_number_of_times() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let first = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &first.hash);
    drop(alice);
    // Whatever the number asked after, its hub answers her first deposit.
    let refund: [u8; 32] = body.refund.0.clone().try_into().unwrap();
    let stands = Local(net.app.clone())
        .request(&licash_api::deposit_state(&refund), None)
        .await
        .unwrap();
    assert_eq!(stands.status, 200);
    let stands: Stands = Box::new(move |_| licash_wallet::Response {
        status: 200,
        body: stands.body.clone(),
    });
    let (restored, asked) = restored_behind(&net, "alice", "restored.sqlite", stands);
    restored.add_hub(HUB).await.unwrap();
    // Her first found, under its own number alone: every other answer
    // counts as none, and the hub is asked no more than for a hub that
    // knows none of them.
    let found = restored.deposits().unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].hash, first.hash);
    assert_eq!(asked.load(Ordering::SeqCst), 1 + licash_wallet::DEPOSIT_GAP);
}

#[tokio::test]
async fn a_wallet_restored_finds_deposits_past_the_numbers_asked_at_once_asking_as_one_at_a_time_would(
) {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    // More asked than the numbers asked at once in a first round.
    let many = licash_wallet::DEPOSIT_GAP + 3;
    for _ in 0..many {
        alice.deposit_paying(HUB, 2_100).await.unwrap();
    }
    let mut asked: Vec<String> = alice
        .deposits()
        .unwrap()
        .into_iter()
        .map(|d| d.hash)
        .collect();
    drop(alice);
    let same: Stands = Box::new(|response| response);
    let (restored, times) = restored_behind(&net, "alice", "restored.sqlite", same);
    restored.add_hub(HUB).await.unwrap();
    let mut found: Vec<String> = (restored.deposits().unwrap().into_iter())
        .map(|d| d.hash)
        .collect();
    asked.sort();
    found.sort();
    assert_eq!(found, asked);
    // Each one asked, then as many unknown in a row as end a look, once
    // each.
    assert_eq!(
        times.load(Ordering::SeqCst),
        many + licash_wallet::DEPOSIT_GAP
    );
}

#[tokio::test]
async fn a_hub_takes_one_deposit_under_a_refund_key_and_answers_for_it_by_that_key() {
    let net = Net::new().await;
    let mut bodies = Vec::new();
    for name in ["alice", "bob"] {
        let deposit = net.wallet(name).deposit(HUB, 3_000).await.unwrap();
        bodies.push(net.asked(name, &deposit.hash).1);
    }
    // A gateway of its own database, which knows neither yet.
    let path = net.dir.path().join("other.sqlite");
    drop(licash_store::create(&path, licash_store::Kind::Hub).unwrap());
    let other = gateway(&net.hub, &net.source, &path);
    let first = other.deposit(&bodies[0], None).await.unwrap();
    // Another deposit, under the first's refund key: refused, and the
    // first still the one that key names.
    let mut second = bodies[1].clone();
    second.refund = bodies[0].refund.clone();
    let refused = other.deposit(&second, None).await.unwrap_err().0;
    assert_eq!(refused.code, Code::Forward, "{refused:?}");
    assert!(refused.message.contains("refund key"), "{refused:?}");
    let refund: [u8; 32] = bodies[0].refund.0.clone().try_into().unwrap();
    let (_, _, hash) = bodies[0].receive.terms().unwrap();
    assert_eq!(other.deposit_of(&refund).unwrap(), hash);
    assert_eq!(other.deposit(&bodies[0], None).await.unwrap(), first);
    // Under its own, taken; a key no deposit is under names none.
    other.deposit(&bodies[1], None).await.unwrap();
    let unknown = other.deposit_of(&[3; 32]).unwrap_err().0;
    assert_eq!(unknown.code, Code::UnknownLock);
}

#[tokio::test]
async fn a_payment_reorganized_away_locks_nothing_and_one_locked_alerts() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let hash = bytes(&deposit.hash);
    let address = deposit.terms.clone().unwrap().address;
    let paid_at = net.height() + 1;
    net.mine(1, vec![payment(&address, 3_100, 1)]);
    net.deposits.round().await;
    assert!(net
        .deposits
        .deposit_status(&hash)
        .unwrap()
        .funding
        .is_some());
    // Its block left the best chain, for two others: forgotten.
    net.fork(paid_at);
    net.mine(2, Vec::new());
    net.deposits.round().await;
    let status = net.deposits.deposit_status(&hash).unwrap();
    assert_eq!(
        (status.status.state, status.funding),
        (ReceiveState::Open, None)
    );
    // Paid again on the new chain, at depth: locked, then received.
    let paid_at = net.height() + 1;
    net.mine(1, vec![payment(&address, 3_100, 1)]);
    net.mine(1, Vec::new());
    net.deposits.round().await;
    let funding = net.deposits.deposit_status(&hash).unwrap().funding.unwrap();
    assert_eq!(funding.height, paid_at);
    assert_eq!(
        alice.follow_deposit(&deposit.hash).await.unwrap().state,
        DepositState::Received
    );
    assert!(alerts(&net.hub).is_empty());
    // Its payment reorganized away once its notes are out: alerted, once.
    net.fork(paid_at);
    net.mine(3, Vec::new());
    net.deposits.round().await;
    net.deposits.round().await;
    let alerts = alerts(&net.hub);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].contains("left the best chain"), "{alerts:?}");
    // Forgotten, and claimed by nothing meanwhile: no coin to claim.
    let status = net.deposits.deposit_status(&hash).unwrap();
    assert_eq!(
        (status.status.state, status.funding),
        (ReceiveState::Settled, None)
    );
    net.backend.lock().unwrap().mempool.clear();
    net.deposits.round().await;
    assert!(net.sent().is_empty(), "{:?}", net.sent());
    // Paid again, by another transaction: found, and its coins claimed.
    let again = payment(&address, 3_100, 2);
    let outpoint = OutPoint::new(again.compute_txid(), 0);
    let paid_at = net.height() + 1;
    net.mine(1, vec![again]);
    net.deposits.round().await;
    let funding = net.deposits.deposit_status(&hash).unwrap().funding.unwrap();
    assert_eq!(
        (funding.txid, funding.vout),
        (outpoint.txid.to_string(), outpoint.vout)
    );
    assert_eq!(funding.height, paid_at);
    net.deposits.round().await;
    let sent = net.sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].input[0].previous_output, outpoint);
    net.confirm_sent();
    net.deposits.round().await;
    assert!(net.sent().is_empty());
}

/// A reorganization that takes even the oldest block scanned is scanned
/// again from that block, not from the new tip: a deposit paid there is
/// found.
#[tokio::test]
async fn a_reorganization_past_every_block_scanned_scans_again_from_the_oldest() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let hash = bytes(&deposit.hash);
    let address = deposit.terms.clone().unwrap().address;
    // The only block scanned so far, the tip, leaves the best chain: the
    // payment is in its replacement, under others.
    let oldest = net.height();
    net.fork(oldest);
    net.mine(1, vec![payment(&address, 3_100, 1)]);
    net.mine(3, Vec::new());
    net.deposits.round().await;
    let funding = net.deposits.deposit_status(&hash).unwrap().funding;
    assert_eq!(funding.map(|f| f.height), Some(oldest));
    assert_eq!(
        alice.follow_deposit(&deposit.hash).await.unwrap().state,
        DepositState::Received
    );
}

async fn call(net: &Net, method: Method, path: &str, body: Option<String>) -> (u16, Problem) {
    let request = Request::builder().method(method).uri(path);
    let request = match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body)),
        None => request.body(Body::empty()),
    };
    let response = net.app.clone().oneshot(request.unwrap()).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

/// Behind a trusted proxy, a deposit is asked from the client it forwards
/// for, resolved by the router before the gateway: one forwarded for
/// otherwise than it parses is refused as invalid, unrecorded; a peer not
/// trusted is its own client, whatever it forwards for.
#[tokio::test]
async fn a_trusted_proxys_client_asks_the_deposit_and_a_malformed_chain_is_refused() {
    let net = Net::new().await;
    let trusted = licash_hub_service::admission::trusted_proxy("10.0.0.2").unwrap();
    let services = Services {
        deposits: Some(net.deposits.clone()),
        ingress: Arc::new(licash_hub_service::Ingress::new(vec![trusted])),
        ..Default::default()
    };
    let app = licash_hub_service::router(net.hub.clone(), services);
    let ask = |peer: &str, xff: &str, body: &licash_api::Deposit| {
        let request = Request::builder()
            .method(Method::POST)
            .uri(licash_api::DEPOSIT)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", xff)
            .extension(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ))
            .body(Body::from(serde_json::to_string(body).unwrap()))
            .unwrap();
        let app = app.clone();
        async move {
            let response = app.oneshot(request).await.unwrap();
            let status = response.status().as_u16();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, body)
        }
    };
    let db = rusqlite::Connection::open(net.dir.path().join("hub.sqlite")).unwrap();
    let source = |hash: [u8; 32]| -> Option<Vec<u8>> {
        db.query_row("SELECT source FROM deposits WHERE hash = ?1", [hash], |r| {
            r.get(0)
        })
        .unwrap_or(None)
    };
    let alice = net.wallet("alice");
    let mut asked = Vec::new();
    for _ in 0..3 {
        let deposit = alice.deposit(HUB, 3_000).await.unwrap();
        let (_, body) = net.asked("alice", &deposit.hash);
        let hash = bytes(&deposit.hash);
        db.execute("DELETE FROM deposits WHERE hash = ?1", [hash])
            .unwrap();
        asked.push((hash, body));
    }
    let (status, body) = ask("10.0.0.2:4000", "198.51.100.7:443", &asked[0].1).await;
    let problem: Problem = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, problem.code), (400, Code::Invalid), "{problem:?}");
    assert!(problem.message.contains("X-Forwarded-For"), "{problem:?}");
    assert_eq!(source(asked[0].0), None);
    let (status, _) = ask("10.0.0.2:4000", "1.1.1.1, 198.51.100.7", &asked[1].1).await;
    assert_eq!(status, 200);
    assert_eq!(
        source(asked[1].0).as_deref(),
        Some(b"ip 198.51.100.7".as_slice())
    );
    let (status, _) = ask("[::ffff:192.0.2.1]:4000", "198.51.100.7", &asked[2].1).await;
    assert_eq!(status, 200);
    assert_eq!(
        source(asked[2].0).as_deref(),
        Some(b"ip 192.0.2.1".as_slice())
    );
}

#[tokio::test]
async fn deposits_asked_and_not_paid_are_bounded_retries_aside() {
    let net = Net::new().await;
    let mut bodies = Vec::new();
    for name in ["alice", "bob"] {
        let deposit = net.wallet(name).deposit(HUB, 3_000).await.unwrap();
        bodies.push(net.asked(name, &deposit.hash).1);
    }
    let path = net.dir.path().join("bounded.sqlite");
    // Its own database: it counts the deposits it holds, and no others.
    drop(licash_store::create(&path, licash_store::Kind::Hub).unwrap());
    let bounded = deposit::Config {
        max_open: 1,
        ..config()
    };
    let profile = ChainProfile::Core30DefaultRegtest;
    let gateway =
        deposit::Gateway::open(net.hub.clone(), net.source.clone(), profile, bounded, &path)
            .unwrap();
    let first = gateway.deposit(&bodies[0], None).await.unwrap();
    let refused = gateway.deposit(&bodies[1], None).await.unwrap_err().0;
    assert_eq!(refused.code, Code::Unavailable, "{refused:?}");
    // The one asked, asked again: the same.
    assert_eq!(gateway.deposit(&bodies[0], None).await.unwrap(), first);
}

/// From one address, whatever its ports, only so many deposits are asked
/// and not paid, one an older release stored under it and a port counted:
/// from another, more.
#[tokio::test]
async fn deposits_asked_and_not_paid_from_one_source_are_bounded() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let mut bodies = Vec::new();
    for _ in 0..=PER_SOURCE {
        let deposit = alice.deposit(HUB, 3_000).await.unwrap();
        bodies.push(net.asked("alice", &deposit.hash).1);
    }
    let path = net.dir.path().join("sockets.sqlite");
    // Its own database: it counts the deposits it holds, and no others.
    drop(licash_store::create(&path, licash_store::Kind::Hub).unwrap());
    let profile = ChainProfile::Core30DefaultRegtest;
    let gateway = deposit::Gateway::open(
        net.hub.clone(),
        net.source.clone(),
        profile,
        config(),
        &path,
    )
    .unwrap();
    let ip = |s: &str| AdmissionSource::of_ip(s.parse().unwrap());
    let (one, other) = (ip("127.0.0.1"), ip("127.0.0.2"));
    let (last, asked) = bodies.split_last().unwrap();
    // The first as an older release stored it: by its peer and port.
    gateway.deposit(&asked[0], None).await.unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    let (_, _, first) = asked[0].receive.terms().unwrap();
    db.execute(
        "UPDATE deposits SET source = ?2 WHERE hash = ?1",
        rusqlite::params![first, b"tcp 127.0.0.1:41000".as_slice()],
    )
    .unwrap();
    for body in &asked[1..] {
        gateway.deposit(body, Some(&one)).await.unwrap();
    }
    let refused = gateway.deposit(last, Some(&one)).await.unwrap_err().0;
    assert_eq!(refused.code, Code::Unavailable, "{refused:?}");
    assert!(refused.message.contains("source"), "{refused:?}");
    // One asked, asked again over it: the same.
    gateway.deposit(&asked[0], Some(&one)).await.unwrap();
    gateway.deposit(last, Some(&other)).await.unwrap();
}

#[tokio::test]
async fn deposits_outside_the_hubs_terms_are_refused() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let (_, body) = net.asked("alice", &deposit.hash);
    // Of more than another gateway takes.
    let path = net.dir.path().join("other.sqlite");
    drop(licash_store::create(&path, licash_store::Kind::Hub).unwrap());
    let mut other = config();
    other.max = 2_000;
    let profile = ChainProfile::Core30DefaultRegtest;
    let smaller =
        deposit::Gateway::open(net.hub.clone(), net.source.clone(), profile, other, &path).unwrap();
    assert_eq!(
        smaller.deposit(&body, None).await.unwrap_err().0.code,
        Code::Forward
    );
    // Not a key to refund with, or of no keyset of the hub's.
    let mut wrong = body.clone();
    wrong.refund = licash_api::Hex(vec![0xff; 32]);
    assert_eq!(
        net.deposits.deposit(&wrong, None).await.unwrap_err().0.code,
        Code::Invalid
    );
    let mut wire = serde_json::to_value(&body).unwrap();
    wire["keyset"] = json!(hex::encode([7; 32]));
    let (status, problem) = call(
        &net,
        Method::POST,
        licash_api::DEPOSIT,
        Some(wire.to_string()),
    )
    .await;
    assert_eq!(
        (status, problem.code),
        (problem.code.status(), Code::UnknownKeyset)
    );
    let (status, problem) = call(&net, Method::POST, licash_api::DEPOSIT, Some("{}".into())).await;
    assert_eq!((status, problem.code), (400, Code::Invalid));
    let unknown = licash_api::deposit_state(&[3; 32]);
    let (status, problem) = call(&net, Method::GET, &unknown, None).await;
    assert_eq!(
        (status, problem.code),
        (problem.code.status(), Code::UnknownLock)
    );
}

#[tokio::test]
async fn deposits_are_kept_in_the_hubs_database_and_timed_within_the_hubs_locks() {
    let net = Net::new().await;
    let profile = ChainProfile::Core30DefaultRegtest;
    let open = |config, path: &std::path::Path| {
        deposit::Gateway::open(net.hub.clone(), net.source.clone(), profile, config, path)
            .err()
            .map(|e| e.to_string())
    };
    // Not the hub's database, nor of a version of the deposits this hub
    // reads.
    let foreign = net.dir.path().join("foreign.sqlite");
    let db = rusqlite::Connection::open(&foreign).unwrap();
    db.execute_batch("CREATE TABLE t (x)").unwrap();
    assert!(open(config(), &foreign)
        .unwrap()
        .contains("not made by this layout"));
    let path = net.dir.path().join("old.sqlite");
    drop(licash_store::create(&path, licash_store::Kind::Hub).unwrap());
    assert_eq!(open(config(), &path), None);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE schema_versions SET version = 4 WHERE component = 'deposits'",
            [],
        )
        .unwrap();
    assert!(open(config(), &path).unwrap().contains("is of version 4"));
    // A lock lasting beyond the window of the hub's, with its depth and
    // reaction; nothing locked; no confirmation asked; fewer than none.
    let fresh = net.dir.path().join("fresh.sqlite");
    drop(licash_store::create(&fresh, licash_store::Kind::Hub).unwrap());
    let long = deposit::Config {
        lock_blocks: 38,
        ..config()
    };
    assert!(open(long, &fresh)
        .unwrap()
        .contains("within their window of 40"));
    let none = deposit::Config {
        lock_blocks: 0,
        ..config()
    };
    assert!(open(none, &fresh).is_some());
    let shallow = deposit::Config {
        depth: 0,
        ..config()
    };
    assert!(open(shallow, &fresh).unwrap().contains("positive"));
    let empty = deposit::Config {
        min: 5_000,
        ..config()
    };
    assert!(open(empty, &fresh).unwrap().contains("at most the largest"));
    // Nothing was made by the refused configurations.
    let conn = licash_store::open(&fresh, licash_store::Kind::Hub).unwrap();
    assert_eq!(
        licash_store::component_version(&conn, "deposits").unwrap(),
        None
    );
    drop(conn);
    let fits = deposit::Config {
        lock_blocks: 37,
        ..config()
    };
    assert_eq!(open(fits, &fresh), None);
}

/// The mock's chain as a wallet's light client sees it, filters aside.
struct Light(esplora::Shared);

impl licash_wallet::Blocks for Light {
    fn height(&self) -> impl std::future::Future<Output = Result<u32, String>> + Send {
        std::future::ready(Ok(self.0.lock().unwrap().chain.height()))
    }

    fn hash(
        &self,
        height: u32,
    ) -> impl std::future::Future<Output = Result<bitcoin::BlockHash, String>> + Send {
        let blocks = &self.0.lock().unwrap().chain.blocks;
        let hash = blocks.get(height as usize).map(|b| b.block_hash());
        std::future::ready(hash.ok_or_else(|| format!("no block {height}")))
    }

    fn filter(
        &self,
        _: &bitcoin::BlockHash,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, String>> + Send {
        std::future::ready(Ok(None))
    }

    fn block(
        &self,
        hash: &bitcoin::BlockHash,
    ) -> impl std::future::Future<Output = Result<bitcoin::Block, String>> + Send {
        let blocks = &self.0.lock().unwrap().chain.blocks;
        let block = blocks.iter().find(|b| b.block_hash() == *hash).cloned();
        std::future::ready(block.ok_or_else(|| format!("no block {hash}")))
    }
}

/// A silent payment of `value` to `to`, from a P2WPKH coin of the `n`th
/// payer that the mock knows the script of.
fn pay_silent(net: &Net, to: &licash_onchain::silent::SpAddress, value: u64, n: u8) -> Transaction {
    let secp = Secp256k1::new();
    let sender = SecretKey::from_slice(&[n; 32]).unwrap();
    let key = bitcoin::CompressedPublicKey(sender.public_key(&secp));
    let previous_output = OutPoint {
        txid: Txid::from_byte_array([n; 32]),
        vout: 0,
    };
    let spent = ScriptBuf::new_p2wpkh(&key.wpubkey_hash());
    let backend = &mut net.backend.lock().unwrap();
    backend.outside.insert(previous_output, spent);
    let paid = licash_onchain::silent::outputs(&[(sender, false)], &[previous_output], &[*to]);
    let output = TweakedPublicKey::dangerous_assume_tweaked(paid.unwrap()[0]);
    let mut witness = Witness::new();
    witness.push([0x30; 71]);
    witness.push(key.to_bytes());
    Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(output),
        }],
    }
}

/// What `tx` spends of the coins `paid`, less what it pays: its fee.
fn fee_of(tx: &Transaction, paid: u64) -> u64 {
    paid - tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>()
}

#[tokio::test]
async fn a_silent_payment_coin_is_deposited_whole_and_alone_or_not_at_all() {
    use licash_hub_service::tweaks::{step, Tweaks};
    let net = Net::new().await;
    let index = Arc::new(Tweaks::open(&net.dir.path().join("tweaks.sqlite")).unwrap());
    step(&index, &net.source, None).await.unwrap();
    let services = Services {
        deposits: Some(net.deposits.clone()),
        tweaks: Some(index.clone()),
        ..Default::default()
    };
    let app = licash_hub_service::router(net.hub.clone(), services);
    let path = net.dir.path().join("alice.sqlite");
    let network = ChainProfile::Core30DefaultRegtest;
    let alice = Wallet::create(&path, &[1; 32], network, Local(app)).unwrap();
    alice.add_hub(HUB).await.unwrap();
    alice
        .watch_silent(HUB, index.first().unwrap().unwrap())
        .unwrap();
    let to = alice.silent_keys().address();
    let rate = FeeRate::from_sat_per_vb_u32(1);
    let light = Light(net.backend.clone());
    let paid = |value: u64, n: u8| {
        let payment = pay_silent(&net, &to, value, n);
        net.mine(1, vec![payment]);
    };
    let scan = || async {
        step(&index, &net.source, None).await.unwrap();
        alice.scan_silent(HUB, &light, u32::MAX).await.unwrap()
    };
    let insufficient = |e: licash_wallet::Error| match e {
        licash_wallet::Error::Insufficient { needed, available } => (needed, available),
        e => panic!("{e:?}"),
    };

    let invalid = |e: licash_wallet::Error| match e {
        licash_wallet::Error::Invalid(reason) => reason,
        e => panic!("{e:?}"),
    };
    let coin = |value: u64| {
        let coins = alice.silent_coins().unwrap();
        coins.iter().find(|c| c.value == value).unwrap().outpoint
    };

    // No coin of the wallet's, or too little for the least the hub takes:
    // no deposit asked.
    let none = OutPoint::new(Txid::from_byte_array([0; 32]), 0);
    let reason = invalid(alice.deposit_silent(HUB, none, rate).await.unwrap_err());
    assert!(reason.contains("no free coin"), "{reason}");
    paid(1_000, 2);
    assert_eq!(scan().await.found.len(), 1);
    let small = alice.deposit_silent(HUB, coin(1_000), rate).await;
    let (needed, held) = insufficient(small.unwrap_err());
    assert_eq!(held, 1_000);
    assert!(needed > 1_100, "{needed}");
    assert!(alice.deposits().unwrap().is_empty());

    // Enough in another coin: it alone deposited, whole, never joined with
    // the first.
    paid(2_600, 3);
    assert_eq!(scan().await.found.len(), 1);
    let (deposit, tx) = alice.deposit_silent(HUB, coin(2_600), rate).await.unwrap();
    let terms = deposit.terms.clone().unwrap();
    assert_eq!(deposit.state, DepositState::Open);
    assert_eq!(terms.pays, deposit.amount + 100);
    assert_eq!((tx.input.len(), tx.output.len()), (1, 1));
    assert_eq!(tx.input[0].previous_output, coin(2_600));
    let address: Address<_> = terms.address.parse().unwrap();
    assert_eq!(
        tx.output[0].script_pubkey,
        address.assume_checked().script_pubkey()
    );
    assert_eq!(tx.output[0].value.to_sat(), terms.pays);
    assert_eq!(fee_of(&tx, 2_600), tx.vsize() as u64);
    // Being spent: not to deposit again.
    let again = alice.deposit_silent(HUB, coin(2_600), rate).await;
    assert!(invalid(again.unwrap_err()).contains("no free coin"));
    assert_eq!(alice.deposits().unwrap().len(), 1);

    // Broadcast, confirmed at depth: the notes.
    net.backend.lock().unwrap().mempool.push(tx.clone());
    net.confirm_sent();
    net.deposits.round().await;
    net.mine(1, Vec::new());
    net.deposits.round().await;
    let received = alice.follow_deposit(&deposit.hash).await.unwrap();
    assert_eq!(received.state, DepositState::Received);
    assert_eq!(available(&alice), deposit.amount);
    // Its notes received under its lock.
    assert!(deposit.lock.is_none());
    let receipts = alice.receipts().unwrap();
    assert_eq!(received.lock.as_ref(), Some(&receipts[0].id));
    let scanned = scan().await;
    assert_eq!(scanned.spent.len(), 1);
    let left = alice.silent_coins().unwrap();
    assert_eq!(left.len(), 1);
    assert!(left[0].value == 1_000 && left[0].spending.is_none());

    // More than the hub takes at once: refused, rather than change left.
    paid(10_000, 4);
    scan().await;
    let most = alice.deposit_silent(HUB, coin(10_000), rate).await;
    let reason = invalid(most.unwrap_err());
    assert!(reason.contains("more than"), "{reason}");
    assert_eq!(alice.deposits().unwrap().len(), 1);
    let coins = alice.silent_coins().unwrap();
    assert!(coins.iter().all(|c| c.spending.is_none()));
}

/// The hub behind a front refusing what is posted while `.1` is set, with
/// a plain 400, as a server only redirecting to HTTPS may.
struct Front(Local, Arc<AtomicBool>);

impl Transport for Front {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<licash_wallet::Response, String>> + Send {
        let refused = body.is_some() && self.1.load(Ordering::SeqCst);
        let answer = self.0.request(url, body);
        async move {
            if refused {
                let body = b"Bad Request\n".to_vec();
                return Ok(licash_wallet::Response { status: 400, body });
            }
            answer.await
        }
    }
}

#[tokio::test]
async fn a_deposit_its_hub_never_answered_is_abandoned_and_a_silent_one_never_kept() {
    use licash_hub_service::tweaks::{step, Tweaks};
    use licash_wallet::Error;
    let net = Net::new().await;
    let index = Arc::new(Tweaks::open(&net.dir.path().join("tweaks.sqlite")).unwrap());
    step(&index, &net.source, None).await.unwrap();
    let services = Services {
        deposits: Some(net.deposits.clone()),
        tweaks: Some(index.clone()),
        ..Default::default()
    };
    let app = licash_hub_service::router(net.hub.clone(), services);
    let path = net.dir.path().join("alice.sqlite");
    let network = ChainProfile::Core30DefaultRegtest;
    let refusing = Arc::new(AtomicBool::new(true));
    let front = Front(Local(app), refusing.clone());
    let alice = Wallet::create(&path, &[1; 32], network, front).unwrap();
    alice.add_hub(HUB).await.unwrap();
    alice
        .watch_silent(HUB, index.first().unwrap().unwrap())
        .unwrap();
    let to = alice.silent_keys().address();
    net.mine(1, vec![pay_silent(&net, &to, 3_000, 2)]);
    step(&index, &net.source, None).await.unwrap();
    let light = Light(net.backend.clone());
    let found = alice.scan_silent(HUB, &light, u32::MAX).await.unwrap();
    assert_eq!(found.found.len(), 1);
    let rate = FeeRate::from_sat_per_vb_u32(1);

    // Its coins never asked a deposit the hub answered: none kept, however
    // often asked, and the coins free.
    let coin = found.found[0].outpoint;
    for _ in 0..3 {
        let unanswered = alice.deposit_silent(HUB, coin, rate).await.unwrap_err();
        assert!(
            matches!(unanswered, Error::Unavailable { .. }),
            "{unanswered:?}"
        );
    }
    assert!(alice.deposits().unwrap().is_empty());
    assert!(alice.silent_coins().unwrap()[0].spending.is_none());

    // One asked for by hand, kept before its hub hears of it, unanswered:
    // given up, as no address was named to pay.
    let pending = alice.deposit(HUB, 1_000).await.unwrap_err();
    let Error::Pending { id, .. } = pending else {
        panic!("{pending:?}");
    };
    let asked = alice.deposits().unwrap();
    assert_eq!(
        (asked[0].state.clone(), asked[0].terms.clone()),
        (DepositState::Open, None)
    );
    alice.abandon_deposit(&id).unwrap();
    let asked = alice.deposits().unwrap();
    assert!(
        matches!(&asked[0].state, DepositState::Canceled(_)),
        "{asked:?}"
    );
    assert!(matches!(alice.abandon_deposit(&id), Err(Error::Invalid(_))));
    refusing.store(false, Ordering::SeqCst);
    assert!(alice.resume().await.unwrap().deposits.is_empty());

    // Answered: kept with its terms, its coins spent on it, and not to be
    // given up.
    let (deposit, tx) = alice.deposit_silent(HUB, coin, rate).await.unwrap();
    assert_eq!(deposit.state, DepositState::Open);
    assert_eq!(deposit.terms.as_ref().unwrap().pays, deposit.amount + 100);
    assert_eq!(fee_of(&tx, 3_000), tx.vsize() as u64);
    assert_eq!(alice.deposits().unwrap().len(), 2);
    let answered = alice.abandon_deposit(&deposit.hash);
    assert!(matches!(answered, Err(Error::Invalid(_))), "{answered:?}");
    let unknown = alice.abandon_deposit(&"00".repeat(32));
    assert!(
        matches!(unknown, Err(Error::UnknownPayment(_))),
        "{unknown:?}"
    );
}

/// The hub behind a front that, while `.1` is set, passes each claim of a
/// lock on to it but answers the wallet an error: a hub taking the
/// preimage and keeping the notes.
struct Withholding(Local, Arc<AtomicBool>);

impl Transport for Withholding {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        let kept = url.ends_with(licash_api::SETTLE) && self.1.load(Ordering::SeqCst);
        let response = self.0.request(url, body).await?;
        if kept {
            let body = br#"{"code":"unavailable","message":"later"}"#.to_vec();
            return Ok(licash_wallet::Response { status: 503, body });
        }
        Ok(response)
    }
}

/// A deposit's lock is protected against the chain's height as the wallet
/// knows it of itself, whatever its hub says of it: one that does not know
/// it trusts its hub with the deposit's notes, as with any.
#[tokio::test]
async fn a_deposit_is_claimed_at_the_height_the_wallet_knows_of_itself_or_trusting_its_hub() {
    let net = Net::new().await;
    let (alice, bob) = (net.wallet("alice"), net.wallet("bob"));
    let hers = alice.deposit(HUB, 3_000).await.unwrap();
    let his = bob.deposit(HUB, 3_000).await.unwrap();
    let pay = |deposit: &licash_wallet::Deposit, n| {
        payment(&deposit.terms.as_ref().unwrap().address, 3_100, n)
    };
    net.mine(2, vec![pay(&hers, 1), pay(&his, 2)]);
    net.deposits.round().await;
    // The chain as her own source shows it, at her deposit's timeout: too
    // late to activate its lock, where her hub says there is time.
    alice.saw_tip(hers.terms.as_ref().unwrap().timeout);
    let kept = alice.follow_deposit(&hers.hash).await.unwrap();
    assert!(
        matches!(&kept.state, DepositState::Canceled(r) if r.contains("too late")),
        "{kept:?}"
    );
    let lock = licash_api::lock_id(kept.lock.as_ref().unwrap()).unwrap();
    assert_eq!(net.hub.locked(&lock).unwrap().preimage, None);
    assert_eq!(available(&alice), 0);
    let received = bob.follow_deposit(&his.hash).await.unwrap();
    assert_eq!(received.state, DepositState::Received);
    assert_eq!(available(&bob), 3_000);
}

#[tokio::test]
async fn a_deposit_whose_notes_its_hub_keeps_is_owed_and_claimed_again_inside_the_margin() {
    use licash_wallet::PROTECTED_MARGIN;
    let net = Net::new().await;
    let keeping = Arc::new(AtomicBool::new(true));
    let front = Withholding(Local(net.app.clone()), keeping.clone());
    let path = net.dir.path().join("alice.sqlite");
    let network = ChainProfile::Core30DefaultRegtest;
    let alice = Wallet::create(&path, &[1; 32], network, front).unwrap();
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let terms = deposit.terms.clone().unwrap();
    net.mine(2, vec![payment(&terms.address, 3_100, 1)]);
    net.deposits.round().await;
    // Its preimage revealed, its notes kept: owed, with what proves its
    // lock on Bitcoin (its hub's own notes, as a payer's).
    let kept = alice.follow_deposit(&deposit.hash).await;
    assert!(
        kept.as_ref().is_ok_and(|d| d.state == DepositState::Open) || kept.is_err(),
        "{kept:?}"
    );
    let owed = alice.owed_locks().unwrap();
    assert_eq!(owed.len(), 1, "{owed:?}");
    assert!(owed[0].anchor.is_some());
    let lock = net.hub.locked(&owed[0].id).unwrap();
    assert!(lock.own);
    assert_eq!(lock.preimage, Some(owed[0].preimage));
    // Inside the margin a fresh preimage needs, its hub answering again:
    // revealed already, so claimed rather than given up.
    let left = owed[0].expiry - net.height();
    net.mine(left - PROTECTED_MARGIN + 2, vec![]);
    assert!(net.height() + PROTECTED_MARGIN > owed[0].expiry);
    keeping.store(false, Ordering::SeqCst);
    let received = alice.follow_deposit(&deposit.hash).await.unwrap();
    assert_eq!(received.state, DepositState::Received, "{received:?}");
    let held: u64 = alice.balance().unwrap().iter().map(|b| b.available).sum();
    assert_eq!(held, 3_000);
}

/// The coin a contract's opening spends, in the tests of close deposits.
fn opening_coin() -> OutPoint {
    OutPoint::new(Txid::from_byte_array([42; 32]), 1)
}

/// A deposit that returns a contract's reserve, asked by `wallet` for
/// 3 000 sat for the contract [`opening_coin`] opens, timing out 100 blocks
/// on: its script and fee, and the contract a hub of ours binds it to.
async fn close_deposit(net: &Net, wallet: &Wallet<Local>) -> (licash_wallet::CloseDeposit, u32) {
    let timeout = net.height() + 100;
    let coin = opening_coin();
    let close = wallet.close_deposit(HUB, coin, 3_000, timeout).await;
    (close.unwrap(), timeout)
}

#[tokio::test]
async fn a_close_deposit_is_the_reserve_exactly_for_the_most_notes_it_covers() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let (close, timeout) = close_deposit(&net, &alice).await;
    // The reserve exactly; the hub's fee is what its notes leave of it.
    assert_eq!(close.fee, 100);
    let deposit = alice.deposit_of(&close.hash).unwrap();
    let terms = deposit.terms.clone().unwrap();
    assert_eq!((terms.pays, terms.timeout), (3_000, timeout));
    assert_eq!(deposit.amount, 2_900);
    // Kept as a contract's close, which her seed finds again.
    let (_, body) = net.asked("alice", &close.hash);
    assert_eq!(
        body.close,
        Some(licash_api::CloseTerms {
            pays: 3_000,
            until: timeout
        })
    );
    // Notes other than the most it covers, a timeout too soon or too far
    // for the hub to keep it: refused.
    let mut fewer = body.clone();
    fewer.close = Some(licash_api::CloseTerms {
        pays: 3_100,
        until: timeout,
    });
    let refused = net.deposits.deposit(&fewer, None).await.unwrap_err();
    assert_eq!(refused.0.code, Code::Forward);
    for bad in [net.height() + 5, net.height() + 200_000] {
        let mut asked = body.clone();
        asked.close = Some(licash_api::CloseTerms {
            pays: 3_000,
            until: bad,
        });
        // Another hash: the same notes under a timeout of its own.
        asked.receive = licash_api::Receive::new(
            &body.receive.terms().unwrap().0,
            &body.receive.terms().unwrap().1,
            &body.receive.outputs().unwrap(),
            &[77; 32],
        );
        let refused = net.deposits.deposit(&asked, None).await.unwrap_err();
        assert_eq!(refused.0.code, Code::Forward, "a timeout at {bad}");
    }
}

#[tokio::test]
async fn a_close_deposit_no_contract_binds_is_given_up_after_its_window() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let (close, timeout) = close_deposit(&net, &alice).await;
    let hash = bytes(&close.hash);
    // Nothing is locked to a deposit no contract binds, and nothing asks.
    let refused = net.deposits.ask_lock(&hash).unwrap_err();
    assert_eq!(refused.0.code, Code::Forward);
    net.mine(11, Vec::new());
    net.deposits.round().await;
    assert_eq!(
        net.deposits.deposit_status(&hash).unwrap().status.state,
        ReceiveState::Canceled
    );
    let late = net
        .deposits
        .bind_close(close.script.as_bytes(), [1; 32], 3_000, 100, timeout);
    assert!(late.is_err(), "{late:?}");
}

#[tokio::test]
async fn a_contract_binds_its_close_deposit_once_and_as_asked() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let (close, timeout) = close_deposit(&net, &alice).await;
    let bind = |contract: u8, pays: u64, fee: u64, timeout: u32| {
        net.deposits
            .bind_close(close.script.as_bytes(), [contract; 32], pays, fee, timeout)
    };
    // As the contract names it, nothing else.
    assert!(bind(1, 3_001, 100, timeout).is_err());
    assert!(bind(1, 3_000, 101, timeout).is_err());
    assert!(bind(1, 3_000, 100, timeout + 1).is_err());
    let unknown = net
        .deposits
        .bind_close(&[0x51; 34], [1; 32], 3_000, 100, timeout);
    assert!(unknown.is_err());
    bind(1, 3_000, 100, timeout).unwrap();
    // The same again for the same contract, another's refused.
    bind(1, 3_000, 100, timeout).unwrap();
    assert!(bind(2, 3_000, 100, timeout).is_err());
    // Kept past its window, till its timeout.
    net.mine(15, Vec::new());
    net.deposits.round().await;
    assert_eq!(
        net.deposits
            .deposit_status(&bytes(&close.hash))
            .unwrap()
            .status
            .state,
        ReceiveState::Open
    );
}

#[tokio::test]
async fn a_close_deposit_is_locked_when_its_wallet_asks_not_when_it_is_paid() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let (close, timeout) = close_deposit(&net, &alice).await;
    let hash = bytes(&close.hash);
    net.deposits
        .bind_close(close.script.as_bytes(), [1; 32], 3_000, 100, timeout)
        .unwrap();
    let address = alice
        .deposit_of(&close.hash)
        .unwrap()
        .terms
        .unwrap()
        .address;
    // The contract's default pays it, long after its window, and it is
    // buried: nothing is locked, and no one is given up on.
    net.mine(15, Vec::new());
    net.mine(1, vec![payment(&address, 3_000, 1)]);
    net.mine(3, Vec::new());
    net.deposits.round().await;
    net.deposits.round().await;
    assert_eq!(
        net.deposits.deposit_status(&hash).unwrap().status.state,
        ReceiveState::Open
    );
    // She comes back: seen paid, she asks, and the hub locks.
    let followed = alice.follow_deposit(&close.hash).await.unwrap();
    assert_eq!(followed.state, DepositState::Open);
    assert!(followed.funding.is_some());
    net.deposits.round().await;
    assert_eq!(
        net.deposits.deposit_status(&hash).unwrap().status.state,
        ReceiveState::Locked
    );
    let received = alice.follow_deposit(&close.hash).await.unwrap();
    assert_eq!(received.state, DepositState::Received, "{received:?}");
    // Her notes are the reserve less the hub's fee; its coins its own.
    assert_eq!(available(&alice), 2_900);
    net.deposits.round().await;
    net.deposits.round().await;
    let sent = net.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].output[0].script_pubkey, sweep_to());
}

#[tokio::test]
async fn a_close_deposit_never_asked_for_is_given_up_a_wait_after_its_payment_and_refunded() {
    use licash_onchain::deposit::CLOSE_WAIT;
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let (close, until) = close_deposit(&net, &alice).await;
    let hash = bytes(&close.hash);
    net.deposits
        .bind_close(close.script.as_bytes(), [1; 32], 3_000, 100, until)
        .unwrap();
    let address = alice
        .deposit_of(&close.hash)
        .unwrap()
        .terms
        .unwrap()
        .address;
    net.mine(1, vec![payment(&address, 3_000, 1)]);
    let paid_at = net.height();
    net.mine(3, Vec::new());
    net.deposits.round().await;
    // Not asked for: kept, locked to no one, well past the block it was
    // watched for until, a wait counted from its payment.
    let state = || net.deposits.deposit_status(&hash).unwrap().status.state;
    assert_eq!(state(), ReceiveState::Open);
    let wait = u32::from(CLOSE_WAIT);
    net.mine(paid_at + wait - 2 - net.height(), Vec::new());
    net.deposits.round().await;
    assert_eq!(state(), ReceiveState::Open);
    // Her payer may take it back from block paid_at + wait: given up as it
    // can be, and the wallet takes the coins back.
    net.mine(2, Vec::new());
    net.deposits.round().await;
    assert_eq!(state(), ReceiveState::Canceled);
    let funded = alice.follow_deposit(&close.hash).await.unwrap();
    assert_ne!(funded.state, DepositState::Received);
    assert_eq!(funded.refund_height(), Some(paid_at + wait - 1));
    let due = alice.deposits_to_refund(net.height()).unwrap();
    assert_eq!(due.len(), 1, "{due:?}");
    assert!(alice
        .deposits_to_refund(paid_at + wait - 2)
        .unwrap()
        .is_empty());
    // Its refund waits on the payment's depth, not on a height.
    let (outpoint, _) = funded.funding.unwrap();
    let refund = alice
        .refund_deposit(
            &close.hash,
            outpoint,
            Amount::from_sat(3_000),
            sweep_to(),
            FeeRate::from_sat_per_vb_u32(1),
        )
        .unwrap();
    assert_eq!(refund.lock_time, bitcoin::absolute::LockTime::ZERO);
    assert_eq!(
        refund.input[0].sequence,
        bitcoin::Sequence::from_height(CLOSE_WAIT)
    );
}

#[tokio::test]
async fn an_ordinary_deposit_is_no_contracts_to_lock_or_bind() {
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let deposit = alice.deposit(HUB, 3_000).await.unwrap();
    let hash = bytes(&deposit.hash);
    let refused = net.deposits.ask_lock(&hash).unwrap_err();
    assert_eq!(refused.0.code, Code::Forward);
    let script = alice
        .deposit_of(&deposit.hash)
        .unwrap()
        .terms
        .unwrap()
        .address
        .parse::<Address<_>>()
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let bound = net
        .deposits
        .bind_close(script.as_bytes(), [1; 32], 3_100, 100, net.height() + 100);
    assert!(bound.is_err(), "{bound:?}");
}

/// A transport to no hub at all: the hub is gone.
struct Gone;

impl Transport for Gone {
    async fn request(
        &self,
        _: &str,
        _: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        Err("the hub is gone".to_owned())
    }
}

/// The chain `source` reads, as a wallet reads Bitcoin: no filters.
struct Blocks(Source);

impl licash_wallet::Blocks for Blocks {
    async fn height(&self) -> Result<u32, String> {
        Ok(self.0.tip().await.map_err(|e| format!("{e:#}"))?.height)
    }
    async fn hash(&self, height: u32) -> Result<bitcoin::BlockHash, String> {
        self.0.hash(height).await.map_err(|e| format!("{e:#}"))
    }
    async fn filter(&self, _: &bitcoin::BlockHash) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    async fn block(&self, hash: &bitcoin::BlockHash) -> Result<bitcoin::Block, String> {
        self.0.block(hash).await.map_err(|e| format!("{e:#}"))
    }
}

/// The wallet file and the hub are both gone: its seed, the hub's public
/// address and deposit root, and a chain, find the payment of a contract's
/// default to its close deposit and take it back a wait after, with no word
/// from the hub.
#[tokio::test]
async fn a_wallet_restored_from_its_seed_alone_takes_back_a_close_deposit_the_hub_never_answers_for(
) {
    use licash_onchain::deposit::CLOSE_WAIT;
    let net = Net::new().await;
    let alice = net.wallet("alice");
    let (close, until) = close_deposit(&net, &alice).await;
    net.deposits
        .bind_close(close.script.as_bytes(), [1; 32], 3_000, 100, until)
        .unwrap();
    let address = alice
        .deposit_of(&close.hash)
        .unwrap()
        .terms
        .unwrap()
        .address;
    // Another deposit's payment, which a seed's scan is not to take for hers.
    let other = alice.deposit(HUB, 2_000).await.unwrap();
    let other_address = other.terms.unwrap().address;
    net.mine(
        1,
        vec![
            payment(&address, 3_000, 1),
            payment(&other_address, 2_100, 2),
        ],
    );
    let paid_at = net.height();

    // What a hub publishes, kept by her or read from it while it answered.
    let info = net.info().await;
    let hub_address = info.address.to_bytes();
    let root = info.deposits.unwrap().close_root.expect("a deposit root");
    let root = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&root.0).unwrap();

    // The same seed, no file of the first and no hub.
    let mut seed = [0; 32];
    seed[.."alice".len()].copy_from_slice(b"alice");
    let path = net.dir.path().join("restored.sqlite");
    let regtest = ChainProfile::Core30DefaultRegtest;
    let restored = Wallet::create(&path, &seed, regtest, Gone).unwrap();
    let chain = Blocks(net.source.clone());
    // Her coins not found again, and none named: nothing to look for.
    let none = restored.find_close_payments(&hub_address, &root, &[], &chain, 0);
    assert!(none.await.unwrap().is_empty());
    // Found again as a scan of her payments finds it, the coin that opened
    // her contract need not be named.
    found_spent(&path, opening_coin());
    let own = restored.find_close_payments(&hub_address, &root, &[], &chain, 0);
    assert_eq!(own.await.unwrap().len(), 1);
    let found = restored
        .find_close_payments(&hub_address, &root, &[opening_coin()], &chain, 0)
        .await
        .unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    let payment_found = &found[0];
    assert_eq!(
        (
            payment_found.hash,
            payment_found.value,
            payment_found.height
        ),
        (bytes(&close.hash), 3_000, paid_at)
    );
    assert_eq!(payment_found.spent_by, None);
    assert_eq!(
        payment_found.refund_height(),
        paid_at + u32::from(CLOSE_WAIT) - 1
    );
    // Another seed's scan finds nothing: the keys are hers.
    let stranger = Wallet::create(
        &net.dir.path().join("stranger.sqlite"),
        &[7; 32],
        regtest,
        Gone,
    )
    .unwrap();
    assert!(stranger
        .find_close_payments(&hub_address, &root, &[opening_coin()], &chain, 0)
        .await
        .unwrap()
        .is_empty());
    // Nor does another hub's root name her deposit's address.
    let wrong = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&[2; 32]).unwrap();
    assert!(restored
        .find_close_payments(&hub_address, &wrong, &[opening_coin()], &chain, 0)
        .await
        .unwrap()
        .is_empty());

    // A wait after the payment it takes the coins back, the transaction the
    // wallet built enforcing it, and a scan later finds it spent.
    let rate = FeeRate::from_sat_per_vb_u32(1);
    let refund = restored
        .refund_close_payment(&hub_address, &root, payment_found, sweep_to(), rate)
        .unwrap();
    assert_eq!(refund.input[0].previous_output, payment_found.outpoint);
    assert_eq!(
        refund.input[0].sequence,
        bitcoin::Sequence::from_height(CLOSE_WAIT)
    );
    assert_eq!(refund.lock_time, bitcoin::absolute::LockTime::ZERO);
    net.mine(u32::from(CLOSE_WAIT), vec![refund.clone()]);
    let after = restored
        .find_close_payments(&hub_address, &root, &[opening_coin()], &chain, 0)
        .await
        .unwrap();
    assert_eq!(after[0].spent_by, Some(refund.compute_txid()));
}
