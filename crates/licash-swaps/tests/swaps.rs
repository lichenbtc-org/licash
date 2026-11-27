//! Swaps between two hubs in process, through a provider whose clients
//! reach it as they reach the hubs.

#[allow(dead_code)]
#[path = "../../licash-wallet/tests/net/mod.rs"]
mod net;

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use licash::spend::{lock_hash, ChainProfile, ProposalId};
use licash_api::{
    swaps::{self, Request},
    Code, Fee, Hex, Problem,
};
use licash_swaps::{Config, Issuer, Notice, Provider, Stage};
use licash_wallet::{Error, Response, SwapLimits, SwapState, Transport, Wallet};
use net::{Fault, Link, Net};

const A: &str = "http://a.test";
const B: &str = "http://b.test";
const PROVIDER: &str = "http://swaps.test";
const FEE: Fee = Fee { base: 1, ppm: 0 };
const CONFIG: Config = Config {
    fee: Fee {
        base: 1,
        ppm: 10_000,
    },
    min: 5,
    max: 150,
    margin: 6,
    confirm: 4,
};
/// Hub A's response window, longer than B's ([`net::TIMING`]): a provider
/// paying at B needs the client's lock at A to outlive its own by B's
/// window and more.
const WINDOW_A: u32 = 46;
/// Blocks the client's lock outlives the provider's at B at least: the
/// refund request's confirmation, B's window, reading the preimage, the
/// provider's margin and one.
const LEAD_B: u32 = 4 + 20 + 1 + 6 + 1;
/// And at A.
const LEAD_A: u32 = 4 + WINDOW_A + 1 + 6 + 1;
/// Blocks the client's lock outlives B's own lock, B the provider: the
/// confirmation of an activation on Bitcoin, reading it, the provider's
/// margin and one.
const OWN_LEAD: u32 = 4 + 1 + 6 + 1;

/// Both hubs' window when B is the provider: too short at A for a third
/// party to outlast B's window, long enough for B itself.
const WINDOW: u32 = 30;

/// Whether hub B holds a hash for another of its services.
type Guard = Box<dyn Fn(&[u8; 32]) -> Result<bool, String> + Send + Sync>;

#[test]
fn a_hash_reservation_is_not_proof_of_lock_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let hash = [1; 32];
    let id = ProposalId::from_bytes([2; 32]);
    assert!(!licash_swaps::holds_hash(&path, &hash).unwrap());
    assert!(!licash_swaps::owns_hash_lock(&path, &hash, &id).unwrap());
    assert!(!path.exists());
    // A wallet's file that holds no provider's tables reserves nothing.
    let net = Net::new();
    let wallet = Wallet::create(
        &path,
        &[0x50; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(net),
    )
    .unwrap();
    assert!(!licash_swaps::holds_hash(&path, &hash).unwrap());
    let _provider = Provider::create(wallet, Config::default()).unwrap();
    assert!(!licash_swaps::holds_hash(&path, &hash).unwrap());
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "INSERT INTO provider_swaps (id, hash, from_url, to_url, address, amount, fee, paid,
            expiry_from_height, expiry_height, state, created_at, updated_at)
         VALUES (?1, ?2, 'a', 'b', x'00', 1, 0, 1, 1, 1, 'accepted', 0, 0)",
        rusqlite::params![[9u8; 32], hash],
    )
    .unwrap();
    assert!(licash_swaps::holds_hash(&path, &hash).unwrap());
    assert!(!licash_swaps::owns_hash_lock(&path, &hash, &id).unwrap());
    db.execute("UPDATE provider_swaps SET lock = ?1", [[3; 32]])
        .unwrap();
    assert!(!licash_swaps::owns_hash_lock(&path, &hash, &id).unwrap());
    db.execute("UPDATE provider_swaps SET lock = ?1", [id.as_bytes()])
        .unwrap();
    assert!(licash_swaps::owns_hash_lock(&path, &hash, &id).unwrap());
}

/// A provider on a new wallet at `path`.
fn bare_provider(path: &std::path::Path) -> Provider<Link> {
    let wallet = Wallet::create(
        path,
        &[0x50; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(Net::new()),
    )
    .unwrap();
    Provider::create(wallet, Config::default()).unwrap()
}

#[test]
fn the_provider_keeps_its_tables_in_its_wallets_file_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let wallet = Wallet::create(
        &path,
        &[0x50; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(Net::new()),
    )
    .unwrap();
    // A wallet alone has no provider to open.
    let refused = Provider::open(wallet, Config::default()).err().unwrap();
    assert!(
        refused.to_string().contains("no swap provider"),
        "{refused}"
    );
    let wallet = Wallet::open(&path, Link(Net::new())).unwrap();
    let provider = Provider::create(wallet, Config::default()).unwrap();
    drop(provider);
    let db = rusqlite::Connection::open(&path).unwrap();
    let versions: Vec<(String, i64)> = db
        .prepare("SELECT component, version FROM schema_versions ORDER BY component")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        versions,
        [("provider".to_owned(), 2), ("wallet".to_owned(), 6)]
    );
    let wallet = Wallet::open(&path, Link(Net::new())).unwrap();
    let again = Provider::create(wallet, Config::default()).err().unwrap();
    assert!(again.to_string().contains("already"), "{again}");
    // Opened again, it is the same provider: its Nostr key stays.
    let wallet = Wallet::open(&path, Link(Net::new())).unwrap();
    assert!(Provider::open(wallet, Config::default()).is_ok());
}

#[test]
fn the_providers_rows_hold_to_their_kinds_and_states() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let _provider = bare_provider(&path);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    let swap = |state: &str, kind: &str, amount: i64| {
        db.execute(
            "INSERT INTO provider_swaps (id, hash, from_url, to_url, address, amount, fee, paid,
                expiry_from_height, expiry_height, state, kind, created_at, updated_at)
             VALUES (randomblob(32), randomblob(32), 'a', 'b', x'00', ?3, 0, 1, 1, 1, ?1, ?2, 0, 0)",
            rusqlite::params![state, kind, amount],
        )
    };
    assert!(swap("accepted", "notes", 1).is_ok());
    assert!(swap("accepted", "lightning", 1).is_ok());
    assert!(swap("begun", "notes", 1).is_err());
    assert!(swap("accepted", "barter", 1).is_err());
    assert!(swap("accepted", "notes", -1).is_err());
    let event = |kind: &str| {
        db.execute(
            "INSERT INTO provider_events (at, kind, json) VALUES (0, ?1, '{}')",
            [kind],
        )
    };
    // A notice of a kind this version does not know is kept as it is.
    assert!(event("alert").is_ok());
    assert!(event("gossip").is_ok());
    // A payout's coin is recorded for a payout only, and a scan keeps a
    // hash of a block's length or none.
    let orphan = db.execute(
        "INSERT INTO provider_payout_fundings (id, tx, vout) VALUES (randomblob(32), x'00', 0)",
        [],
    );
    assert!(orphan.is_err());
}

#[test]
fn one_snapshot_of_a_providers_wallet_file_is_the_provider_whole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let wallet = Wallet::create(
        &path,
        &[0x50; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(Net::new()),
    )
    .unwrap();
    let to = dir.path().join("snapshot.sqlite");
    let provider = Provider::create(wallet, Config::default()).unwrap();
    let nostr = provider.nostr_secret().unwrap();
    provider.wallet().backup_to(&to).unwrap();
    drop(provider);
    let wallet = Wallet::open(&to, Link(Net::new())).unwrap();
    let restored = Provider::open(wallet, Config::default()).unwrap();
    assert_eq!(restored.nostr_secret().unwrap(), nostr);
}

/// The provider, as its clients reach it.
#[derive(Default)]
struct Desk {
    provider: Mutex<Option<Arc<Provider<Link>>>>,
    /// The next request to each path fails so.
    faults: Mutex<Vec<(&'static str, Fault)>>,
    /// Every request fails: the provider is gone.
    gone: AtomicBool,
    /// Answered to the next swap request instead of the provider's answer.
    lie: Mutex<Option<swaps::Swap>>,
}

impl Desk {
    fn provider(&self) -> Arc<Provider<Link>> {
        self.provider.lock().unwrap().clone().unwrap()
    }

    fn fail(&self, path: &'static str, fault: Fault) {
        self.faults.lock().unwrap().push((path, fault));
    }

    async fn serve(&self, path: &str, body: Option<Vec<u8>>) -> Result<Response, String> {
        let fault = {
            let mut faults = self.faults.lock().unwrap();
            let found = faults.iter().position(|(p, _)| *p == path);
            found.map(|i| faults.remove(i).1)
        };
        if self.gone.load(Ordering::Relaxed) || matches!(fault, Some(Fault::Lost)) {
            return Err("connection refused".into());
        }
        let lie = body.as_ref().and(self.lie.lock().unwrap().take());
        let provider = self.provider();
        let answer = match (path, body) {
            (swaps::SWAPS_INFO, None) => Ok(serde_json::to_vec(&provider.info().unwrap()).unwrap()),
            (swaps::SWAPS, Some(body)) => {
                let request: Request = serde_json::from_slice(&body).unwrap();
                match lie {
                    Some(lie) => Ok(serde_json::to_vec(&lie).unwrap()),
                    None => provider
                        .take(&request)
                        .await
                        .map(|swap| serde_json::to_vec(&swap).unwrap()),
                }
            }
            (path, None) => {
                let id = licash_api::lock_id(&path[swaps::SWAPS.len() + 1..]).unwrap();
                match provider.swap(&id).unwrap() {
                    Some(swap) => Ok(serde_json::to_vec(&swap).unwrap()),
                    None => Err(Problem::new(Code::UnknownLock, "no such swap")),
                }
            }
            _ => Err(Problem::invalid("no such route")),
        };
        if let Some(Fault::Dropped) = fault {
            return Err("connection reset".into());
        }
        Ok(match answer {
            Ok(body) => Response { status: 200, body },
            Err(problem) => Response {
                status: problem.code.status(),
                body: serde_json::to_vec(&problem).unwrap(),
            },
        })
    }
}

/// A client's way to the hubs and the provider.
#[derive(Clone)]
struct Client(Arc<Net>, Arc<Desk>);

impl Transport for Client {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let (net, desk, url) = (self.0.clone(), self.1.clone(), url.to_owned());
        async move {
            match url.strip_prefix(PROVIDER) {
                Some(path) => desk.serve(path, body).await,
                None => net.serve(&url, body),
            }
        }
    }
}

struct Eco {
    net: Arc<Net>,
    desk: Arc<Desk>,
    dir: tempfile::TempDir,
    client: Wallet<Client>,
    config: Config,
    /// Hub B is the provider, taking at most this of A's notes.
    cap: Option<u64>,
    turn: Arc<tokio::sync::Mutex<()>>,
}

impl Eco {
    /// Hubs A and B at height 3, A's window the longer, a provider holding
    /// `stock` at B, and a client holding 100 at A.
    async fn new(stock: u64) -> Self {
        Self::with(stock, WINDOW_A, CONFIG).await
    }

    /// As [`Eco::new`], A's window `window_a`, the provider's terms
    /// `config`.
    async fn with(stock: u64, window_a: u32, config: Config) -> Self {
        Self::build(stock, window_a, config, None).await
    }

    /// Hubs A and B of window [`WINDOW`] at height 3, B the provider of the
    /// swaps into it, taking at most `cap` of A's notes and no hash
    /// `guard` says it holds, and a client holding 100 at A.
    async fn issuing(cap: u64, guard: Guard) -> Self {
        Self::build(0, WINDOW, CONFIG, Some((cap, guard))).await
    }

    async fn build(
        stock: u64,
        window_a: u32,
        config: Config,
        issuing: Option<(u64, Guard)>,
    ) -> Self {
        let net = Net::new();
        let timing = licash_hub::Timing {
            window: window_a,
            ..net::TIMING
        };
        net.start_timed(A, FEE, timing);
        match issuing {
            Some(_) => net.start_timed(B, FEE, timing),
            None => net.start(B, FEE),
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sqlite");
        let wallet = Wallet::create(
            &path,
            &[0x50; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        for hub in [A, B] {
            wallet.add_hub(hub).await.unwrap();
        }
        let cap = issuing.as_ref().map(|&(cap, _)| cap);
        let turn = Arc::new(tokio::sync::Mutex::new(()));
        let provider = match issuing {
            Some((cap, guard)) => {
                let issuer = Issuer::new(net.hub(B), B)
                    .cap(A, cap)
                    .guard(turn.clone(), guard);
                Provider::create_issuing(wallet, config, issuer).unwrap()
            }
            None => {
                wallet
                    .receive(&net.pay(B, &wallet.address(), stock))
                    .unwrap();
                Provider::create(wallet, config).unwrap()
            }
        };
        let desk = Arc::new(Desk::default());
        *desk.provider.lock().unwrap() = Some(Arc::new(provider));
        let client = Client(net.clone(), desk.clone());
        let client = Wallet::create(
            &dir.path().join("client.sqlite"),
            &[0xc1; 32],
            ChainProfile::Core30DefaultRegtest,
            client,
        )
        .unwrap();
        for hub in [A, B] {
            client.add_hub(hub).await.unwrap();
        }
        client.receive(&net.pay(A, &client.address(), 100)).unwrap();
        Self {
            net,
            desk,
            dir,
            client,
            config,
            cap,
            turn,
        }
    }

    fn provider(&self) -> Arc<Provider<Link>> {
        self.desk.provider()
    }

    /// Stop the provider and start it again on its files.
    fn restart(&self) {
        self.stop();
        let provider = self.reopen(self.cap).unwrap();
        *self.desk.provider.lock().unwrap() = Some(Arc::new(provider));
    }

    fn stop(&self) {
        let old = self.desk.provider.lock().unwrap().take().unwrap();
        assert_eq!(Arc::strong_count(&old), 1, "the provider is in use");
        drop(old);
    }

    /// The provider on its files, as hub B taking at most `cap` of A's
    /// notes if given.
    fn reopen(&self, cap: Option<u64>) -> Result<Provider<Link>, licash_swaps::Error> {
        let path = self.dir.path().join("provider.sqlite");
        let wallet = Wallet::open(&path, Link(self.net.clone())).unwrap();
        match cap {
            Some(cap) => {
                let issuer = Issuer::new(self.net.hub(B), B).cap(A, cap);
                Provider::open_issuing(wallet, self.config, issuer)
            }
            None => Provider::open(wallet, self.config),
        }
    }

    /// Mine `blocks` on both hubs' chains, as if they followed one.
    fn mine(&self, blocks: u32) {
        self.net.mine(A, blocks, None);
        self.net.mine(B, blocks, None);
    }

    fn kinds(&self) -> Vec<String> {
        let events = self.provider().events(0, 100).unwrap();
        events.into_iter().map(|e| e.kind).collect()
    }
}

/// What `wallet` holds available at the hub at `url`.
fn held<T: Transport>(wallet: &Wallet<T>, url: &str) -> u64 {
    let balance = wallet.balance().unwrap();
    balance
        .iter()
        .find(|b| b.hub == url)
        .map_or(0, |b| b.available)
}

/// The swap's own fee, and the hubs' fee for a lock.
fn costs(amount: u64) -> (u64, u64) {
    (CONFIG.fee.due(amount), FEE.base)
}

impl Eco {
    fn address(&self, url: &str) -> licash::address::Address {
        self.net.hub(url).info().address
    }

    /// A swap of `amount` from A to B whose request never reached the
    /// provider: the client's lock is made.
    async fn pending(&self, amount: u64) -> licash_wallet::Swap {
        self.desk.fail(swaps::SWAPS, Fault::Lost);
        let e = self
            .client
            .swap(PROVIDER, A, B, amount, SwapLimits::usual(amount))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::Pending { .. }), "{e}");
        let swap = self.client.swaps().unwrap().remove(0);
        assert_eq!(
            (&swap.state, swap.theirs.as_ref()),
            (&SwapState::Open, None)
        );
        swap
    }

    /// The provider answers `swap` locked by `lock`, whatever it is.
    async fn lie(&self, swap: &licash_wallet::Swap, lock: &str) -> licash_wallet::Swap {
        *self.desk.lie.lock().unwrap() = Some(swaps::Swap {
            id: Hex(hex::decode(swap.lock.as_ref().unwrap()).unwrap()),
            state: swaps::State::Locked,
            amount: swap.amount,
            lock: Some(Hex(hex::decode(lock).unwrap())),
            expiry: 14,
            reason: None,
        });
        self.client.follow_swap(&swap.hash).await.unwrap()
    }
}

fn lock_id(text: &str) -> ProposalId {
    licash_api::lock_id(text).unwrap()
}

fn hash_of(swap: &licash_wallet::Swap) -> [u8; 32] {
    let mut hash = [0; 32];
    hex::decode_to_slice(&swap.hash, &mut hash).unwrap();
    hash
}

#[tokio::test]
async fn a_swap_moves_notes_from_one_hub_to_another_for_the_providers_fee() {
    let eco = Eco::new(200).await;
    let (fee, lock_fee) = costs(20);
    let provider = eco.provider();
    let info = provider.info().unwrap();
    // What it holds at B less the lock fee on it, up to its most; nothing
    // at A.
    assert_eq!(info.hub(&eco.address(B)).unwrap().max, 150);
    assert_eq!(info.hub(&eco.address(A)).unwrap().max, 0);
    assert_eq!(info.address, provider.wallet().address());
    // By how much the client's lock outlives the provider's at each hub,
    // and at every hub, for a client that reads only that.
    let margin = |url| info.hub(&eco.address(url)).unwrap().margin;
    assert_eq!((margin(B), margin(A)), (Some(LEAD_B), Some(LEAD_A)));
    assert_eq!(info.margin, LEAD_A);

    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    assert_eq!((swap.amount, swap.fee, swap.from.as_str()), (20, fee, A));
    assert!(swap.lock.is_some() && swap.theirs.is_some());
    assert_eq!(held(&eco.client, B), 20);
    assert_eq!(provider.records(10).unwrap()[0].stage, Stage::Locked);

    // The provider follows its lock to the preimage, and claims with it.
    assert!(provider.step().await.unwrap().is_empty());
    let record = &provider.records(10).unwrap()[0];
    assert_eq!(
        (record.stage, record.amount, record.fee, record.paid),
        (Stage::Done, 20, fee, 20 + fee)
    );
    assert_eq!(held(provider.wallet(), A), 20 + fee);
    assert_eq!(held(provider.wallet(), B), 200 - 20 - lock_fee);
    // Its record, and what its lock paid hub B.
    let outcome = provider.outcome(&record.id).unwrap().unwrap();
    assert_eq!((&outcome.record, outcome.hub_fee), (record, Some(lock_fee)));
    assert_eq!(provider.outcome(&"00".repeat(32)).unwrap(), None);
    assert_eq!(provider.outcome("not hex").unwrap(), None);
    eco.client.resume().await.unwrap();
    assert_eq!(held(&eco.client, A), 100 - 20 - fee - lock_fee);

    assert_eq!(eco.kinds(), ["accepted", "done"]);
    let events = provider.events(0, 10).unwrap();
    assert!(matches!(
        events[1].notice(),
        Some(Notice::Done { amount: 20, fee: f, .. }) if f == fee
    ));
    let stats = provider.stats().unwrap();
    assert_eq!((stats.done, stats.earned, stats.open), (1, fee, 0));
    assert_eq!((stats.events, provider.last_event().unwrap()), (2, 2));
    assert_eq!(
        eco.client.follow_swap(&swap.hash).await.unwrap().state,
        SwapState::Done
    );
    let theirs = provider.swap(&lock_id(swap.lock.as_ref().unwrap()));
    assert_eq!(theirs.unwrap().unwrap().state, swaps::State::Done);
}

/// A client's way, counting the times it asks each hub what it says of
/// itself.
struct Counting(Client, Arc<Mutex<HashMap<String, u32>>>);

impl Transport for Counting {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        if let Some(hub) = url.strip_suffix(licash_api::INFO) {
            *self.1.lock().unwrap().entry(hub.to_owned()).or_default() += 1;
        }
        self.0.request(url, body)
    }
}

/// Each round trip of a swap is one more over Tor, a second or more: a hub
/// is asked what it says of itself where the swap needs its height, as the
/// swap is made and for each lock looked at there, not again for who it
/// is.
#[tokio::test]
async fn a_swap_asks_its_hubs_what_they_say_of_themselves_only_where_it_needs_their_height() {
    let eco = Eco::new(200).await;
    let path = eco.dir.path().join("client.sqlite");
    let asked = Arc::new(Mutex::new(HashMap::new()));
    let client = Client(eco.net.clone(), eco.desk.clone());
    let counting = Wallet::open(&path, Counting(client, asked.clone())).unwrap();
    let swap = counting
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    let asked = asked.lock().unwrap().clone();
    // Each as the swap is made; A again for the wallet's lock looked at,
    // B for the provider's lock looked at and claimed.
    assert_eq!((asked.get(A), asked.get(B)), (Some(&2), Some(&3)));
}

/// A follower elsewhere (a second handle on the client's wallet, on
/// another thread) never sees a swap without its lock, which it would fail
/// as one whose lock was never made: the swap, its lock and its notes are
/// recorded at once.
#[tokio::test]
async fn a_concurrent_follower_never_fails_a_swap_being_made() {
    let eco = Eco::new(200).await;
    let path = eco.dir.path().join("client.sqlite");
    let follower = Wallet::open(&path, Client(eco.net.clone(), eco.desk.clone())).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopping = stop.clone();
    let following = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let mut rounds = 0;
            while !stopping.load(std::sync::atomic::Ordering::Relaxed) {
                follower.resume().await.unwrap();
                rounds += 1;
            }
            rounds
        })
    });
    // As many as its 50 sat at A pay.
    for _ in 0..2 {
        // Taken on by the follower at the same time, it may be pending.
        match eco
            .client
            .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
            .await
        {
            Ok(swap) => assert!(!matches!(swap.state, SwapState::Failed(_)), "{swap:?}"),
            Err(Error::Pending { .. }) => {}
            Err(e) => panic!("{e}"),
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(following.join().unwrap() > 0);
    for swap in eco.client.swaps().unwrap() {
        assert!(!matches!(swap.state, SwapState::Failed(_)), "{swap:?}");
    }
}

#[tokio::test]
async fn a_client_locks_nothing_for_a_swap_the_provider_would_decline() {
    let eco = Eco::new(60).await;
    // Below its least, beyond what it holds at B, the other way, at one hub.
    for (from, to, amount) in [(A, B, 4), (A, B, 60), (B, A, 10), (A, A, 10)] {
        let e = eco
            .client
            .swap(PROVIDER, from, to, amount, SwapLimits::usual(amount))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::Invalid(_)), "{e}");
    }
    assert!(matches!(
        eco.client
            .swap(PROVIDER, A, "http://c.test", 10, SwapLimits::usual(10))
            .await,
        Err(Error::UnknownHub(_))
    ));
    assert!(eco.client.swaps().unwrap().is_empty());
    assert_eq!(held(&eco.client, A), 100);
}

/// A swap whose lock, as the hub's fee on it signs it, costs more than was
/// quoted in all locks nothing: a hub raising its fee after the quote is
/// not paid it. Within the quote, it is swapped.
#[tokio::test]
async fn a_client_locks_nothing_for_a_swap_whose_lock_fee_passes_what_was_quoted_in_all() {
    let eco = Eco::new(60).await;
    let limits = SwapLimits::usual(20);
    let (fee, _) = costs(20);
    let lock_fee = eco.client.lock_fee(A, 20 + fee).unwrap();
    assert!(lock_fee > 0);
    let all = fee + lock_fee;
    let refused = (eco.client).swap_within(PROVIDER, A, B, 20, limits, Some(all - 1));
    match refused.await {
        Err(Error::FeeRose { agreed, asked, .. }) => assert_eq!((agreed, asked), (all - 1, all)),
        other => panic!("{other:?}"),
    }
    let swaps = eco.client.swaps().unwrap();
    assert!(
        matches!(&swaps[..], [s] if matches!(s.state, SwapState::Failed(_))),
        "{swaps:?}"
    );
    assert!(eco.client.locks().unwrap().is_empty());
    assert_eq!(held(&eco.client, A), 100);
    assert!(eco.provider().records(10).unwrap().is_empty());

    let swap = (eco.client).swap_within(PROVIDER, A, B, 20, limits, Some(all));
    assert_eq!(swap.await.unwrap().fee, fee);
    assert_eq!(eco.client.locks().unwrap()[0].fee, lock_fee);
}

#[tokio::test]
async fn a_client_locks_nothing_for_a_swap_costing_more_than_it_allows() {
    let eco = Eco::new(60).await;
    let (fee, _) = costs(20);
    let cheaper = SwapLimits {
        fee: fee - 1,
        margin: LEAD_B,
    };
    let sooner = SwapLimits {
        fee,
        margin: LEAD_B - 1,
    };
    for (limits, says) in [(cheaper, "more than"), (sooner, "locked")] {
        let e = eco.client.swap(PROVIDER, A, B, 20, limits).await;
        match e {
            Err(Error::Invalid(why) | Error::FeeRose { reason: why, .. }) => {
                assert!(why.contains(says), "{why}")
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(eco.client.swaps().unwrap().is_empty());
    assert_eq!(held(&eco.client, A), 100);
    assert!(eco.provider().records(10).unwrap().is_empty());

    // At its limits exactly: swapped.
    let exact = SwapLimits {
        fee,
        margin: LEAD_B,
    };
    let swap = eco.client.swap(PROVIDER, A, B, 20, exact).await.unwrap();
    assert_eq!((swap.state, swap.fee), (SwapState::Done, fee));
}

#[tokio::test]
async fn a_client_asks_what_a_swap_costs_and_what_it_would_refuse() {
    let eco = Eco::new(60).await;
    let quote =
        |from, to, amount, limits| eco.client.swap_quote(PROVIDER, from, to, amount, limits);
    let (fee, lock_fee) = costs(20);
    let quoted = quote(A, B, 20, SwapLimits::usual(20)).await.unwrap();
    assert_eq!((quoted.amount, quoted.fee), (20, fee));
    // A's fee on the lock that swap makes, of what the client holds now.
    assert_eq!(eco.client.lock_fee(A, 20 + fee).unwrap(), lock_fee);
    // Its margin at B, the hub swapped to.
    assert_eq!(
        (quoted.info.min, quoted.margin, quoted.info.margin),
        (CONFIG.min, LEAD_B, LEAD_A)
    );
    assert!(quoted.info.hub(&eco.address(B)).is_some());
    // Below its least: its least.
    let least = quote(A, B, 1, SwapLimits::usual(1)).await.unwrap();
    assert_eq!((least.amount, least.fee), (CONFIG.min, costs(CONFIG.min).0));

    // What a swap refuses: beyond what it holds at B, the other way, at
    // one hub, nothing, and more than allowed.
    let cheaper = SwapLimits {
        fee: fee - 1,
        margin: LEAD_B,
    };
    let sooner = SwapLimits {
        fee,
        margin: LEAD_B - 1,
    };
    let usual = SwapLimits::usual(10);
    for (from, to, amount, limits) in [
        (A, B, 60, usual),
        (B, A, 10, usual),
        (A, A, 10, usual),
        (A, B, 0, usual),
        (A, B, 20, cheaper),
        (A, B, 20, sooner),
    ] {
        let e = quote(from, to, amount, limits).await.unwrap_err();
        assert!(
            matches!(e, Error::Invalid(_) | Error::FeeRose { .. }),
            "{e}"
        );
    }
    let unknown = quote(A, "http://c.test", 10, usual).await;
    assert!(matches!(unknown, Err(Error::UnknownHub(_))), "{unknown:?}");
    // Asking locked and recorded nothing.
    assert!(eco.client.swaps().unwrap().is_empty());
    assert_eq!(held(&eco.client, A), 100);
    assert!(eco.provider().records(10).unwrap().is_empty());
}

#[tokio::test]
async fn the_provider_declines_locks_that_do_not_pay_it_or_leave_it_no_room() {
    let eco = Eco::new(30).await;
    let provider = eco.provider();
    let (a, b, me) = (eco.address(A), eco.address(B), eco.client.address());
    for _ in 0..2 {
        eco.client.receive(&eco.net.pay(A, &me, 64)).unwrap();
    }
    let to = provider.wallet().address();
    let (fee, _) = costs(20);

    let short = eco.client.lock(A, &to, 20, lock_hash(&[1; 32]), Some(20));
    let short = lock_id(&short.await.unwrap().id);
    let declined = provider
        .take(&Request::new(&a, &short, &b, &me, 20))
        .await
        .unwrap_err();
    assert_eq!(declined.code, Code::Declined);
    assert!(declined.message.contains("pays 20"), "{declined:?}");
    for (from, to, payee, amount, code) in [
        (a, b, me, 4, Code::Declined),
        (a, b, me, 151, Code::Declined),
        (a, me, me, 20, Code::Declined),
        (a, a, me, 20, Code::Declined),
        (a, b, b, 20, Code::Invalid),
    ] {
        let request = Request::new(&from, &short, &to, &payee, amount);
        assert_eq!(provider.take(&request).await.unwrap_err().code, code);
    }

    // Expiring at 38: the provider's lock would expire at 6, within 6 blocks.
    let soon = eco
        .client
        .lock(A, &to, 20 + fee, lock_hash(&[2; 32]), Some(LEAD_B + 6));
    let soon = lock_id(&soon.await.unwrap().id);
    let request = Request::new(&a, &soon, &b, &me, 20);
    let declined = provider.take(&request).await.unwrap_err();
    assert!(declined.message.contains("too soon"), "{declined:?}");
    // Refunded once expired at depth.
    eco.mine(LEAD_B + 4);
    eco.client.resume().await.unwrap();
    let declined = provider.take(&request).await.unwrap_err();
    assert!(declined.message.contains("settled"), "{declined:?}");

    // More than it holds at B.
    let big = eco
        .client
        .lock(A, &to, 40 + costs(40).0, lock_hash(&[3; 32]), None);
    let big = lock_id(&big.await.unwrap().id);
    let declined = provider
        .take(&Request::new(&a, &big, &b, &me, 40))
        .await
        .unwrap_err();
    assert!(declined.message.contains("too little"), "{declined:?}");

    assert!(provider.records(10).unwrap().is_empty());
    assert!(eco.kinds().is_empty());
    assert_eq!(held(provider.wallet(), B), 30);
}

#[tokio::test]
async fn a_swap_asked_again_answers_where_it_stands_and_a_hash_serves_once() {
    let eco = Eco::new(200).await;
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    let provider = eco.provider();
    let (a, b, me) = (eco.address(A), eco.address(B), eco.client.address());
    let id = lock_id(swap.lock.as_ref().unwrap());
    let request = Request::new(&a, &id, &b, &me, 20);
    let again = provider.take(&request).await.unwrap();
    assert_eq!((again.state, again.amount), (swaps::State::Locked, 20));
    assert_eq!(
        hex::encode(&again.lock.unwrap().0),
        swap.theirs.clone().unwrap()
    );
    let other = Request {
        amount: 21,
        ..request.clone()
    };
    let declined = provider.take(&other).await.unwrap_err();
    assert!(declined.message.contains("another swap"), "{declined:?}");

    // Another lock under the hash the client revealed.
    let to = provider.wallet().address();
    let reuse = eco.client.lock(A, &to, 30, hash_of(&swap), None);
    let reuse = lock_id(&reuse.await.unwrap().id);
    let declined = provider
        .take(&Request::new(&a, &reuse, &b, &me, 20))
        .await
        .unwrap_err();
    assert!(declined.message.contains("hash"), "{declined:?}");
    assert_eq!(provider.records(10).unwrap().len(), 1);
}

#[tokio::test]
async fn a_client_whose_provider_never_locks_is_refunded_once_its_lock_expired() {
    let eco = Eco::new(200).await;
    let swap = eco.pending(20).await;
    eco.desk.gone.store(true, Ordering::Relaxed);
    let resumed = eco.client.resume().await.unwrap();
    assert_eq!(resumed.pending.len(), 1, "{resumed:?}");
    // Its lock expires at 46, the latest hub A admitted at 3.
    eco.mine(44);
    let resumed = eco.client.resume().await.unwrap();
    assert!(
        matches!(&resumed.swaps[0].state, SwapState::Failed(why) if why.contains("never locked")),
        "{resumed:?}"
    );
    assert_eq!(resumed.swaps[0].hash, swap.hash);
    assert_eq!(held(&eco.client, A), 100 - FEE.base);
    assert!(eco.provider().records(10).unwrap().is_empty());
}

#[tokio::test]
async fn a_swap_its_provider_could_not_lock_fails_and_the_client_is_refunded() {
    let eco = Eco::new(200).await;
    let swap = eco.pending(20).await;
    eco.net.fail(licash_api::LOCK, Fault::Refused(Code::Timing));
    let failed = eco.client.follow_swap(&swap.hash).await.unwrap();
    assert!(
        matches!(&failed.state, SwapState::Failed(why) if why.contains("not locked")),
        "{failed:?}"
    );
    let provider = eco.provider();
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Failed);
    assert_eq!(eco.kinds(), ["accepted", "failed"]);
    assert_eq!(held(provider.wallet(), B), 200);
    assert!(provider.step().await.unwrap().is_empty());
    eco.mine(44);
    eco.client.resume().await.unwrap();
    assert_eq!(held(&eco.client, A), 100 - FEE.base);
    assert_eq!(provider.stats().unwrap().failed, 1);
}

#[tokio::test]
async fn a_lock_its_client_never_claims_returns_to_the_provider() {
    let eco = Eco::new(200).await;
    // The client's claim is lost, and the client gone.
    eco.net.fail(licash_api::SETTLE, Fault::Lost);
    let e = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Pending { .. }), "{e}");
    let swap = eco.client.swaps().unwrap().remove(0);
    assert!(swap.theirs.is_some());
    let provider = eco.provider();
    // Its lock expires at 14, 32 before the client's.
    assert_eq!(provider.records(1).unwrap()[0].expiry, 46 - LEAD_B);
    eco.mine(11);
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Locked);
    eco.mine(1);
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Refunded);
    assert_eq!(held(provider.wallet(), B), 200 - FEE.base);
    assert_eq!(eco.kinds(), ["accepted", "refunded"]);
    // Its lock's refund fee at B, all it cost.
    let id = &provider.records(1).unwrap()[0].id;
    let outcome = provider.outcome(id).unwrap().unwrap();
    assert_eq!(outcome.hub_fee, Some(FEE.base));

    // Back, the client cannot claim the provider's lock any more, and is
    // refunded its own once expired.
    eco.mine(32);
    let resumed = eco.client.resume().await.unwrap();
    assert!(
        matches!(&resumed.swaps[0].state, SwapState::Failed(why) if why.contains("refunded")),
        "{resumed:?}"
    );
    assert_eq!(held(&eco.client, A), 100 - FEE.base);
    assert_eq!(held(&eco.client, B), 0);
}

#[tokio::test]
async fn a_lock_its_hub_holds_is_followed_on_though_a_later_step_is_refused() {
    let eco = Eco::new(200).await;
    // The client's claim is lost: the provider's lock stands at B.
    eco.net.fail(licash_api::SETTLE, Fault::Lost);
    let e = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Pending { .. }), "{e}");
    let provider = eco.provider();
    let record = provider.records(1).unwrap().remove(0);
    assert_eq!(record.stage, Stage::Locked);
    // B refuses to say where the lock stands, to the wallet resuming its
    // payments then to the swap followed: no reason to give the swap up,
    // whose lock its client may still claim.
    let lock = lock_id(&record.lock.unwrap());
    let path: &'static str = licash_api::lock_state(&lock).leak();
    for _ in 0..2 {
        eco.net.fail(path, Fault::Refused(Code::UnknownLock));
    }
    let pending = provider.step().await.unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Locked);
    assert_eq!(eco.kinds(), ["accepted"]);
    // The client claims after all, and the provider claims its lock.
    let resumed = eco.client.resume().await.unwrap();
    assert_eq!(resumed.swaps[0].state, SwapState::Done, "{resumed:?}");
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Done);
    assert_eq!(held(provider.wallet(), A), 20 + costs(20).0);
}

#[tokio::test]
async fn a_provider_restarted_takes_its_swaps_on() {
    let eco = Eco::new(200).await;
    let swap = eco.pending(20).await;
    // The provider's lock is recorded, but never reaches its hub.
    eco.net.fail(licash_api::LOCK, Fault::Lost);
    let e = eco.client.follow_swap(&swap.hash).await.unwrap_err();
    assert!(
        matches!(&e, Error::Pending { reason, .. } if reason.contains("locking")),
        "{e}"
    );
    assert_eq!(eco.provider().records(1).unwrap()[0].stage, Stage::Accepted);
    assert!(eco.provider().records(1).unwrap()[0].lock.is_some());

    eco.restart();
    assert!(eco.provider().step().await.unwrap().is_empty());
    assert_eq!(eco.provider().records(1).unwrap()[0].stage, Stage::Locked);
    let done = eco.client.follow_swap(&swap.hash).await.unwrap();
    assert_eq!(done.state, SwapState::Done);
    assert_eq!(held(&eco.client, B), 20);

    // Stopped before it saw the preimage: it claims once started again.
    eco.restart();
    assert!(eco.provider().step().await.unwrap().is_empty());
    assert_eq!(eco.provider().records(1).unwrap()[0].stage, Stage::Done);
    assert_eq!(held(eco.provider().wallet(), A), 20 + costs(20).0);
    assert_eq!(eco.kinds(), ["accepted", "done"]);
}

#[tokio::test]
async fn a_provider_that_claims_too_late_loses_the_swap() {
    let eco = Eco::new(200).await;
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    // Asleep until the client's lock, expiring at 46, expired.
    eco.mine(44);
    let provider = eco.provider();
    assert!(provider.step().await.unwrap().is_empty());
    let record = &provider.records(1).unwrap()[0];
    assert_eq!(record.stage, Stage::Lost);
    assert!(
        record.reason.as_ref().unwrap().contains("expired"),
        "{record:?}"
    );
    assert_eq!(eco.kinds(), ["accepted", "lost"]);
    let stats = provider.stats().unwrap();
    assert_eq!((stats.lost, stats.lost_amount, stats.earned), (1, 20, 0));
    // Its lock at B paid, and its fee with it.
    let outcome = provider.outcome(&record.id).unwrap().unwrap();
    assert_eq!(outcome.hub_fee, Some(costs(20).1));
    // The client keeps both.
    eco.client.resume().await.unwrap();
    assert_eq!(held(&eco.client, A), 100 - FEE.base);
    assert_eq!(held(&eco.client, B), 20);
}

#[tokio::test]
async fn a_provider_claims_the_clients_lock_in_its_last_blocks_the_preimage_out_already() {
    let eco = Eco::new(200).await;
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    // Asleep until the client's lock, expiring at 46, is within 3 blocks:
    // B published the preimage paying the provider's lock, so claiming
    // reveals it to no one new.
    eco.mine(40);
    let provider = eco.provider();
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Done);
    assert_eq!(held(provider.wallet(), A), 20 + costs(20).0);
    assert_eq!(eco.kinds(), ["accepted", "done"]);
}

#[tokio::test]
async fn a_client_reveals_nothing_for_a_lock_that_does_not_pay_it_the_swap() {
    for lie in 0..5 {
        let eco = Eco::new(200).await;
        let provider = eco.provider();
        let payer = provider.wallet();
        let me = eco.client.address();
        let swap = eco.pending(20).await;
        let hash = hash_of(&swap);
        let (lock, why) = match lie {
            0 => (
                payer.lock(B, &me, 19, hash, Some(14)).await,
                "pays 19 of 20",
            ),
            1 => (
                payer.lock(B, &me, 20, lock_hash(&[9; 32]), Some(14)).await,
                "another hash",
            ),
            2 => (
                payer.lock(B, &payer.address(), 20, hash, Some(14)).await,
                "nothing",
            ),
            // The swap, but expiring too soon to claim: a provider's lock is
            // claimed only with the blocks left that a claim needs.
            3 => {
                let height = eco.net.view(B).height();
                let lock = payer.lock(B, &me, 20, hash, Some(height + 2)).await;
                (lock, "too late to claim")
            }
            _ => (Err(Error::PaysNothing), "does not hold"),
        };
        let lock = lock.map_or("00".repeat(32), |l| l.id);
        let lied = eco.lie(&swap, &lock).await;
        assert!(
            matches!(&lied.state, SwapState::Failed(reason) if reason.contains(why)),
            "{lied:?}"
        );
        // Only a lock that pays the swap is taken as the provider's.
        assert_eq!(lied.theirs.is_some(), lie == 3);

        // No preimage was revealed: every lock is refunded once expired.
        assert!(payer
            .locks()
            .unwrap()
            .iter()
            .all(|l| l.state == licash_wallet::LockState::Locked));
        eco.mine(44);
        eco.client.resume().await.unwrap();
        assert_eq!(held(&eco.client, A), 100 - FEE.base);
    }
}

/// A provider's lock its hub says is far from expiry, while the hub of the
/// client's lock is past it: its preimage is not revealed, the chain being
/// where the higher of the two says. Every lock is refunded once expired.
#[tokio::test]
async fn a_client_reveals_nothing_for_a_lock_its_hub_says_is_not_expired_yet() {
    let eco = Eco::new(200).await;
    let provider = eco.provider();
    let payer = provider.wallet();
    let swap = eco.pending(20).await;
    let height = eco.net.view(B).height();
    let me = eco.client.address();
    let lock = payer.lock(B, &me, 20, hash_of(&swap), Some(height + 8));
    let lock = lock.await.unwrap();
    // A is 6 blocks on, B behind it: 3 blocks are left as A sees it.
    eco.net.mine(A, 6, None);
    let lied = eco.lie(&swap, &lock.id).await;
    assert!(
        matches!(&lied.state, SwapState::Failed(why) if why.contains("too late to claim")),
        "{lied:?}"
    );
    assert!(payer
        .locks()
        .unwrap()
        .iter()
        .all(|l| l.state == licash_wallet::LockState::Locked));
    eco.mine(44);
    eco.client.resume().await.unwrap();
    assert_eq!(held(&eco.client, A), 100 - FEE.base);
}

#[tokio::test]
async fn the_operator_is_alerted_once_of_each_hub_the_provider_cannot_swap_to() {
    let eco = Eco::new(30).await;
    let provider = eco.provider();
    // Nothing at A, 30 at B: swaps to A stop.
    assert_eq!(provider.check_stock().unwrap(), [A]);
    assert_eq!(provider.check_stock().unwrap(), Vec::<String>::new());
    let events = provider.events(0, 10).unwrap();
    assert!(matches!(
        events[0].notice(),
        Some(Notice::Alert { message }) if message.contains(A) && message.contains("least")
    ));

    // Paid at A, it swaps to A again; it holds too little at B now.
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 25, SwapLimits::usual(25))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.check_stock().unwrap(), [B]);
    assert_eq!(provider.check_stock().unwrap(), Vec::<String>::new());
    assert_eq!(eco.kinds(), ["alert", "accepted", "done", "alert"]);

    // Told again once started again.
    drop(provider);
    eco.restart();
    assert_eq!(eco.provider().check_stock().unwrap(), [B]);
}

#[tokio::test]
async fn no_swap_is_made_to_a_hub_whose_window_the_lock_paying_the_provider_cannot_outlast() {
    // A's window no longer than B's: no lock at A outlives the provider's
    // at B by B's window and more.
    let eco = Eco::with(200, net::TIMING.window, CONFIG).await;
    let provider = eco.provider();
    let info = provider.info().unwrap();
    let at_b = info.hub(&eco.address(B)).unwrap();
    assert_eq!((at_b.max, at_b.margin), (150, Some(LEAD_B)));
    let quoted = eco
        .client
        .swap_quote(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await;
    let swapped = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await;
    for e in [quoted.unwrap_err(), swapped.unwrap_err()] {
        assert!(
            matches!(&e, Error::Invalid(why) if why.contains("admits none expiring after 20")),
            "{e}"
        );
    }
    assert!(eco.client.swaps().unwrap().is_empty());
    assert_eq!(held(&eco.client, A), 100);

    // A client that locks anyway, as late as A admits, is declined.
    let (a, b, me) = (eco.address(A), eco.address(B), eco.client.address());
    let to = provider.wallet().address();
    let lock = eco
        .client
        .lock(A, &to, 20 + costs(20).0, lock_hash(&[4; 32]), None);
    let lock = lock_id(&lock.await.unwrap().id);
    let declined = provider
        .take(&Request::new(&a, &lock, &b, &me, 20))
        .await
        .unwrap_err();
    assert_eq!(declined.code, Code::Declined);
    assert!(declined.message.contains("too soon"), "{declined:?}");
    assert!(provider.records(10).unwrap().is_empty());
}

#[tokio::test]
async fn a_provider_locks_nowhere_its_operator_would_hear_of_a_kept_preimage_too_late() {
    // A refund request that confirms within 3 blocks of the lock's expiry
    // is due before the hub, at depth 1 and reaction 2, has to refund.
    let config = Config {
        confirm: 3,
        ..CONFIG
    };
    let eco = Eco::with(200, WINDOW_A, config).await;
    let provider = eco.provider();
    let info = provider.info().unwrap();
    for url in [A, B] {
        let hub = info.hub(&eco.address(url)).unwrap();
        assert_eq!((hub.max, hub.margin), (0, None));
    }
    assert_eq!(info.margin, CONFIG.margin);
    let e = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await;
    assert!(
        matches!(&e, Err(Error::Invalid(why)) if why.contains("to 0")),
        "{e:?}"
    );

    let (a, b, me) = (eco.address(A), eco.address(B), eco.client.address());
    let to = provider.wallet().address();
    let lock = eco
        .client
        .lock(A, &to, 20 + costs(20).0, lock_hash(&[5; 32]), None);
    let lock = lock_id(&lock.await.unwrap().id);
    let declined = provider
        .take(&Request::new(&a, &lock, &b, &me, 20))
        .await
        .unwrap_err();
    assert_eq!(declined.code, Code::Declined);
    assert!(declined.message.contains("refund request"), "{declined:?}");
    assert!(provider.records(10).unwrap().is_empty());
}

#[tokio::test]
async fn the_operator_is_alerted_once_of_a_hub_that_neither_pays_nor_refunds_its_lock() {
    let eco = Eco::new(200).await;
    // The client's claim is lost, and the client gone.
    eco.net.fail(licash_api::SETTLE, Fault::Lost);
    let e = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Pending { .. }), "{e}");
    let provider = eco.provider();
    // The refund of the provider's lock, which its wallet and the swap ask
    // for at each step, is not given.
    let withhold = |fault| {
        for _ in 0..2 {
            eco.net.fail(licash_api::REFUND, fault);
        }
    };
    // Its lock expires at 14, owed back at 15, refunded by 17 at the
    // latest if B answers.
    eco.mine(12);
    withhold(Fault::Refused(Code::Unexpired));
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(eco.kinds(), ["accepted"]);
    eco.mine(2);
    withhold(Fault::Lost);
    assert_eq!(provider.step().await.unwrap().len(), 1);
    assert_eq!(eco.kinds(), ["accepted", "alert"]);
    withhold(Fault::Refused(Code::Unexpired));
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(eco.kinds(), ["accepted", "alert"]);
    let events = provider.events(0, 10).unwrap();
    let Some(Notice::Alert { message }) = events[1].notice() else {
        panic!("{events:?}");
    };
    // The refund request is due by 14 + 4; the client's lock expires at 46.
    for says in [B, "expired at 14", "by height 18", A, "expires at 46"] {
        assert!(message.contains(says), "{message}");
    }
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Locked);

    // Told again once started again, until B refunds.
    drop(provider);
    eco.restart();
    withhold(Fault::Refused(Code::Unexpired));
    assert!(eco.provider().step().await.unwrap().is_empty());
    assert!(eco.provider().step().await.unwrap().is_empty());
    assert_eq!(eco.provider().records(1).unwrap()[0].stage, Stage::Refunded);
    assert_eq!(eco.kinds(), ["accepted", "alert", "alert", "refunded"]);
}

impl Eco {
    /// Hub B's own lock under the hash of the swap `id`, made as the
    /// provider makes it from the ephemeral secret it recorded, or from
    /// another: as if B stopped once it locked, before the provider
    /// recorded the lock.
    fn lock_own(&self, id: &str, recorded: bool) {
        use licash::{address::Ephemeral, crypto::ScalarBytes, spend::TimedTerms};
        let c = rusqlite::Connection::open(self.dir.path().join("provider.sqlite")).unwrap();
        let (address, amount, hash, expiry, secret) = c
            .query_row(
                "SELECT s.address, s.amount, s.hash, s.expiry_height, i.ephemeral
                 FROM provider_swaps s JOIN provider_issues i ON i.id = s.id WHERE s.id = ?1",
                [hex::decode(id).unwrap()],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, [u8; 32]>(2)?,
                        r.get::<_, u32>(3)?,
                        r.get::<_, [u8; 32]>(4)?,
                    ))
                },
            )
            .unwrap();
        let secret = if recorded { secret } else { [7; 32] };
        let ephemeral = Ephemeral::from_scalar(ScalarBytes(secret).to_scalar().unwrap()).unwrap();
        let address = licash::address::Address::from_bytes(&address).unwrap();
        let hub = self.net.hub(B);
        let keyset = hub.info().keysets.remove(0);
        let pay = licash_wallet::pay_outputs(&keyset, &ephemeral, &address, amount).unwrap();
        let checkpoint = hub.checkpoint().unwrap();
        let terms = TimedTerms::new(
            checkpoint.profile(),
            checkpoint.commitment(),
            expiry,
            1,
            hash,
        )
        .unwrap();
        hub.lock_own(keyset.id(), ephemeral.public(), pay, terms)
            .unwrap();
    }

    /// The expiry of the lock `id` at the hub at `url`.
    fn expiry(&self, url: &str, id: &str) -> u32 {
        let lock = self.net.hub(url).locked(&lock_id(id)).unwrap();
        lock.proposal.lock().unwrap().terms().expiry()
    }
}

fn no_guard() -> Guard {
    Box::new(|_| Ok(false))
}

#[tokio::test]
async fn a_hub_swaps_into_itself_notes_it_issues_from_a_hub_of_the_same_window() {
    let eco = Eco::issuing(100, no_guard()).await;
    let (fee, lock_fee) = costs(20);
    let provider = eco.provider();
    // At B as much as it may still take of A's notes, up to its most, the
    // client's lock outliving its own by little: B keeps no preimage from
    // itself. Nothing at A.
    let info = provider.info().unwrap();
    let at = |url| {
        let hub = info.hub(&eco.address(url)).unwrap();
        (hub.max, hub.margin)
    };
    assert_eq!((at(B), at(A)), ((100, Some(OWN_LEAD)), (0, None)));
    assert_eq!(info.margin, OWN_LEAD);
    assert_ne!(info.address, eco.address(B));

    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    assert_eq!(held(&eco.client, B), 20);
    let record = provider.records(1).unwrap().remove(0);
    assert_eq!(record.stage, Stage::Locked);
    let lock = record.lock.unwrap();
    assert_eq!(
        record.expiry,
        eco.expiry(A, swap.lock.as_ref().unwrap()) - OWN_LEAD
    );
    // Of notes B issued: the provider's wallet locked nothing there.
    assert!(eco.net.hub(B).locked(&lock_id(&lock)).unwrap().own);
    assert!(provider.wallet().locks().unwrap().is_empty());
    // What the client's lock pays at A counts against the cap, owed or
    // held.
    let left = || provider.info().unwrap().hub(&eco.address(B)).unwrap().max;
    assert_eq!(left(), 100 - 20 - fee);

    assert!(provider.step().await.unwrap().is_empty());
    let record = &provider.records(1).unwrap()[0];
    assert_eq!((record.stage, record.paid), (Stage::Done, 20 + fee));
    assert_eq!(held(provider.wallet(), A), 20 + fee);
    assert_eq!(left(), 100 - 20 - fee);
    assert_eq!(eco.kinds(), ["accepted", "done"]);
    eco.client.resume().await.unwrap();
    assert_eq!(held(&eco.client, A), 100 - 20 - fee - lock_fee);
    assert_eq!(
        eco.client.follow_swap(&swap.hash).await.unwrap().state,
        SwapState::Done
    );
}

#[tokio::test]
async fn a_hub_takes_swaps_into_itself_only_from_the_hubs_it_caps() {
    let eco = Eco::issuing(30, no_guard()).await;
    let provider = eco.provider();
    let fee = costs(20).0;
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    // Owed 21 of A's notes, 9 under its cap: a client locks nothing for
    // more.
    let left = provider.info().unwrap().hub(&eco.address(B)).unwrap().max;
    assert_eq!(left, 30 - 20 - fee);
    let e = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Invalid(_)), "{e}");
    assert_eq!(eco.client.swaps().unwrap().len(), 1);

    // One that locks anyway is declined.
    let (a, b, me) = (eco.address(A), eco.address(B), eco.client.address());
    let to = provider.wallet().address();
    let lock = eco.client.lock(A, &to, 20 + fee, lock_hash(&[6; 32]), None);
    let lock = lock_id(&lock.await.unwrap().id);
    let take = |request: Request| {
        let provider = provider.clone();
        async move { provider.take(&request).await.unwrap_err() }
    };
    let declined = take(Request::new(&a, &lock, &b, &me, 20)).await;
    assert_eq!(declined.code, Code::Declined);
    assert!(declined.message.contains("no more"), "{declined:?}");
    // Nor does B swap out of itself, or into another hub.
    let declined = take(Request::new(&b, &lock, &a, &me, 20)).await;
    assert!(
        declined.message.contains("between these hubs"),
        "{declined:?}"
    );
    let invalid = take(Request::new(&a, &lock, &b, &b, 20)).await;
    assert_eq!(invalid.code, Code::Invalid);

    // Nor from a hub it holds no cap for.
    const C: &str = "http://c.test";
    eco.net.start(C, FEE);
    provider.wallet().add_hub(C).await.unwrap();
    eco.client.add_hub(C).await.unwrap();
    eco.client
        .receive(&eco.net.pay(C, &eco.client.address(), 100))
        .unwrap();
    let lock = eco.client.lock(C, &to, 20 + fee, lock_hash(&[7; 32]), None);
    let lock = lock_id(&lock.await.unwrap().id);
    let declined = take(Request::new(&eco.address(C), &lock, &b, &me, 20)).await;
    assert!(
        declined.message.contains("no swaps from hub"),
        "{declined:?}"
    );
    assert_eq!(provider.records(10).unwrap().len(), 1);
}

#[tokio::test]
async fn a_hub_caps_a_hub_it_swaps_from_at_every_url_its_wallet_knows_it_by() {
    const SECURE_A: &str = "https://a.test";
    let eco = Eco::issuing(30, no_guard()).await;
    let fee = costs(20).0;
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    // A answers over HTTPS too: the provider reaches it there from now on,
    // owed 21 of its notes by a swap recorded at the old URL.
    eco.net.alias(SECURE_A, A);
    eco.restart();
    eco.provider().wallet().add_hub(A).await.unwrap();
    assert_eq!(eco.provider().wallet().hub_urls(A).unwrap(), [SECURE_A, A]);
    let left = |eco: &Eco| {
        let info = eco.provider().info().unwrap();
        info.hub(&eco.address(B)).unwrap().max
    };
    // Its cap, naming the old URL or the new, counts what is owed.
    assert_eq!(left(&eco), 30 - 20 - fee);
    eco.stop();
    let path = eco.dir.path().join("provider.sqlite");
    let wallet = Wallet::open(&path, Link(eco.net.clone())).unwrap();
    let issuer = Issuer::new(eco.net.hub(B), B).cap(SECURE_A, 30);
    let provider = Provider::open_issuing(wallet, CONFIG, issuer).unwrap();
    let provider = Arc::new(provider);
    *eco.desk.provider.lock().unwrap() = Some(provider.clone());
    assert_eq!(left(&eco), 30 - 20 - fee);
    // One that locks for more anyway is declined.
    let (a, b, me) = (eco.address(A), eco.address(B), eco.client.address());
    let to = provider.wallet().address();
    let lock = eco.client.lock(A, &to, 20 + fee, lock_hash(&[6; 32]), None);
    let lock = lock_id(&lock.await.unwrap().id);
    let declined = provider
        .take(&Request::new(&a, &lock, &b, &me, 20))
        .await
        .unwrap_err();
    assert!(declined.message.contains("no more"), "{declined:?}");
    assert_eq!(provider.records(10).unwrap().len(), 1);
}

/// Intake limits of these hubs' notes, by URL.
fn limits(of: &[(&str, u64)]) -> Option<HashMap<String, u64>> {
    Some(
        of.iter()
            .map(|&(url, most)| (url.to_owned(), most))
            .collect(),
    )
}

#[tokio::test]
async fn a_provider_takes_notes_at_each_hub_only_within_its_limit_there() {
    const SECURE_A: &str = "https://a.test";
    let eco = Eco::new(200).await;
    let fee = costs(20).0;
    let provider = eco.provider();
    // Not limited until limited.
    assert_eq!(provider.intake(), None);
    provider.limit_intake(limits(&[(A, 30)]));
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    // Owed 21 of A's notes, then holding them: counted once.
    assert_eq!(provider.exposure(A).unwrap(), 20 + fee);
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Done);
    assert_eq!(provider.exposure(A).unwrap(), 20 + fee);
    assert_eq!(provider.exposure(B).unwrap(), held(provider.wallet(), B));

    // A swap bringing it 21 more, 9 under its limit, is declined.
    let (a, b, me) = (eco.address(A), eco.address(B), eco.client.address());
    let to = provider.wallet().address();
    let lock = eco.client.lock(A, &to, 20 + fee, lock_hash(&[6; 32]), None);
    let lock = lock_id(&lock.await.unwrap().id);
    let request = Request::new(&a, &lock, &b, &me, 20);
    let declined = provider.take(&request).await.unwrap_err();
    assert_eq!(declined.code, Code::Declined);
    let no_more = "the provider takes no more of hub http://a.test's notes now";
    assert_eq!(declined.message, no_more);
    // As at a hub its limits do not name.
    provider.limit_intake(limits(&[(B, 1_000)]));
    let declined = provider.take(&request).await.unwrap_err();
    assert_eq!(declined.message, no_more);
    drop(provider);

    // A answers over HTTPS too: a limit naming it there counts what it
    // took at the old URL. Restarted, it is not limited until limited.
    eco.net.alias(SECURE_A, A);
    eco.restart();
    let provider = eco.provider();
    assert_eq!(provider.intake(), None);
    provider.wallet().add_hub(A).await.unwrap();
    assert_eq!(provider.wallet().hub_urls(A).unwrap(), [SECURE_A, A]);
    provider.limit_intake(limits(&[(SECURE_A, 30)]));
    assert_eq!(provider.intake(), limits(&[(SECURE_A, 30)]));
    assert_eq!(provider.exposure(A).unwrap(), 20 + fee);
    assert_eq!(provider.exposure(SECURE_A).unwrap(), 20 + fee);
    let declined = provider.take(&request).await.unwrap_err();
    assert!(declined.message.contains("takes no more"), "{declined:?}");
    assert_eq!(provider.records(10).unwrap().len(), 1);

    // Within it, or the limit lifted: taken.
    provider.limit_intake(limits(&[(SECURE_A, 30 + 20 + fee)]));
    provider.take(&request).await.unwrap();
    assert_eq!(provider.records(10).unwrap().len(), 2);
    assert_eq!(provider.exposure(A).unwrap(), 2 * (20 + fee));
    provider.limit_intake(None);
    assert_eq!(provider.intake(), None);
}

#[tokio::test]
async fn a_hub_takes_another_hubs_notes_within_its_cap_and_its_limit_both() {
    let eco = Eco::issuing(30, no_guard()).await;
    let provider = eco.provider();
    let left = || provider.info().unwrap().hub(&eco.address(B)).unwrap().max;
    assert_eq!(left(), 30);
    // The lesser of its cap and its limit, none at a hub not named.
    provider.limit_intake(limits(&[(A, 10)]));
    assert_eq!(left(), 10);
    provider.limit_intake(limits(&[(A, 1_000)]));
    assert_eq!(left(), 30);
    provider.limit_intake(limits(&[]));
    assert_eq!(left(), 0);
    // A client locks nothing for more.
    let e = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Invalid(_)), "{e}");
    assert!(eco.client.swaps().unwrap().is_empty());

    // One that locks anyway, under its cap and over its limit, is declined.
    provider.limit_intake(limits(&[(A, 15)]));
    let fee = costs(20).0;
    let (a, b, me) = (eco.address(A), eco.address(B), eco.client.address());
    let to = provider.wallet().address();
    let lock = eco.client.lock(A, &to, 20 + fee, lock_hash(&[6; 32]), None);
    let lock = lock_id(&lock.await.unwrap().id);
    let declined = provider
        .take(&Request::new(&a, &lock, &b, &me, 20))
        .await
        .unwrap_err();
    assert_eq!(declined.code, Code::Declined);
    assert_eq!(
        declined.message,
        "the hub takes no more of hub http://a.test's notes now"
    );
    assert!(provider.records(10).unwrap().is_empty());
}

#[tokio::test]
async fn a_hub_restarted_adopts_the_lock_it_made_and_never_locks_again() {
    // B's other services' hashes cannot be read: the provider records the
    // swaps, but does not lock.
    let eco = Eco::issuing(100, Box::new(|_| Err("receipts unreadable".into()))).await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        // A note for each lock: the change of the last is not back yet.
        let note = eco.net.pay(A, &eco.client.address(), 16);
        eco.client.receive(&note).unwrap();
        let e = eco
            .client
            .swap(PROVIDER, A, B, 10, SwapLimits::usual(10))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, Error::Pending { reason, .. } if reason.contains("locking")),
            "{e}"
        );
        let record = eco.provider().records(1).unwrap().remove(0);
        assert_eq!((record.stage, record.lock), (Stage::Accepted, None));
        ids.push(record.id);
    }
    // B locked the second swap's notes before it stopped, and other notes
    // under the third's hash.
    eco.lock_own(&ids[1], true);
    eco.lock_own(&ids[2], false);

    // Only B takes its swaps on.
    eco.stop();
    // Counted read only, beside it or without it: none of a file never made.
    let file = eco.dir.path().join("provider.sqlite");
    assert_eq!(licash_swaps::own_under_way(&file).unwrap(), 3);
    let none = eco.dir.path().join("none.sqlite");
    assert_eq!(licash_swaps::own_under_way(&none).unwrap(), 0);
    assert!(!none.exists());
    match eco.reopen(None) {
        Err(licash_swaps::Error::Setup(why)) => assert!(why.contains("3 swaps"), "{why}"),
        Err(e) => panic!("{e}"),
        Ok(_) => panic!("opened"),
    }
    *eco.desk.provider.lock().unwrap() = Some(Arc::new(eco.reopen(eco.cap).unwrap()));
    let provider = eco.provider();
    assert!(provider.step().await.unwrap().is_empty());
    let record = |id: &str| {
        let records = provider.records(10).unwrap();
        records.into_iter().find(|r| r.id == id).unwrap()
    };
    let (first, second, third) = (record(&ids[0]), record(&ids[1]), record(&ids[2]));
    assert_eq!(first.stage, Stage::Failed);
    assert!(first.reason.unwrap().contains("stopped before locking"));
    assert_eq!(second.stage, Stage::Locked);
    assert!(second.lock.is_some());
    assert_eq!(third.stage, Stage::Failed);
    assert!(third.reason.unwrap().contains("other notes"));
    assert_eq!(
        eco.kinds(),
        ["accepted", "accepted", "accepted", "failed", "alert", "failed"]
    );
    // Read beside the provider: only the second swap backs a lock of B's.
    let swaps = eco.dir.path().join("provider.sqlite");
    let hashes: Vec<[u8; 32]> = {
        let c = rusqlite::Connection::open(&swaps).unwrap();
        let hash = |id: &String| {
            let id = hex::decode(id).unwrap();
            c.query_row("SELECT hash FROM provider_swaps WHERE id = ?1", [id], |r| {
                r.get(0)
            })
        };
        ids.iter().map(hash).collect::<Result<_, _>>().unwrap()
    };
    let backing = licash_swaps::backing_own(&swaps, &hashes).unwrap();
    assert_eq!(backing.into_iter().collect::<Vec<_>>(), [hashes[1]]);
    assert_eq!(licash_swaps::own_under_way(&swaps).unwrap(), 1);
    let none = eco.dir.path().join("none.sqlite");
    assert!(licash_swaps::backing_own(&none, &hashes)
        .unwrap()
        .is_empty());
    assert!(!none.exists());

    // The second swap's client claims B's lock, and the provider the
    // client's.
    let resumed = eco.client.resume().await.unwrap();
    let done = resumed.swaps.iter().filter(|s| s.state == SwapState::Done);
    assert_eq!(done.count(), 1, "{resumed:?}");
    assert_eq!(held(&eco.client, B), 10);
    // Reached at another URL once started again, B still takes it on.
    drop(provider);
    eco.stop();
    let wallet = Wallet::open(
        &eco.dir.path().join("provider.sqlite"),
        Link(eco.net.clone()),
    );
    let issuer = Issuer::new(eco.net.hub(B), "http://b.renamed.test").cap(A, 100);
    let provider = Provider::open_issuing(wallet.unwrap(), CONFIG, issuer).unwrap();
    assert!(provider.step().await.unwrap().is_empty());
    let records = provider.records(10).unwrap();
    let second = records.iter().find(|r| r.id == ids[1]).unwrap();
    assert_eq!(second.stage, Stage::Done);
    assert_eq!(held(provider.wallet(), A), 10 + costs(10).0);
}

#[tokio::test]
async fn a_hub_locks_no_hash_another_of_its_services_holds() {
    let eco = Eco::issuing(100, Box::new(|_| Ok(true))).await;
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await;
    let failed = match swap {
        Ok(swap) => swap.state,
        Err(e) => panic!("{e}"),
    };
    assert!(
        matches!(&failed, SwapState::Failed(why) if why.contains("another payment")),
        "{failed:?}"
    );
    let record = &eco.provider().records(1).unwrap()[0];
    assert_eq!((record.stage, &record.lock), (Stage::Failed, &None));
    assert_eq!(eco.kinds(), ["accepted", "failed"]);
}

#[tokio::test]
async fn a_canceled_take_keeps_its_turn_until_the_blocking_lock_is_recorded() {
    let (entered, entering) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let released = Mutex::new(released);
    let guard: Guard = Box::new(move |_| {
        entered.send(()).unwrap();
        released
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        Ok(false)
    });
    let eco = Arc::new(Eco::issuing(100, guard).await);
    let taking = {
        let eco = eco.clone();
        tokio::spawn(async move {
            eco.client
                .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while entering.try_recv().is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    taking.abort();
    assert!(taking.await.unwrap_err().is_cancelled());
    assert!(eco.turn.try_lock().is_err());
    let provider = eco.provider();
    let mut following = tokio::spawn(async move { provider.step().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut following)
            .await
            .is_err()
    );
    release.send(()).unwrap();
    assert!(following.await.unwrap().unwrap().is_empty());
    let row = eco.provider().records(1).unwrap().remove(0);
    assert_eq!(row.stage, Stage::Locked);
    let id = lock_id(&row.lock.unwrap());
    assert!(eco.net.hub(B).locked(&id).unwrap().own);
    assert!(eco.turn.try_lock().is_ok());
    assert_eq!(eco.kinds(), ["accepted"]);
}

#[tokio::test]
async fn canceling_while_waiting_for_the_turn_creates_no_own_lock() {
    let eco = Arc::new(Eco::issuing(100, no_guard()).await);
    let held = eco.turn.clone().lock_owned().await;
    let taking = {
        let eco = eco.clone();
        tokio::spawn(async move {
            eco.client
                .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while eco.provider().records(1).unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    taking.abort();
    assert!(taking.await.unwrap_err().is_cancelled());
    drop(held);
    assert!(eco.provider().step().await.unwrap().is_empty());
    let row = eco.provider().records(1).unwrap().remove(0);
    assert_eq!(row.stage, Stage::Failed);
    assert!(row.lock.is_none());
    let hash: [u8; 32] = hex::decode(&row.hash).unwrap().try_into().unwrap();
    assert!(eco.net.hub(B).own_lock_of(&hash).unwrap().is_none());
    assert!(eco.turn.try_lock().is_ok());
}

/// What the hub's ledger waits on, such as a block scan, waits off the
/// async runtime: the runtime's one thread runs other tasks meanwhile.
#[tokio::test]
async fn a_hub_locks_its_own_off_the_async_runtime() {
    let (entered, entering) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = Mutex::new(released);
    let guard: Guard = Box::new(move |_| {
        entered.send(()).map_err(|e| e.to_string())?;
        let waited = released
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
        waited
            .map(|()| false)
            .map_err(|_| "the runtime stood still".into())
    });
    let eco = Eco::issuing(100, guard).await;
    let releasing = tokio::spawn(async move {
        while entering.try_recv().is_err() {
            tokio::task::yield_now().await;
        }
        release.send(()).unwrap();
    });
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    releasing.await.unwrap();
}

#[tokio::test]
async fn a_hubs_own_lock_its_client_never_claims_is_refunded() {
    let eco = Eco::issuing(100, no_guard()).await;
    // The client's claim is lost, and the client gone.
    eco.net.fail(licash_api::SETTLE, Fault::Lost);
    let e = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Pending { .. }), "{e}");
    let provider = eco.provider();
    let expiry = provider.records(1).unwrap()[0].expiry;
    let left = || provider.info().unwrap().hub(&eco.address(B)).unwrap().max;
    assert_eq!(left(), 100 - 20 - costs(20).0);
    // Refunded once expired at depth 1.
    eco.mine(expiry - 3);
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Locked);
    eco.mine(1);
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Refunded);
    assert_eq!(eco.kinds(), ["accepted", "refunded"]);
    // Owed nothing at A any more.
    assert_eq!(left(), 100);
}

#[tokio::test]
async fn the_operator_is_alerted_once_of_a_claim_late_at_the_hub_swapped_from() {
    let eco = Eco::issuing(100, no_guard()).await;
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    let provider = eco.provider();
    // The provider claims the client's lock within its margin, 6, and the
    // time a claim on Bitcoin takes, 4, of its expiry.
    let expiry = eco.expiry(A, swap.lock.as_ref().unwrap());
    let due = expiry - 6 - 4;
    eco.mine(due - 1 - 3);
    eco.net.fail(licash_api::SETTLE, Fault::Lost);
    assert_eq!(provider.step().await.unwrap().len(), 1);
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Paid);
    assert_eq!(eco.kinds(), ["accepted"]);
    eco.mine(1);
    for _ in 0..2 {
        eco.net.fail(licash_api::SETTLE, Fault::Lost);
        assert_eq!(provider.step().await.unwrap().len(), 1);
    }
    assert_eq!(eco.kinds(), ["accepted", "alert"]);
    let events = provider.events(0, 10).unwrap();
    let Some(Notice::Alert { message }) = events[1].notice() else {
        panic!("{events:?}");
    };
    for says in [A, &format!("expires at {expiry}")] {
        assert!(message.contains(says), "{message}");
    }
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Done);
    assert_eq!(eco.kinds(), ["accepted", "alert", "done"]);
}

#[tokio::test]
async fn the_operator_is_alerted_of_a_late_claim_though_the_hub_swapped_from_lags() {
    let eco = Eco::issuing(100, no_guard()).await;
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    let provider = eco.provider();
    let expiry = eco.expiry(A, swap.lock.as_ref().unwrap());
    // Hub A says it is still at 3, and loses the claim: the provider's own
    // hub, at the height it is due by, alerts the operator.
    eco.net.mine(B, expiry - 6 - 4 - 3, None);
    eco.net.fail(licash_api::SETTLE, Fault::Lost);
    assert_eq!(provider.step().await.unwrap().len(), 1);
    assert_eq!(eco.kinds(), ["accepted", "alert"]);
}

#[tokio::test]
async fn a_hubs_own_lock_activated_too_late_is_refunded_and_the_clients_lock_left_unclaimed() {
    let eco = Eco::issuing(100, no_guard()).await;
    let provider = eco.provider();
    let fee = costs(20).0;
    let (a, b, me) = (eco.address(A), eco.address(B), eco.client.address());
    let to = provider.wallet().address();
    for preimage in [[5; 32], [6; 32]] {
        let note = eco.net.pay(A, &me, 30);
        eco.client.receive(&note).unwrap();
        let lock = eco
            .client
            .lock(A, &to, 20 + fee, lock_hash(&preimage), None);
        let lock = lock_id(&lock.await.unwrap().id);
        let request = Request::new(&a, &lock, &b, &me, 20);
        let taken = provider.take(&request).await.unwrap();
        assert_eq!(taken.state, swaps::State::Locked);
    }
    let record = |preimage: [u8; 32]| {
        let hash = hex::encode(lock_hash(&preimage));
        let records = provider.records(10).unwrap();
        records.into_iter().find(|r| r.hash == hash).unwrap()
    };
    // The first activated on Bitcoin in time, its client gone: the hub
    // pays it, and the provider claims the client's lock.
    eco.net.mine(B, 1, Some([5; 32]));
    assert!(provider.step().await.unwrap().is_empty());
    let first = record([5; 32]);
    assert_eq!(first.stage, Stage::Done);
    assert_eq!(held(provider.wallet(), A), 20 + fee);
    let lock = first.lock.unwrap();
    eco.client.claim(B, &lock, &[5; 32]).await.unwrap();
    assert_eq!(held(&eco.client, B), 20);

    // The second activated once expired: the hub pays nothing, refunds,
    // and claims nothing at A.
    let second = record([6; 32]);
    let height = eco.net.view(B).height();
    eco.net.mine(B, second.expiry - height, None);
    eco.net.mine(B, 1, Some([6; 32]));
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(record([6; 32]).stage, Stage::Refunded);
    assert_eq!(held(provider.wallet(), A), 20 + fee);
    let late = eco.client.claim(B, &second.lock.unwrap(), &[6; 32]).await;
    assert!(late.is_err(), "{late:?}");
    assert_eq!(held(&eco.client, B), 20);
}

#[tokio::test]
async fn a_hub_claims_the_lock_backing_its_own_until_the_hub_swapped_from_refuses() {
    let eco = Eco::issuing(100, no_guard()).await;
    let swap = eco
        .client
        .swap(PROVIDER, A, B, 20, SwapLimits::usual(20))
        .await
        .unwrap();
    assert_eq!(swap.state, SwapState::Done);
    let provider = eco.provider();
    // Asleep until the client's lock is within 3 blocks of its expiry: the
    // preimage out at B already, the provider claims it still.
    let expiry = eco.expiry(A, swap.lock.as_ref().unwrap());
    eco.mine(expiry - 2 - 3);
    assert!(provider.step().await.unwrap().is_empty());
    assert_eq!(provider.records(1).unwrap()[0].stage, Stage::Done);
    assert_eq!(held(provider.wallet(), A), 20 + costs(20).0);
}
