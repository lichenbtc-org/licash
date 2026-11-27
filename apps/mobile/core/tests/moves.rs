//! Moving notes between the phone's own hubs through swap providers in
//! this process, announced on a relay its hubs name: what it costs, the
//! move itself, and the next provider tried only when one failed before
//! the phone's notes were locked to it. And paying a Lightning invoice
//! through such a provider, from its own node, when no hub's gateway does.

#[path = "../../../hub/tests/chain/mod.rs"]
mod chain;
mod mint;

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::Duration,
};

use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    Json,
};
use licash::{
    address::Address,
    spend::{lock_hash, ChainProfile},
};
use licash_api::{swaps, Code, Fee, Payment, Problem};
use licash_hub::{Hub, Policy, Timing};
use licash_hub_service::Services;
use licash_lightning::fake::{Fake, Outcome};
use licash_mobile::{
    ChainError, ChainSource, Details, Flow, InvoiceQuote, Kind, MoveQuote, Network, State, Wallet,
    Way,
};
use licash_nostr::Route;
use licash_swaps::{Config, Provider};
use licash_transport::Http;
use licash_wallet::PaymentCode;
use nostr_sdk::prelude::MockRelay;

const MAX_POW: u32 = 6;

/// Short, as the wallet CLI's tests have it.
const TIMING: Timing = Timing {
    window: 20,
    reaction: 2,
    min_depth: 1,
    max_headers: 4032,
    bury: 6,
    max_lag: 120,
};

/// The response window of the first hub, moved from: a provider's lock at
/// the second, of [`TIMING`]'s window of 20, expires 32 blocks before the
/// phone's with [`TERMS`], and leaves room to claim it.
const SOURCE_WINDOW: u32 = 46;

/// A provider's terms: a fee of 1 and 1%, swapping 5 to 5000, 6 blocks to
/// claim its client's lock and 4 to get a refund request confirmed.
const TERMS: Config = Config {
    fee: Fee {
        base: 1,
        ppm: 10_000,
    },
    min: 5,
    max: 5_000,
    margin: 6,
    confirm: 4,
};

/// Two hubs charging 1 on a payment, a lock and a refund, following the
/// same chain, naming one relay for their wallets to find providers on.
struct Hubs {
    runtime: tokio::runtime::Runtime,
    relay: MockRelay,
    hubs: Vec<Served>,
    dir: tempfile::TempDir,
}

struct Served {
    hub: Arc<Hub>,
    seed: std::path::PathBuf,
    url: String,
}

impl Hubs {
    fn start() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay = runtime.block_on(MockRelay::run()).unwrap();
        let relays = vec![runtime.block_on(relay.url()).to_string()];
        let dir = tempfile::tempdir().unwrap();
        let mut chain = chain::Chain::new();
        let mut hubs = Vec::new();
        for (name, window) in [("a", SOURCE_WINDOW), ("b", TIMING.window)] {
            let seed = dir.path().join(format!("{name}.seed"));
            let db = dir.path().join(format!("{name}.sqlite"));
            Hub::init(&seed, &db, MAX_POW).unwrap();
            let fee = Fee { base: 1, ppm: 0 };
            let policy = Policy {
                spend: fee,
                lock: fee,
                refund: fee,
                output_msat: 0,
                timing: Timing { window, ..TIMING },
            };
            let hub = Arc::new(Hub::open(&seed, &db, policy).unwrap());
            hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
            let services = Services {
                deposits: None,
                tweaks: None,
                inbox: None,
                relays: relays.clone(),
                contracts: None,
                urls: Default::default(),
                ingress: Default::default(),
            };
            let app = licash_hub_service::router(hub.clone(), services);
            let listener = runtime
                .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
                .unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });
            hubs.push(Served { hub, seed, url });
        }
        for _ in 0..3 {
            let block = chain.mine(None).clone();
            for served in &hubs {
                served.hub.observe(chain.height(), &block).unwrap();
            }
        }
        for served in &hubs {
            assert!(served.hub.synced(chain.height(), &chain.tip()).unwrap());
        }
        // Kept synced as a hub's service following Bitcoin keeps it: a
        // loaded runner setting providers up can take longer than the
        // hubs' `max_lag`, past which they would admit no lock.
        let (height, tip) = (chain.height(), chain.tip());
        for served in &hubs {
            let hub = served.hub.clone();
            runtime.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    hub.synced(height, &tip).unwrap();
                }
            });
        }
        Self {
            runtime,
            relay,
            hubs,
            dir,
        }
    }

    fn url(&self, i: usize) -> String {
        self.hubs[i].url.clone()
    }

    fn relays(&self) -> Vec<String> {
        vec![self.runtime.block_on(self.relay.url()).to_string()]
    }

    /// A phone trusting both hubs, holding `amount` at the first.
    fn phone(&self, amount: u64) -> Arc<Wallet> {
        let dir = self.dir.path().join("phone").display().to_string();
        let phone = Wallet::create(dir, Network::Regtest, 0, None).unwrap();
        phone.add_hub(self.url(0)).unwrap();
        phone.add_hub(self.url(1)).unwrap();
        let code: PaymentCode = phone.payment_code(None).unwrap().qr.parse().unwrap();
        let address = code.licash.unwrap().address;
        let payment = self.pay(0, &address, amount);
        phone
            .receive(serde_json::to_string(&payment).unwrap(), false)
            .unwrap();
        phone
    }

    /// Notes of `amount` paid to `to` at hub `i`, minted as its issuer.
    fn pay(&self, i: usize, to: &Address, amount: u64) -> Payment {
        let served = &self.hubs[i];
        mint::paid(
            (&served.hub, &served.seed, &served.url),
            MAX_POW,
            to,
            amount,
        )
    }
}

/// A swap provider on a local port between both hubs, holding stock at
/// the second, announced on their relay, taking its swaps on as the
/// service does, in the runtime of its own thread.
struct Swaps {
    provider: Arc<Provider<Http>>,
    /// Answers nothing but 503 while set: as if unreachable.
    down: Arc<AtomicBool>,
    /// Refuses swap requests while set, as invalid.
    refuse: Arc<AtomicBool>,
    addr: SocketAddr,
    stop: Option<(tokio::sync::oneshot::Sender<()>, JoinHandle<()>)>,
    _dir: tempfile::TempDir,
}

impl Swaps {
    fn start(hubs: &Hubs, seed: u8, terms: Config) -> Self {
        Self::start_with(hubs, seed, terms, None, None, None)
    }

    /// [`Swaps::start`], taking donations on `donating` through its node
    /// too, payers reaching it at [`DONATIONS`], as the service does with
    /// `--lnurl-url`.
    fn start_donating(
        hubs: &Hubs,
        seed: u8,
        terms: Config,
        donating: (Arc<Fake>, licash_swaps::DonationTerms),
    ) -> Self {
        Self::start_with(hubs, seed, terms, None, Some(donating), None)
    }

    /// [`Swaps::start`], paying Lightning invoices from `node` too, on
    /// `lightning`'s terms, as the service does with `--lnd`.
    fn start_paying(
        hubs: &Hubs,
        seed: u8,
        terms: Config,
        (node, lightning): (Arc<Fake>, swaps::Lightning),
    ) -> Self {
        Self::start_with(hubs, seed, terms, Some((node, lightning)), None, None)
    }

    /// [`Swaps::start`], taking payments over Lightning for wallets through
    /// `node` too, on `receiving`'s terms, as the service does with
    /// `--receive`.
    fn start_receiving(
        hubs: &Hubs,
        seed: u8,
        terms: Config,
        receiving: (Arc<Fake>, licash_swaps::ReceiveTerms),
    ) -> Self {
        Self::start_with(hubs, seed, terms, None, None, Some(receiving))
    }

    fn start_with(
        hubs: &Hubs,
        seed: u8,
        terms: Config,
        lightning: Option<(Arc<Fake>, swaps::Lightning)>,
        donating: Option<(Arc<Fake>, licash_swaps::DonationTerms)>,
        receiving: Option<(Arc<Fake>, licash_swaps::ReceiveTerms)>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let wallet = licash_wallet::Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[seed; 32],
            ChainProfile::Core30DefaultRegtest,
            Http::new(None).unwrap(),
        )
        .unwrap();
        let stocked = hubs.pay(1, &wallet.address(), 3_000);
        let urls = vec![hubs.url(0), hubs.url(1)];
        let relays = hubs.relays();
        let (down, refuse) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let (downed, refusing) = (down.clone(), refuse.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (ready, started) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                for url in &urls {
                    wallet.add_hub(url).await.unwrap();
                }
                wallet.receive(&stocked).unwrap();
                let provider = Provider::create(wallet, terms).unwrap();
                let paying = lightning.is_some();
                let provider = match lightning {
                    Some((node, lightning)) => provider.pay_lightning(node, lightning).unwrap(),
                    None => provider,
                };
                let provider = match donating {
                    Some((node, terms)) => provider.take_donations(node, terms, DONATIONS).unwrap(),
                    None => provider,
                };
                let receives = receiving.is_some();
                let provider = match receiving {
                    Some((node, terms)) => provider.take_receives(node, terms).unwrap(),
                    None => provider,
                };
                let provider = Arc::new(provider);
                let nostr = licash_nostr::public_key(&provider.nostr_secret().unwrap()).unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                ready.send((addr, provider.clone())).unwrap();
                let every = Duration::from_millis(100);
                let stepping = tokio::spawn(licash_swaps_service::step(provider.clone(), every));
                let paying = paying.then(|| {
                    tokio::spawn(licash_swaps_service::pay_invoices(provider.clone(), every))
                });
                let receiving = receives.then(|| {
                    tokio::spawn(licash_swaps_service::take_receives(provider.clone(), every))
                });
                let announcing = tokio::spawn(licash_swaps_service::announce(
                    provider.clone(),
                    relays,
                    Route::Direct,
                    vec![format!("http://{addr}")],
                    Some(format!("provider {seed}")),
                ));
                let failing = move |request: Request, next: Next| {
                    let down = downed.load(Ordering::SeqCst);
                    let refuse =
                        refusing.load(Ordering::SeqCst) && request.method() == Method::POST;
                    async move {
                        if down {
                            return StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        if refuse {
                            let problem = Problem::new(Code::Invalid, "refused as asked");
                            return (StatusCode::BAD_REQUEST, Json(problem)).into_response();
                        }
                        next.run(request).await
                    }
                };
                let router = licash_swaps_service::router(
                    provider,
                    licash_swaps_service::Serving {
                        nostr: Some(nostr),
                        ..Default::default()
                    },
                )
                .layer(middleware::from_fn(failing));
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        stopped.await.ok();
                    })
                    .await
                    .unwrap();
                stepping.abort();
                announcing.abort();
                for task in [paying, receiving].into_iter().flatten() {
                    task.abort();
                }
            });
        });
        let (addr, provider) = started.recv().unwrap();
        Self {
            provider,
            down,
            refuse,
            addr,
            stop: Some((stop, thread)),
            _dir: dir,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// How many swaps it took.
    fn swaps(&self) -> usize {
        self.provider.records(100).unwrap().len()
    }
}

impl Drop for Swaps {
    fn drop(&mut self) {
        if let Some((stop, thread)) = self.stop.take() {
            stop.send(()).ok();
            thread.join().ok();
        }
    }
}

/// The offers of moving `amount` from the first hub to the second, once
/// `count` providers are found, within 10 seconds.
fn offers(hubs: &Hubs, phone: &Wallet, amount: Option<u64>, count: usize) -> Vec<MoveQuote> {
    let mut last = None;
    for _ in 0..50 {
        match phone.move_offers(hubs.url(0), hubs.url(1), amount) {
            Ok(offers) if offers.len() >= count => return offers,
            other => last = Some(other),
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("{last:?}");
}

/// What the phone holds available at hub `i`.
fn held(hubs: &Hubs, phone: &Wallet, i: usize) -> u64 {
    let url = hubs.url(i);
    let holdings = phone.holdings().unwrap();
    holdings
        .iter()
        .find(|h| h.hub == url)
        .map_or(0, |h| h.available)
}

/// What the phone holds at hub `i` once nothing is pending there: its
/// change of a lock comes back once the lock settles, within 10 seconds.
fn settled(hubs: &Hubs, phone: &Wallet, i: usize) -> u64 {
    let url = hubs.url(i);
    for _ in 0..50 {
        let holdings = phone.holdings().unwrap();
        let holding = holdings.iter().find(|h| h.hub == url);
        if holding.is_none_or(|h| h.pending == 0) {
            return holding.map_or(0, |h| h.available);
        }
        phone.resume().unwrap();
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("{:?}", phone.holdings().unwrap());
}

/// The phone's move of `id` once done, its history followed meanwhile,
/// within a minute: a loaded runner, running several of these at once,
/// took more than 10 seconds.
fn until_moved(phone: &Wallet, id: &str) {
    let by = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < by {
        let history = phone.history().unwrap();
        let line = history.iter().find(|a| a.id == id && a.kind == Kind::Swap);
        match line.map(|a| a.state) {
            Some(State::Done) => return,
            Some(State::Failed) => panic!("{line:?}"),
            _ => {}
        }
        phone.resume().unwrap();
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("{:?}", phone.history().unwrap());
}

#[test]
fn a_phone_moves_its_notes_to_another_of_its_hubs_through_a_provider() {
    let hubs = Hubs::start();
    let phone = hubs.phone(1_000);
    let swaps = Swaps::start(&hubs, 0x51, TERMS);
    let quoted = offers(&hubs, &phone, Some(300), 1);
    // The provider's 1 and 1%, and the first hub's 1 on the lock.
    let offer = &quoted[0];
    assert_eq!(
        (offer.amount, offer.lock_fee, offer.fee),
        (300, 1, 5),
        "{offer:?}"
    );
    assert_eq!((&offer.from, &offer.to), (&hubs.url(0), &hubs.url(1)));
    // Its lock at the second hub expires 32 blocks before the phone's: 4 to
    // confirm a refund request, 20, 1 to read the preimage, 6 and 1.
    assert_eq!(offer.margin, 32, "{offer:?}");
    assert_eq!(offer.provider, swaps.url());
    assert_eq!(offer.provider_name.as_deref(), Some("provider 81"));

    let moved = phone.move_notes(quoted.clone()).unwrap();
    assert_eq!((moved.kind, moved.amount, moved.fee), (Kind::Swap, 300, 5));
    until_moved(&phone, &moved.id);
    assert_eq!(held(&hubs, &phone, 1), 300);
    assert_eq!(settled(&hubs, &phone, 0), 1_000 - 305);
    match phone.details(Kind::Swap, moved.id.clone()).unwrap() {
        Details::Swap {
            from,
            to,
            provider,
            lock,
            theirs,
            failure,
            provider_fee,
            lock_fee,
            expiry,
        } => {
            assert_eq!(
                (from, to, provider),
                (hubs.url(0), hubs.url(1), swaps.url())
            );
            assert!(lock.is_some() && theirs.is_some() && failure.is_none());
            // Its lock's expiry, when its notes would come back.
            assert!(expiry.is_some_and(|e| e > 0), "{expiry:?}");
            // Its fee's parts as recorded: the provider's 4, the hub's 1.
            assert_eq!((provider_fee, lock_fee), (4, 1));
        }
        other => panic!("{other:?}"),
    }
    // Its lock spent notes at the first hub, its claim made them at the
    // second.
    let notes = phone.notes_of(Kind::Swap, moved.id.clone()).unwrap();
    let at = |notes: &[licash_mobile::NoteLine], i: usize| -> u64 {
        let url = hubs.url(i);
        notes
            .iter()
            .filter(|n| n.hub == url)
            .map(|n| n.amount)
            .sum()
    };
    assert_eq!(at(&notes.spent, 1), 0, "{notes:?}");
    assert_eq!(at(&notes.made, 1), 300, "{notes:?}");
    assert_eq!(at(&notes.spent, 0), 305 + at(&notes.made, 0), "{notes:?}");

    // All that is left at the first hub, fitted to the fees.
    let left = held(&hubs, &phone, 0);
    let all = offers(&hubs, &phone, None, 1);
    let spends = all[0].amount + all[0].fee;
    assert!(spends <= left && spends + 5 >= left, "{all:?} of {left}");
    let moved = phone.move_notes(all.clone()).unwrap();
    until_moved(&phone, &moved.id);
    assert_eq!(settled(&hubs, &phone, 0), left - spends);
    assert_eq!(held(&hubs, &phone, 1), 300 + all[0].amount);
    let history = phone.history().unwrap();
    assert_eq!(history.iter().filter(|a| a.kind == Kind::Swap).count(), 2);

    // Stats count each move once, with its fee's parts, and what the other
    // hub's lock brought is no payment received.
    // The history shows the notes it brought as received besides.
    let got: Vec<_> = history
        .iter()
        .filter(|a| a.kind == Kind::Received)
        .collect();
    assert_eq!(got.len(), 3, "{got:?}");
    let stats = phone.stats(Arc::new(NoBlocks)).unwrap();
    let moves: Vec<_> = stats
        .events
        .iter()
        .filter(|e| (e.flow, e.way) == (Flow::Moved, Way::Licash))
        .collect();
    assert_eq!(moves.len(), 2, "{:?}", stats.events);
    let first = moves.iter().find(|e| e.amount == 300).unwrap();
    assert_eq!(
        (first.fee, first.hub_fee, first.provider_fee, first.state),
        (5, Some(1), Some(4), State::Done)
    );
    assert!(first.took.is_some());
    let received: Vec<_> = stats
        .events
        .iter()
        .filter(|e| e.flow == Flow::Received)
        .collect();
    assert_eq!(received.len(), 1, "{received:?}");
    assert_eq!(received[0].amount, 1_000);

    // Between two hubs only.
    assert!(phone.move_offers(hubs.url(0), hubs.url(0), None).is_err());
}

#[test]
fn a_move_tries_the_next_provider_costing_no_more_if_one_fails_before_locking() {
    let hubs = Hubs::start();
    let phone = hubs.phone(1_000);
    let first = Swaps::start(&hubs, 0x51, TERMS);
    let dearer = Config {
        fee: Fee {
            base: 50,
            ppm: 10_000,
        },
        ..TERMS
    };
    let pricier = Swaps::start(&hubs, 0x52, dearer);
    let same = Swaps::start(&hubs, 0x53, TERMS);
    let found = offers(&hubs, &phone, Some(300), 3);
    let by = |swaps: &Swaps| {
        found
            .iter()
            .find(|o| o.provider == swaps.url())
            .unwrap()
            .clone()
    };
    let chosen = vec![by(&first), by(&pricier), by(&same)];
    assert!(chosen[1].fee > chosen[0].fee && chosen[2].fee == chosen[0].fee);

    // The first unreachable: nothing locked to it, so the next costing
    // no more is tried; the dearer one never.
    first.down.store(true, Ordering::SeqCst);
    let moved = phone.move_notes(chosen.clone()).unwrap();
    until_moved(&phone, &moved.id);
    match phone.details(Kind::Swap, moved.id.clone()).unwrap() {
        Details::Swap { provider, .. } => assert_eq!(provider, same.url()),
        other => panic!("{other:?}"),
    }
    assert_eq!((first.swaps(), pricier.swaps(), same.swaps()), (0, 0, 1));
    assert_eq!(held(&hubs, &phone, 1), 300);

    // None costing no more reachable: refused, nothing moved or locked.
    same.down.store(true, Ordering::SeqCst);
    let before = held(&hubs, &phone, 0);
    assert!(phone.move_notes(chosen).is_err());
    assert_eq!(held(&hubs, &phone, 0), before);
    assert_eq!(pricier.swaps(), 0);
    let history = phone.history().unwrap();
    assert_eq!(history.iter().filter(|a| a.kind == Kind::Swap).count(), 1);
}

#[test]
fn a_move_is_never_tried_again_once_its_notes_were_locked() {
    let hubs = Hubs::start();
    let phone = hubs.phone(1_000);
    let first = Swaps::start(&hubs, 0x51, TERMS);
    let next = Swaps::start(&hubs, 0x53, TERMS);
    let found = offers(&hubs, &phone, Some(300), 2);
    let by = |swaps: &Swaps| {
        found
            .iter()
            .find(|o| o.provider == swaps.url())
            .unwrap()
            .clone()
    };

    // The phone locks its notes first, then asks: refused once locked.
    first.refuse.store(true, Ordering::SeqCst);
    let moving = phone.move_notes(vec![by(&first), by(&next)]);
    assert_eq!(next.swaps(), 0, "{moving:?}");
    let history = phone.history().unwrap();
    let swaps: Vec<_> = history.iter().filter(|a| a.kind == Kind::Swap).collect();
    assert_eq!(swaps.len(), 1, "{history:?}");
    match phone.details(Kind::Swap, swaps[0].id.clone()).unwrap() {
        Details::Swap { provider, lock, .. } => {
            assert_eq!(provider, first.url());
            assert!(lock.is_some());
        }
        other => panic!("{other:?}"),
    }
    // Its notes stay locked until the lock expires: none at the other hub.
    assert_eq!(held(&hubs, &phone, 1), 0);
    assert!(held(&hubs, &phone, 0) < 1_000 - 300);
}

/// The quote of paying `request` through a provider, once one is found,
/// within 10 seconds.
/// Where payers reach a provider taking donations.
const DONATIONS: &str = "https://donate.test";

#[test]
fn a_phone_finds_its_static_donation_address_at_a_provider_taking_them() {
    let hubs = Hubs::start();
    let phone = hubs.phone(1_000);
    // No provider, then one taking no donations: no address.
    assert_eq!(phone.donation_address().unwrap(), None);
    let swapping = Swaps::start(&hubs, 0x51, TERMS);
    offers(&hubs, &phone, Some(300), 1);
    assert_eq!(phone.donation_address().unwrap(), None);

    let terms = licash_swaps::DonationTerms::default();
    let donating = Swaps::start_donating(&hubs, 0x53, TERMS, (Arc::new(Fake::new()), terms));
    let mut found = None;
    for _ in 0..50 {
        found = phone.donation_address().unwrap();
        if found.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let address = found.expect("a donation address");
    assert_eq!(address.provider, donating.url());
    assert_eq!(address.name.as_deref(), Some("provider 83"));
    let terms = licash_swaps::DonationTerms::default();
    assert_eq!(
        (address.fee_base, address.fee_ppm, address.min, address.max),
        (terms.fee.base, terms.fee.ppm, terms.min, terms.max)
    );
    // It holds 3,000 at the second hub.
    assert!(address.stocked, "{address:?}");
    // The code the phone shows, at the provider's public URL.
    let code: PaymentCode = phone.payment_code(None).unwrap().qr.parse().unwrap();
    let code = code.licash.unwrap().to_string();
    let (_, url) = bitcoin::bech32::decode(&address.lnurl).unwrap();
    assert_eq!(
        String::from_utf8(url).unwrap(),
        format!("{DONATIONS}/v1/lnurlp/{code}")
    );
    assert_eq!(address.lnurl, address.lnurl.to_uppercase());
    // Asked again: the same.
    assert_eq!(phone.donation_address().unwrap(), Some(address.clone()));
    assert!(address.reachable);

    // Shown, its provider is kept: a cheaper one found since, or the
    // phone started again, change nothing.
    assert!(phone.keep_donation_address("LNURL1OTHER".into()).is_err());
    phone.keep_donation_address(address.lnurl.clone()).unwrap();
    let free = licash_swaps::DonationTerms {
        fee: Fee { base: 0, ppm: 0 },
        ..terms
    };
    let cheaper = Swaps::start_donating(&hubs, 0x54, TERMS, (Arc::new(Fake::new()), free));
    // Found: each of the three swaps too.
    phone.refresh_providers().unwrap();
    offers(&hubs, &phone, Some(300), 3);
    assert_eq!(phone.donation_address().unwrap(), Some(address.clone()));
    drop(phone);
    let dir = hubs.dir.path().join("phone").display().to_string();
    let phone = Wallet::open(dir, None).unwrap();
    assert_eq!(phone.donation_address().unwrap(), Some(address.clone()));

    // Its provider gone: shown as kept, unheard, rather than another's.
    drop(donating);
    let shown = phone.donation_address().unwrap().unwrap();
    assert_eq!(
        (&shown.lnurl, &shown.provider),
        (&address.lnurl, &address.provider)
    );
    assert!(!shown.reachable && !shown.stocked, "{shown:?}");
    drop((swapping, cheaper));
}

#[test]
fn a_phone_asks_the_providers_kept_ahead_of_a_quote() {
    let hubs = Hubs::start();
    let phone = hubs.phone(1_000);
    // None kept: none asked.
    assert_eq!(phone.warm_providers().unwrap(), 0);
    let swapping = Swaps::start(&hubs, 0x51, TERMS);
    // Once kept, each asked: its announcement may take a moment to come.
    let mut asked = 0;
    for _ in 0..50 {
        phone.refresh_providers().unwrap();
        asked = phone.warm_providers().unwrap();
        if asked > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(asked, 1);
    // Gone, still announced: asked, not answering.
    drop(swapping);
    assert_eq!(phone.warm_providers().unwrap(), 0);
}

fn via_quote(phone: &Wallet, request: &str) -> InvoiceQuote {
    let mut last = None;
    for _ in 0..50 {
        match phone.invoice_quote(request.to_owned()) {
            Ok(quote) => return quote,
            other => last = Some(other),
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("{last:?}");
}

#[test]
fn a_phone_pays_an_invoice_through_a_provider_when_no_hub_pays_it() {
    let hubs = Hubs::start();
    let node = Arc::new(Fake::new());
    node.tip(3, [0; 32]);
    // A fee of 2 and 1%, its routes ending 18 blocks before the lock does.
    let lightning = swaps::Lightning {
        node: node.pubkey(),
        fee: Fee {
            base: 2,
            ppm: 10_000,
        },
        max: 2_000,
        slack: licash_swaps::MIN_SLACK,
    };
    let swaps = Swaps::start_paying(&hubs, 0x52, TERMS, (node.clone(), lightning));
    let phone = hubs.phone(1_000);
    let preimage = [7; 32];
    let request = node.invoice(100_000, lock_hash(&preimage), 6, Outcome::Pay(preimage));

    // No hub of the phone's has a gateway: the provider pays it, for its
    // fee of 3 and the hub's 1 on the lock, from notes at the first hub.
    let quote = via_quote(&phone, &request);
    let provider = quote.provider.clone();
    assert_eq!((quote.hub.clone(), quote.amount), (hubs.url(0), 100));
    assert_eq!(provider.url, swaps.url());
    assert_eq!(provider.name.as_deref(), Some("provider 82"));
    assert_eq!((provider.fee, provider.lock_fee), (3, 1));
    assert_eq!(quote.fee, provider.fee + provider.lock_fee);
    assert!(provider.refund_blocks > 6 + 18, "{provider:?}");
    let offers = phone.invoice_offers(request.clone()).unwrap();
    assert_eq!(offers, vec![quote.clone()]);

    let paying = phone
        .pay_invoice_via(
            request.clone(),
            quote.hub.clone(),
            provider.url.clone(),
            provider.fee,
            provider.lock_fee,
        )
        .unwrap();
    assert_eq!(
        (paying.kind, paying.state, paying.amount),
        (Kind::Lightning, State::Pending, 100)
    );
    // Paid by the provider's node, which claims the lock with the preimage.
    let mut paid = None;
    for _ in 0..50 {
        phone.resume().unwrap();
        let history = phone.history().unwrap();
        paid = history.into_iter().find(|a| a.id == paying.id);
        if paid.as_ref().is_some_and(|a| a.state == State::Done) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let paid = paid.unwrap();
    assert_eq!((paid.state, paid.amount), (State::Done, 100), "{paid:?}");
    assert_eq!(node.sent().len(), 1);
    match phone.details(Kind::Lightning, paid.id.clone()).unwrap() {
        Details::Lightning {
            hub,
            invoice,
            preimage: got,
            failure,
            provider: through,
            expiry,
            refund_blocks,
        } => {
            assert_eq!((hub, invoice), (hubs.url(0), request.clone()));
            assert_eq!(got, Some(hex::encode(preimage)));
            assert_eq!((failure, through), (None, Some(swaps.url())));
            assert!(expiry.is_some());
            // Paid: nothing waits to come back.
            assert_eq!(refund_blocks, None);
        }
        other => panic!("{other:?}"),
    }
    // Paid through the provider: not again through it, nor anyone else.
    let (fee, lock_fee) = (provider.fee, provider.lock_fee);
    let again = phone.pay_invoice_via(request, quote.hub, provider.url, fee, lock_fee);
    assert_eq!(again.unwrap().id, paid.id);
}

#[test]
fn an_invoice_is_paid_through_the_next_provider_if_one_fails_before_locking() {
    let hubs = Hubs::start();
    let lightning = |node: &Fake| swaps::Lightning {
        node: node.pubkey(),
        fee: Fee {
            base: 2,
            ppm: 10_000,
        },
        max: 2_000,
        slack: licash_swaps::MIN_SLACK,
    };
    let (one, two) = (Arc::new(Fake::new()), Arc::new(Fake::new()));
    one.tip(3, [0; 32]);
    two.tip(3, [0; 32]);
    let first = Swaps::start_paying(&hubs, 0x52, TERMS, (one.clone(), lightning(&one)));
    let next = Swaps::start_paying(&hubs, 0x56, TERMS, (two.clone(), lightning(&two)));
    let phone = hubs.phone(1_000);
    let preimage = [7; 32];
    let request = one.invoice(100_000, lock_hash(&preimage), 6, Outcome::Pay(preimage));
    let mut offers = Vec::new();
    for _ in 0..50 {
        offers = phone.invoice_offers(request.clone()).unwrap_or_default();
        if offers.len() == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(offers.len(), 2, "{offers:?}");
    let chosen = offers
        .iter()
        .find(|o| o.provider.url == first.url())
        .unwrap();

    // Quoted from the terms kept; the chosen one unreachable when paid:
    // nothing locked to it, so the other, costing no more, pays it.
    first.down.store(true, Ordering::SeqCst);
    let (provider, fees) = (
        &chosen.provider,
        (chosen.provider.fee, chosen.provider.lock_fee),
    );
    let paying = phone.pay_invoice_via(
        request.clone(),
        chosen.hub.clone(),
        provider.url.clone(),
        fees.0,
        fees.1,
    );
    let paying = paying.unwrap();
    match phone.details(Kind::Lightning, paying.id.clone()).unwrap() {
        Details::Lightning { provider, .. } => assert_eq!(provider, Some(next.url())),
        other => panic!("{other:?}"),
    }
    let locks = phone.history().unwrap();
    assert_eq!(
        locks.iter().filter(|a| a.kind == Kind::Lightning).count(),
        1
    );
}

#[test]
fn a_phone_is_paid_over_lightning_through_a_provider_when_no_hub_takes_it() {
    let hubs = Hubs::start();
    let phone = hubs.phone(1_000);
    // No hub of the phone's has a gateway, nor a provider: none made.
    assert!(!phone.provider_takes_lightning().unwrap());
    assert!(phone.ask_invoice_for(500, None).is_err());
    let node = Arc::new(Fake::new());
    node.tip(3, [0; 32]);
    let terms = licash_swaps::ReceiveTerms::default();
    let swaps = Swaps::start_receiving(&hubs, 0x55, TERMS, (node.clone(), terms));
    let mut takes = false;
    for _ in 0..50 {
        phone.refresh_providers().unwrap();
        takes = phone.provider_takes_lightning().unwrap();
        if takes {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(takes);
    // At the second hub, where it holds 3,000: the payer asked 500, the
    // provider's 2 and 0.5% in it.
    let before = held(&hubs, &phone, 1);
    let invoice = phone.ask_invoice_for(500, Some("Lunch".into())).unwrap();
    assert_eq!(invoice.hub, hubs.url(1));
    assert_eq!(
        (invoice.amount, invoice.asks),
        (495, Some(500)),
        "{invoice:?}"
    );
    assert_eq!(invoice.state, State::Pending);
    let hash: [u8; 32] = hex::decode(&invoice.hash).unwrap().try_into().unwrap();
    let cltv = node.held_cltv(hash).unwrap() as u32;
    node.pay_held(hash, 3 + cltv);
    // Locked to the phone once paid, claimed, and settled.
    let mut followed = None;
    for _ in 0..50 {
        let now = phone.follow_invoice(invoice.hash.clone()).unwrap();
        let done = now.state == State::Done;
        followed = Some(now);
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let followed = followed.unwrap();
    assert_eq!(followed.state, State::Done, "{followed:?}");
    assert_eq!(held(&hubs, &phone, 1), before + 495);
    for _ in 0..50 {
        if node.held(hash).unwrap().0 == licash_lightning::HeldState::Settled {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        node.held(hash),
        Some((licash_lightning::HeldState::Settled, 500_000))
    );
    let history = phone.history().unwrap();
    let line = history.iter().find(|a| a.id == invoice.hash).unwrap();
    assert_eq!(
        (line.kind, line.memo.as_deref()),
        (Kind::Invoice, Some("Lunch"))
    );
    drop(swaps);
}

/// Bitcoin as no light client tells it: the wallets here have no coins.
struct NoBlocks;

impl ChainSource for NoBlocks {
    fn height(&self) -> Result<u32, ChainError> {
        Ok(0)
    }
    fn hash(&self, _: u32) -> Result<Vec<u8>, ChainError> {
        Err(failed())
    }
    fn time(&self, _: u32) -> Result<i64, ChainError> {
        Err(failed())
    }
    fn header(&self, _: u32) -> Result<Vec<u8>, ChainError> {
        Err(failed())
    }
    fn filter(&self, _: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        Err(failed())
    }
    fn block(&self, _: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        Err(failed())
    }
    fn broadcast(&self, _: Vec<u8>) -> Result<(), ChainError> {
        Err(failed())
    }
    fn unconfirmed(&self, _: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        Ok(Vec::new())
    }
}

fn failed() -> ChainError {
    ChainError::Failed {
        reason: "no light client".into(),
    }
}

/// A bridge for its owner alone at hub `i`, paid over Lightning through
/// the provider at `via`, serving Lightning Addresses, its rounds every
/// 100 ms: its URL and pairing code, once it knows its provider's terms.
fn bridged(hubs: &Hubs, i: usize, via: String) -> (String, String) {
    let path = hubs.dir.path().join("bridge.sqlite");
    let hub = hubs.url(i);
    let (url, pairing, bridge) = hubs.runtime.block_on(async move {
        let wallet = licash_wallet::Wallet::create(
            &path,
            &[0x60; 32],
            ChainProfile::Core30DefaultRegtest,
            Http::new(None).unwrap(),
        )
        .unwrap();
        wallet.add_hub(&hub).await.unwrap();
        let pairing = licash_bridge::Bridge::init(&wallet).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = licash_bridge::Config {
            hub,
            via: Some(via),
            relays: vec!["ws://127.0.0.1:1".into()],
            public_url: Some(url.clone()),
            ..licash_bridge::Config::default()
        };
        let bridge = Arc::new(licash_bridge::Bridge::open(wallet, config).unwrap());
        let every = Duration::from_millis(100);
        tokio::spawn(licash_bridge::rounds(bridge.clone(), every));
        let served = bridge.clone();
        tokio::spawn(async move {
            axum::serve(listener, licash_bridge::router(served))
                .await
                .unwrap()
        });
        (url, pairing, bridge)
    });
    for _ in 0..100 {
        if bridge.info().is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (url, pairing)
}

#[test]
fn a_phone_tops_up_a_bridge_connects_apps_and_takes_its_notes_back_to_claim() {
    let hubs = Hubs::start();
    let alice = hubs.phone(100);
    // Notes at the second hub too, the bridge's.
    let code: PaymentCode = alice.payment_code(None).unwrap().qr.parse().unwrap();
    let paid = hubs.pay(1, &code.licash.unwrap().address, 2_000);
    alice
        .receive(serde_json::to_string(&paid).unwrap(), false)
        .unwrap();
    let node = Arc::new(Fake::new());
    node.tip(3, [0; 32]);
    let terms = licash_swaps::ReceiveTerms::default();
    let swaps = Swaps::start_receiving(&hubs, 0x55, TERMS, (node, terms));
    let (url, pairing) = bridged(&hubs, 1, swaps.url());
    // Its owner's alone: not without the pairing code.
    assert!(alice.add_bridge(url.clone(), None).is_err());
    let added = alice.add_bridge(url.clone(), Some(pairing)).unwrap();
    assert_eq!(
        (added.open, added.addresses, added.rules),
        (false, true, None)
    );
    assert_eq!(added.hub, hubs.url(1));
    assert_eq!(alice.bridges().unwrap(), vec![added]);

    // By hand, in notes at its hub: credited whole, the hub's fee on top.
    let before = held(&hubs, &alice, 1);
    let topped = alice.top_up_bridge(url.clone(), 300, None).unwrap();
    assert_eq!((topped.credits, topped.error), (300, None));
    assert_eq!(alice.bridge_account(url.clone()).unwrap().balance, 300);
    assert_eq!(held(&hubs, &alice, 1), before - 301);

    // By the rules: below 1000, up to 1000, 500 a day, 300 of it spent.
    let wrong = licash_mobile::TopUpRules {
        below: 2_000,
        up_to: 1_000,
        daily: 500,
        max_fee: None,
    };
    assert!(alice.set_bridge_rules(url.clone(), Some(wrong)).is_err());
    let rules = licash_mobile::TopUpRules {
        below: 1_000,
        ..wrong
    };
    alice.set_bridge_rules(url.clone(), Some(rules)).unwrap();
    assert_eq!(alice.bridges().unwrap()[0].rules, Some(rules));
    let done = alice.top_up_bridges().unwrap();
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!((done[0].credits, &done[0].error), (200, &None));
    assert_eq!(alice.bridge_account(url.clone()).unwrap().balance, 500);
    assert!(alice.top_up_bridges().unwrap().is_empty());
    alice.set_bridge_rules(url.clone(), None).unwrap();

    // Back in notes, the hub's fee out of the account.
    let before = held(&hubs, &alice, 1);
    assert_eq!(
        alice.withdraw_bridge(url.clone(), 100).unwrap(),
        State::Done
    );
    assert_eq!(held(&hubs, &alice, 1), before + 100);
    assert_eq!(alice.bridge_account(url.clone()).unwrap().balance, 399);

    // An app, paying at most 100 a week; revoked.
    let terms = licash_mobile::AppTerms {
        name: "  Zapper ".into(),
        pay: true,
        receive: false,
        max_payment: None,
        budget: Some(100),
        period: licash_mobile::BudgetPeriod::Weekly,
        expires_at: None,
    };
    let refused = licash_mobile::AppTerms {
        pay: false,
        ..terms.clone()
    };
    assert!(invalid(alice.connect_app(url.clone(), refused)).contains("paid"));
    let connected = alice.connect_app(url.clone(), terms).unwrap();
    assert!(
        connected.uri.starts_with("nostr+walletconnect://"),
        "{}",
        connected.uri
    );
    let app = &connected.app;
    assert_eq!(
        (app.name.as_str(), app.pay, app.receive),
        ("Zapper", true, false)
    );
    assert_eq!(
        (app.budget, app.period),
        (Some(100), Some(licash_mobile::BudgetPeriod::Weekly))
    );
    assert!(
        alice
            .revoke_app(url.clone(), app.key.clone())
            .unwrap()
            .revoked
    );

    // Its Lightning Address, named and cleared.
    let host = url.strip_prefix("http://").unwrap();
    let named = alice
        .bridge_address(url.clone(), Some("Alice".into()))
        .unwrap();
    assert_eq!(named.lightning_address, Some(format!("alice@{host}")));
    let cleared = alice.bridge_address(url.clone(), None).unwrap();
    assert_eq!(cleared.lightning_address, None);

    // Frozen for good, its notes the phone's to claim; nothing paid out
    // from then on, until discarded and unfrozen.
    let exported = alice.export_bridge(url.clone()).unwrap();
    assert!(exported.imported.amount >= 399, "{exported:?}");
    let imported = alice.imported_notes().unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].amount, exported.imported.amount);
    assert_eq!((imported[0].claimed, imported[0].dropped), (0, 0));
    let again = alice.import_notes(exported.export.clone()).unwrap();
    assert_eq!(again.known, exported.imported.added);
    assert!(invalid(alice.import_notes("zz".into())).contains("export"));
    assert!(alice.top_up_bridge(url.clone(), 10, None).is_err());
    let source = exported.imported.source.clone();
    assert_eq!(
        alice.discard_imported(source).unwrap(),
        exported.imported.added
    );
    assert!(alice.imported_notes().unwrap().is_empty());
}

fn invalid(result: Result<impl std::fmt::Debug, licash_mobile::LicashError>) -> String {
    match result {
        Err(licash_mobile::LicashError::Invalid { reason }) => reason,
        other => panic!("not refused as invalid: {other:?}"),
    }
}
