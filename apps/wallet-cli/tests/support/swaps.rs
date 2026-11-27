//! A swap provider service on a local port, over its own wallet, taking
//! its swaps on as the service does.

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
use licash::spend::ChainProfile;
use licash_api::{Code, Problem};
use licash_lightning::fake::Fake;
use licash_swaps::{Config, Provider, Record};
use licash_transport::Http;
use licash_wallet::Wallet;

use super::Server;

/// Deposits on Bitcoin of 100 to 5,000 (to 150 as it swaps), its fee of 1 and 200 for its
/// claim's miners on top, at 2 confirmations, confirmed within 10 blocks.
pub const DEPOSITS: licash_swaps::DepositTerms = licash_swaps::DepositTerms {
    fee: licash_api::Fee { base: 1, ppm: 0 },
    miner: 200,
    min: 100,
    max: 5_000,
    depth: 2,
    window: 10,
    timeout: 1_008,
    sweep: 6,
    max_open: 10,
};

/// Its fee of 1 and 1%, swapping 5 to 150, its locks expiring 6 blocks
/// before its clients'.
pub const CONFIG: Config = Config {
    fee: licash_api::Fee {
        base: 1,
        ppm: 10_000,
    },
    min: 5,
    max: 150,
    margin: 6,
    confirm: 4,
};

pub struct Swaps {
    pub provider: Arc<Provider<Http>>,
    /// Swap requests are answered as by a provider that cannot serve.
    pub refuse: Arc<AtomicBool>,
    addr: SocketAddr,
    stop: Option<(tokio::sync::oneshot::Sender<()>, JoinHandle<()>)>,
    _dir: tempfile::TempDir,
}

impl Swaps {
    /// A provider swapping between `hubs`, holding `stock` at the last,
    /// all in the runtime of its own thread, as its wallet's client is.
    pub fn start(hubs: &[&Server], stock: u64) -> Self {
        Self::with(hubs, stock, 0x50, CONFIG)
    }

    /// [`Swaps::start`], taking payments over Lightning for wallets through
    /// `node` too, on the default terms, as the service does with
    /// `--receive`.
    pub fn receiving(hubs: &[&Server], stock: u64, node: Arc<Fake>) -> Self {
        Self::started(hubs, stock, 0x50, CONFIG, (Some(node), None))
    }

    /// [`Swaps::start`], taking deposits on Bitcoin for wallets on
    /// [`DEPOSITS`] too, on the chain of the Esplora at `chain`, as the
    /// service does with `--deposits --chain`.
    pub fn depositing(hubs: &[&Server], stock: u64, chain: &str) -> Self {
        Self::started(hubs, stock, 0x50, CONFIG, (None, Some(chain.to_owned())))
    }

    /// [`Swaps::start`], its wallet of seed `seed`, on terms `config`.
    pub fn with(hubs: &[&Server], stock: u64, seed: u8, config: Config) -> Self {
        Self::started(hubs, stock, seed, config, (None, None))
    }

    fn started(
        hubs: &[&Server],
        stock: u64,
        seed: u8,
        config: Config,
        (receiving, depositing): (Option<Arc<Fake>>, Option<String>),
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let wallet = Wallet::create(
            &path,
            &[seed; 32],
            ChainProfile::Core30DefaultRegtest,
            Http::new(None).unwrap(),
        )
        .unwrap();
        let stocked = hubs.last().unwrap().pay(&wallet.address(), stock);
        let urls: Vec<String> = hubs.iter().map(|hub| hub.url()).collect();
        let refuse = Arc::new(AtomicBool::new(false));
        let refusing = refuse.clone();
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
                let provider = Provider::create(wallet, config).unwrap();
                let receives = receiving.is_some();
                let provider = match receiving {
                    Some(node) => provider
                        .take_receives(node, licash_swaps::ReceiveTerms::default())
                        .unwrap(),
                    None => provider,
                };
                let chain = depositing
                    .map(|url| Arc::new(licash_swaps_service::ChainView(url.parse().unwrap())));
                let provider = match &chain {
                    Some(_) => provider.take_deposits(DEPOSITS).unwrap(),
                    None => provider,
                };
                let provider = Arc::new(provider);
                let nostr = licash_nostr::public_key(&provider.nostr_secret().unwrap()).unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready
                    .send((listener.local_addr().unwrap(), provider.clone()))
                    .unwrap();
                let every = Duration::from_millis(100);
                let stepping = tokio::spawn(licash_swaps_service::step(provider.clone(), every));
                let following = receives.then(|| {
                    tokio::spawn(licash_swaps_service::take_receives(provider.clone(), every))
                });
                let depositing = chain.clone().map(|chain| {
                    let following =
                        licash_swaps_service::take_deposits(provider.clone(), chain, every);
                    tokio::spawn(following)
                });
                let refusing = move |request: Request, next: Next| {
                    let refuse =
                        refusing.load(Ordering::Relaxed) && request.method() == Method::POST;
                    async move {
                        if refuse {
                            let problem = Problem::new(Code::Unavailable, "refused as asked");
                            return (StatusCode::SERVICE_UNAVAILABLE, Json(problem))
                                .into_response();
                        }
                        next.run(request).await
                    }
                };
                let router = licash_swaps_service::router(
                    provider,
                    licash_swaps_service::Serving {
                        nostr: Some(nostr),
                        chain,
                        ..Default::default()
                    },
                )
                .layer(middleware::from_fn(refusing));
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        stopped.await.ok();
                    })
                    .await
                    .unwrap();
                stepping.abort();
                for following in [following, depositing].into_iter().flatten() {
                    following.abort();
                }
            });
        });
        let (addr, provider) = started.recv().unwrap();
        Self {
            provider,
            refuse,
            addr,
            stop: Some((stop, thread)),
            _dir: dir,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Its latest swap once `done` says it is, within 10 seconds.
    pub fn until(&self, done: impl Fn(&Record) -> bool) -> Record {
        for _ in 0..100 {
            let latest = self.provider.records(1).unwrap().pop();
            if let Some(record) = latest.filter(|r| done(r)) {
                return record;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("{:?}", self.provider.records(1).unwrap());
    }

    /// What it holds available at `hub`.
    pub fn held(&self, hub: &Server) -> u64 {
        let balance = self.provider.wallet().balance().unwrap();
        balance
            .iter()
            .find(|b| b.hub == hub.url())
            .map_or(0, |b| b.available)
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
