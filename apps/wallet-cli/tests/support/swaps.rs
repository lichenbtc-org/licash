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
        Self::started(hubs, stock, 0x50, CONFIG, Some(node))
    }

    /// [`Swaps::start`], its wallet of seed `seed`, on terms `config`.
    pub fn with(hubs: &[&Server], stock: u64, seed: u8, config: Config) -> Self {
        Self::started(hubs, stock, seed, config, None)
    }

    fn started(
        hubs: &[&Server],
        stock: u64,
        seed: u8,
        config: Config,
        receiving: Option<Arc<Fake>>,
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
                if let Some(following) = following {
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
