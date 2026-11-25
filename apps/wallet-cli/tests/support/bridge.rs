//! A Licash bridge on a local port, over its own wallet at a hub, taking
//! its payments and invoices on as the service does. Its NWC service is
//! not run: the CLI only manages its account.

use std::{net::SocketAddr, sync::Arc, thread::JoinHandle, time::Duration};

use licash::spend::ChainProfile;
use licash_bridge::{Bridge, Config};
use licash_transport::Http;
use licash_wallet::Wallet;

use super::Server;

pub struct Bridged {
    pub bridge: Arc<Bridge<Http>>,
    /// The code its owner registers with.
    pub pairing: String,
    addr: SocketAddr,
    stop: Option<(tokio::sync::oneshot::Sender<()>, JoinHandle<()>)>,
    _dir: tempfile::TempDir,
}

impl Bridged {
    /// A bridge for its owner alone, paying and paid through `hub`, all in
    /// the runtime of its own thread, as its wallet's client is.
    pub fn start(hub: &Server) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let url = hub.url();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (ready, started) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let wallet = Wallet::create(
                    &path,
                    &[0x60; 32],
                    ChainProfile::Core30DefaultRegtest,
                    Http::new(None).unwrap(),
                )
                .unwrap();
                wallet.add_hub(&url).await.unwrap();
                let pairing = Bridge::init(&wallet).unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let config = Config {
                    hub: url,
                    relays: vec!["ws://127.0.0.1:1".into()],
                    public_url: Some(format!("http://{}", listener.local_addr().unwrap())),
                    ..Config::default()
                };
                let bridge = Arc::new(Bridge::open(wallet, config).unwrap());
                ready
                    .send((listener.local_addr().unwrap(), bridge.clone(), pairing))
                    .unwrap();
                let rounds = tokio::spawn(licash_bridge::rounds(
                    bridge.clone(),
                    Duration::from_millis(100),
                ));
                axum::serve(listener, licash_bridge::router(bridge))
                    .with_graceful_shutdown(async {
                        stopped.await.ok();
                    })
                    .await
                    .unwrap();
                rounds.abort();
            });
        });
        let (addr, bridge, pairing) = started.recv().unwrap();
        Self {
            bridge,
            pairing,
            addr,
            stop: Some((stop, thread)),
            _dir: dir,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for Bridged {
    fn drop(&mut self) {
        if let Some((stop, thread)) = self.stop.take() {
            stop.send(()).ok();
            thread.join().ok();
        }
    }
}
