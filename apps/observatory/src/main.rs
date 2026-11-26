//! `licash-observatory`: watch the Licash hubs and swap providers of a
//! network, and show what was seen on a web page.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use licash::spend::ChainProfile;
use licash_chain_client::Source;
use licash_nostr::Route;
use licash_observatory::{
    mover::{Mover, Moving},
    observer::{self, Watching},
    probe::Dialer,
    store::Store,
    web::{self, App},
};
use licash_tor::Tor;
use licash_transport::Http;
use licash_wallet::Wallet;
use rand_core::{OsRng, RngCore};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "licash-observatory",
    version,
    about = "Watch the Licash hubs and swap providers of the networks, and show them on a web page"
)]
struct Cli {
    /// The observatory's directory: Tor's state, and for each network a
    /// directory of its records `observatory.sqlite` and its wallet
    /// `wallet.sqlite`.
    #[arg(
        long,
        global = true,
        env = "LICASH_OBSERVATORY_DATA",
        default_value = "data"
    )]
    data: PathBuf,
    /// Log lines on stderr as text or JSON, filtered by RUST_LOG.
    #[arg(long, global = true, env = "LICASH_OBSERVATORY_LOG", value_enum, default_value_t = Log::Text)]
    log: Log,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Log {
    Text,
    Json,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Network {
    Bitcoin,
    Signet,
    Mutinynet,
    Regtest,
}

impl Network {
    fn profile(self) -> ChainProfile {
        match self {
            Network::Bitcoin => ChainProfile::Core30Mainnet,
            Network::Signet => ChainProfile::Core30Signet,
            Network::Mutinynet => ChainProfile::Mutinynet,
            Network::Regtest => ChainProfile::Core30DefaultRegtest,
        }
    }

    /// Seconds between two blocks.
    fn block_secs(self) -> u64 {
        match self {
            Network::Mutinynet => 30,
            _ => 600,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Network::Bitcoin => "bitcoin",
            Network::Signet => "signet",
            Network::Mutinynet => "mutinynet",
            Network::Regtest => "regtest",
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Watch, move within the budget, and serve the page.
    Run(Run),
}

#[derive(Args)]
struct Run {
    /// The networks whose services are watched, each under its name on the
    /// page, the first at `/`. Repeat it, or separate them with commas.
    #[arg(
        long = "network",
        env = "LICASH_OBSERVATORY_NETWORK",
        value_enum,
        value_delimiter = ',',
        required = true
    )]
    networks: Vec<Network>,
    /// The network whose balance is moved, as `--budget` says: of those
    /// watched, the only one with moves measured. By default the network,
    /// if there is one.
    #[arg(long, env = "LICASH_OBSERVATORY_FUNDED", value_enum)]
    funded: Option<Network>,
    /// Where the page is served.
    #[arg(
        long,
        env = "LICASH_OBSERVATORY_LISTEN",
        default_value = "127.0.0.1:8350"
    )]
    listen: SocketAddr,
    /// Nostr relays to find services on; the usual ones if none. Repeat
    /// it, or separate them with commas. With one network only.
    #[arg(
        long = "relay",
        env = "LICASH_OBSERVATORY_RELAYS",
        value_delimiter = ','
    )]
    relays: Vec<String>,
    /// A hub to watch besides those announced. Repeat it, or separate
    /// them with commas. With one network only.
    #[arg(long = "hub", env = "LICASH_OBSERVATORY_HUBS", value_delimiter = ',')]
    hubs: Vec<String>,
    /// A swap provider to watch besides those announced. With one network
    /// only.
    #[arg(
        long = "provider",
        env = "LICASH_OBSERVATORY_PROVIDERS",
        value_delimiter = ','
    )]
    providers: Vec<String>,
    /// Reach services and relays directly rather than over Tor: on
    /// regtest, or behind a VPN of one's own. Onion services are
    /// skipped, and services see the observatory's address.
    #[arg(long, env = "LICASH_OBSERVATORY_DIRECT")]
    direct: bool,
    /// Seconds between two probes of a service.
    #[arg(long, env = "LICASH_OBSERVATORY_PROBE_EVERY", default_value_t = 300,
          value_parser = clap::value_parser!(u64).range(10..))]
    probe_every: u64,
    /// Sat a month the observatory may spend on moving its balance
    /// between services, fees and losses included; 0 moves nothing,
    /// and makes no wallet. Cheap moves are made more often than dear
    /// ones, all as often as this allows.
    #[arg(long, env = "LICASH_OBSERVATORY_BUDGET", default_value_t = 0)]
    budget: u64,
    /// Sat a move moves.
    #[arg(long, env = "LICASH_OBSERVATORY_AMOUNT", default_value_t = 2_000,
          value_parser = clap::value_parser!(u64).range(1..))]
    amount: u64,
    /// The chain to follow payouts on and broadcast their claims to:
    /// Bitcoin Core's JSON-RPC, `http[s]://[user:pass@]host:port`, or
    /// Esplora, `esplora+https://host/api`. With it, a move on Bitcoin, out
    /// of a hub and into one, comes at most once a day; it is read directly,
    /// not over Tor.
    #[arg(long, env = "LICASH_OBSERVATORY_CHAIN")]
    chain: Option<Source>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    logging(cli.log);
    match command(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn logging(format: Log) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(match format {
            Log::Text => "info,licash_wallet=warn,nostr_sdk=off,arti_client=warn,tor_=warn",
            Log::Json => "info",
        })
    });
    let logs = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr);
    match format {
        Log::Text => logs.without_time().with_target(false).init(),
        Log::Json => logs.json().init(),
    }
}

fn command(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Run(run) => tokio::runtime::Runtime::new()?.block_on(serve(cli.data, run)),
    }
}

async fn serve(data: PathBuf, run: Run) -> anyhow::Result<()> {
    let mut networks = Vec::new();
    for network in &run.networks {
        if !networks.contains(network) {
            networks.push(*network);
        }
    }
    let funded = match (run.budget, run.funded, networks.as_slice()) {
        (0, ..) => None,
        (_, Some(network), _) => Some(network),
        (_, None, [only]) => Some(*only),
        (..) => anyhow::bail!("--budget with several networks needs --funded to say which"),
    };
    if let Some(funded) = funded {
        anyhow::ensure!(
            networks.contains(&funded),
            "--funded {} is not among the networks watched",
            funded.name()
        );
    }
    anyhow::ensure!(
        networks.len() == 1
            || (run.hubs.is_empty() && run.providers.is_empty() && run.relays.is_empty()),
        "--hub, --provider and --relay name a network's services: with one network only"
    );
    std::fs::create_dir_all(&data).with_context(|| format!("{}", data.display()))?;
    let tor = match run.direct {
        true => None,
        false => {
            let tor = Tor::new(&data.join("tor"))?;
            let bootstrapping = tor.clone();
            tokio::spawn(async move {
                match bootstrapping.bootstrap().await {
                    Ok(()) => tracing::info!("connected to Tor"),
                    Err(e) => tracing::warn!("connecting to Tor: {e}"),
                }
            });
            Some(tor)
        }
    };
    let fresh = run.probe_every * 3;
    let mut apps = Vec::new();
    let mut tasks = Vec::new();
    // The funded network first: the page `/` leads to.
    networks.sort_by_key(|n| Some(*n) != funded);
    for network in networks {
        let dir = data.join(network.name());
        std::fs::create_dir_all(&dir).with_context(|| format!("{}", dir.display()))?;
        let store = Arc::new(Store::open(&dir.join("observatory.sqlite"))?);
        let (route, dialer) = match &tor {
            // Regtest's services run on the observatory's own network.
            None => (
                Route::Direct,
                Dialer::direct_reaching(network == Network::Regtest),
            ),
            Some(tor) => (Route::Tor(tor.clone()), Dialer::Tor(tor.clone())),
        };
        let relays = if run.relays.is_empty() {
            licash_nostr::default_relays(network.name(), !run.direct)
        } else {
            run.relays.clone()
        };
        let watching = Watching {
            network: network.name().to_owned(),
            relays,
            route,
            dialer,
            hubs: run.hubs.clone(),
            providers: run.providers.clone(),
            probe_every: Duration::from_secs(run.probe_every),
            discover_every: Duration::from_secs(600),
            timeout: Duration::from_secs(if run.direct { 20 } else { 90 }),
        };
        let budget = Arc::new(Mutex::new(None));
        apps.push(Arc::new(App::new(
            store.clone(),
            network.name().to_owned(),
            !run.direct,
            Duration::from_secs(fresh),
            budget.clone(),
        )));
        tasks.push(tokio::spawn(observer::run(store.clone(), watching)));
        if funded == Some(network) {
            let transport = match tor.clone() {
                Some(tor) => Http::tor(tor),
                None => Http::new(None)?,
            };
            let wallet = wallet(&dir.join("wallet.sqlite"), network, transport)?;
            let moving = Moving {
                store,
                monthly: run.budget,
                amount: run.amount,
                fresh: (fresh * 1000) as i64,
                shown: budget,
                chain: run.chain.clone(),
                block_secs: network.block_secs(),
            };
            tasks.push(tokio::spawn(Mover::new(wallet, moving)?.run()));
        }
    }
    let listener = tokio::net::TcpListener::bind(run.listen)
        .await
        .with_context(|| format!("listening at {}", run.listen))?;
    tracing::info!("serving the observatory at http://{}", run.listen);
    licash_serve::listen(listener, web::router(apps), shutdown()).await;
    for task in tasks {
        task.abort();
    }
    tracing::info!("stopped");
    Ok(())
}

/// The observatory's wallet, made with a seed of its own on its first run.
fn wallet(path: &Path, network: Network, transport: Http) -> anyhow::Result<Wallet<Http>> {
    if path.exists() {
        let wallet = Wallet::open(path, transport)?;
        anyhow::ensure!(
            wallet.network() == network.profile(),
            "{} is a wallet for {}, not {}",
            path.display(),
            wallet.network().name(),
            network.name()
        );
        return Ok(wallet);
    }
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    let wallet = Wallet::create(path, &seed, network.profile(), transport)?;
    tracing::info!(
        wallet = %path.display(),
        "a wallet made; fund it at a hub with `licash-wallet` (LICASH_WALLET={})",
        path.display()
    );
    Ok(wallet)
}

async fn shutdown() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! {
            _ = interrupt => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = interrupt.await;
    tracing::info!("stopping");
}
