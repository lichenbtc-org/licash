//! `licash-bridge`: a Nostr Wallet Connect service over a Licash wallet of
//! its own, paying and paid through its hub, for its owner alone or, with
//! `--open`, for anyone registering an account.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use clap::{Parser, Subcommand};
use licash::spend::ChainProfile;
use licash_bridge::{Bridge, Config};
use licash_transport::Http;
use licash_wallet::Wallet;
use rand_core::{OsRng, RngCore};

#[derive(Parser)]
#[command(name = "licash-bridge", version, about)]
struct Cli {
    /// Where the bridge keeps its wallet, wallet.sqlite: back it up.
    #[arg(long, env = "LICASH_BRIDGE_DATA", default_value = "licash-bridge")]
    data: PathBuf,
    /// Log as JSON lines.
    #[arg(long, env = "LICASH_BRIDGE_LOG_JSON")]
    log_json: bool,
    /// Reach hubs through this SOCKS5 proxy, such as Tor's.
    #[arg(long, env = "LICASH_BRIDGE_PROXY")]
    proxy: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make the bridge: a wallet of its own at its hub, and the pairing
    /// code its owner registers with, printed.
    Init {
        /// bitcoin, signet, mutinynet or regtest.
        #[arg(long, default_value = "bitcoin")]
        network: ChainProfile,
        /// The hub to pay and be paid through.
        #[arg(long)]
        hub: String,
    },
    /// Serve the management API and NWC.
    Run {
        #[arg(long, env = "LICASH_BRIDGE_LISTEN", default_value = "127.0.0.1:8090")]
        listen: SocketAddr,
        /// The hub to pay through: the wallet's only one if not given.
        #[arg(long, env = "LICASH_BRIDGE_HUB")]
        hub: Option<String>,
        /// A Nostr relay to serve NWC on: once each.
        #[arg(
            long = "relay",
            env = "LICASH_BRIDGE_RELAYS",
            value_delimiter = ',',
            required = true
        )]
        relays: Vec<String>,
        /// Let anyone register an account, not only the owner.
        #[arg(long)]
        open: bool,
        /// What the bridge calls itself.
        #[arg(long)]
        name: Option<String>,
        /// The most an account may hold, in sat.
        #[arg(long)]
        max_balance: Option<u64>,
        /// The most one payment may be, in sat.
        #[arg(long)]
        max_payment: Option<u64>,
        /// Where the bridge is reached publicly, https://domain: it serves
        /// its accounts' Lightning Addresses, name@domain, and zaps there.
        #[arg(long, env = "LICASH_BRIDGE_PUBLIC_URL")]
        public_url: Option<String>,
        /// Seconds between rounds following payments and invoices.
        #[arg(long, default_value_t = 5)]
        interval: u64,
    },
    /// What the bridge owes its accounts and what its wallet holds.
    Status,
    /// The pairing code the owner registers with, if not used yet.
    Pairing {
        /// A new one, handing the owner's account to whoever registers
        /// with it next, such as the owner's new wallet.
        #[arg(long)]
        renew: bool,
    },
    /// Freeze the bridge for good and seal its notes to KEY, a wallet's
    /// key here (`licash-wallet bridge show` names it), for that wallet to
    /// claim in a recovery should the hub stop cooperating: printed, or
    /// written to --out. Every account's notes: an open bridge's operator
    /// exports them to a wallet of its own. Stop `run` first.
    Export {
        to: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Pay out again after an export, once the wallet the notes went to
    /// discarded them (`licash-wallet bridge discard`): a note claimed by
    /// both is lost to both.
    Unfreeze {
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let logs = tracing_subscriber::fmt().with_env_filter(filter);
    if cli.log_json {
        logs.json().init();
    } else {
        logs.with_writer(std::io::stderr).init();
    }
    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn transport(proxy: Option<&str>) -> anyhow::Result<Http> {
    Http::new(proxy).context("the HTTP client")
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let path = cli.data.join("wallet.sqlite");
    let runtime = tokio::runtime::Runtime::new()?;
    match cli.command {
        Command::Init { network, hub } => {
            let mut dir = std::fs::DirBuilder::new();
            dir.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
            dir.create(&cli.data)
                .with_context(|| format!("create {}", cli.data.display()))?;
            anyhow::ensure!(
                !path.exists(),
                "{} exists already: never replaced",
                path.display()
            );
            let mut seed = [0; 32];
            OsRng.fill_bytes(&mut seed);
            let wallet = Wallet::create(&path, &seed, network, transport(cli.proxy.as_deref())?)
                .context("create the wallet")?;
            runtime
                .block_on(wallet.add_hub(&hub))
                .with_context(|| format!("add hub {hub}"))?;
            let pairing = Bridge::init(&wallet)?;
            eprintln!(
                "Bridge made. Back up wallet.sqlite in {}. Pair its owner's wallet with:",
                cli.data.display()
            );
            println!("{pairing}");
            Ok(())
        }
        Command::Run {
            listen,
            hub,
            relays,
            open,
            name,
            max_balance,
            max_payment,
            public_url,
            interval,
        } => {
            let wallet =
                Wallet::open(&path, transport(cli.proxy.as_deref())?).context("open the wallet")?;
            let hub = match hub {
                Some(hub) => hub,
                None => only_hub(&wallet)?,
            };
            let config = Config {
                hub,
                open,
                name,
                relays,
                max_balance: max_balance.map(|sat| sat.saturating_mul(1000)),
                max_payment: max_payment.map(|sat| sat.saturating_mul(1000)),
                public_url,
            };
            let bridge = Arc::new(Bridge::open(wallet, config)?);
            runtime.block_on(serve(bridge, listen, Duration::from_secs(interval.max(1))))
        }
        Command::Status => {
            let wallet = Wallet::open(&path, transport(cli.proxy.as_deref())?)?;
            let config = Config {
                hub: only_hub(&wallet).unwrap_or_default(),
                ..Config::default()
            };
            let bridge = Bridge::open(wallet, config)?;
            let status = bridge.status()?;
            println!("Accounts  {}", status.accounts);
            println!("Owed      {} sat", status.owed / 1000);
            println!("Held      {} sat", status.held);
            if status.frozen {
                println!("Frozen    its notes were exported: it pays nothing out");
            }
            if status.held.saturating_mul(1000) < status.owed {
                println!(
                    "Short     {} sat",
                    (status.owed / 1000).saturating_sub(status.held)
                );
            }
            Ok(())
        }
        Command::Export { to, out } => {
            let mut key = [0u8; 32];
            hex::decode_to_slice(to.trim(), &mut key).context("KEY: a key in hex, of 32 bytes")?;
            let wallet = Wallet::open(&path, transport(cli.proxy.as_deref())?)?;
            let bridge = Bridge::open(wallet, Config::default())?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let exported = runtime.block_on(bridge.export(&key))?;
            let text = hex::encode(&exported.export.0);
            match out {
                Some(out) => std::fs::write(&out, format!("{text}\n"))
                    .with_context(|| format!("writing {}", out.display()))?,
                None => println!("{text}"),
            }
            eprintln!(
                "Frozen: {} notes worth {} sat exported. It pays nothing out until unfrozen.",
                exported.notes, exported.amount
            );
            Ok(())
        }
        Command::Unfreeze { yes } => {
            anyhow::ensure!(
                yes,
                "only once the wallet its notes went to discarded them: --yes says it did"
            );
            let wallet = Wallet::open(&path, transport(cli.proxy.as_deref())?)?;
            let bridge = Bridge::open(wallet, Config::default())?;
            match bridge.unfreeze()? {
                true => println!("Unfrozen: it pays out again."),
                false => println!("Not frozen."),
            }
            Ok(())
        }
        Command::Pairing { renew } => {
            let wallet = Wallet::open(&path, transport(cli.proxy.as_deref())?)?;
            let bridge = Bridge::open(wallet, Config::default())?;
            match bridge.pairing(renew)? {
                Some(code) => println!("{code}"),
                None => eprintln!("Paired already: `--renew` hands the account to a new wallet."),
            }
            Ok(())
        }
    }
}

fn only_hub(wallet: &Wallet<Http>) -> anyhow::Result<String> {
    let hubs = wallet.hubs()?;
    match hubs.as_slice() {
        [(url, _)] => Ok(url.clone()),
        [] => anyhow::bail!("the wallet knows no hub: give --hub"),
        _ => anyhow::bail!("the wallet knows several hubs: give --hub"),
    }
}

async fn serve(
    bridge: Arc<Bridge<Http>>,
    listen: SocketAddr,
    every: Duration,
) -> anyhow::Result<()> {
    let hub = bridge.config().hub.clone();
    bridge
        .wallet()
        .add_hub(&hub)
        .await
        .with_context(|| format!("reach hub {hub}"))?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listen on {listen}"))?;
    tracing::info!(%listen, %hub, open = bridge.config().open, "bridge serving");
    let router =
        licash_bridge::router(bridge.clone()).layer(tower_http::trace::TraceLayer::new_for_http());
    let rounds = tokio::spawn(licash_bridge::rounds(bridge.clone(), every));
    // Relays come and go: served again a while after they fail.
    let nwc = tokio::spawn(async move {
        loop {
            if let Err(e) = licash_bridge::nwc::run(bridge.clone()).await {
                tracing::warn!("NWC stopped, starting again in 10 s: {e:#}");
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
    let shutdown = async {
        let terminate = async {
            #[cfg(unix)]
            if let Ok(mut s) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                s.recv().await;
                return;
            }
            std::future::pending::<()>().await
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate => {}
        }
    };
    let served = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await;
    nwc.abort();
    rounds.abort();
    served.context("serve")
}
