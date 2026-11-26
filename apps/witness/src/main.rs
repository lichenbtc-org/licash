//! `licash-witness`: keep what a Licash hub may sign once, and serve it
//! back to it over pinned TLS.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use licash_witness::{server, store::Store};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Its directory: its database, `witness.sqlite`, and its TLS
    /// identity.
    #[arg(long, env = "LICASH_WITNESS_DATA", default_value = "./witness")]
    data: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make a witness for the hub of `--hub-key` (`licash-hub witness-key`):
    /// of a new set, or of the set `--set-id` of its other witnesses. Its
    /// set and pin are printed, for the hub's `--contracts-witnesses` and
    /// `--contracts-witness`.
    Init {
        #[arg(long)]
        hub_key: String,
        #[arg(long)]
        set_id: Option<String>,
    },
    /// Serve it until SIGINT or SIGTERM.
    Run {
        #[arg(long, env = "LICASH_WITNESS_LISTEN", default_value = "0.0.0.0:8339")]
        listen: SocketAddr,
    },
    /// Print its set, hub, sequence and pin.
    Show,
    /// A consistent copy of its database at `--to`, while it serves: what
    /// a witness lost is made again from ([`Command::Clone`]).
    Backup {
        #[arg(long)]
        to: PathBuf,
    },
    /// Make this witness (its directory new) a copy of a surviving one, of
    /// its database or a backup of it at `--from`, under a TLS identity of
    /// its own: its pin, which the hub names in place of the lost one's.
    Clone {
        #[arg(long)]
        from: PathBuf,
    },
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(hex::decode(s).unwrap_or_default())
        .map_err(|_| anyhow::anyhow!("{what}: 32 bytes in hex"))
}

fn new_dir(dir: &std::path::Path) -> Result<()> {
    if dir.exists() {
        ensure!(
            std::fs::read_dir(dir)?.next().is_none(),
            "{} is not empty",
            dir.display()
        );
    }
    std::fs::create_dir_all(dir)?;
    Ok(())
}

fn show(dir: &std::path::Path, store: &Store) -> Result<()> {
    let status = store.status()?;
    let (cert, _) = server::identity(dir)?;
    println!("set_id   {}", hex::encode(status.set_id));
    println!("hub_key  {}", hex::encode(status.hub_key));
    println!("sequence {}", status.sequence);
    println!("sealed   {}", status.seal.is_some());
    match &status.leader {
        Some(leader) => println!(
            "epoch    {} (instance {})",
            leader.epoch,
            hex::encode(&leader.entry.body)
        ),
        None => println!("epoch    0 (never taken over)"),
    }
    println!("pin      {}", hex::encode(server::pin_of(&cert)));
    Ok(())
}

async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("a SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let db = cli.data.join("witness.sqlite");
    match cli.command {
        Command::Init { hub_key, set_id } => {
            let hub_key = hex32(&hub_key, "--hub-key")?;
            let set_id = match set_id {
                Some(s) => hex32(&s, "--set-id")?,
                None => {
                    let mut id = [0; 32];
                    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
                    id
                }
            };
            new_dir(&cli.data)?;
            Store::create(&db, &set_id, &hub_key)?;
            server::make_identity(&cli.data)?;
            show(&cli.data, &Store::open(&db)?)
        }
        Command::Clone { from } => {
            new_dir(&cli.data)?;
            Store::copy(&from, &db)?;
            server::make_identity(&cli.data)?;
            show(&cli.data, &Store::open(&db)?)
        }
        Command::Show => show(&cli.data, &Store::open(&db)?),
        Command::Backup { to } => Store::open(&db)?.backup(&to),
        Command::Run { listen } => {
            let store = Arc::new(Store::open(&db)?);
            let status = store.status()?;
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("listen on {listen}"))?;
            tracing::info!(
                set_id = %hex::encode(status.set_id),
                sequence = status.sequence,
                "witnessing at {}",
                listener.local_addr()?
            );
            server::serve(listener, &cli.data, store, shutdown()).await
        }
    }
}
