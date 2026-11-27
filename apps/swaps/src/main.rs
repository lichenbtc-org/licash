//! `licash-swaps`: create, run and watch a Licash swap provider.

use std::{
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use licash::spend::ChainProfile;
use licash_api::{swaps, Fee};
use licash_contracts::holder::Node;
use licash_lightning::{lnd::Lnd, Node as LightningNode};
use licash_nostr::Route;
use licash_notify::{Message, Priority, Target};
use licash_swaps::{Config, DepositTerms, DonationTerms, Provider, ReceiveTerms};
use licash_swaps_service::{
    dashboard,
    keeper::{self, Keeper},
    notify::{self, Notifier},
    ChainView,
};
use licash_tor::{Onion, Tor};
use licash_transport::Http;
use licash_wallet::{LicashCode, Wallet};
use rand_core::{OsRng, RngCore};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "licash-swaps",
    version,
    about = "Create, run and watch a Licash swap provider"
)]
struct Cli {
    /// The provider's directory: its wallet `wallet.sqlite`, which holds its
    /// swaps too.
    #[arg(long, global = true, env = "LICASH_SWAPS_DATA", default_value = "data")]
    data: PathBuf,
    /// Log lines on stderr as text or JSON, filtered by RUST_LOG.
    #[arg(long, global = true, env = "LICASH_SWAPS_LOG", value_enum, default_value_t = Log::Text)]
    log: Log,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Log {
    Text,
    Json,
}

#[derive(Args)]
struct Notify {
    /// Notify of the provider's events at this Apprise-style URL: gotify://,
    /// tgram://, ntfy://, json:// or apprise://. Repeat it, or separate URLs
    /// with commas, for more targets.
    #[arg(
        long = "notify",
        value_name = "URL",
        env = "LICASH_SWAPS_NOTIFY",
        value_delimiter = ',',
        hide_env_values = true
    )]
    urls: Vec<String>,
    /// The name heading notification titles.
    #[arg(long, env = "LICASH_SWAPS_NAME", default_value = "licash-swaps")]
    name: String,
}

impl Notify {
    /// The targets, refused without quoting their URLs, which hold tokens.
    fn targets(&self) -> anyhow::Result<Vec<Target>> {
        self.urls
            .iter()
            .enumerate()
            .filter(|(_, url)| !url.trim().is_empty())
            .map(|(i, url)| {
                url.parse()
                    .with_context(|| format!("notification target {}", i + 1))
            })
            .collect()
    }
}

/// What the provider swaps, and on what terms.
#[derive(Args)]
struct Terms {
    /// The fee on each swap, in the smallest unit.
    #[arg(long, env = "LICASH_SWAPS_FEE_BASE", default_value_t = Config::default().fee.base)]
    fee_base: u64,
    /// The fee on each swap, in parts per million of its amount.
    #[arg(long, env = "LICASH_SWAPS_FEE_PPM", default_value_t = Config::default().fee.ppm,
          value_parser = clap::value_parser!(u64).range(0..=1_000_000))]
    fee_ppm: u64,
    /// The least swapped at once.
    #[arg(long, env = "LICASH_SWAPS_MIN", default_value_t = Config::default().min)]
    min: u64,
    /// The most swapped at once.
    #[arg(long, env = "LICASH_SWAPS_MAX", default_value_t = Config::default().max)]
    max: u64,
    /// Blocks the provider needs to claim the client's lock once it holds
    /// the preimage.
    #[arg(long, env = "LICASH_SWAPS_MARGIN", default_value_t = Config::default().margin)]
    margin: u32,
    /// Blocks within which the operator gets a refund request of the
    /// provider's lock confirmed, once alerted that the hub keeps the
    /// preimage. The provider's lock expires that, the hub's response
    /// window and the margin before the client's, at least.
    #[arg(long, env = "LICASH_SWAPS_CONFIRM", default_value_t = Config::default().confirm,
          value_parser = clap::value_parser!(u32).range(1..))]
    confirm: u32,
}

impl Terms {
    fn config(&self) -> anyhow::Result<Config> {
        anyhow::ensure!(self.min <= self.max, "--min must not exceed --max");
        anyhow::ensure!(
            self.margin > licash_wallet::CLAIM_MARGIN + 2,
            "--margin must exceed {}",
            licash_wallet::CLAIM_MARGIN + 2
        );
        Ok(Config {
            fee: Fee {
                base: self.fee_base,
                ppm: self.fee_ppm,
            },
            min: self.min,
            max: self.max,
            margin: self.margin,
            confirm: self.confirm,
        })
    }
}

/// The chain the provider's wallet follows, for its coins on Bitcoin.
#[derive(Args)]
struct ChainArgs {
    /// Follow Bitcoin at this source: Bitcoin Core's JSON-RPC as
    /// `http://user:password@127.0.0.1:8332` (or `?cookie=PATH`), or
    /// Esplora as `esplora+https://esplora.example/api`.
    #[arg(long, env = "LICASH_SWAPS_CHAIN", hide_env_values = true)]
    chain: Option<String>,
    /// The first block to look in for the provider's coins, once: an
    /// earlier one looks again [default: the chain's tip when first
    /// followed].
    #[arg(long, env = "LICASH_SWAPS_CHAIN_FROM")]
    chain_from: Option<u32>,
}

impl ChainArgs {
    fn source(&self) -> anyhow::Result<Option<Arc<ChainView>>> {
        match &self.chain {
            Some(url) => Ok(Some(Arc::new(ChainView(url.parse().context("--chain")?)))),
            None => Ok(None),
        }
    }

    /// Have `wallet` watch `chain` for its coins: from `--chain-from`, or
    /// the tip unless it watches already.
    async fn watch<T: licash_wallet::Transport>(
        &self,
        wallet: &Wallet<T>,
        chain: Option<&ChainView>,
    ) -> anyhow::Result<()> {
        let from = match (self.chain_from, wallet.silent_next()?, chain) {
            (Some(from), ..) => from,
            (None, Some(_), _) => return Ok(()),
            (None, None, Some(chain)) => chain.0.tip().await.context("the chain's tip")?.height,
            (None, None, None) => {
                anyhow::bail!("--chain or --chain-from: the first block to look in for coins")
            }
        };
        wallet.watch_silent(None, from)?;
        Ok(())
    }
}

/// The recovery contracts protecting the provider's notes at its hubs.
#[derive(Args)]
struct ContractArgs {
    /// Take notes in at any hub with no contract protecting them there:
    /// reckless, as a hub that withholds them keeps them. By default a
    /// provider takes in at each hub only what its contracts there
    /// protect, the first opened by its operator with `licash-wallet
    /// --wallet <data>/wallet.sqlite open-contract`, and keeps them with
    /// --chain: replaced before they end, forced closed at their safe
    /// deadline if needed.
    #[arg(long, env = "LICASH_SWAPS_NO_CONTRACTS",
          value_parser = clap::builder::BoolishValueParser::new())]
    no_contracts: bool,
    /// Days before a contract's safe deadline to open its successor.
    #[arg(
        long,
        env = "LICASH_SWAPS_CONTRACT_SUCCESSOR_DAYS",
        default_value_t = 14
    )]
    contract_successor_days: u32,
    /// Days kept for a forced close to play out in (the exit margin),
    /// before each contract's last request height: its safe deadline comes
    /// a day earlier.
    // Its environment variable and alias keep the name it had as the
    // proof margin, so deployments setting them keep their margin.
    #[arg(
        long,
        alias = "contract-proof-days",
        env = "LICASH_SWAPS_CONTRACT_PROOF_DAYS",
        default_value_t = 14
    )]
    contract_exit_days: u32,
    /// The most a successor costs, in sat [default: what the contract it
    /// replaces cost, and a quarter]: the most one --contract-open-cap
    /// opens costs.
    #[arg(long, env = "LICASH_SWAPS_CONTRACT_MAX_PRICE")]
    contract_max_price: Option<u64>,
    /// Open a contract of up to SAT protected at each hub where none
    /// protects the provider's notes nor is being opened (the first, or
    /// after all ended), costing --contract-max-price at most [default:
    /// its operator opens those].
    #[arg(
        long,
        value_name = "SAT",
        env = "LICASH_SWAPS_CONTRACT_OPEN_CAP",
        requires = "contract_max_price"
    )]
    contract_open_cap: Option<u32>,
    /// Pay out to the provider's own address on Bitcoin, through the swap
    /// provider at URL, what a contract that could not be replaced leaves
    /// unprotected [default: only take no more in there].
    #[arg(long, value_name = "URL", env = "LICASH_SWAPS_DRAIN_VIA")]
    drain_via: Option<String>,
}

impl ContractArgs {
    /// The keeper of the contracts of `provider`, whose files are in
    /// `data`, on `chain`: none with --no-contracts. Refused where contracts
    /// cannot protect its notes.
    fn keeper(
        &self,
        provider: &Arc<Provider<Http>>,
        chain: Option<&str>,
        data: &Path,
    ) -> anyhow::Result<Option<Keeper<Http>>> {
        if self.no_contracts {
            tracing::warn!(
                "--no-contracts: no contract protects the notes the provider takes in at its \
                 hubs, which a hub that withholds them keeps. Reckless outside of tests"
            );
            return Ok(None);
        }
        let reckless = "--no-contracts runs it unprotected, recklessly";
        let network = provider.wallet().network();
        licash_contracts::trust(network).with_context(|| {
            format!("contracts protect a provider's notes, and none opens on {network}: {reckless}")
        })?;
        let chain = chain.with_context(|| {
            format!("contracts protect a provider's notes, and are kept with --chain: {reckless}")
        })?;
        let wallet = data.join("wallet.sqlite");
        let settings = keeper::Settings::new(
            self.contract_exit_days,
            self.contract_successor_days,
            format!(
                "licash-wallet --wallet {} open-contract {{hub}} --chain CHAIN",
                wallet.display()
            ),
        );
        let settings = keeper::Settings {
            max_price: self.contract_max_price,
            open_cap: self.contract_open_cap,
            drain_via: self.drain_via.clone(),
            ..settings
        };
        let node = Node(chain.parse().context("--chain")?);
        Ok(Some(Keeper::new(provider.clone(), node, wallet, settings)))
    }
}

/// What the provider pays out on Bitcoin, with `--chain`.
#[derive(Args)]
struct PayoutTerms {
    /// The fee on each payout, in satoshis.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_FEE_BASE", default_value_t = 0)]
    payout_fee_base: u64,
    /// The fee on each payout, in parts per million of its coin's value.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_FEE_PPM", default_value_t = 2000,
          value_parser = clap::value_parser!(u64).range(0..=1_000_000))]
    payout_fee_ppm: u64,
    /// What each payout pays on top for the miners of its coin, in
    /// satoshis.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_MINER", default_value_t = 500)]
    payout_miner: u64,
    /// The least fee rate its coins, cancels and refunds are paid at (the
    /// chain's estimate when higher), and its clients' claims budgeted at
    /// least, in sat/vB [default: the chain's estimate within 6 blocks at
    /// start, at least 1].
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_RATE",
          value_parser = clap::value_parser!(u64).range(1..))]
    payout_rate: Option<u64>,
    /// The least a payout's coin is worth.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_MIN", default_value_t = 10_000)]
    payout_min: u64,
    /// The most a payout's coin is worth.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_MAX", default_value_t = 1_000_000)]
    payout_max: u64,
    /// Blocks a payout's coin times out before the client's lock expires,
    /// at least: the provider's time to claim it once the coin is claimed.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_MARGIN", default_value_t = 36)]
    payout_margin: u32,
    /// Payouts from one hub whose clients never claimed their coins, in
    /// the last day, from which more from that hub are declined: each cost
    /// the fees of its coin and of its refund.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_MAX_UNCLAIMED", default_value_t = 8)]
    payout_max_unclaimed: u32,
    /// Payouts under way at once, from which no more are taken.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_MAX_OPEN", default_value_t = 32)]
    payout_max_open: u64,
    /// The most blocks a payout's coin is held before it times out: locks
    /// expiring later are declined.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_MAX_BLOCKS", default_value_t = 144)]
    payout_max_blocks: u32,
    /// The least a payout's coin is worth, in multiples of what it and its
    /// refund pay in fees at the rate it is paid at (with --payout-min, the
    /// larger): a client never claiming costs the provider no more than
    /// this share of what it pays out.
    #[arg(long, env = "LICASH_SWAPS_PAYOUT_FEE_SHARE", default_value_t = 20)]
    payout_fee_share: u64,
}

impl PayoutTerms {
    /// The terms, at the rate given or `chain` estimates.
    async fn terms(&self, chain: &ChainView) -> anyhow::Result<swaps::Chain> {
        anyhow::ensure!(
            self.payout_min <= self.payout_max,
            "--payout-min must not exceed --payout-max"
        );
        anyhow::ensure!(
            self.payout_margin > licash_wallet::CLAIM_MARGIN + 2,
            "--payout-margin must exceed {}",
            licash_wallet::CLAIM_MARGIN + 2
        );
        // In sat per 1000 virtual bytes.
        let rate = match self.payout_rate {
            Some(rate) => rate * 1000,
            None => {
                let estimate = chain.0.fee_rate(6).await.unwrap_or_else(|e| {
                    tracing::warn!("no fee estimate: {e:#}");
                    None
                });
                estimate.map_or(1000, |r| r.to_sat_per_kwu() * 4).max(1000)
            }
        };
        Ok(swaps::Chain {
            fee: Fee {
                base: self.payout_fee_base,
                ppm: self.payout_fee_ppm,
            },
            miner: self.payout_miner,
            rate,
            min: self.payout_min,
            max: self.payout_max,
            margin: self.payout_margin,
        })
    }

    /// What payouts whose clients never claim may cost the provider.
    fn limits(&self) -> licash_swaps::PayoutLimits {
        licash_swaps::PayoutLimits {
            no_shows: self.payout_max_unclaimed,
            open: self.payout_max_open,
            max_blocks: self.payout_max_blocks,
            fee_share: self.payout_fee_share,
        }
    }
}

/// What the provider pays over Lightning, from an LND node, with `--lnd`.
#[derive(Args)]
struct LightningArgs {
    /// Pay Lightning invoices for clients' locks from the LND node whose
    /// REST API is at this URL, such as `https://127.0.0.1:8080`.
    #[arg(long, value_name = "URL", env = "LICASH_SWAPS_LND")]
    lnd: Option<String>,
    /// The macaroon the provider calls LND with: it pays invoices and
    /// reads its payments.
    #[arg(
        long,
        value_name = "FILE",
        env = "LICASH_SWAPS_LND_MACAROON",
        requires = "lnd"
    )]
    lnd_macaroon: Option<PathBuf>,
    /// LND's TLS certificate, pinned. Without it, the URL's certificate
    /// must validate against the system's roots.
    #[arg(
        long,
        value_name = "FILE",
        env = "LICASH_SWAPS_LND_CERT",
        requires = "lnd"
    )]
    lnd_cert: Option<PathBuf>,
    /// The fee on each invoice paid, routing fees included, in satoshis.
    #[arg(long, env = "LICASH_SWAPS_LN_FEE_BASE", default_value_t = 2)]
    ln_fee_base: u64,
    /// The fee on each invoice paid, in parts per million of its amount.
    #[arg(long, env = "LICASH_SWAPS_LN_FEE_PPM", default_value_t = 5000,
          value_parser = clap::value_parser!(u64).range(0..=1_000_000))]
    ln_fee_ppm: u64,
    /// The largest invoice paid, in satoshis: less while the node's
    /// channels pay less, with the fee.
    #[arg(long, env = "LICASH_SWAPS_LN_MAX", default_value_t = 1_000_000)]
    ln_max: u64,
    /// Blocks between the end of a payment's route timelock and the expiry
    /// of the client's lock paying for it: the provider's time to learn
    /// the preimage, on Bitcoin at worst, and claim, its node's downtime
    /// and its hubs' included.
    #[arg(long, env = "LICASH_SWAPS_LN_SLACK", default_value_t = 80,
          value_parser = clap::value_parser!(u32).range(i64::from(licash_swaps::MIN_SLACK)..))]
    ln_slack: u32,
}

impl LightningArgs {
    /// The node and what the provider pays through it, if it pays
    /// invoices: the terms name the node's public key, as it says.
    async fn payer(&self) -> anyhow::Result<Option<(Arc<dyn LightningNode>, swaps::Lightning)>> {
        let Some(url) = &self.lnd else {
            return Ok(None);
        };
        let macaroon = self
            .lnd_macaroon
            .as_ref()
            .context("--lnd needs --lnd-macaroon")?;
        let macaroon =
            std::fs::read(macaroon).with_context(|| format!("read {}", macaroon.display()))?;
        let cert = match &self.lnd_cert {
            Some(path) => {
                Some(std::fs::read(path).with_context(|| format!("read {}", path.display()))?)
            }
            None => None,
        };
        let node: Arc<dyn LightningNode> =
            Arc::new(Lnd::new(url, &macaroon, cert.as_deref()).context("--lnd")?);
        let info = node
            .info()
            .await
            .map_err(|e| anyhow::anyhow!("--lnd: {e}"))?;
        let terms = swaps::Lightning {
            node: info.pubkey,
            fee: Fee {
                base: self.ln_fee_base,
                ppm: self.ln_fee_ppm,
            },
            max: self.ln_max,
            slack: self.ln_slack,
        };
        Ok(Some((node, terms)))
    }
}

/// Donations to the wallets of Licash codes, over LNURL-pay, with
/// `--lnurl-url`.
#[derive(Args)]
struct DonationArgs {
    /// Take donations to the wallets of Licash codes over LNURL-pay,
    /// through the node of `--lnd`, payers reaching the provider at this
    /// public URL, such as `https://swaps.example.com`. `licash-swaps
    /// lnurl` prints the static LNURL of a code.
    #[arg(
        long,
        value_name = "URL",
        env = "LICASH_SWAPS_LNURL_URL",
        requires = "lnd"
    )]
    lnurl_url: Option<String>,
    /// The fee on each donation, taken from it, in satoshis: the hub's fee
    /// on paying the payee comes out of it.
    #[arg(long, env = "LICASH_SWAPS_DONATION_FEE_BASE",
          default_value_t = DonationTerms::default().fee.base)]
    donation_fee_base: u64,
    /// The fee on each donation, in parts per million of it.
    #[arg(long, env = "LICASH_SWAPS_DONATION_FEE_PPM",
          default_value_t = DonationTerms::default().fee.ppm,
          value_parser = clap::value_parser!(u64).range(0..=1_000_000))]
    donation_fee_ppm: u64,
    /// The smallest donation, in satoshis.
    #[arg(long, env = "LICASH_SWAPS_DONATION_MIN", default_value_t = DonationTerms::default().min)]
    donation_min: u64,
    /// The largest donation, in satoshis.
    #[arg(long, env = "LICASH_SWAPS_DONATION_MAX", default_value_t = DonationTerms::default().max)]
    donation_max: u64,
    /// The most donations whose invoices are open at once.
    #[arg(long, env = "LICASH_SWAPS_DONATION_MAX_OPEN",
          default_value_t = DonationTerms::default().max_open)]
    donation_max_open: u64,
}

/// Receipts over Lightning for wallets, with `--receive`.
#[derive(Args)]
struct ReceiveArgs {
    /// Take payments over Lightning for wallets, through the node of
    /// `--lnd`: held invoices paid on as locks of the provider's notes to
    /// the wallets at its hubs, settled once claimed.
    #[arg(long, env = "LICASH_SWAPS_RECEIVE", requires = "lnd")]
    receive: bool,
    /// The fee on each receipt, asked on top, in satoshis: the hub's fee
    /// on the lock comes out of it.
    #[arg(long, env = "LICASH_SWAPS_RECEIVE_FEE_BASE",
          default_value_t = ReceiveTerms::default().fee.base)]
    receive_fee_base: u64,
    /// The fee on each receipt, in parts per million of it.
    #[arg(long, env = "LICASH_SWAPS_RECEIVE_FEE_PPM",
          default_value_t = ReceiveTerms::default().fee.ppm,
          value_parser = clap::value_parser!(u64).range(0..=1_000_000))]
    receive_fee_ppm: u64,
    /// The smallest receipt, in satoshis.
    #[arg(long, env = "LICASH_SWAPS_RECEIVE_MIN", default_value_t = ReceiveTerms::default().min)]
    receive_min: u64,
    /// The largest receipt, in satoshis.
    #[arg(long, env = "LICASH_SWAPS_RECEIVE_MAX", default_value_t = ReceiveTerms::default().max)]
    receive_max: u64,
    /// The most receipts under way at once.
    #[arg(long, env = "LICASH_SWAPS_RECEIVE_MAX_OPEN",
          default_value_t = ReceiveTerms::default().max_open)]
    receive_max_open: u64,
}

impl ReceiveArgs {
    /// Its terms, if it takes receipts.
    fn terms(&self) -> Option<ReceiveTerms> {
        self.receive.then_some(ReceiveTerms {
            fee: Fee {
                base: self.receive_fee_base,
                ppm: self.receive_fee_ppm,
            },
            min: self.receive_min,
            max: self.receive_max,
            max_open: self.receive_max_open,
        })
    }
}

/// Deposits on Bitcoin for wallets, with `--deposits` and `--chain`.
#[derive(Args)]
struct DepositArgs {
    /// Take deposits on Bitcoin for wallets, on the chain of `--chain`:
    /// coins hash-locked to the provider, paid on as locks of its notes to
    /// the wallets at its hubs, claimed once the wallets claim.
    #[arg(long, env = "LICASH_SWAPS_DEPOSITS", requires = "chain")]
    deposits: bool,
    /// The fee on each deposit, paid on top, in satoshis: the hub's fee on
    /// the lock comes out of it.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_FEE_BASE",
          default_value_t = DepositTerms::default().fee.base)]
    deposit_fee_base: u64,
    /// The fee on each deposit, in parts per million of it.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_FEE_PPM",
          default_value_t = DepositTerms::default().fee.ppm,
          value_parser = clap::value_parser!(u64).range(0..=1_000_000))]
    deposit_fee_ppm: u64,
    /// What each deposit's coin pays on top for the miners of the
    /// provider's claim of it, in satoshis.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_MINER",
          default_value_t = DepositTerms::default().miner)]
    deposit_miner: u64,
    /// The smallest deposit, in satoshis.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_MIN", default_value_t = DepositTerms::default().min)]
    deposit_min: u64,
    /// The largest deposit, in satoshis.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_MAX", default_value_t = DepositTerms::default().max)]
    deposit_max: u64,
    /// Confirmations a deposit's coin needs before the provider locks.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_DEPTH",
          default_value_t = DepositTerms::default().depth)]
    deposit_depth: u32,
    /// Blocks from a request within which its coin must confirm.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_WINDOW",
          default_value_t = DepositTerms::default().window)]
    deposit_window: u32,
    /// The most blocks from a request to its coin's timeout: deposits at
    /// hubs whose windows need more are declined.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_TIMEOUT",
          default_value_t = DepositTerms::default().timeout)]
    deposit_timeout: u32,
    /// Blocks within which the provider's claim of a coin confirms once it
    /// holds the preimage, its fee rising as they run out.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_SWEEP",
          default_value_t = DepositTerms::default().sweep)]
    deposit_sweep: u32,
    /// The most deposits under way at once.
    #[arg(long, env = "LICASH_SWAPS_DEPOSIT_MAX_OPEN",
          default_value_t = DepositTerms::default().max_open)]
    deposit_max_open: u64,
}

impl DepositArgs {
    /// Its terms, if it takes deposits.
    fn terms(&self) -> Option<DepositTerms> {
        self.deposits.then_some(DepositTerms {
            fee: Fee {
                base: self.deposit_fee_base,
                ppm: self.deposit_fee_ppm,
            },
            miner: self.deposit_miner,
            min: self.deposit_min,
            max: self.deposit_max,
            depth: self.deposit_depth,
            window: self.deposit_window,
            timeout: self.deposit_timeout,
            sweep: self.deposit_sweep,
            max_open: self.deposit_max_open,
        })
    }
}

impl DonationArgs {
    /// The provider's public URL and its terms, if it takes donations.
    fn terms(&self) -> anyhow::Result<Option<(String, DonationTerms)>> {
        let Some(url) = &self.lnurl_url else {
            return Ok(None);
        };
        Ok(Some((
            lnurl_base(url)?,
            DonationTerms {
                fee: Fee {
                    base: self.donation_fee_base,
                    ppm: self.donation_fee_ppm,
                },
                min: self.donation_min,
                max: self.donation_max,
                max_open: self.donation_max_open,
            },
        )))
    }
}

/// The public URL `url` of the provider, as `--lnurl-url` gives it.
fn lnurl_base(url: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        url.starts_with("https://") || url.starts_with("http://"),
        "--lnurl-url {url}: an https:// URL (http:// for an onion or a test)"
    );
    Ok(url.trim_end_matches('/').to_owned())
}

/// The provider's announcement on Nostr, for wallets to discover it.
#[derive(Args)]
struct AnnounceArgs {
    /// Announce the provider on this Nostr relay. Repeat it, or separate
    /// relays with commas, for more. Needs `--announce-url`.
    #[arg(
        long = "nostr-relay",
        value_name = "URL",
        env = "LICASH_SWAPS_NOSTR_RELAYS",
        value_delimiter = ','
    )]
    nostr_relays: Vec<String>,
    /// A URL wallets reach the provider at: `https://`, or an onion
    /// service's `http://`. Repeat it, up to 4 with `--onion`'s.
    #[arg(
        long = "announce-url",
        value_name = "URL",
        env = "LICASH_SWAPS_ANNOUNCE_URLS",
        value_delimiter = ','
    )]
    announce_urls: Vec<String>,
    /// The name the announcement shows.
    #[arg(long = "announce-name", env = "LICASH_SWAPS_ANNOUNCE_NAME")]
    announce_name: Option<String>,
}

/// The provider's announcement: the relays, how it reaches them, and the
/// URLs and name it announces.
struct Announcing {
    relays: Vec<String>,
    route: Route,
    urls: Vec<String>,
    name: Option<String>,
}

impl AnnounceArgs {
    /// The relays and the announcement's URLs and name, if it announces:
    /// with `onion`, the onion service's URL is added once it runs.
    fn announcing(self, onion: bool) -> anyhow::Result<Option<Announcing>> {
        let relays: Vec<String> = self
            .nostr_relays
            .into_iter()
            .filter(|r| !r.is_empty())
            .collect();
        let urls: Vec<String> = self
            .announce_urls
            .into_iter()
            .filter(|u| !u.is_empty())
            .collect();
        if relays.is_empty() {
            anyhow::ensure!(urls.is_empty(), "--announce-url needs --nostr-relay");
            return Ok(None);
        }
        // `--onion`'s URL joins them once its service runs.
        if !(onion && urls.is_empty()) {
            check(&urls).context("--announce-url")?;
        }
        Ok(Some(Announcing {
            relays,
            route: Route::Direct,
            urls,
            name: self.announce_name,
        }))
    }
}

/// Whether wallets can use the announced `urls`.
fn check(urls: &[String]) -> anyhow::Result<()> {
    let announcement = licash_nostr::Announcement {
        urls: urls.to_vec(),
        network: String::new(),
        name: None,
    };
    announcement.check()
}

/// Announce through `tor`, unless through --proxy, and at `onion`'s URL
/// too, if the service announces.
fn announce_over(
    announcing: &mut Option<Announcing>,
    tor: &Tor,
    onion: Option<&Onion>,
) -> anyhow::Result<()> {
    let Some(announcing) = announcing else {
        return Ok(());
    };
    if let Route::Direct = announcing.route {
        announcing.route = Route::Tor(tor.clone());
    }
    if let Some(onion) = onion {
        announcing.urls.push(onion.url().to_owned());
        check(&announcing.urls).context("--onion")?;
    }
    Ok(())
}

// Parsed once: its size does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Create the provider: a wallet with a fresh seed, and no swaps. Never
    /// replaces either. Add hubs and fund it with `licash-wallet --wallet
    /// <data>/wallet.sqlite`.
    Init {
        /// The network of its hubs: bitcoin, regtest, signet or mutinynet.
        #[arg(long, env = "LICASH_SWAPS_NETWORK", default_value_t = ChainProfile::Core30Mainnet)]
        network: ChainProfile,
    },
    /// Serve the provider's HTTP API, and take its swaps on, until SIGINT
    /// or SIGTERM.
    Run {
        #[arg(long, env = "LICASH_SWAPS_LISTEN", default_value = "127.0.0.1:8340")]
        listen: SocketAddr,
        /// A reverse proxy in front of `--listen` whose `X-Forwarded-For`
        /// the provider believes, as an address or a CIDR block; repeat (or
        /// separate by commas) for more. Receipts and donations asked and
        /// not paid are bounded by client address: without it, every
        /// client behind the proxy is the proxy's one address. The proxy
        /// must replace the header its clients send, and nothing else may
        /// reach `--listen`.
        #[arg(long = "trusted-proxy", env = "LICASH_SWAPS_TRUSTED_PROXY",
              value_name = "CIDR", value_delimiter = ',',
              value_parser = licash_serve::trusted_proxy)]
        trusted_proxies: Vec<ipnet::IpNet>,
        #[command(flatten)]
        terms: Terms,
        /// Seconds between rounds over the swaps under way.
        #[arg(long, env = "LICASH_SWAPS_STEP", default_value_t = 10,
              value_parser = clap::value_parser!(u64).range(1..))]
        step: u64,
        /// Renew notes a hub no longer unlinks since it restarted, paying
        /// them to the provider itself, only if its fee on them is at most
        /// this many parts per million of their value, or its spending
        /// schedule is at most 1 sat base, this rate and 0.1 sat per
        /// output. Contract ceilings take precedence. 0 means free only.
        #[arg(long, env = "LICASH_SWAPS_RENEW_PPM", default_value_t = licash_wallet::RENEW_PPM)]
        renew_ppm: u32,
        /// Reach hubs, and Nostr relays, through this proxy, such as
        /// socks5h://127.0.0.1:9050 for Tor's (relays through SOCKS only).
        #[arg(long, env = "LICASH_SWAPS_PROXY")]
        proxy: Option<String>,
        /// Reach hubs and Nostr relays through a Tor client of the
        /// provider's own, instead of --proxy, keeping its state in
        /// `<data>/tor`.
        #[arg(long, env = "LICASH_SWAPS_TOR", conflicts_with = "proxy",
              value_parser = clap::builder::BoolishValueParser::new())]
        tor: bool,
        /// Also serve the API as an onion service of that Tor client, at
        /// the same address on every start (its key in `<data>/tor`), and
        /// announce it.
        #[arg(long, env = "LICASH_SWAPS_ONION",
              value_parser = clap::builder::BoolishValueParser::new())]
        onion: bool,
        /// Whether `--onion`'s service asks its clients for a proof of work
        /// while it is under load, which prices each new circuit to it.
        #[arg(long, env = "LICASH_SWAPS_ONION_POW", default_value_t = true,
              action = clap::ArgAction::Set,
              value_parser = clap::builder::BoolishValueParser::new())]
        onion_pow: bool,
        #[command(flatten)]
        notify: Notify,
        /// Notify only of these kinds of event [default: all but accepted].
        #[arg(long, value_name = "KIND", env = "LICASH_SWAPS_NOTIFY_KINDS", value_delimiter = ',',
              value_parser = clap::builder::PossibleValuesParser::new(notify::KINDS))]
        notify_kinds: Vec<String>,
        #[command(flatten)]
        announce: AnnounceArgs,
        /// With --chain, the provider pays notes out on Bitcoin too, from
        /// its coins there: fund it at `address`.
        #[command(flatten)]
        chain: ChainArgs,
        #[command(flatten)]
        payouts: PayoutTerms,
        /// With --lnd, the provider pays Lightning invoices too, for
        /// clients' locks at its hubs.
        #[command(flatten)]
        lightning: LightningArgs,
        /// With --lnurl-url and --lnd, the provider takes donations to
        /// the wallets of Licash codes over LNURL-pay too.
        #[command(flatten)]
        donations: DonationArgs,
        /// With --receive and --lnd, the provider takes payments over
        /// Lightning for wallets too.
        #[command(flatten)]
        receives: ReceiveArgs,
        /// With --deposits and --chain, the provider takes deposits on
        /// Bitcoin for wallets too.
        #[command(flatten)]
        deposits: DepositArgs,
        #[command(flatten)]
        contracts: ContractArgs,
    },
    /// Print the static LNURL of donations to the wallet of a Licash code
    /// through the provider at `--lnurl-url`, for a QR code: any Lightning
    /// wallet pays it, again and again, while the payee is offline.
    Lnurl {
        #[arg(long = "lnurl-url", value_name = "URL", env = "LICASH_SWAPS_LNURL_URL")]
        url: String,
        /// The payee's Licash code.
        code: String,
    },
    /// Hand out an address on Bitcoin to fund the provider's payouts at:
    /// a plain taproot address of its wallet, watched from then on.
    Address {
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Send a test notification to each `--notify` target.
    TestNotify {
        #[command(flatten)]
        notify: Notify,
    },
    /// Earnings, balances and what needs attention; details on request.
    Status {
        #[arg(long)]
        json: bool,
        /// Show this many recent swaps (default: none, or 10 with --details).
        #[arg(long)]
        swaps: Option<u32>,
        /// Include per-hub balances, identity and recent swaps.
        #[arg(long)]
        details: bool,
    },
    /// An interactive dashboard of the provider's swaps, fees, notes and
    /// health over time, read from its files only (never migrated), beside
    /// the running provider or without it.
    Dashboard {
        #[command(flatten)]
        dashboard: licash_dashboard::Args,
        /// The running provider's URL, asked for its health [default:
        /// http:// and `LICASH_SWAPS_LISTEN`, or 127.0.0.1:8340].
        #[arg(long)]
        url: Option<String>,
    },
    /// The provider's events as JSON lines, oldest first.
    Events {
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// Keep printing new events as they come.
        #[arg(long)]
        follow: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    logging(cli.log);
    let structured = matches!(cli.log, Log::Json);
    match command(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if structured {
                tracing::error!("{e:#}");
            } else {
                eprintln!("error: {e:#}");
            }
            ExitCode::FAILURE
        }
    }
}

fn logging(format: Log) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(match format {
            Log::Text => "info,licash_wallet=warn,nostr_sdk=off",
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
    let data = cli.data;
    // Whatever the command: an earlier layout is never read, nor replaced.
    refuse_legacy(&data)?;
    match cli.command {
        Command::Init { network } => init(&data, network, cli.log),
        Command::Run {
            listen,
            trusted_proxies,
            terms,
            step,
            renew_ppm,
            proxy,
            tor,
            onion,
            onion_pow,
            notify,
            notify_kinds,
            announce,
            chain,
            payouts,
            lightning,
            donations,
            receives,
            deposits,
            contracts,
        } => {
            let config = terms.config()?;
            let source = chain.source()?;
            let mut announcing = announce.announcing(onion)?;
            if let (Some(announcing), Some(proxy)) = (&mut announcing, &proxy) {
                announcing.route = Route::socks(proxy).context("--proxy")?;
            }
            let targets = notify.targets()?;
            // Before the Tor client creates its directory.
            let wallet = data.join("wallet.sqlite");
            anyhow::ensure!(
                wallet.exists(),
                "{}: no provider, `init` creates one",
                wallet.display()
            );
            let runtime = tokio::runtime::Runtime::new()?;
            let _entered = runtime.enter();
            let client = match tor || onion {
                true => Some(Tor::new(&data.join("tor")).context("a Tor client")?),
                false => None,
            };
            let transport = match &client {
                Some(client) if tor => Http::tor(client.clone()),
                _ => Http::new(proxy.as_deref())?,
            };
            let provider = open(&data, transport, config)?;
            provider.wallet().set_renew_limit(renew_ppm);
            let provider = match &source {
                Some(source) => {
                    runtime.block_on(chain.watch(provider.wallet(), Some(source)))?;
                    let terms = runtime.block_on(payouts.terms(source))?;
                    provider.pay_out(terms).limit_payouts(payouts.limits())
                }
                None => {
                    let open = provider.open_payouts()?;
                    anyhow::ensure!(
                        open == 0,
                        "{open} payouts on Bitcoin under way: they need --chain"
                    );
                    provider
                }
            };
            let provider = match (deposits.terms(), &source) {
                (Some(terms), Some(_)) => provider.take_deposits(terms)?,
                (Some(_), None) => anyhow::bail!("--deposits needs --chain"),
                (None, _) => {
                    let open = provider.open_deposits()?;
                    anyhow::ensure!(
                        open == 0,
                        "{open} deposits on Bitcoin under way: they need --deposits and --chain"
                    );
                    provider
                }
            };
            let payer = runtime.block_on(lightning.payer())?;
            let node = payer.as_ref().map(|(node, _)| node.clone());
            let provider = match payer {
                Some((node, terms)) => provider.pay_lightning(node, terms)?,
                None => {
                    let open = provider.open_invoices()?;
                    anyhow::ensure!(
                        open == 0,
                        "{open} Lightning payments under way: they need --lnd"
                    );
                    provider
                }
            };
            let provider = match (receives.terms(), &node) {
                (Some(terms), Some(node)) => provider.take_receives(node.clone(), terms)?,
                (Some(_), None) => anyhow::bail!("--receive needs --lnd"),
                (None, _) => {
                    let open = provider.open_receives()?;
                    anyhow::ensure!(
                        open == 0,
                        "{open} receipts over Lightning under way: they need --receive and --lnd"
                    );
                    provider
                }
            };
            let donating = donations.terms()?;
            let provider = match (&donating, node) {
                (Some((url, terms)), Some(node)) => {
                    let provider = provider.take_donations(node, terms.clone(), url)?;
                    match provider.names_domain() {
                        Some(domain) => tracing::info!(%domain, "serving Lightning Addresses"),
                        None => tracing::info!(
                            %url,
                            "no Lightning Addresses: --lnurl-url is not an https:// origin \
                             without a path (http:// for an onion or on regtest)"
                        ),
                    }
                    provider
                }
                (Some(_), None) => anyhow::bail!("--lnurl-url needs --lnd"),
                (None, _) => {
                    let open = provider.open_donations()?;
                    anyhow::ensure!(
                        open == 0,
                        "{open} donations under way: they need --lnurl-url and --lnd"
                    );
                    provider
                }
            };
            // Payments to donations' payees are mailed as announcements go.
            let mailing = match (&donating, &proxy, &client) {
                (None, _, _) => None,
                (Some(_), Some(proxy), _) => Some(Route::socks(proxy).context("--proxy")?),
                (Some(_), None, Some(client)) => Some(Route::Tor(client.clone())),
                (Some(_), None, None) => Some(Route::Direct),
            };
            let provider = Arc::new(provider);
            // Before it serves: nothing is taken in unprotected.
            let keeper = contracts.keeper(&provider, chain.chain.as_deref(), &data)?;
            let nostr = match announcing {
                Some(_) => Some(licash_nostr::public_key(&provider.nostr_secret()?)?),
                None => None,
            };
            let serving = licash_swaps_service::Serving {
                nostr,
                chain: source.clone(),
                ingress: Arc::new(licash_serve::Ingress::new(trusted_proxies)),
            };
            let router = licash_swaps_service::router(provider.clone(), serving);
            let onion = match &client {
                Some(client) if onion => {
                    let onion = client.serve("licash-swaps", router.clone(), onion_pow)?;
                    tracing::info!(url = onion.url(), "serving as an onion service");
                    Some(onion)
                }
                _ => None,
            };
            if let Some(client) = &client {
                announce_over(&mut announcing, client, onion.as_ref())?;
            }
            let notifier = if targets.is_empty() {
                None
            } else {
                let cursors = data.join("notify.json");
                let notifier = Notifier::new(
                    provider.clone(),
                    &notify.name,
                    targets,
                    &cursors,
                    notify_kinds,
                )
                .context("set up notifications")?;
                Some(notifier)
            };
            let every = Duration::from_secs(step);
            // Stopped as the provider stops: dropped on return.
            let keeping = match keeper {
                Some(keeper) => {
                    tracing::info!("keeping the contracts protecting the provider's notes");
                    let running = keeper.spawn(keeper::EVERY);
                    Some(running.context("a thread for the contracts")?)
                }
                None => None,
            };
            let serving = serve(
                provider, router, listen, every, notifier, announcing, source, keeping, mailing,
            );
            runtime.block_on(serving)
        }
        Command::Address { chain } => address(&data, &chain),
        Command::Lnurl { url, code } => {
            let code: LicashCode = code
                .parse()
                .map_err(|e| anyhow::anyhow!("a Licash code: {e}"))?;
            let base = lnurl_base(&url)?;
            println!("{}", code.lnurl(&base));
            Ok(())
        }
        Command::TestNotify { notify } => test_notify(&notify),
        Command::Status {
            json,
            swaps,
            details,
        } => {
            // JSON keeps its previous default of ten records.
            let latest = swaps.unwrap_or(if json || details { 10 } else { 0 });
            status(&data, json, latest, details)
        }
        Command::Dashboard { dashboard, url } => show(&data, dashboard, url),
        Command::Events {
            after,
            limit,
            follow,
        } => events(&data, after, limit, follow),
    }
}

fn init(data: &Path, network: ChainProfile, log: Log) -> anyhow::Result<()> {
    let mut dir = std::fs::DirBuilder::new();
    dir.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
    dir.create(data)
        .with_context(|| format!("create {}", data.display()))?;
    let wallet = data.join("wallet.sqlite");
    anyhow::ensure!(
        !wallet.exists(),
        "{} exists already: never replaced",
        wallet.display()
    );
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    let wallet =
        Wallet::create(&wallet, &seed, network, Http::new(None)?).context("create the wallet")?;
    let address = hex::encode(wallet.address().to_bytes());
    Provider::create(wallet, Config::default()).context("create the provider")?;
    if matches!(log, Log::Json) {
        tracing::info!(data = %data.display(), %address, %network, "provider created: back up its wallet file");
    } else {
        eprintln!(
            "Provider created. Back up wallet.sqlite in {}.",
            data.display()
        );
    }
    println!("{address}");
    Ok(())
}

/// Print an address on Bitcoin of the provider's wallet, to fund it at.
fn address(data: &Path, chain: &ChainArgs) -> anyhow::Result<()> {
    let provider = open(data, Http::new(None)?, Config::default())?;
    let source = chain.source()?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(chain.watch(provider.wallet(), source.as_deref()))?;
    println!("{}", provider.wallet().fallback_address()?);
    Ok(())
}

fn open(data: &Path, transport: Http, config: Config) -> anyhow::Result<Provider<Http>> {
    let wallet = Wallet::open(&data.join("wallet.sqlite"), transport).context("open the wallet")?;
    Provider::open(wallet, config).context("open the swap provider")
}

/// The files an earlier layout kept beside the wallet's, which this version
/// never reads: refused by name, and left for the operator to move away.
fn refuse_legacy(data: &Path) -> anyhow::Result<()> {
    licash_store::refuse_legacy(data, &["swaps.sqlite", "contracts.sqlite"], "wallet.sqlite")?;
    Ok(())
}

// Each an explicit part of what it serves: no bundle would say more.
#[allow(clippy::too_many_arguments)]
async fn serve(
    provider: Arc<Provider<Http>>,
    router: axum::Router,
    listen: SocketAddr,
    every: Duration,
    notifier: Option<Notifier>,
    announcing: Option<Announcing>,
    chain: Option<Arc<ChainView>>,
    keeping: Option<keeper::Running>,
    mailing: Option<Route>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listen on {listen}"))?;
    let config = provider.config();
    tracing::debug!(
        address = %hex::encode(provider.wallet().address().to_bytes()),
        config = %serde_json::to_string(config)?,
        "swap configuration"
    );
    tracing::info!("serving at {}", listener.local_addr()?);
    let hubs = provider.wallet().hubs()?;
    if hubs.len() < 2 {
        tracing::warn!(
            hubs = hubs.len(),
            "swapping needs two hubs: add them with licash-wallet"
        );
    }
    let notifying = notifier.clone().map(|notifier| {
        tracing::info!(
            "notifications enabled ({} targets)",
            notifier.targets().len()
        );
        tokio::spawn(notifier.run())
    });
    let mut critical = Critical::default();
    critical.spawn(
        "the swaps' rounds",
        licash_swaps_service::step(provider.clone(), every),
    );
    if let Some(chain) = chain {
        let terms = provider.payout_terms().copied();
        tracing::debug!(
            chain = %chain.0,
            terms = %serde_json::to_string(&terms).unwrap_or_default(),
            "paying out on Bitcoin"
        );
        tracing::info!("paying out on Bitcoin");
        critical.spawn(
            "the payouts' follower",
            licash_swaps_service::follow(provider.clone(), chain.clone(), every),
        );
        if let Some(terms) = provider.deposit_terms() {
            tracing::info!(
                fee_base = terms.fee.base,
                fee_ppm = terms.fee.ppm,
                min = terms.min,
                max = terms.max,
                "taking deposits on Bitcoin for wallets"
            );
            critical.spawn(
                "the deposits' follower",
                licash_swaps_service::take_deposits(provider.clone(), chain, every),
            );
        }
    }
    if let Some(terms) = provider.lightning_terms().cloned() {
        tracing::debug!(
            terms = %serde_json::to_string(&terms).unwrap_or_default(),
            "paying over Lightning"
        );
        tracing::info!(node = %terms.node, "paying Lightning invoices");
        critical.spawn(
            "the invoices' payer",
            licash_swaps_service::pay_invoices(provider.clone(), every),
        );
    }
    if let Some(terms) = provider.receive_terms() {
        tracing::info!(
            fee_base = terms.fee.base,
            fee_ppm = terms.fee.ppm,
            min = terms.min,
            max = terms.max,
            "taking payments over Lightning for wallets"
        );
        critical.spawn(
            "the receipts' follower",
            licash_swaps_service::take_receives(provider.clone(), every),
        );
    }
    if let (Some(terms), Some(route)) = (provider.donation_terms(), mailing) {
        tracing::info!(
            fee_base = terms.fee.base,
            fee_ppm = terms.fee.ppm,
            min = terms.min,
            max = terms.max,
            "taking donations over LNURL-pay"
        );
        critical.spawn(
            "the donations' follower",
            licash_swaps_service::take_donations(provider.clone(), route, every),
        );
    }
    if let Some(mut keeping) = keeping {
        // Its thread ending stops the provider; the provider stopping
        // drops it, which stops the thread.
        critical.spawn("the contracts' keeper", async move {
            keeping.ended().await;
        });
    }
    let announcing = announcing.map(|a| {
        let (relays, urls) = (a.relays.join(", "), a.urls.join(", "));
        tracing::debug!(%relays, %urls, "announcement configuration");
        tracing::info!("announcing on Nostr");
        tokio::spawn(licash_swaps_service::announce(
            provider.clone(),
            a.relays,
            a.route,
            a.urls,
            a.name,
        ))
    });
    // Stopped by a signal, or by a critical task's end: then with an
    // error, for the provider's supervisor (its container's restart
    // policy) to start it again. Dropped, the others are aborted.
    let (tell, mut told) = tokio::sync::oneshot::channel();
    let stop = async move {
        tokio::select! {
            () = shutdown() => {}
            why = critical.stopped() => {
                tracing::error!("stopping: {why}");
                let _ = tell.send(why);
            }
        }
    };
    licash_serve::listen(listener, router, stop).await;
    if let Some(announcing) = announcing {
        announcing.abort();
    }
    if let (Some(notifying), Some(notifier)) = (notifying, notifier) {
        // Events not yet sent go out after the next start.
        notifying.abort();
        notifier.stopped().await;
    }
    if let Ok(why) = told.try_recv() {
        anyhow::bail!("{why}");
    }
    tracing::info!("stopped");
    Ok(())
}

/// The tasks the provider can't serve without, each looping for as long
/// as it runs: one that returns or panics stops the provider.
#[derive(Default)]
struct Critical {
    set: tokio::task::JoinSet<()>,
    names: std::collections::HashMap<tokio::task::Id, &'static str>,
}

impl Critical {
    fn spawn(
        &mut self,
        name: &'static str,
        task: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let id = self.set.spawn(task).id();
        self.names.insert(id, name);
    }

    /// Why the first of them stopped; pending forever if none runs.
    async fn stopped(&mut self) -> String {
        let name = |id| self.names.get(&id).copied().unwrap_or("a task");
        match self.set.join_next_with_id().await {
            None => std::future::pending().await,
            Some(Ok((id, ()))) => format!("{} stopped", name(id)),
            Some(Err(e)) if e.is_panic() => format!("{} panicked", name(e.id())),
            Some(Err(e)) => format!("{} was cancelled", name(e.id())),
        }
    }
}

fn test_notify(notify: &Notify) -> anyhow::Result<()> {
    let targets = notify.targets()?;
    anyhow::ensure!(!targets.is_empty(), "no target: give --notify URL");
    let client = licash_notify::client()?;
    let message = notify::titled(
        &notify.name,
        Message::new(
            Priority::Normal,
            "Test",
            "Notifications of this swap provider reach you here.",
        ),
    );
    let failed = tokio::runtime::Runtime::new()?.block_on(async {
        let mut failed = 0;
        for target in &targets {
            match target.send(&client, &message).await {
                Ok(()) => println!("sent    {target}"),
                Err(e) => {
                    println!("failed  {target}: {e:#}");
                    failed += 1;
                }
            }
        }
        failed
    });
    anyhow::ensure!(failed == 0, "{failed} of {} targets failed", targets.len());
    Ok(())
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
    tracing::info!("stopping: finishing the requests in flight");
}

fn show(data: &Path, args: licash_dashboard::Args, url: Option<String>) -> anyhow::Result<()> {
    let url = url.unwrap_or_else(|| {
        let listen = std::env::var("LICASH_SWAPS_LISTEN");
        format!("http://{}", listen.as_deref().unwrap_or("127.0.0.1:8340"))
    });
    let probe = licash_dashboard::Probe::new(&url, licash_swaps_service::HEALTH)?;
    // Blocks are told in the time of the provider's network's.
    let network = open(data, Http::new(None)?, Config::default())?
        .wallet()
        .network();
    licash_dashboard::set_block_seconds(network.block_seconds());
    let data = data.to_owned();
    args.run(move || licash_swaps_service::dashboard::report(&data, Some(&probe)))
}

fn status(data: &Path, json: bool, latest: u32, details: bool) -> anyhow::Result<()> {
    let provider = open(data, Http::new(None)?, Config::default())?;
    let stats = provider.stats()?;
    let balance = provider.wallet().balance()?;
    let swaps = provider.records(latest)?;
    let address = hex::encode(provider.wallet().address().to_bytes());
    let network = provider.wallet().network();
    // Its coins on Bitcoin, for payouts, and those no transaction spends.
    let coins = provider.wallet().silent_coins()?;
    let onchain: u64 = coins.iter().map(|c| c.value).sum();
    let free: u64 = coins
        .iter()
        .filter(|c| c.spending.is_none())
        .map(|c| c.value)
        .sum();
    let payouts = provider.open_payouts()?;
    if json {
        let balance: Vec<_> = balance
            .iter()
            .map(|b| serde_json::json!({"hub": b.hub, "available": b.available, "pending": b.pending}))
            .collect();
        let status = serde_json::json!({
            "address": address,
            "network": network.name(),
            "stats": stats,
            "balance": balance,
            "onchain": {"total": onchain, "free": free, "open_payouts": payouts},
            "swaps": swaps,
        });
        println!("{status}");
        return Ok(());
    }
    // What it earned first, then what it did and holds; who it is last.
    let n = |v: u64| licash_dashboard::grouped(v as i64);
    let sat = |v: u64| format!("{} sat", n(v));
    let done: Vec<String> = [
        (stats.done, "done"),
        (stats.open, "open"),
        (stats.refunded, "refunded"),
        (stats.failed, "failed"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, what)| format!("{} {what}", n(count)))
    .collect();
    let mut rows = vec![
        ("earned".to_owned(), sat(stats.earned)),
        (
            "swaps".to_owned(),
            match done.is_empty() {
                true => "none".to_owned(),
                false => done.join(", "),
            },
        ),
        (
            "lost".to_owned(),
            match stats.lost {
                0 => "none".to_owned(),
                1 => format!("1 swap, {}", sat(stats.lost_amount)),
                count => format!("{} swaps, {}", n(count), sat(stats.lost_amount)),
            },
        ),
    ];
    rows.push((
        "balance".to_owned(),
        sat(balance.iter().map(|b| b.available).sum()),
    ));
    let pending = balance.iter().map(|b| b.pending).sum();
    if pending > 0 {
        rows.push(("pending".to_owned(), sat(pending)));
    }
    if details {
        for b in &balance {
            let pending = match b.pending {
                0 => String::new(),
                p => format!(", {} pending", sat(p)),
            };
            rows.push((
                dashboard::short(&b.hub),
                format!("{}{pending}", sat(b.available)),
            ));
        }
    }
    if onchain > 0 || payouts > 0 {
        rows.push((
            "on Bitcoin".to_owned(),
            format!(
                "{}, {} free, {payouts} payouts open",
                sat(onchain),
                sat(free)
            ),
        ));
    }
    rows.push(("network".to_owned(), network.to_string()));
    if details {
        rows.push(("events".to_owned(), n(stats.events)));
        rows.push(("address".to_owned(), address));
    }
    let width = rows
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0);
    for (label, value) in &rows {
        println!("{label:<width$}  {value}");
    }
    // The latest swaps, a line each.
    let amounts: Vec<String> = swaps
        .iter()
        .map(|s| {
            format!(
                "{}, fee {}",
                sat(s.amount),
                licash_dashboard::fee(s.fee as i64, s.amount as i64)
            )
        })
        .collect();
    let wide = amounts.iter().map(|a| a.chars().count()).max().unwrap_or(0);
    if !swaps.is_empty() {
        println!();
    }
    for (s, amount) in swaps.iter().zip(&amounts) {
        let stage = serde_json::to_value(s.stage)?;
        let stage = stage.as_str().unwrap_or_default();
        let reason = s
            .reason
            .as_deref()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default();
        println!(
            "{}…  {stage:<8}  {amount:<wide$}  {} → {}{reason}",
            &s.id[..8],
            dashboard::short(&s.from),
            dashboard::short(&s.to),
        );
    }
    Ok(())
}

fn events(data: &Path, mut after: u64, limit: u32, follow: bool) -> anyhow::Result<()> {
    let provider = open(data, Http::new(None)?, Config::default())?;
    let mut out = std::io::stdout().lock();
    loop {
        let page = provider.events(after, limit)?;
        for event in &page {
            let printed =
                writeln!(out, "{}", serde_json::to_string(event)?).and_then(|()| out.flush());
            match printed {
                // The reader is gone, as `events --follow | head` leaves it.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                printed => printed?,
            }
            after = event.seq;
        }
        if !follow {
            return Ok(());
        }
        if page.is_empty() {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_first_critical_task_to_stop_or_panic_is_named() {
        let mut critical = Critical::default();
        critical.spawn("forever", std::future::pending());
        critical.spawn("the follower", async {});
        assert_eq!(critical.stopped().await, "the follower stopped");
        critical.spawn("the keeper", async { panic!("a bug") });
        assert_eq!(critical.stopped().await, "the keeper panicked");
        let waited = tokio::time::timeout(Duration::from_millis(50), critical.stopped());
        assert!(waited.await.is_err(), "the one that runs on stopped");
    }

    fn announcing(route: Route) -> Option<Announcing> {
        Some(Announcing {
            relays: vec!["wss://relay.example".into()],
            route,
            urls: vec!["https://swaps.example".into()],
            name: None,
        })
    }

    #[tokio::test]
    async fn relays_are_reached_through_tor_unless_through_the_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let tor = Tor::new(dir.path()).unwrap();
        let mut direct = announcing(Route::Direct);
        announce_over(&mut direct, &tor, None).unwrap();
        assert!(matches!(direct.unwrap().route, Route::Tor(_)));
        let mut proxied = announcing(Route::socks("socks5h://127.0.0.1:9050").unwrap());
        announce_over(&mut proxied, &tor, None).unwrap();
        assert!(matches!(proxied.unwrap().route, Route::Socks(_)));
        let mut none = None;
        announce_over(&mut none, &tor, None).unwrap();
        assert!(none.is_none());
    }

    fn contracts(args: &[&str]) -> ContractArgs {
        let cli = Cli::try_parse_from([&["licash-swaps", "run"], args].concat()).unwrap();
        match cli.command {
            Command::Run { contracts, .. } => contracts,
            _ => unreachable!("run"),
        }
    }

    #[test]
    fn the_exit_margin_keeps_its_name_as_the_proof_margin() {
        let named = contracts(&["--contract-exit-days", "9"]);
        let old = contracts(&["--contract-proof-days", "9"]);
        assert_eq!((named.contract_exit_days, old.contract_exit_days), (9, 9));
    }

    #[test]
    fn contracts_protect_a_providers_notes_unless_recklessly_told_not_to() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[7; 32],
            ChainProfile::Core30DefaultRegtest,
            Http::new(None).unwrap(),
        )
        .unwrap();
        let provider = Arc::new(Provider::create(wallet, Config::default()).unwrap());
        let chain = Some("http://user:password@127.0.0.1:1");

        let defaults = contracts(&[]);
        assert!(!defaults.no_contracts);
        assert_eq!(
            (
                defaults.contract_exit_days,
                defaults.contract_successor_days
            ),
            (14, 14)
        );
        assert_eq!(
            (defaults.contract_max_price, defaults.drain_via),
            (None, None)
        );
        let unprotected = contracts(&["--no-contracts"]);
        let none = unprotected.keeper(&provider, chain, dir.path()).unwrap();
        assert!(none.is_none());
        assert_eq!(provider.intake(), None);
        // Kept: nothing taken in at any hub until its first round.
        let kept = contracts(&[]).keeper(&provider, chain, dir.path()).unwrap();
        assert!(kept.is_some());
        assert_eq!(provider.intake(), Some(Default::default()));
        let refused = contracts(&[]).keeper(&provider, None, dir.path());
        assert!(refused.is_err());
    }

    #[test]
    fn renewals_default_to_1000_parts_per_million_unless_set() {
        let renew = |args: &[&str]| {
            let cli = Cli::try_parse_from([&["licash-swaps", "run"], args].concat()).unwrap();
            match cli.command {
                Command::Run { renew_ppm, .. } => renew_ppm,
                _ => unreachable!("run"),
            }
        };
        assert_eq!(renew(&[]), 1_000);
        assert_eq!(renew(&["--renew-ppm", "0"]), 0);
    }
}
