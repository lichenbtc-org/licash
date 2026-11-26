//! `licash-hub`: create, run and watch a Licash hub.

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
use licash_chain_client::Source;
use licash_contracts::hub::Openings;
use licash_hub::{Fee, Hub, Ledger, Policy, Timing};
use licash_hub_service::{
    announce::announce,
    dashboard, deposit,
    inbox::Inbox,
    lightning::{lnd::Lnd, Config, Gateway},
    notify::{self, Notifier},
    payouts, peer,
    tweaks::{self, Tweaks},
    watch::watch,
    Services,
};
use licash_nostr::{Announcement, Route};
use licash_notify::{Message, Priority, Target};
use licash_swaps::{Config as SwapsConfig, Issuer, Provider};
use licash_swaps_service::{
    keeper::{self, Keeper},
    notify::Notifier as SwapsNotifier,
};
use licash_tor::{Onion, Tor};
use licash_transport::Http;
use licash_wallet::Wallet;
use rand_core::{OsRng, RngCore};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "licash-hub",
    version,
    about = "Create, run and watch a Licash hub"
)]
struct Cli {
    /// The hub's directory: its database `hub.sqlite`, and its seed unless
    /// `--seed` says otherwise.
    #[arg(long, global = true, env = "LICASH_HUB_DATA", default_value = "data")]
    data: PathBuf,
    /// The seed file, the hub's one secret: `<data>/seed` unless given.
    #[arg(long, global = true, env = "LICASH_HUB_SEED")]
    seed: Option<PathBuf>,
    /// Log lines on stderr as text or JSON, filtered by RUST_LOG.
    #[arg(long, global = true, env = "LICASH_HUB_LOG", value_enum, default_value_t = Log::Text)]
    log: Log,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Notify {
    /// Notify of the hub's events at this Apprise-style URL: gotify://,
    /// tgram://, ntfy://, json:// or apprise:// (see docs/hub.md). Repeat it,
    /// or separate URLs with commas, for more targets.
    #[arg(
        long = "notify",
        value_name = "URL",
        env = "LICASH_HUB_NOTIFY",
        value_delimiter = ',',
        hide_env_values = true
    )]
    urls: Vec<String>,
    /// The name heading notification titles, to tell hubs apart.
    #[arg(long, env = "LICASH_HUB_NAME", default_value = "licash-hub")]
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

/// The chain the hub follows, for locks.
#[derive(Args)]
struct Chain {
    /// Follow Bitcoin at this URL: a node's JSON-RPC,
    /// `http[s]://[user:pass@]host:port[?cookie=PATH]`, or an Esplora API,
    /// `esplora+http[s]://host[:port][/path]`. Without it, locks are refused.
    #[arg(
        long = "chain",
        value_name = "URL",
        env = "LICASH_HUB_CHAIN",
        hide_env_values = true
    )]
    url: Option<String>,
    /// The network the chain must be: bitcoin, regtest, signet or mutinynet.
    #[arg(long, env = "LICASH_HUB_NETWORK", default_value_t = ChainProfile::Core30Mainnet)]
    network: ChainProfile,
    /// Seconds between rounds of the scan and of deposits, below `--max-lag`.
    #[arg(long, env = "LICASH_HUB_CHAIN_POLL", default_value_t = 10,
          value_parser = clap::value_parser!(u64).range(1..))]
    chain_poll: u64,
    /// Index the silent payment tweaks of the chain's blocks, in
    /// `<data>/tweaks.sqlite`, and serve them to light wallets.
    #[arg(long, env = "LICASH_HUB_TWEAKS",
          value_parser = clap::builder::BoolishValueParser::new())]
    tweaks: bool,
    /// The first block to index the tweaks of, when the index is new
    /// [default: the tip]. Delete the index to start from another.
    #[arg(
        long,
        env = "LICASH_HUB_TWEAKS_FROM",
        value_name = "HEIGHT",
        requires = "tweaks"
    )]
    tweaks_from: Option<u32>,
    /// Open recovery contracts with wallets, kept in
    /// `<data>/openings.sqlite`, F funded and signed by the wallet of the
    /// node `--contracts-wallet` names, else `--chain`. On regtest under
    /// the mock authority, a contract there protecting nothing; on signet
    /// under the genuine programs; none elsewhere yet.
    #[arg(long, env = "LICASH_HUB_CONTRACTS",
          value_parser = clap::builder::BoolishValueParser::new())]
    contracts: bool,
    /// Fund and sign contracts with the wallet of the node at this URL, its
    /// JSON-RPC as `--chain` takes it, such as
    /// `http://host:port/wallet/NAME?cookie=PATH`: one apart from the chain
    /// followed, which may be an Esplora API. By default, `--chain`'s.
    #[arg(
        long = "contracts-wallet",
        value_name = "URL",
        env = "LICASH_HUB_CONTRACTS_WALLET",
        hide_env_values = true,
        requires = "contracts"
    )]
    contracts_wallet: Option<String>,
    /// Pay the hub's share of each new contract to a new address of the
    /// wallet of the node at this URL, as `--contracts-wallet` takes one,
    /// rather than of the wallet that funds it: a wallet without private
    /// keys watching a descriptor whose keys are offline, so that what
    /// contracts return at their end is out of this host's reach. Contracts
    /// open before keep the address they were signed with; no contract
    /// opens while this wallet gives no address.
    #[arg(
        long = "contracts-payout-wallet",
        value_name = "URL",
        env = "LICASH_HUB_CONTRACTS_PAYOUT_WALLET",
        hide_env_values = true,
        requires = "contracts"
    )]
    contracts_payout_wallet: Option<String>,
    /// Scale the prover's estimate of each proof by this as the hub admits
    /// contracts: it opens one only if its prover could prove an exit of
    /// every contract it holds at once, in an assert window. Above 1 for a
    /// prover slower than its benchmark; below 1 admits more contracts than
    /// it is sure to defend if their holders exit together.
    #[arg(
        long = "contracts-proof-scale",
        value_name = "FACTOR",
        env = "LICASH_HUB_CONTRACTS_PROOF_SCALE",
        default_value_t = 1.0,
        requires = "contracts"
    )]
    contracts_proof_scale: f64,
    /// Let holders choose a contract's cap up to this many sat, taken
    /// down to a size (2^n - 1 sat, 131 071 the least), and how long it
    /// lasts up to `--contracts-max-blocks`, besides the fixed terms
    /// (131 071 sat over 1 000 blocks, 1 912 on Mutinynet): a holder's
    /// deposit funds a contract of its own part by default, any larger one
    /// she asks the hub funding the rest of it, at `--contracts-rate`.
    /// Advertised as no more than the hub's wallet funds.
    #[arg(
        long = "contracts-max-cap",
        value_name = "SAT",
        env = "LICASH_HUB_CONTRACTS_MAX_CAP",
        default_value_t = 33_554_431,
        requires = "contracts"
    )]
    contracts_max_cap: u32,
    /// Offer the fixed terms only, at their price, with no interest:
    /// holders choose no cap or duration (`--contracts-max-cap` and the
    /// rates unused).
    #[arg(
        long = "contracts-fixed-only",
        env = "LICASH_HUB_CONTRACTS_FIXED_ONLY",
        value_parser = clap::builder::BoolishValueParser::new(),
        requires = "contracts"
    )]
    contracts_fixed_only: bool,
    /// The most blocks a contract a holder chooses lasts: the fixed
    /// terms' at least (1 912 on Mutinynet). By default a year of
    /// Bitcoin's blocks (about 18 days of Mutinynet's).
    #[arg(
        long = "contracts-max-blocks",
        value_name = "BLOCKS",
        env = "LICASH_HUB_CONTRACTS_MAX_BLOCKS",
        default_value_t = licash_api::YEAR_BLOCKS,
        requires = "contracts"
    )]
    contracts_max_blocks: u32,
    /// What a contract costs over the fixed price, in millionths of the
    /// part of its cap the hub funds for each year it lasts (52 560
    /// blocks, Mutinynet's 1 051 200): 200 000 is 20% a year, the price of
    /// the hub's own bitcoin locked. Its reserve and fee are not counted.
    #[arg(
        long = "contracts-rate",
        value_name = "PPM",
        env = "LICASH_HUB_CONTRACTS_RATE",
        default_value_t = 200_000,
        requires = "contracts"
    )]
    contracts_rate: u32,
    /// Likewise, of the part of its cap its holder funds herself: none
    /// by default, her own coin locked for her own notes.
    #[arg(
        long = "contracts-rate-funded",
        value_name = "PPM",
        env = "LICASH_HUB_CONTRACTS_RATE_FUNDED",
        default_value_t = 0,
        requires = "contracts"
    )]
    contracts_rate_funded: u32,
    /// The hub's fee for opening a contract, in sat, of its fixed terms
    /// and those chosen alike, besides the holder's reserve and the rate
    /// on its part: what it charges for what it brings. Past half its
    /// most contracts live, it doubles at each eighth more.
    #[arg(
        long = "contracts-fee",
        value_name = "SAT",
        env = "LICASH_HUB_CONTRACTS_FEE",
        default_value_t = licash_contracts::hub::terms::OPENING_FEE,
        requires = "contracts"
    )]
    contracts_fee: u64,
    /// The most contracts live at once, signed and not ended or under
    /// way: as many as the hub proves the exits of, all at once, within
    /// an assertion window, twice over. Past half of them its fee doubles
    /// at each eighth more, up to 16 times; at the most, it opens none.
    #[arg(
        long = "contracts-max-live",
        value_name = "N",
        env = "LICASH_HUB_CONTRACTS_MAX_LIVE",
        default_value_t = licash_contracts::hub::MAX_LIVE,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..),
        requires = "contracts"
    )]
    contracts_max_live: usize,
    /// Blocks of work the hub's statement reads on top of a holder's
    /// request's response, in the contracts it quotes from now on: the
    /// work a private chain must carry to fool a proof, so the more value
    /// its contracts protect, the more to ask. From the network's floor
    /// (1 on regtest, 6 on signet) to 144 more; the assertion window and
    /// the shortest contract grow as much, its prover's time unchanged.
    /// By default, the floor.
    #[arg(
        long = "contracts-work-depth",
        value_name = "BLOCKS",
        env = "LICASH_HUB_CONTRACTS_WORK_DEPTH",
        requires = "contracts"
    )]
    contracts_work_depth: Option<u32>,
    #[command(flatten)]
    witnesses: WitnessArgs,
}

/// Whom the hub writes each contract's one-time answers to before it
/// signs them: `--contracts-witnesses none`, or a set and its witnesses.
#[derive(clap::Args, Debug, Clone)]
struct WitnessArgs {
    /// `none`: keep each contract's one-time answers in `hub.sqlite` alone,
    /// on regtest or signet. A restore of it older than an answer, or a
    /// second copy of the hub, may then sign another, which gives the
    /// holder the hub's outputs. Refused on mainnet, and once its contracts
    /// are witnessed.
    #[arg(
        long = "contracts-witnesses",
        value_name = "none",
        env = "LICASH_HUB_CONTRACTS_WITNESSES",
        value_parser = ["none"],
        conflicts_with = "contracts_witness_set",
    )]
    contracts_witnesses: Option<String>,
    /// The id of the set of the hub's contract witnesses
    /// (`licash-witness init`), each named with `--contracts-witness`.
    #[arg(
        long = "contracts-witness-set",
        value_name = "SET_ID",
        env = "LICASH_HUB_CONTRACTS_WITNESS_SET",
        requires = "contracts_witness"
    )]
    contracts_witness_set: Option<String>,
    /// A witness of the set, as `https://host:port#<pin>`, its pin the
    /// SHA-256 of its certificate as `licash-witness show` prints it. The
    /// hub writes each one-time answer to every one before it signs it,
    /// and signs none unless all keep the same: two on mainnet at least,
    /// apart from the hub and from each other. Repeat, or separate with
    /// commas.
    #[arg(
        long = "contracts-witness",
        value_name = "URL#PIN",
        env = "LICASH_HUB_CONTRACTS_WITNESS",
        value_delimiter = ',',
        requires = "contracts_witness_set"
    )]
    contracts_witness: Vec<String>,
}

impl WitnessArgs {
    /// The witnesses named, with the hub's witness key of the seed at
    /// `seed`: none named is refused, never taken as `none`.
    fn witnesses(&self, seed: &Path) -> anyhow::Result<licash_contracts::hub::Witnesses> {
        use licash_contracts::hub::Witnesses;
        if self.contracts_witnesses.is_some() {
            return Ok(Witnesses::none());
        }
        let set = self.contracts_witness_set.as_deref().context(
            "contracts need witnesses: --contracts-witness-set and --contracts-witness, or \
             --contracts-witnesses none on regtest or signet",
        )?;
        let set = <[u8; 32]>::try_from(hex::decode(set).unwrap_or_default())
            .map_err(|_| anyhow::anyhow!("--contracts-witness-set: 32 bytes in hex"))?;
        let members = self
            .contracts_witness
            .iter()
            .map(|w| licash_witness::client::Client::parse(w))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let secret = licash_hub::witness_secret_of(seed).context("the hub's witness key")?;
        Witnesses::of(set, members, secret)
    }
}

impl Chain {
    /// The contract terms holders may choose, unless the operator offers
    /// the fixed terms only.
    fn range(&self) -> Option<licash_contracts::hub::terms::Range> {
        (!self.contracts_fixed_only).then_some(licash_contracts::hub::terms::Range {
            max_cap: self.contracts_max_cap,
            max_blocks: self.contracts_max_blocks,
            ppm_year: self.contracts_rate,
            ppm_year_funded: self.contracts_rate_funded,
        })
    }

    fn source(&self, policy: &Policy) -> anyhow::Result<Option<(Source, ChainProfile, Duration)>> {
        let Some(url) = &self.url else {
            return Ok(None);
        };
        anyhow::ensure!(
            self.chain_poll < policy.timing.max_lag,
            "--chain-poll must be below --max-lag"
        );
        let source = url.parse().context("--chain")?;
        let every = Duration::from_secs(self.chain_poll);
        Ok(Some((source, self.network, every)))
    }
}

/// The hub's announcement on Nostr, for wallets to discover it.
#[derive(Args)]
struct AnnounceArgs {
    /// Announce the hub on this Nostr relay, such as `wss://relay.example`.
    /// Repeat it, or separate relays with commas, for more. Needs
    /// `--announce-url` and `--chain`, whose network it announces.
    #[arg(
        long = "nostr-relay",
        value_name = "URL",
        env = "LICASH_HUB_NOSTR_RELAYS",
        value_delimiter = ','
    )]
    nostr_relays: Vec<String>,
    /// A URL wallets reach the hub at: `https://`, or an onion service's
    /// `http://`. Repeat it, up to 4 with `--onion`'s.
    #[arg(
        long = "announce-url",
        value_name = "URL",
        env = "LICASH_HUB_ANNOUNCE_URLS",
        value_delimiter = ','
    )]
    announce_urls: Vec<String>,
    /// The name the announcement shows.
    #[arg(long = "announce-name", env = "LICASH_HUB_ANNOUNCE_NAME")]
    announce_name: Option<String>,
    /// A Nostr relay of its wallets' mailboxes, named in the hub's info:
    /// where payers send its notes to their payees. Repeat it, or separate
    /// relays with commas, for more; the `--nostr-relay` relays by default.
    #[arg(
        long = "mailbox-relay",
        value_name = "URL",
        env = "LICASH_HUB_MAILBOX_RELAYS",
        value_delimiter = ',',
        value_parser = relay
    )]
    mailbox_relays: Vec<String>,
}

/// A relay's URL, `ws://` or `wss://`.
fn relay(url: &str) -> Result<String, String> {
    let host = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"));
    match host {
        Some(host) if !host.is_empty() => Ok(url.to_owned()),
        _ => Err("a relay is at a ws:// or wss:// URL".into()),
    }
}

impl AnnounceArgs {
    /// The relays of its wallets' mailboxes.
    fn mailboxes(&self) -> Vec<String> {
        let relays = match self.mailbox_relays.is_empty() {
            true => &self.nostr_relays,
            false => &self.mailbox_relays,
        };
        relays.iter().filter(|r| !r.is_empty()).cloned().collect()
    }

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
    let announcement = Announcement {
        urls: urls.to_vec(),
        network: String::new(),
        name: None,
    };
    announcement.check()
}

/// Announce through `tor`, and at `onion`'s URL too, if the service
/// announces.
fn announce_over(
    announcing: &mut Option<Announcing>,
    tor: &Tor,
    onion: Option<&Onion>,
) -> anyhow::Result<()> {
    let Some(announcing) = announcing else {
        return Ok(());
    };
    announcing.route = Route::Tor(tor.clone());
    if let Some(onion) = onion {
        announcing.urls.push(onion.url().to_owned());
        check(&announcing.urls).context("--onion")?;
    }
    Ok(())
}

/// The hub's announcement: the relays, how it reaches them, and the URLs
/// and name it announces.
#[derive(Clone)]
struct Announcing {
    relays: Vec<String>,
    route: Route,
    urls: Vec<String>,
    name: Option<String>,
}

/// The fee a hub charges on everything unless told otherwise: a sat and a
/// hundredth of a percent of what moves.
const FEE: Fee = Fee { base: 1, ppm: 100 };

/// And, on a spend or a branch of a lock, a tenth of a sat for each note
/// made for others than the hub.
const OUTPUT_FEE_MSAT: u64 = 100;

/// What the hub charges and the locks it admits.
#[derive(Args)]
struct PolicyArgs {
    /// The fee on each spend, in the smallest unit.
    #[arg(long, env = "LICASH_HUB_SPEND_FEE_BASE", default_value_t = FEE.base)]
    spend_fee_base: u64,
    /// The fee on each spend, in parts per million of its inputs.
    #[arg(long, env = "LICASH_HUB_SPEND_FEE_PPM", default_value_t = FEE.ppm, value_parser = ppm())]
    spend_fee_ppm: u64,
    /// The fee in a lock's pay branch, in the smallest unit.
    #[arg(long, env = "LICASH_HUB_LOCK_FEE_BASE", default_value_t = FEE.base)]
    lock_fee_base: u64,
    /// The fee in a lock's pay branch, in parts per million of its inputs.
    #[arg(long, env = "LICASH_HUB_LOCK_FEE_PPM", default_value_t = FEE.ppm, value_parser = ppm())]
    lock_fee_ppm: u64,
    /// The fee in a lock's refund branch, in the smallest unit.
    #[arg(long, env = "LICASH_HUB_REFUND_FEE_BASE", default_value_t = FEE.base)]
    refund_fee_base: u64,
    /// The fee in a lock's refund branch, in parts per million of its inputs.
    #[arg(long, env = "LICASH_HUB_REFUND_FEE_PPM", default_value_t = FEE.ppm, value_parser = ppm())]
    refund_fee_ppm: u64,
    /// The fee on each note a spend, or a branch of a lock, makes for
    /// others than the hub, in thousandths of the smallest unit: the sum
    /// is rounded to the nearest unit.
    #[arg(long, env = "LICASH_HUB_OUTPUT_FEE_MSAT", default_value_t = OUTPUT_FEE_MSAT)]
    output_fee_msat: u64,
    /// A lock's expiry, depth and reaction fit within this many blocks of
    /// the scanned tip: how long a lock lives at most. Swap providers read
    /// it as the hub's response window too: with --contracts, the hub
    /// refuses to start with one below its contracts' response window.
    #[arg(long, env = "LICASH_HUB_LOCK_WINDOW", default_value_t = Timing::default().window)]
    lock_window: u32,
    /// Blocks the hub needs to produce and confirm a response.
    #[arg(long, env = "LICASH_HUB_LOCK_REACTION", default_value_t = Timing::default().reaction)]
    lock_reaction: u32,
    /// Least activation depth of a lock. Keep it above 1 on mainnet.
    #[arg(long, env = "LICASH_HUB_LOCK_MIN_DEPTH", default_value_t = Timing::default().min_depth)]
    lock_min_depth: u32,
    /// Blocks from its checkpoint within which a lock is decided.
    #[arg(long, env = "LICASH_HUB_LOCK_MAX_HEADERS", default_value_t = Timing::default().max_headers)]
    lock_max_headers: u32,
    /// Confirmations of a block before it becomes a checkpoint.
    #[arg(long, env = "LICASH_HUB_CHECKPOINT_BURY", default_value_t = Timing::default().bury)]
    checkpoint_bury: u32,
    /// Seconds after the scan last reached the tip that the hub stops
    /// admitting locks.
    #[arg(long, env = "LICASH_HUB_MAX_LAG", default_value_t = Timing::default().max_lag)]
    max_lag: u64,
}

/// The hub's Lightning gateway, over an LND node.
#[derive(Args)]
struct LightningArgs {
    /// Run a Lightning gateway over the LND REST API at this URL, such as
    /// `https://127.0.0.1:8080`.
    #[arg(long, value_name = "URL", env = "LICASH_HUB_LND")]
    lnd: Option<String>,
    /// The macaroon the gateway calls LND with: it pays, and makes, settles
    /// and cancels invoices.
    #[arg(
        long,
        value_name = "FILE",
        env = "LICASH_HUB_LND_MACAROON",
        requires = "lnd"
    )]
    lnd_macaroon: Option<PathBuf>,
    /// LND's TLS certificate, pinned. Without it, the URL's certificate
    /// must validate against the system's roots.
    #[arg(
        long,
        value_name = "FILE",
        env = "LICASH_HUB_LND_CERT",
        requires = "lnd"
    )]
    lnd_cert: Option<PathBuf>,
    /// The fee on each invoice paid, routing fees included, in satoshis.
    #[arg(long, env = "LICASH_HUB_LN_PAY_FEE_BASE", default_value_t = Config::default().pay.base)]
    ln_pay_fee_base: u64,
    /// The fee on each invoice paid, in parts per million of its amount.
    #[arg(long, env = "LICASH_HUB_LN_PAY_FEE_PPM", default_value_t = Config::default().pay.ppm,
          value_parser = ppm())]
    ln_pay_fee_ppm: u64,
    /// The fee on each payment received, in satoshis.
    #[arg(long, env = "LICASH_HUB_LN_RECEIVE_FEE_BASE", default_value_t = FEE.base)]
    ln_receive_fee_base: u64,
    /// The fee on each payment received, in parts per million.
    #[arg(long, env = "LICASH_HUB_LN_RECEIVE_FEE_PPM", default_value_t = FEE.ppm, value_parser = ppm())]
    ln_receive_fee_ppm: u64,
    /// The largest invoice paid, in satoshis.
    #[arg(long, env = "LICASH_HUB_LN_MAX_PAY", default_value_t = Config::default().max_pay)]
    ln_max_pay: u64,
    /// The most paid over Lightning in any 24 hours, in satoshis, the
    /// gateway's fee in it: past it invoices are refused, their locks
    /// refunded, and the operator alerted. It bounds what a thief of the
    /// hub's seed takes over Lightning in a day. Without it, no limit.
    #[arg(long, env = "LICASH_HUB_LN_MAX_PAY_DAY", value_name = "SAT")]
    ln_max_pay_day: Option<u64>,
    /// The least received, in satoshis.
    #[arg(long, env = "LICASH_HUB_LN_MIN_RECEIVE", default_value_t = Config::default().min_receive)]
    ln_min_receive: u64,
    /// The most received, in satoshis.
    #[arg(long, env = "LICASH_HUB_LN_MAX_RECEIVE", default_value_t = Config::default().max_receive)]
    ln_max_receive: u64,
    /// The most Lightning receipts open or locked at once.
    #[arg(long, env = "LICASH_HUB_LN_MAX_RECEIPTS", default_value_t = Config::default().max_receipts)]
    ln_max_receipts: u32,
    /// Blocks between the end of a payment's route timelock and the
    /// expiry of the lock paying for it.
    #[arg(long, env = "LICASH_HUB_LN_PAY_SLACK", default_value_t = Config::default().pay_slack)]
    ln_pay_slack: u32,
    /// LND's `holdexpirydelta`: blocks before an HTLC's expiry at which
    /// LND cancels it while held.
    #[arg(long, env = "LICASH_HUB_LN_HOLD_DELTA", default_value_t = Config::default().hold_delta)]
    ln_hold_delta: u32,
    /// Blocks the gateway may be down while a payment received is locked.
    #[arg(long, env = "LICASH_HUB_LN_DOWNTIME", default_value_t = Config::default().downtime)]
    ln_downtime: u32,
    /// Blocks a payment received stays locked to its payee.
    #[arg(long, env = "LICASH_HUB_LN_RECEIVE_BLOCKS", default_value_t = Config::default().receive_blocks)]
    ln_receive_blocks: u32,
    /// Seconds an invoice to receive stays payable.
    #[arg(long, env = "LICASH_HUB_LN_INVOICE_EXPIRY", default_value_t = Config::default().invoice_expiry)]
    ln_invoice_expiry: u64,
    /// Seconds LND tries to route a payment.
    #[arg(long, env = "LICASH_HUB_LN_PAY_TIMEOUT", default_value_t = Config::default().pay_timeout)]
    ln_pay_timeout: u32,
}

impl LightningArgs {
    /// The node and the gateway's configuration, if it runs one.
    fn gateway(&self) -> anyhow::Result<Option<(Lnd, Config)>> {
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
        let lnd = Lnd::new(url, &macaroon, cert.as_deref()).context("--lnd")?;
        let fee = |base, ppm| Fee { base, ppm };
        let config = Config {
            pay: fee(self.ln_pay_fee_base, self.ln_pay_fee_ppm),
            receive: fee(self.ln_receive_fee_base, self.ln_receive_fee_ppm),
            max_pay: self.ln_max_pay,
            max_pay_day: self.ln_max_pay_day,
            min_receive: self.ln_min_receive,
            max_receive: self.ln_max_receive,
            max_receipts: self.ln_max_receipts,
            pay_slack: self.ln_pay_slack,
            hold_delta: self.ln_hold_delta,
            downtime: self.ln_downtime,
            receive_blocks: self.ln_receive_blocks,
            invoice_expiry: self.ln_invoice_expiry,
            pay_timeout: self.ln_pay_timeout,
            ..Config::default()
        };
        Ok(Some((lnd, config)))
    }
}

/// The hub's deposits on Bitcoin.
#[derive(Args)]
struct DepositArgs {
    /// Take deposits on Bitcoin, claiming their coins to this address:
    /// a payment confirmed locks the hub's own notes to its payer.
    #[arg(long, value_name = "ADDRESS", env = "LICASH_HUB_DEPOSIT_SWEEP_ADDRESS")]
    deposit_sweep_address: Option<String>,
    /// The fee on each deposit, in satoshis, paid on top of its notes.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_FEE_BASE", default_value_t = deposits().fee.base)]
    deposit_fee_base: u64,
    /// The fee on each deposit, in parts per million of its notes.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_FEE_PPM", default_value_t = deposits().fee.ppm,
          value_parser = ppm())]
    deposit_fee_ppm: u64,
    /// The least notes a deposit locks, in satoshis.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_MIN", default_value_t = deposits().min)]
    deposit_min: u64,
    /// The most notes a deposit locks, in satoshis.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_MAX", default_value_t = deposits().max)]
    deposit_max: u64,
    /// Confirmations a deposit's payment needs.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_DEPTH", default_value_t = deposits().depth)]
    deposit_depth: u32,
    /// Blocks from a request within which its payment must confirm.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_WINDOW", default_value_t = deposits().window)]
    deposit_window: u32,
    /// Blocks a deposit's notes stay locked to its payer.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_LOCK_BLOCKS", default_value_t = deposits().lock_blocks)]
    deposit_lock_blocks: u32,
    /// Blocks the hub may be down while a deposit is locked.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_DOWNTIME", default_value_t = deposits().downtime)]
    deposit_downtime: u32,
    /// Blocks the hub's claim of a deposit has to confirm in before its
    /// payer may take the coins back.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_SWEEP_BLOCKS", default_value_t = deposits().sweep_blocks)]
    deposit_sweep_blocks: u32,
    /// The least fee rate of claims, in sat/vB, also used while the chain
    /// estimates none.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_MIN_FEE_RATE",
          default_value_t = deposits().min_fee_rate.to_sat_per_vb_ceil(),
          value_parser = clap::value_parser!(u64).range(1..=10_000))]
    deposit_min_fee_rate: u64,
    /// The most deposits asked and not yet paid at once: new ones are
    /// refused past it, never retries or those under way.
    #[arg(long, env = "LICASH_HUB_DEPOSIT_MAX_OPEN", default_value_t = deposits().max_open)]
    deposit_max_open: u32,
}

/// The defaults of deposits.
fn deposits() -> deposit::Config {
    deposit::Config::new(bitcoin::ScriptBuf::new())
}

impl DepositArgs {
    /// The gateway's configuration, if the hub takes deposits on `profile`.
    fn config(&self, profile: ChainProfile) -> anyhow::Result<Option<deposit::Config>> {
        let Some(address) = &self.deposit_sweep_address else {
            return Ok(None);
        };
        let network = licash_chain_client::network(profile);
        let address = address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .context("--deposit-sweep-address")?
            .require_network(network)
            .with_context(|| format!("--deposit-sweep-address: not an address on {profile}"))?;
        let min_fee_rate = bitcoin::FeeRate::from_sat_per_vb(self.deposit_min_fee_rate)
            .context("--deposit-min-fee-rate: too high")?;
        Ok(Some(deposit::Config {
            fee: Fee {
                base: self.deposit_fee_base,
                ppm: self.deposit_fee_ppm,
            },
            min: self.deposit_min,
            max: self.deposit_max,
            depth: self.deposit_depth,
            window: self.deposit_window,
            lock_blocks: self.deposit_lock_blocks,
            downtime: self.deposit_downtime,
            sweep_blocks: self.deposit_sweep_blocks,
            min_fee_rate,
            max_open: self.deposit_max_open,
            ..deposit::Config::new(address.script_pubkey())
        }))
    }
}

fn ppm() -> clap::builder::RangedU64ValueParser<u64> {
    clap::value_parser!(u64).range(0..=1_000_000)
}

/// The swaps into the hub, which it provides, locking notes it issues.
#[derive(Args)]
struct SwapsArgs {
    /// Provide the swaps into the hub from the hubs of `--swaps-from`: the
    /// hub locks notes it issues to the client, against the client's lock
    /// there. The provider's wallet, which claims those locks, and its
    /// swaps are kept in `<data>/swaps`, made on the first start. Needs
    /// `--chain`.
    #[arg(long, env = "LICASH_HUB_SWAPS",
          value_parser = clap::builder::BoolishValueParser::new())]
    swaps: bool,
    /// Take swaps from the hub at URL while the provider holds, or is owed
    /// by the swaps under way, at most CAP of its notes: `URL=CAP`. Repeat
    /// it, or separate them with commas, for more hubs.
    #[arg(
        long = "swaps-from",
        value_name = "URL=CAP",
        env = "LICASH_HUB_SWAPS_FROM",
        value_delimiter = ','
    )]
    swaps_from: Vec<String>,
    /// Reach the hubs of `--swaps-from`, onion services among them, through
    /// a Tor client of the hub's own (that of `--onion`, its state in
    /// `<data>/tor`) rather than directly.
    #[arg(long, env = "LICASH_HUB_SWAPS_TOR",
          value_parser = clap::builder::BoolishValueParser::new())]
    swaps_tor: bool,
    /// The fee on each swap, in the smallest unit.
    #[arg(long, env = "LICASH_HUB_SWAPS_FEE_BASE",
          default_value_t = SwapsConfig::default().fee.base)]
    swaps_fee_base: u64,
    /// The fee on each swap, in parts per million of its amount.
    #[arg(long, env = "LICASH_HUB_SWAPS_FEE_PPM",
          default_value_t = SwapsConfig::default().fee.ppm, value_parser = ppm())]
    swaps_fee_ppm: u64,
    /// The least swapped at once.
    #[arg(long, env = "LICASH_HUB_SWAPS_MIN", default_value_t = SwapsConfig::default().min)]
    swaps_min: u64,
    /// The most swapped at once.
    #[arg(long, env = "LICASH_HUB_SWAPS_MAX", default_value_t = SwapsConfig::default().max)]
    swaps_max: u64,
    /// Blocks the provider needs to claim the client's lock once it holds
    /// the preimage.
    #[arg(long, env = "LICASH_HUB_SWAPS_MARGIN",
          default_value_t = SwapsConfig::default().margin)]
    swaps_margin: u32,
    /// Blocks within which a client's activation of the hub's lock on
    /// Bitcoin confirms: the hub's lock expires that, the margin and two
    /// blocks before the client's.
    #[arg(long, env = "LICASH_HUB_SWAPS_CONFIRM",
          default_value_t = SwapsConfig::default().confirm,
          value_parser = clap::value_parser!(u32).range(1..))]
    swaps_confirm: u32,
    /// Take the notes of the hubs of `--swaps-from` in with no contract
    /// protecting them there: reckless, as a hub that withholds them keeps
    /// them. By default the provider takes in at each only what its
    /// contracts there protect, the first opened by the operator with
    /// `licash-wallet --wallet <data>/swaps/wallet.sqlite open-contract`,
    /// and keeps them: replaced before they end, forced closed at their
    /// safe deadline if needed. The hub's own notes need none.
    #[arg(long, env = "LICASH_HUB_SWAPS_NO_CONTRACTS",
          value_parser = clap::builder::BoolishValueParser::new())]
    swaps_no_contracts: bool,
    /// Days before a contract's safe deadline to open its successor.
    #[arg(
        long,
        env = "LICASH_HUB_SWAPS_CONTRACT_SUCCESSOR_DAYS",
        default_value_t = 14
    )]
    swaps_contract_successor_days: u32,
    /// Days kept for a forced close to play out in (the exit margin),
    /// before each contract's last request height: its safe deadline comes
    /// a day earlier.
    #[arg(
        long,
        // As named when it was the proof margin, for deployments that set it.
        alias = "swaps-contract-proof-days",
        env = "LICASH_HUB_SWAPS_CONTRACT_PROOF_DAYS",
        default_value_t = 14
    )]
    swaps_contract_exit_days: u32,
    /// The most a successor costs, in sat [default: what the contract it
    /// replaces cost, and a quarter].
    #[arg(long, env = "LICASH_HUB_SWAPS_CONTRACT_MAX_PRICE")]
    swaps_contract_max_price: Option<u64>,
    /// Pay out to the provider's own address on Bitcoin, through the swap
    /// provider at URL, what a contract that could not be replaced leaves
    /// unprotected [default: only take no more in there].
    #[arg(long, value_name = "URL", env = "LICASH_HUB_SWAPS_DRAIN_VIA")]
    swaps_drain_via: Option<String>,
}

impl SwapsArgs {
    /// The provider's terms, and the hubs it takes swaps from with their
    /// caps, if the hub provides swaps.
    fn terms(&self) -> anyhow::Result<Option<(SwapsConfig, Vec<Capped>)>> {
        let from: Vec<Capped> = self
            .swaps_from
            .iter()
            .filter(|f| !f.trim().is_empty())
            .map(|f| capped(f).with_context(|| format!("--swaps-from {f}")))
            .collect::<anyhow::Result<_>>()?;
        if !self.swaps {
            anyhow::ensure!(from.is_empty(), "--swaps-from needs --swaps");
            anyhow::ensure!(!self.swaps_tor, "--swaps-tor needs --swaps");
            anyhow::ensure!(
                !self.swaps_no_contracts,
                "--swaps-no-contracts needs --swaps"
            );
            anyhow::ensure!(
                self.swaps_drain_via.is_none(),
                "--swaps-drain-via needs --swaps"
            );
            return Ok(None);
        }
        anyhow::ensure!(
            self.swaps_min <= self.swaps_max,
            "--swaps-min must not exceed --swaps-max"
        );
        anyhow::ensure!(
            self.swaps_margin > licash_wallet::CLAIM_MARGIN + 2,
            "--swaps-margin must exceed {}",
            licash_wallet::CLAIM_MARGIN + 2
        );
        let config = SwapsConfig {
            fee: Fee {
                base: self.swaps_fee_base,
                ppm: self.swaps_fee_ppm,
            },
            min: self.swaps_min,
            max: self.swaps_max,
            margin: self.swaps_margin,
            confirm: self.swaps_confirm,
        };
        Ok(Some((config, from)))
    }

    /// Whether contracts protect the notes the provider takes in from the
    /// hubs `from`, on `network`: refused where none opens, unless
    /// --swaps-no-contracts runs it unprotected. None needed from no hub.
    fn protected(&self, network: ChainProfile, from: &[Capped]) -> anyhow::Result<bool> {
        if from.is_empty() {
            return Ok(false);
        }
        if self.swaps_no_contracts {
            tracing::warn!(
                "--swaps-no-contracts: no contract protects the notes the hub takes in from \
                 the hubs of --swaps-from, which a hub that withholds them keeps. Reckless \
                 outside of tests"
            );
            return Ok(false);
        }
        licash_contracts::trust(network).with_context(|| {
            format!(
                "contracts protect the notes taken in from the hubs of --swaps-from, and none \
                 opens on {network}: --swaps-no-contracts runs it unprotected, recklessly"
            )
        })?;
        Ok(true)
    }

    /// The keeper of the contracts of `provider`, whose files are in `dir`,
    /// on `chain`, protecting the notes of the hubs `from`.
    fn keeper(
        &self,
        provider: &Arc<Provider<Http>>,
        chain: Source,
        dir: &Path,
        from: &[Capped],
    ) -> Keeper<Http> {
        let wallet = dir.join("wallet.sqlite");
        let hint = format!(
            "licash-wallet --wallet {} open-contract {{hub}} --chain CHAIN",
            wallet.display()
        );
        let settings = keeper::Settings::new(
            self.swaps_contract_exit_days,
            self.swaps_contract_successor_days,
            hint,
        );
        let settings = keeper::Settings {
            hubs: Some(from.iter().map(|(url, _)| url.clone()).collect()),
            max_price: self.swaps_contract_max_price,
            drain_via: self.swaps_drain_via.clone(),
            // Nothing else looks for the coins of the swaps' wallet.
            scan: true,
            ..settings
        };
        let chain = licash_contracts::holder::Node(chain);
        Keeper::new(provider.clone(), chain, wallet.to_owned(), settings)
    }
}

/// A hub swapped from, by URL, and the most of its notes the provider
/// holds.
type Capped = (String, u64);

/// A hub's URL and the cap on its notes, of `URL=CAP`.
fn capped(arg: &str) -> anyhow::Result<Capped> {
    let (url, cap) = arg.rsplit_once('=').context("not URL=CAP")?;
    let url = url.trim().trim_end_matches('/');
    anyhow::ensure!(
        url.starts_with("http://") || url.starts_with("https://"),
        "not a hub URL: {url}"
    );
    let cap = cap.trim().parse().with_context(|| format!("cap {cap}"))?;
    Ok((url.to_owned(), cap))
}

impl PolicyArgs {
    fn policy(&self) -> Policy {
        let fee = |base, ppm| Fee { base, ppm };
        Policy {
            spend: fee(self.spend_fee_base, self.spend_fee_ppm),
            lock: fee(self.lock_fee_base, self.lock_fee_ppm),
            refund: fee(self.refund_fee_base, self.refund_fee_ppm),
            output_msat: self.output_fee_msat,
            timing: Timing {
                window: self.lock_window,
                reaction: self.lock_reaction,
                min_depth: self.lock_min_depth,
                max_headers: self.lock_max_headers,
                bury: self.checkpoint_bury,
                max_lag: self.max_lag,
            },
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Log {
    Text,
    Json,
}

/// Who the hub admits deposits and receipts by, behind a proxy.
#[derive(Args)]
struct IngressArgs {
    /// A reverse proxy in front of `--listen` whose `X-Forwarded-For`
    /// the hub believes, as an address or a CIDR block; repeat (or
    /// separate by commas) for more. Deposits and receipts asked and
    /// not paid are bounded by client address: without it, every
    /// client behind the proxy is the proxy's one address. The proxy
    /// must replace the header its clients send, and nothing else may
    /// reach `--listen`.
    #[arg(long = "trusted-proxy", env = "LICASH_HUB_TRUSTED_PROXY",
          value_name = "CIDR", value_delimiter = ',',
          value_parser = licash_serve::trusted_proxy)]
    trusted_proxies: Vec<ipnet::IpNet>,
}

#[derive(Subcommand)]
enum Command {
    /// Create the hub: a fresh seed and an empty ledger. Never replaces
    /// either.
    Init {
        /// The largest denomination, as a power of two.
        #[arg(long, default_value_t = 40, value_parser = clap::value_parser!(u32).range(0..=licash_hub::MAX_POW as i64))]
        max_pow: u32,
    },
    /// Serve the hub's HTTP API until SIGINT or SIGTERM.
    Run {
        #[arg(long, env = "LICASH_HUB_LISTEN", default_value = "127.0.0.1:8338")]
        listen: SocketAddr,
        #[command(flatten)]
        ingress: Box<IngressArgs>,
        #[command(flatten)]
        policy: PolicyArgs,
        #[command(flatten)]
        chain: Box<Chain>,
        #[command(flatten)]
        notify: Notify,
        #[command(flatten)]
        lightning: Box<LightningArgs>,
        #[command(flatten)]
        deposits: Box<DepositArgs>,
        #[command(flatten)]
        announce: Box<AnnounceArgs>,
        #[command(flatten)]
        swaps: Box<SwapsArgs>,
        /// Also serve the API as an onion service of a Tor client of the
        /// hub's own, at the same address on every start (its key in
        /// `<data>/tor`), and announce it, reaching relays through Tor too.
        #[arg(long, env = "LICASH_HUB_ONION",
              value_parser = clap::builder::BoolishValueParser::new())]
        onion: bool,
        /// Whether `--onion`'s service asks its clients for a proof of work
        /// while it is under load, which prices each new circuit to it.
        #[arg(long, env = "LICASH_HUB_ONION_POW", default_value_t = true,
              action = clap::ArgAction::Set,
              value_parser = clap::builder::BoolishValueParser::new())]
        onion_pow: bool,
        /// Run even though own locks of the hub, which it may yet pay, are
        /// backed by no deposit, Lightning receipt or swap it keeps, as
        /// once such a file was restored older than `hub.sqlite`: alerting
        /// the operator, rather than refusing to start.
        #[arg(long, env = "LICASH_HUB_ALLOW_UNBACKED_LOCKS",
              value_parser = clap::builder::BoolishValueParser::new())]
        allow_unbacked_locks: bool,
        /// Notify only of these kinds of event [default: all but locked].
        #[arg(long, value_name = "KIND", env = "LICASH_HUB_NOTIFY_KINDS", value_delimiter = ',',
              value_parser = clap::builder::PossibleValuesParser::new(notify::KINDS))]
        notify_kinds: Vec<String>,
        /// Only answer the disputes of the contracts open, as a standby
        /// copy of the hub: no API but `/health`, no new contract, fold,
        /// Lightning, deposit, swap, announcement nor onion service. As a
        /// copy runs once another took its contracts over
        /// (`contracts-takeover`). Needs `--contracts` and witnesses.
        #[arg(long, env = "LICASH_HUB_RESPOND_ONLY",
              value_parser = clap::builder::BoolishValueParser::new())]
        respond_only: bool,
    },
    /// Send a test notification to each `--notify` target. Fails if any
    /// target does not take it.
    TestNotify {
        #[command(flatten)]
        notify: Notify,
    },
    /// Counts over the ledger, beside the running hub or without it.
    Status {
        #[arg(long)]
        json: bool,
        /// Include internal note and event counts.
        #[arg(long)]
        details: bool,
    },
    /// The spends the ledger retired notes for that a contract's dispute
    /// cannot cite, read-only and of a ledger of this release or the one
    /// before: a claim on Bitcoin of any of their notes goes unanswered and
    /// is paid whole. Run before closing the contracts of an earlier
    /// release. Fails if it finds any.
    Audit {
        #[arg(long)]
        json: bool,
        /// The notes of one spend the contracts' statement reads: their
        /// Base's `max_authorizations`, as quoted.
        #[arg(long, default_value_t = 128)]
        max_authorizations: u64,
    },
    /// An interactive dashboard of the hub's records, beside the running
    /// hub or without it: payments, fees, reserves, contracts, privacy and
    /// health, over a range (30 days at first) against the one before.
    Dashboard {
        #[command(flatten)]
        dashboard: licash_dashboard::Args,
        /// The running hub's URL, asked for its health [default: http://
        /// and `LICASH_HUB_LISTEN`, or 127.0.0.1:8338].
        #[arg(long)]
        url: Option<String>,
        /// The hub's network, for the time blocks take: bitcoin, regtest,
        /// signet or mutinynet.
        #[arg(long, env = "LICASH_HUB_NETWORK", default_value_t = ChainProfile::Core30Mainnet)]
        network: ChainProfile,
    },
    /// Resume the Lightning payments out the hub paused on finding notes
    /// retired that its ledger never issued, beside the running hub (which
    /// resumes within half a minute) or without it. What its ledger shows
    /// now is taken as known: more found later pause again. Look at the
    /// alert and the ledger first: such notes were made with the hub's
    /// seed outside it, unless its ledger was restored from an older copy.
    ResumePayouts,
    /// The x-only public key of the hub's witness key, of its seed, in hex:
    /// what `licash-witness init --hub-key` takes.
    WitnessKey,
    /// Give the hub's contract witnesses, all new, the contracts it opened
    /// before it had them, with the hub stopped: each enrolled, each answer
    /// it signed kept as it signed it, and each it may have signed with
    /// what it no longer knows (marked as about to be signed, nothing
    /// pinned) kept never to be signed. Then the witnesses are sealed and
    /// `hub.sqlite` bound to their set. Run again if it fails; refused on
    /// mainnet, which never runs contracts without witnesses.
    ContractsWitnessImport {
        #[command(flatten)]
        witnesses: WitnessArgs,
        /// The hub's network: bitcoin, regtest, signet or mutinynet.
        #[arg(long, env = "LICASH_HUB_NETWORK")]
        network: ChainProfile,
    },
    /// Take the contracts over for this copy of the hub, on the copy that
    /// is to open contracts from now on: the next epoch, kept by every
    /// witness, naming this copy (its id in `<data>/contracts-instance`,
    /// never to be backed up or copied). Every other copy then opens no
    /// contract and serves no wallet, and answers the disputes of those
    /// open, as each may. Fails, taking nothing, where a witness cannot be
    /// reached; where one is of an earlier release, upgrade it and run
    /// again.
    ContractsTakeover {
        #[command(flatten)]
        witnesses: WitnessArgs,
    },
    /// The hub's events as JSON lines, oldest first.
    Events {
        /// Only events after this sequence number.
        #[arg(long, default_value_t = 0)]
        after: u64,
        /// At most this many events, or per poll with `--follow`.
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
    let db = cli.data.join("hub.sqlite");
    // Whatever the command: files of an earlier layout are never read, nor
    // replaced.
    licash_store::refuse_legacy(
        &cli.data,
        &[
            "deposits.sqlite",
            "lightning.sqlite",
            "inbox.sqlite",
            "openings.sqlite",
            "responses.sqlite",
        ],
        "hub.sqlite",
    )?;
    let seed = cli.seed.unwrap_or_else(|| cli.data.join("seed"));
    match cli.command {
        Command::Init { max_pow } => init(&cli.data, &seed, &db, max_pow, cli.log),
        Command::Run {
            listen,
            ingress,
            policy,
            chain,
            notify,
            lightning,
            deposits,
            announce,
            swaps,
            onion,
            onion_pow,
            allow_unbacked_locks,
            notify_kinds,
            respond_only,
        } => {
            let respond_only = match responding_only(respond_only, &chain, &seed, &cli.data)? {
                Some(why) => {
                    tracing::warn!("responding only: {why}");
                    true
                }
                None => false,
            };
            let policy = policy.policy();
            let lock_window = policy.timing.window;
            let (indexing, tweaks_from) = (chain.tweaks, chain.tweaks_from);
            let contracting = chain.contracts;
            let response_poll = Duration::from_secs(chain.chain_poll);
            let range = chain.range();
            let max_live = chain.contracts_max_live;
            let proof_scale = chain.contracts_proof_scale;
            let work_depth = chain.contracts_work_depth;
            let witnessing = chain.witnesses.clone();
            let opening_fee = chain.contracts_fee;
            let wallet = match (&chain.contracts_wallet, &chain.url) {
                (Some(url), _) => Some(url.parse::<Source>().context("--contracts-wallet")?),
                (None, Some(url)) if contracting && url.starts_with("esplora+") => anyhow::bail!(
                    "opening contracts (--contracts) on an Esplora API needs --contracts-wallet, a node's JSON-RPC"
                ),
                (None, _) => None,
            };
            let payout_wallet = match &chain.contracts_payout_wallet {
                Some(url) => {
                    anyhow::ensure!(
                        !url.trim_start().starts_with("esplora+"),
                        "--contracts-payout-wallet: a node's JSON-RPC, not an Esplora API"
                    );
                    Some(url.parse::<Source>().context("--contracts-payout-wallet")?)
                }
                None => None,
            };
            let chain = chain.source(&policy)?;
            anyhow::ensure!(
                !indexing || chain.is_some(),
                "indexing tweaks (--tweaks) needs --chain"
            );
            anyhow::ensure!(
                !contracting || chain.is_some(),
                "opening contracts (--contracts) needs --chain"
            );
            let lightning = match respond_only {
                true => None,
                false => lightning.gateway()?,
            };
            anyhow::ensure!(
                lightning.is_none() || chain.is_some(),
                "a Lightning gateway (--lnd) needs --chain"
            );
            let depositing = match &chain {
                Some(_) if respond_only => None,
                // Polling the chain as often as the hub follows it.
                Some((source, profile, every)) => deposits.config(*profile)?.map(|config| {
                    let config = deposit::Config {
                        poll: *every,
                        ..config
                    };
                    (source.clone(), *profile, config)
                }),
                None => {
                    anyhow::ensure!(
                        deposits.deposit_sweep_address.is_none(),
                        "taking deposits (--deposit-sweep-address) needs --chain"
                    );
                    None
                }
            };
            let relays = announce.mailboxes();
            let onion = onion && !respond_only;
            let mut announcing = match respond_only {
                true => None,
                false => (*announce).announcing(onion)?,
            };
            anyhow::ensure!(
                announcing.is_none() || chain.is_some(),
                "announcing on Nostr (--nostr-relay) needs --chain"
            );
            let swapping = match respond_only {
                true => None,
                false => swaps.terms()?,
            };
            let swaps_tor = swaps.swaps_tor && !respond_only;
            let indexing = indexing && !respond_only;
            anyhow::ensure!(
                swapping.is_none() || chain.is_some(),
                "providing swaps (--swaps) needs --chain"
            );
            let swaps_protected = match (&swapping, &chain) {
                (Some((_, from)), Some((_, profile, _))) => swaps.protected(*profile, from)?,
                _ => false,
            };
            let swaps_dir = cli.data.join("swaps");
            if swapping.is_none() && !respond_only {
                check_idle(&swaps_dir)?;
            }
            let targets = notify.targets()?;
            let swaps_targets = targets.clone();
            // Before the hub opens, so that new targets hear of its start.
            let notifier = if targets.is_empty() {
                None
            } else {
                let cursors = cli.data.join("notify.json");
                let notifier = Notifier::new(&db, &notify.name, targets, &cursors, notify_kinds)
                    .context("set up notifications")?;
                Some(notifier)
            };
            let hub = Hub::open(&seed, &db, policy).context("open the hub")?;
            let hub = Arc::new(hub);
            if respond_only {
                // What its gateways and swaps owe is collected by the copy
                // that leads, if one does: told, as no one here does.
                let owed = [
                    check_idle(&swaps_dir),
                    check_gateway_idle(&hub, &db, false),
                    check_gateway_idle(&hub, &db, true),
                ];
                for e in owed.into_iter().filter_map(Result::err) {
                    let message = format!(
                        "responding only, this copy collects nothing it is owed: {e:#}. The copy \
                         that leads must run its gateways and swaps before their locks expire"
                    );
                    tracing::error!("{message}");
                    if let Err(e) = hub.alert(&message) {
                        tracing::error!("notifying an alert: {e:#}");
                    }
                }
            } else {
                if lightning.is_none() {
                    check_gateway_idle(&hub, &db, false)?;
                }
                if depositing.is_none() {
                    check_gateway_idle(&hub, &db, true)?;
                }
            }
            // Paused as it was when the hub stopped, before anything is paid.
            let guard = payouts::Guard::open(&cli.data);
            let gateway = match lightning {
                Some((lnd, config)) => {
                    let gateway = Gateway::open(hub.clone(), Arc::new(lnd), config, &db)
                        .context("open the Lightning gateway")?;
                    gateway.guard_with(guard.clone());
                    Some(Arc::new(gateway))
                }
                None => None,
            };
            let deposits = match depositing {
                Some((source, profile, config)) => {
                    let deposits =
                        deposit::Gateway::open(hub.clone(), source, profile, config, &db)
                            .context("open the deposits")?;
                    Some(Arc::new(deposits))
                }
                None => None,
            };
            let turn = Arc::new(tokio::sync::Mutex::new(()));
            peer::coordinate(gateway.as_ref(), deposits.as_ref(), &cli.data, turn.clone());
            let tweaks = match indexing {
                true => {
                    let path = cli.data.join("tweaks.sqlite");
                    let index = Tweaks::open(&path).context("open the tweak index")?;
                    Some(Arc::new(index))
                }
                false => None,
            };
            let inbox = Inbox::open(&db).context("open the inbox")?;
            let inbox = Some(Arc::new(inbox));
            let runtime = tokio::runtime::Runtime::new()?;
            let _entered = runtime.enter();
            let contracts = match (contracting, &chain) {
                (true, Some((source, _, _))) => {
                    let keyset = hub.issuing();
                    let wallet = wallet.unwrap_or_else(|| source.clone());
                    let witnesses = witnessing.witnesses(&seed)?;
                    let opening = Openings::with_wallet(
                        &cli.data,
                        source.clone(),
                        wallet,
                        keyset.clone(),
                        range,
                    );
                    let openings = runtime.block_on(opening).context("open the contracts")?;
                    let count = witnesses.count();
                    runtime
                        .block_on(openings.witnessed_by(witnesses))
                        .context("the contracts' witnesses")?;
                    match count {
                        0 => tracing::warn!(
                            "contracts without witnesses (--contracts-witnesses none): a \
                             restore of hub.sqlite older than an answer, or a second copy of \
                             the hub, may sign another"
                        ),
                        n => tracing::info!(witnesses = n, "contracts witnessed"),
                    }
                    openings
                        .check_lock_window(lock_window)
                        .context("--lock-window")?;
                    if let Some(payout) = payout_wallet {
                        runtime
                            .block_on(openings.pay_out_to(payout))
                            .context("--contracts-payout-wallet")?;
                    }
                    openings.limit_live(max_live);
                    openings.charge_opening(opening_fee);
                    if let Some(depth) = work_depth {
                        openings.ask_work(depth).context("--contracts-work-depth")?;
                    }
                    openings
                        .scale_proofs(proof_scale)
                        .context("--contracts-proof-scale")?;
                    // What each holder agrees to pay at most from now on.
                    openings.charging(hub.info().policy.fees());
                    // Holders' exits are played as they come: the hub
                    // decides each claim against its ledger, and proves
                    // what it answers.
                    licash_hub_service::answer_from(&openings, hub.clone());
                    // Contracts open on its lock checkpoints, so that every
                    // later lock is judged on their chain.
                    licash_hub_service::open_on_lock_checkpoints(&openings, hub.clone());
                    // The deposits her reserve returns to, bound to her
                    // contract, where the hub takes deposits.
                    match &deposits {
                        Some(deposits) => {
                            licash_hub_service::close_with_deposits(&openings, deposits.clone())
                        }
                        None if respond_only => {}
                        None => tracing::warn!(
                            "contracts are on and deposits are not (--deposit-sweep-address): no \
                             contract opens, for none has a deposit to return its holder's reserve to"
                        ),
                    }
                    // Its prover not ready, failing or short of time, a
                    // notification.
                    let notify = hub.clone();
                    openings.alert_with(Arc::new(move |message| {
                        if let Err(e) = notify.alert(message) {
                            tracing::error!("notifying an alert: {e:#}");
                        }
                    }));
                    tracing::info!(
                        mock = openings.advertise().mock,
                        ?range,
                        "opening contracts"
                    );
                    Some(openings)
                }
                _ => {
                    match licash_contracts::hub::signed(&cli.data) {
                        Ok(0) => {}
                        Ok(signed) => tracing::warn!(
                            signed,
                            "contracts signed in the hub's database, and --contracts is off"
                        ),
                        Err(e) => tracing::warn!("the contracts in the hub's database: {e:#}"),
                    }
                    None
                }
            };
            // Their holders agreed to what it charged then, and no more.
            match licash_contracts::hub::opened_for_less(&cli.data, &hub.info().policy.fees()) {
                Ok(0) => {}
                Ok(contracts) => tracing::warn!(
                    contracts,
                    "contracts were opened while the hub charged less: their holders pay it nothing more until they agree to its fees now"
                ),
                Err(e) => tracing::warn!("the fees kept in the hub's database: {e:#}"),
            }
            // One Tor client for the onion service and the swaps' wallet
            // alike, since its state directory takes only one.
            let tor = match onion || swaps_tor {
                true => Some(Tor::new(&cli.data.join("tor")).context("a Tor client")?),
                false => None,
            };
            let swapping = match (swapping, &chain) {
                (Some((config, from)), Some((source, profile, every))) => {
                    if from.is_empty() {
                        tracing::warn!("providing swaps from no hub (--swaps-from)");
                    }
                    // As clients reach the hub, or at least as it listens.
                    let url = announcing.as_ref().and_then(|a| a.urls.first().cloned());
                    let url = url.unwrap_or_else(|| format!("http://{listen}"));
                    let (receipts, deposits) = (gateway.clone(), deposits.clone());
                    let issuer = issuer(
                        &hub,
                        url,
                        &from,
                        receipts,
                        deposits,
                        &cli.data,
                        turn.clone(),
                    );
                    let transport = match &tor {
                        Some(tor) if swaps_tor => {
                            tracing::info!("the swaps' wallet reaches hubs through Tor");
                            Http::tor(tor.clone())
                        }
                        _ => Http::new(None)?,
                    };
                    let provider =
                        swap_provider(&swaps_dir, *profile, config, issuer, transport, cli.log)?;
                    let provider = Arc::new(provider);
                    // Before it serves: nothing is taken in unprotected.
                    let keeper = swaps_protected
                        .then(|| swaps.keeper(&provider, source.clone(), &swaps_dir, &from));
                    let notifier = match swaps_targets.is_empty() {
                        true => None,
                        false => {
                            let cursors = swaps_dir.join("notify.json");
                            let name = format!("{} swaps", notify.name);
                            let notifier = SwapsNotifier::new(
                                provider.clone(),
                                &name,
                                swaps_targets,
                                &cursors,
                                Vec::new(),
                            )
                            .context("set up the swaps' notifications")?;
                            Some(notifier)
                        }
                    };
                    Some(Swapping {
                        provider,
                        every: *every,
                        notifier,
                        keeper,
                    })
                }
                _ => None,
            };
            // Once the files of what backs them are open, and up to date.
            // Responding only, it pays no lock: it says so, and answers.
            check_backed(&hub, &cli.data, allow_unbacked_locks || respond_only)?;
            let swaps = match &swapping {
                Some(Swapping { provider, .. }) => {
                    let nostr = match &announcing {
                        Some(_) => Some(licash_nostr::public_key(&provider.nostr_secret()?)?),
                        None => None,
                    };
                    Some(licash_swaps_service::api(provider.clone(), nostr))
                }
                None => None,
            };
            let announced = announcing.as_ref().map(|a| a.urls.clone());
            let urls = Arc::new(std::sync::RwLock::new(announced.unwrap_or_default()));
            // Sweeping idle openings and playing exits as they come.
            let responding = contracts.clone().map(|c| (c, response_poll));
            let services = Services {
                gateway: gateway.clone(),
                deposits: deposits.clone(),
                tweaks: tweaks.clone(),
                inbox,
                relays,
                contracts,
                swaps,
                urls: urls.clone(),
                ingress: Arc::new(licash_hub_service::Ingress::new(ingress.trusted_proxies)),
            };
            let router = match respond_only {
                true => licash_hub_service::responding(hub.clone()),
                false => licash_hub_service::router(hub.clone(), services),
            };
            // Served until the hub stops.
            let _onion = match &tor {
                Some(tor) if onion => {
                    let onion = tor.serve("licash-hub", router.clone(), onion_pow)?;
                    tracing::info!(url = onion.url(), "serving as an onion service");
                    announce_over(&mut announcing, tor, Some(&onion))?;
                    let mut urls = urls
                        .write()
                        .map_err(|_| anyhow::anyhow!("the URLs' lock"))?;
                    if !urls.iter().any(|url| url == onion.url()) {
                        urls.push(onion.url().to_owned());
                    }
                    Some(onion)
                }
                _ => None,
            };
            let tasks = Tasks {
                contracts: responding,
                respond_only,
                chain,
                notifier,
                gateway,
                guard,
                deposits,
                announcing,
                tweaks: tweaks.map(|index| (index, tweaks_from)),
                swapping,
            };
            let serving = serve(hub, router, listen, policy, tasks);
            runtime.block_on(serving)
        }
        Command::TestNotify { notify } => test_notify(&notify),
        Command::Status { json, details } => status(&db, json, details),
        Command::Audit {
            json,
            max_authorizations,
        } => audit(&db, json, max_authorizations),
        Command::ResumePayouts => resume_payouts(&cli.data),
        Command::WitnessKey => {
            let secret = licash_hub::witness_secret_of(&seed).context("the hub's witness key")?;
            println!("{}", hex::encode(licash_witness::public_key(&secret)?));
            Ok(())
        }
        Command::ContractsWitnessImport { witnesses, network } => {
            anyhow::ensure!(
                network != ChainProfile::Core30Mainnet,
                "an import is refused on mainnet: its contracts are witnessed from the first"
            );
            anyhow::ensure!(db.exists(), "no hub at {}", db.display());
            anyhow::ensure!(
                witnesses.contracts_witnesses.is_none(),
                "an import is into witnesses: --contracts-witness-set and --contracts-witness"
            );
            // Held until the import is done: no hub signs beside it.
            let _stopped = licash_hub::stopped(&db)?;
            let witnesses = witnesses.witnesses(&seed)?;
            let runtime = tokio::runtime::Runtime::new()?;
            let imported = runtime.block_on(witnesses.import(&cli.data))?;
            println!(
                "enrolled {} contracts, kept {} answers signed and {} never to be signed; sealed",
                imported.enrolled, imported.answers, imported.burnt
            );
            Ok(())
        }
        Command::ContractsTakeover { witnesses } => {
            anyhow::ensure!(db.exists(), "no hub at {}", db.display());
            anyhow::ensure!(
                witnesses.contracts_witnesses.is_none(),
                "a takeover is kept by witnesses: --contracts-witness-set and --contracts-witness"
            );
            let witnesses = witnesses.witnesses(&seed)?;
            let runtime = tokio::runtime::Runtime::new()?;
            let epoch = runtime.block_on(witnesses.take_over(&cli.data))?;
            println!(
                "took the contracts over at epoch {epoch}: every other copy of the hub answers \
                 their disputes only"
            );
            Ok(())
        }
        Command::Dashboard {
            dashboard,
            url,
            network,
        } => show(&cli.data, network, dashboard, url),
        Command::Events {
            after,
            limit,
            follow,
        } => events(&db, after, limit, follow),
    }
}

fn init(data: &Path, seed: &Path, db: &Path, max_pow: u32, log: Log) -> anyhow::Result<()> {
    let mut dir = std::fs::DirBuilder::new();
    dir.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
    dir.create(data)
        .with_context(|| format!("create {}", data.display()))?;
    Hub::init(seed, db, max_pow).context("create the hub")?;
    if matches!(log, Log::Json) {
        tracing::info!(db = %db.display(), seed = %seed.display(), max_pow, "hub created: keep a copy of the seed");
    } else {
        eprintln!("Hub created. Back up {}.", seed.display());
    }
    Ok(())
}

/// `hub`, reached at `url`, issuing the locks of the swaps into it from
/// the hubs of `from` under their caps: under no hash its Lightning
/// receipts or its deposits hold.
fn issuer(
    hub: &Arc<Hub>,
    url: String,
    from: &[Capped],
    receipts: Option<Arc<Gateway>>,
    deposits: Option<Arc<deposit::Gateway>>,
    data: &Path,
    turn: Arc<tokio::sync::Mutex<()>>,
) -> Issuer {
    let issuer = from
        .iter()
        .fold(Issuer::new(hub.clone(), url), |issuer, (from, cap)| {
            issuer.cap(from, *cap)
        });
    let db = data.join("hub.sqlite");
    issuer.guard(turn, move |hash| {
        if let Some(gateway) = &receipts {
            if gateway.holds(hash)? {
                return Ok(true);
            }
        } else if Gateway::holding(&db, &[*hash])
            .map_err(|e| e.to_string())?
            .contains(hash)
        {
            return Ok(true);
        }
        match &deposits {
            Some(deposits) => deposits.holds(hash),
            None => deposit::Gateway::holding(&db, &[*hash])
                .map(|found| found.contains(hash))
                .map_err(|e| e.to_string()),
        }
    })
}

/// Refuse to run without `--swaps` while the provider in `dir`, if any,
/// has swaps into the hub under way: the notes the hub locked for them
/// are backed once the provider claims the clients' locks, which it then
/// would not.
fn check_idle(dir: &Path) -> anyhow::Result<()> {
    licash_store::refuse_legacy(dir, &["swaps.sqlite", "contracts.sqlite"], "wallet.sqlite")?;
    let wallet = dir.join("wallet.sqlite");
    if !wallet.exists() {
        return Ok(());
    }
    let off = "--swaps is off";
    let wallet = Wallet::open(&wallet, Http::new(None)?).context(off)?;
    Provider::open(wallet, SwapsConfig::default()).context(off)?;
    tracing::warn!(dir = %dir.display(), "{off}: the swap provider takes no swaps");
    Ok(())
}

/// Backing on disk is not enough: a disabled gateway cannot collect it.
/// Read without creating or upgrading anything: a gateway that never ran in
/// the hub's database `db` has nothing to collect. Open records alone cost no
/// notes, except when a crash left their own lock recorded only in the hub.
fn check_gateway_idle(hub: &Hub, db: &Path, deposits: bool) -> anyhow::Result<()> {
    let (component, table, flag) = if deposits {
        ("deposits", "deposits", "--deposit-sweep-address")
    } else {
        ("lightning", "lightning_receipts", "--lnd")
    };
    let check = || -> anyhow::Result<(usize, usize)> {
        let Some(conn) = peer::reader(db, component)? else {
            return Ok((0, 0));
        };
        // A deposit bound to a contract is a promise of months: owed, though
        // nothing is paid to it yet. None where the table was never made.
        let bound: std::collections::HashSet<[u8; 32]> = match deposits {
            true => conn
                .prepare("SELECT hash FROM deposit_closes WHERE contract IS NOT NULL")
                .and_then(|mut s| s.query_map([], |r| r.get(0))?.collect())
                .unwrap_or_default(),
            false => Default::default(),
        };
        let mut stmt = conn.prepare(&format!("SELECT hash, lock, state, done_at FROM {table}"))?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, [u8; 32]>(0)?,
                r.get::<_, Option<Vec<u8>>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?;
        let (mut required, mut open) = (0, 0);
        for row in rows {
            let (hash, lock, state, done) = row?;
            let owes = match state.as_str() {
                "locked" => true,
                "settled" => deposits && done.is_none(),
                "canceled" => false,
                "open" => {
                    open += 1;
                    lock.is_some()
                        || bound.contains(&hash)
                        || hub
                            .own_lock_of(&hash)?
                            .is_some_and(|l| l.settled != Some(licash_hub::Settled::Refund))
                }
                other => anyhow::bail!("unknown {table} state {other}"),
            };
            required += usize::from(owes);
        }
        Ok((required, open))
    };
    let (required, open) = check().with_context(|| {
        format!(
            "{flag} is off: cannot establish that the {component} are idle in {}",
            db.display()
        )
    })?;
    anyhow::ensure!(required == 0, "{flag} is off but {required} obligations in {} still need its gateway; enable {flag} to follow them", db.display());
    if open > 0 {
        tracing::warn!(file = %db.display(), open, "{flag} is off: open payments wait for its gateway");
    }
    Ok(())
}

/// Refuse to run, unless `allow`ed, while own locks of `hub` it may yet pay
/// are backed by no deposit, Lightning receipt or swap under way in `data`:
/// each was recorded before its lock, so such a record was lost, or the
/// swap provider's file restored older than `hub.sqlite` (the deposits and
/// receipts are in it, restored as one), and the hub would pay the notes it
/// locked without collecting what was paid for them. Allowed, the operator
/// is alerted. Opens no file while no own lock is live.
fn check_backed(hub: &Hub, data: &Path, allow: bool) -> anyhow::Result<()> {
    let live = hub.live_own_locks().context("read the hub's own locks")?;
    if live.is_empty() {
        return Ok(());
    }
    let hashes: Vec<[u8; 32]> = live
        .iter()
        .filter_map(|lock| Some(*lock.proposal.lock()?.terms().hash()))
        .collect();
    let db = data.join("hub.sqlite");
    let swaps = data.join("swaps").join("wallet.sqlite");
    let mut backed = std::collections::HashSet::new();
    let mut unreadable = Vec::new();
    let mut read = |path: &Path, found: Result<_, String>| match found {
        Ok(found) => backed.extend(found),
        Err(e) => unreadable.push(format!("{} ({e})", path.display())),
    };
    let held = deposit::Gateway::holding(&db, &hashes).map_err(|e| e.to_string());
    read(&db, held);
    let held = Gateway::holding(&db, &hashes).map_err(|e| e.to_string());
    read(&db, held);
    let held = licash_swaps::backing_own(&swaps, &hashes).map_err(|e| e.to_string());
    read(&swaps, held);
    let unbacked: Vec<String> = live
        .iter()
        .filter_map(|lock| {
            let terms = lock.proposal.lock()?.terms();
            if backed.contains(terms.hash()) {
                return None;
            }
            let amount: u64 = lock
                .proposal
                .outputs()
                .iter()
                .map(|o| o.denomination())
                .sum();
            Some(format!(
                "lock {} under hash {}, {amount} sat, expiring at {}",
                hex::encode(lock.proposal.id().as_bytes()),
                hex::encode(terms.hash()),
                terms.expiry()
            ))
        })
        .collect();
    if unbacked.is_empty() {
        return Ok(());
    }
    let mut message = format!(
        "{} own locks of the hub, which it may yet pay, are backed by no deposit, Lightning \
         receipt or swap under way in {}: {}. Restore hub.sqlite and \
         swaps/wallet.sqlite as recent as each other.",
        unbacked.len(),
        data.display(),
        unbacked.join("; ")
    );
    if !unreadable.is_empty() {
        message.push_str(&format!(" Unreadable: {}.", unreadable.join(", ")));
    }
    anyhow::ensure!(
        allow,
        "{message} Or run with --allow-unbacked-locks, to pay them unbacked."
    );
    hub.alert(&message).context("alert the operator")?;
    Ok(())
}

/// The provider of the swaps into the hub, on its files in `dir`: made on
/// the first start, its wallet's on `network`, and never replaced. Its
/// wallet reaches hubs through `transport`.
fn swap_provider(
    dir: &Path,
    network: ChainProfile,
    config: SwapsConfig,
    issuer: Issuer,
    transport: Http,
    log: Log,
) -> anyhow::Result<Provider<Http>> {
    licash_store::refuse_legacy(dir, &["swaps.sqlite", "contracts.sqlite"], "wallet.sqlite")?;
    let wallet = dir.join("wallet.sqlite");
    if wallet.exists() {
        let wallet = Wallet::open(&wallet, transport).context("open the swaps' wallet")?;
        anyhow::ensure!(
            wallet.network() == network,
            "the swaps' wallet is of {}, the hub of {network}",
            wallet.network()
        );
        return Provider::open_issuing(wallet, config, issuer).context("open the swap provider");
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    let wallet =
        Wallet::create(&wallet, &seed, network, transport).context("create the swaps' wallet")?;
    let address = hex::encode(wallet.address().to_bytes());
    let provider =
        Provider::create_issuing(wallet, config, issuer).context("create the swap provider")?;
    if matches!(log, Log::Json) {
        tracing::info!(dir = %dir.display(), %address, "swap provider created: back up its wallet file");
    } else {
        eprintln!(
            "swap provider created: back up wallet.sqlite in {}.",
            dir.display()
        );
    }
    Ok(provider)
}

/// What runs beside the API, if configured.
struct Tasks {
    /// The contracts, their exits played every so often.
    contracts: Option<(Arc<Openings>, Duration)>,
    /// Whether it only answers their disputes: opening none, it leaves
    /// openings to the copy that leads, and follows no leadership.
    respond_only: bool,
    chain: Option<(Source, ChainProfile, Duration)>,
    notifier: Option<Notifier>,
    gateway: Option<Arc<Gateway>>,
    /// The watch over the hub's payments out.
    guard: Arc<payouts::Guard>,
    deposits: Option<Arc<deposit::Gateway>>,
    announcing: Option<Announcing>,
    /// With the first block to index if the index is new.
    tweaks: Option<(Arc<Tweaks>, Option<u32>)>,
    swapping: Option<Swapping>,
}

/// The provider of the swaps into the hub, which takes them on every
/// `every`, and tells the operator of them through `notifier`.
struct Swapping {
    provider: Arc<Provider<Http>>,
    every: Duration,
    notifier: Option<SwapsNotifier>,
    /// The keeper of the contracts protecting the notes it takes in from
    /// other hubs, unless run unprotected.
    keeper: Option<Keeper<Http>>,
}

async fn serve(
    hub: Arc<Hub>,
    router: axum::Router,
    listen: SocketAddr,
    policy: Policy,
    tasks: Tasks,
) -> anyhow::Result<()> {
    let Tasks {
        contracts,
        respond_only,
        chain,
        notifier,
        gateway,
        guard,
        deposits,
        announcing,
        tweaks,
        swapping,
    } = tasks;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listen on {listen}"))?;
    tracing::debug!(policy = %serde_json::to_string(&policy)?, "hub policy");
    // Said plainly: the defaults charge, which a hub upgraded from one that
    // charged nothing unless told to should see.
    let said = |fee: Fee| format!("{} + {} ppm", fee.base, fee.ppm);
    tracing::info!(
        spend = %said(policy.spend),
        lock = %said(policy.lock),
        refund = %said(policy.refund),
        output_msat = policy.output_msat,
        "charging fees"
    );
    tracing::info!("serving at {}", listener.local_addr()?);
    let notifying = notifier.clone().map(|notifier| {
        tracing::info!(
            "notifications enabled ({} targets)",
            notifier.targets().len()
        );
        tokio::spawn(notifier.run(hub.clone()))
    });
    // What the hub can't do without: one stopping stops it.
    let mut critical = Critical::default();
    if let Some((openings, every)) = contracts {
        if !respond_only {
            critical.spawn(
                "the idle openings' sweeper",
                openings.clone().sweep_every_minute(),
            );
            // Superseded, it stops: started again, it responds only.
            let (leading, notify) = (openings.clone(), hub.clone());
            critical.spawn("the lead of the contracts", async move {
                let epoch = leading.lead_until_superseded(LEADERSHIP).await;
                let message = superseded(epoch);
                tracing::error!("{message}");
                let _ = tokio::task::spawn_blocking(move || notify.alert(&message)).await;
            });
        }
        critical.spawn("the contracts' responder", openings.respond_every(every));
    }
    if let (Some((source, network, every)), Some((index, from))) = (&chain, tweaks) {
        let notify = hub.clone();
        let alert = move |message: &str| {
            let (hub, message) = (notify.clone(), message.to_owned());
            tokio::task::spawn_blocking(move || {
                if let Err(e) = hub.alert(&message) {
                    tracing::error!("notifying an alert: {e:#}");
                }
            });
        };
        let indexing = tweaks::index(index, source.clone(), *network, from, *every, alert);
        critical.spawn("the tweaks' index", indexing);
    }
    match chain {
        Some((source, network, every)) => {
            critical.spawn(
                "the chain's watch",
                watch(hub.clone(), source, network, every),
            );
        }
        None => tracing::warn!("following no chain (--chain): locks are refused"),
    }
    if guard.paused() {
        tracing::error!(
            "Lightning payments out are paused (payouts.json): `licash-hub resume-payouts` resumes them"
        );
    }
    critical.spawn("the watch over payments out", guard.run(hub.clone()));
    if let Some(gateway) = gateway.clone() {
        tracing::info!("running a Lightning gateway");
        critical.spawn("the Lightning gateway", gateway.run());
    }
    if let Some(deposits) = deposits {
        tracing::info!("taking deposits on Bitcoin");
        critical.spawn("the deposits", deposits.run());
    }
    let mut swaps = Vec::new();
    // Stopped as the hub stops: dropped on return.
    let mut _keeping = None;
    if let Some(Swapping {
        provider,
        every,
        notifier,
        keeper,
    }) = swapping
    {
        if let Some(keeper) = keeper {
            tracing::info!("keeping the contracts protecting the notes of the hubs swapped from");
            let running = keeper.spawn(keeper::EVERY);
            _keeping = Some(running.context("a thread for the swaps' contracts")?);
        }
        let address = hex::encode(provider.wallet().address().to_bytes());
        tracing::debug!(%address, config = %serde_json::to_string(provider.config())?, "swap configuration");
        tracing::info!("providing swaps");
        critical.spawn(
            "the swaps",
            licash_swaps_service::step(provider.clone(), every),
        );
        // Its events not yet sent go out after the next start.
        swaps.extend(notifier.map(|notifier| tokio::spawn(notifier.run())));
        if let Some(a) = &announcing {
            let (relays, route) = (a.relays.clone(), a.route.clone());
            let (urls, name) = (a.urls.clone(), a.name.clone());
            let announcing = licash_swaps_service::announce(provider, relays, route, urls, name);
            swaps.push(tokio::spawn(announcing));
        }
    }
    let announcing = announcing.map(|a| {
        let (relays, urls) = (a.relays.join(", "), a.urls.join(", "));
        tracing::debug!(%relays, %urls, "announcement configuration");
        tracing::info!("announcing on Nostr");
        tokio::spawn(announce(hub.clone(), a.relays, a.route, a.urls, a.name))
    });
    // Stopped by a signal, or by a critical task's end: then with an
    // error, for the hub's supervisor (its container's restart policy) to
    // start it again. Dropped, the others are aborted.
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
    // Each request knows its peer: deposits and receipts are capped by its
    // address, or its client's behind a trusted proxy
    // (licash_hub_service::AdmissionSource).
    licash_serve::listen(listener, router, stop).await;
    for task in announcing.into_iter().chain(swaps) {
        task.abort();
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

/// How often a hub that opens contracts asks its witnesses whether another
/// copy took them over.
const LEADERSHIP: Duration = Duration::from_secs(60);

/// What a hub superseded at `epoch` tells its operator.
fn superseded(epoch: u64) -> String {
    format!(
        "another copy of the hub took the contracts over (epoch {epoch}): this one now only \
         answers their disputes, serving no wallet, until it takes them back \
         (licash-hub contracts-takeover)"
    )
}

/// Why `run` responds only, if it does: asked (`respond_only`, refused
/// without contracts and witnesses), or another copy of the hub took the
/// contracts over, as its witnesses say. Not known (a witness unreachable),
/// it responds only if it last saw itself superseded
/// ([`licash_contracts::hub::superseded`]), else runs as asked: as its
/// witnesses unreachable stop its signing anyway.
fn responding_only(
    respond_only: bool,
    chain: &Chain,
    seed: &Path,
    data: &Path,
) -> anyhow::Result<Option<String>> {
    use licash_contracts::hub::Leadership;
    let witnessed = chain.contracts && chain.witnesses.contracts_witness_set.is_some();
    if respond_only {
        anyhow::ensure!(
            witnessed,
            "--respond-only answers the contracts' disputes beside the copy that leads: it \
             needs --contracts and their witnesses"
        );
        return Ok(Some("asked (--respond-only)".into()));
    }
    if !witnessed {
        return Ok(None);
    }
    let witnesses = chain.witnesses.witnesses(seed)?;
    let asked = tokio::runtime::Runtime::new()?.block_on(witnesses.leadership(data));
    Ok(match asked {
        Ok(Leadership::Superseded(epoch)) => Some(superseded(epoch)),
        Ok(Leadership::Unfenced | Leadership::Leads(_)) => None,
        Err(e) => {
            tracing::warn!("which copy of the hub leads, not known: {e:#}");
            licash_contracts::hub::superseded(data)?.map(superseded)
        }
    })
}

/// The tasks the hub can't serve without, each looping for as long as it
/// runs: one that returns or panics stops the hub.
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

fn resume_payouts(data: &Path) -> anyhow::Result<()> {
    let (paused, now) = payouts::resume(data)?;
    match paused {
        Some(why) => println!("Lightning payments out resumed. They were paused: {why}."),
        None => println!("Lightning payments out were not paused."),
    }
    for e in &now.baseline {
        println!(
            "known: {} notes of {} sat of keyset {} retired beyond those issued",
            e.notes, e.denom, e.keyset
        );
    }
    println!(
        "A running hub takes this within {} s.",
        payouts::EVERY.as_secs()
    );
    Ok(())
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
            "Notifications of this hub reach you here.",
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

fn show(
    data: &Path,
    network: ChainProfile,
    args: licash_dashboard::Args,
    url: Option<String>,
) -> anyhow::Result<()> {
    // Blocks are told in the time of its network's.
    licash_dashboard::set_block_seconds(network.block_seconds());
    let url = url.unwrap_or_else(|| {
        let listen = std::env::var("LICASH_HUB_LISTEN");
        format!("http://{}", listen.as_deref().unwrap_or("127.0.0.1:8338"))
    });
    let probe = licash_dashboard::Probe::new(&url, licash_hub_service::HEALTH)?;
    let data = data.to_owned();
    args.run(move || dashboard::report(&data, Some(&probe)))
}

fn audit(db: &Path, json: bool, max_authorizations: u64) -> anyhow::Result<()> {
    let found = licash_hub::uncitable(db, max_authorizations).context("audit the ledger")?;
    if json {
        println!("{}", serde_json::to_string(&found)?);
    } else if found.is_empty() {
        println!("Every spend the ledger retired notes for can be cited.");
    } else {
        for spend in &found {
            println!("{} ({} notes): {}", spend.proposal, spend.notes, spend.why);
        }
    }
    anyhow::ensure!(
        found.is_empty(),
        "{} spends no dispute can cite: a claim of any of their notes is paid whole",
        found.len()
    );
    Ok(())
}

fn status(db: &Path, json: bool, details: bool) -> anyhow::Result<()> {
    let stats = Ledger::open(db).context("read the hub")?.stats()?;
    if json {
        println!("{}", serde_json::to_string(&stats)?);
        return Ok(());
    }
    // What it earned first, then what it did.
    let n = |v: u64| licash_dashboard::grouped(v as i64);
    let mut rows = vec![
        ("income", format!("{} sat", n(stats.income))),
        ("payments", format!("{} released", n(stats.released))),
        ("locks", format!("{} open", n(stats.open_locks))),
    ];
    if details {
        rows.extend([
            ("offers", n(stats.offers)),
            ("all locks", n(stats.locks)),
            (
                "notes",
                format!(
                    "{} issued, {} spent, {} unlinked",
                    n(stats.issued),
                    n(stats.spent),
                    n(stats.unlinked)
                ),
            ),
            ("events", n(stats.events)),
        ]);
    }
    let width = rows.iter().map(|(label, _)| label.len()).max().unwrap_or(0);
    for (name, value) in rows {
        println!("{name:<width$}  {value}");
    }
    Ok(())
}

fn events(db: &Path, mut after: u64, limit: u32, follow: bool) -> anyhow::Result<()> {
    let ledger = Ledger::open(db).context("read the hub")?;
    let mut out = std::io::stdout().lock();
    loop {
        let page = ledger.events(after, limit)?;
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
    use clap::Parser;

    use super::{responding_only, Cli, Command, Critical};

    #[tokio::test]
    async fn the_first_critical_task_to_stop_or_panic_is_named() {
        let mut critical = Critical::default();
        critical.spawn("forever", std::future::pending());
        critical.spawn("the watch", async {});
        assert_eq!(critical.stopped().await, "the watch stopped");
        critical.spawn("the responder", async { panic!("a bug") });
        assert_eq!(critical.stopped().await, "the responder panicked");
        let waited = tokio::time::timeout(std::time::Duration::from_millis(50), critical.stopped());
        assert!(waited.await.is_err(), "the one that runs on stopped");
    }

    fn mailboxes(args: &[&str]) -> Vec<String> {
        let cli = Cli::try_parse_from([&["licash-hub", "run"], args].concat()).unwrap();
        match cli.command {
            Command::Run { announce, .. } => announce.mailboxes(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn the_most_paid_over_lightning_in_a_day_is_unlimited_unless_given() {
        let most = |args: &[&str]| {
            let cli = Cli::try_parse_from([&["licash-hub", "run"], args].concat()).unwrap();
            match cli.command {
                Command::Run { lightning, .. } => lightning.ln_max_pay_day,
                _ => unreachable!(),
            }
        };
        assert_eq!(most(&[]), None);
        assert_eq!(most(&["--ln-max-pay-day", "500000"]), Some(500_000));
    }

    #[test]
    fn the_swaps_exit_margin_keeps_its_name_as_the_proof_margin() {
        let days = |args: &[&str]| {
            let cli = Cli::try_parse_from([&["licash-hub", "run"], args].concat()).unwrap();
            match cli.command {
                Command::Run { swaps, .. } => swaps.swaps_contract_exit_days,
                _ => unreachable!(),
            }
        };
        assert_eq!(days(&[]), 14);
        assert_eq!(days(&["--swaps-contract-exit-days", "9"]), 9);
        assert_eq!(days(&["--swaps-contract-proof-days", "9"]), 9);
    }

    /// Contracts are of terms holders choose by default, a deposit
    /// funding the smallest it fits and the hub the rest at 20% a year;
    /// the fixed terms alone only if asked.
    #[test]
    fn contracts_are_chosen_within_a_range_at_twenty_percent_unless_fixed_only() {
        let range = |args: &[&str]| {
            let cli = Cli::try_parse_from([&["licash-hub", "run"], args].concat()).unwrap();
            match cli.command {
                Command::Run { chain, .. } => chain.range(),
                _ => unreachable!(),
            }
        };
        let chosen = range(&["--contracts"]).unwrap();
        assert_eq!(
            (
                chosen.max_cap,
                chosen.max_blocks,
                chosen.ppm_year,
                chosen.ppm_year_funded
            ),
            (33_554_431, licash_api::YEAR_BLOCKS, 200_000, 0)
        );
        // Without contracts, the defaults are not an error.
        assert!(range(&[]).is_some());
        assert!(range(&["--contracts", "--contracts-fixed-only"]).is_none());
        let set = range(&[
            "--contracts",
            "--contracts-max-cap",
            "2097151",
            "--contracts-rate",
            "10000",
        ]);
        assert_eq!(
            set.map(|r| (r.max_cap, r.ppm_year)),
            Some((2_097_151, 10_000))
        );
        // Set without contracts: refused, as before.
        let refused = Cli::try_parse_from(["licash-hub", "run", "--contracts-max-cap", "2097151"]);
        assert!(refused.is_err());
    }

    /// Asked to respond only, a hub does so only with contracts witnessed;
    /// unasked, it never does without witnesses to say another copy
    /// leads, nor asks them anything.
    #[test]
    fn a_hub_responds_only_as_asked_with_witnesses_or_superseded() {
        let only = |args: &[&str]| {
            let cli = Cli::try_parse_from([&["licash-hub", "run"], args].concat()).unwrap();
            match cli.command {
                Command::Run {
                    chain,
                    respond_only,
                    ..
                } => {
                    let dir = tempfile::tempdir().unwrap();
                    let seed = dir.path().join("seed");
                    responding_only(respond_only, &chain, &seed, dir.path())
                }
                _ => unreachable!(),
            }
        };
        let witnessed = [
            "--contracts",
            "--contracts-witness-set",
            &"03".repeat(32),
            "--contracts-witness",
            &format!("https://127.0.0.1:1#{}", "ab".repeat(32)),
        ];
        for refused in [&["--respond-only"][..], &["--respond-only", "--contracts"]] {
            assert!(only(refused).is_err(), "{refused:?}");
        }
        let unwitnessed = [
            "--respond-only",
            "--contracts",
            "--contracts-witnesses",
            "none",
        ];
        assert!(only(&unwitnessed).is_err());
        let asked = [&["--respond-only"][..], &witnessed].concat();
        assert!(only(&asked).unwrap().is_some());
        assert_eq!(only(&[]).unwrap(), None);
        assert_eq!(
            only(&["--contracts", "--contracts-witnesses", "none"]).unwrap(),
            None
        );
    }

    /// Its witnesses unreachable, a hub responds only if it last saw
    /// another copy take its contracts over, and otherwise runs as asked.
    #[test]
    fn a_hub_once_superseded_responds_only_while_its_witnesses_are_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        licash_hub::Hub::init(&seed, &db, 6).unwrap();
        let witness = format!("https://127.0.0.1:1#{}", "ab".repeat(32));
        let args = [
            "licash-hub",
            "run",
            "--contracts",
            "--contracts-witness-set",
            &"03".repeat(32),
            "--contracts-witness",
            &witness,
        ];
        let Command::Run { chain, .. } = Cli::try_parse_from(args).unwrap().command else {
            unreachable!()
        };
        assert_eq!(
            responding_only(false, &chain, &seed, dir.path()).unwrap(),
            None
        );
        let marker = dir.path().join(licash_contracts::hub::SUPERSEDED_FILE);
        std::fs::write(&marker, "3").unwrap();
        let why = responding_only(false, &chain, &seed, dir.path()).unwrap();
        assert!(why.unwrap().contains("epoch 3"));
    }

    #[test]
    fn mailboxes_are_on_the_announcement_relays_unless_named() {
        assert!(mailboxes(&[]).is_empty());
        let announced = ["--nostr-relay", "wss://a.example,wss://b.example"];
        assert_eq!(
            mailboxes(&announced),
            ["wss://a.example", "wss://b.example"]
        );
        let named = [&announced[..], &["--mailbox-relay", "ws://c.example"]].concat();
        assert_eq!(mailboxes(&named), ["ws://c.example"]);
    }
}
