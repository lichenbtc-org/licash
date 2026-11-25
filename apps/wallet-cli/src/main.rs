//! `licash-wallet`: pay and get paid through Licash hubs.

use std::{
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand, ValueEnum};
use licash::{
    address::Address,
    spend::{lock_hash, ChainProfile},
};
use licash_api::Payment;
use licash_nostr::{wallet::swap_providers, Role, Route};
use licash_transport::Http;
use licash_wallet::{
    Deposit, DepositState, Error, Invoice, InvoiceState, Lock, LockState, Payable, PaymentCode,
    PaymentNote, State, Swap, SwapLimits, SwapState, Wallet,
};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use tracing_subscriber::EnvFilter;

mod background;
mod bridge;
mod cold;
mod contract;
mod onchain;
mod payout;
mod qr;
mod say;

/// The exit status of a payment recorded but not finished: retry later.
const PENDING: u8 = 75;

#[derive(Parser)]
#[command(
    name = "licash-wallet",
    version,
    about = "Pay and get paid through Licash hubs"
)]
struct Cli {
    /// The wallet file [default: $XDG_DATA_HOME/licash/wallet.sqlite].
    #[arg(long, global = true, env = "LICASH_WALLET")]
    wallet: Option<PathBuf>,
    /// Reach hubs, swap providers and Nostr relays through this proxy, such
    /// as socks5h://127.0.0.1:9050 for Tor's.
    #[arg(long, global = true, env = "LICASH_WALLET_PROXY")]
    proxy: Option<String>,
    /// Reach hubs, swap providers and Nostr relays through a Tor client of
    /// the wallet's own, instead of --proxy, keeping its state in `tor`
    /// next to the wallet file.
    #[arg(long, global = true, env = "LICASH_WALLET_TOR", conflicts_with = "proxy",
          value_parser = clap::builder::BoolishValueParser::new())]
    tor: bool,
    /// Skip opportunistic collection for this command.
    #[arg(long, global = true, env = "LICASH_WALLET_NO_COLLECT",
          value_parser = clap::builder::BoolishValueParser::new())]
    no_collect: bool,
    /// Print results as JSON.
    #[arg(long, global = true)]
    json: bool,
    /// Renew notes a hub no longer unlinks since it restarted, paying them
    /// to the wallet itself, only if its fee on them is at most this many
    /// parts per million of their value, or its spending schedule is at
    /// most 1 sat base, this rate and 0.1 sat per output. Contract ceilings
    /// take precedence. 0 renews them only for free.
    #[arg(long, global = true, env = "LICASH_WALLET_RENEW_PPM",
          default_value_t = licash_wallet::RENEW_PPM)]
    renew_ppm: u32,
    /// Diagnostic logs on stderr as text or JSON (default: off). RUST_LOG
    /// also enables diagnostics; explicit --log defaults to warn.
    #[arg(long, global = true, env = "LICASH_WALLET_LOG", value_enum)]
    log: Option<Log>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Log {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    #[command(hide = true)]
    CollectBackground,
    /// Create a wallet, with a new seed. Back up its file: the seed alone
    /// does not restore its notes.
    Init {
        /// The network of the hubs it trusts: bitcoin, regtest, signet or
        /// mutinynet.
        #[arg(long, env = "LICASH_WALLET_NETWORK", default_value_t = ChainProfile::Core30Mainnet)]
        network: ChainProfile,
        /// A chain source (as `onchain --chain`): the wallet, of a new
        /// seed, looks for its coins on Bitcoin from its tip, not from the
        /// first block its hubs serve tweaks of.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
    },
    /// Where others pay this wallet.
    Address {
        /// Also draw it as a QR code, on a terminal.
        #[arg(long)]
        qr: bool,
    },
    /// A payment code to show as text or a QR code, `licash:...`: payers
    /// pay it in notes at a hub it names that they trust, else once a swap
    /// brought their notes there.
    Code {
        /// A hub it is paid at, preferred first; repeat it for more, the
        /// first three named [default: those whose contracts have the most
        /// room to protect more, then those holding the least].
        #[arg(long, conflicts_with = "onchain")]
        hub: Vec<String>,
        /// Instead, the code to pay on Bitcoin, `bitcoin:...`: the wallet's
        /// silent payment address and a fallback address. `onchain scan`
        /// finds what they pay.
        #[arg(long)]
        onchain: bool,
        /// In upper case, which a QR code holds in fewer modules, and drawn
        /// as one on a terminal.
        #[arg(long)]
        qr: bool,
        /// Instead, extra code N (`codes`), naming no mailbox.
        #[arg(long, conflicts_with = "onchain")]
        extra: Option<u32>,
    },
    /// The wallet's extra codes, by number: codes of keys of their own,
    /// that no one can tell are this wallet's, or each other's.
    Codes,
    /// A new extra code, called LABEL: a payment code of keys of its own,
    /// the next number's, that no one can tell is this wallet's, naming no
    /// mailbox. What it is paid is collected by `mailbox` and paid on to
    /// this wallet, less its hub's fee.
    NewCode { label: String },
    /// Pay the payee of a payment code AMOUNT, the hub's fee on top, at a
    /// hub it names that this wallet trusts and holds enough at, else once
    /// a swap through a provider announced on Nostr brought it there: sent
    /// to the payee's mailbox, else printed to hand over.
    Pay {
        code: String,
        /// In satoshis [default: what the code asks for].
        amount: Option<u64>,
        /// Write the payment here instead of to stdout, if not sent.
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// All its fees at most, in sat, a swap's included [default: any,
        /// but a payment needing a swap is refused, saying its fees].
        #[arg(long)]
        max_fee: Option<u64>,
        /// Also show the payment ID and the hub's full URL.
        #[arg(long)]
        details: bool,
        /// A few words for the payee, sealed for it alone: refused at a hub
        /// that would not keep them with the payment.
        #[arg(long)]
        note: Option<String>,
        /// Tell the payee this wallet's payment code, as `code` writes it,
        /// proved this wallet's to the payee alone: so that it knows who
        /// paid and may pay back.
        #[arg(long)]
        share_code: bool,
        /// Tell the payee extra code N instead (`codes`), as `--share-code`
        /// does this wallet's own.
        #[arg(long, conflicts_with = "share_code")]
        share_extra: Option<u32>,
    },
    /// Receive the payments the wallet's hubs keep for it and those sent to
    /// its mailbox, on the relays its hubs name, and unlink their notes;
    /// then mail the payments due to their payees, as `deliver` does.
    #[command(alias = "collect")]
    Mailbox,
    /// Mail the payments made to payment codes that are due to their
    /// payees' mailboxes: those their payees did not collect at the hub
    /// within an hour, or that their hub does not keep.
    Deliver,
    /// Receive and deliver until stopped, as `mailbox` does, every so
    /// often: payments made reach their payees even if they never collect
    /// them at the hub. Bridges with rules are topped up as they say.
    Watch {
        /// Seconds between looks.
        #[arg(long, default_value_t = 60)]
        every: u64,
    },
    /// Trust the hub at URL, or learn again what it charges.
    AddHub { url: String },
    /// The hubs trusted, and their fees.
    Hubs,
    /// Available balance; --details shows where it is held.
    Balance {
        #[arg(long)]
        details: bool,
    },
    /// Pay AMOUNT to ADDRESS, the hub's fee on top, and print the payment
    /// to hand the payee (its id on stderr).
    Send {
        address: String,
        amount: u64,
        /// Through this hub [default: the one holding the most].
        #[arg(long)]
        hub: Option<String>,
        /// Write the payment here instead of to stdout.
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Take a payment from a file, or from stdin, and unlink its notes.
    Receive {
        #[arg(default_value = "-")]
        payment: PathBuf,
        /// Trust the hub the payer names if it is not trusted yet.
        #[arg(long)]
        trust: bool,
    },
    /// Finish the payments under way and unlink the notes still linked.
    Resume {
        /// The chain, for its height: a protected invoice's payment, or a
        /// deposit's, is taken only at a height the wallet knows of itself
        /// (this, or the last block it scanned), not on its hub's word.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
    },
    /// Payments sent and received, newest first (JSON lists sends only).
    History,
    /// The payments taken, newest first (also shown in text history).
    Received,
    /// Drop the notes a copy of this wallet spent, as after restoring an
    /// old backup of its file. Each hub learns which notes are this
    /// wallet's.
    Check,
    /// A payment made, to hand its payee again.
    Payment {
        id: String,
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Give up a payment its hub never signed for, freeing its notes.
    Abandon { id: String },
    /// A new secret to lock payments to: its preimage, to keep, and its
    /// hash, to hand the payer.
    Secret,
    /// Lock AMOUNT to ADDRESS, paid on the preimage of HASH until the
    /// lock expires, else refunded; the hub's fee on top. Prints the lock,
    /// whose id the payee claims it with.
    Lock {
        address: String,
        amount: u64,
        hash: String,
        /// Through this hub [default: the one holding the most].
        #[arg(long)]
        hub: Option<String>,
        /// The height the lock expires at [default: the latest the hub
        /// admits].
        #[arg(long)]
        expiry: Option<u32>,
    },
    /// The locks made, newest first.
    Locks,
    /// Take what lock ID pays this wallet, revealing PREIMAGE.
    Claim {
        id: String,
        preimage: String,
        /// The hub holding the lock [default: the only one trusted].
        #[arg(long)]
        hub: Option<String>,
    },
    /// Unlink the notes held from the payments they came in.
    Unlink,
    /// Preview a smaller-denomination note layout at a trusted hub.
    /// --max-fee executes it within that satoshi limit, bypassing automatic
    /// rest periods and the daily shaping budget, but not contract ceilings.
    Optimize {
        hub: String,
        #[arg(long)]
        max_fee: Option<u64>,
    },
    /// Pay a Lightning invoice through a hub, its fee on top: the hub pays
    /// it for a lock of notes, refunded if the payment fails. With --via,
    /// a swap provider pays it instead, for a lock of notes at the hub to
    /// it, refunded once expired if the payment fails.
    PayInvoice {
        invoice: String,
        /// Through this hub, or from notes at it with --via [default: the
        /// one holding the most].
        #[arg(long)]
        hub: Option<String>,
        /// Through the swap provider at this URL, from its own Lightning
        /// node, rather than through the hub.
        #[arg(long, value_name = "URL")]
        via: Option<String>,
        /// The fee at most, in sat: the provider's with --via [default: 1%
        /// and 100], else the hub's, with the exact notes it may make
        /// [default: none]. Asking more, it is asked on a terminal whether
        /// to pay that, else refused.
        #[arg(long)]
        max_fee: Option<u64>,
        /// Seconds to wait for the payment to end; `resume` follows it
        /// after.
        #[arg(long, default_value_t = 60)]
        wait: u64,
    },
    /// A Lightning invoice paying this wallet AMOUNT through a hub, its fee
    /// on top, to hand the payer (its hash on stderr). `resume` takes the
    /// payment once made.
    Invoice {
        amount: u64,
        /// Through this hub, or paid at it with --via [default: the only one
        /// trusted].
        #[arg(long)]
        hub: Option<String>,
        /// Made by the swap provider at this URL, from its own Lightning
        /// node, for a hub without a gateway: once paid, it locks its notes
        /// to the wallet at the hub, its fee on top for the payer. It sees
        /// the amount, the memo, and which payments go to this wallet.
        #[arg(long, value_name = "URL", conflicts_with = "chain")]
        via: Option<String>,
        /// Also draw it as a QR code, on a terminal.
        #[arg(long)]
        qr: bool,
        /// The chain, to protect the payment where a contract of the
        /// wallet's at the hub can: its lock's preimage revealed only with
        /// 6 blocks left, for the wallet to activate the lock on Bitcoin
        /// should the hub keep the notes (`recoveries --chain`), the payment
        /// failing back otherwise. Without, the hub is trusted with them.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
        /// What the invoice says to its payer, up to 100 characters: the
        /// hub and its Lightning node read it too.
        #[arg(long)]
        memo: Option<String>,
    },
    /// The Lightning invoices asked for, newest first.
    Invoices,
    /// Get AMOUNT in notes for coins paid on Bitcoin: the address and the
    /// exact amount to pay, the hub's fee on top, as a BIP21 URI (the
    /// deposit's hash on stderr). `resume` takes the notes once the
    /// payment confirmed.
    Deposit {
        amount: u64,
        /// At this hub [default: the only one trusted].
        #[arg(long)]
        hub: Option<String>,
        /// Also draw the URI as a QR code, on a terminal.
        #[arg(long)]
        qr: bool,
    },
    /// The deposits asked for, newest first.
    Deposits,
    /// Take back the coins paid to deposit HASH once its timeout passed,
    /// its notes never received.
    Refund {
        hash: String,
        /// Pay the coins to this address.
        #[arg(long)]
        to: String,
        /// The chain to find the payment on and broadcast to: Esplora as
        /// `esplora+https://esplora.example/api`, or a Bitcoin Core node
        /// as `http://user:password@127.0.0.1:8332`.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: String,
        /// In sat/vB [default: the chain's estimate within 6 blocks, at
        /// least 1].
        #[arg(long)]
        fee_rate: Option<u64>,
    },
    /// Find on Bitcoin the payments of contracts' defaults to the deposits
    /// that return their reserves, which this wallet's seed asked of a hub,
    /// and take back those whose wait passed: with the seed, the wallet's
    /// coins (found again by a scan, or named with --coin), the hub's
    /// address and its deposit root alone, its file and the hub both gone.
    /// A hub's address and root are in `hubs --json`: keep them with the
    /// seed.
    Recover {
        /// The hub, by its URL as the wallet's file records it (its address and
        /// deposit root as last heard) [or --hub-address and --claim-root].
        #[arg(long, conflicts_with_all = ["hub_address", "claim_root"])]
        hub: Option<String>,
        /// The hub's address bytes, hex (`hubs --json`'s `address`).
        #[arg(long, requires = "claim_root")]
        hub_address: Option<String>,
        /// The hub's deposit root, hex (`hubs --json`'s `deposits.close_root`).
        #[arg(long, requires = "hub_address")]
        claim_root: Option<String>,
        /// The chain to read and broadcast to: Esplora as
        /// `esplora+https://esplora.example/api`, or a Bitcoin Core node
        /// as `http://user:password@127.0.0.1:8332`.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: String,
        /// The block to look from [default: the first].
        #[arg(long, default_value_t = 0)]
        from: u32,
        /// A coin that opened a contract, `txid:vout`, beside those the
        /// wallet found: for a wallet that cannot find its coins again.
        #[arg(long = "coin")]
        coins: Vec<bitcoin::OutPoint>,
        /// Take back what is due to this address [default: only look].
        #[arg(long)]
        to: Option<String>,
        /// In sat/vB [default: the chain's estimate within 6 blocks, at
        /// least 1].
        #[arg(long)]
        fee_rate: Option<u64>,
    },
    /// Swap notes at one hub for AMOUNT at another through a swap provider,
    /// its fee and the hub's on top. `resume` takes a pending swap on.
    Swap {
        amount: u64,
        /// The hub to get AMOUNT at.
        #[arg(long)]
        to: String,
        /// The swap provider, by its URL [default: of those announced on
        /// the relays that swap AMOUNT within the limits, one swapped
        /// through before, else the cheapest].
        #[arg(long, env = "LICASH_WALLET_PROVIDER")]
        provider: Option<String>,
        /// A relay to find a provider on [default: those the wallet's hubs
        /// name]. Repeat it, or separate relays with commas, for more.
        #[arg(
            long = "relay",
            value_name = "URL",
            env = "LICASH_WALLET_RELAYS",
            value_delimiter = ',',
            conflicts_with = "provider"
        )]
        relays: Vec<String>,
        /// The hub to pay at [default: the other one holding the most].
        #[arg(long)]
        from: Option<String>,
        /// The provider's fee at most, in sat [default: 1% and 100].
        #[arg(long)]
        max_fee: Option<u64>,
        /// The provider's margin at most, in blocks: how much longer the
        /// notes stay locked should it never pay.
        #[arg(long, default_value_t = SwapLimits::usual(0).margin)]
        max_margin: u32,
        /// The chain, for its height: the provider's lock is claimed only
        /// with blocks left at the highest of this, the last block the
        /// wallet scanned, and the heights both hubs say.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
    },
    /// The swaps made, newest first.
    Swaps,
    /// Pay AMOUNT to TO, an address on Bitcoin, a silent payment address,
    /// or a `bitcoin:` code naming either (the silent payment address
    /// first), from notes at a hub through a swap provider: the wallet
    /// locks the amount and the fees to the provider, which locks a coin on
    /// chain the wallet claims, paying TO exactly AMOUNT. `payouts` takes
    /// it on until done.
    Payout {
        amount: u64,
        #[arg(long)]
        to: String,
        /// The swap provider, by its URL [default: of those announced on
        /// the relays that pay AMOUNT out within --max-fee, one paid out
        /// through before, else the cheapest].
        #[arg(long, env = "LICASH_WALLET_PROVIDER")]
        provider: Option<String>,
        /// A relay to find a provider on [default: those the wallet's hubs
        /// name]. Repeat it, or separate relays with commas, for more.
        #[arg(
            long = "relay",
            value_name = "URL",
            env = "LICASH_WALLET_RELAYS",
            value_delimiter = ',',
            conflicts_with = "provider"
        )]
        relays: Vec<String>,
        /// The hub to pay at [default: the one holding the most].
        #[arg(long)]
        from: Option<String>,
        /// What the payout costs at most on top of AMOUNT, in sat: the
        /// claim's fee, the provider's and the hub's [default: 1% and
        /// 2000].
        #[arg(long)]
        max_fee: Option<u64>,
        /// The fee rate the claim is budgeted at least, in sat/vB
        /// [default: the chain's estimate within 6 blocks, at least 1].
        #[arg(long)]
        fee_rate: Option<u64>,
        /// The chain to find the provider's coin on and broadcast the claim
        /// to: a Bitcoin Core node as `http://user:password@127.0.0.1:8332`,
        /// or Esplora as `esplora+https://esplora.example/api`.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: String,
    },
    /// The payouts made, newest first: with --chain, those under way taken
    /// on first and their claims broadcast.
    Payouts {
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
    },
    /// The coins paid on Bitcoin to the wallet's silent payment and
    /// fallback addresses: found, spent, or moved to notes.
    Onchain {
        /// The chain to read and broadcast to: a Bitcoin Core node as
        /// `http://user:password@127.0.0.1:8332`, which with
        /// `-blockfilterindex` spares fetching blocks that pay the wallet
        /// nothing, or Esplora as `esplora+https://esplora.example/api`.
        #[arg(long, global = true, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
        #[command(subcommand)]
        command: onchain::Onchain,
    },
    /// Licash bridges: Nostr Wallet Connect for apps, out of an account the
    /// wallet tops up there, by hand or by rules. Custodial: the bridge
    /// holds what the account does.
    Bridge {
        #[command(subcommand)]
        command: bridge::BridgeCommand,
    },
    /// Cold storage: notes withdrawn now and then to an external wallet by
    /// its extended public key, never to an address twice, and what it
    /// holds.
    Cold {
        /// The chain to read: a Bitcoin Core node as
        /// `http://user:password@127.0.0.1:8332`, or Esplora as
        /// `esplora+https://esplora.example/api`.
        #[arg(long, global = true, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
        #[command(subcommand)]
        command: cold::ColdCommand,
    },
    /// Open a recovery contract at HUB, a hub the wallet trusts: its
    /// collateral protects the wallet's notes there, up to its cap, until
    /// the contract's deadline. Paid from one coin of the wallet's on
    /// Bitcoin, spent whole. On regtest under the mock authority,
    /// protecting nothing; on signet under the genuine programs, a trial:
    /// `force-close` recovers from it, not yet tried on signet itself. No
    /// other network for now.
    OpenContract {
        hub: String,
        /// Blocks from now to its close [default: as many as the hub
        /// allows].
        #[arg(long)]
        blocks: Option<u32>,
        /// The most to pay to open it, in sat, its reserve and the hub's
        /// fee [default: no more than sane fees make it, --any-fees
        /// aside].
        #[arg(long)]
        max_price: Option<u64>,
        /// The least notes it protects, in sat, if the hub lets holders
        /// choose (its info's range), over --blocks [default: the
        /// smallest that takes the coin whole].
        #[arg(long, requires = "blocks")]
        cap: Option<u32>,
        /// The coin on Bitcoin to pay it from, as TXID:VOUT [default: the
        /// smallest free that a contract takes whole]. The coin is spent
        /// whole: it pays the reserve and the hub's fee, and all the rest
        /// of it funds your part of the contract, issued back to you as
        /// notes at the hub once its funding is buried. No change comes
        /// back from it.
        #[arg(long)]
        coin: Option<bitcoin::OutPoint>,
        /// Open it at a hub charging more than is sane too: over 10 sat
        /// or 1% a payment, lock or refund, a sat for each note made, or
        /// 20% of the cap chosen a year.
        #[arg(long)]
        any_fees: bool,
        /// With no coin of the wallet's: pay for one with notes, a payout
        /// through a swap provider to the wallet's own address. Its coin is
        /// worth the price and 1000 sat of the contract yours, the hub
        /// funding the rest. The contract opens on it once the coin is the
        /// wallet's, as `contracts --chain` carries it on; should it not,
        /// the coin stays yours. For notes on Lightning, receive them at a
        /// hub first.
        #[arg(long, conflicts_with_all = ["coin", "any_fees"])]
        with_notes: bool,
        /// The swap provider paying the coin, by its URL [default: of those
        /// announced on the relays that pay it within --max-fee, one paid
        /// out through before, else the cheapest].
        #[arg(long, env = "LICASH_WALLET_PROVIDER", requires = "with_notes")]
        provider: Option<String>,
        /// A relay to find a provider on [default: those the wallet's hubs
        /// name]. Repeat it, or separate relays with commas, for more.
        #[arg(
            long = "relay",
            value_name = "URL",
            env = "LICASH_WALLET_RELAYS",
            value_delimiter = ',',
            conflicts_with = "provider",
            requires = "with_notes"
        )]
        relays: Vec<String>,
        /// The hub whose notes pay for the coin [default: the one holding
        /// the most].
        #[arg(long, requires = "with_notes")]
        from: Option<String>,
        /// What the coin costs at most on top of its value, in sat: its
        /// claim's fee, the provider's and the hub's [default: 1% and
        /// 2000].
        #[arg(long, requires = "with_notes")]
        max_fee: Option<u64>,
        /// The fee rate the coin's claim is budgeted at least, in sat/vB
        /// [default: the chain's estimate within 6 blocks, at least 1].
        #[arg(long, requires = "with_notes")]
        fee_rate: Option<u64>,
        /// The chain to check the hub's quote on and broadcast to.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
    },
    /// What a contract at HUB costs, itemized, before opening it: the
    /// hub's opening fee, its interest by the year on the part it funds
    /// and on yours, your reserve and your part, and the sizes and
    /// durations it lets holders choose.
    ContractTerms {
        hub: String,
        /// Blocks from now to its close [default: the hub's fixed terms].
        #[arg(long)]
        blocks: Option<u32>,
        /// The notes it protects, in sat, one of the hub's sizes [default:
        /// the hub's fixed terms].
        #[arg(long)]
        cap: Option<u32>,
        /// Sat of it to fund yourself [default: none].
        #[arg(long, default_value_t = 0)]
        funded: u32,
    },
    /// What the hub at URL charges now, asked again, beside what the
    /// wallet agreed to pay it at most: its fees as the wallet's contracts
    /// there opened. A hub charging more is paid nothing, and its notes
    /// are not renewed, until --yes agrees to what was shown.
    ApproveFees {
        url: String,
        /// Agree to its fees, as last shown.
        #[arg(long)]
        yes: bool,
    },
    /// The wallet's contracts, the newest first. With --chain, those
    /// under way carried on, where each one's funding stands, and what
    /// each protecting notes would claim of them now, sharing them with
    /// the others at its hub.
    Contracts {
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
    },
    /// Close contract ID (its id, or the start of it) early with its hub,
    /// cooperatively: the wallet's reserve paid back on Bitcoin at once,
    /// the hub's share less the fee to it. The contract protects nothing
    /// from then on.
    Close {
        id: String,
        /// The chain to read and broadcast to.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
    },
    /// Force contract ID (its id, or the start of it) closed when its hub
    /// stopped answering: the wallet's notes at the hub, up to its cap,
    /// claimed on Bitcoin, and once the hub's window to answer passed
    /// unanswered, paid to the wallet on Bitcoin with its reserve (and the
    /// hub's, on a contract opened before graph id 8). Past
    /// its first step, irrevocable: those notes leave the wallet's balance
    /// for good. Run `recoveries --chain` until it is done.
    ForceClose {
        id: String,
        /// Its fees' rate, in sat/vB [default: the chain's estimate].
        #[arg(long)]
        fee_rate: Option<u64>,
        /// The chain to read and broadcast to.
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
    },
    /// The contracts the wallet forced closed. With --chain, each carried
    /// on as far as the chain lets it: the payouts followed and the coins
    /// looked for first, and a coin one needs for its fees, should its
    /// purse and no coin alone pay them, paid out of notes to the wallet
    /// through a swap provider announced on its hubs' relays.
    Recoveries {
        /// Its fees' rate, in sat/vB [default: the chain's estimate].
        #[arg(long)]
        fee_rate: Option<u64>,
        #[arg(long, env = "LICASH_WALLET_CHAIN")]
        chain: Option<String>,
    },
    /// Give up forcing contract ID closed, its notes back to the wallet:
    /// only before its request is signed.
    GiveUpRecovery { id: String },
    /// Let the forced close of contract ID pay SATS in all for its
    /// publication's fees, more than its reserve holds: its coins on
    /// Bitcoin pay the rest. Without it, its publication pays at most what
    /// its reserve holds, however high the chain says fees are, and
    /// `recoveries` says when that falls short.
    AllowPublicationFee { id: String, sats: u64 },
    /// Hubs announced on Nostr relays, at the URLs that answer as the hub
    /// that announced them. Needs no wallet.
    Discover {
        /// A relay to ask, such as `wss://relay.example`. Repeat it, or
        /// separate relays with commas, for more.
        #[arg(
            long = "relay",
            value_name = "URL",
            env = "LICASH_WALLET_RELAYS",
            value_delimiter = ',',
            required = true
        )]
        relays: Vec<String>,
        /// The network of the hubs: bitcoin, regtest, signet or mutinynet
        /// [default: the wallet's, else bitcoin].
        #[arg(long)]
        network: Option<ChainProfile>,
        /// Swap providers instead of hubs.
        #[arg(long)]
        swaps: bool,
        /// NWC bridges keeping accounts for anyone instead of hubs: those
        /// at hubs the wallet trusts first.
        #[arg(long, conflicts_with = "swaps")]
        bridges: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    logging(cli.log);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let mut collection = None;
    let result = runtime.block_on(run(cli, &mut collection));
    drop(runtime);
    if let Some(collection) = collection {
        collection.start();
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let pending = matches!(e.downcast_ref(), Some(Error::Pending { .. }));
            eprintln!("error: {}", say::terminal(&format!("{e:#}")));
            if pending {
                ExitCode::from(PENDING)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn log_filter(format: Option<Log>, rust_log: Option<&str>) -> EnvFilter {
    rust_log
        .and_then(|value| EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| {
            EnvFilter::new(if format.is_some() {
                "warn"
            } else {
                "off,licash_wallet=warn"
            })
        })
}

fn logging(format: Option<Log>) {
    let filter = log_filter(format, std::env::var("RUST_LOG").ok().as_deref());
    let logs = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr);
    match format.unwrap_or(Log::Text) {
        Log::Text => logs
            .with_ansi(false)
            .with_writer(|| say::TerminalWriter(std::io::stderr()))
            .without_time()
            .with_target(false)
            .init(),
        Log::Json => logs.json().init(),
    }
}

fn transport_at(
    path: &Path,
    use_tor: bool,
    proxy: Option<&str>,
) -> anyhow::Result<(Http, Option<licash_tor::Tor>)> {
    let tor = if use_tor {
        let dir = path.parent().unwrap_or(Path::new(".")).join("tor");
        Some(licash_tor::Tor::for_wallet(&dir).context("a Tor client")?)
    } else {
        None
    };
    let http = match &tor {
        Some(tor) => Http::tor(tor.clone()),
        None => Http::new(proxy)?,
    };
    Ok((http, tor))
}

async fn run(cli: Cli, collection: &mut Option<background::Collection>) -> anyhow::Result<()> {
    let path = match cli.wallet.as_ref() {
        Some(path) => path.clone(),
        None => default_path()?,
    };
    if matches!(cli.command, Command::CollectBackground) {
        return background::Collection::new(path, &cli).work().await;
    }
    let (transport, tor) = transport_at(&path, cli.tor, cli.proxy.as_deref())?;
    let json = cli.json;
    match cli.command {
        Command::Init { network, chain } => {
            return init(&path, network, chain.as_deref(), transport, json).await
        }
        Command::Discover {
            relays,
            network,
            swaps,
            bridges,
        } => {
            // Opening it reaches nothing.
            let known = match path.exists() {
                true => Some(Wallet::open(&path, Http::new(None)?)?),
                false => None,
            };
            let network = match (network, &known) {
                (Some(network), _) => network,
                (None, Some(wallet)) => wallet.network(),
                (None, None) => ChainProfile::Core30Mainnet,
            };
            let role = match (swaps, bridges) {
                (true, _) => Role::Swaps,
                (_, true) => Role::Bridge,
                _ => Role::Hub,
            };
            let trusted = match &known {
                Some(wallet) => wallet.hubs()?.into_iter().map(|(url, _)| url).collect(),
                None => Vec::new(),
            };
            let route = route(tor, cli.proxy.as_deref())?;
            let at = (&relays[..], network.name(), role, &trusted[..]);
            return discover(transport, route, at, json).await;
        }
        _ => {}
    }
    if !path.exists() {
        bail!(
            "no wallet at {}: `licash-wallet init` creates one",
            path.display()
        );
    }
    let wallet = Wallet::open(&path, transport)?;
    if !cli.no_collect {
        let background = background::Collection::new(path.clone(), &cli);
        background.report();
        if !matches!(cli.command, Command::Mailbox | Command::Watch { .. }) {
            *collection = Some(background);
        }
    }
    wallet.set_renew_limit(cli.renew_ppm);
    contract::agree(&wallet, &path);
    match cli.command {
        Command::Init { .. } | Command::Discover { .. } | Command::CollectBackground => {
            unreachable!("handled above")
        }
        Command::Address { qr } => {
            let address = encode(&wallet.address());
            show_qr(qr && !json, &address);
            show(json, json!({ "address": address }), address.clone());
        }
        Command::Code {
            onchain: true, qr, ..
        } => {
            let code = wallet.onchain_code(true)?;
            let text = if qr { code.qr() } else { code.to_string() };
            show_qr(qr && !json, &text);
            show(json, json!({ "code": text, "onchain": true }), text.clone());
        }
        Command::Code { hub, qr, extra, .. } => {
            let hubs = match hub.is_empty() {
                false => hub,
                true => contract::code_hubs(&wallet, &path)?,
            };
            if hubs.is_empty() {
                bail!("no hub: `licash-wallet add-hub URL` trusts one");
            }
            let code = match extra {
                Some(index) => wallet.extra_code(index, &hubs)?,
                None => wallet.payment_code(&hubs)?,
            };
            let licash = code.licash.as_ref().expect("a Licash code");
            let mailbox = licash.mailbox.is_some();
            let text = if qr { code.qr() } else { code.to_string() };
            if !mailbox && extra.is_none() {
                eprintln!(
                    "warning: none of its hubs names mailbox relays: payments they do not keep are handed over"
                );
            }
            let named: Vec<&String> = licash.locations.iter().map(|(_, url)| url).collect();
            show_qr(qr && !json, &text);
            show(
                json,
                json!({ "code": text, "hubs": named, "mailbox": mailbox, "onchain": false }),
                text.clone(),
            );
        }
        Command::Pay {
            code,
            amount,
            out,
            max_fee,
            details,
            note,
            share_code,
            share_extra,
        } => {
            let hubs = || contract::code_hubs(&wallet, &path);
            let from = match (share_code, share_extra) {
                (_, Some(index)) => wallet.extra_code(index, &hubs()?)?.licash,
                (true, None) => wallet.payment_code(&hubs()?)?.licash,
                (false, None) => None,
            };
            let note = PaymentNote { text: note, from };
            let route = route(tor.clone(), cli.proxy.as_deref())?;
            let out = out.as_deref();
            let how = Paying {
                max_fee,
                out,
                json,
                details,
                note: &note,
            };
            pay(&wallet, &route, &code, amount, how).await?;
        }
        Command::Codes => {
            let hubs = contract::code_hubs(&wallet, &path)?;
            let mut rows = Vec::new();
            let mut lines = Vec::new();
            for at in wallet.code_activity()? {
                let code = at.code;
                let text = match hubs.is_empty() {
                    true => None,
                    false => Some(wallet.extra_code(code.index, &hubs)?.to_string()),
                };
                let received: u64 = at.received.iter().map(|r| r.amount).sum();
                let fees: u64 = at.swept.iter().map(|s| s.fee).sum();
                lines.push(format!(
                    "{}  {}  received {} in {} payments, {} in fees  {}",
                    code.index,
                    say::terminal(&code.label),
                    say::sat(received),
                    at.received.len(),
                    say::sat(fees),
                    text.as_deref().unwrap_or("(no hub)"),
                ));
                rows.push(json!({
                    "index": code.index, "label": code.label, "code": text,
                    "created_at": code.created_at, "received": received,
                    "payments": at.received.len(), "fees": fees,
                }));
            }
            if lines.is_empty() {
                lines.push("no extra codes: `licash-wallet new-code LABEL` makes one".into());
            }
            show(json, json!({ "codes": rows }), lines.join("\n"));
        }
        Command::NewCode { ref label } => {
            let code = {
                let _turn = background::Collection::new(path.clone(), &cli)
                    .wait_for_turn()
                    .await;
                wallet.add_code(label).await?
            };
            let hubs = contract::code_hubs(&wallet, &path)?;
            let text = match hubs.is_empty() {
                true => None,
                false => Some(wallet.extra_code(code.index, &hubs)?.to_string()),
            };
            show(
                json,
                json!({ "index": code.index, "label": code.label, "code": text }),
                format!(
                    "extra code {}: {}",
                    code.index,
                    text.as_deref()
                        .unwrap_or("no hub yet, `licash-wallet add-hub URL` trusts one")
                ),
            );
        }
        Command::Mailbox => {
            let route = route(tor.clone(), cli.proxy.as_deref())?;
            let background = background::Collection::new(path.clone(), &cli);
            mailbox(&wallet, &route, &background, json).await?;
        }
        Command::Deliver => {
            let route = route(tor.clone(), cli.proxy.as_deref())?;
            deliver(&wallet, &route, json).await?;
        }
        Command::Watch { every } => {
            let route = route(tor.clone(), cli.proxy.as_deref())?;
            let background = background::Collection::new(path.clone(), &cli);
            watch(&wallet, &route, &background, every, json).await?;
        }
        Command::AddHub { url } => {
            let info = wallet.add_hub(&url).await?;
            let fees = info.fees;
            show(
                json,
                json!({
                    "fees": info.fees, "keysets": info.keysets.len(), "locks": info.locks.is_some(),
                    "lightning": info.lightning,
                }),
                match (fees.spend.base, fees.spend.ppm, fees.output_msat) {
                    (0, 0, 0) => "trusted: it charges no fee".to_owned(),
                    _ => format!("trusted: it charges {} a payment", say::payment_fee(&fees)),
                },
            );
        }
        Command::Hubs => {
            let hubs = wallet.hubs()?;
            let rows = hubs.iter().map(|(url, info)| {
                json!({
                    "url": url, "fees": info.fees, "locks": info.locks.is_some(),
                    "lightning": info.lightning, "deposits": info.deposits,
                    // What `recover` needs of it, to be kept with the seed.
                    "address": hex::encode(info.address.to_bytes()),
                })
            });
            let lines = hubs.iter().map(|(url, info)| {
                let lightning = if info.lightning.is_some() {
                    "  lightning"
                } else {
                    ""
                };
                let deposits = match &info.deposits {
                    Some(d) => format!("  deposits {}", say::between(d.min, d.max)),
                    None => String::new(),
                };
                let agreed = wallet.fee_ceilings(url).ok().flatten();
                let raised = match agreed.is_some_and(|agreed| info.fees.above(&agreed)) {
                    true => "  more than agreed: approve-fees",
                    false => "",
                };
                format!(
                    "{url}  {}{lightning}{deposits}{raised}",
                    say::payment_fee(&info.fees)
                )
            });
            show(json, rows.collect(), lines.collect::<Vec<_>>().join("\n"));
        }
        Command::Balance { details } => {
            let balance = wallet.balance()?;
            let rows = balance
                .iter()
                .map(|b| json!({ "hub": b.hub, "available": b.available, "pending": b.pending }));
            let total: u64 = balance.iter().map(|b| b.available).sum();
            let mut lines = vec![format!("balance  {}", say::sat(total))];
            let pending: u64 = balance.iter().map(|b| b.pending).sum();
            if pending > 0 {
                lines.push(format!("pending  {}", say::sat(pending)));
            }
            if details {
                lines.extend(balance.iter().map(|b| match b.pending {
                    0 => format!("{}  {}", b.hub, say::sat(b.available)),
                    p => format!(
                        "{}  {} ({} pending)",
                        b.hub,
                        say::sat(b.available),
                        say::sat(p)
                    ),
                }));
            }
            // Left at hubs visited to pay there, apart from the total (and
            // from the JSON rows, which sum to it) until added.
            for b in wallet.visited_balance()? {
                if b.available + b.pending > 0 {
                    let held = b.available + b.pending;
                    lines.push(format!(
                        "not counted  {} at {} (hub not added: add-hub to count it)",
                        say::sat(held),
                        b.hub
                    ));
                }
            }
            // Worth protecting, or cashing part out.
            match contract::unprotected(&wallet, &path) {
                Ok(found) => lines.extend(found.iter().map(|u| {
                    format!(
                        "not protected  {} of {} at {}: open-contract to protect it, or payout part of it",
                        say::sat(u.missing()),
                        say::sat(u.held),
                        u.hub
                    )
                })),
                Err(e) => tracing::warn!("what contracts protect: {e:#}"),
            }
            show(json, rows.collect(), lines.join("\n"));
        }
        Command::Send {
            address,
            amount,
            hub,
            out,
        } => {
            let payee = decode(&address)?;
            let hub = match hub {
                Some(hub) => hub,
                None => richest(&wallet)?,
            };
            let paid = wallet.send(&hub, &payee, amount).await?;
            eprintln!("payment {}", paid.id);
            write_payment(&paid.payment, out.as_deref())?;
            // Its change, linked to it until then.
            unlink(&wallet).await;
        }
        Command::Receive { payment, trust } => {
            let text = read(&payment)?;
            let payment: Payment = serde_json::from_str(&text).context("not a payment")?;
            let received = match wallet.receive(&payment) {
                Err(Error::UnknownHub(hub)) if trust => {
                    wallet.add_hub(&hub).await?;
                    wallet.receive(&payment)?
                }
                Err(e @ Error::UnknownHub(_)) => bail!("{e}, or receive with --trust"),
                received => received?,
            };
            let unlinked = unlink(&wallet).await;
            let amount = received.amount;
            show(
                json,
                json!({ "id": received.id, "hub": received.hub, "amount": amount, "unlinked": unlinked }),
                format!("received {}", say::sat(amount)),
            );
        }
        Command::Resume { chain } => {
            if let Some(chain) = &chain {
                contract::saw_tip(&wallet, chain).await?;
            }
            let resumed = resume(&wallet, json).await;
            // The payments it made among them.
            let route = route(tor.clone(), cli.proxy.as_deref())?;
            deliver_due(&wallet, &route).await;
            resumed?
        }
        Command::History => {
            let sends = wallet.sends()?;
            let notes = wallet.payment_notes()?;
            if json {
                let rows = sends.iter().map(|s| {
                    let (note, from) = note_json(notes.get(&s.id));
                    json!({
                        "id": s.id, "hub": s.hub, "payee": encode(&s.payee), "amount": s.amount,
                        "fee": s.fee, "state": state(&s.state), "created_at": s.created_at,
                        "optimization": s.is_optimization(&wallet.address()),
                        "note": note, "shared_code": from.is_some(),
                    })
                });
                show(true, rows.collect(), String::new());
            } else {
                let receipts = wallet.receipts()?;
                let sent = sends.iter().map(|s| {
                    let amount = if s.is_optimization(&wallet.address()) {
                        format!("optimized notes, fee {}", say::sat(s.fee))
                    } else {
                        say::plus(s.amount, s.fee)
                    };
                    let said = notes
                        .get(&s.id)
                        .and_then(|n| n.text.as_deref())
                        .map_or_else(String::new, |text| format!("  \"{}\"", say::terminal(text)));
                    let line = format!(
                        "{}  {amount}  via {}  {}{said}",
                        state(&s.state),
                        s.hub,
                        s.id
                    );
                    (s.created_at, &s.id, line)
                });
                let received = receipts.iter().map(|r| {
                    let amount = say::sat(r.amount);
                    let said = note_said(notes.get(&r.id));
                    let line = format!("received  {amount}  via {}  {}{said}", r.hub, r.id);
                    (r.received_at, &r.id, line)
                });
                let mut rows: Vec<_> = sent.chain(received).collect();
                rows.sort_by_key(|(at, id, _)| (std::cmp::Reverse(*at), *id));
                let lines: Vec<_> = rows
                    .into_iter()
                    .map(|(at, _, line)| format!("{}  {line}", say::when(at)))
                    .collect();
                show(false, serde_json::Value::Null, lines.join("\n"));
            }
        }
        Command::Received => {
            let receipts = wallet.receipts()?;
            let notes = wallet.payment_notes()?;
            let rows = receipts.iter().map(|r| {
                let (note, from) = note_json(notes.get(&r.id));
                json!({
                    "id": r.id, "hub": r.hub, "amount": r.amount, "received_at": r.received_at,
                    "note": note, "from": from,
                })
            });
            let lines = receipts.iter().map(|r| {
                let (at, amount) = (say::when(r.received_at), say::sat(r.amount));
                let said = note_said(notes.get(&r.id));
                format!("{at}  {amount}  via {}  {}{said}", r.hub, r.id)
            });
            show(json, rows.collect(), lines.collect::<Vec<_>>().join("\n"));
        }
        Command::Check => {
            let checked = wallet.check().await?;
            let text = match (checked.dropped, checked.recovered) {
                (0, 0) => "no note was spent elsewhere".into(),
                (d, 0) => format!("dropped {d} spent by a copy of this wallet, as its hub proved"),
                (d, r) => format!(
                    "dropped {d} spent by a copy of this wallet, as its hub proved, and took {r} of the change those spends paid it"
                ),
            };
            show(
                json,
                json!({ "dropped": checked.dropped, "recovered": checked.recovered }),
                text,
            );
        }
        Command::Payment { id, out } => write_payment(&wallet.payment(&id)?, out.as_deref())?,
        Command::Abandon { id } => {
            wallet.abandon(&id)?;
            show(
                json,
                json!({ "abandoned": id }),
                "abandoned; its notes are free".into(),
            );
        }
        Command::Secret => {
            let mut preimage = [0; 32];
            OsRng.fill_bytes(&mut preimage);
            let hash = hex::encode(lock_hash(&preimage));
            let preimage = hex::encode(preimage);
            show(
                json,
                json!({ "preimage": preimage, "hash": hash }),
                format!("preimage {preimage}\nhash {hash}"),
            );
        }
        Command::Lock {
            address,
            amount,
            hash,
            hub,
            expiry,
        } => {
            let payee = decode(&address)?;
            let hub = match hub {
                Some(hub) => hub,
                None => richest(&wallet)?,
            };
            let lock = wallet
                .lock(&hub, &payee, amount, bytes(&hash)?, expiry)
                .await?;
            show(json, lock_json(&lock), lock_line(&lock));
        }
        Command::Locks => {
            let locks = wallet.locks()?;
            let lines = locks.iter().map(lock_line).collect::<Vec<_>>();
            show(
                json,
                locks.iter().map(lock_json).collect(),
                lines.join("\n"),
            );
        }
        Command::Claim { id, preimage, hub } => {
            let hub = match hub {
                Some(hub) => hub,
                None => only_hub(&wallet)?,
            };
            let received = wallet.claim(&hub, &id, &bytes(&preimage)?).await?;
            let unlinked = unlink(&wallet).await;
            let amount = received.amount;
            show(
                json,
                json!({ "id": received.id, "hub": received.hub, "amount": amount, "unlinked": unlinked }),
                format!("received {}", say::sat(amount)),
            );
        }
        Command::Unlink => {
            let unlinked = wallet.unlink().await?;
            let optimized = maintain(&wallet).await;
            show(
                json,
                json!({ "unlinked": unlinked, "optimized": optimized }),
                format!("unlinked {unlinked} notes"),
            );
        }
        Command::Optimize { hub, max_fee } => {
            let hub = hub.trim_end_matches('/');
            anyhow::ensure!(
                wallet.hubs()?.iter().any(|(url, _)| url == hub),
                "{hub} is no hub this wallet trusts"
            );
            let (quote, id) = match max_fee {
                Some(max_fee) => match wallet.optimize_notes(hub, max_fee).await? {
                    Some(done) => (Some(done.quote), Some(done.id)),
                    None => (None, None),
                },
                None => {
                    wallet.add_hub(hub).await?;
                    (wallet.optimization_quote(hub)?, None)
                }
            };
            match quote {
                Some(quote) => {
                    let status = if id.is_some() { "optimized" } else { "preview" };
                    let mut line = format!(
                        "{status}: {} to {} notes, reminting {}, fee {}{}",
                        quote.notes_before,
                        quote.notes_after,
                        say::sat(quote.value),
                        say::sat(quote.fee),
                        say::share(quote.fee, quote.value)
                            .map(|s| format!(" ({s})"))
                            .unwrap_or_default(),
                    );
                    if id.is_none() {
                        line.push_str(&format!(
                            "\n--max-fee {} executes this within that limit",
                            quote.fee
                        ));
                    }
                    show(
                        json,
                        json!({ "hub": quote.hub, "value": quote.value, "fee": quote.fee,
                        "notes_before": quote.notes_before, "notes_after": quote.notes_after,
                        "id": id, "optimized": id.is_some() }),
                        line,
                    );
                }
                None => show(
                    json,
                    json!({ "hub": hub, "optimized": false }),
                    "no note optimization available (or one is pending)".into(),
                ),
            }
        }
        Command::PayInvoice {
            invoice,
            hub,
            via,
            max_fee,
            wait,
        } => {
            let hub = match hub {
                Some(hub) => hub,
                None => richest(&wallet)?,
            };
            let lock = match via {
                Some(provider) => {
                    let amount = Payable::read(&invoice)?.amount;
                    let max_fee = max_fee.unwrap_or(SwapLimits::usual(amount).fee);
                    let paying =
                        |max_fee| wallet.pay_invoice_via(&provider, &hub, &invoice, max_fee);
                    match paying(max_fee).await {
                        Err(e @ licash_wallet::Error::FeeRose { .. }) => {
                            paying(accept_raise(e, json)?).await?
                        }
                        paid => paid?,
                    }
                }
                None => {
                    let paying = |max_fee| wallet.pay_invoice_within(&hub, &invoice, max_fee);
                    match paying(max_fee).await {
                        Err(e @ licash_wallet::Error::FeeRose { .. }) => {
                            paying(Some(accept_raise(e, json)?)).await?
                        }
                        paid => paid?,
                    }
                }
            };
            return pay_invoice(&wallet, lock, wait, json).await;
        }
        Command::Invoice {
            amount,
            hub,
            via,
            qr,
            chain,
            memo,
        } => {
            let hub = match hub {
                Some(hub) => hub,
                None => only_hub(&wallet)?,
            };
            let memo = memo.as_deref();
            let invoice = match (via, chain) {
                (Some(via), _) => wallet.invoice_through(&via, &hub, amount, memo).await?,
                (None, Some(chain)) => {
                    contract::invoice(&wallet, &path, &chain, &hub, amount, memo).await?
                }
                (None, None) => wallet.invoice_saying(&hub, amount, memo, false).await?,
            };
            eprintln!("invoice {}", invoice.hash);
            let request = invoice.request.clone().unwrap_or_default();
            show_qr(qr && !json && !request.is_empty(), &request);
            show(json, invoice_json(&invoice), request);
        }
        Command::Invoices => {
            let invoices = wallet.invoices()?;
            let lines = invoices.iter().map(invoice_line).collect::<Vec<_>>();
            show(
                json,
                invoices.iter().map(invoice_json).collect(),
                lines.join("\n"),
            );
        }
        Command::Deposit { amount, hub, qr } => {
            let hub = match hub {
                Some(hub) => hub,
                None => only_hub(&wallet)?,
            };
            let deposit = wallet.deposit(&hub, amount).await?;
            let text = match (&deposit.terms, &deposit.state) {
                (Some(terms), DepositState::Open) => {
                    eprintln!(
                        "deposit {}: pay exactly {} sat, confirmed by block {}; refundable after block {}",
                        deposit.hash, terms.pays, terms.fund_by, terms.timeout
                    );
                    bip21(&terms.address, terms.pays)
                }
                _ => {
                    show(json, deposit_json(&deposit), deposit_line(&deposit));
                    bail!(
                        "deposit {}: {}",
                        deposit.hash,
                        deposit_state(&deposit.state)
                    )
                }
            };
            show_qr(qr && !json, &text);
            show(json, deposit_json(&deposit), text);
        }
        Command::Deposits => {
            let deposits = wallet.deposits()?;
            let lines = deposits.iter().map(deposit_line).collect::<Vec<_>>();
            show(
                json,
                deposits.iter().map(deposit_json).collect(),
                lines.join("\n"),
            );
        }
        Command::Recover {
            hub,
            hub_address,
            claim_root,
            chain,
            from,
            coins,
            to,
            fee_rate,
        } => {
            let keys = match (hub, hub_address, claim_root) {
                (Some(url), _, _) => HubKeys::Recorded(url),
                (None, Some(address), Some(root)) => HubKeys::Named(address, root),
                _ => bail!("--hub, or --hub-address with --claim-root"),
            };
            return recover(&wallet, keys, &chain, from, &coins, to, fee_rate, json).await;
        }
        Command::Refund {
            hash,
            to,
            chain,
            fee_rate,
        } => {
            let txid = refund(&wallet, &hash, &to, &chain, fee_rate).await?;
            show(
                json,
                json!({ "hash": hash, "txid": txid.to_string() }),
                txid.to_string(),
            );
        }
        Command::Swap {
            amount,
            to,
            provider,
            relays,
            from,
            max_fee,
            max_margin,
            chain,
        } => {
            if let Some(chain) = &chain {
                contract::saw_tip(&wallet, chain).await?;
            }
            let from = match from {
                Some(from) => from,
                None => richest_but(&wallet, &to)?,
            };
            let limits = SwapLimits {
                fee: max_fee.unwrap_or(SwapLimits::usual(amount).fee),
                margin: max_margin,
            };
            let (provider, found) = match provider {
                Some(provider) => (provider, false),
                None => {
                    let route = route(tor.clone(), cli.proxy.as_deref())?;
                    let pair = (from.as_str(), to.as_str());
                    let found = find_provider(&wallet, relays, &route, pair, amount, limits);
                    (found.await?, true)
                }
            };
            let swap = match wallet.swap(&provider, &from, &to, amount, limits).await {
                Err(e @ licash_wallet::Error::FeeRose { .. }) => {
                    let fee = accept_raise(e, json)?;
                    let limits = SwapLimits { fee, ..limits };
                    wallet.swap(&provider, &from, &to, amount, limits).await?
                }
                swap => swap?,
            };
            let unlinked = unlink(&wallet).await;
            let mut shown = swap_json(&swap);
            shown["unlinked"] = json!(unlinked);
            match &swap.state {
                SwapState::Failed(reason) => {
                    show(json, shown, swap_line(&swap));
                    bail!("the swap failed ({reason}): its lock returns once expired")
                }
                _ => {
                    let through = match found {
                        true => format!(" through {provider}"),
                        false => String::new(),
                    };
                    show(
                        json,
                        shown,
                        format!(
                            "swapped {} at {} for {} at {}{through}",
                            say::plus(swap.amount, swap.fee),
                            swap.from,
                            say::sat(swap.amount),
                            swap.to
                        ),
                    )
                }
            }
        }
        Command::Onchain { chain, command } => {
            return onchain::run(&wallet, chain, command, json).await;
        }
        Command::Bridge { command } => return bridge::run(&wallet, command, json).await,
        Command::Cold { chain, command } => {
            let route = route(tor, cli.proxy.as_deref())?;
            return cold::run(&wallet, chain, route, command, json).await;
        }
        Command::Payout {
            amount,
            to,
            provider,
            relays,
            from,
            max_fee,
            fee_rate,
            chain,
        } => {
            let from = match from {
                Some(from) => from,
                None => richest_but(&wallet, "")?,
            };
            let provider = match provider {
                Some(url) => payout::Provider::At(url),
                None => payout::Provider::Announced(relays, route(tor, cli.proxy.as_deref())?),
            };
            let route = (provider, from.as_str(), to.as_str());
            return payout::pay(&wallet, &chain, route, amount, (max_fee, fee_rate), json).await;
        }
        Command::Payouts { chain } => return payout::list(&wallet, chain.as_deref(), json).await,
        Command::OpenContract {
            hub,
            blocks,
            max_price,
            cap,
            coin,
            any_fees,
            with_notes,
            provider,
            relays,
            from,
            max_fee,
            fee_rate,
            chain,
        } => {
            let ask = contract::Asked {
                blocks,
                max_price,
                cap,
                coin,
                any_fees,
            };
            if with_notes {
                let provider = match provider {
                    Some(url) => payout::Provider::At(url),
                    None => payout::Provider::Announced(relays, route(tor, cli.proxy.as_deref())?),
                };
                let from = match from {
                    Some(from) => from,
                    None => richest_but(&wallet, "")?,
                };
                let payment = (provider, from, max_fee, fee_rate);
                let chain = chain.as_deref();
                return contract::open_paid(&wallet, &path, chain, &hub, ask, payment, json).await;
            }
            return contract::open(&wallet, &path, chain.as_deref(), &hub, ask, json).await;
        }
        Command::ContractTerms {
            hub,
            blocks,
            cap,
            funded,
        } => return contract::terms(&wallet, &hub, (cap, blocks), funded, json),
        Command::Contracts { chain } => {
            return contract::list(&wallet, &path, chain.as_deref(), json).await;
        }
        Command::ApproveFees { url, yes } => {
            return contract::approve_fees(&wallet, &path, &url, yes, json).await;
        }
        Command::Close { id, chain } => {
            return contract::close(&wallet, &path, chain.as_deref(), &id, json).await;
        }
        Command::ForceClose {
            id,
            fee_rate,
            chain,
        } => {
            return contract::force_close(&wallet, &path, chain.as_deref(), &id, fee_rate, json)
                .await;
        }
        Command::Recoveries { fee_rate, chain } => {
            let route = route(tor, cli.proxy.as_deref())?;
            let chain = (chain.as_deref(), &route);
            return contract::recoveries(&wallet, &path, chain, fee_rate, json).await;
        }
        Command::GiveUpRecovery { id } => contract::give_up(&wallet, &path, &id)?,
        Command::AllowPublicationFee { id, sats } => {
            contract::allow_publication_fee(&path, &id, sats)?
        }
        Command::Swaps => {
            let swaps = wallet.swaps()?;
            let lines = swaps.iter().map(swap_line).collect::<Vec<_>>();
            show(
                json,
                swaps.iter().map(swap_json).collect(),
                lines.join("\n"),
            );
        }
    }
    Ok(())
}

/// A fee risen past `--max-fee`, as `e` ([`licash_wallet::Error::FeeRose`])
/// says: on a terminal, the user asked whether to pay it, the fee to allow
/// then if so; else refused, saying how to accept it.
pub(crate) fn accept_raise(e: licash_wallet::Error, json: bool) -> anyhow::Result<u64> {
    let licash_wallet::Error::FeeRose { asked, reason, .. } = e else {
        return Err(e.into());
    };
    let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    if !json && terminal {
        eprint!("{reason}. Pay {asked} sat in fees? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if matches!(answer.trim(), "y" | "Y" | "yes") {
            return Ok(asked);
        }
    }
    bail!("{reason}: --max-fee {asked} accepts it")
}

/// Follow `lock`, paying an invoice, for up to `wait` seconds: done once
/// paid, failed once refunded, pending while under way.
async fn pay_invoice(
    wallet: &Wallet<Http>,
    mut lock: Lock,
    wait: u64,
    json: bool,
) -> anyhow::Result<()> {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(wait);
    let mut pending = None;
    // A provider's payment given up: its lock is refunded only once expired.
    let given_up = |lock: &Lock| lock.via.is_some() && lock.failure.is_some();
    while matches!(lock.state, LockState::Requested | LockState::Locked)
        && !given_up(&lock)
        && std::time::Instant::now() < until
    {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        match wallet.follow_lock(&lock.id).await {
            Ok(followed) => (lock, pending) = (followed, None),
            Err(Error::Pending { reason, .. }) => pending = Some(reason),
            Err(e) => return Err(e.into()),
        }
    }
    let text = match &lock.state {
        LockState::Paid(preimage) => format!(
            "paid {}\npreimage {}",
            say::plus(lock.amount, lock.fee),
            hex::encode(preimage)
        ),
        _ => lock_line(&lock),
    };
    show(json, lock_json(&lock), text);
    let given_up = given_up(&lock);
    match (&lock.state, lock.failure) {
        (LockState::Paid(_), _) => Ok(()),
        (LockState::Locked, Some(failure)) if given_up => bail!(
            "the invoice was not paid ({failure}); its lock is refunded once expired at {}",
            lock.expiry
        ),
        (LockState::Requested | LockState::Locked, _) => Err(Error::Pending {
            id: lock.id,
            reason: pending.unwrap_or_else(|| "the payment is under way".into()),
        }
        .into()),
        (LockState::Refunded, Some(failure)) => {
            bail!("the invoice was not paid ({failure}); its lock was refunded")
        }
        (state, failure) => bail!(
            "the invoice was not paid: its lock {}{}",
            lock_state(state),
            failure.map(|f| format!(" ({f})")).unwrap_or_default()
        ),
    }
}

/// Print the services of `role` announced on `relays` for `network`, each
/// at the URLs whose info names the key that announced it: bridges open to
/// anyone only, those at hubs `trusted` first.
async fn discover(
    http: Http,
    route: Route,
    (relays, network, role, trusted): (&[String], &str, Role, &[String]),
    json: bool,
) -> anyhow::Result<()> {
    // Onion services are reached the way relays are, if through Tor.
    let onions = !matches!(route, Route::Direct);
    let found = licash_nostr::discover(relays, &route, role, network).await?;
    let http = Arc::new(http);
    let mut checks = tokio::task::JoinSet::new();
    let at_once = Arc::new(tokio::sync::Semaphore::new(CHECKS_AT_ONCE));
    for (i, service) in found.iter().enumerate() {
        for url in &service.announcement.urls {
            if is_onion(url) && !onions {
                tracing::warn!(%url, "skipped: an onion service needs --proxy or --tor");
                continue;
            }
            let (http, url, at_once) = (http.clone(), url.clone(), at_once.clone());
            checks.spawn(async move {
                let _turn = at_once.acquire_owned().await;
                let info = tokio::time::timeout(CHECK_TIMEOUT, info_at(&http, &url, role)).await;
                let info = info.unwrap_or_else(|_| Err("no answer in time".into()));
                (i, url, info)
            });
        }
    }
    let mut answered: Vec<Vec<(String, Answer)>> = Vec::new();
    answered.resize_with(found.len(), Vec::new);
    while let Some(checked) = checks.join_next().await {
        let (i, url, info) = checked?;
        match info {
            Ok(info) if found[i].named_by(info.nostr()) => answered[i].push((url, info)),
            Ok(_) => tracing::warn!(%url, "skipped: not the service that announced it"),
            Err(e) => tracing::warn!(%url, "skipped: {e}"),
        }
    }
    let mut rows = Vec::new();
    let mut lines = Vec::new();
    let mut services: Vec<_> = found.iter().zip(answered).collect();
    let same = |a: &str, b: &str| a.trim_end_matches('/') == b.trim_end_matches('/');
    let at_trusted = |info: &licash_api::bridge::Info| trusted.iter().any(|t| same(t, &info.hub));
    services.retain(|(_, at)| !matches!(at.first(), Some((_, Answer::Bridge(info))) if !info.open));
    // Stable: in the order found otherwise.
    services.sort_by_key(|(_, at)| match at.first() {
        Some((_, Answer::Bridge(info))) => !at_trusted(info),
        _ => false,
    });
    for (service, mut at) in services {
        if at.is_empty() {
            continue;
        }
        // In the order announced.
        let announced = &service.announcement.urls;
        at.sort_by_key(|(url, _)| announced.iter().position(|u| u == url));
        let urls: Vec<&str> = at.iter().map(|(url, _)| url.as_str()).collect();
        let name = service.announcement.name.as_deref().unwrap_or_default();
        let (key, shown) = (&service.key, &service.announcement.name);
        match &at[0].1 {
            Answer::Hub(info) => {
                let lightning = if info.lightning.is_some() {
                    "  lightning"
                } else {
                    ""
                };
                lines.push(format!(
                    "{}  {}{lightning}  {name}",
                    urls.join(" "),
                    say::payment_fee(&info.fees)
                ));
                rows.push(json!({
                    "key": key, "name": shown, "urls": urls, "fees": info.fees,
                    "locks": info.locks.is_some(), "lightning": info.lightning,
                }));
            }
            Answer::Swaps(info) => {
                let fee = info.fee;
                lines.push(format!(
                    "{}  {}  {}  {} hubs  {name}",
                    urls.join(" "),
                    say::fee(fee.base, fee.ppm),
                    say::between(info.min, info.max),
                    info.hubs.len()
                ));
                let hubs = info.hubs.iter().map(|hub| {
                    json!({
                        "address": encode(&hub.address), "max": hub.max,
                        "margin": info.margin_at(hub),
                    })
                });
                rows.push(json!({
                    "key": key, "name": shown, "urls": urls, "fee": fee, "min": info.min,
                    "max": info.max, "margin": info.margin, "hubs": hubs.collect::<Vec<_>>(),
                }));
            }
            Answer::Bridge(info) => {
                let trusted = at_trusted(info);
                let most = |m: Option<u64>| m.map_or("no limit".to_owned(), |m| say::sat(m / 1000));
                let address = if info.lightning_address.is_some() {
                    "  address"
                } else {
                    ""
                };
                lines.push(format!(
                    "{}  at {}{}  holds {}  pays {}{address}  {name}",
                    urls.join(" "),
                    info.hub,
                    if trusted { " (trusted)" } else { "" },
                    most(info.max_balance),
                    most(info.max_payment),
                ));
                rows.push(json!({
                    "key": key, "name": shown, "urls": urls, "hub": info.hub, "trusted": trusted,
                    "max_balance": info.max_balance, "max_payment": info.max_payment,
                    "receive_fee": info.receive_fee, "lightning_address": info.lightning_address,
                }));
            }
        }
    }
    show(json, rows.into(), lines.join("\n"));
    Ok(())
}

/// How long a service announced has to answer.
const CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The most URLs announced asked at once: announcing is free, so relays
/// may hold thousands, each naming a few.
const CHECKS_AT_ONCE: usize = 32;

/// What a service announced says of itself.
enum Answer {
    Hub(Box<licash_api::Info>),
    Swaps(Box<licash_api::swaps::Info>),
    Bridge(Box<licash_api::bridge::Info>),
}

impl Answer {
    /// The key it announces itself under.
    fn nostr(&self) -> Option<&str> {
        match self {
            Self::Hub(info) => info.nostr.as_deref(),
            Self::Swaps(info) => info.nostr.as_deref(),
            Self::Bridge(info) => Some(&info.nostr),
        }
    }
}

/// What the service of `role` at `url` says of itself.
async fn info_at(http: &Http, url: &str, role: Role) -> Result<Answer, String> {
    let path = match role {
        Role::Hub => licash_api::INFO,
        Role::Swaps => licash_api::swaps::SWAPS_INFO,
        Role::Bridge => licash_api::bridge::INFO,
    };
    let at = format!("{}{path}", url.trim_end_matches('/'));
    let response = licash_wallet::Transport::request(http, &at, None).await?;
    if response.status != 200 {
        return Err(format!("status {}", response.status));
    }
    let body = &response.body;
    let answer = match role {
        Role::Hub => serde_json::from_slice(body).map(|info| Answer::Hub(Box::new(info))),
        Role::Swaps => serde_json::from_slice(body).map(|info| Answer::Swaps(Box::new(info))),
        Role::Bridge => serde_json::from_slice(body).map(|info| Answer::Bridge(Box::new(info))),
    };
    answer.map_err(|e| format!("not a service's info: {e}"))
}

fn is_onion(url: &str) -> bool {
    let host = url.split("://").nth(1).unwrap_or(url);
    let host = host.split(['/', ':']).next().unwrap_or(host);
    host.ends_with(".onion")
}

async fn init(
    path: &Path,
    network: ChainProfile,
    chain: Option<&str>,
    transport: Http,
    json: bool,
) -> anyhow::Result<()> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        let mut create = std::fs::DirBuilder::new();
        create.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut create, 0o700);
        create
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    let source = chain.map(payout::source).transpose()?;
    let wallet = Wallet::create(path, &seed, network, transport)?;
    // Its seed new, no coin of its is in an earlier block: looked for from
    // the chain's tip. Unknown, from the first block its hubs serve tweaks
    // of, as before.
    let from = match source {
        Some(source) => match born(&wallet, network, source).await {
            Ok(tip) => Some(tip),
            Err(e) => {
                eprintln!(
                    "warning: no chain tip ({e:#}): the first `onchain scan` looks from the \
                     first block its hubs serve tweaks of"
                );
                None
            }
        },
        None => None,
    };
    let address = encode(&wallet.address());
    let scans = from.map_or(String::new(), |tip| {
        format!("\nlooks for its coins on Bitcoin from block {tip}")
    });
    show(
        json,
        json!({ "wallet": path, "address": address, "network": network.name(), "from": from }),
        format!(
            "created {} for {network}\naddress {address}{scans}\nBack up this file: the seed alone does not restore its notes.",
            path.display()
        ),
    );
    Ok(())
}

/// The tip of `source`, which `wallet`, new, of `network`, watches for its
/// coins from: refused, nothing kept, for a chain of another network, whose
/// tip would hide every block of its own.
async fn born(
    wallet: &Wallet<Http>,
    network: ChainProfile,
    source: licash_chain_client::Source,
) -> anyhow::Result<u32> {
    let profile = source.profile().await?;
    if profile.name() != network.name() {
        bail!("a chain of {}, not {}", profile.name(), network.name());
    }
    let tip = source.tip().await?.height;
    wallet.watch_silent(None, tip)?;
    Ok(tip)
}

async fn resume(wallet: &Wallet<Http>, json: bool) -> anyhow::Result<()> {
    let resumed = wallet.resume().await?;
    let unlinked = unlink(wallet).await;
    // `unlink` also runs best-effort maintenance. No optimization payment
    // is returned as a handover by the wallet's resume.
    let mut lines = Vec::new();
    for paid in &resumed.paid {
        let id = &paid.id;
        lines.push(format!(
            "done {id}: `licash-wallet payment {id}` prints its payment"
        ));
    }
    lines.extend(resumed.locks.iter().map(lock_line));
    lines.extend(resumed.invoices.iter().map(invoice_line));
    lines.extend(resumed.swaps.iter().map(swap_line));
    lines.extend(resumed.deposits.iter().map(deposit_line));
    for (id, reason) in &resumed.abandoned {
        lines.push(format!("abandoned {id}: {reason}"));
    }
    for (id, reason) in &resumed.pending {
        lines.push(format!("pending {id}: {reason}"));
    }
    let paid = resumed
        .paid
        .iter()
        .map(|p| json!({ "id": p.id, "payment": p.payment }));
    let abandoned = resumed
        .abandoned
        .iter()
        .map(|(id, r)| json!({ "id": id, "reason": r }));
    let pending = resumed
        .pending
        .iter()
        .map(|(id, r)| json!({ "id": id, "reason": r }));
    show(
        json,
        json!({
            "paid": paid.collect::<Vec<_>>(),
            "locks": resumed.locks.iter().map(lock_json).collect::<Vec<_>>(),
            "invoices": resumed.invoices.iter().map(invoice_json).collect::<Vec<_>>(),
            "swaps": resumed.swaps.iter().map(swap_json).collect::<Vec<_>>(),
            "deposits": resumed.deposits.iter().map(deposit_json).collect::<Vec<_>>(),
            "abandoned": abandoned.collect::<Vec<_>>(),
            "pending": pending.collect::<Vec<_>>(),
            "unlinked": unlinked,
        }),
        lines.join("\n"),
    );
    match resumed.pending.into_iter().next() {
        Some((id, reason)) => Err(Error::Pending { id, reason }.into()),
        None => Ok(()),
    }
}

/// Pay the payee of payment code `text` `amount`, or what the code asks
/// for, at a hub it names that the wallet trusts and holds enough at, else
/// once a swap brought it there, fees of `max_fee` at most: sent to its
/// mailbox on the relays that hub names, if it has one, else written to
/// `out` or stdout to hand over. A swap is only made with a `max_fee`.
async fn pay(
    wallet: &Wallet<Http>,
    route: &Route,
    text: &str,
    amount: Option<u64>,
    how: Paying<'_>,
) -> anyhow::Result<()> {
    let Paying {
        max_fee,
        out,
        json,
        details,
        note,
    } = how;
    let code: PaymentCode = text.parse()?;
    let progress = !json && std::io::stderr().is_terminal();
    if progress {
        eprintln!("Preparing payment…");
    }
    let plan = licash_nostr::wallet::plan(wallet, &code, amount, route).await?;
    let fees = plan.fees();
    if let Some(swap) = &plan.swap {
        let (provider, quote) = (&swap.provider, &swap.provider.quote);
        let technical = format!(
            "paying {} at {} swaps {} from {} through {} first",
            plan.amount, plan.hub, quote.amount, swap.from, provider.url
        );
        let swapping = if json || details {
            technical
        } else {
            format!("A swap is needed to send {}", say::sat(plan.amount))
        };
        let swapping = if plan.trusted {
            swapping
        } else {
            format!("{swapping}; {} is not a hub you added: what the swap brings past the payment stays there", plan.hub)
        };
        if max_fee.is_none() {
            if json {
                bail!("{swapping}, {fees} sat in fees at most in all: pay again with --max-fee {fees}");
            }
            bail!(
                "{swapping}; fee up to {}: pay again with --max-fee {fees}",
                say::fee_of(fees, plan.amount)
            );
        }
        if json || details || !plan.trusted {
            eprintln!("{}", say::terminal(&swapping));
        }
    }
    if let Some(max) = max_fee.filter(|max| fees > *max) {
        if json {
            bail!("paying costs {fees} sat in fees at most, more than --max-fee {max}");
        }
        bail!(
            "fee up to {} exceeds --max-fee {max}",
            say::fee_of(fees, plan.amount)
        );
    }
    if progress {
        eprintln!("Sending {}…", say::sat(plan.amount));
    }
    let paid = licash_nostr::wallet::pay_planned(wallet, &code, &plan, note).await?;
    let (id, hub, amount, kept) = (&paid.paid.id, &paid.hub, paid.amount, paid.paid.kept);
    if json || details {
        eprintln!("payment {id}");
    }
    let fee = format!(
        "{}{}",
        if fees == 0 { "" } else { "up to " },
        say::fee_of(fees, amount)
    );
    let hub_line = match details {
        true => format!("\nhub              {hub}"),
        false => String::new(),
    };
    let mailbox = code.licash.as_ref().is_some_and(|c| c.mailbox.is_some());
    // Not kept at its hub: to the payee's mailbox at once, the payer waiting.
    let mailed = match mailbox && !kept {
        true => Some(deliver_now(wallet, route, id).await),
        false => None,
    };
    match (&mailed, kept && mailbox) {
        (Some(Ok(relays)), _) => show(
            json,
            json!({ "id": id, "hub": hub, "amount": amount, "kept": false, "relays": relays }),
            format!(
                "sent to mailbox  {}\nfee              {fee}{hub_line}",
                say::sat(amount)
            ),
        ),
        (None, true) => {
            show(
                json,
                json!({ "id": id, "hub": hub, "amount": amount, "kept": true }),
                format!(
                    "kept at hub      {}\nfee              {fee}{hub_line}",
                    say::sat(amount)
                ),
            );
            if !json {
                eprintln!(
                    "Kept at the hub, not yet collected: if the recipient has not collected it \
                     within an hour, `licash-wallet deliver` mails it to them."
                );
            }
        }
        (mailed, _) => {
            if let Some(Err(reason)) = mailed {
                eprintln!(
                    "warning: not sent to the payee's mailbox ({}): hand it over, or \
                     `licash-wallet deliver` mails it again later",
                    say::terminal(reason)
                );
            }
            write_payment(&paid.paid.payment, out)?;
            if !json {
                let hand = match kept {
                    true => "Kept at the hub for the recipient to collect, else hand the payment to them.",
                    false => "Hand the payment to the recipient.",
                };
                eprintln!(
                    "payment ready  {}\nfee            {fee}\n{hand}",
                    say::sat(amount)
                );
            }
        }
    }
    // Preserve change unlinking, but leave older receipts to delivery runs:
    // a relay timeout must not hold up a new payment kept at its hub.
    let _ = unlink(wallet).await;
    Ok(())
}

/// The payments `collected` took, warned of what it did not look through
/// or take.
fn collection_warnings(collected: &licash_nostr::wallet::Collected, mut warn: impl FnMut(String)) {
    for (index, reason) in &collected.codes.failed {
        warn(format!(
            "extra code {index} not collected ({}): again next time",
            say::terminal(reason)
        ));
    }
    for (id, reason) in &collected.skipped {
        warn(format!("{id} in the mailbox {}", say::terminal(reason)));
    }
    for relay in &collected.full {
        warn(format!(
            "mailbox relay {} answered all the mail asked for: newer mail, junk perhaps, may hide an older payment to you there",
            say::terminal(relay)
        ));
    }
    for (at, reason) in &collected.failed {
        let at = match at.as_str() {
            licash_nostr::wallet::MAILBOX => "the mailbox".to_owned(),
            hub => format!("the payments kept at {hub}"),
        };
        warn(format!(
            "{at} not looked through ({}): looked through again next time",
            say::terminal(reason)
        ));
    }
}

fn collected_said(collected: licash_nostr::wallet::Collected) -> Vec<licash_wallet::Received> {
    collection_warnings(&collected, |warning| eprintln!("warning: {warning}"));
    collected.received
}

/// Mail the payments due to their payees' mailboxes, now and as `watch`
/// does: those mailed, those not, and how many are still on their way.
async fn deliver(wallet: &Wallet<Http>, route: &Route, json: bool) -> anyhow::Result<()> {
    let delivered = licash_nostr::wallet::deliver(wallet, || Ok(route.clone())).await?;
    let on_their_way = wallet.delivering()?;
    let mut lines: Vec<String> = delivered
        .mailed
        .iter()
        .map(|(id, relays)| format!("mailed {id} to {relays} relays"))
        .collect();
    for (id, why) in &delivered.failed {
        lines.push(format!("not mailed {id}: {why}, mailed again later"));
    }
    lines.push(match (lines.is_empty(), on_their_way) {
        (true, 0) => "nothing to deliver".into(),
        (_, 0) => "nothing more on its way".into(),
        (_, n) => format!("{n} on their way: kept at their hubs, or to mail later"),
    });
    let mailed = delivered
        .mailed
        .iter()
        .map(|(id, r)| json!({ "id": id, "relays": r }));
    let failed = delivered
        .failed
        .iter()
        .map(|(id, r)| json!({ "id": id, "reason": r }));
    show(
        json,
        json!({
            "mailed": mailed.collect::<Vec<_>>(),
            "failed": failed.collect::<Vec<_>>(),
            "delivering": on_their_way,
        }),
        lines.join("\n"),
    );
    Ok(())
}

/// Receive and deliver every `every` seconds, until stopped: the payments
/// the wallet's hubs keep for it and those in its mailbox taken, its
/// relays kept connected between looks, and the payments due mailed.
async fn watch(
    wallet: &Wallet<Http>,
    route: &Route,
    background: &background::Collection,
    every: u64,
    json: bool,
) -> anyhow::Result<()> {
    let mut kept = None;
    loop {
        let collected = {
            let _turn = background.wait_for_turn().await;
            licash_nostr::wallet::collect_kept(wallet, route, &mut kept).await
        };
        let received = match collected {
            Ok(collected) => {
                for (row, line) in at_codes(wallet, &collected.codes) {
                    show(json, json!({ "received_at_code": row }), line);
                }
                collected_said(collected)
            }
            Err(e) => {
                eprintln!(
                    "warning: nothing received ({})",
                    say::terminal(&format!("{e:#}"))
                );
                Vec::new()
            }
        };
        let unlinking = async {
            if !received.is_empty() {
                unlink(wallet).await;
            }
        };
        let (_, mailed, _) = tokio::join!(
            unlinking,
            deliver_due(wallet, route),
            bridge::top_up_due(wallet, json)
        );
        for r in &received {
            show(
                json,
                json!({ "received": { "id": r.id, "hub": r.hub, "amount": r.amount } }),
                format!("received {} at {}", say::sat(r.amount), r.hub),
            );
        }
        for (id, relays) in &mailed {
            show(
                json,
                json!({ "mailed": { "id": id, "relays": relays } }),
                format!("mailed {id} to its payee"),
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(every.max(1))).await;
    }
}

/// Mail the payments due to their payees' mailboxes, payment `id` among
/// them: to how many relays it went, or why not. Those others not mailed
/// are warned of, mailed again later as `id` is.
async fn deliver_now(wallet: &Wallet<Http>, route: &Route, id: &str) -> Result<usize, String> {
    let delivered = licash_nostr::wallet::deliver(wallet, || Ok(route.clone()));
    let delivered = delivered.await.map_err(|e| format!("{e:#}"))?;
    let mut mine = Err("it was not due".to_owned());
    for (paid, relays) in delivered.mailed {
        if paid == id {
            mine = Ok(relays);
        }
    }
    for (paid, why) in delivered.failed {
        match paid == id {
            true => mine = Err(why),
            false => not_mailed(&paid, &why),
        }
    }
    mine
}

/// Mail the payments due to their payees' mailboxes, if any is on its way
/// there: those mailed, and those not, warned of and mailed again later.
async fn deliver_due(wallet: &Wallet<Http>, route: &Route) -> Vec<(String, usize)> {
    match wallet.delivering() {
        Ok(0) => return Vec::new(),
        Ok(_) => {}
        Err(e) => {
            eprintln!(
                "warning: payments due not mailed ({})",
                say::terminal(&e.to_string())
            );
            return Vec::new();
        }
    }
    match licash_nostr::wallet::deliver(wallet, || Ok(route.clone())).await {
        Ok(delivered) => {
            for (id, why) in &delivered.failed {
                not_mailed(id, why);
            }
            delivered.mailed
        }
        Err(e) => {
            eprintln!(
                "warning: payments due not mailed ({})",
                say::terminal(&format!("{e:#}"))
            );
            Vec::new()
        }
    }
}

fn not_mailed(id: &str, why: &str) {
    eprintln!(
        "warning: payment {id} not mailed to its payee ({}): mailed again later",
        say::terminal(why)
    );
}

/// Receive the payments the wallet's hubs keep for it, and those in its
/// mailbox, on the relays its hubs name: each once, of hubs it trusts
/// only. Then mail the payments due to their payees.
async fn mailbox(
    wallet: &Wallet<Http>,
    route: &Route,
    background: &background::Collection,
    json: bool,
) -> anyhow::Result<()> {
    let collected = {
        let _turn = background.wait_for_turn().await;
        licash_nostr::wallet::collect(wallet, route).await?
    };
    let (code_rows, code_lines): (Vec<_>, Vec<_>) =
        at_codes(wallet, &collected.codes).into_iter().unzip();
    let swept: Vec<String> = (collected.codes.swept.iter())
        .map(|(_, paid)| paid.id.clone())
        .collect();
    let received = collected_said(collected);
    let unlinking = async {
        match received.is_empty() {
            true => Some(0),
            false => unlink(wallet).await,
        }
    };
    let (unlinked, _) = tokio::join!(unlinking, deliver_due(wallet, route));
    let notes = wallet.payment_notes()?;
    let rows: Vec<_> = received
        .iter()
        .map(|r| {
            let (note, from) = note_json(notes.get(&r.id));
            json!({ "id": r.id, "hub": r.hub, "amount": r.amount, "note": note, "from": from })
        })
        .collect();
    let mut lines: Vec<String> = received
        .iter()
        .map(|r| {
            let said = note_said(notes.get(&r.id));
            match swept.contains(&r.id) {
                true => format!(
                    "moved {} in from extra codes at {}",
                    say::sat(r.amount),
                    r.hub
                ),
                false => format!("received {} at {}{said}", say::sat(r.amount), r.hub),
            }
        })
        .collect();
    lines.extend(code_lines);
    if lines.is_empty() {
        lines.push("nothing new".into());
    }
    show(
        json,
        json!({ "received": rows, "at_codes": code_rows, "unlinked": unlinked }),
        lines.join("\n"),
    );
    Ok(())
}

/// The payments the wallet's extra codes took in `codes`, as JSON and as
/// lines, their notes said: their wallets' own notes.
fn at_codes(
    wallet: &Wallet<Http>,
    codes: &licash_wallet::CodesCollected,
) -> Vec<(serde_json::Value, String)> {
    if codes.received.is_empty() {
        return Vec::new();
    }
    let activity = wallet.code_activity().unwrap_or_default();
    codes
        .received
        .iter()
        .map(|(index, r)| {
            let at = activity.iter().find(|a| a.code.index == *index);
            let note = at.and_then(|a| a.notes.get(&r.id));
            let label = at.map(|a| a.code.label.as_str()).unwrap_or_default();
            let (text, from) = note_json(note);
            let row = json!({
                "code": index, "label": label, "id": r.id, "hub": r.hub,
                "amount": r.amount, "note": text, "from": from,
            });
            let line = format!(
                "received {} at extra code {index} ({}){}",
                say::sat(r.amount),
                say::terminal(label),
                note_said(note)
            );
            (row, line)
        })
        .collect()
}

/// How [`pay`] pays: its fees at most, where to write a payment not
/// mailed, how it says so, and the note for its payee.
struct Paying<'a> {
    max_fee: Option<u64>,
    out: Option<&'a Path>,
    json: bool,
    details: bool,
    note: &'a PaymentNote,
}

/// A payment's note, as JSON: its text and the payer's code, if any.
fn note_json(note: Option<&PaymentNote>) -> (Option<&str>, Option<String>) {
    let text = note.and_then(|n| n.text.as_deref());
    let from = note.and_then(|n| n.from.as_ref()).map(|c| c.to_string());
    (text, from)
}

/// A payment's note, as a line ends with it: its text quoted, and the
/// payer's code.
fn note_said(note: Option<&PaymentNote>) -> String {
    let Some(note) = note else {
        return String::new();
    };
    let text = (note.text.as_deref()).map(|t| format!("  \"{}\"", say::terminal(t)));
    let from = (note.from.as_ref()).map(|c| format!("  from {c}"));
    text.unwrap_or_default() + &from.unwrap_or_default()
}

/// How to reach Nostr relays: through the wallet's own Tor client, else
/// `proxy`, else directly.
fn route(tor: Option<licash_tor::Tor>, proxy: Option<&str>) -> anyhow::Result<Route> {
    Ok(match (tor, proxy) {
        (Some(tor), _) => Route::Tor(tor),
        (None, Some(proxy)) => Route::socks(proxy)?,
        (None, None) => Route::Direct,
    })
}

/// Unlink what can be: a failure leaves notes linked until the next try.
async fn unlink(wallet: &Wallet<Http>) -> Option<usize> {
    let unlinked = match wallet.unlink().await {
        Ok(unlinked) => Some(unlinked),
        Err(e) => {
            eprintln!(
                "warning: some notes stay linked for now ({}); resume unlinks them",
                say::terminal(&e.to_string())
            );
            None
        }
    };
    maintain(wallet).await;
    unlinked
}

/// A failed background optimization never turns a successful payment or
/// receipt into a failed command.
async fn maintain(wallet: &Wallet<Http>) -> Option<usize> {
    match wallet.maintain_notes().await {
        Ok(optimized) => Some(optimized),
        Err(e) => {
            eprintln!(
                "warning: note optimization deferred ({})",
                say::terminal(&e.to_string())
            );
            None
        }
    }
}

/// The hub holding the most.
fn richest(wallet: &Wallet<Http>) -> anyhow::Result<String> {
    let balance = wallet.balance()?;
    let richest = balance.into_iter().max_by_key(|b| b.available);
    Ok(richest
        .context("no hub: `licash-wallet add-hub URL` trusts one")?
        .hub)
}

/// The hub holding the most, other than `other`.
fn richest_but(wallet: &Wallet<Http>, other: &str) -> anyhow::Result<String> {
    let other = other.trim_end_matches('/');
    let balance = wallet.balance()?;
    let richest = balance
        .into_iter()
        .filter(|b| b.hub != other)
        .max_by_key(|b| b.available);
    Ok(richest
        .context("no other hub to pay at: `licash-wallet add-hub URL` trusts one")?
        .hub)
}

/// The provider to swap `amount` from hub `from` to hub `to` through
/// within `limits`: the first [`swap_providers`] finds on `relays`, else
/// on those the wallet's hubs name.
async fn find_provider(
    wallet: &Wallet<Http>,
    relays: Vec<String>,
    route: &Route,
    (from, to): (&str, &str),
    amount: u64,
    limits: SwapLimits,
) -> anyhow::Result<String> {
    let relays = match relays {
        relays if !relays.is_empty() => relays,
        _ => licash_nostr::wallet::hub_relays(wallet)?,
    };
    if relays.is_empty() {
        bail!("no relay to find a provider on: name one with --relay, or a provider");
    }
    let found = swap_providers(wallet, &relays, route, (from, to), amount, limits).await?;
    // Of those swapping that much exactly, not their least if more.
    let found = found.into_iter().find(|p| p.quote.amount == amount);
    let found = found.with_context(|| {
        format!("no provider announced swaps {amount} from {from} to {to} within the limits")
    })?;
    let (fee, known) = (found.quote.fee, found.known);
    tracing::info!(provider = %found.url, fee, known, "provider found");
    Ok(found.url)
}

/// The only hub trusted.
fn only_hub(wallet: &Wallet<Http>) -> anyhow::Result<String> {
    let hubs = wallet.hubs()?;
    match &hubs[..] {
        [(url, _)] => Ok(url.clone()),
        [] => bail!("no hub: `licash-wallet add-hub URL` trusts one"),
        _ => bail!("several hubs trusted: name one with --hub"),
    }
}

fn lock_state(state: &LockState) -> String {
    match state {
        LockState::Requested => "requested".into(),
        LockState::Locked => "locked".into(),
        LockState::Paid(_) => "paid".into(),
        LockState::Refunded => "refunded".into(),
        LockState::Abandoned(reason) => format!("abandoned ({reason})"),
        _ => "unknown".into(),
    }
}

fn lock_json(lock: &Lock) -> serde_json::Value {
    let preimage = match &lock.state {
        LockState::Paid(preimage) => Some(hex::encode(preimage)),
        _ => None,
    };
    json!({
        "id": lock.id, "hub": lock.hub, "payee": encode(&lock.payee), "amount": lock.amount,
        "fee": lock.fee, "hash": hex::encode(lock.hash), "expiry": lock.expiry,
        "state": lock_state(&lock.state), "preimage": preimage, "invoice": lock.invoice,
        "via": lock.via.as_ref().map(|v| json!({"provider": v.provider, "invoice": v.invoice})),
        "failure": lock.failure, "created_at": lock.created_at,
    })
}

fn lock_line(lock: &Lock) -> String {
    let state = match &lock.failure {
        Some(failure) => format!("{} ({failure})", lock_state(&lock.state)),
        None => lock_state(&lock.state),
    };
    format!(
        "{}  lock {}  {}  until block {}  via {}  {}",
        say::when(lock.created_at),
        state,
        say::plus(lock.amount, lock.fee),
        lock.expiry,
        lock.hub,
        lock.id
    )
}

fn invoice_state(state: &InvoiceState) -> String {
    match state {
        InvoiceState::Open => "open".into(),
        InvoiceState::Received => "received".into(),
        InvoiceState::Canceled(reason) => format!("canceled ({reason})"),
        _ => "unknown".into(),
    }
}

fn invoice_json(invoice: &Invoice) -> serde_json::Value {
    json!({
        "hash": invoice.hash, "hub": invoice.hub, "amount": invoice.amount,
        "request": invoice.request, "state": invoice_state(&invoice.state),
        "created_at": invoice.created_at, "protected": invoice.protected,
        "memo": invoice.memo,
    })
}

fn invoice_line(invoice: &Invoice) -> String {
    format!(
        "{}  invoice {}  {}  via {}{}  {}{}",
        say::when(invoice.created_at),
        invoice_state(&invoice.state),
        say::sat(invoice.amount),
        invoice.hub,
        if invoice.protected {
            " (protected)"
        } else {
            ""
        },
        invoice.hash,
        invoice
            .memo
            .as_ref()
            .map_or_else(String::new, |memo| format!("  \"{memo}\"")),
    )
}

fn deposit_state(state: &DepositState) -> String {
    match state {
        DepositState::Open => "open".into(),
        DepositState::Received => "received".into(),
        DepositState::Canceled(reason) => format!("canceled ({reason})"),
        DepositState::Refunded(txid) => format!("refunded ({txid})"),
        _ => "unknown".into(),
    }
}

fn deposit_json(deposit: &Deposit) -> serde_json::Value {
    let terms = deposit.terms.as_ref().map(|t| {
        json!({
            "address": t.address, "pays": t.pays, "fund_by": t.fund_by, "timeout": t.timeout,
            "uri": bip21(&t.address, t.pays),
        })
    });
    let funding = deposit
        .funding
        .map(|(outpoint, height)| json!({ "outpoint": outpoint.to_string(), "height": height }));
    json!({
        "hash": deposit.hash, "hub": deposit.hub, "amount": deposit.amount, "terms": terms,
        "funding": funding, "state": deposit_state(&deposit.state),
        "created_at": deposit.created_at,
    })
}

fn deposit_line(deposit: &Deposit) -> String {
    let terms = match &deposit.terms {
        Some(t) => format!(
            "  pay {} to {} by block {}",
            say::plus(deposit.amount, t.pays.saturating_sub(deposit.amount)),
            t.address,
            t.fund_by
        ),
        None => String::new(),
    };
    format!(
        "{}  deposit {}  {}  at {}  {}{terms}",
        say::when(deposit.created_at),
        deposit_state(&deposit.state),
        say::sat(deposit.amount),
        deposit.hub,
        deposit.hash
    )
}

/// A BIP21 URI paying `sat` to `address`.
fn bip21(address: &str, sat: u64) -> String {
    let btc = bitcoin::Amount::from_sat(sat).to_string_in(bitcoin::Denomination::Bitcoin);
    format!("bitcoin:{address}?amount={btc}")
}

/// A hub's address and deposit root, as `recover` is given them.
enum HubKeys {
    /// By the hub's URL, from the wallet's record of its info.
    Recorded(String),
    /// Hex: its address bytes, and its deposit root.
    Named(String, String),
}

/// Look for the payments of contracts' defaults to close deposits that the
/// wallet's seed asked of a hub, on `chain` from block `from`, and take
/// back to `to`, if given, those whose wait passed.
#[allow(clippy::too_many_arguments)]
async fn recover(
    wallet: &Wallet<Http>,
    hub: HubKeys,
    chain: &str,
    from: u32,
    coins: &[bitcoin::OutPoint],
    to: Option<String>,
    fee_rate: Option<u64>,
    json: bool,
) -> anyhow::Result<()> {
    let (address, root) = match hub {
        HubKeys::Recorded(url) => {
            let url = url.trim_end_matches('/');
            let hubs = wallet.hubs()?;
            let info = hubs
                .iter()
                .find(|(known, _)| known.trim_end_matches('/') == url)
                .map(|(_, info)| info)
                .with_context(|| format!("{url} is no hub the wallet's file records"))?;
            let root = info
                .deposits
                .as_ref()
                .and_then(|d| d.close_root)
                .with_context(|| format!("{url} published no deposit root"))?;
            (info.address.to_bytes().to_vec(), root.0)
        }
        HubKeys::Named(address, root) => {
            let mut key = [0; 32];
            hex::decode_to_slice(&root, &mut key).context("--claim-root: 32 bytes of hex")?;
            (hex::decode(&address).context("--hub-address: hex")?, key)
        }
    };
    let root = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&root).context("the deposit root")?;
    let source: licash_chain_client::Source = chain.parse().context("--chain")?;
    let blocks = onchain::Blocks(source.clone());
    let tip = source.tip().await?.height;
    let payments = wallet
        .find_close_payments(&address, &root, coins, &blocks, from)
        .await?;
    let network = licash_chain_client::network(wallet.network());
    let to = match &to {
        Some(to) => Some(
            to.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .context("--to")?
                .require_network(network)
                .with_context(|| format!("--to: not an address on {}", wallet.network()))?,
        ),
        None => None,
    };
    let mut rows = Vec::new();
    let mut lines = Vec::new();
    for payment in &payments {
        let due = payment.refund_height();
        let (status, refund) = match (payment.spent_by, &to) {
            (Some(by), _) => (format!("spent by {by}"), None),
            (None, _) if tip < due => (
                format!("refundable after block {due}, the tip is {tip}"),
                None,
            ),
            (None, None) => ("refundable now: --to takes it back".to_owned(), None),
            (None, Some(to)) => {
                let rate = onchain::rate(&source, fee_rate).await?;
                let tx = wallet.refund_close_payment(
                    &address,
                    &root,
                    payment,
                    to.script_pubkey(),
                    rate,
                )?;
                let txid = source.broadcast(&tx).await?;
                (format!("refunded by {txid}"), Some(txid))
            }
        };
        rows.push(json!({
            "coin": payment.close.coin.to_string(), "attempt": payment.close.attempt,
            "hash": hex::encode(payment.hash),
            "outpoint": payment.outpoint.to_string(), "value": payment.value,
            "height": payment.height, "refundable_after": due,
            "spent_by": payment.spent_by.map(|t| t.to_string()),
            "refund": refund.map(|t| t.to_string()), "status": status,
        }));
        lines.push(format!(
            "{} #{}  {}  block {}  {status}",
            payment.close.coin,
            payment.close.attempt,
            say::sat(payment.value),
            payment.height
        ));
    }
    if lines.is_empty() {
        lines.push("no payment to the wallet's close deposits found".to_owned());
    }
    show(json, json!(rows), lines.join("\n"));
    Ok(())
}

/// Refund deposit `hash` to `to` from what `chain` shows paid to it, once
/// its timeout passed: the refund's id, broadcast.
async fn refund(
    wallet: &Wallet<Http>,
    hash: &str,
    to: &str,
    chain: &str,
    fee_rate: Option<u64>,
) -> anyhow::Result<bitcoin::Txid> {
    let network = licash_chain_client::network(wallet.network());
    let to = to
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .context("--to")?
        .require_network(network)
        .with_context(|| format!("--to: not an address on {}", wallet.network()))?;
    let source: licash_chain_client::Source = chain.parse().context("--chain")?;
    let deposit = wallet.deposit_of(hash)?;
    if deposit.state == DepositState::Received {
        bail!("its notes were received: the coins are its hub's");
    }
    let terms = deposit
        .terms
        .as_ref()
        .context("its hub named no address: nothing was paid to it")?;
    let address = terms
        .address
        .parse::<bitcoin::Address<_>>()?
        .assume_checked();
    let tip = source.tip().await?.height;
    // A deposit that returns a contract's reserve is refundable a wait after
    // its payment, which its hub may never have seen: the network judges it.
    if let Some(due) = deposit.refund_height() {
        if tip < due {
            bail!("refundable after block {due}, the tip is {tip}");
        }
    }
    let found = source.unspent(&address).await?;
    let Some(paid) = found.first() else {
        bail!("nothing unspent pays {address}: claimed or refunded already, or never paid");
    };
    if found.len() > 1 {
        tracing::warn!(
            count = found.len(),
            "several payments to the deposit: refunding the oldest, again for the others"
        );
    }
    let rate = onchain::rate(&source, fee_rate).await?;
    let tx = wallet.refund_deposit(hash, paid.outpoint, paid.value, to.script_pubkey(), rate)?;
    source.broadcast(&tx).await
}

fn swap_state(state: &SwapState) -> String {
    match state {
        SwapState::Open => "open".into(),
        SwapState::Done => "done".into(),
        SwapState::Failed(reason) => format!("failed ({reason})"),
        _ => "unknown".into(),
    }
}

fn swap_json(swap: &Swap) -> serde_json::Value {
    json!({
        "hash": swap.hash, "provider": swap.provider, "from": swap.from, "to": swap.to,
        "amount": swap.amount, "fee": swap.fee, "lock": swap.lock, "theirs": swap.theirs,
        "state": swap_state(&swap.state), "created_at": swap.created_at,
    })
}

fn swap_line(swap: &Swap) -> String {
    format!(
        "{}  swap {}  {}  {} → {}  {}",
        say::when(swap.created_at),
        swap_state(&swap.state),
        say::plus(swap.amount, swap.fee),
        swap.from,
        swap.to,
        swap.hash
    )
}

/// 32 bytes, in hex.
fn bytes(hex: &str) -> anyhow::Result<[u8; 32]> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(hex.trim(), &mut bytes).context("not 32 bytes in hex")?;
    Ok(bytes)
}

fn state(state: &State) -> String {
    match state {
        State::Offered => "offered".into(),
        State::Signed => "signed".into(),
        State::Done => "done".into(),
        State::Abandoned(reason) => format!("abandoned ({reason})"),
        _ => "unknown".into(),
    }
}

fn show(json: bool, value: serde_json::Value, text: String) {
    if json {
        println!("{value}");
    } else if !text.is_empty() {
        println!("{}", say::terminal(&text));
    }
}

/// Draw `text` as a QR code above it, if `wanted` and stdout is a terminal:
/// scripts reading stdout get the text alone, as without `--qr`.
fn show_qr(wanted: bool, text: &str) {
    if !wanted || !std::io::stdout().is_terminal() {
        return;
    }
    match qr::draw(text) {
        Ok(drawing) => print!("{drawing}"),
        Err(e) => eprintln!("warning: {e}"),
    }
}

fn write_payment(payment: &Payment, out: Option<&Path>) -> anyhow::Result<()> {
    let text = serde_json::to_string(payment)?;
    match out {
        Some(out) => std::fs::write(out, text + "\n")
            .with_context(|| format!("writing {}", out.display()))?,
        None => writeln!(std::io::stdout(), "{text}")?,
    }
    Ok(())
}

fn read(path: &Path) -> anyhow::Result<String> {
    let mut text = String::new();
    if path == Path::new("-") {
        std::io::stdin().read_to_string(&mut text)?;
    } else {
        text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    }
    Ok(text)
}

fn encode(address: &Address) -> String {
    hex::encode(address.to_bytes())
}

fn decode(address: &str) -> anyhow::Result<Address> {
    let bytes = hex::decode(address.trim()).context("an address is hex")?;
    Address::from_bytes(&bytes).context("not an address")
}

fn default_path() -> anyhow::Result<PathBuf> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".local/share")))
        .context("no wallet file: give --wallet")?;
    Ok(data.join("licash").join("wallet.sqlite"))
}

#[cfg(test)]
mod presentation_tests {
    use super::*;

    #[test]
    fn diagnostics_are_opt_in_and_keep_explicit_filters() {
        let quiet = log_filter(None, None).to_string();
        assert!(
            quiet.contains("off") && quiet.contains("licash_wallet=warn"),
            "{quiet}"
        );
        assert_eq!(log_filter(Some(Log::Text), None).to_string(), "warn");
        assert_eq!(log_filter(Some(Log::Json), None).to_string(), "warn");
        assert_eq!(
            log_filter(None, Some("nostr_sdk=debug")).to_string(),
            "nostr_sdk=debug"
        );
    }

    #[test]
    fn relay_noise_is_hidden_but_wallet_warnings_are_not() {
        use std::sync::{Arc, Mutex};
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let capture = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(log_filter(None, None))
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(move || Capture(capture.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "nostr_sdk::relay::inner", "Connection reset");
            tracing::warn!(target: "licash_wallet::payout", "claim not broadcast: retry required");
        });
        let bytes = buffer.lock().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("claim not broadcast: retry required"),
            "{text}"
        );
        assert!(!text.contains("Connection reset"), "{text}");
    }
}
