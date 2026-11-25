//! `licash-wallet bridge`: Licash bridges, Nostr Wallet Connect services
//! keeping an account for the wallet, custodial: topped up by hand or by
//! rules, and connecting apps that pay or receive out of it.

use anyhow::{bail, Context};
use clap::{Subcommand, ValueEnum};
use licash_api::bridge::{
    Account, Activity, Budget, Connect, Connection, Direction, Period, Permission, State,
};
use licash_transport::Http;
use licash_wallet::{AddedBridge, BridgeRules, BridgeTopUp, Wallet};
use serde_json::json;

use crate::{say, show, show_qr};

#[derive(Subcommand)]
pub enum BridgeCommand {
    /// Add the bridge at URL and register the wallet's account there: with
    /// the pairing code its operator printed, if it keeps its owner's only.
    /// Added again after a restore, it finds the same account.
    Add {
        url: String,
        #[arg(long)]
        pairing: Option<String>,
    },
    /// The bridges added.
    List,
    /// The wallet's account at a bridge: its balance, connections and
    /// latest payments.
    Show {
        #[arg(long)]
        bridge: Option<String>,
    },
    /// Connect an app: a nostr+walletconnect:// URI to paste or scan in it,
    /// shown once. It pays out of the account, receives into it, or both.
    Connect {
        /// What to call it: the app it is for.
        name: String,
        #[arg(long)]
        bridge: Option<String>,
        /// May pay invoices.
        #[arg(long)]
        pay: bool,
        /// May make invoices, as Stacker News and other receiving apps ask.
        #[arg(long)]
        receive: bool,
        /// The most one payment may be, in sat, fees included.
        #[arg(long)]
        max_payment: Option<u64>,
        /// The most it pays in each --period, in sat, fees included.
        #[arg(long)]
        budget: Option<u64>,
        #[arg(long, value_enum, default_value_t = Every::Day, requires = "budget")]
        period: Every,
        /// Draw the URI as a QR code, on a terminal.
        #[arg(long)]
        qr: bool,
    },
    /// The account's Lightning Address, for payers and zaps: named NAME at
    /// the bridge's domain, or none with --clear. Its hub's fee on
    /// receiving comes out of what it is paid.
    Address {
        #[arg(required_unless_present = "clear")]
        name: Option<String>,
        #[arg(long)]
        bridge: Option<String>,
        #[arg(long, conflicts_with = "name")]
        clear: bool,
        /// Draw it as a QR code, on a terminal.
        #[arg(long)]
        qr: bool,
    },
    /// Revoke the app connected under KEY, its key in hex, for good.
    Revoke {
        key: String,
        #[arg(long)]
        bridge: Option<String>,
    },
    /// Pay AMOUNT sat into the account through a hub, its Lightning fee on
    /// top; the bridge's hub keeps its fee on receiving out of it.
    TopUp {
        amount: u64,
        #[arg(long)]
        bridge: Option<String>,
        /// Through this hub [default: the one holding the most].
        #[arg(long)]
        hub: Option<String>,
        /// The Lightning fee at most, in sat.
        #[arg(long)]
        max_fee: Option<u64>,
    },
    /// Have the bridge pay AMOUNT sat of the account back to the wallet.
    Withdraw {
        amount: u64,
        #[arg(long)]
        bridge: Option<String>,
        /// At this hub [default: the only one trusted].
        #[arg(long)]
        hub: Option<String>,
    },
    /// Top the account up by `bridge run` or `watch` once it holds less
    /// than --below sat, up to --up-to, at most --daily in any day.
    Rules {
        #[arg(long)]
        bridge: Option<String>,
        #[arg(long, required_unless_present = "clear")]
        below: Option<u64>,
        #[arg(long, required_unless_present = "clear")]
        up_to: Option<u64>,
        #[arg(long, required_unless_present = "clear")]
        daily: Option<u64>,
        /// Each top-up's Lightning fee at most, in sat.
        #[arg(long)]
        max_fee: Option<u64>,
        /// Top up by hand only.
        #[arg(long, conflicts_with_all = ["below", "up_to", "daily", "max_fee"])]
        clear: bool,
    },
    /// Top up the bridges whose rules say so, now.
    Run {
        /// Through this hub [default: the one holding the most].
        #[arg(long)]
        hub: Option<String>,
    },
    /// Freeze the bridge for good and import its notes, for a recovery
    /// contract with its hub to claim should the hub stop cooperating.
    /// It pays nothing out from then on. --out keeps the export too.
    Export {
        #[arg(long)]
        bridge: Option<String>,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Freezing it is for good, until its operator unfreezes it.
        #[arg(long)]
        yes: bool,
    },
    /// Import the notes of a frozen bridge from FILE, as `licash-bridge
    /// export` wrote them to this wallet's key there.
    Import { file: std::path::PathBuf },
    /// The notes imported, by bridge, and those a recovery claims.
    Imported,
    /// Forget the notes imported from the bridge of Nostr key SOURCE, for
    /// it to be unfrozen: refused while a recovery claims them.
    Discard { source: String },
    /// Forget the bridge: its account stays there, found again by adding it.
    Remove { url: String },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Every {
    Day,
    Week,
    Month,
    Year,
    Never,
}

impl From<Every> for Period {
    fn from(every: Every) -> Self {
        match every {
            Every::Day => Period::Daily,
            Every::Week => Period::Weekly,
            Every::Month => Period::Monthly,
            Every::Year => Period::Yearly,
            Every::Never => Period::Never,
        }
    }
}

/// The bridge at `url`, or the only one added.
fn which(wallet: &Wallet<Http>, url: Option<String>) -> anyhow::Result<String> {
    if let Some(url) = url {
        return Ok(url);
    }
    let bridges = wallet.bridges()?;
    match &bridges[..] {
        [one] => Ok(one.url.clone()),
        [] => bail!("no bridge: `licash-wallet bridge add URL` adds one"),
        _ => bail!("several bridges added: name one with --bridge"),
    }
}

fn msat_of(msat: u64) -> anyhow::Result<u64> {
    msat.checked_mul(1000).context("an amount out of range")
}

pub async fn run(wallet: &Wallet<Http>, command: BridgeCommand, json: bool) -> anyhow::Result<()> {
    match command {
        BridgeCommand::Add { url, pairing } => {
            let (added, account) = wallet.add_bridge(&url, pairing.as_deref()).await?;
            let mut text = vec![format!("added {}", added.url), bridge_text(&added)];
            text.push(account_text(&account));
            let mut shown = bridge_json(&added);
            shown["account"] = json!(account);
            show(json, shown, text.join("\n"));
        }
        BridgeCommand::List => {
            let bridges = wallet.bridges()?;
            let text = match bridges.is_empty() {
                true => "no bridge: `licash-wallet bridge add URL` adds one".into(),
                false => bridges
                    .iter()
                    .map(bridge_text)
                    .collect::<Vec<_>>()
                    .join("\n\n"),
            };
            let shown: Vec<_> = bridges.iter().map(bridge_json).collect();
            show(json, json!(shown), text);
        }
        BridgeCommand::Show { bridge } => {
            let url = which(wallet, bridge)?;
            let account = wallet.bridge_account(&url).await?;
            show(json, json!(account), account_text(&account));
        }
        BridgeCommand::Connect {
            name,
            bridge,
            pay,
            receive,
            max_payment,
            budget,
            period,
            qr,
        } => {
            let url = which(wallet, bridge)?;
            let mut permissions = Vec::new();
            if pay {
                permissions.push(Permission::Pay);
            }
            if receive {
                permissions.push(Permission::Receive);
            }
            if permissions.is_empty() {
                bail!("--pay, --receive or both: what the app may do");
            }
            let connect = Connect {
                name,
                permissions,
                max_payment: max_payment.map(msat_of).transpose()?,
                budget: match budget {
                    Some(sat) => Some(Budget {
                        amount: msat_of(sat)?,
                        period: period.into(),
                    }),
                    None => None,
                },
                expires_at: None,
            };
            let connected = wallet.bridge_connect(&url, &connect).await?;
            eprintln!("{}", say::terminal(&connection_line(&connected.connection)));
            eprintln!(
                "The URI carries the connection's secret: shown once, give it to the app only."
            );
            show_qr(qr && !json, &connected.uri);
            show(json, json!(connected), connected.uri.clone());
        }
        BridgeCommand::Address {
            name,
            bridge,
            clear,
            qr,
        } => {
            let url = which(wallet, bridge)?;
            let name = if clear { None } else { name };
            let account = wallet.bridge_username(&url, name.as_deref()).await?;
            let address = account.lightning_address.clone();
            if let Some(address) = &address {
                show_qr(qr && !json, address);
            }
            show(
                json,
                json!({ "lightning_address": address }),
                address.unwrap_or_else(|| "no Lightning Address".into()),
            );
        }
        BridgeCommand::Revoke { key, bridge } => {
            let url = which(wallet, bridge)?;
            let connection = wallet.bridge_revoke(&url, &key).await?;
            show(json, json!(connection), connection_line(&connection));
        }
        BridgeCommand::TopUp {
            amount,
            bridge,
            hub,
            max_fee,
        } => {
            let url = which(wallet, bridge)?;
            let hub = match hub {
                Some(hub) => hub,
                None => crate::richest(wallet)?,
            };
            let topped = wallet.top_up_bridge(&url, &hub, amount, max_fee).await?;
            show(json, top_up_json(&topped), top_up_text(&topped));
        }
        BridgeCommand::Withdraw {
            amount,
            bridge,
            hub,
        } => {
            let url = which(wallet, bridge)?;
            let hub = match hub {
                Some(hub) => hub,
                None => crate::only_hub(wallet)?,
            };
            let (invoice, payment) = wallet.withdraw_bridge(&url, &hub, amount).await?;
            let text = match payment.state {
                State::Settled => format!(
                    "withdrawn {} to {hub}, {} paid by the bridge on top",
                    say::sat(amount),
                    msat(payment.fee)
                ),
                State::Pending => format!(
                    "withdrawing {}: under way, `resume` takes it once paid (invoice {})",
                    say::sat(amount),
                    invoice.hash
                ),
                _ => format!(
                    "not withdrawn: {}",
                    payment
                        .failure
                        .as_deref()
                        .unwrap_or("the bridge's payment failed")
                ),
            };
            show(
                json,
                json!({ "invoice": invoice.hash, "payment": payment }),
                text,
            );
        }
        BridgeCommand::Rules {
            bridge,
            below,
            up_to,
            daily,
            max_fee,
            clear,
        } => {
            let url = which(wallet, bridge)?;
            let rules = match (clear, below, up_to, daily) {
                (true, ..) => None,
                (false, Some(below), Some(up_to), Some(daily)) => Some(BridgeRules {
                    below,
                    up_to,
                    daily,
                    max_fee,
                }),
                _ => bail!("--below, --up-to and --daily, or --clear"),
            };
            wallet.set_bridge_rules(&url, rules)?;
            let added = wallet.bridge(&url)?;
            show(json, bridge_json(&added), bridge_text(&added));
        }
        BridgeCommand::Run { hub } => {
            let hub = match hub {
                Some(hub) => hub,
                None => crate::richest(wallet)?,
            };
            let done = wallet.top_up_bridges(&hub).await?;
            if done.is_empty() && !json {
                println!("no top-up due");
            }
            for (url, topped) in done {
                match topped {
                    Ok(topped) => show(json, top_up_json(&topped), top_up_text(&topped)),
                    Err(e) => show(
                        json,
                        json!({ "bridge": url, "error": e.to_string() }),
                        format!("a top-up of {url} is due but not made: {e}"),
                    ),
                }
            }
        }
        BridgeCommand::Export { bridge, out, yes } => {
            if !yes {
                bail!("the bridge pays nothing out once exported, until its operator unfreezes it: --yes says so");
            }
            let url = which(wallet, bridge)?;
            let (imported, export) = wallet.export_bridge(&url).await?;
            if let Some(out) = out {
                std::fs::write(&out, format!("{}\n", hex::encode(&export)))?;
            }
            show(json, imported_json(&imported), imported_text(&imported));
        }
        BridgeCommand::Import { file } => {
            let text = std::fs::read_to_string(&file)?;
            let export = hex::decode(text.trim())
                .map_err(|_| anyhow::anyhow!("{}: not an export of notes", file.display()))?;
            let imported = wallet.import_notes(&export)?;
            show(json, imported_json(&imported), imported_text(&imported));
        }
        BridgeCommand::Imported => {
            let sources = wallet.imported_notes()?;
            let rows: Vec<_> = (sources.iter())
                .map(|s| {
                    json!({
                        "source": s.source,
                        "notes": s.notes,
                        "amount": s.amount,
                        "claimed": s.claimed,
                        "void": s.void,
                    })
                })
                .collect();
            let text = match sources.is_empty() {
                true => "no notes imported".to_owned(),
                false => (sources.iter())
                    .map(|s| {
                        format!(
                            "{}  {} notes, {} sat, {} claimed, {} dropped",
                            s.source, s.notes, s.amount, s.claimed, s.void
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            show(json, json!(rows), text);
        }
        BridgeCommand::Discard { source } => {
            let gone = wallet.discard_imported(&source)?;
            show(
                json,
                json!({ "discarded": gone }),
                format!("{gone} notes imported forgotten: the bridge may be unfrozen"),
            );
        }
        BridgeCommand::Remove { url } => wallet.remove_bridge(&url)?,
    }
    Ok(())
}

/// Top up the bridges whose rules say so, as `watch` does every look:
/// warned of on stderr if they cannot be.
pub async fn top_up_due(wallet: &Wallet<Http>, json: bool) {
    let ruled = wallet
        .bridges()
        .is_ok_and(|bridges| bridges.iter().any(|b| b.rules.is_some()));
    if !ruled {
        return;
    }
    let done = match crate::richest(wallet) {
        Ok(hub) => wallet
            .top_up_bridges(&hub)
            .await
            .map_err(anyhow::Error::from),
        Err(e) => Err(e),
    };
    match done {
        Ok(done) => {
            for (url, topped) in done {
                match topped {
                    Ok(topped) => show(
                        json,
                        json!({ "bridge_top_up": top_up_json(&topped) }),
                        top_up_text(&topped),
                    ),
                    Err(e) => eprintln!(
                        "warning: a top-up of {url} is due but not made ({})",
                        say::terminal(&e.to_string())
                    ),
                }
            }
        }
        Err(e) => eprintln!(
            "warning: no bridge topped up ({})",
            say::terminal(&format!("{e:#}"))
        ),
    }
}

/// An amount in msat, as sat: `1,234 sat`, or `1,234.567 sat`.
fn msat(msat: u64) -> String {
    match msat % 1000 {
        0 => say::sat(msat / 1000),
        rest => format!("{}.{rest:03} sat", say::grouped(msat / 1000)),
    }
}

fn bridge_json(added: &AddedBridge) -> serde_json::Value {
    json!({
        "url": added.url,
        "info": added.info,
        "rules": added.rules.map(|r| json!({
            "below": r.below, "up_to": r.up_to, "daily": r.daily, "max_fee": r.max_fee,
        })),
        "created_at": added.created_at,
    })
}

fn bridge_text(added: &AddedBridge) -> String {
    let info = &added.info;
    let mut lines = vec![format!(
        "{}{}",
        added.url,
        info.name
            .as_deref()
            .map(|n| format!(" ({n})"))
            .unwrap_or_default()
    )];
    let who = if info.open {
        "anyone's accounts"
    } else {
        "its owner's account"
    };
    lines.push(format!(
        "  Keeps    {who}, custodial, through hub {}",
        info.hub
    ));
    lines.push(format!(
        "  Fee      {} on receiving, the hub's",
        say::fee(info.receive_fee.base, info.receive_fee.ppm)
    ));
    if let Some(max) = info.max_balance {
        lines.push(format!("  Holds    {} at most", msat(max)));
    }
    if let Some(address) = &info.lightning_address {
        lines.push(format!("  Address  @{address}"));
    }
    lines.push(match added.rules {
        Some(r) => format!(
            "  Rules    below {}, up to {}, {} a day at most",
            say::sat(r.below),
            say::sat(r.up_to),
            say::sat(r.daily)
        ),
        None => "  Rules    none: topped up by hand".into(),
    });
    lines.join("\n")
}

fn account_text(account: &Account) -> String {
    let mut lines = vec![format!("Balance  {}", msat(account.balance))];
    if account.reserved > 0 {
        lines.push(format!(
            "Held     {} for payments under way",
            msat(account.reserved)
        ));
    }
    if let Some(address) = &account.lightning_address {
        lines.push(format!("Address  {address}"));
    }
    let live: Vec<_> = account.connections.iter().filter(|c| !c.revoked).collect();
    if !live.is_empty() {
        lines.push(String::new());
        lines.push("Connections".into());
        lines.extend(live.iter().map(|c| format!("  {}", connection_line(c))));
    }
    if !account.activity.is_empty() {
        lines.push(String::new());
        lines.push("Latest".into());
        lines.extend(account.activity.iter().take(10).map(activity_line));
    }
    lines.join("\n")
}

fn connection_line(c: &Connection) -> String {
    let may = c
        .permissions
        .iter()
        .map(|p| match p {
            Permission::Pay => "pays",
            Permission::Receive => "receives",
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut line = format!("{} ({may})", c.name);
    if let Some(budget) = c.budget {
        let per = match budget.period {
            Period::Daily => " a day",
            Period::Weekly => " a week",
            Period::Monthly => " a month",
            Period::Yearly => " a year",
            Period::Never => "",
        };
        line.push_str(&format!(
            ", {} of {}{per} spent",
            msat(c.spent),
            msat(budget.amount)
        ));
    }
    if c.revoked {
        line.push_str(", revoked");
    }
    format!("{line}\n    key {}", c.key)
}

fn activity_line(a: &Activity) -> String {
    let (sign, what) = match a.direction {
        Direction::Incoming => ("+", "in"),
        Direction::Outgoing => ("-", "out"),
    };
    let state = match a.state {
        State::Pending => "pending",
        State::Settled => "settled",
        State::Failed => "failed",
        State::Expired => "expired",
    };
    let description = a
        .description
        .as_deref()
        .map(|d| format!("  {d}"))
        .unwrap_or_default();
    format!(
        "  {}  {sign}{} {what}, {state}{description}",
        say::when(a.created_at),
        msat(a.amount)
    )
}

fn top_up_json(topped: &BridgeTopUp) -> serde_json::Value {
    json!({
        "bridge": topped.url, "invoice": topped.invoice, "lock": crate::lock_json(&topped.lock),
    })
}

fn top_up_text(topped: &BridgeTopUp) -> String {
    format!(
        "topping up {} with {}, {} credited once paid (lock {})",
        topped.url,
        msat(topped.invoice.amount),
        msat(topped.invoice.credits),
        topped.lock.id
    )
}

fn imported_json(imported: &licash_wallet::Imported) -> serde_json::Value {
    json!({
        "source": imported.source,
        "added": imported.added,
        "amount": imported.amount,
        "known": imported.known,
        "unknown": imported.unknown,
    })
}

fn imported_text(imported: &licash_wallet::Imported) -> String {
    let mut text = format!(
        "{} notes worth {} sat imported, for a recovery contract with their hub to claim \
         within what the wallet's own notes leave of its cap",
        imported.added, imported.amount
    );
    if imported.known > 0 {
        text += &format!("; {} imported before", imported.known);
    }
    if imported.unknown > 0 {
        text += &format!(
            "; {} of a keyset this wallet never held, left out",
            imported.unknown
        );
    }
    text
}
