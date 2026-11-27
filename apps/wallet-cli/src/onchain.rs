//! `licash-wallet onchain`: the coins paid on Bitcoin to the wallet's
//! silent payment and fallback addresses, found with a hub's tweaks in the
//! blocks of a chain source, spent, or moved to notes.

use anyhow::{bail, Context};
use bitcoin::{BlockHash, FeeRate};
use clap::Subcommand;
use licash_chain_client::Source;
use licash_transport::Http;
use licash_wallet::{Payee, PaymentCode, SilentCoin, Wallet};
use serde_json::json;

use crate::{deposit_json, show};

/// Blocks a scan looks in at a time, each batch recorded whole.
const BATCH: u32 = 144;

#[derive(Subcommand)]
pub enum Onchain {
    /// Look in the blocks since the last scan for payments and spends of
    /// the coins, then broadcast again the wallet's spends in no block yet.
    /// In blocks no hub trusted serves silent payment tweaks of, for the
    /// fallback addresses and the coins held only: those are looked in
    /// again for silent payments once a hub serves their tweaks.
    Scan {
        /// The block to look from: at the first scan, or an earlier one to
        /// look again [default: the first a hub trusted serves tweaks of;
        /// at the first scan with none serving them, required].
        #[arg(long)]
        from: Option<u32>,
    },
    /// The coins found, not spent in a block yet: with --chain, looked for
    /// first up to the chain's height, as `scan` does.
    Coins,
    /// Pay AMOUNT to TO, a Bitcoin address, a silent payment address or a
    /// payment code naming either, the fee on top, from one coin alone,
    /// never joined with another: its transaction id.
    Send {
        to: String,
        /// In satoshis [default: what the code asks for].
        amount: Option<u64>,
        /// From this coin, `TXID:VOUT` [default: the largest, if it pays
        /// it alone].
        #[arg(long)]
        coin: Option<bitcoin::OutPoint>,
        /// The whole coin of --coin, the fee taken from it.
        #[arg(long, conflicts_with = "amount", requires = "coin")]
        all: bool,
        /// In sat/vB [default: the chain's estimate within 6 blocks, at
        /// least 1].
        #[arg(long)]
        fee_rate: Option<u64>,
    },
    /// Move one coin, whole, to notes at a hub taking deposits, or through
    /// a swap provider taking them, never joined with another nor leaving
    /// change: the deposit, which `resume` takes the notes of once its
    /// payment confirmed (`resume --chain` through a provider).
    Move {
        /// At this hub [default: the first trusted taking deposits, or the
        /// first trusted with --via].
        #[arg(long)]
        hub: Option<String>,
        /// Through the swap provider at this URL, for its notes at the hub.
        #[arg(long)]
        via: Option<String>,
        /// This coin, `TXID:VOUT` [default: the largest free].
        #[arg(long)]
        coin: Option<bitcoin::OutPoint>,
        /// In sat/vB [default: the chain's estimate within 6 blocks, at
        /// least 1].
        #[arg(long)]
        fee_rate: Option<u64>,
    },
}

/// A chain source as the wallet reads Bitcoin through it.
pub(crate) struct Blocks(pub(crate) Source);

fn text(e: anyhow::Error) -> String {
    format!("{e:#}")
}

impl licash_wallet::Blocks for Blocks {
    async fn height(&self) -> Result<u32, String> {
        Ok(self.0.tip().await.map_err(text)?.height)
    }

    async fn hash(&self, height: u32) -> Result<BlockHash, String> {
        self.0.hash(height).await.map_err(text)
    }

    async fn filter(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, String> {
        self.0.filter(hash).await.map_err(text)
    }

    async fn block(&self, hash: &BlockHash) -> Result<bitcoin::Block, String> {
        self.0.block(hash).await.map_err(text)
    }
}

pub async fn run(
    wallet: &Wallet<Http>,
    chain: Option<String>,
    command: Onchain,
    json: bool,
) -> anyhow::Result<()> {
    let source = || -> anyhow::Result<Source> {
        let chain = chain.as_deref().context(
            "--chain: Bitcoin Core as http://user:password@127.0.0.1:8332, \
             or Esplora as esplora+https://esplora.example/api",
        )?;
        chain.parse().context("--chain")
    };
    // Caught up first, implicitly, with a chain to read: the coins as
    // the chain has them, without a scan asked for.
    if chain.is_some() && !matches!(command, Onchain::Scan { .. }) {
        if let Err(e) = catch_up(wallet, &source()?, None).await {
            tracing::warn!("coins not looked for: {e:#}");
        }
    }
    match command {
        Onchain::Scan { from } => scan(wallet, &source()?, from, json).await,
        Onchain::Coins => {
            let coins = wallet.silent_coins()?;
            let total: u64 = coins.iter().map(|c| c.value).sum();
            let mut lines: Vec<String> = coins.iter().map(coin_line).collect();
            lines.push(format!("total  {}", crate::say::sat(total)));
            show(
                json,
                coins.iter().map(coin_json).collect(),
                lines.join("\n"),
            );
            Ok(())
        }
        Onchain::Send {
            to,
            amount,
            coin,
            all,
            fee_rate,
        } => {
            let source = source()?;
            let code: PaymentCode = to.parse().context("TO")?;
            let payee = payee(wallet, &code)?;
            let amount = match (amount, code.amount, all) {
                (_, _, true) => None,
                (Some(given), Some(asked), _) if given != asked => {
                    bail!("the code asks for {asked}, not {given}")
                }
                (Some(amount), _, _) | (None, Some(amount), _) => Some(amount),
                (None, None, false) => bail!("the code does not say how much: an AMOUNT or --all"),
            };
            let rate = rate(&source, fee_rate).await?;
            let coin = match (coin, amount) {
                (Some(coin), _) => coin,
                (None, Some(amount)) => wallet
                    .silent_coin_paying(&payee, amount, rate)?
                    .with_context(|| {
                        format!("no one coin pays {amount} sat and its fee: coins are never joined")
                    })?,
                (None, None) => bail!("--all sends the coin of --coin whole"),
            };
            let tx = wallet.spend_silent_coin(payee, coin, amount, rate)?;
            let txid = broadcast(&source, &tx).await?;
            let paid = tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
            show(
                json,
                json!({ "txid": txid.to_string(), "outputs": paid, "vsize": tx.vsize() }),
                txid.to_string(),
            );
            Ok(())
        }
        Onchain::Move {
            hub,
            via,
            coin,
            fee_rate,
        } => {
            let source = source()?;
            let hub = match (hub, &via) {
                (Some(hub), _) => hub,
                (None, Some(_)) => match wallet.hubs()?.into_iter().next() {
                    Some((url, _)) => url,
                    None => bail!("no hub trusted"),
                },
                (None, None) => {
                    let hubs = wallet.hubs()?.into_iter();
                    let mut taking = hubs.filter(|(_, info)| info.deposits.is_some());
                    match taking.next() {
                        Some((url, _)) => url,
                        None => bail!("no hub trusted takes deposits"),
                    }
                }
            };
            let rate = rate(&source, fee_rate).await?;
            let coin = match coin {
                Some(coin) => coin,
                None => (wallet.silent_coins()?.into_iter())
                    .filter(|c| c.spending.is_none())
                    .max_by_key(|c| c.value)
                    .map(|c| c.outpoint)
                    .context("no free coin to move")?,
            };
            let (deposit, tx) = match &via {
                Some(provider) => {
                    (wallet.deposit_silent_through(provider, &hub, coin, rate)).await?
                }
                None => wallet.deposit_silent(&hub, coin, rate).await?,
            };
            let txid = broadcast(&source, &tx).await?;
            eprintln!(
                "deposit {}: {} sat in notes once {txid} confirms; `licash-wallet resume` takes them",
                deposit.hash, deposit.amount
            );
            let mut shown = deposit_json(&deposit);
            shown["txid"] = json!(txid.to_string());
            show(json, shown, deposit.hash.clone());
            Ok(())
        }
    }
}

/// Scan from the next block to the chain's height, as [`catch_up`], and
/// say what was found.
async fn scan(
    wallet: &Wallet<Http>,
    source: &Source,
    from: Option<u32>,
    json: bool,
) -> anyhow::Result<()> {
    let CaughtUp {
        found,
        spent,
        fetched,
        scanned,
        without,
    } = catch_up(wallet, source, from).await?;
    let value: u64 = found.iter().map(|c| c.value).sum();
    let behind = match scanned.next > scanned.height {
        true => String::new(),
        false => format!(
            " (the hub's tweaks stop there, the chain is at {})",
            scanned.height
        ),
    };
    let without_text = match without {
        true => " (some without tweaks: the fallback addresses only)",
        false => "",
    };
    show(
        json,
        json!({
            "next": scanned.next, "height": scanned.height, "fetched": fetched,
            "found": found.iter().map(coin_json).collect::<Vec<_>>(),
            "spent": spent.iter().map(|o| o.to_string()).collect::<Vec<_>>(),
            "tweaks": !without,
        }),
        format!(
            "found {} {} of {}, {} spent; looked up to block {}{behind}{without_text}",
            found.len(),
            if found.len() == 1 { "coin" } else { "coins" },
            crate::say::sat(value),
            spent.len(),
            scanned.next.saturating_sub(1)
        ),
    );
    Ok(())
}

/// What [`catch_up`] found: the coins found and spent, the blocks fetched,
/// the last batch, and whether some blocks were looked in without tweaks.
pub struct CaughtUp {
    pub found: Vec<licash_wallet::SilentCoin>,
    pub spent: Vec<bitcoin::OutPoint>,
    pub fetched: u32,
    pub scanned: licash_wallet::Scanned,
    pub without: bool,
}

/// Scan from the next block (`from` if named) to the chain's height, with
/// the tweaks of every hub trusted serving them, those of a block any of
/// them serves, and without in blocks none serves tweaks of; then
/// broadcast again the spends in no block yet. Refused for a wallet
/// watching nothing yet, no hub serving tweaks, `from` not named.
pub async fn catch_up(
    wallet: &Wallet<Http>,
    source: &Source,
    from: Option<u32>,
) -> anyhow::Result<CaughtUp> {
    let earliest = wallet
        .hubs()?
        .into_iter()
        .filter_map(|(_, i)| i.tweaks)
        .min();
    match (from, wallet.silent_next()?, earliest) {
        (Some(from), ..) => wallet.watch_silent(None, from)?,
        (None, None, Some(first)) => wallet.watch_silent(None, first)?,
        (None, None, None) => bail!(
            "no hub trusted serves silent payment tweaks: name the block to look from, --from HEIGHT"
        ),
        (None, Some(_), _) => {}
    }
    let chain = Blocks(source.clone());
    let (mut found, mut spent, mut fetched) = (Vec::new(), Vec::new(), 0);
    let mut without = false;
    let scanned = loop {
        let next = wallet.silent_next()?.expect("watching");
        let (scanned, tweaks) = wallet.scan_silent_trusted(&chain, BATCH, None).await?;
        without |= !tweaks;
        tracing::info!(
            next = scanned.next,
            height = scanned.height,
            tweaks,
            "scanned"
        );
        found.extend(scanned.found.iter().cloned());
        spent.extend(scanned.spent.iter().copied());
        fetched += scanned.fetched;
        // Caught up, or at the newest block the hubs indexed.
        if scanned.next > scanned.height || scanned.next == next {
            break scanned;
        }
    };
    for tx in wallet.silent_spends()? {
        if let Err(e) = source.broadcast(&tx).await {
            tracing::warn!(txid = %tx.compute_txid(), "broadcasting again: {e:#}");
        }
    }
    Ok(CaughtUp {
        found,
        spent,
        fetched,
        scanned,
        without,
    })
}

/// Whom `code` names to pay on Bitcoin: its silent payment address, else
/// its address, of the wallet's network.
fn payee(wallet: &Wallet<Http>, code: &PaymentCode) -> anyhow::Result<Payee> {
    if let Some(silent) = code.silent {
        return Ok(silent.into());
    }
    let Some(address) = &code.address else {
        bail!("TO names no address on Bitcoin");
    };
    let network = licash_chain_client::network(wallet.network());
    let address = address
        .clone()
        .require_network(network)
        .with_context(|| format!("TO: not an address on {}", wallet.network()))?;
    Ok(address.script_pubkey().into())
}

/// `sat_per_vb`, else what `source` estimates confirms within 6 blocks, at
/// least the least relayed.
pub async fn rate(source: &Source, sat_per_vb: Option<u64>) -> anyhow::Result<FeeRate> {
    Ok(match sat_per_vb {
        Some(rate) => FeeRate::from_sat_per_vb(rate).context("--fee-rate")?,
        None => source
            .fee_rate(6)
            .await?
            .unwrap_or(FeeRate::BROADCAST_MIN)
            .max(FeeRate::BROADCAST_MIN),
    })
}

/// Broadcast the wallet's spend `tx`. An error may follow relay, so keep
/// the signed transaction and its reserved inputs for retry or inspection.
async fn broadcast(source: &Source, tx: &bitcoin::Transaction) -> anyhow::Result<bitcoin::Txid> {
    match source.broadcast(tx).await {
        Ok(txid) => Ok(txid),
        Err(e) => Err(e.context(format!(
            "broadcast outcome unknown; transaction {} and its coins are kept for retry",
            tx.compute_txid()
        ))),
    }
}

fn coin_json(coin: &SilentCoin) -> serde_json::Value {
    json!({
        "outpoint": coin.outpoint.to_string(), "value": coin.value, "height": coin.height,
        "change": coin.change, "spending": coin.spending.map(|t| t.to_string()),
    })
}

fn coin_line(coin: &SilentCoin) -> String {
    let value = crate::say::sat(coin.value);
    let mut line = format!("{}  {value}  block {}", coin.outpoint, coin.height);
    if coin.change {
        line.push_str("  change");
    }
    if let Some(txid) = coin.spending {
        line.push_str(&format!("  spending in {txid}"));
    }
    line
}
