//! Reads Bitcoin for Licash services, block by block, from Bitcoin Core's
//! JSON-RPC or from an Esplora REST server, as a [`Source`] URL names it.

use std::{collections::HashMap, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{bail, ensure, Context};
use bitcoin::{
    block::Header,
    consensus::{deserialize, encode::serialize_hex, serialize},
    hashes::Hash,
    Address, Amount, Block, BlockHash, FeeRate, Network, OutPoint, ScriptBuf, Transaction, Txid,
};
use licash::{chain::Checkpoint, spend::ChainProfile};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use url::Url;

/// A chain to read, by URL:
///
/// - `http[s]://[user:pass@]host:port[?cookie=PATH]`: Bitcoin Core's
///   JSON-RPC, with a password or the node's cookie file;
/// - `esplora+http[s]://host[:port][/path]`: an Esplora REST API, such as
///   `esplora+https://esplora.example/api`.
///
/// It shows as its scheme, host and path, never its credentials.
#[derive(Clone)]
pub struct Source {
    kind: Kind,
    shown: String,
    client: reqwest::Client,
}

#[derive(Clone)]
enum Kind {
    Rpc { url: Url, auth: Auth },
    Esplora { base: String },
}

#[derive(Clone)]
enum Auth {
    None,
    Password { user: String, pass: String },
    Cookie(PathBuf),
}

/// The best block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    pub height: u32,
    pub hash: BlockHash,
}

impl FromStr for Source {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        let mut url = Url::parse(text.trim()).map_err(|e| anyhow::anyhow!("chain URL: {e}"))?;
        let host = url.host_str().context("chain URL: no host")?.to_owned();
        let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let path = url.path().trim_end_matches('/').to_owned();
        let shown = format!("{}://{host}{port}{path}", url.scheme());
        let kind = match url.scheme() {
            "http" | "https" => {
                let mut cookie = None;
                for (key, value) in url.query_pairs() {
                    ensure!(
                        key == "cookie" && cookie.is_none(),
                        "chain URL: unknown or repeated parameter {key}"
                    );
                    cookie = Some(PathBuf::from(value.into_owned()));
                }
                let auth = match (cookie, url.username(), url.password()) {
                    (Some(path), "", None) => Auth::Cookie(path),
                    (Some(_), ..) => bail!("chain URL: a cookie or a password, not both"),
                    (None, "", None) => Auth::None,
                    (None, user, pass) => Auth::Password {
                        user: decode(user),
                        pass: decode(pass.unwrap_or_default()),
                    },
                };
                url.set_query(None);
                let _ = url.set_username("");
                let _ = url.set_password(None);
                Kind::Rpc { url, auth }
            }
            "esplora+http" | "esplora+https" => {
                ensure!(
                    url.username().is_empty() && url.password().is_none() && url.query().is_none(),
                    "chain URL: Esplora takes no credentials or parameters"
                );
                let scheme = url.scheme().trim_start_matches("esplora+");
                Kind::Esplora {
                    base: format!("{scheme}://{host}{port}{path}"),
                }
            }
            other => bail!("chain URL: unknown scheme {other}: http(s) or esplora+http(s)"),
        };
        Ok(Self {
            kind,
            shown,
            client: client()?,
        })
    }
}

fn decode(part: &str) -> String {
    percent_encoding::percent_decode_str(part)
        .decode_utf8_lossy()
        .into_owned()
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.shown)
    }
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Source({})", self.shown)
    }
}

pub use licash_onchain::network;

/// A step along the best chain, of [`Source::follow`].
#[derive(Debug)]
pub enum Follow {
    /// The block at this height.
    Next(u32, Box<Block>),
    /// Forget the blocks from this height up.
    Rewind(u32),
    AtTip,
}

/// An output paying an address, unspent, confirmed at `height`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unspent {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub height: u32,
}

/// What a node answers of a transaction it already has.
const KNOWN: [&str; 3] = [
    "txn-already-known",
    "txn-already-in-mempool",
    "already in utxo set",
];

/// Whether a node's refusal of a transaction says it has it already: by
/// its message, or by the code of a transaction in the chain already, -27,
/// which mempool's backend relays alone (`{"code":-27}`) and nodes word
/// differently from version to version.
fn known(refusal: &str) -> bool {
    let refusal = refusal.replace('\\', "");
    KNOWN.iter().any(|known| refusal.contains(known))
        || refusal.contains("\"code\":-27")
        || refusal.ends_with("(-27)")
}

/// Transactions per page of an Esplora block's.
const ESPLORA_PAGE: usize = 25;

/// The most a fee rate estimated is believed: 1,000 sat/vB, above any
/// fee market Bitcoin has known.
pub const MAX_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_u32(1_000);

fn client() -> anyhow::Result<reqwest::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("licash-chain-client/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

#[derive(Deserialize)]
struct Reply<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

impl Source {
    /// The best block.
    pub async fn tip(&self) -> anyhow::Result<Tip> {
        match &self.kind {
            Kind::Rpc { .. } => {
                #[derive(Deserialize)]
                struct Info {
                    blocks: u32,
                    bestblockhash: String,
                }
                let info: Info = self.call("getblockchaininfo", json!([])).await?;
                Ok(Tip {
                    height: info.blocks,
                    hash: info.bestblockhash.parse().context("best block hash")?,
                })
            }
            Kind::Esplora { .. } => {
                let height = self.text("blocks/tip/height").await?;
                let height = height.parse().context("tip height")?;
                Ok(Tip {
                    height,
                    hash: self.hash(height).await?,
                })
            }
        }
    }

    /// The hash of the best chain's block at `height`.
    pub async fn hash(&self, height: u32) -> anyhow::Result<BlockHash> {
        match &self.kind {
            Kind::Rpc { .. } => self.call::<String>("getblockhash", json!([height])).await,
            Kind::Esplora { .. } => self.text(&format!("block-height/{height}")).await,
        }?
        .trim()
        .parse()
        .context("block hash")
    }

    pub async fn header(&self, hash: &BlockHash) -> anyhow::Result<Header> {
        let hex: String = match &self.kind {
            Kind::Rpc { .. } => {
                self.call("getblockheader", json!([hash.to_string(), false]))
                    .await?
            }
            Kind::Esplora { .. } => self.text(&format!("block/{hash}/header")).await?,
        };
        let header: Header = deserialize(&hex::decode(hex.trim())?).context("header encoding")?;
        ensure!(
            header.block_hash() == *hash,
            "header {hash} does not hash to itself"
        );
        Ok(header)
    }

    pub async fn block(&self, hash: &BlockHash) -> anyhow::Result<Block> {
        let bytes = match &self.kind {
            Kind::Rpc { .. } => {
                let hex: String = self.call("getblock", json!([hash.to_string(), 0])).await?;
                hex::decode(hex.trim())?
            }
            Kind::Esplora { base } => self
                .get(&format!("{base}/block/{hash}/raw"))
                .await?
                .bytes()
                .await?
                .to_vec(),
        };
        let block: Block = deserialize(&bytes).context("block encoding")?;
        ensure!(
            block.block_hash() == *hash,
            "block {hash} does not hash to itself"
        );
        ensure!(block.check_merkle_root(), "block {hash}: merkle root");
        Ok(block)
    }

    /// The basic compact filter (BIP158) of the block of `hash`, if the
    /// source serves them: a node indexing them (`-blockfilterindex`), as
    /// Esplora does not. A node still building its index fails.
    pub async fn filter(&self, hash: &BlockHash) -> anyhow::Result<Option<Vec<u8>>> {
        #[derive(Deserialize)]
        struct Filter {
            filter: String,
        }
        if let Kind::Esplora { .. } = &self.kind {
            return Ok(None);
        }
        let params = json!([hash.to_string(), "basic"]);
        match self.call::<Filter>("getblockfilter", params).await {
            Ok(found) => Ok(Some(hex::decode(found.filter.trim())?)),
            Err(e) if format!("{e:#}").contains("Index is not enabled") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The scripts that the transactions of `block` paying a taproot
    /// output spend, by input, in the block's order, and None for the
    /// others, its coinbase among them: what a silent payment's tweak is
    /// computed from. As the source tells: they are not checked against
    /// the outputs they name.
    pub async fn taproot_spends(
        &self,
        block: &Block,
    ) -> anyhow::Result<Vec<Option<Vec<ScriptBuf>>>> {
        let wanted: Vec<bool> = block
            .txdata
            .iter()
            .enumerate()
            .map(|(i, tx)| i > 0 && tx.output.iter().any(|o| o.script_pubkey.is_p2tr()))
            .collect();
        let mut spends = vec![None; block.txdata.len()];
        let hash = block.block_hash();
        let mut take = |i: usize, txid: &str, scripts: Vec<Option<String>>| -> anyhow::Result<()> {
            let tx = &block.txdata[i];
            ensure!(
                txid == tx.compute_txid().to_string() && scripts.len() == tx.input.len(),
                "block {hash}: the spends of transaction {i} are not its"
            );
            let scripts = scripts
                .into_iter()
                .map(|s| Ok(ScriptBuf::from_hex(&s.context("an input spends nothing")?)?))
                .collect::<anyhow::Result<_>>()
                .with_context(|| format!("block {hash}: transaction {i} ({txid})"))?;
            spends[i] = Some(scripts);
            Ok(())
        };
        match &self.kind {
            _ if !wanted.contains(&true) => {}
            Kind::Rpc { .. } => {
                #[derive(Deserialize)]
                struct Verbose {
                    tx: Vec<VerboseTx>,
                }
                #[derive(Deserialize)]
                struct VerboseTx {
                    txid: String,
                    vin: Vec<VerboseIn>,
                }
                #[derive(Deserialize)]
                struct VerboseIn {
                    prevout: Option<VerbosePrevout>,
                }
                #[derive(Deserialize)]
                struct VerbosePrevout {
                    #[serde(rename = "scriptPubKey")]
                    script: VerboseScript,
                }
                #[derive(Deserialize)]
                struct VerboseScript {
                    hex: String,
                }
                // Each input with what it spends: Bitcoin Core 23 or later.
                let verbose: Verbose = self.call("getblock", json!([hash.to_string(), 3])).await?;
                ensure!(
                    verbose.tx.len() == block.txdata.len(),
                    "block {hash}: not its transactions"
                );
                for (i, tx) in verbose.tx.into_iter().enumerate() {
                    if wanted[i] {
                        let scripts = tx.vin.into_iter();
                        take(
                            i,
                            &tx.txid,
                            scripts.map(|v| Some(v.prevout?.script.hex)).collect(),
                        )?;
                    }
                }
            }
            Kind::Esplora { base } => {
                #[derive(Deserialize)]
                struct EsploraTx {
                    txid: String,
                    vin: Vec<EsploraIn>,
                }
                #[derive(Deserialize)]
                struct EsploraIn {
                    prevout: Option<EsploraPrevout>,
                }
                #[derive(Deserialize)]
                struct EsploraPrevout {
                    scriptpubkey: String,
                }
                let scripts = |tx: EsploraTx| -> Vec<Option<String>> {
                    let inputs = tx.vin.into_iter();
                    inputs.map(|v| Some(v.prevout?.scriptpubkey)).collect()
                };
                // Asked for alone: those a page leaves out, or the spends
                // of some inputs of. mempool's backend serves ten of a
                // page's transactions, and the spends of only the first
                // thirteen inputs of each (the others "lazy"), as Esplora
                // serves all.
                let mut alone = Vec::new();
                // Only the pages, of 25 transactions, holding a wanted one.
                for start in (0..wanted.len()).step_by(ESPLORA_PAGE) {
                    let end = (start + ESPLORA_PAGE).min(wanted.len());
                    if !wanted[start..end].contains(&true) {
                        continue;
                    }
                    let url = format!("{base}/block/{hash}/txs/{start}");
                    let page: Vec<EsploraTx> = self.get(&url).await?.json().await?;
                    ensure!(
                        page.len() <= end - start,
                        "block {hash}: not its transactions"
                    );
                    let served = start + page.len();
                    for (i, tx) in (start..).zip(page) {
                        if !wanted[i] {
                            continue;
                        }
                        if tx.vin.iter().all(|v| v.prevout.is_some()) {
                            let txid = tx.txid.clone();
                            take(i, &txid, scripts(tx))?;
                        } else {
                            ensure!(
                                tx.txid == block.txdata[i].compute_txid().to_string(),
                                "block {hash}: the spends of transaction {i} are not its"
                            );
                            alone.push(i);
                        }
                    }
                    alone.extend((served..end).filter(|&i| wanted[i]));
                }
                for i in alone {
                    let txid = block.txdata[i].compute_txid();
                    let url = format!("{base}/tx/{txid}");
                    let tx: EsploraTx = self.get(&url).await?.json().await?;
                    let answered = tx.txid.clone();
                    take(i, &answered, scripts(tx))?;
                }
            }
        }
        Ok(spends)
    }

    /// What comes after `top`, the newest block a follower of the best
    /// chain read, where `ours` tells the hash it read at a height: the
    /// next block, from `first` if it read none yet; the height to forget
    /// blocks from, which left the best chain; or nothing, at the tip.
    pub async fn follow(
        &self,
        top: Option<(u32, BlockHash)>,
        first: u32,
        ours: impl Fn(u32) -> anyhow::Result<Option<BlockHash>>,
    ) -> anyhow::Result<Follow> {
        let tip = self.tip().await.context("the chain's tip")?;
        let next = top.map_or(first, |(height, _)| height + 1);
        if next > tip.height {
            // At or beyond the tip: the same chain, or one the source left.
            let Some((height, _)) = top else {
                return Ok(Follow::AtTip);
            };
            let at = height.min(tip.height);
            return Ok(match ours(at)? {
                Some(hash) if hash != self.hash(at).await? => Follow::Rewind(at),
                _ => Follow::AtTip,
            });
        }
        let hash = self.hash(next).await?;
        let block = self.block(&hash).await?;
        match top {
            Some((height, hash)) if block.header.prev_blockhash != hash => {
                Ok(Follow::Rewind(height))
            }
            _ => Ok(Follow::Next(next, Box::new(block))),
        }
    }

    /// Hand `tx` to the network: its id. One the source already has, in
    /// its mempool or its chain, is no error.
    pub async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<Txid> {
        let hex = serialize_hex(tx);
        let refused = match &self.kind {
            Kind::Rpc { .. } => {
                let sent: anyhow::Result<String> =
                    self.call("sendrawtransaction", json!([hex])).await;
                sent.err().map(|e| format!("{e:#}"))
            }
            Kind::Esplora { base } => {
                let url = format!("{base}/tx");
                // mempool's backend reads the body only as text/plain:
                // otherwise Core gets nothing and answers code -1.
                let response = self
                    .client
                    .post(&url)
                    .header(reqwest::header::CONTENT_TYPE, "text/plain")
                    .body(hex)
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("{self}: {}", e.without_url()))?;
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                (!status.is_success()).then(|| format!("{self}: {url}: HTTP {status}: {text}"))
            }
        };
        match refused {
            Some(e) if !known(&e) => bail!("broadcast: {e}"),
            _ => Ok(tx.compute_txid()),
        }
    }

    /// Whether the source holds `txid`: in its mempool, or, an Esplora's,
    /// in its chain too.
    pub async fn holds(&self, txid: &Txid) -> anyhow::Result<bool> {
        match &self.kind {
            Kind::Rpc { .. } => {
                let entry: anyhow::Result<Value> = self
                    .call("getmempoolentry", json!([txid.to_string()]))
                    .await;
                match entry {
                    Ok(_) => Ok(true),
                    // RPC_INVALID_ADDRESS_OR_KEY: not in its mempool.
                    Err(e) if format!("{e:#}").contains("(-5)") => Ok(false),
                    Err(e) => Err(e),
                }
            }
            Kind::Esplora { base } => {
                // The transaction, not its status: Blockstream's electrs
                // answers `{"confirmed":false}` for one it never saw.
                let url = format!("{base}/tx/{txid}");
                let response = self
                    .client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("{self}: {}", e.without_url()))?;
                match response.status() {
                    reqwest::StatusCode::NOT_FOUND => Ok(false),
                    status if status.is_success() => Ok(true),
                    status => bail!("{self}: {url}: HTTP {status}"),
                }
            }
        }
    }

    /// Hand `txs` to the network as one package, a child after its
    /// parents: a parent paying less than the source's mempool takes alone
    /// relays with the child paying for both. Where the source takes no
    /// package (a node older than 28, an Esplora without `/txs/package`),
    /// or refuses it, each goes in turn, as [`Source::broadcast`]: its
    /// refusal is the error. Their ids.
    pub async fn broadcast_package(&self, txs: &[Transaction]) -> anyhow::Result<Vec<Txid>> {
        if txs.len() > 1 && self.submit_package(txs).await.is_ok() {
            return Ok(txs.iter().map(Transaction::compute_txid).collect());
        }
        let mut ids = Vec::with_capacity(txs.len());
        for tx in txs {
            ids.push(self.broadcast(tx).await?);
        }
        Ok(ids)
    }

    /// `submitpackage`, from the node or Esplora's `/txs/package`: an
    /// error unless every transaction is in the mempool after.
    async fn submit_package(&self, txs: &[Transaction]) -> anyhow::Result<()> {
        let hexes: Vec<String> = txs.iter().map(serialize_hex).collect();
        let result: Value = match &self.kind {
            Kind::Rpc { .. } => self.call("submitpackage", json!([hexes])).await?,
            Kind::Esplora { base } => {
                let url = format!("{base}/txs/package");
                let response = self
                    .client
                    .post(&url)
                    .json(&hexes)
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("{self}: {}", e.without_url()))?;
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                ensure!(status.is_success(), "{self}: {url}: HTTP {status}: {text}");
                serde_json::from_str(&text).with_context(|| format!("{self}: {url}: {text}"))?
            }
        };
        ensure!(
            result["package_msg"] == "success",
            "{self}: package refused: {result}"
        );
        Ok(())
    }

    /// The fee rate the source estimates confirms a transaction within
    /// `blocks`: None while it has no estimate, as on a chain of few
    /// transactions, or one of no fee, or not a number. An estimate above
    /// [`MAX_FEE_RATE`] is refused: no source sane says so.
    pub async fn fee_rate(&self, blocks: u16) -> anyhow::Result<Option<FeeRate>> {
        let rate = self.estimate(blocks).await?;
        if let Some(rate) = rate.filter(|r| *r > MAX_FEE_RATE) {
            anyhow::bail!(
                "{self}: an estimate of {} sat/vB, above {} sat/vB",
                rate.to_sat_per_vb_ceil(),
                MAX_FEE_RATE.to_sat_per_vb_ceil()
            );
        }
        Ok(rate)
    }

    /// [`Source::fee_rate`], unbounded above.
    async fn estimate(&self, blocks: u16) -> anyhow::Result<Option<FeeRate>> {
        // From satoshis per thousand virtual bytes, rounded up: none of no
        // fee or not a number, as Core's -1 of none.
        let rate = |sat_per_kvb: f64| {
            (sat_per_kvb.is_finite() && sat_per_kvb > 0.0).then(|| {
                let sat_per_kvb = sat_per_kvb.round().max(1.0) as u64;
                FeeRate::from_sat_per_kwu(sat_per_kvb.div_ceil(4))
            })
        };
        match &self.kind {
            Kind::Rpc { .. } => {
                #[derive(Deserialize)]
                struct Estimate {
                    /// In bitcoins per thousand virtual bytes.
                    feerate: Option<f64>,
                }
                let estimate: Estimate = self.call("estimatesmartfee", json!([blocks])).await?;
                Ok(estimate.feerate.and_then(|btc| rate(btc * 1e8)))
            }
            Kind::Esplora { base } => {
                let url = format!("{base}/fee-estimates");
                let response = self
                    .client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("{self}: {}", e.without_url()))?;
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    return self.recommended(base, blocks).await.map(|r| rate(r * 1e3));
                }
                let status = response.status();
                ensure!(status.is_success(), "{self}: {url}: HTTP {status}");
                let estimates: HashMap<String, f64> = response.json().await?;
                let mut estimates: Vec<(u16, FeeRate)> = estimates
                    .into_iter()
                    .filter_map(|(target, r)| Some((target.parse().ok()?, rate(r * 1e3)?)))
                    .collect();
                estimates.sort_by_key(|(target, _)| *target);
                // The latest within `blocks`, else the soonest.
                let within = estimates.iter().rev().find(|(target, _)| *target <= blocks);
                Ok(within.or(estimates.first()).map(|(_, r)| *r))
            }
        }
    }

    /// What mempool's backend, which serves no `fee-estimates`, recommends
    /// paying to confirm within `blocks`, in sat/vB: in the next block, in
    /// about three, six, or later.
    async fn recommended(&self, base: &str, blocks: u16) -> anyhow::Result<f64> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Recommended {
            fastest_fee: f64,
            half_hour_fee: f64,
            hour_fee: f64,
            economy_fee: f64,
        }
        let url = format!("{base}/v1/fees/recommended");
        let fees: Recommended = self.get(&url).await?.json().await?;
        Ok(match blocks {
            0..=1 => fees.fastest_fee,
            2..=3 => fees.half_hour_fee,
            4..=6 => fees.hour_fee,
            _ => fees.economy_fee,
        })
    }

    /// The outputs paying `address` that are confirmed and unspent, as the
    /// source tells: a node scans its whole set of them, which takes a
    /// while on a large chain.
    pub async fn unspent(&self, address: &Address) -> anyhow::Result<Vec<Unspent>> {
        let parse = |txid: &str, vout, sat, height| {
            Ok(Unspent {
                outpoint: OutPoint {
                    txid: txid.parse().context("a txid")?,
                    vout,
                },
                value: Amount::from_sat(sat),
                height,
            })
        };
        let mut unspent = match &self.kind {
            Kind::Rpc { .. } => {
                #[derive(Deserialize)]
                struct Scan {
                    unspents: Vec<Found>,
                }
                #[derive(Deserialize)]
                struct Found {
                    txid: String,
                    vout: u32,
                    /// In bitcoins.
                    amount: f64,
                    height: u32,
                }
                let descriptor = json!([{ "desc": format!("addr({address})") }]);
                let scan: Scan = self
                    .call("scantxoutset", json!(["start", descriptor]))
                    .await?;
                let found = scan.unspents.into_iter();
                found
                    .map(|f| parse(&f.txid, f.vout, (f.amount * 1e8).round() as u64, f.height))
                    .collect::<anyhow::Result<Vec<_>>>()?
            }
            Kind::Esplora { base } => {
                #[derive(Deserialize)]
                struct Found {
                    txid: String,
                    vout: u32,
                    value: u64,
                    status: Status,
                }
                #[derive(Deserialize)]
                struct Status {
                    block_height: Option<u32>,
                }
                let url = format!("{base}/address/{address}/utxo");
                let found: Vec<Found> = self.get(&url).await?.json().await?;
                let confirmed = found.into_iter().filter_map(|f| {
                    let height = f.status.block_height?;
                    Some(parse(&f.txid, f.vout, f.value, height))
                });
                confirmed.collect::<anyhow::Result<Vec<_>>>()?
            }
        };
        unspent.sort_by_key(|u| (u.height, u.outpoint));
        Ok(unspent)
    }

    /// The network, from the node or from its genesis block.
    pub async fn network(&self) -> anyhow::Result<Network> {
        let genesis = self.hash(0).await?;
        [
            Network::Bitcoin,
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ]
        .into_iter()
        .find(|n| bitcoin::constants::genesis_block(*n).block_hash() == genesis)
        .with_context(|| format!("unknown genesis block {genesis}"))
    }

    /// The checkpoint profile of the chain, from its genesis block and its
    /// block 1, which tells the signets apart: refused for a chain Licash
    /// has none for, such as testnet or a signet other than Mutinynet.
    pub async fn profile(&self) -> anyhow::Result<ChainProfile> {
        let genesis = self.hash(0).await?.to_byte_array();
        let first = match self.tip().await?.height {
            0 => None,
            _ => Some(self.hash(1).await?.to_byte_array()),
        };
        ChainProfile::identify(&genesis, first.as_ref()).context(
            "a chain Licash has no checkpoint profile for: bitcoin, regtest, signet or mutinynet",
        )
    }

    /// The checkpoint at `height` of the best chain: its header, the times
    /// of the eleven blocks to it and, where the difficulty retargets, the
    /// time of the first block of its retarget period.
    pub async fn checkpoint(&self, height: u32) -> anyhow::Result<Checkpoint> {
        let profile = self.profile().await?;
        let mut headers: Vec<Header> = Vec::new();
        for h in height.saturating_sub(10)..=height {
            let header = self.header(&self.hash(h).await?).await?;
            if let Some(previous) = headers.last() {
                // The chain moved while it was read.
                ensure!(
                    header.prev_blockhash == previous.block_hash(),
                    "the chain changed while the checkpoint was read: retry"
                );
            }
            headers.push(header);
        }
        let anchor = *headers.last().expect("at least the anchor");
        let period_start = match profile.retarget_interval() {
            Some(interval) => {
                let first = height - height % interval;
                Some(self.header(&self.hash(first).await?).await?.time)
            }
            None => None,
        };
        let bytes = serialize(&anchor).try_into().expect("a header is 80 bytes");
        let times = headers.iter().map(|h| h.time).collect();
        Checkpoint::new(profile, height, bytes, times, period_start)
            .map_err(|e| anyhow::anyhow!("checkpoint at {height}: {e}"))
    }

    /// Call `method` of the node's JSON-RPC with `params`, for what this
    /// client does not wrap, as its wallet's calls. Refused on an Esplora
    /// API.
    pub async fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> anyhow::Result<T> {
        ensure!(
            matches!(self.kind, Kind::Rpc { .. }),
            "{self}: {method} needs a node's JSON-RPC"
        );
        self.call(method, params).await
    }

    /// A JSON-RPC method whose successful result may be null, as
    /// `gettxout` for an absent or spent coin. RPC failures remain errors.
    pub async fn rpc_optional<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> anyhow::Result<Option<T>> {
        ensure!(
            matches!(self.kind, Kind::Rpc { .. }),
            "{self}: {method} needs a node's JSON-RPC"
        );
        self.call_optional(method, params).await
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> anyhow::Result<T> {
        self.call_optional(method, params)
            .await?
            .with_context(|| format!("{self}: {method}: no result"))
    }

    async fn call_optional<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> anyhow::Result<Option<T>> {
        let Kind::Rpc { url, auth } = &self.kind else {
            unreachable!("JSON-RPC on a node");
        };
        let body = json!({"jsonrpc": "1.0", "id": "licash", "method": method, "params": params});
        let mut request = self.client.post(url.clone()).json(&body);
        request = match auth {
            Auth::None => request,
            Auth::Password { user, pass } => request.basic_auth(user, Some(pass)),
            Auth::Cookie(path) => {
                // Read each time: the node writes a new one when it starts.
                let cookie = std::fs::read_to_string(path)
                    .with_context(|| format!("cookie {}", path.display()))?;
                let (user, pass) = cookie
                    .trim()
                    .split_once(':')
                    .with_context(|| format!("cookie {}: not user:password", path.display()))?;
                request.basic_auth(user, Some(pass))
            }
        };
        let response = request
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{self}: {method}: {}", e.without_url()))?;
        let status = response.status();
        ensure!(
            status != reqwest::StatusCode::UNAUTHORIZED,
            "{self}: {method}: unauthorized, check the credentials"
        );
        let reply: Reply<T> = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("{self}: {method}: HTTP {status}: {}", e.without_url()))?;
        if let Some(e) = reply.error {
            bail!("{self}: {method}: {} ({})", e.message, e.code);
        }
        Ok(reply.result)
    }

    async fn text(&self, path: &str) -> anyhow::Result<String> {
        let Kind::Esplora { base } = &self.kind else {
            unreachable!("REST on Esplora");
        };
        Ok(self.get(&format!("{base}/{path}")).await?.text().await?)
    }

    /// GET `url` of an Esplora: asked again, as it tells (`Retry-After`)
    /// or after a wait twice as long each time, while it limits the rate
    /// it answers at or is overloaded, for [`MOST_THROTTLED`] at most. A
    /// scan of thousands of blocks goes at the rate it allows, rather than
    /// failing partway to start over.
    async fn get(&self, url: &str) -> anyhow::Result<reqwest::Response> {
        let mut waited = Duration::ZERO;
        let mut backoff = Duration::from_secs(1);
        loop {
            let response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("{self}: {}", e.without_url()))?;
            let status = response.status();
            if let Some(wait) = throttled(&response, backoff) {
                if waited + wait <= MOST_THROTTLED {
                    tokio::time::sleep(wait).await;
                    waited += wait;
                    backoff = (backoff * 2).min(MOST_BACKOFF);
                    continue;
                }
            }
            ensure!(status.is_success(), "{self}: {url}: HTTP {status}");
            return Ok(response);
        }
    }
}

/// How long one request to an Esplora limiting its rate is waited on.
const MOST_THROTTLED: Duration = Duration::from_secs(120);

/// The longest wait between asking a throttled Esplora again.
const MOST_BACKOFF: Duration = Duration::from_secs(30);

/// How long to wait before asking again, if `response` refuses for now:
/// too many requests (429), or overloaded (503). As long as it asks, in
/// seconds; else `backoff`.
fn throttled(response: &reqwest::Response, backoff: Duration) -> Option<Duration> {
    let status = response.status();
    let refused = status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE;
    if !refused {
        return None;
    }
    let asked = response.headers().get(reqwest::header::RETRY_AFTER);
    let asked = asked.and_then(|v| v.to_str().ok()?.trim().parse::<u64>().ok());
    Some(asked.map_or(backoff, Duration::from_secs))
}
