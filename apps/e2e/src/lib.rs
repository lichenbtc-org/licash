//! The regtest ecosystem of `docker-compose.yml`, for the end-to-end tests:
//! Bitcoin Core, two hubs, a swap provider over its LND node, an outside LND
//! node, and wallets in temporary files. `run.sh` brings the stack up;
//! [`Eco::up`] funds the nodes and opens their channel once.

use std::{
    future::Future,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use bitcoin::{
    absolute::LockTime,
    consensus::{deserialize, encode::serialize_hex},
    ecdsa,
    key::TweakedPublicKey,
    secp256k1::{Message, Secp256k1, SecretKey},
    sighash::SighashCache,
    transaction, Address, Amount, CompressedPublicKey, EcdsaSighashType, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness,
};
use licash::spend::{lock_hash, ChainProfile};
use licash_api::{swaps, Info};
use licash_onchain::silent::{self, SpAddress};
use licash_wallet::InvoiceState;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use tokio::process::Command;

pub use licash_transport::Http;

pub mod phone;

/// Satoshis in each channel, half pushed to its other end.
const CHANNEL: u64 = 6_000_000;

/// The Lightning nodes: the outside one and the swap provider's. Hubs run
/// none: wallets pay and are paid over Lightning through the provider.
pub const OUTSIDE: &str = "outside-ln";
pub const SWAPS_LN: &str = "swaps-ln";
pub const NODES: [&str; 2] = [OUTSIDE, SWAPS_LN];

/// The channels, by their nodes in [`NODES`], the first opening each: the
/// provider's to the outside node.
const CHANNELS: [(usize, usize); 1] = [(1, 0)];

/// The least the provider's wallet funds of a contract at a hub at once
/// when it holds too little there ([`Eco::stock_at`]): few contracts, few
/// blocks.
const RESTOCK: u64 = 150_000;

/// The most the provider pays to open a contract it stocks with, on top
/// of its part: the reserve, the hub's fee and its interest.
const CONTRACT_PRICE: u64 = 50_000;

/// Bitcoin Core's RPC as the stack's services reach it.
const INSIDE_CHAIN: &str = "http://licash:licash@bitcoind:18443";

/// A wallet of the tests, over HTTP.
pub type Wallet = licash_wallet::Wallet<Http>;

pub struct Eco {
    project: String,
    file: PathBuf,
    core: String,
    http: reqwest::Client,
    /// Each hub's URL, as published on this host.
    hubs: Vec<String>,
    /// The Nostr relay's URL, as published on this host.
    relay: String,
    /// The swap provider's URL, as published on this host.
    swaps: String,
    /// The NWC bridge's URL, as published on this host.
    bridge: String,
    /// The owner-only NWC bridge's URL, as published on this host.
    bridge2: String,
    /// The Gotify server's URL, as published on this host.
    gotify: String,
    /// Bitcoin Core's peer-to-peer address, as published on this host.
    p2p: String,
    dir: tempfile::TempDir,
}

/// A notification the stack's Gotify server took.
#[derive(Clone, Debug)]
pub struct Notification {
    pub id: u64,
    pub title: String,
    pub message: String,
    pub priority: u64,
}

/// Wait up to `secs` for `check` to give something, every half second.
pub async fn until<T, F: Future<Output = anyhow::Result<Option<T>>>>(
    what: &str,
    secs: u64,
    mut check: impl FnMut() -> F,
) -> anyhow::Result<T> {
    let start = Instant::now();
    loop {
        let last = match check().await {
            Ok(Some(found)) => return Ok(found),
            Ok(None) => String::new(),
            Err(e) => format!(": {e:#}"),
        };
        if start.elapsed() > Duration::from_secs(secs) {
            bail!("{what}: not after {secs} s{last}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

impl Eco {
    /// The stack of Compose project `$LICASH_E2E_PROJECT` (by default
    /// `licash-e2e`), with its nodes funded and the `CHANNELS` open.
    pub async fn up() -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let project = std::env::var("LICASH_E2E_PROJECT").unwrap_or_else(|_| "licash-e2e".into());
        let mut eco = Self {
            project,
            file: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docker-compose.yml"),
            core: String::new(),
            http: reqwest::Client::new(),
            hubs: Vec::new(),
            relay: String::new(),
            swaps: String::new(),
            bridge: String::new(),
            bridge2: String::new(),
            gotify: String::new(),
            p2p: String::new(),
            dir: tempfile::tempdir()?,
        };
        eco.core = format!("http://{}", eco.port("bitcoind", 18443).await?);
        eco.relay = format!("ws://{}", eco.port("relay", 8080).await?);
        eco.swaps = format!("http://{}", eco.port("swaps", 8340).await?);
        eco.bridge = format!("http://{}", eco.port("bridge", 8090).await?);
        eco.bridge2 = format!("http://{}", eco.port("bridge2", 8090).await?);
        eco.gotify = format!("http://{}", eco.port("gotify", 80).await?);
        eco.p2p = eco.port("bitcoind", 18444).await?;
        for hub in ["hub1", "hub2"] {
            let at = eco.port(hub, 8338).await?;
            eco.hubs.push(format!("http://{at}"));
        }
        eco.fund().await?;
        Ok(eco)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new("docker");
        command
            .args(["compose", "-p", &self.project, "-f"])
            .arg(&self.file)
            .args(args)
            .kill_on_drop(true);
        command
    }

    async fn compose(&self, args: &[&str]) -> anyhow::Result<Vec<u8>> {
        let output = self.command(args).output().await?;
        ensure!(
            output.status.success(),
            "docker compose {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    async fn port(&self, service: &str, port: u16) -> anyhow::Result<String> {
        let published = self.compose(&["port", service, &port.to_string()]).await;
        let published = String::from_utf8(published.unwrap_or_default())?;
        ensure!(
            !published.trim().is_empty(),
            "{service} of {} is not up: run apps/e2e/run.sh",
            self.project
        );
        Ok(published.trim().to_owned())
    }

    /// `args` run in `service`, and what they print.
    pub async fn exec(&self, service: &str, args: &[&str]) -> anyhow::Result<Vec<u8>> {
        let mut all = vec!["exec", "-T", service];
        all.extend(args);
        self.compose(&all).await
    }

    /// The dashboard of `service`, run there by its `cli` beside it, as
    /// JSON: the range of 30 days.
    pub async fn dashboard(&self, service: &str, cli: &str) -> anyhow::Result<Dashboard> {
        let view = self.exec(service, &[cli, "dashboard", "--json"]).await?;
        Ok(Dashboard(serde_json::from_slice(&view)?))
    }

    /// Stop `service`, until [`Eco::start`]ed again.
    pub async fn stop(&self, service: &str) -> anyhow::Result<()> {
        self.compose(&["stop", service]).await?;
        Ok(())
    }

    /// Start `service` again, and wait for it to be healthy.
    pub async fn start(&self, service: &str) -> anyhow::Result<()> {
        self.compose(&["start", service]).await?;
        self.compose(&["up", "--wait", service]).await?;
        Ok(())
    }

    /// Restart `service`, and wait for it to be healthy.
    pub async fn restart(&self, service: &str) -> anyhow::Result<()> {
        self.compose(&["restart", service]).await?;
        self.compose(&["up", "--wait", service]).await?;
        Ok(())
    }

    /// The URL of hub `n`, 1 or 2.
    pub fn hub(&self, n: usize) -> &str {
        &self.hubs[n - 1]
    }

    /// Bitcoin Core's JSON-RPC, as published on this host, with its
    /// credentials: a chain URL of `licash-chain-client`.
    pub fn chain(&self) -> String {
        self.core.replacen("http://", "http://licash:licash@", 1)
    }

    /// The URL of the Nostr relay the hubs announce themselves on.
    pub fn relay(&self) -> &str {
        &self.relay
    }

    /// Bitcoin Core's peer-to-peer address, serving compact filters, for
    /// light clients.
    pub fn p2p(&self) -> &str {
        &self.p2p
    }

    /// A new wallet, in a file of its own.
    pub fn wallet(&self, name: &str) -> anyhow::Result<Wallet> {
        let mut seed = [0; 32];
        OsRng.fill_bytes(&mut seed);
        let path = self.dir.path().join(format!("{name}.sqlite"));
        Ok(Wallet::create(
            &path,
            &seed,
            ChainProfile::Core30DefaultRegtest,
            Http::new(None)?,
        )?)
    }

    pub async fn info(&self, hub: &str) -> anyhow::Result<Info> {
        let url = format!("{hub}{}", licash_api::INFO);
        let response = self.http.get(url).send().await?.error_for_status()?;
        Ok(response.json().await?)
    }

    /// `wallet`, paid `amount` in notes at `hub` from outside over
    /// Lightning, through the swap provider: its fee on top, the provider
    /// stocked there first.
    pub async fn pay_in(&self, wallet: &Wallet, hub: &str, amount: u64) -> anyhow::Result<()> {
        self.stock_at(hub, amount).await?;
        wallet.add_hub(hub).await?;
        let invoice = wallet
            .invoice_through(&self.swaps, hub, amount, None)
            .await?;
        let paying = self.pay(OUTSIDE, invoice.request.as_deref().context("a request")?);
        let state = received(wallet, &invoice.hash).await?;
        ensure!(state == InvoiceState::Received, "the invoice was {state:?}");
        ensure!(paying.await??, "the outside node's payment failed");
        Ok(())
    }

    /// What the hubs and the swap provider notified their operators of on
    /// the stack's Gotify server, newest first.
    pub async fn notifications(&self) -> anyhow::Result<Vec<Notification>> {
        let url = format!("{}/message?limit=200", self.gotify);
        let response = self.http.get(url).basic_auth("admin", Some("licash"));
        let page: Value = response.send().await?.error_for_status()?.json().await?;
        let messages = page["messages"].as_array().context("Gotify's messages")?;
        messages
            .iter()
            .map(|m| {
                Ok(Notification {
                    id: m["id"].as_u64().context("an id")?,
                    title: m["title"].as_str().context("a title")?.to_owned(),
                    message: m["message"].as_str().context("a message")?.to_owned(),
                    priority: m["priority"].as_u64().context("a priority")?,
                })
            })
            .collect()
    }

    /// Call Bitcoin Core, at `path`.
    async fn rpc(&self, path: &str, method: &str, params: Value) -> anyhow::Result<Value> {
        let body = json!({ "jsonrpc": "1.0", "id": "e2e", "method": method, "params": params });
        let answer: Value = self
            .http
            .post(format!("{}{path}", self.core))
            .basic_auth("licash", Some("licash"))
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if !answer["error"].is_null() {
            bail!("{method}: {}", answer["error"]);
        }
        Ok(answer["result"].clone())
    }

    /// Call the miner's wallet in Bitcoin Core.
    async fn miner(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        self.rpc("/wallet/miner", method, params).await
    }

    /// Call Bitcoin Core's node.
    pub async fn core(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        self.rpc("", method, params).await
    }

    /// Pay `sat` to `address` from the miner's wallet, unconfirmed: the
    /// transaction's id.
    pub async fn send_to(&self, address: &str, sat: u64) -> anyhow::Result<String> {
        let btc = sat as f64 / 1e8;
        let txid = self.miner("sendtoaddress", json!([address, btc])).await?;
        Ok(txid.as_str().context("a txid")?.to_owned())
    }

    /// The output of transaction `txid` paying `address`, and its value.
    pub async fn paying(
        &self,
        txid: &str,
        address: &str,
    ) -> anyhow::Result<(bitcoin::OutPoint, bitcoin::Amount)> {
        let tx = self.rpc("", "getrawtransaction", json!([txid, 1])).await?;
        let outputs = tx["vout"].as_array().context("outputs")?;
        let output = outputs
            .iter()
            .find(|o| o["scriptPubKey"]["address"] == address)
            .with_context(|| format!("an output paying {address}"))?;
        let vout = output["n"].as_u64().context("its index")? as u32;
        let value = output["value"].as_f64().context("its value")?;
        let value = bitcoin::Amount::from_btc(value)?;
        Ok((bitcoin::OutPoint::new(txid.parse()?, vout), value))
    }

    /// Pay `sat` to the silent payment address `to`, from a key of its own
    /// the miner's wallet funds, unconfirmed: the transaction's id.
    pub async fn pay_silent(&self, to: &str, sat: u64) -> anyhow::Result<String> {
        let to: SpAddress = to.to_lowercase().parse()?;
        let secp = Secp256k1::new();
        let mut secret = [0; 32];
        OsRng.fill_bytes(&mut secret);
        let key = SecretKey::from_slice(&secret)?;
        let public = CompressedPublicKey(key.public_key(&secp));
        let spent = ScriptBuf::new_p2wpkh(&public.wpubkey_hash());
        let funding = Address::from_script(&spent, bitcoin::Network::Regtest)?;
        let value = sat + 1_000;
        let txid = self.send_to(&funding.to_string(), value).await?;
        let raw = self.miner("gettransaction", json!([txid])).await?;
        let raw = hex::decode(raw["hex"].as_str().context("a raw transaction")?)?;
        let funded: Transaction = deserialize(&raw)?;
        let vout = funded
            .output
            .iter()
            .position(|o| o.script_pubkey == spent)
            .context("the funding output")?;
        let outpoint = OutPoint::new(funded.compute_txid(), vout as u32);
        let output = silent::outputs(&[(key, false)], &[outpoint], &[to])?[0];
        let mut tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(sat),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(output),
                ),
            }],
        };
        let hash = SighashCache::new(&tx).p2wpkh_signature_hash(
            0,
            &spent,
            Amount::from_sat(value),
            EcdsaSighashType::All,
        )?;
        let signature = ecdsa::Signature {
            signature: secp.sign_ecdsa(&Message::from(hash), &key),
            sighash_type: EcdsaSighashType::All,
        };
        tx.input[0].witness = Witness::p2wpkh(&signature, &public.0);
        let sent = self
            .core("sendrawtransaction", json!([serialize_hex(&tx)]))
            .await?;
        Ok(sent.as_str().context("a txid")?.to_owned())
    }

    /// A new address of the miner's wallet, of `kind`, such as `bech32m`.
    pub async fn miner_address(&self, kind: &str) -> anyhow::Result<String> {
        let address = self.miner("getnewaddress", json!(["", kind])).await?;
        Ok(address.as_str().context("an address")?.to_owned())
    }

    pub async fn height(&self) -> anyhow::Result<u32> {
        let count = self.rpc("", "getblockcount", json!([])).await?;
        Ok(count.as_u64().context("a block count")? as u32)
    }

    /// Mine `blocks`, then wait for every node and hub to follow. The new
    /// height.
    pub async fn mine(&self, blocks: u32) -> anyhow::Result<u32> {
        let address = self.miner("getnewaddress", json!([])).await?;
        self.miner("generatetoaddress", json!([blocks, address]))
            .await?;
        let height = self.height().await?;
        self.synced(height).await?;
        Ok(height)
    }

    /// Wait for every Lightning node and hub to reach `height`.
    pub async fn synced(&self, height: u32) -> anyhow::Result<()> {
        for node in NODES {
            until(&format!("{node} at {height}"), 120, || async move {
                let info = self.lncli(node, &["getinfo"]).await?;
                let at = info["block_height"].as_u64().unwrap_or(0);
                Ok((info["synced_to_chain"] == true && at >= u64::from(height)).then_some(()))
            })
            .await?;
        }
        for hub in &self.hubs {
            until(&format!("{hub} at {height}"), 120, || async move {
                let locks = self.info(hub).await?.locks;
                Ok(locks.filter(|l| l.height >= height).map(|_| ()))
            })
            .await?;
        }
        Ok(())
    }
}

/// Follow the invoice of `hash` until it is received or canceled.
pub async fn received(wallet: &Wallet, hash: &str) -> anyhow::Result<InvoiceState> {
    until(&format!("invoice {hash}"), 180, || async {
        Ok(match wallet.follow_invoice(hash).await {
            Ok(invoice) if invoice.state != InvoiceState::Open => Some(invoice.state),
            Ok(_) | Err(licash_wallet::Error::Pending { .. }) => None,
            Err(e) => return Err(e.into()),
        })
    })
    .await
}

/// Bitcoin Core's chain, as a wallet reads it.
impl licash_wallet::Blocks for Eco {
    async fn height(&self) -> Result<u32, String> {
        Eco::height(self).await.map_err(|e| format!("{e:#}"))
    }

    async fn hash(&self, height: u32) -> Result<bitcoin::BlockHash, String> {
        let hash = self.core("getblockhash", json!([height])).await;
        let hash = hash.map_err(|e| format!("{e:#}"))?;
        hash.as_str()
            .and_then(|h| h.parse().ok())
            .ok_or_else(|| format!("no block hash: {hash}"))
    }

    async fn filter(&self, hash: &bitcoin::BlockHash) -> Result<Option<Vec<u8>>, String> {
        let filter = self
            .core("getblockfilter", json!([hash.to_string(), "basic"]))
            .await
            .map_err(|e| format!("{e:#}"))?;
        let filter = filter["filter"].as_str().ok_or("no filter")?;
        hex::decode(filter).map(Some).map_err(|e| e.to_string())
    }

    async fn block(&self, hash: &bitcoin::BlockHash) -> Result<bitcoin::Block, String> {
        let block = self
            .core("getblock", json!([hash.to_string(), 0]))
            .await
            .map_err(|e| format!("{e:#}"))?;
        let raw = hex::decode(block.as_str().ok_or("no block")?).map_err(|e| e.to_string())?;
        deserialize(&raw).map_err(|e| e.to_string())
    }
}

/// The swap provider.
impl Eco {
    /// The provider's URL, as published on this host.
    pub fn swaps(&self) -> &str {
        &self.swaps
    }

    /// The NWC bridge's URL, as published on this host.
    pub fn bridge(&self) -> &str {
        &self.bridge
    }

    /// The NWC bridge at hub 2 for its owner alone, whom its pairing code
    /// registers, as published on this host: its Lightning Addresses' too.
    pub fn bridge2(&self) -> &str {
        &self.bridge2
    }

    pub async fn swaps_info(&self) -> anyhow::Result<swaps::Info> {
        self.swaps_info_at(&self.swaps).await
    }

    /// What the swap provider at `provider` says of itself.
    pub async fn swaps_info_at(&self, provider: &str) -> anyhow::Result<swaps::Info> {
        let url = format!("{provider}{}", swaps::SWAPS_INFO);
        let response = self.http.get(url).send().await?.error_for_status()?;
        Ok(response.json().await?)
    }

    /// Ask the provider for the swap `request` asks for.
    pub async fn ask_swap(&self, request: &swaps::Request) -> anyhow::Result<swaps::Swap> {
        let url = format!("{}{}", self.swaps, swaps::SWAPS);
        let response = self.http.post(url).json(request).send().await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(status.is_success(), "swap refused, {status}: {body}");
        Ok(serde_json::from_str(&body)?)
    }

    /// Where the swap of the client's lock `id`, in hex, stands.
    pub async fn swap_state(&self, id: &str) -> anyhow::Result<swaps::Swap> {
        self.swap_state_at(&self.swaps, id).await
    }

    /// Where the swap of the client's lock `id`, in hex, stands at the
    /// provider at `provider`.
    pub async fn swap_state_at(&self, provider: &str, id: &str) -> anyhow::Result<swaps::Swap> {
        let id = licash_api::lock_id(id).map_err(|p| anyhow::anyhow!(p.message))?;
        let url = format!("{provider}{}", swaps::swap_state(&id));
        let response = self.http.get(url).send().await?.error_for_status()?;
        Ok(response.json().await?)
    }

    /// Where the invoice the provider pays for the client's lock `id`, in
    /// hex, stands.
    pub async fn lightning_payment(&self, id: &str) -> anyhow::Result<swaps::LightningSwap> {
        let id = licash_api::lock_id(id).map_err(|p| anyhow::anyhow!(p.message))?;
        let url = format!("{}{}", self.swaps, swaps::lightning_swap_state(&id));
        let response = self.http.get(url).send().await?.error_for_status()?;
        Ok(response.json().await?)
    }

    /// Where the payout on Bitcoin of the client's lock `id`, in hex,
    /// stands.
    pub async fn payout_state(&self, id: &str) -> anyhow::Result<swaps::ChainSwap> {
        let id = licash_api::lock_id(id).map_err(|p| anyhow::anyhow!(p.message))?;
        let url = format!("{}{}", self.swaps, swaps::chain_swap_state(&id));
        let response = self.http.get(url).send().await?.error_for_status()?;
        Ok(response.json().await?)
    }

    /// Hand `tx` to Bitcoin Core: its id.
    pub async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<String> {
        let txid = self
            .core("sendrawtransaction", json!([serialize_hex(tx)]))
            .await?;
        Ok(txid.as_str().context("a txid")?.to_owned())
    }

    /// What `url` answers in JSON, an LNURL's for instance.
    pub async fn get_json(&self, url: &str) -> anyhow::Result<Value> {
        let response = self.http.get(url).send().await?.error_for_status()?;
        Ok(response.json().await?)
    }

    /// The info of the bridge at `bridge`, once it answers: once the
    /// provider it is paid through holds notes at its hub, `amount` of
    /// them at least, which it stocks there first.
    pub async fn bridge_ready(
        &self,
        bridge: &str,
        hub: &str,
        amount: u64,
    ) -> anyhow::Result<Value> {
        self.stock_at(hub, amount).await?;
        let url = format!("{bridge}{}", licash_api::bridge::INFO);
        until("the bridge paid through its provider", 60, || async {
            Ok(self.get_json(&url).await.ok())
        })
        .await
    }

    /// The most the provider locks at hub 2 now.
    pub async fn stocked(&self) -> anyhow::Result<u64> {
        self.stocked_at(self.hub(2)).await
    }

    /// The most the provider locks at `hub` now.
    pub async fn stocked_at(&self, hub: &str) -> anyhow::Result<u64> {
        let at = self.info(hub).await?.address;
        let info = self.swaps_info().await?;
        Ok(info.hub(&at).map_or(0, |hub| hub.max))
    }

    /// The provider able to lock `amount` at hub 2 ([`Eco::stock_at`]).
    pub async fn stock(&self, amount: u64) -> anyhow::Result<()> {
        self.stock_at(self.hub(2), amount).await
    }

    /// The provider able to lock `amount` at `hub`, its wallet stocked
    /// there if it is not yet as a provider stocks: a contract it funds
    /// with a coin of its own, its part issued back to it as notes.
    pub async fn stock_at(&self, hub: &str, amount: u64) -> anyhow::Result<()> {
        if self.stocked_at(hub).await? >= amount {
            return Ok(());
        }
        let n = (self.hubs.iter().position(|h| h == hub)).context("a hub of the stack")? + 1;
        // At the URL the provider reaches it at, its fee on the locks to
        // come generously.
        let inside = format!("http://hub{n}:8338");
        let part = (amount + amount / 100 + 100).max(RESTOCK);
        let address = self.exec("swaps", &["licash-swaps", "address"]).await?;
        let address = String::from_utf8(address)?.trim().to_owned();
        let from = (self.height().await? + 1).to_string();
        let txid = self.send_to(&address, part + CONTRACT_PRICE).await?;
        let (coin, _) = self.paying(&txid, &address).await?;
        let coin = coin.to_string();
        self.mine(1).await?;
        let wallet = |args: &[&str]| {
            let mut all = vec!["licash-wallet".to_owned(), "--json".to_owned()];
            all.extend(args.iter().map(|a| a.to_string()));
            async move {
                let all: Vec<&str> = all.iter().map(String::as_str).collect();
                self.exec("swaps", &all).await
            }
        };
        // The service finds the coin itself, as it watches its wallet's
        // coins on the chain; the scan only hastens it, and may find the
        // wallet busy.
        let scan = ["onchain", "--chain", INSIDE_CHAIN, "scan", "--from", &from];
        // Opened once the coin is the wallet's and the hub's wallet,
        // funding its reserve, is learned.
        let price = CONTRACT_PRICE.to_string();
        let open = [
            "open-contract",
            &inside,
            "--chain",
            INSIDE_CHAIN,
            "--blocks",
            "1000",
            "--coin",
            &coin,
            "--max-price",
            &price,
        ];
        until("the provider's contract opened", 180, || async {
            if let Err(e) = wallet(&scan).await {
                eprintln!("the provider's scan: {e:#}");
            }
            match wallet(&open).await {
                Ok(opened) => Ok(Some(opened)),
                Err(e) => {
                    eprintln!("the provider's contract not opened yet: {e:#}");
                    Ok(None)
                }
            }
        })
        .await?;
        // Its funding buried, the hub issues its part, which the wallet
        // takes on carrying the contract.
        until("the provider stocked", 300, || async {
            self.mine(1).await?;
            if let Err(e) = wallet(&["contracts", "--chain", INSIDE_CHAIN]).await {
                eprintln!("the provider's contracts not carried on: {e:#}");
            }
            Ok((self.stocked_at(hub).await? >= amount).then_some(()))
        })
        .await
    }
}

/// Lightning nodes.
impl Eco {
    /// `lncli` on `node`, and its answer.
    pub async fn lncli(&self, node: &str, args: &[&str]) -> anyhow::Result<Value> {
        let mut all = vec!["exec", "-T", node, "lncli", "--network=regtest"];
        all.extend(args);
        Ok(serde_json::from_slice(&self.compose(&all).await?)?)
    }

    /// `node` pays `request`, in the background: whether it was paid.
    pub fn pay(&self, node: &str, request: &str) -> tokio::task::JoinHandle<anyhow::Result<bool>> {
        let mut command = self.command(&[
            "exec",
            "-T",
            node,
            "lncli",
            "--network=regtest",
            "payinvoice",
            "--force",
            "--json",
            "--timeout=3m",
            request,
        ]);
        tokio::spawn(async move {
            let output = command.output().await?;
            Ok(String::from_utf8_lossy(&output.stdout).contains("\"SUCCEEDED\""))
        })
    }

    /// An invoice of `node` for `sat`: its request and hash, in hex.
    pub async fn invoice(&self, node: &str, sat: u64) -> anyhow::Result<(String, String)> {
        let added = self
            .lncli(node, &["addinvoice", "--amt", &sat.to_string()])
            .await?;
        let request = added["payment_request"].as_str().context("a request")?;
        let hash = added["r_hash"].as_str().context("a hash")?;
        Ok((request.to_owned(), hash.to_owned()))
    }

    /// A held invoice of `node` for `sat`, under the hash of a preimage
    /// drawn here: its request, hash and preimage, in hex. It is settled
    /// or canceled at will.
    pub async fn hold_invoice(
        &self,
        node: &str,
        sat: u64,
    ) -> anyhow::Result<(String, String, String)> {
        let mut preimage = [0; 32];
        OsRng.fill_bytes(&mut preimage);
        let hash = hex::encode(lock_hash(&preimage));
        let added = self
            .lncli(node, &["addholdinvoice", &hash, "--amt", &sat.to_string()])
            .await?;
        let request = added["payment_request"].as_str().context("a request")?;
        Ok((request.to_owned(), hash, hex::encode(preimage)))
    }

    /// Where `node`'s invoice of `hash` stands, such as `SETTLED`, and its
    /// preimage.
    pub async fn invoice_state(&self, node: &str, hash: &str) -> anyhow::Result<(String, String)> {
        let invoice = self.lncli(node, &["lookupinvoice", hash]).await?;
        let state = invoice["state"].as_str().context("a state")?;
        let preimage = invoice["r_preimage"].as_str().unwrap_or_default();
        Ok((state.to_owned(), preimage.to_owned()))
    }

    /// The timelock of the route of each part of `node`'s payment of
    /// `hash`.
    pub async fn timelocks(&self, node: &str, hash: &str) -> anyhow::Result<Vec<u64>> {
        let payments = self.lncli(node, &["listpayments"]).await?;
        let payments = payments["payments"].as_array().context("payments")?;
        let payment = payments
            .iter()
            .find(|p| p["payment_hash"] == hash)
            .context("no payment of that hash")?;
        let htlcs = payment["htlcs"].as_array().into_iter().flatten();
        Ok(htlcs
            .filter_map(|h| h["route"]["total_time_lock"].as_u64())
            .collect())
    }

    async fn pubkey(&self, node: &str) -> anyhow::Result<String> {
        let info = self.lncli(node, &["getinfo"]).await?;
        Ok(info["identity_pubkey"]
            .as_str()
            .context("a node key")?
            .to_owned())
    }

    /// Whether `node` has a channel with `peer`, open or opening.
    async fn channel(&self, node: &str, peer: &str) -> anyhow::Result<bool> {
        let open = self.lncli(node, &["listchannels"]).await?;
        let pending = self.lncli(node, &["pendingchannels"]).await?;
        let open = open["channels"].as_array().into_iter().flatten();
        let opening = pending["pending_open_channels"]
            .as_array()
            .into_iter()
            .flatten();
        Ok(open.map(|c| &c["remote_pubkey"]).any(|k| k == peer)
            || opening
                .map(|c| &c["channel"]["remote_node_pub"])
                .any(|k| k == peer))
    }

    /// Whether `node`'s channel with `peer` is active.
    async fn active(&self, node: &str, peer: &str) -> anyhow::Result<bool> {
        let open = self.lncli(node, &["listchannels", "--active_only"]).await?;
        let mut open = open["channels"].as_array().into_iter().flatten();
        Ok(open.any(|c| c["remote_pubkey"] == peer))
    }

    /// Coins for the miner and the [`CHANNELS`], half their funds on each
    /// side: whatever is missing.
    async fn fund(&self) -> anyhow::Result<()> {
        for wallet in ["miner", "hub2"] {
            if let Err(e) = self.rpc("", "createwallet", json!([wallet])).await {
                ensure!(format!("{e}").contains("already exists"), e);
                let _ = self.rpc("", "loadwallet", json!([wallet])).await;
            }
        }
        let height = self.height().await?;
        if height < 101 {
            self.mine(101 - height).await?;
        }
        // Hub2's wallet, funding the reserves of its contracts.
        let hub2 = self.rpc("/wallet/hub2", "getbalances", json!([])).await?;
        let held = hub2["mine"]["trusted"].as_f64().unwrap_or(0.0)
            + hub2["mine"]["untrusted_pending"].as_f64().unwrap_or(0.0);
        if held < 1.0 {
            let address = self.rpc("/wallet/hub2", "getnewaddress", json!([])).await?;
            let address = address.as_str().context("an address")?;
            self.miner("sendtoaddress", json!([address, 5.0])).await?;
            self.mine(1).await?;
        }
        let mut keys = Vec::new();
        for node in NODES {
            keys.push(self.pubkey(node).await?);
        }
        let mut missing = Vec::new();
        for (a, b) in CHANNELS {
            if !self.channel(NODES[a], &keys[b]).await? {
                missing.push((a, b));
            }
        }
        for &(a, _) in &missing {
            let address = self.lncli(NODES[a], &["newaddress", "p2wkh"]).await?;
            let address = address["address"].as_str().context("an address")?;
            let btc = (CHANNEL + 100_000) as f64 / 1e8;
            self.miner("sendtoaddress", json!([address, btc])).await?;
        }
        if !missing.is_empty() {
            self.mine(6).await?;
        }
        for &(a, b) in &missing {
            let (node, peer) = (NODES[a], &keys[b]);
            until(&format!("{node} funded"), 60, || async move {
                let balance = self.lncli(node, &["walletbalance"]).await?;
                let confirmed = balance["confirmed_balance"].as_str().unwrap_or("0");
                Ok((confirmed.parse::<u64>()? > CHANNEL).then_some(()))
            })
            .await?;
            let at = format!("{peer}@{}:9735", NODES[b]);
            if let Err(e) = self.lncli(node, &["connect", &at]).await {
                ensure!(format!("{e}").contains("already connected"), e);
            }
            self.lncli(
                node,
                &[
                    "openchannel",
                    &format!("--node_key={peer}"),
                    &format!("--local_amt={CHANNEL}"),
                    &format!("--push_amt={}", CHANNEL / 2),
                    "--sat_per_vbyte=1",
                ],
            )
            .await?;
        }
        let mut inactive = false;
        for (a, b) in CHANNELS {
            inactive |= !self.active(NODES[a], &keys[b]).await?;
        }
        if inactive {
            self.mine(6).await?;
        }
        for (a, b) in CHANNELS {
            let (node, peer) = (NODES[a], &keys[b]);
            until(
                &format!("{node}'s channel to {}", NODES[b]),
                120,
                || async move { Ok(self.active(node, peer).await?.then_some(())) },
            )
            .await?;
        }
        // Active is not routable yet: a payment right after fails with no
        // route, for good, until the node's router has the channel.
        for (a, b) in CHANNELS {
            let (node, peer) = (NODES[a], &keys[b]);
            until(
                &format!("{node}'s route to {}", NODES[b]),
                120,
                || async move {
                    let args = ["queryroutes", "--dest", peer, "--amt", "1000"];
                    Ok(self.lncli(node, &args).await.ok().map(|_| ()))
                },
            )
            .await?;
        }
        Ok(())
    }
}

/// A service's dashboard as it prints in JSON ([`Eco::dashboard`]).
pub struct Dashboard(pub Value);

impl Dashboard {
    fn panels(&self) -> impl Iterator<Item = &Value> {
        let pages = self.0["pages"].as_array().into_iter().flatten();
        let rows = pages.flat_map(|p| p["rows"].as_array().into_iter().flatten());
        rows.flat_map(|r| r.as_array().into_iter().flatten())
    }

    /// The value of the card `title`, on any page: none if it has none.
    pub fn card(&self, title: &str) -> Option<f64> {
        let cards = self
            .panels()
            .flat_map(|p| p["cards"].as_array().into_iter().flatten());
        cards.into_iter().find(|c| c["title"] == title)?["value"].as_f64()
    }

    /// The text cells of each row of the list `title`, on any page.
    pub fn texts(&self, title: &str) -> Vec<Vec<String>> {
        let table = self
            .panels()
            .find(|p| p["type"] == "table" && p["title"] == title);
        let rows = table
            .and_then(|t| t["rows"].as_array())
            .into_iter()
            .flatten();
        rows.map(|r| {
            let cells = r["cells"].as_array().into_iter().flatten();
            cells
                .filter_map(|c| Some(c["text"].as_str()?.to_owned()))
                .collect()
        })
        .collect()
    }

    /// The tone and detail of the health check `name`.
    pub fn check(&self, name: &str) -> Option<(String, String)> {
        let checks = self
            .panels()
            .flat_map(|p| p["checks"].as_array().into_iter().flatten());
        let check = checks.into_iter().find(|c| c["name"] == name)?;
        Some((
            check["tone"].as_str()?.to_owned(),
            check["detail"].as_str()?.to_owned(),
        ))
    }
}
