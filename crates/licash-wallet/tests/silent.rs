//! Silent payments to a wallet, found with a hub's tweaks and a light
//! client's compact filters on an in-process chain of real payments: found,
//! spent with change found again, through reorganizations, and refused from
//! a hub that names another block.

#[allow(dead_code)]
mod net;

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
};

use bitcoin::{
    absolute::LockTime,
    bip158::{self, BlockFilter},
    block::{Header, Version},
    hashes::{sha256d, Hash},
    key::{Secp256k1, TweakedPublicKey},
    pow::CompactTarget,
    secp256k1::{Message, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
    transaction, Amount, Block, BlockHash, CompressedPublicKey, FeeRate, Network, OutPoint,
    ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
};
use licash::spend::ChainProfile;
use licash_api::{BlockTweaks, Fee, Hex, Info};
use licash_onchain::silent::{self, SpAddress};
use licash_wallet::{Blocks, Error, Payee, PaymentCode, Response, SilentSpend, Transport, Wallet};
use net::{Link, Net, HUB};

const REGTEST: ChainProfile = ChainProfile::Core30DefaultRegtest;

/// A best chain from genesis, the outputs of every transaction ever made
/// (fictional coins of payers among them), and what the wallet read.
struct Chain {
    blocks: Vec<Block>,
    outputs: HashMap<OutPoint, TxOut>,
    /// Serve compact filters.
    filters: bool,
    /// The blocks the wallet fetched whole.
    fetched: Vec<BlockHash>,
    /// The filters it read.
    filtered: u32,
    /// Serve blocks without their last transaction.
    tampered: bool,
    /// Makes each coinbase and payer coin unique.
    made: u32,
}

type Shared = Arc<Mutex<Chain>>;

impl Chain {
    fn new() -> Shared {
        Arc::new(Mutex::new(Chain {
            blocks: vec![bitcoin::constants::genesis_block(Network::Regtest)],
            outputs: HashMap::new(),
            filters: true,
            fetched: Vec::new(),
            filtered: 0,
            tampered: false,
            made: 0,
        }))
    }

    fn height(&self) -> u32 {
        self.blocks.len() as u32 - 1
    }

    /// Mine `txs` in a block on the tip.
    fn mine(&mut self, txs: Vec<Transaction>) -> BlockHash {
        self.made += 1;
        let coinbase = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(self.made.to_be_bytes().to_vec()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new_op_return([1]),
            }],
        };
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: self.blocks.last().unwrap().block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000 + self.made,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: [vec![coinbase], txs].concat(),
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                self.outputs
                    .insert(OutPoint::new(txid, vout as u32), output.clone());
            }
        }
        let hash = block.block_hash();
        self.blocks.push(block);
        hash
    }

    /// Mine `count` empty blocks.
    fn mine_empty(&mut self, count: u32) {
        for _ in 0..count {
            self.mine(Vec::new());
        }
    }

    /// Drop the blocks from height `at` on.
    fn fork(&mut self, at: u32) {
        self.blocks.truncate(at as usize);
    }

    /// A payer's transaction from a fresh coin of its own, of key-hash
    /// inputs, paying `values` to `to` in order.
    fn pay(&mut self, to: &[SpAddress], values: &[u64]) -> Transaction {
        self.made += 1;
        let secp = Secp256k1::new();
        let mut secret = [0x11; 32];
        secret[..4].copy_from_slice(&self.made.to_be_bytes());
        let secret = SecretKey::from_slice(&secret).unwrap();
        let key = CompressedPublicKey(secret.public_key(&secp));
        let coin = OutPoint::new(
            Txid::from_raw_hash(sha256d::Hash::hash(&self.made.to_be_bytes())),
            0,
        );
        self.outputs.insert(
            coin,
            TxOut {
                value: Amount::from_sat(values.iter().sum::<u64>() + 1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&key.wpubkey_hash()),
            },
        );
        let keys = silent::outputs(&[(secret, false)], &[coin], to).unwrap();
        let mut witness = Witness::new();
        witness.push([0x30; 71]);
        witness.push(key.to_bytes());
        Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: coin,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: keys
                .iter()
                .zip(values)
                .map(|(key, value)| TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: ScriptBuf::new_p2tr_tweaked(
                        TweakedPublicKey::dangerous_assume_tweaked(*key),
                    ),
                })
                .collect(),
        }
    }

    /// A payer's transaction from a fresh coin of its own, of a script-hash
    /// input, which silent payments skip (no tweak), paying `value` to `to`.
    fn pay_plain(&mut self, to: &ScriptBuf, value: u64) -> Transaction {
        self.made += 1;
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let coin = OutPoint::new(
            Txid::from_raw_hash(sha256d::Hash::hash(&self.made.to_be_bytes())),
            0,
        );
        self.outputs.insert(
            coin,
            TxOut {
                value: Amount::from_sat(value + 1_000),
                script_pubkey: ScriptBuf::new_p2wsh(&script.wscript_hash()),
            },
        );
        let mut witness = Witness::new();
        witness.push(script.as_bytes());
        Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: coin,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: to.clone(),
            }],
        }
    }

    /// What an index server serves of the block at `height`.
    fn tweaks(&self, height: u32) -> BlockTweaks {
        let block = &self.blocks[height as usize];
        let tweaks = block.txdata[1..].iter().filter_map(|tx| {
            let prevouts: Option<Vec<&bitcoin::Script>> = tx
                .input
                .iter()
                .map(|i| {
                    self.outputs
                        .get(&i.previous_output)
                        .map(|o| o.script_pubkey.as_script())
                })
                .collect();
            silent::tweak(tx, &prevouts?)
        });
        BlockTweaks {
            height,
            hash: block.block_hash().to_string(),
            tweaks: tweaks.map(|t| Hex(t.serialize().to_vec())).collect(),
        }
    }
}

/// A light client's view of a [`Chain`].
struct Light(Shared);

impl Blocks for Light {
    fn height(&self) -> impl Future<Output = Result<u32, String>> + Send {
        std::future::ready(Ok(self.0.lock().unwrap().height()))
    }

    fn hash(&self, height: u32) -> impl Future<Output = Result<BlockHash, String>> + Send {
        let chain = self.0.lock().unwrap();
        let hash = chain.blocks.get(height as usize).map(Block::block_hash);
        std::future::ready(hash.ok_or_else(|| format!("no block {height}")))
    }

    fn filter(
        &self,
        hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, String>> + Send {
        let mut chain = self.0.lock().unwrap();
        chain.filtered += 1;
        let chain = &*chain;
        let block = chain.blocks.iter().find(|b| b.block_hash() == *hash);
        let filter = match (chain.filters, block) {
            (false, _) => Ok(None),
            (true, None) => Err(format!("no block {hash}")),
            (true, Some(block)) => BlockFilter::new_script_filter(block, |coin| {
                let output = chain.outputs.get(coin);
                let script = output.map(|o| o.script_pubkey.clone());
                script.ok_or(bip158::Error::UtxoMissing(*coin))
            })
            .map(|f| Some(f.content))
            .map_err(|e| e.to_string()),
        };
        std::future::ready(filter)
    }

    fn block(&self, hash: &BlockHash) -> impl Future<Output = Result<Block, String>> + Send {
        let mut chain = self.0.lock().unwrap();
        chain.fetched.push(*hash);
        let mut block = chain
            .blocks
            .iter()
            .find(|b| b.block_hash() == *hash)
            .cloned();
        if let Some(block) = block.as_mut().filter(|_| chain.tampered) {
            block.txdata.pop();
        }
        std::future::ready(block.ok_or_else(|| format!("no block {hash}")))
    }
}

/// A hub of the [`Net`] that indexes the tweaks of a [`Chain`], and
/// another, at [`OTHER`], once [`Setup::other`] starts it.
struct Indexer {
    net: Arc<Net>,
    chain: Shared,
    /// The first block whose tweaks it serves.
    first: Mutex<Option<u32>>,
    /// The height at which it names another block than the chain's.
    forged: Mutex<Option<u32>>,
    /// How often it was asked for tweaks.
    asked: Mutex<u32>,
    /// How each hub serves tweaks besides, by URL.
    views: Mutex<HashMap<&'static str, View>>,
}

/// The second hub serving tweaks.
const OTHER: &str = "http://other.test";

/// How a hub serves tweaks.
#[derive(Clone, Default)]
struct View {
    /// The first block whose tweaks it serves, for [`OTHER`].
    first: Option<u32>,
    /// The newest block it indexed, if not the chain's.
    top: Option<u32>,
    /// Serving no tweaks of any block.
    omits: bool,
    /// Never answering for tweaks.
    stalls: bool,
    /// Unreachable when asked for tweaks.
    lost: bool,
    /// How long it takes to answer for tweaks.
    delay: Option<std::time::Duration>,
    /// How often it was asked for tweaks.
    asked: u32,
    /// How often the wallet gave up on its answer.
    given_up: u32,
}

impl Indexer {
    fn serve(&self, url: &str, body: Option<Vec<u8>>) -> Result<Response, String> {
        for hub in [HUB, OTHER] {
            let tweaks = format!("{hub}{}?", licash_api::TWEAKS);
            if let Some(query) = url.strip_prefix(&tweaks) {
                return Ok(self.tweaks(hub, query));
            }
        }
        let mut response = self.net.serve(url, body)?;
        if url.ends_with(licash_api::INFO) && response.status == 200 {
            let mut info: Info = serde_json::from_slice(&response.body).unwrap();
            info.tweaks = match url.starts_with(OTHER) {
                true => self.view(OTHER).first,
                false => *self.first.lock().unwrap(),
            };
            response.body = serde_json::to_vec(&info).unwrap();
        }
        Ok(response)
    }

    fn view(&self, hub: &'static str) -> View {
        let views = self.views.lock().unwrap();
        views.get(hub).cloned().unwrap_or_default()
    }

    fn tweaks(&self, hub: &'static str, query: &str) -> Response {
        let number = |name: &str| -> u32 {
            let pair = query.split('&').find_map(|p| p.strip_prefix(name)).unwrap();
            pair.trim_start_matches('=').parse().unwrap()
        };
        let (from, count) = (number("from"), number("count"));
        if hub == HUB {
            *self.asked.lock().unwrap() += 1;
        }
        self.views.lock().unwrap().entry(hub).or_default().asked += 1;
        let view = self.view(hub);
        assert!(count <= licash_api::MAX_TWEAK_BLOCKS);
        let chain = self.chain.lock().unwrap();
        let top = view.top.unwrap_or(chain.height()).min(chain.height());
        let mut blocks: Vec<BlockTweaks> = (from..from + count)
            .take_while(|h| *h <= top)
            .map(|h| chain.tweaks(h))
            .collect();
        if hub == HUB {
            let forged = *self.forged.lock().unwrap();
            for block in blocks.iter_mut().filter(|b| Some(b.height) == forged) {
                block.hash = BlockHash::all_zeros().to_string();
            }
        }
        if view.omits {
            blocks.iter_mut().for_each(|b| b.tweaks.clear());
        }
        Response {
            status: 200,
            body: serde_json::to_vec(&blocks).unwrap(),
        }
    }

    /// How the hub asked for tweaks at `url` serves them, if one.
    fn asked_of(&self, url: &str) -> View {
        let views = self.views.lock().unwrap();
        let mut asked = views
            .iter()
            .filter(|(hub, _)| url.starts_with(&format!("{hub}{}?", licash_api::TWEAKS)));
        asked.next().map(|(_, v)| v.clone()).unwrap_or_default()
    }
}

struct Via(Arc<Indexer>);

impl Transport for Via {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<Response, String>> + Send {
        let view = self.0.asked_of(url);
        let answer = match view.lost {
            true => Err("connection refused".into()),
            false => self.0.serve(url, body),
        };
        async move {
            if let Some(delay) = view.delay {
                tokio::time::sleep(delay).await;
            }
            if view.stalls {
                std::future::pending::<()>().await;
            }
            answer
        }
    }

    fn gave_up(&self, url: &str) {
        let mut views = self.0.views.lock().unwrap();
        for (hub, view) in views.iter_mut() {
            if url.starts_with(hub) {
                view.given_up += 1;
            }
        }
    }
}

struct Setup {
    wallet: Wallet<Via>,
    chain: Shared,
    hub: Arc<Indexer>,
    /// Kept for as long as the wallet's file is used.
    _dir: tempfile::TempDir,
}

/// A wallet trusting a hub that serves the tweaks of a chain of two empty
/// blocks, from the first.
async fn setup() -> Setup {
    let net = Net::new();
    net.start(HUB, Fee { base: 0, ppm: 0 });
    let chain = Chain::new();
    chain.lock().unwrap().mine_empty(2);
    let hub = Arc::new(Indexer {
        net,
        chain: chain.clone(),
        first: Mutex::new(Some(1)),
        forged: Mutex::new(None),
        asked: Mutex::new(0),
        views: Mutex::default(),
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let wallet = Wallet::create(&path, &[7; 32], REGTEST, Via(hub.clone())).unwrap();
    wallet.add_hub(HUB).await.unwrap();
    Setup {
        wallet,
        chain,
        hub,
        _dir: dir,
    }
}

impl Setup {
    fn address(&self) -> SpAddress {
        self.wallet.silent_keys().address()
    }

    async fn scan(&self) -> Result<licash_wallet::Scanned, Error> {
        self.wallet
            .scan_silent(HUB, &Light(self.chain.clone()), u32::MAX)
            .await
    }

    /// A second hub trusted, at [`OTHER`], serving the tweaks of blocks from
    /// `first` on as `view` tells.
    async fn other(&self, first: u32, view: View) {
        self.hub.net.start(OTHER, Fee { base: 0, ppm: 0 });
        let view = View {
            first: Some(first),
            ..view
        };
        self.hub.views.lock().unwrap().insert(OTHER, view);
        self.wallet.add_hub(OTHER).await.unwrap();
    }

    /// How `hub` serves tweaks from now on.
    fn view(&self, hub: &'static str, change: impl FnOnce(&mut View)) {
        change(self.hub.views.lock().unwrap().entry(hub).or_default());
    }

    /// Up to `max` blocks scanned with the tweaks of every hub trusted.
    async fn scan_trusted(&self, max: u32) -> Result<(licash_wallet::Scanned, bool), Error> {
        let light = Light(self.chain.clone());
        self.wallet.scan_silent_trusted(&light, max, None).await
    }

    fn mine(&self, txs: Vec<Transaction>) -> BlockHash {
        self.chain.lock().unwrap().mine(txs)
    }

    fn pay(&self, to: &[SpAddress], values: &[u64]) -> Transaction {
        self.chain.lock().unwrap().pay(to, values)
    }

    /// The fetched blocks so far, forgotten.
    fn fetched(&self) -> Vec<BlockHash> {
        std::mem::take(&mut self.chain.lock().unwrap().fetched)
    }

    fn pay_plain(&self, to: &ScriptBuf, value: u64) -> Transaction {
        self.chain.lock().unwrap().pay_plain(to, value)
    }

    /// The fallback address a payment code hands out now, as a script.
    fn fallback(&self) -> ScriptBuf {
        let code = self.wallet.onchain_code(true).unwrap();
        code.address.unwrap().assume_checked().script_pubkey()
    }
}

/// The script of `wallet`'s fallback address `index`.
fn fallback_of<T: Transport>(wallet: &Wallet<T>, index: u32) -> ScriptBuf {
    let found = wallet.silent_keys().scanner([]).fallback(index).unwrap();
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(found.output))
}

/// Someone else's silent payment address.
fn stranger() -> SpAddress {
    silent::Keys::from_seed(&[9; 32], bitcoin::NetworkKind::Test)
        .unwrap()
        .address()
}

/// A key-hash script outside the wallet.
fn elsewhere() -> ScriptBuf {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[5; 32]).unwrap().public_key(&secp);
    ScriptBuf::new_p2wpkh(&CompressedPublicKey(key).wpubkey_hash())
}

/// Every input of `tx` is signed for the coin it spends, as `chain` holds.
fn assert_signed(chain: &Chain, tx: &Transaction) {
    let secp = Secp256k1::verification_only();
    let prevouts: Vec<TxOut> = tx
        .input
        .iter()
        .map(|i| chain.outputs[&i.previous_output].clone())
        .collect();
    let mut cache = SighashCache::new(tx);
    for (i, input) in tx.input.iter().enumerate() {
        let sighash = cache
            .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let signature = bitcoin::taproot::Signature::from_slice(&input.witness[0]).unwrap();
        let key = XOnlyPublicKey::from_slice(&prevouts[i].script_pubkey.as_bytes()[2..]).unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        secp.verify_schnorr(&signature.signature, &message, &key)
            .unwrap();
        assert_eq!(input.witness.len(), 1);
    }
}

fn rate() -> FeeRate {
    FeeRate::from_sat_per_vb(2).unwrap()
}

#[tokio::test]
async fn scanning_needs_a_first_block_and_a_hub_serving_tweaks() {
    let s = setup().await;
    assert_eq!(s.wallet.silent_next().unwrap(), None);
    match s.scan().await {
        Err(Error::Invalid(why)) => assert!(why.contains("watch_silent"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s.chain.lock().unwrap().filtered, 0);
    s.wallet.watch_silent(HUB, 2).unwrap();
    // Never later than it stands.
    s.wallet.watch_silent(HUB, 5).unwrap();
    assert_eq!(s.wallet.silent_next().unwrap(), Some(2));
    for (first, says) in [(Some(3), "from block 3 on"), (None, "serves no")] {
        *s.hub.first.lock().unwrap() = first;
        s.wallet.add_hub(HUB).await.unwrap();
        match s.scan().await {
            Err(Error::Invalid(why)) => assert!(why.contains(says), "{why}"),
            other => panic!("{other:?}"),
        }
        // Nor can it look earlier than the hub serves.
        match s.wallet.watch_silent(HUB, 1) {
            Err(Error::Invalid(why)) => assert!(why.contains(says), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(s.wallet.silent_next().unwrap(), Some(2));
    }
    *s.hub.first.lock().unwrap() = Some(1);
    s.wallet.add_hub(HUB).await.unwrap();
    let scanned = s.scan().await.unwrap();
    assert_eq!((scanned.next, scanned.height), (3, 2));
    assert!(scanned.found.is_empty());
    // At most `max` blocks at a time.
    s.chain.lock().unwrap().mine_empty(5);
    let light = Light(s.chain.clone());
    let scanned = s.wallet.scan_silent(HUB, &light, 2).await.unwrap();
    assert_eq!((scanned.next, scanned.height), (5, 7));
    assert_eq!(s.scan().await.unwrap().next, 8);
}

#[tokio::test]
async fn payments_are_found_and_spent_with_change_found_again() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let me = s.address();
    let paying = s.pay(&[me, me], &[30_000, 20_000]);
    let other = s.pay(&[stranger()], &[10_000]);
    s.mine(vec![other]);
    let paid = s.mine(vec![paying.clone()]);
    s.chain.lock().unwrap().mine_empty(1);
    let scanned = s.scan().await.unwrap();
    assert_eq!((scanned.next, scanned.height), (6, 5));
    let mut values: Vec<u64> = scanned.found.iter().map(|c| c.value).collect();
    values.sort();
    assert_eq!(values, [20_000, 30_000]);
    // The filters spared the block paying someone else, and the empty
    // blocks before any coin were not even filtered.
    assert_eq!(s.fetched(), [paid]);
    assert_eq!(scanned.fetched, 1);
    assert_eq!(s.chain.lock().unwrap().filtered, 3);
    let coins = s.wallet.silent_coins().unwrap();
    assert_eq!(coins.len(), 2);
    assert!(coins
        .iter()
        .all(|c| c.height == 4 && !c.change && c.spending.is_none()));
    assert!(coins
        .iter()
        .all(|c| c.outpoint.txid == paying.compute_txid()));
    // Looked in already: nothing again.
    assert!(s.scan().await.unwrap().found.is_empty());

    let spend = s
        .wallet
        .spend_silent(elsewhere(), Some(35_000), rate())
        .unwrap();
    assert_signed(&s.chain.lock().unwrap(), &spend);
    assert_eq!(spend.input.len(), 2);
    assert_eq!(spend.output.len(), 2);
    assert!(spend.input.iter().all(|i| i.sequence.is_rbf()));
    let out: u64 = spend.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = 50_000 - out;
    assert_eq!(fee, rate().fee_wu(spend.weight()).unwrap().to_sat());
    let pays = |tx: &Transaction, script: &ScriptBuf| {
        tx.output
            .iter()
            .filter(|o| o.script_pubkey == *script)
            .map(|o| o.value.to_sat())
            .sum::<u64>()
    };
    assert_eq!(pays(&spend, &elsewhere()), 35_000);
    assert_eq!(
        s.wallet.silent_spends().unwrap(),
        std::slice::from_ref(&spend)
    );
    let txid = spend.compute_txid();
    assert!(s
        .wallet
        .silent_coins()
        .unwrap()
        .iter()
        .all(|c| c.spending == Some(txid)));
    match s.wallet.spend_silent(elsewhere(), Some(1_000), rate()) {
        Err(Error::Insufficient { available: 0, .. }) => {}
        other => panic!("{other:?}"),
    }

    s.mine(vec![spend.clone()]);
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.spent.len(), 2);
    assert_eq!(scanned.found.len(), 1);
    let change = &scanned.found[0];
    assert!(change.change);
    assert_eq!(change.value, 50_000 - 35_000 - fee);
    assert_eq!(change.outpoint.txid, txid);
    assert!(s.wallet.silent_spends().unwrap().is_empty());
    let coins = s.wallet.silent_coins().unwrap();
    assert_eq!(coins.len(), 1);
    assert_eq!(coins[0].outpoint, change.outpoint);

    // Everything: no change.
    let all = s.wallet.spend_silent(elsewhere(), None, rate()).unwrap();
    assert_signed(&s.chain.lock().unwrap(), &all);
    assert_eq!(all.output.len(), 1);
    let fee = rate().fee_wu(all.weight()).unwrap().to_sat();
    assert_eq!(pays(&all, &elsewhere()), change.value - fee);
}

#[tokio::test]
async fn a_spend_of_one_coin_never_joins_another() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let me = s.address();
    s.mine(vec![s.pay(&[me, me], &[30_000, 20_000])]);
    s.scan().await.unwrap();
    let coins = s.wallet.silent_coins().unwrap();
    let coin = |value: u64| coins.iter().find(|c| c.value == value).unwrap().outpoint;
    let payee = Payee::from(elsewhere());

    // The largest, paying it alone; none if no one coin does.
    let paying = |amount| s.wallet.silent_coin_paying(&payee, amount, rate()).unwrap();
    assert_eq!(paying(10_000), Some(coin(30_000)));
    assert_eq!(paying(25_000), Some(coin(30_000)));
    assert_eq!(paying(35_000), None);

    // One coin, its change back; another not free refused.
    let spend = s
        .wallet
        .spend_silent_coin(elsewhere(), coin(20_000), Some(10_000), rate())
        .unwrap();
    assert_signed(&s.chain.lock().unwrap(), &spend);
    assert_eq!((spend.input.len(), spend.output.len()), (1, 2));
    assert_eq!(spend.input[0].previous_output, coin(20_000));
    let again = s
        .wallet
        .spend_silent_coin(elsewhere(), coin(20_000), Some(1_000), rate());
    assert!(matches!(again, Err(Error::Invalid(_))), "{again:?}");
    // Too much for the coin alone, though both would pay it.
    let more = s
        .wallet
        .spend_silent_coin(elsewhere(), coin(30_000), Some(35_000), rate());
    assert!(matches!(more, Err(Error::Insufficient { .. })), "{more:?}");

    // All of one: no change.
    let all = s
        .wallet
        .spend_silent_coin(elsewhere(), coin(30_000), None, rate())
        .unwrap();
    assert_eq!((all.input.len(), all.output.len()), (1, 1));
    let fee = rate().fee_wu(all.weight()).unwrap().to_sat();
    assert_eq!(all.output[0].value.to_sat(), 30_000 - fee);
}

#[tokio::test]
async fn a_spend_shows_its_fee_and_its_block_as_far_as_the_wallet_knows() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address(), s.address()], &[30_000, 20_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let paying = |script: &ScriptBuf| s.wallet.silent_spends_paying(script).unwrap();
    assert!(paying(&elsewhere()).is_empty());
    let spend = s
        .wallet
        .spend_silent(elsewhere(), Some(35_000), rate())
        .unwrap();
    let out: u64 = spend.output.iter().map(|o| o.value.to_sat()).sum();
    let sent = SilentSpend {
        tx: spend.clone(),
        fee: Some(50_000 - out),
        height: None,
    };
    assert_eq!(paying(&elsewhere()), std::slice::from_ref(&sent));
    assert!(paying(&ScriptBuf::new_op_return([1])).is_empty());

    // In block 4, once a scan saw it there.
    s.mine(vec![spend]);
    assert_eq!(paying(&elsewhere()), std::slice::from_ref(&sent));
    s.scan().await.unwrap();
    let confirmed = SilentSpend {
        height: Some(4),
        ..sent.clone()
    };
    assert_eq!(paying(&elsewhere()), [confirmed]);

    // Its block replaced: in none again.
    s.chain.lock().unwrap().fork(4);
    s.chain.lock().unwrap().mine_empty(2);
    s.scan().await.unwrap();
    assert_eq!(paying(&elsewhere()), std::slice::from_ref(&sent));

    // Its coins' block replaced too: what they held is unknown.
    s.chain.lock().unwrap().fork(3);
    s.chain.lock().unwrap().mine_empty(4);
    s.scan().await.unwrap();
    assert!(s.wallet.silent_coins().unwrap().is_empty());
    let unknown = SilentSpend { fee: None, ..sent };
    assert_eq!(paying(&elsewhere()), [unknown]);
}

#[tokio::test]
async fn amounts_too_small_or_too_large_are_refused() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    match s.wallet.spend_silent(elsewhere(), None, rate()) {
        Err(Error::Insufficient { available: 0, .. }) => {}
        other => panic!("{other:?}"),
    }
    let paying = s.pay(&[s.address()], &[10_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    match s.wallet.spend_silent(elsewhere(), Some(100), rate()) {
        Err(Error::Invalid(why)) => assert!(why.contains("dust"), "{why}"),
        other => panic!("{other:?}"),
    }
    match s.wallet.spend_silent(elsewhere(), Some(10_000), rate()) {
        Err(Error::Insufficient {
            available: 10_000, ..
        }) => {}
        other => panic!("{other:?}"),
    }
    // Change too small to keep goes to the fee.
    let spend = s
        .wallet
        .spend_silent(elsewhere(), Some(9_500), rate())
        .unwrap();
    assert_eq!(spend.output.len(), 1);
    assert_eq!(spend.output[0].value.to_sat(), 9_500);
    assert!(s.wallet.silent_spends().unwrap().len() == 1);
}

#[tokio::test]
async fn an_abandoned_spend_frees_its_coins() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[10_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let spend = s.wallet.spend_silent(elsewhere(), None, rate()).unwrap();
    let txid = spend.compute_txid();
    s.wallet.abandon_silent(&txid).unwrap();
    assert!(s.wallet.silent_spends().unwrap().is_empty());
    assert_eq!(s.wallet.silent_coins().unwrap()[0].spending, None);
    assert!(matches!(
        s.wallet.abandon_silent(&txid),
        Err(Error::UnknownPayment(_))
    ));
    // Should it reach a block after all, a scan sees its coin spent.
    let again = s
        .wallet
        .spend_silent(elsewhere(), Some(5_000), rate())
        .unwrap();
    s.mine(vec![spend]);
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.spent.len(), 1);
    assert!(s.wallet.silent_coins().unwrap().is_empty());
    // And the spend it replaced is no longer offered for broadcast.
    assert!(!s.wallet.silent_spends().unwrap().contains(&again));
    // That spend, not the wallet's own any more, replaced: the coin is the
    // wallet's again.
    s.chain.lock().unwrap().fork(4);
    s.chain.lock().unwrap().mine_empty(2);
    s.scan().await.unwrap();
    let coins = s.wallet.silent_coins().unwrap();
    assert_eq!(coins.len(), 1);
    assert_eq!(coins[0].spending, None);
}

#[tokio::test]
async fn a_spend_canceled_pays_its_coins_back_in_its_place() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address(), s.address()], &[30_000, 20_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let coins: Vec<OutPoint> = s
        .wallet
        .silent_coins()
        .unwrap()
        .iter()
        .map(|c| c.outpoint)
        .collect();
    let spend = s
        .wallet
        .spend_silent(elsewhere(), Some(35_000), rate())
        .unwrap();
    let txid = spend.compute_txid();
    assert_eq!(
        s.wallet.silent_spender(&coins[0]).unwrap(),
        Some((txid, None))
    );
    let at = |vb: u64| FeeRate::from_sat_per_vb(vb).unwrap();
    let old_fee = s.wallet.silent_spend(&txid).unwrap().unwrap().fee.unwrap();
    // At its own rate it pays too little to take its place: what does.
    let least = s.wallet.replace_silent(&txid, rate()).unwrap();
    let paid = 50_000 - least.output[0].value.to_sat();
    assert_eq!(paid, old_fee + least.vsize() as u64);
    let least_txid = least.compute_txid();
    let cancel = s.wallet.replace_silent(&least_txid, at(10)).unwrap();
    assert_signed(&s.chain.lock().unwrap(), &cancel);
    assert_eq!(cancel.input.len(), 2);
    assert!(cancel.input.iter().all(|i| spend
        .input
        .iter()
        .any(|o| o.previous_output == i.previous_output)));
    assert_eq!(cancel.output.len(), 1);
    let fee = at(10).fee_wu(cancel.weight()).unwrap().to_sat();
    assert_eq!(cancel.output[0].value.to_sat(), 50_000 - fee);
    let canceled = cancel.compute_txid();
    assert_eq!(
        s.wallet.silent_spends().unwrap(),
        std::slice::from_ref(&cancel)
    );
    assert!(s
        .wallet
        .silent_coins()
        .unwrap()
        .iter()
        .all(|c| c.spending == Some(canceled)));
    let spent = s.wallet.silent_spend(&canceled).unwrap().unwrap();
    assert_eq!((spent.fee, spent.height), (Some(fee), None));
    // The spends it took the place of are the coins' no more.
    for replaced in [txid, least_txid] {
        let again = s.wallet.replace_silent(&replaced, at(50));
        assert!(matches!(again, Err(Error::Invalid(_))), "{again:?}");
    }
    let unknown = s
        .wallet
        .replace_silent(&Txid::from_byte_array([1; 32]), at(50));
    assert!(
        matches!(unknown, Err(Error::UnknownPayment(_))),
        "{unknown:?}"
    );
    // Canceled again higher, the cancel is replaced the same way.
    let higher = s.wallet.replace_silent(&canceled, at(20)).unwrap();
    let higher_txid = higher.compute_txid();
    assert_eq!(
        s.wallet.silent_spends().unwrap(),
        std::slice::from_ref(&higher)
    );

    // Mined: its coin back, as change.
    s.mine(vec![higher.clone()]);
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.spent.len(), 2);
    assert_eq!(scanned.found.len(), 1);
    assert!(scanned.found[0].change);
    assert_eq!(scanned.found[0].value, higher.output[0].value.to_sat());
    assert!(s.wallet.silent_spends().unwrap().is_empty());
    assert_eq!(
        s.wallet.silent_spender(&coins[0]).unwrap(),
        Some((higher_txid, Some(4)))
    );
    // Its block replaced: the latest cancel is broadcast again.
    s.chain.lock().unwrap().fork(4);
    s.chain.lock().unwrap().mine_empty(2);
    s.scan().await.unwrap();
    assert_eq!(s.wallet.silent_spends().unwrap(), [higher]);
    assert_eq!(
        s.wallet.silent_spender(&coins[0]).unwrap(),
        Some((higher_txid, None))
    );
}

#[tokio::test]
async fn a_spend_bumped_pays_the_same_its_change_paying_the_fee() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address(), s.address()], &[30_000, 20_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let at = |vb: u64| FeeRate::from_sat_per_vb(vb).unwrap();
    let coin = s.wallet.silent_coins().unwrap()[0].outpoint;
    // A record of no value, as an activation of a lock.
    let record = ScriptBuf::from_bytes([&[0x6a, 4][..], b"lock"].concat());
    let spend = s
        .wallet
        .spend_silent_coin(record.clone(), coin, Some(0), rate())
        .unwrap();
    let txid = spend.compute_txid();
    let old_fee = s.wallet.silent_spend(&txid).unwrap().unwrap().fee.unwrap();
    let bumped = s.wallet.bump_silent(&txid, at(10)).unwrap();
    assert_signed(&s.chain.lock().unwrap(), &bumped);
    let spent = |tx: &Transaction| {
        tx.input
            .iter()
            .map(|i| i.previous_output)
            .collect::<Vec<_>>()
    };
    assert_eq!(spent(&bumped), spent(&spend));
    assert_eq!(bumped.output.len(), spend.output.len());
    let kept = |tx: &Transaction| tx.output.iter().position(|o| o.script_pubkey == record);
    assert_eq!(kept(&bumped), kept(&spend));
    let change = |tx: &Transaction| {
        (tx.output.iter().find(|o| o.script_pubkey != record))
            .unwrap()
            .clone()
    };
    assert_eq!(change(&bumped).script_pubkey, change(&spend).script_pubkey);
    let fee = change(&spend).value.to_sat() - change(&bumped).value.to_sat() + old_fee;
    assert_eq!(fee, at(10).fee_wu(bumped.weight()).unwrap().to_sat());
    let bumped_txid = bumped.compute_txid();
    assert_eq!(
        s.wallet.silent_spends().unwrap(),
        std::slice::from_ref(&bumped)
    );
    assert_eq!(
        s.wallet.silent_spender(&coin).unwrap(),
        Some((bumped_txid, None))
    );
    // Both pay the record until one is in a block.
    assert_eq!(s.wallet.silent_spends_paying(&record).unwrap().len(), 2);
    // The spend it took the place of is the coin's no more.
    let again = s.wallet.bump_silent(&txid, at(50));
    assert!(matches!(again, Err(Error::Invalid(_))), "{again:?}");
    // Its change cannot pay so much: refused, not dropped.
    let much = s.wallet.bump_silent(&bumped_txid, at(10_000));
    assert!(matches!(much, Err(Error::Insufficient { .. })), "{much:?}");

    // Mined: the record paid, its change back.
    s.mine(vec![bumped.clone()]);
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.found.len(), 1);
    assert!(scanned.found[0].change);
    assert_eq!(scanned.found[0].value, change(&bumped).value.to_sat());
    let paid = s.wallet.silent_spends_paying(&record).unwrap();
    let mined: Vec<_> = paid.iter().filter(|p| p.height.is_some()).collect();
    assert_eq!(mined.len(), 1);
    assert_eq!(mined[0].tx, bumped);

    // One paying no change cannot be bumped.
    let other = s.wallet.silent_coins().unwrap();
    let whole = other.iter().find(|c| !c.change).unwrap().outpoint;
    let all = s
        .wallet
        .spend_silent_coin(elsewhere(), whole, None, rate())
        .unwrap();
    let none = s.wallet.bump_silent(&all.compute_txid(), at(10));
    assert!(matches!(none, Err(Error::Invalid(_))), "{none:?}");
}

#[tokio::test]
async fn a_spend_canceled_that_confirms_after_all_gives_its_cancel_up() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[30_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let coin = s.wallet.silent_coins().unwrap()[0].outpoint;
    let spend = s
        .wallet
        .spend_silent(elsewhere(), Some(10_000), rate())
        .unwrap();
    let txid = spend.compute_txid();
    let rate = FeeRate::from_sat_per_vb(10).unwrap();
    s.wallet.replace_silent(&txid, rate).unwrap();
    s.mine(vec![spend.clone()]);
    s.scan().await.unwrap();
    assert!(s.wallet.silent_spends().unwrap().is_empty());
    assert_eq!(
        s.wallet.silent_spender(&coin).unwrap(),
        Some((txid, Some(4)))
    );
    let paid = s.wallet.silent_spends_paying(&elsewhere()).unwrap();
    assert_eq!(paid.len(), 1);
    assert_eq!((paid[0].tx.compute_txid(), paid[0].height), (txid, Some(4)));
    // Its change found, free.
    let coins = s.wallet.silent_coins().unwrap();
    assert_eq!(coins.len(), 1);
    assert!(coins[0].change && coins[0].spending.is_none());
}

/// A transaction spending another party's coin, then the wallet's coin
/// `coin`, paying `value` elsewhere, and the coins it spends: a contract's
/// funding, as far as the wallet sees it.
fn shared(chain: &Chain, coin: OutPoint, value: u64) -> (Transaction, Vec<TxOut>) {
    let theirs = OutPoint::new(Txid::from_byte_array([3; 32]), 0);
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: [theirs, coin]
            .map(|previous_output| TxIn {
                previous_output,
                ..Default::default()
            })
            .to_vec(),
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: elsewhere(),
        }],
    };
    let prevouts = vec![
        TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: elsewhere(),
        },
        chain.outputs[&coin].clone(),
    ];
    (tx, prevouts)
}

#[tokio::test]
async fn a_coin_signed_into_anothers_transaction_is_reserved_for_it() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[10_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let coin = s.wallet.silent_coins().unwrap()[0].outpoint;
    let (tx, prevouts) = shared(&s.chain.lock().unwrap(), coin, 55_000);
    let txid = tx.compute_txid();

    // Its input signed as the coin it spends, committing to every coin:
    // the other party's left as it was.
    let signed = s.wallet.sign_input(&tx, &prevouts, 1).unwrap();
    assert_eq!(signed.compute_txid(), txid);
    assert!(signed.input[0].witness.is_empty());
    let mut cache = SighashCache::new(&signed);
    let sighash = cache
        .taproot_key_spend_signature_hash(1, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap();
    let signature = bitcoin::taproot::Signature::from_slice(&signed.input[1].witness[0]).unwrap();
    let key = XOnlyPublicKey::from_slice(&prevouts[1].script_pubkey.as_bytes()[2..]).unwrap();
    let message = Message::from_digest(sighash.to_byte_array());
    Secp256k1::verification_only()
        .verify_schnorr(&signature.signature, &message, &key)
        .unwrap();

    // Reserved for it, nothing to broadcast: no spend takes the coin.
    assert_eq!(s.wallet.silent_coins().unwrap()[0].spending, Some(txid));
    assert!(s.wallet.silent_spends().unwrap().is_empty());
    let spend = s.wallet.spend_silent(elsewhere(), None, rate());
    assert!(
        matches!(spend, Err(Error::Insufficient { .. })),
        "{spend:?}"
    );
    // Signed again for it alone.
    s.wallet.sign_input(&tx, &prevouts, 1).unwrap();
    let (other, other_prevouts) = shared(&s.chain.lock().unwrap(), coin, 54_000);
    let again = s.wallet.sign_input(&other, &other_prevouts, 1);
    assert!(matches!(again, Err(Error::NoteTaken)), "{again:?}");

    // Never the other party's coin, nor the wallet's for another value.
    let theirs = s.wallet.sign_input(&tx, &prevouts, 0);
    assert!(matches!(theirs, Err(Error::Invalid(_))), "{theirs:?}");
    let mut lied = prevouts.clone();
    lied[1].value = Amount::from_sat(20_000);
    let lied = s.wallet.sign_input(&tx, &lied, 1);
    assert!(matches!(lied, Err(Error::Invalid(_))), "{lied:?}");
    let short = s.wallet.sign_input(&tx, &prevouts[1..], 1);
    assert!(matches!(short, Err(Error::Invalid(_))), "{short:?}");

    // Given up, the coin is free again.
    s.wallet.abandon_silent(&txid).unwrap();
    assert_eq!(s.wallet.silent_coins().unwrap()[0].spending, None);
    s.wallet.spend_silent(elsewhere(), None, rate()).unwrap();
}

/// The other party never completed the transaction the wallet's coin was
/// signed into: the coin spent back to the wallet in its place, the same
/// cancel each time asked, and found as its change once mined.
#[tokio::test]
async fn a_coin_signed_into_anothers_transaction_is_canceled_back_to_the_wallet() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[10_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let coin = s.wallet.silent_coins().unwrap()[0].outpoint;
    let (tx, prevouts) = shared(&s.chain.lock().unwrap(), coin, 55_000);

    // Nothing to cancel before it is signed into it; never their coin.
    let early = s.wallet.cancel_signed(&tx, 1, rate());
    assert!(matches!(early, Err(Error::Invalid(_))), "{early:?}");
    s.wallet.sign_input(&tx, &prevouts, 1).unwrap();
    let theirs = s.wallet.cancel_signed(&tx, 0, rate());
    assert!(matches!(theirs, Err(Error::Invalid(_))), "{theirs:?}");

    let cancel = s.wallet.cancel_signed(&tx, 1, rate()).unwrap();
    assert_eq!(cancel.input.len(), 1);
    assert_eq!(cancel.input[0].previous_output, coin);
    assert_eq!(cancel.output.len(), 1);
    let id = cancel.compute_txid();
    assert_eq!(s.wallet.silent_coins().unwrap()[0].spending, Some(id));
    assert_eq!(s.wallet.cancel_signed(&tx, 1, rate()).unwrap(), cancel);
    // Signed into it no more.
    let again = s.wallet.sign_input(&tx, &prevouts, 1);
    assert!(matches!(again, Err(Error::NoteTaken)), "{again:?}");

    s.mine(vec![cancel]);
    s.scan().await.unwrap();
    let coins = s.wallet.silent_coins().unwrap();
    assert_eq!(coins.len(), 1);
    assert!(coins[0].change && coins[0].outpoint.txid == id);
}

#[tokio::test]
async fn a_coin_set_aside_under_a_marker_is_taken_by_nothing_until_freed() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[10_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let coin = s.wallet.silent_coins().unwrap()[0].outpoint;
    let marker = Txid::from_byte_array([7; 32]);

    // Set aside, again with no error: nothing to broadcast, no spend.
    s.wallet.reserve_silent(&coin, &marker).unwrap();
    s.wallet.reserve_silent(&coin, &marker).unwrap();
    assert_eq!(s.wallet.silent_coins().unwrap()[0].spending, Some(marker));
    assert!(s.wallet.silent_spends().unwrap().is_empty());
    let spend = s.wallet.spend_silent(elsewhere(), None, rate());
    assert!(
        matches!(spend, Err(Error::Insufficient { .. })),
        "{spend:?}"
    );
    // Neither another's transaction nor another marker takes it.
    let (tx, prevouts) = shared(&s.chain.lock().unwrap(), coin, 55_000);
    let signed = s.wallet.sign_input(&tx, &prevouts, 1);
    assert!(matches!(signed, Err(Error::NoteTaken)), "{signed:?}");
    let other = s
        .wallet
        .reserve_silent(&coin, &Txid::from_byte_array([8; 32]));
    assert!(matches!(other, Err(Error::NoteTaken)), "{other:?}");
    let unknown = OutPoint::new(Txid::from_byte_array([9; 32]), 0);
    let unknown = s.wallet.reserve_silent(&unknown, &marker);
    assert!(matches!(unknown, Err(Error::Invalid(_))), "{unknown:?}");

    // Freed, another's transaction takes it.
    s.wallet.abandon_silent(&marker).unwrap();
    s.wallet.sign_input(&tx, &prevouts, 1).unwrap();
}

#[tokio::test]
async fn the_block_a_coin_signed_into_anothers_transaction_is_spent_in_is_known() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[10_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let coin = s.wallet.silent_coins().unwrap()[0].outpoint;
    let (tx, mut prevouts) = shared(&s.chain.lock().unwrap(), coin, 55_000);
    // The other party's coin, on the chain: of a script-hash, no tweak.
    let theirs = tx.input[0].previous_output;
    let script = ScriptBuf::from_bytes(vec![0x51]);
    prevouts[0].script_pubkey = ScriptBuf::new_p2wsh(&script.wscript_hash());
    let output = prevouts[0].clone();
    s.chain.lock().unwrap().outputs.insert(theirs, output);
    let signed = s.wallet.sign_input(&tx, &prevouts, 1).unwrap();

    // Signed, in no block yet; nor is a coin not the wallet's.
    assert_eq!(s.wallet.silent_spent_at(&coin).unwrap(), None);
    assert_eq!(s.wallet.silent_spent_at(&theirs).unwrap(), None);

    // In block 4, however deep.
    s.mine(vec![signed]);
    s.mine(Vec::new());
    s.scan().await.unwrap();
    assert_eq!(s.wallet.silent_spent_at(&coin).unwrap(), Some(4));

    // That block replaced, without it: in none again.
    s.chain.lock().unwrap().fork(4);
    s.chain.lock().unwrap().mine_empty(3);
    s.scan().await.unwrap();
    assert_eq!(s.wallet.silent_spent_at(&coin).unwrap(), None);
}

#[test]
fn a_wallets_contract_secrets_are_its_own_and_its_spending_roots() {
    let dir = tempfile::tempdir().unwrap();
    let open = |name: &str, seed: [u8; 32]| {
        let path = dir.path().join(name);
        Wallet::create(&path, &seed, REGTEST, Link(Net::new())).unwrap()
    };
    let a = open("a.sqlite", [7; 32]).contract_secrets();
    let again = open("again.sqlite", [7; 32]).contract_secrets();
    let b = open("b.sqlite", [8; 32]).contract_secrets();
    assert_eq!((a.seed, a.spend), (again.seed, again.spend));
    assert_ne!(a.seed, b.seed);
    assert_ne!(a.spend, b.spend);
    // Of a domain of its own: neither the seed nor the spending root's.
    assert_ne!(a.seed, [7; 32]);
    let owner = licash::address::OwnerKeys::from_seed(&[7; 32]).unwrap();
    assert_eq!(a.spend, *owner.spend_secret());
    assert_eq!(format!("{a:?}"), "ContractSecrets(..)");
}

/// A spend given up takes those it took the place of with it: none comes
/// back once looked in again. One it took the place of, given up, leaves
/// it.
#[tokio::test]
async fn a_replacement_given_up_takes_what_it_replaced_with_it() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[20_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    let free = |s: &Setup| {
        s.wallet
            .silent_coins()
            .unwrap()
            .iter()
            .all(|c| c.spending.is_none())
    };
    let spend = s
        .wallet
        .spend_silent(elsewhere(), Some(5_000), rate())
        .unwrap();
    let at = |sat| FeeRate::from_sat_per_vb(sat).unwrap();
    let bumped = s.wallet.bump_silent(&spend.compute_txid(), at(10)).unwrap();
    s.wallet.abandon_silent(&spend.compute_txid()).unwrap();
    assert_eq!(
        s.wallet.silent_spends().unwrap(),
        std::slice::from_ref(&bumped)
    );
    let canceled = s
        .wallet
        .replace_silent(&bumped.compute_txid(), at(20))
        .unwrap();
    s.wallet.abandon_silent(&canceled.compute_txid()).unwrap();
    assert!(free(&s));
    // Looked in again from the first block: still free, nothing to send.
    s.wallet.watch_silent(HUB, 1).unwrap();
    s.scan().await.unwrap();
    assert!(free(&s));
    assert!(s.wallet.silent_spends().unwrap().is_empty());
    assert_eq!(s.wallet.silent_spend(&bumped.compute_txid()).unwrap(), None);
}

/// A key paid again, twice in its transaction or in another of the same
/// block: each coin found.
#[tokio::test]
async fn every_output_paying_a_key_found_is_found() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let mut paying = s.pay(&[s.address()], &[20_000]);
    let script = paying.output[0].script_pubkey.clone();
    paying.output.push(TxOut {
        value: Amount::from_sat(5_000),
        script_pubkey: script.clone(),
    });
    let again = s.pay_plain(&script, 7_000);
    s.mine(vec![paying, again]);
    let mut values: Vec<u64> = s
        .scan()
        .await
        .unwrap()
        .found
        .iter()
        .map(|c| c.value)
        .collect();
    values.sort();
    assert_eq!(values, [5_000, 7_000, 20_000]);
}

#[tokio::test]
async fn a_spend_a_block_conflicts_with_is_given_up() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address(), s.address()], &[20_000, 10_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();
    // The larger coin alone, given up; then both.
    let first = s
        .wallet
        .spend_silent(elsewhere(), Some(5_000), rate())
        .unwrap();
    assert_eq!(first.input.len(), 1);
    s.wallet.abandon_silent(&first.compute_txid()).unwrap();
    let second = s
        .wallet
        .spend_silent(elsewhere(), Some(25_000), rate())
        .unwrap();
    assert_eq!(second.input.len(), 2);
    // The first confirms after all: the second never can.
    s.mine(vec![first.clone()]);
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.spent, [first.input[0].previous_output]);
    assert!(s.wallet.silent_spends().unwrap().is_empty());
    // The smaller coin is free, beside the first's change.
    let coins = s.wallet.silent_coins().unwrap();
    assert_eq!(coins.len(), 2);
    assert!(coins.iter().all(|c| c.spending.is_none()));
    assert!(coins.iter().any(|c| c.value == 10_000 && !c.change));
    assert!(coins.iter().any(|c| c.change));
    // Its block replaced: both coins are free.
    s.chain.lock().unwrap().fork(4);
    s.chain.lock().unwrap().mine_empty(2);
    s.scan().await.unwrap();
    let coins = s.wallet.silent_coins().unwrap();
    assert_eq!(coins.len(), 2);
    assert!(coins.iter().all(|c| c.spending.is_none() && !c.change));
}

#[tokio::test]
async fn a_block_unlike_its_header_is_refused() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    s.chain.lock().unwrap().tampered = true;
    match s.scan().await {
        Err(Error::Chain(why)) => assert!(why.contains("header"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s.wallet.silent_next().unwrap(), Some(1));
    s.chain.lock().unwrap().tampered = false;
    assert_eq!(s.scan().await.unwrap().found.len(), 1);
}

#[tokio::test]
async fn without_filters_the_blocks_that_could_pay_or_spend_are_fetched() {
    let s = setup().await;
    s.chain.lock().unwrap().filters = false;
    s.wallet.watch_silent(HUB, 3).unwrap();
    let other = s.pay(&[stranger()], &[10_000]);
    let theirs = s.mine(vec![other]);
    s.mine(Vec::new());
    let scanned = s.scan().await.unwrap();
    assert!(scanned.found.is_empty());
    assert_eq!(s.fetched(), [theirs]);
    // Once it holds a coin, any block may spend it.
    let paying = s.pay(&[s.address()], &[10_000]);
    let paid = s.mine(vec![paying]);
    let empty = s.mine(Vec::new());
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.found.len(), 1);
    assert_eq!(s.fetched(), [paid, empty]);
    assert_eq!(scanned.fetched, 2);
}

#[tokio::test]
async fn a_reorganization_drops_what_the_replaced_blocks_held() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying.clone()]);
    s.mine(Vec::new());
    assert_eq!(s.scan().await.unwrap().found[0].height, 3);

    // Blocks 3 and 4 replaced, without the payment: a chain behind the
    // blocks looked in proves nothing yet.
    s.chain.lock().unwrap().fork(3);
    s.chain.lock().unwrap().mine_empty(1);
    let scanned = s.scan().await.unwrap();
    assert_eq!((scanned.next, scanned.height), (5, 3));
    assert_eq!(s.wallet.silent_coins().unwrap().len(), 1);
    s.chain.lock().unwrap().mine_empty(2);
    let scanned = s.scan().await.unwrap();
    assert_eq!((scanned.next, scanned.height), (6, 5));
    assert!(scanned.found.is_empty());
    assert!(s.wallet.silent_coins().unwrap().is_empty());

    // Mined again later: found again.
    s.mine(vec![paying.clone()]);
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.found.len(), 1);
    assert_eq!(scanned.found[0].height, 6);

    // The wallet's spend, in no block yet, outlives its coin's block.
    let spend = s.wallet.spend_silent(elsewhere(), None, rate()).unwrap();
    let txid = spend.compute_txid();
    s.chain.lock().unwrap().fork(6);
    s.mine(Vec::new());
    s.mine(vec![paying.clone()]);
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.next, 8);
    let coins = s.wallet.silent_coins().unwrap();
    assert_eq!(coins.len(), 1);
    assert_eq!(coins[0].height, 7);
    assert_eq!(coins[0].spending, Some(txid));
    assert_eq!(
        s.wallet.silent_spends().unwrap(),
        std::slice::from_ref(&spend)
    );

    // Its spend's block replaced: the coin is the wallet's again, its
    // spend still to broadcast.
    s.mine(vec![spend.clone()]);
    s.scan().await.unwrap();
    assert!(s.wallet.silent_coins().unwrap().is_empty());
    s.chain.lock().unwrap().fork(8);
    s.chain.lock().unwrap().mine_empty(2);
    s.scan().await.unwrap();
    let coins = s.wallet.silent_coins().unwrap();
    assert_eq!(coins.len(), 1);
    assert_eq!(coins[0].spending, Some(txid));
    assert_eq!(s.wallet.silent_spends().unwrap(), [spend]);
}

#[tokio::test]
async fn a_reorganization_deeper_than_the_blocks_kept_needs_a_look_again() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    s.chain.lock().unwrap().mine_empty(297);
    assert_eq!(s.scan().await.unwrap().found.len(), 1);
    s.chain.lock().unwrap().fork(3);
    s.chain.lock().unwrap().mine_empty(299);
    match s.scan().await {
        Err(Error::Invalid(why)) => assert!(why.contains("deeper"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s.wallet.silent_coins().unwrap().len(), 1);
    s.wallet.watch_silent(HUB, 1).unwrap();
    let scanned = s.scan().await.unwrap();
    assert_eq!((scanned.next, scanned.height), (302, 301));
    assert!(s.wallet.silent_coins().unwrap().is_empty());
}

#[tokio::test]
async fn tweaks_of_another_block_than_the_chains_are_refused() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    *s.hub.forged.lock().unwrap() = Some(2);
    match s.scan().await {
        Err(Error::Unavailable { hub, reason }) => {
            assert_eq!(hub, HUB);
            assert!(reason.contains("block 2"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    // Nothing of the batch was recorded.
    assert_eq!(s.wallet.silent_next().unwrap(), Some(1));
    *s.hub.forged.lock().unwrap() = None;
    assert_eq!(s.scan().await.unwrap().found.len(), 1);
}

#[tokio::test]
async fn a_fallback_address_is_watched_once_handed_out_and_the_next_once_paid() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let first = fallback_of(&s.wallet, 0);
    // None handed out: none watched, blocks without tweaks not even filtered.
    let plain = s.wallet.payment_code(&[HUB.into()]).unwrap();
    assert_eq!(plain.address, None);
    let early = s.pay_plain(&first, 10_000);
    let paid = s.mine(vec![early]);
    s.mine(Vec::new());
    assert!(s.scan().await.unwrap().found.is_empty());
    assert_eq!(s.chain.lock().unwrap().filtered, 0);

    // Handed out in a code, its QR's too, and the same until paid.
    let code = s.wallet.onchain_code(true).unwrap();
    assert!(code.qr().starts_with("BITCOIN:BCRT1P"), "{}", code.qr());
    assert!(code.qr().contains("?SP=TSP1Q"), "{}", code.qr());
    assert_eq!(code.to_string().parse::<PaymentCode>().unwrap(), code);
    assert_eq!(s.fallback(), first);
    // Looked for again: found, in the one block paying it.
    s.wallet.watch_silent(HUB, 1).unwrap();
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.found.len(), 1);
    let coin = &scanned.found[0];
    assert_eq!((coin.value, coin.height, coin.change), (10_000, 3, false));
    assert_eq!(s.fetched(), [paid]);

    // Paid: the next is handed out, the first still watched.
    let second = s.fallback();
    assert_eq!(second, fallback_of(&s.wallet, 1));
    assert_eq!(s.fallback(), second);
    let again = s.pay_plain(&first, 20_000);
    let to_second = s.pay_plain(&second, 30_000);
    s.mine(vec![again, to_second]);
    assert_eq!(s.scan().await.unwrap().found.len(), 2);
    assert_eq!(s.fallback(), fallback_of(&s.wallet, 2));

    // Spent with the spend key, like any coin of the address.
    let all = s.wallet.spend_silent(elsewhere(), None, rate()).unwrap();
    assert_eq!(all.input.len(), 3);
    assert_signed(&s.chain.lock().unwrap(), &all);
}

#[tokio::test]
async fn a_wallet_restored_watches_the_fallback_addresses_its_copy_handed_out() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    // Its copy handed out the first two and was paid at the second.
    let paying = s.pay_plain(&fallback_of(&s.wallet, 1), 10_000);
    s.mine(vec![paying]);
    s.wallet.watch_fallbacks().unwrap();
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.found.len(), 1);
    // Watching again changes nothing: the next handed out is past it.
    s.wallet.watch_fallbacks().unwrap();
    assert_eq!(s.fallback(), fallback_of(&s.wallet, 2));
    // Paid past the 20 after the first handed out, as its copy went on:
    // watched 20 past the last paid.
    let paying = s.pay_plain(&fallback_of(&s.wallet, 1 + 20), 20_000);
    s.mine(vec![paying]);
    assert_eq!(s.scan().await.unwrap().found.len(), 1);
    assert_eq!(s.fallback(), fallback_of(&s.wallet, 22));
}

#[tokio::test]
async fn the_fallback_address_handed_out_never_goes_back() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let first = s.fallback();
    let paying = s.pay_plain(&first, 10_000);
    s.mine(vec![paying]);
    assert_eq!(s.scan().await.unwrap().found.len(), 1);
    let second = s.fallback();
    assert_eq!(second, fallback_of(&s.wallet, 1));
    // Its payment reorganized away: the second is still the one handed out.
    s.chain.lock().unwrap().fork(3);
    s.chain.lock().unwrap().mine_empty(2);
    s.scan().await.unwrap();
    assert!(s.wallet.silent_coins().unwrap().is_empty());
    assert_eq!(s.fallback(), second);
    // A copy of the wallet handed out more: paid there, found here, and
    // handed out past it.
    let paying = s.pay_plain(&fallback_of(&s.wallet, 5), 10_000);
    s.mine(vec![paying]);
    assert_eq!(s.scan().await.unwrap().found.len(), 1);
    assert_eq!(s.fallback(), fallback_of(&s.wallet, 6));
    // Beyond the 20 watched past it: not found.
    let paying = s.pay_plain(&fallback_of(&s.wallet, 6 + 20 + 1), 10_000);
    s.mine(vec![paying]);
    assert!(s.scan().await.unwrap().found.is_empty());
}

/// The outputs of `tx` that `keys` finds paying it, by the tweak of the
/// coins `chain` holds that it spends.
fn found_by(chain: &Chain, keys: &silent::Keys, tx: &Transaction) -> Vec<u64> {
    let spent: Vec<&bitcoin::Script> = tx
        .input
        .iter()
        .map(|i| chain.outputs[&i.previous_output].script_pubkey.as_script())
        .collect();
    let tweak = silent::tweak(tx, &spent).unwrap();
    let found = keys
        .scanner([silent::CHANGE])
        .scan(&tweak, &silent::taproot_outputs(tx));
    let value = |key: XOnlyPublicKey| {
        let script = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key));
        tx.output
            .iter()
            .find(|o| o.script_pubkey == script)
            .unwrap()
            .value
            .to_sat()
    };
    let mut values: Vec<u64> = found.iter().map(|f| value(f.output)).collect();
    values.sort();
    values
}

#[tokio::test]
async fn a_spend_pays_a_silent_payment_address_its_receiver_finds() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    let paying = s.pay(&[s.address()], &[50_000]);
    s.mine(vec![paying]);
    s.scan().await.unwrap();

    // Another network's address is refused, its coins left free.
    let main = silent::Keys::from_seed(&[9; 32], bitcoin::NetworkKind::Main).unwrap();
    match s.wallet.spend_silent(main.address(), Some(20_000), rate()) {
        Err(Error::Invalid(why)) => assert!(why.contains("not of regtest"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(s.wallet.silent_spends().unwrap().is_empty());

    // Someone else's: they find what it pays them, the wallet its change.
    let them = silent::Keys::from_seed(&[9; 32], bitcoin::NetworkKind::Test).unwrap();
    assert_eq!(them.address(), stranger());
    let spend = s
        .wallet
        .spend_silent(stranger(), Some(20_000), rate())
        .unwrap();
    assert_signed(&s.chain.lock().unwrap(), &spend);
    assert_eq!(spend.output.len(), 2);
    assert!(spend.output.iter().all(|o| o.script_pubkey.is_p2tr()));
    assert_eq!(found_by(&s.chain.lock().unwrap(), &them, &spend), [20_000]);
    s.mine(vec![spend.clone()]);
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.found.len(), 1);
    assert!(scanned.found[0].change);
    let fee = rate().fee_wu(spend.weight()).unwrap().to_sat();
    let change = 50_000 - 20_000 - fee;
    assert_eq!(scanned.found[0].value, change);

    // Its own address: the payment and the change, derived together, both
    // found again.
    let to_self = s
        .wallet
        .spend_silent(s.address(), Some(10_000), rate())
        .unwrap();
    assert_eq!(to_self.output.len(), 2);
    s.mine(vec![to_self.clone()]);
    let scanned = s.scan().await.unwrap();
    let mut found: Vec<(u64, bool)> = scanned.found.iter().map(|c| (c.value, c.change)).collect();
    found.sort();
    let fee = rate().fee_wu(to_self.weight()).unwrap().to_sat();
    assert_eq!(found, [(10_000, false), (change - 10_000 - fee, true)]);
}

#[tokio::test]
async fn payments_to_fallback_addresses_are_seen_on_their_way() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    // None handed out: nothing to watch.
    assert!(s.wallet.fallback_scripts().unwrap().is_empty());
    let first = s.fallback();
    let watched = s.wallet.fallback_scripts().unwrap();
    // The one handed out and 20 after.
    assert_eq!(watched.len(), 21);
    assert!(watched.contains(&first));
    assert!(watched.contains(&fallback_of(&s.wallet, 20)));

    // On its way: its output to the address, once however often relayed,
    // and nothing of a payment elsewhere.
    let paying = s.pay_plain(&first, 10_000);
    let other = s.pay_plain(&elsewhere(), 5_000);
    let txs = [paying.clone(), other, paying.clone()];
    let seen = s.wallet.unconfirmed_payments(&txs).unwrap();
    let vout = paying.output.iter().position(|o| o.script_pubkey == first);
    let outpoint = OutPoint::new(paying.compute_txid(), vout.unwrap() as u32);
    assert_eq!(seen, [(outpoint, 10_000)]);

    // Found in a block: no longer on its way, even once spent.
    s.mine(vec![paying.clone()]);
    assert_eq!(s.scan().await.unwrap().found.len(), 1);
    assert!(s.wallet.unconfirmed_payments(&txs).unwrap().is_empty());
    let spend = s.wallet.spend_silent(elsewhere(), None, rate()).unwrap();
    s.mine(vec![spend]);
    s.scan().await.unwrap();
    assert!(s.wallet.unconfirmed_payments(&txs).unwrap().is_empty());
}

#[tokio::test]
async fn without_tweaks_fallback_payments_their_spends_and_change_are_found() {
    let s = setup().await;
    *s.hub.first.lock().unwrap() = None;
    s.wallet.add_hub(HUB).await.unwrap();
    assert!(s.wallet.watch_silent(HUB, 1).is_err());
    s.wallet.watch_silent(None, 1).unwrap();
    let light = Light(s.chain.clone());
    let paying = s.pay_plain(&s.fallback(), 30_000);
    let silent = s.pay(&[s.address()], &[20_000]);
    s.mine(vec![paying]);
    s.mine(vec![silent]);
    let scanned = s.wallet.scan_silent(None, &light, u32::MAX).await.unwrap();
    assert_eq!((scanned.next, scanned.height), (5, 4));
    // The fallback payment only: a silent payment needs its tweak.
    let values: Vec<u64> = scanned.found.iter().map(|c| c.value).collect();
    assert_eq!(values, [30_000]);

    // Its spend, and the change of it, found with the tweak of the coins
    // it spends.
    let spend = s
        .wallet
        .spend_silent(elsewhere(), Some(10_000), rate())
        .unwrap();
    assert_eq!(spend.output.len(), 2);
    s.mine(vec![spend.clone()]);
    let scanned = s.wallet.scan_silent(None, &light, u32::MAX).await.unwrap();
    assert_eq!(scanned.spent.len(), 1);
    assert_eq!(scanned.found.len(), 1);
    let change = scanned.found[0].clone();
    assert!(change.change);
    assert_eq!(change.outpoint.txid, spend.compute_txid());
    // Spendable, and seen spent.
    let all = s.wallet.spend_silent(elsewhere(), None, rate()).unwrap();
    assert_signed(&s.chain.lock().unwrap(), &all);
    s.mine(vec![all]);
    let scanned = s.wallet.scan_silent(None, &light, u32::MAX).await.unwrap();
    assert_eq!(scanned.spent, [change.outpoint]);
    assert!(s.wallet.silent_coins().unwrap().is_empty());
    assert_eq!(*s.hub.asked.lock().unwrap(), 0);
}

#[tokio::test]
async fn blocks_looked_in_without_tweaks_are_looked_in_again_once_a_hub_serves_them() {
    let s = setup().await;
    let light = Light(s.chain.clone());
    s.wallet.watch_silent(None, 1).unwrap();
    let plain = s.pay_plain(&s.fallback(), 30_000);
    let silent = s.pay(&[s.address()], &[20_000]);
    s.mine(vec![plain]);
    s.mine(vec![silent]);
    let scanned = s.wallet.scan_silent(None, &light, u32::MAX).await.unwrap();
    assert_eq!(scanned.found.len(), 1);
    // The wallet's spend, in no block yet, outlives looking again.
    let spend = s
        .wallet
        .spend_silent(elsewhere(), Some(10_000), rate())
        .unwrap();
    let txid = spend.compute_txid();

    // From the first block looked in without tweaks: the silent payment
    // found, the fallback payment again, once.
    let scanned = s.scan().await.unwrap();
    assert_eq!((scanned.next, scanned.height), (5, 4));
    let mut values: Vec<u64> = scanned.found.iter().map(|c| c.value).collect();
    values.sort();
    assert_eq!(values, [20_000, 30_000]);
    let mut coins: Vec<_> = s
        .wallet
        .silent_coins()
        .unwrap()
        .into_iter()
        .map(|c| (c.value, c.spending))
        .collect();
    coins.sort();
    assert_eq!(coins, [(20_000, None), (30_000, Some(txid))]);
    assert_eq!(s.wallet.silent_spends().unwrap(), [spend]);
    // Once.
    s.chain.lock().unwrap().mine_empty(1);
    s.fetched();
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.next, 6);
    assert!(scanned.found.is_empty());
    assert!(s.fetched().is_empty());
}

#[tokio::test]
async fn looking_again_with_tweaks_starts_at_the_first_block_the_hub_serves() {
    let s = setup().await;
    let light = Light(s.chain.clone());
    s.wallet.watch_silent(None, 1).unwrap();
    let early = s.pay(&[s.address()], &[10_000]);
    s.mine(vec![early]);
    s.chain.lock().unwrap().mine_empty(2);
    let late = s.pay(&[s.address()], &[20_000]);
    s.mine(vec![late]);
    let scanned = s.wallet.scan_silent(None, &light, u32::MAX).await.unwrap();
    assert_eq!(scanned.next, 7);
    assert!(scanned.found.is_empty());

    // A hub serving tweaks from after the next block is refused, and what
    // was looked in without them is still to look in again.
    s.chain.lock().unwrap().mine_empty(3);
    *s.hub.first.lock().unwrap() = Some(8);
    s.wallet.add_hub(HUB).await.unwrap();
    match s.scan().await {
        Err(Error::Invalid(why)) => assert!(why.contains("from block 8 on"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s.wallet.silent_next().unwrap(), Some(7));

    // One serving them from block 5: from it, not before.
    *s.hub.first.lock().unwrap() = Some(5);
    s.wallet.add_hub(HUB).await.unwrap();
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.next, 10);
    let values: Vec<u64> = scanned.found.iter().map(|c| c.value).collect();
    assert_eq!(values, [20_000]);
    // Again with it: nothing more to look in.
    s.chain.lock().unwrap().mine_empty(1);
    assert!(s.scan().await.unwrap().found.is_empty());
    // The blocks before, once a hub serves their tweaks: from the first
    // looked in without them, once.
    *s.hub.first.lock().unwrap() = Some(1);
    s.wallet.add_hub(HUB).await.unwrap();
    let mut values: Vec<u64> = s
        .scan()
        .await
        .unwrap()
        .found
        .iter()
        .map(|c| c.value)
        .collect();
    values.sort();
    assert_eq!(values, [10_000, 20_000]);
    assert!(s.scan().await.unwrap().found.is_empty());
    // Looked in again from one, as asked.
    s.wallet.watch_silent(HUB, 1).unwrap();
    assert_eq!(s.scan().await.unwrap().found.len(), 2);
}

#[tokio::test]
async fn a_reorganization_of_blocks_looked_in_without_tweaks_keeps_them_to_look_in_again() {
    let s = setup().await;
    let light = Light(s.chain.clone());
    s.wallet.watch_silent(HUB, 1).unwrap();
    s.scan().await.unwrap();
    // Blocks 3 on looked in without tweaks.
    let silent = s.pay(&[s.address()], &[10_000]);
    s.mine(vec![silent.clone()]);
    s.chain.lock().unwrap().mine_empty(2);
    s.wallet.scan_silent(None, &light, u32::MAX).await.unwrap();
    // Replaced from block 4, then from block 2, each looked in without
    // tweaks again.
    for at in [4, 2] {
        s.chain.lock().unwrap().fork(at);
        s.chain.lock().unwrap().mine_empty(6 - at);
        if at == 2 {
            s.mine(vec![silent.clone()]);
        }
        let scanned = s.wallet.scan_silent(None, &light, u32::MAX).await.unwrap();
        assert!(scanned.found.is_empty());
    }
    let scanned = s.scan().await.unwrap();
    let found: Vec<(u64, u32)> = scanned.found.iter().map(|c| (c.value, c.height)).collect();
    assert_eq!(found, [(10_000, 6)]);
    assert!(s.scan().await.unwrap().found.is_empty());
}

#[tokio::test]
async fn a_hub_serving_tweaks_from_the_next_block_looks_in_none_again() {
    let s = setup().await;
    let light = Light(s.chain.clone());
    s.wallet.watch_silent(None, 1).unwrap();
    s.chain.lock().unwrap().mine_empty(2);
    let scanned = s.wallet.scan_silent(None, &light, u32::MAX).await.unwrap();
    assert_eq!(scanned.next, 5);
    // Tweaks from block 5 on: what was looked in without them stays so,
    // and the first batch with them is looked in once.
    *s.hub.first.lock().unwrap() = Some(5);
    s.wallet.add_hub(HUB).await.unwrap();
    let paying = s.pay(&[s.address()], &[10_000]);
    s.mine(vec![paying]);
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.next, 6);
    assert_eq!(scanned.found.len(), 1);
    s.fetched();
    let scanned = s.scan().await.unwrap();
    assert_eq!(scanned.next, 6);
    assert!(scanned.found.is_empty());
    assert!(s.fetched().is_empty());
    assert_eq!(s.wallet.silent_coins().unwrap().len(), 1);
}

/// The warnings logged on this thread while one is kept.
#[derive(Clone, Default)]
struct Warnings(Arc<Mutex<Vec<String>>>);

impl Warnings {
    fn logged(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl tracing::Subscriber for Warnings {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Text(String);
        impl tracing::field::Visit for Text {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0 += &format!("{}={value:?} ", field.name());
            }
        }
        let mut text = Text(String::new());
        event.record(&mut text);
        self.0.lock().unwrap().push(text.0);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn a_payment_a_hub_omits_the_tweak_of_is_found_with_anothers_and_warned_of() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    s.other(1, View::default()).await;
    // The hub asked first serves none.
    s.view(HUB, |v| v.omits = true);
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    let warnings = Warnings::default();
    let (scanned, tweaked) = {
        let _logging = tracing::subscriber::set_default(warnings.clone());
        s.scan_trusted(u32::MAX).await.unwrap()
    };
    assert!(tweaked);
    assert_eq!((scanned.next, scanned.height), (4, 3));
    assert_eq!(scanned.found.len(), 1);
    assert_eq!(scanned.found[0].value, 40_000);
    let logged = warnings.logged();
    let omits = logged.iter().find(|w| w.contains("fewer tweaks"));
    let omits = omits.unwrap_or_else(|| panic!("{logged:?}"));
    assert!(omits.contains(&format!("hub={HUB}")), "{omits}");
    assert!(omits.contains(&format!("others={OTHER}")), "{omits}");
    assert!(omits.contains("block=3"), "{omits}");
    // Both asked once, at once.
    assert_eq!(*s.hub.asked.lock().unwrap(), 1);
    assert_eq!(s.hub.view(OTHER).asked, 1);
}

#[tokio::test]
async fn a_hub_behind_another_does_not_hold_the_scan_back() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    s.other(1, View::default()).await;
    // The hub asked first indexed up to block 2 only, as one stuck.
    s.view(HUB, |v| v.top = Some(2));
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    s.mine(Vec::new());
    let (scanned, tweaked) = s.scan_trusted(u32::MAX).await.unwrap();
    assert!(tweaked);
    assert_eq!((scanned.next, scanned.height), (5, 4));
    assert_eq!(scanned.found.len(), 1);
    // Scanned with the first alone, it waits at its newest block.
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    s.view(HUB, |v| v.top = Some(2));
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    let (scanned, _) = s.scan_trusted(u32::MAX).await.unwrap();
    assert_eq!((scanned.next, scanned.height), (3, 3));
    assert!(scanned.found.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_hub_that_does_not_answer_is_passed_over_for_one_that_does() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    s.other(1, View::default()).await;
    s.view(HUB, |v| v.stalls = true);
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    let warnings = Warnings::default();
    let started = tokio::time::Instant::now();
    let (scanned, tweaked) = {
        let _logging = tracing::subscriber::set_default(warnings.clone());
        s.scan_trusted(u32::MAX).await.unwrap()
    };
    assert!(tweaked);
    assert_eq!((scanned.next, scanned.height), (4, 3));
    assert_eq!(scanned.found.len(), 1);
    // Waited on for a while, not for good.
    let waited = started.elapsed();
    assert!(waited >= std::time::Duration::from_secs(5), "{waited:?}");
    assert!(waited < std::time::Duration::from_secs(60), "{waited:?}");
    let logged = warnings.logged();
    assert!(
        logged
            .iter()
            .any(|w| w.contains("no answer") && w.contains(HUB)),
        "{logged:?}"
    );
    // Told the transport, which passes it over a while as one not answering.
    assert_eq!(s.hub.view(HUB).given_up, 1);
    assert_eq!(s.hub.view(OTHER).given_up, 0);
}

#[tokio::test]
async fn a_hub_naming_another_block_is_passed_over_for_one_that_does_not() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    s.other(1, View::default()).await;
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    *s.hub.forged.lock().unwrap() = Some(2);
    let (scanned, _) = s.scan_trusted(u32::MAX).await.unwrap();
    assert_eq!((scanned.next, scanned.found.len()), (4, 1));
}

#[tokio::test]
async fn none_of_the_hubs_serving_the_tweaks_answering_the_scan_waits() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    s.other(1, View::default()).await;
    *s.hub.forged.lock().unwrap() = Some(2);
    s.view(OTHER, |v| v.lost = true);
    match s.scan_trusted(u32::MAX).await {
        Err(Error::Unavailable { hub, reason }) => {
            assert_eq!(hub, HUB);
            assert!(reason.contains("block 2"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(s.wallet.silent_next().unwrap(), Some(1));
}

#[tokio::test]
async fn without_a_hub_serving_the_next_blocks_tweaks_up_to_the_first_that_does() {
    let s = setup().await;
    *s.hub.first.lock().unwrap() = Some(3);
    s.wallet.add_hub(HUB).await.unwrap();
    s.wallet.watch_silent(None, 1).unwrap();
    s.mine(Vec::new());
    s.mine(Vec::new());
    let (scanned, tweaked) = s.scan_trusted(u32::MAX).await.unwrap();
    assert!(!tweaked);
    assert_eq!(scanned.next, 3);
    assert_eq!(*s.hub.asked.lock().unwrap(), 0);
    let (scanned, tweaked) = s.scan_trusted(u32::MAX).await.unwrap();
    assert!(tweaked);
    assert_eq!((scanned.next, scanned.height), (5, 4));
}

#[tokio::test]
async fn tweaks_fetched_ahead_are_not_fetched_again_while_still_the_chains() {
    let s = setup().await;
    let light = Light(s.chain.clone());
    s.wallet.watch_silent(HUB, 1).unwrap();
    // Nothing to fetch ahead: no block past the next, or no hub serving it.
    assert!(s.wallet.silent_tweaks(&light, 0).await.unwrap().is_none());
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    let ahead = s.wallet.silent_tweaks(&light, u32::MAX).await.unwrap();
    assert_eq!(*s.hub.asked.lock().unwrap(), 1);
    let scan = s.wallet.scan_silent_trusted(&light, u32::MAX, ahead);
    let (scanned, tweaked) = scan.await.unwrap();
    assert!(tweaked);
    assert_eq!((scanned.next, scanned.found.len()), (4, 1));
    assert_eq!(*s.hub.asked.lock().unwrap(), 1);
    assert!(s
        .wallet
        .silent_tweaks(&light, u32::MAX)
        .await
        .unwrap()
        .is_none());

    // Of blocks a reorganization replaced, or another than the next:
    // fetched again.
    let paying = s.pay(&[s.address()], &[30_000]);
    s.mine(vec![paying.clone()]);
    let stale = s.wallet.silent_tweaks(&light, u32::MAX).await.unwrap();
    assert_eq!(*s.hub.asked.lock().unwrap(), 2);
    s.chain.lock().unwrap().fork(4);
    s.mine(vec![paying]);
    let scan = s
        .wallet
        .scan_silent_trusted(&light, u32::MAX, stale.clone());
    assert_eq!(scan.await.unwrap().0.found.len(), 1);
    assert_eq!(*s.hub.asked.lock().unwrap(), 3);
    s.mine(Vec::new());
    let scan = s.wallet.scan_silent_trusted(&light, u32::MAX, stale);
    assert_eq!(scan.await.unwrap().0.next, 6);
    assert_eq!(*s.hub.asked.lock().unwrap(), 4);
}

#[tokio::test(start_paused = true)]
async fn a_hub_behind_answering_at_once_does_not_cut_short_the_wait_for_one_slower() {
    let s = setup().await;
    s.wallet.watch_silent(HUB, 1).unwrap();
    // Over Tor, the hub that indexed the blocks answers in 15 s; the one
    // behind, with none of them, at once.
    let slow = View {
        delay: Some(std::time::Duration::from_secs(15)),
        ..View::default()
    };
    s.other(1, slow).await;
    s.view(HUB, |v| v.top = Some(0));
    let paying = s.pay(&[s.address()], &[40_000]);
    s.mine(vec![paying]);
    let (scanned, tweaked) = s.scan_trusted(u32::MAX).await.unwrap();
    assert!(tweaked);
    assert_eq!((scanned.next, scanned.height), (4, 3));
    assert_eq!(scanned.found.len(), 1);
}
