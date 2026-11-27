//! The mobile wallet against a hub in this process, over HTTP: paid on
//! Bitcoin at its silent payment address, found through a light client,
//! moved to notes, paying another wallet in them through its mailbox or by
//! hand; and what it refuses.

#[path = "../../../hub/tests/chain/mod.rs"]
mod chain;
#[path = "../../../hub/tests/esplora/mod.rs"]
mod esplora;
mod mint;

use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc, Mutex,
};

use axum::response::IntoResponse;
use bitcoin::{
    absolute::LockTime,
    bip158::BlockFilter,
    consensus::{deserialize, serialize},
    hashes::Hash,
    key::TweakedPublicKey,
    secp256k1::{Secp256k1, SecretKey},
    transaction, Amount, Block, BlockHash, CompressedPublicKey, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use licash_api::Fee;
use licash_chain_client::Source;
use licash_hub::{Hub, Policy, Timing};
use licash_hub_service::{
    deposit,
    tweaks::{step, Tweaks},
    Services,
};
use licash_mobile::{
    default_relays, set_logger, wallet_exists, Activity, Balance, ChainError, ChainSource, Details,
    Fees, FeesRaised, Kind, LicashError, Linking, Logger, Network, Onchain, PaidTo, PayOffer,
    PayQuote, Range, Rate, Scanned, State, TorClient, Wallet,
};
use licash_nostr::{Announcement, Announcer, Role, Route};
use licash_wallet::PaymentCode;
use nostr_sdk::prelude::MockRelay;

const MAX_POW: u32 = 6;

/// Short, as the wallet CLI's tests have it.
const TIMING: Timing = Timing {
    window: 20,
    reaction: 2,
    min_depth: 1,
    max_headers: 4032,
    bury: 6,
    max_lag: 120,
};

/// A hub charging 1 on a payment, taking deposits of 1000 to 4000 for 100,
/// and indexing tweaks from block 3, over a mock Esplora; mailbox relays
/// if asked.
struct Net {
    runtime: tokio::runtime::Runtime,
    hub: Arc<Hub>,
    deposits: Arc<deposit::Gateway>,
    tweaks: Arc<Tweaks>,
    source: Source,
    backend: esplora::Shared,
    url: String,
    relay: Option<MockRelay>,
    /// The hub answers 503 to everything while set.
    down: Arc<AtomicBool>,
    dir: tempfile::TempDir,
}

impl Net {
    fn new(relays: bool) -> Self {
        Self::with(relays, true)
    }

    /// The hub serving tweaks only if `tweaks`.
    fn with(relays: bool, tweaks: bool) -> Self {
        Self::built(relays, tweaks, false)
    }

    /// [`Net::new`], with relays, the hub keeping the payments its wallets
    /// ask it to for their payees, as hubs do.
    fn keeping() -> Self {
        Self::built(true, true, true)
    }

    fn built(relays: bool, tweaks: bool, keeps: bool) -> Self {
        let serves_tweaks = tweaks;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay = relays.then(|| relay(&runtime));
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, MAX_POW).unwrap();
        let fee = Fee { base: 1, ppm: 0 };
        let policy = Policy {
            spend: fee,
            lock: fee,
            refund: fee,
            output_msat: 0,
            timing: TIMING,
        };
        let hub = Arc::new(Hub::open(&seed, &db, policy).unwrap());
        let chain = chain::Chain::new();
        hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
        let backend = esplora::backend(chain);
        let source: Source = esplora::serve(backend.clone()).parse().unwrap();
        let config = deposit::Config {
            fee: Fee { base: 100, ppm: 0 },
            min: 1_000,
            max: 4_000,
            depth: 2,
            window: 10,
            lock_blocks: 6,
            downtime: 2,
            sweep_blocks: 6,
            min_fee_rate: bitcoin::FeeRate::from_sat_per_vb_u32(1),
            // As hubs took them before they took those of closes only.
            plain: true,
            ..deposit::Config::new(sweep())
        };
        let profile = licash::spend::ChainProfile::Core30DefaultRegtest;
        let path = dir.path().join("hub.sqlite");
        let gateway = deposit::Gateway::open(hub.clone(), source.clone(), profile, config, &path);
        let deposits = Arc::new(gateway.unwrap());
        let tweaks = Arc::new(Tweaks::open(&dir.path().join("tweaks.sqlite")).unwrap());
        let mut net = Self {
            runtime,
            hub,
            deposits,
            tweaks,
            source,
            backend,
            url: String::new(),
            relay,
            down: Arc::new(AtomicBool::new(false)),
            dir,
        };
        net.mine(3, Vec::new());
        net.round();
        let relays = match &net.relay {
            Some(relay) => vec![net.runtime.block_on(relay.url()).to_string()],
            None => Vec::new(),
        };
        let services = Services {
            deposits: Some(net.deposits.clone()),
            tweaks: serves_tweaks.then(|| net.tweaks.clone()),
            inbox: keeps.then(|| {
                let path = net.dir.path().join("hub.sqlite");
                Arc::new(licash_hub_service::inbox::Inbox::open(&path).unwrap())
            }),
            relays,
            contracts: None,
            urls: Default::default(),
            ingress: Default::default(),
        };
        let down = net.down.clone();
        let app = licash_hub_service::router(net.hub.clone(), services).layer(
            axum::middleware::from_fn(move |request, next: axum::middleware::Next| {
                let down = down.load(Ordering::SeqCst);
                async move {
                    if down {
                        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    next.run(request).await
                }
            }),
        );
        let listener = net
            .runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        net.url = format!("http://{}", listener.local_addr().unwrap());
        net.runtime
            .spawn(async move { axum::serve(listener, app).await.unwrap() });
        net
    }

    /// Mine `blocks`, the first with `txs`, which the hub scans and
    /// indexes the tweaks of.
    fn mine(&self, blocks: u32, mut txs: Vec<Transaction>) {
        {
            let mut backend = self.backend.lock().unwrap();
            let ids: Vec<Txid> = txs.iter().map(Transaction::compute_txid).collect();
            backend.mempool.retain(|t| !ids.contains(&t.compute_txid()));
            let chain = &mut backend.chain;
            for _ in 0..blocks {
                let block = chain.mine_with(None, std::mem::take(&mut txs)).clone();
                self.hub.observe(chain.height(), &block).unwrap();
            }
            assert!(self.hub.synced(chain.height(), &chain.tip()).unwrap());
        }
        let indexed = step(&self.tweaks, &self.source, None);
        self.runtime.block_on(indexed).unwrap();
    }

    /// Mine what was sent, in one block.
    fn confirm_sent(&self) {
        let sent = self.sent();
        self.mine(1, sent);
    }

    fn sent(&self) -> Vec<Transaction> {
        self.backend.lock().unwrap().mempool.clone()
    }

    /// One round of the deposit gateway.
    fn round(&self) {
        self.runtime.block_on(self.deposits.round());
    }

    fn height(&self) -> u32 {
        self.backend.lock().unwrap().chain.height()
    }

    fn dir(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }

    /// A new wallet `name`, made at `birthday`, trusting the hub.
    fn wallet(&self, name: &str, birthday: u32) -> Arc<Wallet> {
        let wallet = Wallet::create(self.dir(name), Network::Regtest, birthday, None).unwrap();
        wallet.add_hub(self.url.clone()).unwrap();
        wallet
    }

    /// Pay `value` to the silent payment address of the payment code
    /// `code`, from a P2WPKH coin of the `n`th payer: unconfirmed.
    fn pay_silent(&self, code: &str, value: u64, n: u8) -> Transaction {
        let code: PaymentCode = code.parse().unwrap();
        let to = code.silent.expect("a silent payment address");
        let secp = Secp256k1::new();
        let sender = SecretKey::from_slice(&[n; 32]).unwrap();
        let key = CompressedPublicKey(sender.public_key(&secp));
        let previous_output = OutPoint::new(Txid::from_byte_array([n; 32]), 0);
        let spent = ScriptBuf::new_p2wpkh(&key.wpubkey_hash());
        let mut backend = self.backend.lock().unwrap();
        backend.outside.insert(previous_output, spent);
        let paid = licash_onchain::silent::outputs(&[(sender, false)], &[previous_output], &[to]);
        let output = TweakedPublicKey::dangerous_assume_tweaked(paid.unwrap()[0]);
        let mut witness = Witness::new();
        witness.push([0x30; 71]);
        witness.push(key.to_bytes());
        Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(output),
            }],
        }
    }

    /// A payment of `value` to `address` from coin `n` of a payer's, of a
    /// script-hash input, which silent payments skip.
    fn pay_plain(&self, address: &str, value: u64, n: u8) -> Transaction {
        let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            address.parse().unwrap();
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let previous_output = OutPoint::new(Txid::from_byte_array([n; 32]), 0);
        let spent = ScriptBuf::new_p2wsh(&script.wscript_hash());
        self.backend
            .lock()
            .unwrap()
            .outside
            .insert(previous_output, spent);
        let mut witness = Witness::new();
        witness.push(script.as_bytes());
        Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: address.assume_checked().script_pubkey(),
            }],
        }
    }
}

/// A Nostr relay in this process, tried again should another socket take
/// the port it probed.
fn relay(runtime: &tokio::runtime::Runtime) -> MockRelay {
    let mut failed = None;
    for _ in 0..5 {
        match runtime.block_on(MockRelay::run()) {
            Ok(relay) => return relay,
            Err(e) => failed = Some(e),
        }
    }
    panic!("no mock relay: {failed:?}");
}

/// Where the hub's deposit claims pay.
fn sweep() -> ScriptBuf {
    let key = SecretKey::from_slice(&[9; 32]).unwrap();
    let key = key.x_only_public_key(&Secp256k1::new()).0;
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key))
}

/// The mock's chain as a phone's light client serves it: the blocks'
/// compact filters, the blocks it asks for, counted, and a broadcast that
/// can be made to fail.
struct Light {
    backend: esplora::Shared,
    fetched: Mutex<Vec<u32>>,
    failing: AtomicBool,
    accepted_error: AtomicBool,
    /// Added to the times blocks claim.
    skew: AtomicI64,
    /// The heights it says, in turn, in place of its chain's: the last
    /// for good. Its chain's if none.
    heights: Mutex<Vec<u32>>,
}

impl Light {
    fn new(net: &Net) -> Arc<Self> {
        Arc::new(Self {
            backend: net.backend.clone(),
            fetched: Mutex::new(Vec::new()),
            failing: AtomicBool::new(false),
            accepted_error: AtomicBool::new(false),
            skew: AtomicI64::new(0),
            heights: Mutex::default(),
        })
    }

    /// The heights of the blocks fetched since last asked.
    fn fetched(&self) -> Vec<u32> {
        std::mem::take(&mut self.fetched.lock().unwrap())
    }

    fn block_of(&self, hash: &[u8]) -> Result<Block, ChainError> {
        let hash = BlockHash::from_byte_array(hash.try_into().unwrap());
        let backend = self.backend.lock().unwrap();
        let block = backend.chain.blocks.iter().find(|b| b.block_hash() == hash);
        block.cloned().ok_or_else(|| ChainError::Failed {
            reason: format!("no block {hash}"),
        })
    }
}

impl ChainSource for Light {
    fn height(&self) -> Result<u32, ChainError> {
        let mut heights = self.heights.lock().unwrap();
        match heights.len() {
            0 => Ok(self.backend.lock().unwrap().chain.height()),
            1 => Ok(heights[0]),
            _ => Ok(heights.remove(0)),
        }
    }

    fn hash(&self, height: u32) -> Result<Vec<u8>, ChainError> {
        let backend = self.backend.lock().unwrap();
        match backend.chain.blocks.get(height as usize) {
            Some(block) => Ok(block.block_hash().to_byte_array().to_vec()),
            None => Err(ChainError::Failed {
                reason: format!("no block {height}"),
            }),
        }
    }

    /// Its block's header, no block counted as fetched.
    fn header(&self, height: u32) -> Result<Vec<u8>, ChainError> {
        let backend = self.backend.lock().unwrap();
        match backend.chain.blocks.get(height as usize) {
            Some(block) => Ok(serialize(&block.header)),
            None => Err(ChainError::Failed {
                reason: format!("no block {height}"),
            }),
        }
    }

    fn filter(&self, hash: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let block = self.block_of(&hash)?;
        let backend = self.backend.lock().unwrap();
        let spent = |outpoint: &OutPoint| {
            let mut made = backend.chain.blocks.iter().flat_map(|b| &b.txdata);
            let made = made.find(|tx| tx.compute_txid() == outpoint.txid);
            let made = made.and_then(|tx| tx.output.get(outpoint.vout as usize));
            let made = made.map(|output| output.script_pubkey.clone());
            let outside = backend.outside.get(outpoint).cloned();
            outside
                .or(made)
                .ok_or(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        };
        Ok(BlockFilter::new_script_filter(&block, spent)
            .unwrap()
            .content)
    }

    fn block(&self, hash: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let block = self.block_of(&hash)?;
        let backend = self.backend.lock().unwrap();
        let height = backend.chain.blocks.iter().position(|b| *b == block);
        self.fetched.lock().unwrap().push(height.unwrap() as u32);
        Ok(serialize(&block))
    }

    fn broadcast(&self, tx: Vec<u8>) -> Result<(), ChainError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(ChainError::Failed {
                reason: "no peers".into(),
            });
        }
        let tx: Transaction = deserialize(&tx).unwrap();
        let mut backend = self.backend.lock().unwrap();
        if !backend.mempool.contains(&tx) {
            backend.mempool.push(tx);
        }
        if self.accepted_error.load(Ordering::SeqCst) {
            return Err(ChainError::Failed {
                reason: "response lost after relay".into(),
            });
        }
        Ok(())
    }

    /// Ten minutes apart, the tip's now: the times its headers claim are
    /// of 2011.
    fn time(&self, height: u32) -> Result<i64, ChainError> {
        let tip = self.backend.lock().unwrap().chain.height();
        if height > tip {
            return Err(ChainError::Failed {
                reason: format!("no block {height}"),
            });
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        Ok(now - i64::from(tip - height) * 600 + self.skew.load(Ordering::SeqCst))
    }

    fn unconfirmed(&self, script: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let backend = self.backend.lock().unwrap();
        let paying = backend.mempool.iter().filter(|tx| {
            let mut outputs = tx.output.iter();
            outputs.any(|o| o.script_pubkey.as_bytes() == script.as_slice())
        });
        Ok(paying.flat_map(serialize).collect())
    }
}

/// The lines logged, by level.
#[derive(Default)]
struct Lines(Mutex<Vec<(String, String)>>);

impl Logger for Lines {
    fn log(&self, level: String, line: String) {
        self.0.lock().unwrap().push((level, line));
    }
}

/// Look until caught up with the chain: the coins found, and their worth.
fn scan(wallet: &Wallet, light: &Arc<Light>) -> (u32, u64) {
    let (mut found, mut value) = (0, 0);
    loop {
        let scan = wallet.scan(light.clone()).unwrap();
        found += scan.found;
        value += scan.found_value;
        if scan.next > scan.height {
            return (found, value);
        }
    }
}

fn invalid(result: Result<impl std::fmt::Debug, LicashError>) -> String {
    match result {
        Err(LicashError::Invalid { reason }) => reason,
        other => panic!("not refused as invalid: {other:?}"),
    }
}

fn notes(wallet: &Wallet) -> u64 {
    wallet.balance().unwrap().notes
}

#[test]
fn a_phone_fetches_the_tweaks_ahead_and_looks_with_them() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let code = alice.bitcoin_code(None).unwrap();
    // Not watching yet: nothing to fetch ahead, the scan starts it.
    assert!(alice.tweaks(light.clone()).unwrap().is_none());
    let first = alice.scan_with(light.clone(), None).unwrap();
    assert!(first.next > first.height);
    assert!(alice.tweaks(light.clone()).unwrap().is_none());
    let payment = net.pay_silent(&code.qr, 3_000, 1);
    net.mine(1, vec![payment]);
    let ahead = alice.tweaks(light.clone()).unwrap();
    assert!(ahead.is_some());
    let scan = alice.scan_with(light.clone(), ahead).unwrap();
    assert!(scan.tweaks);
    assert_eq!((scan.found, scan.found_value), (1, 3_000));
    assert_eq!((scan.next, scan.height), (net.height() + 1, net.height()));
}

#[test]
fn coins_found_on_bitcoin_take_their_blocks_time_in_the_history() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let code = alice.bitcoin_code(None).unwrap();
    net.mine(2, Vec::new());
    let payment = net.pay_silent(&code.qr, 3_000, 1);
    net.mine(1, vec![payment]);
    let block = net.height();
    net.mine(2, Vec::new());
    assert_eq!(scan(&alice, &light), (1, 3_000));
    let history = alice.history().unwrap();
    assert_eq!(history[0].detail, format!("block {block}"));
    // The fake chain's times move with the clock: seconds apart at most.
    let claimed = light.time(block).unwrap();
    let at = history[0].at.expect("the time of its block");
    assert!((at - claimed).abs() <= 5, "{at} for a block of {claimed}");
}

#[test]
fn a_phone_paid_on_bitcoin_moves_it_to_notes_and_pays_in_them() {
    let lines = Arc::new(Lines::default());
    set_logger(lines.clone(), "info".into());
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let bob = net.wallet("bob", net.height());
    let hubs = alice.hubs().unwrap();
    assert_eq!(hubs.len(), 1);
    assert_eq!((hubs[0].fee_base, hubs[0].fee_ppm), (1, 0));
    assert_eq!(
        hubs[0].deposits,
        Some(Range {
            min: 1_000,
            max: 4_000
        })
    );
    assert!(hubs[0].silent && hubs[0].mailbox);

    // Paid at the silent payment address in her code on Bitcoin: found in
    // the one block whose filter matches, and shown first in her history.
    // Her code in notes says nothing of Bitcoin, nor her code on Bitcoin
    // of notes.
    let in_notes = alice.payment_code(None).unwrap();
    assert!(
        in_notes.qr.starts_with("LICASH:TLICASH1Q"),
        "{}",
        in_notes.qr
    );
    assert_eq!((&in_notes.address, &in_notes.silent), (&None, &None));
    let code = alice.bitcoin_code(None).unwrap();
    assert!(code.qr.starts_with("BITCOIN:BCRT1P"), "{}", code.qr);
    assert!(code.qr.contains("?SP=TSP1Q"), "{}", code.qr);
    assert!(!code.qr.contains("LICASH"), "{}", code.qr);
    // The silent payment address on its own, as in the code.
    let silent = code.silent.clone().expect("a silent payment address");
    assert!(silent.starts_with("tsp1q"), "{silent}");
    assert!(code.text.contains(&format!("sp={silent}")), "{}", code.text);
    net.mine(2, Vec::new());
    let payment = net.pay_silent(&code.qr, 3_000, 1);
    net.mine(1, vec![payment]);
    net.mine(2, Vec::new());
    assert_eq!(scan(&alice, &light), (1, 3_000));
    assert_eq!(light.fetched(), [6]);
    let onchain = Balance {
        onchain: 3_000,
        ..Balance::default()
    };
    assert_eq!(alice.balance().unwrap(), onchain);
    let history = alice.history().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!((history[0].kind, history[0].amount), (Kind::Onchain, 3_000));
    // Nothing new: nothing fetched.
    assert_eq!(scan(&alice, &light), (0, 0));
    assert_eq!(light.fetched(), [0; 0]);

    // Moved to notes: all of it but the hub's fee and the transaction's,
    // under way until the deposit confirms at depth.
    let moving = alice.move_to_licash(light.clone()).unwrap();
    assert_eq!((moving.kind, moving.state), (Kind::Moved, State::Pending));
    assert_eq!(moving.fee, 100);
    let sent = net.sent();
    assert_eq!(
        (sent.len(), sent[0].input.len(), sent[0].output.len()),
        (1, 1, 1)
    );
    assert_eq!(sent[0].output[0].value.to_sat(), moving.amount + 100);
    let fee = 3_000 - moving.amount - 100;
    assert_eq!(fee, 2 * sent[0].vsize() as u64);
    let moving_balance = Balance {
        moving: 3_000,
        ..Balance::default()
    };
    assert_eq!(alice.balance().unwrap(), moving_balance);
    net.confirm_sent();
    net.round();
    net.mine(1, Vec::new());
    net.round();
    alice.resume().unwrap();
    assert_eq!(scan(&alice, &light), (0, 0));
    let held = Balance {
        notes: moving.amount,
        ..Balance::default()
    };
    assert_eq!(alice.balance().unwrap(), held);
    let history = alice.history().unwrap();
    assert_eq!(history.len(), 1, "{history:#?}");
    assert_eq!(
        (history[0].kind, history[0].state),
        (Kind::Moved, State::Done)
    );
    let logged = lines.0.lock().unwrap().clone();
    assert!(
        logged
            .iter()
            .any(|(level, line)| level == "INFO" && line.contains("moving to notes")),
        "{logged:?}"
    );

    // More than she holds: what is needed and held.
    let held = notes(&alice);
    let open = bob.payment_code(None).unwrap();
    match alice.pay(open.text, Some(held + 1), None, None) {
        Err(LicashError::Insufficient { needed, available }) => {
            assert_eq!((needed, available), (held + 2, held));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(notes(&alice), held);

    // Bob asks for 500 with a code naming his mailbox: she pays it there.
    let asked = bob.payment_code(Some(500)).unwrap();
    let scanned = alice.scanned(asked.qr.clone()).unwrap();
    let wanted = Scanned::Code {
        amount: Some(500),
        notes: true,
    };
    assert_eq!(scanned, wanted);
    let paid = alice.pay(asked.qr, None, None, None).unwrap();
    assert!(paid.delivered, "{paid:?}");
    assert_eq!((paid.amount, &paid.hub), (500, &hubs[0].url));
    assert_eq!((paid.handover, paid.undelivered), (None, None));
    assert_eq!(notes(&alice), moving.amount - 501);
    let got = bob.collect().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].kind, got[0].amount), (Kind::Received, 500));
    // Each payment is taken once.
    assert!(bob.collect().unwrap().is_empty());
    assert_eq!(notes(&bob), 500);
    let history = alice.history().unwrap();
    let sent = Activity {
        id: paid.id.clone(),
        kind: Kind::Sent,
        state: State::Done,
        amount: 500,
        fee: 1,
        detail: hubs[0].url.clone(),
        at: history[0].at,
        memo: None,
        from: None,
        code: None,
    };
    assert_eq!(history[0], sent);
    // That hub keeps no payments, so no note with one: refused, nothing
    // paid, to pay without it if the user chooses.
    let refused = alice.pay(
        bob.payment_code(Some(5)).unwrap().qr,
        None,
        Some("hi".into()),
        None,
    );
    assert!(
        matches!(&refused, Err(LicashError::NoteUnkept { hub }) if *hub == hubs[0].url),
        "{refused:?}"
    );
    assert_eq!(notes(&alice), moving.amount - 501);

    // The mailbox's relay down: a payment to hand over, which Bob takes
    // once, and someone else not at all.
    net.relay.as_ref().unwrap().shutdown();
    let code = bob.payment_code(None).unwrap();
    let paid = alice.pay(code.text, Some(100), None, None).unwrap();
    assert!(!paid.delivered && paid.undelivered.is_some(), "{paid:?}");
    let handover = paid.handover.unwrap();
    assert_eq!(bob.scanned(handover.clone()).unwrap(), Scanned::Payment);
    let carol = Wallet::create(net.dir("carol"), Network::Regtest, 0, None).unwrap();
    let unknown = carol.receive(handover.clone(), false);
    assert!(
        matches!(&unknown, Err(LicashError::UnknownHub { url }) if *url == hubs[0].url),
        "{unknown:?}"
    );
    let refused = invalid(carol.receive(handover.clone(), true));
    assert!(refused.contains("pays this wallet nothing"), "{refused}");
    assert_eq!(carol.hubs().unwrap().len(), 1);
    let received = bob.receive(handover.clone(), false).unwrap();
    assert_eq!((received.kind, received.amount), (Kind::Received, 100));
    assert!(invalid(bob.receive(handover, false)).contains("received already"));
    assert_eq!(notes(&bob), 600);
    assert_eq!(notes(&alice), moving.amount - 602);
}

#[test]
fn a_phone_refuses_what_it_cannot_do_and_retries_an_uncertain_broadcast() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let dir = net.dir("alice");
    assert!(!wallet_exists(dir.clone()));
    let alice = Wallet::create(dir.clone(), Network::Regtest, 0, None).unwrap();
    assert!(wallet_exists(dir.clone()));
    let again = Wallet::create(dir.clone(), Network::Regtest, 0, None).map(|_| ());
    assert!(invalid(again).contains("already"));
    drop(alice);
    let alice = Wallet::open(dir, None).unwrap();
    assert_eq!((alice.network(), alice.tor()), (Network::Regtest, false));

    // No hub: nothing to scan with or move to.
    assert!(invalid(alice.scan(light.clone())).contains("no hub trusted serves"));
    assert!(invalid(alice.move_to_licash(light.clone())).contains("no hub trusted takes"));
    assert!(alice.collect().unwrap().is_empty());

    // Onion hubs need Tor; hubs down are unavailable.
    let onion = "http://licashhubv3licashhubv3licashhubv3licashhubv3licashhubqd.onion";
    assert!(matches!(
        alice.add_hub(onion.into()),
        Err(LicashError::NeedsTor)
    ));
    let down = alice.add_hub("http://127.0.0.1:1".into());
    assert!(
        matches!(down, Err(LicashError::Unavailable { .. })),
        "{down:?}"
    );
    assert!(alice.hubs().unwrap().is_empty());
    // Not answering, it rests: passed over at once by the app's own
    // rounds, asked still when the user adds it.
    assert!(alice.hub_resting_ms("http://127.0.0.1:1".into()).is_some());
    let passed = alice.relearn_hub("http://127.0.0.1:1".into());
    assert!(
        matches!(&passed, Err(LicashError::Unavailable { reason }) if reason.contains("did not answer lately")),
        "{passed:?}"
    );
    let asked = alice.add_hub("http://127.0.0.1:1".into());
    assert!(
        matches!(&asked, Err(LicashError::Unavailable { reason }) if !reason.contains("lately")),
        "{asked:?}"
    );
    assert_eq!(alice.hub_answers_ms("http://127.0.0.1:1".into()), None);
    let hub = alice.add_hub(net.url.clone()).unwrap();
    assert!(hub.silent && !hub.mailbox);
    assert!(alice.hub_answers_ms(net.url.clone()).is_some());
    assert_eq!(alice.hub_resting_ms(net.url.clone()), None);
    assert_eq!(alice.relearn_hub(net.url.clone()).unwrap().url, hub.url);
    // A hub naming no relays: no mailbox to look in.
    assert!(alice.collect().unwrap().is_empty());

    // Nothing paid on Bitcoin yet: too little to move.
    match alice.move_to_licash(light.clone()) {
        Err(LicashError::Insufficient { needed, available }) => {
            assert_eq!(available, 0);
            assert!(needed > 1_100, "{needed}");
        }
        other => panic!("{other:?}"),
    }

    // Codes and payments it cannot take.
    assert!(invalid(alice.scanned("garbage".into())).contains("neither"));
    let elsewhere = Wallet::create(net.dir("mainnet"), Network::Bitcoin, 0, None).unwrap();
    let mainnet = elsewhere.payment_code(None).unwrap();
    assert!(invalid(alice.scanned(mainnet.text.clone())).contains("not on"));
    assert!(invalid(alice.pay(mainnet.text, Some(10), None, None)).contains("not on"));
    assert!(!invalid(alice.pay("garbage".into(), Some(10), None, None)).is_empty());
    let bob = net.wallet("bob", 0);
    let asking = bob.payment_code(Some(500)).unwrap();
    assert!(
        invalid(alice.pay(asking.text.clone(), Some(400), None, None))
            .contains("asks for 500, not 400")
    );
    let open = bob.payment_code(None).unwrap();
    assert!(invalid(alice.pay(open.text.clone(), None, None, None)).contains("does not say"));
    // No notes to pay with, and no Bitcoin address to fall back to: a
    // code pays in notes only.
    let unfunded = invalid(alice.pay(open.text, Some(10), None, None));
    assert!(unfunded.contains("holding 10 and the fee"), "{unfunded}");
    assert!(!unfunded.contains("on Bitcoin"), "{unfunded}");
    assert!(invalid(alice.receive("{}".into(), false)).contains("not a payment"));
    assert!(alice.history().unwrap().is_empty());

    // A generic broadcast error cannot prove the signed spend was never
    // relayed. Its inputs stay reserved and scanning retries that spend.
    let code = alice.bitcoin_code(None).unwrap();
    let payment = net.pay_silent(&code.text, 3_000, 1);
    net.mine(1, vec![payment]);
    assert_eq!(scan(&alice, &light), (1, 3_000));
    light.failing.store(true, Ordering::SeqCst);
    let failed = alice.move_to_licash(light.clone());
    assert!(
        matches!(failed, Err(LicashError::Unavailable { .. })),
        "{failed:?}"
    );
    let moving = Balance {
        moving: 3_000,
        ..Balance::default()
    };
    assert_eq!(alice.balance().unwrap(), moving);
    assert!(net.sent().is_empty());
    light.failing.store(false, Ordering::SeqCst);
    scan(&alice, &light);
    assert_eq!(alice.balance().unwrap(), moving);
    assert_eq!(net.sent().len(), 1);
}

#[test]
fn a_move_accepted_before_an_error_is_kept_and_rebroadcast_after_restart() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let alice = net.wallet("alice", 0);
    let code = alice.bitcoin_code(None).unwrap();
    let payment = net.pay_silent(&code.text, 3_000, 1);
    net.mine(1, vec![payment]);
    assert_eq!(scan(&alice, &light), (1, 3_000));
    light.accepted_error.store(true, Ordering::SeqCst);
    let failed = alice.move_to_licash(light.clone());
    assert!(
        matches!(failed, Err(LicashError::Unavailable { .. })),
        "{failed:?}"
    );
    let accepted = net.sent();
    assert_eq!(accepted.len(), 1);
    assert!(!accepted[0].input[0].witness.is_empty());
    assert_eq!(alice.balance().unwrap().moving, 3_000);
    assert_eq!(alice.balance().unwrap().onchain, 0);
    drop(alice);
    let alice = Wallet::open(net.dir("alice"), None).unwrap();
    light.accepted_error.store(false, Ordering::SeqCst);
    scan(&alice, &light);
    assert_eq!(net.sent(), accepted);
    net.confirm_sent();
    net.round();
    net.mine(1, Vec::new());
    net.round();
    alice.resume().unwrap();
    scan(&alice, &light);
    assert_eq!(alice.balance().unwrap().moving, 0);
    assert!(alice.balance().unwrap().notes > 0);
}

#[test]
fn a_phone_looks_for_payments_from_its_birthday_or_all_the_hub_indexed() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let born = net.height() + 2;
    let young = net.wallet("young", born);
    // Its birthday lost: everything the hub indexed is looked in.
    let unsure = net.wallet("unsure", born);
    std::fs::remove_file(net.dir.path().join("unsure/app.json")).unwrap();
    let pay = |n: u8| {
        let to_young = net.pay_silent(&young.bitcoin_code(None).unwrap().text, 2_000, n);
        let to_unsure = net.pay_silent(&unsure.bitcoin_code(None).unwrap().text, 2_000, n + 1);
        net.mine(1, vec![to_young, to_unsure]);
        net.height()
    };
    let before = pay(1);
    net.mine(1, Vec::new());
    let after = pay(3);
    assert!(before < born && born < after);
    assert_eq!(scan(&young, &light), (1, 2_000));
    assert_eq!(light.fetched(), [after]);
    assert_eq!(scan(&unsure, &light), (2, 4_000));
    assert_eq!(light.fetched(), [before, after]);
    // Where each looked from, kept as its birthday: the one lost, from
    // the day before it was made, block 1 on this chain.
    assert_eq!(young.birthday(), Some(born));
    assert_eq!(unsure.birthday(), Some(1));
    let again = unsure.scan(light.clone()).unwrap();
    assert_eq!((again.from, again.next, again.tweaks), (1, after + 1, true));
    // A scan goes on from where it stood.
    let next = pay(5);
    assert_eq!(scan(&young, &light), (1, 2_000));
    assert_eq!(light.fetched(), [next]);
}

/// Cold storage of a tpub's taproot addresses: what its first address is
/// paid is found from its birthday, the next withdrawal going to another;
/// nothing withdrawn with no notes held.
#[test]
fn a_phone_counts_what_cold_storage_holds_and_withdraws_to_a_new_address() {
    use bitcoin::bip32::{Xpriv, Xpub};
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let master = Xpriv::new_master(bitcoin::NetworkKind::Test, &[0xc0; 32]).unwrap();
    let tpub = Xpub::from_priv(&secp, &master).to_string();
    assert_eq!(alice.cold().unwrap(), None);
    assert!(
        invalid(alice.set_cold(tpub.clone(), None, 50_000, 0, 1.0, None)).contains("wpkh or tr")
    );
    let birthday = net.height();
    let cold = alice
        .set_cold(tpub, Some("tr".into()), 50_000, 0, 1.0, Some(birthday))
        .unwrap();
    assert!(cold.next.starts_with("bcrt1p"), "{}", cold.next);
    let payment = net.pay_plain(&cold.next, 4_000, 1);
    net.mine(1, vec![payment]);
    let looked = alice.run_cold(light.clone()).unwrap().unwrap();
    assert_eq!(
        (looked.balance, looked.coins, &looked.pending),
        (4_000, 1, &None)
    );
    assert_eq!(looked.scanned, Some(net.height()));
    assert_ne!(looked.next, cold.next);
    assert_eq!(alice.cold().unwrap(), Some(looked.clone()));
    // Said to be blocks on, then behind what was looked in: not looked in
    // until it gets there, never waited on.
    let at = net.height();
    net.mine(5, vec![]);
    *light.heights.lock().unwrap() = vec![at + 5, at - 1];
    let (phone, chain) = (alice.clone(), light.clone());
    let (done, ran) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(phone.run_cold(chain).unwrap().unwrap());
    });
    let behind = ran
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("not looked in without end");
    assert_eq!(behind.scanned, Some(at));
    light.heights.lock().unwrap().clear();
    let caught_up = alice.run_cold(light.clone()).unwrap().unwrap();
    assert_eq!(caught_up.scanned, Some(at + 5));
    alice.clear_cold().unwrap();
    assert_eq!(alice.cold().unwrap(), None);
    assert_eq!(alice.run_cold(light).unwrap(), None);
}

#[test]
fn a_phone_paid_at_its_fallback_address_finds_it_and_shows_the_next() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let code = alice.bitcoin_code(None).unwrap();
    let address = code.address.clone().expect("a fallback address");
    assert!(address.starts_with("bcrt1p"), "{address}");
    let uri = format!("bitcoin:{address}?sp=");
    assert!(code.text.starts_with(&uri), "{}", code.text);
    // The same until paid.
    assert_eq!(alice.bitcoin_code(None).unwrap(), code);
    let payment = net.pay_plain(&address, 3_000, 1);
    net.mine(1, vec![payment]);
    assert_eq!(scan(&alice, &light), (1, 3_000));
    assert_eq!(alice.balance().unwrap().onchain, 3_000);
    let next = alice.bitcoin_code(None).unwrap().address.unwrap();
    assert_ne!(next, address);
}

#[test]
fn a_phone_restored_from_its_words_finds_what_its_fallback_addresses_were_paid() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let born = net.height();
    let alice = net.wallet("alice", born);
    let first = alice.bitcoin_code(None).unwrap().address.unwrap();
    net.mine(1, vec![net.pay_plain(&first, 3_000, 1)]);
    assert_eq!(scan(&alice, &light), (1, 3_000));
    let second = alice.bitcoin_code(None).unwrap().address.unwrap();
    net.mine(1, vec![net.pay_plain(&second, 4_000, 2)]);
    // Restored from its words alone, no address handed out there yet.
    let restored = Wallet::from_phrase(
        net.dir("restored"),
        alice.backup_phrase().unwrap(),
        Network::Regtest,
        Some(born),
        None,
    )
    .unwrap();
    restored.add_hub(net.url.clone()).unwrap();
    assert_eq!(scan(&restored, &light), (2, 7_000));
    assert_eq!(restored.balance().unwrap().onchain, 7_000);
    // And hands out the next, not one paid.
    let next = restored.bitcoin_code(None).unwrap().address.unwrap();
    assert!(next != first && next != second, "{next}");
}

#[test]
fn a_phone_sees_payments_to_its_fallback_address_on_their_way() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    // No code shown yet: nothing to watch.
    assert_eq!(alice.incoming(light.clone()).unwrap(), []);
    let address = alice.bitcoin_code(None).unwrap().address.unwrap();
    let payment = net.pay_plain(&address, 3_000, 1);
    net.backend.lock().unwrap().mempool.push(payment.clone());
    let incoming = alice.incoming(light.clone()).unwrap();
    assert_eq!(incoming.len(), 1);
    let on_its_way = &incoming[0];
    assert_eq!(
        (on_its_way.kind, on_its_way.state, on_its_way.amount),
        (Kind::Onchain, State::Pending, 3_000)
    );
    assert!(on_its_way
        .id
        .starts_with(&payment.compute_txid().to_string()));
    // Not a coin until found in a block.
    assert_eq!(alice.balance().unwrap().onchain, 0);
    net.mine(1, vec![payment]);
    assert_eq!(scan(&alice, &light), (1, 3_000));
    assert_eq!(alice.incoming(light.clone()).unwrap(), []);
}

#[test]
fn a_phone_whose_hubs_serve_no_tweaks_finds_its_fallback_payments_from_the_day_before_it_was_made()
{
    let net = Net::with(false, false);
    let light = Light::new(&net);
    // Its birthday unknown.
    let alice = net.wallet("alice", 0);
    let made = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(!alice.hubs().unwrap()[0].silent);
    // No silent payment address, which no hub's tweaks would find paid.
    let code = alice.bitcoin_code(None).unwrap();
    assert!(!code.text.contains("sp="), "{}", code.text);
    assert_eq!(code.silent, None);
    let address = code.address.unwrap();
    let early = net.pay_plain(&address, 1_000, 1);
    net.mine(1, vec![early]);
    let before = net.height();
    let late = net.pay_plain(&address, 4_000, 2);
    net.mine(1, vec![late]);
    // Block `before` claims a time just before the day before the wallet
    // was made, the next just after.
    let claimed = light.time(before).unwrap();
    let skew = made - 86_400 - 300 - claimed;
    light.skew.store(skew, Ordering::SeqCst);
    assert_eq!(scan(&alice, &light), (1, 4_000));
    assert_eq!(light.fetched(), [before + 1]);
    assert_eq!(alice.balance().unwrap().onchain, 4_000);
    // Its first block kept as its birthday; no tweaks to look with.
    assert_eq!(alice.birthday(), Some(before + 1));
    assert!(!alice.scan(light.clone()).unwrap().tweaks);

    // Moved to notes, whole and alone: no change.
    alice.move_to_licash(light.clone()).unwrap();
    let sent = net.sent();
    assert_eq!((sent[0].input.len(), sent[0].output.len()), (1, 1));
    net.confirm_sent();
    assert_eq!(scan(&alice, &light), (0, 0));
    assert_eq!(alice.balance().unwrap().onchain, 0);
}

#[test]
fn a_phone_born_before_its_hubs_tweaks_looks_in_each_block_once() {
    let net = Net::new(false);
    let light = Light::new(&net);
    // Born at block 1, the hub's tweaks from block 3 on: blocks 1 and 2
    // looked in without them.
    let alice = net.wallet("alice", 1);
    let code = alice.bitcoin_code(None).unwrap();
    let silent = net.pay_silent(&code.text, 2_000, 1);
    net.mine(1, vec![silent]);
    let paid = net.height();
    let plain = net.pay_plain(&code.address.unwrap(), 3_000, 2);
    net.mine(1, vec![plain]);
    assert_eq!(scan(&alice, &light), (2, 5_000));
    assert_eq!(light.fetched(), [paid, paid + 1]);
    net.mine(1, Vec::new());
    assert_eq!(scan(&alice, &light), (0, 0));
    assert!(light.fetched().is_empty());
    assert_eq!(alice.balance().unwrap().onchain, 5_000);
}

#[test]
fn a_lightning_address_or_an_lnurl_is_read_as_one_asking_nothing() {
    let net = Net::new(true);
    let alice = net.wallet("alice", net.height());
    let lnurl = |payee: &str| Scanned::Lnurl {
        payee: payee.into(),
    };
    assert_eq!(
        alice.scanned(" Bob@Pay.Example ".into()).unwrap(),
        lnurl("bob@pay.example")
    );
    let hrp = bitcoin::bech32::Hrp::parse("lnurl").unwrap();
    let url = b"https://pay.example/lnurlp/bob";
    let code = bitcoin::bech32::encode_upper::<bitcoin::bech32::Bech32>(hrp, url).unwrap();
    assert_eq!(alice.scanned(code.clone()).unwrap(), lnurl("pay.example"));
    assert_eq!(
        alice.scanned(format!("lightning:{code}")).unwrap(),
        lnurl("pay.example")
    );
    // Neither: said so.
    let why = invalid(alice.scanned("bob@".into()));
    assert!(why.contains("Lightning Address"), "{why}");
}

#[test]
fn a_phone_pays_out_to_bitcoin_addresses_and_codes_of_hubs_it_does_not_trust() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let address = "bcrt1p8sjsah3xnncxd4jar9pc0xn3lhu7tlg2wwk03vxnvn0zhd24j25sl5zmq9";
    let plain = Scanned::Bitcoin {
        address: address.into(),
        amount: None,
    };
    assert_eq!(alice.scanned(format!(" {address} ")).unwrap(), plain);
    let asked = alice.scanned(format!("bitcoin:{address}?amount=0.0001"));
    let asked_for = Scanned::Bitcoin {
        address: address.into(),
        amount: Some(10_000),
    };
    assert_eq!(asked.unwrap(), asked_for);
    // A code of a wallet at a hub she does not trust, saying where to
    // reach it: paid in notes there if a swap brings them. Its code on
    // Bitcoin is paid out to its silent payment address, not the fallback.
    let other = Net::new(true);
    let bob = other.wallet("bob", other.height());
    let code = bob.payment_code(None).unwrap();
    assert_eq!(
        alice.scanned(code.qr.clone()).unwrap(),
        Scanned::Visit { amount: None }
    );
    let onchain = bob.bitcoin_code(None).unwrap();
    let silent = onchain.silent.clone().unwrap();
    match alice.scanned(onchain.qr).unwrap() {
        Scanned::Bitcoin {
            amount: None,
            address,
        } => assert_eq!(address.to_lowercase(), silent),
        other => panic!("{other:?}"),
    }
    // No provider to swap there with: not in notes, nothing held there.
    assert!(alice.pay_quote(code.qr, Some(1_000)).is_err());
    assert!(alice.visited().unwrap().is_empty());

    // No provider announced on her hub's relays: nothing quoted, nothing
    // paid out.
    let quote = alice.payout_quote(address.into(), Some(1_000), None);
    assert!(invalid(quote).contains("no swap provider"));
    let all = alice.payout_quote(address.into(), None, None);
    assert!(invalid(all).contains("no swap provider"));
    // Nor any most to offer instead.
    assert_eq!(alice.payout_most(address.into(), None).unwrap(), None);
    assert!(!alice.follow_payouts(light.clone()).unwrap());
    let history = alice.history().unwrap();
    assert!(
        history.iter().all(|a| a.kind != Kind::Payout),
        "{history:?}"
    );
}

#[test]
fn a_phone_finds_the_hubs_announced_on_its_hubs_relays_but_those_it_uses() {
    let net = Net::new(true);
    let alice = net.wallet("alice", net.height());
    let relay = net.relay.as_ref().unwrap();
    let relays = vec![net.runtime.block_on(relay.url()).to_string()];
    let other = Net::new(false);
    let announce = |secret: [u8; 32], url: &str, name: &str| {
        let announcement = Announcement {
            urls: vec![url.into()],
            network: "regtest".into(),
            name: Some(name.into()),
        };
        net.runtime.block_on(async {
            let announcer = Announcer::new(&secret, Role::Hub, &relays, &Route::Direct);
            let sent = announcer.await.unwrap().announce(&announcement).await;
            assert_eq!(sent.unwrap(), 1);
        })
    };
    // Nothing announced: nothing found.
    assert_eq!(alice.discover_hubs().unwrap(), []);

    // Her own hub, another, and the other's URL announced by another key:
    // only the other found, at the URL that answered as its key.
    announce(net.hub.nostr_secret().unwrap(), &net.url, "hers");
    announce(other.hub.nostr_secret().unwrap(), &other.url, "another");
    announce([5; 32], &other.url, "not it");
    let found = alice.discover_hubs().unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].name.as_deref(), Some("another"));
    assert_eq!(found[0].hub.url, other.url);
    assert_eq!((found[0].hub.fee_base, found[0].hub.fee_ppm), (1, 0));
    // Not added by finding it.
    assert_eq!(alice.hubs().unwrap().len(), 1);

    // Added: found no more.
    alice.add_hub(found[0].hub.url.clone()).unwrap();
    assert_eq!(alice.discover_hubs().unwrap(), []);

    // A hub naming no relays: nowhere to look.
    let bob = other.wallet("bob", other.height());
    assert!(invalid(bob.discover_hubs()).contains("no hub you use names relays"));
}

#[test]
fn a_phone_finds_hubs_on_relays_it_is_given_and_is_told_of_those_not_answering() {
    let net = Net::new(true);
    let relay = net.relay.as_ref().unwrap();
    let relays = vec![net.runtime.block_on(relay.url()).to_string()];
    let other = Net::new(false);
    let announce = |secret: [u8; 32], url: String, name: &str| {
        let announcement = Announcement {
            urls: vec![url],
            network: "regtest".into(),
            name: Some(name.into()),
        };
        net.runtime.block_on(async {
            let announcer = Announcer::new(&secret, Role::Hub, &relays, &Route::Direct);
            let sent = announcer.await.unwrap().announce(&announcement).await;
            assert_eq!(sent.unwrap(), 1);
        })
    };
    announce(net.hub.nostr_secret().unwrap(), net.url.clone(), "a hub");
    // One down, and one an onion service only, out of reach without Tor.
    announce([6; 32], "http://127.0.0.1:9".into(), "down");
    let onion = format!("http://{}.onion", "a".repeat(56));
    announce([7; 32], onion, "onion");

    // Bob's hub names no relays: only those given to look on.
    let bob = other.wallet("bob", other.height());
    assert!(invalid(bob.find_hubs(vec![])).contains("no relays"));
    let found = bob.find_hubs(relays.clone()).unwrap();
    assert_eq!(found.hubs.len(), 1, "{found:?}");
    assert_eq!(found.hubs[0].name.as_deref(), Some("a hub"));
    assert_eq!(found.hubs[0].hub.url, net.url);
    assert_eq!((found.silent, found.silent_onion), (2, 1));
    // Not added by finding it.
    assert_eq!(bob.hubs().unwrap().len(), 1);

    // His own hub announced: neither found nor told of.
    announce(other.hub.nostr_secret().unwrap(), other.url.clone(), "his");
    let found = bob.find_hubs(relays.clone()).unwrap();
    assert_eq!(found.hubs.len(), 1, "{found:?}");
    assert_eq!((found.silent, found.silent_onion), (2, 1));

    // Added: found no more, nor told of.
    bob.add_hub(net.url.clone()).unwrap();
    let found = bob.find_hubs(relays).unwrap();
    assert!(found.hubs.is_empty(), "{found:?}");
    assert_eq!((found.silent, found.silent_onion), (2, 1));
}

#[test]
fn default_relays_are_none_on_regtest_and_onion_services_only_over_tor() {
    assert!(default_relays(Network::Regtest, true).is_empty());
    let clear = default_relays(Network::Signet, false);
    let all = default_relays(Network::Signet, true);
    assert!(!clear.is_empty() && clear.len() < all.len());
    assert!(clear.iter().all(|r| !r.contains(".onion")));
    assert!(all.iter().any(|r| r.contains(".onion")));
    assert_eq!(default_relays(Network::Bitcoin, true), all);
}

fn funded(net: &Net, light: &Arc<Light>, name: &str) -> Arc<Wallet> {
    let wallet = net.wallet(name, net.height());
    let code = wallet.bitcoin_code(None).unwrap();
    let payment = net.pay_silent(&code.qr, 3_000, 1);
    net.mine(1, vec![payment]);
    assert_eq!(scan(&wallet, light), (1, 3_000));
    wallet.move_to_licash(light.clone()).unwrap();
    net.confirm_sent();
    net.round();
    net.mine(1, Vec::new());
    net.round();
    wallet.resume().unwrap();
    assert!(notes(&wallet) > 0);
    wallet
}

#[test]
fn a_phone_pays_a_code_as_quoted() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let held = notes(&alice);
    let bob = net.wallet("bob", net.height());
    let hub = bob.hubs().unwrap()[0].url.clone();
    let asked = bob.payment_code(Some(500)).unwrap();

    // At the hub she trusts, holding enough there: no swap.
    let quote = alice.pay_quote(asked.qr.clone(), None).unwrap();
    let wanted = PayQuote {
        hub: hub.clone(),
        amount: 500,
        fee: 1,
        swap_from: None,
        swapped: 0,
        trusted: true,
    };
    assert_eq!(quote, wanted);
    let paid = alice.pay(asked.qr.clone(), None, None, None).unwrap();
    assert_eq!((paid.amount, &paid.hub), (500, &hub));
    assert_eq!(notes(&alice), held - 501);

    // Quoted for another amount than paid: paid as without a quote.
    let open = bob.payment_code(None).unwrap();
    alice.pay_quote(open.qr.clone(), Some(100)).unwrap();
    let paid = alice.pay(open.qr, Some(200), None, None).unwrap();
    assert_eq!(paid.amount, 200);
    assert_eq!(notes(&alice), held - 501 - 201);
}

#[test]
fn a_phone_knows_what_paying_a_code_costs_without_the_network_and_pays_no_more() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let held = notes(&alice);
    let bob = net.wallet("bob", net.height());
    let open = bob.payment_code(None).unwrap();
    for amount in [500, 1_234, held / 3] {
        let fee = alice
            .pay_fee(open.qr.clone(), Some(amount))
            .unwrap()
            .unwrap();
        let quote = alice.pay_quote(open.qr.clone(), Some(amount)).unwrap();
        assert_eq!(quote.fee, fee, "paying {amount}");
        let before = notes(&alice);
        alice
            .pay(open.qr.clone(), Some(amount), None, None)
            .unwrap();
        assert_eq!(notes(&alice), before - amount - fee, "paying {amount}");
    }
    // More than held there: told over the network, by a quote.
    assert_eq!(alice.pay_fee(open.qr.clone(), Some(held)).unwrap(), None);
    assert!(alice.pay_fee("garbage".into(), Some(10)).is_err());
}

#[test]
fn a_phone_paying_now_answers_once_paid_and_mails_it_and_unlinks_after() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let held = notes(&alice);
    let bob = net.wallet("bob", net.height());
    let hub = bob.hubs().unwrap()[0].url.clone();
    let asked = bob.payment_code(Some(500)).unwrap();

    // Answered once paid: neither delivered yet nor to hand over.
    let paid = alice.clone().pay_now(asked.qr, None, None, None).unwrap();
    assert_eq!((paid.amount, &paid.hub), (500, &hub));
    assert!(!paid.delivered, "{paid:?}");
    assert_eq!((&paid.handover, &paid.undelivered), (&None, &None));
    assert_eq!(notes(&alice), held - 501);

    // In Bob's mailbox right after, and Alice's change unlinked.
    let waited = std::time::Instant::now();
    let got = loop {
        let got = bob.collect().unwrap();
        if !got.is_empty() || waited.elapsed().as_secs() > 30 {
            break got;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!((got[0].kind, got[0].amount), (Kind::Received, 500));
    assert_eq!(notes(&bob), 500);
    let unlinked = |alice: &Wallet| {
        let sent = alice.notes_of(Kind::Sent, paid.id.clone()).unwrap();
        !sent.made.is_empty() && sent.made.iter().all(|n| n.linking == Linking::Unlinked)
    };
    while !unlinked(&alice) && waited.elapsed().as_secs() <= 30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(unlinked(&alice));
    // Mailed once: not mailed again.
    alice.resume().unwrap();
    assert_eq!(alice.on_their_way().unwrap(), 0);
    assert!(bob.collect().unwrap().is_empty());
    let history = alice.history().unwrap();
    assert_eq!(
        (history[0].kind, history[0].state),
        (Kind::Sent, State::Done)
    );
}

#[test]
fn a_phone_collecting_now_answers_once_taken_and_unlinks_after() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let bob = net.wallet("bob", net.height());
    let asked = bob.payment_code(Some(500)).unwrap();
    let paid = alice.pay(asked.qr, None, None, None).unwrap();
    assert!(paid.delivered, "{paid:?}");

    let got = bob.clone().collect_now().unwrap();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!((got[0].kind, got[0].amount), (Kind::Received, 500));
    assert_eq!(notes(&bob), 500);
    // Its notes unlinked right after.
    let unlinked = |bob: &Wallet| {
        let taken = bob.notes_of(Kind::Received, got[0].id.clone()).unwrap();
        !taken.made.is_empty() && taken.made.iter().all(|n| n.linking == Linking::Unlinked)
    };
    let waited = std::time::Instant::now();
    while !unlinked(&bob) && waited.elapsed().as_secs() <= 30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(unlinked(&bob));
    // Each payment is taken once.
    assert!(bob.clone().collect_now().unwrap().is_empty());
    assert_eq!(notes(&bob), 500);
}

#[test]
fn a_phone_waiting_for_mail_wakes_as_its_relays_push_a_payment() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let bob = net.wallet("bob", net.height());
    let asked = bob.payment_code(Some(500)).unwrap();
    // Not looked in yet: nothing pushes.
    assert!(!bob.wait_for_mail(0));
    assert!(bob.clone().collect_now().unwrap().is_empty());
    // Looked in, and nothing came.
    assert!(!bob.wait_for_mail(1));

    let waiting = {
        let bob = bob.clone();
        std::thread::spawn(move || bob.wait_for_mail(30))
    };
    let paid = alice.pay(asked.qr, None, None, None).unwrap();
    assert!(paid.delivered, "{paid:?}");
    assert!(waiting.join().unwrap());
    let got = bob.clone().collect_now().unwrap();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!((got[0].kind, got[0].amount), (Kind::Received, 500));
}

#[test]
fn a_phone_keeps_contacts_by_name_one_to_each_wallet() {
    let net = Net::new(true);
    let alice = net.wallet("alice", net.height());
    let bob = net.wallet("bob", net.height());
    let carol = net.wallet("carol", net.height());
    assert!(alice.contacts().unwrap().is_empty());

    // Bob's code asking 500: kept asking nothing, paid in notes.
    let asking = bob.payment_code(Some(500)).unwrap();
    let kept = alice.save_contact(" Bob ".into(), asking.text).unwrap();
    assert_eq!(kept.name, "Bob");
    let code: PaymentCode = kept.code.parse().unwrap();
    assert_eq!((code.amount, &code.address), (None, &None));
    assert!(code.silent.is_none() && code.licash.is_some(), "{code:?}");
    assert!(matches!(
        alice.scanned(kept.code.clone()).unwrap(),
        Scanned::Code {
            amount: None,
            notes: true
        }
    ));
    // Whom another of his codes pays: Bob.
    let open = bob.payment_code(None).unwrap();
    assert_eq!(
        alice.contact_of(open.text.clone()).unwrap(),
        Some(kept.clone())
    );
    let carols = carol.payment_code(None).unwrap();
    assert_eq!(alice.contact_of(carols.text.clone()).unwrap(), None);
    assert_eq!(alice.contact_of("garbage".into()).unwrap(), None);

    // Another wallet under his name: refused. His again: renamed.
    let taken = invalid(alice.save_contact("bob".into(), carols.text.clone()));
    assert!(taken.contains("another contact's name"), "{taken}");
    alice.save_contact("Carol".into(), carols.text).unwrap();
    alice.save_contact("Bobby".into(), open.text).unwrap();
    let names: Vec<String> = alice
        .contacts()
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, ["Bobby", "Carol"]);

    // Codes paying on Bitcoin only, or on another chain: no contacts.
    let address = bob.bitcoin_address().unwrap();
    assert!(invalid(alice.save_contact("Dan".into(), address)).contains("paid in notes"));
    let elsewhere = Wallet::create(net.dir("mainnet"), Network::Bitcoin, 0, None).unwrap();
    let mainnet = elsewhere.payment_code(None).unwrap();
    assert!(invalid(alice.save_contact("Eve".into(), mainnet.text)).contains("not on"));
    assert!(
        invalid(alice.save_contact(" ".into(), carol.payment_code(None).unwrap().text))
            .contains("a name")
    );

    // Forgotten, and kept so: opened again, the same.
    alice.remove_contact("Carol".into()).unwrap();
    alice.remove_contact("nobody".into()).unwrap();
    let left = alice.contacts().unwrap();
    assert_eq!(left.len(), 1);
    drop(alice);
    let alice = Wallet::open(net.dir("alice"), None).unwrap();
    assert_eq!(alice.contacts().unwrap(), left);
}

#[test]
fn a_phone_shows_the_notes_each_line_of_its_history_spent_and_made() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    // Renewals of notes a restarted hub no longer unlinks: 1000 parts per
    // million at most unless set.
    assert_eq!(alice.renew_limit(), 1_000);
    alice.set_renew_limit(0);
    assert_eq!(alice.renew_limit(), 0);
    let held = notes(&alice);
    let history = alice.history().unwrap();
    let moved = history.iter().find(|a| a.kind == Kind::Moved).unwrap();
    let got = alice.notes_of(Kind::Moved, moved.id.clone()).unwrap();
    assert!(got.spent.is_empty(), "{got:?}");
    assert_eq!(got.made.iter().map(|n| n.amount).sum::<u64>(), held);
    // Taken, then unlinked from the move.
    assert!(
        got.made.iter().all(|n| n.linking == Linking::Unlinked),
        "{got:?}"
    );
    assert!(got
        .made
        .iter()
        .all(|n| !n.made_by_itself && n.spent_by.is_none()));

    let bob = net.wallet("bob", net.height());
    let asked = bob.payment_code(Some(500)).unwrap();
    let paid = alice.pay(asked.qr, None, None, None).unwrap();
    let sent = alice.notes_of(Kind::Sent, paid.id.clone()).unwrap();
    let spent: u64 = sent.spent.iter().map(|n| n.amount).sum();
    let change: u64 = sent.made.iter().map(|n| n.amount).sum();
    assert_eq!(spent, 501 + change, "{sent:?}");
    assert!(sent
        .spent
        .iter()
        .all(|n| n.spent_by.as_ref() == Some(&paid.id)));
    assert!(sent.made.iter().all(|n| n.made_by == paid.id));
    // Its change, unlinked as it is made.
    assert!(
        sent.made.iter().all(|n| n.linking == Linking::Unlinked),
        "{sent:?}"
    );
    let after = alice.notes_of(Kind::Moved, moved.id.clone()).unwrap().made;
    let by = after
        .iter()
        .filter(|n| n.spent_by.as_ref() == Some(&paid.id));
    assert_eq!(by.count(), sent.spent.len());

    // A coin on Bitcoin alone: no notes; a line of none: refused.
    let coin = history.iter().find(|a| a.kind == Kind::Onchain);
    if let Some(coin) = coin {
        assert_eq!(
            alice.notes_of(Kind::Onchain, coin.id.clone()).unwrap(),
            Default::default()
        );
    }
    assert!(alice.notes_of(Kind::Moved, "00".repeat(32)).is_err());
}

#[test]
fn a_phone_shows_whom_the_notes_a_payment_spent_paid_and_what_it_kept() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let history = alice.history().unwrap();
    let moved = history.iter().find(|a| a.kind == Kind::Moved).unwrap();
    // Notes taken pay nothing.
    let got = alice.notes_of(Kind::Moved, moved.id.clone()).unwrap();
    assert!(got.paid.is_empty(), "{got:?}");

    let bob = net.wallet("bob", net.height());
    let asked = bob.payment_code(Some(500)).unwrap();
    let paid = alice.pay(asked.qr, None, None, None).unwrap();
    let sent = alice.notes_of(Kind::Sent, paid.id.clone()).unwrap();
    let spent: u64 = sent.spent.iter().map(|n| n.amount).sum();
    let parts: Vec<_> = sent.paid.iter().map(|p| (p.to, p.amount)).collect();
    assert_eq!(
        parts,
        [
            (PaidTo::Payee, 500),
            (PaidTo::Hub, 1),
            (PaidTo::Kept, spent - 501)
        ],
        "{sent:?}"
    );
    assert!(sent.paid.iter().all(|p| p.hub == paid.hub));
    for part in &sent.paid {
        assert_eq!(part.notes.iter().sum::<u64>(), part.amount, "{part:?}");
    }
    // What it kept is its change, note for note.
    let made: Vec<u64> = sent.made.iter().map(|n| n.amount).collect();
    assert_eq!(sent.paid[2].notes, made);
}

#[test]
fn a_phone_offers_the_ways_it_could_pay_to_choose_from() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let held = notes(&alice);
    let bob = net.wallet("bob", net.height());
    let hub = bob.hubs().unwrap()[0].url.clone();
    let asked = bob.payment_code(Some(500)).unwrap();

    // Holding enough at the payee's hub: one way, through no provider,
    // the one quoted.
    let offers = alice.pay_offers(asked.qr.clone(), None).unwrap();
    let quote = PayQuote {
        hub: hub.clone(),
        amount: 500,
        fee: 1,
        swap_from: None,
        swapped: 0,
        trusted: true,
    };
    let direct = PayOffer {
        provider: None,
        provider_name: None,
        known: false,
        quote: quote.clone(),
    };
    assert_eq!(offers, [direct]);
    assert_eq!(alice.pay_quote(asked.qr.clone(), None).unwrap(), quote);
    // No provider to choose: refused, nothing paid.
    let chosen = alice.choose_pay_offer(asked.qr.clone(), None, "http://swaps.example".into());
    assert!(invalid(chosen).contains("offers no swap"));
    assert_eq!(notes(&alice), held);

    // No provider announced on her hub's relays: no payout offered.
    let address = "bcrt1p8sjsah3xnncxd4jar9pc0xn3lhu7tlg2wwk03vxnvn0zhd24j25sl5zmq9";
    let offers = alice.payout_offers(address.into(), Some(1_000), None);
    assert!(invalid(offers).contains("no swap provider"));
    assert_eq!(notes(&alice), held);
}

#[test]
fn a_phone_paying_while_its_hub_is_down_sends_the_payment_to_the_mailbox_once_made() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let held = notes(&alice);
    let bob = net.wallet("bob", net.height());
    let asked = bob.payment_code(Some(500)).unwrap();

    // Its hub down: under way, and still so when resumed.
    net.down.store(true, Ordering::SeqCst);
    let paid = alice.pay(asked.qr.clone(), None, None, None);
    assert!(matches!(paid, Err(LicashError::Pending { .. })), "{paid:?}");
    alice.resume().unwrap();
    assert!(notes(&alice) < held);

    // Back up: made when resumed, and sent to Bob's mailbox, once.
    net.down.store(false, Ordering::SeqCst);
    alice.resume().unwrap();
    assert_eq!(notes(&alice), held - 501);
    let got = bob.collect().unwrap();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!((got[0].kind, got[0].amount), (Kind::Received, 500));
    alice.resume().unwrap();
    assert!(bob.collect().unwrap().is_empty());
    assert_eq!(notes(&bob), 500);
    assert_eq!(alice.on_their_way().unwrap(), 0);

    // Paid with its hub up: sent at once, nothing kept to send later.
    let paid = alice.pay(asked.qr, None, None, None).unwrap();
    assert!(paid.delivered, "{paid:?}");
    alice.resume().unwrap();
    assert_eq!(bob.collect().unwrap().len(), 1);
    assert_eq!(notes(&bob), 1_000);
}

#[test]
fn a_phone_paying_a_code_at_a_hub_keeping_it_is_done_once_released_and_collected_there() {
    let net = Net::keeping();
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let held = notes(&alice);
    let bob = net.wallet("bob", net.height());
    let hub = bob.hubs().unwrap()[0].url.clone();
    let asked = bob.payment_code(Some(500)).unwrap();

    // Kept at the hub for Bob: nothing mailed, nothing to hand over.
    let paid = alice.pay(asked.qr.clone(), None, None, None).unwrap();
    assert_eq!((paid.amount, &paid.hub), (500, &hub));
    assert!(paid.kept && !paid.delivered, "{paid:?}");
    assert_eq!((&paid.handover, &paid.undelivered), (&None, &None));
    assert_eq!(notes(&alice), held - 501);
    assert_eq!(alice.on_their_way().unwrap(), 1);

    // Bob collects it there, once, and tells Alice so through the hub.
    let got = bob.collect().unwrap();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!((got[0].kind, got[0].amount), (Kind::Received, 500));
    assert!(bob.collect().unwrap().is_empty());
    assert_eq!(notes(&bob), 500);
    alice.resume().unwrap();
    assert_eq!(alice.on_their_way().unwrap(), 0);

    // Paying now: answered once released, collected as soon.
    let paid = alice.clone().pay_now(asked.qr, None, None, None).unwrap();
    assert!(paid.kept && paid.handover.is_none(), "{paid:?}");
    let got = bob.clone().collect_now().unwrap();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(notes(&bob), 1_000);
}

#[test]
fn a_phone_tells_whom_it_pays_a_note_and_learns_who_paid_it() {
    let net = Net::keeping();
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let bob = net.wallet("bob", net.height());
    let asked = bob.payment_code(Some(500)).unwrap();

    let note = Some("  for the  pizza ".into());
    let paid = alice.pay(asked.qr.clone(), None, note, Some(0)).unwrap();
    assert!(paid.kept, "{paid:?}");
    let sent = alice.history().unwrap();
    let sent = sent.iter().find(|a| a.id == paid.id).unwrap();
    assert_eq!(
        (sent.memo.as_deref(), &sent.from),
        (Some("for the pizza"), &None)
    );

    // Bob reads the note, and who paid: Alice, proved to him alone, whom
    // he may keep as a contact, and finds as one once kept.
    let got = bob.collect().unwrap();
    assert_eq!(got[0].memo.as_deref(), Some("for the pizza"));
    let from = got[0].from.clone().expect("who paid");
    let alices = alice.payment_code(None).unwrap();
    assert_eq!(from, alices.text);
    assert_eq!(bob.contact_of(from.clone()).unwrap(), None);
    let kept = bob.save_contact("Alice".into(), from.clone()).unwrap();
    assert_eq!(bob.contact_of(from).unwrap(), Some(kept));
    let history = bob.history().unwrap();
    let line = history.iter().find(|a| a.id == paid.id).unwrap();
    assert_eq!(line, &got[0]);

    // A note alone, no code shared: no one named.
    let paid = alice
        .pay(asked.qr, None, Some("rent".into()), None)
        .unwrap();
    let got = bob.collect().unwrap();
    assert_eq!(
        (got[0].memo.as_deref(), &got[0].from),
        (Some("rent"), &None)
    );
    assert_eq!(got[0].id, paid.id);
}

#[test]
fn a_phone_names_the_contacts_its_payments_went_to_and_came_from() {
    let net = Net::keeping();
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let bob = net.wallet("bob", net.height());
    let asked = bob.payment_code(Some(500)).unwrap();
    let paid = alice.pay(asked.qr.clone(), None, None, Some(0)).unwrap();
    let got = bob.collect().unwrap();
    let sent = alice.history().unwrap();
    let sent: Vec<Activity> = sent.into_iter().filter(|a| a.id == paid.id).collect();
    let taken: Vec<Activity> = bob
        .history()
        .unwrap()
        .into_iter()
        .filter(|a| a.id == got[0].id)
        .collect();

    // No contacts: no one named.
    assert_eq!(alice.contacts_of(sent.clone()).unwrap(), vec![None]);
    assert_eq!(bob.contacts_of(taken.clone()).unwrap(), vec![None]);

    // Each kept as the other's contact: the payment says to whom, and from whom.
    let bobs = bob.payment_code(None).unwrap();
    alice.save_contact("Bob".into(), bobs.text).unwrap();
    let from = got[0].from.clone().expect("who paid");
    bob.save_contact("Alice".into(), from).unwrap();
    assert_eq!(
        alice.contacts_of(sent).unwrap(),
        vec![Some("Bob".to_string())]
    );
    assert_eq!(
        bob.contacts_of(taken).unwrap(),
        vec![Some("Alice".to_string())]
    );
}

#[test]
fn a_phone_is_paid_at_an_extra_code_apart_from_its_own_and_shows_each_payment() {
    let net = Net::keeping();
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let bob = net.wallet("bob", net.height());
    assert!(bob.codes().unwrap().is_empty());
    let made = bob.add_code(" Bob  online ".into()).unwrap();
    assert_eq!((made.index, made.label.as_str()), (1, "Bob online"));
    let shown = made.code.clone().expect("a code at its hubs");
    let own = bob.payment_code(None).unwrap();
    assert_ne!(shown.text, own.text);
    let asked = bob.extra_code(1, Some(500)).unwrap();

    // Alice pays it, telling who pays: an extra code of her own.
    let alices = alice.add_code("Alice online".into()).unwrap();
    let note = Some("for the pizza".into());
    let paid = alice.pay(asked.qr, None, note, Some(1)).unwrap();
    assert!(paid.kept, "{paid:?}");

    // Collected at the code, paid on to Bob's own: one line, the payment
    // taken at the code, its fee that of paying it on.
    let got = bob.collect().unwrap();
    assert_eq!(got.len(), 1, "{got:#?}");
    let line = &got[0];
    assert_eq!(
        (line.id.as_str(), line.amount, line.kind),
        (paid.id.as_str(), 500, Kind::Received)
    );
    assert_eq!(line.code.as_deref(), Some("Bob online"));
    assert_eq!(line.memo.as_deref(), Some("for the pizza"));
    assert_eq!(line.from, alices.code.map(|c| c.text));
    assert!(line.fee > 0 && line.state == State::Done, "{line:?}");
    assert_eq!(notes(&bob), 500 - line.fee);
    let history = bob.history().unwrap();
    assert_eq!(history, got, "the payment on not shown itself");
    assert!(matches!(
        bob.details(Kind::Received, paid.id.clone()),
        Ok(Details::Notes { .. })
    ));
    let codes = bob.codes().unwrap();
    assert_eq!(
        (codes[0].received, codes[0].payments, codes[0].fees),
        (500, 1, line.fee)
    );
    assert!(bob.collect().unwrap().is_empty());
}

#[test]
fn a_phone_paying_a_code_naming_no_mailbox_hands_it_over_though_its_hub_keeps_it() {
    let net = Net::keeping();
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let bob = net.wallet("bob", net.height());
    let asked = bob.payment_code(Some(500)).unwrap();
    // Bob's code, its mailbox left out.
    let mut code: PaymentCode = asked.text.parse().unwrap();
    code.licash.as_mut().unwrap().mailbox = None;
    let paid = alice.pay(code.to_string(), None, None, None).unwrap();
    assert!(paid.kept && !paid.delivered, "{paid:?}");
    let handover = paid.handover.unwrap();
    // Collected at the hub, or handed over: taken once.
    assert_eq!(bob.collect().unwrap().len(), 1);
    assert!(invalid(bob.receive(handover, false)).contains("received already"));
    assert_eq!(notes(&bob), 500);
}

/// HTTP to a hub, losing every request that posts.
struct Lossy(licash_transport::Http);

impl licash_wallet::Transport for Lossy {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<licash_wallet::Response, String>> + Send {
        let lost = body.is_some();
        let answer = self.0.request(url, body);
        async move {
            match lost {
                true => Err("connection reset".into()),
                false => answer.await,
            }
        }
    }
}

#[test]
fn a_phone_keeps_no_move_its_hub_never_answered_and_gives_up_those_kept_before() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let alice = net.wallet("alice", 0);
    let code = alice.bitcoin_code(None).unwrap();
    net.mine(1, vec![net.pay_silent(&code.text, 3_000, 1)]);
    assert_eq!(scan(&alice, &light), (1, 3_000));
    let moves = |wallet: &Wallet| {
        let history = wallet.history().unwrap();
        history.iter().filter(|a| a.kind == Kind::Moved).count()
    };

    // Its hub down: no move kept, however often asked, its coins still on
    // Bitcoin.
    net.down.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        let moved = alice.move_to_licash(light.clone());
        assert!(
            matches!(moved, Err(LicashError::Unavailable { .. })),
            "{moved:?}"
        );
        alice.resume().unwrap();
    }
    net.down.store(false, Ordering::SeqCst);
    assert_eq!(moves(&alice), 0);
    let onchain = Balance {
        onchain: 3_000,
        ..Balance::default()
    };
    assert_eq!(alice.balance().unwrap(), onchain);
    drop(alice);

    // Moves kept unanswered, as earlier versions did: given up on resuming,
    // never shown again, and the coins moved anew.
    let path = std::path::Path::new(&net.dir("alice")).join("wallet.sqlite");
    let http = licash_transport::Http::new(None).unwrap();
    let earlier = licash_wallet::Wallet::open(&path, Lossy(http)).unwrap();
    for _ in 0..2 {
        let kept = net.runtime.block_on(earlier.deposit(&net.url, 2_000));
        assert!(
            matches!(kept, Err(licash_wallet::Error::Pending { .. })),
            "{kept:?}"
        );
    }
    drop(earlier);
    let alice = Wallet::open(net.dir("alice"), None).unwrap();
    assert_eq!(moves(&alice), 2);
    alice.resume().unwrap();
    assert_eq!(moves(&alice), 0);
    alice.move_to_licash(light.clone()).unwrap();
    assert_eq!(moves(&alice), 1);
    let moving = Balance {
        moving: 3_000,
        ..Balance::default()
    };
    assert_eq!(alice.balance().unwrap(), moving);
}

#[test]
fn a_move_whose_payment_is_in_a_block_is_moving_until_its_notes_arrive() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let alice = net.wallet("alice", 0);
    let code = alice.bitcoin_code(None).unwrap();
    net.mine(1, vec![net.pay_silent(&code.text, 3_000, 1)]);
    assert_eq!(scan(&alice, &light), (1, 3_000));
    let moving = alice.move_to_licash(light.clone()).unwrap();

    // Its payment in a block, seen spent before its hub made the notes:
    // neither the wallet's coins nor its notes, moving still.
    net.confirm_sent();
    assert_eq!(scan(&alice, &light).1, 0);
    let confirmed = Balance {
        moving: moving.amount,
        ..Balance::default()
    };
    assert_eq!(alice.balance().unwrap(), confirmed);

    // Its notes received: counted once, as notes.
    net.round();
    net.mine(1, Vec::new());
    net.round();
    alice.resume().unwrap();
    let held = Balance {
        notes: moving.amount,
        ..Balance::default()
    };
    assert_eq!(alice.balance().unwrap(), held);
}

#[test]
fn a_phone_reaches_a_hub_named_by_its_host_alone_over_https() {
    let net = Net::new(false);
    let alice = Wallet::create(net.dir("alice"), Network::Regtest, 0, None).unwrap();
    // Not over plain HTTP, which the hub here serves on its port.
    let host = net.url.strip_prefix("http://").unwrap();
    let secure = alice.add_hub(host.into());
    assert!(
        matches!(secure, Err(LicashError::Unavailable { .. })),
        "{secure:?}"
    );
    assert!(alice.hubs().unwrap().is_empty());
    alice.add_hub(net.url.clone()).unwrap();
    assert_eq!(alice.hubs().unwrap()[0].url, net.url);
}

#[test]
fn a_phone_shows_what_a_move_cost_and_how_deep_its_payment_is() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let url = alice.hubs().unwrap()[0].url.clone();
    let code = alice.bitcoin_code(None).unwrap();
    net.mine(2, Vec::new());
    let paying = net.pay_silent(&code.qr, 3_000, 1);
    net.mine(1, vec![paying.clone()]);
    let paid_in = net.height();
    net.mine(1, Vec::new());
    scan(&alice, &light);
    let id = OutPoint::new(paying.compute_txid(), 0).to_string();
    let found = Onchain {
        txid: paying.compute_txid().to_string(),
        fee: None,
        height: Some(paid_in),
        confirmations: 2,
    };
    let coin = Details::Coin {
        tx: found.clone(),
        vout: 0,
        change: false,
        moving: None,
    };
    assert_eq!(alice.details(Kind::Onchain, id.clone()).unwrap(), coin);

    // Moved: the hub's fee and the miners', and its payment in no block.
    let moving = alice.move_to_licash(light.clone()).unwrap();
    let sent = net.sent().remove(0);
    let txid = sent.compute_txid().to_string();
    let coin = Details::Coin {
        tx: found,
        vout: 0,
        change: false,
        moving: Some(txid.clone()),
    };
    assert_eq!(alice.details(Kind::Onchain, id).unwrap(), coin);
    let paid = |confirmations, height| Onchain {
        txid: txid.clone(),
        fee: Some(3_000 - moving.amount - 100),
        height,
        confirmations,
    };
    let moved = |payment| match alice.details(Kind::Moved, moving.id.clone()).unwrap() {
        Details::Moved {
            hub,
            hash,
            provider: None,
            pays,
            address,
            payment: shown,
            depth,
            fund_by,
            timeout,
            refund,
        } => {
            assert_eq!((hub, hash), (url.clone(), moving.id.clone()));
            assert_eq!(pays, Some(moving.amount + 100));
            let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
                address.unwrap().parse().unwrap();
            let script = address.assume_checked().script_pubkey();
            assert_eq!(script, sent.output[0].script_pubkey);
            assert_eq!(depth, Some(2));
            assert!(fund_by.unwrap() < timeout.unwrap());
            assert_eq!(refund, None);
            assert_eq!(shown, Some(payment));
        }
        other => panic!("{other:?}"),
    };
    moved(paid(0, None));

    // In a block once the phone looked in it, deeper with each block.
    net.confirm_sent();
    let confirmed = net.height();
    moved(paid(0, None));
    scan(&alice, &light);
    moved(paid(1, Some(confirmed)));
    net.mine(1, Vec::new());
    scan(&alice, &light);
    moved(paid(2, Some(confirmed)));
    net.round();
    alice.resume().unwrap();
    let history = alice.history().unwrap();
    assert_eq!(
        (history[0].kind, history[0].state),
        (Kind::Moved, State::Done)
    );
    moved(paid(2, Some(confirmed)));

    let none = invalid(alice.details(Kind::Moved, "00".repeat(32)));
    assert!(none.contains("nothing in the history"), "{none}");
    assert!(invalid(alice.details(Kind::Onchain, "no".into())).contains("nothing"));
    assert!(invalid(alice.details(Kind::Sent, "no".into())).contains("nothing"));
}

#[test]
fn a_phone_whose_hub_opens_no_contracts_has_none_and_keeps_no_file_for_them() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let hub = alice.hubs().unwrap().remove(0);
    assert_eq!(hub.contracts, None);
    assert!(alice.contracts().unwrap().is_empty());
    assert!(alice.resume_contracts(light.clone()).unwrap().is_empty());
    let balance = alice.balance().unwrap();
    assert_eq!((balance.covered, balance.opening), (0, 0));
    // Asked anyway: refused, and nothing kept.
    let quoted = invalid(alice.contract_quote(hub.url.clone()));
    assert!(quoted.contains("opens no contracts"), "{quoted}");
    let opened = invalid(alice.open_contract(light.clone(), hub.url.clone(), None, None));
    assert!(opened.contains("opens no contracts"), "{opened}");
    let other = invalid(alice.contract_quote("https://other.example".into()));
    assert!(other.contains("no hub you use"), "{other}");
    // Nor paid for with notes: none waiting.
    let paid = invalid(alice.paid_contract_quote(hub.url.clone(), None, None, None, None));
    assert!(paid.contains("opens no contracts"), "{paid}");
    assert!(alice.paid_contracts().unwrap().is_empty());
    // No contract to exit: no consent taken, nothing driven.
    assert_eq!(alice.exit_consent().unwrap(), None);
    let address = alice.bitcoin_address().unwrap();
    let consent = invalid(alice.consent_to_exit(address, 2_016));
    assert!(consent.contains("no contracts"), "{consent}");
    assert!(alice.drive_exits(light.clone(), 2_016).unwrap().is_empty());
    alice.revoke_exit_consent().unwrap();
    let dir = std::path::Path::new(&net.dir("alice")).to_owned();
    assert!(dir.join("wallet.sqlite").exists());
    assert!(!holds_contracts(&dir));
}

/// A contract at `hub` in the wallet's directory `dir`, its F buried, as
/// one opened there leaves it: its hub held to `fees`, as JSON.
fn contract_under(dir: &str, hub: &str, fees: &str) {
    let fees: licash_api::Fees = serde_json::from_str(fees).unwrap();
    let wallet = std::path::Path::new(dir).join("wallet.sqlite");
    licash_contracts::holder::seed_contract(&wallet, hub, &fees).unwrap();
}

/// Whether the wallet's directory `dir` holds the holder's contracts: made
/// with the first contract, and by no reading of them.
fn holds_contracts(dir: &std::path::Path) -> bool {
    let db = rusqlite::Connection::open(dir.join("wallet.sqlite")).unwrap();
    let n: i64 = db
        .query_row(
            "SELECT count(*) FROM schema_versions WHERE component = 'contracts'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    n > 0 || dir.join("contracts").exists()
}

#[test]
fn a_phone_pays_a_hub_charging_more_than_its_contract_opened_under_once_approved() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let held = notes(&alice);
    let bob = net.wallet("bob", net.height());
    let hub = alice.hubs().unwrap().remove(0);
    // No contract: no hub is held to anything, and nothing is made.
    assert!(alice.fees_raised().unwrap().is_empty());
    let one = Rate { base: 1, ppm: 0 };
    let charged = Fees {
        spend: one,
        lock: one,
        refund: one,
        output_msat: 0,
    };
    alice.approve_fees(hub.url.clone(), charged).unwrap();
    let dir = net.dir("alice");
    assert!(!holds_contracts(std::path::Path::new(&dir)));
    let other = invalid(alice.approve_fees("https://other.example".into(), charged));
    assert!(other.contains("no hub you use"), "{other}");
    drop(alice);

    // Her contract there opened while a payment was free.
    let free = r#"{"spend":{"base":0,"ppm":0},"lock":{"base":1,"ppm":0},"refund":{"base":1,"ppm":0},"output_msat":0}"#;
    contract_under(&dir, &hub.url, free);
    let alice = Wallet::open(dir.clone(), None).unwrap();
    let agreed = Fees {
        spend: Rate { base: 0, ppm: 0 },
        ..charged
    };
    let raised = vec![FeesRaised {
        hub: hub.url.clone(),
        charged,
        agreed,
    }];
    assert_eq!(alice.fees_raised().unwrap(), raised);
    let asked = bob.payment_code(Some(500)).unwrap();
    let refused = alice.pay(asked.qr.clone(), None, None, None).unwrap_err();
    assert!(
        matches!(&refused, LicashError::FeesRaised { hub: at } if *at == hub.url),
        "{refused:?}"
    );
    assert_eq!(notes(&alice), held);
    assert_eq!(alice.fees_raised().unwrap(), raised);

    // Approved as shown: paid, and kept for the wallet opened again.
    alice.approve_fees(hub.url.clone(), charged).unwrap();
    assert!(alice.fees_raised().unwrap().is_empty());
    let paid = alice.pay(asked.qr, None, None, None).unwrap();
    assert_eq!(paid.amount, 500);
    assert_eq!(notes(&alice), held - 501);
    drop(alice);
    let alice = Wallet::open(dir.clone(), None).unwrap();
    assert!(alice.fees_raised().unwrap().is_empty());
    let asked = bob.payment_code(Some(100)).unwrap();
    assert_eq!(alice.pay(asked.qr, None, None, None).unwrap().amount, 100);
    drop(alice);

    // Her contracts unreadable: what they agreed unknown, a hub charging
    // anything is paid nothing, and shown so.
    let db = rusqlite::Connection::open(format!("{dir}/wallet.sqlite")).unwrap();
    let version = |v: i64| {
        db.execute(
            "UPDATE schema_versions SET version = ?1 WHERE component = 'contracts'",
            [v],
        )
        .unwrap()
    };
    let kept: i64 = db
        .query_row(
            "SELECT version FROM schema_versions WHERE component = 'contracts'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    version(kept + 1);
    let alice = Wallet::open(dir.clone(), None).unwrap();
    let nothing = Fees {
        spend: Rate { base: 0, ppm: 0 },
        lock: Rate { base: 0, ppm: 0 },
        refund: Rate { base: 0, ppm: 0 },
        output_msat: 0,
    };
    let raised = vec![FeesRaised {
        hub: hub.url.clone(),
        charged,
        agreed: nothing,
    }];
    assert_eq!(alice.fees_raised().unwrap(), raised);
    let asked = bob.payment_code(Some(100)).unwrap();
    let refused = alice.pay(asked.qr.clone(), None, None, None).unwrap_err();
    assert!(
        matches!(refused, LicashError::FeesRaised { .. }),
        "{refused:?}"
    );
    drop(alice);
    // Readable again: paid.
    version(kept);
    let alice = Wallet::open(dir, None).unwrap();
    assert_eq!(alice.pay(asked.qr, None, None, None).unwrap().amount, 100);
}

#[test]
fn a_phone_with_no_contract_forces_none_closed_and_keeps_no_file_for_it() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    assert!(alice.recoveries().unwrap().is_empty());
    let bad = invalid(alice.force_close_contract(light.clone(), "zz".into()));
    assert!(bad.contains("no contract id"), "{bad}");
    let failed = |result: Result<_, LicashError>| match result {
        Err(LicashError::Failed { reason }) => reason,
        other => panic!("not failed: {other:?}"),
    };
    let none = failed(
        alice
            .force_close_contract(light.clone(), "00".repeat(32))
            .map(|_| ()),
    );
    assert!(none.contains("no contracts"), "{none}");
    let none = failed(alice.give_up_recovery("00".repeat(32)));
    assert!(none.contains("no contracts"), "{none}");
    let none = failed(alice.allow_publication_fee("00".repeat(32), 1_000));
    assert!(none.contains("no contracts"), "{none}");
    let bad = invalid(alice.allow_publication_fee("zz".into(), 1_000));
    assert!(bad.contains("no contract id"), "{bad}");
    // Carried on with the others: nothing.
    assert!(alice.resume_contracts(light.clone()).unwrap().is_empty());
    assert!(alice.recoveries().unwrap().is_empty());
    let dir = std::path::Path::new(&net.dir("alice")).to_owned();
    assert!(!holds_contracts(&dir));
}

#[test]
fn a_phone_previews_and_optimizes_notes_and_shows_the_fee_in_its_history() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let bob = funded(&net, &light, "bob");
    let alice = net.wallet("alice", net.height());
    let code = alice.payment_code(Some(64)).unwrap();
    let paid = bob.pay(code.qr, None, None, None).unwrap();
    alice.receive(paid.handover.unwrap(), false).unwrap();
    alice.resume().unwrap();
    assert_eq!(notes(&alice), 64);
    assert_eq!(alice.maintain_notes().unwrap(), 0);
    let hub = alice.hubs().unwrap()[0].url.clone();
    let quote = alice.optimization_quote(hub.clone()).unwrap().unwrap();
    assert_eq!((quote.id, quote.fee, quote.notes_before), (None, 1, 1));
    assert!((18..=24).contains(&quote.notes_after));
    assert!(invalid(alice.optimize_notes(hub.clone(), 0)).contains("more than the limit"));
    let done = alice.optimize_notes(hub.clone(), 1).unwrap().unwrap();
    assert_eq!(done.notes_after, quote.notes_after);
    assert_eq!(notes(&alice), 63);
    let id = done.id.unwrap();
    let history = alice.history().unwrap();
    let optimized = history.iter().find(|a| a.kind == Kind::Optimized).unwrap();
    assert_eq!(optimized.id, id);
    assert_eq!(
        (optimized.state, optimized.amount, optimized.fee),
        (State::Done, 0, 1)
    );
    assert_eq!(
        alice.details(Kind::Optimized, id.clone()).unwrap(),
        Details::Notes { hub }
    );
    let changed = alice.notes_of(Kind::Optimized, id).unwrap();
    assert_eq!(changed.spent.iter().map(|n| n.amount).sum::<u64>(), 64);
    assert_eq!(changed.made.iter().map(|n| n.amount).sum::<u64>(), 63);
    assert_eq!(alice.maintain_notes().unwrap(), 0);
}

/// Over Tor, the light client goes through the app's Tor client, wallet or
/// not: a SOCKS5 proxy only it can use. Nothing here reaches the Tor
/// network.
#[test]
fn the_tor_client_lends_the_light_client_a_proxy_of_its_own() {
    use std::io::{Read, Write};

    let dir = tempfile::tempdir().unwrap();
    let client = TorClient::new(dir.path().join("tor").display().to_string(), None).unwrap();
    let url = client.proxy().unwrap();
    assert_eq!(
        client.proxy().unwrap().as_str(),
        url.as_str(),
        "the same each time"
    );
    let (credentials, address) = url
        .strip_prefix("socks5://")
        .unwrap()
        .split_once('@')
        .unwrap();
    let (user, password) = credentials.split_once(':').unwrap();
    assert!(address.starts_with("127.0.0.1:"), "{address}");

    let greet = |user: &str, password: &str| {
        let mut client = std::net::TcpStream::connect(address).unwrap();
        client.write_all(&[5, 1, 2]).unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [5, 2]);
        let mut auth = vec![1, user.len() as u8];
        auth.extend(user.as_bytes());
        auth.push(password.len() as u8);
        auth.extend(password.as_bytes());
        client.write_all(&auth).unwrap();
        client.read_exact(&mut reply).unwrap();
        reply[1]
    };
    assert_eq!(greet(user, password), 0);
    assert_ne!(greet(user, "guessed"), 0);

    // Kept open by a wallet over it, closed with the last of them.
    let wallet = Wallet::create(
        dir.path().join("wallet").display().to_string(),
        Network::Signet,
        0,
        Some(client.clone()),
    )
    .unwrap();
    assert!(wallet.tor());
    drop(client);
    assert_eq!(greet(user, password), 0);
    drop(wallet);
    assert!(std::net::TcpStream::connect(address).is_err());
}

/// Taken on from the app's thread, outside any runtime, over Tor: the hubs
/// asked what URLs they name, here none, without failing for want of one.
/// Nothing here reaches the Tor network.
#[test]
fn a_wallet_over_tor_takes_things_on_from_a_thread_of_the_apps() {
    let dir = tempfile::tempdir().unwrap();
    let tor = TorClient::new(dir.path().join("tor").display().to_string(), None).unwrap();
    let wallet = Wallet::create(
        dir.path().join("wallet").display().to_string(),
        Network::Signet,
        0,
        Some(tor),
    )
    .unwrap();
    wallet.resume().unwrap();
    wallet.resume().unwrap();
}

#[test]
fn a_phone_takes_back_the_coins_of_a_move_whose_notes_it_never_claimed() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let code = alice.bitcoin_code(None).unwrap();
    net.mine(2, Vec::new());
    let payment = net.pay_silent(&code.qr, 3_000, 1);
    net.mine(1, vec![payment]);
    net.mine(2, Vec::new());
    assert_eq!(scan(&alice, &light), (1, 3_000));

    // Moved, paid and confirmed at depth: the hub locks its notes, which
    // the phone, asleep, never claims; the hub takes them back.
    let moving = alice.move_to_licash(light.clone()).unwrap();
    let sent = net.sent();
    let funding = OutPoint::new(sent[0].compute_txid(), 0);
    let pays = moving.amount + 100;
    assert_eq!(sent[0].output[0].value.to_sat(), pays);
    let timeout = match alice.details(Kind::Moved, moving.id.clone()).unwrap() {
        Details::Moved { timeout, .. } => timeout.unwrap(),
        other => panic!("{other:?}"),
    };
    net.confirm_sent();
    net.round();
    net.mine(1, Vec::new());
    net.round();
    for _ in 0..8 {
        net.mine(1, Vec::new());
        net.round();
    }
    alice.resume().unwrap();
    assert_eq!(alice.balance().unwrap().notes, 0);
    let refunds = |net: &Net| -> Vec<Transaction> {
        let sent = net.sent().into_iter();
        let spending = sent.filter(|t| t.input.iter().any(|i| i.previous_output == funding));
        spending.collect()
    };

    // Not before its timeout.
    while net.height() + 1 < timeout {
        net.mine(1, Vec::new());
    }
    scan(&alice, &light);
    assert!(refunds(&net).is_empty());

    // From it on, taken back by itself, to an address of its own: found
    // once confirmed, and shown with the move.
    net.mine(1, Vec::new());
    assert!(net.height() >= timeout);
    scan(&alice, &light);
    let refunded = refunds(&net);
    assert_eq!(refunded.len(), 1, "{refunded:?}");
    let refund = &refunded[0];
    assert_eq!(refund.output.len(), 1);
    let fee = pays - refund.output[0].value.to_sat();
    assert!(fee > 0 && fee <= 2 * refund.vsize() as u64 + 2, "{fee}");
    let txid = refund.compute_txid().to_string();
    match alice.details(Kind::Moved, moving.id.clone()).unwrap() {
        Details::Moved { refund, .. } => assert_eq!(refund, Some(txid.clone())),
        other => panic!("{other:?}"),
    }
    // Handed the network again until found in a block.
    net.confirm_sent();
    assert_eq!(scan(&alice, &light), (1, refund.output[0].value.to_sat()));
    scan(&alice, &light);
    assert!(refunds(&net).is_empty());
}

/// Alice's move of a 3,000 sat coin, paid and confirmed at depth, its
/// notes locked by the hub and, never claimed, taken back by it: what
/// her payment spends, pays and times out at, and the move's id. She
/// never asked her hub since, and knows none of it.
fn moved_unclaimed(net: &Net, light: &Arc<Light>, alice: &Wallet) -> (OutPoint, u64, u32, String) {
    let code = alice.bitcoin_code(None).unwrap();
    net.mine(2, Vec::new());
    let payment = net.pay_silent(&code.qr, 3_000, 1);
    net.mine(1, vec![payment]);
    net.mine(2, Vec::new());
    assert_eq!(scan(alice, light), (1, 3_000));
    let moving = alice.move_to_licash(light.clone()).unwrap();
    let sent = net.sent();
    let funding = OutPoint::new(sent[0].compute_txid(), 0);
    let pays = moving.amount + 100;
    assert_eq!(sent[0].output[0].value.to_sat(), pays);
    let timeout = match alice.details(Kind::Moved, moving.id.clone()).unwrap() {
        Details::Moved { timeout, .. } => timeout.unwrap(),
        other => panic!("{other:?}"),
    };
    net.confirm_sent();
    for _ in 0..10 {
        net.round();
        net.mine(1, Vec::new());
    }
    net.round();
    (funding, pays, timeout, moving.id)
}

/// The transactions sent spending `coin`.
fn spending(net: &Net, coin: OutPoint) -> Vec<Transaction> {
    let sent = net.sent().into_iter();
    sent.filter(|t| t.input.iter().any(|i| i.previous_output == coin))
        .collect()
}

#[test]
fn a_phone_takes_back_the_coins_of_a_move_its_hub_never_locked_to_it_as_far_as_it_knows() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let (funding, pays, timeout, id) = moved_unclaimed(&net, &light, &alice);
    // Moving, paid in a block: no longer her coin, not yet her notes.
    scan(&alice, &light);
    let balance = alice.balance().unwrap();
    assert_eq!((balance.onchain, balance.notes), (0, 0));
    assert_eq!(balance.moving, pays - 100);

    // Still open as far as she knows, no lock to her ever seen: not
    // before its timeout, then taken back all the same.
    while net.height() + 1 < timeout {
        net.mine(1, Vec::new());
    }
    scan(&alice, &light);
    assert!(spending(&net, funding).is_empty());
    net.mine(1, Vec::new());
    scan(&alice, &light);
    let refunded = spending(&net, funding);
    assert_eq!(refunded.len(), 1, "{refunded:?}");
    let txid = refunded[0].compute_txid().to_string();
    let detail = |alice: &Wallet| {
        let history = alice.history().unwrap();
        let moved = history.into_iter().find(|a| a.id == id).unwrap();
        (moved.state, moved.detail)
    };
    // On its way until found in a block.
    let on_its_way = format!("refund {txid} on its way");
    assert_eq!(detail(&alice), (State::Failed, on_its_way));
    net.confirm_sent();
    let value = refunded[0].output[0].value.to_sat();
    assert_eq!(scan(&alice, &light), (1, value));
    let refunded_in = format!("refunded in {txid}");
    assert_eq!(detail(&alice), (State::Failed, refunded_in));
    assert_eq!(alice.balance().unwrap().onchain, value);
}

/// A payment of a deposit the phone knows of only from its hub, as one
/// made before a restore: taken back only once a block shows it paying the
/// deposit, a refund of a coin that pays it not standing in for its own.
#[test]
fn a_phone_takes_back_only_a_deposit_payment_its_hub_names_that_a_block_shows() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let (funding, _, timeout, _) = moved_unclaimed(&net, &light, &alice);
    while net.height() < timeout {
        net.mine(1, Vec::new());
    }
    // Its own payment forgotten, which its hub names, as it would after a
    // restore: first another output of it.
    let paid_at = (0..=net.height())
        .find(|&h| {
            let block = light.block(light.hash(h).unwrap()).unwrap();
            let block: Block = deserialize(&block).unwrap();
            block
                .txdata
                .iter()
                .any(|t| t.compute_txid() == funding.txid)
        })
        .unwrap();
    let db = rusqlite::Connection::open(format!("{}/wallet.sqlite", net.dir("alice"))).unwrap();
    db.execute("DELETE FROM silent_spends", []).unwrap();
    let named = |vout: u32| {
        db.execute("DELETE FROM deposit_fundings", []).unwrap();
        db.execute(
            "INSERT INTO deposit_fundings (hash, txid, vout, height)
             SELECT hash, ?1, ?2, ?3 FROM deposits",
            rusqlite::params![funding.txid.to_byte_array(), vout, paid_at],
        )
        .unwrap();
    };
    named(funding.vout + 1);
    scan(&alice, &light);
    let wrong = OutPoint::new(funding.txid, funding.vout + 1);
    assert!(spending(&net, wrong).is_empty());
    assert!(spending(&net, funding).is_empty());
    // Named right, at its next look.
    named(funding.vout);
    net.mine(6, Vec::new());
    scan(&alice, &light);
    assert_eq!(spending(&net, funding).len(), 1);
}

#[test]
fn a_phone_hands_its_refund_on_long_after_its_timeout() {
    let net = Net::new(false);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let (funding, _, timeout, _) = moved_unclaimed(&net, &light, &alice);
    while net.height() < timeout {
        net.mine(1, Vec::new());
    }
    // Made, but its broadcasts fail for over two weeks.
    light.failing.store(true, Ordering::SeqCst);
    scan(&alice, &light);
    assert!(spending(&net, funding).is_empty());
    net.mine(2_016 + 144, Vec::new());
    scan(&alice, &light);
    // Working again: handed on a day after the last try.
    light.failing.store(false, Ordering::SeqCst);
    net.mine(143, Vec::new());
    scan(&alice, &light);
    assert!(spending(&net, funding).is_empty());
    net.mine(1, Vec::new());
    scan(&alice, &light);
    let refunded = spending(&net, funding);
    assert_eq!(refunded.len(), 1, "{refunded:?}");
    net.confirm_sent();
    scan(&alice, &light);
    let value = refunded[0].output[0].value.to_sat();
    assert_eq!(alice.balance().unwrap().onchain, value);
}

#[test]
fn a_phone_names_what_a_restore_needs_of_its_hub_and_refuses_what_it_is_not() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let alice = net.wallet("alice", net.height());
    let keys = alice.hub_keys().unwrap();
    assert_eq!(keys.len(), 1);
    let (address, root) = (keys[0].address.clone(), keys[0].close_root.clone());
    let root = root.expect("a deposit root");
    assert_eq!(root.len(), 64, "{root}");
    // Nothing paid its close deposits: nothing found, nothing sent.
    let none = alice
        .recover_closes(light.clone(), address.clone(), root.clone(), 0)
        .unwrap();
    assert!(none.is_empty(), "{none:?}");
    let refused = |address: &str, root: &str| {
        invalid(alice.recover_closes(light.clone(), address.into(), root.into(), 0))
    };
    assert!(refused("zz", &root).contains("hex"));
    assert!(refused(&address, "0707").contains("32 bytes"));
}

/// What a phone did and what it cost, as the Stats screen reads it: each
/// event once, a coin paid on Bitcoin and turned into notes counted
/// as what came and as a move, the fees of payments the history hides
/// included, and the balance replayed from the records the balance now.
#[test]
fn a_phone_counts_what_it_did_and_what_it_cost_and_replays_its_balance() {
    use licash_mobile::{Flow, Way};

    let net = Net::new(false);
    let light = Light::new(&net);
    let alice = funded(&net, &light, "alice");
    let hub = alice.holdings().unwrap()[0].hub.clone();
    // A payment in notes, its change to optimize.
    let bob = net.wallet("bob", net.height());
    let code = bob.payment_code(Some(200)).unwrap();
    let paid = alice.pay(code.qr, None, None, None).unwrap();
    alice.resume().unwrap();
    let done = alice.optimize_notes(hub, 1).unwrap().unwrap();

    let stats = alice.stats(light.clone()).unwrap();
    let of = |flow: Flow, way: Way| {
        stats
            .events
            .iter()
            .filter(|e| e.flow == flow && e.way == way)
            .collect::<Vec<_>>()
    };
    // The coin that came, once; its conversion into notes, apart.
    let came = of(Flow::Received, Way::Bitcoin);
    assert_eq!(came.len(), 1, "{:?}", stats.events);
    assert_eq!(
        (came[0].amount, came[0].fee, came[0].state),
        (3_000, 0, State::Done)
    );
    assert!(came[0].at.is_some());
    let moved = of(Flow::Moved, Way::Bitcoin);
    assert_eq!(moved.len(), 1, "{:?}", stats.events);
    let history = alice.history().unwrap();
    let line = history.iter().find(|a| a.kind == Kind::Moved).unwrap();
    assert_eq!((moved[0].amount, moved[0].fee), (line.amount, line.fee));
    assert_eq!(moved[0].hub_fee, Some(line.fee));

    // The payment in notes, the hub's fee on it.
    let sent = of(Flow::Sent, Way::Licash);
    assert_eq!((sent.len(), sent[0].amount), (1, 200), "{:?}", stats.events);
    assert_eq!((sent[0].id.as_str(), sent[0].fee), (paid.id.as_str(), 1));

    // The optimization, its fee its own.
    let optimized = of(Flow::Optimized, Way::Licash);
    assert_eq!(optimized.len(), 1);
    assert_eq!(optimized[0].id, done.id.unwrap());
    assert_eq!((optimized[0].amount, optimized[0].fee), (0, 1));

    // Fees add up to the history's.
    let total: u64 = stats.events.iter().map(|e| e.fee).sum();
    let shown: u64 = history
        .iter()
        .filter(|a| a.state == State::Done)
        .map(|a| a.fee)
        .sum();
    assert_eq!(total, shown, "{:?}", stats.events);

    // Replayed to now, the balance is what it is.
    let balance = alice.balance().unwrap();
    let now = i64::MAX;
    let [point] = &alice.balance_over(vec![now], light.clone()).unwrap()[..] else {
        panic!("one point");
    };
    assert_eq!(point.licash, balance.notes + balance.notes_pending);
    assert_eq!(point.bitcoin, balance.onchain);
    assert_eq!(
        point.hubs.iter().map(|h| h.amount).sum::<u64>(),
        point.licash
    );
    // And before anything, nothing.
    let [before] = &alice.balance_over(vec![0], light.clone()).unwrap()[..] else {
        panic!("one point");
    };
    assert_eq!((before.licash, before.bitcoin), (0, 0));
}

/// A swap provider on a local port taking deposits on Bitcoin for notes at
/// the hub of `net`, holding 3000 there, following its chain, in the
/// runtime of its own thread: its URL and its key on Nostr, and what stops
/// it.
struct Depositing {
    url: String,
    nostr: [u8; 32],
    stop: Option<(
        tokio::sync::oneshot::Sender<()>,
        std::thread::JoinHandle<()>,
    )>,
    _dir: tempfile::TempDir,
}

impl Depositing {
    fn start(net: &Net) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let wallet = licash_wallet::Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[0x50; 32],
            licash::spend::ChainProfile::Core30DefaultRegtest,
            licash_transport::Http::new(None).unwrap(),
        )
        .unwrap();
        let seed = net.dir.path().join("seed");
        let stocked = mint::paid(
            (&net.hub, &seed, &net.url),
            MAX_POW,
            &wallet.address(),
            3_000,
        );
        let (hub, chain) = (net.url.clone(), net.source.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (ready, started) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                wallet.add_hub(&hub).await.unwrap();
                wallet.receive(&stocked).unwrap();
                let config = licash_swaps::Config {
                    fee: Fee { base: 1, ppm: 0 },
                    min: 5,
                    max: 5_000,
                    margin: 6,
                    confirm: 4,
                };
                let terms = licash_swaps::DepositTerms {
                    fee: Fee { base: 1, ppm: 0 },
                    miner: 200,
                    min: 100,
                    max: 5_000,
                    depth: 2,
                    window: 10,
                    timeout: 1_008,
                    sweep: 6,
                    max_open: 10,
                };
                let provider = licash_swaps::Provider::create(wallet, config).unwrap();
                let provider = Arc::new(provider.take_deposits(terms).unwrap());
                let nostr = provider.nostr_secret().unwrap();
                let chain = Arc::new(licash_swaps_service::ChainView(chain));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                ready.send((addr, nostr)).unwrap();
                let every = std::time::Duration::from_millis(100);
                let stepping = tokio::spawn(licash_swaps_service::step(provider.clone(), every));
                let following =
                    licash_swaps_service::take_deposits(provider.clone(), chain.clone(), every);
                let following = tokio::spawn(following);
                let serving = licash_swaps_service::Serving {
                    nostr: Some(licash_nostr::public_key(&nostr).unwrap()),
                    chain: Some(chain),
                    ..Default::default()
                };
                let router = licash_swaps_service::router(provider, serving);
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        stopped.await.ok();
                    })
                    .await
                    .unwrap();
                stepping.abort();
                following.abort();
            });
        });
        let (addr, nostr) = started.recv().unwrap();
        Self {
            url: format!("http://{addr}"),
            nostr,
            stop: Some((stop, thread)),
            _dir: dir,
        }
    }

    /// Announced on the relay of `net`'s hub, as its service announces it.
    fn announce(&self, net: &Net) {
        let relays = vec![net
            .runtime
            .block_on(net.relay.as_ref().unwrap().url())
            .to_string()];
        let announcement = Announcement {
            urls: vec![self.url.clone()],
            network: "regtest".into(),
            name: Some("depositing".into()),
        };
        net.runtime.block_on(async {
            let announcer = Announcer::new(&self.nostr, Role::Swaps, &relays, &Route::Direct);
            let sent = announcer.await.unwrap().announce(&announcement).await;
            assert_eq!(sent.unwrap(), 1);
        });
    }
}

impl Drop for Depositing {
    fn drop(&mut self) {
        if let Some((stop, thread)) = self.stop.take() {
            stop.send(()).ok();
            thread.join().ok();
        }
    }
}

#[test]
fn a_phone_says_why_its_provider_would_not_move_a_coin_rather_than_ask_its_hub() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let provider = Depositing::start(&net);
    provider.announce(&net);
    let alice = net.wallet("alice", net.height());
    let code = alice.bitcoin_code(None).unwrap();
    let payment = net.pay_silent(&code.qr, 4_000, 1);
    net.mine(1, vec![payment]);
    assert_eq!(scan(&alice, &light), (1, 4_000));
    // More than the provider holds at the hub: refused, and the hub, which
    // would take it, not asked instead.
    let refused = invalid(alice.move_to_licash(light.clone()));
    assert!(refused.contains("takes at once (2999 sat"), "{refused}");
    assert!(net.sent().is_empty(), "{:?}", net.sent());
    assert!(alice
        .history()
        .unwrap()
        .iter()
        .all(|a| a.kind != Kind::Moved));
}

#[test]
fn a_phone_moves_a_coin_to_notes_through_a_provider_announced_before_its_hub() {
    let net = Net::new(true);
    let light = Light::new(&net);
    let provider = Depositing::start(&net);
    provider.announce(&net);
    let alice = net.wallet("alice", net.height());
    let code = alice.bitcoin_code(None).unwrap();
    let payment = net.pay_silent(&code.qr, 3_000, 1);
    net.mine(1, vec![payment]);
    assert_eq!(scan(&alice, &light), (1, 3_000));

    // Through the provider, though the hub takes deposits too: its fee of 1
    // and 200 for its claim's miners, not the hub's 100.
    let moving = alice.move_to_licash(light.clone()).unwrap();
    assert_eq!((moving.kind, moving.state), (Kind::Moved, State::Pending));
    assert_eq!(moving.fee, 201);
    let sent = net.sent();
    assert_eq!((sent.len(), sent[0].output.len()), (1, 1));
    let paid = OutPoint::new(sent[0].compute_txid(), 0);
    assert_eq!(sent[0].output[0].value.to_sat(), moving.amount + 201);
    assert_eq!(
        3_000 - moving.amount - 201,
        2 * sent[0].vsize() as u64,
        "the coin, whole"
    );

    // Confirmed at the provider's depth: found on scanning, told to the
    // provider on resuming, which locks its notes, claimed.
    net.confirm_sent();
    net.mine(1, Vec::new());
    assert_eq!(scan(&alice, &light), (0, 0));
    for _ in 0..50 {
        alice.resume().unwrap();
        if notes(&alice) > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert_eq!(notes(&alice), moving.amount);
    let history = alice.history().unwrap();
    let moved = history.iter().find(|a| a.id == moving.id).unwrap();
    assert_eq!(moved.state, State::Done, "{history:#?}");
    // Its details name the provider, and no depth of the hub's.
    match alice.details(Kind::Moved, moving.id.clone()).unwrap() {
        Details::Moved {
            provider: shown,
            depth,
            ..
        } => assert_eq!((shown, depth), (Some(provider.url.clone()), None)),
        other => panic!("{other:?}"),
    }
    // The provider sweeps the coin with the preimage the claim showed.
    let mut swept = false;
    for _ in 0..50 {
        let sent = net.sent();
        swept = sent
            .iter()
            .any(|tx| tx.input.iter().any(|i| i.previous_output == paid));
        if swept {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(swept, "{:?}", net.sent());
}
