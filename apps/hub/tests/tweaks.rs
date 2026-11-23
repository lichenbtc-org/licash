//! The hub's index of silent payment tweaks, over a mock Esplora, and its
//! endpoint.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use bitcoin::{
    absolute::LockTime, consensus::serialize, key::TweakedPublicKey, secp256k1::SecretKey,
    transaction, Amount, CompressedPublicKey, NetworkKind, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use http_body_util::BodyExt;
use licash::spend::ChainProfile;
use licash_api::{BlockTweaks, Code, Info, Problem};
use licash_chain_client::Source;
use licash_hub::{Hub, Policy};
use licash_hub_service::{
    tweaks::{step, Tweaks},
    Services, IMMUTABLE_DEPTH,
};
use licash_onchain::silent::{self, Keys};
use serde_json::{json, Value};
use tower::ServiceExt;

mod chain;

/// A chain, and the scripts of outputs its blocks spend but never made.
struct Backend {
    chain: chain::Chain,
    spent: HashMap<OutPoint, ScriptBuf>,
    /// Serving a block's transactions as mempool's backend: ten a page,
    /// and of each the spends of its first [`TOLD`] inputs only.
    mempool: bool,
    /// The blocks asked for whole.
    fetched: usize,
}

/// Inputs mempool's backend tells the spends of, in a block's pages.
const TOLD: usize = 13;

type Shared = Arc<Mutex<Backend>>;

async fn tip(State(backend): State<Shared>) -> String {
    backend.lock().unwrap().chain.height().to_string()
}

async fn hash(State(backend): State<Shared>, Path(height): Path<usize>) -> Response {
    match backend.lock().unwrap().chain.blocks.get(height) {
        Some(block) => block.block_hash().to_string().into_response(),
        None => (StatusCode::NOT_FOUND, "Block not found").into_response(),
    }
}

fn find(backend: &Backend, hash: &str) -> Option<bitcoin::Block> {
    let blocks = &backend.chain.blocks;
    blocks
        .iter()
        .find(|b| b.block_hash().to_string() == hash)
        .cloned()
}

async fn block(
    State(backend): State<Shared>,
    Path((hash, part)): Path<(String, String)>,
) -> Response {
    let mut backend = backend.lock().unwrap();
    match (find(&backend, &hash), part.as_str()) {
        (Some(block), "header") => hex::encode(serialize(&block.header)).into_response(),
        (Some(block), "raw") => {
            backend.fetched += 1;
            serialize(&block).into_response()
        }
        _ => (StatusCode::NOT_FOUND, "Block not found").into_response(),
    }
}

async fn txs(
    State(backend): State<Shared>,
    Path((hash, start)): Path<(String, usize)>,
) -> Response {
    let backend = backend.lock().unwrap();
    let Some(block) = find(&backend, &hash) else {
        return (StatusCode::NOT_FOUND, "Block not found").into_response();
    };
    let (count, told) = match backend.mempool {
        true => (10, TOLD),
        false => (25, usize::MAX),
    };
    let page: Vec<Value> = block.txdata[start..]
        .iter()
        .take(count)
        .map(|tx| esplora_json(&backend, tx, told))
        .collect();
    Json(page).into_response()
}

/// A transaction alone, what each of its inputs spends with it.
async fn tx(State(backend): State<Shared>, Path(txid): Path<String>) -> Response {
    let backend = backend.lock().unwrap();
    let mut txs = backend.chain.blocks.iter().flat_map(|b| &b.txdata);
    match txs.find(|tx| tx.compute_txid().to_string() == txid) {
        Some(tx) => Json(esplora_json(&backend, tx, usize::MAX)).into_response(),
        None => (StatusCode::NOT_FOUND, "Transaction not found").into_response(),
    }
}

/// `tx` as Esplora tells it, with the spends of its first `told` inputs.
fn esplora_json(backend: &Backend, tx: &Transaction, told: usize) -> Value {
    let vin: Vec<Value> = (tx.input.iter().enumerate())
        .map(
            |(i, input)| match backend.spent.get(&input.previous_output) {
                Some(_) if i >= told => json!({"prevout": null, "lazy": true}),
                spent => {
                    json!({"prevout": spent.map(|s| json!({"scriptpubkey": s.to_hex_string()}))})
                }
            },
        )
        .collect();
    json!({"txid": tx.compute_txid().to_string(), "vin": vin})
}

async fn esplora(backend: Shared) -> Source {
    let app = Router::new()
        .route("/api/blocks/tip/height", get(tip))
        .route("/api/block-height/{height}", get(hash))
        .route("/api/block/{hash}/{part}", get(block))
        .route("/api/block/{hash}/txs/{start}", get(txs))
        .route("/api/tx/{txid}", get(tx))
        .with_state(backend);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("esplora+http://{address}/api").parse().unwrap()
}

/// A transaction spending a P2WPKH output of `secret`, which `backend`
/// knows the script of, paying `pays`.
fn spending(backend: &Shared, secret: &SecretKey, vout: u32, pays: Vec<ScriptBuf>) -> Transaction {
    spending_all(backend, secret, vout..vout + 1, pays)
}

/// [`spending`] the outputs `vouts`, each an input.
fn spending_all(
    backend: &Shared,
    secret: &SecretKey,
    vouts: std::ops::Range<u32>,
    pays: Vec<ScriptBuf>,
) -> Transaction {
    let secp = bitcoin::key::Secp256k1::new();
    let key = CompressedPublicKey(secret.public_key(&secp));
    let script = ScriptBuf::new_p2wpkh(&key.wpubkey_hash());
    let mut witness = Witness::new();
    witness.push([0x30; 71]);
    witness.push(key.to_bytes());
    let input = vouts
        .map(|vout| {
            let previous_output = OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([9; 32])),
                vout,
            };
            let spent = &mut backend.lock().unwrap().spent;
            spent.insert(previous_output, script.clone());
            TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: witness.clone(),
            }
        })
        .collect();
    Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output: pays
            .into_iter()
            .map(|script_pubkey| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey,
            })
            .collect(),
    }
}

fn hub(dir: &std::path::Path) -> Arc<Hub> {
    std::fs::create_dir_all(dir).unwrap();
    let (seed, db) = (dir.join("seed"), dir.join("hub.sqlite"));
    Hub::init(&seed, &db, 6).unwrap();
    Arc::new(Hub::open(&seed, &db, Policy::default()).unwrap())
}

/// The status, cache header and body of `GET path`.
async fn get_from(app: &Router, path: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let request = Request::get(path).body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, cache, body.to_vec())
}

#[tokio::test]
async fn the_hub_indexes_and_serves_the_tweaks_of_its_chain() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Shared = Arc::new(Mutex::new(Backend {
        chain: chain::Chain::new(),
        spent: HashMap::new(),
        mempool: false,
        fetched: 0,
    }));
    for _ in 0..3 {
        backend.lock().unwrap().chain.mine(None);
    }
    let source = esplora(backend.clone()).await;
    let path = dir.path().join("tweaks.sqlite");
    let index = Arc::new(Tweaks::open(&path).unwrap());
    assert_eq!(index.first().unwrap(), None);

    // A new index starts at the tip.
    step(&index, &source, None).await.unwrap();
    assert_eq!(index.first().unwrap(), Some(3));

    // A silent payment, and transactions that cannot be one.
    let receiver = Keys::from_seed(&[1; 32], NetworkKind::Test).unwrap();
    let sender = SecretKey::from_slice(&[2; 32]).unwrap();
    let outpoint = |vout| OutPoint {
        txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([9; 32])),
        vout,
    };
    let paid = silent::outputs(&[(sender, false)], &[outpoint(0)], &[receiver.address()]).unwrap();
    let taproot = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(paid[0]));
    let payment = spending(&backend, &sender, 0, vec![taproot]);
    let no_taproot = spending(&backend, &sender, 1, vec![ScriptBuf::new_op_return([1])]);
    backend
        .lock()
        .unwrap()
        .chain
        .mine_with(None, vec![payment.clone(), no_taproot]);
    step(&index, &source, None).await.unwrap();
    let blocks = index.blocks(3, 2).unwrap();
    assert_eq!(blocks.iter().map(|b| b.height).collect::<Vec<_>>(), [3, 4]);
    assert!(blocks[0].tweaks.is_empty());
    let prevout = backend.lock().unwrap().spent[&outpoint(0)].clone();
    let tweak = silent::tweak(&payment, &[&prevout]).unwrap();
    assert_eq!(blocks[1].tweaks.len(), 1);
    assert_eq!(blocks[1].tweaks[0].0, tweak.serialize());
    let found = receiver
        .scanner([])
        .scan(&tweak, &silent::taproot_outputs(&payment));
    assert_eq!(found.len(), 1);

    // Served, and advertised.
    let app = licash_hub_service::router(
        hub(dir.path()),
        Services {
            tweaks: Some(index.clone()),
            ..Default::default()
        },
    );
    let (status, cache, body) = get_from(&app, "/v1/chain/tweaks?from=3&count=5").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("no-cache"));
    let served: Vec<BlockTweaks> = serde_json::from_slice(&body).unwrap();
    assert_eq!(served, blocks);
    let chain = backend.lock().unwrap().chain.blocks.clone();
    assert_eq!(served[1].hash, chain[4].block_hash().to_string());
    let (_, _, info) = get_from(&app, licash_api::INFO).await;
    let info: Info = serde_json::from_slice(&info).unwrap();
    assert_eq!(info.tweaks, Some(3));
    for bad in [
        "/v1/chain/tweaks?from=2&count=1",
        "/v1/chain/tweaks?from=3&count=0",
        "/v1/chain/tweaks?from=3&count=145",
        "/v1/chain/tweaks?from=3",
        "/v1/chain/tweaks?from=x&count=1",
    ] {
        let (status, _, body) = get_from(&app, bad).await;
        let problem: Problem = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            (status, problem.code),
            (StatusCode::BAD_REQUEST, Code::Invalid),
            "{bad}"
        );
    }

    // A reorganization replaces the blocks that left the best chain.
    {
        let mut backend = backend.lock().unwrap();
        backend.chain.blocks.truncate(4);
        backend.chain.mine(None);
        backend.chain.mine(None);
    }
    step(&index, &source, None).await.unwrap();
    let chain = backend.lock().unwrap().chain.blocks.clone();
    let blocks = index.blocks(3, 10).unwrap();
    let hashes: Vec<String> = chain[3..]
        .iter()
        .map(|b| b.block_hash().to_string())
        .collect();
    assert_eq!(
        blocks.iter().map(|b| b.hash.clone()).collect::<Vec<_>>(),
        hashes
    );
    assert!(blocks.iter().all(|b| b.tweaks.is_empty()));

    // Reopened, it keeps its first block, whatever else is asked.
    drop(app);
    let reopened = Tweaks::open(&path).unwrap();
    step(&reopened, &source, Some(1)).await.unwrap();
    assert_eq!(reopened.first().unwrap(), Some(3));

    // Ranges buried deep enough are answered as never changing.
    for _ in 0..IMMUTABLE_DEPTH {
        backend.lock().unwrap().chain.mine(None);
    }
    step(&index, &source, None).await.unwrap();
    let app = licash_hub_service::router(
        hub(&dir.path().join("other")),
        Services {
            tweaks: Some(index.clone()),
            ..Default::default()
        },
    );
    let (_, cache, _) = get_from(&app, "/v1/chain/tweaks?from=3&count=2").await;
    assert_eq!(
        cache.as_deref(),
        Some("public, max-age=31536000, immutable")
    );
    let (_, cache, _) = get_from(&app, "/v1/chain/tweaks?from=3&count=144").await;
    assert_eq!(cache.as_deref(), Some("no-cache"));
}

/// Block 3607161 of Mutinynet, which mempool's backend served the spends
/// of 13 of its consolidation's 100 inputs of: indexed all the same.
#[tokio::test]
async fn the_index_reads_alone_a_transaction_whose_page_tells_part_of_its_spends() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Shared = Arc::new(Mutex::new(Backend {
        chain: chain::Chain::new(),
        spent: HashMap::new(),
        mempool: true,
        fetched: 0,
    }));
    backend.lock().unwrap().chain.mine(None);
    let source = esplora(backend.clone()).await;
    let index = Tweaks::open(&dir.path().join("tweaks.sqlite")).unwrap();
    step(&index, &source, None).await.unwrap();

    // A silent payment spending 100 coins, among more than a page holds.
    let receiver = Keys::from_seed(&[1; 32], NetworkKind::Test).unwrap();
    let sender = SecretKey::from_slice(&[2; 32]).unwrap();
    let outpoints: Vec<OutPoint> = (0..100)
        .map(|vout| OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([9; 32])),
            vout,
        })
        .collect();
    let keys = vec![(sender, false); outpoints.len()];
    let paid = silent::outputs(&keys, &outpoints, &[receiver.address()]).unwrap();
    let taproot = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(paid[0]));
    let payment = spending_all(&backend, &sender, 0..100, vec![taproot]);
    let others = (100..111)
        .map(|vout| spending(&backend, &sender, vout, vec![ScriptBuf::new_op_return([1])]));
    // And one past the page.
    let past = spending(
        &backend,
        &sender,
        111,
        vec![ScriptBuf::new_p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(paid[0]),
        )],
    );
    let txs = std::iter::once(payment.clone())
        .chain(others)
        .chain([past.clone()])
        .collect();
    backend.lock().unwrap().chain.mine_with(None, txs);
    step(&index, &source, None).await.unwrap();

    let blocks = index.blocks(2, 1).unwrap();
    let spent = backend.lock().unwrap().spent.clone();
    let tweak_of = |tx: &Transaction| {
        let prevouts: Vec<&bitcoin::Script> = (tx.input.iter())
            .map(|i| spent[&i.previous_output].as_script())
            .collect();
        silent::tweak(tx, &prevouts).unwrap()
    };
    let tweak = tweak_of(&payment);
    assert_eq!(blocks[0].height, 2);
    assert_eq!(
        blocks[0]
            .tweaks
            .iter()
            .map(|t| t.0.clone())
            .collect::<Vec<_>>(),
        [
            tweak.serialize().to_vec(),
            tweak_of(&past).serialize().to_vec()
        ]
    );
    let found = receiver
        .scanner([])
        .scan(&tweak, &silent::taproot_outputs(&payment));
    assert_eq!(found.len(), 1);
}

/// A block no source tells the spends of fails each round: the index
/// waits longer after each, asking for it a handful of times rather than
/// once a round, and moves on once it is told.
#[tokio::test]
async fn an_index_failing_on_a_block_asks_for_it_less_and_less() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Shared = Arc::new(Mutex::new(Backend {
        chain: chain::Chain::new(),
        spent: HashMap::new(),
        mempool: false,
        fetched: 0,
    }));
    backend.lock().unwrap().chain.mine(None);
    let source = esplora(backend.clone()).await;
    let index = Arc::new(Tweaks::open(&dir.path().join("tweaks.sqlite")).unwrap());
    step(&index, &source, None).await.unwrap();
    let sender = SecretKey::from_slice(&[2; 32]).unwrap();
    let taproot = ScriptBuf::from_bytes([&[0x51, 0x20][..], &[7; 32]].concat());
    let payment = spending(&backend, &sender, 1, vec![taproot]);
    // What it spends, unknown.
    let unknown = payment.input[0].previous_output;
    let told = backend.lock().unwrap().spent.remove(&unknown).unwrap();
    backend.lock().unwrap().chain.mine_with(None, vec![payment]);
    backend.lock().unwrap().fetched = 0;

    let every = std::time::Duration::from_millis(20);
    let indexing = tokio::spawn(licash_hub_service::tweaks::index(
        index.clone(),
        source.clone(),
        ChainProfile::Core30DefaultRegtest,
        None,
        every,
        |_: &str| {},
    ));
    // At 20, 40, 80, 160, 320 and 640 ms: 7 rounds in 1.5 s, not 75.
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    let fetched = backend.lock().unwrap().fetched;
    assert!((3..=10).contains(&fetched), "{fetched} rounds");
    assert_eq!(index.top().unwrap().map(|(h, _)| h), Some(1));

    // Told: indexed at the next round, within the longest wait yet.
    backend.lock().unwrap().spent.insert(unknown, told);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while index.top().unwrap().map(|(h, _)| h) != Some(2) {
        assert!(std::time::Instant::now() < deadline, "never indexed");
        tokio::time::sleep(every).await;
    }
    indexing.abort();
}

#[tokio::test]
async fn an_index_starts_where_asked_and_only_in_its_own_file() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Shared = Arc::new(Mutex::new(Backend {
        chain: chain::Chain::new(),
        spent: HashMap::new(),
        mempool: false,
        fetched: 0,
    }));
    for _ in 0..5 {
        backend.lock().unwrap().chain.mine(None);
    }
    let source = esplora(backend.clone()).await;
    let index = Tweaks::open(&dir.path().join("tweaks.sqlite")).unwrap();
    step(&index, &source, Some(2)).await.unwrap();
    let heights: Vec<u32> = index
        .blocks(0, 10)
        .unwrap()
        .iter()
        .map(|b| b.height)
        .collect();
    assert_eq!(heights, [2, 3, 4, 5]);
    // Beyond the tip: nothing yet.
    let later = Tweaks::open(&dir.path().join("later.sqlite")).unwrap();
    step(&later, &source, Some(9)).await.unwrap();
    assert_eq!(later.first().unwrap(), Some(9));
    assert!(later.top().unwrap().is_none());

    // Nor of another network's chain.
    let mainnet = Arc::new(Tweaks::open(&dir.path().join("mainnet.sqlite")).unwrap());
    let indexing = licash_hub_service::tweaks::index(
        mainnet.clone(),
        source.clone(),
        ChainProfile::Core30Mainnet,
        None,
        std::time::Duration::from_millis(10),
        |_: &str| {},
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), indexing)
        .await
        .unwrap();
    assert_eq!(mainnet.first().unwrap(), None);

    // Not an index: refused.
    let other = dir.path().join("other.sqlite");
    let conn = rusqlite::Connection::open(&other).unwrap();
    conn.execute_batch("CREATE TABLE t (x)").unwrap();
    drop(conn);
    let error = Tweaks::open(&other).err().unwrap().to_string();
    assert!(error.contains("not a tweak index"), "{error}");

    // A hub not indexing serves no tweaks, and says so.
    let app = licash_hub_service::router(hub(dir.path()), Services::default());
    let (status, _, _) = get_from(&app, "/v1/chain/tweaks?from=2&count=1").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, _, info) = get_from(&app, licash_api::INFO).await;
    let info: Info = serde_json::from_slice(&info).unwrap();
    assert_eq!(info.tweaks, None);
}
