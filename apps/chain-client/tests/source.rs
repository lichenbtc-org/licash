//! Both kinds of source against a mock node and a mock Esplora, serving
//! the same self-mined regtest chain.

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bitcoin::{
    absolute::LockTime,
    block::{Header, Version},
    consensus::{deserialize, serialize},
    hashes::Hash,
    pow::CompactTarget,
    transaction, Address, Amount, Block, BlockHash, FeeRate, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
};
use licash::{chain::Checkpoint, spend::ChainProfile};
use licash_chain_client::Source;
use serde_json::{json, Value};

/// `user:p@ss w` and `__cookie__:c00k1e`.
const PASSWORD: &str = "Basic dXNlcjpwQHNzIHc=";
const COOKIE: &str = "Basic X19jb29raWVfXzpjMDBrMWU=";

struct Chain {
    blocks: Vec<Block>,
    by_hash: HashMap<String, Block>,
    /// Every output of the chain.
    outputs: HashMap<OutPoint, TxOut>,
    auth: &'static str,
    /// The mempool.
    sent: std::sync::Mutex<Vec<Transaction>>,
}

/// Outputs of each coinbase, which the next block spends.
const COINBASE_OUTPUTS: u32 = 30;

/// A script of output `i` of the coinbase at `height`, of a key hash.
fn script(height: u32, i: u32) -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14, height as u8, i as u8];
    bytes.resize(22, 0xab);
    ScriptBuf::from_bytes(bytes)
}

/// Genesis and `n` blocks mined on it. From block 2, each spends outputs
/// of the coinbase before it, one or two at a time, and block 3 all of
/// them: a taproot output pays every other one.
fn mine(n: u32) -> Vec<Block> {
    let mut blocks = vec![bitcoin::constants::genesis_block(Network::Regtest)];
    for height in 1..=n {
        let previous = blocks.last().unwrap().header;
        let output = (0..COINBASE_OUTPUTS)
            .map(|i| TxOut {
                value: Amount::from_sat(50),
                script_pubkey: script(height, i),
            })
            .collect();
        let spent = match height {
            1 => 0,
            3 => COINBASE_OUTPUTS,
            _ => 2,
        };
        let spends = (0..spent).map(|i| Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: blocks.last().unwrap().txdata[0].compute_txid(),
                    vout: i,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(40),
                script_pubkey: match i % 2 {
                    0 => ScriptBuf::from_bytes([&[0x51, 0x20][..], &[i as u8; 32]].concat()),
                    _ => script(0, i),
                },
            }],
        });
        let coinbase = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, height as u8, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output,
        };
        let txdata = std::iter::once(coinbase).chain(spends).collect();
        blocks.push(seal(&previous, txdata));
    }
    blocks
}

/// The block of `txdata` after `previous`, mined.
fn seal(previous: &Header, txdata: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: previous.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: previous.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    while block.header.validate_pow(block.header.target()).is_err() {
        block.header.nonce += 1;
    }
    block
}

/// The inputs of a consolidation spending outputs 2 on of the coinbase of
/// the last of `blocks`: more than mempool's backend tells the spends of.
const CONSOLIDATED: u32 = COINBASE_OUTPUTS - 2;

/// `blocks` and one more: its coinbase, and a transaction spending outputs
/// 2 on of the last block's coinbase, which pays a taproot output.
fn consolidate(mut blocks: Vec<Block>) -> Vec<Block> {
    let previous = blocks.last().unwrap();
    let height = blocks.len() as u32;
    let coinbase = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, height as u8, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: script(height, 0),
        }],
    };
    let txid = previous.txdata[0].compute_txid();
    let consolidation = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: (2..COINBASE_OUTPUTS)
            .map(|vout| TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes([&[0x51, 0x20][..], &[7; 32]].concat()),
        }],
    };
    let block = seal(&previous.header, vec![coinbase, consolidation]);
    blocks.push(block);
    blocks
}

fn rpc_reply(result: Value) -> Response {
    Json(json!({"result": result, "error": null, "id": "licash"})).into_response()
}

fn rpc_error(code: i64, message: &str) -> Response {
    let body = json!({"result": null, "error": {"code": code, "message": message}, "id": "licash"});
    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}

async fn rpc(
    State(chain): State<Arc<Chain>>,
    headers: HeaderMap,
    Json(call): Json<Value>,
) -> Response {
    let authorized = headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(chain.auth);
    if !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let params = &call["params"];
    let by_hash = |i: usize| chain.by_hash.get(params[i].as_str().unwrap_or_default());
    match call["method"].as_str().unwrap_or_default() {
        "gettxout" => rpc_reply(Value::Null),
        "getblockchaininfo" => {
            let tip = chain.blocks.last().unwrap();
            rpc_reply(json!({
                "blocks": chain.blocks.len() - 1,
                "bestblockhash": tip.block_hash().to_string(),
            }))
        }
        "getblockhash" => match chain.blocks.get(params[0].as_u64().unwrap() as usize) {
            Some(block) => rpc_reply(json!(block.block_hash().to_string())),
            None => rpc_error(-8, "Block height out of range"),
        },
        "getblockheader" if params[1] == json!(false) => match by_hash(0) {
            Some(block) => rpc_reply(json!(hex::encode(serialize(&block.header)))),
            None => rpc_error(-5, "Block not found"),
        },
        "getblock" if params[1] == json!(0) => match by_hash(0) {
            Some(block) => rpc_reply(json!(hex::encode(serialize(block)))),
            None => rpc_error(-5, "Block not found"),
        },
        "getblock" if params[1] == json!(3) => match by_hash(0) {
            Some(block) => {
                let txs: Vec<Value> = block
                    .txdata
                    .iter()
                    .map(|tx| {
                        let vin: Vec<Value> = tx
                            .input
                            .iter()
                            .map(|input| match chain.outputs.get(&input.previous_output) {
                                Some(spent) => json!({"prevout": {
                                    "value": spent.value.to_btc(),
                                    "scriptPubKey": {"hex": spent.script_pubkey.to_hex_string()},
                                }}),
                                None => json!({"coinbase": "00"}),
                            })
                            .collect();
                        json!({"txid": tx.compute_txid().to_string(), "vin": vin})
                    })
                    .collect();
                rpc_reply(json!({"hash": block.block_hash().to_string(), "tx": txs}))
            }
            None => rpc_error(-5, "Block not found"),
        },
        "getblockfilter" if params[1] == json!("basic") => match by_hash(0) {
            Some(block) => {
                let spent = |o: &OutPoint| {
                    let found = chain.outputs.get(o).map(|t| t.script_pubkey.clone());
                    found.ok_or(bitcoin::bip158::Error::UtxoMissing(*o))
                };
                let filter = bitcoin::bip158::BlockFilter::new_script_filter(block, spent).unwrap();
                rpc_reply(json!({"filter": hex::encode(filter.content), "header": "00"}))
            }
            None => rpc_error(-5, "Block not found"),
        },
        "getmempoolentry" => {
            let sent = chain.sent.lock().unwrap();
            let txid = params[0].as_str().unwrap_or_default();
            match sent.iter().any(|tx| tx.compute_txid().to_string() == txid) {
                true => rpc_reply(json!({"vsize": 100})),
                false => rpc_error(-5, "Transaction not in mempool"),
            }
        }
        "sendrawtransaction" => match send(&chain, params[0].as_str().unwrap_or_default()) {
            Ok(txid) => rpc_reply(json!(txid)),
            Err((code, message)) => rpc_error(code, message),
        },
        "submitpackage" => match params[0].as_array() {
            Some(raws) => rpc_reply(send_package(&chain, raws)),
            None => rpc_error(-8, "package must be an array"),
        },
        "estimatesmartfee" => match params[0].as_u64() {
            Some(target @ 1..=144) => rpc_reply(json!({"feerate": 0.00012, "blocks": target})),
            // No fee, and one past any fee market.
            Some(200) => rpc_reply(json!({"feerate": -1, "blocks": 200})),
            Some(300) => rpc_reply(json!({"feerate": 0.0101, "blocks": 300})),
            _ => {
                rpc_reply(json!({"errors": ["Insufficient data or no feerate found"], "blocks": 0}))
            }
        },
        "scantxoutset" => {
            let descriptor = params[1][0]["desc"].as_str().unwrap_or_default();
            let address = descriptor
                .strip_prefix("addr(")
                .and_then(|d| d.strip_suffix(')'))
                .and_then(|a| a.parse::<Address<_>>().ok());
            let Some(address) = address else {
                return rpc_error(-5, "Invalid descriptor");
            };
            let script = address.assume_checked().script_pubkey();
            let found: Vec<Value> = unspent(&chain, &script)
                .into_iter()
                .map(|(o, out, height)| {
                    json!({"txid": o.txid.to_string(), "vout": o.vout, "amount": out.value.to_btc(),
                           "scriptPubKey": script.to_hex_string(), "height": height})
                })
                .collect();
            rpc_reply(json!({"success": true, "unspents": found}))
        }
        _ => rpc_error(-32601, "Method not found"),
    }
}

/// A node without a compact filter index.
async fn unindexed(
    state: State<Arc<Chain>>,
    headers: HeaderMap,
    Json(call): Json<Value>,
) -> Response {
    match call["method"].as_str() {
        Some("getblockfilter") => rpc_error(-1, "Index is not enabled for filtertype basic"),
        _ => rpc(state, headers, Json(call)).await,
    }
}

/// The outputs paying `script` that no block spends, with their heights.
fn unspent<'a>(chain: &'a Chain, script: &'a ScriptBuf) -> Vec<(OutPoint, &'a TxOut, u32)> {
    let spent: std::collections::HashSet<OutPoint> = chain
        .blocks
        .iter()
        .flat_map(|b| &b.txdata)
        .flat_map(|tx| tx.input.iter().map(|i| i.previous_output))
        .collect();
    let mut found = Vec::new();
    for (height, block) in (0u32..).zip(&chain.blocks) {
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            for (vout, output) in (0u32..).zip(&tx.output) {
                let outpoint = OutPoint { txid, vout };
                if output.script_pubkey == *script && !spent.contains(&outpoint) {
                    found.push((outpoint, output, height));
                }
            }
        }
    }
    found
}

/// Take `tx` into the mempool, as a node does, or why not. A transaction
/// locked to height 1 pays less than the mempool takes alone.
fn send(chain: &Chain, raw: &str) -> Result<String, (i64, &'static str)> {
    let tx = decode(raw)?;
    if tx.lock_time == LockTime::from_height(1).unwrap() {
        return Err((-26, "min relay fee not met"));
    }
    take(chain, tx)
}

fn decode(raw: &str) -> Result<Transaction, (i64, &'static str)> {
    hex::decode(raw)
        .ok()
        .and_then(|raw| deserialize(&raw).ok())
        .ok_or((-22, "TX decode failed"))
}

/// `submitpackage`'s answer: a child pays for its parents.
fn send_package(chain: &Chain, raws: &[Value]) -> Value {
    let txs: Result<Vec<Transaction>, _> = raws
        .iter()
        .map(|r| decode(r.as_str().unwrap_or_default()))
        .collect();
    let taken = txs.and_then(|txs| txs.into_iter().try_for_each(|tx| take(chain, tx).map(drop)));
    match taken {
        Ok(()) => json!({"package_msg": "success", "tx-results": {}}),
        Err((_, why)) => {
            json!({"package_msg": "transaction failed", "tx-results": {"x": {"error": why}}})
        }
    }
}

fn take(chain: &Chain, tx: Transaction) -> Result<String, (i64, &'static str)> {
    let txid = tx.compute_txid();
    let confirmed = chain.blocks.iter().flat_map(|b| &b.txdata);
    if confirmed.clone().any(|t| t.compute_txid() == txid) {
        return Err((-27, "Transaction outputs already in utxo set"));
    }
    let mut sent = chain.sent.lock().unwrap();
    if !sent.iter().any(|t| t.compute_txid() == txid) {
        let spends = confirmed.flat_map(|t| &t.input).map(|i| i.previous_output);
        let spent: Vec<OutPoint> = spends.collect();
        let pending = |o: &OutPoint| {
            sent.iter()
                .any(|t| t.compute_txid() == o.txid && (o.vout as usize) < t.output.len())
        };
        let spendable =
            |o: &OutPoint| (chain.outputs.contains_key(o) || pending(o)) && !spent.contains(o);
        if !tx.input.iter().all(|i| spendable(&i.previous_output)) {
            return Err((-25, "bad-txns-inputs-missingorspent"));
        }
        sent.push(tx);
    }
    Ok(txid.to_string())
}

async fn esplora_send(
    State(chain): State<Arc<Chain>>,
    headers: HeaderMap,
    raw: String,
) -> Response {
    // As mempool's backend: a body not sent as text/plain goes unread,
    // and Core is handed nothing.
    let plain = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/plain"));
    let sent = if plain {
        send(&chain, &raw)
    } else {
        Err((-1, ""))
    };
    match sent {
        Ok(txid) => txid.into_response(),
        Err((code, message)) => {
            let text = format!(
                "sendrawtransaction RPC error: {{\"code\":{code},\"message\":\"{message}\"}}"
            );
            (StatusCode::BAD_REQUEST, text).into_response()
        }
    }
}

async fn esplora_package(
    State(chain): State<Arc<Chain>>,
    Json(raws): Json<Vec<Value>>,
) -> Json<Value> {
    Json(send_package(&chain, &raws))
}

async fn esplora_fees() -> Json<Value> {
    // Past the tests' others: none, then one past any fee market.
    Json(json!({"1": 20.5, "6": 12.0, "144": 1.0, "2000": 0.0, "3000": 1010.0}))
}

async fn esplora_utxo(State(chain): State<Arc<Chain>>, Path(address): Path<String>) -> Response {
    let Ok(address) = address.parse::<Address<_>>() else {
        return (StatusCode::BAD_REQUEST, "Invalid Bitcoin address").into_response();
    };
    let script = address.assume_checked().script_pubkey();
    let mut found: Vec<Value> = unspent(&chain, &script)
        .into_iter()
        .map(|(o, out, height)| {
            let status = json!({"confirmed": true, "block_height": height});
            json!({"txid": o.txid.to_string(), "vout": o.vout, "value": out.value.to_sat(), "status": status})
        })
        .collect();
    // And those of the mempool, unconfirmed.
    for tx in chain.sent.lock().unwrap().iter() {
        for (vout, output) in (0u32..).zip(&tx.output) {
            if output.script_pubkey == script {
                let txid = tx.compute_txid().to_string();
                let status = json!({"confirmed": false});
                found.push(json!({"txid": txid, "vout": vout, "value": output.value.to_sat(), "status": status}));
            }
        }
    }
    Json(found).into_response()
}

async fn esplora_tip(State(chain): State<Arc<Chain>>) -> String {
    (chain.blocks.len() - 1).to_string()
}

/// Times the throttled Esplora was asked for its tip.
static THROTTLED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// An Esplora limiting its rate: the tip, once asked twice before.
async fn throttled_tip(State(chain): State<Arc<Chain>>) -> Response {
    match THROTTLED.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
        0 => (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "0")]).into_response(),
        1 => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        _ => esplora_tip(State(chain)).await.into_response(),
    }
}

/// One asking to be asked again only in an hour.
async fn refusing_tip() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, "3600")],
    )
        .into_response()
}

async fn esplora_hash(State(chain): State<Arc<Chain>>, Path(height): Path<usize>) -> Response {
    match chain.blocks.get(height) {
        Some(block) => block.block_hash().to_string().into_response(),
        None => (StatusCode::NOT_FOUND, "Block not found").into_response(),
    }
}

async fn esplora_block(
    State(chain): State<Arc<Chain>>,
    Path((hash, part)): Path<(String, String)>,
) -> Response {
    let Some(block) = chain.by_hash.get(&hash) else {
        return (StatusCode::NOT_FOUND, "Block not found").into_response();
    };
    match part.as_str() {
        "header" => hex::encode(serialize(&block.header)).into_response(),
        "raw" => serialize(block).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn esplora_txs(
    State(chain): State<Arc<Chain>>,
    Path((hash, start)): Path<(String, usize)>,
) -> Response {
    let Some(block) = chain.by_hash.get(&hash) else {
        return (StatusCode::NOT_FOUND, "Block not found").into_response();
    };
    if start % 25 != 0 || start >= block.txdata.len() {
        return (StatusCode::BAD_REQUEST, "start index out of range").into_response();
    }
    let txs: Vec<Value> = block.txdata[start..]
        .iter()
        .take(25)
        .map(|tx| esplora_json(&chain, tx, usize::MAX))
        .collect();
    Json(txs).into_response()
}

/// Inputs mempool's backend tells the spends of, in a block's pages.
const TOLD: usize = 13;

/// A block's transactions as mempool's backend serves them: ten from
/// `start`, and of each the spends of its first [`TOLD`] inputs only.
async fn mempool_txs(
    State(chain): State<Arc<Chain>>,
    Path((hash, start)): Path<(String, usize)>,
) -> Response {
    let Some(block) = chain.by_hash.get(&hash) else {
        return (StatusCode::NOT_FOUND, "Block not found").into_response();
    };
    let txs: Vec<Value> = block.txdata[start.min(block.txdata.len())..]
        .iter()
        .take(10)
        .map(|tx| esplora_json(&chain, tx, TOLD))
        .collect();
    Json(txs).into_response()
}

fn tx_of(chain: &Chain, txid: &str) -> Option<Transaction> {
    let mut txs = chain.blocks.iter().flat_map(|b| &b.txdata);
    txs.find(|tx| tx.compute_txid().to_string() == txid)
        .cloned()
}

/// A transaction with what each of its inputs spends.
async fn esplora_tx(State(chain): State<Arc<Chain>>, Path(txid): Path<String>) -> Response {
    match tx_of(&chain, &txid) {
        Some(tx) => Json(esplora_json(&chain, &tx, usize::MAX)).into_response(),
        None => (StatusCode::NOT_FOUND, "Transaction not found").into_response(),
    }
}

/// A transaction's status as Blockstream's electrs answers it: unconfirmed,
/// even for one it never saw.
async fn electrs_status() -> Json<Value> {
    Json(json!({"confirmed": false}))
}

/// [`esplora_tx`], telling as few spends as [`mempool_txs`].
async fn stingy_tx(State(chain): State<Arc<Chain>>, Path(txid): Path<String>) -> Response {
    match tx_of(&chain, &txid) {
        Some(tx) => Json(esplora_json(&chain, &tx, TOLD)).into_response(),
        None => (StatusCode::NOT_FOUND, "Transaction not found").into_response(),
    }
}

/// `tx` as Esplora tells it, with the spends of its first `told` inputs.
fn esplora_json(chain: &Chain, tx: &Transaction, told: usize) -> Value {
    let vin: Vec<Value> = tx
        .input
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let spent = chain.outputs.get(&input.previous_output);
            if i >= told && spent.is_some() {
                return json!({"is_coinbase": false, "prevout": null, "lazy": true});
            }
            json!({
                "is_coinbase": spent.is_none(),
                "prevout": spent.map(|o| json!({
                    "scriptpubkey": o.script_pubkey.to_hex_string(),
                    "value": o.value.to_sat(),
                })),
            })
        })
        .collect();
    json!({"txid": tx.compute_txid().to_string(), "vin": vin})
}

/// Serves `blocks` as a node at `/` and as Esplora under `/api`, with
/// `tampered` answering for a hash that is not its block's.
async fn serve(
    blocks: Vec<Block>,
    auth: &'static str,
    tampered: Option<(BlockHash, Block)>,
) -> String {
    let mut by_hash: HashMap<String, Block> = blocks
        .iter()
        .map(|b| (b.block_hash().to_string(), b.clone()))
        .collect();
    if let Some((hash, block)) = tampered {
        by_hash.insert(hash.to_string(), block);
    }
    let outputs = blocks
        .iter()
        .flat_map(|b| &b.txdata)
        .flat_map(|tx| {
            let txid = tx.compute_txid();
            (0..)
                .zip(tx.output.clone())
                .map(move |(vout, o)| (OutPoint { txid, vout }, o))
        })
        .collect();
    let chain = Arc::new(Chain {
        blocks,
        by_hash,
        outputs,
        auth,
        sent: Default::default(),
    });
    let app = Router::new()
        .route("/", post(rpc))
        .route("/unindexed", post(unindexed))
        .route("/api/blocks/tip/height", get(esplora_tip))
        .route("/api/block-height/{height}", get(esplora_hash))
        .route("/api/block/{hash}/{part}", get(esplora_block))
        .route("/api/block/{hash}/txs/{start}", get(esplora_txs))
        .route("/api/tx", post(esplora_send))
        .route("/api/tx/{txid}", get(esplora_tx))
        .route("/api/tx/{txid}/status", get(electrs_status))
        // mempool's backend, and one telling no more of a transaction alone.
        .route("/mempool/api/blocks/tip/height", get(esplora_tip))
        .route("/mempool/api/block-height/{height}", get(esplora_hash))
        .route("/mempool/api/block/{hash}/txs/{start}", get(mempool_txs))
        .route("/mempool/api/tx/{txid}", get(esplora_tx))
        .route("/stingy/api/block/{hash}/txs/{start}", get(mempool_txs))
        .route("/stingy/api/tx/{txid}", get(stingy_tx))
        .route("/throttled/api/blocks/tip/height", get(throttled_tip))
        .route("/throttled/api/block-height/{height}", get(esplora_hash))
        .route("/refusing/api/blocks/tip/height", get(refusing_tip))
        .route("/api/txs/package", post(esplora_package))
        .route("/api/fee-estimates", get(esplora_fees))
        .route("/api/address/{address}/utxo", get(esplora_utxo))
        // An Esplora taking no packages.
        .route("/old/tx", post(esplora_send))
        .with_state(chain);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    address.to_string()
}

fn sources(address: &str) -> [Source; 2] {
    [
        format!("http://user:p%40ss%20w@{address}").parse().unwrap(),
        format!("esplora+http://{address}/api/").parse().unwrap(),
    ]
}

#[tokio::test]
async fn a_node_and_esplora_read_the_same_chain() {
    let blocks = mine(12);
    let address = serve(blocks.clone(), PASSWORD, None).await;
    let mut commitments = Vec::new();
    for source in sources(&address) {
        let tip = source.tip().await.unwrap();
        assert_eq!(tip.height, 12, "{source}");
        assert_eq!(tip.hash, blocks[12].block_hash());
        assert_eq!(source.network().await.unwrap(), Network::Regtest);
        for (height, block) in blocks.iter().enumerate() {
            let hash = source.hash(height as u32).await.unwrap();
            assert_eq!(hash, block.block_hash());
            assert_eq!(source.header(&hash).await.unwrap(), block.header);
            assert_eq!(&source.block(&hash).await.unwrap(), block);
        }
        // Anchored at genesis, with fewer than eleven times, and at the tip.
        let genesis = source.checkpoint(0).await.unwrap();
        let expected = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
        assert_eq!(genesis.commitment(), expected.commitment());
        let early = source.checkpoint(4).await.unwrap();
        assert_eq!(
            (early.height(), early.header()),
            (4, &serialize(&blocks[4].header)[..].try_into().unwrap())
        );
        let checkpoint = source.checkpoint(12).await.unwrap();
        assert_eq!(checkpoint.profile(), ChainProfile::Core30DefaultRegtest);
        commitments.push(checkpoint.commitment());
    }
    assert_eq!(commitments[0], commitments[1]);
}

#[tokio::test]
async fn a_node_indexing_them_serves_compact_filters_esplora_none() {
    let blocks = mine(3);
    let address = serve(blocks.clone(), PASSWORD, None).await;
    let [node, esplora] = sources(&address);
    let unindexed: Source = format!("http://user:p%40ss%20w@{address}/unindexed")
        .parse()
        .unwrap();
    let elsewhere = ScriptBuf::from_bytes(vec![0x51; 34]);
    for block in &blocks {
        let hash = block.block_hash();
        let filter = node.filter(&hash).await.unwrap().unwrap();
        let filter = bitcoin::bip158::BlockFilter::new(&filter);
        let paid = block.txdata[0].output[0].script_pubkey.as_bytes();
        assert!(filter.match_any(&hash, std::iter::once(paid)).unwrap());
        let other = std::iter::once(elsewhere.as_bytes());
        assert!(!filter.match_any(&hash, other).unwrap());
        assert_eq!(esplora.filter(&hash).await.unwrap(), None);
        assert_eq!(unindexed.filter(&hash).await.unwrap(), None);
    }
    let unknown = node.filter(&BlockHash::all_zeros()).await.unwrap_err();
    assert!(
        format!("{unknown:#}").contains("Block not found"),
        "{unknown:#}"
    );
}

#[tokio::test]
async fn both_read_what_the_transactions_paying_taproot_outputs_spend() {
    let blocks = mine(4);
    let address = serve(blocks.clone(), PASSWORD, None).await;
    for source in sources(&address) {
        for (height, block) in (0u32..).zip(&blocks) {
            let spends = source.taproot_spends(block).await.unwrap();
            let expected: Vec<Option<Vec<ScriptBuf>>> = (0u32..)
                .zip(&block.txdata)
                .map(|(i, _)| match i {
                    // The coinbase, and those paying a key hash.
                    0 => None,
                    i if (i - 1) % 2 == 1 => None,
                    i => Some(vec![script(height - 1, i - 1)]),
                })
                .collect();
            assert_eq!(spends, expected, "{source}: block {height}");
        }
        // Spread over two of Esplora's pages.
        assert_eq!(blocks[3].txdata.len(), 31);
        // The source's transactions are not those of the block asked of.
        let mut forged = blocks[2].clone();
        forged.txdata.swap(1, 2);
        let error = source.taproot_spends(&forged).await.unwrap_err();
        assert!(format!("{error:#}").contains("are not its"), "{error:#}");
    }
}

#[tokio::test]
async fn esplora_asks_for_a_transaction_alone_what_its_page_leaves_out() {
    let blocks = consolidate(mine(4));
    let address = serve(blocks.clone(), PASSWORD, None).await;
    let [node, esplora] = sources(&address);
    let mempool: Source = format!("esplora+http://{address}/mempool/api")
        .parse()
        .unwrap();
    // Pages of ten of 31 transactions, and one of more inputs than told.
    assert_eq!(blocks[3].txdata.len(), 31);
    assert!(CONSOLIDATED as usize > TOLD);
    for block in &blocks[3..] {
        let expected = node.taproot_spends(block).await.unwrap();
        assert_eq!(esplora.taproot_spends(block).await.unwrap(), expected);
        assert_eq!(mempool.taproot_spends(block).await.unwrap(), expected);
    }
    let spent: Vec<ScriptBuf> = (2..COINBASE_OUTPUTS).map(|i| script(4, i)).collect();
    let spends = mempool.taproot_spends(&blocks[5]).await.unwrap();
    assert_eq!(spends, [None, Some(spent)]);
    // Told no more alone: refused, the transaction named, never passed over.
    let stingy: Source = format!("esplora+http://{address}/stingy/api")
        .parse()
        .unwrap();
    let error = stingy.taproot_spends(&blocks[5]).await.unwrap_err();
    let error = format!("{error:#}");
    let txid = blocks[5].txdata[1].compute_txid().to_string();
    assert!(
        error.contains("an input spends nothing") && error.contains(&txid),
        "{error}"
    );
}

#[tokio::test]
async fn both_broadcast_estimate_fees_and_find_what_pays_an_address() {
    let blocks = mine(4);
    let address = serve(blocks.clone(), PASSWORD, None).await;
    let to = |script: ScriptBuf| Address::from_script(&script, Network::Regtest).unwrap();
    let [node, esplora] = sources(&address);
    for source in [&node, &esplora] {
        // Paid by a transaction of each block from 2 on, never spent.
        let found = source.unspent(&to(script(0, 1))).await.unwrap();
        let heights: Vec<u32> = found.iter().map(|u| u.height).collect();
        assert_eq!(heights, [2, 3, 4], "{source}");
        assert!(found.iter().all(|u| u.value == Amount::from_sat(40)));
        // Spent by the next block.
        assert!(source.unspent(&to(script(1, 0))).await.unwrap().is_empty());
        let tip = source.unspent(&to(script(4, 5))).await.unwrap();
        let coinbase = blocks[4].txdata[0].compute_txid();
        assert_eq!(tip.len(), 1);
        assert_eq!(
            (tip[0].outpoint.txid, tip[0].outpoint.vout, tip[0].height),
            (coinbase, 5, 4)
        );
        assert_eq!(tip[0].value, Amount::from_sat(50));
    }

    // 12 sat/vB, or 3000 per thousand weight units.
    let twelve = FeeRate::from_sat_per_kwu(3000);
    assert_eq!(node.fee_rate(6).await.unwrap(), Some(twelve));
    assert_eq!(node.fee_rate(1008).await.unwrap(), None);
    assert_eq!(esplora.fee_rate(6).await.unwrap(), Some(twelve));
    // The latest estimate within the blocks asked, else the soonest.
    let soonest = FeeRate::from_sat_per_kwu(5125);
    assert_eq!(esplora.fee_rate(3).await.unwrap(), Some(soonest));
    assert_eq!(esplora.fee_rate(0).await.unwrap(), Some(soonest));
    assert_eq!(
        esplora.fee_rate(1000).await.unwrap(),
        Some(FeeRate::from_sat_per_kwu(250))
    );
    // An estimate of no fee is none, one past any fee market refused.
    assert_eq!(node.fee_rate(200).await.unwrap(), None);
    assert_eq!(
        esplora.fee_rate(2000).await.unwrap(),
        Some(FeeRate::from_sat_per_kwu(250))
    );
    for (source, blocks) in [(&node, 300), (&esplora, 3000)] {
        let refused = source.fee_rate(blocks).await.unwrap_err();
        assert!(
            format!("{refused:#}").contains("above 1000 sat/vB"),
            "{refused:#}"
        );
    }

    // A spend of the tip's coinbase, paying the address of many outputs.
    let spend = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase_of(&blocks, 4),
                vout: 7,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(45),
            script_pubkey: script(0, 1),
        }],
    };
    let txid = spend.compute_txid();
    for source in [&node, &esplora] {
        // Again, or once it is in a block: no error.
        assert_eq!(source.broadcast(&spend).await.unwrap(), txid, "{source}");
        let mined = &blocks[3].txdata[1];
        assert_eq!(source.broadcast(mined).await.unwrap(), mined.compute_txid());
        let mut missing = spend.clone();
        missing.input[0].previous_output.vout = 99;
        let error = format!("{:#}", source.broadcast(&missing).await.unwrap_err());
        assert!(error.contains("bad-txns-inputs-missingorspent"), "{error}");
    }
    // Unconfirmed, it pays the address nothing yet.
    assert_eq!(esplora.unspent(&to(script(0, 1))).await.unwrap().len(), 3);
}

/// A spend of `coin`, paying `value` to a key hash.
fn spending(coin: OutPoint, value: u64, lock_time: LockTime) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: coin,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script(0, 2),
        }],
    }
}

#[tokio::test]
async fn a_parent_below_the_mempools_floor_relays_with_its_child_as_a_package() {
    let blocks = mine(4);
    let address = serve(blocks.clone(), PASSWORD, None).await;
    let [node, esplora] = sources(&address);
    let low = LockTime::from_height(1).unwrap();
    for (vout, source) in [(10, &node), (11, &esplora)] {
        let coin = OutPoint {
            txid: coinbase_of(&blocks, 4),
            vout,
        };
        let parent = spending(coin, 45, low);
        let child = spending(
            OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            30,
            LockTime::ZERO,
        );
        let alone = format!("{:#}", source.broadcast(&parent).await.unwrap_err());
        assert!(alone.contains("min relay fee not met"), "{source}: {alone}");
        let ids = source
            .broadcast_package(&[parent.clone(), child.clone()])
            .await
            .unwrap();
        assert_eq!(
            ids,
            [parent.compute_txid(), child.compute_txid()],
            "{source}"
        );
        // Again: both known.
        source.broadcast_package(&[parent, child]).await.unwrap();
    }
    // An Esplora taking no packages: each in turn, the parent refused.
    let old: Source = format!("esplora+http://{address}/old/").parse().unwrap();
    let coin = OutPoint {
        txid: coinbase_of(&blocks, 4),
        vout: 12,
    };
    let parent = spending(coin, 45, low);
    let child = spending(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        30,
        LockTime::ZERO,
    );
    let refused = format!(
        "{:#}",
        old.broadcast_package(&[parent, child]).await.unwrap_err()
    );
    assert!(refused.contains("min relay fee not met"), "{refused}");
    // One paying its way: in turn, the child after it.
    let parent = spending(coin, 45, LockTime::ZERO);
    let child = spending(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        30,
        LockTime::ZERO,
    );
    let ids = old
        .broadcast_package(&[parent.clone(), child.clone()])
        .await
        .unwrap();
    assert_eq!(ids, [parent.compute_txid(), child.compute_txid()]);
}

fn coinbase_of(blocks: &[Block], height: usize) -> bitcoin::Txid {
    blocks[height].txdata[0].compute_txid()
}

#[tokio::test]
async fn a_block_or_header_that_is_not_the_one_asked_for_is_refused() {
    let blocks = mine(3);
    let claimed = blocks[2].block_hash();
    let address = serve(blocks.clone(), PASSWORD, Some((claimed, blocks[3].clone()))).await;
    // The tampered entry replaced block 2 under its own hash.
    for source in sources(&address) {
        let header = source.header(&claimed).await.unwrap_err().to_string();
        assert!(header.contains("does not hash to itself"), "{header}");
        let block = source.block(&claimed).await.unwrap_err().to_string();
        assert!(block.contains("does not hash to itself"), "{block}");
    }
}

#[tokio::test]
async fn a_null_rpc_result_is_optional_only_when_the_caller_asks_for_it() {
    let address = serve(mine(1), PASSWORD, None).await;
    let [node, esplora] = sources(&address);
    let coin = node
        .rpc_optional::<Value>("gettxout", json!(["missing", 0, false]))
        .await
        .unwrap();
    assert_eq!(coin, None);
    // Preserve the non-null call's previous error contract.
    assert!(node
        .rpc::<Value>("gettxout", json!([]))
        .await
        .unwrap_err()
        .to_string()
        .contains("no result"));
    assert!(node
        .rpc_optional::<Value>("not_a_method", json!([]))
        .await
        .is_err());
    assert!(esplora
        .rpc_optional::<Value>("gettxout", json!([]))
        .await
        .is_err());
    let tip = node
        .rpc_optional::<Value>("getblockchaininfo", json!([]))
        .await
        .unwrap();
    assert!(tip.is_some());
}

#[tokio::test]
async fn node_errors_and_missing_blocks_are_reported() {
    let address = serve(mine(2), PASSWORD, None).await;
    let [node, esplora] = sources(&address);
    let error = node.hash(99).await.unwrap_err().to_string();
    assert!(
        error.contains("getblockhash: Block height out of range (-8)"),
        "{error}"
    );
    let error = esplora.hash(99).await.unwrap_err().to_string();
    assert!(error.contains("HTTP 404"), "{error}");
    let missing = BlockHash::all_zeros();
    assert!(node
        .block(&missing)
        .await
        .unwrap_err()
        .to_string()
        .contains("Block not found"));
    assert!(esplora.block(&missing).await.is_err());
}

#[tokio::test]
async fn credentials_authenticate_and_never_show() {
    let address = serve(mine(1), PASSWORD, None).await;
    let [node, _] = sources(&address);
    assert_eq!(node.to_string(), format!("http://{address}"));
    assert_eq!(format!("{node:?}"), format!("Source(http://{address})"));
    node.tip().await.unwrap();
    let wrong: Source = format!("http://user:nope@{address}/").parse().unwrap();
    let error = wrong.tip().await.unwrap_err().to_string();
    assert!(
        error.contains("unauthorized") && !error.contains("nope"),
        "{error}"
    );
    let anonymous: Source = format!("http://{address}").parse().unwrap();
    assert!(anonymous.tip().await.is_err());
}

#[tokio::test]
async fn a_cookie_file_is_read_on_each_call() {
    let address = serve(mine(1), COOKIE, None).await;
    let dir = tempfile::tempdir().unwrap();
    let cookie = dir.path().join(".cookie");
    let node: Source = format!("http://{address}?cookie={}", cookie.display())
        .parse()
        .unwrap();
    assert_eq!(node.to_string(), format!("http://{address}"));
    let error = node.tip().await.unwrap_err().to_string();
    assert!(error.contains(".cookie"), "{error}");
    std::fs::write(&cookie, "__cookie__:stale").unwrap();
    assert!(node.tip().await.is_err());
    // The node restarted and wrote a new cookie.
    std::fs::write(&cookie, "__cookie__:c00k1e\n").unwrap();
    assert_eq!(node.tip().await.unwrap().height, 1);
}

#[test]
fn urls_are_checked() {
    for bad in [
        "ftp://host:1",
        "localhost:8332",
        "http://u:p@host:1?cookie=/c",
        "http://host:1?wallet=w",
        "http://host:1?cookie=/a&cookie=/b",
        "esplora+https://u:p@host/api",
        "esplora+https://host/api?x=1",
        "esplora+https:///api",
    ] {
        assert!(bad.parse::<Source>().is_err(), "{bad}");
    }
    let esplora: Source = "esplora+https://esplora.example/api/".parse().unwrap();
    assert_eq!(esplora.to_string(), "esplora+https://esplora.example/api");
}

/// As mempool's backend answers a transaction it has in a block, or one
/// spending what it does not know: by the node's code alone.
async fn mempool_send(State(confirmed): State<Arc<Vec<String>>>, raw: String) -> Response {
    let code = match confirmed.contains(&raw) {
        true => -27,
        false => -25,
    };
    let error = format!("sendrawtransaction RPC error: {{\"code\":{code}}}");
    (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response()
}

#[tokio::test]
async fn mempools_backend_is_read_as_esplora() {
    let blocks = mine(2);
    let confirmed = blocks[2].txdata[1].clone();
    let elsewhere = Transaction {
        input: vec![TxIn::default()],
        ..confirmed.clone()
    };
    let raw = vec![hex::encode(serialize(&confirmed))];
    let fees =
        json!({"fastestFee": 5, "halfHourFee": 4, "hourFee": 3, "economyFee": 2, "minimumFee": 1});
    let app = Router::new()
        .route("/api/tx", post(mempool_send))
        .route(
            "/api/v1/fees/recommended",
            get(move || async move { Json(fees) }),
        )
        .with_state(Arc::new(raw));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let source: Source = format!("esplora+http://{address}/api").parse().unwrap();

    // It has it in a block: no error.
    assert_eq!(
        source.broadcast(&confirmed).await.unwrap(),
        confirmed.compute_txid()
    );
    let refused = source.broadcast(&elsewhere).await.unwrap_err();
    assert!(format!("{refused:#}").contains("-25"), "{refused:#}");
    // No fee-estimates: what it recommends instead.
    for (blocks, rate) in [(1, 5), (3, 4), (6, 3), (144, 2)] {
        let estimate = source.fee_rate(blocks).await.unwrap();
        assert_eq!(
            estimate,
            Some(FeeRate::from_sat_per_vb_u32(rate)),
            "{blocks}"
        );
    }
}

#[tokio::test]
async fn an_esplora_limiting_its_rate_is_asked_again_as_it_tells() {
    let blocks = mine(4);
    let address = serve(blocks.clone(), PASSWORD, None).await;
    let throttled: Source = format!("esplora+http://{address}/throttled/api")
        .parse()
        .unwrap();
    // Refused (429, asked again at once), overloaded (503, asked again a
    // while later), then the tip.
    let started = std::time::Instant::now();
    let tip = throttled.tip().await.unwrap();
    assert_eq!(tip.height as usize, blocks.len() - 1);
    assert_eq!(tip.hash, blocks.last().unwrap().block_hash());
    assert_eq!(THROTTLED.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    // Asked to wait longer than it is waited on: refused at once.
    let refusing: Source = format!("esplora+http://{address}/refusing/api")
        .parse()
        .unwrap();
    let started = std::time::Instant::now();
    let error = format!("{:#}", refusing.tip().await.unwrap_err());
    assert!(error.contains("429"), "{error}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[tokio::test]
async fn a_node_tells_what_its_mempool_holds_and_esplora_what_it_ever_saw() {
    let blocks = mine(4);
    let address = serve(blocks.clone(), PASSWORD, None).await;
    let [node, esplora] = sources(&address);
    let unknown = bitcoin::Txid::from_byte_array([7; 32]);
    let mined = blocks[2].txdata[0].compute_txid();
    // In a block: no longer in the node's mempool; Esplora knows it.
    assert!(!node.holds(&mined).await.unwrap());
    assert!(esplora.holds(&mined).await.unwrap());
    // Never seen: by neither, though electrs calls its status unconfirmed.
    assert!(!node.holds(&unknown).await.unwrap());
    assert!(!esplora.holds(&unknown).await.unwrap());
    // Handed to the node: in its mempool.
    let spend = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase_of(&blocks, 4),
                vout: 7,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(45),
            script_pubkey: script(0, 1),
        }],
    };
    let txid = node.broadcast(&spend).await.unwrap();
    assert!(node.holds(&txid).await.unwrap());
}
