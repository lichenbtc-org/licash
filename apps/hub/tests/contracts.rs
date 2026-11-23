//! Contracts opened between a wallet and the hub service over HTTP, on a
//! regtest node whose wallet funds F: under the mock authority, so they
//! protect nothing. Needs `bitcoind` (`LICHEN_BITCOIND`, as
//! `regtest/run.sh` sets it) and a release build, as the openings build
//! and check their garbled instances: `regtest/run.sh` from the
//! repository root.

use std::path::Path;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use bitcoin::Amount;
use licash::recovery::Format;
use licash::spend::ChainProfile;
use licash_chain_client::Source;
use licash_contracts::holder::{self, Ask, Contract, Fate, Node, Phase};
use licash_contracts::hub::terms::Range;
use licash_contracts::hub::Openings;
use licash_hub::{Hub, Policy};
use licash_hub_service::{deposit, watch, Services};
use licash_transport::Http;
use licash_wallet::{Transport as _, Wallet};
use lichen_btc::regtest::Regtest;

/// Whether the wallet's file at `wallet` holds the holder's contracts: made
/// with the first contract opened, and by no reading of them.
fn holds_contracts(wallet: &std::path::Path) -> Result<bool> {
    let db = rusqlite::Connection::open(wallet)?;
    let n: i64 = db.query_row(
        "SELECT count(*) FROM schema_versions WHERE component = 'contracts'",
        [],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// A hub service opening contracts, funded by `rt`'s wallet: its URL.
async fn hub(rt: &Regtest, dir: &Path) -> Result<(String, Source)> {
    hub_with(rt, dir, None).await
}

/// The hub's deposits, which every contract's reserve returns to, scanning
/// the chain of `source` and bound to the contracts in `openings`.
fn deposits_for(
    hub: &Arc<Hub>,
    source: &Source,
    dir: &Path,
    openings: &Openings,
) -> Result<Arc<deposit::Gateway>> {
    let config = deposit::Config {
        max: 2_000_000,
        ..deposit::Config::new(bitcoin::ScriptBuf::new_op_return([]))
    };
    let regtest = ChainProfile::Core30DefaultRegtest;
    let path = dir.join("hub.sqlite");
    let deposits = deposit::Gateway::open(hub.clone(), source.clone(), regtest, config, &path)?;
    let deposits = Arc::new(deposits);
    licash_hub_service::close_with_deposits(openings, deposits.clone());
    tokio::spawn(deposits.clone().run());
    Ok(deposits)
}

/// As [`hub`], holders choosing their terms within `range`, if any.
async fn hub_with(rt: &Regtest, dir: &Path, range: Option<Range>) -> Result<(String, Source)> {
    let (url, source, _) = hub_serving(rt, dir, range).await?;
    Ok((url, source))
}

/// As [`hub_with`], and the hub it serves, for a test to pay with.
async fn hub_serving(
    rt: &Regtest,
    dir: &Path,
    range: Option<Range>,
) -> Result<(String, Source, Arc<Hub>)> {
    serve(rt, dir, range, None).await
}

/// As [`hub_serving`], its openings' chain the node estimating every fee at
/// `rate` sat/vB, if any.
async fn serve(
    rt: &Regtest,
    dir: &Path,
    range: Option<Range>,
    rate: Option<f64>,
) -> Result<(String, Source, Arc<Hub>)> {
    std::fs::create_dir_all(dir)?;
    let (seed, db) = (dir.join("seed"), dir.join("hub.sqlite"));
    Hub::init(&seed, &db, NOTE_POW)?;
    let hub = Arc::new(Hub::open(&seed, &db, Policy::default())?);
    let url = format!(
        "{}/wallet/harness?cookie={}",
        rt.rpc_url(),
        rt.cookie().display()
    );
    let source: Source = url.parse()?;
    let keyset = hub.info().keysets[0].clone();
    let chain = match rate {
        Some(rate) => estimating(source.clone(), rate).await?,
        None => source.clone(),
    };
    let openings = Openings::with_wallet(dir, chain, source.clone(), keyset, range);
    let openings = openings.await?;
    let deposits = deposits_for(&hub, &source, dir, &openings)?;
    // An opening takes a deposit of the hub's for her reserve, which it
    // gives only once it follows a chain.
    followed(&hub, &source, &deposits).await?;
    let services = Services {
        contracts: Some(openings),
        deposits: Some(deposits),
        ..Default::default()
    };
    let app = licash_hub_service::router(hub.clone(), services);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok((url, source, hub))
}

/// The node of `real`, but estimating every fee at `rate` sat/vB: a JSON-RPC
/// in front of it.
async fn estimating(real: Source, rate: f64) -> Result<Source> {
    use axum::{extract::State, routing::post, Json};
    use serde_json::{json, Value};
    async fn answer(
        State((real, rate)): State<(Source, f64)>,
        Json(call): Json<Value>,
    ) -> Json<Value> {
        let (method, params) = (
            call["method"].as_str().unwrap_or_default(),
            call["params"].clone(),
        );
        let id = call["id"].clone();
        if method == "estimatesmartfee" {
            let feerate = rate / 100_000.0;
            return Json(
                json!({ "result": { "feerate": feerate, "blocks": 6 }, "error": null, "id": id }),
            );
        }
        Json(match real.rpc_optional::<Value>(method, params).await {
            Ok(result) => json!({ "result": result, "error": null, "id": id }),
            Err(e) => {
                // "...: message (code)", as the client words a node's error.
                let e = e.to_string();
                let code = e
                    .rsplit_once('(')
                    .and_then(|(_, c)| c.trim_end_matches(')').parse::<i64>().ok())
                    .unwrap_or(-1);
                json!({ "result": null, "error": { "code": code, "message": e }, "id": id })
            }
        })
    }
    let app = axum::Router::new()
        .fallback(post(answer))
        .with_state((real, rate));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(async move { axum::serve(listener, app).await });
    url.parse()
}

/// What the wallet finds on the chain to the tip: its coins' total.
async fn scan<T: licash_wallet::Transport>(wallet: &Wallet<T>, chain: &Node) -> Result<u64> {
    wallet.scan_silent(None, chain, 10_000).await?;
    Ok(wallet.silent_coins()?.iter().map(|c| c.value).sum())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_learns_what_its_contracts_wallet_holds() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
    Hub::init(&seed, &db, NOTE_POW)?;
    let hub = Hub::open(&seed, &db, Policy::default())?;
    let url = format!(
        "{}/wallet/harness?cookie={}",
        rt.rpc_url(),
        rt.cookie().display()
    );
    let source: Source = url.parse()?;
    let keyset = hub.info().keysets[0].clone();
    let range = Range {
        max_cap: licash_contracts::hub::terms::MAX_CAP,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let openings =
        Openings::with_wallet(dir.path(), source.clone(), source, keyset, Some(range)).await?;
    // Its confirmed balance, as the node's wallet says it now.
    let balance = openings.learn_funds().await?;
    ensure!(balance > 0, "{balance}");
    let fundable = licash_contracts::hub::terms::fundable(balance).context("none funded")?;
    let advertised = openings.advertise().range.context("no range")?.max_cap;
    ensure!(
        advertised == fundable,
        "{advertised} advertised, {fundable} funded"
    );
    Ok(())
}

/// [`Http`], but its second instance upload heard of no answer, once, as
/// one timed out over Tor after the hub had it: and the uploads it sent.
#[derive(Default)]
struct Dropping {
    http: Option<Http>,
    sent: std::sync::Mutex<Vec<[u8; 32]>>,
}

impl licash_wallet::Transport for Dropping {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        use bitcoin::hashes::Hash as _;
        let http = self.http.as_ref().expect("an Http");
        let instance = url.ends_with("/instances");
        let answer = http.request(url, body.clone()).await;
        if let (true, Some(body)) = (instance, &body) {
            let mut sent = self.sent.lock().unwrap();
            let hash = bitcoin::hashes::sha256::Hash::hash(body);
            sent.push(hash.to_byte_array());
            if sent.len() == 2 {
                return Err("no answer over Tor in 120 s".into());
            }
        }
        answer
    }
}

/// An opening whose instance upload timed out resumes sending only those
/// the hub did not answer as had: each of 25 MB on signet, over Tor.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn an_opening_resumed_sends_no_instance_the_hub_answered_again() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source) = hub(&rt, &dir.path().join("hub")).await?;
    let chain = Node(source);
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let transport = Dropping {
        http: Some(Http::new(None)?),
        ..Default::default()
    };
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(&mine.join("wallet.sqlite"), &[31; 32], regtest, transport)?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    let to = wallet.fallback_address()?.script_pubkey();
    rt.fund(&to, Amount::from_sat(60_000))?;
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == 60_000);

    // The second of its two instances unanswered: the opening waits.
    let failed = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await;
    ensure!(failed.is_err(), "{failed:?}");
    let listed = holder::list(&mine.join("wallet.sqlite"))?;
    ensure!(
        listed.len() == 1 && listed[0].phase == Phase::Chosen,
        "{listed:?}"
    );

    // Resumed: the first not sent again, the second again, and funded.
    let contracts = holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(contracts[0].phase == Phase::Funded, "{contracts:?}");
    let sent = wallet.transport().sent.lock().unwrap().clone();
    ensure!(sent.len() == 3, "{} instance uploads", sent.len());
    ensure!(
        sent[0] != sent[1] && sent[1] == sent[2],
        "the first sent again"
    );
    Ok(())
}

/// An opening whose instance upload dropped, opened as the apps open
/// one: resumed at once, the instance sent again, the one answered not.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn an_opening_carries_on_where_an_instance_upload_dropped() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source) = hub(&rt, &dir.path().join("hub")).await?;
    let chain = Node(source);
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let transport = Dropping {
        http: Some(Http::new(None)?),
        ..Default::default()
    };
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(&mine.join("wallet.sqlite"), &[32; 32], regtest, transport)?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    let to = wallet.fallback_address()?.script_pubkey();
    rt.fund(&to, Amount::from_sat(60_000))?;
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == 60_000);

    let opened =
        holder::open_with(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    ensure!(opened.phase == Phase::Funded, "{opened:?}");
    let sent = wallet.transport().sent.lock().unwrap().clone();
    ensure!(sent.len() == 3, "{} instance uploads", sent.len());
    ensure!(
        sent[0] != sent[1] && sent[1] == sent[2],
        "the first sent again"
    );
    Ok(())
}

/// A quote the hub no longer makes once she asks it again for her coin's
/// terms, its fee surcharged meanwhile as its contracts filled up: her coin
/// is spent whole, so the opening stops before she signs anything, nothing
/// kept, to be made again on a quote asked anew, at the price now, within
/// her ceiling.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_wallet_quoted_before_the_hub_surcharged_opens_on_a_quote_asked_again() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    // Armed, the hub's most contracts falls to 2 once it answered a quote.
    let armed = Arc::new(AtomicBool::new(false));
    let arm = armed.clone();
    let serve = move |app: axum::Router, openings: Arc<Openings>| {
        app.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let (armed, openings) = (arm.clone(), openings.clone());
                async move {
                    let quote = request.uri().path() == licash_contracts::QUOTE;
                    let response = next.run(request).await;
                    if quote && armed.swap(false, Ordering::SeqCst) {
                        openings.limit_live(2);
                    }
                    response
                }
            },
        ))
    };
    let (url, source, _hub, _) =
        hub_answering_through(&rt, &dir.path().join("hub"), None, serve).await?;
    let chain = Node(source);
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &[7; 32],
        regtest,
        Http::new(None)?,
    )?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    for sats in [COIN, 40_000] {
        let to = wallet.fallback_address()?.script_pubkey();
        rt.fund(&to, Amount::from_sat(sats))?;
    }
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == COIN + 40_000);
    let ask = Ask {
        max_price: 60_000,
        ..ask()
    };
    let first = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask).await?;
    ensure!(
        first.phase == Phase::Funded && first.price == 23_000,
        "{first:?}"
    );

    // One of 2 live once the hub quoted her: its fee doubled since.
    armed.store(true, Ordering::SeqCst);
    let refused = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask).await;
    let refused = format!("{:#}", refused.expect_err("opened on a quote gone"));
    ensure!(refused.contains("ask again"), "{refused}");
    ensure!(!armed.load(Ordering::SeqCst), "not quoted");
    ensure!(holder::list(&mine.join("wallet.sqlite"))?.len() == 1);

    // Asked again, at the price now.
    let second = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask).await?;
    ensure!(second.phase == Phase::Funded, "{second:?}");
    ensure!(
        second.price > first.price,
        "{} not surcharged",
        second.price
    );
    ensure!(holder::list(&mine.join("wallet.sqlite"))?.len() == 2);
    Ok(())
}

/// A coin an opening spends whole, no change coming back: a fixed contract's
/// price, 23 000 sat, and what is left of it hers to fund, in notes.
const COIN: u64 = 24_000;

fn ask() -> Ask {
    Ask {
        blocks: 300,
        max_price: 30_000,
        cap: None,
        deposit: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_wallet_opens_contracts_at_a_hub_and_sees_them_confirm() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source) = hub(&rt, &dir.path().join("hub")).await?;
    let chain = Node(source);

    // A wallet trusting the hub, which says it opens mock contracts.
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let seed = [7; 32];
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &seed,
        regtest,
        Http::new(None)?,
    )?;
    let info = wallet.add_hub(&url).await?;
    let offered = info.contracts.context("no contracts in the hub's info")?;
    ensure!(offered.mock && offered.cap == 131_071 && offered.price == 23_000);
    ensure!(holder::list(&mine.join("wallet.sqlite"))?.is_empty());
    ensure!(
        !holds_contracts(&mine.join("wallet.sqlite"))?,
        "made by a list"
    );

    // Two coins of hers on Bitcoin, at her fallback addresses.
    wallet.watch_silent(None, rt.height()?)?;
    for sats in [COIN + 400, COIN] {
        let to = wallet.fallback_address()?.script_pubkey();
        rt.fund(&to, Amount::from_sat(sats))?;
    }
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == 2 * COIN + 400);

    // Asked to pay more than she would: refused, nothing kept.
    let cheap = Ask {
        max_price: 22_999,
        ..ask()
    };
    let refused = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, cheap).await;
    ensure!(format!("{:#}", refused.unwrap_err()).contains("23000 sat to open"));

    // Opened on the smaller coin: F signed whole, broadcast, her coin
    // reserved for it.
    let tip = rt.height()?;
    let first = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    ensure!(first.phase == Phase::Funded, "{first:?}");
    ensure!(first.mock && first.cap == 131_071 && first.price == 23_000);
    ensure!(first.value == COIN && first.abandoned.is_none());
    ensure!((first.close_height, first.assert_height) == (tip + 300, tip + 134));
    let f = first.funding.context("no F")?;
    ensure!(first.fate == Some(Fate::Open), "{first:?}");
    let reserved = wallet.silent_coins()?;
    ensure!(reserved
        .iter()
        .any(|c| c.outpoint == first.deposit && c.spending == Some(f)));

    // A second contract at the same hub, on her other coin.
    let second = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    ensure!(second.phase == Phase::Funded && second.value == COIN + 400);
    ensure!(second.id != first.id && second.deposit != first.deposit);

    // Her coin's reservation lost, as a wallet rewound past it loses it:
    // kept for F again once the contracts resume.
    wallet.abandon_silent(&f)?;
    let kept = |coins: Vec<licash_wallet::SilentCoin>| {
        coins
            .iter()
            .any(|c| c.outpoint == first.deposit && c.spending == Some(f))
    };
    ensure!(!kept(wallet.silent_coins()?));
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(kept(wallet.silent_coins()?), "not kept again");

    // Both F in a block: live, each having taken its coin whole.
    rt.mine(1)?;
    let contracts = holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    let tip = rt.height()?;
    let live = |c: &Contract| c.fate == Some(Fate::Live) && c.live(tip);
    ensure!(
        contracts.len() == 2 && contracts.iter().all(live),
        "{contracts:?}"
    );
    ensure!(contracts[0].id == second.id, "not the newest first");
    let found: serde_json::Value = chain
        .0
        .rpc(
            "getrawtransaction",
            serde_json::json!([f.to_string(), true]),
        )
        .await?;
    ensure!(found["confirmations"] == 1, "{found}");
    ensure!(scan(&wallet, &chain).await? == 0);

    // Nothing more to do for them, as stored.
    let again = holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(again == contracts);
    ensure!(holder::list(&mine.join("wallet.sqlite"))? == contracts);
    Ok(())
}

/// A hub whose node estimates fees above the quote's ceiling funds F at the
/// ceiling, its fee within it as she checks it (over F unsigned): she signs
/// F, and it confirms.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_funds_f_within_the_fee_ceiling_however_high_fees_are() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, _) = serve(&rt, &dir.path().join("hub"), None, Some(25.0)).await?;
    let chain = Node(source);
    let path = dir.path().join("wallet.sqlite");
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(&path, &[8; 32], regtest, Http::new(None)?)?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    rt.fund(
        &wallet.fallback_address()?.script_pubkey(),
        Amount::from_sat(COIN),
    )?;
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == COIN);

    let opened = holder::open(&wallet, &chain, &path, &url, ask()).await?;
    ensure!(opened.phase == Phase::Funded, "{opened:?}");
    let f = opened.funding.context("no F")?;
    // Near the ceiling of 10 sat/vB, F signed.
    let entry: serde_json::Value = chain
        .0
        .rpc("getmempoolentry", serde_json::json!([f.to_string()]))
        .await?;
    let fee = entry["fees"]["base"].as_f64().context("fee")? * 1e8;
    let rate = fee.round() / entry["vsize"].as_f64().context("vsize")?;
    ensure!((8.0..=10.0).contains(&rate), "F at {rate} sat/vB");
    rt.mine(1)?;
    let contracts = holder::resume(&wallet, &chain, &path).await?;
    ensure!(contracts[0].fate == Some(Fate::Live), "{contracts:?}");
    Ok(())
}

/// A hub following Bitcoin opens contracts on the newest block its ledger
/// takes as a lock checkpoint, kept as its newest: every lock named after
/// a contract opens is on the chain its statement reads.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_opens_contracts_on_its_newest_lock_checkpoint() -> Result<()> {
    let newest = |hub: &Hub| hub.checkpoint().map(|c| c.commitment());
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, hub, openings) =
        hub_answering_unfollowed(&rt, &dir.path().join("hub")).await?;
    licash_hub_service::open_on_lock_checkpoints(&openings, hub.clone());
    let chain = Node(source.clone());
    // Following no chain yet: no offer.
    ensure!(openings.offer(None, 0).await.is_err());
    // Following one, it proves its identity: a wallet adds it.
    while !watch::step(&hub, &source).await? {}
    let seed = [7; 32];
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, seed, &[100_000]).await?;
    while !watch::step(&hub, &source).await? {}
    let first = hub.checkpoint().context("no checkpoint")?;
    // Later blocks, too few for the hub to take another checkpoint.
    rt.mine(20)?;
    while !watch::step(&hub, &source).await? {}
    ensure!(newest(&hub) == Some(first.commitment()));
    let tip = rt.height()?;
    let offer = openings.offer(None, 0).await;
    let offer = offer.map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let at = offer.quote.chain.checkpoint.clone();
    let bury = Policy::default().timing.bury;
    ensure!(at.height() == tip + 1 - bury && at.height() > first.height());
    // A quote keeps nothing: an opening does.
    ensure!(newest(&hub) == Some(first.commitment()), "kept on a quote");
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    ensure!(opened.phase == Phase::Funded, "{opened:?}");
    ensure!(newest(&hub) == Some(at.commitment()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_wallet_opens_a_contract_of_terms_it_chose_on_a_small_coin() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source) = hub_with(&rt, &dir.path().join("hub"), Some(range)).await?;
    let chain = Node(source);
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &[8; 32],
        regtest,
        Http::new(None)?,
    )?;

    // Its fixed terms, as apps installed open on, and the range beside.
    let info = wallet.add_hub(&url).await?;
    let offered = info.contracts.context("no contracts in the hub's info")?;
    let chosen = offered.range.context("no range in the hub's info")?;
    // No bound on the cap by her coin, announced as none.
    ensure!((chosen.min_blocks, chosen.max_blocks, chosen.per_coin) == (200, 5_000, u32::MAX));
    // Its fixed terms priced by the same formula: 1% a year of their cap.
    let fixed_price = chosen.price(131_071, 1_000, 0);
    ensure!(fixed_price == 23_000 + 24, "{fixed_price}");
    ensure!(offered.cap == 131_071 && offered.price == fixed_price && offered.blocks == 1_000);
    // 2^21 - 1 sat over 2 000 blocks: 1% a year of it over the fixed fee.
    let price = chosen.price(2_097_151, 2_000, 0);
    ensure!(price == 23_000 + 798, "{price}");

    // Asked of terms she chose: those exactly, a graph as wide as them.
    let offer = holder::offer(&wallet, &url, Some((2_097_151, 2_000)), 0).await?;
    ensure!(offer.quote.cap == 2_097_151 && offer.bounds.lock == 2_000);
    ensure!(offer.quote.graph.bits == 21 && offer.price() == price);
    // Out of its range, or half asked: refused.
    let refused = holder::offer(&wallet, &url, Some((131_071, 199)), 0).await;
    let refused = refused.err().context("offered 199 blocks")?;
    ensure!(format!("{refused:#}").contains("status 400"), "{refused:#}");
    let half = format!("{url}{}?cap=5000", licash_contracts::QUOTE);
    let half = wallet.transport().request(&half, None).await;
    let half = half.map_err(anyhow::Error::msg)?;
    ensure!(half.status == 400, "{}", half.status);

    // Two small coins, each paying a price and her part of a contract in
    // the notes a claim names.
    wallet.watch_silent(None, rt.height()?)?;
    for sats in [70_000, 65_000] {
        let to = wallet.fallback_address()?.script_pubkey();
        rt.fund(&to, Amount::from_sat(sats))?;
    }
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == 135_000);
    let small = wallet.silent_coins()?;
    let small = small
        .iter()
        .find(|c| c.value == 70_000)
        .context("no coin")?;

    // 2^21 - 1 sat on her 70 000 sat coin, 30 times it: the hub funds the
    // rest, its interest priced on it. F funded whole.
    let tip = rt.height()?;
    let ask = Ask {
        blocks: 2_000,
        max_price: price,
        cap: Some(2_097_151),
        deposit: Some(small.outpoint),
    };
    let first = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask).await?;
    ensure!(first.phase == Phase::Funded, "{first:?}");
    ensure!(first.cap == 2_097_151 && first.value == 70_000);
    // Her part of it, her coin's rest, the hub charges no interest on.
    ensure!(first.price == chosen.price(2_097_151, 2_000, first.funded as u32));
    ensure!(first.price <= price);
    ensure!((first.close_height, first.assert_height) == (tip + 2_000, tip + 1_834));

    // Of the fixed terms beside it, on her other coin, as an app
    // installed asks.
    let fixed = Ask {
        blocks: 300,
        max_price: fixed_price,
        cap: None,
        deposit: None,
    };
    let second = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, fixed).await?;
    ensure!(second.cap == 131_071 && second.value == 65_000);
    ensure!(second.price == chosen.price(131_071, 300, second.funded as u32));

    // Both live; the hub's collateral for hers 2^21 - 1 sat at least.
    rt.mine(1)?;
    let contracts = holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    let tip = rt.height()?;
    ensure!(contracts
        .iter()
        .all(|c| c.fate == Some(Fate::Live) && c.live(tip)));
    let f = first.funding.context("no F")?;
    let found: serde_json::Value = chain
        .0
        .rpc(
            "getrawtransaction",
            serde_json::json!([f.to_string(), true]),
        )
        .await?;
    let outputs = found["vout"].as_array().context("no outputs")?;
    let sats = |o: &serde_json::Value| (o["value"].as_f64().unwrap_or(0.0) * 1e8).round() as u64;
    let most = outputs.iter().map(sats).max().unwrap_or(0);
    ensure!(most >= (1 << 21) - 1, "{found}");
    Ok(())
}

/// The largest note of the hubs [`pay`] pays from: 2^16 sat, half the
/// least contract size and some.
const NOTE_POW: u32 = 16;

/// A payment of `amount` to `to` at `hub`, of seed file `seed`, its fee
/// paid, from notes its keys made for someone outside any wallet.
fn pay(
    hub: &Hub,
    seed: &Path,
    url: &str,
    to: &licash::address::Address,
    amount: u64,
) -> Result<licash_api::Payment> {
    pay_at(hub, seed, url, to, amount, NOTE_POW)
}

/// [`pay`] at a hub of notes up to 2^`pow` sat.
fn pay_at(
    hub: &Hub,
    seed: &Path,
    url: &str,
    to: &licash::address::Address,
    amount: u64,
    pow: u32,
) -> Result<licash_api::Payment> {
    use licash::address::{Ephemeral, OwnerKeys};
    use licash::authorization::{Authorization, SignedProposal};
    use licash::claim::Branch;
    use licash::note::{Evidence, IssuerKeys, Note};
    use licash::spend::{Output, Proposal};
    use licash::unlink::Nonce;

    let split = |mut amount: u64| {
        let mut denoms = Vec::new();
        while amount > 0 {
            let d = 1u64 << (63 - amount.leading_zeros());
            denoms.push(d);
            amount -= d;
        }
        denoms
    };
    let text = std::fs::read_to_string(seed)?;
    let mut bytes = [0; 32];
    hex::decode_to_slice(text.trim(), &mut bytes)?;
    let keys = IssuerKeys::from_seed(&bytes, 0, pow)?;
    let keyset = keys.keyset()?;
    let info = hub.info();
    let mut total = amount;
    while amount + info.policy.spend.due(total) != total {
        total = amount + info.policy.spend.due(total);
    }
    let payer = OwnerKeys::from_seed(&[0xfa; 32])?;
    let mut inputs = Vec::new();
    for denom in split(total) {
        let d = Ephemeral::random().derive(&payer.address(), denom, Branch::Pay, 0)?;
        let output = Output::from_derivation(&d)?;
        let proof = keys.prove_blinded(denom, output.blinded())?;
        let note = Note::from_parts(
            &keyset,
            *keyset.id(),
            d.message().clone(),
            proof.open_point(&keyset, &d)?,
            Evidence::Linked {
                dleq: proof.dleq(),
                blinding: *d.blinding(),
                commit: Nonce::new(&keyset, &output)?.commit()?,
            },
        )?;
        inputs.push((note, d));
    }
    let notes: Vec<Note> = inputs.iter().map(|(note, _)| note.clone()).collect();
    let ephemeral = Ephemeral::random();
    let to_hub = split(total - amount)
        .into_iter()
        .map(|d| (d, &info.address));
    let outputs = split(amount)
        .into_iter()
        .map(|d| (d, to))
        .chain(to_hub)
        .enumerate()
        .map(|(i, (d, to))| Output::from_derivation(&ephemeral.derive(to, d, Branch::Pay, i)?))
        .collect::<Result<Vec<_>, _>>()?;
    let proposal = Proposal::new(&keyset, &notes, ephemeral.public(), outputs, None)?;
    let grant = hub.offer(&proposal, &notes)?;
    let owners = inputs
        .iter()
        .map(|(_, d)| d.ownership().owner_secret(payer.spend_secret()))
        .collect::<Result<Vec<_>, _>>()?;
    let signed = SignedProposal::sign(
        &keyset,
        proposal,
        &notes,
        Authorization::Granted(Box::new(grant)),
        &owners,
    )?;
    let unlock = hub.release(&signed, &notes)?;
    Ok(licash_api::Payment::new(url, &signed, &notes, &unlock))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_holder_forces_her_contract_closed_on_a_silent_hub_and_takes_her_notes_value(
) -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    // A hub service that answers no request: silent.
    let (url, source, hub) = hub_serving(&rt, &at, None).await?;
    let chain = Node(source);
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &[9; 32],
        regtest,
        Http::new(None)?,
    )?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    for sats in [COIN, COIN] {
        let to = wallet.fallback_address()?.script_pubkey();
        rt.fund(&to, Amount::from_sat(sats))?;
    }
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == 2 * COIN);
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    let rate = FeeRate::from_sat_per_vb(2).context("a rate")?;

    // 3 000 sat of notes at the hub: 7 of them.
    let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 3_000)?;
    wallet.receive(&payment)?;
    let available =
        |w: &Wallet<Http>| -> Result<u64> { Ok(w.balance()?.iter().map(|b| b.available).sum()) };
    ensure!(available(&wallet)? == 3_000);

    // Not before F is buried: nothing taken.
    let early = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await;
    let early = format!("{:#}", early.unwrap_err());
    ensure!(early.contains("not buried"), "{early}");
    ensure!(
        available(&wallet)? == 3_000
            && recovery::recoveries(&mine.join("wallet.sqlite"))?.is_empty()
    );
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    // No coin of hers left on Bitcoin: her purse pays her forced close.
    empty(&rt, &wallet, &chain).await?;

    // Forced closed: her notes claimed, out of her balance; revocable
    // until R may be in the next block, after its lock from F.
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    ensure!(
        forced.stage == Stage::Claimed && !forced.irrevocable,
        "{forced:?}"
    );
    // Her notes, and what she funded it with, not issued her.
    ensure!(
        (forced.claimed, forced.notes) == (3_000 + opened.funded, 7),
        "{forced:?}"
    );
    ensure!(forced.error.is_none(), "{forced:?}");
    ensure!(available(&wallet)? == 0);
    let lock_end = forced.next_at.context("no lock")?;
    ensure!(lock_end > rt.height()? + 1, "{forced:?}");
    // Given up: her notes back. Then forced closed again.
    recovery::give_up(&wallet, &mine.join("wallet.sqlite"), &opened.id)?;
    ensure!(
        available(&wallet)? == 3_000
            && recovery::recoveries(&mine.join("wallet.sqlite"))?.is_empty()
    );
    // Asked again, as a second tap waiting behind the first: done already.
    recovery::give_up(&wallet, &mine.join("wallet.sqlite"), &opened.id)?;
    ensure!(available(&wallet)? == 3_000);
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    ensure!(
        forced.stage == Stage::Claimed && forced.claimed == 3_000 + opened.funded,
        "{forced:?}"
    );
    ensure!(available(&wallet)? == 0);
    // Again: the same one, carried on.
    let again = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    ensure!(again == forced, "{again:?}");

    rt.mine_to_height(lock_end - 2)?;
    let held = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(
        held[0].stage == Stage::Claimed && held[0].error.is_none(),
        "{held:?}"
    );
    // R may be in the next block: irrevocable, R and P broadcast.
    rt.mine(1)?;
    let sent = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(
        sent[0].stage == Stage::Published && sent[0].irrevocable,
        "{sent:?}"
    );
    ensure!(sent[0].error.is_none(), "{sent:?}");
    let given_up = recovery::give_up(&wallet, &mine.join("wallet.sqlite"), &opened.id);
    ensure!(format!("{:#}", given_up.unwrap_err()).contains("past giving up"));

    // R and P in a block: the hub's window runs.
    rt.mine(1)?;
    let tip = rt.height()?;
    let all = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    let requested = &all[0];
    ensure!(
        all.len() == 1 && requested.stage == Stage::Requested,
        "{all:?}"
    );
    ensure!(requested.requested_at == Some(tip), "{requested:?}");
    let window_end = requested.next_at.context("no window")?;
    ensure!(window_end > tip + 1, "{requested:?}");
    // P's fees paid of R's alone: its claim slot, its anchor and her
    // purse, no coin of hers.
    let p = requested.publication.context("no P")?;
    let r = requested.request.context("no R")?;
    let (r, p) = (rt.get_tx(&r)?, rt.get_tx(&p)?);
    let spent: Vec<_> = p.input.iter().map(|i| i.previous_output).collect();
    let of_r = |vout| bitcoin::OutPoint {
        txid: r.compute_txid(),
        vout,
    };
    ensure!(spent == [of_r(2), of_r(1), of_r(3)], "{p:?}");
    // The reserve's model weighs them as measured (7 notes, compact), and
    // at most as if each note she funded it with were one more: a forced
    // close the quote's reserve affords is one that confirms.
    let model = licash_contracts::reserve::publication_vsize(Format::Compact, 7);
    let most = licash_contracts::reserve::publication_vsize(
        Format::Compact,
        7 + opened.funded.count_ones(),
    );
    ensure!(
        r.vsize() as u64 <= licash_contracts::reserve::R_VSIZE,
        "R weighs {} vB",
        r.vsize()
    );
    ensure!(
        (model - 20..=most).contains(&(p.vsize() as u64)),
        "P weighs {} vB, the model {model} to {most}",
        p.vsize()
    );

    // Nothing to do until it passes; then request_timeout, paid of P's
    // fee coin.
    rt.mine_to_height(window_end - 2)?;
    let waiting = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(waiting[0].stage == Stage::Requested, "{waiting:?}");
    rt.mine(1)?;
    let timing_out = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(timing_out[0].stage == Stage::TimingOut, "{timing_out:?}");
    ensure!(timing_out[0].error.is_none(), "{timing_out:?}");
    rt.mine(1)?;
    let timed_out =
        &recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0];
    ensure!(timed_out.stage == Stage::TimedOut, "{timed_out:?}");
    ensure!(
        timed_out.timed_out_at == Some(rt.height()?),
        "{timed_out:?}"
    );

    // Her bits and reserve, swept to her wallet once their delay passed.
    let delay_end = timed_out.next_at.context("no delay")?;
    rt.mine_to_height(delay_end - 2)?;
    let held = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(held[0].stage == Stage::TimedOut, "{held:?}");
    let before = scan(&wallet, &chain).await?;
    rt.mine(1)?;
    let sweeping = &recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0];
    ensure!(sweeping.stage == Stage::Sweeping, "{sweeping:?}");
    let sweep = sweeping.sweep.context("no sweep")?;
    rt.mine(1)?;
    let done = &recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0];
    ensure!(
        done.stage == Stage::Done && done.swept_at == Some(rt.height()?),
        "{done:?}"
    );
    let found: serde_json::Value = chain
        .0
        .rpc(
            "getrawtransaction",
            serde_json::json!([sweep.to_string(), true]),
        )
        .await?;
    let paid = found["vout"][0]["value"].as_f64().context("no output")?;
    let paid = (paid * 1e8).round() as u64;
    let after = scan(&wallet, &chain).await?;
    ensure!(
        after == before + paid,
        "{before} then {after}, {paid} swept"
    );
    // Her claim's bits (3 000 rounded down to 2 560) and all her 20 000,
    // her purse (P's, taken already) refunded, less the sweep's fee (its
    // bits' witnesses are large): the hub, only silent, gets its 100 000
    // back less what the links took, her purse among it (its graph id 8's
    // `request_timeout`).
    ensure!(
        paid > 2_560 + 20_000 - 3_000 && paid < 2_560 + 20_000,
        "{paid} swept"
    );
    let timeout = timed_out.timeout.context("no timeout")?;
    let found: serde_json::Value = chain
        .0
        .rpc(
            "getrawtransaction",
            serde_json::json!([timeout.to_string(), true]),
        )
        .await?;
    let outputs = found["vout"].as_array().context("no outputs")?;
    // After the bits and her reserve, last.
    let last = outputs.last().and_then(|o| o["value"].as_f64());
    let back = (last.context("no output")? * 1e8).round() as u64;
    ensure!((70_000..80_000).contains(&back), "the hub's {back} back");
    eprintln!("swept {paid} sat to her wallet");
    // Nothing more to do.
    let over = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(over[0] == *done, "{over:?}");
    Ok(())
}

/// The notes she funded her contract with, never issued by a silent hub,
/// are claimed by her forced close with her others, and paid her when it
/// times out.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_holder_claims_the_notes_she_funded_that_a_silent_hub_never_issued() -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let (url, source, hub) = hub_serving(&rt, &at, None).await?;
    let chain = Node(source);
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &[9; 32],
        ChainProfile::Core30DefaultRegtest,
        Http::new(None)?,
    )?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    // The price of a hub's one contract, 23 000 sat, and 3 000 hers.
    let to = wallet.fallback_address()?.script_pubkey();
    rt.fund(&to, Amount::from_sat(26_000))?;
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == 26_000);
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    ensure!(
        opened.funded == 3_000 && !opened.funded_received,
        "{opened:?}"
    );
    let rate = FeeRate::from_sat_per_vb(2).context("a rate")?;
    let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 1_000)?;
    wallet.receive(&payment)?;
    for _ in 0..4 {
        rt.mine(1)?;
        holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    }
    // Never issued: this hub issues none.
    let listed = holder::list(&mine.join("wallet.sqlite"))?;
    ensure!(!listed[0].funded_received, "{listed:?}");
    ensure!(available(&wallet)? == 1_000);
    empty(&rt, &wallet, &chain).await?;

    // Her funded notes claimed first, with those she holds.
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    ensure!(
        forced.stage == Stage::Claimed && forced.claimed == 4_000,
        "{forced:?}"
    );
    ensure!(forced.error.is_none(), "{forced:?}");
    ensure!(available(&wallet)? == 0);
    let lock_end = forced.next_at.context("no lock")?;
    rt.mine_to_height(lock_end - 1)?;
    let sent = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(sent[0].stage == Stage::Published, "{sent:?}");
    ensure!(sent[0].error.is_none(), "{sent:?}");
    rt.mine(1)?;
    let requested =
        &recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0];
    ensure!(requested.stage == Stage::Requested, "{requested:?}");
    let window_end = requested.next_at.context("no window")?;
    rt.mine_to_height(window_end - 1)?;
    let timing_out = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(timing_out[0].stage == Stage::TimingOut, "{timing_out:?}");
    rt.mine(1)?;
    let timed_out =
        &recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0];
    ensure!(timed_out.stage == Stage::TimedOut, "{timed_out:?}");
    // Paid all she claimed: her timeout's bits of 4 000, rounded down.
    let timeout = timed_out.timeout.context("no timeout")?;
    let found = rt.get_tx(&timeout)?;
    let total: u64 = found.output.iter().map(|o| o.value.to_sat()).sum();
    ensure!(total > 3_000, "{found:?}");
    Ok(())
}

/// Her wallet's coins on Bitcoin, all spent away, mined.
async fn empty(rt: &Regtest, wallet: &Wallet<Http>, chain: &Node) -> Result<()> {
    if scan(wallet, chain).await? > 0 {
        let away =
            bitcoin::ScriptBuf::new_p2wsh(&bitcoin::ScriptBuf::from(vec![0x51]).wscript_hash());
        let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
        let tx = wallet.spend_silent(away, None, rate)?;
        rt.send_and_confirm(&tx)?;
    }
    ensure!(scan(wallet, chain).await? == 0, "coins left");
    Ok(())
}

/// A forced close at a fee rate her purse falls short of, no coin of hers
/// on Bitcoin: published within her reserve all the same, its fee a
/// quarter of what it may pay, whatever the rate. Held out of blocks, it
/// is bumped as its window passes, up to all her reserve, then she is
/// told; once she allows more, one coin of hers pays the rest. Whichever
/// version a block holds is hers.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_holder_publishes_within_her_reserve_and_bumps_it_then_adds_a_coin_she_allows(
) -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let (url, source, hub) = hub_serving(&rt, &at, None).await?;
    let chain = Node(source);
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &[9; 32],
        regtest,
        Http::new(None)?,
    )?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    let to = wallet.fallback_address()?.script_pubkey();
    rt.fund(&to, Amount::from_sat(60_000))?;
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == 60_000);
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 2_048)?;
    wallet.receive(&payment)?;
    rt.mine(2)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    empty(&rt, &wallet, &chain).await?;
    // Coins of hers, one to be set aside for a challenge: none to be
    // spent on her publication's fee until she allows it.
    let mut funded = Vec::new();
    for _ in 0..2 {
        let (coin, _) = rt.fund(
            &wallet.fallback_address()?.script_pubkey(),
            Amount::from_sat(100_000),
        )?;
        funded.push(coin);
    }
    ensure!(scan(&wallet, &chain).await? == 200_000);

    // 20 sat/vB: R's package alone is past her purse.
    let rate = FeeRate::from_sat_per_vb(20).context("a rate")?;
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    let lock_end = forced.next_at.context("no lock")?;
    rt.mine_to_height(lock_end - 1)?;
    let file = mine.join("wallet.sqlite");
    let advance = || recovery::advance(&wallet, &chain, &file, rate);
    let sent = advance().await?.remove(0);
    ensure!(
        sent.stage == Stage::Published && sent.irrevocable && sent.error.is_none(),
        "{sent:?}"
    );
    let first = rt.get_tx(&sent.publication.context("no P")?)?;
    let r = rt.get_tx(&sent.request.context("no R")?)?;
    let of_r = |vout| bitcoin::OutPoint {
        txid: r.compute_txid(),
        vout,
    };
    let spent = |p: &bitcoin::Transaction| -> Vec<_> {
        p.input.iter().map(|i| i.previous_output).collect()
    };
    ensure!(
        spent(&first) == [of_r(2), of_r(1), of_r(3)],
        "first spends {:?}",
        spent(&first)
    );
    // What R hands her for it, less the fee coin her terminals need.
    let held: u64 = [1, 2, 3].iter().map(|&v| r.output[v].value.to_sat()).sum();
    let limit = held - first.output[1].value.to_sat();
    ensure!(
        fee_of(&rt, &first)? <= limit / 4,
        "first fee {} limit {limit}",
        fee_of(&rt, &first)?
    );

    // R in a block, P held out: at half its window, bumped to half.
    let r_at = rt.mine_with(std::slice::from_ref(&r))?;
    advance().await?;
    for _ in 0..3 {
        rt.mine_with(&[])?;
    }
    let bumped = advance().await?.remove(0);
    ensure!(bumped.stage == Stage::Published, "{bumped:?}");
    let half = rt.get_tx(&bumped.publication.context("no P")?)?;
    ensure!(half.compute_txid() != first.compute_txid());
    ensure!(half.output[..2] == first.output[..2] && spent(&half) == spent(&first));
    ensure!(
        fee_of(&rt, &half)? == limit / 2,
        "half fee {} limit {limit}",
        fee_of(&rt, &half)?
    );

    // At three quarters: all of it, and she is told.
    for _ in 0..2 {
        rt.mine_with(&[])?;
    }
    let all = advance().await?.remove(0);
    let why = all.error.clone().context("not told")?;
    ensure!(why.contains("allow-publication-fee"), "{why}");
    let whole = rt.get_tx(&all.publication.context("no P")?)?;
    ensure!(
        fee_of(&rt, &whole)? == limit,
        "whole fee {} limit {limit}",
        fee_of(&rt, &whole)?
    );
    ensure!(rt.height()? == r_at + 5);

    // She allows twice that: one coin of hers pays the rest.
    let value = (holder::list(&mine.join("wallet.sqlite"))?.into_iter())
        .find(|c| c.id == opened.id)
        .context("no contract")?
        .value;
    ensure!(
        recovery::allow_publication_fee(&mine.join("wallet.sqlite"), &opened.id, value + 1)
            .is_err()
    );
    recovery::allow_publication_fee(&mine.join("wallet.sqlite"), &opened.id, 2 * limit)?;
    let allowed = advance().await?.remove(0);
    ensure!(allowed.stage == Stage::Published, "{allowed:?}");
    let paid = rt.get_tx(&allowed.publication.context("no P")?)?;
    let inputs = spent(&paid);
    ensure!(
        inputs[..3] == [of_r(2), of_r(1), of_r(3)]
            && inputs.len() == 4
            && funded.contains(&inputs[3]),
        "paid spends {inputs:?}"
    );
    ensure!(
        fee_of(&rt, &paid)? == 2 * limit,
        "paid fee {} limit {limit}",
        fee_of(&rt, &paid)?
    );

    // The first, a block holds: hers all the same.
    rt.mine_with(std::slice::from_ref(&first))?;
    let requested = advance().await?.remove(0);
    ensure!(requested.stage == Stage::Requested, "{requested:?}");
    ensure!(requested.publication == Some(first.compute_txid()));
    Ok(())
}

/// An honest forced close at a hub that plays exits: her claim is owed all
/// it asks, so the hub posts nothing and her timeout pays her.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_lets_an_honest_claim_time_out_to_its_holder() -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let (url, source, hub, openings) = hub_answering(&rt, &at).await?;
    let chain = Node(source);
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &[21; 32],
        ChainProfile::Core30DefaultRegtest,
        Http::new(None)?,
    )?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    for sats in [COIN, COIN] {
        let to = wallet.fallback_address()?.script_pubkey();
        rt.fund(&to, Amount::from_sat(sats))?;
    }
    rt.mine(1)?;
    scan(&wallet, &chain).await?;
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    let rate = FeeRate::from_sat_per_vb(2).context("a rate")?;
    let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 3_000)?;
    wallet.receive(&payment)?;
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;

    let mut done = None;
    for _ in 0..400 {
        rt.mine(1)?;
        let round = openings.answer_requests().await?;
        ensure!(round.answered == 0 && round.failed == 0, "{round:?}");
        let all = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
        ensure!(all[0].stage != Stage::Answered, "{all:?}");
        if all[0].stage == Stage::Done {
            done = Some(all[0].clone());
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(done.received.is_some_and(|r| r > 3_000), "{done:?}");
    // The notes she was paid for on Bitcoin are spent at the hub: no
    // spend takes them.
    let claimed: Vec<licash::crypto::Point> =
        rusqlite::Connection::open(mine.join("wallet.sqlite"))?
            .prepare("SELECT y FROM notes WHERE spent_by IS NOT NULL")?
            .query_map([], |r| r.get::<_, [u8; 33]>(0))?
            .map(|y| Ok(licash::crypto::Point(y?)))
            .collect::<Result<_>>()?;
    ensure!(!claimed.is_empty(), "no claimed note");
    ensure!(
        hub.spent(&claimed)?.iter().all(|s| *s),
        "a claimed note unspent"
    );
    Ok(())
}

/// A contract no one exits ends at its close: the hub posts the default,
/// which pays her reserve to her wallet and the rest to the hub's, once.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_ends_a_contract_no_one_exited_by_default_at_its_close() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, _, openings) = hub_answering(&rt, &dir.path().join("hub")).await?;
    let chain = Node(source);
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, [23; 32], &[COIN]).await?;
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    // F took her coin whole: nothing came back.
    ensure!(scan(&wallet, &chain).await? == 0);

    // Not before its close: the default's lock is the close.
    let close = opened.close_height;
    rt.mine(u64::from(close) - u64::from(rt.height()?) - 1)?;
    let round = openings.answer_requests().await?;
    ensure!(round == Default::default(), "{round:?}");
    rt.mine(1)?;
    let round = openings.answer_requests().await?;
    ensure!(round.closed == 1 && round.failed == 0, "{round:?}");
    let again = openings.answer_requests().await?;
    ensure!(again == Default::default(), "posted again: {again:?}");
    rt.mine(1)?;

    // Her reserve at the hub's close deposit, not her wallet; the rest, V_max
    // and the hub's reserve, at the hub's.
    ensure!(scan(&wallet, &chain).await? == 0);
    let f = opened.funding.context("no F")?;
    let spent: Option<serde_json::Value> = chain
        .0
        .rpc_optional("gettxout", serde_json::json!([f.to_string(), 0, true]))
        .await?;
    ensure!(spent.is_none(), "the contract stands");
    let funding: serde_json::Value = chain
        .0
        .rpc(
            "getrawtransaction",
            serde_json::json!([f.to_string(), true]),
        )
        .await?;
    let value = funding["vout"][0]["value"]
        .as_f64()
        .context("no contract output")?;
    let share = (value * 1e8).round() as u64 - 20_000;
    let ours: serde_json::Value = chain
        .0
        .rpc("listunspent", serde_json::json!([1, 1]))
        .await?;
    let back = ours
        .as_array()
        .context("no coins")?
        .iter()
        .filter_map(|c| c["amount"].as_f64())
        .any(|btc| (btc * 1e8).round() as u64 == share);
    ensure!(back, "the hub's share not in its wallet: {ours}");
    let after = openings.answer_requests().await?;
    ensure!(after == Default::default(), "{after:?}");
    Ok(())
}

/// A holder closes her contract early with the hub, cooperatively: its
/// fold pays her reserve to her wallet at once, the rest to the hub's less
/// the fee, and the contract protects nothing from then on. The hub's
/// watcher takes the fold as the contract's end, and posts no default.
/// Closed early as soon as its F is buried, her wallet not told so
/// before: the close looks at the chain itself.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_holder_closes_a_contract_buried_since_she_last_looked() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, hub, _openings) = hub_answering(&rt, &dir.path().join("hub")).await?;
    let chain = Node(source.clone());
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, [33; 32], &[COIN]).await?;
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    ensure!(holder::list(&mine.join("wallet.sqlite"))?[0].fate != Some(Fate::Live));
    let early = holder::close(&wallet, &chain, &mine.join("wallet.sqlite"), &opened.id).await;
    ensure!(
        early
            .as_ref()
            .is_err_and(|e| format!("{e:#}").contains("not buried")),
        "{early:?}"
    );
    funded_in(
        &rt,
        &hub,
        &source,
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
    )
    .await?;
    let txid = holder::close(&wallet, &chain, &mine.join("wallet.sqlite"), &opened.id).await?;
    let listed = holder::list(&mine.join("wallet.sqlite"))?;
    ensure!(listed[0].folded == Some(txid), "{:?}", listed[0]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_holder_closes_her_contract_early_with_the_hub_and_gets_her_reserve_back() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, hub, openings) = hub_answering(&rt, &dir.path().join("hub")).await?;
    let chain = Node(source.clone());
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, [29; 32], &[COIN]).await?;
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    funded_in(
        &rt,
        &hub,
        &source,
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
    )
    .await?;
    // F took her coin whole: nothing came back.
    ensure!(scan(&wallet, &chain).await? == 0);
    let tip = rt.height()?;
    let listed = holder::list(&mine.join("wallet.sqlite"))?;
    ensure!(listed[0].live(tip), "not live: {:?}", listed[0]);

    let txid = holder::close(&wallet, &chain, &mine.join("wallet.sqlite"), &opened.id).await?;
    let listed = holder::list(&mine.join("wallet.sqlite"))?;
    ensure!(listed[0].folded == Some(txid), "{:?}", listed[0]);
    ensure!(!listed[0].live(tip) && listed[0].over(tip));
    // Asked again, its fold in the mempool: the hub refuses before she
    // signs another, and it stays closed.
    let again = holder::close(&wallet, &chain, &mine.join("wallet.sqlite"), &opened.id).await;
    ensure!(
        again
            .as_ref()
            .is_err_and(|e| format!("{e:#}").contains("spent")),
        "{again:?}"
    );
    ensure!(holder::list(&mine.join("wallet.sqlite"))?[0].folded == Some(txid));
    rt.mine(1)?;

    // Her reserve and her funded notes' value at her wallet; the hub's share
    // less the fee at its own.
    ensure!(scan(&wallet, &chain).await? == 20_000 + opened.funded);
    let fold: serde_json::Value = chain
        .0
        .rpc(
            "getrawtransaction",
            serde_json::json!([txid.to_string(), true]),
        )
        .await?;
    let f = opened.funding.context("no F")?;
    ensure!(fold["vin"][0]["txid"] == f.to_string(), "{fold}");
    ensure!(fold["confirmations"].as_u64() == Some(1), "{fold}");
    let sats = |v: &serde_json::Value| (v["value"].as_f64().unwrap_or(0.0) * 1e8).round() as u64;
    let outs = fold["vout"].as_array().context("no outputs")?;
    ensure!(
        outs.len() == 2 && sats(&outs[0]) == 20_000 + opened.funded,
        "{fold}"
    );
    let funding: serde_json::Value = chain
        .0
        .rpc(
            "getrawtransaction",
            serde_json::json!([f.to_string(), true]),
        )
        .await?;
    let value = sats(&funding["vout"][0]);
    let fee = value - 20_000 - opened.funded - sats(&outs[1]);
    ensure!((1..2_000).contains(&fee), "a fee of {fee}: {fold}");

    // The hub posts no default, now or at the close, and ends it.
    let round = openings.answer_requests().await?;
    ensure!(round == Default::default(), "{round:?}");
    let close = opened.close_height;
    rt.mine(u64::from(close) - u64::from(rt.height()?) + 1)?;
    let round = openings.answer_requests().await?;
    ensure!(round == Default::default(), "{round:?}");
    ensure!(scan(&wallet, &chain).await? == 20_000 + opened.funded);
    Ok(())
}

/// Blocks mined, the hub following them and the wallet resuming its contracts,
/// until the notes she funded each with are in her balance: issued once F is
/// buried, which a contract closes early only after.
async fn funded_in<T: licash_wallet::Transport>(
    rt: &Regtest,
    hub: &Arc<Hub>,
    source: &Source,
    wallet: &Wallet<T>,
    chain: &Node,
    file: &Path,
) -> Result<()> {
    for _ in 0..12 {
        rt.mine(1)?;
        while !watch::step(hub, source).await? {}
        let contracts = holder::resume(wallet, chain, file).await?;
        if contracts.iter().all(|c| c.funded_received) {
            return Ok(());
        }
    }
    anyhow::bail!("her funded notes never came")
}

/// A holder's wallet of `seed` over `transport` with a contract of a cap of
/// 131 071 sat at a hub, and three notes of 65 536 there, the largest
/// [`pay`] makes: more than its cap, so that a claim takes two of them,
/// 131 072 sat of face value for its cap of 131 071, and leaves the third.
struct Notes<T: licash_wallet::Transport> {
    rt: Regtest,
    _dir: tempfile::TempDir,
    hub: Arc<Hub>,
    openings: Arc<Openings>,
    chain: Node,
    wallet: Wallet<T>,
    mine: std::path::PathBuf,
    contract: Contract,
}

async fn with_notes<T: licash_wallet::Transport>(seed: [u8; 32], transport: T) -> Result<Notes<T>> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: licash_contracts::hub::terms::MAX_CAP,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub, openings) = hub_answering_with(&rt, &at, Some(range)).await?;
    let chain = Node(source.clone());
    let (mine, wallet) = holder_wallet_over(
        &rt,
        &chain,
        &dir.path().join("wallet"),
        &url,
        seed,
        &[COIN, COIN],
        transport,
    )
    .await?;
    let chosen = Ask {
        cap: Some(131_071),
        ..ask()
    };
    let contract = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, chosen).await?;
    ensure!(contract.cap == 131_071, "{contract:?}");
    funded_in(
        &rt,
        &hub,
        &source,
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
    )
    .await?;
    for _ in 0..3 {
        let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 65_536)?;
        wallet.receive(&payment)?;
    }
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(available(&wallet)? == 196_608 + contract.funded);
    Ok(Notes {
        rt,
        _dir: dir,
        hub,
        openings,
        chain,
        wallet,
        mine,
        contract,
    })
}

/// Closed early with the hub, a contract is paid her claim by the fold: her
/// cap in her notes there, and her reserve, on Bitcoin, the notes gone from
/// her balance and retired in the hub's ledger.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_holder_closes_her_contract_on_her_notes_and_its_fold_pays_them_to_her() -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::recovery::{self, Stage};

    let n = with_notes([31; 32], Http::new(None)?).await?;
    let (rt, wallet, chain, mine) = (&n.rt, &n.wallet, &n.chain, &n.mine);
    let id = n.contract.id;
    let before = scan(wallet, chain).await?;
    let keyset = *n.hub.info().keysets[0].id();
    let notes = wallet.claimed_notes(&id, &keyset)?;
    ensure!(notes.is_empty(), "claimed before she closed");

    let txid = holder::close(wallet, chain, &mine.join("wallet.sqlite"), &id).await?;
    // Her notes left her balance and are claimed in a close awaiting its
    // fold; the contract counts as closed. What she funded it with is hers.
    ensure!(available(wallet)? == 65_536 + n.contract.funded);
    let rows = recovery::recoveries(&mine.join("wallet.sqlite"))?;
    ensure!(rows.len() == 1, "{rows:?}");
    let row = &rows[0];
    ensure!(
        row.stage == Stage::Folding && row.irrevocable && (row.claimed, row.notes) == (131_071, 2),
        "{row:?}"
    );
    ensure!(holder::list(&mine.join("wallet.sqlite"))?[0].folded == Some(txid));
    // Asked again with its fold in the mempool: the hub refuses before she
    // signs another, and nothing of hers changes.
    let again = holder::close(wallet, chain, &mine.join("wallet.sqlite"), &id).await;
    ensure!(
        again
            .as_ref()
            .is_err_and(|e| format!("{e:#}").contains("spent")),
        "{again:?}"
    );
    ensure!(recovery::recoveries(&mine.join("wallet.sqlite"))?[0].stage == Stage::Folding);

    // The hub retired her notes before it signed.
    let claimed = wallet.claimed_notes(&id, &keyset)?;
    let ys = (claimed.iter())
        .map(|c| c.note.message().identifier())
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(n.hub.spent(&ys)? == vec![true; 2]);

    rt.mine(1)?;
    // Her claim and her reserve at her wallet, the rest the hub's less the
    // fee: her notes' value beyond her cap is not paid.
    let fold = rt.get_tx(&txid)?;
    ensure!(fold.output.len() == 2, "{fold:?}");
    ensure!(
        fold.output[0].value.to_sat() == 131_071 + 20_000,
        "{fold:?}"
    );
    ensure!(scan(wallet, chain).await? == before + 151_071);
    let rate = FeeRate::from_sat_per_vb(2).context("a rate")?;
    let done = recovery::advance(wallet, chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(
        done.len() == 1
            && done[0].stage == Stage::Done
            && done[0].fold == Some(txid)
            && done[0].received == Some(151_071)
            && done[0].claimed == 131_071,
        "{done:?}"
    );
    // Her notes stay out of her balance for good.
    ensure!(available(wallet)? == 65_536 + n.contract.funded);
    // The hub posts no default, now or at the close.
    let round = n.openings.answer_requests().await?;
    ensure!(round == Default::default(), "{round:?}");
    rt.mine(u64::from(n.contract.close_height) - u64::from(rt.height()?) + 1)?;
    let round = n.openings.answer_requests().await?;
    ensure!(round == Default::default(), "{round:?}");
    ensure!(scan(wallet, chain).await? == before + 151_071);
    Ok(())
}

/// A note of the claim the hub spent is not paid by a fold, which has no
/// dispute to cite the spend in: the hub refuses it before she signs, and
/// her wallet, shown the spend, checks it, drops the note, takes the change
/// the spend paid and closes on the rest.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_fold_the_hub_refuses_for_a_spent_note_is_made_again_on_what_it_proves() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    // The copy claims four notes, the one paid away among them: the hub
    // refuses it, and the copy proves it spent, takes the change and folds
    // on what is left.
    let s = stale_copy([32; 32], Http::new(None)?).await?;
    let (rt, wallet, chain, mine, id) = (&s.rt, &s.wallet, &s.chain, &s.mine, s.id);
    ensure!(available(wallet)? == 131_072 + s.funded);
    let txid = holder::close(wallet, chain, &mine.join("wallet.sqlite"), &id).await?;
    let rows = recovery::recoveries(&mine.join("wallet.sqlite"))?;
    ensure!(rows.len() == 1, "{rows:?}");
    ensure!(
        rows[0].stage == Stage::Folding && rows[0].irrevocable,
        "{:?}",
        rows[0]
    );
    // Three of the four notes held and the change of the spend that
    // retired the fourth, less than the cap of them all.
    ensure!(
        rows[0].claimed < 131_071 && rows[0].claimed >= 98_304,
        "{:?}",
        rows[0]
    );
    ensure!(holder::list(&mine.join("wallet.sqlite"))?[0].folded == Some(txid));
    // Nothing the hub holds anything against is left held.
    let spent = wallet.check().await?;
    ensure!(spent == Default::default(), "{spent:?}");
    rt.mine(1)?;
    Ok(())
}

/// [`Http`], but the hub shows no evidence of any note asked about, as a hub
/// that refuses notes it calls spent and proves nothing would.
struct Hushed(Http);

impl licash_wallet::Transport for Hushed {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        if url.ends_with(licash_api::INQUIRE) {
            let asked: licash_api::Inquire =
                serde_json::from_slice(&body.ok_or("no body")?).map_err(|e| e.to_string())?;
            let none = vec![Vec::new(); asked.notes.len()];
            return Ok(licash_wallet::Response {
                status: 200,
                body: serde_json::to_vec(&licash_api::Evidenced::new(&none))
                    .map_err(|e| e.to_string())?,
            });
        }
        self.0.request(url, body).await
    }
}

/// A hub that calls a note spent and shows no spend of it is not believed:
/// nothing is dropped, the close stops before she signs, her notes are back
/// in her balance and her contract is open, to force closed on them all.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_fold_refused_for_a_note_the_hub_does_not_prove_spent_stops() -> Result<()> {
    use licash_contracts::holder::recovery;

    let s = stale_copy([34; 32], Hushed(Http::new(None)?)).await?;
    let (rt, wallet, chain, mine, id) = (&s.rt, &s.wallet, &s.chain, &s.mine, s.id);
    ensure!(available(wallet)? == 131_072 + s.funded);
    let closed = holder::close(wallet, chain, &mine.join("wallet.sqlite"), &id).await;
    ensure!(
        closed
            .as_ref()
            .is_err_and(|e| format!("{e:#}").contains("no proof")),
        "{closed:?}"
    );
    ensure!(
        available(wallet)? == 131_072 + s.funded,
        "notes dropped or not given back"
    );
    ensure!(recovery::recoveries(&mine.join("wallet.sqlite"))?.is_empty());
    ensure!(holder::list(&mine.join("wallet.sqlite"))?[0]
        .folded
        .is_none());
    ensure!(holder::list(&mine.join("wallet.sqlite"))?[0].live(rt.height()?));
    Ok(())
}

/// [`Http`], but the request to sign a fold lost: the hub is never told
/// of her signature, as a hub that took her claim and does not fold.
struct NoFoldSign(Http);

impl licash_wallet::Transport for NoFoldSign {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        if body.is_some() && url.ends_with("/fold/sign") {
            return Err("lost".into());
        }
        self.0.request(url, body).await
    }
}

/// [`Http`], with a stranger who knows her contract's id meddling in her
/// fold: before her partial signature reaches the hub, he asks the hub for
/// a fold on what she asked, without her signature, then sends it a
/// partial signature of nothing. What the hub answered him, kept.
struct Meddled {
    http: Http,
    asked: std::sync::Mutex<Option<(String, Vec<u8>)>>,
    answered: Arc<std::sync::Mutex<Vec<u16>>>,
}

impl licash_wallet::Transport for Meddled {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        if let Some(body) = &body {
            if url.ends_with("/fold") || url.ends_with("/fold/claim") {
                *self.asked.lock().unwrap() = Some((url.to_owned(), body.clone()));
            }
            if url.ends_with("/fold/sign") {
                let (to, mut asked) = self.asked.lock().unwrap().clone().ok_or("not asked")?;
                asked.truncate(asked.len().saturating_sub(64));
                let offer = self.http.request(&to, Some(asked)).await?;
                let partial = self.http.request(url, Some(vec![0; 32])).await?;
                self.answered
                    .lock()
                    .unwrap()
                    .extend([offer.status, partial.status]);
            }
        }
        self.http.request(url, body).await
    }
}

/// A fold is offered to its holder alone: a stranger is refused one of
/// the contract, and a partial signature that does not check takes
/// nothing, so her fold, offered before, is signed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_fold_offered_to_her_is_neither_replaced_nor_taken_by_a_stranger() -> Result<()> {
    let answered = Arc::default();
    let meddled = Meddled {
        http: Http::new(None)?,
        asked: Default::default(),
        answered: Arc::clone(&answered),
    };
    let n = with_notes([35; 32], meddled).await?;
    let (wallet, chain, mine) = (&n.wallet, &n.chain, &n.mine);
    let txid = holder::close(wallet, chain, &mine.join("wallet.sqlite"), &n.contract.id).await?;
    ensure!(holder::list(&mine.join("wallet.sqlite"))?[0].folded == Some(txid));
    let answered = answered.lock().unwrap().clone();
    ensure!(answered == [400, 400], "{answered:?}");
    Ok(())
}

/// A fold the hub never signs leaves her claim to file: her recovery waits
/// for the fold, then forces the contract closed on the same notes by
/// itself, before it is too late, and is paid as a forced close is.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_fold_the_hub_never_signs_gives_way_to_her_request_on_the_same_claim() -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::recovery::{self, Stage};

    let n = with_notes([33; 32], NoFoldSign(Http::new(None)?)).await?;
    let (rt, wallet, chain, mine) = (&n.rt, &n.wallet, &n.chain, &n.mine);
    let id = n.contract.id;
    let rate = FeeRate::from_sat_per_vb(2).context("a rate")?;

    let closed = holder::close(wallet, chain, &mine.join("wallet.sqlite"), &id).await;
    ensure!(closed.is_err(), "{closed:?}");
    let rows = recovery::recoveries(&mine.join("wallet.sqlite"))?;
    ensure!(
        rows.len() == 1 && rows[0].stage == Stage::Folding && rows[0].irrevocable,
        "{rows:?}"
    );
    ensure!((rows[0].claimed, rows[0].notes) == (131_071, 2), "{rows:?}");
    ensure!(available(wallet)? == 65_536 + n.contract.funded);

    // Block by block: waiting for the fold, then her request, the hub's
    // timeout paying her, the claim she pinned the same.
    let mut now = rows[0].clone();
    let mut forced = false;
    for _ in 0..600 {
        if now.stage == Stage::Done {
            break;
        }
        rt.mine(1)?;
        let round = n.openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        now = recovery::advance(wallet, chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(now.stage != Stage::Lost, "{now:?}");
        forced |= now.stage != Stage::Folding;
    }
    ensure!(forced, "never forced closed");
    ensure!(
        now.stage == Stage::Done && now.claimed == 131_071 && now.fold.is_none(),
        "{now:?}"
    );
    let swept = rt.get_tx(&now.sweep.context("no sweep")?)?.output[0].value;
    ensure!(swept.to_sat() > 131_071, "{swept} swept");
    Ok(())
}

/// The JSON-RPC of `rt`'s node: of its wallet `wallet`, if any.
fn rpc_of(rt: &Regtest, wallet: Option<&str>) -> Result<Source> {
    let wallet = wallet.map(|w| format!("/wallet/{w}")).unwrap_or_default();
    format!("{}{wallet}?cookie={}", rt.rpc_url(), rt.cookie().display()).parse()
}

/// A wallet of `rt`'s node without private keys, `cold`, watching the
/// taproot descriptor of another, `cold-keys`, which stands for a signer
/// kept offline: its JSON-RPC.
async fn watch_only(rt: &Regtest) -> Result<Source> {
    use serde_json::{json, Value};
    let node = rpc_of(rt, None)?;
    let _: Value = node.rpc("createwallet", json!(["cold-keys"])).await?;
    let listed: Value = rpc_of(rt, Some("cold-keys"))?
        .rpc("listdescriptors", json!([]))
        .await?;
    let descriptor = listed["descriptors"]
        .as_array()
        .context("no descriptors")?
        .iter()
        .filter(|d| d["internal"] == false)
        .filter_map(|d| d["desc"].as_str())
        .find(|d| d.starts_with("tr("))
        .context("no taproot descriptor")?
        .to_owned();
    // Named, without private keys, blank.
    let _: Value = node
        .rpc("createwallet", json!(["cold", true, true]))
        .await?;
    let cold = rpc_of(rt, Some("cold"))?;
    let import = json!([[{
        "desc": descriptor,
        "active": true,
        "internal": false,
        "timestamp": "now",
        "range": [0, 100],
    }]]);
    let imported: Value = cold.rpc("importdescriptors", import).await?;
    ensure!(imported[0]["success"] == true, "{imported}");
    Ok(cold)
}

/// Whether `address` is of the wallet `wallet` names.
async fn is_mine(wallet: &Source, address: &str) -> Result<bool> {
    let info: serde_json::Value = wallet
        .rpc("getaddressinfo", serde_json::json!([address]))
        .await?;
    info["ismine"].as_bool().context("no ismine")
}

/// A hub told of a payout wallet is paid its share of a contract ended by
/// default there, at an address of a descriptor its funding wallet holds
/// no key of, and ends the contract all the same.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_is_paid_its_share_of_a_default_at_its_payout_wallet() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, _, openings) = hub_answering(&rt, &dir.path().join("hub")).await?;
    let cold = watch_only(&rt).await?;
    openings.pay_out_to(cold.clone()).await?;
    let chain = Node(source.clone());
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, [41; 32], &[COIN]).await?;
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;

    rt.mine(u64::from(opened.close_height) - u64::from(rt.height()?))?;
    let round = openings.answer_requests().await?;
    ensure!(round.closed == 1 && round.failed == 0, "{round:?}");
    rt.mine(1)?;

    // Her reserve at the hub's close deposit; the rest at the payout wallet,
    // and at no address of the wallet that funded it.
    ensure!(scan(&wallet, &chain).await? == 0);
    let f = opened.funding.context("no F")?;
    let funding: serde_json::Value = source
        .rpc(
            "getrawtransaction",
            serde_json::json!([f.to_string(), true]),
        )
        .await?;
    let value = funding["vout"][0]["value"]
        .as_f64()
        .context("no contract output")?;
    let share = (value * 1e8).round() as u64 - 20_000;
    let coins: serde_json::Value = cold.rpc("listunspent", serde_json::json!([1])).await?;
    let coins = coins.as_array().context("no coins")?;
    ensure!(coins.len() == 1, "{coins:?}");
    let sats = (coins[0]["amount"].as_f64().context("no amount")? * 1e8).round() as u64;
    ensure!(sats == share, "{sats} of {share}");
    let address = coins[0]["address"].as_str().context("no address")?;
    ensure!(
        !is_mine(&source, address).await?,
        "paid to the funding wallet"
    );
    // Ended: the hub looks for its share in no wallet.
    let after = openings.answer_requests().await?;
    ensure!(after == Default::default(), "{after:?}");
    Ok(())
}

/// A hub told of a payout wallet is paid its share of a contract its
/// holder closes early there too: the fold pays the script the contract
/// was opened with.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_is_paid_its_share_of_a_fold_at_its_payout_wallet() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, hub, openings) = hub_answering(&rt, &dir.path().join("hub")).await?;
    let cold = watch_only(&rt).await?;
    openings.pay_out_to(cold.clone()).await?;
    let chain = Node(source.clone());
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, [43; 32], &[COIN]).await?;
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?;
    funded_in(
        &rt,
        &hub,
        &source,
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
    )
    .await?;

    let txid = holder::close(&wallet, &chain, &mine.join("wallet.sqlite"), &opened.id).await?;
    rt.mine(1)?;
    ensure!(scan(&wallet, &chain).await? == 20_000 + opened.funded);
    let fold: serde_json::Value = source
        .rpc(
            "getrawtransaction",
            serde_json::json!([txid.to_string(), true]),
        )
        .await?;
    let outs = fold["vout"].as_array().context("no outputs")?;
    ensure!(outs.len() == 2, "{fold}");
    let address = outs[1]["scriptPubKey"]["address"]
        .as_str()
        .context("no address")?;
    ensure!(is_mine(&cold, address).await?, "not the payout wallet's");
    ensure!(
        !is_mine(&source, address).await?,
        "paid to the funding wallet"
    );
    // The hub posts no default, and ends it.
    let round = openings.answer_requests().await?;
    ensure!(round == Default::default(), "{round:?}");
    Ok(())
}

/// A hub whose payout wallet gives no address opens no contract: it never
/// pays its funding wallet instead.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_opens_no_contract_its_payout_wallet_gives_no_address_for() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, _, openings) = hub_answering(&rt, &dir.path().join("hub")).await?;
    // A wallet its node never loaded.
    openings.pay_out_to(rpc_of(&rt, Some("absent"))?).await?;
    let chain = Node(source);
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, [47; 32], &[COIN]).await?;
    let refused = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await;
    ensure!(
        refused
            .as_ref()
            .is_err_and(|e| format!("{e:#}").contains("payout wallet")),
        "{refused:?}"
    );
    ensure!(openings.load()?.live == 0, "an opening started");
    Ok(())
}

/// As [`hub_serving`], and its openings, for a test to answer a holder's
/// request with.
async fn hub_answering(
    rt: &Regtest,
    dir: &Path,
) -> Result<(String, Source, Arc<Hub>, Arc<Openings>)> {
    hub_answering_with(rt, dir, None).await
}

/// As [`hub_answering`], holders choosing their terms within `range`, if
/// any.
async fn hub_answering_with(
    rt: &Regtest,
    dir: &Path,
    range: Option<Range>,
) -> Result<(String, Source, Arc<Hub>, Arc<Openings>)> {
    hub_answering_through(rt, dir, range, |app, _| app).await
}

/// As [`hub_answering_with`], its service made by `serve` of the hub
/// service's router and its contracts.
async fn hub_answering_through(
    rt: &Regtest,
    dir: &Path,
    range: Option<Range>,
    serve: impl FnOnce(axum::Router, Arc<Openings>) -> axum::Router,
) -> Result<(String, Source, Arc<Hub>, Arc<Openings>)> {
    hub_answering_following(rt, dir, range, true, serve).await
}

/// As [`hub_answering`], the hub following no chain yet: for a test of what
/// it answers then, which follows it itself.
async fn hub_answering_unfollowed(
    rt: &Regtest,
    dir: &Path,
) -> Result<(String, Source, Arc<Hub>, Arc<Openings>)> {
    hub_answering_following(rt, dir, None, false, |app, _| app).await
}

/// As [`hub_answering_through`], the hub following the chain at first if
/// `follow`: an opening takes a deposit of its for her reserve, which it
/// gives only once it does.
async fn hub_answering_following(
    rt: &Regtest,
    dir: &Path,
    range: Option<Range>,
    follow: bool,
    serve: impl FnOnce(axum::Router, Arc<Openings>) -> axum::Router,
) -> Result<(String, Source, Arc<Hub>, Arc<Openings>)> {
    std::fs::create_dir_all(dir)?;
    let (seed, db) = (dir.join("seed"), dir.join("hub.sqlite"));
    Hub::init(&seed, &db, NOTE_POW)?;
    let hub = Arc::new(Hub::open(&seed, &db, Policy::default())?);
    let url = format!(
        "{}/wallet/harness?cookie={}",
        rt.rpc_url(),
        rt.cookie().display()
    );
    let source: Source = url.parse()?;
    let keyset = hub.info().keysets[0].clone();
    let openings = Openings::with_wallet(dir, source.clone(), source.clone(), keyset, range);
    let openings = openings.await?;
    // Its ledger against holders' claims, as the hub service's.
    licash_hub_service::answer_from(&openings, hub.clone());
    let deposits = deposits_for(&hub, &source, dir, &openings)?;
    if follow {
        followed(&hub, &source, &deposits).await?;
    }
    let services = Services {
        contracts: Some(openings.clone()),
        deposits: Some(deposits),
        ..Default::default()
    };
    let app = serve(
        licash_hub_service::router(hub.clone(), services),
        openings.clone(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok((url, source, hub, openings))
}

/// [`Node`], but stalling at its first broadcast, kept: as a holder whose
/// app stops once the hub signed F, before it hands F to the network or
/// tells the hub, which would broadcast it too.
struct Stalling {
    node: Node,
    f: std::sync::Mutex<Option<bitcoin::Transaction>>,
}

impl licash_wallet::Blocks for Stalling {
    async fn height(&self) -> Result<u32, String> {
        self.node.height().await
    }

    async fn hash(&self, height: u32) -> Result<bitcoin::BlockHash, String> {
        self.node.hash(height).await
    }

    async fn filter(&self, hash: &bitcoin::BlockHash) -> Result<Option<Vec<u8>>, String> {
        self.node.filter(hash).await
    }

    async fn block(&self, hash: &bitcoin::BlockHash) -> Result<bitcoin::Block, String> {
        self.node.block(hash).await
    }
}

impl holder::Chain for Stalling {
    async fn checkpoint(&self, height: u32) -> Result<licash::chain::Checkpoint, String> {
        self.node.checkpoint(height).await
    }

    async fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), String> {
        self.f.lock().unwrap().get_or_insert_with(|| tx.clone());
        std::future::pending().await
    }

    async fn fee_rate(&self, blocks: u16) -> Result<Option<bitcoin::FeeRate>, String> {
        self.node.fee_rate(blocks).await
    }
}

/// An opening at `url` by `wallet` (of `mine`) stalled once the hub signed
/// F, before F is broadcast: F.
async fn stalled_opening(
    wallet: &Wallet<Http>,
    source: &Source,
    mine: &Path,
    url: &str,
) -> Result<bitcoin::Transaction> {
    let stalling = Stalling {
        node: Node(source.clone()),
        f: Default::default(),
    };
    let reached = async {
        while stalling.f.lock().unwrap().is_none() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    };
    let file = mine.join("wallet.sqlite");
    tokio::select! {
        opened = holder::open(wallet, &stalling, &file, url, ask()) => {
            anyhow::bail!("opened, never stalled: {opened:?}")
        }
        () = reached => {}
    }
    let f = stalling.f.lock().unwrap().clone();
    f.context("no F")
}

/// The hub frees the coins of an opening it signed whose F never confirms:
/// at once once her deposit is spent elsewhere, deep; else, a day after it
/// first saw F in no block (or once F may no longer fund its contract),
/// by spending one of its own coins F spends back to its wallet.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_frees_the_coins_of_an_opening_it_signed_whose_f_never_confirms() -> Result<()> {
    use bitcoin::FeeRate;
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let hub_dir = dir.path().join("hub");
    let (url, source, _, openings) = hub_answering(&rt, &hub_dir).await?;
    let chain = Node(source.clone());
    let locked = || async {
        let locked: Vec<serde_json::Value> = chain
            .0
            .rpc("listlockunspent", serde_json::json!([]))
            .await?;
        anyhow::Ok(locked.len())
    };
    let gettxout = |coin: bitcoin::OutPoint, mempool: bool| {
        let chain = &chain;
        async move {
            let args = serde_json::json!([coin.txid.to_string(), coin.vout, mempool]);
            let out: Option<serde_json::Value> = chain.0.rpc_optional("gettxout", args).await?;
            anyhow::Ok(out.is_some_and(|out| !out.is_null()))
        }
    };

    // Three holders whose apps stop once the hub signed their F.
    let mut stalled = Vec::new();
    for (n, seed) in [[41; 32], [42; 32], [43; 32]].into_iter().enumerate() {
        let at = dir.path().join(format!("holder{n}"));
        std::fs::create_dir(&at)?;
        let (mine, wallet) = holder_wallet(&rt, &chain, &at, &url, seed, &[COIN]).await?;
        let deposit = wallet.silent_coins()?[0].outpoint;
        let f = stalled_opening(&wallet, &source, &mine, &url).await?;
        ensure!(f.input.iter().any(|i| i.previous_output == deposit));
        stalled.push((wallet, f, deposit));
    }
    ensure!(licash_contracts::hub::signed(&hub_dir)? == 3);
    openings.answer_requests().await?;
    let seen = rt.height()?;

    // One's F broadcast late, once the hub saw it in no block: its
    // contract stands, its coins never spent back.
    let late = stalled.pop().context("three")?.1;
    rt.send_raw(&late)?;
    rt.mine(1)?;
    openings.answer_requests().await?;
    let held = locked().await?;
    ensure!(held >= 2, "{held} coins locked");

    // Her deposit spent elsewhere: given up once that is deep, its coins
    // unlocked.
    let (wallet, f, deposit) = &stalled[1];
    wallet.abandon_silent(&f.compute_txid())?;
    let to = wallet.fallback_address()?.script_pubkey();
    let rate = FeeRate::from_sat_per_vb_u32(2);
    let elsewhere =
        wallet.spend_silent_coin(licash_wallet::Payee::Script(to), *deposit, None, rate)?;
    rt.send_raw(&elsewhere)?;
    rt.mine(5)?;
    openings.answer_requests().await?;
    ensure!(
        licash_contracts::hub::signed(&hub_dir)? == 3,
        "given up 5 deep"
    );
    rt.mine(1)?;
    openings.answer_requests().await?;
    ensure!(
        licash_contracts::hub::signed(&hub_dir)? == 2,
        "not given up 6 deep"
    );
    let mid = locked().await?;
    ensure!(mid < held, "{mid} of {held} coins locked");

    // The other: one of the hub's coins F spends is spent back to its
    // wallet, not at once, a day after F was first seen in no block at
    // the latest.
    let (_, f, deposit) = &stalled[0];
    let hub_coins: Vec<bitcoin::OutPoint> = (f.input.iter())
        .map(|i| i.previous_output)
        .filter(|o| o != deposit)
        .collect();
    let spent_back = || async {
        for coin in &hub_coins {
            if gettxout(*coin, false).await? && !gettxout(*coin, true).await? {
                return anyhow::Ok(true);
            }
        }
        anyhow::Ok(false)
    };
    ensure!(!spent_back().await?, "spent back at once");
    let mut at = None;
    while rt.height()? < seen + 144 {
        rt.mine(1)?;
        openings.answer_requests().await?;
        if spent_back().await? {
            at = Some(rt.height()?);
            break;
        }
    }
    let at = at.context("no coin of the hub's spent back")?;
    ensure!(at > seen + 1, "spent back at {at}, first seen at {seen}");
    ensure!(gettxout(*deposit, true).await?, "her deposit spent");
    // Deep: given up, its coins unlocked. The late one stands.
    rt.mine(6)?;
    openings.answer_requests().await?;
    ensure!(
        licash_contracts::hub::signed(&hub_dir)? == 1,
        "not given up"
    );
    let contract = bitcoin::OutPoint::new(late.compute_txid(), 0);
    ensure!(gettxout(contract, false).await?, "the late contract gone");
    let left = locked().await?;
    ensure!(left < mid, "{left} of {mid} coins locked");
    Ok(())
}

/// `from`'s files copied into `to`, made.
fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// A wallet of `seed` in `dir`'s `wallet`, trusting the hub at `url`,
/// with coins of `coins` sat on Bitcoin, in a block: its directory too.
async fn holder_wallet(
    rt: &Regtest,
    chain: &Node,
    dir: &Path,
    url: &str,
    seed: [u8; 32],
    coins: &[u64],
) -> Result<(std::path::PathBuf, Wallet<Http>)> {
    holder_wallet_over(
        rt,
        chain,
        &dir.join("wallet"),
        url,
        seed,
        coins,
        Http::new(None)?,
    )
    .await
}

/// As [`holder_wallet`], in `mine`, over `transport`.
async fn holder_wallet_over<T: licash_wallet::Transport>(
    rt: &Regtest,
    chain: &Node,
    mine: &Path,
    url: &str,
    seed: [u8; 32],
    coins: &[u64],
    transport: T,
) -> Result<(std::path::PathBuf, Wallet<T>)> {
    let mine = mine.to_path_buf();
    std::fs::create_dir(&mine)?;
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(&mine.join("wallet.sqlite"), &seed, regtest, transport)?;
    wallet.add_hub(url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    for sats in coins {
        let to = wallet.fallback_address()?.script_pubkey();
        rt.fund(&to, Amount::from_sat(*sats))?;
    }
    rt.mine(1)?;
    ensure!(scan(&wallet, chain).await? == coins.iter().sum::<u64>());
    Ok((mine, wallet))
}

fn available<T: licash_wallet::Transport>(wallet: &Wallet<T>) -> Result<u64> {
    Ok(wallet.balance()?.iter().map(|b| b.available).sum())
}

/// What each contract in `mine` protecting notes at `tip` would claim of
/// `wallet`'s notes now, by id ([`holder::coverage`]): none of one under
/// recovery.
fn recoverable(
    wallet: &Wallet<Http>,
    mine: &Path,
    tip: u32,
) -> Result<std::collections::HashMap<[u8; 32], u64>> {
    holder::coverage(
        wallet,
        &mine.join("wallet.sqlite"),
        &holder::list(&mine.join("wallet.sqlite"))?,
        tip,
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_holder_recovers_her_cap_of_notes_beyond_it_from_a_hub_that_answered() -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub, openings) = hub_answering_with(&rt, &at, Some(range)).await?;
    let chain = Node(source.clone());
    let (mine, wallet) =
        holder_wallet(&rt, &chain, dir.path(), &url, [10; 32], &[COIN, COIN]).await?;
    let chosen = Ask {
        cap: Some(131_071),
        ..ask()
    };
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, chosen).await?;
    ensure!(opened.cap == 131_071, "{opened:?}");
    funded_in(
        &rt,
        &hub,
        &source,
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
    )
    .await?;
    let rate = FeeRate::from_sat_per_vb(2).context("a rate")?;
    // Four notes of 32 768 sat: three recover 98 304 of her cap, four all
    // of it.
    for _ in 0..4 {
        let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 32_768)?;
        wallet.receive(&payment)?;
    }
    ensure!(available(&wallet)? == 131_072 + opened.funded);
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    // What it protects: its cap, of the four.
    let each = recoverable(&wallet, &mine, rt.height()?)?;
    ensure!(each.get(&opened.id) == Some(&131_071), "{each:?}");

    // Forced closed: the notes claimed for her cap, their excess lost.
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    ensure!(forced.stage == Stage::Claimed, "{forced:?}");
    ensure!((forced.claimed, forced.notes) == (131_071, 4), "{forced:?}");
    // What she funded it with is hers, past her cap.
    ensure!(available(&wallet)? == opened.funded);
    rt.mine_to_height(forced.next_at.context("no lock")? - 1)?;
    let sent = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(sent[0].stage == Stage::Published, "{sent:?}");
    rt.mine(1)?;
    let requested = recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    let requested = &requested[0];
    ensure!(requested.stage == Stage::Requested, "{requested:?}");

    // A claim of her cap is owed all of it: the hub, playing her exit,
    // posts nothing, and her timeout pays her.
    let mut now = requested.clone();
    for _ in 0..400 {
        if now.stage == Stage::Done {
            break;
        }
        ensure!(now.stage != Stage::Answered, "{now:?}");
        rt.mine(1)?;
        let round = openings.answer_requests().await?;
        ensure!(round.answered == 0 && round.failed == 0, "{round:?}");
        now =
            recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
    }
    ensure!(
        now.stage == Stage::Done && now.claimed == 131_071,
        "{now:?}"
    );
    let swept = rt.get_tx(&now.sweep.context("no sweep")?)?.output[0].value;
    let swept = swept.to_sat();
    ensure!(swept > 131_071, "{swept} swept");
    eprintln!("swept {swept} sat to her wallet of a claim of 131071");
    Ok(())
}

/// A stale claim requested at a hub that answers: she restores a copy of
/// her wallet made before she paid a note away and forces her contract
/// closed on it, claiming her cap of 131 071 sat in four notes of 32 768.
struct Stale {
    rt: Regtest,
    _dir: tempfile::TempDir,
    hub: Arc<Hub>,
    openings: Arc<Openings>,
    chain: Node,
    wallet: Wallet<Http>,
    mine: std::path::PathBuf,
    rate: bitcoin::FeeRate,
}

async fn stale_claim(seed: [u8; 32]) -> Result<Stale> {
    stale_claim_scanned(seed, false).await
}

/// As [`stale_claim`], its hub's ledger scanned, if `scanned`, to before
/// her request.
async fn stale_claim_scanned(seed: [u8; 32], scanned: bool) -> Result<Stale> {
    stale_claim_after(seed, scanned, |_| ()).await
}

/// A dishonest holder's filings for as long as it lives
/// ([`licash_contracts::holder::recovery::forge_filings`]): honest again
/// when the test ends, however it does.
struct Forging;

impl Forging {
    fn of(forge: licash_contracts::holder::recovery::Forge) -> Self {
        licash_contracts::holder::recovery::forge_filings(Some(forge));
        Self
    }
}

impl Drop for Forging {
    fn drop(&mut self) {
        licash_contracts::holder::recovery::forge_filings(None);
    }
}

/// `bytes`, those of `filing`, with the issuance proof of its settled note
/// `at` no longer the issuer's: a note never issued, to the statement that
/// reads them, signed for by its hold key all the same.
fn never_issued(filing: &licash::recovery::Filing, at: usize, mut bytes: Vec<u8>) -> Vec<u8> {
    let note = filing.witness().notes[at].to_compact_bytes();
    let found: Vec<usize> = (bytes.windows(note.len()).enumerate())
        .filter(|(_, w)| *w == note)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(found.len(), 1, "a note's bytes, once in its filing");
    // C, the kind of its proof, then the proof: the last byte of that.
    bytes[found[0] + 33 + 1 + 63] ^= 1;
    bytes
}

/// As [`stale_claim_scanned`], with `before` run on its hub before she
/// forces her contract closed.
async fn stale_claim_after(
    seed: [u8; 32],
    scanned: bool,
    before: impl FnOnce(&Arc<Hub>),
) -> Result<Stale> {
    use licash_contracts::holder::recovery;

    let StaleCopy {
        rt,
        dir,
        hub,
        openings,
        source,
        chain,
        wallet,
        mine,
        id,
        rate,
        funded: _,
    } = stale_copy(seed, Http::new(None)?).await?;
    if scanned {
        while !watch::step(&hub, &source).await? {}
    }
    before(&hub);
    let forced =
        recovery::force_close(&wallet, &chain, &mine.join("wallet.sqlite"), &id, rate).await?;
    ensure!((forced.claimed, forced.notes) == (131_071, 4), "{forced:?}");
    rt.mine_to_height(forced.next_at.context("no lock")? - 1)?;
    recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    rt.mine(1)?;
    Ok(Stale {
        rt,
        _dir: dir,
        hub,
        openings,
        chain,
        wallet,
        mine,
        rate,
    })
}

/// A contract of cap 131 071 sat at a hub that answers, four notes of 32 768
/// in a wallet, and a copy of that wallet made before one was paid away,
/// restored over `transport`: it claims, as it holds, the note paid away
/// too, which the hub knows spent. Nothing is closed.
struct StaleCopy<T: licash_wallet::Transport> {
    rt: Regtest,
    dir: tempfile::TempDir,
    hub: Arc<Hub>,
    openings: Arc<Openings>,
    source: Source,
    chain: Node,
    wallet: Wallet<T>,
    mine: std::path::PathBuf,
    id: [u8; 32],
    /// What she funded the contract with herself, in sat: in her notes.
    funded: u64,
    rate: bitcoin::FeeRate,
}

async fn stale_copy<T: licash_wallet::Transport>(
    seed: [u8; 32],
    transport: T,
) -> Result<StaleCopy<T>> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub, openings) = hub_answering_with(&rt, &at, Some(range)).await?;
    let chain = Node(source.clone());
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, seed, &[COIN, COIN]).await?;
    let chosen = Ask {
        cap: Some(131_071),
        ..ask()
    };
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, chosen).await?;
    let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
    funded_in(
        &rt,
        &hub,
        &source,
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
    )
    .await?;
    for _ in 0..4 {
        let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 32_768)?;
        wallet.receive(&payment)?;
    }
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(available(&wallet)? == 131_072 + opened.funded);

    // Her wallet as it was, copied; then a note of it paid away.
    drop(wallet);
    let stale = dir.path().join("stale");
    copy_dir(&mine, &stale)?;
    let wallet = Wallet::open(&mine.join("wallet.sqlite"), Http::new(None)?)?;
    let bob = licash::address::OwnerKeys::from_seed(&[0xbb; 32])?.address();
    wallet.send(&url, &bob, 32_768).await?;
    let left = available(&wallet)?;
    ensure!(left < 131_072, "{left} left");
    drop(wallet);

    // Restored, the copy claims the note paid away too.
    let wallet = Wallet::open(&stale.join("wallet.sqlite"), transport)?;
    Ok(StaleCopy {
        rt,
        dir,
        hub,
        openings,
        source,
        chain,
        wallet,
        mine: stale,
        id: opened.id,
        funded: opened.funded,
        rate,
    })
}

/// The hub's answers to a stale claim and hers, a block at a time while
/// `hub` says the hub plays, until her recovery is done: it.
async fn played(
    s: &Stale,
    mut hub: impl FnMut(&licash_contracts::holder::recovery::Recovery) -> bool,
) -> Result<licash_contracts::holder::recovery::Recovery> {
    use licash_contracts::holder::recovery::{self, Stage};

    let mut last = None;
    for _ in 0..800 {
        s.rt.mine(1)?;
        if last.as_ref().is_none_or(&mut hub) {
            let round = s.openings.answer_requests().await?;
            ensure!(round.failed == 0, "{round:?}");
        }
        let r = recovery::advance(&s.wallet, &s.chain, &s.mine.join("wallet.sqlite"), s.rate)
            .await?[0]
            .clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            return Ok(r);
        }
        last = Some(r);
    }
    anyhow::bail!("never paid: {last:?}")
}

/// The hub meets the stale claim with the spend it released, discloses
/// that spend's unlock and responds what is left. Her wallet, shown what it
/// responded on, checks it, finds it borne out and lets it stand: nothing
/// is contested or proven, and her payout is what the response says.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_meets_a_stale_claim_with_the_spend_it_released_and_pays_what_is_left() -> Result<()>
{
    let s = stale_claim([11; 32]).await?;
    let done = played(&s, |_| true).await?;
    let x = done.response.context("no response")?;
    ensure!(s.rt.confirmations(&x)?.is_some(), "{done:?}");
    // Its disclose slot spent: the unlock published.
    ensure!(!s.rt.is_unspent(&bitcoin::OutPoint { txid: x, vout: 2 })?);
    // Her notes less the one paid away: three of 32 768.
    let corrected = done.corrected.context("no response")?;
    ensure!(corrected == 98_304, "{done:?}");
    // Paid by the response's own terminal: no contest, no proof.
    ensure!(
        done.assertion.is_none() && done.challenge.is_none(),
        "{done:?}"
    );
    ensure!(done.payout.is_some() && done.timeout.is_none(), "{done:?}");
    let received = done.received.context("nothing received")?;
    eprintln!("a stale claim of 131071 paid {corrected}, {received} swept to her wallet");
    Ok(())
}

/// The notes of `dir`'s hub that claims on Bitcoin retired.
fn retired(dir: &Path) -> Result<i64> {
    let db = rusqlite::Connection::open(dir.join("hub").join("hub.sqlite"))?;
    Ok(db.query_row("SELECT count(*) FROM claimed", [], |r| r.get(0))?)
}

/// A stale claim one note of which was never issued, as its filing shows
/// it: her wallet's copy claims the note she paid away, and files another
/// of her notes with an issuance proof that is not the issuer's. The
/// contract's statement owes that note nothing and the rest as ever, and
/// so does the hub: it reads the claim its statement decides on, meets
/// the note paid away with the spend it released, responds what the two
/// others are worth, and retires all four, which she signed for. A hub
/// that read no claim in such a filing answered nothing, paid her all she
/// claimed at her timeout and left the four hers to claim again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_meets_a_stale_claim_of_a_note_never_issued_with_the_spend_it_released() -> Result<()>
{
    let mut forging = None;
    let s = stale_claim_after([21; 32], false, |hub| {
        let ledger = hub.clone();
        forging = Some(Forging::of(Box::new(move |filing, bytes| {
            // The note paid away, as the hub's ledger holds its spend:
            // another is the one never issued.
            let held = ledger.evidence(filing.publication().claim()).unwrap();
            let spent: Vec<_> = (held.iter())
                .flat_map(|e| match e {
                    licash::recovery::Evidence::Spend { notes, .. } => notes.clone(),
                    _ => Vec::new(),
                })
                .map(|n| n.message().identifier().unwrap())
                .collect();
            assert_eq!(spent.len(), 1);
            let notes = &filing.witness().notes;
            let at = (notes.iter())
                .position(|n| !spent.contains(&n.message().identifier().unwrap()))
                .unwrap();
            never_issued(filing, at, bytes)
        })));
    })
    .await?;
    ensure!(retired(s._dir.path())? == 0);
    let done = played(&s, |_| true).await?;
    let x = done.response.context("no response")?;
    ensure!(s.rt.confirmations(&x)?.is_some(), "{done:?}");
    // Its disclose slot spent: the unlock of the spend published.
    ensure!(!s.rt.is_unspent(&bitcoin::OutPoint { txid: x, vout: 2 })?);
    // Her notes less the one paid away and the one never issued.
    ensure!(done.corrected == Some(65_536), "{done:?}");
    ensure!(
        done.assertion.is_none() && done.challenge.is_none(),
        "{done:?}"
    );
    ensure!(done.payout.is_some() && done.timeout.is_none(), "{done:?}");
    // All four retired, the one never issued too: none is claimed again.
    ensure!(retired(s._dir.path())? == 4);
    drop(forging);
    Ok(())
}

/// A hub that cannot read its ledger answers a claim it proves owed less
/// without it: of the stale claim one note was never issued, as its
/// filing shows it, which the contract's statement finds with no evidence
/// at all. While its ledger may yet answer it waits; half the blocks to
/// respond in gone, it tells its operator, once, and responds what the
/// three other notes are worth, the note paid away among them: less than
/// its ledger would have saved it, and more than no answer.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_whose_ledger_gives_no_evidence_answers_on_what_it_proves_without() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let mut forging = None;
    let s = stale_claim_after([22; 32], false, |_| {
        forging = Some(Forging::of(Box::new(|filing, bytes| {
            never_issued(filing, 0, bytes)
        })));
    })
    .await?;
    let told = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let alerts = told.clone();
    s.openings.alert_with(Arc::new(move |message: &str| {
        alerts.lock().unwrap().push(message.to_owned())
    }));
    let count = |of: &str| {
        let told = told.lock().unwrap();
        told.iter().filter(|m| m.contains(of)).count()
    };
    // Its ledger changed under it: halted, it reads nothing more.
    let db = rusqlite::Connection::open(s._dir.path().join("hub").join("hub.sqlite"))?;
    db.execute("UPDATE meta SET seq = seq + 1", [])?;
    drop(db);
    ensure!(s.hub.alert("halt").is_err() && s.hub.halted());

    let (mut waited, mut done) = (0, None);
    for _ in 0..800 {
        s.rt.mine(1)?;
        let round = s.openings.answer_requests().await?;
        // While it waits for its ledger it answers nothing, and tells
        // nobody it will.
        if count("what it proves without") == 0 {
            ensure!(round.answered == 0, "{round:?}");
            waited += round.failed;
        }
        let r = recovery::advance(&s.wallet, &s.chain, &s.mine.join("wallet.sqlite"), s.rate)
            .await?[0]
            .clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(waited > 0, "the hub never waited for its ledger");
    ensure!(
        count("what it proves without") == 1 && count("cannot decide its answer") == 0,
        "{:?}",
        told.lock().unwrap()
    );
    let x = done.response.context("no response")?;
    ensure!(s.rt.confirmations(&x)?.is_some(), "{done:?}");
    // Nothing cited, nothing disclosed.
    ensure!(s.rt.is_unspent(&bitcoin::OutPoint { txid: x, vout: 2 })?);
    ensure!(done.corrected == Some(98_304), "{done:?}");
    ensure!(done.payout.is_some() && done.timeout.is_none(), "{done:?}");
    drop(forging);
    Ok(())
}

/// A hub whose wallet funds no fee coin, as one out of coins or locked,
/// answers a stale claim all the same: its response goes at its presigned
/// fee, with no fee child, and its operator is told once. A hub that gave
/// up its response for want of the coin that would have raised its fee
/// answered nothing, and her timeout paid her all she claimed. Its wallet
/// funded again, it plays on to the payout of what it responded.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_whose_wallet_funds_no_fee_coin_responds_at_its_presigned_fee() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let s = stale_claim([24; 32]).await?;
    let told = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let alerts = told.clone();
    s.openings.alert_with(Arc::new(move |message: &str| {
        alerts.lock().unwrap().push(message.to_owned())
    }));
    s.openings.fund_no_fee_coins(true);
    let mut response = None;
    for _ in 0..800 {
        s.rt.mine(1)?;
        // A round that cannot pay for all it would post fails, and posts
        // what needs no coin.
        s.openings.answer_requests().await?;
        let r = recovery::advance(&s.wallet, &s.chain, &s.mine.join("wallet.sqlite"), s.rate)
            .await?[0]
            .clone();
        ensure!(r.stage != Stage::Lost && r.timeout.is_none(), "{r:?}");
        ensure!(r.stage != Stage::Done, "paid with no response: {r:?}");
        if let Some(x) = r.response {
            if s.rt.confirmations(&x)?.is_some() {
                response = Some(x);
                break;
            }
        }
    }
    let x = response.context("no response")?;
    // At its presigned fee, its anchor unspent: no fee child.
    paid_its_way(&s.rt, &x)?;
    ensure!(s.rt.is_unspent(&bitcoin::OutPoint { txid: x, vout: 1 })?);
    let unfunded = || {
        let told = told.lock().unwrap();
        told.iter()
            .filter(|m| m.contains("funds no fee coin"))
            .count()
    };
    ensure!(unfunded() == 1, "{:?}", told.lock().unwrap());

    s.openings.fund_no_fee_coins(false);
    let done = played(&s, |_| true).await?;
    ensure!(done.response == Some(x), "{done:?}");
    ensure!(done.corrected == Some(98_304), "{done:?}");
    ensure!(done.payout.is_some() && done.timeout.is_none(), "{done:?}");
    ensure!(unfunded() == 1, "{:?}", told.lock().unwrap());
    Ok(())
}

/// A lock of hers the hub certified and never settled is refunded on
/// Bitcoin: her force close past its expiry at depth claims its refund
/// beside her notes, and the hub, once its ledger scanned her claim's
/// block, finds it owed all she asks: her timeout pays it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_force_close_claims_an_unsettled_locks_refund_once_expired_at_depth() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub, openings) = hub_answering_with(&rt, &at, Some(range)).await?;
    let chain = Node(source.clone());
    let (mine, wallet) =
        holder_wallet(&rt, &chain, dir.path(), &url, [17; 32], &[COIN, COIN]).await?;
    // Long enough for her exit to close it after the lock's refund is owed.
    let chosen = Ask {
        cap: Some(131_071),
        blocks: 1_000,
        ..ask()
    };
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, chosen).await?;
    for _ in 0..3 {
        let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 2_048)?;
        wallet.receive(&payment)?;
    }
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(available(&wallet)? == 6_144);

    // A lock to Bob the hub certifies, then never asked to settle.
    while !watch::step(&hub, &source).await? {}
    let expiry = rt.height()? + 6;
    let bob = licash::address::OwnerKeys::from_seed(&[0xbb; 32])?.address();
    let hash = licash::spend::lock_hash(&[7; 32]);
    // One owed its refund only after her contract closes is refused.
    let late = (holder::list(&mine.join("wallet.sqlite"))?
        .iter()
        .map(|c| c.assert_height)
        .max())
    .context("no contract")?;
    let refused = wallet.lock(&url, &bob, 1_000, hash, Some(late)).await;
    ensure!(
        matches!(&refused, Err(licash_wallet::Error::Invalid(why)) if why.contains("unprotected")),
        "{refused:?}"
    );
    let lock = wallet.lock(&url, &bob, 1_000, hash, Some(expiry)).await?;
    ensure!(lock.state == licash_wallet::LockState::Locked, "{lock:?}");
    let left = available(&wallet)?;
    ensure!(left == 4_096, "{left} left");
    // Past its expiry at any depth the hub takes.
    rt.mine_to_height(expiry + 12)?;
    while !watch::step(&hub, &source).await? {}

    let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    // Her two notes, and the lock's refund less the hub's fee.
    let refund = forced.claimed - 4_096 - opened.funded;
    ensure!(
        forced.notes == 2 && refund > 1_000 && refund <= 2_048,
        "{forced:?}"
    );
    rt.mine_to_height(forced.next_at.context("no lock")? - 1)?;
    recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    let mut done = None;
    for _ in 0..800 {
        rt.mine(1)?;
        while !watch::step(&hub, &source).await? {}
        let round = openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        let r =
            recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(
        done.response.is_none() && done.timeout.is_some() && done.payout == done.timeout,
        "{done:?}"
    );
    // Its hub refunds it no more, nor pays it.
    let followed = wallet.follow_lock(&lock.id).await?;
    ensure!(
        followed.state == licash_wallet::LockState::Locked,
        "{followed:?}"
    );
    Ok(())
}

/// A transport that loses every request to make a lock: its hub never
/// sees one, nor certifies it.
struct NoLock(Http);

impl licash_wallet::Transport for NoLock {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        if body.is_some() && url.ends_with(licash_api::LOCK) {
            return Err("lost".into());
        }
        self.0.request(url, body).await
    }
}

/// A lock of hers whose request never reached the hub, so never
/// certified, is refunded on Bitcoin all the same: her force close past
/// its expiry at depth claims its refund on its own inputs, which she
/// signed, beside her notes, and the hub, which never saw it, finds it
/// owed all she asks: her timeout pays it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_force_close_claims_the_refund_of_a_lock_its_hub_never_certified() -> Result<()> {
    uncertified_refund([18; 32], || ()).await?;
    Ok(())
}

/// The force close of a holder past the expiry of a lock of hers her hub
/// never heard of, played to its end, her timeout paying her notes and the
/// lock's refund; `before` run before she files. Her hub's directory and
/// ledger.
async fn uncertified_refund(
    seed: [u8; 32],
    before: impl FnOnce(),
) -> Result<(tempfile::TempDir, Arc<Hub>)> {
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub, openings) = hub_answering_with(&rt, &at, Some(range)).await?;
    let chain = Node(source.clone());
    let (mine, wallet) = holder_wallet_over(
        &rt,
        &chain,
        &dir.path().join("wallet"),
        &url,
        seed,
        &[COIN, COIN],
        NoLock(Http::new(None)?),
    )
    .await?;
    let chosen = Ask {
        cap: Some(131_071),
        blocks: 1_000,
        ..ask()
    };
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, chosen).await?;
    for _ in 0..3 {
        let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 2_048)?;
        wallet.receive(&payment)?;
    }
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(available(&wallet)? == 6_144);

    // A lock to Bob the hub never hears of.
    while !watch::step(&hub, &source).await? {}
    let expiry = rt.height()? + 6;
    let bob = licash::address::OwnerKeys::from_seed(&[0xbb; 32])?.address();
    let hash = licash::spend::lock_hash(&[7; 32]);
    let lost = wallet.lock(&url, &bob, 1_000, hash, Some(expiry)).await;
    ensure!(
        matches!(&lost, Err(licash_wallet::Error::Pending { .. })),
        "{lost:?}"
    );
    let left = available(&wallet)?;
    ensure!(left == 4_096, "{left} left");
    rt.mine_to_height(expiry + 12)?;
    while !watch::step(&hub, &source).await? {}

    before();
    let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    // Her two notes, and the lock's refund less the hub's fee.
    let refund = forced.claimed - 4_096 - opened.funded;
    ensure!(
        forced.notes == 2 && refund > 1_000 && refund <= 2_048,
        "{forced:?}"
    );
    rt.mine_to_height(forced.next_at.context("no lock")? - 1)?;
    recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?;
    let mut done = None;
    for _ in 0..800 {
        rt.mine(1)?;
        while !watch::step(&hub, &source).await? {}
        let round = openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        let r =
            recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(
        done.response.is_none() && done.timeout.is_some() && done.payout == done.timeout,
        "{done:?}"
    );
    Ok((dir, hub))
}

/// The refund of such a lock claimed with a signature that is not its
/// input's hold key's: the statement of a lean contract, which verifies no
/// hold signature of a lock's inputs, owes it all the same, and her
/// timeout pays it. Her hub, shown the lock in her filing, signed by the
/// input's owner, retires that note by it: no spend takes it after, and
/// the lock is its answer to any other claim of it. A hub that retired
/// only what hold keys signed for left the note hers to spend or to claim
/// again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_retires_the_input_of_a_lock_whose_refund_is_claimed_without_its_hold_key(
) -> Result<()> {
    use licash::recovery::{Evidence, SourceWitness};

    let input = Arc::new(std::sync::Mutex::new(None));
    let mut forging = None;
    let seen = input.clone();
    let (dir, hub) = uncertified_refund([23; 32], || {
        forging = Some(Forging::of(Box::new(move |filing, mut bytes| {
            let [SourceWitness::Signed { notes, .. }] = &filing.witness().sources[..] else {
                panic!("not one lock on its own inputs");
            };
            let [note] = &notes[..] else {
                panic!("not a lock of one note");
            };
            let records = filing.publication().envelope().records();
            let record = (records.iter())
                .find(|r| &r.message == note.message())
                .expect("her wallet signs for the input");
            let sig = &record.sig.0[..];
            let found: Vec<usize> = (bytes.windows(sig.len()).enumerate())
                .filter(|(_, w)| *w == sig)
                .map(|(i, _)| i)
                .collect();
            assert_eq!(found.len(), 1, "a hold signature, once in its filing");
            bytes[found[0] + sig.len() - 1] ^= 1;
            *seen.lock().unwrap() = Some(note.clone());
            bytes
        })));
    })
    .await?;
    drop(forging);
    let note = input.lock().unwrap().clone().context("nothing filed")?;
    let y = note.message().identifier()?;
    // Retired, by the lock and no hold key's word, and spent by nothing.
    ensure!(hub.spent(&[y])? == [true]);
    let db = rusqlite::Connection::open(dir.path().join("hub").join("hub.sqlite"))?;
    let rows = |sql: &str| -> Result<i64> { Ok(db.query_row(sql, [&y.0], |r| r.get(0))?) };
    ensure!(rows("SELECT count(*) FROM shown_inputs WHERE y = ?1")? == 1);
    ensure!(rows("SELECT count(*) FROM claimed WHERE y = ?1")? == 0);
    ensure!(rows("SELECT count(*) FROM spent WHERE y = ?1")? == 0);
    // Against a claim of it in any other contract: the lock, which voids
    // it to whoever checks.
    let keyset = (hub.info().keysets.into_iter())
        .find(|k| k.id() == note.keyset_id())
        .context("no keyset of the note's")?;
    let context = licash::claim::Context {
        base: [9; 32],
        deposit: [8; 36],
        cap: 131_071,
    };
    let parts = licash::claim::Parts {
        items: vec![licash::claim::Item::Settled(note.message().clone())],
        sources: vec![],
        activations: vec![],
        authorizations: vec![note.message().clone()],
    };
    let again = licash::claim::UnsignedClaim::new(context, &keyset, 1, parts, 16)?;
    let found = hub.evidence(&again)?;
    let [lock @ Evidence::Spend { unlock: None, .. }] = &found[..] else {
        anyhow::bail!("not the lock alone: {} found", found.len());
    };
    ensure!(licash::recovery::voids_note(&keyset, note.message(), lock)?);
    Ok(())
}

/// A transport that loses every request to release a payment: its hub
/// holds its offer, never its owner's signature.
struct NoRelease(Http);

impl licash_wallet::Transport for NoRelease {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        if body.is_some() && url.ends_with(licash_api::RELEASE) {
            return Err("lost".into());
        }
        self.0.request(url, body).await
    }
}

/// A payment she signed whose release never reached the hub: her force
/// close claims its notes beside her others, its change named as a
/// fallback, and the hub, which never released it, finds it owed all she
/// asks: her timeout pays it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_force_close_claims_the_notes_of_a_payment_its_hub_never_released() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub, openings) = hub_answering_with(&rt, &at, Some(range)).await?;
    let chain = Node(source.clone());
    let (mine, wallet) = holder_wallet_over(
        &rt,
        &chain,
        &dir.path().join("wallet"),
        &url,
        [19; 32],
        &[COIN, COIN],
        NoRelease(Http::new(None)?),
    )
    .await?;
    let chosen = Ask {
        cap: Some(131_071),
        blocks: 1_000,
        ..ask()
    };
    let opened = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, chosen).await?;
    for _ in 0..3 {
        let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 2_048)?;
        wallet.receive(&payment)?;
    }
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(available(&wallet)? == 6_144);

    // A payment to Bob signed, its release lost.
    let bob = licash::address::OwnerKeys::from_seed(&[0xbb; 32])?.address();
    let lost = wallet.send(&url, &bob, 1_000).await;
    ensure!(
        matches!(&lost, Err(licash_wallet::Error::Pending { .. })),
        "{lost:?}"
    );
    ensure!(available(&wallet)? == 4_096);
    while !watch::step(&hub, &source).await? {}

    // A rate her reserve affords whatever the payment's shape: its filing
    // carries the payment's signed spend, grant and all, whose size varies
    // with the outputs its change was shaped into (at 2 sat/vB, near the
    // reserve's 17,658 sat, some shapes outgrew it and asked her to allow
    // more).
    let rate = bitcoin::FeeRate::from_sat_per_vb(1).context("a rate")?;
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    // Her two notes, and the payment's.
    ensure!(
        forced.notes == 3 && forced.claimed == 6_144 + opened.funded,
        "{forced:?}"
    );
    let mut done = None;
    let mut last = None;
    for _ in 0..800 {
        rt.mine(1)?;
        while !watch::step(&hub, &source).await? {}
        let round = openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        let r =
            recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
        last = Some(r);
    }
    let done = done.with_context(|| format!("never paid: {last:?}"))?;
    ensure!(
        done.response.is_none() && done.timeout.is_some() && done.payout == done.timeout,
        "{done:?}"
    );
    Ok(())
}

/// A transport that loses every request to settle a lock: its hub never
/// learns a preimage from the wallet.
struct NoSettle(Http);

impl licash_wallet::Transport for NoSettle {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        if body.is_some() && url.contains(licash_api::SETTLE) {
            return Err("lost".into());
        }
        self.0.request(url, body).await
    }
}

/// A lock paying her whose settle never reaches its hub is owed to her
/// on Bitcoin: as its expiry nears unpaid, her wallet activates it with a
/// coin of hers, records the activation once confirmed, and her force
/// close past it at depth claims its pay branch beside her notes; the
/// hub, finding it owed all she asks, lets her timeout pay it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_force_close_claims_a_lock_paying_her_once_activated_at_depth() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};
    use licash_contracts::holder::{activation, exit};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub, openings) = hub_answering_with(&rt, &at, Some(range)).await?;
    // As the hub service: every lock named after a contract opens is
    // anchored no earlier than its Base.
    licash_hub_service::open_on_lock_checkpoints(&openings, hub.clone());
    while !watch::step(&hub, &source).await? {}
    let chain = Node(source.clone());
    let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
    let (mine, bob) = holder_wallet_over(
        &rt,
        &chain,
        &dir.path().join("bob"),
        &url,
        [18; 32],
        &[COIN, COIN],
        NoSettle(Http::new(None)?),
    )
    .await?;
    let chosen = Ask {
        cap: Some(131_071),
        blocks: 1_000,
        ..ask()
    };
    let opened = holder::open(&bob, &chain, &mine.join("wallet.sqlite"), &url, chosen).await?;
    let payment = pay(&hub, &at.join("seed"), &url, &bob.address(), 2_048)?;
    bob.receive(&payment)?;
    rt.mine(1)?;
    holder::resume(&bob, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(available(&bob)? == 2_048);

    // Alice, of no contract, locks 1 000 to him.
    let (_, alice) = holder_wallet(&rt, &chain, dir.path(), &url, [17; 32], &[]).await?;
    for _ in 0..2 {
        let payment = pay(&hub, &at.join("seed"), &url, &alice.address(), 2_048)?;
        alice.receive(&payment)?;
    }
    while !watch::step(&hub, &source).await? {}
    let preimage = [9; 32];
    let expiry = rt.height()? + 40;
    let lock = (alice.lock(
        &url,
        &bob.address(),
        1_000,
        licash::spend::lock_hash(&preimage),
        Some(expiry),
    ))
    .await?;
    ensure!(lock.state == licash_wallet::LockState::Locked, "{lock:?}");
    // His claim never reaches the hub: owed to him, provable.
    ensure!(bob.claim(&url, &lock.id, &preimage).await.is_err());
    let owed = bob.owed_locks()?;
    ensure!(owed.len() == 1 && owed[0].anchor.is_some(), "{owed:?}");
    let depth = owed[0].depth;

    // Not yet near its expiry: nothing done.
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.is_empty(), "{kept:?}");
    let lead = activation::lead();
    rt.mine_to_height(expiry - lead)?;
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.len() == 1 && kept[0].step == "activated", "{kept:?}");
    let script = bitcoin::ScriptBuf::from_bytes(licash::chain::activation_script(&preimage));
    let first = bob.silent_spends_paying(&script)?[0].tx.compute_txid();
    // Left out of blocks a quarter of its lead: bumped, paying the same.
    for _ in 0..lead / 4 {
        rt.mine_with(&[])?;
    }
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.len() == 1 && kept[0].step == "bumped", "{kept:?}");
    let spends = bob.silent_spends_paying(&script)?;
    ensure!(spends.len() == 2, "{spends:?}");
    let bumped = spends
        .iter()
        .find(|s| s.tx.compute_txid() != first)
        .context("no bump")?;
    let old = spends
        .iter()
        .find(|s| s.tx.compute_txid() == first)
        .context("no first")?;
    ensure!(bumped.fee > old.fee, "{spends:?}");
    rt.mine(1)?;
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.len() == 1 && kept[0].step == "confirmed", "{kept:?}");
    ensure!(rt.confirmations(&bumped.tx.compute_txid())?.is_some());
    let activated = (bob.owed_locks()?[0].activated_at).context("not recorded")?;
    ensure!(
        activated < expiry,
        "activated at {activated}, expiring at {expiry}"
    );
    // Done: nothing more until claimed.
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.is_empty(), "{kept:?}");
    // Her exit counts it as what only this contract's forced close claims.
    let exits = exit::drive(
        &bob,
        &chain,
        &mine.join("wallet.sqlite"),
        &NoProvider,
        144,
        rate,
    )
    .await?;
    ensure!(
        exits.len() == 1 && exits[0].owed > opened.funded && exits[0].owed <= opened.funded + 1_000,
        "{exits:?}"
    );

    rt.mine_to_height(expiry.max(activated + depth) + 1)?;
    while !watch::step(&hub, &source).await? {}
    let forced =
        recovery::force_close(&bob, &chain, &mine.join("wallet.sqlite"), &opened.id, rate).await?;
    // His note, and the lock's pay branch.
    // And her part of the contract, not issued her yet.
    let paid = forced.claimed - 2_048 - opened.funded;
    ensure!(forced.notes == 1 && paid > 0 && paid <= 1_000, "{forced:?}");
    ensure!(bob.owed_locks()?[0].claimed);
    let mut done = None;
    for _ in 0..800 {
        rt.mine(1)?;
        while !watch::step(&hub, &source).await? {}
        let round = openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        let r =
            recovery::advance(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(
        done.response.is_none() && done.timeout.is_some() && done.payout == done.timeout,
        "{done:?}"
    );
    Ok(())
}

/// His activation's block replaced, the chain shorter for a while: the
/// activation forgotten, then found again in the block that holds it now,
/// and his forced close claims the lock with that one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn an_activation_whose_block_leaves_the_chain_is_found_again_and_claimed() -> Result<()> {
    use bitcoincore_rpc::RpcApi as _;
    use licash_contracts::holder::recovery::{self, Stage};
    use licash_contracts::holder::{activation, exit};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub, openings) = hub_answering_with(&rt, &at, Some(range)).await?;
    licash_hub_service::open_on_lock_checkpoints(&openings, hub.clone());
    while !watch::step(&hub, &source).await? {}
    let chain = Node(source.clone());
    let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
    let (mine, bob) = holder_wallet_over(
        &rt,
        &chain,
        &dir.path().join("bob"),
        &url,
        [18; 32],
        &[COIN, COIN],
        NoSettle(Http::new(None)?),
    )
    .await?;
    let chosen = Ask {
        cap: Some(131_071),
        blocks: 1_000,
        ..ask()
    };
    let opened = holder::open(&bob, &chain, &mine.join("wallet.sqlite"), &url, chosen).await?;
    let payment = pay(&hub, &at.join("seed"), &url, &bob.address(), 2_048)?;
    bob.receive(&payment)?;
    rt.mine(1)?;
    holder::resume(&bob, &chain, &mine.join("wallet.sqlite")).await?;

    let (_, alice) = holder_wallet(&rt, &chain, dir.path(), &url, [17; 32], &[]).await?;
    for _ in 0..2 {
        let payment = pay(&hub, &at.join("seed"), &url, &alice.address(), 2_048)?;
        alice.receive(&payment)?;
    }
    while !watch::step(&hub, &source).await? {}
    let preimage = [9; 32];
    let expiry = rt.height()? + 40;
    let lock = (alice.lock(
        &url,
        &bob.address(),
        1_000,
        licash::spend::lock_hash(&preimage),
        Some(expiry),
    ))
    .await?;
    ensure!(lock.state == licash_wallet::LockState::Locked, "{lock:?}");
    ensure!(bob.claim(&url, &lock.id, &preimage).await.is_err());
    let depth = bob.owed_locks()?[0].depth;

    let lead = activation::lead();
    rt.mine_to_height(expiry - lead)?;
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.len() == 1 && kept[0].step == "activated", "{kept:?}");
    rt.mine(1)?;
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.len() == 1 && kept[0].step == "confirmed", "{kept:?}");
    let first = (bob.owed_locks()?[0].activated_at).context("not recorded")?;

    // Its block replaced, nothing yet in its place: forgotten, not an
    // error, and still what only this contract's forced close claims.
    let replaced = rt.rpc.get_block_hash(u64::from(first))?;
    rt.rpc.invalidate_block(&replaced)?;
    ensure!(rt.height()? == first - 1);
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.len() == 1 && kept[0].step == "forgotten", "{kept:?}");
    ensure!(bob.owed_locks()?[0].activated_at.is_none());
    let exits = exit::drive(
        &bob,
        &chain,
        &mine.join("wallet.sqlite"),
        &NoProvider,
        144,
        rate,
    )
    .await?;
    ensure!(
        exits.len() == 1 && exits[0].owed > opened.funded && exits[0].owed <= opened.funded + 1_000,
        "{exits:?}"
    );
    // A block of none of it, then one of it: found again there.
    rt.mine_with(&[])?;
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.iter().all(|k| k.error.is_none()), "{kept:?}");
    ensure!(bob.owed_locks()?[0].activated_at.is_none());
    rt.mine(1)?;
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.len() == 1 && kept[0].step == "confirmed", "{kept:?}");
    let again = (bob.owed_locks()?[0].activated_at).context("not found again")?;
    ensure!(again == first + 1 && again < expiry, "{first} then {again}");
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.is_empty(), "{kept:?}");

    rt.mine_to_height(expiry.max(again + depth) + 1)?;
    while !watch::step(&hub, &source).await? {}
    let forced =
        recovery::force_close(&bob, &chain, &mine.join("wallet.sqlite"), &opened.id, rate).await?;
    // And her part of the contract, not issued her yet.
    let paid = forced.claimed - 2_048 - opened.funded;
    ensure!(forced.notes == 1 && paid > 0 && paid <= 1_000, "{forced:?}");
    let mut done = None;
    for _ in 0..800 {
        rt.mine(1)?;
        while !watch::step(&hub, &source).await? {}
        let round = openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        let r =
            recovery::advance(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(done.payout.is_some(), "{done:?}");
    Ok(())
}

/// A hub whose ledger follows the chain, its scan stopped before her
/// request, still meets a claim of no lock with the spend it holds: only
/// a claim of a lock waits for the scan of its block.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_meets_a_claim_of_no_lock_while_its_ledgers_scan_lags() -> Result<()> {
    let s = stale_claim_scanned([13; 32], true).await?;
    let done = played(&s, |_| true).await?;
    ensure!(done.corrected == Some(98_304), "{done:?}");
    let scanned = s.hub.scanned()?.context("no scan")?.0;
    // Before her request, so before her publication.
    let requested = done.requested_at.context("no request")?;
    ensure!(
        scanned < requested,
        "scanned to {scanned}, requested at {requested}"
    );
    Ok(())
}

/// The hub responds to the stale claim and shows her no evidence of it, so
/// that she contests, and stops: its assertion window passes, and her
/// contest's timeout pays her all she claimed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_that_responds_and_never_asserts_pays_her_whole_claim() -> Result<()> {
    let s = stale_claim([12; 32]).await?;
    s.openings.refuse_evidence();
    // The hub plays until she sees its response, then no more.
    let done = played(&s, |r| r.response.is_none()).await?;
    ensure!(done.assertion.is_none(), "{done:?}");
    ensure!(done.corrected == Some(98_304), "{done:?}");
    ensure!(done.timeout.is_some(), "not her timeout: {done:?}");
    let received = done.received.context("nothing received")?;
    ensure!(
        received > 131_071,
        "{received} of a claim of 131071: {done:?}"
    );
    Ok(())
}

/// A hub whose ledger gives no evidence against the stale claim, as one
/// halted, responds nothing on evidence it cannot read: the operator is
/// alerted of that contract once, and her timeout pays her all she
/// claimed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_whose_ledger_gives_no_evidence_alerts_and_pays_her_whole_claim() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let s = stale_claim([20; 32]).await?;
    let told = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let alerts = told.clone();
    s.openings.alert_with(Arc::new(move |message: &str| {
        alerts.lock().unwrap().push(message.to_owned())
    }));
    let undecided = || {
        let told = told.lock().unwrap();
        told.iter()
            .filter(|m| m.contains("cannot decide its answer"))
            .count()
    };
    // Its ledger changed under it: halted, it reads nothing more.
    let db = rusqlite::Connection::open(s._dir.path().join("hub").join("hub.sqlite"))?;
    db.execute("UPDATE meta SET seq = seq + 1", [])?;
    drop(db);
    ensure!(s.hub.alert("halt").is_err() && s.hub.halted());

    let (mut failed, mut done) = (0, None);
    for _ in 0..800 {
        s.rt.mine(1)?;
        let round = s.openings.answer_requests().await?;
        ensure!(round.answered == 0, "{round:?}");
        failed += round.failed;
        // Never told before it failed to decide.
        ensure!(failed > 0 || undecided() == 0, "{:?}", told.lock().unwrap());
        let r = recovery::advance(&s.wallet, &s.chain, &s.mine.join("wallet.sqlite"), s.rate)
            .await?[0]
            .clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(failed > 0, "the hub decided");
    ensure!(undecided() == 1, "{:?}", told.lock().unwrap());
    ensure!(
        done.response.is_none() && done.timeout.is_some(),
        "{done:?}"
    );
    ensure!(done.claimed == 131_071, "{done:?}");
    Ok(())
}

/// A hub whose ledger retired her stale note by a spend it can no longer
/// cite (its signed spend unreadable, as one of more than a statement
/// reads would be) is told so at once, on the first round it decides, not
/// half the blocks to respond in later: it answers nothing, and her
/// timeout pays her all she claimed, the loss it was told of.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_holding_evidence_it_cannot_cite_alerts_at_once() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let s = stale_claim([21; 32]).await?;
    let told = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let alerts = told.clone();
    s.openings.alert_with(Arc::new(move |message: &str| {
        alerts.lock().unwrap().push(message.to_owned())
    }));
    let uncited = || {
        let told = told.lock().unwrap();
        told.iter().filter(|m| m.contains("cannot cite")).count()
    };
    // The spend of her stale note, kept as nothing it reads back.
    let db = rusqlite::Connection::open(s._dir.path().join("hub").join("hub.sqlite"))?;
    let broken = db.execute(
        "UPDATE grants SET signed = x'00' WHERE released_at IS NOT NULL",
        [],
    )?;
    ensure!(broken >= 1, "no released spend");
    drop(db);

    let (mut rounds, mut first, mut done) = (0, None, None);
    for _ in 0..800 {
        let round = s.openings.answer_requests().await?;
        ensure!(round.answered == 0 && round.failed == 0, "{round:?}");
        rounds += 1;
        if first.is_none() && uncited() > 0 {
            first = Some(rounds);
        }
        s.rt.mine(1)?;
        let r = recovery::advance(&s.wallet, &s.chain, &s.mine.join("wallet.sqlite"), s.rate)
            .await?[0]
            .clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    // Once, and well before half the blocks to respond in were gone.
    let first = first.context("never told")?;
    ensure!(uncited() == 1, "{:?}", told.lock().unwrap());
    ensure!(first * 4 < rounds, "told on round {first} of {rounds}");
    ensure!(
        done.response.is_none() && done.timeout.is_some(),
        "{done:?}"
    );
    ensure!(done.claimed == 131_071, "{done:?}");
    Ok(())
}

/// A hub that signed its response and lost its response pins signs no
/// other, decided anew: its openings tell it began that answer, and where
/// they tell nothing either, as of a database restored older, its response
/// in the mempool does. The one it broadcast
/// confirms, it proves nothing of evidence it no longer holds, and her
/// response timeout pays her all she claimed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_that_lost_its_pinned_response_signs_no_other() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let s = stale_claim([19; 32]).await?;
    let data = s._dir.path().join("hub");
    let told = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let alerts = told.clone();
    s.openings.alert_with(Arc::new(move |message: &str| {
        alerts.lock().unwrap().push(message.to_owned())
    }));
    let lost = || {
        let told = told.lock().unwrap();
        told.iter()
            .filter(|m| m.contains("response pins no longer hold"))
            .count()
    };
    // Its response signed and broadcast, in no block yet.
    let mut responded = false;
    for _ in 0..50 {
        let round = s.openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        if round.answered == 1 {
            responded = true;
            break;
        }
        s.rt.mine(1)?;
    }
    ensure!(responded && lost() == 0, "{:?}", told.lock().unwrap());
    let db = rusqlite::Connection::open(data.join("hub.sqlite"))?;
    let begun = || {
        db.query_row("SELECT count(*) FROM opening_signing", [], |r| {
            r.get::<_, i64>(0)
        })
    };
    ensure!(begun()? == 1);
    let lose = || db.execute("DELETE FROM response_pins", []);

    // The pins lost: no response is decided anew, and the operator is
    // told, once.
    lose()?;
    for _ in 0..2 {
        let round = s.openings.answer_requests().await?;
        ensure!(round.answered == 0 && round.failed == 0, "{round:?}");
    }
    ensure!(lost() == 1, "{:?}", told.lock().unwrap());

    // Its openings telling nothing either: the mempool does, and it is
    // kept.
    db.execute("DELETE FROM opening_signing", [])?;
    lose()?;
    let round = s.openings.answer_requests().await?;
    ensure!(round.answered == 0 && round.failed == 0, "{round:?}");
    ensure!(begun()? == 1);

    // The response it broadcast confirms; it asserts nothing.
    let mut done = None;
    for _ in 0..800 {
        s.rt.mine(1)?;
        let round = s.openings.answer_requests().await?;
        ensure!(round.answered == 0, "{round:?}");
        let r = recovery::advance(&s.wallet, &s.chain, &s.mine.join("wallet.sqlite"), s.rate)
            .await?[0]
            .clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(
        done.response.is_some() && done.assertion.is_none(),
        "{done:?}"
    );
    ensure!(done.corrected == Some(98_304), "{done:?}");
    ensure!(done.timeout.is_some(), "not her timeout: {done:?}");
    let received = done.received.context("nothing received")?;
    ensure!(
        received > 131_071,
        "{received} of a claim of 131071: {done:?}"
    );
    Ok(())
}

/// A hub whose response is in a block, its response pins lost since: no
/// answer begun and nothing in the mempool tell of it, but it cannot
/// assert on evidence it no longer holds, and the operator is told, once.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_that_lost_what_it_responded_on_is_told_it_asserts_nothing() -> Result<()> {
    let s = stale_claim([21; 32]).await?;
    let data = s._dir.path().join("hub");
    let told = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let alerts = told.clone();
    s.openings.alert_with(Arc::new(move |message: &str| {
        alerts.lock().unwrap().push(message.to_owned())
    }));
    let lost = || {
        let told = told.lock().unwrap();
        told.iter()
            .filter(|m| m.contains("response pins no longer hold"))
            .count()
    };
    let mut responded = false;
    for _ in 0..50 {
        let round = s.openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        if round.answered == 1 {
            responded = true;
            break;
        }
        s.rt.mine(1)?;
    }
    ensure!(responded && lost() == 0, "{:?}", told.lock().unwrap());
    // Its response in a block, then the pins lost: her wallet is shown no
    // evidence, and contests, which the hub cannot answer.
    s.rt.mine(1)?;
    rusqlite::Connection::open(data.join("hub.sqlite"))?
        .execute("DELETE FROM response_pins", [])?;
    for _ in 0..40 {
        let round = s.openings.answer_requests().await?;
        ensure!(round.answered == 0, "{round:?}");
        licash_contracts::holder::recovery::advance(
            &s.wallet,
            &s.chain,
            &s.mine.join("wallet.sqlite"),
            s.rate,
        )
        .await?;
        if lost() > 0 {
            break;
        }
        s.rt.mine(1)?;
    }
    let told = told.lock().unwrap();
    let asserts: Vec<_> = told
        .iter()
        .filter(|m| m.contains("response pins no longer hold"))
        .collect();
    ensure!(
        asserts.len() == 1 && asserts[0].contains("asserts nothing"),
        "{told:?}"
    );
    Ok(())
}

/// Transaction `txid` of a dispute, confirmed on `rt`'s standard node at
/// the fee its graph presigned: at least 1 sat/vB of its actual size,
/// what a node relays by default, with nothing to bump it.
fn paid_its_way(rt: &Regtest, txid: &bitcoin::Txid) -> Result<()> {
    let tx = rt.get_tx(txid)?;
    let mut spent = 0;
    for input in &tx.input {
        let prev = rt.get_tx(&input.previous_output.txid)?;
        spent += prev.output[input.previous_output.vout as usize]
            .value
            .to_sat();
    }
    let made: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let (fee, vsize) = (spent - made, tx.vsize() as u64);
    eprintln!(
        "{txid}: {vsize} vB, {fee} sat, {:.3} sat/vB",
        fee as f64 / vsize as f64
    );
    ensure!(fee >= vsize, "{txid} pays {fee} sat for {vsize} vB");
    ensure!(rt.confirmations(txid)?.is_some(), "{txid} unconfirmed");
    Ok(())
}

/// The fee of `tx`, of transactions the node has.
fn fee_of(rt: &Regtest, tx: &bitcoin::Transaction) -> Result<u64> {
    let mut spent = 0;
    for input in &tx.input {
        let prev = rt.get_tx(&input.previous_output.txid)?;
        spent += prev.output[input.previous_output.vout as usize]
            .value
            .to_sat();
    }
    Ok(spent - tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>())
}

/// That link `txid` confirmed with its poster's fee child, spending its
/// anchor (output 1) in its block, the pair paying `rate` sat/vB at least:
/// as the hub posts a link at 2 sat/vB without an estimate, as on regtest.
fn paid_with_child(rt: &Regtest, txid: &bitcoin::Txid, rate: u64) -> Result<()> {
    let link = rt.get_tx(txid)?;
    let at = rt.confirmations(txid)?.context("unconfirmed")?;
    let anchor = bitcoin::OutPoint {
        txid: *txid,
        vout: 1,
    };
    let child = rt
        .block_txs(at)?
        .into_iter()
        .find(|tx| tx.input.iter().any(|i| i.previous_output == anchor))
        .with_context(|| format!("no fee child of {txid} in block {at}"))?;
    let fee = fee_of(rt, &link)? + fee_of(rt, &child)?;
    let vsize = (link.vsize() + child.vsize()) as u64;
    eprintln!("{txid} and its child: {vsize} vB, {fee} sat");
    ensure!(
        fee >= rate * vsize,
        "{txid} and its child pay {fee} sat for {vsize} vB"
    );
    Ok(())
}

/// The stale claim's request and publication buried, the hub not playing
/// and her timeout not posted: the block her response timeout is valid
/// from, then mined past, her wallet offline.
async fn past_the_response_window(s: &Stale) -> Result<u32> {
    use licash_contracts::holder::recovery::{self, Stage};

    let mut last = None;
    for _ in 0..50 {
        let r = recovery::advance(&s.wallet, &s.chain, &s.mine.join("wallet.sqlite"), s.rate)
            .await?[0]
            .clone();
        if r.stage == Stage::Requested && r.publication.is_some() {
            let window_end = r.next_at.context("no response window")?;
            s.rt.mine_to_height(window_end + 1)?;
            return Ok(window_end);
        }
        last = Some(r);
        s.rt.mine(1)?;
    }
    anyhow::bail!("never requested: {last:?}")
}

/// The response window makes her timeout valid, but does not expire the
/// hub's answer: one confirming after it, before her timeout, still gets
/// a fresh contest window, a fresh assertion window after her contest and
/// her a fresh challenge window after the assertion. Here the hub shows her
/// no evidence, she contests, and the hub proves and asserts, and pays what
/// is left.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hubs_answer_can_confirm_after_its_response_window() -> Result<()> {
    use licash_contracts::holder::recovery;

    let s = stale_claim([15; 32]).await?;
    s.openings.refuse_evidence();
    let window_end = past_the_response_window(&s).await?;
    // The hub plays first: its response confirms strictly after the
    // earliest timeout block.
    let round = s.openings.answer_requests().await?;
    ensure!(round.failed == 0 && round.answered == 1, "{round:?}");
    s.rt.mine(1)?;
    let observed = recovery::advance(&s.wallet, &s.chain, &s.mine.join("wallet.sqlite"), s.rate)
        .await?[0]
        .clone();
    // Told only that she cannot check the response: the hub shows her none.
    ensure!(
        observed
            .error
            .as_deref()
            .is_none_or(|e| e.contains("her check of the hub's response")),
        "{observed:?}"
    );
    ensure!(observed.stage.disputed(), "{observed:?}");
    let x = observed.response.context("no response")?;
    let confirmed_at = s.rt.confirmations(&x)?.context("unconfirmed")?;
    ensure!(confirmed_at > window_end, "{confirmed_at} by {window_end}");
    ensure!(observed.timeout.is_none(), "{observed:?}");
    // Its assertion within the fresh window, then her challenge window.
    let done = played(&s, |_| true).await?;
    ensure!(done.assertion.is_some() && done.proved, "{done:?}");
    ensure!(done.corrected == Some(98_304), "{done:?}");
    ensure!(done.payout.is_some() && done.timeout.is_none(), "{done:?}");
    // The hub's response and assertion relayed and confirmed at their
    // presigned fee, with a fee child each.
    let assertion = done.assertion.context("no assertion")?;
    paid_its_way(&s.rt, &assertion)?;
    paid_with_child(&s.rt, &x, 2)?;
    paid_with_child(&s.rt, &assertion, 2)?;
    Ok(())
}

/// Past the response window, her timeout confirms before the hub's late
/// answer: the timeout wins, and pays her all she claimed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn her_timeout_wins_over_a_late_answer_that_confirms_after_it() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let s = stale_claim([16; 32]).await?;
    past_the_response_window(&s).await?;
    // She plays first: her timeout confirms before the hub plays.
    let r = recovery::advance(&s.wallet, &s.chain, &s.mine.join("wallet.sqlite"), s.rate).await?[0]
        .clone();
    ensure!(r.stage == Stage::TimingOut, "{r:?}");
    s.rt.mine(1)?;
    let done = played(&s, |_| true).await?;
    ensure!(done.response.is_none(), "{done:?}");
    ensure!(done.timeout.is_some(), "not her timeout: {done:?}");
    let received = done.received.context("nothing received")?;
    ensure!(
        received > 131_071,
        "{received} of a claim of 131071: {done:?}"
    );
    Ok(())
}

/// A dishonest hub asserts a proof of another statement: she challenges
/// it, no kept instance answers, and the assertion's failure pays her all
/// she claimed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_holder_challenges_a_false_assertion_and_its_failure_pays_her_whole_claim() -> Result<()>
{
    let s = stale_claim([13; 32]).await?;
    s.openings.refuse_evidence();
    s.openings.assert_false_proofs();
    // A coin for a challenge's fee, as one she held at her forced close:
    // set aside from her next round.
    let reserve = 100_000;
    let to = s.wallet.fallback_address()?.script_pubkey();
    s.rt.fund(&to, Amount::from_sat(reserve))?;
    s.rt.mine(1)?;
    scan(&s.wallet, &s.chain).await?;
    let coins = s.wallet.silent_coins()?;
    let coin = coins
        .iter()
        .find(|c| c.value == reserve)
        .context("no coin")?;
    let coin = coin.outpoint;
    let done = played(&s, |_| true).await?;
    ensure!(done.assertion.is_some() && !done.proved, "{done:?}");
    ensure!(done.challenge.is_some(), "not challenged: {done:?}");
    // Paid by `failure`, a timed payout of her claim and the hub's reserve.
    ensure!(
        done.payout.is_some() && done.timeout == done.payout,
        "{done:?}"
    );
    let received = done.received.context("nothing received")?;
    ensure!(
        received > 131_071,
        "{received} of a claim of 131071: {done:?}"
    );
    // Her challenge and the hub's assertion, each at its presigned fee.
    paid_its_way(&s.rt, &done.assertion.context("no assertion")?)?;
    let challenge = done.challenge.context("no challenge")?;
    paid_its_way(&s.rt, &challenge)?;
    // With a fee child, of the coin set aside, at her 2 sat/vB without an
    // estimate, as on regtest; nothing left set aside.
    paid_with_child(&s.rt, &challenge, 2)?;
    ensure!(!s.rt.is_unspent(&coin)?, "the coin set aside unspent");
    let marker = licash_contracts::holder::recovery::challenge_marker(&done.id);
    let held = s.wallet.silent_coins()?;
    ensure!(held.iter().all(|c| c.spending != Some(marker)), "{held:?}");
    Ok(())
}

/// Her chain, but her claim's publication (P, spending R's claim slot
/// first) never handed to the network: a holder who requests and never
/// publishes.
struct Withholding(Node);

impl licash_wallet::Blocks for Withholding {
    async fn height(&self) -> Result<u32, String> {
        self.0.height().await
    }
    async fn hash(&self, height: u32) -> Result<bitcoin::BlockHash, String> {
        self.0.hash(height).await
    }
    async fn filter(&self, hash: &bitcoin::BlockHash) -> Result<Option<Vec<u8>>, String> {
        self.0.filter(hash).await
    }
    async fn block(&self, hash: &bitcoin::BlockHash) -> Result<bitcoin::Block, String> {
        self.0.block(hash).await
    }
}

impl holder::Chain for Withholding {
    async fn checkpoint(&self, height: u32) -> Result<licash::chain::Checkpoint, String> {
        self.0.checkpoint(height).await
    }
    async fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), String> {
        let publication = tx.input.len() >= 3
            && tx.input[0].previous_output.vout == 2
            && tx.input[1].previous_output.vout == 1
            && tx.input[0].previous_output.txid == tx.input[1].previous_output.txid;
        if publication {
            return Ok(());
        }
        self.0.broadcast(tx).await
    }
}

/// She requests and never publishes her claim: the hub reclaims its slot
/// after k, answers her claim, empty, owed nothing, proves it and asserts;
/// her request's timeout never pays her, and her reserve comes back.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_reclaims_a_claim_never_published_and_answers_it_owed_nothing() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let (url, source, hub, openings) = hub_answering(&rt, &at).await?;
    let node = Node(source.clone());
    let (mine, wallet) =
        holder_wallet(&rt, &node, dir.path(), &url, [14; 32], &[COIN, COIN]).await?;
    let opened = holder::open(&wallet, &node, &mine.join("wallet.sqlite"), &url, ask()).await?;
    let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 3_000)?;
    wallet.receive(&payment)?;
    rt.mine(2)?;
    holder::resume(&wallet, &node, &mine.join("wallet.sqlite")).await?;

    let chain = Withholding(Node(source));
    let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &opened.id,
        rate,
    )
    .await?;
    rt.mine_to_height(forced.next_at.context("no lock")? - 1)?;
    let mut last = None;
    for _ in 0..800 {
        let round = openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        let r =
            recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        ensure!(
            !matches!(r.stage, Stage::TimingOut | Stage::TimedOut),
            "{r:?}"
        );
        if r.stage == Stage::Done {
            last = Some(r);
            break;
        }
        last = Some(r);
        rt.mine(1)?;
    }
    let done = last.context("no recovery")?;
    ensure!(done.stage == Stage::Done, "never done: {done:?}");
    // Her request confirmed, her publication never; the hub's response,
    // its assertion and `success` did.
    let r = done.request.context("no R")?;
    ensure!(rt.confirmations(&r)?.is_some(), "{done:?}");
    let p = done.publication.context("no P")?;
    // Unknown to the node: never published.
    ensure!(rt.get_tx(&p).is_err(), "P published: {done:?}");
    let slot = bitcoin::OutPoint { txid: r, vout: 2 };
    ensure!(!rt.is_unspent(&slot)?, "slot never reclaimed");
    ensure!(done.corrected == Some(0), "{done:?}");
    ensure!(done.assertion.is_some() && done.proved, "{done:?}");
    ensure!(
        done.payout.is_some() && done.timeout.is_none(),
        "not success: {done:?}"
    );
    // Her purse, R's, never spent by a P: swept back to her.
    let purse = bitcoin::OutPoint { txid: r, vout: 3 };
    ensure!(!rt.is_unspent(&purse)?, "purse stranded: {done:?}");
    ensure!(
        done.sweep.is_some() && done.received.is_some_and(|sat| sat > 10_000),
        "purse not swept: {done:?}"
    );
    eprintln!("reclaimed: {done:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn her_contracts_at_a_hub_each_claim_their_share_of_her_notes() -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let (url, source, hub) = hub_serving(&rt, &at, None).await?;
    let chain = Node(source);
    let coins = [COIN, COIN];
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, [11; 32], &coins).await?;
    let mut both = [
        holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?,
        holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask()).await?,
    ];
    // The one asserting first served first: by id, of the same deadline.
    both.sort_by_key(|c| (c.assert_height, c.id));
    let [first, later] = both;
    ensure!(first.cap == 131_071 && later.cap == 131_071);
    let rate = FeeRate::from_sat_per_vb(2).context("a rate")?;
    // 65 536 twice, 32 768 and 16 384: within their caps together, the
    // first taking the three smaller, which fit its cap, the later the
    // other 65 536.
    for sat in [65_536, 65_536, 49_152] {
        let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), sat)?;
        wallet.receive(&payment)?;
    }
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    let tip = rt.height()?;
    let each = recoverable(&wallet, &mine, tip)?;
    let shares = (each.get(&first.id), each.get(&later.id));
    ensure!(shares == (Some(&114_688), Some(&65_536)), "{each:?}");

    // The later forced closed first: its share only, not the smaller
    // notes within its cap too, which the first would then miss.
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &later.id,
        rate,
    )
    .await?;
    ensure!(forced.stage == Stage::Claimed, "{forced:?}");
    // And what she funded it with, not issued her yet.
    ensure!(
        (forced.claimed, forced.notes) == (65_536 + later.funded, 1),
        "{forced:?}"
    );
    ensure!(available(&wallet)? == 114_688);
    let each = recoverable(&wallet, &mine, tip)?;
    let shares = (each.get(&first.id), each.get(&later.id));
    ensure!(shares == (Some(&114_688), None), "{each:?}");
    let forced = recovery::force_close(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &first.id,
        rate,
    )
    .await?;
    ensure!(
        (forced.claimed, forced.notes) == (114_688 + first.funded, 3),
        "{forced:?}"
    );
    ensure!(available(&wallet)? == 0);

    // Both given up: her notes back.
    recovery::give_up(&wallet, &mine.join("wallet.sqlite"), &later.id)?;
    recovery::give_up(&wallet, &mine.join("wallet.sqlite"), &first.id)?;
    ensure!(available(&wallet)? == 180_224);
    Ok(())
}

/// A hub service opening contracts as [`hub_serving`], of notes up to
/// 2^30 sat, taking deposits of up to 2 M sat for 1000 sat each, scanning
/// `rt` once [`followed`]: its URL, chain, it, its deposits and contracts.
async fn hub_taking_deposits(
    rt: &Regtest,
    dir: &Path,
) -> Result<(
    String,
    Source,
    Arc<Hub>,
    Arc<deposit::Gateway>,
    Arc<Openings>,
)> {
    std::fs::create_dir_all(dir)?;
    let (seed, db) = (dir.join("seed"), dir.join("hub.sqlite"));
    Hub::init(&seed, &db, 30)?;
    let hub = Arc::new(Hub::open(&seed, &db, Policy::default())?);
    let url = format!(
        "{}/wallet/harness?cookie={}",
        rt.rpc_url(),
        rt.cookie().display()
    );
    let source: Source = url.parse()?;
    let keyset = hub.info().keysets[0].clone();
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let openings = Openings::with_wallet(dir, source.clone(), source.clone(), keyset, Some(range));
    let config = deposit::Config {
        max: 2_000_000,
        ..deposit::Config::new(bitcoin::ScriptBuf::new_op_return([]))
    };
    let regtest = ChainProfile::Core30DefaultRegtest;
    let path = dir.join("hub.sqlite");
    let deposits = deposit::Gateway::open(hub.clone(), source.clone(), regtest, config, &path)?;
    let deposits = Arc::new(deposits);
    let openings = openings.await?;
    licash_hub_service::close_with_deposits(&openings, deposits.clone());
    // On its lock checkpoints, issuing her funded notes and answering
    // claims from its ledger, as the hub service's.
    licash_hub_service::open_on_lock_checkpoints(&openings, hub.clone());
    licash_hub_service::answer_from(&openings, hub.clone());
    let services = Services {
        contracts: Some(openings.clone()),
        deposits: Some(deposits.clone()),
        ..Default::default()
    };
    let app = licash_hub_service::router(hub.clone(), services);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok((url, source, hub, deposits, openings))
}

/// `hub` scanned to the tip of `source`, then its `deposits`.
async fn followed(hub: &Arc<Hub>, source: &Source, deposits: &deposit::Gateway) -> Result<()> {
    for _ in 0..1_000 {
        if watch::step(hub, source).await? {
            deposits.round().await;
            return Ok(());
        }
    }
    anyhow::bail!("the hub never reached the tip")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_holder_funds_part_of_her_contract_and_is_issued_its_notes_once_f_is_buried() -> Result<()>
{
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, hub, deposits, _) = hub_taking_deposits(&rt, &dir.path().join("hub")).await?;
    let chain = Node(source.clone());
    followed(&hub, &source, &deposits).await?;
    let mine = dir.path().join("wallet");
    std::fs::create_dir(&mine)?;
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &[9; 32],
        regtest,
        Http::new(None)?,
    )?;
    let info = wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    let to = wallet.fallback_address()?.script_pubkey();
    rt.fund(&to, Amount::from_sat(1_000_000))?;
    rt.mine(1)?;
    followed(&hub, &source, &deposits).await?;
    ensure!(scan(&wallet, &chain).await? == 1_000_000);
    let coin = wallet.silent_coins()?[0].outpoint;

    // Her coin is spent whole: the smallest contract that takes it, her part
    // of it what the price leaves, the hub's interest on the rest only.
    let range = (info.contracts.and_then(|c| c.range)).context("no range")?;
    let quote = holder::offer(&wallet, &url, None, 0).await?;
    let (denominations, notes) = holder::funding_notes(&quote.quote);
    let fitted = holder::fit(
        &holder::Pricing::Range(&range),
        300,
        1_000_000,
        330,
        (&denominations, notes),
        0,
    )
    .context("no contract takes the coin")?;
    let (cap, funded) = (fitted.cap, fitted.funded);
    let price = range.price(cap, 300, funded);
    let ask = Ask {
        blocks: 300,
        max_price: 30_000,
        cap: None,
        deposit: Some(coin),
    };
    let opened = holder::open_with(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask).await?;
    ensure!(
        opened.phase == Phase::Funded
            && opened.price == price
            && opened.cap == cap
            && opened.funded == u64::from(funded)
            && !opened.funded_received,
        "{opened:?}"
    );

    // Not issued before F is buried: asked, the hub refuses; nor closed
    // early while they are owed.
    let id = licash_contracts::hex_id(&opened.id);
    let issuance = format!("{url}{}", licash_contracts::FUNDED.replace("{id}", &id));
    let ask_hub = || wallet.transport().request(&issuance, Some(vec![]));
    let early = ask_hub().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    ensure!(early.status == 409, "{}", early.status);
    let mut received = false;
    for _ in 0..12 {
        rt.mine(1)?;
        followed(&hub, &source, &deposits).await?;
        let contracts = holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
        if contracts[0].funded_received {
            received = true;
            break;
        }
    }
    ensure!(received, "her funded notes never came");
    let held: u64 = wallet.balance()?.iter().map(|b| b.available).sum();
    ensure!(held == u64::from(funded), "{held}");
    // Not owed to her: her claim names them as funded notes already.
    ensure!(
        wallet.owed_locks()?.is_empty(),
        "{:?}",
        wallet.owed_locks()?
    );
    // F spent her coin whole: no change came back from it.
    let left = scan(&wallet, &chain).await?;
    ensure!(left == 0, "{left}");
    // Asked again, the same lock: nothing more issued.
    let again = ask_hub().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    ensure!(again.status == 200, "{}", again.status);
    let issued = licash_contracts::FundedIssued::decode(&again.body)?;
    let lock = hub.locked(&licash::spend::ProposalId::from_bytes(issued.lock))?;
    ensure!(lock.settled == Some(licash_hub::Settled::Pay));
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    let held: u64 = wallet.balance()?.iter().map(|b| b.available).sum();
    ensure!(held == u64::from(funded), "{held}");
    Ok(())
}

/// A provider's keeper told of what cap opens the first contract at a hub
/// itself, once: its notes there taken in once it is live.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_providers_keeper_opens_the_first_contract_at_a_hub_where_told_to() -> Result<()> {
    use std::collections::HashMap;

    use licash_swaps::{Config as SwapsConfig, Provider};
    use licash_swaps_service::keeper::{Alert, Keeper, Settings};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let (url, source, _hub) = hub_serving(&rt, &at, None).await?;
    let mine = dir.path().join("provider");
    std::fs::create_dir(&mine)?;
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &[12; 32],
        regtest,
        Http::new(None)?,
    )?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    let to = wallet.fallback_address()?.script_pubkey();
    rt.fund(&to, Amount::from_sat(60_000))?;
    rt.mine(1)?;
    let provider = Arc::new(Provider::create(wallet, SwapsConfig::default())?);
    let settings = Settings {
        max_price: Some(30_000),
        open_cap: Some(131_071),
        scan: true,
        ..Settings::new(0, 0, "open-contract {hub}".into())
    };
    let mut keeper = Keeper::new(
        provider.clone(),
        Node(source),
        mine.join("wallet.sqlite"),
        settings,
    );
    let limited = |most: u64| Some(HashMap::from([(url.clone(), most)]));

    // None at the hub: it opens one, taking nothing in meanwhile.
    let plan = keeper.round().await?;
    ensure!(
        plan.alerts == [Alert::NoContract { hub: url.clone() }],
        "{plan:?}"
    );
    ensure!(provider.intake() == limited(0));
    let events = provider.events(0, 1_000)?;
    ensure!(
        (events.iter())
            .any(|e| e.kind == "alert" && e.data.to_string().contains("opening contract")),
        "{events:?}"
    );
    let opened = holder::list(&mine.join("wallet.sqlite"))?;
    ensure!(opened.len() == 1 && opened[0].hub == url, "{opened:?}");
    ensure!(opened[0].cap == 131_071 && opened[0].price <= 30_000);

    // Once: being opened, then live, its cap taken in.
    let plan = keeper.round().await?;
    ensure!(plan.alerts.is_empty(), "{plan:?}");
    rt.mine(1)?;
    keeper.round().await?;
    keeper.round().await?;
    ensure!(holder::list(&mine.join("wallet.sqlite"))?.len() == 1);
    ensure!(
        provider.intake() == limited(131_071),
        "{:?}",
        provider.intake()
    );
    Ok(())
}

/// A provider found by her app that pays nothing out.
struct NoProvider;

impl licash_contracts::holder::exit::CashOut for NoProvider {
    async fn quote_all(&self, _: &str, _: &str) -> Result<licash_wallet::PayoutQuote> {
        anyhow::bail!("no provider pays out now")
    }
}

/// Her exit from a contract ending, notes at its hub no other contract
/// recovers: nothing done without her consent, only told; consented, her
/// notes paid out, which fails here, then forced closed a day before its
/// request would have to confirm.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn her_exit_needs_consent_then_forces_closed_what_it_could_not_pay_out() -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::{exit, recovery, safety};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub) = hub_serving(&rt, &at, Some(range)).await?;
    let chain = Node(source);
    let coins = [COIN, COIN];
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, [12; 32], &coins).await?;
    let address = wallet.fallback_address()?.to_string();
    let (margin, rate) = (10, FeeRate::from_sat_per_vb_u32(2));
    let file = mine.join("wallet.sqlite");
    let drive = || exit::drive(&wallet, &chain, &file, &NoProvider, margin, rate);
    // No contract: nothing to consent to exit, nothing made.
    ensure!(exit::consent_to(&wallet, &mine.join("wallet.sqlite"), &address, margin).is_err());
    ensure!(drive().await?.is_empty());
    ensure!(!holds_contracts(&mine.join("wallet.sqlite"))?);

    let ask = Ask {
        blocks: 1_000,
        ..ask()
    };
    let contract = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask).await?;
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    let live = holder::list(&mine.join("wallet.sqlite"))?;
    ensure!(live[0].live(rt.height()?), "{live:?}");
    let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 3_000)?;
    wallet.receive(&payment)?;
    let tip = rt.height()?;
    let s = safety::of(
        &wallet,
        &mine.join("wallet.sqlite"),
        &contract.id,
        tip,
        margin,
        exit::TIMEOUT_SLACK,
    )?;
    let by = s.request_by.context("no request deadline")?;
    let (cash_at, force_at) = (by - 3 * 144, by - 144);
    ensure!(cash_at > tip, "{s:?} at {tip}");

    let exits = drive().await?;
    ensure!(exits.len() == 1, "{exits:?}");
    ensure!(
        (exits[0].step, exits[0].cash_at, exits[0].force_at)
            == (exit::Step::Waiting, cash_at, force_at),
        "{exits:?}"
    );
    // Due, her notes at risk, and no consent: she is told, nothing done,
    // even past its forced close's block.
    rt.mine_to_height(force_at)?;
    let exits = drive().await?;
    ensure!(exits[0].step == exit::Step::NeedsConsent, "{exits:?}");
    ensure!(exits[0].uncovered == 3_000, "{exits:?}");
    ensure!(recovery::recoveries(&mine.join("wallet.sqlite"))?.is_empty());
    ensure!(exit::consent(&mine.join("wallet.sqlite"))?.is_none());

    // Consented: forced closed at once, its notes not paid out in time.
    let consent = exit::consent_to(&wallet, &mine.join("wallet.sqlite"), &address, margin)?;
    ensure!(consent.address == address && consent.exit_margin == margin);
    let exits = drive().await?;
    ensure!(
        exits[0].step == exit::Step::ForceClosing && exits[0].error.is_none(),
        "{exits:?}"
    );
    let recoveries = recovery::recoveries(&mine.join("wallet.sqlite"))?;
    ensure!(
        recoveries.len() == 1 && recoveries[0].id == contract.id,
        "{recoveries:?}"
    );
    // Under recovery: the exit has nothing more to do of it.
    ensure!(drive().await?.is_empty());
    exit::revoke(&mine.join("wallet.sqlite"))?;
    ensure!(exit::consent(&mine.join("wallet.sqlite"))?.is_none());
    Ok(())
}

/// Her exit, consented, before its forced close's block: her notes paid
/// out, which fails without a provider, told and tried again next round,
/// nothing locked.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn her_exit_tries_to_pay_out_before_forcing_closed() -> Result<()> {
    use bitcoin::FeeRate;
    use licash_contracts::holder::{exit, recovery, safety};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let range = Range {
        max_cap: 50_000_000,
        max_blocks: 5_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };
    let (url, source, hub) = hub_serving(&rt, &at, Some(range)).await?;
    let chain = Node(source);
    let coins = [COIN, COIN];
    let (mine, wallet) = holder_wallet(&rt, &chain, dir.path(), &url, [13; 32], &coins).await?;
    let address = wallet.fallback_address()?.to_string();
    let (margin, rate) = (10, FeeRate::from_sat_per_vb_u32(2));
    let ask = Ask {
        blocks: 1_000,
        ..ask()
    };
    let contract = holder::open(&wallet, &chain, &mine.join("wallet.sqlite"), &url, ask).await?;
    rt.mine(1)?;
    holder::resume(&wallet, &chain, &mine.join("wallet.sqlite")).await?;
    let payment = pay(&hub, &at.join("seed"), &url, &wallet.address(), 3_000)?;
    wallet.receive(&payment)?;
    exit::consent_to(&wallet, &mine.join("wallet.sqlite"), &address, margin)?;
    let s = safety::of(
        &wallet,
        &mine.join("wallet.sqlite"),
        &contract.id,
        rt.height()?,
        margin,
        exit::TIMEOUT_SLACK,
    )?;
    let by = s.request_by.context("no request deadline")?;
    rt.mine_to_height(by - 3 * 144)?;
    for _ in 0..2 {
        let exits = exit::drive(
            &wallet,
            &chain,
            &mine.join("wallet.sqlite"),
            &NoProvider,
            margin,
            rate,
        )
        .await?;
        ensure!(exits[0].step == exit::Step::CashingOut, "{exits:?}");
        let error = exits[0].error.as_deref().unwrap_or_default();
        ensure!(error.contains("no provider pays out now"), "{exits:?}");
        ensure!(recovery::recoveries(&mine.join("wallet.sqlite"))?.is_empty());
        ensure!(wallet.payouts()?.is_empty() && wallet.locks()?.is_empty());
        rt.mine(1)?;
    }
    // A margin preferred since changes nothing: her consent's is planned.
    let exits = exit::drive(
        &wallet,
        &chain,
        &mine.join("wallet.sqlite"),
        &NoProvider,
        1_000,
        rate,
    )
    .await?;
    ensure!(exits[0].step == exit::Step::CashingOut, "{exits:?}");
    Ok(())
}

/// A provider's keeper, a round at a time: what the provider takes in at
/// the hub held to its contracts there, the one ending replaced in time,
/// and forced closed at its safe deadline only once its successor cannot
/// recover every note held there.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_providers_keeper_holds_its_intake_to_its_contracts_and_replaces_them() -> Result<()> {
    use std::collections::HashMap;

    use licash_contracts::holder::{recovery, safety};
    use licash_swaps::{Config as SwapsConfig, Provider};
    use licash_swaps_service::keeper::{Alert, Deadlines, Keeper, Settings};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let (url, source, hub) = hub_serving(&rt, &at, None).await?;
    let mine = dir.path().join("provider");
    std::fs::create_dir(&mine)?;
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create(
        &mine.join("wallet.sqlite"),
        &[11; 32],
        regtest,
        Http::new(None)?,
    )?;
    wallet.add_hub(&url).await?;
    wallet.watch_silent(None, rt.height()?)?;
    for sats in [COIN, COIN] {
        let to = wallet.fallback_address()?.script_pubkey();
        rt.fund(&to, Amount::from_sat(sats))?;
    }
    rt.mine(1)?;
    let provider = Arc::new(Provider::create(wallet, SwapsConfig::default())?);
    let (day, lead, margin, slack) = (2, 20, 10, 6);
    let settings = Settings {
        exit_margin: margin,
        timeout_slack: slack,
        day,
        successor_lead: lead,
        max_price: Some(30_000),
        scan: true,
        ..Settings::new(0, 0, "open-contract {hub}".into())
    };
    let chain = Node(source.clone());
    let mut keeper = Keeper::new(
        provider.clone(),
        Node(source),
        mine.join("wallet.sqlite"),
        settings,
    );
    let limited = |most: u64| Some(HashMap::from([(url.clone(), most)]));
    let alerted = |says: &str| -> Result<bool> {
        let events = provider.events(0, 1_000)?;
        Ok((events.iter()).any(|e| e.kind == "alert" && e.data.to_string().contains(says)))
    };
    // Nothing taken in until it knows what protects the notes.
    ensure!(provider.intake() == Some(HashMap::new()));

    // No contract at the hub: nothing taken in there, the operator told
    // how to open one.
    let plan = keeper.round().await?;
    ensure!(
        plan.alerts == [Alert::NoContract { hub: url.clone() }],
        "{plan:?}"
    );
    ensure!(provider.intake() == limited(0));
    ensure!(alerted(&format!("open-contract {url}"))?);

    // Opened by the operator: nothing yet while it opens, then its cap.
    let first = holder::open(
        provider.wallet(),
        &chain,
        &mine.join("wallet.sqlite"),
        &url,
        ask(),
    )
    .await?;
    let plan = keeper.round().await?;
    ensure!(
        plan.alerts.is_empty() && plan.successors.is_empty(),
        "{plan:?}"
    );
    ensure!(provider.intake() == limited(0));
    rt.mine(1)?;
    keeper.round().await?;
    keeper.round().await?;
    ensure!(
        provider.intake() == limited(131_071),
        "{:?}",
        provider.intake()
    );

    let tip = rt.height()?;
    let safety = safety::of(
        provider.wallet(),
        &mine.join("wallet.sqlite"),
        &first.id,
        tip,
        margin,
        slack,
    )?;
    let Deadlines { renew_at, claim_at } = Deadlines::new(safety.request_by, day, lead);
    ensure!(renew_at > tip + 1, "{safety:?}");
    rt.mine_to_height(renew_at - 1)?;
    let plan = keeper.round().await?;
    ensure!(plan.successors.is_empty(), "{plan:?}");
    ensure!(provider.intake() == limited(131_071));

    // Due to be replaced: a successor of its cap opened, counted in its
    // stead while it opens.
    rt.mine(1)?;
    let plan = keeper.round().await?;
    ensure!(
        plan.successors.len() == 1 && plan.successors[0].replaces == first.id,
        "{plan:?}"
    );
    let all = holder::list(&mine.join("wallet.sqlite"))?;
    let second = all
        .iter()
        .find(|c| c.id != first.id)
        .context("no successor")?;
    ensure!(
        second.since >= renew_at && second.cap == 131_071 && second.price <= 30_000,
        "{second:?}"
    );
    let plan = keeper.round().await?;
    ensure!(plan.successors.is_empty(), "{plan:?}");
    ensure!(provider.intake() == limited(131_071));
    // Live: it counts, and nothing more is opened.
    rt.mine(1)?;
    keeper.round().await?;
    let plan = keeper.round().await?;
    ensure!(
        plan.successors.is_empty() && plan.force_close.is_empty(),
        "{plan:?}"
    );
    ensure!(provider.intake() == limited(131_071));
    ensure!(holder::list(&mine.join("wallet.sqlite"))?.len() == 2);

    // At its safe deadline, its successor recovers every note there: not
    // claimed.
    let payment = pay(
        &hub,
        &at.join("seed"),
        &url,
        &provider.wallet().address(),
        3_000,
    )?;
    provider.wallet().receive(&payment)?;
    rt.mine_to_height(claim_at)?;
    let plan = keeper.round().await?;
    ensure!(
        plan.force_close.is_empty() && plan.drains.is_empty(),
        "{plan:?}"
    );
    ensure!(recovery::recoveries(&mine.join("wallet.sqlite"))?.is_empty());
    // More than it recovers: claimed, whatever the hub says, and what the
    // successor cannot protect to be drained.
    let payment = pay(
        &hub,
        &at.join("seed"),
        &url,
        &provider.wallet().address(),
        130_000,
    )?;
    provider.wallet().receive(&payment)?;
    let plan = keeper.round().await?;
    ensure!(plan.force_close == [first.id], "{plan:?}");
    ensure!(
        plan.drains == [(url.clone(), 133_000 - 131_071)],
        "{plan:?}"
    );
    let recoveries = recovery::recoveries(&mine.join("wallet.sqlite"))?;
    ensure!(
        recoveries.len() == 1 && recoveries[0].id == first.id,
        "{recoveries:?}"
    );
    ensure!(alerted("forced contract")?);
    // Never forced again, nor replaced.
    let plan = keeper.round().await?;
    ensure!(
        plan.force_close.is_empty() && plan.successors.is_empty(),
        "{plan:?}"
    );
    Ok(())
}

/// A deposit whose settle never reaches its hub is owed to her on Bitcoin
/// as a payer's lock is, its lock of the hub's own notes proven by their
/// owner signatures: activated with a coin of hers as its expiry nears,
/// its pay branch claimed by her forced close beside her notes, and the
/// hub, finding it owed all she asks, lets her timeout pay it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_force_close_claims_a_deposit_its_hub_kept_once_activated_at_depth() -> Result<()> {
    use licash_contracts::holder::activation;
    use licash_contracts::holder::recovery::{self, Stage};

    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let at = dir.path().join("hub");
    let (url, source, hub, deposits, openings) = hub_taking_deposits(&rt, &at).await?;
    followed(&hub, &source, &deposits).await?;
    let chain = Node(source.clone());
    let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
    let (mine, bob) = holder_wallet_over(
        &rt,
        &chain,
        &dir.path().join("bob"),
        &url,
        [18; 32],
        &[COIN, COIN],
        NoSettle(Http::new(None)?),
    )
    .await?;
    followed(&hub, &source, &deposits).await?;
    let chosen = Ask {
        cap: Some(131_071),
        blocks: 1_000,
        ..ask()
    };
    let opened = holder::open(&bob, &chain, &mine.join("wallet.sqlite"), &url, chosen).await?;
    let payment = pay_at(&hub, &at.join("seed"), &url, &bob.address(), 2_048, 30)?;
    bob.receive(&payment)?;
    rt.mine(1)?;
    followed(&hub, &source, &deposits).await?;
    holder::resume(&bob, &chain, &mine.join("wallet.sqlite")).await?;
    ensure!(available(&bob)? == 2_048);

    // A deposit paid and buried: the hub locks its own notes to him.
    let deposit = bob.deposit(&url, 10_000).await?;
    let terms = deposit.terms.clone().context("no terms")?;
    let address: bitcoin::Address<_> = terms.address.parse()?;
    rt.fund(
        &address.assume_checked().script_pubkey(),
        Amount::from_sat(terms.pays),
    )?;
    for _ in 0..3 {
        rt.mine(1)?;
        followed(&hub, &source, &deposits).await?;
    }
    // His settle never reaches the hub: owed to him, provable.
    let kept = bob.follow_deposit(&deposit.hash).await;
    ensure!(
        kept.as_ref()
            .map_or(true, |d| d.state == licash_wallet::DepositState::Open),
        "{kept:?}"
    );
    let owed = bob.owed_locks()?;
    ensure!(owed.len() == 1 && owed[0].anchor.is_some(), "{owed:?}");
    ensure!(hub.locked(&owed[0].id)?.own);
    let (expiry, depth) = (owed[0].expiry, owed[0].depth);

    let lead = activation::lead();
    rt.mine_to_height(expiry - lead)?;
    followed(&hub, &source, &deposits).await?;
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.len() == 1 && kept[0].step == "activated", "{kept:?}");
    rt.mine(1)?;
    let kept = activation::keep(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?;
    ensure!(kept.len() == 1 && kept[0].step == "confirmed", "{kept:?}");
    let activated = (bob.owed_locks()?[0].activated_at).context("not recorded")?;
    ensure!(
        activated < expiry,
        "activated at {activated}, expiring at {expiry}"
    );

    rt.mine_to_height(expiry.max(activated + depth) + 1)?;
    followed(&hub, &source, &deposits).await?;
    let forced =
        recovery::force_close(&bob, &chain, &mine.join("wallet.sqlite"), &opened.id, rate).await?;
    // His note, and the deposit lock's pay branch.
    let paid = forced.claimed - 2_048 - opened.funded;
    ensure!(
        forced.notes == 1 && paid > 0 && paid <= 10_000,
        "{forced:?}"
    );
    ensure!(bob.owed_locks()?[0].claimed);
    let mut done = None;
    for _ in 0..800 {
        rt.mine(1)?;
        followed(&hub, &source, &deposits).await?;
        let round = openings.answer_requests().await?;
        ensure!(round.failed == 0, "{round:?}");
        let r =
            recovery::advance(&bob, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(
        done.response.is_none() && done.timeout.is_some() && done.payout == done.timeout,
        "{done:?}"
    );
    Ok(())
}
