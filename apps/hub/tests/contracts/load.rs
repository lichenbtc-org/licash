//! Contracts under load: many holders at one hub at once, each with a
//! wallet and coins of her own. What they measure is printed; what they
//! check is that the hub's admission bounds hold and that no holder's
//! opening takes another's coins, or the hub's twice.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use licash_contracts::hub::{MAX_UNDER_WAY, MAX_UNFUNDED};

use super::*;

/// A holder of [`holders`]: her wallet's directory and the wallet, and
/// the runtime it runs on, as on a device of her own. Her calls are made
/// on it alone ([`Holder::on`]): her wallet's connections live there, and
/// an opening holds her store's connection across its awaits (not Send).
struct Holder {
    mine: std::path::PathBuf,
    wallet: Wallet<Http>,
    /// Always some, but as it is dropped.
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Holder {
    /// Her runtime let go of in the background: not blocking the test's.
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// A runtime of one thread, a holder's ([`Holder`]).
fn device() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?)
}

impl Holder {
    /// `work` of hers, on her runtime: from a thread of her own, or the
    /// test's, which is let go of meanwhile.
    fn on<R>(&self, work: impl std::future::Future<Output = R>) -> R {
        let runtime = self.runtime.as_ref().expect("her runtime");
        tokio::task::block_in_place(|| runtime.block_on(work))
    }
}

/// Holders `ids` at the hub at `url`, each with one coin of `coin` sat.
async fn holders(
    rt: &Regtest,
    chain: &Node,
    dir: &Path,
    url: &str,
    ids: std::ops::Range<usize>,
    coin: u64,
) -> Result<Vec<Holder>> {
    let mut all = Vec::new();
    for i in ids {
        let at = dir.join(format!("holder-{i}"));
        std::fs::create_dir(&at)?;
        let mut seed = [0x40; 32];
        seed[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        let runtime = device()?;
        let coins = [coin];
        let made = holder_wallet(rt, chain, &at, url, seed, &coins);
        let (mine, wallet) = tokio::task::block_in_place(|| runtime.block_on(made))?;
        all.push(Holder {
            mine,
            wallet,
            runtime: Some(runtime),
        });
    }
    Ok(all)
}

/// What [`start_opening`] gives back: a holder, her opening's result,
/// and how long it took.
type Opened = (Holder, Result<Contract>, Duration);

/// Each of `holders` asking to open at `url` at once, of the chain of
/// `source`, each on a thread of her own and her runtime: to [`joined`].
fn start_opening(
    holders: Vec<Holder>,
    source: &Source,
    url: &str,
) -> Vec<std::thread::JoinHandle<Opened>> {
    holders
        .into_iter()
        .map(|holder| {
            let (source, url) = (source.clone(), url.to_string());
            std::thread::spawn(move || {
                let at = Instant::now();
                let file = holder.mine.join("wallet.sqlite");
                let runtime = holder.runtime.as_ref().expect("her runtime");
                let opened = runtime.block_on(holder::open(
                    &holder.wallet,
                    &Node(source),
                    &file,
                    &url,
                    ask(),
                ));
                (holder, opened, at.elapsed())
            })
        })
        .collect()
}

/// The openings of [`start_opening`], in their order, each told: joined
/// off the test's runtime, whose hub serves them meanwhile.
async fn joined(threads: Vec<std::thread::JoinHandle<Opened>>) -> Result<Vec<Opened>> {
    let done = tokio::task::spawn_blocking(move || {
        threads
            .into_iter()
            .map(|t| t.join().expect("a holder's thread"))
            .collect::<Vec<_>>()
    })
    .await?;
    for (_, opened, took) in &done {
        match opened {
            Ok(_) => eprintln!("opened in {:>6.1} s", took.as_secs_f64()),
            Err(e) => eprintln!("refused in {:>6.1} s: {e:#}", took.as_secs_f64()),
        }
    }
    Ok(done)
}

/// The contracts of `done`, each F hers and apart from the others': its
/// own deposit, of [`COIN`], and no input any other F spends, so that all
/// confirm in one block. `deposits` and `inputs` are those seen before.
fn apart(
    rt: &Regtest,
    done: Vec<Opened>,
    deposits: &mut HashSet<bitcoin::OutPoint>,
    inputs: &mut HashSet<bitcoin::OutPoint>,
) -> Result<Vec<Holder>> {
    let mut holders = Vec::new();
    for (h, opened, _) in done {
        let c = opened?;
        ensure!(c.phase == Phase::Funded && c.value == COIN, "{c:?}");
        ensure!(deposits.insert(c.deposit), "a deposit twice: {c:?}");
        let tx = rt.get_tx(&c.funding.context("no F")?)?;
        for input in &tx.input {
            ensure!(inputs.insert(input.previous_output), "an input twice");
        }
        holders.push(h);
    }
    Ok(holders)
}

/// Blocks mined, the hub's watch stepped, until every one of `holders`
/// took her funded notes.
async fn all_funded(
    rt: &Regtest,
    hub: &Arc<Hub>,
    source: &Source,
    chain: &Node,
    holders: &[&Holder],
) -> Result<()> {
    let mut short = Vec::new();
    for _ in 0..12 {
        rt.mine(1)?;
        while !watch::step(hub, source).await? {}
        short.clear();
        for (i, h) in holders.iter().enumerate() {
            let file = h.mine.join("wallet.sqlite");
            let contracts = h.on(holder::resume(&h.wallet, chain, &file))?;
            // Not those she gave up, as the hub turned her away busy.
            let live: Vec<_> = contracts.iter().filter(|c| c.abandoned.is_none()).collect();
            if !live.iter().all(|c| c.funded_received) {
                short.push(format!("{i}: {live:?}"));
            }
        }
        if short.is_empty() {
            return Ok(());
        }
    }
    eprintln!("{} short:\n{}", short.len(), short.join("\n"));
    anyhow::bail!("not every holder's funded notes came")
}

/// How long [`as_many_holders_as_the_hub_admits_open_at_once_and_more_wait_for_a_block`]
/// holds back the block that confirms the first openings' F.
const HELD: Duration = Duration::from_secs(45);

/// As many holders as the hub takes openings of under way, asking at once:
/// every one opens, those it is too busy for at a time asking again, each
/// F on her own coin and coins of the hub's no other F spends. Then, all
/// signed and in no block, two more: held off by the hub's bound on such
/// openings, from the moment each was signed, until a block confirms
/// them; then opened.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn as_many_holders_as_the_hub_admits_open_at_once_and_more_wait_for_a_block() -> Result<()> {
    // What holders and hub warn of, with each run's output.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::WARN)
        .with_test_writer()
        .try_init();
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, hub, openings) = hub_answering(&rt, &dir.path().join("hub")).await?;
    // Its surcharge counts openings under way as live: with room for many
    // more, its price stays the one asked, and what bounds them is
    // admission alone.
    openings.limit_live(256);
    let chain = Node(source.clone());
    let first = holders(&rt, &chain, dir.path(), &url, 0..MAX_UNDER_WAY, COIN).await?;
    let more = MAX_UNDER_WAY..MAX_UNDER_WAY + 2;
    let more = holders(&rt, &chain, dir.path(), &url, more, COIN).await?;

    let start = Instant::now();
    let done = joined(start_opening(first, &source, &url)).await?;
    eprintln!(
        "{MAX_UNDER_WAY} at once opened in {:.1} s",
        start.elapsed().as_secs_f64()
    );
    let (mut deposits, mut inputs) = (HashSet::new(), HashSet::new());
    let first = apart(&rt, done, &mut deposits, &mut inputs)?;
    ensure!(first.len() == MAX_UNFUNDED);

    // As many signed as it keeps in no block: the next wait for one.
    let waiting = start_opening(more, &source, &url);
    tokio::time::sleep(HELD).await;
    let first: Vec<&Holder> = first.iter().collect();
    all_funded(&rt, &hub, &source, &chain, &first).await?;
    // Its responder sees them in a block.
    openings.answer_requests().await?;
    let done = joined(waiting).await?;
    for (_, _, took) in &done {
        ensure!(*took >= HELD, "opened before a block: {took:?}");
    }
    let more = apart(&rt, done, &mut deposits, &mut inputs)?;
    let more: Vec<&Holder> = more.iter().collect();
    all_funded(&rt, &hub, &source, &chain, &more).await?;
    let tip = rt.height()?;
    for h in first.iter().chain(&more) {
        // Live once, beside those she gave up as the hub turned her away.
        let listed = holder::list(&h.mine.join("wallet.sqlite"))?;
        let live = listed.iter().filter(|c| c.live(tip)).count();
        ensure!(live == 1, "{listed:?}");
    }
    Ok(())
}
