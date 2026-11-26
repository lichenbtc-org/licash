//! Answers lost on the way back: the hub took a holder's request, and she
//! heard nothing, as a Tor circuit dropping after the hub had it. What
//! they check is that she asks again and the hub takes it again as it took
//! it, making nothing twice.

use std::collections::HashSet;

use super::*;

/// [`Http`], but the answer to each opening's start and step lost once,
/// after the hub had it: a request of each body heard of no answer the
/// first time, and the hub's answer the next. Instance uploads, which
/// [`Dropping`] loses, pass, as all else.
#[derive(Default)]
struct Hushing {
    http: Option<Http>,
    /// The digests of the bodies whose answer was lost.
    lost: std::sync::Mutex<HashSet<[u8; 32]>>,
}

impl Hushing {
    /// Whether a request to `url` is an opening's start or step.
    fn steps(url: &str) -> bool {
        let path = url.split_once("/v1/").map_or("", |(_, p)| p);
        let step = path
            .strip_prefix("contracts/openings/")
            .is_some_and(|id| !id.contains('/'));
        step || path == "contracts/open"
    }
}

impl licash_wallet::Transport for Hushing {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        use bitcoin::hashes::Hash as _;
        let http = self.http.as_ref().expect("an Http");
        let answer = http.request(url, body.clone()).await;
        if let (true, Some(body), Ok(_)) = (Self::steps(url), &body, &answer) {
            let digest = bitcoin::hashes::sha256::Hash::hash(body).to_byte_array();
            if self.lost.lock().unwrap().insert(digest) {
                return Err("no answer over Tor in 120 s".into());
            }
        }
        answer
    }
}

/// The hub's answer to an opening's start and to each of its steps lost
/// once, after the hub took it: she asks each again, the hub answers as it
/// did, and the contract opens, once, on one F, which confirms.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn an_opening_whose_every_answer_was_lost_once_opens_once() -> Result<()> {
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let (url, source, hub, openings) = hub_answering(&rt, &dir.path().join("hub")).await?;
    let chain = Node(source.clone());
    let transport = Hushing {
        http: Some(Http::new(None)?),
        ..Default::default()
    };
    let at = dir.path().join("wallet");
    let (mine, wallet) =
        holder_wallet_over(&rt, &chain, &at, &url, [33; 32], &[COIN], transport).await?;
    let file = mine.join("wallet.sqlite");
    let opened = holder::open(&wallet, &chain, &file, &url, ask()).await?;
    ensure!(opened.phase == Phase::Funded, "{opened:?}");
    let lost = wallet.transport().lost.lock().unwrap().len();
    // Its start, and her Commit, Opened, Consent and Funded at least.
    ensure!(lost >= 5, "{lost} answers lost");
    ensure!(openings.load()?.live == 1, "{:?}", openings.load()?);
    let listed = holder::list(&file)?;
    ensure!(listed.len() == 1, "{listed:?}");
    funded_in(&rt, &hub, &source, &wallet, &chain, &file).await?;
    let f = opened.funding.context("no F")?;
    ensure!(rt.confirmations(&f)?.is_some(), "F unmined");
    eprintln!("an opening opened with {lost} of its answers lost once");
    Ok(())
}

#[test]
fn only_an_openings_start_and_steps_are_hushed() {
    let at = "http://127.0.0.1:1/v1/contracts";
    assert!(Hushing::steps(&format!("{at}/open")));
    assert!(Hushing::steps(&format!("{at}/openings/ab12")));
    assert!(!Hushing::steps(&format!("{at}/openings/ab12/instances")));
    assert!(!Hushing::steps(&format!("{at}/openings/ab12/funded")));
    assert!(!Hushing::steps(&format!("{at}/quote")));
}

/// [`Http`], but the first request to a route ending in `route` lost:
/// before the hub had it, or, if `after`, its answer, once the hub had it.
struct Losing {
    http: Http,
    route: &'static str,
    after: bool,
    lost: std::sync::atomic::AtomicBool,
}

impl Losing {
    fn new(route: &'static str, after: bool) -> Result<Self> {
        Ok(Self {
            http: Http::new(None)?,
            route,
            after,
            lost: Default::default(),
        })
    }
}

impl licash_wallet::Transport for Losing {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        use std::sync::atomic::Ordering;
        let losing = url.ends_with(self.route) && !self.lost.swap(true, Ordering::Relaxed);
        if losing && !self.after {
            return Err("no answer over Tor in 120 s".into());
        }
        let answer = self.http.request(url, body).await;
        match losing {
            true => Err("no answer over Tor in 120 s".into()),
            false => answer,
        }
    }
}

/// Her close's fold, signed by her, its answer lost once the hub signed
/// it, which the hub broadcasts: her close fails as one that may be
/// signed, and her wallet, seeing the fold in a block, is paid by it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_fold_whose_signature_answer_was_lost_pays_her_as_it_confirms() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let n = with_notes([34; 32], Losing::new("/fold/sign", true)?).await?;
    let (rt, wallet, chain, mine) = (&n.rt, &n.wallet, &n.chain, &n.mine);
    let file = mine.join("wallet.sqlite");
    let before = scan(wallet, chain).await?;
    let closed = holder::close(wallet, chain, &file, &n.contract.id).await;
    ensure!(
        closed
            .as_ref()
            .is_err_and(|e| format!("{e:#}").contains("may be signed")),
        "{closed:?}"
    );
    let rows = recovery::recoveries(&file)?;
    ensure!(
        rows[0].stage == Stage::Folding && rows[0].irrevocable,
        "{rows:?}"
    );
    // Her notes are out of her balance, claimed in the fold.
    ensure!(available(wallet)? == 65_536 + n.contract.funded);
    rt.mine(1)?;
    let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
    let done = recovery::advance(wallet, chain, &file, rate).await?;
    ensure!(
        done.len() == 1
            && done[0].stage == Stage::Done
            && done[0].fold.is_some()
            && done[0].received == Some(151_071),
        "{done:?}"
    );
    ensure!(scan(wallet, chain).await? == before + 151_071);
    ensure!(available(wallet)? == 65_536 + n.contract.funded);
    Ok(())
}

/// Her close's fold, signed by her, lost before the hub had it: the hub
/// signed nothing. Her close fails as one that may be signed; asked again,
/// it folds, and she is paid as by any fold.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_fold_whose_signature_never_reached_the_hub_folds_asked_again() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let n = with_notes([35; 32], Losing::new("/fold/sign", false)?).await?;
    let (rt, wallet, chain, mine) = (&n.rt, &n.wallet, &n.chain, &n.mine);
    let file = mine.join("wallet.sqlite");
    let before = scan(wallet, chain).await?;
    let closed = holder::close(wallet, chain, &file, &n.contract.id).await;
    ensure!(closed.is_err(), "{closed:?}");
    let first = holder::list(&file)?[0].folded;
    let txid = holder::close(wallet, chain, &file, &n.contract.id).await?;
    eprintln!("folded asked again: {first:?} first, {txid} then");
    rt.mine(1)?;
    ensure!(rt.confirmations(&txid)?.is_some(), "the fold unmined");
    let rate = bitcoin::FeeRate::from_sat_per_vb(2).context("a rate")?;
    let done = recovery::advance(wallet, chain, &file, rate).await?;
    ensure!(
        done.len() == 1
            && done[0].stage == Stage::Done
            && done[0].fold == Some(txid)
            && done[0].received == Some(151_071),
        "{done:?}"
    );
    ensure!(scan(wallet, chain).await? == before + 151_071);
    ensure!(available(wallet)? == 65_536 + n.contract.funded);
    Ok(())
}
