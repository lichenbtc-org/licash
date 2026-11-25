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
