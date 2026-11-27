//! The hub's standby: a copy of its data on another machine, without its
//! seed (`--standby-keys`). What it checks is that such a copy answers a
//! dispute as its hub would, from the ledger alone.

use super::*;

/// The hub's machine is lost once her stale claim is requested. Its
/// standby holds a copy of its data and, in place of its seed, the keys
/// its hub wrote for it: it meets her claim with the spend the hub
/// released, that spend's unlock read from the ledger, responds what is
/// left and retires the notes she claimed, taking nothing over. A standby
/// serves no wallet, so hers is shown neither what it responded on nor
/// its proof: she contests and challenges, and the standby proves, asserts
/// and answers. She is paid what the hub itself would have paid her.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_standby_without_the_seed_meets_a_stale_claim_as_its_hub_would() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};
    use licash_contracts::hub::Leadership;

    let _witnessed = Witnessed::by(2);
    let Stale {
        rt,
        _dir: dir,
        hub,
        openings: master,
        chain,
        wallet,
        mine,
        rate,
    } = stale_claim([47; 32]).await?;
    let (at, copy) = (dir.path().join("hub"), dir.path().join("standby"));
    backed_up(&at, &copy, true)?;
    // All of its data but the seed, and its keys instead.
    std::fs::remove_file(copy.join("seed"))?;
    let keys = copy.join("standby.json");
    licash_hub::write_standby_keys(&at.join("seed"), &at.join("hub.sqlite"), &keys)?;
    // Its machine lost: it plays no more.
    drop(master);
    drop(hub);

    let db = copy.join("hub.sqlite");
    let ledger = Arc::new(Hub::open_standby(&keys, &db, Policy::default())?);
    ensure!(ledger.standby());
    let standby = copy_answering(&rt, &copy, ledger).await?;
    let told_standby = told(&standby);
    let mut done = None;
    for _ in 0..800 {
        rt.mine(1)?;
        let round = standby.answer_requests().await?;
        ensure!(
            round.failed == 0,
            "the standby: {round:?} {:?}",
            told_standby.lock().unwrap()
        );
        let r =
            recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    // It took nothing over: no copy is fenced off by it.
    ensure!(standby.leadership().await? == Leadership::Unfenced);
    let x = done.response.context("no response")?;
    ensure!(rt.confirmations(&x)?.is_some(), "{done:?}");
    // Its disclose slot spent: the unlock published, which no seed here
    // derived.
    ensure!(!rt.is_unspent(&bitcoin::OutPoint { txid: x, vout: 2 })?);
    // Her notes less the one paid away: three of 32 768.
    ensure!(done.corrected == Some(98_304), "{done:?}");
    // Shown nothing by a copy that serves no wallet, she contested its
    // response and challenged its assertion: paid by its answer to her
    // challenge, not by a timeout.
    ensure!(
        done.assertion.is_some() && done.challenge.is_some(),
        "{done:?}"
    );
    ensure!(done.payout.is_some() && done.timeout.is_none(), "{done:?}");
    let received = done.received.context("nothing received")?;
    ensure!(
        received < 131_071,
        "{received} of a claim of 131071: {done:?}"
    );
    let request = done.request.context("no request")?;
    let responses = responses_to(&copy, &request)?;
    ensure!(responses.len() == 1, "{} responses signed", responses.len());
    // The notes she claimed, retired in the standby's ledger.
    let claimed: i64 =
        rusqlite::Connection::open(&db)?
            .query_row("SELECT count(*) FROM claimed", [], |r| r.get(0))?;
    ensure!(claimed == 4, "{claimed} notes retired");
    let alerts = told_standby.lock().unwrap().clone();
    ensure!(
        alerts
            .iter()
            .all(|m| !m.contains("disagree") && !m.contains("no longer hold")),
        "{alerts:?}"
    );
    eprintln!("a standby without the seed: a challenged claim of 131071 paid {received}, alerts {alerts:?}");
    Ok(())
}
