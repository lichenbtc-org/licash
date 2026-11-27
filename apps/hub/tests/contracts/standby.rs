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

/// The standby in `copy` as its entrypoint starts it, the hub's data in
/// `at`: its ledger restored from the hub's newest copy (and marked
/// restored, as the entrypoint does), unless it acted on its own, then
/// opened as a standby, deferring its steps.
async fn standby_started(
    rt: &Regtest,
    at: &Path,
    copy: &Path,
    keys: &Path,
) -> Result<(Arc<Openings>, Told)> {
    if !copy.join(licash_contracts::hub::STANDBY_ACTED).exists() {
        if copy.exists() {
            std::fs::remove_dir_all(copy)?;
        }
        backed_up(at, copy, true)?;
        std::fs::remove_file(copy.join("seed"))?;
        std::fs::write(copy.join(licash_contracts::hub::STANDBY_RESTORED), "")?;
    }
    let ledger = Hub::open_standby(keys, &copy.join("hub.sqlite"), Policy::default())?;
    let standby = copy_answering(rt, copy, Arc::new(ledger)).await?;
    let told = told(&standby);
    standby.defer_as_standby();
    Ok((standby, told))
}

/// What [`beside`] saw: her claim's end, how often the standby was
/// restored, whether it marked itself acted, the hub's and the standby's
/// data, and the standby's alerts.
struct Beside {
    done: licash_contracts::holder::recovery::Recovery,
    restarts: usize,
    acted: bool,
    at: std::path::PathBuf,
    copy: std::path::PathBuf,
    alerts: Vec<String>,
    _dir: tempfile::TempDir,
}

/// Her stale claim (of `seed`) met by a hub with a standby beside it,
/// restored from the hub's newest copy each time it stops for one, until
/// she is paid. If `lost`, the hub's machine is lost once it asserted (as
/// she contests, `Doubting`) and plays no more; while it plays, the
/// standby never marks itself acted.
async fn beside(seed: [u8; 32], lost: bool) -> Result<Beside> {
    use licash_contracts::holder::recovery::{self, Stage};

    let Stale {
        rt,
        _dir: dir,
        hub: _,
        openings: master,
        chain,
        wallet,
        mine,
        rate,
    } = stale_claim(seed).await?;
    let (at, copy) = (dir.path().join("hub"), dir.path().join("standby"));
    let keys = dir.path().join("standby.json");
    licash_hub::write_standby_keys(&at.join("seed"), &at.join("hub.sqlite"), &keys)?;
    let acted = copy.join(licash_contracts::hub::STANDBY_ACTED);
    master.refuse_evidence();
    let told_master = told(&master);
    let _doubting = lost.then(Doubting::of);
    let mut master = Some(master);
    let (mut standby, mut told_standby) = standby_started(&rt, &at, &copy, &keys).await?;
    let (mut restarts, mut done) = (0, None);
    for _ in 0..800 {
        if let Some(master) = &master {
            let round = master.answer_requests().await?;
            ensure!(
                round.failed == 0,
                "the hub: {round:?} {:?}",
                told_master.lock().unwrap()
            );
        }
        let round = standby.answer_requests().await?;
        ensure!(
            round.failed == 0,
            "the standby: {round:?} {:?}",
            told_standby.lock().unwrap()
        );
        if standby.stale() {
            restarts += 1;
            drop(standby);
            (standby, told_standby) = standby_started(&rt, &at, &copy, &keys).await?;
        }
        rt.mine(1)?;
        let r =
            recovery::advance(&wallet, &chain, &mine.join("wallet.sqlite"), rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if master.is_some() {
            ensure!(
                !acted.exists(),
                "the standby acted beside its live hub: {r:?} {:?}",
                told_standby.lock().unwrap()
            );
        }
        if lost && r.assertion.is_some() && master.is_some() {
            // Its machine lost: it plays no more.
            master = None;
        }
        if r.stage == Stage::Done {
            done = Some(r);
            break;
        }
    }
    let done = done.context("never paid")?;
    ensure!(
        !lost || master.is_none(),
        "the hub never asserted: {done:?}"
    );
    // Her contract's ending steps (its close, sweeps) are past them too.
    if let Some(master) = &master {
        for _ in 0..40 {
            master.answer_requests().await?;
            standby.answer_requests().await?;
            if standby.stale() {
                restarts += 1;
                drop(standby);
                (standby, told_standby) = standby_started(&rt, &at, &copy, &keys).await?;
            }
            rt.mine(1)?;
            ensure!(!acted.exists(), "the standby acted at its end: {done:?}");
        }
    }
    let alerts = told_standby.lock().unwrap().clone();
    Ok(Beside {
        done,
        restarts,
        acted: acted.exists(),
        at,
        copy,
        alerts,
        _dir: dir,
    })
}

/// A standby runs beside its hub. Through her stale claim's response,
/// contest and assertion, the live hub takes every step and the standby
/// none: it never marks itself acted. The hub's machine lost once it
/// asserted, the standby answers her challenge, halfway through the
/// blocks to answer in, on a ledger restored after the hub's last act:
/// marked acted first, it signed no response of its own, and she is paid
/// by its answer, not by a timeout.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_standby_beside_its_live_hub_takes_no_step_and_answers_once_it_is_lost() -> Result<()> {
    let _witnessed = Witnessed::by(2);
    let b = beside([48; 32], true).await?;
    let done = &b.done;
    ensure!(b.restarts > 0, "the standby never stopped for a newer copy");
    ensure!(b.acted, "the standby answered unmarked");
    ensure!(
        done.assertion.is_some() && done.challenge.is_some(),
        "{done:?}"
    );
    ensure!(done.payout.is_some() && done.timeout.is_none(), "{done:?}");
    // The one response signed is the hub's.
    let request = done.request.context("no request")?;
    let ours = responses_to(&b.at, &request)?;
    ensure!(
        ours.len() == 1,
        "{} responses signed by the hub",
        ours.len()
    );
    ensure!(
        responses_to(&b.copy, &request)? == ours,
        "the standby signed another response"
    );
    ensure!(
        b.alerts
            .iter()
            .all(|m| !m.contains("disagree") && !m.contains("no longer hold")),
        "{:?}",
        b.alerts
    );
    eprintln!(
        "a standby beside its hub: restored {} times, alerts {:?}",
        b.restarts, b.alerts
    );
    Ok(())
}

/// A standby beside a hub alive throughout her stale claim, which she
/// leaves uncontested: whatever the hub's response discloses or not, it
/// takes no step of its own to the claim's end and past it, never marked
/// acted, as a live hub has taken each by its midpoint.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_standby_beside_a_hub_alive_throughout_never_acts() -> Result<()> {
    let _witnessed = Witnessed::by(2);
    let b = beside([49; 32], false).await?;
    ensure!(!b.acted, "the standby marked itself acted: {:?}", b.alerts);
    ensure!(b.done.challenge.is_none(), "{:?}", b.done);
    eprintln!(
        "a standby beside a live hub: restored {} times, alerts {:?}, {:?}",
        b.restarts, b.alerts, b.done
    );
    Ok(())
}
