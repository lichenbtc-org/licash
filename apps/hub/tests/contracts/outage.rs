//! The hub's node out of reach while a dispute is under way: as a node
//! restarting, its RPC overloaded, or the network between them down. What
//! they check is that the hub's responder fails its rounds cleanly while
//! it cannot reach its node, and answers in time once it can.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

/// While one lives, the hubs made by [`hub_answering_following`] reach
/// their node through [`through`], which [`Down`] cuts off.
static SEVERABLE: AtomicBool = AtomicBool::new(false);

/// Whether the node [`through`] passes calls to is out of reach.
static DOWN: AtomicBool = AtomicBool::new(false);

/// Whether, out of reach, it holds each call unanswered rather than
/// refusing it: as a node stuck in a long call, or a link dropping
/// packets.
static STALLS: AtomicBool = AtomicBool::new(false);

/// The coins a transaction the node is handed must spend none of
/// ([`Severable::withhold`]): refused, as a hub withholding F would.
static WITHHELD: std::sync::Mutex<Vec<bitcoin::OutPoint>> = std::sync::Mutex::new(Vec::new());

pub(super) struct Severable;

impl Severable {
    pub(super) fn on() -> Self {
        SEVERABLE.store(true, Ordering::Relaxed);
        Self
    }

    /// The node out of reach, until [`Self::up`].
    fn down(&self) {
        DOWN.store(true, Ordering::Relaxed);
    }

    /// The node holding every call unanswered, until [`Self::up`].
    fn stalled(&self) {
        STALLS.store(true, Ordering::Relaxed);
        DOWN.store(true, Ordering::Relaxed);
    }

    fn up(&self) {
        DOWN.store(false, Ordering::Relaxed);
        STALLS.store(false, Ordering::Relaxed);
    }

    /// No transaction spending `coin` handed to the node: as a hub that
    /// withholds an F spending it, or whose broadcasts never relay.
    pub(super) fn withhold(&self, coin: bitcoin::OutPoint) {
        WITHHELD.lock().unwrap().push(coin);
    }
}

/// Whether `params`, of `sendrawtransaction`, hand the node a transaction
/// spending a coin [`WITHHELD`].
fn withheld(params: &serde_json::Value) -> bool {
    let tx = params[0].as_str().and_then(|hex| {
        bitcoin::consensus::encode::deserialize_hex::<bitcoin::Transaction>(hex).ok()
    });
    let withheld = WITHHELD.lock().unwrap();
    tx.is_some_and(|tx| (tx.input.iter()).any(|i| withheld.contains(&i.previous_output)))
}

impl Drop for Severable {
    fn drop(&mut self) {
        SEVERABLE.store(false, Ordering::Relaxed);
        WITHHELD.lock().unwrap().clear();
        self.up();
    }
}

/// `real`, as the hubs made next reach it: through [`through`] while a
/// [`Severable`] lives, else as it is.
pub(super) async fn reached(real: Source) -> Result<Source> {
    match SEVERABLE.load(Ordering::Relaxed) {
        true => through(real).await,
        false => Ok(real),
    }
}

/// The node of `real` as a JSON-RPC in front of it, answering every call
/// 503 with no body while [`DOWN`], as a node's RPC refusing work, or
/// none for 10 minutes if it [`STALLS`].
async fn through(real: Source) -> Result<Source> {
    use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json};
    use serde_json::Value;
    async fn answer(
        State(real): State<Source>,
        Json(call): Json<Value>,
    ) -> axum::response::Response {
        if DOWN.load(Ordering::Relaxed) {
            if STALLS.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            }
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let (method, params, id) = (
            call["method"].as_str().unwrap_or_default(),
            call["params"].clone(),
            call["id"].clone(),
        );
        if method == "sendrawtransaction" && withheld(&params) {
            let error = serde_json::json!({ "code": -26, "message": "withheld" });
            return Json(serde_json::json!({ "result": null, "error": error, "id": id }))
                .into_response();
        }
        Json(forwarded(&real, method, params, id).await.0).into_response()
    }
    let app = axum::Router::new().fallback(post(answer)).with_state(real);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(async move { axum::serve(listener, app).await });
    url.parse()
}

/// The blocks before her request's deadline (the height her timeout spends
/// at) at which the hub's node comes back: enough for its response to be
/// mined, with the regtest margin.
const BACK_BEFORE: u32 = 4;

/// A stale claim's request posted while the hub's node is out of reach:
/// every block until shortly before its deadline, the hub's rounds fail,
/// and the hub neither crashes nor gives anything up for it. Its node back,
/// it meets the claim with the spend it released, in a block before the
/// deadline, and pays her what is left, as it would have at once.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_hub_whose_node_was_out_of_reach_meets_a_stale_claim_before_its_deadline() -> Result<()> {
    use licash_contracts::holder::recovery::{self, Stage};

    let severable = Severable::on();
    let s = stale_claim([13; 32]).await?;
    let file = s.mine.join("wallet.sqlite");
    // Her request in a block ([`stale_claim`]), the hub's node cut off
    // before the hub's first round after it.
    severable.down();
    let cut = s.rt.height()?;
    // The heights the hub's node is back at, and her timeout's, as her
    // request's block tells it.
    let (mut back, mut deadline, mut failed) = (None, None, 0);
    let mut last = None;
    for _ in 0..800 {
        s.rt.mine(1)?;
        let height = s.rt.height()?;
        if let (None, Some(deadline)) = (back, deadline) {
            if height + BACK_BEFORE >= deadline {
                severable.up();
                back = Some(height);
            }
        }
        let round = s.openings.answer_requests().await;
        match back.is_some() {
            // Reaching its node, the hub plays every round.
            true => ensure!(round.as_ref().is_ok_and(|r| r.failed == 0), "{round:?}"),
            false => failed += usize::from(round.is_err() || round.is_ok_and(|r| r.failed > 0)),
        }
        let r = recovery::advance(&s.wallet, &s.chain, &file, s.rate).await?[0].clone();
        ensure!(r.stage != Stage::Lost, "{r:?}");
        if r.stage == Stage::Requested && deadline.is_none() {
            let at = r.next_at.context("a request of no timeout")?;
            ensure!(at > height + BACK_BEFORE, "too late to come back: {r:?}");
            deadline = Some(at);
        }
        if r.stage == Stage::Done {
            let (back, deadline) = (back.context("never back")?, deadline.context("none")?);
            ensure!(failed > 0, "no round failed while its node was down");
            let x = r.response.context("no response")?;
            // The height of the block it is in, despite its name.
            let mined = s.rt.confirmations(&x)?.context("unmined")?;
            ensure!(
                back < mined && mined < deadline,
                "{cut} {back} {mined} {r:?}"
            );
            ensure!(r.corrected == Some(98_304), "{r:?}");
            ensure!(r.payout.is_some() && r.timeout.is_none(), "{r:?}");
            eprintln!(
                "its node out of reach {} blocks ({failed} rounds failed): \
                 responded at {mined}, {} before its deadline",
                back - cut,
                deadline - mined
            );
            return Ok(());
        }
        last = Some(r);
    }
    anyhow::bail!("never paid: {last:?}")
}

/// A round of the hub's responder while its node holds every call
/// unanswered: how long it takes, printed, and that it ends, failed,
/// rather than hanging; its node back, the next round plays.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn a_round_of_a_hub_whose_node_stalls_ends_failed() -> Result<()> {
    let severable = Severable::on();
    let s = stale_claim([14; 32]).await?;
    severable.stalled();
    s.rt.mine(1)?;
    let started = std::time::Instant::now();
    let round = tokio::time::timeout(
        std::time::Duration::from_secs(590),
        s.openings.answer_requests(),
    )
    .await;
    let took = started.elapsed();
    eprintln!("a round with its node stalled took {took:.1?}: {round:?}");
    let round = round.context("a round still waiting on its node")?;
    ensure!(round.is_err() || round.is_ok_and(|r| r.failed > 0));
    severable.up();
    let round = s.openings.answer_requests().await?;
    ensure!(round.failed == 0, "{round:?}");
    Ok(())
}
