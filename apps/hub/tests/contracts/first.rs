//! She signs her deposit into F before the hub signs its inputs: what they
//! check is that the hub signs only on her valid signature, and that a hub
//! which then withholds F, the whole of which it alone holds, or answers
//! it signed otherwise, has her coin taken back from it
//! [`holder::F_UNSEEN`] blocks on.

use licash_contract::wire::{self, Envelope, Kind};
use licash_contracts::Frame;

use super::*;

/// What [`Meddling`] does to her consent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Meddle {
    /// Her deposit's signature in it spoiled on the way to the hub.
    Spoil,
    /// The hub's answer to it lost, every time: she never hears F whole.
    Hush,
    /// The hub's signatures in its answer spoiled: F whole to her, which
    /// no node takes.
    Junk,
}

/// `answer`, the hub's frames, with the signatures of its inputs of each F
/// answered whole spoiled: all but her `deposit`'s.
fn spoiled(answer: &[u8], deposit: bitcoin::OutPoint) -> Result<Vec<u8>, String> {
    let frames = Frame::decode_all(answer).map_err(|e| e.to_string())?;
    let frames = frames.into_iter().map(|Frame::Message(bytes)| {
        let Ok(mut envelope) = Envelope::from_bytes(&bytes) else {
            return Frame::Message(bytes);
        };
        if envelope.kind != Kind::Funded {
            return Frame::Message(bytes);
        }
        let mut funded = wire::Funded::decode(&envelope.body).expect("F");
        for input in &mut funded.funding.input {
            if input.previous_output != deposit {
                let mut sig = input.witness.to_vec();
                sig[0][0] ^= 1;
                input.witness = bitcoin::Witness::from_slice(&sig);
            }
        }
        envelope.body = funded.encode();
        Frame::Message(envelope.to_bytes())
    });
    Ok(Frame::encode_all(&frames.collect::<Vec<_>>()))
}

/// [`Http`], but her consent ([`Meddle`]d) as `meddle` says; all else
/// passes.
struct Meddling {
    http: Http,
    meddle: Meddle,
    /// Her deposit, once known.
    deposit: std::sync::Mutex<Option<bitcoin::OutPoint>>,
}

/// The kind byte of an opening's message: after its magic and version.
const KIND_AT: usize = 6;
/// The kind of her consent ([`licash_contract::wire::Kind::Consent`]).
const CONSENT: u8 = 8;

impl licash_wallet::Transport for Meddling {
    async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<licash_wallet::Response, String> {
        let consent = url.contains("/v1/contracts/openings/")
            && body
                .as_ref()
                .is_some_and(|b| b.get(KIND_AT) == Some(&CONSENT));
        match (consent, self.meddle, body) {
            (true, Meddle::Spoil, Some(mut body)) => {
                // Her consent ends with her deposit's Schnorr signature.
                *body.last_mut().expect("a consent") ^= 1;
                self.http.request(url, Some(body)).await
            }
            (true, Meddle::Hush, body) => {
                self.http.request(url, body).await?;
                Err("no answer over Tor in 120 s".into())
            }
            (true, Meddle::Junk, body) => {
                let mut answer = self.http.request(url, body).await?;
                let deposit = self.deposit.lock().unwrap().expect("her deposit");
                if answer.status == 200 {
                    answer.body = spoiled(&answer.body, deposit)?;
                }
                Ok(answer)
            }
            (_, _, body) => self.http.request(url, body).await,
        }
    }
}

/// How many coins the hub's node's wallet has locked.
async fn locked(chain: &Node) -> Result<usize> {
    let locked: Vec<serde_json::Value> = chain
        .0
        .rpc("listlockunspent", serde_json::json!([]))
        .await?;
    Ok(locked.len())
}

/// Three holders whose openings stop once each signed her deposit into F:
/// one's signature spoiled on the way, which the hub refuses, signing
/// nothing; the others' taken, the hub signing F and broadcasting it, but
/// F never relayed, and its answer never heard, as from a hub withholding
/// it, or heard with the hub's signatures spoiled, as from a hub keeping
/// her cancel off with an F no node takes. No F confirms. [`holder::F_UNSEEN`] blocks after each signed,
/// and not before, each takes her coin back, which her wallet finds as
/// change; the hub, its coins in the F it signed freed once her cancel is
/// deep, holds no contract.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs bitcoind and a release build"]
async fn she_takes_her_coin_back_from_a_hub_that_never_completes_f() -> Result<()> {
    let severable = outage::Severable::on();
    let rt = Regtest::start_standard()?;
    let dir = tempfile::tempdir()?;
    let hub_dir = dir.path().join("hub");
    let (url, source, _, openings) = hub_answering(&rt, &hub_dir).await?;
    let chain = Node(source.clone());

    let mut holders = Vec::new();
    let meddles = [Meddle::Spoil, Meddle::Hush, Meddle::Junk];
    for (n, meddle) in meddles.into_iter().enumerate() {
        let transport = Meddling {
            http: Http::new(None)?,
            meddle,
            deposit: Default::default(),
        };
        let at = dir.path().join(format!("holder{n}"));
        let seed = [50 + n as u8; 32];
        let (mine, wallet) =
            holder_wallet_over(&rt, &chain, &at, &url, seed, &[COIN], transport).await?;
        let deposit = wallet.silent_coins()?[0].outpoint;
        *wallet.transport().deposit.lock().unwrap() = Some(deposit);
        severable.withhold(deposit);
        let file = mine.join("wallet.sqlite");
        let opened = holder::open(&wallet, &chain, &file, &url, ask()).await;
        // Answered F whole, which no node takes: opened, to her.
        ensure!(
            opened.is_err() != (meddle == Meddle::Junk),
            "opened: {opened:?}"
        );
        let listed = holder::list(&file)?;
        ensure!(listed.len() == 1, "{listed:?}");
        let contract = &listed[0];
        ensure!(contract.phase == Phase::Funded, "{contract:?}");
        ensure!(contract.abandoned.is_none(), "{contract:?}");
        let f = contract.funding.context("no F")?;
        ensure!(rt.get_tx(&f).is_err(), "F broadcast");
        // Her coin held for F, which the hub alone may complete.
        ensure!(wallet.silent_coins()?[0].spending == Some(f));
        let signed = rt.height()?;
        holders.push((wallet, file, deposit, f, signed));
    }
    // The hub signed those whose signature it was given whole, and only
    // them.
    ensure!(licash_contracts::hub::signed(&hub_dir)? == 2);
    openings.answer_requests().await?;
    let held = locked(&chain).await?;

    // Not before F_UNSEEN blocks after she signed.
    let last = holders.iter().map(|h| h.4).max().context("two")?;
    rt.mine_to_height(last + holder::F_UNSEEN - 1)?;
    for (wallet, file, _, f, signed) in &holders {
        holder::resume(wallet, &chain, file).await?;
        if rt.height()? < signed + holder::F_UNSEEN {
            ensure!(
                wallet.silent_coins()?[0].spending == Some(*f),
                "canceled early"
            );
        }
    }
    rt.mine(1)?;
    let mut cancels = Vec::new();
    for (wallet, file, deposit, f, _) in &holders {
        holder::resume(wallet, &chain, file).await?;
        let coin = wallet.silent_coins()?;
        let cancel = coin[0].spending.context("her coin spent by nothing")?;
        ensure!(cancel != *f, "not canceled");
        let tx = rt.get_tx(&cancel)?;
        ensure!(tx.input.len() == 1 && tx.input[0].previous_output == *deposit);
        // Asked again, the same cancel.
        holder::resume(wallet, &chain, file).await?;
        ensure!(wallet.silent_coins()?[0].spending == Some(cancel));
        cancels.push(cancel);
    }
    rt.mine(1)?;
    for ((wallet, ..), cancel) in holders.iter().zip(&cancels) {
        ensure!(rt.confirmations(cancel)?.is_some(), "cancel unmined");
        scan(wallet, &chain).await?;
        let coins = wallet.silent_coins()?;
        ensure!(
            coins.len() == 1 && coins[0].change && coins[0].outpoint.txid == *cancel,
            "her coin not back: {coins:?}"
        );
    }

    // Her cancel deep, the hub gives up the F it signed, its coins freed.
    rt.mine(6)?;
    openings.answer_requests().await?;
    ensure!(
        licash_contracts::hub::signed(&hub_dir)? == 0,
        "not given up"
    );
    let left = locked(&chain).await?;
    ensure!(left < held, "{left} of {held} coins locked");
    for (wallet, file, ..) in &holders {
        holder::resume(wallet, &chain, file).await?;
        let listed = holder::list(file)?;
        ensure!(listed[0].fate == Some(Fate::Dead), "{listed:?}");
    }
    drop(severable);
    Ok(())
}
