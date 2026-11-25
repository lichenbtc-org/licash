//! The Android app among the stack of `apps/e2e/run.sh`, on the emulator or
//! phone adb picks, as its user sees it: made, paid on Bitcoin and in
//! Licash, paying, told what went wrong, and started again. Skipped unless
//! `LICASH_E2E_APP` names the app's APK. What it showed and logged on a
//! failure is kept beside the stack's logs.

use std::{path::PathBuf, time::Duration};

use anyhow::{ensure, Context};
use licash_e2e::{
    phone::{amount, Phone, View},
    until, Eco, OUTSIDE,
};
use licash_nostr::{wallet, Route};
use licash_wallet::{PaymentCode, PaymentNote};
use serde_json::json;

/// The most keeping its notes few costs at a time, in sat: the wallet
/// remints notes by itself once they have rested a while of its choosing,
/// so between reading a balance and looking again, a few sat may go.
const NOTES_UPKEEP: u64 = 50;

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh and an Android device"]
async fn the_app_is_paid_and_pays_on_bitcoin_and_in_licash() -> anyhow::Result<()> {
    let Some(phone) = Phone::from_env() else {
        eprintln!("skipped: LICASH_E2E_APP names no APK of the app");
        return Ok(());
    };
    let eco = Eco::up().await?;
    phone.fresh(&eco).await?;
    let used = used(&eco, &phone).await;
    if used.is_err() {
        keep(&phone).await;
    }
    used
}

/// What the app shows and logged, beside the stack's logs.
async fn keep(phone: &Phone) {
    let dir = std::env::var_os("LICASH_E2E_LOGS").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/e2e"),
        PathBuf::from,
    );
    let _ = std::fs::create_dir_all(&dir);
    let _ = phone.screenshot(&dir.join("app.png")).await;
    for log in ["app.log", "chain.log"] {
        if let Ok(text) = phone.file(&format!("files/logs/{log}")).await {
            let _ = std::fs::write(dir.join(format!("app-{log}")), text);
        }
    }
}

/// A hub as the app names it: its host and port.
fn name(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.trim_end_matches('/')
}

/// Whatever waits in the mempool, mined.
async fn mine(eco: &Eco) -> anyhow::Result<()> {
    let waiting = eco.core("getmempoolinfo", json!([])).await?["size"].as_u64();
    if waiting.unwrap_or(0) > 0 {
        eco.mine(1).await?;
    }
    Ok(())
}

/// The history, opened from Home: what it shows.
async fn history(phone: &Phone) -> anyhow::Result<Vec<View>> {
    phone.tap_id("activity").await?;
    // Home says "Activity" too: the history's own list, then.
    phone.by_id("history", 30).await?;
    phone.views().await
}

/// What the history came to, opened from it: the fees paid in all of it said,
/// as a sum, and a way back to Home.
async fn stats(phone: &Phone) -> anyhow::Result<()> {
    history(phone).await?;
    phone.tap_id("stats-open").await?;
    phone.by_id("stats", 30).await?;
    phone.tap("All").await?;
    // Paid and received by now: something cost, and the page says what.
    let fees = phone.by_id("stats-fees", 30).await?;
    ensure!(
        fees.text == "None" || fees.text.ends_with(" sat"),
        "fees paid said as {:?}",
        fees.text
    );
    // Back to the history, and Home.
    phone.back_to("history").await?;
    phone.back_to("receive").await?;
    Ok(())
}

/// The newest line of the history titled `title`, opened from Home: where
/// it stands is shown first.
async fn opened(phone: &Phone, title: &str) -> anyhow::Result<()> {
    phone.tap_id("activity").await?;
    let line = until(&format!("a line {title:?} in the history"), 30, || async {
        Ok(phone.views().await?.into_iter().find(|v| v.text == title))
    })
    .await?;
    phone.tap_view(&line).await?;
    phone.by_id("state", 30).await?;
    Ok(())
}

/// What a payment to confirm must say before it is agreed to: what it
/// costs, and when it arrives.
async fn reviewed(phone: &Phone, secs: u64) -> anyhow::Result<()> {
    let fee = phone.by_id("fee", secs).await?;
    ensure!(!fee.text.is_empty(), "no fee said");
    let arrives = phone.by_id("arrives", 10).await?;
    ensure!(!arrives.text.is_empty(), "no time of arrival said");
    Ok(())
}

/// Mine whatever waits in the mempool until Home says nothing is under
/// way, and the history shows `moves` payments on Bitcoin moved into the
/// balance.
async fn settle(eco: &Eco, phone: &Phone, moves: usize) -> anyhow::Result<()> {
    let what = format!("{moves} payments on Bitcoin moved into the balance");
    until(&what, 300, || async {
        mine(eco).await?;
        // Home's one line of what is going on: gone once nothing is.
        if phone.has("status").await? {
            return Ok(None);
        }
        let lines = history(phone).await?;
        let moved = lines.iter().filter(|v| v.text == "From Bitcoin").count();
        // On its way, or found on Bitcoin and not moved in yet.
        let busy = lines
            .iter()
            .any(|v| v.id == "pending" || v.text == "Arriving" || v.text == "On Bitcoin");
        phone.back_to("receive").await?;
        Ok((moved == moves && !busy).then_some(()))
    })
    .await
}

/// What was paid on Bitcoin, once found there, added to the balance with
/// no protection, as its owner asks once warned: nothing moves by itself.
async fn move_in(eco: &Eco, phone: &Phone) -> anyhow::Result<()> {
    on_bitcoin(phone).await?;
    until("the payment found on Bitcoin", 300, || async {
        mine(eco).await?;
        Ok(phone.views().await?.into_iter().find(|v| v.id == "move-in"))
    })
    .await?;
    ensure!(
        !phone.has("moving").await?,
        "what was paid on Bitcoin moved in by itself"
    );
    phone.tap_id("move-in").await?;
    phone.wait("Not protected", 10).await?;
    phone.tap_id("move-in-anyway").await?;
    phone.gone("move-in-anyway", 30).await?;
    phone.back_to("onchain").await?;
    phone.back_to("receive").await?;
    Ok(())
}

/// Wait for the balance Home shows to change from `from`: the new one.
async fn changed(phone: &Phone, from: u64, secs: u64) -> anyhow::Result<u64> {
    until("the balance to change", secs, || async {
        let now = phone.balance().await?;
        Ok((now != from).then_some(now))
    })
    .await
}

/// Its silent payment address `silent` alone, among the other ways on
/// Receive, for any amount.
async fn silently(phone: &Phone, silent: &str) -> anyhow::Result<()> {
    phone.tap_id("receive").await?;
    phone.tap_id("other-ways").await?;
    phone.tap_id("way-silent").await?;
    phone.tagged("silent", silent, 30).await?;
    phone.tagged("asking", "Any amount, on Bitcoin", 10).await?;
    phone.tap("Back").await?;
    phone.home(30).await
}

/// Bob paid again, picked by name among the contacts rather than scanned.
/// A separate code, made on Receive under a name: not the wallet's own,
/// paid by Bob, moved to the balance less the hub's fee, and shown in the
/// history as paid to it.
async fn separate_code(phone: &Phone, bob: &licash_e2e::Wallet) -> anyhow::Result<()> {
    let own = phone.code().await?;
    phone.tap_id("receive").await?;
    phone.wait("QR code", 30).await?;
    phone.tap_id("other-ways").await?;
    phone.tap_id("which-code").await?;
    phone.tap_id("new-code").await?;
    // Typed, the keyboard not hidden after: in a sheet, Escape closes the
    // sheet when no keyboard takes it, and the sheet clears one that shows.
    phone.tap_id("code-label").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    phone.type_text("Forum").await?;
    phone.tap_id("create-code").await?;
    let shown = until("the separate code", 30, || async {
        let shown = phone.qr(30).await?;
        Ok((shown != own).then_some(shown))
    })
    .await?;
    phone.tap("Back").await?;
    phone.home(30).await?;

    let before = phone.balance().await?;
    let code: PaymentCode = shown.parse()?;
    let paid = wallet::pay(bob, &code, Some(2_000), &PaymentNote::default()).await?;
    ensure!(paid.paid.kept, "not kept at the hub: {paid:?}");
    let now = changed(phone, before, 90).await?;
    ensure!(
        (1_900..2_000).contains(&(now - before)),
        "{} moved in of 2000 paid to a separate code",
        now - before
    );
    let lines = history(phone).await?;
    ensure!(
        lines
            .iter()
            .any(|v| v.id == "row-code" && v.text == "To Forum"),
        "no payment to the separate code in the history"
    );
    phone.back_to("receive").await?;
    Ok(())
}

async fn contact(phone: &Phone, bob: &licash_e2e::Wallet) -> anyhow::Result<()> {
    let before = phone.balance().await?;
    phone.tap_id("send").await?;
    phone.tap_id("contact Bob").await?;
    until("the amount to type in", 10, || async {
        let views = phone.views().await?;
        Ok(views
            .iter()
            .any(|v| v.id == "amount" && v.focused)
            .then_some(()))
    })
    .await?;
    phone.type_text("1000").await?;
    // Whom it pays, a contact: by name.
    phone.tagged("to", "Bob", 10).await?;
    phone.tagged("arrives", "Instantly", 10).await?;
    phone.tap_id("confirm").await?;
    phone.tagged("result", "Sent", 60).await?;
    phone.tagged("contact", "To Bob", 10).await?;
    phone.tap_id("done").await?;
    ensure!(
        collected(bob, 60).await? == 1_000,
        "Bob got other than 1000"
    );
    changed(phone, before, 30).await?;
    Ok(())
}

/// Paid over Lightning: an invoice its hub makes asking the amount it
/// enters, the hub's fee in it, shown as a QR code as soon as it has an
/// amount, which a node outside pays. Its notes are taken while shown, and the payment is in the
/// history.
async fn lightning(eco: &Eco, phone: &Phone) -> anyhow::Result<()> {
    let before = phone.balance().await?;
    // What the wallet gets of an invoice asking 4000: the most that fits
    // with the hub's fee on it.
    let info = eco.info(eco.hub(1)).await?;
    let receive = info.lightning.context("hub 1 takes no Lightning")?.receive;
    let gets = (0..=4_000u64)
        .rev()
        .find(|n| n + receive.due(*n) <= 4_000)
        .context("no amount fits 4000 with its fee")?;
    phone.tap_id("receive").await?;
    phone.tap_id("set-amount").await?;
    phone.tap_id("amount").await?;
    phone.type_text("4000").await?;
    // A memo for the payer: hub 1 puts one in its invoices.
    phone.fill_id("memo-field", "Pizza night").await?;
    phone.tap_id("done").await?;
    phone.tagged("way", "Lightning invoice", 10).await?;
    phone.tagged("asking", "4,000 sat", 10).await?;
    phone
        .tagged("memo", "\u{201c}Pizza night\u{201d}", 10)
        .await?;
    // In upper case, as a QR code holds it best.
    let shown = phone.qr(60).await?;
    let request = shown.to_lowercase();
    ensure!(
        request.starts_with("lnbcrt"),
        "{shown} shown for an invoice"
    );
    let paying = eco.pay(OUTSIDE, &request);
    let says = format!("Received {},{:03} sat", gets / 1_000, gets % 1_000);
    phone.tagged("received", &says, 120).await?;
    ensure!(paying.await??, "the node outside did not pay {request}");
    phone.tap("Back").await?;
    phone.home(30).await?;
    let now = changed(phone, before, 30).await?;
    ensure!(
        now == before + gets,
        "{now} held after {gets} of 4000 over Lightning"
    );
    opened(phone, "Received over Lightning").await?;
    phone.tagged("state", "In your balance", 10).await?;
    phone.tagged("memo", "Pizza night", 10).await?;
    phone.back().await?;
    phone.back_to("receive").await?;
    Ok(())
}

/// Paid an invoice of the node outside through the swap provider, chosen
/// in advanced mode over its hub's gateway: the provider's node pays it for
/// a lock of the app's notes at hub 1, and claims the lock with the
/// preimage. The confirm screen names the provider and how long the sats
/// would wait should it not pay; the history, who paid it.
async fn paid_through_provider(eco: &Eco, phone: &Phone) -> anyhow::Result<()> {
    let before = phone.balance().await?;
    let (request, hash) = eco.invoice(OUTSIDE, 2_000).await?;
    phone.link(&format!("lightning:{request}")).await?;
    phone.tagged("paying", "2,000 sat", 120).await?;
    // Every way to pay it: hub 1's gateway and the provider, announced as
    // "swaps"; the provider chosen, unless it was already, the cheapest.
    phone.tap_id("providers").await?;
    phone.wait("swaps", 120).await?;
    if phone.has("use swaps").await? {
        phone.tap_id("use swaps").await?;
    }
    phone.tagged("through", "swaps", 30).await?;
    let wait = phone.by_id("refund-wait", 10).await?;
    ensure!(
        wait.text.contains("declines or fails"),
        "{:?} said of a payment the provider may not make",
        wait.text
    );
    phone.tagged("arrives", "In seconds", 10).await?;
    phone.tap_id("confirm").await?;
    // Paid at once, or under way while the provider pays.
    let result = until("the payment's result", 60, || async {
        let views = phone.views().await?;
        let result = views.into_iter().find(|v| v.id == "result");
        Ok(result.filter(|v| v.text.starts_with("Paid") || v.text == "Under way"))
    })
    .await?;
    eprintln!("paying through the provider: {:?}", result.text);
    phone.tap_id("done").await?;
    until("the outside invoice settled", 180, || async {
        let (state, _) = eco.invoice_state(OUTSIDE, &hash).await?;
        Ok((state == "SETTLED").then_some(()))
    })
    .await?;
    phone.back_to("receive").await?;
    // Less what it asked and fees of a few sat, once the lock's change is
    // back in the balance.
    let after = until("the balance less the payment", 60, || async {
        let now = phone.balance().await?;
        Ok((now < before - 2_000 && now > before - 2_100).then_some(now))
    })
    .await?;
    eprintln!("{after} held after paying 2000 through the provider from {before}");
    // Claimed by the provider with the preimage: paid, through it.
    opened(phone, "Paid over Lightning").await?;
    phone.tagged("state", "Paid", 180).await?;
    let through = phone.by_id("through", 10).await?;
    eprintln!("paid through {:?}", through.text);
    phone.back().await?;
    phone.back_to("receive").await?;
    Ok(())
}

/// Paid at its static donation address, among the other ways on Receive
/// once the provider announced takes donations at its hub: an LNURL of the
/// provider's, its code in it, which the node outside pays while the app is
/// stopped. The provider pays the donation, its fee taken, in notes kept at
/// the hub, which the app takes once started again.
async fn donated(eco: &Eco, phone: &Phone) -> anyhow::Result<()> {
    use bitcoin::bech32;

    let terms = eco.swaps_info().await?.donations;
    let terms = terms.context("the provider takes no donations")?;
    let code: PaymentCode = phone.code().await?.parse()?;
    let code = code.licash.context("a Licash code")?.to_string();
    phone.tap_id("receive").await?;
    phone.tap_id("other-ways").await?;
    // Listed once the provider is found, looked for as Receive opens.
    phone.by_id("way-donations", 120).await?;
    phone.tap_id("way-donations").await?;
    phone.tagged("way", "Donation address", 30).await?;
    let range = format!("{} sat to {} sat", digits(terms.min), digits(terms.max));
    phone.tagged("asking", &range, 10).await?;
    phone.wait("Paid to you in notes by swaps", 10).await?;
    // In upper case, as a QR code holds it best: the app's very code, at
    // the URL payers reach the provider at.
    let shown = phone.qr(30).await?;
    ensure!(shown.starts_with("LNURL1"), "{shown} shown for donations");
    let (_, url) = bech32::decode(&shown)?;
    let url = String::from_utf8(url)?;
    ensure!(
        url == format!("{}/v1/lnurlp/{code}", terms.url),
        "{url} for the code {code}"
    );
    phone.tap("Back").await?;
    phone.home(30).await?;

    // Stopped, the app is paid as LNURL-pay has it.
    let before = phone.balance().await?;
    phone
        .shell(&format!("am force-stop {}", licash_e2e::phone::PACKAGE))
        .await?;
    let request = eco.get_json(&url).await?;
    ensure!(request["tag"] == "payRequest", "{request}");
    let callback = request["callback"].as_str().context("a callback")?;
    let donated = 1_000;
    let invoice = eco
        .get_json(&format!("{callback}?amount={}", donated * 1_000))
        .await?;
    let pr = invoice["pr"]
        .as_str()
        .with_context(|| format!("{invoice}"))?;
    ensure!(
        eco.pay(OUTSIDE, pr).await??,
        "the node outside did not pay {pr}"
    );

    phone.launch().await?;
    phone.home(60).await?;
    let gets = donated - terms.fee.due(donated);
    // Resuming can also charge a note optimization fee. Check the
    // donation itself in Activity, where it is separate from that fee.
    until(
        "the balance to increase after the donation",
        120,
        || async { Ok((phone.balance().await? > before).then_some(())) },
    )
    .await?;
    opened(phone, "Received").await?;
    phone
        .tagged("amount", &format!("+{} sat", digits(gets)), 10)
        .await?;
    phone.tagged("state", "Received", 10).await?;
    phone.back().await?;
    phone.back_to("receive").await
}

/// `12,345`, as the app writes amounts.
fn digits(amount: u64) -> String {
    let text = amount.to_string();
    let mut out = String::new();
    for (i, c) in text.chars().enumerate() {
        if i > 0 && (text.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Collect Bob's mailbox, for up to `secs`, until it holds payments: their
/// sum.
async fn collected(bob: &licash_e2e::Wallet, secs: u64) -> anyhow::Result<u64> {
    until("a payment in Bob's mailbox", secs, || async {
        let collected = wallet::collect(bob, &Route::Direct).await?;
        let sum: u64 = collected.received.iter().map(|r| r.amount).sum();
        Ok((sum > 0).then_some(sum))
    })
    .await
}

async fn used(eco: &Eco, phone: &Phone) -> anyhow::Result<()> {
    let hub = eco.hub(1);
    let first = phone.launch().await?;
    eprintln!("first start in {first:?}");
    phone.onboard().await?;
    phone.connect(hub).await?;

    // Its code names the hub and its mailbox, nothing on Bitcoin; its
    // address on Bitcoin, in a tab of its own, bare, for any wallet; its
    // silent payment address under More, the hub serving tweaks.
    let shown: PaymentCode = phone.code().await?.parse()?;
    ensure!(
        shown.address.is_none() && shown.silent.is_none(),
        "Bitcoin in {shown}"
    );
    let licash = shown.licash.clone().context("a Licash code")?;
    ensure!(licash.mailbox.is_some(), "no mailbox in {shown}");
    let code: PaymentCode = phone.bitcoin_code().await?.parse()?;
    ensure!(code.licash.is_none(), "a Licash code in {code}");
    let fallback = code.address.clone().context("a fallback address")?;
    let fallback = fallback.assume_checked().to_string();
    ensure!(code.silent.is_none(), "a silent payment address in {code}");
    let silent = phone.silent_address().await?;
    // A wallet with nothing yet: its first funding is a screen of its
    // own, which Home's card leads back to, to that same address, bare,
    // and one figure to send at least.
    phone.tap_id("setup-card-go").await?;
    phone.tagged("funding-title", "Fill your vault", 30).await?;
    let asked = phone.by_id("funding-how-much", 10).await?;
    ensure!(
        asked.text.starts_with("Send at least 50,000 sat."),
        "{:?} asked for",
        asked.text
    );
    let guided = phone.qr(30).await?;
    ensure!(
        guided == format!("BITCOIN:{}", fallback.to_uppercase()),
        "{guided} guided to, {fallback} on Receive"
    );
    // Paid at the fallback address: its steps say it was seen, and Home,
    // once gone to, that it is on its way; then it is found in a block
    // and moved into the balance once asked, the next address shown from
    // then on.
    eco.send_to(&fallback, 30_000).await?;
    phone.tagged("funding-title", "Seen", 60).await?;
    phone.home(30).await?;
    phone.tagged("status", "Receiving 30,000 sat", 60).await?;
    eco.mine(1).await?;
    move_in(eco, phone).await?;
    settle(eco, phone, 1).await?;
    let moved = phone.balance().await?;
    // Less the hub's 1000 and the fees of the move on Bitcoin.
    ensure!(
        (25_000..29_000).contains(&moved),
        "{moved} of 30000 moved in"
    );
    // Opened, the move shows what it cost: the hub's 1000 and the miners'.
    opened(phone, "From Bitcoin").await?;
    phone.tagged("state", "In your balance", 10).await?;
    let hubs = phone.by_id("fee-hub", 10).await?;
    ensure!(hubs.text == "1,000 sat", "a hub fee of {:?}", hubs.text);
    phone.by_id("fee-network", 10).await?;
    phone.back().await?;
    phone.back_to("receive").await?;
    let next: PaymentCode = phone.bitcoin_code().await?.parse()?;
    ensure!(next.address != code.address, "paid at, and shown again");
    ensure!(
        phone.silent_address().await? == silent,
        "another silent payment address"
    );

    let bob = eco.wallet("bob")?;
    bob.add_hub(hub).await?;
    let bobs = bob.payment_code(&[hub.to_owned()])?;
    // Check refusals before later payments build up enough notes to optimize.
    refused(eco, phone, &bobs).await?;

    // Paid at its silent payment address: found and moved in too.
    eco.pay_silent(&silent, 20_000).await?;
    eco.mine(1).await?;
    move_in(eco, phone).await?;
    settle(eco, phone, 2).await?;
    let held = phone.balance().await?;
    ensure!(
        (15_000..19_000).contains(&(held - moved)),
        "{} moved in",
        held - moved
    );
    silently(phone, &silent).await?;

    // It pays Bob at the hub, an amount it enters, to his mailbox.
    phone.link(&bobs.to_string()).await?;
    // Typed straight in: the field has the focus, untouched.
    until("the amount to type in", 10, || async {
        let views = phone.views().await?;
        Ok(views
            .iter()
            .any(|v| v.id == "amount" && v.focused)
            .then_some(()))
    })
    .await?;
    phone.type_text("5000").await?;
    // What it costs, as the wallet would pay it, and when it arrives,
    // before it is paid.
    let fee = until("the fee of 5000", 10, || async {
        let views = phone.views().await?;
        let fee = views.into_iter().find(|v| v.id == "fee");
        Ok(fee.and_then(|v| match v.text.as_str() {
            "None" => Some(0),
            text => text
                .strip_suffix(" sat")?
                .replace(',', "")
                .parse::<u64>()
                .ok(),
        }))
    })
    .await?;
    eprintln!("paying 5000, fee: {fee}");
    // Whom it pays, no contact yet: the start of his code.
    let text = bobs.to_string();
    let body = text.strip_prefix("licash:").unwrap_or(&text);
    phone.tagged("to", &body[..10], 10).await?;
    phone.tagged("arrives", "Instantly", 10).await?;
    // A note for Bob, sealed for him alone.
    phone.fill_id("note-field", "for the pizza").await?;
    phone.tap_id("confirm").await?;
    phone.tagged("result", "Sent", 60).await?;
    // Bob, kept as a contact once paid.
    phone.tap_id("save-contact").await?;
    phone.fill_id("contact-name", "Bob").await?;
    phone.tap_id("save-contact-name").await?;
    phone.tagged("contact", "To Bob", 10).await?;
    phone.tap_id("done").await?;
    ensure!(
        collected(&bob, 60).await? == 5_000,
        "Bob got other than 5000"
    );
    let notes = bob.payment_notes()?;
    ensure!(
        notes
            .values()
            .any(|n| n.text.as_deref() == Some("for the pizza") && n.from.is_none()),
        "Bob read no note: {notes:?}"
    );
    let after = changed(phone, held, 30).await?;
    // At most what was shown: the wallet pays no more than it quoted, the
    // notes it makes counted.
    ensure!(
        (5_000..=5_000 + fee).contains(&(held - after)),
        "{} spent paying 5000",
        held - after
    );

    // Bob pays its code back, kept at the hub for the app, which takes it
    // there by itself: nothing mailed.
    let code: PaymentCode = phone.code().await?.parse()?;
    // With a note, and his code: the app shows the note.
    let thanks = PaymentNote {
        text: Some("thanks".into()),
        from: bobs.licash.clone(),
    };
    let paid = wallet::pay(&bob, &code, Some(3_000), &thanks).await?;
    ensure!(paid.paid.kept, "not kept at the hub: {paid:?}");
    let now = changed(phone, after, 90).await?;
    ensure!(now == after + 3_000, "{now} held after 3000 received");
    let lines = history(phone).await?;
    ensure!(
        lines.iter().any(|v| v.text == "Received"),
        "no payment received in the history"
    );
    ensure!(
        lines
            .iter()
            .any(|v| v.id == "row-memo" && v.text == "thanks"),
        "no note shown in the history"
    );
    phone.back_to("receive").await?;
    contact(phone, &bob).await?;
    separate_code(phone, &bob).await?;

    lightning(eco, phone).await?;
    paid_through_provider(eco, phone).await?;
    donated(eco, phone).await?;
    hub_down(eco, phone, &bob, &bobs).await?;
    found_hubs(phone).await?;
    cashed_out(eco, phone).await?;
    visited(eco, phone).await?;
    contracted(eco, phone).await?;
    stats(phone).await?;

    // Started again: at once, holding the same, less what keeping its
    // notes few may cost meanwhile.
    let held = phone.balance().await?;
    let again = phone.launch().await?;
    ensure!(again < Duration::from_secs(10), "{again:?} to start again");
    phone
        .wait_balance(held.saturating_sub(NOTES_UPKEEP)..=held, 30)
        .await?;
    logs(phone).await?;
    guided_again(phone).await?;
    restored(phone, hub, &silent.to_string()).await
}

/// The onboarding again, from Settings, for a wallet holding and protected
/// already: the tour, then a vault set up a screen at a time, until hidden.
async fn guided_again(phone: &Phone) -> anyhow::Result<()> {
    phone.launch().await?;
    ensure!(
        !phone.has("funding").await?,
        "a wallet in use guided unasked"
    );
    phone.tap("Settings").await?;
    phone.tap_id("how-it-works").await?;
    phone.tap_id("tour-skip").await?;
    phone.tap_id("guide-start").await?;
    phone.tagged("funding-title", "Fill your vault", 30).await?;
    phone.by_id("funding-address", 30).await?;
    // Under its steps, always in sight: of a wallet in use, it ends the guide.
    phone.wait("Hide guide", 10).await?;
    phone.tap_id("funding-hide").await?;
    phone.gone("funding", 10).await?;
    phone.home(10).await?;
    ensure!(
        !phone.has("setup-card").await?,
        "a guide hidden still suggested"
    );
    Ok(())
}

/// The notes at its hub made few now, by hand, as the hub's page offers in
/// advanced mode: the wallet does it by itself once they have rested, and
/// then rests again for hours. A backup made between would not know the new
/// notes, and the old ones are spent (docs/wallet-cli.md: keep backups
/// current). Nothing to do if none is offered.
async fn optimized(phone: &Phone) -> anyhow::Result<()> {
    phone.launch().await?;
    phone.tap("Settings").await?;
    phone.tap_id("hubs").await?;
    phone.tap_id("hub").await?;
    let optimize = phone.scroll_to_id("optimize-notes").await?;
    phone.tap_view(&optimize).await?;
    let offered = until("the optimization offered or not", 30, || async {
        let views = phone.views().await?;
        if views.iter().any(|v| v.id == "confirm-optimize") {
            return Ok(Some(true));
        }
        let none = views
            .iter()
            .any(|v| v.text.starts_with("No optimization is available"));
        Ok(none.then_some(false))
    })
    .await?;
    if offered {
        // Its words in sight, not only its tag: the button, cut off at the
        // bottom, has the center of its bounds on the navigation bar, and
        // a tap there goes Home. Its words are those of the text in it.
        let confirm = phone.scroll_to_text("Optimize for").await?;
        phone.tap_view(&confirm).await?;
        phone
            .wait("Optimized. Its fee is recorded in History.", 60)
            .await?;
    }
    Ok(())
}

/// Backed up from Settings, deleted and brought back from the first
/// screen: from its backup file, all it held; from its 24 words, its keys,
/// the same silent payment address.
async fn restored(phone: &Phone, hub: &str, silent: &str) -> anyhow::Result<()> {
    optimized(phone).await?;
    phone.launch().await?;
    let held = phone.balance().await?;
    phone.tap("Settings").await?;
    phone.tap_id("backup").await?;
    phone.tap_id("backup-words").await?;
    phone.tap_id("show-words").await?;
    phone.by_id("word 24", 30).await?;
    let views = phone.views().await?;
    let words = (1..=24)
        .map(|i| {
            let word = views.iter().find(|v| v.id == format!("word {i}"));
            Ok(word.with_context(|| format!("no word {i}"))?.text.clone())
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    // Copied too, to keep them elsewhere.
    phone.tap_id("copy-words").await?;
    phone.wait("Copied", 10).await?;
    phone.tap_id("words-done").await?;
    phone.tap_id("backup-file").await?;
    phone.tap_id("save-backup").await?;
    // The system's file picker, the file's name suggested.
    picked(phone, |text| text.eq_ignore_ascii_case("save")).await?;
    phone.tap_id("backup-done").await?;
    deleted(phone).await?;

    phone.tap_id("restore-wallet").await?;
    phone.tap_id("restore-file").await?;
    picked(phone, |text| text.starts_with("licash-regtest-backup-")).await?;
    phone.home(120).await?;
    // All it held, less what keeping its notes few may cost meanwhile.
    phone
        .wait_balance(held.saturating_sub(NOTES_UPKEEP)..=held, 60)
        .await?;
    deleted(phone).await?;

    phone.tap_id("restore-wallet").await?;
    phone.tap_id("restore-words").await?;
    // A few words at a time: typed all at once, the last ones can be lost.
    phone.tap_id("phrase").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    for few in words.chunks(6) {
        phone.type_text(&format!("{} ", few.join(" "))).await?;
    }
    // The keyboard left as it is: the words are in a sheet, which Escape
    // closes, back to the first screen, unless a keyboard shown takes it.
    phone.wait("24 of 24", 10).await?;
    phone.tap_id("restore").await?;
    // Its keys only: no hub until one is added again.
    phone.by_id("choose-hub", 120).await?;
    phone.connect(hub).await?;
    silently(phone, silent).await
}

/// In the system's file picker, tap the first view whose text `wanted`.
async fn picked(phone: &Phone, wanted: impl Fn(&str) -> bool) -> anyhow::Result<()> {
    let view = until("the file picker", 60, || async {
        Ok(phone.views().await?.into_iter().find(|v| wanted(&v.text)))
    })
    .await?;
    phone.tap_view(&view).await
}

/// The wallet deleted from Settings' advanced page, from Home or a page
/// of Settings: the first screen shown again.
async fn deleted(phone: &Phone) -> anyhow::Result<()> {
    phone.launch().await?;
    phone.tap("Settings").await?;
    phone.tap_id("advanced").await?;
    let delete = phone.scroll_to_id("delete-wallet").await?;
    phone.tap_view(&delete).await?;
    phone.tap_id("delete").await?;
    phone.past_tour().await
}

/// The question the app asks, or what it says went wrong, starting with
/// `text`, waiting up to `secs` for it.
async fn asked(phone: &Phone, text: &str, secs: u64) -> anyhow::Result<()> {
    phone.tagged("ask", text, secs).await?;
    Ok(())
}

/// What it cannot pay: told why, nothing spent.
async fn refused(eco: &Eco, phone: &Phone, bobs: &PaymentCode) -> anyhow::Result<()> {
    let held = phone.balance().await?;
    let mut asking = bobs.clone();
    asking.amount = Some(10_000_000);
    phone.link(&asking.to_string()).await?;
    phone.tap_id("confirm").await?;
    asked(phone, "Not enough", 60).await?;
    phone.tap_id("cancel").await?;

    phone.link("licash:nonsense").await?;
    asked(phone, "Neither a Licash address", 30).await?;
    phone.tap_id("cancel").await?;

    // A code naming only a hub it does not use.
    let carol = eco.wallet("carol")?;
    carol.add_hub(eco.hub(2)).await?;
    let carols = carol.payment_code(&[eco.hub(2).to_owned()])?;
    phone.link(&carols.to_string()).await?;
    asked(phone, "Their hub is not one of yours", 30).await?;
    phone.tap_id("cancel").await?;
    phone.home(10).await?;
    ensure!(phone.balance().await? == held, "spent refusing");
    Ok(())
}

/// Where the money is, from Home, then the page of the hub at `url`.
async fn at_hub(phone: &Phone, url: &str) -> anyhow::Result<()> {
    phone.tap_id("balance").await?;
    phone.by_id("onchain", 30).await?;
    phone.tap(name(url)).await?;
    phone.by_id("cash-out", 30).await?;
    Ok(())
}

/// Where the money is, from Home, then what is on Bitcoin.
async fn on_bitcoin(phone: &Phone) -> anyhow::Result<()> {
    phone.tap_id("balance").await?;
    phone.tap_id("onchain").await?;
    phone.wait("On Bitcoin", 30).await?;
    Ok(())
}

/// A code naming only a hub it does not use, saying where to reach it:
/// paid there once asked and reviewed, a swap bringing notes there from
/// its hub. What the swap brought past the payment shows apart until the
/// hub is added.
async fn visited(eco: &Eco, phone: &Phone) -> anyhow::Result<()> {
    eco.stock(5_000).await?;
    let held = phone.balance().await?;
    let dave = eco.wallet("dave")?;
    dave.add_hub(eco.hub(2)).await?;
    let mut daves = dave.payment_code(&[eco.hub(2).to_owned()])?;
    // Less than the provider swaps at least: some is left there.
    daves.amount = Some(800);
    phone.link(&daves.to_string()).await?;
    // Its amount asked: straight to what it costs.
    asked(phone, "Their hub is not one of yours", 30).await?;
    phone.tap_id("confirm").await?;
    // At a hub not added, notes moved there first: both said.
    phone.by_id("not-added", 120).await?;
    phone.by_id("moves", 10).await?;
    reviewed(phone, 10).await?;
    phone.tap_id("confirm").await?;
    phone.tagged("result", "Sent", 180).await?;
    phone.tap_id("done").await?;
    ensure!(
        collected(&dave, 60).await? == 800,
        "Dave got other than 800"
    );
    // More than the 800 gone: waited for as such, not for any change, the
    // wallet's own upkeep taking a few sat at any time (NOTES_UPKEEP).
    let after = until("more than 800 spent swapping for 800", 30, || async {
        let now = phone.balance().await?;
        Ok((held.saturating_sub(now) > 800).then_some(now))
    })
    .await?;

    // What is left there, apart: added with a tap and a word of warning.
    phone.tap_id("balance").await?;
    phone.tap_id("visited").await?;
    phone
        .wait("Left over from paying someone at this hub", 10)
        .await?;
    phone.tap_id("add-visited").await?;
    // The sheet closed, then its hub among those used.
    phone.gone("add-visited", 30).await?;
    phone.by_id("onchain", 30).await?;
    phone.gone("visited", 60).await?;
    phone.back_to("receive").await?;
    until("more held once the hub was added", 60, || async {
        let now = phone.balance().await?;
        Ok((now > after).then_some(now))
    })
    .await?;
    Ok(())
}

/// Cashed out to itself: half its notes paid out on Bitcoin to its own
/// address, the rest left in the balance, and kept there rather than moved
/// back into the balance, until it is asked to.
async fn cashed_out(eco: &Eco, phone: &Phone) -> anyhow::Result<()> {
    let pays = || async {
        let chain = eco.swaps_info().await?.chain;
        anyhow::Ok(
            chain
                .context("the provider pays nothing out on Bitcoin")?
                .max,
        )
    };
    if pays().await? < 100_000 {
        let address = eco.exec("swaps", &["licash-swaps", "address"]).await?;
        eco.send_to(String::from_utf8(address)?.trim(), 300_000)
            .await?;
        eco.mine(1).await?;
        until("the provider's coins found", 120, || async {
            Ok((pays().await? >= 100_000).then_some(()))
        })
        .await?;
    }
    let held = phone.balance().await?;
    at_hub(phone, eco.hub(1)).await?;
    phone.tap_id("cash-out").await?;
    phone.tap_id("to-own").await?;
    // As much as chosen: half of it, the rest left there.
    phone.tagged("to", "To this wallet", 30).await?;
    let half = held / 2;
    phone.fill_id("amount", &half.to_string()).await?;
    phone.tap_id("continue").await?;
    phone.tagged("to", "This wallet", 120).await?;
    reviewed(phone, 10).await?;
    // In advanced mode (since onboarding), every provider's offer: the
    // stack's only one, the one picked.
    phone.tap_id("providers").await?;
    phone.wait("The only provider", 120).await?;
    phone.wait("Chosen", 10).await?;
    phone.tap_id("confirm").await?;
    phone.tagged("result", "Sending", 60).await?;
    phone.tap_id("done").await?;
    // Under way, watched in a foreground service: finished out of sight too.
    until("the watching notification", 30, || async {
        Ok(phone.notifying("watching").await?.then_some(()))
    })
    .await?;
    // Home tells it is under way, no block mined yet; opened from there,
    // where it stands, at one of its first steps.
    phone.back_to("onchain").await?;
    phone.back_to("receive").await?;
    let going = phone.tagged("status", "Sending", 30).await?;
    phone.tap_view(&going).await?;
    let stands = phone.tagged("state", "On its way", 30).await?;
    eprintln!("cashing out, on Home: {:?}, {:?}", going.text, stands.text);
    phone.tap_id("more").await?;
    phone.scroll_to_id("step locked").await?;
    phone.back_to("receive").await?;
    on_bitcoin(phone).await?;
    // Claimed once the provider's coin confirms, then found on Bitcoin:
    // kept there.
    let kept = until("the payout kept on Bitcoin", 300, || async {
        mine(eco).await?;
        Ok(phone.views().await?.into_iter().find(|v| v.id == "kept"))
    })
    .await?;
    eprintln!("cashed out, kept: {:?}", kept.text);
    // Half of it, not all.
    let cashed = amount(&kept.text);
    ensure!(
        cashed >= half && cashed < held * 6 / 10,
        "{cashed} kept once {half} of {held} cashed out"
    );
    // Rounds later, not moved back in by itself.
    tokio::time::sleep(Duration::from_secs(20)).await;
    mine(eco).await?;
    tokio::time::sleep(Duration::from_secs(10)).await;
    ensure!(
        !phone.has("moving").await?,
        "what was cashed out moved back in by itself"
    );
    phone.by_id("kept", 10).await?;
    // Asked to, once warned: moved in, none left on Bitcoin.
    phone.tap_id("move-in").await?;
    phone.tap_id("move-in-anyway").await?;
    // The sheet stays while it is done, and hides the page behind it: none
    // of its rows are seen until it goes.
    phone.gone("move-in-anyway", 60).await?;
    until("all moved back into the balance", 300, || async {
        mine(eco).await?;
        let views = phone.views().await?;
        let busy = views
            .iter()
            .any(|v| ["kept", "moving", "coming"].contains(&v.id.as_str()));
        Ok((!busy).then_some(()))
    })
    .await?;
    phone.back_to("onchain").await?;
    phone.back_to("receive").await?;
    let back = phone.balance().await?;
    ensure!(
        back < held && back > held * 8 / 10,
        "{back} held once {held} cashed out and moved back in"
    );
    // In the history, arrived, each of its steps there once asked for.
    opened(phone, "Sent on Bitcoin").await?;
    phone.tagged("state", "Arrived", 60).await?;
    phone.tap_id("more").await?;
    for step in [
        "step locked",
        "step coin",
        "step coin-confirmed",
        "step claimed",
        "step arrived",
    ] {
        phone.scroll_to_id(step).await?;
    }
    phone.back().await?;
    phone.back_to("receive").await?;
    Ok(())
}

/// Protection at its hub, a recovery contract, set up as its user would:
/// with no coin on Bitcoin to pay its price, offered a cover for what it
/// holds there and the coin to cash out to itself first, the price and a
/// small part of its own, the hub funding the rest; then, that coin cashed
/// out, of the length it chooses, that cover, taking the coin whole: its
/// price itemized, the rest of the coin its own part, issued back as notes. Signed, confirmed and
/// protecting the notes there, on credit no longer, nothing left on
/// Bitcoin. Ending it, it is told to cash out instead.
async fn contracted(eco: &Eco, phone: &Phone) -> anyhow::Result<()> {
    // hub1's opening fee, and over it 1% a year of the part of the cover
    // it funds (licash-hub's --contracts-rate by default), none of hers:
    // the cost shown. Its reserve, hers, is paid beside it, apart.
    const OPENING: u64 = 3_000;
    const RESERVE: u64 = 20_000;
    // Its sizes, 2^n - 1 sat: the least.
    const LEAST: u64 = 131_071;
    // Her own part of the coin she is told to cash out for it.
    const PART: u64 = 1_000;
    // What a coin spent whole may leave unpaid: less than an output is
    // worth.
    const DUST: u64 = 330;
    /// What a mock contract is worth, said wherever one shows.
    const MOCK: &str = "Test only: protects nothing";
    let cost = |cap: u64, funded: u64, blocks: u32| {
        OPENING
            + licash_api::rate(
                10_000,
                u32::try_from(cap - funded).unwrap_or(u32::MAX),
                blocks,
                licash_api::YEAR_BLOCKS,
            )
    };
    // Enough in notes to pay for it, and to pay with after.
    let code: PaymentCode = phone.bitcoin_code().await?.parse()?;
    let fallback = code.address.context("a fallback address")?;
    let held = phone.balance().await?;
    eco.send_to(&fallback.assume_checked().to_string(), 100_000)
        .await?;
    // Too little for protection worth its price: none offered, moved in
    // with none.
    move_in(eco, phone).await?;
    ensure!(!phone.has("offer").await?, "protection offered for 100000");
    until("100000 moved into the balance", 300, || async {
        mine(eco).await?;
        // Home's one line of what is going on: gone once nothing is.
        let busy = phone.has("status").await?;
        Ok((!busy && phone.balance().await? > held + 90_000).then_some(()))
    })
    .await?;

    // No coin on Bitcoin pays its price: offered a cover for what it holds
    // at hub1, half again what is not protected there, a size; its cost
    // and reserve, and the coin to cash out to itself first: the price and
    // its own small part, the hub funding the rest. Nothing to pay or
    // choose yet.
    at_hub(phone, eco.hub(1)).await?;
    phone.tap_id("open-contract").await?;
    let wanted = amount(&phone.by_id("quote-cap", 60).await?.text);
    ensure!(
        (wanted + 1).is_power_of_two() && wanted >= LEAST,
        "a cover of {wanted} offered with no coin"
    );
    let first = amount(&phone.by_id("quote-price", 10).await?.text);
    ensure!(
        first == cost(wanted, PART, 1_000),
        "{first} for {wanted} with {PART} of hers"
    );
    phone.tagged("contract-reserve", "20,000 sat", 10).await?;
    phone.by_id("cash-out-first", 10).await?;
    let asked = first + RESERVE + PART;
    let words = phone.scroll_to_text("Cash out ").await?;
    ensure!(
        words.text.ends_with(" to yourself") && amount(&words.text) == asked,
        "{:?} for {asked}",
        words.text
    );
    phone.tagged("worth", MOCK, 10).await?;
    for gone in [
        "protect",
        "contract-funded",
        "contract-cap",
        "contract-problem",
    ] {
        ensure!(!phone.has(gone).await?, "{gone:?} with no coin");
    }
    // Or paid for with the notes there, the same coin: quoted through a
    // provider found on Nostr, its fees on top. Not paid this way here: the
    // coin cashed out by hand is what the rest opens on.
    let words = phone.scroll_to_text("Pay ").await?;
    ensure!(
        words.text.ends_with(" from notes") && amount(&words.text) == asked,
        "{:?} for {asked}",
        words.text
    );
    phone.tap_id("pay-with-notes").await?;
    let paid_coin = amount(&phone.by_id("paid-coin", 120).await?.text);
    ensure!(paid_coin == asked, "a coin of {paid_coin} paid for {asked}");
    let paid_cap = amount(&phone.by_id("paid-cap", 10).await?.text);
    ensure!(
        paid_cap == wanted,
        "a cap of {paid_cap} paid for, {wanted} offered"
    );
    let fees = amount(&phone.by_id("paid-fees", 10).await?.text);
    phone.by_id("paid-provider", 10).await?;
    phone.by_id("pay-paid", 10).await?;
    let total = amount(&phone.scroll_to_text("Pay ").await?.text);
    ensure!(
        total == asked + fees,
        "{total} to pay for {asked} and {fees} in fees"
    );
    phone.back().await?;
    phone.gone("pay-paid", 10).await?;
    phone.tap_id("open-contract").await?;
    let cash_out = phone.by_id("cash-out-first", 60).await?;

    // Cashed out to itself from there, that much.
    phone.tap_view(&cash_out).await?;
    phone.tagged("to", "This wallet", 120).await?;
    let paying = amount(&phone.by_id("paying", 10).await?.text);
    ensure!(paying == asked, "{paying} cashed out for {asked}");
    reviewed(phone, 10).await?;
    phone.tap_id("confirm").await?;
    phone.tagged("result", "Sending", 60).await?;
    phone.tap_id("done").await?;
    phone.back_to("onchain").await?;
    phone.tap_id("onchain").await?;
    let coin = until("the payout kept on Bitcoin", 300, || async {
        mine(eco).await?;
        Ok(phone.views().await?.into_iter().find(|v| v.id == "kept"))
    })
    .await?;
    let coin = amount(&coin.text);
    ensure!(
        (asked..asked + 1_000).contains(&coin),
        "a coin of {coin} cashed out for {asked}"
    );
    phone.back_to("onchain").await?;
    let credit = amount(&phone.by_id("credit", 10).await?.text);
    phone.back_to("receive").await?;
    let before = phone.balance().await?;
    eprintln!("a coin of {coin} kept, {before} held, {credit} on credit");

    // Paid from it now: the cover offered for it, its price as hub1
    // prices it, all the rest of the coin her part, less than dust left.
    // Smaller covers take it whole too: the cover is hers to choose.
    at_hub(phone, eco.hub(1)).await?;
    phone.tap_id("open-contract").await?;
    let cap = amount(&phone.by_id("quote-cap", 60).await?.text);
    ensure!(
        cap == wanted,
        "a cap of {cap} offered on {coin}, cashed out for {wanted}"
    );
    for gone in ["contract-funding", "cash-out-first"] {
        ensure!(!phone.has(gone).await?, "{gone:?} on {coin}");
    }
    // Its reserve apart from its cost, hers, and her part, in sight with
    // what the hub protects then; its size, the coin paying it and how
    // long folded under More.
    phone.tagged("contract-reserve", "20,000 sat", 10).await?;
    for shown in ["contract-funded", "contract-after"] {
        phone.by_id(shown, 10).await?;
    }
    for folded in ["contract-blocks", "contract-cap", "contract-paid-with"] {
        ensure!(!phone.has(folded).await?, "{folded:?} unfolded");
    }
    phone.tap_id("contract-more").await?;
    // Its fit over `blocks`, as shown: her part and its cost, the reserve
    // paid beside them.
    let fit = |blocks: u32| async move {
        until(
            &format!("the fit of {coin} over {blocks} blocks"),
            10,
            || async {
                let views = phone.views().await?;
                let of = |id: &str| views.iter().find(|v| v.id == id).map(|v| amount(&v.text));
                let (Some(funded), Some(paid)) = (of("contract-funded"), of("quote-price")) else {
                    return Ok(None);
                };
                let spent = funded + paid + RESERVE;
                let whole = funded > 0
                    && paid == cost(cap, funded, blocks)
                    && (spent..spent + DUST).contains(&coin);
                Ok(whole.then_some((funded, paid)))
            },
        )
        .await
    };
    let (funded, paid) = fit(1_000).await?;
    eprintln!("{coin} pays {paid} and funds {funded} of {cap}");
    // Itemized: the hub's fee, its interest by the year on its own part.
    phone
        .tagged("contract-opening-fee", "3,000 sat", 10)
        .await?;
    let interest = phone.by_id("contract-interest", 10).await?.text;
    let of = interest.rsplit("a year of").next().map(amount);
    ensure!(
        interest.starts_with(&format!("{} sat", paid - OPENING))
            && interest.contains("1% a year of")
            && of == Some(cap - funded),
        "{interest:?} for its interest on {} of {cap}",
        cap - funded
    );
    // None on her part, its only coin, nothing to say against it.
    for gone in [
        "contract-interest-funded",
        "contract-coin",
        "contract-problem",
    ] {
        ensure!(!phone.has(gone).await?, "{gone:?} on {coin}");
    }
    // Its shortest costs less, at once, and funds more of hers; the
    // longest again, to protect.
    phone.slide_id("contract-blocks", 0.0).await?;
    let (shortest, cheaper) = fit(200).await?;
    ensure!(
        cheaper < paid && shortest >= funded,
        "{cheaper} for {shortest} over 200 blocks, {paid} for {funded} over 1000"
    );
    phone.slide_id("contract-blocks", 1.0).await?;
    ensure!(
        fit(1_000).await? == (funded, paid),
        "another fit over 1000 blocks"
    );
    // Its size and the coin paying it, unfolded below what it costs.
    for shown in ["contract-cap", "contract-paid-with"] {
        phone.scroll_to_id(shown).await?;
    }
    // Below what was unfolded: scrolled to, its words in sight. The button,
    // tagged, has none for uiautomator: they are those of the text in it.
    let words = phone.scroll_to_text("Protect for").await?;
    ensure!(
        amount(&words.text) == paid,
        "{:?} for a cost of {paid}",
        words.text
    );
    let protect = phone.by_id("protect", 10).await?;
    phone.tagged("worth", MOCK, 10).await?;
    phone.tap_view(&protect).await?;
    // Being set up: said at once, then the step it is at.
    until("protection being set up", 30, || async {
        let views = phone.views().await?;
        Ok(views
            .into_iter()
            .find(|v| v.id == "opening" || v.id == "contract-step"))
    })
    .await?;
    let protecting = until("the contract protecting", 900, || async {
        mine(eco).await?;
        let views = phone.views().await?;
        let state = views.into_iter().find(|v| v.id == "contract-state");
        Ok(state.filter(|v| v.text == "Protecting"))
    })
    .await?;
    eprintln!("contract {:?}", protecting.text);
    // What it is worth, in sight without a tap.
    phone.tagged("worth", MOCK, 10).await?;
    // Unfolded: her part, issued back to her once its funding is buried,
    // 3 blocks deep at hub1: mined, as nothing else waits to be.
    phone.tap_view(&protecting).await?;
    eco.mine(3).await?;
    let issued = until("her part in the balance", 600, || async {
        mine(eco).await?;
        let views = phone.views().await?;
        let shown = views.into_iter().find(|v| v.id == "contract-funded");
        Ok(shown.filter(|v| v.text.ends_with("in your balance")))
    })
    .await?;
    ensure!(
        amount(issued.text.split('·').next().unwrap_or_default()) == funded,
        "{:?} funded of {funded}",
        issued.text
    );
    // In advanced mode, since onboarding: forcing it, not yet. Below its
    // details: scrolled to, as often as the page moves.
    phone.scroll_to_id("force-close").await?;
    let end = phone.scroll_to_id("close-contract").await?;
    phone.tap_view(&end).await?;
    // Closing pays what is held there, up to its cap; cashing out first
    // takes what is beyond it too. Neither pressed: the contract stays.
    phone.by_id("end-close", 10).await?;
    phone.by_id("end-cash-out", 10).await?;
    phone.back().await?;
    phone.gone("end-cash-out", 10).await?;
    phone.scroll_to_id("close-contract").await?;
    phone.back_to("onchain").await?;

    // Its notes protected; nothing left on Bitcoin, its coin spent whole.
    let protected = until("its notes protected", 30, || async {
        let views = phone.views().await?;
        let of = |id: &str| views.iter().find(|v| v.id == id).map(|v| amount(&v.text));
        let (protected, onchain) = (of("protected"), of("onchain"));
        Ok(protected.filter(|&p| p > 0 && onchain == Some(0)))
    })
    .await?;
    let now = amount(&phone.by_id("credit", 10).await?.text);
    phone.back_to("receive").await?;
    let after = phone.balance().await?;
    // Less its coin, but her part back in notes: its price and what less
    // than dust it left, and what keeping its notes few may have cost
    // meanwhile (a few sat, at times).
    let spent = before.checked_sub(after);
    ensure!(
        spent.is_some_and(|s| (coin - funded..=coin - funded + NOTES_UPKEEP).contains(&s)),
        "{after} held, {before} before, a coin of {coin} funding {funded}"
    );
    eprintln!("{after} held, {protected} protected, {now} on credit");
    // A claim names so many notes at most, 32 or more: the smallest past
    // them are on credit, which the many payments before, and her part's
    // notes, leave a few of. Nearly all of it is protected, then.
    ensure!(
        now * 100 <= protected,
        "{now} on credit, {protected} protected, {credit} on credit before"
    );
    // Home says it is protected.
    let share = phone.by_id("protection", 10).await?;
    ensure!(
        share.text.ends_with("% protected"),
        "{:?} on Home with a contract protecting",
        share.text
    );
    // What it took from her Bitcoin in the history, as paid once its
    // funding confirmed: its cost and its reserve, refundable, itemized
    // below; not her part, which is still hers.
    opened(phone, "Protection").await?;
    let shown = amount(&phone.by_id("amount", 10).await?.text);
    ensure!(
        shown == paid + RESERVE,
        "{shown} paid for it in the history, of a cost of {paid} and a reserve of {RESERVE}"
    );
    phone.tagged("state", "Set up", 30).await?;
    phone.by_id("at", 10).await?;
    phone.tagged("paid-from", "Your Bitcoin", 10).await?;
    phone.back().await?;
    phone.back_to("receive").await?;
    // Her part in the history as what it is, the rest of her own coin back
    // as notes: not a payment received from anyone.
    opened(phone, "From Bitcoin, protected").await?;
    let back = amount(&phone.by_id("amount", 10).await?.text);
    ensure!(
        back == funded,
        "{back} of her part of {funded} in the history"
    );
    phone.back().await?;
    phone.back_to("receive").await?;
    Ok(())
}

/// The other hub, announced on the relay its hub names: found in Settings,
/// offered to add with a tap and a word of warning.
async fn found_hubs(phone: &Phone) -> anyhow::Result<()> {
    phone.tap("Settings").await?;
    phone.tap_id("hubs").await?;
    let find = phone.scroll_to_id("find-hubs").await?;
    phone.tap_view(&find).await?;
    phone.wait("hub2", 60).await?;
    phone.tap_id("add-found").await?;
    // Which it is, and what adding it means, before it is added.
    let url = phone.by_id("found-url", 10).await?;
    ensure!(url.text.contains("://"), "{:?} for its address", url.text);
    phone
        .wait(
            "Up to what you protect, your balance here can be taken back",
            10,
        )
        .await?;
    phone.by_id("add-hub", 10).await?;
    // Not now: paid there first, below.
    phone.back().await?;
    phone.gone("add-hub", 10).await?;
    phone.tap("Back").await?;
    // In advanced mode, since onboarding: its page listed.
    phone.scroll_to_id("toggle Advanced mode").await?;
    phone.scroll_to_id("advanced").await?;
    phone.back_to("receive").await?;
    Ok(())
}

/// Its hub down: paying is under way, and once the hub is back up the app
/// finishes it by itself, to Bob's mailbox, paid once.
async fn hub_down(
    eco: &Eco,
    phone: &Phone,
    bob: &licash_e2e::Wallet,
    bobs: &PaymentCode,
) -> anyhow::Result<()> {
    let held = phone.balance().await?;
    let fee = eco.info(eco.hub(1)).await?.fees.spending().at_most(held);
    let mut asking = bobs.clone();
    asking.amount = Some(1_000);
    eco.stop("hub1").await?;
    let told = async {
        phone.link(&asking.to_string()).await?;
        phone.tap_id("confirm").await?;
        // Said to be under way, or sent, or asked to try again.
        until("what became of paying", 120, || async {
            let views = phone.views().await?;
            Ok(views
                .into_iter()
                .find(|v| v.id == "result" || v.text == "Try again"))
        })
        .await
    }
    .await;
    eco.start("hub1").await?;
    let told = told?;
    ensure!(
        told.text.starts_with("Under way"),
        "told {:?} with its hub down",
        told.text
    );
    phone.tap_id("done").await?;
    phone.home(10).await?;

    // Back up: finished and sent on within a few rounds of the app.
    ensure!(
        collected(bob, 180).await? == 1_000,
        "Bob got other than 1000"
    );
    // Resuming can also charge a note optimization fee, a few sat.
    let spent = until("the payment done", 60, || async {
        let spent = held - phone.balance().await?;
        Ok((1_000..=1_000 + fee + NOTES_UPKEEP)
            .contains(&spent)
            .then_some(spent))
    })
    .await?;
    eprintln!("{spent} spent paying 1000 while its hub was down");
    // Once: nothing more for Bob a round later.
    tokio::time::sleep(Duration::from_secs(30)).await;
    let again = wallet::collect(bob, &Route::Direct).await?;
    ensure!(
        again.received.is_empty(),
        "paid twice: {:?}",
        again.received
    );
    Ok(())
}

/// The app's log and the light client's, and both exported from About in
/// Settings, which shows what the app keeps on the phone.
async fn logs(phone: &Phone) -> anyhow::Result<()> {
    let app = phone.file("files/logs/app.log").await?;
    for want in ["light client of regtest started", "moving to notes"] {
        ensure!(app.contains(want), "no {want:?} in the app's log");
    }
    let chain = phone.file("files/logs/chain.log").await?;
    ensure!(
        chain.contains("LCHN"),
        "no neutrino in the light client's log"
    );
    phone.tap("Settings").await?;
    phone.tap_id("about").await?;
    // What the app keeps on the phone, its light client's and its own
    // code among it, in a sheet.
    phone.tap_id("storage").await?;
    phone.by_id("storage-total", 30).await?;
    phone.scroll_to_id("storage-chain").await?;
    phone.scroll_to_id("storage-app").await?;
    phone.back().await?;
    let export = phone.scroll_to_id("export-logs").await?;
    phone.tap_view(&export).await?;
    phone.wait("licash-logs.txt", 30).await?;
    phone.back().await?;
    Ok(())
}
