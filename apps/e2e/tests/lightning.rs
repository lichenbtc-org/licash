//! Wallets pay and get paid over Lightning through a swap provider, paying
//! and paid through its own node, on the stack of `apps/e2e/run.sh`, which
//! runs these. Hubs run no Lightning node.

use licash_api::swaps::State;
use licash_e2e::{received, until, Eco, Wallet, OUTSIDE, SWAPS_LN};
use licash_wallet::{InvoiceState, Lock, LockState};

/// What `wallet` paid its hubs on its payments to itself, which make the
/// exact notes a lock to a hub locks.
fn exact_fees(wallet: &Wallet) -> u64 {
    let me = wallet.address();
    let sends = wallet.sends().unwrap();
    sends.iter().filter(|s| s.payee == me).map(|s| s.fee).sum()
}

/// Follow `lock` until it is paid or refunded.
async fn settled(wallet: &Wallet, lock: &Lock) -> anyhow::Result<Lock> {
    until(&format!("lock {}", lock.id), 180, || async {
        Ok(match wallet.follow_lock(&lock.id).await {
            Ok(lock) if matches!(lock.state, LockState::Paid(_) | LockState::Refunded) => {
                Some(lock)
            }
            Ok(_) | Err(licash_wallet::Error::Pending { .. }) => None,
            Err(e) => return Err(e.into()),
        })
    })
    .await
}

/// What `wallet` can spend at `hub`.
fn available_at(wallet: &Wallet, hub: &str) -> u64 {
    let balance = wallet.balance().unwrap();
    balance
        .iter()
        .find(|b| b.hub == hub)
        .map_or(0, |b| b.available)
}

/// Follow the provider's payment for the client's lock `id` until it
/// reaches `state`.
async fn paid_as(
    eco: &Eco,
    id: &str,
    state: State,
) -> anyhow::Result<licash_api::swaps::LightningSwap> {
    until(
        &format!("the provider's payment for {id} {state:?}"),
        180,
        || async {
            let payment = eco.lightning_payment(id).await?;
            Ok((payment.state == state).then_some(payment))
        },
    )
    .await
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_provider_pays_an_outside_invoice_for_a_lock_at_a_hub() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let hub1 = eco.hub(1);
    let hal = eco.wallet("hal")?;
    eco.pay_in(&hal, hub1, 30_000).await?;
    assert_eq!(available_at(&hal, hub1), 30_000);

    // Hal locks notes at hub1 to the provider, which pays the outside
    // node's invoice from its own. No contract with the hub or the
    // provider.
    let (request, hash) = eco.invoice(OUTSIDE, 10_000).await?;
    let offer = eco.swaps_info().await?;
    let terms = offer
        .lightning
        .as_ref()
        .expect("the provider pays invoices");
    let lock = hal
        .pay_invoice_via(eco.swaps(), hub1, &request, 1_000)
        .await?;
    assert_eq!(lock.payee, offer.address);
    assert_eq!(hex::encode(lock.hash), hash);
    assert_eq!(lock.amount, terms.pays(10_000 * 1000));

    // The invoice's preimage settles it, and the provider claims Hal's
    // lock with it.
    let lock = settled(&hal, &lock).await?;
    let (state, preimage) = eco.invoice_state(OUTSIDE, &hash).await?;
    assert_eq!(state, "SETTLED");
    assert_eq!(lock.state, LockState::Paid(hex_32(&preimage)));
    let payment = paid_as(&eco, &lock.id, State::Done).await?;
    assert_eq!(payment.preimage()?, Some(hex_32(&preimage)));
    assert_eq!(payment.amount, 10_000);

    // Its routes ended at least its slack of 80 blocks before Hal's lock
    // expires.
    let timelocks = eco.timelocks(SWAPS_LN, &hash).await?;
    assert!(!timelocks.is_empty());
    assert!(
        timelocks.iter().all(|t| *t + 80 <= u64::from(lock.expiry)),
        "{timelocks:?} for {}",
        lock.expiry
    );
    // Hal paid the lock, and hub1 its fee for the exact notes it spent.
    let cost = lock.cost.expect("a settled lock's cost");
    assert!(cost >= lock.amount, "{lock:?}");
    assert_eq!(available_at(&hal, hub1), 30_000 - cost - exact_fees(&hal));

    // The same invoice asked again answers the same lock, locking nothing.
    let again = hal
        .pay_invoice_via(eco.swaps(), hub1, &request, 1_000)
        .await?;
    assert_eq!(again.id, lock.id);
    assert_eq!(available_at(&hal, hub1), 30_000 - cost - exact_fees(&hal));
    Ok(())
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_payment_the_provider_fails_returns_once_its_lock_expires() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let hub1 = eco.hub(1);
    let jack = eco.wallet("jack")?;
    eco.pay_in(&jack, hub1, 20_000).await?;

    let (request, hash, _) = eco.hold_invoice(OUTSIDE, 5_000).await?;
    let lock = jack
        .pay_invoice_via(eco.swaps(), hub1, &request, 1_000)
        .await?;
    until("the outside node holds the payment", 60, || async {
        let (state, _) = eco.invoice_state(OUTSIDE, &hash).await?;
        Ok((state == "ACCEPTED").then_some(()))
    })
    .await?;
    eco.lncli(OUTSIDE, &["cancelinvoice", &hash]).await?;
    let payment = paid_as(&eco, &lock.id, State::Failed).await?;
    assert!(payment.reason.is_some(), "{payment:?}");
    assert_eq!(payment.preimage, None);

    // The provider releases nothing early: the lock stands until expired.
    let locked = jack.follow_lock(&lock.id).await?;
    assert_eq!(locked.state, LockState::Locked);
    let depth = eco
        .info(hub1)
        .await?
        .locks
        .expect("hub1 takes locks")
        .min_depth;
    let height = eco.height().await?;
    eco.mine(lock.expiry - height + depth + 1).await?;
    let lock = settled(&jack, &lock).await?;
    assert_eq!(lock.state, LockState::Refunded);
    // Only hub1's refund fee, and its fee for the exact notes, are lost.
    let refund_fee = lock.cost.expect("a refunded lock's cost");
    assert_eq!(
        available_at(&jack, hub1),
        20_000 - refund_fee - exact_fees(&jack)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_provider_restarted_mid_payment_claims_its_lock() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let hub1 = eco.hub(1);
    let kate = eco.wallet("kate")?;
    eco.pay_in(&kate, hub1, 20_000).await?;

    // The outside node holds the payment while the provider restarts.
    let (request, hash, preimage) = eco.hold_invoice(OUTSIDE, 6_000).await?;
    let lock = kate
        .pay_invoice_via(eco.swaps(), hub1, &request, 1_000)
        .await?;
    until("the outside node holds the payment", 60, || async {
        let (state, _) = eco.invoice_state(OUTSIDE, &hash).await?;
        Ok((state == "ACCEPTED").then_some(()))
    })
    .await?;
    eco.restart("swaps").await?;
    eco.lncli(OUTSIDE, &["settleinvoice", &preimage]).await?;
    let lock = settled(&kate, &lock).await?;
    assert_eq!(lock.state, LockState::Paid(hex_32(&preimage)));
    let payment = paid_as(&eco, &lock.id, State::Done).await?;
    assert_eq!(payment.preimage()?, Some(hex_32(&preimage)));
    Ok(())
}

fn hex_32(text: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes).unwrap();
    bytes
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_static_lnurl_takes_donations_for_a_wallet_offline() -> anyhow::Result<()> {
    use bitcoin::hashes::{sha256, Hash};

    let eco = Eco::up().await?;
    let hub2 = eco.hub(2);
    eco.stock(20_000).await?;
    // Quinn hands out her code's static LNURL once, then goes offline.
    let quinn = eco.wallet("quinn")?;
    quinn.add_hub(hub2).await?;
    let code = quinn.payment_code(&[hub2.to_owned()])?;
    let code = code.licash.expect("a Licash code").to_string();
    let lnurl = eco
        .exec(
            "swaps",
            &["licash-swaps", "lnurl", "--lnurl-url", eco.swaps(), &code],
        )
        .await?;
    let lnurl = String::from_utf8(lnurl)?;
    let (_, url) = bitcoin::bech32::decode(lnurl.trim())?;
    let url = String::from_utf8(url)?;
    assert_eq!(url, format!("{}/v1/lnurlp/{code}", eco.swaps()));

    // A payer's wallet reads it, as LNURL-pay has it.
    let request = eco.get_json(&url).await?;
    assert_eq!(request["tag"], "payRequest", "{request}");
    let (min, max) = (
        request["minSendable"].as_u64().unwrap(),
        request["maxSendable"].as_u64().unwrap(),
    );
    assert!(min <= 5_000_000 && 5_000_000 <= max, "{request}");
    let metadata = request["metadata"].as_str().unwrap();
    let callback = request["callback"].as_str().unwrap();
    let invoice = eco.get_json(&format!("{callback}?amount=5000000")).await?;
    let pr = invoice["pr"].as_str().expect("an invoice");
    // An invoice of the provider's node, committing to the metadata.
    let decoded = eco.lncli(OUTSIDE, &["decodepayreq", pr]).await?;
    assert_eq!(decoded["num_satoshis"], "5000");
    let hash = sha256::Hash::hash(metadata.as_bytes());
    assert_eq!(
        decoded["description_hash"],
        hex::encode(hash.to_byte_array())
    );
    let provider = eco.swaps_info().await?;
    // Its info tells wallets where payers reach it, for them to show this.
    let donations = provider.donations.clone().expect("donations taken");
    assert_eq!(donations.url, eco.swaps());
    let node = eco.lncli(SWAPS_LN, &["getinfo"]).await?;
    assert_eq!(
        decoded["destination"], node["identity_pubkey"],
        "{provider:?}"
    );

    // The outside node pays: the provider pays Quinn in notes at hub2,
    // kept for her there, then settles.
    let paying = eco.pay(OUTSIDE, pr);
    let got = until("the donation collected", 180, || async {
        let inboxed = quinn.collect_inbox().await?;
        let got: u64 = inboxed.received.iter().map(|r| r.amount).sum();
        Ok((got > 0).then_some(got))
    })
    .await?;
    // Less the provider's default fee of 2 sat and 5,000 ppm.
    assert_eq!(got, 5_000 - 2 - 25);
    assert!(paying.await??, "the outside node's payment failed");
    assert_eq!(available_at(&quinn, hub2), got);

    // A second donation to the same LNURL: another invoice.
    let again = eco.get_json(&format!("{callback}?amount=5000000")).await?;
    assert_ne!(again["pr"], invoice["pr"]);
    // Refused as LNURL says, not in whole satoshis.
    let refused = eco.get_json(&format!("{callback}?amount=5000500")).await?;
    assert_eq!(refused["status"], "ERROR", "{refused}");
    Ok(())
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_provider_has_a_wallet_paid_over_lightning_at_a_hub() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let hub2 = eco.hub(2);
    eco.stock(20_000).await?;
    let rose = eco.wallet("rose")?;
    rose.add_hub(hub2).await?;
    let provider = eco.swaps_info().await?;
    let terms = provider.receive.expect("receipts taken");

    // The provider's node makes the invoice under Rose's hash, asking the
    // amount and its fee exactly.
    let invoice = rose
        .invoice_through(eco.swaps(), hub2, 5_000, Some("Tea"))
        .await?;
    let request = invoice.request.as_deref().expect("an invoice");
    let decoded = eco.lncli(OUTSIDE, &["decodepayreq", request]).await?;
    assert_eq!(decoded["num_satoshis"], terms.asks(5_000).to_string());
    assert_eq!(decoded["payment_hash"], invoice.hash);
    assert_eq!(decoded["description"], "Tea");
    let node = eco.lncli(SWAPS_LN, &["getinfo"]).await?;
    assert_eq!(decoded["destination"], node["identity_pubkey"]);
    // Held long enough for the provider to force the preimage out on
    // Bitcoin, should hub2 keep it: past its window, its margins and
    // Rose's time to claim.
    let window = eco
        .info(hub2)
        .await?
        .locks
        .expect("hub2 takes locks")
        .window;
    let cltv: u32 = decoded["cltv_expiry"].as_str().unwrap().parse()?;
    assert!(
        cltv >= window + 18 + 12 + 3,
        "{cltv} for a window of {window}"
    );

    // Paid from outside: locked to Rose at hub2, claimed, then settled.
    let paying = eco.pay(OUTSIDE, request);
    assert_eq!(
        received(&rose, &invoice.hash).await?,
        InvoiceState::Received
    );
    assert_eq!(available_at(&rose, hub2), 5_000);
    assert!(paying.await??, "the outside node's payment failed");
    let status = eco
        .get_json(&format!(
            "{}{}",
            eco.swaps(),
            licash_api::swaps::receive_state(&hex_32(&invoice.hash))
        ))
        .await?;
    assert_eq!(status["state"], "settled", "{status}");
    let (state, _) = eco.invoice_state(SWAPS_LN, &invoice.hash).await?;
    assert_eq!(state, "SETTLED");
    Ok(())
}
