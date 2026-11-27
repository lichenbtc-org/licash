//! A payment code paid at the first hub and sent to its payee's mailbox on
//! the stack's relay (nostr-rs-relay), on the stack of `apps/e2e/run.sh`,
//! which runs these: the relay takes the gift wrap and serves it to the
//! payee alone.

use anyhow::{ensure, Context};
use licash_e2e::{until, Eco};
use licash_nostr::{mailbox, Route};
use licash_wallet::PaymentCode;

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_payment_code_is_paid_through_the_payees_mailbox() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let hub = eco.hub(1);
    let (alice, bob) = (eco.wallet("alice")?, eco.wallet("bob")?);
    // Alice holds 10000 at the hub, paid in over Lightning.
    eco.pay_in(&alice, hub, 10_000).await?;

    // Bob's code names the hub, which names the relay, and his mailbox.
    let info = bob.add_hub(hub).await?;
    ensure!(!info.relays.is_empty(), "the hub names no mailbox relay");
    let code: PaymentCode = bob.payment_code(&[hub.to_owned()])?.qr().parse()?;
    code.check(alice.network())?;
    let licash = code.licash.context("a Licash code")?;
    let to = licash.mailbox.context("a mailbox")?;
    ensure!(alice.hub_to_pay(&licash, 2_000)?.as_deref() == Some(hub));

    // Alice pays and sends it; the relay keeps it for Bob alone.
    let paid = alice.send(hub, &licash.address, 2_000).await?;
    let content = serde_json::to_string(&paid.payment)?;
    let sent = mailbox::send(&to, &content, &info.relays, &Route::Direct).await?;
    ensure!(sent == 1, "taken by {sent} relays");
    let theirs = mailbox::fetch(&alice.mailbox_secret(), &info.relays, &Route::Direct).await?;
    ensure!(theirs.is_empty(), "Alice's mailbox holds {theirs:?}");
    let mail = until("the payment in the mailbox", 30, || async {
        let mail = mailbox::fetch(&bob.mailbox_secret(), &info.relays, &Route::Direct).await?;
        Ok((!mail.is_empty()).then_some(mail))
    })
    .await?;
    ensure!(mail.len() == 1 && mail[0].content == content, "{mail:?}");
    let received = bob.receive(&serde_json::from_str(&mail[0].content)?)?;
    ensure!(received.amount == 2_000, "received {}", received.amount);
    Ok(())
}
