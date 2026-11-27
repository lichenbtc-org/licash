//! A wallet finds the NWC bridge announced on the stack's relay, keeps an
//! account there topped up in notes at its hub, and is paid at its Lightning
//! Address there from outside, on the stack of `apps/e2e/run.sh`, which
//! runs these.

use licash_e2e::{until, Eco, Wallet, OUTSIDE};
use licash_nostr::{discover, Role, Route};

/// The balance of `wallet`'s account at `bridge`, in msat, once more than
/// `above`.
async fn credited(wallet: &Wallet, bridge: &str, above: u64) -> anyhow::Result<u64> {
    until(
        &format!("an account credited above {above} msat"),
        180,
        || async {
            let account = wallet.bridge_account(bridge).await?;
            Ok((account.balance > above).then_some(account.balance))
        },
    )
    .await
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_wallet_finds_an_open_bridge_tops_it_up_and_is_paid_at_its_address() -> anyhow::Result<()>
{
    let eco = Eco::up().await?;
    let bridge = eco.bridge();
    let relays = [eco.relay().to_owned()];
    let found = until("the bridge announced", 120, || async {
        let found = discover(&relays, &Route::Direct, Role::Bridge, "regtest").await?;
        Ok((!found.is_empty()).then_some(found))
    })
    .await?;
    let info = eco
        .get_json(&format!("{bridge}{}", licash_api::bridge::INFO))
        .await?;
    let announced = &found[0];
    assert_eq!(announced.announcement.urls, [bridge]);
    assert!(announced.named_by(info["nostr"].as_str()), "{announced:?}");
    assert_eq!(info["open"], true, "{info}");

    // Topped up in notes at the bridge's hub, hub2: credited whole.
    let wallet = eco.wallet("bridged")?;
    let hub = eco.hub(2);
    wallet.add_hub(hub).await?;
    eco.pay_in(&wallet, hub, 5_000).await?;
    let (_, account) = wallet.add_bridge(bridge, None).await?;
    assert_eq!(account.balance, 0);
    let topped = wallet.top_up_bridge(bridge, 1_000, Some(50)).await?;
    assert_eq!(topped.credited, Some(1_000_000));
    let topped = credited(&wallet, bridge, 0).await?;
    assert_eq!(topped, 1_000_000);

    // Paid at its Lightning Address, from outside.
    let account = wallet.bridge_username(bridge, Some("alice")).await?;
    let address = account.lightning_address.expect("an address");
    assert!(address.starts_with("alice@"), "{address}");
    let pay = eco
        .get_json(&format!("{bridge}/.well-known/lnurlp/alice"))
        .await?;
    assert_eq!(pay["tag"], "payRequest", "{pay}");
    let callback = pay["callback"].as_str().expect("a callback");
    let invoice = eco.get_json(&format!("{callback}?amount=200000")).await?;
    let request = invoice["pr"].as_str().expect("an invoice");
    let paying = eco.pay(OUTSIDE, request);
    let paid = credited(&wallet, bridge, topped).await?;
    assert!(paying.await??, "the outside node's payment failed");
    assert!(
        (topped + 190_000..=topped + 200_000).contains(&paid),
        "{paid} msat"
    );

    // Open to anyone, it hands no account its notes: only its operator,
    // on its own command line, exports them.
    assert!(wallet.export_bridge(bridge).await.is_err());
    Ok(())
}
