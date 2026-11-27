//! Wallets discover the hubs announced on the stack's Nostr relay, of
//! `apps/e2e/run.sh`, which runs these.

use licash_e2e::{until, Eco};
use licash_nostr::{discover, Role, Route};

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn wallets_discover_the_hubs_announced_on_nostr() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let relays = [eco.relay().to_owned()];
    let found = until("both hubs announced", 120, || async {
        let found = discover(&relays, &Route::Direct, Role::Hub, "regtest").await?;
        Ok((found.len() == 2).then_some(found))
    })
    .await?;
    for (n, name) in [(1, "hub1"), (2, "hub2")] {
        let hub = found
            .iter()
            .find(|f| f.announcement.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("{name} among {found:?}"));
        assert_eq!(hub.announcement.urls, [eco.hub(n)]);
        // The hub at the URL announced is the one that announced it.
        let info = eco.info(eco.hub(n)).await?;
        assert!(hub.named_by(info.nostr.as_deref()), "{hub:?}");
        let other = eco.info(eco.hub(3 - n)).await?;
        assert!(!hub.named_by(other.nostr.as_deref()));
    }
    assert!(discover(&relays, &Route::Direct, Role::Hub, "bitcoin")
        .await?
        .is_empty());

    // A wallet trusts a hub discovered.
    let wallet = eco.wallet("discoverer")?;
    let hub = &found[0].announcement.urls[0];
    let info = wallet.add_hub(hub).await?;
    assert!(info.locks.is_some(), "{info:?}");
    Ok(())
}
