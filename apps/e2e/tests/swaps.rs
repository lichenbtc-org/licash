//! Wallets swap notes between the stack's hubs through the swap provider
//! they discover on Nostr, on the stack of `apps/e2e/run.sh`, which runs
//! these. Hubs provide no swaps.

use licash::spend::lock_hash;
use licash_api::{
    swaps::{Request, State, Swap},
    Info,
};
use licash_e2e::{until, Eco, Wallet};
use licash_nostr::{discover, Role, Route};
use licash_wallet::{Lock, LockState, SwapLimits, SwapState};
use rand_core::{OsRng, RngCore};

/// What the provider holds at hub 2 for the tests.
const STOCK: u64 = 60_000;

/// Blocks the provider's lock at hub 2 expires before its client's at hub
/// 1, at least: 36 to get a refund request confirmed, hub 2's window of
/// 144, 1 to read the preimage, its margin of 12 to claim with it, and 1.
const LEAD: u32 = 36 + 144 + 1 + 12 + 1;

fn held(wallet: &Wallet, hub: &str) -> u64 {
    let balance = wallet.balance().unwrap();
    balance
        .iter()
        .find(|b| b.hub == hub)
        .map_or(0, |b| b.available)
}

/// Wait for the swap of the client's lock `id` at the provider at
/// `provider` to reach `state`.
async fn reaches(eco: &Eco, provider: &str, id: &str, state: State) -> anyhow::Result<Swap> {
    until(&format!("swap {id} {state:?}"), 120, || async {
        let swap = eco.swap_state_at(provider, id).await?;
        Ok((swap.state == state).then_some(swap))
    })
    .await
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn wallets_swap_between_hubs_through_a_provider_found_on_nostr() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let (hub1, hub2) = (eco.hub(1), eco.hub(2));
    let relays = [eco.relay().to_owned()];
    let found = until("the provider announced", 120, || async {
        let found = discover(&relays, &Route::Direct, Role::Swaps, "regtest").await?;
        Ok((!found.is_empty()).then_some(found))
    })
    .await?;
    // The stack's own, and no hub.
    let info = eco.swaps_info().await?;
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].announcement.urls, [eco.swaps()]);
    assert!(found[0].named_by(info.nostr.as_deref()));
    assert_eq!((info.fee.base, info.fee.ppm), (1, 5000));
    let address = eco.info(hub2).await?.address;
    assert_ne!(info.address, address);
    // Its lock at hub 2 outlives hub 2's window and its margins.
    let at_hub2 = info.hub(&address).unwrap();
    assert_eq!(info.margin_at(at_hub2), LEAD);

    let alice = eco.wallet("swapper")?;
    eco.pay_in(&alice, hub1, 60_000).await?;
    eco.stock(STOCK).await?;
    alice.add_hub(hub2).await?;
    let swap = alice
        .swap(eco.swaps(), hub1, hub2, 10_000, SwapLimits::usual(10_000))
        .await?;
    assert_eq!(swap.state, SwapState::Done, "{swap:?}");
    // 1 + 5000 ppm of 10 000.
    assert_eq!(swap.fee, 51);
    assert_eq!(held(&alice, hub2), 10_000);

    // The provider claims Alice's lock with the preimage she revealed to
    // claim its own.
    let id = swap.lock.clone().unwrap();
    reaches(&eco, eco.swaps(), &id, State::Done).await?;
    alice.resume().await?;
    let ours = alice.locks()?.into_iter().find(|l| l.id == id).unwrap();
    assert!(matches!(ours.state, LockState::Paid(_)), "{ours:?}");
    assert_eq!(ours.amount, 10_051);
    assert_eq!(alice.swaps()?.len(), 1);
    Ok(())
}

/// Bob's own lock of `amount` and the provider's fee to the provider at
/// hub 1 under the hash of `preimage`, expiring at `expiry`, and the swap
/// he asks for with it.
async fn ask(
    eco: &Eco,
    bob: &Wallet,
    hubs: (&Info, &Info),
    preimage: &[u8; 32],
    expiry: u32,
) -> anyhow::Result<(Lock, Swap)> {
    let info = eco.swaps_info().await?;
    let amount = 5_000;
    let total = amount + info.fee.due(amount);
    let lock = bob
        .lock(
            eco.hub(1),
            &info.address,
            total,
            lock_hash(preimage),
            Some(expiry),
        )
        .await?;
    let id = licash_api::lock_id(&lock.id).map_err(|p| anyhow::anyhow!(p.message))?;
    let request = Request::new(
        &hubs.0.address,
        &id,
        &hubs.1.address,
        &bob.address(),
        amount,
    );
    let swap = eco.ask_swap(&request).await?;
    assert_eq!(swap.state, State::Locked, "{swap:?}");
    // The provider's lock expires its lead earlier.
    assert_eq!(swap.expiry, expiry - LEAD);
    Ok((lock, swap))
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_provider_restarted_takes_its_swaps_on_and_unclaimed_locks_return() -> anyhow::Result<()>
{
    let eco = Eco::up().await?;
    let (hub1, hub2) = (eco.hub(1), eco.hub(2));
    eco.stock(STOCK).await?;
    let bob = eco.wallet("bob-swaps")?;
    // Two payments in, for two locks at once.
    eco.pay_in(&bob, hub1, 8_000).await?;
    eco.pay_in(&bob, hub1, 8_000).await?;
    bob.add_hub(hub2).await?;
    let hubs = (eco.info(hub1).await?, eco.info(hub2).await?);
    // Within hub 1's 240 blocks, leaving the provider's lock 26.
    let expiry = eco.height().await? + LEAD + 26;
    let mut preimages = [[0; 32]; 2];
    for preimage in &mut preimages {
        OsRng.fill_bytes(preimage);
    }
    let (claimed, theirs) = ask(&eco, &bob, (&hubs.0, &hubs.1), &preimages[0], expiry).await?;
    let (unclaimed, other) = ask(&eco, &bob, (&hubs.0, &hubs.1), &preimages[1], expiry).await?;

    // Bob claims the provider's first lock while the provider restarts:
    // started again, it claims his lock with the preimage he revealed.
    eco.restart("swaps").await?;
    let lock = hex::encode(&theirs.lock.unwrap().0);
    let received = bob.claim(hub2, &lock, &preimages[0]).await?;
    assert_eq!(received.amount, 5_000);
    reaches(&eco, eco.swaps(), &claimed.id, State::Done).await?;

    // Unclaimed, the provider's second lock returns to it once expired at
    // the hub's depth of 3.
    let height = eco.height().await?;
    eco.mine(other.expiry + 3 + 1 - height).await?;
    reaches(&eco, eco.swaps(), &unclaimed.id, State::Refunded).await?;
    // Bob's returns to him once his expired.
    let height = eco.height().await?;
    eco.mine(expiry + 3 + 1 - height).await?;
    let refunded = until("Bob's lock refunded", 120, || async {
        let lock = bob.follow_lock(&unclaimed.id).await;
        Ok(lock.ok().filter(|l| l.state == LockState::Refunded))
    })
    .await?;
    assert_eq!(refunded.amount, 5_026);
    assert_eq!(held(&bob, hub2), 5_000);

    // The operator sees both, in its status and its events.
    let status = eco
        .exec("swaps", &["licash-swaps", "status", "--json"])
        .await?;
    let status: serde_json::Value = serde_json::from_slice(&status)?;
    assert!(status["stats"]["done"].as_u64() >= Some(1), "{status}");
    assert!(status["stats"]["refunded"].as_u64() >= Some(1), "{status}");
    let events = eco.exec("swaps", &["licash-swaps", "events"]).await?;
    let events = String::from_utf8(events)?;
    for kind in ["accepted", "done", "refunded"] {
        assert!(events.contains(&format!("\"kind\":\"{kind}\"")), "{events}");
    }
    // And in its dashboard, read beside it running.
    let dashboard = eco.dashboard("swaps", "licash-swaps").await?;
    assert_eq!(dashboard.check("Service").map(|c| c.0), Some("good".into()));
    assert!(dashboard.card("Done") >= Some(1.0));
    assert!(dashboard.card("Never claimed") >= Some(1.0));
    assert!(dashboard.card("Fees") > Some(0.0));
    assert!(dashboard.card("Notes held") > Some(0.0));
    let events = dashboard.texts("Recent events");
    for event in ["taken", "done", "refunded"] {
        assert!(events.iter().any(|e| e[0] == event), "{event}: {events:?}");
    }
    Ok(())
}
