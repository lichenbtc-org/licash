//! A recovery contract paid for with notes, by a wallet with no coin on
//! Bitcoin, on the stack of `apps/e2e/run.sh`: the swap provider pays the
//! wallet's own address a coin worth the contract's price and her part,
//! and the contract opens on it as on any coin of hers.

use anyhow::Context;
use bitcoin::FeeRate;
use licash_api::swaps::State;
use licash_contracts::holder::paid::PART;
use licash_contracts::holder::{self, paid, Ask, Fate, Node};
use licash_e2e::{until, Eco};
use licash_nostr::{wallet::payout_providers, Route};
use licash_wallet::{LockState, PayoutState};
use serde_json::json;

/// What the provider holds on chain for the tests.
const COINS: u64 = 300_000;

/// The provider funded on chain with `COINS`, once: what it pays out now.
async fn funded(eco: &Eco, amount: u64) -> anyhow::Result<()> {
    let max = || async {
        let info = eco.swaps_info().await?;
        let chain = info
            .chain
            .context("the provider pays nothing out on Bitcoin")?;
        anyhow::Ok(chain.max)
    };
    if max().await? >= amount {
        return Ok(());
    }
    let address = eco.exec("swaps", &["licash-swaps", "address"]).await?;
    let address = String::from_utf8(address)?;
    eco.send_to(address.trim(), COINS).await?;
    eco.mine(1).await?;
    until("the provider's coins found", 120, || async {
        Ok((max().await? >= amount).then_some(()))
    })
    .await
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_wallet_with_no_coin_pays_for_a_contract_with_notes() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let hub1 = eco.hub(1);
    funded(&eco, 60_000).await?;
    // Its wallet's coins, made as the stack came up, learned once a minute:
    // until then it funds none of a contract.
    let offered = until("hub1's wallet funding a contract", 150, || async {
        let info = eco.info(hub1).await?;
        let offered = info.contracts.context("hub1 opens no contracts")?;
        Ok(offered
            .funds
            .is_none_or(|most| most >= offered.cap)
            .then_some(offered))
    })
    .await?;

    let alice = eco.wallet("contractor")?;
    eco.pay_in(&alice, hub1, 60_000).await?;
    let path = alice.path().to_owned();
    let node = Node(eco.chain().parse()?);
    let ask = Ask {
        blocks: offered.blocks,
        max_price: 40_000,
        cap: None,
        inbound: 0,
        deposit: None,
    };
    let coin = paid::coin(&alice, hub1, ask, 0).await?;
    assert_eq!(coin.to, alice.fallback_address()?.to_string());
    // Asked again for the coin quoted, as the app opens it: the same.
    assert_eq!(paid::coin_worth(&alice, hub1, ask, coin.value).await?, coin);
    // Raised to a provider's least: her part larger, of the same contract.
    let raised = paid::coin(&alice, hub1, ask, coin.value + 5_000).await?;
    assert!(raised.value >= coin.value + 5_000, "{raised:?}");
    assert_eq!(raised.fit.cap, coin.fit.cap);
    assert!(raised.fit.funded > coin.fit.funded, "{raised:?}");
    // Its provider found on the relay it announces itself on, as the app
    // finds it.
    let relays = [eco.relay().to_owned()];
    let rate = FeeRate::from_sat_per_vb_u32(1);
    let pair = (hub1, coin.to.as_str());
    let found = payout_providers(
        &alice,
        &relays,
        &Route::Direct,
        pair,
        coin.value,
        (5_000, rate),
    );
    let found = found
        .await?
        .into_iter()
        .next()
        .context("no provider found")?;
    assert_eq!(found.url, eco.swaps());
    let paid = paid::pay(&alice, &path, &coin, &found.quote).await?;
    assert_eq!(paid.value, paid.price + u64::from(paid.fit.funded));
    assert_eq!(u64::from(paid.fit.funded), PART);
    let payout = alice
        .payouts()?
        .into_iter()
        .find(|p| p.hash == paid.ticket)
        .context("the payout")?;
    let lock = payout.lock.clone().context("a lock")?;
    // To her own address, the coin worth what was paid for and the claim's
    // budget.
    assert_eq!(payout.address, alice.fallback_address()?.to_string());
    assert_eq!(payout.amount, paid.value);
    assert_eq!(
        eco.payout_state(&lock).await?.value,
        paid.value + payout.budget
    );

    // Claimed to her wallet, then opened on that coin as on any.
    let contract = until("the contract opened on the coin", 900, || async {
        eco.mine(1).await?;
        let contracts = holder::resume(&alice, &node, &path).await?;
        let payouts = alice.payouts()?;
        let ours = payouts
            .iter()
            .find(|p| p.hash == paid.ticket)
            .context("the payout")?;
        // Failed, it never opens: told why at once.
        if let PayoutState::Failed(why) = &ours.state {
            anyhow::bail!("the coin's payout failed: {why}");
        }
        let Some(claim) = ours.claim else {
            return Ok(None);
        };
        let opened = contracts
            .into_iter()
            .find(|c| c.deposit.txid == claim && c.fate == Some(Fate::Live));
        Ok(opened)
    })
    .await?;
    assert_eq!(contract.hub, hub1);
    assert!((1..=PART).contains(&contract.funded), "{contract:?}");
    let done = alice.follow_payout(&paid.ticket, &eco).await?;
    assert_eq!(done.state, PayoutState::Done, "{done:?}");
    assert_eq!(done.claim, Some(contract.deposit.txid));

    // The provider paid with the preimage her claim revealed.
    until("the provider paid", 120, || async {
        Ok((eco.payout_state(&lock).await?.state == State::Done).then_some(()))
    })
    .await?;
    alice.resume().await?;
    let ours = alice.locks()?.into_iter().find(|l| l.id == lock).unwrap();
    assert!(matches!(ours.state, LockState::Paid(_)), "{ours:?}");
    // Her coin spent by F, the contract's funding.
    let coin = eco
        .core(
            "gettxout",
            json!([contract.deposit.txid.to_string(), contract.deposit.vout]),
        )
        .await?;
    assert!(coin.is_null(), "her coin unspent: {coin}");
    Ok(())
}
