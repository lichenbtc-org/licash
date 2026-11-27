//! Deposits on Bitcoin through the swap provider, for notes at the first
//! hub, paid and refunded on Bitcoin Core, on the stack of
//! `apps/e2e/run.sh`, which runs these: Core's mempool and blocks take the
//! provider's claim and the payer's refund as valid spends, and the hub
//! itself takes no new plain deposit.

use anyhow::{bail, ensure, Context};
use bitcoin::{consensus::encode::serialize_hex, Amount, FeeRate, OutPoint, ScriptBuf, Txid};
use licash_e2e::{until, Eco, Wallet};
use licash_wallet::{Deposit, DepositState};
use serde_json::json;

/// The deposit of `hash` once in a state `done` accepts, followed on
/// through its provider, a block mined between rounds if `mining`.
async fn followed(
    eco: &Eco,
    wallet: &Wallet,
    (hash, mining): (&str, bool),
    what: &str,
    done: impl Fn(&DepositState) -> bool,
) -> anyhow::Result<Deposit> {
    until(what, 120, || async {
        if mining {
            eco.mine(1).await?;
        }
        wallet.follow_deposits_through(eco).await?;
        let deposit = wallet.deposit_of(hash)?;
        Ok(done(&deposit.state).then_some(deposit))
    })
    .await
}

/// Whether Bitcoin Core's chain leaves `outpoint` unspent.
async fn unspent(eco: &Eco, outpoint: &OutPoint) -> anyhow::Result<bool> {
    let txid = outpoint.txid.to_string();
    let out = eco
        .core("gettxout", json!([txid, outpoint.vout, false]))
        .await?;
    Ok(!out.is_null())
}

/// Mine until the tip is `height`.
async fn mine_to(eco: &Eco, height: u32) -> anyhow::Result<()> {
    let tip = eco.height().await?;
    ensure!(tip <= height, "the tip {tip} is past {height}");
    if tip < height {
        eco.mine(height - tip).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn the_hub_refuses_a_plain_deposit_new_to_it() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let alice = eco.wallet("alice")?;
    // Asked as wallets of earlier releases ask: canceled unpaid, the hub
    // naming providers.
    let deposit = alice.deposit(eco.hub(1), 20_000).await?;
    match &deposit.state {
        DepositState::Canceled(why) if why.contains("through a swap provider") => {}
        _ => bail!("a plain deposit: {deposit:?}"),
    }
    ensure!(deposit.terms.is_none(), "{deposit:?}");
    Ok(())
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_deposit_paid_on_bitcoin_is_received_and_its_coins_claimed() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let hub = eco.hub(1);
    eco.stock_at(hub, 30_000).await?;
    let alice = eco.wallet("alice")?;
    alice.add_hub(hub).await?;
    let deposit = alice.deposit_through(eco.swaps(), hub, 20_000).await?;
    let terms = deposit.terms.clone().context("its terms")?;
    // The provider's fee of 5000 ppm and 500 for its claim's miners on top.
    ensure!(terms.pays == 20_600, "pays {}", terms.pays);
    let txid = eco.send_to(&terms.address, terms.pays).await?;
    let (funding, _) = eco.paying(&txid, &terms.address).await?;
    eco.mine(1).await?;

    // At depth, the wallet tells the provider, which locks its notes at
    // the hub, which the wallet claims.
    let received = followed(
        &eco,
        &alice,
        (&deposit.hash, false),
        "the deposit received",
        |s| *s == DepositState::Received,
    )
    .await?;
    ensure!(
        received.funding.map(|(o, _)| o) == Some(funding),
        "{received:?}"
    );
    let balance: u64 = alice.balance()?.iter().map(|b| b.available).sum();
    ensure!(balance == 20_000, "a balance of {balance}");

    // The preimage the wallet claimed with lets the provider claim the
    // coin, which Core takes into its mempool, then a block.
    let prevout = json!([{ "txid": funding.txid.to_string(), "vout": funding.vout }]);
    let claim = until("the provider's claim", 120, || async {
        let spending = eco.core("gettxspendingprevout", json!([prevout])).await?;
        Ok(spending[0]["spendingtxid"].as_str().map(str::to_owned))
    })
    .await?;
    let height = eco.mine(1).await?;
    ensure!(
        !unspent(&eco, &funding).await?,
        "the deposit is still unspent"
    );
    let block = eco.core("getblockhash", json!([height])).await?;
    let tx = eco
        .core("getrawtransaction", json!([claim, 1, block]))
        .await?;
    ensure!(tx["confirmations"].as_u64() >= Some(1), "{tx}");
    let refund = alice.refund_deposit(
        &deposit.hash,
        funding,
        Amount::from_sat(terms.pays),
        ScriptBuf::new(),
        FeeRate::from_sat_per_vb_u32(2),
    );
    ensure!(
        refund.is_err(),
        "a refund of a deposit received: {refund:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn a_deposit_paid_wrong_returns_to_its_payer_after_its_timeout() -> anyhow::Result<()> {
    let eco = Eco::up().await?;
    let hub = eco.hub(1);
    eco.stock_at(hub, 30_000).await?;
    let alice = eco.wallet("alice")?;
    alice.add_hub(hub).await?;
    let deposit = alice.deposit_through(eco.swaps(), hub, 15_000).await?;
    let terms = deposit.terms.clone().context("its terms")?;
    // A satoshi short: never told of, canceled once too late to lock.
    let txid = eco.send_to(&terms.address, terms.pays - 1).await?;
    let (funding, value) = eco.paying(&txid, &terms.address).await?;
    eco.mine(1).await?;
    followed(
        &eco,
        &alice,
        (&deposit.hash, true),
        "the deposit canceled",
        |s| matches!(s, DepositState::Canceled(_)),
    )
    .await?;
    let balance: u64 = alice.balance()?.iter().map(|b| b.available).sum();
    ensure!(balance == 0, "a balance of {balance}");

    // Its refund is not final before the timeout: Core refuses it.
    let to = eco.miner_address("bech32m").await?;
    let to = to
        .parse::<bitcoin::Address<_>>()?
        .assume_checked()
        .script_pubkey();
    let rate = FeeRate::from_sat_per_vb_u32(2);
    let refund = alice.refund_deposit(&deposit.hash, funding, value, to.clone(), rate)?;
    ensure!(refund.lock_time.to_consensus_u32() == terms.timeout);
    ensure!(
        eco.height().await? < terms.timeout,
        "canceled past its timeout"
    );
    let early = eco
        .core("sendrawtransaction", json!([serialize_hex(&refund)]))
        .await;
    match early {
        Err(e) if format!("{e:#}").contains("non-final") => {}
        other => bail!("a refund before the timeout: {other:?}"),
    }
    // From the timeout on, it is.
    mine_to(&eco, terms.timeout).await?;
    let sent = eco
        .core("sendrawtransaction", json!([serialize_hex(&refund)]))
        .await?;
    let sent: Txid = sent.as_str().context("a txid")?.parse()?;
    ensure!(sent == refund.compute_txid());
    eco.mine(1).await?;
    ensure!(
        !unspent(&eco, &funding).await?,
        "the deposit is still unspent"
    );
    let state = alice.deposit_of(&deposit.hash)?.state;
    ensure!(state == DepositState::Refunded(sent), "{state:?}");
    Ok(())
}
