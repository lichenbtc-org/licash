//! The observatory watches the stack's hubs and provider, then moves a
//! balance of its own between them, in Licash, through the provider and on
//! Bitcoin, each move recorded with what it cost, on the stack of
//! `apps/e2e/run.sh`, which runs these. Over Lightning it finds no route:
//! hubs make no invoices, and a provider's invoice for a wallet asks a
//! final CLTV no lock at a hub outlasts.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use licash_e2e::{until, Eco};
use licash_nostr::Route;
use licash_observatory::{
    budget::Kind,
    mover::{Mover, Moving, Skipped},
    observer::{self, Watching},
    probe::Dialer,
    store::{Outcome, Store},
};

/// What each move moves.
const AMOUNT: u64 = 2_000;

/// What the observatory's wallet is funded with.
const FUNDS: u64 = 40_000;

/// The provider able to pay out `amount` on Bitcoin, funded there once.
async fn funded(eco: &Eco, amount: u64) -> anyhow::Result<()> {
    let max = || async {
        let info = eco.swaps_info().await?;
        anyhow::Ok(info.chain.map_or(0, |c| c.max))
    };
    if max().await? >= amount {
        return Ok(());
    }
    let address = eco.exec("swaps", &["licash-swaps", "address"]).await?;
    eco.send_to(String::from_utf8(address)?.trim(), 3 * amount)
        .await?;
    eco.mine(1).await?;
    until("the provider's coins found", 120, || async {
        Ok((max().await? >= amount).then_some(()))
    })
    .await
}

#[tokio::test]
#[ignore = "needs the stack of apps/e2e/run.sh"]
async fn the_observatory_moves_its_balance_between_hubs_and_records_each_move() -> anyhow::Result<()>
{
    let eco = Eco::up().await?;
    let (hub1, hub2) = (eco.hub(1).to_owned(), eco.hub(2).to_owned());
    eco.stock(10 * AMOUNT).await?;
    funded(&eco, 100_000).await?;

    let dir = tempfile::tempdir()?;
    let store = Arc::new(Store::open(&dir.path().join("observatory.sqlite"))?);
    // By their URLs on this host: those announced are the stack's own.
    let watching = Watching {
        network: "regtest".into(),
        relays: Vec::new(),
        route: Route::Direct,
        dialer: Dialer::direct_reaching(true),
        hubs: vec![hub1.clone(), hub2.clone()],
        providers: vec![eco.swaps().to_owned()],
        probe_every: Duration::from_secs(5),
        discover_every: Duration::from_secs(600),
        timeout: Duration::from_secs(20),
    };
    observer::discover(&store, &watching).await?;
    observer::round(store.clone(), watching).await;
    let probes = store.probes_since(0)?;
    assert_eq!(probes.len(), 3);
    assert!(probes.iter().all(|p| p.ok), "{probes:?}");

    let wallet = eco.wallet("observatory")?;
    wallet.add_hub(&hub1).await?;
    eco.pay_in(&wallet, &hub1, FUNDS).await?;
    let shown = Arc::new(Mutex::new(None));
    let moving = Moving {
        store: store.clone(),
        monthly: 100_000,
        amount: AMOUNT,
        fresh: 600_000,
        shown: shown.clone(),
        chain: Some(eco.chain().parse()?),
        block_secs: 600,
    };
    let mut mover = Mover::new(wallet, moving)?;

    let lightning = mover.move_now(Kind::Lightning).await;
    assert!(
        matches!(lightning, Err(Skipped::NoRoute(_))),
        "{lightning:?}"
    );
    for kind in [Kind::Hub, Kind::Swap, Kind::Chain] {
        // Blocks mined meanwhile, for a move on Bitcoin.
        let mining = async {
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                eco.mine(1).await?;
            }
        };
        let quoted = tokio::select! {
            made = mover.move_now(kind) => made,
            failed = mining => return failed,
        }
        .map_err(|e| anyhow::anyhow!("{kind:?}: {e:?}"))?;
        let actions = store.actions_since(0)?;
        let made = actions.last().unwrap();
        assert_eq!(made.kind, kind.key());
        assert_eq!(made.outcome, Outcome::Done, "{kind:?}: {:?}", made.detail);
        assert_eq!(made.quoted, Some(quoted));
        let cost = made.cost.expect("a cost measured");
        eprintln!(
            "{kind:?}: quoted {quoted}, cost {cost}, {} ms",
            made.ended.unwrap() - made.started
        );
        assert!(cost < AMOUNT, "{kind:?} cost {cost}");
        assert!(made.ended.unwrap() >= made.started);
        // A move on Bitcoin is timed by its swap, the provider's coin out,
        // not by the blocks waited for after it.
        if kind == Kind::Chain {
            let swapped = made.swapped.expect("its swap timed");
            let all = u64::try_from(made.ended.unwrap() - made.started)?;
            assert!(swapped < all, "swap {swapped} ms of {all} ms in all");
        } else {
            assert_eq!(made.swapped, None, "{kind:?} is timed by all of it");
        }
    }
    let actions = store.actions_since(0)?;
    let swap = actions.iter().find(|a| a.kind == Kind::Swap.key()).unwrap();
    assert_eq!(swap.via.as_deref(), Some(eco.swaps()));
    assert_ne!(swap.source, swap.target);

    let budget = shown.lock().unwrap().clone().unwrap();
    let spent: u64 = actions.iter().filter_map(|a| a.cost).sum();
    assert_eq!(budget.spent, spent);
    assert!(spent > 0, "fees are paid");
    // What was spent is what the wallet holds less, all of it.
    assert_eq!(budget.balance, Some(FUNDS - spent));
    Ok(())
}
