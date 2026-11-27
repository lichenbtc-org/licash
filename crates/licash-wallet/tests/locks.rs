#[allow(dead_code)]
mod net;

use std::sync::Arc;

use licash::claim::{Branch, Item, Source};
use licash::spend::{lock_hash, ChainProfile};
use licash_api::{Code, Fee};
use licash_wallet::{ClaimSlot, Error, LockState, PartTo, Wallet};
use net::{Fault, Link, LockLie, Net, HUB};

const FEE: Fee = Fee { base: 2, ppm: 0 };
const PREIMAGE: [u8; 32] = [7; 32];

struct Party {
    _dir: tempfile::TempDir,
    wallet: Wallet<Link>,
}

impl std::ops::Deref for Party {
    type Target = Wallet<Link>;
    fn deref(&self) -> &Wallet<Link> {
        &self.wallet
    }
}

async fn party(net: &Arc<Net>, seed: u8) -> Party {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(
        &dir.path().join("w.sqlite"),
        &[seed; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(net.clone()),
    )
    .unwrap();
    wallet.add_hub(HUB).await.unwrap();
    Party { _dir: dir, wallet }
}

/// Alice, holding one note of 64, and Bob, holding nothing.
async fn parties() -> (Arc<Net>, Party, Party) {
    let net = Net::new();
    net.start(HUB, FEE);
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    (net, alice, bob)
}

fn available(wallet: &Wallet<Link>) -> (u64, u64) {
    let balance = wallet.balance().unwrap();
    (balance[0].available, balance[0].pending)
}

fn hash() -> [u8; 32] {
    lock_hash(&PREIMAGE)
}

#[tokio::test]
async fn a_lock_pays_its_payee_on_the_preimage_and_returns_the_change() {
    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), None)
        .await
        .unwrap();
    // The latest expiry the hub admits at height 3: its window of 20, less
    // the depth of 1 and its reaction of 2.
    assert_eq!(
        (lock.amount, lock.fee, lock.expiry, &lock.state),
        (10, 2, 20, &LockState::Locked)
    );
    assert_eq!(available(&alice), (0, 64));
    assert_eq!(
        alice.follow_lock(&lock.id).await.unwrap().state,
        LockState::Locked
    );

    let received = bob.claim(HUB, &lock.id, &PREIMAGE).await.unwrap();
    assert_eq!(
        (received.id.as_str(), received.amount),
        (lock.id.as_str(), 10)
    );
    assert_eq!(available(&bob), (10, 0));
    assert!(matches!(
        bob.claim(HUB, &lock.id, &PREIMAGE).await,
        Err(Error::AlreadyReceived)
    ));
    let paid = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(paid.state, LockState::Paid(PREIMAGE));
    assert_eq!(available(&alice), (52, 0));
    assert_eq!(alice.locks().unwrap()[0].state, LockState::Paid(PREIMAGE));

    // Paid, it stays so past its expiry.
    net.mine(HUB, 20, None);
    assert_eq!(
        alice.follow_lock(&lock.id).await.unwrap().state,
        LockState::Paid(PREIMAGE)
    );
    let payment = bob.send(HUB, &alice.address(), 8).await.unwrap().payment;
    assert_eq!(alice.receive(&payment).unwrap().amount, 8);
}

#[tokio::test]
async fn a_lock_unpaid_is_refunded_once_expired_at_depth() {
    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(8))
        .await
        .unwrap();
    net.mine(HUB, 5, None);
    // At its expiry, but not at its depth.
    assert_eq!(
        alice.follow_lock(&lock.id).await.unwrap().state,
        LockState::Locked
    );
    assert!(matches!(
        bob.claim(HUB, &lock.id, &PREIMAGE).await,
        Err(Error::Invalid(why)) if why.contains("too late")
    ));
    net.mine(HUB, 1, None);
    let refunded = alice.resume().await.unwrap();
    assert_eq!(refunded.locks[0].state, LockState::Refunded);
    assert_eq!(available(&alice), (62, 0));
    assert!(matches!(
        bob.claim(HUB, &lock.id, &PREIMAGE).await,
        Err(Error::Invalid(why)) if why.contains("refunded")
    ));
}

/// A lock its hub certified and never settled is refunded on Bitcoin, by
/// a contract's recovery, once expired at depth: its refund outputs paying
/// the payer, claimed by one recovery only, and no longer asked of its
/// hub until that recovery is given up.
#[tokio::test]
async fn a_recovery_claims_an_unsettled_locks_refund_once_expired_at_depth() {
    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(8))
        .await
        .unwrap();
    let keyset = *net.hub(HUB).info().keysets[0].id();
    let slot = |id: [u8; 32]| ClaimSlot {
        id,
        keyset,
        cap: 1_000,
        max: 32,
    };
    let (first, second) = ([7; 32], [8; 32]);
    // At its expiry, short of its depth: owed nothing on Bitcoin yet.
    let (notes, refunds) = alice
        .claim_with_locks(&first, &[slot(first)], 8, None, false)
        .unwrap();
    assert!(notes.is_empty() && refunds.is_empty());
    let (_, refunds) = alice
        .claim_with_locks(&first, &[slot(first)], 100, None, false)
        .unwrap();
    assert_eq!(refunds.len(), 1);
    let refund = &refunds[0];
    assert_eq!(
        refund.id.as_bytes().as_slice(),
        &hex::decode(&lock.id).unwrap()[..]
    );
    // All but the hub's refund fee, its output not hers.
    assert_eq!(refund.value, 62);
    assert_eq!(refund.keys.len(), refund.items.len());
    assert!(refund.items.iter().all(|i| matches!(
        i,
        Item::Pending { branch: Branch::Refund, preimage: None, source, .. } if *source == refund.id
    )));
    let again = alice.claimed_locks(&first, &keyset).unwrap();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].id, refund.id);
    // Taken: no other recovery claims it.
    let (_, none) = alice
        .claim_with_locks(&second, &[slot(second)], 100, None, false)
        .unwrap();
    assert!(none.is_empty());
    // Settled on Bitcoin, not asked of its hub.
    net.mine(HUB, 6, None);
    assert_eq!(
        alice.follow_lock(&lock.id).await.unwrap().state,
        LockState::Locked
    );
    // Given up: its hub refunds it.
    alice.unclaim_notes(&first).unwrap();
    assert!(alice.claimed_locks(&first, &keyset).unwrap().is_empty());
    assert_eq!(
        alice.follow_lock(&lock.id).await.unwrap().state,
        LockState::Refunded
    );
    assert_eq!(available(&alice), (62, 0));
}

/// What a recovery would recover of the notes leaves out what the refunds
/// it claims first take of its cap, as it would claim them, once owed:
/// those left to the contracts after it.
#[tokio::test]
async fn a_refund_owed_takes_its_part_of_a_recoverys_cap_before_notes() {
    let (net, alice, bob) = parties().await;
    alice
        .lock(HUB, &bob.address(), 10, hash(), Some(8))
        .await
        .unwrap();
    alice.receive(&net.pay(HUB, &alice.address(), 32)).unwrap();
    let keyset = *net.hub(HUB).info().keysets[0].id();
    let slot = |id: [u8; 32], cap: u64| ClaimSlot {
        id,
        keyset,
        cap,
        max: 32,
    };
    let (first, second) = ([7; 32], [8; 32]);
    let alone = [slot(first, 70)];
    let recoverable = |slots: &[ClaimSlot], tip| alice.recoverable(slots, tip, None).unwrap();
    // Not owed yet: its notes alone.
    assert_eq!(recoverable(&alone, 8)[&first], 32);
    // Owed, its refund of 62 takes all but 8 of the cap.
    assert_eq!(recoverable(&alone, 100)[&first], 8);
    // Another contract after it there recovers the note in full, the
    // refund claimed once.
    let both = [slot(first, 70), slot(second, 100)];
    let each = recoverable(&both, 100);
    assert_eq!((each[&first], each[&second]), (0, 32));
    // As the recovery takes them.
    let (notes, refunds) = alice
        .claim_with_locks(&first, &alone, 100, None, false)
        .unwrap();
    let face: u64 = notes.iter().map(|n| n.note.message().denomination()).sum();
    assert_eq!((refunds.len(), refunds[0].value), (1, 62));
    assert_eq!(face.min(70 - 62), 8);
    // Taken: none left to the others, nor the first anymore.
    let each = recoverable(&both, 100);
    assert_eq!((each[&first], each[&second]), (0, 0));
}

/// A preimage is revealed to a hub only once what proves its lock on
/// Bitcoin is recorded: its payer's signatures and the checkpoint it
/// names. A hub leaving either out, or saying the lock was paid without
/// showing the preimage, learns nothing, and the lock stays its payer's
/// to refund.
#[tokio::test]
async fn a_preimage_is_revealed_only_against_what_proves_its_lock_on_bitcoin() {
    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(20))
        .await
        .unwrap();
    let lies = [
        vec![LockLie::Unsigned],
        vec![LockLie::Unanchored],
        vec![LockLie::Unsigned, LockLie::PaidUnshown],
        vec![LockLie::Unanchored, LockLie::PaidUnshown],
    ];
    for lie in lies {
        *net.lock_lies.lock().unwrap() = lie.clone();
        let refused = bob.claim(HUB, &lock.id, &PREIMAGE).await;
        assert!(
            matches!(&refused, Err(Error::Unavailable { reason, .. }) if reason.contains("proof")),
            "{lie:?}: {refused:?}"
        );
        assert!(bob.owed_locks().unwrap().is_empty(), "{lie:?}");
        net.lock_lies.lock().unwrap().clear();
        let state = alice.follow_lock(&lock.id).await.unwrap().state;
        assert_eq!(state, LockState::Locked, "{lie:?}");
    }
    // Proven, revealed and paid.
    let received = bob.claim(HUB, &lock.id, &PREIMAGE).await.unwrap();
    assert_eq!(received.amount, 10);
}

/// A lock paying the wallet that its hub never issued, its preimage
/// revealed, is recorded as owed before the hub learns it, and its pay
/// branch claimed on Bitcoin once activated at depth, by one recovery
/// only; issued since, it is owed no more.
#[tokio::test]
async fn a_recovery_claims_an_owed_locks_pay_once_activated_at_depth() {
    use licash::chain::{Activation, ActivationRef, Inclusion};
    use licash::recovery::SourceWitness;

    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(20))
        .await
        .unwrap();
    // Her settle never reaches the hub.
    net.fail(licash_api::SETTLE, Fault::Lost);
    assert!(bob.claim(HUB, &lock.id, &PREIMAGE).await.is_err());
    let owed = bob.owed_locks().unwrap();
    assert_eq!(owed.len(), 1);
    let o = &owed[0];
    assert_eq!(hex::encode(o.id.as_bytes()), lock.id);
    assert_eq!((o.preimage, o.hash, o.expiry), (PREIMAGE, hash(), 20));
    let anchor = o.anchor.clone().expect("its hub's checkpoint");
    assert_eq!(anchor.commitment(), o.checkpoint);
    assert!(o.activated_at.is_none() && !o.claimed);

    let keyset = *net.hub(HUB).info().keysets[0].id();
    let slot = |id: [u8; 32]| ClaimSlot {
        id,
        keyset,
        cap: 1_000,
        max: 32,
    };
    let (first, second) = ([7; 32], [8; 32]);
    let any = |_: &licash_wallet::LockClaim| true;
    // Not activated: nothing to claim.
    let (_, none) = bob
        .claim_with_locks(&first, &[slot(first)], 100, Some(&any), false)
        .unwrap();
    assert!(none.is_empty());
    bob.unclaim_notes(&first).unwrap();
    let activation = Activation {
        reference: ActivationRef {
            height: 10,
            block_hash: [3; 32],
            txid: [4; 32],
            output: 1,
        },
        inclusion: Inclusion {
            transaction: vec![1],
            index: 1,
            siblings: vec![],
            coinbase: vec![2],
            coinbase_siblings: vec![],
        },
    };
    bob.record_activation(&o.id, Some((&activation, &anchor)))
        .unwrap();
    let depth = o.depth;
    // Short of its depth, or refused by the caller: not claimed.
    let (_, none) = bob
        .claim_with_locks(&first, &[slot(first)], 10 + depth - 2, Some(&any), false)
        .unwrap();
    assert!(none.is_empty());
    bob.unclaim_notes(&first).unwrap();
    let (_, none) = bob
        .claim_with_locks(
            &first,
            &[slot(first)],
            100,
            Some(&|_: &licash_wallet::LockClaim| false),
            false,
        )
        .unwrap();
    assert!(none.is_empty());
    bob.unclaim_notes(&first).unwrap();
    let (_, none) = bob
        .claim_with_locks(&first, &[slot(first)], 100, None, false)
        .unwrap();
    assert!(none.is_empty());
    bob.unclaim_notes(&first).unwrap();
    let (_, pays) = bob
        .claim_with_locks(&first, &[slot(first)], 10 + depth - 1, Some(&any), false)
        .unwrap();
    assert_eq!(pays.len(), 1);
    let pay = &pays[0];
    assert_eq!((pay.id, pay.branch, pay.value), (o.id, Branch::Pay, 10));
    assert_eq!(pay.keys.len(), pay.items.len());
    assert!(pay.items.iter().all(|i| matches!(
        i,
        Item::Pending { branch: Branch::Pay, preimage: Some(p), source, .. }
            if *p == PREIMAGE && *source == pay.id
    )));
    assert!(matches!(pay.witness, SourceWitness::Certified { .. }));
    let (record, _) = pay.activation.as_ref().expect("its activation");
    assert_eq!(
        (record.source, record.reference),
        (o.id, activation.reference)
    );
    assert_eq!(bob.claimed_locks(&first, &keyset).unwrap().len(), 1);
    assert!(bob.owed_locks().unwrap()[0].claimed);
    // Claimed: by no other recovery, its activation kept as filed.
    let (_, none) = bob
        .claim_with_locks(&second, &[slot(second)], 100, Some(&any), false)
        .unwrap();
    assert!(none.is_empty());
    assert!(bob.record_activation(&o.id, None).is_err());
    // Given up, then issued by its hub: owed no more.
    bob.unclaim_notes(&first).unwrap();
    bob.unclaim_notes(&second).unwrap();
    bob.claim(HUB, &lock.id, &PREIMAGE).await.unwrap();
    assert!(bob.owed_locks().unwrap().is_empty());
    let (_, none) = bob
        .claim_with_locks(&first, &[slot(first)], 100, Some(&any), false)
        .unwrap();
    assert!(none.is_empty());
}

/// A wallet whose contracts at a hub are closed by some block keeps its
/// locks there claimable on Bitcoin: one of no expiry asked expires, at
/// depth, by then; one asked to expire later is refused, as is any once no
/// lock fits, or while its protection is unknown.
#[tokio::test]
async fn a_lock_expires_at_depth_before_her_contracts_at_its_hub_close() {
    let (net, alice, bob) = parties().await;
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    let horizon = |h: Result<Option<u32>, String>| {
        Arc::new(move |urls: &[String], _tip: u32| {
            assert!(urls.iter().any(|u| u.trim_end_matches('/') == HUB));
            h.clone()
        })
    };
    let refused = |r: Result<licash_wallet::Lock, Error>, what: &str| {
        assert!(
            matches!(&r, Err(Error::Invalid(why)) if why.contains(what)),
            "{r:?}"
        );
    };
    // Depth 1 here: a lock of expiry 9 is owed its refund from block 10.
    alice.guard_locks(horizon(Ok(Some(10))));
    let lock = alice
        .lock(HUB, &bob.address(), 1, hash(), None)
        .await
        .unwrap();
    assert_eq!(lock.expiry, 9);
    refused(
        alice.lock(HUB, &bob.address(), 1, hash(), Some(10)).await,
        "unprotected",
    );
    alice.guard_locks(horizon(Ok(Some(0))));
    refused(
        alice.lock(HUB, &bob.address(), 1, hash(), None).await,
        "unprotected",
    );
    alice.guard_locks(horizon(Err("no store".into())));
    refused(
        alice.lock(HUB, &bob.address(), 1, hash(), None).await,
        "protection is unknown",
    );
    // No contract there: as ever.
    alice.guard_locks(horizon(Ok(None)));
    let lock = alice
        .lock(HUB, &bob.address(), 1, hash(), Some(20))
        .await
        .unwrap();
    assert_eq!(lock.expiry, 20);
}

#[tokio::test]
async fn a_lock_is_not_made_at_a_hub_charging_more_than_agreed() {
    let (_net, alice, bob) = parties().await;
    let charged = alice.hubs().unwrap()[0].1.fees;
    // Either branch's fee raised refuses it.
    for agreed in [
        licash_api::Fees {
            lock: Fee::default(),
            ..charged
        },
        licash_api::Fees {
            refund: Fee::default(),
            ..charged
        },
    ] {
        alice.set_fee_ceilings(HUB, Some(agreed)).unwrap();
        assert!(matches!(
            alice.lock(HUB, &bob.address(), 10, hash(), Some(8)).await,
            Err(Error::FeesRaised { .. })
        ));
        assert!(alice.locks().unwrap().is_empty());
    }
    alice.set_fee_ceilings(HUB, Some(charged)).unwrap();
    alice
        .lock(HUB, &bob.address(), 10, hash(), Some(8))
        .await
        .unwrap();
}

#[tokio::test]
async fn each_branch_of_a_lock_pays_for_the_notes_it_makes() {
    // 2 in each branch, and a sat for each note made for others than the
    // hub.
    let net = Net::new();
    net.start_per_note(HUB, FEE, 1_000);
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();

    // Paid: 10 in two notes and a change of 48 in two, 6 to the hub.
    assert_eq!(alice.lock_fee(HUB, 10).unwrap(), 6);
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(8))
        .await
        .unwrap();
    assert_eq!(lock.fee, 6);
    let received = bob.claim(HUB, &lock.id, &PREIMAGE).await.unwrap();
    assert_eq!(received.amount, 10);
    let paid = alice.follow_lock(&lock.id).await.unwrap();
    assert_eq!(paid.state, LockState::Paid(PREIMAGE));
    assert_eq!(available(&alice), (48, 0));

    // Refunded: 48 back as 42 in three notes, 6 to the hub with its 2 and
    // one sat that would take a note more.
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(8))
        .await
        .unwrap();
    net.mine(HUB, 6, None);
    let refunded = alice.resume().await.unwrap();
    assert_eq!(refunded.locks[0].state, LockState::Refunded);
    assert_eq!(available(&alice), (42, 0));
    assert_eq!(lock.amount, 10);
}

#[tokio::test]
async fn a_locks_parts_are_what_it_pays_until_refunded_then_the_refund() {
    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(8))
        .await
        .unwrap();
    let parts = |alice: &Party| {
        let parts = alice.operation_parts(&lock.id).unwrap();
        for part in &parts {
            assert_eq!(part.notes.iter().sum::<u64>(), part.amount, "{part:?}");
        }
        parts
            .into_iter()
            .map(|p| (p.to, p.amount))
            .collect::<Vec<_>>()
    };
    // Its one note of 64: 10 to Bob if paid, its fee of 2, 52 back.
    let pays = vec![
        (PartTo::Payee(bob.address()), 10),
        (PartTo::Hub, 2),
        (PartTo::Kept, 52),
    ];
    assert_eq!(parts(&alice), pays);
    net.mine(HUB, 6, None);
    assert_eq!(
        alice.resume().await.unwrap().locks[0].state,
        LockState::Refunded
    );
    // Refunded: the hub's refund fee, and the rest back.
    assert_eq!(parts(&alice), [(PartTo::Hub, 2), (PartTo::Kept, 62)]);
}

/// A hub behind the blocks the wallet looked in itself, or saying it is,
/// is not believed on how many blocks a lock has left: the preimage is
/// kept from it.
#[tokio::test]
async fn a_claim_counts_the_blocks_left_at_the_wallets_own_height_too() {
    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(12))
        .await
        .unwrap();
    // Bob looked in every block up to the lock's margin; his hub says it
    // stands twelve blocks before its expiry.
    bob.watch_silent(None, lock.expiry - licash_wallet::CLAIM_MARGIN + 1)
        .unwrap();
    let refused = bob.claim(HUB, &lock.id, &PREIMAGE).await;
    assert!(
        matches!(&refused, Err(Error::Invalid(why)) if why.contains("too late")),
        "{refused:?}"
    );
    let id = licash_api::lock_id(&lock.id).unwrap();
    assert_eq!(net.hub(HUB).locked(&id).unwrap().preimage, None);
}

#[tokio::test]
async fn a_claim_reveals_the_preimage_only_well_before_expiry() {
    let (net, alice, bob) = parties().await;
    let late = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(6))
        .await
        .unwrap();
    let refused = bob.claim(HUB, &late.id, &PREIMAGE).await;
    assert!(
        matches!(&refused, Err(Error::Invalid(why)) if why.contains("too late")),
        "{refused:?}"
    );
    let id = licash_api::lock_id(&late.id).unwrap();
    assert_eq!(net.hub(HUB).locked(&id).unwrap().preimage, None);

    alice.receive(&net.pay(HUB, &alice.address(), 8)).unwrap();
    let lock = alice
        .lock(HUB, &bob.address(), 4, hash(), None)
        .await
        .unwrap();
    assert!(matches!(
        bob.claim(HUB, &lock.id, &[8; 32]).await,
        Err(Error::Invalid(_))
    ));
    let carol = party(&net, 3).await;
    assert!(matches!(
        carol.claim(HUB, &lock.id, &PREIMAGE).await,
        Err(Error::PaysNothing)
    ));
    assert_eq!(bob.claim(HUB, &lock.id, &PREIMAGE).await.unwrap().amount, 4);
}

/// The notes a settled lock issues, shown with their evidence cut short
/// or with a false proof of their denomination's key, are taken by
/// neither payee nor payer: nothing is kept, the lock stands as it was,
/// and asked again for the hub's true issuances each takes its own, as
/// on a lock never tampered with.
#[tokio::test]
async fn a_locks_issuances_with_missing_or_false_evidence_are_never_taken() {
    let changes: [Option<net::Tamper>; 3] =
        [None, Some(net::evidence_missing), Some(net::evidence_false)];
    for change in changes {
        let (net, alice, bob) = parties().await;
        let tamper = |path| {
            if let Some(change) = change {
                net.fail(path, Fault::Tampered(change));
            }
        };
        let paid = alice
            .lock(HUB, &bob.address(), 10, hash(), None)
            .await
            .unwrap();
        tamper(licash_api::SETTLE);
        let claimed = bob.claim(HUB, &paid.id, &PREIMAGE).await;
        if change.is_some() {
            assert!(
                matches!(claimed, Err(Error::Unavailable { .. })),
                "{claimed:?}"
            );
            assert_eq!(bob.receipts().unwrap(), []);
            assert_eq!(bob.notes().unwrap(), []);
            assert_eq!(
                bob.claim(HUB, &paid.id, &PREIMAGE).await.unwrap().amount,
                10
            );
        } else {
            assert_eq!(claimed.unwrap().amount, 10);
        }
        assert_eq!(available(&bob), (10, 0));
        // Her change, of the same issuances.
        tamper(licash_api::SETTLE);
        let followed = alice.follow_lock(&paid.id).await;
        if change.is_some() {
            assert!(
                matches!(&followed, Err(Error::Pending { reason, .. }) if reason.contains("unavailable")),
                "{followed:?}"
            );
            assert_eq!(alice.locks().unwrap()[0].state, LockState::Locked);
            assert_eq!(available(&alice), (0, 64));
        }
        let followed = alice.follow_lock(&paid.id).await.unwrap();
        assert_eq!(followed.state, LockState::Paid(PREIMAGE));
        assert_eq!(available(&alice), (52, 0));

        // A refund, of a lock never paid.
        let refunded = alice
            .lock(HUB, &bob.address(), 10, hash(), Some(8))
            .await
            .unwrap();
        net.mine(HUB, 6, None);
        tamper(licash_api::REFUND);
        let followed = alice.follow_lock(&refunded.id).await;
        if change.is_some() {
            assert!(
                matches!(&followed, Err(Error::Pending { reason, .. }) if reason.contains("unavailable")),
                "{followed:?}"
            );
            let lock = alice.locks().unwrap();
            let lock = lock.iter().find(|l| l.id == refunded.id).unwrap();
            assert_eq!(lock.state, LockState::Locked);
            assert_eq!(available(&alice), (20, 32));
        }
        let followed = alice.follow_lock(&refunded.id).await.unwrap();
        assert_eq!(followed.state, LockState::Refunded);
        assert_eq!(available(&alice), (50, 0));
    }
}

#[tokio::test]
async fn a_lock_its_hub_refuses_is_given_up() {
    let (net, alice, bob) = parties().await;
    net.fail(licash_api::LOCK, Fault::Refused(Code::Timing));
    let refused = alice.lock(HUB, &bob.address(), 10, hash(), None).await;
    assert!(
        matches!(&refused, Err(Error::Refused { problem, .. }) if problem.code == Code::Timing),
        "{refused:?}"
    );
    assert_eq!(available(&alice), (64, 0));
    let lock = &alice.locks().unwrap()[0];
    assert!(matches!(&lock.state, LockState::Abandoned(_)));
    assert!(matches!(
        alice.follow_lock(&lock.id).await,
        Err(Error::Abandoned { .. })
    ));
    // Out of the hub's window.
    let refused = alice.lock(HUB, &bob.address(), 10, hash(), Some(40)).await;
    assert!(matches!(refused, Err(Error::Invalid(_))), "{refused:?}");
}

#[tokio::test]
async fn a_lock_whose_answer_is_lost_is_taken_on_by_resume() {
    let (net, alice, bob) = parties().await;
    for fault in [Fault::Lost, Fault::Dropped] {
        net.fail(licash_api::LOCK, fault);
        let Err(Error::Pending { id, .. }) = alice.lock(HUB, &bob.address(), 4, hash(), None).await
        else {
            panic!("not pending");
        };
        assert_eq!(alice.locks().unwrap()[0].state, LockState::Requested);
        assert!(matches!(alice.abandon(&id), Err(Error::Invalid(_))));
        let resumed = alice.resume().await.unwrap();
        assert_eq!(resumed.locks.len(), 1);
        assert_eq!(
            (resumed.locks[0].id.as_str(), &resumed.locks[0].state),
            (id.as_str(), &LockState::Locked)
        );
        assert_eq!(bob.claim(HUB, &id, &PREIMAGE).await.unwrap().amount, 4);
        assert_eq!(
            alice.follow_lock(&id).await.unwrap().state,
            LockState::Paid(PREIMAGE)
        );
    }
    assert_eq!(available(&alice), (64 - 2 * (4 + 2), 0));
}

#[tokio::test]
async fn a_lock_to_its_hub_spends_exact_notes_and_pays_the_hub_only() {
    let (net, alice, _) = parties().await;
    let hub = alice.hubs().unwrap()[0].1.address;
    let lock = alice.lock(HUB, &hub, 10, hash(), None).await.unwrap();
    assert_eq!((lock.amount, lock.fee), (10, 0));
    // A payment to itself made the notes: 10, its fee of 2 and the change.
    assert_eq!(alice.sends().unwrap().len(), 1);
    assert_eq!(available(&alice), (52, 10));
    // The hub settles a lock paying it only whenever it learns the
    // preimage, past the lock's expiry too.
    net.mine(HUB, 30, None);
    let id = licash_api::lock_id(&lock.id).unwrap();
    net.hub(HUB).settle(&id, &PREIMAGE).unwrap();
    assert_eq!(
        alice.follow_lock(&lock.id).await.unwrap().state,
        LockState::Paid(PREIMAGE)
    );
    assert_eq!(available(&alice), (52, 0));
}

#[tokio::test]
async fn an_activation_on_bitcoin_pays_the_lock() {
    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(8))
        .await
        .unwrap();
    net.mine(HUB, 1, Some(PREIMAGE));
    net.mine(HUB, 10, None);
    assert_eq!(
        alice.follow_lock(&lock.id).await.unwrap().state,
        LockState::Paid(PREIMAGE)
    );
    assert_eq!(available(&alice), (52, 0));
    // Paid, the lock is claimed past its expiry too.
    assert_eq!(
        bob.claim(HUB, &lock.id, &PREIMAGE).await.unwrap().amount,
        10
    );
}

#[tokio::test]
async fn a_preimage_revealed_past_expiry_does_not_pay_the_lock() {
    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(8))
        .await
        .unwrap();
    net.mine(HUB, 6, None);
    net.mine(HUB, 1, Some(PREIMAGE));
    let id = licash_api::lock_id(&lock.id).unwrap();
    assert_eq!(net.hub(HUB).locked(&id).unwrap().preimage, Some(PREIMAGE));
    assert_eq!(
        alice.follow_lock(&lock.id).await.unwrap().state,
        LockState::Refunded
    );
    assert_eq!(available(&alice), (62, 0));
}

#[tokio::test]
async fn a_payee_sees_what_a_lock_pays_it_before_revealing_anything() {
    let (net, alice, bob) = parties().await;
    let lock = alice
        .lock(HUB, &bob.address(), 10, hash(), Some(12))
        .await
        .unwrap();
    let incoming = bob.incoming(HUB, &lock.id).await.unwrap();
    assert_eq!(
        (
            incoming.amount,
            incoming.hash,
            incoming.expiry,
            incoming.height
        ),
        (10, hash(), 12, 3)
    );
    assert_eq!((incoming.settled, incoming.preimage), (None, None));
    // It pays Alice her change, and Carol nothing.
    assert_eq!(alice.incoming(HUB, &lock.id).await.unwrap().amount, 52);
    let carol = party(&net, 3).await;
    assert!(matches!(
        carol.incoming(HUB, &lock.id).await,
        Err(Error::PaysNothing)
    ));
    assert!(matches!(
        bob.incoming(HUB, &"00".repeat(32)).await,
        Err(Error::Refused { problem, .. }) if problem.code == Code::UnknownLock
    ));

    bob.claim(HUB, &lock.id, &PREIMAGE).await.unwrap();
    net.mine(HUB, 1, None);
    let paid = bob.incoming(HUB, &lock.id).await.unwrap();
    assert_eq!(
        (paid.settled, paid.preimage, paid.height),
        (Some(licash_api::Settled::Pay), Some(PREIMAGE), 4)
    );
}

/// A lock its hub never answered for, its signed request kept: once
/// expired at depth, a recovery claims its refund on its own inputs, which
/// her claim's keys authorize, whether or not the hub ever admitted it.
/// Left out where the caller leaves such locks out.
#[tokio::test]
async fn a_recovery_claims_the_refund_of_a_lock_its_hub_never_certified() {
    let (net, alice, bob) = parties().await;
    net.fail(licash_api::LOCK, Fault::Lost);
    let Err(Error::Pending { id, .. }) = alice.lock(HUB, &bob.address(), 10, hash(), Some(8)).await
    else {
        panic!("not pending");
    };
    let keyset = *net.hub(HUB).info().keysets[0].id();
    let slot = |id: [u8; 32]| ClaimSlot {
        id,
        keyset,
        cap: 1_000,
        max: 32,
    };
    let (first, second) = ([7; 32], [8; 32]);
    // Short of its expiry at depth, or such locks left out: none.
    let (notes, refunds) = alice
        .claim_with_locks(&first, &[slot(first)], 8, None, true)
        .unwrap();
    assert!(notes.is_empty() && refunds.is_empty());
    let (notes, refunds) = alice
        .claim_with_locks(&first, &[slot(first)], 100, None, false)
        .unwrap();
    assert!(notes.is_empty() && refunds.is_empty());
    let (notes, refunds) = alice
        .claim_with_locks(&first, &[slot(first)], 100, None, true)
        .unwrap();
    assert!(notes.is_empty());
    assert_eq!(refunds.len(), 1);
    let refund = &refunds[0];
    assert_eq!(hex::encode(refund.id.as_bytes()), id);
    assert!(matches!(&refund.source, Source::OwnInputs { inputs, .. } if inputs.len() == 1));
    assert_eq!(refund.value, 62);
    // Its items' keys, and its input's.
    assert_eq!(refund.keys.len(), refund.items.len() + 1);
    let input = refund.source.inputs()[0];
    assert!(refund
        .keys
        .iter()
        .any(|(m, _)| m.identifier().unwrap() == input));
    let again = alice.claimed_locks(&first, &keyset).unwrap();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].id, refund.id);
    // Taken: no other recovery claims it, nor its input as a note.
    let (notes, none) = alice
        .claim_with_locks(&second, &[slot(second)], 100, None, true)
        .unwrap();
    assert!(notes.is_empty() && none.is_empty());
    // Given back: the lock is the wallet's to follow again.
    alice.unclaim_notes(&first).unwrap();
    assert!(alice.claimed_locks(&first, &keyset).unwrap().is_empty());
    assert_eq!(alice.locks().unwrap()[0].state, LockState::Requested);
}

/// A recovery's claim gives up the payments its hub was never asked to
/// sign, to claim their notes: a payment its hub could release is kept.
#[tokio::test]
async fn a_recovery_takes_the_notes_of_a_payment_its_hub_never_signed() {
    let (net, alice, bob) = parties().await;
    net.fail(licash_api::OFFER, Fault::Lost);
    let Err(Error::Pending { id, .. }) = alice.send(HUB, &bob.address(), 10).await else {
        panic!("not pending");
    };
    let keyset = *net.hub(HUB).info().keysets[0].id();
    let slot = ClaimSlot {
        id: [7; 32],
        keyset,
        cap: 1_000,
        max: 32,
    };
    let offered = alice.sends().unwrap();
    assert_eq!(offered[0].state, licash_wallet::State::Offered);
    let (notes, locks) = alice
        .claim_with_locks(&slot.id, &[slot], 100, None, true)
        .unwrap();
    assert!(locks.is_empty());
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].note.message().denomination(), 64);
    let send = alice.sends().unwrap();
    let send = send.iter().find(|s| s.id == id).unwrap();
    assert!(
        matches!(&send.state, licash_wallet::State::Abandoned(_)),
        "{:?}",
        send.state
    );
}

/// A lock its hub refused while serving it is given up, its notes freed,
/// until its hub shows the wallet's own lock spent them: then it is the
/// wallet's lock again, followed to its end, its notes not dropped.
#[tokio::test]
async fn a_lock_its_hub_refused_but_served_is_taken_on_again_once_shown() {
    let (net, alice, bob) = parties().await;
    net.fail(licash_api::LOCK, Fault::Belied(Code::Timing));
    let refused = alice.lock(HUB, &bob.address(), 10, hash(), None).await;
    assert!(
        matches!(&refused, Err(Error::Refused { .. })),
        "{refused:?}"
    );
    let id = alice.locks().unwrap()[0].id.clone();
    assert!(matches!(
        &alice.locks().unwrap()[0].state,
        LockState::Abandoned(_)
    ));
    assert_eq!(available(&alice), (64, 0));
    // Asked of its hub: spent by her own lock, which she takes on again.
    let checked = alice.check().await.unwrap();
    assert_eq!(checked.dropped, 0);
    assert_eq!(alice.locks().unwrap()[0].state, LockState::Requested);
    assert_eq!(available(&alice).0, 0);
    let resumed = alice.resume().await.unwrap();
    assert_eq!(resumed.locks.len(), 1);
    assert_eq!(resumed.locks[0].state, LockState::Locked);
    assert_eq!(bob.claim(HUB, &id, &PREIMAGE).await.unwrap().amount, 10);
    assert_eq!(
        alice.follow_lock(&id).await.unwrap().state,
        LockState::Paid(PREIMAGE)
    );
    assert_eq!(available(&alice), (52, 0));
}

/// A lock its hub refused as spending notes spent, while serving it: the
/// spend its hub shows is the lock itself, which is kept, not given up.
#[tokio::test]
async fn a_lock_its_hub_refused_as_spent_by_itself_is_kept() {
    let (net, alice, bob) = parties().await;
    net.fail(licash_api::LOCK, Fault::Belied(Code::Spent));
    let refused = alice.lock(HUB, &bob.address(), 10, hash(), None).await;
    assert!(
        matches!(&refused, Err(Error::Pending { .. })),
        "{refused:?}"
    );
    let id = alice.locks().unwrap()[0].id.clone();
    assert_eq!(alice.locks().unwrap()[0].state, LockState::Requested);
    assert_eq!(available(&alice).0, 0);
    let resumed = alice.resume().await.unwrap();
    assert_eq!(resumed.locks[0].state, LockState::Locked);
    assert_eq!(bob.claim(HUB, &id, &PREIMAGE).await.unwrap().amount, 10);
    assert_eq!(
        alice.follow_lock(&id).await.unwrap().state,
        LockState::Paid(PREIMAGE)
    );
    assert_eq!(available(&alice), (52, 0));
}

/// A lock its hub refused while serving it, its notes then spent again by
/// a payment its hub refuses as spent by the lock: the payment is given
/// up, and the notes are the lock's, not dropped.
#[tokio::test]
async fn a_payment_refused_as_spent_by_a_lock_given_up_hands_its_notes_to_it() {
    let (net, alice, bob) = parties().await;
    net.fail(licash_api::LOCK, Fault::Belied(Code::Timing));
    let refused = alice.lock(HUB, &bob.address(), 10, hash(), None).await;
    assert!(
        matches!(&refused, Err(Error::Refused { .. })),
        "{refused:?}"
    );
    let id = alice.locks().unwrap()[0].id.clone();
    assert_eq!(available(&alice), (64, 0));
    let sent = alice.send(HUB, &bob.address(), 5).await;
    assert!(matches!(&sent, Err(Error::Refused { .. })), "{sent:?}");
    assert_eq!(alice.locks().unwrap()[0].state, LockState::Requested);
    assert_eq!(available(&alice).0, 0);
    let inputs = alice.operation_notes(&id).unwrap().spent;
    assert_eq!(inputs.len(), 1);
    assert!(!inputs[0].gone, "{:?}", inputs[0]);
    let resumed = alice.resume().await.unwrap();
    assert_eq!(resumed.locks[0].state, LockState::Locked);
    assert_eq!(bob.claim(HUB, &id, &PREIMAGE).await.unwrap().amount, 10);
    assert_eq!(
        alice.follow_lock(&id).await.unwrap().state,
        LockState::Paid(PREIMAGE)
    );
    assert_eq!(available(&alice), (52, 0));
}

/// A payment signed whose release its hub never answered: a force close
/// claims its notes, its change named beside them should its hub show it
/// released, and takes no more of either for another recovery. Given
/// back, the payment is the wallet's again; finished while claimed, its
/// change stays the recovery's, its notes the payment's.
#[tokio::test]
async fn a_recovery_claims_a_signed_payment_its_hub_never_released() {
    let (net, alice, bob) = parties().await;
    net.fail(licash_api::RELEASE, Fault::Lost);
    let Err(Error::Pending { id, .. }) = alice.send(HUB, &bob.address(), 10).await else {
        panic!("not pending");
    };
    let state = |alice: &Wallet<Link>| {
        let sends = alice.sends().unwrap();
        sends.iter().find(|s| s.id == id).unwrap().state.clone()
    };
    assert_eq!(state(&alice), licash_wallet::State::Signed);
    let keyset = *net.hub(HUB).info().keysets[0].id();
    let slot = |id: [u8; 32]| ClaimSlot {
        id,
        keyset,
        cap: 1_000,
        max: 32,
    };
    let (first, second) = ([7; 32], [8; 32]);
    // Left out where the caller leaves such payments out.
    let (notes, locks) = alice
        .claim_with_locks(&first, &[slot(first)], 100, None, false)
        .unwrap();
    assert!(notes.is_empty() && locks.is_empty());
    let (notes, locks) = alice
        .claim_with_locks(&first, &[slot(first)], 100, None, true)
        .unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].note.message().denomination(), 64);
    assert_eq!(locks.len(), 1);
    let send = &locks[0];
    assert_eq!(hex::encode(send.id.as_bytes()), id);
    let input = notes[0].note.message().identifier().unwrap();
    assert!(matches!(&send.source, Source::Plain { inputs, .. } if *inputs == vec![input]));
    assert_eq!(send.value, 0);
    assert!(!send.items.is_empty() && send.keys.len() == send.items.len());
    assert!(send.items.iter().all(|i| matches!(
        i,
        Item::Pending { branch: Branch::Pay, preimage: None, source, .. } if *source == send.id
    )));
    // Read back as taken; no other recovery takes it.
    assert_eq!(alice.claimed_notes(&first, &keyset).unwrap().len(), 1);
    assert_eq!(alice.claimed_locks(&first, &keyset).unwrap().len(), 1);
    let (notes, none) = alice
        .claim_with_locks(&second, &[slot(second)], 100, None, true)
        .unwrap();
    assert!(notes.is_empty() && none.is_empty());

    // Given back: the payment's again, and finished.
    alice.unclaim_notes(&first).unwrap();
    assert!(alice.claimed_locks(&first, &keyset).unwrap().is_empty());
    assert_eq!(available(&alice).0, 0);
    assert_eq!(state(&alice), licash_wallet::State::Signed);
    let (notes, _) = alice
        .claim_with_locks(&first, &[slot(first)], 100, None, true)
        .unwrap();
    assert_eq!(notes.len(), 1);
    // Finished while claimed: its change the recovery's.
    alice.resume().await.unwrap();
    assert_eq!(state(&alice), licash_wallet::State::Done);
    assert_eq!(available(&alice).0, 0);
    let claimed = alice.claimed_notes(&first, &keyset).unwrap();
    assert_eq!(
        claimed
            .iter()
            .map(|n| n.note.message().denomination())
            .sum::<u64>(),
        52
    );
    assert!(alice.claimed_locks(&first, &keyset).unwrap().is_empty());
    // Given back: its change free, its notes spent.
    alice.unclaim_notes(&first).unwrap();
    assert_eq!(available(&alice), (52, 0));
}
