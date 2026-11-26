mod net;

use std::{path::Path, sync::Arc};

use licash::spend::ChainProfile;
use licash_api::{Code, Fee, Hex, Payment};
use licash_wallet::{Balance, Checked, Error, HubId, NoteRecord, PartTo, State, Unlinking, Wallet};
use net::{Fault, Link, Net, HUB};

const FEE: Fee = Fee { base: 2, ppm: 0 };
const OFFER: &str = licash_api::OFFER;
const RELEASE: &str = licash_api::RELEASE;
const UNLINK: &str = licash_api::UNLINK;

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

/// A wallet of the owner of `[seed; 32]` that added the hub at [`HUB`].
async fn party(net: &Arc<Net>, seed: u8) -> Party {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(
        &dir.path().join("w.sqlite"),
        &[seed; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(net.clone()),
    )
    .unwrap();
    wallet.add_hub(&format!("{HUB}/")).await.unwrap();
    Party { _dir: dir, wallet }
}

fn available(wallet: &Wallet<Link>) -> (u64, u64) {
    let balance = wallet.balance().unwrap();
    balance
        .iter()
        .fold((0, 0), |(a, p), b| (a + b.available, p + b.pending))
}

fn same(a: &Payment, b: &Payment) -> bool {
    serde_json::to_value(a).unwrap() == serde_json::to_value(b).unwrap()
}

fn network() -> Arc<Net> {
    let net = Net::new();
    net.start(HUB, FEE);
    net
}

#[tokio::test]
async fn a_payment_pays_its_payee_and_the_hub_its_fee() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    let received = alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    assert_eq!((received.amount, received.hub.as_str()), (100, HUB));
    assert_eq!(
        alice.balance().unwrap(),
        [Balance {
            hub: HUB.into(),
            available: 100,
            pending: 0
        }]
    );

    let paid = alice.send(HUB, &bob.address(), 30).await.unwrap();
    let payment = paid.payment;
    assert_eq!(payment.hub, HUB);
    let received = bob.receive(&payment).unwrap();
    assert_eq!(
        (received.id.as_str(), received.amount),
        (paid.id.as_str(), 30)
    );
    assert_eq!(bob.receipts().unwrap(), [received]);
    assert_eq!(available(&alice), (68, 0));
    assert_eq!(available(&bob), (30, 0));

    let sends = alice.sends().unwrap();
    assert_eq!(sends.len(), 1);
    let sent = &sends[0];
    assert_eq!(sent.id, paid.id);
    assert_eq!((sent.amount, sent.fee, &sent.state), (30, 2, &State::Done));
    assert_eq!(sent.payee, bob.address());
    assert!(same(&alice.payment(&sent.id).unwrap(), &payment));

    // Received once only, and by its payee only.
    assert!(matches!(bob.receive(&payment), Err(Error::AlreadyReceived)));
    let carol = party(&net, 3).await;
    assert!(matches!(carol.receive(&payment), Err(Error::PaysNothing)));
    let mut forged = payment.clone();
    forged.unlock = Hex(vec![7; 32]);
    assert!(matches!(carol.receive(&forged), Err(Error::Invalid(_))));

    // Bob pays on what he received, Alice on her change.
    let back = bob.send(HUB, &alice.address(), 28).await.unwrap();
    assert_eq!(alice.receive(&back.payment).unwrap().amount, 28);
    assert_eq!(available(&bob), (0, 0));
    let all = alice.send(HUB, &bob.address(), 94).await.unwrap();
    assert_eq!(bob.receive(&all.payment).unwrap().amount, 94);
    assert_eq!(available(&alice), (0, 0));
    assert_eq!(alice.receipts().unwrap().len(), 2);
}

#[tokio::test]
async fn the_notes_counted_are_those_spendable_by_denomination() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    assert_eq!(alice.notes().unwrap(), []);
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    alice.receive(&net.pay(HUB, &alice.address(), 4)).unwrap();
    let notes = |wallet: &Wallet<Link>| -> Vec<(u64, u64)> {
        let notes = wallet.notes().unwrap();
        assert!(notes.iter().all(|n| n.hub == HUB));
        notes.iter().map(|n| (n.denomination, n.count)).collect()
    };
    assert_eq!(notes(&alice), [(64, 1), (32, 1), (4, 2)]);

    // Notes held by a payment under way are not spendable.
    net.fail(RELEASE, Fault::Lost);
    assert!(matches!(
        alice.send(HUB, &bob.address(), 30).await,
        Err(Error::Pending { .. })
    ));
    let (available, pending) = available(&alice);
    let counted: u64 = notes(&alice).iter().map(|(d, c)| d * c).sum();
    assert_eq!((counted, pending), (available, 104 - available));
    assert!(pending > 0);
}

#[tokio::test]
async fn a_payment_cut_off_at_any_step_finishes_on_resume() {
    for (path, fault) in [
        (OFFER, Fault::Lost),
        (OFFER, Fault::Dropped),
        (RELEASE, Fault::Lost),
        (RELEASE, Fault::Dropped),
    ] {
        let net = network();
        let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
        alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
        net.fail(path, fault);
        let id = match alice.send(HUB, &bob.address(), 10).await {
            Err(Error::Pending { id, .. }) => id,
            other => panic!("{path} {fault:?}: {other:?}"),
        };
        assert_eq!(available(&alice), (0, 64), "{path} {fault:?}");
        let state = if path == OFFER {
            State::Offered
        } else {
            State::Signed
        };
        assert_eq!(alice.sends().unwrap()[0].state, state);

        let resumed = alice.resume().await.unwrap();
        assert_eq!(resumed.paid.len(), 1, "{path} {fault:?}: {resumed:?}");
        assert_eq!(resumed.paid[0].id, id);
        assert_eq!(bob.receive(&resumed.paid[0].payment).unwrap().amount, 10);
        assert_eq!(available(&alice), (52, 0));
        assert!(alice.resume().await.unwrap().paid.is_empty());
    }
}

/// As [`a_payment_cut_off_at_any_step_finishes_on_resume`], the hub
/// stopped and started again on its files between the step cut off and
/// her resumption: what it committed before it stopped holds, and the
/// payment is made once.
#[tokio::test]
async fn a_payment_cut_off_at_any_step_finishes_after_the_hub_restarts() {
    for (path, fault) in [
        (OFFER, Fault::Lost),
        (OFFER, Fault::Dropped),
        (RELEASE, Fault::Lost),
        (RELEASE, Fault::Dropped),
    ] {
        let net = network();
        let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
        alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
        net.fail(path, fault);
        let id = match alice.send(HUB, &bob.address(), 10).await {
            Err(Error::Pending { id, .. }) => id,
            other => panic!("{path} {fault:?}: {other:?}"),
        };
        net.restart(HUB);

        let resumed = alice.resume().await.unwrap();
        assert_eq!(resumed.paid.len(), 1, "{path} {fault:?}: {resumed:?}");
        assert_eq!(resumed.paid[0].id, id);
        assert_eq!(bob.receive(&resumed.paid[0].payment).unwrap().amount, 10);
        assert_eq!(available(&alice), (52, 0), "{path} {fault:?}");
        assert!(alice.resume().await.unwrap().paid.is_empty());
        // Bob's notes spend at the hub restarted, as any.
        let carol = party(&net, 3).await;
        let paid = bob.send(HUB, &carol.address(), 4).await.unwrap();
        assert_eq!(carol.receive(&paid.payment).unwrap().amount, 4);
    }
}

#[tokio::test]
async fn a_wallet_reopened_resumes_where_it_stopped() {
    let net = network();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.sqlite");
    let bob = party(&net, 2).await;
    {
        let alice = Wallet::create(
            &path,
            &[1; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        alice.add_hub(HUB).await.unwrap();
        alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
        net.fail(RELEASE, Fault::Dropped);
        assert!(matches!(
            alice.send(HUB, &bob.address(), 10).await,
            Err(Error::Pending { .. })
        ));
    }
    assert!(matches!(
        Wallet::create(
            &path,
            &[1; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone())
        ),
        Err(Error::Setup(_))
    ));
    let alice = Wallet::open(&path, Link(net.clone())).unwrap();
    let owner = licash::address::OwnerKeys::from_seed(&[1; 32]).unwrap();
    assert_eq!(alice.address(), owner.address());
    let resumed = alice.resume().await.unwrap();
    assert_eq!(bob.receive(&resumed.paid[0].payment).unwrap().amount, 10);
    assert_eq!(available(&alice), (52, 0));
    assert!(matches!(
        Wallet::open(Path::new("/nonexistent/w.sqlite"), Link(net)),
        Err(Error::Setup(_))
    ));
}

#[tokio::test]
async fn fees_changed_since_the_hub_was_added_are_learned_and_paid_once() {
    let net = network();
    *net.stale.lock().unwrap() = Some(Fee { base: 0, ppm: 0 });
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    *net.stale.lock().unwrap() = None;
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();

    let payment = alice.send(HUB, &bob.address(), 10).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 10);
    assert_eq!(available(&alice), (52, 0));
    let sends = alice.sends().unwrap();
    assert_eq!((sends[0].fee, &sends[0].state), (2, &State::Done));
    assert!(matches!(&sends[1].state, State::Abandoned(why) if why.contains("Fee")));
    assert_eq!(alice.hubs().unwrap()[0].1.fees.spend, FEE);
}

#[tokio::test]
async fn a_send_refused_as_spent_is_given_up_and_drops_the_spent_notes() {
    // Two copies of one wallet, as after restoring an old backup: what one
    // spends, the other learns from the hub. Each copy holds 64 they share
    // and the copy 32 of its own.
    let net = network();
    let bob = party(&net, 2).await;
    for signed in [false, true] {
        let seed = if signed { 4 } else { 1 };
        let (alice, copy) = (party(&net, seed).await, party(&net, seed).await);
        let funds = net.pay(HUB, &alice.address(), 64);
        alice.receive(&funds).unwrap();
        copy.receive(&funds).unwrap();
        copy.receive(&net.pay(HUB, &copy.address(), 32)).unwrap();

        if signed {
            // The hub spent an input otherwise, so it never releases this.
            net.fail(RELEASE, Fault::Lost);
            let Err(Error::Pending { id, .. }) = copy.send(HUB, &bob.address(), 10).await else {
                panic!("not pending");
            };
            assert!(matches!(copy.abandon(&id), Err(Error::Invalid(_))));
            alice.send(HUB, &bob.address(), 10).await.unwrap();
            let resumed = copy.resume().await.unwrap();
            assert_eq!((resumed.paid.len(), resumed.pending.len()), (0, 0));
            assert!(resumed.abandoned[0].1.contains("Spent"), "{resumed:?}");
            assert!(matches!(copy.payment(&id), Err(Error::Abandoned { .. })));
        } else {
            alice.send(HUB, &bob.address(), 10).await.unwrap();
            let refused = copy.send(HUB, &bob.address(), 10).await;
            assert!(
                matches!(&refused, Err(Error::Refused { problem, .. }) if problem.code == Code::Spent),
                "{refused:?}"
            );
        }
        assert!(matches!(
            copy.sends().unwrap()[0].state,
            State::Abandoned(_)
        ));
        // The shared note is dropped, not chosen again.
        assert_eq!(available(&copy), (32, 0));
        let paid = copy.send(HUB, &bob.address(), 10).await.unwrap();
        assert_eq!(bob.receive(&paid.payment).unwrap().amount, 10);
        assert_eq!(available(&copy), (20, 0));
        assert_eq!(copy.check().await.unwrap(), Checked::default());
    }
}

#[tokio::test]
async fn a_restored_copy_drops_the_notes_spent_since() {
    let net = network();
    let (alice, copy, bob) = (
        party(&net, 1).await,
        party(&net, 1).await,
        party(&net, 2).await,
    );
    let funds = net.pay(HUB, &alice.address(), 100);
    alice.receive(&funds).unwrap();
    copy.receive(&funds).unwrap();
    alice.send(HUB, &bob.address(), 60).await.unwrap();
    assert_eq!(available(&copy), (100, 0));
    // The hub proves the spend of the 64 note, and the change it paid
    // Alice comes back with it (the 60 paid to Bob no scan key of the copy
    // opens): the copy is what Alice is.
    let checked = copy.check().await.unwrap();
    assert_eq!(
        checked,
        Checked {
            dropped: 64,
            recovered: 2
        }
    );
    assert_eq!(available(&copy), (38, 0));
    assert_eq!(copy.check().await.unwrap(), Checked::default());
    assert_eq!(alice.check().await.unwrap(), Checked::default());
    assert_eq!(available(&alice), (38, 0));
    // A note dropped is not unlinked either: the two held and the two notes
    // of the change (1 and 1) are.
    assert_eq!(copy.unlink().await.unwrap(), 4);
}

#[tokio::test]
async fn a_hub_that_shows_no_proof_of_a_spend_drops_nothing() {
    let net = network();
    let (alice, copy, bob) = (
        party(&net, 1).await,
        party(&net, 1).await,
        party(&net, 2).await,
    );
    let funds = net.pay(HUB, &alice.address(), 100);
    alice.receive(&funds).unwrap();
    copy.receive(&funds).unwrap();
    alice.send(HUB, &bob.address(), 60).await.unwrap();
    // The hub knows the spend, and says nothing of it: the copy takes no
    // one's word, and keeps the notes it was asked to drop.
    net.fail(licash_api::INQUIRE, Fault::Hushed);
    assert_eq!(copy.check().await.unwrap(), Checked::default());
    assert_eq!(available(&copy), (100, 0));
    // Shown the spend, it drops what it proves.
    assert_eq!(copy.check().await.unwrap().dropped, 64);
}

#[tokio::test]
async fn a_signed_send_refused_otherwise_stays_pending_and_finishes() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    net.fail(RELEASE, Fault::Refused(Code::Invalid));
    let Err(Error::Pending { id, reason }) = alice.send(HUB, &bob.address(), 10).await else {
        panic!("not pending");
    };
    assert!(reason.contains("Invalid"), "{reason}");
    assert_eq!(alice.sends().unwrap()[0].state, State::Signed);
    assert_eq!(available(&alice), (0, 64));
    assert!(matches!(alice.payment(&id), Err(Error::Pending { .. })));
    let resumed = alice.resume().await.unwrap();
    assert_eq!(resumed.paid[0].id, id);
    assert_eq!(bob.receive(&resumed.paid[0].payment).unwrap().amount, 10);
    assert!(same(&alice.payment(&id).unwrap(), &resumed.paid[0].payment));
}

/// A hub that forgot a signed send's offer (it deletes those left
/// unreleased long) is offered it again and released it under the new
/// offer, once per attempt: forgotten twice, the send stays pending and
/// finishes later.
#[tokio::test]
async fn a_signed_send_whose_offer_its_hub_forgot_is_offered_again() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    net.fail(RELEASE, Fault::Refused(Code::UnknownOffer));
    let paid = alice.send(HUB, &bob.address(), 10).await.unwrap();
    assert_eq!(bob.receive(&paid.payment).unwrap().amount, 10);
    net.fail(RELEASE, Fault::Refused(Code::UnknownOffer));
    net.fail(RELEASE, Fault::Refused(Code::UnknownOffer));
    let Err(Error::Pending { id, reason }) = alice.send(HUB, &bob.address(), 10).await else {
        panic!("not pending");
    };
    assert!(reason.contains("UnknownOffer"), "{reason}");
    let sends = alice.sends().unwrap();
    let send = sends.iter().find(|s| s.id == id).unwrap();
    assert_eq!(send.state, State::Signed);
    let resumed = alice.resume().await.unwrap();
    assert_eq!(resumed.paid[0].id, id);
    assert_eq!(bob.receive(&resumed.paid[0].payment).unwrap().amount, 10);
}

#[tokio::test]
async fn an_unsigned_send_refused_is_given_up() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    net.fail(OFFER, Fault::Refused(Code::Invalid));
    let refused = alice.send(HUB, &bob.address(), 10).await;
    assert!(
        matches!(&refused, Err(Error::Refused { problem, .. }) if problem.code == Code::Invalid),
        "{refused:?}"
    );
    assert_eq!(available(&alice), (64, 0));
    let id = alice.sends().unwrap()[0].id.clone();
    assert!(matches!(alice.payment(&id), Err(Error::Abandoned { .. })));
    let resumed = alice.resume().await.unwrap();
    assert!(resumed.paid.is_empty() && resumed.abandoned.is_empty());
    assert!(matches!(
        alice.payment(&"00".repeat(32)),
        Err(Error::UnknownPayment(_))
    ));
}

#[tokio::test]
async fn an_owner_gives_up_an_unsigned_send_only() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    net.fail(OFFER, Fault::Lost);
    let Err(Error::Pending { id, .. }) = alice.send(HUB, &bob.address(), 10).await else {
        panic!("not pending");
    };
    alice.abandon(&id).unwrap();
    assert_eq!(available(&alice), (64, 0));
    assert!(alice.abandon(&id).is_err());
    assert!(alice.resume().await.unwrap().paid.is_empty());
    assert!(matches!(alice.payment(&id), Err(Error::Abandoned { .. })));
    alice.send(HUB, &bob.address(), 10).await.unwrap();
}

#[tokio::test]
async fn only_hubs_added_are_trusted() {
    const OTHER: &str = "http://other.test";
    let net = network();
    net.start(OTHER, FEE);
    let bob = party(&net, 2).await;
    let payment = net.pay(OTHER, &bob.address(), 8);
    assert!(matches!(bob.receive(&payment), Err(Error::UnknownHub(hub)) if hub == OTHER));
    bob.add_hub(OTHER).await.unwrap();
    assert_eq!(bob.receive(&payment).unwrap().amount, 8);
    assert_eq!(bob.hubs().unwrap().len(), 2);

    // Another URL claiming a hub's keysets is not that hub.
    net.alias("http://mirror.test", HUB);
    assert!(matches!(
        bob.add_hub("http://mirror.test").await,
        Err(Error::Invalid(_))
    ));
    assert_eq!(bob.hubs().unwrap().len(), 2);
    assert!(matches!(
        bob.send("http://mirror.test", &bob.address(), 1).await,
        Err(Error::UnknownHub(_))
    ));
    assert!(matches!(
        bob.add_hub("ftp://hub.test").await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        bob.add_hub("http://down.test").await,
        Err(Error::Unavailable { .. })
    ));
}

#[tokio::test]
async fn a_hub_proving_another_identity_or_none_is_refused() {
    const OTHER: &str = "http://other.test";
    let net = network();
    net.start(OTHER, FEE);
    let bob = party(&net, 2).await;
    let regtest = ChainProfile::Core30DefaultRegtest;
    assert_eq!(bob.hubs().unwrap()[0].1.proved(regtest), Ok(true));
    let proof = |url: &str| net.hub(url).advertise().unwrap().proof;
    let refused = |result: Result<_, Error>| {
        assert!(
            matches!(&result, Err(Error::Invalid(m)) if m.contains("proof")),
            "{result:?}"
        );
    };

    // A proof of another identity, whoever made it: not the hub's info,
    // neither added nor refreshing what is kept.
    let mut forged = proof(OTHER).unwrap();
    forged.0[0] ^= 1;
    *net.proof.lock().unwrap() = Some(Some(forged));
    refused(bob.add_hub(OTHER).await);
    refused(bob.add_hub(HUB).await);
    *net.proof.lock().unwrap() = Some(proof(OTHER));
    refused(bob.add_hub(HUB).await);
    assert_eq!(bob.hubs().unwrap().len(), 1);
    assert_eq!(bob.hubs().unwrap()[0].1.proof, proof(HUB));

    // None: its keysets are no one's, and it is not added. One added is
    // unavailable while it proves none, what it said before kept.
    *net.proof.lock().unwrap() = Some(None);
    let none = bob.add_hub(OTHER).await;
    assert!(
        matches!(&none, Err(Error::Invalid(m)) if m.contains("proves no identity")),
        "{none:?}"
    );
    let again = bob.add_hub(HUB).await;
    assert!(
        matches!(&again, Err(Error::Unavailable { reason, .. }) if reason.contains("no longer proves")),
        "{again:?}"
    );
    assert_eq!(bob.hubs().unwrap().len(), 1);
    assert_eq!(bob.hubs().unwrap()[0].1.proof, proof(HUB));
    *net.proof.lock().unwrap() = None;
    bob.add_hub(OTHER).await.unwrap();
    assert_eq!(bob.hubs().unwrap().len(), 2);
}

#[tokio::test]
async fn a_hub_added_stays_the_one_it_proved_it_is() {
    const OTHER: &str = "http://other.test";
    let net = network();
    net.start(OTHER, FEE);
    let bob = party(&net, 2).await;
    let added = HubId::of(&bob.hubs().unwrap()[0].1.address);
    let keysets = bob.hubs().unwrap()[0].1.keysets.clone();

    // Another hub answers at its URL, proving an identity of its own, with
    // keysets new to the wallet: not learned as the hub added, whether
    // what is under way asks or the owner adds it again.
    net.alias(HUB, OTHER);
    assert_ne!(HubId::of(&net.hub(HUB).advertise().unwrap().address), added);
    let unavailable = |result: Result<(), Error>| {
        assert!(
            matches!(&result, Err(Error::Unavailable { reason, .. }) if reason.contains("no longer proves")),
            "{result:?}"
        );
    };
    unavailable(
        bob.lock(HUB, &bob.address(), 1, [0; 32], None)
            .await
            .map(drop),
    );
    unavailable(bob.add_hub(HUB).await.map(drop));
    let kept = bob.hubs().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(HubId::of(&kept[0].1.address), added);
    assert_eq!(kept[0].1.keysets, keysets);

    // Nor are the notes it issues taken as that hub's.
    let payment = net.pay(HUB, &bob.address(), 8);
    assert!(bob.receive(&payment).is_err());
    assert_eq!(available(&bob), (0, 0));
}

#[tokio::test]
async fn a_hub_visited_proves_it_is_the_one_a_code_names_and_is_not_trusted() {
    const OTHER: &str = "http://other.test";
    let net = network();
    net.start(OTHER, FEE);
    let bob = party(&net, 2).await;
    let other = HubId::of(&net.hub(OTHER).advertise().unwrap().address);
    let added = HubId::of(&bob.hubs().unwrap()[0].1.address);
    fn refused<T: std::fmt::Debug>(result: Result<T, Error>, why: &str) {
        assert!(
            matches!(&result, Err(Error::Invalid(m)) if m.contains(why)),
            "{result:?}"
        );
    }

    // Not the hub the code names, or proving none: refused, nothing kept.
    refused(bob.visit(OTHER, added).await, "not the hub the code names");
    *net.proof.lock().unwrap() = Some(None);
    refused(bob.visit(OTHER, other).await, "proves no identity");
    *net.proof.lock().unwrap() = None;
    assert!(bob.visited().unwrap().is_empty());

    // Visited: known apart, its payments not taken, and in no code.
    let info = bob.visit(&format!("{OTHER}/"), other).await.unwrap();
    assert_eq!(HubId::of(&info.address), other);
    assert_eq!(bob.hubs().unwrap().len(), 1);
    assert_eq!(bob.visited().unwrap()[0].0, OTHER);
    let payment = net.pay(OTHER, &bob.address(), 8);
    assert!(matches!(bob.receive(&payment), Err(Error::UnknownHub(hub)) if hub == OTHER));
    assert_eq!(bob.balance().unwrap().len(), 1);
    let apart = Balance {
        hub: OTHER.into(),
        available: 0,
        pending: 0,
    };
    assert_eq!(bob.visited_balance().unwrap(), [apart]);
    let code = bob.payment_code(&[OTHER.into()]);
    assert!(matches!(code, Err(Error::UnknownHub(_))), "{code:?}");
    // Nor asked for what its proof does not cover.
    refused(bob.deposit(OTHER, 1_000).await, "only visited");
    refused(bob.invoice(OTHER, 1_000).await, "only visited");

    // Learned again only as the hub it proved it is: else unavailable,
    // what is under way there waiting for it to prove it again.
    *net.proof.lock().unwrap() = Some(None);
    let lock = bob.lock(OTHER, &bob.address(), 1, [0; 32], None).await;
    assert!(
        matches!(&lock, Err(Error::Unavailable { reason, .. }) if reason.contains("no longer proves")),
        "{lock:?}"
    );
    *net.proof.lock().unwrap() = None;
    assert_eq!(bob.visited().unwrap()[0].1.proof, info.proof);

    // A hub added stays trusted when visited; one visited, once added, is.
    bob.visit(HUB, added).await.unwrap();
    assert_eq!(bob.hubs().unwrap().len(), 1);
    bob.add_hub(OTHER).await.unwrap();
    assert!(bob.visited().unwrap().is_empty());
    assert_eq!(bob.receive(&payment).unwrap().amount, 8);
    assert_eq!(bob.balance().unwrap().len(), 2);
}

#[tokio::test]
async fn a_hub_visited_is_added_at_the_url_the_owner_gives() {
    const OTHER: &str = "http://other.test";
    const MIRROR: &str = "http://mirror.test";
    let net = network();
    net.start(OTHER, FEE);
    net.alias(MIRROR, OTHER);
    let bob = party(&net, 2).await;
    let other = HubId::of(&net.hub(OTHER).advertise().unwrap().address);
    bob.visit(OTHER, other).await.unwrap();

    // The same hub, proving it is, at another URL: reached there, trusted.
    bob.add_hub(MIRROR).await.unwrap();
    assert!(bob.visited().unwrap().is_empty());
    let hubs = bob.hubs().unwrap();
    assert_eq!(hubs.len(), 2);
    assert!(hubs
        .iter()
        .any(|(url, i)| url == MIRROR && HubId::of(&i.address) == other));
    let payment = net.pay(OTHER, &bob.address(), 8);
    assert_eq!(bob.receive(&payment).unwrap().amount, 8);
    let held = bob.balance().unwrap();
    assert!(
        held.iter().any(|b| b.hub == MIRROR && b.available == 8),
        "{held:?}"
    );
}

#[tokio::test]
async fn a_delayed_unlink_records_its_completion_time_not_its_receipt_time() {
    let net = charging(Fee { base: 0, ppm: 0 });
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    let db = rusqlite::Connection::open(alice._dir.path().join("w.sqlite")).unwrap();
    db.execute("UPDATE notes SET added_at = 1", []).unwrap();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert_eq!(alice.unlink().await.unwrap(), 1);
    let (received, unlinked): (i64, i64) = db
        .query_row("SELECT added_at, unlinked_at FROM notes", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(received, 1);
    assert!(unlinked >= before);
}

#[tokio::test]
async fn a_hub_over_plain_http_is_reached_over_https_once_it_answers_the_same_there() {
    const SECURE: &str = "https://hub.test";
    let net = network();
    let bob = party(&net, 2).await;
    bob.receive(&net.pay(HUB, &bob.address(), 8)).unwrap();
    net.alias(SECURE, HUB);
    // Asked over HTTPS once since opened: not again.
    bob.add_hub(HUB).await.unwrap();
    assert_eq!(bob.hubs().unwrap()[0].0, HUB);

    // Added over HTTPS: the same hub, its notes with it, reached there from
    // now on, and still known at the other URL.
    bob.add_hub(SECURE).await.unwrap();
    let hubs = bob.hubs().unwrap();
    assert_eq!((hubs.len(), hubs[0].0.as_str()), (1, SECURE));
    let balance = bob.balance().unwrap();
    assert_eq!((balance[0].hub.as_str(), balance[0].available), (SECURE, 8));
    bob.add_hub(HUB).await.unwrap();
    assert_eq!(bob.hubs().unwrap().len(), 1);

    // A wallet adding it over plain HTTP: reached over HTTPS at once.
    let alice = party(&net, 1).await;
    assert_eq!(alice.hubs().unwrap()[0].0, SECURE);
    let paid = bob.send(HUB, &alice.address(), 4).await.unwrap();
    assert_eq!(paid.payment.hub, SECURE);
    assert_eq!(alice.receive(&paid.payment).unwrap().amount, 4);
    // Never back to plain HTTP from HTTPS.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.sqlite");
    let network = ChainProfile::Core30DefaultRegtest;
    let carol = Wallet::create(&path, &[3; 32], network, Link(net.clone())).unwrap();
    carol.add_hub(SECURE).await.unwrap();
    assert!(matches!(carol.add_hub(HUB).await, Err(Error::Invalid(_))));
    // Another host's URL over HTTPS is not the hub.
    net.alias("https://mirror.test", HUB);
    let mirror = carol.add_hub("https://mirror.test").await;
    assert!(matches!(mirror, Err(Error::Invalid(_))), "{mirror:?}");
    assert_eq!(carol.hubs().unwrap().len(), 1);

    // Asked over HTTPS only, even at the other URL: another hub answering
    // over plain HTTP there is not taken for it.
    let keysets = bob.hubs().unwrap()[0].1.keysets.clone();
    net.start(HUB, FEE);
    bob.add_hub(HUB).await.unwrap();
    let hubs = bob.hubs().unwrap();
    assert_eq!(hubs.len(), 1);
    assert!(hubs[0].1.keysets == keysets);
}

#[tokio::test]
async fn a_hub_is_known_at_each_of_its_urls_the_one_reached_first() {
    const SECURE: &str = "https://hub.test";
    let net = network();
    let bob = party(&net, 2).await;
    assert_eq!(bob.hub_urls(HUB).unwrap(), [HUB]);
    net.alias(SECURE, HUB);
    bob.add_hub(SECURE).await.unwrap();
    for url in [HUB, SECURE, "https://hub.test/"] {
        assert_eq!(bob.hub_urls(url).unwrap(), [SECURE, HUB]);
    }
    assert!(bob.hub_urls("https://other.test").unwrap().is_empty());
    assert!(matches!(bob.hub_urls("hub.test"), Err(Error::Invalid(_))));
}

#[tokio::test]
async fn a_hub_over_plain_http_is_asked_over_https_again_once_its_wallet_is_opened_again() {
    let net = network();
    let bob = party(&net, 2).await;
    net.alias("https://hub.test", HUB);
    let path = bob._dir.path().join("w.sqlite");
    let again = Wallet::open_with_seed(&path, &[2; 32], Link(net.clone())).unwrap();
    assert_eq!(again.hubs().unwrap()[0].0, HUB);
    // Even unavailable over plain HTTP, as through Tor to a server only
    // redirecting to HTTPS.
    net.fail(licash_api::INFO, Fault::Lost);
    again.add_hub(HUB).await.unwrap();
    assert_eq!(again.hubs().unwrap()[0].0, "https://hub.test");
}

#[tokio::test]
async fn another_hub_over_https_is_neither_reached_nor_trusted_unasked() {
    let net = network();
    net.start("https://hub.test", FEE);
    let bob = party(&net, 2).await;
    let hubs = bob.hubs().unwrap();
    assert_eq!((hubs.len(), hubs[0].0.as_str()), (1, HUB));
}

#[tokio::test]
async fn a_payment_beyond_the_balance_is_refused_before_the_hub_hears_of_it() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 20)).unwrap();
    let short = alice.send(HUB, &bob.address(), 19).await;
    assert!(
        matches!(
            short,
            Err(Error::Insufficient {
                needed: 21,
                available: 20
            })
        ),
        "{short:?}"
    );
    assert!(matches!(
        alice.send(HUB, &bob.address(), 0).await,
        Err(Error::Invalid(_))
    ));
    assert!(alice.sends().unwrap().is_empty());
    assert_eq!(
        bob.send(HUB, &alice.address(), 1)
            .await
            .unwrap_err()
            .to_string(),
        "3 needed, 0 available in one payment"
    );
}

#[tokio::test]
async fn notes_unlink_and_stay_spendable() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();

    // An answer lost: the same request is asked again.
    net.fail(UNLINK, Fault::Dropped);
    assert!(matches!(
        alice.unlink().await,
        Err(Error::Unavailable { .. })
    ));
    assert_eq!(alice.unlink().await.unwrap(), 3);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert_eq!(available(&alice), (100, 0));

    let payment = alice.send(HUB, &bob.address(), 98).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 98);
    assert_eq!(available(&alice), (0, 0));
}

#[tokio::test]
async fn many_notes_unlink_none_asked_once_the_first_went_unanswered() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    // In more notes than are asked to unlink at once.
    alice.receive(&net.pay(HUB, &alice.address(), 255)).unwrap();
    net.fail(UNLINK, Fault::Lost);
    assert!(matches!(
        alice.unlink().await,
        Err(Error::Unavailable { .. })
    ));
    // Asked a few at once then, all of them.
    assert_eq!(alice.unlink().await.unwrap(), net::split(255).len());
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert_eq!(available(&alice), (255, 0));

    let payment = alice.send(HUB, &bob.address(), 250).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 250);
}

#[tokio::test]
async fn notes_a_restarted_hub_no_longer_unlinks_stay_linked_and_spendable() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 6)).unwrap();
    net.restart(HUB);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    let payment = alice.send(HUB, &bob.address(), 4).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 4);
}

/// The wallet's payments to itself: its renewals.
fn renewals(wallet: &Wallet<Link>) -> Vec<licash_wallet::Sent> {
    let me = wallet.address();
    let sends = wallet.sends().unwrap().into_iter();
    sends.filter(|s| s.payee == me).collect()
}

/// How the notes the operation `id` made stand.
fn made(wallet: &Wallet<Link>, id: &str) -> Vec<Unlinking> {
    let notes = wallet.operation_notes(id).unwrap().made;
    notes.iter().map(|n| n.unlinked).collect()
}

/// A network of one hub at [`HUB`] charging `fee`.
fn charging(fee: Fee) -> Arc<Net> {
    let net = Net::new();
    net.start(HUB, fee);
    net
}

#[tokio::test]
async fn notes_a_restarted_hub_no_longer_unlinks_are_renewed_once_and_unlinked() {
    let net = charging(Fee::default());
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    let got = alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.restart(HUB);
    let unlinked = alice.unlink().await.unwrap();
    let renewals = renewals(&alice);
    assert_eq!(renewals.len(), 1, "{renewals:?}");
    let renewal = &renewals[0];
    assert_eq!((renewal.amount, renewal.fee), (100, 0));
    assert_eq!(renewal.state, State::Done);
    let fresh = made(&alice, &renewal.id);
    assert_eq!(unlinked, fresh.len());
    assert!(fresh.iter().all(|u| *u == Unlinking::Unlinked), "{fresh:?}");
    let spent = alice.operation_notes(&got.id).unwrap().made;
    assert!(spent
        .iter()
        .all(|n| n.spent_by.as_ref() == Some(&renewal.id)));
    assert_eq!(available(&alice), (100, 0));
    // No payment to hand anyone, and nothing more to renew.
    assert!(alice.resume().await.unwrap().paid.is_empty());
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert_eq!(alice.sends().unwrap().len(), 1);
    let payment = alice.send(HUB, &bob.address(), 100).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 100);
}

#[tokio::test]
async fn a_renewal_pays_its_hub_within_the_limit_only() {
    // 5% of 100: 5, 50,000 parts per million.
    let net = charging(Fee {
        base: 0,
        ppm: 50_000,
    });
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.restart(HUB);
    assert_eq!(alice.renew_limit(), licash_wallet::RENEW_PPM);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    alice.set_renew_limit(49_999);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert!(renewals(&alice).is_empty());
    assert_eq!(available(&alice), (100, 0));
    alice.set_renew_limit(50_000);
    assert!(alice.unlink().await.unwrap() > 0);
    let renewals = renewals(&alice);
    assert_eq!(renewals.len(), 1, "{renewals:?}");
    assert_eq!((renewals[0].amount, renewals[0].fee), (95, 5));
    assert_eq!(available(&alice), (95, 0));
}

#[tokio::test]
async fn a_payment_pays_for_the_notes_it_makes_for_its_payee_and_as_change() {
    // 1, and a sat for each note made for others than the hub.
    let net = Net::new();
    net.start_per_note(HUB, Fee { base: 1, ppm: 0 }, 1_000);
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    assert_eq!(alice.hubs().unwrap()[0].1.fees.output_msat, 1_000);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();

    // 10 in two notes. A fee of 5 would leave 49, in three notes where it
    // pays for two: 6 leaves 48, in two.
    assert_eq!(alice.send_fee(HUB, 10).unwrap(), 6);
    let payment = alice.send(HUB, &bob.address(), 10).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 10);
    assert_eq!(available(&alice), (48, 0));
    assert_eq!(alice.sends().unwrap()[0].fee, 6);

    // All of it, in three notes, and no change to pay for.
    assert!(matches!(
        alice.send(HUB, &bob.address(), 45).await,
        Err(Error::Insufficient { needed: 50, .. })
    ));
    assert_eq!(alice.lacks(HUB, 45).unwrap(), 2);
    let payment = alice.send(HUB, &bob.address(), 44).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 44);
    assert_eq!(available(&alice), (0, 0));
    assert_eq!(alice.sends().unwrap()[0].fee, 4);
}

#[tokio::test]
async fn a_payment_consolidates_unlinked_extras_into_a_small_note_distribution() {
    let net = charging(Fee { base: 0, ppm: 0 });
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    for _ in 0..40 {
        alice.receive(&net.pay(HUB, &alice.address(), 1)).unwrap();
    }
    assert_eq!(alice.unlink().await.unwrap(), 41);
    let quote = alice.send_fee(HUB, 8).unwrap();
    let paid = alice.send(HUB, &bob.address(), 8).await.unwrap();
    assert_eq!(bob.receive(&paid.payment).unwrap().amount, 8);
    assert_eq!(alice.sends().unwrap()[0].fee, quote);
    assert_eq!(available(&alice), (96, 0));
    let held = alice.notes().unwrap();
    let count: u64 = held.iter().map(|n| n.count).sum();
    assert!((18..=24).contains(&count), "{held:?}");
    assert!(held.iter().all(|n| n.denomination <= 8), "{held:?}");
    let operation = alice.operation_notes(&paid.id).unwrap();
    assert!(operation.spent.len() > 1);
    assert!(operation.spent.len() <= licash_wallet::MAX_INPUTS);
    assert!(operation
        .spent
        .iter()
        .all(|n| n.unlinked == Unlinking::Unlinked));
    assert_eq!(
        operation.made.iter().map(|n| n.amount).sum::<u64>() + 8 + quote,
        operation.spent.iter().map(|n| n.amount).sum::<u64>()
    );
}

#[tokio::test]
async fn a_shaped_payment_quotes_its_actual_output_fee_and_preserves_value() {
    let net = Net::new();
    net.start_per_note(HUB, Fee { base: 1, ppm: 100 }, 100);
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    let quote = alice.send_fee(HUB, 10).unwrap();
    let paid = alice.send(HUB, &bob.address(), 10).await.unwrap();
    assert_eq!(bob.receive(&paid.payment).unwrap().amount, 10);
    let operation = alice.operation_notes(&paid.id).unwrap();
    assert!((18..=24).contains(&operation.made.len()));
    assert_eq!(alice.sends().unwrap()[0].fee, quote);
    assert_eq!(available(&alice).0 + 10 + quote, 64);
    let fee = alice.hubs().unwrap()[0].1.fees.spending();
    assert!(quote >= fee.due(64, 10u64.count_ones() as usize + operation.made.len()));
}

/// Simulate a completed privacy rest without sleeping or changing receipt
/// timestamps. The wallet's migration and unlink-clock tests cover how
/// these durable timestamps are written.
fn rested_notes(party: &Party) {
    rusqlite::Connection::open(party._dir.path().join("w.sqlite"))
        .unwrap()
        .execute("UPDATE notes SET unlinked_at = 1 WHERE unlinked = 1", [])
        .unwrap();
}

#[tokio::test]
async fn automatic_note_maintenance_waits_after_unlinking_and_records_its_fee() {
    let net = charging(Fee { base: 1, ppm: 0 });
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 128)).unwrap();
    assert_eq!(alice.unlink().await.unwrap(), 2);
    assert_eq!(alice.maintain_notes().await.unwrap(), 0);
    assert!(alice.sends().unwrap().is_empty());
    rested_notes(&alice);
    assert_eq!(alice.maintain_notes().await.unwrap(), 1);
    let sends = alice.sends().unwrap();
    assert_eq!(sends.len(), 1);
    assert_eq!((sends[0].amount, sends[0].fee), (0, 1));
    assert_eq!(sends[0].payee, alice.address());
    assert_eq!(sends[0].state, State::Done);
    assert_eq!(available(&alice), (127, 0));
    assert_eq!(alice.maintain_notes().await.unwrap(), 0);
}

#[tokio::test]
async fn note_work_is_reported_while_resting_and_not_once_healthy_or_unaffordable() {
    let net = charging(Fee { base: 1, ppm: 0 });
    let alice = party(&net, 1).await;
    assert!(!alice.note_maintenance_needed().unwrap());
    alice.receive(&net.pay(HUB, &alice.address(), 128)).unwrap();
    // Linked notes: the next round unlinks them.
    assert!(alice.note_maintenance_needed().unwrap());
    alice.unlink().await.unwrap();
    // Resting: nothing now, but a later round reshapes them.
    assert_eq!(alice.maintain_notes().await.unwrap(), 0);
    assert!(alice.note_maintenance_needed().unwrap());
    rested_notes(&alice);
    assert_eq!(alice.maintain_notes().await.unwrap(), 1);
    assert!(!alice.note_maintenance_needed().unwrap());
    assert!(alice.sends().unwrap().len() == 1);

    // Free-only authority: a paid remint is never a reason to keep a
    // background job alive.
    let bob = party(&net, 2).await;
    bob.set_renew_limit(0);
    bob.receive(&net.pay(HUB, &bob.address(), 128)).unwrap();
    bob.unlink().await.unwrap();
    assert!(!bob.note_maintenance_needed().unwrap());
    assert!(bob.sends().unwrap().is_empty());
}

#[tokio::test]
async fn expired_notes_are_note_work_only_while_their_renewal_is_affordable() {
    let net = charging(Fee { base: 1, ppm: 0 });
    let alice = party(&net, 1).await;
    alice.set_renew_limit(0);
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.restart(HUB);
    let _ = alice.unlink().await;
    assert!(alice.sends().unwrap().is_empty());
    assert!(!alice.note_maintenance_needed().unwrap());
    alice.set_renew_limit(1_000);
    assert!(alice.note_maintenance_needed().unwrap());
    // Reading it started nothing.
    assert!(alice.sends().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_or_future_unlink_times_never_start_automatic_optimization() {
    let net = charging(Fee { base: 1, ppm: 0 });
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 128)).unwrap();
    alice.unlink().await.unwrap();
    let db = rusqlite::Connection::open(alice._dir.path().join("w.sqlite")).unwrap();
    db.execute("UPDATE notes SET unlinked_at = NULL", [])
        .unwrap();
    assert_eq!(alice.maintain_notes().await.unwrap(), 0);
    let observed: i64 = db
        .query_row("SELECT unlinked_at FROM notes", [], |r| r.get(0))
        .unwrap();
    assert!(observed > 1);
    assert!(alice.sends().unwrap().is_empty());
    db.execute("UPDATE notes SET unlinked_at = ?1", [observed + 86_400])
        .unwrap();
    assert_eq!(alice.maintain_notes().await.unwrap(), 0);
    assert!(alice.sends().unwrap().is_empty());
}

#[tokio::test]
async fn automatic_optimization_obeys_the_rolling_budget_but_explicit_optimization_can_bypass_it() {
    let net = charging(Fee { base: 1, ppm: 0 });
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 128)).unwrap();
    alice.unlink().await.unwrap();
    let first = alice.optimize_notes(HUB, 1).await.unwrap().unwrap();
    for _ in 0..9 {
        alice.receive(&net.pay(HUB, &alice.address(), 1)).unwrap();
    }
    alice.unlink().await.unwrap();
    rested_notes(&alice);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let db = rusqlite::Connection::open(alice._dir.path().join("w.sqlite")).unwrap();
    // A real paid optimization from seven hours ago: its cooldown is
    // over, but its fee remains in the rolling daily budget.
    db.execute(
        "UPDATE sends SET created_at = ?1, done_at = ?1 WHERE id = ?2",
        rusqlite::params![now - 7 * 3_600, hex::decode(&first.id).unwrap()],
    )
    .unwrap();
    let quote = alice.optimization_quote(HUB).unwrap().unwrap();
    assert_eq!(quote.fee, 1);
    assert_eq!(available(&alice), (136, 0));
    assert_eq!(alice.maintain_notes().await.unwrap(), 0);
    assert_eq!(alice.sends().unwrap().len(), 1);
    assert!(alice.optimize_notes(HUB, 1).await.unwrap().is_some());
    assert_eq!(alice.sends().unwrap().len(), 2);
    assert_eq!(available(&alice), (135, 0));
    // Long-pending work is charged to its completion day, not merely
    // the day it was first recorded.
    db.execute(
        "UPDATE sends SET created_at = ?1, done_at = ?2 WHERE amount = 0",
        rusqlite::params![now - 2 * 86_400, now - 7 * 3_600],
    )
    .unwrap();
    for _ in 0..9 {
        alice.receive(&net.pay(HUB, &alice.address(), 1)).unwrap();
    }
    alice.unlink().await.unwrap();
    rested_notes(&alice);
    assert_eq!(alice.maintain_notes().await.unwrap(), 0);
    assert_eq!(alice.sends().unwrap().len(), 2);
    db.execute(
        "UPDATE sends SET done_at = ?1 WHERE amount = 0",
        [now - 2 * 86_400],
    )
    .unwrap();
    assert_eq!(alice.maintain_notes().await.unwrap(), 1);
    assert_eq!(alice.sends().unwrap().len(), 3);
    assert_eq!(available(&alice), (143, 0));
}

#[tokio::test]
async fn explicit_optimization_honors_its_quote_cap_and_contract_ceilings() {
    let net = charging(Fee { base: 1, ppm: 0 });
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 128)).unwrap();
    alice.unlink().await.unwrap();
    // Explicit optimization may bypass the privacy rest, but never the
    // quoted fee cap or a contract's fee agreement.
    let quote = alice.optimization_quote(HUB).unwrap().unwrap();
    assert_eq!(quote.fee, 1);
    assert!(matches!(
        alice.optimize_notes(HUB, 0).await,
        Err(Error::Invalid(_))
    ));
    assert!(alice.sends().unwrap().is_empty());
    alice
        .set_fee_ceilings(HUB, Some(licash_api::Fees::default()))
        .unwrap();
    assert!(matches!(
        alice.optimize_notes(HUB, 1).await,
        Err(Error::FeesRaised { .. })
    ));
    assert!(alice.sends().unwrap().is_empty());
    alice.set_fee_ceilings(HUB, None).unwrap();
    let optimized = alice.optimize_notes(HUB, quote.fee).await.unwrap().unwrap();
    assert_eq!(optimized.quote, quote);
    let operation = alice.operation_notes(&optimized.id).unwrap();
    assert_eq!(operation.made.len(), quote.notes_after);
    assert_eq!(available(&alice), (127, 0));
    assert!(alice.resume().await.unwrap().paid.is_empty());
}

#[tokio::test]
async fn a_pending_optimization_blocks_another_connection_and_resumes_without_handover() {
    let net = charging(Fee { base: 0, ppm: 0 });
    let alice = party(&net, 1).await;
    for _ in 0..100 {
        alice.receive(&net.pay(HUB, &alice.address(), 1)).unwrap();
    }
    alice.unlink().await.unwrap();
    rested_notes(&alice);
    net.fail(OFFER, Fault::Lost);
    let pending = alice.maintain_notes().await;
    assert!(
        matches!(&pending, Err(Error::Pending { .. })),
        "{pending:?}"
    );
    let id = alice.sends().unwrap()[0].id.clone();
    // The first attempt takes at most 64 inputs: enough disjoint notes
    // remain for a second process to remint unless the hub-wide guard
    // prevents it.
    let other = Wallet::open(&alice._dir.path().join("w.sqlite"), Link(net.clone())).unwrap();
    assert!(available(&other).0 > 0);
    assert_eq!(other.maintain_notes().await.unwrap(), 0);
    assert_eq!(other.sends().unwrap().len(), 1);
    let resumed = other.resume().await.unwrap();
    assert!(resumed.paid.is_empty());
    assert!(resumed.pending.is_empty());
    assert_eq!(other.sends().unwrap()[0].id, id);
    assert_eq!(other.sends().unwrap()[0].state, State::Done);
    assert_eq!(other.maintain_notes().await.unwrap(), 0);
    assert_eq!(other.sends().unwrap().len(), 1);
}

#[tokio::test]
async fn automatic_optimization_never_retries_a_fee_increase_or_bypasses_free_only() {
    let net = charging(Fee { base: 1, ppm: 0 });
    *net.stale.lock().unwrap() = Some(Fee { base: 0, ppm: 0 });
    let alice = party(&net, 1).await;
    *net.stale.lock().unwrap() = None;
    alice.receive(&net.pay(HUB, &alice.address(), 128)).unwrap();
    alice.unlink().await.unwrap();
    rested_notes(&alice);
    let refused = alice.maintain_notes().await;
    assert!(
        matches!(&refused, Err(Error::Refused { problem, .. }) if problem.code == Code::Fee),
        "{refused:?}"
    );
    assert_eq!(alice.sends().unwrap().len(), 1);
    assert!(matches!(
        alice.sends().unwrap()[0].state,
        State::Abandoned(_)
    ));
    assert_eq!(available(&alice), (128, 0));
    let db = rusqlite::Connection::open(alice._dir.path().join("w.sqlite")).unwrap();
    db.execute(
        "UPDATE sends SET created_at = 1, done_at = NULL WHERE amount = 0",
        [],
    )
    .unwrap();
    assert_eq!(alice.maintain_notes().await.unwrap(), 0);
    assert_eq!(alice.sends().unwrap().len(), 1);
    let observed: i64 = db
        .query_row("SELECT done_at FROM sends WHERE amount = 0", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(observed > 1, "an unknown refusal clock starts a new rest");

    let bob = party(&net, 2).await;
    bob.receive(&net.pay(HUB, &bob.address(), 128)).unwrap();
    bob.unlink().await.unwrap();
    rested_notes(&bob);
    bob.set_renew_limit(0);
    assert_eq!(bob.maintain_notes().await.unwrap(), 0);
    assert!(bob.sends().unwrap().is_empty());
}

#[tokio::test]
async fn a_renewal_counts_the_notes_it_makes_in_its_fee_and_its_limit() {
    // A sat for each note: 100 renewed is 97 in three notes, and 3.
    let net = Net::new();
    net.start_per_note(HUB, Fee::default(), 1_000);
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.restart(HUB);
    alice.set_renew_limit(29_999);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert!(renewals(&alice).is_empty());
    alice.set_renew_limit(30_000);
    assert!(alice.unlink().await.unwrap() > 0);
    let renewals = renewals(&alice);
    assert_eq!(renewals.len(), 1, "{renewals:?}");
    assert_eq!((renewals[0].amount, renewals[0].fee), (97, 3));
    assert_eq!(available(&alice), (97, 0));
}

#[tokio::test]
async fn a_hub_charging_more_than_agreed_is_not_paid_until_its_fees_are_approved() {
    let fee = Fee { base: 1, ppm: 0 };
    let net = charging(fee);
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    assert_eq!(alice.fee_ceilings(HUB).unwrap(), None);
    assert!(matches!(
        alice.set_fee_ceilings("http://other.test", None),
        Err(Error::UnknownHub(_))
    ));

    // Agreed to less than it charges, in one fee of them: nothing is paid
    // there, though what it would cost is still told.
    let charged = alice.hubs().unwrap()[0].1.fees;
    let agreed = licash_api::Fees {
        spend: Fee::default(),
        ..charged
    };
    alice.set_fee_ceilings(HUB, Some(agreed)).unwrap();
    assert_eq!(alice.fee_ceilings(HUB).unwrap(), Some(agreed));
    assert!(matches!(
        alice.send(HUB, &bob.address(), 10).await,
        Err(Error::FeesRaised { hub }) if hub == HUB
    ));
    assert_eq!(alice.send_fee(HUB, 10).unwrap(), 1);
    assert_eq!(available(&alice), (100, 0));
    assert!(alice.sends().unwrap().is_empty());
    // Nor are its notes renewed, whatever the limit.
    net.restart(HUB);
    alice.set_renew_limit(1_000_000);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert!(renewals(&alice).is_empty());

    // Approved, it is paid, and its notes renewed whatever the limit.
    alice.set_fee_ceilings(HUB, Some(charged)).unwrap();
    alice.set_renew_limit(0);
    assert!(alice.unlink().await.unwrap() > 0);
    assert_eq!(available(&alice), (99, 0));
    let payment = alice.send(HUB, &bob.address(), 10).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 10);

    // Lifted, the limit is back.
    alice.set_fee_ceilings(HUB, None).unwrap();
    assert_eq!(alice.fee_ceilings(HUB).unwrap(), None);
}

#[tokio::test]
async fn a_renewal_refused_for_fees_changed_asks_them_again_once() {
    let net = charging(Fee {
        base: 0,
        ppm: 50_000,
    });
    *net.stale.lock().unwrap() = Some(Fee::default());
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.restart(HUB);
    *net.stale.lock().unwrap() = None;
    alice.set_renew_limit(50_000);
    assert!(alice.unlink().await.unwrap() > 0);
    let renewals = renewals(&alice);
    let states: Vec<_> = renewals.iter().map(|s| (&s.state, s.fee)).collect();
    assert!(
        matches!(states[..], [(State::Done, 5), (State::Abandoned(_), 0)]),
        "{states:?}"
    );
    assert_eq!(available(&alice), (95, 0));
}

#[tokio::test]
async fn a_renewal_whose_hub_restarted_meanwhile_stays_linked_and_is_not_renewed_again() {
    let net = charging(Fee::default());
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.restart(HUB);
    // Released, but its answer lost: under way, its notes taken.
    net.fail(RELEASE, Fault::Dropped);
    assert!(matches!(alice.unlink().await, Err(Error::Pending { .. })));
    assert_eq!(available(&alice), (0, 100));
    net.restart(HUB);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    let renewals = renewals(&alice);
    assert_eq!(renewals.len(), 1, "{renewals:?}");
    let fresh = made(&alice, &renewals[0].id);
    assert!(
        fresh.iter().all(|u| *u == Unlinking::StaysLinked),
        "{fresh:?}"
    );
    let payment = alice.send(HUB, &bob.address(), 100).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 100);
}

#[tokio::test]
async fn a_renewal_its_hub_never_heard_of_is_finished_by_unlink_not_resume() {
    let net = charging(Fee::default());
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.restart(HUB);
    net.fail(OFFER, Fault::Lost);
    assert!(matches!(alice.unlink().await, Err(Error::Pending { .. })));
    let resumed = alice.resume().await.unwrap();
    assert!(resumed.paid.is_empty() && resumed.pending.is_empty());
    assert_eq!(renewals(&alice)[0].state, State::Offered);
    assert!(alice.unlink().await.unwrap() > 0);
    let renewals = renewals(&alice);
    assert_eq!(renewals.len(), 1, "{renewals:?}");
    assert_eq!(renewals[0].state, State::Done);
    assert_eq!(available(&alice), (100, 0));
}

#[tokio::test]
async fn a_renewal_given_up_by_its_owner_is_not_made_again() {
    let net = charging(Fee::default());
    let alice = party(&net, 1).await;
    let got = alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.restart(HUB);
    net.fail(OFFER, Fault::Lost);
    assert!(alice.unlink().await.is_err());
    alice.abandon(&renewals(&alice)[0].id).unwrap();
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert_eq!(alice.sends().unwrap().len(), 1);
    let held = made(&alice, &got.id);
    assert!(
        held.iter().all(|u| *u == Unlinking::StaysLinked),
        "{held:?}"
    );
    assert_eq!(available(&alice), (100, 0));
}

#[tokio::test]
async fn notes_that_stay_linked_for_no_reason_recorded_are_never_renewed() {
    let net = charging(Fee::default());
    let alice = party(&net, 1).await;
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.restart(HUB);
    // Linked for good as a file of an older version holds them, which
    // recorded no reason.
    net.fail(UNLINK, Fault::Refused(Code::Invalid));
    net.fail(UNLINK, Fault::Refused(Code::Invalid));
    net.fail(UNLINK, Fault::Refused(Code::Invalid));
    assert_eq!(alice.unlink().await.unwrap(), 0);
    let db = rusqlite::Connection::open(alice._dir.path().join("w.sqlite")).unwrap();
    db.execute("UPDATE notes SET stays_linked = NULL", [])
        .unwrap();
    assert_eq!(alice.unlink().await.unwrap(), 0);
    assert!(renewals(&alice).is_empty());
}

#[tokio::test]
async fn an_unavailable_hub_leaves_the_other_hubs_notes_unlinked() {
    const OTHER: &str = "http://other.test";
    let net = network();
    net.start(OTHER, FEE);
    let alice = party(&net, 1).await;
    alice.add_hub(OTHER).await.unwrap();
    let here = alice.receive(&net.pay(HUB, &alice.address(), 8)).unwrap();
    let there = alice.receive(&net.pay(OTHER, &alice.address(), 8)).unwrap();
    // The first hub asked, HUB, does not answer.
    net.fail(UNLINK, Fault::Lost);
    assert!(matches!(
        alice.unlink().await,
        Err(Error::Unavailable { .. })
    ));
    assert_eq!(made(&alice, &here.id), [Unlinking::Linked]);
    assert_eq!(made(&alice, &there.id), [Unlinking::Unlinked]);
    assert_eq!(alice.unlink().await.unwrap(), 1);
}

#[tokio::test]
async fn a_note_its_hub_refuses_to_unlink_stays_linked_and_spendable() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    net.fail(UNLINK, Fault::Refused(Code::Invalid));
    assert_eq!(alice.unlink().await.unwrap(), 2);
    assert_eq!(alice.unlink().await.unwrap(), 0);
    let payment = alice.send(HUB, &bob.address(), 98).await.unwrap().payment;
    assert_eq!(bob.receive(&payment).unwrap().amount, 98);
}

#[tokio::test]
async fn an_operations_parts_show_whom_its_notes_paid_and_what_it_kept() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    let got = alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    // A receipt spends none of the wallet's notes: it pays nothing.
    assert!(alice.operation_parts(&got.id).unwrap().is_empty());

    let sent = alice.send(HUB, &bob.address(), 50).await.unwrap();
    let parts = alice.operation_parts(&sent.id).unwrap();
    let to: Vec<_> = parts.iter().map(|p| (&p.to, p.amount)).collect();
    let notes = alice.operation_notes(&sent.id).unwrap();
    let spent: u64 = notes.spent.iter().map(|n| n.amount).sum();
    assert_eq!(
        to,
        [
            (&PartTo::Payee(bob.address()), 50),
            (&PartTo::Hub, 2),
            (&PartTo::Kept, spent - 52)
        ],
        "{parts:?}"
    );
    for part in &parts {
        assert_eq!(part.notes.iter().sum::<u64>(), part.amount, "{part:?}");
        assert!(part.notes.windows(2).all(|w| w[0] >= w[1]), "{part:?}");
    }
    // What it kept is the change made the wallet's, note for note.
    let made: Vec<u64> = notes.made.iter().map(|n| n.amount).collect();
    assert_eq!(parts[2].notes, made);
    // Bob was paid in the notes made for him.
    let received = bob.receive(&sent.payment).unwrap();
    let his: Vec<u64> = bob
        .operation_notes(&received.id)
        .unwrap()
        .made
        .iter()
        .map(|n| n.amount)
        .collect();
    assert_eq!(parts[0].notes, his);

    // None of the wallet's: nothing.
    assert!(alice.operation_parts(&"00".repeat(32)).unwrap().is_empty());
    assert!(matches!(
        alice.operation_parts("zz"),
        Err(Error::Invalid(_))
    ));
}

#[tokio::test]
async fn an_operations_notes_show_what_it_spent_and_made_and_which_are_unlinked() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    let got = alice.receive(&net.pay(HUB, &alice.address(), 100)).unwrap();
    let paid = alice.operation_notes(&got.id).unwrap();
    assert!(paid.spent.is_empty(), "{paid:?}");
    assert_eq!(paid.made.iter().map(|n| n.amount).sum::<u64>(), 100);
    assert!(paid.made.windows(2).all(|w| w[0].amount >= w[1].amount));
    for note in &paid.made {
        assert_eq!((note.unlinked, note.hub.as_str()), (Unlinking::Linked, HUB));
        assert_eq!(
            (&note.made_by, &note.spent_by, note.gone),
            (&got.id, &None, false)
        );
    }
    assert_eq!(alice.unlink().await.unwrap(), paid.made.len());
    let unlinked = alice.operation_notes(&got.id).unwrap().made;
    assert!(unlinked.iter().all(|n| n.unlinked == Unlinking::Unlinked));
    // Unlinking keeps each note's identifier.
    let ids = |notes: &[NoteRecord]| notes.iter().map(|n| n.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&unlinked), ids(&paid.made));

    // A payment spends them, its change made the wallet's.
    let sent = alice.send(HUB, &bob.address(), 50).await.unwrap();
    let fee = alice.sends().unwrap()[0].fee;
    let notes = alice.operation_notes(&sent.id).unwrap();
    let spent: u64 = notes.spent.iter().map(|n| n.amount).sum();
    let change: u64 = notes.made.iter().map(|n| n.amount).sum();
    assert_eq!(spent, 50 + fee + change, "{notes:?}");
    assert!(notes
        .spent
        .iter()
        .all(|n| n.spent_by.as_ref() == Some(&sent.id)));
    assert!(notes
        .made
        .iter()
        .all(|n| n.made_by == sent.id && n.spent_by.is_none()));
    let spent_now = alice.operation_notes(&got.id).unwrap().made;
    let by_payment = spent_now
        .iter()
        .filter(|n| n.spent_by.as_ref() == Some(&sent.id));
    assert_eq!(by_payment.count(), notes.spent.len());

    // A note its hub refuses to unlink stays linked.
    let received = bob.receive(&sent.payment).unwrap();
    net.fail(UNLINK, Fault::Refused(Code::Invalid));
    let made = bob.operation_notes(&received.id).unwrap().made;
    assert_eq!(bob.unlink().await.unwrap(), made.len() - 1);
    let made = bob.operation_notes(&received.id).unwrap().made;
    let refused = made.iter().filter(|n| n.unlinked == Unlinking::StaysLinked);
    assert_eq!(refused.count(), 1, "{made:?}");

    // None of the wallet's: nothing.
    assert_eq!(
        alice.operation_notes(&"00".repeat(32)).unwrap(),
        Default::default()
    );
    assert!(matches!(
        alice.operation_notes("zz"),
        Err(Error::Invalid(_))
    ));
}

#[tokio::test]
async fn a_wallet_whose_seed_is_kept_elsewhere_opens_with_it_only() {
    let net = network();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.sqlite");
    let link = || Link(net.clone());
    let address =
        Wallet::create_without_seed(&path, &[5; 32], ChainProfile::Core30DefaultRegtest, link())
            .unwrap()
            .address();
    let seed: Option<Vec<u8>> = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("SELECT seed FROM meta", [], |r| r.get(0))
        .unwrap();
    assert_eq!(seed, None);
    assert!(matches!(Wallet::open(&path, link()), Err(Error::Setup(_))));
    assert!(matches!(
        Wallet::open_with_seed(&path, &[6; 32], link()),
        Err(Error::Setup(_))
    ));
    let wallet = Wallet::open_with_seed(&path, &[5; 32], link()).unwrap();
    assert_eq!(wallet.address(), address);

    // A wallet holding its seed opens with it too.
    let path = dir.path().join("held.sqlite");
    drop(Wallet::create(&path, &[5; 32], ChainProfile::Core30DefaultRegtest, link()).unwrap());
    Wallet::open_with_seed(&path, &[5; 32], link()).unwrap();
    assert!(matches!(
        Wallet::open_with_seed(&path, &[6; 32], link()),
        Err(Error::Setup(_))
    ));
}

#[tokio::test]
async fn a_wallet_trusts_hubs_of_its_network_only() {
    let net = network();
    let dir = tempfile::tempdir().unwrap();
    let link = || Link(net.clone());
    let others = [
        ChainProfile::Core30Mainnet,
        ChainProfile::Core30Signet,
        ChainProfile::Mutinynet,
    ];
    for profile in others {
        let path = dir.path().join(profile.name());
        let wallet = Wallet::create(&path, &[1; 32], profile, link()).unwrap();
        assert_eq!(wallet.network(), profile);
        match wallet.add_hub(HUB).await {
            Err(Error::Invalid(reason)) => assert!(reason.contains("follows regtest"), "{reason}"),
            other => panic!("{other:?}"),
        }
        assert!(wallet.hubs().unwrap().is_empty());
        drop(wallet);
        assert_eq!(Wallet::open(&path, link()).unwrap().network(), profile);
    }
    let path = dir.path().join("regtest");
    let regtest = ChainProfile::Core30DefaultRegtest;
    let wallet = Wallet::create_without_seed(&path, &[1; 32], regtest, link()).unwrap();
    wallet.add_hub(HUB).await.unwrap();
    drop(wallet);
    let wallet = Wallet::open_with_seed(&path, &[1; 32], link()).unwrap();
    assert_eq!(wallet.network(), regtest);
    assert_eq!(wallet.hubs().unwrap().len(), 1);
}

#[test]
fn its_futures_run_on_any_runtime_thread() {
    fn send<F: std::future::Future + Send>(_: F) {}
    let net = network();
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(
        &dir.path().join("w"),
        &[1; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(net),
    )
    .unwrap();
    let to = wallet.address();
    send(wallet.add_hub(HUB));
    send(wallet.send(HUB, &to, 1));
    send(wallet.resume());
    send(wallet.unlink());
    send(wallet.check());
}

/// A hub that says an input of a signed send is spent, and proves no
/// spend of it, has her give nothing up: it holds her signature and may
/// release the send whenever it likes, so her notes stay with the send,
/// which finishes once its hub releases it.
#[tokio::test]
async fn a_signed_send_refused_as_spent_without_proof_stays_pending() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    net.fail(RELEASE, Fault::Refused(Code::Spent));
    let Err(Error::Pending { id, reason }) = alice.send(HUB, &bob.address(), 10).await else {
        panic!("not pending");
    };
    assert!(reason.contains("Spent"), "{reason}");
    assert_eq!(alice.sends().unwrap()[0].state, State::Signed);
    assert_eq!(available(&alice), (0, 64));
    let resumed = alice.resume().await.unwrap();
    assert_eq!(resumed.paid[0].id, id);
    assert_eq!(bob.receive(&resumed.paid[0].payment).unwrap().amount, 10);
    assert_eq!(available(&alice), (52, 0));
}

/// A hub that released a signed send, its answer lost, and refuses it as
/// spent from then on shows the release it made: the send finishes with
/// the unlock shown, its change kept, and nothing is given up.
#[tokio::test]
async fn a_signed_send_refused_as_spent_that_its_hub_shows_released_finishes() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    net.fail(RELEASE, Fault::Dropped);
    let Err(Error::Pending { id, .. }) = alice.send(HUB, &bob.address(), 10).await else {
        panic!("not pending");
    };
    net.fail(RELEASE, Fault::Refused(Code::Spent));
    let resumed = alice.resume().await.unwrap();
    assert_eq!(resumed.paid.len(), 1, "{resumed:?}");
    assert_eq!(resumed.paid[0].id, id);
    assert_eq!(bob.receive(&resumed.paid[0].payment).unwrap().amount, 10);
    assert_eq!(alice.sends().unwrap()[0].state, State::Done);
    assert_eq!(available(&alice), (52, 0));
    assert!(same(&alice.payment(&id).unwrap(), &resumed.paid[0].payment));
}

/// A signed send whose hub forgot its offer, and refuses the offer made
/// again, is given up as an unsigned one refused is: its notes are freed.
#[tokio::test]
async fn a_signed_send_whose_forgotten_offer_is_refused_again_is_given_up() {
    let net = network();
    let (alice, bob) = (party(&net, 1).await, party(&net, 2).await);
    alice.receive(&net.pay(HUB, &alice.address(), 64)).unwrap();
    net.fail(RELEASE, Fault::Lost);
    let Err(Error::Pending { id, .. }) = alice.send(HUB, &bob.address(), 10).await else {
        panic!("not pending");
    };
    assert_eq!(alice.sends().unwrap()[0].state, State::Signed);
    net.fail(RELEASE, Fault::Refused(Code::UnknownOffer));
    net.fail(OFFER, Fault::Refused(Code::Fee));
    let resumed = alice.resume().await.unwrap();
    assert_eq!((resumed.paid.len(), resumed.pending.len()), (0, 0));
    assert_eq!(resumed.abandoned[0].0, id);
    assert!(resumed.abandoned[0].1.contains("Fee"), "{resumed:?}");
    assert!(matches!(
        alice.sends().unwrap()[0].state,
        State::Abandoned(_)
    ));
    assert_eq!(available(&alice), (64, 0));
}
