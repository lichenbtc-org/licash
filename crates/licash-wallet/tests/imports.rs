//! Notes of a bridge exported to its owner's wallet, for her recoveries
//! to claim within what her own notes leave of a contract's cap.

#[allow(dead_code)]
mod net;

use std::sync::Arc;

use licash::{
    claim::Source,
    crypto::x_only_pub,
    spend::{lock_hash, ChainProfile},
};
use licash_api::{bridge::Info, Fee};
use licash_wallet::{ClaimNote, ClaimSlot, Error, LockClaim, LockState, Wallet};
use net::{Fault, Link, Net, HUB};

const FEE: Fee = Fee { base: 2, ppm: 0 };
const ID: [u8; 32] = [7; 32];
/// The Nostr key of the bridge exporting.
const SOURCE: [u8; 32] = [0x42; 32];

struct Party {
    _dir: tempfile::TempDir,
    wallet: Wallet<Link>,
    keyset: [u8; 32],
}

async fn party(net: &Arc<Net>, seed: u8, amounts: &[u64]) -> Party {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(
        &dir.path().join("w.sqlite"),
        &[seed; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(net.clone()),
    )
    .unwrap();
    wallet.add_hub(&format!("{HUB}/")).await.unwrap();
    for amount in amounts {
        wallet
            .receive(&net.pay(HUB, &wallet.address(), *amount))
            .unwrap();
    }
    let keyset = *net.hub(HUB).info().keysets[0].id();
    Party {
        _dir: dir,
        wallet,
        keyset,
    }
}

fn available(wallet: &Wallet<Link>) -> u64 {
    wallet.balance().unwrap().iter().map(|b| b.available).sum()
}

/// The wallet's key at the bridge answering as [`SOURCE`].
fn key_at_bridge(wallet: &Wallet<Link>) -> [u8; 32] {
    let info: Info = serde_json::from_value(serde_json::json!({
        "network": "regtest",
        "hub": HUB,
        "nostr": hex::encode(SOURCE),
        "relays": [],
        "open": false,
        "receive_fee": { "base": 1, "ppm": 0 },
    }))
    .unwrap();
    let mut key = [0; 32];
    hex::decode_to_slice(wallet.bridge_key(&info).unwrap(), &mut key).unwrap();
    key
}

fn denominations(notes: &[ClaimNote]) -> Vec<u64> {
    notes
        .iter()
        .map(|n| n.note.message().denomination())
        .collect()
}

fn slot(p: &Party, id: [u8; 32], cap: u64) -> ClaimSlot {
    ClaimSlot {
        id,
        keyset: p.keyset,
        cap,
        max: 32,
    }
}

#[tokio::test]
async fn a_bridge_s_notes_fill_what_her_own_leave_of_a_claim() {
    let net = Net::new();
    net.start(HUB, FEE);
    // The bridge holds 64 + 32 + 4; she holds 4 of her own.
    let bridge = party(&net, 3, &[100]).await;
    let her = party(&net, 1, &[4]).await;
    let w = &her.wallet;
    // Nothing imported yet: nothing to claim of it.
    assert!(w.imported_notes().unwrap().is_empty());
    assert!(w
        .claim_imported(&ID, &her.keyset, 50, 32)
        .unwrap()
        .is_empty());

    let sealed = bridge
        .wallet
        .export_notes(&SOURCE, &key_at_bridge(w))
        .unwrap();
    assert_eq!((sealed.notes, sealed.amount), (3, 100));
    // Of no lock: of the format builds reading no locks read.
    assert_eq!((sealed.sealed[0], sealed.locks, sealed.locked), (1, 0, 0));
    // Sealed to her key there: no other wallet opens it, nor a copy cut.
    let other = party(&net, 2, &[]).await;
    let refused = other.wallet.import_notes(&sealed.sealed);
    assert!(
        matches!(&refused, Err(Error::Invalid(m)) if m.contains("another")),
        "{refused:?}"
    );
    let mut cut = sealed.sealed.clone();
    *cut.last_mut().unwrap() ^= 1;
    assert!(w.import_notes(&cut).is_err());
    assert!(w.imported_notes().unwrap().is_empty());

    let imported = w.import_notes(&sealed.sealed).unwrap();
    assert_eq!(
        (imported.added, imported.amount, imported.unknown),
        (3, 100, 0)
    );
    assert_eq!(imported.source, hex::encode(SOURCE));
    let again = w.import_notes(&sealed.sealed).unwrap();
    assert_eq!((again.added, again.known), (0, 3));
    // Not hers to spend: her balance, and what she shows protected, are
    // her own notes'.
    assert_eq!(available(w), 4);
    let slots = [slot(&her, ID, 50)];
    assert_eq!(w.recoverable(&slots, 0, None).unwrap()[&ID], 4);

    // Hers first, then the imported cover what is left of the cap.
    let own = w.claim_notes(&ID, &slots).unwrap();
    assert_eq!(denominations(&own), [4]);
    let filled = w.claim_imported(&ID, &her.keyset, 46, 31).unwrap();
    assert_eq!(denominations(&filled), [64]);
    assert!(w
        .claim_imported(&ID, &her.keyset, 46, 31)
        .unwrap()
        .is_empty());
    assert!(matches!(w.claim_notes(&ID, &slots), Err(Error::Invalid(_))));
    let claimed = w.claimed_notes(&ID, &her.keyset).unwrap();
    assert_eq!(denominations(&claimed), [4, 64]);
    // Each authorized by its own hold key: the bridge's, of its note.
    let keys = w.hold_keys(&claimed).unwrap();
    let theirs = bridge.wallet.hold_keys(&claimed[1..]).unwrap();
    assert_eq!(keys[1].1 .0, theirs[0].1 .0);
    for (note, (message, key)) in claimed.iter().zip(&keys) {
        assert_eq!(note.note.message(), message);
        assert_eq!(&x_only_pub(&key.to_scalar().unwrap()), message.hold());
    }
    // Another contract takes what is left, not the same.
    let more = w.claim_imported(&[8; 32], &her.keyset, 1_000, 32).unwrap();
    assert_eq!(denominations(&more), [32, 4]);

    // Kept while claimed; given back with her own; dropped for good from
    // a claim not owed whole with them.
    assert!(w.discard_imported(&hex::encode(SOURCE)).is_err());
    assert_eq!(w.unclaim_notes(&ID).unwrap(), 2);
    assert_eq!(available(w), 4);
    let dropped = w.void_imported(&[8; 32], "not owed").unwrap();
    assert_eq!(dropped.len(), 2);
    let listed = &w.imported_notes().unwrap()[0];
    assert_eq!(
        (listed.notes, listed.amount, listed.claimed, listed.void),
        (3, 64, 0, 2)
    );
    let last = w.claim_imported(&[9; 32], &her.keyset, 1_000, 32).unwrap();
    assert_eq!(denominations(&last), [64]);
    assert_eq!(w.unclaim_notes(&[9; 32]).unwrap(), 1);
    assert_eq!(w.discard_imported(&hex::encode(SOURCE)).unwrap(), 3);
    assert!(w.imported_notes().unwrap().is_empty());
}

fn signed_by_their_keys(locks: &[LockClaim]) {
    for lock in locks {
        for (message, key) in &lock.keys {
            assert_eq!(&x_only_pub(&key.to_scalar().unwrap()), message.hold());
        }
    }
}

/// The refunds of a bridge's locks its hub never settled, a payment stuck
/// on it, exported with its notes: claimed once owed on Bitcoin, each
/// whole within what is left of a claim's cap, and left out once their
/// notes are held otherwise.
#[tokio::test]
async fn a_bridge_s_unsettled_locks_are_exported_and_claimed_once_owed() {
    let net = Net::new();
    net.start(HUB, FEE);
    let bridge = party(&net, 3, &[100]).await;
    let her = party(&net, 1, &[4]).await;
    let payee = party(&net, 2, &[]).await;
    let b = &bridge.wallet;
    let certified = b
        .lock(
            HUB,
            &payee.wallet.address(),
            10,
            lock_hash(&[7; 32]),
            Some(8),
        )
        .await
        .unwrap();
    net.fail(licash_api::LOCK, Fault::Lost);
    let Err(Error::Pending { id: requested, .. }) = b
        .lock(
            HUB,
            &payee.wallet.address(),
            2,
            lock_hash(&[8; 32]),
            Some(8),
        )
        .await
    else {
        panic!("not pending");
    };
    let w = &her.wallet;
    let sealed = b.export_notes(&SOURCE, &key_at_bridge(w)).unwrap();
    assert_eq!((sealed.sealed[0], sealed.locks), (2, 2));
    let mut later = sealed.sealed.clone();
    later[0] = 3;
    let refused = w.import_notes(&later);
    assert!(
        matches!(&refused, Err(Error::Invalid(m)) if m.contains("of format 3")),
        "{refused:?}"
    );
    let imported = w.import_notes(&sealed.sealed).unwrap();
    assert_eq!(
        (
            imported.added,
            imported.amount,
            imported.locks,
            imported.locked
        ),
        (sealed.notes, sealed.amount, 2, sealed.locked)
    );
    assert_eq!(
        w.import_notes(&sealed.sealed).unwrap().known,
        sealed.notes + 2
    );
    let listed = &w.imported_notes().unwrap()[0];
    assert_eq!((listed.locks, listed.locked), (2, sealed.locked));
    // Not hers: her balance is her own notes'.
    assert_eq!(available(w), 4);

    // Short of their expiry at depth: owed nothing yet.
    assert!(w
        .claim_imported_locks(&ID, &her.keyset, 8, 1_000, 32)
        .unwrap()
        .is_empty());
    // Each whole or not at all: the smaller alone fits.
    let (_, b_claims) = b
        .claim_with_locks(&[1; 32], &[slot(&bridge, [1; 32], 1_000)], 100, None, true)
        .unwrap();
    let smallest = b_claims.iter().map(|l| l.value).min().unwrap();
    b.unclaim_notes(&[1; 32]).unwrap();
    let one = w
        .claim_imported_locks(&ID, &her.keyset, 100, smallest, 32)
        .unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].value, smallest);
    let released = w.release_imported_locks(&ID, "not owed").unwrap();
    assert_eq!(released, [one[0].id]);
    assert!(w.claimed_locks(&ID, &her.keyset).unwrap().is_empty());

    let locks = w
        .claim_imported_locks(&ID, &her.keyset, 100, 1_000, 32)
        .unwrap();
    assert_eq!(locks.len(), 2);
    signed_by_their_keys(&locks);
    // As the bridge's recovery would claim them, the certified on its
    // certificate, the other on its own inputs.
    let mut ids: Vec<String> = locks.iter().map(|l| hex::encode(l.id.as_bytes())).collect();
    ids.sort();
    let mut theirs = vec![certified.id.clone(), requested.clone()];
    theirs.sort();
    assert_eq!(ids, theirs);
    for lock in &locks {
        let made = b_claims.iter().find(|l| l.id == lock.id).unwrap();
        assert_eq!((lock.value, lock.keys.len()), (made.value, made.keys.len()));
        let own = matches!(lock.source, Source::OwnInputs { .. });
        assert_eq!(own, hex::encode(lock.id.as_bytes()) == requested);
    }
    // Taken: again, or by another contract, none.
    assert!(w
        .claim_imported_locks(&ID, &her.keyset, 100, 1_000, 32)
        .unwrap()
        .is_empty());
    assert!(w
        .claim_imported_locks(&[8; 32], &her.keyset, 100, 1_000, 32)
        .unwrap()
        .is_empty());
    let mut again: Vec<_> = (w.claimed_locks(&ID, &her.keyset).unwrap())
        .iter()
        .map(|l| l.id)
        .collect();
    again.sort();
    let mut taken: Vec<_> = locks.iter().map(|l| l.id).collect();
    taken.sort();
    assert_eq!(again, taken);
    assert!(w.discard_imported(&hex::encode(SOURCE)).is_err());

    // Refunded by its hub once expired at depth: its refund's notes, at
    // the points its claim has, exported as notes. Claimed by no other
    // recovery while the lock's claims them.
    net.mine(HUB, 6, None);
    b.resume().await.unwrap();
    let state = &b.locks().unwrap();
    let refunded = state.iter().find(|l| l.id == certified.id).unwrap();
    assert_eq!(refunded.state, LockState::Refunded);
    let refund_points: Vec<[u8; 33]> = (locks.iter())
        .filter(|l| hex::encode(l.id.as_bytes()) == certified.id)
        .flat_map(|l| l.keys.iter().map(|(m, _)| m.identifier().unwrap().0))
        .collect();
    assert!(!refund_points.is_empty());
    let sealed = b.export_notes(&SOURCE, &key_at_bridge(w)).unwrap();
    assert!(w.import_notes(&sealed.sealed).unwrap().added >= refund_points.len());
    let notes = w.claim_imported(&[9; 32], &her.keyset, 1_000, 32).unwrap();
    assert!(!notes.is_empty());
    assert!(notes.iter().all(|n| {
        let y = n.note.message().identifier().unwrap().0;
        !refund_points.contains(&y)
    }));
    w.unclaim_notes(&[9; 32]).unwrap();

    // Given back with her own: the lock is left out of a claim then, which
    // would have its refund's notes twice.
    w.unclaim_notes(&ID).unwrap();
    assert!(w.claimed_locks(&ID, &her.keyset).unwrap().is_empty());
    let left = w
        .claim_imported_locks(&[10; 32], &her.keyset, 100, 1_000, 32)
        .unwrap();
    assert!(left
        .iter()
        .all(|l| hex::encode(l.id.as_bytes()) != certified.id));
    w.unclaim_notes(&[10; 32]).unwrap();
    // Forgotten whole, locks with notes.
    let forgotten = w.discard_imported(&hex::encode(SOURCE)).unwrap();
    let listed = &w.imported_notes().unwrap();
    assert!(listed.is_empty(), "{forgotten} forgotten, left {listed:?}");
}
