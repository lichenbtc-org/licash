//! Notes of a bridge exported to its owner's wallet, for her recoveries
//! to claim within what her own notes leave of a contract's cap.

#[allow(dead_code)]
mod net;

use std::sync::Arc;

use licash::{crypto::x_only_pub, spend::ChainProfile};
use licash_api::{bridge::Info, Fee};
use licash_wallet::{ClaimNote, ClaimSlot, Error, Wallet};
use net::{Link, Net, HUB};

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
