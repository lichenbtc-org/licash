use k256::Scalar;
use licash::{
    crypto::{self, Point},
    note::{Derivation, HoldRoot, Message, MintLedger, Note},
};

fn point(key: u64) -> Point {
    Point::from_projective(&crypto::generator_mul(&Scalar::from(key)))
}

fn derive(index: u32) -> Derivation {
    let root = HoldRoot::from_seed(&[7; 32]).unwrap();
    Derivation::derive(4, point(17), root.public(), &[23; 32], index).unwrap()
}

#[test]
fn a_mint_reply_opens_a_verified_note_under_only_its_exact_keyset() {
    let mut ledger = MintLedger::fresh(3).unwrap();
    let output = derive(0);
    let reply = ledger.mint(4, output.blinded().unwrap()).unwrap();
    let note = reply.open(ledger.keyset(), &output).unwrap();
    note.verify(ledger.keyset()).unwrap();
    assert_eq!(note.keyset_id(), ledger.keyset().id());
    assert_eq!(note.message(), output.message());
    assert_eq!(
        Note::from_parts(
            ledger.keyset(),
            *note.keyset_id(),
            note.message().clone(),
            note.signature(),
            *note.evidence()
        )
        .unwrap(),
        note
    );
    let other = MintLedger::fresh(3).unwrap();
    assert!(note.verify(other.keyset()).is_err());
    assert!(reply.open(other.keyset(), &output).is_err());
    assert!(reply.open(ledger.keyset(), &derive(1)).is_err());
    assert!(Note::from_parts(
        ledger.keyset(),
        [0; 32],
        note.message().clone(),
        note.signature(),
        *note.evidence()
    )
    .is_err());
    assert!(Note::from_parts(
        ledger.keyset(),
        *note.keyset_id(),
        note.message().clone(),
        Point([0; 33]),
        *note.evidence()
    )
    .is_err());
    assert_eq!(format!("{note:?}"), "Note(..)");
    assert_eq!(format!("{reply:?}"), "MintResponse(..)");
}

#[test]
fn every_public_message_field_remains_bound_after_minting() {
    let mut ledger = MintLedger::fresh(3).unwrap();
    let output = derive(0);
    let note = ledger
        .mint(4, output.blinded().unwrap())
        .unwrap()
        .open(ledger.keyset(), &output)
        .unwrap();
    for field in 0..3 {
        let mut bytes = note.message().to_bytes();
        match field {
            0 => bytes[14..22].copy_from_slice(&2u64.to_be_bytes()),
            1 => bytes[22..54].copy_from_slice(&point(31).x_only()),
            _ => bytes[54..].copy_from_slice(&point(37).x_only()),
        }
        assert!(Note::from_parts(
            ledger.keyset(),
            *note.keyset_id(),
            Message::from_bytes(&bytes).unwrap(),
            note.signature(),
            *note.evidence()
        )
        .is_err());
    }
}

#[test]
fn mint_replay_preserves_the_entire_reply_and_unlink_commitment() {
    let mut ledger = MintLedger::fresh(3).unwrap();
    let output = derive(0);
    let blinded = output.blinded().unwrap();
    let first = ledger.mint(4, blinded).unwrap();
    assert_eq!(ledger.issued_count(), 1);
    assert_eq!(ledger.mint(4, blinded).unwrap(), first);
    let mut snapshot = ledger.clone();
    assert_eq!(snapshot.mint(4, blinded).unwrap(), first);
    assert!(snapshot.mint(2, blinded).is_err());
    assert_eq!(snapshot.issued_count(), 1);
    assert_eq!(snapshot.mint(4, blinded).unwrap(), first);
    assert_eq!(format!("{ledger:?}"), "MintLedger(..)");
}

#[test]
fn invalid_requests_do_not_create_issuance_or_replace_existing_records() {
    let mut ledger = MintLedger::fresh(3).unwrap();
    assert!(ledger.mint(4, Point([0; 33])).is_err());
    assert!(ledger.mint(3, derive(0).blinded().unwrap()).is_err());
    assert_eq!(ledger.issued_count(), 0);
    let first = derive(0);
    let response = ledger.mint(4, first.blinded().unwrap()).unwrap();
    assert!(ledger.mint(8, first.blinded().unwrap()).is_err());
    assert_eq!(ledger.issued_count(), 1);
    assert_eq!(ledger.mint(4, first.blinded().unwrap()).unwrap(), response);
}

#[test]
fn all_32_minted_outputs_have_verified_distinct_notes_and_replayable_records() {
    let mut ledger = MintLedger::fresh(3).unwrap();
    let mut ids = std::collections::BTreeSet::new();
    let mut replies = Vec::new();
    for index in 0..32 {
        let output = derive(index);
        let reply = ledger.mint(4, output.blinded().unwrap()).unwrap();
        let note = reply.open(ledger.keyset(), &output).unwrap();
        note.verify(ledger.keyset()).unwrap();
        assert!(ids.insert(note.message().identifier().unwrap()));
        replies.push((output.blinded().unwrap(), reply));
    }
    assert_eq!(ledger.issued_count(), 32);
    for (blinded, reply) in replies {
        assert_eq!(ledger.mint(4, blinded).unwrap(), reply);
    }
    assert_eq!(ledger.issued_count(), 32);
}
