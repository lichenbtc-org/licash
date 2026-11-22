use k256::Scalar;
use licash::{
    crypto::{self, Point, ScalarBytes},
    ec::Pt,
    note::Evidence,
    note::{Derivation, HoldRoot, Message, MESSAGE_BYTES},
};

fn point(key: u64) -> Point {
    Point::from_projective(&crypto::generator_mul(&Scalar::from(key)))
}

fn derive(index: u32, hold: &HoldRoot) -> Derivation {
    Derivation::derive(1, point(17), hold.public(), &[23; 32], index).unwrap()
}

#[test]
fn canonical_message_binds_amount_owner_and_hold_key() {
    let root = HoldRoot::from_scalar(Scalar::from(29u64)).unwrap();
    let output = derive(0, &root);
    let message = output.message();
    let bytes = message.to_bytes();
    assert_eq!(MESSAGE_BYTES, 86);
    assert_eq!(&bytes[..14], b"licash/note/v3");
    assert_eq!(&bytes[14..22], &1u64.to_be_bytes());
    assert_eq!(&bytes[22..54], message.owner());
    assert_eq!(&bytes[54..], message.hold());
    assert_eq!(Message::from_bytes(&bytes).unwrap(), *message);
    let y = message.identifier().unwrap();
    for field in 0..3 {
        let mut altered = bytes;
        match field {
            0 => altered[14..22].copy_from_slice(&2u64.to_be_bytes()),
            1 => altered[22..54].copy_from_slice(&point(31).x_only()),
            _ => altered[54..].copy_from_slice(&point(37).x_only()),
        }
        assert_ne!(
            Message::from_bytes(&altered).unwrap().identifier().unwrap(),
            y
        );
    }
}

#[test]
fn invalid_encodings_do_not_acquire_default_authority() {
    let root = HoldRoot::from_seed(&[3; 32]).unwrap();
    let output = derive(0, &root);
    let bytes = output.message().to_bytes();
    assert!(Message::from_bytes(&bytes[..85]).is_err());
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(Message::from_bytes(&trailing).is_err());
    let mut wrong_tag = bytes;
    wrong_tag[13] = b'1';
    assert!(Message::from_bytes(&wrong_tag).is_err());
    assert!(Message::new(0, point(17).x_only(), point(29).x_only()).is_err());
    assert!(Message::new(1, [0xff; 32], point(29).x_only()).is_err());
    assert!(Message::new(1, point(17).x_only(), [0xff; 32]).is_err());
    assert!(Derivation::derive(1, Point([0; 33]), root.public(), &[23; 32], 0).is_err());
    assert!(Derivation::derive(1, point(17), Point([0; 33]), &[23; 32], 0).is_err());
}

#[test]
fn root_derivation_is_independent_and_secret_debug_output_is_redacted() {
    let seed = [5; 32];
    let root = HoldRoot::from_seed(&seed).unwrap();
    let expected = crypto::scalar_from_hash(&crypto::tagged_hash("licash/root/hold/v2", &[&seed]));
    assert_eq!(root.to_bytes(), ScalarBytes::from_scalar(&expected).0);
    assert_eq!(
        HoldRoot::from_bytes(root.to_bytes()).unwrap().public(),
        root.public()
    );
    assert!(HoldRoot::from_bytes([0; 32]).is_err());
    assert!(HoldRoot::from_bytes([0xff; 32]).is_err());
    assert_eq!(format!("{root:?}"), "HoldRoot(..)");
    assert_eq!(
        format!("{:?}", derive(0, &root).message()),
        "NoteMessage(..)"
    );
    assert_eq!(format!("{:?}", derive(0, &root)), "NoteDerivation(..)");
}

#[test]
fn what_is_derived_for_an_output_prints_no_key() {
    let receipt = licash::note::derive_output(&point(17), &[23; 32], 1).unwrap();
    let printed = format!("{receipt:?} {receipt:#?}");
    for key in [&receipt.seed[..], &receipt.blinding.0[..]] {
        assert!(!printed.contains(&hex::encode(key)), "{printed}");
        assert!(!printed.contains(&format!("{key:?}")), "{printed}");
    }
    assert!(
        !printed.contains(&format!("{:?}", receipt.seed)),
        "{printed}"
    );
    assert!(printed.starts_with("Derived"), "{printed}");
}

#[test]
fn a_scan_agent_derives_hold_authority_without_the_spending_scalar() {
    let root = HoldRoot::from_seed(&[7; 32]).unwrap();
    let output = derive(1, &root);
    let spend = point(17);
    let receipt = licash::note::derive_output(&spend, &[23; 32], 1).unwrap();
    let tweak = crypto::scalar_from_hash(&crypto::tagged_hash(
        "licash/hold-tweak/v2",
        &[&root.public().0, &spend.0, &receipt.seed],
    ));
    let expected = root.public().to_projective().unwrap() + crypto::generator_mul(&tweak);
    assert_eq!(
        output.message().hold(),
        &Point::from_projective(&expected).x_only()
    );
    let key = output.hold_key(&root).unwrap().to_scalar().unwrap();
    assert_eq!(
        &Point::from_projective(&crypto::generator_mul(&key)).x_only(),
        output.message().hold()
    );
    let digest = crypto::tagged_hash("test/next-note-hold", &[&output.message().to_bytes()]);
    let sig = crypto::schnorr_sign(&key, &digest).unwrap();
    crypto::schnorr_verify(output.message().hold(), &digest, &sig).unwrap();
    assert!(crypto::schnorr_verify(output.message().owner(), &digest, &sig).is_err());
}

#[test]
fn hold_root_rotation_changes_y_not_the_existing_spending_derivation() {
    let old = HoldRoot::from_seed(&[7; 32]).unwrap();
    let new = HoldRoot::from_seed(&[11; 32]).unwrap();
    let before = derive(2, &old);
    let after = derive(2, &new);
    assert_eq!(before.message().owner(), after.message().owner());
    assert_ne!(before.message().hold(), after.message().hold());
    assert_ne!(
        before.message().identifier().unwrap(),
        after.message().identifier().unwrap()
    );
    assert!(after.hold_key(&old).is_err());
    assert!(
        before.hold_key(&old).is_ok(),
        "rotation does not revoke an old note's key"
    );
}

#[test]
fn issuer_and_grant_evidence_verify_the_note_point() {
    let root = HoldRoot::from_seed(&[13; 32]).unwrap();
    let output = derive(3, &root);
    let y = output
        .message()
        .identifier()
        .unwrap()
        .to_projective()
        .unwrap();
    let blinded = output.blinded().unwrap().to_projective().unwrap();
    let r = output.blinding().to_scalar().unwrap();
    let issuer = Scalar::from(31u64);
    let key = crypto::generator_mul(&issuer);
    let blind_sig = crypto::blind_sign(&issuer, &blinded);
    let c = crypto::unblind(&blind_sig, &r, &key);
    assert_eq!(c, y * issuer);
    let convert =
        |point: k256::ProjectivePoint| Pt::from_point(&Point::from_projective(&point)).unwrap();
    let commit = crypto::dleq_commit(&Scalar::from(37u64), &blinded);
    Evidence::Linked {
        dleq: crypto::dleq_prove(&issuer, &blinded, &blind_sig),
        blinding: *output.blinding(),
        commit,
    }
    .verify(&convert(key), &convert(y), &convert(c))
    .unwrap();
    Evidence::Unlinked(crypto::dleq_prove(&issuer, &y, &c))
        .verify(&convert(key), &convert(y), &convert(c))
        .unwrap();
    let unlock = Scalar::from(41u64);
    let mask = crypto::generator_mul(&Scalar::from(43u64));
    let (sealed, seal) = crypto::seal_prove(&issuer, &unlock, &blinded, &mask, &commit.to_bytes());
    assert_eq!(sealed - mask * unlock, blind_sig);
    Evidence::Granted {
        seal,
        blinding: *output.blinding(),
        commit,
        unlock: ScalarBytes::from_scalar(&unlock),
        mask: Point::from_projective(&mask),
    }
    .verify(&convert(key), &convert(y), &convert(c))
    .unwrap();
}

#[test]
fn all_32_outputs_have_independent_hold_keys_and_identifiers() {
    let root = HoldRoot::from_seed(&[17; 32]).unwrap();
    let mut identifiers = std::collections::BTreeSet::new();
    let mut holds = std::collections::BTreeSet::new();
    for index in 0..32 {
        let output = derive(index, &root);
        assert!(identifiers.insert(output.message().identifier().unwrap()));
        assert!(holds.insert(*output.message().hold()));
        assert!(output.hold_key(&root).is_ok());
    }
    assert_eq!(identifiers.len(), 32);
}

/// Y is a function of the message fields alone: remembering it changes
/// neither equality nor what a copy or a re-decoded message computes.
#[test]
fn a_remembered_identifier_does_not_change_the_message() {
    let fresh = || Message::new(8, point(17).x_only(), point(29).x_only()).unwrap();
    let (used, untouched) = (fresh(), fresh());
    let y = used.identifier().unwrap();
    assert_eq!(used.identifier().unwrap(), y);
    assert!(used == untouched && used.to_bytes() == untouched.to_bytes());
    assert_eq!(used.clone().identifier().unwrap(), y);
    assert_eq!(untouched.identifier().unwrap(), y);
    assert_eq!(
        Message::from_bytes(&used.to_bytes())
            .unwrap()
            .identifier()
            .unwrap(),
        y
    );
    let other = Message::new(8, point(17).x_only(), point(31).x_only()).unwrap();
    assert!(other != used && other.identifier().unwrap() != y);
}
