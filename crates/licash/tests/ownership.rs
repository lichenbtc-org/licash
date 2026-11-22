use k256::Scalar;
use licash::{
    crypto::{self, Point},
    note::{Derivation, HoldRoot, Message, Ownership},
};

fn point(value: u64) -> Point {
    Point::from_projective(&crypto::generator_mul(&Scalar::from(value)))
}
fn output() -> Derivation {
    Derivation::derive(
        4,
        point(17),
        HoldRoot::from_seed(&[7; 32]).unwrap().public(),
        &[23; 32],
        3,
    )
    .unwrap()
}

#[test]
fn derived_and_retained_witnesses_recompute_the_existing_bound_tweak_rule() {
    let output = output();
    let witness = output.ownership();
    witness.verify(&point(17), output.message()).unwrap();
    let retained = licash::note::derive_output(&point(17), &[23; 32], 3).unwrap();
    let imported = Ownership::from_seed(retained.seed);
    imported.verify(&point(17), output.message()).unwrap();
    assert_eq!(imported.unlink_commitment(), output.unlink_commitment());
    assert_eq!(witness.unlink_commitment(), imported.unlink_commitment());
    assert_eq!(format!("{witness:?}"), "Ownership(..)");
}

#[test]
fn the_owner_secret_signs_for_the_messages_owner() {
    let output = output();
    let witness = output.ownership();
    let secret = witness.owner_secret(&Scalar::from(17u64)).unwrap();
    let seed = licash::note::derive_output(&point(17), &[23; 32], 3)
        .unwrap()
        .seed;
    let tweak =
        crypto::scalar_from_hash(&crypto::tagged_hash("licash/tweak", &[&point(17).0, &seed]));
    assert_eq!(secret, Scalar::from(17u64) + tweak);
    assert_eq!(&crypto::x_only_pub(&secret), output.message().owner());
    let other = witness.owner_secret(&Scalar::from(19u64)).unwrap();
    assert_ne!(&crypto::x_only_pub(&other), output.message().owner());
    assert!(witness.owner_secret(&Scalar::ZERO).is_err());
}

#[test]
fn wrong_roots_seeds_and_invalid_points_do_not_establish_ownership() {
    let output = output();
    let witness = output.ownership();
    for root in [point(19), point(17 + 5), Point([0; 33]), Point([255; 33])] {
        assert!(witness.verify(&root, output.message()).is_err());
    }
    assert!(Ownership::from_seed([0; 32])
        .verify(&point(17), output.message())
        .is_err());
    let other = Derivation::derive(
        4,
        point(17),
        HoldRoot::from_seed(&[7; 32]).unwrap().public(),
        &[23; 32],
        4,
    )
    .unwrap();
    assert!(witness.verify(&point(17), other.message()).is_err());
}

#[test]
fn an_arbitrary_owner_field_does_not_gain_root_authority() {
    let output = output();
    let unrelated = Message::new(4, point(17).x_only(), *output.message().hold()).unwrap();
    assert!(output.ownership().verify(&point(17), &unrelated).is_err());
    // The verifier has no supplied-tweak parameter. It always recomputes the
    // root-bound hash, including for a related root, rather than trusting data.
    let related = Point::from_projective(
        &(point(17).to_projective().unwrap() + crypto::generator_mul(&Scalar::from(1u64))),
    );
    assert!(output
        .ownership()
        .verify(&related, output.message())
        .is_err());
}

#[test]
fn ownership_alone_is_not_note_authentication_or_hold_root_derivation() {
    let output = output();
    let original = output.message();
    let changed = Message::new(8, *original.owner(), point(37).x_only()).unwrap();
    output.ownership().verify(&point(17), &changed).unwrap();
    assert_ne!(
        original.identifier().unwrap(),
        changed.identifier().unwrap()
    );
    // Holder composition must also verify issuer evidence for this exact new
    // message and its exact Q envelope. Receiving still checks full derivation.
    // Those requirements must not be silently conflated with owner binding.
}
