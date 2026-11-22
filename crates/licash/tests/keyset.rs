use k256::Scalar;
use licash::{
    crypto::{self, Point},
    note::{Derivation, HoldRoot, IssuerKeys, Keyset},
};

#[test]
fn fresh_keys_and_strict_metadata_are_namespaced() {
    let issuer = IssuerKeys::random(3).unwrap();
    let keyset = issuer.keyset().unwrap();
    assert_eq!(Keyset::from_bytes(&keyset.to_bytes()).unwrap(), keyset);
    assert_ne!(
        IssuerKeys::random(3).unwrap().keyset().unwrap().id(),
        keyset.id()
    );
    let bytes = keyset.to_bytes();
    let records = &bytes[b"LICASH-KS\x05".len() + 68..];
    let mut old_parts: Vec<&[u8]> = vec![keyset.issuer()];
    for record in records.as_chunks::<41>().0 {
        old_parts.push(record);
    }
    assert_ne!(
        keyset.id(),
        &crypto::tagged_hash("licash/keyset", &old_parts),
        "namespace differs even for identical public keys"
    );
    assert!(IssuerKeys::random(64).is_err());
    assert!(IssuerKeys::random(u32::MAX).is_err());
    assert_eq!(format!("{issuer:?}"), "IssuerKeys(..)");
    assert_eq!(format!("{keyset:?}"), "Keyset(..)");
}

#[test]
fn metadata_rejects_wrong_ids_lengths_order_and_curve_keys() {
    let keyset = IssuerKeys::random(2).unwrap().keyset().unwrap();
    let original = keyset.to_bytes();
    let tag = b"LICASH-KS\x05".len();
    let records = tag + 32 + 32 + 4;
    for mutation in 0..7 {
        let mut bytes = original.clone();
        match mutation {
            0 => bytes[tag] ^= 1,
            1 => bytes.push(0),
            2 => {
                bytes.pop();
            }
            3 => bytes[tag + 64..records].copy_from_slice(&u32::MAX.to_be_bytes()),
            4 => bytes[records..records + 8].fill(0),
            5 => bytes[records + 41..records + 49].copy_from_slice(&1u64.to_be_bytes()),
            _ => bytes[records + 8..records + 41].fill(0),
        }
        assert!(Keyset::from_bytes(&bytes).is_err());
    }
    for length in 0..records {
        assert!(Keyset::from_bytes(&original[..length]).is_err());
    }
}

#[test]
fn blinded_proof_is_scoped_to_the_new_keyset_denomination_and_target() {
    let issuer = IssuerKeys::random(3).unwrap();
    let keyset = issuer.keyset().unwrap();
    let hold = HoldRoot::from_seed(&[7; 32]).unwrap();
    let spend = Point::from_projective(&crypto::generator_mul(&Scalar::from(17u64)));
    let output = Derivation::derive(4, spend, hold.public(), &[23; 32], 0).unwrap();
    let blinded = output.blinded().unwrap();
    let proof = issuer.prove_blinded(4, blinded).unwrap();
    proof.verify(&keyset, 4, &blinded).unwrap();
    assert!(proof.verify(&keyset, 2, &blinded).is_err());
    assert!(proof
        .verify(
            &IssuerKeys::random(3).unwrap().keyset().unwrap(),
            4,
            &blinded
        )
        .is_err());
    assert!(proof.verify(&keyset, 4, &spend).is_err());
    assert!(issuer.prove_blinded(3, blinded).is_err());
    assert!(issuer.prove_blinded(4, Point([0; 33])).is_err());
    let c = crypto::unblind(
        &proof.signature().to_projective().unwrap(),
        &output.blinding().to_scalar().unwrap(),
        &keyset.key(4).unwrap().to_projective().unwrap(),
    );
    assert_eq!(
        proof.open_point(&keyset, &output).unwrap(),
        Point::from_projective(&c)
    );
    let other = Derivation::derive(4, spend, hold.public(), &[23; 32], 1).unwrap();
    assert!(proof.open_point(&keyset, &other).is_err());
    assert_eq!(format!("{proof:?}"), "BlindProof(..)");
}

#[test]
fn signing_keys_cannot_be_reused_even_with_a_recomputed_metadata_id() {
    let original = IssuerKeys::random(2).unwrap().keyset().unwrap().to_bytes();
    let tag = b"LICASH-KS\x05".len();
    let start = tag + 68;
    for mutation in 0..4 {
        let mut bytes = original.clone();
        let first: [u8; 33] = bytes[start + 8..start + 41].try_into().unwrap();
        match mutation {
            0 => bytes[start + 49..start + 82].copy_from_slice(&first),
            1 => {
                bytes[start + 49..start + 82].copy_from_slice(&first);
                bytes[start + 49] ^= 1; // same x, opposite point
            }
            2 => {
                let credential: [u8; 32] = bytes[tag + 32..tag + 64].try_into().unwrap();
                bytes[start + 8] = 2;
                bytes[start + 9..start + 41].copy_from_slice(&credential);
            }
            _ => bytes[start + 8..start + 41].fill(0),
        }
        let format = crypto::tagged_hash(
            "licash/note-format/v5",
            &[
                b"licash/note/v3",
                b"LICASH-V2-secp256k1_XMD:SHA-256_SSWU_RO_",
            ],
        );
        let id = crypto::tagged_hash(
            "licash/keyset/v2",
            &[
                &format,
                &bytes[tag + 32..tag + 64],
                &bytes[tag + 64..start],
                &bytes[start..],
            ],
        );
        bytes[tag..tag + 32].copy_from_slice(&id);
        assert!(Keyset::from_bytes(&bytes).is_err());
    }
}

#[test]
fn the_full_u64_binary_denomination_range_has_distinct_keys() {
    let keyset = IssuerKeys::random(63).unwrap().keyset().unwrap();
    let mut keys = std::collections::BTreeSet::new();
    for power in 0..64 {
        assert!(keys.insert(keyset.key(1u64 << power).unwrap().x_only()));
    }
    assert_eq!(keys.len(), 64);
    assert!(keyset.key(0).is_err());
    assert!(keyset.key(3).is_err());
    assert_eq!(Keyset::from_bytes(&keyset.to_bytes()).unwrap(), keyset);
}

#[test]
fn seeded_issuer_keys_are_deterministic_and_independent_per_index_and_size() {
    let keys = IssuerKeys::from_seed(&[5; 32], 0, 3).unwrap();
    let keyset = keys.keyset().unwrap();
    assert_eq!(keys.id(), keyset.id());
    // Hubs check their stored keysets against this derivation at startup.
    assert_eq!(
        hex::encode(keyset.id()),
        "348c118699ce7f6244a6c6bc1d01d52b50d10debbd298d67d3041bc0272066bd"
    );
    let again = IssuerKeys::from_seed(&[5; 32], 0, 3).unwrap();
    assert_eq!(again.keyset().unwrap(), keyset);
    for (seed, index, max_pow) in [([5; 32], 1, 3), ([5; 32], 0, 4), ([6; 32], 0, 3)] {
        let other = IssuerKeys::from_seed(&seed, index, max_pow)
            .unwrap()
            .keyset()
            .unwrap();
        assert_ne!(other.id(), keyset.id());
        assert_ne!(other.issuer(), keyset.issuer());
        for denom in [1, 2, 4, 8] {
            assert_ne!(other.key(denom).unwrap(), keyset.key(denom).unwrap());
        }
    }
    assert!(keyset.key(16).is_err());
    assert!(IssuerKeys::from_seed(&[5; 32], 0, 64).is_err());
}
