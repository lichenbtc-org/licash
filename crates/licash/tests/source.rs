use k256::Scalar;
use licash::{
    authorization::{Authorization, SignedProposal},
    crypto::{self, Point, Signature},
    note::Evidence,
    note::{Derivation, HoldRoot, IssuerKeys, Keyset, Note},
    source::{self, Certificate, Metadata},
    spend::{ChainProfile, Output, Proposal, ProposalId, TimedLock, TimedTerms, TIMED_TERMS_BYTES},
};

fn point(key: u64) -> Point {
    Point::from_projective(&crypto::generator_mul(&Scalar::from(key)))
}
fn derive(index: u32) -> Derivation {
    Derivation::derive(
        4,
        point(17),
        HoldRoot::from_seed(&[7; 32]).unwrap().public(),
        &[23; 32],
        index,
    )
    .unwrap()
}
fn owner(index: u32) -> Scalar {
    Scalar::from(17u64)
        + licash::note::derive_output(&point(17), &[23; 32], index)
            .unwrap()
            .tweak
            .to_scalar()
            .unwrap()
}
fn fixture() -> (IssuerKeys, Keyset, Vec<Note>, SignedProposal) {
    let keys = IssuerKeys::random(2).unwrap();
    let keyset = keys.keyset().unwrap();
    let notes: Vec<_> = [1, 0]
        .into_iter()
        .map(|i| {
            let d = derive(i);
            let proof = keys.prove_blinded(4, d.blinded().unwrap()).unwrap();
            Note::from_parts(
                &keyset,
                *keyset.id(),
                d.message().clone(),
                proof.open_point(&keyset, &d).unwrap(),
                Evidence::Linked {
                    dleq: proof.dleq(),
                    blinding: *d.blinding(),
                    commit: crypto::dleq_commit(
                        &Scalar::from(71u64),
                        &d.blinded().unwrap().to_projective().unwrap(),
                    ),
                },
            )
            .unwrap()
        })
        .collect();
    let terms = TimedTerms::new(
        ChainProfile::Core30DefaultRegtest,
        [31; 32],
        1_000,
        3,
        [41; 32],
    )
    .unwrap();
    let lock = TimedLock::new(
        terms,
        vec![
            Output::from_derivation(&derive(12)).unwrap(),
            Output::from_derivation(&derive(13)).unwrap(),
        ],
    )
    .unwrap();
    let proposal = Proposal::new(
        &keyset,
        &notes,
        point(19),
        vec![
            Output::from_derivation(&derive(10)).unwrap(),
            Output::from_derivation(&derive(11)).unwrap(),
        ],
        Some(lock),
    )
    .unwrap();
    let signed = SignedProposal::sign(
        &keyset,
        proposal,
        &notes,
        Authorization::Plain,
        &[owner(1), owner(0)],
    )
    .unwrap();
    (keys, keyset, notes, signed)
}

#[test]
fn public_certificate_roundtrips_and_matches_its_private_authorized_source() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    cert.verify(&keyset).unwrap();
    cert.verify_source(&keyset, &signed, &notes).unwrap();
    let bytes = cert.to_bytes();
    assert_eq!(Certificate::from_bytes(&keyset, &bytes).unwrap(), cert);
    assert_eq!(cert.metadata().source_id(), signed.proposal().id());
    assert_eq!(cert.metadata().keyset_id(), keyset.id());
    assert_eq!(
        cert.metadata().terms(),
        signed.proposal().lock().unwrap().terms()
    );
    let mut ys = signed.verify(&keyset, &notes).unwrap();
    ys.sort_unstable();
    assert_eq!(cert.metadata().inputs(), ys);
    let mut counted = 2u32.to_be_bytes().to_vec();
    for y in &ys {
        counted.extend(y.0);
    }
    assert_eq!(
        source::input_root(&ys).unwrap(),
        crypto::tagged_hash("licash/source-inputs/v2", &[&counted])
    );
    let message = crypto::tagged_hash(
        "licash/timed-lock-admission/v1",
        &[
            keyset.id(),
            signed.proposal().id().as_bytes(),
            &source::input_root(&ys).unwrap(),
            &cert.metadata().terms().root(),
        ],
    );
    crypto::schnorr_verify(keyset.issuer(), &message, &cert.signature()).unwrap();
    assert_eq!(format!("{cert:?}"), "SourceCertificate(..)");
    assert_eq!(format!("{:?}", cert.metadata()), "SourceMetadata(..)");
}

#[test]
fn public_metadata_contains_ys_and_terms_not_the_payer_note_openings() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    let metadata = cert.metadata().unsigned_bytes();
    let expected_len = 32 + 32 + 4 + 2 * 33 + TIMED_TERMS_BYTES;
    assert_eq!(metadata.len(), expected_len);
    assert_eq!(&metadata[..32], keyset.id());
    assert_eq!(&metadata[32..64], signed.proposal().id().as_bytes());
    assert_eq!(&metadata[64..68], &2u32.to_be_bytes());
    assert_eq!(
        &metadata[metadata.len() - TIMED_TERMS_BYTES..],
        &cert.metadata().terms().to_bytes()
    );
    for note in &notes {
        for secret_field in [note.message().owner(), note.message().hold()] {
            assert!(!metadata.windows(32).any(|window| window == secret_field));
        }
    }
    assert!(!metadata
        .windows(64)
        .any(|window| window == cert.signature().0));
}

#[test]
fn certificate_rejects_changed_source_input_root_terms_issuer_and_keyset() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    let m = cert.metadata();
    let other = IssuerKeys::random(2).unwrap().keyset().unwrap();
    assert!(cert.verify(&other).is_err());
    for field in 0..8 {
        let mut inputs = m.inputs().to_vec();
        let mut terms = m.terms().to_bytes();
        let mut source = m.source_id();
        let mut keyset_id = *keyset.id();
        match field {
            0 => source = ProposalId::from_bytes([43; 32]),
            1 => {
                inputs[0] = point(47);
                inputs.sort_unstable();
            }
            2 => terms[0] = 0,
            3 => terms[1] ^= 1,
            4 => terms[36] ^= 1,
            5 => terms[40] ^= 1,
            6 => terms[41] ^= 1,
            _ => keyset_id[0] ^= 1,
        }
        let changed = Metadata::new(
            keyset_id,
            source,
            inputs,
            TimedTerms::from_bytes(&terms).unwrap(),
        )
        .unwrap();
        assert!(
            Certificate::from_parts(&keyset, changed, cert.signature()).is_err(),
            "field {field}"
        );
    }
    assert!(Certificate::from_parts(&keyset, m.clone(), Signature([0; 64])).is_err());
}

#[test]
fn canonical_input_sets_are_nonempty_strictly_sorted_and_nonidentity() {
    let (_, keyset, _, signed) = fixture();
    let terms = signed.proposal().lock().unwrap().terms();
    let mut inputs = vec![point(17), point(19)];
    inputs.sort_unstable();
    assert!(Metadata::new(
        *keyset.id(),
        signed.proposal().id(),
        inputs.clone(),
        terms.clone()
    )
    .is_ok());
    for bad in [
        vec![],
        vec![Point([0; 33])],
        vec![Point([0xff; 33])],
        vec![inputs[0], inputs[0]],
        vec![inputs[1], inputs[0]],
    ] {
        assert!(Metadata::new(*keyset.id(), signed.proposal().id(), bad, terms.clone()).is_err());
    }
}

#[test]
fn strict_certificate_framing_has_no_count_fallback() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    let body = cert.to_bytes();
    for n in 0..body.len() {
        assert!(Certificate::from_bytes(&keyset, &body[..n]).is_err());
    }
    let tag_len = b"LICASH-SRC\x02".len();
    for field in 0..8 {
        let mut changed = body.clone();
        let start = tag_len + 68;
        match field {
            0 => changed[0] ^= 1,
            1 => changed.push(0),
            2 => changed[tag_len + 64..start].copy_from_slice(&u32::MAX.to_be_bytes()),
            3 => changed[tag_len + 64..start].fill(0),
            4 => changed[start..start + 33].fill(0),
            5 => {
                let first = changed[start..start + 33].to_vec();
                changed[start + 33..start + 66].copy_from_slice(&first);
            }
            6 => changed[start + 66] = 2,
            _ => changed[start + 66 + 37..start + 66 + 41].fill(0),
        }
        assert!(Certificate::from_bytes(&keyset, &changed).is_err());
    }
}

#[test]
fn public_attestation_does_not_replace_matching_the_actual_private_source() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    let p = signed.proposal();
    let changed = Proposal::new(
        &keyset,
        &notes,
        point(53),
        p.outputs().to_vec(),
        p.lock().cloned(),
    )
    .unwrap();
    let other_source = SignedProposal::sign(
        &keyset,
        changed,
        &notes,
        Authorization::Plain,
        &[owner(1), owner(0)],
    )
    .unwrap();
    cert.verify(&keyset).unwrap();
    assert!(cert.verify_source(&keyset, &other_source, &notes).is_err());
    assert!(cert.verify_source(&keyset, &signed, &notes[..1]).is_err());
    let plain = Proposal::new(&keyset, &notes, point(19), p.outputs().to_vec(), None).unwrap();
    let plain = SignedProposal::sign(
        &keyset,
        plain,
        &notes,
        Authorization::Plain,
        &[owner(1), owner(0)],
    )
    .unwrap();
    assert!(Certificate::attest(&keys, &plain, &notes).is_err());
    assert!(Certificate::attest(&IssuerKeys::random(2).unwrap(), &signed, &notes).is_err());
}

#[test]
fn unsigned_source_set_roots_are_counted_order_independent_and_deduplicate_sources() {
    let (keys, keyset, notes, signed) = fixture();
    let a = Certificate::attest(&keys, &signed, &notes).unwrap();
    let p = signed.proposal();
    let changed = Proposal::new(
        &keyset,
        &notes,
        point(59),
        p.outputs().to_vec(),
        p.lock().cloned(),
    )
    .unwrap();
    let changed = SignedProposal::sign(
        &keyset,
        changed,
        &notes,
        Authorization::Plain,
        &[owner(1), owner(0)],
    )
    .unwrap();
    let b = Certificate::attest(&keys, &changed, &notes).unwrap();
    let ab = source::metadata_root(&keyset, &[a.clone(), b.clone()]).unwrap();
    assert_eq!(
        source::metadata_root(&keyset, &[b.clone(), a.clone(), a.clone()]).unwrap(),
        ab
    );
    assert_ne!(source::metadata_root(&keyset, &[a]).unwrap(), ab);
    assert_eq!(
        source::metadata_root(&keyset, &[]).unwrap(),
        crypto::tagged_hash("licash/claim-sources/v2", &[&0u32.to_be_bytes()])
    );
    assert!(
        source::metadata_root(&IssuerKeys::random(2).unwrap().keyset().unwrap(), &[b]).is_err()
    );
}

#[test]
fn public_timed_term_codec_preserves_existing_proposal_commitment_bytes() {
    let (_, _, _, signed) = fixture();
    let terms = signed.proposal().lock().unwrap().terms();
    let mut old_encoding = vec![1u8];
    old_encoding.extend([31; 32]);
    old_encoding.extend(1_000u32.to_be_bytes());
    old_encoding.extend(3u32.to_be_bytes());
    old_encoding.extend([41; 32]);
    assert_eq!(terms.to_bytes().as_slice(), old_encoding);
    assert_eq!(TimedTerms::from_bytes(&old_encoding).unwrap(), *terms);
    for n in 0..old_encoding.len() {
        assert!(TimedTerms::from_bytes(&old_encoding[..n]).is_err());
    }
    old_encoding.push(0);
    assert!(TimedTerms::from_bytes(&old_encoding).is_err());
    let bytes = signed.proposal().commitment_bytes();
    assert_eq!(
        Proposal::from_commitment_bytes(&bytes).unwrap().id(),
        signed.proposal().id()
    );
}

#[test]
fn receipt_body_and_owner_signatures_authenticate_without_payer_note_evidence() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    let body = signed.proposal().commitment_bytes();
    let signatures = signed.signatures().to_vec();
    drop(notes);
    drop(signed);
    let received = Proposal::from_commitment_bytes(&body).unwrap();
    let authenticated: Result<(), licash::Error> =
        cert.authenticate_source(&keyset, &received, &signatures);
    authenticated.unwrap();
    // This path yields neither a Note nor a partly verified SignedProposal.
    assert!(received.verify(&keyset, &[]).is_err());
    assert!(
        SignedProposal::from_parts(&keyset, received, &[], Authorization::Plain, signatures)
            .is_err()
    );
}

#[test]
fn certified_authentication_keeps_every_strict_missing_note_check() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    cert.authenticate_source(&keyset, signed.proposal(), signed.signatures())
        .unwrap();
    assert!(signed.verify(&keyset, &[]).is_err());
    assert!(cert.verify_source(&keyset, &signed, &[]).is_err());
    assert!(Certificate::attest(&keys, &signed, &[]).is_err());
    assert!(SignedProposal::from_parts(
        &keyset,
        signed.proposal().clone(),
        &[],
        Authorization::Plain,
        signed.signatures().to_vec()
    )
    .is_err());
    assert!(Proposal::new(
        &keyset,
        &[],
        signed.proposal().ephemeral(),
        signed.proposal().outputs().to_vec(),
        signed.proposal().lock().cloned()
    )
    .is_err());
}

#[test]
fn receipt_authentication_requires_all_owner_signatures_in_body_order() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    for signatures in [
        vec![],
        vec![signed.signatures()[0]],
        vec![signed.signatures()[0]; 3],
        vec![signed.signatures()[1], signed.signatures()[0]],
        vec![Signature([0; 64]), signed.signatures()[1]],
    ] {
        assert!(cert
            .authenticate_source(&keyset, signed.proposal(), &signatures)
            .is_err());
    }
}

#[test]
fn a_valid_certificate_cannot_authenticate_a_different_authorized_source() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    let p = signed.proposal();
    for field in 0..5 {
        let mut eph = p.ephemeral();
        let mut inputs = notes.clone();
        let mut owners = vec![owner(1), owner(0)];
        let mut outputs = p.outputs().to_vec();
        let mut terms = p.lock().unwrap().terms().to_bytes();
        let mut refunds = p.lock().unwrap().refund().to_vec();
        match field {
            0 => eph = point(53),
            1 => {
                inputs.reverse();
                owners.reverse();
            }
            2 => outputs.reverse(),
            3 => terms[36] ^= 1, // expiry, preserving a valid timed source
            _ => refunds.reverse(),
        }
        let proposal = Proposal::new(
            &keyset,
            &inputs,
            eph,
            outputs,
            Some(TimedLock::new(TimedTerms::from_bytes(&terms).unwrap(), refunds).unwrap()),
        )
        .unwrap();
        let other = SignedProposal::sign(&keyset, proposal, &inputs, Authorization::Plain, &owners)
            .unwrap();
        assert_eq!(
            cert.authenticate_source(&keyset, other.proposal(), other.signatures())
                .unwrap_err(),
            licash::Error::Protocol("source certificate authorized-body mismatch".into()),
            "field {field}"
        );
    }
}

#[test]
fn receipt_authentication_rechecks_the_expected_keyset_and_each_declared_denomination() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    let other = IssuerKeys::random(2).unwrap().keyset().unwrap();
    assert!(cert
        .authenticate_source(&other, signed.proposal(), signed.signatures())
        .is_err());
    let mut bytes = signed.proposal().commitment_bytes();
    let keyset_at = b"LICASH-SP\x02".len();
    bytes[keyset_at..keyset_at + 32].copy_from_slice(other.id());
    let wrong_context = Proposal::from_commitment_bytes(&bytes).unwrap();
    assert_eq!(
        cert.authenticate_source(&keyset, &wrong_context, signed.signatures())
            .unwrap_err(),
        licash::Error::Protocol("proposal input witness context".into())
    );

    // Keep each branch's total at eight while declaring unsupported seven
    // and supported one. These context-free bodies must fail before signatures.
    let input_at = keyset_at + 32 + 33 + 4;
    let pay_at = input_at + 2 * licash::note::MESSAGE_BYTES + 4;
    let refund_at = pay_at + 2 * (8 + 33 + 32) + 1 + TIMED_TERMS_BYTES + 4;
    for (at, width) in [
        (input_at, licash::note::MESSAGE_BYTES),
        (pay_at, 8 + 33 + 32),
        (refund_at, 8 + 33 + 32),
    ] {
        let mut bytes = signed.proposal().commitment_bytes();
        let amount_at = if at == input_at {
            at + b"licash/note/v3".len()
        } else {
            at
        };
        bytes[amount_at..amount_at + 8].copy_from_slice(&7u64.to_be_bytes());
        bytes[amount_at + width..amount_at + width + 8].copy_from_slice(&1u64.to_be_bytes());
        let unsupported = Proposal::from_commitment_bytes(&bytes).unwrap();
        assert_eq!(
            cert.authenticate_source(&keyset, &unsupported, signed.signatures())
                .unwrap_err(),
            licash::Error::UnknownDenomination(7)
        );
    }
}

#[test]
fn receipt_authentication_cannot_turn_an_untimed_source_into_timed_admission() {
    let (keys, keyset, notes, signed) = fixture();
    let cert = Certificate::attest(&keys, &signed, &notes).unwrap();
    let plain = Proposal::new(
        &keyset,
        &notes,
        point(19),
        signed.proposal().outputs().to_vec(),
        None,
    )
    .unwrap();
    let plain = SignedProposal::sign(
        &keyset,
        plain,
        &notes,
        Authorization::Plain,
        &[owner(1), owner(0)],
    )
    .unwrap();
    assert_eq!(
        cert.authenticate_source(&keyset, plain.proposal(), plain.signatures())
            .unwrap_err(),
        licash::Error::Protocol("timed certificate needs a timed source".into())
    );
}
