use k256::Scalar;
use licash::{
    crypto::{self, Point, ScalarBytes},
    note::Evidence,
    note::{Derivation, HoldRoot, Keyset, Message, MintLedger, Note, MESSAGE_BYTES},
    spend::{ChainProfile, Output, Proposal, TimedLock, TimedTerms},
};

const TAG: &[u8] = b"LICASH-SP\x02";
const HEADER: usize = TAG.len() + 32 + 33;
const OUT_BYTES: usize = 73;

fn point(key: u64) -> Point {
    Point::from_projective(&crypto::generator_mul(&Scalar::from(key)))
}

fn derive(denom: u64, index: u32) -> Derivation {
    Derivation::derive(
        denom,
        point(17),
        HoldRoot::from_seed(&[7; 32]).unwrap().public(),
        &[23; 32],
        index,
    )
    .unwrap()
}

fn mint(ledger: &mut MintLedger, denom: u64, index: u32) -> Note {
    let output = derive(denom, index);
    ledger
        .mint(denom, output.blinded().unwrap())
        .unwrap()
        .open(ledger.keyset(), &output)
        .unwrap()
}

fn output(denom: u64, index: u32) -> Output {
    Output::from_derivation(&derive(denom, index)).unwrap()
}

fn terms(field: Option<u8>) -> TimedTerms {
    TimedTerms::new(
        if field == Some(0) {
            ChainProfile::Core30Mainnet
        } else {
            ChainProfile::Core30DefaultRegtest
        },
        [if field == Some(1) { 32 } else { 31 }; 32],
        if field == Some(2) { 1_001 } else { 1_000 },
        if field == Some(3) { 4 } else { 3 },
        [if field == Some(4) { 42 } else { 41 }; 32],
    )
    .unwrap()
}

fn fixture(locked: bool) -> (MintLedger, Vec<Note>, Proposal) {
    let mut ledger = MintLedger::fresh(3).unwrap();
    let notes = vec![mint(&mut ledger, 4, 0), mint(&mut ledger, 4, 1)];
    let lock =
        locked.then(|| TimedLock::new(terms(None), vec![output(4, 12), output(4, 13)]).unwrap());
    let proposal = Proposal::new(
        ledger.keyset(),
        &notes,
        point(19),
        vec![output(4, 10), output(4, 11)],
        lock,
    )
    .unwrap();
    (ledger, notes, proposal)
}

fn pay_count_offset() -> usize {
    HEADER + 4 + 2 * MESSAGE_BYTES
}
fn presence_offset() -> usize {
    pay_count_offset() + 4 + 2 * OUT_BYTES
}

#[test]
fn canonical_body_roundtrips_and_identity_hashes_exactly_that_buffer() {
    for locked in [false, true] {
        let (ledger, notes, proposal) = fixture(locked);
        let bytes = proposal.commitment_bytes();
        assert_eq!(&bytes[..TAG.len()], TAG);
        assert_eq!(&bytes[TAG.len()..TAG.len() + 32], ledger.keyset().id());
        assert_eq!(&bytes[HEADER..HEADER + 4], &2u32.to_be_bytes());
        assert_eq!(
            &bytes[HEADER + 4..HEADER + 4 + MESSAGE_BYTES],
            &notes[0].message().to_bytes()
        );
        assert_eq!(
            &bytes[pay_count_offset()..pay_count_offset() + 4],
            &2u32.to_be_bytes()
        );
        assert_eq!(bytes[presence_offset()], u8::from(locked));
        assert_eq!(
            proposal.id().as_bytes(),
            &crypto::tagged_hash("licash/source-proposal/v2", &[&bytes])
        );
        let decoded = Proposal::from_commitment_bytes(&bytes).unwrap();
        assert_eq!(decoded, proposal);
        assert_eq!(decoded.commitment_bytes(), bytes);
        assert_eq!(
            decoded.verify(ledger.keyset(), &notes).unwrap(),
            notes
                .iter()
                .map(|n| n.message().identifier().unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(decoded.keyset_id(), ledger.keyset().id());
        assert_eq!(decoded.ephemeral(), point(19));
        assert_eq!(decoded.outputs()[1].blinded(), output(4, 11).blinded());
        assert_eq!(format!("{decoded:?}"), "SpendProposal(..)");
    }
}

#[test]
fn input_output_and_refund_order_are_identity_not_sorting_hints() {
    let (ledger, notes, proposal) = fixture(true);
    let build = |notes: &[Note], pay, refund| {
        Proposal::new(
            ledger.keyset(),
            notes,
            point(19),
            pay,
            Some(TimedLock::new(terms(None), refund).unwrap()),
        )
        .unwrap()
    };
    let reversed = vec![notes[1].clone(), notes[0].clone()];
    assert_ne!(
        build(
            &reversed,
            proposal.outputs().to_vec(),
            proposal.lock().unwrap().refund().to_vec()
        )
        .id(),
        proposal.id()
    );
    assert_ne!(
        build(
            &notes,
            vec![output(4, 11), output(4, 10)],
            proposal.lock().unwrap().refund().to_vec()
        )
        .id(),
        proposal.id()
    );
    let swapped = build(
        &notes,
        proposal.outputs().to_vec(),
        vec![output(4, 13), output(4, 12)],
    );
    assert_ne!(swapped.id(), proposal.id());
    assert_eq!(
        Proposal::from_commitment_bytes(&swapped.commitment_bytes())
            .unwrap()
            .lock()
            .unwrap()
            .refund()[0],
        output(4, 13)
    );
    assert!(proposal.verify(ledger.keyset(), &reversed).is_err());
}

#[test]
fn all_timed_terms_and_explicit_lock_presence_change_the_source_id() {
    let (ledger, notes, proposal) = fixture(true);
    for field in 0..5 {
        let lock = TimedLock::new(
            terms(Some(field)),
            proposal.lock().unwrap().refund().to_vec(),
        )
        .unwrap();
        let altered = Proposal::new(
            ledger.keyset(),
            &notes,
            point(19),
            proposal.outputs().to_vec(),
            Some(lock),
        )
        .unwrap();
        assert_ne!(altered.id(), proposal.id());
        assert_ne!(
            altered.lock().unwrap().terms().root(),
            proposal.lock().unwrap().terms().root()
        );
    }
    let plain = Proposal::new(
        ledger.keyset(),
        &notes,
        point(19),
        proposal.outputs().to_vec(),
        None,
    )
    .unwrap();
    assert_ne!(plain.id(), proposal.id());
    let t = terms(None);
    assert_eq!(
        t.root(),
        crypto::tagged_hash(
            "licash/timed-lock-terms/v1",
            &[
                &[1],
                &[31; 32],
                &1_000u32.to_be_bytes(),
                &3u32.to_be_bytes(),
                &[41; 32],
            ]
        )
    );
    assert_eq!(t.profile(), ChainProfile::Core30DefaultRegtest);
    assert_eq!(t.checkpoint(), &[31; 32]);
    assert_eq!((t.expiry(), t.depth(), *t.hash()), (1_000, 3, [41; 32]));
    for (expiry, depth) in [(0, 1), (1, 0), (u32::MAX, 1)] {
        assert!(TimedTerms::new(
            ChainProfile::Core30DefaultRegtest,
            [31; 32],
            expiry,
            depth,
            [41; 32]
        )
        .is_err());
    }
}

#[test]
fn output_target_unlink_commitment_and_ephemeral_are_bound() {
    let (ledger, notes, proposal) = fixture(false);
    let original = proposal.outputs()[0];
    for altered in [
        Output::new(4, point(53), *original.unlink_commitment()).unwrap(),
        Output::new(4, original.blinded(), [59; 32]).unwrap(),
    ] {
        let next = Proposal::new(
            ledger.keyset(),
            &notes,
            point(19),
            vec![altered, proposal.outputs()[1]],
            None,
        )
        .unwrap();
        assert_ne!(next.id(), proposal.id());
    }
    assert_ne!(
        Proposal::new(
            ledger.keyset(),
            &notes,
            point(29),
            proposal.outputs().to_vec(),
            None
        )
        .unwrap()
        .id(),
        proposal.id()
    );
    let d = derive(4, 10);
    let expected = licash::note::derive_output(&point(17), &[23; 32], 10).unwrap();
    assert_eq!(
        d.unlink_commitment(),
        licash::note::unlink_commitment(&expected.seed)
    );
    assert_eq!(original.denomination(), 4);
}

#[test]
fn decoder_rejects_truncation_counts_tags_trailing_and_invalid_points() {
    let (_, _, proposal) = fixture(true);
    let body = proposal.commitment_bytes();
    for n in 0..body.len() {
        assert!(
            Proposal::from_commitment_bytes(&body[..n]).is_err(),
            "prefix {n}"
        );
    }
    for field in 0..14 {
        let mut bytes = body.clone();
        let pay = pay_count_offset() + 4;
        match field {
            0 => bytes[0] ^= 1,
            1 => bytes.push(0),
            2 => bytes[HEADER..HEADER + 4].copy_from_slice(&u32::MAX.to_be_bytes()),
            3 => bytes[HEADER..HEADER + 4].fill(0),
            4 => bytes[pay_count_offset()..pay].copy_from_slice(&u32::MAX.to_be_bytes()),
            5 => bytes[pay_count_offset()..pay].fill(0),
            6 => bytes[presence_offset()] = 2,
            7 => bytes[presence_offset() + 1] = 2,
            8 => bytes[presence_offset() + 38..presence_offset() + 42].fill(0),
            9 => bytes[HEADER - 33..HEADER].fill(0),
            10 => bytes[pay + 8..pay + 41].fill(0),
            11 => bytes[pay..pay + 8].fill(0),
            12 => bytes[HEADER + 4 + 13] = b'1',
            _ => bytes[pay + 8..pay + 41].fill(0xff),
        }
        assert!(
            Proposal::from_commitment_bytes(&bytes).is_err(),
            "field {field}"
        );
    }
    assert!(Output::new(0, point(19), [0; 32]).is_err());
    assert!(Output::new(4, Point([0; 33]), [0; 32]).is_err());
}

#[test]
fn duplicate_inputs_outputs_and_unbalanced_or_empty_branches_are_refused() {
    let (ledger, notes, proposal) = fixture(true);
    let pay = proposal.outputs().to_vec();
    assert!(Proposal::new(ledger.keyset(), &[], point(19), pay.clone(), None).is_err());
    assert!(Proposal::new(ledger.keyset(), &notes, point(19), vec![], None).is_err());
    assert!(Proposal::new(
        ledger.keyset(),
        &[notes[0].clone(), notes[0].clone()],
        point(19),
        pay.clone(),
        None
    )
    .is_err());
    assert!(Proposal::new(
        ledger.keyset(),
        &notes,
        point(19),
        vec![pay[0], pay[0]],
        None
    )
    .is_err());
    assert!(Proposal::new(ledger.keyset(), &notes, point(19), vec![pay[0]], None).is_err());
    assert!(TimedLock::new(terms(None), vec![]).is_err());
    assert!(Proposal::new(
        ledger.keyset(),
        &notes,
        point(19),
        pay.clone(),
        Some(TimedLock::new(terms(None), vec![output(4, 12)]).unwrap())
    )
    .is_err());
    assert!(Proposal::new(
        ledger.keyset(),
        &notes,
        point(19),
        pay.clone(),
        Some(TimedLock::new(terms(None), pay).unwrap())
    )
    .is_err());
    assert!(Proposal::new(
        ledger.keyset(),
        &notes,
        Point([0; 33]),
        proposal.outputs().to_vec(),
        None
    )
    .is_err());

    let mut bytes = proposal.commitment_bytes();
    let first = bytes[HEADER + 4..HEADER + 4 + MESSAGE_BYTES].to_vec();
    bytes[HEADER + 4 + MESSAGE_BYTES..HEADER + 4 + 2 * MESSAGE_BYTES].copy_from_slice(&first);
    assert!(Proposal::from_commitment_bytes(&bytes).is_err());
}

#[test]
fn contextual_verification_is_required_after_successful_structural_decoding() {
    let (ledger, notes, proposal) = fixture(true);
    assert!(proposal.verify(ledger.keyset(), &notes[..1]).is_err());
    let mut other = MintLedger::fresh(3).unwrap();
    let other_notes = vec![mint(&mut other, 4, 0), mint(&mut other, 4, 1)];
    assert!(proposal.verify(other.keyset(), &other_notes).is_err());
    assert!(proposal.verify(ledger.keyset(), &other_notes).is_err());
    for refund in [false, true] {
        let mut bytes = proposal.commitment_bytes();
        let start = if refund {
            presence_offset() + 1 + 73 + 4
        } else {
            pay_count_offset() + 4
        };
        bytes[start..start + 8].copy_from_slice(&3u64.to_be_bytes());
        bytes[start + OUT_BYTES..start + OUT_BYTES + 8].copy_from_slice(&5u64.to_be_bytes());
        // Each branch still totals eight, but these keys do not exist.
        let decoded = Proposal::from_commitment_bytes(&bytes).unwrap();
        assert!(decoded.verify(ledger.keyset(), &notes).is_err());
    }
    let mut bytes = proposal.commitment_bytes();
    bytes[TAG.len()] ^= 1;
    assert!(Proposal::from_commitment_bytes(&bytes)
        .unwrap()
        .verify(ledger.keyset(), &notes)
        .is_err());
    let mut bytes = proposal.commitment_bytes();
    bytes[HEADER + 4 + 54..HEADER + 4 + 86].copy_from_slice(&point(71).x_only());
    let changed_q = Proposal::from_commitment_bytes(&bytes).unwrap();
    assert_ne!(changed_q.id(), proposal.id());
    assert!(changed_q.verify(ledger.keyset(), &notes).is_err());
}

#[test]
fn source_vectors_are_not_limited_by_the_32_claim_item_ceiling() {
    let mut ledger = MintLedger::fresh(2).unwrap();
    let notes: Vec<_> = (0..33).map(|i| mint(&mut ledger, 4, i)).collect();
    let pay: Vec<_> = (100..133).map(|i| output(4, i)).collect();
    let proposal = Proposal::new(ledger.keyset(), &notes, point(19), pay, None).unwrap();
    let decoded = Proposal::from_commitment_bytes(&proposal.commitment_bytes()).unwrap();
    assert_eq!(decoded.inputs().len(), 33);
    assert_eq!(decoded.outputs().len(), 33);
    assert_eq!(decoded.verify(ledger.keyset(), &notes).unwrap().len(), 33);
}

#[test]
fn aggregate_values_are_exact_u128_not_wrapping_u64() {
    let mut ledger = MintLedger::fresh(63).unwrap();
    let notes = vec![
        mint(&mut ledger, 1u64 << 63, 0),
        mint(&mut ledger, 1u64 << 63, 1),
        mint(&mut ledger, 1, 2),
    ];
    let pay = vec![
        output(1u64 << 63, 10),
        output(1u64 << 63, 11),
        output(1, 12),
    ];
    let proposal = Proposal::new(ledger.keyset(), &notes, point(19), pay, None).unwrap();
    assert_eq!(
        Proposal::from_commitment_bytes(&proposal.commitment_bytes()).unwrap(),
        proposal
    );
    assert!(Proposal::new(
        ledger.keyset(),
        &notes,
        point(19),
        vec![output(1, 12)],
        None
    )
    .is_err());
}

#[test]
fn all_valid_issuance_evidence_variants_share_the_same_proposal_identity() {
    // Known test keys permit independent valid proofs of all three variants,
    // without adding a production secret-export or unlink-answer API.
    let scalar = Scalar::from(31u64);
    let public = point(31);
    let credential = point(43).x_only();
    let mut records = 4u64.to_be_bytes().to_vec();
    records.extend(public.0);
    let format = crypto::tagged_hash(
        "licash/note-format/v5",
        &[
            b"licash/note/v3",
            b"LICASH-V2-secp256k1_XMD:SHA-256_SSWU_RO_",
        ],
    );
    let id = crypto::tagged_hash(
        "licash/keyset/v2",
        &[&format, &credential, &1u32.to_be_bytes(), &records],
    );
    let mut encoded = b"LICASH-KS\x05".to_vec();
    encoded.extend(id);
    encoded.extend(credential);
    encoded.extend(1u32.to_be_bytes());
    encoded.extend(records);
    let keyset = Keyset::from_bytes(&encoded).unwrap();
    let derivation = derive(4, 0);
    let y = derivation
        .message()
        .identifier()
        .unwrap()
        .to_projective()
        .unwrap();
    let b = derivation.blinded().unwrap().to_projective().unwrap();
    let c = y * scalar;
    let blinded_sig = b * scalar;
    let commit = crypto::dleq_commit(&Scalar::from(47u64), &b);
    let unlock = Scalar::from(53u64);
    let variants = [
        Evidence::Unlinked(crypto::dleq_prove(&scalar, &y, &c)),
        Evidence::Linked {
            dleq: crypto::dleq_prove(&scalar, &b, &blinded_sig),
            blinding: *derivation.blinding(),
            commit,
        },
        {
            let mask = crypto::generator_mul(&Scalar::from(59u64));
            let (_, seal) = crypto::seal_prove(&scalar, &unlock, &b, &mask, &commit.to_bytes());
            Evidence::Granted {
                seal,
                blinding: *derivation.blinding(),
                commit,
                unlock: ScalarBytes::from_scalar(&unlock),
                mask: Point::from_projective(&mask),
            }
        },
    ];
    let mut expected = None;
    for evidence in variants {
        let note = Note::from_parts(
            &keyset,
            id,
            derivation.message().clone(),
            Point::from_projective(&c),
            evidence,
        )
        .unwrap();
        let proposal = Proposal::new(
            &keyset,
            std::slice::from_ref(&note),
            point(19),
            vec![output(4, 10)],
            None,
        )
        .unwrap();
        assert_eq!(
            proposal.verify(&keyset, &[note]).unwrap(),
            vec![Point::from_projective(&y)]
        );
        if let Some(id) = expected {
            assert_eq!(proposal.id(), id);
        } else {
            expected = Some(proposal.id());
        }
    }
    assert!(Message::new(0, point(17).x_only(), point(19).x_only()).is_err());
}
