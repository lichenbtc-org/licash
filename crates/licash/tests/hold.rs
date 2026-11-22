use k256::Scalar;
use licash::{
    crypto::{self, Point, ScalarBytes, Signature},
    hold::{authorization_root, Context, Envelope, Record, RECORD_BYTES},
    note::{Derivation, HoldRoot, Message, PUBLIC_FIELDS_BYTES},
};

fn entries(count: u32) -> Vec<(Message, ScalarBytes)> {
    let root = HoldRoot::from_seed(&[7; 32]).unwrap();
    let spend = Point::from_projective(&crypto::generator_mul(&Scalar::from(17u64)));
    let mut entries: Vec<_> = (0..count)
        .map(|index| {
            let d = Derivation::derive(4, spend, root.public(), &[23; 32], index).unwrap();
            (d.message().clone(), d.hold_key(&root).unwrap())
        })
        .collect();
    entries.sort_by_key(|(message, _)| message.identifier().unwrap());
    entries
}

fn messages(entries: &[(Message, ScalarBytes)]) -> Vec<Message> {
    entries.iter().map(|(message, _)| message.clone()).collect()
}

fn context(root: &[u8; 32]) -> Context {
    Context {
        base: [31; 32],
        deposit: [37; 36],
        amount: 128,
        // Test fixture only, not a complete native claim/E formula.
        claim_digest: crypto::tagged_hash("test/claim-with-holds", &[root]),
    }
}

#[test]
fn thirty_two_hold_records_sign_only_with_their_independent_q_keys() {
    let entries = entries(32);
    let root = authorization_root(&messages(&entries), 32).unwrap();
    let ctx = context(&root);
    let envelope = Envelope::sign(ctx, &entries, 32).unwrap();
    envelope.verify(&ctx, &root, 32).unwrap();
    assert_eq!(envelope.records().len(), 32);
    assert_eq!(envelope.context(), &ctx);
    for record in envelope.records() {
        let digest = crypto::tagged_hash(
            "licash/hold-note-authorization/v2",
            &[
                &ctx.base,
                &ctx.deposit,
                &ctx.amount.to_be_bytes(),
                &ctx.claim_digest,
                &record.message.public_fields(),
            ],
        );
        assert_eq!(ctx.signing_digest(&record.message), digest);
        crypto::schnorr_verify(record.message.hold(), &digest, &record.sig).unwrap();
        assert!(crypto::schnorr_verify(record.message.owner(), &digest, &record.sig).is_err());
    }
    let bytes = envelope.to_bytes();
    assert_eq!(RECORD_BYTES, 136);
    assert_eq!(bytes.len(), b"LICASH-HOLD\x02".len() + 104 + 4 + 32 * 136);
    assert_eq!(bytes.len(), 4_472);
    assert_eq!(
        Envelope::from_bytes(&ctx, &root, 32, &bytes).unwrap(),
        envelope
    );
}

#[test]
fn request_final_digest_deposit_amount_and_e_are_all_scoped() {
    let entries = entries(2);
    let root = authorization_root(&messages(&entries), 2).unwrap();
    let ctx = context(&root);
    let envelope = Envelope::sign(ctx, &entries, 2).unwrap();
    for field in 0..4 {
        let mut changed = ctx;
        match field {
            0 => changed.base[0] ^= 1,
            1 => changed.deposit[0] ^= 1,
            2 => changed.amount += 1,
            _ => changed.claim_digest[0] ^= 1,
        }
        assert!(envelope.verify(&changed, &root, 2).is_err());
        assert!(Envelope::from_records(changed, &root, envelope.records().to_vec(), 2).is_err());
        assert!(Envelope::from_bytes(&changed, &root, 2, &envelope.to_bytes()).is_err());
    }
}

#[test]
fn the_unsigned_root_matches_the_counted_compact_model_not_signature_bytes() {
    let entries = entries(2);
    let messages = messages(&entries);
    let mut unsigned = 2u32.to_be_bytes().to_vec();
    for message in &messages {
        assert_eq!(
            message.public_fields().as_slice(),
            &message.to_bytes()[14..]
        );
        assert_eq!(message.public_fields().len(), PUBLIC_FIELDS_BYTES);
        assert_eq!(
            Message::from_public_fields(&message.public_fields()).unwrap(),
            *message
        );
        unsigned.extend(message.public_fields());
    }
    let root = authorization_root(&messages, 2).unwrap();
    assert_eq!(
        root,
        crypto::tagged_hash("licash/hold-set/v2", &[&unsigned])
    );
    let ctx = context(&root);
    let a = Envelope::sign(ctx, &entries, 2).unwrap();
    let b = Envelope::sign(ctx, &entries, 2).unwrap();
    assert_ne!(a.to_bytes(), b.to_bytes());
    a.verify(&ctx, &root, 2).unwrap();
    b.verify(&ctx, &root, 2).unwrap();
    assert_eq!(a.clone().to_bytes(), a.to_bytes());
}

#[test]
fn a_valid_signature_cannot_replace_the_claims_expected_hold_set() {
    let entries = entries(2);
    let root = authorization_root(&messages(&entries), 2).unwrap();
    let ctx = context(&root);
    let envelope = Envelope::sign(ctx, &entries, 2).unwrap();
    let subset_root = authorization_root(&messages(&entries[..1]), 2).unwrap();
    assert!(envelope.verify(&ctx, &subset_root, 2).is_err());
    assert!(Envelope::from_records(ctx, &root, envelope.records()[..1].to_vec(), 2).is_err());
    assert!(Envelope::from_bytes(&ctx, &subset_root, 2, &envelope.to_bytes()).is_err());
    let mut records = envelope.records().to_vec();
    records[0].sig = Signature([0; 64]);
    assert!(Envelope::from_records(ctx, &root, records, 2).is_err());
}

#[test]
fn zero_wrong_and_spending_keys_are_not_hold_authority() {
    let mut entries = entries(2);
    let root = authorization_root(&messages(&entries), 2).unwrap();
    let ctx = context(&root);
    for key in [
        ScalarBytes([0; 32]),
        ScalarBytes([0xff; 32]),
        ScalarBytes::from_scalar(&Scalar::from(17u64)),
        entries[1].1,
    ] {
        entries[0].1 = key;
        assert!(Envelope::sign(ctx, &entries, 2).is_err());
    }
}

#[test]
fn notes_sharing_a_hold_key_cannot_exchange_authorization_signatures() {
    let (first, key) = entries(1).remove(0);
    let second = Message::new(8, *first.owner(), *first.hold()).unwrap();
    let mut entries = vec![(first, key), (second, key)];
    entries.sort_by_key(|(m, _)| m.identifier().unwrap());
    let root = authorization_root(&messages(&entries), 2).unwrap();
    let ctx = context(&root);
    let envelope = Envelope::sign(ctx, &entries, 2).unwrap();
    envelope.verify(&ctx, &root, 2).unwrap();
    let mut records = envelope.records().to_vec();
    let first_sig = records[0].sig;
    records[0].sig = records[1].sig;
    records[1].sig = first_sig;
    assert!(Envelope::from_records(ctx, &root, records, 2).is_err());
}

#[test]
fn context_only_signatures_are_not_accepted_as_note_authorizations() {
    let entries = entries(1);
    let root = authorization_root(&messages(&entries), 1).unwrap();
    let ctx = context(&root);
    let old_digest = crypto::tagged_hash(
        "licash/hold-authorization/v2",
        &[
            &ctx.base,
            &ctx.deposit,
            &ctx.amount.to_be_bytes(),
            &ctx.claim_digest,
        ],
    );
    let records = vec![Record {
        message: entries[0].0.clone(),
        sig: crypto::schnorr_sign(&entries[0].1.to_scalar().unwrap(), &old_digest).unwrap(),
    }];
    assert!(Envelope::from_records(ctx, &root, records, 1).is_err());
}

#[test]
fn ordering_duplicates_and_caller_budgets_are_enforced_without_a_source_cap() {
    let entries = entries(33);
    let ordered = messages(&entries);
    let root = authorization_root(&ordered, 33).unwrap();
    let ctx = context(&root);
    let envelope = Envelope::sign(ctx, &entries, 33).unwrap();
    assert!(authorization_root(&ordered, 32).is_err());
    assert!(envelope.verify(&ctx, &root, 32).is_err());
    assert!(Envelope::from_bytes(&ctx, &root, 32, &envelope.to_bytes()).is_err());
    let mut reversed = ordered.clone();
    reversed.reverse();
    assert!(authorization_root(&reversed, 33).is_err());
    assert!(authorization_root(&[ordered[0].clone(), ordered[0].clone()], 2).is_err());
    let empty_root = crypto::tagged_hash("licash/hold-set/v2", &[&0u32.to_be_bytes()]);
    let empty = Envelope::sign(context(&empty_root), &[], 0).unwrap();
    empty.verify(&context(&empty_root), &empty_root, 0).unwrap();
    assert_eq!(
        Envelope::from_bytes(&context(&empty_root), &empty_root, 0, &empty.to_bytes()).unwrap(),
        empty
    );
}

#[test]
fn malformed_envelopes_have_no_missing_q_fallback() {
    let entries = entries(2);
    let root = authorization_root(&messages(&entries), 2).unwrap();
    let ctx = context(&root);
    let bytes = Envelope::sign(ctx, &entries, 2).unwrap().to_bytes();
    for n in 0..bytes.len() {
        assert!(Envelope::from_bytes(&ctx, &root, 2, &bytes[..n]).is_err());
    }
    let header = b"LICASH-HOLD\x02".len() + 104 + 4;
    for field in 0..6 {
        let mut changed = bytes.clone();
        match field {
            0 => changed[0] ^= 1,
            1 => changed.push(0),
            2 => changed[header - 4..header].copy_from_slice(&u32::MAX.to_be_bytes()),
            3 => changed[header..header + 8].fill(0),
            4 => changed[header + 72..header + 104].fill(0xff),
            _ => changed[header + 104..header + 168].fill(0),
        }
        assert!(Envelope::from_bytes(&ctx, &root, 2, &changed).is_err());
    }
    assert!(Envelope::from_bytes(&ctx, &root, 2, &bytes[header..]).is_err());
}

#[test]
fn public_fields_are_not_implicitly_tagged_notes_or_claim_eligibility() {
    let entries = entries(1);
    let message = &entries[0].0;
    let bytes = message.public_fields();
    assert!(Message::from_bytes(&bytes).is_err());
    for n in 0..bytes.len() {
        assert!(Message::from_public_fields(&bytes[..n]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(Message::from_public_fields(&trailing).is_err());
    let root = authorization_root(&messages(&entries), 1).unwrap();
    let ctx = context(&root);
    let records = Envelope::sign(ctx, &entries, 1).unwrap().records().to_vec();
    let record: &Record = &records[0];
    assert_eq!(format!("{record:?}"), "HoldRecord(..)");
    assert_eq!(format!("{ctx:?}"), "HoldContext(..)");
    // These constructors deliberately require no issuer C or DLEQ: Q can
    // authorize a hold, never establish that this Message is recoverable cash.
    assert_eq!(
        Envelope::from_records(ctx, &root, records, 1)
            .unwrap()
            .records()
            .len(),
        1
    );
}
