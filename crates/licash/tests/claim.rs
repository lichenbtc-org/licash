//! Public metadata checks only. None of these objects is a recovery proof.
use k256::Scalar;
use licash::{
    authorization::{Authorization, SignedProposal},
    chain::ActivationRef,
    claim::{ActivationRecord, Branch, Context, Item, Parts, Source, UnsignedClaim},
    crypto::{self, Point, ScalarBytes},
    hold::{self, Envelope},
    note::Evidence,
    note::{Derivation, HoldRoot, IssuerKeys, Keyset, Message, Note},
    source::{self, Certificate},
    spend::{ChainProfile, Output, Proposal, ProposalId, TimedLock, TimedTerms},
};
use sha2::{Digest, Sha256};

fn point(value: u64) -> Point {
    Point::from_projective(&crypto::generator_mul(&Scalar::from(value)))
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
fn context() -> Context {
    Context {
        base: [31; 32],
        deposit: [37; 36],
        cap: 128,
    }
}
fn canonical(mut messages: Vec<Message>) -> Vec<Message> {
    messages.sort_by_key(|m| m.identifier().unwrap());
    messages
}
fn settled(count: u32) -> Parts {
    let messages: Vec<_> = (0..count).map(|i| derive(i).message().clone()).collect();
    Parts {
        items: messages.iter().cloned().map(Item::Settled).collect(),
        sources: vec![],
        activations: vec![],
        authorizations: canonical(messages),
    }
}
fn pending(
    source: ProposalId,
    branch: Branch,
    index: u32,
    d: &Derivation,
    preimage: Option<[u8; 32]>,
) -> Item {
    Item::Pending {
        message: d.message().clone(),
        source,
        branch,
        index,
        blinding: *d.blinding(),
        preimage,
    }
}
fn terms() -> TimedTerms {
    TimedTerms::new(
        ChainProfile::Core30DefaultRegtest,
        [47; 32],
        1_000,
        3,
        Sha256::digest([41; 32]).into(),
    )
    .unwrap()
}
fn source_fixture(keys: &IssuerKeys, keyset: &Keyset) -> (SignedProposal, Vec<Note>, Certificate) {
    source_fixture_for_output(keys, keyset, 10, 19)
}
fn source_fixture_for_output(
    keys: &IssuerKeys,
    keyset: &Keyset,
    output: u32,
    ephemeral: u64,
) -> (SignedProposal, Vec<Note>, Certificate) {
    let d = derive(0);
    let proof = keys.prove_blinded(4, d.blinded().unwrap()).unwrap();
    let input = Note::from_parts(
        keyset,
        *keyset.id(),
        d.message().clone(),
        proof.open_point(keyset, &d).unwrap(),
        Evidence::Linked {
            dleq: proof.dleq(),
            blinding: *d.blinding(),
            commit: crypto::dleq_commit(
                &Scalar::from(71u64),
                &d.blinded().unwrap().to_projective().unwrap(),
            ),
        },
    )
    .unwrap();
    let notes = vec![input];
    let proposal = Proposal::new(
        keyset,
        &notes,
        point(ephemeral),
        vec![Output::from_derivation(&derive(output)).unwrap()],
        Some(TimedLock::new(terms(), vec![Output::from_derivation(&derive(11)).unwrap()]).unwrap()),
    )
    .unwrap();
    let owner = Scalar::from(17u64)
        + licash::note::derive_output(&point(17), &[23; 32], 0)
            .unwrap()
            .tweak
            .to_scalar()
            .unwrap();
    let signed =
        SignedProposal::sign(keyset, proposal, &notes, Authorization::Plain, &[owner]).unwrap();
    let certificate = Certificate::attest(keys, &signed, &notes).unwrap();
    (signed, notes, certificate)
}
fn admitted(cert: Certificate) -> Parts {
    let output = derive(10);
    let id = cert.metadata().source_id();
    Parts {
        items: vec![pending(id, Branch::Pay, 0, &output, Some([41; 32]))],
        sources: vec![Source::Admitted(cert)],
        activations: vec![],
        authorizations: vec![output.message().clone()],
    }
}

#[test]
fn complete_settled_metadata_binds_thirty_two_independent_q_authorizations() {
    let keys = IssuerKeys::random(2).unwrap().keyset().unwrap();
    let claim = UnsignedClaim::new(context(), &keys, 128, settled(32), 32).unwrap();
    let root = HoldRoot::from_seed(&[7; 32]).unwrap();
    let mut entries: Vec<_> = (0..32)
        .map(|i| {
            let d = derive(i);
            (d.message().clone(), d.hold_key(&root).unwrap())
        })
        .collect();
    entries.sort_by_key(|(message, _)| message.identifier().unwrap());
    let a = Envelope::sign(claim.hold_context(), &entries, 32).unwrap();
    let b = Envelope::sign(claim.hold_context(), &entries, 32).unwrap();
    assert_ne!(a.to_bytes(), b.to_bytes());
    a.verify(&claim.hold_context(), claim.hold_root(), 32)
        .unwrap();
    b.verify(&claim.hold_context(), claim.hold_root(), 32)
        .unwrap();
    assert_eq!(claim.amount(), 128);
    assert_eq!(claim.parts().items.len(), 32);
    assert_eq!(claim.keyset_id(), keys.id());
    assert_eq!(claim.context(), &context());
    assert_eq!(format!("{claim:?}"), "UnsignedClaim(..)");
}

#[test]
fn the_e_formula_counts_and_binds_every_item() {
    let keys = IssuerKeys::random(2).unwrap().keyset().unwrap();
    let claim = UnsignedClaim::new(context(), &keys, 8, settled(2), 2).unwrap();
    let mut items = 2u32.to_be_bytes().to_vec();
    for item in &claim.parts().items {
        items.push(0);
        items.extend(item.message().public_fields());
    }
    let empty = 0u32.to_be_bytes();
    let body = crypto::tagged_hash(
        "licash/claim-body/v2",
        &[
            &context().base,
            &context().deposit,
            keys.id(),
            &8u32.to_be_bytes(),
            &crypto::tagged_hash("licash/claim-items/v2", &[&items]),
            &crypto::tagged_hash("licash/claim-source-references/v2", &[&empty]),
            &source::metadata_root(&keys, &[]).unwrap(),
            &crypto::tagged_hash("licash/claim-activations/v2", &[&empty]),
        ],
    );
    let hold = hold::authorization_root(&claim.parts().authorizations, 2).unwrap();
    assert_eq!(
        claim.digest(),
        &crypto::tagged_hash(
            "licash/claim/v2",
            &[
                &body,
                &hold,
                &crypto::tagged_hash("licash/hold-exemptions/v2", &[&empty])
            ]
        )
    );
}

#[test]
fn context_amount_item_order_keyset_and_full_messages_change_e() {
    let keyset = IssuerKeys::random(2).unwrap().keyset().unwrap();
    let original = UnsignedClaim::new(context(), &keyset, 8, settled(2), 2).unwrap();
    for field in 0..5 {
        let mut ctx = context();
        let mut parts = settled(2);
        let mut amount = 8;
        match field {
            0 => ctx.base[0] ^= 1,
            1 => ctx.deposit[0] ^= 1,
            2 => amount = 4,
            3 => parts.items.reverse(),
            _ => {
                let old = parts.items[0].message();
                parts.items[0] = Item::Settled(Message::new(4, *old.hold(), *old.owner()).unwrap());
                parts.authorizations =
                    canonical(parts.items.iter().map(|i| i.message().clone()).collect());
            }
        }
        assert_ne!(
            UnsignedClaim::new(ctx, &keyset, amount, parts, 2)
                .unwrap()
                .digest(),
            original.digest()
        );
    }
    let other = IssuerKeys::random(2).unwrap().keyset().unwrap();
    assert_ne!(
        UnsignedClaim::new(context(), &other, 8, settled(2), 2)
            .unwrap()
            .digest(),
        original.digest()
    );
}

#[test]
fn certificate_signatures_do_not_enter_e_and_duplicate_metadata_is_canonical() {
    let issuer = IssuerKeys::random(2).unwrap();
    let keyset = issuer.keyset().unwrap();
    let (signed, notes, a) = source_fixture(&issuer, &keyset);
    let b = Certificate::attest(&issuer, &signed, &notes).unwrap();
    assert_ne!(a.to_bytes(), b.to_bytes());
    let one = UnsignedClaim::new(context(), &keyset, 4, admitted(a.clone()), 1).unwrap();
    let two = UnsignedClaim::new(context(), &keyset, 4, admitted(b.clone()), 1).unwrap();
    assert_eq!(one.digest(), two.digest());
    let mut repeated = admitted(a);
    repeated.sources.push(Source::Admitted(b));
    let repeated = UnsignedClaim::new(context(), &keyset, 4, repeated, 1).unwrap();
    assert_eq!(one.digest(), repeated.digest());
    assert_eq!(repeated.parts().sources.len(), 1);
    // Only the claimed output needs Q authority, not its certified spent input.
    assert_eq!(one.parts().authorizations.len(), 1);
}

#[test]
fn own_inputs_union_has_an_explicit_budget_not_a_thirty_two_source_input_cap() {
    let keyset = IssuerKeys::random(2).unwrap().keyset().unwrap();
    let inputs: Vec<_> = (0..33).map(|i| derive(i).message().clone()).collect();
    let mut ys: Vec<_> = inputs.iter().map(|m| m.identifier().unwrap()).collect();
    ys.sort();
    let id = ProposalId::from_bytes([59; 32]);
    let output = derive(100);
    let mut auth = inputs;
    auth.push(output.message().clone());
    let parts = Parts {
        items: vec![pending(id, Branch::Pay, 0, &output, Some([41; 32]))],
        sources: vec![Source::OwnInputs {
            id,
            inputs: ys,
            terms: terms(),
        }],
        activations: vec![],
        authorizations: canonical(auth),
    };
    UnsignedClaim::new(context(), &keyset, 4, parts.clone(), 34).unwrap();
    assert!(UnsignedClaim::new(context(), &keyset, 4, parts.clone(), 32).is_err());
    let mut missing = parts.clone();
    missing.authorizations.pop();
    assert!(UnsignedClaim::new(context(), &keyset, 4, missing, 34).is_err());
    let mut extra = parts;
    extra.authorizations.push(derive(101).message().clone());
    extra.authorizations = canonical(extra.authorizations);
    assert!(UnsignedClaim::new(context(), &keyset, 4, extra, 35).is_err());
}

#[test]
fn fallbacks_link_existing_settled_inputs_but_add_no_unchallenged_value() {
    let keyset = IssuerKeys::random(2).unwrap().keyset().unwrap();
    let id = ProposalId::from_bytes([61; 32]);
    let input = derive(0);
    let output = derive(10);
    let parts = Parts {
        items: vec![
            Item::Settled(input.message().clone()),
            pending(id, Branch::Pay, 0, &output, None),
        ],
        sources: vec![Source::Plain {
            id,
            inputs: vec![input.message().identifier().unwrap()],
        }],
        activations: vec![],
        authorizations: canonical(vec![input.message().clone(), output.message().clone()]),
    };
    UnsignedClaim::new(context(), &keyset, 4, parts.clone(), 2).unwrap();
    assert!(UnsignedClaim::new(context(), &keyset, 8, parts.clone(), 2).is_err());
    let mut missing = parts;
    missing.items.remove(0);
    assert!(UnsignedClaim::new(context(), &keyset, 4, missing, 2).is_err());
}

#[test]
fn conflicting_source_classes_opposite_branches_and_duplicate_positions_fail() {
    let issuer = IssuerKeys::random(2).unwrap();
    let keyset = issuer.keyset().unwrap();
    let (_, _, cert) = source_fixture(&issuer, &keyset);
    let id = cert.metadata().source_id();
    let mut conflicting = admitted(cert.clone());
    conflicting.sources.push(Source::OwnInputs {
        id,
        inputs: cert.metadata().inputs().to_vec(),
        terms: terms(),
    });
    assert!(UnsignedClaim::new(context(), &keyset, 4, conflicting, 2).is_err());
    for branch in [Branch::Pay, Branch::Refund] {
        let mut parts = admitted(cert.clone());
        let d = derive(11);
        parts.items.push(pending(
            id,
            branch,
            0,
            &d,
            (branch == Branch::Pay).then_some([41; 32]),
        ));
        parts.authorizations = canonical(vec![derive(10).message().clone(), d.message().clone()]);
        assert!(UnsignedClaim::new(context(), &keyset, 4, parts, 2).is_err());
    }
}

#[test]
fn activation_references_are_unsigned_metadata_not_verified_immunity() {
    let issuer = IssuerKeys::random(2).unwrap();
    let keyset = issuer.keyset().unwrap();
    let (_, _, cert) = source_fixture(&issuer, &keyset);
    let id = cert.metadata().source_id();
    let base = UnsignedClaim::new(context(), &keyset, 4, admitted(cert.clone()), 1).unwrap();
    let record = ActivationRecord {
        source: id,
        reference: ActivationRef {
            height: 71,
            block_hash: [73; 32],
            txid: [79; 32],
            output: 1,
        },
    };
    let mut parts = admitted(cert.clone());
    parts.activations.push(record);
    let referenced = UnsignedClaim::new(context(), &keyset, 4, parts.clone(), 1).unwrap();
    assert_ne!(base.digest(), referenced.digest());
    // This arbitrary reference is only committed here. A complete predicate
    // must positively verify it; this is not evidence that a block exists.
    parts.activations.push(record);
    assert!(UnsignedClaim::new(context(), &keyset, 4, parts, 1).is_err());
    let mut own = admitted(cert.clone());
    own.sources = vec![Source::OwnInputs {
        id,
        inputs: cert.metadata().inputs().to_vec(),
        terms: terms(),
    }];
    own.authorizations = canonical(vec![
        derive(0).message().clone(),
        derive(10).message().clone(),
    ]);
    own.activations.push(record);
    assert!(UnsignedClaim::new(context(), &keyset, 4, own, 2).is_err());
}

#[test]
fn refund_metadata_has_no_holder_clock_gate_or_activation_immunity_marker() {
    let issuer = IssuerKeys::random(2).unwrap();
    let keyset = issuer.keyset().unwrap();
    let (_, _, cert) = source_fixture(&issuer, &keyset);
    let id = cert.metadata().source_id();
    let mut parts = admitted(cert);
    let output = derive(11);
    parts.items = vec![pending(id, Branch::Refund, 0, &output, None)];
    parts.authorizations = vec![output.message().clone()];
    UnsignedClaim::new(context(), &keyset, 4, parts.clone(), 1).unwrap();
    parts.activations.push(ActivationRecord {
        source: id,
        reference: ActivationRef {
            height: 71,
            block_hash: [73; 32],
            txid: [79; 32],
            output: 0,
        },
    });
    assert!(UnsignedClaim::new(context(), &keyset, 4, parts, 1).is_err());
}

#[test]
fn a_certified_input_cannot_be_recounted_as_a_separate_claim_item() {
    let issuer = IssuerKeys::random(2).unwrap();
    let keyset = issuer.keyset().unwrap();
    let (_, _, cert) = source_fixture(&issuer, &keyset);
    let mut parts = admitted(cert);
    parts
        .items
        .insert(0, Item::Settled(derive(0).message().clone()));
    // Self-evident in-claim double value is not a stale item left for masks.
    // Neither removing its Q authorization nor supplying it fixes that.
    assert_eq!(
        UnsignedClaim::new(context(), &keyset, 4, parts.clone(), 2).unwrap_err(),
        licash::Error::Protocol("overlapping timed claim value".into())
    );
    parts.authorizations = canonical(vec![
        derive(0).message().clone(),
        derive(10).message().clone(),
    ]);
    assert_eq!(
        UnsignedClaim::new(context(), &keyset, 4, parts, 2).unwrap_err(),
        licash::Error::Protocol("overlapping timed claim value".into())
    );
}

#[test]
fn own_input_value_cannot_be_claimed_both_as_input_and_timed_output() {
    let keyset = IssuerKeys::random(2).unwrap().keyset().unwrap();
    let id = ProposalId::from_bytes([89; 32]);
    let input = derive(0);
    let output = derive(10);
    let parts = Parts {
        items: vec![
            Item::Settled(input.message().clone()),
            pending(id, Branch::Refund, 0, &output, None),
        ],
        sources: vec![Source::OwnInputs {
            id,
            inputs: vec![input.message().identifier().unwrap()],
            terms: terms(),
        }],
        activations: vec![],
        authorizations: canonical(vec![input.message().clone(), output.message().clone()]),
    };
    assert_eq!(
        UnsignedClaim::new(context(), &keyset, 8, parts, 2).unwrap_err(),
        licash::Error::Protocol("overlapping timed claim value".into())
    );
}

#[test]
fn distinct_timed_sources_with_shared_inputs_are_not_additive() {
    let issuer = IssuerKeys::random(2).unwrap();
    let keyset = issuer.keyset().unwrap();
    let (_, _, a) = source_fixture(&issuer, &keyset);
    let (_, _, b) = source_fixture_for_output(&issuer, &keyset, 20, 29);
    assert_ne!(a.metadata().source_id(), b.metadata().source_id());
    for own_a in [false, true] {
        for own_b in [false, true] {
            let make = |cert: &Certificate, own| {
                if own {
                    Source::OwnInputs {
                        id: cert.metadata().source_id(),
                        inputs: cert.metadata().inputs().to_vec(),
                        terms: terms(),
                    }
                } else {
                    Source::Admitted(cert.clone())
                }
            };
            let mut auth = vec![derive(10).message().clone(), derive(20).message().clone()];
            if own_a || own_b {
                auth.push(derive(0).message().clone());
            }
            let parts = Parts {
                items: vec![
                    pending(
                        a.metadata().source_id(),
                        Branch::Pay,
                        0,
                        &derive(10),
                        Some([41; 32]),
                    ),
                    pending(
                        b.metadata().source_id(),
                        Branch::Pay,
                        0,
                        &derive(20),
                        Some([41; 32]),
                    ),
                ],
                sources: vec![make(&a, own_a), make(&b, own_b)],
                activations: vec![],
                authorizations: canonical(auth),
            };
            assert_eq!(
                UnsignedClaim::new(context(), &keyset, 8, parts, 3).unwrap_err(),
                licash::Error::Protocol("overlapping timed claim value".into())
            );
        }
    }
}

#[test]
fn malformed_or_unreferenced_components_and_invalid_amounts_fail_closed() {
    let keyset = IssuerKeys::random(2).unwrap().keyset().unwrap();
    for (amount, parts) in [
        (0, settled(1)),
        (5, settled(1)),
        (4, settled(0)),
        (4, settled(33)),
    ] {
        assert!(UnsignedClaim::new(context(), &keyset, amount, parts, 33).is_err());
    }
    let mut duplicate = settled(2);
    duplicate.items[1] = duplicate.items[0].clone();
    assert!(UnsignedClaim::new(context(), &keyset, 4, duplicate, 2).is_err());
    let mut extra = settled(1);
    extra.sources.push(Source::Plain {
        id: ProposalId::from_bytes([83; 32]),
        inputs: vec![point(17)],
    });
    assert!(UnsignedClaim::new(context(), &keyset, 4, extra, 1).is_err());
    let mut invalid = settled(1);
    invalid.sources.push(Source::Plain {
        id: ProposalId::from_bytes([83; 32]),
        inputs: vec![Point([0; 33])],
    });
    assert!(UnsignedClaim::new(context(), &keyset, 4, invalid, 1).is_err());
    let mut over_cap = context();
    over_cap.cap = 3;
    assert!(UnsignedClaim::new(over_cap, &keyset, 4, settled(1), 1).is_err());
    let mut bad_blinding = settled(1);
    let id = ProposalId::from_bytes([97; 32]);
    bad_blinding.items.push(Item::Pending {
        message: derive(10).message().clone(),
        source: id,
        branch: Branch::Pay,
        index: 0,
        blinding: ScalarBytes([255; 32]),
        preimage: None,
    });
    bad_blinding.sources.push(Source::Plain {
        id,
        inputs: vec![derive(0).message().identifier().unwrap()],
    });
    bad_blinding
        .authorizations
        .push(derive(10).message().clone());
    bad_blinding.authorizations = canonical(bad_blinding.authorizations);
    assert_eq!(
        UnsignedClaim::new(context(), &keyset, 4, bad_blinding, 2).unwrap_err(),
        licash::Error::InvalidScalar
    );
}
