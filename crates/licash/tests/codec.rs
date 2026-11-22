use k256::Scalar;
use licash::{
    address::{Ephemeral, OwnerKeys},
    authorization::{Authorization, Grant, PreparedGrant, SignedProposal},
    claim::Branch,
    crypto,
    note::{Derivation, Evidence, IssuerKeys, Keyset, Note},
    spend::{Output, Proposal},
};

const NOTE_TAG: &[u8] = b"LICASH-NT\x05";
/// Tag, keyset, public fields, C, evidence tag, DLEQ, blinding, commitment.
const LINKED_NOTE_BYTES: usize = 10 + 32 + 72 + 33 + 1 + 64 + 32 + 66;

struct Fixture {
    keys: IssuerKeys,
    keyset: Keyset,
    alice: OwnerKeys,
    inputs: Vec<(Derivation, Note)>,
    proposal: Proposal,
}

/// A note of `denom` to `owner` with ordinary issuance evidence.
fn issue(keys: &IssuerKeys, keyset: &Keyset, owner: &OwnerKeys, denom: u64) -> (Derivation, Note) {
    let d = Ephemeral::random()
        .derive(&owner.address(), denom, Branch::Pay, 0)
        .unwrap();
    let b = d.blinded().unwrap();
    let proof = keys.prove_blinded(denom, b).unwrap();
    let note = Note::from_parts(
        keyset,
        *keyset.id(),
        d.message().clone(),
        proof.open_point(keyset, &d).unwrap(),
        Evidence::Linked {
            dleq: proof.dleq(),
            blinding: *d.blinding(),
            commit: crypto::dleq_commit(&crypto::random_scalar(), &b.to_projective().unwrap()),
        },
    )
    .unwrap();
    (d, note)
}

/// Alice spends 4 and 2 to Bob's 4 and her own 2.
fn fixture() -> Fixture {
    let keys = IssuerKeys::random(3).unwrap();
    let keyset = keys.keyset().unwrap();
    let (alice, bob) = (
        OwnerKeys::from_seed(&[1; 32]).unwrap(),
        OwnerKeys::from_seed(&[2; 32]).unwrap(),
    );
    let inputs = vec![
        issue(&keys, &keyset, &alice, 4),
        issue(&keys, &keyset, &alice, 2),
    ];
    let e = Ephemeral::random();
    let out = |to: &OwnerKeys, denom, position| {
        Output::from_derivation(
            &e.derive(&to.address(), denom, Branch::Pay, position)
                .unwrap(),
        )
        .unwrap()
    };
    let notes: Vec<Note> = inputs.iter().map(|(_, n)| n.clone()).collect();
    let proposal = Proposal::new(
        &keyset,
        &notes,
        e.public(),
        vec![out(&bob, 4, 0), out(&alice, 2, 1)],
        None,
    )
    .unwrap();
    Fixture {
        keys,
        keyset,
        alice,
        inputs,
        proposal,
    }
}

impl Fixture {
    fn notes(&self) -> Vec<Note> {
        self.inputs.iter().map(|(_, n)| n.clone()).collect()
    }

    fn owners(&self) -> Vec<Scalar> {
        self.inputs
            .iter()
            .map(|(d, _)| {
                d.ownership()
                    .owner_secret(self.alice.spend_secret())
                    .unwrap()
            })
            .collect()
    }

    fn sign(&self, authorization: Authorization) -> SignedProposal {
        SignedProposal::sign(
            &self.keyset,
            self.proposal.clone(),
            &self.notes(),
            authorization,
            &self.owners(),
        )
        .unwrap()
    }

    fn grant(&self) -> Grant {
        PreparedGrant::new(&self.keys, &self.proposal)
            .unwrap()
            .offer()
    }
}

/// Every proper prefix and one trailing byte are refused by `decode`.
fn refuses_framing_errors(bytes: &[u8], decode: impl Fn(&[u8]) -> bool) {
    for n in 0..bytes.len() {
        assert!(!decode(&bytes[..n]), "prefix of {n} bytes");
    }
    assert!(!decode(&[bytes, &[0]].concat()), "trailing byte");
    let mut tag = bytes.to_vec();
    tag[0] ^= 1;
    assert!(!decode(&tag), "tag");
}

#[test]
fn notes_roundtrip_and_decode_only_under_their_keyset() {
    let f = fixture();
    let note = &f.inputs[0].1;
    let bytes = note.to_bytes();
    assert_eq!(&bytes[..NOTE_TAG.len()], NOTE_TAG);
    assert_eq!(bytes.len(), LINKED_NOTE_BYTES);
    assert_eq!(&Note::from_bytes(&f.keyset, &bytes).unwrap(), note);
    refuses_framing_errors(&bytes, |b| Note::from_bytes(&f.keyset, b).is_ok());
    let other = IssuerKeys::random(3).unwrap().keyset().unwrap();
    assert!(Note::from_bytes(&other, &bytes).is_err());
}

#[test]
fn note_decoding_verifies_the_signature_and_evidence() {
    let f = fixture();
    let bytes = f.inputs[0].1.to_bytes();
    let evidence = 10 + 32 + 72 + 33;
    // Any change to C, the evidence tag, the DLEQ or the blinding is refused.
    // The unlink commitment that follows is the issuer's, checked only when
    // unlinking, not by the evidence.
    for at in (evidence - 33..evidence + 97).step_by(5) {
        let mut b = bytes.clone();
        b[at] ^= 1;
        assert!(Note::from_bytes(&f.keyset, &b).is_err(), "byte {at}");
    }
    // The other evidence forms frame correctly but do not verify here.
    let unlinked = [
        &bytes[..evidence],
        &[0],
        &bytes[evidence + 1..evidence + 65],
    ]
    .concat();
    assert!(Note::from_bytes(&f.keyset, &unlinked).is_err());
    let granted = [&bytes[..evidence], &[2], &bytes[evidence + 1..], &[1; 32]].concat();
    assert!(Note::from_bytes(&f.keyset, &granted).is_err());
    let unknown = [&bytes[..evidence], &[3], &bytes[evidence + 1..]].concat();
    assert!(Note::from_bytes(&f.keyset, &unknown).is_err());
}

#[test]
fn a_peek_reads_what_a_note_claims_without_verifying_it() {
    let f = fixture();
    let note = &f.inputs[0].1;
    let bytes = note.to_bytes();
    let peek = Note::peek(&bytes).unwrap();
    assert_eq!(&peek.keyset, f.keyset.id());
    assert_eq!(&peek.message, note.message());
    assert_eq!(peek.message.denomination(), 4);
    assert!(!peek.unlinked);
    refuses_framing_errors(&bytes, |b| Note::peek(b).is_ok());
    // An unlinked form that does not verify still frames, and says so.
    let evidence = 10 + 32 + 72 + 33;
    let unlinked = [
        &bytes[..evidence],
        &[0],
        &bytes[evidence + 1..evidence + 65],
    ]
    .concat();
    assert!(Note::from_bytes(&f.keyset, &unlinked).is_err());
    assert!(Note::peek(&unlinked).unwrap().unlinked);
}

#[test]
fn grants_roundtrip_structurally_and_verify_after_decoding() {
    let f = fixture();
    let grant = f.grant();
    let bytes = grant.to_bytes().unwrap();
    let decoded = Grant::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, grant);
    decoded.verify(&f.keyset, &f.proposal).unwrap();
    assert_eq!(decoded.commitment().unwrap(), grant.commitment().unwrap());
    refuses_framing_errors(&bytes, |b| Grant::from_bytes(b).is_ok());
    // A changed byte still decodes, and verification refuses it.
    for at in (10..bytes.len()).step_by(11) {
        let mut b = bytes.clone();
        b[at] ^= 1;
        if let Ok(g) = Grant::from_bytes(&b) {
            assert!(g.verify(&f.keyset, &f.proposal).is_err(), "byte {at}");
        }
    }
}

#[test]
fn signed_proposals_roundtrip_with_both_authorizations() {
    let f = fixture();
    for authorization in [
        Authorization::Plain,
        Authorization::Granted(Box::new(f.grant())),
    ] {
        let signed = f.sign(authorization.clone());
        let bytes = signed.to_bytes();
        let decoded = SignedProposal::from_bytes(&f.keyset, &f.notes(), &bytes).unwrap();
        assert_eq!(decoded.proposal(), signed.proposal());
        assert_eq!(decoded.authorization(), &authorization);
        assert_eq!(decoded.signatures(), signed.signatures());
        assert_eq!(decoded.to_bytes(), bytes);
        refuses_framing_errors(&bytes, |b| {
            SignedProposal::from_bytes(&f.keyset, &f.notes(), b).is_ok()
        });
        // The notes must be the proposal's inputs, in order.
        let mut swapped = f.notes();
        swapped.reverse();
        assert!(SignedProposal::from_bytes(&f.keyset, &swapped, &bytes).is_err());
        assert!(SignedProposal::from_bytes(&f.keyset, &f.notes()[..1], &bytes).is_err());
        // A changed signature byte is refused.
        let mut b = bytes.clone();
        let last = b.len() - 1;
        b[last] ^= 1;
        assert!(SignedProposal::from_bytes(&f.keyset, &f.notes(), &b).is_err());
    }
}

#[test]
fn a_keyset_lists_its_denominations_and_keeps_them_through_its_bytes() {
    let keyset = IssuerKeys::from_seed(&[5; 32], 0, 3)
        .unwrap()
        .keyset()
        .unwrap();
    assert_eq!(keyset.denominations().collect::<Vec<_>>(), [1, 2, 4, 8]);
    let back = Keyset::from_bytes(&keyset.to_bytes()).unwrap();
    assert_eq!(back.denominations().rev().collect::<Vec<_>>(), [8, 4, 2, 1]);
}
